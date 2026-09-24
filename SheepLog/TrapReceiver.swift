import Combine
import Darwin
import Foundation

/// UDP 162 listener for SNMPv1 / v2c traps and informs. Each trap becomes a `LogEntry`
/// (vendor `.snmpTrap`, program = trap name from the MIB registry, fields = var-binds) in the
/// same `LogStore` the syslog lines go to. Datagrams are decoded on a serial queue (informs
/// are acknowledged there), then handed to the main actor every ~100 ms for naming.
@MainActor
final class TrapReceiver: ObservableObject {
    @Published private(set) var isRunning = false
    @Published private(set) var lastError: String?
    @Published private(set) var trapCount = 0
    @Published private(set) var port: UInt16 = 0
    /// SNMPv3 traps seen (acknowledged by nothing, logged as undecoded).
    @Published private(set) var v3Count = 0
    /// Datagrams that were not SNMP at all.
    @Published private(set) var invalidCount = 0

    private let store: LogStore
    private var listener: TrapListener?
    /// Names traps (tests use their own).
    var registry: MIBRegistry = .shared
    /// Traps the loaded MIBs could not fully name (the launch load still running, or a vendor
    /// OID no module defines yet): named again, in place, whenever a new MIB index is installed
    /// — the launch load finishing, or the vendor's MIB imported (traps that arrived before or
    /// during the import kept `enterprises.12356…` for good). The most recent `maxUnnamed`
    /// (and `maxUnnamedVarBinds` var-binds) are kept for that.
    private var unnamed: [(id: Int, trap: SNMPTrap)] = []
    /// How much of each `unnamed` trap's line is named (`namedness`), by id: a re-name only
    /// ever names more. A module removed (or replaced by one that names less) must not turn
    /// lines it named back into dotted OIDs — the fully named ones were never kept here, so a
    /// trap with one vendor var-bind no module defines went dotted while its neighbours kept
    /// their names. Old lines keep their names; new traps are named by the MIBs of the moment.
    private var unnamedScore: [Int: Int] = [:]
    private var unnamedVarBinds = 0
    /// The registry a re-name is waiting on (nil: none).
    private weak var renameScheduledOn: MIBRegistry?
    static let maxUnnamed = 20_000
    static let maxUnnamedVarBinds = 400_000

    init(store: LogStore) { self.store = store }

    /// Traps the listener has read but not yet handed over (tests).
    var batchedCount: Int { listener?.pendingCount ?? 0 }

    func start(port: UInt16) {
        stop()
        lastError = nil
        do {
            // A trap storm while the main thread is busy: at most `backlogSlots` batches wait
            // for it; later ones are dropped and counted instead of queueing without bound.
            let gate = BacklogGate(slots: TrapListener.backlogSlots)
            let store = self.store
            let l = try TrapListener(port: port, deliver: { [weak self] batch in
                DispatchQueue.main.async {
                    MainActor.assumeIsolated {
                        self?.ingest(batch, writtenToDisk: true)
                        // Traps dropped at the gate were received too (Status "N received").
                        let dropped = gate.leave()
                        store.noteDropped(dropped)
                        if dropped > 0 { self?.trapCount += dropped }
                    }
                }
            }, gate: gate)
            // Like the syslog listener: every trap goes to the disk log from the listener queue,
            // before the backlog gate may drop its batch and before ⌘Q can strand it on the main
            // queue.
            let disk = store.diskSink
            l.rawSink = { raws in disk.append(raws) }
            listener = l
            l.resume()
            self.port = port
            isRunning = true
        } catch let e as TrapListener.BindError {
            lastError = e.message
            isRunning = false
        } catch {
            lastError = error.localizedDescription
            isRunning = false
        }
    }

    /// Stops listening. Traps still waiting in the listener's 100 ms batch are written to the
    /// disk log and added to the store before this returns: ⌘Q calls it and then closes the
    /// disk log, so a batch left for `DispatchQueue.main.async` would never be logged.
    func stop() {
        if let l = listener {
            let rest = l.cancelAndDrain()
            if !rest.isEmpty { ingest(rest, writtenToDisk: true) }
        }
        listener = nil
        isRunning = false
    }

    /// One batch from the listener queue. The counters are summed first and published once
    /// (each `+=` on a `@Published` sends objectWillChange).
    /// `writtenToDisk`: the listener already handed these traps to the disk log.
    func ingest(_ batch: [ReceivedTrap], writtenToDisk: Bool = false) {
        var entries: [LogEntry] = []
        entries.reserveCapacity(batch.count)
        var traps = 0, v3 = 0, invalid = 0
        let registry = self.registry
        let early = registry.isFirstLoadPending
        for item in batch {
            switch item {
            case .trap(let t):
                let e = Self.entry(for: t, registry: registry)
                entries.append(e)
                if early || !Self.fullyNamed(t, registry: registry) {
                    keepUnnamed(e.id, t, score: early ? 0 : Self.namedness(t, registry: registry))
                }
                traps += 1
            case .v3(let source, let port, let received):
                v3 += 1
                traps += 1
                let msg = Self.v3Message(source: source)
                entries.append(LogEntry(id: LogStore.nextID(), received: received, deviceTime: nil,
                                        sourceAddress: source, sourcePort: port, transport: .trap,
                                        facility: .local0, severity: .notice, priority: nil, hostname: source,
                                        program: "snmpv3", pid: nil, message: msg, raw: msg, vendor: .snmpTrap,
                                        fields: [LogField("version", "v3")]))
            case .invalid:
                invalid += 1
            }
        }
        if traps > 0 { trapCount += traps }
        if v3 > 0 { v3Count += v3 }
        if invalid > 0 { invalidCount += invalid }
        if !entries.isEmpty { store.ingest(entries, writtenToDisk: writtenToDisk) }
        if !unnamed.isEmpty, renameScheduledOn !== registry {
            renameScheduledOn = registry
            let r = registry
            if early { r.whenFirstLoadFinishes { [weak self] in self?.renameUnnamedTraps(r) } }
            else { r.whenNextIndexInstalled { [weak self] in self?.renameUnnamedTraps(r) } }
        }
    }

    private func keepUnnamed(_ id: Int, _ t: SNMPTrap, score: Int) {
        unnamed.append((id, t))
        unnamedScore[id] = score
        unnamedVarBinds += t.varBinds.count
        // The oldest go first: they are the likeliest to have rolled out of the log already.
        var drop = 0
        while unnamed.count - drop > Self.maxUnnamed || (unnamedVarBinds > Self.maxUnnamedVarBinds && unnamed.count - drop > 1) {
            unnamedVarBinds -= unnamed[drop].trap.varBinds.count
            unnamedScore[unnamed[drop].id] = nil
            drop += 1
        }
        if drop > 0 { unnamed.removeFirst(drop) }
    }

    /// The loaded MIBs name the notification and every var-bind's object (not just a prefix
    /// such as `enterprises` — a later import may name those).
    static func fullyNamed(_ t: SNMPTrap, registry: MIBRegistry) -> Bool {
        if t.trapOID.parts.count >= 3, registry.exactNode(t.trapOID) == nil { return false }
        for vb in t.varBinds.prefix(maxVarBinds) {
            guard let n = registry.node(for: vb.oid) else { return false }
            if n.oid != vb.oid, n.kind != "scalar", n.kind != "column" { return false }
        }
        return true
    }

    /// The trap OID named exactly, plus each var-bind named to its object (a scalar, a column
    /// or an exact node) — what a re-name compares.
    static func namedness(_ t: SNMPTrap, registry: MIBRegistry) -> Int {
        var n = t.trapOID.parts.count >= 3 && registry.exactNode(t.trapOID) != nil ? 1 : 0
        for vb in t.varBinds.prefix(maxVarBinds) {
            guard let node = registry.node(for: vb.oid) else { continue }
            if node.oid == vb.oid || node.kind == "scalar" || node.kind == "column" { n += 1 }
        }
        return n
    }

    /// A new MIB index is in (the launch load finished, a vendor MIB was imported): the traps
    /// it could not name get their names (`linkDown`, `fgTrapHaSwitch`, `ifIndex.3`) in place —
    /// the same ids, so their order in the log stays. Those still not fully named wait for the
    /// next index.
    private func renameUnnamedTraps(_ r: MIBRegistry) {
        if renameScheduledOn === r { renameScheduledOn = nil }
        guard r === registry else { unnamed = []; unnamedScore = [:]; unnamedVarBinds = 0; return }
        let pending = unnamed
        let scores = unnamedScore
        unnamed = []
        unnamedScore = [:]
        unnamedVarBinds = 0
        guard !pending.isEmpty else { return }
        var updated: [LogEntry] = []
        for (id, t) in pending {
            let before = scores[id] ?? 0
            let now = Self.namedness(t, registry: r)
            if now > before { updated.append(Self.entry(for: t, registry: r, id: id)) }
            if !Self.fullyNamed(t, registry: r) { keepUnnamed(id, t, score: max(before, now)) }
        }
        store.replaceEntries(updated)
        if !unnamed.isEmpty {
            renameScheduledOn = r
            r.whenNextIndexInstalled { [weak self] in self?.renameUnnamedTraps(r) }
        }
    }

    static let warningTraps: Set<OID> = [
        OID([1, 3, 6, 1, 6, 3, 1, 1, 5, 1]),   // coldStart
        OID([1, 3, 6, 1, 6, 3, 1, 1, 5, 2]),   // warmStart
        OID([1, 3, 6, 1, 6, 3, 1, 1, 5, 3]),   // linkDown
        OID([1, 3, 6, 1, 6, 3, 1, 1, 5, 5]),   // authenticationFailure
    ]

    /// snmpTrapEnterprise.0 (RFC 3584 §3.1: appended to a v1 trap translated to v2).
    nonisolated static let snmpTrapEnterprise = OID([1, 3, 6, 1, 6, 3, 1, 1, 4, 3, 0])
    /// snmpTrapAddress.0 (SNMP-COMMUNITY-MIB; RFC 3584 §3.1: a v1 trap's agent-addr).
    nonisolated static let snmpTrapAddress = OID([1, 3, 6, 1, 6, 3, 18, 1, 3, 0])

    /// Var-binds turned into fields and message text per trap; the rest are counted in a
    /// `varbinds_truncated` field (a 64 KB datagram can carry ~10,000 tiny ones, all named on
    /// the main actor).
    nonisolated static let maxVarBinds = 1_000

    nonisolated static func v3Message(source: String) -> String {
        "SNMPv3 trap from \(source) (not decoded — v3 traps need a user configured; not supported yet)"
    }

    nonisolated private static func rawText(_ version: SNMPVersion, _ oid: OID, _ numeric: [String]) -> String {
        "SNMP\(version.label) trap \(oid.dotted)" + (numeric.isEmpty ? "" : " " + numeric.joined(separator: " "))
    }

    /// The `raw` text of the log line for `t` (what the disk log records), built without the
    /// MIB registry so the listener queue can write it before the batch reaches the main actor.
    nonisolated static func rawText(for t: SNMPTrap) -> String {
        let kept = t.varBinds.prefix(maxVarBinds)
        return rawText(t.version, t.trapOID, kept.map { "\($0.oid.dotted)=\($0.value.display)" })
    }

    /// Builds the log line for one trap (names and values through the MIB registry).
    ///
    /// What the log filter sees:
    /// - `program` = the notification's name (`linkDown`, a vendor name from an imported MIB,
    ///   or the dotted OID when no loaded MIB names it) — `app:linkDown`;
    /// - `hostname` = the v1 agent-addr, else the sender's address — `host:10.1.`;
    /// - `message` = name + `object.instance=value` pairs;
    /// - `raw` = version, trap OID and the numeric `oid=value` pairs;
    /// - `fields` = one per var-bind keyed `object.instance` (`ifOperStatus.7`; an OID no MIB
    ///   names keeps its dotted form), then `trap_oid`, `version`, `community`, `uptime`, and
    ///   for v1 `agent_addr`.
    static func entry(for t: SNMPTrap, registry: MIBRegistry, id: Int? = nil) -> LogEntry {
        var trapName: String
        if t.trapOID.parts.count < 3 {
            trapName = "snmpTrap"              // a v2 trap without snmpTrapOID.0
        } else {
            trapName = registry.name(for: t.trapOID)
            if trapName.hasSuffix(".0") { trapName.removeLast(2) }
        }
        trapName = DisplayText.label(trapName, max: 512)
        var parts: [String] = []
        var fields: [LogField] = []
        var numeric: [String] = []
        let kept = t.varBinds.count > maxVarBinds ? Array(t.varBinds.prefix(maxVarBinds)) : t.varBinds
        // One longest-prefix search per column, not two per var-bind (a 200-var-bind trap).
        let described = registry.describe(kept)
        for (vb, d) in zip(kept, described) {
            parts.append("\(d.name)=\(d.value)")
            fields.append(LogField(d.name, d.value))
            numeric.append("\(vb.oid.dotted)=\(vb.value.display)")
        }
        if t.varBinds.count > kept.count {
            fields.append(LogField("varbinds_truncated", "\(t.varBinds.count - kept.count) more not shown"))
        }
        fields.append(LogField("trap_oid", t.trapOID.dotted))
        fields.append(LogField("version", t.version.label))
        fields.append(LogField("community", DisplayText.label(t.community, max: 255)))
        if let up = t.uptime { fields.append(LogField("uptime", Format.uptime(ticks: UInt64(up)))) }
        let message = DisplayText.neutralize(parts.isEmpty ? trapName : trapName + " " + parts.joined(separator: ", "),
                                             keepLineBreaks: true)
        let severity: Severity = warningTraps.contains(t.trapOID) ? .warning : .notice
        var host = t.sourceAddress
        if let agent = t.agentAddress, !agent.isEmpty {
            fields.append(LogField("agent_addr", DisplayText.label(agent, max: 64)))
            // Only a real IPv4 address stands for the host (a v1 agent-addr of the wrong
            // length decodes as hex bytes).
            var a = in_addr()
            if agent != "0.0.0.0", inet_pton(AF_INET, agent, &a) == 1 { host = agent }
        }
        let raw = rawText(t.version, t.trapOID, numeric)
        return LogEntry(id: id ?? LogStore.nextID(), received: t.received, deviceTime: nil, sourceAddress: t.sourceAddress,
                        sourcePort: t.sourcePort, transport: .trap, facility: .local0, severity: severity,
                        priority: nil, hostname: host, program: trapName, pid: nil, message: message, raw: raw,
                        vendor: .snmpTrap, fields: fields)
    }
}

nonisolated enum ReceivedTrap: Sendable {
    case trap(SNMPTrap)
    case v3(source: String, port: UInt16, received: Date)
    case invalid

    /// A trap or an undecoded v3 trap: a line in the log (not a datagram that was not SNMP).
    var isLogLine: Bool { if case .invalid = self { false } else { true } }

    /// The line the disk log gets for it (nil for a datagram that was not SNMP).
    var diskLine: RawSyslog? {
        switch self {
        case .trap(let t):
            RawSyslog(received: t.received, sourceAddress: t.sourceAddress, sourcePort: t.sourcePort,
                      transport: .trap, text: TrapReceiver.rawText(for: t))
        case .v3(let source, let port, let received):
            RawSyslog(received: received, sourceAddress: source, sourcePort: port, transport: .trap,
                      text: TrapReceiver.v3Message(source: source))
        case .invalid: nil
        }
    }
}

/// The socket half: dual-stack UDP, a DispatchSource on a serial queue, 100 ms batching.
/// `@unchecked`: every mutable member is confined to `queue` (`rawSink` is set before `resume()`).
nonisolated final class TrapListener: @unchecked Sendable {
    struct BindError: Error { let message: String }

    private let fd: Int32
    private let queue = DispatchQueue(label: "SheepLog.traps", qos: .utility)
    private var source: DispatchSourceRead?
    private var pending: [ReceivedTrap] = []
    private var flushScheduled = false
    private var cancelled = false
    private let closed = DispatchSemaphore(value: 0)
    private var buf = [UInt8](repeating: 0, count: 65_536)     // queue-confined, reused per read
    private let deliver: @Sendable ([ReceivedTrap]) -> Void
    private let gate: BacklogGate?
    /// Receives every batch on the listener queue before the backlog gate (the disk log). Set
    /// before `resume()`.
    var rawSink: (@Sendable ([RawSyslog]) -> Void)?
    /// Inform acknowledgements sent in the current second (a spoofed-source inform flood must
    /// not turn this into a reflector at line rate).
    private var acksThisSecond = 0
    private var ackSecond: UInt64 = 0

    static let backlogSlots = 32

    /// Traps read but not yet flushed (tests).
    var pendingCount: Int { queue.sync { pending.count } }
    static let maxAcksPerSecond = 500

    init(port: UInt16, deliver: @escaping @Sendable ([ReceivedTrap]) -> Void, gate: BacklogGate? = nil) throws {
        self.deliver = deliver
        self.gate = gate
        fd = try Self.bind(port: port)
    }

    func resume() {
        let src = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        let fd = self.fd
        let closed = self.closed
        src.setEventHandler { [weak self] in self?.readAvailable() }
        src.setCancelHandler {
            Darwin.close(fd)
            closed.signal()
        }
        source = src
        src.resume()
    }

    /// Cancels the source and waits until its handler has closed the socket, so the port can
    /// be bound again right away (a quick off/on would otherwise hit EADDRINUSE). Traps still
    /// batched are delivered.
    func cancel() {
        let rest = cancelAndDrain()
        if !rest.isEmpty { deliver(rest) }
    }

    /// `cancel()`, but the traps still batched are returned (already given to `rawSink`)
    /// instead of delivered, so a caller on the main actor can take them in synchronously.
    func cancelAndDrain() -> [ReceivedTrap] {
        enum Step { case none, wait, close }
        var rest: [ReceivedTrap] = []
        let step: Step = queue.sync {
            guard !cancelled else { return .none }      // a second cancel must not close twice
            cancelled = true
            flushScheduled = false
            rest = pending
            pending = []
            if !rest.isEmpty { rawSink?(rest.compactMap(\.diskLine)) }
            guard let s = source else { return .close }  // bound but never resumed
            s.cancel()
            source = nil
            return .wait
        }
        switch step {
        case .none: break
        case .wait: _ = closed.wait(timeout: .now() + 2)
        case .close: Darwin.close(fd)
        }
        return rest
    }

    /// The syslog listener's socket factory: a dual-stack socket, but only after an IPv4 probe
    /// bind — on macOS an IPv6 (V6ONLY=0) socket binds even while another program (snmptrapd,
    /// `nc -ul 162`) holds the port for IPv4, and every IPv4 trap would go to that program.
    static func bind(port: UInt16) throws -> Int32 {
        switch SocketFactory.bind(type: SOCK_DGRAM, port: port) {
        case .success(let fd): return fd
        case .failure(let e): throw BindError(message: e.message(transport: "UDP", port: port))
        }
    }

    private func readAvailable() {
        // At most a few thousand datagrams per event (the source fires again), so a trap storm
        // cannot keep this loop — and the undelivered `pending` — growing forever.
        var reads = 0
        while reads < 2_000 {
            var from = sockaddr_storage()
            var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let n = withUnsafeMutablePointer(to: &from) { sp in
                sp.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    buf.withUnsafeMutableBytes { recvfrom(fd, $0.baseAddress, $0.count, 0, sa, &len) }
                }
            }
            if n < 0 { break }   // EAGAIN: drained
            reads += 1
            let (host, port) = SocketFactory.describe(&from)
            let item = handle(Array(buf[0..<n]), host: host, port: port, from: &from, fromLen: len)
            pending.append(item)
        }
        if pending.count >= 2_000 {
            flush()
        } else if !pending.isEmpty, !flushScheduled {
            flushScheduled = true
            queue.asyncAfter(deadline: .now() + 0.1) { [weak self] in self?.flush() }
        }
    }

    private func flush() {
        flushScheduled = false
        guard !pending.isEmpty else { return }
        let batch = pending
        pending = []
        if let rawSink { rawSink(batch.compactMap(\.diskLine)) }
        // Only traps count as dropped log lines: a datagram that was not SNMP would never have
        // become one (and delivered, it is not counted as received either).
        if let gate, !gate.tryEnter(count: batch.reduce(0) { $0 + ($1.isLogLine ? 1 : 0) }) { return }
        deliver(batch)
    }

    /// Decodes one datagram (and acknowledges an inform).
    private func handle(_ bytes: [UInt8], host: String, port: UInt16, from: inout sockaddr_storage,
                        fromLen: socklen_t) -> ReceivedTrap {
        let decoded = Self.decode(bytes, host: host, port: port, received: Date())
        if case .trap = decoded.item, let ack = decoded.informResponse {
            let second = clock_gettime_nsec_np(CLOCK_UPTIME_RAW) / 1_000_000_000
            if second != ackSecond { ackSecond = second; acksThisSecond = 0 }
            acksThisSecond += 1
            guard acksThisSecond <= Self.maxAcksPerSecond else { return decoded.item }
            _ = ack.withUnsafeBytes { raw in
                withUnsafePointer(to: &from) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        sendto(fd, raw.baseAddress, raw.count, 0, $0, fromLen)
                    }
                }
            }
        }
        return decoded.item
    }

    /// Pure decoding, shared with the tests: the trap, plus the Response to send for an inform.
    static func decode(_ bytes: [UInt8], host: String, port: UInt16, received: Date) -> (item: ReceivedTrap, informResponse: [UInt8]?) {
        guard let version = CommunityMessage.peekVersion(bytes) else { return (.invalid, nil) }
        if version == 3 { return (.v3(source: host, port: port, received: received), nil) }
        guard version == 0 || version == 1, let msg = try? CommunityMessage.decode(bytes),
              let pduTLV = msg.pduTLV else { return (.invalid, nil) }
        let community = String(decoding: msg.community, as: UTF8.self)
        if version == 0 {
            guard pduTLV.tag == BER.trapV1, let v1 = try? TrapV1PDU.decode(pduTLV) else { return (.invalid, nil) }
            // RFC 3584 §3.1 (3): the translated notification carries the agent-addr
            // (snmpTrapAddress.0) and the enterprise (snmpTrapEnterprise.0) — for the generic
            // traps (coldStart … linkDown) the only place the enterprise survives, and the
            // agent-addr then reaches the raw text: the disk log and a bare-word search find the
            // device a proxy forwarded the trap for.
            var appended: [VarBind] = []
            var a = in_addr()
            if v1.agentAddress != "0.0.0.0", inet_pton(AF_INET, v1.agentAddress, &a) == 1 {
                appended.append(VarBind(TrapReceiver.snmpTrapAddress, .ipAddress(v1.agentAddress)))
            }
            appended.append(VarBind(TrapReceiver.snmpTrapEnterprise, .oid(v1.enterprise)))
            let trap = SNMPTrap(received: received, sourceAddress: host, sourcePort: port, version: .v1,
                                community: community, trapOID: v1.trapOID, uptime: v1.timeStamp,
                                agentAddress: v1.agentAddress,
                                varBinds: v1.varBinds + appended)
            return (.trap(trap), nil)
        }
        guard let pdu = msg.pdu, pdu.type == BER.trapV2 || pdu.type == BER.informRequest else { return (.invalid, nil) }
        var uptime: UInt32?
        var trapOID = OID([0, 0])
        var rest: [VarBind] = []
        for vb in pdu.varBinds {
            if vb.oid == OID.sysUpTimeInstance, case .timeTicks(let t) = vb.value, uptime == nil { uptime = t; continue }
            if vb.oid == OID.snmpTrapOID, case .oid(let o) = vb.value { trapOID = o; continue }
            rest.append(vb)
        }
        let trap = SNMPTrap(received: received, sourceAddress: host, sourcePort: port, version: .v2c,
                            community: community, trapOID: trapOID, uptime: uptime, agentAddress: nil, varBinds: rest)
        var ack: [UInt8]?
        if pdu.type == BER.informRequest {
            var a = BER.encodeSequence([
                BER.encodeInteger(1),
                BER.encodeOctets(msg.community),
                SNMPPDU(type: BER.response, requestID: pdu.requestID, varBinds: pdu.varBinds).encoded(),
            ])
            // The answer goes to whatever source address the datagram claims: it must never be
            // larger than the request (no amplification). Re-encoding can grow it — a sloppy
            // 4-byte Counter32 0x80000000 gains a leading zero, a 0-byte IpAddress becomes 4 —
            // so then the request itself is echoed with the Response tag (RFC 3416 §4.2.7:
            // same request-id and var-binds).
            if a.count > bytes.count { a = echoAck(bytes, pduStart: pduTLV.start) ?? [] }
            ack = !a.isEmpty && a.count <= bytes.count ? a : nil
        }
        return (.trap(trap), ack)
    }

    /// The inform as received (up to the end of its outer SEQUENCE) with the PDU tag changed
    /// to Response.
    static func echoAck(_ bytes: [UInt8], pduStart: Int) -> [UInt8]? {
        var outer = BERReader(bytes)
        guard let t = try? outer.readTLV(), pduStart > 0, pduStart < t.range.upperBound,
              bytes[pduStart] == BER.informRequest else { return nil }
        var out = Array(bytes[0..<t.range.upperBound])
        out[pduStart] = BER.response
        return out
    }
}
