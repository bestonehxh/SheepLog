import Foundation

// MARK: - Findings (what the Troubleshoot pane lists)

nonisolated enum FindingSeverity: Int, Sendable, Comparable, CaseIterable {
    case info = 0, warn = 1, bad = 2

    static func < (a: FindingSeverity, b: FindingSeverity) -> Bool { a.rawValue < b.rawValue }

    var word: String {
        switch self {
        case .info: "Note"
        case .warn: "Warning"
        case .bad: "Problem"
        }
    }
}

nonisolated enum FindingCategory: String, Sendable, CaseIterable {
    case link, hardware, auth, dhcp, dns, arpIP, stp, routing, tcp, snmp, config, security, capacity

    /// The chip / section word.
    var label: String {
        switch self {
        case .link: "Link"
        case .hardware: "Hardware"
        case .auth: "Auth"
        case .dhcp: "DHCP"
        case .dns: "DNS"
        case .arpIP: "ARP & IP"
        case .stp: "STP"
        case .routing: "Routing"
        case .tcp: "TCP"
        case .snmp: "SNMP"
        case .config: "Config"
        case .security: "Security"
        case .capacity: "Capacity"
        }
    }

    /// The long name (reports).
    var title: String {
        switch self {
        case .hardware: "Power & hardware"
        case .arpIP: "ARP & IP"
        case .stp: "Spanning tree"
        case .config: "Configuration & admin"
        default: label
        }
    }
}

/// What a finding was computed from. `.auth` is the Authentication pane's (see
/// `FindingRules.authProvider`, wired by the integrator).
nonisolated enum FindingSource: String, Sendable {
    case logs, traps, packets, flows, snmp, engine, auth
}

/// One TCP conversation a finding points at: the Flows pane finds it by key and frame (flow ids
/// are renumbered by every analysis).
nonisolated struct FlowRef: Sendable, Hashable {
    let key: FlowKey
    let packetID: Int
    /// The conversation's last frame: whether any of it is still in the capture ring.
    var lastPacketID: Int? = nil
}

/// A group of things a finding was built from, and how to show them.
nonisolated struct Evidence: Sendable, Hashable, Identifiable {
    nonisolated enum Kind: String, Sendable, Hashable { case logLines, traps, packets, flows }
    let kind: Kind
    /// "12 log lines", "8 packets", "flow ⇄".
    let label: String
    /// Log entry ids, packet frame numbers or flow ids.
    let ids: [Int]
    /// The Log / Packets filter that shows them ("" for flows).
    let query: String
    var flows: [FlowRef] = []

    var id: String { kind.rawValue + "|" + label + "|" + query }
}

nonisolated struct Finding: Identifiable, Sendable, Equatable {
    /// Stable across analyses ("link.flap|CORE-CX-6300|1/1/24"), so an expanded row stays expanded.
    let id: String
    var rule: String
    var severity: FindingSeverity
    var category: FindingCategory
    var source: FindingSource
    /// One sentence, specific.
    var title: String
    /// Two to four sentences: what was seen and why it matters.
    var detail: String
    var evidence: [Evidence] = []
    var firstSeen: Date
    var lastSeen: Date
    var count: Int = 1
    /// The device it is about (name as the log shows it) and its address.
    var device: String? = nil
    var deviceAddress: String? = nil
    /// The one endpoint it is about (MAC or IP).
    var client: String? = nil
    var nextSteps: [String] = []
    /// "Open in SNMP test" target, when there is one.
    var snmpTarget: String? = nil
}

// MARK: - Input and output

/// One SNMP result set from the Test pane (the Interfaces walk joins ifTable and ifXTable).
nonisolated struct SNMPSnapshot: Sendable {
    let host: String
    let taken: Date
    var sysName: String?
    /// Ticks (1/100 s).
    var sysUpTime: UInt32?
    var interfaces: [InterfaceRow]
    /// Var-binds as the Test pane shows them (value text), by OID.
    var values: [OID: String]

    var name: String { (sysName?.isEmpty ?? true) ? host : sysName! }
}

nonisolated struct EngineCounters: Sendable, Equatable {
    var logCount = 0
    var logLimit = 0
    var logDropped = 0
    var logLost = 0
    var packetCount = 0
    var packetLimit = 0
    var packetDropped = 0
    var packetLost = 0
}

nonisolated struct TroubleshootInput: Sendable {
    var entries: [LogEntry] = []
    var packets: [Packet] = []
    var flows: [TCPFlow] = []
    /// Oldest first; the last one per host is the current state, an earlier one of the same host
    /// shows what grew.
    var snmp: [SNMPSnapshot] = []
    var counters = EngineCounters()
    var now = Date()
    /// Findings computed elsewhere (the Authentication pane's `authProvider`).
    var extra: [Finding] = []
    /// Lines the paused Log pane holds back (newer than `entries`); `takeHeld()` joins them to
    /// `entries` off the main actor.
    var held: [LogEntry] = []
    /// The packet store's `epoch` when the packets were read (frame numbers start over after a
    /// Clear: a finding's frames are then other packets).
    var packetEpoch = 0

    mutating func takeHeld() {
        guard !held.isEmpty else { return }
        entries += held
        held = []
    }
}

nonisolated struct AnalysisSummary: Sendable, Equatable {
    var lines = 0
    var traps = 0
    var devices = 0
    var packets = 0
    var flows = 0
    var snmpWalks = 0
    var start: Date?
    var end: Date?
    /// What could not be checked, and why.
    var notes: [String] = []
}

nonisolated struct TroubleshootResult: Sendable {
    var findings: [Finding] = []
    /// The TCP conversations the flow rules read (the client report uses them too).
    var flows: [TCPFlow] = []
    var timeline = Timeline.empty
    var summary = AnalysisSummary()
    /// `TroubleshootInput.packetEpoch` of the packets these findings were read from.
    var packetEpoch = 0
}

// MARK: - The rules

/// Pure, off the main actor: syslog lines, traps, packets, TCP flows and SNMP results in,
/// plain-English findings out. The log and packet passes run on every core; the per-rule work
/// only sees the few lines and packets the passes picked out.
nonisolated enum FindingRules {
    // Thresholds (CLAUDE.md, "Troubleshoot").
    static let flapCount = 3
    static let flapWindow: Double = 600
    static let downStuck: Double = 300
    static let stpRepeat = 3
    static let stpWindow: Double = 300
    static let loginBurst = 5
    static let loginWindow: Double = 300
    static let configLead: Double = 300
    static let dhcpDiscovers = 3
    static let dhcpOfferWait: Double = 10
    static let shortLease: UInt32 = 300
    static let dnsFailShare = 0.30
    static let dnsMinQueries = 10
    static let dnsAnswerWait: Double = 2
    static let arpUnanswered = 3
    static let icmpBurst = 10
    static let redirectBurst = 5
    static let retransShare = 0.02
    static let slowHandshake = 0.3
    static let refusedAttempts = 3
    static let clockSkew: Double = 300
    static let spikeFactor = 10.0
    static let chattyUnknown = 500
    static let floodRate = 1_000
    static let recentBoot: UInt32 = 60_000        // ticks = 10 min
    /// A restart line this soon after a requested reload of the same device is that reload.
    static let plannedBoot: Double = 1_800
    /// A routing neighbor that only steps between states (never Full / Established) this many
    /// times over at least this long has not come up (a session coming up takes seconds).
    static let notUpSteps = 3
    static let notUpSpan: Double = 120
    /// NXDOMAIN counts as a DNS failure from this many different names (one mistyped name, with
    /// its search-domain variants, is the user's typo, not the resolver's fault).
    static let nxNames = 3
    /// Discards worth a finding: this many per 10,000 packets (0.1 %) through the port.
    static let discardRate = 10.0
    /// Without packet counters, discards that grew this much between two walks.
    static let discardGrowth: UInt64 = 100
    /// Retransmission shares are read from conversations with at least this many data segments
    /// (one lost segment of a 5-packet exchange is 20 % and means nothing).
    static let retransMinSegments = 20
    /// Log lines of the same configuration change (Junos UI_COMMIT and its UI_COMMIT_COMPLETED,
    /// an ASA's 111010 lines and its write memory) within this many seconds are one change.
    static let configSameChange: Double = 60

    static func analyze(_ input: TroubleshootInput, isCancelled: () -> Bool = { false }) -> TroubleshootResult {
        var ctx = RuleContext(input: input)
        let logs = LogScan.scan(input.entries)
        if isCancelled() { return TroubleshootResult() }
        ctx.absorb(logs)
        var findings: [Finding] = []
        findings += linkRules(&ctx)
        findings += hardwareRules(&ctx)
        findings += stpRules(&ctx)
        findings += routingRules(&ctx)
        findings += adminRules(&ctx)
        findings += hygieneRules(&ctx)
        if isCancelled() { return TroubleshootResult() }
        let pk = PacketScan.scan(input.packets)
        ctx.packetEnd = pk.end
        ctx.packetStart = pk.start
        if isCancelled() { return TroubleshootResult() }
        findings += dhcpRules(pk, &ctx)
        findings += dnsRules(pk, &ctx)
        findings += arpRules(pk, &ctx)
        findings += flowRules(input.flows)
        findings += snmpRules(input.snmp, now: input.now)
        findings += capacityRules(input.counters, &ctx)
        findings += input.extra
        crossReference(&findings, &ctx)
        findings.sort { a, b in
            if a.firstSeen != b.firstSeen { return a.firstSeen < b.firstSeen }
            if a.severity != b.severity { return a.severity > b.severity }
            return a.title < b.title
        }
        var result = TroubleshootResult()
        result.findings = findings
        result.flows = input.flows
        result.packetEpoch = input.packetEpoch
        result.summary = ctx.summary(input: input, packets: pk)
        result.timeline = TimelineBuilder.build(warn: ctx.warnFacts, times: ctx, flows: input.flows,
                                                findings: findings, start: result.summary.start, end: result.summary.end)
        return result
    }

    /// The Authentication pane's findings (RADIUS / 802.1X sessions) of the packets being
    /// analysed. Read on the main actor, run with the rest of the analysis off it: run on the
    /// main actor (as it was) it rebuilt every authentication session there before each analysis
    /// — every 2 s during a live capture. EXTENSION POINT: `AppModel.startup` sets it to
    /// `AuthFindings.findings(from:)`; findings it returns use `category: .auth, source: .auth`.
    @MainActor static var authProvider: (@Sendable ([Packet]) -> [Finding])?
}

// MARK: - Shared state of one analysis

nonisolated struct RuleContext: Sendable {
    let input: TroubleshootInput
    var facts: [LineFact] = []
    var warnFacts: [WarnFact] = []
    var sources: [String: SourceAcc] = [:]
    var replayed: Set<String> = []
    var nameByAddress: [String: String] = [:]
    var multiHost: Set<String> = []
    var configEvents: [(device: String, time: Date, user: String?, id: Int, message: String, address: String)] = []
    var packetStart: Date?
    var packetEnd: Date?
    var lines = 0
    var traps = 0

    init(input: TroubleshootInput) { self.input = input }

    mutating func absorb(_ scan: LogScan.Output) {
        facts = scan.facts
        warnFacts = scan.warn
        sources = scan.sources
        lines = scan.lines
        traps = scan.traps
        for (addr, s) in sources {
            if s.transportFile || (s.recvMax.timeIntervalSince(s.recvMin) < 10 && s.devSpan > 120) { replayed.insert(addr) }
            if let h = s.bestHostname { nameByAddress[addr] = h }
            if s.hostnames.count > 1 { multiHost.insert(addr) }
        }
    }

    /// The time a line is placed at: arrival for a live source (the Mac's clock, as packets
    /// are), the device's own timestamp for a replayed file.
    func time(_ address: String, received: Date, device: Date?) -> Date {
        replayed.contains(address) ? (device ?? received) : received
    }

    func time(_ f: LineFact) -> Date { time(f.address, received: f.received, device: f.deviceTime) }

    func device(_ address: String, hostname: String, isTrap: Bool) -> String {
        if isTrap { return nameByAddress[address] ?? (hostname.isEmpty ? address : hostname) }
        if !hostname.isEmpty { return hostname }
        // An address that sends several hostnames (a relay, a stack) cannot name a line that has
        // none: its most frequent name put another device's port or fan in the finding.
        if multiHost.contains(address) { return address }
        return nameByAddress[address] ?? address
    }

    func device(_ f: LineFact) -> String { device(f.address, hostname: f.hostname, isTrap: f.isTrap) }

    /// `host:` term for a device's lines: its address, or — for an address that sends several
    /// hostnames (a relay) — the name itself (`host:"SW1$"`: `host:SW1` was a prefix and showed
    /// SW10–SW19's lines too).
    func hostTerm(address: String, name: String) -> String {
        multiHost.contains(address) ? "host:" + FText.quote(name + "$") : "host:" + address
    }

    func summary(input: TroubleshootInput, packets: PacketScan.Output) -> AnalysisSummary {
        var s = AnalysisSummary()
        s.lines = lines
        s.traps = traps
        var names = Set<String>()
        for (addr, acc) in sources {
            if acc.hostnames.isEmpty { names.insert(nameByAddress[addr] ?? addr) } else { names.formUnion(acc.hostnames.keys) }
        }
        s.devices = names.count
        s.packets = input.packets.count
        s.flows = input.flows.count
        s.snmpWalks = Set(input.snmp.map(\.host)).count
        var lo: Date?, hi: Date?
        for (addr, acc) in sources {
            let a = replayed.contains(addr) ? (acc.devMin ?? acc.recvMin) : acc.recvMin
            let b = replayed.contains(addr) ? (acc.devMax ?? acc.recvMax) : acc.recvMax
            lo = min(lo ?? a, a); hi = max(hi ?? b, b)
        }
        if let a = packets.start { lo = min(lo ?? a, a) }
        if let b = packets.end { hi = max(hi ?? b, b) }
        s.start = lo
        s.end = hi
        if input.snmp.isEmpty {
            s.notes.append("SNMP: no results yet — run Interfaces on the SNMP Test pane to include port errors and status.")
        }
        if input.packets.isEmpty {
            s.notes.append("Packets: none — start a capture or open a .pcap (⌘O) for DHCP, DNS, ARP and TCP checks.")
        }
        if input.entries.isEmpty {
            s.notes.append("Syslog: no lines — point devices at this Mac (UDP/TCP 514) or send traps to UDP 162.")
        }
        if !replayed.isEmpty {
            s.notes.append("\(replayed.count == 1 ? "1 source was" : "\(replayed.count) sources were") replayed (all lines arrived at once): their own timestamps are used.")
        }
        return s
    }
}

// MARK: - Log pass

nonisolated enum HardwareKind: String, Sendable, CaseIterable {
    case psu, fan, temperature, poe

    var label: String {
        switch self {
        case .psu: "power supply"
        case .fan: "fan"
        case .temperature: "temperature"
        case .poe: "PoE power"
        }
    }
}
nonisolated enum STPKind: String, Sendable, CaseIterable { case topologyChange, rootChange, bpduGuard, loop, storm }

nonisolated enum FactKind: Sendable {
    case link(iface: String, up: Bool)
    case hardware(HardwareKind, recovered: Bool)
    case stp(STPKind, port: String?)
    case routing(proto: String, neighbor: String, up: Bool)
    /// A BGP NOTIFICATION sent to / received from a neighbor (Cisco IOS / Arista
    /// `%BGP-3-NOTIFICATION`): why the session that the adjacency line reports ended — never a
    /// down of its own (with the ADJCHANGE after it, one reset read as two downs, "flapping").
    case routingNotice(proto: String, neighbor: String, reason: String, sent: Bool)
    /// A step between states that is neither up nor down (BGP Idle → Connect → Active, OSPF
    /// Init → 2-Way → ExStart): a peer that only ever does these never came up.
    case routingStep(proto: String, neighbor: String)
    /// A routing session's segment from `neighbor` whose TCP MD5 signature was missing or wrong:
    /// the session cannot come up (a password mismatch), and it is no admin login failure.
    case routingAuth(proto: String, neighbor: String)
    case reboot(cold: Bool, planned: Bool)
    case loginFail(ip: String?, user: String?)
    case loginOK(ip: String?, user: String?)
    case config(user: String?)
}

/// One line the log pass picked out, with what it says.
nonisolated struct LineFact: Sendable {
    let id: Int
    let address: String
    let hostname: String
    let isTrap: Bool
    let received: Date
    let deviceTime: Date?
    let severity: Severity
    let kind: FactKind
    let message: String
}

/// A warning-or-worse line or a trap (the timeline and the error-spike rule).
nonisolated struct WarnFact: Sendable {
    let id: Int
    let address: String
    let hostname: String
    let isTrap: Bool
    let received: Date
    let deviceTime: Date?
    let severity: Severity
    /// The message (a trap's name); cut to a label only for what the timeline draws.
    let text: String
}

/// Per-source counters of one log pass.
nonisolated struct SourceAcc: Sendable {
    var count = 0
    var unknownVendor = 0
    var trapCount = 0
    var recvMin = Date.distantFuture
    var recvMax = Date.distantPast
    var devMin: Date?
    var devMax: Date?
    var devSpan: Double { guard let a = devMin, let b = devMax else { return 0 }; return b.timeIntervalSince(a) }
    var transportFile = false
    /// received − deviceTime, a sample of them.
    var skews: [Double] = []
    var hostnames: [String: Int] = [:]
    /// Lines per whole second of arrival: (second, count), in arrival order.
    var seconds: [(Int, Int)] = []

    var bestHostname: String? { hostnames.max { $0.value < $1.value }?.key }

    mutating func merge(_ o: SourceAcc) {
        count += o.count
        unknownVendor += o.unknownVendor
        trapCount += o.trapCount
        recvMin = min(recvMin, o.recvMin)
        recvMax = max(recvMax, o.recvMax)
        if let a = o.devMin { devMin = min(devMin ?? a, a) }
        if let b = o.devMax { devMax = max(devMax ?? b, b) }
        transportFile = transportFile || o.transportFile
        if skews.count < 256 { skews += o.skews.prefix(256 - skews.count) }
        for (h, n) in o.hostnames { hostnames[h, default: 0] += n }
        if let last = seconds.last, let first = o.seconds.first, last.0 == first.0 {
            seconds[seconds.count - 1].1 += first.1
            seconds += o.seconds.dropFirst()
        } else {
            seconds += o.seconds
        }
    }
}

/// `body(lo, hi)` over `0..<count` in chunks on every core (one chunk when it is small), in order.
nonisolated enum Parallel {
    static func chunks<T: Sendable>(_ count: Int, minimum: Int, _ body: @Sendable (Int, Int) -> T) -> [T] {
        guard count > 0 else { return [] }
        let cores = max(1, ProcessInfo.processInfo.activeProcessorCount)
        let n = max(1, min(cores * 3, count / max(1, minimum)))
        if n == 1 { return [body(0, count)] }
        let per = (count + n - 1) / n
        let slots = ChunkSlots<T>(n)
        DispatchQueue.concurrentPerform(iterations: n) { c in
            let lo = c * per, hi = min(count, lo + per)
            if lo < hi { slots.set(c, body(lo, hi)) }
        }
        return slots.values
    }
}

/// Written from `concurrentPerform` at disjoint indices only (one slot per iteration), read after
/// it returns.
nonisolated final class ChunkSlots<T>: @unchecked Sendable {
    let count: Int
    private let p: UnsafeMutablePointer<T?>
    init(_ count: Int) {
        self.count = count
        p = .allocate(capacity: count)
        p.initialize(repeating: nil, count: count)
    }
    deinit {
        p.deinitialize(count: count)
        p.deallocate()
    }
    func set(_ i: Int, _ v: T) { p[i] = v }
    var values: [T] { (0..<count).compactMap { p[$0] } }
}

/// The keyword pre-screen: C strings, allocated once and never freed or written (read from every
/// log-pass thread).
nonisolated final class Needles: @unchecked Sendable {
    let groups: [(group: Int, needles: [UnsafeMutablePointer<CChar>])]
    static let shared = Needles()
    static let link = 0, hardware = 1, stp = 2, routing = 3, reboot = 4, login = 5, config = 6

    private init() {
        let words: [[String]] = [
            ["link", "-line", "line protocol", "turned into down state", "turned into up state", "if_up", "if_down",
             "interface-stat-change", "interface status changed", ", state down", ", state up", "status changed from",
             // FRR / Quagga zebra: "interface eth0 index 2 changed <UP,BROADCAST,MULTICAST>".
             "multicast>", "running>", "lower_up>",
             // Linux `ip monitor link`: "3: eth1: <NO-CARRIER,BROADCAST,MULTICAST,UP> … state DOWN";
             // a port the switch shut for an error (IOS `%PM-4-ERR_DISABLE`, Huawei error-down,
             // AOS-CX "err-disabled").
             "no-carrier", ",up>", "err-disable", "errdisable", "err_disable", "error-down",
             // NX-OS `%ETHPORT-5-IF_DOWN_ERROR_DISABLED: … is down (Error disabled. Reason:…)`.
             "error disabled", "error_disabled"],
            ["power", "psu", "fan", "temperat", "thermal", "poe", "overheat", "pem"],
            ["stp", "topology", "bpdu", "loop", "storm", "spanning", "root bridge"],
            // "peer" / "bgp" / "ospf": Huawei `BGP/3/STATE_CHG_UPDOWN` ("The status of the peer …
            // changed from ESTABLISHED to IDLE"), PAN-OS "BGP peer session left established
            // state" and Junos `bgp_hold_timeout: NOTIFICATION sent to …` never say "neighbor"
            // (they were never read). `routing` still needs a protocol, and a neighbor it can
            // name unless the line says "neighbor".
            ["neighbo", "adjchg", "adjchange", "nbr", "peer", "bgp", "ospf",
             // A routing session's TCP MD5 signature rejected (IOS `%TCP-6-BADAUTH`, Junos
             // `tcp_auth_ok`, Linux "MD5 Hash mismatch"): a routing fault, not an admin login.
             "md5", "tcp_auth", "badauth"],
            ["reboot", "restart", "reload", "cold start", "coldstart", "booted", "boot up", "bootup", "booting"],
            ["login", "logon", "log in", "logging in", "logged in", "password", "authenticat", "invalid user"],
            ["config", "commit", "write mem", "-111010", "-111008"],
        ]
        groups = words.enumerated().map { i, w in (i, w.map { strdup($0)! }) }
    }
}

nonisolated enum LogScan {
    struct Output: Sendable {
        var facts: [LineFact] = []
        var warn: [WarnFact] = []
        var sources: [String: SourceAcc] = [:]
        var lines = 0
        var traps = 0
    }

    static func scan(_ entries: [LogEntry]) -> Output {
        let n = entries.count
        guard n > 0 else { return Output() }
        let cores = max(1, ProcessInfo.processInfo.activeProcessorCount)
        let chunks = max(1, min(cores * 3, n / 1_500))
        let per = (n + chunks - 1) / chunks
        let slots = ChunkSlots<Output>(chunks)
        DispatchQueue.concurrentPerform(iterations: chunks) { c in
            let lo = c * per, hi = min(n, lo + per)
            guard lo < hi else { slots.set(c, Output()); return }
            slots.set(c, scanRange(entries, lo, hi))
        }
        var out = Output()
        for part in slots.values {
            out.facts += part.facts
            out.warn += part.warn
            out.lines += part.lines
            out.traps += part.traps
            for (k, v) in part.sources {
                if out.sources[k] == nil { out.sources[k] = v } else { out.sources[k]!.merge(v) }
            }
        }
        return out
    }

    private static func scanRange(_ entries: [LogEntry], _ lo: Int, _ hi: Int) -> Output {
        var out = Output()
        var accs: [String: SourceAcc] = [:]
        var lastAddress = ""
        var acc = SourceAcc()
        func flush() { if !lastAddress.isEmpty { accs[lastAddress] = acc } }
        for i in lo..<hi {
            let e = entries[i]
            if e.sourceAddress != lastAddress {
                flush()
                lastAddress = e.sourceAddress
                acc = accs[lastAddress] ?? SourceAcc()
            }
            let isTrap = e.transport == .trap || e.vendor == .snmpTrap
            acc.count += 1
            if isTrap { acc.trapCount += 1; out.traps += 1 } else { out.lines += 1 }
            if e.transport == .file { acc.transportFile = true }
            if e.received < acc.recvMin { acc.recvMin = e.received }
            if e.received > acc.recvMax { acc.recvMax = e.received }
            if let d = e.deviceTime {
                if acc.devMin.map({ d < $0 }) ?? true { acc.devMin = d }
                if acc.devMax.map({ d > $0 }) ?? true { acc.devMax = d }
                if acc.skews.count < 64 || i % 97 == 0, acc.skews.count < 256 {
                    acc.skews.append(e.received.timeIntervalSince(d))
                }
            }
            if !isTrap {
                if e.vendor == .unknown, LineClassifier.looksLikeKnownVendor(e.message) { acc.unknownVendor += 1 }
                if !e.hostname.isEmpty { acc.hostnames[e.hostname, default: 0] += 1 }
            }
            let sec = Int(e.received.timeIntervalSinceReferenceDate)
            if let last = acc.seconds.last, last.0 == sec { acc.seconds[acc.seconds.count - 1].1 += 1 }
            else { acc.seconds.append((sec, 1)) }
            if isTrap || e.severity <= .warning {
                out.warn.append(WarnFact(id: e.id, address: e.sourceAddress, hostname: e.hostname, isTrap: isTrap,
                                         received: e.received, deviceTime: e.deviceTime, severity: e.severity,
                                         text: isTrap ? e.program : e.message))
            }
            let kind: FactKind? = isTrap ? LineClassifier.trap(e) : LineClassifier.line(e)
            if let kind {
                out.facts.append(LineFact(id: e.id, address: e.sourceAddress, hostname: e.hostname, isTrap: isTrap,
                                          received: e.received, deviceTime: e.deviceTime, severity: e.severity,
                                          kind: kind, message: e.message))
            }
        }
        flush()
        out.sources = accs
        return out
    }
}

// MARK: - Reading one line

nonisolated enum LineClassifier {
    /// Firewall session logs never carry link, hardware or spanning-tree news: skipped unread
    /// (they are most of a busy log).
    static func isSessionLog(_ e: LogEntry) -> Bool {
        switch e.vendor {
        case .paloAlto:
            return CText.prefix(e.program, "TRAFFIC") || CText.prefix(e.program, "THREAT") || CText.prefix(e.program, "DECRYPTION")
        case .fortigate:
            return CText.prefix(e.program, "traffic") || CText.prefix(e.program, "utm")
        case .checkPoint:
            return CText.contains(e.program, "Fire") || CText.contains(e.program, "Threat") || CText.contains(e.program, "IPS")
                || CText.contains(e.program, "Anti") || CText.contains(e.program, "URL") || CText.contains(e.program, "Application")
        default:
            return false
        }
    }

    /// A line vendor detection left as "Other" that carries a supported vendor's marks (a
    /// FortiGate line missing `logid=`, a Huawei `%%01` line in an odd header, an AOS-CX event
    /// relayed with a prefix): the per-source vendor setting would read its fields. Plain
    /// RFC 3164 / 5424 lines (Cisco, Linux, a NAS) are "Other" by design — counting them told a
    /// busy Cisco switch or Linux server its format was unknown.
    static let vendorMarks = ["devname=", "devid=", "logid=", "%%0", "%%1", "Event|", "CPPM_", "Common.", "product=", "product:",
                              ",TRAFFIC,", ",THREAT,", ",SYSTEM,", ",CONFIG,", ",GLOBALPROTECT,", "|LOG_"]

    static func looksLikeKnownVendor(_ message: String) -> Bool {
        message.withCString { c in vendorMarks.contains { strstr(c, $0) != nil } }
    }

    static func line(_ e: LogEntry) -> FactKind? {
        if isSessionLog(e) { return nil }
        return e.message.withCString { c -> FactKind? in
            var bits: UInt8 = 0
            // Cisco IOS's own form puts the mnemonic in the program (`%LINK-3-UPDOWN`,
            // `%BGP-5-ADJCHANGE`) and leaves "Interface Gi0/1, changed state to down" /
            // "neighbor 203.0.113.1 Up" as the message: the program is screened too (those lines
            // were never read — a BGP peer that came back stayed "down and has not come back").
            // Junos's structured form (RFC 5424) puts `SNMP_TRAP_LINK_DOWN` in the MSGID and
            // leaves the message "ifIndex 526, … ifName ge-0/0/12" (or nothing but its SD): the
            // MSGID (the parser's first field) is screened too.
            let msgid = e.fields.first.flatMap { $0.key == "msgid" ? $0.value : nil } ?? ""
            e.program.withCString { pc in
                msgid.withCString { mc in
                    for g in Needles.shared.groups {
                        for n in g.needles where strcasestr(c, n) != nil || strcasestr(pc, n) != nil || strcasestr(mc, n) != nil {
                            bits |= 1 << UInt8(g.group)
                            break
                        }
                    }
                }
            }
            func hit(_ g: Int) -> Bool { bits & (1 << UInt8(g)) != 0 }
            let any = bits != 0
            // Palo Alto CONFIG and AOS-CX hpe-config lines say so in the program.
            let configProgram = CText.contains(e.program, "config")
            guard any || configProgram else { return nil }
            if hit(Needles.link), let k = link(e, c) { return k }
            if hit(Needles.hardware), let k = hardware(e, c) { return k }
            if hit(Needles.stp), let k = stp(e, c) { return k }
            if hit(Needles.routing), let k = routing(e, c) { return k }
            if hit(Needles.reboot), let k = reboot(e, c) { return k }
            if hit(Needles.login), let k = login(e, c) { return k }
            if hit(Needles.config) || configProgram, let k = config(e, c) { return k }
            return nil
        }
    }

    // Link

    static func link(_ e: LogEntry, _ c: UnsafePointer<CChar>) -> FactKind? {
        if CText.has(c, "lldp") || CText.has(c, "neighbor") { return nil }
        // An admin's shutdown (Cisco / NX-OS "administratively down", Junos's link trap with
        // ifAdminStatus down) is not a link failure.
        if CText.hasAny(c, ["administratively down", "ifadminstatus down"]) { return nil }
        // FortiOS: `logdesc="Interface status changed" action="interface-stat-change"
        // status="DOWN"` — the state is a field and the message never says "link".
        if e.vendor == .fortigate,
           e.field("action") == "interface-stat-change" || (e.field("logdesc")?.lowercased().contains("interface status") ?? false),
           let status = e.field("status")?.lowercased(), status.hasPrefix("up") || status.hasPrefix("down") {
            let iface = ["interface", "intf", "ifname", "port"].lazy.compactMap { e.field($0) }.first { !$0.isEmpty }
                ?? e.field("msg").flatMap { m in FText.token(after: "interface ", in: m) }
            guard let iface else { return nil }
            return .link(iface: iface, up: status.hasPrefix("up"))
        }
        // FortiOS link monitor (`logdesc="Link monitor status"`, msg "Link Monitor changed state
        // from alive to dead"): the gateway beyond the interface stopped answering — FortiOS
        // takes the link as down (its routes are withdrawn) until it is alive again.
        if e.vendor == .fortigate, e.field("logdesc")?.lowercased().contains("link monitor") ?? false,
           let msg = e.field("msg")?.lowercased(), let iface = e.field("interface") ?? e.field("name"), !iface.isEmpty {
            if msg.contains("to dead") || msg.contains("to die") { return .link(iface: iface, up: false) }
            if msg.contains("to alive") { return .link(iface: iface, up: true) }
            return nil
        }
        // PAN-OS SYSTEM `link-change`: "Port ethernet1/3: Down 1Gb/s-full duplex" / "Port
        // ethernet1/3: Up …"; `ha1-link-change` / `ha2-link-change`: "HA2 link down". The state
        // is in the description column, which never says "link down" (never read).
        if e.vendor == .paloAlto, let ev = e.field("eventid"), ev.hasSuffix("link-change"), let d = e.field("description") {
            return paloLinkChange(d)
        }
        // Junos structured: MSGID SNMP_TRAP_LINK_DOWN / _UP, the port and statuses in the SD
        // (`interface-name`, `admin-status`, `operational-status`).
        if let msgid = e.fields.first, msgid.key == "msgid", msgid.value.hasPrefix("SNMP_TRAP_LINK_") {
            func sd(_ name: String) -> String? { e.fields.first { $0.key.hasSuffix("." + name) }?.value }
            if sd("admin-status")?.lowercased().hasPrefix("down") ?? false { return nil }
            if CText.has(c, "ifadminstatus down") { return nil }
            guard let iface = sd("interface-name") ?? FText.token(after: "ifName ", in: e.message), !iface.isEmpty else { return nil }
            return .link(iface: iface, up: msgid.value.hasPrefix("SNMP_TRAP_LINK_UP"))
        }
        if let k = kernelFlagsLink(e, c) { return k.up.map { .link(iface: k.iface, up: $0) } }
        if CText.hasAny(c, errDisableWords) { return errDisabled(e, c) }
        var up: Bool?
        if let s = e.field("OperStatus") { up = s.uppercased().hasPrefix("UP") }
        // Ruckus ICX: "Interface ethernet 1/1/5, state down"; Meraki MS: "port 3 status changed
        // from 1Gfdx to down" (neither says "link": both were never read).
        else if CText.has(c, ", state down") { up = false }
        else if CText.has(c, ", state up") { up = true }
        else if CText.has(c, "status changed from"), CText.hasAny(c, [" to down", "from down to "]) {
            up = !CText.has(c, " to down")
        }
        else if CText.hasAny(c, ["link down", "linkdown", "link_down", "link is down", "link status for interface", "off-line",
                             "changed state to down", "entered the down state", "link failure", "went down", "turned into down state"]) {
            up = CText.hasAny(c, ["link status for interface"]) ? !CText.has(c, " is down") : false
        } else if CText.hasAny(c, ["link up", "linkup", "link_up", "link is up", "on-line", "changed state to up",
                               "entered the up state", "came up", "turned into up state"]) {
            up = true
        } else if CText.has(c, " is down") {
            up = false
        } else if CText.has(c, " is up") {
            up = true
        }
        guard let up else { return nil }
        guard let iface = interfaceName(e) else { return nil }
        return .link(iface: iface, up: up)
    }

    /// FRR / Quagga zebra's "interface eth0 index 2 changed <UP,BROADCAST,MULTICAST>": the
    /// kernel's flags — RUNNING (carrier) gone with UP (admin) kept is the link down, RUNNING
    /// back is up, no UP is an admin's shutdown (nothing), a loopback is nothing. nil: not
    /// such a line; `up` nil: such a line that is no link event.
    static func kernelFlagsLink(_ e: LogEntry, _ c: UnsafePointer<CChar>) -> (iface: String, up: Bool?)? {
        let m = e.message
        let name = CText.has(c, " index ") ? FText.token(after: "interface ", in: m) : ipMonitorInterface(m)
        guard let iface = name, let open = m.firstIndex(of: "<"), let close = m[open...].firstIndex(of: ">") else { return nil }
        let flags = Set(m[m.index(after: open)..<close].uppercased().split(separator: ",").map(String.init))
        guard !flags.isDisjoint(with: ["BROADCAST", "POINTOPOINT", "MULTICAST", "LOOPBACK", "RUNNING", "UP"]) else { return nil }
        if flags.contains("LOOPBACK") || !flags.contains("UP") { return (iface, nil) }
        // A container host's bridges and veth pairs come and go with their containers: docker0
        // is NO-CARRIER whenever no container runs — that is no port that went down.
        if virtualInterfacePrefixes.contains(where: { iface.lowercased().hasPrefix($0) }) { return (iface, nil) }
        return (iface, !flags.contains("NO-CARRIER") && (flags.contains("RUNNING") || flags.contains("LOWER_UP")))
    }

    /// PAN-OS `link-change` descriptions: "Port ethernet1/3: Down 1Gb/s-full duplex", "Port
    /// ae1: Up …", "HA2 link down" / "HA1 link up (primary)".
    static func paloLinkChange(_ d: String) -> FactKind? {
        let lower = d.lowercased()
        if lower.hasPrefix("port "), let colon = d.firstIndex(of: ":") {
            let name = d[d.index(d.startIndex, offsetBy: 5)..<colon].trimmingCharacters(in: .whitespaces)
            let state = d[d.index(after: colon)...].trimmingCharacters(in: .whitespaces).lowercased()
            guard !name.isEmpty else { return nil }
            if state.hasPrefix("down") { return .link(iface: name, up: false) }
            if state.hasPrefix("up") { return .link(iface: name, up: true) }
            return nil
        }
        if let r = lower.range(of: " link ") {
            let name = String(d[..<r.lowerBound]).trimmingCharacters(in: .whitespaces)
            let rest = lower[r.upperBound...]
            guard !name.isEmpty, !name.contains(" ") else { return nil }
            if rest.hasPrefix("down") || rest.hasPrefix("is down") { return .link(iface: name, up: false) }
            if rest.hasPrefix("up") || rest.hasPrefix("is up") { return .link(iface: name, up: true) }
        }
        return nil
    }

    /// The words of a port shut by the switch for an error (IOS / AOS-CX err-disable, Huawei
    /// error-down, NX-OS "Error disabled").
    static let errDisableWords = ["err-disable", "errdisable", "err_disable", "error-down", "error disabled", "error_disabled"]
    static let recoverWords = ["recover", "re-enabl", "reenabl", "timer expired"]

    /// Why the switch shut the port, in words an engineer acts on (nil: no cause it can read).
    static func errDisableCause(_ m: String) -> String? {
        let l = m.lowercased()
        let causes: [([String], String)] = [
            (["link-flap", "link flap"], "the link went up and down too often (link-flap)"),
            (["crc"], "too many CRC errors — a bad cable, optic or port"),
            (["mac-address-flap", "mac-flap", "macflap", "mac flap"], "a MAC address kept moving between ports — usually a loop, or a host attached twice"),
            (["transceiver", "sfp", "gbic", "power-low", "optic"], "the optic is out of range — dirty, failing, or a fibre too long"),
            (["psecure", "port-security", "portsec", "port security"], "port security — more MAC addresses than allowed, or one it does not know"),
            (["udld"], "UDLD found a one-way link — a fibre pair crossed or one strand broken"),
            (["arp-inspection", "arp inspection"], "dynamic ARP inspection — ARP over the rate limit"),
            (["dhcp-rate-limit", "dhcp rate", "dhcp snooping"], "DHCP snooping — DHCP packets over the rate limit"),
            (["no-lacpdu", "lacp"], "LACP — no LACPDUs from the other end (the member is not in the partner's bundle)"),
            (["dual-active"], "a stack split (dual-active)"),
            (["auto-defend"], "attack defence — a flood of packets to the CPU from the port"),
        ]
        for (words, text) in causes where words.contains(where: { l.contains($0) }) { return text }
        for marker in ["cause=", "reason:", "reason="] {
            if let r = l.range(of: marker) {
                let v = l[r.upperBound...].prefix { $0 != "," && $0 != ")" }.trimmingCharacters(in: .whitespaces)
                if !v.isEmpty { return v }
            }
        }
        if let r = l.range(of: " error detected") {
            let v = l[..<r.lowerBound].split(separator: " ").last.map(String.init) ?? ""
            if !v.isEmpty, !v.contains(":") { return v }
        }
        return nil
    }

    static let virtualInterfacePrefixes = ["docker", "veth", "br-", "virbr", "cni", "flannel", "cali", "vnet", "lxc", "podman"]

    /// Linux `ip monitor link` / `ip link` output relayed to syslog: "3: eth1: <NO-CARRIER,…>
    /// mtu 1500 … state DOWN", "5: vlan10@eth0: <…>". A "Deleted 3: veth…" line is not a port.
    static func ipMonitorInterface(_ m: String) -> String? {
        let parts = m.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard parts.count == 3, parts[0].count >= 2, parts[0].hasSuffix(":"), parts[0].dropLast().allSatisfy(\.isNumber),
              parts[1].count >= 2, parts[1].hasSuffix(":"), parts[2].hasPrefix("<") else { return nil }
        var name = parts[1].dropLast()
        if let at = name.firstIndex(of: "@") { name = name[..<at] }
        return name.isEmpty ? nil : String(name)
    }

    /// A port the switch shut because of an error — IOS `%PM-4-ERR_DISABLE: link-flap error
    /// detected on Gi1/0/5, putting Gi1/0/5 in err-disable state`, Huawei `ERRDOWN_DOWNNOTIFY …
    /// error-down. (InterfaceName=…, Cause=link-flap)`, AOS-CX "Port 1/1/5 is err-disabled …":
    /// that port down (it stays down until recovery or shut / no shut). A recovery attempt
    /// (`%PM-4-ERR_RECOVER`, `ERRDOWN_DOWNRECOVER`) is not the link back — the link-up line
    /// that follows is. A BPDU-guard / loop / storm cause is spanning tree's finding.
    static func errDisabled(_ e: LogEntry, _ c: UnsafePointer<CChar>) -> FactKind? {
        if CText.hasAny(c, recoverWords) { return nil }
        if CText.hasAny(c, ["bpdu", "loop", "storm"]) { return nil }
        let m = e.message
        let port = e.field("InterfaceName") ?? e.field("ifName")
            ?? FText.token(after: "putting ", in: m) ?? FText.token(after: "detected on ", in: m)
            ?? interfaceName(e) ?? FText.token(after: " on ", in: m)
        guard let port, !port.isEmpty else { return nil }
        return .link(iface: port, up: false)
    }

    static func interfaceName(_ e: LogEntry) -> String? {
        for k in ["ifName", "interface", "intf", "ifDescr", "port", "Interface", "InterfaceName"] {
            if let v = e.field(k), !v.isEmpty { return v }
        }
        let m = e.message
        for marker in ["interface ", "Interface ", "port ", "Port ", "ifName=", "ifName "] {
            if let t = FText.token(after: marker, in: m), !t.isEmpty, t.lowercased() != "status" {
                // Ruckus / Brocade: "Interface ethernet 1/1/5" — the type word, then the port.
                if ["ethernet", "ethe", "ve", "lag", "loopback", "tunnel", "management"].contains(t.lowercased()),
                   let n = FText.token(after: marker + t + " ", in: m), n.first?.isNumber ?? false {
                    return "\(t) \(n)"
                }
                return t
            }
        }
        // UniFi switches: "TRAPMGR: Link Down: 0/9" — the port follows (the word before " Link"
        // was every port's "TRAPMGR:", so all their events were one port flapping).
        for marker in ["link down: ", "link up: "] {
            if let t = FText.token(after: marker, in: m), !t.isEmpty { return t }
        }
        // "ether1 link down", "eth0 NIC Link is Down"
        if let r = m.range(of: " link", options: .caseInsensitive) {
            let words = m[..<r.lowerBound].split(separator: " ")
            if var w = words.last.map(String.init) {
                if w.uppercased() == "NIC", words.count >= 2 { w = String(words[words.count - 2]) }
                w = w.trimmingCharacters(in: CharacterSet(charactersIn: ":,;"))
                if !w.isEmpty, w.count <= 40, !w.contains("%") { return w }
            }
        }
        return nil
    }

    // Hardware

    static let failWords = ["fail", "fault", "error", "removed", "absent", "not present", "lost", "stopped", " down",
                            "denied", "exceed", "over threshold", "overheat", "too high", " high", "critical", "alarm",
                            "insufficient", "shutdown", "shut down", "abnormal", "unavailable", "overload", "not ok",
                            "budget", "rising", "warning", "offline", "removal"]
    static let okWords = ["recovered", "restored", "normal", "back to", "cleared", "inserted", "resumed", " ok", "returned", "online"]

    static func hardware(_ e: LogEntry, _ c: UnsafePointer<CChar>) -> FactKind? {
        let kind: HardwareKind
        // Junos calls a power supply a PEM (power entry module).
        if CText.hasAny(c, ["power supply", "power_supply", "powersupply", "power-supply"]) || CText.hasWord(c, "psu") || CText.hasWord(c, "pem") { kind = .psu }
        else if CText.hasWord(c, "fan") || CText.has(c, "fan tray") || CText.has(c, "fantray") { kind = .fan }
        else if CText.hasAny(c, ["temperat", "thermal", "overheat"]) { kind = .temperature }
        else if CText.hasWord(c, "poe") || CText.hasAny(c, ["power denied", "power budget", "insufficient power", "power limit"]) { kind = .poe }
        else { return nil }
        // Thresholds a line merely states ("warning threshold 70C", "high threshold 90C") are
        // not what happened: "Temperature sensor 2 is normal, warning threshold 70C" was a
        // temperature failure.
        let stated = hardwareText(e.message)
        let failed = stated.withCString { CText.hasAny($0, failWords) }
        let ok = stated.withCString { CText.hasAny($0, okWords) }
        // A fan's speed following the temperature ("Fan speed adjusted to 60%", "… to high")
        // is the fan doing its job.
        if kind == .fan, CText.hasAny(c, ["speed adjusted", "speed changed", "speed set", "speed increased", "speed decreased"]),
           !CText.hasAny(c, ["fail", "fault", "stopped", "stall", "removed", "absent", "not present", "not spinning", "too low", "below"]) {
            return nil
        }
        // Neither a failure nor a recovery word: a warning or worse is one ("fan module 2 status"
        // at warning) — unless the line is a reading against its thresholds ("CPU temperature
        // 45C, high threshold 90C" at warning was a temperature failure).
        let reading = stated.contains("threshold")
        if !failed && !ok && (e.severity > .warning || reading) { return nil }
        if kind == .poe && !failed { return nil }
        return .hardware(kind, recovered: ok && !failed)
    }

    /// The message without the thresholds it states.
    static func hardwareText(_ m: String) -> String {
        var t = m.lowercased()
        guard t.contains("threshold") else { return t }
        for w in ["warning", "high", "critical", "alarm", "shutdown", "low", "major", "minor"] {
            t = t.replacingOccurrences(of: w + " threshold", with: "threshold")
            t = t.replacingOccurrences(of: w + "-threshold", with: "threshold")
        }
        return t
    }

    // Spanning tree, loops, storms

    static func stp(_ e: LogEntry, _ c: UnsafePointer<CChar>) -> FactKind? {
        // A routing protocol's own "topology change" (OSPF / IS-IS SPF runs) or "AS path loop"
        // is not spanning tree: read as STP, a BGP path loop was a layer-2 loop.
        if isRoutingProtocolLine(e, c), !CText.hasAny(c, ["spanning", "stp", "bpdu", "vlan"]),
           !CText.contains(e.program, "STP"), !CText.contains(e.program, "SPANTREE") {
            return nil
        }
        // An error-down / err-disable recovery ("Attempting to recover from bpduguard
        // err-disable state", Huawei ERRDOWN_DOWNRECOVER … Cause=bpdu-protection) is the port
        // coming back, not another BPDU guard action (each was counted twice).
        if CText.hasAny(c, errDisableWords), CText.hasAny(c, recoverWords) { return nil }
        // Huawei names the port in a field and says "Notify interface to change status to
        // error-down" ("interface to" made the port "to"): the field first, and a port has a digit.
        let port = [e.field("InterfaceName"), FText.token(after: "port ", in: e.message),
                    FText.token(after: "interface ", in: e.message), FText.token(after: "putting ", in: e.message)]
            .lazy.compactMap { $0 }.first { $0.contains { $0.isNumber } }
        if CText.hasWord(c, "loop") && CText.hasAny(c, ["detect", "protect", "found", "block", "disabl", "loop-protect"]) {
            return .stp(.loop, port: port)
        }
        // Huawei `Cause=loopback-detect` (an error-down by loop detection), IOS's `loopback error
        // detected` (a keepalive that came back): a loop — "loopback" is no whole word "loop".
        if CText.hasAny(c, ["loopback-detect", "loopback detect", "loopback error", "loop-detect", "loopdetect"]) {
            return .stp(.loop, port: port)
        }
        if CText.has(c, "storm") && CText.hasAny(c, ["detect", "exceed", "control", "block", "threshold", "drop", "storm-control"]) {
            return .stp(.storm, port: port)
        }
        if CText.has(c, "bpdu") && CText.hasAny(c, ["guard", "protect", "block", "disabl", "shut", "err"]) {
            return .stp(.bpduGuard, port: port)
        }
        if CText.hasAny(c, ["topology change", "topologychange", "topology_change", "topology changed", "tcn", "tc received",
                        "received tc", "tc-received"]) {
            return .stp(.topologyChange, port: port)
        }
        if CText.hasAny(c, ["root bridge", "new root", "root changed", "root change", "newroot", "became root", "root port changed"]) {
            return .stp(.rootChange, port: port)
        }
        return nil
    }

    static let routingWords = ["ospf", "is-is", "isis", "bgp", " spf", "spf ", "eigrp", "as path", "as-path", "as_path", "rip "]
    static let routingPrograms = ["OSPF", "BGP", "ISIS", "EIGRP", "ospfd", "bgpd", "isisd", "zebra", "rpd", "ROUTING-"]

    static func isRoutingProtocolLine(_ e: LogEntry, _ c: UnsafePointer<CChar>) -> Bool {
        CText.hasAny(c, routingWords) || routingPrograms.contains { CText.contains(e.program, $0) }
    }

    // Routing neighbours

    static func routing(_ e: LogEntry, _ c: UnsafePointer<CChar>) -> FactKind? {
        // OSPF's own forms first: FRR's "auth-type mismatch, local MD5, … Router-ID x" says MD5
        // and names this router's address first (the TCP MD5 reading took that as the peer).
        if let k = ospfAuthFailure(e, c) { return k }
        if let k = sessionAuthFailure(e, c) { return k }
        let proto: String
        let p = e.program
        if CText.has(c, "notification") || CText.contains(p, "NOTIFICATION"),
           let notice = bgpNotification(e, c) { return notice }
        if CText.has(c, "ospf") || CText.contains(p, "OSPF") || e.field("module") == "OSPF" { proto = "OSPF" }
        else if CText.has(c, "bgp") || CText.contains(p, "BGP") { proto = "BGP" }
        else if CText.has(c, "eigrp") || CText.contains(p, "EIGRP") || CText.contains(p, "DUAL") { proto = "EIGRP" }
        else if CText.hasAny(c, ["isis", "is-is"]) || CText.contains(p, "ISIS") || CText.contains(p, "CLNS") { proto = "IS-IS" }
        else if CText.has(c, "bfd") || CText.contains(p, "BFD") { proto = "BFD" }
        else { return nil }
        var up: Bool?
        // A change from one state to another (Arista / FRR "old state X … new state Y", Junos
        // "changed state from X to Y", Huawei "changed from ESTABLISHED to IDLE" and its
        // NeighborPreviousState / NeighborCurrentState, FRR / Quagga / FortiOS ospfd "Full ->
        // Deleted"): reaching Full / Established is up, leaving it is down, reaching Down is
        // down, and the steps between are neither ("Idle" in Junos's "from Idle to Connect"
        // read as a down; Huawei's Down → Init was a down and Init → 2Way an up, so one OSPF
        // reset read as "went down 2 times" and a neighbor stuck before Full as back up).
        if let change = stateChange(e) {
            guard let u = transitionUp(old: change.old, new: change.new) else {
                guard change.old != change.new else { return nil }
                let neighbor = e.field("NeighborAddress") ?? e.field("PeerAddress") ?? neighborAddress(e.message) ?? "?"
                return neighbor == "?" ? nil : .routingStep(proto: proto, neighbor: neighbor)
            }
            up = u
        }
        // PAN-OS SYSTEM routing: "BGP peer session entered / left established state".
        else if CText.hasAny(c, ["entered established", "enter-established", "enter established"]) { up = true }
        else if CText.hasAny(c, ["left established", "left-established", "leave established"]) { up = false }
        else if CText.hasAny(c, ["to down", "neighbor down", "neighbour down", "changed to down", "state down", " down", "idle", "dead timer", "hold time expired"]) {
            up = CText.hasAny(c, ["to full", "to up"]) && !CText.has(c, "to down") ? true : false
        } else if CText.hasAny(c, ["to full", " up", "established", "to up", "went full"]) {
            // NX-OS: "Nbr 10.0.13.2 on Ethernet1/49 went FULL".
            up = true
        }
        guard let up else { return nil }
        let neighbor = e.field("NeighborAddress") ?? e.field("PeerAddress") ?? neighborAddress(e.message) ?? "?"
        // A line that names no neighbor is about one only when it says so ("neighbor down"):
        // "bgpd shutting down" or "OSPF process 1 is down" are no neighbor that went down.
        if neighbor == "?", !CText.hasAny(c, ["neighbo", "nbr", "adjch"]) { return nil }
        return .routing(proto: proto, neighbor: neighbor, up: up)
    }

    /// A routing session's TCP MD5 signature missing or wrong: IOS `%TCP-6-BADAUTH: Invalid MD5
    /// digest from 10.0.0.2(179) to 10.0.0.1(11003)`, Junos `tcp_auth_ok: Packet from
    /// 10.0.0.2:179 missing MD5 digest`, Linux (FRR's kernel) `MD5 Hash mismatch for (10.0.0.2,
    /// 179)->(10.0.0.1, 40312)`, bgpd "MD5 authentication failed". The peer is the sender; the
    /// protocol is BGP for TCP 179 or a line that says so, LDP for 646, MSDP for 639.
    static func sessionAuthFailure(_ e: LogEntry, _ c: UnsafePointer<CChar>) -> FactKind? {
        guard CText.hasAny(c, ["md5", "tcp_auth", "tcp-ao", "badauth"]) || CText.contains(e.program, "BADAUTH") else { return nil }
        guard CText.hasAny(c, ["digest", "hash", "authenticat", "badauth", "tcp_auth", "signature", "mismatch", "md5 fail"])
                || CText.contains(e.program, "BADAUTH") else { return nil }
        // A password stored as an MD5 hash, an MD5 checksum of a file: not a session.
        guard !CText.hasAny(c, ["checksum", "password hash", "image", "file "]) else { return nil }
        let m = e.message
        let peer = FText.firstIPv4(after: "from", in: m) ?? FText.firstIPv4(after: "neighbor", in: m)
            ?? FText.firstIPv4(after: "peer", in: m) ?? FText.firstIPv4(after: "", in: m, excluding: e.sourceAddress)
            ?? FText.firstIPv6(after: "from", in: m)
        guard let peer else { return nil }
        let proto: String
        if CText.has(c, "ospf") || CText.contains(e.program, "OSPF") { proto = "OSPF" }
        else if CText.hasAny(c, ["(646)", ":646", ", 646)", "ldp"]) { proto = "LDP" }
        else if CText.hasAny(c, ["(639)", ":639", ", 639)", "msdp"]) { proto = "MSDP" }
        else { proto = "BGP" }
        return .routingAuth(proto: proto, neighbor: peer)
    }

    /// OSPF packets dropped for their authentication: IOS `%OSPF-4-ERRRCV: Received invalid
    /// packet: Mismatched Authentication type / Key … from 10.0.12.2, Gi0/1`, FRR ospfd
    /// "interface eth1:10.0.15.5: auth-type mismatch, local MD5, rcvd Null, Router-ID 10.255.0.2",
    /// Junos "OSPF packet ignored: authentication failure (bad password) from 10.0.14.6". They
    /// read as failed admin logins from the neighbor ("invalid" + "authentication"), or not at
    /// all. The neighbor is the sender (FRR names its router ID; the address in "eth1:10.0.15.5"
    /// is this router's own) — else the interface it came in on.
    static func ospfAuthFailure(_ e: LogEntry, _ c: UnsafePointer<CChar>) -> FactKind? {
        guard CText.has(c, "ospf") || CText.contains(e.program, "OSPF") || CText.contains(e.program, "ospfd") else { return nil }
        guard CText.hasAny(c, ["mismatched authentication", "mismatch authentication", "auth-type mismatch", "authentication type mismatch",
                               "authentication failure", "authentication failed", "auth failed", "authentication key", "key-id",
                               "bad password", "authentication error", "auth type mismatch"]) else { return nil }
        let m = e.message
        if let peer = FText.firstIPv4(after: "router-id", in: m) ?? FText.firstIPv4(after: "from", in: m)
            ?? FText.firstIPv4(after: "neighbor", in: m) ?? FText.firstIPv4(after: "nbr", in: m)
            ?? FText.firstIPv6(after: "from", in: m) {
            return .routingAuth(proto: "OSPF", neighbor: peer)
        }
        guard var iface = FText.token(after: "interface ", in: m) else { return nil }
        if let colon = iface.firstIndex(of: ":") { iface = String(iface[..<colon]) }
        return iface.isEmpty ? nil : .routingAuth(proto: "OSPF", neighbor: "interface " + iface)
    }

    /// The neighbor a routing line names: the first IPv4 after "neighbor" / "nbr" / "peer", else
    /// an IPv6 one there (FRR "neighbor 2001:db8::2 Down": every IPv6 peer of a router was "?",
    /// one neighbor, so one peer coming up hid another that stayed down).
    static func neighborAddress(_ m: String) -> String? {
        for marker in ["neighbor", "nbr", "peer"] {
            if let v4 = FText.firstIPv4(after: marker, in: m) { return v4 }
        }
        for marker in ["neighbor", "nbr", "peer"] {
            if let v6 = FText.firstIPv6(after: marker, in: m) { return v6 }
        }
        return nil
    }

    /// Adjacency states as the vendors spell them, reduced to a word ("FULL/DR" → full,
    /// "2-Way" → 2way, "ESTABLISHED." → established).
    static let adjacencyStates: Set<String> = ["established", "idle", "connect", "active", "opensent", "openconfirm", "full", "down",
                                               "init", "attempt", "2way", "exstart", "exchange", "loading", "deleted", "up"]

    static func stateWord(_ s: Substring) -> String? {
        let w = s.drop { !$0.isLetter && !$0.isNumber }.prefix { $0.isLetter || $0.isNumber || $0 == "-" }
            .lowercased().replacingOccurrences(of: "-", with: "")
        return adjacencyStates.contains(w) ? w : nil
    }

    /// The previous and the new adjacency state a line reports (the previous one may be unknown).
    static func stateChange(_ e: LogEntry) -> (old: String?, new: String)? {
        if let cur = e.field("NeighborCurrentState"), let new = stateWord(Substring(cur)) {
            return (e.field("NeighborPreviousState").flatMap { stateWord(Substring($0)) }, new)
        }
        let m = e.message
        if let r = m.range(of: "new state ", options: .caseInsensitive), let new = stateWord(m[r.upperBound...]) {
            let old = m.range(of: "old state ", options: .caseInsensitive).flatMap { stateWord(m[$0.upperBound...]) }
            return (old, new)
        }
        // "from X to Y", both of them states (not "received from neighbor 10.0.0.2 to …").
        var search = m.startIndex..<m.endIndex
        while let r = m.range(of: "from ", options: .caseInsensitive, range: search) {
            search = r.upperBound..<m.endIndex
            let rest = m[r.upperBound...]
            guard let old = stateWord(rest), let to = rest.range(of: " to ", options: .caseInsensitive),
                  rest.distance(from: rest.startIndex, to: to.lowerBound) <= 14, let new = stateWord(rest[to.upperBound...]) else { continue }
            return (old, new)
        }
        // ospfd's AdjChg: "… on eth0:10.0.0.1: Full -> Deleted (InactivityTimer)".
        if let r = m.range(of: " -> ") {
            let before = m[..<r.lowerBound].split(separator: " ").last ?? ""
            if let new = stateWord(m[r.upperBound...]), let old = stateWord(before) { return (old, new) }
        }
        return nil
    }

    /// Up (reached Full / Established), down (left it, or reached Down / Deleted), or nothing
    /// (a step between, or no change).
    static func transitionUp(old: String?, new: String) -> Bool? {
        let upStates: Set<String> = ["full", "established", "up"]
        if old == new { return nil }
        if upStates.contains(new) { return true }
        if let old, upStates.contains(old) { return false }
        if new == "down" || new == "deleted" { return false }
        // BGP Idle from anything but Established (Active → Idle while it retries a peer that
        // is not there) is the session not up yet; with no previous state, the session gone.
        if new == "idle", old == nil { return false }
        return nil
    }

    /// `%BGP-3-NOTIFICATION: sent to neighbor 10.0.0.2 4/0 (hold time expired) 0 bytes` (IOS),
    /// `… received from neighbor 10.0.0.2 (VRF default AS 65002) 4/0 (Hold Timer Expired
    /// Error/Unspecific) 0 bytes` (Arista). An adjacency line that also names a notification
    /// (IOS XR "neighbor … Down - BGP Notification sent, hold time expired") stays a down.
    static func bgpNotification(_ e: LogEntry, _ c: UnsafePointer<CChar>) -> FactKind? {
        let m = e.message
        let sent: Bool
        let after: String
        // Junos: `bgp_peer_mgmt_clear:6969: NOTIFICATION sent to 10.0.0.2 (External AS 65002):
        // code 6 (Cease) subcode 4 (Administratively Reset), Reason: …` (no "neighbor": it was
        // never read, and the Junos peer's down had no reason).
        if let r = m.range(of: "sent to neighbor", options: .caseInsensitive) ?? m.range(of: "notification sent to", options: .caseInsensitive) {
            sent = true; after = String(m[r.upperBound...])
        } else if let r = m.range(of: "received from neighbor", options: .caseInsensitive)
                    ?? m.range(of: "notification received from", options: .caseInsensitive) {
            sent = false; after = String(m[r.upperBound...])
        } else { return nil }
        guard let neighbor = FText.firstIPv4(after: "", in: after) ?? FText.token(after: " ", in: after) else { return nil }
        // The reason: the parentheses after the "code/subcode" pair (IOS, Arista), or Junos's
        // "code 6 (Cease) subcode 4 (Administratively Reset)".
        var reason = ""
        if let code = after.range(of: #"\d+/\d+\s*\("#, options: .regularExpression) {
            reason = String(after[code.upperBound...].prefix { $0 != ")" })
        } else if let code = after.range(of: #"code \d+ \("#, options: .regularExpression) {
            reason = String(after[code.upperBound...].prefix { $0 != ")" })
            let tail = after[code.upperBound...]
            if let sub = tail.range(of: #"^[^)]*\) subcode \d+ \("#, options: .regularExpression) {
                reason += "/" + String(tail[sub.upperBound...].prefix { $0 != ")" })
            }
        }
        return .routingNotice(proto: "BGP", neighbor: neighbor, reason: reason, sent: sent)
    }

    // Restarts

    static func reboot(_ e: LogEntry, _ c: UnsafePointer<CChar>) -> FactKind? {
        let cold = CText.hasAny(c, ["cold start", "coldstart", "power on", "power-on", "power cycle"])
        let system = cold || CText.hasAny(c, ["system restart", "system reboot", "device restart", "switch restart", "chassis",
                                          "system is rebooting", "rebooting", "reboot", "reload", "%sys-5-restart",
                                          "system boot", "booted", "boot up", "bootup", "system start", "restarted"])
        guard system else { return nil }
        // "systemctl restart nginx": a service, not the device.
        if !cold && CText.has(c, "restart") && !CText.hasAny(c, ["system", "device", "switch", "chassis", "unit", "router", "reboot", "reload", "member", "firewall", "restarted"]) {
            return nil
        }
        if CText.hasAny(c, ["restart nginx", "systemctl", "service restart", "process restart", "restarting process", "daemon"]) { return nil }
        let planned = CText.hasAny(c, ["requested", "by user", "by admin", "reload by", "reboot by", "scheduled", "initiated by", "command"])
        return .reboot(cold: cold, planned: planned)
    }

    // Admin logins

    static func login(_ e: LogEntry, _ c: UnsafePointer<CChar>) -> FactKind? {
        // 802.1X / MAC auth of clients is the Authentication pane's, not an admin login.
        if e.vendor == .clearPass || CText.hasAny(c, ["802.1x", "dot1x", "mac-auth", "mac auth", "radius", "wpa", "captive"]) { return nil }
        // A routing protocol's packets or neighbors failing their authentication are the
        // routing rules' (an OSPF key mismatch read as failed logins from the neighbor).
        if isRoutingProtocolLine(e, c), CText.hasAny(c, ["packet", "neighbor", "neighbour", "nbr", "adjacen", "peer", "router-id"]) { return nil }
        let failed = CText.hasAny(c, ["fail", "invalid", "denied", "incorrect", "wrong", "reject", "unsuccessful", "bad password",
                                  "result=failure", "not allowed", "authentication error"])
        let ok = !failed && CText.hasAny(c, ["success", "succeeded", "accepted", "logged in", "session opened", "result=success"])
        guard failed || ok else { return nil }
        guard CText.hasAny(c, ["login", "logon", "log in", "logging in", "logged in", "password", "authenticat", "user", "ssh", "telnet"]) else { return nil }
        let ip = ["srcip", "src", "UserIp", "UserAddress", "ip", "client_ip", "remote_ip", "rhost", "source", "Ip", "remote-address"]
            .lazy.compactMap { e.field($0) }.first { FText.isIPv4($0) }
            ?? FText.firstIPv4(after: "from", in: e.message) ?? FText.firstIPv4(after: "", in: e.message, excluding: e.sourceAddress)
        let user = ["user", "UserName", "username", "usr", "administrator", "srcuser"].lazy.compactMap { e.field($0) }.first
            ?? FText.token(after: "user ", in: e.message) ?? FText.token(after: "for ", in: e.message)
        return failed ? .loginFail(ip: ip, user: user) : .loginOK(ip: ip, user: user)
    }

    // Configuration changes

    static func config(_ e: LogEntry, _ c: UnsafePointer<CChar>) -> FactKind? {
        let paloConfig = e.vendor == .paloAlto && CText.prefix(e.program, "CONFIG")
        let fortiConfig = e.vendor == .fortigate && (e.field("cfgpath") != nil || e.field("cfgattr") != nil)
        // Junos: `mgd: UI_COMMIT: User 'netops' requested 'commit' operation` (the structured
        // form carries UI_COMMIT as its MSGID); progress lines are not changes.
        let msgid = e.field("msgid") ?? ""
        let junosCommit = ((CText.has(c, "ui_commit") || msgid.hasPrefix("UI_COMMIT"))
                           && !CText.has(c, "ui_commit_progress") && !msgid.hasPrefix("UI_COMMIT_PROGRESS"))
            || (CText.has(c, "requested 'commit'") && !CText.has(c, "commit check"))
        // Cisco ASA: 111010 "User 'admin' … executed 'no shutdown'" (a configuration command),
        // 111008 for `write memory`, 111005 "end configuration: OK".
        let asaConfig = CText.contains(e.program, "%ASA-")
            && (CText.contains(e.program, "-111010") || CText.contains(e.program, "-111005")
                || (CText.contains(e.program, "-111008") && CText.hasAny(c, ["'write mem", "'copy running-config", "'copy run"])))
        let change = paloConfig || fortiConfig || junosCommit || asaConfig
            || (CText.has(c, "config") && CText.hasAny(c, ["change", "changed", "configured", "commit", "saved", "modif", "config_i",
                                                    "write mem", "cfg_change", "edited", "updated"]))
            || (CText.has(c, "commit") && CText.hasAny(c, ["success", "complete", "succeeded", " by "]))
        guard change else { return nil }
        if CText.hasAny(c, ["fail", "error", "invalid"]) && !paloConfig { return nil }
        let user = ["user", "UserName", "username", "admin", "administrator", "srcuser"].lazy.compactMap { e.field($0) }.first
            ?? e.fields.first { $0.key.hasSuffix(".username") }?.value
            // IOS XR: "Configuration committed by user 'admin'." (was the user "user").
            ?? FText.token(after: " by user ", in: e.message)
            ?? FText.token(after: " by ", in: e.message)
            ?? ((junosCommit || asaConfig) ? FText.token(after: "user ", in: e.message) : nil)
        return .config(user: user)
    }

    // Traps

    static let trapOIDs: [String: String] = [
        "1.3.6.1.6.3.1.1.5.1": "coldStart", "1.3.6.1.6.3.1.1.5.2": "warmStart", "1.3.6.1.6.3.1.1.5.3": "linkDown",
        "1.3.6.1.6.3.1.1.5.4": "linkUp", "1.3.6.1.2.1.17.0.1": "newRoot", "1.3.6.1.2.1.17.0.2": "topologyChange",
    ]

    static func trap(_ e: LogEntry) -> FactKind? {
        var name = e.program
        if name.first?.isNumber ?? false, let n = trapOIDs[e.field("trap_oid") ?? name] { name = n }
        switch name {
        case "linkDown", "linkUp":
            var iface: String?
            var index: String?
            for f in e.fields {
                if f.key.hasPrefix("ifName.") || f.key.hasPrefix("ifDescr.") { iface = iface ?? f.value }
                if f.key.hasPrefix("ifIndex.") || f.key.hasPrefix("ifIndex") { index = index ?? f.value }
            }
            return .link(iface: iface ?? index.map { "ifIndex \($0)" } ?? "?", up: name == "linkUp")
        case "coldStart": return .reboot(cold: true, planned: false)
        case "warmStart": return .reboot(cold: false, planned: true)
        case "newRoot": return .stp(.rootChange, port: nil)
        case "topologyChange": return .stp(.topologyChange, port: nil)
        default:
            return name.withCString { c -> FactKind? in
                let kind: HardwareKind
                if CText.hasAny(c, ["psu", "powersupply", "power_supply", "supply"]) { kind = .psu }
                else if CText.hasWord(c, "fan") || CText.has(c, "fan") { kind = .fan }
                else if CText.hasAny(c, ["temperat", "thermal", "sensor"]) { kind = .temperature }
                else if CText.has(c, "poe") || CText.hasAny(c, ["pethpsemain", "pethmain", "pethpsu"]) { kind = .poe }
                else { return nil }
                let ok = CText.hasAny(c, ["ok", "normal", "clear", "recover", "on"]) && !CText.hasAny(c, ["fail", "fault", "off", "alarm", "high"])
                return .hardware(kind, recovered: ok)
            }
        }
    }
}

// MARK: - Log rules

nonisolated extension FindingRules {
    static func linkRules(_ ctx: inout RuleContext) -> [Finding] {
        struct Key: Hashable { let device: String; let iface: String }
        var groups: [Key: [(t: Date, up: Bool, f: LineFact)]] = [:]
        // A port by its full name: IOS's err-disable line says "Gi1/0/5" and its link line
        // "GigabitEthernet1/0/5" — two ports, so the one that came back stayed "down and has
        // not come back". Every spelling seen goes into the evidence filter.
        var spellings: [Key: Set<String>] = [:]
        for f in ctx.facts {
            guard case .link(let iface, let up) = f.kind else { continue }
            let key = Key(device: ctx.device(f), iface: FText.canonicalInterface(iface))
            groups[key, default: []].append((ctx.time(f), up, f))
            spellings[key, default: []].insert(iface)
        }
        var out: [Finding] = []
        for (key, raw) in groups {
            // The same change said twice (a physical and a protocol line, a trap and a line) counts once.
            var events: [(t: Date, up: Bool, f: LineFact)] = []
            for e in raw.sorted(by: { $0.t < $1.t }) {
                if let last = events.last, last.up == e.up, e.t.timeIntervalSince(last.t) < 5 { continue }
                events.append(e)
            }
            let downs = events.filter { !$0.up }
            let f0 = events[0].f
            let address = f0.address
            let evidence = logEvidence(ids: raw.filter { !$0.f.isTrap }.map(\.f.id), trapIDs: raw.filter { $0.f.isTrap }.map(\.f.id),
                                       query: ctx.hostTerm(address: address, name: key.device) + " " + FText.wordTerms(spellings[key] ?? [key.iface]),
                                       trapQuery: "host:\(raw.first { $0.f.isTrap }?.f.address ?? address) (app:linkDown OR app:linkUp)"
                                        + (key.iface == "?" || key.iface.hasPrefix("ifIndex ") ? "" : " " + FText.wordTerms(spellings[key] ?? [key.iface])))
            // Flapping: ≥ 3 downs inside any 10 minutes.
            var best = (count: 0, from: 0, to: 0)
            var lo = 0
            for hi in downs.indices {
                while downs[hi].t.timeIntervalSince(downs[lo].t) > flapWindow { lo += 1 }
                if hi - lo + 1 > best.count { best = (hi - lo + 1, lo, hi) }
            }
            if best.count >= flapCount {
                let first = downs[best.from].t, last = events.last!.t
                let span = downs[best.to].t.timeIntervalSince(downs[best.from].t)
                let stillDown = !(events.last!.up)
                var f = Finding(id: "link.flap|\(key.device)|\(key.iface)", rule: "link.flap", severity: .bad, category: .link,
                                source: raw.allSatisfy { $0.f.isTrap } ? .traps : .logs,
                                title: "Port \(key.iface) on \(key.device) went down \(downs.count) times in \(FText.duration(max(60, downs.last!.t.timeIntervalSince(downs[0].t)))) (\(FText.clock(first))–\(FText.clock(downs.last!.t))).",
                                detail: "The link went down \(best.count) times within \(FText.duration(max(1, span)))"
                                    + (stillDown ? " and came back every time but the last" : " and came back each time") + " — a flapping port. "
                                    + "Every flap drops traffic, restarts spanning tree on that port and can trigger topology changes elsewhere. "
                                    + (stillDown ? "It is down now (last change \(FText.clock(last))). " : "It was up at the last change (\(FText.clock(last))). ")
                                    + "Usual causes: a bad cable or optic, a duplex or speed mismatch, a powered device rebooting, or a loop-protect / BPDU action.",
                                evidence: evidence, firstSeen: events[0].t, lastSeen: last, count: downs.count,
                                device: key.device, deviceAddress: address)
                f.nextSteps = ["Quick test SNMP on \(key.device) and walk the Interfaces table — look at \(key.iface)'s errors and last change.",
                               "Check the cable, optic and the device on the other end of \(key.iface) (show interface \(key.iface) for CRC / input errors).",
                               "Show the log lines for \(key.iface) around \(FText.clock(first))."]
                f.snmpTarget = address
                out.append(f)
            } else if let lastDown = downs.last, !events.last!.up,
                      ctx.input.now.timeIntervalSince(lastDown.t) > downStuck {
                var f = Finding(id: "link.down|\(key.device)|\(key.iface)", rule: "link.down", severity: .warn, category: .link,
                                source: lastDown.f.isTrap ? .traps : .logs,
                                title: "Port \(key.iface) on \(key.device) went down at \(FText.clock(lastDown.t)) and has not come back.",
                                detail: "No link-up for \(key.iface) was seen in the \(FText.duration(ctx.input.now.timeIntervalSince(lastDown.t))) since. "
                                    + (lastDown.f.message.withCString { CText.hasAny($0, LineClassifier.errDisableWords) }
                                       ? "The switch shut it itself (err-disabled: “\(FText.excerpt(lastDown.f.message))”): it stays down until error-disable recovery brings it back or someone enters shutdown / no shutdown, and it goes down again if the cause is still there. "
                                        + (LineClassifier.errDisableCause(lastDown.f.message).map { "The cause: \($0). " } ?? "")
                                       : "")
                                    + "If something should be connected there (an uplink, an AP, a server) it is unreachable through this port.",
                                evidence: evidence, firstSeen: lastDown.t, lastSeen: lastDown.t, count: downs.count,
                                device: key.device, deviceAddress: address)
                f.nextSteps = ["Check what is patched into \(key.iface) on \(key.device) and whether it has power.",
                               "Quick test SNMP on \(key.device) and walk the Interfaces table: admin up, oper down means no link."]
                f.snmpTarget = address
                out.append(f)
            }
        }
        return out
    }

    static func hardwareRules(_ ctx: inout RuleContext) -> [Finding] {
        struct Key: Hashable { let device: String; let kind: HardwareKind }
        var groups: [Key: [(t: Date, recovered: Bool, f: LineFact)]] = [:]
        for f in ctx.facts {
            guard case .hardware(let kind, let rec) = f.kind else { continue }
            groups[Key(device: ctx.device(f), kind: kind), default: []].append((ctx.time(f), rec, f))
        }
        var out: [Finding] = []
        for (key, raw) in groups {
            let items = raw.sorted { $0.t < $1.t }
            let failures = items.filter { !$0.recovered }
            guard let worst = failures.min(by: { $0.f.severity < $1.f.severity }) ?? items.first else { continue }
            let recoveredAfter = items.last!.recovered && !failures.isEmpty
            if failures.isEmpty { continue }
            let address = worst.f.address
            var sev: FindingSeverity
            switch key.kind {
            case .psu, .fan: sev = .bad
            case .temperature: sev = worst.f.severity <= .critical || failures.contains { $0.f.message.lowercased().contains("shut") } ? .bad : .warn
            case .poe: sev = .warn
            }
            if recoveredAfter { sev = .info }
            let quote = FText.excerpt(worst.f.message)
            let what: String
            switch key.kind {
            case .psu: what = "a power supply problem"
            case .fan: what = "a fan problem"
            case .temperature: what = "a temperature alarm"
            case .poe: what = "PoE power problems"
            }
            let why: String
            switch key.kind {
            case .psu: why = "With one supply failed the device has no redundancy left; if it was the only one, it runs on borrowed time or is already off."
            case .fan: why = "A failed fan raises the temperature; many switches shut ports or power down when they overheat."
            case .temperature: why = "Overheating shortens hardware life and can make the device shut down ports or itself."
            case .poe: why = "Ports that are denied power leave phones, APs and cameras dark; the PoE budget or a per-port limit is exhausted."
            }
            var f = Finding(id: "hw.\(key.kind.rawValue)|\(key.device)", rule: "hw.\(key.kind.rawValue)", severity: sev, category: .hardware,
                            source: raw.allSatisfy { $0.f.isTrap } ? .traps : .logs,
                            title: "\(key.device) reported \(what)\(failures.count > 1 ? " (\(failures.count)×)" : ""): “\(quote)”",
                            detail: "\(failures.count == 1 ? "One line" : "\(failures.count) lines") from \(key.device) between \(FText.clock(failures.first!.t)) and \(FText.clock(failures.last!.t)). " + why
                                + (recoveredAfter ? " A later line (\(FText.clock(items.last!.t))) says it recovered." : ""),
                            evidence: logEvidence(ids: items.filter { !$0.f.isTrap }.map(\.f.id), trapIDs: items.filter { $0.f.isTrap }.map(\.f.id),
                                                  query: ctx.hostTerm(address: address, name: key.device) + " " + FText.hardwareQuery(key.kind),
                                                  trapQuery: "host:\(address) vendor:trap"),
                            firstSeen: items.first!.t, lastSeen: items.last!.t, count: failures.count,
                            device: key.device, deviceAddress: address)
            switch key.kind {
            case .psu: f.nextSteps = ["Check the supply's LED and power cord / PDU on \(key.device) (show environment power).", "Open a hardware case if the supply stays failed."]
            case .fan: f.nextSteps = ["Check the fan tray on \(key.device) (show environment fan) and the air flow around the rack.", "Watch the temperature lines that follow."]
            case .temperature: f.nextSteps = ["Check the room / rack cooling and the fans of \(key.device) (show environment temperature)."]
            case .poe: f.nextSteps = ["Check the PoE budget on \(key.device) (show power-over-ethernet) and which ports draw most.", "Move high-power devices or set per-port priorities."]
            }
            f.nextSteps.append("Quick test SNMP on \(key.device) to confirm it still answers.")
            f.snmpTarget = address
            out.append(f)
        }
        return out
    }

    static func stpRules(_ ctx: inout RuleContext) -> [Finding] {
        struct Key: Hashable { let device: String; let kind: STPKind }
        var groups: [Key: [(t: Date, port: String?, f: LineFact)]] = [:]
        for f in ctx.facts {
            guard case .stp(let kind, let port) = f.kind else { continue }
            groups[Key(device: ctx.device(f), kind: kind), default: []].append((ctx.time(f), port, f))
        }
        var out: [Finding] = []
        for (key, raw) in groups {
            let items = raw.sorted { $0.t < $1.t }
            var best = (count: 0, from: 0, to: 0)
            var lo = 0
            for hi in items.indices {
                while items[hi].t.timeIntervalSince(items[lo].t) > stpWindow { lo += 1 }
                if hi - lo + 1 > best.count { best = (hi - lo + 1, lo, hi) }
            }
            let serious = key.kind == .loop || key.kind == .storm
            let repeated = best.count >= stpRepeat
            guard serious || repeated || key.kind == .bpduGuard else { continue }
            let address = items[0].f.address
            let ports = Array(Set(items.compactMap(\.port))).sorted()
            let portText = ports.isEmpty ? "" : " on \(ports.count == 1 ? "port" : "ports") \(FText.list(ports, max: 4))"
            let title: String
            let detail: String
            var steps: [String] = []
            switch key.kind {
            case .topologyChange:
                let within = FText.duration(max(1, items[best.to].t.timeIntervalSince(items[best.from].t)))
                title = best.count == items.count
                    ? "\(items.count) spanning-tree topology changes on \(key.device) in \(within)\(portText)."
                    : "\(items.count) spanning-tree topology changes on \(key.device) (\(best.count) within \(within))\(portText)."
                detail = "Each topology change flushes the MAC tables, so switches flood unicast traffic until they re-learn — users see short stalls. "
                    + "Repeated changes mean a port keeps going up and down or a bridge keeps re-electing; edge ports without portfast / admin-edge also cause them."
                steps = ["Find the port that keeps changing: show spanning-tree detail on \(key.device) (\"last topology change … from port\").",
                         "Set client ports as edge ports (portfast / admin-edge) so they do not cause topology changes."]
            case .rootChange:
                title = "The spanning-tree root changed \(items.count) times on \(key.device)."
                detail = "A root bridge change re-converges the whole tree. Repeated changes usually mean a switch with a lower bridge priority keeps joining and leaving, or the root's uplinks are flapping."
                steps = ["Pin the root: set the core switch's spanning-tree priority explicitly (e.g. 4096).", "Check which bridge ID became root in these lines."]
            case .bpduGuard:
                // "BPDU guard shut port 1/1/9 on SW1" (it read "shut on port 1/1/9 on SW1").
                title = "BPDU guard shut \(ports.isEmpty ? "a port" : "\(ports.count == 1 ? "port" : "ports") \(FText.list(ports, max: 4))") on \(key.device) (\(items.count)×)."
                detail = "A switch or a bridging device was plugged into an edge port and BPDU guard disabled the port. It stays down until someone re-enables it or the recovery timer runs."
                steps = ["Find what is connected\(ports.first.map { " to \($0)" } ?? ""), remove the switch, then re-enable the port."]
            case .loop:
                title = "Loop detected on \(key.device)\(portText) (\(items.count)×)."
                detail = "The switch saw its own frames come back — a physical loop (a cable between two ports, an unmanaged switch looped, a phone's PC port). Loops flood the VLAN and take the network down."
                steps = ["Unplug the looped cable\(ports.first.map { " at \($0)" } ?? ""), then enable loop-protect / BPDU guard on edge ports."]
            case .storm:
                title = "Broadcast / multicast storm control acted on \(key.device)\(portText) (\(items.count)×)."
                detail = "Storm control dropped or blocked traffic over its threshold — often the sign of a loop or a misbehaving host flooding the VLAN."
                steps = ["Look for a loop on that VLAN and for a host sending the flood (Packets: filter by that port's VLAN, sort by source)."]
            }
            var f = Finding(id: "stp.\(key.kind.rawValue)|\(key.device)", rule: "stp.\(key.kind.rawValue)",
                            severity: serious ? .bad : .warn, category: .stp,
                            source: raw.allSatisfy { $0.f.isTrap } ? .traps : .logs,
                            title: title, detail: detail,
                            evidence: logEvidence(ids: items.filter { !$0.f.isTrap }.map(\.f.id), trapIDs: items.filter { $0.f.isTrap }.map(\.f.id),
                                                  query: ctx.hostTerm(address: address, name: key.device) + " " + FText.stpQuery(key.kind),
                                                  trapQuery: "host:\(address) (app:topologyChange OR app:newRoot)"),
                            firstSeen: items[0].t, lastSeen: items.last!.t, count: items.count,
                            device: key.device, deviceAddress: address, nextSteps: steps)
            f.snmpTarget = address
            out.append(f)
        }
        return out
    }

    static func routingRules(_ ctx: inout RuleContext) -> [Finding] {
        struct Key: Hashable { let device: String; let proto: String; let neighbor: String }
        var groups: [Key: [(t: Date, up: Bool, f: LineFact)]] = [:]
        var notices: [Key: [(t: Date, reason: String, sent: Bool, f: LineFact)]] = [:]
        var steps: [Key: [(t: Date, f: LineFact)]] = [:]
        var auth: [Key: [(t: Date, f: LineFact)]] = [:]
        for f in ctx.facts {
            if case .routingAuth(let proto, let nb) = f.kind {
                auth[Key(device: ctx.device(f), proto: proto, neighbor: nb), default: []].append((ctx.time(f), f))
                continue
            }
            if case .routingNotice(let proto, let nb, let reason, let sent) = f.kind {
                notices[Key(device: ctx.device(f), proto: proto, neighbor: nb), default: []].append((ctx.time(f), reason, sent, f))
                continue
            }
            if case .routingStep(let proto, let nb) = f.kind {
                steps[Key(device: ctx.device(f), proto: proto, neighbor: nb), default: []].append((ctx.time(f), f))
                continue
            }
            guard case .routing(let proto, let nb, let up) = f.kind else { continue }
            groups[Key(device: ctx.device(f), proto: proto, neighbor: nb), default: []].append((ctx.time(f), up, f))
        }
        var out: [Finding] = []
        for (key, raw) in groups {
            let items = raw.sorted { $0.t < $1.t }
            // Outages, not down lines: a down right after a down is the same outage (OSPF's
            // Full → Init then Init → Down, IOS's ADJCHANGE and its BGP_SESSION twin).
            let downs = items.indices.filter { i in !items[i].up && (i == 0 || items[i - 1].up) }.map { items[$0] }
            guard !downs.isEmpty else { continue }
            let stillDown = !items.last!.up
            let address = items[0].f.address
            let nb = key.neighbor == "?" ? "a neighbor" : key.neighbor
            let flapping = downs.count >= 2
            guard stillDown || flapping else { continue }
            // The NOTIFICATION that ended the last session (within 30 s before its down): says
            // whether the peer timed out or somebody reset it.
            let lastDown = downs.last!.t
            let why = notices[key]?.last { $0.t <= lastDown.addingTimeInterval(2) && $0.t >= lastDown.addingTimeInterval(-30) }
            let whyText = why.map { n in
                "The session ended with a NOTIFICATION \(n.sent ? "sent to" : "received from") the neighbor"
                    + (n.reason.isEmpty ? "." : ": \(n.reason).")
                    + (n.reason.lowercased().contains("administrative") ? " An administrative reset or shutdown is somebody's command, not a fault." : "")
                    + " "
            } ?? ""
            let f = Finding(id: "routing|\(key.device)|\(key.proto)|\(key.neighbor)", rule: "routing.neighbor",
                            severity: stillDown ? .bad : .warn, category: .routing, source: .logs,
                            title: stillDown
                                ? "\(key.proto) neighbor \(nb) on \(key.device) went down at \(FText.clock(downs.last!.t)) and has not come back."
                                : "\(key.proto) neighbor \(nb) on \(key.device) went down \(downs.count) times (\(FText.clock(downs[0].t))–\(FText.clock(downs.last!.t))).",
                            detail: whyText + "Routes learned from \(nb) are withdrawn while the adjacency is down, so traffic takes another path or none. "
                                + (flapping ? "A flapping adjacency usually follows a flapping link, MTU or timer mismatch, or a CPU-starved peer." : "Check the link to the neighbor and its \(key.proto) process."),
                            evidence: logEvidence(ids: (items.map(\.f.id) + (notices[key] ?? []).map(\.f.id)).sorted(), trapIDs: [],
                                                  query: ctx.hostTerm(address: address, name: key.device) + " " + key.proto.lowercased()
                                                    + (key.neighbor == "?" ? "" : " " + FText.quote(key.neighbor)),
                                                  trapQuery: ""),
                            firstSeen: items[0].t, lastSeen: items.last!.t, count: downs.count,
                            device: key.device, deviceAddress: address,
                            nextSteps: ["Check the \(key.proto) neighbor table on \(key.device) (show ip \(key.proto.lowercased()) neighbor).",
                                        "Check the link towards \(nb) for flaps and errors."])
            out.append(f)
        }
        // TCP MD5 signatures rejected: the session cannot come up (or drops at its next
        // keepalive) until both sides have the same password — a routing fault, which read as
        // "failed admin logins from 10.0.0.2" (FRR "MD5 authentication failed") or not at all.
        for (key, raw) in auth {
            let items = raw.sorted { $0.t < $1.t }
            guard let first = items.first, let last = items.last else { continue }
            // The session / adjacency came up after the last rejected packet: the keys were
            // put right (a mismatch fixed during a change window is no finding).
            if groups[key]?.contains(where: { $0.up && $0.t >= last.t }) ?? false { continue }
            let nb = key.neighbor
            let span = last.t.timeIntervalSince(first.t)
            if key.proto == "OSPF" {
                out.append(ospfAuthFinding(key.device, nb, items.map { ($0.t, $0.f) }, hostTerm: ctx.hostTerm(address: first.f.address, name: key.device)))
                continue
            }
            out.append(Finding(id: "routing.auth|\(key.device)|\(key.proto)|\(nb)", rule: "routing.authFail", severity: .bad,
                               category: .routing, source: .logs,
                               title: "\(key.proto) session with \(nb) on \(key.device) fails its MD5 authentication: \(items.count) segment\(items.count == 1 ? "" : "s") rejected"
                                + (items.count == 1 ? " at \(FText.clock(first.t))." : " (\(FText.clock(first.t))–\(FText.clock(last.t))).") ,
                               detail: "\(key.device) dropped TCP segments from \(nb) because their MD5 signature was missing or did not match. "
                                + "The two sides are configured with different passwords (or one side has none), so the \(key.proto) session "
                                + "cannot be established — or, if it was up, it fails at the next keepalive"
                                + (span >= 60 ? "; this went on for \(FText.duration(span))." : ".")
                                + " This is the routing session's password, not an administrator's login.",
                               evidence: logEvidence(ids: items.map(\.f.id), trapIDs: [],
                                                     query: ctx.hostTerm(address: first.f.address, name: key.device) + " md5 " + FText.quote(nb),
                                                     trapQuery: ""),
                               firstSeen: first.t, lastSeen: last.t, count: items.count,
                               device: key.device, deviceAddress: first.f.address,
                               nextSteps: ["Set the same \(key.proto) neighbor password on \(key.device) and on \(nb) (e.g. neighbor \(nb) password …), or remove it on both.",
                                           "Check \(nb) is the peer you expect: a segment signed with an old password may come from a device that was replaced."]))
        }
        // A neighbor that only ever steps between states (BGP Idle → Connect → Active → Idle,
        // OSPF stuck in ExStart) for minutes never came up. Its steps were "downs" before round
        // 15 ("went down and has not come back"); read as nothing, it was silent.
        for (key, raw) in steps where groups[key] == nil {
            let items = raw.sorted { $0.t < $1.t }
            guard items.count >= notUpSteps, let first = items.first, let last = items.last,
                  last.t.timeIntervalSince(first.t) >= notUpSpan else { continue }
            let nb = key.neighbor
            let target = key.proto == "OSPF" || key.proto == "IS-IS" ? "Full" : "Established"
            let why = key.proto == "OSPF"
                ? "The adjacency keeps starting and stops before Full: an MTU mismatch (stuck in ExStart / Exchange), an area, timer or authentication mismatch, or hellos that only one side hears."
                : "The session keeps starting and fails before it is established: the peer is unreachable or refuses TCP \(key.proto == "BGP" ? "179" : "connections"), is not configured for this router (address or AS), or the authentication (MD5 / TTL security) does not match."
            out.append(Finding(id: "routing.notUp|\(key.device)|\(key.proto)|\(nb)", rule: "routing.notUp", severity: .bad, category: .routing, source: .logs,
                               title: "\(key.proto) neighbor \(nb) on \(key.device) has not come up: \(items.count) state changes from \(FText.clock(first.t)) to \(FText.clock(last.t)), none to \(target).",
                               detail: why + " Nothing is learned from \(nb) meanwhile.",
                               evidence: logEvidence(ids: items.map(\.f.id), trapIDs: [],
                                                     query: ctx.hostTerm(address: first.f.address, name: key.device) + " " + key.proto.lowercased() + " " + FText.quote(nb),
                                                     trapQuery: ""),
                               firstSeen: first.t, lastSeen: last.t, count: items.count,
                               device: key.device, deviceAddress: first.f.address,
                               nextSteps: ["Check \(nb) answers from \(key.device) (ping with the session's source address)\(key.proto == "BGP" ? " and that TCP 179 is allowed" : "").",
                                           "Compare the neighbor configuration on both sides (\(key.proto == "OSPF" ? "area, MTU, timers, authentication" : "addresses, AS numbers, authentication"))."]))
        }
        return out
    }

    /// OSPF packets whose authentication (type or key) does not match: the adjacency cannot
    /// form, or drops when its dead timer runs out. `neighbor` is an address, or "interface
    /// eth1" when the line names none.
    static func ospfAuthFinding(_ device: String, _ neighbor: String, _ items: [(t: Date, f: LineFact)], hostTerm: String) -> Finding {
        let first = items[0], last = items[items.count - 1]
        let fromText = neighbor.hasPrefix("interface ") ? "received on \(neighbor)" : "from \(neighbor)"
        let what = last.f.message.withCString { c -> String in
            if CText.hasAny(c, ["type mismatch", "auth-type", "authentication type"]) { return "the two ends use different authentication types (none, plain text, MD5 / SHA)" }
            if CText.hasAny(c, ["key-id", "key id", "authentication key", "bad password", "md5", "digest"]) { return "the two ends have different keys (or key IDs)" }
            return "the authentication does not match"
        }
        let span = last.t.timeIntervalSince(first.t)
        let term = neighbor.hasPrefix("interface ") ? FText.wordTerm(String(neighbor.dropFirst(10))) : FText.quote(neighbor)
        return Finding(id: "routing.auth|\(device)|OSPF|\(neighbor)", rule: "routing.authFail", severity: .bad,
                       category: .routing, source: .logs,
                       title: "OSPF packets \(fromText) on \(device) fail authentication: \(items.count) rejected"
                        + (items.count == 1 ? " at \(FText.clock(first.t))." : " (\(FText.clock(first.t))–\(FText.clock(last.t)))."),
                       detail: "\(device) dropped OSPF packets \(fromText) because \(what): “\(FText.excerpt(last.f.message))”. "
                        + "No adjacency forms while they differ — or, if one was up, it goes down when the dead timer runs out"
                        + (span >= 60 ? "; this went on for \(FText.duration(span))." : ".")
                        + " This is the routing protocol's key, not an administrator's login.",
                       evidence: logEvidence(ids: items.map(\.f.id), trapIDs: [],
                                             query: hostTerm + " ospf " + term, trapQuery: ""),
                       firstSeen: first.t, lastSeen: last.t, count: items.count,
                       device: device, deviceAddress: first.f.address,
                       nextSteps: ["Set the same OSPF authentication (type, key ID and key) on the interface or area of \(device) and of the neighbor \(neighbor.hasPrefix("interface ") ? "on \(neighbor.dropFirst(10))" : neighbor).",
                                   "Check the neighbor comes up (show ip ospf neighbor) once both sides match."])
    }

    static func adminRules(_ ctx: inout RuleContext) -> [Finding] {
        var out: [Finding] = []
        // Configuration changes: one note per device, and remembered for the cross-reference.
        var configs: [String: [(t: Date, user: String?, f: LineFact)]] = [:]
        var reboots: [String: [(t: Date, cold: Bool, planned: Bool, f: LineFact)]] = [:]
        // Failed logins per device and source address: one device's console typos and another's
        // are not one attack, nor are two addresses' failures one burst.
        struct LoginKey: Hashable { let device: String; let ip: String? }
        var fails: [LoginKey: [(t: Date, device: String, user: String?, f: LineFact)]] = [:]
        var oks: [String: [(t: Date, device: String, user: String?)]] = [:]
        for f in ctx.facts {
            switch f.kind {
            case .config(let user):
                let d = ctx.device(f)
                configs[d, default: []].append((ctx.time(f), user, f))
                ctx.configEvents.append((d, ctx.time(f), user, f.id, f.message, f.address))
            case .reboot(let cold, let planned):
                reboots[ctx.device(f), default: []].append((ctx.time(f), cold, planned, f))
            case .loginFail(let ip, let user):
                let d = ctx.device(f)
                fails[LoginKey(device: d, ip: ip), default: []].append((ctx.time(f), d, user, f))
            case .loginOK(let ip, let user):
                if let ip { oks[ip, default: []].append((ctx.time(f), ctx.device(f), user)) }
            default: break
            }
        }
        for (device, raw) in configs {
            let items = raw.sorted { $0.t < $1.t }
            let users = Array(Set(items.compactMap(\.user))).sorted()
            let address = items[0].f.address
            // Changes, not lines: a Junos commit and its "commit complete", an ASA's commands and
            // its write memory, a minute apart at most, are one change.
            var changes = 0
            var last: Date?
            for it in items {
                if last.map({ it.t.timeIntervalSince($0) > configSameChange }) ?? true { changes += 1 }
                last = it.t
            }
            out.append(Finding(id: "config|\(device)", rule: "config.change", severity: .info, category: .config, source: .logs,
                               title: "Configuration changed on \(device)\(users.isEmpty ? "" : " by \(FText.list(users, max: 3))")"
                                   + (changes > 1 ? " (\(changes) changes, \(FText.clock(items[0].t))–\(FText.clock(items.last!.t)))." : " at \(FText.clock(items[0].t))."),
                               detail: "“\(FText.excerpt(items.last!.f.message))”. Changes are the usual cause of trouble that starts right after them — the findings that follow on this device say so when one came within 5 minutes before.",
                               evidence: logEvidence(ids: items.map(\.f.id), trapIDs: [],
                                                     query: ctx.hostTerm(address: address, name: device) + " " + FText.configQuery, trapQuery: ""),
                               firstSeen: items[0].t, lastSeen: items.last!.t, count: changes,
                               device: device, deviceAddress: address,
                               nextSteps: ["Compare the running configuration of \(device) with the last saved one (show archive / checkpoint diff)."]))
        }
        for (device, raw) in reboots {
            let items = raw.sorted { $0.t < $1.t }
            // A reload someone asked for is followed by the boot's own lines ("System restarted",
            // an SNMP cold start): those are the requested restart, not a crash.
            let explained = items.indices.map { k in
                items[k].planned || items[..<k].contains { $0.planned && items[k].t.timeIntervalSince($0.t) <= plannedBoot }
            }
            let unplanned = items.indices.contains { !explained[$0] }
            let cold = items.indices.contains { items[$0].cold && !explained[$0] }
            // Restarts, not lines: a request and its boot's lines, or lines of one boot (a
            // "System restarted" and the cold start a second later), are one ("3 times in all"
            // for one reload).
            var restarts = 0
            var lastLine: Date?, lastRequest: Date?
            for it in items {
                let sameBoot = lastLine.map { it.t.timeIntervalSince($0) <= 120 } ?? false
                let afterRequest = !it.planned && (lastRequest.map { it.t.timeIntervalSince($0) <= plannedBoot } ?? false)
                if !sameBoot && !afterRequest { restarts += 1 }
                if it.planned { lastRequest = it.t }
                lastLine = it.t
            }
            let address = items[0].f.address
            out.append(Finding(id: "reboot|\(device)", rule: "device.restart", severity: unplanned ? .warn : .info, category: .config,
                               source: items.allSatisfy { $0.f.isTrap } ? .traps : .logs,
                               title: "\(device) restarted at \(FText.clock(items.last!.t))\(cold ? " (cold start)" : "")\(restarts > 1 ? ", \(restarts) times in all" : "").",
                               detail: cold
                                   ? "A cold start means the device lost power or crashed and booted from scratch. Everything behind it was down while it booted."
                                   : (unplanned ? "The restart was not announced as requested by someone. Check whether it crashed (a crash file, show version \"last reload reason\")."
                                                : "The restart was requested (a reload or reboot command)."),
                               evidence: logEvidence(ids: items.filter { !$0.f.isTrap }.map(\.f.id), trapIDs: items.filter { $0.f.isTrap }.map(\.f.id),
                                                     // Every word the lines were picked by ("cold start" lines were hidden).
                                                     query: ctx.hostTerm(address: address, name: device)
                                                        + " (restart OR reboot OR reload OR boot OR coldstart OR warmstart OR \"cold start\" OR \"warm start\" OR \"power on\" OR \"power-on\" OR \"power cycle\")",
                                                     trapQuery: "host:\(address) (app:coldStart OR app:warmStart)"),
                               firstSeen: items[0].t, lastSeen: items.last!.t, count: restarts,
                               device: device, deviceAddress: address,
                               nextSteps: ["Check the reload reason on \(device) (show version / show system) and its power source (UPS, PDU).",
                                           "Quick test SNMP on \(device): sysUpTime says when it came back."],
                               snmpTarget: address))
        }
        // A known address failing on several devices (a script with an old password, someone
        // trying every switch): its failures across them, for the burst check.
        var bySource: [String: [(t: Date, device: String)]] = [:]
        for (key, raw) in fails { if let ip = key.ip { bySource[ip, default: []] += raw.map { ($0.t, $0.device) } } }
        func burst(_ times: [Date]) -> (count: Int, from: Date, to: Date) {
            let t = times.sorted()
            var best = (count: 0, from: Date.distantPast, to: Date.distantPast)
            var lo = 0
            for hi in t.indices {
                while t[hi].timeIntervalSince(t[lo]) > loginWindow { lo += 1 }
                if hi - lo + 1 > best.count { best = (hi - lo + 1, t[lo], t[hi]) }
            }
            return best
        }
        for (key, raw) in fails {
            let items = raw.sorted { $0.t < $1.t }
            let device = key.device
            let own = burst(items.map(\.t))
            let sourceDevices = key.ip.map { ip in Array(Set(bySource[ip]!.map(\.device))).sorted() } ?? [device]
            let spread = key.ip.flatMap { ip in sourceDevices.count > 1 ? burst(bySource[ip]!.map(\.t)) : nil }
            let isBurst = own.count >= loginBurst || (spread?.count ?? 0) >= loginBurst
            // One typo on one device is not a finding; one failure that is part of a source's
            // run across devices is.
            guard isBurst || items.count >= 2 else { continue }
            let users = Array(Set(items.compactMap(\.user))).sorted()
            let from = key.ip.map { " from \($0)" } ?? ""
            var detail = "\(items.count) failed login\(items.count == 1 ? "" : "s")\(users.isEmpty ? "" : " as \(FText.list(users, max: 4))")\(from) on \(device) between \(FText.clock(items[0].t)) and \(FText.clock(items.last!.t))."
            if key.ip == nil {
                detail += " The lines do not say where the attempts came from, so they are counted per device — they may be more than one source."
            }
            if own.count >= loginBurst {
                detail += " \(own.count) came within \(FText.duration(max(1, own.to.timeIntervalSince(own.from)))) — password guessing, or a script with an old password."
            }
            if let ip = key.ip, let spread, sourceDevices.count > 1 {
                let others = sourceDevices.filter { $0 != device }
                detail += " \(ip) also failed on \(FText.list(others, max: 4))"
                    + (spread.count >= loginBurst ? ": \(spread.count) failures across \(sourceDevices.count) devices within \(FText.duration(max(1, spread.to.timeIntervalSince(spread.from)))) — someone trying device after device, or a script with an old password." : ".")
            }
            if let ip = key.ip, let list = oks[ip] {
                let success = list.first { $0.t >= items[0].t && $0.device == device } ?? list.first { $0.t >= items[0].t }
                if let success {
                    detail += " Then a login from \(ip) succeeded at \(FText.clock(success.t)) on \(success.device)\(success.user.map { " as \($0)" } ?? "") — check that it was the owner."
                }
            }
            let title: String
            if let ip = key.ip {
                title = own.count >= loginBurst
                    ? "\(own.count) failed admin logins from \(ip) on \(device) in \(FText.duration(max(60, own.to.timeIntervalSince(own.from))))."
                    : "\(items.count) failed admin login\(items.count == 1 ? "" : "s") from \(ip) on \(device)"
                        + (sourceDevices.count > 1 ? " (and on \(sourceDevices.count - 1) other device\(sourceDevices.count == 2 ? "" : "s"))." : ".")
            } else {
                title = own.count >= loginBurst
                    ? "\(own.count) failed admin logins on \(device) in \(FText.duration(max(60, own.to.timeIntervalSince(own.from)))) (source not in the lines)."
                    : "\(items.count) failed admin logins on \(device) (source not in the lines)."
            }
            let address = items[0].f.address
            let q = ctx.hostTerm(address: address, name: device) + " " + (key.ip.map { FText.quote($0) + " " } ?? "") + FText.loginFailQuery
            out.append(Finding(id: "login.fail|\(device)|\(key.ip ?? "-")", rule: "login.failures", severity: isBurst ? .bad : .info,
                               category: .security, source: .logs,
                               title: title, detail: detail,
                               evidence: logEvidence(ids: items.map(\.f.id), trapIDs: [], query: q, trapQuery: ""),
                               firstSeen: items[0].t, lastSeen: items.last!.t, count: items.count,
                               device: device, deviceAddress: address,
                               client: key.ip,
                               nextSteps: key.ip.map { ip in
                                   ["Find who uses \(ip) (Troubleshoot client \(ip)) and whether it should manage \(device).",
                                    "Restrict management access (SSH / HTTPS / SNMP) to the admin subnet with an ACL."] }
                                   ?? ["Check the console / local logins on \(device) (show logging, show users) to see where they came from.",
                                       "Restrict management access to the admin subnet with an ACL."]))
        }
        return out
    }

    /// Clock, error spikes, undetected vendors (the log itself).
    static func hygieneRules(_ ctx: inout RuleContext) -> [Finding] {
        var out: [Finding] = []
        for (addr, acc) in ctx.sources {
            let name = ctx.nameByAddress[addr] ?? addr
            // Clock: the device's timestamps against arrival (live sources only).
            if !ctx.replayed.contains(addr), acc.skews.count >= 3 {
                let sorted = acc.skews.sorted()
                let median = sorted[sorted.count / 2]
                if abs(median) > clockSkew {
                    let hours = abs(median) / 3600
                    let zone = hours >= 0.9 && abs(hours - hours.rounded()) < 0.05
                    out.append(Finding(id: "clock|\(addr)", rule: "syslog.clock", severity: .warn, category: .config, source: .logs,
                                       title: "\(name)'s clock is \(FText.duration(abs(median))) \(median > 0 ? "behind" : "ahead of") this Mac.",
                                       detail: "Its log timestamps differ from when the lines arrived by \(FText.duration(abs(median))) (median of \(acc.skews.count) lines). "
                                           + (zone ? "A whole number of hours usually means a time-zone setting (UTC vs local), not a drifting clock. " : "")
                                           + "Wrong clocks make logs from different devices impossible to line up, and break certificates and SNMPv3.",
                                       evidence: [Evidence(kind: .logLines, label: "\(Format.count(acc.count)) log lines", ids: [],
                                                           query: ctx.hostTerm(address: addr, name: name))],
                                       firstSeen: acc.recvMin, lastSeen: acc.recvMax, count: acc.count,
                                       device: name, deviceAddress: addr,
                                       nextSteps: ["Configure NTP on \(name) (ntp server …) and check it is synchronised (show ntp status).",
                                                   zone ? "Check the time zone / clock timezone setting on \(name)." : "Check the device's NTP server is reachable."]))
                }
            }
            if acc.unknownVendor >= chattyUnknown, acc.trapCount < acc.count / 2 {
                out.append(Finding(id: "vendor|\(addr)", rule: "syslog.vendor", severity: .info, category: .config, source: .logs,
                                   title: "\(name) sent \(Format.count(acc.unknownVendor)) lines that look like a supported vendor's but were not recognised.",
                                   detail: "They carry a supported vendor's marks (FortiOS, Huawei, Aruba, Palo Alto, Check Point, ClearPass) but vendor detection left them “Other”: only the syslog header is read, so their fields — ports, users, addresses — cannot be filtered or used by these checks.",
                                   evidence: [Evidence(kind: .logLines, label: "\(Format.count(acc.unknownVendor)) log lines", ids: [],
                                                       query: ctx.hostTerm(address: addr, name: name) + " vendor:other")],
                                   firstSeen: acc.recvMin, lastSeen: acc.recvMax, count: acc.unknownVendor,
                                   device: name, deviceAddress: addr,
                                   nextSteps: ["If \(name) is an Aruba, Huawei, Fortinet, Palo Alto or Check Point device, set its vendor on the Sources pane.",
                                               "Otherwise switch its syslog format to RFC 5424 or key=value if it offers one."]))
            }
        }
        // Error spikes: a minute with ≥ 10× the source's usual error rate. Counted on every core,
        // the ids gathered for the peak minute only.
        let warn = ctx.warnFacts
        let frozen = ctx
        let parts = Parallel.chunks(warn.count, minimum: 4_000) { lo, hi -> [String: [Int: Int]] in
            var m: [String: [Int: Int]] = [:]
            for i in lo..<hi {
                let w = warn[i]
                guard !w.isTrap, w.severity <= .error else { continue }
                let t = frozen.time(w.address, received: w.received, device: w.deviceTime)
                m[w.address, default: [:]][Int(t.timeIntervalSinceReferenceDate / 60), default: 0] += 1
            }
            return m
        }
        var perSource: [String: [Int: Int]] = [:]
        for part in parts {
            for (addr, minutes) in part {
                for (k, v) in minutes { perSource[addr, default: [:]][k, default: 0] += v }
            }
        }
        for (addr, minutes) in perSource {
            guard let lo = minutes.keys.min(), let hi = minutes.keys.max(), hi - lo >= 9 else { continue }
            let total = minutes.values.reduce(0, +)
            guard let top = minutes.max(by: { $0.value < $1.value }) else { continue }
            let others = Double(total - top.value) / Double(hi - lo)      // per other minute
            let usual = max(others, 0.5)
            guard top.value >= 10, Double(top.value) >= spikeFactor * usual else { continue }
            let ids = warn.filter { w in
                !w.isTrap && w.severity <= .error && w.address == addr
                    && Int(ctx.time(w.address, received: w.received, device: w.deviceTime).timeIntervalSinceReferenceDate / 60) == top.key
            }.map(\.id)
            let peak = (key: top.key, value: ids)
            let name = ctx.nameByAddress[addr] ?? addr
            let t = Date(timeIntervalSinceReferenceDate: Double(peak.key) * 60)
            out.append(Finding(id: "spike|\(addr)", rule: "syslog.errorSpike", severity: .warn, category: .capacity, source: .logs,
                               title: "\(name) logged \(peak.value.count) errors in the minute at \(FText.clock(t)) — \(Int(Double(peak.value.count) / usual))× its usual rate.",
                               detail: "Over \(hi - lo + 1) minutes it averaged \(String(format: "%.1f", others)) error lines a minute outside that one. A sudden burst of errors usually has one cause worth finding: read the first lines of the burst.",
                               evidence: [Evidence(kind: .logLines, label: "\(peak.value.count) log lines", ids: peak.value,
                                                   query: ctx.hostTerm(address: addr, name: name) + " sev:<=err")],
                               firstSeen: t, lastSeen: t.addingTimeInterval(59), count: peak.value.count,
                               device: name, deviceAddress: addr,
                               nextSteps: ["Show \(name)'s error lines and read the first ones of the burst."]))
        }
        return out
    }

    static func capacityRules(_ c: EngineCounters, _ ctx: inout RuleContext) -> [Finding] {
        var out: [Finding] = []
        let now = ctx.input.now
        for (addr, acc) in ctx.sources where !ctx.replayed.contains(addr) {
            let busy = acc.seconds.filter { $0.1 >= floodRate }
            guard busy.count >= 5, let peak = acc.seconds.max(by: { $0.1 < $1.1 }) else { continue }
            let name = ctx.nameByAddress[addr] ?? addr
            let first = Date(timeIntervalSinceReferenceDate: Double(busy[0].0))
            out.append(Finding(id: "rate|\(addr)", rule: "capacity.logRate", severity: .warn, category: .capacity, source: .engine,
                               title: "\(name) sent over \(Format.count(floodRate)) lines/s for \(busy.count) s (peak \(Format.count(peak.1))/s).",
                               detail: "A flood like this fills the log buffer in minutes and pushes every other device's lines out. It is usually debug logging left on, a session log of every packet, or a device in trouble repeating itself.",
                               evidence: [Evidence(kind: .logLines, label: "\(Format.count(acc.count)) log lines", ids: [],
                                                   query: ctx.hostTerm(address: addr, name: name))],
                               firstSeen: first, lastSeen: Date(timeIntervalSinceReferenceDate: Double(busy.last!.0)), count: acc.count,
                               device: name, deviceAddress: addr,
                               nextSteps: ["Lower \(name)'s logging level or turn off per-session / debug logging.", "Show its lines to see what repeats."]))
        }
        if c.logLost > 0 {
            out.append(Finding(id: "capacity.logLost", rule: "capacity.logLost", severity: .warn, category: .capacity, source: .engine,
                               title: "\(Format.count(c.logLost)) syslog lines were lost before they reached the table.",
                               detail: "Lines arrived faster than SheepLog could take them in (or past the pause buffer). The findings may miss events from those moments.",
                               firstSeen: now, lastSeen: now, count: c.logLost,
                               nextSteps: ["Turn on disk logging in Settings: the disk log keeps every line received.", "Find the chattiest source on the Sources pane."]))
        }
        if c.packetLost > 0 {
            out.append(Finding(id: "capacity.packetLost", rule: "capacity.packetLost", severity: .warn, category: .capacity, source: .engine,
                               title: "The capture lost \(Format.count(c.packetLost)) packets (kernel or back-pressure drops).",
                               detail: "Missing packets look like retransmissions, unanswered DHCP and DNS, and gaps — packet findings may be worse than the network is.",
                               firstSeen: now, lastSeen: now, count: c.packetLost,
                               nextSteps: ["Capture with a BPF filter (Settings ▸ Capture filter) to take in only what matters.", "Capture on a wired interface rather than Wi-Fi."]))
        }
        if c.logLimit > 0, c.logCount >= c.logLimit, c.logDropped > c.logLost {
            out.append(Finding(id: "capacity.logFull", rule: "capacity.logBuffer", severity: .info, category: .capacity, source: .engine,
                               title: "The log buffer is full (\(Format.count(c.logLimit)) lines): \(Format.count(c.logDropped - c.logLost)) older lines rolled out.",
                               detail: "Findings only cover the lines still in memory. Raise the buffer in Settings or turn on disk logging to keep more.",
                               firstSeen: now, lastSeen: now, count: c.logDropped - c.logLost,
                               nextSteps: ["Raise “Keep in memory” in Settings, or filter noisy sources at the device."]))
        }
        if c.packetLimit > 0, c.packetCount >= c.packetLimit, c.packetDropped > c.packetLost {
            out.append(Finding(id: "capacity.packetFull", rule: "capacity.packetBuffer", severity: .info, category: .capacity, source: .engine,
                               title: "The packet buffer is full (\(Format.count(c.packetLimit)) packets): the oldest ones rolled out.",
                               detail: "Packet findings only cover what is still in memory.",
                               firstSeen: now, lastSeen: now, count: c.packetDropped - c.packetLost,
                               nextSteps: ["Save the capture (Packets ▸ Save) before it rolls further, or raise the packet buffer in Settings."]))
        }
        return out
    }

    /// A configuration change on the same device within 5 minutes before a link, spanning-tree
    /// or routing finding is named in that finding (the nearest one; another device's when this
    /// one made none).
    static func crossReference(_ findings: inout [Finding], _ ctx: inout RuleContext) {
        guard !ctx.configEvents.isEmpty else { return }
        let changes = ctx.configEvents.sorted { $0.time < $1.time }
        for i in findings.indices {
            let f = findings[i]
            guard f.rule.hasPrefix("link.") || f.rule.hasPrefix("stp.") || f.rule.hasPrefix("routing.") else { continue }
            // Changes in [firstSeen − 5 min, firstSeen]: a binary search, then a short walk back.
            var lo = 0, hi = changes.count
            while lo < hi { let mid = (lo + hi) / 2; if changes[mid].time <= f.firstSeen { lo = mid + 1 } else { hi = mid } }
            var before: [(device: String, time: Date, user: String?, id: Int, message: String, address: String)] = []
            var j = lo - 1
            while j >= 0, f.firstSeen.timeIntervalSince(changes[j].time) <= configLead { before.insert(changes[j], at: 0); j -= 1 }
            guard let change = before.last(where: { $0.device == f.device }) ?? before.last else { continue }
            let lead = f.firstSeen.timeIntervalSince(change.time)
            let same = change.device == f.device
            findings[i].detail += " A configuration change on \(same ? "this device" : change.device)\(change.user.map { " by \($0)" } ?? "") at \(FText.clock(change.time)) came \(FText.duration(max(1, lead))) before this started — check what was changed."
            findings[i].evidence.append(Evidence(kind: .logLines, label: "config change", ids: [change.id],
                                                 query: ctx.hostTerm(address: change.address, name: change.device) + " " + FText.configQuery))
            findings[i].nextSteps.insert("Review the change made on \(change.device) at \(FText.clock(change.time)) and roll it back if it caused this.", at: 0)
        }
    }

    static func logEvidence(ids: [Int], trapIDs: [Int], query: String, trapQuery: String) -> [Evidence] {
        var out: [Evidence] = []
        if !ids.isEmpty {
            out.append(Evidence(kind: .logLines, label: "\(Format.count(ids.count)) log line\(ids.count == 1 ? "" : "s")", ids: ids, query: query))
        }
        if !trapIDs.isEmpty {
            out.append(Evidence(kind: .traps, label: "\(Format.count(trapIDs.count)) trap\(trapIDs.count == 1 ? "" : "s")", ids: trapIDs, query: trapQuery))
        }
        return out
    }
}

// MARK: - Packet pass

nonisolated struct DHCPFact: Sendable {
    let id: Int
    let time: Date
    let type: String
    let clientMAC: String
    let xid: UInt32
    let server: String?
    let lease: UInt32?
    let yourIP: String?
    let vlan: UInt16?
    /// Between a relay agent and the server (UDP 67 → 67): a copy of a client's message or of
    /// the server's answer on its way to the relay, not what the client's segment saw.
    var relayHop = false
}

nonisolated struct DNSFact: Sendable {
    let id: Int
    let time: Date
    let isResponse: Bool
    let client: String
    let clientPort: UInt16
    let server: String
    let txid: UInt16
    let name: String
    let rcode: Int
}

nonisolated struct ARPFact: Sendable {
    let id: Int
    let time: Date
    let isRequest: Bool
    let senderMAC: String
    let senderIP: String
    let targetIP: String
    let vlan: UInt16?
}

nonisolated struct ICMPFact: Sendable {
    let id: Int
    let time: Date
    let type: UInt8
    let router: String
    let destination: String
    /// Where the expired / redirected packet was going (the quoted IPv4 header).
    var probeDestination: String? = nil
}

nonisolated enum PacketScan {
    struct Output: Sendable {
        var dhcp: [DHCPFact] = []
        var dns: [DNSFact] = []
        var arp: [ARPFact] = []
        var icmp: [ICMPFact] = []
        var start: Date?
        var end: Date?
    }

    static func scan(_ packets: [Packet]) -> Output {
        let n = packets.count
        guard n > 0 else { return Output() }
        let cores = max(1, ProcessInfo.processInfo.activeProcessorCount)
        let chunks = max(1, min(cores * 3, n / 4_000))
        let per = (n + chunks - 1) / chunks
        let slots = ChunkSlots<Output>(chunks)
        DispatchQueue.concurrentPerform(iterations: chunks) { c in
            let lo = c * per, hi = min(n, lo + per)
            var out = Output()
            if lo < hi {
                for i in lo..<hi {
                    let p = packets[i]
                    if out.start.map({ p.timestamp < $0 }) ?? true { out.start = p.timestamp }
                    if out.end.map({ p.timestamp > $0 }) ?? true { out.end = p.timestamp }
                    visit(p, &out)
                }
            }
            slots.set(c, out)
        }
        var out = Output()
        for part in slots.values {
            out.dhcp += part.dhcp
            out.dns += part.dns
            out.arp += part.arp
            out.icmp += part.icmp
            if let a = part.start { out.start = min(out.start ?? a, a) }
            if let b = part.end { out.end = max(out.end ?? b, b) }
        }
        return out
    }

    private static func visit(_ p: Packet, _ out: inout Output) {
        let d = p.decoded
        if let a = d.arp {
            out.arp.append(ARPFact(id: p.id, time: p.timestamp, isRequest: a.isRequest, senderMAC: a.senderMAC,
                                   senderIP: a.senderIP, targetIP: a.targetIP, vlan: d.vlan))
            return
        }
        if let icmp = d.icmp, let ip = d.ip, ip.version == 4, icmp.type == 11 || icmp.type == 5 {
            var inner: String?
            let o = d.payloadOffset
            if o > 0, p.data.count >= o + 20 {
                let b = p.data.startIndex + o
                if p.data[b] >> 4 == 4 { inner = "\(p.data[b + 16]).\(p.data[b + 17]).\(p.data[b + 18]).\(p.data[b + 19])" }
            }
            out.icmp.append(ICMPFact(id: p.id, time: p.timestamp, type: icmp.type, router: ip.source, destination: ip.destination,
                                     probeDestination: inner))
            return
        }
        switch d.app {
        case .dhcp(let type, let mac, let yi)?:
            let opts = dhcpOptions(p.data, d.payloadOffset)
            out.dhcp.append(DHCPFact(id: p.id, time: p.timestamp, type: type, clientMAC: mac ?? "?", xid: opts.xid,
                                     server: opts.server ?? (type == "Offer" || type == "ACK" || type == "NAK" ? d.ip?.source : nil),
                                     lease: opts.lease, yourIP: yi, vlan: d.vlan,
                                     relayHop: d.udp.map { $0.sourcePort == 67 && $0.destinationPort == 67 } ?? false))
        case .dns(let q, let isResponse, _, let rcode)?:
            guard d.protocolName == "DNS", let ip = d.ip, let udp = d.udp else { return }
            let txid = p.data.count >= d.payloadOffset + 2
                ? UInt16(p.data[p.data.startIndex + d.payloadOffset]) << 8 | UInt16(p.data[p.data.startIndex + d.payloadOffset + 1]) : 0
            out.dns.append(DNSFact(id: p.id, time: p.timestamp, isResponse: isResponse,
                                   client: isResponse ? ip.destination : ip.source,
                                   clientPort: isResponse ? udp.destinationPort : udp.sourcePort,
                                   server: isResponse ? ip.source : ip.destination,
                                   txid: txid, name: q ?? "", rcode: rcode))
        default:
            return
        }
    }

    /// xid, option 54 (server identifier) and 51 (lease time) of a DHCP message.
    static func dhcpOptions(_ data: Data, _ offset: Int) -> (xid: UInt32, server: String?, lease: UInt32?) {
        let b = [UInt8](data)
        let s = offset
        guard s >= 0, b.count >= s + 240 else { return (0, nil, nil) }
        func u32(_ i: Int) -> UInt32 { UInt32(b[i]) << 24 | UInt32(b[i + 1]) << 16 | UInt32(b[i + 2]) << 8 | UInt32(b[i + 3]) }
        let xid = u32(s + 4)
        var server: String?, lease: UInt32?
        var p = s + 240
        var guardCount = 0
        while p < b.count, guardCount < 128 {
            guardCount += 1
            let code = b[p]
            if code == 0 { p += 1; continue }
            if code == 255 { break }
            guard p + 1 < b.count else { break }
            let len = Int(b[p + 1])
            guard p + 2 + len <= b.count else { break }
            if code == 54, len == 4 { server = "\(b[p + 2]).\(b[p + 3]).\(b[p + 4]).\(b[p + 5])" }
            if code == 51, len == 4 { lease = u32(p + 2) }
            p += 2 + len
        }
        return (xid, server, lease)
    }
}

// MARK: - Packet rules

nonisolated extension FindingRules {
    static func vlanText(_ v: UInt16?) -> String { v.map { "VLAN \($0)" } ?? "this segment" }

    static func dhcpRules(_ pk: PacketScan.Output, _ ctx: inout RuleContext) -> [Finding] {
        guard !pk.dhcp.isEmpty else { return [] }
        var out: [Finding] = []
        let facts = pk.dhcp.sorted { $0.time < $1.time }
        let offers = facts.filter { $0.type == "Offer" }
        // Discovers without an Offer within 10 s, per client, grouped by VLAN.
        var byClient: [String: [DHCPFact]] = [:]
        // The client's own Discovers (a relay's copy to the server is the same Discover again).
        for f in facts where f.type == "Discover" && !f.relayHop { byClient[f.clientMAC, default: []].append(f) }
        struct Stuck { var clients: [String] = []; var discovers: [DHCPFact] = [] }
        var stuck: [UInt16?: Stuck] = [:]
        for (mac, ds) in byClient {
            let unanswered = ds.filter { d in
                !offers.contains { o in (o.xid == d.xid || o.clientMAC == mac) && o.time >= d.time && o.time.timeIntervalSince(d.time) <= dhcpOfferWait }
            }
            // A Discover in the capture's last 10 s may still get its Offer.
            let settled = unanswered.filter { d in pk.end.map { e in e.timeIntervalSince(d.time) >= dhcpOfferWait } ?? true }
            guard settled.count >= dhcpDiscovers else { continue }
            let vlan = settled[0].vlan
            stuck[vlan, default: Stuck()].clients.append(mac)
            stuck[vlan, default: Stuck()].discovers += settled
        }
        for (vlan, s) in stuck {
            let ds = s.discovers.sorted { $0.time < $1.time }
            let where_ = vlanText(vlan)
            let one = s.clients.count == 1
            var f = Finding(id: "dhcp.noanswer|\(vlan.map(String.init) ?? "-")", rule: "dhcp.noAnswer", severity: .bad, category: .dhcp, source: .packets,
                            title: "No DHCP answer on \(where_): \(one ? "client \(s.clients[0])" : "\(s.clients.count) clients") sent \(ds.count) Discovers and got no Offer within \(Int(dhcpOfferWait)) s.",
                            detail: "Clients that get no Offer fall back to a 169.254.x.x address and cannot reach anything. "
                                + "Either no DHCP server serves \(where_), the relay (ip helper-address) on its gateway is missing or wrong, or the server's scope is full. "
                                + (offers.isEmpty ? "No Offer at all was seen in this capture." : "Offers were seen for other clients, so the capture does see server replies.")
                                + (one ? "" : " Clients: \(FText.list(s.clients.sorted(), max: 8))."),
                            evidence: [packetEvidence(ds.map(\.id), fallback: "proto:dhcp" + (vlan.map { " vlan:\($0)" } ?? ""))],
                            firstSeen: ds[0].time, lastSeen: ds.last!.time, count: ds.count,
                            client: one ? s.clients[0] : nil)
            f.nextSteps = ["Check that \(where_) has a DHCP scope with free addresses on the server.",
                           vlan.map { "Check the ip helper-address / DHCP relay on the VLAN \($0) gateway interface." } ?? "Check the ip helper-address / DHCP relay on this subnet's gateway.",
                           one ? "Troubleshoot client \(s.clients[0]) to see everything it did." : "Capture on the server side of the relay to see whether the requests arrive."]
            out.append(f)
        }
        // Two servers answering — on the clients' side: the server's answer to a relay and the
        // relay's to the client are one server (with server-id override the relay even names
        // itself in option 54).
        var serversByVLAN: [UInt16?: [String: [DHCPFact]]] = [:]
        for f in facts where (f.type == "Offer" || f.type == "ACK") && !f.relayHop {
            if let s = f.server { serversByVLAN[f.vlan, default: [:]][s, default: []].append(f) }
        }
        for (vlan, servers) in serversByVLAN where servers.count >= 2 {
            let all = servers.values.flatMap { $0 }.sorted { $0.time < $1.time }
            let names = servers.keys.sorted()
            out.append(Finding(id: "dhcp.twoservers|\(vlan.map(String.init) ?? "-")", rule: "dhcp.twoServers", severity: .warn, category: .dhcp, source: .packets,
                               title: "\(names.count) DHCP servers answer on \(vlanText(vlan)): \(FText.list(names, max: 4)).",
                               detail: "Clients take the first Offer they get, so some end up with a wrong gateway or subnet. A second server is often a home router or a VM with DHCP left on (a rogue server).",
                               evidence: [packetEvidence(all.map(\.id), fallback: "proto:dhcp")],
                               firstSeen: all[0].time, lastSeen: all.last!.time, count: all.count,
                               nextSteps: ["Find the unexpected server (\(FText.list(names, max: 4))) by its MAC in the switch's MAC table and unplug or reconfigure it.",
                                           "Turn on DHCP snooping with only the uplink trusted."]))
        }
        // NAKs.
        var naks: [String: [DHCPFact]] = [:]
        for f in facts where f.type == "NAK" { naks[f.server ?? "?", default: []].append(f) }
        for (server, list) in naks {
            let clients = Array(Set(list.map(\.clientMAC))).sorted()
            out.append(Finding(id: "dhcp.nak|\(server)", rule: "dhcp.nak", severity: .warn, category: .dhcp, source: .packets,
                               title: "DHCP server \(server) refused \(list.count) request\(list.count == 1 ? "" : "s") (NAK) from \(clients.count == 1 ? clients[0] : "\(clients.count) clients").",
                               detail: "A NAK means the client asked for an address the server will not give it — usually a client that moved to another VLAN and asks for its old address, or two servers with overlapping scopes. The client starts over with a Discover.",
                               evidence: [packetEvidence(list.map(\.id), fallback: "proto:dhcp")],
                               firstSeen: list[0].time, lastSeen: list.last!.time, count: list.count,
                               client: clients.count == 1 ? clients[0] : nil,
                               nextSteps: ["Check the scope on \(server) for the client's subnet, and whether another server serves the same range."]))
        }
        // Very short leases.
        var shortBy: [String: [DHCPFact]] = [:]
        for f in facts where (f.type == "ACK" || f.type == "Offer") {
            if let l = f.lease, l > 0, l < shortLease { shortBy[f.server ?? "?", default: []].append(f) }
        }
        for (server, list) in shortBy {
            let minLease = list.compactMap(\.lease).min() ?? 0
            out.append(Finding(id: "dhcp.shortlease|\(server)", rule: "dhcp.shortLease", severity: .info, category: .dhcp, source: .packets,
                               title: "DHCP leases from \(server) last only \(FText.duration(Double(minLease))).",
                               detail: "Clients renew every half lease, so a short lease multiplies DHCP traffic and makes clients lose their address quickly when the server is unreachable. Usual leases are hours (8 h – 1 day).",
                               evidence: [packetEvidence(list.map(\.id), fallback: "proto:dhcp")],
                               firstSeen: list[0].time, lastSeen: list.last!.time, count: list.count,
                               nextSteps: ["Check the lease time of the scope on \(server) — a short lease is sometimes left from a migration."]))
        }
        return out
    }

    static func dnsRules(_ pk: PacketScan.Output, _ ctx: inout RuleContext) -> [Finding] {
        guard !pk.dns.isEmpty else { return [] }
        struct QKey: Hashable { let client: String; let port: UInt16; let server: String; let txid: UInt16 }
        struct Q1 { let f: DNSFact; var answered = false; var rcode = 0; var responseID: Int? }
        var queries: [Q1] = []
        var index: [QKey: Int] = [:]
        for f in pk.dns.sorted(by: { $0.time < $1.time }) {
            let k = QKey(client: f.client, port: f.clientPort, server: f.server, txid: f.txid)
            if !f.isResponse {
                index[k] = queries.count
                queries.append(Q1(f: f))
            } else if let i = index[k], !queries[i].answered {
                queries[i].answered = true
                queries[i].rcode = f.rcode
                queries[i].responseID = f.id
            }
        }
        let end = pk.end ?? Date.distantFuture
        var byServer: [String: [Q1]] = [:]
        for q in queries where q.answered || end.timeIntervalSince(q.f.time) >= dnsAnswerWait { byServer[q.f.server, default: []].append(q) }
        var out: [Finding] = []
        for (server, list) in byServer {
            let clients = Array(Set(list.map(\.f.client))).sorted()
            let answered = list.filter(\.answered)
            let noAnswer = list.count - answered.count
            let servfail = answered.filter { $0.rcode == 2 }.count
            // NXDOMAIN for one mistyped name (and its search-domain variants) is the typo; for
            // many different names it is a zone the resolver lost.
            let nxQueried = Set(answered.filter { $0.rcode == 3 }.map { $0.f.name.lowercased() })
            let nxRoots = nxQueried.filter { n in !nxQueried.contains { m in m != n && n.hasPrefix(m + ".") } }
            let nxCounts = nxRoots.count >= nxNames
            let nx = nxCounts ? answered.filter { $0.rcode == 3 }.count : 0
            let refused = answered.filter { $0.rcode == 5 }.count
            func bad(_ q: Q1) -> Bool { !q.answered || q.rcode == 2 || q.rcode == 5 || (q.rcode == 3 && nxCounts) }
            let failed = list.filter(bad)
            let ids = failed.flatMap { [$0.f.id] + ($0.responseID.map { [$0] } ?? []) }
            let one = clients.count == 1
            if answered.isEmpty && list.count >= 3 {
                out.append(Finding(id: "dns.dead|\(server)", rule: "dns.noAnswer", severity: .bad, category: .dns, source: .packets,
                                   title: "DNS server \(server) never answered: \(list.count) queries from \(one ? clients[0] : "\(clients.count) clients"), no reply.",
                                   detail: "Clients that use this resolver cannot resolve names at all; they wait a few seconds per name and may fall back to a second resolver. The server is down, not a DNS server, or a firewall drops UDP 53 to it.",
                                   evidence: [packetEvidence(list.map(\.f.id), fallback: "port:53 ip:\(server)")],
                                   firstSeen: list[0].f.time, lastSeen: list.last!.f.time, count: list.count,
                                   client: one ? clients[0] : nil,
                                   nextSteps: ["Check that \(server) is up and serving DNS: dig @\(server) example.com.",
                                               "Check which DNS servers DHCP hands out (option 6) — \(server) may be an old one.",
                                               "Show the DNS packets to \(server)."]))
                continue
            }
            guard list.count >= dnsMinQueries else { continue }
            // The worst minute, and the whole capture.
            var minutes: [Int: (n: Int, bad: Int)] = [:]
            for q in list {
                let m = Int(q.f.time.timeIntervalSinceReferenceDate / 60)
                minutes[m, default: (0, 0)].n += 1
                if bad(q) { minutes[m, default: (0, 0)].bad += 1 }
            }
            let share = Double(failed.count) / Double(list.count)
            let worst = minutes.filter { $0.value.n >= dnsMinQueries }.max { Double($0.value.bad) / Double($0.value.n) < Double($1.value.bad) / Double($1.value.n) }
            let worstShare = worst.map { Double($0.value.bad) / Double($0.value.n) } ?? 0
            guard share >= dnsFailShare || worstShare >= dnsFailShare else { continue }
            let hard = Double(noAnswer + servfail + refused) / Double(list.count)
            var parts: [String] = []
            if servfail > 0 { parts.append("SERVFAIL \(servfail)") }
            if nx > 0 { parts.append("NXDOMAIN \(nx)") }
            if refused > 0 { parts.append("REFUSED \(refused)") }
            if noAnswer > 0 { parts.append("no answer \(noAnswer)") }
            var names: [String: Int] = [:]
            for q in failed where !q.f.name.isEmpty { names[q.f.name, default: 0] += 1 }
            let top = names.sorted { $0.value > $1.value }.prefix(3).map { "\($0.key) (\($0.value))" }
            let whole = share >= dnsFailShare
            let windowText = whole ? "" : " in the minute at \(FText.clock(Date(timeIntervalSinceReferenceDate: Double(worst!.key) * 60)))"
            let shown = whole ? share : worstShare
            let counted = whole ? "\(parts.joined(separator: ", ")) of \(list.count)" : "\(worst!.value.bad) of \(worst!.value.n) that minute; \(failed.count) of \(list.count) in all"
            out.append(Finding(id: "dns.fail|\(server)", rule: "dns.failures", severity: hard >= 0.3 ? .bad : .warn, category: .dns, source: .packets,
                               title: "DNS server \(server) failed \(Int((shown * 100).rounded())) % of queries\(windowText) (\(counted)).",
                               detail: "\(clients.count == 1 ? "Client \(clients[0])" : "\(clients.count) clients") asked \(server) \(list.count) times. "
                                   + (top.isEmpty ? "" : "Names that failed most: \(top.joined(separator: ", ")). ")
                                   + "SERVFAIL and no answer mean the resolver or its upstream is failing; NXDOMAIN alone can be normal for search-domain lookups.",
                               evidence: [packetEvidence(ids, fallback: "port:53 ip:\(server)")],
                               firstSeen: failed.first?.f.time ?? list[0].f.time, lastSeen: failed.last?.f.time ?? list.last!.f.time, count: failed.count,
                               client: one ? clients[0] : nil,
                               nextSteps: ["Query \(server) directly for a failing name: dig @\(server) \(names.max { $0.value < $1.value }?.key ?? "example.com").",
                                           "Check \(server)'s forwarders / root hints and its reachability to the Internet.",
                                           "Show the failed DNS packets."]))
        }
        return out
    }

    static func arpRules(_ pk: PacketScan.Output, _ ctx: inout RuleContext) -> [Finding] {
        var out: [Finding] = []
        if !pk.arp.isEmpty {
            // One IP, several MACs.
            var claims: [String: [String: [Int]]] = [:]
            var times: [String: (Date, Date)] = [:]
            for a in pk.arp where a.senderIP != "0.0.0.0" && !a.senderIP.isEmpty {
                claims[a.senderIP, default: [:]][a.senderMAC, default: []].append(a.id)
                let t = times[a.senderIP] ?? (a.time, a.time)
                times[a.senderIP] = (min(t.0, a.time), max(t.1, a.time))
            }
            for (ip, macs) in claims where macs.count >= 2 {
                let list = macs.keys.sorted()
                let ids = macs.values.flatMap { $0 }.sorted()
                let t = times[ip]!
                out.append(Finding(id: "arp.dup|\(ip)", rule: "arp.duplicateIP", severity: .bad, category: .arpIP, source: .packets,
                                   title: "Duplicate IP \(ip): claimed by \(list.count) MAC addresses (\(FText.list(list, max: 3))).",
                                   detail: "Two hosts answer ARP for the same address, so traffic for \(ip) goes to whichever answered last — connections to it break at random. Usually a static address inside the DHCP range, or a cloned VM. (A VRRP / HSRP pair can show this briefly during a failover.)",
                                   evidence: [packetEvidence(ids, fallback: "proto:arp \(ip)")],
                                   firstSeen: t.0, lastSeen: t.1, count: ids.count, client: ip,
                                   nextSteps: ["Find both MACs in the switch MAC tables (show mac address-table address …) and the ports they are on.",
                                               "Check whether \(ip) is set statically on one of them and exclude it from the DHCP scope.",
                                               "Troubleshoot client \(ip)."]))
            }
            // Requests nobody answers.
            let replied = Set(pk.arp.filter { !$0.isRequest }.map(\.senderIP))
            let anyReply = !replied.isEmpty
            var asks: [String: [ARPFact]] = [:]
            for a in pk.arp where a.isRequest && a.senderIP != a.targetIP && a.senderIP != "0.0.0.0" { asks[a.targetIP, default: []].append(a) }
            for (target, list) in asks where list.count >= arpUnanswered && !replied.contains(target) {
                let sorted = list.sorted { $0.time < $1.time }
                let askers = Array(Set(list.map(\.senderIP))).sorted()
                let gateway = target.hasSuffix(".1") || target.hasSuffix(".254")
                out.append(Finding(id: "arp.noreply|\(target)", rule: "arp.unanswered", severity: anyReply ? .bad : .warn, category: .arpIP, source: .packets,
                                   title: "Nobody answers ARP for \(target)\(gateway ? " (the gateway?)" : ""): \(list.count) requests from \(askers.count == 1 ? askers[0] : "\(askers.count) hosts").",
                                   detail: "Hosts that cannot resolve \(target) cannot send it anything\(gateway ? " — if it is their default gateway, they are cut off from every other subnet" : ""). "
                                       + "It is down, on another VLAN, or its interface is shut. "
                                       + (anyReply ? "Other ARP replies are in the capture, so a reply would have been seen." : "No ARP reply at all is in this capture — capture on the asking host's port to be sure."),
                                   evidence: [packetEvidence(sorted.map(\.id), fallback: "proto:arp \(target)")],
                                   firstSeen: sorted[0].time, lastSeen: sorted.last!.time, count: list.count,
                                   client: askers.count == 1 ? askers[0] : nil,
                                   nextSteps: ["Check that \(target) is up and its interface is on \(vlanText(sorted[0].vlan)) (show ip interface brief / show vlan).",
                                               "Check the VLAN of the port the asking hosts are on."]))
            }
        }
        // ICMP time exceeded / redirects in bursts. A traceroute (or mtr, which never stops) gets
        // time-exceeded from every hop on the way to one destination; a routing loop expires one
        // host's packets to a destination at the same router every time. Probes answered by two
        // or more routers are a trace, not a loop.
        var hopsByProbe: [String: Set<String>] = [:]
        for i in pk.icmp where i.type == 11 {
            hopsByProbe["\(i.destination)>\(i.probeDestination ?? "?")", default: []].insert(i.router)
        }
        var byRouter: [String: [ICMPFact]] = [:]
        for i in pk.icmp {
            if i.type == 11, (hopsByProbe["\(i.destination)>\(i.probeDestination ?? "?")"]?.count ?? 0) >= 2 { continue }
            byRouter["\(i.type)|\(i.router)", default: []].append(i)
        }
        for (key, list) in byRouter {
            let sorted = list.sorted { $0.time < $1.time }
            let redirect = sorted[0].type == 5
            var best = 0, lo = 0
            for hi in sorted.indices {
                while sorted[hi].time.timeIntervalSince(sorted[lo].time) > 60 { lo += 1 }
                best = max(best, hi - lo + 1)
            }
            guard best >= (redirect ? redirectBurst : icmpBurst) else { continue }
            let router = sorted[0].router
            let dests = Array(Set(sorted.map(\.destination))).sorted()
            out.append(Finding(id: "icmp|\(key)", rule: redirect ? "icmp.redirects" : "icmp.ttlExceeded", severity: .warn, category: .arpIP, source: .packets,
                               title: redirect
                                   ? "\(router) sent \(best) ICMP redirects in a minute (\(list.count) in all)."
                                   : "\(router) sent \(best) ICMP time-exceeded messages in a minute (\(list.count) in all).",
                               detail: redirect
                                   ? "Redirects tell hosts to use another gateway on their own subnet: hosts \(FText.list(dests, max: 3)) are configured with the wrong default gateway, or a static route points the long way round."
                                   : "Packets are expiring at \(router). A few come from traceroute; a steady burst means a routing loop between two routers (a static route and a default pointing at each other).",
                               evidence: [packetEvidence(sorted.map(\.id), fallback: "proto:icmp ip:\(router)")],
                               firstSeen: sorted[0].time, lastSeen: sorted.last!.time, count: list.count,
                               nextSteps: redirect
                                   ? ["Check the default gateway of \(FText.list(dests, max: 3)) (DHCP option 3).", "Check the routes on \(router)."]
                                   : ["Traceroute through \(router) to one of \(FText.list(dests, max: 2)) and look for the same hops repeating.",
                                      "Check the routing table on \(router) for routes pointing back where they came from."]))
        }
        return out
    }

    static func packetEvidence(_ ids: [Int], fallback: String) -> Evidence {
        let sorted = Array(Set(ids)).sorted()
        let query = sorted.count <= 50 ? sorted.map { "frame:\($0)" }.joined(separator: " OR ") : fallback
        return Evidence(kind: .packets, label: "\(Format.count(sorted.count)) packet\(sorted.count == 1 ? "" : "s")", ids: sorted, query: query)
    }
}

// MARK: - TCP flow rules

nonisolated extension FindingRules {
    static func flowRules(_ flows: [TCPFlow]) -> [Finding] {
        guard !flows.isEmpty else { return [] }
        struct Key: Hashable { let server: String; let port: UInt16 }
        var groups: [Key: [TCPFlow]] = [:]
        for f in flows { groups[Key(server: f.server, port: f.serverPort), default: []].append(f) }
        var out: [Finding] = []
        for (key, list) in groups {
            let endpoint = TCPFlow.endpoint(key.server, key.port)
            let app = TCPFlowAnalyzer.portName(key.port)
            let label = app.isEmpty || app == "\(key.port)" || app.hasPrefix("port ") ? endpoint : "\(endpoint) (\(app))"
            let clients = Set(list.map(\.client))
            func ev(_ fs: [TCPFlow]) -> Evidence {
                let sorted = fs.sorted { $0.firstTime < $1.firstTime }
                return Evidence(kind: .flows, label: sorted.count == 1 ? "flow ⇄" : "\(sorted.count) flows ⇄", ids: sorted.map(\.id), query: "",
                                flows: sorted.prefix(50).map { FlowRef(key: $0.key, packetID: $0.firstPacketID, lastPacketID: $0.lastPacketID) })
            }
            func span(_ fs: [TCPFlow]) -> (Date, Date) {
                (fs.map(\.firstTime).min()!, fs.map { $0.firstTime.addingTimeInterval($0.duration) }.max()!)
            }
            func oneClient(_ fs: [TCPFlow]) -> String? { let c = Set(fs.map(\.client)); return c.count == 1 ? c.first : nil }
            // SYNs nobody answers.
            let silent = list.filter { f in f.reasons.contains { $0.hasPrefix("SYN never answered") } }
            let attempts = silent.reduce(0) { $0 + $1.synRetransmissions + 1 }
            let silentClients = Set(silent.map(\.client))
            if !silent.isEmpty, attempts >= refusedAttempts || silentClients.count >= 3 {
                let t = span(silent)
                out.append(Finding(id: "tcp.silent|\(endpoint)", rule: "tcp.synUnanswered", severity: .bad, category: .tcp, source: .flows,
                                   title: "Nothing answers on \(label): \(attempts) SYN\(attempts == 1 ? "" : "s") from \(silentClients.count == 1 ? silentClients.first! : "\(silentClients.count) clients"), no reply.",
                                   detail: "Connection attempts get no answer at all — the port is filtered by a firewall, the host is down, or the route back is broken. Applications wait for their connect timeout (often 20–75 s) before they give up.",
                                   evidence: [ev(silent)], firstSeen: t.0, lastSeen: t.1, count: attempts, client: oneClient(silent),
                                   nextSteps: ["Show the flow to \(endpoint).",
                                               "Check that \(key.server) is up (ping) and that a firewall on the path permits TCP \(key.port).",
                                               "Check the service listens on \(key.port) on \(key.server) (ss -ltn / netstat -an)."]))
            }
            // Refused (RST to the SYN). One refused attempt is a client trying a port once (a
            // scan, a moved service, a probe): a note. Three attempts, or two clients, is a
            // service people cannot reach.
            let refused = list.filter(\.refused)
            if !refused.isEmpty {
                let t = span(refused)
                let rc = Set(refused.map(\.client))
                let tries = refused.reduce(0) { $0 + $1.synRetransmissions + 1 }
                let sev: FindingSeverity = rc.count >= 3 ? .bad : (tries >= refusedAttempts || rc.count >= 2 ? .warn : .info)
                out.append(Finding(id: "tcp.refused|\(endpoint)", rule: "tcp.refused", severity: sev, category: .tcp, source: .flows,
                                   title: "\(label) refused \(tries) connection attempt\(tries == 1 ? "" : "s") with RST (port closed)"
                                       + " from \(rc.count == 1 ? rc.first! : "\(rc.count) clients").",
                                   detail: "The host answered the SYN with a reset: it is up, but nothing listens on TCP \(key.port) (or a firewall rejects it). \(rc.count == 1 ? "Client \(rc.first!)" : "\(rc.count) clients") tried."
                                       + (sev == .info ? " Once is often a scan, a probe or a client trying an old port; it matters when it repeats." : ""),
                                   evidence: [ev(refused)], firstSeen: t.0, lastSeen: t.1, count: tries, client: oneClient(refused),
                                   nextSteps: ["Check the service on \(key.server) is running and listening on \(key.port).",
                                               "Check the client uses the right port (a moved service, http vs https)."]))
            }
            // Server resets mid-connection.
            let resets = list.filter { f in f.reasons.contains("server reset the connection") }
            if !resets.isEmpty {
                let t = span(resets)
                out.append(Finding(id: "tcp.reset|\(endpoint)", rule: "tcp.serverReset", severity: resets.count >= 3 ? .bad : .warn, category: .tcp, source: .flows,
                                   title: "\(label) reset \(resets.count) connection\(resets.count == 1 ? "" : "s") from \(Set(resets.map(\.client)).count == 1 ? resets[0].client : "\(Set(resets.map(\.client)).count) clients").",
                                   detail: "The server (or a firewall / load balancer in front of it) tore established connections down with RST — users see “connection reset” errors. Common causes: an idle timeout on a firewall, a crashing application, a load balancer with no healthy member.",
                                   evidence: [ev(resets)], firstSeen: t.0, lastSeen: t.1, count: resets.count, client: oneClient(resets),
                                   nextSteps: ["Show the flow to \(endpoint) and look at what came right before the RST.",
                                               "Check the application log on \(key.server) and idle timeouts on firewalls in between."]))
            }
            // Retransmissions — of conversations long enough for a share to mean something: one
            // lost segment of a 5-segment exchange is 20 % of it.
            let long = list.filter { $0.dataSegments >= retransMinSegments }
            let lost = long.reduce(0) { $0 + max(0, $1.retransmissions - $1.spuriousRetransmissions) }
            let pkts = long.reduce(0) { $0 + $1.packetCount }
            let share = Double(lost) / Double(max(1, pkts))
            if lost >= 3, share >= retransShare {
                let affected = long.filter { $0.retransmissions > $0.spuriousRetransmissions }
                let t = span(affected)
                out.append(Finding(id: "tcp.retrans|\(endpoint)", rule: "tcp.retransmissions", severity: share >= 0.05 ? .bad : .warn, category: .tcp, source: .flows,
                                   title: String(format: "%.1f %% of packets to and from %@ were retransmitted (%@ of %@ packets).", share * 100, label, Format.count(lost), Format.count(pkts)),
                                   detail: "Retransmissions mean segments were lost on the way; every loss costs at least a round trip and halves the sending rate, so transfers crawl. Above 1–2 % users notice. Look for errors or drops on the links between \(clients.count == 1 ? clients.first! : "the clients") and \(key.server).",
                                   evidence: [ev(affected)], firstSeen: t.0, lastSeen: t.1, count: lost, client: oneClient(affected),
                                   nextSteps: ["Show the flow to \(endpoint) with the most retransmissions.",
                                               "Walk the Interfaces table (SNMP) on the switches in the path and look for errors and discards.",
                                               "Check Wi-Fi signal / duplex settings on the client side."]))
            }
            // Slow handshakes.
            let rtts = list.compactMap(\.handshakeRTT).sorted()
            if !rtts.isEmpty, rtts[rtts.count / 2] > slowHandshake {
                let slow = list.filter { ($0.handshakeRTT ?? 0) > slowHandshake }
                let t = span(slow)
                out.append(Finding(id: "tcp.rtt|\(endpoint)", rule: "tcp.slowHandshake", severity: .warn, category: .tcp, source: .flows,
                                   title: "Slow handshakes to \(label): median \(TCPFlowAnalyzer.msText(rtts[rtts.count / 2])) over \(rtts.count) connection\(rtts.count == 1 ? "" : "s").",
                                   detail: "The SYN → SYN/ACK time is the network round trip plus the server's accept time. Over 300 ms every request feels slow; on a LAN it should be a few ms. A distant or overloaded server, a congested WAN link or a proxy in the path.",
                                   evidence: [ev(slow)], firstSeen: t.0, lastSeen: t.1, count: slow.count, client: oneClient(slow),
                                   nextSteps: ["Ping \(key.server) from the client and from the switch next to the server to see which half is slow.",
                                               "Show the flow to \(endpoint): the ladder splits the delay into client side and server side."]))
            }
            // Zero windows.
            let zero = list.filter { $0.zeroWindows > 0 }
            if !zero.isEmpty {
                let t = span(zero)
                let fromClient = zero.contains { $0.reasons.contains("zero window from client") }
                let fromServer = zero.contains { $0.reasons.contains("zero window from server") }
                let who = fromClient && fromServer ? "both sides" : (fromClient ? "the client" : "the server")
                out.append(Finding(id: "tcp.zerowin|\(endpoint)", rule: "tcp.zeroWindow", severity: .warn, category: .tcp, source: .flows,
                                   title: "Zero window on \(zero.count) connection\(zero.count == 1 ? "" : "s") to \(label): \(who) stopped reading.",
                                   detail: "A zero window means the receiving application is not reading its socket fast enough — the network is fine, the host is the bottleneck (busy CPU, slow disk, a stuck application).",
                                   evidence: [ev(zero)], firstSeen: t.0, lastSeen: t.1, count: zero.count, client: oneClient(zero),
                                   nextSteps: ["Check CPU, memory and disk on \(fromServer ? key.server : (oneClient(zero) ?? "the client")).",
                                               "Show the flow to \(endpoint) to see how long the window stayed closed."]))
            }
            // Slow answers: per server and port, naming the request that waited longest (the
            // slowest conversation's first request was named — often a quick one before it).
            let slowAnswer = list.filter { ($0.longestResponseWait ?? 0) > 3 }
            if !slowAnswer.isEmpty {
                let t = span(slowAnswer)
                let worst = slowAnswer.max { ($0.longestResponseWait ?? 0) < ($1.longestResponseWait ?? 0) }!
                let what = worst.longestWaitFor.map { " \($0)" } ?? ""
                out.append(Finding(id: "tcp.slow|\(endpoint)", rule: "tcp.slowResponse", severity: .warn, category: .tcp, source: .flows,
                                   title: "\(label) took up to \(TCPFlowAnalyzer.msText(worst.longestResponseWait ?? 0)) to answer\(what) (\(slowAnswer.count) connection\(slowAnswer.count == 1 ? "" : "s")).",
                                   detail: "The request reached the server quickly and it acknowledged it, then waited seconds before the first byte of the answer — the delay is in the application or its back end (database, API), not the network.",
                                   evidence: [ev(slowAnswer)], firstSeen: t.0, lastSeen: t.1, count: slowAnswer.count, client: oneClient(slowAnswer),
                                   nextSteps: ["Show the flow to \(endpoint).", "Check the application / database behind \(key.server) at \(FText.clock(t.0))."]))
            }
        }
        return out
    }
}

// MARK: - SNMP rules

nonisolated extension FindingRules {
    static let dot3Duplex = OID([1, 3, 6, 1, 2, 1, 10, 7, 2, 1, 19])
    static let ifInDiscards = OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 13])
    static let ifOutDiscards = OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 19])
    // Packet counters, for the discard rate: ifTable's 32-bit ones and ifXTable's 64-bit ones.
    static let ifInPackets32 = [OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 11]), OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 12])]
    static let ifOutPackets32 = [OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 17]), OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 18])]
    static let ifInPacketsHC = [7, 8, 9].map { OID([1, 3, 6, 1, 2, 1, 31, 1, 1, 1, $0]) }
    static let ifOutPacketsHC = [11, 12, 13].map { OID([1, 3, 6, 1, 2, 1, 31, 1, 1, 1, $0]) }

    /// One direction of one port in one walk: discards and the packets that went through, each
    /// counter column on its own (a Counter32 wraps by itself: the sum of ifInUcastPkts and
    /// ifInNUcastPkts cannot be unwrapped).
    struct PortFlow: Sendable {
        var discards: UInt64?
        /// ifTable's Counter32 packet columns, and ifXTable's Counter64 ones, by column number.
        var p32: [UInt32: UInt64] = [:]
        var pHC: [UInt32: UInt64] = [:]
        var packets32: UInt64? { p32.isEmpty ? nil : p32.values.reduce(0, &+) }
        var packetsHC: UInt64? { pHC.isEmpty ? nil : pHC.values.reduce(0, &+) }
        var packets: UInt64? { packetsHC ?? packets32 }
    }

    /// Discards and packet counts per ifIndex and direction (0 in, 1 out) from a walk's var-binds.
    static func portFlows(_ values: [OID: String]) -> [UInt32: [PortFlow]] {
        var out: [UInt32: [PortFlow]] = [:]
        func add(_ oid: OID, _ value: String, _ dir: Int, _ f: (inout PortFlow, UInt64) -> Void) {
            guard let idx = oid.parts.last, let n = UInt64(value.prefix { $0.isNumber }) else { return }
            var list = out[idx] ?? [PortFlow(), PortFlow()]
            f(&list[dir], n)
            out[idx] = list
        }
        for (oid, value) in values where oid.parts.count >= 11 {
            let column = OID(Array(oid.parts.dropLast()))
            let col = column.parts.last ?? 0
            if column == ifInDiscards { add(oid, value, 0) { $0.discards = $1 } }
            else if column == ifOutDiscards { add(oid, value, 1) { $0.discards = $1 } }
            else if ifInPackets32.contains(column) { add(oid, value, 0) { $0.p32[col] = $1 } }
            else if ifOutPackets32.contains(column) { add(oid, value, 1) { $0.p32[col] = $1 } }
            else if ifInPacketsHC.contains(column) { add(oid, value, 0) { $0.pHC[col] = $1 } }
            else if ifOutPacketsHC.contains(column) { add(oid, value, 1) { $0.pHC[col] = $1 } }
        }
        return out
    }

    /// How much a Counter32 went up between two readings: past 4,294,967,295 it starts again at
    /// 0 (RFC 2578 §7.1.6) — a 1 Gb/s port's ifInUcastPkts does that in about an hour at full
    /// rate. A smaller value was read as "counters cleared" (the walk's totals) and the wrap's
    /// discards were lost or the rate taken over all time. A wrap needs the earlier reading in
    /// the counter's upper half and the new one in its lower half; anything else smaller is a
    /// `clear counters` (nil) — and so is a "wrap" of more than the port could have carried
    /// (`limit`, `maxFrames`): a counter cleared from its upper half (3,000,000,000 → 5) read as
    /// 1,294,967,301 errors in five minutes on a 1 Gb/s port that can carry 446 million frames.
    static func delta32(_ now: UInt64, _ before: UInt64, limit: UInt64? = nil) -> UInt64? {
        if now >= before { return now - before }
        let half: UInt64 = 1 << 31
        guard before <= UInt64(UInt32.max), before >= half, now < half else { return nil }
        let d = now + (UInt64(UInt32.max) + 1) - before
        if let limit, d > limit { return nil }
        return d
    }

    /// The most frames a port of `speedBits` can carry in `seconds` (minimum frames: 84 bytes on
    /// the wire), with room to spare; nil when the speed is not known.
    static func maxFrames(speedBits: UInt64, seconds: Double) -> UInt64? {
        guard speedBits > 0, seconds > 0 else { return nil }
        let frames = Double(speedBits) / 672 * seconds * 1.1 + 10_000
        return frames >= Double(UInt64.max) ? nil : UInt64(frames)
    }

    /// The device restarted between two walks: its uptime at the second is shorter than the
    /// time between them, or shorter than it was at the first (clocks of the two walks aside).
    static func restartedBetween(_ before: SNMPSnapshot, _ now: SNMPSnapshot) -> Bool {
        guard let up = now.sysUpTime else { return false }
        let gap = now.taken.timeIntervalSince(before.taken)
        // sysUpTime is TimeTicks (RFC 2578 §7.1.8): past 4,294,967,295 hundredths — 497 days —
        // it starts again at 0. A device up that long read as restarted at every walk after.
        if let was = before.sysUpTime, uptimeWrapped(was: was, now: up, gap: gap) { return false }
        if Double(up) / 100 < gap { return true }
        if let was = before.sysUpTime, up < was { return true }
        return false
    }

    /// sysUpTime went past 2^32 hundredths (497.1 days) between two readings `gap` seconds apart
    /// on the Mac's clock: the earlier reading plus the gap reaches past 2^32, and the new one is
    /// that sum modulo 2^32 — give or take 30 s or 5 % (the walks' own timing, an agent's clock).
    static func uptimeWrapped(was: UInt32, now: UInt32, gap: Double) -> Bool {
        guard now < was, gap > 0, gap.isFinite else { return false }
        let wrap = 4_294_967_296.0
        let reached = Double(was) + gap * 100
        guard reached >= wrap else { return false }
        let expected = reached.truncatingRemainder(dividingBy: wrap)
        return abs(Double(now) - expected) <= max(3_000, gap * 100 * 0.05)
    }

    /// Seconds a 32-bit packet counter of a port of `speedBits` takes to start again at full
    /// rate (minimum frames); nil when the speed is not known.
    static func wrapSeconds32(speedBits: UInt64) -> Double? {
        guard speedBits > 0 else { return nil }
        return 4_294_967_296.0 / (Double(speedBits) / 672)
    }

    static let ifCounterDiscontinuityTime = OID([1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 19])

    /// Both walks' counters of this ifIndex count the same port since the same start: the same
    /// ifName / ifDescr (a module pulled and another put in may give its ifIndex to a new port,
    /// whose small counters read as a wrap of the old port's big ones) and the same
    /// ifCounterDiscontinuityTime when the agent has it (RFC 2863 §3.1.5).
    static func sameCounters(_ r: InterfaceRow, in s: SNMPSnapshot, as p: InterfaceRow, in old: SNMPSnapshot) -> Bool {
        // ifDescr (ifTable, in every Interfaces walk); the name only when one walk has no
        // ifDescr (a walk without ifXTable names ports by ifDescr, one with it by ifName).
        if !r.descr.isEmpty, !p.descr.isEmpty { if r.descr != p.descr { return false } }
        else if r.name != p.name { return false }
        return sameDiscontinuity(r.index, s, old)
    }

    static func sameDiscontinuity(_ idx: UInt32, _ s: SNMPSnapshot, _ old: SNMPSnapshot) -> Bool {
        let oid = ifCounterDiscontinuityTime.appending(idx)
        guard let a = s.values[oid], let b = old.values[oid] else { return true }
        return a == b
    }

    /// Packets through one direction between two walks: the Counter64 columns when both walks
    /// have them (they never wrap: smaller means cleared), else the Counter32 ones, column by column.
    static func packetDelta(_ now: PortFlow, _ before: PortFlow, limit: UInt64? = nil) -> UInt64? {
        if !now.pHC.isEmpty, Set(now.pHC.keys) == Set(before.pHC.keys) {
            var sum: UInt64 = 0
            for (c, v) in now.pHC { guard let b = before.pHC[c], v >= b else { return nil }; sum &+= v - b }
            return sum
        }
        if !now.p32.isEmpty, Set(now.p32.keys) == Set(before.p32.keys) {
            var sum: UInt64 = 0
            for (c, v) in now.p32 { guard let b = before.p32[c], let d = delta32(v, b, limit: limit) else { return nil }; sum &+= d }
            return sum
        }
        return nil
    }

    /// "12.5" / "340": discards per 10,000 packets.
    static func rateText(_ r: Double) -> String { r < 100 ? String(format: "%.1f", r) : String(format: "%.0f", r) }

    static func snmpRules(_ snaps: [SNMPSnapshot], now: Date) -> [Finding] {
        guard !snaps.isEmpty else { return [] }
        var byHost: [String: [SNMPSnapshot]] = [:]
        for s in snaps { byHost[s.host, default: []].append(s) }
        var out: [Finding] = []
        for (host, list) in byHost {
            // What each rule reads is the newest result that has it: a Quick test or a GET run
            // after the Interfaces walk has no ports — it hid every port finding of the walk
            // (and one with the walk's rows still on screen compared the walk with itself).
            let walks = list.filter { !$0.interfaces.isEmpty }
            let cur = walks.last
            let prev = walks.count >= 2 ? walks[walks.count - 2] : nil
            let name = list.last { !($0.sysName?.isEmpty ?? true) }?.name ?? host
            let names = Dictionary((cur?.interfaces ?? []).map { ($0.index, $0.name.isEmpty ? "ifIndex \($0.index)" : $0.name) },
                                   uniquingKeysWith: { a, _ in a })
            func base(_ id: String, _ rule: String, _ sev: FindingSeverity, _ title: String, _ detail: String, _ steps: [String],
                      count: Int, taken: Date) -> Finding {
                Finding(id: "snmp.\(id)|\(host)", rule: rule, severity: sev, category: .snmp, source: .snmp, title: title, detail: detail,
                        firstSeen: taken, lastSeen: taken, count: count, device: name, deviceAddress: host,
                        nextSteps: steps, snmpTarget: host)
            }
            // A small sysUpTime that is the earlier walk's past 497 days (the TimeTicks wrap) is
            // no restart.
            if let i = list.lastIndex(where: { $0.sysUpTime != nil }), let up = list[i].sysUpTime, up < recentBoot,
               !list[..<i].contains(where: { p in p.sysUpTime.map { uptimeWrapped(was: $0, now: up, gap: list[i].taken.timeIntervalSince(p.taken)) } ?? false }) {
                let s = list[i]
                out.append(base("uptime", "snmp.recentBoot", .info, "\(name) restarted \(FText.duration(Double(up) / 100)) before the SNMP walk (sysUpTime \(Format.uptime(ticks: UInt64(up)))).",
                                "A device that has just booted lost its counters, its MAC and ARP tables and its sessions. If nobody restarted it, look for a power or crash reason.",
                                ["Check the reload reason on \(name) (show version)."], count: 1, taken: s.taken))
            }
            if let s = cur {
                // Enabled but down.
                let downs = s.interfaces.filter { $0.admin.lowercased().hasPrefix("up") && $0.oper.lowercased().hasPrefix("down") }
                if !downs.isEmpty {
                    let recent = downs.filter { ($0.sinceChange ?? .max) < 360_000 }.sorted { ($0.sinceChange ?? 0) < ($1.sinceChange ?? 0) }
                    let list = (recent + downs.filter { r in !recent.contains { $0.index == r.index } }).map { names[$0.index] ?? "\($0.index)" }
                    var detail = "\(downs.count == 1 ? "This port is" : "These ports are") enabled (admin up) but have no link (oper down): nothing is plugged in, the far end is off, or the cable / optic is bad."
                    if let r = recent.first, let age = r.sinceChange {
                        detail += " \(names[r.index] ?? "") went down \(FText.duration(Double(age) / 100)) before the walk — that one is new."
                    }
                    // Enabled ports with nothing plugged in are every access switch's normal state: a
                    // warning only when one of them lost its link in the last hour.
                    out.append(base("operdown", "snmp.operDown", recent.isEmpty ? .info : .warn,
                                    "\(downs.count) port\(downs.count == 1 ? "" : "s") on \(name) \(downs.count == 1 ? "is" : "are") enabled but down: \(FText.list(list, max: 6)).",
                                    detail, ["Shut unused ports (and put them in an unused VLAN) so real faults stand out.",
                                             recent.isEmpty ? "Check the ports that should be up." : "Check what was connected to \(names[recent[0].index] ?? "") and whether it has power."],
                                    count: downs.count, taken: s.taken))
                }
                // Errors: growth since the previous walk, or a total. Each Counter32 column on
                // its own (ifInErrors wrapping past 4,294,967,295 made the in + out sum smaller:
                // the growth was lost); a port whose counters started again (cleared, the device
                // restarted, a module swapped under the same ifIndex) compares nothing.
                let restarted = prev.map { Self.restartedBetween($0, s) } ?? false
                let before = restarted ? nil : prev.map { Dictionary($0.interfaces.map { ($0.index, $0) }, uniquingKeysWith: { a, _ in a }) }
                var grown: [(String, UInt64)] = []
                var totals: [(String, UInt64)] = []
                for r in s.interfaces where r.totalErrors > 0 {
                    let n = names[r.index] ?? "\(r.index)"
                    if let p = before?[r.index], let old = prev, Self.sameCounters(r, in: s, as: p, in: old) {
                        // A column that went down without wrapping was cleared since: what it
                        // holds now all came after the clear, between the walks.
                        let limit = Self.maxFrames(speedBits: r.speedBits, seconds: s.taken.timeIntervalSince(old.taken))
                        let d = (Self.delta32(r.inErrors, p.inErrors, limit: limit) ?? r.inErrors)
                            &+ (Self.delta32(r.outErrors, p.outErrors, limit: limit) ?? r.outErrors)
                        if d > 0 { grown.append((n, d)) }
                    } else {
                        totals.append((n, r.totalErrors))
                    }
                }
                if !grown.isEmpty, let p = prev {
                    let top = grown.sorted { $0.1 > $1.1 }
                    out.append(base("errors", "snmp.errorsGrowing", .warn,
                                    "Interface errors are growing on \(name): \(top.prefix(4).map { "\($0.0) +\(Format.count(Int(clamping: $0.1)))" }.joined(separator: ", ")) in \(FText.duration(s.taken.timeIntervalSince(p.taken))).",
                                    "ifInErrors / ifOutErrors went up between two walks: frames are arriving damaged (CRC) or cannot be sent — a bad cable or optic, a duplex mismatch, or interference. Errors turn into retransmissions and slow applications.",
                                    ["Check the cable / optic on \(top[0].0) (show interface \(top[0].0): CRC, runts, input errors).", "Check both ends agree on speed and duplex."],
                                    count: top.count, taken: s.taken))
                } else if !totals.isEmpty {
                    let top = totals.sorted { $0.1 > $1.1 }
                    let since = restarted
                        ? "These are counts since \(name) restarted (\(FText.duration(Double(s.sysUpTime ?? 0) / 100)) before the walk): SheepLog cannot tell whether they came with the restart or after it. Walk the Interfaces table again in a few minutes: SheepLog compares the two walks and says whether they grow."
                        : "These are totals since the counters were last cleared, so they may be old. Walk the Interfaces table again in a few minutes: SheepLog compares the two walks and says whether they grow."
                    out.append(base("errors", "snmp.errors", .info,
                                    "\(top.count) interface\(top.count == 1 ? "" : "s") on \(name) \(top.count == 1 ? "has" : "have") error counts: \(top.prefix(4).map { "\($0.0) \(Format.count(Int(clamping: $0.1)))" }.joined(separator: ", ")).",
                                    since, ["Run Interfaces again on the SNMP Test pane in a few minutes."], count: top.count, taken: s.taken))
                }
            }
            // Half duplex: the newest result with dot3StatsDuplexStatus (a walk of dot3StatsTable,
            // not the Interfaces walk).
            if let s = list.last(where: { $0.values.keys.contains { dot3Duplex.isPrefix(of: $0) } }) {
                var half: [String] = []
                for (oid, value) in s.values where dot3Duplex.isPrefix(of: oid) {
                    guard let idx = oid.parts.last else { continue }
                    if value.hasPrefix("half") || value == "2" || value.hasSuffix("(2)") { half.append(names[idx] ?? "ifIndex \(idx)") }
                }
                if !half.isEmpty {
                    out.append(base("duplex", "snmp.halfDuplex", .warn,
                                    "\(half.count) port\(half.count == 1 ? "" : "s") on \(name) run\(half.count == 1 ? "s" : "") at half duplex: \(FText.list(half.sorted(), max: 6)).",
                                    "Half duplex on a modern link almost always means auto-negotiation failed on one side (one end forced to full, the other auto). The result is late collisions, errors and very slow transfers.",
                                    ["Set both ends to auto (or both to the same fixed speed and duplex)."], count: half.count, taken: s.taken))
                }
            }
            out += discardRules(list, name: name, names: names, base: base)
        }
        return out
    }

    /// Discards as a rate — per 10,000 packets through the port, or their growth between two
    /// walks — never a raw count: a core port that forwarded ten billion packets and dropped a
    /// thousand since last year is healthy.
    static func discardRules(_ list: [SNMPSnapshot], name: String, names: [UInt32: String],
                             base: (String, String, FindingSeverity, String, String, [String], Int, Date) -> Finding) -> [Finding] {
        let counted = list.filter { s in s.values.keys.contains { ifInDiscards.isPrefix(of: $0) || ifOutDiscards.isPrefix(of: $0) } }
        guard let cur = counted.last else { return [] }
        let prev = counted.count >= 2 ? counted[counted.count - 2] : nil
        let now = portFlows(cur.values)
        // A device that restarted between the walks cleared its counters: smaller values are
        // then a new start, not a wrap (its uptime is shorter than the time between the walks).
        let restarted = prev.map { restartedBetween($0, cur) } ?? false
        let before = restarted ? nil : prev.map { portFlows($0.values) }
        let rowsNow = Dictionary(cur.interfaces.map { ($0.index, $0) }, uniquingKeysWith: { a, _ in a })
        let rowsBefore = Dictionary((prev?.interfaces ?? []).map { ($0.index, $0) }, uniquingKeysWith: { a, _ in a })
        let dirWord = ["in", "out"]
        var growing: [(text: String, weight: Double)] = []
        var totals: [(text: String, weight: Double)] = []
        /// Ports whose one-walk rate is taken over 32-bit packet counters that may have started
        /// again since the clear (the port can wrap one faster than the device has been up).
        var wrapped32: [(name: String, wrap: Double)] = []
        for (idx, flows) in now {
            let n = names[idx] ?? "ifIndex \(idx)"
            for dir in 0..<2 {
                guard let disc = flows[dir].discards, disc > 0 else { continue }
                let pkts = flows[dir].packets
                // Per 10,000 packets through the port (a received packet that was discarded is not
                // in ifInUcastPkts; one that was to be sent is in ifOutUcastPkts).
                // Never more than all of them (an agent's absurd counter overflowed `p + d` to a
                // rate of 10^23 per 10,000).
                func rate(_ d: UInt64, _ p: UInt64) -> Double {
                    let (sum, over) = p.addingReportingOverflow(dir == 0 ? d : 0)
                    return min(10_000, Double(d) / Double(max(1, over ? UInt64.max : sum)) * 10_000)
                }
                let same = rowsNow[idx].flatMap { r in rowsBefore[idx].map { p in sameCounters(r, in: cur, as: p, in: prev!) } }
                    ?? prev.map { sameDiscontinuity(idx, cur, $0) } ?? false
                let limit = prev.flatMap { p in rowsNow[idx].flatMap { maxFrames(speedBits: $0.speedBits, seconds: cur.taken.timeIntervalSince(p.taken)) } }
                if same, let b = before?[idx]?[dir], let d0 = b.discards, let d = delta32(disc, d0, limit: limit) {
                    guard d > 0 else { continue }
                    if let dp = packetDelta(flows[dir], b, limit: limit) {
                        let r = rate(d, dp)
                        if r >= discardRate { growing.append(("\(n) \(dirWord[dir]) \(rateText(r)) per 10,000 packets (+\(Format.count(Int(clamping: d))))", r)) }
                    } else if d >= discardGrowth {
                        growing.append(("\(n) \(dirWord[dir]) +\(Format.count(Int(clamping: d)))", Double(d)))
                    }
                } else if let p = pkts {
                    // One walk (or the counters were reset since): totals since they were cleared.
                    let r = rate(disc, p)
                    if r >= discardRate {
                        totals.append(("\(n) \(dirWord[dir]) \(rateText(r)) per 10,000 packets", r))
                        // ifInUcastPkts & co. are Counter32: on a 1 Gb/s port they can start again
                        // every 48 minutes, so a total of months is what is left since the last
                        // wrap — the rate was presented as exact.
                        if flows[dir].packetsHC == nil, let w = rowsNow[idx].flatMap({ wrapSeconds32(speedBits: $0.speedBits) }),
                           cur.sysUpTime.map({ Double($0) / 100 >= w }) ?? true, !wrapped32.contains(where: { $0.name == n }) {
                            wrapped32.append((n, w))
                        }
                    }
                }
            }
        }
        if !growing.isEmpty, let p = prev {
            let top = growing.sorted { $0.weight > $1.weight }
            return [base("discards", "snmp.discardsGrowing", .warn,
                         "Discards are growing on \(name): \(top.prefix(4).map(\.text).joined(separator: ", ")) in \(FText.duration(cur.taken.timeIntervalSince(p.taken))).",
                         "Between two walks the port dropped good frames at over \(Int(discardRate)) in 10,000 (\(String(format: "%.1f", discardRate / 100)) %) — usually full output buffers (congestion, a fast port feeding a slow one, microbursts) or frames for a VLAN the port does not carry.",
                         ["Check the utilisation of \(top[0].text.split(separator: " ").first.map(String.init) ?? "the port") and its QoS / buffer drops.", "Check allowed VLANs on trunks at both ends."],
                         top.count, cur.taken)]
        }
        if !totals.isEmpty {
            let top = totals.sorted { $0.weight > $1.weight }
            return [base("discards", "snmp.discards", .info,
                         "\(top.count) interface\(top.count == 1 ? "" : "s") on \(name) dropped over \(String(format: "%.1f", discardRate / 100)) % of \(top.count == 1 ? "its" : "their") packets since the counters were cleared: \(top.prefix(4).map(\.text).joined(separator: ", ")).",
                         "Discards are good frames the switch dropped — full buffers or unwanted VLANs. These are totals since the counters were last cleared, so they may be old: walk the Interfaces table again in a few minutes and SheepLog says whether they still grow."
                            + (wrapped32.isEmpty ? "" : " The packet counts of \(FText.list(wrapped32.map(\.name), max: 4)) come from 32-bit counters (ifTable), which start again past 4,294,967,295 — at full rate every \(FText.duration(wrapped32.map(\.wrap).min() ?? 0)) on \(wrapped32.count == 1 ? "that port" : "the fastest of them") — so these totals may be understated and the rate may be far off. An agent with ifXTable (ifHCInUcastPkts) gives the true count; two walks a few minutes apart give the rate between them."),
                         ["Run Interfaces again on the SNMP Test pane in a few minutes."], top.count, cur.taken)]
        }
        return []
    }
}

// MARK: - Text helpers

/// C-string tests over one line (the log pass runs them on every core).
nonisolated enum CText {
    @inline(__always) static func has(_ c: UnsafePointer<CChar>, _ n: String) -> Bool { strcasestr(c, n) != nil }

    static func hasAny(_ c: UnsafePointer<CChar>, _ ns: [String]) -> Bool {
        for n in ns where strcasestr(c, n) != nil { return true }
        return false
    }

    @inline(__always) static func isAlpha(_ b: CChar) -> Bool { (b >= 65 && b <= 90) || (b >= 97 && b <= 122) }

    /// `n` as a whole word (no letter either side).
    static func hasWord(_ c: UnsafePointer<CChar>, _ n: String) -> Bool {
        n.withCString { np -> Bool in
            let len = strlen(np)
            var p = c
            while let hit = strcasestr(p, np) {
                let before: CChar = hit == c ? 0 : hit[-1]
                let after = hit[len]
                if !isAlpha(before) && !isAlpha(after) { return true }
                p = UnsafePointer(hit) + 1
            }
            return false
        }
    }

    static func prefix(_ s: String, _ p: String) -> Bool {
        s.withCString { a in p.withCString { b in strncasecmp(a, b, strlen(b)) == 0 } }
    }

    static func contains(_ s: String, _ n: String) -> Bool {
        s.withCString { a in strcasestr(a, n) != nil }
    }
}

/// Words, addresses, times and durations for the findings' text.
nonisolated enum FText {
    static let clockFormat = Format.gregorian("HH:mm:ss")

    static func clock(_ d: Date) -> String { clockFormat.string(from: d) }

    static func duration(_ s: Double) -> String {
        let s = abs(s)
        if s < 60 { return "\(Int(s.rounded())) s" }
        if s < 3600 {
            let m = Int(s / 60), sec = Int(s) % 60
            return sec == 0 || m >= 10 ? "\(m) min" : "\(m) min \(sec) s"
        }
        if s < 86_400 {
            let h = Int(s / 3600), m = (Int(s) % 3600) / 60
            return m == 0 ? "\(h) h" : "\(h) h \(m) min"
        }
        let d = Int(s / 86_400), h = (Int(s) % 86_400) / 3600
        return h == 0 ? "\(d) d" : "\(d) d \(h) h"
    }

    static func list(_ items: [String], max n: Int) -> String {
        guard items.count > n else {
            if items.count <= 2 { return items.joined(separator: " and ") }
            return items.dropLast().joined(separator: ", ") + " and " + items.last!
        }
        return items.prefix(n).joined(separator: ", ") + " and \(items.count - n) more"
    }

    /// A filter term, quoted unless it is one plain word.
    /// `word:<name>`: an interface (or any name) as a whole word — a plain word `Gi1/0/1` also
    /// showed Gi1/0/10–19's lines, `ether1` ether10's.
    static func wordTerm(_ s: String) -> String { "word:" + quote(s) }

    /// `word:a`, or `(word:a OR word:b)` for a port written two ways.
    static func wordTerms(_ names: Set<String>) -> String {
        let terms = names.sorted().map(wordTerm)
        return terms.count == 1 ? terms[0] : "(" + terms.joined(separator: " OR ") + ")"
    }

    /// Cisco's abbreviations spelled out (`Gi1/0/5` → `GigabitEthernet1/0/5`, `Te1/1/1`,
    /// `Fa0/1`, `Po10`, NX-OS / Arista `Eth1/1` / `Et5`, Huawei `GE0/0/5` / `XGE0/0/1`): the
    /// same port in a PM / err-disable line and in a LINK line. Anything else is kept.
    static func canonicalInterface(_ s: String) -> String {
        let letters = s.prefix { $0.isLetter }
        guard !letters.isEmpty, letters.count < s.count, s[letters.endIndex].isNumber else { return s }
        let full: [String: String] = [
            "gi": "GigabitEthernet", "gig": "GigabitEthernet", "ge": "GigabitEthernet", "fa": "FastEthernet",
            "te": "TenGigabitEthernet", "ten": "TenGigabitEthernet", "tw": "TwoGigabitEthernet", "fi": "FiveGigabitEthernet",
            "twe": "TwentyFiveGigE", "fo": "FortyGigabitEthernet", "hu": "HundredGigE", "po": "Port-channel",
            "eth": "Ethernet", "et": "Ethernet", "xge": "XGigabitEthernet",
        ]
        let lower = letters.lowercased()
        // Linux's eth0 is no NX-OS Ethernet port: the short forms that are also other systems'
        // names only with a slot ("Eth1/1", "GE0/0/5").
        if ["eth", "et", "ge"].contains(lower), !s[letters.endIndex...].contains("/") { return s }
        if let name = full[lower] { return name + s[letters.endIndex...] }
        // Full names in any case ("gigabitethernet1/0/5") read as the same port.
        for name in Set(full.values) where name.lowercased() == lower { return name + s[letters.endIndex...] }
        return s
    }

    static func quote(_ s: String) -> String {
        let plain = s.unicodeScalars.allSatisfy { CharacterSet.alphanumerics.contains($0) || "._-:".unicodeScalars.contains($0) }
        return plain && !s.isEmpty && !["AND", "OR", "NOT", "NOR"].contains(s.uppercased()) ? s : "\"" + s.replacingOccurrences(of: "\"", with: "") + "\""
    }

    static func excerpt(_ s: String, max n: Int = 90) -> String {
        var t = s
        // Drop an AOS-CX "Event|1105|LOG_CRIT|AMM|1/1|" prefix.
        if t.hasPrefix("Event|"), let r = t.range(of: "|", options: .backwards) { t = String(t[r.upperBound...]) }
        if let r = t.range(of: ":", options: []), t.hasPrefix("%%"), t.distance(from: t.startIndex, to: r.lowerBound) < 60 {
            t = String(t[r.upperBound...])
        }
        t = t.trimmingCharacters(in: .whitespaces)
        return t.count > n ? String(t.prefix(n - 1)) + "…" : t
    }

    /// The word after `marker` (case-insensitive), without trailing punctuation.
    static func token(after marker: String, in s: String) -> String? {
        guard let r = s.range(of: marker, options: .caseInsensitive) else { return nil }
        let rest = s[r.upperBound...].drop { $0 == " " || $0 == "=" || $0 == ":" || $0 == "\"" || $0 == "'" }
        var tok = String(rest.prefix { !(" ,;()\"'[]\t".contains($0)) })
        while let l = tok.last, ".:".contains(l) { tok.removeLast() }
        return tok.isEmpty ? nil : tok
    }

    static func isIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 4 && parts.allSatisfy { p in !p.isEmpty && p.count <= 3 && p.allSatisfy(\.isNumber) && (Int(p) ?? 999) <= 255 }
    }

    /// The first IPv6 address after `marker`: a word (up to space, comma, parenthesis or
    /// quote; a trailing "." or ":" dropped) that parses as one.
    static func firstIPv6(after marker: String, in s: String) -> String? {
        guard let r = s.range(of: marker, options: .caseInsensitive) else { return nil }
        for word in s[r.upperBound...].split(whereSeparator: { " ,;()[]\"'=\t".contains($0) }) where word.contains(":") {
            var w = String(word)
            while let l = w.last, l == "." || (l == ":" && !w.hasSuffix("::")) { w.removeLast() }
            var a6 = in6_addr()
            if w.count >= 2, inet_pton(AF_INET6, w, &a6) == 1 { return w.lowercased() }
        }
        return nil
    }

    /// The first IPv4 address after `marker` ("" = anywhere), not `excluding`.
    static func firstIPv4(after marker: String, in s: String, excluding: String? = nil) -> String? {
        var hay = Substring(s)
        if !marker.isEmpty {
            guard let r = s.range(of: marker, options: .caseInsensitive) else { return nil }
            hay = s[r.upperBound...]
        }
        let bytes = Array(hay.utf8)
        var i = 0
        while i < bytes.count {
            if bytes[i] >= 48, bytes[i] <= 57, i == 0 || !(bytes[i - 1] >= 48 && bytes[i - 1] <= 57) && bytes[i - 1] != 46 {
                var j = i
                while j < bytes.count, (bytes[j] >= 48 && bytes[j] <= 57) || bytes[j] == 46 { j += 1 }
                let cand = String(decoding: bytes[i..<j], as: UTF8.self)
                let trimmed = cand.hasSuffix(".") ? String(cand.dropLast()) : cand
                if isIPv4(trimmed), trimmed != excluding { return trimmed }
                i = j
            } else {
                i += 1
            }
        }
        return nil
    }

    /// Every word a failed-login line is picked by (`LineClassifier.login`): a bare `fail` is a
    /// substring, so it also finds "failed" and "failure".
    static let loginFailQuery = "(fail OR invalid OR denied OR incorrect OR wrong OR reject OR unsuccessful OR \"bad password\" OR \"not allowed\" OR \"authentication error\")"

    /// Every word a configuration line is picked by (`LineClassifier.config`).
    static let configQuery = "(config OR commit OR \"write mem\" OR app:111010 OR app:111005 OR app:111008)"

    static func hardwareQuery(_ k: HardwareKind) -> String {
        switch k {
        case .psu: "(power OR psu OR supply OR pem)"
        case .fan: "fan"
        case .temperature: "(temperature OR thermal OR overheat)"
        case .poe: "(poe OR power)"
        }
    }

    static func stpQuery(_ k: STPKind) -> String {
        switch k {
        case .topologyChange, .rootChange: "(stp OR spanning OR topology OR root)"
        case .bpduGuard: "bpdu"
        case .loop: "loop"
        case .storm: "storm"
        }
    }
}
