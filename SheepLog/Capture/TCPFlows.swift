import Foundation

/// One TCP conversation, analysed for the ladder diagram and the health table.
nonisolated struct TCPFlow: Identifiable, Sendable {
    nonisolated enum Direction: Sendable { case clientToServer, serverToClient }

    nonisolated enum EventKind: Sendable, Equatable {
        case syn, synAck, ack, fin, rst
        /// `count` consecutive same-direction data segments totalling `bytes`.
        case data(count: Int, bytes: Int)
        case retransmission(bytes: Int)
        /// Old data that is not a retransmission: it arrived within one handshake RTT of the
        /// newest segment (reordered on the way), Wireshark's "TCP Out-Of-Order".
        case outOfOrder(bytes: Int)
        case dupAck(count: Int)
        case zeroWindow
        /// A 1-byte probe into the peer's zero window (Wireshark's "TCP Zero Window Probe"):
        /// not new data, not a retransmission.
        case zeroWindowProbe
        case keepAlive
        case httpRequest(String)
        case httpResponse(String)
        case tlsClientHello(String)
        case tlsServerHello
        /// Nothing happened for `seconds` — drawn as a gap.
        case gap(seconds: Double)
    }

    nonisolated struct Event: Sendable, Identifiable {
        let id: Int
        /// Seconds since the flow's first packet.
        let time: Double
        let direction: Direction
        let kind: EventKind
        /// Frame numbers this event covers.
        let packetIDs: [Int]
        /// A problem worth colouring red, when there is one.
        let problem: String?
        /// Seconds since the flow's first packet of the event's last packet (groups span time).
        var endTime: Double? = nil
    }

    nonisolated enum Health: Sendable { case ok, warn, bad }

    /// Wireshark's verdict on one segment that repeated or preceded sequence space already sent
    /// (`tcp.analysis.retransmission` / `fast_retransmission` / `spurious_retransmission` /
    /// `out_of_order`; the first three all count as retransmissions).
    nonisolated enum SegmentVerdict: Sendable, Equatable {
        case retransmission, fastRetransmission, spuriousRetransmission, outOfOrder
    }

    /// One application request (HTTP) and how long the server took to start answering it.
    nonisolated struct RequestTiming: Sendable, Equatable {
        let request: String
        let time: Double
        var responseTime: Double?
        var status: String?
    }

    let id: Int
    let key: FlowKey
    let client: String
    let clientPort: UInt16
    let server: String
    let serverPort: UInt16
    let firstTime: Date
    let duration: Double
    let packetCount: Int
    let bytesToServer: Int
    let bytesToClient: Int
    let events: [Event]
    /// SYN → SYN/ACK time, when both were seen. With retried SYNs it is measured from the last
    /// SYN before the SYN/ACK (Karn's rule, and Wireshark's): an answer cannot be matched to one
    /// of several identical attempts, and the last one gives the smaller, conservative value.
    let handshakeRTT: Double?
    /// First client data → first server data (for HTTP: the first request → the first byte of
    /// its response; `requests` has every request's own time).
    let firstResponseTime: Double?
    /// Segments that repeated sequence space already sent — Wireshark's
    /// `tcp.analysis.retransmission` count: RTO, fast and spurious retransmissions, repeated
    /// SYN/ACKs and FINs (repeated SYNs are `synRetransmissions`).
    let retransmissions: Int
    let dupAcks: Int
    let resets: Int
    let zeroWindows: Int
    let health: Health
    /// Plain-English reasons for `health` ("3 retransmissions", "server closed with RST", "SYN never answered").
    let reasons: [String]
    /// Application name when recognised ("HTTP", "TLS www.example.com", "SSH").
    let application: String

    // Additive members (defaulted so the memberwise init stays source compatible).

    /// HTTP requests in order, with the time to the first byte of their response.
    var requests: [RequestTiming] = []
    /// Longest wait between the end of a client request and the server's first answering byte.
    var longestResponseWait: Double? = nil
    /// One-way delay between the capture point and the client (half of SYN/ACK → ACK).
    var clientSideDelay: Double? = nil
    /// One-way delay between the capture point and the server (half of SYN → SYN/ACK).
    var serverSideDelay: Double? = nil
    /// Times the client had to repeat its SYN.
    var synRetransmissions: Int = 0
    /// Segments that arrived out of order (not counted in `retransmissions`).
    var outOfOrder: Int = 0
    /// Retransmissions of data the receiver had already acknowledged (counted in
    /// `retransmissions` too): the sender's timer fired too early or the ACK was lost; nothing
    /// was missing.
    var spuriousRetransmissions: Int = 0
    /// The server answered the SYN with RST (closed port, or a firewall rejecting): the
    /// attempt ended at once, as a port scan's does.
    var refused: Bool = false
    /// Packets seen twice by the capture — identical TCP headers a few ms apart on another
    /// VLAN / with another TTL or MAC (a SPAN of both sides of a router): left out of the
    /// analysis so they do not read as retransmissions and duplicate ACKs.
    var capturedTwice: Int = 0
    /// Facts worth knowing that are not problems ("412 packets captured twice (VLAN 10 and 20)").
    var notes: [String] = []
    /// First and last frame number of the conversation (frames of other conversations may lie
    /// between them).
    var firstPacketID: Int = 0
    var lastPacketID: Int = 0
    /// Frame id → verdict, for every retransmitted (fast / spurious too, repeated SYNs and
    /// SYN/ACKs included) or out-of-order segment.
    var verdicts: [Int: SegmentVerdict] = [:]

    var clientEndpoint: String { TCPFlow.endpoint(client, clientPort) }
    var serverEndpoint: String { TCPFlow.endpoint(server, serverPort) }

    static func endpoint(_ address: String, _ port: UInt16) -> String {
        address.contains(":") ? "[\(address)]:\(port)" : "\(address):\(port)"
    }
}

nonisolated enum TCPFlowAnalyzer {
    /// Groups TCP packets into conversations and analyses each. Client = the side that sent SYN
    /// (or the higher port when no SYN was seen).
    static func analyze(_ packets: [Packet]) -> [TCPFlow] {
        analyze(packets) { false }
    }

    /// A 4-tuple silent this long and then opened by a SYN with a new ISN is a new conversation
    /// even when its close was never captured.
    static let reuseIdle: Double = 60

    /// Ladder events kept per conversation, and a note for the rest (a storm of 1,000,000
    /// random-sequence segments is one event — and one text — each).
    static let maxEvents = 20_000

    private struct GroupState {
        var closed = false
        /// ISN of the bare SYN that opened it, when one was seen.
        var isn: UInt32?
        var lastTime: Double = 0
    }

    /// `isCancelled` is polled every few thousand packets (and per flow); when it returns true
    /// the analysis stops and returns `[]`.
    static func analyze(_ packets: [Packet], isCancelled: () -> Bool) -> [TCPFlow] {
        var index: [FlowKey: Int] = [:]
        var groups: [[Int]] = []
        var state: [GroupState] = []
        index.reserveCapacity(1024)

        for i in packets.indices {
            if i & 4095 == 4095, isCancelled() { return [] }
            let d = packets[i].decoded
            guard let tcp = d.tcp, let ip = d.ip else { continue }
            let key = FlowKey(ip.source, tcp.sourcePort, ip.destination, tcp.destinationPort, proto: 6)
            let f = tcp.flags
            let t = packets[i].timestamp.timeIntervalSinceReferenceDate
            let freshSYN = f.contains(.syn) && !f.contains(.ack)
            var reuse = false
            if let g = index[key], freshSYN {
                let s = state[g]
                // A SYN repeating the ISN is a retry of the same attempt (even after a RST);
                // a new ISN after a close, or after a long silence, is a new conversation.
                let retry = s.isn == tcp.sequence
                reuse = !retry && (s.closed || t - s.lastTime > reuseIdle)
            }
            if let g = index[key], !reuse {
                groups[g].append(i)
                if f.contains(.fin) || f.contains(.rst) { state[g].closed = true }
                if freshSYN, state[g].isn == nil { state[g].isn = tcp.sequence }
                state[g].lastTime = max(state[g].lastTime, t)
            } else {
                // New conversation (or the 4-tuple was reused).
                index[key] = groups.count
                groups.append([i])
                state.append(GroupState(closed: f.contains(.fin) || f.contains(.rst),
                                        isn: freshSYN ? tcp.sequence : nil, lastTime: t))
            }
        }

        var flows: [TCPFlow] = []
        flows.reserveCapacity(groups.count)
        for g in groups {
            if isCancelled() { return [] }
            flows.append(analyzeFlow(packets, g))
        }
        flows.sort { $0.firstTime < $1.firstTime }
        return flows.enumerated().map { n, f in f.withID(n + 1) }
    }

    // MARK: Per-flow analysis

    /// A step back in capture order larger than this is the capture clock being set back (NTP
    /// after a sleep, a VM resumed), not packets merged or queued out of order.
    static let clockStep: Double = 1

    private static func analyzeFlow(_ all: [Packet], _ group: [Int]) -> TCPFlow {
        let (order, clockStepped) = timeOrder(all, group)
        let first = all[order[0]], last = all[order[order.count - 1]]
        let (clientAddr, clientPort, serverAddr, serverPort) = pickClient(all, order)
        let screened = screen(all, order)

        var walk = FlowWalk(clientAddr: clientAddr, clientPort: clientPort,
                            t0: first.timestamp.timeIntervalSinceReferenceDate, clockStepped: clockStepped)
        all.withUnsafeBufferPointer { buf in
            for pi in screened.analysed { walk.step(buf[pi]) }
        }
        walk.finish()
        let (health, reasons) = walk.judge()
        var notes = walk.notes(screened)
        if walk.drafts.count > maxEvents {
            notes.append("The ladder shows the first \(Format.count(maxEvents)) of \(Format.count(walk.drafts.count)) events")
            walk.drafts.removeLast(walk.drafts.count - maxEvents)
        }
        let events = walk.drafts.enumerated().map { n, e in
            TCPFlow.Event(id: n, time: e.time, direction: e.direction, kind: e.kind, packetIDs: e.ids,
                          problem: e.problem, endTime: e.lastTime)
        }
        var clientDelay: Double?, serverDelay: Double?
        if let s = walk.lastSYNTime, let sa = walk.synAckTime, sa >= s {
            serverDelay = (sa - s) / 2
            if let a = walk.handshakeAckTime, a >= sa { clientDelay = (a - sa) / 2 }
        }
        let ids = all.withUnsafeBufferPointer { buf in
            var ids = (Int.max, Int.min)
            for pi in order { ids = (min(ids.0, buf[pi].id), max(ids.1, buf[pi].id)) }
            return ids
        }
        return TCPFlow(
            id: 0, key: FlowKey(clientAddr, clientPort, serverAddr, serverPort, proto: 6), client: clientAddr,
            clientPort: clientPort, server: serverAddr, serverPort: serverPort, firstTime: first.timestamp,
            duration: clockStepped ? max(0, walk.lastPacketTime) : last.timestamp.timeIntervalSince(first.timestamp),
            packetCount: order.count, bytesToServer: walk.dirs[0].bytes, bytesToClient: walk.dirs[1].bytes,
            events: events, handshakeRTT: walk.handshakeRTT, firstResponseTime: walk.firstResponse,
            retransmissions: walk.retransmissions, dupAcks: walk.dupAcks, resets: walk.resets,
            zeroWindows: walk.zeroWindowEvents[0] + walk.zeroWindowEvents[1], health: health,
            reasons: reasons, application: walk.appName ?? portName(serverPort),
            requests: walk.requests, longestResponseWait: walk.longestWait,
            clientSideDelay: clientDelay, serverSideDelay: serverDelay,
            synRetransmissions: walk.synRetransmissions, outOfOrder: walk.outOfOrder,
            spuriousRetransmissions: walk.spurious, refused: walk.refused, capturedTwice: screened.copies, notes: notes,
            firstPacketID: ids.0, lastPacketID: ids.1, verdicts: walk.verdicts)
    }

    /// The group in time order, for captures merged from two points (each packet twice, the
    /// second file's after the first's) and multi-queue timestamps a few µs out of order. But a
    /// clock set back mid-capture repeats nothing: sorting would put everything after the step
    /// before the handshake. Then capture order stays (`clockStepped`), and the walk shifts later
    /// times to follow on.
    private static func timeOrder(_ all: [Packet], _ group: [Int]) -> (order: [Int], clockStepped: Bool) {
        var sorted = true
        var bigSteps = 0
        all.withUnsafeBufferPointer { buf in
            var previous = buf[group[0]].timestamp.timeIntervalSinceReferenceDate
            for k in 1..<max(1, group.count) {
                let now = buf[group[k]].timestamp.timeIntervalSinceReferenceDate
                let back = previous - now
                previous = now
                if back > 0 { sorted = false }
                if back > clockStep { bigSteps += 1 }
            }
        }
        guard !sorted else { return (group, false) }
        var byTime = group
        byTime.sort { a, b in
            let ta = all[a].timestamp, tb = all[b].timestamp
            return ta == tb ? a < b : ta < tb
        }
        if bigSteps > 0, !hasCopies(all, byTime) { return (group, true) }
        return (byTime, false)
    }

    /// The packets the walk analyses, and what was left out of it.
    private struct Screened {
        var analysed: [Int] = []
        /// Second copies of packets the capture saw twice (a SPAN of both VLANs of a router, or
        /// of two switch ports): they would read as retransmissions / dup ACKs.
        var copies = 0
        var copyVLANs = Set<UInt16>()
        /// First fragments of fragmented IP datagrams: their TCP header is there, most of the
        /// segment is not (the other fragments carry no TCP header).
        var fragments = 0
    }

    private static func screen(_ all: [Packet], _ order: [Int]) -> Screened {
        var s = Screened()
        s.analysed.reserveCapacity(order.count)
        let keys = CopyKey.keys(all, order)
        /// Positions in `order` of the packets analysed so far.
        var analysedAt: [Int] = []
        analysedAt.reserveCapacity(order.count)
        for k in 0..<order.count {
            let pi = order[k]
            if keys[k].fragment {
                s.fragments += 1
                continue
            }
            if let original = captureCopy(all, order, keys, k, analysedAt[...], from: max(0, analysedAt.count - 8)),
               !reportedByDSACK(all, pi, order[(k + 1)...].prefix(8)) {
                s.copies += 1
                if let v = all[pi].decoded.vlan { s.copyVLANs.insert(v) }
                if let v = all[original].decoded.vlan { s.copyVLANs.insert(v) }
                continue
            }
            s.analysed.append(pi)
            analysedAt.append(k)
        }
        return s
    }

    /// What an exact capture copy repeats, read once per packet: comparing the `Packet`s
    /// themselves copied each one (strings, payload) up to eight times — a quarter of the
    /// analysis in a Debug build.
    private struct CopyKey {
        let time: Double
        let tcp: Bool
        let fragment: Bool
        let sport: UInt16
        let seq: UInt32
        let ack: UInt32
        let flags: UInt8
        let len: Int
        let window: UInt16
        /// Timestamps option; bit 0 / 1 of `hasTS` = value / echo present.
        let tsval: UInt32
        let tsecr: UInt32
        let hasTS: UInt8

        /// `order`'s packets' keys (read in place: a Debug build copies a `Packet` taken out of
        /// the array whole).
        static func keys(_ all: [Packet], _ order: [Int]) -> [CopyKey] {
            all.withUnsafeBufferPointer { buf in
                var out: [CopyKey] = []
                out.reserveCapacity(order.count)
                for pi in order { out.append(CopyKey(buf[pi].timestamp, buf[pi].decoded.ip, buf[pi].decoded.tcp)) }
                return out
            }
        }

        init(_ timestamp: Date, _ ipHeader: IPHeader?, _ tcpHeader: TCPHeader?) {
            time = timestamp.timeIntervalSinceReferenceDate
            fragment = ipHeader.map { $0.moreFragments || $0.fragmentOffset > 0 } ?? false
            guard let t = tcpHeader, ipHeader != nil else {
                tcp = false; sport = 0; seq = 0; ack = 0; flags = 0; len = 0; window = 0; tsval = 0; tsecr = 0; hasTS = 0
                return
            }
            tcp = true
            sport = t.sourcePort
            seq = t.sequence
            ack = t.acknowledgment
            flags = t.flags.rawValue
            len = t.payloadLength
            window = t.window
            tsval = t.timestampValue ?? 0
            tsecr = t.timestampEcho ?? 0
            hasTS = (t.timestampValue != nil ? 1 : 0) | (t.timestampEcho != nil ? 2 : 0)
        }

        /// The TCP header fields `captureCopy` compares (all but the source address).
        func sameSegment(_ o: CopyKey) -> Bool {
            sport == o.sport && seq == o.seq && ack == o.ack && flags == o.flags && len == o.len
                && window == o.window && tsval == o.tsval && tsecr == o.tsecr && hasTS == o.hasTS
        }
    }

    // MARK: The walk through one conversation

    private struct DirState {
        var seqKnown = false
        var lastSeqRaw: UInt32 = 0
        var lastSeqRel: Int64 = 0
        var maxEnd: Int64?
        var lastAck: UInt32?
        var lastWindow: UInt16 = 0
        var bytes = 0
        var sentSYN = false
        var sentFIN = false
        var sentData = false
        /// When each new segment (by relative start) was first sent, to date a retransmission
        /// ("210 ms after the original"). Bounded: cleared past 50,000 entries.
        var sentAt: [Int64: Double] = [:]

        mutating func remember(_ r: Int64, _ t: Double) {
            if sentAt.count >= 50_000 { sentAt.removeAll(keepingCapacity: true) }
            sentAt[r] = t
        }

        /// `seq` relative to this side's first sequence number, without moving the unwrap base
        /// (for the peer's ACK numbers).
        func relPeek(_ seq: UInt32) -> Int64? {
            seqKnown ? lastSeqRel + Int64(Int32(bitPattern: seq &- lastSeqRaw)) : nil
        }

        /// Sequence number relative to the first one seen, unwrapped across 2^32.
        mutating func rel(_ seq: UInt32) -> Int64 {
            guard seqKnown else {
                seqKnown = true; lastSeqRaw = seq; lastSeqRel = 0
                return 0
            }
            lastSeqRel += Int64(Int32(bitPattern: seq &- lastSeqRaw))
            lastSeqRaw = seq
            return lastSeqRel
        }
    }

    private struct Draft {
        var time: Double
        var lastTime: Double
        var direction: TCPFlow.Direction
        var kind: TCPFlow.EventKind
        var ids: [Int]
        var problem: String?
    }

    /// One segment as the walk sees it.
    private struct Segment {
        let id: Int
        /// Seconds since the flow's first packet (after any clock-step shift).
        let t: Double
        let tcp: TCPHeader
        let app: AppLayer?
        let c2s: Bool

        var dir: TCPFlow.Direction { c2s ? .clientToServer : .serverToClient }
        /// Index of the sending side in the per-side arrays (0 = client), and of the other side.
        var d: Int { c2s ? 0 : 1 }
        var o: Int { c2s ? 1 : 0 }
        var side: String { c2s ? "client" : "server" }
        var flags: TCPFlags { tcp.flags }
        var len: Int { tcp.payloadLength }
    }

    /// The state of one conversation, segment by segment: the ladder events (`drafts`), the
    /// counters and the timings.
    private struct FlowWalk {
        let clientAddr: String
        let clientPort: UInt16
        let t0: Double
        let clockStepped: Bool

        var dirs = [DirState(), DirState()]
        var drafts: [Draft] = []
        var openData: Int?
        /// A run of back-to-back retransmitted / reordered segments (SACK recovery resends a
        /// dozen at once): one row "5× Retransmission", not five.
        var openLoss: Int?
        var openLossSeq: (lo: Int64, hi: Int64) = (0, 0)
        var openAck: [Int?] = [nil, nil]
        var openDup: [Int?] = [nil, nil]
        var openZero: [Int?] = [nil, nil]
        /// Each side's last segment was a keep-alive (the peer's same-ACK answer is not a
        /// duplicate ACK), and whether the peer's was when the current segment arrived.
        var sentKeepAlive = [false, false]
        var peerProbed = false

        var lastPacketTime = 0.0
        /// Clock steps: the seconds added to times after each, the first one's frame and size.
        var shift = 0.0
        var previousRaw: Double?
        var firstStep: (frame: Int, seconds: Double)?
        var steps = 0
        var lastSYNTime: Double?
        var lastSYNIndex: Int?
        var synAckTime: Double?
        var handshakeAckTime: Double?
        var handshakeRTT: Double?
        var synRetransmissions = 0
        var retransmissions = 0
        var spurious = 0
        var dupAcks = 0
        var outOfOrder = 0
        /// Wireshark's sequence analysis, run on every segment: it decides retransmission /
        /// fast / spurious / out of order, duplicate ACKs, keep-alives and zero-window probes.
        var sequence = TCPSequenceAnalysis()
        var verdicts: [Int: TCPFlow.SegmentVerdict] = [:]
        var resets = 0
        var zeroWindowEvents = [0, 0]
        /// Each side's SYN/ACKs (a second one from the same side is a retransmission) and
        /// bare SYNs (both sides: a simultaneous open, RFC 9293 §3.5).
        var sentSynAck = [false, false]
        var synAckRetransmissions = 0
        var simultaneousOpen = false
        /// Segments with ECE (the receiver echoing a congestion mark) from each side.
        var eceSegments = [0, 0]
        /// Bytes a side sent after its own FIN.
        var dataAfterFIN = [0, 0]
        /// The client's TLS ClientHello has had no answer yet.
        var clientHelloPending = false
        /// What the server closed on without answering ("GET /x", "the TLS ClientHello").
        var closedUnanswered: String?
        var serverResetEarly = false
        /// The server's RST answered a SYN (no SYN/ACK before it): refused.
        var refusedBySYNReset = false
        var resetSinceSYN = false
        var rstAfterData = false
        var endedWithRST = false
        var anyData = false
        var dataSegments = 0

        var firstClientData: Double?
        var lastClientData: Double?
        /// The client's last data segment: a 1-byte keep-alive probe mid-stream looks like
        /// data until its twin (same sequence number) shows up.
        var lastClientSegment: (r: Int64, len: Int, draft: Int, time: Double)?
        var awaiting = false
        var firstResponse: Double?
        var longestWait: Double?
        var longestWaitFor: String?
        var requests: [TCPFlow.RequestTiming] = []
        var nextUnanswered = 0

        var appName: String?
        var appHasSNI = false

        init(clientAddr: String, clientPort: UInt16, t0: Double, clockStepped: Bool) {
            self.clientAddr = clientAddr
            self.clientPort = clientPort
            self.t0 = t0
            self.clockStepped = clockStepped
            drafts.reserveCapacity(32)
        }

        // MARK: Helpers

        /// The flags a plain data segment may carry and still join the open data row.
        static let plainDataFlags: TCPFlags = [.psh, .ack, .ece, .cwr]

        mutating func closeGroups() {
            openData = nil
            openLoss = nil
            openAck = [nil, nil]
            openDup = [nil, nil]
            openZero = [nil, nil]
        }

        @discardableResult
        mutating func append(_ s: Segment, _ kind: TCPFlow.EventKind, problem: String? = nil) -> Int {
            drafts.append(Draft(time: s.t, lastTime: s.t, direction: s.dir, kind: kind, ids: [s.id], problem: problem))
            return drafts.count - 1
        }

        /// Adds the segment to the open event `g`.
        mutating func extend(_ g: Int, _ s: Segment) {
            drafts[g].ids.append(s.id)
            drafts[g].lastTime = s.t
        }

        mutating func noteApp(_ app: AppLayer?) {
            guard let app else { return }
            switch app {
            case .tlsClientHello(let sni, _):
                if let sni, !sni.isEmpty { appName = "TLS \(sni)"; appHasSNI = true }
                else if appName == nil { appName = "TLS" }
            case .tlsServerHello, .tlsOther:
                if appName == nil { appName = "TLS" }
            default:
                if appName == nil || (!appHasSNI && appName == "TLS" && app.name != "TLS") { appName = app.name }
            }
        }

        /// What the server is being waited on for: the oldest unanswered HTTP request, else
        /// nothing specific.
        func waitingFor() -> String? {
            nextUnanswered < requests.count ? requests[nextUnanswered].request : nil
        }

        /// Seconds since the flow's first packet; after a clock step (`clockStepped`) later
        /// times are shifted to follow on.
        mutating func time(of p: Packet) -> Double {
            let raw = p.timestamp.timeIntervalSinceReferenceDate - t0
            if clockStepped, let pr = previousRaw, pr - raw > clockStep {
                shift += pr - raw
                steps += 1
                if firstStep == nil { firstStep = (p.id, pr - raw) }
            }
            previousRaw = raw
            return raw + shift
        }

        // MARK: Segments

        mutating func step(_ p: Packet) {
            guard let tcp = p.decoded.tcp, let ip = p.decoded.ip else { return }
            let s = Segment(id: p.id, t: time(of: p), tcp: tcp, app: p.decoded.app,
                            c2s: ip.source == clientAddr && tcp.sourcePort == clientPort)
            let f = s.flags
            dirs[s.d].bytes += s.len
            if f.contains(.ece), !f.contains(.syn) { eceSegments[s.d] += 1 }
            if s.len > 0 { dataSegments += 1 }
            noteApp(s.app)
            noteIdle(until: s.t)
            lastPacketTime = s.t
            // Whole microseconds: a Date near 2026 resolves ~0.24 µs, so a 20.000 ms gap read
            // back from a pcap came out as 19.9999998 ms (Wireshark's "< 20 ms" said fast).
            let ws = sequence.analyse(fromClient: s.c2s, timeNS: Int64((s.t * 1e6).rounded()) * 1000, tcp: tcp)
            peerProbed = sentKeepAlive[s.o]
            sentKeepAlive[s.d] = false
            defer {
                if f.contains(.ack) {
                    dirs[s.d].lastAck = tcp.acknowledgment
                    dirs[s.d].lastWindow = tcp.window
                }
            }
            if f.contains(.rst) { reset(s); return }
            endedWithRST = false
            if f.contains(.syn) { syn(s); return }
            let r = dirs[s.d].rel(tcp.sequence)
            if s.len > 0 { data(s, r, ws) }
            else if f.contains(.fin) { emptyFIN(s, r, ws) }
            else if f.contains(.ack) { emptyACK(s, r, ws) }
        }

        /// Idle time between packets: a gap event.
        mutating func noteIdle(until t: Double) {
            guard !drafts.isEmpty, t - lastPacketTime > 1.0 else { return }
            closeGroups()
            let idle = t - lastPacketTime
            var problem: String?
            if awaiting, idle > 3 {
                problem = "Idle \(seconds(idle)) waiting for the server" + (waitingFor().map { " to answer \($0)" } ?? "")
            }
            drafts.append(Draft(time: lastPacketTime, lastTime: t, direction: .clientToServer,
                                kind: .gap(seconds: idle), ids: [], problem: problem))
        }

        mutating func reset(_ s: Segment) {
            closeGroups()
            resets += 1
            // After a FIN, a RST is how many stacks (browsers, load balancers) finish the close
            // quickly: not a problem.
            let afterFIN = dirs[0].sentFIN || dirs[1].sentFIN
            endedWithRST = !afterFIN
            let answersSYN = !s.c2s && synAckTime == nil && dirs[0].sentSYN && !anyData
            if answersSYN { refusedBySYNReset = true; resetSinceSYN = true }
            else if !s.c2s && !dirs[1].sentData && !afterFIN { serverResetEarly = true }
            if anyData { rstAfterData = true }
            let problem: String?
            if afterFIN { problem = nil }
            else if answersSYN { problem = "Refused: the server answered the SYN with RST (port closed, or a firewall rejecting)" }
            else if !s.c2s && !dirs[1].sentData { problem = "Server reset the connection before sending any data" }
            else { problem = "Reset by \(s.side)" + (anyData ? " after \(Format.count(dirs[0].bytes + dirs[1].bytes)) bytes" : "") }
            append(s, .rst, problem: problem)
        }

        mutating func syn(_ s: Segment) {
            closeGroups()
            let d = s.d, t = s.t
            let r = dirs[d].rel(s.tcp.sequence)
            dirs[d].maxEnd = r + 1 + Int64(s.len)
            var problem: String?
            guard s.flags.contains(.ack) else {
                if dirs[d].sentSYN {
                    synRetransmissions += 1
                    verdicts[s.id] = .retransmission
                    problem = (resetSinceSYN ? "SYN tried again after the RST" : "SYN retransmitted")
                        + (lastSYNTime.map { " (\(msText(t - $0)) after the previous one)" } ?? "")
                } else if !s.c2s, dirs[0].sentSYN {
                    simultaneousOpen = true
                }
                resetSinceSYN = false
                dirs[d].sentSYN = true
                lastSYNTime = t
                lastSYNIndex = append(s, .syn, problem: problem)
                // TCP Fast Open: data in the SYN is the client's first request.
                if s.c2s, s.len > 0 {
                    if case .httpRequest(let text)? = appEvent(s.app) {
                        requests.append(.init(request: text, time: t))
                    }
                    if case .tlsClientHello? = appEvent(s.app) { clientHelloPending = true }
                    if firstClientData == nil { firstClientData = t }
                    lastClientData = t
                    awaiting = true
                }
                return
            }
            if sentSynAck[d] {
                retransmissions += 1
                synAckRetransmissions += 1
                verdicts[s.id] = .retransmission
                problem = "SYN, ACK retransmitted (the \(s.c2s ? "server" : "client")'s ACK did not arrive)"
            } else if synAckTime != nil {
                // The other side's SYN/ACK of a simultaneous open.
            } else {
                synAckTime = t
                if let synTime = lastSYNTime {
                    handshakeRTT = t - synTime
                    if t - synTime > 0.3 { problem = "Slow handshake: the SYN, ACK came \(msText(t - synTime)) after the SYN" }
                }
            }
            dirs[d].sentSYN = true
            sentSynAck[d] = true
            append(s, .synAck, problem: problem)
        }

        /// 0 or 1 byte one below what the peer has acknowledged: a keep-alive (RFC 1122
        /// §4.2.3.6: SEG.SEQ = SND.NXT − 1). Wireshark only knows one from the side's own next
        /// sequence number, so in a capture that began mid-connection it calls the first 1-byte
        /// probe a spurious retransmission and every 0-byte probe (and its answer) a duplicate
        /// ACK; with the side's data in the capture both rules agree.
        func belowPeerAck(_ s: Segment) -> Bool {
            guard s.len <= 1, !s.flags.contains(.fin), let peerAck = dirs[s.o].lastAck else { return false }
            return peerAck == s.tcp.sequence &+ 1
        }

        /// A segment carrying data (`r` = its relative sequence number, `ws` Wireshark's flags).
        mutating func data(_ s: Segment, _ r: Int64, _ ws: TCPSequenceAnalysis.Flags) {
            let d = s.d, len = s.len, f = s.flags
            let end = r + Int64(len)
            if ws.contains(.zeroWindowProbe), !f.contains(.fin) {
                // Zero-window probe: the next byte, into a window the peer said is closed.
                // It does not move this side's sequence (the peer does not take it).
                openData = nil
                append(s, .zeroWindowProbe)
                return
            }
            if ws.contains(.keepAlive) || belowPeerAck(s) {
                keepAlive(s, r)
            } else if !ws.isDisjoint(with: .resent) {
                resent(s, r, ws)
            } else {
                newData(s, r)
            }
            if s.tcp.window == 0 {
                zeroWindowEvents[d] += 1
                append(s, .zeroWindow, problem: "Zero window: the \(s.side) cannot take more data (its receive buffer is full)")
            }
            if f.contains(.fin) {
                closeGroups()
                dirs[d].maxEnd = max(dirs[d].maxEnd ?? 0, end + 1)
                dirs[d].sentFIN = true
                append(s, .fin)
            }
        }

        mutating func keepAlive(_ s: Segment, _ r: Int64) {
            openData = nil
            append(s, .keepAlive)
            sentKeepAlive[s.d] = true
            // The first probe of a mid-stream capture was taken for a 1-byte request.
            if s.c2s, let last = lastClientSegment, last.r == r, last.len <= 1 {
                drafts[last.draft].kind = .keepAlive
                for i in last.draft..<drafts.count {
                    if case .gap = drafts[i].kind { drafts[i].problem = nil }
                }
                awaiting = false
                if firstResponse == nil, firstClientData == last.time { firstClientData = nil }
                lastClientSegment = nil
            }
            if dirs[s.d].maxEnd == nil { dirs[s.d].maxEnd = r + 1 }
        }

        /// Old data: a retransmission, or a segment reordered on the way — as Wireshark decides
        /// (`TCPSequenceAnalysis`): spurious when the peer had already acknowledged it, fast
        /// when it answers the peer's duplicate ACKs within 20 ms, out of order when it came
        /// within the initial RTT of the peer's last segment and was not seen before, else a
        /// retransmission.
        mutating func resent(_ s: Segment, _ r: Int64, _ ws: TCPSequenceAnalysis.Flags) {
            let d = s.d, len = s.len, t = s.t
            let end = r + Int64(len)
            openData = nil
            let acked = ws.contains(.spuriousRetransmission)
            let fast = ws.contains(.fastRetransmission)
            let reordered = ws.contains(.outOfOrder)
            dirs[d].maxEnd = max(dirs[d].maxEnd ?? end, end)
            if reordered { outOfOrder += 1 } else { retransmissions += 1 }
            if acked { spurious += 1 }
            verdicts[s.id] = acked ? .spuriousRetransmission : fast ? .fastRetransmission : reordered ? .outOfOrder : .retransmission
            if let g = openLoss, drafts[g].direction == s.dir, t - drafts[g].lastTime <= 0.1 {
                switch (drafts[g].kind, reordered) {
                case (.retransmission(let b), false):
                    drafts[g].kind = .retransmission(bytes: b + len)
                    openLossSeq = (min(openLossSeq.lo, r), max(openLossSeq.hi, end))
                    drafts[g].problem = "\(drafts[g].ids.count + 1) retransmissions, seq \(Format.count(Int(openLossSeq.lo)))–"
                        + "\(Format.count(Int(openLossSeq.hi))), \(Format.count(b + len)) bytes"
                    extend(g, s)
                    return
                case (.outOfOrder(let b), true):
                    drafts[g].kind = .outOfOrder(bytes: b + len)
                    extend(g, s)
                    return
                default: break
                }
            }
            // ACKs after this row are drawn after it: an open ACK / dup-ACK row from before the
            // loss must not take them in (the ladder would show them above the retransmission).
            openAck = [nil, nil]
            openDup = [nil, nil]
            if reordered {
                openLoss = append(s, .outOfOrder(bytes: len))
                return
            }
            let what = acked ? "Spurious retransmission" : fast ? "Fast retransmission" : "Retransmission"
            var text = "\(what) of seq \(Format.count(Int(r))), \(Format.count(len)) bytes"
            if let original = dirs[d].sentAt[r] { text += ", \(msText(t - original)) after the original" }
            else if !acked { text += " (original not in the capture)" }
            if acked { text += " (already acknowledged)" }
            openLoss = append(s, .retransmission(bytes: len), problem: text)
            openLossSeq = (r, end)
        }

        /// New data: a data event (or an application one), and the request / response timing.
        mutating func newData(_ s: Segment, _ r: Int64) {
            let d = s.d, len = s.len, t = s.t
            let afterOwnFIN = dirs[d].sentFIN
            dirs[d].maxEnd = max(dirs[d].maxEnd ?? 0, r + Int64(len))
            dirs[d].remember(r, t)
            dirs[d].sentData = true
            anyData = true
            let appKind = appEvent(s.app)
            if s.c2s {
                if case .tlsClientHello? = appKind { clientHelloPending = true }
            } else {
                clientHelloPending = false
            }
            let eventIndex: Int
            if let appKind {
                closeGroups()
                eventIndex = append(s, appKind)
                if case .httpRequest(let text) = appKind {
                    requests.append(.init(request: text, time: t))
                }
            } else if let od = openData, drafts[od].direction == s.dir,
                      t - drafts[od].lastTime <= 0.1,
                      s.flags.subtracting(Self.plainDataFlags).isEmpty,
                      case .data(let n, let b) = drafts[od].kind {
                drafts[od].kind = .data(count: n + 1, bytes: b + len)
                extend(od, s)
                eventIndex = od
            } else {
                closeGroups()
                eventIndex = append(s, .data(count: 1, bytes: len))
                openData = eventIndex
            }

            if afterOwnFIN {
                dataAfterFIN[d] += len
                if drafts[eventIndex].problem == nil {
                    drafts[eventIndex].problem = "The \(s.side) sent data after its own FIN (a FIN is the last byte a side sends)"
                }
            }

            if s.c2s {
                if firstClientData == nil { firstClientData = t }
                lastClientData = t
                lastClientSegment = (r, len, eventIndex, t)
                awaiting = true
            } else {
                serverAnswers(s, eventIndex: eventIndex, appKind: appKind)
            }
        }

        /// Server data: the wait it ended, and which request it answers.
        mutating func serverAnswers(_ s: Segment, eventIndex: Int, appKind: TCPFlow.EventKind?) {
            let t = s.t
            let startsAnswer = awaiting
            if awaiting {
                awaiting = false
                if firstResponse == nil, let fc = firstClientData { firstResponse = t - fc }
                if let lc = lastClientData {
                    let wait = t - lc
                    if wait > (longestWait ?? 0) { longestWait = wait; longestWaitFor = waitingFor() }
                    if wait > 1, drafts[eventIndex].problem == nil, drafts[eventIndex].ids.first == s.id {
                        drafts[eventIndex].problem = "The server took \(seconds(wait)) to answer"
                            + (waitingFor().map { " \($0)" } ?? "")
                    }
                }
            }
            guard nextUnanswered < requests.count else { return }
            // HTTP/1.1 answers in request order: each response header belongs to the oldest
            // unanswered request (pipelining sends several first). An interim 1xx (100
            // Continue) answers first but the final status follows.
            if case .httpResponse(let status)? = appKind {
                let code = Int(status.prefix(3)) ?? 0
                if requests[nextUnanswered].responseTime == nil {
                    requests[nextUnanswered].responseTime = t - requests[nextUnanswered].time
                }
                requests[nextUnanswered].status = status
                if !(100...199).contains(code) || code == 101 { nextUnanswered += 1 }
            } else if startsAnswer {
                // A response whose header was not recognised (captured mid-way, or split
                // oddly): its first byte still times the oldest open request.
                if requests[nextUnanswered].responseTime != nil, nextUnanswered + 1 < requests.count {
                    nextUnanswered += 1
                }
                if requests[nextUnanswered].responseTime == nil {
                    requests[nextUnanswered].responseTime = t - requests[nextUnanswered].time
                }
            }
        }

        /// A FIN without data.
        mutating func emptyFIN(_ s: Segment, _ r: Int64, _ ws: TCPSequenceAnalysis.Flags) {
            let d = s.d
            closeGroups()
            var problem: String?
            if ws.contains(.outOfOrder) {
                outOfOrder += 1
                verdicts[s.id] = .outOfOrder
                problem = "FIN out of order (it arrived before the \(s.side)'s last data)"
            } else if !ws.isDisjoint(with: .resent) {
                retransmissions += 1
                verdicts[s.id] = ws.contains(.fastRetransmission) ? .fastRetransmission : .retransmission
                problem = dirs[d].sentFIN ? "FIN retransmitted (the \(s.c2s ? "server" : "client") did not acknowledge it)"
                                          : "FIN retransmitted"
            } else {
                dirs[d].maxEnd = max(dirs[d].maxEnd ?? 0, r + 1)
            }
            if !s.c2s, !dirs[1].sentFIN, awaiting, problem == nil {
                if let w = waitingFor() { closedUnanswered = w }
                else if clientHelloPending { closedUnanswered = "the TLS ClientHello" }
                if let what = closedUnanswered {
                    problem = "The server closed the connection without answering \(what)"
                }
            }
            dirs[d].sentFIN = true
            append(s, .fin, problem: problem)
        }

        /// A pure ACK: handshake ACK, keep-alive, duplicate ACK, zero window, or plain ACK.
        mutating func emptyACK(_ s: Segment, _ r: Int64, _ ws: TCPSequenceAnalysis.Flags) {
            let d = s.d, o = s.o, ack = s.tcp.acknowledgment
            if dirs[d].maxEnd == nil { dirs[d].maxEnd = r }

            if s.tcp.window == 0 {
                if let z = openZero[d] {
                    extend(z, s)
                } else {
                    zeroWindowEvents[d] += 1
                    openZero[d] = append(s, .zeroWindow,
                                         problem: "Zero window: the \(s.side) cannot take more data (its receive buffer is full)")
                }
                return
            }
            openZero[d] = nil

            if ws.contains(.keepAlive) || belowPeerAck(s) {
                append(s, .keepAlive)
                sentKeepAlive[d] = true
            } else if ws.contains(.keepAliveAck) || (peerProbed && ack == dirs[d].lastAck) {
                // keep-alive ACK: not news
            } else if s.c2s, synAckTime != nil, handshakeAckTime == nil, !anyData {
                handshakeAckTime = s.t
                closeGroups()
                append(s, .ack)
            } else if ws.contains(.dupAck) {
                // RFC 5681 duplicate ACK (same ACK, same window, no data, at the next sequence
                // number), or — RFC 6675 and Wireshark — the same ACK carrying SACK blocks.
                dupAcks += 1
                if let g = openDup[d], case .dupAck(let n) = drafts[g].kind {
                    drafts[g].kind = .dupAck(count: n + 1)
                    extend(g, s)
                    if n + 1 >= 3 {
                        let missing = dirs[o].relPeek(ack).map { " for seq \(Format.count(Int($0)))" } ?? ""
                        drafts[g].problem = "\(n + 1) duplicate ACKs\(missing): the \(s.side) is missing that segment"
                    }
                } else {
                    openAck[d] = nil
                    openDup[d] = append(s, .dupAck(count: 1))
                }
            } else if dirs[d].lastAck.map({ Int32(bitPattern: ack &- $0) > 0 }) ?? true {
                openDup[d] = nil
                if let g = openAck[d] {
                    extend(g, s)
                } else {
                    openAck[d] = append(s, .ack)
                }
            }
            // else: a window update — no event of its own.
        }

        // MARK: Verdict

        var refused: Bool { refusedBySYNReset && synAckTime == nil }

        /// The server answered, the client never completed the handshake — and the server had
        /// time to notice (it repeated its SYN/ACK, or 3 s passed): a half-open connection.
        var halfOpen: Bool {
            synAckTime != nil && handshakeAckTime == nil && !anyData && !simultaneousOpen
                && !dirs[0].sentData && resets == 0 && !dirs[0].sentFIN
                && (synAckRetransmissions > 0 || lastPacketTime - (synAckTime ?? 0) > 3)
        }

        var synNeverAnswered: Bool {
            dirs[0].sentSYN && synAckTime == nil && !anyData && !(resets > 0 && serverResetEarly) && !refused
        }

        /// After the last segment: a request still open at the end of the capture, and the SYN
        /// nobody answered.
        mutating func finish() {
            if awaiting, let lc = lastClientData, !dirs[1].sentFIN, resets == 0 {
                let wait = lastPacketTime - lc
                if wait > 3, wait > (longestWait ?? 0) { longestWait = wait; longestWaitFor = waitingFor() }
            }
            if synNeverAnswered, let i = lastSYNIndex {
                drafts[i].problem = "No answer to the SYN" + (synRetransmissions > 0 ? " (\(synRetransmissions + 1) attempts)" : "")
            }
        }

        /// Health and its reasons (problems first, then warnings).
        func judge() -> (TCPFlow.Health, [String]) {
            var bad: [String] = []
            var warn: [String] = []
            if synNeverAnswered {
                bad.append(synRetransmissions > 0 ? "SYN never answered (\(synRetransmissions + 1) attempts)"
                                                  : "SYN never answered")
            } else if refused {
                warn.append("refused (RST to the SYN)" + (synRetransmissions > 0 ? ", \(synRetransmissions + 1) attempts" : ""))
            } else if synRetransmissions > 0 {
                warn.append(synRetransmissions == 1 ? "SYN retransmitted" : "SYN retransmitted \(synRetransmissions)×")
            }
            if halfOpen {
                bad.append("handshake never completed: no ACK from the client to the SYN, ACK"
                           + (synAckRetransmissions > 0 ? " (\(synAckRetransmissions + 1) attempts)" : ""))
            } else if synAckRetransmissions > 0 {
                warn.append(synAckRetransmissions == 1 ? "SYN, ACK retransmitted" : "SYN, ACK retransmitted \(synAckRetransmissions)×")
            }
            if serverResetEarly { bad.append("server reset the connection") }
            // Repeated SYN/ACKs are judged above, as the handshake.
            let lost = retransmissions - spurious - synAckRetransmissions
            // Loss is judged by its share: 6 resends in a 1,000-segment download (0.6 %) slow it
            // a little; 3 in a 10-segment exchange stall it. Bad from 3 resends that are ≥ 2 %.
            let share = Double(lost) / Double(max(1, dataSegments))
            let shareText = lost >= 3 && dataSegments > 0 ? String(format: " (%.1f %% of data segments)", share * 100) : ""
            if lost >= 3, share >= 0.02 { bad.append("\(lost) retransmissions" + shareText) }
            else if lost > 0 { warn.append((lost == 1 ? "1 retransmission" : "\(lost) retransmissions") + shareText) }
            if spurious > 0 { warn.append(spurious == 1 ? "1 spurious retransmission" : "\(spurious) spurious retransmissions") }
            if zeroWindowEvents[0] > 0 { bad.append("zero window from client") }
            if zeroWindowEvents[1] > 0 { bad.append("zero window from server") }
            if let w = longestWait, w > 3 {
                bad.append("server took \(seconds(w)) to answer" + (longestWaitFor.map { " \($0)" } ?? ""))
            } else if let fr = firstResponse, fr > 1 {
                warn.append("server took \(seconds(fr)) to answer" + (requests.first.map { " \($0.request)" } ?? ""))
            }
            if outOfOrder > 0 { warn.append(outOfOrder == 1 ? "1 segment out of order" : "\(outOfOrder) segments out of order") }
            if dupAcks >= 3 { warn.append("\(dupAcks) duplicate ACKs") }
            if let rtt = handshakeRTT, rtt > 0.3 { warn.append("slow handshake (\(msText(rtt)))") }
            if endedWithRST, rstAfterData, !serverResetEarly { warn.append("connection ended with RST") }
            if let what = closedUnanswered { warn.append("server closed without answering \(what)") }
            for (k, name) in ["client", "server"].enumerated() where dataAfterFIN[k] > 0 {
                warn.append("data after FIN from the \(name) (\(Format.count(dataAfterFIN[k])) bytes)")
            }
            return (!bad.isEmpty ? .bad : (!warn.isEmpty ? .warn : .ok), bad + warn)
        }

        /// Facts worth knowing that are not problems.
        func notes(_ screened: Screened) -> [String] {
            var notes: [String] = []
            if let s = firstStep {
                notes.append("The capture's clock went back \(seconds(s.seconds)) at frame \(s.frame)"
                             + (steps > 1 ? " (and \(steps - 1) more time\(steps == 2 ? "" : "s"))" : "")
                             + ": the analysis keeps capture order and shifts later times to follow on")
            }
            let fragments = screened.fragments
            if fragments > 0 {
                notes.append("\(Format.count(fragments)) IP fragment\(fragments == 1 ? "" : "s") of TCP segments not analysed "
                             + "(the rest of each segment is in fragments without a TCP header)")
            }
            if simultaneousOpen { notes.append("Simultaneous open: both sides sent a SYN") }
            for (k, name) in ["client", "server"].enumerated() where eceSegments[k] > 0 {
                notes.append("ECN: the \(name) echoed a congestion mark (ECE) in \(Format.count(eceSegments[k])) segment"
                             + (eceSegments[k] == 1 ? "" : "s") + " — the network signalled congestion instead of dropping")
            }
            let copies = screened.copies
            if copies > 0 {
                let vlans = screened.copyVLANs.sorted().map(String.init)
                notes.append("\(Format.count(copies)) packet\(copies == 1 ? "" : "s") captured twice"
                             + (vlans.count >= 2 ? " (VLAN \(vlans.joined(separator: " and ")))" : "") + ", counted once")
            }
            return notes
        }
    }

    /// Some packet of `order` (time order) is a capture copy of one just before it.
    private static func hasCopies(_ all: [Packet], _ order: [Int]) -> Bool {
        let keys = CopyKey.keys(all, order)
        let positions = Array(order.indices)
        for k in order.indices.dropFirst() where captureCopy(all, order, keys, k, positions[..<k], from: max(0, k - 8)) != nil {
            return true
        }
        return false
    }

    /// The receiver's next segment reports `pi` as received twice (a D-SACK, RFC 2883: a first
    /// SACK block at or below its ACK covering the segment): the duplicate reached the host —
    /// a network duplicate (Wi-Fi, a loop), not the capture seeing one packet twice.
    private static func reportedByDSACK(_ all: [Packet], _ pi: Int, _ next: ArraySlice<Int>) -> Bool {
        let p = all[pi]
        guard let t = p.decoded.tcp, let ip = p.decoded.ip, t.payloadLength > 0 else { return false }
        for qi in next {
            let q = all[qi]
            guard let u = q.decoded.tcp, let qip = q.decoded.ip else { continue }
            if q.timestamp.timeIntervalSince(p.timestamp) > 0.05 { break }
            guard qip.source == ip.destination, u.sourcePort == t.destinationPort else { continue }
            guard u.sackEdges.count >= 2 else { return false }
            let left = u.sackEdges[0], right = u.sackEdges[1]
            let end = t.sequence &+ UInt32(t.payloadLength)
            return TCPSequenceAnalysis.le(right, u.acknowledgment)
                && TCPSequenceAnalysis.le(left, t.sequence) && TCPSequenceAnalysis.ge(right, end)
        }
        return false
    }

    /// `pi` repeats one of the last few packets exactly (TCP header, timestamps option) within
    /// 50 ms but was seen on another VLAN, with another TTL or other MACs: the same packet
    /// captured twice. Returns the original. A retransmission on one link keeps its MACs and TTL.
    /// `order[k]` against the packets at the positions `previous[from...]` (positions in
    /// `order`, newest last); `keys[i]` is `order[i]`'s `CopyKey`.
    private static func captureCopy(_ all: [Packet], _ order: [Int], _ keys: [CopyKey],
                                    _ k: Int, _ previous: ArraySlice<Int>, from: Int) -> Int? {
        let pk = keys[k]
        guard pk.tcp else { return nil }
        var n = previous.endIndex
        while n > max(from, previous.startIndex) {
            n -= 1
            let j = previous[n]
            let qk = keys[j]
            if pk.time - qk.time > 0.05 { break }
            // Most packets repeat nothing: only a header match reads the packets themselves.
            guard qk.tcp, qk.sameSegment(pk) else { continue }
            let p = all[order[k]], q = all[order[j]], qi = order[j]
            guard let t = p.decoded.tcp, let ip = p.decoded.ip else { return nil }
            guard let u = q.decoded.tcp, let qip = q.decoded.ip,
                  qip.source == ip.source, u.sourcePort == t.sourcePort,
                  u.sequence == t.sequence, u.acknowledgment == t.acknowledgment, u.flags == t.flags,
                  u.payloadLength == t.payloadLength, u.window == t.window,
                  u.timestampValue == t.timestampValue, u.timestampEcho == t.timestampEcho else { continue }
            let elsewhere = q.decoded.vlan != p.decoded.vlan || qip.ttl != ip.ttl
                || q.decoded.sourceMAC != p.decoded.sourceMAC || q.decoded.destinationMAC != p.decoded.destinationMAC
            // Or the very same IPv4 datagram (a SPAN of both directions of one port, or of
            // ingress and egress): a retransmission is a new datagram with a new
            // identification. 0 is left out — some stacks send every DF datagram with ID 0.
            let sameDatagram = ip.version == 4 && ip.identification != 0 && qip.identification == ip.identification
            return elsewhere || sameDatagram ? qi : nil
        }
        return nil
    }

    /// Client = sender of the first bare SYN; else receiver of the first SYN/ACK; else the side
    /// without a well-known port; else the higher port.
    private static func pickClient(_ all: [Packet], _ order: [Int]) -> (String, UInt16, String, UInt16) {
        for i in order {
            guard let tcp = all[i].decoded.tcp, let ip = all[i].decoded.ip, tcp.flags.contains(.syn) else { continue }
            if tcp.flags.contains(.ack) {
                return (ip.destination, tcp.destinationPort, ip.source, tcp.sourcePort)
            }
            return (ip.source, tcp.sourcePort, ip.destination, tcp.destinationPort)
        }
        let p = all[order[0]].decoded
        let src = p.ip?.source ?? "", dst = p.ip?.destination ?? ""
        let sp = p.tcp?.sourcePort ?? 0, dp = p.tcp?.destinationPort ?? 0
        let srcIsClient: Bool
        if dp < 1024, sp >= 1024 { srcIsClient = true }
        else if sp < 1024, dp >= 1024 { srcIsClient = false }
        else if sp != dp { srcIsClient = sp > dp }
        else { srcIsClient = true }
        return srcIsClient ? (src, sp, dst, dp) : (dst, dp, src, sp)
    }

    private static func appEvent(_ app: AppLayer?) -> TCPFlow.EventKind? {
        switch app {
        case .httpRequest(let method, let path, _)?: .httpRequest("\(method) \(path)")
        case .httpResponse(let status, let reason)?: .httpResponse(reason.isEmpty ? "\(status)" : "\(status) \(reason)")
        case .tlsClientHello(let sni, _)?: .tlsClientHello(sni ?? "")
        case .tlsServerHello?: .tlsServerHello
        default: nil
        }
    }

    static func portName(_ port: UInt16) -> String {
        switch port {
        case 21: "FTP"
        case 22: "SSH"
        case 23: "Telnet"
        case 25, 587: "SMTP"
        case 53: "DNS"
        case 80, 8080, 8000: "HTTP"
        case 110: "POP3"
        case 143: "IMAP"
        case 179: "BGP"
        case 389: "LDAP"
        case 443: "TLS"
        case 445: "SMB"
        case 636: "LDAPS"
        case 993: "IMAPS"
        case 995: "POP3S"
        case 1433: "SQL Server"
        case 3306: "MySQL"
        case 3389: "RDP"
        case 5432: "PostgreSQL"
        case 6379: "Redis"
        default: "port \(port)"
        }
    }

    static func seconds(_ s: Double) -> String { String(format: "%.1f s", s) }

    static func msText(_ s: Double) -> String {
        let ms = s * 1000
        if ms < 10 { return String(format: "%.1f ms", ms) }
        if ms < 1_000 { return String(format: "%.0f ms", ms) }
        if ms < 10_000 { return String(format: "%.2f s", s) }
        return String(format: "%.1f s", s)
    }
}

nonisolated extension TCPFlow {
    func withID(_ newID: Int) -> TCPFlow {
        TCPFlow(id: newID, key: key, client: client, clientPort: clientPort, server: server,
                serverPort: serverPort, firstTime: firstTime, duration: duration, packetCount: packetCount,
                bytesToServer: bytesToServer, bytesToClient: bytesToClient, events: events,
                handshakeRTT: handshakeRTT, firstResponseTime: firstResponseTime,
                retransmissions: retransmissions, dupAcks: dupAcks, resets: resets, zeroWindows: zeroWindows,
                health: health, reasons: reasons, application: application, requests: requests,
                longestResponseWait: longestResponseWait, clientSideDelay: clientSideDelay,
                serverSideDelay: serverSideDelay, synRetransmissions: synRetransmissions, outOfOrder: outOfOrder,
                spuriousRetransmissions: spuriousRetransmissions, refused: refused, capturedTwice: capturedTwice,
                notes: notes, firstPacketID: firstPacketID, lastPacketID: lastPacketID, verdicts: verdicts)
    }
}

// MARK: - Synthetic packets (tests and the `-demoFlows 1` launch argument)

nonisolated enum TCPFlowDemo {
    static let base = Date(timeIntervalSinceReferenceDate: 780_000_000)

    /// A TCP/IPv4 packet with a hand-filled `Decoded`; `data` is zeros (54-byte header + payload).
    static func packet(id: Int, t: Double, src: String, sport: UInt16, dst: String, dport: UInt16,
                       flags: TCPFlags, seq: UInt32, ack: UInt32, len: Int, window: UInt16 = 65535,
                       app: AppLayer? = nil) -> Packet {
        let ip = IPHeader(version: 4, source: src, destination: dst, proto: 6, ttl: 64, identification: 0,
                          dontFragment: true, moreFragments: false, fragmentOffset: 0, headerLength: 20,
                          totalLength: 40 + len, dscp: 0)
        let tcp = TCPHeader(sourcePort: sport, destinationPort: dport, sequence: seq, acknowledgment: ack,
                            flags: flags, window: window, headerLength: 20, payloadLength: len,
                            mss: flags.contains(.syn) ? 1460 : nil, windowScale: nil, sackPermitted: false,
                            sackBlocks: 0, timestampValue: nil, timestampEcho: nil)
        var d = Decoded()
        d.sourceMAC = "02:00:00:00:00:01"
        d.destinationMAC = "02:00:00:00:00:02"
        d.etherType = 0x0800
        d.ip = ip
        d.tcp = tcp
        d.app = app
        d.payloadOffset = 54
        d.protocolName = app?.name ?? "TCP"
        d.info = "\(sport) → \(dport) [\(flags.label)] Len=\(len)"
        return Packet(id: id, timestamp: base.addingTimeInterval(t), relative: t, length: 54 + len,
                      captured: 54 + len, data: Data(count: 54 + len), decoded: d)
    }

    /// Writes one conversation, tracking sequence numbers for both sides.
    struct Script {
        var packets: [Packet] = []
        var nextID: Int
        let client: String, clientPort: UInt16, server: String, serverPort: UInt16
        var cseq: UInt32 = 1_000
        var sseq: UInt32 = 50_000
        let offset: Double

        init(firstID: Int = 1, offset: Double = 0, client: String, clientPort: UInt16,
             server: String, serverPort: UInt16) {
            nextID = firstID
            self.offset = offset
            self.client = client; self.clientPort = clientPort
            self.server = server; self.serverPort = serverPort
        }

        /// Client → server. `seq` overrides the running sequence (for retransmissions).
        mutating func c(_ t: Double, _ flags: TCPFlags, len: Int = 0, seq: UInt32? = nil,
                        window: UInt16 = 65535, app: AppLayer? = nil) {
            let s = seq ?? cseq
            packets.append(TCPFlowDemo.packet(id: nextID, t: offset + t, src: client, sport: clientPort,
                                              dst: server, dport: serverPort, flags: flags, seq: s,
                                              ack: flags.contains(.ack) ? sseq : 0, len: len, window: window, app: app))
            nextID += 1
            if seq == nil { cseq &+= UInt32(len) + (flags.contains(.syn) || flags.contains(.fin) ? 1 : 0) }
        }

        /// Server → client.
        mutating func s(_ t: Double, _ flags: TCPFlags, len: Int = 0, seq: UInt32? = nil,
                        window: UInt16 = 65535, app: AppLayer? = nil, ack: UInt32? = nil) {
            let q = seq ?? sseq
            packets.append(TCPFlowDemo.packet(id: nextID, t: offset + t, src: server, sport: serverPort,
                                              dst: client, dport: clientPort, flags: flags, seq: q,
                                              ack: ack ?? cseq, len: len, window: window, app: app))
            nextID += 1
            if seq == nil { sseq &+= UInt32(len) + (flags.contains(.syn) || flags.contains(.fin) ? 1 : 0) }
        }

        /// Client ACK carrying an explicit acknowledgment number (for duplicate ACKs).
        mutating func cAck(_ t: Double, ack: UInt32, window: UInt16 = 65535) {
            packets.append(TCPFlowDemo.packet(id: nextID, t: offset + t, src: client, sport: clientPort,
                                              dst: server, dport: serverPort, flags: .ack, seq: cseq,
                                              ack: ack, len: 0, window: window))
            nextID += 1
        }

        mutating func handshake(rtt: Double, at t: Double = 0) {
            c(t, .syn)
            s(t + rtt, [.syn, .ack])
            c(t + rtt + 0.0001, .ack)
        }
    }

    /// The demo capture: a clean HTTP exchange like the textbook figure, a TLS transfer with loss,
    /// a SYN nobody answers, a slow API call and a refused port.
    static func packets() -> [Packet] {
        var all: [Packet] = []
        let me = "10.1.20.15"

        // 1. Clean HTTP GET, client-side capture, RTT 56 ms, 40 ms of server processing.
        var h = Script(firstID: 1, client: me, clientPort: 51234, server: "93.184.216.34", serverPort: 80)
        h.handshake(rtt: 0.056)
        h.c(0.0562, [.psh, .ack], len: 142, app: .httpRequest(method: "GET", path: "/file", host: "example.com"))
        h.s(0.1522, .ack, len: 1460, app: .httpResponse(status: 200, reason: "OK"))
        for k in 0..<10 {
            h.s(0.1530 + Double(k) * 0.0004, k == 9 ? [.psh, .ack] : .ack, len: 1460)
            if k % 2 == 1 { h.c(0.1540 + Double(k) * 0.0004, .ack) }
        }
        h.s(0.2102, [.fin, .ack])
        h.c(0.2104, .ack)
        h.c(0.2110, [.fin, .ack])
        h.s(0.2670, .ack)
        all += h.packets

        // 2. TLS download with a lost segment: 3 duplicate ACKs, fast retransmit, then two RTOs.
        var l = Script(firstID: 100, offset: 0.4, client: me, clientPort: 51240, server: "10.1.30.8", serverPort: 443)
        l.handshake(rtt: 0.012)
        l.c(0.0125, [.psh, .ack], len: 517, app: .tlsClientHello(sni: "files.corp.example", version: "TLS 1.3"))
        l.s(0.0260, [.psh, .ack], len: 1200, app: .tlsServerHello(version: "TLS 1.3"))
        l.c(0.0280, [.psh, .ack], len: 80, app: .tlsOther(recordType: "Application Data"))
        for k in 0..<4 { l.s(0.0420 + Double(k) * 0.0005, .ack, len: 1460, app: .tlsOther(recordType: "Application Data")) }
        let lostSeq = l.sseq
        l.sseq &+= 1460                                     // this segment never arrives
        let ackBeforeLoss = lostSeq
        l.cAck(0.0445, ack: ackBeforeLoss)
        for k in 0..<3 {
            l.s(0.0450 + Double(k) * 0.0005, .ack, len: 1460, app: .tlsOther(recordType: "Application Data"))
            l.cAck(0.0452 + Double(k) * 0.0005, ack: ackBeforeLoss)
        }
        l.s(0.0580, .ack, len: 1460, seq: lostSeq)          // fast retransmit
        l.s(0.2600, .ack, len: 1460, seq: lostSeq)          // RTO
        l.s(0.7600, .ack, len: 1460, seq: lostSeq)          // RTO again
        l.c(0.7720, .ack)
        l.s(0.7800, [.psh, .ack], len: 900, app: .tlsOther(recordType: "Application Data"))
        l.c(0.7920, .ack)
        l.c(0.8000, [.fin, .ack])
        l.s(0.8120, [.fin, .ack])
        l.c(0.8121, .ack)
        all += l.packets

        // 3. SSH to a host that never answers: the SYN is retried twice.
        var n = Script(firstID: 200, offset: 0.9, client: me, clientPort: 51250, server: "10.1.40.20", serverPort: 22)
        n.c(0, .syn)
        n.c(1.0, .syn, seq: 1_000)
        n.c(3.0, .syn, seq: 1_000)
        all += n.packets

        // 4. A slow API call: the server takes 4.2 s to answer the POST.
        var s = Script(firstID: 300, offset: 1.2, client: me, clientPort: 51262, server: "10.1.30.12", serverPort: 8080)
        s.handshake(rtt: 0.004)
        s.c(0.0045, [.psh, .ack], len: 380, app: .httpRequest(method: "POST", path: "/api/report", host: "reports.corp.example"))
        s.s(0.0085, .ack)
        s.s(4.2100, [.psh, .ack], len: 820, app: .httpResponse(status: 200, reason: "OK"))
        s.c(4.2140, .ack)
        s.c(4.2200, [.fin, .ack])
        s.s(4.2240, [.fin, .ack])
        s.c(4.2241, .ack)
        all += s.packets

        // 5. A closed port: SYN answered by RST.
        var r = Script(firstID: 400, offset: 1.5, client: me, clientPort: 51270, server: "10.1.30.9", serverPort: 8443)
        r.c(0, .syn)
        r.s(0.0011, [.rst, .ack], seq: 0)
        all += r.packets

        // 6. A healthy TLS session.
        var t = Script(firstID: 500, offset: 2.0, client: me, clientPort: 51280, server: "17.253.144.10", serverPort: 443)
        t.handshake(rtt: 0.018)
        t.c(0.0182, [.psh, .ack], len: 517, app: .tlsClientHello(sni: "www.apple.com", version: "TLS 1.3"))
        t.s(0.0370, [.psh, .ack], len: 2800, app: .tlsServerHello(version: "TLS 1.3"))
        t.c(0.0390, [.psh, .ack], len: 420, app: .tlsOther(recordType: "Application Data"))
        for k in 0..<6 { t.s(0.0620 + Double(k) * 0.0004, .ack, len: 1400, app: .tlsOther(recordType: "Application Data")) }
        t.c(0.0650, .ack)
        t.c(0.2000, [.fin, .ack])
        t.s(0.2180, [.fin, .ack])
        t.c(0.2181, .ack)
        all += t.packets

        // Frame numbers in capture order, as a real file would have them.
        return all.sorted { $0.timestamp < $1.timestamp }.enumerated().map { n, p in
            Packet(id: n + 1, timestamp: p.timestamp, relative: p.relative, length: p.length,
                   captured: p.captured, data: p.data, decoded: p.decoded)
        }
    }
}
