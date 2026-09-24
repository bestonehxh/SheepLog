import Darwin
import XCTest
@testable import SheepLog

/// Writes one TCP conversation as real Ethernet frames (IPv4 or IPv6, optional 802.1Q tag),
/// tracking both sides' sequence numbers — the frames go through `PacketDecoder`, into a pcap
/// file, and to Wireshark's `tshark` for the ground truth.
struct WireConversation {
    static let FIN: UInt8 = 0x01, SYN: UInt8 = 0x02, RST: UInt8 = 0x04, PSH: UInt8 = 0x08, ACK: UInt8 = 0x10
    static let ECE: UInt8 = 0x40, CWR: UInt8 = 0x80

    var v6 = false
    var vlan: Int?
    var client = "10.1.20.15", server = "93.184.216.34"
    var cport: UInt16 = 51234, sport: UInt16 = 80
    /// Next sequence number of each side.
    var cseq: UInt32 = 1_000, sseq: UInt32 = 5_000
    var cttl: UInt8 = 64, sttl: UInt8 = 57
    var cmac: [UInt8] = [0x02, 0, 0, 0, 0, 0x01], smac: [UInt8] = [0x02, 0, 0, 0, 0, 0x02]
    var cid: UInt16 = 0x1000, sid: UInt16 = 0x7000
    var base = 1_750_000_000.0
    var packets: [Packet] = []

    init(v6: Bool = false, vlan: Int? = nil, cport: UInt16 = 51234, sport: UInt16 = 80) {
        self.v6 = v6
        self.vlan = vlan
        self.cport = cport
        self.sport = sport
        if v6 { client = "2001:db8:20::15"; server = "2001:db8:30::1" }
    }

    static func v6bytes(_ s: String) -> [UInt8] {
        var a = in6_addr()
        _ = inet_pton(AF_INET6, s, &a)
        return withUnsafeBytes(of: &a) { Array($0) }
    }

    /// One frame. `payload` overrides the zero bytes; `omitPayload` writes the headers only
    /// (a capture truncated by its snap length); `ipTotalZero` = TSO (IPv4 total length 0).
    mutating func frame(fromClient: Bool, _ t: Double, _ flags: UInt8, len: Int, seq: UInt32, ack: UInt32,
                        win: UInt16, options: [UInt8] = [], payload: [UInt8]? = nil, omitPayload: Bool = false,
                        ipTotalZero: Bool = false, ttl: UInt8? = nil, ipID: UInt16? = nil, mf: Bool = false,
                        ecnIP: UInt8 = 0) {
        typealias F = PacketFixture
        var opts = options
        while opts.count % 4 != 0 { opts.append(1) }
        let hl = 20 + opts.count
        let body = omitPayload ? [] : (payload ?? [UInt8](repeating: 0x41, count: len))
        let (sp, dp) = fromClient ? (cport, sport) : (sport, cport)
        var tcp = F.be16(Int(sp)) + F.be16(Int(dp)) + F.be32(seq) + F.be32(ack) + [UInt8(hl / 4) << 4, flags]
        tcp += F.be16(Int(win)) + [0, 0, 0, 0] + opts
        let l4len = hl + len
        let src = fromClient ? client : server, dst = fromClient ? server : client
        let hop = ttl ?? (fromClient ? cttl : sttl)
        var ip: [UInt8]
        if v6 {
            ip = [0x60 | (ecnIP >> 4), (ecnIP & 0x0F) << 4, 0, 0] + F.be16(l4len) + [6, hop] + Self.v6bytes(src) + Self.v6bytes(dst)
        } else {
            let id = ipID ?? { () -> UInt16 in
                if fromClient { cid &+= 1; return cid } else { sid &+= 1; return sid }
            }()
            let total = ipTotalZero ? 0 : 20 + l4len
            ip = [0x45, ecnIP] + F.be16(total) + F.be16(Int(id)) + [mf ? 0x20 : 0x40, 0x00]
            ip += [hop, 6, 0, 0] + F.ip4(src) + F.ip4(dst)
        }
        var f = (fromClient ? smac : cmac) + (fromClient ? cmac : smac)
        if let vlan { f += F.be16(0x8100) + F.be16(vlan) }
        f += F.be16(v6 ? 0x86DD : 0x0800) + ip + tcp + body
        while f.count < 60 { f.append(0) }
        let wire = omitPayload ? f.count + len : f.count
        let data = Data(f)
        packets.append(Packet(id: packets.count + 1, timestamp: Date(timeIntervalSince1970: base + t), relative: t,
                              length: wire, captured: data.count, data: data, decoded: PacketDecoder.decode(data)))
    }

    /// Client → server; `seq`/`ack` override the running numbers (the running one is not moved).
    mutating func c(_ t: Double, _ flags: UInt8, len: Int = 0, seq: UInt32? = nil, ack: UInt32? = nil, win: UInt16 = 65535,
                    options: [UInt8] = [], payload: [UInt8]? = nil, omitPayload: Bool = false, ipTotalZero: Bool = false) {
        let s = seq ?? cseq
        frame(fromClient: true, t, flags, len: payload?.count ?? len, seq: s,
              ack: ack ?? (flags & Self.ACK != 0 ? sseq : 0), win: win, options: options, payload: payload,
              omitPayload: omitPayload, ipTotalZero: ipTotalZero)
        if seq == nil { cseq &+= UInt32(payload?.count ?? len) + (flags & (Self.SYN | Self.FIN) != 0 ? 1 : 0) }
    }

    mutating func s(_ t: Double, _ flags: UInt8, len: Int = 0, seq: UInt32? = nil, ack: UInt32? = nil, win: UInt16 = 65535,
                    options: [UInt8] = [], payload: [UInt8]? = nil, omitPayload: Bool = false, ipTotalZero: Bool = false) {
        let q = seq ?? sseq
        frame(fromClient: false, t, flags, len: payload?.count ?? len, seq: q,
              ack: ack ?? (flags & Self.ACK != 0 ? cseq : 0), win: win, options: options, payload: payload,
              omitPayload: omitPayload, ipTotalZero: ipTotalZero)
        if seq == nil { sseq &+= UInt32(payload?.count ?? len) + (flags & (Self.SYN | Self.FIN) != 0 ? 1 : 0) }
    }

    static let synOptions: [UInt8] = [0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x0e, 0x04, 0x02]   // MSS 1460, WS 14, SACK_PERM

    mutating func handshake(at t: Double = 0, rtt: Double = 0.020, ecn: Bool = false) {
        c(t, Self.SYN | (ecn ? Self.ECE | Self.CWR : 0), options: Self.synOptions)
        s(t + rtt, Self.SYN | Self.ACK | (ecn ? Self.ECE : 0), options: Self.synOptions)
        c(t + rtt + 0.0002, Self.ACK)
    }

    mutating func close(at t: Double, rtt: Double = 0.020) {
        c(t, Self.FIN | Self.ACK)
        s(t + rtt, Self.FIN | Self.ACK)
        c(t + rtt + 0.0002, Self.ACK)
    }

    static func http(_ s: String) -> [UInt8] { Array(s.utf8) }
}

final class Round5FlowTests: XCTestCase {
    typealias W = WireConversation

    private var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appending(path: "SheepLogRound5Flows", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    /// Writes `packets` to `<name>.pcap`, reads them back as the app does and analyses them;
    /// with tshark present, also compares every counter with Wireshark's TCP analysis.
    @discardableResult
    private func analyse(_ name: String, _ packets: [Packet], wireshark: Bool = true,
                         file: StaticString = #filePath, line: UInt = #line) throws -> [TCPFlow] {
        let url = dir.appending(path: "\(name).pcap")
        try PcapFile.write(packets, linkType: 1, to: url)
        var read: [Packet] = []
        _ = try PcapFile.read(url) { read += $0 }
        XCTAssertEqual(read.count, packets.count, file: file, line: line)
        let flows = TCPFlowAnalyzer.analyze(read)
        if wireshark, let tshark = CaptureGroundTruthTests.tshark {
            let r = try TCPFlowGroundTruthTests().compare(url, tshark: tshark)
            XCTAssertEqual(r.mismatches, [], "\(name) against Wireshark", file: file, line: line)
        }
        return flows
    }

    private func only(_ flows: [TCPFlow], file: StaticString = #filePath, line: UInt = #line) throws -> TCPFlow {
        XCTAssertEqual(flows.count, 1, "\(flows.map(\.clientEndpoint))", file: file, line: line)
        return try XCTUnwrap(flows.first, file: file, line: line)
    }

    private func problems(_ f: TCPFlow) -> [String] { f.events.compactMap(\.problem) }

    // MARK: 1. Captures that start in the middle

    /// No SYN, data both ways from the first packet: no "SYN never answered", nothing counted
    /// as a retransmission or duplicate ACK, the server by its port.
    func testMidStreamBothDirections() throws {
        var w = W(cport: 51234, sport: 443)
        w.cseq = 3_000_000_000; w.sseq = 123_456_789
        w.s(0, W.PSH | W.ACK, len: 1400)
        w.c(0.001, W.ACK)
        w.c(0.010, W.PSH | W.ACK, len: 200)
        w.s(0.030, W.PSH | W.ACK, len: 900)
        for k in 0..<20 {
            w.s(0.05 + Double(k) * 0.001, W.ACK, len: 1448)
            if k % 2 == 1 { w.c(0.0505 + Double(k) * 0.001, W.ACK) }
        }
        let f = try only(analyse("midstream", w.packets))
        XCTAssertEqual(f.clientPort, 51234)
        XCTAssertEqual(f.serverPort, 443)
        XCTAssertEqual(f.retransmissions, 0)
        XCTAssertEqual(f.dupAcks, 0)
        XCTAssertEqual(f.health, .ok, "\(f.reasons)")
        XCTAssertEqual(f.bytesToClient, 1400 + 900 + 20 * 1448)
        XCTAssertEqual(f.bytesToServer, 200)
        XCTAssertNil(f.handshakeRTT)
    }

    // MARK: 2. Handshakes

    /// SYN, SYN/ACK, and the client never ACKs: the server repeats its SYN/ACK (1, 2, 4 s)
    /// and gives up. A half-open connection (a SYN flood, a client firewall eating the SYN/ACK).
    func testHalfOpenHandshake() throws {
        var w = W()
        w.c(0, W.SYN, options: W.synOptions)
        w.s(0.02, W.SYN | W.ACK, options: W.synOptions)
        for t in [1.02, 3.02, 7.02] { w.s(t, W.SYN | W.ACK, seq: w.sseq &- 1, options: W.synOptions) }
        let f = try only(analyse("halfopen", w.packets))
        XCTAssertEqual(f.retransmissions, 3, "Wireshark: 3 retransmitted SYN, ACKs")
        XCTAssertEqual(f.health, .bad, "\(f.reasons)")
        XCTAssertTrue(f.reasons.contains { $0.contains("handshake never completed") }, "\(f.reasons)")
        XCTAssertFalse(f.reasons.contains { $0.contains("% of data segments") }, "no share of zero data segments: \(f.reasons)")
    }

    /// Simultaneous open (RFC 793 §3.4 figure 8): SYN both ways, then SYN/ACK both ways.
    func testSimultaneousOpen() throws {
        var w = W(cport: 40000, sport: 40001)
        w.c(0, W.SYN, options: W.synOptions)
        w.s(0.0001, W.SYN, options: W.synOptions)
        w.c(0.020, W.SYN | W.ACK, seq: w.cseq &- 1, options: W.synOptions)
        w.s(0.0201, W.SYN | W.ACK, seq: w.sseq &- 1, options: W.synOptions)
        w.c(0.05, W.PSH | W.ACK, len: 10)
        w.s(0.07, W.PSH | W.ACK, len: 10)
        w.c(0.08, W.ACK)
        // Wireshark calls the first SYN/ACK a retransmission (its SYN's sequence number again)
        // and the second one out of order: both are each side's one and only SYN/ACK.
        let f = try only(analyse("simultaneous", w.packets, wireshark: false))
        XCTAssertEqual(f.synRetransmissions, 0, "each side sent one SYN")
        XCTAssertEqual(f.retransmissions, 0)
        XCTAssertEqual(f.outOfOrder, 0)
        XCTAssertEqual(f.notes, ["Simultaneous open: both sides sent a SYN"])
        XCTAssertEqual(f.health, .ok, "\(f.reasons) \(problems(f))")
    }

    /// TCP Fast Open: the request rides in the SYN (with the cookie), the answer follows the
    /// SYN/ACK. The bytes count and the request is timed.
    func testFastOpenDataInSYN() throws {
        var w = W()
        let req = W.http("GET /tfo HTTP/1.1\r\nHost: tfo.example\r\n\r\n")
        w.c(0, W.SYN, options: W.synOptions + [0x22, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8], payload: req)
        w.s(0.020, W.SYN | W.ACK, options: W.synOptions)
        w.s(0.021, W.PSH | W.ACK, payload: W.http("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
        w.c(0.041, W.ACK)
        w.close(at: 0.1)
        let f = try only(analyse("tfo", w.packets))
        XCTAssertEqual(f.bytesToServer, req.count)
        XCTAssertEqual(f.retransmissions, 0)
        XCTAssertEqual(f.health, .ok, "\(f.reasons)")
        XCTAssertEqual(f.requests.first?.request, "GET /tfo")
        XCTAssertEqual(f.requests.first?.responseTime ?? 0, 0.021, accuracy: 1e-6)
        XCTAssertEqual(f.firstResponseTime ?? 0, 0.021, accuracy: 1e-6)
    }

    // MARK: 3. Closes

    /// HTTP/1.0 style: the client half-closes right after its request; the server answers
    /// afterwards and closes. Not a reset, not waiting, healthy.
    func testClientHalfCloseBeforeTheResponse() throws {
        var w = W()
        w.handshake()
        w.c(0.03, W.PSH | W.ACK, payload: W.http("GET / HTTP/1.0\r\n\r\n"))
        w.c(0.0301, W.FIN | W.ACK)
        w.s(0.05, W.ACK)
        w.s(0.25, W.PSH | W.ACK, payload: W.http("HTTP/1.0 200 OK\r\n\r\nhello"))
        w.s(0.2501, W.FIN | W.ACK)
        w.c(0.27, W.ACK)
        let f = try only(analyse("halfclose", w.packets))
        XCTAssertEqual(f.health, .ok, "\(f.reasons)")
        XCTAssertEqual(f.requests.first?.status, "200 OK")
        XCTAssertEqual(f.requests.first?.responseTime ?? 0, 0.22, accuracy: 1e-6)
    }

    /// The server closes (FIN) before it has sent anything — it will not answer.
    func testServerFINBeforeResponding() throws {
        var w = W()
        w.handshake()
        w.c(0.03, W.PSH | W.ACK, payload: W.http("GET /x HTTP/1.1\r\nHost: a\r\n\r\n"))
        w.s(0.05, W.FIN | W.ACK)
        w.c(0.051, W.FIN | W.ACK)
        w.s(0.07, W.ACK)
        let f = try only(analyse("serverfin", w.packets))
        XCTAssertEqual(f.retransmissions, 0)
        XCTAssertNil(f.requests.first?.responseTime)
        XCTAssertTrue(f.reasons.contains { $0.contains("closed without answering") }, "\(f.reasons)")
        XCTAssertEqual(f.health, .warn, "\(f.reasons)")
    }

    /// A buggy peer sends data after its own FIN (RFC 9293: a FIN is the last byte).
    func testDataAfterFIN() throws {
        var w = W()
        w.handshake()
        w.c(0.03, W.PSH | W.ACK, len: 20)
        w.s(0.05, W.PSH | W.ACK, len: 100)
        w.s(0.051, W.FIN | W.ACK)
        w.s(0.052, W.PSH | W.ACK, len: 50)          // after the FIN, at FIN+1
        w.c(0.07, W.ACK)
        w.c(0.071, W.FIN | W.ACK)
        w.s(0.09, W.ACK)
        let f = try only(analyse("dataafterfin", w.packets))
        XCTAssertEqual(f.bytesToClient, 150)
        XCTAssertTrue(problems(f).contains { $0.contains("after its own FIN") }, "\(problems(f))")
        XCTAssertTrue(f.reasons.contains { $0.contains("data after FIN") }, "\(f.reasons)")
    }

    // MARK: 4. Sequence space and time

    /// A 10 GB transfer (64 KB TSO segments captured with a 96-byte snap length) wraps the
    /// server's sequence space twice: no retransmissions, the byte count to the byte.
    func testTenGigabyteTransferWrapsTheSequenceSpace() throws {
        var w = W(cport: 50000, sport: 873)
        w.sseq = 0xF000_0000
        w.handshake()
        w.c(0.03, W.PSH | W.ACK, len: 100)
        let seg = 65_000
        let count = 10_000_000_000 / seg + 1
        var t = 0.05
        for k in 0..<count {
            w.s(t, W.ACK, len: seg, omitPayload: true)
            if k % 2 == 1 { w.c(t + 0.00001, W.ACK) }
            t += 0.00005
        }
        w.close(at: t + 0.01)
        XCTAssertGreaterThan(w.packets.count, 230_000)
        let f = try only(analyse("tengig", w.packets))
        XCTAssertEqual(f.bytesToClient, count * seg)
        XCTAssertGreaterThan(f.bytesToClient, 2 * Int(UInt32.max))
        XCTAssertEqual(f.retransmissions, 0)
        XCTAssertEqual(f.outOfOrder, 0)
        XCTAssertEqual(f.dupAcks, 0)
        XCTAssertEqual(f.health, .ok, "\(f.reasons)")
        XCTAssertLessThan(f.events.count, 100, "one long data group")
    }

    /// Two capture points merged by appending (mergecap -a): the second file's packets come
    /// after the first's in the file but are earlier in time, and each packet is there twice
    /// (another TTL). The analysis runs in time order and counts the copies once.
    func testTimestampsGoingBackwardsFromMergedCaptures() throws {
        var w = W()
        w.handshake()
        w.c(0.03, W.PSH | W.ACK, len: 300)
        w.s(0.06, W.PSH | W.ACK, len: 1200)
        w.c(0.061, W.ACK)
        w.close(at: 0.1)
        let a = w.packets
        let b = a.map { p -> Packet in
            var d = p.data
            // The other capture point is one router hop further: TTL − 1, 300 µs later.
            let ttlOffset = 14 + 8
            d[ttlOffset] = d[ttlOffset] &- 1
            return Packet(id: 0, timestamp: p.timestamp.addingTimeInterval(0.0003), relative: 0, length: p.length,
                          captured: p.captured, data: d, decoded: PacketDecoder.decode(d))
        }
        let merged = (a + b).enumerated().map { n, p in
            Packet(id: n + 1, timestamp: p.timestamp, relative: 0, length: p.length, captured: p.captured,
                   data: p.data, decoded: p.decoded)
        }
        // Wireshark analyses in file order (every copy a retransmission): no tshark comparison.
        let f = try only(analyse("merged", merged, wireshark: false))
        XCTAssertEqual(f.capturedTwice, a.count)
        XCTAssertEqual(f.retransmissions, 0)
        XCTAssertEqual(f.dupAcks, 0)
        XCTAssertEqual(f.health, .ok, "\(f.reasons)")
        XCTAssertGreaterThanOrEqual(f.duration, 0)
        XCTAssertTrue(f.events.allSatisfy { $0.time >= 0 })
        XCTAssertEqual(f.handshakeRTT ?? 0, 0.02, accuracy: 1e-6)
    }

    /// The capture's clock is set back an hour mid-conversation (NTP after a wake, a VM
    /// resumed): capture order is kept, the times after the step follow on, and a note says so —
    /// sorted by time, the second half came before the handshake (SYN never answered,
    /// retransmissions everywhere).
    func testClockSetBackMidFlow() throws {
        var w = W()
        w.handshake()
        w.c(0.03, W.PSH | W.ACK, payload: W.http("GET /a HTTP/1.1\r\nHost: x\r\n\r\n"))
        w.s(0.06, W.PSH | W.ACK, payload: W.http("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
        w.c(0.061, W.ACK)
        let stepAt = w.packets.count
        w.base -= 3_600                                        // the clock goes back an hour
        w.c(0.5, W.PSH | W.ACK, payload: W.http("GET /b HTTP/1.1\r\nHost: x\r\n\r\n"))
        w.s(0.52, W.PSH | W.ACK, payload: W.http("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
        w.close(at: 0.6)
        XCTAssertLessThan(w.packets[stepAt].timestamp, w.packets[0].timestamp)
        // Wireshark analyses in capture order with the raw times: no comparison of durations.
        let f = try only(analyse("clockstep", w.packets, wireshark: false))
        XCTAssertEqual(f.retransmissions, 0)
        XCTAssertEqual(f.synRetransmissions, 0)
        XCTAssertEqual(f.health, .ok, "\(f.reasons)")
        XCTAssertEqual(f.handshakeRTT ?? 0, 0.02, accuracy: 1e-6)
        XCTAssertEqual(f.requests.map(\.request), ["GET /a", "GET /b"])
        XCTAssertEqual(f.requests.last?.responseTime ?? 0, 0.02, accuracy: 1e-6)
        XCTAssertTrue(f.events.map(\.time) == f.events.map(\.time).sorted(), "event times never go back")
        XCTAssertLessThan(f.duration, 3_600)
        XCTAssertEqual(f.notes.count, 1)
        // The step less the 0.44 s that really passed between the two packets.
        XCTAssertTrue(f.notes[0].hasPrefix("The capture's clock went back 3599.6 s at frame \(w.packets[stepAt].id):"), f.notes[0])
    }

    /// A bidirectional SPAN of a routed IPv6 link: every packet twice, the hop limit one lower.
    func testIPv6CapturedTwice() throws {
        var w = W(v6: true, cport: 51000, sport: 443)
        w.handshake()
        w.c(0.03, W.PSH | W.ACK, len: 517)
        w.s(0.05, W.PSH | W.ACK, len: 3000)
        w.c(0.051, W.ACK)
        w.close(at: 0.2)
        var both: [Packet] = []
        for p in w.packets {
            both.append(p)
            var d = p.data
            d[14 + 7] = d[14 + 7] &- 1                    // hop limit
            both.append(Packet(id: 0, timestamp: p.timestamp.addingTimeInterval(0.00002), relative: 0, length: p.length,
                               captured: p.captured, data: d, decoded: PacketDecoder.decode(d)))
        }
        both = both.enumerated().map { n, p in
            Packet(id: n + 1, timestamp: p.timestamp, relative: 0, length: p.length, captured: p.captured, data: p.data, decoded: p.decoded)
        }
        let f = try only(analyse("v6twice", both, wireshark: false))
        XCTAssertEqual(f.capturedTwice, w.packets.count)
        XCTAssertEqual(f.retransmissions, 0)
        XCTAssertEqual(f.dupAcks, 0)
        XCTAssertEqual(f.bytesToClient, 3000)
        XCTAssertEqual(f.health, .ok, "\(f.reasons)")
    }

    /// A SPAN of both directions of one switch port: every packet twice with the same TTL and
    /// MACs — but the same IPv4 identification, which a real retransmission never repeats.
    func testIdenticalCopiesWithTheSameIPIDAreCapturedTwice() throws {
        var w = W()
        w.handshake()
        w.c(0.03, W.PSH | W.ACK, len: 300)
        w.s(0.06, W.PSH | W.ACK, len: 1200)
        w.c(0.061, W.ACK)
        var both: [Packet] = []
        for p in w.packets {
            both.append(p)
            both.append(Packet(id: 0, timestamp: p.timestamp.addingTimeInterval(0.00001), relative: 0, length: p.length,
                               captured: p.captured, data: p.data, decoded: p.decoded))
        }
        both = both.enumerated().map { n, p in
            Packet(id: n + 1, timestamp: p.timestamp, relative: 0, length: p.length, captured: p.captured, data: p.data, decoded: p.decoded)
        }
        let f = try only(analyse("sameport", both, wireshark: false))
        XCTAssertEqual(f.capturedTwice, w.packets.count)
        XCTAssertEqual(f.retransmissions, 0)
        XCTAssertEqual(f.health, .ok, "\(f.reasons)")
    }

    // MARK: 5. Many packets

    /// A capture of one direction only (asymmetric routing): 50,000 pure ACKs. The ladder keeps
    /// < 400 arrows with Collapse ACKs, and building it is quick.
    @MainActor
    func testFiftyThousandPureACKs() throws {
        var w = W()
        w.handshake()
        var ack = w.sseq
        for k in 0..<50_000 {
            ack &+= 1448
            w.c(0.05 + Double(k) * 0.0005, W.ACK, ack: ack)
        }
        let f = try only(analyse("acks", w.packets))
        XCTAssertEqual(f.dupAcks, 0)
        XCTAssertEqual(f.health, .ok, "\(f.reasons)")
        for collapse in [true, false] {
            let t0 = Date()
            let layout = LadderLayout.make(flow: f, collapseAcks: collapse, width: 800)
            XCTAssertLessThan(Date().timeIntervalSince(t0), 0.5)
            XCTAssertLessThanOrEqual(layout.items.count, LadderLayout.cap + 1)
        }
        XCTAssertLessThan(f.events.count, 50, "the ACKs are one group: \(f.events.count) events")
    }

    /// A bulk download with an ACK every other segment: 50,000 ACKs among 100,000 data segments.
    @MainActor
    func testBulkDownloadWithFiftyThousandACKs() throws {
        var w = W()
        w.handshake()
        w.c(0.03, W.PSH | W.ACK, len: 100)
        var t = 0.05
        for k in 0..<100_000 {
            w.s(t, W.ACK, len: 1448, omitPayload: true)
            if k % 2 == 1 { w.c(t + 0.00002, W.ACK) }
            t += 0.00004
        }
        let f = try only(analyse("bulk", w.packets))
        XCTAssertEqual(f.health, .ok, "\(f.reasons)")
        XCTAssertEqual(f.bytesToClient, 100_000 * 1448)
        let layout = LadderLayout.make(flow: f, collapseAcks: true, width: 800)
        XCTAssertLessThan(layout.items.count, 400)
    }

    // MARK: 6. Framing

    /// TSO / GSO: 64 KB segments captured on the sending host (IPv4 total length set, or 0 as
    /// some drivers leave it). Byte counts as tshark counts them.
    func testTSOGiantSegments() throws {
        var w = W()
        w.handshake()
        w.c(0.03, W.PSH | W.ACK, len: 200)
        for k in 0..<10 { w.s(0.05 + Double(k) * 0.001, W.ACK, len: 64_000) }
        w.s(0.07, W.ACK, len: 1400, ipTotalZero: true)
        w.c(0.08, W.ACK)
        let f = try only(analyse("tso", w.packets))
        XCTAssertEqual(f.bytesToClient, 10 * 64_000 + 1400)
        XCTAssertEqual(f.retransmissions, 0)
        XCTAssertEqual(f.health, .ok, "\(f.reasons)")
    }

    /// 802.1Q-tagged TCP is analysed like untagged, IPv4 and IPv6.
    func testTCPOverVLAN() throws {
        for v6 in [false, true] {
            var w = W(v6: v6, vlan: 30)
            w.handshake()
            w.c(0.03, W.PSH | W.ACK, payload: W.http("GET /vlan HTTP/1.1\r\nHost: v\r\n\r\n"))
            w.s(0.06, W.PSH | W.ACK, payload: W.http("HTTP/1.1 204 No Content\r\n\r\n"))
            w.close(at: 0.1)
            XCTAssertEqual(w.packets[0].decoded.vlan, 30)
            let f = try only(analyse("vlan\(v6 ? 6 : 4)", w.packets))
            XCTAssertEqual(f.health, .ok, "\(f.reasons)")
            XCTAssertEqual(f.requests.first?.status, "204 No Content")
            XCTAssertEqual(f.handshakeRTT ?? 0, 0.02, accuracy: 1e-6)
        }
    }

    /// TCP carried in IPv4 fragments. A first fragment whose TCP header is cut short (8 bytes
    /// in the fragment, the frame padded to 60) must not be read from the Ethernet padding; a
    /// first fragment with a whole header is not analysed as a segment (its payload is
    /// elsewhere) but counted; nothing crashes.
    func testTCPInIPv4Fragments() throws {
        var w = W()
        w.handshake()
        // A tiny first fragment: IP total length 28 (8 bytes of TCP), frame padded to 60.
        let typ = PacketFixture.self
        var tiny = w.smac + w.cmac + typ.be16(0x0800)
        tiny += [0x45, 0] + typ.be16(28) + typ.be16(0x4242) + [0x20, 0x00, 64, 6, 0, 0] + typ.ip4(w.client) + typ.ip4(w.server)
        tiny += typ.be16(Int(w.cport)) + typ.be16(Int(w.sport)) + typ.be32(w.cseq)
        while tiny.count < 60 { tiny.append(0) }
        let d = PacketDecoder.decode(Data(tiny))
        XCTAssertNil(d.tcp, "a TCP header cut short by the fragment is not read from the padding")
        XCTAssertTrue(d.info.contains("Fragmented") || d.info.contains("Truncated"), d.info)
        // A first fragment carrying a whole TCP header and 1,000 of the segment's 3,000 bytes.
        w.frame(fromClient: true, 0.03, W.PSH | W.ACK, len: 1_000, seq: w.cseq, ack: w.sseq, win: 65535, mf: true)
        w.packets.append(Packet(id: w.packets.count + 1, timestamp: Date(timeIntervalSince1970: w.base + 0.0301), relative: 0,
                                length: tiny.count, captured: tiny.count, data: Data(tiny), decoded: d))
        w.cseq &+= 3_000
        w.s(0.06, W.ACK)
        w.s(0.07, W.PSH | W.ACK, len: 500)
        w.c(0.08, W.ACK)
        let f = try only(analyse("fragments", w.packets, wireshark: false))
        XCTAssertEqual(f.retransmissions, 0)
        XCTAssertEqual(f.bytesToServer, 0, "the fragment's bytes are not a whole segment")
        XCTAssertTrue(f.notes.contains { $0.contains("IP fragment") }, "\(f.notes)")
        XCTAssertEqual(f.health, .ok, "\(f.reasons)")
    }

    /// ECN negotiated in the handshake, CE marks answered with ECE until the sender's CWR: data
    /// groups are not split by the ECN bits, nothing is a problem, and the congestion signal is
    /// a note.
    func testECNFlags() throws {
        var w = W()
        w.handshake(ecn: true)
        w.c(0.03, W.PSH | W.ACK, len: 100)
        for k in 0..<10 {
            w.s(0.05 + Double(k) * 0.0005, k == 5 ? W.ACK | W.CWR : W.ACK, len: 1448)
            if k % 2 == 1 { w.c(0.0502 + Double(k) * 0.0005, (k >= 1 && k <= 5) ? W.ACK | W.ECE : W.ACK) }
        }
        w.close(at: 0.1)
        let f = try only(analyse("ecn", w.packets))
        XCTAssertEqual(f.health, .ok, "\(f.reasons)")
        XCTAssertEqual(f.retransmissions, 0)
        let dataEvents = f.events.filter { if case .data = $0.kind { true } else { false } }
        XCTAssertLessThanOrEqual(dataEvents.count, 2, "\(f.events.map(\.kind))")
        XCTAssertTrue(f.notes.contains { $0.contains("ECN") }, "\(f.notes)")
    }

    // MARK: 7. Windows and keep-alives

    /// Window scale 14 negotiated; the client's receive buffer fills (window 0), the server
    /// probes with 1-byte zero-window probes, the client opens again. Wireshark: zero window,
    /// zero-window probes and their ACKs — no retransmissions, no duplicate ACKs.
    func testZeroWindowProbesWithWindowScale14() throws {
        var w = W()
        w.handshake()
        w.c(0.03, W.PSH | W.ACK, len: 100)
        for k in 0..<4 { w.s(0.05 + Double(k) * 0.001, W.ACK, len: 1448, win: 4) }
        w.c(0.055, W.ACK, win: 0)                               // full
        for (n, t) in [0.3, 0.9, 2.1, 4.5].enumerated() {
            w.s(t, W.ACK, len: 1, seq: w.sseq, win: 4)          // probe: the next byte, not advanced
            w.c(t + 0.0002, W.ACK, win: 0)                       // still full
            _ = n
        }
        w.c(5.0, W.ACK, win: 2)                                 // window update
        w.s(5.02, W.ACK, len: 1448, win: 4)
        w.c(5.04, W.ACK, win: 2)
        let f = try only(analyse("zwp", w.packets))
        XCTAssertEqual(f.retransmissions, 0, "zero-window probes are not retransmissions: \(problems(f))")
        XCTAssertEqual(f.dupAcks, 0, "their ACKs are not duplicate ACKs")
        XCTAssertGreaterThan(f.zeroWindows, 0)
        XCTAssertEqual(f.health, .bad, "\(f.reasons)")
        XCTAssertEqual(f.reasons, ["zero window from client"])
        XCTAssertEqual(f.bytesToClient, 5 * 1448 + 4, "the probes' bytes are on the wire")
    }

    /// A keep-alive every 30 s for an hour on an idle SSH session: healthy, and the timeline
    /// strip has nothing red.
    @MainActor
    func testHourOfKeepAlives() throws {
        var w = W(cport: 52000, sport: 22)
        w.handshake()
        w.c(0.03, W.PSH | W.ACK, len: 40)
        w.s(0.05, W.PSH | W.ACK, len: 40)
        w.c(0.06, W.ACK)
        for k in 1...120 {
            let t = Double(k) * 30
            w.c(t, W.ACK, seq: w.cseq &- 1)                     // keep-alive (0 bytes, next − 1)
            w.s(t + 0.02, W.ACK)
        }
        let f = try only(analyse("keepalive", w.packets))
        XCTAssertEqual(f.health, .ok, "\(f.reasons)")
        XCTAssertEqual(f.dupAcks, 0)
        XCTAssertEqual(f.retransmissions, 0)
        XCTAssertEqual(f.events.filter { $0.kind == .keepAlive }.count, 120)
        XCTAssertTrue(f.events.allSatisfy { $0.problem == nil }, "\(problems(f))")
        XCTAssertTrue(FlowTimeline.marks(f).isEmpty, "nothing red on the timeline strip")
    }

    // MARK: 8. Who is the client

    /// Both ports below 1024 (rsh from a privileged port, BGP between two routers) and a
    /// capture that starts mid-way: the same client whichever side's packet comes first.
    func testClientChoiceWithTwoPrivilegedPorts() throws {
        for serverFirst in [false, true] {
            var w = W(cport: 1022, sport: 514)
            if serverFirst { w.s(0, W.PSH | W.ACK, len: 10); w.c(0.01, W.PSH | W.ACK, len: 10) }
            else { w.c(0, W.PSH | W.ACK, len: 10); w.s(0.01, W.PSH | W.ACK, len: 10) }
            w.c(0.02, W.ACK)
            let f = try only(analyse("privileged\(serverFirst)", w.packets, wireshark: false))
            XCTAssertEqual(f.clientPort, 1022, "serverFirst \(serverFirst)")
            XCTAssertEqual(f.serverPort, 514)
            XCTAssertEqual(f.health, .ok)
        }
        // A well-known service port wins over "the higher port": 179 ↔ 1023 → the server is 179.
        var b = W(cport: 1023, sport: 179)
        b.s(0, W.PSH | W.ACK, len: 19)
        b.c(0.01, W.ACK)
        XCTAssertEqual(try only(analyse("bgp", b.packets, wireshark: false)).serverPort, 179)
    }
}
