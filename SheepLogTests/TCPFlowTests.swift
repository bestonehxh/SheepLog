import XCTest
@testable import SheepLog

final class TCPFlowTests: XCTestCase {
    private var nextID = 1
    private let client = "10.1.20.15"
    private let server = "93.184.216.34"

    override func setUp() { nextID = 1 }

    private func pkt(t: Double, src: String, sport: UInt16, dst: String, dport: UInt16, flags: TCPFlags,
                     seq: UInt32, ack: UInt32, len: Int, window: UInt16 = 65535, app: AppLayer? = nil) -> Packet {
        defer { nextID += 1 }
        return TCPFlowDemo.packet(id: nextID, t: t, src: src, sport: sport, dst: dst, dport: dport, flags: flags,
                                  seq: seq, ack: ack, len: len, window: window, app: app)
    }

    /// Client → server / server → client shorthands for one connection 51234 ⇄ 80.
    private func c(_ t: Double, _ f: TCPFlags, seq: UInt32, ack: UInt32, len: Int = 0, window: UInt16 = 65535,
                   app: AppLayer? = nil) -> Packet {
        pkt(t: t, src: client, sport: 51234, dst: server, dport: 80, flags: f, seq: seq, ack: ack, len: len,
            window: window, app: app)
    }

    private func s(_ t: Double, _ f: TCPFlags, seq: UInt32, ack: UInt32, len: Int = 0, window: UInt16 = 65535,
                   app: AppLayer? = nil) -> Packet {
        pkt(t: t, src: server, sport: 80, dst: client, dport: 51234, flags: f, seq: seq, ack: ack, len: len,
            window: window, app: app)
    }

    /// SYN at 0, SYN/ACK at 28 ms, ACK at 56 ms. Client ISN 1000, server ISN 5000.
    private func handshake() -> [Packet] {
        [c(0, .syn, seq: 1000, ack: 0),
         s(0.028, [.syn, .ack], seq: 5000, ack: 1001),
         c(0.056, .ack, seq: 1001, ack: 5001)]
    }

    private func onlyFlow(_ packets: [Packet], file: StaticString = #filePath, line: UInt = #line) -> TCPFlow? {
        let flows = TCPFlowAnalyzer.analyze(packets)
        XCTAssertEqual(flows.count, 1, file: file, line: line)
        return flows.first
    }

    // (a) The textbook exchange.
    func testCleanHTTPExchange() throws {
        var p = handshake()
        p.append(c(0.0561, [.psh, .ack], seq: 1001, ack: 5001, len: 100,
                   app: .httpRequest(method: "GET", path: "/file", host: "example.com")))
        var sseq: UInt32 = 5001
        for k in 0..<10 {
            p.append(s(0.096 + Double(k) * 0.001, .ack, seq: sseq, ack: 1101, len: 1460))
            sseq += 1460
            if k % 2 == 1 { p.append(c(0.0965 + Double(k) * 0.001, .ack, seq: 1101, ack: sseq)) }
        }
        p.append(s(0.150, [.fin, .ack], seq: sseq, ack: 1101))
        p.append(c(0.151, .ack, seq: 1101, ack: sseq + 1))
        p.append(c(0.152, [.fin, .ack], seq: 1101, ack: sseq + 1))
        p.append(s(0.180, .ack, seq: sseq + 1, ack: 1102))

        let flow = try XCTUnwrap(onlyFlow(p))
        let kinds = flow.events.map(\.kind)
        XCTAssertEqual(Array(kinds.prefix(6)), [.syn, .synAck, .ack, .httpRequest("GET /file"),
                                                .data(count: 10, bytes: 14_600), .ack])
        XCTAssertEqual(flow.events[5].packetIDs.count, 5, "the five client ACKs are one grouped event")
        XCTAssertEqual(Array(kinds.suffix(4)), [.fin, .ack, .fin, .ack])
        XCTAssertEqual(flow.client, client)
        XCTAssertEqual(flow.clientPort, 51234)
        XCTAssertEqual(flow.serverPort, 80)
        XCTAssertEqual(flow.handshakeRTT ?? 0, 0.028, accuracy: 0.0005)
        XCTAssertEqual(flow.firstResponseTime ?? 0, 0.0399, accuracy: 0.001)
        XCTAssertEqual(flow.health, .ok, "\(flow.reasons)")
        XCTAssertEqual(flow.reasons, [])
        XCTAssertEqual(flow.application, "HTTP")
        XCTAssertEqual(flow.retransmissions, 0)
        XCTAssertEqual(flow.dupAcks, 0)
        XCTAssertEqual(flow.bytesToServer, 100)
        XCTAssertEqual(flow.bytesToClient, 14_600)
        XCTAssertEqual(flow.requests.first?.request, "GET /file")
        XCTAssertEqual(flow.requests.first?.responseTime ?? 0, 0.0399, accuracy: 0.001)
        XCTAssertEqual(flow.id, 1)
        XCTAssertTrue(flow.events.allSatisfy { $0.problem == nil })
    }

    // (b)
    func testSYNNeverAnswered() throws {
        let flow = try XCTUnwrap(onlyFlow([c(0, .syn, seq: 1000, ack: 0)]))
        XCTAssertEqual(flow.health, .bad)
        XCTAssertTrue(flow.reasons.contains("SYN never answered"), "\(flow.reasons)")
        XCTAssertEqual(flow.events.map(\.kind), [.syn])
        XCTAssertNotNil(flow.events[0].problem)
    }

    // (c)
    func testThreeRetransmissions() throws {
        var p = handshake()
        p.append(c(0.057, [.psh, .ack], seq: 1001, ack: 5001, len: 100))
        p.append(s(0.100, .ack, seq: 5001, ack: 1101, len: 1460))
        p.append(s(0.400, .ack, seq: 5001, ack: 1101, len: 1460))
        p.append(s(0.900, .ack, seq: 5001, ack: 1101, len: 1460))
        p.append(s(1.500, .ack, seq: 5001, ack: 1101, len: 1460))
        p.append(c(1.520, .ack, seq: 1101, ack: 6461))
        let flow = try XCTUnwrap(onlyFlow(p))
        XCTAssertEqual(flow.retransmissions, 3)
        XCTAssertEqual(flow.health, .bad)
        XCTAssertEqual(flow.reasons, ["3 retransmissions (60.0 % of data segments)"])
        let retrans = flow.events.filter { if case .retransmission = $0.kind { return true } else { return false } }
        XCTAssertEqual(retrans.count, 3)
        XCTAssertTrue(retrans.allSatisfy { $0.direction == .serverToClient })
        // Specific: which bytes, how many, how long after the original.
        XCTAssertEqual(retrans.map(\.problem), ["Retransmission of seq 1, 1,460 bytes, 300 ms after the original",
                                                "Retransmission of seq 1, 1,460 bytes, 800 ms after the original",
                                                "Retransmission of seq 1, 1,460 bytes, 1.40 s after the original"])
    }

    // (d)
    func testServerResetAfterHandshake() throws {
        var p = handshake()
        p.append(s(0.060, [.rst, .ack], seq: 5001, ack: 1001))
        let flow = try XCTUnwrap(onlyFlow(p))
        XCTAssertEqual(flow.health, .bad)
        XCTAssertEqual(flow.resets, 1)
        XCTAssertTrue(flow.reasons.contains("server reset the connection"), "\(flow.reasons)")
        XCTAssertFalse(flow.reasons.contains { $0.hasPrefix("SYN") })
        XCTAssertEqual(flow.events.last?.kind, .rst)
    }

    // (e)
    func testSlowResponse() throws {
        var p = handshake()
        p.append(c(0.057, [.psh, .ack], seq: 1001, ack: 5001, len: 200,
                   app: .httpRequest(method: "POST", path: "/api", host: nil)))
        p.append(s(0.090, .ack, seq: 5001, ack: 1201))
        p.append(s(4.057, [.psh, .ack], seq: 5001, ack: 1201, len: 500,
                   app: .httpResponse(status: 200, reason: "OK")))
        p.append(c(4.080, .ack, seq: 1201, ack: 5501))
        let flow = try XCTUnwrap(onlyFlow(p))
        XCTAssertEqual(flow.health, .bad)
        XCTAssertEqual(flow.reasons, ["server took 4.0 s to answer POST /api"])
        XCTAssertEqual(flow.firstResponseTime ?? 0, 4.0, accuracy: 0.01)
        let gap = try XCTUnwrap(flow.events.first { if case .gap = $0.kind { return true } else { return false } })
        if case .gap(let secs) = gap.kind { XCTAssertEqual(secs, 3.967, accuracy: 0.01) }
        XCTAssertNotNil(gap.problem, "an idle gap during an open request is a problem")
        XCTAssertEqual(flow.requests.first?.status, "200 OK")
    }

    // (f)
    func testDuplicateACKs() throws {
        var p = handshake()
        p.append(c(0.057, [.psh, .ack], seq: 1001, ack: 5001, len: 100))
        // Server sends 4 segments; the one at 6461 is lost.
        p.append(s(0.090, .ack, seq: 5001, ack: 1101, len: 1460))
        p.append(c(0.0905, .ack, seq: 1101, ack: 6461))
        p.append(s(0.091, .ack, seq: 7921, ack: 1101, len: 1460))
        p.append(c(0.0915, .ack, seq: 1101, ack: 6461))
        p.append(s(0.092, .ack, seq: 9381, ack: 1101, len: 1460))
        p.append(c(0.0925, .ack, seq: 1101, ack: 6461))
        p.append(s(0.093, .ack, seq: 10841, ack: 1101, len: 1460))
        p.append(c(0.0935, .ack, seq: 1101, ack: 6461))
        // Fast retransmit fills the hole.
        p.append(s(0.094, .ack, seq: 6461, ack: 1101, len: 1460))
        p.append(c(0.0945, .ack, seq: 1101, ack: 12301))
        let flow = try XCTUnwrap(onlyFlow(p))
        XCTAssertEqual(flow.dupAcks, 3)
        XCTAssertEqual(flow.retransmissions, 1)
        XCTAssertEqual(flow.health, .warn, "\(flow.reasons)")
        XCTAssertTrue(flow.reasons.contains("3 duplicate ACKs"), "\(flow.reasons)")
        let dup = try XCTUnwrap(flow.events.first { if case .dupAck = $0.kind { return true } else { return false } })
        XCTAssertEqual(dup.kind, .dupAck(count: 3))
        XCTAssertEqual(dup.problem, "3 duplicate ACKs for seq 1,461: the client is missing that segment")
    }

    // (g)
    func testClientDetectionWithoutSYN() throws {
        // Capture started mid-conversation: the first packet seen is from the server (port 443).
        let a = "10.1.20.15", b = "17.253.144.10"
        let p = [
            pkt(t: 0, src: b, sport: 443, dst: a, dport: 50000, flags: [.psh, .ack], seq: 9000, ack: 100, len: 500),
            pkt(t: 0.01, src: a, sport: 50000, dst: b, dport: 443, flags: .ack, seq: 100, ack: 9500, len: 0),
            pkt(t: 0.02, src: a, sport: 50000, dst: b, dport: 443, flags: [.psh, .ack], seq: 100, ack: 9500, len: 80),
        ]
        let flow = try XCTUnwrap(onlyFlow(p))
        XCTAssertEqual(flow.client, a)
        XCTAssertEqual(flow.clientPort, 50000)
        XCTAssertEqual(flow.server, b)
        XCTAssertEqual(flow.serverPort, 443)
        XCTAssertEqual(flow.events.first?.direction, .serverToClient)
        XCTAssertEqual(flow.application, "TLS")

        // Two ephemeral ports: the higher one is the client.
        let q = [pkt(t: 0, src: a, sport: 8443, dst: b, dport: 61000, flags: [.psh, .ack], seq: 1, ack: 1, len: 10)]
        let f2 = try XCTUnwrap(TCPFlowAnalyzer.analyze(q).first)
        XCTAssertEqual(f2.clientPort, 61000)
        XCTAssertEqual(f2.application, "port 8443")
    }

    func testDemoSetShapes() {
        let flows = TCPFlowAnalyzer.analyze(TCPFlowDemo.packets())
        XCTAssertEqual(flows.count, 6)
        XCTAssertEqual(flows.map(\.id), Array(1...6))
        XCTAssertEqual(flows[0].health, .ok, "\(flows[0].reasons)")
        XCTAssertEqual(flows[1].health, .bad, "\(flows[1].reasons)")
        XCTAssertEqual(flows[1].application, "TLS files.corp.example")
        XCTAssertEqual(flows[2].health, .bad)
        XCTAssertEqual(flows[3].health, .bad)
        XCTAssertEqual(flows[4].health, .warn, "a refused port is a fact, not a broken network")
        XCTAssertTrue(flows[4].refused)
        XCTAssertEqual(flows[5].health, .ok, "\(flows[5].reasons)")
    }

    // MARK: Review: sequence space, conversation splitting, keep-alives, closes, HTTP timing

    func testSequenceWraparoundIsNotRetransmission() throws {
        let isn: UInt32 = 0xFFFF_FF00
        var p = [c(0, .syn, seq: isn, ack: 0),
                 s(0.01, [.syn, .ack], seq: 7, ack: isn &+ 1),
                 c(0.02, .ack, seq: isn &+ 1, ack: 8)]
        var seq = isn &+ 1
        for k in 0..<6 {
            p.append(c(0.03 + Double(k) * 0.001, [.psh, .ack], seq: seq, ack: 8, len: 100))
            seq &+= 100
            p.append(s(0.0305 + Double(k) * 0.001, .ack, seq: 8, ack: seq))
        }
        let flow = try XCTUnwrap(onlyFlow(p))
        XCTAssertEqual(flow.retransmissions, 0, "\(flow.reasons)")
        XCTAssertEqual(flow.dupAcks, 0)
        XCTAssertEqual(flow.bytesToServer, 600)
        XCTAssertEqual(flow.health, .ok, "\(flow.reasons)")
        // A real retransmission across the wrap is still one.
        p.append(c(0.2, [.psh, .ack], seq: isn &+ 201, ack: 8, len: 100))
        XCTAssertEqual(try XCTUnwrap(onlyFlow(p)).retransmissions, 1)
    }

    func testSYNRetransmissionWithSameISNIsOneConversation() throws {
        var p = [c(0, .syn, seq: 1000, ack: 0), c(1, .syn, seq: 1000, ack: 0)]
        p += [s(1.02, [.syn, .ack], seq: 5000, ack: 1001), c(1.04, .ack, seq: 1001, ack: 5001)]
        let flow = try XCTUnwrap(onlyFlow(p))
        XCTAssertEqual(flow.synRetransmissions, 1)
        XCTAssertEqual(flow.handshakeRTT ?? 0, 0.02, accuracy: 0.001)
        XCTAssertEqual(flow.health, .warn)
        // A SYN retried with the same ISN after the server refused it (RST) stays one attempt too.
        let q = [c(0, .syn, seq: 1000, ack: 0), s(0.001, [.rst, .ack], seq: 0, ack: 1001),
                 c(1, .syn, seq: 1000, ack: 0), s(1.001, [.rst, .ack], seq: 0, ack: 1001)]
        XCTAssertEqual(TCPFlowAnalyzer.analyze(q).count, 1)
    }

    /// The same 4-tuple reused: after a close, or after a long silence with a fresh ISN.
    func testReusedFourTupleSplitsConversations() {
        func conversation(at t0: Double, isn: UInt32, close: Bool) -> [Packet] {
            var p = [c(t0, .syn, seq: isn, ack: 0),
                     s(t0 + 0.01, [.syn, .ack], seq: 9000, ack: isn &+ 1),
                     c(t0 + 0.02, .ack, seq: isn &+ 1, ack: 9001),
                     c(t0 + 0.03, [.psh, .ack], seq: isn &+ 1, ack: 9001, len: 50),
                     s(t0 + 0.04, [.psh, .ack], seq: 9001, ack: isn &+ 51, len: 70)]
            if close {
                p += [c(t0 + 0.05, [.fin, .ack], seq: isn &+ 51, ack: 9071),
                      s(t0 + 0.06, [.fin, .ack], seq: 9071, ack: isn &+ 52),
                      c(t0 + 0.07, .ack, seq: isn &+ 52, ack: 9072)]
            }
            return p
        }
        // Closed, then reopened 2 s later with a new ISN.
        let a = TCPFlowAnalyzer.analyze(conversation(at: 0, isn: 1000, close: true) + conversation(at: 2, isn: 777_000, close: true))
        XCTAssertEqual(a.count, 2)
        XCTAssertTrue(a.allSatisfy { $0.health == .ok && $0.retransmissions == 0 }, "\(a.map(\.reasons))")
        // The close was not captured: a fresh SYN with another ISN after 5 minutes of silence.
        let b = TCPFlowAnalyzer.analyze(conversation(at: 0, isn: 1000, close: false) + conversation(at: 300, isn: 777_000, close: true))
        XCTAssertEqual(b.count, 2, "\(b.map(\.reasons))")
        XCTAssertTrue(b.allSatisfy { $0.synRetransmissions == 0 && $0.retransmissions == 0 }, "\(b.map(\.reasons))")
    }

    func testFINWithDataAndKeepAlives() throws {
        var p = handshake()
        p.append(c(0.06, [.psh, .ack], seq: 1001, ack: 5001, len: 10))
        p.append(s(0.07, [.psh, .ack], seq: 5001, ack: 1011, len: 20))
        p.append(c(0.08, .ack, seq: 1011, ack: 5021))
        // Keep-alives 45 s apart: a 1-byte probe and a 0-byte probe, both at next − 1, each ACKed.
        p.append(c(45, .ack, seq: 1010, ack: 5021, len: 1))
        p.append(s(45.01, .ack, seq: 5021, ack: 1011))
        p.append(c(90, .ack, seq: 1010, ack: 5021))
        p.append(s(90.01, .ack, seq: 5021, ack: 1011))
        // The server's last segment carries data and FIN.
        p.append(s(90.5, [.fin, .psh, .ack], seq: 5021, ack: 1011, len: 30))
        p.append(c(90.51, [.fin, .ack], seq: 1011, ack: 5052))
        p.append(s(90.52, .ack, seq: 5052, ack: 1012))
        let flow = try XCTUnwrap(onlyFlow(p))
        XCTAssertEqual(flow.retransmissions, 0, "\(flow.reasons)")
        XCTAssertEqual(flow.dupAcks, 0, "\(flow.reasons)")
        XCTAssertEqual(flow.events.filter { $0.kind == .keepAlive }.count, 2)
        XCTAssertEqual(flow.bytesToClient, 50)
        XCTAssertEqual(flow.bytesToServer, 11, "the 1-byte keep-alive is the byte already sent, but it is on the wire")
        let kinds = flow.events.map(\.kind)
        XCTAssertTrue(kinds.contains(.data(count: 1, bytes: 30)), "\(kinds)")
        XCTAssertEqual(kinds.filter { $0 == .fin }.count, 2)
        XCTAssertEqual(flow.health, .ok, "\(flow.reasons)")
    }

    func testRSTAfterFINIsANormalClose() throws {
        var p = handshake()
        p.append(c(0.06, [.psh, .ack], seq: 1001, ack: 5001, len: 10, app: .httpRequest(method: "GET", path: "/", host: nil)))
        p.append(s(0.08, [.psh, .ack], seq: 5001, ack: 1011, len: 20, app: .httpResponse(status: 200, reason: "OK")))
        p.append(s(0.09, [.fin, .ack], seq: 5021, ack: 1011))
        p.append(c(0.10, [.fin, .ack], seq: 1011, ack: 5022))
        p.append(c(0.11, [.rst, .ack], seq: 1012, ack: 5022))
        let flow = try XCTUnwrap(onlyFlow(p))
        XCTAssertEqual(flow.health, .ok, "\(flow.reasons)")
        XCTAssertNil(flow.events.last?.problem)
    }

    func testDupAckNeedsSameWindowNoPayloadNoFIN() throws {
        var p = handshake()
        p.append(s(0.06, [.psh, .ack], seq: 5001, ack: 1001, len: 100))
        p.append(c(0.07, .ack, seq: 1001, ack: 5101, window: 1000))
        p.append(c(0.08, .ack, seq: 1001, ack: 5101, window: 2000))   // window update
        p.append(c(0.09, .ack, seq: 1001, ack: 5101, window: 3000))   // window update
        p.append(c(0.10, [.psh, .ack], seq: 1001, ack: 5101, len: 5, window: 3000))   // data, same ack
        p.append(c(0.11, [.fin, .ack], seq: 1006, ack: 5101, window: 3000))   // FIN, same ack
        let flow = try XCTUnwrap(onlyFlow(p))
        XCTAssertEqual(flow.dupAcks, 0, "\(flow.events.map(\.kind))")
    }

    /// Reordering on the path is not loss: a segment overtaken by the next one and arriving
    /// within an RTT is out of order (Wireshark's rule), not a retransmission. (A 100 MB download
    /// over Wi-Fi showed 84 of these counted as retransmissions before.)
    func testOutOfOrderIsNotRetransmission() throws {
        var p = handshake()        // RTT 28 ms
        p.append(c(0.057, [.psh, .ack], seq: 1001, ack: 5001, len: 100))
        p.append(s(0.090, .ack, seq: 5001, ack: 1101, len: 1460))
        p.append(s(0.0902, .ack, seq: 7921, ack: 1101, len: 1460))    // overtook 6461
        p.append(s(0.0904, .ack, seq: 6461, ack: 1101, len: 1460))    // 0.2 ms later
        p.append(c(0.0905, .ack, seq: 1101, ack: 9381))
        let flow = try XCTUnwrap(onlyFlow(p))
        XCTAssertEqual(flow.retransmissions, 0)
        XCTAssertEqual(flow.outOfOrder, 1)
        XCTAssertEqual(flow.health, .warn, "\(flow.reasons)")
        XCTAssertTrue(flow.events.contains { $0.kind == .outOfOrder(bytes: 1460) })
    }

    func testScaledWindowIsNotZeroWindow() throws {
        var p = handshake()
        p.append(s(0.06, [.psh, .ack], seq: 5001, ack: 1001, len: 100))
        p.append(c(0.07, .ack, seq: 1001, ack: 5101, window: 1))    // 1 << 7 = 128 bytes with WS=7
        let flow = try XCTUnwrap(onlyFlow(p))
        XCTAssertEqual(flow.zeroWindows, 0)
    }

    func testHTTPRequestSplitAcrossSegments() throws {
        var p = handshake()
        p.append(c(0.06, .ack, seq: 1001, ack: 5001, len: 1400, app: .httpRequest(method: "POST", path: "/upload", host: "h")))
        p.append(c(0.061, [.psh, .ack], seq: 2401, ack: 5001, len: 300))
        p.append(s(0.261, [.psh, .ack], seq: 5001, ack: 2701, len: 100, app: .httpResponse(status: 201, reason: "Created")))
        let flow = try XCTUnwrap(onlyFlow(p))
        XCTAssertEqual(flow.requests.count, 1)
        XCTAssertEqual(flow.requests[0].responseTime ?? 0, 0.201, accuracy: 0.0005)
        XCTAssertEqual(flow.requests[0].status, "201 Created")
        XCTAssertEqual(flow.longestResponseWait ?? 0, 0.2, accuracy: 0.0005, "measured from the request's last segment")
    }

    func testHTTPPipelining() throws {
        var p = handshake()
        p.append(c(0.06, [.psh, .ack], seq: 1001, ack: 5001, len: 50, app: .httpRequest(method: "GET", path: "/a", host: nil)))
        p.append(c(0.061, [.psh, .ack], seq: 1051, ack: 5001, len: 50, app: .httpRequest(method: "GET", path: "/b", host: nil)))
        p.append(s(0.100, [.psh, .ack], seq: 5001, ack: 1101, len: 300, app: .httpResponse(status: 200, reason: "OK")))
        p.append(s(0.101, .ack, seq: 5301, ack: 1101, len: 300))
        p.append(s(0.150, [.psh, .ack], seq: 5601, ack: 1101, len: 200, app: .httpResponse(status: 404, reason: "Not Found")))
        let flow = try XCTUnwrap(onlyFlow(p))
        XCTAssertEqual(flow.requests.map(\.request), ["GET /a", "GET /b"])
        XCTAssertEqual(flow.requests[0].status, "200 OK")
        XCTAssertEqual(flow.requests[0].responseTime ?? -1, 0.040, accuracy: 0.0005)
        XCTAssertEqual(flow.requests[1].status, "404 Not Found")
        XCTAssertEqual(flow.requests[1].responseTime ?? -1, 0.089, accuracy: 0.0005)
    }

    // MARK: Round 2: behaviour on real traffic (checked against Wireshark in TCPFlowGroundTruthTests)

    /// `nc -zv host 25` to a closed port: SYN → RST/ACK, and macOS tries once more with the
    /// same ISN. One flow, a warning ("refused"), never "SYN never answered" or "bad".
    func testRefusedPortScanIsAWarning() throws {
        let p = [c(0, .syn, seq: 1000, ack: 0), s(0.003, [.rst, .ack], seq: 0, ack: 1001),
                 c(1.0, .syn, seq: 1000, ack: 0), s(1.003, [.rst, .ack], seq: 0, ack: 1001)]
        let flow = try XCTUnwrap(onlyFlow(p))
        XCTAssertTrue(flow.refused)
        XCTAssertEqual(flow.health, .warn)
        XCTAssertEqual(flow.reasons, ["refused (RST to the SYN), 2 attempts"])
        XCTAssertEqual(flow.events.first { $0.kind == .rst }?.problem?.hasPrefix("Refused"), true)
        XCTAssertEqual(flow.events[2].problem, "SYN tried again after the RST (1.00 s after the previous one)")
        // A single refused SYN.
        let one = try XCTUnwrap(onlyFlow([c(0, .syn, seq: 1000, ack: 0), s(0.003, [.rst, .ack], seq: 0, ack: 1001)]))
        XCTAssertEqual(one.health, .warn)
        XCTAssertEqual(one.reasons, ["refused (RST to the SYN)"])
        // A reset after the handshake is still the server breaking the connection.
        var q = handshake()
        q.append(s(0.06, [.rst, .ack], seq: 5001, ack: 1001))
        XCTAssertEqual(try XCTUnwrap(onlyFlow(q)).health, .bad)
    }

    /// A capture started mid-conversation with nothing but ACKs: no SYN, so no "SYN never
    /// answered", no dup ACKs from ACKs that simply repeat, healthy.
    func testMidStreamACKsOnly() throws {
        var p: [Packet] = []
        for k in 0..<6 {
            p.append(c(Double(k) * 0.2, .ack, seq: 7000, ack: 9000 + UInt32(k) * 100))
        }
        let flow = try XCTUnwrap(onlyFlow(p))
        XCTAssertEqual(flow.health, .ok, "\(flow.reasons)")
        XCTAssertFalse(flow.reasons.contains { $0.contains("SYN") })
        XCTAssertEqual(flow.dupAcks, 0)
    }

    /// An idle session kept open by keep-alives for 10 minutes, captured from the middle: the
    /// first 1-byte probe looks like a request until its twin arrives; after that nothing is
    /// a problem (no "waiting for a response", no dup ACKs, not "bad").
    func testKeepAliveOnlyLongFlowIsHealthy() throws {
        for oneByte in [true, false] {
            nextID = 1
            var p: [Packet] = []
            for k in 0..<14 {
                let t = Double(k) * 45
                p.append(c(t, .ack, seq: 4999, ack: 8000, len: oneByte ? 1 : 0))
                p.append(s(t + 0.02, .ack, seq: 8000, ack: 5000))
            }
            let flow = try XCTUnwrap(onlyFlow(p))
            XCTAssertEqual(flow.health, .ok, "\(oneByte ? "1-byte" : "0-byte") probes: \(flow.reasons)")
            XCTAssertEqual(flow.dupAcks, 0)
            XCTAssertNil(flow.longestResponseWait.flatMap { $0 > 3 ? $0 : nil })
            XCTAssertGreaterThanOrEqual(flow.events.filter { $0.kind == .keepAlive }.count, 13)
            XCTAssertTrue(flow.events.allSatisfy { $0.problem == nil }, "\(flow.events.compactMap(\.problem))")
        }
    }

    /// Data the receiver had already acknowledged, sent again 1 ms after newer data: Wireshark's
    /// "spurious retransmission" — not out-of-order (it was acked), not a loss.
    func testSpuriousRetransmission() throws {
        var p = handshake()
        p.append(c(0.057, [.psh, .ack], seq: 1001, ack: 5001, len: 100))
        p.append(s(0.090, .ack, seq: 5001, ack: 1101, len: 1460))
        p.append(s(0.091, .ack, seq: 6461, ack: 1101, len: 1460))
        p.append(c(0.0912, .ack, seq: 1101, ack: 7921))
        p.append(s(0.092, .ack, seq: 5001, ack: 1101, len: 1460))     // already acked
        let flow = try XCTUnwrap(onlyFlow(p))
        XCTAssertEqual(flow.retransmissions, 1, "Wireshark counts it as a retransmission")
        XCTAssertEqual(flow.spuriousRetransmissions, 1)
        XCTAssertEqual(flow.outOfOrder, 0)
        XCTAssertEqual(flow.health, .warn)
        XCTAssertEqual(flow.reasons, ["1 spurious retransmission"])
        let e = try XCTUnwrap(flow.events.first { if case .retransmission = $0.kind { true } else { false } })
        XCTAssertEqual(e.problem, "Spurious retransmission of seq 1, 1,460 bytes, 2.0 ms after the original (already acknowledged)")
    }

    /// With SACK the same ACK is a duplicate even when the window moved (RFC 6675, Wireshark):
    /// macOS grows its window while SACKing the segments after a hole.
    func testDupAckWithSACKAndMovingWindow() throws {
        var p = handshake()
        p.append(s(0.06, .ack, seq: 5001, ack: 1001, len: 1460))
        p.append(c(0.061, .ack, seq: 1001, ack: 6461, window: 2000))
        for (k, w) in [2100, 2200, 2300].enumerated() {
            let sackAck = pkt(t: 0.062 + Double(k) * 0.001, src: client, sport: 51234, dst: server, dport: 80,
                              flags: .ack, seq: 1001, ack: 6461, len: 0, window: UInt16(w))
            p.append(withSACK(sackAck))
        }
        // Without SACK a changed window is a window update, not a duplicate.
        p.append(c(0.07, .ack, seq: 1001, ack: 6461, window: 2400))
        let flow = try XCTUnwrap(onlyFlow(p))
        XCTAssertEqual(flow.dupAcks, 3)
    }

    /// A SPAN of both VLANs of a router sees every packet twice (VLAN 10 in, VLAN 20 out, TTL
    /// one lower): the copies are counted once, not as 100 % retransmissions and dup ACKs.
    func testPacketsCapturedTwiceAcrossVLANs() throws {
        var p = handshake()
        p.append(c(0.057, [.psh, .ack], seq: 1001, ack: 5001, len: 100))
        p.append(s(0.090, [.psh, .ack], seq: 5001, ack: 1101, len: 1460))
        p.append(c(0.091, .ack, seq: 1101, ack: 6461))
        var both: [Packet] = []
        for pk in p {
            both.append(copy(pk, id: both.count + 1, vlan: 10, ttlDrop: 0, dt: 0))
            both.append(copy(pk, id: both.count + 1, vlan: 20, ttlDrop: 1, dt: 0.00005))
        }
        let flow = try XCTUnwrap(onlyFlow(both))
        XCTAssertEqual(flow.packetCount, 12)
        XCTAssertEqual(flow.capturedTwice, 6)
        XCTAssertEqual(flow.retransmissions, 0)
        XCTAssertEqual(flow.dupAcks, 0)
        XCTAssertEqual(flow.bytesToClient, 1460)
        XCTAssertEqual(flow.health, .ok, "\(flow.reasons)")
        XCTAssertEqual(flow.notes, ["6 packets captured twice (VLAN 10 and 20), counted once"])
        // The same capture on one VLAN (a real retransmission 50 µs later keeps MAC and TTL).
        var one: [Packet] = []
        for pk in p {
            one.append(copy(pk, id: one.count + 1, vlan: 10, ttlDrop: 0, dt: 0))
        }
        one.append(copy(p[4], id: one.count + 1, vlan: 10, ttlDrop: 0, dt: 0.00005))
        let f1 = try XCTUnwrap(onlyFlow(one))
        XCTAssertEqual(f1.capturedTwice, 0)
        XCTAssertEqual(f1.retransmissions, 1)
    }

    /// IPv6 conversations are flows like any other (endpoint in brackets).
    func testIPv6Flow() throws {
        var sc = TCPFlowDemo.Script(client: "2001:db8::10", clientPort: 50000, server: "2001:db8::1", serverPort: 443)
        sc.handshake(rtt: 0.012)
        sc.c(0.0121, [.psh, .ack], len: 300, app: .tlsClientHello(sni: "v6.example", version: "TLS 1.3"))
        sc.s(0.03, [.psh, .ack], len: 1200, app: .tlsServerHello(version: "TLS 1.3"))
        let flow = try XCTUnwrap(onlyFlow(sc.packets))
        XCTAssertEqual(flow.clientEndpoint, "[2001:db8::10]:50000")
        XCTAssertEqual(flow.application, "TLS v6.example")
        XCTAssertEqual(flow.handshakeRTT ?? 0, 0.012, accuracy: 1e-6)
        XCTAssertEqual(flow.firstPacketID, 1)
        XCTAssertEqual(flow.lastPacketID, 5)
    }

    private func withSACK(_ p: Packet) -> Packet {
        var d = p.decoded
        let t = d.tcp!
        d.tcp = TCPHeader(sourcePort: t.sourcePort, destinationPort: t.destinationPort, sequence: t.sequence,
                          acknowledgment: t.acknowledgment, flags: t.flags, window: t.window, headerLength: 32,
                          payloadLength: t.payloadLength, mss: nil, windowScale: nil, sackPermitted: false,
                          sackBlocks: 1, timestampValue: nil, timestampEcho: nil)
        return Packet(id: p.id, timestamp: p.timestamp, relative: p.relative, length: p.length, captured: p.captured,
                      data: p.data, decoded: d)
    }

    private func copy(_ p: Packet, id: Int, vlan: UInt16, ttlDrop: UInt8, dt: Double) -> Packet {
        var d = p.decoded
        let ip = d.ip!
        d.vlan = vlan
        d.ip = IPHeader(version: ip.version, source: ip.source, destination: ip.destination, proto: ip.proto,
                        ttl: ip.ttl - ttlDrop, identification: ip.identification, dontFragment: ip.dontFragment,
                        moreFragments: ip.moreFragments, fragmentOffset: ip.fragmentOffset, headerLength: ip.headerLength,
                        totalLength: ip.totalLength, dscp: ip.dscp)
        return Packet(id: id, timestamp: p.timestamp.addingTimeInterval(dt), relative: p.relative + dt, length: p.length,
                      captured: p.captured, data: p.data, decoded: d)
    }

    // MARK: Review: ladder cap, export size, cancellation, 200k

    @MainActor
    func testLadderCapCountsEventsNotGaps() throws {
        // 300 request/answer pairs, each after 1.5 s of silence: 600 data events + 599 gaps.
        var p = handshake()
        var cs: UInt32 = 1001, ss: UInt32 = 5001
        for k in 0..<300 {
            let t = 1 + Double(k) * 1.5
            p.append(c(t, [.psh, .ack], seq: cs, ack: ss, len: 10)); cs += 10
            p.append(s(t + 0.01, [.psh, .ack], seq: ss, ack: cs, len: 10)); ss += 10
        }
        let flow = try XCTUnwrap(onlyFlow(p))
        let gaps = flow.events.filter { if case .gap = $0.kind { return true } else { return false } }.count
        XCTAssertGreaterThan(gaps, 250)
        let layout = LadderLayout.make(flow: flow, collapseAcks: true, width: 700)
        let shownEvents = layout.items.filter { if case .gap = $0.event.kind { return false } else { return true } }.count
        XCTAssertEqual(shownEvents, LadderLayout.cap, "the cap counts arrows, not idle gaps")
        XCTAssertEqual(layout.hidden, flow.events.count - gaps - LadderLayout.cap)
        // The PNG of a full 400-arrow ladder stays under the bitmap limits.
        let scale = LadderLayout.exportScale(width: layout.width, height: layout.height)
        XCTAssertLessThanOrEqual(layout.height * scale, 16_384)
        XCTAssertGreaterThan(scale, 0.4)
    }

    func testAnalysisCanBeCancelled() {
        let packets = TCPFlowDemo.packets()
        var calls = 0
        let flows = TCPFlowAnalyzer.analyze(packets) { calls += 1; return true }
        XCTAssertTrue(flows.isEmpty)
        XCTAssertGreaterThan(calls, 0)
        XCTAssertEqual(TCPFlowAnalyzer.analyze(packets) { false }.count, 6)
    }

    func testPerformance200kPacketsIPv6() {
        var packets: [Packet] = []
        packets.reserveCapacity(200_000)
        var id = 1
        for f in 0..<2_000 {
            var sc = TCPFlowDemo.Script(firstID: id, offset: Double(f) * 0.005, client: "2001:db8:1::\(String(f, radix: 16))",
                                        clientPort: UInt16(20_000 + f), server: "2001:db8:ffff::\(f % 13 + 1)", serverPort: 443)
            sc.handshake(rtt: 0.010)
            sc.c(0.0101, [.psh, .ack], len: 300, app: .tlsClientHello(sni: "host\(f).example", version: "TLS 1.3"))
            for k in 0..<46 {
                sc.s(0.03 + Double(k) * 0.0005, .ack, len: 1460)
                sc.c(0.0302 + Double(k) * 0.0005, .ack)
            }
            sc.s(0.06, [.fin, .ack]); sc.c(0.061, .ack); sc.c(0.062, [.fin, .ack]); sc.s(0.07, .ack)
            packets += sc.packets
            id = sc.nextID
        }
        packets.sort { $0.timestamp < $1.timestamp }
        XCTAssertEqual(packets.count, 200_000)
        let start = Date()
        let flows = TCPFlowAnalyzer.analyze(packets)
        let elapsed = Date().timeIntervalSince(start)
        XCTAssertEqual(flows.count, 2_000)
        XCTAssertTrue(flows.allSatisfy { $0.health == .ok })
        print("[perf] TCPFlowAnalyzer 200,000 IPv6 packets / 2,000 flows: \(String(format: "%.3f", elapsed)) s")
        XCTAssertWithinBudget(elapsed, 1.0)
    }

    // (h)
    func testPerformance50kPackets() {
        var packets: [Packet] = []
        packets.reserveCapacity(50_000)
        var id = 1
        for f in 0..<500 {
            var sc = TCPFlowDemo.Script(firstID: id, offset: Double(f) * 0.01, client: "10.1.\(f / 250).\(f % 250 + 1)",
                                        clientPort: UInt16(40_000 + f), server: "10.9.0.\(f % 7 + 1)", serverPort: 443)
            sc.handshake(rtt: 0.010)
            sc.c(0.0101, [.psh, .ack], len: 300, app: .tlsClientHello(sni: "host\(f).example", version: "TLS 1.3"))
            for k in 0..<46 {
                sc.s(0.03 + Double(k) * 0.0005, .ack, len: 1460)
                sc.c(0.0302 + Double(k) * 0.0005, .ack)
            }
            sc.s(0.06, [.fin, .ack]); sc.c(0.061, .ack); sc.c(0.062, [.fin, .ack]); sc.s(0.07, .ack)
            precondition(sc.packets.count == 100)
            packets += sc.packets
            id = sc.nextID
        }
        packets.sort { $0.timestamp < $1.timestamp }
        XCTAssertEqual(packets.count, 50_000)
        let start = Date()
        let flows = TCPFlowAnalyzer.analyze(packets)
        let elapsed = Date().timeIntervalSince(start)
        XCTAssertEqual(flows.count, 500)
        XCTAssertTrue(flows.allSatisfy { $0.health == .ok }, "\(flows.first { $0.health != .ok }?.reasons ?? [])")
        XCTAssertWithinBudget(elapsed, 1.0, "analysed 50,000 packets in \(elapsed) s")
        print("[perf] TCPFlowAnalyzer 50,000 packets / 500 flows: \(String(format: "%.3f", elapsed)) s")
    }
}
