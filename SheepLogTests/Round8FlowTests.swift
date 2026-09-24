import XCTest
@testable import SheepLog

/// Round 8: the flow analyser's retransmission / fast / spurious / out-of-order verdicts frame
/// by frame against tshark (Wireshark's `tcp_analyze_sequence_number`, modelled in
/// `TCPSequenceAnalysis`), on the committed captures, the local recordings and synthetic
/// conversations built for the cases where the rules differ.
final class Round8FlowTests: XCTestCase {
    typealias W = WireConversation
    typealias V = TCPFlow.SegmentVerdict

    struct FrameReport {
        var ours: [Int: V] = [:]
        var wireshark: [Int: V] = [:]
        var differences: [String] = []
        var summary: String {
            func count(_ m: [Int: V], _ v: V) -> Int { m.values.filter { $0 == v }.count }
            let kinds: [(String, V)] = [("retrans", .retransmission), ("fast", .fastRetransmission),
                                        ("spurious", .spuriousRetransmission), ("ooo", .outOfOrder)]
            return kinds.map { "\($0.0) \(count(ours, $0.1))/\(count(wireshark, $0.1))" }.joined(separator: ", ")
                + " — \(differences.count) frame(s) differ"
        }
    }

    /// Wireshark's verdict for every flagged frame of `url`.
    static func wiresharkVerdicts(_ tshark: String, _ url: URL) -> [Int: V] {
        let out = CaptureGroundTruthTests.run(tshark, [
            "-r", url.path, "-o", "tcp.desegment_tcp_streams:FALSE", "-Y",
            "tcp.analysis.retransmission or tcp.analysis.fast_retransmission or tcp.analysis.spurious_retransmission or tcp.analysis.out_of_order",
            "-T", "fields", "-E", "separator=/t", "-e", "frame.number", "-e", "tcp.analysis.fast_retransmission",
            "-e", "tcp.analysis.spurious_retransmission", "-e", "tcp.analysis.out_of_order", "-e", "tcp.analysis.retransmission"])
        var result: [Int: V] = [:]
        for line in out.split(separator: "\n") {
            let c = line.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
            guard c.count >= 5, let frame = Int(c[0]) else { continue }
            if !c[1].isEmpty { result[frame] = .fastRetransmission }
            else if !c[2].isEmpty { result[frame] = .spuriousRetransmission }
            else if !c[3].isEmpty { result[frame] = .outOfOrder }
            else if !c[4].isEmpty { result[frame] = .retransmission }
        }
        return result
    }

    static func compareFrames(_ url: URL, tshark: String) throws -> FrameReport {
        var packets: [Packet] = []
        _ = try PcapFile.read(url) { packets += $0 }
        var r = FrameReport()
        for f in TCPFlowAnalyzer.analyze(packets) { r.ours.merge(f.verdicts) { a, _ in a } }
        r.wireshark = wiresharkVerdicts(tshark, url)
        // A client retrying a refused port with the same ISN: Wireshark starts a new stream
        // ("TCP Port numbers reused"), SheepLog keeps one attempt and calls the SYN a
        // retransmission (see TCPFlowGroundTruthTests' fold).
        let reused = CaptureGroundTruthTests.run(tshark, ["-r", url.path, "-Y", "tcp.analysis.reused_ports and tcp.flags.syn == 1 and tcp.flags.ack == 0",
                                                          "-T", "fields", "-e", "frame.number"])
        for frame in reused.split(separator: "\n").compactMap({ Int($0) }) where r.ours[frame] == .retransmission && r.wireshark[frame] == nil {
            r.wireshark[frame] = .retransmission
        }
        for frame in Set(r.ours.keys).union(r.wireshark.keys).sorted() where r.ours[frame] != r.wireshark[frame] {
            r.differences.append("frame \(frame): ours \(r.ours[frame].map { "\($0)" } ?? "—"), "
                                 + "Wireshark \(r.wireshark[frame].map { "\($0)" } ?? "—")")
        }
        print("FRAMETRUTH \(url.lastPathComponent): \(r.summary)"
              + (r.differences.isEmpty ? "" : "\n  " + r.differences.prefix(20).joined(separator: "\n  ")))
        return r
    }

    private var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appending(path: "SheepLogRound8Flows", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    // MARK: Real captures

    func testCommittedCapturesFrameByFrame() throws {
        guard let tshark = CaptureGroundTruthTests.tshark else { throw XCTSkip("tshark not installed") }
        let files = try FileManager.default.contentsOfDirectory(at: CaptureGroundTruthTests.pcapDir, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "pcap" }.sorted { $0.lastPathComponent < $1.lastPathComponent }
        for url in files {
            let r = try Self.compareFrames(url, tshark: tshark)
            XCTAssertEqual(r.differences, [], url.lastPathComponent)
        }
    }

    func testLocalRecordingsFrameByFrame() throws {
        guard let tshark = CaptureGroundTruthTests.tshark else { throw XCTSkip("tshark not installed") }
        var paths = (1...9).map { "/tmp/c\($0).pcap" }
        if let extra = ProcessInfo.processInfo.environment["SHEEPLOG_PCAPS"] { paths += extra.split(separator: ":").map(String.init) }
        let present = paths.filter { FileManager.default.fileExists(atPath: $0) }
        try XCTSkipIf(present.isEmpty, "no local recordings")
        for path in present {
            let r = try Self.compareFrames(URL(fileURLWithPath: path), tshark: tshark)
            XCTAssertEqual(r.differences, [], path)
        }
    }

    // MARK: Synthetic conversations

    /// Writes `w`'s frames, analyses them as the app does, compares frame by frame with tshark
    /// when it is installed, and returns our verdicts.
    @discardableResult
    private func verdicts(_ name: String, _ w: W, file: StaticString = #filePath, line: UInt = #line) throws -> [Int: V] {
        let url = dir.appending(path: "\(name).pcap")
        try PcapFile.write(w.packets, linkType: 1, to: url)
        var read: [Packet] = []
        _ = try PcapFile.read(url) { read += $0 }
        var ours: [Int: V] = [:]
        for f in TCPFlowAnalyzer.analyze(read) { ours.merge(f.verdicts) { a, _ in a } }
        if let tshark = CaptureGroundTruthTests.tshark {
            let r = try Self.compareFrames(url, tshark: tshark)
            XCTAssertEqual(r.differences, [], "\(name) against Wireshark", file: file, line: line)
        }
        return ours
    }

    /// Loss before any duplicate ACK: the server sends A and B, the client acknowledges up to A
    /// once (not yet a duplicate), and the server resends A 1 ms later. A was captured and is
    /// still unacknowledged, so Wireshark calls it a retransmission however soon it comes —
    /// not "out of order" (round 7 did: within one RTT of B, not ending at B's end).
    func testLossBeforeAnyDuplicateACK() throws {
        var w = W()
        w.handshake(rtt: 0.020)
        w.c(0.021, W.PSH | W.ACK, payload: W.http("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
        let a = w.sseq
        w.s(0.045, W.ACK, len: 1000)                                  // frame 5: A (lost after the tap)
        w.s(0.0452, W.ACK, len: 1000)                                 // frame 6: B
        w.c(0.0460, W.ACK, ack: a)                                    // frame 7: "I have up to A"
        w.s(0.0470, W.ACK, len: 1000, seq: a)                         // frame 8: A again
        w.c(0.0680, W.ACK)
        let v = try verdicts("r8-loss-before-dupacks", w)
        XCTAssertEqual(v, [8: .retransmission])
    }

    /// Loss after duplicate ACKs. The client's three dup ACKs are followed 30 ms later by a
    /// request of its own (same ACK), and the server resends the hole 1 ms after that: fast —
    /// Wireshark's 20 ms run from the peer's last segment of any kind, and the dup-ACK count
    /// only resets when the ACK moves (round 7 timed it from the last dup ACK: a
    /// retransmission). A resend above the ACK without SACK blocks is not fast.
    func testLossAfterDuplicateACKs() throws {
        var w = W(sport: 8080)
        w.handshake(rtt: 0.020)
        w.c(0.021, W.PSH | W.ACK, payload: W.http("GET /a HTTP/1.1\r\nHost: x\r\n\r\n"))
        w.s(0.045, W.ACK, len: 1000)
        let lost = w.sseq
        w.sseq &+= 1000
        w.c(0.0455, W.ACK, ack: lost)                                 // frame 6
        for k in 0..<3 {
            w.s(0.046 + Double(k) * 0.0005, W.ACK, len: 1000)         // frames 7, 9, 11
            w.c(0.0462 + Double(k) * 0.0005, W.ACK, ack: lost)        // frames 8, 10, 12: dup ACKs
        }
        let above = lost &+ 2000
        w.c(0.078, W.PSH | W.ACK, ack: lost, payload: W.http("GET /b HTTP/1.1\r\nHost: x\r\n\r\n"))   // frame 13
        w.s(0.079, W.ACK, len: 1000, seq: lost)                       // frame 14: fast
        w.s(0.0792, W.ACK, len: 1000, seq: above)                     // frame 15: above the ACK, no SACK
        w.c(0.100, W.ACK)
        let v = try verdicts("r8-loss-after-dupacks", w)
        XCTAssertEqual(v[14], .fastRetransmission)
        XCTAssertNotEqual(v[15], .fastRetransmission)
        XCTAssertEqual(v.count, 2, "\(v)")
    }

    /// Capture begins mid-connection (no SYN: the out-of-order threshold is 3 ms). The server
    /// sends past a hole and fills it 1 ms later, but the client's last segment was 20 ms
    /// before: a retransmission (Wireshark times from the peer). Then the client ACKs and the
    /// next hole is filled 1 ms after that ACK: out of order.
    func testReorderingWithoutAnRTTSample() throws {
        var w = W()
        w.s(0.000, W.PSH | W.ACK, len: 100)                           // frame 1
        w.c(0.001, W.ACK)                                             // frame 2
        let hole = w.sseq
        w.sseq &+= 1000
        w.s(0.020, W.ACK, len: 1000)                                  // frame 3
        w.s(0.021, W.ACK, len: 1000, seq: hole)                       // frame 4: 20 ms after the client → retransmission
        w.c(0.0212, W.ACK)                                            // frame 5
        let hole2 = w.sseq
        w.sseq &+= 1000
        w.s(0.040, W.ACK, len: 1000)                                  // frame 6
        w.c(0.0402, W.ACK, ack: hole2)                                // frame 7
        w.s(0.0412, W.ACK, len: 1000, seq: hole2)                     // frame 8: 1 ms after the client → out of order
        w.c(0.0414, W.ACK)
        let v = try verdicts("r8-reorder-no-rtt", w)
        XCTAssertEqual(v, [4: .retransmission, 8: .outOfOrder])
    }

    /// Captured at the server: SYN → SYN/ACK 0.1 ms, SYN/ACK → ACK 30 ms. Wireshark's
    /// threshold is SYN → ACK (30.1 ms), so a hole filled 5 ms after the client's last segment
    /// is out of order (round 7 used SYN → SYN/ACK, 0.1 ms, and said retransmission).
    func testReorderingWithAnRTTSample() throws {
        var w = W()
        w.c(0.000, W.SYN, options: W.synOptions)
        w.s(0.0001, W.SYN | W.ACK, options: W.synOptions)
        w.c(0.0301, W.ACK)
        w.c(0.0302, W.PSH | W.ACK, payload: W.http("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))   // frame 4
        w.s(0.031, W.ACK)                                             // frame 5
        let hole = w.sseq
        w.sseq &+= 1000
        w.s(0.032, W.ACK, len: 1000)                                  // frame 6
        w.s(0.036, W.ACK, len: 1000, seq: hole)                       // frame 7: 5.8 ms after the client → out of order
        w.c(0.070, W.ACK)
        let v = try verdicts("r8-reorder-rtt", w)
        XCTAssertEqual(v, [7: .outOfOrder])
    }

    /// Capture begins mid-connection with the client's ACK; the server then sends a segment the
    /// client had already acknowledged (its original was before the capture): spurious.
    func testSpuriousRetransmission() throws {
        var w = W()
        w.c(0.000, W.ACK, ack: w.sseq &+ 2000)                        // frame 1: acknowledges 2000 bytes
        w.s(0.200, W.ACK, len: 1000)                                  // frame 2: the first 1000 again
        w.c(0.201, W.ACK, ack: w.sseq &+ 1000)
        let v = try verdicts("r8-spurious", w)
        XCTAssertEqual(v, [2: .spuriousRetransmission])
    }

    /// SACK recovery: three dup ACKs carrying SACK blocks, then the client's own data 25 ms
    /// later (same ACK, SACK blocks); the server resends both holes 1 ms after it — fast (the
    /// 20 ms run from the peer's last segment; round 7 timed them from the last dup ACK).
    func testSACKRecoveryResendsAreFast() throws {
        var w = W(sport: 8080)
        w.handshake(rtt: 0.020)
        w.c(0.021, W.PSH | W.ACK, payload: W.http("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
        let hole1 = w.sseq
        w.sseq &+= 1000
        w.s(0.045, W.ACK, len: 1000)                                  // frame 5 (hole1 lost)
        let hole2 = w.sseq
        w.sseq &+= 1000
        w.s(0.0452, W.ACK, len: 1000)                                 // frame 6 (hole2 lost)
        func sack(_ l: UInt32, _ r: UInt32) -> [UInt8] {
            [1, 1, 5, 10] + PacketFixture.be32(l) + PacketFixture.be32(r)
        }
        w.c(0.0460, W.ACK, ack: hole1, options: sack(hole1 &+ 1000, hole1 &+ 2000))   // frame 7
        w.s(0.0462, W.ACK, len: 1000)                                 // frame 8
        w.c(0.0465, W.ACK, ack: hole1, options: sack(hole1 &+ 1000, hole1 &+ 2000))   // frame 9: dup
        w.s(0.0467, W.ACK, len: 1000)                                 // frame 10
        w.c(0.0470, W.ACK, ack: hole1, options: sack(hole1 &+ 1000, hole1 &+ 2000))   // frame 11: dup
        w.c(0.0475, W.ACK, ack: hole1, options: sack(hole1 &+ 1000, hole1 &+ 2000))   // frame 12: dup
        w.c(0.0720, W.PSH | W.ACK, ack: hole1, options: sack(hole1 &+ 1000, hole1 &+ 2000),
            payload: W.http("GET /2 HTTP/1.1\r\nHost: x\r\n\r\n"))                  // frame 13
        w.s(0.0730, W.ACK, len: 1000, seq: hole1)                     // frame 14: fast (at the ACK)
        w.s(0.0732, W.ACK, len: 1000, seq: hole2)                     // frame 15: fast (SACK)
        w.c(0.0950, W.ACK)
        let v = try verdicts("r8-sack-recovery", w)
        XCTAssertEqual(v, [14: .fastRetransmission, 15: .fastRetransmission])
    }

    /// A datagram delivered twice (same IPv4 ID and TSval, 1 ms apart — a Wi-Fi duplicate seen
    /// in a real recording) that the receiver reports with a D-SACK: it reached the host, so it
    /// is analysed (Wireshark: spurious retransmission), not dropped as "captured twice". Without
    /// the D-SACK it stays a capture copy (Round5FlowTests).
    func testDuplicateReportedByDSACKIsNotACaptureCopy() throws {
        var w = W()
        w.handshake(rtt: 0.020)
        w.c(0.021, W.PSH | W.ACK, payload: W.http("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
        let seg = w.sseq
        w.frame(fromClient: false, 0.045, W.PSH | W.ACK, len: 140, seq: seg, ack: w.cseq, win: 65535, ipID: 0xB244)
        w.sseq &+= 140
        w.c(0.0452, W.ACK)
        w.frame(fromClient: false, 0.0463, W.PSH | W.ACK, len: 140, seq: seg, ack: w.cseq, win: 65535, ipID: 0xB244)
        w.c(0.0464, W.ACK, options: [1, 1, 5, 10] + PacketFixture.be32(seg) + PacketFixture.be32(seg &+ 140))
        let v = try verdicts("r8-dsack-duplicate", w)
        XCTAssertEqual(v, [7: .spuriousRetransmission])
        var read: [Packet] = []
        let url = dir.appending(path: "r8-dsack-duplicate.pcap")
        _ = try PcapFile.read(url) { read += $0 }
        let flow = try XCTUnwrap(TCPFlowAnalyzer.analyze(read).first)
        XCTAssertEqual(flow.capturedTwice, 0)
        XCTAssertEqual(flow.bytesToClient, 280)
    }

    // MARK: Random conversations

    /// Seeded random conversations (new data, holes before the tap, resends of any earlier
    /// segment, cumulative / duplicate / SACK ACKs, client data, window changes and zero windows,
    /// gaps from 0.1 ms to 60 ms, with and without a handshake): every retransmission-family
    /// verdict and the duplicate-ACK count must be tshark's.
    func testRandomConversationsFrameByFrame() throws {
        guard let tshark = CaptureGroundTruthTests.tshark else { throw XCTSkip("tshark not installed") }
        var failures: [String] = []
        for seed in 1...Self.fuzzSeeds {
            var rng = SplitMix(seed: UInt64(seed) &* 0x9E37)
            let w = Self.randomConversation(&rng, lagging: seed % 2 == 0)
            let url = dir.appending(path: "r8-fuzz-\(seed).pcap")
            try PcapFile.write(w.packets, linkType: 1, to: url)
            let r = try Self.compareFrames(url, tshark: tshark)
            var packets: [Packet] = []
            _ = try PcapFile.read(url) { packets += $0 }
            let ours = TCPFlowAnalyzer.analyze(packets).reduce(0) { $0 + $1.dupAcks }
            let theirs = CaptureGroundTruthTests.run(tshark, ["-r", url.path, "-Y", "tcp.analysis.duplicate_ack", "-T", "fields", "-e", "frame.number"])
                .split(separator: "\n").count
            if !r.differences.isEmpty || ours != theirs {
                failures.append("seed \(seed): \(r.differences.prefix(5)) dup ACKs ours \(ours) Wireshark \(theirs)")
            }
        }
        XCTAssertEqual(failures, [], failures.joined(separator: "\n"))
    }

    /// 60 by default (~12 s); `SHEEPLOG_FUZZ_SEEDS=300` for a longer run.
    static let fuzzSeeds = Int(ProcessInfo.processInfo.environment["SHEEPLOG_FUZZ_SEEDS"] ?? "") ?? 60

    /// `lagging`: the client's ACK moves one segment at a time and resends pick unacknowledged
    /// segments (holes, dup ACKs, fast retransmissions, reordering); otherwise ACKs jump ahead
    /// and most resends are spurious.
    static func randomConversation(_ rng: inout SplitMix, lagging: Bool) -> W {
        var w = W(sport: 8080)
        var t = 0.0
        if Bool.random(using: &rng) || Bool.random(using: &rng) {
            let rtt = [0.0001, 0.002, 0.015, 0.040].randomElement(using: &rng)!
            w.c(0, W.SYN, options: W.synOptions)
            w.s(rtt, W.SYN | W.ACK, options: W.synOptions)
            let back = [0.0002, 0.030].randomElement(using: &rng)!
            w.c(rtt + back, W.ACK)
            t = rtt + back
        }
        var sent: [(seq: UInt32, len: Int)] = []
        var clientAck = w.sseq
        var clientWin: UInt16 = 65535
        var sackBlock: (UInt32, UInt32)?
        func sackOption(_ b: (UInt32, UInt32)) -> [UInt8] { [1, 1, 5, 10] + PacketFixture.be32(b.0) + PacketFixture.be32(b.1) }
        for _ in 0..<160 {
            t += [0.0001, 0.0005, 0.002, 0.004, 0.010, 0.025, 0.060].randomElement(using: &rng)!
            let roll = Int.random(in: 0..<100, using: &rng)
            switch roll {
            case 0..<34:
                let len = [100, 500, 1000, 1448].randomElement(using: &rng)!
                sent.append((w.sseq, len))
                if Int.random(in: 0..<100, using: &rng) < 15 {
                    w.sseq &+= UInt32(len)                            // lost before the tap
                } else {
                    w.s(t, W.ACK, len: len)
                }
            case 34..<48:
                let pool = lagging ? sent.filter { Int32(bitPattern: $0.seq &- clientAck) >= 0 } : sent
                guard let old = pool.randomElement(using: &rng) else { continue }
                w.s(t, W.ACK, len: old.len, seq: old.seq)
            case 48..<66:
                let ends = sent.map { $0.seq &+ UInt32($0.len) }.filter { Int32(bitPattern: $0 &- clientAck) >= 0 }
                if lagging {
                    clientAck = ends.filter { $0 != clientAck }.min { Int32(bitPattern: $0 &- $1) < 0 } ?? clientAck
                } else {
                    clientAck = (ends + [w.sseq]).randomElement(using: &rng)!
                }
                sackBlock = nil
                w.c(t, W.ACK, ack: clientAck, win: clientWin)
            case 66..<80:
                if Int.random(in: 0..<100, using: &rng) < 45, let b = sent.randomElement(using: &rng) {
                    sackBlock = (b.seq, b.seq &+ UInt32(b.len))
                }
                w.c(t, W.ACK, ack: clientAck, win: clientWin, options: sackBlock.map(sackOption) ?? [])
            case 80..<86:
                w.c(t, W.PSH | W.ACK, ack: clientAck, win: clientWin,
                    payload: [UInt8](repeating: 0x42, count: Int.random(in: 100...400, using: &rng)))
            case 86..<91:
                clientWin = [0, 512, 8192, 65535].randomElement(using: &rng)!
                w.c(t, W.ACK, ack: clientAck, win: clientWin)
            case 91..<96:
                w.s(t, W.ACK)
            default:
                // A resend starting inside an earlier segment (repacketised).
                guard let old = sent.randomElement(using: &rng), old.len > 200 else { continue }
                w.s(t, W.ACK, len: old.len / 2, seq: old.seq &+ UInt32(old.len / 4))
            }
        }
        return w
    }
}
