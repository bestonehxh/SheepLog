import XCTest
@testable import SheepLog

/// `TCPFlowAnalyzer` on real captures against Wireshark's own TCP analysis (tshark): per
/// conversation the packet and payload-byte counts, duration, which side is the client, the
/// retransmission / out-of-order / duplicate-ACK counts (`tcp.analysis.*`), zero windows, the
/// handshake RTT (SYN → SYN/ACK) and, for HTTP, request → first response byte.
/// Skipped when Wireshark is not installed. Per-file reports: `$TMPDIR/SheepLog-flowtruth-<file>.txt`.
final class TCPFlowGroundTruthTests: XCTestCase {
    struct Stream {
        var id: Int
        var key: FlowKey?
        var first = 0.0, last = 0.0
        var packets = 0
        /// Client endpoint (sender of the first bare SYN, or receiver of the first SYN/ACK).
        var client: (String, UInt16)?
        var firstAddr: (String, UInt16)?
        var bytesFromFirst = 0, bytesToFirst = 0
        var retrans = 0, ooo = 0, dupAcks = 0, zeroWin = 0, spurious = 0
        var lastSYN: Double?
        var synAck: Double?
        var firstRequest: Double?
        var firstResponse: Double?
        var startsWithSYN = false
    }

    struct Report {
        var flows = 0
        var matched = 0
        var mismatches: [String] = []
        var lines: [String] = []
    }

    func testCommittedCapturesMatchWireshark() throws {
        guard let tshark = CaptureGroundTruthTests.tshark else { throw XCTSkip("tshark not installed") }
        let files = try FileManager.default.contentsOfDirectory(at: CaptureGroundTruthTests.pcapDir, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "pcap" }.sorted { $0.lastPathComponent < $1.lastPathComponent }
        for url in files {
            let r = try compare(url, tshark: tshark)
            XCTAssertEqual(r.mismatches.count, 0, "\(url.lastPathComponent):\n" + r.mismatches.prefix(12).joined(separator: "\n"))
            XCTAssertEqual(r.matched, r.flows, "\(url.lastPathComponent): every Wireshark stream is one of our flows")
        }
    }

    func testLocalRecordingsMatchWireshark() throws {
        guard let tshark = CaptureGroundTruthTests.tshark else { throw XCTSkip("tshark not installed") }
        var paths = (1...9).map { "/tmp/c\($0).pcap" }
        if let extra = ProcessInfo.processInfo.environment["SHEEPLOG_PCAPS"] { paths += extra.split(separator: ":").map(String.init) }
        let present = paths.filter { FileManager.default.fileExists(atPath: $0) }
        try XCTSkipIf(present.isEmpty, "no local recordings")
        for path in present {
            let r = try compare(URL(fileURLWithPath: path), tshark: tshark)
            XCTAssertEqual(r.mismatches.count, 0, "\(path):\n" + r.mismatches.prefix(12).joined(separator: "\n"))
        }
    }

    // MARK: -

    func compare(_ url: URL, tshark: String) throws -> Report {
        var packets: [Packet] = []
        _ = try PcapFile.read(url) { packets += $0 }
        let flows = TCPFlowAnalyzer.analyze(packets)
        let streams = Self.streams(tshark, url)
        var r = Report()
        r.flows = streams.count
        // Wireshark opens a new stream when a SYN follows a RST on the same ports; a client
        // retrying a refused port (macOS does once, with the same ISN) is one attempt to us —
        // one flow, "refused, 2 attempts", the retried SYN counted as a SYN retransmission.
        // Such follow-on streams are folded into the stream they continue.
        var merged: [Stream] = []
        for s in streams {
            if let i = merged.lastIndex(where: { $0.key == s.key }), s.startsWithSYN,
               let f = flows.first(where: { $0.key == s.key && abs($0.firstTime.timeIntervalSince1970 - merged[i].first) < 2e-6 }),
               f.refused, s.first <= f.firstTime.timeIntervalSince1970 + f.duration + 1e-6 {
                var m = merged[i]
                m.last = max(m.last, s.last); m.packets += s.packets
                m.bytesFromFirst += s.bytesFromFirst; m.bytesToFirst += s.bytesToFirst
                m.retrans += s.retrans + 1          // the retried SYN
                m.ooo += s.ooo; m.dupAcks += s.dupAcks; m.zeroWin += s.zeroWin; m.spurious += s.spurious
                merged[i] = m
                r.lines.append("stream \(s.id) folded into stream \(m.id) (SYN retried after RST)")
                r.matched += 1
                continue
            }
            merged.append(s)
        }
        for s in merged {
            guard let key = s.key else { continue }
            guard let f = flows.first(where: { $0.key == key && abs($0.firstTime.timeIntervalSince1970 - s.first) < 2e-6 }) else {
                r.mismatches.append("stream \(s.id) \(key): no flow of ours starts with it")
                continue
            }
            r.matched += 1
            let tag = "stream \(s.id) \(f.clientEndpoint) → \(f.serverEndpoint) [\(f.application)]"
            func eq<T: Equatable>(_ what: String, _ ours: T, _ ws: T) {
                if ours != ws { r.mismatches.append("\(tag) \(what): ours \(ours), Wireshark \(ws)") }
            }
            func near(_ what: String, _ ours: Double?, _ ws: Double?) {
                guard let ws else { return }
                guard let ours else { r.mismatches.append("\(tag) \(what): ours nil, Wireshark \(ws)"); return }
                if abs(ours - ws) > 2e-6 { r.mismatches.append("\(tag) \(what): ours \(ours), Wireshark \(ws)") }
            }
            eq("packets", f.packetCount, s.packets)
            near("duration", f.duration, s.last - s.first)
            if let c = s.client {
                eq("client", f.clientEndpoint, TCPFlow.endpoint(c.0, c.1))
            }
            if let fa = s.firstAddr {
                let firstIsClient = f.client == fa.0 && f.clientPort == fa.1
                eq("bytes to server", f.bytesToServer, firstIsClient ? s.bytesFromFirst : s.bytesToFirst)
                eq("bytes to client", f.bytesToClient, firstIsClient ? s.bytesToFirst : s.bytesFromFirst)
            }
            eq("retransmissions (incl. SYN)", f.retransmissions + f.synRetransmissions, s.retrans)
            eq("out of order", f.outOfOrder, s.ooo)
            eq("duplicate ACKs", f.dupAcks, s.dupAcks)
            eq("zero window seen", f.zeroWindows > 0, s.zeroWin > 0)
            if let a = s.synAck, let syn = s.lastSYN { near("handshake RTT", f.handshakeRTT, a - syn) }
            if let rq = s.firstRequest, let rs = s.firstResponse, rs > rq {
                near("HTTP first response", f.requests.first?.responseTime, rs - rq)
            }
            r.lines.append("\(tag): \(f.packetCount) pkts, rtt \(f.handshakeRTT.map { TCPFlowAnalyzer.msText($0) } ?? "—"), "
                + "retrans \(f.retransmissions)+\(f.synRetransmissions) (ws \(s.retrans), spurious \(s.spurious)), ooo \(f.outOfOrder) (ws \(s.ooo)), "
                + "dup \(f.dupAcks) (ws \(s.dupAcks)), health \(f.health): \(f.reasons.joined(separator: "; "))")
        }
        var text = "\(url.lastPathComponent): \(r.flows) streams, \(r.matched) matched, \(r.mismatches.count) mismatches\n"
        text += r.mismatches.joined(separator: "\n") + "\n--\n" + r.lines.joined(separator: "\n") + "\n"
        let out = FileManager.default.temporaryDirectory.appending(path: "SheepLog-flowtruth-\(url.lastPathComponent).txt")
        try? text.write(to: out, atomically: true, encoding: .utf8)
        print("FLOWTRUTH \(url.lastPathComponent) streams=\(r.flows) matched=\(r.matched) mismatches=\(r.mismatches.count) report=\(out.path)")
        return r
    }

    static func streams(_ tshark: String, _ url: URL) -> [Stream] {
        let fields = ["tcp.stream", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport", "tcp.dstport",
                      "tcp.flags", "tcp.len", "tcp.analysis.retransmission", "tcp.analysis.out_of_order",
                      "tcp.analysis.duplicate_ack", "tcp.analysis.zero_window", "http.request", "http.response",
                      "tcp.analysis.spurious_retransmission"]
        var args = ["-r", url.path, "-o", "tcp.desegment_tcp_streams:FALSE", "-Y", "tcp", "-T", "fields",
                    "-E", "separator=/t", "-E", "occurrence=f"]
        for f in fields { args += ["-e", f] }
        let out = CaptureGroundTruthTests.run(tshark, args)
        var byID: [Int: Stream] = [:]
        var order: [Int] = []
        for line in out.split(separator: "\n") {
            let c = line.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
            guard c.count >= fields.count, let id = Int(c[0]), let t = Double(c[1]) else { continue }
            let src = c[2].isEmpty ? c[3] : c[2], dst = c[4].isEmpty ? c[5] : c[4]
            guard let sp = UInt16(c[6]), let dp = UInt16(c[7]) else { continue }
            let flags = UInt8(c[8].replacingOccurrences(of: "0x", with: ""), radix: 16) ?? 0
            let len = Int(c[9]) ?? 0
            var s = byID[id] ?? Stream(id: id)
            if byID[id] == nil {
                order.append(id)
                s.key = FlowKey(src, sp, dst, dp, proto: 6)
                s.first = t
                s.firstAddr = (src, sp)
                s.startsWithSYN = flags & 0x12 == 0x02
            }
            s.last = max(s.last, t)
            s.packets += 1
            if let fa = s.firstAddr, fa.0 == src, fa.1 == sp { s.bytesFromFirst += len } else { s.bytesToFirst += len }
            let syn = flags & 0x02 != 0, ack = flags & 0x10 != 0
            if syn, !ack {
                if s.client == nil { s.client = (src, sp) }
                if s.synAck == nil { s.lastSYN = t }
            }
            if syn, ack {
                if s.client == nil { s.client = (dst, dp) }
                if s.synAck == nil, s.lastSYN != nil { s.synAck = t }
            }
            if !c[10].isEmpty { s.retrans += 1 }
            if !c[11].isEmpty { s.ooo += 1 }
            if !c[12].isEmpty { s.dupAcks += 1 }
            if !c[13].isEmpty { s.zeroWin += 1 }
            if !c[14].isEmpty, s.firstRequest == nil { s.firstRequest = t }
            if !c[15].isEmpty, s.firstResponse == nil, s.firstRequest != nil { s.firstResponse = t }
            if !c[16].isEmpty { s.spurious += 1 }
            byID[id] = s
        }
        return order.compactMap { byID[$0] }
    }
}
