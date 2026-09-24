import Darwin
import XCTest
@testable import SheepLog

/// Round-2 review: a 1,000,000-packet file through the 200,000-packet ring, and the decoder
/// details found against tcpdump / Wireshark.
@MainActor
final class CaptureLoadStressTests: XCTestCase {
    /// Main-thread timer bookkeeping (touched only on the main run loop).
    private final class Probe: @unchecked Sendable {
        var maxStall = 0.0
        var last = CFAbsoluteTimeGetCurrent()
        var peak = 0.0
    }

    /// Resident memory of this process, in MB.
    nonisolated private static func rssMB() -> Double {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size / MemoryLayout<natural_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
            }
        }
        return kr == KERN_SUCCESS ? Double(info.resident_size) / 1_048_576 : 0
    }

    /// A classic pcap of `n` small UDP frames (60 bytes, 20 kinds of 5-tuples), written directly.
    private func writeSynthetic(_ n: Int, to url: URL) throws {
        var out = Data(capacity: 24 + n * 76)
        func le32(_ v: UInt32) { withUnsafeBytes(of: v.littleEndian) { out.append(contentsOf: $0) } }
        func le16(_ v: UInt16) { withUnsafeBytes(of: v.littleEndian) { out.append(contentsOf: $0) } }
        le32(0xa1b2c3d4); le16(2); le16(4); le32(0); le32(0); le32(65535); le32(1)
        let frames: [Data] = (0..<20).map { i in
            PacketFixture.udp4(src: "10.9.\(i).1", dst: "10.9.0.254", 40000 + i, 514, Array("<14>n\(i)".utf8))
        }
        for k in 0..<n {
            let f = frames[k % frames.count]
            le32(UInt32(1_790_000_000 + k / 10_000)); le32(UInt32((k % 10_000) * 100))
            le32(UInt32(f.count)); le32(UInt32(f.count))
            out.append(f)
            if out.count > 32 << 20 {
                try append(out, to: url); out.removeAll(keepingCapacity: true)
            }
        }
        try append(out, to: url)
    }

    private func append(_ d: Data, to url: URL) throws {
        if !FileManager.default.fileExists(atPath: url.path) { FileManager.default.createFile(atPath: url.path, contents: nil) }
        let h = try FileHandle(forWritingTo: url)
        try h.seekToEnd()
        try h.write(contentsOf: d)
        try h.close()
    }

    /// The store keeps the LAST `limit` packets (it is a ring, as for a live capture: the end of a
    /// file is where the trouble that made someone save it usually is), memory stays bounded,
    /// the main thread keeps turning while the file is read, and the heading says what is shown.
    func testMillionPacketFileKeepsTheLast200k() async throws {
        let url = FileManager.default.temporaryDirectory.appending(path: "SheepLogTests-\(UUID().uuidString)-1M.pcap")
        defer { try? FileManager.default.removeItem(at: url) }
        let n = 1_000_000
        try writeSynthetic(n, to: url)

        let store = PacketStore()
        store.limit = 200_000
        let before = Self.rssMB()
        let probe = Probe()
        probe.peak = before
        let timer = Timer(timeInterval: 0.01, repeats: true) { _ in
            let now = CFAbsoluteTimeGetCurrent()
            probe.maxStall = max(probe.maxStall, now - probe.last)
            probe.last = now
        }
        RunLoop.main.add(timer, forMode: .common)
        let sampler = Timer(timeInterval: 0.1, repeats: true) { _ in
            probe.peak = max(probe.peak, Self.rssMB())
        }
        RunLoop.main.add(sampler, forMode: .common)

        let done = expectation(description: "loaded")
        let start = Date()
        try store.load(from: url) { done.fulfill() }
        XCTAssertTrue(store.isLoading)
        await fulfillment(of: [done], timeout: 120)
        let elapsed = Date().timeIntervalSince(start)
        timer.invalidate(); sampler.invalidate()
        let after = Self.rssMB()
        let peak = max(probe.peak, after), maxStall = probe.maxStall

        XCTAssertFalse(store.isLoading)
        XCTAssertEqual(store.totalReceived, n)
        XCTAssertEqual(store.packets.count, 200_000)
        XCTAssertEqual(store.packets.first?.id, 800_001, "the last 200,000 frames, numbered as in the file")
        XCTAssertEqual(store.packets.last?.id, n)
        XCTAssertEqual(store.dropped, 800_000)
        print(String(format: "MEM 1M-packet load: rss before %.0f MB, peak %.0f MB, after %.0f MB, %.1f s, longest main-thread stall %.0f ms",
                     before, peak, after, elapsed, maxStall * 1000))
        XCTAssertWithinBudget(peak - before, 600, "memory stays bounded while 1,000,000 packets stream through a 200k ring")
        XCTAssertWithinBudget(maxStall, 0.5, "the main thread keeps running while the file is read")
    }

    /// Save with a filter writes exactly the filtered packets, as a file tcpdump reads.
    func testSaveFilteredSubsetIsReadByTcpdump() async throws {
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: "/usr/sbin/tcpdump"))
        let src = CaptureGroundTruthTests.pcapDir.appending(path: "http-tls.pcap")
        let store = PacketStore()
        let loaded = expectation(description: "loaded")
        try store.load(from: src) { loaded.fulfill() }
        await fulfillment(of: [loaded], timeout: 30)
        store.queryText = "proto:http"
        store.applyQueryNow(synchronous: true)
        let n = store.visible.count
        XCTAssertGreaterThan(n, 0)
        XCTAssertLessThan(n, store.packets.count)
        let out = FileManager.default.temporaryDirectory.appending(path: "SheepLogTests-\(UUID().uuidString)-saved.pcap")
        defer { try? FileManager.default.removeItem(at: out) }
        let saved = expectation(description: "saved")
        store.save(to: out) { error in XCTAssertNil(error); saved.fulfill() }
        XCTAssertEqual(store.savingCount, n, "the heading can say how many filtered packets are being saved")
        await fulfillment(of: [saved], timeout: 30)
        let text = CaptureGroundTruthTests.run("/usr/sbin/tcpdump", ["-nn", "-r", out.path])
        XCTAssertEqual(text.split(separator: "\n").count, n, text)
    }

    /// A bad BPF filter given while a capture runs: the old run is stopped (no read thread left),
    /// nothing half-started, the libpcap message shown.
    func testBadFilterWhileRunningLeavesNothingHalfStarted() throws {
        let fd = open("/dev/bpf0", O_RDONLY)
        try XCTSkipIf(fd < 0 && errno == EACCES, "no permission for /dev/bpf*")
        if fd >= 0 { close(fd) }
        let store = PacketStore()
        let engine = CaptureEngine(store: store)
        engine.start(interface: "lo0", promiscuous: false, bpfFilter: "")
        XCTAssertTrue(engine.isRunning, engine.lastError ?? "")
        engine.start(interface: "lo0", promiscuous: false, bpfFilter: "tcp port 80 and and")
        XCTAssertFalse(engine.isRunning)
        let message = try XCTUnwrap(engine.lastError)
        XCTAssertTrue(message.hasPrefix("Bad capture filter: "), message)
        XCTAssertTrue(message.contains("syntax error"), "libpcap's own words: \(message)")
        XCTAssertEqual(CaptureReader.activeCount, 0)
        engine.stop()
    }
}

final class CaptureRound2DecoderTests: XCTestCase {
    private typealias F = PacketFixture

    func testDNSResponseListsEveryAnswer() {
        var m = F.be16(0x77) + [0x81, 0x80] + F.be16(1) + F.be16(3) + F.be16(0) + F.be16(0)
        m += F.dnsName("www.example.com") + F.be16(1) + F.be16(1)
        m += [0xc0, 0x0c] + F.be16(5) + F.be16(1) + F.be32(60) + F.be16(10) + F.dnsName("edge.cdn")
        m += [0xc0, 0x0c] + F.be16(1) + F.be16(1) + F.be32(60) + F.be16(4) + F.ip4("1.2.3.4")
        m += [0xc0, 0x0c] + F.be16(1) + F.be16(1) + F.be32(60) + F.be16(4) + F.ip4("5.6.7.8")
        let d = PacketDecoder.decode(F.udp4(src: "1.1.1.1", dst: "10.1.0.9", 53, 53000, m))
        XCTAssertEqual(d.info, "Standard query response 0x0077 A www.example.com CNAME edge.cdn A 1.2.3.4 A 5.6.7.8")
    }

    /// A v2 trap's first varbind is sysUpTime.0; what it is about is snmpTrapOID.0's value.
    func testSNMPv2TrapShowsTheTrapOID() {
        func tlv(_ tag: UInt8, _ body: [UInt8]) -> [UInt8] { [tag, UInt8(body.count)] + body }
        func oid(_ s: [UInt8]) -> [UInt8] { tlv(0x06, s) }
        let upTime = tlv(0x30, oid([0x2b, 6, 1, 2, 1, 1, 3, 0]) + tlv(0x43, [0x01]))
        let trapOID = tlv(0x30, oid([0x2b, 6, 1, 6, 3, 1, 1, 4, 1, 0]) + oid([0x2b, 6, 1, 6, 3, 1, 1, 5, 3]))
        let pdu = tlv(0xA7, tlv(0x02, [0x01]) + tlv(0x02, [0]) + tlv(0x02, [0]) + tlv(0x30, upTime + trapOID))
        let msg = tlv(0x30, tlv(0x02, [1]) + tlv(0x04, Array("public".utf8)) + pdu)
        let d = PacketDecoder.decode(F.udp4(src: "10.1.0.2", dst: "10.1.0.9", 40000, 162, msg))
        XCTAssertEqual(d.info, "snmpV2-trap 1.3.6.1.6.3.1.1.5.3 (linkDown)")
        // A GetBulk's non-repeaters is not an error-status.
        let bulk = tlv(0xA5, tlv(0x02, [0x05]) + tlv(0x02, [1]) + tlv(0x02, [10])
                       + tlv(0x30, tlv(0x30, oid([0x2b, 6, 1, 2, 1, 2]) + [0x05, 0x00])))
        let b = PacketDecoder.decode(F.udp4(40000, 161, tlv(0x30, tlv(0x02, [1]) + tlv(0x04, Array("public".utf8)) + bulk)))
        XCTAssertEqual(b.info, "getBulkRequest 1.3.6.1.2.1.2")
        // An error names itself.
        let resp = tlv(0xA2, tlv(0x02, [0x05]) + tlv(0x02, [2]) + tlv(0x02, [1])
                       + tlv(0x30, tlv(0x30, oid([0x2b, 6, 1, 2, 1, 1, 9, 9]) + [0x05, 0x00])))
        let e = PacketDecoder.decode(F.udp4(src: "10.1.0.2", dst: "10.1.0.9", 161, 40000,
                                            tlv(0x30, tlv(0x02, [1]) + tlv(0x04, Array("public".utf8)) + resp)))
        XCTAssertEqual(e.info, "get-response 1.3.6.1.2.1.1.9.9 error-status=noSuchName (2)")
    }

    /// The server's banner and KEXINIT in one segment; a KEXINIT split over two segments.
    func testSSHKexInitAfterBannerAndSplit() {
        var kex = F.be32(1_000) + [8, 20] + [UInt8](repeating: 0x41, count: 40)
        let banner = Array("SSH-2.0-OpenSSH_9.9\r\n".utf8)
        let d = PacketDecoder.decode(F.tcp4(src: "10.1.0.2", dst: "10.1.0.9", 22, 50000, seq: 1, ack: 1, flags: 0x18, banner + kex))
        XCTAssertEqual(d.info, "Protocol (SSH-2.0-OpenSSH_9.9), Key Exchange Init")
        kex += [UInt8](repeating: 0x42, count: 100)
        let first = PacketDecoder.decode(F.tcp4(50000, 22, seq: 1, ack: 1, flags: 0x10, kex))
        XCTAssertEqual(first.info, "Key Exchange Init", "first of two segments")
    }

    /// An ICMP traceroute's hop answer names the probe (id / seq) it answers.
    func testTimeExceededQuotesTheEchoProbe() {
        let probe: [UInt8] = [8, 0, 0, 0] + F.be16(0xabcd) + F.be16(6)
        let quoted = F.ipv4(src: "10.1.0.9", dst: "8.8.8.8", proto: 1, ttl: 1, probe)
        let icmp: [UInt8] = [11, 0, 0, 0, 0, 0, 0, 0] + quoted
        let d = PacketDecoder.decode(Data(F.ether(type: 0x0800, F.ipv4(src: "10.1.0.1", dst: "10.1.0.9", proto: 1, icmp))))
        XCTAssertEqual(d.info, "Time exceeded (TTL exceeded in transit) for 10.1.0.9 → 8.8.8.8 ICMP echo id=0xabcd seq=6")
    }

    @MainActor
    func testFlowSummaryAndTimeline() throws {
        let flows = TCPFlowAnalyzer.analyze(TCPFlowDemo.packets())
        let slow = try XCTUnwrap(flows.first { $0.application == "HTTP" && $0.serverPort == 8080 })
        let text = FlowSummary.text(slow)
        XCTAssertTrue(text.hasPrefix("TCP 10.1.20.15:51262 → 10.1.30.12:8080 (HTTP)\n"), text)
        XCTAssertTrue(text.contains("Health: problem — server took 4.2 s to answer POST /api/report"), text)
        XCTAssertTrue(text.contains("POST /api/report → 200 OK after 4.21 s"), text)
        XCTAssertTrue(text.contains("The server took 4.2 s to answer POST /api/report"), text)
        let lossy = try XCTUnwrap(flows.first { $0.application == "TLS files.corp.example" })
        XCTAssertFalse(FlowTimeline.marks(lossy).isEmpty)
        XCTAssertEqual(FlowTimeline.durationText(125), "2 min 5 s")
    }

    func testFlowSelectRequestPicksTheConversationOfTheFrame() {
        // The same 4-tuple twice (closed, reopened with a new ISN): frame → its own conversation.
        func conv(_ t0: Double, _ id0: Int, isn: UInt32) -> [Packet] {
            var s = TCPFlowDemo.Script(firstID: id0, offset: t0, client: "10.0.0.1", clientPort: 50000, server: "10.0.0.2", serverPort: 80)
            s.cseq = isn
            s.handshake(rtt: 0.01)
            s.c(0.02, [.fin, .ack]); s.s(0.03, [.fin, .ack]); s.c(0.04, .ack)
            return s.packets
        }
        let flows = TCPFlowAnalyzer.analyze(conv(0, 1, isn: 100) + conv(5, 7, isn: 90_000))
        XCTAssertEqual(flows.count, 2)
        let key = flows[0].key
        XCTAssertEqual(FlowSelectRequest.match(flows, key: key, packetID: 9)?.id, flows[1].id)
        XCTAssertEqual(FlowSelectRequest.match(flows, key: key, packetID: 2)?.id, flows[0].id)
    }
}
