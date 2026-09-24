import CPcap
import XCTest
@testable import SheepLog

final class PcapFileTests: XCTestCase {
    private typealias F = PacketFixture

    private func tempURL(_ name: String) -> URL {
        FileManager.default.temporaryDirectory.appending(path: "SheepLogTests-\(UUID().uuidString)-\(name)")
    }

    /// 100 plain TCP / UDP packets (one tcpdump line each), 1 ms apart.
    private func synthetic() -> [Packet] {
        let base = 1_700_000_000.123456
        return (0..<100).map { i in
            let data: Data = i % 2 == 0
                ? F.tcp4(src: "10.1.0.\(i % 50 + 1)", 40000 + i, 8080, seq: UInt32(i), flags: 0x02, options: F.synOptions)
                : F.udp4(src: "10.1.0.\(i % 50 + 1)", 40000 + i, 9999, [UInt8](repeating: UInt8(i), count: i))
            let ts = base + Double(i) * 0.001
            // Every tenth packet claims a longer wire length (snap-length truncated).
            let length = i % 10 == 0 ? data.count + 100 : data.count
            return Packet(id: i + 1, timestamp: Date(timeIntervalSince1970: ts), relative: Double(i) * 0.001,
                          length: length, captured: data.count, data: data, decoded: PacketDecoder.decode(data))
        }
    }

    func testRoundTrip() throws {
        let url = tempURL("roundtrip.pcap")
        defer { try? FileManager.default.removeItem(at: url) }
        let original = synthetic()
        try PcapFile.write(original, linkType: 1, to: url)

        var read: [Packet] = []
        var batches = 0
        let lt = try PcapFile.read(url) { batch in read += batch; batches += 1 }
        XCTAssertEqual(lt, 1)
        XCTAssertEqual(batches, 1)
        XCTAssertEqual(read.count, 100)
        for (a, b) in zip(original, read) {
            XCTAssertEqual(a.id, b.id)
            XCTAssertEqual(a.timestamp.timeIntervalSince1970, b.timestamp.timeIntervalSince1970, accuracy: 1e-6)
            XCTAssertEqual(a.relative, b.relative, accuracy: 1e-6)
            XCTAssertEqual(a.length, b.length)
            XCTAssertEqual(a.captured, b.captured)
            XCTAssertEqual(a.data, b.data)
            XCTAssertEqual(a.decoded, b.decoded)
        }
    }

    func testTcpdumpReadsOurFile() throws {
        let tcpdump = URL(fileURLWithPath: "/usr/sbin/tcpdump")
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: tcpdump.path), "tcpdump not installed")
        let url = tempURL("tcpdump.pcap")
        defer { try? FileManager.default.removeItem(at: url) }
        try PcapFile.write(synthetic(), linkType: 1, to: url)

        let p = Process()
        p.executableURL = tcpdump
        p.arguments = ["-n", "-r", url.path]
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        try p.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        let lines = String(decoding: data, as: UTF8.self).split(separator: "\n")
        XCTAssertEqual(p.terminationStatus, 0, String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self))
        XCTAssertEqual(lines.count, 100)
        XCTAssertTrue(lines.first?.contains("10.1.0.1.40000 > 93.184.216.34.8080") ?? false, String(lines.first ?? ""))
    }

    func testBadFileThrows() throws {
        let url = tempURL("garbage.pcap")
        defer { try? FileManager.default.removeItem(at: url) }
        try Data("this is not a capture file at all".utf8).write(to: url)
        XCTAssertThrowsError(try PcapFile.read(url) { _ in })
        XCTAssertThrowsError(try PcapFile.linkType(of: url))
        XCTAssertThrowsError(try PcapFile.read(URL(fileURLWithPath: "/nonexistent/x.pcap")) { _ in })
    }

    func testLargeFileBatches() throws {
        let url = tempURL("big.pcap")
        defer { try? FileManager.default.removeItem(at: url) }
        let one = synthetic()
        var many: [Packet] = []
        for i in 0..<12_000 { many.append(one[i % one.count]) }
        try PcapFile.write(many, linkType: 1, to: url)
        var sizes: [Int] = []
        _ = try PcapFile.read(url) { sizes.append($0.count) }
        XCTAssertEqual(sizes, [5_000, 5_000, 2_000])
    }

    @MainActor
    func testStoreLoadAndSave() async throws {
        let url = tempURL("store.pcap")
        let saved = tempURL("saved.pcap")
        defer {
            try? FileManager.default.removeItem(at: url)
            try? FileManager.default.removeItem(at: saved)
        }
        try PcapFile.write(synthetic(), linkType: 1, to: url)
        let store = PacketStore()
        let done = expectation(description: "loaded")
        try store.load(from: url) { done.fulfill() }
        await fulfillment(of: [done], timeout: 5)
        XCTAssertEqual(store.packets.count, 100)
        XCTAssertEqual(store.packets.first?.id, 1)
        XCTAssertEqual(store.fileURL, url)
        XCTAssertEqual(store.linkType, 1)
        XCTAssertFalse(store.isLoading)

        store.queryText = "proto:udp"
        store.applyQueryNow(synchronous: true)
        XCTAssertEqual(store.visible.count, 50)
        try store.save(to: saved)
        var back: [Packet] = []
        _ = try PcapFile.read(saved) { back += $0 }
        XCTAssertEqual(back.count, 50)
        XCTAssertTrue(back.allSatisfy { $0.decoded.udp != nil })
    }
}

// MARK: - Review: odd files

/// Little-endian pcapng blocks, built by hand.
enum PcapNG {
    static func u16(_ v: Int) -> [UInt8] { [UInt8(v & 0xff), UInt8((v >> 8) & 0xff)] }
    static func u32(_ v: UInt32) -> [UInt8] { [UInt8(v & 0xff), UInt8((v >> 8) & 0xff), UInt8((v >> 16) & 0xff), UInt8(v >> 24)] }

    static func block(_ type: UInt32, _ body: [UInt8]) -> [UInt8] {
        var b = body
        while b.count % 4 != 0 { b.append(0) }
        let total = UInt32(12 + b.count)
        return u32(type) + u32(total) + b + u32(total)
    }

    static let shb: [UInt8] = block(0x0A0D_0D0A, u32(0x1A2B_3C4D) + u16(1) + u16(0) + [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    static func idb(linkType: Int, snap: UInt32 = 262_144) -> [UInt8] { block(1, u16(linkType) + u16(0) + u32(snap)) }
    static func epb(interface: UInt32, micros: UInt64, _ data: [UInt8]) -> [UInt8] {
        block(6, u32(interface) + u32(UInt32(micros >> 32)) + u32(UInt32(micros & 0xffff_ffff))
              + u32(UInt32(data.count)) + u32(UInt32(data.count)) + data)
    }
}

final class PcapFileReviewTests: XCTestCase {
    private typealias F = PacketFixture

    private func tempURL(_ name: String) -> URL {
        FileManager.default.temporaryDirectory.appending(path: "SheepLogTests-\(UUID().uuidString)-\(name)")
    }

    private func packet(_ data: Data, t: Double, id: Int = 1, length: Int? = nil) -> Packet {
        Packet(id: id, timestamp: Date(timeIntervalSince1970: t), relative: 0, length: length ?? data.count,
               captured: data.count, data: data, decoded: PacketDecoder.decode(data))
    }

    /// A packet longer than the dead handle's snap length is written truncated (with its wire
    /// length kept), so libpcap and tcpdump can still read the file.
    func testCaptureLengthAboveSnapLength() throws {
        let url = tempURL("jumbo.pcap")
        defer { try? FileManager.default.removeItem(at: url) }
        var bytes = [UInt8](F.tcp4(51234, 80, seq: 1, ack: 1, flags: 0x18, Array("GET / HTTP/1.1\r\n".utf8)))
        bytes += [UInt8](repeating: 0x41, count: 300_000 - bytes.count)
        let small = F.udp4(40000, 53, F.dnsQuery("after.example"))
        try PcapFile.write([packet(Data(bytes), t: 1_700_000_000), packet(small, t: 1_700_000_001, id: 2)], linkType: 1, to: url)
        var back: [Packet] = []
        _ = try PcapFile.read(url) { back += $0 }
        XCTAssertEqual(back.count, 2)
        XCTAssertEqual(back.first?.captured, 262_144)
        XCTAssertEqual(back.first?.length, 300_000)
        XCTAssertEqual(back.last?.data, small)
    }

    /// Timestamps before 1970 (and with a fractional part) survive a round trip.
    func testTimestampsBefore1970() throws {
        let url = tempURL("old.pcap")
        defer { try? FileManager.default.removeItem(at: url) }
        let d = F.udp4(40000, 53, F.dnsQuery("old.example"))
        let times = [-1.5, -0.25, 0, 0.999_999_6, 1_700_000_000.5]
        try PcapFile.write(times.enumerated().map { packet(d, t: $1, id: $0 + 1) }, linkType: 1, to: url)
        var back: [Packet] = []
        _ = try PcapFile.read(url) { back += $0 }
        XCTAssertEqual(back.count, times.count)
        for (t, p) in zip(times, back) {
            XCTAssertEqual(p.timestamp.timeIntervalSince1970, t, accuracy: 1e-6)
        }
        XCTAssertEqual(back.first?.relative ?? -1, 0, accuracy: 1e-9)
        XCTAssertEqual(back[1].relative, 1.25, accuracy: 1e-6)
    }

    func testPcapngWithNoPackets() throws {
        let url = tempURL("empty.pcapng")
        defer { try? FileManager.default.removeItem(at: url) }
        try Data(PcapNG.shb + PcapNG.idb(linkType: 1)).write(to: url)
        var n = 0
        XCTAssertEqual(try PcapFile.read(url) { n += $0.count }, 1)
        XCTAssertEqual(n, 0)
    }

    /// pcapng with two interfaces of different link types: libpcap exposes one link type per
    /// file, so the read stops at the first packet of the other type — with the packets before it
    /// kept and an error that says why.
    func testPcapngTwoLinkTypes() throws {
        let url = tempURL("two.pcapng")
        defer { try? FileManager.default.removeItem(at: url) }
        let eth = [UInt8](F.udp4(40000, 53, F.dnsQuery("eth.example")))
        let raw = F.ipv4(proto: 17, F.udp(40000, 53, F.dnsQuery("raw.example")))
        var file = PcapNG.shb + PcapNG.idb(linkType: 1) + PcapNG.idb(linkType: 101)
        file += PcapNG.epb(interface: 0, micros: 1_700_000_000_000_000, eth)
        file += PcapNG.epb(interface: 0, micros: 1_700_000_000_000_100, eth)
        file += PcapNG.epb(interface: 1, micros: 1_700_000_000_000_200, raw)
        try Data(file).write(to: url)
        var back: [Packet] = []
        do {
            let lt = try PcapFile.read(url) { back += $0 }
            // A libpcap that maps every interface: then every packet must at least be there.
            XCTAssertEqual(lt, 1)
            XCTAssertEqual(back.count, 3)
        } catch {
            // libpcap rejects the second IDB when it reads it — IDBs come first in real files,
            // so usually no packet at all is read.
            print("[pcapng] two link types: \(back.count) packets, error: \(error.localizedDescription)")
            XCTAssertLessThanOrEqual(back.count, 2)
            XCTAssertTrue(error.localizedDescription.localizedCaseInsensitiveContains("link type"), error.localizedDescription)
        }
    }

    /// A file still being written ends in the middle of a record: the complete packets are read
    /// and the error says what happened in words.
    func testFileStillBeingWritten() throws {
        let url = tempURL("growing.pcap")
        defer { try? FileManager.default.removeItem(at: url) }
        let d = F.udp4(40000, 53, F.dnsQuery("grow.example"))
        try PcapFile.write((1...100).map { packet(d, t: 1_700_000_000 + Double($0), id: $0) }, linkType: 1, to: url)
        let full = try Data(contentsOf: url)
        try full.prefix(full.count - 10).write(to: url)
        var n = 0
        XCTAssertThrowsError(try PcapFile.read(url) { n += $0.count }) { error in
            XCTAssertTrue(error.localizedDescription.contains("ends in the middle of a packet"), error.localizedDescription)
        }
        XCTAssertEqual(n, 99)
    }

    func testNotACaptureFileSaysSo() throws {
        let url = tempURL("notes.txt")
        defer { try? FileManager.default.removeItem(at: url) }
        try Data("hello, this is a text file\n".utf8).write(to: url)
        XCTAssertThrowsError(try PcapFile.linkType(of: url)) { error in
            XCTAssertTrue(error.localizedDescription.contains("not a pcap or pcapng capture file"), error.localizedDescription)
        }
    }
}

// MARK: - Review: the libpcap capture lifecycle (needs /dev/bpf access; skipped otherwise)

@MainActor
final class CaptureEngineTests: XCTestCase {
    private func requireBPF() throws {
        try XCTSkipUnless(FileManager.default.isReadableFile(atPath: "/dev/bpf0"), "no read access to /dev/bpf*")
    }

    /// UDP datagrams to 127.0.0.1:`port` — they cross lo0 whether or not anyone listens.
    private func sendUDP(count: Int, port: UInt16) {
        TestSockets.sendUDP(Array("sheeplog-capture-test".utf8), to: port, times: count)
    }

    private func waitForReaders(_ n: Int, timeout: Double = 2) async {
        let end = Date().addingTimeInterval(timeout)
        while CaptureReader.activeCount != n, Date() < end { try? await Task.sleep(for: .milliseconds(20)) }
    }

    func testBadInterfaceAndBadFilter() throws {
        let store = PacketStore()
        let engine = CaptureEngine(store: store)
        engine.start(interface: "nonexistent-if9", promiscuous: false, bpfFilter: "")
        XCTAssertFalse(engine.isRunning)
        XCTAssertNotNil(engine.lastError)
        engine.stop()
        engine.stop()
        try requireBPF()
        engine.start(interface: "lo0", promiscuous: false, bpfFilter: "port nope-not-a-port")
        XCTAssertFalse(engine.isRunning)
        XCTAssertTrue(engine.lastError?.hasPrefix("Bad capture filter") ?? false, engine.lastError ?? "nil")
    }

    func testLiveLoopbackCaptureStopRestart() async throws {
        try requireBPF()
        let store = PacketStore()
        let engine = CaptureEngine(store: store)
        await waitForReaders(0)
        // Promiscuous on lo0 is PCAP_WARNING_PROMISC_NOTSUP territory: a warning, not a failure.
        engine.start(interface: "lo0", promiscuous: true, bpfFilter: "udp port 50999")
        XCTAssertTrue(engine.isRunning, engine.lastError ?? "")
        try await Task.sleep(for: .milliseconds(200))
        sendUDP(count: 200, port: 50999)
        let end = Date().addingTimeInterval(3)
        while store.packets.count < 200, Date() < end { try await Task.sleep(for: .milliseconds(20)) }
        XCTAssertEqual(store.packets.count, 200)
        XCTAssertEqual(store.packets.first?.id, 1)
        XCTAssertEqual(store.packets.first?.decoded.udp?.destinationPort, 50999)

        // Start while running = restart; the store starts over.
        engine.start(interface: "lo0", promiscuous: false, bpfFilter: "udp port 50999")
        XCTAssertTrue(engine.isRunning)
        XCTAssertEqual(store.packets.count, 0)
        try await Task.sleep(for: .milliseconds(100))
        sendUDP(count: 10, port: 50999)
        let end2 = Date().addingTimeInterval(3)
        while store.packets.count < 10, Date() < end2 { try await Task.sleep(for: .milliseconds(20)) }
        XCTAssertEqual(store.packets.count, 10)
        XCTAssertEqual(store.packets.first?.id, 1)

        // Stop returns promptly even with no traffic (pcap_next_ex blocked in the kernel).
        try await Task.sleep(for: .milliseconds(300))
        let t0 = Date()
        engine.stop()
        let took = Date().timeIntervalSince(t0)
        print("[timing] CaptureEngine.stop on an idle lo0: \(String(format: "%.0f", took * 1000)) ms")
        XCTAssertWithinBudget(took, 0.5)
        XCTAssertFalse(engine.isRunning)
        engine.stop()
        await waitForReaders(0)
        XCTAssertEqual(CaptureReader.activeCount, 0)
    }

    /// Dropping the last reference mid-capture ends the read thread and closes the handle.
    func testEngineReleasedMidCapture() async throws {
        try requireBPF()
        await waitForReaders(0)
        let store = PacketStore()
        do {
            let engine = CaptureEngine(store: store)
            engine.start(interface: "lo0", promiscuous: false, bpfFilter: "udp port 50998")
            XCTAssertTrue(engine.isRunning, engine.lastError ?? "")
            await waitForReaders(1)
            XCTAssertEqual(CaptureReader.activeCount, 1)
        }
        await waitForReaders(0)
        XCTAssertEqual(CaptureReader.activeCount, 0)
    }

    /// The read loop owns the handle: it is closed by the thread itself, after its last use.
    func testReaderClosesHandleAfterItsLastUse() async throws {
        let url = FileManager.default.temporaryDirectory.appending(path: "SheepLogTests-\(UUID().uuidString).pcap")
        defer { try? FileManager.default.removeItem(at: url) }
        let d = PacketFixture.udp4(40000, 53, PacketFixture.dnsQuery("reader.example"))
        try PcapFile.write((1...50).map {
            Packet(id: $0, timestamp: Date(timeIntervalSince1970: 1_700_000_000 + Double($0)), relative: 0,
                   length: d.count, captured: d.count, data: d, decoded: PacketDecoder.decode(d))
        }, linkType: 1, to: url)
        var errbuf = [CChar](repeating: 0, count: 256)
        guard let p = pcap_open_offline(url.path, &errbuf) else { return XCTFail("pcap_open_offline") }
        let handle = PcapHandle(p)
        let got = LockedBox(0)
        let reader = CaptureReader(handle: handle, linkType: 1, deliver: { batch in got.mutate { $0 += batch.count } }, stats: { _ in }, failed: { _ in })
        reader.start()
        reader.join(timeout: 2)
        XCTAssertEqual(got.value, 50)
        XCTAssertNil(handle.pointer, "closed by the read thread")
        handle.breakLoop()      // harmless after close
        handle.close()          // idempotent
    }
}

