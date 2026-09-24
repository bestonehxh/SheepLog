import CPcap
import Darwin
import XCTest
@testable import SheepLog

/// Round 3: MIB files and capture files are hostile input too.
@MainActor
final class HostileMIBTests: XCTestCase {
    private func tempDir(_ tag: String) -> URL {
        let dir = FileManager.default.temporaryDirectory.appending(path: "SheepLogR3\(tag)-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func settle(_ reg: MIBRegistry) async {
        let deadline = Date().addingTimeInterval(20)
        while reg.isLoading, Date() < deadline { try? await Task.sleep(for: .milliseconds(10)) }
    }

    /// A symlink to /etc/passwd, a binary file, a 25 MB file, a FIFO: refused with a reason;
    /// nothing of them lands in the MIB folder.
    func testImportRefusesLinksBinariesAndHugeFiles() async throws {
        let src = tempDir("Src"), dst = tempDir("Dst")
        defer { try? FileManager.default.removeItem(at: src); try? FileManager.default.removeItem(at: dst) }
        let link = src.appending(path: "PASSWD-MIB.mib")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: URL(fileURLWithPath: "/etc/passwd"))
        XCTAssertNotNil(MIBRegistry.importProblem(link))
        let zip = src.appending(path: "vendor.zip.mib")
        try Data([0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x08, 0x00] + [UInt8](repeating: 0, count: 100)).write(to: zip)
        XCTAssertTrue(MIBRegistry.importProblem(zip)?.contains("binary") ?? false)
        let huge = src.appending(path: "HUGE-MIB.mib")
        FileManager.default.createFile(atPath: huge.path, contents: nil)
        let h = try FileHandle(forWritingTo: huge)
        try h.truncate(atOffset: 25 * 1024 * 1024)
        try h.close()
        XCTAssertTrue(MIBRegistry.importProblem(huge)?.contains("20 MB") ?? false)
        let fifo = src.appending(path: "FIFO-MIB.mib")
        XCTAssertEqual(mkfifo(fifo.path, 0o600), 0)
        XCTAssertNotNil(MIBRegistry.importProblem(fifo))
        // A symlink to a real MIB is imported as a copy of the file, not as a link.
        let real = src.appending(path: "real.txt")
        try "REAL-MIB DEFINITIONS ::= BEGIN\nIMPORTS enterprises FROM SNMPv2-SMI;\nreal OBJECT IDENTIFIER ::= { enterprises 424247 }\nEND\n"
            .write(to: real, atomically: true, encoding: .utf8)
        let goodLink = src.appending(path: "REAL-MIB.mib")
        try FileManager.default.createSymbolicLink(at: goodLink, withDestinationURL: real)
        XCTAssertNil(MIBRegistry.importProblem(goodLink))

        let reg = MIBRegistry()
        reg.userFolderOverride = dst
        reg.loadNow(bundled: [])
        reg.importFiles([link, zip, huge, fifo, goodLink])
        await settle(reg)
        let files = try FileManager.default.contentsOfDirectory(atPath: dst.path)
        XCTAssertEqual(files, ["REAL-MIB.mib"])
        let attrs = try FileManager.default.attributesOfItem(atPath: dst.appending(path: "REAL-MIB.mib").path)
        XCTAssertEqual(attrs[.type] as? FileAttributeType, .typeRegular)
        XCTAssertTrue(reg.modules.contains { $0.name == "REAL-MIB" })
        // A folder holding a symlink to /etc/passwd skips it (not a regular file).
        XCTAssertFalse(MIBRegistry.mibFiles(in: src).contains { $0.lastPathComponent == "PASSWD-MIB.mib" })
    }

    /// The MIB folder is a file (or unwritable): the import fails with a reason, no crash, and
    /// nothing is loaded.
    func testImportIntoAnUnusableFolder() async throws {
        let src = tempDir("Src2")
        defer { try? FileManager.default.removeItem(at: src) }
        let mib = src.appending(path: "OK-MIB.mib")
        try "OK-MIB DEFINITIONS ::= BEGIN\nIMPORTS enterprises FROM SNMPv2-SMI;\nok OBJECT IDENTIFIER ::= { enterprises 424248 }\nEND\n"
            .write(to: mib, atomically: true, encoding: .utf8)
        let notAFolder = src.appending(path: "folder-is-a-file")
        try "x".write(to: notAFolder, atomically: true, encoding: .utf8)
        let reg = MIBRegistry()
        reg.userFolderOverride = notAFolder
        reg.loadNow(bundled: [])
        reg.importFiles([mib])
        await settle(reg)
        XCTAssertFalse(reg.modules.contains { $0.name == "OK-MIB" })
        XCTAssertEqual(try String(contentsOf: notAFolder, encoding: .utf8), "x")
    }

    func testSafeFileName() {
        XCTAssertEqual(MIBRegistry.safeFileName("../../etc/passwd"), "_.._etc_passwd")
        XCTAssertEqual(MIBRegistry.safeFileName("A\u{0}B:C"), "A_B_C")
        XCTAssertEqual(MIBRegistry.safeFileName(".."), "unnamed.mib")
        XCTAssertLessThanOrEqual(MIBRegistry.safeFileName(String(repeating: "x", count: 5000)).utf8.count, 200)
    }

    /// `a ::= { b 1 }`, `b ::= { a 1 }` inside a module, and the same cycle through several
    /// modules that each define the names (which the linker explored once per path —
    /// exponential in its depth limit).
    func testCyclicOIDDefinitionsLinkQuickly() {
        var text = "LOOP-MIB DEFINITIONS ::= BEGIN\na OBJECT IDENTIFIER ::= { b 1 }\nb OBJECT IDENTIFIER ::= { a 1 }\nEND\n"
        for k in 0..<4 {
            text += "M\(k)-MIB DEFINITIONS ::= BEGIN\nx OBJECT IDENTIFIER ::= { y 1 }\nEND\n"
            text += "N\(k)-MIB DEFINITIONS ::= BEGIN\ny OBJECT IDENTIFIER ::= { x 1 }\nEND\n"
        }
        let files = MIBParser.parseModules(text, fileName: "loops").map { MIBParsedFile(result: $0, url: nil, builtIn: false) }
        let t0 = Date()
        let idx = MIBIndex.build(files)
        XCTAssertWithinBudget(Date().timeIntervalSince(t0), 1.0)
        XCTAssertNil(idx.byName["a"])
        XCTAssertNil(idx.byName["x"])
    }

    /// Adversarial single files: a 1 MB token, an unterminated DESCRIPTION, 10,000 IMPORTS,
    /// 50,000 unresolvable parents, a 100,000-arc OID value. Each parses and links quickly
    /// with a bounded error list.
    func testAdversarialModulesParseQuickly() {
        let cases: [(String, String)] = [
            ("token", "BIG-MIB DEFINITIONS ::= BEGIN\n" + String(repeating: "x", count: 1_000_000) + "\nEND\n"),
            ("description", "D-MIB DEFINITIONS ::= BEGIN\nfoo OBJECT-TYPE SYNTAX INTEGER DESCRIPTION \"" + String(repeating: "never closed ", count: 50_000)),
            ("imports", "I-MIB DEFINITIONS ::= BEGIN\nIMPORTS " + (0..<10_000).map { "sym\($0)" }.joined(separator: ", ") + " FROM OTHER-MIB;\nEND\n"),
            ("parents", "P-MIB DEFINITIONS ::= BEGIN\n" + (0..<50_000).map { "n\($0) OBJECT IDENTIFIER ::= { p\($0) 1 }" }.joined(separator: "\n") + "\nEND\n"),
            ("arcs", "A-MIB DEFINITIONS ::= BEGIN\nIMPORTS enterprises FROM SNMPv2-SMI;\nlong OBJECT IDENTIFIER ::= { enterprises " + (0..<100_000).map { String($0 % 50) }.joined(separator: " ") + " }\nEND\n"),
            ("junk", String(repeating: "::= } { ( ) ; , .. -- \"\n", count: 40_000)),
        ]
        for (name, text) in cases {
            let t0 = Date()
            let results = MIBParser.parseModules(text, fileName: name)
            let idx = MIBIndex.build(results.map { MIBParsedFile(result: $0, url: nil, builtIn: false) })
            let dt = Date().timeIntervalSince(t0)
            XCTAssertWithinBudget(dt, 3.0, name)
            for r in results { XCTAssertLessThanOrEqual(r.errors.count, 201, name) }
            for m in idx.modules { XCTAssertLessThanOrEqual(m.missingImports.count, 101, name) }
            for r in results { XCTAssertTrue(r.errors.allSatisfy { $0.utf8.count < 400 }, name) }
        }
    }

    /// 2,000 random mutations of a real MIB: every parse ends quickly and never crashes.
    func testFuzzedMIBsParseQuickly() throws {
        let url = try XCTUnwrap(MIBTests.bundledURLs().first { $0.lastPathComponent == "SNMPv2-MIB.mib" })
        let base = Array(try Data(contentsOf: url))
        var rng = SystemRandomNumberGenerator()
        let alphabet = Array("{}()[];,.:=-\"' \n\tabcXYZ019".utf8)
        var worst = 0.0
        for i in 0..<2_000 {
            var b = base
            for _ in 0..<Int.random(in: 1...20, using: &rng) {
                let p = Int.random(in: 0..<b.count, using: &rng)
                switch Int.random(in: 0..<4, using: &rng) {
                case 0: b[p] = alphabet.randomElement(using: &rng)!
                case 1: b.remove(at: p)
                case 2: b.insert(alphabet.randomElement(using: &rng)!, at: p)
                default:
                    let q = min(b.count, p + Int.random(in: 1...200, using: &rng))
                    b.replaceSubrange(p..<q, with: b[p..<q].reversed())
                }
            }
            if i % 50 == 0 { b = Array(b.prefix(Int.random(in: 0...b.count, using: &rng))) }
            let t0 = Date()
            let r = MIBParser.parseModules(String(decoding: b, as: UTF8.self), fileName: "fuzz")
            _ = MIBIndex.build(r.map { MIBParsedFile(result: $0, url: nil, builtIn: false) })
            worst = max(worst, Date().timeIntervalSince(t0))
        }
        print("[round3] slowest fuzzed MIB parse+link: \(String(format: "%.1f", worst * 1000)) ms")
        XCTAssertWithinBudget(worst, 0.2)
    }
}

// MARK: - Capture

final class HostileCaptureTests: XCTestCase {
    private func tempFile(_ name: String) -> URL {
        FileManager.default.temporaryDirectory.appending(path: "sheeplog-r3-\(UUID().uuidString)-\(name)")
    }

    private func le32(_ v: UInt32) -> [UInt8] { [UInt8(v & 0xff), UInt8((v >> 8) & 0xff), UInt8((v >> 16) & 0xff), UInt8(v >> 24)] }
    private func le16(_ v: UInt16) -> [UInt8] { [UInt8(v & 0xff), UInt8(v >> 8)] }

    private func pcapHeader(snaplen: UInt32, linkType: UInt32 = 1) -> [UInt8] {
        le32(0xa1b2c3d4) + le16(2) + le16(4) + le32(0) + le32(0) + le32(snaplen) + le32(linkType)
    }

    private func record(caplen: UInt32, len: UInt32, data: [UInt8]) -> [UInt8] {
        le32(1_700_000_000) + le32(0) + le32(caplen) + le32(len) + data
    }

    /// A header claiming a 2 GB packet (and one claiming more than the bytes that follow):
    /// libpcap refuses it; the packets before it are kept; nothing crashes or allocates 2 GB.
    func testHugeCaplenIsRefused() throws {
        let frame = [UInt8](repeating: 0x11, count: 60)
        for bogus in [UInt32(0x8000_0000), 0xFFFF_FFFF, 300_000] {
            let url = tempFile("caplen.pcap")
            defer { try? FileManager.default.removeItem(at: url) }
            try Data(pcapHeader(snaplen: 0xFFFF_FFFF) + record(caplen: 60, len: 60, data: frame)
                     + record(caplen: bogus, len: bogus, data: frame)).write(to: url)
            var got = 0
            XCTAssertThrowsError(try PcapFile.read(url) { got += $0.count }, "caplen \(bogus)")
            XCTAssertEqual(got, 1)
        }
    }

    /// snaplen 0xFFFFFFFF in the file header is clamped by libpcap; normal records still read.
    func testHugeSnaplenHeaderReads() throws {
        let url = tempFile("snap.pcap")
        defer { try? FileManager.default.removeItem(at: url) }
        let frame = [UInt8](repeating: 0x22, count: 60)
        try Data(pcapHeader(snaplen: 0xFFFF_FFFF) + record(caplen: 60, len: 60, data: frame) + record(caplen: 60, len: 9000, data: frame)).write(to: url)
        var got: [Packet] = []
        _ = try PcapFile.read(url) { got += $0 }
        XCTAssertEqual(got.map(\.captured), [60, 60])
        XCTAssertEqual(got.last?.length, 9000)
    }

    /// 300,000 one-byte packets: the reader hands over batches as it goes (never an array of
    /// the whole file first).
    func testManyTinyPacketsStreamInBatches() throws {
        let url = tempFile("tiny.pcap")
        defer { try? FileManager.default.removeItem(at: url) }
        var d = Data(pcapHeader(snaplen: 65_535))
        let rec = Data(record(caplen: 1, len: 1, data: [0x42]))
        d.reserveCapacity(d.count + rec.count * 300_000)
        for _ in 0..<300_000 { d.append(rec) }
        try d.write(to: url)
        var batches = 0, total = 0, largest = 0
        _ = try PcapFile.read(url) { b in batches += 1; total += b.count; largest = max(largest, b.count) }
        XCTAssertEqual(total, 300_000)
        XCTAssertLessThanOrEqual(largest, PcapFile.batchSize)
        XCTAssertGreaterThan(batches, 50)
    }

    func testBadCaptureFilters() {
        XCTAssertNil(CaptureEngine.filterError("tcp port 443 and not host 10.0.0.1"))
        XCTAssertNotNil(CaptureEngine.filterError("((tcp port 443"))
        XCTAssertNotNil(CaptureEngine.filterError("tcp port 443))"))
        XCTAssertNotNil(CaptureEngine.filterError(String(repeating: "(", count: 8_000)))
        // libpcap's optimiser took 15 s on 700 `or`ed hosts (13 KB) — the compile runs on the
        // main thread when a capture starts. Too long is refused; long is compiled unoptimised.
        let tooLong = (0..<700).map { "host 10.0.\($0 / 250).\($0 % 250)" }.joined(separator: " or ")
        XCTAssertTrue(CaptureEngine.filterError(tooLong)?.contains("too long") ?? false)
        let long = (0..<440).map { "host 10.0.\($0 / 250).\($0 % 250)" }.joined(separator: " or ")
        XCTAssertLessThanOrEqual(long.utf8.count, CaptureEngine.maxFilterLength)
        let t0 = Date()
        XCTAssertNil(CaptureEngine.filterError(long))
        XCTAssertWithinBudget(Date().timeIntervalSince(t0), 1.5)
        XCTAssertNotNil(CaptureEngine.filterError(String(repeating: "x", count: 70_000)))
    }

    // MARK: Decoder

    private typealias F = PacketFixture

    /// A DNS answer whose name is a compression pointer to itself, and a two-pointer loop.
    func testDNSPointerLoopsEnd() {
        let selfLoop = F.be16(0x1234) + [0x81, 0x80] + F.be16(1) + F.be16(1) + F.be16(0) + F.be16(0)
            + [0xc0, 0x0c] + F.be16(1) + F.be16(1)
            + [0xc0, 0x0c] + F.be16(1) + F.be16(1) + F.be32(1) + F.be16(4) + [1, 2, 3, 4]
        let twoLoop = F.be16(0x1234) + [0x81, 0x80] + F.be16(1) + F.be16(0) + F.be16(0) + F.be16(0)
            + [0xc0, 0x0e, 0xc0, 0x0c] + F.be16(1) + F.be16(1)
        for payload in [selfLoop, twoLoop] {
            let d = PacketDecoder.decode(F.udp4(src: "10.0.0.53", dst: "10.0.0.9", 53, 40000, payload))
            XCTAssertFalse(d.info.isEmpty)
        }
    }

    /// TLS ClientHello whose extension lengths point far past the record.
    func testTLSExtensionLengthOverflow() {
        var body: [UInt8] = [0x03, 0x03] + [UInt8](repeating: 7, count: 32) + [0] + F.be16(2) + [0x13, 0x01] + [1, 0]
        body += F.be16(0xFFFF) + F.be16(0) + F.be16(0xFFF0) + [0, 0xFF, 0]       // SNI with a 65,520-byte claim
        let hs = [0x01] + F.be24(0xFFFFFF) + body
        let rec = [0x16, 0x03, 0x01] + F.be16(0xFFFF) + hs
        let d = PacketDecoder.decode(F.tcp4(49152, 443, seq: 1, ack: 1, flags: 0x18, rec))
        XCTAssertEqual(d.tcp?.destinationPort, 443)
    }

    /// An IPv6 packet with 1,000 chained extension headers: the walk stops early.
    func testIPv6ExtensionHeaderChain() {
        var ext: [UInt8] = []
        for _ in 0..<1_000 { ext += [0, 0, 0, 0, 0, 0, 0, 0] }          // hop-by-hop → hop-by-hop …
        ext += F.udp(1, 2, [1, 2, 3])
        let v6 = F.ipv6(src: [UInt8](repeating: 0xfe, count: 16), dst: [UInt8](repeating: 0x20, count: 16), next: 0, ext)
        let t0 = Date()
        let d = PacketDecoder.decode(Data(F.ether(type: 0x86DD, v6)))
        XCTAssertWithinBudget(Date().timeIntervalSince(t0), 0.05)
        XCTAssertNotNil(d.ip)
    }

    /// 1,000,000 random buffers (Release only; Debug runs 50,000).
    func testDecoderMillionRandomBuffers() {
        #if DEBUG
        let n = 50_000
        #else
        let n = 1_000_000
        #endif
        var rng = SystemRandomNumberGenerator()
        let seeds = F.all()
        var buf = [UInt8](repeating: 0, count: 2_048)
        let t0 = Date()
        for i in 0..<n {
            let count: Int
            if i & 1 == 0, let s = seeds.randomElement(using: &rng) {
                count = min(buf.count, s.count)
                s.copyBytes(to: &buf, count: count)
                for _ in 0..<Int.random(in: 1...8, using: &rng) { buf[Int.random(in: 0..<count, using: &rng)] = UInt8.random(in: 0...255, using: &rng) }
            } else {
                count = Int.random(in: 0...256, using: &rng)
                for k in 0..<count { buf[k] = UInt8.random(in: 0...255, using: &rng) }
            }
            let lt: Int32 = [1, 0, 113, 12, 101][i % 5]
            _ = buf.withUnsafeBytes { PacketDecoder.decode(UnsafeRawBufferPointer(rebasing: $0[0..<count]), linkType: lt) }
        }
        print("[round3] \(n) random buffers decoded in \(String(format: "%.2f", Date().timeIntervalSince(t0))) s")
    }

    // MARK: Flows

    /// 1,000,000 packets of one 4-tuple with random sequence numbers (Release; Debug 100,000):
    /// bounded time, bounded events.
    func testFlowAnalysisOfRandomSequenceStorm() {
        #if DEBUG
        let n = 100_000
        let budget = 8.0
        #else
        let n = 1_000_000
        let budget = 3.0
        #endif
        var rng = SystemRandomNumberGenerator()
        var packets: [Packet] = []
        packets.reserveCapacity(n)
        for i in 0..<n {
            let c2s = Bool.random(using: &rng)
            packets.append(TCPFlowDemo.packet(id: i + 1, t: Double(i) * 0.00001,
                                              src: c2s ? "10.0.0.1" : "10.0.0.2", sport: c2s ? 40000 : 443,
                                              dst: c2s ? "10.0.0.2" : "10.0.0.1", dport: c2s ? 443 : 40000,
                                              flags: [.ack, .psh], seq: UInt32.random(in: 0...UInt32.max, using: &rng),
                                              ack: UInt32.random(in: 0...UInt32.max, using: &rng), len: Int.random(in: 0...1400, using: &rng)))
        }
        let t0 = Date()
        let flows = TCPFlowAnalyzer.analyze(packets)
        let dt = Date().timeIntervalSince(t0)
        print("[round3] \(n) random-seq packets analysed in \(String(format: "%.2f", dt)) s, \(flows.first?.events.count ?? 0) events")
        XCTAssertEqual(flows.count, 1)
        XCTAssertWithinBudget(dt, budget)
        XCTAssertLessThanOrEqual(flows.first?.events.count ?? 0, TCPFlowAnalyzer.maxEvents + 1)
    }
}
