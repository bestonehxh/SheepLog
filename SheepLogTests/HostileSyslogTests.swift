import Darwin
import XCTest
@testable import SheepLog

/// Round 3: every received byte is hostile. The parser, the store, the listener and the disk
/// logger must bound their cost and never pass a sender's control characters on.
@MainActor
final class HostileSyslogTests: XCTestCase {
    // MARK: - Parser

    /// ESC sequences, NUL, BEL, backspace and C1 CSI in a message are shown as U+FFFD; tab and
    /// line breaks stay; `raw` keeps the bytes as received.
    func testControlCharactersAreNeutralisedForDisplay() {
        let text = "<13>Sep 23 10:15:32 h app: a\u{1B}[31mred\u{1B}[0m\u{07}\u{08}\u{00}b\tc\u{9B}2Jd\ne"
        let e = parsedLine(text)
        XCTAssertEqual(e.raw, text)
        XCTAssertFalse(e.message.unicodeScalars.contains { $0.value == 0x1B || $0.value == 0x07 || $0.value == 0x08 || $0.value == 0 || $0.value == 0x9B })
        XCTAssertTrue(e.message.contains("\t"))
        XCTAssertTrue(e.message.contains("\n"))
        XCTAssertTrue(e.message.contains("\u{FFFD}[31mred"))
    }

    /// A 5424 HOSTNAME of 10,000 characters, one with a bidi override, one that is `../../etc`.
    func testHostnameIsCappedAndCleaned() {
        let long = parsedLine("<13>1 2026-09-23T10:15:32Z \(String(repeating: "h", count: 10_000)) app - - - msg")
        XCTAssertLessThanOrEqual(long.hostname.utf8.count, 255)
        let rtl = parsedLine("<13>1 2026-09-23T10:15:32Z evil\u{202E}moc.knab app - - - msg")
        XCTAssertFalse(rtl.hostname.unicodeScalars.contains { $0.value == 0x202E })
        let zw = parsedLine("<13>1 2026-09-23T10:15:32Z co\u{200B}re app\u{1B}x - - - msg")
        XCTAssertFalse(zw.hostname.unicodeScalars.contains { $0.value == 0x200B })
        XCTAssertFalse(zw.program.unicodeScalars.contains { $0.value == 0x1B })
        // A path-looking hostname is only text (nothing is ever derived from it on disk).
        XCTAssertEqual(parsedLine("<13>1 2026-09-23T10:15:32Z ../../etc app - - - msg").hostname, "../../etc")
        XCTAssertLessThanOrEqual(parsedLine("<13>1 2026-09-23T10:15:32Z h \(String(repeating: "p", count: 5000)) - - - msg").program.utf8.count, 128)
    }

    func testInvalidUTF8AndEmbeddedNULs() {
        let bytes: [UInt8] = Array("<13>Sep 23 10:15:32 h app: ".utf8) + [0xFF, 0xFE, 0x00, 0xC3, 0x28, 0x41]
        let text = bytes.withUnsafeBufferPointer { SyslogFraming.decode($0) }
        let e = parsedLine(text)
        XCTAssertFalse(e.message.unicodeScalars.contains { $0.value == 0 })
        XCTAssertTrue(e.message.hasSuffix("A"))
    }

    /// A 64 KB line of `a=1 ` would make 16,000 fields.
    func testFieldsPerLineAreCapped() {
        let e = parsedLine("<13>Sep 23 10:15:32 h app: " + String(repeating: "a=1 ", count: 16_000))
        XCTAssertLessThanOrEqual(e.fields.count, DisplayText.maxFields + 1)
        XCTAssertEqual(e.fields.last?.key, "truncated_fields")
    }

    /// Every vendor detector and field extractor on 64 KB pathological lines: linear, not
    /// quadratic (< 5 ms each optimised; Debug is ~10× slower).
    func testVendorParsersOnPathologicalLinesAreLinear() {
        let n = 65_000
        let bodies: [(String, String)] = [
            ("semicolons", String(repeating: ";", count: n)),
            ("equals", String(repeating: "=", count: n)),
            ("key=value;", "a=b;" + String(repeating: "k=v;", count: n / 4) + "product=x"),
            ("quotes", String(repeating: "\"", count: n)),
            ("key=\"", String(repeating: "k=\"", count: n / 3)),
            ("Common.", " " + String(repeating: "Common.", count: n / 7)),
            (",Common.x", String(repeating: ",Common.x", count: n / 9)),
            ("Common.k=", "Common.k=" + String(repeating: ",", count: n)),
            ("CPPM", "CPPM_x 1 2 3 " + String(repeating: "Ab Cd Ef ", count: n / 9)),
            ("%%", String(repeating: "%%01", count: n / 4)),
            ("parens", "%%01IFNET/4/X(l)[1]:" + String(repeating: "(", count: n) + ")"),
            ("paren keys", "%%01IFNET/4/X(l)[1]:(" + String(repeating: "a=b, ", count: n / 5) + ")"),
            ("brackets", String(repeating: "[", count: n)),
            ("cp brackets", "[" + String(repeating: "k:\"v\"; ", count: n / 7) + "]"),
            ("cp nested", "[k:" + String(repeating: "[", count: n) + "]"),
            ("bars", "Event|" + String(repeating: "|", count: n)),
            ("palo", "1," + String(repeating: ",", count: n)),
            ("palo quotes", "1,2,3,TRAFFIC,end," + String(repeating: "\",", count: n / 2)),
            ("aos8", "<123456> <WARN> <" + String(repeating: ">", count: n)),
            ("lt", String(repeating: "<", count: n)),
            ("aoss", "12345 " + String(repeating: "a", count: n) + ":"),
            ("forti", "logid= type= devid= " + String(repeating: "x=\"\\", count: n / 4)),
            ("spaces", String(repeating: " ", count: n)),
            ("digits", String(repeating: "7", count: n)),
        ]
        var worst = (name: "", ms: 0.0)
        for (name, body) in bodies {
            for text in [body, "<13>Sep 23 10:15:32 host app: " + body, "<13>1 2026-09-23T10:15:32Z h a - - - " + body] {
                for vendor in [nil] + Vendor.allCases.map(Optional.some) {
                    let t0 = clock_gettime_nsec_np(CLOCK_UPTIME_RAW)
                    _ = parsedLine(text, from: "10.0.0.1", vendor: vendor)
                    let ms = Double(clock_gettime_nsec_np(CLOCK_UPTIME_RAW) - t0) / 1e6
                    if ms > worst.ms { worst = ("\(name) as \(vendor.map { "\($0)" } ?? "auto")", ms) }
                }
            }
        }
        #if DEBUG
        let limit = 60.0
        #else
        let limit = 5.0
        #endif
        print("[round3] slowest 64 KB vendor parse: \(worst.name) \(String(format: "%.2f", worst.ms)) ms")
        XCTAssertWithinBudget(worst.ms, limit, "slowest: \(worst.name) \(worst.ms) ms")
    }

    // MARK: - Store

    /// 64 KB datagrams: memory is bounded by `byteBudget`, not only by the line count.
    func testStoreEvictsByBytes() {
        let saved = LogStore.byteBudget
        LogStore.byteBudget = 8 * 1024 * 1024
        defer { LogStore.byteBudget = saved }
        let store = LogStore()
        store.limit = 100_000
        let big = "<13>Sep 23 10:15:32 h app: " + String(repeating: "x", count: 60_000)
        for _ in 0..<10 {
            let first = LogStore.reserveIDs(100)
            store.ingest((0..<100).map { parsedLine(big, from: "10.0.0.1", id: first + $0) })
        }
        XCTAssertLessThanOrEqual(store.entryBytes, LogStore.byteBudget)
        XCTAssertLessThan(store.entries.count, 100)
        XCTAssertGreaterThan(store.entries.count, 10)
        XCTAssertEqual(store.totalReceived, store.entries.count + store.dropped)
        XCTAssertEqual(store.severityCounts.reduce(0, +), store.entries.count)
    }

    /// 60,000 spoofed source addresses: the Sources table stops growing at `maxSources`, the
    /// lines are all kept, and ingest stays fast.
    func testSpoofedSourceFloodIsBounded() {
        let store = LogStore()
        store.limit = 100_000
        let t0 = Date()
        for chunk in 0..<12 {
            let first = LogStore.reserveIDs(5_000)
            let batch = (0..<5_000).map { k -> LogEntry in
                let i = chunk * 5_000 + k
                return parsedLine("<13>x", from: "10.\(i >> 16).\((i >> 8) & 255).\(i & 255)", id: first + k)
            }
            store.ingest(batch)
        }
        store.publishSources()
        XCTAssertWithinBudget(Date().timeIntervalSince(t0), 5)
        XCTAssertEqual(store.sources.count, LogStore.maxSources)
        XCTAssertEqual(store.untrackedSources, 60_000 - LogStore.maxSources)
        XCTAssertEqual(store.entries.count, 60_000)
    }

    func testBacklogGate() {
        let g = BacklogGate(slots: 2)
        XCTAssertTrue(g.tryEnter(count: 10))
        XCTAssertTrue(g.tryEnter(count: 10))
        XCTAssertFalse(g.tryEnter(count: 7))
        XCTAssertFalse(g.tryEnter(count: 3))
        XCTAssertEqual(g.leave(), 10)
        XCTAssertTrue(g.tryEnter(count: 1))
        XCTAssertEqual(g.leave(), 0)
        XCTAssertEqual(g.droppedTotal, 10)
    }

    /// A listener whose consumer never catches up keeps at most `slots` batches in flight and
    /// counts the rest as dropped.
    func testListenerDropsWhenTheMainThreadIsBehind() throws {
        let port = TestSockets.freePort()
        guard case .success(let u) = SocketFactory.bind(type: SOCK_DGRAM, port: port) else { return XCTFail("bind") }
        let gate = BacklogGate(slots: 2)
        let got = LockedBox(0)
        let l = SyslogListener(overrides: VendorOverrideMap(), deliver: { b in got.mutate { $0 += b.count } },
                               clientsChanged: { _ in }, gate: gate)
        l.start(udpFD: u, tcpFD: -1)
        defer { l.stop() }
        for _ in 0..<5 {
            TestSockets.sendUDP(Array(repeating: "<13>Sep 23 10:15:32 h app: flood", count: 200), to: port)
            usleep(200_000)          // one flush per round
        }
        XCTAssertLessThanOrEqual(gate.batchesInFlight, 2)
        XCTAssertGreaterThan(gate.droppedTotal, 0)
        XCTAssertEqual(got.value + gate.droppedTotal, 1_000, "every datagram delivered or counted")
    }

    // MARK: - TCP limits

    /// Reads until the peer closes (0) or the timeout; true when it was closed.
    private func closedByPeer(_ fd: Int32, within seconds: Double) -> Bool {
        var tv = timeval(tv_sec: 0, tv_usec: 50_000)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        let end = Date().addingTimeInterval(seconds)
        var b = [UInt8](repeating: 0, count: 64)
        while Date() < end {
            let n = recv(fd, &b, b.count, 0)
            if n == 0 { return true }
            if n < 0, errno != EAGAIN, errno != EWOULDBLOCK, errno != EINTR { return true }
        }
        return false
    }

    /// Slowloris: bytes trickle in but no message ever completes — disconnected after
    /// `idleTimeout`. A client that completes messages stays.
    func testStalledTCPClientIsDisconnected() throws {
        let port = TestSockets.freePort()
        guard case .success(let t) = SocketFactory.bind(type: SOCK_STREAM, port: port) else { return XCTFail("bind") }
        let got = LockedBox<[String]>([])
        let l = SyslogListener(overrides: VendorOverrideMap(), deliver: { b in got.mutate { $0 += b.map(\.message) } },
                               clientsChanged: { _ in })
        l.idleTimeout = 0.6
        l.silentTimeout = 60
        l.start(udpFD: -1, tcpFD: t)
        defer { l.stop() }
        let slow = try XCTUnwrap(TestSockets.connectTCP(port)), good = try XCTUnwrap(TestSockets.connectTCP(port))
        defer { close(slow); close(good) }
        for k in 0..<8 {
            _ = send(slow, "x", 1, 0)                                         // no newline, ever
            let msg = Array("<13>Sep 23 10:15:32 h app: ok \(k)\n".utf8)
            _ = msg.withUnsafeBytes { send(good, $0.baseAddress, msg.count, 0) }
            usleep(150_000)
        }
        XCTAssertTrue(closedByPeer(slow, within: 1.0), "the stalled client must be disconnected")
        XCTAssertEqual(l.clientCount, 1)
        XCTAssertGreaterThanOrEqual(got.value.count, 7)
        XCTAssertFalse(got.value.contains { $0.contains("xxxx") }, "the stalled partial line is not logged")
    }

    /// Past `maxClients`, connections are refused at once and the limit is reported once;
    /// UDP keeps working.
    func testTCPClientCapKeepsUDPServing() throws {
        let port = TestSockets.freePort()
        guard case .success(let u) = SocketFactory.bind(type: SOCK_DGRAM, port: port),
              case .success(let t) = SocketFactory.bind(type: SOCK_STREAM, port: port) else { return XCTFail("bind") }
        let got = LockedBox<[String]>([])
        let reported = LockedBox(0)
        let l = SyslogListener(overrides: VendorOverrideMap(), deliver: { b in got.mutate { $0 += b.map(\.message) } },
                               clientsChanged: { _ in })
        l.maxClients = 5
        l.onClientLimit = { _ in reported.mutate { $0 += 1 } }
        l.start(udpFD: u, tcpFD: t)
        defer { l.stop() }
        var fds: [Int32] = []
        defer { fds.forEach { close($0) } }
        for _ in 0..<40 { if let fd = TestSockets.connectTCP(port) { fds.append(fd) } }
        usleep(300_000)
        XCTAssertEqual(l.clientCount, 5)
        XCTAssertEqual(l.refusedCount, 35)
        XCTAssertEqual(reported.value, 1)
        // UDP still arrives.
        TestSockets.sendUDP(["<13>Sep 23 10:15:32 h app: udp alive"], to: port)
        let end = Date().addingTimeInterval(2)
        while Date() < end, !got.value.contains("udp alive") { usleep(20_000) }
        XCTAssertTrue(got.value.contains("udp alive"))
    }

    /// Many clients each holding a big unterminated line share `partialBudget`.
    func testPartialLinesShareAMemoryBudget() throws {
        let port = TestSockets.freePort()
        guard case .success(let t) = SocketFactory.bind(type: SOCK_STREAM, port: port) else { return XCTFail("bind") }
        let got = LockedBox<[String]>([])
        let l = SyslogListener(overrides: VendorOverrideMap(), deliver: { b in got.mutate { $0 += b.map(\.message) } },
                               clientsChanged: { _ in })
        l.partialBudget = 1_000_000
        l.start(udpFD: -1, tcpFD: t)
        defer { l.stop() }
        var fds: [Int32] = []
        defer { fds.forEach { close($0) } }
        let chunk = [UInt8](repeating: 0x41, count: 400_000)
        for _ in 0..<4 {
            let fd = try XCTUnwrap(TestSockets.connectTCP(port))
            fds.append(fd)
            var sent = 0
            while sent < chunk.count {
                let n = chunk.withUnsafeBytes { send(fd, $0.baseAddress! + sent, chunk.count - sent, 0) }
                if n <= 0 { break }
                sent += n
            }
        }
        usleep(300_000)
        // Every client then finishes its line and sends a good one.
        for (k, fd) in fds.enumerated() {
            let tail = Array("\n<13>Sep 23 10:15:32 h app: after \(k)\n".utf8)
            _ = tail.withUnsafeBytes { send(fd, $0.baseAddress, tail.count, 0) }
        }
        let end = Date().addingTimeInterval(3)
        while Date() < end, got.value.filter({ $0.hasPrefix("after") }).count < 4 { usleep(20_000) }
        XCTAssertEqual(got.value.filter { $0.hasPrefix("after") }.count, 4)
        XCTAssertLessThan(got.value.filter { $0.hasPrefix("AAAA") }.count, 4, "at least one partial line was dropped")
    }

    func testDescriptorLimitIsRaised() {
        var rl = rlimit()
        getrlimit(RLIMIT_NOFILE, &rl)
        let saved = rl
        defer { var r = saved; setrlimit(RLIMIT_NOFILE, &r) }
        rl.rlim_cur = 256
        setrlimit(RLIMIT_NOFILE, &rl)
        let now = SocketFactory.raiseDescriptorLimit()
        XCTAssertGreaterThanOrEqual(now, min(4_096, Int(clamping: saved.rlim_max)))
    }

    // MARK: - Disk

    private func tempDir() -> URL {
        FileManager.default.temporaryDirectory.appending(path: "sheeplog-r3-\(UUID().uuidString)")
    }

    private func entries(_ texts: [String]) -> [LogEntry] {
        texts.enumerated().map { parsedLine($1).withID($0) }
    }

    /// ESC, NUL, BEL, CR, LF, DEL and the C1 CSI are written as `#ooo`; tab stays; the file is
    /// 0600 and every entry is exactly one line.
    func testDiskLinesAreEscapedAndPrivate() throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let logger = DiskLogger(directory: dir)
        logger.append(entries(["<13>h app: a\u{1B}[2Jb\u{00}c\u{07}d\re\nf\tg\u{7F}h\u{9B}31mi"]))
        logger.close()
        let file = try XCTUnwrap(logger.currentFile)
        let text = try String(contentsOf: file, encoding: .utf8)
        XCTAssertEqual(text.filter { $0 == "\n" }.count, 1)
        XCTAssertTrue(text.contains("a#033[2Jb#000c#007d#015e#012f\tg#177h#23331mi"), text)
        XCTAssertFalse(text.unicodeScalars.contains { $0.value < 0x20 && $0 != "\n" && $0 != "\t" })
        let mode = try XCTUnwrap(FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? Int)
        XCTAssertEqual(mode & 0o777, 0o600)
        XCTAssertEqual(LogStore.exportText(entries(["<13>h app: x\u{1B}y"])), "<13>h app: x#033y\n")
    }

    /// The folder removed while logging: re-created, later lines land in the new file.
    func testDiskLoggerRecreatesARemovedFolder() throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let logger = DiskLogger(directory: dir)
        logger.append(entries(["<13>h app: before"]))
        logger.sync()
        try FileManager.default.removeItem(at: dir)
        Thread.sleep(forTimeInterval: 1.1)          // the identity check runs once a second
        logger.append(entries(["<13>h app: after"]))
        logger.close()
        let text = try String(contentsOf: logger.todaysFile, encoding: .utf8)
        XCTAssertTrue(text.contains("after"))
        XCTAssertFalse(text.contains("before"))
    }

    /// A symlink planted as today's file is not followed.
    func testDiskLoggerDoesNotFollowASymlink() throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let victim = dir.appending(path: "victim.txt")
        try "keep me\n".write(to: victim, atomically: true, encoding: .utf8)
        let logger = DiskLogger(directory: dir)
        try FileManager.default.createSymbolicLink(at: logger.todaysFile, withDestinationURL: victim)
        let errors = LockedBox<[String]>([])
        let l2 = DiskLogger(directory: dir) { m in errors.mutate { $0.append(m) } }
        l2.append(entries(["<13>h app: injected"]))
        l2.close()
        XCTAssertEqual(try String(contentsOf: victim, encoding: .utf8), "keep me\n")
        XCTAssertEqual(errors.value.count, 1)
    }

    /// `/`, a system folder, or a path that is a file: refused with one readable error.
    func testUnsuitableLogFoldersAreRefused() throws {
        XCTAssertNotNil(DiskLogger.unsuitableReason(URL(fileURLWithPath: "/")))
        XCTAssertNotNil(DiskLogger.unsuitableReason(URL(fileURLWithPath: "/System/Library")))
        XCTAssertNotNil(DiskLogger.unsuitableReason(URL(fileURLWithPath: "/etc")))
        XCTAssertNil(DiskLogger.unsuitableReason(FileManager.default.temporaryDirectory))
        XCTAssertNil(DiskLogger.unsuitableReason(URL(fileURLWithPath: NSHomeDirectory()).appending(path: "Library/Logs/SheepLog")))
        let file = FileManager.default.temporaryDirectory.appending(path: "sheeplog-file-\(UUID().uuidString)")
        try "x".write(to: file, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: file) }
        let errors = LockedBox<[String]>([])
        let logger = DiskLogger(directory: file) { m in errors.mutate { $0.append(m) } }
        for _ in 0..<50 { logger.append(entries(["<13>h app: x"])) }
        logger.sync()
        XCTAssertEqual(errors.value.count, 1, "one report, not one per batch")
        XCTAssertTrue(errors.value.first?.contains("is a file") ?? false, errors.value.first ?? "")
    }

    /// A write that fails (here: RLIMIT_FSIZE, standing in for a full disk) is reported once,
    /// not per batch.
    func testWriteFailureIsReportedOnce() throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let errors = LockedBox<[String]>([])
        let logger = DiskLogger(directory: dir) { m in errors.mutate { $0.append(m) } }
        logger.append(entries(["<13>h app: first"]))
        logger.sync()
        let oldHandler = signal(SIGXFSZ, SIG_IGN)
        var rl = rlimit()
        getrlimit(RLIMIT_FSIZE, &rl)
        let saved = rl
        rl.rlim_cur = 4_096
        setrlimit(RLIMIT_FSIZE, &rl)
        for _ in 0..<50 { logger.append(entries([String(repeating: "y", count: 1_000)])) }
        logger.sync()
        var r = saved
        setrlimit(RLIMIT_FSIZE, &r)
        signal(SIGXFSZ, oldHandler)
        logger.close()
        XCTAssertEqual(errors.value.count, 1, errors.value.joined(separator: "\n"))
    }
}

private extension LogEntry {
    func withID(_ id: Int) -> LogEntry {
        LogEntry(id: id, received: received, deviceTime: deviceTime, sourceAddress: sourceAddress, sourcePort: sourcePort,
                 transport: transport, facility: facility, severity: severity, priority: priority, hostname: hostname,
                 program: program, pid: pid, message: message, raw: raw, vendor: vendor, fields: fields)
    }
}

extension HostileSyslogTests {
    /// A device's last message is usually the one that matters: a TCP line still without its
    /// newline when the listener stops (⌘Q, switch off) is delivered as it stands.
    func testUnterminatedTCPLineIsDeliveredOnStop() throws {
        let port = TestSockets.freePort()
        guard case .success(let t) = SocketFactory.bind(type: SOCK_STREAM, port: port) else { return XCTFail("bind") }
        let got = LockedBox<[String]>([])
        let l = SyslogListener(overrides: VendorOverrideMap(), deliver: { b in got.mutate { $0 += b.map(\.message) } },
                               clientsChanged: { _ in })
        l.start(udpFD: -1, tcpFD: t)
        let c = try XCTUnwrap(TestSockets.connectTCP(port))
        defer { close(c) }
        let msg = Array("<13>Sep 23 10:15:32 h app: the last words before quit".utf8)   // no newline
        _ = msg.withUnsafeBytes { send(c, $0.baseAddress, msg.count, 0) }
        usleep(200_000)
        XCTAssertTrue(got.value.isEmpty, "not delivered while the line is still open")
        l.stop()
        SyslogListener.waitForParser()        // (round 19: stop hands the last batch to the parser)
        XCTAssertTrue(got.value.contains { $0.contains("the last words before quit") },
                      "stop() delivers the unterminated line: \(got.value)")
    }
}
