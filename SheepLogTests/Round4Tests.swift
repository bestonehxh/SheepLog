import AppKit
import Darwin
import XCTest
@testable import SheepLog

/// Round 4 (cold review): the defects found by following an engineer's week — long runs, a Thai
/// calendar, a flood at ⌘Q, traps at launch, odd Settings values, a customer's pcap saved back.
@MainActor
final class Round4Tests: XCTestCase {
    private var model: AppModel { AppModel.shared }
    private var savedSettings = AppSettings()
    private var temp: URL!

    override func setUp() async throws {
        savedSettings = model.settings
        model.dismissAllErrors()
        temp = FileManager.default.temporaryDirectory.appending(path: "SheepLogRound4-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: temp, withIntermediateDirectories: true)
    }

    override func tearDown() async throws {
        model.stopSyslog()
        model.stopTraps()
        model.settings = savedSettings
        model.dismissAllErrors()
        try? FileManager.default.removeItem(at: temp)
    }

    private func wait(_ seconds: Double = 10, until condition: () -> Bool) async {
        let end = Date().addingTimeInterval(seconds)
        while !condition(), Date() < end { try? await Task.sleep(for: .milliseconds(20)) }
    }

    private static func lines(in dir: URL) -> [String] {
        let files = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []
        return files.filter { $0.pathExtension == "log" }
            .flatMap { ((try? String(contentsOf: $0, encoding: .utf8)) ?? "").split(separator: "\n").map(String.init) }
    }

    // MARK: 1. Thai calendar: the Packets Save name

    /// A plain `DateFormatter` follows the Mac's calendar: on a Thai (Buddhist) Mac the proposed
    /// file name was `SheepLog-25690924-….pcap`.
    func testPcapSaveNameHasGregorianDigits() throws {
        var c = DateComponents()
        c.calendar = Calendar(identifier: .gregorian)
        c.timeZone = .current
        (c.year, c.month, c.day, c.hour, c.minute, c.second) = (2026, 9, 24, 8, 15, 30)
        let date = try XCTUnwrap(c.date)
        XCTAssertEqual(PacketFileActions.saveName(date: date), "SheepLog-20260924-081530.pcap")
        // What the old code produced under a Buddhist calendar:
        let f = DateFormatter()
        f.calendar = Calendar(identifier: .buddhist)
        f.dateFormat = "yyyyMMdd-HHmmss"
        XCTAssertEqual(f.string(from: date), "25690924-081530")
    }

    // MARK: 2. The filter banner

    /// A notice (a regex that may be slow / was stopped) is about a filter that IS applied; the
    /// banner said "Filter not applied … Showing the last filter that worked".
    func testFilterBannerTellsANoticeFromAParseError() async {
        let store = LogStore()
        store.queryText = "/(a+)+$/"
        store.applyQueryText()
        XCTAssertTrue(store.queryErrorIsNotice)
        let notice = LogView.filterBanner(store.queryError ?? "", isNotice: store.queryErrorIsNotice)
        XCTAssertTrue(notice.hasPrefix("Filter applied"), notice)
        XCTAssertFalse(notice.contains("not applied"), notice)

        store.queryText = "(host:10.1"
        store.applyQueryText()
        XCTAssertFalse(store.queryErrorIsNotice)
        let error = LogView.filterBanner(store.queryError ?? "", isNotice: store.queryErrorIsNotice)
        XCTAssertTrue(error.hasPrefix("Filter not applied"), error)
    }

    // MARK: 3. Follow TCP stream on a reused 4-tuple

    /// The Flows pane put the frame of "Follow TCP stream" into the wrong variable: the request
    /// resolved with no frame, i.e. to the first conversation on that 4-tuple, and the ladder
    /// event of the right-clicked frame was never selected.
    func testFollowTCPStreamLandsOnTheConversationOfTheFrame() async throws {
        // Not on Flows: a Flows pane on screen takes the request itself (its .onReceive).
        model.mainPane = .status
        try? await Task.sleep(for: .milliseconds(300))
        var id = 1
        func p(_ t: Double, _ fromClient: Bool, _ f: TCPFlags, seq: UInt32, ack: UInt32, len: Int = 0) -> Packet {
            defer { id += 1 }
            return fromClient
                ? TCPFlowDemo.packet(id: id, t: t, src: "10.0.0.1", sport: 51000, dst: "10.0.0.2", dport: 443, flags: f,
                                     seq: seq, ack: ack, len: len, window: 65535, app: nil)
                : TCPFlowDemo.packet(id: id, t: t, src: "10.0.0.2", sport: 443, dst: "10.0.0.1", dport: 51000, flags: f,
                                     seq: seq, ack: ack, len: len, window: 65535, app: nil)
        }
        func conversation(_ t0: Double, isn: UInt32) -> [Packet] {
            [p(t0, true, .syn, seq: isn, ack: 0), p(t0 + 0.01, false, [.syn, .ack], seq: 9000, ack: isn &+ 1),
             p(t0 + 0.02, true, .ack, seq: isn &+ 1, ack: 9001), p(t0 + 0.03, true, [.psh, .ack], seq: isn &+ 1, ack: 9001, len: 50),
             p(t0 + 0.04, false, [.psh, .ack], seq: 9001, ack: isn &+ 51, len: 70),
             p(t0 + 0.05, true, [.fin, .ack], seq: isn &+ 51, ack: 9071), p(t0 + 0.06, false, [.fin, .ack], seq: 9071, ack: isn &+ 52),
             p(t0 + 0.07, true, .ack, seq: isn &+ 52, ack: 9072)]
        }
        let packets = conversation(0, isn: 1000) + conversation(5, isn: 777_000)
        let flows = TCPFlowAnalyzer.analyze(packets)
        XCTAssertEqual(flows.count, 2)
        let second = try XCTUnwrap(flows.first { $0.firstPacketID == 9 })
        let frame = 12                                       // the server's data in the second one
        let key = second.key

        // Packets pane → AppModel (the Flows pane does not exist yet) → Flows pane.
        NotificationCenter.default.post(name: .sheepLogSelectFlow, object: FlowSelectRequest(key: key, packetID: frame))
        let request = try XCTUnwrap(model.takePendingFlowRequest())
        XCTAssertEqual(request.packetID, frame, "the frame travels with the key")
        let target = try XCTUnwrap(request.resolve(in: flows))
        XCTAssertEqual(target.flow.id, second.id, "the conversation the frame is in, not the first on the 4-tuple")
        let event = try XCTUnwrap(second.events.first { $0.id == target.eventID })
        XCTAssertTrue(event.packetIDs.contains(frame))
        // Without the frame (the old path) it was the first conversation.
        XCTAssertEqual(FlowSelectRequest(key: key, packetID: nil).resolve(in: flows)?.flow.firstPacketID, 1)
    }

    // MARK: 4. SNMP timeout / retries from Settings

    /// Settings' Retries is a free text field: 1,000,000 retries made Quick test against a
    /// silent firewall run for weeks, and Int.max overflowed `retries + 1` (a crash).
    func testSNMPRetriesAndTimeoutAreClamped() {
        let m = SNMPTestModel.shared
        let (t0, r0) = (m.timeout, m.retries)
        defer { m.timeout = t0; m.retries = r0 }
        m.retries = Int.max
        m.timeout = 1e12
        XCTAssertEqual(m.target.retries, 10)
        XCTAssertEqual(m.target.timeout, 60)
        m.timeout = -3
        m.retries = -1
        XCTAssertEqual(m.target.timeout, 0.2)
        XCTAssertEqual(m.target.retries, 0)
        m.timeout = .nan
        XCTAssertEqual(m.target.timeout, 2)
        // The result card's words for a timeout with an absurd target (was an overflow trap).
        let title = SNMPTestModel.title(for: .timeout, target: SNMPTarget(host: "10.0.0.1", port: 161, timeout: 2, retries: Int.max))
        XCTAssertTrue(title.contains("11 tries"), title)
        // A Recent entry from settings.json with an infinite timeout (Int(inf) trapped).
        let inf = SNMPTestModel.title(for: .timeout, target: SNMPTarget(host: "10.0.0.1", port: 161, timeout: .infinity, retries: 1))
        XCTAssertTrue(inf.contains("× 2 s"), inf)
        // Settings → the Test pane: clamped on the way.
        model.settings.snmpRetries = 1_000_000
        XCTAssertEqual(m.retries, 10)
        model.settings.snmpTimeout = 0
        XCTAssertEqual(m.timeout, 0.2)
    }

    // MARK: 5. Trap port = syslog port

    /// Both set to the same UDP port: the trap receiver's "already in use" sent the user
    /// hunting with lsof for "a second copy of SheepLog" — it is SheepLog's own syslog listener.
    func testTrapPortSameAsSyslogPortIsExplained() {
        let port = TestSockets.freePort()
        model.settings.syslogUDPPort = port
        model.settings.syslogTCPPort = 0
        model.settings.trapPort = port
        model.startSyslog()
        XCTAssertTrue(model.syslog.isRunning)
        model.dismissAllErrors()
        model.startTraps()
        XCTAssertFalse(model.traps.isRunning)
        let message = model.lastError ?? ""
        XCTAssertTrue(message.contains("SheepLog’s own syslog listener"), message)
        XCTAssertFalse((model.lastErrorDetail ?? "").contains("lsof"), model.lastErrorDetail ?? "")
        XCTAssertFalse((model.lastErrorDetail ?? "").contains("second copy"), model.lastErrorDetail ?? "")
        // Another program on the port still gets the lsof advice.
        XCTAssertNil(AppModel.ownPortClash("UDP port 162 is already in use (EADDRINUSE).", port: 162, heldBy: 514,
                                           starting: "SNMP trap receiver", holder: "syslog listener"))
    }

    // MARK: 6. Traps before the MIBs have loaded

    /// At launch the MIB registry parses on a background queue (seconds with a folder of vendor
    /// MIBs); a trap that arrived meanwhile kept a dotted OID as its program and dotted field
    /// names for good (`app:linkDown` and `f:ifIndex` never found it). It is named again, in
    /// place, once the load finishes.
    func testTrapsReceivedWhileMIBsLoadAreNamedAfterwards() async throws {
        let reg = MIBRegistry()
        reg.userFolderOverride = temp
        let store = LogStore()
        let traps = TrapReceiver(store: store)
        traps.registry = reg
        reg.loadAll()
        XCTAssertTrue(reg.isFirstLoadPending)
        let trap = SNMPTrap(received: Date(), sourceAddress: "10.1.0.1", sourcePort: 50000, version: .v2c,
                            community: "public", trapOID: OID([1, 3, 6, 1, 6, 3, 1, 1, 5, 3]), uptime: 12345, agentAddress: nil,
                            varBinds: [VarBind(OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 7]), .integer(7))])
        store.ingest([LogEntry.syslogBefore])
        traps.ingest([.trap(trap)])
        store.ingest([LogEntry.syslogAfter])
        let early = try XCTUnwrap(store.entries.first { $0.transport == .trap })
        XCTAssertEqual(early.program, "snmpModules.1.1.5.3", "named before the MIBs were there (only the seeded roots)")
        XCTAssertNil(early.field("ifIndex.7"))

        await wait(30) { !reg.isFirstLoadPending }
        XCTAssertFalse(reg.isFirstLoadPending)
        await store.settle()
        let named = try XCTUnwrap(store.entries.first { $0.transport == .trap })
        XCTAssertEqual(named.id, early.id)
        XCTAssertEqual(named.program, "linkDown")
        XCTAssertEqual(named.field("ifIndex.7"), "7")
        XCTAssertEqual(store.entries.map(\.transport), [.udp, .trap, .udp], "its place in the log is kept")
        XCTAssertEqual(store.visible.count, 3)
        XCTAssertEqual(store.visible[1].program, "linkDown")

        // After the load, traps are named at once and nothing is renamed.
        traps.ingest([.trap(trap)])
        XCTAssertEqual(store.entries.last?.program, "linkDown")
    }

    // MARK: 7. Disk logging: pause, floods, ⌘Q

    /// Pause in the Log pane holds lines back from the table only; the disk log keeps writing.
    func testPauseDoesNotPauseDiskLogging() {
        let store = LogStore()
        let logger = DiskLogger(directory: temp)
        store.diskLogger = logger
        store.paused = true
        store.ingest([LogEntry.line("x")])
        logger.sync()
        XCTAssertEqual(Self.lines(in: temp).count, 1)
        XCTAssertEqual(store.entries.count, 0)
        XCTAssertEqual(store.pausedCount, 1)
        logger.retire()
    }

    /// A flood the main thread cannot keep up with: the backlog gate drops whole batches before
    /// they reach `LogStore.ingest` — where disk logging used to happen, so those lines were in
    /// neither the table nor the file ("Every received line … appended to one file per day").
    /// The listener now hands every line to the disk first.
    func testDiskLogGetsTheLinesTheMainThreadNeverTook() throws {
        let port = TestSockets.freePort()
        guard case .success(let u) = SocketFactory.bind(type: SOCK_DGRAM, port: port) else { return XCTFail("bind") }
        let logger = DiskLogger(directory: temp)
        let sink = DiskSink()
        sink.logger = logger
        let gate = BacklogGate(slots: 1)
        let delivered = LockedBox(0)
        let l = SyslogListener(overrides: VendorOverrideMap(), deliver: { b in delivered.mutate { $0 += b.count } },
                               clientsChanged: { _ in }, gate: gate)          // never leaves: the main thread is "busy"
        l.rawSink = { raws in sink.append(raws) }
        l.start(udpFD: u, tcpFD: -1)
        for round in 0..<5 {
            TestSockets.sendUDP((0..<200).map { "<13>Sep 23 10:15:32 h app: flood \(round)-\($0)" }, to: port)
            usleep(200_000)
        }
        l.stop()                          // flushes what is batched (⌘Q does the same)
        SyslogListener.waitForParser()    // (round 19: parsed off the listener queue)
        logger.sync()
        XCTAssertGreaterThan(gate.droppedTotal, 0, "batches were dropped on the way to the main thread")
        XCTAssertEqual(delivered.value + gate.droppedTotal, 1_000)
        XCTAssertEqual(Self.lines(in: temp).count, 1_000, "every received line is on disk")
        logger.retire()
    }

    /// Through the real listener and store: each line is written once (the store no longer
    /// writes syslog lines the listener already wrote).
    func testSyslogLinesAreWrittenToDiskOnce() async throws {
        let port = TestSockets.freePort()
        let store = LogStore()
        let logger = DiskLogger(directory: temp)
        store.diskLogger = logger
        let server = SyslogServer(store: store)
        server.start(udpPort: port, tcpPort: 0)
        defer { server.stop() }
        XCTAssertTrue(server.isRunning, server.lastError ?? "")
        TestSockets.sendUDP((0..<10).map { "<13>Sep 23 10:15:32 h app: once \($0)" }, to: port)
        await wait { store.entries.count == 10 }
        XCTAssertEqual(store.entries.count, 10)
        logger.sync()
        XCTAssertEqual(Self.lines(in: temp).count, 10)
        // Traps (and anything else) still go through the store's writer.
        store.ingest([LogEntry.line("x")])
        logger.sync()
        XCTAssertEqual(Self.lines(in: temp).count, 11)
        logger.retire()
    }

    /// Disk logging turned off (or the folder changed) while a listener thread is mid-append:
    /// the old logger must not reopen its file afterwards.
    func testRetiredLoggerNeverReopens() {
        let logger = DiskLogger(directory: temp)
        logger.retire()
        logger.append(raws: [RawSyslog(received: Date(), sourceAddress: "10.0.0.1", sourcePort: 514, transport: .udp, text: "late")])
        logger.append([LogEntry.line("x")])
        logger.sync()
        XCTAssertEqual(Self.lines(in: temp).count, 0)
    }

    /// The log folder on a USB disk that was unplugged: the report said "permission denied"
    /// (creating /Volumes/<disk> is refused); it names the missing disk.
    func testLogFolderOnAMissingDiskIsReportedAsSuch() {
        let dir = URL(fileURLWithPath: "/Volumes/SheepLogNoSuchDisk-\(UUID().uuidString.prefix(6))/logs")
        XCTAssertNotNil(DiskLogger.missingVolume(dir))
        XCTAssertNil(DiskLogger.missingVolume(temp))
        XCTAssertNil(DiskLogger.missingVolume(URL(fileURLWithPath: "/Volumes/Macintosh HD/Users")), "a symlink to /")
        let reported = LockedBox<[String]>([])
        let logger = DiskLogger(directory: dir) { m in reported.mutate { $0.append(m) } }
        logger.append([LogEntry.line("x")])
        logger.sync()
        XCTAssertEqual(reported.value.count, 1)
        XCTAssertTrue(reported.value.first?.contains("is not connected") ?? false, reported.value.first ?? "")
        logger.retire()
    }

    // MARK: 8. Saving an opened capture

    /// Opened and saved again without a filter, a capture is the same file: libpcap reports the
    /// snapshot length clamped (262,144) and the copy's header said so instead of the file's
    /// 524,288 (tcpdump on macOS).
    func testSavingAnOpenedCaptureGivesTheSameBytes() async throws {
        let files = try FileManager.default.contentsOfDirectory(at: CaptureGroundTruthTests.pcapDir, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "pcap" }.sorted { $0.path < $1.path }
        XCTAssertGreaterThanOrEqual(files.count, 5)
        for url in files {
            let store = PacketStore()
            var done = false
            try store.load(from: url) { done = true }
            await wait { done }
            XCTAssertTrue(done)
            let out = temp.appending(path: url.lastPathComponent)
            try store.save(to: out)
            let a = try Data(contentsOf: url), b = try Data(contentsOf: out)
            XCTAssertEqual(a.count, b.count, url.lastPathComponent)
            XCTAssertTrue(a == b, "\(url.lastPathComponent): first difference at byte \(zip(a, b).enumerated().first { $0.element.0 != $0.element.1 }?.offset ?? -1)")
        }
        XCTAssertEqual(PcapFile.headerSnapLength(of: files[0]), 524_288)
    }

    /// Pause pressed during a live capture, then a customer's file opened: every packet went to
    /// the pause buffer and the table said "No packets … open a .pcap".
    func testOpeningAFileWhilePausedShowsIt() async throws {
        let store = PacketStore()
        store.paused = true
        let url = CaptureGroundTruthTests.pcapDir.appending(path: "dns-mdns.pcap")
        var done = false
        try store.load(from: url) { done = true }
        await wait { done }
        XCTAssertFalse(store.paused)
        XCTAssertGreaterThan(store.packets.count, 0)
        XCTAssertEqual(store.visible.count, store.packets.count)
    }

    /// settings.json with a limit the Settings field would never accept.
    func testBufferLimitsFromTheFileAreClamped() {
        var s = model.settings
        s.packetLimit = 100_000_000
        s.logLimit = 50_000_000
        model.settings = s
        XCTAssertEqual(model.packets.limit, AppModel.maxPacketLimit)
        XCTAssertEqual(model.logs.limit, AppModel.maxLogLimit)
    }

    // MARK: 9. Kernel drop counter

    /// `ps_drop` is 32-bit; a week on a busy SPAN port wraps it. The increase across the wrap
    /// was negative and thrown away.
    func testKernelDropCounterAcrossTheWrap() {
        XCTAssertEqual(CaptureEngine.dropIncrease(from: 10, to: 25), 15)
        XCTAssertEqual(CaptureEngine.dropIncrease(from: 4_294_967_000, to: 100), 396)
        XCTAssertEqual(CaptureEngine.dropIncrease(from: 0, to: 0), 0)
    }

    // MARK: 10. Start all / ⌘⇧L on a running listener

    /// Status ▸ Start all with syslog running and traps off re-bound the syslog listener: every
    /// TCP device was disconnected (and its partial line lost). ⌘⇧L did the same.
    func testStartAllLeavesARunningSyslogListenerAlone() async throws {
        let udp = TestSockets.freePort(), trap = TestSockets.freePort()
        let tcp = TestSockets.freePort(SOCK_STREAM)
        model.settings.syslogUDPPort = udp
        model.settings.syslogTCPPort = tcp
        model.settings.trapPort = trap
        model.startSyslog()
        XCTAssertTrue(model.syslog.isRunning, model.syslog.lastError ?? "")
        let fd = try XCTUnwrap(TestSockets.connectTCP(tcp))
        defer { close(fd) }
        await wait { self.model.syslog.tcpClients == 1 }
        XCTAssertEqual(model.syslog.tcpClients, 1)

        model.startAll()
        model.startSyslogIfStopped()
        XCTAssertTrue(model.traps.isRunning)
        try? await Task.sleep(for: .milliseconds(200))
        XCTAssertEqual(model.syslog.tcpClients, 1, "the TCP device is still connected")
        var b = [UInt8](repeating: 0, count: 8)
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
        let n = recv(fd, &b, b.count, 0)
        XCTAssertTrue(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK), "the listener closed the connection (recv \(n))")
    }

    /// There is one window: no ⌘N / New Window / New Tab in the menus.
    func testNoMenuCommandOpensASecondWindow() {
        func items(_ m: NSMenu) -> [NSMenuItem] { m.items.flatMap { [$0] + ($0.submenu.map(items) ?? []) } }
        let all = NSApp.mainMenu.map(items) ?? []
        XCTAssertFalse(all.isEmpty)
        XCTAssertFalse(all.contains { $0.keyEquivalent == "n" && $0.keyEquivalentModifierMask == .command }, "⌘N")
        XCTAssertFalse(all.contains { $0.title.localizedCaseInsensitiveContains("New Window") || $0.title.localizedCaseInsensitiveContains("New Tab") })
        XCTAssertFalse(all.contains { $0.action == NSSelectorFromString("newWindowForTab:") })
    }

    // MARK: 11. "dropped" that was never lost

    /// A 1,000,000-packet file in the 200,000 ring said "800,000 dropped" under the heading; a
    /// week of syslog said "1,234,567 dropped" in the footer. Rolling the oldest out of the
    /// ring is not a loss; only kernel / back-pressure / pause-overflow drops are.
    func testRolledOutIsNotCountedAsLost() {
        let packets = PacketStore()
        packets.limit = 1_000
        packets.ingest((1...3_000).map { i in
            Packet(id: i, timestamp: Date(timeIntervalSince1970: Double(i)), relative: Double(i - 1), length: 60, captured: 60,
                   data: Data(count: 60), decoded: PacketDecoder.decode(Data(count: 60)))
        })
        XCTAssertGreaterThan(packets.dropped, 0)
        XCTAssertEqual(packets.lost, 0)
        packets.addKernelDrops(7)
        XCTAssertEqual(packets.lost, 7)

        let logs = LogStore()
        logs.limit = 1_000
        logs.ingest((0..<3_000).map { LogEntry.line("\($0)") })
        XCTAssertGreaterThan(logs.dropped, 0)
        XCTAssertEqual(logs.lost, 0)
        logs.noteDropped(5)
        XCTAssertEqual(logs.lost, 5)
        XCTAssertEqual(LogView.dropText(dropped: logs.dropped, lost: logs.lost),
                       " · \(Format.count(logs.dropped - 5)) rolled out · 5 dropped")
        XCTAssertEqual(LogView.dropText(dropped: 0, lost: 0), "")
    }

    // MARK: 12. Status: what to type into the devices

    func testStatusSyslogTargetWords() {
        XCTAssertEqual(StatusView.syslogTarget("10.0.0.5", udp: 514, tcp: 514), "10.0.0.5:514  (udp or tcp)")
        XCTAssertEqual(StatusView.syslogTarget("10.0.0.5", udp: 514, tcp: 0), "udp 10.0.0.5:514")
        XCTAssertEqual(StatusView.syslogTarget("10.0.0.5", udp: 0, tcp: 0), "no syslog port is open",
                       "was “10.0.0.5:0  (udp or tcp)”")
    }
}

extension LogEntry {
    fileprivate static var syslogBefore: LogEntry { line("before") }
    fileprivate static var syslogAfter: LogEntry { line("after") }

    fileprivate static func line(_ text: String) -> LogEntry {
        parsedLine("<13>Sep 23 10:15:32 h app: \(text)", from: "10.1.0.2", id: LogStore.nextID())
    }
}
