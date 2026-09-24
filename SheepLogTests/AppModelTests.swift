import Darwin
import XCTest
@testable import SheepLog

/// The shell: settings persistence, cross-pane requests, listener restarts and error queueing.
/// The test host runs the real app; `AppSettings.file` points into a temporary folder there and
/// the listeners are not auto-started, so nothing here touches the user's settings or 514/162.
@MainActor
final class AppModelTests: XCTestCase {
    private var model: AppModel { AppModel.shared }
    private var savedSettings = AppSettings()

    override func setUp() async throws {
        savedSettings = model.settings
        drainErrors()
    }

    override func tearDown() async throws {
        model.stopSyslog()
        model.stopTraps()
        model.settings = savedSettings
        drainErrors()
    }

    private func drainErrors() { model.dismissAllErrors() }

    // MARK: Settings persistence

    private static func everythingChanged() -> AppSettings {
        var s = AppSettings()
        s.syslogUDPPort = 5514
        s.syslogTCPPort = 6514
        s.trapPort = 1162
        s.syslogAutoStart = false
        s.trapAutoStart = false
        s.logLimit = 12_345
        s.diskLogging = true
        s.logDirectory = "/tmp/sheeplog-logs"
        s.newestFirst = false
        s.captureInterface = "en7"
        s.capturePromiscuous = false
        s.captureFilter = "not port 22"
        s.packetLimit = 54_321
        s.snmpTimeout = 4.5
        s.snmpRetries = 7
        s.snmpDefaults = SNMPCredentials(version: .v3, community: "", username: "ops",   // secrets never reach settings.json
                                         authProtocol: .sha256, authPassword: "", privProtocol: .aes256,
                                         privPassword: "", contextName: "ctx")
        s.recentTargets = [SNMPTarget(host: "10.1.0.1", port: 1161, timeout: 3, retries: 1)]
        s.sourceVendorOverrides = ["10.1.0.9": .huawei, "10.1.0.10": .fortigate]
        return s
    }

    func testEveryPropertyRoundTripsThroughJSON() throws {
        let s = Self.everythingChanged()
        // Every stored property differs from the default, so a property left out of the
        // coding keys (or decoded from the wrong key) fails the equality below.
        let defaults = Mirror(reflecting: AppSettings()).children.map { "\($0.value)" }
        let changed = Mirror(reflecting: s).children.map { "\($0.value)" }
        XCTAssertEqual(defaults.count, changed.count)
        for (label, (a, b)) in zip(Mirror(reflecting: s).children.map { $0.label ?? "?" }, zip(defaults, changed)) {
            XCTAssertNotEqual(a, b, "\(label) must be non-default in this fixture")
        }
        XCTAssertEqual(AppSettings.CodingKeys.allCases.count, Mirror(reflecting: s).children.count,
                       "every stored property needs a coding key")
        let data = try XCTUnwrap(s.encoded())
        XCTAssertEqual(AppSettings.decode(data), s)
    }

    func testEmptyObjectDecodesToDefaults() {
        XCTAssertEqual(AppSettings.decode(Data("{}".utf8)), AppSettings())
    }

    func testOlderAndNewerFilesLoad() throws {
        let json = """
        {"logLimit": 5000, "trapPort": "not a number", "someFutureKey": {"x": [1, 2]},
         "sourceVendorOverrides": {"10.0.0.1": "huawei", "10.0.0.2": "vendorFromTheFuture"},
         "recentTargets": [{"host": "a", "port": 161, "timeout": 2, "retries": 2}, {"bogus": true}],
         "snmpDefaults": 42}
        """
        let s = try XCTUnwrap(AppSettings.decode(Data(json.utf8)))
        XCTAssertEqual(s.logLimit, 5000)
        XCTAssertEqual(s.trapPort, 162, "a bad value falls back to the default")
        XCTAssertEqual(s.sourceVendorOverrides, ["10.0.0.1": .huawei])
        XCTAssertEqual(s.recentTargets.map(\.host), ["a"])
        XCTAssertEqual(s.snmpDefaults, SNMPCredentials())
        XCTAssertEqual(s.syslogUDPPort, 514, "a missing key takes the default")
    }

    func testCorruptFileStartsWithDefaults() throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "sheeplog-settings-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appending(path: "settings.json")
        try Data([0xFF, 0x00, 0x7B, 0x22]).write(to: url)
        XCTAssertEqual(AppSettings.load(from: url), AppSettings())
        XCTAssertTrue(FileManager.default.fileExists(atPath: dir.appending(path: "settings.corrupt.json").path))
        // Missing file: defaults, no copy.
        XCTAssertEqual(AppSettings.load(from: dir.appending(path: "nothing.json")), AppSettings())
    }

    func testSaveLoadThroughAFile() throws {
        let url = FileManager.default.temporaryDirectory.appending(path: "sheeplog-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: url) }
        Self.everythingChanged().save(to: url)
        XCTAssertEqual(AppSettings.load(from: url), Self.everythingChanged())
    }

    func testTestsNeverTouchTheUsersSettings() {
        XCTAssertTrue(AppSettings.isRunningTests)
        XCTAssertFalse(AppSettings.file.path.contains("/Library/Application Support/"))
    }

    // MARK: Settings applied

    func testBufferSettingsApplyImmediately() {
        model.settings.logLimit = 2_000
        XCTAssertEqual(model.logs.limit, 2_000)
        model.settings.packetLimit = 3_000
        XCTAssertEqual(model.packets.limit, 3_000)
        model.settings.newestFirst = !savedSettings.newestFirst
        XCTAssertEqual(model.logs.newestFirst, !savedSettings.newestFirst)
    }

    func testDiskLoggerOnlyRecreatedWhenItsFolderChanges() {
        let a = FileManager.default.temporaryDirectory.appending(path: "sheeplog-a-\(UUID().uuidString)")
        let b = FileManager.default.temporaryDirectory.appending(path: "sheeplog-b-\(UUID().uuidString)")
        model.settings.logDirectory = a.path
        model.settings.diskLogging = true
        let first = model.logs.diskLogger
        XCTAssertNotNil(first)
        model.settings.logLimit = 7_777                  // unrelated
        model.settings.captureFilter = "tcp"             // unrelated
        XCTAssertTrue(model.logs.diskLogger === first)
        model.settings.logDirectory = b.path
        XCTAssertFalse(model.logs.diskLogger === first)
        XCTAssertEqual(model.logs.diskLogger?.directory.standardizedFileURL, b.standardizedFileURL)
        model.settings.diskLogging = false
        XCTAssertNil(model.logs.diskLogger)
    }

    func testDiskLoggerFailureReachesTheCaller() {
        let failed = expectation(description: "error reported")
        // A folder under a regular file cannot be created.
        let logger = DiskLogger(directory: URL(fileURLWithPath: "/dev/null/SheepLog")) { _ in failed.fulfill() }
        logger.append([LogEntry.testLine()])
        wait(for: [failed], timeout: 2)
        logger.close()
    }

    func testSNMPSettingsFollowIntoTheTestPane() {
        model.settings.snmpTimeout = 7
        model.settings.snmpRetries = 5
        XCTAssertEqual(SNMPTestModel.shared.timeout, 7)
        XCTAssertEqual(SNMPTestModel.shared.retries, 5)
    }

    func testRecentTargetsCappedAndDeduplicated() {
        model.settings.recentTargets = []
        for i in 0..<25 { model.rememberTarget(SNMPTarget(host: "10.0.0.\(i)")) }
        model.rememberTarget(SNMPTarget(host: "10.0.0.20"))
        XCTAssertEqual(model.settings.recentTargets.count, AppSettings.recentTargetLimit)
        XCTAssertEqual(model.settings.recentTargets.first?.host, "10.0.0.20")
        XCTAssertEqual(model.settings.recentTargets.filter { $0.host == "10.0.0.20" }.count, 1)
    }

    func testVendorOverrideReachesTheStoreAndSettings() {
        model.setVendorOverride(.paloAlto, for: "192.0.2.77")
        XCTAssertEqual(model.logs.vendorOverrides.get("192.0.2.77"), .paloAlto)
        XCTAssertEqual(model.settings.sourceVendorOverrides["192.0.2.77"], .paloAlto)
        model.setVendorOverride(nil, for: "192.0.2.77")
        XCTAssertNil(model.logs.vendorOverrides.get("192.0.2.77"))
        XCTAssertNil(model.settings.sourceVendorOverrides["192.0.2.77"])
    }

    func testMissingCaptureInterfaceFallsBackWithANote() {
        let list = [CaptureInterface(name: "en0", description: "", addresses: ["10.0.0.2"], isUp: true, isLoopback: false),
                    CaptureInterface(name: "lo0", description: "", addresses: ["127.0.0.1"], isUp: true, isLoopback: true)]
        XCTAssertEqual(AppModel.captureInterface(wanted: "", available: list).name, "en0")
        XCTAssertNil(AppModel.captureInterface(wanted: "lo0", available: list).note)
        let gone = AppModel.captureInterface(wanted: "en9", available: list)
        XCTAssertEqual(gone.name, "en0")
        XCTAssertTrue(gone.note?.contains("en9") == true)
        // No list at all (no /dev/bpf access): try the named one and let libpcap say why.
        XCTAssertEqual(AppModel.captureInterface(wanted: "en9", available: []).name, "en9")
    }

    // MARK: Cross-pane requests (posted together with the pane switch, before the pane exists)

    func testLogDetailOpensSNMPTestOnTheHost() {
        let m = SNMPTestModel.shared
        let (host, port) = (m.host, m.port)
        defer { m.host = host; m.port = port }
        model.mainPane = .snmpTest
        NotificationCenter.default.post(name: Notification.Name("SheepLog.snmpTarget"), object: "192.0.2.10")
        XCTAssertEqual(m.host, "192.0.2.10")
        NotificationCenter.default.post(name: .sheepLogSNMPTarget, object: "[2001:db8::1]:1161")
        XCTAssertEqual(m.host, "2001:db8::1")
        XCTAssertEqual(m.port, 1161)
    }

    func testMIBUseInTestFillsTheOID() {
        let m = SNMPTestModel.shared
        let old = m.oidText
        defer { m.oidText = old }
        NotificationCenter.default.post(name: .sheepLogSNMPOID, object: "1.3.6.1.2.1.1.5.0")
        XCTAssertEqual(m.oidText, "1.3.6.1.2.1.1.5.0")
    }

    func testFlowsShowPacketsFiltersThePacketsPane() {
        let old = model.packets.queryText
        defer { model.applyPacketFilter(old) }
        NotificationCenter.default.post(name: .sheepLogPacketFilter, object: "frame:3 OR frame:9")
        XCTAssertEqual(model.packets.queryText, "frame:3 OR frame:9")
        XCTAssertNil(model.packets.queryError)
        XCTAssertFalse(model.packets.query.isEmpty)
    }

    func testFollowTCPStreamWaitsForTheFlowsPane() {
        let key = FlowKey("10.0.0.1", 51000, "10.0.0.2", 443, proto: 6)
        NotificationCenter.default.post(name: .sheepLogSelectFlow, object: key)
        XCTAssertEqual(model.pendingFlowKey, key)
        XCTAssertEqual(model.takePendingFlowRequest()?.key, key)
        XCTAssertNil(model.takePendingFlowRequest(), "taken once")
        // Wrong object type: ignored, not crashed on.
        NotificationCenter.default.post(name: .sheepLogSelectFlow, object: "10.0.0.1")
        XCTAssertNil(model.pendingFlowKey)
    }

    func testSourcesShowFiltersTheLog() {
        model.logs.queryText = "sev:<=warn"
        model.logs.applyQueryText()
        model.logs.showSource("192.0.2.44")
        XCTAssertEqual(model.logs.selectedSource, "192.0.2.44")
        XCTAssertEqual(model.logs.queryText, "")
        XCTAssertTrue(model.logs.query.isEmpty)
        model.logs.selectedSource = nil
    }

    // MARK: Errors

    func testSecondErrorWaitsForTheFirst() async throws {
        model.report("first", detail: "a")
        model.report("second")
        model.report("first", detail: "a")           // duplicate of the one on screen
        model.report("second")                        // duplicate of a waiting one
        XCTAssertEqual(model.lastError, "first")
        XCTAssertEqual(model.pendingErrors.count, 1)
        model.clearError()
        model.clearError()                            // OK + the sheet binding: one dismissal
        XCTAssertNil(model.lastError)
        XCTAssertEqual(model.pendingErrors.count, 0)
        try await Task.sleep(for: .seconds(AppModel.nextErrorDelay + 0.3))
        XCTAssertEqual(model.lastError, "second")
        model.clearError()
    }

    func testPortConflictDetailNamesTheCommand() {
        let d = AppModel.portConflictDetail("UDP port 514 is already in use (EADDRINUSE).", udp: [514], tcp: [514])
        XCTAssertTrue(d?.contains("lsof -nP -iUDP:514") == true)
        XCTAssertTrue(d?.contains("-iTCP:514") == true)
        XCTAssertNil(AppModel.portConflictDetail("needs administrator rights (EACCES).", udp: [514], tcp: []))
    }

    // MARK: Listeners

    func testApplyPortsKeepsTheOldPortsWhenTheNewOnesFail() throws {
        let p1 = TestSockets.freePort(SOCK_DGRAM)
        let t1 = TestSockets.freePort(SOCK_DGRAM)
        model.settings.syslogUDPPort = p1
        model.settings.syslogTCPPort = 0
        model.settings.trapPort = t1
        model.startSyslog()
        model.startTraps()
        XCTAssertTrue(model.syslog.isRunning)
        XCTAssertTrue(model.traps.isRunning)
        XCTAssertNil(model.lastError)

        // Settings → new ports that another program holds (IPv4 only), then Apply ports.
        let p2 = TestSockets.freePort(SOCK_DGRAM)
        let t2 = TestSockets.freePort(SOCK_DGRAM)
        let h1 = try XCTUnwrap(TestSockets.holdIPv4(SOCK_DGRAM, port: p2)).fd
        let h2 = try XCTUnwrap(TestSockets.holdIPv4(SOCK_DGRAM, port: t2)).fd
        defer { close(h1); close(h2) }
        model.settings.syslogUDPPort = p2
        model.settings.trapPort = t2
        XCTAssertTrue(model.listenerPortsChanged)
        model.restartListeners()
        XCTAssertTrue(model.syslog.isRunning, "not left stopped")
        XCTAssertEqual(model.syslog.udpPort, p1)
        XCTAssertTrue(model.traps.isRunning)
        XCTAssertEqual(model.traps.port, t1)
        XCTAssertTrue(model.lastError?.contains("could not move") == true)
        XCTAssertEqual(model.pendingErrors.count, 1, "the trap failure waits behind the syslog one")

        // A free new port: moved.
        let p3 = TestSockets.freePort(SOCK_DGRAM)
        model.settings.syslogUDPPort = p3
        model.settings.trapPort = t1
        model.restartListeners()
        XCTAssertEqual(model.syslog.udpPort, p3)
        XCTAssertFalse(model.listenerPortsChanged)
    }

    func testApplyPortsRetriesAListenerThatFailedToStart() throws {
        let busy = TestSockets.freePort(SOCK_DGRAM)
        let holder = try XCTUnwrap(TestSockets.holdIPv4(SOCK_DGRAM, port: busy)).fd
        defer { close(holder) }
        model.settings.syslogUDPPort = busy
        model.settings.syslogTCPPort = 0
        model.startSyslog()
        XCTAssertFalse(model.syslog.isRunning)
        XCTAssertNotNil(model.syslog.lastError)
        XCTAssertTrue(model.lastErrorDetail?.contains("lsof -nP -iUDP:\(busy)") == true)
        model.dismissAllErrors()
        XCTAssertTrue(model.listenerPortsChanged, "Apply ports is enabled for a failed listener")
        let free = TestSockets.freePort(SOCK_DGRAM)
        model.settings.syslogUDPPort = free
        model.restartListeners()
        XCTAssertTrue(model.syslog.isRunning)
        XCTAssertEqual(model.syslog.udpPort, free)
        XCTAssertNil(model.lastError)
    }

    func testRapidSwitchTogglingLeavesOneListener() {
        let p = TestSockets.freePort(SOCK_DGRAM)
        model.settings.syslogUDPPort = p
        model.settings.syslogTCPPort = 0
        for _ in 0..<10 { model.startSyslog(); model.startSyslog(); model.stopSyslog() }
        model.startSyslog()
        model.startSyslog()
        XCTAssertTrue(model.syslog.isRunning)
        XCTAssertNil(model.syslog.lastError)
        XCTAssertNil(model.lastError)
    }
}

private extension LogEntry {
    static func testLine() -> LogEntry {
        parsedLine("<13>Sep 24 10:00:00 host app: hello", from: "192.0.2.1")
    }
}
