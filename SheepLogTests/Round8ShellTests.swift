import XCTest
@testable import SheepLog

/// Round 8 sweep: filter grammar and helpers, settings that apply later, errors that must not be
/// lost to a pane switch.
@MainActor
final class Round8ShellTests: XCTestCase {
    private var model: AppModel { AppModel.shared }

    private func matches(_ q: String, _ e: LogEntry) throws -> Bool {
        LogFilter(query: try Query.parse(q), source: nil, mask: Set(Severity.allCases)).matches(e)
    }

    /// `-/re/` and `!/re/` are NOT the regex. They were NOT the literal text "/re/", which
    /// hid nothing — the filter silently did the opposite of what was typed.
    func testMinusBeforeARegexNegatesIt() throws {
        let keepalive = parsedLine("<13>Sep 23 10:00:00 sw1 app: keepalive from 10.1.0.2")
        let login = parsedLine("<13>Sep 23 10:00:00 sw1 app: login failed for admin")
        for q in ["-/keep.?alive/", "!/keep.?alive/"] {
            XCTAssertFalse(try matches(q, keepalive), q)
            XCTAssertTrue(try matches(q, login), q)
        }
        XCTAssertTrue(try matches("login -/keep.?alive/", login))
        XCTAssertEqual(try QueryLexer.tokenize("-/a b/"), [.not, .regex("a b")])
    }

    /// "Filter this host" / "Exclude this host" / "Filter this program" AND a term with the
    /// filter; one with a top-level OR is grouped first.
    func testAppendingATermKeepsAnORFilterTogether() throws {
        XCTAssertEqual(LogStore.appending("host:10.1.0.1", to: ""), "host:10.1.0.1")
        XCTAssertEqual(LogStore.appending("host:10.1.0.1", to: "sev:err"), "sev:err host:10.1.0.1")
        XCTAssertEqual(LogStore.appending("host:10.1.0.1", to: "sev:err OR sev:warn"), "(sev:err OR sev:warn) host:10.1.0.1")
        XCTAssertEqual(LogStore.appending("-host:x", to: "a NOR b"), "(a NOR b) -host:x")
        XCTAssertEqual(LogStore.appending("host:x", to: "(a OR b) c"), "(a OR b) c host:x", "an OR inside ( ) is already grouped")
        let other = parsedLine("<11>Sep 23 10:00:00 sw2 app: link down", from: "10.1.0.2")
        let q = LogStore.appending("host:10.1.0.1", to: "sev:err OR sev:warn")
        XCTAssertFalse(try matches(q, other), "an error from another host is not 'this host'")
        let store = LogStore()
        store.queryText = "sev:err OR sev:warn"
        store.appendToQuery("host:10.1.0.1")
        XCTAssertEqual(store.queryText, "(sev:err OR sev:warn) host:10.1.0.1")
    }

    /// `sport:` is the line's own field (like `dport:`); the syslog sender's port is `port:`.
    func testSportIsTheLinesFieldNotTheSyslogSourcePort() throws {
        let cisco = parsedLine("<13>Sep 23 10:00:00 sw1 app: interface up")                      // no sport field; sent from 514
        let forti = parsedLine(#"<13>date=2026-09-23 time=10:00:00 devname="fw" devid="FG1" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=10.1.1.1 sport=514 dstip=8.8.8.8 dport=53"#)
        XCTAssertFalse(try matches("sport:514", cisco), "no sport field: not every line from port 514")
        XCTAssertTrue(try matches("sport:514", forti))
        XCTAssertTrue(try matches("port:514", cisco), "port: is the syslog source port")
        XCTAssertTrue(try matches("dport:53", forti))
    }

    /// settings.json never holds the community (secrets are blanked); the Test form keeps
    /// "public" instead of starting empty after the first settings save.
    func testStoredSNMPDefaultsDoNotBlankTheCommunity() throws {
        var s = AppSettings()
        s.snmpDefaults.community = "s3cret"
        s.snmpDefaults.version = .v2c
        let back = try XCTUnwrap(AppSettings.decode(try XCTUnwrap(s.encoded())))
        XCTAssertEqual(back.snmpDefaults.community, "", "never written")
        XCTAssertEqual(SNMPTestModel.formDefaults(back.snmpDefaults).community, "public")
        var v3 = back.snmpDefaults
        v3.version = .v3
        v3.community = "kept"
        XCTAssertEqual(SNMPTestModel.formDefaults(v3).community, "kept")
        XCTAssertEqual(SNMPTestModel.formDefaults(v3).version, .v3)
    }

    /// A capture file that fails part-way reports it even when the Packets pane is not shown
    /// (the report lived in the Packets header's onChange).
    func testCaptureFileErrorIsReportedFromAnyPane() async throws {
        let source = CaptureGroundTruthTests.pcapDir.appending(path: "http-tls.pcap")
        var data = try Data(contentsOf: source)
        data.removeLast(40)                                   // the last record is cut short
        let url = FileManager.default.temporaryDirectory.appending(path: "round8-truncated-\(UUID().uuidString).pcap")
        try data.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        model.mainPane = .status
        while model.lastError != nil { model.clearError() }
        let done = expectation(description: "loaded")
        try model.packets.load(from: url) { done.fulfill() }
        await fulfillment(of: [done], timeout: 10)
        try await Task.sleep(for: .milliseconds(100))
        XCTAssertEqual(model.lastError, "The capture file could not be read completely.")
        XCTAssertTrue(model.lastErrorDetail?.contains("round8-truncated") == true, model.lastErrorDetail ?? "")
        XCTAssertNil(model.packets.lastError, "consumed, so the next failure shows too")
        model.clearError()
        model.packets.clear()
    }

    /// Interface / promiscuous / filter apply at the next Start: Settings says so while a
    /// capture runs with other values (and says nothing otherwise).
    func testCaptureSettingsChangedDuringACaptureSayTheyApplyAtTheNextStart() {
        var s = AppSettings()
        s.captureFilter = "not port 22"
        s.capturePromiscuous = true
        XCTAssertNil(SettingsView.captureRestartNote(settings: s, running: false, interface: "en0", promiscuous: true, filter: ""))
        XCTAssertNil(SettingsView.captureRestartNote(settings: s, running: true, interface: "en0", promiscuous: true, filter: "not port 22"))
        let note = SettingsView.captureRestartNote(settings: s, running: true, interface: "en0", promiscuous: true, filter: "")
        XCTAssertTrue(note?.contains("next Start") == true, note ?? "nil")
        XCTAssertTrue(note?.contains("no filter") == true)
        s.captureInterface = "en7"
        XCTAssertNotNil(SettingsView.captureRestartNote(settings: s, running: true, interface: "en0", promiscuous: true, filter: "not port 22"))
        s.captureInterface = ""
        s.capturePromiscuous = false
        XCTAssertNotNil(SettingsView.captureRestartNote(settings: s, running: true, interface: "en0", promiscuous: true, filter: "not port 22"))
    }

    /// An unfinished packet filter leaves the last good one applied, and the Packets table
    /// now says so under the table as the Log does (it had only a red border and a tooltip).
    func testPacketFilterErrorKeepsTheLastFilterAndHasABanner() throws {
        let store = PacketStore()
        store.queryText = "proto:tcp"
        store.applyQueryNow(synchronous: true)
        let good = store.query
        store.queryText = "proto:tcp OR"
        store.applyQueryNow(synchronous: true)
        XCTAssertEqual(store.query, good)
        let error = try XCTUnwrap(store.queryError)
        XCTAssertFalse(store.queryErrorIsNotice)
        XCTAssertTrue(LogView.filterBanner(error, isNotice: false).contains("Showing the last filter that worked"))
    }

    /// No window tabs: the tab bar's "+" made a second window on the one set of services.
    func testNoWindowTabbing() {
        XCTAssertFalse(NSWindow.allowsAutomaticWindowTabbing)
    }

    /// The Settings number boxes read what was typed when they commit (Return, focus loss,
    /// pane switch, quit).
    func testCommitNumberFieldParsing() {
        XCTAssertEqual(CommitNumberField.parse("100,000"), 100_000)
        XCTAssertEqual(CommitNumberField.parse(" 250 000 "), 250_000)
        XCTAssertEqual(CommitNumberField.parse("2.5"), 2.5)
        XCTAssertNil(CommitNumberField.parse(""))
        XCTAssertNil(CommitNumberField.parse("abc"))
        XCTAssertNil(CommitNumberField.parse("inf"))
        XCTAssertEqual(CommitNumberField.text(100_000, integer: true), "100,000")
        XCTAssertEqual(CommitNumberField.text(0.5, integer: false), "0.5")
    }
}
