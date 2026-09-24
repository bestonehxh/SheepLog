import XCTest
@testable import SheepLog

/// Round 9, part 3: the Test pane's model driven the way a click-through goes, against
/// `Tests/snmp-lab.sh` (skipped unless SHEEPLOG_SNMP_LAB=1): the result card, the table and the
/// subtitle after every step, and the requests other panes send while a run is in flight.
@MainActor
final class Round9SNMPFlowTests: XCTestCase {
    private let m = SNMPTestModel.shared
    private var savedSettings = AppSettings()
    private var savedForm: (host: String, port: UInt16, credentials: SNMPCredentials, timeout: Double, retries: Int, oid: String)?
    private var savedKeychain: [String: Data?] = [:]
    /// The Keychain did not answer (an access prompt is up): its steps are skipped.
    private var keychainBlocked = false
    private static let accounts = ["127.0.0.1:1161", "10.9.0.1:161", "10.9.0.1:1161"]

    override func setUp() async throws {
        let env = ProcessInfo.processInfo.environment
        guard env["SHEEPLOG_SNMP_LAB"] == "1" || env["TEST_RUNNER_SHEEPLOG_SNMP_LAB"] == "1" else {
            throw XCTSkip("Start Tests/snmp-lab.sh and set SHEEPLOG_SNMP_LAB=1 to run the live flows.")
        }
        savedSettings = AppModel.shared.settings
        savedForm = (m.host, m.port, m.credentials, m.timeout, m.retries, m.oidText)
        // The owner's own Keychain entries for these accounts come back afterwards.
        // Only accounts actually read are put back (a timed-out read must not become a delete).
        for a in Self.accounts {
            if let read = await Self.keychain({ KeychainStore.load(account: a) }) { savedKeychain[a] = read }
            else { keychainBlocked = true; break }
        }
        if keychainBlocked {
            print("Round9SNMPFlowTests: the Keychain did not answer within 5 s (an access prompt for an item an earlier build wrote?) — the Keychain steps are skipped")
        }
    }

    override func tearDown() async throws {
        guard let f = savedForm else { return }
        m.cancel()
        await waitIdle()
        m.host = f.host; m.port = f.port; m.applyCredentials(f.credentials); m.timeout = f.timeout; m.retries = f.retries
        m.oidText = f.oid
        AppModel.shared.settings = savedSettings
        let restore = savedKeychain
        if !keychainBlocked, !restore.isEmpty {
            _ = await Self.keychain {
                for (a, d) in restore {
                    if let d { KeychainStore.save(d, account: a) } else { KeychainStore.delete(account: a) }
                }
            }
        }
        AppModel.shared.dismissAllErrors()
    }

    /// Keychain calls on the app's own Keychain queue, given up after 5 s: a fresh Debug build
    /// has a new code signature, and reading an item an earlier build wrote can put up an
    /// access prompt that would hold the main thread (and the run) until someone answers it.
    static func keychain<T: Sendable>(_ body: @escaping @Sendable () -> T) async -> T? {
        let box = LockedBox<T?>(nil)
        let finished = LockedBox(false)
        SNMPTestModel.keychainQueue.async { box.mutate { $0 = body() }; finished.mutate { $0 = true } }
        let end = Date().addingTimeInterval(5)
        while !finished.value, Date() < end { try? await Task.sleep(for: .milliseconds(5)) }
        return finished.value ? box.value : nil
    }

    private func waitIdle(_ timeout: Double = 20) async {
        let end = Date().addingTimeInterval(timeout)
        while m.isRunning, Date() < end { try? await Task.sleep(for: .milliseconds(10)) }
    }

    private func succeeded(file: StaticString = #filePath, line: UInt = #line) -> (summary: String, facts: [(String, String)])? {
        guard case .success(let s, let f)? = m.outcome else {
            XCTFail("not a success: \(String(describing: m.outcome)) heading=\(m.heading)", file: file, line: line)
            return nil
        }
        return (s, f)
    }

    private func v2c(_ community: String = "public") {
        m.version = .v2c
        m.community = community
    }

    func testClickThroughFlow() async throws {
        m.setTarget("127.0.0.1:1161")
        XCTAssertEqual(m.port, 1161)
        v2c()
        m.timeout = 3              // the app's 2 s × 2 tries, with room for a sanitizer build
        m.retries = 1

        // Quick test.
        m.quickTest()
        XCTAssertEqual(m.running, "Quick test")
        await waitIdle()
        var ok = try XCTUnwrap(succeeded())
        XCTAssertTrue(ok.summary.hasPrefix("SNMPv2c OK"), ok.summary)
        XCTAssertTrue(m.heading.hasPrefix("sheeplog-lab answered"), m.heading)
        XCTAssertEqual(ok.facts.first { $0.0 == "sysName" }?.1, "sheeplog-lab")
        XCTAssertTrue(m.subtitle.contains("127.0.0.1:1161"), m.subtitle)
        XCTAssertEqual(m.rows.count, SNMPTestModel.systemOIDs.count)

        // Walk (empty OID = mib-2).
        m.oidText = ""
        m.walk()
        await waitIdle()
        ok = try XCTUnwrap(succeeded())
        XCTAssertGreaterThan(m.rows.count, 50)
        XCTAssertEqual(m.displayed.count, m.rows.count)
        XCTAssertTrue(m.subtitle.contains("127.0.0.1:1161 · v2c"), m.subtitle)
        XCTAssertTrue(m.footer.contains("var-binds"), m.footer)

        // Another version, Quick test again: the card says which.
        m.version = .v1
        m.quickTest()
        await waitIdle()
        ok = try XCTUnwrap(succeeded())
        XCTAssertTrue(ok.summary.hasPrefix("SNMPv1 OK"), ok.summary)
        XCTAssertEqual(m.rows.count, SNMPTestModel.systemOIDs.count, "the walk's rows were replaced")

        // v3 (authPriv) with the lab user.
        m.version = .v3
        m.username = "lab"
        m.authProtocol = .sha1
        m.authPassword = "labpassword"
        m.privProtocol = .aes128
        m.privPassword = "labprivpass"
        m.quickTest()
        await waitIdle()
        ok = try XCTUnwrap(succeeded())
        XCTAssertTrue(ok.summary.hasPrefix("SNMPv3 authPriv OK"), ok.summary)
        v2c()

        // Interfaces.
        m.walkInterfaces()
        await waitIdle()
        _ = try XCTUnwrap(succeeded())
        XCTAssertFalse(m.interfaces.isEmpty)
        XCTAssertEqual(m.resultView, .interfaces)
        XCTAssertTrue(m.subtitle.contains("interfaces from ifTable"), m.subtitle)

        // Cancel mid-walk (the whole tree), then a Get by name at once: no late chunk of the
        // cancelled walk may land in the Get's table.
        m.oidText = "1.3.6.1"
        m.walk()
        let end = Date().addingTimeInterval(5)
        while m.rows.isEmpty, Date() < end { try await Task.sleep(for: .milliseconds(5)) }
        XCTAssertFalse(m.rows.isEmpty, "the walk showed rows before the cancel")
        m.cancel()
        await waitIdle()
        XCTAssertEqual(m.heading, "Stopped.")
        XCTAssertTrue(m.subtitle.hasPrefix("Walk cancelled after"), m.subtitle)
        XCTAssertNil(m.outcome)
        let afterCancel = m.rows.count
        try await Task.sleep(for: .milliseconds(300))
        XCTAssertEqual(m.rows.count, afterCancel, "rows arrived after Cancel")
        m.oidText = "sysName"
        m.get()
        await waitIdle()
        _ = try XCTUnwrap(succeeded())
        XCTAssertEqual(m.rows.map(\.name), ["sysName.0"])
        XCTAssertEqual(m.rows.first?.value, "sheeplog-lab")
        try await Task.sleep(for: .milliseconds(200))
        XCTAssertEqual(m.rows.count, 1, "a chunk of the cancelled walk landed in the Get's table")

        // Wrong credentials. macOS's snmpd is built without VACM (any community reads), so the
        // wrong secret is a v3 auth password: the error card, nothing remembered.
        try await Task.sleep(for: .milliseconds(200))
        let stored = await Self.keychain { KeychainStore.loadCredentials(host: "127.0.0.1", port: 1161) } ?? nil
        if !keychainBlocked { XCTAssertEqual(stored?.version, .v2c, "the last successful run's credentials are in the Keychain") }
        m.version = .v3
        m.username = "lab"
        m.authPassword = "wrong-password"
        m.quickTest()
        await waitIdle()
        guard case .failure(let e, _, let title, let hint)? = m.outcome else { return XCTFail("expected a failure") }
        XCTAssertEqual(e, .wrongDigest, title)
        XCTAssertTrue(hint.contains("auth password"), hint)
        XCTAssertEqual(m.heading, "127.0.0.1 answered with an error.")
        XCTAssertTrue(m.subtitle.contains("v3"), m.subtitle)
        try await Task.sleep(for: .milliseconds(200))
        if !keychainBlocked {
            let after = await Self.keychain { KeychainStore.loadCredentials(host: "127.0.0.1", port: 1161) } ?? nil
            XCTAssertEqual(after, stored, "a failed run must not store its credentials")
        }
        // Right password.
        m.authPassword = "labpassword"
        m.quickTest()
        await waitIdle()
        _ = try XCTUnwrap(succeeded())
        v2c()
        m.quickTest()
        await waitIdle()
        _ = try XCTUnwrap(succeeded())

        // Recent target + Keychain round trip: another host, then the Recent entry back — the
        // saved credentials (v2c public) come back with it.
        let recent = try XCTUnwrap(AppModel.shared.settings.recentTargets.first)
        XCTAssertEqual(recent.host, "127.0.0.1")
        XCTAssertEqual(recent.port, 1161)
        m.setTarget("10.9.0.1")
        m.community = "something-else"
        m.fill(from: recent)
        let back = Date().addingTimeInterval(3)
        while m.community != "public", Date() < back { try await Task.sleep(for: .milliseconds(10)) }
        if !keychainBlocked { XCTAssertEqual(m.community, "public", "the Keychain entry of the Recent target") }
        XCTAssertEqual(m.host, "127.0.0.1")
        XCTAssertEqual(m.port, 1161)
    }

    /// "SNMP test ›" from a log line's inspector and "Use in SNMP test" from MIBs while a run is
    /// in flight: the form takes the new target / object, the run finishes as asked, and the
    /// result card and Recent describe what was asked.
    func testRequestsFromOtherPanesDuringARun() async throws {
        m.setTarget("127.0.0.1:1161")
        v2c()
        m.timeout = 3
        m.retries = 1
        m.oidText = "1.3.6.1.2.1.2"
        m.walk()
        XCTAssertTrue(m.isRunning)
        // The Log inspector's "Open in SNMP test" on a device line.
        AppModel.shared.mainPane = .snmpTest
        NotificationCenter.default.post(name: .sheepLogSNMPTarget, object: "10.9.0.1")
        XCTAssertEqual(m.host, "10.9.0.1")
        XCTAssertEqual(m.port, 161, "a device from the log is asked on SNMP's port, not the lab's 1161 left in the form")
        XCTAssertEqual(m.portText, "161")
        // MIBs' "Use in SNMP test".
        NotificationCenter.default.post(name: .sheepLogSNMPOID, object: "1.3.6.1.2.1.1.5")
        XCTAssertEqual(m.oidText, "1.3.6.1.2.1.1.5")
        await waitIdle()
        _ = try XCTUnwrap(succeeded())
        XCTAssertTrue(m.subtitle.contains("127.0.0.1:1161"), "the card describes the run that was asked: \(m.subtitle)")
        XCTAssertEqual(m.host, "10.9.0.1", "the finished run did not put its target back")
        XCTAssertEqual(m.oidText, "1.3.6.1.2.1.1.5")
        XCTAssertEqual(AppModel.shared.settings.recentTargets.first?.host, "127.0.0.1")

        // Get next in flight, then "Use in SNMP test": the object chosen afterwards stays.
        m.setTarget("127.0.0.1:1161")
        m.oidText = "sysDescr"
        m.getNext()
        NotificationCenter.default.post(name: .sheepLogSNMPOID, object: "1.3.6.1.2.1.1.6")
        await waitIdle()
        _ = try XCTUnwrap(succeeded())
        XCTAssertEqual(m.oidText, "1.3.6.1.2.1.1.6", "the Get next result replaced the object chosen in MIBs meanwhile")
        // Without a change meanwhile, Get next steps on as before.
        m.oidText = "sysDescr"
        m.getNext()
        await waitIdle()
        XCTAssertEqual(m.oidText, "1.3.6.1.2.1.1.1.0")
    }
}
