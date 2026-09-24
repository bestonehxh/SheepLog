import Darwin
import XCTest
@testable import SheepLog

/// Traps and informs sent by net-snmp's own `snmptrap` / `snmpinform` (always in /usr/bin on
/// macOS) to a TrapReceiver / TrapListener on a free high port, end to end: decoding, the
/// inform acknowledgement, naming through the MIB registry (bundled and user-imported), and
/// what the resulting log entries give the log filter.
@MainActor
final class TrapScenarioTests: XCTestCase {
    private nonisolated static let snmptrap = "/usr/bin/snmptrap"
    private static let snmpinform = "/usr/bin/snmpinform"

    override func setUpWithError() throws {
        guard FileManager.default.isExecutableFile(atPath: Self.snmptrap) else {
            throw XCTSkip("net-snmp's snmptrap is not installed")
        }
    }

    /// The bundled modules, loaded once into the shared registry the receiver names traps with.
    private static let registryLoaded: Void = {
        MainActor.assumeIsolated { MIBRegistry.shared.loadNow(bundled: MIBRegistry.bundledURLs()) }
    }()

    /// Runs a net-snmp tool with no MIB loading surprises (numeric OIDs only).
    @discardableResult
    private func run(_ tool: String, _ args: [String]) throws -> (status: Int32, output: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        var env = ProcessInfo.processInfo.environment
        env["MIBS"] = ""                     // no MIB parsing warnings on stderr
        p.environment = env
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        try p.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, String(decoding: data, as: UTF8.self))
    }

    /// Spins the main run loop (the receiver hands batches over with DispatchQueue.main) until
    /// `done` or the deadline.
    private func spin(until deadline: TimeInterval = 5, _ done: () -> Bool) {
        let end = Date().addingTimeInterval(deadline)
        while !done(), Date() < end { RunLoop.main.run(until: Date().addingTimeInterval(0.02)) }
    }

    private func receiver() -> (TrapReceiver, LogStore, UInt16) {
        _ = Self.registryLoaded
        let store = LogStore()
        let r = TrapReceiver(store: store)
        let port = TestSockets.freePort()
        r.start(port: port)
        XCTAssertTrue(r.isRunning, r.lastError ?? "")
        return (r, store, port)
    }

    private func matches(_ q: String, _ e: LogEntry) throws -> Bool {
        LogFilter(query: try Query.parse(q), source: nil, mask: Set(Severity.allCases)).matches(e)
    }

    // MARK: -

    func testV1EnterpriseSpecificWithVarBinds() throws {
        let (r, store, port) = receiver()
        defer { r.stop() }
        let rc = try run(Self.snmptrap, ["-v1", "-c", "public", "127.0.0.1:\(port)", "1.3.6.1.4.1.99999", "192.0.2.77",
                                         "6", "17", "4242",
                                         "1.3.6.1.4.1.99999.1.1.0", "s", "fan tray 2",
                                         "1.3.6.1.4.1.99999.1.2.0", "i", "42"])
        XCTAssertEqual(rc.status, 0, rc.output)
        spin { store.entries.count == 1 }
        let e = try XCTUnwrap(store.entries.first)
        XCTAssertEqual(e.vendor, .snmpTrap)
        XCTAssertEqual(e.program, "enterprises.99999.0.17", "no MIB names it: dotted under the nearest name")
        XCTAssertEqual(e.hostname, "192.0.2.77", "v1 agent-addr")
        XCTAssertEqual(e.sourceAddress, "127.0.0.1")
        XCTAssertEqual(e.field("trap_oid"), "1.3.6.1.4.1.99999.0.17")
        XCTAssertEqual(e.field("version"), "v1")
        XCTAssertEqual(e.field("agent_addr"), "192.0.2.77")
        XCTAssertEqual(e.field("uptime"), Format.uptime(ticks: 4242))
        XCTAssertEqual(e.field("enterprises.99999.1.1.0"), "fan tray 2")
        XCTAssertEqual(e.field("enterprises.99999.1.2.0"), "42")
        // RFC 3584 §3.1: the enterprise travels as snmpTrapEnterprise.0.
        XCTAssertEqual(e.field("snmpTrapEnterprise.0"), "enterprises.99999")
        XCTAssertEqual(r.trapCount, 1)
        XCTAssertEqual(r.invalidCount, 0)
    }

    func testV2cGenericTrapsAndFilterKeys() throws {
        let (r, store, port) = receiver()
        defer { r.stop() }
        let target = "127.0.0.1:\(port)"
        try run(Self.snmptrap, ["-v2c", "-c", "public", target, "", "1.3.6.1.6.3.1.1.5.1"])            // coldStart
        try run(Self.snmptrap, ["-v2c", "-c", "public", target, "", "1.3.6.1.6.3.1.1.5.5"])            // authenticationFailure
        try run(Self.snmptrap, ["-v2c", "-c", "public", target, "", "1.3.6.1.6.3.1.1.5.3",             // linkDown
                                "1.3.6.1.2.1.2.2.1.1.3", "i", "3",
                                "1.3.6.1.2.1.2.2.1.7.3", "i", "1",
                                "1.3.6.1.2.1.2.2.1.8.3", "i", "2"])
        spin { store.entries.count == 3 }
        XCTAssertEqual(store.entries.map(\.program), ["coldStart", "authenticationFailure", "linkDown"])
        XCTAssertEqual(store.entries.map(\.severity), [.warning, .warning, .warning])
        let link = store.entries[2]
        XCTAssertEqual(link.message, "linkDown ifIndex.3=3, ifAdminStatus.3=up(1), ifOperStatus.3=down(2)")
        XCTAssertEqual(link.hostname, "127.0.0.1")
        XCTAssertEqual(link.facility, .local0)
        XCTAssertEqual(link.fields.map(\.key), ["ifIndex.3", "ifAdminStatus.3", "ifOperStatus.3",
                                                "trap_oid", "version", "community", "uptime"])
        XCTAssertEqual(link.field("community"), "public")
        XCTAssertTrue(try matches("vendor:trap", link))
        XCTAssertTrue(try matches("app:linkDown", link))
        XCTAssertTrue(try matches("f:ifOperStatus.3=down", link))
        XCTAssertTrue(try matches("f:trap_oid=1.3.6.1.6.3.1.1.5.3", link))
        XCTAssertTrue(try matches("host:127.0.0.1 sev:<=warn", link))
        XCTAssertTrue(try matches("msg:ifOperStatus.3=down", link))
        XCTAssertFalse(try matches("app:linkDown", store.entries[0]))
    }

    func testInformIsAcknowledged() throws {
        let (r, store, port) = receiver()
        defer { r.stop() }
        let rc = try run(Self.snmpinform, ["-v2c", "-c", "public", "-t", "2", "-r", "0", "127.0.0.1:\(port)", "",
                                           "1.3.6.1.6.3.1.1.5.4", "1.3.6.1.2.1.2.2.1.1.5", "i", "5"])
        XCTAssertEqual(rc.status, 0, "snmpinform got no acknowledgement: \(rc.output)")
        spin { store.entries.count == 1 }
        XCTAssertEqual(store.entries.first?.program, "linkUp")
        XCTAssertEqual(store.entries.first?.severity, .notice)
    }

    func testTwoHundredVarBinds() throws {
        let (r, store, port) = receiver()
        defer { r.stop() }
        var args = ["-v2c", "-c", "public", "127.0.0.1:\(port)", "", "1.3.6.1.4.1.99999.0.1"]
        for i in 1...200 { args += ["1.3.6.1.4.1.99999.1.\(i).0", "i", "\(i)"] }
        let rc = try run(Self.snmptrap, args)
        XCTAssertEqual(rc.status, 0, rc.output)
        spin { store.entries.count == 1 }
        let e = try XCTUnwrap(store.entries.first)
        XCTAssertEqual(e.fields.count, 200 + 4)
        XCTAssertEqual(e.field("enterprises.99999.1.200.0"), "200")
        XCTAssertEqual(r.invalidCount, 0)
    }

    func testMalformedDatagramsAreCountedNotLogged() throws {
        let (r, store, port) = receiver()
        defer { r.stop() }
        let s = try UDPEndpoint(host: "127.0.0.1", port: port)
        var rng = SystemRandomNumberGenerator()
        for n in [0, 1, 7, 300, 1400] {
            try s.send((0..<n).map { _ in UInt8.random(in: 0...255, using: &rng) })
        }
        try s.send([0x30, 0x03, 0x02, 0x01])                         // truncated SEQUENCE
        try s.send([0x30, 0x06, 0x02, 0x01, 0x01, 0x04, 0x01, 0x70])   // v2c, no PDU
        try run(Self.snmptrap, ["-v2c", "-c", "public", "127.0.0.1:\(port)", "", "1.3.6.1.6.3.1.1.5.1"])
        spin { store.entries.count == 1 && r.invalidCount >= 6 }
        XCTAssertEqual(store.entries.count, 1, "only the real trap is logged")
        XCTAssertGreaterThanOrEqual(r.invalidCount, 6)   // a 0-byte datagram may not be delivered at all
        XCTAssertEqual(r.trapCount, 1)
    }

    func testV3TrapIsCountedAndLoggedUndecoded() throws {
        let (r, store, port) = receiver()
        defer { r.stop() }
        try run(Self.snmptrap, ["-v3", "-u", "trapuser", "-l", "noAuthNoPriv", "-e", "0x8000000001020304",
                                "127.0.0.1:\(port)", "", "1.3.6.1.6.3.1.1.5.1"])
        spin { store.entries.count == 1 }
        XCTAssertEqual(r.v3Count, 1)
        XCTAssertEqual(store.entries.first?.program, "snmpv3")
    }

    /// Another program holding the trap port for IPv4 only (snmptrapd, `nc -ul 162`): the
    /// dual-stack socket would bind anyway and never see an IPv4 trap — it must say "in use".
    func testPortHeldForIPv4ByAnotherProgramIsReported() throws {
        let (held, port) = try XCTUnwrap(TestSockets.holdIPv4(SOCK_DGRAM))
        defer { close(held) }
        XCTAssertThrowsError(try TrapListener(port: port) { _ in }) { e in
            XCTAssertEqual((e as? TrapListener.BindError)?.message, "UDP port \(port) is already in use (EADDRINUSE).")
        }
        let store = LogStore()
        let r = TrapReceiver(store: store)
        r.start(port: port)
        XCTAssertFalse(r.isRunning)
        XCTAssertEqual(r.lastError, "UDP port \(port) is already in use (EADDRINUSE).")
    }

    /// A vendor MIB imported by the user names the notification (and its var-binds).
    func testUserImportedNotificationName() throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "SheepLogTrapMIB-\(UUID().uuidString)")
        let userFolder = dir.appending(path: "user")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let mib = dir.appending(path: "SHEEP-TEST-MIB.mib")
        try """
        SHEEP-TEST-MIB DEFINITIONS ::= BEGIN
        IMPORTS
            MODULE-IDENTITY, OBJECT-TYPE, NOTIFICATION-TYPE, enterprises FROM SNMPv2-SMI;
        sheepTest MODULE-IDENTITY
            LAST-UPDATED "202609240000Z"
            ORGANIZATION "SheepLog"
            CONTACT-INFO "lab@example.net"
            DESCRIPTION "Test notifications."
            ::= { enterprises 99999 }
        sheepNotifications OBJECT IDENTIFIER ::= { sheepTest 0 }
        sheepObjects OBJECT IDENTIFIER ::= { sheepTest 1 }
        sheepAlarmLevel OBJECT-TYPE
            SYNTAX      INTEGER { clear(1), minor(2), major(3) }
            MAX-ACCESS  accessible-for-notify
            STATUS      current
            DESCRIPTION "Alarm level."
            ::= { sheepObjects 1 }
        sheepFanFailed NOTIFICATION-TYPE
            OBJECTS     { sheepAlarmLevel }
            STATUS      current
            DESCRIPTION "A fan failed."
            ::= { sheepNotifications 7 }
        END
        """.write(to: mib, atomically: true, encoding: .utf8)

        let reg = MIBRegistry()
        reg.userFolderOverride = userFolder
        reg.loadNow(bundled: MIBRegistry.bundledURLs())
        reg.importFiles([mib])
        spin { reg.oid(forName: "sheepFanFailed") != nil }
        XCTAssertEqual(reg.oid(forName: "SHEEP-TEST-MIB::sheepFanFailed"), OID([1, 3, 6, 1, 4, 1, 99999, 0, 7]))
        XCTAssertEqual(reg.modules.first { $0.name == "SHEEP-TEST-MIB" }?.errors, [])

        // The datagram as snmptrap sends it, through the listener's decoder and the registry.
        let port = TestSockets.freePort()
        let got = LockedBox<[ReceivedTrap]>([])
        let listener = try TrapListener(port: port) { batch in got.mutate { $0 += batch } }
        listener.resume()
        defer { listener.cancel() }
        try run(Self.snmptrap, ["-v2c", "-c", "public", "127.0.0.1:\(port)", "", "1.3.6.1.4.1.99999.0.7",
                                "1.3.6.1.4.1.99999.1.1.0", "i", "3"])
        try run(Self.snmptrap, ["-v1", "-c", "public", "127.0.0.1:\(port)", "1.3.6.1.4.1.99999", "127.0.0.1", "6", "7", ""])
        spin { got.value.count == 2 }
        let traps = got.value.compactMap { if case .trap(let t) = $0 { return t } else { return nil } }
        XCTAssertEqual(traps.count, 2)
        let entries = traps.map { TrapReceiver.entry(for: $0, registry: reg) }
        XCTAssertEqual(entries.map(\.program), ["sheepFanFailed", "sheepFanFailed"], "v2c and v1 forms of the same notification")
        XCTAssertEqual(entries.first?.message, "sheepFanFailed sheepAlarmLevel.0=major(3)")
        XCTAssertEqual(entries.first?.field("sheepAlarmLevel.0"), "major(3)")
    }
}
