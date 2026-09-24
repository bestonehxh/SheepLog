import Darwin
import SwiftUI
import XCTest
@testable import SheepLog

/// Round 7 (final review): traps and sources, the filter, Cisco / FortiOS shapes, the parser's
/// clock, TCP framing losses, SNMP Interfaces / v3 / MIB import / BER, the packet filter and
/// decoder, the flow analyser against tshark, and the test gaps round 6's claims left open.
@MainActor
final class Round7Tests: XCTestCase {

    private func matches(_ q: String, _ e: LogEntry) throws -> Bool {
        LogFilter(query: try Query.parse(q), source: nil, mask: Set(Severity.allCases)).matches(e)
    }

    private func spin(_ seconds: Double = 5, until done: () -> Bool) {
        let end = Date().addingTimeInterval(seconds)
        while !done(), Date() < end { RunLoop.main.run(until: Date().addingTimeInterval(0.02)) }
    }

    // MARK: - Traps and Sources

    private static let registry: MIBRegistry = {
        let r = MIBRegistry()
        r.loadNow(bundled: MIBRegistry.bundledURLs())
        return r
    }()

    private func v1Trap(agent: String) -> [UInt8] {
        let pdu = TrapV1PDU(enterprise: OID([1, 3, 6, 1, 4, 1, 9]), agentAddress: agent, genericTrap: 2, specificTrap: 0,
                            timeStamp: 4242, varBinds: [VarBind(OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 3]), .integer(3))])
        return CommunityMessage.encode(version: .v1, community: "public", pdu: pdu.encoded())
    }

    /// A switch that sends syslog (hostname CORE-SW1) and traps from the same address kept
    /// flipping its Sources / Status name to its IP on every trap.
    func testTrapDoesNotRenameItsSource() {
        let store = LogStore()
        store.ingest([parsedLine("<189>Sep 23 10:15:32 CORE-SW1 lldpd: neighbour up", from: "10.1.0.1", id: LogStore.nextID())])
        guard case .trap(let t) = TrapListener.decode(Round5TrapTests.linkDown(3), host: "10.1.0.1", port: 5000,
                                                      received: Date()).item else { return XCTFail("not decoded") }
        store.ingest([TrapReceiver.entry(for: t, registry: Self.registry)])
        store.publishSources()
        XCTAssertEqual(store.sources.first { $0.address == "10.1.0.1" }?.displayName, "CORE-SW1")
        XCTAssertEqual(store.sources.first?.count, 2)
    }

    /// RFC 3584 §3.1: a v1 trap's agent-addr travels as snmpTrapAddress.0 — so the raw text
    /// (the disk log) keeps the device a proxy forwarded the trap for, and typing the address
    /// shown in the Host column finds the line.
    func testV1TrapCarriesItsAgentAddress() throws {
        guard case .trap(let t) = TrapListener.decode(v1Trap(agent: "192.0.2.77"), host: "127.0.0.1", port: 162,
                                                      received: Date()).item else { return XCTFail("not decoded") }
        XCTAssertEqual(t.varBinds.map(\.oid).suffix(2), [TrapReceiver.snmpTrapAddress, TrapReceiver.snmpTrapEnterprise])
        let e = TrapReceiver.entry(for: t, registry: Self.registry)
        XCTAssertEqual(e.hostname, "192.0.2.77")
        XCTAssertEqual(e.field("snmpTrapAddress.0"), "192.0.2.77")
        XCTAssertTrue(e.raw.contains("1.3.6.1.6.3.18.1.3.0=192.0.2.77"), e.raw)
        XCTAssertTrue(ReceivedTrap.trap(t).diskLine?.text.contains("192.0.2.77") ?? false)
        XCTAssertTrue(try matches("192.0.2.77", e), "the Host column's address as a bare word")
        // 0.0.0.0 (an agent that does not fill it in) is not a device address.
        guard case .trap(let z) = TrapListener.decode(v1Trap(agent: "0.0.0.0"), host: "127.0.0.1", port: 162,
                                                      received: Date()).item else { return XCTFail("not decoded") }
        XCTAssertFalse(z.varBinds.contains { $0.oid == TrapReceiver.snmpTrapAddress })
    }

    /// Junk datagrams dropped at a full backlog gate are not log lines: only traps count as
    /// dropped (they used to be counted as received + lost lines).
    func testTrapGateCountsOnlyTraps() throws {
        let gate = BacklogGate(slots: 1)
        XCTAssertTrue(gate.tryEnter(count: 0))                  // the main thread is "busy"
        let port = TestSockets.freePort()
        let l = try TrapListener(port: port, deliver: { _ in }, gate: gate)
        l.resume()
        defer { l.cancel() }
        TestSockets.sendUDP([0x30, 0x03, 0x02, 0x01, 0x07], to: port)          // not SNMP
        TestSockets.sendUDP(Round5TrapTests.linkDown(1), to: port)
        usleep(500_000)
        XCTAssertEqual(gate.leave(), 1, "one trap dropped, the junk datagram not counted")
    }

    // MARK: - Filter

    /// `-( … )` / `!( … )` negate the group (they were the word "-" AND the group).
    func testMinusBeforeParenthesisNegatesTheGroup() throws {
        XCTAssertEqual(try Query.parse("-(a OR b)").root, .not(.or(.text("a"), .text("b"))))
        XCTAssertEqual(try Query.parse("!(a b)").root, .not(.and(.text("a"), .text("b"))))
        XCTAssertEqual(try Query.parse("x -(y)").root, .and(.text("x"), .not(.text("y"))))
        XCTAssertEqual(try Query.parse("-").root, .text("-"))
        let e = parsedLine("<13>Sep 23 10:15:32 h app: keepalive ok")
        XCTAssertFalse(try matches("-(keepalive OR heartbeat)", e))
        XCTAssertTrue(try matches("-(heartbeat OR probe)", e))
    }

    /// PAN-OS THREAT severity "critical" maps to syslog error; `severity:critical` must still
    /// find those rows (the field), as well as syslog-critical lines. `sev:` is syslog only.
    func testSeverityNameAlsoMatchesTheLinesOwnSeverityField() throws {
        let threat = "<12>Sep 23 10:16:01 PA-3220 1,2026/09/23 10:16:01,012801012345,THREAT,vulnerability,2561,2026/09/23 10:16:01,10.1.0.5,93.184.216.34,203.0.113.10,93.184.216.34,allow-web,corp\\alice,,web-browsing,vsys1,trust,untrust,ethernet1/2,ethernet1/1,default,,123457,1,53100,80,41300,80,0x40b000,tcp,reset-both,\"x\",Log4j(91991),vulnerability,critical,client-to-server,7300000000000001"
        let e = parsedLine(threat)
        XCTAssertEqual(e.vendor, .paloAlto)
        XCTAssertEqual(e.field("severity"), "critical")
        XCTAssertEqual(e.severity, .error)
        XCTAssertTrue(try matches("severity:critical", e))
        XCTAssertFalse(try matches("severity!=critical", e))
        XCTAssertTrue(try matches("severity:critical,high", e))
        XCTAssertFalse(try matches("sev:critical", e), "sev: is the syslog severity")
        XCTAssertTrue(try matches("sev:err", e))
        let crit = parsedLine("<10>Sep 23 10:15:32 h kernel: fan failure")
        XCTAssertTrue(try matches("severity:critical", crit))
        XCTAssertFalse(try matches("severity:critical", parsedLine("<14>Sep 23 10:15:32 h app: fine")))
    }

    /// Round 6's claim "a subnet as the value of f:srcip=" for IPv6 (untested until now).
    func testIPv6SubnetInAFieldFilter() throws {
        let e = parsedLine("<189>date=2026-09-23 time=10:15:32 devname=\"FGT\" devid=\"FGT60F\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"notice\" srcip=2001:db8:5::9 dstip=10.1.0.1 action=\"accept\"")
        XCTAssertEqual(e.vendor, .fortigate)
        XCTAssertTrue(try matches("f:srcip=2001:db8::/32", e))
        XCTAssertFalse(try matches("f:srcip=2001:db9::/32", e))
        XCTAssertTrue(try matches("src:2001:db8:5::/48", e))
    }

    // MARK: - Syslog shapes

    /// IOS with `service sequence-numbers`: a counter, the origin host, the sequence number.
    func testCiscoSequenceNumbers() {
        let a = parsedLine("<189>35: 000034: *Sep 23 10:15:32.123: %SYS-5-CONFIG_I: Configured from console by vty0")
        XCTAssertEqual(a.hostname, "", "000034 is the sequence number, not a host")
        XCTAssertEqual(a.program, "%SYS-5-CONFIG_I")
        XCTAssertNotNil(a.deviceTime)
        XCTAssertEqual(a.field("seq"), "35")
        XCTAssertEqual(a.field("seqno"), "000034")
        XCTAssertEqual(a.message, "Configured from console by vty0")

        let b = parsedLine("<187>35: CORE-RTR1: 000034: *Sep 23 10:15:32.123 UTC: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down")
        XCTAssertEqual(b.hostname, "CORE-RTR1")
        XCTAssertEqual(b.program, "%LINK-3-UPDOWN")
        XCTAssertNotNil(b.deviceTime)
        XCTAssertEqual(b.field("seqno"), "000034")

        // No timestamps configured: the counter, then the mnemonic.
        let c = parsedLine("<189>36: %LINK-3-UPDOWN: Interface Gi0/2, changed state to up")
        XCTAssertEqual(c.program, "%LINK-3-UPDOWN")
        XCTAssertEqual(c.field("seq"), "36")

        // The shapes that already worked still do.
        let d = parsedLine("<189>35: CORE-RTR1: *Sep 23 10:15:32.123: %SYS-5-CONFIG_I: Configured")
        XCTAssertEqual(d.hostname, "CORE-RTR1")
        XCTAssertEqual(d.field("seq"), "35")
        XCTAssertNil(d.field("seqno"))
    }

    /// FortiOS `set format csv`: the same pairs separated by commas.
    func testFortiOSCSVFormat() {
        let e = parsedLine("<189>date=2026-09-23,time=10:15:32,devname=\"FGT60F-Branch\",devid=\"FGT60FTK20000000\",logid=\"0000000013\",type=\"traffic\",subtype=\"forward\",level=\"warning\",vd=\"root\",srcip=10.1.0.5,srcport=53012,dstip=8.8.8.8,action=\"deny\",msg=\"blocked, by policy\",policyid=1")
        XCTAssertEqual(e.vendor, .fortigate)
        XCTAssertEqual(e.hostname, "FGT60F-Branch")
        XCTAssertEqual(e.program, "traffic/forward")
        XCTAssertEqual(e.severity, .warning)
        XCTAssertEqual(e.field("srcip"), "10.1.0.5")
        XCTAssertEqual(e.field("msg"), "blocked, by policy")
        XCTAssertEqual(e.field("policyid"), "1")
        XCTAssertNotNil(e.deviceTime)
        // The usual space-separated form is unchanged.
        let s = parsedLine("<189>date=2026-09-23 time=10:15:32 devname=\"FGT\" devid=\"FGT60F\" logid=\"1\" type=\"event\" subtype=\"system\" level=\"error\" msg=\"a, b\"")
        XCTAssertEqual(s.field("msg"), "a, b")
        XCTAssertEqual(s.severity, .error)
    }

    /// A zone-less timestamp is read in the Mac's zone *now*: the parser took a copy of the
    /// zone at first use and kept it after the Mac moved.
    func testZonelessTimestampsFollowATimeZoneChange() throws {
        let saved = NSTimeZone.default
        defer { NSTimeZone.default = saved }
        NSTimeZone.default = TimeZone(identifier: "Asia/Bangkok")!
        let bkk = try XCTUnwrap(parsedLine("<13>2026-09-23T10:15:32 host app: x").deviceTime)
        NSTimeZone.default = TimeZone(identifier: "America/New_York")!
        let ny = try XCTUnwrap(parsedLine("<13>2026-09-23T10:15:32 host app: x").deviceTime)
        XCTAssertEqual(ny.timeIntervalSince(bkk), 11 * 3600, accuracy: 1, "10:15 in New York is 11 h after 10:15 in Bangkok")
    }

    /// A TCP line thrown away in framing (over 1 MB) is counted as lost, and the client-limit
    /// error clears once the clients have gone.
    func testTCPFramingLossIsCountedAndTheClientLimitClears() throws {
        let store = LogStore()
        let server = SyslogServer(store: store)
        server.maxTCPClients = 2
        let port = TestSockets.freePort(SOCK_STREAM)
        server.start(udpPort: 0, tcpPort: port)
        defer { server.stop() }
        XCTAssertTrue(server.isRunning, server.lastError ?? "")

        let fd = try XCTUnwrap(TestSockets.connectTCP(port))
        var big = [UInt8](repeating: 0x41, count: SyslogFraming.maxFrame + 100_000)
        big += Array("\n<13>Sep 23 10:15:32 h app: after the long one\n".utf8)
        var sent = 0
        while sent < big.count {
            let n = big.withUnsafeBytes { send(fd, $0.baseAddress! + sent, big.count - sent, 0) }
            if n <= 0 { break }
            sent += n
        }
        spin { store.lost >= 1 && store.entries.count >= 1 }
        XCTAssertEqual(store.lost, 1, "the 1 MB line")
        XCTAssertEqual(store.entries.last?.message, "after the long one")

        // Past the limit, then back under it.
        var extra: [Int32] = []
        for _ in 0..<3 { if let f = TestSockets.connectTCP(port) { extra.append(f) } }
        spin { server.lastError != nil }
        XCTAssertEqual(server.lastError, SyslogServer.clientLimitText(2))
        close(fd)
        extra.forEach { close($0) }
        spin { server.lastError == nil }
        XCTAssertNil(server.lastError, "clients closed: the listener is no longer shown as failed")
        XCTAssertTrue(server.isRunning)
    }

    /// The inspector's lookup stays right across appends and evictions (it now starts at the
    /// last answer's place in the ring).
    func testEntryLookupAcrossEvictions() {
        let store = LogStore()
        store.limit = 1_000
        store.ingest((0..<500).map { parsedLine("<13>Sep 23 10:15:32 h app: n\($0)", id: LogStore.nextID()) })
        let target = store.entries[400]
        XCTAssertEqual(store.entry(id: target.id)?.message, "n400")
        store.ingest((0..<400).map { parsedLine("<13>Sep 23 10:15:32 h app: m\($0)", id: LogStore.nextID()) })
        XCTAssertEqual(store.entry(id: target.id)?.message, "n400", "still found after appends")
        store.ingest((0..<700).map { parsedLine("<13>Sep 23 10:15:32 h app: k\($0)", id: LogStore.nextID()) })
        XCTAssertNil(store.entry(id: target.id), "rolled out")
        let later = store.entries[10]
        XCTAssertEqual(store.entry(id: later.id)?.message, later.message)
    }

    // MARK: - SNMP

    func testInterfacesChangedColumnIsAnAge() {
        let entry = OID.ifTable.appending(1)
        let rows = SNMPTestModel.joinInterfaces(ifTable: [
            VarBind(entry.appending(2).appending(1), .octetString(Data("Gi1/0/1".utf8))),
            VarBind(entry.appending(9).appending(1), .timeTicks(3_500)),          // changed at uptime 35 s
        ], ifXTable: [], sysUpTime: 200 * 86_400 * 100)
        let r = try? XCTUnwrap(rows.first)
        XCTAssertEqual(r?.sinceChange, 200 * 86_400 * 100 - 3_500)
        XCTAssertEqual(r.map(SNMPTestView.changeText), "199d 23h", "not 00:00:35, which read like 35 s ago")
        let noUptime = SNMPTestModel.joinInterfaces(ifTable: [VarBind(entry.appending(9).appending(1), .timeTicks(3_500))], ifXTable: [])
        XCTAssertEqual(noUptime.first.map(SNMPTestView.changeText), "at 00:00:35")
    }

    func testInterfacesSubtitleSaysWhatIsMissing() {
        XCTAssertEqual(SNMPTestModel.interfacesSubtitle(count: 24, noIfXTable: nil, truncated: false),
                       "24 interfaces from ifTable + ifXTable")
        let v1 = SNMPTestModel.interfacesSubtitle(count: 8, noIfXTable: "the agent has no ifXTable", truncated: false)
        XCTAssertTrue(v1.contains("ifTable only") && v1.contains("32-bit"), v1)
        XCTAssertTrue(SNMPTestModel.interfacesSubtitle(count: 9_000, noIfXTable: nil, truncated: true).contains("stopped at"))
    }

    /// A walk takes its own cap (the Interfaces view walks whole tables of big chassis).
    func testWalkCapIsAParameter() async throws {
        var mib: [VarBind] = []
        for i in 1...300 { mib.append(VarBind(OID([1, 3, 6, 1, 4, 1, 99999, 1, UInt32(i)]), .integer(Int64(i)))) }
        let agent = try FakeAgent(mib: mib)
        defer { agent.stop() }
        let client = SNMPClient(target: SNMPTarget(host: "127.0.0.1", port: agent.port, timeout: 1, retries: 1),
                                credentials: SNMPCredentials(version: .v2c), engines: EngineCache())
        let capped = try await client.walk(OID([1, 3, 6, 1, 4, 1, 99999]), cap: 120)
        XCTAssertTrue(capped.truncated)
        XCTAssertEqual(capped.varBinds.count, 120)
        let all = try await client.walk(OID([1, 3, 6, 1, 4, 1, 99999]), cap: SNMPClient.interfaceWalkCap)
        XCTAssertFalse(all.truncated)
        XCTAssertEqual(all.varBinds.count, 300)
        XCTAssertGreaterThan(SNMPClient.interfaceWalkCap, 22 * 10_000)
    }

    /// After a success the engine is cached as synced; a wrong priv password then got silence
    /// ("no response") on every later Get / Walk, never the diagnosis. Now the engine is
    /// forgotten on that silence and the next request says what is wrong.
    func testWrongPrivPasswordAfterASuccessIsDiagnosed() async throws {
        let agent = try FakeAgent(mib: [VarBind(.sysDescr, .octetString(Data("fake".utf8)))])
        defer { agent.stop() }
        agent.user = FakeAgent.User(name: "lab", auth: .sha1, priv: .aes128, authPassword: "labpassword", privPassword: "labprivpass")
        agent.dropUndecryptable = true
        let engines = EngineCache()
        let target = SNMPTarget(host: "127.0.0.1", port: agent.port, timeout: 0.4, retries: 0)
        var good = SNMPCredentials(version: .v3, username: "lab", authProtocol: .sha1, authPassword: "labpassword",
                                   privProtocol: .aes128, privPassword: "labprivpass")
        _ = try await SNMPClient(target: target, credentials: good, engines: engines).get([.sysDescr])
        good.privPassword = "wrongprivpass"
        let bad = SNMPClient(target: target, credentials: good, engines: engines)
        do { _ = try await bad.get([.sysDescr]); XCTFail("answered") }
        catch { XCTAssertEqual(error as? SNMPError, .timeout) }
        do { _ = try await bad.get([.sysDescr]); XCTFail("answered") }
        catch { XCTAssertEqual(error as? SNMPError, .decryptionError, "the second try is diagnosed") }
        XCTAssertTrue(SNMPTestModel.hint(for: .timeout, target: target, version: .v3).contains("priv password"))
    }

    func testMIBFileWithAnUnusualExtensionSurvivesAReload() async throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "SheepLogR7MIB-\(UUID().uuidString)", directoryHint: .isDirectory)
        let folder = dir.appending(path: "folder", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let src = dir.appending(path: "R7-TEST-MIB.smi")
        try """
        R7-TEST-MIB DEFINITIONS ::= BEGIN
        IMPORTS enterprises FROM SNMPv2-SMI;
        r7Test OBJECT IDENTIFIER ::= { enterprises 99977 }
        END
        """.write(to: src, atomically: true, encoding: .utf8)
        let reg = MIBRegistry()
        reg.userFolderOverride = folder
        reg.loadNow(bundled: MIBRegistry.bundledURLs())
        reg.importFiles([src])
        let deadline = Date().addingTimeInterval(20)
        while reg.isLoading, Date() < deadline { try await Task.sleep(for: .milliseconds(10)) }
        XCTAssertNotNil(reg.modules.first { $0.name == "R7-TEST-MIB" })
        XCTAssertTrue(FileManager.default.fileExists(atPath: folder.appending(path: "R7-TEST-MIB.smi.mib").path))
        XCTAssertTrue(MIBRegistry.mibFiles(in: folder).contains { $0.lastPathComponent == "R7-TEST-MIB.smi.mib" },
                      "what the next load (Reload, relaunch) reads")
        XCTAssertEqual(MIBRegistry.importedName("A.my"), "A.my")
        XCTAssertEqual(MIBRegistry.importedName("A"), "A")
    }

    func testOverlongBERIntegerMustBeASignExtension() throws {
        func int(_ bytes: [UInt8]) throws -> Int64 {
            var r = BERReader([BER.integer, UInt8(bytes.count)] + bytes)
            return try r.readTLV().int64()
        }
        XCTAssertThrowsError(try int([0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE]), "above Int64.max, not -2")
        XCTAssertThrowsError(try int([0xFF, 0x7F, 0, 0, 0, 0, 0, 0, 0]))
        XCTAssertEqual(try int([0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]), .max)
        XCTAssertEqual(try int([0xFF, 0x80, 0, 0, 0, 0, 0, 0, 0]), .min)
        XCTAssertEqual(try int([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE]), -2)
    }

    func testOIDsBERCannotCarryAreRefused() {
        XCTAssertNotNil(SNMPTestModel.oidProblem(OID([3, 6, 1, 2, 1])))
        XCTAssertNotNil(SNMPTestModel.oidProblem(OID([1, 45, 1])))
        XCTAssertNil(SNMPTestModel.oidProblem(OID([1, 3, 6, 1, 2, 1])))
        XCTAssertNil(SNMPTestModel.oidProblem(OID([2, 999, 1])))
        XCTAssertNil(SNMPTestModel.oidProblem(OID([0, 39])))
    }

    func testPortUnreachableIsNotCalledUnreachableHost() {
        let e = SNMPError.network("10.1.0.1 refused UDP 161 (ICMP port unreachable) — SNMP is not listening there")
        let t = SNMPTarget(host: "10.1.0.1", port: 161, timeout: 1, retries: 0)
        XCTAssertTrue(SNMPTestModel.isPortUnreachable("10.1.0.1 refused UDP 161 (ICMP port unreachable) — x"))
        XCTAssertTrue(SNMPTestModel.hint(for: e, target: t, version: .v2c).contains("nothing listens on UDP 161"))
        XCTAssertEqual(SNMPTestModel.hint(for: .network("No route to host"), target: t, version: .v2c),
                       "Check the host name or address, and that this Mac has a route to it.")
    }

    /// A Keychain load still on its way when a run starts must not replace the credentials the
    /// run used (the form showed v3 next to a v2c result).
    func testLateKeychainLoadDoesNotChangeTheFormAfterARunStarts() throws {
        let host = "192.0.2.\(Int.random(in: 10...250))", port: UInt16 = 16_161
        var saved = SNMPCredentials(version: .v3, username: "late-user")
        saved.authPassword = "x-long-password"
        KeychainStore.saveCredentials(saved, host: host, port: port)
        defer { KeychainStore.delete(account: SNMPTestModel.keychainAccount(host: host, port: port)) }
        guard KeychainStore.loadCredentials(host: host, port: port) != nil else { throw XCTSkip("no Keychain in this host") }
        let m = SNMPTestModel.shared
        let before = m.credentials
        defer { m.cancel(); m.applyCredentials(before) }
        m.applyCredentials(SNMPCredentials(version: .v2c))
        SNMPTestModel.keychainQueue.suspend()
        m.setTarget("\(host):\(port)")
        m.timeout = 0.2
        m.retries = 0
        m.quickTest()                                   // runs with v2c, as shown
        SNMPTestModel.keychainQueue.resume()
        spin(1.5) { false }
        XCTAssertEqual(m.version, .v2c)
        XCTAssertNotEqual(m.username, "late-user")
    }

    // MARK: - Packets

    private func store(from pcap: String) throws -> PacketStore {
        let url = CaptureGroundTruthTests.pcapDir.appending(path: pcap)
        var packets: [Packet] = []
        _ = try PcapFile.read(url) { packets += $0 }
        let s = PacketStore()
        s.ingest(packets)
        return s
    }

    private func count(_ s: PacketStore, _ q: String) -> Int {
        s.queryText = q
        s.applyQueryNow(synchronous: true)
        return s.visible.count
    }

    /// IPv6 in ip:/src:/dst: by value and as a subnet (they compared text: a subnet matched
    /// nothing, the uncompressed spelling of an address matched nothing).
    func testPacketFilterIPv6ByValueAndSubnet() throws {
        let s = try store(from: "http-tls.pcap")
        let one = count(s, "ip:2001:fb0:100::207:49")
        XCTAssertGreaterThan(one, 0)
        XCTAssertEqual(count(s, "ip:2001:0fb0:0100:0000:0000:0000:0207:0049"), one)
        XCTAssertGreaterThanOrEqual(count(s, "ip:2001:fb0:100::/48"), one)
        XCTAssertEqual(count(s, "ip:2001:fb0:100::/48"), count(s, "ip:2001:fb0:100::/64"))
        XCTAssertEqual(count(s, "ip:2001:db8::/32"), 0)
        XCTAssertGreaterThan(count(s, "proto:tcp port:443"), 0, "the placeholder's shape works")
    }

    func testHTTPHostIsNotReadFromTheBody() {
        let req = Array("POST /x HTTP/1.1\r\nUser-Agent: t\r\n\r\nhost: not-a-header\r\n".utf8)
        let d = PacketDecoder.decode(PacketFixture.tcp4(51000, 80, seq: 1, ack: 1, flags: 0x18, req))
        guard case .httpRequest(_, _, let host)? = d.app else { return XCTFail("\(String(describing: d.app))") }
        XCTAssertNil(host)
        let ok = PacketDecoder.decode(PacketFixture.tcp4(51000, 80, seq: 1, ack: 1, flags: 0x18,
                                                         Array("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".utf8)))
        guard case .httpRequest(_, _, let h2)? = ok.app else { return XCTFail() }
        XCTAssertEqual(h2, "example.com")
    }

    func testUDPLengthLargerThanTheDatagramIsFlagged() {
        var udp = PacketFixture.udp(40000, 9999, [1, 2, 3, 4])
        udp[4] = 0x01; udp[5] = 0xEC                                  // says 492
        let d = PacketDecoder.decode(Data(PacketFixture.ether(type: 0x0800, PacketFixture.ipv4(proto: 17, udp))))
        XCTAssertTrue(d.info.contains("bad length 492"), d.info)
        let good = PacketDecoder.decode(PacketFixture.udp4(40000, 9999, [1, 2, 3, 4]))
        XCTAssertFalse(good.info.contains("bad length"), good.info)
    }

    func testPacketDetailWordsAndColours() {
        XCTAssertEqual(PacketDetailBuilder.ipFlagsTitle(df: true, mf: true), "Don't fragment, More fragments")
        XCTAssertEqual(PacketDetailBuilder.ipFlagsTitle(df: false, mf: false), "none")
        XCTAssertEqual(PacketDetailBuilder.arpOpcode(isRequest: true, rarp: true), "reverse request (3)")
        XCTAssertEqual(PacketDetailBuilder.arpOpcode(isRequest: false, rarp: false), "reply (2)")
        var d = PacketDecoder.decode(PacketFixture.udp4(40000, 9999, [1]))
        d.info = "GET /FIRST HTTP/1.1"
        XCTAssertNotEqual(PacketTableController.protocolColor(d), PacketTableController.protocolColor(
            PacketDecoder.decode(PacketFixture.tcp4(1, 2, flags: 0x04))), "an Info with the letters RST is not a reset")
    }

    func testFooterSaysPausedNotRolledOut() {
        let t = PacketsFooter.text(shown: 100, inMemory: 100, received: 150, bytes: 1000, filtered: false, file: nil, waiting: 50)
        XCTAssertTrue(t.contains("50 waiting (paused)"), t)
        XCTAssertFalse(t.contains("kept"), t)
        let r = PacketsFooter.text(shown: 100, inMemory: 100, received: 400, bytes: 1000, filtered: false, file: nil, waiting: 50)
        XCTAssertTrue(r.contains("the last 100 of 350 kept"), r)
        XCTAssertTrue(PacketsTableArea.pausedText(3).contains("3 packets are waiting"))
    }

    /// A replaced load stops reading instead of decoding the rest of the file for nothing.
    func testFileReadStopsWhenAsked() throws {
        let url = CaptureGroundTruthTests.pcapDir.appending(path: "http-tls.pcap")
        var n = 0
        _ = try PcapFile.read(url, while: { false }) { n += $0.count }
        XCTAssertEqual(n, 0)
        _ = try PcapFile.read(url, while: { true }) { n += $0.count }
        XCTAssertEqual(n, 172)
    }

    // MARK: - Flows

    private func demoLossFlow() throws -> TCPFlow {
        let flows = TCPFlowAnalyzer.analyze(TCPFlowDemo.packets())
        return try XCTUnwrap(flows.first { $0.serverPort == 443 && $0.retransmissions > 0 })
    }

    /// Three dup ACKs, a fast retransmit, then two resends 200 ms and 700 ms later: those are the
    /// retransmission timer's (Wireshark: fast only within 20 ms of the last dup ACK).
    func testRTOAfterDuplicateACKsIsNotCalledFast() throws {
        let f = try demoLossFlow()
        let texts = f.events.compactMap(\.problem).filter { $0.contains("etransmission of seq") }
        XCTAssertEqual(texts.filter { $0.hasPrefix("Fast retransmission") }.count, 1, "\(texts)")
        XCTAssertEqual(texts.filter { $0.hasPrefix("Retransmission") }.count, 2, "\(texts)")
    }

    /// The ladder is in time order around a loss: an ACK row from before the retransmission
    /// does not take in ACKs sent after it.
    func testLadderRowsDoNotSpanALoss() throws {
        let f = try demoLossFlow()
        let times = Dictionary(uniqueKeysWithValues: TCPFlowDemo.packets().map { ($0.id, $0.timestamp) })
        let losses = f.events.filter { if case .retransmission = $0.kind { return true }; return false }
        for e in f.events {
            switch e.kind {
            case .ack, .dupAck:
                let ts = e.packetIDs.compactMap { times[$0] }
                for l in losses {
                    guard let lt = l.packetIDs.first.flatMap({ times[$0] }) else { continue }
                    XCTAssertTrue(ts.allSatisfy { $0 < lt } || ts.allSatisfy { $0 > lt },
                                  "\(e.kind) row \(e.packetIDs) spans the retransmission at frame \(l.packetIDs)")
                }
            default: break
            }
        }
    }

    /// Fast vs timer retransmissions frame by frame against tshark (skipped without it).
    func testFastRetransmissionFramesMatchTshark() throws {
        guard let tshark = CaptureGroundTruthTests.tshark else { throw XCTSkip("tshark not installed") }
        typealias W = WireConversation
        var w = W(cport: 51240, sport: 443)
        w.handshake(rtt: 0.012)
        for k in 0..<3 { w.s(0.05 + Double(k) * 0.0005, W.ACK, len: 1000) }
        let lost = w.sseq
        w.sseq &+= 1000                                            // never arrives
        w.c(0.0512, W.ACK, ack: lost)
        for k in 0..<3 {
            w.s(0.052 + Double(k) * 0.0005, W.ACK, len: 1000)
            w.c(0.0522 + Double(k) * 0.0005, W.ACK, ack: lost)
        }
        w.s(0.056, W.ACK, len: 1000, seq: lost)                   // fast
        w.s(0.260, W.ACK, len: 1000, seq: lost)                   // timer
        w.c(0.262, W.ACK)
        let url = FileManager.default.temporaryDirectory.appending(path: "SheepLogR7-rto.pcap")
        try PcapFile.write(w.packets, linkType: 1, to: url)
        var read: [Packet] = []
        _ = try PcapFile.read(url) { read += $0 }
        let f = try XCTUnwrap(TCPFlowAnalyzer.analyze(read).first)
        let out = CaptureGroundTruthTests.run(tshark, ["-r", url.path, "-Y", "tcp.analysis.fast_retransmission",
                                                       "-T", "fields", "-e", "frame.number"])
        let theirs = Set(out.split(separator: "\n").compactMap { Int($0) })
        let ours = Set(f.events.filter { $0.problem?.hasPrefix("Fast retransmission") == true }.flatMap(\.packetIDs))
        XCTAssertEqual(ours, theirs)
        XCTAssertEqual(theirs.count, 1)
        let r = try TCPFlowGroundTruthTests().compare(url, tshark: tshark)
        XCTAssertEqual(r.mismatches, [])
    }

    func testShowPacketsCoversALargeGroup() throws {
        let f = try demoLossFlow()
        XCTAssertEqual(FlowView.packetFilter([3, 5], flow: f), "frame:3 OR frame:5")
        let big = FlowView.packetFilter(Array(100...180), flow: f)
        XCTAssertTrue(big.hasPrefix("frame:>=100 frame:<=180 ip:"), big)
        XCTAssertNoThrow(try Query.parse(big))
    }

    /// "SNMP trap" is not a syslog format a source can be forced to.
    func testSourcesVendorChoicesLeaveOutTraps() {
        XCTAssertFalse(VendorOverridePicker.choices(current: nil).contains(.snmpTrap))
        XCTAssertTrue(VendorOverridePicker.choices(current: nil).contains(.unknown))
        XCTAssertTrue(VendorOverridePicker.choices(current: .snmpTrap).contains(.snmpTrap), "one set earlier still shows")
    }

    /// OWASP's list: a cell starting with CR is neutralised too (it was = + - @ tab only).
    func testCSVCellStartingWithCarriageReturnIsNeutralised() {
        XCTAssertEqual(Format.csvField("\r=1+1"), "\"'\r=1+1\"")
        XCTAssertEqual(Format.csvField("=1+1"), "'=1+1")
        XCTAssertEqual(Format.csvField("plain"), "plain")
    }

    // MARK: - Exports read back (the Export… / Save… paths, without the panels)

    /// RFC 4180 rows (quoted cells with "" and line breaks).
    private static func csvRows(_ text: String) -> [[String]] {
        var rows: [[String]] = [], row: [String] = [], cell = "", quoted = false
        var it = Array(text).makeIterator()
        var pending: Character? = nil
        while let c = pending ?? it.next() {
            pending = nil
            if quoted {
                if c == "\"" {
                    if let n = it.next() { if n == "\"" { cell.append("\"") } else { quoted = false; pending = n } } else { quoted = false }
                } else { cell.append(c) }
            } else if c == "\"" { quoted = true }
            else if c == "," { row.append(cell); cell = "" }
            else if c == "\r\n" || c == "\n" { row.append(cell); rows.append(row); row = []; cell = "" }
            else { cell.append(c) }
        }
        if !cell.isEmpty || !row.isEmpty { row.append(cell); rows.append(row) }
        return rows
    }

    func testLogExportsReadBack() throws {
        let dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().appending(path: "Tests/corpus")
        var lines: [String] = []
        for f in try FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) where f.pathExtension == "log" {
            lines += try String(contentsOf: f, encoding: .utf8).split(separator: "\n").map(String.init)
        }
        lines.append("<13>Sep 23 10:15:32 h app: =HYPERLINK(\"http://x\") and, a \"quote\"")
        lines.append("<13>Sep 23 10:15:32 h app: two\nlines")
        let store = LogStore()
        store.ingest(lines.map { parsedLine($0, id: LogStore.nextID()) })
        let rows = store.exportRows
        XCTAssertEqual(rows.count, lines.count)

        let csv = Self.csvRows(LogStore.exportCSV(rows))
        XCTAssertEqual(csv.first, ["received", "host", "vendor", "severity", "facility", "program", "message", "raw"])
        XCTAssertEqual(csv.count, rows.count + 1)
        for (r, e) in zip(csv.dropFirst(), rows) {
            XCTAssertEqual(r.count, 8)
            let raw = r[7].hasPrefix("'") && "=+-@\t\r".contains(e.raw.first ?? " ") ? String(r[7].dropFirst()) : r[7]
            XCTAssertEqual(raw, e.raw)
            XCTAssertEqual(r[2], e.vendor.label)
        }
        let log = LogStore.exportText(rows)
        let logLines = log.split(separator: "\n", omittingEmptySubsequences: false).dropLast()
        XCTAssertEqual(logLines.count, rows.count, "one entry per line")
        XCTAssertTrue(logLines.contains { $0.hasSuffix("two#012lines") })
    }

    func testPcapSaveReadsBackInTcpdump() throws {
        let s = try store(from: "http-tls.pcap")
        let url = FileManager.default.temporaryDirectory.appending(path: "SheepLogR7-save.pcap")
        try s.save(to: url)
        var back: [Packet] = []
        _ = try PcapFile.read(url) { back += $0 }
        XCTAssertEqual(back.count, 172)
        XCTAssertEqual(back.map(\.data), s.packets.map(\.data))
        let tcpdump = "/usr/sbin/tcpdump"
        guard FileManager.default.isExecutableFile(atPath: tcpdump) else { return }
        let out = CaptureGroundTruthTests.run(tcpdump, ["-nn", "-r", url.path])
        XCTAssertEqual(out.split(separator: "\n").count, 172)
    }

    // MARK: - Round 6 claims without a test

    func testFormatCountGroupsThousands() {
        XCTAssertEqual(Format.count(1_234_567), "1,234,567")
        XCTAssertEqual(Format.count(999), "999")
    }

    func testInterfacePickerTitleDoesNotRepeatTheName() {
        XCTAssertEqual(CaptureInterface(name: "en2", description: "Ethernet Adapter (en2)", addresses: [], isUp: true,
                                        isLoopback: false).pickerTitle, "Ethernet Adapter (en2)")
        XCTAssertEqual(CaptureInterface(name: "en0", description: "Wi-Fi", addresses: ["192.168.1.36"], isUp: true,
                                        isLoopback: false).pickerTitle, "Wi-Fi (en0) — 192.168.1.36")
    }

    func testPortFieldTakesDigitsOnly() {
        XCTAssertEqual(PortField.port("514"), 514)
        XCTAssertEqual(PortField.port("0514"), 514)
        XCTAssertEqual(PortField.port("0"), 0)
        for bad in ["5 14", "51a4", "70000", "+514", "", " 514", "-1"] { XCTAssertNil(PortField.port(bad), bad) }
    }

    /// On any Mac, not only one set to the Buddhist calendar.
    func testDateFormattersAreGregorianPOSIX() {
        for f in [Format.clock, Format.stamp, Format.day, Format.hms, Format.compactStamp] {
            XCTAssertEqual(f.calendar.identifier, .gregorian)
            XCTAssertEqual(f.locale.identifier, "en_US_POSIX")
        }
        let thai = DateFormatter()
        thai.locale = Locale(identifier: "th_TH")
        thai.calendar = Calendar(identifier: .buddhist)
        thai.dateFormat = "yyyy"
        let d = Date(timeIntervalSince1970: 1_790_000_000)
        XCTAssertEqual(thai.string(from: d), "2569", "what a bare formatter prints on the owner's Mac")
        XCTAssertTrue(Format.day.string(from: d).hasPrefix("2026"))
    }
}
