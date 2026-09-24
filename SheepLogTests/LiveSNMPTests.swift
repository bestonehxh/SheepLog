import XCTest
@testable import SheepLog

/// Against macOS's own snmpd started by `Tests/snmp-lab.sh` (UDP 127.0.0.1:1161). Skipped
/// unless SHEEPLOG_SNMP_LAB=1 (with xcodebuild: TEST_RUNNER_SHEEPLOG_SNMP_LAB=1).
/// net-snmp 5.6 has no SHA-2 / AES-192/256 — those are covered by SNMPClientTests' fake agent.
final class LiveSNMPTests: XCTestCase {
    /// SNMP_LAB_PORT (as given to snmp-lab.sh), default 1161.
    private static let port: UInt16 = {
        let env = ProcessInfo.processInfo.environment
        return (env["SNMP_LAB_PORT"] ?? env["TEST_RUNNER_SNMP_LAB_PORT"]).flatMap(UInt16.init) ?? 1161
    }()
    private let target = SNMPTarget(host: "127.0.0.1", port: LiveSNMPTests.port, timeout: 2, retries: 1)

    override func setUpWithError() throws {
        let env = ProcessInfo.processInfo.environment
        guard env["SHEEPLOG_SNMP_LAB"] == "1" || env["TEST_RUNNER_SHEEPLOG_SNMP_LAB"] == "1" else {
            throw XCTSkip("Start Tests/snmp-lab.sh and set SHEEPLOG_SNMP_LAB=1 to run the live tests.")
        }
    }

    private var v2c: SNMPCredentials { SNMPCredentials(version: .v2c, community: "public") }

    private func v3(user: String = "lab", auth: AuthProtocol = .sha1, authPassword: String = "labpassword",
                    priv: PrivProtocol = .aes128, privPassword: String = "labprivpass") -> SNMPCredentials {
        SNMPCredentials(version: .v3, username: user, authProtocol: auth, authPassword: authPassword,
                        privProtocol: priv, privPassword: privPassword)
    }

    /// `snmpwalk … | wc -l` — what net-snmp's own tool counts.
    private func netSnmpWalkCount(_ oid: String) throws -> Int { try netSnmpWalk(oid).count }

    /// `snmpwalk -On` — the OIDs net-snmp's own tool gets, in order.
    private func netSnmpWalk(_ oid: String) throws -> [String] {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/snmpwalk")
        p.arguments = ["-v2c", "-c", "public", "-On", "127.0.0.1:\(Self.port)", oid]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = Pipe()
        try p.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(decoding: data, as: UTF8.self).split(separator: "\n").filter { $0.hasPrefix(".") }
            .map { String($0.prefix { $0 != " " }) }
    }

    func testV2cGetAndWalkSystem() async throws {
        let client = SNMPClient(target: target, credentials: v2c, engines: EngineCache())
        let r = try await client.get([.sysDescr, .sysName])
        guard case .octetString(let d) = r.varBinds[0].value else { return XCTFail("sysDescr: \(r.varBinds)") }
        XCTAssertTrue(String(decoding: d, as: UTF8.self).hasPrefix("Darwin"))
        XCTAssertEqual(r.varBinds[1].value, .octetString(Data("sheeplog-lab".utf8)))

        let w = try await client.walk(.system)
        XCTAssertEqual(w.varBinds.count, try netSnmpWalkCount("system"))
        // "localhost" resolves to ::1 first; the lab listens on 127.0.0.1 only.
        var viaName = target
        viaName.host = "localhost"
        let l = try await SNMPClient(target: viaName, credentials: v2c, engines: EngineCache()).get([.sysName])
        XCTAssertEqual(l.varBinds.first?.value, .octetString(Data("sheeplog-lab".utf8)))
        let ifs = try await client.walk(.ifTable)
        XCTAssertEqual(ifs.varBinds.count, try netSnmpWalkCount("ifTable"))

        let v1 = SNMPClient(target: target, credentials: SNMPCredentials(version: .v1, community: "public"), engines: EngineCache())
        let w1 = try await v1.walk(.system)
        XCTAssertEqual(w1.varBinds.map(\.oid), w.varBinds.map(\.oid))
    }

    /// The whole tree (thousands of var-binds): same OIDs, same order as net-snmp's snmpwalk.
    func testWholeTreeWalkMatchesNetSnmp() async throws {
        let client = SNMPClient(target: target, credentials: v2c, engines: EngineCache())
        let chunks = LockedBox(0)
        let t0 = Date()
        let w = try await client.walk(OID([1, 3, 6, 1])) { _ in chunks.mutate { $0 += 1 } }
        let elapsed = Date().timeIntervalSince(t0)
        let theirs = try netSnmpWalk(".1.3.6.1")
        let expected = theirs.count
        print("live whole-tree walk: \(w.varBinds.count) var-binds (snmpwalk \(expected)), \(w.requests) requests, "
              + "\(chunks.value) chunks, \(String(format: "%.2f", elapsed)) s, truncated \(w.truncated)")
        if expected < SNMPClient.walkCap {
            // The agent's own tables (udpEndpointTable, hrSWRun…) move between two walks by a
            // few rows; everything else must match, and both must reach the same end.
            let ours = w.varBinds.map { $0.oid.description }
            let onlyOurs = Set(ours).subtracting(theirs), onlyTheirs = Set(theirs).subtracting(ours)
            print("only ours: \(onlyOurs.sorted().prefix(8)) only snmpwalk: \(onlyTheirs.sorted().prefix(8))")
            XCTAssertLessThan(onlyOurs.count + onlyTheirs.count, 40)
            XCTAssertEqual(ours.last, theirs.last)
        } else {
            XCTAssertTrue(w.truncated)
        }
        XCTAssertEqual(w.varBinds.map(\.oid), w.varBinds.map(\.oid).sorted())
        let v3 = SNMPClient(target: target, credentials: v3(), engines: EngineCache())
        let w3 = try await v3.walk(.ifTable)
        let w2 = try await client.walk(.ifTable)
        XCTAssertEqual(w3.varBinds.map(\.oid), w2.varBinds.map(\.oid))
    }

    func testV3AuthPrivSHAAES() async throws {
        let cache = EngineCache()
        let client = SNMPClient(target: target, credentials: v3(), engines: cache)
        let engine = try await client.discover()
        XCTAssertNotNil(engine)
        XCTAssertGreaterThan(engine?.engineID.count ?? 0, 4)
        let r = try await client.get([.sysDescr, .sysName])
        XCTAssertEqual(r.varBinds[1].value, .octetString(Data("sheeplog-lab".utf8)))
        XCTAssertEqual(r.engine?.engineID, engine?.engineID)
        let w = try await client.walk(.system)
        XCTAssertEqual(w.varBinds.count, try netSnmpWalkCount("system"))
    }

    func testV3OtherLevelsAndErrors() async throws {
        // authNoPriv with the same user.
        let authOnly = SNMPClient(target: target, credentials: v3(priv: .none), engines: EngineCache())
        let a = try await authOnly.get([.sysName])
        XCTAssertEqual(a.varBinds.first?.value, .octetString(Data("sheeplog-lab".utf8)))

        // MD5 / DES user.
        let md5 = SNMPClient(target: target, credentials: v3(user: "labmd5", auth: .md5, priv: .des), engines: EngineCache())
        let m = try await md5.walk(.system)
        XCTAssertEqual(m.varBinds.count, try netSnmpWalkCount("system"))

        do {
            _ = try await SNMPClient(target: target, credentials: v3(authPassword: "wrongpassword"), engines: EngineCache()).get([.sysName])
            XCTFail("wrong auth password accepted")
        } catch { XCTAssertEqual(error as? SNMPError, .wrongDigest) }

        do {
            _ = try await SNMPClient(target: target, credentials: v3(user: "nobody"), engines: EngineCache()).get([.sysName])
            XCTFail("unknown user accepted")
        } catch { XCTAssertEqual(error as? SNMPError, .unknownUser) }

        do {
            _ = try await SNMPClient(target: target, credentials: v3(privPassword: "wrongprivpass"), engines: EngineCache()).get([.sysName])
            XCTFail("wrong priv password accepted")
        } catch {
            // net-snmp drops what it cannot decrypt; the client tells that apart from a dead
            // agent by asking again authNoPriv.
            XCTAssertEqual(error as? SNMPError, .decryptionError)
        }
    }
}

// MARK: - Scenarios (round 2): the Test pane's operations against the lab, semantically

extension LiveSNMPTests {
    private func tool(_ path: String, _ args: [String]) throws -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = Pipe()
        try p.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }

    /// Quick Test's seven objects on every version and both v3 users: all present, same sysName.
    func testQuickTestObjectsOnEveryVersion() async throws {
        let creds: [SNMPCredentials] = [SNMPCredentials(version: .v1, community: "public"), v2c,
                                        v3(), v3(user: "labmd5", auth: .md5, priv: .des), v3(priv: .none)]
        for c in creds {
            let client = SNMPClient(target: target, credentials: c, engines: EngineCache())
            if c.version == .v3 { _ = try await client.discover() }
            let r = try await client.get(SNMPTestModel.systemOIDs)
            XCTAssertEqual(r.varBinds.map(\.oid), SNMPTestModel.systemOIDs, "\(c.version) \(c.username)")
            XCTAssertFalse(r.varBinds.contains { $0.value.isException }, "\(c.version) \(c.username): \(r.varBinds)")
            XCTAssertEqual(r.varBinds[4].value, .octetString(Data("sheeplog-lab".utf8)))
        }
    }

    /// The Interfaces view against `snmptable ifTable`: same rows, same ifDescr / ifOperStatus,
    /// speed from ifSpeed (bit/s) unless ifHighSpeed (Mb/s) says more.
    @MainActor
    func testInterfacesJoinMatchesSnmptable() async throws {
        MIBRegistry.shared.loadNow(bundled: MIBRegistry.bundledURLs())
        let client = SNMPClient(target: target, credentials: v2c, engines: EngineCache())
        let a = try await client.walk(.ifTable)
        let b = try await client.walk(.ifXTable)
        let rows = SNMPTestModel.joinInterfaces(ifTable: a.varBinds, ifXTable: b.varBinds)

        let table = try tool("/usr/bin/snmptable", ["-v2c", "-c", "public", "-Cf", "|", "127.0.0.1:\(Self.port)", "IF-MIB::ifTable"])
        let lines = table.split(separator: "\n").map(String.init).filter { $0.contains("|") }
        let header = try XCTUnwrap(lines.first).split(separator: "|", omittingEmptySubsequences: false).map(String.init)
        let col = { (name: String) in header.firstIndex(of: name)! }
        var theirs: [UInt32: [String]] = [:]
        for line in lines.dropFirst() {
            let cells = line.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
            theirs[UInt32(cells[col("ifIndex")])!] = cells
        }
        XCTAssertEqual(rows.map(\.index), theirs.keys.sorted(), "same interfaces")
        var high: [UInt32: UInt64] = [:]
        for vb in b.varBinds where OID.ifXTable.appending([1, 15]).isPrefix(of: vb.oid) {
            if case .gauge32(let v) = vb.value { high[vb.oid.parts.last!] = UInt64(v) }
        }
        for r in rows {
            let t = try XCTUnwrap(theirs[r.index])
            XCTAssertEqual(r.descr, t[col("ifDescr")], "ifDescr \(r.index)")
            XCTAssertEqual(r.oper, t[col("ifOperStatus")], "ifOperStatus \(r.index)")
            XCTAssertEqual(r.admin, t[col("ifAdminStatus")], "ifAdminStatus \(r.index)")
            let ifSpeed = UInt64(t[col("ifSpeed")]) ?? 0
            let highBits = (high[r.index] ?? 0) * 1_000_000
            let expected = highBits >= ifSpeed + 1_000_000 ? highBits : ifSpeed
            XCTAssertEqual(r.speedBits, expected, "speed \(r.index): ifSpeed \(ifSpeed) ifHighSpeed \(high[r.index] ?? 0)")
            if ifSpeed > 0, ifSpeed < UInt64(UInt32.max) {
                XCTAssertEqual(r.speedBits, ifSpeed, "ifSpeed is exact below 4.29 Gb/s (\(r.name))")
            }
        }
        print("interfaces: \(rows.count) rows = snmptable \(theirs.count); e.g. "
              + rows.filter { $0.speedBits > 0 }.prefix(4).map { "\($0.name) \($0.oper) \($0.speedText)" }.joined(separator: ", "))
    }

    /// GETNEXT past the last object: v2c answers endOfMibView (no error), v1 noSuchName.
    func testGetNextPastTheEndOfTheMIB() async throws {
        let client = SNMPClient(target: target, credentials: v2c, engines: EngineCache())
        let tail = try await client.walk(OID([1, 3, 6, 1, 6, 3]))
        let last = try XCTUnwrap(tail.varBinds.last?.oid)
        let r = try await client.getNext([last])
        XCTAssertEqual(r.varBinds.first?.value, .endOfMibView, "\(r.varBinds)")
        let beyond = try await client.getNext([OID([2, 99])])
        XCTAssertEqual(beyond.varBinds.first?.value, .endOfMibView)
        let v1 = SNMPClient(target: target, credentials: SNMPCredentials(version: .v1, community: "public"), engines: EngineCache())
        do { _ = try await v1.getNext([last]); XCTFail("v1 past the end") }
        catch { XCTAssertEqual(error as? SNMPError, .response(status: 2, index: 1)) }
        // A walk rooted at the last instance: the instance itself (by GET), not an error.
        let tailWalk = try await client.walk(last)
        XCTAssertEqual(tailWalk.varBinds.map(\.oid), [last])
    }

    /// Walks by MIB name resolve to what snmpwalk walks for the same name.
    @MainActor
    func testWalkByName() async throws {
        let reg = MIBRegistry.shared
        reg.loadNow(bundled: MIBRegistry.bundledURLs())
        let client = SNMPClient(target: target, credentials: v2c, engines: EngineCache())
        let names = ["ifDescr": "IF-MIB::ifDescr", "IF-MIB::ifTable": "IF-MIB::ifTable", "ifTable": "IF-MIB::ifTable",
                     "system": "SNMPv2-MIB::system", "IF-MIB::ifOperStatus": "IF-MIB::ifOperStatus"]
        for (ours, theirs) in names {
            let oid = try XCTUnwrap(reg.oid(forName: ours), ours)
            let w = try await client.walk(oid)
            XCTAssertEqual(w.varBinds.map { $0.oid.description }, try netSnmpWalk(theirs), ours)
        }
    }

    /// Host names, IPv6 literals with and without brackets (the lab listens on [::1] too).
    func testHostForms() async throws {
        for host in ["localhost", "127.0.0.1", "::1", "[::1]"] {
            var t = target
            t.host = host
            let r = try await SNMPClient(target: t, credentials: v2c, engines: EngineCache()).get([.sysName])
            XCTAssertEqual(r.varBinds.first?.value, .octetString(Data("sheeplog-lab".utf8)), host)
        }
        var t6 = target
        t6.host = "::1"
        let r3 = try await SNMPClient(target: t6, credentials: v3(), engines: EngineCache()).get([.sysName])
        XCTAssertEqual(r3.varBinds.first?.value, .octetString(Data("sheeplog-lab".utf8)), "v3 over IPv6")
    }

    /// macOS's snmpd has no VACM (any community is accepted), so this only proves spaces and
    /// UTF-8 survive the encoder; SNMPClientTests checks the bytes on the wire.
    func testCommunityWithSpacesAndUTF8() async throws {
        let c = SNMPCredentials(version: .v2c, community: "my comm ไทย é")
        let r = try await SNMPClient(target: target, credentials: c, engines: EngineCache()).get([.sysName])
        XCTAssertEqual(r.varBinds.first?.value, .octetString(Data("sheeplog-lab".utf8)))
    }

    /// Values as the Test pane shows them, next to net-snmp's own rendering.
    @MainActor
    func testFormattingAgainstTheLab() async throws {
        let reg = MIBRegistry.shared
        reg.loadNow(bundled: MIBRegistry.bundledURLs())
        let client = SNMPClient(target: target, credentials: v2c, engines: EngineCache())
        let macs = try await client.walk(OID.ifTable.appending([1, 6]))       // ifPhysAddress
        let mac = try XCTUnwrap(macs.varBinds.first { vb in
            if case .octetString(let d) = vb.value { return d.count == 6 }
            return false
        })
        let shown = reg.format(mac)
        XCTAssertNotNil(shown.range(of: #"^([0-9a-f]{2}:){5}[0-9a-f]{2}$"#, options: .regularExpression), shown)
        let theirs = try tool("/usr/bin/snmpget", ["-v2c", "-c", "public", "-Oqv", "127.0.0.1:\(Self.port)", mac.oid.dotted])
            .trimmingCharacters(in: .whitespacesAndNewlines)
        XCTAssertEqual(shown.split(separator: ":").map { UInt8($0, radix: 16) },
                       theirs.split(separator: ":").map { UInt8($0, radix: 16) }, "same bytes as snmpget (\(theirs))")

        let r = try await client.get([.sysUpTime, OID.ifTable.appending([1, 8, 1]), OID.ifXTable.appending([1, 6, 1]), .sysDescr])
        let up = reg.format(r.varBinds[0])
        XCTAssertNotNil(up.range(of: #"\(\d+\)$"#, options: .regularExpression), "duration and raw ticks: \(up)")
        XCTAssertEqual(reg.format(r.varBinds[1]), "up(1)", "lo0 ifOperStatus")
        guard case .counter64 = r.varBinds[2].value else { return XCTFail("ifHCInOctets: \(r.varBinds[2])") }
        XCTAssertEqual(reg.format(r.varBinds[2]), r.varBinds[2].value.display)
        XCTAssertTrue(reg.format(r.varBinds[3]).hasPrefix("Darwin"))
    }

    /// A non-empty contextName reaches the agent; net-snmp without VACM answers noSuchObject for
    /// a context it does not have (no error, no crash).
    func testV3ContextName() async throws {
        var c = v3()
        c.contextName = "no-such-context"
        let r = try await SNMPClient(target: target, credentials: c, engines: EngineCache()).get([.sysName])
        XCTAssertEqual(r.varBinds.first?.value, .noSuchObject)
        c.contextName = ""
        let ok = try await SNMPClient(target: target, credentials: c, engines: EngineCache()).get([.sysName])
        XCTAssertEqual(ok.varBinds.first?.value, .octetString(Data("sheeplog-lab".utf8)))
    }

    /// Cancel against a black hole (1 s × 6 tries) answers at once, not after the next poll slice.
    func testCancelAgainstBlackHoleIsImmediate() async throws {
        // A socket that is bound and never answers: a black hole on every network (10.255.255.1
        // is one only where nothing routes it — a router answering "network unreachable" made
        // this fail with .network after 30 ms).
        let held = try XCTUnwrap(TestSockets.holdIPv4(SOCK_DGRAM))
        defer { close(held.fd) }
        let hole = SNMPTarget(host: "127.0.0.1", port: held.port, timeout: 1, retries: 5)
        let client = SNMPClient(target: hole, credentials: v2c, engines: EngineCache())
        var worst: TimeInterval = 0
        for delay in [30, 250, 1_100] {
            let task = Task { try await client.get(SNMPTestModel.systemOIDs) }
            try await Task.sleep(for: .milliseconds(delay))
            let c0 = Date()
            task.cancel()
            do { _ = try await task.value; XCTFail("black hole answered") }
            catch { XCTAssertEqual(error as? SNMPError, .cancelled) }
            worst = max(worst, Date().timeIntervalSince(c0))
        }
        print("black-hole cancel latency: worst \(Int(worst * 1000)) ms")
        XCTAssertLessThan(worst, 0.1)
    }

    /// The agent is rebooted (same engine ID, boots + 1) or replaced (new engine ID) under a
    /// client that has the engine cached: the next request re-syncs / re-discovers by itself.
    func testEngineRediscoveryAfterAgentRestart() async throws {
        let script = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appending(path: "Tests/snmp-lab.sh")
        let port: UInt16 = 1_171
        let tmp = FileManager.default.temporaryDirectory.appending(path: "SheepLogLab-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        func lab(_ args: [String], keep: Bool = false) throws {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/bin/bash")
            p.arguments = [script.path] + args
            var env = ProcessInfo.processInfo.environment
            env["TMPDIR"] = tmp.path
            env["SNMP_LAB_PORT"] = String(port)
            if keep { env["SNMP_LAB_KEEP_STATE"] = "1" }
            p.environment = env
            p.standardOutput = Pipe()
            p.standardError = Pipe()
            try p.run()
            p.waitUntilExit()
            XCTAssertEqual(p.terminationStatus, 0, "snmp-lab.sh \(args)")
        }
        try lab([])
        defer { try? lab(["stop"]); try? FileManager.default.removeItem(at: tmp) }
        let t = SNMPTarget(host: "127.0.0.1", port: port, timeout: 1, retries: 1)
        let client = SNMPClient(target: t, credentials: v3(), engines: EngineCache())
        let first = try await client.get([.sysName])
        let id1 = try XCTUnwrap(first.engine?.engineID)

        // Rebooted: same engine ID, boots 2 — notInTimeWindows, then a re-sync.
        try lab(["stop"])
        try lab([], keep: true)
        let second = try await client.get([.sysName])
        XCTAssertEqual(second.varBinds.first?.value, .octetString(Data("sheeplog-lab".utf8)))
        XCTAssertEqual(second.engine?.engineID, id1)
        XCTAssertEqual(second.engine?.boots, 2)

        // Replaced: state wiped, a new engine ID — unknownEngineIDs, then re-discovery.
        try lab(["stop"])
        try lab([])
        let third = try await client.get([.sysName])
        XCTAssertEqual(third.varBinds.first?.value, .octetString(Data("sheeplog-lab".utf8)))
        XCTAssertNotEqual(third.engine?.engineID, id1)
        XCTAssertEqual(third.engine?.boots, 1)
        let w = try await client.walk(.system)
        XCTAssertGreaterThan(w.varBinds.count, 5, "GETBULK on the re-discovered engine")
    }
}
