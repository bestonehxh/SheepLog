import XCTest
@testable import SheepLog

/// Round 5: SNMPv3 against agents that behave like real ones (the in-process `FakeAgent` with
/// the quirks of embedded agents, Cisco contexts, reboots and a Mac that slept), checked
/// against what net-snmp's `snmpget` / `snmpwalk` do.
final class Round5SNMPTests: XCTestCase {
    private func table(_ rows: Int) -> [VarBind] {
        var out: [VarBind] = [
            VarBind(.sysDescr, .octetString(Data("SheepLog fake agent".utf8))),
            VarBind(.sysName, .octetString(Data("fake-1".utf8))),
        ]
        for col: UInt32 in [1, 2] {
            for i in 1...UInt32(rows) {
                let oid = OID.ifTable.appending([1, col, i])
                out.append(VarBind(oid, col == 1 ? .integer(Int64(i)) : .octetString(Data("port\(i)".utf8))))
            }
        }
        return out.sorted { $0.oid < $1.oid }
    }

    private func agent(rows: Int = 10, auth: AuthProtocol = .sha1, priv: PrivProtocol = .aes128) throws -> (FakeAgent, SNMPCredentials) {
        let a = try FakeAgent(mib: table(rows))
        a.user = FakeAgent.User(name: "lab", auth: auth, priv: priv, authPassword: "labpassword", privPassword: "labprivpass")
        let c = SNMPCredentials(version: .v3, username: "lab", authProtocol: auth, authPassword: "labpassword",
                                privProtocol: priv, privPassword: "labprivpass")
        return (a, c)
    }

    private func client(_ a: FakeAgent, _ c: SNMPCredentials, cache: EngineCache = EngineCache(),
                        timeout: Double = 1, retries: Int = 1) -> SNMPClient {
        SNMPClient(target: SNMPTarget(host: "127.0.0.1", port: a.port, timeout: timeout, retries: retries),
                   credentials: c, engines: cache)
    }

    /// Discovery answered with boots 0 / time 0 (many embedded agents): the authenticated
    /// probe gets a notInTimeWindows report with the real clock and is sent again — four
    /// messages before the answer, as snmpget sends.
    func testDiscoveryReportWithZeroBootsAndTime() async throws {
        let (a, c) = try agent()
        defer { a.stop() }
        a.discoveryZeroTime = true
        let r = try await client(a, c).get([.sysName])
        XCTAssertEqual(r.varBinds.first?.value, .octetString(Data("fake-1".utf8)))
        XCTAssertEqual(r.engine?.boots, a.boots)
        XCTAssertEqual(a.v3Requests, 4, "discovery, time probe, its repeat, the GET")
    }

    /// We say msgMaxSize 65507 (net-snmp's value for UDP). An agent that drops larger ones
    /// times out, as snmpget does; one that says why is told apart.
    func testAgentRejectingLargeMsgMaxSize() async throws {
        let (a, c) = try agent()
        defer { a.stop() }
        _ = try await client(a, c).get([.sysName])
        XCTAssertEqual(a.lastMsgMaxSize, 65507)
        a.maxAcceptedMsgSize = 1500
        let t0 = Date()
        do { _ = try await client(a, c, timeout: 0.3, retries: 1).get([.sysName]); XCTFail("answered") }
        catch { XCTAssertEqual(error as? SNMPError, .timeout) }
        XCTAssertLessThan(Date().timeIntervalSince(t0), 2)
        a.reportInvalidMsgs = true
        do { _ = try await client(a, c, timeout: 0.3, retries: 0).get([.sysName]); XCTFail("answered") }
        catch {
            guard case .decode(let text) = error as? SNMPError else { return XCTFail("\(error)") }
            XCTAssertTrue(text.contains("snmpInvalidMsgs"), text)
        }
    }

    /// GETBULK answered with fewer repetitions than asked (agents cap them): the walk goes on
    /// from the last OID returned and gets every row.
    func testBulkWithFewerRepetitionsThanAsked() async throws {
        let (a, c) = try agent(rows: 40)
        defer { a.stop() }
        a.bulkCap = 3
        let w = try await client(a, c).walk(.ifTable)
        XCTAssertEqual(w.varBinds.count, 80)
        XCTAssertNil(w.stopReason)
        XCTAssertGreaterThanOrEqual(w.requests, 80 / 3)
    }

    /// The same OID twice in one response (a buggy agent): the walk stops there, as snmpwalk
    /// does ("OID not increasing"), and says why — no loop, no silent short result.
    func testSameOIDTwiceInOneResponse() async throws {
        let (a, c) = try agent(rows: 40)
        defer { a.stop() }
        a.duplicateInBulk = true
        let w = try await client(a, c).walk(.ifTable)
        XCTAssertEqual(w.varBinds.count, 2)
        let why = try XCTUnwrap(w.stopReason)
        XCTAssertTrue(why.contains("OID not increasing"), why)
        XCTAssertEqual(Set(w.varBinds.map(\.oid)).count, w.varBinds.count, "no duplicate rows")
    }

    /// A "SHA-256" agent that truncates its digest to 16 bytes (RFC 7860 says 24): a clear
    /// error at the first answer — not "wrong password", not a wait for the timeout.
    func testSHA256DigestTruncatedTo16Bytes() async throws {
        let (a, c) = try agent(auth: .sha256, priv: .aes128)
        defer { a.stop() }
        a.shortDigest = true
        let t0 = Date()
        do { _ = try await client(a, c, timeout: 2, retries: 2).get([.sysName]); XCTFail("accepted") }
        catch {
            guard case .decode(let text) = error as? SNMPError else { return XCTFail("\(error)") }
            XCTAssertTrue(text.contains("16 bytes") && text.contains("SHA-256") && text.contains("24"), text)
        }
        XCTAssertLessThan(Date().timeIntervalSince(t0), 1.5, "no retries until the timeout")
    }

    /// Cisco's per-VLAN contexts: `vlan-10` answers from its own instance; an unknown context
    /// is the snmpUnknownContexts report in words.
    func testNonEmptyContext() async throws {
        let (a, c0) = try agent()
        var c = c0
        defer { a.stop() }
        let bridge = OID([1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2])
        a.contexts = ["vlan-10": [VarBind(bridge.appending([0, 0x1c, 0x0e, 0x87, 0x78, 1]), .integer(5)),
                                  VarBind(bridge.appending([0, 0x1c, 0x0e, 0x87, 0x78, 2]), .integer(7))]]
        c.contextName = "vlan-10"
        let w = try await client(a, c).walk(bridge)
        XCTAssertEqual(w.varBinds.map(\.value), [.integer(5), .integer(7)])
        c.contextName = "vlan-99"
        do { _ = try await client(a, c).walk(bridge); XCTFail("unknown context answered") }
        catch {
            guard case .decode(let text) = error as? SNMPError else { return XCTFail("\(error)") }
            XCTAssertTrue(text.contains("no SNMPv3 context by that name"), text)
        }
    }

    /// The agent reboots and keeps its boots counter on disk: boots + 1, engine time back to 0
    /// (behind what we had). One notInTimeWindows report, one resync, the answer.
    func testAgentRebootMovesEngineTimeBackwards() async throws {
        let (a, c) = try agent()
        defer { a.stop() }
        let cache = EngineCache()
        let cl = client(a, c, cache: cache)
        let first = try await cl.get([.sysName])
        let bootsBefore = try XCTUnwrap(first.engine?.boots)
        XCTAssertGreaterThan(try XCTUnwrap(first.engine?.time), 4_000)
        a.reboot()
        let before = a.v3Requests
        let r = try await cl.get([.sysName])
        XCTAssertEqual(r.varBinds.first?.value, .octetString(Data("fake-1".utf8)))
        XCTAssertEqual(r.engine?.boots, bootsBefore + 1)
        XCTAssertLessThan(try XCTUnwrap(r.engine?.time), 10)
        XCTAssertEqual(a.v3Requests - before, 2, "the request, its report, the one resent request")
        // Later answers are not mistaken for going back in time.
        let again = try await cl.get([.sysName])
        XCTAssertEqual(again.engine?.boots, bootsBefore + 1)
        XCTAssertEqual(a.v3Requests - before, 3)
    }

    /// After 8 hours of sleep. The agent's clock ran on, and so does our estimate (the
    /// monotonic clock counts sleep): no resync. A cached time that is stale all the same (an
    /// estimate on a clock that stopped during sleep): one notInTimeWindows report, one resync.
    func testEngineTimeAfterAnEightHourSleep() async throws {
        let (a, c) = try agent()
        defer { a.stop() }
        let cache = EngineCache()
        let cl = client(a, c, cache: cache)
        _ = try await cl.get([.sysName])
        let key = "127.0.0.1:\(a.port)"
        let sleep: UInt32 = 8 * 3_600

        // The Mac slept 8 h: the agent's clock and our learned-at stamp both moved by 8 h.
        var e = try XCTUnwrap(cache.entry(key))
        e.learnedAt -= Double(sleep)
        cache.set(key, e)
        a.advanceClock(sleep)
        var before = a.v3Requests
        _ = try await cl.get([.sysName])
        XCTAssertEqual(a.v3Requests - before, 1, "in the time window straight away")

        // A stale estimate (8 h behind the agent).
        e = try XCTUnwrap(cache.entry(key))
        e.time -= sleep
        cache.set(key, e)
        before = a.v3Requests
        let r = try await cl.get([.sysName])
        XCTAssertEqual(r.varBinds.first?.value, .octetString(Data("fake-1".utf8)))
        XCTAssertEqual(a.v3Requests - before, 2, "one report, one resync")
        before = a.v3Requests
        _ = try await cl.get([.sysName])
        XCTAssertEqual(a.v3Requests - before, 1, "and in sync afterwards")
    }
}
