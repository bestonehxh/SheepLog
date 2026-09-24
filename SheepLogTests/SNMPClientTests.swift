import Darwin
import XCTest
@testable import SheepLog

final class SNMPClientTests: XCTestCase {
    private func hex(_ s: String) -> [UInt8] {
        let clean = s.filter { !$0.isWhitespace }
        var out: [UInt8] = []
        var i = clean.startIndex
        while i < clean.endIndex {
            let j = clean.index(i, offsetBy: 2)
            out.append(UInt8(clean[i..<j], radix: 16)!)
            i = j
        }
        return out
    }

    // MARK: Wire format

    func testEncodeV2cGetRequest() {
        let bytes = CommunityMessage.encode(version: .v2c, community: "public",
                                            pdu: SNMPPDU(type: BER.getRequest, requestID: 1,
                                                         varBinds: [VarBind(.sysDescr, .null)]).encoded())
        XCTAssertEqual(bytes, hex("""
            30 26 02 01 01 04 06 70 75 62 6c 69 63 a0 19 02 01 01 02 01 00 02 01 00
            30 0e 30 0c 06 08 2b 06 01 02 01 01 01 00 05 00
            """))
    }

    func testDecodeCapturedResponse() throws {
        // A v2c Response: sysDescr.0 = "Linux", request-id 0x1234.
        let bytes = hex("""
            30 2c 02 01 01 04 06 70 75 62 6c 69 63 a2 1f 02 02 12 34 02 01 00 02 01 00
            30 13 30 11 06 08 2b 06 01 02 01 01 01 00 04 05 4c 69 6e 75 78
            """)
        let m = try CommunityMessage.decode(bytes)
        XCTAssertEqual(m.version, 1)
        XCTAssertEqual(String(decoding: m.community, as: UTF8.self), "public")
        XCTAssertEqual(m.pdu?.type, BER.response)
        XCTAssertEqual(m.pdu?.requestID, 0x1234)
        XCTAssertEqual(m.pdu?.varBinds, [VarBind(.sysDescr, .octetString(Data("Linux".utf8)))])
    }

    func testV3RoundTripAuthPrivAndWrongPasswords() throws {
        let engine: [UInt8] = [0x80, 0x00, 0x1F, 0x88, 0x80, 0x11, 0x22, 0x33, 0x44]
        let combos: [(AuthProtocol, PrivProtocol)] = [
            (.md5, .des), (.sha1, .aes128), (.sha224, .aes192), (.sha256, .aes256), (.sha384, .des),
            (.sha512, .aes256), (.sha1, .none), (.md5, .aes256),
        ]
        for (a, p) in combos {
            func sec(_ authPw: String, _ privPw: String) -> USMSecurity {
                USMSecurity(userName: "lab", auth: a, priv: p,
                            authKey: USM.localizedKey(password: authPw, engineID: engine, a),
                            privKey: p == .none ? [] : USM.privKey(password: privPw, auth: a, priv: p, engineID: engine))
            }
            let good = sec("authpassword", "privpassword")
            let pdu = SNMPPDU(type: BER.response, requestID: 4242,
                              varBinds: [VarBind(.sysDescr, .octetString(Data("Aruba CX".utf8))), VarBind(.sysUpTime, .timeTicks(99))])
            let salt = p == .des ? USM.desSalt(boots: 5, counter: 1) : USM.aesSalt(77)
            let bytes = try good.encode(msgID: 4242, reportable: false, engineID: engine, boots: 5, time: 1234,
                                        contextEngineID: engine, contextName: "", pdu: pdu, salt: salt)
            let m = try good.decode(bytes)
            XCTAssertEqual(m.pdu, pdu, "\(a) \(p)")
            XCTAssertEqual(m.engineID, engine)
            XCTAssertEqual(m.boots, 5)
            XCTAssertEqual(m.time, 1234)
            XCTAssertEqual(String(decoding: m.userName, as: UTF8.self), "lab")
            XCTAssertEqual(m.authParams.count, USM.macLength(a))
            XCTAssertEqual(m.flags & 0x03, p == .none ? 0x01 : 0x03)
            if p != .none {
                XCTAssertNil(String(data: Data(bytes), encoding: .utf8)?.range(of: "Aruba CX"), "encrypted on the wire")
            }

            XCTAssertThrowsError(try sec("wrongpassword", "privpassword").decode(bytes), "\(a) \(p)") { e in
                XCTAssertEqual(e as? SNMPError, .wrongDigest)
            }
            if p != .none {
                XCTAssertThrowsError(try sec("authpassword", "wrongprivpass").decode(bytes), "\(a) \(p)")
            }
            // A flipped byte anywhere breaks the digest.
            var tampered = bytes
            tampered[tampered.count - 3] ^= 0x40
            XCTAssertThrowsError(try good.decode(tampered))
        }
    }

    // MARK: Traps

    func testTrapDecoding() throws {
        let vbs = [VarBind(.sysUpTimeInstance, .timeTicks(500)),
                   VarBind(.snmpTrapOID, .oid(OID([1, 3, 6, 1, 6, 3, 1, 1, 5, 3]))),
                   VarBind(OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 3]), .integer(3))]
        let trap = CommunityMessage.encode(version: .v2c, community: "traps",
                                           pdu: SNMPPDU(type: BER.trapV2, requestID: 11, varBinds: vbs).encoded())
        let d = TrapListener.decode(trap, host: "10.0.0.1", port: 5000, received: Date())
        guard case .trap(let t) = d.item else { return XCTFail("not decoded") }
        XCTAssertNil(d.informResponse)
        XCTAssertEqual(t.trapOID, OID([1, 3, 6, 1, 6, 3, 1, 1, 5, 3]))
        XCTAssertEqual(t.uptime, 500)
        XCTAssertEqual(t.community, "traps")
        XCTAssertEqual(t.varBinds.count, 1)

        let inform = CommunityMessage.encode(version: .v2c, community: "traps",
                                             pdu: SNMPPDU(type: BER.informRequest, requestID: 31337, varBinds: vbs).encoded())
        let di = TrapListener.decode(inform, host: "10.0.0.1", port: 5000, received: Date())
        let ack = try XCTUnwrap(di.informResponse)
        let reply = try CommunityMessage.decode(ack)
        XCTAssertEqual(reply.pdu?.type, BER.response)
        XCTAssertEqual(reply.pdu?.requestID, 31337)
        XCTAssertEqual(reply.pdu?.varBinds, vbs)

        let v1 = BER.encodeSequence([BER.encodeInteger(0), BER.encodeOctets(Array("public".utf8)),
                                     TrapV1PDU(enterprise: OID([1, 3, 6, 1, 4, 1, 14823]), agentAddress: "10.2.2.2",
                                               genericTrap: 2, specificTrap: 0, timeStamp: 77, varBinds: []).encoded()])
        guard case .trap(let t1) = TrapListener.decode(v1, host: "10.0.0.2", port: 162, received: Date()).item else {
            return XCTFail("v1 not decoded")
        }
        XCTAssertEqual(t1.trapOID, OID([1, 3, 6, 1, 6, 3, 1, 1, 5, 3]), "generic linkDown")
        XCTAssertEqual(t1.agentAddress, "10.2.2.2")
        XCTAssertEqual(t1.version, .v1)

        let v1s = BER.encodeSequence([BER.encodeInteger(0), BER.encodeOctets(Array("public".utf8)),
                                      TrapV1PDU(enterprise: OID([1, 3, 6, 1, 4, 1, 2011]), agentAddress: "10.2.2.2",
                                                genericTrap: 6, specificTrap: 42, timeStamp: 77, varBinds: []).encoded()])
        guard case .trap(let t2) = TrapListener.decode(v1s, host: "10.0.0.2", port: 162, received: Date()).item else {
            return XCTFail("v1 specific not decoded")
        }
        XCTAssertEqual(t2.trapOID, OID([1, 3, 6, 1, 4, 1, 2011, 0, 42]))

        let sec = USMSecurity.noAuth
        let v3 = try sec.encode(msgID: 1, reportable: false, engineID: [1, 2, 3], boots: 0, time: 0, contextEngineID: [],
                                contextName: "", pdu: SNMPPDU(type: BER.trapV2, requestID: 1, varBinds: vbs), salt: [])
        guard case .v3 = TrapListener.decode(v3, host: "10.0.0.3", port: 162, received: Date()).item else {
            return XCTFail("v3 not recognised")
        }
        guard case .invalid = TrapListener.decode([1, 2, 3], host: "x", port: 1, received: Date()).item else {
            return XCTFail("garbage accepted")
        }
    }

    func testTrapListenerReceivesAndAcknowledgesInforms() throws {
        let port = TestSockets.freePort()

        let got = expectation(description: "batch")
        let box = LockedBox<[ReceivedTrap]>([])
        let listener = try TrapListener(port: port) { batch in
            box.mutate { $0 += batch }
            got.fulfill()
        }
        listener.resume()
        defer { listener.cancel() }
        // Second bind on the same port reports the friendly error.
        XCTAssertThrowsError(try TrapListener(port: port) { _ in }) { e in
            XCTAssertEqual((e as? TrapListener.BindError)?.message, "UDP port \(port) is already in use (EADDRINUSE).")
        }

        let client = try UDPEndpoint(host: "127.0.0.1", port: port)
        let vbs = [VarBind(.sysUpTimeInstance, .timeTicks(1)), VarBind(.snmpTrapOID, .oid(OID([1, 3, 6, 1, 6, 3, 1, 1, 5, 1])))]
        try client.send(CommunityMessage.encode(version: .v2c, community: "public",
                                                pdu: SNMPPDU(type: BER.informRequest, requestID: 555, varBinds: vbs).encoded()))
        let reply = try XCTUnwrap(try client.receive(until: Date().addingTimeInterval(2), token: CancelToken()))
        XCTAssertEqual(try CommunityMessage.decode(reply).pdu?.requestID, 555)
        wait(for: [got], timeout: 2)
        XCTAssertEqual(box.value.count, 1)
    }

    // MARK: Against the fake agent

    private func mib(count: Int) -> [VarBind] {
        var out: [VarBind] = [
            VarBind(.sysDescr, .octetString(Data("SheepLog fake agent".utf8))),
            VarBind(.sysObjectID, .oid(OID([1, 3, 6, 1, 4, 1, 8072, 3, 2, 10]))),
            VarBind(.sysUpTime, .timeTicks(123_456)),
            VarBind(.sysContact, .octetString(Data("noc@example.net".utf8))),
            VarBind(.sysName, .octetString(Data("fake-1".utf8))),
            VarBind(.sysLocation, .octetString(Data("lab".utf8))),
            VarBind(.ifNumber, .integer(Int64(count))),
        ]
        for col: UInt32 in [1, 2, 8] {
            for i in 1...UInt32(count) {
                let oid = OID.ifTable.appending([1, col, i])
                switch col {
                case 1: out.append(VarBind(oid, .integer(Int64(i))))
                case 2: out.append(VarBind(oid, .octetString(Data("port\(i)".utf8))))
                default: out.append(VarBind(oid, .integer(i % 3 == 0 ? 2 : 1)))
                }
            }
        }
        out.append(VarBind(OID([1, 3, 6, 1, 2, 1, 4, 1, 0]), .integer(1)))
        return out.sorted { $0.oid < $1.oid }
    }

    func testV2cGetWalkBulk() async throws {
        let agent = try FakeAgent(mib: mib(count: 45))
        defer { agent.stop() }
        let client = SNMPClient(target: SNMPTarget(host: "127.0.0.1", port: agent.port, timeout: 1, retries: 1),
                                credentials: SNMPCredentials(version: .v2c, community: "public"), engines: EngineCache())
        let r = try await client.get([.sysDescr, .sysName, OID([1, 3, 6, 1, 2, 1, 1, 99, 0])])
        XCTAssertEqual(r.varBinds[1].value, .octetString(Data("fake-1".utf8)))
        XCTAssertEqual(r.varBinds[2].value, .noSuchObject)
        XCTAssertGreaterThan(r.rtt, 0)

        let n = try await client.getNext([.sysDescr])
        XCTAssertEqual(n.varBinds.first?.oid, .sysObjectID)

        let chunks = LockedBox(0)
        let w = try await client.walk(.ifTable) { chunk in chunks.mutate { $0 += chunk.count } }
        XCTAssertEqual(w.varBinds.count, 135)
        XCTAssertEqual(chunks.value, 135)
        XCTAssertEqual(w.operation, "GETBULK")
        XCTAssertEqual(w.requests, 7)            // 20 per GETBULK, the last one crosses the subtree end
        XCTAssertFalse(w.truncated)
        XCTAssertEqual(w.varBinds.map(\.oid), w.varBinds.map(\.oid).sorted())

        // Walking an instance answers the instance itself.
        let one = try await client.walk(.sysName)
        XCTAssertEqual(one.varBinds.map(\.oid), [.sysName])

        let wrong = SNMPClient(target: SNMPTarget(host: "127.0.0.1", port: agent.port, timeout: 0.2, retries: 0),
                               credentials: SNMPCredentials(version: .v2c, community: "nope"), engines: EngineCache())
        do { _ = try await wrong.get([.sysDescr]); XCTFail("wrong community answered") }
        catch { XCTAssertEqual(error as? SNMPError, .timeout) }
    }

    func testV1WalkEndsOnNoSuchName() async throws {
        let agent = try FakeAgent(mib: mib(count: 5))
        defer { agent.stop() }
        let client = SNMPClient(target: SNMPTarget(host: "127.0.0.1", port: agent.port, timeout: 1, retries: 0),
                                credentials: SNMPCredentials(version: .v1, community: "public"), engines: EngineCache())
        let all = try await client.walk(OID([1, 3, 6, 1]))
        XCTAssertEqual(all.varBinds.count, mib(count: 5).count)
        XCTAssertEqual(all.operation, "GETNEXT")
        do { _ = try await client.get([OID([1, 3, 6, 1, 2, 1, 1, 99, 0])]); XCTFail() }
        catch { XCTAssertEqual(error as? SNMPError, .response(status: 2, index: 1)) }
    }

    func testRetriesTimeoutAndCancel() async throws {
        let agent = try FakeAgent(mib: mib(count: 2))
        defer { agent.stop() }
        agent.dropNext = 1
        let client = SNMPClient(target: SNMPTarget(host: "127.0.0.1", port: agent.port, timeout: 0.3, retries: 1),
                                credentials: SNMPCredentials(version: .v2c), engines: EngineCache())
        let r = try await client.get([.sysName])
        XCTAssertEqual(r.varBinds.first?.value, .octetString(Data("fake-1".utf8)))

        agent.dropNext = 100
        let t0 = Date()
        do { _ = try await client.get([.sysName]); XCTFail() }
        catch { XCTAssertEqual(error as? SNMPError, .timeout) }
        XCTAssertLessThan(Date().timeIntervalSince(t0), 1.5)

        let slow = SNMPClient(target: SNMPTarget(host: "127.0.0.1", port: agent.port, timeout: 10, retries: 3),
                              credentials: SNMPCredentials(version: .v2c), engines: EngineCache())
        let task = Task { try await slow.get([.sysName]) }
        try await Task.sleep(for: .milliseconds(200))
        let c0 = Date()
        task.cancel()
        do { _ = try await task.value; XCTFail() }
        catch { XCTAssertEqual(error as? SNMPError, .cancelled) }
        XCTAssertLessThan(Date().timeIntervalSince(c0), 1)
    }

    func testWalkCapAndLoopGuard() async throws {
        var big: [VarBind] = []
        for i in 1...10_050 { big.append(VarBind(OID([1, 3, 6, 1, 4, 1, 99999, 1, UInt32(i)]), .integer(Int64(i)))) }
        let agent = try FakeAgent(mib: big)
        defer { agent.stop() }
        let client = SNMPClient(target: SNMPTarget(host: "127.0.0.1", port: agent.port, timeout: 1, retries: 1),
                                credentials: SNMPCredentials(version: .v2c), engines: EngineCache())
        let w = try await client.walk(OID([1, 3, 6, 1, 4, 1, 99999]))
        XCTAssertTrue(w.truncated)
        XCTAssertEqual(w.varBinds.count, SNMPClient.walkCap)

        agent.loop = true
        let l = try await client.walk(OID([1, 3, 6, 1, 4, 1, 99999]))
        XCTAssertLessThan(l.varBinds.count, 100, "a looping agent must not walk forever")
    }

    func testV3AllLevelsAgainstFakeAgent() async throws {
        let combos: [(AuthProtocol, PrivProtocol)] = [
            (.none, .none), (.md5, .none), (.md5, .des), (.sha1, .aes128), (.sha224, .aes192),
            (.sha256, .aes256), (.sha384, .aes128), (.sha512, .aes256), (.sha1, .des),
        ]
        for (a, p) in combos {
            let agent = try FakeAgent(mib: mib(count: 30))
            agent.user = FakeAgent.User(name: "lab", auth: a, priv: p, authPassword: "labpassword", privPassword: "labprivpass")
            defer { agent.stop() }
            let creds = SNMPCredentials(version: .v3, username: "lab", authProtocol: a, authPassword: "labpassword",
                                        privProtocol: p, privPassword: "labprivpass")
            let target = SNMPTarget(host: "127.0.0.1", port: agent.port, timeout: 1, retries: 1)
            let cache = EngineCache()
            let client = SNMPClient(target: target, credentials: creds, engines: cache)
            let info = try await client.discover()
            XCTAssertEqual(info?.engineID, Data(agent.engineID), "\(a) \(p)")
            XCTAssertEqual(info?.boots, agent.boots)
            let r = try await client.get([.sysDescr])
            XCTAssertEqual(r.varBinds.first?.value, .octetString(Data("SheepLog fake agent".utf8)), "\(a) \(p)")
            XCTAssertNotNil(r.engine)
            let w = try await client.walk(.ifTable)
            XCTAssertEqual(w.varBinds.count, 90, "\(a) \(p)")

            if a != .none {
                // Agent reboots: boots moves on, the client resyncs once and carries on.
                agent.boots += 1
                let again = try await client.get([.sysName])
                XCTAssertEqual(again.varBinds.first?.value, .octetString(Data("fake-1".utf8)))
                XCTAssertEqual(again.engine?.boots, agent.boots)

                var bad = creds
                bad.authPassword = "wrongpassword"
                do { _ = try await SNMPClient(target: target, credentials: bad, engines: EngineCache()).get([.sysDescr]); XCTFail() }
                catch { XCTAssertEqual(error as? SNMPError, .wrongDigest, "\(a) \(p)") }
            }
            if p != .none {
                var bad = creds
                bad.privPassword = "wrongprivpass"
                do { _ = try await SNMPClient(target: target, credentials: bad, engines: EngineCache()).get([.sysDescr]); XCTFail() }
                catch { XCTAssertEqual(error as? SNMPError, .decryptionError, "\(a) \(p)") }
            }
            var who = creds
            who.username = "nobody"
            do { _ = try await SNMPClient(target: target, credentials: who, engines: EngineCache()).get([.sysDescr]); XCTFail() }
            catch { XCTAssertEqual(error as? SNMPError, .unknownUser, "\(a) \(p)") }
        }
    }
}

// MARK: - Adversarial review: protocol edge cases

extension SNMPClientTests {
    private func v2Client(_ agent: FakeAgent, version: SNMPVersion = .v2c, timeout: Double = 1) -> SNMPClient {
        SNMPClient(target: SNMPTarget(host: "127.0.0.1", port: agent.port, timeout: timeout, retries: 0),
                   credentials: SNMPCredentials(version: version, community: "public"), engines: EngineCache())
    }

    /// net-snmp's snmpwalk stops at any exception value; so must we (a view that ends with
    /// noSuchObject / noSuchInstance at a *larger* OID must not be walked through).
    func testWalkStopsAtNoSuchObjectAndNoSuchInstance() async throws {
        let base = OID([1, 3, 6, 1, 4, 1, 99999])
        for exception in [SNMPValue.noSuchObject, .noSuchInstance] {
            let mib = [VarBind(base.appending([1, 1]), .integer(1)), VarBind(base.appending([1, 2]), .integer(2)),
                       VarBind(base.appending([1, 3]), exception), VarBind(base.appending([1, 4]), .integer(4))]
            let agent = try FakeAgent(mib: mib)
            defer { agent.stop() }
            for version in [SNMPVersion.v2c, .v1] {
                let w = try await v2Client(agent, version: version).walk(base)
                XCTAssertEqual(w.varBinds.map(\.oid), [base.appending([1, 1]), base.appending([1, 2])], "\(exception) \(version)")
            }
        }
    }

    /// GETBULK: non-repeaters is clamped to the var-bind count, negatives to 0; v1 never sends GETBULK.
    func testGetBulkClampsAndV1NeverSendsBulk() async throws {
        let agent = try FakeAgent(mib: mib(count: 3))
        defer { agent.stop() }
        _ = try await v2Client(agent).getBulk([.system], nonRepeaters: 5, maxRepetitions: -3)
        XCTAssertEqual(agent.lastPDU?.type, BER.getBulkRequest)
        XCTAssertEqual(agent.lastPDU?.errorStatus, 1, "non-repeaters > var-binds → var-binds")
        XCTAssertEqual(agent.lastPDU?.errorIndex, 0, "negative max-repetitions → 0")
        _ = try await v2Client(agent, version: .v1).getBulk([.system])
        XCTAssertEqual(agent.lastPDU?.type, BER.getNextRequest)
        _ = try await v2Client(agent, version: .v1).walk(.system)
        XCTAssertEqual(agent.lastPDU?.type, BER.getNextRequest)
    }

    /// A Response with somebody else's request-id is ignored; the real one still lands.
    func testStrayResponseWithOtherRequestIDIsIgnored() async throws {
        let agent = try FakeAgent(mib: mib(count: 3))
        defer { agent.stop() }
        agent.strayFirst = true
        let r = try await v2Client(agent).get([.sysName])
        XCTAssertEqual(r.varBinds, [VarBind(.sysName, .octetString(Data("fake-1".utf8)))])
        let w = try await v2Client(agent).walk(.system)
        XCTAssertEqual(w.varBinds.count, 6)
    }

    private func v3Agent() throws -> (FakeAgent, SNMPCredentials) {
        let agent = try FakeAgent(mib: mib(count: 3))
        agent.user = FakeAgent.User(name: "lab", auth: .sha1, priv: .aes128, authPassword: "labpassword", privPassword: "labprivpass")
        let creds = SNMPCredentials(version: .v3, username: "lab", authProtocol: .sha1, authPassword: "labpassword",
                                    privProtocol: .aes128, privPassword: "labprivpass")
        return (agent, creds)
    }

    private static func report(_ oid: OID, msgID: Int32, engineID: [UInt8], boots: UInt32 = 1, time: UInt32 = 1) -> [UInt8]? {
        try? USMSecurity.noAuth.encode(msgID: msgID, reportable: false, engineID: engineID, boots: boots, time: time,
                                       contextEngineID: engineID, contextName: "",
                                       pdu: SNMPPDU(type: BER.report, requestID: msgID, varBinds: [VarBind(oid, .counter32(1))]),
                                       salt: [])
    }

    /// An unauthenticated notInTimeWindows report (anyone can forge one) must not switch the
    /// cached engine ID — only discovery may set it.
    func testUnauthenticatedTimeReportCannotSwitchEngine() async throws {
        let (agent, creds) = try v3Agent()
        defer { agent.stop() }
        let spoofed: [UInt8] = [0x80, 0, 0, 0, 9, 9, 9, 9, 9]
        agent.v3Hook = { id, discovery in
            discovery ? nil : Self.report(USM.notInTimeWindows, msgID: id, engineID: spoofed, boots: 77, time: 77)
        }
        let cache = EngineCache()
        let client = SNMPClient(target: SNMPTarget(host: "127.0.0.1", port: agent.port, timeout: 0.5, retries: 0),
                                credentials: creds, engines: cache)
        do { _ = try await client.get([.sysName]); XCTFail("spoofed report accepted") }
        catch { XCTAssertEqual(error as? SNMPError, .notInTimeWindow) }
        XCTAssertEqual(cache.entry("127.0.0.1:\(agent.port)")?.engineID, agent.engineID)
    }

    /// msgSecurityParameters that is not a SEQUENCE is a malformed message, not a priv failure.
    func testMalformedSecurityParametersIsDecodeNotDecryptionError() async throws {
        let (agent, creds) = try v3Agent()
        defer { agent.stop() }
        agent.v3Hook = { id, discovery in
            if discovery { return nil }
            return BER.encodeSequence([
                BER.encodeInteger(3),
                BER.encodeSequence([BER.encodeInteger(Int64(id)), BER.encodeInteger(65507), BER.encodeOctets([0x03]), BER.encodeInteger(3)]),
                BER.encodeOctets(BER.encodeInteger(5)),
                BER.encodeOctets([1, 2, 3, 4]),
            ])
        }
        let client = SNMPClient(target: SNMPTarget(host: "127.0.0.1", port: agent.port, timeout: 0.5, retries: 0),
                                credentials: creds, engines: EngineCache())
        do { _ = try await client.get([.sysName]); XCTFail("garbage accepted") }
        catch {
            guard case .decode = error as? SNMPError else { return XCTFail("\(error)") }
        }
    }

    /// SnmpEngineID is at most 32 bytes (RFC 3411).
    func testDiscoveryRejectsOversizeEngineID() async throws {
        let (agent, _) = try v3Agent()
        defer { agent.stop() }
        agent.v3Hook = { id, discovery in
            discovery ? Self.report(USM.unknownEngineIDs, msgID: id, engineID: [UInt8](repeating: 0x42, count: 40)) : nil
        }
        let noAuth = SNMPCredentials(version: .v3, username: "lab", authProtocol: .none, privProtocol: .none)
        let client = SNMPClient(target: SNMPTarget(host: "127.0.0.1", port: agent.port, timeout: 0.5, retries: 0),
                                credentials: noAuth, engines: EngineCache())
        do { _ = try await client.discover(); XCTFail("40-byte engine ID accepted") }
        catch {
            guard case .decode = error as? SNMPError else { return XCTFail("\(error)") }
        }
    }

    /// A Report with no var-binds is an error, not a crash.
    func testReportWithoutVarBinds() async throws {
        let (agent, creds) = try v3Agent()
        defer { agent.stop() }
        let eid = agent.engineID
        agent.v3Hook = { id, discovery in
            if discovery { return nil }
            return try? USMSecurity.noAuth.encode(msgID: id, reportable: false, engineID: eid, boots: 3, time: 5000,
                                                  contextEngineID: eid, contextName: "",
                                                  pdu: SNMPPDU(type: BER.report, requestID: id, varBinds: []), salt: [])
        }
        let client = SNMPClient(target: SNMPTarget(host: "127.0.0.1", port: agent.port, timeout: 0.5, retries: 0),
                                credentials: creds, engines: EngineCache())
        do { _ = try await client.get([.sysName]); XCTFail() }
        catch {
            guard case .decode = error as? SNMPError else { return XCTFail("\(error)") }
        }
    }

    /// Privacy salts: never repeat, across threads.
    func testSaltCountersAreUniqueAcrossThreads() {
        let cache = EngineCache()
        let box = LockedBox<[UInt64]>([])
        DispatchQueue.concurrentPerform(iterations: 8) { _ in
            var local: [UInt64] = []
            for _ in 0..<2_000 { local.append(cache.nextSalt64()); local.append(UInt64(cache.nextSalt32()) << 32) }
            box.mutate { $0 += local }
        }
        XCTAssertEqual(Set(box.value).count, box.value.count)
    }

    /// "localhost" resolves to ::1 first; an agent bound to 127.0.0.1 only answers ICMP port
    /// unreachable there. The client must fall through to the next address, not fail.
    func testLocalhostFallsBackToIPv4() async throws {
        let agent = try FakeAgent(mib: mib(count: 2))
        defer { agent.stop() }
        let client = SNMPClient(target: SNMPTarget(host: "localhost", port: agent.port, timeout: 1, retries: 0),
                                credentials: SNMPCredentials(version: .v2c), engines: EngineCache())
        let r = try await client.get([.sysName])
        XCTAssertEqual(r.varBinds.first?.value, .octetString(Data("fake-1".utf8)))
        // Nothing listening at all: a network error, fast (not a timeout).
        agent.stop()
        try await Task.sleep(for: .milliseconds(150))
        let t0 = Date()
        do { _ = try await client.get([.sysName]); XCTFail("closed port answered") }
        catch {
            guard case .network = error as? SNMPError else { return XCTFail("\(error)") }
        }
        XCTAssertLessThan(Date().timeIntervalSince(t0), 0.9)
        // Unresolvable name: a network error naming the host.
        do {
            _ = try await SNMPClient(target: SNMPTarget(host: "no-such-host.invalid", port: 161, timeout: 0.2, retries: 0),
                                     credentials: SNMPCredentials(version: .v2c), engines: EngineCache()).get([.sysName])
            XCTFail()
        } catch {
            guard case .network(let s) = error as? SNMPError else { return XCTFail("\(error)") }
            XCTAssertTrue(s.contains("no-such-host.invalid"), s)
        }
    }

    /// Cancellation while the socket is waiting ends the call with `.cancelled` exactly once,
    /// within ~100 ms, for every operation (walks included).
    func testCancelDuringWalkIsPrompt() async throws {
        let agent = try FakeAgent(mib: mib(count: 2))
        defer { agent.stop() }
        agent.dropNext = 1_000
        let client = SNMPClient(target: SNMPTarget(host: "127.0.0.1", port: agent.port, timeout: 5, retries: 5),
                                credentials: SNMPCredentials(version: .v2c), engines: EngineCache())
        for _ in 0..<5 {
            let task = Task { try await client.walk(OID([1, 3, 6, 1])) }
            try await Task.sleep(for: .milliseconds(50))
            let c0 = Date()
            task.cancel()
            do { _ = try await task.value; XCTFail() }
            catch { XCTAssertEqual(error as? SNMPError, .cancelled) }
            XCTAssertLessThan(Date().timeIntervalSince(c0), 0.3)
        }
        // Already cancelled before the call starts.
        let pre = Task { () -> SNMPReply in
            withUnsafeCurrentTask { $0?.cancel() }
            return try await client.get([.sysName])
        }
        do { _ = try await pre.value; XCTFail() }
        catch { XCTAssertEqual(error as? SNMPError, .cancelled) }
    }

    /// `-demoSNMP 1` must not put "1" in the Host field.
    func testDemoFlagHost() {
        XCTAssertEqual(SNMPTestModel.demoHost(["app"]).open, false)
        for args in [["app", "-demoSNMP"], ["app", "-demoSNMP", "1"], ["app", "-demoSNMP", "YES"],
                     ["app", "-demoSNMP", "-demoSNMPAction", "walk"]] {
            let d = SNMPTestModel.demoHost(args)
            XCTAssertTrue(d.open, "\(args)")
            XCTAssertNil(d.host, "\(args)")
        }
        XCTAssertEqual(SNMPTestModel.demoHost(["app", "-demoSNMP", "127.0.0.1:1161"]).host, "127.0.0.1:1161")
        XCTAssertEqual(SNMPTestModel.demoHost(["app", "-demoSNMP", "switch-1"]).host, "switch-1")
    }

    /// 10,000 var-binds in 500 chunks reach the main actor in a handful of batches, all of them.
    func testChunkBatcherRateLimits() {
        let batches = LockedBox<[Int]>([])
        let done = expectation(description: "all delivered")
        let b = ChunkBatcher(interval: 0.1) { batch in
            batches.mutate { $0.append(batch.count) }
            if batches.value.reduce(0, +) == 10_000 { done.fulfill() }
        }
        let vbs = (0..<20).map { VarBind(OID([1, 3, UInt32($0)]), .integer(1)) }
        let t0 = Date()
        for _ in 0..<500 { b.add(vbs); usleep(400) }        // ~0.2 s of GETBULK replies
        wait(for: [done], timeout: 2)
        let elapsed = Date().timeIntervalSince(t0)
        XCTAssertLessThanOrEqual(batches.value.count, Int(elapsed / 0.1) + 2, "\(batches.value)")
    }

    /// A 60 KB value in a single datagram decodes (buffer is sized for the largest UDP payload).
    func testLargeDatagram() async throws {
        let big = VarBind(OID([1, 3, 6, 1, 4, 1, 99999, 1, 0]), .octetString(Data(repeating: 0x41, count: 60_000)))
        let agent = try FakeAgent(mib: [big])
        defer { agent.stop() }
        let r = try await v2Client(agent).get([big.oid])
        XCTAssertEqual(r.varBinds, [big])
        // A request bigger than macOS's default UDP send cap (9216 bytes): 1,000 OIDs ≈ 17 KB.
        let many = (1...1_000).map { OID([1, 3, 6, 1, 4, 1, 99999, 2, UInt32($0)]) }
        let m = try await v2Client(agent).get(many)
        XCTAssertEqual(m.varBinds.count, 1_000)
    }
}

/// A small SNMP agent on 127.0.0.1: v1/v2c with community "public", and the authoritative
/// side of USM for one configured v3 user.
final class FakeAgent: @unchecked Sendable {
    struct User {
        var name: String
        var auth: AuthProtocol
        var priv: PrivProtocol
        var authPassword: String
        var privPassword: String
    }

    let port: UInt16
    let engineID: [UInt8] = [0x80, 0x00, 0x1F, 0x88, 0x80, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67]
    private let fd: Int32
    private let lock = NSLock()
    private var stopped = false
    private let mib: [VarBind]
    private var started = Date()
    private var _timeBase: UInt32 = 5_000
    private var _boots: UInt32 = 3
    private var _dropNext = 0
    private var _loop = false
    private var _user: User?
    /// Drop (no report) what cannot be decrypted, as net-snmp does.
    private var _dropUndecryptable = false
    var dropUndecryptable: Bool { get { locked { _dropUndecryptable } } set { locked { _dropUndecryptable = newValue } } }

    var boots: UInt32 { get { locked { _boots } } set { locked { _boots = newValue } } }
    var dropNext: Int { get { locked { _dropNext } } set { locked { _dropNext = newValue } } }
    var loop: Bool { get { locked { _loop } } set { locked { _loop = newValue } } }
    var user: User? { get { locked { _user } } set { locked { _user = newValue } } }

    /// v3: craft the reply yourself (msgID, is-discovery). nil = normal handling.
    typealias V3Hook = @Sendable (_ msgID: Int32, _ discovery: Bool) -> [UInt8]?
    private var _v3Hook: V3Hook?
    var v3Hook: V3Hook? { get { locked { _v3Hook } } set { locked { _v3Hook = newValue } } }
    /// v1/v2c: send a copy of each response with request-id + 1 first (a stray reply).
    private var _strayFirst = false
    var strayFirst: Bool { get { locked { _strayFirst } } set { locked { _strayFirst = newValue } } }
    /// The last v1/v2c request PDU received.
    private var _lastPDU: SNMPPDU?
    var lastPDU: SNMPPDU? { locked { _lastPDU } }
    private var time: UInt32 { locked { _timeBase &+ UInt32(max(0, Date().timeIntervalSince(started))) } }

    // Round 5: behaviours of real agents.

    /// The discovery report says boots 0, time 0 (many embedded agents do).
    private var _discoveryZeroTime = false
    var discoveryZeroTime: Bool { get { locked { _discoveryZeroTime } } set { locked { _discoveryZeroTime = newValue } } }
    /// v3 requests with a larger msgMaxSize are dropped (nil: accepted), or answered with an
    /// snmpInvalidMsgs report when `reportInvalidMsgs`.
    private var _maxAcceptedMsgSize: Int?
    var maxAcceptedMsgSize: Int? { get { locked { _maxAcceptedMsgSize } } set { locked { _maxAcceptedMsgSize = newValue } } }
    private var _reportInvalidMsgs = false
    var reportInvalidMsgs: Bool { get { locked { _reportInvalidMsgs } } set { locked { _reportInvalidMsgs = newValue } } }
    /// GETBULK answers with at most this many repetitions (whatever was asked).
    private var _bulkCap: Int?
    var bulkCap: Int? { get { locked { _bulkCap } } set { locked { _bulkCap = newValue } } }
    /// Every GETBULK response carries its second var-bind twice (a buggy agent).
    private var _duplicateInBulk = false
    var duplicateInBulk: Bool { get { locked { _duplicateInBulk } } set { locked { _duplicateInBulk = newValue } } }
    /// v3 responses carry a 16-byte digest whatever the user's protocol (a non-standard
    /// SHA-256 that truncates like SHA-224).
    private var _shortDigest = false
    var shortDigest: Bool { get { locked { _shortDigest } } set { locked { _shortDigest = newValue } } }
    /// v3 contexts other than "" (Cisco's `vlan-10`): name → objects. Unknown → snmpUnknownContexts.
    private var _contexts: [String: [VarBind]] = [:]
    var contexts: [String: [VarBind]] { get { locked { _contexts } } set { locked { _contexts = newValue } } }
    /// v3 requests seen (all kinds, discovery included).
    private var _v3Requests = 0
    var v3Requests: Int { locked { _v3Requests } }
    /// msgMaxSize of the last v3 request.
    private var _lastMsgMaxSize = 0
    var lastMsgMaxSize: Int { locked { _lastMsgMaxSize } }

    /// The engine clock jumps forward (the agent ran on while this Mac slept).
    func advanceClock(_ seconds: UInt32) { locked { _timeBase &+= seconds } }

    /// A reboot that keeps boots on disk: boots + 1 and the engine clock back to 0.
    func reboot() {
        locked {
            _boots += 1
            _timeBase = 0
            started = Date()
        }
    }

    private func locked<T>(_ f: () -> T) -> T { lock.lock(); defer { lock.unlock() }; return f() }

    init(mib: [VarBind]) throws {
        self.mib = mib
        let sock = socket(AF_INET, SOCK_DGRAM, 0)
        var a = sockaddr_in(sin_len: UInt8(MemoryLayout<sockaddr_in>.size), sin_family: sa_family_t(AF_INET), sin_port: 0,
                            sin_addr: in_addr(s_addr: inet_addr("127.0.0.1")), sin_zero: (0, 0, 0, 0, 0, 0, 0, 0))
        let rc = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard rc == 0 else { throw SNMPError.network("fake agent bind") }
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(sock, $0, &len) } }
        fd = sock
        var sndbuf: Int32 = 256 << 10   // macOS caps a UDP send at SO_SNDBUF (9216 by default)
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, socklen_t(MemoryLayout<Int32>.size))
        port = UInt16(bigEndian: a.sin_port)
        let t = Thread { [weak self] in self?.run() }
        t.start()
    }

    func stop() { locked { stopped = true } }

    private func run() {
        var buf = [UInt8](repeating: 0, count: 65_536)
        while !locked({ stopped }) {
            var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            guard poll(&p, 1, 50) > 0 else { continue }
            var from = sockaddr_storage()
            var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let n = withUnsafeMutablePointer(to: &from) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fd, &buf, buf.count, 0, $0, &len) } }
            guard n > 0 else { continue }
            if locked({ () -> Bool in if _dropNext > 0 { _dropNext -= 1; return true }; return false }) { continue }
            guard let reply = handle(Array(buf[0..<n])) else { continue }
            var replies = [reply]
            if strayFirst, let m = try? CommunityMessage.decode(reply), var pdu = m.pdu {
                pdu.requestID &+= 1
                pdu.varBinds = pdu.varBinds.map { VarBind($0.oid, .octetString(Data("stray".utf8))) }
                replies.insert(BER.encodeSequence([BER.encodeInteger(Int64(m.version)), BER.encodeOctets(m.community),
                                                   pdu.encoded()]), at: 0)
            }
            for out in replies {
                _ = out.withUnsafeBytes { r in
                    withUnsafePointer(to: &from) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, r.baseAddress, r.count, 0, $0, len) } }
                }
            }
        }
        close(fd)
    }

    private func handle(_ bytes: [UInt8]) -> [UInt8]? {
        guard let v = CommunityMessage.peekVersion(bytes) else { return nil }
        if v == 3 { return handleV3(bytes) }
        guard let m = try? CommunityMessage.decode(bytes), let pdu = m.pdu,
              String(decoding: m.community, as: UTF8.self) == "public" else { return nil }
        let resp = process(pdu, v1: v == 0)
        return BER.encodeSequence([BER.encodeInteger(Int64(v)), BER.encodeOctets(m.community), resp.encoded()])
    }

    private func next(after oid: OID, in mib: [VarBind]) -> VarBind? {
        var lo = 0, hi = mib.count
        while lo < hi {
            let mid = (lo + hi) / 2
            if mib[mid].oid <= oid { lo = mid + 1 } else { hi = mid }
        }
        return lo < mib.count ? mib[lo] : nil
    }

    private func next(after oid: OID) -> VarBind? { next(after: oid, in: mib) }

    private func process(_ pdu: SNMPPDU, v1: Bool, context: [VarBind]? = nil) -> SNMPPDU {
        let mib = context ?? self.mib
        func next(after oid: OID) -> VarBind? { self.next(after: oid, in: mib) }
        locked { _lastPDU = pdu }
        var out: [VarBind] = []
        switch pdu.type {
        case BER.getRequest:
            for (i, vb) in pdu.varBinds.enumerated() {
                if let hit = mib.first(where: { $0.oid == vb.oid }) { out.append(hit) }
                else if v1 { return SNMPPDU(type: BER.response, requestID: pdu.requestID, errorStatus: 2, errorIndex: i + 1, varBinds: pdu.varBinds) }
                else { out.append(VarBind(vb.oid, .noSuchObject)) }
            }
        case BER.getNextRequest:
            for (i, vb) in pdu.varBinds.enumerated() {
                if let n = next(after: vb.oid) { out.append(n) }
                else if v1 { return SNMPPDU(type: BER.response, requestID: pdu.requestID, errorStatus: 2, errorIndex: i + 1, varBinds: pdu.varBinds) }
                else { out.append(VarBind(vb.oid, .endOfMibView)) }
            }
        case BER.getBulkRequest:
            var cur = pdu.varBinds.first?.oid ?? OID([])
            for _ in 0..<min(max(1, pdu.errorIndex), bulkCap ?? Int.max) {
                if loop { out.append(VarBind(OID([1, 3, 6, 1, 4, 1, 99999, 1, 5]), .integer(5))); continue }
                guard let n = next(after: cur) else { out.append(VarBind(cur, .endOfMibView)); break }
                out.append(n)
                cur = n.oid
            }
            if duplicateInBulk, out.count >= 2 { out.insert(out[1], at: 2) }
        default:
            break
        }
        return SNMPPDU(type: BER.response, requestID: pdu.requestID, varBinds: out)
    }

    // USM, authoritative side.
    private func handleV3(_ bytes: [UInt8]) -> [UInt8]? {
        // Header, unauthenticated.
        var outer = BERReader(bytes)
        guard var r = try? outer.readSequence(), (try? r.readInteger()) == 3, var g = try? r.readSequence(),
              let msgID = try? g.readInteger(), (try? g.readInteger()) != nil, let flags = try? g.readOctets(),
              var sp = try? r.read(BER.octetString).reader, var s = try? sp.readSequence(),
              let eid = try? s.readOctets(), (try? s.readInteger()) != nil, (try? s.readInteger()) != nil,
              let userName = try? s.readOctets() else { return nil }
        let id = Int32(truncatingIfNeeded: msgID)
        let maxSize = (try? { () throws -> Int in
            var o = BERReader(bytes); var rr = try o.readSequence(); _ = try rr.readInteger()
            var gg = try rr.readSequence(); _ = try gg.readInteger(); return Int(try gg.readInteger())
        }()) ?? 0
        locked { _v3Requests += 1; _lastMsgMaxSize = maxSize }

        func report(_ oid: OID, sec: USMSecurity = .noAuth, zero: Bool = false) -> [UInt8]? {
            try? sec.encode(msgID: id, reportable: false, engineID: engineID, boots: zero ? 0 : boots, time: zero ? 0 : time,
                            contextEngineID: engineID, contextName: "",
                            pdu: SNMPPDU(type: BER.report, requestID: 0, varBinds: [VarBind(oid, .counter32(1))]),
                            salt: [])
        }
        if let hook = v3Hook, let crafted = hook(id, eid.isEmpty) { return crafted }
        if let cap = maxAcceptedMsgSize, maxSize > cap {
            return reportInvalidMsgs ? report(OID([1, 3, 6, 1, 6, 3, 11, 2, 1, 2, 0])) : nil
        }
        if eid.isEmpty { return report(USM.unknownEngineIDs, zero: discoveryZeroTime) }
        guard let u = user, String(decoding: userName, as: UTF8.self) == u.name else { return report(USM.unknownUserNames) }
        let sec = USMSecurity(userName: u.name, auth: u.auth, priv: u.auth == .none ? .none : u.priv,
                              authKey: u.auth == .none ? [] : USM.localizedKey(password: u.authPassword, engineID: engineID, u.auth),
                              privKey: (u.auth == .none || u.priv == .none) ? [] :
                                USM.privKey(password: u.privPassword, auth: u.auth, priv: u.priv, engineID: engineID))
        guard (flags.first ?? 0) & 0x03 == sec.flags else { return report(USM.unsupportedSecLevels) }
        let m: V3Message
        do { m = try sec.decode(bytes) }
        catch SNMPError.wrongDigest { return report(USM.wrongDigests) }
        catch { return dropUndecryptable ? nil : report(USM.decryptionErrors) }
        if u.auth != .none, m.boots != boots || abs(Int64(m.time) - Int64(time)) > 150 {
            // Authenticated report, no privacy.
            var authOnly = sec
            authOnly.priv = .none
            return report(USM.notInTimeWindows, sec: authOnly)
        }
        let contextName = String(decoding: m.contextName, as: UTF8.self)
        var context: [VarBind]?
        if !contextName.isEmpty {
            guard let c = contexts[contextName] else {
                var authOnly = sec
                authOnly.priv = .none
                return report(OID([1, 3, 6, 1, 6, 3, 12, 1, 5, 0]), sec: authOnly)     // snmpUnknownContexts
            }
            context = c
        }
        let resp = process(m.pdu, v1: false, context: context)
        let salt = sec.priv == .des ? USM.desSalt(boots: boots, counter: UInt32.random(in: 0...UInt32.max))
                                    : USM.aesSalt(UInt64.random(in: 0...UInt64.max))
        var out = sec
        if shortDigest, u.auth == .sha256 {
            // HMAC over the message cut to 16 bytes: encoded as SHA-224 is (16-byte field).
            out.auth = .sha224
        }
        return try? out.encode(msgID: id, reportable: false, engineID: engineID, boots: boots, time: time,
                               contextEngineID: engineID, contextName: contextName, pdu: resp, salt: salt)
    }
}

// MARK: - Round 2: form input, cancel latency, replaced runs, reports, Keychain names

extension SNMPClientTests {
    func testHostAndPortFieldParsing() {
        typealias M = SNMPTestModel
        func split(_ s: String) -> String {
            let r = M.splitAddress(s)
            return "\(r.host)|\(r.port.map(String.init) ?? "-")|\(r.problem == nil ? "ok" : "bad")"
        }
        XCTAssertEqual(split("10.1.0.1"), "10.1.0.1|-|ok")
        XCTAssertEqual(split(" switch-1:1161 "), "switch-1|1161|ok")
        XCTAssertEqual(split("localhost:1161"), "localhost|1161|ok")
        XCTAssertEqual(split("::1"), "::1|-|ok", "bare IPv6: the port stays in the Port field")
        XCTAssertEqual(split("fe80::1%en0"), "fe80::1%en0|-|ok")
        XCTAssertEqual(split("[::1]"), "::1|-|ok")
        XCTAssertEqual(split("[::1]:1161"), "::1|1161|ok")
        XCTAssertEqual(split("[2001:db8::7]:161"), "2001:db8::7|161|ok")
        XCTAssertEqual(split("[::1"), "[::1|-|bad")
        XCTAssertEqual(split("[::1]x"), "::1|-|bad")
        XCTAssertEqual(split("[]:161"), "[]:161|-|bad")
        XCTAssertEqual(split("switch:0"), "switch|-|bad")
        XCTAssertEqual(split("switch:65536"), "switch|-|bad")
        XCTAssertEqual(split("switch:snmp"), "switch|-|bad")
        XCTAssertEqual(split(":161"), ":161|-|bad")

        XCTAssertNil(M.portProblem("161"))
        XCTAssertNil(M.portProblem(" 65535 "))
        XCTAssertNil(M.portProblem("1"))
        for bad in ["", "0", "65536", "99999999999999999999", "-1", "16a", "1.5", "١٦١"] {
            let p = M.portProblem(bad)
            XCTAssertNotNil(p, bad)
            XCTAssertTrue(p?.contains("1 to 65535") ?? false, "\(bad): \(p ?? "")")
        }

        XCTAssertEqual(M.keychainAccount(host: "10.1.0.1", port: 161), "10.1.0.1:161")
        XCTAssertEqual(M.keychainAccount(host: "::1", port: 1161), "[::1]:1161")
        XCTAssertEqual(M.display(host: "::1", port: 161), "::1")
        XCTAssertEqual(M.display(host: "::1", port: 1161), "[::1]:1161")
        XCTAssertEqual(M.display(host: "sw", port: 1161), "sw:1161")
    }

    /// Community strings are sent as their UTF-8 bytes, spaces and all.
    func testCommunityUTF8OnTheWire() throws {
        let community = "my comm ไทย é"
        let bytes = CommunityMessage.encode(version: .v2c, community: community,
                                            pdu: SNMPPDU(type: BER.getRequest, requestID: 1, varBinds: [VarBind(.sysName, .null)]).encoded())
        XCTAssertEqual(try CommunityMessage.decode(bytes).community, Array(community.utf8))
    }

    /// Cancel resumes the caller at once — not after the socket thread's next 100 ms poll slice.
    func testCancelResumesImmediately() async throws {
        let agent = try FakeAgent(mib: mib(count: 2))
        defer { agent.stop() }
        agent.dropNext = 1_000
        let client = SNMPClient(target: SNMPTarget(host: "127.0.0.1", port: agent.port, timeout: 1, retries: 5),
                                credentials: SNMPCredentials(version: .v2c), engines: EngineCache())
        var worst: TimeInterval = 0
        for i in 0..<20 {
            let task = Task { try await client.walk(OID([1, 3, 6, 1])) }
            try await Task.sleep(for: .milliseconds(5 + 13 * i))
            let c0 = Date()
            task.cancel()
            do { _ = try await task.value; XCTFail() }
            catch { XCTAssertEqual(error as? SNMPError, .cancelled) }
            worst = max(worst, Date().timeIntervalSince(c0))
        }
        XCTAssertLessThan(worst, 0.05, "worst cancel latency \(Int(worst * 1000)) ms")
    }

    /// The cancel handler and the worker race for one continuation: exactly one resume, every
    /// time (a double resume traps).
    func testCancelRaceResumesExactlyOnce() async throws {
        let agent = try FakeAgent(mib: mib(count: 50))
        defer { agent.stop() }
        let client = v2Client(agent)
        var cancelled = 0, finished = 0
        for i in 0..<200 {
            let task = Task { try await client.get([.sysName]) }
            if i % 3 != 0 { try await Task.sleep(for: .microseconds(i * 7 % 400)) }
            task.cancel()
            do { _ = try await task.value; finished += 1 }
            catch { XCTAssertEqual(error as? SNMPError, .cancelled); cancelled += 1 }
        }
        XCTAssertEqual(cancelled + finished, 200)
        let token = CancelToken()
        token.cancel()
        let ran = LockedBox(0)
        XCTAssertFalse(token.onCancel { ran.mutate { $0 += 1 } }, "already cancelled: runs now")
        XCTAssertEqual(ran.value, 1)
        XCTAssertFalse(token.finish(), "the cancel side delivered")
    }

    /// Reports outside USM get words, and the unknown-context one a Context hint.
    func testNonUSMReportsAreExplained() async throws {
        let (agent, creds) = try v3Agent()
        defer { agent.stop() }
        let eid = agent.engineID
        let unknownContexts = OID([1, 3, 6, 1, 6, 3, 12, 1, 5, 0])
        agent.v3Hook = { id, discovery in discovery ? nil : Self.report(unknownContexts, msgID: id, engineID: eid) }
        var c = creds
        c.contextName = "vrf-red"
        let client = SNMPClient(target: SNMPTarget(host: "127.0.0.1", port: agent.port, timeout: 0.5, retries: 0),
                                credentials: c, engines: EngineCache())
        do { _ = try await client.get([.sysName]); XCTFail() }
        catch {
            let e = try XCTUnwrap(error as? SNMPError)
            guard case .decode(let text) = e else { return XCTFail("\(e)") }
            XCTAssertTrue(text.contains("snmpUnknownContexts"), text)
            let hint = await SNMPTestModel.hint(for: e, target: client.target, version: .v3)
            XCTAssertTrue(hint.contains("Context"), hint)
        }
        XCTAssertNotNil(SNMPSession.reportText(OID([1, 3, 6, 1, 6, 3, 11, 2, 1, 3, 0])))
        XCTAssertNil(SNMPSession.reportText(OID([1, 3, 6, 1, 2, 1, 1, 1, 0])))
    }

    /// The timeout card names the port and attempts, and (v1/v2c) that a wrong community looks
    /// exactly like this.
    @MainActor
    func testTimeoutCopyNamesPortAndCommunity() {
        let t = SNMPTarget(host: "10.255.255.1", port: 1161, timeout: 1, retries: 5)
        XCTAssertEqual(SNMPTestModel.title(for: .timeout, target: t), "No response from 10.255.255.1:1161 (UDP 1161) — 6 tries × 1 s.")
        XCTAssertTrue(SNMPTestModel.hint(for: .timeout, target: t, version: .v2c).contains("wrong community looks exactly like this"))
        XCTAssertTrue(SNMPTestModel.hint(for: .timeout, target: t, version: .v2c).contains("UDP 1161"))
        XCTAssertFalse(SNMPTestModel.hint(for: .timeout, target: t, version: .v3).contains("community"))
        XCTAssertEqual(SNMPTestModel.title(for: .wrongDigest, target: t), SNMPError.wrongDigest.errorDescription)
    }

    /// A second operation started while one runs replaces it: the first one's cancellation (or
    /// late result) never reaches the form. A bad port is refused with words, not ignored.
    @MainActor
    func testSecondOperationReplacesTheFirst() async throws {
        let agent = try FakeAgent(mib: mib(count: 2))
        defer { agent.stop() }
        agent.dropNext = 1_000
        let m = SNMPTestModel.shared
        let saved = (m.host, m.port, m.timeout, m.retries, m.version, m.oidText)
        defer {
            m.cancel()
            (m.host, m.port, m.timeout, m.retries, m.version, m.oidText) = saved
        }
        m.host = "127.0.0.1"
        m.port = agent.port
        m.version = .v2c
        m.timeout = 0.4
        m.retries = 0
        m.oidText = ""
        m.quickTest()
        XCTAssertEqual(m.running, "Quick test")
        m.walk()                                    // replaces the Quick Test
        XCTAssertEqual(m.running, "Walk")
        try await Task.sleep(for: .milliseconds(150))
        XCTAssertEqual(m.running, "Walk", "the cancelled Quick Test must not end the Walk's run")
        XCTAssertNotEqual(m.heading, "Stopped.")
        let end = Date().addingTimeInterval(3)
        while m.isRunning, Date() < end { try await Task.sleep(for: .milliseconds(20)) }
        guard case .failure(let e, let context, let title, let hint) = m.outcome else { return XCTFail("\(String(describing: m.outcome))") }
        XCTAssertEqual(e, .timeout)
        XCTAssertEqual(context, "Walk")
        XCTAssertTrue(title.contains("UDP \(agent.port)"), title)
        XCTAssertTrue(hint.contains("community"), hint)
        try await Task.sleep(for: .milliseconds(300))
        if case .failure(_, let c2, _, _) = m.outcome { XCTAssertEqual(c2, "Walk") } else { XCTFail("outcome replaced") }

        // Port field: out of range, zero and text are refused with a message.
        for bad in ["65536", "0", "snmp"] {
            m.portText = bad
            XCTAssertNotNil(m.portProblem)
            m.quickTest()
            XCTAssertFalse(m.isRunning, bad)
            guard case .failure(_, "form", let title, _) = m.outcome else { return XCTFail("\(bad): \(String(describing: m.outcome))") }
            XCTAssertTrue(title.contains("1 to 65535"), title)
        }
        m.portText = "1161"
        XCTAssertEqual(m.port, 1161)
        XCTAssertNil(m.portProblem)
        // Host with a port and brackets moves the port into the Port field.
        m.host = "[::1]:\(agent.port)"
        m.quickTest()
        XCTAssertEqual(m.host, "::1")
        XCTAssertEqual(m.port, agent.port)
        XCTAssertEqual(m.portText, String(agent.port))
        m.cancel()
    }

    /// Keychain entries per target, IPv6 bracketed; an unbracketed entry from an earlier build
    /// is found and renamed. Test items use their own host names and are removed.
    func testKeychainAccountsPerTarget() throws {
        let tag = "sheeplog-test-\(UUID().uuidString.prefix(8))"
        let v6 = "fd00:\(tag.count)::\(Int.random(in: 1...0xfff))"
        let accounts = ["\(tag):1161", "[\(v6)]:1161", "\(v6):1161"]
        defer { for a in accounts { KeychainStore.delete(account: a) } }
        var c = SNMPCredentials(version: .v3, username: "u1", authPassword: "pw-one-long", privPassword: "pw-two-long")
        KeychainStore.saveCredentials(c, host: tag, port: 1161)
        guard KeychainStore.load(account: "\(tag):1161") != nil else {
            throw XCTSkip("the login keychain is not writable from this test host")
        }
        XCTAssertEqual(KeychainStore.loadCredentials(host: tag, port: 1161), c)
        XCTAssertNil(KeychainStore.loadCredentials(host: tag, port: 161), "per port")

        c.username = "u6"
        KeychainStore.saveCredentials(c, host: v6, port: 1161)
        XCTAssertNotNil(KeychainStore.load(account: "[\(v6)]:1161"))
        XCTAssertEqual(KeychainStore.loadCredentials(host: v6, port: 1161)?.username, "u6")
        // Legacy name only.
        KeychainStore.delete(account: "[\(v6)]:1161")
        c.username = "legacy"
        KeychainStore.saveCredentials(c, account: "\(v6):1161")
        XCTAssertEqual(KeychainStore.loadCredentials(host: v6, port: 1161)?.username, "legacy")
        XCTAssertNotNil(KeychainStore.load(account: "[\(v6)]:1161"), "moved to the bracketed name")
        XCTAssertNil(KeychainStore.load(account: "\(v6):1161"))
    }

    /// The Test pane against an agent that never answers (1 s × 6 tries): the main thread keeps
    /// ticking, and Cancel ends the run (running = nil, "Stopped.") within 100 ms.
    @MainActor
    func testPaneStaysResponsiveAndCancelsFast() async throws {
        let agent = try FakeAgent(mib: mib(count: 2))
        defer { agent.stop() }
        agent.dropNext = 100_000
        let m = SNMPTestModel.shared
        let saved = (m.host, m.port, m.timeout, m.retries, m.version)
        defer { (m.host, m.port, m.timeout, m.retries, m.version) = saved }
        m.host = "127.0.0.1"
        m.port = agent.port
        m.version = .v2c
        m.timeout = 1
        m.retries = 5
        m.quickTest()
        var worstGap: TimeInterval = 0
        var last = Date()
        let until = Date().addingTimeInterval(1.2)
        while Date() < until {
            try await Task.sleep(for: .milliseconds(10))
            worstGap = max(worstGap, Date().timeIntervalSince(last))
            last = Date()
        }
        XCTAssertTrue(m.isRunning)
        let c0 = Date()
        m.cancel()
        while m.isRunning, Date().timeIntervalSince(c0) < 2 { try await Task.sleep(for: .milliseconds(1)) }
        let latency = Date().timeIntervalSince(c0)
        print("pane: worst main-thread gap \(Int(worstGap * 1000)) ms, cancel → idle \(Int(latency * 1000)) ms")
        XCTAssertLessThan(worstGap, 0.1)
        XCTAssertLessThan(latency, 0.1)
        XCTAssertEqual(m.heading, "Stopped.")
    }

    /// Device-controlled values cannot become spreadsheet formulas in the CSV export.
    @MainActor
    func testCSVExportNeutralisesFormulas() {
        let rows = ["=HYPERLINK(\"http://x\")", "+1", "-2", "@SUM(A1)", "\tx", "plain", "say \"hi\""].enumerated().map {
            VarBindRow(id: $0.offset, oid: OID([1, 3, 6, 1, UInt32($0.offset)]), oidText: "1.3.6.1.\($0.offset)",
                       name: "sysDescr.0", type: "STRING", value: $0.element, isBad: false)
        }
        let lines = SNMPTestModel.shared.csv(rows).split(separator: "\n").map(String.init)
        XCTAssertEqual(lines[0], "OID,Name,Type,Value")
        XCTAssertEqual(lines[1], "\"1.3.6.1.0\",\"sysDescr.0\",\"STRING\",\"'=HYPERLINK(\"\"http://x\"\")\"")
        XCTAssertTrue(lines[2].hasSuffix(",\"'+1\""))
        XCTAssertTrue(lines[3].hasSuffix(",\"'-2\""))
        XCTAssertTrue(lines[4].hasSuffix(",\"'@SUM(A1)\""))
        XCTAssertTrue(lines[5].hasSuffix(",\"'\tx\""))
        XCTAssertTrue(lines[6].hasSuffix(",\"plain\""))
        XCTAssertTrue(lines[7].hasSuffix(",\"say \"\"hi\"\"\""))
    }

    /// ifSpeed is bit/s (exact to 4.29 Gb/s), ifHighSpeed Mb/s: the join must not round
    /// 748.8 Mb/s down, and must use ifHighSpeed when ifSpeed is saturated or 0.
    @MainActor
    func testInterfaceSpeedUnits() {
        let e = OID.ifTable.appending(1), x = OID.ifXTable.appending(1)
        let ifTable = [VarBind(e.appending([2, 1]), .octetString(Data("en0".utf8))), VarBind(e.appending([5, 1]), .gauge32(748_800_000)),
                       VarBind(e.appending([2, 2]), .octetString(Data("te1".utf8))), VarBind(e.appending([5, 2]), .gauge32(UInt32.max)),
                       VarBind(e.appending([2, 3]), .octetString(Data("vl3".utf8))), VarBind(e.appending([5, 3]), .gauge32(0)),
                       VarBind(e.appending([2, 4]), .octetString(Data("fe4".utf8))), VarBind(e.appending([5, 4]), .gauge32(100_000_000))]
        let ifX = [VarBind(x.appending([1, 2]), .octetString(Data("Te1/1".utf8))),
                   VarBind(x.appending([15, 1]), .gauge32(748)), VarBind(x.appending([15, 2]), .gauge32(10_000)),
                   VarBind(x.appending([15, 3]), .gauge32(100)), VarBind(x.appending([15, 4]), .gauge32(100))]
        let rows = SNMPTestModel.joinInterfaces(ifTable: ifTable, ifXTable: ifX)
        XCTAssertEqual(rows.map(\.speedText), ["748.8 Mb/s", "10 Gb/s", "100 Mb/s", "100 Mb/s"])
        XCTAssertEqual(rows[1].name, "Te1/1", "ifName wins")
        XCTAssertEqual(rows[1].descr, "te1", "ifDescr kept")
    }
}
