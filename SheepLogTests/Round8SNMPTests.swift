import XCTest
@testable import SheepLog

/// Round 8: AES-192/256 with both key extensions — Reeder/Cisco (`aes192` / `aes256`, net-snmp's
/// AES192C / AES256C) and Blumenthal (`aes192b` / `aes256b`, draft-blumenthal-aes-usm-04
/// §3.1.2.1, net-snmp's AES192 / AES256) — and the diagnosis that tells them apart.
final class Round8SNMPTests: XCTestCase {
    private let engine: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
    private func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

    /// Known answers. SHA-1 "maplesyrup", engine 00…02: the draft's own Appendix A.1 vector
    /// (Kul ‖ SHA1(Kul), 256 bits). The MD5 and SHA-256 ones follow the draft's algorithm
    /// (Kul = Kul ‖ H(Kul) until long enough), computed independently with Python's hashlib.
    func testBlumenthalKeyExtensionKnownAnswers() {
        XCTAssertEqual(hex(USM.privKey(password: "maplesyrup", auth: .sha1, priv: .aes256b, engineID: engine)),
                       "6695febc9288e36282235fc7151f128497b38f3f505e07eb9af25568fa1f5dbe")
        XCTAssertEqual(hex(USM.privKey(password: "maplesyrup", auth: .sha1, priv: .aes192b, engineID: engine)),
                       "6695febc9288e36282235fc7151f128497b38f3f505e07eb")
        XCTAssertEqual(hex(USM.privKey(password: "maplesyrup", auth: .md5, priv: .aes256b, engineID: engine)),
                       "526f5eed9fcce26f8964c2930787d82bfa24a92467426c2f4b09192be10dfaec")
        XCTAssertEqual(hex(USM.privKey(password: "maplesyrup", auth: .md5, priv: .aes192b, engineID: engine)),
                       "526f5eed9fcce26f8964c2930787d82bfa24a92467426c2f")
        // A 256-bit hash needs no extension: both variants are the localized key.
        XCTAssertEqual(hex(USM.privKey(password: "maplesyrup", auth: .sha256, priv: .aes256b, engineID: engine)),
                       "8982e0e549e866db361a6b625d84cccc11162d453ee8ce3a6445c2d6776f0f8b")
        XCTAssertEqual(USM.privKey(password: "maplesyrup", auth: .sha256, priv: .aes256b, engineID: engine),
                       USM.privKey(password: "maplesyrup", auth: .sha256, priv: .aes256, engineID: engine))
        // Two rounds: H(Kul), then H(Kul ‖ H(Kul)).
        let kul = USM.localizedKey(password: "maplesyrup", engineID: engine, .md5)
        XCTAssertEqual(hex(USM.extendKeyBlumenthal(kul, to: 48, .md5)),
                       "526f5eed9fcce26f8964c2930787d82bfa24a92467426c2f4b09192be10dfaecf0e919ede2ddaa44c67a3ed12eda7a81")
        // The Reeder/Cisco extension is unchanged (pysnmp / net-snmp AES256C vectors).
        XCTAssertEqual(hex(USM.privKey(password: "maplesyrup", auth: .sha1, priv: .aes256, engineID: engine)),
                       "6695febc9288e36282235fc7151f128497b38f3f9b8b6d78936ba6e7d19dfd9c")
        XCTAssertEqual(hex(USM.privKey(password: "maplesyrup", auth: .md5, priv: .aes256, engineID: engine)),
                       "526f5eed9fcce26f8964c2930787d82b79eff44a90650ee0a3a40abfac5acc12")
    }

    func testBlumenthalRoundTripsAndLabels() throws {
        for p in [PrivProtocol.aes192b, .aes256b] {
            let key = USM.privKey(password: "privpassword", auth: .sha1, priv: p, engineID: engine)
            XCTAssertEqual(key.count, p == .aes192b ? 24 : 32)
            let plain = Array((0..<77).map { UInt8($0) })
            let salt = USM.aesSalt(42)
            let cipher = try USM.encrypt(p, key: key, boots: 3, time: 4567, salt: salt, plaintext: plain)
            XCTAssertEqual(try USM.decrypt(p, key: key, boots: 3, time: 4567, salt: salt, ciphertext: cipher), plain)
        }
        XCTAssertEqual(PrivProtocol.aes192b.label, "AES-192 (Blumenthal)")
        XCTAssertEqual(PrivProtocol.aes256b.label, "AES-256 (Blumenthal)")
        XCTAssertEqual(PrivProtocol.aes256.otherKeyExtension, .aes256b)
        XCTAssertEqual(PrivProtocol.aes192b.otherKeyExtension, .aes192)
        XCTAssertNil(PrivProtocol.aes128.otherKeyExtension)
    }

    /// Settings written before round 8 keep meaning Reeder/Cisco; the new cases round-trip.
    func testStoredPrivProtocolsKeepTheirMeaning() throws {
        let old = #"{"version":"v3","community":"","username":"u","authProtocol":"sha1","authPassword":"","privProtocol":"aes256","privPassword":"","contextName":""}"#
        let c = try JSONDecoder().decode(SNMPCredentials.self, from: Data(old.utf8))
        XCTAssertEqual(c.privProtocol, .aes256)
        for p in PrivProtocol.allCases {
            var creds = SNMPCredentials(version: .v3)
            creds.privProtocol = p
            let back = try JSONDecoder().decode(SNMPCredentials.self, from: JSONEncoder().encode(creds))
            XCTAssertEqual(back.privProtocol, p)
        }
    }

    /// A Blumenthal agent against every level, and the other extension diagnosed both ways
    /// (net-snmp drops what it cannot decrypt; other agents report usmStatsDecryptionErrors).
    func testFakeAgentWithEitherExtension() async throws {
        let pairs: [(agent: PrivProtocol, client: PrivProtocol)] = [
            (.aes256b, .aes256), (.aes256, .aes256b), (.aes192b, .aes192), (.aes192, .aes192b),
        ]
        for (agentPriv, clientPriv) in pairs {
            for drop in [true, false] {
                let agent = try FakeAgent(mib: [VarBind(.sysDescr, .octetString(Data("fake".utf8)))])
                defer { agent.stop() }
                agent.user = FakeAgent.User(name: "lab", auth: .sha1, priv: agentPriv, authPassword: "labpassword",
                                            privPassword: "labprivpass")
                agent.dropUndecryptable = drop
                let target = SNMPTarget(host: "127.0.0.1", port: agent.port, timeout: 0.4, retries: 0)
                var creds = SNMPCredentials(version: .v3, username: "lab", authProtocol: .sha1, authPassword: "labpassword",
                                            privProtocol: agentPriv, privPassword: "labprivpass")
                let ok = try await SNMPClient(target: target, credentials: creds, engines: EngineCache()).get([.sysDescr])
                XCTAssertEqual(ok.varBinds.first?.value, .octetString(Data("fake".utf8)))
                creds.privProtocol = clientPriv
                do {
                    _ = try await SNMPClient(target: target, credentials: creds, engines: EngineCache()).get([.sysDescr])
                    XCTFail("\(clientPriv) answered by a \(agentPriv) agent")
                } catch {
                    XCTAssertEqual(error as? SNMPError, .privKeyExtension(agentPriv), "\(agentPriv) agent, \(clientPriv), drop \(drop)")
                }
                // A wrong priv password is still a wrong priv password.
                creds.privProtocol = agentPriv
                creds.privPassword = "wrongprivpass"
                do {
                    _ = try await SNMPClient(target: target, credentials: creds, engines: EngineCache()).get([.sysDescr])
                    XCTFail("answered")
                } catch {
                    XCTAssertEqual(error as? SNMPError, .decryptionError, "\(agentPriv), drop \(drop)")
                }
            }
        }
    }

    @MainActor
    func testHelpSaysWhichToPick() {
        let help = SNMPTestView.privHelp
        XCTAssertTrue(help.contains("Cisco, Palo Alto, Fortinet, Aruba: AES-192 / AES-256"))
        XCTAssertTrue(help.contains("not AES256C"))
        XCTAssertTrue(help.contains("(Blumenthal)"))
        let target = SNMPTarget(host: "10.0.0.1")
        XCTAssertTrue(SNMPTestModel.hint(for: .privKeyExtension(.aes256b), target: target, version: .v3).contains("AES-256 (Blumenthal)"))
        XCTAssertTrue(SNMPError.privKeyExtension(.aes256).errorDescription?.contains("AES-256") ?? false)
    }
}
