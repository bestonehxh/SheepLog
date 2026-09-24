import XCTest
@testable import SheepLog

final class USMTests: XCTestCase {
    private let engine: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]

    private func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

    /// RFC 3414 A.3.1 / A.3.2.
    func testKeyLocalisationVectors() {
        XCTAssertEqual(hex(USM.passwordToKey("maplesyrup", .md5)), "9faf3283884e92834ebc9847d8edd963")
        XCTAssertEqual(hex(USM.localizedKey(password: "maplesyrup", engineID: engine, .md5)),
                       "526f5eed9fcce26f8964c2930787d82b")
        XCTAssertEqual(hex(USM.passwordToKey("maplesyrup", .sha1)), "9fb5cc0381497b3793528939ff788d5d79145211")
        XCTAssertEqual(hex(USM.localizedKey(password: "maplesyrup", engineID: engine, .sha1)),
                       "6695febc9288e36282235fc7151f128497b38f3f")
    }

    func testDigestAndMACLengths() {
        let expected: [(AuthProtocol, Int, Int)] = [
            (.md5, 16, 12), (.sha1, 20, 12), (.sha224, 28, 16), (.sha256, 32, 24), (.sha384, 48, 32), (.sha512, 64, 48),
        ]
        for (p, digest, mac) in expected {
            XCTAssertEqual(USM.hash(p, Array("abc".utf8)).count, digest, p.label)
            XCTAssertEqual(USM.localizedKey(password: "maplesyrup", engineID: engine, p).count, digest, p.label)
            XCTAssertEqual(USM.macLength(p), mac, p.label)
            XCTAssertEqual(USM.mac(p, key: [1, 2, 3], message: [4, 5, 6]).count, mac, p.label)
        }
        // SHA-224("abc") — FIPS 180-2 example.
        XCTAssertEqual(hex(USM.hash(.sha224, Array("abc".utf8))), "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7")
        // HMAC-SHA-256 (RFC 4231 test case 2).
        XCTAssertEqual(hex(USM.hmac(.sha256, key: Array("Jefe".utf8), data: Array("what do ya want for nothing?".utf8))),
                       "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    }

    func testReederKeyExtension() {
        let md5Priv = USM.privKey(password: "maplesyrup", auth: .md5, priv: .aes256, engineID: engine)
        XCTAssertEqual(md5Priv.count, 32)
        let kul = USM.localizedKey(password: "maplesyrup", engineID: engine, .md5)
        XCTAssertEqual(Array(md5Priv.prefix(16)), kul, "the extension keeps Kul as its prefix")
        // K2 = localize(passwordToKey(K1)): the full 1 MB password-to-key run, not a single hash.
        XCTAssertEqual(Array(md5Priv.suffix(16)),
                       USM.localize(USM.passwordToKey(bytes: kul, .md5), engineID: engine, .md5))
        XCTAssertEqual(USM.privKey(password: "maplesyrup", auth: .sha1, priv: .aes256, engineID: engine).count, 32)
        XCTAssertEqual(USM.privKey(password: "maplesyrup", auth: .sha1, priv: .aes192, engineID: engine).count, 24)
        XCTAssertEqual(USM.privKey(password: "maplesyrup", auth: .sha224, priv: .aes256, engineID: engine).count, 32)
        XCTAssertEqual(USM.privKey(password: "maplesyrup", auth: .sha256, priv: .aes256, engineID: engine).count, 32)
        XCTAssertEqual(USM.privKey(password: "maplesyrup", auth: .sha1, priv: .aes128, engineID: engine),
                       Array(USM.localizedKey(password: "maplesyrup", engineID: engine, .sha1).prefix(16)))
    }

    /// Known answers for the Reeder extension, computed with pysnmp's `AbstractAesReeder.localizeKey`
    /// algorithm (hashPassphrase → localizeKey, repeated with the key so far as the passphrase),
    /// password "maplesyrup", engine 00…02. The first 16/20 bytes are the RFC 3414 A.3 keys.
    func testReederKeyExtensionKnownAnswers() {
        XCTAssertEqual(hex(USM.privKey(password: "maplesyrup", auth: .md5, priv: .aes256, engineID: engine)),
                       "526f5eed9fcce26f8964c2930787d82b79eff44a90650ee0a3a40abfac5acc12")
        XCTAssertEqual(hex(USM.privKey(password: "maplesyrup", auth: .md5, priv: .aes192, engineID: engine)),
                       "526f5eed9fcce26f8964c2930787d82b79eff44a90650ee0")
        XCTAssertEqual(hex(USM.privKey(password: "maplesyrup", auth: .sha1, priv: .aes256, engineID: engine)),
                       "6695febc9288e36282235fc7151f128497b38f3f9b8b6d78936ba6e7d19dfd9c")
        XCTAssertEqual(hex(USM.privKey(password: "maplesyrup", auth: .sha1, priv: .aes192, engineID: engine)),
                       "6695febc9288e36282235fc7151f128497b38f3f9b8b6d78")
        XCTAssertEqual(hex(USM.privKey(password: "maplesyrup", auth: .sha256, priv: .aes256, engineID: engine)),
                       "8982e0e549e866db361a6b625d84cccc11162d453ee8ce3a6445c2d6776f0f8b")
    }

    func testDESRoundTrip() throws {
        let key = USM.privKey(password: "privpassword", auth: .md5, priv: .des, engineID: engine)
        XCTAssertEqual(key.count, 16)
        let plain = BER.encodeSequence([BER.encodeOctets(Array("some scoped PDU of odd length".utf8))])
        let salt = USM.desSalt(boots: 7, counter: 12345)
        let cipher = try USM.encrypt(.des, key: key, boots: 7, time: 100, salt: salt, plaintext: plain)
        XCTAssertEqual(cipher.count % 8, 0)
        XCTAssertNotEqual(Array(cipher.prefix(plain.count)), plain)
        let back = try USM.decrypt(.des, key: key, boots: 7, time: 100, salt: salt, ciphertext: cipher)
        XCTAssertEqual(Array(back.prefix(plain.count)), plain)
        XCTAssertThrowsError(try USM.decrypt(.des, key: key, boots: 7, time: 100, salt: salt, ciphertext: Array(cipher.dropLast())))
    }

    func testAESRoundTrips() throws {
        for p in [PrivProtocol.aes128, .aes192, .aes256] {
            let key = USM.privKey(password: "privpassword", auth: .sha1, priv: p, engineID: engine)
            let plain = Array((0..<77).map { UInt8($0) })
            let salt = USM.aesSalt(0x0102_0304_0506_0708)
            let cipher = try USM.encrypt(p, key: key, boots: 3, time: 4567, salt: salt, plaintext: plain)
            XCTAssertEqual(cipher.count, plain.count, "CFB needs no padding")
            XCTAssertNotEqual(cipher, plain)
            XCTAssertEqual(try USM.decrypt(p, key: key, boots: 3, time: 4567, salt: salt, ciphertext: cipher), plain)
            // A different engine time gives a different IV, so garbage.
            XCTAssertNotEqual(try USM.decrypt(p, key: key, boots: 3, time: 4568, salt: salt, ciphertext: cipher), plain)
        }
    }

    /// RFC 3826 uses AES-128-CFB: check CommonCrypto's CFB against the NIST SP 800-38A F.3.13 vector.
    func testAESCFB128KnownAnswer() throws {
        func bytes(_ s: String) -> [UInt8] {
            var out: [UInt8] = []
            var i = s.startIndex
            while i < s.endIndex {
                let j = s.index(i, offsetBy: 2)
                out.append(UInt8(s[i..<j], radix: 16)!)
                i = j
            }
            return out
        }
        let key = bytes("2b7e151628aed2a6abf7158809cf4f3c")
        let iv = bytes("000102030405060708090a0b0c0d0e0f")
        // IV = boots ‖ time ‖ salt → split the NIST IV accordingly.
        let boots = UInt32(0x0001_0203), time = UInt32(0x0405_0607)
        let salt = Array(iv[8..<16])
        let plain = bytes("6bc1bee22e409f96e93d7e117393172a")
        let cipher = try USM.encrypt(.aes128, key: key, boots: boots, time: time, salt: salt, plaintext: plain)
        XCTAssertEqual(hex(cipher), "3b3fd92eb72dad20333449f8e83cfb4a")
    }
}
