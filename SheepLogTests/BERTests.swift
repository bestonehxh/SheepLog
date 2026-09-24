import XCTest
@testable import SheepLog

final class BERTests: XCTestCase {
    private func roundTrip(_ v: SNMPValue, file: StaticString = #filePath, line: UInt = #line) throws {
        let bytes = BER.encodeValue(v)
        var r = BERReader(bytes)
        let back = try BER.decodeValue(try r.readTLV())
        XCTAssertEqual(back, v, file: file, line: line)
        XCTAssertTrue(r.isAtEnd, file: file, line: line)
    }

    func testIntegerEncodingIsMinimalTwosComplement() {
        XCTAssertEqual(BER.encodeInteger(0), [0x02, 0x01, 0x00])
        XCTAssertEqual(BER.encodeInteger(127), [0x02, 0x01, 0x7F])
        XCTAssertEqual(BER.encodeInteger(128), [0x02, 0x02, 0x00, 0x80])
        XCTAssertEqual(BER.encodeInteger(256), [0x02, 0x02, 0x01, 0x00])
        XCTAssertEqual(BER.encodeInteger(-1), [0x02, 0x01, 0xFF])
        XCTAssertEqual(BER.encodeInteger(-128), [0x02, 0x01, 0x80])
        XCTAssertEqual(BER.encodeInteger(-129), [0x02, 0x02, 0xFF, 0x7F])
        XCTAssertEqual(BER.encodeInteger(Int64.min).count, 10)
    }

    func testIntegerRoundTrips() throws {
        for v: Int64 in [0, 1, -1, 127, 128, -128, -129, 255, 256, 32767, -32768, 65535, 2_147_483_647,
                         -2_147_483_648, 4_294_967_295, Int64.max, Int64.min] {
            try roundTrip(.integer(v))
        }
    }

    func testUnsignedTypes() throws {
        XCTAssertEqual(BER.encodeValue(.counter32(UInt32.max)), [0x41, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF])
        XCTAssertEqual(BER.encodeValue(.counter64(UInt64.max)), [0x46, 0x09, 0x00] + [UInt8](repeating: 0xFF, count: 8))
        try roundTrip(.counter32(0))
        try roundTrip(.counter32(UInt32.max))
        try roundTrip(.gauge32(1_000_000_000))
        try roundTrip(.timeTicks(123_456_789))
        try roundTrip(.counter64(18_446_744_073_709_551_615))
        try roundTrip(.counter64(9_876_543_210_123))
        // Sloppy agents send Counter32 without the leading zero: read it as unsigned anyway.
        var r = BERReader([0x41, 0x04, 0xFF, 0xFF, 0xFF, 0xFE])
        XCTAssertEqual(try BER.decodeValue(try r.readTLV()), .counter32(0xFFFF_FFFE))
    }

    func testEveryValueType() throws {
        let values: [SNMPValue] = [
            .integer(-42), .octetString(Data("SheepLog".utf8)), .octetString(Data()), .null,
            .oid(OID([1, 3, 6, 1, 4, 1, 14823, 1, 2, 3])), .ipAddress("10.1.0.254"), .counter32(7),
            .gauge32(8), .timeTicks(9), .opaque(Data([0x9F, 0x78, 0x04, 0x3F, 0x80, 0x00, 0x00])),
            .counter64(1 << 40), .noSuchObject, .noSuchInstance, .endOfMibView,
        ]
        for v in values { try roundTrip(v) }
    }

    func testOIDEncoding() throws {
        XCTAssertEqual(BER.encodeOID(.sysDescr), [0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
        // 2.999 → first sub-identifier 1079 = 0x88 0x37 (X.690 example)
        XCTAssertEqual(BER.encodeOID(OID([2, 999, 3])), [0x06, 0x03, 0x88, 0x37, 0x03])
        try roundTrip(.oid(OID([2, 999, 3])))
        try roundTrip(.oid(OID([1, 3, 6, 1, 4, 1, UInt32.max, 0, UInt32.max])))
        try roundTrip(.oid(OID([2, UInt32.max])))
        try roundTrip(.oid(OID([0, 0])))
        try roundTrip(.oid(OID([1, 0, 8802, 1, 1, 2, 1, 4, 1])))
        // Sub-identifier beyond 32 bits is rejected, not wrapped.
        var r = BERReader([0x06, 0x07, 0x2B, 0x90, 0x80, 0x80, 0x80, 0x80, 0x00])
        XCTAssertThrowsError(try r.readTLV().oid())
    }

    func testLongFormLengths() throws {
        for n in [127, 128, 255, 256, 300, 65_535, 70_000] {
            let d = Data((0..<n).map { UInt8($0 & 0xFF) })
            let enc = BER.encodeValue(.octetString(d))
            if n == 300 { XCTAssertEqual(Array(enc.prefix(4)), [0x04, 0x82, 0x01, 0x2C]) }
            if n == 128 { XCTAssertEqual(Array(enc.prefix(3)), [0x04, 0x81, 0x80]) }
            try roundTrip(.octetString(d))
        }
        XCTAssertEqual(BER.length(70_000), [0x83, 0x01, 0x11, 0x70])
    }

    func testMalformedInputThrows() {
        let bad: [[UInt8]] = [
            [], [0x30], [0x30, 0x05, 0x02, 0x01], [0x04, 0x84, 0xFF, 0xFF, 0xFF, 0xFF],
            [0x04, 0x80, 0x00], [0x02, 0x00], [0x1F, 0x01, 0x00], [0x04, 0x85, 1, 1, 1, 1, 1],
        ]
        for b in bad {
            var r = BERReader(b)
            XCTAssertThrowsError(try { let t = try r.readTLV(); _ = try BER.decodeValue(t) }(), "\(b)")
        }
    }

    func testMoreMalformedShapes() throws {
        // Single-byte OID: first sub-identifier only.
        var r1 = BERReader([0x06, 0x01, 0x2B])
        XCTAssertEqual(try r1.readTLV().oid(), OID([1, 3]))
        // Counter64 that is really a 9-byte negative number: an error, not a wrap.
        var r2 = BERReader([0x46, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        XCTAssertThrowsError(try BER.decodeValue(try r2.readTLV()))
        // Length bigger than what is left, in each long form.
        for bad: [UInt8] in [[0x04, 0x81, 0x05, 1], [0x04, 0x82, 0x01, 0x00, 1], [0x04, 0x84, 0x7F, 0xFF, 0xFF, 0xFF, 1]] {
            var r = BERReader(bad)
            XCTAssertThrowsError(try r.readTLV(), "\(bad)")
        }
        // A var-bind whose value is a 20,000-deep SEQUENCE bomb: rejected without recursion.
        var bomb: [UInt8] = [0x05, 0x00]
        for _ in 0..<20_000 { bomb = BER.tlv(0x30, bomb) }
        let msg = CommunityMessage.encode(version: .v2c, community: "public",
                                          pdu: BER.encodeSequence([BER.encodeInteger(1), BER.encodeInteger(0), BER.encodeInteger(0),
                                                                   BER.encodeSequence([BER.encodeSequence([BER.encodeOID(.sysDescr), bomb])])],
                                                                  tag: BER.response))
        XCTAssertThrowsError(try CommunityMessage.decode(msg))
        // A Response whose var-bind list is not a SEQUENCE, and a PDU with a tag that is no PDU.
        let noList = CommunityMessage.encode(version: .v2c, community: "p",
                                             pdu: BER.encodeSequence([BER.encodeInteger(1), BER.encodeInteger(0), BER.encodeInteger(0),
                                                                      BER.encodeOctets([1])], tag: BER.response))
        XCTAssertThrowsError(try CommunityMessage.decode(noList))
        XCTAssertThrowsError(try CommunityMessage.decode(CommunityMessage.encode(version: .v2c, community: "p", pdu: BER.encodeNull())))
        // Decoding works on a buffer that is a slice of a larger one (absolute offsets).
        let inner = BER.encodeValue(.octetString(Data("abc".utf8)))
        let outer = [0xEE, 0xEE] + inner + [0xEE]
        var sliced = BERReader(outer, range: 2..<(2 + inner.count))
        XCTAssertEqual(try BER.decodeValue(try sliced.readTLV()), .octetString(Data("abc".utf8)))
        XCTAssertTrue(sliced.isAtEnd)
        let d = Data(outer)[2..<(2 + inner.count)]      // a Data slice with startIndex 2
        var fromData = BERReader(d)
        XCTAssertEqual(try BER.decodeValue(try fromData.readTLV()), .octetString(Data("abc".utf8)))
    }

    /// RFC 1157 Trap-PDU: [4] IMPLICIT SEQUENCE { enterprise, agent-addr (IpAddress), generic,
    /// specific, time-stamp (TimeTicks), variable-bindings } — byte for byte.
    func testV1TrapWireFormat() {
        let t = TrapV1PDU(enterprise: OID([1, 3, 6, 1, 4, 1, 9]), agentAddress: "10.0.0.1", genericTrap: 6,
                          specificTrap: 1, timeStamp: 100, varBinds: [])
        XCTAssertEqual(t.encoded(), [0xA4, 0x19,
                                     0x06, 0x06, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x09,
                                     0x40, 0x04, 0x0A, 0x00, 0x00, 0x01,
                                     0x02, 0x01, 0x06,
                                     0x02, 0x01, 0x01,
                                     0x43, 0x01, 0x64,
                                     0x30, 0x00])
    }

    func testPDURoundTrip() throws {
        let pdu = SNMPPDU(type: BER.getBulkRequest, requestID: -5, errorStatus: 0, errorIndex: 20,
                          varBinds: [VarBind(.ifTable, .null), VarBind(.sysUpTime, .timeTicks(5))])
        var r = BERReader(pdu.encoded())
        XCTAssertEqual(try SNMPPDU.decode(try r.readTLV()), pdu)
        let trap = TrapV1PDU(enterprise: OID([1, 3, 6, 1, 4, 1, 14823]), agentAddress: "10.0.0.9", genericTrap: 6,
                             specificTrap: 1003, timeStamp: 4242, varBinds: [VarBind(OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 3]), .integer(3))])
        var tr = BERReader(trap.encoded())
        let back = try TrapV1PDU.decode(try tr.readTLV())
        XCTAssertEqual(back, trap)
        XCTAssertEqual(back.trapOID, OID([1, 3, 6, 1, 4, 1, 14823, 0, 1003]))
    }

    /// Walks every TLV (recursing into constructed ones) and decodes every value it can.
    private func exercise(_ r: inout BERReader, depth: Int = 0) {
        guard depth < 64 else { return }
        while !r.isAtEnd {
            guard let t = try? r.readTLV() else { return }
            if t.tag == 0x30 || (t.tag >= 0xA0 && t.tag <= 0xA8) {
                var inner = t.reader
                exercise(&inner, depth: depth + 1)
                _ = try? SNMPPDU.decode(t)
                _ = try? TrapV1PDU.decode(t)
            } else {
                _ = try? BER.decodeValue(t)
                _ = try? t.int64()
                _ = try? t.uint64()
                _ = try? t.oid()
            }
        }
    }

    func testFuzzRandomBuffersNeverCrash() {
        var rng = SystemRandomNumberGenerator()
        let sample = CommunityMessage.encode(version: .v2c, community: "public",
                                             pdu: SNMPPDU(type: BER.response, requestID: 77,
                                                          varBinds: [VarBind(.sysDescr, .octetString(Data("x".utf8))),
                                                                     VarBind(.ifNumber, .integer(24))]).encoded())
        let sec = USMSecurity(userName: "u", auth: .sha1, priv: .aes128, authKey: [UInt8](repeating: 1, count: 20),
                              privKey: [UInt8](repeating: 2, count: 16))
        let v3 = try! sec.encode(msgID: 9, reportable: true, engineID: [1, 2, 3, 4, 5], boots: 1, time: 2,
                                 contextEngineID: [1, 2, 3, 4, 5], contextName: "",
                                 pdu: SNMPPDU(type: BER.getRequest, requestID: 9, varBinds: [VarBind(.sysDescr, .null)]),
                                 salt: [0, 0, 0, 0, 0, 0, 0, 1])
        for i in 0..<2_000 {
            var bytes: [UInt8]
            switch i % 4 {
            case 0:
                bytes = (0..<Int.random(in: 0...300, using: &rng)).map { _ in UInt8.random(in: 0...255, using: &rng) }
            case 1:
                // Plausible framing, random insides.
                bytes = [0x30, UInt8.random(in: 0...255, using: &rng)] +
                    (0..<Int.random(in: 0...200, using: &rng)).map { _ in UInt8.random(in: 0...255, using: &rng) }
            case 2:
                bytes = sample
                for _ in 0..<Int.random(in: 1...6, using: &rng) {
                    bytes[Int.random(in: 0..<bytes.count, using: &rng)] = UInt8.random(in: 0...255, using: &rng)
                }
                if Bool.random(using: &rng) { bytes = Array(bytes.prefix(Int.random(in: 0...bytes.count, using: &rng))) }
            default:
                bytes = v3
                for _ in 0..<Int.random(in: 1...6, using: &rng) {
                    bytes[Int.random(in: 0..<bytes.count, using: &rng)] = UInt8.random(in: 0...255, using: &rng)
                }
            }
            var r = BERReader(bytes)
            exercise(&r)
            _ = try? CommunityMessage.decode(bytes)
            _ = CommunityMessage.peekVersion(bytes)
            _ = try? sec.decode(bytes)
            _ = USMSecurity.peekMsgID(bytes)
            _ = TrapListener.decode(bytes, host: "127.0.0.1", port: 162, received: Date())
        }
    }
}
