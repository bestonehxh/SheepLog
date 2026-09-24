import Foundation

/// ASN.1 BER as SNMP uses it (X.690 subset): definite lengths only, single-byte tags.
/// Encoding produces minimal forms; decoding is strict about bounds and never traps on
/// malformed input — everything bad becomes `SNMPError.decode`.
nonisolated enum BER {
    // Universal
    static let integer: UInt8 = 0x02
    static let octetString: UInt8 = 0x04
    static let null: UInt8 = 0x05
    static let objectIdentifier: UInt8 = 0x06
    static let sequence: UInt8 = 0x30
    // SNMP application types
    static let ipAddress: UInt8 = 0x40
    static let counter32: UInt8 = 0x41
    static let gauge32: UInt8 = 0x42
    static let timeTicks: UInt8 = 0x43
    static let opaque: UInt8 = 0x44
    static let counter64: UInt8 = 0x46
    // v2 exceptions (context-specific, primitive, NULL content)
    static let noSuchObject: UInt8 = 0x80
    static let noSuchInstance: UInt8 = 0x81
    static let endOfMibView: UInt8 = 0x82
    // PDUs
    static let getRequest: UInt8 = 0xA0
    static let getNextRequest: UInt8 = 0xA1
    static let response: UInt8 = 0xA2
    static let setRequest: UInt8 = 0xA3
    static let trapV1: UInt8 = 0xA4
    static let getBulkRequest: UInt8 = 0xA5
    static let informRequest: UInt8 = 0xA6
    static let trapV2: UInt8 = 0xA7
    static let report: UInt8 = 0xA8

    // MARK: Encoding

    static func length(_ n: Int) -> [UInt8] {
        if n < 0x80 { return [UInt8(n)] }
        var bytes: [UInt8] = []
        var v = n
        while v > 0 { bytes.insert(UInt8(v & 0xFF), at: 0); v >>= 8 }
        return [0x80 | UInt8(bytes.count)] + bytes
    }

    static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [tag]
        out.reserveCapacity(content.count + 6)
        out += length(content.count)
        out += content
        return out
    }

    /// Minimal two's complement.
    static func integerContent(_ v: Int64) -> [UInt8] {
        var bytes: [UInt8] = []
        var x = v
        repeat {
            bytes.insert(UInt8(truncatingIfNeeded: x), at: 0)
            x >>= 8
        } while x != 0 && x != -1
        // Make sure the sign bit of the first byte matches the sign.
        if v >= 0, bytes[0] & 0x80 != 0 { bytes.insert(0x00, at: 0) }
        if v < 0, bytes[0] & 0x80 == 0 { bytes.insert(0xFF, at: 0) }
        return bytes
    }

    /// Unsigned value as a (non-negative) two's complement integer: a leading 0 when the top bit is set.
    static func unsignedContent(_ v: UInt64) -> [UInt8] {
        var bytes: [UInt8] = []
        var x = v
        repeat {
            bytes.insert(UInt8(x & 0xFF), at: 0)
            x >>= 8
        } while x != 0
        if bytes[0] & 0x80 != 0 { bytes.insert(0x00, at: 0) }
        return bytes
    }

    static func encodeInteger(_ v: Int64, tag: UInt8 = BER.integer) -> [UInt8] { tlv(tag, integerContent(v)) }
    static func encodeUnsigned(_ v: UInt64, tag: UInt8) -> [UInt8] { tlv(tag, unsignedContent(v)) }
    static func encodeOctets(_ d: [UInt8], tag: UInt8 = BER.octetString) -> [UInt8] { tlv(tag, d) }
    static func encodeNull(tag: UInt8 = BER.null) -> [UInt8] { [tag, 0x00] }
    /// One allocation, sized up front (no intermediate flattened copy).
    static func encodeSequence(_ parts: [[UInt8]], tag: UInt8 = BER.sequence) -> [UInt8] {
        let n = parts.reduce(0) { $0 + $1.count }
        var out: [UInt8] = [tag]
        out.reserveCapacity(n + 6)
        out += length(n)
        for p in parts { out += p }
        return out
    }

    static func oidContent(_ oid: OID) -> [UInt8] {
        var parts = oid.parts
        if parts.isEmpty { parts = [0, 0] }
        if parts.count == 1 { parts.append(0) }
        var out: [UInt8] = []
        // First two arcs packed: 40·X + Y (X ≤ 2). May exceed 32 bits when X = 2.
        let first = UInt64(min(parts[0], 2)) * 40 + UInt64(parts[1])
        appendBase128(first, to: &out)
        for p in parts.dropFirst(2) { appendBase128(UInt64(p), to: &out) }
        return out
    }

    private static func appendBase128(_ v: UInt64, to out: inout [UInt8]) {
        var groups: [UInt8] = [UInt8(v & 0x7F)]
        var x = v >> 7
        while x > 0 {
            groups.insert(UInt8(x & 0x7F) | 0x80, at: 0)
            x >>= 7
        }
        out += groups
    }

    static func encodeOID(_ oid: OID) -> [UInt8] { tlv(objectIdentifier, oidContent(oid)) }

    static func encodeValue(_ v: SNMPValue) -> [UInt8] {
        switch v {
        case .integer(let i): return encodeInteger(i)
        case .octetString(let d): return encodeOctets([UInt8](d))
        case .null: return encodeNull()
        case .oid(let o): return encodeOID(o)
        case .ipAddress(let s): return encodeOctets(ipv4Bytes(s), tag: ipAddress)
        case .counter32(let u): return encodeUnsigned(UInt64(u), tag: counter32)
        case .gauge32(let u): return encodeUnsigned(UInt64(u), tag: gauge32)
        case .timeTicks(let u): return encodeUnsigned(UInt64(u), tag: timeTicks)
        case .opaque(let d): return encodeOctets([UInt8](d), tag: opaque)
        case .counter64(let u): return encodeUnsigned(u, tag: counter64)
        case .noSuchObject: return encodeNull(tag: noSuchObject)
        case .noSuchInstance: return encodeNull(tag: noSuchInstance)
        case .endOfMibView: return encodeNull(tag: endOfMibView)
        }
    }

    static func ipv4Bytes(_ s: String) -> [UInt8] {
        let parts = s.split(separator: ".").compactMap { UInt8($0) }
        return parts.count == 4 ? parts : [0, 0, 0, 0]
    }

    static func encodeVarBinds(_ vbs: [VarBind]) -> [UInt8] {
        encodeSequence(vbs.map { encodeSequence([encodeOID($0.oid), encodeValue($0.value)]) })
    }

    // MARK: Decoding

    static func decodeValue(_ t: TLV) throws -> SNMPValue {
        switch t.tag {
        case integer: return .integer(try t.int64())
        case octetString: return .octetString(Data(t.content))
        case null: return .null
        case objectIdentifier: return .oid(try t.oid())
        case ipAddress:
            let b = t.content
            if b.count == 4 { return .ipAddress(b.map(String.init).joined(separator: ".")) }
            return .ipAddress(b.map { String(format: "%02x", $0) }.joined(separator: ":"))
        case counter32: return .counter32(UInt32(truncatingIfNeeded: try t.uint64()))
        case gauge32: return .gauge32(UInt32(truncatingIfNeeded: try t.uint64()))
        case timeTicks: return .timeTicks(UInt32(truncatingIfNeeded: try t.uint64()))
        case opaque: return .opaque(Data(t.content))
        case counter64: return .counter64(try t.uint64())
        case noSuchObject: return .noSuchObject
        case noSuchInstance: return .noSuchInstance
        case endOfMibView: return .endOfMibView
        default: throw SNMPError.decode(String(format: "unknown value type 0x%02X", t.tag))
        }
    }

    static func decodeVarBinds(_ reader: inout BERReader) throws -> [VarBind] {
        var list = try reader.readSequence()
        var out: [VarBind] = []
        while !list.isAtEnd {
            var vb = try list.readSequence()
            let oid = try vb.read(objectIdentifier).oid()
            let value = try decodeValue(try vb.readTLV())
            out.append(VarBind(oid, value))
        }
        return out
    }
}

/// One decoded TLV. `range` indexes the shared buffer so nested structures keep absolute
/// offsets (the USM digest check needs the position of msgAuthenticationParameters).
nonisolated struct TLV: Sendable {
    let tag: UInt8
    let buffer: [UInt8]
    let range: Range<Int>
    /// Where the TLV starts (tag byte), absolute.
    let start: Int

    var content: [UInt8] { Array(buffer[range]) }
    var count: Int { range.count }
    /// The complete encoding (tag + length + content).
    var encoded: [UInt8] { Array(buffer[start..<range.upperBound]) }
    var reader: BERReader { BERReader(buffer, range: range) }

    func int64() throws -> Int64 {
        guard !range.isEmpty else { throw SNMPError.decode("empty INTEGER") }
        guard range.count <= 8 else {
            // Tolerate redundant sign-extension bytes.
            let lead = buffer[range.lowerBound]
            let extra = range.count - 8
            for i in 0..<extra where buffer[range.lowerBound + i] != lead {
                throw SNMPError.decode("INTEGER too large")
            }
            // Only a sign extension is redundant: 00 before a clear top bit, FF before a set
            // one (00 FF…FE is a positive value above Int64.max, not -2).
            let next = buffer[range.lowerBound + extra]
            guard (lead == 0x00 && next & 0x80 == 0) || (lead == 0xFF && next & 0x80 != 0) else {
                throw SNMPError.decode("INTEGER too large")
            }
            return try TLV(tag: tag, buffer: buffer, range: (range.lowerBound + extra)..<range.upperBound, start: start).int64()
        }
        var v: Int64 = (buffer[range.lowerBound] & 0x80) != 0 ? -1 : 0
        for i in range { v = (v << 8) | Int64(buffer[i]) }
        return v
    }

    /// Unsigned: the bytes as a magnitude (a leading 0 is dropped; sloppy agents that send
    /// Counter32 without it are read as unsigned too).
    func uint64() throws -> UInt64 {
        guard !range.isEmpty else { throw SNMPError.decode("empty unsigned integer") }
        var lo = range.lowerBound
        while range.upperBound - lo > 8, buffer[lo] == 0 { lo += 1 }
        guard range.upperBound - lo <= 8 else { throw SNMPError.decode("unsigned integer too large") }
        var v: UInt64 = 0
        for i in lo..<range.upperBound { v = (v << 8) | UInt64(buffer[i]) }
        return v
    }

    func oid() throws -> OID {
        guard !range.isEmpty else { return OID([0, 0]) }
        var parts: [UInt32] = []
        var acc: UInt64 = 0
        var first = true
        var inSub = false
        for i in range {
            let b = buffer[i]
            if !inSub, b == 0x80 { throw SNMPError.decode("OID sub-identifier with leading 0x80") }
            acc = (acc << 7) | UInt64(b & 0x7F)
            guard acc <= (first ? UInt64(UInt32.max) + 80 : UInt64(UInt32.max)) else {
                throw SNMPError.decode("OID sub-identifier too large")
            }
            if b & 0x80 != 0 { inSub = true; continue }
            inSub = false
            if first {
                if acc < 40 { parts += [0, UInt32(acc)] }
                else if acc < 80 { parts += [1, UInt32(acc - 40)] }
                else { parts += [2, UInt32(acc - 80)] }
                first = false
            } else {
                parts.append(UInt32(acc))
            }
            acc = 0
        }
        if inSub { throw SNMPError.decode("truncated OID") }
        return OID(parts)
    }
}

/// A bounds-checked cursor over a BER buffer.
nonisolated struct BERReader: Sendable {
    let buffer: [UInt8]
    private(set) var pos: Int
    let end: Int

    init(_ bytes: [UInt8]) {
        buffer = bytes
        pos = 0
        end = bytes.count
    }

    init(_ data: Data) { self.init([UInt8](data)) }

    init(_ buffer: [UInt8], range: Range<Int>) {
        self.buffer = buffer
        pos = range.lowerBound
        end = range.upperBound
    }

    var isAtEnd: Bool { pos >= end }
    var remaining: Int { end - pos }

    mutating func readTLV() throws -> TLV {
        let start = pos
        guard pos < end else { throw SNMPError.decode("unexpected end of data") }
        let tag = buffer[pos]
        pos += 1
        if tag & 0x1F == 0x1F { throw SNMPError.decode("multi-byte tags are not used by SNMP") }
        guard pos < end else { throw SNMPError.decode("missing length") }
        let first = buffer[pos]
        pos += 1
        var len = 0
        if first < 0x80 {
            len = Int(first)
        } else {
            let n = Int(first & 0x7F)
            guard n > 0 else { throw SNMPError.decode("indefinite length") }
            guard n <= 4 else { throw SNMPError.decode("length field too long") }
            guard end - pos >= n else { throw SNMPError.decode("truncated length") }
            for _ in 0..<n { len = (len << 8) | Int(buffer[pos]); pos += 1 }
        }
        guard len <= end - pos else { throw SNMPError.decode("length \(len) exceeds the \(end - pos) bytes left") }
        let range = pos..<(pos + len)
        pos += len
        return TLV(tag: tag, buffer: buffer, range: range, start: start)
    }

    mutating func read(_ tag: UInt8) throws -> TLV {
        let t = try readTLV()
        guard t.tag == tag else {
            throw SNMPError.decode(String(format: "expected tag 0x%02X, got 0x%02X", tag, t.tag))
        }
        return t
    }

    mutating func readSequence(_ tag: UInt8 = BER.sequence) throws -> BERReader {
        try read(tag).reader
    }

    mutating func readInteger() throws -> Int64 { try read(BER.integer).int64() }
    mutating func readOctets() throws -> [UInt8] { try read(BER.octetString).content }
    mutating func readOID() throws -> OID { try read(BER.objectIdentifier).oid() }
}

// MARK: - PDUs

/// GetRequest / GetNext / Response / Set / GetBulk / Inform / TrapV2 / Report.
/// For GetBulk, `errorStatus` = non-repeaters and `errorIndex` = max-repetitions.
nonisolated struct SNMPPDU: Sendable, Equatable {
    var type: UInt8
    var requestID: Int32
    var errorStatus: Int
    var errorIndex: Int
    var varBinds: [VarBind]

    init(type: UInt8, requestID: Int32, errorStatus: Int = 0, errorIndex: Int = 0, varBinds: [VarBind]) {
        self.type = type
        self.requestID = requestID
        self.errorStatus = errorStatus
        self.errorIndex = errorIndex
        self.varBinds = varBinds
    }

    func encoded() -> [UInt8] {
        BER.encodeSequence([
            BER.encodeInteger(Int64(requestID)),
            BER.encodeInteger(Int64(errorStatus)),
            BER.encodeInteger(Int64(errorIndex)),
            BER.encodeVarBinds(varBinds),
        ], tag: type)
    }

    static func decode(_ t: TLV) throws -> SNMPPDU {
        guard t.tag >= 0xA0, t.tag <= 0xA8, t.tag != BER.trapV1 else {
            throw SNMPError.decode(String(format: "not a PDU (tag 0x%02X)", t.tag))
        }
        var r = t.reader
        let rid = try r.readInteger()
        let es = try r.readInteger()
        let ei = try r.readInteger()
        let vbs = try BER.decodeVarBinds(&r)
        return SNMPPDU(type: t.tag, requestID: Int32(truncatingIfNeeded: rid),
                       errorStatus: Int(clamping: es), errorIndex: Int(clamping: ei), varBinds: vbs)
    }
}

/// The SNMPv1 Trap-PDU.
nonisolated struct TrapV1PDU: Sendable, Equatable {
    var enterprise: OID
    var agentAddress: String
    var genericTrap: Int
    var specificTrap: Int
    var timeStamp: UInt32
    var varBinds: [VarBind]

    func encoded() -> [UInt8] {
        BER.encodeSequence([
            BER.encodeOID(enterprise),
            BER.encodeOctets(BER.ipv4Bytes(agentAddress), tag: BER.ipAddress),
            BER.encodeInteger(Int64(genericTrap)),
            BER.encodeInteger(Int64(specificTrap)),
            BER.encodeUnsigned(UInt64(timeStamp), tag: BER.timeTicks),
            BER.encodeVarBinds(varBinds),
        ], tag: BER.trapV1)
    }

    static func decode(_ t: TLV) throws -> TrapV1PDU {
        guard t.tag == BER.trapV1 else { throw SNMPError.decode("not a v1 trap") }
        var r = t.reader
        let ent = try r.readOID()
        let addrTLV = try r.readTLV()
        let addr: String
        if case .ipAddress(let s) = try BER.decodeValue(addrTLV) { addr = s }
        else { addr = addrTLV.content.map(String.init).joined(separator: ".") }
        let g = try r.readInteger()
        let s = try r.readInteger()
        let ts = try r.readTLV()
        let vbs = try BER.decodeVarBinds(&r)
        return TrapV1PDU(enterprise: ent, agentAddress: addr, genericTrap: Int(clamping: g),
                         specificTrap: Int(clamping: s), timeStamp: UInt32(truncatingIfNeeded: try ts.uint64()),
                         varBinds: vbs)
    }

    /// RFC 3584 §3.1: the v2 snmpTrapOID for this trap.
    var trapOID: OID {
        if genericTrap >= 0, genericTrap < 6 {
            return OID([1, 3, 6, 1, 6, 3, 1, 1, 5, UInt32(genericTrap + 1)])
        }
        return enterprise.appending([0, UInt32(truncatingIfNeeded: specificTrap)])
    }
}

/// SNMPv1 / v2c message: SEQUENCE { version, community, PDU }.
nonisolated struct CommunityMessage: Sendable {
    var version: Int
    var community: [UInt8]
    /// The PDU TLV as read (Response, Trap, …).
    var pduTLV: TLV?
    var pdu: SNMPPDU?

    static func encode(version: SNMPVersion, community: String, pdu: [UInt8]) -> [UInt8] {
        BER.encodeSequence([
            BER.encodeInteger(Int64(version.wireValue)),
            BER.encodeOctets(Array(community.utf8)),
            pdu,
        ])
    }

    static func decode(_ bytes: [UInt8]) throws -> CommunityMessage {
        var outer = BERReader(bytes)
        var r = try outer.readSequence()
        let v = try r.readInteger()
        let c = try r.readOctets()
        let p = try r.readTLV()
        let pdu = p.tag == BER.trapV1 ? nil : try SNMPPDU.decode(p)
        return CommunityMessage(version: Int(clamping: v), community: c, pduTLV: p, pdu: pdu)
    }

    /// Reads just the version field (0, 1, 3) — used to dispatch a datagram.
    static func peekVersion(_ bytes: [UInt8]) -> Int? {
        var outer = BERReader(bytes)
        guard var r = try? outer.readSequence(), let v = try? r.readInteger() else { return nil }
        return Int(clamping: v)
    }
}
