import Foundation

// Authentication traffic, decoded for the Authentication pane: 802.1X (EAPOL, EAP, the WPA 4-way
// handshake), RADIUS (with the vendor attributes Aruba / Cisco / Fortinet networks carry), and the
// DHCP / DNS / HTTP signs that a client got onto the network or met a captive portal.
//
// Works from `Packet.data` + `Packet.decoded` (the packet decoder already found the EtherType, the
// UDP payload and the application layer); every read is bounds-checked — a hostile or truncated
// frame gives a shorter answer, never a crash.

nonisolated enum AuthDecoder {
    /// The Packets-pane filter that keeps only what the Authentication pane reads — RADIUS on
    /// every port `isRADIUSPort` reads (the legacy 1645 / 1646 and CoA 3799 were decoded into
    /// attempts but hidden by "Auth packets").
    static let packetFilterPreset = "proto:eapol OR port:1812 OR port:1813 OR port:1645 OR port:1646 OR port:3799 OR proto:dhcp OR proto:dns OR proto:http"

    static let eapolEtherType: UInt16 = 0x888E

    // MARK: - Bytes

    /// A bounds-checked view of a byte array.
    struct Bytes {
        let b: [UInt8]
        var count: Int { b.count }
        init(_ b: [UInt8]) { self.b = b }
        @inline(__always) func has(_ o: Int, _ n: Int) -> Bool { o >= 0 && n >= 0 && o <= b.count - n }
        @inline(__always) func u8(_ o: Int) -> UInt8 { o >= 0 && o < b.count ? b[o] : 0 }
        @inline(__always) func u16(_ o: Int) -> UInt16 { UInt16(u8(o)) << 8 | UInt16(u8(o + 1)) }
        @inline(__always) func u32(_ o: Int) -> UInt32 { UInt32(u16(o)) << 16 | UInt32(u16(o + 2)) }
        func u64(_ o: Int) -> UInt64 { UInt64(u32(o)) << 32 | UInt64(u32(o + 4)) }
        func slice(_ o: Int, _ n: Int) -> [UInt8] {
            let lo = max(0, min(o, b.count)), hi = max(lo, min(o + max(0, n), b.count))
            return Array(b[lo..<hi])
        }
    }

    /// Printable text: UTF-8 (lossy), NULs trimmed, control characters shown as `·`, capped.
    static func text(_ bytes: [UInt8], max: Int = 253) -> String {
        var v = Array(bytes.prefix(max))
        while let last = v.last, last == 0 { v.removeLast() }
        let s = String(decoding: v, as: UTF8.self)
        return String(s.unicodeScalars.map { $0.value < 0x20 || (0x7f...0x9f).contains($0.value) ? "·" : Character($0) })
    }

    static func hex(_ bytes: [UInt8], max: Int = 16) -> String {
        let shown = bytes.prefix(max).map { String(format: "%02x", $0) }.joined()
        return bytes.count > max ? shown + "…" : shown
    }

    static func ipv4(_ b: [UInt8]) -> String? {
        guard b.count == 4 else { return nil }
        return "\(b[0]).\(b[1]).\(b[2]).\(b[3])"
    }

    // MARK: - MAC spellings

    /// `aa-bb-cc-dd-ee-ff`, `aabb.ccdd.eeff`, `AABBCCDDEEFF`, `aa:bb:cc:dd:ee:ff` → `aa:bb:cc:dd:ee:ff`,
    /// plus whatever follows (Called-Station-Id `…:SSID`). nil when the text does not start with a MAC.
    static func macPrefix(_ s: String) -> (mac: String, rest: String)? {
        var digits: [Character] = []
        var index = s.startIndex
        var lastWasSeparator = false
        while index < s.endIndex, digits.count < 12 {
            let c = s[index]
            if c.isHexDigit, c.isASCII {
                digits.append(Character(c.lowercased()))
                lastWasSeparator = false
            } else if c == ":" || c == "-" || c == ".", !digits.isEmpty, !lastWasSeparator {
                lastWasSeparator = true
            } else {
                return nil
            }
            index = s.index(after: index)
        }
        guard digits.count == 12 else { return nil }
        // Separators must sit on byte (or, for Cisco dotted, 2-byte) boundaries: no "a-abbccddeeff".
        let raw = s[s.startIndex..<index]
        let groups = raw.split(whereSeparator: { $0 == ":" || $0 == "-" || $0 == "." })
        guard groups.count == 1 || (groups.count == 6 && groups.allSatisfy { $0.count == 2 })
                || (groups.count == 3 && groups.allSatisfy { $0.count == 4 }) else { return nil }
        // A 13th hex digit right after means it was not a MAC ("aabbccddeeff0").
        if index < s.endIndex, s[index].isHexDigit, groups.count == 1 { return nil }
        var out = ""
        for (i, d) in digits.enumerated() {
            if i > 0, i % 2 == 0 { out.append(":") }
            out.append(d)
        }
        var rest = String(s[index...])
        if rest.hasPrefix(":") || rest.hasPrefix("-") { rest.removeFirst() }
        return (out, rest)
    }

    /// The whole text is a MAC address, in any common spelling.
    static func normalisedMAC(_ s: String) -> String? {
        let t = s.trimmingCharacters(in: .whitespaces)
        guard let (mac, rest) = macPrefix(t), rest.isEmpty else { return nil }
        return mac
    }

    // MARK: - EAPOL / EAP

    nonisolated enum EAPOLType: UInt8, Sendable {
        case eapPacket = 0, start = 1, logoff = 2, key = 3, asfAlert = 4

        var name: String {
            switch self {
            case .eapPacket: "EAP-Packet"
            case .start: "EAPOL-Start"
            case .logoff: "EAPOL-Logoff"
            case .key: "EAPOL-Key"
            case .asfAlert: "EAPOL-ASF-Alert"
            }
        }
    }

    nonisolated enum EAPCode: UInt8, Sendable {
        case request = 1, response = 2, success = 3, failure = 4, initiate = 5, finish = 6

        var name: String {
            switch self {
            case .request: "Request"
            case .response: "Response"
            case .success: "Success"
            case .failure: "Failure"
            case .initiate: "Initiate"
            case .finish: "Finish"
            }
        }
    }

    /// EAP method names (IANA "EAP Method Types").
    static func eapTypeName(_ t: UInt8) -> String {
        switch t {
        case 1: "Identity"
        case 2: "Notification"
        case 3: "Nak"
        case 4: "MD5-Challenge"
        case 5: "OTP"
        case 6: "GTC"
        case 13: "EAP-TLS"
        case 17: "LEAP"
        case 18: "EAP-SIM"
        case 21: "EAP-TTLS"
        case 23: "EAP-AKA"
        case 25: "PEAP"
        case 26: "EAP-MSCHAPv2"
        case 43: "EAP-FAST"
        case 50: "EAP-AKA'"
        case 52: "EAP-pwd"
        case 55: "TEAP"
        case 254: "Expanded"
        default: "EAP type \(t)"
        }
    }

    /// Methods that carry TLS records (a flags octet, then an optional 4-byte length).
    static func isTLSMethod(_ t: UInt8) -> Bool { t == 13 || t == 21 || t == 25 || t == 43 || t == 55 }

    nonisolated struct TLSFlags: Sendable, Equatable {
        var start = false
        var more = false
        var lengthIncluded = false
        var tlsLength: UInt32?
        var version: UInt8 = 0
        /// TLS record bytes in this EAP packet (after flags / length).
        var dataLength = 0
    }

    nonisolated struct EAPPacket: Sendable, Equatable {
        var code: UInt8
        var id: UInt8
        /// The EAP length field.
        var length: Int
        /// Method type (Request / Response only).
        var type: UInt8?
        var identity: String?
        var tls: TLSFlags?
        /// Nak: the methods the peer asked for instead.
        var desired: [UInt8] = []
        /// EAP-MSCHAPv2 opcode (1 Challenge, 2 Response, 3 Success, 4 Failure, 7 Change-Password).
        var mschapOpcode: UInt8?
        /// Expanded type: vendor id / vendor type (WFA 0x372A / 1 = WPS).
        var expandedVendor: UInt32?
        var expandedType: UInt32?
        /// The length field says more than the bytes present.
        var truncated = false

        var codeName: String { EAPCode(rawValue: code)?.name ?? "Code \(code)" }
        var typeName: String? { type.map(AuthDecoder.eapTypeName) }
        var isRequest: Bool { code == 1 }
        var isResponse: Bool { code == 2 }
        var isSuccess: Bool { code == 3 }
        var isFailure: Bool { code == 4 }

        /// "EAP-Request Identity", "EAP-Response PEAP (start)", "EAP-Success".
        var summary: String {
            var s = "EAP-\(codeName)"
            if let type {
                if type == 254, expandedVendor == 0x372A, expandedType == 1 { s += " WPS" }
                else { s += " " + AuthDecoder.eapTypeName(type) }
                if type == 1, isResponse, let identity, !identity.isEmpty { s += " (\(identity))" }
                if type == 3, !desired.isEmpty { s += " → wants " + desired.map(AuthDecoder.eapTypeName).joined(separator: ", ") }
                if let tls, tls.start { s += " (start)" }
                if let op = mschapOpcode {
                    let n = switch op { case 1: "Challenge"; case 2: "Response"; case 3: "Success"; case 4: "Failure"; case 7: "Change-Password"; default: "op \(op)" }
                    s += " \(n)"
                }
            }
            return s
        }
    }

    /// The EAP packet at `o` (its own length field bounds it, then the bytes present).
    static func eap(_ bytes: [UInt8], at o: Int = 0) -> EAPPacket? {
        let b = Bytes(bytes)
        guard b.has(o, 4) else { return nil }
        let code = b.u8(o), id = b.u8(o + 1)
        let length = Int(b.u16(o + 2))
        guard (1...6).contains(code), length >= 4 else { return nil }
        let end = min(o + length, b.count)
        var p = EAPPacket(code: code, id: id, length: length)
        p.truncated = o + length > b.count
        guard code == 1 || code == 2, end > o + 4 else { return p }
        let type = b.u8(o + 4)
        p.type = type
        let data = o + 5
        switch type {
        case 1:
            p.identity = text(b.slice(data, end - data))
        case 3:
            p.desired = b.slice(data, min(16, end - data)).filter { $0 != 0 }
        case 26:
            if end > data { p.mschapOpcode = b.u8(data) }
        case 254:
            if b.has(data, 7), data + 7 <= end {
                p.expandedVendor = UInt32(b.u8(data)) << 16 | UInt32(b.u8(data + 1)) << 8 | UInt32(b.u8(data + 2))
                p.expandedType = b.u32(data + 3)
            }
        default:
            if isTLSMethod(type), end > data {
                let f = b.u8(data)
                var t = TLSFlags()
                t.lengthIncluded = f & 0x80 != 0
                t.more = f & 0x40 != 0
                t.start = f & 0x20 != 0
                t.version = f & 0x07
                var q = data + 1
                if t.lengthIncluded, q + 4 <= end {
                    t.tlsLength = b.u32(q)
                    q += 4
                }
                t.dataLength = max(0, end - q)
                p.tls = t
            }
        }
        return p
    }

    // MARK: EAPOL-Key

    nonisolated enum KeyMessage: Sendable, Equatable {
        case m1, m2, m3, m4, group1, group2, requestFailure, unknown

        /// "1/4", "Group 1/2".
        var label: String {
            switch self {
            case .m1: "1/4"
            case .m2: "2/4"
            case .m3: "3/4"
            case .m4: "4/4"
            case .group1: "Group 1/2"
            case .group2: "Group 2/2"
            case .requestFailure: "Request (MIC failure report)"
            case .unknown: "?"
            }
        }

        /// Sent by the authenticator (AP / switch) — ACK set.
        var fromAuthenticator: Bool { self == .m1 || self == .m3 || self == .group1 }
        var number: Int { switch self { case .m1: 1; case .m2: 2; case .m3: 3; case .m4: 4; default: 0 } }
    }

    nonisolated struct EAPOLKey: Sendable, Equatable {
        /// 2 = RSN (WPA2/WPA3), 254 = WPA, 1 = RC4 (802.1X-2004 dynamic WEP).
        var descriptor: UInt8
        var info: UInt16
        var keyLength: Int
        var replayCounter: UInt64
        var noncePresent: Bool
        var micPresent: Bool
        var keyDataLength: Int
        /// The frame holds the whole nonce field (a short snap length or a wrong EAPOL length cuts it).
        var nonceCaptured = true

        var descriptorVersion: Int { Int(info & 0x0007) }
        var pairwise: Bool { info & 0x0008 != 0 }
        var install: Bool { info & 0x0040 != 0 }
        var ack: Bool { info & 0x0080 != 0 }
        var mic: Bool { info & 0x0100 != 0 }
        var secure: Bool { info & 0x0200 != 0 }
        var error: Bool { info & 0x0400 != 0 }
        var request: Bool { info & 0x0800 != 0 }
        var encryptedKeyData: Bool { info & 0x1000 != 0 }

        var descriptorName: String {
            switch descriptor {
            case 2: "RSN"
            case 254: "WPA"
            case 1: "RC4"
            default: "descriptor \(descriptor)"
            }
        }

        /// Which message of the 4-way / group handshake: ACK without MIC is 1/4, ACK + MIC 3/4;
        /// MIC without ACK is 4/4 when secure with no key data (or no nonce), else 2/4 (the SNonce).
        var message: KeyMessage {
            if request { return error ? .requestFailure : .unknown }
            if pairwise {
                if ack { return mic ? .m3 : .m1 }
                guard mic else { return .unknown }
                // Cut before the nonce: 2/4 or 4/4 is not known — only the secure bit (set in an RSN
                // 4/4, never in a 2/4) says 4/4. Read as 4/4, a cut 2/4 made a wrong PSK "Accept".
                guard nonceCaptured else { return secure ? .m4 : .unknown }
                if secure && keyDataLength == 0 { return .m4 }
                return noncePresent ? .m2 : .m4
            }
            if descriptor == 1 { return .unknown }
            if ack { return .group1 }
            if mic { return .group2 }
            return .unknown
        }
    }

    nonisolated struct EAPOLFrame: Sendable, Equatable {
        var version: UInt8
        var typeRaw: UInt8
        var length: Int
        var eap: EAPPacket?
        var key: EAPOLKey?
        var truncated = false

        var type: EAPOLType? { EAPOLType(rawValue: typeRaw) }

        var summary: String {
            if let eap { return eap.summary }
            if let key {
                let m = key.message
                return m == .unknown ? "EAPOL-Key (\(key.descriptorName))" : "EAPOL-Key \(m.label)"
            }
            return type?.name ?? "EAPOL type \(typeRaw)"
        }
    }

    /// An EAPOL PDU at `o` (the EtherType 0x888E payload).
    static func eapol(_ bytes: [UInt8], at o: Int = 0) -> EAPOLFrame? {
        let b = Bytes(bytes)
        guard b.has(o, 4) else { return nil }
        let version = b.u8(o), type = b.u8(o + 1), length = Int(b.u16(o + 2))
        guard (1...3).contains(version) else { return nil }
        var f = EAPOLFrame(version: version, typeRaw: type, length: length)
        f.truncated = o + 4 + length > b.count
        let body = o + 4
        let end = min(body + length, b.count)
        switch type {
        case 0:
            // Only the bytes the EAPOL length covers (Ethernet padding follows).
            f.eap = eap(b.slice(body, end - body))
        case 3:
            // Only the bytes the EAPOL length covers: the key frame's offsets are relative to it.
            let k = Bytes(b.slice(body, end - body))
            guard k.count >= 1 else { break }
            let d = k.u8(0)
            // RC4 (1): key length, replay counter, IV, index, signature, key.
            if d == 1 {
                guard k.count >= 11 else { break }
                f.key = EAPOLKey(descriptor: 1, info: 0, keyLength: Int(k.u16(1)), replayCounter: k.u64(3),
                                 noncePresent: false, micPresent: false, keyDataLength: 0)
                break
            }
            guard k.count >= 13 else { break }
            let nonce = k.has(13, 32) ? k.slice(13, 32) : []
            let mic = k.has(77, 16) ? k.slice(77, 16) : []
            f.key = EAPOLKey(descriptor: d, info: k.u16(1), keyLength: Int(k.u16(3)), replayCounter: k.u64(5),
                             noncePresent: nonce.contains { $0 != 0 }, micPresent: mic.contains { $0 != 0 },
                             keyDataLength: k.has(93, 2) ? Int(k.u16(93)) : 0, nonceCaptured: k.has(13, 32))
        default:
            break
        }
        return f
    }

    // MARK: - RADIUS

    static func radiusCodeName(_ c: UInt8) -> String {
        switch c {
        case 1: "Access-Request"
        case 2: "Access-Accept"
        case 3: "Access-Reject"
        case 4: "Accounting-Request"
        case 5: "Accounting-Response"
        case 11: "Access-Challenge"
        case 12: "Status-Server"
        case 13: "Status-Client"
        case 40: "Disconnect-Request"
        case 41: "Disconnect-ACK"
        case 42: "Disconnect-NAK"
        case 43: "CoA-Request"
        case 44: "CoA-ACK"
        case 45: "CoA-NAK"
        default: "Code \(c)"
        }
    }

    static func radiusAttributeName(_ t: UInt8) -> String {
        switch t {
        case 1: "User-Name"
        case 2: "User-Password"
        case 3: "CHAP-Password"
        case 4: "NAS-IP-Address"
        case 5: "NAS-Port"
        case 6: "Service-Type"
        case 7: "Framed-Protocol"
        case 8: "Framed-IP-Address"
        case 11: "Filter-Id"
        case 12: "Framed-MTU"
        case 18: "Reply-Message"
        case 24: "State"
        case 25: "Class"
        case 26: "Vendor-Specific"
        case 27: "Session-Timeout"
        case 28: "Idle-Timeout"
        case 30: "Called-Station-Id"
        case 31: "Calling-Station-Id"
        case 32: "NAS-Identifier"
        case 33: "Proxy-State"
        case 40: "Acct-Status-Type"
        case 41: "Acct-Delay-Time"
        case 42: "Acct-Input-Octets"
        case 43: "Acct-Output-Octets"
        case 44: "Acct-Session-Id"
        case 45: "Acct-Authentic"
        case 46: "Acct-Session-Time"
        case 49: "Acct-Terminate-Cause"
        case 55: "Event-Timestamp"
        case 60: "CHAP-Challenge"
        case 61: "NAS-Port-Type"
        case 64: "Tunnel-Type"
        case 65: "Tunnel-Medium-Type"
        case 77: "Connect-Info"
        case 79: "EAP-Message"
        case 80: "Message-Authenticator"
        case 81: "Tunnel-Private-Group-ID"
        case 85: "Acct-Interim-Interval"
        case 87: "NAS-Port-Id"
        case 95: "NAS-IPv6-Address"
        case 101: "Error-Cause"
        default: "Attribute \(t)"
        }
    }

    static func serviceTypeName(_ v: UInt32) -> String {
        switch v {
        case 1: "Login"
        case 2: "Framed"
        case 5: "Outbound"
        case 6: "Administrative"
        case 8: "Authenticate-Only"
        case 10: "Call-Check"
        case 17: "Authorize-Only"
        default: "\(v)"
        }
    }

    static func nasPortTypeName(_ v: UInt32) -> String {
        switch v {
        case 0: "Async"
        case 5: "Virtual"
        case 15: "Ethernet"
        case 19: "Wireless-802.11"
        default: "\(v)"
        }
    }

    static func acctStatusName(_ v: UInt32) -> String {
        switch v {
        case 1: "Start"
        case 2: "Stop"
        case 3: "Interim-Update"
        case 7: "Accounting-On"
        case 8: "Accounting-Off"
        default: "\(v)"
        }
    }

    static func terminateCauseName(_ v: UInt32) -> String {
        switch v {
        case 1: "User-Request"
        case 2: "Lost-Carrier"
        case 3: "Lost-Service"
        case 4: "Idle-Timeout"
        case 5: "Session-Timeout"
        case 6: "Admin-Reset"
        case 7: "Admin-Reboot"
        case 8: "Port-Error"
        case 9: "NAS-Error"
        case 10: "NAS-Request"
        case 11: "NAS-Reboot"
        case 12: "Port-Unneeded"
        case 13: "Port-Preempted"
        case 14: "Port-Suspended"
        case 15: "Service-Unavailable"
        case 16: "Callback"
        case 17: "User-Error"
        case 18: "Host-Request"
        default: "\(v)"
        }
    }

    static func tunnelTypeName(_ v: UInt32) -> String { v == 13 ? "VLAN" : "\(v)" }
    static func tunnelMediumName(_ v: UInt32) -> String { v == 6 ? "IEEE-802" : "\(v)" }

    static let vendorAruba: UInt32 = 14823
    static let vendorCisco: UInt32 = 9
    static let vendorMicrosoft: UInt32 = 311
    static let vendorFortinet: UInt32 = 12356
    static let vendorPalo: UInt32 = 25461
    static let vendorHuawei: UInt32 = 2011

    static func vendorName(_ v: UInt32) -> String {
        switch v {
        case vendorAruba: "Aruba"
        case vendorCisco: "Cisco"
        case vendorMicrosoft: "Microsoft"
        case vendorFortinet: "Fortinet"
        case vendorPalo: "PaloAlto"
        case vendorHuawei: "Huawei"
        default: "vendor \(v)"
        }
    }

    /// (name, is text, is secret) of a vendor attribute this decoder knows.
    static func vendorAttribute(_ vendor: UInt32, _ type: UInt8) -> (String, Kind)? {
        switch (vendor, type) {
        case (vendorAruba, 1): ("Aruba-User-Role", .text)
        case (vendorAruba, 2): ("Aruba-User-Vlan", .integer)
        case (vendorAruba, 5): ("Aruba-Essid-Name", .text)
        case (vendorAruba, 6): ("Aruba-Location-Id", .text)
        case (vendorAruba, 10): ("Aruba-AP-Group", .text)
        case (vendorAruba, 12): ("Aruba-Device-Type", .text)
        case (vendorCisco, 1): ("cisco-avpair", .text)
        case (vendorFortinet, 1): ("Fortinet-Group-Name", .text)
        case (vendorFortinet, 3): ("Fortinet-Vdom-Name", .text)
        case (vendorPalo, 1): ("PaloAlto-Admin-Role", .text)
        case (vendorHuawei, 138): ("HW-Domain-Name", .text)
        case (vendorMicrosoft, 16): ("MS-MPPE-Send-Key", .secret)
        case (vendorMicrosoft, 17): ("MS-MPPE-Recv-Key", .secret)
        default: nil
        }
    }

    nonisolated enum Kind: Sendable { case text, integer, address, secret, octets }

    nonisolated struct RadiusAttribute: Sendable, Equatable {
        let type: UInt8
        /// Vendor-Specific: the vendor id and the vendor's own attribute type.
        var vendor: UInt32?
        var vendorType: UInt8?
        let value: [UInt8]
        /// The value as shown ("(present)" for passwords and keys).
        let display: String
        let name: String
    }

    nonisolated struct RadiusPacket: Sendable, Equatable {
        var code: UInt8
        var id: UInt8
        var length: Int
        var authenticator: [UInt8]
        var attributes: [RadiusAttribute] = []
        /// The EAP packet the EAP-Message attributes carry (concatenated, RFC 3579 §3.1).
        var eap: EAPPacket?
        var eapFragments = 0
        /// The length field or an attribute runs past the datagram.
        var truncated = false

        var codeName: String { AuthDecoder.radiusCodeName(code) }
        var isAccessRequest: Bool { code == 1 }
        var isResponse: Bool { code == 2 || code == 3 || code == 11 }

        func first(_ type: UInt8) -> RadiusAttribute? { attributes.first { $0.type == type && $0.vendor == nil } }
        func string(_ type: UInt8) -> String? { first(type)?.display }
        func vendor(_ vendor: UInt32, _ type: UInt8) -> RadiusAttribute? {
            attributes.first { $0.vendor == vendor && $0.vendorType == type }
        }

        var userName: String? { first(1).map { AuthDecoder.text($0.value) } }
        var callingStationId: String? { first(31).map { AuthDecoder.text($0.value) } }
        var calledStationId: String? { first(30).map { AuthDecoder.text($0.value) } }
        var nasIdentifier: String? { first(32).map { AuthDecoder.text($0.value) } }
        var nasIPAddress: String? { first(4).flatMap { AuthDecoder.ipv4($0.value) } }
        var nasPortId: String? { first(87).map { AuthDecoder.text($0.value) } }
        var replyMessage: String? {
            let parts = attributes.filter { $0.type == 18 && $0.vendor == nil }.map { AuthDecoder.text($0.value, max: 512) }
            return parts.isEmpty ? nil : parts.joined(separator: " ")
        }
        var framedIP: String? { first(8).flatMap { AuthDecoder.ipv4($0.value) } }
        var hasPassword: Bool { first(2) != nil || first(3) != nil }
        var hasEAP: Bool { eapFragments > 0 }
        var messageAuthenticator: Bool { first(80) != nil }
        var acctStatus: String? { first(40).map(\.display) }

        /// Tunnel-Private-Group-ID (tag stripped) or Aruba-User-Vlan.
        var vlan: String? {
            if let a = first(81) { return a.display }
            if let a = vendor(AuthDecoder.vendorAruba, 2) { return a.display }
            if let pair = attributes.first(where: { $0.vendor == AuthDecoder.vendorCisco && $0.display.lowercased().hasPrefix("tunnel-private-group-id=") }) {
                return String(pair.display.split(separator: "=", maxSplits: 1).last ?? "")
            }
            return nil
        }

        /// Aruba-User-Role, Filter-Id, Fortinet-Group-Name, PaloAlto-Admin-Role, or a Cisco ACL / role pair.
        var role: String? {
            if let a = vendor(AuthDecoder.vendorAruba, 1) { return a.display }
            if let a = first(11) { return a.display }
            if let a = vendor(AuthDecoder.vendorFortinet, 1) { return a.display }
            if let a = vendor(AuthDecoder.vendorPalo, 1) { return a.display }
            for a in attributes where a.vendor == AuthDecoder.vendorCisco {
                let l = a.display.lowercased()
                for key in ["role=", "acs:ciscosecure-defined-acl=", "ip:inacl#", "url-redirect-acl="] where l.hasPrefix(key) {
                    return a.display
                }
            }
            return nil
        }

        /// SSID from Called-Station-Id `MAC:SSID`, or Aruba-Essid-Name.
        var ssid: String? {
            if let a = vendor(AuthDecoder.vendorAruba, 5) { return a.display }
            if let c = calledStationId, let (_, rest) = AuthDecoder.macPrefix(c), !rest.isEmpty { return rest }
            return nil
        }

        /// "Access-Accept id=12 (VLAN 20, role employee)".
        var summary: String { "\(codeName) id=\(id)" }
    }

    /// A RADIUS datagram (the UDP payload). nil when it does not look like one.
    static func radius(_ bytes: [UInt8]) -> RadiusPacket? {
        let b = Bytes(bytes)
        guard b.has(0, 20) else { return nil }
        let code = b.u8(0)
        guard [1, 2, 3, 4, 5, 11, 12, 13, 40, 41, 42, 43, 44, 45].contains(code) else { return nil }
        let length = Int(b.u16(2))
        guard length >= 20 else { return nil }
        var r = RadiusPacket(code: code, id: b.u8(1), length: length, authenticator: b.slice(4, 16))
        r.truncated = length > b.count
        let end = min(length, b.count, 4096)
        var p = 20
        var eapBytes: [UInt8] = []
        var n = 0
        while p < end, n < 256 {
            n += 1
            guard p + 2 <= end else { r.truncated = true; break }
            let t = b.u8(p), l = Int(b.u8(p + 1))
            guard l >= 2, p + l <= end else { r.truncated = true; break }
            let value = b.slice(p + 2, l - 2)
            if t == 26 {
                r.attributes += vendorSpecific(value)
            } else {
                r.attributes.append(attribute(t, value))
            }
            if t == 79 {
                eapBytes += value
                r.eapFragments += 1
            }
            p += l
        }
        if !eapBytes.isEmpty { r.eap = eap(eapBytes) }
        return r
    }

    static func integer(_ v: [UInt8]) -> UInt32? {
        guard v.count == 4 else { return nil }
        return UInt32(v[0]) << 24 | UInt32(v[1]) << 16 | UInt32(v[2]) << 8 | UInt32(v[3])
    }

    static func attribute(_ t: UInt8, _ v: [UInt8]) -> RadiusAttribute {
        let name = radiusAttributeName(t)
        let display: String
        switch t {
        case 2, 3:
            display = "(present)"
        case 1, 11, 18, 30, 31, 32, 44, 77, 87:
            display = text(v, max: 512)
        case 4, 8:
            display = ipv4(v) ?? hex(v)
        case 5, 27, 28, 41, 42, 43, 46, 85:
            display = integer(v).map { "\($0)" } ?? hex(v)
        case 6:
            display = integer(v).map(serviceTypeName) ?? hex(v)
        case 40:
            display = integer(v).map(acctStatusName) ?? hex(v)
        case 49:
            display = integer(v).map(terminateCauseName) ?? hex(v)
        case 61:
            display = integer(v).map(nasPortTypeName) ?? hex(v)
        case 64, 65:
            // Tagged integer: tag octet + 3-byte value (RFC 2868).
            if v.count == 4 {
                let n = UInt32(v[1]) << 16 | UInt32(v[2]) << 8 | UInt32(v[3])
                display = t == 64 ? tunnelTypeName(n) : tunnelMediumName(n)
            } else { display = hex(v) }
        case 81:
            // Tagged string: a first octet 0x01–0x1F is the tag.
            let s = v.first.map { $0 >= 1 && $0 <= 0x1F } == true ? Array(v.dropFirst()) : v
            display = text(s, max: 253)
        case 79:
            display = "(\(v.count) bytes)"
        case 80:
            display = "(\(v.count) bytes)"
        default:
            display = hex(v)
        }
        return RadiusAttribute(type: t, value: v, display: display, name: name)
    }

    /// Vendor-Specific (26): vendor id, then the vendor's own type/length/value list.
    static func vendorSpecific(_ v: [UInt8]) -> [RadiusAttribute] {
        let b = Bytes(v)
        guard b.has(0, 4) else { return [RadiusAttribute(type: 26, value: v, display: hex(v), name: "Vendor-Specific")] }
        let vendor = b.u32(0)
        var out: [RadiusAttribute] = []
        var p = 4
        var n = 0
        while p + 2 <= b.count, n < 64 {
            n += 1
            let t = b.u8(p), l = Int(b.u8(p + 1))
            guard l >= 2, p + l <= b.count else { break }
            let value = b.slice(p + 2, l - 2)
            if let (name, kind) = vendorAttribute(vendor, t) {
                let display: String
                switch kind {
                case .text: display = text(value, max: 512)
                case .integer: display = integer(value).map { "\($0)" } ?? hex(value)
                case .address: display = ipv4(value) ?? hex(value)
                case .secret: display = "(present)"
                case .octets: display = hex(value)
                }
                out.append(RadiusAttribute(type: 26, vendor: vendor, vendorType: t, value: value, display: display, name: name))
            } else {
                out.append(RadiusAttribute(type: 26, vendor: vendor, vendorType: t, value: value,
                                           display: hex(value), name: "\(vendorName(vendor))/\(t)"))
            }
            p += l
        }
        if out.isEmpty {
            out.append(RadiusAttribute(type: 26, vendor: vendor, vendorType: nil, value: Array(v.dropFirst(4)),
                                       display: hex(Array(v.dropFirst(4))), name: "\(vendorName(vendor))"))
        }
        return out
    }

    // MARK: - HTTP captive-portal signs

    /// Hosts operating systems probe to decide whether the network is open or behind a portal.
    static let probeHosts: Set<String> = [
        "captive.apple.com", "www.apple.com", "www.appleiphonecell.com", "www.itools.info", "www.ibook.info",
        "www.airport.us", "www.thinkdifferent.us",
        "connectivitycheck.gstatic.com", "connectivitycheck.android.com", "clients3.google.com", "clients1.google.com",
        "www.google.com", "play.googleapis.com",
        "www.msftconnecttest.com", "www.msftncsi.com", "msftconnecttest.com", "ipv6.msftconnecttest.com",
        "detectportal.firefox.com", "nmcheck.gnome.org", "connectivity-check.ubuntu.com", "network-test.debian.org",
    ]

    static func bareHost(_ host: String) -> String {
        var h = host.lowercased().trimmingCharacters(in: .whitespaces)
        if h.hasPrefix("["), let close = h.firstIndex(of: "]") { return String(h[h.index(after: h.startIndex)..<close]) }
        if let colon = h.lastIndex(of: ":"), h.filter({ $0 == ":" }).count == 1 { h = String(h[..<colon]) }
        return h
    }

    static func isProbeHost(_ host: String?) -> Bool {
        guard let host else { return false }
        let h = bareHost(host)
        return probeHosts.contains(h) || h.hasSuffix(".msftconnecttest.com") || h.hasPrefix("connectivitycheck.")
    }

    /// The host of a URL (`http://portal.example.com:8080/login?x` → `portal.example.com`).
    static func urlHost(_ url: String) -> String? {
        guard let c = URLComponents(string: url.trimmingCharacters(in: .whitespaces)), let h = c.host, !h.isEmpty else { return nil }
        return h.lowercased()
    }

    /// Header value (case-insensitive name) of the HTTP message at `start`, within its headers.
    static func httpHeader(_ bytes: [UInt8], start: Int, name: String) -> String? {
        let b = Bytes(bytes)
        let key = Array(name.lowercased().utf8) + [0x3a]
        var p = start
        let limit = min(b.count, start + 8192)
        // Skip the start line.
        while p < limit, b.u8(p) != 0x0a { p += 1 }
        p += 1
        while p < limit {
            var e = p
            while e < limit, b.u8(e) != 0x0a { e += 1 }
            var lineEnd = e
            if lineEnd > p, b.u8(lineEnd - 1) == 0x0d { lineEnd -= 1 }
            if lineEnd == p { return nil }   // blank line: end of headers
            if lineEnd - p > key.count {
                var match = true
                for i in 0..<key.count {
                    let c = b.u8(p + i)
                    let lc = c >= 0x41 && c <= 0x5a ? c | 0x20 : c
                    if lc != key[i] { match = false; break }
                }
                if match {
                    return text(b.slice(p + key.count, lineEnd - p - key.count), max: 1024).trimmingCharacters(in: .whitespaces)
                }
            }
            p = e + 1
        }
        return nil
    }

    /// The body bytes after the blank line (as far as captured), or nil when the headers do not end here.
    static func httpBody(_ bytes: [UInt8], start: Int) -> [UInt8]? {
        let b = Bytes(bytes)
        var p = start
        let limit = min(b.count, start + 16384)
        while p + 1 < limit {
            if b.u8(p) == 0x0a, b.u8(p + 1) == 0x0a { return b.slice(p + 2, b.count - p - 2) }
            if p + 3 < limit, b.u8(p) == 0x0d, b.u8(p + 1) == 0x0a, b.u8(p + 2) == 0x0d, b.u8(p + 3) == 0x0a {
                return b.slice(p + 4, b.count - p - 4)
            }
            p += 1
        }
        return nil
    }

    /// The body of a probe answer that says "you are online" (Apple, Microsoft, Firefox).
    static func isProbeSuccessBody(_ body: [UInt8]) -> Bool {
        let s = String(decoding: body.prefix(2048), as: UTF8.self).lowercased()
        return s.contains("success") || s.contains("microsoft connect test") || s.contains("microsoft ncsi")
    }

    // MARK: - Classification

    nonisolated enum Frame: Sendable {
        case eapol(EAPOLFrame)
        case radius(RadiusPacket)
        case dhcp(type: String, clientMAC: String?, yourIP: String?)
        case dns(query: String?, isResponse: Bool, answers: Int, rcode: Int)
        case httpRequest(method: String, host: String?, path: String)
        /// `location` for a redirect; `body` (captured part, up to 2 KB) when the packet carries it.
        case httpResponse(status: Int, location: String?, body: [UInt8]?)
        case tlsHello(sni: String)
    }

    /// What `p` says about authentication, or nil for everything else (fast for the rest).
    static func classify(_ p: Packet) -> Frame? {
        let d = p.decoded
        if d.etherType == eapolEtherType {
            let off = d.payloadOffset
            guard off >= 0, off < p.data.count else { return nil }
            let bytes = [UInt8](p.data[(p.data.startIndex + off)...].prefix(4 + 1600))
            return eapol(bytes).map(Frame.eapol)
        }
        if let udp = d.udp {
            let sp = udp.sourcePort, dp = udp.destinationPort
            if isRADIUSPort(sp) || isRADIUSPort(dp) {
                let off = d.payloadOffset
                guard off >= 0, off < p.data.count else { return nil }
                let n = max(0, min(udp.payloadLength, p.data.count - off))
                let bytes = [UInt8](p.data[(p.data.startIndex + off)..<(p.data.startIndex + off + n)])
                return radius(bytes).map(Frame.radius)
            }
        }
        guard let app = d.app else { return nil }
        switch app {
        case .dhcp(let t, let mac, let yi):
            return .dhcp(type: t, clientMAC: mac, yourIP: yi)
        case .dns(let q, let r, let a, let rc):
            return .dns(query: q, isResponse: r, answers: a, rcode: rc)
        case .httpRequest(let m, let path, let host):
            return .httpRequest(method: m, host: host, path: path)
        case .httpResponse(let status, _):
            let off = d.payloadOffset
            guard off >= 0, off < p.data.count else { return .httpResponse(status: status, location: nil, body: nil) }
            let bytes = [UInt8](p.data[(p.data.startIndex + off)...].prefix(16384))
            let location = (300...399).contains(status) ? httpHeader(bytes, start: 0, name: "location") : nil
            let body = httpBody(bytes, start: 0).map { Array($0.prefix(2048)) }
            return .httpResponse(status: status, location: location, body: body)
        case .tlsClientHello(let sni, _):
            guard let sni, !sni.isEmpty else { return nil }
            return .tlsHello(sni: sni)
        default:
            return nil
        }
    }

    static func isRADIUSPort(_ p: UInt16) -> Bool { p == 1812 || p == 1813 || p == 1645 || p == 1646 || p == 3799 }
}
