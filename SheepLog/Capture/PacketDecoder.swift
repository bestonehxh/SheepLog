import Foundation

/// Ethernet (+802.1Q, QinQ) → ARP / IPv4 / IPv6 → TCP / UDP / ICMP / ICMPv6 → a few application
/// layers by port and shape. Pure, allocation-light.
///
/// Every read is bounds-checked: a truncated or garbage buffer decodes as far as it goes and
/// never traps.
nonisolated enum PacketDecoder {
    /// `linkType` is libpcap's DLT (1 = Ethernet, 113 = Linux cooked, 0 = loopback/NULL).
    static func decode(_ data: Data, linkType: Int32 = 1) -> Decoded {
        data.withUnsafeBytes { decode($0, linkType: linkType) }
    }

    /// Decode straight from a C buffer (the capture thread, before the copy into `Data`).
    static func decode(_ raw: UnsafeRawBufferPointer, linkType: Int32) -> Decoded {
        var run = DecodeRun(b: PacketBytes(p: raw))
        run.link(linkType)
        return run.d
    }
}

// MARK: - Bounds-checked big-endian reads

nonisolated struct PacketBytes {
    let p: UnsafeRawBufferPointer
    var count: Int { p.count }

    @inline(__always) func has(_ off: Int, _ n: Int) -> Bool {
        off >= 0 && n >= 0 && off <= p.count - n
    }
    @inline(__always) func u8(_ o: Int) -> UInt8 { has(o, 1) ? p[o] : 0 }
    @inline(__always) func u16(_ o: Int) -> UInt16 {
        has(o, 2) ? UInt16(p[o]) << 8 | UInt16(p[o + 1]) : 0
    }
    @inline(__always) func u24(_ o: Int) -> Int {
        has(o, 3) ? Int(p[o]) << 16 | Int(p[o + 1]) << 8 | Int(p[o + 2]) : 0
    }
    @inline(__always) func u32(_ o: Int) -> UInt32 {
        has(o, 4) ? UInt32(p[o]) << 24 | UInt32(p[o + 1]) << 16 | UInt32(p[o + 2]) << 8 | UInt32(p[o + 3]) : 0
    }

    /// Does the buffer at `off` start with `lit` (exact bytes)?
    func starts(_ off: Int, _ lit: [UInt8]) -> Bool {
        guard has(off, lit.count) else { return false }
        for i in 0..<lit.count where p[off + i] != lit[i] { return false }
        return true
    }

    /// PacketBytes [a, b) clamped, as text; control characters become spaces.
    func text(_ a: Int, _ b: Int, max: Int = 256) -> String {
        let lo = Swift.max(0, a), hi = Swift.min(p.count, b, lo + max)
        guard hi > lo else { return "" }
        var out = [UInt8](repeating: 0, count: hi - lo)
        for i in lo..<hi {
            let c = p[i]
            out[i - lo] = (c < 0x20 || c == 0x7f) ? 0x20 : c
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Index of the first CR or LF in [a, b), or b.
    func lineEnd(_ a: Int, _ b: Int) -> Int {
        var i = Swift.max(0, a)
        let hi = Swift.min(b, p.count)
        while i < hi {
            let c = p[i]
            if c == 0x0d || c == 0x0a { return i }
            i += 1
        }
        return hi
    }
}

// MARK: - Fast formatting

nonisolated enum PacketFormat {
    static let hexChars: [UInt8] = Array("0123456789abcdef".utf8)

    static func mac(_ b: PacketBytes, _ o: Int) -> String {
        guard b.has(o, 6) else { return "" }
        return String(unsafeUninitializedCapacity: 17) { buf in
            var j = 0
            for i in 0..<6 {
                let v = b.p[o + i]
                if i > 0 { buf[j] = 0x3a; j += 1 }
                buf[j] = hexChars[Int(v >> 4)]; buf[j + 1] = hexChars[Int(v & 0xf)]
                j += 2
            }
            return j
        }
    }

    static func ipv4(_ b: PacketBytes, _ o: Int) -> String {
        guard b.has(o, 4) else { return "" }
        return ipv4(b.p[o], b.p[o + 1], b.p[o + 2], b.p[o + 3])
    }

    static func ipv4(_ a: UInt8, _ b: UInt8, _ c: UInt8, _ d: UInt8) -> String {
        String(unsafeUninitializedCapacity: 15) { buf in
            var j = 0
            func put(_ v: UInt8) {
                if v >= 100 { buf[j] = 0x30 + v / 100; j += 1 }
                if v >= 10 { buf[j] = 0x30 + (v / 10) % 10; j += 1 }
                buf[j] = 0x30 + v % 10; j += 1
            }
            put(a); buf[j] = 0x2e; j += 1
            put(b); buf[j] = 0x2e; j += 1
            put(c); buf[j] = 0x2e; j += 1
            put(d)
            return j
        }
    }

    /// RFC 5952 text form (longest zero run compressed, lowercase, IPv4-mapped kept dotted).
    static func ipv6(_ b: PacketBytes, _ o: Int) -> String {
        guard b.has(o, 16) else { return "" }
        var g = [UInt16](repeating: 0, count: 8)
        for i in 0..<8 { g[i] = b.u16(o + i * 2) }
        if g[0] == 0, g[1] == 0, g[2] == 0, g[3] == 0, g[4] == 0, g[5] == 0xffff {
            return "::ffff:" + ipv4(b, o + 12)
        }
        var bestStart = -1, bestLen = 0, curStart = -1, curLen = 0
        for i in 0..<8 {
            if g[i] == 0 {
                if curStart < 0 { curStart = i; curLen = 0 }
                curLen += 1
                if curLen > bestLen { bestLen = curLen; bestStart = curStart }
            } else {
                curStart = -1; curLen = 0
            }
        }
        if bestLen < 2 { bestStart = -1 }
        return String(unsafeUninitializedCapacity: 41) { buf in
            var j = 0
            var i = 0
            while i < 8 {
                if i == bestStart {
                    buf[j] = 0x3a; j += 1
                    if i == 0 { buf[j] = 0x3a; j += 1 }
                    i += bestLen
                    continue
                }
                let v = g[i]
                var started = false
                for shift in stride(from: 12, through: 0, by: -4) {
                    let nib = Int((v >> UInt16(shift)) & 0xf)
                    if nib != 0 || started || shift == 0 {
                        buf[j] = hexChars[nib]; j += 1; started = true
                    }
                }
                if i < 7 { buf[j] = 0x3a; j += 1 }
                i += 1
            }
            return j
        }
    }

    static func hex(_ v: UInt64, digits: Int) -> String {
        String(unsafeUninitializedCapacity: digits + 2) { buf in
            buf[0] = 0x30; buf[1] = 0x78
            for i in 0..<digits {
                let shift = UInt64((digits - 1 - i) * 4)
                buf[2 + i] = hexChars[Int((v >> shift) & 0xf)]
            }
            return digits + 2
        }
    }

    static func hex2(_ v: UInt8) -> String { hex(UInt64(v), digits: 2) }
    static func hex4(_ v: UInt16) -> String { hex(UInt64(v), digits: 4) }
    static func hex8(_ v: UInt32) -> String { hex(UInt64(v), digits: 8) }
}

// MARK: - Names

nonisolated enum PacketNames {
    static func ipProto(_ p: UInt8) -> String? {
        switch p {
        case 0: "HOPOPT"
        case 1: "ICMP"
        case 2: "IGMP"
        case 4: "IPIP"
        case 6: "TCP"
        case 17: "UDP"
        case 41: "IPv6"
        case 47: "GRE"
        case 50: "ESP"
        case 51: "AH"
        case 58: "ICMPv6"
        case 88: "EIGRP"
        case 89: "OSPF"
        case 103: "PIM"
        case 112: "VRRP"
        case 115: "L2TP"
        case 132: "SCTP"
        default: nil
        }
    }

    static func etherType(_ t: UInt16) -> String? {
        switch t {
        case 0x0800: "IPv4"
        case 0x0806: "ARP"
        case 0x8035: "RARP"
        case 0x809B: "AppleTalk"
        case 0x86DD: "IPv6"
        case 0x8808: "Ethernet flow control"
        case 0x8809: "Slow protocols (LACP)"
        case 0x8847, 0x8848: "MPLS"
        case 0x8863: "PPPoE Discovery"
        case 0x8864: "PPPoE Session"
        case 0x886D: "Intel ANS"
        case 0x888E: "EAPOL"
        case 0x88CC: "LLDP"
        case 0x88E5: "MACsec"
        case 0x88F7: "PTP"
        case 0x8902: "CFM"
        case 0x893A: "IEEE 1905.1"
        case 0x9000: "Loopback"
        default: nil
        }
    }

    static func tlsVersion(_ v: UInt16) -> String {
        switch v {
        case 0x0300: "SSL 3.0"
        case 0x0301: "TLS 1.0"
        case 0x0302: "TLS 1.1"
        case 0x0303: "TLS 1.2"
        case 0x0304: "TLS 1.3"
        default: PacketFormat.hex4(v)
        }
    }

    static func dnsType(_ t: UInt16) -> String {
        switch t {
        case 1: "A"
        case 2: "NS"
        case 5: "CNAME"
        case 6: "SOA"
        case 12: "PTR"
        case 13: "HINFO"
        case 15: "MX"
        case 16: "TXT"
        case 28: "AAAA"
        case 33: "SRV"
        case 35: "NAPTR"
        case 41: "OPT"
        case 43: "DS"
        case 46: "RRSIG"
        case 47: "NSEC"
        case 48: "DNSKEY"
        case 64: "SVCB"
        case 65: "HTTPS"
        case 252: "AXFR"
        case 255: "ANY"
        default: "Unknown (\(t))"
        }
    }

    static func dnsRcode(_ r: Int) -> String {
        switch r {
        case 0: "No error"
        case 1: "Format error"
        case 2: "Server failure"
        case 3: "No such name"
        case 4: "Not implemented"
        case 5: "Refused"
        default: "Error \(r)"
        }
    }

    static let syslogFacilities = ["KERN", "USER", "MAIL", "DAEMON", "AUTH", "SYSLOG", "LPR", "NEWS",
                                   "UUCP", "CRON", "AUTHPRIV", "FTP", "NTP", "SECURITY", "CONSOLE", "SOLARIS-CRON",
                                   "LOCAL0", "LOCAL1", "LOCAL2", "LOCAL3", "LOCAL4", "LOCAL5", "LOCAL6", "LOCAL7"]
    static let syslogSeverities = ["EMERG", "ALERT", "CRIT", "ERR", "WARNING", "NOTICE", "INFO", "DEBUG"]

    static func radiusCode(_ c: UInt8) -> String? {
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
        default: nil
        }
    }

    static func snmpPDU(_ tag: UInt8) -> String? {
        switch tag {
        case 0xA0: "get-request"
        case 0xA1: "get-next-request"
        case 0xA2: "get-response"
        case 0xA3: "set-request"
        case 0xA4: "trap"
        case 0xA5: "getBulkRequest"
        case 0xA6: "inform-request"
        case 0xA7: "snmpV2-trap"
        case 0xA8: "report"
        default: nil
        }
    }

    static func icmpUnreachable(_ code: UInt8) -> String {
        switch code {
        case 0: "Network unreachable"
        case 1: "Host unreachable"
        case 2: "Protocol unreachable"
        case 3: "Port unreachable"
        case 4: "Fragmentation needed"
        case 5: "Source route failed"
        case 6: "Destination network unknown"
        case 7: "Destination host unknown"
        case 8: "Source host isolated"
        case 9: "Network administratively prohibited"
        case 10: "Host administratively prohibited"
        case 11: "Network unreachable for TOS"
        case 12: "Host unreachable for TOS"
        case 13: "Communication administratively filtered"
        case 14: "Host precedence violation"
        case 15: "Precedence cutoff in effect"
        default: "Code \(code)"
        }
    }

    static func icmp6Unreachable(_ code: UInt8) -> String {
        switch code {
        case 0: "No route to destination"
        case 1: "Administratively prohibited"
        case 2: "Beyond scope of source address"
        case 3: "Address unreachable"
        case 4: "Port unreachable"
        case 5: "Source address failed ingress/egress policy"
        case 6: "Reject route to destination"
        default: "Code \(code)"
        }
    }
}

nonisolated enum PacketPorts {
    static func isHTTP(_ p: UInt16) -> Bool {
        switch p {
        case 80, 8080, 8000, 8008, 8081, 8888, 3128, 591, 5985: true
        default: false
        }
    }

    static func isTLS(_ p: UInt16) -> Bool {
        switch p {
        case 443, 8443, 993, 995, 465, 636, 853, 989, 990, 992, 994, 3269, 5061, 5986, 6514, 10443: true
        default: false
        }
    }

    static func isRADIUS(_ p: UInt16) -> Bool {
        p == 1812 || p == 1813 || p == 1645 || p == 1646 || p == 3799
    }
}

// MARK: - The decoder

nonisolated private enum Lits {
    static let httpMethods: [[UInt8]] = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH",
                                         "CONNECT", "TRACE", "PROPFIND", "SUBSCRIBE", "NOTIFY", "M-SEARCH"]
        .map { Array($0.utf8) }
    static let httpVersion: [UInt8] = Array("HTTP/1.".utf8)
    static let ssh: [UInt8] = Array("SSH-".utf8)
}

nonisolated private struct DecodeRun {
    let b: PacketBytes
    var d = Decoded()

    init(b: PacketBytes) { self.b = b }

    // MARK: Link layer

    mutating func link(_ lt: Int32) {
        guard b.count > 0 else {
            d.protocolName = "Frame"
            d.info = "Empty frame"
            return
        }
        switch lt {
        case 1:
            ether()
        case 0, 108:
            guard b.has(0, 4) else { truncated("NULL", "loopback header"); return }
            let be = b.u32(0)
            let le = UInt32(b.u8(0)) | UInt32(b.u8(1)) << 8 | UInt32(b.u8(2)) << 16 | UInt32(b.u8(3)) << 24
            let af = lt == 108 ? be : (b.u8(0) == 0 && b.u8(1) == 0 ? be : le)
            d.payloadOffset = 4
            switch af {
            case 2: ipv4(4)
            case 24, 28, 30: ipv6(4)
            default:
                d.protocolName = "NULL"
                d.info = "Loopback, family \(af)"
            }
        case 113:
            guard b.has(0, 16) else { truncated("SLL", "Linux cooked header"); return }
            if b.u16(4) == 6 { d.sourceMAC = PacketFormat.mac(b, 6) }
            cooked(b.u16(14), 16)
        case 276:
            guard b.has(0, 20) else { truncated("SLL2", "Linux cooked v2 header"); return }
            if b.u8(11) == 6 { d.sourceMAC = PacketFormat.mac(b, 12) }
            cooked(b.u16(0), 20)
        case 12, 14, 101, 228, 229:
            switch b.u8(0) >> 4 {
            case 4: d.etherType = 0x0800; ipv4(0)
            case 6: d.etherType = 0x86DD; ipv6(0)
            default:
                d.protocolName = "Raw"
                d.info = "Raw IP, bogus version \(b.u8(0) >> 4)"
            }
        default:
            d.protocolName = "DLT \(lt)"
            d.info = "Link type \(lt), \(b.count) bytes"
        }
    }

    /// Linux cooked: values ≥ 0x0600 are EtherTypes; below that they are Linux `ETH_P_*`
    /// pseudo-protocols (1 = 802.3 without LLC, 4 = 802.2 LLC, 0x0C = CAN, …), not EtherTypes.
    mutating func cooked(_ proto: UInt16, _ off: Int) {
        d.etherType = proto
        if proto >= 0x0600 { l3(proto, off); return }
        d.payloadOffset = min(off, b.count)
        switch proto {
        case 4: llc(off, length: max(0, b.count - off))
        case 1:
            d.protocolName = "IPX"
            d.info = "Novell 802.3 (raw IPX), \(max(0, b.count - off)) bytes"
        default:
            d.protocolName = "SLL"
            d.info = "Linux cooked, protocol \(PacketFormat.hex4(proto)) (not an EtherType), \(max(0, b.count - off)) bytes"
        }
    }

    mutating func truncated(_ proto: String, _ what: String) {
        d.protocolName = proto
        d.info = "Truncated \(what) (\(b.count) bytes)"
    }

    mutating func ether() {
        if b.has(0, 6) { d.destinationMAC = PacketFormat.mac(b, 0) }
        if b.has(6, 6) { d.sourceMAC = PacketFormat.mac(b, 6) }
        guard b.has(0, 14) else { truncated("Ethernet", "Ethernet frame"); return }
        var type = b.u16(12)
        var off = 14
        var tags = 0
        var inner: UInt16 = 0
        while (type == 0x8100 || type == 0x88A8 || type == 0x9100), tags < 4 {
            guard b.has(off, 4) else {
                d.etherType = type
                d.payloadOffset = off
                d.protocolName = "802.1Q"
                d.info = "Truncated VLAN tag"
                return
            }
            let vid = b.u16(off) & 0x0FFF
            if tags == 0 { d.vlan = vid }
            inner = vid
            tags += 1
            type = b.u16(off + 2)
            off += 4
        }
        d.etherType = type
        if type < 0x0600 {
            llc(off, length: Int(type))
        } else {
            l3(type, off)
        }
        if tags >= 2, let outer = d.vlan {
            d.info += " [QinQ \(outer), inner VLAN \(inner)]"
        }
    }

    mutating func llc(_ off: Int, length: Int) {
        d.payloadOffset = min(off, b.count)
        guard b.has(off, 3) else { truncated("LLC", "802.2 LLC header"); return }
        let dsap = b.u8(off), ssap = b.u8(off + 1)
        if dsap == 0xAA, ssap == 0xAA {
            guard b.has(off + 3, 5) else { truncated("LLC", "SNAP header"); return }
            let oui = UInt32(b.u8(off + 3)) << 16 | UInt32(b.u8(off + 4)) << 8 | UInt32(b.u8(off + 5))
            let pid = b.u16(off + 6)
            if oui == 0x00000C, pid == 0x2000 { cdp(off + 8); return }
            if oui == 0 { l3(pid, off + 8); return }
            d.protocolName = "LLC"
            d.info = "SNAP OUI \(PacketFormat.hex(UInt64(oui), digits: 6)), PID \(PacketFormat.hex4(pid))"
            return
        }
        if dsap == 0x42, ssap == 0x42 { stp(off + 3); return }
        d.protocolName = "LLC"
        d.info = "DSAP \(PacketFormat.hex2(dsap)) SSAP \(PacketFormat.hex2(ssap)), length \(length)"
    }

    mutating func l3(_ type: UInt16, _ off: Int) {
        d.payloadOffset = min(off, b.count)
        switch type {
        case 0x0800: ipv4(off)
        case 0x86DD: ipv6(off)
        case 0x0806: arp(off)
        case 0x88CC: lldp(off)
        default:
            d.protocolName = PacketNames.etherType(type) ?? "Ethernet"
            d.info = PacketFormat.hex4(type)
        }
    }

    // MARK: Layer 2 control protocols

    mutating func arp(_ off: Int) {
        d.protocolName = "ARP"
        guard b.has(off, 8) else { d.info = "Truncated ARP"; return }
        let htype = b.u16(off), ptype = b.u16(off + 2)
        let hlen = b.u8(off + 4), plen = b.u8(off + 5), oper = b.u16(off + 6)
        guard hlen == 6, plen == 4, ptype == 0x0800, b.has(off + 8, 20) else {
            d.info = "ARP opcode \(oper) (hardware \(htype), protocol \(PacketFormat.hex4(ptype)))"
            return
        }
        let sha = PacketFormat.mac(b, off + 8), spa = PacketFormat.ipv4(b, off + 14)
        let tha = PacketFormat.mac(b, off + 18), tpa = PacketFormat.ipv4(b, off + 24)
        let isRequest = oper == 1 || oper == 3
        d.arp = ARPInfo(isRequest: isRequest, senderMAC: sha, senderIP: spa, targetMAC: tha, targetIP: tpa)
        if oper == 3 || oper == 4 { d.protocolName = "RARP" }
        if isRequest {
            if spa == tpa {
                d.info = "Gratuitous ARP for \(spa) (Request)"
            } else if spa == "0.0.0.0" {
                d.info = "Who has \(tpa)? (ARP Probe)"
            } else {
                d.info = "Who has \(tpa)? Tell \(spa)"
            }
        } else {
            d.info = "\(spa) is at \(sha)"
        }
    }

    mutating func lldp(_ off: Int) {
        d.protocolName = "LLDP"
        var p = off
        var chassis: String?, port: String?, sys: String?
        var n = 0
        while n < 64, b.has(p, 2) {
            n += 1
            let h = b.u16(p)
            let t = h >> 9, l = Int(h & 0x1FF)
            p += 2
            if t == 0 { break }
            let avail = min(l, b.count - p)
            switch t {
            case 1: chassis = lldpID(p, avail, macSubtype: 4, netSubtype: 5)
            case 2: port = lldpID(p, avail, macSubtype: 3, netSubtype: 4)
            case 5: sys = b.text(p, p + avail, max: 128)
            default: break
            }
            p += l
        }
        var parts: [String] = []
        if let chassis { parts.append("Chassis \(chassis)") }
        if let port { parts.append("Port \(port)") }
        if let sys { parts.append("Sys \(sys)") }
        d.info = parts.isEmpty ? "LLDP" : parts.joined(separator: " ")
    }

    func lldpID(_ p: Int, _ l: Int, macSubtype: UInt8, netSubtype: UInt8) -> String? {
        guard l >= 2, b.has(p, 1) else { return nil }
        let sub = b.u8(p)
        if sub == macSubtype, l - 1 == 6 { return PacketFormat.mac(b, p + 1) }
        if sub == netSubtype, l - 1 >= 5, b.u8(p + 1) == 1 { return PacketFormat.ipv4(b, p + 2) }
        return b.text(p + 1, p + l, max: 128)
    }

    mutating func cdp(_ off: Int) {
        d.protocolName = "CDP"
        d.payloadOffset = min(off, b.count)
        var p = off + 4
        var device: String?, port: String?, platform: String?
        var n = 0
        while n < 64, b.has(p, 4) {
            n += 1
            let t = b.u16(p), l = Int(b.u16(p + 2))
            guard l >= 4 else { break }
            switch t {
            case 1: device = b.text(p + 4, p + l, max: 128)
            case 3: port = b.text(p + 4, p + l, max: 128)
            case 6: platform = b.text(p + 4, p + l, max: 128)
            default: break
            }
            p += l
        }
        var s = "CDP"
        if let device { s += " Device-ID \(device)" }
        if let port { s += " Port-ID \(port)" }
        if let platform { s += " Platform \(platform)" }
        d.info = s
    }

    mutating func stp(_ off: Int) {
        d.protocolName = "STP"
        d.payloadOffset = min(off, b.count)
        guard b.has(off, 4) else { d.info = "Truncated BPDU"; return }
        let version = b.u8(off + 2), type = b.u8(off + 3)
        if type == 0x80 { d.info = "STP Topology Change Notification"; return }
        guard b.has(off, 27) else { d.info = "Truncated BPDU"; return }
        let rootPrio = b.u16(off + 5)
        let rootMAC = PacketFormat.mac(b, off + 7)
        let cost = b.u32(off + 13)
        let port = b.u16(off + 25)
        let kind = switch version { case 0: "Conf."; case 2: "RST."; case 3: "MST."; default: "BPDU" }
        d.info = "STP \(kind) Root=\(rootPrio & 0xF000)/\(rootPrio & 0x0FFF)/\(rootMAC) Cost=\(cost) Port=\(PacketFormat.hex4(port))"
    }

    // MARK: IP

    mutating func ipv4(_ off: Int) {
        d.payloadOffset = min(off, b.count)
        guard b.has(off, 20) else { d.protocolName = "IPv4"; d.info = "Truncated IPv4 header"; return }
        guard b.u8(off) >> 4 == 4 else { d.protocolName = "IPv4"; d.info = "Bogus IP version \(b.u8(off) >> 4)"; return }
        let ihl = Int(b.u8(off) & 0x0F) * 4
        let tos = b.u8(off + 1)
        let total = Int(b.u16(off + 2))
        let ident = b.u16(off + 4)
        let ff = b.u16(off + 6)
        let ttl = b.u8(off + 8), proto = b.u8(off + 9)
        let fragBytes = (ff & 0x1FFF) &* 8
        let ip = IPHeader(version: 4, source: PacketFormat.ipv4(b, off + 12), destination: PacketFormat.ipv4(b, off + 16),
                          proto: proto, ttl: ttl, identification: ident,
                          dontFragment: ff & 0x4000 != 0, moreFragments: ff & 0x2000 != 0,
                          fragmentOffset: fragBytes, headerLength: ihl, totalLength: total, dscp: tos >> 2)
        d.ip = ip
        guard ihl >= 20 else { d.protocolName = "IPv4"; d.info = "Bogus IPv4 header length \(ihl)"; return }
        let l4 = off + ihl
        // 0 = TCP segmentation offload (captured on the sending host before the NIC splits it):
        // the captured bytes are the datagram. Anything else below the header is bogus.
        if total > 0, total < ihl {
            d.protocolName = "IPv4"
            d.info = "Bogus IPv4 total length \(total) (less than the header length \(ihl))"
            return
        }
        let lengthKnown = total > 0
        let wire = lengthKnown ? total - ihl : max(0, b.count - l4)
        let end = lengthKnown ? min(b.count, off + total) : b.count
        if fragBytes > 0 {
            d.payloadOffset = min(l4, b.count)
            d.protocolName = "IPv4"
            d.info = "Fragmented IP protocol (proto=\(PacketNames.ipProto(proto) ?? "\(proto)") \(proto), off=\(fragBytes), ID=\(PacketFormat.hex4(ident)))"
            return
        }
        transport(proto, l4, end: end, wire: wire, ttl: ttl, v6: false)
    }

    mutating func ipv6(_ off: Int) {
        d.payloadOffset = min(off, b.count)
        guard b.has(off, 40) else { d.protocolName = "IPv6"; d.info = "Truncated IPv6 header"; return }
        guard b.u8(off) >> 4 == 6 else { d.protocolName = "IPv6"; d.info = "Bogus IP version \(b.u8(off) >> 4)"; return }
        let tc = UInt8(truncatingIfNeeded: b.u16(off) >> 4)
        let plen = Int(b.u16(off + 4))
        var next = b.u8(off + 6)
        let hop = b.u8(off + 7)
        let src = PacketFormat.ipv6(b, off + 8), dst = PacketFormat.ipv6(b, off + 24)
        var p = off + 40
        var fragOff: UInt16 = 0, mf = false, fragID: UInt32 = 0, isFragment = false
        var hops = 0
        walk: while hops < 12 {
            hops += 1
            switch next {
            case 0, 43, 60, 135, 139, 140:
                guard b.has(p, 2) else { break walk }
                let n = b.u8(p)
                p += (Int(b.u8(p + 1)) + 1) * 8
                next = n
            case 44:
                guard b.has(p, 8) else { break walk }
                let n = b.u8(p)
                let fo = b.u16(p + 2)
                fragOff = (fo >> 3) &* 8
                mf = fo & 1 == 1
                fragID = b.u32(p + 4)
                isFragment = true
                p += 8
                next = n
            case 51:
                guard b.has(p, 2) else { break walk }
                let n = b.u8(p)
                p += (Int(b.u8(p + 1)) + 2) * 4
                next = n
            default:
                break walk
            }
        }
        let headerLength = p - off
        d.ip = IPHeader(version: 6, source: src, destination: dst, proto: next, ttl: hop,
                        identification: UInt16(truncatingIfNeeded: fragID), dontFragment: false,
                        moreFragments: mf, fragmentOffset: fragOff, headerLength: headerLength,
                        totalLength: 40 + plen, dscp: tc >> 2)
        let end = plen > 0 ? min(b.count, off + 40 + plen) : b.count
        let wire = plen > 0 ? max(0, 40 + plen - headerLength) : max(0, b.count - p)
        if isFragment, fragOff > 0 {
            d.payloadOffset = min(p, b.count)
            d.protocolName = "IPv6"
            d.info = "IPv6 fragment (off=\(fragOff), ID=\(PacketFormat.hex8(fragID)), nh=\(next))"
            return
        }
        if next == 59 {
            d.payloadOffset = min(p, b.count)
            d.protocolName = "IPv6"
            d.info = "IPv6 no next header"
            return
        }
        transport(next, p, end: end, wire: wire, ttl: hop, v6: true)
    }

    // MARK: Transport

    mutating func transport(_ proto: UInt8, _ off: Int, end: Int, wire: Int, ttl: UInt8, v6: Bool) {
        d.payloadOffset = min(max(off, 0), b.count)
        switch proto {
        case 6: tcp(off, end: end, wire: wire)
        case 17: udp(off, end: end, wire: wire)
        case 1: icmp(off, end: end, ttl: ttl)
        case 58: icmp6(off, end: end, ttl: ttl)
        case 2: igmp(off)
        case 89: ospf(off)
        case 112: vrrp(off)
        default:
            let name = PacketNames.ipProto(proto)
            d.protocolName = name ?? (v6 ? "IPv6" : "IPv4")
            d.info = "IP protocol \(proto)" + (name.map { " (\($0))" } ?? "")
        }
    }

    mutating func tcp(_ off: Int, end: Int, wire: Int) {
        d.protocolName = "TCP"
        // The header must lie within the IP datagram, not in the Ethernet padding after it (a
        // first fragment carrying only 8 bytes of TCP, padded to 60).
        guard b.has(off, 20), off + 20 <= end else {
            if b.has(off, 4) {
                d.info = "\(b.u16(off)) → \(b.u16(off + 2)) [Truncated TCP header]"
            } else {
                d.info = "Truncated TCP header"
            }
            return
        }
        let sp = b.u16(off), dp = b.u16(off + 2)
        let seq = b.u32(off + 4), ack = b.u32(off + 8)
        let doff = Int(b.u8(off + 12) >> 4) * 4
        let flags = TCPFlags(rawValue: b.u8(off + 13))
        let win = b.u16(off + 14)
        var mss: UInt16?, ws: UInt8?, sackPerm = false, sackBlocks = 0
        var tsv: UInt32?, tse: UInt32?
        var sackEdges: [UInt32] = []
        var p = off + 20
        let optEnd = min(off + max(doff, 20), b.count)
        var n = 0
        while p < optEnd, n < 40 {
            n += 1
            let kind = b.u8(p)
            if kind == 0 { break }
            if kind == 1 { p += 1; continue }
            guard p + 1 < optEnd else { break }
            let len = Int(b.u8(p + 1))
            guard len >= 2, p + len <= optEnd else { break }
            switch kind {
            case 2 where len == 4: mss = b.u16(p + 2)
            case 3 where len == 3: ws = b.u8(p + 2)
            case 4: sackPerm = true
            case 5:
                sackBlocks = (len - 2) / 8
                sackEdges = []
                for k in 0..<min(sackBlocks, 4) {
                    sackEdges += [b.u32(p + 2 + 8 * k), b.u32(p + 6 + 8 * k)]
                }
            case 8 where len == 10: tsv = b.u32(p + 2); tse = b.u32(p + 6)
            default: break
            }
            p += len
        }
        let hdr = max(doff, 20)
        let payloadLength = max(0, wire - hdr)
        let payStart = off + hdr
        d.payloadOffset = min(payStart, b.count)
        d.tcp = TCPHeader(sourcePort: sp, destinationPort: dp, sequence: seq, acknowledgment: ack, flags: flags,
                          window: win, headerLength: doff, payloadLength: payloadLength, mss: mss,
                          windowScale: ws, sackPermitted: sackPerm, sackBlocks: sackBlocks,
                          timestampValue: tsv, timestampEcho: tse, sackEdges: sackEdges)
        var s = "\(sp) → \(dp) [\(flags.rawValue == 0 ? "<None>" : flags.label)] Seq=\(seq)"
        if flags.contains(.ack) { s += " Ack=\(ack)" }
        s += " Win=\(win) Len=\(payloadLength)"
        if let mss { s += " MSS=\(mss)" }
        if let ws { s += " WS=\(1 << Int(min(ws, 14)))" }
        if sackPerm { s += " SACK_PERM" }
        if sackBlocks > 0 { s += " SACK×\(sackBlocks)" }
        if let tsv, let tse { s += " TSval=\(tsv) TSecr=\(tse)" }
        if doff < 20 { s += " [bogus header length \(doff)]" }
        d.info = s
        let payEnd = min(end, b.count)
        if payloadLength > 0, payEnd > payStart {
            tcpApp(sp, dp, payStart, payEnd, payloadLength: payloadLength)
        }
    }

    mutating func udp(_ off: Int, end: Int, wire: Int) {
        d.protocolName = "UDP"
        guard b.has(off, 8) else { d.info = "Truncated UDP header"; return }
        let sp = b.u16(off), dp = b.u16(off + 2), len = Int(b.u16(off + 4))
        let payloadLength = len >= 8 ? len - 8 : max(0, wire - 8)
        d.payloadOffset = min(off + 8, b.count)
        d.udp = UDPHeader(sourcePort: sp, destinationPort: dp, length: len, payloadLength: payloadLength)
        d.info = "\(sp) → \(dp) Len=\(payloadLength)"
        // A length field the datagram cannot hold (a truncated or malformed packet): say so,
        // as Wireshark does, instead of showing a payload that is not there (a first IP fragment
        // carries the whole datagram's length).
        if d.ip?.moreFragments != true, len > wire || (len > 0 && len < 8) { d.info += " [bad length \(len), IP payload \(wire)]" }
        var payEnd = min(end, b.count)
        if len >= 8 { payEnd = min(payEnd, off + len) }
        let payStart = off + 8
        if payEnd > payStart { udpApp(sp, dp, payStart, payEnd) }
    }

    mutating func icmp(_ off: Int, end: Int, ttl: UInt8) {
        d.protocolName = "ICMP"
        guard b.has(off, 4) else { d.info = "Truncated ICMP"; return }
        let type = b.u8(off), code = b.u8(off + 1)
        var id: UInt16?, seq: UInt16?
        switch type {
        case 0, 8, 13, 14, 15, 16, 17, 18:
            if b.has(off, 8) { id = b.u16(off + 4); seq = b.u16(off + 6) }
        default: break
        }
        d.icmp = ICMPHeader(type: type, code: code, identifier: id, sequence: seq)
        d.payloadOffset = min(off + 8, b.count)
        switch type {
        case 0: d.info = Self.echo("reply", id, seq) + " ttl=\(ttl)"
        case 8: d.info = Self.echo("request", id, seq) + " ttl=\(ttl)"
        case 3: d.info = "Destination unreachable (\(PacketNames.icmpUnreachable(code)))" + embedded(off + 8)
        case 11:
            d.info = "Time exceeded (\(code == 0 ? "TTL exceeded in transit" : code == 1 ? "Fragment reassembly time exceeded" : "Code \(code)"))" + embedded(off + 8)
        case 5:
            let what = switch code {
            case 0: "Redirect for network"
            case 1: "Redirect for host"
            case 2: "Redirect for TOS and network"
            case 3: "Redirect for TOS and host"
            default: "Code \(code)"
            }
            d.info = "Redirect (\(what))" + (b.has(off + 4, 4) ? " gateway \(PacketFormat.ipv4(b, off + 4))" : "")
        case 4: d.info = "Source quench"
        case 9: d.info = "Router advertisement"
        case 10: d.info = "Router solicitation"
        case 12: d.info = "Parameter problem"
        case 13: d.info = "Timestamp request"
        case 14: d.info = "Timestamp reply"
        default: d.info = "Type \(type) Code \(code)"
        }
    }

    /// "Echo (ping) request id=0x… seq=…" (ICMP and ICMPv6).
    static func echo(_ word: String, _ id: UInt16?, _ seq: UInt16?) -> String {
        var s = "Echo (ping) \(word)"
        if let id, let seq { s += " id=\(PacketFormat.hex4(id)) seq=\(seq)" }
        return s
    }

    /// The original datagram quoted inside an ICMP error.
    func embedded(_ off: Int) -> String {
        guard b.has(off, 20), b.u8(off) >> 4 == 4 else { return "" }
        let ihl = Int(b.u8(off) & 0x0F) * 4
        guard ihl >= 20 else { return "" }
        let proto = b.u8(off + 9)
        let src = PacketFormat.ipv4(b, off + 12), dst = PacketFormat.ipv4(b, off + 16)
        let name = PacketNames.ipProto(proto) ?? "proto \(proto)"
        if (proto == 6 || proto == 17), b.has(off + ihl, 4) {
            return " for \(src):\(b.u16(off + ihl)) → \(dst):\(b.u16(off + ihl + 2)) \(name)"
        }
        // An ICMP traceroute's probe: which echo (id / seq) this hop answered.
        if proto == 1, b.has(off + ihl, 8), b.u8(off + ihl) == 8 {
            return " for \(src) → \(dst) ICMP echo id=\(PacketFormat.hex4(b.u16(off + ihl + 4))) seq=\(b.u16(off + ihl + 6))"
        }
        return " for \(src) → \(dst) \(name)"
    }

    mutating func icmp6(_ off: Int, end: Int, ttl: UInt8) {
        d.protocolName = "ICMPv6"
        guard b.has(off, 4) else { d.info = "Truncated ICMPv6"; return }
        let type = b.u8(off), code = b.u8(off + 1)
        var id: UInt16?, seq: UInt16?
        if type == 128 || type == 129, b.has(off, 8) { id = b.u16(off + 4); seq = b.u16(off + 6) }
        d.icmp = ICMPHeader(type: type, code: code, identifier: id, sequence: seq)
        d.payloadOffset = min(off + 8, b.count)
        switch type {
        case 128: d.info = Self.echo("request", id, seq) + " hlim=\(ttl)"
        case 129: d.info = Self.echo("reply", id, seq) + " hlim=\(ttl)"
        case 1: d.info = "Destination Unreachable (\(PacketNames.icmp6Unreachable(code)))"
        case 2: d.info = "Packet Too Big" + (b.has(off + 4, 4) ? " (MTU=\(b.u32(off + 4)))" : "")
        case 3: d.info = "Time Exceeded (\(code == 0 ? "hop limit exceeded in transit" : "fragment reassembly time exceeded"))"
        case 4: d.info = "Parameter Problem"
        case 130: d.info = "Multicast Listener Query" + (b.has(off + 8, 16) ? " \(PacketFormat.ipv6(b, off + 8))" : "")
        case 131: d.info = "Multicast Listener Report" + (b.has(off + 8, 16) ? " \(PacketFormat.ipv6(b, off + 8))" : "")
        case 132: d.info = "Multicast Listener Done" + (b.has(off + 8, 16) ? " \(PacketFormat.ipv6(b, off + 8))" : "")
        case 143: d.info = "Multicast Listener Report Message v2"
        case 133: d.info = "Router Solicitation"
        case 134: d.info = "Router Advertisement" + (d.ip.map { " from \($0.source)" } ?? "")
        case 135: d.info = "Neighbor Solicitation" + (b.has(off + 8, 16) ? " for \(PacketFormat.ipv6(b, off + 8))" : "")
        case 136:
            var s = "Neighbor Advertisement"
            if b.has(off + 8, 16) { s += " \(PacketFormat.ipv6(b, off + 8))" }
            let f = b.u8(off + 4)
            var fl: [String] = []
            if f & 0x80 != 0 { fl.append("rtr") }
            if f & 0x40 != 0 { fl.append("sol") }
            if f & 0x20 != 0 { fl.append("ovr") }
            if !fl.isEmpty { s += " (\(fl.joined(separator: ", ")))" }
            d.info = s
        case 137: d.info = "Redirect"
        default: d.info = "Type \(type) Code \(code)"
        }
    }

    mutating func igmp(_ off: Int) {
        d.protocolName = "IGMP"
        guard b.has(off, 1) else { d.info = "Truncated IGMP"; return }
        let type = b.u8(off)
        let group = b.has(off + 4, 4) ? PacketFormat.ipv4(b, off + 4) : ""
        switch type {
        case 0x11: d.info = "Membership Query" + (group.isEmpty || group == "0.0.0.0" ? ", general" : ", specific for group \(group)")
        case 0x12: d.info = "Membership Report (v1) group \(group)"
        case 0x16: d.info = "Membership Report group \(group)"
        case 0x17: d.info = "Leave Group \(group)"
        case 0x22: d.info = "Membership Report (v3)"
        default: d.info = "IGMP type \(PacketFormat.hex2(type))"
        }
    }

    mutating func ospf(_ off: Int) {
        d.protocolName = "OSPF"
        guard b.has(off, 2) else { d.info = "Truncated OSPF"; return }
        let t = b.u8(off + 1)
        d.info = switch t {
        case 1: "Hello Packet"
        case 2: "DB Description"
        case 3: "LS Request"
        case 4: "LS Update"
        case 5: "LS Acknowledge"
        default: "OSPF type \(t)"
        }
    }

    mutating func vrrp(_ off: Int) {
        d.protocolName = "VRRP"
        guard b.has(off, 4) else { d.info = "Truncated VRRP"; return }
        let v = b.u8(off) >> 4
        d.info = "Announcement (v\(v)) VRID=\(b.u8(off + 1)) Prio=\(b.u8(off + 2))"
    }

    // MARK: Application layer — TCP

    mutating func tcpApp(_ sp: UInt16, _ dp: UInt16, _ s: Int, _ e: Int, payloadLength: Int) {
        if (sp == 53 || dp == 53), e - s >= 14, dns(s + 2, e, name: "DNS") { return }
        let httpPort = PacketPorts.isHTTP(sp) || PacketPorts.isHTTP(dp)
        if http(s, e, httpPort: httpPort) { return }
        let tlsPort = PacketPorts.isTLS(sp) || PacketPorts.isTLS(dp)
        if tls(s, e, onTLSPort: tlsPort) { return }
        if sp == 22 || dp == 22 { ssh(s, e, payloadLength: payloadLength); return }
        if sp == 514 || dp == 514 || sp == 601 || dp == 601, syslog(s, e, tcp: true) { return }
        if sp == 179 || dp == 179, bgp(s, e) { return }
        if httpPort {
            // Body bytes of a request or response on an HTTP port: tcpdump and Wireshark
            // (per packet) both call them HTTP ("Continuation"). No `app`: the flow analysis
            // keys on the header packets only.
            d.protocolName = "HTTP"
            d.info = "[Continuation] " + d.info
            return
        }
        if sp == 49 || dp == 49, b.has(s, 12) {
            let t = b.u8(s + 1)
            let kind = t == 1 ? "Authentication" : t == 2 ? "Authorization" : t == 3 ? "Accounting" : "type \(t)"
            d.app = .other(name: "TACACS+")
            d.protocolName = "TACACS+"
            d.info = "TACACS+ \(kind)"
            return
        }
    }

    mutating func http(_ s: Int, _ e: Int, httpPort: Bool) -> Bool {
        let lineEnd = b.lineEnd(s, min(e, s + 4096))
        if b.starts(s, Lits.httpVersion) {
            // "HTTP/1.1 200 OK"
            let line = b.text(s, lineEnd, max: 512)
            let parts = line.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
            guard parts.count >= 2, let status = Int(parts[1]) else { return false }
            let reason = parts.count > 2 ? String(parts[2]) : ""
            d.app = .httpResponse(status: status, reason: reason)
            d.protocolName = "HTTP"
            d.info = line
            return true
        }
        var matched = false
        for m in Lits.httpMethods where b.starts(s, m) {
            let after = s + m.count
            if b.u8(after) == 0x20, b.u8(after + 1) == 0x2f || (httpPort && b.u8(after + 1) > 0x20) || m == Lits.httpMethods[7] {
                matched = true
            }
            break
        }
        guard matched else { return false }
        let line = b.text(s, lineEnd, max: 1024)
        let parts = line.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard parts.count >= 2 else { return false }
        // Host header
        var host: String?
        var p = lineEnd
        let limit = min(e, s + 8192)
        while p < limit {
            // One line break (CRLF or LF): a second one right after it is the blank line that
            // ends the headers — a "host:" in the body is not the Host header.
            if b.u8(p) == 0x0d, p + 1 < limit, b.u8(p + 1) == 0x0a { p += 2 } else if b.u8(p) == 0x0a || b.u8(p) == 0x0d { p += 1 }
            let le = b.lineEnd(p, limit)
            if le == p { break }
            if le - p > 5,
               b.u8(p) | 0x20 == 0x68, b.u8(p + 1) | 0x20 == 0x6f, b.u8(p + 2) | 0x20 == 0x73,
               b.u8(p + 3) | 0x20 == 0x74, b.u8(p + 4) == 0x3a {
                host = b.text(p + 5, le, max: 256).trimmingCharacters(in: .whitespaces)
                break
            }
            p = le
        }
        d.app = .httpRequest(method: String(parts[0]), path: String(parts[1]), host: host)
        d.protocolName = "HTTP"
        d.info = line
        return true
    }

    mutating func tls(_ s: Int, _ e: Int, onTLSPort: Bool) -> Bool {
        func validRecord(_ p: Int) -> Bool {
            let ct = b.u8(p)
            return (20...24).contains(ct) && b.u8(p + 1) == 3 && b.u8(p + 2) <= 4 && b.has(p, 5)
        }
        guard b.has(s, 5), validRecord(s) else {
            // The middle of a record that began in an earlier segment (Wireshark, per packet:
            // "Continuation Data").
            if onTLSPort {
                d.app = .tlsOther(recordType: "Continuation Data")
                d.protocolName = "TLS"
                d.info = "Continuation Data"
                return true
            }
            return false
        }
        if !onTLSPort {
            // By shape only: a handshake record with a real TLS version.
            guard b.u8(s) == 0x16, (1...4).contains(b.u8(s + 2)) else { return false }
        }
        var names: [String] = []
        var app: AppLayer?
        var p = s
        while p + 5 <= e, names.count < 12, validRecord(p) {
            let ct = b.u8(p)
            let len = Int(b.u16(p + 3))
            let body = p + 5
            let bodyEnd = min(body + len, e)
            var name: String
            switch ct {
            case 20: name = "Change Cipher Spec"
            case 21: name = "Alert"
            case 23: name = "Application Data"
            case 24: name = "Heartbeat"
            default:
                let hs = b.u8(body)
                let hsLen = b.u24(body + 1)
                let plausible = bodyEnd > body && hsLen + 4 <= len
                if !plausible {
                    name = "Encrypted Handshake Message"
                } else {
                    switch hs {
                    case 1:
                        let (sni, version) = clientHello(body, bodyEnd)
                        name = sni.map { "Client Hello (SNI=\($0))" } ?? "Client Hello"
                        if app == nil { app = .tlsClientHello(sni: sni, version: version) }
                    case 2:
                        let version = serverHello(body, bodyEnd)
                        name = "Server Hello"
                        if app == nil { app = .tlsServerHello(version: version) }
                    case 4: name = "New Session Ticket"
                    case 8: name = "Encrypted Extensions"
                    case 11: name = "Certificate"
                    case 12: name = "Server Key Exchange"
                    case 13: name = "Certificate Request"
                    case 14: name = "Server Hello Done"
                    case 15: name = "Certificate Verify"
                    case 16: name = "Client Key Exchange"
                    case 20: name = "Finished"
                    default: name = "Encrypted Handshake Message"
                    }
                }
            }
            if names.last != name { names.append(name) }
            p = body + len
        }
        guard !names.isEmpty else { return false }
        d.app = app ?? .tlsOther(recordType: names[0])
        d.protocolName = "TLS"
        d.info = names.joined(separator: ", ")
        return true
    }

    /// `h` = start of the handshake message (type byte).
    func clientHello(_ h: Int, _ e: Int) -> (String?, String) {
        var q = h + 4
        let legacy = b.u16(q)
        q += 2 + 32
        guard q < e else { return (nil, PacketNames.tlsVersion(legacy)) }
        q += 1 + Int(b.u8(q))
        guard q + 2 <= e else { return (nil, PacketNames.tlsVersion(legacy)) }
        q += 2 + Int(b.u16(q))
        guard q < e else { return (nil, PacketNames.tlsVersion(legacy)) }
        q += 1 + Int(b.u8(q))
        guard q + 2 <= e else { return (nil, PacketNames.tlsVersion(legacy)) }
        let extEnd = min(q + 2 + Int(b.u16(q)), e)
        q += 2
        var sni: String?
        var best: UInt16?
        var n = 0
        while q + 4 <= extEnd, n < 64 {
            n += 1
            let t = b.u16(q), l = Int(b.u16(q + 2))
            let v = q + 4
            if t == 0, b.has(v, 5), v + 5 <= extEnd, b.u8(v + 2) == 0 {
                let nameLen = Int(b.u16(v + 3))
                let name = b.text(v + 5, min(v + 5 + nameLen, extEnd), max: 255)
                if !name.isEmpty { sni = name }
            } else if t == 43, v < extEnd {
                let listLen = Int(b.u8(v))
                var i = v + 1
                while i + 2 <= min(v + 1 + listLen, extEnd) {
                    let ver = b.u16(i)
                    if ver & 0x0f0f != 0x0a0a, ver <= 0x0304, ver > (best ?? 0) { best = ver }
                    i += 2
                }
            }
            q = v + l
        }
        return (sni, PacketNames.tlsVersion(best ?? legacy))
    }

    func serverHello(_ h: Int, _ e: Int) -> String {
        var q = h + 4
        let legacy = b.u16(q)
        q += 2 + 32
        guard q < e else { return PacketNames.tlsVersion(legacy) }
        q += 1 + Int(b.u8(q))
        q += 3
        guard q + 2 <= e else { return PacketNames.tlsVersion(legacy) }
        let extEnd = min(q + 2 + Int(b.u16(q)), e)
        q += 2
        var n = 0
        while q + 4 <= extEnd, n < 64 {
            n += 1
            let t = b.u16(q), l = Int(b.u16(q + 2))
            if t == 43, l == 2, q + 6 <= extEnd { return PacketNames.tlsVersion(b.u16(q + 4)) }
            q += 4 + l
        }
        return PacketNames.tlsVersion(legacy)
    }

    mutating func ssh(_ s: Int, _ e: Int, payloadLength: Int) {
        d.protocolName = "SSH"
        if b.starts(s, Lits.ssh) {
            let le = b.lineEnd(s, min(e, s + 255))
            let banner = b.text(s, le, max: 255)
            d.app = .ssh(banner: banner)
            d.info = "Protocol (\(banner))"
            // Servers often send their KEXINIT in the same segment as the banner.
            var p = le
            while p < e, p < le + 2, b.u8(p) == 0x0d || b.u8(p) == 0x0a { p += 1 }
            if let name = sshMessage(p, e, bytes: e - p) { d.info += ", \(name)" }
            return
        }
        d.app = .ssh(banner: nil)
        if let name = sshMessage(s, e, bytes: payloadLength) { d.info = name; return }
        d.info = "Encrypted packet (len=\(payloadLength))"
    }

    /// A cleartext SSH binary packet (before NEWKEYS) at `p`: packet_length, padding_length,
    /// message code. A KEXINIT (≈1.5 KB) is often split over two segments, so the packet may
    /// run past this one (or several share it); the length must still be sane (RFC 4253: at
    /// most 35,000) and the padding 4…255 bytes and shorter than the packet.
    func sshMessage(_ p: Int, _ e: Int, bytes: Int) -> String? {
        guard b.has(p, 6), p + 6 <= e, bytes >= 6 else { return nil }
        let len = Int(b.u32(p)), pad = Int(b.u8(p + 4))
        guard len >= 12, len <= 35_000, pad >= 4, pad < len else { return nil }
        return switch b.u8(p + 5) {
        case 20: "Key Exchange Init"
        case 21: "New Keys"
        case 30: "Elliptic Curve Diffie-Hellman Key Exchange Init"
        case 31: "Elliptic Curve Diffie-Hellman Key Exchange Reply"
        default: nil
        }
    }

    mutating func bgp(_ s: Int, _ e: Int) -> Bool {
        guard b.has(s, 19) else { return false }
        for i in 0..<16 where b.u8(s + i) != 0xff { return false }
        var names: [String] = []
        var p = s
        while b.has(p, 19), names.count < 8 {
            let len = Int(b.u16(p + 16))
            guard len >= 19 else { break }
            let n = switch b.u8(p + 18) {
            case 1: "OPEN Message"
            case 2: "UPDATE Message"
            case 3: "NOTIFICATION Message"
            case 4: "KEEPALIVE Message"
            case 5: "ROUTE-REFRESH Message"
            default: "BGP type \(b.u8(p + 18))"
            }
            if names.last != n { names.append(n) }
            p += len
        }
        d.app = .other(name: "BGP")
        d.protocolName = "BGP"
        d.info = names.joined(separator: ", ")
        return true
    }

    // MARK: Application layer — UDP

    mutating func udpApp(_ sp: UInt16, _ dp: UInt16, _ s: Int, _ e: Int) {
        func either(_ p: UInt16) -> Bool { sp == p || dp == p }
        if either(53), dns(s, e, name: "DNS") { return }
        if either(5353), dns(s, e, name: "MDNS") { return }
        if either(5355), dns(s, e, name: "LLMNR") { return }
        if either(67) || either(68), dhcp(s, e) { return }
        if either(161) || either(162), snmp(s, e) { return }
        if either(514), syslog(s, e, tcp: false) { return }
        if PacketPorts.isRADIUS(sp) || PacketPorts.isRADIUS(dp), radius(s, e) { return }
        if either(123), ntp(s, e) { return }
        if either(546) || either(547), dhcpv6(s, e) { return }
        if either(443), quic(s, e) { return }
        if either(1900), b.has(s, 8) {
            d.app = .other(name: "SSDP")
            d.protocolName = "SSDP"
            d.info = b.text(s, b.lineEnd(s, min(e, s + 256)), max: 256)
            return
        }
    }

    mutating func dns(_ s: Int, _ e: Int, name: String) -> Bool {
        guard e - s >= 12, b.has(s, 12) else { return false }
        let id = b.u16(s), flags = b.u16(s + 2)
        let qd = Int(b.u16(s + 4)), an = Int(b.u16(s + 6))
        let qr = flags & 0x8000 != 0
        let opcode = Int((flags >> 11) & 0xF)
        let rcode = Int(flags & 0xF)
        guard qd <= 64, an <= 1024 else { return false }
        var q = s + 12
        var qname: String?
        var qtype: UInt16 = 0
        for i in 0..<qd {
            guard let (nm, next) = readName(q, base: s, end: e), next + 4 <= e else {
                if i == 0 { return false }
                break
            }
            if i == 0 { qname = nm; qtype = b.u16(next) }
            q = next + 4
        }
        // Every answer, in order, like Wireshark's Info ("CNAME x A 1.2.3.4 A 5.6.7.8"); a
        // round-robin or a CNAME chain is what the engineer is looking for.
        var answers: [String] = []
        var more = false
        if qr, an > 0 {
            var i = 0
            while i < min(an, 32) {
                i += 1
                guard let (_, next) = readName(q, base: s, end: e), next + 10 <= e else { break }
                let t = b.u16(next)
                let rdlen = Int(b.u16(next + 8))
                let rd = next + 10
                guard rd + rdlen <= e else { break }
                q = rd + rdlen
                if answers.count == 8 { more = true; break }
                switch t {
                case 1 where rdlen == 4: answers.append("A " + PacketFormat.ipv4(b, rd))
                case 28 where rdlen == 16: answers.append("AAAA " + PacketFormat.ipv6(b, rd))
                case 2, 5, 12:
                    if let (n, _) = readName(rd, base: s, end: rd + rdlen) {
                        answers.append("\(PacketNames.dnsType(t)) \(n)")
                    }
                case 15 where rdlen > 2:
                    if let (n, _) = readName(rd + 2, base: s, end: rd + rdlen) { answers.append("MX \(b.u16(rd)) \(n)") }
                case 41: break      // EDNS OPT (additional section only)
                default: answers.append(PacketNames.dnsType(t))
                }
            }
            if an > 32 { more = true }
        }
        var answer: String? = answers.isEmpty ? nil : answers.joined(separator: " ")
        if more, let a = answer { answer = a + " …" }
        d.app = .dns(query: qname, isResponse: qr, answers: an, rcode: rcode)
        d.protocolName = name
        let op = switch opcode {
        case 0: "Standard query"
        case 1: "Inverse query"
        case 2: "Server status request"
        case 4: "Zone change notification"
        case 5: "Dynamic update"
        default: "Opcode \(opcode)"
        }
        var s2 = op + (qr ? " response " : " ") + PacketFormat.hex4(id)
        if qr, rcode != 0 { s2 += " " + PacketNames.dnsRcode(rcode) }
        if let qname { s2 += " \(PacketNames.dnsType(qtype)) \(qname)" }
        if let answer { s2 += " \(answer)" }
        d.info = s2
        return true
    }

    /// A DNS name at `q` (with compression pointers relative to `base`). Returns the name and the
    /// offset just after it in the original position.
    func readName(_ q: Int, base: Int, end: Int) -> (String, Int)? {
        var out: [UInt8] = []
        var p = q
        var after: Int?
        var jumps = 0
        while true {
            guard p < end, b.has(p, 1) else { return nil }
            let len = Int(b.u8(p))
            if len == 0 {
                if after == nil { after = p + 1 }
                break
            }
            if len & 0xC0 == 0xC0 {
                guard p + 1 < end else { return nil }
                let ptr = base + ((len & 0x3F) << 8 | Int(b.u8(p + 1)))
                if after == nil { after = p + 2 }
                jumps += 1
                guard jumps <= 16, ptr < end, ptr >= base else { return nil }
                p = ptr
                continue
            }
            guard len & 0xC0 == 0, p + 1 + len <= end, b.has(p + 1, len) else { return nil }
            if !out.isEmpty { out.append(0x2e) }
            for i in 0..<len {
                let c = b.p[p + 1 + i]
                out.append(c < 0x20 || c == 0x7f ? 0x3f : c)
            }
            guard out.count <= 255 else { return nil }
            p += 1 + len
        }
        let name = out.isEmpty ? "<Root>" : String(decoding: out, as: UTF8.self)
        return (name, after ?? p + 1)
    }

    mutating func dhcp(_ s: Int, _ e: Int) -> Bool {
        guard e - s >= 240, b.has(s, 240), b.u32(s + 236) == 0x63825363 else { return false }
        let op = b.u8(s), hlen = b.u8(s + 2)
        let xid = b.u32(s + 4)
        let yi = PacketFormat.ipv4(b, s + 16)
        let chaddr = hlen == 6 ? PacketFormat.mac(b, s + 28) : nil
        var mt: UInt8?
        var hostName: String?
        var p = s + 240
        var n = 0
        while p < e, n < 128 {
            n += 1
            let code = b.u8(p)
            if code == 0 { p += 1; continue }
            if code == 255 { break }
            guard p + 1 < e else { break }
            let len = Int(b.u8(p + 1))
            guard p + 2 + len <= e else { break }
            if code == 53, len >= 1 { mt = b.u8(p + 2) }
            if code == 12, len >= 1 { hostName = b.text(p + 2, p + 2 + len, max: 64) }
            p += 2 + len
        }
        let typeName: String
        if let mt {
            typeName = switch mt {
            case 1: "Discover"
            case 2: "Offer"
            case 3: "Request"
            case 4: "Decline"
            case 5: "ACK"
            case 6: "NAK"
            case 7: "Release"
            case 8: "Inform"
            default: "Type \(mt)"
            }
        } else {
            typeName = op == 1 ? "BOOTP Request" : "BOOTP Reply"
        }
        d.app = .dhcp(messageType: typeName, clientMAC: chaddr, yourIP: yi == "0.0.0.0" ? nil : yi)
        d.protocolName = "DHCP"
        var info = "DHCP \(typeName) - Transaction ID \(PacketFormat.hex8(xid))"
        if yi != "0.0.0.0" { info += " yiaddr \(yi)" }
        if let hostName { info += " (\(hostName))" }
        d.info = info
        return true
    }

    mutating func dhcpv6(_ s: Int, _ e: Int) -> Bool {
        guard b.has(s, 4) else { return false }
        let t = b.u8(s)
        let name: String
        switch t {
        case 1: name = "Solicit"
        case 2: name = "Advertise"
        case 3: name = "Request"
        case 4: name = "Confirm"
        case 5: name = "Renew"
        case 6: name = "Rebind"
        case 7: name = "Reply"
        case 8: name = "Release"
        case 9: name = "Decline"
        case 10: name = "Reconfigure"
        case 11: name = "Information-request"
        case 12: name = "Relay-forw"
        case 13: name = "Relay-reply"
        default: return false
        }
        d.app = .other(name: "DHCPv6")
        d.protocolName = "DHCPv6"
        d.info = t >= 12 ? name : "\(name) XID: \(PacketFormat.hex(UInt64(b.u24(s + 1)), digits: 6))"
        return true
    }

    mutating func quic(_ s: Int, _ e: Int) -> Bool {
        guard b.has(s, 1) else { return false }
        let b0 = b.u8(s)
        guard b0 & 0x40 != 0 else { return false }
        let what: String
        if b0 & 0x80 != 0 {
            guard b.has(s, 5) else { return false }
            if b.u32(s + 1) == 0 {
                what = "Version Negotiation"
            } else {
                what = switch (b0 >> 4) & 3 { case 0: "Initial"; case 1: "0-RTT"; case 2: "Handshake"; default: "Retry" }
            }
        } else {
            what = "Protected Payload"
        }
        d.app = .other(name: "QUIC")
        d.protocolName = "QUIC"
        d.info = what
        return true
    }

    mutating func syslog(_ s: Int, _ e: Int, tcp: Bool) -> Bool {
        var p = s
        if tcp {
            // octet-counting: "123 <PRI>…"
            var q = p
            while q < min(e, p + 6), b.u8(q) >= 0x30, b.u8(q) <= 0x39 { q += 1 }
            if q > p, b.u8(q) == 0x20 { p = q + 1 }
        }
        guard p < e else { return false }
        var pri: Int?
        if b.u8(p) == 0x3c {
            var q = p + 1, v = 0, digits = 0
            while q < e, digits < 3, b.u8(q) >= 0x30, b.u8(q) <= 0x39 {
                v = v * 10 + Int(b.u8(q) - 0x30); q += 1; digits += 1
            }
            if digits > 0, b.u8(q) == 0x3e, v <= 191 { pri = v; p = q + 1 }
        }
        if tcp, pri == nil { return false }
        let preview = b.text(p, b.lineEnd(p, min(e, p + 240)), max: 240)
            .trimmingCharacters(in: .whitespaces)
        // Wireshark shows the whole message; the Info column truncates to its width anyway,
        // and the 60 characters kept before cut most messages before the part that matters.
        let short = preview.count > 200 ? String(preview.prefix(200)) + "…" : preview
        d.app = .syslog(priority: pri, preview: short)
        d.protocolName = "Syslog"
        if let pri {
            let fac = pri >> 3, sev = pri & 7
            let fname = fac < PacketNames.syslogFacilities.count ? PacketNames.syslogFacilities[fac] : "FAC\(fac)"
            d.info = "\(fname).\(PacketNames.syslogSeverities[sev]): \(short)"
        } else {
            d.info = short
        }
        return true
    }

    mutating func radius(_ s: Int, _ e: Int) -> Bool {
        guard e - s >= 20, b.has(s, 20), let name = PacketNames.radiusCode(b.u8(s)) else { return false }
        let id = b.u8(s + 1)
        let len = Int(b.u16(s + 2))
        guard len >= 20 else { return false }
        var user: String?
        var p = s + 20
        let end = min(e, s + len)
        var n = 0
        while p + 2 <= end, n < 128 {
            n += 1
            let t = b.u8(p), l = Int(b.u8(p + 1))
            guard l >= 2, p + l <= end else { break }
            if t == 1 { user = b.text(p + 2, p + l, max: 128) }
            p += l
        }
        d.app = .radius(code: name, id: id)
        d.protocolName = "RADIUS"
        d.info = "\(name) id=\(id)" + (user.map { " User-Name=\($0)" } ?? "")
        return true
    }

    mutating func ntp(_ s: Int, _ e: Int) -> Bool {
        guard e - s >= 48, b.has(s, 48) else { return false }
        let b0 = b.u8(s)
        let vn = (b0 >> 3) & 7, mode = b0 & 7
        guard vn >= 1, vn <= 4 else { return false }
        let modeName = switch mode {
        case 1: "symmetric active"
        case 2: "symmetric passive"
        case 3: "client"
        case 4: "server"
        case 5: "broadcast"
        case 6: "control"
        case 7: "private"
        default: "reserved"
        }
        d.app = .ntp
        d.protocolName = "NTP"
        d.info = "NTP Version \(vn), \(modeName)" + (mode == 4 ? ", stratum \(b.u8(s + 1))" : "")
        return true
    }

    // MARK: SNMP (just enough BER)

    struct TLV { let tag: UInt8; let start: Int; let end: Int }

    func tlv(_ p: Int, _ limit: Int) -> TLV? {
        guard p + 2 <= limit, b.has(p, 2) else { return nil }
        let tag = b.u8(p)
        var len = Int(b.u8(p + 1))
        var q = p + 2
        if len & 0x80 != 0 {
            let n = len & 0x7F
            guard n >= 1, n <= 4, q + n <= limit else { return nil }
            len = 0
            for i in 0..<n { len = len << 8 | Int(b.u8(q + i)) }
            q += n
        }
        guard len >= 0, q + len <= limit else { return nil }
        return TLV(tag: tag, start: q, end: q + len)
    }

    func berInt(_ t: TLV) -> Int {
        var v = 0
        for i in t.start..<min(t.end, t.start + 8) { v = v << 8 | Int(b.u8(i)) }
        return v
    }

    func oid(_ t: TLV) -> String {
        guard t.end > t.start else { return "" }
        var parts: [String] = []
        let first = Int(b.u8(t.start))
        let x = min(first / 40, 2)
        parts.append("\(x)")
        parts.append("\(first - x * 40)")
        var v = 0
        var i = t.start + 1
        while i < t.end, parts.count < 64 {
            let c = b.u8(i)
            v = v << 7 | Int(c & 0x7F)
            if c & 0x80 == 0 { parts.append("\(v)"); v = 0 }
            i += 1
        }
        return parts.joined(separator: ".")
    }

    mutating func snmp(_ s: Int, _ e: Int) -> Bool {
        guard let top = tlv(s, e), top.tag == 0x30,
              let ver = tlv(top.start, top.end), ver.tag == 0x02 else { return false }
        let version = berInt(ver)
        var community: String?
        var pduType = "?"
        var detail = ""
        let versionName: String
        switch version {
        case 0, 1:
            versionName = version == 0 ? "v1" : "v2c"
            guard let c = tlv(ver.end, top.end), c.tag == 0x04,
                  let pdu = tlv(c.end, top.end), let name = PacketNames.snmpPDU(pdu.tag) else { return false }
            community = b.text(c.start, c.end, max: 128)
            pduType = name
            detail = pduDetail(pdu)
        case 3:
            versionName = "v3"
            guard let global = tlv(ver.end, top.end), global.tag == 0x30,
                  let sec = tlv(global.end, top.end), sec.tag == 0x04,
                  let data = tlv(sec.end, top.end) else { return false }
            if let usm = tlv(sec.start, sec.end), usm.tag == 0x30, let eng = tlv(usm.start, usm.end),
               let boots = tlv(eng.end, usm.end), let time = tlv(boots.end, usm.end),
               let user = tlv(time.end, usm.end), user.tag == 0x04, user.end > user.start {
                detail = " user=\(b.text(user.start, user.end, max: 64))"
            }
            if data.tag == 0x04 {
                pduType = "encryptedPDU"
            } else if data.tag == 0x30, let ctxEngine = tlv(data.start, data.end), let ctxName = tlv(ctxEngine.end, data.end),
                      let pdu = tlv(ctxName.end, data.end), let name = PacketNames.snmpPDU(pdu.tag) {
                pduType = name
                detail = pduDetail(pdu) + detail
            }
        default:
            return false
        }
        d.app = .snmp(version: versionName, community: community, pduType: pduType)
        d.protocolName = "SNMP"
        d.info = pduType + detail
        return true
    }

    /// What the PDU is about: the first varbind's OID (a report names its usmStats counter),
    /// a v2 trap / inform's snmpTrapOID.0 value (its first varbind is always sysUpTime.0, which
    /// says nothing), a v1 trap's enterprise and generic trap, and a non-zero error-status.
    func pduDetail(_ pdu: TLV) -> String {
        if pdu.tag == 0xA4 {
            guard let ent = tlv(pdu.start, pdu.end), ent.tag == 0x06 else { return "" }
            var s = " " + oid(ent)
            if let agent = tlv(ent.end, pdu.end), let generic = tlv(agent.end, pdu.end), generic.tag == 0x02 {
                let g = berInt(generic)
                let names = ["coldStart", "warmStart", "linkDown", "linkUp", "authenticationFailure", "egpNeighborLoss"]
                if g >= 0, g < names.count { s += " " + names[g] }
                else if let specific = tlv(generic.end, pdu.end), specific.tag == 0x02 {
                    s += " enterpriseSpecific \(berInt(specific))"
                }
            }
            return s
        }
        guard let rid = tlv(pdu.start, pdu.end), let es = tlv(rid.end, pdu.end),
              let ei = tlv(es.end, pdu.end), let list = tlv(ei.end, pdu.end), list.tag == 0x30 else { return "" }
        var s = ""
        var first: String?
        var p = list.start
        var n = 0
        while n < 16, let vb = tlv(p, list.end), vb.tag == 0x30 {
            n += 1
            p = vb.end
            guard let name = tlv(vb.start, vb.end), name.tag == 0x06 else { continue }
            let o = oid(name)
            if first == nil { first = o }
            if pdu.tag == 0xA7 || pdu.tag == 0xA6, o == "1.3.6.1.6.3.1.1.4.1.0",
               let value = tlv(name.end, vb.end), value.tag == 0x06 {
                let trap = oid(value)
                let standard = ["1.3.6.1.6.3.1.1.5.1": "coldStart", "1.3.6.1.6.3.1.1.5.2": "warmStart",
                                "1.3.6.1.6.3.1.1.5.3": "linkDown", "1.3.6.1.6.3.1.1.5.4": "linkUp",
                                "1.3.6.1.6.3.1.1.5.5": "authenticationFailure"][trap]
                s = " " + trap + (standard.map { " (\($0))" } ?? "")
                break
            }
        }
        if s.isEmpty, let first { s = " " + first }
        // A GetBulk's second integer is non-repeaters, not an error-status.
        let err = berInt(es)
        if err != 0, pdu.tag != 0xA5 {
            let names = ["noError", "tooBig", "noSuchName", "badValue", "readOnly", "genErr", "noAccess", "wrongType",
                         "wrongLength", "wrongEncoding", "wrongValue", "noCreation", "inconsistentValue",
                         "resourceUnavailable", "commitFailed", "undoFailed", "authorizationError", "notWritable",
                         "inconsistentName"]
            s += " error-status=" + (err > 0 && err < names.count ? "\(names[err]) (\(err))" : "\(err)")
        }
        return s
    }
}
