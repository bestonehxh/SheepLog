import Foundation
import XCTest
@testable import SheepLog

// MARK: - Byte builders

/// Builds authentication traffic as real Ethernet frames: EAPOL (EAP, EAPOL-Key), IPv4/UDP RADIUS
/// with correct lengths and a fake Message-Authenticator, DHCP, DNS and HTTP over TCP. Every frame
/// goes through `PacketDecoder`, so the tests see what a capture file gives the pane.
struct AuthLab {
    static let ap: [UInt8] = [0x00, 0x0b, 0x86, 0x10, 0x20, 0x30]        // AP / switch port (authenticator)
    static let nasUplink: [UInt8] = [0x00, 0x0b, 0x86, 0x10, 0x20, 0x31]
    static let serverMAC: [UInt8] = [0x00, 0x50, 0x56, 0x0a, 0x00, 0x0a]
    static let gatewayMAC: [UInt8] = [0x00, 0x0b, 0x86, 0x10, 0x20, 0x01]
    static let pae: [UInt8] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x03]
    static let broadcast: [UInt8] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    static let nasIP = "10.0.0.2"
    static let serverIP = "10.0.0.10"

    var base = 1_758_000_000.0
    var t = 0.0
    var client: [UInt8] = [0x02, 0, 0, 0, 0, 0x01]
    var packets: [Packet] = []
    var radiusID: UInt8 = 0
    var eapID: UInt8 = 0
    var authCounter: UInt8 = 0
    var ipID: UInt16 = 0x100
    /// The AP / switch port its EAPOL frames go to and come from.
    var authenticator: [UInt8] = AuthLab.ap

    init(client: [UInt8], at start: Double = 0, base: Double = 1_758_000_000.0) {
        self.client = client
        self.t = start
        self.base = base
    }

    static func be16(_ v: Int) -> [UInt8] { [UInt8((v >> 8) & 0xff), UInt8(v & 0xff)] }
    static func be32(_ v: UInt32) -> [UInt8] { [UInt8(v >> 24), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)] }
    static func ip4(_ s: String) -> [UInt8] { s.split(separator: ".").map { UInt8($0)! } }
    static func macText(_ m: [UInt8], _ sep: String = ":", upper: Bool = false) -> String {
        m.map { String(format: upper ? "%02X" : "%02x", $0) }.joined(separator: sep)
    }

    var clientText: String { Self.macText(client) }

    // MARK: Frames

    mutating func add(_ bytes: [UInt8], dt: Double) {
        t += dt
        var f = bytes
        while f.count < 60 { f.append(0) }
        let data = Data(f)
        packets.append(Packet(id: packets.count + 1, timestamp: Date(timeIntervalSince1970: base + t), relative: t,
                              length: data.count, captured: data.count, data: data, decoded: PacketDecoder.decode(data)))
    }

    static func ether(dst: [UInt8], src: [UInt8], type: Int, _ payload: [UInt8]) -> [UInt8] {
        dst + src + be16(type) + payload
    }

    static func ipv4(src: String, dst: String, proto: UInt8, id: UInt16, _ payload: [UInt8]) -> [UInt8] {
        var h: [UInt8] = [0x45, 0] + be16(20 + payload.count) + be16(Int(id)) + [0x40, 0x00, 64, proto, 0, 0] + ip4(src) + ip4(dst)
        var sum: UInt32 = 0
        for i in stride(from: 0, to: 20, by: 2) { sum += UInt32(h[i]) << 8 | UInt32(h[i + 1]) }
        while sum > 0xffff { sum = (sum & 0xffff) + (sum >> 16) }
        let c = ~UInt16(sum)
        h[10] = UInt8(c >> 8); h[11] = UInt8(c & 0xff)
        return h + payload
    }

    static func udp(_ sp: Int, _ dp: Int, _ payload: [UInt8]) -> [UInt8] {
        be16(sp) + be16(dp) + be16(8 + payload.count) + [0, 0] + payload
    }

    static func tcp(_ sp: Int, _ dp: Int, seq: UInt32, _ payload: [UInt8]) -> [UInt8] {
        be16(sp) + be16(dp) + be32(seq) + be32(1) + [0x50, 0x18] + be16(65535) + [0, 0, 0, 0] + payload
    }

    mutating func udpFrame(srcMAC: [UInt8], dstMAC: [UInt8], src: String, dst: String, sp: Int, dp: Int,
                           _ payload: [UInt8], dt: Double) {
        ipID &+= 1
        add(Self.ether(dst: dstMAC, src: srcMAC, type: 0x0800,
                       Self.ipv4(src: src, dst: dst, proto: 17, id: ipID, Self.udp(sp, dp, payload))), dt: dt)
    }

    mutating func tcpFrame(srcMAC: [UInt8], dstMAC: [UInt8], src: String, dst: String, sp: Int, dp: Int,
                           _ payload: [UInt8], dt: Double) {
        ipID &+= 1
        add(Self.ether(dst: dstMAC, src: srcMAC, type: 0x0800,
                       Self.ipv4(src: src, dst: dst, proto: 6, id: ipID, Self.tcp(sp, dp, seq: 1000, payload))), dt: dt)
    }

    // MARK: EAPOL

    mutating func eapol(fromClient: Bool, type: UInt8, _ body: [UInt8], toGroup: Bool = false, dt: Double = 0.004) {
        let dst = fromClient ? (toGroup ? Self.pae : authenticator) : client
        let src = fromClient ? client : authenticator
        add(Self.ether(dst: dst, src: src, type: 0x888E, [2, type] + Self.be16(body.count) + body), dt: dt)
    }

    static func eap(code: UInt8, id: UInt8, type: UInt8? = nil, _ data: [UInt8] = []) -> [UInt8] {
        let payload = (type.map { [$0] } ?? []) + data
        return [code, id] + be16(4 + payload.count) + payload
    }

    /// A TLS-method data field: flags (L / M / S) and the optional TLS length.
    static func tlsData(start: Bool = false, more: Bool = false, length: Int? = nil, bytes: Int = 0) -> [UInt8] {
        var flags: UInt8 = 0
        if length != nil { flags |= 0x80 }
        if more { flags |= 0x40 }
        if start { flags |= 0x20 }
        var out = [flags]
        if let length { out += be32(UInt32(length)) }
        out += [UInt8](repeating: 0x16, count: bytes)
        return out
    }

    mutating func eapToClient(code: UInt8, type: UInt8? = nil, _ data: [UInt8] = [], newID: Bool = true, dt: Double = 0.004) {
        if newID { eapID &+= 1 }
        eapol(fromClient: false, type: 0, Self.eap(code: code, id: eapID, type: type, data), dt: dt)
    }

    mutating func eapFromClient(type: UInt8, _ data: [UInt8], dt: Double = 0.004) {
        eapol(fromClient: true, type: 0, Self.eap(code: 2, id: eapID, type: type, data), dt: dt)
    }

    /// EAPOL-Key message `m` (1…4) of an RSN 4-way handshake.
    static func key(_ m: Int, replay: UInt64) -> [UInt8] {
        let info: Int
        var nonce = [UInt8](repeating: 0, count: 32)
        var mic = [UInt8](repeating: 0, count: 16)
        var data: [UInt8] = []
        switch m {
        case 1: info = 0x008A; nonce = [UInt8](repeating: 0xA1, count: 32); data = [UInt8](repeating: 0xdd, count: 22)
        case 2: info = 0x010A; nonce = [UInt8](repeating: 0xB2, count: 32); mic = [UInt8](repeating: 0x4d, count: 16); data = [UInt8](repeating: 0x30, count: 22)
        case 3: info = 0x13CA; nonce = [UInt8](repeating: 0xA1, count: 32); mic = [UInt8](repeating: 0x4e, count: 16); data = [UInt8](repeating: 0xee, count: 56)
        default: info = 0x030A; mic = [UInt8](repeating: 0x4f, count: 16)
        }
        var r: [UInt8] = []
        for s in stride(from: 56, through: 0, by: -8) { r.append(UInt8((replay >> UInt64(s)) & 0xff)) }
        return [2] + be16(info) + be16(16) + r + nonce + [UInt8](repeating: 0, count: 16 + 8 + 8) + mic + be16(data.count) + data
    }

    mutating func fourWay(upTo last: Int = 4, replay: UInt64 = 1, dt: Double = 0.006) {
        for m in 1...last { eapol(fromClient: m % 2 == 0, type: 3, Self.key(m, replay: replay + UInt64(m >= 3 ? 1 : 0)), dt: dt) }
    }

    // MARK: RADIUS

    static func attr(_ t: UInt8, _ v: [UInt8]) -> [UInt8] { [t, UInt8(v.count + 2)] + v }
    static func text(_ t: UInt8, _ s: String) -> [UInt8] { attr(t, Array(s.utf8)) }
    static func int(_ t: UInt8, _ v: UInt32) -> [UInt8] { attr(t, be32(v)) }
    static func vsa(_ vendor: UInt32, _ type: UInt8, _ v: [UInt8]) -> [UInt8] { attr(26, be32(vendor) + [type, UInt8(v.count + 2)] + v) }
    static let fakeMessageAuthenticator = attr(80, [UInt8](repeating: 0xA5, count: 16))

    /// EAP-Message attributes (≤ 253 bytes each) for `eap`.
    static func eapMessage(_ eap: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        var i = 0
        while i < eap.count {
            let n = min(253, eap.count - i)
            out += attr(79, Array(eap[i..<(i + n)]))
            i += n
        }
        return out
    }

    static func radius(code: UInt8, id: UInt8, auth: [UInt8], _ attrs: [[UInt8]]) -> [UInt8] {
        let body = attrs.flatMap { $0 }
        return [code, id] + be16(20 + body.count) + auth + body
    }

    /// Access-Request (or Accounting-Request) NAS → server; returns (id, authenticator) for a retransmission.
    @discardableResult
    mutating func toServer(code: UInt8 = 1, _ attrs: [[UInt8]], id: UInt8? = nil, auth: [UInt8]? = nil, dt: Double = 0.002) -> (UInt8, [UInt8]) {
        let rid: UInt8
        if let id { rid = id } else { radiusID &+= 1; rid = radiusID }
        authCounter &+= 1
        let a = auth ?? [UInt8](repeating: authCounter, count: 15) + [rid]
        let port = code == 4 ? 1813 : 1812
        udpFrame(srcMAC: Self.nasUplink, dstMAC: Self.serverMAC, src: Self.nasIP, dst: Self.serverIP, sp: 50_000, dp: port,
                 Self.radius(code: code, id: rid, auth: a, attrs + [Self.fakeMessageAuthenticator]), dt: dt)
        return (rid, a)
    }

    mutating func toNAS(code: UInt8, _ attrs: [[UInt8]], id: UInt8? = nil, dt: Double = 0.012) {
        let port = code == 5 ? 1813 : 1812
        udpFrame(srcMAC: Self.serverMAC, dstMAC: Self.nasUplink, src: Self.serverIP, dst: Self.nasIP, sp: port, dp: 50_000,
                 Self.radius(code: code, id: id ?? radiusID, auth: [UInt8](repeating: 0x5a, count: 16), attrs + [Self.fakeMessageAuthenticator]), dt: dt)
    }

    func common(user: String, callingStation: String? = nil) -> [[UInt8]] {
        [Self.text(1, user), Self.attr(4, Self.ip4(Self.nasIP)), Self.int(5, 1),
         Self.text(30, Self.macText(Self.ap, "-", upper: true) + ":Corp-WiFi"),
         Self.text(31, callingStation ?? Self.macText(client, "-", upper: true)), Self.text(32, "aruba-ctrl-01"),
         Self.int(61, 19), Self.text(87, "ap-2F-east")]
    }

    // MARK: DHCP, DNS, HTTP

    static func dhcp(op: UInt8, type: UInt8, chaddr: [UInt8], yiaddr: String = "0.0.0.0", xid: UInt32 = 0x3903F326) -> [UInt8] {
        var b: [UInt8] = [op, 1, 6, 0] + be32(xid) + [0, 0, 0x80, 0] + ip4("0.0.0.0") + ip4(yiaddr) + ip4("0.0.0.0") + ip4("0.0.0.0")
        b += chaddr + [UInt8](repeating: 0, count: 10) + [UInt8](repeating: 0, count: 192)
        b += [0x63, 0x82, 0x53, 0x63, 53, 1, type, 255]
        return b
    }

    mutating func dhcpExchange(ip: String, server: String = "10.20.0.1", dt: Double = 0.03, offer: Bool = true) {
        udpFrame(srcMAC: client, dstMAC: Self.broadcast, src: "0.0.0.0", dst: "255.255.255.255", sp: 68, dp: 67,
                 Self.dhcp(op: 1, type: 1, chaddr: client), dt: dt)
        guard offer else { return }
        udpFrame(srcMAC: Self.gatewayMAC, dstMAC: client, src: server, dst: ip, sp: 67, dp: 68,
                 Self.dhcp(op: 2, type: 2, chaddr: client, yiaddr: ip), dt: dt)
        udpFrame(srcMAC: client, dstMAC: Self.broadcast, src: "0.0.0.0", dst: "255.255.255.255", sp: 68, dp: 67,
                 Self.dhcp(op: 1, type: 3, chaddr: client), dt: dt)
        udpFrame(srcMAC: Self.gatewayMAC, dstMAC: client, src: server, dst: ip, sp: 67, dp: 68,
                 Self.dhcp(op: 2, type: 5, chaddr: client, yiaddr: ip), dt: dt)
    }

    static func dnsName(_ name: String) -> [UInt8] {
        var out: [UInt8] = []
        for label in name.split(separator: ".") { out.append(UInt8(label.utf8.count)); out += Array(label.utf8) }
        return out + [0]
    }

    mutating func dnsAnswer(_ name: String, clientIP: String, address: String, dt: Double = 0.02) {
        let q = Self.be16(0x1a2b) + [0x01, 0x00] + Self.be16(1) + Self.be16(0) + Self.be16(0) + Self.be16(0) + Self.dnsName(name) + Self.be16(1) + Self.be16(1)
        udpFrame(srcMAC: client, dstMAC: Self.gatewayMAC, src: clientIP, dst: "10.20.0.1", sp: 53_001, dp: 53, q, dt: dt)
        let r = Self.be16(0x1a2b) + [0x81, 0x80] + Self.be16(1) + Self.be16(1) + Self.be16(0) + Self.be16(0) + Self.dnsName(name)
            + Self.be16(1) + Self.be16(1) + [0xc0, 0x0c] + Self.be16(1) + Self.be16(1) + Self.be32(300) + Self.be16(4) + Self.ip4(address)
        udpFrame(srcMAC: Self.gatewayMAC, dstMAC: client, src: "10.20.0.1", dst: clientIP, sp: 53, dp: 53_001, r, dt: dt)
    }

    mutating func http(clientIP: String, serverIP: String, port: Int, request: String, response: String, dt: Double = 0.03) {
        tcpFrame(srcMAC: client, dstMAC: Self.gatewayMAC, src: clientIP, dst: serverIP, sp: port, dp: 80, Array(request.utf8), dt: dt)
        tcpFrame(srcMAC: Self.gatewayMAC, dstMAC: client, src: serverIP, dst: clientIP, sp: 80, dp: port, Array(response.utf8), dt: dt)
    }
}

// MARK: - Scenarios

/// The synthetic attempts: each builds one client's traffic from `start` seconds.
enum AuthScenario: String, CaseIterable {
    case peapSuccess = "peap-success"
    case eapTLSReject = "eap-tls-reject"
    case macAuthAccept = "mac-auth-accept"
    case macThenDot1x = "mac-then-dot1x"
    case pskSuccess = "psk-success"
    case pskWrong = "psk-wrong"
    case radiusTimeout = "radius-timeout"
    case captivePortal = "captive-portal"
    case wiredSideOnly = "radius-wired-side"
    case callingStationSpellings = "calling-station-spellings"
    case eapFragmented = "eap-message-fragmented"

    var client: [UInt8] { [0x02, 0x5e, 0x10, 0x00, 0x00, UInt8(Self.allCases.firstIndex(of: self)! + 1)] }
    var clientText: String { AuthLab.macText(client) }

    func build(start: Double = 0) -> [Packet] {
        var lab = AuthLab(client: client, at: start)
        switch self {
        case .peapSuccess: lab.peap(user: "alice@corp.example", succeed: true, rounds: 4, ip: "10.20.0.15")
        case .eapTLSReject: lab.eapTLSReject()
        case .macAuthAccept: lab.macAuth(accept: true, withDHCP: true)
        case .macThenDot1x:
            lab.macAuth(accept: false, withDHCP: false)
            lab.t += 1.5
            lab.peap(user: "bob@corp.example", succeed: true, rounds: 3, ip: "10.20.0.16")
        case .pskSuccess:
            lab.fourWay()
            lab.dhcpExchange(ip: "192.168.1.44", server: "192.168.1.1")
        case .pskWrong:
            for _ in 0..<4 { lab.eapol(fromClient: false, type: 3, AuthLab.key(1, replay: 1), dt: 1.0) }
        case .radiusTimeout:
            var attrs = lab.common(user: "carol@corp.example")
            attrs.append(AuthLab.eapMessage(AuthLab.eap(code: 2, id: 1, type: 1, Array("carol@corp.example".utf8))))
            let (id, auth) = lab.toServer(attrs)
            lab.toServer(attrs, id: id, auth: auth, dt: 5)
            lab.toServer(attrs, id: id, auth: auth, dt: 5)
        case .captivePortal: lab.captive()
        case .wiredSideOnly: lab.peapRADIUSOnly()
        case .callingStationSpellings:
            let spellings = [AuthLab.macText(client, "-", upper: true), "025e.1000.000a", AuthLab.macText(client, "", upper: true)]
            for (i, s) in spellings.enumerated() {
                lab.toServer(lab.common(user: AuthLab.macText(client, ""), callingStation: s) + [AuthLab.text(2, "secret")], dt: i == 0 ? 0 : 70)
                lab.toNAS(code: 2, [AuthLab.int(64, 13), AuthLab.int(65, 6), AuthLab.text(81, "30")])
            }
        case .eapFragmented:
            let identity = AuthLab.eap(code: 2, id: 1, type: 1, Array("dave@corp.example".utf8))
            lab.toServer(lab.common(user: "dave@corp.example") + [AuthLab.eapMessage(identity)])
            lab.toNAS(code: 11, [AuthLab.eapMessage(AuthLab.eap(code: 1, id: 2, type: 25, AuthLab.tlsData(start: true)))])
            let big = AuthLab.eap(code: 2, id: 2, type: 25, AuthLab.tlsData(length: 700, bytes: 600))
            lab.toServer(lab.common(user: "dave@corp.example") + [AuthLab.eapMessage(big)])
            lab.toNAS(code: 3, [AuthLab.eapMessage(AuthLab.eap(code: 4, id: 3)), AuthLab.text(18, "Login incorrect")])
        }
        return lab.packets
    }

    /// Every scenario in one capture, two minutes apart, frames renumbered.
    static func combined() -> [Packet] {
        var all: [Packet] = []
        for (i, s) in allCases.enumerated() {
            for p in s.build(start: Double(i) * 180) {
                all.append(Packet(id: all.count + 1, timestamp: p.timestamp, relative: p.relative, length: p.length,
                                  captured: p.captured, data: p.data, decoded: p.decoded))
            }
        }
        return all
    }
}

extension AuthLab {
    /// EAPOL-Start → Identity → PEAP start → `rounds` TLS rounds → Accept + EAP-Success → 4-way → DHCP → DNS.
    mutating func peap(user: String, succeed: Bool, rounds: Int, ip: String) {
        eapol(fromClient: true, type: 1, [], toGroup: true)
        eapToClient(code: 1, type: 1, dt: 0.003)
        eapFromClient(type: 1, Array(user.utf8))
        let base = common(user: user)
        toServer(base + [AuthLab.eapMessage(AuthLab.eap(code: 2, id: eapID, type: 1, Array(user.utf8)))])
        eapID &+= 1
        toNAS(code: 11, [AuthLab.eapMessage(AuthLab.eap(code: 1, id: eapID, type: 25, AuthLab.tlsData(start: true))), AuthLab.attr(24, [1, 2, 3, 4])])
        eapToClient(code: 1, type: 25, AuthLab.tlsData(start: true), newID: false)
        for r in 0..<rounds {
            let resp = AuthLab.tlsData(length: r == 0 ? 180 : nil, bytes: r == 0 ? 180 : 60)
            eapFromClient(type: 25, resp, dt: 0.01)
            toServer(base + [AuthLab.eapMessage(AuthLab.eap(code: 2, id: eapID, type: 25, resp)), AuthLab.attr(24, [1, 2, 3, 4])])
            eapID &+= 1
            let req = AuthLab.tlsData(more: r == 0, length: r == 0 ? 2800 : nil, bytes: r == 0 ? 1000 : 80)
            toNAS(code: 11, [AuthLab.eapMessage(AuthLab.eap(code: 1, id: eapID, type: 25, req)), AuthLab.attr(24, [1, 2, 3, 4])])
            eapToClient(code: 1, type: 25, req, newID: false)
        }
        eapFromClient(type: 25, AuthLab.tlsData(bytes: 40), dt: 0.01)
        toServer(base + [AuthLab.eapMessage(AuthLab.eap(code: 2, id: eapID, type: 25, AuthLab.tlsData(bytes: 40)))])
        eapID &+= 1
        toNAS(code: 2, [AuthLab.eapMessage(AuthLab.eap(code: 3, id: eapID)),
                        AuthLab.int(64, 13), AuthLab.int(65, 6), AuthLab.attr(81, [0x01] + Array("20".utf8)),
                        AuthLab.vsa(AuthDecoder.vendorAruba, 1, Array("employee".utf8)),
                        AuthLab.vsa(AuthDecoder.vendorMicrosoft, 16, [UInt8](repeating: 0x77, count: 34)),
                        AuthLab.int(27, 28_800)], dt: 0.02)
        eapToClient(code: 3, newID: false)
        fourWay()
        dhcpExchange(ip: ip)
        dnsAnswer("intranet.corp.example", clientIP: ip, address: "10.1.1.5")
    }

    mutating func eapTLSReject() {
        let user = "host/laptop-17.corp.example"
        eapol(fromClient: true, type: 1, [], toGroup: true)
        eapToClient(code: 1, type: 1)
        eapFromClient(type: 1, Array(user.utf8))
        let base = common(user: user)
        toServer(base + [AuthLab.eapMessage(AuthLab.eap(code: 2, id: eapID, type: 1, Array(user.utf8)))])
        eapID &+= 1
        toNAS(code: 11, [AuthLab.eapMessage(AuthLab.eap(code: 1, id: eapID, type: 13, AuthLab.tlsData(start: true)))])
        eapToClient(code: 1, type: 13, AuthLab.tlsData(start: true), newID: false)
        for r in 0..<3 {
            let resp = AuthLab.tlsData(length: r == 1 ? 1400 : nil, bytes: r == 1 ? 1000 : 120)
            eapFromClient(type: 13, resp, dt: 0.01)
            toServer(base + [AuthLab.eapMessage(AuthLab.eap(code: 2, id: eapID, type: 13, resp))])
            eapID &+= 1
            let req = AuthLab.tlsData(bytes: 90)
            toNAS(code: 11, [AuthLab.eapMessage(AuthLab.eap(code: 1, id: eapID, type: 13, req))])
            eapToClient(code: 1, type: 13, req, newID: false)
        }
        eapFromClient(type: 13, AuthLab.tlsData(bytes: 20), dt: 0.01)
        toServer(base + [AuthLab.eapMessage(AuthLab.eap(code: 2, id: eapID, type: 13, AuthLab.tlsData(bytes: 20)))])
        eapID &+= 1
        toNAS(code: 3, [AuthLab.eapMessage(AuthLab.eap(code: 4, id: eapID)),
                        AuthLab.text(18, "certificate expired: CN=laptop-17.corp.example")], dt: 0.03)
        eapToClient(code: 4, newID: false)
    }

    mutating func macAuth(accept: Bool, withDHCP: Bool) {
        let user = AuthLab.macText(client, "")
        // A switch port: no Called-Station SSID, NAS-Port-Type Ethernet, the port name.
        var attrs = common(user: user).filter { ![30, 61, 87].contains($0.first!) }
        attrs += [AuthLab.text(2, "hidden-password"), AuthLab.int(6, 10), AuthLab.int(61, 15), AuthLab.text(87, "1/1/5")]
        toServer(attrs)
        if accept {
            toNAS(code: 2, [AuthLab.int(64, 13), AuthLab.int(65, 6), AuthLab.text(81, "20"),
                            AuthLab.vsa(AuthDecoder.vendorAruba, 1, Array("iot-cameras".utf8))])
            if withDHCP { dhcpExchange(ip: "10.30.0.21", server: "10.30.0.1", dt: 0.5) }
        } else {
            toNAS(code: 3, [AuthLab.text(18, "Unknown endpoint")])
        }
    }

    mutating func captive() {
        let ip = "192.168.50.23"
        fourWay()
        dhcpExchange(ip: ip, server: "192.168.50.1")
        let probe = "GET /hotspot-detect.html HTTP/1.1\r\nHost: captive.apple.com\r\nUser-Agent: CaptiveNetworkSupport\r\n\r\n"
        http(clientIP: ip, serverIP: "17.253.144.10", port: 50_100, request: probe,
             response: "HTTP/1.1 302 Found\r\nLocation: http://portal.guest.example/login?mac=\(clientText)\r\nContent-Length: 0\r\n\r\n")
        http(clientIP: ip, serverIP: "192.168.50.1", port: 50_101,
             request: "GET /login?mac=\(clientText) HTTP/1.1\r\nHost: portal.guest.example\r\n\r\n",
             response: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><form method=post>", dt: 0.2)
        http(clientIP: ip, serverIP: "192.168.50.1", port: 50_102,
             request: "POST /login HTTP/1.1\r\nHost: portal.guest.example\r\nContent-Length: 20\r\n\r\naccept=1&room=1204",
             response: "HTTP/1.1 302 Found\r\nLocation: http://www.example.com/\r\n\r\n", dt: 8)
        http(clientIP: ip, serverIP: "17.253.144.10", port: 50_103, request: probe,
             response: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>", dt: 1)
    }

    /// PEAP seen only on the switch uplink: RADIUS, no EAPOL.
    mutating func peapRADIUSOnly() {
        let user = "erin@corp.example"
        let base = common(user: user)
        toServer(base + [AuthLab.eapMessage(AuthLab.eap(code: 2, id: 1, type: 1, Array(user.utf8)))])
        toNAS(code: 11, [AuthLab.eapMessage(AuthLab.eap(code: 1, id: 2, type: 25, AuthLab.tlsData(start: true)))])
        for r in 0..<3 {
            toServer(base + [AuthLab.eapMessage(AuthLab.eap(code: 2, id: UInt8(2 + r), type: 25, AuthLab.tlsData(bytes: 100)))], dt: 0.02)
            toNAS(code: 11, [AuthLab.eapMessage(AuthLab.eap(code: 1, id: UInt8(3 + r), type: 25, AuthLab.tlsData(bytes: 100)))])
        }
        toServer(base + [AuthLab.eapMessage(AuthLab.eap(code: 2, id: 5, type: 25, AuthLab.tlsData(bytes: 30)))], dt: 0.02)
        toNAS(code: 2, [AuthLab.eapMessage(AuthLab.eap(code: 3, id: 6)), AuthLab.text(81, "40"), AuthLab.text(11, "staff-acl")])
    }
}

// MARK: - Tests

final class AuthTests: XCTestCase {
    static let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
    static let fixtures = repo.appendingPathComponent("Tests/pcaps/auth")

    func sessions(_ s: AuthScenario) -> [AuthSession] { AuthSessions.build(s.build()) }

    func only(_ s: AuthScenario, file: StaticString = #filePath, line: UInt = #line) throws -> AuthSession {
        let all = sessions(s)
        XCTAssertEqual(all.count, 1, "\(s.rawValue): \(all.map { "\($0.client) \($0.methodLabel) \($0.result)" })", file: file, line: line)
        return try XCTUnwrap(all.first, file: file, line: line)
    }

    // MARK: Decoder

    func testMACSpellings() {
        for s in ["aa-bb-cc-dd-ee-ff", "AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff", "AABBCCDDEEFF", "aa:bb:cc:dd:ee:ff", " aabbccddeeff "] {
            XCTAssertEqual(AuthDecoder.normalisedMAC(s), "aa:bb:cc:dd:ee:ff", s)
        }
        for s in ["aabbccddeeff0", "aa-bbcc-dd-ee-ff", "alice", "aa:bb:cc:dd:ee", "", "gg:bb:cc:dd:ee:ff", "a-abbccddeeff"] {
            XCTAssertNil(AuthDecoder.normalisedMAC(s), s)
        }
        let called = AuthDecoder.macPrefix("00-0B-86-10-20-30:Corp-WiFi")
        XCTAssertEqual(called?.mac, "00:0b:86:10:20:30")
        XCTAssertEqual(called?.rest, "Corp-WiFi")
        XCTAssertEqual(AuthDecoder.macPrefix("000b86102030:CafeNet")?.rest, "CafeNet")
    }

    func testEAPOLKeyMessages() {
        for m in 1...4 {
            let f = AuthDecoder.eapol([2, 3] + AuthLab.be16(AuthLab.key(m, replay: 1).count) + AuthLab.key(m, replay: 1))
            XCTAssertEqual(f?.key?.message.number, m, "message \(m)")
            XCTAssertEqual(f?.key?.descriptorName, "RSN")
            XCTAssertEqual(f?.key?.replayCounter, m >= 3 ? 1 : 1)
        }
        let m1 = AuthDecoder.eapol([2, 3] + AuthLab.be16(AuthLab.key(1, replay: 7).count) + AuthLab.key(1, replay: 7))!.key!
        XCTAssertTrue(m1.ack); XCTAssertFalse(m1.mic); XCTAssertTrue(m1.noncePresent); XCTAssertTrue(m1.pairwise)
        XCTAssertEqual(m1.replayCounter, 7)
        let m3 = AuthDecoder.eapol([2, 3] + AuthLab.be16(AuthLab.key(3, replay: 2).count) + AuthLab.key(3, replay: 2))!.key!
        XCTAssertTrue(m3.install && m3.secure && m3.encryptedKeyData && m3.mic)
        // Group key 1/2 (ACK + MIC + secure, not pairwise) and 2/2.
        var g1 = AuthLab.key(3, replay: 3); g1[1] = 0x13; g1[2] = 0x82
        XCTAssertEqual(AuthDecoder.eapol([2, 3] + AuthLab.be16(g1.count) + g1)?.key?.message, .group1)
        var g2 = AuthLab.key(4, replay: 3); g2[1] = 0x03; g2[2] = 0x02
        XCTAssertEqual(AuthDecoder.eapol([2, 3] + AuthLab.be16(g2.count) + g2)?.key?.message, .group2)
    }

    func testEAPPackets() {
        let id = AuthDecoder.eap(AuthLab.eap(code: 2, id: 9, type: 1, Array("alice@corp.example".utf8)))!
        XCTAssertEqual(id.summary, "EAP-Response Identity (alice@corp.example)")
        let start = AuthDecoder.eap(AuthLab.eap(code: 1, id: 3, type: 25, AuthLab.tlsData(start: true)))!
        XCTAssertEqual(start.tls?.start, true)
        XCTAssertEqual(start.summary, "EAP-Request PEAP (start)")
        let frag = AuthDecoder.eap(AuthLab.eap(code: 1, id: 4, type: 13, AuthLab.tlsData(more: true, length: 3000, bytes: 1000)))!
        XCTAssertEqual(frag.tls?.more, true)
        XCTAssertEqual(frag.tls?.lengthIncluded, true)
        XCTAssertEqual(frag.tls?.tlsLength, 3000)
        XCTAssertEqual(frag.tls?.dataLength, 1000)
        let nak = AuthDecoder.eap(AuthLab.eap(code: 2, id: 4, type: 3, [25, 13]))!
        XCTAssertEqual(nak.desired, [25, 13])
        XCTAssertTrue(nak.summary.contains("wants PEAP, EAP-TLS"))
        XCTAssertEqual(AuthDecoder.eap(AuthLab.eap(code: 3, id: 5))?.summary, "EAP-Success")
        XCTAssertEqual(AuthDecoder.eap(AuthLab.eap(code: 4, id: 5))?.summary, "EAP-Failure")
        let wps = AuthDecoder.eap(AuthLab.eap(code: 1, id: 1, type: 254, [0x00, 0x37, 0x2A, 0, 0, 0, 1, 4]))!
        XCTAssertEqual(wps.summary, "EAP-Request WPS")
        for (t, name) in [(4, "MD5-Challenge"), (21, "EAP-TTLS"), (26, "EAP-MSCHAPv2"), (43, "EAP-FAST"), (52, "EAP-pwd")] {
            XCTAssertEqual(AuthDecoder.eapTypeName(UInt8(t)), name)
        }
        // EAPOL types.
        XCTAssertEqual(AuthDecoder.eapol([1, 1, 0, 0])?.summary, "EAPOL-Start")
        XCTAssertEqual(AuthDecoder.eapol([2, 2, 0, 0])?.summary, "EAPOL-Logoff")
        XCTAssertEqual(AuthDecoder.eapol([3, 4, 0, 0])?.type, .asfAlert)
    }

    func testRADIUSAttributes() {
        let bytes = AuthLab.radius(code: 2, id: 42, auth: [UInt8](repeating: 1, count: 16), [
            AuthLab.text(1, "aabbccddeeff"), AuthLab.text(2, "secret"), AuthLab.attr(3, [1] + [UInt8](repeating: 9, count: 16)),
            AuthLab.attr(4, [10, 0, 0, 2]), AuthLab.int(5, 12), AuthLab.int(6, 10), AuthLab.attr(8, [10, 20, 0, 15]),
            AuthLab.text(11, "guest-acl"), AuthLab.text(18, "Welcome"), AuthLab.attr(24, [0xde, 0xad]),
            AuthLab.int(27, 3600), AuthLab.text(30, "00-0B-86-10-20-30:Corp-WiFi"), AuthLab.text(31, "AA-BB-CC-DD-EE-FF"),
            AuthLab.text(32, "sw-core-1"), AuthLab.int(40, 1), AuthLab.text(44, "0000ABCD"), AuthLab.int(49, 4), AuthLab.int(61, 15),
            AuthLab.int(64, 13), AuthLab.int(65, 6), AuthLab.attr(81, [0x01] + Array("20".utf8)), AuthLab.text(87, "Gi1/0/5"),
            AuthLab.vsa(14823, 1, Array("employee".utf8)), AuthLab.vsa(14823, 2, AuthLab.be32(30)), AuthLab.vsa(14823, 5, Array("Corp-WiFi".utf8)),
            AuthLab.vsa(14823, 6, Array("AP-2F".utf8)), AuthLab.vsa(14823, 10, Array("floor2".utf8)),
            AuthLab.vsa(9, 1, Array("url-redirect-acl=REDIRECT".utf8)), AuthLab.vsa(12356, 1, Array("vpn-users".utf8)),
            AuthLab.vsa(12356, 3, Array("root".utf8)), AuthLab.vsa(311, 16, [UInt8](repeating: 7, count: 34)),
            AuthLab.vsa(25461, 1, Array("superuser".utf8)), AuthLab.vsa(2011, 99, [1, 2, 3]),
            AuthLab.fakeMessageAuthenticator,
        ])
        let r = AuthDecoder.radius(bytes)!
        XCTAssertEqual(r.codeName, "Access-Accept")
        XCTAssertEqual(r.id, 42)
        XCTAssertFalse(r.truncated)
        func d(_ name: String) -> String? { r.attributes.first { $0.name == name }?.display }
        XCTAssertEqual(d("User-Password"), "(present)")
        XCTAssertEqual(d("CHAP-Password"), "(present)")
        XCTAssertFalse(r.attributes.contains { $0.display.contains("secret") }, "a password is never shown")
        XCTAssertEqual(d("NAS-IP-Address"), "10.0.0.2")
        XCTAssertEqual(d("NAS-Port"), "12")
        XCTAssertEqual(d("Service-Type"), "Call-Check")
        XCTAssertEqual(d("Framed-IP-Address"), "10.20.0.15")
        XCTAssertEqual(d("Session-Timeout"), "3600")
        XCTAssertEqual(d("Acct-Status-Type"), "Start")
        XCTAssertEqual(d("Acct-Terminate-Cause"), "Idle-Timeout")
        XCTAssertEqual(d("NAS-Port-Type"), "Ethernet")
        XCTAssertEqual(d("Tunnel-Type"), "VLAN")
        XCTAssertEqual(d("Tunnel-Medium-Type"), "IEEE-802")
        XCTAssertEqual(d("Tunnel-Private-Group-ID"), "20")
        XCTAssertEqual(d("Message-Authenticator"), "(16 bytes)")
        XCTAssertEqual(d("Aruba-User-Role"), "employee")
        XCTAssertEqual(d("Aruba-User-Vlan"), "30")
        XCTAssertEqual(d("Aruba-Essid-Name"), "Corp-WiFi")
        XCTAssertEqual(d("Aruba-Location-Id"), "AP-2F")
        XCTAssertEqual(d("Aruba-AP-Group"), "floor2")
        XCTAssertEqual(d("cisco-avpair"), "url-redirect-acl=REDIRECT")
        XCTAssertEqual(d("Fortinet-Group-Name"), "vpn-users")
        XCTAssertEqual(d("Fortinet-Vdom-Name"), "root")
        XCTAssertEqual(d("MS-MPPE-Send-Key"), "(present)")
        XCTAssertEqual(d("PaloAlto-Admin-Role"), "superuser")
        XCTAssertEqual(d("Huawei/99"), "010203")
        XCTAssertEqual(r.vlan, "20")
        XCTAssertEqual(r.role, "employee")
        XCTAssertEqual(r.ssid, "Corp-WiFi")
        XCTAssertEqual(r.replyMessage, "Welcome")
        XCTAssertEqual(r.nasIdentifier, "sw-core-1")
        for c: UInt8 in [1, 2, 3, 4, 5, 11, 40, 41, 42, 43, 44, 45] {
            XCTAssertFalse(AuthDecoder.radiusCodeName(c).hasPrefix("Code"), "\(c)")
        }
    }

    func testEAPMessageFragmentedAcrossThreeAttributes() throws {
        let packets = AuthScenario.eapFragmented.build()
        let radius = packets.compactMap { p -> AuthDecoder.RadiusPacket? in
            if case .radius(let r) = AuthDecoder.classify(p) { return r } else { return nil }
        }
        let big = try XCTUnwrap(radius.first { $0.eapFragments == 3 })
        XCTAssertEqual(big.eap?.type, 25)
        XCTAssertEqual(big.eap?.length, 5 + 5 + 600)
        XCTAssertEqual(big.eap?.tls?.tlsLength, 700)
        XCTAssertEqual(big.eap?.tls?.dataLength, 600)
        XCTAssertEqual(big.eap?.truncated, false)
        let s = try only(.eapFragmented)
        XCTAssertEqual(s.method, .dot1x("PEAP"))
        XCTAssertEqual(s.result, .rejected("Login incorrect"))
        XCTAssertTrue(s.events.contains { $0.detail?.contains("EAP-Message in 3 attributes") == true })
    }

    func testTruncatedInputs() {
        // An attribute whose length runs past the datagram.
        var r = AuthLab.radius(code: 1, id: 1, auth: [UInt8](repeating: 0, count: 16), [AuthLab.text(1, "alice")])
        r += [31, 40, 0x41, 0x41]
        r[3] = UInt8(r.count)
        let p = AuthDecoder.radius(r)!
        XCTAssertTrue(p.truncated)
        XCTAssertEqual(p.userName, "alice")
        // A RADIUS length past the end.
        var long = AuthLab.radius(code: 2, id: 1, auth: [UInt8](repeating: 0, count: 16), [])
        long[2] = 0x10
        XCTAssertEqual(AuthDecoder.radius(long)?.truncated, true)
        // An EAP length past the end, inside EAPOL and inside RADIUS.
        var eap = AuthLab.eap(code: 1, id: 1, type: 25, AuthLab.tlsData(length: 4000, bytes: 10))
        eap[2] = 0x0F; eap[3] = 0xA0
        XCTAssertEqual(AuthDecoder.eap(eap)?.truncated, true)
        XCTAssertEqual(AuthDecoder.eapol([2, 0] + AuthLab.be16(eap.count + 100) + eap)?.truncated, true)
        let inner = AuthDecoder.radius(AuthLab.radius(code: 11, id: 2, auth: [UInt8](repeating: 0, count: 16), [AuthLab.eapMessage(eap)]))
        XCTAssertEqual(inner?.eap?.truncated, true)
        // Short EAPOL-Key bodies.
        for n in 0..<96 {
            let k = Array(AuthLab.key(2, replay: 1).prefix(n))
            _ = AuthDecoder.eapol([2, 3] + AuthLab.be16(n) + k)
            _ = AuthDecoder.eapol([2, 3] + AuthLab.be16(200) + k)
        }
        XCTAssertNil(AuthDecoder.eapol([2, 3]))
        XCTAssertNil(AuthDecoder.radius([1, 2, 0, 19] + [UInt8](repeating: 0, count: 16)))
        XCTAssertNil(AuthDecoder.eap([1, 1, 0, 2]))
    }

    func testFuzzFiveThousandMutations() {
        var rng = AuthRNG(seed: 0x5EED_A117)
        let sources = AuthScenario.allCases.flatMap { $0.build() }
        var batch: [Packet] = []
        for n in 0..<5_000 {
            var bytes = [UInt8](sources[Int(rng.next() % UInt64(sources.count))].data)
            switch rng.next() % 4 {
            case 0:
                for _ in 0..<(1 + rng.next() % 8) { bytes[Int(rng.next() % UInt64(bytes.count))] = UInt8(truncatingIfNeeded: rng.next()) }
            case 1:
                bytes = Array(bytes.prefix(Int(rng.next() % UInt64(bytes.count + 1))))
            case 2:
                // Length fields: EAPOL / EAP / RADIUS / attribute lengths near the front.
                for _ in 0..<4 {
                    let i = min(bytes.count - 1, 14 + Int(rng.next() % 60))
                    if i >= 0 { bytes[i] = [0x00, 0x01, 0x02, 0xff, 0xfe, 0x80][Int(rng.next() % 6)] }
                }
            default:
                bytes += (0..<Int(rng.next() % 64)).map { _ in UInt8(truncatingIfNeeded: rng.next()) }
            }
            let data = Data(bytes)
            let p = Packet(id: n + 1, timestamp: Date(timeIntervalSince1970: 1_758_000_000 + Double(n) * 0.01), relative: Double(n) * 0.01,
                           length: data.count, captured: data.count, data: data, decoded: PacketDecoder.decode(data))
            _ = AuthDecoder.classify(p)
            _ = AuthDecoder.radius(bytes)
            _ = AuthDecoder.eapol(bytes)
            _ = AuthDecoder.eap(bytes)
            batch.append(p)
            if batch.count == 250 {
                for s in AuthSessions.build(batch) { _ = AuthSummary.text(s); _ = s.searchText }
                batch.removeAll()
            }
        }
        XCTAssertTrue(true, "no crash")
    }

    // MARK: Sessions

    func testPEAPSuccess() throws {
        let s = try only(.peapSuccess)
        XCTAssertEqual(s.client, AuthScenario.peapSuccess.clientText)
        XCTAssertEqual(s.user, "alice@corp.example")
        XCTAssertEqual(s.method, .dot1x("PEAP"))
        XCTAssertEqual(s.result, .accepted)
        XCTAssertEqual(s.health, .ok, s.reasons.joined(separator: "; "))
        XCTAssertEqual(s.vlan, "20")
        XCTAssertEqual(s.role, "employee")
        XCTAssertEqual(s.ip, "10.20.0.15")
        XCTAssertEqual(s.ssid, "Corp-WiFi")
        XCTAssertEqual(s.nas, "aruba-ctrl-01")
        XCTAssertEqual(s.serverIP, AuthLab.serverIP)
        XCTAssertEqual(s.nasMAC, AuthLab.macText(AuthLab.ap))
        XCTAssertEqual(s.lifelines, [.client, .nas, .server])
        XCTAssertEqual(s.radiusRTTs.count, 6)
        XCTAssertEqual(s.retries, 0)
        let labels = s.events.map(\.label)
        XCTAssertEqual(labels.first, "EAPOL-Start")
        XCTAssertTrue(labels.contains("EAP-Request Identity"))
        XCTAssertTrue(labels.contains("EAP-Response Identity (alice@corp.example)"))
        XCTAssertTrue(labels.contains { $0.hasPrefix("PEAP · TLS handshake ×") }, labels.joined(separator: "\n"))
        XCTAssertTrue(labels.contains { $0.hasPrefix("Access-Accept") && $0.contains("VLAN 20") && $0.contains("role employee") })
        XCTAssertTrue(labels.contains("EAP-Success"))
        for m in ["1/4", "2/4", "3/4", "4/4"] { XCTAssertTrue(labels.contains { $0.hasPrefix("EAPOL-Key \(m)") }, m) }
        XCTAssertTrue(labels.contains("DHCP ACK 10.20.0.15"))
        XCTAssertTrue(labels.contains { $0.hasPrefix("DNS answer") })
        XCTAssertFalse(labels.contains { $0.contains("MPPE") }, "keys are not labels")
        let accept = try XCTUnwrap(s.events.first { $0.kind == .radiusAccept })
        XCTAssertEqual(accept.from, .server); XCTAssertEqual(accept.to, .nas)
        XCTAssertTrue(accept.detail?.contains("MS-MPPE-Send-Key (present)") == true)
        let req = try XCTUnwrap(s.events.first { $0.kind == .eapRequest })
        XCTAssertEqual(req.from, .nas); XCTAssertEqual(req.to, .client)
        // The grouped rows keep every frame.
        XCTAssertEqual(Set(s.events.flatMap(\.packetIDs)).count, s.packetIDs.count)
        XCTAssertEqual(s.packetIDs.count, AuthScenario.peapSuccess.build().count - 1, "all but the DNS query")
        let text = AuthSummary.text(s)
        XCTAssertTrue(text.contains("Result: Accept"))
        XCTAssertTrue(text.contains("VLAN 20"))
    }

    func testEAPTLSReject() throws {
        let s = try only(.eapTLSReject)
        XCTAssertEqual(s.method, .dot1x("EAP-TLS"))
        XCTAssertEqual(s.result, .rejected("certificate expired: CN=laptop-17.corp.example"))
        XCTAssertEqual(s.health, .bad)
        XCTAssertTrue(s.reasons.first?.contains("EAP-Failure after EAP-TLS") == true, s.reasons.joined())
        XCTAssertTrue(s.reasons.first?.contains("certificate") == true)
        let reject = try XCTUnwrap(s.events.first { $0.kind == .radiusReject })
        XCTAssertTrue(reject.label.contains("certificate expired"))
        XCTAssertNotNil(reject.problem)
        XCTAssertTrue(s.events.contains { $0.kind == .eapFailure && $0.problem != nil })
    }

    func testMACAuthAccept() throws {
        let s = try only(.macAuthAccept)
        XCTAssertEqual(s.method, .macAuth)
        XCTAssertEqual(s.user, AuthScenario.macAuthAccept.clientText, "a MAC user name is shown as the MAC")
        XCTAssertEqual(s.result, .accepted)
        XCTAssertEqual(s.vlan, "20")
        XCTAssertEqual(s.role, "iot-cameras")
        XCTAssertEqual(s.port, "1/1/5")
        XCTAssertEqual(s.ip, "10.30.0.21")
        XCTAssertEqual(s.health, .ok, s.reasons.joined())
        let req = try XCTUnwrap(s.events.first { $0.kind == .radiusRequest })
        XCTAssertTrue(req.label.contains("User-Name \(AuthScenario.macAuthAccept.clientText)"))
        XCTAssertTrue(req.detail?.contains("User-Password (present)") == true)
        XCTAssertFalse(AuthSummary.text(s).contains("hidden-password"))
    }

    func testMACThenDot1x() throws {
        let s = try only(.macThenDot1x)
        XCTAssertEqual(s.method, .macThenDot1x("PEAP"))
        XCTAssertEqual(s.macStageResult, .rejected("Unknown endpoint"))
        XCTAssertEqual(s.result, .accepted)
        XCTAssertEqual(s.user, "bob@corp.example")
        XCTAssertTrue(s.notes.contains { $0.contains("MAC auth was rejected first") })
        XCTAssertEqual(s.health, .ok, s.reasons.joined())
    }

    func testPSKSuccess() throws {
        let s = try only(.pskSuccess)
        XCTAssertEqual(s.method, .psk)
        XCTAssertEqual(s.result, .accepted)
        XCTAssertEqual(s.ip, "192.168.1.44")
        XCTAssertEqual(s.lifelines, [.client, .nas])
        XCTAssertEqual(s.events.filter { if case .key = $0.kind { true } else { false } }.count, 4)
        XCTAssertEqual(s.health, .ok, s.reasons.joined())
    }

    func testPSKWrong() throws {
        let s = try only(.pskWrong)
        XCTAssertEqual(s.method, .psk)
        guard case .timeout = s.result else { return XCTFail("\(s.result)") }
        XCTAssertEqual(s.health, .bad)
        XCTAssertTrue(s.reasons.first?.contains("stopped after message 1/4") == true, s.reasons.joined())
        XCTAssertTrue(s.reasons.first?.contains("wrong PSK") == true)
        XCTAssertEqual(s.retries, 3)
        XCTAssertEqual(s.events.count, 1, "four identical 1/4 are one row ×4")
        XCTAssertEqual(s.events.first?.label, "EAPOL-Key 1/4 (ANonce) ×4 over 3.00 s")
        XCTAssertEqual(s.events.first?.problem, "no 2/4 from the client")
    }

    func testPSKWrongAfterTwoOfFour() {
        var lab = AuthLab(client: [0x02, 0, 0, 0, 9, 9])
        for _ in 0..<3 {
            lab.eapol(fromClient: false, type: 3, AuthLab.key(1, replay: 1), dt: 1)
            lab.eapol(fromClient: true, type: 3, AuthLab.key(2, replay: 1), dt: 0.01)
        }
        let s = AuthSessions.build(lab.packets)
        XCTAssertEqual(s.count, 1)
        XCTAssertEqual(s.first?.result, .rejected("wrong PSK"))
        XCTAssertTrue(s.first?.reasons.first?.contains("after message 2/4") == true)
    }

    func testRADIUSTimeout() throws {
        let s = try only(.radiusTimeout)
        XCTAssertEqual(s.result, .timeout("RADIUS server did not answer"))
        XCTAssertEqual(s.health, .bad)
        XCTAssertTrue(s.reasons.first?.contains("RADIUS server 10.0.0.10 did not answer 3 requests") == true, s.reasons.joined())
        XCTAssertEqual(s.retries, 2)
        XCTAssertEqual(s.lifelines, [.nas, .server], "wired side only: no client lifeline")
        XCTAssertEqual(s.events.count, 1)
        XCTAssertEqual(s.events.first?.packetIDs.count, 3)
        XCTAssertTrue(s.events.first?.problem?.contains("3 transmissions") == true)
    }

    func testCaptivePortal() throws {
        let s = try only(.captivePortal)
        XCTAssertEqual(s.method, .psk)
        XCTAssertTrue(s.captive)
        XCTAssertEqual(s.methodLabel, "PSK + Captive")
        XCTAssertEqual(s.portalHost, "portal.guest.example")
        XCTAssertEqual(s.result, .accepted)
        XCTAssertEqual(s.health, .ok, s.reasons.joined())
        XCTAssertTrue(AuthMethodFilter.captive.matches(s))
        XCTAssertTrue(AuthMethodFilter.psk.matches(s))
        let kinds = s.events.map(\.kind)
        XCTAssertTrue(kinds.contains(.captiveProbe))
        XCTAssertTrue(kinds.contains(.captiveRedirect))
        XCTAssertTrue(kinds.contains(.captiveLogin))
        XCTAssertTrue(kinds.contains(.captivePassed))
        XCTAssertTrue(s.events.contains { $0.label.contains("POST") && $0.label.contains("portal login") })
        // Without the login and the final probe: not completed.
        let cut = Array(AuthScenario.captivePortal.build().prefix(12))
        let open = try XCTUnwrap(AuthSessions.build(cut).first)
        XCTAssertTrue(open.captive)
        XCTAssertTrue(open.reasons.contains { $0.contains("redirect to portal.guest.example not completed") }, open.reasons.joined())
    }

    func testOpenNetworkPortalOnly() throws {
        // No PSK: DHCP, the probe, a redirect: the captive session takes the DHCP of the minute before.
        var lab = AuthLab(client: [0x02, 0, 0, 0, 7, 7])
        lab.dhcpExchange(ip: "172.16.0.9", server: "172.16.0.1")
        lab.http(clientIP: "172.16.0.9", serverIP: "142.250.1.1", port: 40_000,
                 request: "GET /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\n\r\n",
                 response: "HTTP/1.1 302 Found\r\nLocation: https://wifi.hotel.example/portal\r\n\r\n")
        let s = try XCTUnwrap(AuthSessions.build(lab.packets).first)
        XCTAssertEqual(s.method, .captive)
        XCTAssertEqual(s.portalHost, "wifi.hotel.example")
        XCTAssertEqual(s.result, .inProgress)
        XCTAssertTrue(s.events.first?.label.hasPrefix("DHCP Discover") == true, s.events.map(\.label).joined(separator: "\n"))
    }

    @MainActor func testWiredSideOnly() throws {
        let s = try only(.wiredSideOnly)
        XCTAssertEqual(s.method, .dot1x("PEAP"))
        XCTAssertEqual(s.user, "erin@corp.example")
        XCTAssertEqual(s.result, .accepted)
        XCTAssertFalse(s.hasClientSide)
        XCTAssertEqual(s.lifelines, [.nas, .server])
        XCTAssertEqual(s.vlan, "40")
        XCTAssertEqual(s.role, "staff-acl")
        XCTAssertTrue(s.notes.contains { $0.contains("Captured on the wired side") })
        XCTAssertTrue(s.events.contains { $0.isGroup })
        XCTAssertEqual(s.health, .ok, s.reasons.joined())
        let layout = AuthLadderLayout.make(session: s, width: 600)
        XCTAssertEqual(layout.lanes, [.nas, .server])
        XCTAssertTrue(layout.note.contains("wired side"))
    }

    func testCallingStationSpellingsGroupOnOneClient() {
        let s = sessions(.callingStationSpellings)
        XCTAssertEqual(s.count, 3, "three attempts 70 s apart")
        XCTAssertEqual(Set(s.map(\.client)), [AuthScenario.callingStationSpellings.clientText])
        XCTAssertTrue(s.allSatisfy { $0.method == .macAuth && $0.result == .accepted && $0.vlan == "30" })
    }

    func testRADIUSRetryAnswered() throws {
        var lab = AuthLab(client: [0x02, 0, 0, 0, 5, 5])
        let attrs = lab.common(user: "020000000505")
        let (id, auth) = lab.toServer(attrs + [AuthLab.text(2, "x")])
        lab.toServer(attrs + [AuthLab.text(2, "x")], id: id, auth: auth, dt: 3)
        lab.toNAS(code: 2, [AuthLab.text(81, "10")], id: id, dt: 0.05)
        let s = try XCTUnwrap(AuthSessions.build(lab.packets).first)
        XCTAssertEqual(s.result, .accepted)
        XCTAssertEqual(s.retries, 1)
        XCTAssertEqual(s.health, .warn)
        XCTAssertTrue(s.reasons.first?.contains("after 1 retry") == true, s.reasons.joined())
        XCTAssertEqual(s.radiusRTTs.count, 1)
        XCTAssertLessThan(s.radiusRTTs[0], 0.1, "timed from the last transmission")
    }

    func testAcceptedWithoutDHCPWarns() throws {
        // The client's own frames are in the capture (802.1X over EAPOL), then nothing for 30 s.
        var lab = AuthLab(client: [0x02, 0, 0, 0, 6, 6])
        lab.peap(user: "frank@corp.example", succeed: true, rounds: 3, ip: "10.20.0.99")
        lab.packets.removeLast(6)   // no DHCP, no DNS
        lab.udpFrame(srcMAC: [0x02, 0, 0, 0, 6, 7], dstMAC: AuthLab.broadcast, src: "0.0.0.0", dst: "255.255.255.255",
                     sp: 68, dp: 67, AuthLab.dhcp(op: 1, type: 1, chaddr: [0x02, 0, 0, 0, 6, 7]), dt: 30)
        let s = try XCTUnwrap(AuthSessions.build(lab.packets).first { $0.client == "02:00:00:00:06:06" })
        XCTAssertEqual(s.result, .accepted)
        XCTAssertEqual(s.health, .warn)
        XCTAssertTrue(s.reasons.contains { $0.contains("no DHCP within 10 s: VLAN 20 may have no DHCP") }, s.reasons.joined())
        // RADIUS only (MAC auth seen on the uplink): a note, not a warning.
        var wired = AuthLab(client: [0x02, 0, 0, 0, 6, 8])
        wired.macAuth(accept: true, withDHCP: false)
        wired.udpFrame(srcMAC: [0x02, 0, 0, 0, 6, 7], dstMAC: AuthLab.broadcast, src: "0.0.0.0", dst: "255.255.255.255",
                       sp: 68, dp: 67, AuthLab.dhcp(op: 1, type: 1, chaddr: [0x02, 0, 0, 0, 6, 7]), dt: 30)
        let w = try XCTUnwrap(AuthSessions.build(wired.packets).first { $0.client == "02:00:00:00:06:08" })
        XCTAssertEqual(w.health, .ok)
        XCTAssertTrue(w.notes.contains { $0.contains("No DHCP from this client") })
    }

    func testDHCPDiscoverWithoutOfferIsBad() throws {
        var lab = AuthLab(client: [0x02, 0, 0, 0, 8, 8])
        lab.fourWay()
        lab.dhcpExchange(ip: "10.9.9.9", offer: false)
        lab.dhcpExchange(ip: "10.9.9.9", dt: 4, offer: false)
        let s = try XCTUnwrap(AuthSessions.build(lab.packets).first)
        XCTAssertEqual(s.health, .bad)
        XCTAssertTrue(s.reasons.first?.contains("DHCP Discover got no Offer") == true, s.reasons.joined())
    }

    func testEAPOLStartUnanswered() throws {
        var lab = AuthLab(client: [0x02, 0, 0, 0, 4, 4])
        for _ in 0..<3 { lab.eapol(fromClient: true, type: 1, [], toGroup: true, dt: 30) }
        let s = try XCTUnwrap(AuthSessions.build(lab.packets).first)
        XCTAssertEqual(s.result, .timeout("no answer to EAPOL-Start"))
        XCTAssertTrue(s.reasons.first?.contains("did not answer 3 EAPOL-Starts") == true)
    }

    func testCombinedCaptureKeepsEveryScenario() {
        let all = AuthSessions.build(AuthScenario.combined())
        for sc in AuthScenario.allCases {
            XCTAssertTrue(all.contains { $0.client == sc.clientText }, sc.rawValue)
        }
        XCTAssertEqual(all.filter { $0.client == AuthScenario.callingStationSpellings.clientText }.count, 3)
        XCTAssertEqual(all.count, AuthScenario.allCases.count + 2)
    }

    func testPacketFilterPresetMatchesAuthTraffic() throws {
        let m = PacketMatcher(try Query.parse(AuthDecoder.packetFilterPreset))
        let packets = AuthScenario.combined()
        let hits = packets.filter { m.matches($0) }
        XCTAssertTrue(packets.filter { $0.decoded.etherType == 0x888E }.allSatisfy { m.matches($0) }, "EAPOL")
        XCTAssertTrue(packets.filter { $0.decoded.protocolName == "RADIUS" }.allSatisfy { m.matches($0) })
        XCTAssertEqual(hits.count, packets.count, "the fixtures are all auth traffic")
        XCTAssertEqual(AuthView.packetFilter([3, 5]), "frame:3 OR frame:5")
    }

    func testTwoHundredThousandPacketsUnderOneSecond() {
        let auth = AuthScenario.combined()
        var tcp = AuthLab(client: [0x02, 1, 1, 1, 1, 1])
        tcp.tcpFrame(srcMAC: tcp.client, dstMAC: AuthLab.gatewayMAC, src: "10.1.1.1", dst: "10.2.2.2", sp: 443, dp: 51_000,
                     [UInt8](repeating: 0x17, count: 1200), dt: 0)
        let filler = tcp.packets[0]
        var packets: [Packet] = []
        packets.reserveCapacity(200_000)
        var k = 0
        for i in 0..<200_000 {
            let src = i % 200 == 0 && k < auth.count ? auth[k] : filler
            if i % 200 == 0 { k += 1 }
            packets.append(Packet(id: i + 1, timestamp: Date(timeIntervalSince1970: 1_758_000_000 + Double(i) * 0.01),
                                  relative: Double(i) * 0.01, length: src.length, captured: src.captured, data: src.data,
                                  decoded: src.decoded))
        }
        let start = Date()
        let s = AuthSessions.build(packets)
        let elapsed = Date().timeIntervalSince(start)
        print("[perf] AuthSessions.build 200k packets: \(String(format: "%.3f", elapsed)) s, \(s.count) sessions")
        XCTAssertFalse(s.isEmpty)
        XCTAssertWithinBudget(elapsed, 1.0, "200k packets")
    }

    // MARK: Fixture files

    /// `Tests/pcaps/auth/<scenario>.pcap` + `auth-all.pcap`: written with
    /// `TEST_RUNNER_SHEEPLOG_WRITE_AUTH_PCAPS=1`, otherwise read back and checked against the builders.
    func testPcapFixtures() throws {
        let write = ProcessInfo.processInfo.environment["SHEEPLOG_WRITE_AUTH_PCAPS"] == "1"
        var files: [(String, [Packet])] = AuthScenario.allCases.map { ($0.rawValue, $0.build()) }
        files.append(("auth-all", AuthScenario.combined()))
        if write { try FileManager.default.createDirectory(at: Self.fixtures, withIntermediateDirectories: true) }
        for (name, packets) in files {
            let url = Self.fixtures.appendingPathComponent("\(name).pcap")
            if write { try PcapFile.write(packets, linkType: 1, to: url) }
            guard FileManager.default.fileExists(atPath: url.path) else {
                XCTFail("\(url.lastPathComponent) missing: run with TEST_RUNNER_SHEEPLOG_WRITE_AUTH_PCAPS=1")
                continue
            }
            var read: [Packet] = []
            _ = try PcapFile.read(url) { read += $0 }
            XCTAssertEqual(read.count, packets.count, name)
            XCTAssertEqual(read.map(\.data), packets.map(\.data), name)
            let a = AuthSessions.build(read), b = AuthSessions.build(packets)
            XCTAssertEqual(a.map(\.client), b.map(\.client), name)
            XCTAssertEqual(a.map(\.result), b.map(\.result), name)
            XCTAssertEqual(a.map(\.method), b.map(\.method), name)
        }
        // tcpdump names the protocols.
        let tcpdump = "/usr/sbin/tcpdump"
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: tcpdump), "tcpdump not installed")
        let out = CaptureGroundTruthTests.run(tcpdump, ["-nn", "-r", Self.fixtures.appendingPathComponent("auth-all.pcap").path])
        XCTAssertTrue(out.contains("EAP"), out.prefix(400).description)
        XCTAssertTrue(out.contains("EAPOL") || out.contains("EAP packet"))
        XCTAssertTrue(out.contains("RADIUS, Access-Request"))
        XCTAssertTrue(out.contains("RADIUS, Access-Accept"))
        XCTAssertTrue(out.contains("RADIUS, Access-Reject"))
        XCTAssertTrue(out.contains("RADIUS, Access-Challenge"))
        XCTAssertTrue(out.contains("BOOTP/DHCP"))
        XCTAssertTrue(out.contains("HTTP"))
    }
}

/// Seeded generator for the fuzz test (the same mutations every run).
struct AuthRNG {
    var state: UInt64
    init(seed: UInt64) { state = seed }
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}
