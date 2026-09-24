import XCTest
@testable import SheepLog

/// Builds real-shaped frames in code (checksums left zero).
enum PacketFixture {
    static let macA: [UInt8] = [0x00, 0x1c, 0x0e, 0x87, 0x78, 0x01]
    static let macB: [UInt8] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]

    static func be16(_ v: Int) -> [UInt8] { [UInt8((v >> 8) & 0xff), UInt8(v & 0xff)] }
    static func be32(_ v: UInt32) -> [UInt8] { [UInt8(v >> 24), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)] }
    static func be24(_ v: Int) -> [UInt8] { [UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)] }

    static func ip4(_ s: String) -> [UInt8] { s.split(separator: ".").map { UInt8($0)! } }

    static func ether(dst: [UInt8] = macB, src: [UInt8] = macA, type: Int, tags: [(tpid: Int, vid: Int)] = [],
                      _ payload: [UInt8]) -> [UInt8] {
        var f = dst + src
        for t in tags { f += be16(t.tpid) + be16(t.vid) }
        f += be16(type) + payload
        while f.count < 60 { f.append(0) }   // Ethernet minimum (padding after IP)
        return f
    }

    static func ipv4(src: String = "10.1.0.9", dst: String = "93.184.216.34", proto: UInt8, ttl: UInt8 = 64,
                     id: Int = 0x1234, df: Bool = true, dscp: UInt8 = 0, _ payload: [UInt8]) -> [UInt8] {
        var h: [UInt8] = [0x45, dscp << 2] + be16(20 + payload.count) + be16(id) + (df ? [0x40, 0x00] : [0x00, 0x00])
        h += [ttl, proto, 0, 0] + ip4(src) + ip4(dst)
        return h + payload
    }

    static func ipv6(src: [UInt8], dst: [UInt8], next: UInt8, hop: UInt8 = 64, _ payload: [UInt8]) -> [UInt8] {
        [0x60, 0x00, 0x00, 0x00] + be16(payload.count) + [next, hop] + src + dst + payload
    }

    static func tcp(_ sp: Int, _ dp: Int, seq: UInt32 = 0, ack: UInt32 = 0, flags: UInt8, win: Int = 65535,
                    options: [UInt8] = [], _ payload: [UInt8] = []) -> [UInt8] {
        var opts = options
        while opts.count % 4 != 0 { opts.append(1) }
        let hl = 20 + opts.count
        return be16(sp) + be16(dp) + be32(seq) + be32(ack) + [UInt8(hl / 4) << 4, flags] + be16(win) + [0, 0, 0, 0] + opts + payload
    }

    static func udp(_ sp: Int, _ dp: Int, _ payload: [UInt8]) -> [UInt8] {
        be16(sp) + be16(dp) + be16(8 + payload.count) + [0, 0] + payload
    }

    static func tcp4(src: String = "10.1.0.9", dst: String = "93.184.216.34", _ sp: Int, _ dp: Int,
                     seq: UInt32 = 0, ack: UInt32 = 0, flags: UInt8, options: [UInt8] = [], _ payload: [UInt8] = [],
                     vlan: Int? = nil) -> Data {
        Data(ether(type: 0x0800, tags: vlan.map { [(0x8100, $0)] } ?? [],
                   ipv4(src: src, dst: dst, proto: 6, tcp(sp, dp, seq: seq, ack: ack, flags: flags, options: options, payload))))
    }

    static func udp4(src: String = "10.1.0.9", dst: String = "1.1.1.1", _ sp: Int, _ dp: Int, _ payload: [UInt8],
                     tags: [(tpid: Int, vid: Int)] = []) -> Data {
        Data(ether(type: 0x0800, tags: tags, ipv4(src: src, dst: dst, proto: 17, udp(sp, dp, payload))))
    }

    static let synOptions: [UInt8] = [0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x06, 0x04, 0x02]

    static func dnsName(_ name: String) -> [UInt8] {
        var out: [UInt8] = []
        for label in name.split(separator: ".") { out.append(UInt8(label.utf8.count)); out += Array(label.utf8) }
        return out + [0]
    }

    static func dnsQuery(id: Int = 0x1a2b, _ name: String, type: Int = 1) -> [UInt8] {
        be16(id) + [0x01, 0x00] + be16(1) + be16(0) + be16(0) + be16(0) + dnsName(name) + be16(type) + be16(1)
    }

    static func dnsResponse(id: Int = 0x1a2b, _ name: String, address: String) -> [UInt8] {
        be16(id) + [0x81, 0x80] + be16(1) + be16(1) + be16(0) + be16(0) + dnsName(name) + be16(1) + be16(1)
            + [0xc0, 0x0c] + be16(1) + be16(1) + be32(300) + be16(4) + ip4(address)
    }

    static func clientHello(sni: String) -> [UInt8] {
        let name = Array(sni.utf8)
        let sniData = be16(3 + name.count) + [0] + be16(name.count) + name
        let sniExt = be16(0) + be16(sniData.count) + sniData
        let versions: [UInt8] = [6, 0x0a, 0x0a, 0x03, 0x04, 0x03, 0x03]
        let svExt = be16(0x2b) + be16(versions.count) + versions
        let alpn: [UInt8] = be16(16) + be16(5) + be16(3) + [2] + Array("h2".utf8)
        let exts = alpn + sniExt + svExt
        var body: [UInt8] = [0x03, 0x03] + [UInt8](repeating: 7, count: 32)
        body += [32] + [UInt8](repeating: 9, count: 32)
        body += be16(4) + [0x13, 0x01, 0x13, 0x02]
        body += [1, 0]
        body += be16(exts.count) + exts
        let hs = [0x01] + be24(body.count) + body
        return [0x16, 0x03, 0x01] + be16(hs.count) + hs
    }

    static func serverHello() -> [UInt8] {
        let sv = be16(0x2b) + be16(2) + [0x03, 0x04]
        var body: [UInt8] = [0x03, 0x03] + [UInt8](repeating: 3, count: 32)
        body += [0] + [0x13, 0x01] + [0]
        body += be16(sv.count) + sv
        let hs = [0x02] + be24(body.count) + body
        let ccs: [UInt8] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01]
        let appData: [UInt8] = [0x17, 0x03, 0x03, 0x00, 0x04, 1, 2, 3, 4]
        return [0x16, 0x03, 0x03] + be16(hs.count) + hs + ccs + appData
    }

    static func arp(request: Bool, senderMAC: [UInt8] = macA, senderIP: String = "10.1.0.9",
                    targetMAC: [UInt8] = [0, 0, 0, 0, 0, 0], targetIP: String = "10.1.0.1") -> Data {
        let body: [UInt8] = be16(1) + be16(0x0800) + [6, 4] + be16(request ? 1 : 2) + senderMAC + ip4(senderIP) + targetMAC + ip4(targetIP)
        return Data(ether(dst: request ? [0xff, 0xff, 0xff, 0xff, 0xff, 0xff] : macB, src: senderMAC, type: 0x0806, body))
    }

    static func icmpEcho(request: Bool, id: Int = 0x1234, seq: Int = 1, ttl: UInt8 = 64) -> Data {
        let icmp: [UInt8] = [request ? 8 : 0, 0, 0, 0] + be16(id) + be16(seq) + [UInt8](repeating: 0x61, count: 32)
        return Data(ether(type: 0x0800, ipv4(dst: "1.1.1.1", proto: 1, ttl: ttl, icmp)))
    }

    static let v6a: [UInt8] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    static let v6b: [UInt8] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]

    /// Every fixture, for mutation fuzzing.
    static func all() -> [Data] {
        [tcp4(51234, 443, flags: 0x02, options: synOptions),
         tcp4(51234, 80, seq: 1, ack: 1, flags: 0x18, Array("GET / HTTP/1.1\r\nHost: a\r\n\r\n".utf8)),
         tcp4(51234, 443, seq: 1, ack: 1, flags: 0x18, clientHello(sni: "www.example.com")),
         tcp4(443, 51234, seq: 1, ack: 1, flags: 0x18, serverHello()),
         udp4(53000, 53, dnsQuery("www.example.com")),
         udp4(src: "1.1.1.1", dst: "10.1.0.9", 53, 53000, dnsResponse("www.example.com", address: "93.184.216.34")),
         arp(request: true), arp(request: false), icmpEcho(request: true),
         Data(ether(type: 0x86DD, ipv6(src: v6a, dst: v6b, next: 0, [6, 0, 0, 0, 0, 0, 0, 0] + tcp(40000, 22, flags: 0x02)))),
         udp4(40000, 53, dnsQuery("vlan.example"), tags: [(0x8100, 100)])]
    }
}

final class PacketDecoderTests: XCTestCase {
    private typealias F = PacketFixture

    func testTCPSynWithOptions() {
        let opts = F.synOptions + [0x08, 0x0a] + F.be32(12345) + F.be32(0)
        let data = F.tcp4(51234, 443, seq: 1000, flags: 0x02, options: opts)
        let d = PacketDecoder.decode(data)
        XCTAssertEqual(d.sourceMAC, "00:1c:0e:87:78:01")
        XCTAssertEqual(d.destinationMAC, "aa:bb:cc:dd:ee:ff")
        XCTAssertEqual(d.etherType, 0x0800)
        XCTAssertNil(d.vlan)
        let ip = try! XCTUnwrap(d.ip)
        XCTAssertEqual(ip.version, 4)
        XCTAssertEqual(ip.source, "10.1.0.9")
        XCTAssertEqual(ip.destination, "93.184.216.34")
        XCTAssertEqual(ip.proto, 6)
        XCTAssertEqual(ip.ttl, 64)
        XCTAssertEqual(ip.identification, 0x1234)
        XCTAssertTrue(ip.dontFragment)
        XCTAssertFalse(ip.moreFragments)
        XCTAssertEqual(ip.fragmentOffset, 0)
        XCTAssertEqual(ip.headerLength, 20)
        XCTAssertEqual(ip.dscp, 0)
        let t = try! XCTUnwrap(d.tcp)
        XCTAssertEqual(t.sourcePort, 51234)
        XCTAssertEqual(t.destinationPort, 443)
        XCTAssertEqual(t.sequence, 1000)
        XCTAssertEqual(t.acknowledgment, 0)
        XCTAssertEqual(t.flags, .syn)
        XCTAssertEqual(t.window, 65535)
        XCTAssertEqual(t.headerLength, 40)
        XCTAssertEqual(ip.totalLength, 60)
        XCTAssertEqual(t.payloadLength, 0)
        XCTAssertEqual(t.mss, 1460)
        XCTAssertEqual(t.windowScale, 6)
        XCTAssertTrue(t.sackPermitted)
        XCTAssertEqual(t.sackBlocks, 0)
        XCTAssertEqual(t.timestampValue, 12345)
        XCTAssertEqual(t.timestampEcho, 0)
        XCTAssertEqual(d.payloadOffset, 14 + 20 + 40)
        XCTAssertEqual(d.protocolName, "TCP")
        XCTAssertNil(d.app)
        XCTAssertEqual(d.info, "51234 → 443 [SYN] Seq=1000 Win=65535 Len=0 MSS=1460 WS=64 SACK_PERM TSval=12345 TSecr=0")
        XCTAssertEqual(d.sourcePort, 51234)
        XCTAssertEqual(d.destinationPort, 443)
    }

    func testTCPSynInfoMatchesWireshark() {
        let d = PacketDecoder.decode(F.tcp4(51234, 443, flags: 0x02, options: F.synOptions))
        XCTAssertEqual(d.info, "51234 → 443 [SYN] Seq=0 Win=65535 Len=0 MSS=1460 WS=64 SACK_PERM")
    }

    func testRSTAndSackBlocks() {
        let sack: [UInt8] = [1, 1, 5, 10] + F.be32(100) + F.be32(200)
        let d = PacketDecoder.decode(F.tcp4(443, 51234, seq: 5, ack: 9, flags: 0x10, options: sack))
        XCTAssertEqual(d.tcp?.sackBlocks, 1)
        let rst = PacketDecoder.decode(F.tcp4(443, 51234, seq: 5, ack: 9, flags: 0x14))
        XCTAssertEqual(rst.info, "443 → 51234 [RST, ACK] Seq=5 Ack=9 Win=65535 Len=0")
    }

    func testHTTPGet() {
        let payload = Array("GET /index.html HTTP/1.1\r\nUser-Agent: curl/8\r\nHost: www.example.com\r\nAccept: */*\r\n\r\n".utf8)
        let d = PacketDecoder.decode(F.tcp4(51234, 80, seq: 1, ack: 1, flags: 0x18, payload))
        XCTAssertEqual(d.tcp?.flags, [.psh, .ack])
        XCTAssertEqual(d.tcp?.payloadLength, payload.count)
        XCTAssertEqual(d.app, .httpRequest(method: "GET", path: "/index.html", host: "www.example.com"))
        XCTAssertEqual(d.protocolName, "HTTP")
        XCTAssertEqual(d.info, "GET /index.html HTTP/1.1")
        XCTAssertEqual(d.payloadOffset, 14 + 20 + 20)

        // Any port, by shape.
        let resp = PacketDecoder.decode(F.tcp4(src: "93.184.216.34", dst: "10.1.0.9", 9999, 51234, seq: 1, ack: 1, flags: 0x18,
                                                Array("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".utf8)))
        XCTAssertEqual(resp.app, .httpResponse(status: 404, reason: "Not Found"))
        XCTAssertEqual(resp.info, "HTTP/1.1 404 Not Found")
    }

    func testTLSClientHelloSNI() {
        let d = PacketDecoder.decode(F.tcp4(51234, 443, seq: 1, ack: 1, flags: 0x18, F.clientHello(sni: "www.example.com")))
        XCTAssertEqual(d.app, .tlsClientHello(sni: "www.example.com", version: "TLS 1.3"))
        XCTAssertEqual(d.protocolName, "TLS")
        XCTAssertEqual(d.info, "Client Hello (SNI=www.example.com)")
        // By shape on a non-TLS port.
        let odd = PacketDecoder.decode(F.tcp4(51234, 9443, seq: 1, ack: 1, flags: 0x18, F.clientHello(sni: "odd.example")))
        XCTAssertEqual(odd.app, .tlsClientHello(sni: "odd.example", version: "TLS 1.3"))
        // ServerHello + CCS + Application Data in one segment.
        let sh = PacketDecoder.decode(F.tcp4(src: "93.184.216.34", dst: "10.1.0.9", 443, 51234, seq: 1, ack: 1, flags: 0x18, F.serverHello()))
        XCTAssertEqual(sh.app, .tlsServerHello(version: "TLS 1.3"))
        XCTAssertEqual(sh.info, "Server Hello, Change Cipher Spec, Application Data")
        let ad = PacketDecoder.decode(F.tcp4(443, 51234, seq: 1, ack: 1, flags: 0x18, [0x17, 0x03, 0x03, 0x00, 0x02, 9, 9]))
        XCTAssertEqual(ad.app, .tlsOther(recordType: "Application Data"))
    }

    func testDNSQueryAndResponse() {
        let q = PacketDecoder.decode(F.udp4(53000, 53, F.dnsQuery("www.example.com")))
        XCTAssertEqual(q.app, .dns(query: "www.example.com", isResponse: false, answers: 0, rcode: 0))
        XCTAssertEqual(q.protocolName, "DNS")
        XCTAssertEqual(q.info, "Standard query 0x1a2b A www.example.com")
        XCTAssertEqual(q.udp?.sourcePort, 53000)
        XCTAssertEqual(q.udp?.payloadLength, F.dnsQuery("www.example.com").count)

        let r = PacketDecoder.decode(F.udp4(src: "1.1.1.1", dst: "10.1.0.9", 53, 53000,
                                            F.dnsResponse("www.example.com", address: "93.184.216.34")))
        XCTAssertEqual(r.app, .dns(query: "www.example.com", isResponse: true, answers: 1, rcode: 0))
        XCTAssertEqual(r.info, "Standard query response 0x1a2b A www.example.com A 93.184.216.34")
    }

    func testARP() {
        let req = PacketDecoder.decode(F.arp(request: true))
        XCTAssertEqual(req.protocolName, "ARP")
        XCTAssertEqual(req.arp, ARPInfo(isRequest: true, senderMAC: "00:1c:0e:87:78:01", senderIP: "10.1.0.9",
                                        targetMAC: "00:00:00:00:00:00", targetIP: "10.1.0.1"))
        XCTAssertEqual(req.info, "Who has 10.1.0.1? Tell 10.1.0.9")
        XCTAssertEqual(req.source, "10.1.0.9")
        XCTAssertEqual(req.destination, "10.1.0.1")
        let rep = PacketDecoder.decode(F.arp(request: false, senderMAC: F.macB, senderIP: "10.1.0.1", targetMAC: F.macA, targetIP: "10.1.0.9"))
        XCTAssertEqual(rep.info, "10.1.0.1 is at aa:bb:cc:dd:ee:ff")
    }

    func testICMPEcho() {
        let d = PacketDecoder.decode(F.icmpEcho(request: true))
        XCTAssertEqual(d.protocolName, "ICMP")
        XCTAssertEqual(d.icmp, ICMPHeader(type: 8, code: 0, identifier: 0x1234, sequence: 1))
        XCTAssertEqual(d.info, "Echo (ping) request id=0x1234 seq=1 ttl=64")
        let unreach = PacketDecoder.decode(Data(F.ether(type: 0x0800, F.ipv4(src: "10.1.0.1", dst: "10.1.0.9", proto: 1,
            [3, 3, 0, 0, 0, 0, 0, 0] + F.ipv4(src: "10.1.0.9", dst: "10.1.0.1", proto: 17, F.udp(40000, 33434, []))))))
        XCTAssertEqual(unreach.info, "Destination unreachable (Port unreachable) for 10.1.0.9:40000 → 10.1.0.1:33434 UDP")
    }

    func testIPv6TCPWithExtensionHeader() {
        let hopByHop: [UInt8] = [6, 0, 0, 0, 0, 0, 0, 0]
        let frame = F.ether(type: 0x86DD, F.ipv6(src: F.v6a, dst: F.v6b, next: 0, hop: 57,
                                                 hopByHop + F.tcp(40000, 22, seq: 7, flags: 0x02, options: F.synOptions)))
        let d = PacketDecoder.decode(Data(frame))
        let ip = try! XCTUnwrap(d.ip)
        XCTAssertEqual(ip.version, 6)
        XCTAssertEqual(ip.source, "2001:db8::1")
        XCTAssertEqual(ip.destination, "2001:db8::2")
        XCTAssertEqual(ip.proto, 6)
        XCTAssertEqual(ip.ttl, 57)
        XCTAssertEqual(ip.headerLength, 48)
        XCTAssertEqual(d.tcp?.destinationPort, 22)
        XCTAssertEqual(d.tcp?.mss, 1460)
        XCTAssertEqual(d.info, "40000 → 22 [SYN] Seq=7 Win=65535 Len=0 MSS=1460 WS=64 SACK_PERM")
        XCTAssertEqual(d.payloadOffset, 14 + 48 + 32)

        // ICMPv6 Neighbor Solicitation
        let ns: [UInt8] = [135, 0, 0, 0, 0, 0, 0, 0] + F.v6b
        let nd = PacketDecoder.decode(Data(F.ether(type: 0x86DD, F.ipv6(src: F.v6a, dst: F.v6b, next: 58, hop: 255, ns))))
        XCTAssertEqual(nd.protocolName, "ICMPv6")
        XCTAssertEqual(nd.info, "Neighbor Solicitation for 2001:db8::2")
    }

    func testIPv6Formatting() {
        func fmt(_ b: [UInt8]) -> String { b.withUnsafeBytes { PacketFormat.ipv6(PacketBytes(p: $0), 0) } }
        XCTAssertEqual(fmt([0xfe, 0x80] + [UInt8](repeating: 0, count: 13) + [1]), "fe80::1")
        XCTAssertEqual(fmt([UInt8](repeating: 0, count: 16)), "::")
        XCTAssertEqual(fmt([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1]), "2001:db8:0:1::1")
        XCTAssertEqual(fmt([0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1]), "2001:db8:1:0:1::1")
        XCTAssertEqual(fmt([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 1, 0, 1]), "::ffff:10.1.0.1")
    }

    func testVLANTagged() {
        let d = PacketDecoder.decode(F.udp4(40000, 53, F.dnsQuery("vlan.example"), tags: [(0x8100, 100)]))
        XCTAssertEqual(d.vlan, 100)
        XCTAssertEqual(d.etherType, 0x0800)
        XCTAssertEqual(d.ip?.source, "10.1.0.9")
        XCTAssertEqual(d.app, .dns(query: "vlan.example", isResponse: false, answers: 0, rcode: 0))
        XCTAssertEqual(d.payloadOffset, 18 + 20 + 8)

        let qinq = PacketDecoder.decode(F.udp4(40000, 53, F.dnsQuery("qinq.example"), tags: [(0x88A8, 200), (0x8100, 100)]))
        XCTAssertEqual(qinq.vlan, 200)
        XCTAssertEqual(qinq.protocolName, "DNS")
        XCTAssertTrue(qinq.info.hasPrefix("Standard query 0x1a2b A qinq.example"))
        XCTAssertTrue(qinq.info.hasSuffix("inner VLAN 100]"))
    }

    func testTruncatedPacket() {
        let full = F.tcp4(51234, 443, seq: 1, ack: 1, flags: 0x18, F.clientHello(sni: "www.example.com"))
        // Cut inside the TCP header: IP decodes, TCP does not.
        let cut = PacketDecoder.decode(full.prefix(14 + 20 + 10))
        XCTAssertEqual(cut.ip?.destination, "93.184.216.34")
        XCTAssertNil(cut.tcp)
        XCTAssertEqual(cut.protocolName, "TCP")
        XCTAssertTrue(cut.info.contains("Truncated"))
        // Cut inside the ClientHello (snaplen): TCP keeps the wire length, TLS still recognised.
        let snap = PacketDecoder.decode(full.prefix(14 + 20 + 20 + 30))
        XCTAssertEqual(snap.tcp?.payloadLength, F.clientHello(sni: "www.example.com").count)
        XCTAssertEqual(snap.protocolName, "TLS")
        // Every prefix of every fixture decodes without trapping.
        for f in PacketFixture.all() {
            for n in 0...f.count { _ = PacketDecoder.decode(f.prefix(n)) }
        }
        // A Data slice with a non-zero start index.
        let slice = (Data([1, 2, 3]) + full).dropFirst(3)
        XCTAssertEqual(PacketDecoder.decode(slice).app, .tlsClientHello(sni: "www.example.com", version: "TLS 1.3"))
    }

    func testOtherProtocols() {
        // LLDP
        let chassis: [UInt8] = F.be16(1 << 9 | 7) + [4] + F.macA
        let port: [UInt8] = F.be16(2 << 9 | 7) + [5] + Array("1/1/24".utf8)
        let ttl: [UInt8] = F.be16(3 << 9 | 2) + [0, 120]
        let sys: [UInt8] = F.be16(5 << 9 | 12) + Array("CORE-CX-6300".utf8)
        let lldp = PacketDecoder.decode(Data(F.ether(dst: [0x01, 0x80, 0xc2, 0, 0, 0x0e], type: 0x88CC,
                                                     chassis + port + ttl + sys + [0, 0])))
        XCTAssertEqual(lldp.protocolName, "LLDP")
        XCTAssertEqual(lldp.info, "Chassis 00:1c:0e:87:78:01 Port 1/1/24 Sys CORE-CX-6300")

        // STP (802.3 + LLC 0x42)
        var bpdu: [UInt8] = [0x42, 0x42, 0x03, 0, 0, 0, 0, 0] + F.be16(32768) + F.macA + F.be32(4) + F.be16(32768) + F.macB + F.be16(0x8004)
        bpdu += [0, 0, 0x14, 0, 2, 0, 0x0f, 0]
        let stp = PacketDecoder.decode(Data(F.ether(dst: [0x01, 0x80, 0xc2, 0, 0, 0], type: bpdu.count, bpdu)))
        XCTAssertEqual(stp.protocolName, "STP")
        XCTAssertEqual(stp.info, "STP Conf. Root=32768/0/00:1c:0e:87:78:01 Cost=4 Port=0x8004")

        // Syslog
        let sl = PacketDecoder.decode(F.udp4(514, 514, Array("<189>Oct 11 22:14:15 sw1 %LINK-3-UPDOWN: Interface Gi0/1, changed state to down".utf8)))
        XCTAssertEqual(sl.protocolName, "Syslog")
        guard case .syslog(let pri, _) = sl.app else { return XCTFail("syslog") }
        XCTAssertEqual(pri, 189)
        XCTAssertTrue(sl.info.hasPrefix("LOCAL7.NOTICE: Oct 11 22:14:15 sw1"))

        // SNMP v2c get-request
        let oid: [UInt8] = [0x06, 0x08, 0x2b, 6, 1, 2, 1, 1, 1, 0]
        let vb: [UInt8] = [0x30, UInt8(oid.count + 2)] + oid + [0x05, 0x00]
        let vbl: [UInt8] = [0x30, UInt8(vb.count)] + vb
        let pduBody: [UInt8] = [0x02, 0x01, 0x2a, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00] + vbl
        let pdu: [UInt8] = [0xA0, UInt8(pduBody.count)] + pduBody
        let msgBody: [UInt8] = [0x02, 0x01, 0x01, 0x04, 0x06] + Array("public".utf8) + pdu
        let snmp = PacketDecoder.decode(F.udp4(40000, 161, [0x30, UInt8(msgBody.count)] + msgBody))
        XCTAssertEqual(snmp.app, .snmp(version: "v2c", community: "public", pduType: "get-request"))
        XCTAssertEqual(snmp.info, "get-request 1.3.6.1.2.1.1.1.0")

        // DHCP Discover
        var bootp: [UInt8] = [1, 1, 6, 0] + F.be32(0xdeadbeef) + [UInt8](repeating: 0, count: 20) + F.macA
        bootp += [UInt8](repeating: 0, count: 236 - bootp.count)
        bootp += F.be32(0x63825363) + [53, 1, 1, 255]
        let dhcp = PacketDecoder.decode(F.udp4(src: "0.0.0.0", dst: "255.255.255.255", 68, 67, bootp))
        XCTAssertEqual(dhcp.app, .dhcp(messageType: "Discover", clientMAC: "00:1c:0e:87:78:01", yourIP: nil))
        XCTAssertEqual(dhcp.info, "DHCP Discover - Transaction ID 0xdeadbeef")

        // RADIUS Access-Request
        let user: [UInt8] = [1, 5] + Array("bob".utf8)
        let rad: [UInt8] = [1, 7] + F.be16(20 + user.count) + [UInt8](repeating: 0, count: 16) + user
        let radius = PacketDecoder.decode(F.udp4(40000, 1812, rad))
        XCTAssertEqual(radius.app, .radius(code: "Access-Request", id: 7))
        XCTAssertEqual(radius.info, "Access-Request id=7 User-Name=bob")

        // NTP client
        let ntp = PacketDecoder.decode(F.udp4(123, 123, [0x23] + [UInt8](repeating: 0, count: 47)))
        XCTAssertEqual(ntp.app, .ntp)
        XCTAssertEqual(ntp.info, "NTP Version 4, client")

        // SSH banner
        let ssh = PacketDecoder.decode(F.tcp4(22, 51000, seq: 1, ack: 1, flags: 0x18, Array("SSH-2.0-OpenSSH_9.8\r\n".utf8)))
        XCTAssertEqual(ssh.app, .ssh(banner: "SSH-2.0-OpenSSH_9.8"))

        // Unknown EtherType
        let other = PacketDecoder.decode(Data(F.ether(type: 0x88b5, [1, 2, 3])))
        XCTAssertEqual(other.info, "0x88b5")
    }

    func testOtherLinkTypes() {
        let ip = F.ipv4(proto: 17, F.udp(40000, 53, F.dnsQuery("null.example")))
        let null = PacketDecoder.decode(Data([2, 0, 0, 0] + ip), linkType: 0)
        XCTAssertEqual(null.app, .dns(query: "null.example", isResponse: false, answers: 0, rcode: 0))
        let raw = PacketDecoder.decode(Data(ip), linkType: 12)
        XCTAssertEqual(raw.ip?.source, "10.1.0.9")
        let sll: [UInt8] = F.be16(0) + F.be16(1) + F.be16(6) + F.macA + [0, 0] + F.be16(0x0800)
        let cooked = PacketDecoder.decode(Data(sll + ip), linkType: 113)
        XCTAssertEqual(cooked.sourceMAC, "00:1c:0e:87:78:01")
        XCTAssertEqual(cooked.udp?.destinationPort, 53)
    }

    func testFuzzRandomBuffers() {
        var rng = SplitMix(seed: 0x5eed_1e55)
        let linkTypes: [Int32] = [1, 1, 1, 0, 108, 113, 276, 12, 101, 228, 229, 147]
        for _ in 0..<5_000 {
            let n = Int(rng.next() % 1600)
            var bytes = [UInt8](repeating: 0, count: n)
            for i in 0..<n { bytes[i] = UInt8(truncatingIfNeeded: rng.next()) }
            // Bias some buffers towards plausible headers so the deep paths run.
            if n > 40, rng.next() % 2 == 0 {
                bytes[12] = 0x08; bytes[13] = rng.next() % 3 == 0 ? 0x06 : 0x00
                bytes[14] = 0x45
            }
            let lt = linkTypes[Int(rng.next() % UInt64(linkTypes.count))]
            _ = PacketDecoder.decode(Data(bytes), linkType: lt)
        }
        // Mutations of every real fixture.
        let fixtures = PacketFixture.all()
        for _ in 0..<5_000 {
            var f = [UInt8](fixtures[Int(rng.next() % UInt64(fixtures.count))])
            for _ in 0..<(1 + Int(rng.next() % 8)) where !f.isEmpty {
                f[Int(rng.next() % UInt64(f.count))] = UInt8(truncatingIfNeeded: rng.next())
            }
            if rng.next() % 3 == 0 { f = Array(f.prefix(Int(rng.next() % UInt64(f.count + 1)))) }
            _ = PacketDecoder.decode(Data(f))
        }
    }

    // MARK: Hostile bytes

    /// One named hostile frame per suspected trap. None may crash, and each must still say
    /// something sensible about the layers that are well formed.
    func testHostileFrames() {
        let tcpSyn = F.tcp(51234, 443, flags: 0x02)
        func eth(_ type: Int, _ payload: [UInt8]) -> Data { Data(F.ether(type: type, payload)) }
        func v4(_ ihlWords: UInt8, total: Int, _ rest: [UInt8]) -> [UInt8] {
            var h = F.ipv4(proto: 6, rest)
            h[0] = 0x40 | ihlWords
            h[2] = UInt8(total >> 8); h[3] = UInt8(total & 0xff)
            return h
        }

        // IPv4 IHL < 5: the IP header is reported bogus, nothing above it is decoded.
        for ihl: UInt8 in 0..<5 {
            let d = PacketDecoder.decode(eth(0x0800, v4(ihl, total: 40, tcpSyn)))
            XCTAssertEqual(d.protocolName, "IPv4")
            XCTAssertNil(d.tcp)
            XCTAssertTrue(d.info.contains("Bogus IPv4 header length"), d.info)
        }
        // Total length smaller than the header is bogus (the Ethernet padding is not payload);
        // 0 is TCP segmentation offload: the captured bytes are the datagram.
        let small = PacketDecoder.decode(eth(0x0800, v4(5, total: 12, tcpSyn)))
        XCTAssertNil(small.tcp)
        XCTAssertTrue(small.info.contains("Bogus IPv4 total length"), small.info)
        let tso = PacketDecoder.decode(Data(F.ether(type: 0x0800, v4(5, total: 0, tcpSyn + [UInt8](repeating: 0x41, count: 3000)))))
        XCTAssertEqual(tso.tcp?.payloadLength, 3000)
        // IHL past the end of the frame.
        XCTAssertNil(PacketDecoder.decode(Data(F.ether(type: 0x0800, v4(15, total: 60, tcpSyn)).prefix(14 + 30))).tcp)

        // IPv6: a Hop-by-Hop header whose next header is Hop-by-Hop again, forever.
        var loop: [UInt8] = []
        for _ in 0..<40 { loop += [0, 0, 0, 0, 0, 0, 0, 0] }
        let v6loop = PacketDecoder.decode(eth(0x86DD, F.ipv6(src: F.v6a, dst: F.v6b, next: 0, loop + tcpSyn)))
        XCTAssertEqual(v6loop.ip?.version, 6)
        XCTAssertNil(v6loop.tcp)
        // An extension header length pointing far past the frame.
        let v6far = PacketDecoder.decode(eth(0x86DD, F.ipv6(src: F.v6a, dst: F.v6b, next: 60, [6, 255, 0, 0, 0, 0, 0, 0] + tcpSyn)))
        XCTAssertEqual(v6far.ip?.proto, 6)
        XCTAssertNil(v6far.tcp)

        // TCP data offset < 5, and past the end of the frame.
        for doff: UInt8 in [0, 1, 4, 15] {
            var t = tcpSyn
            t[12] = doff << 4
            let d = PacketDecoder.decode(eth(0x0800, F.ipv4(proto: 6, t)))
            XCTAssertEqual(d.tcp?.sourcePort, 51234)
            if doff < 5 { XCTAssertTrue(d.info.contains("bogus header length"), d.info) }
        }
        // TCP options with length 0 and 1 (a naive walker never advances), a SACK option whose
        // length claims more blocks than the header holds, and an option running past the header.
        for opts: [UInt8] in [[2, 0, 5, 0xb4], [2, 1, 5, 0xb4], [5, 34, 0, 0, 0, 0, 0, 0], [3, 3], [8, 10, 0, 0], [5]] {
            let d = PacketDecoder.decode(F.tcp4(51234, 443, flags: 0x10, options: opts))
            XCTAssertEqual(d.tcp?.destinationPort, 443)
            XCTAssertEqual(d.tcp?.sackBlocks, 0)
        }

        // DNS: a compression pointer to itself, a pointer loop of two, a pointer past the end,
        // a label longer than 63, a label running past the end, a reserved label type.
        let header: [UInt8] = F.be16(0x1a2b) + [0x01, 0x00] + F.be16(1) + F.be16(0) + F.be16(0) + F.be16(0)
        let names: [[UInt8]] = [[0xc0, 12], [0xc0, 14, 0xc0, 12], [0xc0, 0xff], [0x40] + [UInt8](repeating: 0x61, count: 64) + [0],
                                [0x3f, 0x61, 0x61], [0x80, 0x01, 0]]
        for n in names {
            let d = PacketDecoder.decode(F.udp4(53000, 53, header + n + F.be16(1) + F.be16(1)))
            XCTAssertEqual(d.udp?.destinationPort, 53)
            XCTAssertNotEqual(d.protocolName, "DNS", "a malformed query name is not a DNS query: \(n)")
        }
        // A response whose answer name points at itself.
        var resp = F.dnsResponse("www.example.com", address: "10.1.1.1")
        resp[resp.count - 16] = 0xc0; resp[resp.count - 15] = UInt8(resp.count - 16)
        XCTAssertEqual(PacketDecoder.decode(F.udp4(53, 53000, resp)).protocolName, "DNS")

        // TLS: extensions length far past the record, SNI length past the extension.
        var hello = F.clientHello(sni: "www.example.com")
        let extLenAt = 5 + 4 + 2 + 32 + 1 + 32 + 2 + 4 + 2
        hello[extLenAt] = 0xff; hello[extLenAt + 1] = 0xff
        XCTAssertEqual(PacketDecoder.decode(F.tcp4(51234, 443, seq: 1, ack: 1, flags: 0x18, hello)).protocolName, "TLS")
        var hello2 = F.clientHello(sni: "www.example.com")
        if let at = hello2.indices.dropLast(5).first(where: { hello2[$0] == 0 && hello2[$0 + 1] == 0 && hello2[$0 + 2] == 0 && hello2[$0 + 3] == 20 }) {
            hello2[at + 3] = 0xff
        }
        XCTAssertEqual(PacketDecoder.decode(F.tcp4(51234, 443, seq: 1, ack: 1, flags: 0x18, hello2)).protocolName, "TLS")
        // A record length of 0 and a handshake length larger than the record.
        _ = PacketDecoder.decode(F.tcp4(51234, 443, seq: 1, ack: 1, flags: 0x18, [0x16, 3, 1, 0, 0, 0x16, 3, 1, 0, 4, 1, 0xff, 0xff, 0xff]))

        // HTTP request line with no space, and a method word alone.
        for text in ["GET", "GET\r\n", "GET/index.html\r\n\r\n", "GET ", "HTTP/1.1", "HTTP/1.1 abc\r\n"] {
            let d = PacketDecoder.decode(F.tcp4(51234, 80, seq: 1, ack: 1, flags: 0x18, Array(text.utf8)))
            XCTAssertEqual(d.tcp?.destinationPort, 80, text)
            // Not a request or response line: bytes on an HTTP port, "continuation" like
            // tcpdump / Wireshark per packet, with no request for the flow analysis.
            XCTAssertNil(d.app, text)
            XCTAssertTrue(d.info.hasPrefix("[Continuation] "), text)
        }

        // DHCP option length past the end.
        var bootp: [UInt8] = [1, 1, 6, 0] + F.be32(1) + [UInt8](repeating: 0, count: 228)
        bootp += F.be32(0x63825363) + [53, 200, 1]
        XCTAssertEqual(PacketDecoder.decode(F.udp4(68, 67, bootp)).protocolName, "DHCP")

        // ARP with a hardware length of 8 and a protocol length of 16.
        var arp = [UInt8](F.arp(request: true))
        arp[14 + 4] = 8; arp[14 + 5] = 16
        let a = PacketDecoder.decode(Data(arp))
        XCTAssertEqual(a.protocolName, "ARP")
        XCTAssertNil(a.arp)

        // A VLAN tag on a 16-byte frame, and 802.1Q nesting beyond the four-tag cap.
        let vlan16 = Data(F.macB + F.macA + [0x81, 0x00, 0x00, 0x64])
        XCTAssertNil(PacketDecoder.decode(vlan16).vlan)
        XCTAssertEqual(PacketDecoder.decode(vlan16).protocolName, "802.1Q")
        var deep: [UInt8] = F.macB + F.macA
        for _ in 0..<40 { deep += [0x81, 0x00, 0x00, 0x05] }
        XCTAssertEqual(PacketDecoder.decode(Data(deep)).vlan, 5)

        // Linux cooked with protocol 0 and the other sub-0x0600 "protocols" (1 = 802.3,
        // 4 = 802.2 LLC): never an "Ethernet 0x0000" row.
        for proto in [0, 1, 2, 3, 4] {
            let sll: [UInt8] = F.be16(0) + F.be16(1) + F.be16(6) + F.macA + [0, 0] + F.be16(proto)
            var bpdu: [UInt8] = [0x42, 0x42, 0x03, 0, 0, 0, 0, 0] + F.be16(32768) + F.macA + F.be32(4) + F.be16(32768) + F.macB + F.be16(0x8004)
            bpdu += [0, 0, 0x14, 0, 2, 0, 0x0f, 0]
            let d = PacketDecoder.decode(Data(sll + bpdu), linkType: 113)
            XCTAssertNotEqual(d.info, "0x" + String(format: "%04x", proto), "SLL protocol \(proto)")
            if proto == 4 { XCTAssertEqual(d.protocolName, "STP") }
        }

        // A zero-length packet, on every link type.
        for lt: Int32 in [0, 1, 12, 101, 108, 113, 147, 228, 229, 276] {
            XCTAssertEqual(PacketDecoder.decode(Data(), linkType: lt).info, "Empty frame")
        }

        // The largest snap length (262,144 bytes): a TCP segment claiming a 64 KB IP datagram.
        var huge = [UInt8](F.tcp4(51234, 80, seq: 1, ack: 1, flags: 0x18, Array("GET / HTTP/1.1\r\n".utf8)))
        huge[16] = 0xff; huge[17] = 0xff
        huge += [UInt8](repeating: 0x41, count: 262_144 - huge.count)
        let h = PacketDecoder.decode(Data(huge))
        XCTAssertEqual(h.tcp?.payloadLength, 65_535 - 40)
        XCTAssertEqual(h.protocolName, "HTTP")
        // …and the same size read as a pile of 802.1Q tags / LLC / garbage.
        _ = PacketDecoder.decode(Data([UInt8](repeating: 0x81, count: 262_144)))
        _ = PacketDecoder.decode(Data([UInt8](repeating: 0x00, count: 262_144)))
        _ = PacketDecoder.decode(Data([UInt8](repeating: 0xff, count: 262_144)), linkType: 113)
    }

    /// The layers of `full` that fit in `n` bytes decode identically from the first `n` bytes.
    private func assertPrefixConsistent(_ full: Data, _ n: Int, file: StaticString = #filePath, line: UInt = #line) {
        let whole = PacketDecoder.decode(full)
        let cut = PacketDecoder.decode(full.prefix(n))
        guard n >= 14 else { return }
        XCTAssertEqual(cut.destinationMAC, whole.destinationMAC, file: file, line: line)
        XCTAssertEqual(cut.sourceMAC, whole.sourceMAC, file: file, line: line)
        // Where layer 3 starts: after the Ethernet header and its VLAN tags.
        let b = [UInt8](full)
        var l3 = 14
        var type = Int(b[12]) << 8 | Int(b[13])
        var tags = 0
        while type == 0x8100 || type == 0x88A8 || type == 0x9100, tags < 4, b.count >= l3 + 4 {
            type = Int(b[l3 + 2]) << 8 | Int(b[l3 + 3])
            l3 += 4; tags += 1
        }
        guard n >= l3 else { return }
        XCTAssertEqual(cut.vlan, whole.vlan, file: file, line: line)
        XCTAssertEqual(cut.etherType, whole.etherType, file: file, line: line)
        if let ip = whole.ip {
            guard n >= l3 + max(ip.version == 4 ? 20 : 40, ip.headerLength) else { return }
            XCTAssertEqual(cut.ip, ip, "IP at \(n) of \(full.count)", file: file, line: line)
            let l4 = l3 + ip.headerLength
            // Without a usable IP length the payload length comes from the captured bytes.
            let lengthKnown = ip.version == 4 ? ip.totalLength >= ip.headerLength && ip.totalLength > 0 : ip.totalLength > 40
            if let t = whole.tcp, n >= l4 + max(20, t.headerLength), lengthKnown {
                XCTAssertEqual(cut.tcp, t, "TCP at \(n) of \(full.count)", file: file, line: line)
            }
            if let u = whole.udp, n >= l4 + 8, u.length >= 8 || lengthKnown {
                XCTAssertEqual(cut.udp, u, "UDP at \(n) of \(full.count)", file: file, line: line)
            }
            if let i = whole.icmp, n >= l4 + 8 {
                XCTAssertEqual(cut.icmp, i, "ICMP at \(n) of \(full.count)", file: file, line: line)
            }
        }
        if let a = whole.arp, n >= l3 + 28 {
            XCTAssertEqual(cut.arp, a, file: file, line: line)
        }
    }

    /// Every prefix of every fixture, and 20,000 random mutations of real frames (each also cut
    /// at a random length): no trap, and the layers that fit agree with the whole frame.
    func testFuzzPrefixesAndMutations() {
        let fixtures = PacketFixture.all() + [
            F.tcp4(51234, 443, seq: 1, ack: 1, flags: 0x10, options: [1, 1, 5, 10] + F.be32(100) + F.be32(200)),
            F.tcp4(51234, 443, seq: 1000, flags: 0x02, options: F.synOptions + [0x08, 0x0a] + F.be32(12345) + F.be32(0)),
            Data(F.ether(type: 0x86DD, F.ipv6(src: F.v6a, dst: F.v6b, next: 58, hop: 255, [135, 0, 0, 0, 0, 0, 0, 0] + F.v6b))),
            Data(F.ether(type: 0x0800, F.ipv4(src: "10.1.0.1", dst: "10.1.0.9", proto: 1,
                [3, 3, 0, 0, 0, 0, 0, 0] + F.ipv4(src: "10.1.0.9", dst: "10.1.0.1", proto: 17, F.udp(40000, 33434, []))))),
        ]
        for f in fixtures {
            for n in 0...f.count { assertPrefixConsistent(f, n) }
        }
        var rng = SplitMix(seed: 0xfeed_beef)
        var failures = 0
        for _ in 0..<20_000 {
            var f = [UInt8](fixtures[Int(rng.next() % UInt64(fixtures.count))])
            for _ in 0..<(1 + Int(rng.next() % 6)) where f.count > 14 {
                // Leave the Ethernet addresses alone so the frame stays Ethernet-shaped more often.
                let i = 12 + Int(rng.next() % UInt64(f.count - 12))
                f[i] = rng.next() % 4 == 0 ? [0, 1, 0xff, 0x7f, 0x80][Int(rng.next() % 5)] : UInt8(truncatingIfNeeded: rng.next())
            }
            let n = Int(rng.next() % UInt64(f.count + 1))
            let before = testRun?.failureCount ?? 0
            assertPrefixConsistent(Data(f), n)
            if (testRun?.failureCount ?? 0) > before {
                failures += 1
                if failures == 1 { print("[fuzz] first inconsistent frame (cut at \(n)): \(f.map { String(format: "%02x", $0) }.joined())") }
                if failures > 5 { break }
            }
        }
    }

    /// The hex dump of a 256 KB frame: offsets past 0xffff do not wrap, blocks join up exactly.
    @MainActor
    func testHexDumpOfHugeFrame() {
        let data = Data((0..<262_144).map { UInt8(truncatingIfNeeded: $0) })
        let whole = PacketHexView.dump(data)
        let lines = whole.split(separator: "\n")
        XCTAssertEqual(lines.count, 16_384)
        XCTAssertTrue(lines[0].hasPrefix("00000  00 01 02"), String(lines[0]))
        XCTAssertTrue(lines[4_096].hasPrefix("10000  00 01 02"), String(lines[4_096]))
        XCTAssertTrue(lines.last!.hasPrefix("3fff0  f0 f1"), String(lines.last!))
        var joined: [String] = []
        for b in 0..<(16_384 / PacketHexView.blockLines) {
            joined.append(PacketHexView.dump(data, lines: b * PacketHexView.blockLines..<(b + 1) * PacketHexView.blockLines))
        }
        XCTAssertEqual(joined.joined(separator: "\n"), whole)
        XCTAssertTrue(PacketHexView.dump(Data([0x41, 0x42])).hasPrefix("0000  41 42"))
    }

    func testDecodeSpeed() {
        let fixtures = PacketFixture.all()
        let start = Date()
        var n = 0
        for _ in 0..<10_000 { for f in fixtures { n += PacketDecoder.decode(f).info.count } }
        let perPacket = Date().timeIntervalSince(start) / Double(10_000 * fixtures.count)
        print("[timing] decode: \(String(format: "%.2f", perPacket * 1_000_000)) µs/packet")
        XCTAssertGreaterThan(n, 0)
    }
}

/// Deterministic generator for the fuzz test.
struct SplitMix: RandomNumberGenerator {
    var state: UInt64
    init(seed: UInt64) { state = seed }
    mutating func next() -> UInt64 {
        state &+= 0x9e3779b97f4a7c15
        var z = state
        z = (z ^ (z >> 30)) &* 0xbf58476d1ce4e5b9
        z = (z ^ (z >> 27)) &* 0x94d049bb133111eb
        return z ^ (z >> 31)
    }
}
