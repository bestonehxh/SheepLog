import XCTest
@testable import SheepLog

/// Ground truth for the decoder: real captures (Tests/pcaps, recorded on en0 / lo0 while
/// generating the traffic named in each file) read through `PcapFile.read`, and every packet
/// compared field by field with `tcpdump -nn -tt -e -vv` — frame length, VLAN, addresses, ports,
/// TCP flags and payload length, DNS query name, HTTP request / status line, ICMP type / id / seq,
/// SNMP version and PDU, syslog PRI, SSH banner, ARP — and, when Wireshark is installed, with
/// tshark's Protocol column and TLS SNI (desegmentation off, so both look at one packet at a time).
///
/// Extra captures are compared when present: `/tmp/c1.pcap` … `/tmp/c9.pcap` (the larger
/// recordings of the review that are not committed) and every path in `SHEEPLOG_PCAPS`
/// (colon-separated; pass it as `TEST_RUNNER_SHEEPLOG_PCAPS=…` to xcodebuild).
///
/// The mismatches of each file are written to `$TMPDIR/SheepLog-groundtruth-<file>.txt`.
final class CaptureGroundTruthTests: XCTestCase {
    private typealias F = PacketFixture

    static let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
    static let pcapDir = repo.appending(path: "Tests/pcaps")
    static let tcpdump = "/usr/sbin/tcpdump"
    static let tshark: String? = ["/Applications/Wireshark.app/Contents/MacOS/tshark", "/opt/homebrew/bin/tshark",
                                  "/usr/local/bin/tshark", "/usr/bin/tshark"]
        .first { FileManager.default.isExecutableFile(atPath: $0) }

    // MARK: Tests

    func testCommittedCapturesMatchTcpdump() throws {
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: Self.tcpdump), "tcpdump not installed")
        let files = try FileManager.default.contentsOfDirectory(at: Self.pcapDir, includingPropertiesForKeys: nil)
            .filter { ["pcap", "pcapng"].contains($0.pathExtension) }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
        XCTAssertGreaterThanOrEqual(files.count, 5, "Tests/pcaps is missing its captures")
        var total = 0
        for url in files {
            let r = try compare(url)
            total += r.packets
            XCTAssertEqual(r.mismatches.count, 0, "\(url.lastPathComponent): \(r.mismatches.prefix(12).joined(separator: "\n"))")
        }
        XCTAssertGreaterThan(total, 300)
    }

    func testLocalRecordingsMatchTcpdump() throws {
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: Self.tcpdump), "tcpdump not installed")
        var paths = (1...9).map { "/tmp/c\($0).pcap" }
        if let extra = ProcessInfo.processInfo.environment["SHEEPLOG_PCAPS"] {
            paths += extra.split(separator: ":").map(String.init)
        }
        let present = paths.filter { FileManager.default.fileExists(atPath: $0) }
        try XCTSkipIf(present.isEmpty, "no local recordings")
        for path in present {
            let r = try compare(URL(fileURLWithPath: path))
            XCTAssertEqual(r.mismatches.count, 0, "\(path): \(r.mismatches.prefix(12).joined(separator: "\n"))")
        }
    }

    /// No 802.1Q on this Mac's Wi-Fi: frames with one tag, QinQ (0x88a8 + 0x8100) and the old
    /// 0x9100 outer TPID, carrying TCP / UDP DNS / ARP / ICMPv6, written as a pcap and compared.
    func testCraftedVLANCaptureMatchesTcpdump() throws {
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: Self.tcpdump), "tcpdump not installed")
        let frames: [Data] = [
            Data(F.ether(type: 0x0800, tags: [(0x8100, 100)],
                         F.ipv4(src: "10.100.0.5", dst: "10.100.0.1", proto: 6, F.tcp(51000, 22, seq: 7, flags: 0x02, options: F.synOptions)))),
            Data(F.ether(dst: F.macA, src: F.macB, type: 0x0800, tags: [(0x8100, 100)],
                         F.ipv4(src: "10.100.0.1", dst: "10.100.0.5", proto: 6, F.tcp(22, 51000, seq: 99, ack: 8, flags: 0x12, options: F.synOptions)))),
            Data(F.ether(type: 0x0800, tags: [(0x8100, 20)],
                         F.ipv4(src: "10.20.0.9", dst: "10.20.0.1", proto: 17, F.udp(53001, 53, F.dnsQuery("vlan20.example"))))),
            Data(F.ether(dst: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff], type: 0x0806, tags: [(0x8100, 30)],
                         F.be16(1) + F.be16(0x0800) + [6, 4] + F.be16(1) + F.macA + F.ip4("10.30.0.9") + [0, 0, 0, 0, 0, 0] + F.ip4("10.30.0.1"))),
            Data(F.ether(type: 0x86DD, tags: [(0x8100, 40)],
                         F.ipv6(src: F.v6a, dst: F.v6b, next: 58, [128, 0, 0, 0] + F.be16(0x77) + F.be16(3) + [UInt8](repeating: 0x61, count: 16)))),
            Data(F.ether(type: 0x0800, tags: [(0x88A8, 200), (0x8100, 10)],
                         F.ipv4(src: "10.10.0.9", dst: "10.10.0.1", proto: 17, F.udp(53002, 53, F.dnsQuery("qinq.example"))))),
            Data(F.ether(type: 0x0800, tags: [(0x9100, 300), (0x8100, 31)],
                         F.ipv4(src: "10.31.0.9", dst: "10.31.0.1", proto: 17, F.udp(53003, 53, F.dnsQuery("q9100.example"))))),
            Data(F.ether(type: 0x0800, tags: [(0x8100, 4094)],
                         F.ipv4(src: "10.94.0.9", dst: "10.94.0.1", proto: 6,
                                F.tcp(40000, 80, seq: 1, ack: 1, flags: 0x18, Array("GET /vlan HTTP/1.1\r\nHost: v\r\n\r\n".utf8))))),
        ]
        let base = 1_790_000_000.0
        let packets = frames.enumerated().map { i, d in
            Packet(id: i + 1, timestamp: Date(timeIntervalSince1970: base + Double(i) * 0.01), relative: Double(i) * 0.01,
                   length: d.count, captured: d.count, data: d, decoded: PacketDecoder.decode(d))
        }
        let url = FileManager.default.temporaryDirectory.appending(path: "SheepLogTests-\(UUID().uuidString)-vlan.pcap")
        defer { try? FileManager.default.removeItem(at: url) }
        try PcapFile.write(packets, linkType: 1, to: url)
        let r = try compare(url)
        XCTAssertEqual(r.packets, frames.count)
        XCTAssertEqual(r.checked["vlan"], frames.count, "every frame's VLAN compared")
        XCTAssertEqual(r.mismatches.count, 0, r.mismatches.joined(separator: "\n"))
    }

    // MARK: The comparison

    struct Report {
        var packets = 0
        var mismatches: [String] = []
        /// Fields compared, by name (how much ground truth there was).
        var checked: [String: Int] = [:]
        /// Differences kept on purpose (each says why).
        var tolerated: [String] = []
    }

    struct Truth {
        var length: Int?
        var vlan: Int?
        var src: String?, dst: String?
        var sport: Int?, dport: Int?
        var flags: Set<Character>?
        var tcpLen: Int?
        var dnsName: String?
        var httpLine: String?
        var icmpType: Int?, icmpID: Int?, icmpSeq: Int?
        /// The echo an ICMP error quotes (an ICMP traceroute probe).
        var quotedEchoSeq: Int?
        var snmpVersion: String?, snmpPDU: String?
        var syslogPRI: Int?
        var sshBanner: String?
        var arpSender: String?, arpTarget: String?
        var wsProtocol: String?
        var sni: String?
        /// tshark flagged the segment (retransmission, out-of-order, …): Wireshark then does not
        /// hand its payload to the application dissectors and calls it TCP.
        var wsAnalysisFlagged = false
        /// Wireshark's layer list ends in "data": no dissector took the payload.
        var wsUndissected = false
    }

    func compare(_ url: URL) throws -> Report {
        var ours: [Packet] = []
        _ = try PcapFile.read(url) { ours += $0 }
        var truths = Self.tcpdumpRecords(url).map(Self.parse)
        if let tshark = Self.tshark {
            for (n, fields) in Self.tsharkFields(tshark, url) where n >= 1 && n <= truths.count {
                truths[n - 1].wsProtocol = fields.count > 0 ? fields[0] : nil
                truths[n - 1].sni = fields.count > 1 && !fields[1].isEmpty ? fields[1] : nil
                truths[n - 1].wsUndissected = fields.count > 2 && fields[2].hasSuffix(":data")
                truths[n - 1].wsAnalysisFlagged = fields.dropFirst(3).contains { !$0.isEmpty }
            }
        }
        var r = Report()
        r.packets = ours.count
        if truths.count != ours.count {
            r.mismatches.append("packet count: ours \(ours.count), tcpdump \(truths.count)")
        }
        for (p, t) in zip(ours, truths) {
            Self.check(p, t, into: &r)
        }
        var text = "\(url.lastPathComponent): \(r.packets) packets, \(r.mismatches.count) mismatches\n"
        text += "checked: " + r.checked.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: " ") + "\n"
        text += r.mismatches.joined(separator: "\n") + "\n"
        if !r.tolerated.isEmpty { text += "tolerated:\n" + r.tolerated.joined(separator: "\n") + "\n" }
        let out = FileManager.default.temporaryDirectory.appending(path: "SheepLog-groundtruth-\(url.lastPathComponent).txt")
        try? text.write(to: out, atomically: true, encoding: .utf8)
        // Our Packets-table columns, for eyeballing against `tshark -r file` (No. Source Destination Protocol Length Info).
        let table = ours.map { p in
            [String(p.id), p.decoded.source, p.decoded.destination, p.decoded.protocolName, String(p.length), p.decoded.info]
                .joined(separator: "\t")
        }.joined(separator: "\n")
        try? table.write(to: FileManager.default.temporaryDirectory.appending(path: "SheepLog-decoded-\(url.lastPathComponent).tsv"),
                         atomically: true, encoding: .utf8)
        print("GROUNDTRUTH \(url.lastPathComponent) packets=\(r.packets) mismatches=\(r.mismatches.count) report=\(out.path)")
        return r
    }

    static func check(_ p: Packet, _ t: Truth, into r: inout Report) {
        let d = p.decoded
        func eq<T: Equatable>(_ field: String, _ ours: T?, _ truth: T?) {
            guard let truth else { return }
            r.checked[field, default: 0] += 1
            if ours != truth {
                r.mismatches.append("frame \(p.id) \(field): ours \(ours.map { "\($0)" } ?? "nil"), truth \(truth)  [\(d.protocolName)] \(d.info.prefix(90))")
            }
        }
        eq("length", p.length, t.length)
        eq("vlan", d.vlan.map(Int.init), t.vlan)
        if t.arpSender == nil {
            eq("src", d.ip?.source, t.src)
            eq("dst", d.ip?.destination, t.dst)
        }
        eq("sport", d.sourcePort.map(Int.init), t.sport)
        eq("dport", d.destinationPort.map(Int.init), t.dport)
        if let tf = t.flags {
            eq("tcp.flags", d.tcp.map { flagChars($0.flags) }, tf)
        }
        eq("tcp.len", d.tcp?.payloadLength, t.tcpLen)
        if let name = t.dnsName {
            var q: String?
            if case .dns(let query, _, _, _)? = d.app { q = query }
            eq("dns.qname", q, name.isEmpty ? "<Root>" : name)
        }
        if let line = t.httpLine {
            var ours: String?
            switch d.app {
            case .httpRequest(let m, let path, _)?: ours = "\(m) \(path)"
            case .httpResponse(let status, _)?: ours = "HTTP \(status)"
            default: ours = nil
            }
            var truth: String
            let parts = line.split(separator: " ")
            if line.hasPrefix("HTTP/1."), parts.count >= 2 { truth = "HTTP \(parts[1])" }
            else if parts.count >= 2 { truth = "\(parts[0]) \(parts[1])" }
            else { truth = line }
            eq("http", ours, truth)
        }
        if let type = t.icmpType {
            eq("icmp.type", d.icmp.map { Int($0.type) }, type)
            eq("icmp.id", d.icmp?.identifier.map(Int.init), t.icmpID)
            eq("icmp.seq", d.icmp?.sequence.map(Int.init), t.icmpSeq)
            if let q = t.quotedEchoSeq {
                eq("icmp.quoted", d.info.contains("ICMP echo") && d.info.hasSuffix(" seq=\(q)") ? q : nil, q)
            }
        }
        if let v = t.snmpVersion {
            var ov: String?, op: String?
            if case .snmp(let version, _, let pdu)? = d.app { ov = version; op = pdu }
            eq("snmp.version", ov, v)
            eq("snmp.pdu", op, t.snmpPDU)
        }
        if let pri = t.syslogPRI {
            var ours: Int?
            if case .syslog(let p, _)? = d.app { ours = p }
            eq("syslog.pri", ours, pri)
        }
        if let banner = t.sshBanner {
            var ours: String?
            if case .ssh(let b)? = d.app { ours = b }
            eq("ssh.banner", ours, banner)
        }
        if let s = t.arpSender {
            eq("arp.sender", d.arp?.senderIP, s)
            eq("arp.target", d.arp?.targetIP, t.arpTarget)
        }
        if let ws = t.wsProtocol {
            if ws == "RSH", case .syslog(let pri?, _)? = d.app {
                // Wireshark names TCP 514 after rsh by port; the bytes are octet-counted
                // "<PRI>…" syslog (network gear sends syslog over TCP to 514).
                r.checked["protocol", default: 0] += 1
                r.tolerated.append("frame \(p.id) protocol: ours Syslog (PRI \(pri)), Wireshark RSH by port")
            } else if ws == "TCP", t.wsAnalysisFlagged, d.protocolName != "TCP" {
                // Per packet we cannot know a segment repeats old data (TCPFlows does); Wireshark
                // stops dissecting such segments and calls them TCP.
                r.checked["protocol", default: 0] += 1
                r.tolerated.append("frame \(p.id) protocol: ours \(d.protocolName), Wireshark TCP (flagged retransmission / out-of-order)")
            } else if ws == "TCP", t.wsUndissected, case .tlsOther("Continuation Data")? = d.app {
                // Mid-record bytes on a TLS port that Wireshark's TLS dissector let go of (it
                // lost the record boundaries): it shows "data", we say TLS by port.
                r.checked["protocol", default: 0] += 1
                r.tolerated.append("frame \(p.id) protocol: ours TLS Continuation Data, Wireshark TCP data (record boundary lost)")
            } else {
                eq("protocol", normalizedOurs(d), normalizedWireshark(ws))
            }
        }
        if let sni = t.sni {
            var ours: String?
            if case .tlsClientHello(let s, _)? = d.app { ours = s }
            eq("tls.sni", ours, sni)
        }
    }

    /// tcpdump's flag letters: F S R P . U E W.
    static func flagChars(_ f: TCPFlags) -> Set<Character> {
        var s = Set<Character>()
        if f.contains(.fin) { s.insert("F") }
        if f.contains(.syn) { s.insert("S") }
        if f.contains(.rst) { s.insert("R") }
        if f.contains(.psh) { s.insert("P") }
        if f.contains(.ack) { s.insert(".") }
        if f.contains(.urg) { s.insert("U") }
        if f.contains(.ece) { s.insert("E") }
        if f.contains(.cwr) { s.insert("W") }
        return s
    }

    /// Wireshark's Protocol column without its version suffixes ("TLSv1.3" → "TLS").
    static func normalizedWireshark(_ p: String) -> String {
        let p = p.trimmingCharacters(in: .whitespaces)
        if p.hasPrefix("TLS") || p.hasPrefix("SSL") { return "TLS" }
        if p.hasPrefix("SSH") { return "SSH" }
        if p.hasPrefix("IGMP") { return "IGMP" }
        if p.hasPrefix("SNMP") { return "SNMP" }
        if p == "ICMPv6" { return "ICMPv6" }
        if p.hasPrefix("DHCPv6") { return "DHCPv6" }
        if p == "BOOTP" || p == "DHCP" { return "DHCP" }
        if p.lowercased() == "syslog" { return "Syslog" }
        if p == "RSTP" || p == "STP" { return "STP" }
        return p
    }

    static func normalizedOurs(_ d: Decoded) -> String {
        d.protocolName
    }

    // MARK: tcpdump / tshark

    static func run(_ tool: String, _ args: [String]) -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return "" }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }

    /// One string per packet (the first line starts with the timestamp; decode lines follow).
    static func tcpdumpRecords(_ url: URL) -> [String] {
        let out = run(tcpdump, ["-nn", "-tt", "-e", "-vv", "-r", url.path])
        var recs: [String] = []
        for line in out.split(separator: "\n", omittingEmptySubsequences: false) {
            if let c = line.first, c.isNumber { recs.append(String(line)) }
            else if !recs.isEmpty, !line.isEmpty { recs[recs.count - 1] += "\n" + line }
        }
        return recs
    }

    static func tsharkFields(_ tshark: String, _ url: URL) -> [(Int, [String])] {
        let out = run(tshark, ["-r", url.path, "-o", "tcp.desegment_tcp_streams:FALSE", "-T", "fields",
                               "-E", "separator=/t", "-E", "occurrence=f",
                               "-e", "frame.number", "-e", "_ws.col.protocol", "-e", "tls.handshake.extensions_server_name",
                               "-e", "frame.protocols",
                "-e", "tcp.analysis.retransmission", "-e", "tcp.analysis.out_of_order",
                "-e", "tcp.analysis.spurious_retransmission", "-e", "tcp.analysis.fast_retransmission"])
        return out.split(separator: "\n").compactMap { line in
            let cols = line.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
            guard let n = cols.first.flatMap({ Int($0) }) else { return nil }
            return (n, Array(cols.dropFirst()))
        }
    }

    nonisolated(unsafe) private static var regexCache: [String: NSRegularExpression] = [:]

    static func match(_ pattern: String, _ s: String) -> [String]? {
        let re: NSRegularExpression
        if let cached = regexCache[pattern] { re = cached } else {
            re = try! NSRegularExpression(pattern: pattern, options: [])
            regexCache[pattern] = re
        }
        guard let m = re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) else { return nil }
        return (0..<m.numberOfRanges).map { i in
            guard let range = Range(m.range(at: i), in: s) else { return "" }
            return String(s[range])
        }
    }

    /// "192.168.1.36.53" / "2001:db8::1.443" → (address, port); no port on ICMP lines.
    static func endpoint(_ s: String) -> (String, Int?) {
        if s.contains(":") {
            if let dot = s.lastIndex(of: "."), !s[..<dot].contains("."), let port = Int(s[s.index(after: dot)...]) {
                return (String(s[..<dot]), port)
            }
            return (s, nil)
        }
        let parts = s.split(separator: ".")
        if parts.count == 5, let port = Int(parts[4]) { return (parts[0..<4].joined(separator: "."), port) }
        return (s, nil)
    }

    static func parse(_ rec: String) -> Truth {
        var t = Truth()
        t.length = match(#"length (\d+):"#, rec).flatMap { Int($0[1]) }
        t.vlan = match(#"vlan (\d+), p \d"#, rec).flatMap { Int($0[1]) }
        if let m = match(#"Request who-has (\S+) tell ([0-9.]+)"#, rec) {
            t.arpTarget = m[1]; t.arpSender = m[2]
            return t
        }
        if let m = match(#"Reply ([0-9.]+) is-at"#, rec) {
            t.arpSender = m[1]
            return t
        }
        if let m = match(#"(?m)(?:^\s+|\) )([0-9a-fA-F][0-9a-fA-F:.]*) > ([0-9a-fA-F][0-9a-fA-F:.]*):"#, rec) {
            let (s, sp) = endpoint(m[1]), (d, dp) = endpoint(m[2])
            t.src = s; t.dst = d; t.sport = sp; t.dport = dp
        }
        if let m = match(#"Flags \[([^\]]*)\]"#, rec) {
            t.flags = Set(m[1])
            t.tcpLen = match(#"Flags \[[^\]]*\][^\n]*?, length (\d+)"#, rec).flatMap { Int($0[1]) }
        }
        let ports = Set([t.sport, t.dport].compactMap { $0 })
        if !ports.isDisjoint(with: [53, 5353, 5355]),
           let m = match(#"\s(?:q: )?(?:[A-Z][A-Z0-9]*|Type\d+)(?: \(Q[UM]\))?\? (\S+) "#, rec) {
            var name = m[1]
            if name.hasSuffix(".") { name.removeLast() }
            t.dnsName = name
        }
        if let m = match(#"HTTP, length: \d+\n\s*([^\n]*)"#, rec) {
            t.httpLine = m[1].trimmingCharacters(in: .whitespacesAndNewlines)
        }
        // Errors first: with -vv tcpdump also prints the datagram an error quotes (an ICMP
        // traceroute's echo request), and that "ICMP echo request" is not this packet's type.
        if match(#": ICMP time exceeded"#, rec) != nil {
            t.icmpType = 11
            t.quotedEchoSeq = match(#"\n\s+\S+ > \S+: ICMP echo request, id \d+, seq (\d+)"#, rec).flatMap { Int($0[1]) }
        } else if match(#": ICMP [^\n]*unreachable"#, rec) != nil {
            t.icmpType = 3
        } else if let m = match(#": ICMP echo (request|reply), id (\d+), seq (\d+)"#, rec) {
            t.icmpType = m[1] == "request" ? 8 : 0; t.icmpID = Int(m[2]); t.icmpSeq = Int(m[3])
        } else if let m = match(#"ICMP6, echo (request|reply), id (\d+), seq (\d+)"#, rec) {
            t.icmpType = m[1] == "request" ? 128 : 129; t.icmpID = Int(m[2]); t.icmpSeq = Int(m[3])
        } else if let m = match(#"ICMP6, (neighbor solicitation|neighbor advertisement|router solicitation|router advertisement|multicast listener report v2|destination unreachable|time exceeded in-transit|packet too big)"#, rec) {
            t.icmpType = ["neighbor solicitation": 135, "neighbor advertisement": 136, "router solicitation": 133,
                          "router advertisement": 134, "multicast listener report v2": 143,
                          "destination unreachable": 1, "time exceeded in-transit": 3, "packet too big": 2][m[1]]
        }
        if let m = match(#"\{ SNMPv(1|2c|3) "#, rec) {
            t.snmpVersion = "v" + m[1]
            if rec.contains("[!scoped PDU]") {
                t.snmpPDU = "encryptedPDU"
            } else if let p = match(#"\{ (GetRequest|GetNextRequest|GetResponse|SetRequest|Trap|GetBulk|Inform|V2Trap|Report)\("#, rec) {
                t.snmpPDU = ["GetRequest": "get-request", "GetNextRequest": "get-next-request", "GetResponse": "get-response",
                             "SetRequest": "set-request", "Trap": "trap", "GetBulk": "getBulkRequest",
                             "Inform": "inform-request", "V2Trap": "snmpV2-trap", "Report": "report"][p[1]]
            }
        }
        if let m = match(#"SYSLOG, length: \d+\s+Facility [^(]*\((\d+)\), Severity [^(]*\((\d+)\)"#, rec),
           let f = Int(m[1]), let s = Int(m[2]) {
            t.syslogPRI = f * 8 + s
        }
        if let m = match(#"SSH: (SSH-[^\n]*)"#, rec) {
            t.sshBanner = m[1].trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return t
    }
}
