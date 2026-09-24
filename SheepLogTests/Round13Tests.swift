import AppKit
import SwiftUI
import XCTest
@testable import SheepLog

/// Round 13: the Troubleshoot rules' thresholds and sentences (a table of every rule on a minimal
/// fixture), the pane's filters together (range × chips × text × Problems only, the export and
/// evidence that rolled out), other vendors' classic line forms, a fuzz of the round-12 EAP-id
/// attribution, the pane-switch flake, and a sweep.
@MainActor
final class Round13Tests: XCTestCase {
    private var windows: [NSWindow] = []

    override func tearDown() async throws {
        for w in windows { w.contentView = nil; w.close() }
        windows = []
        let app = AppModel.shared
        app.packets.paused = false
        app.packets.limit = 200_000
        app.packets.queryText = ""
        app.packets.applyQueryNow(synchronous: true)
        app.packets.clear()
        app.logs.paused = false
        app.logs.limit = 100_000
        app.logs.queryText = ""
        app.logs.applyQueryText()
        app.logs.clear()
        app.mainPane = .status
        TroubleshootModel.shared.jumpNotice = nil
        try? await Task.sleep(for: .milliseconds(50))
    }

    // MARK: - Harness

    static let t0 = Date(timeIntervalSince1970: 1_790_128_800)       // 2026-09-23 03:00 UTC, a whole minute
    static func at(_ s: Double) -> Date { t0.addingTimeInterval(s) }
    static func clock(_ s: Double) -> String { FText.clock(at(s)) }
    /// Device timestamps in the Mac's zone (the lines arrive as a live device's would).
    static func bsd(_ s: Double) -> String { Format.gregorian("MMM dd HH:mm:ss").string(from: at(s)) }
    static func asa(_ s: Double) -> String { Format.gregorian("MMM dd yyyy HH:mm:ss").string(from: at(s)) }
    static func nxos(_ s: Double) -> String { Format.gregorian("yyyy MMM dd HH:mm:ss").string(from: at(s)) }

    /// Log lines as received live, each host from its own address.
    @MainActor struct Lines {
        var entries: [LogEntry] = []
        var nextID = 1
        static func address(_ host: String) -> String {
            let h = host.unicodeScalars.reduce(UInt32(7)) { ($0 &* 31) &+ $1.value }
            return "10.66.\(h % 200 + 1).\(h / 200 % 250 + 1)"
        }
        /// An RFC 5424 line with no timestamp from `host`.
        mutating func add(_ s: Double, _ host: String, _ text: String, sev: Int = 5, address: String? = nil) {
            entries.append(parsedLine("<\(128 + sev)>1 - \(host) app - - - \(text)", from: address ?? Self.address(host),
                                      received: Round13Tests.at(s), id: nextID))
            nextID += 1
        }
        /// A line with its own header.
        mutating func raw(_ s: Double, _ text: String, from address: String) {
            entries.append(parsedLine(text, from: address, received: Round13Tests.at(s).addingTimeInterval(0.25), id: nextID))
            nextID += 1
        }
    }

    static func analyze(_ entries: [LogEntry] = [], packets: [Packet] = [], flows: [TCPFlow]? = nil, snmp: [SNMPSnapshot] = [],
                        counters: EngineCounters = EngineCounters(), extra: [Finding] = [], now: Date? = nil) -> TroubleshootResult {
        var input = TroubleshootInput()
        input.entries = entries
        input.packets = packets
        input.flows = flows ?? TCPFlowAnalyzer.analyze(packets)
        input.snmp = snmp
        input.counters = counters
        input.extra = extra
        let latest = (entries.map(\.received) + packets.map(\.timestamp) + input.flows.map(\.firstTime)).max() ?? t0
        input.now = now ?? latest.addingTimeInterval(60)
        return FindingRules.analyze(input)
    }

    static func packets(_ frames: [(Double, [UInt8])]) -> [Packet] {
        frames.sorted { $0.0 < $1.0 }.enumerated().map { i, f in TroubleshootFixture.packet(f.1, at: at(f.0), id: i + 1, start: t0) }
    }

    static func flows(_ scripts: [TCPFlowDemo.Script]) -> [TCPFlow] {
        TCPFlowAnalyzer.analyze(renumbered(scripts.flatMap(\.packets)))
    }

    static func renumbered(_ packets: [Packet], from first: Int = 1) -> [Packet] {
        packets.sorted { $0.timestamp < $1.timestamp }.enumerated().map { n, p in
            Packet(id: first + n, timestamp: p.timestamp, relative: p.relative, length: p.length, captured: p.captured, data: p.data, decoded: p.decoded)
        }
    }

    private func spin(_ ms: Int = 30) async { try? await Task.sleep(for: .milliseconds(ms)) }

    private func waitUntil(_ timeout: Double = 5, _ condition: () -> Bool) async {
        let end = Date().addingTimeInterval(timeout)
        while !condition(), Date() < end { await spin(10) }
    }

    // MARK: - 1. Fixtures of the rules

    static func dhcp(_ t: Double, type: UInt8, client: String = "02:00:5e:14:00:21", xid: UInt32 = 0x2a01, vlan: Int? = 20,
                     server: String? = nil, from src: String = "0.0.0.0", lease: UInt32? = nil) -> (Double, [UInt8]) {
        let op: UInt8 = [2, 5, 6].contains(type) ? 2 : 1
        let m = TroubleshootFixture.dhcp(op: op, type: type, xid: xid, client: client, yiaddr: op == 2 ? "10.1.30.60" : "0.0.0.0",
                                         server: server, lease: lease)
        return (t, TroubleshootFixture.udp4(srcMAC: op == 2 ? TroubleshootFixture.routerMAC : client, dstMAC: "ff:ff:ff:ff:ff:ff",
                                            src: src, dst: op == 2 ? "10.1.30.60" : "255.255.255.255",
                                            sport: op == 2 ? 67 : 68, dport: op == 2 ? 68 : 67, vlan: vlan, m))
    }

    static func dns(_ t: Double, k: Int, response: Bool, rcode: Int = 0, server: String = "10.1.0.53") -> (Double, [UInt8]) {
        let name = "host\(k).corp.example"
        let sport = 41_000 + k
        return response
            ? (t, TroubleshootFixture.udp4(srcMAC: "02:00:00:00:00:02", dstMAC: "02:00:00:00:00:01", src: server, dst: "10.1.30.60",
                                           sport: 53, dport: sport, vlan: nil,
                                           TroubleshootFixture.dns(id: k, name: name, response: true, rcode: rcode, answer: rcode == 0 ? "10.1.40.1" : nil)))
            : (t, TroubleshootFixture.udp4(srcMAC: "02:00:00:00:00:01", dstMAC: "02:00:00:00:00:02", src: "10.1.30.60", dst: server,
                                           sport: sport, dport: 53, vlan: nil, TroubleshootFixture.dns(id: k, name: name, response: false)))
    }

    static func arp(_ t: Double, request: Bool, mac: String, ip: String, target: String) -> (Double, [UInt8]) {
        (t, TroubleshootFixture.arp(request: request, senderMAC: mac, senderIP: ip, targetIP: target,
                                    targetMAC: request ? "00:00:00:00:00:00" : TroubleshootFixture.routerMAC, vlan: 30))
    }

    static func icmp(_ t: Double, type: UInt8, from router: String, to host: String, probe: String) -> (Double, [UInt8]) {
        let inner = PacketFixture.ipv4(src: host, dst: probe, proto: 17, ttl: 1, PacketFixture.udp(50_000, 443, [0, 0, 0, 0]))
        let body: [UInt8] = [type, 0, 0, 0] + (type == 5 ? PacketFixture.ip4("10.1.20.254") : [0, 0, 0, 0]) + inner
        return (t, PacketFixture.ether(type: 0x0800, PacketFixture.ipv4(src: router, dst: host, proto: 1, body)))
    }

    /// A download of `segments` server segments; the sixth is lost and sent again `resends`
    /// times (fast retransmit, then RTOs).
    static func download(segments: Int, resends: Int, server: String = "10.1.30.8", port: UInt16 = 51_240, offset: Double = 0) -> TCPFlowDemo.Script {
        var l = TCPFlowDemo.Script(firstID: 1, offset: offset, client: "10.1.20.15", clientPort: port, server: server, serverPort: 443)
        l.handshake(rtt: 0.012)
        l.c(0.0125, [.psh, .ack], len: 517, app: .tlsClientHello(sni: "files.corp.example", version: "TLS 1.3"))
        var t = 0.03
        var lost: UInt32?
        for k in 0..<segments {
            if k == 5 { lost = l.sseq; l.sseq &+= 1460; continue }
            l.s(t, .ack, len: 1460)
            if let lost { l.cAck(t + 0.0002, ack: lost) } else if k % 2 == 1 { l.c(t + 0.0002, .ack) }
            t += 0.001
        }
        for r in 0..<resends { l.s(t + 0.2 * Double(r + 1), .ack, len: 1460, seq: lost!) }
        let end = t + 0.2 * Double(resends)
        l.c(end + 0.01, .ack)
        l.c(end + 0.02, [.fin, .ack])
        l.s(end + 0.03, [.fin, .ack])
        l.c(end + 0.031, .ack)
        return l
    }

    static func refusedScripts(clients: Int, perClient: Int, server: String = "10.9.0.6") -> [TCPFlowDemo.Script] {
        var out: [TCPFlowDemo.Script] = []
        for c in 0..<clients {
            for k in 0..<perClient {
                var s = TCPFlowDemo.Script(firstID: 1, offset: Double(c * 10 + k), client: "10.1.20.\(15 + c)", clientPort: UInt16(50_100 + c * 10 + k),
                                           server: server, serverPort: 8443)
                s.c(0, .syn); s.s(0.001, [.rst, .ack], seq: 0)
                out.append(s)
            }
        }
        return out
    }

    static func ifRow(_ i: UInt32, _ name: String, oper: String = "up", errors: UInt64 = 0, since: UInt32 = 8_640_000) -> InterfaceRow {
        var r = InterfaceRow(index: i)
        r.name = name; r.descr = name; r.type = "ethernetCsmacd"; r.admin = "up"; r.oper = oper
        r.speedBits = 1_000_000_000; r.inErrors = errors; r.lastChange = 100; r.sinceChange = since
        return r
    }

    static func walk(_ t: Double, rows: [InterfaceRow], values: [OID: String] = [:], upTime: UInt32 = 86_400_000, host: String = "10.1.0.13") -> SNMPSnapshot {
        var v = values
        v[.sysName] = "SW-A"
        return SNMPSnapshot(host: host, taken: at(t), sysName: "SW-A", sysUpTime: upTime, interfaces: rows, values: v)
    }

    /// ifOutDiscards and ifHCOutUcastPkts (or the 32-bit ifOutUcastPkts) of ifIndex 1.
    static func counters(discards: UInt64, packets: UInt64?, hc: Bool = true) -> [OID: String] {
        var v: [OID: String] = [FindingRules.ifOutDiscards.appending(1): "\(discards)"]
        if let packets { v[(hc ? FindingRules.ifOutPacketsHC[0] : FindingRules.ifOutPackets32[0]).appending(1)] = "\(packets)" }
        return v
    }

    /// Keep-alive HTTP: a quick GET, then a POST the server takes 5 s to answer.
    static func slowAPI(offset: Double = 0) -> TCPFlowDemo.Script {
        var s = TCPFlowDemo.Script(firstID: 1, offset: offset, client: "10.1.20.15", clientPort: 51_262, server: "10.1.30.12", serverPort: 8080)
        s.handshake(rtt: 0.004)
        s.c(0.005, [.psh, .ack], len: 120, app: .httpRequest(method: "GET", path: "/fast", host: "reports.corp.example"))
        s.s(0.009, .ack)
        s.s(0.100, [.psh, .ack], len: 400, app: .httpResponse(status: 200, reason: "OK"))
        s.c(0.101, .ack)
        s.c(0.200, [.psh, .ack], len: 380, app: .httpRequest(method: "POST", path: "/api/slow", host: "reports.corp.example"))
        s.s(0.204, .ack)
        s.s(5.200, [.psh, .ack], len: 820, app: .httpResponse(status: 200, reason: "OK"))
        s.c(5.204, .ack)
        s.c(5.210, [.fin, .ack]); s.s(5.214, [.fin, .ack]); s.c(5.215, .ack)
        return s
    }

    struct RuleCase {
        let rule: String
        let severity: FindingSeverity
        let title: String
        let make: () -> TroubleshootResult
        /// Just under the threshold: no finding of the rule.
        var below: (() -> TroubleshootResult)? = nil
    }

    static func logs(now: Double? = nil, _ build: (inout Lines) -> Void) -> () -> TroubleshootResult {
        var l = Lines()
        build(&l)
        let e = l.entries
        return { analyze(e, now: now.map(at)) }
    }

    static func ruleCases() -> [RuleCase] {
        var cases: [RuleCase] = []
        let c = clock
        // Link
        func flap(_ n: Int) -> (inout Lines) -> Void {
            { l in for k in 0..<n {
                l.add(Double(k) * 120, "SW1", "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/7, changed state to down", sev: 3)
                l.add(Double(k) * 120 + 60, "SW1", "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/7, changed state to up", sev: 3)
            } }
        }
        cases.append(RuleCase(rule: "link.flap", severity: .bad,
                              title: "Port GigabitEthernet1/0/7 on SW1 went down 3 times in 4 min (\(c(0))–\(c(240))).",
                              make: logs(flap(3)), below: logs(flap(2))))
        let down: (inout Lines) -> Void = { $0.add(0, "SW1", "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/2, changed state to down", sev: 3) }
        cases.append(RuleCase(rule: "link.down", severity: .warn,
                              title: "Port GigabitEthernet1/0/2 on SW1 went down at \(c(0)) and has not come back.",
                              make: logs(now: 301, down), below: logs(now: 299, down)))
        // Hardware
        cases.append(RuleCase(rule: "hw.psu", severity: .bad, title: "SW1 reported a power supply problem: “Power supply 2 failed”",
                              make: logs { $0.add(0, "SW1", "Power supply 2 failed", sev: 2) }))
        cases.append(RuleCase(rule: "hw.fan", severity: .bad, title: "SW1 reported a fan problem: “Fan tray 1 fault detected”",
                              make: logs { $0.add(0, "SW1", "Fan tray 1 fault detected", sev: 1) }))
        cases.append(RuleCase(rule: "hw.temperature", severity: .warn,
                              title: "SW1 reported a temperature alarm: “Temperature sensor 1 over threshold”",
                              make: logs { $0.add(0, "SW1", "Temperature sensor 1 over threshold", sev: 4) }))
        cases.append(RuleCase(rule: "hw.poe", severity: .warn, title: "SW1 reported PoE power problems: “PoE power denied on port 5”",
                              make: logs { $0.add(0, "SW1", "PoE power denied on port 5", sev: 4) }))
        // Spanning tree
        func tc(_ n: Int) -> (inout Lines) -> Void { { l in for k in 0..<n { l.add(Double(k) * 60, "SW1", "Topology change received on port 1/1/5", sev: 4) } } }
        cases.append(RuleCase(rule: "stp.topologyChange", severity: .warn,
                              title: "3 spanning-tree topology changes on SW1 in 2 min on port 1/1/5.", make: logs(tc(3)), below: logs(tc(2))))
        func root(_ n: Int) -> (inout Lines) -> Void {
            { l in for k in 0..<n { l.add(Double(k) * 60, "SW1", "Spanning tree root bridge changed to 4096.00aa.bbcc.dd0\(k)", sev: 4) } }
        }
        cases.append(RuleCase(rule: "stp.rootChange", severity: .warn, title: "The spanning-tree root changed 3 times on SW1.",
                              make: logs(root(3)), below: logs(root(2))))
        cases.append(RuleCase(rule: "stp.bpduGuard", severity: .warn, title: "BPDU guard shut port 1/1/9 on SW1 (1×).",
                              make: logs { $0.add(0, "SW1", "BPDU guard shut down port 1/1/9", sev: 4) }))
        cases.append(RuleCase(rule: "stp.loop", severity: .bad, title: "Loop detected on SW1 on port 1/1/11 (1×).",
                              make: logs { $0.add(0, "SW1", "Loop detected on port 1/1/11", sev: 3) }))
        cases.append(RuleCase(rule: "stp.storm", severity: .bad, title: "Broadcast / multicast storm control acted on SW1 on port 1/1/12 (1×).",
                              make: logs { $0.add(0, "SW1", "Broadcast storm detected on port 1/1/12", sev: 3) }))
        // Routing, configuration, restarts, logins
        cases.append(RuleCase(rule: "routing.neighbor", severity: .bad,
                              title: "OSPF neighbor 10.0.0.2 on R1 went down at \(c(0)) and has not come back.",
                              make: logs { $0.add(0, "R1", "OSPF neighbor 10.0.0.2 changed to Down: dead timer expired", sev: 3) },
                              below: logs { l in
                                  l.add(0, "R1", "OSPF neighbor 10.0.0.2 changed to Down: dead timer expired", sev: 3)
                                  l.add(40, "R1", "OSPF neighbor 10.0.0.2 changed to Full: loading done", sev: 5)
                              }))
        // Round 15: a peer that only steps between states for minutes has not come up.
        func steps(_ times: [Double]) -> (inout Lines) -> Void {
            { l in for (k, t) in times.enumerated() { l.add(t, "R1", "BGP peer 10.0.0.9 changed state from \(k % 2 == 0 ? "Idle to Connect" : "Connect to Idle")", sev: 5) } }
        }
        cases.append(RuleCase(rule: "routing.notUp", severity: .bad,
                              title: "BGP neighbor 10.0.0.9 on R1 has not come up: 3 state changes from \(c(0)) to \(c(120)), none to Established.",
                              make: logs(steps([0, 60, 120])), below: logs(steps([0, 60, 110]))))
        cases.append(RuleCase(rule: "config.change", severity: .info, title: "Configuration changed on R1 by admin at \(c(0)).",
                              make: logs { $0.add(0, "R1", "%SYS-5-CONFIG_I: Configured from console by admin on vty0 (10.1.0.5)") }))
        cases.append(RuleCase(rule: "device.restart", severity: .warn, title: "R1 restarted at \(c(0)).",
                              make: logs { $0.add(0, "R1", "%SYS-5-RESTART: System restarted --") }))
        func fails(_ n: Int) -> (inout Lines) -> Void {
            { l in for k in 0..<n { l.add(Double(k) * 30, "web01", "Failed password for root from 198.51.100.7 port \(51_000 + k) ssh2", sev: 4) } }
        }
        cases.append(RuleCase(rule: "login.failures", severity: .info, title: "2 failed admin logins from 198.51.100.7 on web01.",
                              make: logs(fails(2)), below: logs(fails(1))))
        // The log itself
        func skewed(_ behind: Double) -> (inout Lines) -> Void {
            { l in
                let f = Format.gregorian("yyyy-MM-dd'T'HH:mm:ssXXXXX")
                for k in 0..<3 {
                    l.raw(Double(k), "<13>1 \(f.string(from: Round13Tests.at(Double(k) - behind))) SW9 app - - - hello \(k)", from: "10.66.9.9")
                }
            }
        }
        cases.append(RuleCase(rule: "syslog.clock", severity: .warn, title: "SW9's clock is 10 min behind this Mac.",
                              make: logs(skewed(600)), below: logs(skewed(240))))
        func marks(_ n: Int) -> (inout Lines) -> Void {
            { l in for k in 0..<n { l.add(Double(k) / 100, "SW9", "forwarded devname=\"FGT-X\" devid=\"FGT1\" note=relay \(k)", sev: 6) } }
        }
        cases.append(RuleCase(rule: "syslog.vendor", severity: .info,
                              title: "SW9 sent 500 lines that look like a supported vendor's but were not recognised.",
                              make: logs(marks(500)), below: logs(marks(499))))
        func spike(_ n: Int) -> (inout Lines) -> Void {
            { l in
                l.add(0, "SW9", "error 0", sev: 3)
                for k in 0..<n { l.add(300 + Double(k), "SW9", "error burst \(k)", sev: 3) }
                l.add(600, "SW9", "error 99", sev: 3)
            }
        }
        cases.append(RuleCase(rule: "syslog.errorSpike", severity: .warn,
                              title: "SW9 logged 10 errors in the minute at \(c(300)) — 20× its usual rate.",
                              make: logs(spike(10)), below: logs(spike(9))))
        func flood(_ seconds: Int) -> (inout Lines) -> Void {
            { l in for s in 0..<seconds { for k in 0..<1_000 { l.add(Double(s) + Double(k) / 1_000, "SW9", "chatter \(k)", sev: 6) } } }
        }
        cases.append(RuleCase(rule: "capacity.logRate", severity: .warn, title: "SW9 sent over 1,000 lines/s for 5 s (peak 1,000/s).",
                              make: logs(flood(5)), below: logs(flood(4))))
        cases.append(RuleCase(rule: "capacity.logLost", severity: .warn, title: "5 syslog lines were lost before they reached the table.",
                              make: { analyze(counters: EngineCounters(logLost: 5), now: at(0)) }))
        cases.append(RuleCase(rule: "capacity.packetLost", severity: .warn, title: "The capture lost 7 packets (kernel or back-pressure drops).",
                              make: { analyze(counters: EngineCounters(packetLost: 7), now: at(0)) }))
        cases.append(RuleCase(rule: "capacity.logBuffer", severity: .info, title: "The log buffer is full (100 lines): 30 older lines rolled out.",
                              make: { analyze(counters: EngineCounters(logCount: 100, logLimit: 100, logDropped: 30), now: at(0)) },
                              below: { analyze(counters: EngineCounters(logCount: 99, logLimit: 100, logDropped: 30), now: at(0)) }))
        cases.append(RuleCase(rule: "capacity.packetBuffer", severity: .info, title: "The packet buffer is full (100 packets): the oldest ones rolled out.",
                              make: { analyze(counters: EngineCounters(packetCount: 100, packetLimit: 100, packetDropped: 40), now: at(0)) }))
        // DHCP, DNS, ARP, ICMP
        let end = arp(40, request: true, mac: "02:00:5e:1e:00:50", ip: "10.1.30.50", target: "10.1.30.51")
        cases.append(RuleCase(rule: "dhcp.noAnswer", severity: .bad,
                              title: "No DHCP answer on VLAN 20: client 02:00:5e:14:00:21 sent 3 Discovers and got no Offer within 10 s.",
                              make: { analyze(packets: packets([dhcp(0, type: 1), dhcp(4, type: 1), dhcp(8, type: 1), end])) },
                              below: { analyze(packets: packets([dhcp(0, type: 1), dhcp(4, type: 1), end])) }))
        cases.append(RuleCase(rule: "dhcp.twoServers", severity: .warn, title: "2 DHCP servers answer on VLAN 30: 10.1.0.10 and 192.168.1.1.",
                              make: { analyze(packets: packets([dhcp(0, type: 2, vlan: 30, server: "10.1.0.10", from: "10.1.30.1", lease: 86_400),
                                                                dhcp(0.01, type: 2, vlan: 30, server: "192.168.1.1", from: "192.168.1.1", lease: 86_400)])) }))
        cases.append(RuleCase(rule: "dhcp.nak", severity: .warn, title: "DHCP server 10.1.0.10 refused 1 request (NAK) from 02:00:5e:14:00:21.",
                              make: { analyze(packets: packets([dhcp(0, type: 6, vlan: 30, server: "10.1.0.10", from: "10.1.30.1")])) }))
        cases.append(RuleCase(rule: "dhcp.shortLease", severity: .info, title: "DHCP leases from 10.1.0.10 last only 2 min.",
                              make: { analyze(packets: packets([dhcp(0, type: 5, vlan: 30, server: "10.1.0.10", from: "10.1.30.1", lease: 120)])) },
                              below: { analyze(packets: packets([dhcp(0, type: 5, vlan: 30, server: "10.1.0.10", from: "10.1.30.1", lease: 300)])) }))
        let dnsEnd = arp(20, request: true, mac: "02:00:5e:1e:00:50", ip: "10.1.30.50", target: "10.1.30.51")
        cases.append(RuleCase(rule: "dns.noAnswer", severity: .bad, title: "DNS server 10.1.0.53 never answered: 3 queries from 10.1.30.60, no reply.",
                              make: { analyze(packets: packets((0..<3).map { dns(Double($0), k: $0, response: false) } + [dnsEnd])) },
                              below: { analyze(packets: packets((0..<2).map { dns(Double($0), k: $0, response: false) } + [dnsEnd])) }))
        func servfail(_ n: Int) -> () -> TroubleshootResult {
            { analyze(packets: packets((0..<10).flatMap { k in [dns(Double(k), k: k, response: false), dns(Double(k) + 0.01, k: k, response: true, rcode: k < n ? 2 : 0)] })) }
        }
        cases.append(RuleCase(rule: "dns.failures", severity: .bad, title: "DNS server 10.1.0.53 failed 30 % of queries (SERVFAIL 3 of 10).",
                              make: servfail(3), below: servfail(2)))
        cases.append(RuleCase(rule: "arp.duplicateIP", severity: .bad,
                              title: "Duplicate IP 10.1.30.44: claimed by 2 MAC addresses (02:00:5e:1e:00:44 and 02:00:5e:1e:00:99).",
                              make: { analyze(packets: packets([arp(0, request: false, mac: "02:00:5e:1e:00:44", ip: "10.1.30.44", target: "10.1.30.1"),
                                                                arp(2, request: false, mac: "02:00:5e:1e:00:99", ip: "10.1.30.44", target: "10.1.30.1")])) }))
        func asks(_ n: Int) -> () -> TroubleshootResult {
            { analyze(packets: packets((0..<n).map { arp(Double($0), request: true, mac: "02:00:5e:14:00:50", ip: "10.1.20.50", target: "10.1.20.1") })) }
        }
        cases.append(RuleCase(rule: "arp.unanswered", severity: .warn, title: "Nobody answers ARP for 10.1.20.1 (the gateway?): 3 requests from 10.1.20.50.",
                              make: asks(3), below: asks(2)))
        func redirects(_ n: Int) -> () -> TroubleshootResult {
            { analyze(packets: packets((0..<n).map { icmp(Double($0), type: 5, from: "10.1.20.1", to: "10.1.20.77", probe: "10.2.0.9") })) }
        }
        cases.append(RuleCase(rule: "icmp.redirects", severity: .warn, title: "10.1.20.1 sent 5 ICMP redirects in a minute (5 in all).",
                              make: redirects(5), below: redirects(4)))
        func expired(_ n: Int) -> () -> TroubleshootResult {
            { analyze(packets: packets((0..<n).map { icmp(Double($0), type: 11, from: "10.0.0.2", to: "10.1.30.60", probe: "172.16.9.9") })) }
        }
        cases.append(RuleCase(rule: "icmp.ttlExceeded", severity: .warn, title: "10.0.0.2 sent 10 ICMP time-exceeded messages in a minute (10 in all).",
                              make: expired(10), below: expired(9)))
        // TCP
        cases.append(RuleCase(rule: "tcp.synUnanswered", severity: .bad, title: "Nothing answers on 10.9.0.5:22 (SSH): 3 SYNs from 10.1.20.15, no reply.",
                              make: {
                                  var s = TCPFlowDemo.Script(firstID: 1, client: "10.1.20.15", clientPort: 50_001, server: "10.9.0.5", serverPort: 22)
                                  s.c(0, .syn); s.c(1, .syn, seq: 1_000); s.c(3, .syn, seq: 1_000)
                                  return analyze(flows: flows([s]))
                              },
                              below: {
                                  var s = TCPFlowDemo.Script(firstID: 1, client: "10.1.20.15", clientPort: 50_001, server: "10.9.0.5", serverPort: 22)
                                  s.c(0, .syn); s.c(1, .syn, seq: 1_000)
                                  return analyze(flows: flows([s]))
                              }))
        cases.append(RuleCase(rule: "tcp.refused", severity: .warn,
                              title: "10.9.0.6:8443 refused 3 connection attempts with RST (port closed) from 10.1.20.15.",
                              make: { analyze(flows: flows(refusedScripts(clients: 1, perClient: 3))) }))
        cases.append(RuleCase(rule: "tcp.serverReset", severity: .warn, title: "10.9.0.8:8080 (HTTP) reset 1 connection from 10.1.20.15.",
                              make: {
                                  var r = TCPFlowDemo.Script(firstID: 1, client: "10.1.20.15", clientPort: 50_300, server: "10.9.0.8", serverPort: 8080)
                                  r.handshake(rtt: 0.002); r.c(0.003, [.psh, .ack], len: 300); r.s(0.004, [.rst, .ack])
                                  return analyze(flows: flows([r]))
                              }))
        cases.append(RuleCase(rule: "tcp.retransmissions", severity: .bad,
                              title: "7.5 % of packets to and from 10.1.30.8:443 (TLS) were retransmitted (3 of 40 packets).",
                              make: { analyze(flows: flows([download(segments: 17, resends: 3)])) },
                              below: { analyze(flows: flows([download(segments: 16, resends: 3)])) }))
        cases.append(RuleCase(rule: "tcp.slowHandshake", severity: .warn, title: "Slow handshakes to 10.9.0.7:443 (TLS): median 450 ms over 1 connection.",
                              make: {
                                  var s = TCPFlowDemo.Script(firstID: 1, client: "10.1.20.15", clientPort: 50_200, server: "10.9.0.7", serverPort: 443)
                                  s.handshake(rtt: 0.45); s.c(0.46, [.psh, .ack], len: 200); s.s(0.92, [.psh, .ack], len: 300)
                                  s.c(0.93, [.fin, .ack]); s.s(1.4, [.fin, .ack]); s.c(1.41, .ack)
                                  return analyze(flows: flows([s]))
                              }))
        cases.append(RuleCase(rule: "tcp.zeroWindow", severity: .warn, title: "Zero window on 1 connection to 10.9.0.9:445 (SMB): the client stopped reading.",
                              make: {
                                  var z = TCPFlowDemo.Script(firstID: 1, client: "10.1.20.15", clientPort: 50_400, server: "10.9.0.9", serverPort: 445)
                                  z.handshake(rtt: 0.002); z.c(0.003, [.psh, .ack], len: 100); z.s(0.004, .ack, len: 1_460)
                                  z.cAck(0.005, ack: z.sseq, window: 0); z.cAck(0.5, ack: z.sseq, window: 65_535)
                                  z.s(0.501, [.psh, .ack], len: 100); z.c(0.6, [.fin, .ack]); z.s(0.61, [.fin, .ack]); z.c(0.62, .ack)
                                  return analyze(flows: flows([z]))
                              }))
        cases.append(RuleCase(rule: "tcp.slowResponse", severity: .warn,
                              title: "10.1.30.12:8080 (HTTP) took up to 5.00 s to answer POST /api/slow (1 connection).",
                              make: { analyze(flows: flows([slowAPI()])) }))
        // SNMP
        cases.append(RuleCase(rule: "snmp.recentBoot", severity: .info,
                              title: "SW-A restarted 5 min before the SNMP walk (sysUpTime \(Format.uptime(ticks: 30_000))).",
                              make: { analyze(snmp: [walk(0, rows: [ifRow(1, "1/1/1")], upTime: 30_000)], now: at(60)) },
                              below: { analyze(snmp: [walk(0, rows: [ifRow(1, "1/1/1")], upTime: 60_000)], now: at(60)) }))
        cases.append(RuleCase(rule: "snmp.operDown", severity: .warn, title: "1 port on SW-A is enabled but down: 1/1/9.",
                              make: { analyze(snmp: [walk(0, rows: [ifRow(1, "1/1/1"), ifRow(9, "1/1/9", oper: "down", since: 30_000)])], now: at(60)) }))
        cases.append(RuleCase(rule: "snmp.errorsGrowing", severity: .warn, title: "Interface errors are growing on SW-A: 1/1/1 +100 in 5 min.",
                              make: { analyze(snmp: [walk(0, rows: [ifRow(1, "1/1/1", errors: 10)]), walk(300, rows: [ifRow(1, "1/1/1", errors: 110)])], now: at(360)) },
                              below: { analyze(snmp: [walk(0, rows: [ifRow(1, "1/1/1", errors: 10)]), walk(300, rows: [ifRow(1, "1/1/1", errors: 10)])], now: at(360)) }))
        cases.append(RuleCase(rule: "snmp.errors", severity: .info, title: "1 interface on SW-A has error counts: 1/1/1 10.",
                              make: { analyze(snmp: [walk(0, rows: [ifRow(1, "1/1/1", errors: 10)])], now: at(60)) }))
        cases.append(RuleCase(rule: "snmp.halfDuplex", severity: .warn, title: "1 port on SW-A runs at half duplex: 1/1/1.",
                              make: { analyze(snmp: [walk(0, rows: [ifRow(1, "1/1/1")], values: [FindingRules.dot3Duplex.appending(1): "halfDuplex(2)"])], now: at(60)) }))
        cases.append(RuleCase(rule: "snmp.discardsGrowing", severity: .warn,
                              title: "Discards are growing on SW-A: 1/1/1 out 50.0 per 10,000 packets (+500) in 5 min.",
                              make: { analyze(snmp: [walk(0, rows: [ifRow(1, "1/1/1")], values: counters(discards: 1_000, packets: 1_000_000_000)),
                                                     walk(300, rows: [ifRow(1, "1/1/1")], values: counters(discards: 1_500, packets: 1_000_100_000))], now: at(360)) },
                              below: { analyze(snmp: [walk(0, rows: [ifRow(1, "1/1/1")], values: counters(discards: 1_000, packets: 1_000_000_000)),
                                                      walk(300, rows: [ifRow(1, "1/1/1")], values: counters(discards: 1_099, packets: 1_000_100_000))], now: at(360)) }))
        cases.append(RuleCase(rule: "snmp.discards", severity: .info,
                              title: "1 interface on SW-A dropped over 0.1 % of its packets since the counters were cleared: 1/1/1 out 50.0 per 10,000 packets.",
                              make: { analyze(snmp: [walk(0, rows: [ifRow(1, "1/1/1")], values: counters(discards: 500, packets: 100_000))], now: at(60)) },
                              below: { analyze(snmp: [walk(0, rows: [ifRow(1, "1/1/1")], values: counters(discards: 99, packets: 100_000))], now: at(60)) }))
        // Authentication (the Authentication pane's sessions)
        cases.append(RuleCase(rule: "auth.session", severity: .bad,
                              title: "host/laptop-17.corp.example (02:13:00:00:00:01) was rejected (802.1X EAP-TLS: certificate expired: CN=laptop-17.corp.example).",
                              make: {
                                  var lab = AuthLab(client: [0x02, 0x13, 0, 0, 0, 1])
                                  lab.eapTLSReject()
                                  return analyze(extra: AuthFindings.findings(from: Round12Tests.renumbered(lab.packets)), now: at(0))
                              }))
        return cases
    }

    /// Every rule on a minimal fixture: the one finding it raises, its severity and its exact
    /// sentence — and nothing of that rule just under the threshold. Thresholds, the rules' code
    /// and their text stay in step: a changed threshold or wording fails here, by rule. The table
    /// covers every rule id the rules can produce (read from their source).
    func testEveryRuleOnAMinimalFixture() throws {
        let cases = Self.ruleCases()
        var failures: [String] = []
        for rc in cases {
            let r = rc.make()
            let mine = r.findings.filter { $0.rule == rc.rule }
            guard mine.count == 1, let f = mine.first else {
                failures.append("\(rc.rule): \(mine.count) findings (all: \(r.findings.map { "\($0.rule): \($0.title)" }))")
                continue
            }
            if f.title != rc.title { failures.append("\(rc.rule): title\n  got  \(f.title)\n  want \(rc.title)") }
            if f.severity != rc.severity { failures.append("\(rc.rule): severity \(f.severity) ≠ \(rc.severity)") }
            XCTAssertFalse(f.detail.isEmpty, rc.rule)
            XCTAssertFalse(f.nextSteps.isEmpty, rc.rule)
            if let below = rc.below {
                let b = below().findings.filter { $0.rule == rc.rule }
                if !b.isEmpty { failures.append("\(rc.rule): under the threshold still raised “\(b[0].title)”") }
            }
        }
        XCTAssertEqual(failures, [], failures.joined(separator: "\n"))
        // Every rule id the code can produce is in the table.
        let src = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appending(path: "SheepLog/Troubleshoot")
        var ids = Set<String>()
        for file in ["Findings.swift", "AuthFindings.swift"] {
            let text = try String(contentsOf: src.appending(path: file), encoding: .utf8)
            // `rule: "…"`, the SNMP rules' `base("id", "snmp.…"`, the ICMP pair.
            let re = try NSRegularExpression(pattern: #"(?:rule: "|rule: redirect \? "|" : "|base\("[a-z]+", ")((?:link|routing|config|device|login|syslog|capacity|dhcp|dns|arp|icmp|tcp|snmp|auth)\.[A-Za-z]+)""#)
            for m in re.matches(in: text, range: NSRange(text.startIndex..., in: text)) {
                if let r = Range(m.range(at: 1), in: text) { ids.insert(String(text[r])) }
            }
        }
        let icmp = try String(contentsOf: src.appending(path: "Findings.swift"), encoding: .utf8)
        for name in ["icmp.redirects", "icmp.ttlExceeded"] where icmp.contains("\"\(name)\"") { ids.insert(name) }
        ids.formUnion(HardwareKind.allCases.map { "hw.\($0.rawValue)" })
        ids.formUnion(STPKind.allCases.map { "stp.\($0.rawValue)" })
        XCTAssertGreaterThan(ids.count, 40)
        XCTAssertEqual(ids.subtracting(cases.map(\.rule)).sorted(), [], "rules with no fixture in the table")
        XCTAssertEqual(Set(cases.map(\.rule)).subtracting(ids).sorted(), [], "table rows for rules the code does not have")
    }

    // MARK: - 1. The round-13 rules

    /// One refused connection is a note; three attempts, or two clients, a warning; three
    /// clients a problem. (One refusal was a warning — every port scan and every client trying
    /// an old port raised one.)
    func testRefusedConnectionsNeedAttemptsOrClients() {
        func refused(_ clients: Int, _ per: Int) -> Finding? {
            Self.analyze(flows: Self.flows(Self.refusedScripts(clients: clients, perClient: per))).findings.first { $0.rule == "tcp.refused" }
        }
        XCTAssertEqual(refused(1, 1)?.severity, .info)
        XCTAssertTrue(refused(1, 1)?.detail.contains("it matters when it repeats") ?? false)
        XCTAssertEqual(refused(1, 2)?.severity, .info, "two attempts of one client")
        XCTAssertEqual(refused(1, 3)?.severity, .warn)
        XCTAssertEqual(refused(2, 1)?.severity, .warn, "two clients")
        XCTAssertEqual(refused(3, 1)?.severity, .bad)
        XCTAssertEqual(refused(3, 1)?.title, "10.9.0.6:8443 refused 3 connection attempts with RST (port closed) from 3 clients.")
        // A SYN the client repeated after the RST (same ISN: one conversation) is another attempt.
        var retry = TCPFlowDemo.Script(firstID: 1, client: "10.1.20.15", clientPort: 50_900, server: "10.9.0.6", serverPort: 8443)
        retry.c(0, .syn); retry.s(0.001, [.rst, .ack], seq: 0)
        retry.c(1, .syn, seq: 1_000); retry.s(1.001, [.rst, .ack], seq: 0)
        retry.c(3, .syn, seq: 1_000); retry.s(3.001, [.rst, .ack], seq: 0)
        let r = Self.analyze(flows: Self.flows([retry])).findings.first { $0.rule == "tcp.refused" }
        XCTAssertEqual(r?.count, 3, r?.title ?? "")
        XCTAssertEqual(r?.severity, .warn)
    }

    /// Discards as a rate: a busy port's old total is healthy, a small port dropping half a
    /// percent is not; growth between two walks is a warning only over 10 per 10,000 packets
    /// (or, with no packet counters, 100 discards).
    func testSNMPDiscardsNeedARate() {
        func rules(_ snaps: [SNMPSnapshot]) -> [String: Finding] {
            Dictionary(Self.analyze(snmp: snaps, now: Self.at(400)).findings.filter { $0.rule.hasPrefix("snmp.discard") }.map { ($0.rule, $0) },
                       uniquingKeysWith: { a, _ in a })
        }
        let row = [Self.ifRow(1, "1/1/1")]
        // 1,000 discards of ten billion packets since the counters were cleared: nothing (was a warning).
        XCTAssertTrue(rules([Self.walk(0, rows: row, values: Self.counters(discards: 1_000, packets: 10_000_000_000))]).isEmpty)
        // No packet counters and one walk: a raw count says nothing.
        XCTAssertTrue(rules([Self.walk(0, rows: row, values: Self.counters(discards: 5_000, packets: nil))]).isEmpty)
        // 32-bit counters are read too.
        XCTAssertNotNil(rules([Self.walk(0, rows: row, values: Self.counters(discards: 500, packets: 100_000, hc: false))])["snmp.discards"])
        // Growth: 50 of a million packets is 0.5 per 10,000 — nothing; 500 of 100,000 is 50.
        XCTAssertTrue(rules([Self.walk(0, rows: row, values: Self.counters(discards: 1_000, packets: 1_000_000)),
                             Self.walk(300, rows: row, values: Self.counters(discards: 1_050, packets: 2_000_000))]).isEmpty)
        let g = rules([Self.walk(0, rows: row, values: Self.counters(discards: 1_000, packets: 1_000_000)),
                       Self.walk(300, rows: row, values: Self.counters(discards: 1_500, packets: 1_100_000))])["snmp.discardsGrowing"]
        XCTAssertEqual(g?.severity, .warn)
        XCTAssertTrue(g?.title.contains("1/1/1 out 50.0 per 10,000 packets (+500)") ?? false, g?.title ?? "")
        // Without packet counters: +100 between walks is a warning, +99 is not.
        XCTAssertNotNil(rules([Self.walk(0, rows: row, values: Self.counters(discards: 1_000, packets: nil)),
                               Self.walk(300, rows: row, values: Self.counters(discards: 1_100, packets: nil))])["snmp.discardsGrowing"])
        XCTAssertTrue(rules([Self.walk(0, rows: row, values: Self.counters(discards: 1_000, packets: nil)),
                             Self.walk(300, rows: row, values: Self.counters(discards: 1_099, packets: nil))]).isEmpty)
        // Counters cleared between the walks (smaller than before): the totals, not a negative growth.
        let reset = rules([Self.walk(0, rows: row, values: Self.counters(discards: 9_000, packets: 1_000_000)),
                           Self.walk(300, rows: row, values: Self.counters(discards: 200, packets: 10_000))])
        XCTAssertNotNil(reset["snmp.discards"], "\(reset.keys)")
    }

    /// Failed logins per device and source: two devices' console typos with no address are not
    /// one burst from "unknown address"; one device's unknown-source failures say they may be
    /// several sources; two addresses on one device are two findings.
    func testLoginFailuresKeyedByDeviceAndSource() async throws {
        var l = Lines()
        l.add(0, "SW-A", "Login incorrect for admin on console", sev: 4)
        l.add(20, "SW-B", "Login incorrect for admin on console", sev: 4)
        XCTAssertTrue(Self.analyze(l.entries).findings.filter { $0.rule == "login.failures" }.isEmpty,
                      "one typo on each of two devices (was “2 failed admin logins from unknown address”)")
        // Five unknown-source failures on one device: a burst, counted per device and saying so.
        var u = Lines()
        for k in 0..<5 { u.add(Double(k) * 10, "SW-A", "Login incorrect for admin on console", sev: 4) }
        let unknown = try XCTUnwrap(Self.analyze(u.entries).findings.first { $0.rule == "login.failures" })
        XCTAssertEqual(unknown.title, "5 failed admin logins on SW-A in 1 min (source not in the lines).")
        XCTAssertEqual(unknown.severity, .bad)
        XCTAssertNil(unknown.client)
        XCTAssertEqual(unknown.id, "login.fail|SW-A|-")
        XCTAssertTrue(unknown.detail.contains("counted per device — they may be more than one source"), unknown.detail)
        // Its evidence filter shows the lines ("incorrect" was not one of the filter's words).
        let store = LogStore()
        store.ingest(u.entries)
        store.queryText = try XCTUnwrap(unknown.evidence.first?.query)
        store.applyQueryText()
        await waitUntil { store.visible.count == 5 }
        XCTAssertEqual(Set(store.visible.map(\.id)), Set(unknown.evidence[0].ids), store.queryText)
        // Two sources on one device: two findings.
        var two = Lines()
        for k in 0..<3 {
            two.add(Double(k), "web01", "Failed password for root from 198.51.100.7 port 5000\(k) ssh2", sev: 4)
            two.add(Double(k) + 0.5, "web01", "Failed password for root from 198.51.100.8 port 5100\(k) ssh2", sev: 4)
        }
        let byIP = Self.analyze(two.entries).findings.filter { $0.rule == "login.failures" }
        XCTAssertEqual(Set(byIP.compactMap(\.client)), ["198.51.100.7", "198.51.100.8"])
        XCTAssertTrue(byIP.allSatisfy { $0.count == 3 && $0.severity == .info && $0.device == "web01" }, byIP.map(\.title).description)
    }

    /// The slowest answer per server and port, naming the request that waited (the slow
    /// conversation's first request was named: a quick GET before the slow POST).
    func testSlowAnswerNamesTheWorstRequest() throws {
        var quick = TCPFlowDemo.Script(firstID: 1, offset: 20, client: "10.1.20.16", clientPort: 51_300, server: "10.1.30.12", serverPort: 8080)
        quick.handshake(rtt: 0.004)
        quick.c(0.005, [.psh, .ack], len: 120, app: .httpRequest(method: "GET", path: "/health", host: "reports.corp.example"))
        quick.s(0.009, .ack)
        quick.s(3.5, [.psh, .ack], len: 100, app: .httpResponse(status: 200, reason: "OK"))
        quick.c(3.6, [.fin, .ack]); quick.s(3.61, [.fin, .ack]); quick.c(3.62, .ack)
        let flows = Self.flows([Self.slowAPI(), quick])
        let slow = Self.analyze(flows: flows).findings.filter { $0.rule == "tcp.slowResponse" }
        XCTAssertEqual(slow.count, 1, "one finding per server and port")
        let f = try XCTUnwrap(slow.first)
        XCTAssertEqual(f.title, "10.1.30.12:8080 (HTTP) took up to 5.00 s to answer POST /api/slow (2 connections).")
        XCTAssertFalse(f.title.contains("GET /fast"))
    }

    /// Retransmission shares only from conversations with ≥ 20 data segments: three resends in a
    /// 14-segment exchange (21 %) said "packets are being lost"; the same in a long transfer is.
    func testRetransmissionsNeedTwentyDataSegments() {
        let short = Self.flows([Self.download(segments: 12, resends: 3)])
        XCTAssertLessThan(short[0].dataSegments, FindingRules.retransMinSegments)
        XCTAssertGreaterThanOrEqual(short[0].retransmissions, 3)
        XCTAssertTrue(Self.analyze(flows: short).findings.filter { $0.rule == "tcp.retransmissions" }.isEmpty)
        let long = Self.flows([Self.download(segments: 40, resends: 3)])
        XCTAssertGreaterThanOrEqual(long[0].dataSegments, FindingRules.retransMinSegments)
        XCTAssertEqual(Self.analyze(flows: long).findings.filter { $0.rule == "tcp.retransmissions" }.count, 1)
        // Both to one server: the short one is left out of the share and of the evidence.
        let both = Self.flows([Self.download(segments: 12, resends: 3, port: 51_241), Self.download(segments: 40, resends: 3, offset: 10)])
        let f = Self.analyze(flows: both).findings.first { $0.rule == "tcp.retransmissions" }
        XCTAssertEqual(f?.evidence.first?.flows.count, 1, f?.title ?? "")
        XCTAssertEqual(f?.count, 3)
    }

    // MARK: - 2. The pane's filters together

    static func sampleFindings() -> [Finding] {
        func f(_ id: String, _ cat: FindingCategory, _ sev: FindingSeverity, _ from: Double, _ to: Double, device: String?, title: String) -> Finding {
            Finding(id: id, rule: "x.\(id)", severity: sev, category: cat, source: .logs, title: title, detail: "detail of \(id)",
                    firstSeen: at(from), lastSeen: at(to), device: device)
        }
        return [
            f("a", .link, .bad, 0, 60, device: "CORE-SW1", title: "Port 1/1/1 on CORE-SW1 flapped."),
            f("b", .link, .info, 300, 300, device: "ACC-SW2", title: "Port 1/1/2 on ACC-SW2 is down."),
            f("c", .dns, .warn, 400, 700, device: nil, title: "DNS server 10.1.0.53 failed 40 %."),
            f("d", .tcp, .bad, 900, 950, device: nil, title: "Nothing answers on 10.9.0.5:22."),
            f("e", .config, .info, 350, 350, device: "CORE-SW1", title: "Configuration changed on CORE-SW1."),
            f("f", .link, .warn, 650, 800, device: "CORE-SW1", title: "Port 1/1/3 on CORE-SW1 went down."),
            f("g", .snmp, .info, 1_000, 1_000, device: "ACC-SW2", title: "1 port on ACC-SW2 is enabled but down."),
        ]
    }

    /// The list is the intersection of the range, the chip, the text and Problems only, for every
    /// combination; the chips count all but themselves (the chosen one stays, even at 0); the
    /// heading counts the range; clearing the range gives the other filters' list back.
    func testRangeChipsTextAndProblemsOnlyTogether() {
        let all = Self.sampleFindings()
        let ranges: [ClosedRange<Date>?] = [nil, Self.at(250)...Self.at(420), Self.at(640)...Self.at(660), Self.at(2_000)...Self.at(3_000)]
        for cat in [nil] + FindingCategory.allCases.map(Optional.some) {
            for text in ["", "core-sw1", "10.9", "nomatch"] {
                for po in [false, true] {
                    for range in ranges {
                        let filter = TroubleshootFilter(category: cat, text: text, problemsOnly: po, range: range)
                        let want = all.filter { f in
                            (cat == nil || f.category == cat) && (!po || f.severity >= .warn)
                                && (range.map { r in f.lastSeen >= r.lowerBound && f.firstSeen <= r.upperBound } ?? true)
                                && (text.isEmpty || (f.title + " " + f.detail + " " + (f.device ?? "") + " " + f.category.label).lowercased().contains(text))
                        }
                        let tag = "\(String(describing: cat)) “\(text)” po \(po) \(String(describing: range))"
                        XCTAssertEqual(filter.rows(all).map(\.id), want.map(\.id), tag)
                        // Chips: every category the other filters leave, with its count, and the chosen one.
                        var other = filter
                        other.category = nil
                        let base = other.rows(all)
                        let chips = filter.chips(all)
                        XCTAssertNil(chips.first?.category)
                        XCTAssertEqual(chips.first?.count, base.count, tag)
                        for chip in chips.dropFirst() {
                            XCTAssertEqual(chip.count, base.filter { $0.category == chip.category }.count, tag)
                        }
                        XCTAssertEqual(Set(chips.dropFirst().compactMap(\.category)), Set(base.map(\.category)).union(cat.map { [$0] } ?? []), tag)
                        // Clearing the range: the same filters over the whole analysis.
                        var cleared = filter
                        cleared.range = nil
                        XCTAssertEqual(cleared.rows(all).map(\.id), TroubleshootFilter(category: cat, text: text, problemsOnly: po).rows(all).map(\.id), tag)
                    }
                }
            }
        }
        // The heading follows the range.
        XCTAssertEqual(TroubleshootFilter.heading(all, range: nil), "2 problems, 2 warnings on CORE-SW1.")
        XCTAssertEqual(TroubleshootFilter.heading(all, range: Self.at(0)...Self.at(100)),
                       "1 problem between \(Self.clock(0)) and \(Self.clock(100)) on CORE-SW1.")
        XCTAssertEqual(TroubleshootFilter.heading(all, range: Self.at(600)...Self.at(720)),
                       "2 warnings between \(Self.clock(600)) and \(Self.clock(720)) on CORE-SW1.")
        XCTAssertEqual(TroubleshootFilter.heading(all, range: Self.at(250)...Self.at(360)),
                       "Nothing wrong between \(Self.clock(250)) and \(Self.clock(360)) (4 problems and warnings outside it).")
        XCTAssertEqual(TroubleshootFilter.heading([], range: nil), "Nothing wrong that SheepLog can see.")
    }

    /// "Problems only" with a range and a chip whose findings in that range are all notes: the
    /// list is empty, the chip stays (at 0) so it can be undone, and turning Problems only off
    /// brings its notes back.
    func testProblemsOnlyWithARangeAndAChip() {
        let all = Self.sampleFindings()
        var filter = TroubleshootFilter(category: .config, problemsOnly: true, range: Self.at(300)...Self.at(400))
        XCTAssertEqual(filter.rows(all).map(\.id), [])
        XCTAssertEqual(filter.chips(all).first { $0.category == .config }?.count, 0, "the chosen chip is still there, at 0")
        XCTAssertEqual(filter.chips(all).first?.count, 1, "All counts the range's problems and warnings: the DNS warning")
        filter.problemsOnly = false
        XCTAssertEqual(filter.rows(all).map(\.id), ["e"])
        filter.category = .link
        XCTAssertEqual(filter.rows(all).map(\.id), ["b"])
        filter.range = nil
        XCTAssertEqual(filter.rows(all).map(\.id), ["a", "b", "f"])
    }

    /// The Markdown export says which range and filters it used and how many of the findings
    /// it holds, its heading counts the range, and a filter that hides every finding is not
    /// "Nothing wrong". Times carry the day when the data covers two days.
    func testExportStatesItsScope() {
        let all = Self.sampleFindings()
        var summary = AnalysisSummary()
        summary.lines = 12; summary.devices = 2; summary.start = Self.at(0); summary.end = Self.at(1_000)
        var filter = TroubleshootFilter(category: .link, text: "core", problemsOnly: true, range: Self.at(0)...Self.at(700))
        let md = filter.report(all, summary: summary, timeline: .empty, generated: Self.at(2_000))
        XCTAssertTrue(md.contains("**1 problem, 2 warnings between \(Self.clock(0)) and \(Self.clock(700)) on CORE-SW1.**"), md)
        XCTAssertTrue(md.contains("Shown: 2 of 7 findings — Link, problems and warnings only, \(Self.clock(0))–\(Self.clock(700)), matching “core”."), md)
        XCTAssertTrue(md.contains("### Port 1/1/1 on CORE-SW1 flapped."))
        XCTAssertTrue(md.contains("### Port 1/1/3 on CORE-SW1 went down."))
        XCTAssertFalse(md.contains("DNS server"), "outside the filter")
        // Everything: says so.
        let whole = TroubleshootFilter().report(all, summary: summary, timeline: .empty, generated: Self.at(2_000))
        XCTAssertTrue(whole.contains("Shown: all 7 findings."), whole)
        XCTAssertTrue(whole.contains("**2 problems, 2 warnings on CORE-SW1.**"), whole)
        // A filter that hides everything.
        filter.text = "nomatch"
        let none = filter.report(all, summary: summary, timeline: .empty, generated: Self.at(2_000))
        XCTAssertTrue(none.contains("No finding matches what was shown."), none)
        XCTAssertFalse(none.contains("Nothing wrong that SheepLog can see."), none)
        // Two days of data: the range's times carry their day.
        summary.end = Self.at(90_000)
        let wide = TroubleshootFilter(range: Self.at(0)...Self.at(86_400)).report(all, summary: summary, timeline: .empty, generated: Self.at(90_000))
        let a = Format.dayClock.string(from: Self.at(0)), b = Format.dayClock.string(from: Self.at(86_400))
        XCTAssertTrue(wide.contains("Shown: all 7 findings — \(a)–\(b)."), wide)
    }

    /// "Show" on evidence that has rolled out of memory says so and opens nothing (it opened the
    /// Log pane on a filter that showed nothing — or the device's newer lines); partly rolled out
    /// opens the rest; packets of a capture cleared since the analysis are not the new capture's
    /// frames with the same numbers; a conversation the ring rolled past is not opened.
    func testEvidenceThatRolledOutIsSaidNotShown() async throws {
        let app = AppModel.shared
        let logs = app.logs
        let model = TroubleshootModel.shared
        logs.clear()
        app.mainPane = .status
        var l = Lines()
        l.nextID = LogStore.reserveIDs(20)
        for k in 0..<3 {
            l.add(Double(k) * 120, "SW-EV", "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/7, changed state to down", sev: 3)
            l.add(Double(k) * 120 + 60, "SW-EV", "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/7, changed state to up", sev: 3)
        }
        logs.ingest(l.entries)
        let flap = try XCTUnwrap(Self.analyze(l.entries).findings.first { $0.rule == "link.flap" })
        let e = try XCTUnwrap(flap.evidence.first)
        XCTAssertEqual(TroubleshootJump.present(e, epoch: nil)?.present, 6)
        // Four of the six lines roll out: the Log pane opens on the other two.
        logs.limit = 2
        XCTAssertEqual(TroubleshootJump.show(e), .partly(present: 2, of: 6))
        XCTAssertEqual(app.mainPane, .log)
        // All of them (newer lines of the same device pushed them out): no pane, a note.
        app.mainPane = .status
        var newer = Lines()
        newer.nextID = LogStore.reserveIDs(5)
        for k in 0..<3 { newer.add(1_000 + Double(k), "SW-EV", "Interface GigabitEthernet1/0/7 input errors \(k)", sev: 4) }
        logs.ingest(newer.entries)
        XCTAssertEqual(TroubleshootJump.present(e, epoch: nil)?.present, 0)
        model.show(e)
        XCTAssertEqual(app.mainPane, .status, "an empty (or another) Log was opened")
        let note = try XCTUnwrap(model.jumpNotice)
        XCTAssertTrue(note.hasPrefix("These 6 log lines of the finding have rolled out of memory (the log keeps the newest 2 lines)"), note)
        // Evidence with no ids (a clock finding's host filter) cannot be told: it opens.
        let hostOnly = Evidence(kind: .logLines, label: "12 log lines", ids: [], query: "host:10.66.1.1")
        XCTAssertEqual(TroubleshootJump.show(hostOnly), .shown)
        XCTAssertEqual(app.mainPane, .log)

        // Packets: a capture cleared since the analysis numbers its new frames 1, 2, 3 … again.
        let packets = app.packets
        packets.clear()
        let arp = Self.packets((0..<4).map { Self.arp(Double($0), request: true, mac: "02:00:5e:14:00:50", ip: "10.1.20.50", target: "10.1.20.1") })
        packets.ingest(arp)
        let epoch = packets.epoch
        let unanswered = try XCTUnwrap(Self.analyze(packets: arp).findings.first { $0.rule == "arp.unanswered" })
        let pe = try XCTUnwrap(unanswered.evidence.first)
        XCTAssertEqual(TroubleshootJump.present(pe, epoch: epoch)?.present, 4)
        packets.clear()
        packets.ingest(Self.packets((0..<6).map { Self.arp(Double($0), request: false, mac: "02:00:5e:14:00:5\($0)", ip: "10.1.20.6\($0)", target: "10.1.20.1") }))
        XCTAssertTrue(packets.contains(id: pe.ids[0]), "frame numbers start over")
        app.mainPane = .status
        guard case .gone(let text) = TroubleshootJump.show(pe, epoch: epoch) else { return XCTFail("the new capture's frames were shown as evidence") }
        XCTAssertTrue(text.hasPrefix("These 4 packets of the finding are no longer in memory"), text)
        XCTAssertEqual(app.mainPane, .status)

        // A conversation still partly in the ring opens; one the ring rolled past does not.
        packets.clear()
        packets.ingest(Self.renumbered(Self.download(segments: 40, resends: 3).packets))
        let flowsNow = TCPFlowAnalyzer.analyze(packets.packets)
        let ref = FlowRef(key: flowsNow[0].key, packetID: flowsNow[0].firstPacketID, lastPacketID: flowsNow[0].lastPacketID)
        let fe = Evidence(kind: .flows, label: "flow ⇄", ids: [flowsNow[0].id], query: "", flows: [ref])
        packets.limit = 10
        XCTAssertEqual(TroubleshootJump.present(fe, epoch: packets.epoch)?.present, 1, "its last frames are still there")
        XCTAssertEqual(TroubleshootJump.show(fe, epoch: packets.epoch), .shown)
        XCTAssertEqual(app.mainPane, .flows)
        app.mainPane = .status
        await spin(100)
        packets.ingest(Self.renumbered(Self.packets((0..<20).map { Self.arp(100 + Double($0), request: true, mac: "02:00:5e:14:00:50", ip: "10.1.20.50", target: "10.1.20.9") }),
                                       from: (packets.packets.last?.id ?? 0) + 1))
        guard case .gone = TroubleshootJump.show(fe, epoch: packets.epoch) else { return XCTFail("a conversation that left the ring was opened") }
        XCTAssertEqual(app.mainPane, .status)
        // A new analysis clears the note.
        model.jumpNotice = "x"
        let before = PaneProbe.troubleshootAnalyses
        model.appeared()
        await waitUntil(10) { PaneProbe.troubleshootAnalyses > before && !model.analysing && LeakProbe.count("Troubleshoot.analysis") == 0 }
        model.disappeared()
        XCTAssertNil(model.jumpNotice)
    }

    // MARK: - 3. Other vendors' classic forms

    /// Each vendor's own form, read into what it says: Junos's mnemonic in the message (OSPF, a
    /// commit — the classic and the structured form —, a PEM, the link trap with its ifName),
    /// MikroTik's topics, UniFi's TRAPMGR port after "Link Down:" (was the word "TRAPMGR": every
    /// port one flapping port), EdgeOS's kernel, NX-OS's IF_UP (no "link" in it: a port that came
    /// back stayed down) and OSPF "went FULL", ASA's line protocol, 111008 write memory and
    /// 111010, FortiOS's interface status (fields: never read).
    func testOtherVendorsLinesAreRead() async throws {
        func kind(_ text: String) -> FactKind? { LineClassifier.line(parsedLine(text, from: "10.9.9.9")) }
        func text(_ k: FactKind?) -> String { k.map { "\($0)" } ?? "nil" }
        let expect: [(String, String)] = [
            ("<28>Sep 23 10:20:00 MX204-EDGE rpd[1811]: RPD_OSPF_NBRDOWN: OSPF neighbor 10.0.12.2 (realm ospf-v2 xe-0/0/1.0 area 0.0.0.0) state changed from Full to Down due to InactivityTimer (event reason: BFD session timed out and neighbor was declared dead)",
             "routing(proto: \"OSPF\", neighbor: \"10.0.12.2\", up: false)"),
            ("<29>Sep 23 10:20:41 MX204-EDGE rpd[1811]: RPD_OSPF_NBRUP: OSPF neighbor 10.0.12.2 (realm ospf-v2 xe-0/0/1.0 area 0.0.0.0) state changed from Loading to Full due to LoadDone (event reason: OSPF loading completed)",
             "routing(proto: \"OSPF\", neighbor: \"10.0.12.2\", up: true)"),
            ("<189>Sep 23 10:21:00 MX204-EDGE mgd[4410]: UI_COMMIT: User 'netops' requested 'commit' operation (comment: none)", "config(user: Optional(\"netops\"))"),
            ("<189>Sep 23 10:21:00 MX204-EDGE mgd: UI_COMMIT: User 'netops' requested 'commit' operation (comment: none)", "config(user: Optional(\"netops\"))"),
            (#"<189>1 2026-09-23T10:21:00.123+07:00 MX204-EDGE mgd 4410 UI_COMMIT [junos@2636.1.1.1.2.29 username="netops" command="commit"] User 'netops' requested 'commit' operation (comment: none)"#,
             "config(user: Optional(\"netops\"))"),
            ("<189>Sep 23 10:21:01 MX204-EDGE mgd[4410]: UI_COMMIT_PROGRESS: Commit operation in progress: signaling 'Routing protocol process'", "nil"),
            ("<188>Sep 23 10:22:00 MX204-EDGE chassisd[1509]: CHASSISD_FRU_OFFLINE_NOTICE: Taking PEM 1 offline: Removal", "hardware(SheepLog.HardwareKind.psu, recovered: false)"),
            ("<189>Sep 23 10:25:00 MX204-EDGE chassisd[1509]: CHASSISD_FRU_ONLINE_NOTICE: Taking PEM 1 online", "hardware(SheepLog.HardwareKind.psu, recovered: true)"),
            ("<28>Sep 23 10:23:00 MX204-EDGE mib2d[1612]: SNMP_TRAP_LINK_DOWN: ifIndex 526, ifAdminStatus up(1), ifOperStatus down(2), ifName xe-0/0/2", "link(iface: \"xe-0/0/2\", up: false)"),
            ("<29>Sep 23 10:23:30 MX204-EDGE mib2d[1612]: SNMP_TRAP_LINK_UP: ifIndex 526, ifAdminStatus up(1), ifOperStatus up(1), ifName xe-0/0/2", "link(iface: \"xe-0/0/2\", up: true)"),
            ("<28>Sep 23 10:24:00 MX204-EDGE mib2d[1612]: SNMP_TRAP_LINK_DOWN: ifIndex 527, ifAdminStatus down(2), ifOperStatus down(2), ifName xe-0/0/3", "nil"),
            ("<30>Sep 23 10:16:12 RB4011-HQ interface,info ether5 link down", "link(iface: \"ether5\", up: false)"),
            ("<28>Sep 23 10:16:41 RB4011-HQ system,error,critical login failure for user admin from 203.0.113.9 via ssh", "loginFail(ip: Optional(\"203.0.113.9\"), user: Optional(\"admin\"))"),
            ("<30>Sep 23 10:16:21 USW-24-PoE,f4e2c6ddeeff,v6.6.61.15220: switch: TRAPMGR: Link Down: 0/9", "link(iface: \"0/9\", up: false)"),
            ("<30>Sep 23 10:16:51 USW-24-PoE,f4e2c6ddeeff,v6.6.61.15220: switch: TRAPMGR: Link Up: 0/9", "link(iface: \"0/9\", up: true)"),
            ("<3>Sep 23 10:16:20 ER-4 kernel: [ 9812.100211] eth1: link down", "link(iface: \"eth1\", up: false)"),
            ("<189>2026 Sep 23 10:17:30 N9K-LEAF-02 %ETHPORT-5-IF_UP: Interface Ethernet1/7 is up in mode trunk", "link(iface: \"Ethernet1/7\", up: true)"),
            ("<189>2026 Sep 23 10:17:40 N9K-LEAF-02 %ETHPORT-5-IF_DOWN_ADMIN_DOWN: Interface Ethernet1/8 is down (Administratively down)", "nil"),
            ("<189>2026 Sep 23 10:18:40 N9K-LEAF-02 %OSPF-5-ADJCHANGE: ospf-100 [7243] Nbr 10.0.13.2 on Ethernet1/49 went FULL", "routing(proto: \"OSPF\", neighbor: \"10.0.13.2\", up: true)"),
            ("<164>Sep 23 2026 10:19:00 ASA-FW02 : %ASA-4-411002: Line protocol on Interface outside, changed state to down", "link(iface: \"outside\", up: false)"),
            ("<166>Sep 23 2026 10:19:40 ASA-FW02 : %ASA-6-605004: Login denied from 203.0.113.9/51234 to outside:203.0.113.1/ssh for user \"admin\"", "loginFail(ip: Optional(\"203.0.113.9\"), user: Optional(\"admin\"))"),
            ("<165>Sep 23 2026 10:19:50 ASA-FW02 : %ASA-5-111008: User 'admin' executed the 'write memory' command.", "config(user: Optional(\"admin\"))"),
            ("<165>Sep 23 2026 10:19:45 ASA-FW02 : %ASA-5-111010: User 'admin', running 'CLI' from IP 10.1.0.5, executed 'no shutdown'", "config(user: Optional(\"admin\"))"),
            ("<165>Sep 23 2026 10:19:55 ASA-FW02 : %ASA-5-111008: User 'admin' executed the 'show running-config' command.", "nil"),
            (#"<188>date=2026-09-23 time=10:30:00 devname="FGT-100F-HQ" devid="FGT1HFTK21000000" eventtime=1790134200123456789 tz="+0700" logid="0100020022" type="event" subtype="system" level="warning" vd="root" logdesc="Interface status changed" action="interface-stat-change" status="DOWN" msg="Interface port3 changed status to DOWN.""#,
             "link(iface: \"port3\", up: false)"),
        ]
        for (line, want) in expect { XCTAssertEqual(text(kind(line)), want, line) }

        // The rules over them: ports and neighbours that came back are nothing; UniFi's three
        // ports going down and up once each are not one port flapping; a Junos commit and its
        // completion are one change; an ASA's configuration line and its write memory one.
        var l = Lines()
        let unifi = "USW-24-PoE,f4e2c6ddeeff,v6.6.61.15220:"
        for (k, port) in ["0/9", "0/10", "0/11"].enumerated() {
            let s = Double(k) * 60
            l.raw(s, "<30>\(Self.bsd(s)) \(unifi) switch: TRAPMGR: Link Down: \(port)", from: "10.66.5.5")
            l.raw(s + 20, "<30>\(Self.bsd(s + 20)) \(unifi) switch: TRAPMGR: Link Up: \(port)", from: "10.66.5.5")
        }
        l.raw(10, "<189>\(Self.nxos(10)) N9K-LEAF-02 %ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/7 is down (Link failure)", from: "10.66.6.6")
        l.raw(40, "<189>\(Self.nxos(40)) N9K-LEAF-02 %ETHPORT-5-IF_UP: Interface Ethernet1/7 is up in mode trunk", from: "10.66.6.6")
        l.raw(50, "<189>\(Self.nxos(50)) N9K-LEAF-02 %OSPF-5-ADJCHANGE: ospf-100 [7243] Nbr 10.0.13.2 on Ethernet1/49 went DOWN", from: "10.66.6.6")
        l.raw(90, "<189>\(Self.nxos(90)) N9K-LEAF-02 %OSPF-5-ADJCHANGE: ospf-100 [7243] Nbr 10.0.13.2 on Ethernet1/49 went FULL", from: "10.66.6.6")
        l.raw(100, "<189>\(Self.bsd(100)) MX204-EDGE mgd[4410]: UI_COMMIT: User 'netops' requested 'commit' operation (comment: none)", from: "10.66.7.7")
        l.raw(101, "<189>\(Self.bsd(101)) MX204-EDGE mgd[4410]: UI_COMMIT_PROGRESS: Commit operation in progress: commit wrapup...", from: "10.66.7.7")
        l.raw(112, "<189>\(Self.bsd(112)) MX204-EDGE mgd[4410]: UI_COMMIT_COMPLETED: commit complete", from: "10.66.7.7")
        l.raw(120, "<165>\(Self.asa(120)) ASA-FW02 : %ASA-5-111010: User 'admin', running 'CLI' from IP 10.1.0.5, executed 'no shutdown'", from: "10.66.8.8")
        l.raw(130, "<165>\(Self.asa(130)) ASA-FW02 : %ASA-5-111008: User 'admin' executed the 'write memory' command.", from: "10.66.8.8")
        let r = Self.analyze(l.entries)
        XCTAssertEqual(Set(r.findings.map { "\($0.rule)|\($0.device ?? "-")" }), ["config.change|MX204-EDGE", "config.change|ASA-FW02"],
                       r.findings.map(\.title).description)
        let junos = try XCTUnwrap(r.findings.first { $0.device == "MX204-EDGE" })
        XCTAssertEqual(junos.title, "Configuration changed on MX204-EDGE by netops at \(Self.clock(100.25)).", "one commit, not two changes")
        XCTAssertEqual(junos.evidence.first?.ids.count, 2, "the commit and its completion")
        XCTAssertEqual(r.findings.first { $0.device == "ASA-FW02" }?.title, "Configuration changed on ASA-FW02 by admin at \(Self.clock(120.25)).")
        // Their evidence filters show their lines (a Junos commit has no "config" in it).
        let store = LogStore()
        store.ingest(l.entries)
        for f in r.findings {
            let e = try XCTUnwrap(f.evidence.first)
            store.queryText = e.query
            store.applyQueryText()
            await waitUntil { Set(store.visible.map(\.id)).isSuperset(of: e.ids) }
            XCTAssertTrue(Set(store.visible.map(\.id)).isSuperset(of: e.ids), "\(f.title): `\(e.query)`")
        }
    }

    /// The corpus's round-13 lines, read into what each says (Round12Tests' healthy-chatter
    /// list says which of them are findings: a port or neighbour that came back is nothing).
    func testCorpusVendorLinesAreRead() throws {
        let dir = Round12Tests.testsDir.appending(path: "corpus")
        let other = try String(contentsOf: dir.appending(path: "other.log"), encoding: .utf8).split(whereSeparator: \.isNewline).map(String.init)
        let forti = try String(contentsOf: dir.appending(path: "fortigate.log"), encoding: .utf8).split(whereSeparator: \.isNewline).map(String.init)
        XCTAssertEqual(other.count, 63, "round 14 added lines 39–53 (Round14Tests reads them), round 15 lines 54–63 (Round15Tests)")
        XCTAssertEqual(forti.count, 14, "round 15 added lines 11–14")
        let read = (other[21..<38] + forti[8..<10]).map { LineClassifier.line(parsedLine($0, from: "10.9.9.9")).map { "\($0)" } ?? "nil" }
        XCTAssertEqual(read, [
            "routing(proto: \"OSPF\", neighbor: \"10.0.12.2\", up: false)", "routing(proto: \"OSPF\", neighbor: \"10.0.12.2\", up: true)",
            "config(user: Optional(\"netops\"))", "hardware(SheepLog.HardwareKind.psu, recovered: false)",
            "link(iface: \"ether5\", up: false)", "link(iface: \"ether5\", up: true)",
            "link(iface: \"0/9\", up: false)", "link(iface: \"0/9\", up: true)",
            "link(iface: \"eth1\", up: false)", "link(iface: \"eth1\", up: true)",
            "link(iface: \"Ethernet1/7\", up: false)", "link(iface: \"Ethernet1/7\", up: true)",
            "routing(proto: \"OSPF\", neighbor: \"10.0.13.2\", up: false)", "routing(proto: \"OSPF\", neighbor: \"10.0.13.2\", up: true)",
            "link(iface: \"outside\", up: false)", "link(iface: \"outside\", up: true)",
            "config(user: Optional(\"admin\"))",
            "link(iface: \"port3\", up: false)", "link(iface: \"port3\", up: true)",
        ])
    }

    // MARK: - 4. EAP-id attribution fuzz

    /// 200 seeds: 2–8 wired clients on 1–3 authenticators (switch MACs), every EAPOL frame to the
    /// PAE group, each exchange with random EAP ids and outcome, interleaved at random. No attempt
    /// may hold two clients' frames or a result its client did not get; every exchange whose ids no
    /// other exchange used is attributed whole (its frames, its user, its result); no request is
    /// left as a port nobody answered.
    func testEAPIDAttributionFuzz() throws {
        var attributed = 0, ambiguous = 0
        var failures: [String] = []
        for seed in UInt64(1)...UInt64(200) {
            var rng = SplitMix(seed: seed &* 7_919)
            let clients = Int(rng.next() % 7) + 2
            let authenticators = Int(rng.next() % 3) + 1
            var exchanges: [[(bytes: [UInt8], owner: Int)]] = []
            var ids: [Set<UInt8>] = []
            var outcome: [Bool] = []
            var macs: [[UInt8]] = []
            for c in 0..<clients {
                let mac: [UInt8] = [0x02, 0x14, UInt8(seed & 0xff), 0, 0, UInt8(c + 1)]
                let sw: [UInt8] = [0x00, 0x1c, 0x0e, 0, 2, UInt8(Int(rng.next() % UInt64(authenticators)) + 1)]
                let base = UInt8(truncatingIfNeeded: rng.next())
                let ok = rng.next() % 3 != 0
                exchanges.append(Round12Tests.groupExchange(client: mac, sw: sw, idBase: base, succeed: ok))
                ids.append(Set((0...4).map { base &+ UInt8($0) }))
                outcome.append(ok)
                macs.append(mac)
            }
            let (packets, owner) = Round12Tests.interleave(exchanges, seed: seed)
            let sessions = AuthSessions.build(packets)
            let tag = "seed \(seed): \(clients) clients on \(authenticators) authenticator\(authenticators == 1 ? "" : "s")"
            for s in sessions {
                let owners = Set(s.packetIDs.compactMap { owner[$0] })
                if owners.count > 1 { failures.append("\(tag): \(s.client) holds frames of clients \(owners.sorted())") }
                if s.isPortOnly { failures.append("\(tag): every request was answered — \(s.client) \(s.result)") }
                guard let o = owners.first else { continue }
                if s.client != AuthLab.macText(macs[o - 1]) { failures.append("\(tag): \(s.client) holds client \(o)'s frames") }
                switch s.result {
                case .accepted where !outcome[o - 1]: failures.append("\(tag): \(s.client) accepted, its exchange failed")
                case .rejected where outcome[o - 1]: failures.append("\(tag): \(s.client) rejected, its exchange succeeded")
                default: break
                }
            }
            for c in 0..<clients {
                let others = ids.indices.filter { $0 != c }.reduce(Set<UInt8>()) { $0.union(ids[$1]) }
                let mine = sessions.filter { $0.client == AuthLab.macText(macs[c]) }
                let frames = Set(owner.filter { $0.value == c + 1 }.map(\.key))
                if !Set(mine.flatMap(\.packetIDs)).isSubset(of: frames) { failures.append("\(tag): client \(c + 1) holds others' frames") }
                guard ids[c].isDisjoint(with: others) else { ambiguous += 1; continue }
                attributed += 1
                let got = Set(mine.flatMap(\.packetIDs))
                if mine.count != 1 || got != frames || mine.first?.result != (outcome[c] ? .accepted : .rejected("EAP-Failure"))
                    || mine.first?.user != "user\(c + 1)" {
                    failures.append("\(tag): client \(c + 1) (ids \(ids[c].sorted())) — \(mine.count) attempts \(mine.map { "\($0.result)" }), "
                                    + "\(got.count) of \(frames.count) frames, missing \(frames.subtracting(got).sorted())")
                }
            }
        }
        print("[fuzz] EAP ids: \(attributed) exchanges with ids of their own attributed, \(ambiguous) sharing an id checked for mixing; \(failures.count) failures")
        XCTAssertEqual(failures.count, 0, failures.prefix(12).joined(separator: "\n"))
        XCTAssertGreaterThan(attributed, 300)
        XCTAssertGreaterThan(ambiguous, 50)
    }

    /// The test helper `AuthLab.peap(succeed: false)` ignored `succeed`: the "failed" attempts of
    /// the Authentication tests were accepted. It fails now (Access-Reject, EAP-Failure).
    func testPEAPHelperFailsWhenAskedTo() throws {
        for ok in [true, false] {
            var lab = AuthLab(client: [0x02, 0x15, 0, 0, 0, ok ? 1 : 2])
            lab.peap(user: "gil@corp.example", succeed: ok, rounds: 4, ip: "10.20.0.90")
            let s = try XCTUnwrap(AuthSessions.build(lab.packets).first)
            XCTAssertEqual(s.result == .accepted, ok, "\(s.result)")
            if !ok { XCTAssertEqual(s.health, .bad) }
        }
    }

    // MARK: - 5. Panes that left: the pane-switch flake

    /// The flake ("2 analyses" once in testPaneSwitchMidAnalysisLeavesNoStaleTask): a Flows or
    /// Authentication pane that had disappeared — a test window closed, its SwiftUI graph not yet
    /// torn down — still received the store's publishes and started an analysis on the next
    /// ingest, counted with the new pane's (it drew its ladder over the new pane's probe too, and
    /// took Follow requests meant for the pane appearing). A pane that has left starts nothing and
    /// takes nothing; a debounced re-analysis with nothing new (a Packets filter rescan) is skipped.
    func testPanesThatLeftStartNothing() async throws {
        let packets = AppModel.shared.packets
        packets.clear()
        AppModel.shared.mainPane = .status
        packets.ingest(Round11InteractionTests.conversations())
        for (name, make) in [("Flows", { AnyView(FlowView()) }), ("Auth", { AnyView(AuthView()) })] {
            let probe = { name == "Flows" ? PaneProbe.flowAnalyses : PaneProbe.authAnalyses }
            let n0 = probe()
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1280, height: 820), styleMask: [.titled, .resizable], backing: .buffered, defer: false)
            w.isReleasedWhenClosed = false
            w.contentView = NSHostingView(rootView: make())
            w.orderFront(nil)
            await waitUntil { probe() > n0 && LeakProbe.count("\(name).analysis") == 0 }
            XCTAssertEqual(probe(), n0 + 1, name)
            // Nothing new: a Packets filter rescan bumps `generation`; the packets are the same.
            packets.queryText = "tcp"
            packets.applyQueryNow(synchronous: true)
            packets.queryText = ""
            packets.applyQueryNow(synchronous: true)
            try await Task.sleep(for: .milliseconds(1_400))
            XCTAssertEqual(probe(), n0 + 1, "\(name): a rescan of the same packets analysed them again")
            // The window closes as the tests' tearDown closes it: the pane has left.
            w.contentView = nil
            w.close()
            await spin(100)
            let n1 = probe()
            packets.ingest(Round11InteractionTests.conversations(firstID: packets.packets.count + 1, offset: 30, port: UInt16(51_000 + n1 % 100)))
            try await Task.sleep(for: .milliseconds(1_500))
            XCTAssertEqual(probe(), n1, "\(name): a pane that left analysed the new packets")
            XCTAssertEqual(LeakProbe.count("\(name).analysis") + LeakProbe.count("\(name).scheduled"), 0, name)
        }
        // A Follow request while a Flows pane that left is still in memory: the appearing pane gets it.
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1280, height: 820), styleMask: [.titled, .resizable], backing: .buffered, defer: false)
        w.isReleasedWhenClosed = false
        w.contentView = NSHostingView(rootView: FlowView())
        w.orderFront(nil)
        await spin(300)
        w.contentView = nil
        w.close()
        await spin(50)
        let flows = TCPFlowAnalyzer.analyze(packets.packets)
        let target = try XCTUnwrap(flows.first { $0.server == "10.2.0.2" })
        AppModel.shared.mainPane = .flows
        NotificationCenter.default.post(name: .sheepLogSelectFlow, object: FlowSelectRequest(key: target.key, packetID: target.events[3].packetIDs[0]))
        await waitUntil { PaneProbe.flowsLadder?.eventFrames == target.events[3].packetIDs }
        XCTAssertEqual(PaneProbe.flowsLadder?.subject, "\(target.clientEndpoint) → \(target.serverEndpoint)")
        AppModel.shared.mainPane = .status
    }

    // MARK: - 6. Sweep

    /// SNMP results recorded for Troubleshoot: under the host the run asked (the form's host
    /// may have been retyped since), only when it succeeded (a failed run leaves the last run's
    /// rows on screen), and with ports only from the Interfaces walk — a Quick test of another
    /// switch after walking the first was recorded with the first one's ports ("3 ports on SW-B
    /// are enabled but down"); a Get after the walk of the same switch hid the walk's findings.
    func testSNMPResultsRecordedUnderTheRunThatMadeThem() throws {
        let rows = [VarBindRow(id: 1, oid: .sysName, oidText: OID.sysName.dotted, name: "sysName.0", type: "OCTET STRING", value: "SW-B", isBad: false)]
        let ports = [Self.ifRow(1, "1/1/1"), Self.ifRow(2, "1/1/2", oper: "down", since: 30_000)]
        let quick = SNMPTestModel.FinishedRun(host: "10.1.0.14", label: "Quick test", succeeded: true)
        let snap = try XCTUnwrap(TroubleshootModel.snapshot(of: quick, rows: rows, interfaces: ports, taken: Self.at(0)))
        XCTAssertEqual(snap.host, "10.1.0.14")
        XCTAssertTrue(snap.interfaces.isEmpty, "another run's ports")
        let walk = SNMPTestModel.FinishedRun(host: "10.1.0.13", label: "Interfaces", succeeded: true)
        XCTAssertEqual(TroubleshootModel.snapshot(of: walk, rows: rows, interfaces: ports, taken: Self.at(0))?.interfaces.count, 2)
        XCTAssertNil(TroubleshootModel.snapshot(of: SNMPTestModel.FinishedRun(host: "10.1.0.15", label: "Get", succeeded: false),
                                                rows: rows, interfaces: [], taken: Self.at(0)), "a failed run's rows are the last run's")
        XCTAssertNil(TroubleshootModel.snapshot(of: nil, rows: rows, interfaces: ports, taken: Self.at(0)))
        // The rules: a Get after the walk (same device) does not hide the walk's port findings.
        let w = Self.walk(0, rows: [Self.ifRow(1, "1/1/1", errors: 10), Self.ifRow(9, "1/1/9", oper: "down", since: 30_000)],
                          values: [FindingRules.dot3Duplex.appending(1): "halfDuplex(2)"])
        let get = SNMPSnapshot(host: "10.1.0.13", taken: Self.at(120), sysName: "SW-A", sysUpTime: 86_412_000, interfaces: [], values: [.sysName: "SW-A"])
        let r = Self.analyze(snmp: [w, get], now: Self.at(180))
        XCTAssertEqual(Set(r.findings.map(\.rule)), ["snmp.operDown", "snmp.errors", "snmp.halfDuplex"], r.findings.map(\.title).description)
        // A second walk after the Get still compares the two walks.
        let w2 = Self.walk(300, rows: [Self.ifRow(1, "1/1/1", errors: 60), Self.ifRow(9, "1/1/9", oper: "down", since: 60_000)])
        let r2 = Self.analyze(snmp: [w, get, w2], now: Self.at(360))
        XCTAssertEqual(r2.findings.first { $0.rule == "snmp.errorsGrowing" }?.title, "Interface errors are growing on SW-A: 1/1/1 +50 in 5 min.")
    }

    /// A configuration change before a link flap is named in the flap, and the cross-reference's
    /// evidence filter shows the change's line — a Junos commit has no "config" in it, so the
    /// filter `host:… config` hid it.
    func testCrossReferenceEvidenceShowsAJunosCommit() async throws {
        var l = Lines()
        l.raw(0, "<189>\(Self.bsd(0)) MX204-EDGE mgd[4410]: UI_COMMIT: User 'netops' requested 'commit' operation (comment: none)", from: "10.66.7.7")
        for k in 0..<3 {
            let d = 60 + Double(k) * 40, u = d + 20
            l.raw(d, "<28>\(Self.bsd(d)) MX204-EDGE mib2d[1612]: SNMP_TRAP_LINK_DOWN: ifIndex 526, ifAdminStatus up(1), ifOperStatus down(2), ifName xe-0/0/2", from: "10.66.7.7")
            l.raw(u, "<29>\(Self.bsd(u)) MX204-EDGE mib2d[1612]: SNMP_TRAP_LINK_UP: ifIndex 526, ifAdminStatus up(1), ifOperStatus up(1), ifName xe-0/0/2", from: "10.66.7.7")
        }
        let r = Self.analyze(l.entries)
        let flap = try XCTUnwrap(r.findings.first { $0.rule == "link.flap" }, r.findings.map(\.title).description)
        XCTAssertTrue(flap.detail.contains("A configuration change on this device by netops"), flap.detail)
        let change = try XCTUnwrap(flap.evidence.first { $0.label == "config change" })
        let store = LogStore()
        store.ingest(l.entries)
        store.queryText = change.query
        store.applyQueryText()
        await waitUntil { !store.visible.isEmpty }
        XCTAssertTrue(Set(store.visible.map(\.id)).isSuperset(of: change.ids), "`\(change.query)` hides the commit")
    }

    /// A timeline dot or bar clicked while the chip, the text, Problems only and a range hide its
    /// finding: each filter that hid it is lifted, the others stay (what `reveal` does, through
    /// the filter rules the view uses).
    func testRevealLiftsOnlyTheFiltersThatHideIt() {
        let all = Self.sampleFindings()
        let target = all.first { $0.id == "b" }!        // Link, a note, at 300
        var filter = TroubleshootFilter(category: .dns, text: "core", problemsOnly: true, range: Self.at(600)...Self.at(700))
        XCTAssertFalse(filter.rows(all).contains { $0.id == target.id })
        filter.reveal(target)
        XCTAssertTrue(filter.rows(all).contains { $0.id == target.id })
        XCTAssertEqual(filter, TroubleshootFilter())
        // Filters that do not hide it stay: a range and a text that hold it.
        var kept = TroubleshootFilter(category: .link, text: "acc-sw2", problemsOnly: false, range: Self.at(250)...Self.at(350))
        kept.reveal(target)
        XCTAssertEqual(kept, TroubleshootFilter(category: .link, text: "acc-sw2", problemsOnly: false, range: Self.at(250)...Self.at(350)))
    }
}
