import XCTest
@testable import SheepLog

/// The Troubleshoot pane's rules: every rule with a fixture that must raise it and one that must
/// not, the bad-day story in order with its cross-reference, the timeline, the client report,
/// and the time budget.
final class TroubleshootTests: XCTestCase {
    static let dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .appending(path: "Tests/troubleshoot")

    private func fixture(_ name: String) throws -> String {
        try String(contentsOf: Self.dir.appending(path: name), encoding: .utf8)
    }

    /// The fixture's lines as received live from their devices.
    private func entries(_ name: String) throws -> [LogEntry] {
        TroubleshootFixture.liveEntries(try fixture(name), firstID: 1)
    }

    private func run(_ entries: [LogEntry] = [], packets: [Packet] = [], flows: [TCPFlow] = [], snmp: [SNMPSnapshot] = [],
                     counters: EngineCounters = EngineCounters(), now: Date? = nil, extra: [Finding] = []) -> TroubleshootResult {
        var input = TroubleshootInput()
        input.entries = entries
        input.packets = packets
        input.flows = flows
        input.snmp = snmp
        input.counters = counters
        input.extra = extra
        let latest = (entries.map(\.received) + packets.map(\.timestamp)).max() ?? Date()
        input.now = now ?? latest.addingTimeInterval(60)
        return FindingRules.analyze(input)
    }

    private func rules(_ r: TroubleshootResult) -> [String] { r.findings.map(\.rule) }

    private func only(_ r: TroubleshootResult, _ rule: String) -> [Finding] { r.findings.filter { $0.rule == rule } }

    private let t0 = Date(timeIntervalSinceReferenceDate: 780_000_000)

    // MARK: Link

    func testLinkFlapEveryVendorShape() throws {
        let r = run(try entries("link-flap.log"))
        let flaps = only(r, "link.flap")
        let byDevice = Dictionary(flaps.map { ($0.device ?? "", $0) }, uniquingKeysWith: { a, _ in a })
        let expected = ["CX6300-CORE-01": "1/1/24", "HW-CE6881": "10GE1/0/1", "CORE-RTR1": "GigabitEthernet0/1",
                        "FGT-60F-Branch": "port3", "SW-2930F-01": "24", "MT-EDGE": "ether1"]
        XCTAssertEqual(Set(byDevice.keys), Set(expected.keys), rules(r).description)
        for (device, iface) in expected {
            guard let f = byDevice[device] else { continue }
            XCTAssertEqual(f.severity, .bad)
            XCTAssertEqual(f.category, .link)
            XCTAssertTrue(f.title.contains("Port \(iface) on \(device)"), f.title)
            XCTAssertGreaterThanOrEqual(f.count, 3)
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertTrue(f.evidence[0].query.contains("host:"), f.evidence[0].query)
            XCTAssertFalse(f.nextSteps.isEmpty)
            XCTAssertNotNil(f.snmpTarget)
        }
        // The Huawei alarm and its line-protocol line, a second apart, are one change.
        XCTAssertEqual(byDevice["HW-CE6881"]?.count, 3)
        XCTAssertTrue(byDevice["FGT-60F-Branch"]?.detail.contains("It is down now") ?? false)
    }

    func testLinkNoFlap() throws {
        let r = run(try entries("link-ok.log"))
        XCTAssertTrue(r.findings.filter { $0.category == .link }.isEmpty, r.findings.map(\.title).description)
    }

    func testLinkDownAndNotBack() throws {
        let line = "<190>1 2026-09-23T10:00:00+07:00 CX6300-ACC-3 intfd 1633 - - Event|403|LOG_INFO|AMM|1/1|Link status for interface 1/1/7 is down"
        let e = TroubleshootFixture.liveEntries(line, firstID: 1)
        let t = e[0].received
        let late = run(e, now: t.addingTimeInterval(600))
        XCTAssertEqual(only(late, "link.down").count, 1)
        XCTAssertEqual(only(late, "link.down").first?.severity, .warn)
        XCTAssertTrue(only(late, "link.down").first?.title.contains("1/1/7") ?? false)
        XCTAssertTrue(only(run(e, now: t.addingTimeInterval(120)), "link.down").isEmpty, "5 minutes' grace")
        let back = TroubleshootFixture.liveEntries(line + "\n" + line.replacingOccurrences(of: "10:00:00", with: "10:00:30")
            .replacingOccurrences(of: "is down", with: "is up"), firstID: 1)
        XCTAssertTrue(run(back, now: t.addingTimeInterval(900)).findings.isEmpty)
    }

    private func trap(_ id: Int, _ name: String, at t: Date, from address: String = "10.1.0.1", fields: [LogField] = []) -> LogEntry {
        LogEntry(id: id, received: t, deviceTime: nil, sourceAddress: address, sourcePort: 162, transport: .trap, facility: .local0,
                 severity: name.hasPrefix("link") ? .warning : .notice, priority: nil, hostname: address, program: name, pid: nil,
                 message: name + " " + fields.map { "\($0.key)=\($0.value)" }.joined(separator: ", "),
                 raw: name, vendor: .snmpTrap, fields: fields)
    }

    func testLinkFlapFromTrapsNamedAfterTheSyslogHost() throws {
        var list = TroubleshootFixture.liveEntries("<189>1 2026-09-23T10:00:12+07:00 CORE-CX-6300 hpe-config 2211 - - Event|6801|LOG_NOTICE|UKWN|-|Configuration saved to startup-config by admin", firstID: 1)
        list[0] = LogEntry(id: 1, received: list[0].received, deviceTime: list[0].deviceTime, sourceAddress: "10.1.0.1", sourcePort: 514,
                           transport: .udp, facility: list[0].facility, severity: list[0].severity, priority: list[0].priority,
                           hostname: list[0].hostname, program: list[0].program, pid: nil, message: list[0].message, raw: list[0].raw,
                           vendor: list[0].vendor, fields: list[0].fields)
        let start = list[0].received.addingTimeInterval(60)
        let port = [LogField("ifIndex.24", "24"), LogField("ifName.24", "1/1/24"), LogField("trap_oid", "1.3.6.1.6.3.1.1.5.3")]
        for k in 0..<4 {
            list.append(trap(10 + k * 2, "linkDown", at: start.addingTimeInterval(Double(k) * 90), fields: port))
            list.append(trap(11 + k * 2, "linkUp", at: start.addingTimeInterval(Double(k) * 90 + 20), fields: port))
        }
        list.append(trap(40, "1.3.6.1.6.3.1.1.5.1", at: start.addingTimeInterval(400), fields: [LogField("trap_oid", "1.3.6.1.6.3.1.1.5.1")]))
        let r = run(list)
        let flap = try XCTUnwrap(only(r, "link.flap").first)
        XCTAssertEqual(flap.device, "CORE-CX-6300", "a trap is named after the address's syslog host")
        XCTAssertEqual(flap.source, .traps)
        XCTAssertEqual(flap.count, 4)
        XCTAssertTrue(flap.evidence.contains { $0.kind == .traps && $0.ids.count == 8 })
        let restart = try XCTUnwrap(only(r, "device.restart").first)
        XCTAssertEqual(restart.severity, .warn)
        XCTAssertTrue(restart.title.contains("cold start"))
    }

    // MARK: Hardware

    func testHardware() throws {
        let r = run(try entries("hardware.log"))
        func find(_ rule: String, _ device: String) -> Finding? { r.findings.first { $0.rule == rule && $0.device == device } }
        XCTAssertEqual(find("hw.psu", "CX6300-ACC-12")?.severity, .bad, rules(r).description)
        XCTAssertEqual(find("hw.psu", "SW-2930F-01")?.severity, .bad)
        XCTAssertEqual(find("hw.fan", "CX6300-ACC-12")?.severity, .bad)
        XCTAssertEqual(find("hw.fan", "S5720-DIST-B")?.severity, .bad)
        XCTAssertEqual(find("hw.temperature", "CORE-RTR1")?.severity, .bad, "critical and shutting down")
        XCTAssertEqual(find("hw.poe", "ACC-CX-6100-2F")?.severity, .warn)
        XCTAssertTrue(find("hw.psu", "CX6300-ACC-12")?.title.contains("Power supply 2 in slot 1/1 failed") ?? false)
        XCTAssertTrue(r.findings.filter { $0.category == .hardware }.allSatisfy { !$0.nextSteps.isEmpty })
    }

    func testHardwareRoutineLines() throws {
        let r = run(try entries("hardware-ok.log"))
        XCTAssertTrue(r.findings.filter { $0.category == .hardware }.isEmpty, r.findings.map(\.title).description)
    }

    // MARK: Spanning tree

    func testSpanningTree() throws {
        let r = run(try entries("stp.log"))
        XCTAssertEqual(only(r, "stp.topologyChange").first?.severity, .warn, rules(r).description)
        XCTAssertEqual(only(r, "stp.topologyChange").first?.device, "CORE-CX-6300")
        XCTAssertEqual(only(r, "stp.loop").first?.severity, .bad)
        XCTAssertTrue(only(r, "stp.loop").first?.title.contains("port 12") ?? false)
        XCTAssertEqual(only(r, "stp.bpduGuard").first?.severity, .warn)
        XCTAssertTrue(only(r, "stp.bpduGuard").first?.title.contains("Gi1/0/5") ?? false)
        XCTAssertEqual(only(r, "stp.storm").first?.severity, .bad)
        XCTAssertEqual(only(r, "stp.rootChange").first?.device, "S5720-DIST-B")
    }

    func testSpanningTreeQuiet() throws {
        let r = run(try entries("stp-ok.log"))
        XCTAssertTrue(r.findings.filter { $0.category == .stp }.isEmpty, r.findings.map(\.title).description)
    }

    // MARK: Routing

    func testRoutingNeighbors() throws {
        let r = run(try entries("routing.log"))
        let list = only(r, "routing.neighbor")
        XCTAssertEqual(list.first { $0.device == "CORE-RTR1" }?.severity, .bad, rules(r).description)
        XCTAssertTrue(list.first { $0.device == "CORE-RTR1" }?.title.contains("10.0.0.6") ?? false)
        XCTAssertEqual(list.first { $0.device == "S5720-CORE" }?.severity, .bad)
        XCTAssertTrue(list.first { $0.device == "S5720-CORE" }?.title.contains("10.0.0.2") ?? false)
        XCTAssertEqual(list.first { $0.device == "EDGE-RTR2" }?.severity, .warn, "BGP came back each time: flapping")
        XCTAssertTrue(run(try entries("routing-ok.log")).findings.filter { $0.category == .routing }.isEmpty)
    }

    // MARK: Config, logins, restarts

    func testConfigLoginsRestarts() throws {
        let r = run(try entries("admin.log"))
        let configs = only(r, "config.change")
        XCTAssertTrue(configs.contains { $0.device == "CORE-RTR1" && $0.title.contains("netops") }, configs.map(\.title).description)
        XCTAssertTrue(configs.contains { $0.device == "PA-3220" })
        XCTAssertTrue(configs.allSatisfy { $0.severity == .info })
        let login = try XCTUnwrap(only(r, "login.failures").first)
        XCTAssertEqual(login.severity, .bad)
        XCTAssertEqual(login.category, .security)
        XCTAssertEqual(login.client, "198.51.100.7")
        XCTAssertGreaterThanOrEqual(login.count, 5)
        XCTAssertTrue(login.detail.contains("succeeded"), login.detail)
        let restarts = only(r, "device.restart")
        XCTAssertEqual(restarts.first { $0.device == "CORE-RTR1" }?.severity, .warn)
        XCTAssertEqual(restarts.first { $0.device == "S5720-CORE" }?.severity, .info, "a reboot command is planned")
    }

    func testAdminQuiet() throws {
        let r = run(try entries("admin-ok.log"))
        XCTAssertTrue(r.findings.isEmpty, r.findings.map(\.title).description)
    }

    // MARK: Syslog hygiene

    private func line(_ text: String, from: String, received: Date, id: Int) -> LogEntry {
        parsedLine(text, from: from, received: received, id: id)
    }

    private static let stamp: DateFormatter = {
        let f = Format.gregorian("yyyy-MM-dd'T'HH:mm:ssXXXXX")
        f.timeZone = TimeZone(identifier: "UTC")
        return f
    }()

    private func stamped(_ d: Date, _ msg: String, host: String = "SW-CLOCK", sev: Int = 6) -> String {
        "<\(184 + sev)>1 \(Self.stamp.string(from: d)) \(host) app 1 - - \(msg)"
    }

    func testDeviceClock() {
        var list: [LogEntry] = []
        for k in 0..<5 {
            let device = t0.addingTimeInterval(Double(k) * 30)
            list.append(line(stamped(device, "port 3 up"), from: "10.1.0.40", received: device.addingTimeInterval(7_200 + 0.3), id: k + 1))
        }
        let r = run(list)
        let f = only(r, "syslog.clock").first
        XCTAssertEqual(f?.severity, .warn, rules(r).description)
        XCTAssertTrue(f?.title.contains("2 h behind") ?? false, f?.title ?? "")
        XCTAssertTrue(f?.detail.contains("time-zone") ?? false)
        // A good clock, and a file replayed at once (its lines all arrive together): nothing.
        let good = (0..<5).map { k in line(stamped(t0.addingTimeInterval(Double(k) * 30), "x"), from: "10.1.0.41",
                                            received: t0.addingTimeInterval(Double(k) * 30 + 2), id: k + 1) }
        XCTAssertTrue(only(run(good), "syslog.clock").isEmpty)
        let replay = (0..<5).map { k in line(stamped(t0.addingTimeInterval(Double(k) * 60), "x"), from: "10.1.0.42",
                                              received: t0.addingTimeInterval(90_000), id: k + 1) }
        XCTAssertTrue(only(run(replay), "syslog.clock").isEmpty)
    }

    func testErrorSpike() {
        var list: [LogEntry] = []
        var id = 1
        for m in 0..<12 {
            let n = m == 8 ? 30 : 1
            for k in 0..<n {
                let t = t0.addingTimeInterval(Double(m) * 60 + Double(k))
                list.append(line(stamped(t, "fpga parity error", sev: 3), from: "10.1.0.50", received: t, id: id)); id += 1
            }
        }
        let f = only(run(list), "syslog.errorSpike").first
        XCTAssertEqual(f?.severity, .warn)
        XCTAssertEqual(f?.count, 30)
        let steady = (0..<36).map { k in
            let t = t0.addingTimeInterval(Double(k) * 20)
            return line(stamped(t, "fpga parity error", sev: 3), from: "10.1.0.51", received: t, id: k + 1)
        }
        XCTAssertTrue(only(run(steady), "syslog.errorSpike").isEmpty)
    }

    func testUnknownVendorChattySource() {
        func lines(_ n: Int, _ addr: String) -> [LogEntry] {
            (0..<n).map { k in
                let t = t0.addingTimeInterval(Double(k))
                return line("<14>1 \(Self.stamp.string(from: t)) nas01 storaged 1 - - volume check \(k) complete", from: addr, received: t, id: k + 1)
            }
        }
        let loud = lines(600, "10.1.0.60")
        XCTAssertEqual(loud[0].vendor, .unknown)
        XCTAssertEqual(only(run(loud), "syslog.vendor").first?.severity, .info)
        XCTAssertTrue(only(run(lines(100, "10.1.0.61")), "syslog.vendor").isEmpty)
    }

    // MARK: Capacity

    private func flood(seconds: Int, perSecond: Int, from addr: String) -> [LogEntry] {
        let template = parsedLine("<190>1 2026-09-23T10:00:00+07:00 FW-FLOOD app 1 - - debug packet trace", from: addr)
        var out: [LogEntry] = []
        var id = 1
        for s in 0..<seconds {
            for k in 0..<perSecond {
                let t = t0.addingTimeInterval(Double(s) + Double(k) / Double(perSecond))
                out.append(LogEntry(id: id, received: t, deviceTime: t, sourceAddress: addr, sourcePort: 514, transport: .udp,
                                    facility: template.facility, severity: template.severity, priority: template.priority,
                                    hostname: template.hostname, program: template.program, pid: nil, message: template.message,
                                    raw: template.raw, vendor: template.vendor, fields: template.fields))
                id += 1
            }
        }
        return out
    }

    func testLogFlood() {
        XCTAssertEqual(only(run(flood(seconds: 6, perSecond: 1_200, from: "10.1.0.70")), "capacity.logRate").first?.severity, .warn)
        XCTAssertTrue(only(run(flood(seconds: 3, perSecond: 1_200, from: "10.1.0.71")), "capacity.logRate").isEmpty)
        XCTAssertTrue(only(run(flood(seconds: 20, perSecond: 400, from: "10.1.0.72")), "capacity.logRate").isEmpty)
    }

    func testEngineCounters() {
        var c = EngineCounters(logCount: 100_000, logLimit: 100_000, logDropped: 5_000, logLost: 120,
                               packetCount: 10, packetLimit: 200_000, packetDropped: 40, packetLost: 40)
        let r = run(counters: c, now: t0)
        XCTAssertEqual(Set(rules(r)), ["capacity.logLost", "capacity.packetLost", "capacity.logBuffer"])
        c = EngineCounters(logCount: 10, logLimit: 100_000, packetCount: 10, packetLimit: 200_000)
        XCTAssertTrue(run(counters: c, now: t0).findings.isEmpty)
    }

    // MARK: DHCP

    private func dhcpFrame(_ t: Double, client: String, type: UInt8, xid: UInt32, vlan: Int?, server: String? = nil,
                           yiaddr: String = "0.0.0.0", lease: UInt32? = nil) -> (Double, [UInt8]) {
        let fromServer = type == 2 || type == 5 || type == 6
        let msg = TroubleshootFixture.dhcp(op: fromServer ? 2 : 1, type: type, xid: xid, client: client, yiaddr: yiaddr,
                                           server: server, lease: lease)
        return (t, TroubleshootFixture.udp4(srcMAC: fromServer ? "00:1a:1e:00:00:09" : client, dstMAC: fromServer ? client : "ff:ff:ff:ff:ff:ff",
                                            src: fromServer ? (server ?? "10.1.0.10") : "0.0.0.0", dst: fromServer ? "10.1.20.99" : "255.255.255.255",
                                            sport: fromServer ? 67 : 68, dport: fromServer ? 68 : 67, vlan: vlan, msg))
    }

    private func packets(_ frames: [(Double, [UInt8])]) -> [Packet] {
        frames.sorted { $0.0 < $1.0 }.enumerated().map { i, f in TroubleshootFixture.packet(f.1, at: t0.addingTimeInterval(f.0), id: i + 1, start: t0) }
    }

    func testDHCPNoAnswer() {
        let r = run(packets: TroubleshootFixture.badDayPackets(start: t0))
        let f = only(r, "dhcp.noAnswer").first
        XCTAssertEqual(f?.severity, .bad)
        XCTAssertTrue(f?.title.contains("VLAN 20") ?? false, f?.title ?? "")
        XCTAssertTrue(f?.title.contains("2 clients") ?? false)
        XCTAssertEqual(f?.count, 7)
        XCTAssertTrue(f?.nextSteps.contains { $0.contains("VLAN 20 has a DHCP scope") } ?? false)
        XCTAssertEqual(f?.evidence.first?.kind, .packets)
        XCTAssertTrue(f?.evidence.first?.query.hasPrefix("frame:") ?? false)
    }

    func testDHCPServersNAKsAndLeases() {
        let a = "02:00:5e:00:00:0a", b = "02:00:5e:00:00:0b"
        let frames = [
            dhcpFrame(0, client: a, type: 1, xid: 1, vlan: 40),
            dhcpFrame(0.01, client: a, type: 2, xid: 1, vlan: 40, server: "10.1.0.10", yiaddr: "10.1.40.5", lease: 86_400),
            dhcpFrame(0.02, client: a, type: 2, xid: 1, vlan: 40, server: "192.168.1.1", yiaddr: "192.168.1.50", lease: 120),
            dhcpFrame(1, client: b, type: 3, xid: 2, vlan: 40),
            dhcpFrame(1.01, client: b, type: 6, xid: 2, vlan: 40, server: "10.1.0.10"),
            dhcpFrame(30, client: b, type: 1, xid: 3, vlan: 40),
        ]
        let r = run(packets: packets(frames))
        XCTAssertEqual(only(r, "dhcp.twoServers").first?.severity, .warn, rules(r).description)
        XCTAssertTrue(only(r, "dhcp.twoServers").first?.title.contains("192.168.1.1") ?? false)
        XCTAssertEqual(only(r, "dhcp.nak").first?.severity, .warn)
        XCTAssertEqual(only(r, "dhcp.nak").first?.client, b)
        XCTAssertEqual(only(r, "dhcp.shortLease").first?.severity, .info)
        XCTAssertTrue(only(r, "dhcp.shortLease").first?.title.contains("2 min") ?? false)
        XCTAssertTrue(only(r, "dhcp.noAnswer").isEmpty, "one Discover left at the end of the capture is not a pattern")
    }

    func testDHCPHealthy() {
        let c = "02:00:5e:00:00:0c"
        let frames = [
            dhcpFrame(0, client: c, type: 1, xid: 9, vlan: 50), dhcpFrame(0.01, client: c, type: 2, xid: 9, vlan: 50, server: "10.1.0.10", yiaddr: "10.1.50.9", lease: 28_800),
            dhcpFrame(0.02, client: c, type: 3, xid: 9, vlan: 50), dhcpFrame(0.03, client: c, type: 5, xid: 9, vlan: 50, server: "10.1.0.10", yiaddr: "10.1.50.9", lease: 28_800),
            dhcpFrame(60, client: c, type: 3, xid: 10, vlan: 50), dhcpFrame(60.01, client: c, type: 5, xid: 10, vlan: 50, server: "10.1.0.10", yiaddr: "10.1.50.9", lease: 28_800),
        ]
        XCTAssertTrue(run(packets: packets(frames)).findings.isEmpty)
    }

    // MARK: DNS

    private func dnsFrames(server: String, client: String = "10.1.30.60", count: Int, answer: (Int) -> Int?) -> [(Double, [UInt8])] {
        var out: [(Double, [UInt8])] = []
        for k in 0..<count {
            let sport = 40_000 + k
            out.append((Double(k), TroubleshootFixture.udp4(srcMAC: "02:00:00:00:00:01", dstMAC: "02:00:00:00:00:02", src: client, dst: server,
                                                            sport: sport, dport: 53, vlan: nil,
                                                            TroubleshootFixture.dns(id: k, name: "host\(k % 3).corp.example", response: false))))
            if let rcode = answer(k) {
                out.append((Double(k) + 0.02, TroubleshootFixture.udp4(srcMAC: "02:00:00:00:00:02", dstMAC: "02:00:00:00:00:01", src: server, dst: client,
                                                                       sport: 53, dport: sport, vlan: nil,
                                                                       TroubleshootFixture.dns(id: k, name: "host\(k % 3).corp.example", response: true,
                                                                                               rcode: rcode, answer: rcode == 0 ? "10.1.40.1" : nil))))
            }
        }
        out.append((Double(count) + 10, TroubleshootFixture.arp(request: true, senderMAC: "02:00:00:00:00:01", senderIP: client, targetIP: "10.1.30.1", vlan: nil)))
        return out
    }

    func testDNSResolverNeverAnswers() {
        let r = run(packets: packets(dnsFrames(server: "10.1.0.99", count: 4) { _ in nil }))
        let f = only(r, "dns.noAnswer").first
        XCTAssertEqual(f?.severity, .bad, rules(r).description)
        XCTAssertEqual(f?.client, "10.1.30.60")
        XCTAssertTrue(f?.title.contains("10.1.0.99 never answered") ?? false)
    }

    func testDNSFailures() {
        let r = run(packets: TroubleshootFixture.badDayPackets(start: t0))
        let f = only(r, "dns.failures").first
        XCTAssertEqual(f?.severity, .bad, rules(r).description)
        XCTAssertTrue(f?.title.contains("60 %") ?? false, f?.title ?? "")
        XCTAssertTrue(f?.title.contains("SERVFAIL 7") ?? false)
        XCTAssertTrue(f?.title.contains("no answer 5") ?? false)
        // A third NXDOMAIN is a warning (NXDOMAIN alone can be normal), all answered is nothing.
        let nx = run(packets: packets(dnsFrames(server: "10.1.0.53", count: 12) { $0 % 3 == 0 ? 3 : 0 }))
        XCTAssertEqual(only(nx, "dns.failures").first?.severity, .warn)
        let fine = run(packets: packets(dnsFrames(server: "10.1.0.53", count: 12) { _ in 0 }))
        XCTAssertTrue(fine.findings.filter { $0.category == .dns }.isEmpty)
    }

    // MARK: ARP and ICMP

    func testDuplicateIP() {
        let r = run(packets: TroubleshootFixture.badDayPackets(start: t0))
        let f = only(r, "arp.duplicateIP").first
        XCTAssertEqual(f?.severity, .bad)
        XCTAssertEqual(f?.client, "10.1.30.44")
        XCTAssertTrue(f?.title.contains("02:00:5e:1e:00:44") ?? false)
        XCTAssertTrue(f?.title.contains("02:00:5e:1e:00:99") ?? false)
    }

    func testARPNobodyAnswers() {
        var frames: [(Double, [UInt8])] = []
        for k in 0..<4 {
            frames.append((Double(k), TroubleshootFixture.arp(request: true, senderMAC: "02:00:00:00:00:0\(k % 2 + 1)", senderIP: "10.1.20.\(50 + k % 2)", targetIP: "10.1.20.1", vlan: 20)))
        }
        // Another host is answered, so replies are visible in this capture.
        frames.append((5, TroubleshootFixture.arp(request: true, senderMAC: "02:00:00:00:00:01", senderIP: "10.1.20.50", targetIP: "10.1.20.9", vlan: 20)))
        frames.append((5.01, TroubleshootFixture.arp(request: false, senderMAC: "02:00:00:00:00:09", senderIP: "10.1.20.9", targetIP: "10.1.20.50", targetMAC: "02:00:00:00:00:01", vlan: 20)))
        let r = run(packets: packets(frames))
        let f = only(r, "arp.unanswered").first
        XCTAssertEqual(f?.severity, .bad, rules(r).description)
        XCTAssertTrue(f?.title.contains("10.1.20.1 (the gateway?)") ?? false, f?.title ?? "")
        XCTAssertTrue(only(r, "arp.duplicateIP").isEmpty)
        let answered = packets([frames[4], frames[5]])
        XCTAssertTrue(run(packets: answered).findings.isEmpty)
    }

    private func icmp(_ t: Double, type: UInt8, from router: String, to host: String) -> (Double, [UInt8]) {
        let inner = PacketFixture.ipv4(src: host, dst: "8.8.8.8", proto: 17, ttl: 1, PacketFixture.udp(33_434, 33_435, [0, 0, 0, 0]))
        let body: [UInt8] = [type, 0, 0, 0] + (type == 5 ? PacketFixture.ip4("10.1.20.254") : [0, 0, 0, 0]) + inner
        return (t, PacketFixture.ether(type: 0x0800, PacketFixture.ipv4(src: router, dst: host, proto: 1, body)))
    }

    func testICMPBursts() {
        let loop = (0..<12).map { icmp(Double($0) * 2, type: 11, from: "10.1.0.1", to: "10.1.20.\(50 + $0 % 3)") }
        let redirects = (0..<6).map { icmp(100 + Double($0), type: 5, from: "10.1.20.1", to: "10.1.20.77") }
        let r = run(packets: packets(loop + redirects))
        XCTAssertEqual(only(r, "icmp.ttlExceeded").first?.severity, .warn, rules(r).description)
        XCTAssertEqual(only(r, "icmp.redirects").first?.severity, .warn)
        let traceroute = (0..<3).map { icmp(Double($0) * 0.1, type: 11, from: "10.1.0.\($0 + 1)", to: "10.1.20.50") }
        XCTAssertTrue(run(packets: packets(traceroute)).findings.isEmpty)
    }

    // MARK: TCP

    private func flows(_ scripts: [TCPFlowDemo.Script]) -> [TCPFlow] {
        let all = scripts.flatMap(\.packets).sorted { $0.timestamp < $1.timestamp }.enumerated().map { n, p in
            Packet(id: n + 1, timestamp: p.timestamp, relative: p.relative, length: p.length, captured: p.captured, data: p.data, decoded: p.decoded)
        }
        return TCPFlowAnalyzer.analyze(all)
    }

    func testTCPProblems() {
        var scripts: [TCPFlowDemo.Script] = []
        var silent = TCPFlowDemo.Script(firstID: 1, client: "10.1.20.15", clientPort: 50_001, server: "10.9.0.5", serverPort: 22)
        silent.c(0, .syn); silent.c(1, .syn, seq: 1_000); silent.c(3, .syn, seq: 1_000)
        scripts.append(silent)
        for k in 0..<3 {
            var refused = TCPFlowDemo.Script(firstID: 100 + k * 10, offset: 10 + Double(k), client: "10.1.20.\(15 + k)", clientPort: UInt16(50_100 + k),
                                             server: "10.9.0.6", serverPort: 8443)
            refused.c(0, .syn); refused.s(0.001, [.rst, .ack], seq: 0)
            scripts.append(refused)
        }
        var slow = TCPFlowDemo.Script(firstID: 200, offset: 20, client: "10.1.20.15", clientPort: 50_200, server: "10.9.0.7", serverPort: 443)
        slow.handshake(rtt: 0.45)
        slow.c(0.46, [.psh, .ack], len: 200)
        slow.s(0.92, [.psh, .ack], len: 300)
        slow.c(0.93, [.fin, .ack]); slow.s(1.4, [.fin, .ack]); slow.c(1.41, .ack)
        scripts.append(slow)
        var reset = TCPFlowDemo.Script(firstID: 300, offset: 30, client: "10.1.20.15", clientPort: 50_300, server: "10.9.0.8", serverPort: 8080)
        reset.handshake(rtt: 0.002)
        reset.c(0.003, [.psh, .ack], len: 300)
        reset.s(0.004, [.rst, .ack])
        scripts.append(reset)
        var zero = TCPFlowDemo.Script(firstID: 400, offset: 40, client: "10.1.20.15", clientPort: 50_400, server: "10.9.0.9", serverPort: 445)
        zero.handshake(rtt: 0.002)
        zero.c(0.003, [.psh, .ack], len: 100)
        zero.s(0.004, .ack, len: 1_460)
        zero.cAck(0.005, ack: zero.sseq, window: 0)
        zero.cAck(0.5, ack: zero.sseq, window: 65_535)
        zero.s(0.501, [.psh, .ack], len: 100)
        zero.c(0.6, [.fin, .ack]); zero.s(0.61, [.fin, .ack]); zero.c(0.62, .ack)
        scripts.append(zero)
        let r = run(flows: flows(scripts) + TCPFlowAnalyzer.analyze(TCPFlowDemo.packets()), now: t0)
        XCTAssertEqual(only(r, "tcp.synUnanswered").first { $0.title.contains("10.9.0.5:22") }?.severity, .bad, rules(r).description)
        XCTAssertEqual(only(r, "tcp.refused").first { $0.title.contains("10.9.0.6:8443") }?.severity, .bad)
        XCTAssertEqual(only(r, "tcp.refused").first { $0.title.contains("10.1.30.9:8443") }?.severity, .warn, "one refusal")
        XCTAssertEqual(only(r, "tcp.slowHandshake").first?.severity, .warn)
        XCTAssertTrue(only(r, "tcp.slowHandshake").first?.title.contains("10.9.0.7:443") ?? false)
        XCTAssertEqual(only(r, "tcp.serverReset").first?.severity, .warn)
        XCTAssertTrue(only(r, "tcp.zeroWindow").first?.title.contains("the client stopped reading") ?? false, rules(r).description)
        XCTAssertTrue(only(r, "tcp.retransmissions").contains { $0.title.contains("10.1.30.8:443") })
        XCTAssertTrue(only(r, "tcp.slowResponse").contains { $0.title.contains("10.1.30.12:8080") })
        let refs = only(r, "tcp.refused").flatMap(\.evidence).flatMap(\.flows)
        XCTAssertFalse(refs.isEmpty, "flow evidence names the conversations")
    }

    func testTCPHealthy() {
        let healthy = TCPFlowAnalyzer.analyze(TCPFlowDemo.packets()).filter { $0.health == .ok }
        XCTAssertGreaterThanOrEqual(healthy.count, 2)
        XCTAssertTrue(run(flows: healthy, now: t0).findings.isEmpty)
    }

    // MARK: SNMP

    func testSNMPWalks() {
        let walks = TroubleshootFixture.coreSwitchWalks(start: t0)
        let r = run(snmp: walks, now: t0)
        XCTAssertTrue(only(r, "snmp.operDown").first?.title.contains("1/1/24") ?? false, rules(r).description)
        XCTAssertEqual(only(r, "snmp.errorsGrowing").first?.severity, .warn)
        XCTAssertTrue(only(r, "snmp.errorsGrowing").first?.title.contains("+3,784") ?? false, only(r, "snmp.errorsGrowing").first?.title ?? "")
        XCTAssertTrue(only(r, "snmp.halfDuplex").first?.title.contains("1/1/7") ?? false)
        XCTAssertEqual(only(r, "snmp.halfDuplex").first?.device, "CORE-CX-6300")
        // One walk: the totals are a note; a fresh boot is a note.
        var one = walks[0]
        one.sysUpTime = 30_000
        let single = run(snmp: [one], now: t0)
        XCTAssertEqual(only(single, "snmp.errors").first?.severity, .info)
        XCTAssertEqual(only(single, "snmp.recentBoot").first?.severity, .info)
        // All well.
        var fine = walks[0]
        fine.interfaces = fine.interfaces.map { var r = $0; r.oper = "up"; r.inErrors = 0; return r }
        fine.values = [.sysName: "CORE-CX-6300"]
        XCTAssertTrue(run(snmp: [fine], now: t0).findings.isEmpty)
    }

    func testSNMPSnapshotFromTheTestPane() {
        let rows = [
            VarBindRow(id: 1, oid: .sysUpTime, oidText: OID.sysUpTime.dotted, name: "sysUpTime.0", type: "TimeTicks", value: "00:02:03 (12345)", isBad: false),
            VarBindRow(id: 2, oid: .sysName, oidText: OID.sysName.dotted, name: "sysName.0", type: "STRING", value: "SW-9", isBad: false),
        ]
        let s = TroubleshootModel.snapshot(host: "10.1.0.9", rows: rows, interfaces: [], taken: t0)
        XCTAssertEqual(s.sysUpTime, 12_345)
        XCTAssertEqual(s.name, "SW-9")
        XCTAssertEqual(only(run(snmp: [s], now: t0), "snmp.recentBoot").count, 1)
    }

    // MARK: The bad day

    private func badDay() throws -> (entries: [LogEntry], packets: [Packet], flows: [TCPFlow]) {
        let e = try entries("bad-day.log")
        let start = try XCTUnwrap(e.compactMap(\.deviceTime).min())
        let p = TroubleshootFixture.badDayPackets(start: start)
        return (e, p, TCPFlowAnalyzer.analyze(p))
    }

    func testBadDayInOrderWithTheCrossReference() throws {
        let day = try badDay()
        let r = run(day.entries, packets: day.packets, flows: day.flows)
        func index(_ rule: String, _ device: String? = nil) throws -> Int {
            try XCTUnwrap(r.findings.firstIndex { $0.rule == rule && (device == nil || $0.device == device) }, "\(rule) missing: \(rules(r))")
        }
        let config = try index("config.change", "CORE-CX-6300")
        let flap = try index("link.flap", "CORE-CX-6300")
        let stp = try index("stp.topologyChange", "CORE-CX-6300")
        let dhcp = try index("dhcp.noAnswer")
        let dns = try index("dns.failures")
        XCTAssertLessThan(config, flap)
        XCTAssertLessThan(flap, stp)
        XCTAssertLessThan(stp, dhcp)
        XCTAssertLessThan(dhcp, dns)
        let change = try XCTUnwrap(day.entries.first { $0.message.contains("Configuration change") })
        let when = FText.clock(try XCTUnwrap(change.deviceTime).addingTimeInterval(0.25))
        let sentence = "A configuration change on this device by admin at \(when) came 1 min 53 s before this started — check what was changed."
        XCTAssertTrue(r.findings[flap].detail.contains(sentence), r.findings[flap].detail)
        XCTAssertTrue(r.findings[flap].evidence.contains { $0.label == "config change" && $0.ids == [change.id] })
        XCTAssertTrue(r.findings[stp].detail.contains("A configuration change on this device by admin"), r.findings[stp].detail)
        XCTAssertTrue(r.findings[flap].nextSteps[0].hasPrefix("Review the change made on CORE-CX-6300"))
        // The rest of the day is there too.
        for rule in ["login.failures", "routing.neighbor", "hw.poe", "hw.fan", "stp.loop", "arp.duplicateIP"] {
            XCTAssertTrue(rules(r).contains(rule), "\(rule) missing: \(rules(r))")
        }
        XCTAssertEqual(r.summary.lines, day.entries.count)
        XCTAssertEqual(r.summary.devices, 6)
        XCTAssertEqual(r.summary.packets, day.packets.count)
    }

    func testTimeline() throws {
        let day = try badDay()
        let r = run(day.entries, packets: day.packets, flows: day.flows)
        let t = r.timeline
        XCTAssertFalse(t.isEmpty)
        let core = try XCTUnwrap(t.lanes.first { $0.id == "CORE-CX-6300" })
        XCTAssertEqual(core.worst, .bad)
        XCTAssertTrue(core.events.contains { e in if case .finding = e.target { return e.kind == .finding } else { return false } })
        XCTAssertTrue(core.events.contains { e in if case .log(let q) = e.target { return q.hasPrefix("host:10.1.0.1") } else { return false } })
        let capture = try XCTUnwrap(t.lanes.first { $0.id == TimelineBuilder.captureLane })
        XCTAssertTrue(capture.events.contains { $0.label.hasPrefix("No DHCP answer") })
        XCTAssertEqual(t.lanes.first?.worst, .bad, "worst lanes first")
        XCTAssertTrue(t.lanes.allSatisfy { $0.events.filter { $0.kind != .finding }.count <= TimelineBuilder.slots })
        XCTAssertGreaterThanOrEqual(t.fraction(t.end), 1)
        XCTAssertEqual(t.summaryLines().count, t.lanes.count)
    }

    func testFindingsReport() throws {
        let day = try badDay()
        let r = run(day.entries, packets: day.packets, flows: day.flows)
        let md = ReportText.findings(r.findings, summary: r.summary, timeline: r.timeline, heading: "3 problems.", scope: "Link", generated: t0)
        for part in ["# SheepLog troubleshooting report", "## Problems", "## Warnings", "## Notes", "## Timeline", "Next steps:",
                     "Shown: Link.", "filter `host:"] {
            XCTAssertTrue(md.contains(part), part)
        }
    }

    // MARK: Client report

    func testClientIDSpellings() {
        XCTAssertEqual(ClientID.parse("02:00:5E:14:00:21"), .mac("02:00:5e:14:00:21"))
        XCTAssertEqual(ClientID.parse("0200.5e14.0021"), .mac("02:00:5e:14:00:21"))
        XCTAssertEqual(ClientID.parse("02-00-5e-14-00-21"), .mac("02:00:5e:14:00:21"))
        XCTAssertEqual(ClientID.parse("02005e140021"), .mac("02:00:5e:14:00:21"))
        XCTAssertEqual(ClientID.parse(" 10.1.30.60 "), .ip("10.1.30.60"))
        XCTAssertEqual(ClientID.parse("fe80::1"), .ip("fe80::1"))
        XCTAssertNil(ClientID.parse("switch-1"))
        XCTAssertNil(ClientID.parse("10.1.300.1"))
        XCTAssertEqual(ClientID.spellings(ofMAC: "02:00:5e:14:00:21"), ["02:00:5e:14:00:21", "02-00-5e-14-00-21", "0200.5e14.0021", "02005e140021"])
        // An address only as a whole address.
        XCTAssertTrue("host 10.1.1.1 up".withCString { ClientSearch.contains($0, "10.1.1.1") })
        XCTAssertTrue("from 10.1.1.1.".withCString { ClientSearch.contains($0, "10.1.1.1") })
        XCTAssertFalse("host 10.1.1.10 up".withCString { ClientSearch.contains($0, "10.1.1.1") })
        XCTAssertFalse("host 210.1.1.1 up".withCString { ClientSearch.contains($0, "10.1.1.1") })
    }

    func testClientReportOnTheBadDay() throws {
        let day = try badDay()
        let r = run(day.entries, packets: day.packets, flows: day.flows)
        var input = TroubleshootInput()
        input.entries = day.entries
        input.packets = day.packets
        input.flows = day.flows
        input.now = t0
        let stuck = try XCTUnwrap(ClientReport.build("0200.5e14.0021", input: input, findings: r.findings))
        let md = stuck.markdown
        for part in ["# Client 02:00:5e:14:00:21", "## Where it is", "ACC-CX-6100-2F — port 1/1/5", "## Findings (1)", "No DHCP answer on VLAN 20",
                     "## Log lines (1)", "## DHCP", "Discover", "(VLAN 20)", "## DNS", "## ARP", "## TCP flows (0)", "## Next steps",
                     "got no Offer"] {
            XCTAssertTrue(md.contains(part), "\(part) missing in:\n\(md)")
        }
        let ok = try XCTUnwrap(ClientReport.build("10.1.30.60", input: input, findings: r.findings))
        XCTAssertEqual(ok.macs, ["02:00:5e:1e:00:31"], "known by its DHCP lease")
        XCTAssertTrue(ok.markdown.contains("**Also known as:** MAC 02:00:5e:1e:00:31"), ok.markdown)
        XCTAssertTrue(ok.dns.first?.contains("20 queries to 10.1.0.53") ?? false, ok.dns.description)
        XCTAssertTrue(ok.findings.contains { $0.rule == "dns.failures" })
        XCTAssertTrue(ok.nextSteps.contains { $0.contains("DNS") }, ok.nextSteps.description)
        XCTAssertTrue(ok.dhcp.contains { $0.contains("ACK → 10.1.30.60 from 10.1.0.10, lease 1 d") }, ok.dhcp.description)
        XCTAssertNil(ClientReport.build("not a client", input: input, findings: []))
        let nobody = try XCTUnwrap(ClientReport.build("10.99.99.99", input: input, findings: r.findings))
        XCTAssertTrue(nobody.nextSteps.contains { $0.contains("Nothing SheepLog holds mentions") })
    }

    func testClientPortFromABridgeTable() {
        var s = TroubleshootFixture.coreSwitchWalks(start: t0)[0]
        s.values[ClientSearch.fdb.appending([2, 0, 0x5e, 0x14, 0, 0x21])] = "17"
        s.values[ClientSearch.basePortIfIndex.appending(17)] = "24"
        XCTAssertEqual(ClientSearch.fdbPort(mac: "02:00:5e:14:00:21", in: s), "1/1/24")
        XCTAssertNil(ClientSearch.fdbPort(mac: "02:00:5e:14:00:22", in: s))
    }

    // MARK: The Authentication pane's hook

    @MainActor
    func testAuthExtensionPoint() {
        // Wired at startup to the Authentication pane's sessions (AuthFindings); in the test host
        // startup may not have run, so wire it here and check a failed session becomes a finding.
        FindingRules.authProvider = { store in AuthFindings.findings(from: store.packets) }
        XCTAssertNotNil(FindingRules.authProvider)
        let auth = Finding(id: "auth.reject|alice", rule: "auth.rejects", severity: .warn, category: .auth, source: .auth,
                           title: "alice was rejected 5 times.", detail: "RADIUS Access-Reject.", firstSeen: t0, lastSeen: t0)
        let r = run(now: t0, extra: [auth])
        XCTAssertEqual(r.findings.map(\.id), ["auth.reject|alice"])
        XCTAssertEqual(r.findings.first?.source, .auth)
    }

    func testNothingIsQuiet() {
        let r = run(now: t0)
        XCTAssertTrue(r.findings.isEmpty)
        XCTAssertTrue(r.timeline.isEmpty)
        XCTAssertEqual(r.summary.notes.count, 3, "says what was not checked")
    }

    // MARK: Time budget

    /// 100,000 log lines (firewall sessions, the corpus of every vendor, the bad day) from 50
    /// devices and 200,000 packets (TCP, DHCP, DNS, ARP) with their flows: the rules take under
    /// 300 ms.
    func testRulesTimeBudget() throws {
        let corpusDir = Self.dir.deletingLastPathComponent().appending(path: "corpus")
        var templates: [LogEntry] = []
        for name in ["arubacx", "arubaos", "arubasw", "clearpass", "huawei", "checkpoint", "paloalto", "fortigate", "other"] {
            let text = try String(contentsOf: corpusDir.appending(path: "\(name).log"), encoding: .utf8)
            templates += text.split(whereSeparator: \.isNewline).map { parsedLine(String($0)) }
        }
        templates += try entries("bad-day.log")
        let sessions = templates.filter { LineClassifier.isSessionLog($0) }
        XCTAssertGreaterThan(sessions.count, 10)
        var lines: [LogEntry] = []
        lines.reserveCapacity(100_000)
        for i in 0..<100_000 {
            // Two thirds firewall sessions, the rest everything else.
            let src = i % 3 == 0 ? templates[i % templates.count] : sessions[i % sessions.count]
            let t = t0.addingTimeInterval(Double(i) * 0.03)
            lines.append(LogEntry(id: i + 1, received: t, deviceTime: t, sourceAddress: "10.50.0.\(i % 50 + 1)", sourcePort: 514,
                                  transport: .udp, facility: src.facility, severity: src.severity, priority: src.priority,
                                  hostname: src.hostname, program: src.program, pid: src.pid, message: src.message, raw: src.raw,
                                  vendor: src.vendor, fields: src.fields))
        }
        let special = TroubleshootFixture.badDayPackets(start: t0)
        var packets: [Packet] = []
        packets.reserveCapacity(200_000)
        var id = 1
        var flow = 0
        while packets.count < 200_000 {
            let t = Double(packets.count) * 0.01
            if packets.count % 50 == 0 {
                let p = special[(packets.count / 50) % special.count]
                packets.append(Packet(id: id, timestamp: t0.addingTimeInterval(t), relative: t, length: p.length, captured: p.captured,
                                      data: p.data, decoded: p.decoded))
            } else {
                let c = "10.60.\(flow % 200).\(flow % 250 + 1)"
                packets.append(TCPFlowDemo.packet(id: id, t: t, src: c, sport: UInt16(40_000 + flow % 20_000), dst: "10.70.0.\(flow % 40 + 1)",
                                                  dport: 443, flags: .ack, seq: UInt32(1_000 + packets.count * 100), ack: 1, len: 100))
                if packets.count % 40 == 0 { flow += 1 }
            }
            id += 1
        }
        let flows = TCPFlowAnalyzer.analyze(Array(packets.prefix(50_000)))
        var input = TroubleshootInput()
        input.entries = lines
        input.packets = packets
        input.flows = flows
        input.snmp = TroubleshootFixture.coreSwitchWalks(start: t0)
        input.now = t0.addingTimeInterval(4_000)
        _ = FindingRules.analyze(input)            // warm up (lazy statics, first-touch pages)
        let start = Date()
        let r = FindingRules.analyze(input)
        let elapsed = Date().timeIntervalSince(start)
        print("[perf] Troubleshoot rules over \(Format.count(lines.count)) lines, \(Format.count(packets.count)) packets, \(Format.count(flows.count)) flows: \(Int(elapsed * 1000)) ms, \(r.findings.count) findings")
        XCTAssertGreaterThan(r.findings.count, 5)
        XCTAssertWithinBudget(elapsed, 0.3)
    }
}

final class AuthFindingsTests: XCTestCase {
    /// The Authentication fixtures: every failed session is one auth finding with its packets.
    func testFailedAuthSessionsBecomeFindings() throws {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appending(path: "Tests/pcaps/auth/auth-all.pcap")
        var packets: [Packet] = []
        _ = try PcapFile.read(url) { packets += $0 }
        let findings = AuthFindings.findings(from: packets)
        XCTAssertGreaterThanOrEqual(findings.count, 3, "reject, timeout and PSK-wrong sessions")
        XCTAssertTrue(findings.allSatisfy { $0.category == .auth && $0.source == .auth && !$0.evidence.isEmpty && !$0.nextSteps.isEmpty })
        XCTAssertTrue(findings.contains { $0.title.contains("rejected") })
        XCTAssertTrue(findings.contains { $0.title.contains("timed out") })
    }
}
