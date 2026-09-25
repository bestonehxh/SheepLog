import AppKit
import Darwin
import SwiftUI
import XCTest
@testable import SheepLog

/// Round 15: routing protocols' and vendors' lines where the classifier's words overlap, SNMP
/// counters that wrap or start again, file writes that a full disk or ⌘Q could cut short,
/// state restored at launch from values of the wrong type — and a sweep.
@MainActor
final class Round15Tests: XCTestCase {
    private var windows: [NSWindow] = []
    private var cleanup: [URL] = []
    private var disks: [RAMDisk] = []

    override func tearDown() async throws {
        for w in windows { w.contentView = nil; w.close() }
        windows = []
        for u in cleanup { try? FileManager.default.removeItem(at: u) }
        cleanup = []
        for d in disks { d.detach() }
        disks = []
        let app = AppModel.shared
        while app.lastError != nil { app.clearError(); try? await Task.sleep(for: .milliseconds(20)) }
        app.packets.clear()
        app.logs.clear()
        try? await Task.sleep(for: .milliseconds(30))
    }

    // MARK: - Harness

    static let t0 = Round13Tests.t0
    static func at(_ s: Double) -> Date { t0.addingTimeInterval(s) }
    static let bsd = Round13Tests.bsd

    private func spin(_ ms: Int = 30) async { try? await Task.sleep(for: .milliseconds(ms)) }

    private func waitUntil(_ timeout: Double = 5, _ condition: () -> Bool) async {
        let end = Date().addingTimeInterval(timeout)
        while !condition(), Date() < end { await spin(10) }
    }

    private func tempDir() throws -> URL {
        let d = FileManager.default.temporaryDirectory.appending(path: "SheepLogR15-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        cleanup.append(d)
        return d
    }

    /// A 1 MB RAM disk, or a skip when this Mac cannot make one.
    private func ramDisk() throws -> RAMDisk {
        guard let d = RAMDisk.make() else { throw XCTSkip("no RAM disk (hdiutil / newfs_hfs / diskutil unavailable)") }
        disks.append(d)
        return d
    }

    static func kind(_ line: String) -> String {
        LineClassifier.line(parsedLine(line, from: "10.9.9.9")).map { "\($0)" } ?? "nil"
    }

    static func corpus(_ name: String) throws -> [String] {
        try String(contentsOf: Round12Tests.testsDir.appending(path: "corpus/\(name).log"), encoding: .utf8)
            .split(whereSeparator: \.isNewline).map(String.init)
    }

    // MARK: - 1. Routing protocols and vendors

    /// The corpus's round-15 lines, each read into what it says: Junos BGP (the NOTIFICATION of
    /// a `clear bgp neighbor` with its reason; Idle → Connect is a step, not a down), FRR's
    /// bgpd / ospfd / zebra, FortiOS router events, Huawei STATE_CHG_UPDOWN (which never says
    /// "neighbor": never read) and NBR_CHG (Down → Init was a down), PAN-OS SYSTEM routing,
    /// AOS-CX OSPFv2 and BGP.
    func testRound15CorpusLinesAreRead() throws {
        let other = try Self.corpus("other"), forti = try Self.corpus("fortigate"), hw = try Self.corpus("huawei")
        let pa = try Self.corpus("paloalto"), cx = try Self.corpus("arubacx")
        XCTAssertEqual([other.count, forti.count, hw.count, pa.count, cx.count], [73, 14, 16, 14, 17], "round 16 added other 64–73, huawei 14–16, arubacx 15–17 (Round16Tests)")
        func bgp(_ n: String, _ up: Bool) -> String { "routing(proto: \"BGP\", neighbor: \"\(n)\", up: \(up))" }
        func ospf(_ n: String, _ up: Bool) -> String { "routing(proto: \"OSPF\", neighbor: \"\(n)\", up: \(up))" }
        let table: [(String, [String])] = [
            ("other 54–63", other[53..<63].map(Self.kind)),
            ("fortigate 11–14", forti[10...].map(Self.kind)),
            ("huawei 9–13", hw[8..<13].map(Self.kind)),
            ("paloalto 11–14", pa[10...].map(Self.kind)),
            ("arubacx 11–14", cx[10..<14].map(Self.kind)),
        ]
        let want: [[String]] = [
            ["routingNotice(proto: \"BGP\", neighbor: \"10.0.14.2\", reason: \"Cease/Administratively Reset\", sent: true)",
             bgp("10.0.14.2", false), "routingStep(proto: \"BGP\", neighbor: \"10.0.14.2\")", bgp("10.0.14.2", true),
             bgp("10.0.15.2", false), bgp("10.0.15.2", true), ospf("10.0.15.6", false), ospf("10.0.15.6", true),
             "link(iface: \"eth3\", up: false)", "link(iface: \"eth3\", up: true)"],
            [bgp("169.254.10.1", false), bgp("169.254.10.1", true), ospf("10.9.0.2", false), ospf("10.9.0.2", true)],
            [bgp("10.0.0.9", false), bgp("10.0.0.9", true), ospf("10.0.0.10", false), "routingStep(proto: \"OSPF\", neighbor: \"10.0.0.10\")", ospf("10.0.0.10", true)],
            [bgp("10.3.0.2", false), bgp("10.3.0.2", true), ospf("10.3.0.6", false), ospf("10.3.0.6", true)],
            [ospf("10.2.0.1", false), ospf("10.2.0.1", true), bgp("10.2.0.9", false), bgp("10.2.0.9", true)],
        ]
        for (k, (name, read)) in table.enumerated() { XCTAssertEqual(read, want[k], name) }
    }

    /// Each vendor's down alone is a neighbor still down, named by its address; its down and
    /// up is nothing (round 14: Junos's Idle → Connect and Huawei's Down → Init were second
    /// downs — "went down 2 times" on healthy lines); a Junos `clear bgp neighbor` says it was
    /// somebody's command; OSPF's Full → Init then Init → Down is one outage; a Huawei neighbor
    /// that only reached Init / 2Way is still down (it was "back": Init → 2Way read as up); two
    /// IPv6 peers are two neighbors (one "a neighbor … went down 2 times").
    func testRoutingVendorsThroughTheRules() async throws {
        let other = try Self.corpus("other"), forti = try Self.corpus("fortigate"), hw = try Self.corpus("huawei")
        let pa = try Self.corpus("paloalto"), cx = try Self.corpus("arubacx")
        // Down only: one finding each, the neighbor the line names.
        let downs: [(String, String, String)] = [
            (other[54], "BGP neighbor 10.0.14.2 on MX204-EDGE", "10.66.1.1"),
            (other[57], "BGP neighbor 10.0.15.2 on frr-edge1", "10.66.1.2"),
            (other[59], "OSPF neighbor 10.0.15.6 on frr-edge1", "10.66.1.3"),
            (forti[10], "BGP neighbor 169.254.10.1 on FGT-100F-HQ", "10.66.1.4"),
            (forti[12], "OSPF neighbor 10.9.0.2 on FGT-100F-HQ", "10.66.1.5"),
            (hw[8], "BGP neighbor 10.0.0.9 on HW-NE40E", "10.66.1.6"),
            (hw[10], "OSPF neighbor 10.0.0.10 on HW-NE40E", "10.66.1.7"),
            (pa[10], "BGP neighbor 10.3.0.2 on PA-3220", "10.66.1.8"),
            (pa[12], "OSPF neighbor 10.3.0.6 on PA-3220", "10.66.1.9"),
            (cx[10], "OSPF neighbor 10.2.0.1 on CX8360-AGG-02", "10.66.1.10"),
            (cx[12], "BGP neighbor 10.2.0.9 on CX8360-AGG-02", "10.66.1.11"),
        ]
        for (line, title, address) in downs {
            let entries = Round12Tests.live([line], hostless: address)
            let r = Round13Tests.analyze(entries)
            XCTAssertEqual(r.findings.map(\.rule), ["routing.neighbor"], line)
            XCTAssertTrue(r.findings.first?.title.hasPrefix(title + " went down at ") ?? false, "\(r.findings.map(\.title)) for \(line)")
            // …and its evidence filter finds it.
            let store = LogStore()
            store.ingest(entries)
            store.queryText = r.findings.first?.evidence.first?.query ?? "-"
            store.applyQueryText()
            await waitUntil { store.visible.count == 1 }
            XCTAssertEqual(store.visible.map(\.id), [1], "`\(store.queryText)` for \(line)")
        }
        // Each vendor's own down and up, with what is between: nothing.
        for (name, lines) in [("other", Array(other[53..<63])), ("fortigate", Array(forti[10...])), ("huawei", Array(hw[8..<13])),
                              ("paloalto", Array(pa[10...])), ("arubacx", Array(cx[10..<14]))] {
            let r = Round12Tests.analyze(Round12Tests.live(lines, hostless: "10.78.0.1"))
            XCTAssertTrue(r.findings.isEmpty, "\(name): \(r.findings.map(\.title))")
        }
        // Junos: the peer cleared and not back — the finding says it was a command.
        var r = Round13Tests.analyze(Round12Tests.live(Array(other[53...55]), hostless: "10.66.2.1"))
        let cleared = try XCTUnwrap(r.findings.first, "no finding")
        XCTAssertEqual(r.findings.count, 1)
        XCTAssertTrue(cleared.detail.hasPrefix("The session ended with a NOTIFICATION sent to the neighbor: Cease/Administratively Reset. An administrative reset or shutdown is somebody's command, not a fault. "), cleared.detail)
        XCTAssertEqual(cleared.evidence.first?.ids, [1, 2], "the NOTIFICATION and the down (Idle → Connect is no event)")
        // OSPF (Junos): Full → Init (1-way), Init → Down (dead timer), back to Full: one outage.
        var l = Round13Tests.Lines()
        let nbr = "RPD_OSPF_NBRDOWN: OSPF neighbor 10.0.12.2 (realm ospf-v2 xe-0/0/1.0 area 0.0.0.0) state changed from"
        func outage(_ t: Double) {
            l.raw(t, "<28>\(Self.bsd(t)) MX204-EDGE rpd[1811]: \(nbr) Full to Init due to 1WayRcvd", from: "10.66.2.2")
            l.raw(t + 40, "<28>\(Self.bsd(t + 40)) MX204-EDGE rpd[1811]: \(nbr) Init to Down due to InactivityTimer", from: "10.66.2.2")
            l.raw(t + 90, "<29>\(Self.bsd(t + 90)) MX204-EDGE rpd[1811]: RPD_OSPF_NBRUP: OSPF neighbor 10.0.12.2 (realm ospf-v2 xe-0/0/1.0 area 0.0.0.0) state changed from Loading to Full due to LoadDone", from: "10.66.2.2")
        }
        outage(0)
        r = Round13Tests.analyze(l.entries)
        XCTAssertTrue(r.findings.isEmpty, "one outage, back: \(r.findings.map(\.title))")
        // …the same outage twice is a flap of 2.
        outage(300)
        r = Round13Tests.analyze(l.entries)
        XCTAssertEqual(r.findings.map(\.title), ["OSPF neighbor 10.0.12.2 on MX204-EDGE went down 2 times (\(Round13Tests.clock(0))–\(Round13Tests.clock(300)))."])
        // Huawei: Full → Down, Down → Init, Init → 2Way — still not Full: still down.
        l = Round13Tests.Lines()
        func hwNbr(_ s: Double, _ from: String, _ to: String) -> String {
            "<189>\(Round13Tests.asa(s)) HW-NE40E %%01OSPF/4/NBR_CHANGE_E(l)[24]:Neighbor changes event: neighbor status changed. (ProcessId=1, NeighborAddress=10.0.0.10, NeighborEvent=HelloReceived, NeighborPreviousState=\(from), NeighborCurrentState=\(to))"
        }
        l.raw(0, hwNbr(0, "Full", "Down"), from: "10.66.2.3")
        l.raw(10, hwNbr(10, "Down", "Init"), from: "10.66.2.3")
        l.raw(20, hwNbr(20, "Init", "2Way"), from: "10.66.2.3")
        r = Round13Tests.analyze(l.entries)
        XCTAssertEqual(r.findings.map(\.title), ["OSPF neighbor 10.0.0.10 on HW-NE40E went down at \(Round13Tests.clock(0)) and has not come back."])
        // FRR, two IPv6 peers: one down for good, the other down and back — the first is still
        // down (both were one neighbor "?": the second's Up hid it).
        l = Round13Tests.Lines()
        l.raw(0, "<30>\(Self.bsd(0)) frr-edge1 bgpd[912]: %ADJCHANGE: neighbor 2001:db8::2(spine1) in vrf default Down Peer closed the session", from: "10.66.2.4")
        l.raw(5, "<30>\(Self.bsd(5)) frr-edge1 bgpd[912]: %ADJCHANGE: neighbor 2001:db8::3(spine2) in vrf default Down Peer closed the session", from: "10.66.2.4")
        l.raw(30, "<30>\(Self.bsd(30)) frr-edge1 bgpd[912]: %ADJCHANGE: neighbor 2001:db8::3(spine2) in vrf default Up", from: "10.66.2.4")
        r = Round13Tests.analyze(l.entries)
        XCTAssertEqual(r.findings.map(\.title), ["BGP neighbor 2001:db8::2 on frr-edge1 went down at \(Round13Tests.clock(0)) and has not come back."])
    }

    /// Words that belong to one category in the message, the program or the hostname and to
    /// another elsewhere: loop, topology, reset, neighbor, flap, peer, established, index.
    func testWordOverlapTable() {
        let table: [(String, String)] = [
            // "loop": a loopback's flags, a host named LOOP, a BGP AS-path loop, a routing loop
            // guard — none spanning tree; a spanning-tree loop guard is.
            ("<30>Sep 23 10:29:00 frr-edge1 zebra[870]: interface lo index 1 changed <UP,LOOPBACK,RUNNING>.", "nil"),
            ("<189>Sep 23 10:29:01 LOOP-SW1 %LINK-3-UPDOWN: Interface Gi1/0/1, changed state to down", "link(iface: \"Gi1/0/1\", up: false)"),
            ("<187>Sep 23 10:29:02 R1 bgpd[99]: 10.0.0.7 rcvd UPDATE w/ attr: AS path loop detected, withdrawn", "nil"),
            ("<186>Sep 23 10:29:03 SW1 %SPANTREE-2-LOOPGUARD_BLOCK: Loop guard blocking port Gi1/0/2 on VLAN0010.", "stp(SheepLog.STPKind.loop, port: Optional(\"Gi1/0/2\"))"),
            // "topology": IOS's BGP session line, an OSPF SPF, a host named TOPOLOGY.
            ("<189>Sep 23 10:29:04 R1 %BGP_SESSION-5-ADJCHANGE: neighbor 10.0.0.2 IPv4 Unicast topology base removed from session  Peer closed the session", "nil"),
            ("<189>Sep 23 10:29:05 R1 ospfd[99]: SPF scheduled due to topology change", "nil"),
            ("<189>Sep 23 10:29:06 TOPOLOGY-LAB %SPANTREE-5-TOPOTRAP: Topology Change Trap for vlan 10", "stp(SheepLog.STPKind.topologyChange, port: nil)"),
            // "reset": sshd's peer reset, a user's BGP reset (a down), Junos's cleared session.
            ("<38>Sep 23 10:29:07 web01 sshd[22]: Connection reset by peer 10.0.0.9 port 51000", "nil"),
            ("<189>Sep 23 10:29:08 R1 %BGP-5-ADJCHANGE: neighbor 10.0.0.2 Down User reset", "routing(proto: \"BGP\", neighbor: \"10.0.0.2\", up: false)"),
            ("<28>Sep 23 10:29:09 MX1 rpd[1811]: bgp_peer_mgmt_clear:6969: NOTIFICATION sent to 10.0.14.2 (External AS 65014): code 6 (Cease) subcode 4 (Administratively Reset), Reason: Management session cleared BGP neighbor",
             "routingNotice(proto: \"BGP\", neighbor: \"10.0.14.2\", reason: \"Cease/Administratively Reset\", sent: true)"),
            ("<28>Sep 23 10:29:10 MX1 rpd[1811]: bgp_hold_timeout:4058: NOTIFICATION sent to 10.0.14.2 (External AS 65014): code 4 (Hold Timer Expired Error), Reason: holdtime expired for 10.0.14.2",
             "routingNotice(proto: \"BGP\", neighbor: \"10.0.14.2\", reason: \"Hold Timer Expired Error\", sent: true)"),
            // "neighbor": LLDP / CDP / IPv6 ND neighbors are no routing adjacency.
            ("<187>Sep 23 10:29:11 SW1 lldpd[99]: LLDP neighbor 10.1.0.9 removed on port 1/1/24", "nil"),
            ("<189>Sep 23 10:29:12 SW1 %CDP-4-NATIVE_VLAN_MISMATCH: Native VLAN mismatch discovered on Gi1/0/1 (10), with neighbor SW2 Gi0/1 (20).", "nil"),
            ("<28>Sep 23 10:29:13 host1 kernel: IPv6: eth0: IPv6 duplicate address fe80::1 used by 02:00:5e:00:00:01 detected! neighbor down", "nil"),
            // "flap": a link-flap err-disable is the port shut by the switch (round 16: a down; it
            // was nothing — "link-flap" alone is no state word), a flapping BGP peer's down.
            ("<187>Sep 23 10:29:14 SW1 %PM-4-ERR_DISABLE: link-flap error detected on Gi0/1, putting Gi0/1 in err-disable state", "link(iface: \"Gi0/1\", up: false)"),
            ("<189>Sep 23 10:29:15 FLAP-RTR %BGP-5-ADJCHANGE: neighbor 10.0.0.2 Down Interface flap", "routing(proto: \"BGP\", neighbor: \"10.0.0.2\", up: false)"),
            // "peer" / "established": a TLS peer, an established SSH session, a daemon going down.
            ("<30>Sep 23 10:29:16 web01 nginx[5]: SSL_do_handshake() failed: peer closed connection in SSL handshake", "nil"),
            ("<38>Sep 23 10:29:17 web01 sshd[22]: Connection established from 10.0.0.9 to port 22", "nil"),
            ("<30>Sep 23 10:29:18 frr-edge1 bgpd[912]: Terminating on signal; BGPd shutting down", "nil"),
            ("<30>Sep 23 10:29:19 R1 ospfd[99]: OSPF process 1 is down", "nil"),
            // A step between states is nothing (Junos, OSPF, Huawei).
            ("<29>Sep 23 10:29:20 MX1 rpd[1811]: RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 10.0.14.2 (External AS 65014) changed state from Idle to Connect (event Start) (instance master)", "routingStep(proto: \"BGP\", neighbor: \"10.0.14.2\")"),
            ("<29>Sep 23 10:29:21 MX1 rpd[1811]: RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 10.0.14.2 (External AS 65014) changed state from Active to Idle (event ConnectRetry) (instance master)", "routingStep(proto: \"BGP\", neighbor: \"10.0.14.2\")"),
            ("<189>Sep 23 10:29:22 R1 %OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on Gi0/1 from EXSTART to EXCHANGE, Negotiation Done", "routingStep(proto: \"OSPF\", neighbor: \"10.0.0.2\")"),
            ("<189>Sep 23 10:29:23 R1 %OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on Gi0/1 from FULL to DOWN, Neighbor Down: Interface down or detached",
             "routing(proto: \"OSPF\", neighbor: \"10.0.0.2\", up: false)"),
            ("<189>Sep 23 10:29:24 R1 %OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on Gi0/1 from EXSTART to DOWN, Neighbor Down: Too many retransmissions",
             "routing(proto: \"OSPF\", neighbor: \"10.0.0.2\", up: false)"),
            // "index": zebra's admin shutdown (no UP), a port with its carrier back.
            ("<30>Sep 23 10:29:25 frr-edge1 zebra[870]: interface eth4 index 6 changed <BROADCAST,MULTICAST>.", "nil"),
            ("<30>Sep 23 10:29:26 frr-edge1 zebra[870]: interface eth4 index 6 changed", "nil"),
            ("<30>Sep 23 10:29:27 frr-edge1 zebra[870]: interface eth4 index 6 changed <UP,BROADCAST,RUNNING,MULTICAST>.", "link(iface: \"eth4\", up: true)"),
            // The words in the program or the host name only: what the message says decides.
            ("<30>Sep 23 10:29:29 web01 bgpmon[1]: user admin login failed from 10.0.0.9", "loginFail(ip: Optional(\"10.0.0.9\"), user: Optional(\"admin\"))"),
            ("<30>Sep 23 10:29:30 SW1 loopd[1]: port 1/1/3 link down", "link(iface: \"1/1/3\", up: false)"),
            ("<189>Sep 23 10:29:31 RESET-SW %SYS-5-RESTART: System restarted --", "reboot(cold: false, planned: false)"),
            ("<30>Sep 23 10:29:32 SW1 flapd[1]: neighbor 10.0.0.2 flap count 3", "nil"),
            ("<30>Sep 23 10:29:33 PEER-FW1 sshd[22]: session opened for user admin", "nil"),
            // A routing program's hardware-like words: none a failure.
            ("<30>Sep 23 10:29:28 R1 ospfd[99]: OSPF: interface eth0 passive, power of 2 cost", "nil"),
        ]
        for (line, want) in table { XCTAssertEqual(Self.kind(line), want, line) }
    }

    // MARK: - 2. SNMP counters that wrap or start again

    /// One port's ifTable / ifXTable var-binds, as a walk's snapshot holds them.
    static func port(_ idx: UInt32, name: String, inErr: UInt64 = 0, outErr: UInt64 = 0, inDisc: UInt64 = 0, outDisc: UInt64 = 0,
                     inU32: UInt64? = nil, outU32: UInt64? = nil, inHC: UInt64? = nil, outHC: UInt64? = nil,
                     inOct32: UInt64 = 0, inOctHC: UInt64? = nil, discontinuity: String? = nil) -> (InterfaceRow, [OID: String]) {
        var row = InterfaceRow(index: idx)
        row.name = name
        row.descr = name
        row.admin = "up"
        row.oper = "up"
        row.speedBits = 1_000_000_000
        row.inErrors = inErr
        row.outErrors = outErr
        row.inOctets = inOctHC ?? inOct32
        var v: [OID: String] = [:]
        let t = OID.ifTable.appending(1), x = OID.ifXTable.appending(1)
        v[t.appending([13, idx])] = "\(inDisc)"
        v[t.appending([19, idx])] = "\(outDisc)"
        v[t.appending([14, idx])] = "\(inErr)"
        v[t.appending([20, idx])] = "\(outErr)"
        v[t.appending([10, idx])] = "\(inOct32)"
        if let inU32 { v[t.appending([11, idx])] = "\(inU32)" }
        if let outU32 { v[t.appending([17, idx])] = "\(outU32)" }
        if let inHC { v[x.appending([7, idx])] = "\(inHC)" }
        if let outHC { v[x.appending([11, idx])] = "\(outHC)" }
        if let inOctHC { v[x.appending([6, idx])] = "\(inOctHC)" }
        if let discontinuity { v[x.appending([19, idx])] = discontinuity }
        return (row, v)
    }

    static func walk(_ at: Double, upTime: UInt32, _ ports: [(InterfaceRow, [OID: String])]) -> SNMPSnapshot {
        var values: [OID: String] = [.sysUpTime: "\(upTime)", .sysName: "SW-R15"]
        for (_, v) in ports { values.merge(v) { a, _ in a } }
        return SNMPSnapshot(host: "10.66.9.9", taken: Self.at(at), sysName: "SW-R15", sysUpTime: upTime,
                            interfaces: ports.map(\.0), values: values)
    }

    static func titles(_ snaps: [SNMPSnapshot]) -> [String] {
        Round13Tests.analyze(snmp: snaps, now: Self.at(1_000)).findings.map(\.title).sorted()
    }

    /// Errors, discards and packet counters across two walks: a Counter32 that wrapped is its
    /// growth (ifInErrors past 4,294,967,295 made the in + out sum smaller: the growth was
    /// lost); a counter cleared between the walks counts what it holds now; a device that
    /// restarted (uptime shorter than the time between the walks, or shorter than before)
    /// compares nothing and says its counts are since the restart (errors 500 → 30 were
    /// nothing; 5 → 30, "+25"); a module pulled leaves fewer ports (no finding for them); a
    /// port that took a pulled port's ifIndex, or whose ifCounterDiscontinuityTime moved, is
    /// no wrap of the old counters (its 10 discards after 3,000,000,000 were "+1,294,967,306").
    /// Each finding's wording on its minimal fixture.
    func testCountersThatWrapOrStartAgain() {
        let up0: UInt32 = 8_640_000                     // a day
        func w1(_ ports: [(InterfaceRow, [OID: String])]) -> SNMPSnapshot { Self.walk(0, upTime: up0, ports) }
        func w2(_ ports: [(InterfaceRow, [OID: String])], up: UInt32 = up0 + 30_000) -> SNMPSnapshot { Self.walk(300, upTime: up, ports) }
        // ifInErrors wraps: +796, not nothing.
        var t = Self.titles([w1([Self.port(1, name: "ge-1", inErr: 4_294_967_000, outErr: 10)]),
                             w2([Self.port(1, name: "ge-1", inErr: 500, outErr: 10)])])
        XCTAssertEqual(t, ["Interface errors are growing on SW-R15: ge-1 +796 in 5 min."])
        // Cleared between the walks: the 20 it holds now.
        t = Self.titles([w1([Self.port(1, name: "ge-1", inErr: 5_000)]), w2([Self.port(1, name: "ge-1", inErr: 20)])])
        XCTAssertEqual(t, ["Interface errors are growing on SW-R15: ge-1 +20 in 5 min."])
        // Cleared from the counter's upper half (3,000,000,000 → 5): as a wrap that is
        // 1,294,967,301 errors in 5 minutes, more frames than a 1 Gb/s port carries — a clear: +5.
        t = Self.titles([w1([Self.port(1, name: "ge-1", inErr: 3_000_000_000)]), w2([Self.port(1, name: "ge-1", inErr: 5)])])
        XCTAssertEqual(t, ["Interface errors are growing on SW-R15: ge-1 +5 in 5 min."])
        // …and discards and packets cleared from there: totals since the clear, not a growth.
        t = Self.titles([w1([Self.port(3, name: "ge-3", inDisc: 3_000_000_000, inU32: 3_500_000_000)]),
                         w2([Self.port(3, name: "ge-3", inDisc: 2_000, inU32: 1_000_000)])])
        XCTAssertEqual(t, ["1 interface on SW-R15 dropped over 0.1 % of its packets since the counters were cleared: ge-3 in 20.0 per 10,000 packets."])
        XCTAssertEqual(FindingRules.maxFrames(speedBits: 1_000_000_000, seconds: 300), 491_081_428)
        XCTAssertNil(FindingRules.maxFrames(speedBits: 0, seconds: 300))
        // No change: nothing (a total seen twice is old news).
        t = Self.titles([w1([Self.port(1, name: "ge-1", inErr: 5_000)]), w2([Self.port(1, name: "ge-1", inErr: 5_000)])])
        XCTAssertEqual(t, [])
        // One walk: the total, said to be one.
        t = Self.titles([w1([Self.port(1, name: "ge-1", inErr: 5_000)])])
        XCTAssertEqual(t, ["1 interface on SW-R15 has error counts: ge-1 5,000."])
        // Restarted (uptime 2 min < 5 min between the walks; and 30 s < a day before): counts since
        // the restart, never "growing".
        for up: UInt32 in [12_000, 3_000] {
            for before: UInt64 in [500, 5] {
                let snaps = [w1([Self.port(1, name: "ge-1", inErr: before)]), w2([Self.port(1, name: "ge-1", inErr: 30)], up: up)]
                let r = Round13Tests.analyze(snmp: snaps, now: Self.at(1_000))
                let errors = r.findings.filter { $0.rule.hasPrefix("snmp.errors") }
                XCTAssertEqual(errors.map(\.title), ["1 interface on SW-R15 has error counts: ge-1 30."], "uptime \(up), before \(before)")
                XCTAssertTrue(errors.first?.detail.hasPrefix("These are counts since SW-R15 restarted (\(FText.duration(Double(up) / 100)) before the walk)") ?? false,
                              errors.first?.detail ?? "none")
                XCTAssertTrue(r.findings.contains { $0.rule == "snmp.recentBoot" })
            }
        }
        // A walk taken a minute later on a device whose uptime went backwards by less than the
        // interval (clock of the walk off): still a restart.
        let back = Self.titles([w1([Self.port(1, name: "ge-1", inErr: 500)]),
                                Self.walk(60, upTime: up0 - 100_000, [Self.port(1, name: "ge-1", inErr: 30)])])
        XCTAssertEqual(back, ["1 interface on SW-R15 has error counts: ge-1 30."])
        // A module pulled: ports 3 and 4 are gone; port 1 grew.
        t = Self.titles([w1((1...4).map { Self.port($0, name: "ge-\($0)", inErr: 100) }),
                         w2([Self.port(1, name: "ge-1", inErr: 150), Self.port(2, name: "ge-2", inErr: 100)])])
        XCTAssertEqual(t, ["Interface errors are growing on SW-R15: ge-1 +50 in 5 min."])
        // Another port took ifIndex 3 (a new module): its counters are its own, not a wrap.
        t = Self.titles([w1([Self.port(3, name: "ge-3", inErr: 3_000_000_000, inDisc: 3_000_000_000, inU32: 3_500_000_000)]),
                         w2([Self.port(3, name: "xe-3", inErr: 10, inDisc: 10, inU32: 1_000_000)])])
        XCTAssertEqual(t, ["1 interface on SW-R15 has error counts: xe-3 10."])
        // The same port named by ifName in one walk and by ifDescr in the other (ifXTable timed
        // out the first time): the same port, compared.
        var named = Self.port(1, name: "GigabitEthernet1/0/1", inErr: 150)
        named.0.name = "Gi1/0/1"
        t = Self.titles([w1([Self.port(1, name: "GigabitEthernet1/0/1", inErr: 100)]), w2([named])])
        XCTAssertEqual(t, ["Interface errors are growing on SW-R15: Gi1/0/1 +50 in 5 min."])
        // The same name, but ifCounterDiscontinuityTime moved (the line card was re-seated).
        t = Self.titles([w1([Self.port(3, name: "ge-3", inDisc: 3_000_000_000, inU32: 3_500_000_000, discontinuity: "100")]),
                         w2([Self.port(3, name: "ge-3", inDisc: 2_000, inU32: 1_000_000, discontinuity: "29000")])])
        XCTAssertEqual(t, ["1 interface on SW-R15 dropped over 0.1 % of its packets since the counters were cleared: ge-3 in 20.0 per 10,000 packets."])
        // …and with the same discontinuity time, the same small numbers are a wrap: growth.
        t = Self.titles([w1([Self.port(3, name: "ge-3", inDisc: 4_294_967_000, inU32: 4_294_000_000, discontinuity: "100")]),
                         w2([Self.port(3, name: "ge-3", inDisc: 3_704, inU32: 1_000_000, discontinuity: "100")])])
        XCTAssertEqual(t, ["Discards are growing on SW-R15: ge-3 in 20.3 per 10,000 packets (+4,000) in 5 min."])
        // 64-bit packet counters in both walks: never wrap; smaller = cleared (no rate below 0).
        t = Self.titles([w1([Self.port(1, name: "ge-1", inDisc: 1_000, inU32: 5, inHC: 10_000_000_000)]),
                         w2([Self.port(1, name: "ge-1", inDisc: 1_500, inU32: 9, inHC: 10_000_100_000)])])
        XCTAssertEqual(t, ["Discards are growing on SW-R15: ge-1 in 49.8 per 10,000 packets (+500) in 5 min."])
        t = Self.titles([w1([Self.port(1, name: "ge-1", inDisc: 1_000, inHC: 10_000_000_000)]),
                         w2([Self.port(1, name: "ge-1", inDisc: 1_500, inHC: 50_000)])])
        XCTAssertEqual(t, ["Discards are growing on SW-R15: ge-1 in +500 in 5 min."], "HC cleared: no packet rate, the growth")
        // 64-bit counters in only one of the walks (ifXTable not walked the first time): the
        // 32-bit columns of both.
        t = Self.titles([w1([Self.port(1, name: "ge-1", inDisc: 1_000, inU32: 4_000_000_000)]),
                         w2([Self.port(1, name: "ge-1", inDisc: 1_200, inU32: 4_000_100_000, inHC: 12_000_100_000)])])
        XCTAssertEqual(t, ["Discards are growing on SW-R15: ge-1 in 20.0 per 10,000 packets (+200) in 5 min."])
        // A hostile agent's discards at UInt64.max: a number, no trap.
        t = Self.titles([w1([Self.port(1, name: "ge-1", inDisc: 0, inU32: 1)]), w2([Self.port(1, name: "ge-1", inDisc: UInt64.max, inU32: 2)])])
        XCTAssertEqual(t.count, 1)
        XCTAssertTrue(t[0].hasPrefix("Discards are growing on SW-R15: ge-1 in "), t[0])
        // Every rate any of these gave is a number ≥ 0 (never "-", NaN or inf).
        XCTAssertEqual(FindingRules.rateText(0), "0.0")
    }

    /// ifHCInOctets and the 32-bit ifInOctets on the same walk: the table shows the 64-bit one
    /// (the 32-bit one wraps every 34 s at 1 Gb/s), for every port that has it, and the 32-bit
    /// one for a port that has only that.
    func testOctetsPreferTheSixtyFourBitCounter() {
        let t = OID.ifTable.appending(1), x = OID.ifXTable.appending(1)
        let ifTable = [VarBind(t.appending([1, 1]), .integer(1)), VarBind(t.appending([1, 2]), .integer(2)),
                       VarBind(t.appending([10, 1]), .counter32(1_000)), VarBind(t.appending([10, 2]), .counter32(2_000)),
                       VarBind(t.appending([16, 1]), .counter32(3_000)), VarBind(t.appending([16, 2]), .counter32(4_000))]
        let ifX = [VarBind(x.appending([6, 1]), .counter64(8_589_935_592)), VarBind(x.appending([10, 1]), .counter64(12_884_904_888))]
        let rows = SNMPTestModel.joinInterfaces(ifTable: ifTable, ifXTable: ifX)
        XCTAssertEqual(rows.map(\.inOctets), [8_589_935_592, 2_000])
        XCTAssertEqual(rows.map(\.outOctets), [12_884_904_888, 4_000])
    }

    // MARK: - 3. File writes a full disk or ⌘Q could cut short

    nonisolated static func raws(_ n: Int, from start: Date, step: Double, tag: String) -> [RawSyslog] {
        (0..<n).map { k in
            RawSyslog(received: start.addingTimeInterval(Double(k) * step), sourceAddress: "10.15.0.1", sourcePort: 514, transport: .udp,
                      text: "<14>1 - SW1 app - - - \(tag) \(k) " + String(repeating: "x", count: 100))
        }
    }

    /// The lines of a log file: each complete (a stamp, an address, the raw line; the file ends
    /// with a line break).
    static func fileLines(_ url: URL) throws -> [Substring] {
        let text = try String(contentsOf: url, encoding: .utf8)
        XCTAssertTrue(text.isEmpty || text.hasSuffix("\n"), "\(url.lastPathComponent) ends in half a line")
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).dropLast()
        for l in lines { XCTAssertTrue(l.contains(" 10.15.0.1 <14>1 - SW1 app - - - ") && l.hasSuffix("xxxx"), "a cut line: \(l.prefix(60))") }
        return Array(lines)
    }

    /// A flood across midnight: batches the logger's queue writes after midnight hold lines
    /// that arrived before it — they go to the day they arrived (they were the first lines of
    /// the next day's file). 20,000 lines from two listener threads while the clock steps over
    /// midnight, then a close (⌘Q): every line once, each in its own day's file, none cut.
    func testDiskLogRotationAtMidnightDuringAFlood() async throws {
        let dir = try tempDir()
        let midnight = Calendar(identifier: .gregorian).startOfDay(for: Date()).addingTimeInterval(86_400 * 3)
        let clock = LockedBox(midnight.addingTimeInterval(-1))
        let logger = DiskLogger(directory: dir, clock: { clock.value })
        let before = DiskLogger.dayString(midnight.addingTimeInterval(-1)), after = DiskLogger.dayString(midnight)
        // The queue lags: lines of 23:59:59.x written at 00:00:00.3.
        logger.append(raws: Self.raws(5, from: midnight.addingTimeInterval(-1), step: 0.1, tag: "a"))
        logger.sync()
        clock.mutate { $0 = midnight.addingTimeInterval(0.3) }
        logger.append(raws: Self.raws(5, from: midnight.addingTimeInterval(-0.5), step: 0.1, tag: "b")
                      + Self.raws(3, from: midnight, step: 0.1, tag: "c"))
        logger.sync()
        let d1 = try Self.fileLines(dir.appending(path: "\(before).log")), d2 = try Self.fileLines(dir.appending(path: "\(after).log"))
        XCTAssertEqual(d1.count, 10)
        XCTAssertEqual(d2.count, 3)
        XCTAssertTrue(d2.allSatisfy { $0.contains(" c ") }, "yesterday's lines in today's file")
        // The flood: two threads, 10,000 lines each, received across midnight, the clock
        // stepping on while they are written.
        let start = midnight.addingTimeInterval(86_400 - 2)             // the next midnight, 2 s before
        let nextDay = DiskLogger.dayString(start.addingTimeInterval(3))
        clock.mutate { $0 = start }
        let group = DispatchGroup()
        for t in 0..<2 {
            group.enter()
            Thread {
                for b in 0..<100 {
                    let first = start.addingTimeInterval(Double(b) * 0.04)
                    // The Mac's clock is past every line it hands on (by the time the queue
                    // writes them, further still).
                    clock.mutate { $0 = max($0, first.addingTimeInterval(0.05)) }
                    logger.append(raws: Self.raws(100, from: first, step: 0.0004, tag: "f\(t)-\(b)"))
                }
                group.leave()
            }.start()
        }
        await withCheckedContinuation { c in DispatchQueue.global().async { group.wait(); c.resume() } }
        logger.close()                                                    // ⌘Q
        let a = try Self.fileLines(dir.appending(path: "\(after).log")), b = try Self.fileLines(dir.appending(path: "\(nextDay).log"))
        XCTAssertEqual(a.count - 3 + b.count, 20_000, "every line once")
        let stamp = Format.gregorian("yyyy-MM-dd")
        XCTAssertTrue(a.allSatisfy { $0.hasPrefix(stamp.string(from: start)) }, "a line of the next day in the day's file")
        XCTAssertTrue(b.allSatisfy { $0.hasPrefix(stamp.string(from: start.addingTimeInterval(3))) }, "a line of the day before in the next day's file")
        XCTAssertGreaterThan(a.count, 3)
        XCTAssertGreaterThan(b.count, 0)
    }

    /// The disk log on a volume that fills up: one readable error; the file never ends in half
    /// a line (a batch cut part-way stayed in the file and the next line written after space
    /// was freed continued it); once there is room the lines are written again.
    func testDiskLogOnAFullDisk() throws {
        let disk = try ramDisk()
        let dir = disk.mount.appending(path: "logs")
        let errors = LockedBox<[String]>([])
        let logger = DiskLogger(directory: dir) { m in errors.mutate { $0.append(m) } }
        logger.append(raws: Self.raws(10, from: Date(), step: 0.001, tag: "first"))
        logger.sync()
        let filler = disk.fill(leaving: 20_000)
        for k in 0..<10 { logger.append(raws: Self.raws(200, from: Date(), step: 0.001, tag: "full\(k)")) }   // 30 KB each
        logger.sync()
        XCTAssertEqual(errors.value.count, 1, errors.value.description)
        XCTAssertTrue(errors.value.first?.contains("(the disk is full)") ?? false, errors.value.first ?? "")
        let file = try XCTUnwrap(logger.currentFile)
        let atFull = try Self.fileLines(file)
        XCTAssertGreaterThanOrEqual(atFull.count, 10)
        try FileManager.default.removeItem(at: filler)
        logger.append(raws: Self.raws(10, from: Date(), step: 0.001, tag: "after"))
        logger.close()
        let lines = try Self.fileLines(file)
        XCTAssertEqual(lines.suffix(10).map { $0.contains(" after ") }, Array(repeating: true, count: 10))
        XCTAssertEqual(errors.value.count, 1)
    }

    /// A packet Save, a Log export (.log and .csv), settings.json and a MIB folder import onto
    /// a full disk: each says why once and leaves no file (no partial file, no temporary one);
    /// a settings.json already there is the old one, whole.
    func testWritesOntoAFullDisk() async throws {
        let disk = try ramDisk()
        let app = AppModel.shared
        // settings.json written while there is room.
        let settingsURL = disk.mount.appending(path: "settings.json")
        app.saveSettings(to: settingsURL)
        let savedSettings = try Data(contentsOf: settingsURL)
        disk.fill(leaving: 0)
        // Packet Save through the store (the pane's path): an error, no file, no temp.
        let packets = app.packets
        packets.clear()
        packets.ingest(Round11InteractionTests.bulk(firstID: 1, offset: 0, pairs: 5_000))
        await waitUntil { packets.packets.count == 10_000 }
        var saved: String?? = .none
        packets.save(to: disk.mount.appending(path: "capture.pcap")) { saved = .some($0) }
        await waitUntil(10) { saved != nil }
        let saveError = try XCTUnwrap(saved ?? nil, "the Save said nothing")
        XCTAssertTrue(saveError.contains("disk is full") || saveError.localizedCaseInsensitiveContains("space"), saveError)
        XCTAssertFalse(packets.isSaving)
        // Log export, both forms.
        var rows: [LogEntry] = []
        for k in 0..<5_000 { rows.append(parsedLine("<14>1 - SW1 app - - - export \(k) " + String(repeating: "y", count: 60), from: "10.15.0.2", id: k + 1)) }
        for name in ["export.log", "export.csv"] {
            let failure = LogStore.writeExport(rows, csv: name.hasSuffix("csv"), to: disk.mount.appending(path: name))
            XCTAssertTrue(failure?.localizedCaseInsensitiveContains("space") ?? false, failure ?? "no error for \(name)")
        }
        // Settings: two changes, one error; the file is the old one.
        let before = app.lastError
        XCTAssertNil(before)
        app.saveSettings(to: settingsURL)
        app.saveSettings(to: settingsURL)
        XCTAssertEqual(app.lastError, "Settings could not be saved.")
        XCTAssertEqual(try Data(contentsOf: settingsURL), savedSettings)
        XCTAssertTrue(app.settingsSaveFailing)
        app.clearError()
        await spin(400)
        XCTAssertNil(app.lastError, "a second error for the same spell")
        // A MIB folder: one report for the files that could not be copied.
        let src = try tempDir()
        for k in 0..<3 {
            let text = "R15-MIB-\(k) DEFINITIONS ::= BEGIN\nIMPORTS enterprises FROM SNMPv2-SMI;\nr15m\(k) OBJECT IDENTIFIER ::= { enterprises \(99_000 + k) }\n"
                + "-- " + String(repeating: "padding ", count: 1_000) + "\nEND\n"
            try text.write(to: src.appending(path: "R15-MIB-\(k).mib"), atomically: true, encoding: .utf8)
        }
        let reg = MIBRegistry()
        reg.userFolderOverride = disk.mount.appending(path: "MIBs")
        reg.loadNow(bundled: [])
        reg.importFiles([src])
        await waitUntil(20) { !reg.isLoading && app.lastError != nil }
        XCTAssertEqual(app.lastError, "Could not copy 3 files into the MIB folder.")
        app.clearError()
        await spin(400)
        // Nothing half-written anywhere: only the filler, settings.json and the (empty) MIB folder.
        let left = try FileManager.default.contentsOfDirectory(atPath: disk.mount.path).filter { !RAMDisk.system.contains($0) }.sorted()
        XCTAssertEqual(left.filter { !$0.hasPrefix("filler") && $0 != "MIBs" }, ["settings.json"])
        let mibs = (try? FileManager.default.contentsOfDirectory(atPath: disk.mount.appending(path: "MIBs").path)) ?? []
        XCTAssertEqual(mibs.filter { !RAMDisk.system.contains($0) }, [])
        // Room again: settings save, and the next failure is worth a report again.
        for f in left where f.hasPrefix("filler") { try FileManager.default.removeItem(at: disk.mount.appending(path: f)) }
        app.saveSettings(to: settingsURL)
        XCTAssertFalse(app.settingsSaveFailing)
    }

    /// ⌘Q while a MIB folder is being copied in: `shutdownForQuit` waits for the copy (it did
    /// not: a module that replaced another file's had its new file copied and the old one not
    /// yet removed — two files of one module at the next launch).
    func testQuitWaitsForAMIBFolderImport() async throws {
        let folder = try tempDir(), src = try tempDir()
        // The same module under an old file name, and a folder of 60 modules to import.
        let old = "R15-OLD-MIB DEFINITIONS ::= BEGIN\nIMPORTS enterprises FROM SNMPv2-SMI;\nr15old OBJECT IDENTIFIER ::= { enterprises 98000 }\nEND\n"
        try old.write(to: folder.appending(path: "old-name.mib"), atomically: true, encoding: .utf8)
        for k in 0..<60 {
            let name = k == 59 ? "R15-OLD-MIB" : "R15-Q-MIB-\(k)"
            let text = "\(name) DEFINITIONS ::= BEGIN\nIMPORTS enterprises FROM SNMPv2-SMI;\nr15q\(k) OBJECT IDENTIFIER ::= { enterprises \(97_000 + k) }\n"
                + "-- " + String(repeating: "padding ", count: 4_000) + "\nEND\n"
            try text.write(to: src.appending(path: "z\(k).mib"), atomically: true, encoding: .utf8)
        }
        let reg = MIBRegistry()
        reg.userFolderOverride = folder
        reg.loadNow(bundled: [], user: [folder.appending(path: "old-name.mib")])
        reg.importFiles([src])
        XCTAssertGreaterThan(PendingWrites.inFlight, 0, "the import is a pending write from the moment it is asked for")
        AppModel.shared.shutdownForQuit()
        XCTAssertEqual(PendingWrites.inFlight, 0)
        let files = try FileManager.default.contentsOfDirectory(atPath: folder.path).filter { !RAMDisk.system.contains($0) }.sorted()
        XCTAssertEqual(files.count, 60, "\(files.count) files when ⌘Q returned")
        XCTAssertFalse(files.contains("old-name.mib"), "the replaced module's old file is still there")
        await waitUntil(20) { !reg.isLoading }
    }

    /// Every file SheepLog writes for the user goes through a temporary file and a rename:
    /// Foundation's `.atomic` / `atomically: true` (the exports, settings, MIB copies, PNGs,
    /// Markdown reports), `PcapFile.write` (its own temp + rename) and the append-only disk
    /// log (`DiskLogger.writeWhole`). A new `write(to:` without it fails here.
    func testEveryFileWriteIsAtomic() throws {
        let src = Round12Tests.testsDir.deletingLastPathComponent().appending(path: "SheepLog")
        let files = FileManager.default.enumerator(at: src, includingPropertiesForKeys: nil)?.compactMap { $0 as? URL }.filter { $0.pathExtension == "swift" } ?? []
        XCTAssertGreaterThan(files.count, 40)
        var bad: [String] = []
        for f in files {
            let lines = try String(contentsOf: f, encoding: .utf8).split(separator: "\n", omittingEmptySubsequences: false)
            for (i, l) in lines.enumerated() where l.contains(".write(to:") && !l.trimmingCharacters(in: .whitespaces).hasPrefix("//") {
                if !(l.contains(".atomic") || l.contains("atomically: true")) { bad.append("\(f.lastPathComponent):\(i + 1): \(l.trimmingCharacters(in: .whitespaces))") }
            }
        }
        XCTAssertEqual(bad, [])
        // The same calls on a full disk: an error, the old file whole, no temporary file.
        let disk = try ramDisk()
        let a = disk.mount.appending(path: "report.md")
        try "old".write(to: a, atomically: true, encoding: .utf8)
        disk.fill(leaving: 0)
        XCTAssertThrowsError(try String(repeating: "z", count: 200_000).write(to: a, atomically: true, encoding: .utf8))
        XCTAssertThrowsError(try Data(count: 200_000).write(to: a, options: .atomic))
        XCTAssertEqual(try String(contentsOf: a, encoding: .utf8), "old")
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: disk.mount.path).filter { !RAMDisk.system.contains($0) && !$0.hasPrefix("filler") }, ["report.md"])
    }

    // MARK: - 4. State restored at launch from values of the wrong type

    /// Values of every other type (and hostile ones) for a remembered key.
    static let wrongTypes: [Any] = [42, 3.5, true, "nonsense", "", "nan", Data([0, 1, 2]), [1, 2], ["a": 1], Date(), ["status", 7]]

    private func suite() throws -> UserDefaults {
        let name = "SheepLogR15-\(UUID().uuidString)"
        let s = try XCTUnwrap(UserDefaults(suiteName: name))
        addTeardownBlock { UserDefaults().removePersistentDomain(forName: name) }
        return s
    }

    /// The last pane and the hidden columns of both tables, each key holding a value of the
    /// wrong type: the defaults (every column as built, the pane the app starts on); a list
    /// that hides every column still leaves Message / Info.
    func testRememberedPaneAndColumnsOfTheWrongType() throws {
        let s = try suite()
        for v in Self.wrongTypes {
            s.set(v, forKey: LastPane.key)
            XCTAssertNil(LastPane.restore(from: s), "\(v)")
        }
        s.set("flows", forKey: LastPane.key)
        XCTAssertEqual(LastPane.restore(from: s), .flows)
        // The Log table.
        let log = try XCTUnwrap(LogTableView.makeScrollView(coordinator: LogTableView.Coordinator(store: LogStore())).documentView as? NSTableView)
        let built = log.tableColumns.map(\.isHidden)
        for v in Self.wrongTypes {
            s.set(v, forKey: "SheepLog.log.hiddenColumns")
            LogColumn.restoreHidden(log, from: s)
            XCTAssertEqual(log.tableColumns.map(\.isHidden), built, "\(v)")
        }
        s.set(log.tableColumns.map(\.identifier.rawValue) + ["no-such-column"], forKey: "SheepLog.log.hiddenColumns")
        LogColumn.restoreHidden(log, from: s)
        XCTAssertEqual(log.tableColumns.filter { !$0.isHidden }.map(\.identifier), [LogColumn.message])
        // The Packets table.
        let controller = PacketTableController()
        let packets = try XCTUnwrap(PacketTableView.makeScrollView(controller: controller).documentView as? NSTableView)
        let builtP = packets.tableColumns.map(\.isHidden)
        for v in Self.wrongTypes {
            s.set(v, forKey: "SheepLog.packets.hiddenColumns")
            PacketTableController.restoreHiddenColumns(packets, from: s)
            XCTAssertEqual(packets.tableColumns.map(\.isHidden), builtP, "\(v)")
        }
        s.set(PacketTableController.Column.allCases.map(\.rawValue), forKey: "SheepLog.packets.hiddenColumns")
        PacketTableController.restoreHiddenColumns(packets, from: s)
        XCTAssertEqual(packets.tableColumns.filter { !$0.isHidden }.map(\.identifier.rawValue), ["info"])
    }

    /// The Log pane's detail width, its pin and the Packets split, each of the wrong type, the
    /// panes started on them: @AppStorage reads `defaults write … -string nan` as NaN, and
    /// `max(NaN, 260)` is NaN — the detail panel got a NaN width. Every view of the started
    /// pane has a finite frame, and the width in use is the default.
    func testPanesStartOnRememberedValuesOfTheWrongType() async throws {
        let s = try suite()
        // What @AppStorage hands the view for a stored NaN (a real, `defaults write … -float nan`).
        let seen = LockedBox<Double>(0)
        s.set(Double.nan, forKey: "SheepLog.logDetailWidth")
        let probe = host(AppStorageProbe(seen: seen).defaultAppStorage(s))
        await spin(100)
        XCTAssertTrue(seen.value.isNaN, "\(seen.value): the NaN reaches the view")
        close(probe)
        XCTAssertEqual(LogView.detailWidth(stored: .nan, range: 260...560), 360)
        XCTAssertEqual(LogView.detailWidth(stored: .infinity, range: 260...560), 360)
        XCTAssertEqual(LogView.detailWidth(stored: -50, range: 260...560), 260)
        XCTAssertEqual(LogView.detailWidth(stored: 1e12, range: 260...560), 560)
        XCTAssertEqual(LogView.detailWidth(stored: 400, range: 260...560), 400)
        let cases: [(String, [Any], MainPane)] = [
            ("SheepLog.logDetailWidth", [Double.nan, Double.infinity, "nan", "wide", -50.0, 1e12, true, Data([1]), [1]], .log),
            ("SheepLog.logDetailPinned", ["yes", 7, "nan", Data([1]), ["x"]], .log),
            ("SheepLog.packetsSplit", [Double.nan, Double.infinity, "nan", "abc", -1.0, 99.0, [2], Data([1])], .packets),
        ]
        for (key, values, pane) in cases {
            for v in values {
                s.set(true, forKey: "SheepLog.logDetailPinned")          // the detail panel shown
                s.set(v, forKey: key)
                let w = host(Round14Tests.pane(pane).defaultAppStorage(s))
                await spin(150)
                w.contentView?.layoutSubtreeIfNeeded()
                var bad: [String] = []
                func visit(_ v: NSView) {
                    let f = v.frame
                    if !(f.origin.x.isFinite && f.origin.y.isFinite && f.width.isFinite && f.height.isFinite) || f.width < 0 || f.height < 0 {
                        bad.append("\(type(of: v)) \(f)")
                    }
                    v.subviews.forEach(visit)
                }
                if let root = w.contentView { visit(root) }
                XCTAssertEqual(bad, [], "\(key) = \(v)")
                close(w)
            }
        }
    }

    /// A window's remembered frame that is garbage, tiny or huge, read by AppKit for a window
    /// with the app's minimum size: finite and at least that size. (The app's own window is
    /// SwiftUI's WindowGroup, which the test host cannot open: launched with a number, and with
    /// "nan nan nan nan …", under its real "NSWindow Frame SwiftUI.WindowGroup<…>" key it
    /// opened at 1000 × 672 — round 15's launch check. Calling `setFrameUsingName:` directly on
    /// a number or NaN frame raises inside AppKit; the app never does.)
    func testRememberedWindowFrameOfTheWrongType() throws {
        let name = "SheepLogR15-\(UUID().uuidString)"
        let key = "NSWindow Frame \(name)"
        defer { UserDefaults.standard.removeObject(forKey: key) }
        for v in ["garbage", "", "0 0 10 10 0 0 1470 923 ", "-99999999 -99999999 99999999 99999999 0 0 1470 923 ", "1 2 3"] {
            UserDefaults.standard.set(v, forKey: key)
            let w = NSWindow(contentRect: NSRect(x: 100, y: 100, width: 1280, height: 820), styleMask: [.titled, .resizable], backing: .buffered, defer: false)
            w.isReleasedWhenClosed = false
            w.contentMinSize = NSSize(width: Metrics.minimumWindow, height: 640)
            _ = w.setFrameUsingName(name)
            let f = w.frame
            XCTAssertTrue(f.origin.x.isFinite && f.origin.y.isFinite && f.width.isFinite && f.height.isFinite, "\(v): \(f)")
            XCTAssertGreaterThanOrEqual(w.contentRect(forFrameRect: f).width, Metrics.minimumWindow - 0.5, "\(v): \(f)")
            XCTAssertGreaterThanOrEqual(w.contentRect(forFrameRect: f).height, 639.5, "\(v): \(f)")
            w.close()
        }
    }

    private func host<V: View>(_ view: V) -> NSWindow {
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1280, height: 820), styleMask: [.titled, .resizable], backing: .buffered, defer: false)
        w.isReleasedWhenClosed = false
        w.contentView = NSHostingView(rootView: view)
        w.orderFront(nil)
        windows.append(w)
        return w
    }

    private func close(_ w: NSWindow) {
        w.contentView = nil
        w.close()
        windows.removeAll { $0 === w }
    }

    // MARK: - 6. Sweep

    /// A Save over an earlier capture onto a disk with no room even for a temporary file: the
    /// old capture stays, byte for byte (the temporary file could not be made, so the Save
    /// went "in place" — libpcap truncated the old capture and the write failed: both lost).
    func testSaveOverACaptureOnAFullDiskKeepsTheOldOne() throws {
        let disk = try ramDisk()
        let url = disk.mount.appending(path: "capture.pcap")
        try PcapFile.write(Round11InteractionTests.conversations(), linkType: 1, to: url)
        let old = try Data(contentsOf: url)
        disk.fill(leaving: 0)
        XCTAssertThrowsError(try PcapFile.write(Round11InteractionTests.bulk(firstID: 1, offset: 0, pairs: 3_000), linkType: 1, to: url)) { e in
            XCTAssertTrue(e.localizedDescription.contains("(the disk is full)"), e.localizedDescription)
        }
        XCTAssertEqual(try Data(contentsOf: url), old)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: disk.mount.path).filter { !RAMDisk.system.contains($0) && !$0.hasPrefix("filler") },
                       ["capture.pcap"])
    }

    /// settings.json replaced by a folder while the app runs: a change says once that it could
    /// not be saved; the next launch reads defaults (no crash, no copy of a folder aside).
    func testSettingsFileThatIsAFolder() throws {
        let dir = try tempDir()
        let url = dir.appending(path: "settings.json")
        try FileManager.default.createDirectory(at: url.appending(path: "inside"), withIntermediateDirectories: true)
        let app = AppModel.shared
        XCTAssertNil(app.lastError)
        app.saveSettings(to: url)
        app.saveSettings(to: url)
        XCTAssertEqual(app.lastError, "Settings could not be saved.")
        XCTAssertTrue(app.lastErrorDetail?.hasPrefix(url.path(percentEncoded: false)) ?? false, app.lastErrorDetail ?? "")
        XCTAssertEqual(AppSettings.load(from: url), AppSettings())
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.appending(path: "settings.corrupt.json").path))
        app.clearError()
        app.saveSettings(to: dir.appending(path: "other.json"))
        XCTAssertFalse(app.settingsSaveFailing)
    }

    /// A Log export whose folder went away between the save panel and the write: the error
    /// text, no note, nothing written anywhere.
    func testExportToAFolderThatWentAway() async throws {
        let dir = try tempDir()
        let store = LogStore()
        store.ingest((0..<10).map { parsedLine("<14>1 - SW1 app - - - line \($0)", from: "10.15.0.3", id: $0 + 1) })
        try FileManager.default.removeItem(at: dir)
        let failure = await store.export(to: dir.appending(path: "x.csv"), csv: true)
        XCTAssertNotNil(failure)
        XCTAssertNil(store.exportNote)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path))
        XCTAssertEqual(PendingWrites.inFlight, 0)
    }

    /// Cisco IOS writes one BGP reset as a NOTIFICATION, `%BGP-5-ADJCHANGE … Down` and
    /// `%BGP_SESSION-5-ADJCHANGE … topology base removed from session` ("topology" and
    /// "neighbor": neither spanning tree nor a second down) — then Up: nothing; twice: a flap of 2.
    func testIOSResetWithItsSessionTwinIsOneOutage() {
        var l = Round13Tests.Lines()
        func reset(_ t: Double) {
            l.raw(t, "<187>\(Self.bsd(t)) CORE-RTR1 %BGP-3-NOTIFICATION: sent to neighbor 10.0.0.2 4/0 (hold time expired) 0 bytes", from: "10.66.3.1")
            l.raw(t + 0.01, "<189>\(Self.bsd(t)) CORE-RTR1 %BGP-5-ADJCHANGE: neighbor 10.0.0.2 Down BGP Notification sent", from: "10.66.3.1")
            l.raw(t + 0.02, "<189>\(Self.bsd(t)) CORE-RTR1 %BGP_SESSION-5-ADJCHANGE: neighbor 10.0.0.2 IPv4 Unicast topology base removed from session  BGP Notification sent", from: "10.66.3.1")
            l.raw(t + 40, "<189>\(Self.bsd(t + 40)) CORE-RTR1 %BGP-5-ADJCHANGE: neighbor 10.0.0.2 Up", from: "10.66.3.1")
        }
        reset(0)
        XCTAssertTrue(Round13Tests.analyze(l.entries).findings.isEmpty)
        reset(600)
        XCTAssertEqual(Round13Tests.analyze(l.entries).findings.map(\.title),
                       ["BGP neighbor 10.0.0.2 on CORE-RTR1 went down 2 times (\(Round13Tests.clock(0))–\(Round13Tests.clock(600)))."])
    }

    /// A BGP peer that keeps trying (Idle → Connect → Active → Idle every 30 s) and never
    /// reaches Established: not "went down at … and has not come back" (round 14: each Idle was
    /// a down, for a peer that was never up) but "has not come up", with its steps as evidence.
    func testPeerThatNeverComesUp() {
        var l = Round13Tests.Lines()
        let peer = "RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 10.0.14.9 (External AS 65099) changed state from"
        for k in 0..<12 {
            let t = Double(k) * 30
            l.raw(t, "<29>\(Self.bsd(t)) MX204-EDGE rpd[1811]: \(peer) Idle to Connect (event Start) (instance master)", from: "10.66.3.2")
            l.raw(t + 5, "<29>\(Self.bsd(t + 5)) MX204-EDGE rpd[1811]: \(peer) Connect to Active (event ConnectFail) (instance master)", from: "10.66.3.2")
            l.raw(t + 20, "<29>\(Self.bsd(t + 20)) MX204-EDGE rpd[1811]: \(peer) Active to Idle (event ConnectRetry) (instance master)", from: "10.66.3.2")
        }
        let r = Round13Tests.analyze(l.entries)
        XCTAssertEqual(r.findings.map(\.title),
                       ["BGP neighbor 10.0.14.9 on MX204-EDGE has not come up: 36 state changes from \(Round13Tests.clock(0)) to \(Round13Tests.clock(350)), none to Established."])
        XCTAssertEqual(r.findings.first?.evidence.first?.ids.count, 36)
        // …and one that comes up after a minute of trying: nothing.
        l.raw(400, "<29>\(Self.bsd(400)) MX204-EDGE rpd[1811]: \(peer) OpenConfirm to Established (event RecvKeepAlive) (instance master)", from: "10.66.3.2")
        XCTAssertEqual(Round13Tests.analyze(l.entries).findings.map(\.title), [])
    }

    /// An IPv6 neighbor's finding: its evidence filter (`host:… bgp 2001:db8::2`) shows its line
    /// and not the other IPv6 peer's.
    func testIPv6NeighborEvidenceFilter() async throws {
        var l = Round13Tests.Lines()
        l.raw(0, "<30>\(Self.bsd(0)) frr-edge1 bgpd[912]: %ADJCHANGE: neighbor 2001:db8::2(spine1) in vrf default Down Peer closed the session", from: "10.66.3.3")
        l.raw(1, "<30>\(Self.bsd(1)) frr-edge1 bgpd[912]: %ADJCHANGE: neighbor 2001:db8::3(spine2) in vrf default Up", from: "10.66.3.3")
        let r = Round13Tests.analyze(l.entries)
        let e = try XCTUnwrap(r.findings.first?.evidence.first)
        let store = LogStore()
        store.ingest(l.entries)
        store.queryText = e.query
        store.applyQueryText()
        await waitUntil { store.visible.count == 1 }
        XCTAssertEqual(store.visible.map(\.id), [1], "`\(e.query)`")
    }
}

/// What @AppStorage hands a view for the Log pane's detail width.
private struct AppStorageProbe: View {
    @AppStorage("SheepLog.logDetailWidth") var width: Double = 360
    let seen: LockedBox<Double>
    var body: some View {
        let _ = seen.mutate { $0 = width }
        Color.clear.frame(width: 10, height: 10)
    }
}

/// A small HFS+ disk in RAM (`hdiutil attach -nomount ram://N`, `newfs_hfs`, `diskutil mount`):
/// a volume that fills up.
@MainActor
final class RAMDisk {
    let device: String
    let mount: URL
    /// What macOS keeps on a volume of its own (a temporary file of ours is not one of them,
    /// dot or no dot).
    static let system: Set<String> = [".fseventsd", ".Trashes", ".Spotlight-V100", ".TemporaryItems", ".DS_Store", ".DocumentRevisions-V100"]

    init(device: String, mount: URL) {
        self.device = device
        self.mount = mount
    }

    static func run(_ tool: String, _ args: [String]) -> String? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = Pipe()
        do { try p.run() } catch { return nil }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return p.terminationStatus == 0 ? String(decoding: data, as: UTF8.self) : nil
    }

    /// `sectors` of 512 bytes (2048 = 1 MB).
    static func make(sectors: Int = 2048) -> RAMDisk? {
        guard let out = run("/usr/bin/hdiutil", ["attach", "-nomount", "ram://\(sectors)"]),
              let dev = out.split(whereSeparator: \.isWhitespace).first.map(String.init), dev.hasPrefix("/dev/disk") else { return nil }
        let name = "SLR15-\(UUID().uuidString.prefix(6))"
        guard run("/sbin/newfs_hfs", ["-v", name, dev]) != nil, run("/usr/sbin/diskutil", ["mount", dev]) != nil else {
            _ = run("/usr/bin/hdiutil", ["detach", dev, "-force"])
            return nil
        }
        let mount = URL(fileURLWithPath: "/Volumes/\(name)", isDirectory: true)
        guard FileManager.default.fileExists(atPath: mount.path) else {
            _ = run("/usr/bin/hdiutil", ["detach", dev, "-force"])
            return nil
        }
        return RAMDisk(device: dev, mount: mount)
    }

    var free: Int {
        var st = statfs()
        guard statfs(mount.path, &st) == 0 else { return 0 }
        return Int(st.f_bavail) * Int(st.f_bsize)
    }

    /// Fills the disk with a file until `leave` bytes (or fewer) are free.
    @discardableResult
    func fill(leaving leave: Int = 0) -> URL {
        let url = mount.appending(path: "filler-\(UUID().uuidString.prefix(4))")
        let fd = open(url.path, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
        defer { close(fd) }
        let chunk = [UInt8](repeating: 0x5A, count: 4096)
        while free > leave {
            let n = min(chunk.count, max(1, free - leave))
            if chunk.withUnsafeBytes({ Darwin.write(fd, $0.baseAddress!, n) }) <= 0 { break }
        }
        fsync(fd)
        return url
    }

    func detach() {
        _ = Self.run("/usr/bin/hdiutil", ["detach", device, "-force"])
    }
}
