import AppKit
import Darwin
import SwiftUI
import Synchronization
import XCTest
@testable import SheepLog

/// Round 17: link / routing forms of kinds already read (NX-OS error-disabled, Junos structured
/// link traps, Huawei error-down causes, OSPF authentication, PAN-OS and FortiOS link changes),
/// IPv6 addresses by value in free text, the Troubleshoot pane's filter grammar, an evidence Show
/// on a paused Log, "Since change" after a sysUpTime wrap, an IPv6-only Mac, Apply ports under a
/// TCP flood — and a sweep.
@MainActor
final class Round17Tests: XCTestCase {
    private var windows: [NSWindow] = []
    private var cleanup: [URL] = []
    private var savedSettings: AppSettings?

    override func tearDown() async throws {
        for w in windows { w.contentView = nil; w.close() }
        windows = []
        for u in cleanup { try? FileManager.default.removeItem(at: u) }
        cleanup = []
        let app = AppModel.shared
        app.stopSyslog()
        app.stopTraps()
        if let s = savedSettings { app.settings = s; savedSettings = nil }
        app.dismissAllErrors()
        app.logs.paused = false
        app.logs.limit = 100_000
        app.logs.queryText = ""
        app.logs.applyQueryText()
        app.logs.clear()
        app.packets.paused = false
        app.packets.queryText = ""
        app.packets.applyQueryNow(synchronous: true)
        app.packets.clear()
        app.mainPane = .status
        TroubleshootModel.shared.jumpNotice = nil
        try? await Task.sleep(for: .milliseconds(30))
    }

    // MARK: - Harness

    static let t0 = Round13Tests.t0
    static func at(_ s: Double) -> Date { t0.addingTimeInterval(s) }
    static func clock(_ s: Double) -> String { Round13Tests.clock(s) }

    private func spin(_ ms: Int = 30) async { try? await Task.sleep(for: .milliseconds(ms)) }

    private func waitUntil(_ timeout: Double = 5, _ condition: () -> Bool) async {
        let end = Date().addingTimeInterval(timeout)
        while !condition(), Date() < end { await spin(10) }
    }

    static func kind(_ line: String) -> String { Round15Tests.kind(line) }

    static func shown(_ q: String, _ entries: [LogEntry]) throws -> [Int] { try Round16Tests.shown(q, entries) }

    // MARK: - 1. Forms of kinds already read

    static func link(_ i: String, _ up: Bool) -> String { "link(iface: \"\(i)\", up: \(up))" }
    static func ospfAuth(_ n: String) -> String { "routingAuth(proto: \"OSPF\", neighbor: \"\(n)\")" }
    static func ospf(_ n: String, _ up: Bool) -> String { "routing(proto: \"OSPF\", neighbor: \"\(n)\", up: \(up))" }

    /// The round-17 corpus lines, each read into what it says.
    func testRound17CorpusLinesAreRead() throws {
        let other = try Round15Tests.corpus("other"), hw = try Round15Tests.corpus("huawei")
        let pa = try Round15Tests.corpus("paloalto"), forti = try Round15Tests.corpus("fortigate")
        XCTAssertEqual([other.count, hw.count, pa.count, forti.count], [86, 21, 18, 18])
        XCTAssertEqual(other[73...].map(Self.kind), [
            Self.link("Ethernet1/12", false), "nil", Self.link("Ethernet1/12", true),        // NX-OS error-disabled, recovery, up
            Self.link("xe-0/0/3", false), Self.link("xe-0/0/3", true),                        // Junos structured
            Self.link("et-0/0/31", false), Self.link("et-0/0/31", true),                      // Junos classic
            Self.ospfAuth("10.0.12.6"), Self.ospf("10.0.12.6", true),                         // IOS ERRRCV, ADJCHG Full
            Self.ospfAuth("10.255.0.2"), Self.ospf("10.255.0.2", true),                       // FRR (Router-ID, not eth1's own address)
            Self.ospfAuth("10.0.14.6"), Self.ospf("10.0.14.6", true),                         // Junos
        ])
        XCTAssertEqual(hw[16...].map(Self.kind), [Self.link("GigabitEthernet0/0/7", false), "nil", Self.link("GigabitEthernet0/0/7", true),
                                                  Self.link("GigabitEthernet0/0/8", false), Self.link("GigabitEthernet0/0/8", true)])
        XCTAssertEqual(pa[14...].map(Self.kind), [Self.link("ethernet1/3", false), Self.link("ethernet1/3", true),
                                                  Self.link("HA2", false), Self.link("HA2", true)])
        XCTAssertEqual(forti[14...].map(Self.kind), [Self.link("port6", false), Self.link("port6", true),
                                                     Self.link("wan1", false), Self.link("wan1", true)])
    }

    /// Each new form: the down (or the rejected packet) alone is a finding; followed by its
    /// recovery, nothing.
    func testEachNewFormDownAloneIsAFindingAndRecoveredIsNone() throws {
        let other = try Round15Tests.corpus("other"), hw = try Round15Tests.corpus("huawei")
        let pa = try Round15Tests.corpus("paloalto"), forti = try Round15Tests.corpus("fortigate")
        let groups: [(lines: [String], rule: String, title: (Date) -> String)] = [
            (Array(other[73...75]), "link.down", { "Port Ethernet1/12 on N9K-LEAF-03 went down at \(FText.clock($0)) and has not come back." }),
            (Array(other[76...77]), "link.down", { "Port xe-0/0/3 on QFX5120-SPINE1 went down at \(FText.clock($0)) and has not come back." }),
            (Array(other[78...79]), "link.down", { "Port et-0/0/31 on QFX5220-SPINE2 went down at \(FText.clock($0)) and has not come back." }),
            (Array(other[80...81]), "routing.authFail", { "OSPF packets from 10.0.12.6 on CORE-RTR1 fail authentication: 1 rejected at \(FText.clock($0))." }),
            (Array(other[82...83]), "routing.authFail", { "OSPF packets from 10.255.0.2 on frr-core1 fail authentication: 1 rejected at \(FText.clock($0))." }),
            (Array(other[84...85]), "routing.authFail", { "OSPF packets from 10.0.14.6 on MX204-EDGE fail authentication: 1 rejected at \(FText.clock($0))." }),
            (Array(hw[16...18]), "link.down", { "Port GigabitEthernet0/0/7 on S5720-ACC-07 went down at \(FText.clock($0)) and has not come back." }),
            (Array(hw[19...20]), "link.down", { "Port GigabitEthernet0/0/8 on S5720-ACC-07 went down at \(FText.clock($0)) and has not come back." }),
            (Array(pa[14...15]), "link.down", { "Port Ethernet1/3 on PA-3220 went down at \(FText.clock($0)) and has not come back." }),
            (Array(pa[16...17]), "link.down", { "Port HA2 on PA-3220 went down at \(FText.clock($0)) and has not come back." }),
            (Array(forti[14...15]), "link.down", { "Port port6 on FGT-100F-HQ went down at \(FText.clock($0)) and has not come back." }),
            (Array(forti[16...17]), "link.down", { "Port wan1 on FGT-60F-Branch went down at \(FText.clock($0)) and has not come back." }),
        ]
        for g in groups {
            let first = Round12Tests.live([g.lines[0]], hostless: "10.78.1.1")
            let r = Round13Tests.analyze(first, now: first[0].received.addingTimeInterval(600))
            XCTAssertEqual(r.findings.map(\.rule), [g.rule], g.lines[0])
            XCTAssertEqual(r.findings.first?.title, g.title(first[0].received), g.lines[0])
            let all = Round12Tests.live(g.lines, hostless: "10.78.1.1")
            let after = Round13Tests.analyze(all, now: all.last!.received.addingTimeInterval(600))
            XCTAssertEqual(after.findings.map(\.title), [], "recovered: \(g.lines[0])")
            // The evidence filter shows the finding's own lines.
            if let e = r.findings.first?.evidence.first {
                XCTAssertEqual(try Self.shown(e.query, first), first.map(\.id), e.query)
            }
        }
        // Error-down causes are said in the detail.
        let crc = Round12Tests.live([hw[16]], hostless: "10.78.1.1")
        let d = Round13Tests.analyze(crc, now: crc[0].received.addingTimeInterval(600)).findings.first?.detail ?? ""
        XCTAssertTrue(d.contains("The switch shut it itself (err-disabled"), d)
        XCTAssertTrue(d.contains("The cause: too many CRC errors — a bad cable, optic or port."), d)
        let nx = Round12Tests.live([other[73]], hostless: "10.78.1.1")
        let nd = Round13Tests.analyze(nx, now: nx[0].received.addingTimeInterval(600)).findings.first?.detail ?? ""
        XCTAssertTrue(nd.contains("The cause: the link went up and down too often (link-flap)."), nd)
    }

    /// Around the new forms: BPDU guard and loop causes stay spanning tree's, with the port named
    /// (Huawei's "Notify interface to change …" made the port "to"); recovery lines are nothing
    /// (an IOS / Huawei recovery from a BPDU guard error-down counted as a second BPDU guard
    /// action); an admin-down Junos trap is no failure; OSPF authentication is never a login.
    func testNewFormEdges() {
        let hw = "<188>Sep 23 2026 10:22:00 S5720-ACC-07 %%01ERRDOWN/4/ERRDOWN_DOWNNOTIFY(l)[26]:Notify interface to change status to error-down. (InterfaceName=GigabitEthernet0/0/"
        XCTAssertEqual(Self.kind(hw + "6, Cause=bpdu-protection)"), "stp(SheepLog.STPKind.bpduGuard, port: Optional(\"GigabitEthernet0/0/6\"))")
        XCTAssertEqual(Self.kind(hw + "9, Cause=loopback-detect)"), "stp(SheepLog.STPKind.loop, port: Optional(\"GigabitEthernet0/0/9\"))")
        XCTAssertEqual(Self.kind(hw + "10, Cause=storm-control)"), "stp(SheepLog.STPKind.storm, port: Optional(\"GigabitEthernet0/0/10\"))")
        XCTAssertEqual(Self.kind(hw + "11, Cause=transceiver-power-low)"), Self.link("GigabitEthernet0/0/11", false))
        XCTAssertEqual(Self.kind(hw + "12, Cause=portsec-reachedlimit)"), Self.link("GigabitEthernet0/0/12", false))
        XCTAssertEqual(Self.kind("<188>Sep 23 2026 10:27:00 S5720-ACC-07 %%01ERRDOWN/4/ERRDOWN_DOWNRECOVER(l)[27]:Notify interface to recover state from error-down. (InterfaceName=GigabitEthernet0/0/6, Cause=bpdu-protection, RecoverType=auto recovery)"), "nil")
        XCTAssertEqual(Self.kind("<188>1210: ACC-SW5: Sep 23 10:36:00.000: %PM-4-ERR_RECOVER: Attempting to recover from bpduguard err-disable state on Gi1/0/9"), "nil")
        XCTAssertEqual(Self.kind("<188>1204: ACC-SW5: Sep 23 10:31:00.000: %PM-4-ERR_DISABLE: loopback error detected on Gi1/0/7, putting Gi1/0/7 in err-disable state"),
                       "stp(SheepLog.STPKind.loop, port: Optional(\"Gi1/0/7\"))")
        XCTAssertEqual(Self.kind("<188>1204: ACC-SW5: Sep 23 10:31:00.000: %PM-4-ERR_DISABLE: psecure-violation error detected on Gi1/0/6, putting Gi1/0/6 in err-disable state"),
                       Self.link("Gi1/0/6", false))
        XCTAssertEqual(Self.kind("<189>2026 Sep 23 10:40:00 N9K-LEAF1 %ETHPORT-5-IF_DOWN_ERROR_DISABLED: Interface Ethernet1/13 is down (Error disabled. Reason:BPDUGuard)"),
                       "stp(SheepLog.STPKind.bpduGuard, port: Optional(\"Ethernet1/13\"))")
        XCTAssertEqual(Self.kind("<189>2026 Sep 23 10:40:00 N9K-LEAF1 %ETHPORT-5-IF_DOWN_ADMIN_DOWN: Interface Ethernet1/12 is down (Administratively down)"), "nil")
        XCTAssertEqual(Self.kind("<28>1 2026-09-23T10:40:00.123+07:00 MX204 mib2d 1850 SNMP_TRAP_LINK_DOWN [junos@2636.1.1.1.2.43 snmp-interface-index=\"541\" admin-status=\"down(2)\" operational-status=\"down(2)\" interface-name=\"xe-0/1/1\"]"),
                       "nil", "admin down")
        XCTAssertEqual(Self.kind("<28>1 2026-09-23T10:40:00.123+07:00 EX4300 mib2d 1850 SNMP_TRAP_LINK_DOWN [junos@2636.1.1.1.2.43 snmp-interface-index=\"526\" admin-status=\"up(1)\" operational-status=\"down(2)\" interface-name=\"ge-0/0/12\"]"),
                       Self.link("ge-0/0/12", false), "SD only, no message")
        // OSPF authentication forms, none of them a failed admin login.
        for (line, want) in [
            ("<188>1300: R1: Sep 23 10:37:00.000: %OSPF-4-ERRRCV: Received invalid packet: mismatched authentication type. Input packet specified type 0, we use type 2 from 10.0.12.2, GigabitEthernet0/1", Self.ospfAuth("10.0.12.2")),
            ("<188>1300: R1: Sep 23 10:37:00.000: %OSPF-4-ERRRCV: Received invalid packet: Mismatch Authentication Key - Clear Text from 10.0.12.2, GigabitEthernet0/1", Self.ospfAuth("10.0.12.2")),
            ("<28>Sep 23 10:37:20 frr-core1 ospfd[915]: interface eth1: MD5 auth failed", Self.ospfAuth("interface eth1")),
            ("<28>Sep 23 10:37:20 frr-core1 ospfd[915]: interface eth1:10.0.15.5: MD5 key-id 2 not found", Self.ospfAuth("interface eth1")),
            ("<28>Sep 23 10:37:20 MX204 rpd[1567]: OSPF packet ignored: authentication type mismatch (0) from 10.0.14.6 on intf ge-0/0/1.0 area 0.0.0.0", Self.ospfAuth("10.0.14.6")),
        ] {
            XCTAssertEqual(Self.kind(line), want, line)
        }
        // A neighbor named only by its interface: said so, and the filter names the interface.
        var l = Round13Tests.Lines()
        l.add(0, "frr-core1", "ospfd: interface eth1: MD5 auth failed", sev: 4)
        l.add(30, "frr-core1", "ospfd: interface eth1: MD5 auth failed", sev: 4)
        let r = Round13Tests.analyze(l.entries)
        XCTAssertEqual(r.findings.map(\.title), ["OSPF packets received on interface eth1 on frr-core1 fail authentication: 2 rejected (\(Self.clock(0))–\(Self.clock(30)))."])
        XCTAssertTrue(r.findings.first?.detail.contains("different keys") ?? false, r.findings.first?.detail ?? "")
        XCTAssertEqual(try Self.shown(r.findings.first?.evidence.first?.query ?? "", l.entries), l.entries.map(\.id))
        // An SSH login failure is still one.
        XCTAssertEqual(Self.kind("<86>Sep 23 10:00:00 web01 sshd[1]: Failed password for root from 198.51.100.7 port 51000 ssh2"),
                       "loginFail(ip: Optional(\"198.51.100.7\"), user: Optional(\"root\"))")
    }

    // MARK: - 2. IPv6 addresses by value in free text

    /// 100,000 lines, most of them naming IPv6 addresses of the same /32 in several spellings
    /// (the worst case for the by-value search: its anchor group "db8" is on every such line).
    static func v6Entries(_ n: Int) -> [LogEntry] {
        (0..<n).map { i in
            let text: String
            let k = i / 6
            switch i % 6 {
            case 0: text = "<134>Sep 23 10:15:32 fw\(i % 20) kernel: DROP IN=eth0 SRC=2001:0db8:0000:0000:0000:0000:0000:\(String(k % 4096, radix: 16)) DST=2001:db8::1 LEN=\(60 + i % 900)"
            case 1: text = "<134>Sep 23 10:15:32 r\(i % 20) bgpd[12]: neighbor 2001:DB8:0:0::\(String(k % 4096, radix: 16)) Up"
            case 2: text = "<134>Sep 23 10:15:32 sw\(i % 20) lldpd[9]: neighbor change on port 1/1/\(k % 48) seq \(i)"
            case 3: text = "<134>Sep 23 10:15:32 h\(i % 20) sshd[\(i)]: Failed password for admin from 203.0.113.\(i % 250) port \(40000 + i % 20000) ssh2"
            case 4: text = "<134>Sep 23 10:15:32 fw\(i % 20) ASA-6-302013: Built inbound TCP connection \(i) for outside:2001:db8:\(k % 9)::\(String(k % 777, radix: 16))/443 to inside:10.1.0.\(k % 250)/5\(i % 1000)"
            default: text = "<134>date=2026-09-23 time=10:15:32 devname=\"FGT-\(i % 20)\" devid=\"FGT60F\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"notice\" srcip=2001:db8:\(k % 7)::\(k % 100) dstip=8.8.8.8 action=\"accept\""
            }
            return parsedLine(text, from: "10.1.0.\(i % 20 + 1)", received: at(Double(i) / 1000), id: i + 1)
        }
    }

    static func scanTime(_ q: String, _ entries: [LogEntry], runs: Int = 3) throws -> (seconds: Double, hits: Int) {
        let f = LogFilter(query: try Query.parse(q), source: nil, mask: Set(Severity.allCases))
        var best = Double.infinity, hits = 0
        for _ in 0..<runs {
            let t = Monotonic.now()
            hits = LogStore.scan(entries, base: 0, filter: f)?.hits.count ?? -1
            best = min(best, Monotonic.now() - t)
        }
        return (best, hits)
    }

    /// A bare IPv6 address finds every spelling of it in a line's text (it found the typed and
    /// inet_ntop forms only: a device printing `2001:0db8:0000:…:0002` or `2001:DB8:0:0::2` was
    /// missed) — still as a whole address.
    func testIPv6WordMatchesEverySpelling() throws {
        let lines = [
            "neighbor 2001:db8::2 Down",                              // 1 yes
            "SRC=2001:0db8:0000:0000:0000:0000:0000:0002 DST=x",      // 2 yes: full form
            "peer 2001:DB8:0:0::2 up",                                // 3 yes: upper case, half compressed
            "Built outside:2001:0db8::0002/443 to inside:10.1.0.5/80", // 4 yes: ASA, leading zeros
            "from 2001:db8:0:0:0:0:0:2.",                             // 5 yes: sentence end
            "neighbor 2001:db8::20 Down",                             // 6 no
            "neighbor 2001:db8::2:1 Down",                            // 7 no: another address
            "neighbor 2001:db8:0:0:1::2 Down",                        // 8 no
            "SRC=2001:0db8:0000:0000:0000:0000:0000:0020",            // 9 no
            "id 2db8 port 2",                                         // 10 no: no address
            "x2001:db8:0:0:0:0:0:2 glued",                            // 11 no: a letter before it
            "neighbor 2001:db8::2:",                                  // 12 yes: a trailing colon
        ]
        let entries = lines.enumerated().map { Round16Tests.line($0.element, id: $0.offset + 1) }
        XCTAssertEqual(try Self.shown("2001:db8::2", entries), [1, 2, 3, 4, 5, 12])
        XCTAssertEqual(try Self.shown("2001:0DB8::0:2", entries), [1, 2, 3, 4, 5, 12], "typed another way")
        XCTAssertEqual(try Self.shown("NOT 2001:db8::2", entries), [6, 7, 8, 9, 10, 11])
        // Embedded IPv4 and a trailing zero group.
        let more = ["mapped ::ffff:10.0.0.2 seen", "mapped ::FFFF:a00:2 seen", "prefix 2001:db8:: route", "prefix 2001:0db8:0:0:0:0:0:0 route"]
            .enumerated().map { Round16Tests.line($0.element, id: $0.offset + 1) }
        XCTAssertEqual(try Self.shown("::ffff:10.0.0.2", more), [1, 2])
        // An address ending in "::" reads as a prefix (a route, a subnet): it stays a substring.
        XCTAssertNil(AddressWord("2001:db8::"))
        XCTAssertEqual(try Self.shown("2001:db8::", more), [3])
        // The client report counts the same lines (it uses the same needle).
        XCTAssertTrue(AddressWord("2001:db8::2")!.found(in: "SRC=2001:0db8:0000:0000:0000:0000:0000:0002"))
    }

    /// The by-value search stays within the filter's budget on the worst case: every line
    /// names addresses of the same /32 (measured: 75 ms before, 137 ms after in Debug, Low Power).
    func testIPv6ScanTiming() throws {
        let entries = Self.v6Entries(100_000)
        for q in ["2001:db8::2", "2001:db8::abc", "10.1.0.7", "\"port 1/1/24\"", "fe80::1"] {
            let r = try Self.scanTime(q, entries)
            print("[perf] r17 scan «\(q)» over 100,000 lines: \(Int(r.seconds * 1000)) ms, \(r.hits) hits")
            XCTAssertWithinBudget(r.seconds, 0.3, q)
        }
        XCTAssertEqual(try Self.scanTime("2001:db8::abc", entries, runs: 1).hits,
                       entries.filter { $0.raw.contains("2001:0db8:0000:0000:0000:0000:0000:abc ") || $0.raw.contains("2001:DB8:0:0::abc ") }.count)
    }

    // MARK: - 3. The Troubleshoot pane's filter speaks the grammar

    /// The pane's text filter reads like the Log's: words ANDed (it was one substring, so
    /// "core down" matched nothing), OR / NOT / -word / phrases / regex, whole addresses, and
    /// keys for a finding's parts. Unfinished text is still a substring (no blank list mid-word).
    func testTroubleshootFilterGrammar() {
        let all = Round13Tests.sampleFindings()
        func ids(_ text: String) -> [String] { TroubleshootFilter(text: text).rows(all).map(\.id) }
        XCTAssertEqual(ids(""), ["a", "b", "c", "d", "e", "f", "g"])
        XCTAssertEqual(ids("core-sw1"), ["a", "e", "f"], "a plain word: as before")
        XCTAssertEqual(ids("core-sw1 port"), ["a", "f"], "words are ANDed (was: nothing)")
        XCTAssertEqual(ids("core-sw1 -port"), ["e"])
        XCTAssertEqual(ids("NOT core-sw1"), ["b", "c", "d", "g"])
        XCTAssertEqual(ids("dns OR 10.9.0.5"), ["c", "d"])
        XCTAssertEqual(ids("\"went down\""), ["f"])
        XCTAssertEqual(ids("/port 1\\/1\\/[12] /"), ["a", "b"])
        XCTAssertEqual(ids("10.9.0.5"), ["d"], "an address as a whole")
        XCTAssertEqual(ids("10.9.0.50"), [])
        XCTAssertEqual(ids("10.9"), ["d"], "a prefix stays a substring")
        XCTAssertEqual(ids("sev:problem"), ["a", "d"])
        XCTAssertEqual(ids("sev:>=warning"), ["a", "c", "d", "f"])
        XCTAssertEqual(ids("sev:note device:ACC-SW2"), ["b", "g"])
        XCTAssertEqual(ids("device:core"), ["a", "e", "f"], "a device prefix")
        XCTAssertEqual(ids("device!=CORE-SW1"), ["b", "c", "d", "g"])
        XCTAssertEqual(ids("cat:link -sev:note"), ["a", "f"])
        XCTAssertEqual(ids("rule:x.c"), ["c"])
        XCTAssertEqual(ids("detail:x"), [], "an unknown key is the text key:value")
        XCTAssertEqual(ids("\"on core"), [], "an open quote: the whole text as a substring (no finding says \"on core\")")
        XCTAssertEqual(ids("core-sw1 OR"), [], "unfinished: the substring \"core-sw1 or\"")
        XCTAssertEqual(ids("Port 1/1/1 on"), ["a"])
        // Chips count through the grammar too; a timeline click lifts a text filter that hides it.
        let f = TroubleshootFilter(text: "core-sw1 -port")
        XCTAssertEqual(f.chips(all).map(\.count), [1, 1])
        var r = TroubleshootFilter(text: "core-sw1 -port")
        r.reveal(all[0])
        XCTAssertEqual(r.text, "")
        var keep = TroubleshootFilter(text: "core-sw1 -port")
        keep.reveal(all[4])
        XCTAssertEqual(keep.text, "core-sw1 -port")
        XCTAssertTrue(TroubleshootFilter(text: "sev:problem").scope()?.contains("matching “sev:problem”") ?? false)
    }

    // MARK: - 4. Evidence Show on a paused Log

    /// Pause, then the device's lines arrive (held back), then Troubleshoot's evidence "Show":
    /// the Log resumes and shows them, and the footer says why (it said only "N newer lines are
    /// waiting"). Evidence already in the table leaves the Log paused; so does a Status / Sources
    /// "Show" (its note says to press Resume).
    func testEvidenceShowOnAPausedLog() async throws {
        let app = AppModel.shared
        let logs = app.logs
        logs.clear()
        app.mainPane = .status
        var early = Round13Tests.Lines()
        early.nextID = LogStore.reserveIDs(10)
        early.add(0, "SW-P", "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/3, changed state to down", sev: 3)
        logs.ingest(early.entries)
        await logs.settle()
        logs.paused = true
        var l = Round13Tests.Lines()
        l.nextID = LogStore.reserveIDs(10)
        for k in 0..<3 {
            l.add(Double(k) * 120 + 10, "SW-P", "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/7, changed state to down", sev: 3)
            l.add(Double(k) * 120 + 70, "SW-P", "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/7, changed state to up", sev: 3)
        }
        logs.ingest(l.entries)
        XCTAssertEqual(logs.pausedCount, 6)
        XCTAssertEqual(logs.entries.count, 1)
        // Evidence of the line already shown: the Log stays paused.
        let shownOnly = Evidence(kind: .logLines, label: "1 log line", ids: early.entries.map(\.id), query: "host:\(Round13Tests.Lines.address("SW-P")) word:GigabitEthernet1/0/3")
        XCTAssertEqual(TroubleshootJump.show(shownOnly), .shown)
        XCTAssertTrue(logs.paused)
        XCTAssertNil(logs.resumeNote)
        // Evidence of held lines: resumed, the lines in the table, the footer says why.
        let flap = try XCTUnwrap(Round13Tests.analyze(early.entries + l.entries).findings.first { $0.rule == "link.flap" })
        let e = try XCTUnwrap(flap.evidence.first)
        app.mainPane = .status
        TroubleshootModel.shared.show(e)
        XCTAssertEqual(app.mainPane, .log)
        XCTAssertFalse(logs.paused)
        await logs.settle()
        XCTAssertEqual(Set(logs.visible.map(\.id)), Set(l.entries.map(\.id)))
        let footer = LogView.footerText(store: logs, diskLogging: false)
        XCTAssertTrue(footer.contains("Resumed to show the finding’s lines (they arrived while the Log was paused)"), footer)
        XCTAssertEqual(LogView.noMatchText(entries: 7, query: true, source: nil, masked: false, held: logs.paused ? logs.pausedCount : 0),
                       "None of the 7 lines match the filter.")
        // Pause again: the note goes.
        logs.paused = true
        XCTAssertNil(logs.resumeNote)
        XCTAssertFalse(LogView.footerText(store: logs, diskLogging: false).contains("Resumed"))
        // Status "Show" of a source whose lines are held: stays paused, says to press Resume.
        var later = Round13Tests.Lines()
        later.nextID = LogStore.reserveIDs(5)
        later.add(900, "SW-Q", "hello", sev: 6)
        logs.ingest(later.entries)
        logs.showSource(later.entries[0].sourceAddress)
        XCTAssertTrue(logs.paused)
        logs.paused = false
    }

    // MARK: - 5. "Since change" after sysUpTime passed 497 days

    /// sysUpTime below ifLastChange (the uptime counter started again since the change): the age
    /// is computed modulo 2^32 ticks and marked as the least it can be (it was blank, and the
    /// tooltip said sysUpTime had not been read).
    func testSinceChangeAfterAnUptimeWrap() {
        let entry = OID.ifTable.appending(1)
        func row(lastChange: UInt32, up: UInt32?) -> InterfaceRow? {
            SNMPTestModel.joinInterfaces(ifTable: [
                VarBind(entry.appending(2).appending(1), .octetString(Data("xe-0/0/1".utf8))),
                VarBind(entry.appending(9).appending(1), .timeTicks(lastChange)),
            ], ifXTable: [], sysUpTime: up).first
        }
        // Changed 1,000 s before the wrap; now 2 days after it.
        let lastChange: UInt32 = 4_294_967_295 - 100_000
        let up: UInt32 = 2 * 86_400 * 100
        let r = row(lastChange: lastChange, up: up)
        XCTAssertEqual(r?.sinceChange, 100_000 + 1 + up)
        XCTAssertEqual(r?.sinceChangeWrapped, true)
        XCTAssertEqual(r.map(SNMPTestView.changeText), "≥ 2d 00h")
        let help = r.map(SNMPTestView.changeHelp) ?? ""
        XCTAssertTrue(help.hasPrefix("Last state change at least 2d 00:16:40 ago"), help)
        XCTAssertTrue(help.contains("or 497 days (or a multiple) more"), help)
        // No wrap: as before.
        let plain = row(lastChange: 3_500, up: 200 * 86_400 * 100)
        XCTAssertEqual(plain?.sinceChangeWrapped, false)
        XCTAssertEqual(plain.map(SNMPTestView.changeText), "199d 23h")
        XCTAssertFalse(plain.map(SNMPTestView.changeHelp)?.contains("at least") ?? true)
        // The Troubleshoot snapshot's uptime read back from a row is the uptime (mod 2^32).
        let snap = TroubleshootModel.snapshot(host: "sw", rows: [], interfaces: [r!], taken: Self.at(0))
        XCTAssertEqual(snap.sysUpTime, up)
        // Sorting puts the wrapped (old) change among the long ones, not unknown-last.
        XCTAssertEqual(r?.sinceChangeSort, 100_000 + 1 + up)
    }

    // MARK: - 6. An IPv6-only Mac

    /// With no IPv4 address but a global IPv6 one, Status points devices at the IPv6 address
    /// (bracketed with its port, Copy gives the address alone) — it said "no IPv4 address" and
    /// offered no Copy although the listeners are dual-stack; the Log's empty table names it too.
    func testIPv6OnlyMacPointsDevicesAtItsIPv6Address() async throws {
        let v6 = [(interface: "en0", address: "2001:db8:5::10")]
        let v4 = [(interface: "en0", address: "10.1.0.5")]
        XCTAssertEqual(HostAddresses.choose(v4: [], v6: v6).map(\.address), ["2001:db8:5::10"])
        XCTAssertEqual(HostAddresses.choose(v4: v4, v6: v6).map(\.address), ["10.1.0.5"], "IPv4 first when there is one")
        XCTAssertEqual(HostAddresses.choose(v4: [], v6: []).count, 0)
        XCTAssertEqual(HostAddresses.hostPort("2001:db8:5::10", 514), "[2001:db8:5::10]:514")
        XCTAssertEqual(HostAddresses.hostPort("10.1.0.5", 514), "10.1.0.5:514")
        func rows(_ a: String?, _ udp: UInt16, _ tcp: UInt16, _ trap: UInt16) -> [String] {
            StatusView.pointRows(address: a, udp: udp, tcp: tcp, trapPort: trap, mirror: "m").map { "\($0.key)=\($0.value)|\($0.copy ?? "-")" }
        }
        XCTAssertEqual(rows("2001:db8:5::10", 514, 514, 162), ["Syslog server=[2001:db8:5::10]:514  (udp or tcp)|2001:db8:5::10",
                                                              "SNMP trap receiver=[2001:db8:5::10]:162|2001:db8:5::10", "Mirror / SPAN port=m|-"])
        XCTAssertEqual(rows("2001:db8:5::10", 5514, 6514, 162)[0], "Syslog server=udp [2001:db8:5::10]:5514  ·  tcp [2001:db8:5::10]:6514|2001:db8:5::10")
        XCTAssertEqual(StatusView.noLinesNote(address: "2001:db8:5::10", udp: 514, tcp: 514),
                       "No lines yet. Point your devices’ syslog at 2001:db8:5::10, udp 514, then open Log.")
        // What the listeners really accept: an IPv6 datagram to the dual-stack UDP socket.
        let app = AppModel.shared
        savedSettings = app.settings
        app.logs.clear()
        let port = UInt16(46_000 + Int.random(in: 0..<900))
        app.settings.syslogUDPPort = port
        app.settings.syslogTCPPort = 0
        app.startSyslog()
        XCTAssertTrue(app.syslog.isRunning, app.syslog.lastError ?? "")
        let fd = socket(AF_INET6, SOCK_DGRAM, 0)
        XCTAssertGreaterThanOrEqual(fd, 0)
        defer { close(fd) }
        var sa = sockaddr_in6()
        sa.sin6_family = sa_family_t(AF_INET6)
        sa.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        sa.sin6_port = port.bigEndian
        sa.sin6_addr = in6addr_loopback
        let msg = "<134>Sep 23 10:15:32 v6host app: over IPv6"
        let sent = msg.withCString { p in
            withUnsafePointer(to: &sa) { sp in
                sp.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, p, strlen(p), 0, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) }
            }
        }
        XCTAssertEqual(sent, msg.utf8.count)
        await waitUntil { app.logs.entries.contains { $0.message == "over IPv6" } }
        XCTAssertEqual(app.logs.entries.first { $0.message == "over IPv6" }?.sourceAddress, "::1")
    }

    // MARK: - 7. Apply ports that moves only the UDP port, under a TCP flood

    /// A TCP client connected to 127.0.0.1:`port` (IPv4), sending on its own thread.
    nonisolated final class FloodClient: @unchecked Sendable {
        let fd: Int32
        private let stopFlag = Atomic<Bool>(false)
        let sent = Atomic<Int>(0)
        let failed = Atomic<Bool>(false)
        private let done = DispatchSemaphore(value: 0)

        init?(port: UInt16) {
            let s = socket(AF_INET, SOCK_STREAM, 0)
            guard s >= 0 else { return nil }
            var sa = sockaddr_in()
            sa.sin_family = sa_family_t(AF_INET)
            sa.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            sa.sin_port = port.bigEndian
            sa.sin_addr.s_addr = inet_addr("127.0.0.1")
            let r = withUnsafePointer(to: &sa) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
            guard r == 0 else { close(s); return nil }
            var one: Int32 = 1
            setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            fd = s
        }

        func start(tag: Int) {
            Thread.detachNewThread { [self] in
                var n = 0
                while !stopFlag.load(ordering: .relaxed) {
                    let line = "<134>Sep 23 10:15:32 flood\(tag) app: tcp line \(n)\n"
                    let w = line.withCString { send(fd, $0, strlen($0), 0) }
                    if w <= 0 { failed.store(true, ordering: .relaxed); break }
                    n += 1
                    sent.store(n, ordering: .relaxed)
                    if n % 4 == 0 { usleep(1_000) }            // ~3,000 lines/s each: a flood the store keeps whole
                }
                done.signal()
            }
        }

        func stop() {
            stopFlag.store(true, ordering: .relaxed)
            _ = done.wait(timeout: .now() + 5)
            close(fd)
        }
    }

    static func sendUDP(_ text: String, port: UInt16) {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        defer { close(fd) }
        var sa = sockaddr_in()
        sa.sin_family = sa_family_t(AF_INET)
        sa.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        sa.sin_port = port.bigEndian
        sa.sin_addr.s_addr = inet_addr("127.0.0.1")
        _ = text.withCString { p in
            withUnsafePointer(to: &sa) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, p, strlen(p), 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        }
    }

    /// Eight TCP devices flooding while Settings → Apply ports moves the syslog UDP port only:
    /// the TCP clients stay connected (stop + start of the whole listener closed them all, and
    /// the lines they had in flight were lost), the new UDP port receives, the old one is free
    /// again. A UDP move that cannot bind keeps the old UDP port, and TCP still untouched.
    func testApplyPortsMovingOnlyUDPKeepsTCPClients() async throws {
        let app = AppModel.shared
        savedSettings = app.settings
        app.logs.clear()
        app.logs.limit = 2_000_000
        let base = UInt16(47_000 + Int.random(in: 0..<800))
        let udp1 = base, udp2 = base + 1, tcp = base + 2
        app.settings.syslogUDPPort = udp1
        app.settings.syslogTCPPort = tcp
        app.startSyslog()
        XCTAssertTrue(app.syslog.isRunning, app.syslog.lastError ?? "")
        let clients = (0..<8).compactMap { _ in FloodClient(port: tcp) }
        XCTAssertEqual(clients.count, 8)
        for (k, c) in clients.enumerated() { c.start(tag: k) }
        await waitUntil { app.syslog.tcpClients == 8 && app.logs.totalReceived > 5_000 }
        XCTAssertEqual(app.syslog.tcpClients, 8)
        // Move UDP only.
        app.settings.syslogUDPPort = udp2
        XCTAssertTrue(app.listenerPortsChanged)
        app.restartListeners()
        XCTAssertNil(app.lastError, app.lastError ?? "")
        XCTAssertEqual([app.syslog.udpPort, app.syslog.tcpPort], [udp2, tcp])
        XCTAssertFalse(app.listenerPortsChanged)
        let before = app.logs.totalReceived
        await spin(300)
        XCTAssertTrue(clients.allSatisfy { !$0.failed.load(ordering: .relaxed) }, "a TCP client was disconnected")
        XCTAssertEqual(app.syslog.tcpClients, 8)
        XCTAssertGreaterThan(app.logs.totalReceived, before, "TCP lines keep arriving")
        Self.sendUDP("<134>Sep 23 10:15:32 u2 app: on the new UDP port", port: udp2)
        await waitUntil { app.logs.entries.contains { $0.message == "on the new UDP port" } }
        XCTAssertTrue(app.logs.entries.contains { $0.message == "on the new UDP port" })
        // The old UDP port is free again (the trap receiver or another program may take it).
        switch SocketFactory.bind(type: SOCK_DGRAM, port: udp1) {
        case .success(let fd): close(fd)
        case .failure(let e): XCTFail("old UDP port still held: \(e.message(transport: "UDP", port: udp1))")
        }
        // A UDP port that cannot be bound: stays on udp2, TCP untouched, one sheet.
        let blocker = try XCTUnwrap(try? SocketFactory.bind(type: SOCK_DGRAM, port: udp1).get())
        defer { close(blocker) }
        app.settings.syslogUDPPort = udp1
        app.restartListeners()
        XCTAssertEqual([app.syslog.udpPort, app.syslog.tcpPort], [udp2, tcp])
        XCTAssertEqual(app.lastError, "Syslog could not move to UDP \(udp1), so it stays on UDP \(udp2) (TCP \(tcp) and its clients were not touched).")
        app.dismissAllErrors()
        await spin(200)
        XCTAssertTrue(clients.allSatisfy { !$0.failed.load(ordering: .relaxed) })
        XCTAssertEqual(app.syslog.tcpClients, 8)
        // Moving TCP too restarts the listener (the clients reconnect to the new port themselves).
        for c in clients { c.stop() }
        let sentTotal = clients.reduce(0) { $0 + $1.sent.load(ordering: .relaxed) }
        await waitUntil(10) { app.logs.entries.filter { $0.hostname.hasPrefix("flood") }.count >= sentTotal }
        XCTAssertEqual(app.logs.entries.filter { $0.hostname.hasPrefix("flood") }.count, sentTotal, "every TCP line sent arrived")
    }

    // MARK: - 8. Sweep: sequences nobody had scripted

    /// Sequence A: Pause → a relayed FortiGate's lines arrive (read as "Other") → the user sets
    /// its vendor override → Troubleshoot analyses → Resume. The ring was re-parsed at once but
    /// the held lines only at Resume, so the analysis read the port-down as nothing.
    func testOverrideWhilePausedReachesTroubleshootBeforeResume() async throws {
        let app = AppModel.shared
        let logs = app.logs
        logs.clear()
        app.mainPane = .status
        let address = "10.93.1.1"
        defer { app.setVendorOverride(nil, for: address) }
        logs.paused = true
        // No devid / logid: detection leaves it "Other" (the generic key=value fields only).
        let text = "<188>date=2026-09-23 time=10:30:00 devname=\"FGT-RELAY\" type=\"event\" subtype=\"system\" level=\"warning\" vd=\"root\" logdesc=\"Interface status changed\" action=\"interface-stat-change\" status=\"DOWN\" msg=\"Interface port9 changed status to DOWN.\""
        let line = parsedLine(text, from: address, received: Self.at(0), id: LogStore.reserveIDs(1))
        XCTAssertEqual(line.vendor, .unknown)
        logs.ingest([line])
        XCTAssertEqual(logs.pausedCount, 1)
        func analysedRules() -> [String] {
            var input = TroubleshootModel.shared.currentInput()
            input.now = Self.at(900)
            input.takeHeld()
            return FindingRules.analyze(input).findings.filter { $0.source == .logs }.map(\.rule)
        }
        XCTAssertEqual(analysedRules(), [], "Other: no link event")
        app.setVendorOverride(.fortigate, for: address)
        XCTAssertEqual(analysedRules(), ["link.down"], "the override applies to the held line before Resume")
        XCTAssertEqual(logs.heldEntries.first?.vendor, .fortigate)
        XCTAssertEqual(logs.sources.first { $0.address == address }.map { _ in true }, true)
        logs.paused = false
        await logs.settle()
        XCTAssertEqual(logs.entries.map(\.vendor), [.fortigate], "resumed once, as the override reads it")
        XCTAssertEqual(logs.entries.count, 1)
    }

    /// Sequence B: Pause → six lines of a flapping port held → the buffer limit lowered to 2 →
    /// Troubleshoot's evidence Show. The Show resumes the Log; only two of the six fit the ring,
    /// so the outcome says "2 of 6" (it said the evidence was all shown: it counted the held
    /// lines as present before the resume evicted them).
    func testEvidenceShowThatResumesIntoASmallBuffer() async throws {
        let app = AppModel.shared
        let logs = app.logs
        logs.clear()
        app.mainPane = .status
        logs.paused = true
        var l = Round13Tests.Lines()
        l.nextID = LogStore.reserveIDs(10)
        for k in 0..<3 {
            l.add(Double(k) * 120, "SW-B", "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/9, changed state to down", sev: 3)
            l.add(Double(k) * 120 + 60, "SW-B", "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/9, changed state to up", sev: 3)
        }
        logs.ingest(l.entries)
        logs.limit = 2
        let e = try XCTUnwrap(Round13Tests.analyze(l.entries).findings.first { $0.rule == "link.flap" }?.evidence.first)
        XCTAssertEqual(TroubleshootJump.show(e), .partly(present: 2, of: 6))
        XCTAssertFalse(logs.paused)
        XCTAssertEqual(app.mainPane, .log)
        await logs.settle()
        XCTAssertEqual(logs.visible.map(\.id), Array(l.entries.map(\.id).suffix(2)))
        // Limit 1 line and evidence that is all gone once resumed: nothing opened, a note.
        logs.clear()
        app.mainPane = .status
        logs.paused = true
        logs.ingest(l.entries.map { parsedLine($0.raw, from: $0.sourceAddress, received: $0.received, id: $0.id + 100) })
        logs.limit = 1
        let gone = Evidence(kind: .logLines, label: "2 log lines", ids: [l.entries[0].id + 100, l.entries[1].id + 100], query: "host:\(l.entries[0].sourceAddress)")
        let outcome = TroubleshootJump.show(gone)
        if case .gone = outcome {} else { XCTFail("\(outcome)") }
        XCTAssertEqual(app.mainPane, .status)
    }

    /// Sequence C: a client report for an IPv6 client whose devices print the address in full
    /// form → its log link → the Log pane: the report counts and the Log shows the same lines
    /// (both by value now; the Log's filter found only the typed spelling).
    func testIPv6ClientReportToLogShowsWhatItCounted() async throws {
        let app = AppModel.shared
        let logs = app.logs
        logs.clear()
        app.mainPane = .status
        let texts = ["dhcp6 lease 2001:db8:20::15 to 02:00:5e:14:00:21",
                     "fw deny src=2001:0DB8:0020:0000:0000:0000:0000:0015 dst=2001:db8::53",
                     "fw deny src=2001:db8:20::150 dst=2001:db8::53",
                     "nd: neighbor 2001:db8:20:0:0:0:0:15 reachable"]
        let first = LogStore.reserveIDs(texts.count)
        let entries = texts.enumerated().map { Round16Tests.line($1, id: first + $0) }
        logs.ingest(entries)
        await logs.settle()
        var input = TroubleshootInput()
        input.entries = logs.entries
        input.now = Self.at(60)
        let r = try XCTUnwrap(ClientReport.build("2001:db8:20::15", input: input, findings: []))
        XCTAssertEqual(r.logIDs.sorted(), [first, first + 1, first + 3])
        let e = Evidence(kind: .logLines, label: "3 log lines", ids: r.logIDs, query: r.logQuery)
        XCTAssertEqual(TroubleshootJump.show(e), .shown)
        await logs.settle()
        XCTAssertEqual(Set(logs.visible.map(\.id)), Set(r.logIDs), "`\(r.logQuery)`")
    }
}
