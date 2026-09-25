import AppKit
import Darwin
import SwiftUI
import XCTest
@testable import SheepLog

/// Round 16: evidence and Show filters that named an address or a port as a substring, link-state
/// and routing forms still unread (Linux `ip monitor`, err-disable, BGP MD5), sysUpTime past 497
/// days and 32-bit rates of one walk, a log disk ejected mid-write, a cold pass over the Status
/// and Settings panes and the sidebar's counts — and a sweep.
@MainActor
final class Round16Tests: XCTestCase {
    private var windows: [NSWindow] = []
    private var disks: [RAMDisk] = []
    private var cleanup: [URL] = []
    private var savedSettings: AppSettings?

    override func tearDown() async throws {
        for w in windows { w.contentView = nil; w.close() }
        windows = []
        for d in disks { d.detach() }
        disks = []
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
        app.packets.limit = 200_000
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
    static let bsd = Round13Tests.bsd

    private func spin(_ ms: Int = 30) async { try? await Task.sleep(for: .milliseconds(ms)) }

    private func waitUntil(_ timeout: Double = 5, _ condition: () -> Bool) async {
        let end = Date().addingTimeInterval(timeout)
        while !condition(), Date() < end { await spin(10) }
    }

    static func matches(_ q: String, _ e: LogEntry) throws -> Bool {
        LogFilter(query: try Query.parse(q), source: nil, mask: Set(Severity.allCases)).matches(e)
    }

    static func shown(_ q: String, _ entries: [LogEntry]) throws -> [Int] {
        let f = LogFilter(query: try Query.parse(q), source: nil, mask: Set(Severity.allCases))
        return entries.filter { f.matches($0) }.map(\.id)
    }

    static func line(_ text: String, id: Int, from: String = "10.9.9.9") -> LogEntry {
        parsedLine("<134>1 - R1 app - - - " + text, from: from, received: at(Double(id)), id: id)
    }

    static func kind(_ line: String) -> String {
        LineClassifier.line(parsedLine(line, from: "10.9.9.9")).map { "\($0)" } ?? "nil"
    }

    static func packets(_ frames: [[UInt8]]) -> [Packet] {
        frames.enumerated().map { i, f in TroubleshootFixture.packet(f, at: at(Double(i)), id: i + 1, start: t0) }
    }

    private func tempDir() throws -> URL {
        let d = FileManager.default.temporaryDirectory.appending(path: "SheepLogR16-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        cleanup.append(d)
        return d
    }

    // MARK: - 1. Whole addresses and ports in filters

    /// A bare IPv4 / IPv6 literal is that address as a whole: `10.0.0.2` was a substring and
    /// matched 10.0.0.20–29, 110.0.0.2 and 10.0.0.2.5; `10.0.0.` stays a prefix, `raw:` the
    /// substring, `host:` exact as before.
    func testBareAddressIsAWholeAddress() throws {
        let texts = [
            "neighbor 10.0.0.2 Down",                  // 1 yes
            "neighbor 10.0.0.20 Down",                 // 2 no (was yes)
            "neighbor 110.0.0.2 Down",                 // 3 no (was yes)
            "from 10.0.0.2.",                          // 4 yes: the sentence's full stop
            "Deny tcp src inside:10.0.0.2/51234",      // 5 yes: ASA
            "peer 10.0.0.2:179 closed",                // 6 yes
            "oid ipAdEntAddr.10.0.0.2.5",              // 7 no: a longer dotted number
            "[10.0.0.2] ok",                           // 8 yes
            "neighbor 2001:db8::2 Down",               // 9 yes for 2001:db8::2
            "neighbor 2001:db8::20 Down",              // 10 no
            "neighbor 2001:db8::2:1 Down",             // 11 no: another address
            "outside:2001:db8::2/443",                 // 12 yes: ASA IPv6
            "neighbor 2001:DB8:0:0::2 Down",           // 13 yes as typed, and by value
            "link-local fe80::1%en0 up",               // 14 yes for fe80::1
            "link-local fe80::10 up",                  // 15 no
        ]
        let entries = texts.enumerated().map { Self.line($1, id: $0 + 1) }
        XCTAssertEqual(try Self.shown("10.0.0.2", entries), [1, 4, 5, 6, 8])
        XCTAssertEqual(try Self.shown("\"10.0.0.2\"", entries), [1, 4, 5, 6, 8], "a quoted address is the same term")
        XCTAssertEqual(try Self.shown("-10.0.0.2", entries).filter { $0 <= 8 }, [2, 3, 7])
        XCTAssertEqual(try Self.shown("10.0.0.", entries), [1, 2, 3, 4, 5, 6, 7, 8], "a prefix stays a substring")
        XCTAssertEqual(try Self.shown("raw:10.0.0.2", entries), [1, 2, 3, 4, 5, 6, 7, 8], "raw: is the substring")
        XCTAssertEqual(try Self.shown("2001:db8::2", entries), [9, 12])
        // Typed in a longer spelling: that spelling and inet_ntop's (the one devices print).
        XCTAssertEqual(try Self.shown("2001:DB8:0:0::2", entries), [9, 12, 13])
        XCTAssertEqual(try Self.shown("fe80::1", entries), [14], "an address that starts with a letter (lexed as key:value)")
        XCTAssertEqual(try Self.shown("-fe80::1", entries).contains(14), false)
        // host: keeps its exact / prefix forms.
        let hosts = [parsedLine("<13>a", from: "10.1.0.1", id: 1), parsedLine("<13>b", from: "10.1.0.10", id: 2)]
        XCTAssertEqual(try Self.shown("host:10.1.0.1", hosts), [1])
        XCTAssertEqual(try Self.shown("host:=10.1.0.1", hosts), [1])
        XCTAssertEqual(try Self.shown("host:10.1.0.", hosts), [1, 2])
        // A trap line as a bare word searches it.
        XCTAssertTrue(try Self.matches("10.0.0.2", parsedLine("<13>linkDown ipAdEntAddr=10.0.0.2", from: "10.1.0.5", transport: .trap, id: 3)))
        XCTAssertFalse(try Self.matches("10.0.0.2", parsedLine("<13>linkDown ipAdEntAddr=10.0.0.23", from: "10.1.0.5", transport: .trap, id: 4)))
    }

    /// `word:x` — x as a whole word: a port's evidence (`word:Gi1/0/1`) no longer shows Gi1/0/10–19
    /// or the sub-interface Gi1/0/1.100, `word:ether1` not ether10.
    func testWordKeyIsAWholeWord() throws {
        let texts = ["Interface Gi1/0/1, changed state to down",       // 1
                     "Interface Gi1/0/10, changed state to down",      // 2
                     "Interface Gi1/0/1.100, changed state to down",   // 3
                     "ether1 link down",                               // 4
                     "ether10 link down",                              // 5
                     "Interface ethernet 1/1/5, state down",           // 6
                     "Interface ethernet 1/1/50, state down",          // 7
                     "port 3 status changed from 1Gfdx to down",       // 8
                     "port 30 status changed from 1Gfdx to down",      // 9
                     "ifName=Gi1/0/1)"]                                 // 10
        let e = texts.enumerated().map { Self.line($1, id: $0 + 1) }
        XCTAssertEqual(try Self.shown("word:Gi1/0/1", e), [1, 10])
        XCTAssertEqual(try Self.shown("Gi1/0/1", e), [1, 2, 3, 10], "a bare word is still a substring")
        XCTAssertEqual(try Self.shown("word:ether1", e), [4])
        XCTAssertEqual(try Self.shown("word:\"ethernet 1/1/5\"", e), [6])
        XCTAssertEqual(try Self.shown("word:\"port 3\"", e), [8])
        XCTAssertEqual(try Self.shown("-word:ether1", e).contains(4), false)
        XCTAssertEqual(try Self.shown("word:GI1/0/1", e), [1, 10], "case-insensitive")
    }

    /// Every evidence builder that names an address or a port, over two of each whose names
    /// overlap as text: each finding's filter shows its own lines and none of the other's.
    func testEvidenceFiltersNameOneAddressOrPort() async throws {
        var l = Round13Tests.Lines()
        // Routing neighbors 10.0.0.2 and 10.0.0.20, both down for good.
        l.add(0, "R1", "OSPF neighbor 10.0.0.2 changed to Down: dead timer expired", sev: 3)
        l.add(1, "R1", "OSPF neighbor 10.0.0.20 changed to Down: dead timer expired", sev: 3)
        l.add(2, "R1", "BGP %ADJCHANGE: neighbor 2001:db8::2 in vrf default Down Peer closed the session", sev: 3)
        l.add(3, "R1", "BGP %ADJCHANGE: neighbor 2001:db8::20 in vrf default Down Peer closed the session", sev: 3)
        // Peers that never come up: 10.0.0.9 and 10.0.0.90.
        for (k, t) in [0.0, 60, 120].enumerated() {
            l.add(10 + t, "R1", "BGP peer 10.0.0.9 changed state from \(k % 2 == 0 ? "Idle to Connect" : "Connect to Idle")", sev: 5)
            l.add(11 + t, "R1", "BGP peer 10.0.0.90 changed state from \(k % 2 == 0 ? "Idle to Connect" : "Connect to Idle")", sev: 5)
        }
        // MD5 failures from 10.0.0.3 and 10.0.0.30.
        l.add(200, "R1", "%TCP-6-BADAUTH: Invalid MD5 digest from 10.0.0.3(179) to 10.0.0.1(11003) tableid - 0", sev: 6)
        l.add(201, "R1", "%TCP-6-BADAUTH: Invalid MD5 digest from 10.0.0.30(179) to 10.0.0.1(11004) tableid - 0", sev: 6)
        // Failed logins from 198.51.100.7 and 198.51.100.70.
        for k in 0..<2 {
            l.add(300 + Double(k), "web01", "Failed password for root from 198.51.100.7 port 5100\(k) ssh2", sev: 4)
            l.add(310 + Double(k), "web01", "Failed password for root from 198.51.100.70 port 5200\(k) ssh2", sev: 4)
        }
        // Ports Gi1/0/1 and Gi1/0/10 flapping.
        for k in 0..<3 {
            for p in ["1", "10"] {
                l.add(400 + Double(k) * 120, "SW1", "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/\(p), changed state to down", sev: 3)
                l.add(460 + Double(k) * 120, "SW1", "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/\(p), changed state to up", sev: 3)
            }
        }
        let r = Round13Tests.analyze(l.entries)
        let byID = Dictionary(uniqueKeysWithValues: l.entries.map { ($0.id, $0) })
        var checked = 0
        for f in r.findings {
            for e in f.evidence where e.kind == .logLines {
                let shown = Set(try Self.shown(e.query, l.entries))
                XCTAssertEqual(shown, Set(e.ids), "\(f.rule) “\(f.title)”: `\(e.query)` shows \(shown.subtracting(e.ids).compactMap { byID[$0]?.message })")
                checked += 1
            }
        }
        XCTAssertEqual(Set(r.findings.map(\.rule)), ["routing.neighbor", "routing.notUp", "routing.authFail", "login.failures", "link.flap"],
                       r.findings.map(\.title).description)
        XCTAssertEqual(checked, 12)
    }

    /// The client report's log link names every spelling of the MAC it searched (Cisco's dotted
    /// quads, Windows' dashes): its "Show" hid the lines it counted. And the address as a whole.
    func testClientReportLinkShowsWhatItCounted() throws {
        var l = Round13Tests.Lines()
        l.add(0, "SW1", "MAC 0200.5e14.0021 moved from Gi1/0/3 to Gi1/0/4")
        l.add(1, "DHCP", "DHCPACK on 10.1.30.1 to 02-00-5e-14-00-21 via eth0")
        l.add(2, "AP1", "client 02:00:5e:14:00:21 associated")
        l.add(3, "FW", "session from 10.1.30.14 allowed")
        var input = TroubleshootInput()
        input.entries = l.entries
        input.packets = Round13Tests.packets([Round13Tests.arp(0, request: false, mac: "02:00:5e:14:00:21", ip: "10.1.30.1", target: "10.1.30.254")])
        input.now = Self.at(60)
        let report = try XCTUnwrap(ClientReport.build("10.1.30.1", input: input, findings: []))
        XCTAssertEqual(Set(report.logIDs), [1, 2, 3])
        XCTAssertEqual(Set(try Self.shown(report.logEvidence.query, l.entries)), [1, 2, 3], report.logEvidence.query)
    }

    /// The report counts lines by the same rule its Show filter shows them by — over lines where
    /// the two used to disagree (a MAC spelling glued into longer hex was shown and not counted;
    /// "x.10.1.30.1", ASA's "outside:2001:db8::1" counted by one rule only).
    func testClientReportCountsWhatItsFilterShows() throws {
        let texts = ["client 02005e1400210 seen",            // glued hex: neither
                     "engine 8000000903002005e140021ff",      // inside a hex blob: neither
                     "host x.10.1.30.1 up",                   // yes
                     "fw outside:2001:db8::1/443 deny",       // v6 client: yes
                     "fw outside:2001:db8::10/443 deny",      // no
                     "mac=02:00:5e:14:00:21, vlan 20",        // yes
                     "ipv4 10.1.30.1.5 oid",                  // no
                     "Cisco 0200.5e14.0021 Gi1/0/3"]          // yes
        let entries = texts.enumerated().map { Self.line($1, id: $0 + 1) }
        for client in ["10.1.30.1", "2001:db8::1", "02:00:5e:14:00:21"] {
            var input = TroubleshootInput()
            input.entries = entries
            input.now = Self.at(60)
            let r = try XCTUnwrap(ClientReport.build(client, input: input, findings: []))
            XCTAssertEqual(Set(try Self.shown(r.logQuery, entries)), Set(r.logIDs), "\(client): `\(r.logQuery)`")
        }
        var input = TroubleshootInput()
        input.entries = entries
        XCTAssertEqual(ClientReport.build("02:00:5e:14:00:21", input: input, findings: [])?.logIDs.sorted(), [6, 8])
        XCTAssertEqual(ClientReport.build("10.1.30.1", input: input, findings: [])?.logIDs.sorted(), [3])
        XCTAssertEqual(ClientReport.build("2001:db8::1", input: input, findings: [])?.logIDs.sorted(), [4])
    }

    /// Packets: a bare address is the packet's source / destination or that address in Info (ARP
    /// "Who has 10.0.0.2?") — the ARP evidence fallback `proto:arp 10.0.0.2` took 10.0.0.20's.
    /// The conversation filters (Packets' context menu, Flows' Show packets past 256 frames) keep
    /// each address with its own port: A:1000 ⇄ B:80 is not A:80 ⇄ B:1000.
    func testPacketFiltersNameOneAddressAndOneConversation() throws {
        let pk = Self.packets([
            TroubleshootFixture.arp(request: true, senderMAC: "02:00:00:00:00:01", senderIP: "10.0.0.1", targetIP: "10.0.0.2", vlan: nil),
            TroubleshootFixture.arp(request: true, senderMAC: "02:00:00:00:00:01", senderIP: "10.0.0.1", targetIP: "10.0.0.20", vlan: nil),
            Array(PacketFixture.tcp4(src: "10.0.0.5", dst: "10.0.0.6", 1000, 80, flags: 0x02)),
            Array(PacketFixture.tcp4(src: "10.0.0.6", dst: "10.0.0.5", 80, 1000, flags: 0x12)),
            Array(PacketFixture.tcp4(src: "10.0.0.5", dst: "10.0.0.6", 80, 1000, flags: 0x02)),   // ports swapped
            Array(PacketFixture.tcp4(src: "10.0.0.50", dst: "10.0.0.6", 1000, 80, flags: 0x02)),
        ])
        func shown(_ q: String) throws -> [Int] {
            let m = PacketMatcher(try Query.parse(q))
            return pk.filter { m.matches($0) }.map(\.id)
        }
        XCTAssertEqual(try shown("proto:arp 10.0.0.2"), [1])
        XCTAssertEqual(try shown("10.0.0.5"), [3, 4, 5])
        XCTAssertEqual(try shown("info:10.0.0.2"), [1, 2], "info: is the substring")
        let conv = PacketTableController.conversationFilter(pk[2].decoded)
        XCTAssertEqual(try shown(conv), [3, 4], conv)
        // Flows: past 256 frames the range plus the conversation.
        let flow = try XCTUnwrap(TCPFlowAnalyzer.analyze(pk).first { $0.key == FlowKey("10.0.0.5", 1000, "10.0.0.6", 80, proto: 6) })
        let f = FlowView.packetFilter(Array(1...300), flow: flow)
        XCTAssertTrue(f.hasPrefix("frame:>=1 frame:<=300 proto:tcp "), f)
        XCTAssertEqual(try shown(f), [3, 4], f)
        // A host talking to itself: only the pair of ports.
        let lo = Self.packets([Array(PacketFixture.tcp4(src: "127.0.0.1", dst: "127.0.0.1", 5000, 6000, flags: 0x02)),
                               Array(PacketFixture.tcp4(src: "127.0.0.1", dst: "127.0.0.1", 5000, 7000, flags: 0x02))])
        let m = PacketMatcher(try Query.parse(PacketTableController.conversationFilter(lo[0].decoded)))
        XCTAssertEqual(lo.filter { m.matches($0) }.map(\.id), [1])
    }

    /// The Log grid's right-click "Filter this host" on 10.0.0.2's line, with 10.0.0.20's lines
    /// in the table: only 10.0.0.2's stay (and Exclude this host keeps 10.0.0.20's).
    func testLogContextMenuFilterThisHost() async throws {
        let store = LogStore()
        let lines = (0..<6).map { k in
            parsedLine("<13>Sep 23 10:00:0\(k) sw\(k % 2) app: line \(k)", from: k % 2 == 0 ? "10.0.0.2" : "10.0.0.20",
                       received: Self.at(Double(k)), id: k + 1)
        }
        store.ingest(lines)
        let box = SelectionBoxR16()
        let binding = Binding<Int?>(get: { box.id }, set: { box.id = $0 })
        let c = LogTableView.Coordinator(store: store)
        c.parent = LogTableView(store: store, selectedID: binding)
        let scroll = LogTableView.makeScrollView(coordinator: c)
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1000, height: 400), styleMask: [.titled], backing: .buffered, defer: false)
        w.isReleasedWhenClosed = false
        scroll.frame = NSRect(x: 0, y: 0, width: 1000, height: 400)
        w.contentView = scroll
        w.layoutIfNeeded()
        windows.append(w)
        let tv = try XCTUnwrap(scroll.documentView as? NSTableView)
        await waitUntil { tv.numberOfRows == 6 }
        try? await Task.sleep(for: .milliseconds(150))
        let row = (0..<tv.numberOfRows).first { store.visibleEntryIfPresent(atRow: $0)?.sourceAddress == "10.0.0.2" } ?? 0
        let item = try XCTUnwrap(rightClick(tv, row: row, choose: "Filter this host"))
        XCTAssertEqual(item.title, "Filter this host (10.0.0.2)")
        _ = (item.target as? NSObject)?.perform(item.action, with: item)
        await waitUntil { store.visible.count == 3 }
        XCTAssertEqual(Set(store.visible.map(\.sourceAddress)), ["10.0.0.2"], store.queryText)
        store.queryText = ""
        store.applyQueryText()
        await waitUntil { store.visible.count == 6 }
        try? await Task.sleep(for: .milliseconds(150))
        let exclude = try XCTUnwrap(rightClick(tv, row: row, choose: "Exclude this host"))
        _ = (exclude.target as? NSObject)?.perform(exclude.action, with: exclude)
        await waitUntil { store.visible.count == 3 }
        XCTAssertEqual(Set(store.visible.map(\.sourceAddress)), ["10.0.0.20"], store.queryText)
    }

    private func rightClick(_ tv: NSTableView, row: Int, choose prefix: String) -> NSMenuItem? {
        guard row >= 0, row < tv.numberOfRows, let window = tv.window else { return nil }
        tv.scrollRowToVisible(row)
        let r = tv.rect(ofRow: row)
        let p = tv.convert(NSPoint(x: r.midX, y: r.midY), to: nil)
        guard let event = NSEvent.mouseEvent(with: .rightMouseDown, location: p, modifierFlags: [], timestamp: 0,
                                             windowNumber: window.windowNumber, context: nil, eventNumber: 0,
                                             clickCount: 1, pressure: 1),
              let menu = tv.menu(for: event) else { return nil }
        menu.delegate?.menuNeedsUpdate?(menu)
        return menu.items.first { $0.title.hasPrefix(prefix) }
    }

    /// The Troubleshoot pane's evidence buttons through `TroubleshootJump.show`: the Log pane's
    /// filter is the evidence's and the table shows its lines and not the neighbor next door's.
    func testEvidenceButtonsThroughTheLogPane() async throws {
        let logs = AppModel.shared.logs
        logs.clear()
        var l = Round13Tests.Lines()
        l.nextID = LogStore.reserveIDs(10)
        l.add(0, "R1", "OSPF neighbor 10.0.0.2 changed to Down: dead timer expired", sev: 3)
        l.add(1, "R1", "OSPF neighbor 10.0.0.20 changed to Down: dead timer expired", sev: 3)
        let entries = l.entries
        logs.ingest(entries)
        let r = Round13Tests.analyze(entries)
        let f = try XCTUnwrap(r.findings.first { $0.title.contains("10.0.0.2 ") })
        let e = try XCTUnwrap(f.evidence.first)
        TroubleshootJump.show(e)
        XCTAssertEqual(AppModel.shared.mainPane, .log)
        await waitUntil { logs.visible.count == 1 }
        XCTAssertEqual(logs.visible.map(\.id), e.ids, logs.query.source)
    }

    // MARK: - 2. Link-state forms

    /// The round-16 corpus lines, each read into what it says.
    func testRound16CorpusLinesAreRead() throws {
        let other = try Round15Tests.corpus("other"), hw = try Round15Tests.corpus("huawei"), cx = try Round15Tests.corpus("arubacx")
        XCTAssertEqual([other.count, hw.count, cx.count], [73, 16, 17])
        func link(_ i: String, _ up: Bool) -> String { "link(iface: \"\(i)\", up: \(up))" }
        func auth(_ n: String) -> String { "routingAuth(proto: \"BGP\", neighbor: \"\(n)\")" }
        XCTAssertEqual(other[63...].map(Round15Tests.kind), [
            link("eth1", false), link("eth1", true), "nil",                   // docker0: nothing
            link("Gi1/0/5", false), "nil", link("GigabitEthernet1/0/5", true), // ERR_RECOVER: nothing
            auth("10.0.16.2"), auth("10.0.14.6"), auth("10.0.15.10"), auth("10.0.15.10"),
        ])
        XCTAssertEqual(hw[13...].map(Round15Tests.kind), [link("GigabitEthernet0/0/5", false), "nil", link("GigabitEthernet0/0/5", true)])
        XCTAssertEqual(cx[14...].map(Round15Tests.kind), [link("1/1/7", false), "nil", link("1/1/7", true)])
        // Each vendor's err-disable alone: the port is down and has not come back, the detail says
        // the switch shut it; its recovery and link-up: nothing.
        for (lines, port, device) in [(Array(other[66...68]), "GigabitEthernet1/0/5", "ACC-SW5"),
                                      (Array(hw[13...15]), "GigabitEthernet0/0/5", "S5720-ACC-07"),
                                      (Array(cx[14...16]), "1/1/7", "CX6300-ACC-12"),
                                      (Array(other[63...65]), "eth1", "lnx-gw1")] {
            let first = Round12Tests.live([lines[0]], hostless: "10.78.1.1")
            let r = Round13Tests.analyze(first, now: first[0].received.addingTimeInterval(600))
            XCTAssertEqual(r.findings.map(\.title), ["Port \(port) on \(device) went down at \(FText.clock(first[0].received)) and has not come back."], lines[0])
            if port != "eth1" { XCTAssertTrue(r.findings.first?.detail.contains("The switch shut it itself (err-disabled") ?? false, r.findings.first?.detail ?? "") }
            let all = Round12Tests.live(lines, hostless: "10.78.1.1")
            XCTAssertTrue(Round13Tests.analyze(all, now: all.last!.received.addingTimeInterval(600)).findings.isEmpty, "\(device): came back")
        }
    }

    /// Cases around the new forms: a BPDU-guard err-disable stays spanning tree's; `ip monitor`
    /// with UP but no carrier and no NO-CARRIER flag; an admin-down interface; a veth / bridge;
    /// a "Deleted" line; Linux eth0 is not NX-OS "Ethernet0"; IOS abbreviations of one port.
    func testLinkFormsEdges() {
        XCTAssertEqual(Self.kind("<188>1: SW1: Sep 23 10:31:00.000: %PM-4-ERR_DISABLE: bpduguard error detected on Gi1/0/9, putting Gi1/0/9 in err-disable state"),
                       "stp(SheepLog.STPKind.bpduGuard, port: Optional(\"Gi1/0/9\"))")
        XCTAssertEqual(Self.kind("<30>Sep 23 10:30:00 h netmon: 3: eth1: <BROADCAST,MULTICAST,UP> mtu 1500 state DOWN"), "link(iface: \"eth1\", up: false)")
        XCTAssertEqual(Self.kind("<30>Sep 23 10:30:00 h netmon: 3: eth1: <BROADCAST,MULTICAST> mtu 1500 state DOWN"), "nil", "admin down")
        XCTAssertEqual(Self.kind("<30>Sep 23 10:30:00 h netmon: 9: veth1a2b@if8: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500"), "nil")
        XCTAssertEqual(Self.kind("<30>Sep 23 10:30:00 h netmon: 7: br-3f2a: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500"), "nil")
        XCTAssertEqual(Self.kind("<30>Sep 23 10:30:00 h netmon: Deleted 9: veth1a2b@if8: <BROADCAST,MULTICAST> mtu 1500"), "nil")
        XCTAssertEqual(Self.kind("<30>Sep 23 10:30:00 h netmon: 5: vlan10@eth0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500"), "link(iface: \"vlan10\", up: false)")
        XCTAssertEqual(FText.canonicalInterface("eth0"), "eth0")
        XCTAssertEqual(FText.canonicalInterface("Eth1/1"), "Ethernet1/1")
        XCTAssertEqual(FText.canonicalInterface("Gi1/0/5"), "GigabitEthernet1/0/5")
        XCTAssertEqual(FText.canonicalInterface("Te1/1/1"), "TenGigabitEthernet1/1/1")
        XCTAssertEqual(FText.canonicalInterface("GE0/0/5"), "GigabitEthernet0/0/5")
        XCTAssertEqual(FText.canonicalInterface("ge-0/0/1"), "ge-0/0/1", "Junos")
        XCTAssertEqual(FText.canonicalInterface("ether1"), "ether1", "MikroTik")
        XCTAssertEqual(FText.canonicalInterface("Po10"), "Port-channel10")
        // One port spelled two ways is one port — flapping 3 times is one finding whose filter
        // shows both spellings' lines.
        var l = Round13Tests.Lines()
        for k in 0..<3 {
            l.add(Double(k) * 120, "SW1", "%PM-4-ERR_DISABLE: link-flap error detected on Gi1/0/5, putting Gi1/0/5 in err-disable state", sev: 4)
            l.add(Double(k) * 120 + 60, "SW1", "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/5, changed state to up", sev: 3)
        }
        let r = Round13Tests.analyze(l.entries)
        XCTAssertEqual(r.findings.map(\.rule), ["link.flap"], r.findings.map(\.title).description)
        let e = r.findings.first?.evidence.first
        XCTAssertEqual(Set((try? Self.shown(e?.query ?? "", l.entries)) ?? []), Set(l.entries.map(\.id)), e?.query ?? "")
    }

    // MARK: - 3. BGP MD5

    /// MD5 failures are a routing finding (was: the FRR form an admin login failure, the IOS and
    /// Junos forms nothing); passwords hashed with MD5 and file checksums are neither.
    func testRoutingSessionMD5FailuresAreRoutingFindings() throws {
        XCTAssertEqual(Self.kind("<190>1: R1: Sep 23 10:37:00.000: %TCP-6-BADAUTH: No MD5 digest from 10.0.16.2(179) to 10.0.16.1(34567) tableid - 0"),
                       "routingAuth(proto: \"BGP\", neighbor: \"10.0.16.2\")")
        XCTAssertEqual(Self.kind("<190>1: R1: Sep 23 10:37:00.000: %TCP-6-BADAUTH: Invalid MD5 digest from 10.0.16.2(646) to 10.0.16.1(34567) tableid - 0"),
                       "routingAuth(proto: \"LDP\", neighbor: \"10.0.16.2\")")
        XCTAssertEqual(Self.kind("<28>Sep 23 10:37:10 MX /kernel: tcp_auth_ok: Packet from 10.0.14.6:179 wrong MD5 digest"),
                       "routingAuth(proto: \"BGP\", neighbor: \"10.0.14.6\")")
        XCTAssertEqual(Self.kind("<27>Sep 23 10:37:20 frr bgpd[912]: 10.0.15.10 [Error] MD5 authentication failed"),
                       "routingAuth(proto: \"BGP\", neighbor: \"10.0.15.10\")")
        XCTAssertEqual(Self.kind("<27>Sep 23 10:37:20 frr ospfd[915]: ospf_check_md5_digest: MD5 authentication error from 10.0.15.6"),
                       "routingAuth(proto: \"OSPF\", neighbor: \"10.0.15.6\")")
        XCTAssertEqual(Self.kind("<86>Sep 23 10:00:00 web01 sshd[1]: Failed password for root from 198.51.100.7 port 51000 ssh2"),
                       "loginFail(ip: Optional(\"198.51.100.7\"), user: Optional(\"root\"))", "an ssh login is still a login")
        XCTAssertEqual(Self.kind("<30>Sep 23 10:00:00 sw1 upgrade: image flash:c9300.bin MD5 checksum verified"), "nil")
        // Through the rules: one finding per session, not a login failure; bad with its count.
        var l = Round13Tests.Lines()
        for k in 0..<4 { l.add(Double(k) * 30, "R1", "10.0.15.10 [Error] MD5 authentication failed", sev: 3) }
        let r = Round13Tests.analyze(l.entries)
        XCTAssertEqual(r.findings.map(\.title), ["BGP session with 10.0.15.10 on R1 fails its MD5 authentication: 4 segments rejected (\(Self.clock(0))–\(Self.clock(90)))."])
        XCTAssertEqual(r.findings.first?.severity, .bad)
        XCTAssertEqual(r.findings.first?.category, .routing)
    }

    // MARK: - 4. SNMP counters: sysUpTime past 497 days, 32-bit totals

    static func walk(_ t: Double, upTime: UInt32, rows: [InterfaceRow], values: [OID: String] = [:]) -> SNMPSnapshot {
        Round13Tests.walk(t, rows: rows, values: values, upTime: upTime)
    }

    /// A device up 497 days: sysUpTime (TimeTicks) starts again at 0. The walks either side of
    /// the wrap are not a restart — the errors grew by what they grew, no "restarted" note.
    func testUptimeWrapIsNoRestart() {
        let before: UInt32 = 4_294_960_000                     // 73 s before the wrap
        let after = UInt32((UInt64(before) + 30_000) % 4_294_967_296)   // 300 s later: 22,704 ticks
        XCTAssertTrue(FindingRules.uptimeWrapped(was: before, now: after, gap: 300))
        XCTAssertFalse(FindingRules.uptimeWrapped(was: before, now: 500, gap: 300), "a real restart right after")
        XCTAssertFalse(FindingRules.uptimeWrapped(was: 90_000, now: 500, gap: 300), "far from the wrap: a restart")
        let a = Self.walk(0, upTime: before, rows: [Round13Tests.ifRow(1, "1/1/1", errors: 10)])
        let b = Self.walk(300, upTime: after, rows: [Round13Tests.ifRow(1, "1/1/1", errors: 110)])
        XCTAssertFalse(FindingRules.restartedBetween(a, b))
        let r = Round13Tests.analyze(snmp: [a, b], now: Self.at(360))
        XCTAssertEqual(r.findings.map(\.title), ["Interface errors are growing on SW-A: 1/1/1 +100 in 5 min."])
        // A real restart between walks is still one (more than 30 s off where the wrap would be).
        let c = Self.walk(300, upTime: 10_000, rows: [Round13Tests.ifRow(1, "1/1/1", errors: 3)])
        XCTAssertTrue(FindingRules.restartedBetween(a, c))
        XCTAssertEqual(Set(Round13Tests.analyze(snmp: [a, c], now: Self.at(360)).findings.map(\.rule)), ["snmp.recentBoot", "snmp.errors"])
        // Discards across the wrap: growth, not totals.
        let d1 = Self.walk(0, upTime: before, rows: [Round13Tests.ifRow(1, "1/1/1")],
                           values: Round13Tests.counters(discards: 1_000, packets: 1_000_000))
        let d2 = Self.walk(300, upTime: after, rows: [Round13Tests.ifRow(1, "1/1/1")],
                           values: Round13Tests.counters(discards: 1_500, packets: 1_100_000))
        XCTAssertEqual(Round13Tests.analyze(snmp: [d1, d2], now: Self.at(360)).findings.map(\.rule), ["snmp.discardsGrowing"])
    }

    /// One walk of a 1 Gb/s port whose packet counters are ifTable's 32-bit ones, on a device up
    /// for days: the rate says the totals may be understated; with ifXTable's (or a slow port up
    /// for less than one wrap) it does not.
    func testOneWalkOf32BitCountersSaysTheRateMayBeOff() {
        func finding(hc: Bool, upTime: UInt32, speed: UInt64 = 1_000_000_000) -> Finding? {
            var row = Round13Tests.ifRow(1, "1/1/1")
            row.speedBits = speed
            let w = Self.walk(0, upTime: upTime, rows: [row], values: Round13Tests.counters(discards: 500, packets: 100_000, hc: hc))
            return Round13Tests.analyze(snmp: [w], now: Self.at(60)).findings.first { $0.rule == "snmp.discards" }
        }
        let wrapped = finding(hc: false, upTime: 86_400_000)
        XCTAssertTrue(wrapped?.detail.contains("come from 32-bit counters (ifTable), which start again past 4,294,967,295 — at full rate every 48 min") ?? false,
                      wrapped?.detail ?? "no finding")
        XCTAssertTrue(wrapped?.detail.contains("may be understated") ?? false)
        XCTAssertFalse(finding(hc: true, upTime: 86_400_000)?.detail.contains("32-bit") ?? true)
        XCTAssertFalse(finding(hc: false, upTime: 100_000, speed: 10_000_000)?.detail.contains("32-bit") ?? true,
                       "a 10 Mb/s port up 17 min cannot have wrapped (its wrap takes 80 h)")
        XCTAssertEqual(FindingRules.wrapSeconds32(speedBits: 1_000_000_000).map { Int($0) }, 2886)
    }

    // MARK: - 5. A log disk ejected mid-write

    /// Disk logging onto a RAM disk; the disk is force-ejected with the file open; lines keep
    /// coming. One error, saying the disk is not connected (it said "Input/output error"); the
    /// disk back under its name: writing resumes, into a file there.
    func testLogDiskEjectedMidWrite() throws {
        guard let disk = RAMDisk.make() else { throw XCTSkip("no RAM disk (hdiutil / newfs_hfs / diskutil unavailable)") }
        disks.append(disk)
        let name = disk.mount.lastPathComponent
        let dir = disk.mount.appending(path: "logs", directoryHint: .isDirectory)
        let errors = LockedBox<[String]>([])
        let logger = DiskLogger(directory: dir) { m in errors.mutate { $0.append(m) } }
        defer { logger.retire() }
        func raws(_ tag: String, _ n: Int) -> [RawSyslog] {
            (0..<n).map { RawSyslog(received: Date(), sourceAddress: "10.0.0.1", sourcePort: 514, transport: .udp, text: "<13>\(tag) \($0)") }
        }
        logger.append(raws: raws("before", 10))
        logger.sync()
        let file = try XCTUnwrap(logger.currentFile)
        XCTAssertEqual(try String(contentsOf: file, encoding: .utf8).split(separator: "\n").count, 10)
        disk.detach()
        disks.removeAll()
        for k in 0..<5 {
            logger.append(raws: raws("gone\(k)", 20))
            logger.sync()
            Thread.sleep(forTimeInterval: 0.3)
        }
        let seen = errors.value
        XCTAssertEqual(seen.count, 1, "\(seen)")
        XCTAssertEqual(seen.first, DiskLogger.notConnected(name))
        // Back (a new disk under the same name): the next lines go to a file there.
        guard let back = RAMDisk.make(named: name) else { throw XCTSkip("could not mount a second RAM disk as \(name)") }
        disks.append(back)
        logger.append(raws: raws("back", 7))
        logger.sync()
        Thread.sleep(forTimeInterval: 1.1)      // the removed-file check runs once a second
        logger.append(raws: raws("back2", 3))
        logger.sync()
        let again = try XCTUnwrap(logger.currentFile)
        XCTAssertTrue(again.path.hasPrefix(back.mount.path), again.path)
        let text = try String(contentsOf: again, encoding: .utf8)
        XCTAssertTrue(text.contains("back2 2"), text)
        XCTAssertEqual(errors.value.count, 1, "no second error once it is back")
    }

    // MARK: - 6. Status and Settings panes, the sidebar

    /// Every combination of running / stopped / failed for the three services: the heading, the
    /// strip's cells and the sidebar's rows agree. (A capture running alone said "Traps are
    /// listening; syslog is off."; a trap receiver that failed was "off" or "Everything is
    /// stopped." over its red cell.)
    func testStatusHeadingAndCellsForEveryServiceState() {
        enum S: CaseIterable { case running, stopped, failed }
        func svc(_ s: S) -> StatusView.Service { StatusView.Service(running: s == .running, error: s == .failed ? "port in use" : nil) }
        var headings: [String: String] = [:]
        for a in S.allCases { for b in S.allCases { for c in S.allCases {
            let h = StatusView.heading(syslog: svc(a), traps: svc(b), capture: svc(c))
            headings["\(a)/\(b)/\(c)"] = h
            // No heading says a service listens that does not, or calls a failure "off".
            if a != .running { XCTAssertFalse(h.hasPrefix("Syslog is listening") || h.contains("Everything is listening") || h.contains("Everything is running"), "\(a)/\(b)/\(c): \(h)") }
            if c == .running, a != .running, b != .running { XCTAssertTrue(h.hasPrefix("Capturing") || h.contains("could not start"), "\(a)/\(b)/\(c): \(h)") }
            if b != .running { XCTAssertFalse(h.hasPrefix("Traps are listening") || h.contains("Everything is listening") || h.contains("Everything is running"), "\(a)/\(b)/\(c): \(h)") }
            if b == .failed { XCTAssertTrue(h.contains("could not start"), "\(a)/\(b)/\(c): \(h)") }
            if a == .failed { XCTAssertTrue(h.hasPrefix("Syslog"), "\(a)/\(b)/\(c): \(h)") }
            // The cells and the sidebar say the same thing about each service.
            for (state, word) in [(a, "Listening"), (b, "Listening"), (c, "Capturing")] {
                let cell = StatusView.serviceCell("X", running: state == .running, error: svc(state).error, runningWord: word, detail: "udp 514")
                let side = SidebarView.serviceLook(running: state == .running, failed: svc(state).failed, detail: "udp 514")
                switch state {
                case .running:
                    XCTAssertEqual(cell.value, word); XCTAssertEqual(cell.detail, "udp 514"); XCTAssertEqual(side.detail, "udp 514")
                    XCTAssertEqual(side.dot, Theme.live)
                case .stopped:
                    XCTAssertEqual(cell.value, "Stopped"); XCTAssertEqual(cell.detail, "not running"); XCTAssertEqual(side.detail, "off")
                    XCTAssertEqual(side.dot, Theme.faintText)
                case .failed:
                    XCTAssertEqual(cell.value, "Failed"); XCTAssertEqual(cell.detail, "port in use"); XCTAssertEqual(side.detail, "failed")
                    XCTAssertEqual(side.dot, Theme.err); XCTAssertEqual(cell.tint, Theme.err)
                }
            }
        } } }
        XCTAssertEqual(headings["stopped/stopped/running"], "Capturing; syslog and traps are off.")
        XCTAssertEqual(headings["stopped/failed/stopped"], "The trap receiver could not start.")
        XCTAssertEqual(headings["running/failed/running"], "Syslog is listening; the trap receiver could not start.")
        XCTAssertEqual(headings["failed/failed/stopped"], "Syslog and the trap receiver could not start.")
        XCTAssertEqual(headings["running/running/running"], "Everything is running.")
        XCTAssertEqual(headings["running/running/stopped"], "Everything is listening.")
        XCTAssertEqual(headings["stopped/stopped/stopped"], "Everything is stopped.")
        // Running with an error (syslog's TCP port taken while UDP opened): amber, the error said.
        let partly = StatusView.serviceCell("Syslog", running: true, error: "TCP 514 is in use", detail: "udp 514")
        XCTAssertEqual(partly.value, "Listening")
        XCTAssertEqual(partly.tint, Theme.warn)
        XCTAssertEqual(partly.detail, "udp 514 · TCP 514 is in use")
    }

    /// "Point devices here": what each row shows and what Copy puts on the pasteboard, with and
    /// without an IPv4 address, TCP only, the ports off.
    func testPointDevicesRowsAndTheirCopyValues() {
        func rows(_ a: String?, _ udp: UInt16, _ tcp: UInt16, _ trap: UInt16) -> [String] {
            StatusView.pointRows(address: a, udp: udp, tcp: tcp, trapPort: trap, mirror: "m").map { "\($0.key)=\($0.value)|\($0.copy ?? "-")" }
        }
        XCTAssertEqual(rows("10.1.0.5", 514, 514, 162), ["Syslog server=10.1.0.5:514  (udp or tcp)|10.1.0.5",
                                                        "SNMP trap receiver=10.1.0.5:162|10.1.0.5", "Mirror / SPAN port=m|-"])
        XCTAssertEqual(rows("10.1.0.5", 5514, 0, 162)[0], "Syslog server=udp 10.1.0.5:5514|10.1.0.5")
        XCTAssertEqual(rows("10.1.0.5", 0, 6514, 162)[0], "Syslog server=tcp 10.1.0.5:6514|10.1.0.5")
        XCTAssertEqual(rows("10.1.0.5", 0, 0, 0), ["Syslog server=no syslog port is open|-", "SNMP trap receiver=no trap port is set|-", "Mirror / SPAN port=m|-"])
        // No IPv4 address: nothing to copy ("this Mac" was copied).
        XCTAssertEqual(rows(nil, 514, 514, 162), ["Syslog server=this Mac:514  (udp or tcp) — no IPv4 address|-",
                                                  "SNMP trap receiver=udp 162 — no IPv4 address|-", "Mirror / SPAN port=m|-"])
        XCTAssertEqual(StatusView.noLinesNote(address: "10.1.0.5", udp: 0, tcp: 6514), "No lines yet. Point your devices’ syslog at 10.1.0.5, tcp 6514, then open Log.")
        XCTAssertEqual(StatusView.noLinesNote(address: "10.1.0.5", udp: 514, tcp: 514), "No lines yet. Point your devices’ syslog at 10.1.0.5, udp 514, then open Log.")
        XCTAssertEqual(StatusView.noLinesNote(address: nil, udp: 0, tcp: 0), "No lines yet, and no syslog port is set: choose one in Settings.")
        XCTAssertEqual(StatusView.packetsCell(inMemory: 200, received: 200, bytes: 2_000).detail, Format.bytes(2_000))
        XCTAssertEqual(StatusView.packetsCell(inMemory: 200, received: 5_000, bytes: 9_000_000).detail, "\(Format.bytes(9_000_000)) in 5,000 received")
    }

    /// Settings → Apply ports, driven on real listeners: disabled with nothing to do, enabled
    /// for a running listener on other ports or one that failed or runs on one of its two ports;
    /// the trap note follows. A retry of a port still taken says so ("could not move to the new
    /// ports" when no port was new).
    func testApplyPortsEnablementAndMessages() throws {
        let model = AppModel.shared
        savedSettings = model.settings
        model.dismissAllErrors()
        let udp = TestSockets.freePort(SOCK_DGRAM), trap = TestSockets.freePort(SOCK_DGRAM)
        model.settings.syslogUDPPort = udp
        model.settings.syslogTCPPort = 0
        model.settings.trapPort = trap
        XCTAssertFalse(model.listenerPortsChanged, "all stopped")
        model.settings.syslogUDPPort = TestSockets.freePort(SOCK_DGRAM)
        XCTAssertFalse(model.listenerPortsChanged, "stopped: a new port applies at the next start")
        model.settings.syslogUDPPort = udp
        model.startSyslog(); model.startTraps()
        XCTAssertTrue(model.syslog.isRunning && model.traps.isRunning)
        XCTAssertFalse(model.listenerPortsChanged)
        model.settings.trapPort = TestSockets.freePort(SOCK_DGRAM)
        XCTAssertTrue(model.listenerPortsChanged, "traps on another port")
        model.restartListeners()
        XCTAssertFalse(model.listenerPortsChanged)
        XCTAssertNil(model.lastError)
        // Syslog on one of its two ports: TCP taken at start.
        model.stopSyslog()
        let held = try XCTUnwrap(TestSockets.holdIPv4(SOCK_STREAM))
        defer { close(held.fd) }
        model.settings.syslogTCPPort = held.port
        model.startSyslog()
        model.dismissAllErrors()
        XCTAssertTrue(model.syslog.isRunning)
        XCTAssertEqual(model.syslog.tcpPort, 0)
        XCTAssertTrue(model.listenerPortsChanged, "retry the port that failed")
        model.restartListeners()
        XCTAssertTrue(model.syslog.isRunning)
        XCTAssertEqual(model.syslog.udpPort, udp)
        XCTAssertEqual(model.lastError, "Syslog still cannot open TCP \(held.port), so it stays on UDP \(udp) only.")
        model.dismissAllErrors()
        // Failed outright (UDP taken, TCP off): enabled, Apply retries.
        model.stopSyslog()
        let heldU = try XCTUnwrap(TestSockets.holdIPv4(SOCK_DGRAM))
        defer { close(heldU.fd) }
        model.settings.syslogUDPPort = heldU.port
        model.settings.syslogTCPPort = 0
        model.startSyslog()
        XCTAssertFalse(model.syslog.isRunning)
        model.dismissAllErrors()
        XCTAssertTrue(model.listenerPortsChanged)
    }

    /// The sidebar's counts are the panes' own after Clear, a lower limit and eviction (Log,
    /// Sources, Packets), and a paused Log.
    func testSidebarCountsFollowThePanes() async throws {
        let logs = AppModel.shared.logs, packets = AppModel.shared.packets, mibs = MIBRegistry.shared
        logs.clear(); packets.clear()
        let sourcesBefore = logs.sources.count
        func check(_ step: String) {
            let c = SidebarView.counts(logs: logs, packets: packets, mibs: mibs)
            XCTAssertEqual(c[.log], logs.entries.count, step)
            XCTAssertTrue(LogView.footerText(store: logs, diskLogging: false).contains("of \(Format.count(logs.entries.count))"), step)
            XCTAssertEqual(c[.sources], logs.sources.count, step)
            XCTAssertEqual(c[.packets], packets.packets.count, step)
            XCTAssertTrue(PacketsFooter.text(shown: packets.visible.count, inMemory: packets.packets.count, received: packets.totalReceived,
                                             bytes: packets.totalBytes, filtered: false, file: nil).hasPrefix("\(Format.count(packets.packets.count)) packets"), step)
            XCTAssertEqual(c[.mibs], mibs.modules.count, step)
        }
        let lines = (0..<3_000).map { k in parsedLine("<13>Sep 23 10:00:00 sw\(k % 7) app: \(k)", from: "10.216.16.\(k % 7 + 1)", id: LogStore.nextID()) }
        logs.ingest(lines)
        packets.ingest(Self.packets((0..<3_000).map { _ in Array(PacketFixture.udp4(src: "10.0.0.1", dst: "10.0.0.2", 1000, 53, [1, 2, 3])) }))
        await waitUntil { logs.sources.count >= sourcesBefore + 7 }
        check("ingested")
        logs.limit = 1_000; packets.limit = 1_000
        await spin(100)
        XCTAssertEqual(logs.entries.count, 1_000)
        check("limit lowered")
        logs.ingest((0..<500).map { k in parsedLine("<13>Sep 23 10:00:00 sw9 app: \(k)", from: "10.216.16.9", id: LogStore.nextID()) })
        await waitUntil { logs.sources.count >= sourcesBefore + 8 }
        check("evicted")
        logs.paused = true
        logs.ingest((0..<50).map { k in parsedLine("<13>Sep 23 10:00:00 sw9 app: p\(k)", from: "10.216.16.9", id: LogStore.nextID()) })
        await spin(100)
        check("paused")
        logs.paused = false
        logs.clear(); packets.clear()
        await spin(100)
        check("cleared")
        XCTAssertEqual(logs.entries.count, 0)
        XCTAssertGreaterThanOrEqual(logs.sources.count, sourcesBefore + 8, "Sources are since launch — the pane says so")
    }
}

extension Round16Tests {
    // MARK: - 7. Sweep

    /// Sweep 1. The Syslog pane's `.*` toggle on and Info hidden by the severity mask, then a
    /// Troubleshoot evidence button: the evidence filter's words were regexes (`10.0.0.2` found
    /// 10.0.0.20 and "10a0b0c2") and the mask hid the notice-level evidence. Now the toggle goes
    /// off and the severities the evidence has are shown; a mask that hides none of it stays.
    func testEvidenceShowWithRegexModeAndASeverityMask() async throws {
        let logs = AppModel.shared.logs
        logs.clear()
        var l = Round13Tests.Lines()
        l.nextID = LogStore.reserveIDs(10)
        l.add(0, "R1", "BGP neighbor 10.0.0.2 Down Hold timer expired", sev: 5)
        l.add(1, "R1", "BGP neighbor 10.0.0.20 Down Hold timer expired", sev: 5)
        l.add(2, "R1", "BGP neighbor 10a0b0c2 Down", sev: 5)
        logs.ingest(l.entries)
        let r = Round13Tests.analyze(l.entries)
        let e = try XCTUnwrap(r.findings.first { $0.title.contains("10.0.0.2 ") }?.evidence.first)
        logs.regexMode = true
        logs.severityMask = Set(Severity.allCases).subtracting([.notice, .info, .debug])
        TroubleshootJump.show(e)
        await waitUntil { logs.visible.map(\.id) == e.ids }
        XCTAssertEqual(logs.visible.map(\.id), e.ids, "`\(logs.query.source)` regex \(logs.regexMode) mask \(logs.severityMask.count)")
        XCTAssertFalse(logs.regexMode)
        XCTAssertTrue(logs.severityMask.contains(.notice))
        XCTAssertFalse(logs.severityMask.contains(.debug), "only what the evidence needs")
        logs.severityMask = Set(Severity.allCases)
    }

    /// Sweep 2. A relay that forwards SW1 and SW10's lines from one address: a finding of SW1 is
    /// filtered by its name (the address is both), and `host:SW1` was a prefix — SW10's lines
    /// too. `host:"SW1$"` is the name alone; `app:sshd$` the program alone (the Log context
    /// menu's "Filter this program": `app:sshd` took sshd-session's lines).
    func testRelayedHostsAndProgramsByTheirWholeName() async throws {
        var l = Round13Tests.Lines()
        for k in 0..<3 {
            for sw in ["SW1", "SW10"] {
                l.raw(Double(k) * 120, "<187>\(Self.bsd(Double(k) * 120)) \(sw) %LINK-3-UPDOWN: Interface GigabitEthernet1/0/7, changed state to down", from: "10.66.9.9")
                l.raw(Double(k) * 120 + 60, "<187>\(Self.bsd(Double(k) * 120 + 60)) \(sw) %LINK-3-UPDOWN: Interface GigabitEthernet1/0/7, changed state to up", from: "10.66.9.9")
            }
        }
        let r = Round13Tests.analyze(l.entries)
        XCTAssertEqual(r.findings.count, 2, r.findings.map(\.title).description)
        for f in r.findings {
            let e = try XCTUnwrap(f.evidence.first)
            XCTAssertTrue(e.query.hasPrefix("host:\"\(f.device ?? "")$\""), e.query)
            XCTAssertEqual(Set(try Self.shown(e.query, l.entries)), Set(e.ids), "\(f.title): `\(e.query)`")
        }
        let prog = [parsedLine("<38>Sep 23 10:00:00 web01 sshd[1]: Accepted publickey", id: 1),
                    parsedLine("<38>Sep 23 10:00:01 web01 sshd-session[2]: Connection closed", id: 2)]
        XCTAssertEqual(try Self.shown("app:sshd", prog), [1, 2])
        XCTAssertEqual(try Self.shown("app:sshd$", prog), [1])
        XCTAssertEqual(try Self.shown("-app:sshd$", prog), [2])
        XCTAssertEqual(try Self.shown("host:web$", prog), [])
        XCTAssertEqual(try Self.shown("host:WEB01$", prog), [1, 2])
        // Through the grid's context menu.
        let store = LogStore()
        store.ingest(prog.map { parsedLine($0.raw, from: "10.1.0.1", id: LogStore.nextID()) })
        let box = SelectionBoxR16()
        let c = LogTableView.Coordinator(store: store)
        c.parent = LogTableView(store: store, selectedID: Binding(get: { box.id }, set: { box.id = $0 }))
        let scroll = LogTableView.makeScrollView(coordinator: c)
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1000, height: 300), styleMask: [.titled], backing: .buffered, defer: false)
        w.isReleasedWhenClosed = false
        scroll.frame = NSRect(x: 0, y: 0, width: 1000, height: 300)
        w.contentView = scroll
        w.layoutIfNeeded()
        windows.append(w)
        let tv = try XCTUnwrap(scroll.documentView as? NSTableView)
        await waitUntil { tv.numberOfRows == 2 }
        try? await Task.sleep(for: .milliseconds(150))
        let row = (0..<2).first { store.visibleEntryIfPresent(atRow: $0)?.program == "sshd" } ?? 0
        let item = try XCTUnwrap(rightClick(tv, row: row, choose: "Filter this program"))
        _ = (item.target as? NSObject)?.perform(item.action, with: item)
        await waitUntil { store.visible.count == 1 }
        XCTAssertEqual(store.visible.map(\.program), ["sshd"], store.queryText)
    }

    /// Sweep 3. Link traps of two ports of one switch whose names overlap (Gi1/0/1, Gi1/0/10):
    /// each finding's trap filter shows its own port's traps (it showed every link trap of the
    /// switch).
    func testLinkTrapEvidenceNamesItsPort() throws {
        let reg = MIBRegistry()
        reg.loadNow(bundled: MIBRegistry.bundledURLs())
        func trap(_ idx: UInt32, _ name: String, down: Bool, _ t: Double) -> LogEntry {
            let v = SNMPTrap(received: Self.at(t), sourceAddress: "10.1.0.30", sourcePort: 50000, version: .v2c, community: "public",
                             trapOID: OID([1, 3, 6, 1, 6, 3, 1, 1, 5, down ? 3 : 4]), uptime: 12345, agentAddress: nil,
                             varBinds: [VarBind(OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 1, idx]), .integer(Int64(idx))),
                                        VarBind(OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 2, idx]), .octetString(Data(name.utf8)))])
            return TrapReceiver.entry(for: v, registry: reg)
        }
        var entries: [LogEntry] = []
        for k in 0..<3 {
            entries.append(trap(1, "Gi1/0/1", down: true, Double(k) * 120))
            entries.append(trap(1, "Gi1/0/1", down: false, Double(k) * 120 + 60))
            entries.append(trap(10, "Gi1/0/10", down: true, Double(k) * 120 + 1))
        }
        let r = Round13Tests.analyze(entries, now: Self.at(900))
        XCTAssertEqual(r.findings.count, 2, r.findings.map(\.title).description)
        for f in r.findings {
            let e = try XCTUnwrap(f.evidence.first { $0.kind == .traps })
            XCTAssertEqual(Set(try Self.shown(e.query, entries)), Set(e.ids), "\(f.title): `\(e.query)`")
        }
    }

    /// Sweep 4. The Packets grid's right-click "Filter this conversation" on 10.0.0.5:1000 →
    /// 10.0.0.6:80 with the ports-swapped conversation beside it: only its own two packets.
    func testPacketsContextMenuFilterThisConversation() async throws {
        let store = AppModel.shared.packets
        store.clear()
        store.ingest(Self.packets([
            Array(PacketFixture.tcp4(src: "10.0.0.5", dst: "10.0.0.6", 1000, 80, flags: 0x02)),
            Array(PacketFixture.tcp4(src: "10.0.0.6", dst: "10.0.0.5", 80, 1000, flags: 0x12)),
            Array(PacketFixture.tcp4(src: "10.0.0.5", dst: "10.0.0.6", 80, 1000, flags: 0x02)),
            Array(PacketFixture.tcp4(src: "10.0.0.6", dst: "10.0.0.5", 1000, 80, flags: 0x12)),
        ]))
        let controller = PacketTableController()
        controller.liveOverride = false
        let scroll = PacketTableView.makeScrollView(controller: controller)
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1100, height: 400), styleMask: [.titled], backing: .buffered, defer: false)
        w.isReleasedWhenClosed = false
        scroll.frame = NSRect(x: 0, y: 0, width: 1100, height: 400)
        w.contentView = scroll
        w.layoutIfNeeded()
        windows.append(w)
        let tv = try XCTUnwrap(scroll.documentView as? NSTableView)
        controller.refreshNow()
        await waitUntil { tv.numberOfRows == 4 }
        let row = try XCTUnwrap(store.visibleIndex(of: store.packets[0].id))
        let item = try XCTUnwrap(rightClick(tv, row: row, choose: "Filter this conversation"))
        _ = (item.target as? NSObject)?.perform(item.action, with: item)
        await waitUntil { store.visible.count == 2 }
        XCTAssertEqual(store.visible.map(\.id), [store.packets[0].id, store.packets[1].id], store.queryText)
    }
}

/// The Log grid's selection binding target.
@MainActor final class SelectionBoxR16 { var id: Int? }

extension RAMDisk {
    /// A RAM disk mounted under a given volume name (a disk that comes back).
    static func make(named name: String, sectors: Int = 2048) -> RAMDisk? {
        guard let out = run("/usr/bin/hdiutil", ["attach", "-nomount", "ram://\(sectors)"]),
              let dev = out.split(whereSeparator: \.isWhitespace).first.map(String.init), dev.hasPrefix("/dev/disk") else { return nil }
        guard run("/sbin/newfs_hfs", ["-v", name, dev]) != nil, run("/usr/sbin/diskutil", ["mount", dev]) != nil,
              FileManager.default.fileExists(atPath: "/Volumes/\(name)") else {
            _ = run("/usr/bin/hdiutil", ["detach", dev, "-force"])
            return nil
        }
        return RAMDisk(device: dev, mount: URL(fileURLWithPath: "/Volumes/\(name)", isDirectory: true))
    }
}
