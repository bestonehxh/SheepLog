import AppKit
import SwiftUI
import XCTest
@testable import SheepLog

/// Round 12: the Authentication pane's round-11 leftovers (a switch port no supplicant answers,
/// many clients group-addressing one SPAN, the header at 10,000 attempts, a Follow request
/// pending while the user clicks another row), the Troubleshoot pane's first cold review (its
/// rules over healthy device chatter, the timeline's edges, the client report, the re-analysis
/// during a flood), and a sweep.
@MainActor
final class Round12Tests: XCTestCase {
    private var windows: [NSWindow] = []

    override func tearDown() async throws {
        for w in windows { w.contentView = nil; w.close() }
        windows = []
        let packets = AppModel.shared.packets
        packets.paused = false
        packets.limit = 200_000
        packets.queryText = ""
        packets.applyQueryNow(synchronous: true)
        packets.clear()
        AppModel.shared.logs.clear()
        AppModel.shared.mainPane = .status
        try? await Task.sleep(for: .milliseconds(50))
    }

    // MARK: - Harness

    private func host<V: View>(_ view: V, width: CGFloat = 1280, height: CGFloat = 820) -> NSHostingView<V> {
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: width, height: height),
                         styleMask: [.titled, .resizable], backing: .buffered, defer: false)
        w.isReleasedWhenClosed = false
        let h = NSHostingView(rootView: view)
        w.contentView = h
        w.orderFront(nil)
        windows.append(w)
        return h
    }

    private func spin(_ ms: Int = 30) async { try? await Task.sleep(for: .milliseconds(ms)) }

    private func waitUntil(_ timeout: Double = 5, _ condition: () -> Bool) async {
        let end = Date().addingTimeInterval(timeout)
        while !condition(), Date() < end { await spin(10) }
    }

    /// The longest the main actor was unavailable while `body` ran for `seconds` (a 1 ms sleep
    /// loop measures each gap: SwiftUI updates, timers and our own work all run in them).
    private func longestMainGap(for seconds: Double, while body: () -> Void = {}) async -> Double {
        var worst = 0.0
        let end = Date().addingTimeInterval(seconds)
        var last = Monotonic.now()
        while Date() < end {
            body()
            try? await Task.sleep(for: .milliseconds(1))
            let now = Monotonic.now()
            worst = max(worst, now - last)
            last = now
        }
        return worst
    }

    static func renumbered(_ packets: [Packet]) -> [Packet] {
        packets.enumerated().map { i, p in
            Packet(id: i + 1, timestamp: p.timestamp, relative: p.relative, length: p.length, captured: p.captured,
                   data: p.data, decoded: p.decoded)
        }
    }

    // MARK: - 1a. A switch port whose device never answers

    static let silentPort: [UInt8] = [0x00, 0x1c, 0x0e, 0x00, 0x00, 0x07]

    static func eapolFrame(dst: [UInt8], src: [UInt8], _ eap: [UInt8], type: UInt8 = 0) -> [UInt8] {
        AuthLab.ether(dst: dst, src: src, type: 0x888E, [2, type] + AuthLab.be16(eap.count) + eap)
    }

    /// A wired port whose supplicant is off: the switch's group-addressed EAP-Request Identity
    /// came before any client frame and was dropped (nobody to give it to) — the port that
    /// needed attention showed nothing at all.
    func testGroupAddressedIdentityNobodyAnswersIsThePortsAttempt() throws {
        let port = AuthLab.macText(Self.silentPort)
        var lab = AuthLab(client: [0x02, 0x12, 0, 0, 0, 1])
        lab.add(Self.eapolFrame(dst: AuthLab.pae, src: Self.silentPort, AuthLab.eap(code: 1, id: 1, type: 1)), dt: 0)
        // Other traffic goes on for 10 s (another client's DHCP).
        lab.dhcpExchange(ip: "10.20.0.30", dt: 2.5)
        let s = AuthSessions.build(lab.packets)
        XCTAssertEqual(s.count, 1, s.map(\.client).description)
        let one = try XCTUnwrap(s.first)
        XCTAssertEqual(one.client, "port:" + port)
        XCTAssertTrue(one.isPortOnly)
        XCTAssertEqual(one.nasMAC, port)
        XCTAssertEqual(one.result, .timeout("no supplicant answered on port \(port)"))
        XCTAssertEqual(one.health, .warn)
        XCTAssertTrue(one.reasons.first?.hasPrefix("No 802.1X supplicant answered on switch port \(port): its EAP-Request Identity went unanswered.") ?? false,
                      one.reasons.description)
        XCTAssertEqual(one.packetIDs, [1])
        XCTAssertEqual(one.events.last?.problem, "no supplicant answered")
        XCTAssertEqual(AuthView.headline(s), "0 clients authenticated, none failed.", "a silent port is not a failed client")
        // Troubleshoot: one finding, in plain words, about the port (no client).
        let f = try XCTUnwrap(AuthFindings.findings(from: lab.packets).first)
        XCTAssertEqual(f.title, "No 802.1X supplicant answered on switch port \(port).")
        XCTAssertNil(f.client)
        XCTAssertTrue(f.nextSteps.contains { $0.contains("MAC auth bypass") })
        _ = AuthSummary.text(one)

        // The switch asks three times, 30 s apart: one attempt of the port, three requests.
        var three = AuthLab(client: [0x02, 0x12, 0, 0, 0, 2])
        for k in 0..<3 {
            three.add(Self.eapolFrame(dst: AuthLab.pae, src: Self.silentPort, AuthLab.eap(code: 1, id: UInt8(1 + k), type: 1)), dt: k == 0 ? 0 : 30)
        }
        let s3 = AuthSessions.build(three.packets)
        XCTAssertEqual(s3.count, 1)
        XCTAssertEqual(s3.first?.packetIDs, [1, 2, 3])
        XCTAssertTrue(s3.first?.reasons.first?.contains("3 EAP-Request Identity went unanswered") ?? false, s3.first?.reasons.description ?? "")

        // The capture ends a second after the request: not yet a timeout.
        var early = AuthLab(client: [0x02, 0x12, 0, 0, 0, 3])
        early.add(Self.eapolFrame(dst: AuthLab.pae, src: Self.silentPort, AuthLab.eap(code: 1, id: 1, type: 1)), dt: 0)
        early.dhcpExchange(ip: "10.20.0.31", dt: 0.2)
        XCTAssertEqual(AuthSessions.build(early.packets).first?.result, .inProgress)

        // The device answers (to the group, or to the port's MAC): the request is its attempt's first step.
        for toGroup in [true, false] {
            var lab2 = AuthLab(client: [0x02, 0x12, 0, 0, 1, toGroup ? 1 : 2])
            lab2.authenticator = Self.silentPort
            lab2.add(Self.eapolFrame(dst: AuthLab.pae, src: Self.silentPort, AuthLab.eap(code: 1, id: 1, type: 1)), dt: 0)
            lab2.eapID = 1
            lab2.eapol(fromClient: true, type: 0, AuthLab.eap(code: 2, id: 1, type: 1, Array("dana".utf8)), toGroup: toGroup, dt: 0.01)
            lab2.eapToClient(code: 1, type: 25, AuthLab.tlsData(start: true))
            lab2.eapFromClient(type: 25, AuthLab.tlsData(bytes: 100))
            lab2.eapToClient(code: 3)
            lab2.dhcpExchange(ip: "10.20.0.32", dt: 2)
            let s2 = AuthSessions.build(lab2.packets)
            XCTAssertEqual(s2.count, 1, "toGroup \(toGroup): \(s2.map(\.client))")
            XCTAssertEqual(s2.first?.client, lab2.clientText)
            XCTAssertEqual(s2.first?.result, .accepted)
            XCTAssertEqual(s2.first?.firstPacketID, 1, "the switch's request is the attempt's")
            XCTAssertEqual(s2.first?.events.first?.label, "EAP-Request Identity")
            XCTAssertEqual(s2.first?.user, "dana")
        }
    }

    /// After a failed attempt the switch asks the port again (quiet period over) and nothing
    /// answers: the supplicant gave up — not "no supplicant on this port".
    func testPortAttemptAfterAFailureNamesTheClientThatStoppedAnswering() throws {
        let exchange = Self.groupExchange(client: [0x02, 0x34, 0, 0, 0, 1], sw: Self.silentPort, idBase: 10, succeed: false)
        var lab = AuthLab(client: [0x02, 0x34, 0, 0, 0, 1])
        for f in exchange { lab.add(f.bytes, dt: 0.005) }
        lab.add(Self.eapolFrame(dst: AuthLab.pae, src: Self.silentPort, AuthLab.eap(code: 1, id: 30, type: 1)), dt: 60)
        lab.add(Self.eapolFrame(dst: AuthLab.pae, src: Self.silentPort, AuthLab.eap(code: 1, id: 31, type: 1)), dt: 30)
        let s = AuthSessions.build(lab.packets)
        XCTAssertEqual(s.count, 2, s.map { "\($0.client) \($0.result)" }.description)
        XCTAssertEqual(s.first { !$0.isPortOnly }?.result, .rejected("EAP-Failure"))
        let port = try XCTUnwrap(s.first { $0.isPortOnly })
        let reason = try XCTUnwrap(port.reasons.first)
        XCTAssertTrue(reason.contains("02:34:00:00:00:01 was on this port until"), reason)
        XCTAssertTrue(reason.contains("its authentication failed"), reason)
        XCTAssertFalse(reason.contains("no supplicant at all"), reason)
    }

    // MARK: - 1c. The Authentication header at 10,000 attempts

    /// 10,000 wired attempts, each on its own switch port.
    static func tenThousandAttempts() -> [Packet] {
        var packets: [Packet] = []
        packets.reserveCapacity(80_000)
        for c in 0..<10_000 {
            var lab = AuthLab(client: [0x02, 0x22, UInt8(c >> 8), UInt8(c & 0xff), 0, 1], at: Double(c) * 0.01)
            lab.authenticator = [0x00, 0x1c, 0x0e, UInt8(c >> 8), UInt8(c & 0xff), 5]
            lab.eapToClient(code: 1, type: 1)
            lab.eapFromClient(type: 1, Array("user\(c)".utf8))
            lab.toServer(lab.common(user: "user\(c)") + [AuthLab.eapMessage(AuthLab.eap(code: 2, id: 1, type: 1, Array("user\(c)".utf8)))])
            lab.toNAS(code: c % 7 == 0 ? 3 : 2, [AuthLab.eapMessage(AuthLab.eap(code: c % 7 == 0 ? 4 : 3, id: 2))])
            for p in lab.packets {
                packets.append(Packet(id: packets.count + 1, timestamp: p.timestamp, relative: p.relative, length: p.length,
                                      captured: p.captured, data: p.data, decoded: p.decoded))
            }
        }
        return packets
    }

    /// The header's "re-analysed n s ago" ticks every second; each tick re-ran the table's
    /// filter, map and sort of every attempt (for `rows.isEmpty` of Copy summary, several times
    /// per update) and the headline's per-client pass: 85 ms of main thread a second at 10,000
    /// attempts (Debug). Now the rows are sorted once per change of the data, the filters or the
    /// order; a tick at 10,000 attempts costs < 5 ms more than at 10 (SwiftUI's own redraw of the
    /// header, ~10 ms in Debug, is the same for both).
    func testAuthHeaderTickDoesNotResortTenThousandAttempts() async throws {
        let packets = AppModel.shared.packets
        packets.clear()
        let all = Self.tenThousandAttempts()
        let perAttempt = all.count / 10_000
        PaneProbe.reset()
        packets.ingest(Array(all.prefix(10 * perAttempt)))
        var before = PaneProbe.authAnalyses
        let h = host(AuthView())
        await waitUntil(20) { PaneProbe.authAnalyses > before && LeakProbe.count("Auth.analysis") == 0
            && (Self.tablesIn(h).first?.numberOfRows ?? 0) == 10 }
        await spin(500)
        let small = await longestMainGap(for: 3.2)
        before = PaneProbe.authAnalyses
        packets.ingest(Array(all.dropFirst(10 * perAttempt)))
        await waitUntil(20) { PaneProbe.authAnalyses > before && LeakProbe.count("Auth.analysis") == 0
            && (Self.tablesIn(h).first?.numberOfRows ?? 0) == 10_000 }
        XCTAssertEqual(Self.tablesIn(h).first?.numberOfRows, 10_000)
        await spin(500)
        let sorts = PaneProbe.authRowSorts
        let big = await longestMainGap(for: 3.2)
        print("[perf] Authentication header tick: longest main-thread gap \(String(format: "%.1f", small * 1000)) ms at 10 attempts, \(String(format: "%.1f", big * 1000)) ms at 10,000; row sorts during 3 ticks \(PaneProbe.authRowSorts - sorts)")
        XCTAssertEqual(PaneProbe.authRowSorts, sorts, "a tick re-sorted the rows")
        XCTAssertWithinBudget(big - small, 0.005, "what 10,000 attempts add to a header tick")
        XCTAssertWithinBudget(big, 0.033, "a header tick at 10,000 attempts (SwiftUI's own redraw is ~10–17 ms in Debug)")
        // A change of the order does sort again, once.
        let tv = try XCTUnwrap(Self.tablesIn(h).first)
        let column = try XCTUnwrap(tv.tableColumns.first { $0.title == "User" })
        tv.sortDescriptors = [try XCTUnwrap(column.sortDescriptorPrototype)]
        await waitUntil { PaneProbe.authRowSorts > sorts }
        await spin(1_200)
        XCTAssertEqual(PaneProbe.authRowSorts, sorts + 1, "one sort for one change of order")
    }

    // MARK: - 1d. A Follow request pending while the user clicks another row

    /// "Follow TCP stream" for a frame newer than the last analysis waits for the next one; the
    /// user clicks another conversation meanwhile. The analysis then landed and moved the
    /// selection back to the Follow target, undoing the click. The click wins now (the pending
    /// request is dropped), and a Follow posted after a click still wins over the click.
    func testFollowPendingWhileTheUserClicksAnotherRow() async throws {
        let packets = AppModel.shared.packets
        packets.clear()
        AppModel.shared.mainPane = .status
        let two = Round11InteractionTests.conversations()
        packets.ingest(two)
        let flows1 = TCPFlowAnalyzer.analyze(two)
        let short = try XCTUnwrap(flows1.first { $0.server == "10.2.0.1" })
        PaneProbe.reset()
        let before = PaneProbe.flowAnalyses
        let h = host(FlowView())
        await waitUntil { PaneProbe.flowAnalyses > before && LeakProbe.count("Flows.analysis") == 0 && (Self.tablesIn(h).first?.numberOfRows ?? 0) == 2 }
        let tv = try XCTUnwrap(Self.tablesIn(h).first)

        // A long transfer, then the conversation the Follow names: an analysis that takes a moment.
        let bulk = Round11InteractionTests.bulk(firstID: two.count + 1, offset: 10, pairs: 40_000)
        let later = Round11InteractionTests.conversations(firstID: two.count + bulk.count + 1, offset: 20, port: 51_000)
        packets.ingest(bulk + later)
        let flows2 = TCPFlowAnalyzer.analyze(packets.packets)
        let target = try XCTUnwrap(flows2.first { $0.clientPort == 51_001 })
        let frame = target.events[8].packetIDs[0]
        NotificationCenter.default.post(name: .sheepLogSelectFlow, object: FlowSelectRequest(key: target.key, packetID: frame))
        await waitUntil { LeakProbe.count("Flows.analysis") == 1 }
        XCTAssertEqual(LeakProbe.count("Flows.analysis"), 1, "the Follow waits for an analysis")
        // The click, while that analysis runs.
        tv.selectRowIndexes(IndexSet(integer: try XCTUnwrap(Round11InteractionTests.flowRow(flows1, id: short.id))), byExtendingSelection: false)
        XCTAssertEqual(LeakProbe.count("Flows.analysis"), 1, "the click came before the result")
        await waitUntil { PaneProbe.flowsLadder?.subject == "\(short.clientEndpoint) → \(short.serverEndpoint)" }
        // Every analysis the ingest and the Follow asked for lands (the debounced one too).
        await waitUntil(8) { LeakProbe.count("Flows.analysis") == 0 && LeakProbe.count("Flows.scheduled") == 0 && tv.numberOfRows == flows2.count }
        await spin(1_300)
        await waitUntil(8) { LeakProbe.count("Flows.analysis") == 0 && LeakProbe.count("Flows.scheduled") == 0 }
        let shortNow = try XCTUnwrap(flows2.first { $0.key == short.key })
        XCTAssertEqual(PaneProbe.flowsLadder?.subject, "\(short.clientEndpoint) → \(short.serverEndpoint)",
                       "the pending Follow took the selection back from the click: \(String(describing: PaneProbe.flowsLadder))")
        XCTAssertEqual(tv.selectedRowIndexes, IndexSet(integer: try XCTUnwrap(Round11InteractionTests.flowRow(flows2, id: shortNow.id))))

        // The other order: a click, then a Follow for a frame the analysis already has — the Follow wins.
        let n = PaneProbe.flowAnalyses
        NotificationCenter.default.post(name: .sheepLogSelectFlow, object: FlowSelectRequest(key: target.key, packetID: frame))
        await waitUntil { PaneProbe.flowsLadder?.eventFrames == target.events[8].packetIDs }
        XCTAssertEqual(PaneProbe.flowsLadder?.subject, "\(target.clientEndpoint) → \(target.serverEndpoint)")
        XCTAssertEqual(PaneProbe.flowAnalyses, n, "resolved without another analysis")
    }

    // MARK: - 2. Troubleshoot: the rules over healthy device chatter

    static let testsDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().appending(path: "Tests")

    /// Lines as received live: every hostname from its own address, hostless lines from
    /// `hostless`, each arriving 250 ms after its own timestamp.
    static func live(_ lines: [String], hostless: String, firstID: Int = 1) -> [LogEntry] {
        var addresses: [String: String] = [:]
        var out: [LogEntry] = []
        var id = firstID
        // The day after the corpus (a year-less "Sep 23" is read as the latest Sep 23 before it).
        let base = Date(timeIntervalSince1970: 1_790_251_200)       // 2026-09-24 12:00 UTC
        for (k, line) in lines.enumerated() where !line.hasPrefix("#") && !line.isEmpty {
            let probe = SyslogParser.parse(RawSyslog(received: base, sourceAddress: "0.0.0.0", sourcePort: 514, transport: .udp, text: line), id: id)
            let host = probe.hostname
            let address: String
            if host.isEmpty || FText.isIPv4(host) { address = host.isEmpty ? hostless : host }
            else {
                if addresses[host] == nil { addresses[host] = "10.77.\(addresses.count / 250).\(addresses.count % 250 + 1)" }
                address = addresses[host]!
            }
            let received = (probe.deviceTime ?? base.addingTimeInterval(Double(k))).addingTimeInterval(0.25)
            out.append(SyslogParser.parse(RawSyslog(received: received, sourceAddress: address, sourcePort: 514, transport: .udp, text: line), id: id))
            id += 1
        }
        return out.sorted { $0.received < $1.received }
    }

    static func analyze(_ entries: [LogEntry] = [], packets: [Packet] = [], snmp: [SNMPSnapshot] = [], now: Date? = nil) -> TroubleshootResult {
        var input = TroubleshootInput()
        input.entries = entries
        input.packets = packets
        input.flows = TCPFlowAnalyzer.analyze(packets)
        input.snmp = snmp
        input.now = now ?? ((entries.map(\.received) + packets.map(\.timestamp)).max() ?? Date()).addingTimeInterval(60)
        return FindingRules.analyze(input)
    }

    static func keys(_ r: TroubleshootResult) -> Set<String> { Set(r.findings.map { "\($0.rule)|\($0.device ?? $0.client ?? "-")" }) }

    /// Every finding the rules raise over the corpus (healthy chatter with a few real errors) and
    /// the quiet fixtures is one the lines justify — listed here, file by file and all together.
    func testFindingsOverHealthyChatterAreJustified() throws {
        let expected: [String: Set<String>] = [
            // "Link status for interface 1/1/24 is down" and no up; a config change; PSU and fan failures.
            "arubacx": ["link.down|CX6300-CORE-01", "config.change|CX8360-AGG-02", "hw.psu|CX6300-ACC-12", "hw.fan|CX6300-ACC-12"],
            "arubaos": [], "arubasw": [], "clearpass": [], "checkpoint": [], "fortigate": [],
            // "neighbor state changed to Down", never back. Round 15's HW-NE40E peer and neighbor
            // came back (nothing); its lines run the file to 10:21, so the two ports that went
            // DOWN at 10:16 with no UP (10GE1/0/24, GigabitEthernet0/0/3) are now long down, as
            // they are in the files together.
            "huawei": ["routing.neighbor|S5720-CORE", "link.down|S5720-CORE", "link.down|HW-CE6881"],
            // A CONFIG log.
            "paloalto": ["config.change|PA-3220"],
            // Four interfaces down with no up line (CORE-RTR1's own clock is UTC: seven hours of
            // log, so they are long down) — one a Cisco `%LINK-3-UPDOWN` with no hostname, named
            // by its address; a "Configured from console". Round 13's vendor lines: a Junos commit
            // and a PEM (power supply) taken offline, an ASA write memory; their ports and
            // neighbours that went down came back (MikroTik, UniFi, EdgeOS, NX-OS, ASA, Junos).
            // Round 14's: an Arista configuration and an IOS XR commit; their ports (Arista,
            // Extreme, Ruckus, Meraki, IOS XR) came back, and Arista's BGP peer re-established.
            // Round 16's: Linux eth1 (ip monitor) and IOS Gi1/0/5 (err-disabled, recovered) came
            // back, docker0's NO-CARRIER is nothing; three BGP sessions whose MD5 password does not
            // match (IOS BADAUTH, Junos tcp_auth_ok, FRR bgpd + the Linux kernel: one peer) are.
            "other": ["link.down|CORE-RTR1", "link.down|N9K-LEAF-01", "link.down|web01", "link.down|HOSTLESS", "config.change|CORE-RTR1",
                      "config.change|MX204-EDGE", "hw.psu|MX204-EDGE", "config.change|ASA-FW02",
                      "config.change|LEAF-EOS-1", "config.change|XR-PE1",
                      "routing.authFail|EDGE-RTR3", "routing.authFail|MX204-EDGE", "routing.authFail|frr-edge1"],
        ]
        var all: [String] = []
        for (k, name) in expected.keys.sorted().enumerated() {
            let text = try String(contentsOf: Self.testsDir.appending(path: "corpus/\(name).log"), encoding: .utf8)
            let lines = text.split(whereSeparator: \.isNewline).map(String.init)
            all += lines
            let hostless = "10.78.0.\(k + 1)"
            let r = Self.analyze(Self.live(lines, hostless: hostless))
            XCTAssertEqual(Self.keys(r), Set(expected[name]!.map { $0.replacingOccurrences(of: "HOSTLESS", with: hostless) }),
                           "\(name): \(r.findings.map(\.title))")
        }
        // Together: each device's findings stay its own; ports down since the morning are now
        // long down (the combined log runs to CORE-RTR1's UTC-stamped 17:15).
        let r = Self.analyze(Self.live(all, hostless: "10.78.9.9"))
        let together = expected.values.reduce(Set<String>()) { $0.union($1) }.subtracting(["link.down|HOSTLESS"]).union([
            "link.down|10.1.0.20",          // AOS-S "port 24 is now off-line" (its header names 10.1.0.20); 1/1/24 on-line is another switch
            "link.down|10.78.9.9",          // AOS-S "port 12 is now off-line" and Cisco's Gi0/1 down (no hostname)
            "link.down|HW-CE6881",          // 10GE1/0/24 DOWN, twice, no UP
            "link.down|S5720-CORE",         // GigabitEthernet0/0/3 DOWN
        ])
        XCTAssertEqual(Self.keys(r), together, r.findings.map(\.title).joined(separator: "\n"))
        // The quiet fixtures and the round-9/10 shapes (error-level test chatter in one second,
        // FortiOS events of every level): nothing.
        for name in ["admin-ok", "hardware-ok", "link-ok", "routing-ok", "stp-ok"] {
            let text = try String(contentsOf: Self.testsDir.appending(path: "troubleshoot/\(name).log"), encoding: .utf8)
            let r = Self.analyze(TroubleshootFixture.liveEntries(text, firstID: 1))
            XCTAssertTrue(r.findings.isEmpty, "\(name): \(r.findings.map(\.title))")
        }
        var chatter = (0..<60).map { Round10InteractionTests.forti($0) }
        chatter += (0..<60).map { "<11>Sep 24 10:00:00 swA app: a \($0)" } + (0..<40).map { "<11>Sep 24 10:00:00 swB app: b \($0)" }
        chatter += (0..<500).map { "<11>Sep 24 10:00:00 sw app: late 1 \($0)" } + ["<13>Sep 24 10:00:00 FGT-100F-HQ app: hello from the firewall"]
        let quiet = Self.analyze(Self.live(chatter, hostless: "10.78.8.8"))
        XCTAssertTrue(quiet.findings.isEmpty, quiet.findings.map(\.title).description)
    }

    /// Normal events that are not problems: a reload the admin asked for (its boot lines and
    /// cold start after it were "unplanned, lost power or crashed"), the ports coming up after
    /// it, an admin's own login after one typo, a DHCP relay (the server's answer to the relay
    /// and the relay's to the client — with server-id override the relay names itself — were two
    /// "rogue" servers; its copies of a Discover counted twice), a mistyped name's NXDOMAIN with
    /// its search-domain variants (a third of the queries: "DNS server failed 33 %"), an mtr
    /// running for 20 s (time-exceeded from every hop: five "routing loops").
    func testNormalEventsAreNotProblems() throws {
        let t0 = Date(timeIntervalSinceReferenceDate: 780_000_000)
        // Reload, boot, the port up; an admin's login with one typo.
        let boot = [
            "<189>1 2026-09-23T03:00:00.000Z CORE-RTR1 - - - - %SYS-5-RELOAD: Reload requested by admin on vty0 (10.1.0.5). Reload Reason: Reload Command.",
            "<189>1 2026-09-23T03:04:10.000Z CORE-RTR1 - - - - %SYS-5-RESTART: System restarted --",
            "<189>1 2026-09-23T03:04:11.000Z CORE-RTR1 - - - - %SNMP-5-COLDSTART: SNMP agent on host CORE-RTR1 is undergoing a cold start",
            "<187>1 2026-09-23T03:04:20.000Z CORE-RTR1 - - - - %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up",
            "<189>1 2026-09-23T03:04:21.000Z CORE-RTR1 - - - - %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to up",
            "<188>1 2026-09-23T03:10:00.000Z CORE-RTR1 - - - - %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin] [Source: 10.1.0.5] [localport: 22] [Reason: Login Authentication Failed] at 03:10:00 UTC",
            "<189>1 2026-09-23T03:10:08.000Z CORE-RTR1 - - - - %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin] [Source: 10.1.0.5] [localport: 22] at 03:10:08 UTC",
            "<86>1 2026-09-23T03:11:00Z web01 sshd 4411 - - Accepted publickey for admin from 10.1.0.5 port 51234 ssh2",
        ]
        let r1 = Self.analyze(Self.live(boot, hostless: "10.78.0.1"))
        XCTAssertEqual(r1.findings.map(\.rule), ["device.restart"], r1.findings.map(\.title).description)
        let restart = try XCTUnwrap(r1.findings.first)
        XCTAssertEqual(restart.severity, .info, restart.title)
        XCTAssertFalse(restart.title.contains("cold start"), restart.title)
        XCTAssertTrue(restart.detail.contains("requested"), restart.detail)
        XCTAssertEqual(restart.count, 1, "one reload, not one per line: \(restart.title)")
        XCTAssertFalse(restart.title.contains("times in all"), restart.title)
        // The same boot lines with no reload asked for are still a warning (a crash, a power cut).
        let r1b = Self.analyze(Self.live(Array(boot.dropFirst()), hostless: "10.78.0.1"))
        XCTAssertEqual(r1b.findings.first { $0.rule == "device.restart" }?.severity, .warn)

        // DHCP through a relay, seen on a SPAN that carries both sides (no VLAN tags).
        func dhcp(_ t: Double, _ type: UInt8, src: String, dst: String, sport: Int, dport: Int, server: String?, xid: UInt32,
                  client: String = "02:00:5e:1e:00:31", yi: String = "0.0.0.0") -> (Double, [UInt8]) {
            let op: UInt8 = [2, 5, 6].contains(type) ? 2 : 1
            let m = TroubleshootFixture.dhcp(op: op, type: type, xid: xid, client: client, yiaddr: yi, server: server, lease: op == 2 ? 86_400 : nil)
            return (t, TroubleshootFixture.udp4(srcMAC: "00:1a:1e:00:00:0\(sport == 68 ? 2 : 1)", dstMAC: "00:1a:1e:00:00:03", src: src, dst: dst,
                                                sport: sport, dport: dport, vlan: nil, m))
        }
        func packets(_ frames: [(Double, [UInt8])]) -> [Packet] {
            frames.sorted { $0.0 < $1.0 }.enumerated().map { i, f in TroubleshootFixture.packet(f.1, at: t0.addingTimeInterval(f.0), id: i + 1, start: t0) }
        }
        for override in [false, true] {
            let id = override ? "10.1.30.1" : "10.1.0.10"      // option 54 as the client sees it
            var frames = [
                dhcp(0, 1, src: "0.0.0.0", dst: "255.255.255.255", sport: 68, dport: 67, server: nil, xid: 7),
                dhcp(0.001, 1, src: "10.1.30.1", dst: "10.1.0.10", sport: 67, dport: 67, server: nil, xid: 7),
                dhcp(0.010, 2, src: "10.1.0.10", dst: "10.1.30.1", sport: 67, dport: 67, server: "10.1.0.10", xid: 7, yi: "10.1.30.60"),
                dhcp(0.011, 2, src: "10.1.30.1", dst: "10.1.30.60", sport: 67, dport: 68, server: id, xid: 7, yi: "10.1.30.60"),
                dhcp(0.020, 3, src: "0.0.0.0", dst: "255.255.255.255", sport: 68, dport: 67, server: nil, xid: 7),
                dhcp(0.021, 3, src: "10.1.30.1", dst: "10.1.0.10", sport: 67, dport: 67, server: nil, xid: 7),
                dhcp(0.030, 5, src: "10.1.0.10", dst: "10.1.30.1", sport: 67, dport: 67, server: "10.1.0.10", xid: 7, yi: "10.1.30.60"),
                dhcp(0.031, 5, src: "10.1.30.1", dst: "10.1.30.60", sport: 67, dport: 68, server: id, xid: 7, yi: "10.1.30.60"),
            ]
            // A client that asked twice before the capture ended (the relay's copies are not two more asks).
            for (k, t) in [5.0, 9.0].enumerated() {
                frames.append(dhcp(t, 1, src: "0.0.0.0", dst: "255.255.255.255", sport: 68, dport: 67, server: nil, xid: 9, client: "02:00:5e:1e:00:77"))
                frames.append(dhcp(t + 0.001 + Double(k) * 0, 1, src: "10.1.30.1", dst: "10.1.0.10", sport: 67, dport: 67, server: nil, xid: 9, client: "02:00:5e:1e:00:77"))
            }
            frames.append(dhcp(40, 8, src: "10.1.30.60", dst: "10.1.0.10", sport: 68, dport: 67, server: nil, xid: 11))    // Inform: the capture runs on
            let r = Self.analyze(packets: packets(frames))
            XCTAssertTrue(r.findings.filter { $0.category == .dhcp }.isEmpty, "server-id override \(override): \(r.findings.map(\.title))")
            // A real second server on that segment is still one.
            let rogue = frames + [dhcp(0.012, 2, src: "192.168.1.1", dst: "255.255.255.255", sport: 67, dport: 68, server: "192.168.1.1", xid: 7, yi: "192.168.1.50")]
            let rr = Self.analyze(packets: packets(rogue))
            XCTAssertTrue(rr.findings.contains { $0.rule == "dhcp.twoServers" && $0.title.contains("192.168.1.1") }, rr.findings.map(\.title).description)
        }

        // DNS: 12 queries, the typo'd name (A and AAAA, bare and with the search domain) NXDOMAIN.
        var dns: [(Double, [UInt8])] = []
        for k in 0..<12 {
            let typo = k % 3 == 0
            let name = typo ? (k % 2 == 0 ? "wwww.gogle.com" : "wwww.gogle.com.corp.example") : "intranet\(k).corp.example"
            let sport = 41_000 + k
            dns.append((Double(k), TroubleshootFixture.udp4(srcMAC: "02:00:00:00:00:01", dstMAC: "02:00:00:00:00:02", src: "10.1.30.60", dst: "10.1.0.53",
                                                             sport: sport, dport: 53, vlan: nil, TroubleshootFixture.dns(id: k, name: name, response: false))))
            dns.append((Double(k) + 0.01, TroubleshootFixture.udp4(srcMAC: "02:00:00:00:00:02", dstMAC: "02:00:00:00:00:01", src: "10.1.0.53", dst: "10.1.30.60",
                                                                    sport: 53, dport: sport, vlan: nil,
                                                                    TroubleshootFixture.dns(id: k, name: name, response: true, rcode: typo ? 3 : 0, answer: typo ? nil : "10.1.40.\(k)"))))
        }
        let rd = Self.analyze(packets: packets(dns))
        XCTAssertTrue(rd.findings.filter { $0.category == .dns }.isEmpty, rd.findings.map(\.title).description)

        // mtr to 8.8.8.8 for 20 s: one probe per hop a second, five hops answer time-exceeded.
        let hops = ["10.1.30.1", "10.0.0.1", "203.0.113.1", "198.51.100.1", "192.0.2.1"]
        var mtr: [(Double, [UInt8])] = []
        for s in 0..<20 {
            for (h, router) in hops.enumerated() {
                let probe = PacketFixture.ipv4(src: "10.1.30.60", dst: "8.8.8.8", proto: 1, ttl: 1, [8, 0, 0, 0, 0x12, 0x34, 0, UInt8(s * 5 + h)])
                let body: [UInt8] = [11, 0, 0, 0, 0, 0, 0, 0] + probe
                mtr.append((Double(s) + Double(h) * 0.01, PacketFixture.ether(type: 0x0800, PacketFixture.ipv4(src: router, dst: "10.1.30.60", proto: 1, body))))
            }
        }
        let rm = Self.analyze(packets: packets(mtr))
        XCTAssertTrue(rm.findings.isEmpty, rm.findings.map(\.title).description)
        // A routing loop (one router expires every packet a host sends to a destination) still is one.
        let loop = (0..<12).map { k -> (Double, [UInt8]) in
            let probe = PacketFixture.ipv4(src: "10.1.30.60", dst: "172.16.9.9", proto: 17, ttl: 1, PacketFixture.udp(50_000 + k, 443, [0, 0, 0, 0]))
            return (Double(k), PacketFixture.ether(type: 0x0800, PacketFixture.ipv4(src: "10.0.0.2", dst: "10.1.30.60", proto: 1, [11, 0, 0, 0, 0, 0, 0, 0] + probe)))
        }
        XCTAssertEqual(Self.analyze(packets: packets(loop)).findings.map(\.rule), ["icmp.ttlExceeded"])
    }

    /// Cisco IOS's own line form (`seq: HOST: time: %FAC-n-MNEMONIC: text`) puts the mnemonic in
    /// the program: "neighbor 203.0.113.1 Up" and "Interface Gi0/1, changed state to down" were
    /// never read — a BGP peer that came back was "down and has not come back" (a Problem on a
    /// healthy router), a port flapping on LINK lines was nothing. Huawei's IF_STATE "has turned
    /// into DOWN state" was not read either.
    func testCiscoClassicAndHuaweiIFStateLinesAreRead() {
        let bgp = [
            "<189>41: EDGE-RTR2: Sep 23 10:10:00.000: %BGP-5-ADJCHANGE: neighbor 203.0.113.1 Down BGP Notification sent",
            "<189>42: EDGE-RTR2: Sep 23 10:10:40.000: %BGP-5-ADJCHANGE: neighbor 203.0.113.1 Up",
        ]
        let r = Self.analyze(Self.live(bgp, hostless: "10.78.1.1"))
        XCTAssertTrue(r.findings.isEmpty, r.findings.map(\.title).description)
        let stuck = Self.analyze(Self.live(Array(bgp.prefix(1)), hostless: "10.78.1.1"), now: Date(timeIntervalSince1970: 1_790_133_000))
        XCTAssertEqual(stuck.findings.map(\.rule), ["routing.neighbor"], "one that stays down still is one")
        var flap: [String] = []
        for k in 0..<3 {
            flap.append("<187>\(50 + 2 * k): CORE-SW1: Sep 23 10:0\(k):00.000: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/7, changed state to down")
            flap.append("<187>\(51 + 2 * k): CORE-SW1: Sep 23 10:0\(k):20.000: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/7, changed state to up")
            flap.append("<188>Sep 23 2026 10:0\(k):00+07:00 S5720-ACC %%01IFNET/4/IF_STATE(l)[\(k)]:Interface GigabitEthernet0/0/9 has turned into DOWN state.")
            flap.append("<188>Sep 23 2026 10:0\(k):30+07:00 S5720-ACC %%01IFNET/4/IF_STATE(l)[\(k)]:Interface GigabitEthernet0/0/9 has turned into UP state.")
        }
        let rf = Self.analyze(Self.live(flap, hostless: "10.78.1.2"))
        XCTAssertEqual(Self.keys(rf), ["link.flap|CORE-SW1", "link.flap|S5720-ACC"], rf.findings.map(\.title).description)
        XCTAssertTrue(rf.findings.allSatisfy { $0.detail.contains("came back each time") })
    }

    /// An access switch's walk: 20 enabled ports with nothing plugged in for weeks is its normal
    /// state (a note), not a warning; one that lost its link in the last hour is.
    func testEnabledPortsWithoutLinkAreANoteUnlessOneIsNew() {
        func walk(recent: Bool) -> SNMPSnapshot {
            var rows: [InterfaceRow] = []
            for i in 1...24 {
                var r = InterfaceRow(index: UInt32(i))
                r.name = "1/1/\(i)"; r.descr = r.name; r.type = "ethernetCsmacd"; r.admin = "up"
                r.oper = i <= 4 ? "up" : "down"
                r.speedBits = 1_000_000_000; r.lastChange = 100
                r.sinceChange = recent && i == 9 ? 30_000 : 200_000_000
                rows.append(r)
            }
            return SNMPSnapshot(host: "10.1.0.13", taken: Date(timeIntervalSince1970: 1_790_133_000), sysName: "SW-2930F-3F",
                                sysUpTime: 300_000_000, interfaces: rows, values: [.sysName: "SW-2930F-3F"])
        }
        let quiet = Self.analyze(snmp: [walk(recent: false)], now: Date(timeIntervalSince1970: 1_790_133_060))
        XCTAssertEqual(quiet.findings.map(\.rule), ["snmp.operDown"])
        XCTAssertEqual(quiet.findings.first?.severity, .info)
        let fresh = Self.analyze(snmp: [walk(recent: true)], now: Date(timeIntervalSince1970: 1_790_133_060))
        XCTAssertEqual(fresh.findings.first?.severity, .warn)
        XCTAssertTrue(fresh.findings.first?.detail.contains("1/1/9 went down 5 min before the walk") ?? false, fresh.findings.first?.detail ?? "")
    }

    // MARK: - 2. The timeline's edges

    /// A 30-day log (slots of 2 h) with a warning every 2 h and one at the very end: one dot per
    /// slot, each in its own. The slot math (`offset / span * 360`) put 20 of the exact slot
    /// boundaries one slot early, where the earlier event hid them. Also: the event at the end is
    /// in the last slot; a 1-second capture's strip is a minute wide with its finding at the start.
    func testTimelineSlotsAtTheEdges() throws {
        let t0 = Date(timeIntervalSince1970: 1_790_128_800)
        let slot = 7_200.0
        var entries: [LogEntry] = []
        for k in 0...360 {
            let t = t0.addingTimeInterval(Double(k) * slot)
            entries.append(parsedLine("<12>1 - SW-LONG app - - - disk usage warning \(k)", from: "10.1.0.77",
                                      received: t, id: k + 1))
        }
        let r = Self.analyze(entries, now: t0.addingTimeInterval(360 * slot + 60))
        let tl = r.timeline
        XCTAssertEqual(tl.start, t0)
        XCTAssertEqual(tl.end, t0.addingTimeInterval(360 * slot))
        XCTAssertEqual(tl.span / Double(TimelineBuilder.slots), slot, "30 days in 360 slots of 2 h")
        let lane = try XCTUnwrap(tl.lanes.first { $0.id == "SW-LONG" })
        XCTAssertEqual(lane.total, 361)
        XCTAssertEqual(lane.events.count, 360, "one dot per slot")
        let kept = Set(lane.events.map { Int($0.time.timeIntervalSince(t0) / slot) })
        XCTAssertEqual(kept, Set(0..<360), "every slot shows its own line (the last slot the earlier of its two)")
        for k in [13, 26, 49, 359] { XCTAssertEqual(TimelineBuilder.slot(Double(k) * slot, span: tl.span), k) }
        XCTAssertEqual(TimelineBuilder.slot(tl.span, span: tl.span), TimelineBuilder.slots - 1, "the end is the last slot")
        XCTAssertEqual(TimelineBuilder.slot(-5, span: tl.span), 0)
        XCTAssertEqual(tl.fraction(tl.end), 1)
        XCTAssertEqual(tl.date(atFraction: 1), tl.end)

        // A 1-second capture: four unanswered ARP requests for the gateway.
        let arp = (0..<4).map { k in
            TroubleshootFixture.packet(TroubleshootFixture.arp(request: true, senderMAC: "02:00:00:00:00:0\(k + 1)", senderIP: "10.1.20.\(50 + k)",
                                                               targetIP: "10.1.20.1", vlan: 20),
                                       at: t0.addingTimeInterval(Double(k) / 3), id: k + 1, start: t0)
        }
        let rc = Self.analyze(packets: arp)
        let tc = rc.timeline
        XCTAssertEqual(rc.findings.map(\.rule), ["arp.unanswered"])
        XCTAssertEqual(tc.start, t0)
        XCTAssertEqual(tc.end, t0.addingTimeInterval(60), "a strip under a minute is a minute wide")
        let capture = try XCTUnwrap(tc.lanes.first { $0.id == TimelineBuilder.captureLane }, tc.lanes.map(\.id).description)
        let bar = try XCTUnwrap(capture.events.first { $0.kind == .finding })
        XCTAssertEqual(bar.time, t0)
        XCTAssertEqual(tc.fraction(try XCTUnwrap(bar.end)), 1.0 / 60, accuracy: 1e-9)
    }

    /// The Markdown report: what a finding's title, detail, filter and next steps turn into, with
    /// the characters Markdown would eat.
    func testFindingsMarkdownExport() {
        let t0 = Date(timeIntervalSince1970: 1_790_128_800)
        var f = Finding(id: "x", rule: "link.flap", severity: .bad, category: .link, source: .logs,
                        title: "Port 1/1/*24* on SW_A|B went down 3 times.", detail: "Line one.\nLine `two` <b>.",
                        evidence: [Evidence(kind: .logLines, label: "3 log lines", ids: [1, 2, 3], query: "host:\"SW_A|B\" `x`")],
                        firstSeen: t0, lastSeen: t0.addingTimeInterval(125), count: 3, device: "SW_A|B", deviceAddress: "10.1.0.9",
                        client: "02:00:5e:00:00:01", nextSteps: ["Check [the cable]."])
        f.snmpTarget = "10.1.0.9"
        let note = Finding(id: "n", rule: "config.change", severity: .info, category: .config, source: .logs,
                           title: "Configuration changed on SW_A|B.", detail: "d", firstSeen: t0, lastSeen: t0)
        var summary = AnalysisSummary()
        summary.lines = 1_204; summary.devices = 1; summary.start = t0; summary.end = t0.addingTimeInterval(125)
        summary.notes = ["SNMP: no results yet."]
        let md = ReportText.findings([f, note], summary: summary, timeline: .empty, heading: "1 problem on SW_A|B.",
                                     scope: "Link, matching “*24*”", generated: t0)
        let lines = md.components(separatedBy: "\n")
        XCTAssertEqual(lines[0], "# SheepLog troubleshooting report")
        XCTAssertTrue(md.contains("**1 problem on SW\\_A\\|B.**"), md)
        XCTAssertTrue(md.contains("Analysed: 1,204 syslog lines, 0 traps from 1 device;"), md)
        XCTAssertTrue(md.contains("Shown: Link, matching “\\*24\\*”."), md)
        XCTAssertTrue(md.contains("## Problems (1)"))
        XCTAssertTrue(md.contains("### Port 1/1/\\*24\\* on SW\\_A\\|B went down 3 times."), md)
        XCTAssertTrue(md.contains("_Link · \(FText.clock(t0))–\(FText.clock(t0.addingTimeInterval(125))) · 3× · SW\\_A\\|B (10.1.0.9) · client 02:00:5e:00:00:01_"), md)
        XCTAssertTrue(md.contains("Line one. Line \\`two\\` \\<b\\>."), "one paragraph, nothing rendered: \(md)")
        XCTAssertTrue(md.contains("Evidence: 3 log lines — filter `host:\"SW_A|B\" 'x'`"), "the filter as typed, no backtick breaking the span: \(md)")
        XCTAssertTrue(md.contains("- Check \\[the cable\\]."))
        XCTAssertTrue(md.contains("## Notes (1)"))
        XCTAssertFalse(md.contains("## Warnings"))
        XCTAssertFalse(md.contains("## Timeline"), "no timeline section without a timeline")
        XCTAssertTrue(md.contains("## Not checked\n\n- SNMP: no results yet."))
        XCTAssertTrue(ReportText.findings([], summary: summary, timeline: .empty, heading: "h", scope: nil, generated: t0)
            .contains("Nothing wrong that SheepLog can see."))
    }

    // MARK: - 2. Troubleshoot during a flood

    /// 20,000 lines a second for 6.5 s while a capture of 10,000 authentication attempts is in
    /// memory and the pane is on screen: the re-analysis runs at most once every 2 s, and each
    /// holds the main actor < 16 ms (reading the stores, publishing the result). The Authentication
    /// findings were built on the main actor before every analysis (~0.7 s at 60,000 packets,
    /// Debug: every 2 s, the app froze for most of a second).
    func testTroubleshootDuringAFloodRunsEveryTwoSecondsOffTheMainThread() async throws {
        let model = TroubleshootModel.shared
        let logs = AppModel.shared.logs
        let packets = AppModel.shared.packets
        model.disappeared()
        logs.clear()
        packets.clear()
        FindingRules.authProvider = { AuthFindings.findings(from: $0) }
        packets.ingest(Self.tenThousandAttempts())
        // 130,000 lines, parsed before the flood (the parser's cost is the listener's, off-main).
        let first = LogStore.reserveIDs(130_000)
        let t0 = Date()
        let lines = (0..<130_000).map { k in
            parsedLine("<12>1 - SW-\(k % 40) ifmgr - - - Interface 1/1/\(k % 48) input errors \(k)", from: "10.60.0.\(k % 40 + 1)",
                       received: t0.addingTimeInterval(Double(k) / 20_000), id: first + k)
        }
        model.resetMainThreadCost()
        let before = PaneProbe.troubleshootAnalyses
        model.appeared()
        let started = Monotonic.now()
        var sent = 0
        while Monotonic.now() - started < 6.5 {
            let n = min(2_000, lines.count - sent)
            logs.ingest(Array(lines[sent..<(sent + n)]))
            sent += n
            try? await Task.sleep(for: .milliseconds(100))
        }
        await waitUntil(20) { !model.analysing && LeakProbe.count("Troubleshoot.analysis") == 0 }
        let times = PaneProbe.troubleshootAnalysisTimes.suffix(PaneProbe.troubleshootAnalyses - before)
        model.disappeared()
        let gaps = zip(times, times.dropFirst()).map { $1 - $0 }
        print("[perf] Troubleshoot flood: \(times.count) analyses, gaps \(gaps.map { String(format: "%.2f", $0) }), longest main-thread stretch \(String(format: "%.1f", model.longestMainThreadCost * 1000)) ms")
        XCTAssertGreaterThanOrEqual(times.count, 2, "it re-analyses while lines arrive")
        XCTAssertLessThanOrEqual(times.count, 5, "at most one analysis per 2 s")
        XCTAssertTrue(gaps.allSatisfy { $0 >= TroubleshootModel.debounce - 0.05 }, "\(gaps)")
        XCTAssertWithinBudget(model.longestMainThreadCost, 0.016, "an analysis's main-thread stretch")
        XCTAssertTrue(model.result?.findings.contains { $0.source == .auth } ?? false, "the Authentication findings are in")
        logs.clear()
    }

    /// PaneSwitchLeakTests switches every `MainPane` 200 times: Troubleshoot and Authentication
    /// are among them, and with data their analyses do run while shown and stop when left (the
    /// probes it compares are not vacuous for these two).
    func testPaneSwitchLeakTestCoversTroubleshootAndAuthentication() async throws {
        XCTAssertTrue(MainPane.allCases.contains(.troubleshoot))
        XCTAssertTrue(MainPane.allCases.contains(.auth))
        let model = AppModel.shared
        model.packets.clear()
        model.packets.ingest(Self.tenThousandAttempts())
        for (pane, probe) in [(MainPane.auth, "Auth.analysis"), (.troubleshoot, "Troubleshoot.analysis")] {
            model.mainPane = pane
            await waitUntil { LeakProbe.count(probe) == 1 }
            XCTAssertEqual(LeakProbe.count(probe), 1, "\(pane): no analysis while shown")
            model.mainPane = .status
            await waitUntil { LeakProbe.count(probe) == 0 }
            XCTAssertEqual(LeakProbe.count(probe), 0, "\(pane): the analysis outlived the pane")
        }
    }

    // MARK: - 3. Sweep: every finding's evidence button shows its evidence

    /// For every finding of the bad day, the corpus, the boot / login lines and the classic Cisco
    /// lines: "Show" on each log / trap / packet evidence puts its filter on the Log or Packets
    /// pane (through `TroubleshootJump`, as the button does) and that filter shows every line or
    /// frame the finding was built from.
    func testEveryEvidenceFilterShowsItsEvidence() async throws {
        let logs = AppModel.shared.logs
        let packets = AppModel.shared.packets
        logs.clear()
        packets.clear()
        var text: [String] = []
        for name in ["arubacx", "huawei", "paloalto", "other"] {
            text += try String(contentsOf: Self.testsDir.appending(path: "corpus/\(name).log"), encoding: .utf8)
                .split(whereSeparator: \.isNewline).map(String.init)
        }
        for name in ["bad-day", "admin", "hardware", "link-flap", "routing", "stp"] {
            text += try String(contentsOf: Self.testsDir.appending(path: "troubleshoot/\(name).log"), encoding: .utf8)
                .split(whereSeparator: \.isNewline).map(String.init)
        }
        text += [
            "<189>1 2026-09-23T03:00:00.000Z CORE-RTR9 - - - - %SYS-5-RELOAD: Reload requested by admin on vty0 (10.1.0.5). Reload Reason: Reload Command.",
            "<189>1 2026-09-23T03:04:10.000Z CORE-RTR9 - - - - %SYS-5-RESTART: System restarted --",
            "<189>1 2026-09-23T03:04:11.000Z CORE-RTR9 - - - - %SNMP-5-COLDSTART: SNMP agent on host CORE-RTR9 is undergoing a cold start",
            "<189>41: EDGE-RTR3: Sep 23 10:10:00.000: %BGP-5-ADJCHANGE: neighbor 203.0.113.9 Down BGP Notification sent",
            "<187>60: CORE-SW9: Sep 23 10:00:00.000: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/7, changed state to down",
            "<187>61: CORE-SW9: Sep 23 10:01:00.000: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/7, changed state to up",
            "<187>62: CORE-SW9: Sep 23 10:02:00.000: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/7, changed state to down",
            "<187>63: CORE-SW9: Sep 23 10:03:00.000: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/7, changed state to up",
            "<187>64: CORE-SW9: Sep 23 10:04:00.000: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/7, changed state to down",
        ]
        let entries = Self.live(text, hostless: "10.78.5.5", firstID: LogStore.reserveIDs(text.count + 10))
        let start = try XCTUnwrap(entries.compactMap(\.deviceTime).min())
        let pk = TroubleshootFixture.badDayPackets(start: start)
        logs.ingest(entries)
        packets.ingest(pk)
        let r = Self.analyze(entries, packets: pk)
        XCTAssertGreaterThan(r.findings.count, 20)
        var checked = 0
        for f in r.findings {
            for e in f.evidence where !e.ids.isEmpty {
                switch e.kind {
                case .logLines, .traps:
                    TroubleshootJump.show(e)
                    XCTAssertEqual(AppModel.shared.mainPane, .log)
                    XCTAssertNil(logs.queryError, "\(f.rule) \(e.query)")
                    XCTAssertEqual(logs.query.source, e.query)
                    // The table once the rescan landed: what the filter in force matches.
                    let filter = LogFilter(query: logs.query, source: logs.selectedSource, mask: logs.severityMask)
                    let expected = logs.entries.filter { filter.matches($0) }.map(\.id)
                    await waitUntil { logs.visible.map(\.id) == expected }
                    XCTAssertEqual(logs.visible.map(\.id), expected)
                    let shown = Set(logs.visible.map(\.id))
                    XCTAssertTrue(shown.isSuperset(of: e.ids),
                                  "\(f.rule) “\(f.title)”: filter `\(e.query)` hides \(Set(e.ids).subtracting(shown).compactMap { id in entries.first { $0.id == id }?.message })")
                case .packets:
                    TroubleshootJump.show(e)
                    XCTAssertEqual(AppModel.shared.mainPane, .packets)
                    let matcher = PacketMatcher(try Query.parse(e.query))
                    let expected = packets.packets.filter { matcher.matches($0) }.map(\.id)
                    await waitUntil { packets.queryText == e.query && packets.visible.map(\.id) == expected }
                    XCTAssertEqual(packets.visible.map(\.id), expected, e.query)
                    XCTAssertTrue(Set(packets.visible.map(\.id)).isSuperset(of: e.ids), "\(f.rule): `\(e.query)`")
                case .flows:
                    continue
                }
                checked += 1
            }
        }
        XCTAssertGreaterThan(checked, 20)
        logs.queryText = ""
        logs.applyQueryText()
    }

    /// A RADIUS-only attempt with no MAC (`user:erin`) is a finding with that client: its
    /// "Troubleshoot user:erin" button could only beep (the report takes a MAC or an IP).
    func testReportButtonOnlyForAClientItCanReport() throws {
        var lab = AuthLab(client: [0x02, 0x31, 0, 0, 0, 1])
        lab.toServer([AuthLab.text(1, "erin@corp.example"), AuthLab.attr(4, AuthLab.ip4(AuthLab.nasIP)), AuthLab.text(2, "pw")])
        lab.toNAS(code: 3, [AuthLab.text(18, "denied")])
        let f = try XCTUnwrap(AuthFindings.findings(from: lab.packets).first)
        XCTAssertEqual(f.client, "user:erin@corp.example")
        XCTAssertNil(FindingRow.reportTarget(f))
        var byMAC = f
        byMAC.client = "0200.5e14.0021"
        XCTAssertEqual(FindingRow.reportTarget(byMAC), "0200.5e14.0021")
        byMAC.client = "10.1.30.60"
        XCTAssertEqual(FindingRow.reportTarget(byMAC), "10.1.30.60")
    }

    /// The Log pane paused (the user reading), and a port starts flapping: the lines are held
    /// back from the Log's table — and were from Troubleshoot's checks too, until Resume.
    func testPausedLogStillFeedsTroubleshoot() async throws {
        let logs = AppModel.shared.logs
        let model = TroubleshootModel.shared
        model.disappeared()
        logs.clear()
        logs.paused = true
        defer { logs.paused = false }
        var lines: [String] = []
        for k in 0..<3 {
            lines.append("<187>1 2026-09-23T03:0\(k):00.000Z CORE-SW7 - - - - %LINK-3-UPDOWN: Interface GigabitEthernet1/0/3, changed state to down")
            lines.append("<187>1 2026-09-23T03:0\(k):20.000Z CORE-SW7 - - - - %LINK-3-UPDOWN: Interface GigabitEthernet1/0/3, changed state to up")
        }
        logs.ingest(Self.live(lines, hostless: "10.78.6.6", firstID: LogStore.reserveIDs(lines.count)))
        XCTAssertEqual(logs.entries.count, 0)
        XCTAssertEqual(logs.pausedCount, 6)
        let before = PaneProbe.troubleshootAnalyses
        model.appeared()
        await waitUntil(10) { PaneProbe.troubleshootAnalyses > before && !model.analysing && LeakProbe.count("Troubleshoot.analysis") == 0 }
        model.disappeared()
        let r = try XCTUnwrap(model.result)
        // (The SNMP Test pane's results of other tests may add SNMP findings: the log's are these.)
        XCTAssertEqual(r.findings.filter { $0.source == .logs }.map(\.rule), ["link.flap"], r.findings.map(\.title).description)
        XCTAssertEqual(r.summary.lines, 6)
        // "Show" puts the filter on the paused Log, which says the lines are waiting.
        let e = try XCTUnwrap(r.findings.first { $0.rule == "link.flap" }?.evidence.first)
        TroubleshootJump.show(e)
        XCTAssertTrue(LogView.noMatchText(entries: logs.entries.count, query: true, source: nil, masked: false, held: logs.pausedCount)
            .contains("Paused — 6 newer lines are waiting"))
        logs.paused = false
        let filter = LogFilter(query: logs.query, source: nil, mask: logs.severityMask)
        await waitUntil { logs.visible.count == 6 }
        XCTAssertEqual(Set(logs.visible.map(\.id)), Set(e.ids))
        XCTAssertTrue(logs.entries.allSatisfy { filter.matches($0) })
        logs.queryText = ""
        logs.applyQueryText()
    }

    /// A Troubleshoot authentication finding's packets: the attempt's frames, not the range of
    /// frames with every other client's authentication traffic of those seconds (the round-11
    /// fix of the Authentication pane's Show packets, which the finding did not use: from 51
    /// frames it listed a range).
    func testAuthFindingEvidenceIsTheAttemptsFrames() throws {
        var a = AuthLab(client: [0x02, 0x32, 0, 0, 0, 1])
        a.peap(user: "fay@corp.example", succeed: false, rounds: 14, ip: "10.20.0.61")
        var b = AuthLab(client: [0x02, 0x32, 0, 0, 0, 2], at: 0.001)
        b.authenticator = [0x00, 0x0b, 0x86, 0x10, 0x20, 0x40]
        b.peap(user: "gus@corp.example", succeed: true, rounds: 14, ip: "10.20.0.62")
        let all = Self.renumbered((a.packets + b.packets).sorted { $0.timestamp < $1.timestamp })
        let s = try XCTUnwrap(AuthSessions.build(all).first { $0.client == a.clientText })
        XCTAssertGreaterThan(s.packetIDs.count, 50)
        let f = try XCTUnwrap(AuthFindings.findings(from: all).first { $0.client == a.clientText })
        let e = try XCTUnwrap(f.evidence.first)
        let matcher = PacketMatcher(try Query.parse(e.query))
        XCTAssertEqual(all.filter { matcher.matches($0) }.map(\.id), s.packetIDs, e.query.prefix(200).description)
    }

    /// A switch port's unanswered request selected in the Authentication pane; then the device
    /// answers. The port's attempt becomes the device's: the selection follows its frames (it
    /// vanished — the new attempt had another client).
    func testSelectedPortAttemptFollowsTheDeviceThatAnswers() throws {
        var lab = AuthLab(client: [0x02, 0x33, 0, 0, 0, 1])
        lab.authenticator = Self.silentPort
        lab.add(Self.eapolFrame(dst: AuthLab.pae, src: Self.silentPort, AuthLab.eap(code: 1, id: 1, type: 1)), dt: 0)
        lab.dhcpExchange(ip: "10.20.0.70", dt: 2)
        let early = lab.packets
        let s1 = AuthSessions.build(early)
        let port = try XCTUnwrap(s1.first { $0.isPortOnly })
        var state = AuthSelectionState()
        state.selection = port.id
        state.selectionChanged(in: s1)
        state.event = port.events.first?.id
        XCTAssertEqual(state.client, port.client)
        // The device answers the switch's retransmission (same id, 30 s on).
        lab.add(Self.eapolFrame(dst: AuthLab.pae, src: Self.silentPort, AuthLab.eap(code: 1, id: 1, type: 1)), dt: 30)
        lab.eapID = 1
        lab.eapFromClient(type: 1, Array("hal".utf8))
        lab.eapToClient(code: 3)
        let s2 = AuthSessions.build(lab.packets)
        XCTAssertFalse(s2.contains { $0.isPortOnly })
        let device = try XCTUnwrap(s2.first { $0.client == lab.clientText })
        XCTAssertTrue(device.packetIDs.contains(1), "the port's request is the device's attempt's")
        state.apply(s2, previous: s1)
        if state.pendingEventFrames != nil || state.selection != port.id { state.selectionChanged(in: s2) }
        XCTAssertEqual(state.selection, device.id)
        XCTAssertEqual(state.client, device.client)
        XCTAssertEqual(state.event.flatMap { id in device.events.first { $0.id == id }?.packetIDs.first }, 1, "the same step")
    }

    /// A TCP finding's "flow" evidence goes to the Flows pane on that conversation (through the
    /// app window's pane switch, as the button does) — every one of the demo day's.
    func testTroubleshootFlowEvidenceOpensItsConversation() async throws {
        let model = AppModel.shared
        let packets = model.packets
        packets.clear()
        model.mainPane = .status
        await spin(100)
        let t0 = Date(timeIntervalSince1970: 1_790_128_800)
        let pk = TroubleshootFixture.demoFlows(start: t0)
        packets.ingest(pk)
        let r = Self.analyze(packets: pk)
        let refs = r.findings.flatMap { f in f.evidence.filter { $0.kind == .flows }.flatMap(\.flows) }
        XCTAssertGreaterThanOrEqual(refs.count, 3, r.findings.map(\.title).description)
        let flows = TCPFlowAnalyzer.analyze(pk)
        for ref in refs {
            let flow = try XCTUnwrap(FlowSelectRequest.match(flows, key: ref.key, packetID: ref.packetID))
            model.mainPane = .status
            await spin(50)
            TroubleshootJump.flow(ref)
            XCTAssertEqual(model.mainPane, .flows)
            await waitUntil { PaneProbe.flowsLadder?.firstFrame == flow.firstPacketID }
            XCTAssertEqual(PaneProbe.flowsLadder?.subject, "\(flow.clientEndpoint) → \(flow.serverEndpoint)")
            XCTAssertEqual(PaneProbe.flowsLadder?.firstFrame, flow.firstPacketID)
        }
        model.mainPane = .status
    }

    /// The Packets pane's interface picker had no row for a chosen interface that is not in the
    /// list (still loading, or an adapter unplugged): a blank picker and SwiftUI's "selection is
    /// invalid" warning (three times in a full test run). Settings had a row, but only once the
    /// list had loaded.
    func testInterfacePickerAlwaysHasARowForTheChoice() {
        let en0 = CaptureInterface(name: "en0", description: "Wi-Fi", addresses: ["192.168.1.36"], isUp: true, isLoopback: false)
        XCTAssertNil(InterfacePicker.extraRow(selected: "", among: []))
        XCTAssertNil(InterfacePicker.extraRow(selected: "en0", among: [en0]))
        XCTAssertEqual(InterfacePicker.extraRow(selected: "lo0", among: []), "lo0", "while the list loads")
        XCTAssertEqual(InterfacePicker.extraRow(selected: "en7", among: [en0]), "en7 — not present (Automatic is used)")
    }

    // MARK: - 2. Troubleshoot client

    /// "Troubleshoot client" with an address that is only in log message text — an ASA's
    /// `inside:10.1.0.80/22` (the colon glued the address to "inside", so every ASA line was
    /// missed), a MikroTik's `ip:port->ip:port`, a FortiGate's `dstip=` — and a MAC typed in
    /// Cisco form that the logs spell every way; findings about a longer address that starts
    /// with this one are not this client's.
    func testClientReportFindsAddressesInMessageText() throws {
        let lines = [
            "<164>Sep 23 2026 10:15:37 ASA-FW01 : %ASA-4-106023: Deny tcp src outside:203.0.113.9/51234 dst inside:10.1.0.80/22 by access-group \"outside_in\" [0x0, 0x0]",
            "<30>Sep 23 10:16:05 RB4011-HQ firewall,info input: in:ether1 out:(unknown 0), src-mac 02:00:5e:aa:bb:cc, proto TCP (SYN), 203.0.113.9:51234->10.1.0.80:22, len 60",
            "<189>date=2026-09-23 time=10:16:10 devname=\"FGT-100F-HQ\" devid=\"FGT1HFTK21000000\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"notice\" vd=\"root\" srcip=10.1.0.9 srcport=50000 srcintf=\"internal\" dstip=10.1.0.80 dstport=22 action=\"deny\" policyid=3 service=\"SSH\" proto=6",
            "<189>date=2026-09-23 time=10:16:11 devname=\"FGT-100F-HQ\" devid=\"FGT1HFTK21000000\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"notice\" vd=\"root\" srcip=10.1.0.9 srcport=50001 srcintf=\"internal\" dstip=10.1.0.8 dstport=22 action=\"deny\" policyid=3 service=\"SSH\" proto=6",
            "<14>Sep 23 10:16:10 SW-5406R-CORE 02101 802.1x: port A5 - client 0200.5e14.0021 authenticated",
            "<131>Sep 23 10:16:12 2026 MD-7210-1 authmgr[4211]: <522275> <4211> <ERRS> <MD-7210-1 10.1.1.11>  User Authentication failed. username=bob MAC=02:00:5e:14:00:21 IP=0.0.0.0",
            "<14>Sep 23 10:16:14 cppm01 CPPM_Endpoint_Logs 1240 1 0 Endpoint.MAC-Address=02005e140021,Endpoint.Status=Known",
            "<14>Sep 23 10:16:15 cppm01 CPPM_Endpoint_Logs 1241 1 0 Endpoint.MAC-Address=02005e140022,Endpoint.Status=Known",
        ]
        var input = TroubleshootInput()
        input.entries = Self.live(lines, hostless: "10.78.2.1")
        input.now = Date(timeIntervalSince1970: 1_790_133_600)
        let dup = Finding(id: "arp.dup|10.1.0.80", rule: "arp.duplicateIP", severity: .bad, category: .arpIP, source: .packets,
                          title: "Duplicate IP 10.1.0.80: claimed by 2 MAC addresses.", detail: "…", firstSeen: input.now, lastSeen: input.now, client: "10.1.0.80")
        let longer = Finding(id: "arp.dup|10.1.0.8", rule: "arp.duplicateIP", severity: .bad, category: .arpIP, source: .packets,
                             title: "Duplicate IP 10.1.0.8: claimed by 2 MAC addresses.", detail: "Traffic for 10.1.0.8 goes to whichever answered last.",
                             firstSeen: input.now, lastSeen: input.now)
        let report = try XCTUnwrap(ClientReport.build("10.1.0.8", input: input, findings: [dup, longer]))
        XCTAssertEqual(report.logTotal, 1, report.logLines.map(\.message).description)
        XCTAssertEqual(report.findings.map(\.id), ["arp.dup|10.1.0.8"], "10.1.0.80's finding is not 10.1.0.8's")
        let server = try XCTUnwrap(ClientReport.build("10.1.0.80", input: input, findings: [dup, longer]))
        XCTAssertEqual(server.logTotal, 3, "ASA, MikroTik and FortiGate lines: \(server.logLines.map(\.device))")
        XCTAssertEqual(Set(server.logLines.map(\.device)), ["ASA-FW01", "RB4011-HQ", "FGT-100F-HQ"])
        XCTAssertEqual(server.findings.map(\.id), ["arp.dup|10.1.0.80"])
        XCTAssertTrue(server.markdown.contains("## Log lines (3)"), server.markdown)
        // A MAC typed in Cisco form, upper case: every spelling in the logs (not its neighbour ...0022).
        let mac = try XCTUnwrap(ClientReport.build("0200.5E14.0021", input: input, findings: []))
        XCTAssertEqual(mac.macs, ["02:00:5e:14:00:21"])
        XCTAssertEqual(mac.logTotal, 3, mac.logLines.map(\.message).description)
        XCTAssertTrue(mac.location.contains { $0.contains("SW-5406R-CORE — port A5") }, mac.location.description)
        XCTAssertTrue(mac.markdown.contains("# Client 02:00:5e:14:00:21"))
        // "10.1.0.80." at the end of a sentence and "[10.1.0.80]" count; "10.1.0.800" never parses.
        XCTAssertTrue("seen at 10.1.0.80.".withCString { ClientSearch.contains($0, "10.1.0.80") })
        XCTAssertTrue("peer [10.1.0.80]:443".withCString { ClientSearch.contains($0, "10.1.0.80") })
        XCTAssertFalse("fe80::10.1.0.801".withCString { ClientSearch.contains($0, "10.1.0.80") })
        XCTAssertFalse("fe80::1:2".withCString { ClientSearch.contains($0, "fe80::1") }, "IPv6 still glues on ':'")
    }

    /// A relay (or a stack) sending several hostnames from one address, and a line of it with no
    /// hostname: the finding went to the relay's most frequent device — a port of another box.
    func testHostlessLineFromAMultiHostAddressNamesTheAddress() {
        let lines = [
            "<189>Sep 23 10:00:00 SW-A app: hello", "<189>Sep 23 10:00:01 SW-A app: hello", "<189>Sep 23 10:00:02 SW-A app: hello",
            "<189>Sep 23 10:00:03 SW-B app: hello",
            "<187>Sep 23 10:00:05 %LINK-3-UPDOWN: Interface GigabitEthernet0/5, changed state to down",
        ]
        let t0 = Date(timeIntervalSince1970: 1_790_128_800)       // 2026-09-23 10:00 +07
        let entries = lines.enumerated().map { k, l in parsedLine(l, from: "10.1.0.250", received: t0.addingTimeInterval(Double(k)), id: k + 1) }
        XCTAssertEqual(entries.last?.hostname, "")
        let r = Self.analyze(entries, now: t0.addingTimeInterval(900))
        let f = r.findings.first { $0.rule == "link.down" }
        XCTAssertEqual(f?.device, "10.1.0.250", r.findings.map(\.title).description)
        // A device with one name still names its hostless lines.
        let one = lines.filter { !$0.contains("SW-B") }.enumerated().map { k, l in parsedLine(l, from: "10.1.0.251", received: t0.addingTimeInterval(Double(k)), id: k + 1) }
        XCTAssertEqual(Self.analyze(one, now: t0.addingTimeInterval(900)).findings.first { $0.rule == "link.down" }?.device, "SW-A")
    }

    static func tablesIn(_ view: NSView) -> [NSTableView] {
        var out: [NSTableView] = []
        func walk(_ v: NSView) {
            if let t = v as? NSTableView { out.append(t) }
            for s in v.subviews { walk(s) }
        }
        walk(view)
        return out
    }

    // MARK: - 1b. Five clients group-addressing one SPAN

    /// One wired 802.1X exchange where both sides address every frame to the PAE group,
    /// frames tagged with their client.
    static func groupExchange(client: [UInt8], sw: [UInt8], idBase: UInt8, succeed: Bool) -> [(bytes: [UInt8], owner: Int)] {
        let owner = Int(client[5])
        var out: [(bytes: [UInt8], owner: Int)] = []
        func c(_ eap: [UInt8], type: UInt8 = 0) { out.append((eapolFrame(dst: AuthLab.pae, src: client, eap, type: type), owner)) }
        func s(_ eap: [UInt8]) { out.append((eapolFrame(dst: AuthLab.pae, src: sw, eap), owner)) }
        c([], type: 1)
        s(AuthLab.eap(code: 1, id: idBase, type: 1))
        c(AuthLab.eap(code: 2, id: idBase, type: 1, Array("user\(owner)".utf8)))
        s(AuthLab.eap(code: 1, id: idBase &+ 1, type: 25, AuthLab.tlsData(start: true)))
        for k in 0..<3 {
            c(AuthLab.eap(code: 2, id: idBase &+ UInt8(1 + k), type: 25, AuthLab.tlsData(bytes: 60 + k)))
            s(AuthLab.eap(code: 1, id: idBase &+ UInt8(2 + k), type: 25, AuthLab.tlsData(bytes: 60)))
        }
        c(AuthLab.eap(code: 2, id: idBase &+ 4, type: 25, AuthLab.tlsData(bytes: 10)))
        s(AuthLab.eap(code: succeed ? 3 : 4, id: idBase &+ 4))
        return out
    }

    /// The exchanges merged in a seeded random order (each keeps its own order), 2 ms apart.
    static func interleave(_ exchanges: [[(bytes: [UInt8], owner: Int)]], seed: UInt64) -> (packets: [Packet], owner: [Int: Int]) {
        var rng = SplitMix(seed: seed)
        var cursors = exchanges.map { _ in 0 }
        var lab = AuthLab(client: [0, 0, 0, 0, 0, 0])
        var owner: [Int: Int] = [:]
        while true {
            let open = cursors.indices.filter { cursors[$0] < exchanges[$0].count }
            guard !open.isEmpty else { break }
            let k = open[Int(rng.next() % UInt64(open.count))]
            let item = exchanges[k][cursors[k]]
            cursors[k] += 1
            lab.add(item.bytes, dt: 0.002)
            owner[lab.packets.count] = item.owner
        }
        return (lab.packets, owner)
    }

    /// Five clients on five ports of one SPAN, every EAPOL frame to 01:80:c2:00:00:03, their
    /// exchanges interleaved: the switch's frames go to the client whose exchange they continue
    /// (EAP ids), bound by the client's own reply; no attempt holds two clients' frames. Before:
    /// the switch's frames went to the client last bound to the authenticator (one switch MAC)
    /// or were dropped (per-port MACs, several talkers).
    func testFiveGroupTalkingClientsOnOneSPAN() throws {
        let clients: [[UInt8]] = (1...5).map { [0x02, 0x13, 0, 0, 0, UInt8($0)] }
        for oneSwitchMAC in [true, false] {
            for seed in UInt64(1)...UInt64(12) {
                let exchanges = clients.enumerated().map { k, c in
                    Self.groupExchange(client: c, sw: oneSwitchMAC ? [0x00, 0x1c, 0x0e, 0, 1, 0] : [0x00, 0x1c, 0x0e, 0, 1, UInt8(k + 1)],
                                       idBase: UInt8(20 * (k + 1)), succeed: k != 2)
                }
                let (packets, owner) = Self.interleave(exchanges, seed: seed)
                let sessions = AuthSessions.build(packets)
                let tag = "one switch MAC \(oneSwitchMAC), seed \(seed)"
                for s in sessions {
                    let owners = Set(s.packetIDs.compactMap { owner[$0] })
                    XCTAssertEqual(owners.count, 1, "\(tag): \(s.client) holds frames of clients \(owners.sorted())")
                    if let o = owners.first { XCTAssertEqual(s.client, AuthLab.macText(clients[o - 1]), tag) }
                }
                // Distinct EAP ids per port: every frame placed, every outcome right.
                XCTAssertEqual(sessions.count, 5, "\(tag): \(sessions.map { "\($0.client) \($0.result)" })")
                XCTAssertEqual(sessions.flatMap(\.packetIDs).sorted(), packets.map(\.id), tag)
                for (k, c) in clients.enumerated() {
                    let s = try XCTUnwrap(sessions.first { $0.client == AuthLab.macText(c) }, tag)
                    XCTAssertEqual(s.result, k == 2 ? .rejected("EAP-Failure") : .accepted, "\(tag) client \(k + 1)")
                    XCTAssertEqual(s.user, "user\(k + 1)", tag)
                    XCTAssertEqual(s.method, .dot1x("PEAP"), tag)
                }
            }
        }
        // The same EAP ids on every port (one switch MAC): the switch's frames cannot be told
        // apart — nobody's, never another client's, and no "no supplicant" invented for them.
        for seed in UInt64(1)...UInt64(12) {
            let exchanges = clients.map { Self.groupExchange(client: $0, sw: [0x00, 0x1c, 0x0e, 0, 1, 0], idBase: 1, succeed: true) }
            let (packets, owner) = Self.interleave(exchanges, seed: seed)
            let sessions = AuthSessions.build(packets)
            for s in sessions {
                let owners = Set(s.packetIDs.compactMap { owner[$0] })
                XCTAssertLessThanOrEqual(owners.count, 1, "seed \(seed): \(s.client) mixes clients \(owners.sorted())")
                XCTAssertFalse(s.isPortOnly, "seed \(seed): the requests were answered")
            }
        }
    }
}
