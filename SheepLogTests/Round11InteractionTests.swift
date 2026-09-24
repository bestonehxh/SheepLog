import AppKit
import SwiftUI
import XCTest
@testable import SheepLog

/// Round 11: the Flows and Authentication panes driven through their real SwiftUI views (hosted
/// in a window: table rows selected on the NSTableView; buttons and ladder taps through
/// `PaneProbe`, which runs the views' own closures — a unit-test host has no accessibility tree
/// and SwiftUI takes no synthesized clicks; what the ladder drew read back from `PaneProbe`), the Packets pane during a live lo0 capture,
/// state across pane switches, the Sources table under 4 Hz updates, adversarial authentication
/// input — and the round's regressions.
@MainActor
final class Round11InteractionTests: XCTestCase {
    private var windows: [NSWindow] = []
    private var cleanup: [URL] = []

    override func tearDown() async throws {
        for w in windows { w.contentView = nil; w.close() }
        windows = []
        for u in cleanup { try? FileManager.default.removeItem(at: u) }
        cleanup = []
        let packets = AppModel.shared.packets
        packets.paused = false
        packets.limit = 200_000
        packets.queryText = ""
        packets.applyQueryNow(synchronous: true)
        packets.clear()
        AppModel.shared.mainPane = .status
        try? await Task.sleep(for: .milliseconds(50))
    }

    // MARK: - Harness

    /// `view` in its own window, shown (SwiftUI lays out and draws only in a window on screen).
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

    static func tables(in view: NSView) -> [NSTableView] {
        var out: [NSTableView] = []
        func walk(_ v: NSView) {
            if let t = v as? NSTableView { out.append(t) }
            for s in v.subviews { walk(s) }
        }
        walk(view)
        return out
    }

    /// SwiftUI's scroll views in `view` (the ladder is the content of one).
    static func hostingScrollViews(in view: NSView) -> [NSScrollView] {
        var out: [NSScrollView] = []
        func walk(_ v: NSView) {
            if let s = v as? NSScrollView, String(describing: type(of: s)).contains("HostingScrollView") { out.append(s) }
            for c in v.subviews { walk(c) }
        }
        walk(view)
        return out
    }

    /// The width the ladder is laid out at (its scroll view's), for `AuthLadderLayout.make`.
    static func ladderWidth(in view: NSView, minimum: CGFloat) -> CGFloat {
        let widths = hostingScrollViews(in: view).map(\.frame.width).filter { $0 > 200 }
        return max(minimum, widths.max() ?? minimum)
    }

    // MARK: - Fixtures

    /// A short conversation, then a long one (spaced exchanges: one ladder event each).
    static func conversations(firstID: Int = 1, offset: Double = 0, port: UInt16 = 50_000) -> [Packet] {
        var a = TCPFlowDemo.Script(firstID: firstID, offset: offset, client: "10.1.0.5", clientPort: port,
                                   server: "10.2.0.1", serverPort: 443)
        a.handshake(rtt: 0.01)
        a.c(0.02, [.psh, .ack], len: 100)
        a.s(0.03, [.psh, .ack], len: 200)
        a.c(0.04, [.fin, .ack]); a.s(0.05, [.fin, .ack]); a.c(0.06, .ack)
        var b = TCPFlowDemo.Script(firstID: a.nextID, offset: offset + 0.1, client: "10.1.0.5", clientPort: port + 1,
                                   server: "10.2.0.2", serverPort: 443)
        b.handshake(rtt: 0.01)
        for k in 0..<20 {
            let t = 0.1 + Double(k) * 0.3
            b.c(t, [.psh, .ack], len: 100 + k)
            b.s(t + 0.02, [.psh, .ack], len: 1_000 + k)
            b.c(t + 0.04, .ack)
        }
        return (a.packets + b.packets).sorted { $0.timestamp == $1.timestamp ? $0.id < $1.id : $0.timestamp < $1.timestamp }
    }

    /// One bulk transfer of `pairs` data + ACK segments (an analysis that takes a moment).
    static func bulk(firstID: Int, offset: Double, pairs: Int, port: UInt16 = 40_000) -> [Packet] {
        var c = TCPFlowDemo.Script(firstID: firstID, offset: offset, client: "10.9.0.9", clientPort: port,
                                   server: "10.9.0.1", serverPort: 445)
        c.handshake(rtt: 0.001)
        for k in 0..<pairs {
            let t = 0.01 + Double(k) * 0.0001
            c.s(t, .ack, len: 1_400)
            c.c(t + 0.00005, .ack)
        }
        return c.packets
    }

    /// The table row showing flow `id` (the Flows table's default order: health, then start).
    static func flowRow(_ flows: [TCPFlow], id: Int) -> Int? {
        flows.map(FlowRow.init).sorted(using: FlowRow.defaultOrder).firstIndex { $0.id == id }
    }

    // MARK: - 1. Flows through the real view

    func testFlowsViewSelectionShowPacketsAndReanalysis() async throws {
        let packets = AppModel.shared.packets
        packets.clear()
        AppModel.shared.mainPane = .status
        // A bulk transfer after the two, so an analysis is still running when the click lands.
        let two = Self.conversations()
        let all = two + Self.bulk(firstID: two.count + 1, offset: 10, pairs: 40_000)
        packets.ingest(all)
        let flows1 = TCPFlowAnalyzer.analyze(all)
        let long = try XCTUnwrap(flows1.first { $0.server == "10.2.0.2" })
        let short = try XCTUnwrap(flows1.first { $0.server == "10.2.0.1" })

        PaneProbe.reset()
        let analysesBefore = PaneProbe.flowAnalyses
        let h = host(FlowView())
        await waitUntil { PaneProbe.flowAnalyses > analysesBefore && !Self.tables(in: h).isEmpty && Self.tables(in: h)[0].numberOfRows == 3 }
        let tv = try XCTUnwrap(Self.tables(in: h).first, "no table")
        XCTAssertEqual(tv.numberOfRows, 3)
        XCTAssertNil(PaneProbe.flowsLadder, "nothing selected yet")

        // Click the long conversation: its ladder.
        tv.selectRowIndexes(IndexSet(integer: try XCTUnwrap(Self.flowRow(flows1, id: long.id))), byExtendingSelection: false)
        await waitUntil { PaneProbe.flowsLadder?.id == long.id }
        XCTAssertEqual(PaneProbe.flowsLadder?.firstFrame, long.firstPacketID, "\(String(describing: PaneProbe.flowsLadder))")

        // A step: the event carrying a frame in the middle (the Follow-stream path selects it).
        let chosen = long.events[12]
        let frame = try XCTUnwrap(chosen.packetIDs.first)
        NotificationCenter.default.post(name: .sheepLogSelectFlow, object: FlowSelectRequest(key: long.key, packetID: frame))
        await waitUntil { PaneProbe.flowsLadder?.eventFrames == chosen.packetIDs }
        XCTAssertEqual(PaneProbe.flowsLadder?.eventFrames, chosen.packetIDs)

        // Re-analyse, and click the short conversation before the result lands: the click wins.
        let n = PaneProbe.flowAnalyses
        XCTAssertTrue(PaneProbe.press("flows.Re-analyse"), "no Re-analyse button")
        await waitUntil { PaneProbe.flowAnalyses == n + 1 }
        XCTAssertEqual(LeakProbe.count("Flows.analysis"), 1, "an analysis in flight")
        tv.selectRowIndexes(IndexSet(integer: try XCTUnwrap(Self.flowRow(flows1, id: short.id))), byExtendingSelection: false)
        XCTAssertEqual(LeakProbe.count("Flows.analysis"), 1, "the click came before the result")
        await waitUntil { LeakProbe.count("Flows.analysis") == 0 }
        await spin(100)
        XCTAssertEqual(PaneProbe.flowAnalyses, n + 1, "the press starts one analysis")
        XCTAssertEqual(PaneProbe.flowsLadder?.subject, "\(short.clientEndpoint) → \(short.serverEndpoint)",
                       "the analysis landing after the click moved the ladder back")
        XCTAssertNil(PaneProbe.flowsLadder?.eventFrames, "a step of the other conversation")

        // Back to the long one, its step again; then the ring evicts its first frames.
        let flows2 = TCPFlowAnalyzer.analyze(packets.packets)
        tv.selectRowIndexes(IndexSet(integer: try XCTUnwrap(Self.flowRow(flows2, id: flows2.first { $0.key == long.key }!.id))),
                            byExtendingSelection: false)
        await waitUntil { PaneProbe.flowsLadder?.subject.hasSuffix("10.2.0.2:443") == true }
        NotificationCenter.default.post(name: .sheepLogSelectFlow, object: FlowSelectRequest(key: long.key, packetID: frame))
        await waitUntil { PaneProbe.flowsLadder?.eventFrames == chosen.packetIDs }
        let firstKept = long.firstPacketID + 10
        packets.limit = all.count - (firstKept - 1)
        XCTAssertEqual(packets.packets.count, packets.limit)
        XCTAssertEqual(packets.packets.first?.id, firstKept)
        let m = PaneProbe.flowAnalyses
        await waitUntil(6) { PaneProbe.flowAnalyses > m && PaneProbe.flowsLadder?.firstFrame == firstKept }
        await spin(100)
        let ladder = try XCTUnwrap(PaneProbe.flowsLadder, "the selection was lost")
        XCTAssertEqual(ladder.firstFrame, firstKept, "\(ladder)")
        XCTAssertTrue(ladder.subject.hasSuffix("10.2.0.2:443"), "\(ladder)")
        XCTAssertEqual(ladder.eventFrames, chosen.packetIDs, "the step moved to another event: \(ladder)")
        let flows3 = TCPFlowAnalyzer.analyze(packets.packets)
        let longNow = try XCTUnwrap(flows3.first { $0.key == long.key })
        XCTAssertEqual(tv.selectedRowIndexes, IndexSet(integer: try XCTUnwrap(Self.flowRow(flows3, id: longNow.id))),
                       "the table's selected row is not the ladder's conversation")

        // "Show packets": the Packets pane, filtered to exactly the step's frames.
        XCTAssertTrue(PaneProbe.press("flows.Show packets"), "no Show packets button")
        XCTAssertEqual(AppModel.shared.mainPane, .packets)
        XCTAssertEqual(packets.queryText, FlowView.packetFilter(chosen.packetIDs, flow: longNow))
        await waitUntil { packets.visible.map(\.id) == chosen.packetIDs }
        XCTAssertEqual(packets.visible.map(\.id), chosen.packetIDs)
    }

    /// "Show packets" on a step shows that step's frames and nothing else — for a large data
    /// group too (up to what one filter can list), and for an attempt amid other clients' traffic.
    func testShowPacketsIsExactlyTheStep() throws {
        // A data group of 120 segments with the ACKs in between (collapsed into their own row):
        // Show packets on the data showed the ACKs too (a frame range from 51 frames).
        let bulk = Self.bulk(firstID: 1, offset: 0, pairs: 120) + Self.bulk(firstID: 244, offset: 1, pairs: 400, port: 40_001)
        let store = PacketStore()
        store.ingest(bulk)
        var checked = 0
        for flow in TCPFlowAnalyzer.analyze(bulk) {
        for e in flow.events where e.packetIDs.count > 1 {
            store.queryText = FlowView.packetFilter(e.packetIDs, flow: flow)
            store.applyQueryNow(synchronous: true)
            XCTAssertNil(store.queryError)
            if e.packetIDs.count <= Query.maxTerms {
                XCTAssertEqual(store.visible.map(\.id), e.packetIDs.sorted(), "\(e.packetIDs.count) frames: \(store.queryText.prefix(60))")
            } else {
                XCTAssertTrue(Set(store.visible.map(\.id)).isSuperset(of: e.packetIDs))
            }
            checked += 1
        }
        }
        XCTAssertGreaterThanOrEqual(checked, 4)

        // An attempt of 51–256 frames while other clients authenticate: only its frames.
        var lab = AuthLab(client: [0x02, 0x88, 0, 0, 0, 1])
        lab.peap(user: "leo@corp.example", succeed: true, rounds: 12, ip: "10.20.0.88")
        var other = AuthLab(client: [0x02, 0x88, 0, 0, 0, 2])
        other.peap(user: "mia@corp.example", succeed: true, rounds: 12, ip: "10.20.0.89")
        let mixed = zip(lab.packets, other.packets).flatMap { [$0, $1] }.enumerated().map { i, p in
            Packet(id: i + 1, timestamp: p.timestamp.addingTimeInterval(Double(i) * 1e-4), relative: p.relative, length: p.length,
                   captured: p.captured, data: p.data, decoded: p.decoded)
        }
        let leo = try XCTUnwrap(AuthSessions.build(mixed).first { $0.client == "02:88:00:00:00:01" })
        XCTAssertGreaterThan(leo.packetIDs.count, 50)
        let s2 = PacketStore()
        s2.ingest(mixed)
        s2.queryText = AuthView.packetFilter(leo.packetIDs)
        s2.applyQueryNow(synchronous: true)
        XCTAssertNil(s2.queryError)
        XCTAssertEqual(s2.visible.map(\.id), leo.packetIDs, "another client's frames under this attempt's Show packets")

        // RADIUS on the legacy ports and CoA: in the attempts, and under "Auth packets".
        let preset = PacketMatcher(try Query.parse(AuthDecoder.packetFilterPreset))
        for port in [1645, 1646, 3799] {
            var l = AuthLab(client: [0x02, 0x88, 0, 0, 1, 1])
            l.udpFrame(srcMAC: AuthLab.nasUplink, dstMAC: AuthLab.serverMAC, src: AuthLab.nasIP, dst: AuthLab.serverIP,
                       sp: 50_000, dp: port, AuthLab.radius(code: 1, id: 1, auth: [UInt8](repeating: 3, count: 16),
                                                            l.common(user: "020088000101") + [AuthLab.text(2, "x")]), dt: 0)
            XCTAssertTrue(AuthDecoder.isRADIUSPort(UInt16(port)))
            XCTAssertEqual(AuthSessions.build(l.packets).count, 1, "port \(port)")
            XCTAssertTrue(preset.matches(l.packets[0]), "port \(port) hidden by Auth packets")
        }
    }

    // MARK: - 1b / 3. Pane switches mid-analysis

    /// Flows → Packets → Flows while an analysis runs, and the same through the Authentication
    /// pane: the first appearance's analysis is cancelled (not left running, its result never
    /// lands), the second appearance starts exactly one.
    func testPaneSwitchMidAnalysisLeavesNoStaleTask() async throws {
        let model = AppModel.shared
        let packets = model.packets
        // The test host's own window shows ContentView: `mainPane` switches its panes.
        XCTAssertTrue(NSApp.windows.contains { w in w.isVisible && String(describing: w.contentView.map { type(of: $0) }).contains("ContentView") },
                      "no app window")
        packets.clear()
        model.mainPane = .status
        await spin(100)
        let two = Self.conversations()
        let bulk = Self.bulk(firstID: two.count + 1, offset: 10, pairs: 60_000)
        let auth = AuthScenario.combined().enumerated().map { i, p in
            Packet(id: two.count + bulk.count + i + 1, timestamp: p.timestamp, relative: 0, length: p.length,
                   captured: p.captured, data: p.data, decoded: p.decoded)
        }
        packets.ingest(two + bulk + auth)
        let flows = TCPFlowAnalyzer.analyze(packets.packets)
        let sessions = AuthSessions.build(packets.packets)
        // Round 13: the "2 analyses" flake was a pane of an earlier test (its window closed, its
        // view not yet torn down) analysing this ingest. Panes that left start nothing now; and
        // nothing else's analysis is in flight when counting starts.
        await waitUntil(10) {
            ["Flows.analysis", "Flows.scheduled", "Auth.analysis", "Auth.scheduled"].allSatisfy { LeakProbe.count($0) == 0 }
        }

        for (pane, probe, running, scheduled) in [(MainPane.flows, { PaneProbe.flowAnalyses }, "Flows.analysis", "Flows.scheduled"),
                                                  (.auth, { PaneProbe.authAnalyses }, "Auth.analysis", "Auth.scheduled")] {
            let tag = "\(pane)"
            PaneProbe.reset()
            let first = probe()
            model.mainPane = pane
            await waitUntil { probe() > first }
            XCTAssertEqual(probe(), first + 1, tag)
            // Away while it runs: cancelled, not left behind.
            model.mainPane = .packets
            await waitUntil { LeakProbe.count(running) == 0 && LeakProbe.count(scheduled) == 0 }
            XCTAssertEqual(LeakProbe.count(running), 0, "\(tag): the first appearance's analysis still runs")
            XCTAssertEqual(LeakProbe.count(scheduled), 0, tag)
            // Back: exactly one analysis, and it finishes; nothing more while nothing changes.
            let second = probe()
            model.mainPane = pane
            await waitUntil { probe() > second && LeakProbe.count(running) == 0 }
            try await Task.sleep(for: .milliseconds(1_600))
            XCTAssertEqual(probe(), second + 1, "\(tag): the second appearance started \(probe() - second) analyses")
            XCTAssertEqual(LeakProbe.count(running), 0, tag)
            XCTAssertEqual(LeakProbe.count(scheduled), 0, tag)
        }
        XCTAssertNil(PaneProbe.authLadder)

        // "Follow TCP stream" from Packets while the Flows pane is gone: the new pane takes the
        // request, one analysis, the conversation and the step of the frame.
        let long = try XCTUnwrap(flows.first { $0.server == "10.2.0.2" })
        let step = long.events[7]
        model.mainPane = .packets
        await spin(100)
        let n = PaneProbe.flowAnalyses
        model.mainPane = .flows
        NotificationCenter.default.post(name: .sheepLogSelectFlow, object: FlowSelectRequest(key: long.key, packetID: step.packetIDs[0]))
        await waitUntil { PaneProbe.flowsLadder?.eventFrames != nil }
        XCTAssertEqual(PaneProbe.flowsLadder?.subject, "\(long.clientEndpoint) → \(long.serverEndpoint)")
        XCTAssertEqual(PaneProbe.flowsLadder?.eventFrames, step.packetIDs)
        XCTAssertNil(model.takePendingFlowRequest(), "the request was left for the next appearance")
        try await Task.sleep(for: .milliseconds(1_300))
        XCTAssertEqual(PaneProbe.flowAnalyses, n + 1)

        // Show packets → Packets (the filter), Authentication → its Auth packets → Packets.
        XCTAssertTrue(PaneProbe.press("flows.Show packets"))
        XCTAssertEqual(model.mainPane, .packets)
        await waitUntil { packets.visible.map(\.id) == step.packetIDs }
        XCTAssertEqual(packets.visible.map(\.id), step.packetIDs)
        model.mainPane = .auth
        let a = PaneProbe.authAnalyses
        await waitUntil { PaneProbe.authAnalyses > a && LeakProbe.count("Auth.analysis") == 0 }
        await spin(100)
        XCTAssertTrue(PaneProbe.press("auth.Auth packets"))
        XCTAssertEqual(model.mainPane, .packets)
        let preset = PacketMatcher(try Query.parse(AuthDecoder.packetFilterPreset))
        await waitUntil { packets.visible.count == packets.packets.filter { preset.matches($0) }.count }
        XCTAssertEqual(packets.visible.map(\.id), packets.packets.filter { preset.matches($0) }.map(\.id))
        XCTAssertEqual(packets.visible.count, auth.count, "the preset shows the auth frames, not the TCP ones")
        XCTAssertEqual(sessions.count, AuthSessions.build(auth).count)
        packets.queryText = ""
        packets.applyQueryNow(synchronous: true)
        model.mainPane = .status
        await spin(200)
        XCTAssertEqual(LeakProbe.count("Flows.analysis"), 0)
        XCTAssertEqual(LeakProbe.count("Auth.analysis"), 0)
    }

    // MARK: - 2. Packets pane during a live capture

    private func tempDir(_ tag: String) -> URL {
        let u = FileManager.default.temporaryDirectory.appending(path: "SheepLogR11-\(tag)-\(UUID().uuidString)", directoryHint: .isDirectory)
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        cleanup.append(u)
        return u
    }

    private func footer(_ store: PacketStore) -> String {
        PacketsFooter.text(shown: store.visible.count, inMemory: store.packets.count, received: store.totalReceived,
                           bytes: store.totalBytes, filtered: !store.query.isEmpty, file: store.fileURL?.lastPathComponent,
                           waiting: store.pausedCount)
    }

    private func save(_ store: PacketStore, to url: URL) async -> String? {
        await withCheckedContinuation { c in store.save(to: url) { c.resume(returning: $0) } }
    }

    private static func readBack(_ url: URL) throws -> [Data] {
        var read: [Packet] = []
        _ = try PcapFile.read(url) { read += $0 }
        return read.map(\.data)
    }

    /// A lo0 capture of a busy TCP conversation: Pause, the limit lowered (through Settings),
    /// Save, Resume, Clear during a Save — the file has exactly the rows on screen at Save, the
    /// ring stays within the limit, and the footer says what is in memory, waiting and kept.
    func testPacketsPauseLowerLimitSaveResumeClearDuringACapture() async throws {
        try XCTSkipUnless(FileManager.default.isReadableFile(atPath: "/dev/bpf0"), "no /dev/bpf access")
        let model = AppModel.shared
        let packets = model.packets
        let saved = model.settings
        let server = try LoopbackTCPServer()
        let stop = LockedBox(false)
        defer {
            stop.mutate { $0 = true }
            server.stop()
            model.capture.stop()
            model.settings = saved
            model.dismissAllErrors()
        }
        packets.clear()
        model.mainPane = .packets
        model.settings.captureInterface = "lo0"
        model.settings.captureFilter = "tcp port \(server.port)"
        model.startCapture()
        model.dismissAllErrors()
        XCTAssertTrue(model.capture.isRunning, model.capture.lastError ?? "")
        let port = server.port
        Thread {
            guard let fd = TestSockets.connectTCP(port) else { return }
            var k = 0
            while !stop.value {
                k += 1
                let b = Array("r11 packet \(k)\n".utf8)
                _ = b.withUnsafeBytes { Darwin.send(fd, $0.baseAddress, b.count, 0) }
                usleep(500)
            }
            close(fd)
        }.start()
        await waitUntil(15) { packets.packets.count > 2_600 }
        XCTAssertGreaterThan(packets.packets.count, 2_600, "not enough traffic on lo0")
        XCTAssertTrue(footer(packets).hasSuffix(" · live"), footer(packets))

        // Pause: the table freezes, the rest waits.
        packets.paused = true
        let frozen = packets.visible.map(\.id)
        await waitUntil(5) { packets.pausedCount > 300 }
        XCTAssertEqual(packets.visible.map(\.id), frozen, "the paused table moved")
        XCTAssertTrue(footer(packets).contains("\(Format.count(packets.pausedCount)) waiting (paused)"), footer(packets))
        XCTAssertTrue(footer(packets).hasPrefix("\(Format.count(packets.packets.count)) packets"), footer(packets))

        // The limit lowered in Settings while paused: the ring trims at once, the table with it.
        model.settings.packetLimit = 1_000
        XCTAssertEqual(packets.limit, 1_000)
        XCTAssertLessThanOrEqual(packets.packets.count, 1_000)
        XCTAssertEqual(packets.visible.map(\.id), Array(frozen.suffix(packets.packets.count)), "the paused table after the trim")
        let f1 = footer(packets)
        XCTAssertTrue(f1.hasPrefix("1,000 packets"), f1)
        XCTAssertTrue(f1.contains("waiting (paused)"), f1)
        XCTAssertTrue(f1.contains("the last 1,000 of"), f1)

        // Save while paused and capturing: exactly the rows shown.
        let dir = tempDir("save")
        let shownAtSave = packets.visible.map(\.data)
        let e1 = await save(packets, to: dir.appending(path: "paused.pcap"))
        XCTAssertNil(e1)
        XCTAssertEqual(try Self.readBack(dir.appending(path: "paused.pcap")), shownAtSave)

        // With a filter: the filtered rows (packets with a payload).
        packets.queryText = "len:>60"
        packets.applyQueryNow(synchronous: true)
        let filteredAtSave = packets.visible.map(\.data)
        XCTAssertLessThan(filteredAtSave.count, shownAtSave.count)
        let e2 = await save(packets, to: dir.appending(path: "filtered.pcap"))
        XCTAssertNil(e2)
        XCTAssertEqual(try Self.readBack(dir.appending(path: "filtered.pcap")), filteredAtSave)
        XCTAssertTrue(footer(packets).hasPrefix("\(Format.count(filteredAtSave.count)) shown of \(Format.count(packets.packets.count))"), footer(packets))
        packets.queryText = ""
        packets.applyQueryNow(synchronous: true)

        // Resume after the lower limit: never more than the limit, the newest kept.
        await waitUntil(5) { packets.pausedCount > 1_200 }
        packets.paused = false
        XCTAssertLessThanOrEqual(packets.packets.count, 1_000)
        XCTAssertEqual(packets.pausedCount, 0)
        try await Task.sleep(for: .milliseconds(400))
        XCTAssertLessThanOrEqual(packets.packets.count, 1_000)
        XCTAssertEqual(packets.visible.map(\.id), packets.packets.map(\.id))
        let ids = packets.packets.map(\.id)
        XCTAssertEqual(ids, ids.sorted())
        XCTAssertEqual(ids.last.map { $0 - (ids.first ?? 0) + 1 }, ids.count, "a gap in the kept frames")
        let f2 = footer(packets)
        XCTAssertFalse(f2.contains("waiting"), f2)
        XCTAssertTrue(f2.contains("the last \(Format.count(packets.packets.count)) of \(Format.count(packets.totalReceived)) kept"), f2)

        // Clear during a Save: the file is the snapshot, complete; the store starts over.
        let snapshot = packets.packetsToSave.map(\.data)
        let url = dir.appending(path: "cleared.pcap")
        final class Done { var error: String?; var finished = false }
        let done = Done()
        packets.save(to: url) { done.error = $0; done.finished = true }   // as the Save button does
        XCTAssertTrue(packets.isSaving)
        packets.clear()
        XCTAssertTrue(packets.packets.isEmpty || packets.packets.first?.id == 1, "frame numbers start over after Clear")
        await waitUntil { done.finished }
        XCTAssertNil(done.error)
        XCTAssertEqual(try Self.readBack(url), snapshot)
        XCTAssertFalse(packets.isSaving)
        await waitUntil(5) { packets.packets.count > 20 }
        XCTAssertEqual(packets.packets.first?.id, 1)
        let f3 = footer(packets)
        XCTAssertFalse(f3.contains("kept"), "after Clear nothing has rolled out: \(f3)")
        stop.mutate { $0 = true }
    }

    // MARK: - 4. Sources table under 4 Hz updates

    /// A real right-click on `row` (AppKit sets `clickedRow` from the event), then the item.
    private func rightClick(_ tv: NSTableView, row: Int, choose prefix: String) -> NSMenuItem? {
        guard row >= 0, row < tv.numberOfRows, let window = tv.window else { return nil }
        tv.scrollRowToVisible(row)
        let r = tv.rect(ofRow: row)
        let p = tv.convert(NSPoint(x: r.midX, y: r.midY), to: nil)
        guard let event = NSEvent.mouseEvent(with: .rightMouseDown, location: p, modifierFlags: [], timestamp: 0,
                                             windowNumber: window.windowNumber, context: nil, eventNumber: 0,
                                             clickCount: 1, pressure: 1),
              let menu = tv.menu(for: event) else { return nil }
        XCTAssertEqual(tv.clickedRow, row)
        menu.delegate?.menuNeedsUpdate?(menu)
        return menu.items.first { $0.title.hasPrefix(prefix) }
    }

    /// 300 sources whose counts change four times a second: sorted by each column both ways,
    /// the selected source's row follows it, a right-click "Show" on a row whose counts just
    /// changed shows that row's source.
    func testSourcesTableSortedByEachColumnWhileCountsUpdate() async throws {
        let model = AppModel.shared
        let logs = model.logs
        let savedQuery = logs.queryText
        defer { logs.selectedSource = nil; logs.queryText = savedQuery }
        let severities = [3, 4, 6, 5, 2]
        func line(_ i: Int, _ k: Int) -> LogEntry {
            let pri = 8 + severities[(i + k) % severities.count]
            return parsedLine("<\(pri)>Sep 24 10:00:00 dev\(i % 37) app: r11 \(k)", from: "10.211.\(i / 200).\(i % 200 + 1)")
        }
        for i in 0..<300 { logs.ingest([line(i, 0)]) }
        await logs.settle()
        logs.publishSources()
        let mine = Set((0..<300).map { "10.211.\($0 / 200).\($0 % 200 + 1)" })
        let h = host(SourcesView())
        await waitUntil { (Self.tables(in: h).first?.numberOfRows ?? 0) == logs.sources.count }
        let tv = try XCTUnwrap(Self.tables(in: h).first)
        XCTAssertEqual(tv.numberOfRows, logs.sources.count)
        XCTAssertGreaterThanOrEqual(logs.sources.count, 300)

        let keys: [(String, (SortOrder) -> KeyPathComparator<SourceStats>)] = [
            ("Hostname", { KeyPathComparator(\SourceStats.displayName, order: $0) }),
            ("Address", { KeyPathComparator(\SourceStats.address, order: $0) }),
            ("Vendor", { KeyPathComparator(\SourceStats.vendorLabel, order: $0) }),
            ("Lines", { KeyPathComparator(\SourceStats.count, order: $0) }),
            ("Errors", { KeyPathComparator(\SourceStats.errorCount, order: $0) }),
            ("Warnings", { KeyPathComparator(\SourceStats.warningCount, order: $0) }),
            ("Last seen", { KeyPathComparator(\SourceStats.lastSeen, order: $0) }),
        ]
        var rng = AuthRNG(seed: 11)
        var k = 0
        for (title, comparator) in keys {
            for order in [SortOrder.forward, .reverse] {
                let column = try XCTUnwrap(tv.tableColumns.first { $0.title == title }, title)
                let proto = try XCTUnwrap(column.sortDescriptorPrototype)
                tv.sortDescriptors = [order == .forward ? proto : (proto.reversedSortDescriptor as! NSSortDescriptor)]
                await spin(60)
                func expected() -> [SourceStats] { logs.sources.sorted(using: [comparator(order)]) }
                // Select a source of ours in the middle of the table.
                let target = try XCTUnwrap(expected().filter { mine.contains($0.address) }.dropFirst(40).first)
                let row = try XCTUnwrap(expected().firstIndex { $0.address == target.address })
                tv.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
                for tick in 0..<3 {
                    k += 1
                    // A burst to a random third of the sources (counts, severities, last seen move).
                    var batch: [LogEntry] = []
                    for i in 0..<300 where rng.next() % 3 == 0 {
                        for _ in 0..<(1 + Int(rng.next() % 4)) { batch.append(line(i, k)) }
                    }
                    logs.ingest(batch)
                    await logs.settle()
                    try await Task.sleep(for: .milliseconds(260))       // the 4 Hz publish
                    await spin(40)
                    let tag = "\(title) \(order) tick \(tick)"
                    let want = try XCTUnwrap(expected().firstIndex { $0.address == target.address }, tag)
                    XCTAssertEqual(tv.numberOfRows, logs.sources.count, tag)
                    XCTAssertEqual(tv.selectedRowIndexes, IndexSet(integer: want), "\(tag): the selection left \(target.address)")
                }
                // Right-click "Show" on a row whose counts just changed: that row's source.
                let rows = expected()
                let r = try XCTUnwrap(rows.indices.dropFirst(10).first { mine.contains(rows[$0].address) })
                let item = try XCTUnwrap(rightClick(tv, row: r, choose: "Show this source"), title)
                logs.ingest((0..<300).map { line($0, k) })             // every count changes meanwhile
                await logs.settle()
                logs.publishSources()
                await spin(40)
                model.mainPane = .sources
                XCTAssertTrue(NSApp.sendAction(try XCTUnwrap(item.action), to: item.target, from: item), title)
                XCTAssertEqual(logs.selectedSource, rows[r].address, "\(title) \(order): Show went to another source")
                XCTAssertEqual(model.mainPane, .log)
                logs.selectedSource = nil
            }
        }
    }

    /// Clear empties the footer's "Exported N lines to x" (round 10 left it on the empty table);
    /// an export still writing when Clear comes names its file once done.
    func testClearDropsTheExportNote() async throws {
        let store = LogStore()
        store.ingest((0..<50).map { parsedLine("<13>Sep 24 10:00:00 sw1 app: r11 export \($0)", id: $0 + 1) })
        await store.settle()
        let dir = tempDir("export")
        let e1 = await store.export(to: dir.appending(path: "a.log"), csv: false)
        XCTAssertNil(e1)
        XCTAssertEqual(store.exportNote, "Exported 50 lines to a.log")
        store.clear()
        XCTAssertNil(store.exportNote, "the note outlived Clear")
        // Clear while an export writes: the note (after) names the file just written.
        store.ingest((0..<20).map { parsedLine("<13>Sep 24 10:00:00 sw1 app: r11 again \($0)", id: 100 + $0) })
        await store.settle()
        let writing = Task { await store.export(to: dir.appending(path: "b.log"), csv: false) }
        await Task.yield()
        store.clear()
        let e2 = await writing.value
        XCTAssertNil(e2)
        XCTAssertEqual(store.exportNote, "Exported 20 lines to b.log")
        let text = try String(contentsOf: dir.appending(path: "b.log"), encoding: .utf8)
        XCTAssertEqual(text.split(separator: "\n").count, 20)
    }

    // MARK: - 5. Authentication through the real view

    static func authRow(_ sessions: [AuthSession], id: Int) -> Int? {
        sessions.map(AuthRow.init).sorted(using: AuthRow.defaultOrder).firstIndex { $0.id == id }
    }

    /// The combined fixture capture arriving like a live capture: the PEAP attempt (first in it)
    /// up to its second TLS round, a step selected with a real click, the rest arriving (the TLS
    /// rounds fold into one "×n" row: every later step id moves), the ring evicting the attempt's
    /// first frames (the attempt ids and step ids move again), Show packets / Copy / Auth
    /// packets, and the attempt leaving the ring.
    func testAuthViewStepSurvivesLiveGrowthAndEviction() async throws {
        let packets = AppModel.shared.packets
        packets.clear()
        AppModel.shared.mainPane = .status
        let all = AuthScenario.combined()
        let peapClient = AuthScenario.peapSuccess.clientText
        let peapCount = AuthScenario.peapSuccess.build().count
        // The last prefix whose PEAP attempt has two TLS rows not folded yet.
        func peapSession(_ n: Int) -> AuthSession? { AuthSessions.build(Array(all.prefix(n))).first { $0.client == peapClient } }
        let k = try XCTUnwrap((1...peapCount).last { n in
            guard let s = peapSession(n) else { return false }
            return !s.events.contains { $0.isGroup } && s.events.filter { $0.label.contains("PEAP") && !$0.label.contains("start") }.count >= 2
        }, "no prefix with unfolded TLS rows")
        let early = try XCTUnwrap(peapSession(k))
        let chosen = try XCTUnwrap(early.events.last { $0.label.contains("PEAP") && !$0.label.contains("start") })
        let later = try XCTUnwrap(AuthSessions.build(all).first { $0.client == peapClient })
        let folded = try XCTUnwrap(later.events.first { e in e.packetIDs.contains(chosen.packetIDs[0]) })
        XCTAssertTrue(folded.isGroup, "the step folds into the TLS row")
        XCTAssertNotEqual(later.events.first { $0.id == chosen.id }?.packetIDs, folded.packetIDs,
                          "the step's id names another row after folding (else the sequence tests nothing)")

        PaneProbe.reset()
        packets.ingest(Array(all.prefix(k)))
        let before = PaneProbe.authAnalyses
        let h = host(AuthView())
        await waitUntil { PaneProbe.authAnalyses > before && (Self.tables(in: h).first?.numberOfRows ?? 0) > 0 }
        let tv = try XCTUnwrap(Self.tables(in: h).first)
        let sessions1 = AuthSessions.build(Array(all.prefix(k)))
        XCTAssertEqual(tv.numberOfRows, sessions1.count)
        let peap1 = try XCTUnwrap(sessions1.first { $0.client == peapClient })
        tv.selectRowIndexes(IndexSet(integer: try XCTUnwrap(Self.authRow(sessions1, id: peap1.id))), byExtendingSelection: false)
        await waitUntil { PaneProbe.authLadder?.subject == peapClient }
        XCTAssertEqual(PaneProbe.authLadder?.subject, peapClient)
        XCTAssertNil(PaneProbe.authLadder?.eventFrames)

        // A real click on the step's row of the ladder.
        await spin(100)
        let layout = AuthLadderLayout.make(session: peap1, width: Self.ladderWidth(in: h, minimum: 380))
        let item = try XCTUnwrap(layout.items.first { $0.event.id == chosen.id })
        XCTAssertTrue(PaneProbe.tap("auth.ladder", at: CGPoint(x: 40, y: item.y + item.height / 2)), "no ladder")
        await waitUntil { PaneProbe.authLadder?.eventFrames != nil }
        XCTAssertEqual(PaneProbe.authLadder?.eventFrames, chosen.packetIDs, "the click selected another step")

        // The rest of the capture arrives: re-analysed within ~1 s, the TLS rows fold.
        var n = PaneProbe.authAnalyses
        packets.ingest(Array(all.dropFirst(k)))
        await waitUntil(4) { PaneProbe.authAnalyses > n && LeakProbe.count("Auth.analysis") == 0 }
        await spin(150)
        XCTAssertEqual(PaneProbe.authLadder?.subject, peapClient)
        XCTAssertEqual(PaneProbe.authLadder?.eventFrames, folded.packetIDs, "the selected step moved to another row")

        // Show packets: exactly the step's frames. Copy: this attempt.
        XCTAssertTrue(PaneProbe.press("auth.Show packets"))
        XCTAssertEqual(AppModel.shared.mainPane, .packets)
        await waitUntil { packets.visible.map(\.id) == folded.packetIDs }
        XCTAssertEqual(packets.visible.map(\.id), folded.packetIDs, packets.queryText)
        XCTAssertTrue(PaneProbe.press("auth.Copy"))
        XCTAssertEqual(NSPasteboard.general.string(forType: .string), AuthSummary.text(later))
        // Auth packets: the preset, every auth frame of the fixture.
        XCTAssertTrue(PaneProbe.press("auth.Auth packets"))
        XCTAssertEqual(packets.queryText, AuthDecoder.packetFilterPreset)
        await waitUntil { packets.visible.count == all.count }
        XCTAssertEqual(packets.visible.count, all.count)
        packets.queryText = ""
        packets.applyQueryNow(synchronous: true)

        // The ring evicts the attempt's first three frames: attempt and step ids move again.
        n = PaneProbe.authAnalyses
        packets.limit = all.count - 3
        await waitUntil(4) { PaneProbe.authAnalyses > n && LeakProbe.count("Auth.analysis") == 0 }
        await spin(150)
        let evicted = AuthSessions.build(packets.packets)
        let peap3 = try XCTUnwrap(evicted.first { $0.client == peapClient })
        XCTAssertEqual(PaneProbe.authLadder?.firstFrame, peap3.firstPacketID)
        XCTAssertEqual(PaneProbe.authLadder?.eventFrames, folded.packetIDs, "the step moved after eviction")
        XCTAssertEqual(tv.selectedRowIndexes, IndexSet(integer: try XCTUnwrap(Self.authRow(evicted, id: peap3.id))))

        // The whole attempt leaves the ring: nothing selected, not another client's attempt.
        n = PaneProbe.authAnalyses
        packets.limit = all.count - peapCount
        await waitUntil(4) { PaneProbe.authAnalyses > n && LeakProbe.count("Auth.analysis") == 0 }
        await spin(150)
        XCTAssertNil(PaneProbe.authLadder, "\(String(describing: PaneProbe.authLadder))")
        XCTAssertTrue(tv.selectedRowIndexes.isEmpty)
    }

    /// The method chips and the text filter together, Problems only, and what Copy summary copies.
    func testAuthFiltersCombinedAndCopySummary() throws {
        let sessions = AuthSessions.build(AuthScenario.combined())
        let order = AuthRow.defaultOrder
        for method in AuthMethodFilter.allCases {
            for text in ["", "reject", "  CORP.example ", "02:5e:10", "vlan 20", "zzz"] {
                for problems in [false, true] {
                    let rows = AuthView.rows(sessions, problemsOnly: problems, method: method, text: text, order: order)
                    let needle = text.trimmingCharacters(in: .whitespaces).lowercased()
                    let expected = sessions.filter { s in
                        (!problems || s.health != .ok) && method.matches(s) && (needle.isEmpty || s.searchText.contains(needle))
                    }
                    let tag = "\(method) '\(text)' problems \(problems)"
                    XCTAssertEqual(Set(rows.map(\.id)), Set(expected.map(\.id)), tag)
                    XCTAssertEqual(rows.map(\.id), expected.map(AuthRow.init).sorted(using: order).map(\.id), tag)
                    // Copy summary: the rows shown, in their order, one line each.
                    let text = AuthSummary.overview(AuthView.shown(rows, of: sessions), source: "x.pcap")
                    let lines = text.split(separator: "\n")
                    XCTAssertEqual(lines.count, rows.count + 1, tag)
                    for (line, row) in zip(lines.dropFirst(), rows) { XCTAssertTrue(line.contains(row.client), tag) }
                }
            }
        }
        // MAC chip: MAC auth and MAC → 802.1X; 802.1X chip: both 802.1X kinds; "reject" among MAC
        // attempts is the rejected MAC auth, not the MAC → 802.1X that ended accepted.
        let mac = AuthView.rows(sessions, problemsOnly: false, method: .mac, text: "", order: order)
        XCTAssertTrue(mac.contains { $0.client == AuthScenario.macThenDot1x.clientText })
        XCTAssertTrue(mac.contains { $0.client == AuthScenario.macAuthAccept.clientText })
        XCTAssertFalse(mac.contains { $0.client == AuthScenario.pskSuccess.clientText })
        let dot1x = AuthView.rows(sessions, problemsOnly: false, method: .dot1x, text: "", order: order)
        XCTAssertTrue(dot1x.contains { $0.client == AuthScenario.macThenDot1x.clientText })
        XCTAssertFalse(dot1x.contains { $0.client == AuthScenario.macAuthAccept.clientText })
    }

    /// The headline counts each client once, by its latest attempt that ended.
    func testAuthHeadlineCountsEachClientOnce() throws {
        // Accepted, then rejected 70 s later (one client): it read "1 client authenticated, 1 failed."
        var lab = AuthLab(client: [0x02, 0x66, 0, 0, 0, 1])
        lab.macAuth(accept: true, withDHCP: false)
        lab.t += 70
        lab.macAuth(accept: false, withDHCP: false)
        let s = AuthSessions.build(lab.packets)
        XCTAssertEqual(s.count, 2)
        XCTAssertEqual(AuthView.headline(s), "0 clients authenticated, 1 failed.")
        // Rejected, then accepted: authenticated now.
        var lab2 = AuthLab(client: [0x02, 0x66, 0, 0, 0, 2])
        lab2.macAuth(accept: false, withDHCP: false)
        lab2.t += 70
        lab2.macAuth(accept: true, withDHCP: false)
        XCTAssertEqual(AuthView.headline(AuthSessions.build(lab2.packets)), "1 client authenticated, none failed.")
        // Accepted, then a new attempt still in progress at the end of the capture: still authenticated.
        var lab3 = AuthLab(client: [0x02, 0x66, 0, 0, 0, 3])
        lab3.macAuth(accept: true, withDHCP: false)
        lab3.t += 70
        lab3.eapol(fromClient: true, type: 1, [], toGroup: true)
        let s3 = AuthSessions.build(lab3.packets)
        XCTAssertEqual(s3.map(\.result), [.accepted, .inProgress])
        XCTAssertEqual(AuthView.headline(s3), "1 client authenticated, none failed.")
        // The fixture: every scenario's client once.
        let all = AuthSessions.build(AuthScenario.combined())
        let clients = Set(all.map(\.client))
        let text = AuthView.headline(all)
        let numbers = text.split(whereSeparator: { !$0.isNumber }).compactMap { Int($0) }
        XCTAssertLessThanOrEqual(numbers.reduce(0, +), clients.count, text)
    }

    /// `-demoAuthSelect <text>`: the attempt and its first step with a problem. The view set the
    /// step, then its own selection change cleared it (the flag's step never showed).
    func testDemoAuthSelectKeepsItsStep() throws {
        let sessions = AuthSessions.build(AuthScenario.combined())
        var state = AuthSelectionState()
        state.apply(sessions, previous: [])
        state.demoSelect("reject", in: sessions)
        let pick = try XCTUnwrap(sessions.first { $0.searchText.contains("reject") })
        XCTAssertEqual(state.selection, pick.id)
        // The view's onChange(of: selection).
        state.selectionChanged(in: sessions)
        let problem = try XCTUnwrap(pick.events.first { $0.problem != nil })
        XCTAssertEqual(state.event, problem.id)
        XCTAssertEqual(state.client, pick.client)
        // A click on another attempt afterwards: no step carried over.
        let other = try XCTUnwrap(sessions.first { $0.id != pick.id })
        state.selection = other.id
        state.selectionChanged(in: sessions)
        XCTAssertNil(state.event)
        // By id.
        var byID = AuthSelectionState()
        byID.demoSelect("\(other.id)", in: sessions)
        XCTAssertEqual(byID.selection, other.id)
    }

    /// Selection rules without the view: a new attempt of the same client later in the capture
    /// does not take the selection; the attempt found by its frames when its start was evicted.
    func testAuthSelectionStateRules() throws {
        var lab = AuthLab(client: [0x02, 0x77, 0, 0, 0, 1])
        lab.peap(user: "kim@corp.example", succeed: true, rounds: 3, ip: "10.20.0.77")
        let firstAttempt = lab.packets.count
        lab.t += 70
        lab.peap(user: "kim@corp.example", succeed: false, rounds: 3, ip: "10.20.0.77")
        let all = lab.packets
        let s1 = AuthSessions.build(all)
        XCTAssertEqual(s1.count, 2)
        var state = AuthSelectionState()
        state.selection = s1[0].id
        state.selectionChanged(in: s1)
        let step = try XCTUnwrap(s1[0].events.first { $0.isGroup })
        state.event = step.id
        // The first ten frames leave the ring: the first attempt starts later, its step moves up.
        let kept = Array(all.dropFirst(10))
        let s2 = AuthSessions.build(kept)
        state.apply(s2, previous: s1)
        if state.pendingEventFrames != nil { state.selectionChanged(in: s2) }
        let sel = try XCTUnwrap(s2.first { $0.id == state.selection })
        XCTAssertLessThanOrEqual(sel.lastPacketID, firstAttempt, "the selection jumped to the client's second attempt")
        let ev = try XCTUnwrap(sel.events.first { $0.id == state.event })
        XCTAssertTrue(Set(ev.packetIDs).isSuperset(of: step.packetIDs.filter { $0 > 10 }))
        // Unchanged analysis: nothing moves.
        let before = state
        state.apply(s2, previous: s2)
        XCTAssertEqual(state, before)
    }

    // MARK: - 5b. Authentication: adversarial input and the decoder's regressions

    /// Wired 802.1X where the supplicant and the switch address every EAPOL frame to the PAE
    /// group (wpa_supplicant's wired driver, hostapd): the switch's frames were all dropped (no
    /// authenticator was ever learned from a unicast frame) and the attempt read "in progress".
    func testWiredPortWithEveryEAPOLFrameGroupAddressed() throws {
        var lab = AuthLab(client: [0x02, 0x11, 0, 0, 0, 1])
        let sw: [UInt8] = [0x00, 0x1c, 0x0e, 0x00, 0x00, 0x05]
        func toGroup(_ from: [UInt8], _ type: UInt8, _ body: [UInt8], dt: Double = 0.005) {
            lab.add(AuthLab.ether(dst: AuthLab.pae, src: from, type: 0x888E, [2, type] + AuthLab.be16(body.count) + body), dt: dt)
        }
        toGroup(lab.client, 1, [])
        toGroup(sw, 0, AuthLab.eap(code: 1, id: 1, type: 1))
        toGroup(lab.client, 0, AuthLab.eap(code: 2, id: 1, type: 1, Array("alice".utf8)))
        toGroup(sw, 0, AuthLab.eap(code: 1, id: 2, type: 25, AuthLab.tlsData(start: true)))
        for i in 0..<4 {
            toGroup(lab.client, 0, AuthLab.eap(code: 2, id: UInt8(2 + i), type: 25, AuthLab.tlsData(bytes: 100)))
            toGroup(sw, 0, AuthLab.eap(code: 1, id: UInt8(3 + i), type: 25, AuthLab.tlsData(bytes: 100)))
        }
        toGroup(lab.client, 0, AuthLab.eap(code: 2, id: 7, type: 25, AuthLab.tlsData(bytes: 10)))
        toGroup(sw, 0, AuthLab.eap(code: 3, id: 7))
        let all = AuthSessions.build(lab.packets)
        XCTAssertEqual(all.count, 1, all.map(\.client).joined(separator: ", "))
        let s = try XCTUnwrap(all.first)
        XCTAssertEqual(s.client, "02:11:00:00:00:01")
        XCTAssertEqual(s.result, .accepted)
        XCTAssertEqual(s.method, .dot1x("PEAP"))
        XCTAssertEqual(s.nasMAC, "00:1c:0e:00:00:05")
        XCTAssertEqual(s.packetIDs, lab.packets.map(\.id), "every frame of the port is the attempt's")
        XCTAssertTrue(s.events.contains { $0.kind == .eapSuccess })
        XCTAssertTrue(s.events.contains { $0.label == "EAP-Request Identity" })

        // Two clients talking to the group at once (a SPAN of two ports): the switch's first
        // request is nobody's rather than a guess.
        var other = AuthLab(client: [0x02, 0x11, 0, 0, 0, 2])
        other.add(AuthLab.ether(dst: AuthLab.pae, src: other.client, type: 0x888E, [2, 1, 0, 0]), dt: 0.001)
        let mixed = Array(lab.packets.prefix(1)) + other.packets + Array(lab.packets.dropFirst())
        let renumbered = mixed.enumerated().map { i, p in
            Packet(id: i + 1, timestamp: p.timestamp, relative: p.relative, length: p.length, captured: p.captured,
                   data: p.data, decoded: p.decoded)
        }
        let amb = AuthSessions.build(renumbered)
        XCTAssertFalse(amb.contains { $0.client == "02:11:00:00:00:02" && $0.events.contains { $0.kind == .eapRequest } },
                       "a group-addressed request given to the wrong one of two talkers")
    }

    /// 10,000 attempts, each opened by a group-addressed EAP-Request from its own switch port:
    /// the backwards scan over every attempt per such frame took 7.3 s (Debug).
    func testTenThousandAttemptsUnderOneSecond() {
        var packets: [Packet] = []
        packets.reserveCapacity(80_000)
        for c in 0..<10_000 {
            var lab = AuthLab(client: [0x02, 0x22, UInt8(c >> 8), UInt8(c & 0xff), 0, 1], at: Double(c) * 0.01)
            let sw: [UInt8] = [0x00, 0x1c, 0x0e, UInt8(c >> 8), UInt8(c & 0xff), 5]
            // The client answers its switch port (round 12: it answered another MAC, so the
            // port's group-addressed request was a separate "no supplicant answered" attempt).
            lab.authenticator = sw
            lab.add(AuthLab.ether(dst: AuthLab.pae, src: sw, type: 0x888E, [2, 0] + AuthLab.be16(5) + AuthLab.eap(code: 1, id: 1, type: 1)), dt: 0)
            lab.eapID = 1
            lab.eapFromClient(type: 1, Array("user\(c)".utf8))
            lab.toServer(lab.common(user: "user\(c)") + [AuthLab.eapMessage(AuthLab.eap(code: 2, id: 1, type: 1, Array("user\(c)".utf8)))])
            lab.toNAS(code: 2, [AuthLab.eapMessage(AuthLab.eap(code: 3, id: 2))])
            lab.fourWay()
            for p in lab.packets {
                packets.append(Packet(id: packets.count + 1, timestamp: p.timestamp, relative: p.relative, length: p.length,
                                      captured: p.captured, data: p.data, decoded: p.decoded))
            }
        }
        let start = Date()
        let s = AuthSessions.build(packets)
        let elapsed = Date().timeIntervalSince(start)
        print("[perf] AuthSessions.build 10,000 attempts (\(packets.count) packets): \(String(format: "%.3f", elapsed)) s")
        XCTAssertEqual(s.count, 10_000)
        XCTAssertTrue(s.allSatisfy { $0.result == .accepted })
        XCTAssertWithinBudget(elapsed, 1.0, "10,000 attempts")
        // The pane's own work on them: the headline, the sorted rows, a filter.
        let t = Date()
        XCTAssertEqual(AuthView.headline(s), "10,000 clients authenticated, none failed.")
        let rows = s.map(AuthRow.init).sorted(using: AuthRow.defaultOrder)
        XCTAssertEqual(rows.count, 10_000)
        XCTAssertEqual(s.filter { $0.searchText.contains("user99") }.count, 111)
        let filtered = AuthView.rows(s, problemsOnly: false, method: .dot1x, text: "user9", order: AuthRow.defaultOrder)
        XCTAssertEqual(filtered.count, 1_111)
        XCTAssertWithinBudget(Date().timeIntervalSince(t), 1.0, "rows of 10,000 attempts")
        // Copy summary of every row: the attempts were found by a search per row (10,000²/2
        // comparisons on the main thread).
        let c = Date()
        let shown = AuthView.shown(rows, of: s)
        XCTAssertEqual(shown.map(\.id), rows.map(\.id))
        _ = AuthSummary.overview(shown, source: "big.pcap")
        let copy = Date().timeIntervalSince(c)
        let o = Date()
        let old = rows.prefix(2_000).compactMap { r in s.first { $0.id == r.id } }
        let oldFifth = Date().timeIntervalSince(o)
        print("[perf] Copy summary of 10,000 attempts: \(String(format: "%.3f", copy)) s (the old lookup took \(String(format: "%.3f", oldFifth)) s for a fifth of the rows)")
        XCTAssertEqual(old.count, 2_000)
        XCTAssertWithinBudget(copy, 0.5, "Copy summary of 10,000 attempts")
    }

    /// A MAC-auth Access-Request retransmitted after a captive-portal redirect pulled the
    /// client's earlier DHCP rows in front of it: the retransmission joined the DHCP Discover
    /// row ("DHCP Discover ×2 · answered after 1 retry") instead of its request.
    func testRetransmissionKeepsItsRowWhenACaptivePortalPullsEarlierRowsInFront() throws {
        var lab = AuthLab(client: [0x02, 0x33, 0, 0, 0, 1])
        let ip = "192.168.50.23"
        lab.dhcpExchange(ip: ip, server: "192.168.50.1")
        let attrs = lab.common(user: AuthLab.macText(lab.client, "")) + [AuthLab.text(2, "pw")]
        let (id, auth) = lab.toServer(attrs, dt: 1)
        let probe = "GET /hotspot-detect.html HTTP/1.1\r\nHost: captive.apple.com\r\n\r\n"
        lab.http(clientIP: ip, serverIP: "17.253.144.10", port: 50_100, request: probe,
                 response: "HTTP/1.1 302 Found\r\nLocation: http://portal.guest.example/login\r\nContent-Length: 0\r\n\r\n", dt: 0.1)
        lab.toServer(attrs, id: id, auth: auth, dt: 2)
        lab.toNAS(code: 2, [AuthLab.text(11, "guest")], id: id, dt: 0.05)
        let s = try XCTUnwrap(AuthSessions.build(lab.packets).first)
        XCTAssertEqual(s.result, .accepted)
        XCTAssertTrue(s.captive)
        let discover = try XCTUnwrap(s.events.first { $0.label.hasPrefix("DHCP Discover") })
        XCTAssertEqual(discover.packetIDs, [1], discover.label)
        XCTAssertNil(discover.detail)
        let request = try XCTUnwrap(s.events.first { $0.kind == .radiusRequest })
        XCTAssertEqual(request.packetIDs, [5, 8], request.label)
        XCTAssertTrue(request.detail?.contains("answered after 1 retry") == true, request.detail ?? "")
        XCTAssertEqual(try XCTUnwrap(request.endTime), lab.packets[7].relative - lab.packets[0].relative, accuracy: 1e-6,
                       "the row's end is timed from the session's start")
        XCTAssertEqual(s.events.map(\.time), s.events.map(\.time).sorted(), "rows in time order")
    }

    /// Hostile lengths and orders: no crash, no row invented, the rest of the attempt intact.
    func testAdversarialEAPOLAndRADIUS() throws {
        // EAPOL whose length field is 0, 3, or larger than the frame.
        for n in [0, 3, 2_000] {
            var lab = AuthLab(client: [0x02, 0x44, 0, 0, 0, 1])
            lab.peap(user: "grace@corp.example", succeed: true, rounds: 3, ip: "10.20.0.40")
            let body = AuthLab.eap(code: 1, id: 99, type: 25, AuthLab.tlsData(bytes: 50))
            lab.add(AuthLab.ether(dst: lab.client, src: AuthLab.ap, type: 0x888E, [2, 0] + AuthLab.be16(n) + body), dt: 0.01)
            let s = try XCTUnwrap(AuthSessions.build(lab.packets).first, "length \(n)")
            XCTAssertEqual(s.result, .accepted, "length \(n)")
            XCTAssertEqual(s.user, "grace@corp.example", "length \(n)")
        }
        // A 2/4 cut at every byte (a short snap length): never a completed handshake.
        for cut in 0..<99 {
            var lab = AuthLab(client: [0x02, 0x44, 0, 0, 1, 1])
            lab.fourWay(upTo: 1)
            lab.eapol(fromClient: true, type: 3, Array(AuthLab.key(2, replay: 1).prefix(cut)))
            let s = AuthSessions.build(lab.packets)
            XCTAssertLessThanOrEqual(s.count, 1, "cut \(cut)")
            XCTAssertNotEqual(s.first?.result, .accepted, "cut \(cut): a truncated 2/4 read as a completed handshake")
        }
        // RADIUS attribute lengths 0 and 1: parsing stops there; the attributes before it stand.
        for bad: UInt8 in [0, 1] {
            var lab = AuthLab(client: [0x02, 0x44, 0, 0, 2, bad])
            var attrs = lab.common(user: "heidi@corp.example")
            attrs.append(AuthLab.eapMessage(AuthLab.eap(code: 2, id: 1, type: 1, Array("heidi@corp.example".utf8))))
            attrs.append([33, bad])
            attrs.append(AuthLab.text(18, "never read"))
            lab.toServer(attrs)
            lab.toNAS(code: 3, [AuthLab.text(18, "denied")])
            let s = try XCTUnwrap(AuthSessions.build(lab.packets).first, "length \(bad)")
            XCTAssertEqual(s.user, "heidi@corp.example")
            XCTAssertEqual(s.result, .rejected("denied"))
            guard case .radius(let r) = AuthDecoder.classify(lab.packets[0]) else { return XCTFail("not RADIUS") }
            XCTAssertTrue(r.truncated)
            XCTAssertNil(r.first(18), "nothing read past a bad length")
        }
        // EAP-Message fragments out of order: not the EAP packet they make in order.
        let big = AuthLab.eap(code: 2, id: 2, type: 25, AuthLab.tlsData(length: 700, bytes: 600))
        var parts: [[UInt8]] = []
        var i = 0
        while i < big.count { let n = min(253, big.count - i); parts.append(AuthLab.attr(79, Array(big[i..<(i + n)]))); i += n }
        XCTAssertEqual(parts.count, 3)
        let shuffled = [parts[1], parts[0], parts[2]]
        let r = try XCTUnwrap(AuthDecoder.radius(AuthLab.radius(code: 1, id: 3, auth: [UInt8](repeating: 7, count: 16), shuffled)))
        XCTAssertEqual(r.eapFragments, 3)
        XCTAssertNotEqual(r.eap?.type, 25, "fragments out of order read as the TLS response")
        var lab = AuthLab(client: [0x02, 0x44, 0, 0, 3, 1])
        lab.toServer(lab.common(user: "ivan@corp.example") + shuffled)
        lab.toNAS(code: 11, [AuthLab.eapMessage(AuthLab.eap(code: 1, id: 3, type: 25, AuthLab.tlsData(bytes: 20)))])
        for s in AuthSessions.build(lab.packets) { _ = AuthSummary.text(s) }
    }

    /// A client that roams to another AP in the middle of an 802.1X exchange (the new AP asks
    /// for its identity; no EAPOL-Start): the abandoned exchange and the new one are two
    /// attempts, each on its own authenticator.
    func testClientChangesAuthenticatorMidAttempt() throws {
        var lab = AuthLab(client: [0x02, 0x55, 0, 0, 0, 1])
        let ap2: [UInt8] = [0x00, 0x0b, 0x86, 0x99, 0x99, 0x99]
        lab.eapToClient(code: 1, type: 1)
        lab.eapFromClient(type: 1, Array("judy@corp.example".utf8))
        lab.eapToClient(code: 1, type: 25, AuthLab.tlsData(start: true))
        lab.eapFromClient(type: 25, AuthLab.tlsData(bytes: 120))
        func fromAP2(_ body: [UInt8], type: UInt8 = 0, dt: Double = 0.004) {
            lab.add(AuthLab.ether(dst: lab.client, src: ap2, type: 0x888E, [2, type] + AuthLab.be16(body.count) + body), dt: dt)
        }
        func toAP2(_ body: [UInt8], type: UInt8 = 0, dt: Double = 0.004) {
            lab.add(AuthLab.ether(dst: ap2, src: lab.client, type: 0x888E, [2, type] + AuthLab.be16(body.count) + body), dt: dt)
        }
        let firstOnAP2 = lab.packets.count + 1
        fromAP2(AuthLab.eap(code: 1, id: 1, type: 1), dt: 2)
        toAP2(AuthLab.eap(code: 2, id: 1, type: 1, Array("judy@corp.example".utf8)))
        fromAP2(AuthLab.eap(code: 1, id: 2, type: 25, AuthLab.tlsData(start: true)))
        for k in 0..<3 {
            toAP2(AuthLab.eap(code: 2, id: UInt8(2 + k), type: 25, AuthLab.tlsData(bytes: 100)))
            fromAP2(AuthLab.eap(code: 1, id: UInt8(3 + k), type: 25, AuthLab.tlsData(bytes: 100)))
        }
        fromAP2(AuthLab.eap(code: 3, id: 6))
        for m in 1...4 {
            let k = AuthLab.key(m, replay: 1)
            if m % 2 == 1 { fromAP2(k, type: 3) } else { toAP2(k, type: 3) }
        }
        let all = AuthSessions.build(lab.packets)
        XCTAssertEqual(all.count, 2, all.map { "\($0.nasMAC ?? "-") \($0.result)" }.joined(separator: "; "))
        let second = try XCTUnwrap(all.first { $0.nasMAC == "00:0b:86:99:99:99" })
        XCTAssertEqual(second.result, .accepted)
        XCTAssertEqual(second.firstPacketID, firstOnAP2)
        let first = try XCTUnwrap(all.first { $0.nasMAC == AuthLab.macText(AuthLab.ap) })
        XCTAssertNotEqual(first.result, .accepted)
        XCTAssertLessThan(first.lastPacketID, firstOnAP2)
    }
}
