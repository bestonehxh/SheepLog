import AppKit
import Darwin
import SwiftUI
import XCTest
@testable import SheepLog

/// Round 14: every pane that left stops its work (round 13 found the Flows / Authentication
/// ones still analysing), ⌘Q during each pane's background work, the client report after a
/// Clear or eviction, more vendors' line forms, the line classifier's edges, the SNMP discard
/// rate over real ifXTable walks and a 32-bit wrap, the client report's sentences — and a sweep.
@MainActor
final class Round14Tests: XCTestCase {
    private var windows: [NSWindow] = []
    private var cleanup: [URL] = []

    override func tearDown() async throws {
        for w in windows { w.contentView = nil; w.close() }
        windows = []
        for u in cleanup { try? FileManager.default.removeItem(at: u) }
        cleanup = []
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
        TroubleshootModel.shared.report = nil
        try? await Task.sleep(for: .milliseconds(50))
    }

    // MARK: - Harness

    static let t0 = Round13Tests.t0
    static func at(_ s: Double) -> Date { t0.addingTimeInterval(s) }

    private func spin(_ ms: Int = 30) async { try? await Task.sleep(for: .milliseconds(ms)) }

    private func waitUntil(_ timeout: Double = 5, _ condition: () -> Bool) async {
        let end = Date().addingTimeInterval(timeout)
        while !condition(), Date() < end { await spin(10) }
    }

    private func tempDir() throws -> URL {
        let d = FileManager.default.temporaryDirectory.appending(path: "SheepLogR14-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        cleanup.append(d)
        return d
    }

    static func pane(_ p: MainPane) -> AnyView {
        switch p {
        case .status: AnyView(StatusView())
        case .troubleshoot: AnyView(TroubleshootView())
        case .log: AnyView(LogView())
        case .sources: AnyView(SourcesView())
        case .snmpTest: AnyView(SNMPTestView())
        case .mibs: AnyView(MIBsView())
        case .packets: AnyView(PacketsView())
        case .flows: AnyView(FlowView())
        case .auth: AnyView(AuthView())
        case .settings: AnyView(SettingsView())
        }
    }

    /// `view` in a window of its own, on screen (SwiftUI lays out and runs `.task` only there).
    private func host<V: View>(_ view: V) -> NSWindow {
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1280, height: 820), styleMask: [.titled, .resizable], backing: .buffered, defer: false)
        w.isReleasedWhenClosed = false
        w.contentView = NSHostingView(rootView: view)
        w.orderFront(nil)
        return w
    }

    /// Leaves the pane the way the round-13 tests' tearDown does: the window closes (its SwiftUI
    /// graph may outlive it — hosting views of some panes stay alive in AppKit for a while).
    private func close(_ w: NSWindow) {
        w.contentView = nil
        w.close()
    }

    /// What each pane runs on its own: its body, loops, table syncs, analyses, quit hooks.
    static func work(of p: MainPane) -> [String] {
        var k = ["body.\(p.rawValue)"]
        switch p {
        case .log: k += ["log.sync", "log.addressLoop", "log.timeZoneReload"]
        case .status: k += ["status.addressLoop"]
        case .packets: k += ["packets.refresh", "packets.interfaceLoop"]
        case .settings: k += ["settings.commitOnQuit", "settings.interfaces"]
        case .troubleshoot: k += ["troubleshoot.appeared"]
        case .flows: k += ["flows.appeared"]
        case .auth: k += ["auth.appeared"]
        default: break
        }
        return k
    }

    /// Loops and per-appearance objects each pane keeps alive while shown.
    static func alive(of p: MainPane) -> [String] {
        switch p {
        case .log: ["Log.addressLoop"]
        case .status: ["Status.addressLoop"]
        case .packets: ["Packets.interfaceLoop"]
        case .troubleshoot: ["Troubleshoot.analysis", "Troubleshoot.scheduled"]
        case .flows: ["Flows.analysis", "Flows.scheduled"]
        case .auth: ["Auth.analysis", "Auth.scheduled"]
        default: []
        }
    }

    private var nextLine = 5_000_000

    /// Lines, packets, a time-zone change, a quit notification (not the app's own: its delegate
    /// quits on NSApp's) and the cross-pane requests.
    private func stimulate() {
        var entries: [LogEntry] = []
        for k in 0..<40 {
            nextLine += 1
            entries.append(parsedLine("<27>1 - SW\(k % 4) app - - - Interface 1/1/\(k % 8) link down \(nextLine)", from: "10.9.0.\(k % 4 + 1)", id: nextLine))
        }
        AppModel.shared.logs.ingest(entries)
        let packets = AppModel.shared.packets
        packets.ingest(Round11InteractionTests.conversations(firstID: (packets.packets.last?.id ?? 0) + 1, offset: Double(nextLine % 1000),
                                                              port: UInt16(20_000 + nextLine % 20_000)))
        NotificationCenter.default.post(name: .NSSystemTimeZoneDidChange, object: nil)
        NotificationCenter.default.post(name: NSApplication.willTerminateNotification, object: self)
    }

    // MARK: - 1. Every pane that left stops its work

    /// Each pane in a window of its own; the window closes; lines, packets, a time-zone change
    /// and a quit notification arrive, and the debounces and loops get time to fire: the pane's
    /// body, table, loops, analyses and quit hook do not run and its loops are gone. Then the
    /// same pane again: exactly one of each loop starts. (The Packets table's controller
    /// re-read the store on every ingest for as long as AppKit kept the closed window's hosting
    /// view — round 13's Flows finding, in the Packets pane.)
    func testEveryPaneThatLeftStopsItsWork() async throws {
        let app = AppModel.shared
        for p in MainPane.allCases {
            // The app's own window follows `mainPane`: keep it on a pane without these probes.
            app.mainPane = p == .mibs ? .sources : .mibs
            await spin(150)
            let aliveBefore = Dictionary(uniqueKeysWithValues: Self.alive(of: p).map { ($0, LeakProbe.count($0)) })
            let w = host(Self.pane(p))
            await waitUntil { PaneProbe.runs("body.\(p.rawValue)") > 0 }
            await spin(700)
            if p == .log || p == .status || p == .packets {
                XCTAssertEqual(LeakProbe.count(Self.alive(of: p)[0]), aliveBefore[Self.alive(of: p)[0]]! + 1, "\(p): its loop runs while shown")
            }
            close(w)
            await spin(300)
            let before = Dictionary(uniqueKeysWithValues: Self.work(of: p).map { ($0, PaneProbe.runs($0)) })
            let analyses = (PaneProbe.troubleshootAnalyses, PaneProbe.flowAnalyses, PaneProbe.authAnalyses)
            stimulate()
            try await Task.sleep(for: .milliseconds(p == .troubleshoot ? 2_600 : 1_600))
            for (k, n) in before { XCTAssertEqual(PaneProbe.runs(k), n, "\(p): \(k) ran after the pane left") }
            XCTAssertEqual(PaneProbe.troubleshootAnalyses, analyses.0, "\(p): a Troubleshoot analysis")
            XCTAssertEqual(PaneProbe.flowAnalyses, analyses.1, "\(p): a Flows analysis")
            XCTAssertEqual(PaneProbe.authAnalyses, analyses.2, "\(p): an Authentication analysis")
            for (k, n) in aliveBefore { XCTAssertEqual(LeakProbe.count(k), n, "\(p): \(k) left running") }
            if p == .troubleshoot { XCTAssertFalse(TroubleshootModel.shared.visible) }
            // Back: exactly one of each. (The closed window's table coordinator / controller may
            // still be alive — AppKit keeps some closed windows' hosting views for a while — so
            // the new pane is counted by what it adds.)
            let tables = (LeakProbe.count("LogTable.Coordinator"), LeakProbe.count("PacketTableController"))
            let w2 = host(Self.pane(p))
            await spin(900)
            if p == .log || p == .status || p == .packets {
                XCTAssertEqual(LeakProbe.count(Self.alive(of: p)[0]), aliveBefore[Self.alive(of: p)[0]]! + 1, "\(p): one loop on the way back")
            }
            if p == .log { XCTAssertEqual(LeakProbe.count("LogTable.Coordinator"), tables.0 + 1) }
            if p == .packets { XCTAssertEqual(LeakProbe.count("PacketTableController"), tables.1 + 1) }
            if p == .troubleshoot { XCTAssertTrue(TroubleshootModel.shared.visible) }
            close(w2)
            await spin(200)
        }
        app.mainPane = .status
    }

    /// The same through the one window's pane switch (what the app does): every pane's loops and
    /// per-appearance objects gone when it leaves, nothing it runs runs, and the same set again
    /// when it comes back.
    func testEveryPaneLeftThroughThePaneSwitch() async throws {
        let app = AppModel.shared
        let w = host(ContentView())
        windows.append(w)
        app.mainPane = .mibs
        await spin(500)
        for p in MainPane.allCases where p != .mibs {
            let baseline = LeakProbe.snapshot.filter { $0.value != 0 }
            app.mainPane = p
            await spin(900)
            let shown = LeakProbe.snapshot.filter { $0.value != 0 }
            app.mainPane = .mibs
            await spin(300)
            let before = Dictionary(uniqueKeysWithValues: Self.work(of: p).map { ($0, PaneProbe.runs($0)) })
            stimulate()
            try await Task.sleep(for: .milliseconds(p == .troubleshoot ? 2_600 : 1_300))
            for (k, n) in before { XCTAssertEqual(PaneProbe.runs(k), n, "\(p): \(k) ran after the pane left") }
            XCTAssertEqual(LeakProbe.snapshot.filter { $0.value != 0 }, baseline, "\(p): left something running")
            for name in ["PacketTableController", "LogTable.Coordinator"] {
                XCTAssertEqual(LeakProbe.count(name), baseline[name] ?? 0, "\(p): \(name) kept")
            }
            app.mainPane = p
            await spin(900)
            XCTAssertEqual(LeakProbe.snapshot.filter { $0.value != 0 && !$0.key.hasSuffix(".analysis") && !$0.key.hasSuffix(".scheduled") },
                           shown.filter { !$0.key.hasSuffix(".analysis") && !$0.key.hasSuffix(".scheduled") }, "\(p): not the same set on the way back")
            app.mainPane = .mibs
            await spin(300)
        }
    }

    /// The Packets table's controller follows the store only while its pane is shown: detached,
    /// ingests and a Clear do nothing to it; attached again, it shows the store as it is now.
    func testPacketTableFollowsTheStoreOnlyWhileShown() async throws {
        let store = AppModel.shared.packets
        store.clear()
        let c = PacketTableController()
        c.liveOverride = false
        let scroll = PacketTableView.makeScrollView(controller: c)
        let table = try XCTUnwrap(scroll.documentView as? NSTableView)
        store.ingest(Round11InteractionTests.conversations())
        await spin(100)
        XCTAssertEqual(table.numberOfRows, store.visible.count)
        c.detach()
        let refreshes = PaneProbe.runs("packets.refresh")
        store.ingest(Round11InteractionTests.conversations(firstID: store.packets.count + 1, offset: 30, port: 51_000))
        store.clear()
        store.ingest(Round11InteractionTests.conversations(firstID: 1, offset: 60, port: 52_000))
        await spin(150)
        XCTAssertEqual(PaneProbe.runs("packets.refresh"), refreshes, "a detached table re-read the store")
        c.reattach()
        await spin(100)
        XCTAssertEqual(table.numberOfRows, store.visible.count, "back: the rows are the store's now")
        store.ingest(Round11InteractionTests.conversations(firstID: store.packets.count + 1, offset: 90, port: 53_000))
        await spin(150)
        XCTAssertEqual(table.numberOfRows, store.visible.count, "and follows it again")
    }

    // MARK: - 1. ⌘Q during each pane's background work

    /// A packet Save (a big capture takes seconds) and a Log export under way when ⌘Q runs
    /// `shutdownForQuit`: it waits for both, so the files are complete when it returns (it
    /// returned at once and the process exited mid-write: a truncated pcap under the chosen
    /// name, no export at all). An analysis, a report build and an SNMP walk under way are not
    /// waited for.
    func testQuitWaitsForASaveAndAnExportInFlight() async throws {
        let dir = try tempDir()
        let app = AppModel.shared
        let packets = app.packets
        packets.clear()
        let big = Round11InteractionTests.bulk(firstID: 1, offset: 0, pairs: 60_000)
        packets.ingest(big)
        await waitUntil { packets.packets.count == big.count }
        var lines: [LogEntry] = []
        for k in 0..<30_000 { lines.append(parsedLine("<14>1 - SW1 app - - - export line \(k) " + String(repeating: "x", count: 60), from: "10.9.1.1", id: 6_000_000 + k)) }
        app.logs.ingest(lines)
        await waitUntil { app.logs.entries.count >= 30_000 }
        let pcap = dir.appending(path: "quit.pcap"), log = dir.appending(path: "quit.log")
        var saved: String?? = .none
        packets.save(to: pcap) { saved = .some($0) }
        let export = Task { await app.logs.export(to: log, csv: false) }
        // Troubleshoot analysing meanwhile (nothing to write: not waited for).
        TroubleshootModel.shared.start()
        await spin(5)
        XCTAssertGreaterThan(PendingWrites.inFlight, 0, "the Save is under way")
        let started = Monotonic.now()
        app.shutdownForQuit()
        let waited = Monotonic.now() - started
        XCTAssertEqual(PendingWrites.inFlight, 0, "shutdownForQuit returned with a write under way")
        // What is on disk the moment it returns — the process would exit now.
        var count = 0
        _ = try PcapFile.read(pcap) { count += $0.count }
        XCTAssertEqual(count, big.count, "the capture on disk when ⌘Q returned")
        let text = try String(contentsOf: log, encoding: .utf8)
        XCTAssertEqual(text.split(separator: "\n").count, 30_000, "the export on disk when ⌘Q returned")
        XCTAssertLessThan(waited, AppModel.quitWriteWait)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.path).sorted(), ["quit.log", "quit.pcap"], "a temporary file left")
        _ = await export.value
        await waitUntil { saved != nil }
        XCTAssertEqual(saved, .some(nil))
        TroubleshootModel.shared.disappeared()
    }

    /// A Save over an earlier capture: the file under that name is the old one or the new one,
    /// never a part-written one (libpcap truncated it on open and wrote in place — a Save that
    /// failed or was cut short left a truncated capture where the old one had been).
    func testSaveReplacesTheFileOnlyWhenComplete() async throws {
        let dir = try tempDir()
        let url = dir.appending(path: "capture.pcap")
        let old = Round11InteractionTests.conversations()
        try PcapFile.write(old, linkType: 1, to: url)
        let oldSize = try XCTUnwrap(FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int)
        let packets = AppModel.shared.packets
        packets.clear()
        let big = Round11InteractionTests.bulk(firstID: 1, offset: 0, pairs: 60_000)
        packets.ingest(big)
        await waitUntil { packets.packets.count == big.count }
        let sizes = LockedBox<Set<Int>>([])
        let stop = LockedBox(false)
        let path = url.path
        let watcher = Thread {
            while !stop.value {
                var st = stat()
                if stat(path, &st) == 0 { let n = Int(st.st_size); sizes.mutate { $0.insert(n) } } else { sizes.mutate { $0.insert(-1) } }
                usleep(200)
            }
        }
        watcher.start()
        var done = false
        packets.save(to: url) { XCTAssertNil($0); done = true }
        await waitUntil(20) { done }
        stop.mutate { $0 = true }
        let finalSize = try XCTUnwrap(FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int)
        XCTAssertTrue(sizes.value.isSubset(of: [oldSize, finalSize]), "sizes seen under the name: \(sizes.value.sorted().prefix(8))")
        var count = 0
        _ = try PcapFile.read(url) { count += $0.count }
        XCTAssertEqual(count, big.count)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.path), ["capture.pcap"])
        // A Save that cannot finish (a folder that is not there) leaves nothing behind and says why.
        let missing = dir.appending(path: "gone/capture.pcap")
        XCTAssertThrowsError(try PcapFile.write(old, linkType: 1, to: missing))
    }

    /// ⌘Q while the Troubleshoot pane analyses, a client report is being built and the Test
    /// pane walks: `shutdownForQuit` does not wait for any of them.
    func testQuitDoesNotWaitForAnalysesOrWalks() async throws {
        let app = AppModel.shared
        app.packets.ingest(Round11InteractionTests.bulk(firstID: 1, offset: 0, pairs: 20_000))
        TroubleshootModel.shared.start()
        TroubleshootModel.shared.buildReport("10.9.0.9")
        let started = Monotonic.now()
        app.shutdownForQuit()
        XCTAssertLessThan(Monotonic.now() - started, 1.0)
        TroubleshootModel.shared.disappeared()
    }

    // MARK: - 2. The client report after Clear and eviction

    /// A client with DHCP, DNS, a conversation and log lines.
    static func clientPackets(firstID: Int = 1, offset: Double = 0) -> [Packet] {
        let client = "02:00:5e:1e:00:31", ip = "10.1.30.60"
        typealias F = TroubleshootFixture
        var frames: [(Double, [UInt8])] = [
            (offset + 1, F.udp4(srcMAC: client, dstMAC: "ff:ff:ff:ff:ff:ff", src: "0.0.0.0", dst: "255.255.255.255", sport: 68, dport: 67, vlan: 30,
                                F.dhcp(op: 1, type: 1, xid: 0x3b01, client: client))),
            (offset + 1.1, F.udp4(srcMAC: F.routerMAC, dstMAC: client, src: "10.1.30.1", dst: ip, sport: 67, dport: 68, vlan: 30,
                                  F.dhcp(op: 2, type: 5, xid: 0x3b01, client: client, yiaddr: ip, server: "10.1.0.10", lease: 86_400))),
            (offset + 2, F.udp4(srcMAC: client, dstMAC: F.routerMAC, src: ip, dst: "10.1.0.53", sport: 53_001, dport: 53, vlan: 30,
                                F.dns(id: 7, name: "files.corp.example", response: false))),
        ]
        frames.sort { $0.0 < $1.0 }
        var out = frames.enumerated().map { i, f in F.packet(f.1, at: at(f.0), id: firstID + i, start: t0) }
        var s = TCPFlowDemo.Script(firstID: firstID + out.count, offset: offset + 3, client: ip, clientPort: 50_100, server: "10.2.0.9", serverPort: 443)
        s.handshake(rtt: 0.01)
        s.c(0.02, [.psh, .ack], len: 100)
        s.s(0.03, [.psh, .ack], len: 200)
        out += s.packets
        return out
    }

    /// The report's links after a Clear, eviction and a new capture: they say the frames are
    /// gone (a Clear bumps the packet epoch; the new capture's `ip:` packets are not the
    /// report's) and open nothing; the log link says how much is left. It used to open the
    /// Packets pane on the new capture's packets of the same address, a conversation of the
    /// old capture by a frame number of the new one, and an empty Log pane.
    func testReportLinksAfterClearAndEviction() async throws {
        let app = AppModel.shared
        let packets = app.packets, logs = app.logs
        packets.clear(); logs.clear()
        packets.ingest(Self.clientPackets())
        // Five of its lines first, a thousand others, five more: eviction takes the first five.
        logs.limit = 1_000
        var entries: [LogEntry] = []
        func client(_ k: Int) -> LogEntry { parsedLine("<14>1 - ACC-SW1 dot1x - - - client 10.1.30.60 on port 1/1/7 reauth \(k)", from: "10.66.1.1", id: 7_000_000 + k) }
        for k in 0..<5 { entries.append(client(k)) }
        for k in 0..<990 { entries.append(parsedLine("<14>1 - OTHER app - - - chatter \(k)", from: "10.66.2.2", id: 7_000_100 + k)) }
        for k in 5..<10 { entries.append(client(k)) }
        logs.ingest(entries)
        await waitUntil { packets.packets.count > 0 && logs.entries.count == 1_000 }
        var input = TroubleshootModel.shared.currentInput()
        input.flows = TCPFlowAnalyzer.analyze(input.packets)
        let report = try XCTUnwrap(ClientReport.build("10.1.30.60", input: input, findings: []))
        XCTAssertEqual(report.packetEpoch, packets.epoch)
        XCTAssertEqual(report.logTotal, 10)
        let flow = try XCTUnwrap(report.flows.first)
        XCTAssertEqual(ReportLink.title("Show \(report.packetTotal) packets", report.packetEvidence, epoch: report.packetEpoch), "Show \(report.packetTotal) packets")
        XCTAssertFalse(ReportLink.isGone(report.flowEvidence(flow), epoch: report.packetEpoch))

        // Some of its lines roll out of the log: said, and the link still opens.
        var more: [LogEntry] = []
        for k in 0..<20 { more.append(parsedLine("<14>1 - OTHER app - - - more chatter \(k)", from: "10.66.2.2", id: 7_100_000 + k)) }
        logs.ingest(more)
        await waitUntil { logs.countPresent(ids: report.logIDs) < 10 }
        XCTAssertEqual(logs.countPresent(ids: report.logIDs), 5)
        XCTAssertEqual(ReportLink.title("Show on the Log pane", report.logEvidence, epoch: report.packetEpoch),
                       "Show on the Log pane — 5 of 10 still in memory")
        XCTAssertNil(ReportLink.open(report.logEvidence, epoch: report.packetEpoch), "partly there: the Log opens")
        XCTAssertEqual(app.mainPane, .log)
        // Cleared: gone, and nothing opens.
        logs.clear()
        app.mainPane = .troubleshoot
        XCTAssertEqual(ReportLink.title("Show on the Log pane", report.logEvidence, epoch: report.packetEpoch), "Show on the Log pane — no longer in memory")
        let logText = try XCTUnwrap(ReportLink.open(report.logEvidence, epoch: report.packetEpoch))
        XCTAssertTrue(logText.contains("rolled out of memory"), logText)
        XCTAssertEqual(app.mainPane, .troubleshoot, "a link to lines that are gone opened the Log")

        // The capture cleared and a new one with the same client: the report's frames are gone.
        packets.clear()
        packets.ingest(Self.clientPackets(offset: 100))
        await waitUntil { packets.packets.count > 0 }
        XCTAssertNotEqual(packets.epoch, report.packetEpoch)
        XCTAssertEqual(ReportLink.title("Show 7 packets", report.packetEvidence, epoch: report.packetEpoch), "Show 7 packets — no longer in memory")
        XCTAssertTrue(ReportLink.isGone(report.flowEvidence(flow), epoch: report.packetEpoch), "the old capture's conversation")
        let packetText = try XCTUnwrap(ReportLink.open(report.packetEvidence, epoch: report.packetEpoch))
        XCTAssertTrue(packetText.contains("no longer in memory"), packetText)
        XCTAssertNotNil(ReportLink.open(report.flowEvidence(flow), epoch: report.packetEpoch), "a gone conversation opened")
        XCTAssertEqual(app.mainPane, .troubleshoot)
        XCTAssertEqual(packets.queryText, "", "the new capture was filtered to the old report's address")
        app.mainPane = .status
    }

    /// A report built after a Clear lists this capture's conversations (the last analysis's
    /// were the old capture's: their links opened another capture's frames); leaving the pane
    /// drops the report, which used to come back over the next visit.
    func testReportAfterClearListsThisCapturesFlows() async throws {
        let app = AppModel.shared
        let model = TroubleshootModel.shared
        app.packets.clear()
        app.packets.ingest(Self.clientPackets())
        model.start()
        await waitUntil(10) { model.result != nil && !model.analysing && model.result?.packetEpoch == app.packets.epoch }
        let oldEpoch = app.packets.epoch
        app.packets.clear()
        // The same client, other conversations (another server).
        var s = TCPFlowDemo.Script(firstID: 1, offset: 200, client: "10.1.30.60", clientPort: 50_200, server: "10.2.0.77", serverPort: 22)
        s.handshake(rtt: 0.01)
        app.packets.ingest(s.packets)
        await waitUntil { !app.packets.packets.isEmpty }
        XCTAssertNotEqual(app.packets.epoch, oldEpoch)
        model.buildReport("10.1.30.60")
        await waitUntil(10) { model.report != nil }
        let report = try XCTUnwrap(model.report)
        XCTAssertEqual(report.packetEpoch, app.packets.epoch)
        XCTAssertEqual(report.flows.map { $0.text.contains("10.2.0.77:22") }, [true], report.flows.map(\.text).description)
        XCTAssertFalse(report.flows.contains { ReportLink.isGone(report.flowEvidence($0), epoch: report.packetEpoch) })
        // The pane leaves with the sheet up: the report does not come back.
        model.disappeared()
        XCTAssertNil(model.report)
    }

    // MARK: - 3. More vendors' forms

    /// The corpus's round-14 lines (other.log 39–53, arubacx.log 9–10), each read into what it
    /// says: Arista's line protocol, CONFIG_I and BGP (the NOTIFICATION is why the peer went
    /// down, not a down of its own), Extreme's port events, Ruckus's "state down" (no "link"),
    /// Meraki's epoch header and "status changed from … to down", IOS XR's node before the time
    /// (and "committed by user 'admin'", read as the user "user"), AOS-CX with structured data.
    func testRound14CorpusLinesAreRead() throws {
        let dir = Round12Tests.testsDir.appending(path: "corpus")
        let other = try String(contentsOf: dir.appending(path: "other.log"), encoding: .utf8).split(whereSeparator: \.isNewline).map(String.init)
        let cx = try String(contentsOf: dir.appending(path: "arubacx.log"), encoding: .utf8).split(whereSeparator: \.isNewline).map(String.init)
        let read = (other[38..<53] + cx[8..<10]).map { LineClassifier.line(parsedLine($0, from: "10.9.9.9")).map { "\($0)" } ?? "nil" }
        XCTAssertEqual(read, [
            "link(iface: \"Ethernet5\", up: false)", "link(iface: \"Ethernet5\", up: true)", "config(user: Optional(\"admin\"))",
            "routingNotice(proto: \"BGP\", neighbor: \"10.0.0.2\", reason: \"Hold Timer Expired Error/Unspecific\", sent: false)",
            "routing(proto: \"BGP\", neighbor: \"10.0.0.2\", up: false)", "routing(proto: \"BGP\", neighbor: \"10.0.0.2\", up: true)",
            "link(iface: \"1:5\", up: false)", "link(iface: \"1:5\", up: true)",
            "link(iface: \"ethernet 1/1/5\", up: false)", "link(iface: \"ethernet 1/1/5\", up: true)",
            "link(iface: \"3\", up: false)", "link(iface: \"3\", up: true)",
            "link(iface: \"GigabitEthernet0/0/0/1\", up: false)", "link(iface: \"GigabitEthernet0/0/0/1\", up: true)",
            "config(user: Optional(\"admin\"))",
            "link(iface: \"1/1/5\", up: false)", "link(iface: \"1/1/5\", up: true)",
        ])
        // The headers: Meraki's device, category and time; IOS XR's node, program and UTC time.
        let meraki = parsedLine(other[48], from: "10.9.9.9")
        XCTAssertEqual([meraki.hostname, meraki.program, meraki.message], ["MS220-8P", "events", "port 3 status changed from 1Gfdx to down"])
        XCTAssertEqual(meraki.deviceTime?.timeIntervalSince1970 ?? 0, 1_790_133_840.123, accuracy: 0.001)
        let xr = parsedLine(other[50], from: "10.9.9.9")
        XCTAssertEqual([xr.hostname, xr.program, xr.field("node") ?? "-", xr.field("seq") ?? "-"], ["", "ifmgr", "RP/0/RSP0/CPU0", "100"])
        XCTAssertTrue(xr.message.hasPrefix("%PKT_INFRA-LINK-3-UPDOWN : Interface"), xr.message)
        XCTAssertEqual(parsedLine(other[52], from: "10.9.9.9").hostname, "XR-PE1")
    }

    /// The rules over those vendors: a BGP reset reported as NOTIFICATION + ADJCHANGE down + up
    /// is nothing (Cisco IOS's "sent … (hold time expired)" was a second down: "went down 2
    /// times"); a peer still down says why its session ended; Ruckus / Meraki / XR ports that
    /// flap are link flaps of their own port names.
    func testVendorLinesThroughTheRules() async throws {
        var l = Round13Tests.Lines()
        let bsd = Round13Tests.bsd
        // Cisco IOS classic: NOTIFICATION sent (hold time expired), the down, the up.
        l.raw(0, "<187>123: CORE-RTR1: \(bsd(0)).120: %BGP-3-NOTIFICATION: sent to neighbor 10.0.0.2 4/0 (hold time expired) 0 bytes", from: "10.66.1.2")
        l.raw(0.01, "<189>124: CORE-RTR1: \(bsd(0)).130: %BGP-5-ADJCHANGE: neighbor 10.0.0.2 Down BGP Notification sent", from: "10.66.1.2")
        l.raw(40, "<189>125: CORE-RTR1: \(bsd(40)).130: %BGP-5-ADJCHANGE: neighbor 10.0.0.2 Up", from: "10.66.1.2")
        var r = Round13Tests.analyze(l.entries)
        XCTAssertTrue(r.findings.isEmpty, "one reset, back up: \(r.findings.map(\.title))")
        // Arista: the peer does not come back — the reason is in the finding.
        l = Round13Tests.Lines()
        l.raw(0, "<187>\(bsd(0)) LEAF-EOS-1 Bgp: %BGP-3-NOTIFICATION: received from neighbor 10.0.0.2 (VRF default AS 65002) 4/0 (Hold Timer Expired Error/Unspecific) 0 bytes", from: "10.66.3.3")
        l.raw(0.2, "<189>\(bsd(0)) LEAF-EOS-1 Bgp: %BGP-5-ADJCHANGE: peer 10.0.0.2 (VRF default AS 65002) old state Established event HoldTimerExpired new state Idle", from: "10.66.3.3")
        r = Round13Tests.analyze(l.entries)
        let peer = try XCTUnwrap(r.findings.first { $0.rule == "routing.neighbor" }, r.findings.map(\.title).description)
        XCTAssertEqual(r.findings.count, 1)
        XCTAssertTrue(peer.detail.hasPrefix("The session ended with a NOTIFICATION received from the neighbor: Hold Timer Expired Error/Unspecific. "), peer.detail)
        XCTAssertEqual(peer.evidence.first?.ids.count, 2, "the NOTIFICATION is evidence too")
        // An administrative reset says it is somebody's command.
        l = Round13Tests.Lines()
        l.raw(0, "<187>\(bsd(0)) LEAF-EOS-1 Bgp: %BGP-3-NOTIFICATION: sent to neighbor 10.0.0.2 (VRF default AS 65002) 6/4 (Cease/administrative reset) 0 bytes", from: "10.66.3.3")
        l.raw(0.2, "<189>\(bsd(0)) LEAF-EOS-1 Bgp: %BGP-5-ADJCHANGE: peer 10.0.0.2 (VRF default AS 65002) old state Established event Stop new state Idle", from: "10.66.3.3")
        r = Round13Tests.analyze(l.entries)
        XCTAssertTrue(r.findings.first?.detail.contains("An administrative reset or shutdown is somebody's command, not a fault.") ?? false,
                      r.findings.first?.detail ?? "none")
        // Ruckus, Meraki and IOS XR ports flapping: each a link flap of its own port.
        l = Round13Tests.Lines()
        for k in 0..<3 {
            let d = Double(k) * 30, u = d + 10
            l.raw(d, "<14>\(bsd(d)) ICX7150-SW1 System: Interface ethernet 1/1/5, state down", from: "10.66.4.4")
            l.raw(u, "<14>\(bsd(u)) ICX7150-SW1 System: Interface ethernet 1/1/5, state up", from: "10.66.4.4")
            let e = Int(Round13Tests.at(d).timeIntervalSince1970)
            l.raw(d, "<134>1 \(e).5 MS220-8P events port 3 status changed from 1Gfdx to down", from: "10.66.5.5")
            l.raw(u, "<134>1 \(e + 10).5 MS220-8P events port 3 status changed from down to 1Gfdx", from: "10.66.5.5")
        }
        r = Round13Tests.analyze(l.entries)
        XCTAssertEqual(Set(r.findings.map { "\($0.rule)|\($0.device ?? "-")" }), ["link.flap|ICX7150-SW1", "link.flap|MS220-8P"], r.findings.map(\.title).description)
        XCTAssertTrue(r.findings.contains { $0.title.contains("ethernet 1/1/5") }, r.findings.map(\.title).description)
        // Their evidence filters show their lines (a port "ethernet 1/1/5", a port "3").
        let store = LogStore()
        store.ingest(l.entries)
        for f in r.findings {
            let e = try XCTUnwrap(f.evidence.first)
            store.queryText = e.query
            store.applyQueryText()
            await waitUntil { Set(store.visible.map(\.id)).isSuperset(of: e.ids) }
            XCTAssertTrue(Set(store.visible.map(\.id)).isSuperset(of: e.ids), "\(f.title): `\(e.query)`")
            XCTAssertEqual(e.ids.count, 6, f.title)
        }
    }

    // MARK: - 4. The line classifier's edges

    /// Words that name hardware or spanning tree in the program, the host or the message, but
    /// not a failure / an STP event: a fan program's benign line, a fan following temperature,
    /// thresholds a line states, "STP" and "loop" in names and URLs, routing protocols' own
    /// "topology change" and "AS path loop" (read as STP: a BGP path loop was a layer-2 loop).
    func testClassifierEdges() {
        func kind(_ text: String) -> String { LineClassifier.line(parsedLine(text, from: "10.9.9.9")).map { "\($0)" } ?? "nil" }
        let table: [(String, String)] = [
            // Hardware words in the program, a benign message.
            ("<164>1 2026-09-23T10:39:00Z CX6300-ACC-12 fand 1433 - - Event|1401|LOG_WARN|AMM|1/1|Fan speed adjusted to 60% for zone 1", "nil"),
            ("<164>Sep 23 10:39:10 SW1 fand[12]: fan speed adjusted to high", "nil"),
            ("<164>Sep 23 10:39:10 SW1 fand[12]: fan speed changed to 4200 rpm", "nil"),
            ("<164>Sep 23 10:39:11 SW1 envmon: Temperature sensor 2 is normal, warning threshold 70C", "hardware(SheepLog.HardwareKind.temperature, recovered: true)"),
            ("<164>Sep 23 10:39:25 SW1 sys: CPU temperature 45C, high threshold 90C", "nil"),
            ("<164>Sep 23 10:39:26 SW1 poed[99]: PoE port 1/1/5 power delivering 12.5W", "nil"),
            ("<166>Sep 23 10:39:27 SW1 fand: fan tray 1 status", "nil"),
            ("<164>Sep 23 10:39:28 SW1 fand: fan tray 1 status", "hardware(SheepLog.HardwareKind.fan, recovered: false)"),
            ("<164>Sep 23 10:39:29 HW-S5720 %%01DEVM/4/ENTITYREMOVE(l)[3]:The fan module 2 was pulled out.", "hardware(SheepLog.HardwareKind.fan, recovered: false)"),
            // …and the failures still are.
            ("<162>Sep 23 10:39:12 SW1 fand[12]: Fan 2 speed adjusted but fan stopped: rotor stall", "hardware(SheepLog.HardwareKind.fan, recovered: false)"),
            ("<161>Sep 23 10:39:13 SW1 envmon: Temperature 81C is over high threshold 75C", "hardware(SheepLog.HardwareKind.temperature, recovered: false)"),
            ("<177>1 2026-09-23T03:17:11Z CX6300-ACC-12 fand 1433 - - Event|1403|LOG_ALERT|AMM|1/1|Fan tray 1 fault detected, system temperature rising",
             "hardware(SheepLog.HardwareKind.fan, recovered: false)"),
            ("<163>Sep 23 10:39:14 SW1 chassis: fan tray 1 status", "hardware(SheepLog.HardwareKind.fan, recovered: false)"),
            // STP in names, not events.
            ("<189>Sep 23 10:39:20 BESTP-SW1 sshd[99]: session opened for user admin", "nil"),
            ("<189>Sep 23 10:39:21 SW-BESTPRICE stpd[99]: Port 1/1/3 state forwarding", "nil"),
            ("<189>Sep 23 10:39:22 SW1 mstpd[99]: MSTP instance 0 port 1/1/3 role designated", "nil"),
            ("<187>Sep 23 10:39:23 SW1 app: backup to https://stp.example.com/loop failed", "nil"),
            ("<187>Sep 23 10:39:24 STP-LAB-SW %LINK-3-UPDOWN: Interface Gi1/0/1, changed state to down", "link(iface: \"Gi1/0/1\", up: false)"),
            // Routing protocols' own topology changes and loops.
            ("<189>Sep 23 10:42:00 R1 ospfd[99]: SPF scheduled due to topology change", "nil"),
            ("<187>Sep 23 10:42:01 R1 bgpd[99]: %BGP-3-BADPATH: AS path loop detected from neighbor 10.0.0.7", "nil"),
            ("<189>Sep 23 10:42:02 R1 isisd[99]: IS-IS topology changed, SPF run", "nil"),
            // A BGP session's steps between Idle and Established are no adjacency change.
            ("<189>Sep 23 10:42:10 LEAF-EOS-1 Bgp: %BGP-5-ADJCHANGE: peer 10.0.0.2 (VRF default AS 65002) old state Idle event Start new state Connect",
             "routingStep(proto: \"BGP\", neighbor: \"10.0.0.2\")"),
            ("<189>Sep 23 10:42:11 LEAF-EOS-1 Bgp: %BGP-5-ADJCHANGE: peer 10.0.0.2 (VRF default AS 65002) old state Idle event RecvOpen new state Established",
             "routing(proto: \"BGP\", neighbor: \"10.0.0.2\", up: true)"),
            ("<189>Sep 23 10:42:12 LEAF-EOS-1 Bgp: %BGP-5-ADJCHANGE: peer 10.0.0.2 (VRF default AS 65002) old state Established event Stop new state Idle",
             "routing(proto: \"BGP\", neighbor: \"10.0.0.2\", up: false)"),
            // …and spanning tree's still is.
            ("<189>Sep 23 10:42:03 SW1 %SPANTREE-5-TOPOTRAP: Topology Change Trap for vlan 10", "stp(SheepLog.STPKind.topologyChange, port: nil)"),
            ("<186>Sep 23 10:42:04 SW1 %SPANTREE-2-LOOPGUARD_BLOCK: Loop guard blocking port GigabitEthernet1/0/2 on VLAN0010.", "stp(SheepLog.STPKind.loop, port: Optional(\"GigabitEthernet1/0/2\"))"),
            ("<186>Sep 23 10:42:05 SW1 %SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port Gi1/0/3 with BPDU Guard enabled. Disabling port.", "stp(SheepLog.STPKind.bpduGuard, port: Optional(\"Gi1/0/3\"))"),
        ]
        for (line, want) in table { XCTAssertEqual(kind(line), want, line) }
    }

    // MARK: - 5. SNMP discards over real walks

    /// An Interfaces walk against the lab (`Tests/snmp-lab.sh`; `SHEEPLOG_SNMP_LAB_PORT` for
    /// another port): the snapshot Troubleshoot records carries ifTable's discards and
    /// ifXTable's 64-bit packet counters for every port, as the agent's numbers (not a
    /// formatted value read up to its first separator); two walks compare without a finding.
    func testDiscardRateOverALabIfXTableWalk() async throws {
        let env = ProcessInfo.processInfo.environment
        guard env["SHEEPLOG_SNMP_LAB"] == "1" || env["TEST_RUNNER_SHEEPLOG_SNMP_LAB"] == "1" else {
            throw XCTSkip("Start Tests/snmp-lab.sh and set SHEEPLOG_SNMP_LAB=1.")
        }
        let port = env["SHEEPLOG_SNMP_LAB_PORT"] ?? env["TEST_RUNNER_SHEEPLOG_SNMP_LAB_PORT"] ?? "1161"
        let target = "127.0.0.1:\(port)"
        let first = try await walkInterfaces(target)
        let flows = FindingRules.portFlows(first.values)
        XCTAssertGreaterThanOrEqual(flows.count, 1)
        // The agent's own numbers, straight from the client.
        let client = SNMPClient(target: SNMPTarget(host: "127.0.0.1", port: UInt16(port)!, timeout: 2, retries: 1),
                                credentials: SNMPCredentials(version: .v2c, community: "public"), engines: EngineCache())
        let hc = try await client.walk(OID([1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 7]))
        for vb in hc.varBinds {
            guard case .counter64(let v) = vb.value, let idx = vb.oid.parts.last, let seen = flows[idx]?[0].pHC[7] else { continue }
            XCTAssertLessThanOrEqual(seen, v, "ifHCInUcastPkts.\(idx) read from the walk")
            XCTAssertGreaterThan(seen &+ 1_000_000, v, "ifHCInUcastPkts.\(idx): \(seen) vs \(v)")
        }
        XCTAssertTrue(flows.values.allSatisfy { $0[0].discards != nil && $0[1].discards != nil }, "ifIn/OutDiscards for every port")
        XCTAssertTrue(flows.values.contains { !$0[0].pHC.isEmpty }, "ifXTable's packet counters")
        try await Task.sleep(for: .seconds(2))
        let second = try await walkInterfaces(target)
        let r = Round13Tests.analyze(snmp: [first, second], now: second.taken.addingTimeInterval(1))
        XCTAssertFalse(r.findings.contains { $0.rule.hasPrefix("snmp.discard") }, r.findings.map(\.title).description)
    }

    /// Walks Interfaces through the Test pane's model and records the result as Troubleshoot does.
    private func walkInterfaces(_ target: String, taken: Date = Date()) async throws -> SNMPSnapshot {
        let m = SNMPTestModel.shared
        m.setTarget(target)
        m.version = .v2c
        m.community = "public"
        m.timeout = 2
        m.retries = 1
        m.walkInterfaces()
        await waitUntil(30) { !m.isRunning }
        let run = try XCTUnwrap(m.lastFinished)
        XCTAssertTrue(run.succeeded, m.heading)
        return try XCTUnwrap(TroubleshootModel.snapshot(of: run, rows: m.rows, interfaces: m.interfaces, taken: taken))
    }

    /// An agent with ifTable only (32-bit counters) whose counters wrap past 4,294,967,295
    /// between two walks: the wrap is growth (a smaller value was read as counters cleared — the
    /// wrap's 5,000 discards were lost; a packet counter's wrap left discards without a rate, so
    /// 150 discards in ten million packets were a warning); a restart between the walks is not a
    /// wrap; `clear counters` (small before, smaller after) is not a wrap either.
    func testThirtyTwoBitCounterWrapBetweenTwoWalks() async throws {
        let m = SNMPTestModel.shared
        let saved = (m.host, m.port, m.credentials, m.oidText, m.timeout, m.retries)
        func table(inUcast: UInt32, inDiscards: UInt32, outUcast: UInt32, outDiscards: UInt32, upTime: UInt32) -> [VarBind] {
            let e = OID.ifTable.appending(1)
            func v(_ col: UInt32, _ value: SNMPValue) -> VarBind { VarBind(e.appending([col, 1]), value) }
            return [VarBind(.sysUpTime, .timeTicks(upTime)),
                    v(1, .integer(1)), v(2, .octetString(Data("ge-0/0/1".utf8))), v(3, .integer(6)), v(5, .gauge32(1_000_000_000)),
                    v(7, .integer(1)), v(8, .integer(1)), v(9, .timeTicks(100)), v(10, .counter32(1_000)),
                    v(11, .counter32(inUcast)), v(12, .counter32(0)), v(13, .counter32(inDiscards)), v(14, .counter32(0)),
                    v(16, .counter32(2_000)), v(17, .counter32(outUcast)), v(18, .counter32(0)), v(19, .counter32(outDiscards)), v(20, .counter32(0))]
                .sorted { $0.oid < $1.oid }
        }
        let wrapBase = UInt32.max - 999                  // 4,294,966,296
        let agent = try FakeAgent(mib: table(inUcast: UInt32.max - 1_000_000, inDiscards: wrapBase, outUcast: UInt32.max - 5_000_000,
                                             outDiscards: 1_000, upTime: 8_640_000))
        defer {
            agent.stop()
            m.host = saved.0; m.port = saved.1; m.applyCredentials(saved.2); m.oidText = saved.3; m.timeout = saved.4; m.retries = saved.5
            let account = "127.0.0.1:\(agent.port)"
            KeychainProbe.later { KeychainStore.delete(account: account) }
        }
        let target = "127.0.0.1:\(agent.port)"
        let w1 = try await walkInterfaces(target, taken: Self.at(0))
        // Five minutes on: in, 1,000,000 + 1,000,001 packets and 5,000 discards, both counters
        // wrapped; out, 10,000,000 packets (wrapped) and 150 discards (not wrapped).
        agent.mib = table(inUcast: 1_000_000, inDiscards: 4_000, outUcast: 4_999_999, outDiscards: 1_150, upTime: 8_670_000)
        let w2 = try await walkInterfaces(target, taken: Self.at(300))
        let flows = FindingRules.portFlows(w2.values)
        XCTAssertEqual(flows[1]?[0].p32[11], 1_000_000, "ifInUcastPkts read")
        var r = Round13Tests.analyze(snmp: [w1, w2], now: Self.at(400))
        let grow = try XCTUnwrap(r.findings.first { $0.rule == "snmp.discardsGrowing" }, r.findings.map(\.title).description)
        XCTAssertEqual(grow.title, "Discards are growing on \(w2.name): ge-0/0/1 in 24.9 per 10,000 packets (+5,000) in 5 min.")
        XCTAssertFalse(r.findings.contains { $0.rule == "snmp.discards" })
        // The unit rules: wrap, clear, 64-bit.
        XCTAssertEqual(FindingRules.delta32(4_000, UInt64(wrapBase)), 5_000)
        XCTAssertNil(FindingRules.delta32(200, 9_000), "cleared, not wrapped")
        XCTAssertEqual(FindingRules.delta32(9_000, 200), 8_800)
        // A restart between the walks (uptime shorter than the time between them): the second
        // walk's totals, not a wrap.
        agent.mib = table(inUcast: 1_000_000, inDiscards: 4_000, outUcast: 4_999_999, outDiscards: 1_150, upTime: 12_000)
        let rebooted = try await walkInterfaces(target, taken: Self.at(300))
        r = Round13Tests.analyze(snmp: [w1, rebooted], now: Self.at(400))
        XCTAssertFalse(r.findings.contains { $0.rule == "snmp.discardsGrowing" }, r.findings.map(\.title).description)
        XCTAssertTrue(r.findings.contains { $0.rule == "snmp.discards" }, "4,000 of a million since the restart: \(r.findings.map(\.title))")
    }

    // MARK: - 6. The client report's sentences

    /// Each part of the report on a minimal fixture says what it should: where it is (a log
    /// line's port, the bridge table, a DHCP VLAN, not known), findings, log lines, DHCP,
    /// DNS, ARP, TCP flows and each next step — the Markdown export has the same sentences.
    func testEveryReportSectionOnAMinimalFixture() throws {
        typealias F = TroubleshootFixture
        let mac = "02:00:5e:1e:00:31", ip = "10.1.30.60"
        func pk(_ frames: [(Double, [UInt8])]) -> [Packet] { frames.enumerated().map { F.packet($0.element.1, at: Self.at($0.element.0), id: $0.offset + 1, start: Self.t0) } }
        let discover = { (t: Double) in (t, F.udp4(srcMAC: mac, dstMAC: "ff:ff:ff:ff:ff:ff", src: "0.0.0.0", dst: "255.255.255.255", sport: 68, dport: 67, vlan: 20,
                                                  F.dhcp(op: 1, type: 1, xid: 0x77, client: mac))) }
        let offer = (1.5, F.udp4(srcMAC: F.routerMAC, dstMAC: mac, src: "10.1.20.1", dst: ip, sport: 67, dport: 68, vlan: 20,
                                 F.dhcp(op: 2, type: 2, xid: 0x77, client: mac, yiaddr: ip, server: "10.1.0.10", lease: 3_600)))
        let ack = (2.0, F.udp4(srcMAC: F.routerMAC, dstMAC: mac, src: "10.1.20.1", dst: ip, sport: 67, dport: 68, vlan: 20,
                               F.dhcp(op: 2, type: 5, xid: 0x77, client: mac, yiaddr: ip, server: "10.1.0.10", lease: 3_600)))
        func dnsQ(_ t: Double, _ id: Int, _ name: String) -> (Double, [UInt8]) {
            (t, F.udp4(srcMAC: mac, dstMAC: F.routerMAC, src: ip, dst: "10.1.0.53", sport: 50_000 + id, dport: 53, vlan: nil, F.dns(id: id, name: name, response: false)))
        }
        func dnsA(_ t: Double, _ id: Int, _ name: String, rcode: Int) -> (Double, [UInt8]) {
            (t, F.udp4(srcMAC: F.routerMAC, dstMAC: mac, src: "10.1.0.53", dst: ip, sport: 53, dport: 50_000 + id, vlan: nil,
                       F.dns(id: id, name: name, response: true, rcode: rcode, answer: rcode == 0 ? "10.1.40.1" : nil)))
        }
        func line(_ text: String, host: String = "ACC-SW1", id: Int = 1) -> LogEntry {
            parsedLine("<14>1 - \(host) app - - - \(text)", from: "10.66.1.1", received: Self.at(5), id: id)
        }
        func report(_ q: String = mac, packets: [Packet] = [], entries: [LogEntry] = [], snmp: [SNMPSnapshot] = [], findings: [Finding] = []) -> ClientReport {
            var input = TroubleshootInput()
            input.packets = packets
            input.entries = entries
            input.flows = TCPFlowAnalyzer.analyze(packets)
            input.snmp = snmp
            input.now = Self.at(60)
            return ClientReport.build(q, input: input, findings: findings)!
        }
        let clock = { (s: Double) in FText.clock(Self.at(s)) }
        var fdb: [OID: String] = [:]
        fdb[ClientSearch.fdb.appending([2, 0, 0x5e, 0x1e, 0, 0x31])] = "7"
        fdb[ClientSearch.basePortIfIndex.appending(7)] = "107"
        let walk = SNMPSnapshot(host: "10.66.1.1", taken: Self.at(30), sysName: "ACC-SW1", sysUpTime: 8_640_000,
                                interfaces: [Round13Tests.ifRow(107, "1/1/7")], values: fdb)
        let finding = Finding(id: "x", rule: "dhcp.noOffer", severity: .bad, category: .dhcp, source: .packets,
                              title: "Clients on VLAN 20 get no DHCP offer.", detail: "…", firstSeen: Self.at(0), lastSeen: Self.at(1),
                              client: mac, nextSteps: ["Check the DHCP relay on VLAN 20."])
        let many = (0..<45).map { line("client \(mac) seen \($0)", id: 100 + $0) }
        let rows: [(String, ClientReport, String)] = [
            ("where: log line", report(entries: [line("client \(mac) authenticated on port 1/1/7")]),
             "- ACC-SW1 — port 1/1/7 (log line at \(clock(5)))"),
            ("where: bridge table", report(snmp: [walk]), "- ACC-SW1 — 1/1/7 (bridge table, SNMP walk at \(clock(30)))"),
            ("where: DHCP VLAN", report(packets: pk([discover(0)])), "- VLAN 20 (its DHCP packets are tagged with it; the switch port is not known)"),
            ("where: not known", report(packets: pk([dnsQ(0, 1, "a.example")]), entries: []), "Not known — no log line or bridge table names its switch port."),
            ("identity", report(packets: pk([discover(0), offer, ack])), "**Also known as:** IP \(ip) (DHCP ACK at \(clock(2)))"),
            ("findings: none", report(packets: pk([discover(0)])), "No finding is about this client."),
            ("findings: one", report(packets: pk([discover(0)]), findings: [finding]), "- **Problem** — Clients on VLAN 20 get no DHCP offer."),
            ("log lines: none", report(packets: pk([discover(0)])), "No syslog line or trap mentions it."),
            ("log lines: the last 40", report(entries: many), "The last 40 of 45:"),
            ("DHCP: lines", report(packets: pk([discover(0), offer, ack])), "- `\(clock(1.5))  Offer → \(ip) from 10.1.0.10, lease 1 h (VLAN 20)`"),
            ("DHCP: no offer", report(packets: pk([discover(0), discover(4), discover(12)])),
             "1. It asked for an address 3 times and got no Offer: check the DHCP scope and relay for its VLAN (20)."),
            ("DHCP: no ack", report(packets: pk([discover(0), offer])), "1. It was offered an address but never got an ACK: look for a NAK or a second DHCP server."),
            ("DNS: summary", report(ip, packets: pk([discover(0), offer, ack, dnsQ(3, 1, "a.example"), dnsA(3.1, 1, "a.example", rcode: 2),
                                                     dnsQ(4, 2, "b.example"), dnsQ(5, 3, "c.example"), dnsA(5.1, 3, "c.example", rcode: 0)])),
             "- 3 queries to 10.1.0.53; 1 failed (SERVFAIL / NXDOMAIN / REFUSED), 1 unanswered."),
            ("DNS: failing names", report(ip, packets: pk([dnsQ(3, 1, "a.example"), dnsA(3.1, 1, "a.example", rcode: 2)])), "- failed: a.example ×1"),
            ("DNS: next step", report(ip, packets: pk([dnsQ(3, 1, "a.example"), dnsA(3.1, 1, "a.example", rcode: 2)])),
             "Many of its DNS lookups failed: check the resolver it uses (10.1.0.53)."),
            ("ARP", report(ip, packets: pk([(1, F.arp(request: true, senderMAC: mac, senderIP: ip, targetIP: "10.1.30.1", vlan: nil))])),
             "- `\(clock(1))  who has 10.1.30.1? tell \(ip) (\(mac))`"),
            ("TCP flows: none", report(packets: pk([discover(0)])), "No TCP conversation of this client in the capture."),
            ("next step: switch port", report(ip, packets: pk([dnsQ(0, 1, "a.example"), dnsA(0.1, 1, "a.example", rcode: 0)])),
             "Find its switch port: show mac address-table address \\<its MAC\\>, or walk the bridge table (dot1dTpFdbPort) on the SNMP Test pane."),
            ("next step: nothing", report("10.99.99.99"), "Nothing SheepLog holds mentions 10.99.99.99: check the spelling, or capture on its switch port (SPAN) and try again."),
            ("next step: a finding's", report(packets: pk([discover(0)]), findings: [finding]), "Check the DHCP relay on VLAN 20."),
            ("packets", report(packets: pk([discover(0), offer])), "Packets involving it: 2."),
        ]
        for (name, r, sentence) in rows {
            XCTAssertTrue(r.markdown.contains(sentence), "\(name): «\(sentence)» not in\n\(r.markdown)")
        }
        // A bad conversation's next step names it.
        var s = TCPFlowDemo.Script(firstID: 1, offset: 0, client: ip, clientPort: 50_900, server: "10.2.0.9", serverPort: 22)
        s.c(0, .syn); s.c(1, .syn); s.c(3, .syn)
        let bad = report(ip, packets: s.packets)
        let step = try XCTUnwrap(bad.nextSteps.first { $0.hasPrefix("Show the flow") }, bad.nextSteps.description)
        XCTAssertTrue(step.hasPrefix("Show the flow \(ip):50900 → 10.2.0.9:22: "), step)
        XCTAssertTrue(bad.markdown.contains("## TCP flows (1)"), bad.markdown)
    }

    // MARK: - 7. Sweep

    /// A report built while the Log pane is paused lists the held lines, and its log link counts
    /// them as in memory (they are: held, not rolled out).
    func testReportOfHeldLinesSaysTheyAreThere() async throws {
        let logs = AppModel.shared.logs
        logs.clear()
        logs.paused = true
        var entries: [LogEntry] = []
        for k in 0..<5 { entries.append(parsedLine("<14>1 - ACC-SW1 app - - - client 10.1.30.61 roamed \(k)", from: "10.66.1.1", id: 8_000_000 + k)) }
        logs.ingest(entries)
        await waitUntil { logs.pausedCount == 5 }
        var input = TroubleshootModel.shared.currentInput()
        input.takeHeld()
        let r = try XCTUnwrap(ClientReport.build("10.1.30.61", input: input, findings: []))
        XCTAssertEqual(r.logTotal, 5)
        XCTAssertEqual(ReportLink.title("Show on the Log pane", r.logEvidence, epoch: r.packetEpoch), "Show on the Log pane")
        logs.paused = false
    }

    /// MIB import over an earlier copy of the same file: replaced only once the new one is
    /// written (it was deleted first — a write that failed lost the module); a folder in the
    /// way is replaced by the file.
    func testMIBImportReplacesACopyOnlyWhenWritten() async throws {
        let folder = try tempDir()
        let srcDir = try tempDir()
        let src = srcDir.appending(path: "LAB-MIB.mib")
        let v1 = "LAB-MIB DEFINITIONS ::= BEGIN\nIMPORTS enterprises FROM SNMPv2-SMI;\nlab OBJECT IDENTIFIER ::= { enterprises 99999 }\nEND\n"
        try v1.write(to: src, atomically: true, encoding: .utf8)
        let reg = MIBRegistry()
        reg.userFolderOverride = folder
        reg.loadNow(bundled: MIBTests.bundledURLs())
        func settle() async { await waitUntil(20) { !reg.isLoading } }
        reg.importFiles([src])
        await settle()
        let dest = folder.appending(path: "LAB-MIB.mib")
        XCTAssertEqual(try String(contentsOf: dest, encoding: .utf8), v1)
        // Imported again, changed: replaced by the new text.
        let v2 = v1.replacingOccurrences(of: "99999", with: "99998")
        try v2.write(to: src, atomically: true, encoding: .utf8)
        reg.importFiles([src])
        await settle()
        XCTAssertEqual(try String(contentsOf: dest, encoding: .utf8), v2)
        XCTAssertEqual(reg.oid(forName: "lab"), OID([1, 3, 6, 1, 4, 1, 99998]))
        // A folder where the file goes: replaced by the file.
        try FileManager.default.removeItem(at: dest)
        try FileManager.default.createDirectory(at: dest.appending(path: "inside"), withIntermediateDirectories: true)
        reg.importFiles([src])
        await settle()
        var isDir: ObjCBool = true
        XCTAssertTrue(FileManager.default.fileExists(atPath: dest.path, isDirectory: &isDir))
        XCTAssertFalse(isDir.boolValue, "the folder in the way")
        // Nothing but the module in the folder (no temporary file of the atomic write).
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: folder.path).filter { !$0.hasPrefix(".") }, ["LAB-MIB.mib"])
    }

    /// A Clear while the Packets table is detached (another pane shown), then the pane again:
    /// the table is the store's, the selection gone with the cleared packet, no Jump pill.
    func testPacketsTableAfterAClearWhileAway() async throws {
        let store = AppModel.shared.packets
        store.clear()
        let c = PacketTableController()
        c.liveOverride = true
        let scroll = PacketTableView.makeScrollView(controller: c)
        let table = try XCTUnwrap(scroll.documentView as? NSTableView)
        store.ingest(Round11InteractionTests.conversations())
        await spin(100)
        table.selectRowIndexes(IndexSet(integer: 3), byExtendingSelection: false)
        await spin(50)
        XCTAssertNotNil(c.selected)
        c.detach()
        store.clear()
        store.ingest(Round11InteractionTests.conversations(firstID: 1, offset: 60, port: 52_000))
        await spin(100)
        c.reattach()
        await spin(100)
        XCTAssertEqual(table.numberOfRows, store.visible.count)
        XCTAssertFalse(c.showJump)
    }
}
