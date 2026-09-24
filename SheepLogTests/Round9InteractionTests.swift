import AppKit
import SwiftUI
import XCTest
@testable import SheepLog

/// Round 9: scripted interaction sequences on the real objects — the state a user builds by
/// clicking through the app (a filter typed, a context-menu term added, Sources "Show", Pause,
/// Clear, the order and regex toggles), checked after every step: the filter text parses or the
/// last good one is kept with the error shown, `visible` is a fresh filter of `entries`, and the
/// table's rows and selection agree with the inspector.
@MainActor
final class Round9InteractionTests: XCTestCase {
    private var windows: [NSWindow] = []

    override func tearDown() async throws {
        for w in windows { w.close() }
        windows = []
    }

    // MARK: - Harness

    private static let corpusDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .appending(path: "Tests/corpus", directoryHint: .isDirectory)

    /// Every corpus line, each vendor from its own few addresses (hostnames come from the lines).
    private static func corpusRaws(received: Date = Date()) throws -> [RawSyslog] {
        var out: [RawSyslog] = []
        let files = ["arubacx", "arubaos", "arubasw", "clearpass", "huawei", "checkpoint", "paloalto", "fortigate", "other"]
        for (k, file) in files.enumerated() {
            let text = try String(contentsOf: corpusDir.appending(path: "\(file).log"), encoding: .utf8)
            for (i, line) in text.split(separator: "\n").enumerated() {
                out.append(RawSyslog(received: received, sourceAddress: "10.9.\(k).\(i % 3 + 1)", sourcePort: 514,
                                     transport: i % 4 == 0 ? .tcp : .udp, text: String(line)))
            }
        }
        return out
    }

    private final class SelectionBox { var id: Int? }

    private struct Grid {
        let coordinator: LogTableView.Coordinator
        let table: LogNSTableView
        let box: SelectionBox
    }

    private func grid(_ store: LogStore) -> Grid {
        let box = SelectionBox()
        let binding = Binding<Int?>(get: { box.id }, set: { box.id = $0 })
        let c = LogTableView.Coordinator(store: store)
        c.parent = LogTableView(store: store, selectedID: binding)
        let scroll = LogTableView.makeScrollView(coordinator: c)
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1000, height: 500), styleMask: [.titled], backing: .buffered, defer: false)
        w.isReleasedWhenClosed = false
        scroll.frame = NSRect(x: 0, y: 0, width: 1000, height: 500)
        w.contentView = scroll
        w.layoutIfNeeded()
        windows.append(w)
        return Grid(coordinator: c, table: scroll.documentView as! LogNSTableView, box: box)
    }

    private func spin(_ seconds: Double = 0.02) {
        RunLoop.main.run(until: Date().addingTimeInterval(seconds))
    }

    /// What SwiftUI would do after a store change: the representable's update, then the
    /// run loop (the coordinator clears a gone selection asynchronously).
    private func settle(_ store: LogStore, _ g: Grid) async {
        await store.settle()
        g.coordinator.sync(force: false)
        try? await Task.sleep(for: .milliseconds(20))
        g.coordinator.sync(force: false)
    }

    /// Everything a step must leave true.
    private func check(_ store: LogStore, _ g: Grid, lastGood: inout Query, _ step: String,
                       file: StaticString = #filePath, line: UInt = #line) {
        // The filter text parses (and is the query in force), or the last good query is kept
        // and the error is shown.
        if let q = try? Query.parse(store.queryText, regexWords: store.regexMode) {
            XCTAssertEqual(store.query, q, "query in force ≠ the text \(step)", file: file, line: line)
            XCTAssertTrue(store.queryError == nil || store.queryErrorIsNotice, "error left on a good filter \(step): \(store.queryError ?? "")",
                          file: file, line: line)
            lastGood = q
        } else {
            XCTAssertEqual(store.query, lastGood, "a bad filter replaced the last good one \(step)", file: file, line: line)
            XCTAssertNotNil(store.queryError, "a bad filter without an error \(step)", file: file, line: line)
            XCTAssertFalse(store.queryErrorIsNotice, file: file, line: line)
        }
        let f = LogFilter(query: store.query, source: store.selectedSource, mask: store.severityMask)
        XCTAssertEqual(store.visible.map(\.id), store.entries.filter { f.matches($0) }.map(\.id),
                       "visible ≠ filter(entries) \(step)", file: file, line: line)
        XCTAssertEqual(g.table.numberOfRows, store.visibleCount, "table rows \(step)", file: file, line: line)
        // Selection vs inspector.
        let selected = g.table.selectedRowIndexes
        if let id = g.box.id {
            XCTAssertNotNil(store.entry(id: id), "inspector on a line that left the ring \(step)", file: file, line: line)
            if let row = store.visibleRow(forID: id) {
                XCTAssertTrue(selected.contains(row), "the inspector's line is visible but not selected \(step)", file: file, line: line)
            } else {
                XCTAssertTrue(selected.isEmpty, "rows selected while the inspector's line is filtered out \(step)", file: file, line: line)
            }
        } else {
            XCTAssertTrue(selected.isEmpty, "rows selected with no inspector line \(step): \(Array(selected))", file: file, line: line)
        }
        for r in selected { XCTAssertLessThan(r, store.visibleCount, "selected row out of range \(step)", file: file, line: line) }
    }

    /// Right-click on `row` (selected first, as a right-click on an unselected row does in the
    /// grid) and choose the item whose title starts with `prefix`. False when there is none.
    /// With `realClick` the row is right-clicked as it is (another row may stay selected).
    @discardableResult
    private func contextMenu(_ g: Grid, row: Int, _ prefix: String, realClick: Bool = false) -> Bool {
        guard row >= 0, row < g.table.numberOfRows else { return false }
        let found: NSMenuItem?
        if realClick {
            found = rightClick(g.table, row: row, choose: prefix)
        } else {
            g.table.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
            guard let menu = g.table.menu else { return false }
            g.coordinator.menuNeedsUpdate(menu)
            found = menu.items.first { $0.title.hasPrefix(prefix) }
        }
        guard let item = found, let action = item.action else { return false }
        return NSApp.sendAction(action, to: item.target, from: item)
    }

    static let twelveFilters: [String] = [
        "down",                                         // simple
        "sev:err OR vendor:huawei",                     // a OR b
        "NOT (deny traffic)",                           // NOT (a b)
        "/log(in|out)/ host:10.9.",                     // regex + host prefix
        "sev:warn,err vendor:forti",                    // severity list + vendor
        "host:10.9.4.0/24",                             // a subnet
        "host:*-core*",                                 // a glob
        "\"unterminated phrase",                        // parse error
        "",                                             // empty
        (1...30).map { "-zz\($0)" }.joined(separator: " "),   // 30 terms
        "deny OR",                                      // trailing OR (parse error)
        "-\"Admin login\"",                             // NOT a phrase
    ]

    // MARK: - 1. Log filter + context menu sequences

    func testLogFilterAndContextMenuSequences() async throws {
        let store = LogStore()
        let raws = try Self.corpusRaws()
        store.ingest(SyslogListener.parseBatch(raws, overrides: [:]))
        let g = grid(store)
        await settle(store, g)
        var lastGood = Query.empty
        check(store, g, lastGood: &lastGood, "start")

        for (n, filter) in Self.twelveFilters.enumerated() {
            let tag = "[filter \(n): \(filter.prefix(40))]"
            // A fresh start per filter: no source, no query, not paused, default toggles.
            store.selectedSource = nil
            store.paused = false
            store.regexMode = false
            store.queryText = ""
            store.applyQueryText()
            g.table.deselectAll(nil)
            await settle(store, g)
            lastGood = store.query

            store.queryText = filter
            store.applyQueryText()
            await settle(store, g)
            check(store, g, lastGood: &lastGood, "\(tag) typed")

            // Select a line: the inspector follows.
            if store.visibleCount > 1 {
                g.table.selectRowIndexes(IndexSet(integer: 1), byExtendingSelection: false)
                XCTAssertEqual(g.box.id, store.visibleEntry(atRow: 1).id, tag)
            }
            check(store, g, lastGood: &lastGood, "\(tag) selected")

            for item in ["Filter this program", "Filter this host", "Exclude this host"] {
                let before = store.queryText
                let hadRows = store.visibleCount > 0
                let target = hadRows ? store.visibleEntry(atRow: 0) : nil
                let chosen = contextMenu(g, row: 0, item, realClick: n % 2 == 1)
                await settle(store, g)
                check(store, g, lastGood: &lastGood, "\(tag) \(item)")
                guard chosen, let target else { continue }
                XCTAssertNotEqual(store.queryText, before, "\(tag) \(item) changed nothing")
                // What the user asked for is what the table shows: the context-menu term narrows
                // the rows that were on screen (the filter in force), whatever the text was.
                XCTAssertNil(store.queryError.flatMap { store.queryErrorIsNotice ? nil : $0 },
                             "\(tag) \(item) left a filter that does not apply: \(store.queryText)")
                if item == "Exclude this host" {
                    XCTAssertFalse(store.visible.contains { $0.sourceAddress == target.sourceAddress }, "\(tag) \(item)")
                } else if item == "Filter this host" {
                    XCTAssertTrue(store.visible.allSatisfy { $0.sourceAddress == target.sourceAddress }, "\(tag) \(item)")
                    XCTAssertTrue(store.visible.contains { $0.id == target.id }, "\(tag) \(item): the clicked line itself")
                } else {
                    XCTAssertTrue(store.visible.contains { $0.id == target.id }, "\(tag) \(item): the clicked line itself")
                }
            }

            // Sources "Show" on an address: every line of it, the query cleared.
            let address = raws[n * 3 % raws.count].sourceAddress
            store.showSource(address)
            await settle(store, g)
            check(store, g, lastGood: &lastGood, "\(tag) Show source")
            XCTAssertEqual(store.queryText, "", tag)
            XCTAssertNil(store.queryError, tag)
            XCTAssertEqual(store.visible.count, store.entries.filter { $0.sourceAddress == address }.count, tag)

            // Type the filter again on top of the source (the capsule stays).
            store.queryText = filter
            store.applyQueryText()
            await settle(store, g)
            check(store, g, lastGood: &lastGood, "\(tag) filter + source")

            // Pause, lines arrive, the table holds still; Resume shows them.
            store.paused = true
            let frozen = store.visible.map(\.id)
            store.ingest(SyslogListener.parseBatch(Array(raws.prefix(20)), overrides: [:]))
            await settle(store, g)
            XCTAssertEqual(store.visible.map(\.id), frozen, "\(tag) paused table moved")
            store.paused = false
            await settle(store, g)
            check(store, g, lastGood: &lastGood, "\(tag) resumed")

            // Newest first off and on (as the Settings toggle drives the store).
            store.newestFirst.toggle()
            await settle(store, g)
            check(store, g, lastGood: &lastGood, "\(tag) order toggled")
            store.newestFirst.toggle()
            await settle(store, g)
            check(store, g, lastGood: &lastGood, "\(tag) order back")

            // The .* toggle: bare words become regexes (a word that is not one is an error).
            store.regexMode = true
            await settle(store, g)
            check(store, g, lastGood: &lastGood, "\(tag) regex on")
            store.regexMode = false
            await settle(store, g)
            check(store, g, lastGood: &lastGood, "\(tag) regex off")

            // The source capsule's ✕.
            store.selectedSource = nil
            await settle(store, g)
            check(store, g, lastGood: &lastGood, "\(tag) source cleared")

            // Clear: nothing left, no inspector.
            if n % 4 == 3 {
                if store.visibleCount > 0 { g.table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false) }
                store.clear()
                await settle(store, g)
                XCTAssertNil(g.box.id, "\(tag) the inspector kept a cleared line")
                check(store, g, lastGood: &lastGood, "\(tag) cleared")
                store.ingest(SyslogListener.parseBatch(raws, overrides: [:]))
                await settle(store, g)
                check(store, g, lastGood: &lastGood, "\(tag) refilled")
            }
        }
    }

    // MARK: - 1b. Packets filter + context menu + Flows round trip

    private static let pcapDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .appending(path: "Tests/pcaps", directoryHint: .isDirectory)

    static let twelvePacketFilters: [String] = [
        "tcp",                                          // simple word
        "proto:dns OR proto:tls",                       // a OR b
        "NOT (proto:udp port:53)",                      // NOT (a b)
        "/GET|Client Hello/ ip:192.168.",               // regex + address prefix
        "port:https flags:syn",                         // service name + flags
        "ip:192.168.0.0/16",                            // a subnet
        "ip:10.*",                                      // prefix with *
        "\"unterminated",                               // parse error
        "",                                             // empty
        (1...30).map { "-zz\($0)" }.joined(separator: " "),
        "proto:tcp OR",                                 // trailing OR
        "-\"Standard query\"",                          // NOT a phrase
    ]

    private func waitUntil(_ timeout: Double = 5, _ condition: () -> Bool) async {
        let end = Date().addingTimeInterval(timeout)
        while !condition(), Date() < end { try? await Task.sleep(for: .milliseconds(10)) }
    }

    /// `visible` = the query in force over `packets` (after the off-main rescan lands).
    private func packetsSettled(_ store: PacketStore) -> Bool {
        let m = store.query.isEmpty ? nil : PacketMatcher(store.query)
        return store.visible.map(\.id) == PacketStore.filter(store.packets, with: m).map(\.id)
    }

    private func checkPackets(_ store: PacketStore, _ controller: PacketTableController, _ tv: NSTableView,
                              lastGood: inout Query, _ step: String, file: StaticString = #filePath, line: UInt = #line) async {
        await waitUntil { packetsSettled(store) }
        controller.refreshNow()
        if let q = try? Query.parse(store.queryText) {
            XCTAssertEqual(store.query, q, "query in force ≠ the text \(step)", file: file, line: line)
            lastGood = q
        } else {
            XCTAssertEqual(store.query, lastGood, "a bad filter replaced the last good one \(step)", file: file, line: line)
            XCTAssertNotNil(store.queryError, "\(step)", file: file, line: line)
        }
        XCTAssertTrue(packetsSettled(store), "visible ≠ filter(packets) \(step)", file: file, line: line)
        XCTAssertEqual(tv.numberOfRows, store.visible.count, "table rows \(step)", file: file, line: line)
        if let s = controller.selected {
            XCTAssertTrue(store.contains(id: s.id), "detail on a packet that is gone \(step)", file: file, line: line)
            if let i = store.visibleIndex(of: s.id) {
                XCTAssertTrue(tv.selectedRowIndexes.contains(i), "the detail's packet is shown but not selected \(step)", file: file, line: line)
            }
        } else {
            XCTAssertTrue(tv.selectedRowIndexes.isEmpty, "rows selected with no detail \(step)", file: file, line: line)
        }
    }

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

    func testPacketFilterContextMenuAndFlowsRoundTrip() async throws {
        let store = AppModel.shared.packets
        defer { store.queryText = ""; store.applyQueryNow(synchronous: true); store.clear() }
        let controller = PacketTableController()
        controller.liveOverride = false
        let scroll = PacketTableView.makeScrollView(controller: controller)
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1100, height: 500), styleMask: [.titled], backing: .buffered, defer: false)
        w.isReleasedWhenClosed = false
        scroll.frame = NSRect(x: 0, y: 0, width: 1100, height: 500)
        w.contentView = scroll
        w.layoutIfNeeded()
        windows.append(w)
        let tv = scroll.documentView as! PacketNSTableView

        for file in ["http-tls.pcap", "ssh-banner-rst-scan.pcap", "dns-mdns.pcap"] {
            store.queryText = ""
            store.applyQueryNow(synchronous: true)
            let done = expectation(description: file)
            try store.load(from: Self.pcapDir.appending(path: file)) { done.fulfill() }
            await fulfillment(of: [done], timeout: 10)
            var lastGood = store.query
            await checkPackets(store, controller, tv, lastGood: &lastGood, "\(file) loaded")
            let flows = TCPFlowAnalyzer.analyze(store.packets)

            for (n, filter) in Self.twelvePacketFilters.enumerated() {
                let tag = "[\(file) filter \(n): \(filter.prefix(30))]"
                store.queryText = filter
                store.applyQueryNow()
                await checkPackets(store, controller, tv, lastGood: &lastGood, "\(tag) typed")
                guard !store.visible.isEmpty else { continue }
                let row = min(2, store.visible.count - 1)
                tv.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
                let clicked = store.visible[row]
                XCTAssertEqual(controller.selected?.id, clicked.id, tag)

                for item in ["Filter this source", "Filter this destination", "Filter this conversation"] {
                    guard let r = store.visibleIndex(of: clicked.id) else { break }
                    let mi = try XCTUnwrap(rightClick(tv, row: r, choose: item), "\(tag) \(item)")
                    XCTAssertTrue(NSApp.sendAction(try XCTUnwrap(mi.action), to: mi.target, from: mi), "\(tag) \(item)")
                    await checkPackets(store, controller, tv, lastGood: &lastGood, "\(tag) \(item)")
                    XCTAssertNil(store.queryError, "\(tag) \(item): \(store.queryText)")
                    XCTAssertTrue(store.visibleIndex(of: clicked.id) != nil, "\(tag) \(item) hid the clicked packet: \(store.queryText)")
                    let d = clicked.decoded
                    for p in store.visible {
                        switch item {
                        case "Filter this source": XCTAssertEqual(p.decoded.source, d.source, tag)
                        case "Filter this destination": XCTAssertEqual(p.decoded.destination, d.destination, tag)
                        default:
                            XCTAssertEqual(Set([p.decoded.source, p.decoded.destination]), Set([d.source, d.destination]), tag)
                        }
                    }
                    store.queryText = filter
                    store.applyQueryNow()
                    await checkPackets(store, controller, tv, lastGood: &lastGood, "\(tag) \(item) undone")
                }

                // Show in TCP flows → the conversation and the event carrying the frame → Show
                // packets → exactly those frames in Packets.
                guard let r = store.visibleIndex(of: clicked.id), let mi = rightClick(tv, row: r, choose: "Show in TCP flows") else { continue }
                if clicked.decoded.tcp == nil {
                    XCTAssertFalse(mi.isEnabled, tag)
                    continue
                }
                AppModel.shared.mainPane = .packets
                XCTAssertTrue(NSApp.sendAction(try XCTUnwrap(mi.action), to: mi.target, from: mi), tag)
                XCTAssertEqual(AppModel.shared.mainPane, .flows, tag)
                let request = try XCTUnwrap(AppModel.shared.takePendingFlowRequest(), tag)
                XCTAssertEqual(request.packetID, clicked.id, tag)
                let resolved = try XCTUnwrap(request.resolve(in: flows), "\(tag) no conversation for frame \(clicked.id)")
                XCTAssertTrue(resolved.flow.firstPacketID <= clicked.id && clicked.id <= resolved.flow.lastPacketID, tag)
                guard let eventID = resolved.eventID, let event = resolved.flow.events.first(where: { $0.id == eventID }) else {
                    XCTFail("\(tag) no ladder event carries frame \(clicked.id)")
                    continue
                }
                XCTAssertTrue(event.packetIDs.contains(clicked.id), tag)
                AppModel.shared.mainPane = .packets
                NotificationCenter.default.post(name: .sheepLogPacketFilter, object: FlowView.packetFilter(event.packetIDs, flow: resolved.flow))
                await checkPackets(store, controller, tv, lastGood: &lastGood, "\(tag) Show packets")
                XCTAssertEqual(Set(store.visible.map(\.id)), Set(event.packetIDs), "\(tag) Show packets: \(store.queryText)")
                XCTAssertNil(store.queryError, tag)
                // Back to the filter the user had.
                store.queryText = filter
                store.applyQueryNow()
                await checkPackets(store, controller, tv, lastGood: &lastGood, "\(tag) back")
            }
            // Pause / resume / Clear with a filter on.
            store.queryText = "tcp"
            store.applyQueryNow()
            await checkPackets(store, controller, tv, lastGood: &lastGood, "\(file) tcp")
            if !store.visible.isEmpty { tv.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false) }
            store.clear()
            await checkPackets(store, controller, tv, lastGood: &lastGood, "\(file) cleared")
            XCTAssertNil(controller.selected, "\(file) the detail kept a cleared packet")
        }
    }

    // MARK: - 2. Settings changed while the services run

    private static func diskLines(_ dirs: [URL]) -> [String] {
        dirs.flatMap { dir -> [String] in
            let files = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []
            return files.filter { $0.pathExtension == "log" }
                .flatMap { ((try? String(contentsOf: $0, encoding: .utf8)) ?? "").split(separator: "\n").map(String.init) }
        }
    }

    /// settings.json holds what `AppModel.settings` holds (secrets are never written).
    private func assertSettingsFileMatches(_ step: String, file: StaticString = #filePath, line: UInt = #line) {
        var expected = AppModel.shared.settings
        expected.snmpDefaults.authPassword = ""
        expected.snmpDefaults.privPassword = ""
        expected.snmpDefaults.community = ""
        let onDisk = AppSettings.load(from: AppSettings.file)
        XCTAssertEqual(onDisk, expected, "settings.json ≠ AppModel.settings after \(step)", file: file, line: line)
    }

    private var sent = 0

    /// One syslog line over UDP (and one over TCP when `tcp` is given) and one trap; waits until
    /// the store has them. Returns the markers sent.
    @discardableResult
    private func sendAndExpect(_ step: String, udp: UInt16, tcp: UInt16?, trap: UInt16?, expect: Bool = true,
                               file: StaticString = #filePath, line: UInt = #line) async -> [String] {
        let logs = AppModel.shared.logs
        sent += 1
        var markers: [String] = []
        let u = "r9mark-\(sent)-udp"
        TestSockets.sendUDP(["<13>Sep 24 10:00:00 r9host app: \(u)"], to: udp)
        markers.append(u)
        if let tcp, let fd = TestSockets.connectTCP(tcp) {
            let t = "r9mark-\(sent)-tcp"
            let b = Array("<13>Sep 24 10:00:00 r9host app: \(t)\n".utf8)
            _ = b.withUnsafeBytes { Darwin.send(fd, $0.baseAddress, b.count, 0) }
            close(fd)
            markers.append(t)
        }
        if let trap {
            TestSockets.sendUDP(Round5TrapTests.linkDown(Int64(100_000 + sent)), to: trap)
            markers.append("1.3.6.1.2.1.2.2.1.1.\(100_000 + sent)=")
        }
        guard expect else { return markers }
        await waitUntil(5) { markers.allSatisfy { m in logs.entries.contains { $0.raw.contains(m) } } }
        for m in markers {
            XCTAssertTrue(logs.entries.contains { $0.raw.contains(m) }, "\(step): \(m) not received", file: file, line: line)
        }
        return markers
    }

    func testSettingsChangedWhileServicesRun() async throws {
        let model = AppModel.shared
        let saved = model.settings
        let logs = model.logs
        let tmp = FileManager.default.temporaryDirectory.appending(path: "SheepLogR9-\(UUID().uuidString)", directoryHint: .isDirectory)
        let dirA = tmp.appending(path: "A", directoryHint: .isDirectory)
        let dirB = tmp.appending(path: "B", directoryHint: .isDirectory)
        defer {
            model.stopAll()
            model.settings = saved
            model.dismissAllErrors()
            model.packets.clear()
            try? FileManager.default.removeItem(at: tmp)
        }
        model.dismissAllErrors()
        logs.paused = false
        logs.selectedSource = nil
        logs.queryText = ""
        logs.applyQueryText()

        let udp = TestSockets.freePort(SOCK_DGRAM), tcp = TestSockets.freePort(SOCK_STREAM), trap = TestSockets.freePort(SOCK_DGRAM)
        model.settings.syslogUDPPort = udp
        model.settings.syslogTCPPort = tcp
        model.settings.trapPort = trap
        assertSettingsFileMatches("ports")
        model.startSyslog()
        model.startTraps()
        XCTAssertTrue(model.syslog.isRunning, model.syslog.lastError ?? "")
        XCTAssertTrue(model.traps.isRunning, model.traps.lastError ?? "")
        XCTAssertNil(model.lastError)
        await sendAndExpect("started", udp: udp, tcp: tcp, trap: trap)

        // A live capture on lo0 (skipped where /dev/bpf is not readable).
        let canCapture = FileManager.default.isReadableFile(atPath: "/dev/bpf0")
        if canCapture {
            model.packets.clear()
            model.settings.captureInterface = "lo0"
            model.settings.captureFilter = ""
            model.startCapture()
            model.dismissAllErrors()           // lo0: "does not support promiscuous mode"
            XCTAssertTrue(model.capture.isRunning, model.capture.lastError ?? "")
            await sendAndExpect("capturing", udp: udp, tcp: nil, trap: nil)
            await waitUntil { model.packets.packets.contains { $0.decoded.destinationPort == udp } }
            XCTAssertTrue(model.packets.packets.contains { $0.decoded.destinationPort == udp }, "the capture saw the syslog datagram")
        }

        // Disk logging on (folder A): every line from now on is in the file.
        model.settings.logDirectory = dirA.path
        model.settings.diskLogging = true
        assertSettingsFileMatches("disk on")
        XCTAssertEqual(logs.diskLogger?.directory.standardizedFileURL.path, dirA.standardizedFileURL.path)
        var whileOn: [String] = []
        whileOn += await sendAndExpect("disk on", udp: udp, tcp: tcp, trap: trap)

        // Ports changed: nothing moves until Apply ports; the old ports keep receiving.
        let udp2 = TestSockets.freePort(SOCK_DGRAM), tcp2 = TestSockets.freePort(SOCK_STREAM), trap2 = TestSockets.freePort(SOCK_DGRAM)
        model.settings.syslogUDPPort = udp2
        model.settings.syslogTCPPort = tcp2
        model.settings.trapPort = trap2
        assertSettingsFileMatches("new ports typed")
        XCTAssertEqual(model.syslog.udpPort, udp, "a port change waits for Apply ports")
        XCTAssertEqual(model.traps.port, trap)
        XCTAssertTrue(model.listenerPortsChanged)
        whileOn += await sendAndExpect("old ports before Apply", udp: udp, tcp: tcp, trap: trap)
        model.restartListeners()
        XCTAssertNil(model.lastError, model.lastErrorDetail ?? "")
        XCTAssertEqual(model.syslog.udpPort, udp2)
        XCTAssertEqual(model.syslog.tcpPort, tcp2)
        XCTAssertEqual(model.traps.port, trap2)
        XCTAssertFalse(model.listenerPortsChanged)
        whileOn += await sendAndExpect("after Apply ports", udp: udp2, tcp: tcp2, trap: trap2)
        let stale = await sendAndExpect("old port after Apply", udp: udp, tcp: nil, trap: nil, expect: false)
        try await Task.sleep(for: .milliseconds(300))
        XCTAssertFalse(logs.entries.contains { $0.raw.contains(stale[0]) }, "the old port still listens")

        // Auto-start switches: saved, nothing running is touched.
        model.settings.syslogAutoStart.toggle()
        model.settings.trapAutoStart.toggle()
        assertSettingsFileMatches("auto-start")
        XCTAssertTrue(model.syslog.isRunning && model.traps.isRunning)
        whileOn += await sendAndExpect("auto-start toggled", udp: udp2, tcp: tcp2, trap: trap2)

        // Buffer limit lowered: trimmed at once; raised: kept.
        logs.ingest((0..<3_000).map { _ in parsedLine("<13>Sep 24 10:00:00 filler app: pad", from: "192.0.2.99", id: LogStore.nextID()) })
        model.settings.logLimit = 1_000
        assertSettingsFileMatches("log limit")
        XCTAssertLessThanOrEqual(logs.entries.count, 1_000)
        XCTAssertEqual(logs.limit, 1_000)
        whileOn += await sendAndExpect("limit 1000", udp: udp2, tcp: tcp2, trap: trap2)
        model.settings.logLimit = 50_000
        XCTAssertEqual(logs.limit, 50_000)

        // Newest first: the store follows at once.
        model.settings.newestFirst.toggle()
        XCTAssertEqual(logs.newestFirst, model.settings.newestFirst)
        assertSettingsFileMatches("newest first")
        model.settings.newestFirst.toggle()
        XCTAssertEqual(logs.newestFirst, model.settings.newestFirst)

        // The folder moves to B while lines keep arriving from another thread: every line is
        // in A or B, none lost in the switch.
        let flood = LockedBox<[String]>([])
        let stop = LockedBox(false)
        let sender = Thread {
            var k = 0
            while !stop.value {
                k += 1
                let m = "r9flood-\(k)-x"
                TestSockets.sendUDP(["<13>Sep 24 10:00:00 r9host app: \(m)"], to: udp2)
                flood.mutate { $0.append(m) }
                usleep(500)
            }
        }
        sender.start()
        try await Task.sleep(for: .milliseconds(150))
        model.settings.logDirectory = dirB.path
        try await Task.sleep(for: .milliseconds(150))
        stop.mutate { $0 = true }
        try await Task.sleep(for: .milliseconds(50))
        assertSettingsFileMatches("folder B")
        XCTAssertEqual(logs.diskLogger?.directory.standardizedFileURL.path, dirB.standardizedFileURL.path)
        let floodSent = flood.value
        await waitUntil(5) { Set(logs.entries.map(\.raw)).isSuperset(of: []) && floodSent.allSatisfy { m in logs.entries.contains { $0.raw.hasSuffix(m) } } }
        let received = floodSent.filter { m in logs.entries.contains { $0.raw.hasSuffix(m) } }
        XCTAssertEqual(received.count, floodSent.count, "loopback datagrams lost before the store")
        whileOn += received
        whileOn += await sendAndExpect("folder B", udp: udp2, tcp: tcp2, trap: trap2)

        // SNMP defaults follow into the Test pane.
        model.settings.snmpTimeout = 7.5
        model.settings.snmpRetries = 4
        XCTAssertEqual(SNMPTestModel.shared.timeout, 7.5)
        XCTAssertEqual(SNMPTestModel.shared.retries, 4)
        assertSettingsFileMatches("snmp")

        // Capture settings: they apply at the next Start, and Settings says so meanwhile.
        if canCapture {
            model.settings.captureFilter = "udp port \(udp2)"
            model.settings.capturePromiscuous = false
            assertSettingsFileMatches("capture filter")
            XCTAssertTrue(model.capture.isRunning)
            XCTAssertEqual(model.capture.runningFilter, "", "a running capture is not half-restarted")
            XCTAssertNotNil(SettingsView.captureRestartNote(settings: model.settings, running: true,
                                                            interface: model.capture.interfaceName,
                                                            promiscuous: model.capture.runningPromiscuous,
                                                            filter: model.capture.runningFilter))
            whileOn += await sendAndExpect("capture filter typed", udp: udp2, tcp: tcp2, trap: trap2)
            model.startCapture()                // Stop + Start in the pane
            model.dismissAllErrors()
            XCTAssertTrue(model.capture.isRunning, model.capture.lastError ?? "")
            XCTAssertEqual(model.capture.runningFilter, "udp port \(udp2)")
            XCTAssertNil(SettingsView.captureRestartNote(settings: model.settings, running: true,
                                                         interface: model.capture.interfaceName,
                                                         promiscuous: model.capture.runningPromiscuous,
                                                         filter: model.capture.runningFilter))
            whileOn += await sendAndExpect("capture restarted", udp: udp2, tcp: tcp2, trap: trap2)
            await waitUntil { model.packets.packets.contains { $0.decoded.destinationPort == udp2 } }
            XCTAssertTrue(model.packets.packets.allSatisfy { $0.decoded.destinationPort == udp2 || $0.decoded.sourcePort == udp2 },
                          "the new filter is in force")
            // Packet limit lowered while capturing.
            model.settings.packetLimit = 1_000
            XCTAssertEqual(model.packets.limit, 1_000)
            assertSettingsFileMatches("packet limit")
        }

        // Disk logging off: later lines are not written; everything sent while on is.
        model.settings.diskLogging = false
        assertSettingsFileMatches("disk off")
        XCTAssertNil(logs.diskLogger)
        let afterOff = await sendAndExpect("disk off", udp: udp2, tcp: tcp2, trap: trap2)
        try await Task.sleep(for: .milliseconds(200))
        let onDisk = Self.diskLines([dirA, dirB])
        for m in whileOn {
            XCTAssertEqual(onDisk.filter { $0.contains(m) }.count, 1, "\(m) written \(onDisk.filter { $0.contains(m) }.count) times")
        }
        for m in afterOff { XCTAssertFalse(onDisk.contains { $0.contains(m) }, "\(m) written after disk logging was switched off") }
        XCTAssertNil(model.lastError, model.lastErrorDetail ?? "")
    }

    // MARK: - 4. Traps + syslog + a vendor MIB import at the same time

    /// A FortiGate HA-switch trap (FORTINET-FORTIGATE-MIB) carrying fnSysSerial.0.
    nonisolated static func fortiTrap(_ n: Int) -> [UInt8] {
        let pdu = SNMPPDU(type: BER.trapV2, requestID: Int32(n), varBinds: [
            VarBind(OID.sysUpTimeInstance, .timeTicks(4242)),
            VarBind(OID.snmpTrapOID, .oid(OID([1, 3, 6, 1, 4, 1, 12356, 101, 2, 0, 401]))),
            VarBind(OID([1, 3, 6, 1, 4, 1, 12356, 100, 1, 1, 1, 0]), .octetString(Data("FG100F\(n)".utf8))),
        ])
        return BER.encodeSequence([BER.encodeInteger(1), BER.encodeOctets(Array("public".utf8)), pdu.encoded()])
    }

    func testVendorMIBImportedWhileItsTrapsArrive() async throws {
        let model = AppModel.shared
        let logs = model.logs
        let saved = model.settings
        let tmp = FileManager.default.temporaryDirectory.appending(path: "SheepLogR9Traps-\(UUID().uuidString)", directoryHint: .isDirectory)
        let registry = MIBRegistry()
        registry.userFolderOverride = tmp.appending(path: "mibs", directoryHint: .isDirectory)
        registry.loadNow(bundled: MIBRegistry.bundledURLs())
        defer {
            model.stopAll()
            model.traps.registry = .shared
            model.settings = saved
            model.dismissAllErrors()
            try? FileManager.default.removeItem(at: tmp)
        }
        model.dismissAllErrors()
        logs.paused = false
        logs.clear()
        logs.publishSources()
        let countBefore = logs.sources.first { $0.address == "127.0.0.1" }?.count ?? 0
        model.traps.registry = registry
        let udp = TestSockets.freePort(SOCK_DGRAM), trap = TestSockets.freePort(SOCK_DGRAM)
        model.settings.syslogUDPPort = udp
        model.settings.syslogTCPPort = 0
        model.settings.trapPort = trap
        model.settings.logDirectory = tmp.appending(path: "logs").path
        model.settings.diskLogging = true
        model.startSyslog()
        model.startTraps()
        XCTAssertTrue(model.syslog.isRunning && model.traps.isRunning)

        // A syslog line from the same device first (it names the Sources row).
        TestSockets.sendUDP(["<13>Sep 24 10:00:00 FGT-100F-HQ app: hello from the firewall"], to: udp)
        // Traps before the import…
        for n in 0..<20 { TestSockets.sendUDP(Self.fortiTrap(n), to: trap) }
        await waitUntil { logs.entries.filter { $0.transport == .trap }.count == 20 }
        XCTAssertTrue(logs.entries.filter { $0.transport == .trap }.allSatisfy { $0.program.hasPrefix("enterprises.") },
                      "not named yet: \(logs.entries.last?.program ?? "")")
        // …during it (a sender thread keeps going while the import parses and links)…
        let stop = LockedBox(false)
        let count = LockedBox(20)
        let sender = Thread {
            while !stop.value {
                let n = count.value
                TestSockets.sendUDP(Self.fortiTrap(n), to: trap)
                count.mutate { $0 += 1 }
                usleep(2_000)
            }
        }
        sender.start()
        registry.importFiles([URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appending(path: "Tests/mibs/fortinet")])
        await waitUntil(20) { !registry.isLoading }
        try await Task.sleep(for: .milliseconds(100))
        stop.mutate { $0 = true }
        try await Task.sleep(for: .milliseconds(20))
        // …and after.
        let total = count.value + 5
        for n in count.value..<total { TestSockets.sendUDP(Self.fortiTrap(n), to: trap) }
        await waitUntil(5) { logs.entries.filter { $0.transport == .trap }.count == total }
        try await Task.sleep(for: .milliseconds(300))

        let traps = logs.entries.filter { $0.transport == .trap }
        XCTAssertEqual(traps.count, total)
        let unnamed = traps.filter { $0.program != "fgTrapHaSwitch" }
        XCTAssertEqual(unnamed.count, 0, "\(unnamed.count) of \(total) traps not named after the import, e.g. \(unnamed.first?.program ?? "")")
        XCTAssertTrue(traps.allSatisfy { e in e.fields.contains { $0.key == "fnSysSerial.0" } }, "var-binds named too")
        XCTAssertTrue(logs.visible.filter { $0.transport == .trap }.allSatisfy { $0.program == "fgTrapHaSwitch" }, "the table shows the names")
        // Filters on the names find every one.
        logs.queryText = "app:fgTrapHaSwitch"
        logs.applyQueryText()
        await logs.settle()
        XCTAssertEqual(logs.visible.count, total)
        logs.queryText = ""
        logs.applyQueryText()
        await logs.settle()
        // Sources: the device once, its syslog hostname kept.
        logs.publishSources()
        let rows = logs.sources.filter { $0.address == "127.0.0.1" }
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows.first?.hostname, "FGT-100F-HQ")
        XCTAssertEqual(rows.first?.count, countBefore + total + 1, "Sources counts survive Clear; earlier tests sent from here too")
        // Disk log: every trap once, its raw line as the table has it.
        logs.diskLogger?.sync()
        let disk = Self.diskLines([tmp.appending(path: "logs")])
        for e in traps { XCTAssertEqual(disk.filter { $0.hasSuffix(" " + e.raw) }.count, 1, e.raw) }
        logs.clear()
    }

    // MARK: - 5. Lifecycle: errors at launch, ⌘Q with everything running

    /// Three services failing at launch (syslog, traps, capture), then another error while the
    /// user works through the sheets: shown one at a time, in the order they happened.
    func testErrorSheetsKeepTheirOrderAcrossDismissals() async throws {
        let model = AppModel.shared
        model.dismissAllErrors()
        defer { model.dismissAllErrors() }
        let saved = model.settings
        let heldUDP = try XCTUnwrap(TestSockets.holdIPv4(SOCK_DGRAM)), heldTrap = try XCTUnwrap(TestSockets.holdIPv4(SOCK_DGRAM))
        defer { close(heldUDP.fd); close(heldTrap.fd); model.stopAll(); model.settings = saved; model.dismissAllErrors() }
        model.settings.syslogUDPPort = heldUDP.port
        model.settings.syslogTCPPort = 0
        model.settings.trapPort = heldTrap.port
        model.settings.captureInterface = "sheep9"
        // What startup does with both auto-starts on, then a capture that cannot start.
        model.startSyslog()
        model.startTraps()
        model.capture.start(interface: "sheep9", promiscuous: false, bpfFilter: "")
        if let e = model.capture.lastError { model.report(e) }
        var seen: [String] = []
        let expectedCount = 4
        for step in 0..<expectedCount {
            let current = try XCTUnwrap(model.lastError, "step \(step): no sheet; seen \(seen)")
            seen.append(current)
            model.clearError()
            if step == 0 {
                // An error arrives while the next sheet is on its way (the 0.35 s gap).
                model.report("A fourth problem")
            }
            try await Task.sleep(for: .seconds(AppModel.nextErrorDelay + 0.15))
        }
        XCTAssertNil(model.lastError)
        XCTAssertEqual(seen.count, expectedCount)
        XCTAssertTrue(seen[0].contains("\(heldUDP.port)"), seen[0])
        XCTAssertTrue(seen[1].contains("\(heldTrap.port)"), seen[1])
        XCTAssertTrue(seen[2].contains("sheep9"), seen[2])
        XCTAssertEqual(seen[3], "A fourth problem")
    }

    /// ⌘Q (`shutdownForQuit`) with the listeners running, lines and traps in flight, disk
    /// logging on, and a large capture file loading — in both orders a user can reach: a live
    /// capture replaced by Open (the capture stops), and a file loading replaced by Start.
    func testQuitWithEverythingRunning() async throws {
        let model = AppModel.shared
        let logs = model.logs
        let saved = model.settings
        let tmp = FileManager.default.temporaryDirectory.appending(path: "SheepLogR9Quit-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer {
            model.stopAll()
            model.settings = saved
            model.dismissAllErrors()
            model.packets.clear()
            try? FileManager.default.removeItem(at: tmp)
        }
        model.dismissAllErrors()
        logs.paused = false
        // A 300,000-packet file (several seconds to read in Debug).
        let big = tmp.appending(path: "big.pcap")
        let one = TCPFlowDemo.packet(id: 1, t: 0, src: "10.0.0.1", sport: 40_000, dst: "10.0.0.2", dport: 443,
                                     flags: [.ack], seq: 1, ack: 1, len: 100)
        let many = (0..<300_000).map { i in
            Packet(id: i + 1, timestamp: one.timestamp.addingTimeInterval(Double(i) * 0.0001), relative: Double(i) * 0.0001,
                   length: one.length, captured: one.captured, data: one.data, decoded: one.decoded)
        }
        try PcapFile.write(many, linkType: 1, to: big)
        let canCapture = FileManager.default.isReadableFile(atPath: "/dev/bpf0")

        for order in ["capture then open", "open then capture"] {
            let udp = TestSockets.freePort(SOCK_DGRAM), trap = TestSockets.freePort(SOCK_DGRAM)
            let dir = tmp.appending(path: order.replacingOccurrences(of: " ", with: "-"), directoryHint: .isDirectory)
            model.settings.syslogUDPPort = udp
            model.settings.syslogTCPPort = 0
            model.settings.trapPort = trap
            model.settings.logDirectory = dir.path
            model.settings.diskLogging = true
            model.settings.captureInterface = "lo0"
            model.settings.captureFilter = ""
            model.startSyslog()
            model.startTraps()
            XCTAssertTrue(model.syslog.isRunning && model.traps.isRunning, order)
            model.packets.clear()
            if order == "capture then open" {
                if canCapture { model.startCapture(); model.dismissAllErrors() }
                try model.packets.load(from: big)
                XCTAssertFalse(model.capture.isRunning, "Open stops the live capture")
            } else {
                try model.packets.load(from: big)
                if canCapture {
                    model.startCapture()               // no file packets yet: no replace question
                    model.dismissAllErrors()
                    XCTAssertFalse(model.packets.isLoading, "Start stops the file load")
                }
            }
            // Lines and traps right up to the quit.
            var markers: [String] = []
            for k in 0..<50 {
                let m = "r9quit-\(order.prefix(4))-\(k)-end"
                TestSockets.sendUDP(["<13>Sep 24 10:00:00 r9 app: \(m)"], to: udp)
                markers.append(m)
            }
            TestSockets.sendUDP(Round5TrapTests.linkDown(4_242), to: trap)
            try await Task.sleep(for: .milliseconds(30))       // read by the listeners, not yet flushed
            let t0 = Monotonic.now()
            model.shutdownForQuit()
            XCTAssertLessThan(Monotonic.now() - t0, 3, "\(order): ⌘Q waited too long")
            XCTAssertFalse(model.syslog.isRunning || model.traps.isRunning || model.capture.isRunning, order)
            let disk = Self.diskLines([dir])
            for m in markers { XCTAssertEqual(disk.filter { $0.hasSuffix(m) }.count, 1, "\(order): \(m) not on disk at quit") }
            XCTAssertEqual(disk.filter { $0.contains("1.3.6.1.2.1.2.2.1.1.4242=4242") }.count, 1, "\(order): the trap")
            // The load (still running in the background) must not bring the stopped capture's
            // table back or crash; the app would exit here.
            try await Task.sleep(for: .milliseconds(200))
            model.packets.clear()
            model.settings.diskLogging = false
        }
    }

    // MARK: - Regressions (one per finding)

    /// Finding 7. Traps whose OIDs no loaded MIB named kept `enterprises.12356…` for good
    /// after the vendor MIB was imported (only traps from the launch-load window were re-named).
    /// They are now re-named in place at every index install, bounded, and paused lines too.
    func testTrapsReceivedBeforeAnImportAreNamedByIt() async throws {
        let store = LogStore()
        let receiver = TrapReceiver(store: store)
        let reg = MIBRegistry()
        let folder = FileManager.default.temporaryDirectory.appending(path: "SheepLogR9Rename-\(UUID().uuidString)", directoryHint: .isDirectory)
        defer { try? FileManager.default.removeItem(at: folder) }
        reg.userFolderOverride = folder
        reg.loadNow(bundled: MIBRegistry.bundledURLs())
        receiver.registry = reg
        func trap(_ n: Int) -> ReceivedTrap {
            .trap(SNMPTrap(received: Date(), sourceAddress: "10.0.0.1", sourcePort: 162, version: .v2c, community: "public",
                           trapOID: OID([1, 3, 6, 1, 4, 1, 12356, 101, 2, 0, 401]), uptime: 1, agentAddress: nil,
                           varBinds: [VarBind(OID([1, 3, 6, 1, 4, 1, 12356, 100, 1, 1, 1, 0]), .octetString(Data("FG\(n)".utf8)))]))
        }
        let linkDown = ReceivedTrap.trap(SNMPTrap(received: Date(), sourceAddress: "10.0.0.2", sourcePort: 162, version: .v2c,
                                                  community: "public", trapOID: OID([1, 3, 6, 1, 6, 3, 1, 1, 5, 3]), uptime: 1,
                                                  agentAddress: nil, varBinds: [VarBind(OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 3]), .integer(3))]))
        receiver.ingest([trap(1), linkDown, trap(2)])
        store.paused = true
        receiver.ingest([trap(3)])                                     // held back from the table
        XCTAssertEqual(store.entries.map(\.program), ["enterprises.12356.101.2.0.401", "linkDown", "enterprises.12356.101.2.0.401"])
        let ids = store.entries.map(\.id)
        reg.importFiles([URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appending(path: "Tests/mibs/fortinet")])
        await waitUntil(20) { !reg.isLoading }
        await store.settle()
        XCTAssertEqual(store.entries.map(\.program), ["fgTrapHaSwitch", "linkDown", "fgTrapHaSwitch"])
        XCTAssertEqual(store.entries.map(\.id), ids, "in place: same ids, same order")
        XCTAssertTrue(store.entries[0].fields.contains { $0.key == "fnSysSerial.0" })
        XCTAssertEqual(store.visible.map(\.program), store.entries.map(\.program))
        store.paused = false
        XCTAssertEqual(store.entries.last?.program, "fgTrapHaSwitch", "the paused one too")
        // Fully named traps are not kept for renaming; the list is bounded.
        XCTAssertTrue(TrapReceiver.fullyNamed({ if case .trap(let t) = linkDown { t } else { fatalError() } }(), registry: reg))
        receiver.ingest((0..<(TrapReceiver.maxUnnamed + 50)).map { n in
            .trap(SNMPTrap(received: Date(), sourceAddress: "10.0.0.3", sourcePort: 162, version: .v2c, community: "c",
                           trapOID: OID([1, 3, 6, 1, 4, 1, 99_999, 0, UInt32(n % 7)]), uptime: 1, agentAddress: nil, varBinds: []))
        })
        let mirror = Mirror(reflecting: receiver).children.first { $0.label == "unnamed" }?.value as? [(id: Int, trap: SNMPTrap)]
        XCTAssertEqual(mirror?.count, TrapReceiver.maxUnnamed)
    }

    /// Finding 5. "Open in SNMP test" on a log line (a bare address) kept the port the form
    /// had: after a test against a lab or agent on 1161, every device opened from the Log was
    /// asked on 1161 and timed out like a wrong community.
    func testOpenInSNMPTestAsksABareAddressOnPort161() {
        let m = SNMPTestModel.shared
        let (host, port) = (m.host, m.port)
        defer { m.host = host; m.port = port }
        m.setTarget("127.0.0.1:1161")
        XCTAssertEqual(m.port, 1161)
        NotificationCenter.default.post(name: .sheepLogSNMPTarget, object: "10.9.0.1")
        XCTAssertEqual(m.host, "10.9.0.1")
        XCTAssertEqual(m.port, 161)
        XCTAssertEqual(m.portText, "161")
        NotificationCenter.default.post(name: .sheepLogSNMPTarget, object: "[2001:db8::7]:1161")
        XCTAssertEqual(m.port, 1161, "a port in the request is kept")
        NotificationCenter.default.post(name: .sheepLogSNMPTarget, object: "fe80::1%en0")
        XCTAssertEqual(m.host, "fe80::1%en0")
        XCTAssertEqual(m.port, 161)
    }

    /// Finding 6. A Get next still in flight overwrote the OID field with its answer even when
    /// another object had been put there meanwhile (MIBs' "Use in SNMP test", or typed).
    func testGetNextDoesNotOverwriteAnObjectChosenMeanwhile() async throws {
        let agent = try FakeAgent(mib: [VarBind(OID.sysDescr, .octetString(Data("fake".utf8))),
                                        VarBind(OID([1, 3, 6, 1, 2, 1, 1, 5, 0]), .octetString(Data("r9".utf8)))])
        let m = SNMPTestModel.shared
        let saved = (m.host, m.port, m.credentials, m.oidText, AppModel.shared.settings)
        defer {
            agent.stop()
            m.host = saved.0; m.port = saved.1; m.applyCredentials(saved.2); m.oidText = saved.3
            AppModel.shared.settings = saved.4
            // After the run's own save (same serial queue), never on the main thread.
            let account = "127.0.0.1:\(agent.port)"
            SNMPTestModel.keychainQueue.async { KeychainStore.delete(account: account) }
        }
        m.setTarget("127.0.0.1:\(agent.port)")
        m.version = .v2c
        m.community = "public"
        func finish() async {
            let end = Date().addingTimeInterval(5)
            while m.isRunning, Date() < end { try? await Task.sleep(for: .milliseconds(5)) }
        }
        m.oidText = "1.3.6.1.2.1.1.1"
        m.getNext()
        NotificationCenter.default.post(name: .sheepLogSNMPOID, object: "1.3.6.1.2.1.1.6")
        await finish()
        XCTAssertEqual(m.rows.first?.oidText, "1.3.6.1.2.1.1.1.0")
        XCTAssertEqual(m.oidText, "1.3.6.1.2.1.1.6")
        m.oidText = "1.3.6.1.2.1.1.1"
        m.getNext()
        await finish()
        XCTAssertEqual(m.oidText, "1.3.6.1.2.1.1.1.0", "without a change, Get next steps the field on")
    }

    /// Finding 3b. With the old logger retired without waiting (finding 3), ⌘Q right after a
    /// folder change must still wait for the backlog the old logger was writing.
    func testQuitRightAfterAFolderChangeKeepsTheOldLoggersBacklog() async throws {
        let model = AppModel.shared
        let saved = model.settings
        let tmp = FileManager.default.temporaryDirectory.appending(path: "SheepLogR9QuitMove-\(UUID().uuidString)", directoryHint: .isDirectory)
        let dirA = tmp.appending(path: "A", directoryHint: .isDirectory)
        defer { model.settings = saved; model.dismissAllErrors(); try? FileManager.default.removeItem(at: tmp) }
        model.settings.logDirectory = dirA.path
        model.settings.diskLogging = true
        let now = Date()
        model.logs.diskSink.append((0..<100_000).map {
            RawSyslog(received: now, sourceAddress: "192.0.2.1", sourcePort: 514, transport: .udp, text: "<13>Sep 24 10:00:00 b app: r9backlog-\($0)-end")
        })
        model.settings.logDirectory = tmp.appending(path: "B").path
        model.shutdownForQuit()
        let lines = Self.diskLines([dirA]).filter { $0.contains("r9backlog-") }
        XCTAssertEqual(lines.count, 100_000, "the old logger's backlog was cut off by ⌘Q")
    }

    /// Finding 4. Apply ports moved the syslog listener before the trap receiver: syslog onto
    /// the trap receiver's old port (traps moving elsewhere in the same Apply) failed as
    /// "SheepLog's own SNMP trap receiver is listening there" and went back, although the port
    /// was free a moment later; swapping the two ports could never be applied at all.
    func testApplyPortsLetsTheListenersTradePorts() async throws {
        let model = AppModel.shared
        let saved = model.settings
        defer { model.stopAll(); model.settings = saved; model.dismissAllErrors() }
        model.dismissAllErrors()
        let a = TestSockets.freePort(SOCK_DGRAM), b = TestSockets.freePort(SOCK_DGRAM), c = TestSockets.freePort(SOCK_DGRAM)
        model.settings.syslogUDPPort = a
        model.settings.syslogTCPPort = 0
        model.settings.trapPort = b
        model.startSyslog()
        model.startTraps()
        XCTAssertTrue(model.syslog.isRunning && model.traps.isRunning)

        // Syslog onto the trap port, traps elsewhere — one Apply.
        model.settings.syslogUDPPort = b
        model.settings.trapPort = c
        model.restartListeners()
        XCTAssertNil(model.lastError, model.lastError ?? "")
        XCTAssertEqual(model.syslog.udpPort, b)
        XCTAssertEqual(model.traps.port, c)
        XCTAssertFalse(model.listenerPortsChanged)
        await sendAndExpect("moved", udp: b, tcp: nil, trap: c)

        // Swap them.
        model.settings.syslogUDPPort = c
        model.settings.trapPort = b
        model.restartListeners()
        XCTAssertNil(model.lastError, model.lastError ?? "")
        XCTAssertEqual(model.syslog.udpPort, c)
        XCTAssertEqual(model.traps.port, b)
        await sendAndExpect("swapped", udp: c, tcp: nil, trap: b)

        // A move that cannot happen still leaves both listening where they were.
        let held = try XCTUnwrap(TestSockets.holdIPv4(SOCK_DGRAM))
        defer { close(held.fd) }
        model.settings.syslogUDPPort = held.port
        model.settings.trapPort = a
        model.restartListeners()
        XCTAssertTrue(model.lastError?.contains("could not move") == true, model.lastError ?? "nil")
        XCTAssertEqual(model.syslog.udpPort, c)
        XCTAssertTrue(model.syslog.isRunning)
        XCTAssertEqual(model.traps.port, a)
        await sendAndExpect("after a failed move", udp: c, tcp: nil, trap: a)
    }

    /// Finding 3. Moving the log folder (or any logger replacement) retired the old logger
    /// before the new one was handed to the listener threads: a batch a listener wrote in that
    /// window — as long as the old logger took to finish its backlog, since `retire` waits for
    /// it — was queued behind the retirement and thrown away. Disk log = every line received.
    func testLinesWrittenWhileTheLogFolderMovesAreKept() async throws {
        let model = AppModel.shared
        let saved = model.settings
        let tmp = FileManager.default.temporaryDirectory.appending(path: "SheepLogR9Move-\(UUID().uuidString)", directoryHint: .isDirectory)
        let dirA = tmp.appending(path: "A", directoryHint: .isDirectory)
        let dirB = tmp.appending(path: "B", directoryHint: .isDirectory)
        defer { model.settings = saved; model.dismissAllErrors(); try? FileManager.default.removeItem(at: tmp) }
        model.settings.logDirectory = dirA.path
        model.settings.diskLogging = true
        let sink = model.logs.diskSink
        // A backlog on the old logger's queue (a burst it is still writing).
        let now = Date()
        let pad = String(repeating: "x", count: 200)
        sink.append((0..<200_000).map { RawSyslog(received: now, sourceAddress: "192.0.2.1", sourcePort: 514, transport: .udp,
                                                    text: "<13>Sep 24 10:00:00 pad app: \($0) \(pad)") })
        let written = LockedBox<[Int]>([])
        let stop = LockedBox(false)
        let listener = Thread {                      // a listener queue's rawSink
            var k = 0
            while !stop.value {
                k += 1
                sink.append([RawSyslog(received: now, sourceAddress: "192.0.2.2", sourcePort: 514, transport: .udp,
                                       text: "<13>Sep 24 10:00:00 r9 app: r9move-\(k)-end")])
                written.mutate { $0.append(k) }
                usleep(200)
            }
        }
        listener.start()
        try await Task.sleep(for: .milliseconds(20))
        let oldLogger = model.logs.diskLogger
        let t0 = Monotonic.now()
        model.settings.logDirectory = dirB.path        // Settings ▸ Choose… while lines arrive
        XCTAssertLessThan(Monotonic.now() - t0, 0.25, "the switch waited for the old logger's backlog on the main thread")
        try await Task.sleep(for: .milliseconds(30))
        stop.mutate { $0 = true }
        try await Task.sleep(for: .milliseconds(20))
        oldLogger?.sync()
        model.logs.diskLogger?.sync()
        let lines = Self.diskLines([dirA, dirB]).filter { $0.contains("r9move-") }
        let found = Set(lines.compactMap { l -> Int? in
            guard let r = l.range(of: "r9move-") else { return nil }
            return Int(l[r.upperBound...].prefix { $0.isNumber })
        })
        let missing = written.value.filter { !found.contains($0) }
        XCTAssertGreaterThan(written.value.count, 10)
        XCTAssertEqual(missing.count, 0, "\(missing.count) of \(written.value.count) lines lost in the folder switch")
    }

    /// Finding 2. A frame with no address (a loopback frame of another family, a truncated
    /// one) offered "Filter this source ()" / "Filter this conversation", and a double-click
    /// applied `ip: ip:` — the text "ip:", which hid every packet including the clicked one.
    func testAddresslessFrameOffersNoAddressFilter() throws {
        let store = AppModel.shared.packets
        defer { store.queryText = ""; store.applyQueryNow(synchronous: true); store.clear() }
        store.clear()
        let odd = Data([99, 0, 0, 0, 1, 2, 3, 4])                  // DLT_NULL, family 99
        let d = PacketDecoder.decode(odd, linkType: 0)
        XCTAssertEqual(d.source, "")
        let now = Date()
        store.ingest([Packet(id: 1, timestamp: now, relative: 0, length: odd.count, captured: odd.count, data: odd, decoded: d),
                      TCPFlowDemo.packet(id: 2, t: 0.1, src: "10.0.0.1", sport: 40_000, dst: "10.0.0.2", dport: 443,
                                         flags: [.syn], seq: 1, ack: 0, len: 0)])
        let controller = PacketTableController()
        controller.liveOverride = false
        let scroll = PacketTableView.makeScrollView(controller: controller)
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1100, height: 400), styleMask: [.titled], backing: .buffered, defer: false)
        w.isReleasedWhenClosed = false
        scroll.frame = NSRect(x: 0, y: 0, width: 1100, height: 400)
        w.contentView = scroll
        w.layoutIfNeeded()
        windows.append(w)
        let tv = scroll.documentView as! PacketNSTableView
        controller.refreshNow()
        XCTAssertEqual(tv.numberOfRows, 2)
        for title in ["Filter this source", "Filter this destination", "Filter this conversation"] {
            let item = try XCTUnwrap(rightClick(tv, row: 0, choose: title))
            XCTAssertFalse(item.isEnabled, title)
            XCTAssertFalse(item.title.contains("()"), item.title)
        }
        // The double-click (conversation filter) leaves the filter alone on such a frame.
        _ = rightClick(tv, row: 0, choose: "Copy")
        controller.doubleClicked(nil)
        XCTAssertEqual(store.queryText, "")
        // A normal frame still gets all three.
        for title in ["Filter this source (10.0.0.1)", "Filter this destination (10.0.0.2)", "Filter this conversation"] {
            XCTAssertTrue(try XCTUnwrap(rightClick(tv, row: 1, choose: title)).isEnabled, title)
        }
    }

    /// Finding 1. "Filter this host" / "Filter this program" / "Exclude this host" (and the
    /// inspector's Filter this host) on a filter that does not parse — an open quote, a trailing
    /// OR still being typed — appended the term to the broken text: the click only changed the
    /// error ("Unexpected )" for `(deny OR) host:x`) and the table kept the old rows. The term
    /// now narrows the filter the table shows (the last one that worked).
    func testContextMenuTermOnAnUnfinishedFilterNarrowsTheFilterInForce() async {
        let store = LogStore()
        store.ingest([parsedLine("<11>Sep 23 10:00:00 sw1 app: deny all", from: "10.1.0.1", id: LogStore.nextID()),
                      parsedLine("<11>Sep 23 10:00:00 sw2 app: deny some", from: "10.1.0.2", id: LogStore.nextID()),
                      parsedLine("<11>Sep 23 10:00:00 sw2 app: allow", from: "10.1.0.2", id: LogStore.nextID())])
        store.queryText = "deny"
        store.applyQueryText()
        await store.settle()
        for broken in ["deny OR", "deny \"half", "deny (", "deny sev:<="] {
            store.queryText = broken
            store.applyQueryText()
            XCTAssertNotNil(store.queryError, broken)
            store.appendToQuery("host:10.1.0.2")
            await store.settle()
            XCTAssertEqual(store.queryText, "deny host:10.1.0.2", broken)
            XCTAssertNil(store.queryError, broken)
            XCTAssertEqual(store.visible.map(\.message), ["deny some"], broken)
            store.queryText = "deny"
            store.applyQueryText()
            await store.settle()
        }
        // In regex mode a text whose bare word is not a regex does not parse either.
        store.regexMode = true
        store.queryText = "deny [x"
        store.applyQueryText()
        XCTAssertNotNil(store.queryError)
        store.appendToQuery("host:10.1.0.2")
        await store.settle()
        XCTAssertEqual(store.queryText, "deny host:10.1.0.2")
        XCTAssertEqual(store.visible.map(\.message), ["deny some"])
        store.regexMode = false
        // A good text not yet applied (the 200 ms debounce) is still the base.
        store.queryText = "sev:err OR allow"
        store.appendToQuery("host:10.1.0.2")
        XCTAssertEqual(store.queryText, "(sev:err OR allow) host:10.1.0.2")
    }
}
