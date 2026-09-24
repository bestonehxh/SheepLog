import AppKit
import SwiftUI
import XCTest
@testable import SheepLog

/// Round 5: the two big AppKit tables driven at the NSTableView level — the Log grid
/// (`LogTableView.Coordinator` over a `LogStore`) and the Packets table
/// (`PacketTableController` over `AppModel.shared.packets`), each hosted in an off-screen window
/// with 10,000 rows: data source and every column's cell, selection, ⌘C and the context menus
/// (through their selectors), scrolling, reloads while the ring evicts, selection restored by
/// id, "Jump to latest", and the cost of a screenful of cells.
@MainActor
final class Round5TableTests: XCTestCase {
    private var windows: [NSWindow] = []
    private var savedPasteboard: String?

    override func setUp() async throws {
        savedPasteboard = NSPasteboard.general.string(forType: .string)
    }

    override func tearDown() async throws {
        for w in windows { w.close() }
        windows = []
        AppModel.shared.packets.clear()
        AppModel.shared.packets.limit = 200_000
        if let s = savedPasteboard {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(s, forType: .string)
        }
    }

    private func host(_ view: NSView, size: NSSize = NSSize(width: 900, height: 440)) -> NSWindow {
        let w = NSWindow(contentRect: NSRect(origin: .zero, size: size), styleMask: [.titled], backing: .buffered, defer: false)
        w.isReleasedWhenClosed = false
        view.frame = NSRect(origin: .zero, size: size)
        w.contentView = view
        w.layoutIfNeeded()
        windows.append(w)
        return w
    }

    private func spin(_ seconds: Double) {
        RunLoop.main.run(until: Date().addingTimeInterval(seconds))
    }

    private var pasteboard: String { NSPasteboard.general.string(forType: .string) ?? "" }

    // MARK: - Log grid

    private static func line(_ n: Int, host: String = "10.1.0.2", program: String = "app") -> LogEntry {
        SyslogParser.parse(RawSyslog(received: Date(timeIntervalSince1970: 1_750_000_000 + Double(n)), sourceAddress: host,
                                     sourcePort: 514, transport: .udp,
                                     text: "<\(n % 8 + 8)>Sep 23 10:15:32 h\(n % 5) \(program)[\(n)]: message \(n)"),
                           id: LogStore.nextID(), vendorOverride: nil)
    }

    private final class SelectionBox { var id: Int? }

    private func logTable(_ store: LogStore) -> (LogTableView.Coordinator, LogNSTableView, NSScrollView, SelectionBox) {
        let box = SelectionBox()
        let binding = Binding<Int?>(get: { box.id }, set: { box.id = $0 })
        let c = LogTableView.Coordinator(store: store)
        c.parent = LogTableView(store: store, selectedID: binding)
        let scroll = LogTableView.makeScrollView(coordinator: c)
        _ = host(scroll)
        let table = scroll.documentView as! LogNSTableView
        return (c, table, scroll, box)
    }

    private func text(_ table: NSTableView, _ column: NSUserInterfaceItemIdentifier, _ row: Int) -> String? {
        let col = table.tableColumns.first { $0.identifier == column }
        let v = table.delegate?.tableView?(table, viewFor: col, row: row)
        return (v as? NSTableCellView)?.textField?.stringValue
    }

    func testLogGridTenThousandRowsEveryColumn() throws {
        let store = LogStore()
        store.ingest((0..<10_000).map { Self.line($0) })
        let (c, table, _, _) = logTable(store)
        XCTAssertEqual(c.numberOfRows(in: table), 10_000)
        XCTAssertEqual(table.numberOfRows, 10_000)
        XCTAssertEqual(table.rowHeight, 22)
        for row in [0, 1, 4_999, 9_999] {
            let e = store.visibleEntry(atRow: row)
            XCTAssertEqual(text(table, LogColumn.time, row), Format.clock.string(from: e.received))
            XCTAssertEqual(text(table, LogColumn.host, row), e.displayHost)
            XCTAssertEqual(text(table, LogColumn.vendor, row), e.vendor.shortLabel)
            XCTAssertEqual(text(table, LogColumn.program, row), e.program)
            XCTAssertEqual(text(table, LogColumn.message, row), e.message)
            let sev = table.tableColumns.first { $0.identifier == LogColumn.severity }
            let pill = try XCTUnwrap(c.tableView(table, viewFor: sev, row: row) as? SeverityPillCell)
            XCTAssertEqual(pill.severity, e.severity)
            XCTAssertEqual(pill.accessibilityLabel(), e.severity.name)
        }
        XCTAssertEqual(store.visibleEntry(atRow: 0).message, "message 9999", "newest first")
        // A row the table still believes in after the store shrank: no cell, no crash.
        XCTAssertNil(c.tableView(table, viewFor: table.tableColumns[0], row: 10_000))
        XCTAssertNil(c.tableView(table, viewFor: table.tableColumns[0], row: -1))
    }

    /// ⌘C (the Edit menu's copy: through the responder chain) and the context menu's items,
    /// through their selectors, on a selection.
    func testLogGridCopyAndContextMenu() throws {
        let store = LogStore()
        store.ingest((0..<100).map { Self.line($0) })
        let (c, table, _, box) = logTable(store)
        XCTAssertFalse(table.validateUserInterfaceItem(NSMenuItem(title: "Copy", action: #selector(LogNSTableView.copy(_:)), keyEquivalent: "c")))
        table.selectRowIndexes(IndexSet([2, 3, 4]), byExtendingSelection: false)
        XCTAssertEqual(box.id, store.visibleEntry(atRow: 4).id, "the inspector shows the last row selected (AppKit's selectedRow)")
        XCTAssertTrue(table.validateUserInterfaceItem(NSMenuItem(title: "Copy", action: #selector(LogNSTableView.copy(_:)), keyEquivalent: "c")))
        XCTAssertTrue(NSApp.sendAction(#selector(LogNSTableView.copy(_:)), to: table, from: nil))
        XCTAssertEqual(pasteboard, (2...4).map { store.visibleEntry(atRow: $0).raw }.joined(separator: "\n"))

        let menu = try XCTUnwrap(table.menu)
        c.menuNeedsUpdate(menu)
        XCTAssertEqual(menu.items.filter { !$0.isSeparatorItem }.map(\.title).prefix(2), ["Copy raw lines", "Copy messages"])
        let copyMessages = try XCTUnwrap(menu.items.first { $0.title == "Copy messages" })
        XCTAssertTrue(NSApp.sendAction(try XCTUnwrap(copyMessages.action), to: copyMessages.target, from: copyMessages))
        XCTAssertEqual(pasteboard, (2...4).map { store.visibleEntry(atRow: $0).message }.joined(separator: "\n"))
        let filter = try XCTUnwrap(menu.items.first { $0.title.hasPrefix("Filter this host") })
        XCTAssertTrue(NSApp.sendAction(try XCTUnwrap(filter.action), to: filter.target, from: filter))
        XCTAssertEqual(store.queryText, "host:10.1.0.2")
    }

    /// The selection follows its line by id through a full rescan and a newest-first toggle
    /// (every row index changes), and the line is scrolled into view.
    func testLogGridSelectionRestoredByIDAfterRescanAndOrderToggle() async throws {
        let store = LogStore()
        store.ingest((0..<10_000).map { Self.line($0, program: $0 % 2 == 0 ? "even" : "odd") })
        let (c, table, scroll, box) = logTable(store)
        let target = store.visibleEntry(atRow: 20)
        table.selectRowIndexes(IndexSet(integer: 20), byExtendingSelection: false)
        XCTAssertEqual(box.id, target.id)

        store.newestFirst.toggle()
        c.sync(force: false)
        let row = try XCTUnwrap(store.visibleRow(forID: target.id))
        XCTAssertEqual(row, 9_979)
        XCTAssertEqual(table.selectedRowIndexes, IndexSet(integer: row))
        XCTAssertTrue(table.rows(in: scroll.contentView.bounds).contains(row), "scrolled to the selected line")
        XCTAssertEqual(box.id, target.id)

        store.queryText = "app:\(target.program)"
        store.applyQueryText()
        await store.settle()
        c.sync(force: false)
        let filteredRow = try XCTUnwrap(store.visibleRow(forID: target.id))
        XCTAssertEqual(table.numberOfRows, 5_000)
        XCTAssertEqual(table.selectedRowIndexes, IndexSet(integer: filteredRow))
        XCTAssertTrue(table.rows(in: scroll.contentView.bounds).contains(filteredRow))

        // Filtered out: nothing selected in the table, the inspector keeps the line.
        store.queryText = "app:\(target.program == "even" ? "odd" : "even")"
        store.applyQueryText()
        await store.settle()
        c.sync(force: false)
        XCTAssertTrue(table.selectedRowIndexes.isEmpty)
        spin(0.05)
        XCTAssertEqual(box.id, target.id)

        // An outside selection (Status "Show") and a rescan in the same update: selected once,
        // and not scrolled back to on the next append after the user scrolled away.
        store.queryText = ""
        store.applyQueryText()
        await store.settle()
        let other = store.visibleEntry(atRow: 5_000)
        box.id = other.id
        c.sync(force: false)
        XCTAssertEqual(table.selectedRowIndexes, IndexSet(integer: 5_000))
        scroll.contentView.scroll(to: NSPoint(x: 0, y: 22 * 100))
        scroll.reflectScrolledClipView(scroll.contentView)
        spin(0.15)
        let top = table.row(at: NSPoint(x: 1, y: scroll.contentView.bounds.minY + 1))
        let topID = store.visibleEntry(atRow: top).id
        store.ingest([Self.line(10_001)])
        c.sync(force: false)
        let newTop = table.row(at: NSPoint(x: 1, y: scroll.contentView.bounds.minY + 1))
        XCTAssertEqual(store.visibleEntry(atRow: newTop).id, topID, "the view stayed on the same lines")
    }

    /// The ring evicts while the table shows it: row count always the store's, cells for every
    /// row, the selection kept while its line lives and cleared (binding too) once it is gone.
    func testLogGridReloadDuringEviction() throws {
        let store = LogStore()
        store.limit = 1_000
        store.ingest((0..<1_000).map { Self.line($0) })
        let (c, table, _, box) = logTable(store)
        let selected = store.visibleEntry(atRow: 500)          // the 500th newest
        table.selectRowIndexes(IndexSet(integer: 500), byExtendingSelection: false)
        for round in 0..<6 {
            spin(0.12)                                          // the 10-per-second shift limit
            store.ingest((0..<150).map { Self.line(2_000 + round * 150 + $0) })
            c.sync(force: false)
            XCTAssertEqual(table.numberOfRows, store.visibleCount)
            for row in [0, table.numberOfRows - 1] {
                XCTAssertNotNil(text(table, LogColumn.message, row))
            }
            if store.visibleRow(forID: selected.id) != nil {
                XCTAssertEqual(table.selectedRowIndexes, IndexSet(integer: store.visibleRow(forID: selected.id)!), "round \(round)")
            }
        }
        XCTAssertNil(store.visibleRow(forID: selected.id), "rolled out")
        XCTAssertTrue(table.selectedRowIndexes.isEmpty)
        spin(0.05)
        XCTAssertNil(box.id, "the inspector let go of a line that is gone")
    }

    /// A time-zone change (travel; the zone set by location) redraws the time cells on screen
    /// in the new zone, selection kept.
    func testTimeZoneChangeRedrawsTheTimeCells() throws {
        let saved = NSTimeZone.default
        defer { NSTimeZone.default = saved }
        NSTimeZone.default = TimeZone(identifier: "Asia/Bangkok")!
        let store = LogStore()
        store.ingest((0..<50).map { Self.line($0) })
        let (coordinator, table, _, _) = logTable(store)
        table.selectRowIndexes(IndexSet(integer: 3), byExtendingSelection: false)
        table.layoutSubtreeIfNeeded()
        let col = table.column(withIdentifier: LogColumn.time)
        func shown() -> String? { (table.view(atColumn: col, row: 0, makeIfNecessary: false) as? NSTableCellView)?.textField?.stringValue }
        let before = try XCTUnwrap(shown())

        let pstore = AppModel.shared.packets
        pstore.clear()
        pstore.ingest(packets(50))
        let (controller, tv, _) = packetTable()
        tv.layoutSubtreeIfNeeded()
        let pcol = tv.column(withIdentifier: NSUserInterfaceItemIdentifier("clock"))
        func pshown() -> String? { (tv.view(atColumn: pcol, row: 0, makeIfNecessary: false) as? NSTableCellView)?.textField?.stringValue }
        let pbefore = try XCTUnwrap(pshown())

        NSTimeZone.default = TimeZone(identifier: "America/New_York")!
        NotificationCenter.default.post(name: .NSSystemTimeZoneDidChange, object: nil)
        // The log grid redraws synchronously (a selector observer); the packet table's
        // subscription is delivered on the main queue — under ASan that can take longer than
        // any fixed wait, so wait (bounded) until both tables show the new zone.
        let deadline = Date().addingTimeInterval(10)
        repeat {
            spin(0.02)
            for t in [table, tv] as [NSTableView] {
                t.window?.displayIfNeeded()
                t.layoutSubtreeIfNeeded()
            }
        } while (shown() == before || pshown() == pbefore) && Date() < deadline
        XCTAssertNotEqual(shown(), before)
        XCTAssertEqual(shown(), Format.clock.string(from: store.visibleEntry(atRow: 0).received))
        XCTAssertEqual(table.selectedRowIndexes, IndexSet(integer: 3))
        XCTAssertNotEqual(pshown(), pbefore)
        XCTAssertEqual(pshown(), Format.clock.string(from: pstore.visible[0].timestamp))
        withExtendedLifetime((coordinator, controller)) {}      // the table's data source is weak
    }

    // MARK: - Packets table

    private func packets(_ n: Int, from start: Int = 0) -> [Packet] {
        (0..<n).map { k in
            let i = start + k
            var p = TCPFlowDemo.packet(id: i + 1, t: Double(i) * 0.001, src: "10.0.\(i % 7).1", sport: UInt16(40_000 + i % 1000),
                                       dst: "10.9.0.\(i % 3)", dport: 443, flags: [.ack], seq: UInt32(i), ack: 1, len: i % 100)
            if i % 10 == 0 {
                var d = p.decoded
                d.vlan = 30
                p = Packet(id: p.id, timestamp: p.timestamp, relative: p.relative, length: p.length, captured: p.captured,
                           data: p.data, decoded: d)
            }
            return p
        }
    }

    private func packetTable() -> (PacketTableController, PacketNSTableView, NSScrollView) {
        let controller = PacketTableController()
        let scroll = PacketTableView.makeScrollView(controller: controller)
        _ = host(scroll)
        let tv = scroll.documentView as! PacketNSTableView
        controller.refreshNow()
        return (controller, tv, scroll)
    }

    private func topRow(_ tv: NSTableView, _ scroll: NSScrollView) -> Int {
        tv.row(at: NSPoint(x: 1, y: scroll.contentView.bounds.minY + 1))
    }

    func testPacketTableTenThousandRowsColumnsAndCopy() throws {
        let store = AppModel.shared.packets
        store.clear()
        store.ingest(packets(10_000))
        let (controller, tv, _) = packetTable()
        XCTAssertEqual(tv.numberOfRows, 10_000)
        let ids = PacketTableController.Column.allCases.map(\.rawValue)
        XCTAssertEqual(tv.tableColumns.map(\.identifier.rawValue), ids)
        XCTAssertEqual(ids.prefix(3), ["no", "clock", "time"], "time of day right after the frame number")
        let p = store.visible[1_234]
        func cell(_ col: PacketTableController.Column) -> String? { text(tv, NSUserInterfaceItemIdentifier(col.rawValue), 1_234) }
        XCTAssertEqual(cell(.no), String(p.id))
        XCTAssertEqual(cell(.clock), Format.clock.string(from: p.timestamp))
        XCTAssertEqual(cell(.time), String(format: "%.6f", p.relative))
        XCTAssertEqual(cell(.src), p.decoded.source)
        XCTAssertEqual(cell(.dst), p.decoded.destination)
        XCTAssertEqual(cell(.proto), p.decoded.protocolName)
        XCTAssertEqual(cell(.len), String(p.length))
        XCTAssertEqual(cell(.vlan), "")
        XCTAssertEqual(text(tv, NSUserInterfaceItemIdentifier("vlan"), 1_230), "30")
        XCTAssertEqual(cell(.info), p.decoded.info)

        // ⌘C through keyDown, in the default column order: time of day (the full stamp) second.
        tv.selectRowIndexes(IndexSet([1_234, 1_235]), byExtendingSelection: false)
        XCTAssertEqual(controller.selected?.id, store.visible[1_235].id, "the detail shows the last row selected")
        let key = try XCTUnwrap(NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: .command, timestamp: 0,
                                                 windowNumber: tv.window?.windowNumber ?? 0, context: nil, characters: "c",
                                                 charactersIgnoringModifiers: "c", isARepeat: false, keyCode: 8))
        tv.keyDown(with: key)
        let lines = pasteboard.split(separator: "\n").map(String.init)
        XCTAssertEqual(lines.count, 2)
        let fields = lines[0].split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
        XCTAssertEqual(fields.count, 9)
        XCTAssertEqual(fields[0], String(p.id))
        XCTAssertEqual(fields[1], Format.stamp.string(from: p.timestamp))
        XCTAssertEqual(fields[2], String(format: "%.6f", p.relative))
        XCTAssertEqual(fields[8], p.decoded.info)
        XCTAssertEqual(lines[0], PacketTableController.rowText(p))

        // The header menu hides and shows a column; copies follow what is on screen.
        let header = try XCTUnwrap(tv.headerView?.menu)
        controller.menuNeedsUpdate(header)
        let clockItem = try XCTUnwrap(header.items.first { $0.title == "Time of day" })
        XCTAssertEqual(clockItem.state, .on)
        XCTAssertNil(header.items.first { $0.title == "Info" }, "Info cannot be hidden")
        XCTAssertTrue(NSApp.sendAction(try XCTUnwrap(clockItem.action), to: clockItem.target, from: clockItem))
        XCTAssertTrue(tv.tableColumn(withIdentifier: NSUserInterfaceItemIdentifier("clock"))?.isHidden == true)
        controller.copySelectedRows()
        let hidden = pasteboard.split(separator: "\n")[0].split(separator: "\t", omittingEmptySubsequences: false)
        XCTAssertEqual(hidden.count, 8)
        XCTAssertEqual(String(hidden[1]), String(format: "%.6f", p.relative))
        controller.menuNeedsUpdate(header)
        let again = try XCTUnwrap(header.items.first { $0.title == "Time of day" })
        XCTAssertEqual(again.state, .off)
        XCTAssertTrue(NSApp.sendAction(try XCTUnwrap(again.action), to: again.target, from: again))
        XCTAssertTrue(tv.tableColumn(withIdentifier: NSUserInterfaceItemIdentifier("clock"))?.isHidden == false)
        // A column moved by the user moves in the copy too.
        tv.moveColumn(tv.column(withIdentifier: NSUserInterfaceItemIdentifier("info")), toColumn: 0)
        controller.copySelectedRows()
        XCTAssertTrue(pasteboard.hasPrefix(p.decoded.info + "\t" + String(p.id) + "\t"), pasteboard)

        // Row menu actions through their selectors.
        let rowMenu = try XCTUnwrap(tv.menu)
        tv.selectRowIndexes(IndexSet(integer: 1_234), byExtendingSelection: false)
        // clickedRow is -1 outside a real click: the menu then has nothing to act on.
        controller.menuNeedsUpdate(rowMenu)
        XCTAssertTrue(rowMenu.items.isEmpty)
    }

    /// "Jump to latest": offered only for a live capture scrolled away from the newest packets;
    /// while it is, new packets do not move the view; pressed, it follows the bottom again.
    func testPacketTableJumpToLatest() throws {
        let store = AppModel.shared.packets
        store.clear()
        store.ingest(packets(10_000))
        let (controller, tv, scroll) = packetTable()
        controller.liveOverride = true
        controller.jumpToLatest()
        spin(0.1)
        XCTAssertFalse(controller.showJump)
        XCTAssertTrue(tv.rows(in: scroll.contentView.bounds).contains(9_999), "at the bottom")

        scroll.contentView.scroll(to: NSPoint(x: 0, y: 22 * 100))
        scroll.reflectScrolledClipView(scroll.contentView)
        spin(0.05)
        XCTAssertTrue(controller.showJump)
        let top = topRow(tv, scroll)
        store.ingest(packets(500, from: 10_000))
        controller.refreshNow()
        spin(0.05)
        XCTAssertEqual(tv.numberOfRows, 10_500)
        XCTAssertEqual(topRow(tv, scroll), top, "a live capture does not drag a scrolled-away view along")
        XCTAssertTrue(controller.showJump)

        controller.jumpToLatest()
        spin(0.1)
        XCTAssertFalse(controller.showJump)
        store.ingest(packets(300, from: 10_500))
        controller.refreshNow()
        spin(0.2)
        XCTAssertTrue(tv.rows(in: scroll.contentView.bounds).contains(10_799), "following the newest packets again")

        // Not live: never offered.
        controller.liveOverride = false
        scroll.contentView.scroll(to: .zero)
        scroll.reflectScrolledClipView(scroll.contentView)
        spin(0.05)
        XCTAssertFalse(controller.showJump)

        // Clear, then packets again: the new capture follows the bottom (no stale "scrolled away").
        controller.liveOverride = true
        scroll.contentView.scroll(to: .zero)
        scroll.reflectScrolledClipView(scroll.contentView)
        store.clear()
        controller.refreshNow()
        store.ingest(packets(2_000))
        controller.refreshNow()
        spin(0.2)
        XCTAssertFalse(controller.showJump)
        XCTAssertTrue(tv.rows(in: scroll.contentView.bounds).contains(1_999))
    }

    /// The ring drops its oldest packets while the user reads the middle of the table: the rows
    /// on screen stay on screen (they used to jump by the number evicted), the selection stays
    /// on its packet, and once that packet is gone the detail lets go of it.
    func testPacketTableEvictionKeepsTheViewAndSelection() throws {
        let store = AppModel.shared.packets
        store.clear()
        store.limit = 2_000
        store.ingest(packets(2_000))
        let (controller, tv, scroll) = packetTable()
        tv.scrollRowToVisible(0)
        let y = tv.rect(ofRow: 1_000).minY
        scroll.contentView.scroll(to: NSPoint(x: 0, y: y))
        scroll.reflectScrolledClipView(scroll.contentView)
        let topID = store.visible[topRow(tv, scroll)].id
        tv.selectRowIndexes(IndexSet(integer: 1_005), byExtendingSelection: false)
        let selectedID = try XCTUnwrap(controller.selected?.id)

        store.ingest(packets(300, from: 2_000))                  // 300 over: the oldest go
        controller.refreshNow()
        XCTAssertEqual(store.visible.first?.id, 301, "300 evicted")
        XCTAssertEqual(store.visible[topRow(tv, scroll)].id, topID, "the same packet at the top")
        XCTAssertEqual(tv.selectedRowIndexes, IndexSet(integer: try XCTUnwrap(store.visibleIndex(of: selectedID))))
        XCTAssertEqual(controller.selected?.id, selectedID)

        for round in 0..<8 { store.ingest(packets(300, from: 2_300 + round * 300)); controller.refreshNow() }
        XCTAssertNil(store.visibleIndex(of: selectedID))
        XCTAssertTrue(tv.selectedRowIndexes.isEmpty)
        XCTAssertNil(controller.selected, "a packet that rolled out of the ring is not shown in the detail")
    }

    /// A screenful and more: the cells of 10,000 rows' Time of day column (the per-cell
    /// DateFormatter call) and of every column for 1,000 rows, well inside a frame budget.
    func testCellCost() throws {
        let store = AppModel.shared.packets
        store.clear()
        store.ingest(packets(10_000))
        let (controller, tv, _) = packetTable()
        let clock = tv.tableColumn(withIdentifier: NSUserInterfaceItemIdentifier("clock"))
        _ = controller.tableView(tv, viewFor: clock, row: 0)
        var t0 = Date()
        var chars = 0
        for row in 0..<10_000 { chars += Format.clock.string(from: store.visible[row].timestamp).count }
        let formatting = Date().timeIntervalSince(t0)
        XCTAssertEqual(chars, 120_000)
        XCTAssertWithinBudget(formatting, 0.05, "10k Format.clock calls")
        t0 = Date()
        for row in 0..<1_000 {
            for col in tv.tableColumns { _ = controller.tableView(tv, viewFor: col, row: row) }
        }
        let cells = Date().timeIntervalSince(t0)
        print("[perf] 10k clock strings \(Int(formatting * 1000)) ms, 9k packet cells \(Int(cells * 1000)) ms")
        XCTAssertWithinBudget(cells, 2.0, "9,000 cells (made without reuse outside a real scroll)")
    }
}
