import AppKit
import Combine
import SwiftUI

/// The log grid: a view-based `NSTableView` reading `LogStore.visibleEntry(atRow:)`. Cells are
/// reused through `makeView(withIdentifier:)` and formatted only for the rows on screen, so
/// 100k rows at ten batches a second stay cheap. Appends keep the scroll position anchored
/// (pinned to the newest line when the view is already there).
struct LogTableView: NSViewRepresentable {
    @ObservedObject var store: LogStore
    @Binding var selectedID: Int?
    var onDoubleClick: (LogEntry) -> Void = { _ in }

    func makeCoordinator() -> Coordinator { Coordinator(store: store) }

    func makeNSView(context: Context) -> NSScrollView {
        context.coordinator.parent = self
        return Self.makeScrollView(coordinator: context.coordinator)
    }

    /// The scroll view and table for `c` (whose `parent` is set) — tests build it the same way.
    static func makeScrollView(coordinator c: Coordinator) -> NSScrollView {
        let table = LogNSTableView()
        table.style = .plain
        table.usesAlternatingRowBackgroundColors = false
        table.rowHeight = 22
        table.intercellSpacing = NSSize(width: 8, height: 0)
        table.gridStyleMask = []
        table.allowsMultipleSelection = true
        table.allowsColumnReordering = false
        table.columnAutoresizingStyle = .lastColumnOnlyAutoresizingStyle
        table.backgroundColor = Theme.nsDynamic(light: 0xFFFFFF, dark: 0x2A2A2E)
        table.focusRingType = .none

        for spec in LogColumn.all {
            let col = NSTableColumn(identifier: spec.id)
            col.title = spec.title
            col.width = spec.width
            col.minWidth = spec.minWidth
            col.maxWidth = spec.id == LogColumn.message ? 100_000 : 600
            col.resizingMask = spec.id == LogColumn.message ? [.autoresizingMask, .userResizingMask] : .userResizingMask
            col.headerCell.font = NSFont.systemFont(ofSize: 11, weight: .medium)
            table.addTableColumn(col)
        }

        c.table = table
        table.dataSource = c
        table.delegate = c
        table.target = c
        table.doubleAction = #selector(Coordinator.doubleClicked(_:))
        table.copyHandler = { [weak c] in c?.copy(\.raw, rows: nil) }
        let menu = NSMenu()
        menu.delegate = c
        table.menu = menu
        // Right-click the header: choose the columns (Message always stays). Remembered.
        let header = NSMenu()
        header.identifier = NSUserInterfaceItemIdentifier("header")
        header.delegate = c
        table.headerView?.menu = header
        LogColumn.restoreHidden(table)

        let scroll = NSScrollView()
        scroll.documentView = table
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.autohidesScrollers = true
        scroll.drawsBackground = true
        scroll.backgroundColor = table.backgroundColor
        scroll.borderType = .noBorder
        c.scroll = scroll
        c.sync(force: true)
        return scroll
    }

    /// Take whatever space is offered without asking Auto Layout (measuring the scroll view
    /// through constraints on every store update is a main-thread hot spot).
    func sizeThatFits(_ proposal: ProposedViewSize, nsView: NSScrollView, context: Context) -> CGSize? {
        proposal.replacingUnspecifiedDimensions(by: CGSize(width: 600, height: 400))
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        context.coordinator.parent = self
        context.coordinator.sync(force: false)
    }

    // MARK: - Coordinator

    @MainActor
    final class Coordinator: NSObject, NSTableViewDataSource, NSTableViewDelegate, NSMenuDelegate {
        var parent: LogTableView?
        let store: LogStore
        weak var table: LogNSTableView?
        weak var scroll: NSScrollView?

        private var lastGeneration = -1
        private var lastAppended = 0
        private var lastEvicted = 0
        private var lastCount = 0
        private var lastNewestFirst = true
        /// Sequence numbers of the selected lines (stable across appends / evictions).
        private var selectedSeqs: [Int] = []
        private var lastSelectedID: Int?
        private var applyingSelection = false
        private var lastShift: CFTimeInterval = 0
        private var shiftScheduled = false
        private static let minShiftInterval: CFTimeInterval = 0.1

        private let mono = NSFont.monospacedSystemFont(ofSize: 11.5, weight: .regular)
        // Time in tabular SF digits and Vendor in SF text: "HH:mm:ss.SSS" and "ClearPass" fit the
        // 84 / 68 pt columns (SF Mono cuts them to "05:45:30.…" / "ClearPa…").
        private let digits = NSFont.monospacedDigitSystemFont(ofSize: 11.5, weight: .regular)
        private let prose = NSFont.systemFont(ofSize: 11.5, weight: .medium)

        init(store: LogStore) {
            self.store = store
            super.init()
            LeakProbe.add("LogTable.Coordinator")
            // Time cells made in the old zone are redrawn in the new one (selector observers
            // go away with the coordinator).
            NotificationCenter.default.addObserver(self, selector: #selector(timeZoneChanged(_:)),
                                                   name: .NSSystemTimeZoneDidChange, object: nil)
        }

        @objc func timeZoneChanged(_ note: Notification) {
            NSTimeZone.resetSystemTimeZone()
            guard let table else { return }
            let rows = table.selectedRowIndexes
            applyingSelection = true
            table.reloadData()
            table.selectRowIndexes(rows, byExtendingSelection: false)
            applyingSelection = false
        }

        deinit { LeakProbe.remove("LogTable.Coordinator") }

        // MARK: Sync with the store

        func sync(force: Bool) {
            guard let table, let scroll else { return }
            let count = store.visibleCount
            let newest = store.newestFirst

            if force || store.generation != lastGeneration || newest != lastNewestFirst {
                reload(table, count: count, newest: newest)
                return
            }

            let added = store.visibleAppended - lastAppended
            let removed = store.visibleEvicted - lastEvicted
            if added != 0 || removed != 0 || count != lastCount {
                guard shiftIsDue() else { return }
                shiftRows(table, scroll, added: added, removed: removed, count: count, newest: newest)
            }

            // Selection driven from outside (the binding changed).
            if let id = parent?.selectedID, id != lastSelectedID, let row = store.visibleRow(forID: id) {
                select(rows: IndexSet(integer: row))
                table.scrollRowToVisible(row)
            }
            lastSelectedID = parent?.selectedID
        }

        /// A new generation (re-scan, clear, order toggle): reload, and find the selection again
        /// by id (a re-scan invalidates rows and sequence numbers).
        private func reload(_ table: LogNSTableView, count: Int, newest: Bool) {
            table.reloadData()
            lastGeneration = store.generation
            lastNewestFirst = newest
            lastAppended = store.visibleAppended
            lastEvicted = store.visibleEvicted
            lastCount = count
            if let id = parent?.selectedID, let row = store.visibleRow(forID: id) {
                select(rows: IndexSet(integer: row))
                table.scrollRowToVisible(row)
                // Handled: the next append must not take it for a new outside selection and
                // scroll back to it (after the user scrolled away).
                lastSelectedID = id
            } else {
                select(rows: IndexSet())
                if count > 0 { table.scrollRowToVisible(newest ? 0 : count - 1) }
                // Filtered out keeps the inspector on the line; gone from the ring clears it.
                if let id = parent?.selectedID, store.entry(id: id) == nil {
                    lastSelectedID = nil
                    DispatchQueue.main.async { [weak self] in
                        if self?.parent?.selectedID == id { self?.parent?.selectedID = nil }
                    }
                }
            }
        }

        /// At most ten row shifts a second: each endUpdates re-creates the visible row views, so
        /// during a flood (a publish per 5,000-line batch) the table, not the parser, would be
        /// the main thread's cost. The deltas accumulate meanwhile; false = a sync is scheduled.
        private func shiftIsDue() -> Bool {
            let now = CACurrentMediaTime()
            let wait = Self.minShiftInterval - (now - lastShift)
            guard wait > 0 else {
                lastShift = now
                return true
            }
            if !shiftScheduled {
                shiftScheduled = true
                DispatchQueue.main.asyncAfter(deadline: .now() + wait) { [weak self] in
                    guard let self else { return }
                    self.shiftScheduled = false
                    self.sync(force: false)
                }
            }
            return false
        }

        /// Appended and evicted rows, keeping the scroll position anchored (or pinned to the
        /// newest line when the view is there).
        private func shiftRows(_ table: LogNSTableView, _ scroll: NSScrollView, added: Int, removed: Int, count: Int,
                               newest: Bool) {
            let clip = scroll.contentView
            let rowH = table.rowHeight + table.intercellSpacing.height
            let y = clip.bounds.origin.y
            let viewportBottom = y + clip.bounds.height
            let wasAtEnd = newest ? y <= rowH * 0.5
                                  : viewportBottom >= CGFloat(lastCount) * rowH - rowH * 1.5
            // Shift rows in place (existing row views and the selection move with them);
            // fall back to a reload when the deltas do not add up — including when the
            // table's own row count is not the one the deltas start from (insert/remove on
            // a mismatched count is an AppKit inconsistency exception).
            if added >= 0, removed >= 0, removed <= lastCount, lastCount - removed + added == count,
               added + removed < 50_000, table.numberOfRows == lastCount {
                table.beginUpdates()
                if newest {
                    if removed > 0 { table.removeRows(at: IndexSet((lastCount - removed)..<lastCount), withAnimation: []) }
                    if added > 0 { table.insertRows(at: IndexSet(0..<added), withAnimation: []) }
                } else {
                    if removed > 0 { table.removeRows(at: IndexSet(0..<removed), withAnimation: []) }
                    if added > 0 { table.insertRows(at: IndexSet((count - added)..<count), withAnimation: []) }
                }
                table.endUpdates()
            } else {
                table.reloadData()
            }
            if newest {
                if !wasAtEnd, added > 0 {
                    clip.scroll(to: NSPoint(x: clip.bounds.origin.x, y: y + CGFloat(added) * rowH))
                    scroll.reflectScrolledClipView(clip)
                }
            } else if wasAtEnd, count > 0 {
                table.scrollRowToVisible(count - 1)
            } else if removed > 0 {
                clip.scroll(to: NSPoint(x: clip.bounds.origin.x, y: max(0, y - CGFloat(removed) * rowH)))
                scroll.reflectScrolledClipView(clip)
            }
            lastAppended = store.visibleAppended
            lastEvicted = store.visibleEvicted
            lastCount = count
            restoreSelectionBySeq()
        }

        private func restoreSelectionBySeq() {
            guard let table, !selectedSeqs.isEmpty else { return }
            // Every selected line left the ring: clear the binding too, so the inspector does
            // not keep showing (and re-searching the ring for) a line that is gone.
            let allEvicted = selectedSeqs.allSatisfy { store.isEvicted(seq: $0) }
            var rows = IndexSet()
            for s in selectedSeqs { if let r = store.visibleRow(forSeq: s) { rows.insert(r) } }
            if rows != table.selectedRowIndexes { select(rows: rows) }
            if allEvicted, parent?.selectedID != nil {
                lastSelectedID = nil
                // Not during SwiftUI's view update.
                DispatchQueue.main.async { [weak self] in
                    guard let self, let table = self.table, table.selectedRowIndexes.isEmpty else { return }
                    self.parent?.selectedID = nil
                }
            }
        }

        private func select(rows: IndexSet) {
            guard let table else { return }
            applyingSelection = true
            table.selectRowIndexes(rows, byExtendingSelection: false)
            applyingSelection = false
            recordSelection()
        }

        private func recordSelection() {
            guard let table else { return }
            let rows = table.selectedRowIndexes
            selectedSeqs = rows.count <= 10_000 ? rows.compactMap { store.visibleSeq(atRow: $0) } : []
        }

        // MARK: Data source / delegate

        func numberOfRows(in tableView: NSTableView) -> Int { store.visibleCount }

        func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
            // The table may still hold a row count from before the last publish.
            guard let column = tableColumn, let e = store.visibleEntryIfPresent(atRow: row) else { return nil }
            let id = column.identifier
            if id == LogColumn.severity {
                let pill = (tableView.makeView(withIdentifier: id, owner: nil) as? SeverityPillCell) ?? {
                    let v = SeverityPillCell()
                    v.identifier = id
                    return v
                }()
                pill.severity = e.severity
                return pill
            }
            let cell = (tableView.makeView(withIdentifier: id, owner: nil) as? LogTextCell) ?? {
                let v = LogTextCell(font: id == LogColumn.time || id == LogColumn.deviceTime ? digits
                                          : id == LogColumn.vendor ? prose : mono)
                v.identifier = id
                return v
            }()
            let field = cell.label
            switch id {
            case LogColumn.time:
                field.stringValue = Format.clock.string(from: e.received)
                field.textColor = Self.timeColor
                field.toolTip = nil
            case LogColumn.deviceTime:
                // Same day as received: clock only; another day (a wrong device clock, a late
                // relay): the date too, so the difference is visible.
                if let t = e.deviceTime {
                    let sameDay = Calendar.gregorian.isDate(t, inSameDayAs: e.received)
                    field.stringValue = sameDay ? Format.clock.string(from: t) : Format.dayClock.string(from: t)
                    field.toolTip = Format.stamp.string(from: t)
                } else {
                    field.stringValue = "—"
                    field.toolTip = "The line carried no timestamp"
                }
                field.textColor = Self.timeColor
            case LogColumn.host:
                field.stringValue = e.displayHost
                field.textColor = Self.textColor
            case LogColumn.vendor:
                field.stringValue = e.vendor.shortLabel
                field.textColor = Self.vendorColors[e.vendor]
            case LogColumn.program:
                field.stringValue = e.program
                field.textColor = Self.textColor
            default:
                field.stringValue = Self.oneLine(e.message)
                field.textColor = .labelColor
            }
            return cell
        }

        // One dynamic colour each, not a new NSColor per cell per row.
        private static let timeColor = Theme.nsDynamic(light: 0x86868B, dark: 0x8E8E93)
        private static let textColor = Theme.nsDynamic(light: 0x3A3A3C, dark: 0xD1D1D6)
        private static let vendorColors: [Vendor: NSColor] =
            Dictionary(uniqueKeysWithValues: Vendor.allCases.map { ($0, LogColors.nsVendorColor($0)) })

        /// The message as the single-line cell shows it: tabs and line breaks as spaces, and at
        /// most `displayLimit` bytes (laying out a 64 KB datagram in a truncating label on every
        /// scroll is the cost; the inspector shows the whole line).
        nonisolated static let displayLimit = 2_048

        nonisolated static func oneLine(_ m: String) -> String {
            let u = m.utf8
            let long = u.count > displayLimit
            let control = u.contains { $0 == 0x0A || $0 == 0x0D || $0 == 0x09 }
            guard long || control else { return m }
            var bytes = Array(long ? u.prefix(displayLimit) : u[...])
            if control {
                for i in bytes.indices where bytes[i] == 0x0A || bytes[i] == 0x0D || bytes[i] == 0x09 { bytes[i] = 0x20 }
            }
            var s = String(decoding: bytes, as: UTF8.self)
            if long {
                // A cut inside a multi-byte character decodes as a trailing U+FFFD.
                if s.unicodeScalars.last == "\u{FFFD}" { s.unicodeScalars.removeLast() }
                s += "…"
            }
            return s
        }

        func tableViewSelectionDidChange(_ notification: Notification) {
            guard !applyingSelection, let table else { return }
            recordSelection()
            let row = table.selectedRow
            let id: Int? = store.visibleEntryIfPresent(atRow: row)?.id
            lastSelectedID = id
            if parent?.selectedID != id { parent?.selectedID = id }
        }

        @objc func doubleClicked(_ sender: Any?) {
            guard let table else { return }
            let row = table.clickedRow
            guard let e = store.visibleEntryIfPresent(atRow: row) else { return }
            parent?.onDoubleClick(e)
        }

        // MARK: Copy and the context menu

        /// The rows an action applies to: the selection when the clicked row is part of it,
        /// otherwise the clicked row.
        private func targetRows() -> IndexSet {
            guard let table else { return IndexSet() }
            let clicked = table.clickedRow
            if clicked >= 0, !table.selectedRowIndexes.contains(clicked) { return IndexSet(integer: clicked) }
            return table.selectedRowIndexes
        }

        func copy(_ key: KeyPath<LogEntry, String>, rows: IndexSet?) {
            let rows = rows ?? table?.selectedRowIndexes ?? IndexSet()
            guard !rows.isEmpty else { return }
            let text = rows.compactMap { store.visibleEntryIfPresent(atRow: $0)?[keyPath: key] }
                .joined(separator: "\n")
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(text, forType: .string)
        }

        func menuNeedsUpdate(_ menu: NSMenu) {
            menu.removeAllItems()
            guard let table else { return }
            if menu.identifier == NSUserInterfaceItemIdentifier("header") {
                for spec in LogColumn.all where spec.id != LogColumn.message {
                    let i = NSMenuItem(title: spec.title, action: #selector(toggleColumn(_:)), keyEquivalent: "")
                    i.target = self
                    i.representedObject = spec.id.rawValue
                    i.state = table.tableColumn(withIdentifier: spec.id)?.isHidden == false ? .on : .off
                    menu.addItem(i)
                }
                return
            }
            let row = table.clickedRow >= 0 ? table.clickedRow : table.selectedRow
            guard let e = store.visibleEntryIfPresent(atRow: row) else { return }
            func item(_ title: String, _ action: Selector, _ value: String? = nil) {
                let i = NSMenuItem(title: title, action: action, keyEquivalent: "")
                i.target = self
                i.representedObject = value
                menu.addItem(i)
            }
            let many = targetRows().count > 1
            item(many ? "Copy raw lines" : "Copy raw", #selector(copyRaw(_:)))
            item(many ? "Copy messages" : "Copy message", #selector(copyMessage(_:)))
            menu.addItem(.separator())
            item("Filter this host (\(e.sourceAddress))", #selector(filterTerm(_:)), "host:\(e.sourceAddress)")
            if !e.program.isEmpty {
                item("Filter this program (\(e.program))", #selector(filterTerm(_:)), "app:\(Self.quoted(e.program))")
            }
            item("Exclude this host", #selector(filterTerm(_:)), "-host:\(e.sourceAddress)")
        }

        /// Header menu: show or hide one column (Message always stays); the choice is remembered.
        @objc func toggleColumn(_ sender: Any?) {
            guard let raw = (sender as? NSMenuItem)?.representedObject as? String, let table,
                  raw != LogColumn.message.rawValue,
                  let col = table.tableColumn(withIdentifier: NSUserInterfaceItemIdentifier(raw)) else { return }
            col.isHidden.toggle()
            LogColumn.saveHidden(table)
        }

        static func quoted(_ s: String) -> String {
            // The filter grammar has no escape for `"`: a program containing one is matched
            // on the part before it rather than producing an unterminated quote.
            let t = s.split(separator: "\"", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? s
            return t.contains(where: { $0 == " " || $0 == "(" || $0 == ")" }) ? "\"\(t)\"" : t
        }

        @objc func copyRaw(_ sender: Any?) { copy(\.raw, rows: targetRows()) }
        @objc func copyMessage(_ sender: Any?) { copy(\.message, rows: targetRows()) }

        @objc func filterTerm(_ sender: NSMenuItem) {
            guard let term = sender.representedObject as? String else { return }
            store.appendToQuery(term)
        }
    }
}

// MARK: - Columns

@MainActor
enum LogColumn {
    static let time = NSUserInterfaceItemIdentifier("time")
    static let deviceTime = NSUserInterfaceItemIdentifier("deviceTime")
    static let host = NSUserInterfaceItemIdentifier("host")
    static let vendor = NSUserInterfaceItemIdentifier("vendor")
    static let severity = NSUserInterfaceItemIdentifier("sev")
    static let program = NSUserInterfaceItemIdentifier("program")
    static let message = NSUserInterfaceItemIdentifier("message")

    struct Spec { let id: NSUserInterfaceItemIdentifier; let title: String; let width: CGFloat; let minWidth: CGFloat }

    static let all: [Spec] = [
        // Narrow fixed columns so Message is on screen at the 1000 pt minimum window. Message
        // keeps at least 240 pt; below that the table scrolls sideways instead of hiding it.
        Spec(id: time, title: "Received", width: 84, minWidth: 84),
        // The timestamp inside the message — the device's own clock (blank when it sent none).
        Spec(id: deviceTime, title: "Device time", width: 110, minWidth: 84),
        Spec(id: host, title: "Host", width: 110, minWidth: 60),
        Spec(id: vendor, title: "Vendor", width: 68, minWidth: 40),
        Spec(id: severity, title: "Sev", width: 52, minWidth: 44),
        Spec(id: program, title: "Program", width: 90, minWidth: 40),
        Spec(id: message, title: "Message", width: 600, minWidth: 240),
    ]
}

extension LogColumn {
    private static let hiddenKey = "SheepLog.log.hiddenColumns"

    /// Hidden columns are remembered per Mac (not by the tests, whose host is the app itself).
    static func saveHidden(_ table: NSTableView) {
        guard !AppSettings.isRunningTests else { return }
        UserDefaults.standard.set(table.tableColumns.filter(\.isHidden).map(\.identifier.rawValue), forKey: hiddenKey)
    }

    static func restoreHidden(_ table: NSTableView) {
        guard !AppSettings.isRunningTests, let hidden = UserDefaults.standard.stringArray(forKey: hiddenKey) else { return }
        for c in table.tableColumns where c.identifier != message { c.isHidden = hidden.contains(c.identifier.rawValue) }
    }
}

/// Mirrors `Theme.vendorColor` / `Theme.severityTint` as `NSColor` for the AppKit cells.
enum LogColors {
    static func nsVendorColor(_ v: Vendor) -> NSColor {
        switch v {
        case .arubaCX, .arubaOS, .arubaSwitch, .clearPass: return dynamic(0xE0562A, 0xF07A52)
        case .huawei: return dynamic(0xCF0A2C, 0xF04A64)
        case .checkPoint: return dynamic(0xE8318A, 0xF56AAE)
        case .paloAlto: return dynamic(0xFA582D, 0xFF8A5C)
        case .fortigate: return dynamic(0xC4232B, 0xF05A62)
        case .snmpTrap: return dynamic(0x5B7BD5, 0x8FA8F0)
        case .unknown: return dynamic(0x8E8E93, 0x8E8E93)
        }
    }

    /// Error tint for emerg…err, warning tint for warning, nil for the rest (as `Theme.severityTint`).
    /// One instance each, not a new dynamic colour per pill per draw.
    static func nsSeverityTint(_ s: Severity) -> NSColor? {
        switch s {
        case .emergency, .alert, .critical, .error: return errTint
        case .warning: return warnTint
        default: return nil
        }
    }

    private static let errTint = dynamic(0xB8451F, 0xFF8A5C)
    private static let warnTint = dynamic(0xA85B00, 0xF0A030)
    static let pillText = dynamic(0x6E6E73, 0xAEAEB2)

    private static func dynamic(_ light: UInt32, _ dark: UInt32) -> NSColor { Theme.nsDynamic(light: light, dark: dark) }
}

// MARK: - Cells

/// ⌘C copies the selected rows' raw text.
final class LogNSTableView: NSTableView {
    var copyHandler: (() -> Void)?

    @objc func copy(_ sender: Any?) { copyHandler?() }

    override func validateUserInterfaceItem(_ item: any NSValidatedUserInterfaceItem) -> Bool {
        if item.action == #selector(copy(_:)) { return selectedRowIndexes.count > 0 }
        return super.validateUserInterfaceItem(item)
    }
}

/// A single-line label laid out by frame (no constraints: rows are re-laid out constantly).
final class LogTextCell: NSTableCellView {
    let label: NSTextField
    private let lineHeight: CGFloat

    init(font: NSFont) {
        label = NSTextField(labelWithString: "")
        lineHeight = ceil(font.ascender - font.descender + font.leading) + 1
        super.init(frame: .zero)
        label.font = font
        label.lineBreakMode = .byTruncatingTail
        label.cell?.usesSingleLineMode = true
        label.cell?.truncatesLastVisibleLine = true
        label.maximumNumberOfLines = 1
        label.translatesAutoresizingMaskIntoConstraints = true
        addSubview(label)
        textField = label
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError() }

    override func layout() {
        super.layout()
        label.frame = NSRect(x: 2, y: floor((bounds.height - lineHeight) / 2),
                             width: max(0, bounds.width - 4), height: lineHeight)
    }
}

/// A small rounded pill: tinted for problems, neutral for the rest.
final class SeverityPillCell: NSView {
    var severity: Severity = .info { didSet { if severity != oldValue { needsDisplay = true } } }

    private static let font = NSFont.systemFont(ofSize: 10, weight: .semibold)

    override var isFlipped: Bool { true }

    // VoiceOver: a drawn pill has no text of its own — read the full name ("warning", not "WARN").
    override func isAccessibilityElement() -> Bool { true }
    override func accessibilityRole() -> NSAccessibility.Role? { .staticText }
    override func accessibilityLabel() -> String? { severity.name }

    override func draw(_ dirtyRect: NSRect) {
        let text = severity.label as NSString
        let tint = LogColors.nsSeverityTint(severity)
        let fg = tint ?? LogColors.pillText
        let attrs: [NSAttributedString.Key: Any] = [.font: Self.font, .foregroundColor: fg]
        let size = text.size(withAttributes: attrs)
        let w = ceil(size.width) + 12
        let h: CGFloat = 16
        let rect = NSRect(x: 1, y: (bounds.height - h) / 2, width: min(w, bounds.width - 2), height: h)
        let bg: NSColor
        if let tint {
            bg = tint.withAlphaComponent(0.14)
        } else {
            let isDark = effectiveAppearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            bg = isDark ? NSColor.white.withAlphaComponent(0.12) : NSColor.black.withAlphaComponent(0.055)
        }
        bg.setFill()
        NSBezierPath(roundedRect: rect, xRadius: h / 2, yRadius: h / 2).fill()
        text.draw(at: NSPoint(x: rect.minX + (rect.width - size.width) / 2, y: rect.minY + (h - size.height) / 2),
                  withAttributes: attrs)
    }
}
