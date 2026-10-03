import SwiftUI
import AppKit

extension View {
    /// The Quiet look for a SwiftUI `Table` (the Log / Packets grids' look): rows from the
    /// page's left edge to the column's right edge, the first column's text 6 pt in (as in the
    /// Log grid), one hairline under every row, no alternating rows, header titles 11 pt muted
    /// over one hairline, and a selected row that is a quiet fill with a 2 pt ink edge on its
    /// left — the cells keep their own colours (no inversion), in an active or inactive window
    /// alike.
    ///
    /// `selection` is the table's selection value (anything `Hashable`; leave it out for a table
    /// without one): passing it makes a selection change redraw the selection at once.
    func quietTable(selection: AnyHashable? = nil) -> some View {
        self
            .tableStyle(.inset(alternatesRowBackgrounds: false))
            .scrollContentBackground(.hidden)
            .background(QuietTableAttach(token: selection, pass: QuietTablePass.next()))
    }
}

/// Finds the `NSTableView` SwiftUI built for the `Table` this sits behind (a background view
/// has the table's frame) and configures it through public AppKit API only. Holds the table
/// weakly and adds no NotificationCenter block observer.
private struct QuietTableAttach: NSViewRepresentable {
    var token: AnyHashable?
    /// Differs on every evaluation of the table's body, so `updateNSView` runs whenever the
    /// table may have been updated: SwiftUI puts the inset style back when the rows change
    /// (Sources filled after the look was applied stayed 10 pt in, with 28 pt rows), and an
    /// unchanged representable is not updated at all.
    var pass: Int

    func makeNSView(context: Context) -> QuietTableProbe { QuietTableProbe() }

    func updateNSView(_ view: QuietTableProbe, context: Context) {
        view.updated()
    }

    static func dismantleNSView(_ view: QuietTableProbe, coordinator: ()) {
        view.detach()
    }
}

enum QuietTablePass {
    private static var count = 0
    static func next() -> Int { count &+= 1; return count }
}

/// The invisible background view: locates its table once it is in a window and keeps the
/// table's look applied (SwiftUI may set style / highlight back when it updates the table).
final class QuietTableProbe: NSView {
    private weak var table: NSTableView?
    private weak var selectionView: QuietTableSelection?
    private weak var rulesView: QuietTableRules?
    private var lookScheduled = false

    override func hitTest(_ point: NSPoint) -> NSView? { nil }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if window == nil { return }
        scheduleLook()
    }

    override func layout() {
        super.layout()
        if table == nil { scheduleLook() }
    }

    /// Never changes the table in the middle of a layout or update pass: looks right after it.
    private func scheduleLook() {
        guard !lookScheduled else { return }
        lookScheduled = true
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.lookScheduled = false
            self.refresh()
        }
    }

    /// SwiftUI updated the view (the selection, the rows or the sort may have changed): draw the
    /// selection again now, and look at the table once SwiftUI has applied the update to it.
    func updated() {
        redraw()
        scheduleLook()
    }

    private func refresh() {
        if table == nil, window != nil, let found = findTable() { attach(found) }
        guard let table else { return }
        QuietTableLook.apply(to: table)
        redraw()
    }

    private func redraw() {
        selectionView?.needsDisplay = true
        rulesView?.needsDisplay = true
    }

    func detach() {
        selectionView?.removeFromSuperview()
        rulesView?.removeFromSuperview()
        selectionView = nil
        rulesView = nil
        table = nil
    }

    private func attach(_ table: NSTableView) {
        self.table = table
        // The selection lives in the table, under its row views (it scrolls with the rows and
        // goes with the table). The rules must lie over the row views: SwiftUI's row views draw
        // a separator of their own, inset by the first cell's padding and in the system's grey,
        // which the table's public API cannot hide (setting `gridColor` makes SwiftUI's row view
        // raise while a row is set up). Inside the table a later row view would cover them (the
        // table adds row views on top of its subviews), so they live in the clip view, just
        // above the table: they scroll with it (a clip view scrolls by moving its bounds, which
        // moves every subview) and their frame follows the table's.
        if let existing = table.subviews.lazy.compactMap({ $0 as? QuietTableSelection }).first {
            selectionView = existing
        } else {
            let v = QuietTableSelection(table: table)
            table.addSubview(v, positioned: .below, relativeTo: nil)
            selectionView = v
        }
        if let clip = table.superview as? NSClipView {
            if let existing = clip.subviews.lazy.compactMap({ $0 as? QuietTableRules }).first {
                rulesView = existing
            } else {
                let v = QuietTableRules(table: table)
                clip.addSubview(v, positioned: .above, relativeTo: table)
                rulesView = v
            }
        }
        QuietTableLook.apply(to: table)
    }

    /// The table whose scroll view lies where this view lies: searched from the nearest
    /// ancestors down (the background view is a sibling of the table's hosting view).
    private func findTable() -> NSTableView? {
        let mine = convert(bounds, to: nil)
        guard mine.width > 1, mine.height > 1 else { return nil }
        var ancestor = superview
        var depth = 0
        while let a = ancestor, depth < 6 {
            if let t = Self.table(in: a, matching: mine, depth: 0) { return t }
            ancestor = a.superview
            depth += 1
        }
        return nil
    }

    private static func table(in view: NSView, matching rect: NSRect, depth: Int) -> NSTableView? {
        if let scroll = view as? NSScrollView {
            guard let t = scroll.documentView as? NSTableView else { return nil }
            let r = scroll.convert(scroll.bounds, to: nil)
            let near = abs(r.minX - rect.minX) < 2 && abs(r.maxX - rect.maxX) < 2
                && abs(r.minY - rect.minY) < 2 && abs(r.maxY - rect.maxY) < 2
            return near ? t : nil
        }
        guard depth < 12 else { return nil }
        for sub in view.subviews where !(sub is QuietTableProbe) {
            if let t = table(in: sub, matching: rect, depth: depth + 1) { return t }
        }
        return nil
    }
}

enum QuietTableLook {
    /// Where the first column's text starts, from the page's left edge (the Log grid's): half
    /// the space between columns.
    static let textInset: CGFloat = 6
    static let rule = Theme.nsDynamic(light: 0xE6E4DE, dark: 0x262624)

    static func apply(to table: NSTableView) {
        let restyled = table.style != .plain
        if restyled { table.style = .plain }
        // No system highlight: no accent fill, no white-on-accent text; QuietTableSelection
        // draws the selection. Selecting (click, keys, selectRowIndexes) works as before.
        if table.selectionHighlightStyle != .none { table.selectionHighlightStyle = .none }
        if table.usesAlternatingRowBackgroundColors { table.usesAlternatingRowBackgroundColors = false }
        if !table.gridStyleMask.isEmpty { table.gridStyleMask = [] }
        let spacing = NSSize(width: textInset * 2, height: 0)
        if table.intercellSpacing != spacing { table.intercellSpacing = spacing }
        if table.backgroundColor != .clear { table.backgroundColor = .clear }
        if table.focusRingType != .none { table.focusRingType = .none }
        if let scroll = table.enclosingScrollView, scroll.drawsBackground { scroll.drawsBackground = false }
        if let old = table.headerView, !(old is QuietTableHeaderView) {
            let header = QuietTableHeaderView(frame: old.frame)
            header.menu = old.menu
            table.headerView = header
        }
        // Rows laid out under the inset style keep its cell frames (10 pt further in) until
        // something reloads them — a table whose rows were there before this ran (Sources
        // filled at launch) stayed indented.
        if restyled {
            table.tile()
            table.enumerateAvailableRowViews { row, _ in row.needsLayout = true }
            table.needsLayout = true
        }
    }
}

/// A view laid over the whole table (so it scrolls with the rows and is freed with the table's
/// scroll view). Never takes a click.
class QuietTableLayer: NSView {
    weak var table: NSTableView?

    init(table: NSTableView) {
        self.table = table
        super.init(frame: table.bounds)
        autoresizingMask = [.width, .height]
        wantsLayer = true
        layerContentsRedrawPolicy = .onSetNeedsDisplay
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not used") }

    override var isFlipped: Bool { true }
    override var isOpaque: Bool { false }
    override func hitTest(_ point: NSPoint) -> NSView? { nil }

    override func setFrameSize(_ newSize: NSSize) {
        super.setFrameSize(newSize)
        needsDisplay = true
    }

    /// The rows `dirtyRect` crosses, each with its rectangle in this view.
    func eachRow(in dirtyRect: NSRect, _ body: (Int, NSRect) -> Void) {
        guard let table else { return }
        let rows = table.rows(in: convert(dirtyRect, to: table))
        guard rows.length > 0 else { return }
        for row in rows.location..<(rows.location + rows.length) {
            body(row, convert(table.rect(ofRow: row), from: table))
        }
    }
}

/// Under the row views: each selected row's quiet fill and its 2 pt ink edge (the Log grid's
/// `SoftSelectionRowView`), whatever the window's key state.
final class QuietTableSelection: QuietTableLayer {
    override init(table: NSTableView) {
        super.init(table: table)
        // Selector-based, not a block: NotificationCenter drops it when this view goes.
        NotificationCenter.default.addObserver(self, selector: #selector(selectionChanged(_:)),
                                               name: NSTableView.selectionDidChangeNotification, object: table)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not used") }

    @objc private func selectionChanged(_ note: Notification) {
        needsDisplay = true
    }

    override func draw(_ dirtyRect: NSRect) {
        guard let selected = table?.selectedRowIndexes, !selected.isEmpty else { return }
        eachRow(in: dirtyRect) { row, r in
            guard selected.contains(row) else { return }
            Theme.nsSelectedAccent.setFill()
            r.fill()
            Theme.nsText.setFill()
            NSRect(x: r.minX, y: r.minY, width: 2, height: r.height).fill()
        }
    }
}

/// Over the row views, in the clip view just above the table: one hairline under every row,
/// the row's full width — over the separator SwiftUI's row view draws in the same place.
final class QuietTableRules: QuietTableLayer {
    override init(table: NSTableView) {
        super.init(table: table)
        autoresizingMask = []
        frame = table.frame
        table.postsFrameChangedNotifications = true
        // Selector-based, not a block: NotificationCenter drops it when this view goes.
        NotificationCenter.default.addObserver(self, selector: #selector(tableMoved(_:)),
                                               name: NSView.frameDidChangeNotification, object: table)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not used") }

    /// The table grew (rows came) or was resized: lie over it again.
    @objc private func tableMoved(_ note: Notification) {
        guard let table, frame != table.frame else { return }
        frame = table.frame
    }

    override func draw(_ dirtyRect: NSRect) {
        QuietTableLook.rule.setFill()
        eachRow(in: dirtyRect) { _, r in
            NSRect(x: r.minX, y: r.maxY - 1, width: r.width, height: 1).fill()
        }
    }
}

/// The header: the page ground, each title 11 pt muted at the column's text edge, the sort
/// arrow at the column's right, one hairline under it. Clicks (sorting, resizing) and the menu
/// stay `NSTableHeaderView`'s.
final class QuietTableHeaderView: NSTableHeaderView {
    static let titleFont = NSFont.systemFont(ofSize: 11, weight: .medium)

    override func draw(_ dirtyRect: NSRect) {
        Theme.nsContent.setFill()
        bounds.fill()
        if let tv = tableView {
            let attrs: [NSAttributedString.Key: Any] = [.font: Self.titleFont, .foregroundColor: Theme.nsMuted]
            let sorted = tv.sortDescriptors.first
            let inset = tv.intercellSpacing.width / 2
            for (i, col) in tv.tableColumns.enumerated() where !col.isHidden {
                let r = headerRect(ofColumn: i)
                guard r.intersects(dirtyRect) else { continue }
                let title = col.headerCell.stringValue.isEmpty ? col.title : col.headerCell.stringValue
                let text = NSAttributedString(string: title, attributes: attrs)
                let size = text.size()
                var arrowRoom: CGFloat = 0
                if let s = sorted, let key = s.key, col.sortDescriptorPrototype?.key == key {
                    arrowRoom = 13
                    Self.drawArrow(in: NSRect(x: r.maxX - inset - 8, y: r.midY - 3, width: 8, height: 6),
                                   ascending: s.ascending)
                }
                let room = max(0, r.width - inset * 2 - arrowRoom)
                let w = min(size.width, room)
                let x = col.headerCell.alignment == .right ? r.maxX - inset - arrowRoom - w : r.minX + inset
                text.draw(with: NSRect(x: x, y: r.midY - size.height / 2, width: w, height: size.height),
                          options: [.usesLineFragmentOrigin, .truncatesLastVisibleLine])
            }
        }
        QuietTableLook.rule.setFill()
        NSRect(x: bounds.minX, y: isFlipped ? bounds.maxY - 1 : bounds.minY, width: bounds.width, height: 1).fill()
    }

    /// A small chevron: up for ascending, down for descending (the header is flipped).
    private static func drawArrow(in r: NSRect, ascending: Bool) {
        let p = NSBezierPath()
        if ascending {
            p.move(to: NSPoint(x: r.minX, y: r.maxY)); p.line(to: NSPoint(x: r.midX, y: r.minY))
            p.line(to: NSPoint(x: r.maxX, y: r.maxY))
        } else {
            p.move(to: NSPoint(x: r.minX, y: r.minY)); p.line(to: NSPoint(x: r.midX, y: r.maxY))
            p.line(to: NSPoint(x: r.maxX, y: r.minY))
        }
        p.lineWidth = 1.2
        Theme.nsMuted.setStroke()
        p.stroke()
    }
}
