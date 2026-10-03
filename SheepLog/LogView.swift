import AppKit
import Combine
import SwiftUI
import UniformTypeIdentifiers

/// The Syslog pane: state header, filter strip, the grid + an inspector column, a footer.
struct LogView: View {
    @ObservedObject private var model = AppModel.shared
    @ObservedObject private var store = AppModel.shared.logs
    @ObservedObject private var syslog = AppModel.shared.syslog
    @State private var selectedID: Int?
    /// Wider than the family's 320 pt inspector: at 320 the millisecond timestamps and
    /// "address:port (udp)" in the Line group are cut in the middle ("2026-09-…23:14.979").
    /// Remembered across launches; never more than `detailCap` of the pane.
    @AppStorage("SheepLog.logDetailWidth") private var detailWidth: Double = 360
    /// The detail panel shows only while a line is selected, unless it is kept open.
    @AppStorage("SheepLog.logDetailPinned") private var detailPinned = false
    @State private var paneWidth: CGFloat = 0
    @State private var thisMac: String = HostAddresses.primaryForDevices() ?? "this Mac’s address"
    @FocusState private var filterFocused: Bool

    var body: some View {
        let _ = PaneProbe.ran("body.log")
        VStack(spacing: 0) {
            PaneHeader(pane: .log, status: heading, detail: subtitle, problem: syslog.lastError != nil) { headerActions }
                .paneColumn()
                .padding(.top, Metrics.headerTop)
                .padding(.bottom, 14)

            PaneStrip { strip }
                .controlSize(.small)

            // The table, its footer and the inspector sit in the page column: the grid's left
            // edge is the title's.
            VStack(spacing: 0) {
                tableAndDetail
                footer
            }
            .paneColumn()
        }
        .paneKeyCommands(find: { filterFocused = true }, copy: copySelection)
        .onAppear {
            #if DEBUG
            LogDemo.apply(store: store) { selectedID = $0 }
            #endif
        }
        .task {
            // The "point your devices at …" address follows a network change while shown.
            LeakProbe.add("Log.addressLoop")
            defer { LeakProbe.remove("Log.addressLoop") }
            while !Task.isCancelled {
                PaneProbe.ran("log.addressLoop")
                let a = HostAddresses.primaryForDevices() ?? "this Mac’s address"
                if a != thisMac { thisMac = a }
                try? await Task.sleep(for: .seconds(HostAddresses.cacheSeconds))
            }
        }
    }

    /// The detail panel comes in when a line is selected and leaves when none is (or stays,
    /// pinned): at the 1000 pt minimum an always-open 360 pt panel leaves the Message column no
    /// room at all.
    private var tableAndDetail: some View {
        HStack(spacing: 0) {
            tableArea
                .frame(minWidth: 300, maxWidth: .infinity, maxHeight: .infinity)
            if showsDetail {
                Group {
                    ColumnDivider(width: detailWidthBinding, range: detailRange)
                    LogDetailPanel(entry: selectedEntry, compact: shownDetailWidth < 355)
                        .frame(width: shownDetailWidth)
                        .frame(maxHeight: .infinity)
                }
                .transition(.move(edge: .trailing).combined(with: .opacity))
            }
        }
        .frame(maxHeight: .infinity)
        .animation(.snappy(duration: 0.22), value: showsDetail)
        .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { paneWidth = $0 }
    }

    private var selectedEntry: LogEntry? {
        selectedID.flatMap { store.entry(id: $0) }
    }

    private var showsDetail: Bool { detailPinned || selectedID != nil }

    /// At most 32 % of the pane (and never under 220 pt).
    private var detailCap: CGFloat { max(220, (paneWidth > 0 ? paneWidth : 1000) * 0.32) }
    private var detailRange: ClosedRange<CGFloat> { min(260, detailCap)...max(min(260, detailCap), min(560, detailCap)) }
    private var shownDetailWidth: CGFloat { Self.detailWidth(stored: detailWidth, range: detailRange) }

    /// The stored width inside the range; a stored value that is no width (a real NaN or
    /// infinity — `defaults write … -float nan`, which @AppStorage hands over as NaN, and
    /// `max(NaN, 260)` is NaN: the panel got a NaN width) is the default 360 kept in the range.
    static func detailWidth(stored: Double, range: ClosedRange<CGFloat>) -> CGFloat {
        let w = stored.isFinite ? CGFloat(stored) : 360
        return min(max(w, range.lowerBound), range.upperBound)
    }
    private var detailWidthBinding: Binding<CGFloat> {
        Binding(get: { shownDetailWidth }, set: { detailWidth = Double($0) })
    }

    /// ⌘⇧C: the selected line's raw text (the table's own ⌘C copies every selected row).
    private func copySelection() {
        guard let e = selectedEntry else { NSSound.beep(); return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(e.raw, forType: .string)
    }

    // MARK: Header

    private var heading: String {
        if store.paused {
            return "Paused — \(Format.count(store.pausedCount)) \(store.pausedCount == 1 ? "line" : "lines") waiting"
        }
        guard syslog.isRunning else { return "Not listening" }
        return "Listening on \(syslog.portsText)"
    }

    private var subtitle: String {
        // Also while running: one transport can fail while the other listens, and the heading
        // alone would then say only "Listening on tcp 514.".
        if let e = syslog.lastError { return e }
        let n = store.entries.count
        let s = store.sources.count
        return "\(Format.count(n)) \(n == 1 ? "line" : "lines") from \(s) \(s == 1 ? "source" : "sources") · \(LogView.rateText(store.rate))"
    }

    static func rateText(_ rate: Double) -> String {
        if rate > 0, rate < 10 { return String(format: "%.1f msg/s", rate) }
        return "\(Format.count(Int(rate.rounded()))) msg/s"
    }

    // MARK: Strip

    @ViewBuilder private var strip: some View {
        FilterField(text: $store.queryText, prompt: "login failed -keepalive host:10.1.0.9 sev:<=warn",
                    error: store.queryError,
                    help: "Words (AND), OR, NOT/-word, \"phrases\", /regex/, host:, sev:<=warn, vendor:, app:, msg:, f:key=value, key=value, src:, dst:, port: (the syslog sender's port) — ⌘F to focus, Esc to clear",
                    focus: $filterFocused,
                    onSubmit: { store.applyQueryText() },
                    onClear: { store.applyQueryText() })
            .frame(maxWidth: .infinity)

        Button { store.regexMode.toggle() } label: {
            Text(".*")
                .font(.system(size: 12, weight: store.regexMode ? .semibold : .regular, design: .monospaced))
                .foregroundStyle(store.regexMode ? Theme.text : Theme.text2)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Treat every bare word as a regular expression")
        .accessibilityLabel("Regular expressions")
        .accessibilityAddTraits(store.regexMode ? .isSelected : [])

        if let source = store.selectedSource {
            // Words, not a chip: "Source 10.1.0.9  Show all".
            HStack(alignment: .firstTextBaseline, spacing: 12) {
                HStack(alignment: .firstTextBaseline, spacing: 5) {
                    Text("Source")
                        .font(Theme.body)
                        .foregroundStyle(Theme.text2)
                    Text(source)
                        .font(Theme.mono)
                        .foregroundStyle(Theme.text)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Button("Show all") { store.selectedSource = nil }
                    .buttonStyle(.quietLink)
                    .help("Show every source")
                    .accessibilityLabel("Show every source")
            }
            .fixedSize()
        }

        QuietToolToggle("Newest first", isOn: $model.settings.newestFirst)
        QuietToolToggle("Detail", isOn: $detailPinned,
                        help: detailPinned ? "Hide the detail panel when no line is selected"
                                           : "Keep the detail panel open when no line is selected")
            .accessibilityLabel("Keep detail panel open")
    }

    /// The page's actions, on the status line (the page has tabs, so they sit under them).
    @ViewBuilder private var headerActions: some View {
        // One width for both titles, so the links to its right do not jump on Pause.
        Button { store.paused.toggle() } label: {
            Text(store.paused ? "Resume" : "Pause").frame(minWidth: 46, alignment: .trailing)
        }
        .buttonStyle(.quietLink)
        Button("Clear") {
            store.clear()
            selectedID = nil
        }
        .buttonStyle(.quietLink)
        Button(store.isExporting ? "Exporting…" : "Export…") { export() }
            .buttonStyle(.quietLink)
            .disabled(store.isExporting)
    }

    // MARK: Table

    private var tableArea: some View {
        ZStack {
            LogTableView(store: store, selectedID: $selectedID)
            if store.entries.isEmpty {
                TableEmptyOverlay(text: emptyText)
                    .allowsHitTesting(false)
            } else if store.visible.isEmpty {
                TableEmptyOverlay(text: noMatchText)
                    .allowsHitTesting(false)
            }
        }
        .overlay(alignment: .bottom) {
            // The field's red underline alone does not say what is wrong, nor that the table
            // still shows the previous filter.
            if let error = store.queryError {
                let tint = store.queryErrorIsNotice ? Theme.text2 : Theme.err
                Text(Self.filterBanner(error, isNotice: store.queryErrorIsNotice))
                    .font(Theme.caption.weight(.medium))
                    .foregroundStyle(tint)
                    .padding(.horizontal, 14)
                    .padding(.bottom, 10)
                    .frame(maxWidth: .infinity, alignment: .center)
                    .allowsHitTesting(false)
            }
        }
        .background(Theme.panel)
    }

    /// The line under the table for `LogStore.queryError`. A notice (a regex that may be slow,
    /// or one stopped as too slow) is about the filter that *is* applied; only a parse error
    /// leaves the previous filter in place.
    static func filterBanner(_ error: String, isNotice: Bool) -> String {
        isNotice ? "Filter applied — \(error)." : "Filter not applied — \(error). Showing the last filter that worked."
    }

    private var emptyText: String {
        let port = syslog.udpPort > 0 ? "udp \(syslog.udpPort)" : "udp \(model.settings.syslogUDPPort)"
        if store.paused {
            let n = store.pausedCount
            return n == 0 ? "Paused. New lines are held until you press Resume."
                          : "Paused — \(Format.count(n)) \(n == 1 ? "line is" : "lines are") waiting. Press Resume to show them."
        }
        if !syslog.isRunning {
            if let e = syslog.lastError { return "Syslog could not start: \(e)" }
            return "Not listening. Start Syslog on the Status page, then point your devices’ syslog at this Mac (\(thisMac), \(port))."
        }
        return "No lines yet. Point your devices’ syslog at this Mac (\(thisMac), \(port))."
    }

    /// Lines exist but none pass: say which part of the filter is doing it.
    private var noMatchText: String {
        Self.noMatchText(entries: store.entries.count, query: !store.query.isEmpty, source: store.selectedSource,
                         masked: store.severityMask.count < Severity.allCases.count,
                         held: store.paused ? store.pausedCount : 0)
    }

    /// `held`: lines held back while paused. Status / Sources "Show" on a device whose lines
    /// all arrived after Pause said only "None of the 1,000 lines match source 10.9.7.1" while
    /// the device's own counters said 500.
    static func noMatchText(entries n: Int, query: Bool, source: String?, masked: Bool, held: Int) -> String {
        var parts: [String] = []
        if query { parts.append("the filter") }
        if let s = source { parts.append("source \(s)") }
        if masked { parts.append("the severity mask") }
        let lines = n == 1 ? "The 1 line does not" : "None of the \(Format.count(n)) lines"
        var text = parts.isEmpty ? "No lines match." : "\(lines) match \(parts.joined(separator: " + "))."
        if held > 0 {
            text += " Paused — \(Format.count(held)) newer \(held == 1 ? "line is" : "lines are") waiting; press Resume to see \(held == 1 ? "it" : "them")."
        }
        return text
    }

    // MARK: Footer

    /// One faint 11 pt line under the grid, on the column's left edge, no rule above it.
    private var footer: some View {
        Text(footerText)
            .font(Theme.caption)
            .foregroundStyle(Theme.faintText)
            .lineLimit(1)
            .truncationMode(.middle)
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 8)
            .padding(.bottom, 12)
    }

    private var footerText: String { Self.footerText(store: store, diskLogging: model.settings.diskLogging) }

    static func footerText(store: LogStore, diskLogging: Bool) -> String {
        let n = store.entries.count
        let limit = max(1, store.limit)
        var s = "\(Format.count(store.visible.count)) shown of \(Format.count(n)) · \(LogView.rateText(store.rate)) · buffer \(Format.count(limit)) (\(Int((Double(n) / Double(limit) * 100).rounded())) %)"
        s += Self.dropText(dropped: store.dropped, lost: store.lost)
        if let note = store.exportNote { s += " · \(note)" }
        if let note = store.resumeNote, !store.paused { s += " · \(note)" }
        if diskLogging, let logger = store.diskLogger {
            s += " · Saving to \(Self.abbreviate((logger.currentFile ?? logger.todaysFile).path))"
        }
        return s
    }

    /// `/Users/x/Library/…` → `~/Library/…`
    private static func abbreviate(_ path: String) -> String {
        let home = NSHomeDirectory()
        return path.hasPrefix(home) ? "~" + path.dropFirst(home.count) : path
    }

    /// " · 1,204 rolled out · 36 dropped": the oldest lines leaving a full buffer are not a
    /// loss, so they are not called dropped (a week-long run would say "1,234,567 dropped").
    static func dropText(dropped: Int, lost: Int) -> String {
        var s = ""
        let rolled = dropped - lost
        if rolled > 0 { s += " · \(Format.count(rolled)) rolled out" }
        if lost > 0 { s += " · \(Format.count(lost)) dropped" }
        return s
    }

    // MARK: Export

    private func export() {
        let panel = NSSavePanel()
        let logType = UTType(filenameExtension: "log") ?? .plainText
        panel.allowedContentTypes = [logType, .commaSeparatedText]
        panel.allowsOtherFileTypes = true
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = Self.exportName(source: store.selectedSource, date: Date())
        panel.message = LogStore.exportPanelMessage(shown: store.visibleCount, held: store.paused ? store.pausedCount : 0)
        guard panel.runModal() == .OK, let url = panel.url else { return }
        // The store waits for a re-parse / re-scan in flight, snapshots on the main actor and
        // writes off it; the flag lives on the store (a pane switch mid-export made a new
        // LogView with Export enabled while the first write was still running).
        let csv = url.pathExtension.lowercased() == "csv"
        let store = self.store, model = self.model
        Task {
            if let failure = await store.export(to: url, csv: csv) {
                model.report("Could not save \(url.lastPathComponent).", detail: failure)
            }
        }
    }

    /// `UncleSpy-2026-09-23-101532.log`, with the source when one is selected — two exports in
    /// a day do not propose the same name.
    static func exportName(source: String?, date: Date) -> String {
        var name = "UncleSpy-\(Format.day.string(from: date))-\(Format.hms.string(from: date))"
        if let source {
            name += "-" + source.map { $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" ? String($0) : "_" }.joined()
        }
        return name + ".log"
    }
}

#if DEBUG
/// Screenshot helpers for the Syslog pane (Debug builds, with the shell's `-demoShot`):
/// `-demoLogFilter "<query>"` types a filter, `-demoLogPause` pauses before lines arrive,
/// `-demoLogSelect <text>` selects the newest line whose raw text contains `<text>` once it
/// has arrived (send lines with Tests/replay.sh during `-demoShotDelay`), `-demoLogFile
/// <path>` ingests every line of a file as if received (from `-demoLogSources N` addresses,
/// 10.20.0.1…N, default 1), `-demoLogSource <address>` shows one source.
@MainActor
enum LogDemo {
    private static var applied = false

    static func apply(store: LogStore, select: @escaping (Int) -> Void) {
        guard !applied else { return }
        applied = true
        if CommandLine.arguments.contains("-demoLogPause") { store.paused = true }
        if let q = CommandLine.value(after: "-demoLogFilter") {
            store.queryText = q
            store.applyQueryText()
        }
        if let path = CommandLine.value(after: "-demoLogFile"),
           let text = try? String(contentsOfFile: path, encoding: .utf8) {
            let sources = max(1, CommandLine.value(after: "-demoLogSources").flatMap { Int($0) } ?? 1)
            let now = Date()
            let raws = text.split(separator: "\n").enumerated().map { i, line in
                RawSyslog(received: now, sourceAddress: "10.20.0.\(i % sources + 1)", sourcePort: 514,
                          transport: .udp, text: String(line))
            }
            store.ingest(SyslogListener.parseBatch(raws, overrides: [:]))
        }
        // `-demoLogSource <address>`: as Status / Sources "Show" does (the tool row's source words).
        if let source = CommandLine.value(after: "-demoLogSource") { store.showSource(source) }
        guard let needle = CommandLine.value(after: "-demoLogSelect") else { return }
        Task { @MainActor in
            for _ in 0..<120 {
                if let e = store.visible.last(where: { $0.raw.contains(needle) }) {
                    select(e.id)
                    return
                }
                try? await Task.sleep(for: .milliseconds(250))
            }
        }
    }
}
#endif

// MARK: - Inspector column

/// A hairline the inspector column can be resized by (drag left to widen it).
struct ColumnDivider: View {
    @Binding var width: CGFloat
    let range: ClosedRange<CGFloat>
    @State private var start: CGFloat?

    var body: some View {
        Rectangle()
            .fill(Theme.hairline)
            .frame(width: 1)
            .frame(maxHeight: .infinity)
            .overlay {
                Color.clear
                    .frame(width: 7)
                    .contentShape(Rectangle())
                    .onHover { inside in
                        if inside { NSCursor.resizeLeftRight.push() } else { NSCursor.pop() }
                    }
                    .gesture(DragGesture(minimumDistance: 1, coordinateSpace: .global)
                        .onChanged { g in
                            let s = start ?? width
                            if start == nil { start = width }
                            width = min(range.upperBound, max(range.lowerBound, s - g.translation.width))
                        }
                        .onEnded { _ in start = nil })
            }
    }
}

/// Key over value, for the detail panel when it is narrow (at 32 % of a 1000 pt window the
/// side-by-side rows cut every timestamp to "2026….602").
struct StackedFactRow: View {
    let key: String
    let value: String
    var copyable = true
    var copyValue: String?

    var body: some View {
        HStack(alignment: .center, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(key)
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.dimText)
                Text(value)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(Theme.text)
                    .textSelection(.enabled)
                    .lineLimit(3)
                    .truncationMode(.middle)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
            if copyable {
                let v = copyValue ?? value
                CopyButton(value: v, help: "Copy \(v)")
            }
        }
        .padding(.vertical, 7)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// LabDC's inspector row (UsersInspector's `InspectorRow`): the label above the value, a word
/// link at the right, rows divided by hairlines (`GroupedList`).
private struct InspectorFactRow: View {
    let label: String
    let value: String
    var mono = true
    var copyable = true
    var copyValue: String?

    var body: some View {
        HStack(alignment: .lastTextBaseline, spacing: 16) {
            QuietField(label) {
                Text(value)
                    .font(mono ? Theme.mono : Theme.body)
                    .foregroundStyle(Theme.text)
                    .textSelection(.enabled)
                    .lineLimit(3)
                    .truncationMode(.middle)
                    .fixedSize(horizontal: false, vertical: true)
                    .help(value)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            if copyable {
                let v = copyValue ?? value
                CopyButton(value: v, help: "Copy \(v)")
            }
        }
        .padding(.vertical, 9)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct LogDetailPanel: View {
    let entry: LogEntry?
    /// Narrow panel: vendor fields key over value.
    var compact = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 28) {
                if let e = entry {
                    content(e)
                } else {
                    Text("Select a line to see its header, its vendor fields and the raw text.")
                        .font(Theme.body)
                        .foregroundStyle(Theme.faintText)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.top, 2)
                }
            }
            // Room for the scroll bar on the right, so it never covers Copy.
            .padding(.leading, 24)
            .padding(.trailing, 10)
            .padding(.top, 4)
            .padding(.bottom, 24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Theme.content)
    }

    /// The source as the inspector's name: the hostname the line carries, else the address.
    private func title(_ e: LogEntry) -> String {
        e.hostname.isEmpty ? e.sourceAddress : e.hostname
    }

    @ViewBuilder private func content(_ e: LogEntry) -> some View {
        // LabDC's InspectorHeader: the name large and light, a muted line under it, then the
        // label-above rows.
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 6) {
                Text(title(e))
                    .font(Theme.subtitle)
                    .tracking(-0.4)
                    .foregroundStyle(Theme.text)
                    .lineLimit(2)
                    .truncationMode(.middle)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
                    .accessibilityAddTraits(.isHeader)
                HStack(alignment: .firstTextBaseline, spacing: 0) {
                    Text("\(e.vendor.label) · ")
                        .foregroundStyle(Theme.text2)
                    Text(e.severity.label)
                        .foregroundStyle(pillKind(e.severity) == .bad ? Theme.err : Theme.text2)
                        .accessibilityLabel(e.severity.name)
                    Text(" · \(e.facility.name)")
                        .foregroundStyle(Theme.text2)
                }
                .font(Theme.detail)
                .lineLimit(1)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
    
            GroupedList {
                InspectorFactRow(label: "Received", value: Format.stamp.string(from: e.received))
                InspectorFactRow(label: "Device time", value: e.deviceTime.map { Format.stamp.string(from: $0) } ?? "—",
                                 copyable: e.deviceTime != nil)
                // The address alone is what gets pasted into a ping or an ACL; the port and
                // transport stay in the row.
                InspectorFactRow(label: "From", value: "\(e.sourceAddress):\(e.sourcePort) (\(e.transport.rawValue))",
                                 copyValue: e.sourceAddress)
                InspectorFactRow(label: "Hostname", value: e.hostname.isEmpty ? "—" : e.hostname, copyable: !e.hostname.isEmpty)
                InspectorFactRow(label: "Program", value: e.program.isEmpty ? "—" : e.program, copyable: !e.program.isEmpty)
                InspectorFactRow(label: "PID", value: e.pid ?? "—", copyable: e.pid != nil)
                InspectorFactRow(label: "PRI", value: priText(e), copyable: false)
            }
        }

        if !e.fields.isEmpty {
            // A compact key / value list: a FortiGate line carries 40 fields.
            PaneGroup("Vendor fields") {
                ForEach(Array(e.fields.enumerated()), id: \.offset) { _, f in
                    if compact {
                        StackedFactRow(key: f.key, value: f.value)
                    } else {
                        FactRow(key: f.key, value: f.value, keyWidth: 96, monoLines: 3)
                    }
                }
            }
        }

        PaneSection("Raw") {
            // A 64 KB datagram laid out in full is ~2,000 wrapped lines: the Copy / Filter
            // links below it would be a long scroll away and every selection re-lays it out.
            Text(Self.rawPreview(e.raw))
                .font(.system(size: 11.5, design: .monospaced))
                .foregroundStyle(Theme.text)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
                .background(RoundedRectangle(cornerRadius: Metrics.field).fill(Theme.well))
        }

        // Word links; they wrap onto two lines in a narrow panel.
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 20) { actions(e) }
            VStack(alignment: .leading, spacing: 10) { actions(e) }
        }
    }

    @ViewBuilder private func actions(_ e: LogEntry) -> some View {
        CopyButton("Copy raw", value: e.raw, bordered: true)
            .fixedSize()
        Button("Filter this host") {
            AppModel.shared.logs.appendToQuery("host:\(e.sourceAddress)")
        }
        .buttonStyle(.quietLink)
        .fixedSize()
        Button("Open in SNMP test") {
            AppModel.shared.mainPane = .snmpTest
            NotificationCenter.default.post(name: .sheepLogSNMPTarget, object: e.sourceAddress)
        }
        .buttonStyle(.quietLink)
        .fixedSize()
    }

    /// The first 8 KB of the raw line, then how much is left ("Copy raw" copies all of it).
    static let rawPreviewLimit = 8_192

    static func rawPreview(_ raw: String) -> String {
        let u = raw.utf8
        guard u.count > rawPreviewLimit else { return raw }
        var s = String(decoding: u.prefix(rawPreviewLimit), as: UTF8.self)
        if s.unicodeScalars.last == "\u{FFFD}" { s.unicodeScalars.removeLast() }
        let rest = u.count - s.utf8.count
        return s + "…\n\n[\(Format.count(rest)) more bytes of \(Format.count(u.count)) — Copy raw copies the whole line]"
    }

    private func pillKind(_ s: Severity) -> StatusPill.Kind {
        switch s {
        case .emergency, .alert, .critical, .error: .bad
        case .warning: .warn
        default: .neutral
        }
    }

    private func priText(_ e: LogEntry) -> String {
        guard let p = e.priority else { return "none (user.notice assumed)" }
        let f = Facility(rawValue: p >> 3)?.name ?? "\(p >> 3)"
        let s = Severity(rawValue: p & 7)?.name ?? "\(p & 7)"
        return "\(p) = \(f).\(s)"
    }
}
