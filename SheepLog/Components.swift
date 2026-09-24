import AppKit
import SwiftUI
import UniformTypeIdentifiers

// MARK: - Grouped lists (System Settings shape, shared with SheepRadius)

struct GroupedList<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        _VariadicView.Tree(SeparatedRows()) { content }
            .background(RoundedRectangle(cornerRadius: Metrics.card).fill(Theme.panel))
            .clipShape(RoundedRectangle(cornerRadius: Metrics.card))
            .overlay {
                RoundedRectangle(cornerRadius: Metrics.card)
                    .strokeBorder(Theme.hairline, lineWidth: 0.5)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct SeparatedRows: _VariadicView_MultiViewRoot {
    @ViewBuilder func body(children: _VariadicView.Children) -> some View {
        let last = children.last?.id
        VStack(alignment: .leading, spacing: 0) {
            ForEach(children) { child in
                child
                if child.id != last {
                    Rectangle().fill(Theme.hairlineSoft).frame(height: 0.5)
                }
            }
        }
    }
}

struct PaneGroup<Content: View>: View {
    let title: String
    var accessory: AnyView?
    @ViewBuilder var content: Content

    init(_ title: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.accessory = nil
        self.content = content()
    }

    init(_ title: String, accessory: some View, @ViewBuilder content: () -> Content) {
        self.title = title
        self.accessory = AnyView(accessory)
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Text(title).groupTitle()
                Spacer(minLength: 0)
                if let accessory { accessory.controlSize(.small) }
            }
            .padding(.horizontal, 2)
            GroupedList { content }
        }
    }
}

struct KeyValueRow<Value: View>: View {
    let key: String
    var help: String?
    var keyWidth: CGFloat = Metrics.key
    @ViewBuilder var value: Value

    init(_ key: String, help: String? = nil, keyWidth: CGFloat = Metrics.key,
         @ViewBuilder value: () -> Value) {
        self.key = key
        self.help = help
        self.keyWidth = keyWidth
        self.value = value()
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            HStack(spacing: 4) {
                Text(key)
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.text2)
                    .fixedSize(horizontal: false, vertical: true)
                if let help { HelpDot(text: help) }
                Spacer(minLength: 0)
            }
            .frame(width: keyWidth, alignment: .leading)
            value
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct NoteRow: View {
    let text: String
    var systemImage: String?
    var tint: Color = Theme.faintText

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            if let systemImage {
                Image(systemName: systemImage).font(.system(size: 11)).foregroundStyle(tint)
            }
            Text(text)
                .font(.system(size: 11.5))
                .foregroundStyle(tint == Theme.faintText ? Theme.faintText : Theme.text2)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: Metrics.prose, alignment: .leading)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - Copying, and saying so

nonisolated enum CopyFeedback {
    static let hold: Double = 1.2
    static let word = "Copied"
    static let idleSymbol = "doc.on.doc"
    static let copiedSymbol = "checkmark"
    static func symbol(copied: Bool) -> String { copied ? copiedSymbol : idleSymbol }
    static func title(_ idle: String?, copied: Bool) -> String? {
        guard let idle else { return nil }
        return copied ? word : idle
    }
}

struct CopyButton: View {
    private let value: () -> String
    private let title: String?
    private let bordered: Bool
    private let iconSize: CGFloat?
    private let help: String

    @State private var copied = false
    @State private var revert: Task<Void, Never>?

    init(_ title: String? = nil, value: @autoclosure @escaping () -> String,
         bordered: Bool = false, iconSize: CGFloat? = 10, help: String = "Copy") {
        self.value = value
        self.title = title
        self.bordered = bordered
        self.iconSize = iconSize
        self.help = help
    }

    @ViewBuilder
    var body: some View {
        if bordered {
            Button(action: copy) { label }.buttonStyle(.bordered).help(help)
        } else {
            Button(action: copy) { label }.buttonStyle(.borderless).help(help)
        }
    }

    private var label: some View {
        HStack(spacing: 4) {
            Image(systemName: CopyFeedback.symbol(copied: copied))
                .font(iconSize.map { Font.system(size: $0) })
                .frame(width: iconSize.map { $0 + 4 })
            if let title = CopyFeedback.title(title, copied: copied) {
                Text(title)
            }
        }
        .foregroundStyle(copied ? Theme.accent : (bordered ? Color.primary : Theme.dimText))
        .accessibilityLabel(copied ? CopyFeedback.word : (title ?? "Copy"))
    }

    private func copy() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value(), forType: .string)
        copied = true
        revert?.cancel()
        revert = Task {
            try? await Task.sleep(for: .seconds(CopyFeedback.hold))
            guard !Task.isCancelled else { return }
            copied = false
        }
    }
}

// MARK: - Values

struct StatusPill: View {
    enum Kind { case ok, bad, warn, neutral, accent }
    let text: String
    var kind: Kind = .neutral

    var body: some View {
        Text(text)
            .font(.system(size: 11, weight: .medium))
            .foregroundStyle(foreground)
            .padding(.horizontal, 7)
            .padding(.vertical, 2)
            .background(Capsule().fill(background))
            .fixedSize()
    }

    private var foreground: Color {
        switch kind {
        case .ok: Theme.ok
        case .bad: Theme.err
        case .warn: Theme.warn
        case .neutral: Theme.dimText
        case .accent: Theme.accent
        }
    }

    private var background: Color {
        switch kind {
        case .ok: Theme.ok.opacity(0.13)
        case .bad: Theme.err.opacity(0.13)
        case .warn: Theme.warn.opacity(0.13)
        case .neutral: Theme.control
        case .accent: Theme.accent.opacity(0.13)
        }
    }
}

/// **One panel, several cells with hairlines between them** — the Status strip SheepRadius
/// draws under its heading (caption / big value / one line under it, per cell).
struct StatCell: Identifiable, Sendable {
    var id: String { caption }
    let caption: String
    let value: String
    var tint: Color = Theme.text
    var mono = false
    var detail: String = ""
    /// Tooltip for the whole cell (what the number counts).
    var help: String = ""
}

struct StatStrip: View {
    let cells: [StatCell]

    var body: some View {
        HStack(spacing: 0) {
            ForEach(Array(cells.enumerated()), id: \.element.id) { i, c in
                VStack(alignment: .leading, spacing: 2) {
                    Text(c.caption)
                        .font(.system(size: 11.5))
                        .foregroundStyle(Theme.faintText)
                    Text(c.value)
                        .font(.system(size: c.mono ? 16 : 19, weight: .semibold,
                                      design: c.mono ? .monospaced : .default))
                        .foregroundStyle(c.tint)
                        .lineLimit(1)
                        .minimumScaleFactor(0.7)
                        .textSelection(.enabled)
                    Text(c.detail.isEmpty ? " " : c.detail)
                        .font(.system(size: 11.5))
                        .foregroundStyle(Theme.dimText)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                .frame(maxWidth: .infinity, alignment: .topLeading)
                .padding(.horizontal, 14)
                .padding(.vertical, 12)
                .contentShape(Rectangle())
                .help(c.help.isEmpty ? "\(c.caption): \(c.value)\(c.detail.isEmpty ? "" : " — \(c.detail)")" : c.help)
                if i < cells.count - 1 {
                    Rectangle().fill(Theme.hairlineSoft).frame(width: 0.5).padding(.vertical, 10)
                }
            }
        }
        .panelCard()
    }
}

// MARK: - Pane frames

struct PaneColumnFrame: ViewModifier {
    var maxWidth: CGFloat = .infinity
    @State private var available: CGFloat = 0

    func body(content: Content) -> some View {
        content
            .frame(maxWidth: maxWidth, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .center)
            .padding(.horizontal, PaneColumn.gutter(available: available))
            .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { available = $0 }
    }
}

extension View {
    func identifierText() -> some View { lineLimit(1).truncationMode(.middle) }
    func proseText() -> some View { lineLimit(1).truncationMode(.tail) }
    func paneColumn(maxWidth: CGFloat = .infinity) -> some View {
        modifier(PaneColumnFrame(maxWidth: maxWidth))
    }
    func valueControl(_ width: CGFloat = Metrics.control) -> some View {
        frame(width: width, alignment: .leading)
    }
    func valueNumber(_ width: CGFloat = Metrics.numberField) -> some View {
        frame(width: width, alignment: .leading)
    }
    func tablePanel(minHeight: CGFloat = 120) -> some View {
        frame(minHeight: minHeight)
            .background(RoundedRectangle(cornerRadius: Metrics.card).fill(Theme.panel))
            .clipShape(RoundedRectangle(cornerRadius: Metrics.card))
            .overlay {
                RoundedRectangle(cornerRadius: Metrics.card)
                    .strokeBorder(Theme.hairline, lineWidth: 0.5)
            }
    }
    func panelCard(cornerRadius: CGFloat = Metrics.card) -> some View {
        background(RoundedRectangle(cornerRadius: cornerRadius).fill(Theme.panel))
            .clipShape(RoundedRectangle(cornerRadius: cornerRadius))
            .overlay {
                RoundedRectangle(cornerRadius: cornerRadius)
                    .strokeBorder(Theme.hairline, lineWidth: 0.5)
            }
    }
    func groupTitle() -> some View {
        font(.system(size: 11.5, weight: .semibold))
            .kerning(0.2)
            .foregroundStyle(Theme.faintText)
    }
    func hint() -> some View {
        font(.system(size: 11.5))
            .foregroundStyle(Theme.faintText)
            .lineSpacing(2)
            .frame(maxWidth: Metrics.prose, alignment: .leading)
    }
}

struct PaneBody<Content: View>: View {
    var spacing: CGFloat = 18
    var maxWidth: CGFloat = .infinity
    @ViewBuilder var content: Content

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: spacing) { content }
                .padding(.vertical, 18)
                .paneColumn(maxWidth: maxWidth)
        }
    }
}

/// Every pane's control strip under its header. The hairline under it is the only rule in a
/// pane that is not part of a group.
struct PaneStrip<Content: View>: View {
    var maxWidth: CGFloat?
    @ViewBuilder var content: Content

    var body: some View {
        HStack(spacing: 8) { content }
            .paneColumn(maxWidth: maxWidth ?? .infinity)
            .frame(height: 48)
            .overlay(alignment: .bottom) {
                Rectangle().fill(Theme.hairline).frame(height: 0.5)
            }
    }
}

/// An eyebrow, a heading that states the state, a subtitle.
struct PaneHeader<Actions: View>: View {
    let eyebrow: String
    let heading: String
    var subtitle: String = ""
    @ViewBuilder var actions: Actions

    var body: some View {
        HStack(alignment: .top, spacing: 16) {
            VStack(alignment: .leading, spacing: 2) {
                Text(eyebrow.uppercased())
                    .font(.system(size: 11, weight: .semibold))
                    .kerning(1.3)
                    .foregroundStyle(Theme.faintText)
                Text(heading)
                    .font(.system(size: 29, weight: .semibold))
                    .kerning(-0.3)
                    .foregroundStyle(Theme.text)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: 620, alignment: .leading)
                    .textSelection(.enabled)
                    .padding(.top, 1)
                if !subtitle.isEmpty {
                    Text(subtitle)
                        .font(.system(size: 12.5))
                        .foregroundStyle(Theme.text2)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: 720, alignment: .leading)
                        .padding(.top, 2)
                }
            }
            Spacer(minLength: 12)
            HStack(spacing: 8) { actions }
                .controlSize(.small)
                .fixedSize(horizontal: true, vertical: false)
                .padding(.top, 8)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

extension PaneHeader where Actions == EmptyView {
    init(eyebrow: String, heading: String, subtitle: String = "") {
        self.init(eyebrow: eyebrow, heading: heading, subtitle: subtitle) { EmptyView() }
    }
}

/// A titled section of a pane (a larger title and a note beside it, then the content).
struct PaneSection<Content: View>: View {
    let title: String
    var note: String = ""
    @ViewBuilder var content: Content

    init(_ title: String, note: String = "", @ViewBuilder content: () -> Content) {
        self.title = title
        self.note = note
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Text(title)
                    .font(.system(size: 16.5, weight: .semibold))
                    .foregroundStyle(Theme.text)
                if !note.isEmpty {
                    Text(note)
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.faintText)
                        .lineLimit(1)
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 2)
            content
        }
    }
}

/// A read-only fact: key left, value right, copy at the end.
struct FactRow: View {
    let key: String
    let value: String
    var help: String?
    var mono = true
    var copyable = true
    var keyWidth: CGFloat? = nil
    var tint: Color = Theme.text
    /// Lines a monospaced value may take before it is cut in the middle (default 1).
    var monoLines = 1
    /// What Copy puts on the pasteboard when it is not the whole value (the address alone).
    var copyValue: String? = nil

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 16) {
            HStack(spacing: 4) {
                Text(key)
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.text2)
                    .fixedSize(horizontal: false, vertical: true)
                if let help { HelpDot(text: help) }
            }
            .frame(width: keyWidth, alignment: .leading)
            if keyWidth == nil { Spacer(minLength: 12) }
            Text(value)
                .font(.system(size: 12, design: mono ? .monospaced : .default))
                .foregroundStyle(tint)
                .multilineTextAlignment(keyWidth == nil ? .trailing : .leading)
                .textSelection(.enabled)
                .lineLimit(mono ? monoLines : nil)
                .truncationMode(.middle)
                // Prose values wrap (a MIB enum list cut to one line reads "test…lowerLayerDown(7)").
                .fixedSize(horizontal: false, vertical: !mono || monoLines > 1)
                .help(value)
            if copyable { CopyButton(value: copyValue ?? value, help: "Copy \(copyValue ?? value)") }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct HelpDot: View {
    let text: String
    @State private var showing = false

    var body: some View {
        Button { showing = true } label: {
            Image(systemName: "questionmark.circle")
                .font(.system(size: 11.5))
                .foregroundStyle(Theme.faintText)
        }
        .buttonStyle(.plain)
        .help(text)
        .accessibilityLabel("Help")
        .accessibilityHint(text)
        .popover(isPresented: $showing, arrowEdge: .bottom) {
            Text(text)
                .font(.system(size: 12))
                .lineSpacing(3)
                .textSelection(.enabled)
                .multilineTextAlignment(.leading)
                .frame(width: 340, alignment: .leading)
                .padding(16)
        }
    }
}

struct TableEmptyOverlay: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.system(size: 12))
            .foregroundStyle(Theme.faintText)
            .multilineTextAlignment(.center)
            .frame(maxWidth: Metrics.prose)
            .padding(.horizontal, 24)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Sheets

private struct SheetCancelKey: ViewModifier {
    let action: () -> Void
    func body(content: Content) -> some View {
        content.background {
            Button("Cancel", action: action)
                .keyboardShortcut(.cancelAction)
                .opacity(0)
                .frame(width: 0, height: 0)
                .accessibilityHidden(true)
        }
    }
}

extension View {
    func sheetCancel(_ action: @escaping () -> Void) -> some View {
        modifier(SheetCancelKey(action: action))
    }
}

/// The filter box of Log, Packets and TCP flows (one look for the three): panel fill, hairline
/// (orange when the text does not parse), a clear button, Esc clears, Return applies.
struct FilterField: View {
    @Binding var text: String
    let prompt: String
    var mono = true
    var error: String?
    var help: String = ""
    var focus: FocusState<Bool>.Binding
    var onSubmit: () -> Void = {}
    var onClear: () -> Void = {}

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: "line.3.horizontal.decrease")
                .font(.system(size: 11))
                .foregroundStyle(Theme.faintText)
                .accessibilityHidden(true)
            TextField("Filter", text: $text, prompt: Text(prompt).foregroundStyle(Theme.faintText))
                .labelsHidden()
                .textFieldStyle(.plain)
                .font(.system(size: 12, design: mono ? .monospaced : .default))
                .focused(focus)
                .onSubmit(onSubmit)
                .onExitCommand { clear() }
                .accessibilityLabel("Filter")
            if !text.isEmpty {
                Button(action: clear) {
                    Image(systemName: "xmark.circle.fill").font(.system(size: 11))
                }
                .buttonStyle(.plain)
                .foregroundStyle(Theme.faintText)
                .help("Clear the filter (Esc)")
                .accessibilityLabel("Clear the filter")
            }
        }
        .padding(.horizontal, 8)
        .frame(height: 26)
        .background(RoundedRectangle(cornerRadius: 6).fill(Theme.panel))
        .overlay {
            RoundedRectangle(cornerRadius: 6)
                .strokeBorder(error == nil ? Theme.hairline : Theme.err, lineWidth: error == nil ? 0.5 : 1)
        }
        .help(error ?? help)
    }

    private func clear() {
        guard !text.isEmpty else { return }
        text = ""
        onClear()
    }
}

/// A pane's own keys while it is shown: ⌘F puts the caret in its filter / search field, ⌘⇧C
/// copies the selected line / packet / conversation. Hidden buttons carry the shortcuts, so
/// only the pane on screen answers them.
private struct PaneKeyCommands: ViewModifier {
    let find: (() -> Void)?
    let copy: (() -> Void)?

    func body(content: Content) -> some View {
        content.background {
            ZStack {
                if let find {
                    Button("Find", action: find).keyboardShortcut("f", modifiers: .command)
                }
                if let copy {
                    Button("Copy selection", action: copy).keyboardShortcut("c", modifiers: [.command, .shift])
                }
            }
            .opacity(0)
            .frame(width: 0, height: 0)
            .accessibilityHidden(true)
        }
    }
}

extension View {
    func paneKeyCommands(find: (() -> Void)? = nil, copy: (() -> Void)? = nil) -> some View {
        modifier(PaneKeyCommands(find: find, copy: copy))
    }
}

struct ErrorSheet: View {
    let message: String
    let detail: String?
    let dismiss: () -> Void
    @State private var showDetail = true

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 18))
                    .foregroundStyle(Theme.warn)
                VStack(alignment: .leading, spacing: 6) {
                    Text("Something went wrong")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(Theme.text)
                    Text(message)
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.text2)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            if let detail, !detail.isEmpty, detail != message {
                DisclosureGroup("Details", isExpanded: $showDetail) {
                    ScrollView {
                        Text(detail)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(Theme.dimText)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(8)
                    }
                    .frame(height: 180)
                    .background(RoundedRectangle(cornerRadius: Metrics.field).fill(Theme.well))
                }
                .font(.system(size: 12))
                .tint(Theme.accent)
            }
            HStack {
                if let detail, !detail.isEmpty {
                    CopyButton("Copy details", value: "\(message)\n\n\(detail)", bordered: true)
                }
                Spacer(minLength: 0)
                Button("OK", action: dismiss)
                    .buttonStyle(.borderedProminent)
                    .tint(Theme.accent)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .controlSize(.small)
        .padding(18)
        .frame(width: 520)
        // An explicit ground: the sheet's own material is drawn by the window, not the content
        // view, so a dark-mode capture would be white-on-white ("Something went wrong" invisible).
        .background(Theme.panel)
        .sheetCancel(dismiss)
    }
}

// MARK: - Small helpers

extension CommandLine {
    /// The argument after `flag`, or nil.
    nonisolated static func value(after flag: String) -> String? {
        let args = CommandLine.arguments
        guard let i = args.firstIndex(of: flag), i + 1 < args.count else { return nil }
        return args[i + 1]
    }
}

nonisolated enum Format {
    private static let decimal: NumberFormatter = {
        let f = NumberFormatter()
        f.numberStyle = .decimal
        f.locale = Locale(identifier: "en_US")
        f.usesGroupingSeparator = true
        return f
    }()

    static func count(_ n: Int) -> String {
        decimal.string(from: NSNumber(value: n)) ?? "\(n)"
    }

    static func bytes(_ n: Int) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var v = Double(n); var i = 0
        while v >= 1024, i < units.count - 1 { v /= 1024; i += 1 }
        return i == 0 ? "\(n) B" : String(format: "%.1f %@", v, units[i])
    }

    static func ms(_ seconds: Double) -> String {
        if seconds < 0.001 { return String(format: "%.0f µs", seconds * 1_000_000) }
        if seconds < 1 { return String(format: "%.1f ms", seconds * 1000) }
        return String(format: "%.2f s", seconds)
    }

    static func uptime(ticks: UInt64) -> String {
        let s = Int(ticks / 100)
        let d = s / 86400, h = (s % 86400) / 3600, m = (s % 3600) / 60, sec = s % 60
        return d > 0 ? String(format: "%dd %02d:%02d:%02d", d, h, m, sec)
                     : String(format: "%02d:%02d:%02d", h, m, sec)
    }

    /// Gregorian + POSIX locale, so a Thai-locale Mac does not print Buddhist-era years. Every
    /// date SheepLog shows or puts in a file name comes from one of these.
    static func gregorian(_ format: String) -> DateFormatter {
        let f = DateFormatter()
        f.calendar = Calendar(identifier: .gregorian)
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = format
        return f
    }

    static let clock = gregorian("HH:mm:ss.SSS")
    static let stamp = gregorian("yyyy-MM-dd HH:mm:ss.SSS")
    /// A time on another day than the one beside it: "09-23 10:17:40".
    static let dayClock = gregorian("MM-dd HH:mm:ss")
    static let day = gregorian("yyyy-MM-dd")
    static let hms = gregorian("HHmmss")
    static let compactStamp = gregorian("yyyyMMdd-HHmmss")

    /// One CSV cell (RFC 4180 quoting), safe to open in a spreadsheet.
    static func csvField(_ s: String) -> String {
        var out = ""
        appendCSV(&out, s)
        return out
    }

    /// Appends `s` as one CSV cell: quoted when it holds `,` `"` or a line break. A cell a
    /// spreadsheet would run as a formula (a device can send any message, e.g.
    /// `=HYPERLINK(…)`) — or starts with a tab or carriage return — is prefixed with an
    /// apostrophe, as OWASP recommends for CSV exports.
    static func appendCSV(_ out: inout String, _ s: String) {
        if let first = s.utf8.first, first == 0x3D || first == 0x2B || first == 0x2D || first == 0x40 || first == 0x09 || first == 0x0D {
            appendCSV(&out, "'" + s)
            return
        }
        // A byte test: a Character walk per field per row would dominate a 100k-line export.
        guard s.utf8.contains(where: { $0 == 0x2C || $0 == 0x22 || $0 == 0x0A || $0 == 0x0D }) else {
            out += s
            return
        }
        out += "\""
        out += s.utf8.contains(0x22) ? s.replacingOccurrences(of: "\"", with: "\"\"") : s
        out += "\""
    }
}



extension Calendar {
    /// Gregorian for every date arithmetic that reaches the screen or a file (a Thai-locale Mac's
    /// current calendar is Buddhist).
    nonisolated static let gregorian: Calendar = {
        var c = Calendar(identifier: .gregorian)
        c.locale = Locale(identifier: "en_US_POSIX")
        return c
    }()
}
