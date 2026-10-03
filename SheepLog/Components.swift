import AppKit
import SwiftUI
import UniformTypeIdentifiers

// MARK: - Quiet list rows (LabDC look: no cards, hairline rules, words for state)

struct GroupedList<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        _VariadicView.Tree(SeparatedRows()) { content }
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
                    Rectangle().fill(Theme.hairline).frame(height: 1)
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
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Text(title)
                    .font(Theme.emphasis)
                    .foregroundStyle(Theme.text)
                    .accessibilityAddTraits(.isHeader)
                Spacer(minLength: 12)
                if let accessory { accessory.controlSize(.small) }
            }
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
                    .font(Theme.body)
                    .foregroundStyle(Theme.text2)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(width: keyWidth, alignment: .leading)
            value
            Spacer(minLength: 0)
        }
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .help(help ?? "")
    }
}

struct NoteRow: View {
    let text: String
    var systemImage: String?
    var tint: Color = Theme.faintText

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text(text)
                .font(Theme.caption)
                .foregroundStyle(tint == Theme.faintText ? Theme.faintText : Theme.text2)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: Metrics.prose, alignment: .leading)
            Spacer(minLength: 0)
        }
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - Copying, and saying so

nonisolated enum CopyFeedback {
    static let hold: Double = 1.2
    static let word = "Copied"
    static func title(_ idle: String?, copied: Bool) -> String? {
        guard let idle else { return nil }
        return copied ? word : idle
    }
}

/// A Copy link that says "Copied" for a moment (the word, not an icon).
struct CopyButton: View {
    private let value: () -> String
    private let title: String?
    private let bordered: Bool
    @State private var copied = false
    @State private var revert: Task<Void, Never>?

    init(_ title: String? = nil, value: @autoclosure @escaping () -> String,
         bordered: Bool = false, iconSize: CGFloat? = 10, help: String = "Copy") {
        self.value = value
        self.title = title
        self.bordered = bordered
        self.help = help
    }

    private let help: String

    var body: some View {
        Button(action: copy) {
            Text(CopyFeedback.title(title ?? (bordered ? "Copy" : nil), copied: copied) ?? "Copy")
                .frame(minWidth: title == nil ? 40 : 0, alignment: .trailing)
        }
        .buttonStyle(.quietLink)
        .help(help)
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

/// State as words (no capsule, no colour but the red): "ERR", "3 warnings", "Running".
struct StatusPill: View {
    enum Kind { case ok, bad, warn, neutral, accent }
    let text: String
    var kind: Kind = .neutral

    var body: some View {
        Text(text)
            .font(Theme.detail)
            .foregroundStyle(foreground)
            .fixedSize()
            .accessibilityLabel(text)
    }

    private var foreground: Color {
        switch kind {
        case .ok, .neutral: Theme.text2
        case .bad, .warn: Theme.err
        case .accent: Theme.text
        }
    }
}

/// **One row of quiet numbers**: caption above, value under it, hairlines between cells.
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
        HStack(alignment: .top, spacing: 0) {
            ForEach(Array(cells.enumerated()), id: \.element.id) { i, c in
                VStack(alignment: .leading, spacing: 6) {
                    Text(c.value)
                        .font(Theme.metric)
                        .tracking(-0.5)
                        .foregroundStyle(c.tint)
                        .lineLimit(1)
                        .minimumScaleFactor(0.6)
                        .textSelection(.enabled)
                    Text(c.caption)
                        .font(Theme.caption)
                        .foregroundStyle(Theme.text2)
                    Text(c.detail.isEmpty ? " " : c.detail)
                        .font(Theme.caption)
                        .foregroundStyle(Theme.faintText)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                .frame(maxWidth: .infinity, alignment: .topLeading)
                .contentShape(Rectangle())
                .help(c.help.isEmpty ? "\(c.caption): \(c.value)\(c.detail.isEmpty ? "" : " — \(c.detail)")" : c.help)
                if i < cells.count - 1 {
                    Rectangle().fill(Theme.hairline).frame(width: 1).padding(.horizontal, 14).padding(.vertical, 4)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
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
    /// Quiet: no card — tables and lists sit flat on the page (the modifier stays for the call sites).
    func tablePanel(minHeight: CGFloat = 120) -> some View {
        frame(minHeight: minHeight)
    }
    func panelCard(cornerRadius: CGFloat = Metrics.card) -> some View { self }
    func groupTitle() -> some View {
        font(Theme.emphasis)
            .foregroundStyle(Theme.text)
    }
    func hint() -> some View {
        font(Theme.caption)
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
                .padding(.top, 18)
                .padding(.bottom, 24)
                .paneColumn(maxWidth: maxWidth)
        }
    }
}

/// A pane's tool row under its header (LabDC's "Search … · Include history · 2 leases  Refresh"):
/// the filter field first, switches with their words, then a `Spacer` and the counts / word
/// links at the right. No band and no rule of its own — the table's header line follows it.
struct PaneStrip<Content: View>: View {
    var maxWidth: CGFloat?
    @ViewBuilder var content: Content

    var body: some View {
        HStack(alignment: .center, spacing: 20) { content }
            .paneColumn(maxWidth: maxWidth ?? .infinity)
            .padding(.top, 2)
            .padding(.bottom, 14)
    }
}

/// A page header the LabDC way. Line 1: the **page's name** (28 pt light) and, on its baseline
/// at the right, the page's tabs — or, on a page without tabs, the actions. Line 2: the state
/// as a sentence and the facts after it, both muted (LabDC: "Running   relay-only · 2 scopes ·
/// 2 leases"; red when `problem`), and on a page with tabs the actions at the right.
struct PaneHeader<Actions: View>: View {
    private let title: String
    private let tabs: AnyView?
    var status: String = ""
    var detail: String = ""
    var problem = false
    private let actions: Actions

    /// A pane of the app: the title and the tabs are its page's (`Page.of(pane)`).
    init(pane: MainPane, status: String = "", detail: String = "", problem: Bool = false,
         @ViewBuilder actions: () -> Actions) {
        let page = Page.of(pane)
        title = page.title
        tabs = page.panes.count > 1 ? AnyView(PageTabs(page: page, current: pane)) : nil
        self.status = status
        self.detail = detail
        self.problem = problem
        self.actions = actions()
    }

    /// A page with tabs of its own (Settings): the caller holds the selection.
    init<Tab: Hashable>(title: String, tabs: [(Tab, String)], selection: Binding<Tab>, status: String = "",
                        detail: String = "", problem: Bool = false, @ViewBuilder actions: () -> Actions) {
        self.title = title
        self.tabs = AnyView(QuietTabs(items: tabs, selection: selection))
        self.status = status
        self.detail = detail
        self.problem = problem
        self.actions = actions()
    }

    private var hasActions: Bool { Actions.self != EmptyView.self }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: 24) {
                Text(title)
                    .font(Theme.pageTitle)
                    .tracking(-0.5)
                    .foregroundStyle(Theme.text)
                    .lineLimit(1)
                    .accessibilityAddTraits(.isHeader)
                Spacer(minLength: 16)
                if let tabs { tabs } else { HStack(spacing: 24) { actions } }
            }
            if !status.isEmpty || !detail.isEmpty || (tabs != nil && hasActions) {
                HStack(alignment: .firstTextBaseline, spacing: 12) {
                    if !status.isEmpty {
                        Text(status)
                            .font(Theme.body)
                            .foregroundStyle(problem ? Theme.err : Theme.text2)
                            .lineLimit(1)
                            .textSelection(.enabled)
                            .layoutPriority(1)
                    }
                    if !detail.isEmpty {
                        Text(detail)
                            .font(Theme.body)
                            .foregroundStyle(Theme.text2)
                            .lineLimit(1)
                            .truncationMode(.tail)
                            .textSelection(.enabled)
                    }
                    Spacer(minLength: 16)
                    if tabs != nil { HStack(spacing: 24) { actions } }
                }
                .padding(.top, 12)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

extension PaneHeader where Actions == EmptyView {
    init(pane: MainPane, status: String = "", detail: String = "", problem: Bool = false) {
        self.init(pane: pane, status: status, detail: detail, problem: problem) { EmptyView() }
    }
}

/// The page's panes as tabs; a click switches the pane.
private struct PageTabs: View {
    let page: Page
    let current: MainPane

    var body: some View {
        QuietTabs(items: page.panes.map { ($0, Page.tabTitle($0)) },
                  selection: Binding(get: { current }, set: { AppModel.shared.mainPane = $0 }))
    }
}

/// A titled section of a pane (a 13 pt semibold title and a note beside it, then the content).
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
                    .font(Theme.emphasis)
                    .foregroundStyle(Theme.text)
                if !note.isEmpty {
                    Text(note)
                        .font(Theme.caption)
                        .foregroundStyle(Theme.faintText)
                        .lineLimit(1)
                }
                Spacer(minLength: 0)
            }
            content
        }
    }
}

/// A read-only fact: key left, value right, Copy at the end.
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
            Text(key)
                .font(Theme.body)
                .foregroundStyle(Theme.text2)
                .fixedSize(horizontal: false, vertical: true)
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
                .help(help ?? value)
            if copyable { CopyButton(value: copyValue ?? value, help: "Copy \(copyValue ?? value)") }
        }
        .padding(.vertical, 9)
        .frame(maxWidth: .infinity, alignment: .leading)
        .help(help ?? "")
    }
}

struct TableEmptyOverlay: View {
    let text: String

    var body: some View {
        Text(text)
            .font(Theme.body)
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

/// The filter box of Log, Packets and TCP flows (one look for the three): Quiet's field is the
/// text over a single hairline — the line turns the red when the text does not parse.
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
        VStack(spacing: 0) {
            HStack(spacing: 6) {
                TextField("Filter", text: $text, prompt: Text(prompt).foregroundStyle(Theme.faintText))
                    .labelsHidden()
                    .textFieldStyle(.plain)
                    .font(.system(size: 12, design: mono ? .monospaced : .default))
                    .foregroundStyle(Theme.text)
                    .focused(focus)
                    .onSubmit(onSubmit)
                    .onExitCommand { clear() }
                    .accessibilityLabel("Filter")
                if !text.isEmpty {
                    Button(action: clear) {
                        Text("Clear")
                            .font(Theme.caption)
                    }
                    .buttonStyle(.quietLink)
                    .help("Clear the filter (Esc)")
                    .accessibilityLabel("Clear the filter")
                }
            }
            .padding(.vertical, 5)
            Rectangle()
                .fill(error == nil ? Theme.control : Theme.err)
                .frame(height: 1)
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
            VStack(alignment: .leading, spacing: 6) {
                Text("Something went wrong")
                    .font(Theme.emphasis)
                    .foregroundStyle(Theme.text)
                Text(message)
                    .font(Theme.body)
                    .foregroundStyle(Theme.text2)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let detail, !detail.isEmpty, detail != message {
                DisclosureGroup("Details", isExpanded: $showDetail) {
                    ScrollView {
                        Text(detail)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(Theme.text2)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(8)
                    }
                    .frame(height: 180)
                    .background(RoundedRectangle(cornerRadius: Metrics.field).fill(Theme.well))
                }
                .font(Theme.body)
                .tint(Theme.text)
            }
            HStack {
                if let detail, !detail.isEmpty {
                    CopyButton("Copy details", value: "\(message)\n\n\(detail)", bordered: true)
                }
                Spacer(minLength: 0)
                Button("OK", action: dismiss)
                    .buttonStyle(.quietPrimary)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .controlSize(.small)
        .padding(24)
        .frame(width: 520)
        .background(Theme.panel)
        .sheetCancel(dismiss)
    }
}

// MARK: - Quiet controls (LabDC's styles)

/// The default action: a word with a thin underline ("Pause", "Export…", "Copy").
struct QuietLinkStyle: ButtonStyle {
    var role: ButtonRole?
    var size: CGFloat = 13
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        let color = role == .destructive ? Theme.err : Theme.text
        configuration.label
            .font(.system(size: size))
            .foregroundStyle(color)
            .underline(true, color: color.opacity(0.3))
            .opacity(isEnabled ? (configuration.isPressed ? 0.55 : 1) : 0.35)
            .contentShape(Rectangle())
    }
}

/// The single strong action of a screen: ink fill, background text.
struct QuietPrimaryStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .medium))
            .foregroundStyle(Theme.content)
            .padding(.horizontal, 18)
            .padding(.vertical, 8)
            .background(Theme.text, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .opacity(isEnabled ? (configuration.isPressed ? 0.75 : 1) : 0.3)
            .contentShape(Rectangle())
    }
}

extension ButtonStyle where Self == QuietLinkStyle {
    static var quietLink: QuietLinkStyle { QuietLinkStyle() }
    static var quietDestructive: QuietLinkStyle { QuietLinkStyle(role: .destructive) }
}

extension ButtonStyle where Self == QuietPrimaryStyle {
    static var quietPrimary: QuietPrimaryStyle { QuietPrimaryStyle() }
}

/// The monochrome switch: ink when on, the control grey when off.
struct QuietToggleStyle: ToggleStyle {
    func makeBody(configuration: Configuration) -> some View {
        Button { configuration.isOn.toggle() } label: {
            HStack(spacing: 10) {
                configuration.label
                Spacer(minLength: 0)
                ZStack(alignment: configuration.isOn ? .trailing : .leading) {
                    Capsule().fill(configuration.isOn ? Theme.text : Theme.control).frame(width: 34, height: 20)
                    Circle().fill(Theme.content).frame(width: 16, height: 16).padding(2)
                }
                .animation(.easeOut(duration: 0.15), value: configuration.isOn)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityValue(configuration.isOn ? "On" : "Off")
    }
}

extension ToggleStyle where Self == QuietToggleStyle {
    static var quiet: QuietToggleStyle { QuietToggleStyle() }
}

/// A text field with only a line under it (search, wizard fields).
struct QuietFieldStyle: TextFieldStyle {
    var size: CGFloat = 13

    func _body(configuration: TextField<Self._Label>) -> some View {
        VStack(spacing: 4) {
            configuration
                .textFieldStyle(.plain)
                .font(.system(size: size))
                .foregroundStyle(Theme.text)
            Rectangle().fill(Theme.control).frame(height: 1)
        }
    }
}

extension TextFieldStyle where Self == QuietFieldStyle {
    static var quiet: QuietFieldStyle { QuietFieldStyle() }
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
    /// date UncleSpy shows or puts in a file name comes from one of these.
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
        // Byte scans with memchr: a Character walk (or `contains(where:)` and Foundation's
        // `replacingOccurrences` in a Debug build) per field per row dominated a 100k-line export.
        var text = s
        text.withUTF8 { buf in
            guard let base = buf.baseAddress, buf.count > 0 else { out += s; return }
            func has(_ byte: UInt8) -> Bool { memchr(base, Int32(byte), buf.count) != nil }
            let quote = has(0x22)
            guard quote || has(0x2C) || has(0x0A) || has(0x0D) else { out += s; return }
            out += "\""
            guard quote else { out += s; out += "\""; return }
            var start = 0
            while start < buf.count {
                guard let hit = memchr(base + start, 0x22, buf.count - start) else {
                    out += String(decoding: UnsafeBufferPointer(start: base + start, count: buf.count - start), as: UTF8.self)
                    break
                }
                let i = base.distance(to: hit.assumingMemoryBound(to: UInt8.self))
                out += String(decoding: UnsafeBufferPointer(start: base + start, count: i - start + 1), as: UTF8.self)
                out += "\""
                start = i + 1
            }
            out += "\""
        }
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

/// The selected table row: Quiet's quiet fill with a 2 pt ink edge on the left, the cells keeping
/// their own text colours.
class SoftSelectionRowView: NSTableRowView {
    override var isEmphasized: Bool {
        get { false }
        set { }
    }

    override func drawSelection(in dirtyRect: NSRect) {
        guard selectionHighlightStyle != .none, isSelected else { return }
        Theme.nsSelectedAccent.setFill()
        NSBezierPath(rect: bounds).fill()
        Theme.nsText.setFill()
        NSBezierPath(rect: NSRect(x: 0, y: 0, width: 2, height: bounds.height)).fill()
    }
}
