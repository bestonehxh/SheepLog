import SwiftUI

/// The sidebar's pages — LabDC's structure: a few words in the sidebar, and a page with more
/// than one pane shows them as text tabs on its title's baseline (LabDC's DHCP page: "Scopes
/// Reservations  Leases …"). `MainPane` stays the unit everything else speaks (`-demoPane`,
/// ⌘1 … ⌘0, the cross-pane requests, the tests); a page is only how the panes are grouped.
enum Page: String, CaseIterable {
    case status, troubleshoot, log, snmp, capture, settings

    /// The sidebar's list; Settings sits apart at the bottom.
    static let sidebar: [Page] = [.status, .troubleshoot, .log, .snmp, .capture]

    /// The sidebar word and the page's 28 pt title.
    var title: String {
        switch self {
        case .status: "Status"
        case .troubleshoot: "Troubleshoot"
        case .log: "Log"
        case .snmp: "SNMP"
        case .capture: "Capture"
        case .settings: "Settings"
        }
    }

    /// The page's panes, in tab order.
    var panes: [MainPane] {
        switch self {
        case .status: [.status]
        case .troubleshoot: [.troubleshoot]
        case .log: [.log, .sources]
        case .snmp: [.snmpTest, .mibs]
        case .capture: [.packets, .flows, .auth]
        case .settings: [.settings]
        }
    }

    static func of(_ pane: MainPane) -> Page {
        switch pane {
        case .status: .status
        case .troubleshoot: .troubleshoot
        case .log, .sources: .log
        case .snmpTest, .mibs: .snmp
        case .packets, .flows, .auth: .capture
        case .settings: .settings
        }
    }

    /// A pane's word in its page's tabs.
    static func tabTitle(_ pane: MainPane) -> String {
        switch pane {
        case .status: "Status"
        case .troubleshoot: "Troubleshoot"
        case .log: "Lines"
        case .sources: "Sources"
        case .snmpTest: "Test"
        case .mibs: "MIBs"
        case .packets: "Packets"
        case .flows: "TCP flows"
        case .auth: "Authentication"
        case .settings: "Settings"
        }
    }

    /// The pane a sidebar click opens: the one this page showed last, else its first.
    var landingPane: MainPane { Page.lastShown[self] ?? panes[0] }

    private static var lastShown: [Page: MainPane] = [:]

    /// Called on every pane switch (ContentView), so a page reopens on the tab it was left on.
    static func remember(_ pane: MainPane) { lastShown[Page.of(pane)] = pane }
}

/// A row of text tabs ("Packets  TCP flows  Authentication"): the selected one in ink and
/// semibold, the others muted. Also the Quiet replacement for a segmented picker ("v1  v2c
/// v3", "Relative  Time of day") — pass a smaller `spacing` / `size` there.
struct QuietTabs<Value: Hashable>: View {
    let items: [(Value, String)]
    @Binding var selection: Value
    var spacing: CGFloat = 22
    var size: CGFloat = 13

    var body: some View {
        HStack(spacing: spacing) {
            ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                Button { selection = item.0 } label: {
                    Text(item.1)
                        .font(.system(size: size, weight: item.0 == selection ? .semibold : .regular))
                        .foregroundStyle(item.0 == selection ? Theme.text : Theme.text2)
                        .fixedSize()
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(item.0 == selection ? .isSelected : [])
            }
        }
    }
}

/// A form field the LabDC way: the label above (11 pt, muted), the control under it, an
/// optional faint note under that. Text fields inside take `.textFieldStyle(.quiet)` (a line
/// under the text, no box). Several short fields sit side by side in an `HStack(spacing: 28)`.
struct QuietField<Control: View>: View {
    let label: String
    var note: String?
    var width: CGFloat?
    @ViewBuilder var control: Control

    init(_ label: String, note: String? = nil, width: CGFloat? = nil, @ViewBuilder control: () -> Control) {
        self.label = label
        self.note = note
        self.width = width
        self.control = control()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(label)
                .font(Theme.caption)
                .foregroundStyle(Theme.text2)
                .fixedSize(horizontal: false, vertical: true)
            control
            if let note {
                Text(note)
                    .font(Theme.caption)
                    .foregroundStyle(Theme.faintText)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(width: width, alignment: .leading)
    }
}

/// An on/off line of a form: the words on the left in ink, the quiet switch at the right edge
/// (LabDC's Settings rows), an optional faint note under the words.
struct QuietToggleRow: View {
    let title: String
    var note: String?
    @Binding var isOn: Bool

    init(_ title: String, note: String? = nil, isOn: Binding<Bool>) {
        self.title = title
        self.note = note
        _isOn = isOn
    }

    var body: some View {
        Toggle(isOn: $isOn) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(Theme.body).foregroundStyle(Theme.text)
                if let note {
                    Text(note).font(Theme.caption).foregroundStyle(Theme.faintText)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .toggleStyle(.quiet)
        .padding(.vertical, 6)
        .frame(maxWidth: .infinity)
    }
}

/// A switch with its words for a tool row ("Newest first [·]"): its own width, never greedy.
struct QuietToolToggle: View {
    let title: String
    @Binding var isOn: Bool
    var help: String = ""

    init(_ title: String, isOn: Binding<Bool>, help: String = "") {
        self.title = title
        _isOn = isOn
        self.help = help
    }

    var body: some View {
        Toggle(isOn: $isOn) {
            Text(title).font(Theme.body).foregroundStyle(Theme.text).fixedSize()
        }
        .toggleStyle(.quiet)
        .fixedSize()
        .help(help)
    }
}

/// One list row the LabDC way (its Leases rows): a title line and a muted detail line on the
/// left, the state as a word at the right edge. Put these in a `GroupedList` for the hairlines.
struct QuietListRow<Trailing: View>: View {
    let title: String
    var detail: String = ""
    var mono = false
    @ViewBuilder var trailing: Trailing

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 16) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(mono ? Theme.mono : Theme.body)
                    .foregroundStyle(Theme.text)
                    .fixedSize(horizontal: false, vertical: true)
                if !detail.isEmpty {
                    Text(detail)
                        .font(Theme.detail)
                        .foregroundStyle(Theme.text2)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 12)
            trailing
        }
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
