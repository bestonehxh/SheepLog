import SwiftUI

/// The Quiet sidebar, structured exactly like the LabDC app's: the app's name and one status
/// line up top, the pages (`Page.sidebar`: Status, Troubleshoot, Log, SNMP, Capture) as a flat
/// list of words (selected = ink and semibold, no fills, no icons, no section labels), Settings
/// at the bottom. A page's panes are tabs in its header (`PaneHeader(pane:)`). The services have no switches here —
/// they are started and stopped as word links on the Status page, the way LabDC's Services
/// page restarts its services.
struct SidebarView: View {
    @ObservedObject private var model = AppModel.shared
    @ObservedObject private var syslog = AppModel.shared.syslog
    @ObservedObject private var traps = AppModel.shared.traps
    @ObservedObject private var capture = AppModel.shared.capture
    @ObservedObject private var logs = AppModel.shared.logs
    @ObservedObject private var packets = AppModel.shared.packets
    @ObservedObject private var mibs = MIBRegistry.shared


    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            SidebarHeader(failed: failed, status: statusLine)
                .padding(.bottom, 32)
            VStack(alignment: .leading, spacing: 2) {
                ForEach(Page.sidebar, id: \.self) { page in
                    SidebarLink(title: page.title, selected: Page.of(model.mainPane) == page) {
                        // The page's own word again keeps the tab it is on.
                        if Page.of(model.mainPane) != page { model.mainPane = page.landingPane }
                    }
                }
            }
            Spacer(minLength: 24)
            SidebarLink(title: "Settings", selected: model.mainPane == .settings) {
                model.mainPane = .settings
            }
        }
        .padding(.top, 40)
        .padding(.leading, 28)
        .padding(.trailing, 16)
        .padding(.bottom, 28)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Theme.sidebar.ignoresSafeArea())
    }

    private var failed: Bool { syslog.lastError != nil || traps.lastError != nil || capture.lastError != nil }

    /// One quiet line under the app's name: what is running, or what failed.
    private var statusLine: String {
        if failed { return "Needs attention" }
        var running: [String] = []
        if syslog.isRunning { running.append("Syslog") }
        if traps.isRunning { running.append("Traps") }
        if capture.isRunning { running.append("Capture") }
        return running.isEmpty ? "Everything is off" : running.joined(separator: " · ") + " running"
    }

    /// The state of a sidebar service row (read by tests; the sidebar itself writes the state
    /// as words in the header and on the Status page).
    static func serviceLook(running: Bool, failed: Bool, detail: String) -> (detail: String, dot: Color) {
        (running ? detail : (failed ? "failed" : "off"), running ? Theme.live : (failed ? Theme.err : Theme.faintText))
    }

    /// The counts the panes lead with (read by tests).
    static func counts(logs: LogStore, packets: PacketStore, mibs: MIBRegistry) -> [MainPane: Int] {
        [.log: logs.entries.count, .sources: logs.sources.count, .mibs: mibs.modules.count, .packets: packets.packets.count]
    }
}

/// The app's name and one status line, at the top of the sidebar.
struct SidebarHeader: View {
    let failed: Bool
    let status: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("UncleSpy")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(Theme.text)
            Text(status)
                .font(Theme.detail)
                .foregroundStyle(failed ? Theme.err : Theme.text2)
                .lineLimit(1)
        }
        .accessibilityElement(children: .combine)
    }
}

/// One page in the sidebar: a word, ink and semibold when selected.
struct SidebarLink: View {
    let title: String
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.system(size: 13, weight: selected ? .semibold : .regular))
                .foregroundStyle(selected ? Theme.text : Theme.text2)
                .padding(.vertical, 6)
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? .isSelected : [])
        .accessibilityLabel(title)
    }
}
