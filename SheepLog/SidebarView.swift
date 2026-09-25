import SwiftUI

/// SERVICES with their switches, then the panes in four groups — no icons, the word is the row.
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
            HStack { Spacer() }
                .frame(height: model.isFullScreen ? Metrics.titleBarFullScreen : Metrics.titleBar)

            VStack(alignment: .leading, spacing: 0) {
                    sectionHeader("Services", top: 2)
                    service("Syslog", failed: syslog.lastError != nil, detail: syslog.portsText,
                            isOn: Binding(get: { syslog.isRunning }, set: { $0 ? model.startSyslog() : model.stopSyslog() }))
                    service("SNMP traps", failed: traps.lastError != nil, detail: "udp \(traps.port)",
                            isOn: Binding(get: { traps.isRunning }, set: { $0 ? model.startTraps() : model.stopTraps() }))
                    service("Capture", failed: capture.lastError != nil, detail: captureDetail,
                            isOn: Binding(get: { capture.isRunning }, set: { $0 ? model.startCapture() : model.stopCapture() }))

                    sectionHeader("Overview")
                    group {
                        row(.status, "Status")
                        row(.troubleshoot, "Troubleshoot")
                    }

                    sectionHeader("Syslog")
                    group {
                        row(.log, "Log", count: count(.log))
                        row(.sources, "Sources", count: count(.sources))
                    }

                    sectionHeader("SNMP")
                    group {
                        row(.snmpTest, "Test")
                        row(.mibs, "MIBs", count: count(.mibs))
                    }

                    sectionHeader("Capture")
                    group {
                        row(.packets, "Packets", count: count(.packets))
                        row(.flows, "TCP flows")
                        row(.auth, "Authentication")
                    }

                    sectionHeader("App")
                    group { row(.settings, "Settings") }
                }
                .padding(.bottom, 12)
        }
        .frame(maxHeight: .infinity, alignment: .top)
    }

    private func count(_ pane: MainPane) -> Int? { Self.counts(logs: logs, packets: packets, mibs: mibs)[pane] }

    private var captureDetail: String {
        capture.interfaceName + (capture.runningPromiscuous ? " · promisc" : "")
    }

    /// A service's switch (`isOn` = running): green dot and `detail` while running, "off" or a
    /// red "failed" when not.
    private func service(_ name: String, failed: Bool, detail: String, isOn: Binding<Bool>) -> some View {
        let look = Self.serviceLook(running: isOn.wrappedValue, failed: failed, detail: detail)
        return SidebarServiceRow(name: name, detail: look.detail, dot: look.dot, isOn: isOn)
    }

    /// Green dot and what it is doing while running; "off", or a red "failed" when it could not
    /// start.
    static func serviceLook(running: Bool, failed: Bool, detail: String) -> (detail: String, dot: Color) {
        (running ? detail : (failed ? "failed" : "off"), running ? Theme.live : (failed ? Theme.err : Theme.faintText))
    }

    /// The counts beside the panes' rows (the same numbers the panes lead with).
    static func counts(logs: LogStore, packets: PacketStore, mibs: MIBRegistry) -> [MainPane: Int] {
        [.log: logs.entries.count, .sources: logs.sources.count, .mibs: mibs.modules.count, .packets: packets.packets.count]
    }

    private func group(@ViewBuilder _ content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 1) { content() }
            .padding(.horizontal, 8)
    }

    private func row(_ pane: MainPane, _ title: String, count: Int? = nil) -> some View {
        SidebarRow(title: title, isSelected: model.mainPane == pane, count: count) {
            model.mainPane = pane
        }
    }

    private func sectionHeader(_ name: String, top: CGFloat = 14) -> some View {
        Text(name.uppercased())
            .font(.system(size: 10.5, weight: .semibold))
            .kerning(0.4)
            .foregroundStyle(Theme.faintText)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 18)
            .padding(.top, top)
            .padding(.bottom, 4)
    }
}

/// Name and switch on one line, what it is doing under it.
struct SidebarServiceRow: View {
    let name: String
    let detail: String
    let dot: Color
    @Binding var isOn: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            HStack(spacing: 8) {
                Circle().fill(dot).frame(width: 7, height: 7)
                Text(name)
                    .font(.system(size: 13, weight: isOn ? .medium : .regular))
                    .foregroundStyle(Theme.text)
                Spacer(minLength: 0)
                Toggle(name, isOn: $isOn)
                    .toggleStyle(.switch)
                    .controlSize(.mini)
                    .labelsHidden()
                    .tint(Theme.accent)
            }
            Text(detail)
                .font(.system(size: 10.5, design: .monospaced))
                .foregroundStyle(isOn ? Theme.ok : Theme.faintText)
                .lineLimit(1)
                .truncationMode(.middle)
                .padding(.leading, 15)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 5)
    }
}

struct SidebarRow: View {
    let title: String
    var isSelected = false
    var count: Int?
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        HStack(spacing: 9) {
            Text(title)
                .font(.system(size: 13, weight: isSelected ? .medium : .regular))
                .foregroundStyle(isSelected ? Theme.text : Theme.text2)
            Spacer(minLength: 0)
            if let count {
                Text(Format.count(count))
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Theme.faintText)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background(
            RoundedRectangle(cornerRadius: 7)
                .fill(isSelected ? Theme.selectedAccent : hovering ? Theme.hover : .clear)
        )
        .contentShape(Rectangle())
        .onTapGesture(perform: action)
        .onHover { hovering = $0 }
        // VoiceOver: one button per pane ("Log, 498"), selected state included.
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(isSelected ? [.isButton, .isSelected] : .isButton)
        .accessibilityAction { action() }
    }
}
