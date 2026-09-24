import AppKit
import SwiftUI

struct SettingsView: View {
    @ObservedObject private var model = AppModel.shared
    // Apply ports follows the listeners' state (switched from the sidebar while this is open).
    @ObservedObject private var syslog = AppModel.shared.syslog
    @ObservedObject private var traps = AppModel.shared.traps
    @ObservedObject private var capture = AppModel.shared.capture
    @State private var interfaces: [CaptureInterface] = []

    private var s: Binding<AppSettings> { $model.settings }

    var body: some View {
        let _ = PaneProbe.ran("body.settings")
        VStack(spacing: 0) {
            PaneHeader(eyebrow: "App", heading: "Ports, buffers and files.",
                       subtitle: "Where SheepLog listens, how much it keeps, and where it writes")
                .paneColumn()
                .padding(.top, Metrics.headerTop)
                .padding(.bottom, 12)

            PaneBody {
                syslogGroup
                trapGroup
                logGroup
                captureGroup
                snmpGroup
                aboutGroup
            }
        }
        .task {
            // pcap_findalldevs walks every interface: never on the main thread.
            PaneProbe.ran("settings.interfaces")
            interfaces = await Task.detached(priority: .userInitiated) { CaptureEngine.interfaces() }.value
        }
    }

    private var syslogGroup: some View {
        PaneGroup("Syslog listener",
                  accessory: Button("Apply ports") { model.restartListeners() }
                    .buttonStyle(.bordered)
                    .disabled(!model.listenerPortsChanged)
                    .help("Moves the running syslog and trap listeners to these ports (a port that cannot be opened leaves that listener on its old one), and retries a listener that failed to start.")) {
            KeyValueRow("UDP port") { portField(s.syslogUDPPort) }
            KeyValueRow("TCP port", help: "RFC 6587 framing: newline-delimited or octet-counted. 0 disables TCP.") { portField(s.syslogTCPPort) }
            KeyValueRow("Start at launch") { settingSwitch("Start syslog at launch", s.syslogAutoStart) }
            NoteRow(text: "Port 514 binds without administrator rights on this Mac. If another tool already holds it, the switch in the sidebar shows “failed” and the reason is in the error sheet.")
        }
    }

    private var trapGroup: some View {
        PaneGroup("SNMP trap receiver") {
            KeyValueRow("UDP port") { portField(s.trapPort) }
            KeyValueRow("Start at launch") { settingSwitch("Start the trap receiver at launch", s.trapAutoStart) }
            NoteRow(text: "SNMPv1 and v2c traps and informs. Each trap appears in the Log as vendor “Trap”, with its var-binds as fields named from the loaded MIBs."
                    + (traps.isRunning && model.settings.trapPort != traps.port ? " A new port takes effect with Apply ports (above)." : ""))
        }
    }

    private var logGroup: some View {
        PaneGroup("Log buffer and files") {
            KeyValueRow("Keep in memory", help: "Oldest lines are dropped past this (1,000 … 2,000,000). 100,000 lines is roughly 40 MB.") {
                HStack(spacing: 6) {
                    CommitNumberField(value: intBinding(\.logLimit), clamp: { Double(AppModel.clampLogLimit(Int($0))) })
                    unit("lines")
                }
            }
            KeyValueRow("Newest first") { settingSwitch("Newest first", s.newestFirst) }
            KeyValueRow("Write to disk", help: "Every received line, raw, appended to one file per day. Independent of the in-memory limit and of the filter.") {
                settingSwitch("Write to disk", s.diskLogging)
            }
            KeyValueRow("Folder") {
                HStack(spacing: 8) {
                    Text(model.settings.logDirectoryURL.path(percentEncoded: false))
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(Theme.text2)
                        .identifierText()
                        .frame(maxWidth: 420, alignment: .leading)
                    Button("Choose…") { chooseFolder() }.buttonStyle(.bordered).controlSize(.small)
                    Button("Reveal") { NSWorkspace.shared.activateFileViewerSelecting([model.settings.logDirectoryURL]) }
                        .buttonStyle(.bordered).controlSize(.small)
                }
            }
        }
    }

    private var captureGroup: some View {
        PaneGroup("Capture") {
            KeyValueRow("Interface") {
                Picker("Capture interface", selection: s.captureInterface) {
                    Text("Automatic").tag("")
                    // Chosen earlier, gone now (or the list still loading): show it rather than a blank picker.
                    if let extra = InterfacePicker.extraRow(selected: model.settings.captureInterface, among: interfaces) {
                        Text(extra).tag(model.settings.captureInterface)
                    }
                    ForEach(interfaces) { i in
                        Text(i.pickerTitle).tag(i.name)
                    }
                }
                .labelsHidden().valueControl()
            }
            KeyValueRow("Promiscuous", help: "Required to see mirrored (SPAN) traffic that is not addressed to this Mac.") {
                settingSwitch("Promiscuous", s.capturePromiscuous)
            }
            KeyValueRow("Capture filter", help: "A libpcap (BPF) expression applied in the kernel, e.g. “not port 22” or “host 10.1.0.1 and tcp”. Empty captures everything.") {
                TextField("", text: s.captureFilter).textFieldStyle(.roundedBorder).valueControl(360)
            }
            if let note = Self.captureRestartNote(settings: model.settings, running: capture.isRunning,
                                                  interface: capture.interfaceName, promiscuous: capture.runningPromiscuous,
                                                  filter: capture.runningFilter) {
                NoteRow(text: note, systemImage: "arrow.clockwise", tint: Theme.warn)
            }
            KeyValueRow("Keep in memory") {
                HStack(spacing: 6) {
                    CommitNumberField(value: intBinding(\.packetLimit), clamp: { Double(AppModel.clampPacketLimit(Int($0))) })
                    unit("packets")
                }
            }
            // Checked on this Mac, not assumed.
            if FileManager.default.isReadableFile(atPath: "/dev/bpf0") {
                NoteRow(text: "Capture needs read access to /dev/bpf*. This Mac allows it (Wireshark’s ChmodBPF or similar), so no administrator prompt is needed.")
            } else {
                NoteRow(text: "Capture needs read access to /dev/bpf*, which this Mac does not allow yet. Install Wireshark’s ChmodBPF, then start Capture again.",
                        systemImage: "exclamationmark.triangle", tint: Theme.warn)
            }
        }
    }

    private var snmpGroup: some View {
        PaneGroup("SNMP defaults") {
            KeyValueRow("Timeout") {
                HStack(spacing: 6) {
                    CommitNumberField(value: s.snmpTimeout, clamp: SNMPTestModel.clampTimeout, integer: false)
                    unit("seconds")
                }
            }
            KeyValueRow("Retries", help: "0 … 10") {
                CommitNumberField(value: intBinding(\.snmpRetries), clamp: { Double(SNMPTestModel.clampRetries(Int($0))) })
            }
            NoteRow(text: "Communities and SNMPv3 passwords typed on the Test pane are kept in the Keychain (Bestchaan.SheepLog), never in settings.json.")
        }
    }

    private var aboutGroup: some View {
        PaneGroup("About") {
            FactRow(key: "Version", value: Self.version, copyable: false)
            FactRow(key: "Settings file", value: AppSettings.file.path(percentEncoded: false))
            FactRow(key: "MIB folder", value: MIBRegistry.shared.userFolder.path(percentEncoded: false))
        }
    }

    /// While a capture runs with other settings than these: say they apply at the next Start
    /// (libpcap opens the interface, promiscuous mode and filter once).
    static func captureRestartNote(settings: AppSettings, running: Bool, interface: String,
                                   promiscuous: Bool, filter: String) -> String? {
        guard running else { return nil }
        let wanted = settings.captureInterface
        let differs = (!wanted.isEmpty && wanted != interface) || settings.capturePromiscuous != promiscuous
            || settings.captureFilter.trimmingCharacters(in: .whitespaces) != filter.trimmingCharacters(in: .whitespaces)
        guard differs else { return nil }
        let now = filter.trimmingCharacters(in: .whitespaces).isEmpty ? "no filter" : "filter “\(filter)”"
        return "The capture running now uses \(interface)\(promiscuous ? " (promiscuous)" : ""), \(now). "
            + "Interface, promiscuous and filter changes apply at the next Start."
    }

    static var version: String {
        let v = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?"
        let b = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "?"
        return "\(v) (\(b))"
    }

    private func portField(_ binding: Binding<UInt16>) -> some View {
        PortField(value: binding)
    }

    private func settingSwitch(_ title: String, _ isOn: Binding<Bool>) -> some View {
        Toggle(title, isOn: isOn).labelsHidden().toggleStyle(.switch).controlSize(.small).tint(Theme.accent)
    }

    private func unit(_ text: String) -> some View {
        Text(text).font(.system(size: 12)).foregroundStyle(Theme.faintText)
    }

    private func intBinding(_ key: WritableKeyPath<AppSettings, Int>) -> Binding<Double> {
        Binding(get: { Double(model.settings[keyPath: key]) },
                set: { model.settings[keyPath: key] = Int($0) })
    }

    private func chooseFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.directoryURL = model.settings.logDirectoryURL
        guard panel.runModal() == .OK, let url = panel.url else { return }
        model.settings.logDirectory = url.path(percentEncoded: false)
    }
}


/// A number box whose value reaches the setting on Return, on focus loss, when the pane goes
/// away and when the app quits — `TextField(value:format:)` committed on the first two only, so
/// a limit typed and followed by ⌘1…⌘8, a sidebar click or ⌘Q was lost. Not per keystroke:
/// typing 200000 over 100000 passes 2000 on the way, which would trim the buffer to 2,000 lines.
struct CommitNumberField: View {
    @Binding var value: Double
    let clamp: (Double) -> Double
    var integer = true
    @State private var text = ""
    @FocusState private var focused: Bool

    var body: some View {
        TextField("", text: $text)
            .textFieldStyle(.roundedBorder)
            .valueNumber()
            .focused($focused)
            .onAppear { text = Self.text(value, integer: integer) }
            .onChange(of: value) { _, v in if !focused { text = Self.text(v, integer: integer) } }
            .onSubmit { commit() }
            .onChange(of: focused) { _, f in if !f { commit() } }
            .onDisappear { commit() }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification)) { _ in
                PaneProbe.ran("settings.commitOnQuit")
                commit()
            }
    }

    private func commit() {
        if let n = Self.parse(text) {
            let c = clamp(integer ? n.rounded() : n)
            if c != value { value = c }
        }
        text = Self.text(value, integer: integer)
    }

    /// "100,000", "100 000", "2.5" → the number; nil for text that is not one.
    nonisolated static func parse(_ t: String) -> Double? {
        let cleaned = t.filter { !",_ \u{00A0}\u{202F}".contains($0) }
        guard !cleaned.isEmpty, let n = Double(cleaned), n.isFinite else { return nil }
        return n
    }

    nonisolated static func text(_ v: Double, integer: Bool) -> String {
        integer ? Format.count(Int(v)) : String(format: "%g", v)
    }
}

/// A port box that takes digits only, 0…65535. "5 14", "51a4" or "70000" are refused and the
/// box snaps back to the last good value when editing ends — `format: .number` parsed "5 14"
/// as 5 and quietly moved the listener.
struct PortField: View {
    @Binding var value: UInt16
    @State private var text = ""
    @State private var bad = false

    var body: some View {
        TextField("", text: $text)
            .textFieldStyle(.roundedBorder)
            .valueNumber()
            .overlay(RoundedRectangle(cornerRadius: 5).strokeBorder(bad ? Theme.err : .clear, lineWidth: 1))
            .help(bad ? "A port is a number from 0 to 65535" : "")
            .onAppear { text = String(value) }
            .onChange(of: value) { _, v in if UInt16(text) != v { text = String(v) } }
            .onChange(of: text) { _, t in
                if let n = Self.port(t) { bad = false; value = n }
                else { bad = !t.isEmpty }
            }
            .onSubmit { commit() }
            .onChange(of: focused) { _, f in if !f { commit() } }
            .focused($focused)
    }

    @FocusState private var focused: Bool

    /// What a keystroke may set: digits only, 0…65535 ("514", "0514"); nil for "5 14", "51a4",
    /// "70000", "+514", "" — the box then turns red and the port stays as it was.
    nonisolated static func port(_ t: String) -> UInt16? {
        guard let n = UInt16(t), String(n) == t || t == "0" + String(n) else { return nil }
        return n
    }

    private func commit() {
        if let n = UInt16(text.trimmingCharacters(in: .whitespaces)) { value = n }
        text = String(value)
        bad = false
    }
}