import AppKit
import SwiftUI

/// Settings the LabDC way: the page's name with its own text tabs (Listeners · Log · Capture ·
/// SNMP · About), every setting a label above an underlined field, switches at the right edge
/// with their words on the left, notes as faint captions under their section.
struct SettingsView: View {
    @ObservedObject private var model = AppModel.shared
    // Apply ports follows the listeners' state (started / stopped on Status while this is open).
    @ObservedObject private var syslog = AppModel.shared.syslog
    @ObservedObject private var traps = AppModel.shared.traps
    @ObservedObject private var capture = AppModel.shared.capture
    @State private var interfaces: [CaptureInterface] = []
    /// The tab the page was left on (remembered across launches).
    @AppStorage("SheepLog.settingsTab") private var tab: SettingsTab = .listeners

    private var s: Binding<AppSettings> { $model.settings }

    private enum SettingsTab: String, CaseIterable {
        case listeners, log, capture, snmp, about

        var title: String {
            switch self {
            case .listeners: "Listeners"
            case .log: "Log"
            case .capture: "Capture"
            case .snmp: "SNMP"
            case .about: "About"
            }
        }
    }

    var body: some View {
        let _ = PaneProbe.ran("body.settings")
        VStack(spacing: 0) {
            PaneHeader(title: "Settings", tabs: SettingsTab.allCases.map { ($0, $0.title) }, selection: $tab,
                       status: status, detail: detail) {
                if tab == .listeners {
                    Button("Apply ports") { model.restartListeners() }
                        .buttonStyle(.quietLink)
                        .disabled(!model.listenerPortsChanged)
                        .help("Moves the running syslog and trap listeners to these ports (a port that cannot be opened leaves that listener on its old one), and retries a listener that failed to start.")
                }
            }
            .paneColumn()
            .padding(.top, Metrics.headerTop)
            .padding(.bottom, 14)

            PaneBody(spacing: 28) {
                switch tab {
                case .listeners:
                    syslogSection
                    trapSection
                case .log:
                    logMemorySection
                    diskSection
                case .capture:
                    captureSection
                    captureMemorySection
                case .snmp:
                    snmpSection
                case .about:
                    aboutSection
                }
            }
        }
        .task {
            // pcap_findalldevs walks every interface: never on the main thread.
            PaneProbe.ran("settings.interfaces")
            interfaces = await Task.detached(priority: .userInitiated) { CaptureEngine.interfaces() }.value
        }
    }

    // MARK: Header line

    /// The tab's state as words (the header's muted line).
    private var status: String {
        switch tab {
        case .listeners:
            if model.listenerPortsChanged { return "New ports not applied yet" }
            let sys = syslog.isRunning ? "Syslog on \(StatusView.syslogPorts(syslog))" : "Syslog off"
            let tr = traps.isRunning ? "traps on udp \(traps.port)" : "traps off"
            return "\(sys) · \(tr)"
        case .log:
            return "Keeping \(Format.count(model.settings.logLimit)) lines"
        case .capture:
            return capture.isRunning ? "Capturing on \(capture.interfaceName)" : "Not capturing"
        case .snmp:
            let r = model.settings.snmpRetries
            return "Timeout \(CommitNumberField.text(model.settings.snmpTimeout, integer: false)) s · \(r) \(r == 1 ? "retry" : "retries")"
        case .about:
            return "UncleSpy \(Self.version)"
        }
    }

    private var detail: String {
        switch tab {
        case .listeners: model.listenerPortsChanged ? "Apply ports moves the listeners" : ""
        case .log: model.settings.diskLogging ? "writing every line to disk" : "not writing to disk"
        case .capture: model.settings.capturePromiscuous ? "promiscuous" : ""
        case .snmp, .about: ""
        }
    }

    // MARK: Listeners

    private var syslogSection: some View {
        PaneSection("Syslog listener") {
            HStack(alignment: .top, spacing: 28) {
                QuietField("UDP port") { PortField(value: s.syslogUDPPort) }
                QuietField("TCP port (0 = off)") { PortField(value: s.syslogTCPPort) }
                    .help("RFC 6587 framing: newline-delimited or octet-counted. 0 disables TCP.")
            }
            .padding(.top, 4)
            QuietToggleRow("Start syslog at launch", isOn: s.syslogAutoStart)
            note("Port 514 binds without administrator rights on this Mac. If another tool already holds it, the Status page says “Syslog could not start” and the reason is in the error sheet.")
        }
    }

    private var trapSection: some View {
        PaneSection("SNMP trap receiver") {
            QuietField("UDP port") { PortField(value: s.trapPort) }
                .padding(.top, 4)
            QuietToggleRow("Start the trap receiver at launch", isOn: s.trapAutoStart)
            note("SNMPv1 and v2c traps and informs. Each trap appears in the Log as vendor “Trap”, with its var-binds as fields named from the loaded MIBs."
                 + (traps.isRunning && model.settings.trapPort != traps.port ? " A new port takes effect with Apply ports." : ""))
        }
    }

    // MARK: Log

    private var logMemorySection: some View {
        PaneSection("Memory") {
            QuietField("Lines kept in memory (1,000 … 2,000,000)") {
                CommitNumberField(value: intBinding(\.logLimit), clamp: { Double(AppModel.clampLogLimit(Int($0))) })
            }
            .help("Oldest lines are dropped past this (1,000 … 2,000,000). 100,000 lines is roughly 40 MB.")
            .padding(.top, 4)
            QuietToggleRow("Newest first", isOn: s.newestFirst)
            note("100,000 lines take roughly 40 MB. Past the limit the oldest lines roll out of memory (the disk log, when on, keeps every line).")
        }
    }

    private var diskSection: some View {
        PaneSection("Disk") {
            QuietToggleRow("Write to disk", note: "Every received line, raw, appended to one file per day — independent of the in-memory limit and of the filter.",
                           isOn: s.diskLogging)
            QuietField("Folder") {
                HStack(alignment: .firstTextBaseline, spacing: 20) {
                    Text(model.settings.logDirectoryURL.path(percentEncoded: false))
                        .font(Theme.mono)
                        .foregroundStyle(Theme.text)
                        .textSelection(.enabled)
                        .identifierText()
                    Spacer(minLength: 12)
                    Button("Choose…") { chooseFolder() }.buttonStyle(.quietLink)
                    Button("Reveal") { NSWorkspace.shared.activateFileViewerSelecting([model.settings.logDirectoryURL]) }
                        .buttonStyle(.quietLink)
                }
            }
            .padding(.top, 6)
        }
    }

    // MARK: Capture

    private var captureSection: some View {
        PaneSection("Live capture") {
            QuietField("Interface") {
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
                .labelsHidden()
                .pickerStyle(.menu)
                .fixedSize()
            }
            .padding(.top, 4)
            QuietToggleRow("Promiscuous", note: "Required to see mirrored (SPAN) traffic that is not addressed to this Mac.",
                           isOn: s.capturePromiscuous)
            QuietField("Capture filter (libpcap / BPF; empty captures everything)") {
                // No example inside the box: a plain field draws its placeholder nearly as dark as
                // a value (LabDC's UI audit), so an empty filter looked like "not port 22".
                TextField("Capture filter", text: s.captureFilter, prompt: Text(""))
                    .labelsHidden()
                    .textFieldStyle(.quiet)
            }
            .help("A libpcap (BPF) expression applied in the kernel, e.g. “not port 22” or “host 10.1.0.1 and tcp”. Empty captures everything.")
            if let restart = Self.captureRestartNote(settings: model.settings, running: capture.isRunning,
                                                     interface: capture.interfaceName, promiscuous: capture.runningPromiscuous,
                                                     filter: capture.runningFilter) {
                note(restart, tint: Theme.text2)
            }
            // Checked on this Mac, not assumed.
            if FileManager.default.isReadableFile(atPath: "/dev/bpf0") {
                note("Capture needs read access to /dev/bpf*. This Mac allows it (Wireshark’s ChmodBPF or similar), so no administrator prompt is needed.")
            } else {
                note("Capture needs read access to /dev/bpf*, which this Mac does not allow yet. Install Wireshark’s ChmodBPF, then start Capture again.",
                     tint: Theme.err)
            }
        }
    }

    private var captureMemorySection: some View {
        PaneSection("Memory") {
            QuietField("Packets kept in memory") {
                CommitNumberField(value: intBinding(\.packetLimit), clamp: { Double(AppModel.clampPacketLimit(Int($0))) })
            }
            .padding(.top, 4)
        }
    }

    // MARK: SNMP

    private var snmpSection: some View {
        PaneSection("SNMP test defaults") {
            HStack(alignment: .top, spacing: 28) {
                QuietField("Timeout (seconds)") {
                    CommitNumberField(value: s.snmpTimeout, clamp: SNMPTestModel.clampTimeout, integer: false)
                }
                QuietField("Retries (0 … 10)") {
                    CommitNumberField(value: intBinding(\.snmpRetries), clamp: { Double(SNMPTestModel.clampRetries(Int($0))) })
                }
            }
            .padding(.top, 4)
            note("Communities and SNMPv3 passwords typed on the Test pane are kept in the Keychain (Bestchaan.SheepLog), never in settings.json.")
        }
    }

    // MARK: About

    private var aboutSection: some View {
        // The version is the header's status line ("UncleSpy 1.9 (24)").
        PaneSection("Files") {
            GroupedList {
                ReadOnlyFieldRow(label: "Settings file", value: AppSettings.file.path(percentEncoded: false))
                ReadOnlyFieldRow(label: "MIB folder", value: MIBRegistry.shared.userFolder.path(percentEncoded: false))
            }
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

    /// A faint caption under its section (red only for what is wrong).
    private func note(_ text: String, tint: Color = Theme.faintText) -> some View {
        Text(text)
            .font(Theme.caption)
            .foregroundStyle(tint)
            .lineSpacing(2)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: 680, alignment: .leading)
            .padding(.top, 2)
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

/// A read-only fact the LabDC inspector way: the label above the value, Copy at the right edge.
private struct ReadOnlyFieldRow: View {
    let label: String
    let value: String
    var mono = true
    var copyable = true

    var body: some View {
        HStack(alignment: .lastTextBaseline, spacing: 16) {
            QuietField(label) {
                Text(value)
                    .font(mono ? Theme.mono : Theme.body)
                    .foregroundStyle(Theme.text)
                    .textSelection(.enabled)
                    .identifierText()
                    .help(value)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            if copyable { CopyButton(value: value, help: "Copy \(value)") }
        }
        .padding(.vertical, 10)
    }
}

/// The quiet field's look for the number and port boxes: the text over one line (red while the
/// text is not a value), no box, no focus ring.
private struct UnderlinedBox: ViewModifier {
    var bad = false
    var width: CGFloat = 110

    func body(content: Content) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            content
                .textFieldStyle(.plain)
                .font(.system(size: 13).monospacedDigit())
                .foregroundStyle(Theme.text)
                .focusEffectDisabled()
            Rectangle().fill(bad ? Theme.err : Theme.control).frame(height: 1)
        }
        .frame(width: width, alignment: .leading)
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
            .focused($focused)
            .modifier(UnderlinedBox())
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
            .focused($focused)
            .modifier(UnderlinedBox(bad: bad))
            .help(bad ? "A port is a number from 0 to 65535" : "")
            .onAppear { text = String(value) }
            .onChange(of: value) { _, v in if UInt16(text) != v { text = String(v) } }
            .onChange(of: text) { _, t in
                if let n = Self.port(t) { bad = false; value = n }
                else { bad = !t.isEmpty }
            }
            .onSubmit { commit() }
            .onChange(of: focused) { _, f in if !f { commit() } }
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