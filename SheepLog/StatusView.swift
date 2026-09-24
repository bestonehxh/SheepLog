import Combine
import SwiftUI

/// Overview (SheepRadius Status shape): the state sentence, one strip of the three services and
/// this Mac, what to type into devices, the traffic counters, and the busiest sources.
struct StatusView: View {
    @ObservedObject private var model = AppModel.shared
    @ObservedObject private var logs = AppModel.shared.logs
    @ObservedObject private var syslog = AppModel.shared.syslog
    @ObservedObject private var traps = AppModel.shared.traps
    @ObservedObject private var capture = AppModel.shared.capture
    @ObservedObject private var packets = AppModel.shared.packets
    @State private var addresses: [(interface: String, address: String)] = HostAddresses.ipv4()

    private var primary: String { addresses.first?.address ?? "this Mac" }

    var body: some View {
        VStack(spacing: 0) {
            PaneHeader(eyebrow: "Overview", heading: heading, subtitle: subtitle) {
                Button("Stop all") { model.stopAll() }
                    .buttonStyle(.bordered)
                    .disabled(!model.anyRunning)
                    .help("Stops the syslog listener, the trap receiver and a running capture.")
                Button("Start all") { model.startAll() }
                    .buttonStyle(.borderedProminent)
                    .tint(Theme.accent)
                    .disabled(syslog.isRunning && traps.isRunning)
                    .help("Starts the syslog listener and the trap receiver. Capture is not started here — use its switch in the sidebar or the Packets pane.")
            }
            .paneColumn()
            .padding(.top, Metrics.headerTop)
            .padding(.bottom, 12)

            PaneBody {
                servicesStrip
                pointDevicesSection
                trafficSection
                topTalkersSection
            }
        }
        .task {
            // Wi-Fi to another network, a VPN or a dock coming up: the address to type into the
            // devices changes while this pane is open.
            LeakProbe.add("Status.addressLoop")
            defer { LeakProbe.remove("Status.addressLoop") }
            while !Task.isCancelled {
                let fresh = HostAddresses.ipv4()
                if !HostAddresses.same(fresh, addresses) { addresses = fresh }
                try? await Task.sleep(for: .seconds(HostAddresses.cacheSeconds))
            }
        }
    }

    private var servicesStrip: some View {
        StatStrip(cells: [
            Self.serviceCell("Syslog", running: syslog.isRunning, error: syslog.lastError, detail: syslogPorts),
            Self.serviceCell("SNMP traps", running: traps.isRunning, error: traps.lastError,
                             detail: "udp \(traps.port) · \(Format.count(traps.trapCount)) received"),
            Self.serviceCell("Capture", running: capture.isRunning, error: capture.lastError, runningWord: "Capturing",
                             detail: "\(capture.interfaceName) · \(Format.count(packets.packets.count)) packets"),
            StatCell(caption: "This Mac", value: primary, mono: true,
                     detail: addresses.first.map { $0.interface } ?? "no IPv4 address"),
        ])
    }

    private var pointDevicesSection: some View {
        PaneSection("Point devices here", note: "what to type into each device’s syslog and SNMP pages") {
            GroupedList {
                // Copy gives the address alone — what a device's syslog-server field takes.
                FactRow(key: "Syslog server", value: syslogTarget, keyWidth: 190, copyValue: primary)
                FactRow(key: "SNMP trap receiver", value: "\(primary):\(trapPort)", keyWidth: 190, copyValue: primary)
                FactRow(key: "Mirror / SPAN port", value: mirrorText, copyable: false, keyWidth: 190)
                let others = addresses.dropFirst().map { "\($0.address) (\($0.interface))" }
                    + HostAddresses.ipv6Global().map { "\($0.address) (\($0.interface))" }
                if !others.isEmpty {
                    NoteRow(text: "Other addresses: " + others.joined(separator: " · "))
                }
            }
        }
    }

    private var trafficSection: some View {
        PaneSection("Traffic", note: "since launch · buffers in Settings") {
            TimelineView(.periodic(from: .now, by: 5)) { ctx in
                let problems = logs.problemCount(since: ctx.date.addingTimeInterval(-300))
                StatStrip(cells: [
                    StatCell(caption: "Lines in memory", value: Format.count(logs.entries.count),
                             detail: "of \(Format.count(logs.limit)) kept"),    // received is in the subtitle
                    StatCell(caption: "Sources", value: Format.count(logs.sources.count),
                             detail: logs.sources.count == 1 ? "device" : "devices"),
                    StatCell(caption: "Rate", value: LogView.rateText(logs.rate),
                             detail: logs.paused ? "paused" : "last 3 s",
                             help: "Syslog lines per second, averaged over the last 3 seconds"),
                    StatCell(caption: "Errors last 5 min", value: Format.count(problems),
                             tint: problems > 0 ? Theme.err : Theme.text, detail: "emerg … err",
                             help: "Lines of severity error or worse (emergency, alert, critical, error) in the last 5 minutes"),
                    StatCell(caption: "Packets", value: Format.count(packets.packets.count),
                             detail: Format.bytes(packets.totalBytes)),
                ])
            }
        }
    }

    private var topTalkersSection: some View {
        PaneSection("Top talkers", note: topNote) {
            GroupedList {
                let top = Array(logs.sources.sorted { $0.count > $1.count }.prefix(8))
                if top.isEmpty {
                    NoteRow(text: "No lines yet. Point your devices’ syslog at \(primary), udp \(syslog.isRunning ? syslog.udpPort : model.settings.syslogUDPPort), then open Log.")
                } else {
                    ForEach(top) { talkerRow($0) }
                }
            }
        }
    }

    private func talkerRow(_ s: SourceStats) -> some View {
        HStack(spacing: 10) {
            Circle().fill(Theme.vendorColor(s.vendor)).frame(width: 7, height: 7)
            Text(s.displayName).font(.system(size: 12)).foregroundStyle(Theme.text)
            Text(s.address).font(.system(size: 11, design: .monospaced)).foregroundStyle(Theme.faintText)
            Spacer(minLength: 8)
            if s.errorCount > 0 {
                StatusPill(text: "\(Format.count(s.errorCount)) err", kind: .bad)
            }
            Text(Format.count(s.count))
                .font(.system(size: 12, design: .monospaced))
                .foregroundStyle(Theme.text2)
            Button("Show") {
                logs.showSource(s.address)
                model.mainPane = .log
            }
            .buttonStyle(.bordered).controlSize(.small)
            .help("Show this source’s lines")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 7)
    }

    private var heading: String {
        if syslog.lastError != nil, !syslog.isRunning { return "Syslog could not start." }
        if !syslog.isRunning, !traps.isRunning, !capture.isRunning { return "Everything is stopped." }
        if syslog.isRunning, traps.isRunning { return capture.isRunning ? "Everything is running." : "Everything is listening." }
        if syslog.isRunning { return "Syslog is listening; traps are off." }
        return "Traps are listening; syslog is off."
    }

    private var subtitle: String {
        guard !addresses.isEmpty else { return "This Mac has no IPv4 address right now." }
        let n = logs.totalReceived
        let lines = n == 0 ? "no lines yet" : "\(Format.count(n)) line\(n == 1 ? "" : "s") received"
        return "Syslog and traps on \(primary) · \(lines)"
    }

    /// Listening (green) with `detail`, Stopped, or Failed (red) with the error.
    private static func serviceCell(_ caption: String, running: Bool, error: String?, runningWord: String = "Listening",
                                    detail: String) -> StatCell {
        StatCell(caption: caption, value: running ? runningWord : (error == nil ? "Stopped" : "Failed"),
                 tint: running ? Theme.ok : (error == nil ? Theme.text : Theme.err),
                 detail: running ? detail : (error ?? "not running"))
    }

    private var syslogPorts: String {
        var parts: [String] = []
        if syslog.udpPort > 0 { parts.append("udp \(syslog.udpPort)") }
        if syslog.tcpPort > 0 {
            let c = syslog.tcpClients
            parts.append(c > 0 ? "tcp \(syslog.tcpPort) · \(c) client\(c == 1 ? "" : "s")" : "tcp \(syslog.tcpPort)")
        }
        return parts.joined(separator: " · ")
    }

    /// The ports the listener is on while it runs (Settings may hold new ones not applied yet),
    /// else the ones it will open.
    private var syslogTarget: String {
        let s = model.settings
        let udp = syslog.isRunning ? syslog.udpPort : s.syslogUDPPort
        let tcp = syslog.isRunning ? syslog.tcpPort : s.syslogTCPPort
        return Self.syslogTarget(primary, udp: udp, tcp: tcp)
    }

    private var trapPort: UInt16 { traps.isRunning ? traps.port : model.settings.trapPort }

    static func syslogTarget(_ host: String, udp: UInt16, tcp: UInt16) -> String {
        if udp == tcp, udp > 0 { return "\(host):\(udp)  (udp or tcp)" }
        var parts: [String] = []
        if udp > 0 { parts.append("udp \(host):\(udp)") }
        if tcp > 0 { parts.append("tcp \(host):\(tcp)") }
        return parts.isEmpty ? "no syslog port is open" : parts.joined(separator: "  ·  ")
    }

    private var mirrorText: String {
        let iface = model.settings.captureInterface.isEmpty ? (addresses.first?.interface ?? "en0") : model.settings.captureInterface
        return model.settings.capturePromiscuous
            ? "plug the SPAN port into \(iface), then start Capture"
            : "plug the SPAN port into \(iface), turn Promiscuous on, then start Capture"
    }

    private var topNote: String {
        logs.sources.isEmpty ? "" : "\(Format.count(logs.sources.count)) source\(logs.sources.count == 1 ? "" : "s") · Sources has them all"
    }
}
