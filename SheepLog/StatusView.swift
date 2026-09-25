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

    /// One service as the pane reads it.
    struct Service: Equatable {
        var running: Bool
        var error: String?
        /// Not running because it could not start (the sidebar's "failed").
        var failed: Bool { !running && error != nil }
    }

    var body: some View {
        let _ = PaneProbe.ran("body.status")
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
                PaneProbe.ran("status.addressLoop")
                let fresh = HostAddresses.ipv4()
                if !HostAddresses.same(fresh, addresses) { addresses = fresh }
                try? await Task.sleep(for: .seconds(HostAddresses.cacheSeconds))
            }
        }
    }

    private var servicesStrip: some View {
        StatStrip(cells: [
            Self.serviceCell("Syslog", running: syslog.isRunning, error: syslog.lastError, detail: Self.syslogPorts(syslog)),
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
                ForEach(Self.pointRows(address: addresses.first?.address, udp: syslogUDP, tcp: syslogTCP, trapPort: trapPort,
                                       mirror: mirrorText), id: \.key) { r in
                    FactRow(key: r.key, value: r.value, copyable: r.copy != nil, keyWidth: 190, copyValue: r.copy)
                }
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
                    Self.packetsCell(inMemory: packets.packets.count, received: packets.totalReceived, bytes: packets.totalBytes),
                ])
            }
        }
    }

    private var topTalkersSection: some View {
        PaneSection("Top talkers", note: topNote) {
            GroupedList {
                let top = Array(logs.sources.sorted { $0.count > $1.count }.prefix(8))
                if top.isEmpty {
                    NoteRow(text: Self.noLinesNote(address: addresses.first?.address, udp: syslogUDP, tcp: syslogTCP))
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
        Self.heading(syslog: Service(running: syslog.isRunning, error: syslog.lastError),
                     traps: Service(running: traps.isRunning, error: traps.lastError),
                     capture: Service(running: capture.isRunning, error: capture.lastError))
    }

    /// The state sentence. A capture running alone read "Traps are listening; syslog is off."
    /// (the last case caught everything else), and a trap receiver that could not start was
    /// "off" — or, with syslog stopped too, "Everything is stopped." over a red Failed cell.
    static func heading(syslog: Service, traps: Service, capture: Service) -> String {
        if syslog.failed { return traps.failed ? "Syslog and the trap receiver could not start." : "Syslog could not start." }
        if traps.failed { return syslog.running ? "Syslog is listening; the trap receiver could not start." : "The trap receiver could not start." }
        switch (syslog.running, traps.running) {
        case (true, true): return capture.running ? "Everything is running." : "Everything is listening."
        case (true, false): return "Syslog is listening; traps are off."
        case (false, true): return "Traps are listening; syslog is off."
        case (false, false): return capture.running ? "Capturing; syslog and traps are off." : "Everything is stopped."
        }
    }

    /// "Packets": the ones in memory; the bytes are of every packet received, so once the ring
    /// rolled packets out they are said to be (200,000 packets beside 3.2 GB read as the size
    /// of those 200,000).
    static func packetsCell(inMemory: Int, received: Int, bytes: Int) -> StatCell {
        StatCell(caption: "Packets", value: Format.count(inMemory),
                 detail: received > inMemory ? "\(Format.bytes(bytes)) in \(Format.count(received)) received" : Format.bytes(bytes))
    }

    /// Top talkers with no line yet: where to point the devices — the port that is open (a
    /// TCP-only listener said "udp 0").
    static func noLinesNote(address: String?, udp: UInt16, tcp: UInt16) -> String {
        let host = address ?? "this Mac"
        let port = udp > 0 ? "udp \(udp)" : tcp > 0 ? "tcp \(tcp)" : nil
        guard let port else { return "No lines yet, and no syslog port is set: choose one in Settings." }
        return "No lines yet. Point your devices’ syslog at \(host), \(port), then open Log."
    }

    /// A row of "Point devices here": what it shows and what Copy puts on the pasteboard (nil:
    /// no Copy button).
    struct PointRow: Equatable {
        let key: String
        let value: String
        let copy: String?
    }

    /// Copy gives the address alone (what a device's syslog-server / trap-receiver field takes).
    /// With no IPv4 address there is nothing to type into a device: the rows say so and have no
    /// Copy (it copied the words "this Mac").
    static func pointRows(address: String?, udp: UInt16, tcp: UInt16, trapPort: UInt16, mirror: String) -> [PointRow] {
        let host = address ?? "this Mac"
        let syslogValue = syslogTarget(host, udp: udp, tcp: tcp)
        let anySyslog = udp > 0 || tcp > 0
        return [
            PointRow(key: "Syslog server", value: address == nil && anySyslog ? syslogValue + " — no IPv4 address" : syslogValue,
                     copy: anySyslog ? address : nil),
            PointRow(key: "SNMP trap receiver",
                     value: trapPort == 0 ? "no trap port is set" : address == nil ? "udp \(trapPort) — no IPv4 address" : "\(host):\(trapPort)",
                     copy: trapPort == 0 ? nil : address),
            PointRow(key: "Mirror / SPAN port", value: mirror, copy: nil),
        ]
    }

    private var subtitle: String {
        guard !addresses.isEmpty else { return "This Mac has no IPv4 address right now." }
        let n = logs.totalReceived
        let lines = n == 0 ? "no lines yet" : "\(Format.count(n)) line\(n == 1 ? "" : "s") received"
        return "Syslog and traps on \(primary) · \(lines)"
    }

    /// Listening (green) with `detail`, Stopped, or Failed (red) with the error. Running with
    /// an error (syslog's TCP port taken while UDP opened, the TCP client limit) is amber with
    /// the error after the detail — it was a plain green "Listening" and the failure was only
    /// in a sheet that had been dismissed.
    static func serviceCell(_ caption: String, running: Bool, error: String?, runningWord: String = "Listening",
                            detail: String) -> StatCell {
        let partly = running && error != nil
        return StatCell(caption: caption, value: running ? runningWord : (error == nil ? "Stopped" : "Failed"),
                        tint: partly ? Theme.warn : running ? Theme.ok : (error == nil ? Theme.text : Theme.err),
                        detail: running ? (partly ? [detail, error!].filter { !$0.isEmpty }.joined(separator: " · ") : detail) : (error ?? "not running"),
                        help: error ?? "")
    }

    static func syslogPorts(_ syslog: SyslogServer) -> String {
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
    private var syslogUDP: UInt16 { syslog.isRunning ? syslog.udpPort : model.settings.syslogUDPPort }
    private var syslogTCP: UInt16 { syslog.isRunning ? syslog.tcpPort : model.settings.syslogTCPPort }

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
