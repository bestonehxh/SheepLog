import AppKit
import Combine
import Foundation

enum MainPane: String, CaseIterable {
    case status, troubleshoot, log, sources, snmpTest, mibs, packets, flows, auth, settings
}

/// Persisted preferences. `~/Library/Application Support/SheepLog/settings.json`.
///
/// Decoding is lenient on purpose: a key that is missing (a file written by an older build), a
/// key this build does not know (a newer build), or a value of the wrong shape each fall back to
/// that property's default instead of throwing the whole file away.
nonisolated struct AppSettings: Codable, Equatable, Sendable {
    var syslogUDPPort: UInt16 = 514
    var syslogTCPPort: UInt16 = 514
    var trapPort: UInt16 = 162
    var syslogAutoStart = true
    var trapAutoStart = true
    var logLimit = 100_000
    var diskLogging = false
    var logDirectory: String = ""          // "" = ~/Library/Logs/SheepLog
    var newestFirst = true

    var captureInterface: String = ""       // "" = first non-loopback
    var capturePromiscuous = true
    var captureFilter: String = ""
    var packetLimit = 200_000

    var snmpTimeout: Double = 2
    var snmpRetries = 2
    /// Passwords and the community are stripped before this reaches settings.json (see `encoded`);
    /// the Keychain holds them.
    var snmpDefaults = SNMPCredentials()
    var recentTargets: [SNMPTarget] = []
    var sourceVendorOverrides: [String: Vendor] = [:]

    /// The most recent SNMP targets kept.
    static let recentTargetLimit = 20

    init() {}

    enum CodingKeys: String, CodingKey, CaseIterable {
        case syslogUDPPort, syslogTCPPort, trapPort, syslogAutoStart, trapAutoStart, logLimit,
             diskLogging, logDirectory, newestFirst, captureInterface, capturePromiscuous,
             captureFilter, packetLimit, snmpTimeout, snmpRetries, snmpDefaults, recentTargets,
             sourceVendorOverrides
    }

    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        func value<T: Decodable>(_ key: CodingKeys, _ fallback: T) -> T {
            (try? c.decodeIfPresent(T.self, forKey: key)) ?? fallback
        }
        let d = AppSettings()
        syslogUDPPort = value(.syslogUDPPort, d.syslogUDPPort)
        syslogTCPPort = value(.syslogTCPPort, d.syslogTCPPort)
        trapPort = value(.trapPort, d.trapPort)
        syslogAutoStart = value(.syslogAutoStart, d.syslogAutoStart)
        trapAutoStart = value(.trapAutoStart, d.trapAutoStart)
        logLimit = value(.logLimit, d.logLimit)
        diskLogging = value(.diskLogging, d.diskLogging)
        logDirectory = value(.logDirectory, d.logDirectory)
        newestFirst = value(.newestFirst, d.newestFirst)
        captureInterface = value(.captureInterface, d.captureInterface)
        capturePromiscuous = value(.capturePromiscuous, d.capturePromiscuous)
        captureFilter = value(.captureFilter, d.captureFilter)
        packetLimit = value(.packetLimit, d.packetLimit)
        snmpTimeout = value(.snmpTimeout, d.snmpTimeout)
        snmpRetries = value(.snmpRetries, d.snmpRetries)
        snmpDefaults = value(.snmpDefaults, d.snmpDefaults)
        // One bad element (or an unknown vendor written by a newer build) drops that element only.
        recentTargets = Array(value(.recentTargets, [Lossy<SNMPTarget>]()).compactMap(\.value)
            .prefix(Self.recentTargetLimit))
        sourceVendorOverrides = value(.sourceVendorOverrides, [String: String]()).compactMapValues(Vendor.init(rawValue:))
    }

    private struct Lossy<T: Decodable>: Decodable {
        let value: T?
        init(from decoder: any Decoder) throws { value = try? T(from: decoder) }
    }

    /// `logDirectory` with `~` expanded; a relative path (typed into settings.json) is taken
    /// from the home folder — a GUI app's working directory is `/`, where it cannot write.
    var logDirectoryURL: URL {
        if !logDirectory.isEmpty {
            let path = (logDirectory as NSString).expandingTildeInPath
            if path.hasPrefix("/") { return URL(fileURLWithPath: path) }
            return URL(fileURLWithPath: NSHomeDirectory()).appending(path: path)
        }
        return FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask)[0]
            .appending(path: "Logs/SheepLog", directoryHint: .isDirectory)
    }

    /// True inside the XCTest host: the tests must neither read nor overwrite the user's
    /// settings, nor bind 514 / 162 at launch.
    static let isRunningTests = ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil

    static var file: URL {
        // `-demoSettings <path>`: screenshots and perf runs beside an installed copy that holds
        // 514 / 162 (give the demo other ports) without touching its settings.
        if let path = CommandLine.value(after: "-demoSettings") { return URL(fileURLWithPath: path) }
        let base = isRunningTests
            ? FileManager.default.temporaryDirectory.appending(path: "SheepLogTests-\(ProcessInfo.processInfo.processIdentifier)", directoryHint: .isDirectory)
            : FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let dir = base.appending(path: "SheepLog", directoryHint: .isDirectory)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appending(path: "settings.json")
    }

    static func load(from url: URL = file) -> AppSettings {
        guard let data = try? Data(contentsOf: url) else { return AppSettings() }
        if let s = decode(data) { return s }
        // Not JSON at all: keep the file for a look, start with defaults (the next change
        // writes a fresh settings.json).
        let aside = url.deletingLastPathComponent().appending(path: "settings.corrupt.json")
        try? FileManager.default.removeItem(at: aside)
        try? FileManager.default.copyItem(at: url, to: aside)
        NSLog("SheepLog: %@ is not valid JSON; starting with default settings (copy kept as %@).",
              url.path, aside.lastPathComponent)
        return AppSettings()
    }

    static func decode(_ data: Data) -> AppSettings? {
        try? JSONDecoder().decode(AppSettings.self, from: data)
    }

    func encoded() -> Data? {
        var copy = self
        copy.snmpDefaults.authPassword = ""
        copy.snmpDefaults.privPassword = ""
        copy.snmpDefaults.community = ""
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try? enc.encode(copy)
    }

    func save(to url: URL = file) {
        if let data = encoded() { try? data.write(to: url, options: .atomic) }
    }
}

/// Process-global state: the one window's pane, the settings, and the services.
@MainActor
final class AppModel: ObservableObject {
    static let shared = AppModel()

    @Published var mainPane: MainPane = .log
    @Published var isFullScreen = false
    @Published var settings: AppSettings {
        didSet {
            guard settings != oldValue else { return }
            settings.save()
            applySettings(previous: oldValue)
        }
    }
    @Published var lastError: String?
    @Published var lastErrorDetail: String?
    /// Errors reported while the sheet was already up; shown one after another.
    private(set) var pendingErrors: [(message: String, detail: String?)] = []

    /// "Follow TCP stream" asked for this flow; the Flows pane selects it when it appears
    /// (it did not exist when the request was posted).
    var pendingFlowKey: FlowKey?
    var pendingFlowPacketID: Int?

    let logs = LogStore()
    let packets = PacketStore()
    let syslog: SyslogServer
    let traps: TrapReceiver
    let capture: CaptureEngine
    var mibs: MIBRegistry { MIBRegistry.shared }

    private var started = false
    private var observers: [NSObjectProtocol] = []
    private var captureErrorSink: AnyCancellable?
    private var fileErrorSink: AnyCancellable?
    /// Set while `startCapture` runs, which reports its own outcome.
    private var startingCapture = false

    private init() {
        settings = AppSettings.load()
        syslog = SyslogServer(store: logs)
        traps = TrapReceiver(store: logs)
        capture = CaptureEngine(store: packets)
        logs.seedVendorOverrides(settings.sourceVendorOverrides)
        applySettings(previous: nil)
        installCrossPaneObservers()
        // A capture that dies mid-run (interface gone after sleep, cable pulled) says why.
        captureErrorSink = capture.$lastError.dropFirst().sink { [weak self] error in
            guard let error else { return }
            MainActor.assumeIsolated {
                guard let self, !self.startingCapture else { return }
                self.report(error)
            }
        }
        // A capture file that could not be read to the end says so here, whichever pane is
        // shown when the load finishes (the Packets header's onChange missed it on another pane,
        // and the stale error then kept the next one from showing).
        // (After the value is stored — a @Published sink runs in willSet, so clearing it there
        // was overwritten.)
        fileErrorSink = packets.$lastError.dropFirst().receive(on: DispatchQueue.main).sink { [weak self] message in
            guard let message else { return }
            MainActor.assumeIsolated {
                guard let self else { return }
                self.report("The capture file could not be read completely.", detail: message)
                self.packets.lastError = nil
            }
        }
    }

    /// Called once from the app delegate.
    func startup() {
        guard !started else { return }
        started = true
        // Authentication sessions feed the Troubleshoot pane's findings.
        FindingRules.authProvider = { packets in AuthFindings.findings(from: packets) }
        // The Test pane's model listens for snmpTarget / snmpOID from the other panes, so it
        // must exist before the pane is first shown.
        _ = SNMPTestModel.shared
        SNMPTestModel.applyDemoArguments()
        mibs.loadAll()                  // parses on a background queue; the sidebar count follows
        guard !AppSettings.isRunningTests else { return }
        // `-demoNoServices 1`: screenshots and tests while another SheepLog holds the ports.
        guard CommandLine.value(after: "-demoNoServices") == nil else { return }
        if settings.syslogAutoStart { startSyslog() }
        if settings.trapAutoStart { startTraps() }
    }

    static let maxLogLimit = 2_000_000
    static let maxPacketLimit = 5_000_000

    /// The buffer sizes Settings accepts: 1,000 … `maxLogLimit` lines / `maxPacketLimit` packets.
    static func clampLogLimit(_ n: Int) -> Int { min(maxLogLimit, max(1_000, n)) }
    static func clampPacketLimit(_ n: Int) -> Int { min(maxPacketLimit, max(1_000, n)) }

    private func applySettings(previous old: AppSettings?) {
        // The Settings fields clamp what is typed; settings.json (hand-edited, or from another
        // build) is clamped here too — the packet ring has no byte budget, and 10^8 packets of a
        // week-long SPAN capture would take the Mac's memory.
        logs.limit = Self.clampLogLimit(settings.logLimit)
        // A @Published setter publishes even an equal value (and redraws every observer).
        if logs.newestFirst != settings.newestFirst { logs.newestFirst = settings.newestFirst }
        packets.limit = Self.clampPacketLimit(settings.packetLimit)
        if settings.diskLogging {
            if logs.diskLogger?.directory != settings.logDirectoryURL {
                // The new logger first, then the old one retired: a listener thread's batch
                // handed to the old one before the switch is queued ahead of its retirement
                // (and written). Retired first, a batch in between — for as long as the old
                // logger took to write its backlog — was thrown away.
                let old = logs.diskLogger
                logs.diskLogger = DiskLogger(directory: settings.logDirectoryURL) { message in
                    DispatchQueue.main.async {
                        MainActor.assumeIsolated {
                            AppModel.shared.report("Log lines are not being written to disk.", detail: message)
                        }
                    }
                }
                if let old { retireLogger(old) }
            }
        } else if let logger = logs.diskLogger {
            logs.diskLogger = nil
            retireLogger(logger)
        }
        // The Test pane copied these at launch; later changes in Settings follow.
        if let old, old.snmpTimeout != settings.snmpTimeout || old.snmpRetries != settings.snmpRetries {
            let m = SNMPTestModel.shared
            if old.snmpTimeout != settings.snmpTimeout { m.timeout = SNMPTestModel.clampTimeout(settings.snmpTimeout) }
            if old.snmpRetries != settings.snmpRetries { m.retries = SNMPTestModel.clampRetries(settings.snmpRetries) }
        }
    }

    // MARK: Cross-pane requests

    /// Requests other panes post (see `Notification.Name.sheepLog*`) that must not be lost when
    /// the receiving pane does not exist yet: the store-level part is done here, always.
    private func installCrossPaneObservers() {
        let nc = NotificationCenter.default
        observers.append(nc.addObserver(forName: .sheepLogPacketFilter, object: nil, queue: .main) { note in
            let filter = note.object as? String
            MainActor.assumeIsolated {
                guard let filter else { return }
                AppModel.shared.applyPacketFilter(filter)
            }
        })
        // The Mac moved to another zone (travel, automatic time zone): Foundation keeps the old
        // system zone cached until told — zone-less device timestamps are read in `TimeZone.current`
        // on the listener queues whether or not a table is on screen to reset it.
        observers.append(nc.addObserver(forName: .NSSystemTimeZoneDidChange, object: nil, queue: .main) { _ in
            NSTimeZone.resetSystemTimeZone()
        })
        observers.append(nc.addObserver(forName: .sheepLogSelectFlow, object: nil, queue: .main) { note in
            let request = note.object as? FlowSelectRequest
            let key = request?.key ?? note.object as? FlowKey
            MainActor.assumeIsolated {
                guard let key else { return }
                AppModel.shared.pendingFlowKey = key
                AppModel.shared.pendingFlowPacketID = request?.packetID
            }
        })
    }

    func applyPacketFilter(_ filter: String) {
        packets.queryText = filter
        packets.applyQueryNow()
    }

    /// The Flows pane takes the pending "Follow TCP stream" request (once), with the frame that
    /// was right-clicked, so a reused 4-tuple lands on the right conversation.
    func takePendingFlowRequest() -> FlowSelectRequest? {
        guard let key = pendingFlowKey else { return nil }
        let r = FlowSelectRequest(key: key, packetID: pendingFlowPacketID)
        pendingFlowKey = nil
        pendingFlowPacketID = nil
        return r
    }

    // MARK: Services

    func startSyslog() {
        syslog.start(udpPort: settings.syslogUDPPort, tcpPort: settings.syslogTCPPort)
        if let e = syslog.lastError {
            let why = bindFailure(e, traps: false)
            report(why.message, detail: why.detail)
        }
    }

    func stopSyslog() { syslog.stop() }

    func startTraps() {
        traps.start(port: settings.trapPort)
        if let e = traps.lastError {
            let why = bindFailure(e, traps: true)
            report(why.message, detail: why.detail)
        }
    }

    /// What to tell the user when the syslog listener (or, with `traps`, the trap receiver)
    /// could not open Settings' ports: SheepLog's own other listener on that UDP port, or the
    /// error itself with how to find the program that holds it.
    private func bindFailure(_ error: String, traps isTraps: Bool) -> (message: String, detail: String?, ownClash: Bool) {
        let clash = isTraps
            ? Self.ownPortClash(error, port: settings.trapPort, heldBy: syslog.isRunning ? syslog.udpPort : 0,
                                starting: "SNMP trap receiver", holder: "syslog listener")
            : Self.ownPortClash(error, port: settings.syslogUDPPort, heldBy: traps.isRunning ? traps.port : 0,
                                starting: "syslog listener", holder: "SNMP trap receiver")
        if let clash { return (clash.message, clash.detail, true) }
        let detail = isTraps
            ? Self.portConflictDetail(error, udp: [settings.trapPort], tcp: [])
            : Self.portConflictDetail(error, udp: [settings.syslogUDPPort], tcp: [settings.syslogTCPPort])
        return (error, detail, false)
    }

    /// `bindFailure` as the detail under "could not move to the new ports".
    private func moveFailureDetail(_ error: String, traps isTraps: Bool) -> String {
        let why = bindFailure(error, traps: isTraps)
        return why.ownClash ? "\(why.message) \(why.detail ?? "")"
                            : [why.message, why.detail].compactMap { $0 }.joined(separator: "\n\n")
    }

    /// The port is "in use" because SheepLog's other UDP listener holds it (the trap port set
    /// to the syslog port, or the other way round) — not another program, which is what
    /// `portConflictDetail` would send the user looking for with lsof.
    static func ownPortClash(_ error: String, port: UInt16, heldBy other: UInt16, starting: String,
                             holder: String) -> (message: String, detail: String)? {
        guard error.contains("EADDRINUSE"), port > 0, port == other else { return nil }
        return ("The \(starting) cannot use UDP \(port): SheepLog’s own \(holder) is listening there.",
                "Syslog and SNMP traps need different UDP ports (usually 514 and 162). Change one of them in Settings and press Apply ports.")
    }

    func stopTraps() { traps.stop() }

    /// What to run in Terminal to find the program holding a port (only for "in use").
    static func portConflictDetail(_ error: String, udp: [UInt16], tcp: [UInt16]) -> String? {
        guard error.contains("EADDRINUSE") else { return nil }
        let commands = udp.filter { $0 > 0 }.map { "sudo lsof -nP -iUDP:\($0)" }
            + tcp.filter { $0 > 0 }.map { "sudo lsof -nP -iTCP:\($0) -sTCP:LISTEN" }
        return """
            Another program is bound to the port — often a second copy of SheepLog, or another \
            syslog / SNMP tool. To see which one, run in Terminal:

            \(commands.joined(separator: "\n"))

            Quit that program and flip the switch in the sidebar again, or choose another port in \
            Settings and press Apply ports.
            """
    }

    /// A live capture replaces the packets of an open file — ask first (same wording as the pane).
    func confirmReplacingFile() -> Bool {
        guard let url = packets.fileURL, !packets.packets.isEmpty else { return true }
        let alert = NSAlert()
        alert.messageText = "Start a live capture?"
        alert.informativeText = "The \(Format.count(packets.packets.count)) packets from \(url.lastPathComponent) will be cleared from the table (the file itself is not changed)."
        alert.addButton(withTitle: "Start Capture")
        alert.addButton(withTitle: "Cancel")
        return alert.runModal() == .alertFirstButtonReturn
    }

    /// The interface to capture on: the one in Settings, or the automatic choice when that is
    /// empty or no longer on this Mac (then with a note saying so).
    static func captureInterface(wanted: String, available: [CaptureInterface]) -> (name: String, note: String?) {
        let automatic = available.first { !$0.isLoopback && $0.isUp }?.name ?? available.first?.name ?? "en0"
        if wanted.isEmpty { return (automatic, nil) }
        // An empty list means pcap_findalldevs itself failed (no /dev/bpf access): let the
        // capture report the real reason.
        if available.isEmpty || available.contains(where: { $0.name == wanted }) { return (wanted, nil) }
        return (automatic, "The capture interface “\(wanted)” chosen in Settings is not on this Mac right now "
                + "(an unplugged adapter, or a VPN that is down), so the capture runs on \(automatic) instead.")
    }

    func startCapture() {
        guard confirmReplacingFile() else { return }
        let pick = Self.captureInterface(wanted: settings.captureInterface, available: CaptureEngine.interfaces())
        startingCapture = true
        capture.start(interface: pick.name, promiscuous: settings.capturePromiscuous,
                      bpfFilter: settings.captureFilter)
        startingCapture = false
        if let e = capture.lastError { report(e) }
        else if let note = pick.note { report(note, detail: capture.warning) }
        else if let w = capture.warning { report(w) }
    }

    func stopCapture() { capture.stop() }

    /// Every listener (syslog + traps) — the Status pane's Start all. Capture is deliberate, not "all".
    /// Only what is stopped: `start` on a running listener re-binds it, which would disconnect
    /// every syslog TCP client (and lose their partial lines) when only traps were off.
    func startAll() {
        startSyslogIfStopped()
        if !traps.isRunning { startTraps() }
    }

    /// File ▸ Start Syslog Listener (⌘⇧L): a no-op while it is already listening.
    func startSyslogIfStopped() {
        if !syslog.isRunning { startSyslog() }
    }

    /// Stops the listeners and a running capture.
    func stopAll() {
        syslog.stop()
        traps.stop()
        capture.stop()
    }

    var anyRunning: Bool { syslog.isRunning || traps.isRunning || capture.isRunning }

    /// Whether Apply ports has something to do: a running listener on other ports than
    /// Settings', or one that failed to start (retried on the new ports).
    var listenerPortsChanged: Bool {
        (syslog.isRunning && (syslog.udpPort != settings.syslogUDPPort || syslog.tcpPort != settings.syslogTCPPort))
            || (traps.isRunning && traps.port != settings.trapPort)
            || (!syslog.isRunning && syslog.lastError != nil)
            || (!traps.isRunning && traps.lastError != nil)
    }

    /// Settings → Apply ports: move the running listeners to the new ports. A listener that
    /// cannot bind a new port goes back to the ports it had, so a typo never leaves it off.
    /// One that had failed to start is tried again on the new ports.
    func restartListeners() {
        if !syslog.isRunning, syslog.lastError != nil { startSyslog() }
        if !traps.isRunning, traps.lastError != nil { startTraps() }
        let moveSyslog = syslog.isRunning
            && (syslog.udpPort != settings.syslogUDPPort || syslog.tcpPort != settings.syslogTCPPort)
        let moveTraps = traps.isRunning && traps.port != settings.trapPort
        let oldUDP = syslog.udpPort, oldTCP = syslog.tcpPort, oldTrap = traps.port
        // Both moving listeners let go of their ports first: syslog may take the trap
        // receiver's old port in the same Apply (or the two trade ports), which failed as
        // "SheepLog's own trap receiver is listening there" when syslog moved first.
        if moveSyslog { syslog.stop() }
        if moveTraps { traps.stop() }
        var syslogError: String?, trapError: String?
        if moveSyslog {
            syslog.start(udpPort: settings.syslogUDPPort, tcpPort: settings.syslogTCPPort)
            if let e = syslog.lastError { syslogError = e; syslog.stop() }
        }
        if moveTraps {
            traps.start(port: settings.trapPort)
            if let e = traps.lastError { trapError = e; traps.stop() }
        }
        // A listener that could not move goes back (its old ports may have gone to the other).
        if let e = syslogError {
            syslog.start(udpPort: oldUDP, tcpPort: oldTCP)
            let old = Self.portsText(udp: oldUDP, tcp: oldTCP)
            report(syslog.isRunning ? "Syslog could not move to the new ports, so it stays on \(old)."
                                    : "Syslog could not move to the new ports, nor go back to \(old), so it is off.",
                   detail: moveFailureDetail(e, traps: false))
        }
        if let e = trapError {
            traps.start(port: oldTrap)
            report(traps.isRunning ? "The trap receiver could not move to UDP \(settings.trapPort), so it stays on UDP \(oldTrap)."
                                   : "The trap receiver could not move to UDP \(settings.trapPort), nor go back to UDP \(oldTrap), so it is off.",
                   detail: moveFailureDetail(e, traps: true))
        }
    }

    private static func portsText(udp: UInt16, tcp: UInt16) -> String {
        [udp > 0 ? "UDP \(udp)" : nil, tcp > 0 ? "TCP \(tcp)" : nil].compactMap { $0 }.joined(separator: " and ")
    }

    func rememberTarget(_ t: SNMPTarget) {
        var list = settings.recentTargets.filter { $0.host != t.host || $0.port != t.port }
        list.insert(t, at: 0)
        settings.recentTargets = Array(list.prefix(AppSettings.recentTargetLimit))
    }

    func setVendorOverride(_ vendor: Vendor?, for address: String) {
        if let vendor { settings.sourceVendorOverrides[address] = vendor }
        else { settings.sourceVendorOverrides.removeValue(forKey: address) }
        logs.setVendorOverride(vendor, for: address)
    }

    // MARK: Errors

    /// Shows the error sheet. While one is already up the error waits its turn (a duplicate of
    /// the one on screen or of a waiting one is dropped).
    func report(_ message: String, detail: String? = nil) {
        // Between two sheets (the next one is on its way) a new error waits its turn too: shown
        // at once, it jumped the queue and the waiting one went to the back.
        if lastError == nil, !nextErrorScheduled {
            lastError = message
            lastErrorDetail = detail
            return
        }
        if lastError == message && lastErrorDetail == detail { return }
        if pendingErrors.contains(where: { $0.message == message && $0.detail == detail }) { return }
        pendingErrors.append((message, detail))
    }

    /// The sheet's OK. The next waiting error comes up once this sheet has gone (presenting in
    /// the same update as the dismissal would be ignored by SwiftUI).
    func clearError() {
        guard lastError != nil else { return }      // the binding and OK both call this
        lastError = nil
        lastErrorDetail = nil
        guard !pendingErrors.isEmpty else { return }
        nextErrorScheduled = true
        let token = errorToken
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.nextErrorDelay) {
            MainActor.assumeIsolated {
                let m = AppModel.shared
                guard m.errorToken == token else { return }
                m.nextErrorScheduled = false
                guard m.lastError == nil, !m.pendingErrors.isEmpty else { return }
                let next = m.pendingErrors.removeFirst()
                m.lastError = next.message
                m.lastErrorDetail = next.detail
            }
        }
    }

    /// A dismissed sheet's successor is on its way (`clearError`).
    private var nextErrorScheduled = false

    /// Drops the error on screen and every waiting one (tests; quitting).
    func dismissAllErrors() {
        errorToken += 1
        nextErrorScheduled = false
        pendingErrors.removeAll()
        lastError = nil
        lastErrorDetail = nil
    }

    private var errorToken = 0

    static let nextErrorDelay = 0.35

    func shutdownForQuit() {
        syslog.stop()
        traps.stop()
        capture.stop()
        logs.diskLogger?.close()
        // A logger replaced moments before ⌘Q may still be writing its backlog.
        for l in retiredLoggers { l.sync() }
        retiredLoggers = []
    }

    /// Loggers retired without waiting (their backlog is still being written): ⌘Q waits for them.
    private var retiredLoggers: [DiskLogger] = []

    private func retireLogger(_ logger: DiskLogger) {
        logger.retire(wait: false)
        retiredLoggers.append(logger)
        // The last eight only: older ones finished long ago (their queued writes hold them
        // alive until done either way; only the wait at ⌘Q needs the reference).
        if retiredLoggers.count > 8 { retiredLoggers.removeFirst(retiredLoggers.count - 8) }
    }
}
