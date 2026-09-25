import AppKit
import Combine
import SwiftUI
import UniformTypeIdentifiers

// MARK: - Model

/// Runs the findings rules over what the stores hold: off the main actor, at most once every
/// 2 s while lines and packets keep arriving, and only while the pane is on screen (the last
/// result is kept for the next visit). Also keeps the SNMP Test pane's results as they come in,
/// so a second walk of the same device shows what grew.
@MainActor
final class TroubleshootModel: ObservableObject {
    static let shared = TroubleshootModel()

    @Published private(set) var result: TroubleshootResult?
    @Published private(set) var analysing = false
    @Published private(set) var analysedAt: Date?
    /// The client report on screen (a sheet).
    @Published var report: ClientReport?
    @Published private(set) var buildingReport = false
    /// Said instead of opening an empty pane: the evidence of a finding has rolled out of memory.
    @Published var jumpNotice: String?

    private(set) var snmpHistory: [SNMPSnapshot] = []
    private var storeSinks: [AnyCancellable] = []
    private var snmpSink: AnyCancellable?
    private var scheduled: Task<Void, Never>?
    private var running: Task<Void, Never>?
    private var reportTask: Task<Void, Never>?
    private var rerun = false
    private var token = 0
    private(set) var visible = false
    /// The analysis clock (tests; nil = now).
    var nowOverride: Date?

    static let debounce: Double = 2
    static let snmpHistoryLimit = 20

    private init() {
        snmpSink = SNMPTestModel.shared.$running.removeDuplicates().dropFirst().sink { [weak self] running in
            guard running == nil else { return }
            // `$running` publishes before the value is stored: read the results on the next turn.
            DispatchQueue.main.async {
                MainActor.assumeIsolated { self?.recordSNMP() }
            }
        }
    }

    // MARK: Appearing

    func appeared() {
        PaneProbe.ran("troubleshoot.appeared")
        // `-demoPane troubleshoot -demoPcap <file>`: the Packets pane (which opens it) never appeared.
        if AppModel.shared.packets.fileURL == nil, AppModel.shared.packets.packets.isEmpty, DemoFlags.openPcap() {
            AppModel.shared.mainPane = .troubleshoot
        }
        visible = true
        let logs = AppModel.shared.logs, packets = AppModel.shared.packets
        let poke: (Any) -> Void = { [weak self] _ in MainActor.assumeIsolated { self?.scheduleAnalysis() } }
        storeSinks = [
            logs.$totalReceived.removeDuplicates().dropFirst().sink(receiveValue: poke),
            logs.$generation.removeDuplicates().dropFirst().sink(receiveValue: poke),
            packets.$generation.removeDuplicates().dropFirst().sink(receiveValue: poke),
            packets.$totalReceived.removeDuplicates().dropFirst().sink(receiveValue: poke),
        ]
        start()
    }

    /// Leaving the pane stops the work (not just its result).
    func disappeared() {
        PaneProbe.ran("troubleshoot.disappeared")
        visible = false
        storeSinks.removeAll()
        scheduled?.cancel(); scheduled = nil
        running?.cancel(); running = nil
        reportTask?.cancel(); reportTask = nil
        buildingReport = false
        // Its sheet went with the pane: it must not come back over the next visit (its packets
        // may be another capture's by then).
        report = nil
        rerun = false
        analysing = false
    }

    // MARK: Analysis

    func scheduleAnalysis() {
        guard visible, scheduled == nil else { return }
        scheduled = Task {
            LeakProbe.add("Troubleshoot.scheduled")
            defer { LeakProbe.remove("Troubleshoot.scheduled") }
            try? await Task.sleep(for: .seconds(Self.debounce))
            guard !Task.isCancelled else { return }
            scheduled = nil
            start()
        }
    }

    /// One analysis at a time; changes meanwhile collapse into one more run after it.
    func start() {
        if running != nil { rerun = true; return }
        running = Task {
            await analyse()
            guard !Task.isCancelled else { return }
            running = nil
            if rerun { rerun = false; scheduleAnalysis() }
        }
    }

    /// What the stores hold now, as the rules' input (the arrays are shared, not copied).
    func currentInput() -> TroubleshootInput {
        let app = AppModel.shared
        if snmpHistory.isEmpty { recordSNMP() }
        var input = TroubleshootInput()
        input.entries = app.logs.entries
        // A paused Log pane holds new lines back from its table, not from the checks: while the
        // user read the Log, a port flapping now was invisible here until Resume.
        if app.logs.paused { input.held = app.logs.heldEntries }
        input.packets = app.packets.packets
        input.packetEpoch = app.packets.epoch
        input.snmp = snmpHistory
        input.counters = EngineCounters(logCount: app.logs.entries.count, logLimit: app.logs.limit,
                                        logDropped: app.logs.dropped, logLost: app.logs.lost,
                                        packetCount: app.packets.packets.count, packetLimit: app.packets.limit,
                                        packetDropped: app.packets.dropped, packetLost: app.packets.lost)
        input.now = nowOverride ?? Date()
        return input
    }

    private func analyse() async {
        LeakProbe.add("Troubleshoot.analysis")
        defer { LeakProbe.remove("Troubleshoot.analysis") }
        token += 1
        let mine = token
        analysing = true
        PaneProbe.troubleshootAnalysisStarted()
        let started = Monotonic.now()
        let input = currentInput()
        let auth = FindingRules.authProvider
        mainThreadCost(Monotonic.now() - started)
        let work = Task.detached(priority: .userInitiated) { () -> TroubleshootResult in
            var input = input
            input.takeHeld()
            input.flows = TCPFlowAnalyzer.analyze(input.packets) { Task.isCancelled }
            if Task.isCancelled { return TroubleshootResult() }
            input.extra = auth?(input.packets) ?? []
            if Task.isCancelled { return TroubleshootResult() }
            return FindingRules.analyze(input) { Task.isCancelled }
        }
        let result = await withTaskCancellationHandler { await work.value } onCancel: { work.cancel() }
        guard mine == token, !Task.isCancelled else { return }
        let applied = Monotonic.now()
        self.result = result
        jumpNotice = nil
        analysing = false
        analysedAt = Date()
        mainThreadCost(Monotonic.now() - applied)
    }

    /// The longest stretch one analysis held the main actor (reading the stores, publishing the
    /// result), for tests.
    private(set) var longestMainThreadCost: Double = 0
    private func mainThreadCost(_ s: Double) { longestMainThreadCost = max(longestMainThreadCost, s) }
    func resetMainThreadCost() { longestMainThreadCost = 0 }

    /// An evidence button: the pane on it — or, when what it points at has rolled out of
    /// memory since the analysis, a note here instead of an empty (or another) pane.
    func show(_ e: Evidence) {
        switch TroubleshootJump.show(e, epoch: result?.packetEpoch) {
        case .gone(let text): jumpNotice = text
        default: jumpNotice = nil
        }
    }

    // MARK: SNMP results

    /// Keeps the Test pane's current results (a new walk, or the first look at this pane).
    func recordSNMP() {
        let m = SNMPTestModel.shared
        guard let snap = Self.snapshot(of: m.lastFinished, rows: m.rows, interfaces: m.interfaces, taken: Date()) else { return }
        add(snap)
    }

    /// The Test pane's results as one device's snapshot — under the host the run asked (the form
    /// may name another by now), only when it succeeded (a failed run leaves the previous run's
    /// rows on screen), with the ports only when the run was the Interfaces walk (they stay on
    /// screen through later runs: a Quick test of another switch was recorded with the first
    /// one's ports, and a GET of the same one compared its walk with itself).
    nonisolated static func snapshot(of run: SNMPTestModel.FinishedRun?, rows: [VarBindRow],
                                     interfaces: [InterfaceRow], taken: Date) -> SNMPSnapshot? {
        guard let run, run.succeeded else { return nil }
        let ports = run.label == "Interfaces" ? interfaces : []
        guard !rows.isEmpty || !ports.isEmpty else { return nil }
        return snapshot(host: run.host.trimmingCharacters(in: .whitespaces), rows: rows, interfaces: ports, taken: taken)
    }

    func add(_ snap: SNMPSnapshot) {
        if let last = snmpHistory.last, last.host == snap.host, last.values == snap.values,
           last.interfaces.map(\.totalErrors) == snap.interfaces.map(\.totalErrors) { return }
        snmpHistory.append(snap)
        if snmpHistory.count > Self.snmpHistoryLimit { snmpHistory.removeFirst(snmpHistory.count - Self.snmpHistoryLimit) }
        if visible { scheduleAnalysis() }
    }

    nonisolated static func snapshot(host: String, rows: [VarBindRow], interfaces: [InterfaceRow], taken: Date) -> SNMPSnapshot {
        var values: [OID: String] = [:]
        for r in rows where values[r.oid] == nil { values[r.oid] = r.value }
        var up: UInt32?
        if let v = values[.sysUpTime] {
            // "00:02:03 (12345)" — the ticks are in the parentheses.
            if let open = v.lastIndex(of: "("), let n = UInt32(v[v.index(after: open)...].prefix { $0.isNumber }) { up = n }
            else { up = UInt32(v.prefix { $0.isNumber }) }
        } else if let r = interfaces.first(where: { $0.sinceChange != nil }), let since = r.sinceChange {
            up = since &+ r.lastChange
        }
        return SNMPSnapshot(host: host.isEmpty ? "SNMP agent" : host, taken: taken, sysName: values[.sysName],
                            sysUpTime: up, interfaces: interfaces, values: values)
    }

    // MARK: Client report

    func buildReport(_ text: String) {
        reportTask?.cancel()
        var prepared = currentInput()
        // The last analysis's conversations only when they are this capture's: after a Clear
        // they were the old capture's (frame numbers and all), listed beside the new packets.
        let flowsCurrent = result.map { $0.packetEpoch == prepared.packetEpoch } ?? false
        prepared.flows = flowsCurrent ? result?.flows ?? [] : []
        let input = prepared
        let findings = result?.findings ?? []
        buildingReport = true
        reportTask = Task {
            let work = Task.detached(priority: .userInitiated) { () -> ClientReport? in
                var input = input
                input.takeHeld()
                if !flowsCurrent, !input.packets.isEmpty { input.flows = TCPFlowAnalyzer.analyze(input.packets) { Task.isCancelled } }
                return ClientReport.build(text, input: input, findings: findings)
            }
            let built = await withTaskCancellationHandler { await work.value } onCancel: { work.cancel() }
            guard !Task.isCancelled else { return }
            buildingReport = false
            reportTask = nil
            if let built { report = built } else { NSSound.beep() }
        }
    }
}

// MARK: - Going to the evidence

@MainActor
enum TroubleshootJump {
    enum Outcome: Equatable {
        case shown
        /// Some of it rolled out; the pane shows the rest.
        case partly(present: Int, of: Int)
        /// None of it is in memory any more: no pane was opened.
        case gone(String)
    }

    /// Opens the pane on `e` unless every line / frame / conversation of it has rolled out of
    /// memory (or the capture was cleared since the analysis: `epoch` is the packet store's at
    /// analysis time) — then says so and opens nothing. A log filter over lines that are gone
    /// showed an empty Log pane, or the device's newer lines as if they were the evidence.
    @discardableResult
    static func show(_ e: Evidence, epoch: Int? = nil) -> Outcome {
        let presence = present(e, epoch: epoch)
        if let p = presence, p.present == 0 { return .gone(goneText(e, total: p.total)) }
        switch e.kind {
        case .logLines, .traps: log(e.query, ids: e.ids)
        case .packets: packets(e.query)
        case .flows: if let f = e.flows.first(where: { flowPresent($0, epoch: epoch) }) ?? e.flows.first { flow(f) }
        }
        if let p = presence, p.present < p.total { return .partly(present: p.present, of: p.total) }
        return .shown
    }

    /// How much of the evidence is still in memory; nil when that cannot be told (a filter with
    /// no ids: a clock or a flood finding).
    static func present(_ e: Evidence, epoch: Int?) -> (present: Int, total: Int)? {
        let packets = AppModel.shared.packets
        let sameCapture = epoch.map { $0 == packets.epoch } ?? true
        switch e.kind {
        case .logLines, .traps:
            guard !e.ids.isEmpty else { return nil }
            return (AppModel.shared.logs.countPresent(ids: e.ids), Set(e.ids).count)
        case .packets:
            guard !e.ids.isEmpty else { return nil }
            let ids = Set(e.ids)
            return (sameCapture ? ids.filter { packets.contains(id: $0) }.count : 0, ids.count)
        case .flows:
            guard !e.flows.isEmpty else { return nil }
            return (e.flows.filter { flowPresent($0, epoch: epoch) }.count, e.flows.count)
        }
    }

    /// Some frame of the conversation is still in the ring (frames leave oldest first).
    static func flowPresent(_ f: FlowRef, epoch: Int?) -> Bool {
        let packets = AppModel.shared.packets
        if let epoch, epoch != packets.epoch { return false }
        guard let first = packets.packets.first?.id else { return false }
        return (f.lastPacketID ?? f.packetID) >= first
    }

    static func goneText(_ e: Evidence, total: Int) -> String {
        switch e.kind {
        case .logLines, .traps:
            let what = e.kind == .traps ? "trap\(total == 1 ? "" : "s")" : "log line\(total == 1 ? "" : "s")"
            let logs = AppModel.shared.logs
            return "\(total == 1 ? "This" : "These \(Format.count(total))") \(what) of the finding \(total == 1 ? "has" : "have") rolled out of memory "
                + "(the log keeps the newest \(Format.count(logs.limit)) lines" + (logs.entries.isEmpty ? " — it was cleared" : "") + "). "
                + "The disk log (Settings) keeps every line."
        case .packets:
            return "\(total == 1 ? "This packet" : "These \(Format.count(total)) packets") of the finding \(total == 1 ? "is" : "are") no longer in memory: "
                + "the capture rolled past \(total == 1 ? "it" : "them") or was cleared. Save captures you want to keep (Packets ▸ Save)."
        case .flows:
            return "\(total == 1 ? "This conversation" : "These \(total) conversations") of the finding \(total == 1 ? "is" : "are") no longer in memory: "
                + "the capture rolled past \(total == 1 ? "it" : "them") or was cleared."
        }
    }

    static func go(_ t: JumpTarget) {
        switch t {
        case .log(let q): log(q)
        case .packets(let q): packets(q)
        case .flow(let f): flow(f)
        case .finding: break
        }
    }

    /// The Log pane on this filter (all sources: the filter names the host). The filter is
    /// written in the plain grammar: with the Syslog pane's `.*` toggle on, its words were
    /// regular expressions (`10.0.0.2` matched 10.0.0.20 and 10a0b0c2, a phrase's dots any
    /// character), so the toggle goes off; a severity the mask hides that `ids` (the evidence's
    /// lines) have is shown again — the table hid the evidence it was opened for.
    static func log(_ query: String, ids: [Int] = []) {
        let logs = AppModel.shared.logs
        if logs.selectedSource != nil { logs.selectedSource = nil }
        if logs.regexMode { logs.regexMode = false }
        if logs.severityMask.count < Severity.allCases.count, !ids.isEmpty {
            var needed = Set<Severity>()
            for id in ids.prefix(2_000) { if let e = logs.entry(id: id) { needed.insert(e.severity) } }
            if !needed.isSubset(of: logs.severityMask) { logs.severityMask.formUnion(needed) }
        }
        logs.queryText = query
        logs.applyQueryText()
        AppModel.shared.mainPane = .log
    }

    static func packets(_ query: String) {
        AppModel.shared.mainPane = .packets
        NotificationCenter.default.post(name: .sheepLogPacketFilter, object: query)
    }

    static func flow(_ ref: FlowRef) {
        AppModel.shared.mainPane = .flows
        NotificationCenter.default.post(name: .sheepLogSelectFlow, object: FlowSelectRequest(key: ref.key, packetID: ref.packetID))
    }

    static func snmp(_ host: String) {
        AppModel.shared.mainPane = .snmpTest
        NotificationCenter.default.post(name: .sheepLogSNMPTarget, object: host)
    }
}

// MARK: - The pane

struct TroubleshootView: View {
    @ObservedObject private var model = TroubleshootModel.shared
    /// Chip, text, Problems only and time range (`TroubleshootFilter`: the list is their intersection).
    @State private var filter = TroubleshootFilter()
    @State private var clientText = ""
    @State private var expanded: Set<String> = []
    @State private var timelineShown = true
    @State private var paneWidth: CGFloat = 0
    @State private var scrollTarget: String?
    @FocusState private var filterFocused: Bool

    var body: some View {
        let _ = PaneProbe.ran("body.troubleshoot")
        VStack(alignment: .leading, spacing: 0) {
            TimelineView(.periodic(from: .now, by: 5)) { context in
                PaneHeader(eyebrow: "Overview", heading: heading, subtitle: subtitle(now: context.date)) {
                    headerActions
                }
            }
            .paneColumn()
            .padding(.top, Metrics.headerTop)
            .padding(.bottom, 12)

            PaneStrip { strip }

            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 18) {
                        if let r = model.result, !r.timeline.isEmpty { timelineSection(r.timeline) }
                        findingsSection
                    }
                    .padding(.vertical, 18)
                    .paneColumn()
                }
                .onChange(of: scrollTarget) { _, id in
                    guard let id else { return }
                    proxy.scrollTo(id, anchor: .top)
                    scrollTarget = nil
                }
            }
        }
        .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { paneWidth = $0 }
        .paneKeyCommands(find: { filterFocused = true })
        .task {
            TroubleshootDemo.loadIfAsked()
            model.appeared()
        }
        .onChange(of: model.result?.findings.count) {
            // `-demoTroubleshootExpand <rule>`: open that finding (screenshots of the details).
            if let rule = TroubleshootDemo.expand, let f = findings.first(where: { $0.rule == rule }), !expanded.contains(f.id) {
                expanded.insert(f.id)
                Task {
                    try? await Task.sleep(for: .milliseconds(300))
                    scrollTarget = f.id
                }
            }
        }
        .onDisappear { model.disappeared() }
        .sheet(item: $model.report) { r in
            ClientReportSheet(report: r) { model.report = nil }
        }
    }

    // MARK: Header

    private var findings: [Finding] { model.result?.findings ?? [] }

    private var nothingToRead: Bool {
        guard let s = model.result?.summary else { return false }
        return s.lines + s.traps + s.packets + s.snmpWalks == 0
    }

    private var heading: String {
        guard model.result != nil else { return model.analysing ? "Looking at what SheepLog has…" : "Troubleshoot" }
        if nothingToRead { return "Nothing to troubleshoot yet." }
        return TroubleshootFilter.heading(findings, range: filter.range, wide: wide)
    }

    /// The data covers more than a day: times of the range carry their day.
    private var wide: Bool {
        guard let r = model.result else { return false }
        return TroubleshootFilter.wide(summary: r.summary, timeline: r.timeline)
    }

    private func subtitle(now: Date) -> String {
        guard let s = model.result?.summary else {
            return "Reads the syslog lines, traps, packets, TCP flows and SNMP results SheepLog already has."
        }
        var parts: [String] = []
        if s.lines + s.traps > 0 {
            var t = "\(Format.count(s.lines)) syslog line\(s.lines == 1 ? "" : "s")"
            if s.traps > 0 { t += " and \(Format.count(s.traps)) trap\(s.traps == 1 ? "" : "s")" }
            t += " from \(Format.count(s.devices)) device\(s.devices == 1 ? "" : "s")"
            parts.append(t)
        }
        if s.packets > 0 { parts.append("\(Format.count(s.packets)) packets, \(Format.count(s.flows)) TCP flow\(s.flows == 1 ? "" : "s")") }
        if s.snmpWalks > 0 { parts.append("SNMP from \(s.snmpWalks) device\(s.snmpWalks == 1 ? "" : "s")") }
        if let a = s.start, let b = s.end { parts.append(Self.spanText(a, b)) }
        if model.analysing { parts.append("analysing…") }
        else if let at = model.analysedAt { parts.append("analysed \(Self.ago(now.timeIntervalSince(at)))") }
        return parts.isEmpty ? "Nothing received yet." : parts.joined(separator: " · ")
    }

    static func spanText(_ a: Date, _ b: Date) -> String {
        let cal = Calendar.gregorian
        if cal.isDate(a, inSameDayAs: b) { return "\(Format.day.string(from: a)) \(FText.clock(a))–\(FText.clock(b))" }
        return "\(Format.dayClock.string(from: a)) – \(Format.dayClock.string(from: b))"
    }

    private static func ago(_ s: Double) -> String {
        if s < 60 { return "\(max(0, Int(s))) s ago" }
        if s < 3600 { return "\(Int(s / 60)) min ago" }
        return "\(Int(s / 3600)) h ago"
    }

    private var iconOnly: Bool { paneWidth > 0 && paneWidth < 1_150 }

    @ViewBuilder private var headerActions: some View {
        ProgressView().controlSize(.small).opacity(model.analysing ? 1 : 0).accessibilityHidden(!model.analysing)
        Group {
            Button { model.start() } label: { Label("Re-analyse", systemImage: "arrow.clockwise") }
                .disabled(model.analysing)
                .help("Run every check again now")
            Toggle(isOn: $filter.problemsOnly) { Label("Problems only", systemImage: "exclamationmark.triangle") }
                .toggleStyle(.button)
                .help("Hide notes; show problems and warnings only")
            Button { exportReport() } label: { Label("Export report…", systemImage: "square.and.arrow.up") }
                .disabled(model.result == nil)
                .help("Save the findings shown and the timeline as a Markdown file for a ticket")
        }
        .labelStyle(TroubleshootLabelStyle(iconOnly: iconOnly))
    }

    // MARK: Strip

    @ViewBuilder private var strip: some View {
        HStack(spacing: 6) {
            Image(systemName: "person.crop.circle.badge.questionmark")
                .font(.system(size: 11))
                .foregroundStyle(Theme.faintText)
                .accessibilityHidden(true)
            TextField("Troubleshoot client", text: $clientText,
                      prompt: Text("Client MAC or IP").font(.system(size: 12)).foregroundStyle(Theme.faintText))
                .labelsHidden()
                .textFieldStyle(.plain)
                .font(.system(size: 12, design: clientText.isEmpty ? .default : .monospaced))
                .onSubmit(runClientReport)
                .accessibilityLabel("Client MAC or IP address")
        }
        .padding(.horizontal, 8)
        .frame(width: paneWidth > 0 && paneWidth < 900 ? 150 : 180, height: 26)
        .background(RoundedRectangle(cornerRadius: 6).fill(Theme.panel))
        .overlay { RoundedRectangle(cornerRadius: 6).strokeBorder(Theme.hairline, lineWidth: 0.5) }
        .help("A MAC (any spelling) or an IP address: everything SheepLog holds about it, as one report")
        Button(action: runClientReport) {
            if model.buildingReport { ProgressView().controlSize(.mini) } else { Text(paneWidth > 0 && paneWidth < 900 ? "Report" : "Troubleshoot client") }
        }
        .controlSize(.small)
        .disabled(ClientID.parse(clientText) == nil || model.buildingReport)
        .help("Build the client report (Return)")
        Rectangle().fill(Theme.hairline).frame(width: 0.5, height: 18)
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 4) {
                ForEach(filter.chips(findings)) { chip in
                    self.chip(chip.category, chip.category?.label ?? "All", count: chip.count)
                }
            }
            .padding(.vertical, 2)
            .padding(.trailing, 14)
        }
        .frame(maxWidth: .infinity)
        // A soft edge where the chips run under the filter field (they scroll sideways).
        .mask {
            HStack(spacing: 0) {
                Rectangle()
                LinearGradient(colors: [.black, .clear], startPoint: .leading, endPoint: .trailing).frame(width: 18)
            }
        }
        FilterField(text: $filter.text, prompt: "Filter findings", mono: false,
                    help: "Matches titles, details, devices and clients as you type. ⌘F to focus, Esc to clear", focus: $filterFocused)
            .frame(width: paneWidth > 0 && paneWidth < 900 ? 130 : 190)
    }

    private func chip(_ c: FindingCategory?, _ title: String, count: Int) -> some View {
        let selected = filter.category == c
        return Button { filter.category = c } label: {
            HStack(spacing: 4) {
                Text(title).font(.system(size: 11.5, weight: selected ? .semibold : .regular))
                Text(Format.count(count)).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(selected ? Theme.accent : Theme.faintText)
            }
            .foregroundStyle(selected ? Theme.accent : Theme.text2)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(Capsule().fill(selected ? Theme.selectedAccent : Theme.control))
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    private func runClientReport() {
        guard ClientID.parse(clientText) != nil else { NSSound.beep(); return }
        model.buildReport(clientText)
    }

    // MARK: Filtering

    private var rows: [Finding] { filter.rows(findings) }

    // MARK: Timeline

    private func timelineSection(_ t: Timeline) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Button {
                    withAnimation(.easeInOut(duration: 0.15)) { timelineShown.toggle() }
                } label: {
                    HStack(spacing: 6) {
                        Image(systemName: "chevron.right")
                            .font(.system(size: 10, weight: .semibold))
                            .rotationEffect(.degrees(timelineShown ? 90 : 0))
                            .foregroundStyle(Theme.faintText)
                        Text("Timeline")
                            .font(.system(size: 16.5, weight: .semibold))
                            .foregroundStyle(Theme.text)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(timelineShown ? "Hide the timeline" : "Show the timeline")
                Text("\(t.lanes.count) row\(t.lanes.count == 1 ? "" : "s") · \(Self.spanText(t.start, t.end))")
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.faintText)
                    .lineLimit(1)
                Spacer(minLength: 0)
                if filter.range != nil {
                    Button("Clear range") { filter.range = nil }
                        .controlSize(.small)
                }
            }
            .padding(.horizontal, 2)
            if timelineShown {
                TimelineStrip(timeline: t, range: $filter.range) { event in
                    if case .finding(let id) = event.target { reveal(id) } else { TroubleshootJump.go(event.target) }
                }
            }
        }
    }

    private func reveal(_ id: String) {
        guard let f = findings.first(where: { $0.id == id }) else { return }
        filter.reveal(f)
        expanded.insert(id)
        scrollTarget = id
    }

    // MARK: Findings

    @ViewBuilder private var findingsSection: some View {
        let list = rows
        PaneSection("Findings", note: findingsNote(list.count)) {
            if let notice = model.jumpNotice {
                GroupedList {
                    HStack(alignment: .top, spacing: 8) {
                        NoteRow(text: notice, systemImage: "clock.badge.exclamationmark", tint: Theme.caution)
                        Button("Dismiss") { model.jumpNotice = nil }
                            .controlSize(.small)
                            .padding(.trailing, 14)
                            .padding(.top, 8)
                    }
                }
                .padding(.bottom, 8)
            }
            if model.result == nil {
                GroupedList { NoteRow(text: model.analysing ? "Analysing…" : "Starting…", systemImage: "hourglass") }
            } else if nothingToRead {
                emptyState
            } else if findings.isEmpty {
                allClear
            } else if list.isEmpty {
                GroupedList {
                    NoteRow(text: "No finding matches the filter\(filter.range != nil ? " in the selected time range" : "").", systemImage: "line.3.horizontal.decrease")
                }
            } else {
                GroupedList {
                    ForEach(list) { f in
                        FindingRow(finding: f, expanded: expanded.contains(f.id), toggle: { toggle(f.id) },
                                   troubleshootClient: { c in clientText = c; model.buildReport(c) },
                                   show: { e in model.show(e) })
                            // The scroll anchor: an `.id` on a GroupedList row itself is taken by
                            // the list's variadic layout and `scrollTo` never finds it.
                            .overlay(alignment: .top) { Color.clear.frame(height: 1).id(f.id) }
                    }
                }
            }
            if let notes = model.result?.summary.notes, !notes.isEmpty, !nothingToRead {
                VStack(alignment: .leading, spacing: 3) {
                    ForEach(notes, id: \.self) { n in
                        Text(n).hint()
                    }
                }
                .padding(.horizontal, 2)
                .padding(.top, 4)
            }
        }
    }

    private func findingsNote(_ shown: Int) -> String {
        guard !findings.isEmpty else { return "" }
        var s = shown == findings.count ? "\(Format.count(shown)), oldest first" : "\(Format.count(shown)) of \(Format.count(findings.count)) shown"
        if let range = filter.range {
            s += " · \(TroubleshootFilter.time(range.lowerBound, wide: wide))–\(TroubleshootFilter.time(range.upperBound, wide: wide))"
        }
        return s
    }

    private func toggle(_ id: String) {
        if expanded.contains(id) { expanded.remove(id) } else { expanded.insert(id) }
    }

    private var emptyState: some View {
        GroupedList {
            NoteRow(text: "Troubleshoot turns what SheepLog receives into plain-English findings — there is nothing to read yet.", systemImage: "stethoscope", tint: Theme.accent)
            NoteRow(text: "Syslog and traps: switch them on in the sidebar and point devices at this Mac (UDP/TCP 514, traps UDP 162). Link flaps, power and fans, spanning tree, logins, restarts, clocks and log floods are checked.", systemImage: "text.alignleft")
            NoteRow(text: "Packets: start a capture on the Packets pane or open a .pcap (⌘O). DHCP, DNS, ARP, ICMP and every TCP conversation are checked.", systemImage: "point.3.connected.trianglepath.dotted")
            NoteRow(text: "SNMP: run Interfaces on the SNMP Test pane. Port errors (and whether they grow on the next walk), ports down, half duplex, discards and recent reboots are checked.", systemImage: "antenna.radiowaves.left.and.right")
            NoteRow(text: "It re-analyses by itself while data arrives. Type a MAC or IP above for one client's whole story.", systemImage: "arrow.clockwise")
        }
    }

    private var allClear: some View {
        GroupedList {
            NoteRow(text: "Nothing wrong that SheepLog can see in what it has. Checked: link flaps and ports left down, power / fan / temperature / PoE, spanning tree, routing neighbors, restarts, admin logins, configuration changes, device clocks, log floods; DHCP, DNS, ARP, ICMP; TCP refusals, resets, retransmissions, handshake times and zero windows; SNMP port status and errors.", systemImage: "checkmark.circle", tint: Theme.ok)
        }
    }

    // MARK: Export

    private func exportReport() {
        guard let r = model.result else { return }
        // What the list shows, and the heading of that: the range's counts, which filters and
        // range it used, how many of the findings it holds.
        let md = filter.report(findings, summary: r.summary, timeline: r.timeline, generated: Date())
        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "md") ?? .plainText]
        panel.nameFieldStringValue = "SheepLog-troubleshoot-\(Format.compactStamp.string(from: Date())).md"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { try md.write(to: url, atomically: true, encoding: .utf8) }
        catch { AppModel.shared.report("Could not write \(url.lastPathComponent).", detail: error.localizedDescription) }
    }
}

/// Icons only when the pane is narrow (the header's three buttons would wrap the heading).
struct TroubleshootLabelStyle: LabelStyle {
    let iconOnly: Bool
    func makeBody(configuration: Configuration) -> some View {
        if iconOnly { configuration.icon } else { HStack(spacing: 4) { configuration.icon; configuration.title } }
    }
}

// MARK: - One finding

enum FindingStyle {
    static func color(_ s: FindingSeverity) -> Color {
        switch s {
        case .bad: Theme.err
        case .warn: Theme.caution
        case .info: Theme.faintText
        }
    }
}

struct FindingRow: View {
    let finding: Finding
    let expanded: Bool
    let toggle: () -> Void
    let troubleshootClient: (String) -> Void
    /// An evidence button: the Log / Packets / Flows pane on it, or a note that it rolled out.
    var show: (Evidence) -> Void = { _ = TroubleshootJump.show($0) }
    @State private var hovering = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button(action: toggle) { header }
                .buttonStyle(.plain)
                .onHover { hovering = $0 }
                .accessibilityLabel("\(finding.severity.word): \(finding.title)")
                .accessibilityHint(expanded ? "Collapse" : "Show details")
            if expanded { details }
        }
        .background(hovering && !expanded ? Theme.hover : .clear)
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 10) {
            Circle()
                .fill(FindingStyle.color(finding.severity))
                .frame(width: 8, height: 8)
                .padding(.top, 5)
                .help(finding.severity.word)
            VStack(alignment: .leading, spacing: 4) {
                Text(finding.title)
                    .font(.system(size: 13, weight: finding.severity == .info ? .regular : .medium))
                    .foregroundStyle(Theme.text)
                    .multilineTextAlignment(.leading)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 6) {
                    Text(finding.category.label)
                        .font(.system(size: 11.5))
                        .foregroundStyle(Theme.dimText)
                    if let d = finding.device { StatusPill(text: d, kind: .neutral) }
                    if let c = finding.client, c != finding.device { StatusPill(text: c, kind: .accent) }
                    Text(meta)
                        .font(.system(size: 11.5).monospacedDigit())
                        .foregroundStyle(Theme.faintText)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 8)
            Image(systemName: "chevron.right")
                .font(.system(size: 10.5, weight: .semibold))
                .foregroundStyle(Theme.faintText)
                .rotationEffect(.degrees(expanded ? 90 : 0))
                .padding(.top, 4)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .contentShape(Rectangle())
    }

    private var meta: String {
        let span = finding.lastSeen.timeIntervalSince(finding.firstSeen) >= 1
            ? "\(FText.clock(finding.firstSeen))–\(FText.clock(finding.lastSeen))" : FText.clock(finding.firstSeen)
        return finding.count > 1 ? "\(Format.count(finding.count))× · \(span)" : span
    }

    private var details: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(finding.detail)
                .font(.system(size: 12.5))
                .foregroundStyle(Theme.text2)
                .lineSpacing(2)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 760, alignment: .leading)
            if !finding.evidence.isEmpty || finding.snmpTarget != nil || Self.reportTarget(finding) != nil {
                WrapLayout(spacing: 6) {
                    ForEach(finding.evidence) { e in
                        Button { show(e) } label: {
                            Label(e.label, systemImage: Self.symbol(e.kind))
                        }
                        .help(help(e))
                    }
                    if let host = finding.snmpTarget {
                        Button { TroubleshootJump.snmp(host) } label: { Label("SNMP test", systemImage: "antenna.radiowaves.left.and.right") }
                            .help("Open \(host) on the SNMP Test pane")
                    }
                    if let c = Self.reportTarget(finding) {
                        Button { troubleshootClient(c) } label: { Label("Troubleshoot \(c)", systemImage: "person.crop.circle.badge.questionmark") }
                            .help("Everything SheepLog holds about \(c)")
                    }
                    CopyButton("Copy", value: copyText, bordered: true, help: "Copy this finding as text")
                }
                .controlSize(.small)
            }
            if !finding.nextSteps.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Next steps").groupTitle()
                    ForEach(Array(finding.nextSteps.enumerated()), id: \.offset) { _, step in
                        HStack(alignment: .firstTextBaseline, spacing: 6) {
                            Text("•").foregroundStyle(Theme.accent)
                            Text(step)
                                .foregroundStyle(Theme.text)
                                .textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .font(.system(size: 12.5))
                    }
                }
                .frame(maxWidth: 760, alignment: .leading)
            }
        }
        .padding(.leading, 32)
        .padding(.trailing, 14)
        .padding(.bottom, 12)
    }

    /// The client a "Troubleshoot …" button can build a report for: a MAC or an IP. A RADIUS
    /// attempt with no MAC is `user:<name>` — its button could only beep.
    static func reportTarget(_ f: Finding) -> String? {
        guard let c = f.client, ClientID.parse(c) != nil else { return nil }
        return c
    }

    static func symbol(_ k: Evidence.Kind) -> String {
        switch k {
        case .logLines: "text.alignleft"
        case .traps: "bell"
        case .packets: "square.stack.3d.up"
        case .flows: "arrow.left.arrow.right"
        }
    }

    private func help(_ e: Evidence) -> String {
        switch e.kind {
        case .logLines, .traps: "Show them on the Log pane (filter \(e.query))"
        case .packets: "Show them on the Packets pane"
        case .flows: "Open \(e.flows.first.map { "\($0.key)" } ?? "the conversation") on the TCP flows pane"
        }
    }

    private var copyText: String {
        var s = "[\(finding.severity.word)] \(finding.title)\n\(finding.detail)\n"
        if !finding.nextSteps.isEmpty { s += "Next steps:\n" + finding.nextSteps.map { "- \($0)" }.joined(separator: "\n") + "\n" }
        return s
    }
}

/// Buttons that wrap onto the next line when the row is too narrow.
struct WrapLayout: Layout {
    var spacing: CGFloat = 6

    private func rows(_ sizes: [CGSize], width: CGFloat) -> [[Int]] {
        var rows: [[Int]] = [[]]
        var x: CGFloat = 0
        for (i, s) in sizes.enumerated() {
            if x > 0, x + s.width > width { rows.append([]); x = 0 }
            rows[rows.count - 1].append(i)
            x += s.width + spacing
        }
        return rows
    }

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let sizes = subviews.map { $0.sizeThatFits(.unspecified) }
        let width = proposal.width ?? sizes.reduce(0) { $0 + $1.width + spacing }
        let rs = rows(sizes, width: width)
        let height = rs.reduce(CGFloat(0)) { h, r in h + (r.map { sizes[$0].height }.max() ?? 0) } + spacing * CGFloat(max(0, rs.count - 1))
        return CGSize(width: width, height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let sizes = subviews.map { $0.sizeThatFits(.unspecified) }
        var y = bounds.minY
        for r in rows(sizes, width: bounds.width) {
            var x = bounds.minX
            let h = r.map { sizes[$0].height }.max() ?? 0
            for i in r {
                subviews[i].place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(sizes[i]))
                x += sizes[i].width + spacing
            }
            y += h + spacing
        }
    }
}

// MARK: - Timeline strip

/// One row per device (the capture last), dots for warning lines, traps and troubled flows, bars
/// for findings. Drag across it to show only that time; click a dot to open it.
struct TimelineStrip: View {
    let timeline: Timeline
    @Binding var range: ClosedRange<Date>?
    let open: (TimelineEvent) -> Void
    @State private var showAll = false
    @State private var hover: (lane: String, event: TimelineEvent)?

    static let labelWidth: CGFloat = 150
    static let rowHeight: CGFloat = 20
    static let maxLanes = 8

    private var lanes: [TimelineLane] { showAll ? timeline.lanes : Array(timeline.lanes.prefix(Self.maxLanes)) }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .top, spacing: 10) {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(lanes) { lane in
                        HStack(spacing: 6) {
                            Circle().fill(FindingStyle.color(lane.worst)).frame(width: 6, height: 6)
                            Text(lane.id)
                                .font(.system(size: 11.5))
                                .foregroundStyle(Theme.text2)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                        .frame(height: Self.rowHeight, alignment: .leading)
                        .help("\(lane.id): \(Format.count(lane.total)) event\(lane.total == 1 ? "" : "s"), \(Format.count(lane.problems)) problem\(lane.problems == 1 ? "" : "s"), \(FText.clock(lane.first))–\(FText.clock(lane.last))")
                    }
                }
                .frame(width: Self.labelWidth, alignment: .leading)
                GeometryReader { geo in
                    let w = geo.size.width
                    Canvas { ctx, size in draw(&ctx, size) }
                        .contentShape(Rectangle())
                        .gesture(DragGesture(minimumDistance: 4, coordinateSpace: .local)
                            .onChanged { g in
                                let a = min(g.startLocation.x, g.location.x), b = max(g.startLocation.x, g.location.x)
                                range = date(a, w)...date(b, w)
                            })
                        .onTapGesture(coordinateSpace: .local) { p in
                            if let hit = hit(p, w) { open(hit.event) } else { range = nil }
                        }
                        .onContinuousHover(coordinateSpace: .local) { phase in
                            switch phase {
                            case .active(let p): hover = hit(p, w)
                            case .ended: hover = nil
                            }
                        }
                }
                .frame(height: CGFloat(max(1, lanes.count)) * Self.rowHeight)
            }
            HStack(spacing: 0) {
                Color.clear.frame(width: Self.labelWidth + 10, height: 1)
                Text(axis(timeline.start))
                Spacer(minLength: 4)
                Text(axis(timeline.date(atFraction: 0.5)))
                Spacer(minLength: 4)
                Text(axis(timeline.end))
            }
            .font(.system(size: 10, design: .monospaced))
            .foregroundStyle(Theme.faintText)
            HStack(spacing: 8) {
                Text(caption)
                    .font(.system(size: 11.5))
                    .foregroundStyle(hover == nil ? Theme.faintText : Theme.text2)
                    .lineLimit(1)
                    .truncationMode(.tail)
                Spacer(minLength: 8)
                if timeline.lanes.count > Self.maxLanes {
                    Button(showAll ? "Show fewer" : "Show all \(timeline.lanes.count)") { showAll.toggle() }
                        .buttonStyle(.link)
                        .font(.system(size: 11.5))
                }
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .panelCard()
    }

    private var caption: String {
        if let h = hover {
            let e = h.event
            let kind: String
            switch e.kind {
            case .finding: kind = "finding"
            case .flow: kind = "flow"
            case .trap: kind = "trap"
            case .log: kind = "log"
            }
            return "\(FText.clock(e.time)) · \(h.lane) · \(kind): \(e.label)"
        }
        if let r = range {
            return "Showing findings between \(FText.clock(r.lowerBound)) and \(FText.clock(r.upperBound)) — click an empty spot to show all."
        }
        return "Drag across the strip to show only that time; click a dot or bar to open it."
    }

    private func axis(_ d: Date) -> String {
        timeline.span > 86_400 ? Format.dayClock.string(from: d) : FText.clock(d)
    }

    private func x(_ d: Date, _ w: CGFloat) -> CGFloat { 4 + CGFloat(timeline.fraction(d)) * max(1, w - 8) }
    private func date(_ x: CGFloat, _ w: CGFloat) -> Date { timeline.date(atFraction: Double((x - 4) / max(1, w - 8))) }

    private func hit(_ p: CGPoint, _ w: CGFloat) -> (lane: String, event: TimelineEvent)? {
        let row = Int(p.y / Self.rowHeight)
        guard row >= 0, row < lanes.count else { return nil }
        let lane = lanes[row]
        let dots = lane.events.filter { $0.kind != .finding }
        if let d = dots.min(by: { abs(x($0.time, w) - p.x) < abs(x($1.time, w) - p.x) }), abs(x(d.time, w) - p.x) <= 6 {
            return (lane.id, d)
        }
        let bars = lane.events.filter { $0.kind == .finding }
        if let b = bars.last(where: { x($0.time, w) - 4 <= p.x && p.x <= x($0.end ?? $0.time, w) + 4 }) {
            return (lane.id, b)
        }
        return nil
    }

    private func draw(_ ctx: inout GraphicsContext, _ size: CGSize) {
        let w = size.width
        if let r = range {
            let a = x(r.lowerBound, w), b = x(r.upperBound, w)
            let rect = CGRect(x: a, y: 0, width: max(1, b - a), height: size.height)
            ctx.fill(Path(rect), with: .color(Theme.selectedAccent))
            ctx.fill(Path(CGRect(x: a, y: 0, width: 1, height: size.height)), with: .color(Theme.accent))
            ctx.fill(Path(CGRect(x: b - 1, y: 0, width: 1, height: size.height)), with: .color(Theme.accent))
        }
        for (i, lane) in lanes.enumerated() {
            let y = CGFloat(i) * Self.rowHeight + Self.rowHeight / 2
            ctx.fill(Path(CGRect(x: 0, y: y - 0.25, width: w, height: 0.5)), with: .color(Theme.hairlineSoft))
            for e in lane.events.filter({ $0.kind == .finding }).sorted(by: { $0.severity < $1.severity }) {
                let a = x(e.time, w), b = max(a + 6, x(e.end ?? e.time, w))
                let rect = CGRect(x: a - 3, y: y - 4, width: b - a + 6, height: 8)
                let c = FindingStyle.color(e.severity)
                ctx.fill(Path(roundedRect: rect, cornerRadius: 4), with: .color(c.opacity(0.22)))
                ctx.stroke(Path(roundedRect: rect, cornerRadius: 4), with: .color(c.opacity(0.9)), lineWidth: 1)
            }
            for e in lane.events where e.kind != .finding {
                let cx = x(e.time, w)
                let c = FindingStyle.color(e.severity)
                let isHover = hover?.event.id == e.id && hover?.lane == lane.id
                let r: CGFloat = isHover ? 4 : 2.6
                switch e.kind {
                case .trap:
                    var p = Path()
                    p.move(to: CGPoint(x: cx, y: y - r - 0.5)); p.addLine(to: CGPoint(x: cx + r + 0.5, y: y))
                    p.addLine(to: CGPoint(x: cx, y: y + r + 0.5)); p.addLine(to: CGPoint(x: cx - r - 0.5, y: y)); p.closeSubpath()
                    ctx.fill(p, with: .color(c))
                case .flow:
                    ctx.fill(Path(roundedRect: CGRect(x: cx - r, y: y - r, width: r * 2, height: r * 2), cornerRadius: 1), with: .color(c))
                default:
                    ctx.fill(Path(ellipseIn: CGRect(x: cx - r, y: y - r, width: r * 2, height: r * 2)), with: .color(c))
                }
            }
        }
    }
}

// MARK: - Client report sheet

struct ClientReportSheet: View {
    let report: ClientReport
    let dismiss: () -> Void
    /// Said here when a link's lines / frames / conversation are no longer in memory.
    @State private var notice: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 3) {
                Text("CLIENT REPORT")
                    .font(.system(size: 11, weight: .semibold))
                    .kerning(1.3)
                    .foregroundStyle(Theme.faintText)
                Text(report.title)
                    .font(.system(size: 22, weight: .semibold))
                    .foregroundStyle(Theme.text)
                    .textSelection(.enabled)
                Text(summary)
                    .font(.system(size: 12.5))
                    .foregroundStyle(Theme.text2)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.horizontal, 20)
            .padding(.top, 18)
            .padding(.bottom, 12)
            Rectangle().fill(Theme.hairline).frame(height: 0.5)
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    section("Where it is", report.location, empty: "Not known — no log line or bridge table names its switch port.")
                    findingsSection
                    logSection
                    section("DHCP", report.dhcp, empty: "No DHCP packets of this client in the capture.", mono: true)
                    section("DNS", report.dns, empty: "No DNS queries from this client in the capture.")
                    section("ARP", report.arp, empty: "No ARP packets about this client in the capture.", mono: true)
                    flowsSection
                    section("Next steps", report.nextSteps.enumerated().map { "\($0.offset + 1). \($0.element)" }, empty: "Nothing stands out.")
                }
                .padding(20)
            }
            Rectangle().fill(Theme.hairline).frame(height: 0.5)
            HStack(spacing: 8) {
                CopyButton("Copy as Markdown", value: report.markdown, bordered: true, help: "Copy the report as Markdown, ready to paste into a ticket")
                Button("Export…", action: export)
                if report.packetTotal > 0 {
                    Button(ReportLink.title("Show \(Format.count(report.packetTotal)) packets", report.packetEvidence, epoch: report.packetEpoch)) {
                        open(report.packetEvidence)
                    }
                }
                if let notice {
                    Text(notice)
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.caution)
                        .lineLimit(3)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
                Button("Done", action: dismiss)
                    .buttonStyle(.borderedProminent)
                    .tint(Theme.accent)
                    .keyboardShortcut(.defaultAction)
            }
            .controlSize(.small)
            .padding(.horizontal, 20)
            .padding(.vertical, 12)
        }
        .frame(width: 720, height: 580)
        .background(Theme.panel)
        .sheetCancel(dismiss)
    }

    private var summary: String {
        var parts: [String] = []
        if !report.identity.isEmpty { parts.append("Also " + report.identity.joined(separator: ", ")) }
        parts.append("\(Format.count(report.logTotal)) log line\(report.logTotal == 1 ? "" : "s"), \(Format.count(report.packetTotal)) packets, \(Format.count(report.flowTotal)) TCP flow\(report.flowTotal == 1 ? "" : "s"), \(report.findings.count) finding\(report.findings.count == 1 ? "" : "s")")
        return parts.joined(separator: " · ")
    }

    private func section(_ title: String, _ lines: [String], empty: String, mono: Bool = false) -> some View {
        PaneSection(title) {
            GroupedList {
                if lines.isEmpty {
                    NoteRow(text: empty)
                } else {
                    ForEach(Array(lines.enumerated()), id: \.offset) { _, l in
                        Text(l)
                            .font(.system(size: 12, design: mono ? .monospaced : .default))
                            .foregroundStyle(Theme.text)
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 14)
                            .padding(.vertical, 7)
                    }
                }
            }
        }
    }

    private var findingsSection: some View {
        PaneSection("Findings", note: report.findings.isEmpty ? "" : "\(report.findings.count)") {
            GroupedList {
                if report.findings.isEmpty {
                    NoteRow(text: "No finding is about this client.")
                } else {
                    ForEach(report.findings) { f in
                        HStack(alignment: .top, spacing: 8) {
                            Circle().fill(FindingStyle.color(f.severity)).frame(width: 7, height: 7).padding(.top, 5)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(f.title).font(.system(size: 12.5, weight: .medium)).foregroundStyle(Theme.text)
                                Text(f.detail).font(.system(size: 12)).foregroundStyle(Theme.text2)
                            }
                            .fixedSize(horizontal: false, vertical: true)
                            .textSelection(.enabled)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 8)
                    }
                }
            }
        }
    }

    private var logSection: some View {
        PaneSection("Log lines", note: report.logTotal > report.logLines.count ? "last \(report.logLines.count) of \(Format.count(report.logTotal))" : "\(report.logTotal)") {
            GroupedList {
                if report.logLines.isEmpty {
                    NoteRow(text: "No syslog line or trap mentions it.")
                } else {
                    ForEach(report.logLines) { l in
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Text(FText.clock(l.time)).font(.system(size: 11.5, design: .monospaced)).foregroundStyle(Theme.dimText)
                            Text(l.device).font(.system(size: 11.5)).foregroundStyle(Theme.text2).lineLimit(1).frame(width: 120, alignment: .leading)
                            Text(l.message).font(.system(size: 12)).foregroundStyle(Theme.severityTint(l.severity) ?? Theme.text)
                                .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 6)
                    }
                    HStack {
                        Spacer()
                        Button(ReportLink.title("Show on the Log pane", report.logEvidence, epoch: report.packetEpoch)) { open(report.logEvidence) }
                            .controlSize(.small)
                    }
                    .padding(.horizontal, 14)
                    .padding(.vertical, 6)
                }
            }
        }
    }

    private var flowsSection: some View {
        PaneSection("TCP flows", note: report.flowTotal > report.flows.count ? "\(report.flows.count) of \(Format.count(report.flowTotal))" : "\(report.flowTotal)") {
            GroupedList {
                if report.flows.isEmpty {
                    NoteRow(text: "No TCP conversation of this client in the capture.")
                } else {
                    ForEach(report.flows) { f in
                        let gone = ReportLink.isGone(report.flowEvidence(f), epoch: report.packetEpoch)
                        Button { open(report.flowEvidence(f)) } label: {
                            HStack(alignment: .firstTextBaseline, spacing: 8) {
                                Circle().fill(f.health == .ok ? Theme.ok : f.health == .warn ? Theme.caution : Theme.err).frame(width: 7, height: 7)
                                Text(f.text).font(.system(size: 12, design: .monospaced)).foregroundStyle(Theme.text)
                                    .lineLimit(2).multilineTextAlignment(.leading)
                                Spacer(minLength: 0)
                                if gone {
                                    Text("no longer in memory").font(.system(size: 10.5)).foregroundStyle(Theme.faintText)
                                } else {
                                    Image(systemName: "arrow.left.arrow.right").font(.system(size: 10)).foregroundStyle(Theme.faintText)
                                }
                            }
                            .padding(.horizontal, 14)
                            .padding(.vertical, 7)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .help("Open this conversation on the TCP flows pane")
                    }
                }
            }
        }
    }

    /// A link: the pane on it, or — rolled out, or the capture cleared since the report — a
    /// note here and the sheet stays (it used to open an empty pane, or the new capture's
    /// packets of the same address as if they were the report's).
    private func open(_ e: Evidence) {
        if let text = ReportLink.open(e, epoch: report.packetEpoch) { notice = text } else { dismiss() }
    }

    private func export() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "md") ?? .plainText]
        let safe = report.client.text.map { $0.isLetter || $0.isNumber || $0 == "." ? String($0) : "-" }.joined()
        panel.nameFieldStringValue = "client-\(safe)-\(Format.compactStamp.string(from: report.generated)).md"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { try report.markdown.write(to: url, atomically: true, encoding: .utf8) }
        catch { AppModel.shared.report("Could not write \(url.lastPathComponent).", detail: error.localizedDescription) }
    }
}

/// The client report's links (tested without the sheet).
@MainActor
enum ReportLink {
    /// The button's words, saying when what it opens is gone or partly gone.
    static func title(_ base: String, _ e: Evidence, epoch: Int) -> String {
        guard let p = TroubleshootJump.present(e, epoch: epoch) else { return base }
        if p.present == 0 { return base + " — no longer in memory" }
        if p.present < p.total { return base + " — \(Format.count(p.present)) of \(Format.count(p.total)) still in memory" }
        return base
    }

    static func isGone(_ e: Evidence, epoch: Int) -> Bool {
        TroubleshootJump.present(e, epoch: epoch)?.present == 0
    }

    /// Opens the pane on `e`; the sentence to show instead when none of it is in memory.
    static func open(_ e: Evidence, epoch: Int) -> String? {
        if case .gone(let text) = TroubleshootJump.show(e, epoch: epoch) { return text }
        return nil
    }
}

nonisolated extension ClientReport: Identifiable {
    var id: String { query + "|" + String(generated.timeIntervalSinceReferenceDate) }
}

// MARK: - Demo (`-demoTroubleshoot 1` or `-demoTroubleshoot <file.log>`)

/// Screenshots: the bad-day fixture (Tests/troubleshoot/bad-day.log) ingested as if received
/// live, the packets of the same story, and two SNMP walks of the core switch.
@MainActor
enum TroubleshootDemo {
    static let flag = CommandLine.value(after: "-demoTroubleshoot")
    /// `-demoTroubleshootClient <mac|ip>`: open that client's report once the analysis is in.
    static let client = CommandLine.value(after: "-demoTroubleshootClient")
    /// `-demoTroubleshootExpand <rule>`: expand the first finding of that rule.
    static let expand = CommandLine.value(after: "-demoTroubleshootExpand")

    static var fixtureURL: URL? {
        guard let flag else { return nil }
        if flag != "1" { return URL(fileURLWithPath: flag) }
        // The source tree this build came from (demo runs are on the developer's Mac).
        return URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appending(path: "Tests/troubleshoot/bad-day.log")
    }

    static func loadIfAsked() {
        guard let url = fixtureURL, DemoFlags.firstRun("troubleshoot") else { return }
        guard let text = try? String(contentsOf: url, encoding: .utf8) else {
            AppModel.shared.report("-demoTroubleshoot: could not read \(url.path).")
            return
        }
        let entries = TroubleshootFixture.liveEntries(text)
        AppModel.shared.logs.ingest(entries)
        let t0 = entries.compactMap(\.deviceTime).min() ?? Date()
        AppModel.shared.packets.ingest(TroubleshootFixture.badDayPackets(start: t0) + TroubleshootFixture.demoFlows(start: t0))
        for s in TroubleshootFixture.coreSwitchWalks(start: t0) { TroubleshootModel.shared.add(s) }
        if let client {
            Task {
                for _ in 0..<40 {
                    try? await Task.sleep(for: .milliseconds(150))
                    if TroubleshootModel.shared.result != nil, !TroubleshootModel.shared.analysing { break }
                }
                TroubleshootModel.shared.buildReport(client)
            }
        }
    }
}

// MARK: - Fixture builders (demo and tests)

/// Real frames for the Troubleshoot fixtures, run through the packet decoder.
nonisolated enum TroubleshootFixture {
    /// The addresses the bad-day devices send from.
    static let addresses: [String: String] = [
        "CORE-CX-6300": "10.1.0.1", "ACC-CX-6100-2F": "10.1.0.12", "FGT-100F-HQ": "10.1.0.254",
        "S5720-DIST-B": "10.1.0.21", "CORE-RTR1": "10.1.0.2", "SW-2930F-3F": "10.1.0.13",
    ]

    /// Parses each line as received from its device, arriving 250 ms after its own timestamp
    /// (as a live device with a good clock would).
    static func liveEntries(_ text: String, firstID: Int? = nil) -> [LogEntry] {
        let lines = text.split(whereSeparator: \.isNewline).map(String.init).filter { !$0.hasPrefix("#") && !$0.isEmpty }
        var id = firstID ?? LogStore.reserveIDs(lines.count)
        var out: [LogEntry] = []
        for line in lines {
            let probe = SyslogParser.parse(RawSyslog(received: Date(), sourceAddress: "10.20.0.1", sourcePort: 514, transport: .udp, text: line), id: id)
            let address = addresses[probe.hostname] ?? "10.20.0.1"
            let received = (probe.deviceTime ?? Date()).addingTimeInterval(0.25)
            out.append(SyslogParser.parse(RawSyslog(received: received, sourceAddress: address, sourcePort: 514, transport: .udp, text: line), id: id))
            id += 1
        }
        return out.sorted { $0.received < $1.received }
    }

    // Frames

    static func be16(_ v: Int) -> [UInt8] { [UInt8((v >> 8) & 0xff), UInt8(v & 0xff)] }
    static func be32(_ v: UInt32) -> [UInt8] { [UInt8(v >> 24), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)] }
    static func ip4(_ s: String) -> [UInt8] { s.split(separator: ".").map { UInt8($0) ?? 0 } }
    static func mac(_ s: String) -> [UInt8] { s.split(separator: ":").map { UInt8($0, radix: 16) ?? 0 } }

    static func ether(dst: String, src: String, type: Int, vlan: Int?, _ payload: [UInt8]) -> [UInt8] {
        var f = mac(dst) + mac(src)
        if let vlan { f += be16(0x8100) + be16(vlan) }
        f += be16(type) + payload
        while f.count < 60 { f.append(0) }
        return f
    }

    static func udp4(srcMAC: String, dstMAC: String, src: String, dst: String, sport: Int, dport: Int, vlan: Int?, _ payload: [UInt8]) -> [UInt8] {
        let udp = be16(sport) + be16(dport) + be16(8 + payload.count) + [0, 0] + payload
        let ip: [UInt8] = [0x45, 0] + be16(20 + udp.count) + be16(0x1234) + [0, 0, 64, 17, 0, 0] + ip4(src) + ip4(dst)
        return ether(dst: dstMAC, src: srcMAC, type: 0x0800, vlan: vlan, ip + udp)
    }

    static func dhcp(op: UInt8, type: UInt8, xid: UInt32, client: String, yiaddr: String = "0.0.0.0", server: String? = nil,
                     lease: UInt32? = nil) -> [UInt8] {
        var m: [UInt8] = [op, 1, 6, 0] + be32(xid) + [0, 0, 0x80, 0]
        m += ip4("0.0.0.0") + ip4(yiaddr) + ip4("0.0.0.0") + ip4("0.0.0.0")
        m += mac(client) + [UInt8](repeating: 0, count: 10) + [UInt8](repeating: 0, count: 192)
        m += [0x63, 0x82, 0x53, 0x63, 53, 1, type]
        if let server { m += [54, 4] + ip4(server) }
        if let lease { m += [51, 4] + be32(lease) }
        m += [255]
        return m
    }

    static func dnsName(_ name: String) -> [UInt8] {
        var out: [UInt8] = []
        for label in name.split(separator: ".") { out.append(UInt8(label.utf8.count)); out += Array(label.utf8) }
        return out + [0]
    }

    static func dns(id: Int, name: String, response: Bool, rcode: Int = 0, answer: String? = nil) -> [UInt8] {
        let flags: [UInt8] = response ? [0x81, 0x80 | UInt8(rcode & 0xf)] : [0x01, 0x00]
        var m = be16(id) + flags + be16(1) + be16(answer == nil ? 0 : 1) + be16(0) + be16(0) + dnsName(name) + be16(1) + be16(1)
        if let answer { m += [0xc0, 0x0c] + be16(1) + be16(1) + be32(300) + be16(4) + ip4(answer) }
        return m
    }

    static func arp(request: Bool, senderMAC: String, senderIP: String, targetIP: String, targetMAC: String = "00:00:00:00:00:00", vlan: Int?) -> [UInt8] {
        let body: [UInt8] = be16(1) + be16(0x0800) + [6, 4] + be16(request ? 1 : 2) + mac(senderMAC) + ip4(senderIP) + mac(targetMAC) + ip4(targetIP)
        return ether(dst: request ? "ff:ff:ff:ff:ff:ff" : targetMAC, src: senderMAC, type: 0x0806, vlan: vlan, body)
    }

    static func packet(_ bytes: [UInt8], at t: Date, id: Int = 1, start: Date) -> Packet {
        let data = Data(bytes)
        return Packet(id: id, timestamp: t, relative: t.timeIntervalSince(start), length: data.count, captured: data.count,
                      data: data, decoded: PacketDecoder.decode(data))
    }

    static let serverMAC = "00:50:56:0a:00:0a"
    static let routerMAC = "00:1a:1e:00:00:01"

    /// DHCP on VLAN 20 unanswered (9 min in), a healthy lease on VLAN 30, DNS failing at
    /// 10.1.0.53 (11 min in).
    static func badDayPackets(start t0: Date) -> [Packet] {
        var frames: [(Double, [UInt8])] = []
        // Two clients on VLAN 20: Discovers, no Offer.
        for (n, (client, xid)) in [("02:00:5e:14:00:21", UInt32(0x2a01)), ("02:00:5e:14:00:22", UInt32(0x2a02))].enumerated() {
            for (k, dt) in [0.0, 4, 12, 28].enumerated() where !(n == 1 && k == 3) {
                frames.append((540 + Double(n) * 2 + dt, udp4(srcMAC: client, dstMAC: "ff:ff:ff:ff:ff:ff", src: "0.0.0.0", dst: "255.255.255.255",
                                                              sport: 68, dport: 67, vlan: 20, dhcp(op: 1, type: 1, xid: xid, client: client))))
            }
        }
        // VLAN 30 works.
        let ok = "02:00:5e:1e:00:31"
        frames.append((545, udp4(srcMAC: ok, dstMAC: "ff:ff:ff:ff:ff:ff", src: "0.0.0.0", dst: "255.255.255.255", sport: 68, dport: 67, vlan: 30,
                                 dhcp(op: 1, type: 1, xid: 0x3b01, client: ok))))
        frames.append((545.02, udp4(srcMAC: routerMAC, dstMAC: ok, src: "10.1.30.1", dst: "10.1.30.60", sport: 67, dport: 68, vlan: 30,
                                    dhcp(op: 2, type: 2, xid: 0x3b01, client: ok, yiaddr: "10.1.30.60", server: "10.1.0.10", lease: 86_400))))
        frames.append((545.05, udp4(srcMAC: ok, dstMAC: "ff:ff:ff:ff:ff:ff", src: "0.0.0.0", dst: "255.255.255.255", sport: 68, dport: 67, vlan: 30,
                                    dhcp(op: 1, type: 3, xid: 0x3b01, client: ok))))
        frames.append((545.08, udp4(srcMAC: routerMAC, dstMAC: ok, src: "10.1.30.1", dst: "10.1.30.60", sport: 67, dport: 68, vlan: 30,
                                    dhcp(op: 2, type: 5, xid: 0x3b01, client: ok, yiaddr: "10.1.30.60", server: "10.1.0.10", lease: 86_400))))
        // DNS at 10.1.0.53: 20 queries from 10.1.30.60, 8 answered, 7 SERVFAIL, 5 unanswered.
        let names = ["files.corp.example", "intranet.corp.example", "mail.corp.example", "erp.corp.example", "www.apple.com"]
        for k in 0..<20 {
            let t = 660 + Double(k) * 2.5
            let name = names[k % names.count]
            let sport = 53_000 + k
            frames.append((t, udp4(srcMAC: ok, dstMAC: routerMAC, src: "10.1.30.60", dst: "10.1.0.53", sport: sport, dport: 53, vlan: 30,
                                   dns(id: 0x4000 + k, name: name, response: false))))
            if k % 4 == 3 { continue }                                  // 5 unanswered
            let fail = k % 4 != 0 && k < 14                              // SERVFAIL
            frames.append((t + 0.03, udp4(srcMAC: routerMAC, dstMAC: ok, src: "10.1.0.53", dst: "10.1.30.60", sport: 53, dport: sport, vlan: 30,
                                          dns(id: 0x4000 + k, name: name, response: true, rcode: fail ? 2 : 0, answer: fail ? nil : "10.1.40.\(10 + k)"))))
        }
        // A duplicate address on VLAN 30.
        frames.append((720, arp(request: false, senderMAC: "02:00:5e:1e:00:44", senderIP: "10.1.30.44", targetIP: "10.1.30.1", targetMAC: routerMAC, vlan: 30)))
        frames.append((722, arp(request: false, senderMAC: "02:00:5e:1e:00:99", senderIP: "10.1.30.44", targetIP: "10.1.30.1", targetMAC: routerMAC, vlan: 30)))
        frames.append((723, arp(request: true, senderMAC: "02:00:5e:1e:00:44", senderIP: "10.1.30.44", targetIP: "10.1.30.44", vlan: 30)))
        return frames.sorted { $0.0 < $1.0 }.enumerated().map { i, f in
            packet(f.1, at: t0.addingTimeInterval(f.0), id: i + 1, start: t0)
        }
    }

    /// The TCP flows demo (a lost segment, an unanswered SSH, a slow API, a refused port),
    /// moved to 10 min into the day.
    static func demoFlows(start t0: Date) -> [Packet] {
        let shift = t0.addingTimeInterval(600).timeIntervalSince(TCPFlowDemo.base)
        return TCPFlowDemo.packets().map { p in
            Packet(id: p.id, timestamp: p.timestamp.addingTimeInterval(shift), relative: p.relative, length: p.length,
                   captured: p.captured, data: p.data, decoded: p.decoded)
        }
    }

    /// Two Interfaces walks of CORE-CX-6300 five minutes apart: 1/1/24 enabled but down with
    /// growing errors, 1/1/7 at half duplex.
    static func coreSwitchWalks(start t0: Date) -> [SNMPSnapshot] {
        func row(_ i: UInt32, _ name: String, admin: String = "up", oper: String = "up", errors: UInt64 = 0, since: UInt32 = 8_640_000) -> InterfaceRow {
            var r = InterfaceRow(index: i)
            r.name = name; r.descr = name; r.type = "ethernetCsmacd"; r.admin = admin; r.oper = oper
            r.speedBits = 1_000_000_000; r.inErrors = errors; r.lastChange = 100; r.sinceChange = since
            return r
        }
        var values: [OID: String] = [.sysName: "CORE-CX-6300", .sysUpTime: "10d 00:00:00 (86400000)"]
        values[FindingRules.dot3Duplex.appending(7)] = "halfDuplex(2)"
        let first = SNMPSnapshot(host: "10.1.0.1", taken: t0.addingTimeInterval(420), sysName: "CORE-CX-6300", sysUpTime: 86_400_000,
                                 interfaces: [row(1, "1/1/1"), row(7, "1/1/7"), row(24, "1/1/24", oper: "down", errors: 1_204, since: 30_000)],
                                 values: values)
        var second = first
        second = SNMPSnapshot(host: "10.1.0.1", taken: t0.addingTimeInterval(720), sysName: "CORE-CX-6300", sysUpTime: 86_430_000,
                              interfaces: [row(1, "1/1/1"), row(7, "1/1/7"), row(24, "1/1/24", oper: "down", errors: 4_988, since: 60_000)],
                              values: values)
        return [first, second]
    }
}
