import AppKit
import Combine
import SwiftUI
import UniformTypeIdentifiers

/// What the Authentication pane has selected — the attempt and the step — and how that survives
/// a re-analysis. Every analysis renumbers attempts (a live capture's ring evicts the oldest, so
/// the ids shift) and steps (a third TLS round folds the first two into one "×3" row; eviction
/// drops the first ones): an attempt is found again by client and start, else by its frames, else
/// the client's nearest; a step by its frames.
nonisolated struct AuthSelectionState: Sendable, Equatable {
    var selection: Int?
    var client: String?
    var start: Date?
    var event: Int?
    /// The frames of the step to select once `selection` has moved to its attempt.
    var pendingEventFrames: [Int]?

    /// `onChange(of: selection)`: a click on another attempt, or the move `apply` made.
    mutating func selectionChanged(in sessions: [AuthSession]) {
        let s = sessions.first { $0.id == selection }
        event = s.flatMap { s in pendingEventFrames.flatMap { Self.event(in: s, carrying: $0) } }
        pendingEventFrames = nil
        client = s?.client
        start = s?.firstTime
    }

    /// The step of `session` that carries any of `frames` (nil when they all left the ring).
    static func event(in session: AuthSession, carrying frames: [Int]) -> Int? {
        guard !frames.isEmpty else { return nil }
        let set = Set(frames)
        return session.events.first { e in e.packetIDs.contains { set.contains($0) } }?.id
    }

    /// A new analysis (`previous` = the attempts it replaces).
    mutating func apply(_ result: [AuthSession], previous: [AuthSession]) {
        let old = previous.first { $0.id == selection }
        let shownFrames = old.flatMap { s in event.flatMap { id in s.events.first { $0.id == id }?.packetIDs } } ?? []
        guard let client else {
            if let s = selection, !result.contains(where: { $0.id == s }) { selection = nil }
            event = nil
            return
        }
        let same = result.filter { $0.client == client }
        let oldFrames = Set(old?.packetIDs ?? [])
        let match = same.first { $0.firstTime == start }
            ?? same.first { s in s.packetIDs.contains { oldFrames.contains($0) } }
            ?? same.min { a, b in
                abs(a.firstTime.timeIntervalSince(start ?? a.firstTime)) < abs(b.firstTime.timeIntervalSince(start ?? b.firstTime))
            }
            // Its frames now belong to another client's attempt: a switch port's unanswered
            // request became the attempt of the device that answered it (the selection vanished).
            ?? (oldFrames.isEmpty ? nil : result.first { s in s.packetIDs.contains { oldFrames.contains($0) } })
        guard let match else {
            selection = nil
            event = nil
            pendingEventFrames = nil
            return
        }
        if match.id == selection {
            event = Self.event(in: match, carrying: shownFrames)
            start = match.firstTime
            self.client = match.client
        } else {
            pendingEventFrames = shownFrames
            selection = match.id
        }
    }

    /// `-demoAuthSelect <text>`: the first attempt whose row contains the text (or whose id it
    /// is), with its first step that has a problem.
    mutating func demoSelect(_ text: String, in result: [AuthSession]) {
        let want = text.lowercased()
        guard let pick = Int(want).flatMap({ n in result.first { $0.id == n } }) ?? result.first(where: { $0.searchText.contains(want) })
        else { return }
        pendingEventFrames = pick.events.first { $0.problem != nil }?.packetIDs
        selection = pick.id
    }
}

/// Authentication: every 802.1X / MAC auth / PSK / captive-portal attempt in the capture, one row
/// per client attempt on the left, its steps as a ladder (Client | Switch / AP | RADIUS) on the
/// right. Analysis runs off the main actor on every store change (at most once a second).
struct AuthView: View {
    /// Not observed as a whole (a live capture publishes 10 times a second): the two changes
    /// that matter are subscribed to below, as the Flows pane does.
    private let store = AppModel.shared.packets
    @Environment(\.colorScheme) private var colorScheme

    @State private var sessions: [AuthSession] = []
    /// Bumped with every new `sessions` (the rows cache's key).
    @State private var sessionsVersion = 0
    @State private var rowsCache = AuthRowsCache()
    @State private var analysing = false
    @State private var analysedAt: Date?
    @State private var analysisToken = 0
    @State private var scheduledTask: Task<Void, Never>?
    @State private var analysisTask: Task<Void, Never>?
    @State private var rerun = false
    /// On screen (between appeared and disappeared): store publishes that reach a pane after it
    /// left — a window closed without tearing its view down, a publish already in flight — start
    /// nothing.
    @State private var visible = false
    /// The store's stamp the last analysis read: a debounced re-analysis with nothing new skips.
    @State private var analysedStamp: PacketStore.DataStamp?
    @State private var problemsOnly = false
    @State private var filterText = ""
    @State private var methodFilter: AuthMethodFilter = .all
    @State private var selection: Int?
    @State private var selectedClient: String?
    @State private var selectedStart: Date?
    @State private var selectedEvent: Int?
    /// The frames of the step to select once `selection` has moved to its attempt.
    @State private var pendingEventFrames: [Int]?
    @State private var sortOrder: [KeyPathComparator<AuthRow>] = AuthRow.defaultOrder
    @State private var ladderWidth: CGFloat = 560
    @State private var paneWidth: CGFloat = 0
    @FocusState private var filterFocused: Bool

    /// `-demoAuthSelect <text>`: select the first attempt whose client, user, method or result contains it.
    private static let demoSelect = CommandLine.value(after: "-demoAuthSelect")

    var body: some View {
        let _ = PaneProbe.ran("body.auth")
        VStack(alignment: .leading, spacing: 0) {
            TimelineView(.periodic(from: .now, by: 1)) { context in
                PaneHeader(pane: .auth, status: heading, detail: subtitle(now: context.date), problem: anyFailed) {
                    headerActions
                }
            }
            .paneColumn()
            .padding(.top, Metrics.headerTop)
            .padding(.bottom, 14)

            PaneStrip { strip }

            // The attempts and the ladder, one hairline (the split's divider) between them.
            HSplitView {
                table
                    .frame(minWidth: 290, idealWidth: 440, maxWidth: .infinity, maxHeight: .infinity)
                    .padding(.trailing, 14)
                ladderPane
                    .frame(minWidth: 390, maxWidth: .infinity, maxHeight: .infinity)   // 290 + 390 + gaps fit the 1000 pt window's 716 pt column
                    .padding(.leading, 18)
            }
            .paneColumn()
            .padding(.bottom, 14)
        }
        .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { paneWidth = $0 }
        .paneKeyCommands(find: { filterFocused = true },
                         copy: { if selectedSession == nil { NSSound.beep() } else { copySession() } })
        .task { appeared() }
        .onDisappear { disappeared() }
        .onReceive(store.$generation.removeDuplicates().dropFirst()) { _ in scheduleAnalysis() }
        .onReceive(store.$totalReceived.removeDuplicates().dropFirst()) { _ in scheduleAnalysis() }
        .onChange(of: selection) { selectionChanged() }
    }

    private func appeared() {
        PaneProbe.ran("auth.appeared")
        // `-demoPane auth -demoPcap <file>`: the Packets pane (which opens it) never appeared.
        if store.fileURL == nil, store.packets.isEmpty, DemoFlags.openPcap() {
            AppModel.shared.mainPane = .auth
        }
        visible = true
        startAnalysis()
    }

    private func disappeared() {
        PaneProbe.ran("auth.disappeared")
        visible = false
        scheduledTask?.cancel(); scheduledTask = nil
        analysisTask?.cancel(); analysisTask = nil
        rerun = false
        analysing = false
    }

    private func selectionChanged() {
        var state = selectionState
        state.selectionChanged(in: sessions)
        selectionState = state
    }

    /// The selection @State as one value (the rules live in `AuthSelectionState`, tested).
    private var selectionState: AuthSelectionState {
        get {
            AuthSelectionState(selection: selection, client: selectedClient, start: selectedStart, event: selectedEvent,
                               pendingEventFrames: pendingEventFrames)
        }
        nonmutating set {
            if selectedClient != newValue.client { selectedClient = newValue.client }
            if selectedStart != newValue.start { selectedStart = newValue.start }
            if selectedEvent != newValue.event { selectedEvent = newValue.event }
            if pendingEventFrames != newValue.pendingEventFrames { pendingEventFrames = newValue.pendingEventFrames }
            if selection != newValue.selection { selection = newValue.selection }
        }
    }

    // MARK: Header and strip

    /// The state as the page's status words (the headline without its full stop).
    private var heading: String {
        if sessions.isEmpty { return analysing ? "Reading authentication traffic…" : "No authentication traffic yet" }
        let line = rowsCache.headline(version: sessionsVersion) { Self.headline(sessions) }
        return line.hasSuffix(".") ? String(line.dropLast()) : line
    }

    /// Red status words when a client's latest attempt failed (read from the cached headline: the
    /// header ticks every second, and the count walks every attempt).
    private var anyFailed: Bool {
        !sessions.isEmpty && !heading.hasSuffix("none failed")
    }

    /// "3 clients authenticated, 1 failed." — each client counted once, by its latest attempt
    /// that ended (a client accepted and later rejected is a failure now, not both; one still in
    /// progress keeps its earlier outcome).
    nonisolated static func headline(_ sessions: [AuthSession]) -> String {
        var latest: [String: AuthSession] = [:]
        // A switch port nobody answered is not a client that failed.
        for s in sessions where s.result != .inProgress && !s.isPortOnly {
            if let l = latest[s.client], l.firstTime > s.firstTime { continue }
            latest[s.client] = s
        }
        let failed = latest.values.filter { $0.result.isFailure }.count
        let ok = latest.values.filter { $0.result == .accepted }.count
        let noun = ok == 1 ? "client" : "clients"
        return "\(Format.count(ok)) \(noun) authenticated, \(failed == 0 ? "none" : Format.count(failed)) failed."
    }

    private func subtitle(now: Date) -> String {
        var parts = [store.fileURL?.lastPathComponent ?? "live capture"]
        if analysing { parts.append("analysing…") }
        else if let at = analysedAt { parts.append("re-analysed \(Self.ago(now.timeIntervalSince(at)))") }
        return parts.joined(separator: " · ")
    }

    private static func ago(_ s: Double) -> String {
        if s < 60 { return "\(max(0, Int(s))) s ago" }
        if s < 3600 { return "\(Int(s / 60)) min ago" }
        return "\(Int(s / 3600)) h ago"
    }

    /// Word links on the status line. Four do not fit beside the status at the 1000 pt window, so
    /// the two used least (Export…, Auth packets) sit at the tool row's right. "analysing…" is in
    /// the status line's facts, so no spinner.
    @ViewBuilder private var headerActions: some View {
        let _ = PaneProbe.button("auth.Re-analyse", enabled: !analysing) { startAnalysis() }
        let _ = PaneProbe.button("auth.Copy summary", enabled: !rows.isEmpty) { copyOverview() }
        Button("Re-analyse") { startAnalysis() }
            .buttonStyle(.quietLink)
            .fixedSize()        // a long file name in the facts truncates them, never wraps a link
            .disabled(analysing)
            .help("Read the packets again")
        Button("Copy summary") { copyOverview() }
            .buttonStyle(.quietLink)
            .fixedSize()
            .disabled(rows.isEmpty)
            .help("Copy the attempts shown as plain text, one line each, with their problems")
    }

    @ViewBuilder private var strip: some View {
        FilterField(text: $filterText, prompt: "Filter MAC, user, SSID…", mono: false,
                    help: "MAC, user, NAS, SSID, method or result — matches as you type. ⌘F to focus, Esc to clear", focus: $filterFocused)
            .frame(minWidth: 120, maxWidth: 320)
        // The method choice as words (no segmented control).
        QuietTabs(items: AuthMethodFilter.allCases.map { ($0, $0.rawValue) }, selection: $methodFilter, spacing: 14, size: 12)
            .help("Show one kind of authentication")
            .accessibilityLabel("Method")
        QuietToolToggle("Problems only", isOn: $problemsOnly, help: "Show only attempts that failed or have a warning")
        Spacer(minLength: 8)
        if !shownText.isEmpty {
            Text(shownText)
                .font(Theme.body)
                .foregroundStyle(Theme.text2)
                .lineLimit(1)
                .fixedSize()
        }
        Button("Export…") { exportPNG() }
            .buttonStyle(.quietLink)
            .fixedSize()
            .disabled(selectedSession == nil)
            .help("Save the ladder of the selected attempt as a PNG")
        let _ = PaneProbe.button("auth.Auth packets") { showAuthPackets() }
        Button("Auth packets") { showAuthPackets() }
            .buttonStyle(.quietLink)
            .fixedSize()
            .help("Open the Packets pane filtered to authentication traffic:\n\(AuthDecoder.packetFilterPreset)")
    }

    /// How many attempts the filters keep, when they keep fewer than all.
    private var shownText: String {
        let n = rows.count
        return n == sessions.count ? "" : "\(Format.count(n)) of \(Format.count(sessions.count))"
    }

    // MARK: Table

    /// The table's rows, filtered and sorted once per change of the attempts, the filters or the
    /// order: the body asks for them several times per update, and the header's once-a-second
    /// tick re-evaluated them all (10,000 attempts: ~85 ms of main thread every second, Debug).
    private var rows: [AuthRow] {
        rowsCache.rows(AuthRowsCache.Key(version: sessionsVersion, problemsOnly: problemsOnly, method: methodFilter,
                                         text: filterText, order: sortOrder)) {
            Self.rows(sessions, problemsOnly: problemsOnly, method: methodFilter, text: filterText, order: sortOrder)
        }
    }

    /// The table's rows: Problems only, the method chips and the text filter together, sorted.
    nonisolated static func rows(_ sessions: [AuthSession], problemsOnly: Bool, method: AuthMethodFilter, text: String,
                                 order: [KeyPathComparator<AuthRow>]) -> [AuthRow] {
        let needle = text.trimmingCharacters(in: .whitespaces).lowercased()
        return sessions.lazy
            .filter { !problemsOnly || $0.health != .ok }
            .filter { method.matches($0) }
            .filter { needle.isEmpty || $0.searchText.contains(needle) }
            .map(AuthRow.init)
            .sorted(using: order)
    }

    /// The attempts of `rows`, in the rows' order (Copy summary). By id through a dictionary: a
    /// search of every attempt per row froze the pane for seconds on a 10,000-attempt capture.
    nonisolated static func shown(_ rows: [AuthRow], of sessions: [AuthSession]) -> [AuthSession] {
        let byID = Dictionary(sessions.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        return rows.compactMap { byID[$0.id] }
    }

    private var table: some View {
        Table(rows, selection: $selection, sortOrder: $sortOrder) {
            // No health dot: the Result word says it (Reject / Timeout in red, Accept muted).
            TableColumn("Client MAC", value: \AuthRow.client) { r in
                Text(r.client).font(.system(size: 11.5, design: .monospaced)).identifierText()
            }
            .width(min: 100, ideal: 124)
            // Result right after the client: at the 1000 pt window only two columns fit, and the
            // outcome must not be the part that scrolls away.
            TableColumn("Result", value: \AuthRow.resultRank) { r in
                StatusPill(text: r.resultLabel, kind: AuthStyle.pillKind(r.result))
                    .help([r.result.detail ?? r.resultLabel, r.reasons].filter { !$0.isEmpty }.joined(separator: "\n"))
            }
            .width(min: 64, ideal: 80)
            TableColumn("User", value: \AuthRow.user) { r in
                Text(r.user.isEmpty ? "—" : r.user).proseText().foregroundStyle(r.user.isEmpty ? Theme.faintText : Theme.text)
            }
            .width(min: 60, ideal: 110)
            TableColumn("Method", value: \AuthRow.method) { r in Text(r.method).proseText() }
                .width(min: 60, ideal: 120)
            TableColumn("NAS / SSID", value: \AuthRow.nas) { r in
                Text(r.nas.isEmpty ? "—" : r.nas).proseText().foregroundStyle(r.nas.isEmpty ? Theme.faintText : Theme.text)
            }
            .width(min: 60, ideal: 130)
            TableColumn("VLAN · Role", value: \AuthRow.vlanRole) { r in
                Text(r.vlanRole.isEmpty ? "—" : r.vlanRole).proseText().foregroundStyle(r.vlanRole.isEmpty ? Theme.faintText : Theme.text)
            }
            .width(min: 50, ideal: 110)
            TableColumn("IP", value: \AuthRow.ip) { r in
                Text(r.ip.isEmpty ? "—" : r.ip).font(.system(size: 11.5, design: .monospaced)).identifierText()
                    .foregroundStyle(r.ip.isEmpty ? Theme.faintText : Theme.text)
            }
            .width(min: 60, ideal: 96)
            TableColumn("Time", value: \AuthRow.start) { r in
                Text(Format.clock.string(from: r.start)).font(.system(size: 11.5, design: .monospaced)).monospacedDigit()
            }
            .width(min: 70, ideal: 90)
            TableColumn("Retries", value: \AuthRow.retries) { r in
                Text(r.retries == 0 ? "—" : "\(r.retries)").monospacedDigit()
                    .foregroundStyle(r.retries == 0 ? Theme.faintText : Theme.warn)
                    .frame(maxWidth: .infinity, alignment: .trailing)
            }
            .width(min: 40, ideal: 50)
        }
        .font(.system(size: 12))
        .quietTable(selection: selection)
        .tablePanel()
        .overlay {
            if rows.isEmpty {
                TableEmptyOverlay(text: sessions.isEmpty
                    ? (analysing ? "Reading…" : "No 802.1X, RADIUS, PSK handshake or captive portal in the capture yet.")
                    : "No attempt matches the filter.")
            }
        }
    }

    // MARK: Ladder side

    private var selectedSession: AuthSession? {
        guard let selection else { return nil }
        return sessions.first { $0.id == selection }
    }

    /// The selected attempt the LabDC inspector way: the user as the 20 pt subtitle, facts
    /// label-above, then the timeline, the ladder and its footer, flush left.
    @ViewBuilder private var ladderPane: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let session = selectedSession {
                let layout = AuthLadderLayout.make(session: session, width: ladderWidth)
                let _ = PaneProbe.drewAuth(session, event: selectedEvent)
                AuthLadderHeader(session: session)
                AuthTimeline(session: session, selected: $selectedEvent)
                    .padding(.bottom, 10)
                Rectangle().fill(Theme.hairline).frame(height: 1)
                // The tap below, for tests (a unit-test host cannot click a SwiftUI canvas).
                let _ = PaneProbe.tapTarget("auth.ladder") { point in
                    let hit = layout.hit(point)
                    selectedEvent = hit == selectedEvent ? nil : hit
                }
                ScrollView(.vertical) {
                    AuthLadderCanvas(layout: layout, selected: selectedEvent)
                        .frame(height: layout.height)
                        .contentShape(Rectangle())
                        .onTapGesture(coordinateSpace: .local) { point in
                            let hit = layout.hit(point)
                            selectedEvent = hit == selectedEvent ? nil : hit
                        }
                }
                .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { ladderWidth = max(380, $0) }
                .id(session.id)
                Rectangle().fill(Theme.hairline).frame(height: 1)
                selectionFooter(session)
            } else if sessions.isEmpty {
                let _ = PaneProbe.drewAuth(nil, event: nil)
                ScrollView { AuthEmptyGuide().padding(.top, 4).padding(.bottom, 20) }
            } else {
                let _ = PaneProbe.drewAuth(nil, event: nil)
                TableEmptyOverlay(text: "Select an attempt on the left to see its steps.")
            }
            AuthLegend()
        }
    }

    @ViewBuilder private func selectionFooter(_ session: AuthSession) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            if let id = selectedEvent, let event = session.events.first(where: { $0.id == id }) {
                Text(event.label)
                    .font(Theme.emphasis)
                    .foregroundStyle(event.problem != nil ? Theme.err : Theme.text)
                    .proseText()
                    .help(event.label + (event.detail.map { "\n" + $0 } ?? ""))
                Text(Self.framesText(event.packetIDs))
                    .font(Theme.mono)
                    .foregroundStyle(Theme.faintText)
                    .identifierText()
                    .textSelection(.enabled)
                Spacer(minLength: 8)
                let _ = PaneProbe.button("auth.Show packets", enabled: !event.packetIDs.isEmpty) { showPackets(event.packetIDs) }
                Button("Show packets") { showPackets(event.packetIDs) }
                    .buttonStyle(.quietLink)
                    .fixedSize()
                    .disabled(event.packetIDs.isEmpty)
            } else {
                Text("Click a step to see its packets.")
                    .font(Theme.body)
                    .foregroundStyle(Theme.faintText)
                    .proseText()
                Spacer(minLength: 8)
                let _ = PaneProbe.button("auth.Show packets") { showPackets(session.packetIDs) }
                Button("Show packets") { showPackets(session.packetIDs) }
                    .buttonStyle(.quietLink)
                    .fixedSize()
                    .help("Every packet of this attempt in the Packets pane")
            }
            let _ = PaneProbe.button("auth.Copy") { copySession() }
            Button("Copy") { copySession() }
                .buttonStyle(.quietLink)
                .fixedSize()
                .help("Copy this attempt as plain text: who, where, result, reasons and every step (⌘⇧C)")
        }
        .frame(height: 38)
    }

    nonisolated static func framesText(_ ids: [Int]) -> String {
        guard !ids.isEmpty else { return "no packets" }
        let shown = ids.prefix(16).map(String.init).joined(separator: ", ")
        let more = ids.count > 16 ? " … +\(ids.count - 16)" : ""
        return "\(ids.count == 1 ? "frame" : "frames") \(shown)\(more)"
    }

    /// `frame:1 OR frame:2 …` (as many as a filter takes: the matcher folds them into one
    /// lookup), else the frame range narrowed to authentication traffic. (From 51 frames — a PEAP
    /// attempt with its RADIUS side — the range showed every other client's DHCP, DNS and EAPOL
    /// of those seconds under "every packet of this attempt".)
    nonisolated static func packetFilter(_ ids: [Int]) -> String {
        guard ids.count > Query.maxTerms, let lo = ids.min(), let hi = ids.max() else {
            return ids.map { "frame:\($0)" }.joined(separator: " OR ")
        }
        return "frame:>=\(lo) frame:<=\(hi) (\(AuthDecoder.packetFilterPreset))"
    }

    private func showPackets(_ ids: [Int]) {
        guard !ids.isEmpty else { return }
        AppModel.shared.mainPane = .packets
        NotificationCenter.default.post(name: .sheepLogPacketFilter, object: Self.packetFilter(ids))
    }

    private func showAuthPackets() {
        AppModel.shared.mainPane = .packets
        NotificationCenter.default.post(name: .sheepLogPacketFilter, object: AuthDecoder.packetFilterPreset)
    }

    // MARK: Analysis

    private func scheduleAnalysis() {
        guard visible, scheduledTask == nil else { return }
        scheduledTask = Task {
            LeakProbe.add("Auth.scheduled")
            defer { LeakProbe.remove("Auth.scheduled") }
            try? await Task.sleep(for: .seconds(1))
            guard !Task.isCancelled else { return }
            scheduledTask = nil
            // Nothing new since the last analysis read the packets: no second analysis of them.
            if store.dataStamp == analysedStamp { return }
            startAnalysis()
        }
    }

    private func startAnalysis() {
        guard visible else { return }
        if analysisTask != nil { rerun = true; return }
        analysisTask = Task {
            await analyse()
            guard !Task.isCancelled else { return }
            analysisTask = nil
            if rerun { rerun = false; if store.dataStamp != analysedStamp { scheduleAnalysis() } }
        }
    }

    private func analyse() async {
        LeakProbe.add("Auth.analysis")
        defer { LeakProbe.remove("Auth.analysis") }
        PaneProbe.authAnalysisStarted()
        analysisToken += 1
        let token = analysisToken
        analysing = true
        let packets = store.packets
        analysedStamp = store.dataStamp
        let work = Task.detached(priority: .userInitiated) {
            AuthSessions.build(packets) { Task.isCancelled }
        }
        let result = await withTaskCancellationHandler { await work.value } onCancel: { work.cancel() }
        guard token == analysisToken, !Task.isCancelled else { return }
        apply(result)
    }

    private func apply(_ result: [AuthSession]) {
        let previous = sessions
        sessions = result
        sessionsVersion &+= 1
        analysing = false
        analysedAt = Date()
        var state = selectionState
        state.apply(result, previous: previous)
        if state.selection == nil, let want = Self.demoSelect, !result.isEmpty, DemoFlags.firstRun("auth.select") {
            state.demoSelect(want, in: result)
        }
        selectionState = state
    }

    // MARK: Copy and export

    private func copySession() {
        guard let s = selectedSession else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(AuthSummary.text(s), forType: .string)
    }

    private func copyOverview() {
        let shown = Self.shown(rows, of: sessions)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(AuthSummary.overview(shown, source: store.fileURL?.lastPathComponent ?? "live capture"),
                                       forType: .string)
    }

    private func exportPNG() {
        guard let s = selectedSession else { return }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.png]
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = "auth \(s.client) \(Format.compactStamp.string(from: s.firstTime)).png"
            .replacingOccurrences(of: ":", with: "-")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        writePNG(session: s, to: url)
    }

    private func writePNG(session: AuthSession, to url: URL) {
        let layout = AuthLadderLayout.make(session: session, width: max(ladderWidth, 680))
        let content = AuthLadderExport(session: session, layout: layout).environment(\.colorScheme, colorScheme)
        let renderer = ImageRenderer(content: content)
        let side = max(layout.width, layout.height + 140, 1)
        renderer.scale = max(0.25, min(2, 16_384 / side))
        guard let cg = renderer.cgImage,
              let data = NSBitmapImageRep(cgImage: cg).representation(using: .png, properties: [:]) else {
            AppModel.shared.report("Could not render the diagram.")
            return
        }
        do { try data.write(to: url, options: .atomic) }
        catch { AppModel.shared.report("Could not save \(url.lastPathComponent).", detail: error.localizedDescription) }
    }
}

/// The Authentication table's rows and headline, kept until what they are made of changes (a
/// reference in @State: filling it while the body runs changes no state).
@MainActor
final class AuthRowsCache {
    struct Key: Equatable {
        var version: Int
        var problemsOnly: Bool
        var method: AuthMethodFilter
        var text: String
        var order: [KeyPathComparator<AuthRow>]
    }

    private var key: Key?
    private var value: [AuthRow] = []
    private var headlineVersion: Int?
    private var headlineText = ""

    func rows(_ key: Key, _ make: () -> [AuthRow]) -> [AuthRow] {
        if key == self.key { return value }
        PaneProbe.authRowsSorted()
        value = make()
        self.key = key
        return value
    }

    func headline(version: Int, _ make: () -> String) -> String {
        if version == headlineVersion { return headlineText }
        headlineText = make()
        headlineVersion = version
        return headlineText
    }
}

// MARK: - Rows and style

nonisolated struct AuthRow: Identifiable {
    let id: Int
    let health: AuthHealth
    let healthRank: Int
    let client: String
    let user: String
    let method: String
    let nas: String
    let result: AuthResult
    let resultLabel: String
    let resultRank: Int
    let vlanRole: String
    let ip: String
    let start: Date
    let retries: Int
    let reasons: String

    init(_ s: AuthSession) {
        id = s.id
        health = s.health
        healthRank = s.health.rawValue
        client = s.client
        user = s.user ?? ""
        method = s.methodLabel
        nas = s.nasAndPort
        result = s.result
        resultLabel = s.result.label
        resultRank = s.result.rank
        vlanRole = s.vlanRole
        ip = s.ip ?? ""
        start = s.firstTime
        retries = s.retries
        reasons = s.reasons.joined(separator: "\n")
    }

    static let defaultOrder = [KeyPathComparator(\AuthRow.healthRank), KeyPathComparator(\AuthRow.start)]
}

enum AuthStyle {
    static func healthColor(_ h: AuthHealth) -> Color {
        switch h {
        case .ok: Theme.ok
        case .warn: Theme.warn
        case .bad: Theme.err
        }
    }

    static func pillKind(_ r: AuthResult) -> StatusPill.Kind {
        switch r {
        case .accepted: .ok
        case .rejected, .timeout: .bad
        case .inProgress: .neutral
        }
    }

    static func color(_ e: AuthEvent) -> Color {
        if e.problem != nil { return Theme.err }
        switch e.kind {
        case .eapol, .eapRequest, .eapResponse, .tlsRounds, .key: return e.kind == .key(4) ? Theme.ok : Theme.accent
        case .eapSuccess, .radiusAccept, .captivePassed, .dns: return Theme.ok
        case .eapFailure, .radiusReject: return Theme.err
        case .radiusRequest, .radiusChallenge, .accounting, .coa: return Theme.text2
        case .dhcp, .captiveProbe: return Theme.dimText
        case .captiveRedirect, .captiveLogin, .captivePortalPage: return Theme.caution
        }
    }
}

// MARK: - Header, legend, empty guide

/// The selected attempt, LabDC's inspector shape: the user (or the client) as the 20 pt subtitle
/// with where it happened under it (mono, faint), the facts label-above — red only for what is
/// wrong — and the reasons and notes as sentences. No dot: the Result field says it.
private struct AuthLadderHeader: View {
    let session: AuthSession

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text(session.user ?? session.client)
                    .font(Theme.subtitle)
                    .foregroundStyle(Theme.text)
                    .proseText()
                if !endpoints.isEmpty {
                    Text(endpoints)
                        .font(Theme.mono)
                        .foregroundStyle(Theme.faintText)
                        .identifierText()
                        .textSelection(.enabled)
                }
            }
            CaptureFactWrap(spacing: 24, lineSpacing: 10) {
                ForEach(Array(facts.enumerated()), id: \.offset) { _, fact in
                    QuietField(fact.0) {
                        Text(fact.1)
                            .font(Theme.body)
                            .foregroundStyle(fact.2 ? Theme.err : Theme.text)
                            .lineLimit(1)
                            .fixedSize()
                            .textSelection(.enabled)
                    }
                    .fixedSize()
                }
            }
            if !session.reasons.isEmpty {
                Text(session.reasons.joined(separator: " · "))
                    .font(Theme.detail)
                    .foregroundStyle(session.health == .ok ? Theme.text2 : Theme.err)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
            if !session.notes.isEmpty {
                Text(session.notes.joined(separator: " · "))
                    .font(Theme.caption)
                    .foregroundStyle(Theme.faintText)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.top, 2)
        .padding(.bottom, 14)
    }

    private var endpoints: String {
        var parts: [String] = []
        if session.user != nil { parts.append(session.client) }
        if !session.nasAndPort.isEmpty { parts.append(session.nasAndPort) }
        else if let m = session.nasMAC { parts.append("AP \(m)") }
        return parts.joined(separator: "  ·  ")
    }

    /// Label, value, wrong?
    private var facts: [(String, String, Bool)] {
        var out: [(String, String, Bool)] = [("Method", session.methodLabel, false)]
        var result = session.result.label
        if let d = session.result.detail, d.count <= 40 { result += ": \(d)" }
        out.append(("Result", result, session.result.isFailure))
        if let mac = session.macStageResult { out.append(("MAC stage", mac.label, mac.isFailure)) }
        if !session.radiusRTTs.isEmpty {
            let slowest = session.radiusRTTs.max() ?? 0
            let avg = session.radiusRTTs.reduce(0, +) / Double(session.radiusRTTs.count)
            out.append(("RADIUS RTT", AuthSessions.msText(avg) + (session.radiusRTTs.count > 1 ? " (max \(AuthSessions.msText(slowest)))" : ""),
                        slowest > 1))
        }
        if session.retries > 0 { out.append(("Retries", "\(session.retries)", true)) }
        if let v = session.vlan { out.append(("VLAN", "\(v)", false)) }
        if let r = session.role { out.append(("Role", r, false)) }
        if let ip = session.ip { out.append(("IP", ip, false)) }
        out.append(("Took", AuthSessions.msText(session.duration), false))
        return out
    }
}

/// The ladder's own key, one faint row (two when the ladder is narrow).
private struct AuthLegend: View {
    var body: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 14) { first; second }.fixedSize()
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 14) { first }.fixedSize()
                HStack(spacing: 14) { second }.fixedSize()
            }
        }
        .font(Theme.caption)
        .foregroundStyle(Theme.faintText)
        .lineLimit(1)
        .fixedSize(horizontal: false, vertical: true)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.top, 6)
        .padding(.bottom, 2)
    }

    @ViewBuilder private var first: some View {
        line(Theme.accent, "802.1X / EAPOL-Key")
        line(Theme.text2, "RADIUS")
        line(Theme.ok, "Accept / Success")
    }

    @ViewBuilder private var second: some View {
        line(Theme.err, "Reject / problem")
        line(Theme.caution, "Captive portal")
        line(Theme.dimText, "DHCP / DNS")
    }

    private func line(_ c: Color, _ t: String) -> some View {
        HStack(spacing: 4) { Rectangle().fill(c).frame(width: 14, height: 1.5); Text(t) }
    }
}

/// What to capture where, when there is nothing to show: a 13 pt semibold title and label-above
/// paragraphs, flush left.
private struct AuthEmptyGuide: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Where to capture")
                .font(Theme.emphasis)
                .foregroundStyle(Theme.text)
                .accessibilityAddTraits(.isHeader)
            item("Mac’s own Wi-Fi / LAN", "You see EAPOL and the 4-way handshake for this Mac only: 802.1X (EAP identity, the PEAP / EAP-TLS rounds, EAP-Success or -Failure) and WPA2-PSK’s messages 1/4 … 4/4, then DHCP.")
            item("SPAN of the switch / controller uplink", "RADIUS is only visible here: Access-Request / Challenge / Accept / Reject with the user, the client’s MAC, the VLAN and role, and the server’s reply message.")
            item("MAC auth", "Has no client-side packets: the switch asks RADIUS with the client’s MAC. On the client, look for DHCP after the link came up.")
            item("Captive portals", "Show up as an HTTP redirect of the system’s check (captive.apple.com, connectivitycheck.gstatic.com, msftconnecttest.com), the login POST, and the first answer that is not the portal.")
            item("WPA3-SAE / 802.11 frames", "SAE commit/confirm and association frames are 802.11 management frames: an Ethernet capture never has them (a monitor-mode Wi-Fi capture does). The 4-way handshake after SAE is shown.")
            Text("Open a capture file (⌘O) or start a capture on the Packets pane. Filter the Packets pane with “\(AuthDecoder.packetFilterPreset)” to see only these packets.")
                .font(Theme.caption)
                .foregroundStyle(Theme.faintText)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
        }
        .frame(maxWidth: Metrics.prose, alignment: .leading)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func item(_ title: String, _ text: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(Theme.caption).foregroundStyle(Theme.text2)
            Text(text).font(Theme.body).foregroundStyle(Theme.text).fixedSize(horizontal: false, vertical: true)
        }
    }
}

// MARK: - Ladder layout

/// Rows are step order; each row is one arrow between two lifelines (or a band for grouped TLS rounds).
struct AuthLadderLayout {
    struct Item {
        let event: AuthEvent
        let y: CGFloat
        let height: CGFloat
        let fromX: CGFloat
        let toX: CGFloat
        let label: String
        let labelRect: CGRect
        let detail: String?
        let problem: String?
    }

    static let boxTop: CGFloat = 12
    static let boxHeight: CGFloat = 44
    static let firstRow: CGFloat = 74
    static let cap = 400
    static let labelFont = NSFont.systemFont(ofSize: 11)
    static let noteFont = NSFont.systemFont(ofSize: 10)

    let width: CGFloat
    let height: CGFloat
    let lanes: [AuthLifeline]
    let xs: [CGFloat]
    let items: [Item]
    let hidden: Int
    let titles: [String]
    let note: String

    func x(_ lane: AuthLifeline) -> CGFloat? {
        lanes.firstIndex(of: lane).map { xs[$0] }
    }

    static func make(session: AuthSession, width: CGFloat) -> AuthLadderLayout {
        let lanes = session.lifelines
        // Each lifeline in the middle of an equal slot, so the endpoint boxes (≤ one slot wide)
        // never overlap; the time column sits left of the first one.
        let n = CGFloat(lanes.count)
        let edge = min(max(60, width / (2 * n)), 150)
        let xs: [CGFloat] = lanes.count == 1 ? [width / 2]
            : lanes.indices.map { (edge + (width - 2 * edge) * CGFloat($0) / (n - 1)).rounded() }
        func xOf(_ l: AuthLifeline) -> CGFloat {
            if let i = lanes.firstIndex(of: l) { return xs[i] }
            // A row on a lifeline this attempt does not draw: its nearest one.
            return l == .client ? xs.first! : xs.last!
        }
        var items: [Item] = []
        var y = firstRow
        let shown = session.events.prefix(cap)
        for e in shown {
            let a = xOf(e.from), b = xOf(e.to)
            let lo = min(a, b), hi = max(a, b)
            let maxLabel = min(width - 16, max(hi - lo - 10, 250))
            let label = fit(e.label, width: maxLabel, font: labelFont)
            let size = (label as NSString).size(withAttributes: [.font: labelFont])
            let w = ceil(size.width) + 12, h: CGFloat = 17
            let cx = min(max((lo + hi) / 2, 8 + w / 2), width - 8 - w / 2)
            let rect = CGRect(x: cx - w / 2, y: y, width: w, height: h)
            let detail = e.detail.map { fit($0, width: min(width - 16, max(hi - lo, 280)), font: noteFont) }
            let problem = e.problem.map { fit($0, width: min(width - 16, max(hi - lo, 280)), font: noteFont) }
            var rowH: CGFloat = e.isGroup ? 40 : 34
            if detail != nil { rowH += 13 }
            if problem != nil { rowH += 13 }
            items.append(Item(event: e, y: y, height: rowH, fromX: a, toX: b, label: label, labelRect: rect,
                              detail: detail, problem: problem))
            y += rowH
        }
        let hidden = session.events.count - shown.count
        let height = y + (hidden > 0 ? 40 : 18)
        let titles = lanes.map { lane -> String in
            switch lane {
            case .client: session.client
            case .nas: session.nas ?? session.nasMAC ?? "—"
            case .server: session.serverIP ?? "—"
            }
        }
        var note = "Rows are step order, not time. Times are since the attempt’s first packet."
        if !session.hasClientSide { note += " Captured on the wired side (RADIUS only): the client’s own frames are not in this capture." }
        return AuthLadderLayout(width: width, height: height, lanes: lanes, xs: xs, items: items, hidden: hidden,
                                titles: titles, note: note)
    }

    static func fit(_ s: String, width: CGFloat, font: NSFont) -> String {
        func w(_ t: String) -> CGFloat { (t as NSString).size(withAttributes: [.font: font]).width + 12 }
        guard w(s) > width else { return s }
        var t = s
        while t.count > 4, w(t + "…") > width { t.removeLast() }
        return t + "…"
    }

    /// The row containing `p`.
    func hit(_ p: CGPoint) -> Int? {
        items.first { p.y >= $0.y - 2 && p.y < $0.y + $0.height - 2 }?.event.id
    }
}

// MARK: - Ladder drawing

struct AuthLadderCanvas: View {
    let layout: AuthLadderLayout
    var selected: Int?

    var body: some View {
        Canvas { ctx, size in draw(&ctx, size) }
            .frame(height: layout.height)
    }

    private func draw(_ ctx: inout GraphicsContext, _ size: CGSize) {
        let L = layout
        let top = AuthLadderLayout.boxTop + AuthLadderLayout.boxHeight
        for x in L.xs {
            var p = Path()
            p.move(to: CGPoint(x: x, y: top)); p.addLine(to: CGPoint(x: x, y: L.height - 8))
            ctx.stroke(p, with: .color(Theme.hairline), style: StrokeStyle(lineWidth: 1.5, lineCap: .round))
        }
        for (i, lane) in L.lanes.enumerated() {
            endpointHead(&ctx, x: L.xs[i], lane: lane, detail: L.titles[i])
        }
        var lastTime = ""
        for item in L.items {
            drawItem(&ctx, item, lastTime: &lastTime)
        }
        if L.hidden > 0 {
            ctx.draw(Text("… \(Format.count(L.hidden)) more steps (showing the first \(AuthLadderLayout.cap))")
                        .font(.system(size: 11)).foregroundStyle(Theme.faintText),
                     at: CGPoint(x: L.width / 2, y: L.height - 18), anchor: .center)
        }
    }

    private func drawItem(_ ctx: inout GraphicsContext, _ item: AuthLadderLayout.Item, lastTime: inout String) {
        let e = item.event
        let tint = AuthStyle.color(e)
        let isSel = e.id == selected
        if isSel {
            ctx.fill(Path(roundedRect: CGRect(x: 4, y: item.y - 3, width: layout.width - 8, height: item.height - 2), cornerRadius: 6),
                     with: .color(Theme.selectedAccent))
        }
        let arrowY = item.y + 24
        let lo = min(item.fromX, item.toX), hi = max(item.fromX, item.toX)
        if e.isGroup {
            let band = CGRect(x: lo, y: item.y + 20, width: max(8, hi - lo), height: 10)
            ctx.fill(Path(roundedRect: band, cornerRadius: 5), with: .color(tint.opacity(0.16)))
            arrow(&ctx, from: CGPoint(x: lo + 1, y: arrowY + 1), to: CGPoint(x: hi - 1, y: arrowY + 1), tint, 1.5)
            arrow(&ctx, from: CGPoint(x: hi - 1, y: arrowY + 1), to: CGPoint(x: lo + 1, y: arrowY + 1), tint, 1.5)
        } else if item.fromX == item.toX {
            // Both ends on one drawn lifeline (a lifeline this attempt does not show): a short tick.
            let dir: CGFloat = e.from < e.to ? 1 : -1
            arrow(&ctx, from: CGPoint(x: item.fromX, y: arrowY), to: CGPoint(x: item.fromX + 40 * dir, y: arrowY + 4), tint, 1.5)
        } else {
            arrow(&ctx, from: CGPoint(x: item.fromX, y: arrowY - 3), to: CGPoint(x: item.toX, y: arrowY + 3), tint,
                  e.problem != nil ? 2 : 1.5)
        }
        // Label on a ground (lifelines pass under it).
        let problem = e.problem != nil
        ctx.fill(Path(roundedRect: item.labelRect, cornerRadius: 4), with: .color(isSel ? Theme.panel.opacity(0.0) : Theme.panel))
        let weight: Font.Weight = problem || e.kind.isFinal ? .medium : .regular
        ctx.draw(Text(item.label).font(.system(size: 11, weight: weight)).foregroundStyle(problem ? Theme.err : Theme.text),
                 at: CGPoint(x: item.labelRect.midX, y: item.labelRect.midY), anchor: .center)
        var noteY = arrowY + 8
        let mid = (lo + hi) / 2
        func note(_ s: String, _ c: Color) {
            let size = (s as NSString).size(withAttributes: [.font: AuthLadderLayout.noteFont])
            let cx = min(max(mid, 8 + size.width / 2), layout.width - 8 - size.width / 2)
            let ground = CGRect(x: cx - size.width / 2 - 2, y: noteY, width: size.width + 4, height: size.height)
            ctx.fill(Path(roundedRect: ground, cornerRadius: 3), with: .color(isSel ? .clear : Theme.panel))
            ctx.draw(Text(s).font(.system(size: 10)).foregroundStyle(c), at: CGPoint(x: cx, y: noteY), anchor: .top)
            noteY += 13
        }
        if let d = item.detail { note(d, Theme.dimText) }
        if let p = item.problem { note(p, Theme.err) }
        // Time, in the left margin.
        let t = AuthSessions.msText(e.time)
        if t != lastTime {
            ctx.draw(Text(t).font(.system(size: 10, design: .monospaced)).foregroundStyle(Theme.dimText),
                     at: CGPoint(x: (layout.xs.first ?? 80) - 10, y: arrowY), anchor: .trailing)
            lastTime = t
        }
    }

    private func arrow(_ ctx: inout GraphicsContext, from a: CGPoint, to b: CGPoint, _ c: Color, _ w: CGFloat) {
        let dx = b.x - a.x, dy = b.y - a.y
        let len = max(1, hypot(dx, dy))
        let ux = dx / len, uy = dy / len
        let headLen: CGFloat = 8, half: CGFloat = 4
        let base = CGPoint(x: b.x - ux * headLen, y: b.y - uy * headLen)
        var line = Path()
        line.move(to: a); line.addLine(to: base)
        ctx.stroke(line, with: .color(c), style: StrokeStyle(lineWidth: w, lineCap: .round))
        var tri = Path()
        tri.move(to: b)
        tri.addLine(to: CGPoint(x: base.x - uy * half, y: base.y + ux * half))
        tri.addLine(to: CGPoint(x: base.x + uy * half, y: base.y - ux * half))
        tri.closeSubpath()
        ctx.fill(tri, with: .color(c))
    }

    /// A lifeline's head as words (Round 22: no card, no device glyph): "Client" / "Switch / AP" /
    /// "RADIUS" in ink and semibold, the address under it in mono, faint — centred on the lifeline,
    /// at most one slot wide (the heads never overlap), kept inside the canvas.
    private func endpointHead(_ ctx: inout GraphicsContext, x: CGFloat, lane: AuthLifeline, detail full: String) {
        let font = NSFont.monospacedSystemFont(ofSize: 10.5, weight: .regular)
        let slots = CGFloat(max(1, layout.lanes.count))
        let maxW = max(90, min(200, layout.width / slots - 12))
        // `fit` measures with 12 pt of box padding; there is none now.
        let detail = AuthLadderLayout.fit(full, width: maxW + 12, font: font)
        let w = max(60, ceil((detail as NSString).size(withAttributes: [.font: font]).width))
        let cx = min(max(x, 4 + w / 2), layout.width - 4 - w / 2)
        let top = AuthLadderLayout.boxTop
        ctx.draw(Text(lane.title).font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.text),
                 at: CGPoint(x: cx, y: top + 10), anchor: .center)
        ctx.draw(Text(detail).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(Theme.faintText),
                 at: CGPoint(x: cx, y: top + 27), anchor: .center)
    }
}

/// What Export PNG renders: a title, the reasons, the ladder and the note.
private struct AuthLadderExport: View {
    let session: AuthSession
    let layout: AuthLadderLayout

    var body: some View {
        VStack(spacing: 6) {
            Text("\(session.methodLabel) — \(session.client)\(session.user.map { " (\($0))" } ?? "") — \(session.result.label)")
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(Theme.text)
            if !session.reasons.isEmpty {
                Text(session.reasons.joined(separator: " · "))
                    .font(.system(size: 11.5))
                    .foregroundStyle(session.health == .bad ? Theme.err : Theme.warn)
                    .frame(width: layout.width - 40)
                    .fixedSize(horizontal: false, vertical: true)
            }
            AuthLadderCanvas(layout: layout, selected: nil)
                .frame(width: layout.width, height: layout.height)
            Text(layout.note)
                .font(.system(size: 10))
                .foregroundStyle(Theme.faintText)
                .frame(width: layout.width - 40)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, 16)
        .frame(width: layout.width)
        .background(Theme.content)
    }
}

// MARK: - Timeline strip

/// The attempt on one line: a tick per step in its colour (problems red, the outcome green or
/// red). Click a tick to select that step.
struct AuthTimeline: View {
    let session: AuthSession
    @Binding var selected: Int?

    var body: some View {
        VStack(spacing: 3) {
            GeometryReader { geo in
                let w = geo.size.width
                Canvas { ctx, size in draw(&ctx, size) }
                    .contentShape(Rectangle())
                    .onTapGesture(coordinateSpace: .local) { p in
                        let hit = session.events.min { abs(x($0.time, w) - p.x) < abs(x($1.time, w) - p.x) }
                        if let hit, abs(x(hit.time, w) - p.x) <= 6 { selected = hit.id }
                    }
            }
            .frame(height: 16)
            HStack(spacing: 6) {
                Text("0")
                Spacer(minLength: 4)
                Text(caption).lineLimit(1).truncationMode(.tail)
                Spacer(minLength: 4)
                Text(AuthSessions.msText(session.duration))
            }
            .font(.system(size: 10, design: .monospaced))
            .foregroundStyle(Theme.faintText)
        }
        .help("The attempt’s \(AuthSessions.msText(session.duration)) from left to right; red ticks are problems. Click a tick to select its step.")
    }

    private var caption: String {
        let problems = session.events.filter { $0.problem != nil }.count
        let steps = "\(session.events.count) step\(session.events.count == 1 ? "" : "s")"
        return problems == 0 ? steps : "\(steps) · \(problems) problem\(problems == 1 ? "" : "s")"
    }

    private func x(_ t: Double, _ width: CGFloat) -> CGFloat {
        guard session.duration > 0 else { return 3 }
        return 3 + CGFloat(min(1, max(0, t / session.duration))) * max(1, width - 6)
    }

    private func draw(_ ctx: inout GraphicsContext, _ size: CGSize) {
        let bar = CGRect(x: 0, y: 5, width: size.width, height: 6)
        ctx.fill(Path(roundedRect: bar, cornerRadius: 3), with: .color(Theme.well))
        ctx.stroke(Path(roundedRect: bar, cornerRadius: 3), with: .color(Theme.hairline), lineWidth: 0.5)
        // Quiet steps first, problems and outcomes on top.
        let ordered = session.events.sorted { rank($0) < rank($1) }
        for e in ordered {
            let mx = x(e.time, size.width)
            let isSel = e.id == selected
            let tall = isSel || rank(e) > 0
            let rect = CGRect(x: mx - (isSel ? 1.5 : 1), y: tall ? (isSel ? 0 : 2) : 4, width: isSel ? 3 : 2, height: isSel ? 16 : tall ? 12 : 8)
            ctx.fill(Path(roundedRect: rect, cornerRadius: 1), with: .color(AuthStyle.color(e)))
        }
    }

    private func rank(_ e: AuthEvent) -> Int { e.problem != nil ? 2 : e.kind.isFinal ? 1 : 0 }
}
