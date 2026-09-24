import AppKit
import Combine
import SwiftUI
import UniformTypeIdentifiers

/// "Show in TCP Flows" from the Packets pane: the conversation of `packetID` (a 4-tuple reused
/// over time is several conversations; the frame says which one).
nonisolated struct FlowSelectRequest: Sendable {
    let key: FlowKey
    let packetID: Int?

    /// The conversation to select and, when the request names a frame, the ladder event that
    /// carries it.
    func resolve(in flows: [TCPFlow]) -> (flow: TCPFlow, eventID: Int?)? {
        guard let flow = Self.match(flows, key: key, packetID: packetID) else { return nil }
        let event = packetID.flatMap { id in flow.events.first { $0.packetIDs.contains(id) }?.id }
        return (flow, event)
    }

    /// The conversation this frame belongs to: same key, frame inside its first … last frame.
    static func match(_ flows: [TCPFlow], key: FlowKey, packetID: Int?) -> TCPFlow? {
        let same = flows.filter { $0.key == key }
        if let id = packetID, let f = same.first(where: { $0.firstPacketID <= id && id <= $0.lastPacketID }) { return f }
        return same.first
    }
}

/// What the Flows pane has selected — the conversation, the ladder event, a "Follow TCP stream"
/// request waiting for an analysis — and how that survives a re-analysis (ids are renumbered
/// every time, and a live capture's ring evicts the oldest frames: the ladder's events shift).
nonisolated struct FlowSelectionState: Sendable {
    var selection: Int?
    var key: FlowKey?
    var start: Date?
    var event: Int?
    var pendingRequest: FlowSelectRequest?
    /// The frame whose event to select once `selection` has moved to its flow.
    var pendingEventPacket: Int?
    /// The selection as the pane itself last set it (an analysis, a Follow request). Any other
    /// selection is the user's click, and a click wins over a Follow request still waiting for
    /// its analysis (the analysis landing after the click moved the selection back).
    var selectedBySelf: Int?

    /// `onChange(of: selection)`.
    mutating func selectionChanged(in flows: [TCPFlow]) {
        if selection != selectedBySelf {
            pendingRequest = nil
            selectedBySelf = selection
        }
        let f = flows.first { $0.id == selection }
        event = pendingEventPacket.flatMap { id in f?.events.first { $0.packetIDs.contains(id) }?.id }
        pendingEventPacket = nil
        key = f?.key
        start = f?.firstTime
    }

    /// The event of `flow` that carries any of `frames` (nil when they all left the ring).
    static func event(in flow: TCPFlow, carrying frames: [Int]) -> Int? {
        guard !frames.isEmpty else { return nil }
        let set = Set(frames)
        return flow.events.first { e in e.packetIDs.contains { set.contains($0) } }?.id
    }

    /// A new analysis (`previous` = the flows it replaces). The selected conversation is found
    /// again by key and start (a reused 4-tuple is several conversations), else by key; the
    /// selected ladder event by its frames — its index moves when the ring evicts the flow's
    /// first frames, and the old index then named another event (the footer's frames and
    /// "Show packets" were another event's). Returns the flow a "Follow TCP stream" request
    /// resolved to (the pane clears filters that would hide it).
    @discardableResult
    mutating func apply(_ result: [TCPFlow], previous: [TCPFlow]) -> TCPFlow? {
        // The user chose another row after the request (its onChange may not have run yet).
        if pendingRequest != nil, selection != selectedBySelf { pendingRequest = nil }
        defer { selectedBySelf = selection }
        let shownFrames: [Int] = {
            guard let s = selection, let e = event, let f = previous.first(where: { $0.id == s }),
                  let ev = f.events.first(where: { $0.id == e }) else { return [] }
            return ev.packetIDs
        }()
        let byStart = start.flatMap { st in result.first { $0.key == key && $0.firstTime == st } }
        if let request = pendingRequest, let target = request.resolve(in: result) {
            pendingRequest = nil
            // A new selection picks the event up in selectionChanged; the same one now.
            if selection == target.flow.id { event = target.eventID } else { pendingEventPacket = request.packetID }
            selection = target.flow.id
            return target.flow
        }
        if let request = pendingRequest, let frame = request.packetID,
           frame <= (result.map(\.lastPacketID).max() ?? 0) {
            // Analysed past its frame and no conversation has its key: the frame (and its whole
            // conversation) left the ring. Waiting on would jump to whatever reuses that 4-tuple
            // minutes later.
            pendingRequest = nil
        }
        let match = pendingRequest == nil ? byStart : nil
        if let target = match ?? key.flatMap({ FlowSelectRequest.match(result, key: $0, packetID: nil) }) {
            let ev = Self.event(in: target, carrying: shownFrames)
            if selection == target.id {
                event = ev
            } else {
                pendingEventPacket = ev.flatMap { id in target.events.first { $0.id == id }?.packetIDs.first }
            }
            selection = target.id
        } else if let s = selection, !result.contains(where: { $0.id == s }) {
            selection = nil
        } else if selection != nil {
            event = nil
        }
        return nil
    }
}

/// TCP flows: the conversation table on the left, the ladder (sequence) diagram of the selected
/// one on the right. Analysis runs off the main actor on every store change (at most once a second).
struct FlowView: View {
    /// Not observed: during a live capture (10 publishes a second) or a file load (one per
    /// 5,000-packet batch) every store change re-ran this body — the flow table's filter, map
    /// and sort over every conversation — on the main thread. The two changes that matter are
    /// subscribed to below.
    private let store = AppModel.shared.packets
    @Environment(\.colorScheme) private var colorScheme

    @State private var flows: [TCPFlow] = []
    @State private var analysing = false
    @State private var analysedAt: Date?
    @State private var analysisToken = 0
    /// The 1-second debounce before a re-analysis, the running analysis, and whether the
    /// packets changed while it ran (then it runs once more afterwards, never queued up).
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
    @State private var selection: Int?
    @State private var selectedKey: FlowKey?
    @State private var selectedStart: Date?
    /// "Follow TCP stream" (or a selection) waiting for an analysis that contains its frame —
    /// key and frame together, so the frame cannot be dropped on the way.
    @State private var pendingRequest: FlowSelectRequest?
    /// The frame whose event to select once `selection` has moved to its flow.
    @State private var pendingEventPacket: Int?
    /// The selection as the pane last set it (`FlowSelectionState.selectedBySelf`).
    @State private var selectedBySelf: Int?
    @State private var sortOrder: [KeyPathComparator<FlowRow>] = FlowRow.defaultOrder
    @State private var collapseAcks = true
    @State private var selectedEvent: Int?
    @State private var ladderWidth: CGFloat = 560
    @FocusState private var filterFocused: Bool
    @State private var paneWidth: CGFloat = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            TimelineView(.periodic(from: .now, by: 1)) { context in
                PaneHeader(eyebrow: "Capture", heading: heading, subtitle: subtitle(now: context.date)) {
                    headerActions
                }
            }
            .paneColumn()
            .padding(.top, Metrics.headerTop)
            .padding(.bottom, 12)

            PaneStrip { strip }

            HSplitView {
                table
                    .frame(minWidth: 300, idealWidth: 420, maxWidth: .infinity, maxHeight: .infinity)
                    .padding(.trailing, 6)
                ladderPane
                    .frame(minWidth: 420, maxWidth: .infinity, maxHeight: .infinity)   // table 300 + 420 fit the 1000 pt window
                    .padding(.leading, 6)
            }
            .paneColumn()
            .padding(.vertical, 14)
        }
        .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { paneWidth = $0 }
        .paneKeyCommands(find: { filterFocused = true }, copy: { if selectedFlow == nil { NSSound.beep() } else { copySummary() } })
        .task { appeared() }
        .onDisappear { disappeared() }
        // Appends do not bump `generation` (only rescans, evictions and clears do): follow the
        // packet count too, or a live capture would never be re-analysed.
        .onReceive(store.$generation.removeDuplicates().dropFirst()) { _ in scheduleAnalysis() }
        .onReceive(store.$totalReceived.removeDuplicates().dropFirst()) { _ in scheduleAnalysis() }
        .onChange(of: selection) { selectionChanged() }
        .onReceive(NotificationCenter.default.publisher(for: .sheepLogSelectFlow)) { note in
            // A pane that has left (its window closed, the view not yet torn down) must not take
            // the request from the one that is appearing.
            guard visible else { return }
            AppModel.shared.pendingFlowKey = nil        // handled here, not on the next appearance
            if let r = note.object as? FlowSelectRequest { select(key: r.key, packetID: r.packetID) }
            else if let key = note.object as? FlowKey { select(key: key, packetID: nil) }
        }
    }

    private func appeared() {
        if DemoFlags.flows { loadDemo(); return }
        // `-demoPane flows -demoPcap <file>`: the Packets pane (which opens it) never appeared.
        if store.fileURL == nil, store.packets.isEmpty, DemoFlags.openPcap() {
            AppModel.shared.mainPane = .flows
        }
        // "Follow TCP stream" from Packets: posted before this pane existed.
        if let r = AppModel.shared.takePendingFlowRequest() { pendingRequest = r }
        visible = true
        startAnalysis()
    }

    /// Leaving the pane mid-run: stop the work, not just ignore its result.
    private func disappeared() {
        visible = false
        scheduledTask?.cancel(); scheduledTask = nil
        analysisTask?.cancel(); analysisTask = nil
        rerun = false
        analysing = false
    }

    private func selectionChanged() {
        var state = selectionState
        state.selectionChanged(in: flows)
        selectionState = state
    }

    /// The selection @State as one value (the rules live in `FlowSelectionState`, tested).
    private var selectionState: FlowSelectionState {
        get {
            FlowSelectionState(selection: selection, key: selectedKey, start: selectedStart, event: selectedEvent,
                               pendingRequest: pendingRequest, pendingEventPacket: pendingEventPacket, selectedBySelf: selectedBySelf)
        }
        nonmutating set {
            if selectedBySelf != newValue.selectedBySelf { selectedBySelf = newValue.selectedBySelf }
            if selectedKey != newValue.key { selectedKey = newValue.key }
            if selectedStart != newValue.start { selectedStart = newValue.start }
            if selectedEvent != newValue.event { selectedEvent = newValue.event }
            pendingRequest = newValue.pendingRequest
            if pendingEventPacket != newValue.pendingEventPacket { pendingEventPacket = newValue.pendingEventPacket }
            if selection != newValue.selection { selection = newValue.selection }
        }
    }

    // MARK: Header and strip

    private var problemCount: Int { flows.filter { $0.health != .ok }.count }

    private var heading: String {
        if flows.isEmpty { return analysing ? "Analysing TCP conversations…" : "No TCP conversations yet." }
        let noun = flows.count == 1 ? "TCP conversation" : "TCP conversations"
        let p = problemCount
        return "\(Format.count(flows.count)) \(noun), \(p == 0 ? "none" : Format.count(p)) with problems."
    }

    private func subtitle(now: Date) -> String {
        let source = DemoFlags.flows ? "demo flows" : (store.fileURL?.lastPathComponent ?? "live capture")
        var parts = [source]
        if analysing { parts.append("analysing…") }
        else if let at = analysedAt { parts.append("re-analysed \(Self.ago(now.timeIntervalSince(at)))") }
        return parts.joined(separator: " · ")
    }

    private static func ago(_ s: Double) -> String {
        if s < 60 { return "\(max(0, Int(s))) s ago" }
        if s < 3600 { return "\(Int(s / 60)) min ago" }
        return "\(Int(s / 3600)) h ago"
    }

    @ViewBuilder private var headerActions: some View {
        // Always laid out (hidden when idle): inserting it shifted every button to its right.
        ProgressView().controlSize(.small).opacity(analysing ? 1 : 0).accessibilityHidden(!analysing)
        Group {
            let _ = PaneProbe.button("flows.Re-analyse", enabled: !analysing) { if DemoFlags.flows { loadDemo() } else { startAnalysis() } }
            let _ = PaneProbe.button("flows.Copy summary", enabled: selectedFlow != nil) { copySummary() }
            Button {
                if DemoFlags.flows { loadDemo() } else { startAnalysis() }
            } label: {
                Label("Re-analyse", systemImage: "arrow.clockwise")
            }
            .disabled(analysing)
            .help("Analyse the packets again")
            Toggle(isOn: $problemsOnly) { Label("Problems only", systemImage: "exclamationmark.triangle") }
                .toggleStyle(.button)
                .help("Show only conversations with problems")
            Button { copySummary() } label: { Label("Copy summary", systemImage: "doc.on.doc") }
                .disabled(selectedFlow == nil)
                .help("Copy the selected conversation as plain text for a ticket: endpoints, RTT, response time, bytes and timed problems (⌘⇧C)")
            Button { exportPNG() } label: { Label("Export PNG…", systemImage: "square.and.arrow.up") }
                .disabled(selectedFlow == nil)
                .help("Save the ladder diagram of the selected conversation as a PNG")
        }
        // Icons only below 1,150 pt of pane (windows under ~1,360 pt): with titles the four buttons take ~470 pt and the
        // heading wrapped to three lines at 1000 pt, two at 1280.
        .labelStyle(AdaptiveLabelStyle(iconOnly: paneWidth > 0 && paneWidth < 1_150))
    }

    @ViewBuilder private var strip: some View {
        FilterField(text: $filterText, prompt: "Filter client, server, app or problem", mono: false,
                    help: "Matches as you type. ⌘F to focus, Esc to clear", focus: $filterFocused)
            .frame(maxWidth: 380)
        Text(shownText)
            .font(.system(size: 11.5))
            .foregroundStyle(Theme.faintText)
        Spacer(minLength: 8)
        Toggle("Collapse ACKs", isOn: $collapseAcks)
            .toggleStyle(.checkbox)
            .font(.system(size: 12))
            .controlSize(.small)
            .help("Hide the pure ACKs between data groups (the handshake ACK and closing ACKs stay).")
    }

    private var shownText: String {
        let n = rows.count
        return n == flows.count ? "" : "\(Format.count(n)) of \(Format.count(flows.count)) shown"
    }

    // MARK: Table

    private var rows: [FlowRow] {
        let needle = filterText.trimmingCharacters(in: .whitespaces).lowercased()
        return flows.lazy
            .filter { !problemsOnly || $0.health != .ok }
            .filter { f in
                needle.isEmpty
                    || f.clientEndpoint.lowercased().contains(needle)
                    || f.serverEndpoint.lowercased().contains(needle)
                    || f.application.lowercased().contains(needle)
                    || f.reasons.contains { $0.lowercased().contains(needle) }
            }
            .map(FlowRow.init)
            .sorted(using: sortOrder)
    }

    private var table: some View {
        Table(rows, selection: $selection, sortOrder: $sortOrder) {
            TableColumn("", value: \FlowRow.healthRank) { r in
                HealthDot(health: r.health)
                    .help(r.health == .ok ? "Healthy" : r.problems)
            }
            .width(14)
            TableColumn("Client", value: \FlowRow.client) { r in
                Text(r.client).font(.system(size: 11.5, design: .monospaced)).identifierText()
            }
            .width(min: 100, ideal: 138)
            TableColumn("Server", value: \FlowRow.server) { r in
                Text(r.server).font(.system(size: 11.5, design: .monospaced)).identifierText()
            }
            .width(min: 100, ideal: 138)
            TableColumn("App", value: \FlowRow.app) { r in Text(r.app).proseText() }
                .width(min: 50, ideal: 110)
            // Right after App: at the default pane width the numeric columns after it scroll,
            // and the reason a row is orange must not be the part that scrolls away.
            TableColumn("Problems", value: \FlowRow.problems) { r in
                Text(r.problems).proseText()
                    .foregroundStyle(r.health == .bad ? Theme.err : r.health == .warn ? Theme.warn : Theme.dimText)
                    .help(r.problems)
            }
            .width(min: 120, ideal: 240)
            TableColumn("Packets", value: \FlowRow.packets) { r in
                Text(Format.count(r.packets)).monospacedDigit().frame(maxWidth: .infinity, alignment: .trailing)
            }
            .width(min: 44, ideal: 56)
            TableColumn("Bytes", value: \FlowRow.bytes) { r in
                Text(Format.bytes(r.bytes)).monospacedDigit().frame(maxWidth: .infinity, alignment: .trailing)
            }
            .width(min: 50, ideal: 66)
            TableColumn("Duration", value: \FlowRow.duration) { r in
                Text(Format.ms(r.duration)).monospacedDigit().frame(maxWidth: .infinity, alignment: .trailing)
            }
            .width(min: 50, ideal: 66)
            TableColumn("RTT", value: \FlowRow.rttSort) { r in
                Text(r.rtt.map(TCPFlowAnalyzer.msText) ?? "—").monospacedDigit()
                    .foregroundStyle((r.rtt ?? 0) > 0.3 ? Theme.warn : Theme.text)
                    .frame(maxWidth: .infinity, alignment: .trailing)
            }
            .width(min: 44, ideal: 56)
            TableColumn("Response", value: \FlowRow.responseSort) { r in
                Text(r.response.map(TCPFlowAnalyzer.msText) ?? "—").monospacedDigit()
                    .foregroundStyle((r.response ?? 0) > 3 ? Theme.err : (r.response ?? 0) > 1 ? Theme.warn : Theme.text)
                    .frame(maxWidth: .infinity, alignment: .trailing)
            }
            .width(min: 50, ideal: 64)
        }
        .font(.system(size: 12))
        .tablePanel()
        .overlay {
            if rows.isEmpty {
                TableEmptyOverlay(text: flows.isEmpty
                    ? (analysing ? "Analysing…" : "No TCP conversations in the capture. Start a capture on the Packets pane, or open a .pcap file (⌘O).")
                    : "No conversation matches the filter.")
            }
        }
    }

    // MARK: Ladder side

    private var selectedFlow: TCPFlow? {
        guard let selection else { return nil }
        return flows.first { $0.id == selection }
    }

    private func layout(for flow: TCPFlow) -> LadderLayout {
        LadderLayout.make(flow: flow, collapseAcks: collapseAcks, width: ladderWidth)
    }

    @ViewBuilder private var ladderPane: some View {
        VStack(spacing: 0) {
            if let flow = selectedFlow {
                let layout = layout(for: flow)
                let _ = PaneProbe.drewFlow(flow, event: selectedEvent)
                LadderHeader(flow: flow)
                FlowTimeline(flow: flow, layout: layout, selected: $selectedEvent)
                    .padding(.horizontal, 14)
                    .padding(.bottom, 8)
                Rectangle().fill(Theme.hairlineSoft).frame(height: 0.5)
                // The tap below, for tests (a unit-test host cannot click a SwiftUI canvas).
                let _ = PaneProbe.tapTarget("flows.ladder") { point in
                    let hit = layout.hit(point)
                    selectedEvent = hit == selectedEvent ? nil : hit
                }
                ScrollView(.vertical) {
                    LadderCanvas(layout: layout, selected: selectedEvent)
                        .frame(height: layout.height)
                        .contentShape(Rectangle())
                        .onTapGesture(coordinateSpace: .local) { point in
                            let hit = layout.hit(point)
                            selectedEvent = hit == selectedEvent ? nil : hit
                        }
                }
                .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { ladderWidth = max(360, $0) }
                .id(flow.id)
                Rectangle().fill(Theme.hairlineSoft).frame(height: 0.5)
                selectionFooter(flow)
            } else {
                let _ = PaneProbe.drewFlow(nil, event: nil)
                TableEmptyOverlay(text: "Select a conversation on the left to see its ladder diagram.")
            }
            Rectangle().fill(Theme.hairlineSoft).frame(height: 0.5)
            FlowLegend()
        }
        .panelCard()
    }

    @ViewBuilder private func selectionFooter(_ flow: TCPFlow) -> some View {
        HStack(spacing: 8) {
            if let id = selectedEvent, let event = flow.events.first(where: { $0.id == id }) {
                let ids = event.packetIDs
                Text(LadderLayout.label(for: event, flow: flow))
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(event.problem != nil ? Theme.err : Theme.text)
                    .proseText()
                Text(framesText(ids))
                    .font(.system(size: 11.5, design: .monospaced))
                    .foregroundStyle(Theme.dimText)
                    .identifierText()
                    .textSelection(.enabled)
                Spacer(minLength: 8)
                let _ = PaneProbe.button("flows.Show packets", enabled: !ids.isEmpty) { showPackets(ids, flow: flow) }
                Button("Show packets") { showPackets(ids, flow: flow) }
                    .controlSize(.small)
                    .disabled(ids.isEmpty)
            } else {
                let _ = PaneProbe.button("flows.Show packets", enabled: false) {}
                Text("Click an arrow or its label to see its packets.")
                    .font(.system(size: 11.5))
                    .foregroundStyle(Theme.faintText)
                Spacer(minLength: 0)
            }
        }
        .padding(.horizontal, 14)
        .frame(height: 36)
    }

    private func framesText(_ ids: [Int]) -> String {
        guard !ids.isEmpty else { return "no packets" }
        let shown = ids.prefix(24).map(String.init).joined(separator: ", ")
        let more = ids.count > 24 ? " … +\(ids.count - 24)" : ""
        return "\(ids.count == 1 ? "frame" : "frames") \(shown)\(more)"
    }

    private func showPackets(_ ids: [Int], flow: TCPFlow) {
        let filter = Self.packetFilter(ids, flow: flow)
        AppModel.shared.mainPane = .packets
        NotificationCenter.default.post(name: .sheepLogPacketFilter, object: filter)
    }

    /// The Packets filter for an event's frames: the frames themselves (as many as one filter
    /// takes; the matcher folds them into one lookup), else this conversation's packets from its
    /// first to its last frame — the first 50 alone left the rest of a large group out without a
    /// word. (The range from 51 frames showed the ACKs between a data group's segments too.)
    nonisolated static func packetFilter(_ ids: [Int], flow: TCPFlow) -> String {
        guard ids.count > Query.maxTerms, let lo = ids.min(), let hi = ids.max() else {
            return ids.map { "frame:\($0)" }.joined(separator: " OR ")
        }
        let k = flow.key
        return "frame:>=\(lo) frame:<=\(hi) ip:\(k.addressA) ip:\(k.addressB) port:\(k.portA) port:\(k.portB)"
    }

    // MARK: Analysis

    private func scheduleAnalysis() {
        guard visible, !DemoFlags.flows, scheduledTask == nil else { return }
        scheduledTask = Task {
            LeakProbe.add("Flows.scheduled")
            defer { LeakProbe.remove("Flows.scheduled") }
            try? await Task.sleep(for: .seconds(1))
            guard !Task.isCancelled else { return }
            scheduledTask = nil
            // Nothing new since the last analysis read the packets (the publish came from the
            // very change it analysed): no second analysis of the same packets.
            if store.dataStamp == analysedStamp, pendingRequest == nil { return }
            startAnalysis()
        }
    }

    /// One analysis at a time. At 50k pkt/s a 200k-packet analysis can take longer than the
    /// 1-second cadence; requests meanwhile collapse into a single re-run after it.
    private func startAnalysis() {
        guard visible else { return }
        if analysisTask != nil { rerun = true; return }
        analysisTask = Task {
            await analyse()
            guard !Task.isCancelled else { return }
            analysisTask = nil
            if rerun { rerun = false; if store.dataStamp != analysedStamp || pendingRequest != nil { scheduleAnalysis() } }
        }
    }

    private func analyse() async {
        LeakProbe.add("Flows.analysis")
        defer { LeakProbe.remove("Flows.analysis") }
        PaneProbe.flowAnalysisStarted()
        analysisToken += 1
        let token = analysisToken
        analysing = true
        let packets = store.packets
        analysedStamp = store.dataStamp
        let work = Task.detached(priority: .userInitiated) {
            TCPFlowAnalyzer.analyze(packets) { Task.isCancelled }
        }
        let result = await withTaskCancellationHandler { await work.value } onCancel: { work.cancel() }
        guard token == analysisToken, !Task.isCancelled else { return }
        apply(result)
    }

    private func apply(_ result: [TCPFlow]) {
        let previous = flows
        flows = result
        analysing = false
        analysedAt = Date()
        var state = selectionState
        let revealed = state.apply(result, previous: previous)
        if let revealed { revealSelection(revealed) }
        // `-demoFlowSelect largest` (screenshots of a real capture).
        if state.selection == nil, DemoFlags.flowSelect == "largest",
           let big = result.max(by: { $0.bytesToClient + $0.bytesToServer < $1.bytesToClient + $1.bytesToServer }) {
            state.selection = big.id
            state.selectedBySelf = big.id
        }
        selectionState = state
    }

    private func select(key: FlowKey, packetID: Int?) {
        // Before the first analysis of these packets has finished (the Flows pane just opened),
        // or when the frame is newer than the last analysis: wait for the next one.
        let analysedUpTo = flows.map(\.lastPacketID).max() ?? 0
        if let match = FlowSelectRequest.match(flows, key: key, packetID: packetID),
           packetID.map({ $0 <= analysedUpTo }) ?? true {
            revealSelection(match)
            let event = packetID.flatMap { id in match.events.first { $0.packetIDs.contains(id) }?.id }
            if selection == match.id { selectedEvent = event } else { pendingEventPacket = packetID }
            pendingRequest = nil
            selectedBySelf = match.id
            selection = match.id
        } else {
            pendingRequest = FlowSelectRequest(key: key, packetID: packetID)
            selectedBySelf = selection
            if !DemoFlags.flows { startAnalysis() }
        }
    }

    private func copySummary() {
        guard let flow = selectedFlow else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(FlowSummary.text(flow), forType: .string)
    }

    private func revealSelection(_ flow: TCPFlow) {
        if problemsOnly && flow.health == .ok { problemsOnly = false }
        if !filterText.isEmpty { filterText = "" }
    }

    private func loadDemo() {
        analysisToken += 1
        apply(TCPFlowAnalyzer.analyze(TCPFlowDemo.packets()))
        if selection == nil {
            selection = DemoFlags.flowSelect.flatMap(Int.init) ?? flows.first?.id
        }
        if let path = DemoFlags.flowsExport, let flow = selectedFlow {
            DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
                writePNG(flow: flow, to: URL(fileURLWithPath: path))
            }
        }
    }

    // MARK: Export

    private func exportPNG() {
        guard let flow = selectedFlow else { return }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.png]
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = "flow \(flow.client)-\(flow.clientPort) to \(flow.server)-\(flow.serverPort).png"
            .replacingOccurrences(of: ":", with: "_")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        writePNG(flow: flow, to: url)
    }

    private func writePNG(flow: TCPFlow, to url: URL) {
        let layout = LadderLayout.make(flow: flow, collapseAcks: collapseAcks, width: max(ladderWidth, 640))
        let content = LadderExport(flow: flow, layout: layout)
            .environment(\.colorScheme, colorScheme)
        let renderer = ImageRenderer(content: content)
        // The export view adds a title and note (~80 pt) around the ladder.
        renderer.scale = LadderLayout.exportScale(width: layout.width, height: layout.height + 120)
        guard let cg = renderer.cgImage else {
            AppModel.shared.report("Could not render the diagram.")
            return
        }
        let rep = NSBitmapImageRep(cgImage: cg)
        guard let data = rep.representation(using: .png, properties: [:]) else {
            AppModel.shared.report("Could not encode the PNG.")
            return
        }
        do { try data.write(to: url, options: .atomic) }
        catch { AppModel.shared.report("Could not save \(url.lastPathComponent).", detail: error.localizedDescription) }
    }
}

/// Title and icon, or the icon alone (VoiceOver still reads the title) when the pane is narrow.
struct AdaptiveLabelStyle: LabelStyle {
    let iconOnly: Bool

    func makeBody(configuration: Configuration) -> some View {
        if iconOnly {
            Label(configuration).labelStyle(.iconOnly)
        } else {
            Label(configuration).labelStyle(.titleAndIcon)
        }
    }
}

// MARK: - Table rows

nonisolated struct FlowRow: Identifiable {
    let id: Int
    let health: TCPFlow.Health
    let healthRank: Int
    let start: Date
    let client: String
    let server: String
    let app: String
    let packets: Int
    let bytes: Int
    let duration: Double
    let rtt: Double?
    let response: Double?
    let problems: String

    var rttSort: Double { rtt ?? .greatestFiniteMagnitude }
    var responseSort: Double { response ?? .greatestFiniteMagnitude }

    init(_ f: TCPFlow) {
        id = f.id
        health = f.health
        healthRank = switch f.health { case .bad: 0; case .warn: 1; case .ok: 2 }
        start = f.firstTime
        client = f.clientEndpoint
        server = f.serverEndpoint
        app = f.application
        packets = f.packetCount
        bytes = f.bytesToServer + f.bytesToClient
        duration = f.duration
        rtt = f.handshakeRTT
        response = f.firstResponseTime
        problems = f.reasons.joined(separator: ", ")
    }

    static let defaultOrder = [KeyPathComparator(\FlowRow.healthRank), KeyPathComparator(\FlowRow.start)]
}

// MARK: - Colours and labels

enum FlowStyle {
    static func healthColor(_ h: TCPFlow.Health) -> Color {
        switch h {
        case .ok: Theme.ok
        case .warn: Theme.warn
        case .bad: Theme.err
        }
    }

    /// Kinds that are trouble whatever the analyser said. A RST is not one of them: after a FIN
    /// it is how browsers close; the analyser puts a problem on the RSTs that are trouble.
    static func isProblemKind(_ k: TCPFlow.EventKind) -> Bool {
        switch k {
        case .retransmission, .dupAck, .zeroWindow: true
        default: false
        }
    }

    static func color(for e: TCPFlow.Event, handshakeAck: Bool) -> Color {
        if e.problem != nil || isProblemKind(e.kind) { return Theme.err }
        switch e.kind {
        case .syn, .synAck: return Theme.accent
        case .ack: return handshakeAck ? Theme.accent : Theme.dimText
        case .fin, .keepAlive, .zeroWindowProbe, .gap, .rst: return Theme.dimText
        case .data, .httpRequest, .httpResponse, .tlsClientHello, .tlsServerHello: return Theme.ok
        case .outOfOrder: return Theme.warn
        case .retransmission, .dupAck, .zeroWindow: return Theme.err
        }
    }
}

/// The health mark: a filled dot for healthy and problem, a ring for a warning — in the dark
/// appearance the family's warn and err colours are close, and the shape still tells them apart.
struct HealthDot: View {
    let health: TCPFlow.Health
    var size: CGFloat = 8

    var body: some View {
        ZStack {
            if health == .warn {
                Circle().strokeBorder(Theme.warn, lineWidth: 2)
            } else {
                Circle().fill(FlowStyle.healthColor(health))
            }
        }
        .frame(width: size, height: size)
    }
}

// MARK: - Ladder header, legend

private struct LadderHeader: View {
    let flow: TCPFlow

    var body: some View {
        VStack(spacing: 6) {
            HStack(spacing: 8) {
                HealthDot(health: flow.health)
                Text(flow.application)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(Theme.text)
                    .proseText()
                Text("\(flow.clientEndpoint)  ⇄  \(flow.serverEndpoint)")
                    .font(.system(size: 11.5, design: .monospaced))
                    .foregroundStyle(Theme.dimText)
                    .identifierText()
                    .textSelection(.enabled)
            }
            PillFlow(spacing: 6) {
                ForEach(Array(pills.enumerated()), id: \.offset) { _, pill in
                    StatusPill(text: pill.0, kind: pill.1)
                }
            }
            if !flow.reasons.isEmpty {
                Text(flow.reasons.joined(separator: " · "))
                    .font(.system(size: 11.5))
                    .foregroundStyle(flow.health == .bad ? Theme.err : Theme.warn)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if !flow.notes.isEmpty {
                Text(flow.notes.joined(separator: " · "))
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.dimText)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }

    private var pills: [(String, StatusPill.Kind)] {
        var out: [(String, StatusPill.Kind)] = []
        if let rtt = flow.handshakeRTT {
            out.append(("RTT \(TCPFlowAnalyzer.msText(rtt))", rtt > 0.3 ? .warn : .neutral))
        }
        if let r = flow.firstResponseTime {
            let slowest = max(r, flow.longestResponseWait ?? 0)
            out.append(("Response \(TCPFlowAnalyzer.msText(r))", slowest > 3 ? .bad : r > 1 ? .warn : .neutral))
        }
        if flow.retransmissions > 0 {
            out.append(("\(flow.retransmissions) retransmission\(flow.retransmissions == 1 ? "" : "s")",
                        flow.health == .bad && flow.reasons.contains { $0.contains("retransmissions (") } ? .bad : .warn))
        }
        if flow.spuriousRetransmissions > 0 { out.append(("\(flow.spuriousRetransmissions) spurious", .warn)) }
        if flow.outOfOrder > 0 { out.append(("\(flow.outOfOrder) out of order", .warn)) }
        if flow.refused { out.append(("Refused", .warn)) }
        if flow.dupAcks > 0 { out.append(("\(flow.dupAcks) dup ACK\(flow.dupAcks == 1 ? "" : "s")", flow.dupAcks >= 3 ? .warn : .neutral)) }
        if flow.resets > 0 { out.append(("\(flow.resets) reset\(flow.resets == 1 ? "" : "s")", flow.health == .bad ? .bad : flow.health == .warn ? .warn : .neutral)) }
        if flow.zeroWindows > 0 { out.append(("\(flow.zeroWindows) zero window", .bad)) }
        out.append(("\(Format.count(flow.packetCount)) packets · \(Format.bytes(flow.bytesToServer + flow.bytesToClient))", .neutral))
        if flow.health == .ok { out.append(("Healthy", .ok)) }
        return out
    }
}

/// Centred rows that wrap, for the metric pills.
private struct PillFlow: Layout {
    var spacing: CGFloat = 6

    private func rows(_ sizes: [CGSize], width: CGFloat) -> [[Int]] {
        var rows: [[Int]] = [[]]
        var x: CGFloat = 0
        for (i, s) in sizes.enumerated() {
            if !rows[rows.count - 1].isEmpty, x + s.width > width {
                rows.append([]); x = 0
            }
            rows[rows.count - 1].append(i)
            x += s.width + spacing
        }
        return rows
    }

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let sizes = subviews.map { $0.sizeThatFits(.unspecified) }
        let width = proposal.width ?? sizes.reduce(0) { $0 + $1.width + spacing }
        let rs = rows(sizes, width: width)
        let height = rs.reduce(0) { h, r in h + (r.map { sizes[$0].height }.max() ?? 0) } + spacing * CGFloat(max(0, rs.count - 1))
        let used = rs.map { r in r.reduce(0) { $0 + sizes[$1].width } + spacing * CGFloat(max(0, r.count - 1)) }.max() ?? 0
        return CGSize(width: min(width, used), height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let sizes = subviews.map { $0.sizeThatFits(.unspecified) }
        var y = bounds.minY
        for r in rows(sizes, width: bounds.width) {
            let rowWidth = r.reduce(0) { $0 + sizes[$1].width } + spacing * CGFloat(max(0, r.count - 1))
            let rowHeight = r.map { sizes[$0].height }.max() ?? 0
            var x = bounds.midX - rowWidth / 2
            for i in r {
                subviews[i].place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(sizes[i]))
                x += sizes[i].width + spacing
            }
            y += rowHeight + spacing
        }
    }
}

private struct FlowLegend: View {
    var body: some View {
        // Three steps down to the 420 pt minimum ladder: at that width even the two-row form
        // runs off both edges ("…arning", "Server processin…").
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 12) { health; Rectangle().fill(Theme.hairline).frame(width: 0.5, height: 12); arrows }
            VStack(alignment: .leading, spacing: 5) { health; arrows }
            VStack(alignment: .leading, spacing: 5) {
                health
                HStack(spacing: 12) { arrowsFirst }.fixedSize()
                HStack(spacing: 12) { arrowsSecond }.fixedSize()
            }
        }
        .font(.system(size: 11))
        .foregroundStyle(Theme.dimText)
        .lineLimit(1)
        .fixedSize(horizontal: false, vertical: true)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
    }

    private var health: some View {
        HStack(spacing: 12) {
            dot(.ok, "Healthy")
            dot(.warn, "Warning")
            dot(.bad, "Problem")
        }
        .fixedSize()
    }

    private var arrows: some View {
        HStack(spacing: 12) { arrowsFirst; arrowsSecond }
            .fixedSize()
    }

    @ViewBuilder private var arrowsFirst: some View {
        line(Theme.accent, "Handshake")
        line(Theme.ok, "Data")
        line(Theme.dimText, "ACK / FIN")
    }

    @ViewBuilder private var arrowsSecond: some View {
        line(Theme.err, "Loss / reset")
        line(Theme.warn, "Reordered", dashed: true)
        HStack(spacing: 4) {
            RoundedRectangle(cornerRadius: 1.5).fill(Theme.warn).frame(width: 5, height: 12)
            RoundedRectangle(cornerRadius: 1.5).fill(Theme.err).frame(width: 5, height: 12)
            Text("Server processing (red: over 1 s)")
        }
    }

    private func dot(_ h: TCPFlow.Health, _ t: String) -> some View {
        HStack(spacing: 4) { HealthDot(health: h, size: 7); Text(t) }
    }

    private func line(_ c: Color, _ t: String, dashed: Bool = false) -> some View {
        HStack(spacing: 4) {
            if dashed {
                HStack(spacing: 2) { ForEach(0..<3, id: \.self) { _ in Capsule().fill(c).frame(width: 3.5, height: 2) } }
                    .frame(width: 14)
            } else {
                Capsule().fill(c).frame(width: 14, height: 2)
            }
            Text(t)
        }
    }
}

// MARK: - Ladder layout

/// Where every arrow, label and bar of the diagram goes. Rows are event order, not time.
struct LadderLayout {
    struct Item {
        let event: TCPFlow.Event
        let y: CGFloat
        let label: String
        let labelRect: CGRect
        let tailTime: Double
        let headTime: Double
        let handshakeAck: Bool
    }

    struct Bar {
        let top: CGFloat
        let bottom: CGFloat
        let seconds: Double
    }

    static let slant: CGFloat = 28
    static let firstRow: CGFloat = 92
    static let boxTop: CGFloat = 12
    static let boxHeight: CGFloat = 44
    static let cap = 400
    static let labelFont = NSFont.systemFont(ofSize: 11)

    let width: CGFloat
    let height: CGFloat
    let leftX: CGFloat
    let rightX: CGFloat
    let items: [Item]
    let bars: [Bar]
    let hidden: Int
    let clientTitle: String
    let serverTitle: String
    let note: String

    static func make(flow: TCPFlow, collapseAcks: Bool, width: CGFloat) -> LadderLayout {
        let span = min(max(240, width - 2 * 92), 640)
        let leftX = ((width - span) / 2).rounded()
        let rightX = leftX + span

        // Which events to draw.
        var kept: [(TCPFlow.Event, Bool)] = []
        var previous: TCPFlow.EventKind?
        var lastKept: TCPFlow.EventKind?
        for e in flow.events {
            let handshakeAck = e.kind == .ack && previous == .synAck
            previous = e.kind
            if collapseAcks, e.kind == .ack, !handshakeAck, lastKept != .fin { continue }
            kept.append((e, handshakeAck))
            lastKept = e.kind
        }
        // The cap counts arrows; idle gaps between them are markers, not events.
        func isGap(_ e: TCPFlow.Event) -> Bool { if case .gap = e.kind { true } else { false } }
        var hidden = 0
        var arrows = 0
        if let cut = kept.firstIndex(where: { e, _ in
            if !isGap(e) { arrows += 1 }
            return arrows > cap
        }) {
            hidden = kept[cut...].filter { !isGap($0.0) }.count
            kept.removeSubrange(cut...)
            while let last = kept.last, isGap(last.0) { kept.removeLast() }
        }

        // Request → first answering server data, for the processing bars.
        var pairs: [Int: Int] = [:]   // response index → request index
        var lastRequest: Int?
        for (i, (e, _)) in kept.enumerated() where carriesData(e.kind) {
            if e.direction == .clientToServer { lastRequest = i }
            else if let r = lastRequest { pairs[i] = r; lastRequest = nil }
        }

        let cDelay = flow.clientSideDelay ?? 0
        let sDelay = flow.serverSideDelay ?? 0
        let maxLabel = span * 0.74

        var items: [Item] = []
        var bars: [Bar] = []
        var y = firstRow
        for (i, (e, hsAck)) in kept.enumerated() {
            if let r = pairs[i] {
                let req = kept[r].0
                let reqEnd = req.endTime ?? req.time
                // Server-side send time minus server-side arrival of the request's last byte.
                // Negative = the server sent this before the request reached it (a stream, TLS
                // records crossing): not an answer, so no "processing 0.0 ms" bar.
                let processing = (e.time - sDelay) - (reqEnd + sDelay)
                if processing > -0.0005 {
                    y += 30
                    bars.append(Bar(top: items[r].y + slant, bottom: y, seconds: max(0, processing)))
                }
            }
            let label = fit(label(for: e, flow: flow), width: maxLabel)
            let size = (label as NSString).size(withAttributes: [.font: labelFont])
            let w = ceil(size.width) + 14, h: CGFloat = 19
            let c2s = e.direction == .clientToServer
            let cx = c2s ? leftX + 16 + w / 2 : rightX - 16 - w / 2
            let frac = c2s ? (cx - leftX) / span : (rightX - cx) / span
            let cy = y + slant * frac
            let rect: CGRect
            if case .gap = e.kind {
                rect = CGRect(x: leftX + 12, y: y + 22 - h / 2, width: w, height: h)
            } else {
                rect = CGRect(x: cx - w / 2, y: cy - h / 2, width: w, height: h)
            }
            let tail = c2s ? e.time - cDelay : e.time - sDelay
            let head = c2s ? e.time + sDelay : e.time + cDelay
            items.append(Item(event: e, y: y, label: label, labelRect: rect,
                              tailTime: max(0, tail + cDelay), headTime: max(0, head + cDelay),
                              handshakeAck: hsAck))
            if case .gap = e.kind { y += 46 + (e.problem != nil ? 12 : 0) }
            else { y += slant + (e.problem != nil && !label.hasPrefix(e.problem ?? "\u{0}") ? 14 : 0) }
        }
        let height = y + slant + (hidden > 0 ? 44 : 24)

        var note = "Rows are event order, not time. Times are ms since the SYN"
        if flow.clientSideDelay != nil || flow.serverSideDelay != nil {
            note += String(format: ", placed on each lifeline using the handshake (capture ↔ client %@, capture ↔ server %@)",
                           TCPFlowAnalyzer.msText(cDelay), TCPFlowAnalyzer.msText(sDelay))
        } else {
            note = "Rows are event order, not time. Times are ms since the flow’s first packet, as captured"
        }
        note += "."

        return LadderLayout(width: width, height: height, leftX: leftX, rightX: rightX, items: items, bars: bars,
                            hidden: hidden, clientTitle: flow.clientEndpoint, serverTitle: flow.serverEndpoint,
                            note: note)
    }

    /// Pixels per point for Export PNG: 2× (Retina) unless the bitmap would pass 16,384 px on a
    /// side (a 400-arrow ladder is ~11,000–27,000 pt tall) or 64 M pixels.
    static func exportScale(width: CGFloat, height: CGFloat) -> CGFloat {
        let side = max(width, height, 1)
        let bySide = 16_384 / side
        let byArea = (64_000_000 / max(1, width * height)).squareRoot()
        return max(0.25, min(2, bySide, byArea))
    }

    static func carriesData(_ k: TCPFlow.EventKind) -> Bool {
        switch k {
        case .data, .httpRequest, .httpResponse, .tlsClientHello, .tlsServerHello, .retransmission, .outOfOrder: true
        default: false
        }
    }

    static func label(for e: TCPFlow.Event, flow: TCPFlow) -> String {
        let n = e.packetIDs.count
        switch e.kind {
        case .syn: return "SYN"
        case .synAck: return "SYN, ACK"
        case .ack: return n > 1 ? "\(n)× ACK" : "ACK"
        case .fin: return "FIN, ACK"
        case .rst: return "RST"
        case .data(let count, let bytes):
            return count > 1 ? "\(count)× TCP segments · \(Format.count(bytes)) bytes"
                             : "TCP segment · \(Format.count(bytes)) bytes"
        case .retransmission(let bytes):
            return n > 1 ? "\(n)× Retransmission · \(Format.count(bytes)) bytes" : "Retransmission · \(Format.count(bytes)) bytes"
        case .outOfOrder(let bytes):
            return n > 1 ? "\(n)× Out of order · \(Format.count(bytes)) bytes" : "Out of order · \(Format.count(bytes)) bytes"
        case .dupAck(let count): return count > 1 ? "\(count)× Dup ACK" : "Dup ACK"
        case .zeroWindow: return n > 1 ? "\(n)× Zero window" : "Zero window"
        case .keepAlive: return "Keep-alive"
        case .zeroWindowProbe: return "Zero window probe · 1 byte"
        case .httpRequest(let s): return s
        case .httpResponse(let s): return "HTTP \(s)"
        case .tlsClientHello(let sni): return sni.isEmpty ? "Client Hello" : "Client Hello (\(sni))"
        case .tlsServerHello: return "Server Hello"
        case .gap(let s): return "… \(String(format: "%.1f", s)) s"
        }
    }

    static let noteFont = NSFont.systemFont(ofSize: 10)

    /// A problem note cut (with "…") to `width` at the 10 pt note font.
    static func fitNote(_ s: String, width: CGFloat) -> String {
        func w(_ t: String) -> CGFloat { (t as NSString).size(withAttributes: [.font: noteFont]).width }
        guard w(s) > width else { return s }
        var t = s
        while t.count > 4, w(t + "…") > width { t.removeLast() }
        return t + "…"
    }

    private static func fit(_ s: String, width: CGFloat) -> String {
        func w(_ t: String) -> CGFloat { (t as NSString).size(withAttributes: [.font: labelFont]).width + 14 }
        guard w(s) > width else { return s }
        var t = s
        while t.count > 4, w(t + "…") > width { t.removeLast() }
        return t + "…"
    }

    /// The event whose arrow (within 6 pt) or label box contains `p`.
    func hit(_ p: CGPoint) -> Int? {
        var best: (Int, CGFloat)?
        for item in items {
            if item.labelRect.insetBy(dx: -2, dy: -2).contains(p) { return item.event.id }
            if case .gap = item.event.kind { continue }
            let (a, b) = endpoints(item)
            let d = Self.distance(p, a, b)
            if d <= 6, d < (best?.1 ?? .infinity) { best = (item.event.id, d) }
        }
        return best?.0
    }

    func endpoints(_ item: Item) -> (CGPoint, CGPoint) {
        let c2s = item.event.direction == .clientToServer
        return (CGPoint(x: c2s ? leftX : rightX, y: item.y),
                CGPoint(x: c2s ? rightX : leftX, y: item.y + Self.slant))
    }

    private static func distance(_ p: CGPoint, _ a: CGPoint, _ b: CGPoint) -> CGFloat {
        let dx = b.x - a.x, dy = b.y - a.y
        let len2 = dx * dx + dy * dy
        guard len2 > 0 else { return hypot(p.x - a.x, p.y - a.y) }
        let t = max(0, min(1, ((p.x - a.x) * dx + (p.y - a.y) * dy) / len2))
        return hypot(p.x - (a.x + t * dx), p.y - (a.y + t * dy))
    }
}

// MARK: - Ladder drawing

struct LadderCanvas: View {
    let layout: LadderLayout
    var selected: Int?

    var body: some View {
        Canvas { ctx, size in draw(&ctx, size) }
            .frame(width: nil, height: layout.height)
    }

    private func draw(_ ctx: inout GraphicsContext, _ size: CGSize) {
        let L = layout
        drawLifelines(&ctx)
        endpointBox(&ctx, x: L.leftX, symbol: "laptopcomputer", title: "Client", detail: L.clientTitle)
        endpointBox(&ctx, x: L.rightX, symbol: "server.rack", title: "Server", detail: L.serverTitle)
        drawProcessingBars(&ctx)
        drawEvents(&ctx)
        if L.hidden > 0 {
            ctx.draw(Text("… \(Format.count(L.hidden)) more events (showing the first \(LadderLayout.cap))")
                        .font(.system(size: 11)).foregroundStyle(Theme.faintText),
                     at: CGPoint(x: (L.leftX + L.rightX) / 2, y: L.height - 18), anchor: .center)
        }
    }

    /// Lifelines: solid, dashed across idle gaps.
    private func drawLifelines(_ ctx: inout GraphicsContext) {
        let L = layout
        let lifelineTop = LadderLayout.boxTop + LadderLayout.boxHeight
        let bottom = L.height - (L.hidden > 0 ? 36 : 12)
        var gaps: [(CGFloat, CGFloat)] = []
        for item in L.items { if case .gap = item.event.kind { gaps.append((item.y, item.y + 44)) } }
        for x in [L.leftX, L.rightX] {
            var y0 = lifelineTop
            for (g0, g1) in gaps {
                stroke(&ctx, from: CGPoint(x: x, y: y0), to: CGPoint(x: x, y: g0), Theme.hairline, 1.5)
                var dashed = Path()
                dashed.move(to: CGPoint(x: x, y: g0)); dashed.addLine(to: CGPoint(x: x, y: g1))
                ctx.stroke(dashed, with: .color(Theme.dimText), style: StrokeStyle(lineWidth: 1.5, dash: [3, 4]))
                y0 = g1
            }
            stroke(&ctx, from: CGPoint(x: x, y: y0), to: CGPoint(x: x, y: bottom), Theme.hairline, 1.5)
        }
    }

    /// Server processing time, as bars on the server lifeline.
    private func drawProcessingBars(_ ctx: inout GraphicsContext) {
        let L = layout
        for bar in L.bars where bar.bottom > bar.top {
            let slow = bar.seconds > 1
            let tint = slow ? Theme.err : Theme.warn
            let rect = CGRect(x: L.rightX - 3, y: bar.top, width: 6, height: bar.bottom - bar.top)
            ctx.fill(Path(roundedRect: rect, cornerRadius: 2), with: .color(tint.opacity(0.85)))
            ctx.draw(Text("processing \(TCPFlowAnalyzer.msText(bar.seconds))")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(tint),
                     at: CGPoint(x: L.rightX - 10, y: (bar.top + bar.bottom) / 2), anchor: .trailing)
        }
    }

    /// Arrows with their times, label boxes and problem notes; idle-gap labels.
    private func drawEvents(_ ctx: inout GraphicsContext) {
        let L = layout
        var lastTimeY: [CGFloat] = [-100, -100]   // left, right
        var lastTimeText = ["", ""]
        for item in L.items {
            let e = item.event
            let isSel = e.id == selected
            if case .gap = e.kind {
                drawGap(&ctx, item)
                continue
            }
            let (a, b) = L.endpoints(item)
            let tint = FlowStyle.color(for: e, handshakeAck: item.handshakeAck)
            let problem = e.problem != nil || FlowStyle.isProblemKind(e.kind)
            let width: CGFloat = problem ? 2 : 1.5
            if isSel { stroke(&ctx, from: a, to: b, Theme.selectedAccent, 9) }
            var reordered = false
            if case .outOfOrder = e.kind { reordered = true }
            arrow(&ctx, from: a, to: b, tint, width, dashed: reordered)

            // Times on the outside of the lifelines.
            let c2s = e.direction == .clientToServer
            timeLabel(&ctx, item.tailTime, side: c2s ? 0 : 1, y: a.y, last: &lastTimeY, lastText: &lastTimeText)
            timeLabel(&ctx, item.headTime, side: c2s ? 1 : 0, y: b.y, last: &lastTimeY, lastText: &lastTimeText)

            // Label box on the sender's side.
            let box = Path(roundedRect: item.labelRect, cornerRadius: 5)
            ctx.fill(box, with: .color(Theme.panel))
            ctx.stroke(box, with: .color(isSel ? Theme.accent : (problem ? Theme.err : Theme.hairline)),
                       lineWidth: isSel || problem ? 1 : 0.75)
            ctx.draw(Text(item.label).font(.system(size: 11, weight: problem ? .medium : .regular))
                        .foregroundStyle(problem ? Theme.err : Theme.text),
                     at: CGPoint(x: item.labelRect.midX, y: item.labelRect.midY), anchor: .center)
            if let p = e.problem, !item.label.hasPrefix(p) {
                // Kept between the lifelines: at the 420 pt minimum a long note ran over the
                // client's time labels ("Slow handshake: …" on top of "328 ms").
                let note = LadderLayout.fitNote(p, width: L.rightX - L.leftX - 12)
                let at = CGPoint(x: c2s ? item.labelRect.minX + 2 : item.labelRect.maxX - 2, y: item.labelRect.maxY + 2)
                // A ground under the note: it sits where the arrow runs, and the line struck
                // through the text ("Slow handshake …" over the SYN, ACK arrow).
                let size = (note as NSString).size(withAttributes: [.font: LadderLayout.noteFont])
                let ground = CGRect(x: c2s ? at.x - 2 : at.x - size.width - 2, y: at.y, width: size.width + 4, height: size.height)
                ctx.fill(Path(roundedRect: ground, cornerRadius: 3), with: .color(Theme.panel))
                ctx.draw(Text(note).font(.system(size: 10)).foregroundStyle(Theme.err),
                         at: at, anchor: c2s ? .topLeading : .topTrailing)
            }
        }
    }

    /// An idle gap's label, beside the dashed stretch of the client lifeline.
    private func drawGap(_ ctx: inout GraphicsContext, _ item: LadderLayout.Item) {
        let e = item.event
        let at = CGPoint(x: layout.leftX + 14, y: item.y + 22)
        let tint = e.problem != nil ? Theme.err : Theme.dimText
        ctx.draw(Text(item.label).font(.system(size: 11, weight: .medium)).foregroundStyle(tint),
                 at: at, anchor: .leading)
        if let p = e.problem {
            ctx.draw(Text(p).font(.system(size: 10)).foregroundStyle(Theme.err),
                     at: CGPoint(x: at.x, y: at.y + 14), anchor: .leading)
        }
    }

    private func stroke(_ ctx: inout GraphicsContext, from a: CGPoint, to b: CGPoint, _ c: Color, _ w: CGFloat) {
        var p = Path()
        p.move(to: a); p.addLine(to: b)
        ctx.stroke(p, with: .color(c), style: StrokeStyle(lineWidth: w, lineCap: .round))
    }

    private func arrow(_ ctx: inout GraphicsContext, from a: CGPoint, to b: CGPoint, _ c: Color, _ w: CGFloat,
                       dashed: Bool = false) {
        let dx = b.x - a.x, dy = b.y - a.y
        let len = max(1, hypot(dx, dy))
        let ux = dx / len, uy = dy / len
        let headLen: CGFloat = 9, half: CGFloat = 4.5
        let base = CGPoint(x: b.x - ux * headLen, y: b.y - uy * headLen)
        if dashed {
            var p = Path()
            p.move(to: a); p.addLine(to: base)
            ctx.stroke(p, with: .color(c), style: StrokeStyle(lineWidth: w, lineCap: .round, dash: [5, 4]))
        } else {
            stroke(&ctx, from: a, to: base, c, w)
        }
        var tri = Path()
        tri.move(to: b)
        tri.addLine(to: CGPoint(x: base.x - uy * half, y: base.y + ux * half))
        tri.addLine(to: CGPoint(x: base.x + uy * half, y: base.y - ux * half))
        tri.closeSubpath()
        ctx.fill(tri, with: .color(c))
    }

    private func timeLabel(_ ctx: inout GraphicsContext, _ t: Double, side: Int, y: CGFloat,
                           last: inout [CGFloat], lastText: inout [String]) {
        let text = TCPFlowAnalyzer.msText(t)
        // The head of one arrow and the tail of the next often share a row: say the time once.
        if text == lastText[side], abs(y - last[side]) < 12 { return }
        let yy = max(y, last[side] + 12)
        last[side] = yy
        lastText[side] = text
        let x = side == 0 ? layout.leftX - 9 : layout.rightX + 9
        ctx.draw(Text(text).font(.system(size: 10, design: .monospaced)).foregroundStyle(Theme.dimText),
                 at: CGPoint(x: x, y: yy), anchor: side == 0 ? .trailing : .leading)
    }

    private func endpointBox(_ ctx: inout GraphicsContext, x: CGFloat, symbol: String, title: String, detail full: String) {
        // Each box stays in its half of the canvas: an IPv6 endpoint is wider than the margin
        // outside the lifeline, and would be cut off at the pane's edge. Too long → shortened in
        // the middle (the port and the address's end stay).
        let font = NSFont.monospacedSystemFont(ofSize: 10.5, weight: .regular)
        func width(_ t: String) -> CGFloat { (t as NSString).size(withAttributes: [.font: font]).width }
        let half = layout.width / 2
        let maxW = max(120, half - 12)
        var detail = full
        if width(detail) + 48 > maxW, detail.count > 12 {
            let chars = Array(full)
            var keep = chars.count - 1
            while keep > 8, width(String(chars.prefix(keep / 2)) + "…" + String(chars.suffix(keep - keep / 2))) + 48 > maxW { keep -= 1 }
            detail = String(chars.prefix(keep / 2)) + "…" + String(chars.suffix(keep - keep / 2))
        }
        let w = min(maxW, max(120, width(detail) + 48))
        let left = x < half
        let minX = left ? 6 : half + 6
        let maxX = left ? half - 6 - w : layout.width - 6 - w
        let rect = CGRect(x: min(max(x - w / 2, minX), max(minX, maxX)), y: LadderLayout.boxTop, width: w, height: LadderLayout.boxHeight)
        let box = Path(roundedRect: rect, cornerRadius: 8)
        ctx.fill(box, with: .color(Theme.panel))
        ctx.fill(box, with: .color(Theme.well))
        ctx.stroke(box, with: .color(Theme.hairline), lineWidth: 0.75)
        ctx.draw(Text(Image(systemName: symbol)).font(.system(size: 15)).foregroundStyle(Theme.dimText),
                 at: CGPoint(x: rect.minX + 20, y: rect.midY), anchor: .center)
        ctx.draw(Text(title).font(.system(size: 11.5, weight: .semibold)).foregroundStyle(Theme.text),
                 at: CGPoint(x: rect.minX + 36, y: rect.midY - 8), anchor: .leading)
        ctx.draw(Text(detail).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(Theme.text2),
                 at: CGPoint(x: rect.minX + 36, y: rect.midY + 8), anchor: .leading)
    }
}

/// What Export PNG renders: a title line, the diagram and the note.
private struct LadderExport: View {
    let flow: TCPFlow
    let layout: LadderLayout

    var body: some View {
        VStack(spacing: 6) {
            Text("\(flow.application) — \(flow.clientEndpoint) ⇄ \(flow.serverEndpoint)")
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(Theme.text)
            if !flow.reasons.isEmpty {
                Text(flow.reasons.joined(separator: " · "))
                    .font(.system(size: 11.5))
                    .foregroundStyle(flow.health == .bad ? Theme.err : Theme.warn)
            }
            LadderCanvas(layout: layout, selected: nil)
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

/// The whole conversation on one line: its duration left to right, a tick wherever a problem
/// happened (red; reordering orange), idle stretches shaded. A 2-minute flow capped at 400
/// ladder rows still shows *when* its trouble was; the part the ladder does not draw is hatched.
/// Click a tick to select that event in the ladder.
struct FlowTimeline: View {
    let flow: TCPFlow
    let layout: LadderLayout
    @Binding var selected: Int?

    struct Mark {
        let event: TCPFlow.Event
        let color: Color
    }

    static func marks(_ flow: TCPFlow) -> [Mark] {
        flow.events.compactMap { e in
            if case .gap = e.kind { return e.problem != nil ? Mark(event: e, color: Theme.err) : nil }
            if e.problem != nil || FlowStyle.isProblemKind(e.kind) { return Mark(event: e, color: Theme.err) }
            if case .outOfOrder = e.kind { return Mark(event: e, color: Theme.warn) }
            return nil
        }
    }

    /// Seconds up to which the ladder draws events (nil: all of them).
    static func shownUntil(_ layout: LadderLayout) -> Double? {
        guard layout.hidden > 0, let last = layout.items.last?.event else { return nil }
        return last.endTime ?? last.time
    }

    var body: some View {
        let marks = Self.marks(flow)
        let until = Self.shownUntil(layout)
        let shownIDs = Set(layout.items.map(\.event.id))
        VStack(spacing: 3) {
            GeometryReader { geo in
                let w = geo.size.width
                Canvas { ctx, size in
                    draw(&ctx, size, marks: marks, until: until)
                }
                .contentShape(Rectangle())
                .onTapGesture(coordinateSpace: .local) { p in
                    let hit = marks.min { abs(x(for: $0.event.time, w) - p.x) < abs(x(for: $1.event.time, w) - p.x) }
                    if let hit, abs(x(for: hit.event.time, w) - p.x) <= 6, shownIDs.contains(hit.event.id) {
                        selected = hit.event.id
                    }
                }
            }
            .frame(height: 16)
            HStack(spacing: 6) {
                Text("0")
                Spacer(minLength: 4)
                Text(caption(marks: marks, until: until))
                    .lineLimit(1)
                    .truncationMode(.tail)
                Spacer(minLength: 4)
                Text(FlowTimeline.durationText(flow.duration))
            }
            .font(.system(size: 10, design: .monospaced))
            .foregroundStyle(Theme.faintText)
        }
        .help("The conversation’s \(FlowTimeline.durationText(flow.duration)) from left to right; red ticks are problems, orange reordering. Click a tick to select its event.")
    }

    private func caption(marks: [Mark], until: Double?) -> String {
        var parts: [String] = []
        let red = marks.filter { $0.color == Theme.err }.count
        parts.append(red == 0 ? "no problems" : "\(red) problem\(red == 1 ? "" : "s")")
        if let until { parts.append("ladder shows the first \(FlowTimeline.durationText(until))") }
        return parts.joined(separator: " · ")
    }

    private func x(for t: Double, _ width: CGFloat) -> CGFloat {
        guard flow.duration > 0 else { return 3 }
        return 3 + CGFloat(min(1, max(0, t / flow.duration))) * max(1, width - 6)
    }

    private func draw(_ ctx: inout GraphicsContext, _ size: CGSize, marks: [Mark], until: Double?) {
        let bar = CGRect(x: 0, y: 5, width: size.width, height: 6)
        ctx.fill(Path(roundedRect: bar, cornerRadius: 3), with: .color(Theme.well))
        ctx.stroke(Path(roundedRect: bar, cornerRadius: 3), with: .color(Theme.hairline), lineWidth: 0.5)
        // Idle stretches.
        for e in flow.events {
            guard case .gap = e.kind, let end = e.endTime else { continue }
            let a = x(for: e.time, size.width), b = x(for: end, size.width)
            ctx.fill(Path(CGRect(x: a, y: 6, width: max(1, b - a), height: 4)), with: .color(Theme.hairline))
        }
        // Beyond the ladder's cap.
        if let until {
            let a = x(for: until, size.width)
            var hatch = Path()
            var hx = a
            while hx < size.width { hatch.move(to: CGPoint(x: hx, y: 11)); hatch.addLine(to: CGPoint(x: hx + 5, y: 5)); hx += 5 }
            ctx.stroke(hatch, with: .color(Theme.faintText.opacity(0.6)), lineWidth: 0.75)
        }
        for m in marks {
            let mx = x(for: m.event.time, size.width)
            let isSel = m.event.id == selected
            let rect = CGRect(x: mx - (isSel ? 1.5 : 1), y: isSel ? 0 : 2, width: isSel ? 3 : 2, height: isSel ? 16 : 12)
            ctx.fill(Path(roundedRect: rect, cornerRadius: 1), with: .color(m.color))
        }
    }

    nonisolated static func durationText(_ s: Double) -> String {
        if s < 60 { return TCPFlowAnalyzer.msText(s) }
        let m = Int(s) / 60, sec = Int(s) % 60
        if m < 60 { return "\(m) min \(sec) s" }
        return "\(m / 60) h \(m % 60) min"
    }
}

// MARK: - Copy Summary

/// A plain-text summary of one conversation for a ticket or a chat: who, what, how fast, how
/// much, and each problem with its time and frames.
nonisolated enum FlowSummary {
    private static let stamp = Format.gregorian("yyyy-MM-dd HH:mm:ss.SSS xxx")

    static func text(_ f: TCPFlow) -> String {
        var lines: [String] = []
        lines.append("TCP \(f.clientEndpoint) → \(f.serverEndpoint) (\(f.application))")
        let health = switch f.health { case .ok: "healthy"; case .warn: "warning"; case .bad: "problem" }
        lines.append("Health: \(health)" + (f.reasons.isEmpty ? "" : " — " + f.reasons.joined(separator: "; ")))
        lines.append("Start: \(stamp.string(from: f.firstTime)), duration \(FlowTimeline.durationText(f.duration)), "
                     + "\(Format.count(f.packetCount)) packets (frames \(f.firstPacketID)–\(f.lastPacketID))")
        if let rtt = f.handshakeRTT {
            var s = "Handshake RTT (SYN → SYN/ACK): \(TCPFlowAnalyzer.msText(rtt))"
            if let c = f.clientSideDelay, let sv = f.serverSideDelay {
                s += " — capture ↔ client \(TCPFlowAnalyzer.msText(c)), capture ↔ server \(TCPFlowAnalyzer.msText(sv))"
            }
            lines.append(s)
        } else {
            lines.append("Handshake RTT: — (no SYN / SYN-ACK pair in the capture)")
        }
        if let r = f.firstResponseTime { lines.append("First response: \(TCPFlowAnalyzer.msText(r)) after the client's first data") }
        if let w = f.longestResponseWait, w > 1 { lines.append("Longest wait for the server: \(TCPFlowAnalyzer.msText(w))") }
        lines.append("Bytes: \(Format.count(f.bytesToServer)) to the server, \(Format.count(f.bytesToClient)) to the client (payload)")
        var counts = "Retransmissions \(f.retransmissions)"
        if f.spuriousRetransmissions > 0 { counts += " (\(f.spuriousRetransmissions) spurious)" }
        counts += " · SYN retries \(f.synRetransmissions) · out of order \(f.outOfOrder) · duplicate ACKs \(f.dupAcks)"
        counts += " · resets \(f.resets) · zero windows \(f.zeroWindows)"
        lines.append(counts)
        if !f.requests.isEmpty {
            lines.append("Requests:")
            for r in f.requests.prefix(50) {
                var s = "  +\(String(format: "%.3f", r.time)) s  \(r.request)"
                if let rt = r.responseTime { s += " → \(r.status ?? "answer") after \(TCPFlowAnalyzer.msText(rt))" }
                else { s += " → no answer in the capture" }
                lines.append(s)
            }
            if f.requests.count > 50 { lines.append("  … \(f.requests.count - 50) more") }
        }
        let problems = f.events.filter { $0.problem != nil }
        if !problems.isEmpty {
            lines.append("Problems:")
            for e in problems.prefix(50) {
                let frames = e.packetIDs.prefix(8).map(String.init).joined(separator: ", ")
                    + (e.packetIDs.count > 8 ? ", … (\(e.packetIDs.count))" : "")
                let side = e.direction == .clientToServer ? "client→server" : "server→client"
                var s = "  +\(String(format: "%.3f", e.time)) s  "
                if case .gap = e.kind { s += e.problem ?? "" }
                else { s += "\(side)  \(e.problem ?? "")" }
                if !frames.isEmpty { s += "  [frame\(e.packetIDs.count == 1 ? "" : "s") \(frames)]" }
                lines.append(s)
            }
            if problems.count > 50 { lines.append("  … \(problems.count - 50) more") }
        }
        for n in f.notes { lines.append("Note: \(n)") }
        return lines.joined(separator: "\n") + "\n"
    }
}
