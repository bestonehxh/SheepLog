import Foundation

// MARK: - One time axis for everything

/// Where a click on the timeline (or an evidence button) goes.
nonisolated enum JumpTarget: Sendable, Equatable {
    /// The Log pane with this filter.
    case log(String)
    /// The Packets pane with this filter.
    case packets(String)
    /// The TCP flows pane on this conversation.
    case flow(FlowRef)
    /// The finding in this pane's list.
    case finding(String)
}

nonisolated struct TimelineEvent: Identifiable, Sendable, Equatable {
    nonisolated enum Kind: Sendable, Equatable { case log, trap, flow, finding }
    let id: Int
    let time: Date
    /// Findings are bars from first to last seen.
    var end: Date?
    let kind: Kind
    let severity: FindingSeverity
    let label: String
    let target: JumpTarget
}

/// One row of the strip: a device (or the capture).
nonisolated struct TimelineLane: Identifiable, Sendable, Equatable {
    /// The device name ("Capture" for packets and flows).
    let id: String
    var events: [TimelineEvent]
    var worst: FindingSeverity
    /// Events before thinning (a busy device has thousands of warning lines; one dot per slot is drawn).
    var total: Int
    var problems: Int
    var first: Date
    var last: Date
}

nonisolated struct Timeline: Sendable, Equatable {
    var lanes: [TimelineLane]
    var start: Date
    var end: Date

    static let empty = Timeline(lanes: [], start: Date(timeIntervalSinceReferenceDate: 0), end: Date(timeIntervalSinceReferenceDate: 0))

    var isEmpty: Bool { lanes.isEmpty }
    var span: Double { max(1, end.timeIntervalSince(start)) }

    /// 0…1 across the strip.
    func fraction(_ d: Date) -> Double { min(1, max(0, d.timeIntervalSince(start) / span)) }
    func date(atFraction f: Double) -> Date { start.addingTimeInterval(min(1, max(0, f)) * span) }

    /// One line per lane, for the Markdown report.
    func summaryLines(maxLanes: Int = 20) -> [String] {
        lanes.prefix(maxLanes).map { l in
            "\(l.id): \(Format.count(l.total)) event\(l.total == 1 ? "" : "s")"
                + (l.problems > 0 ? ", \(Format.count(l.problems)) problem\(l.problems == 1 ? "" : "s")" : "")
                + " (\(FText.clock(l.first))–\(FText.clock(l.last)))"
        } + (lanes.count > maxLanes ? ["… \(lanes.count - maxLanes) more devices"] : [])
    }
}

/// Per-lane counters of one chunk of warning lines.
nonisolated struct LaneCount: Sendable {
    var worst = FindingSeverity.info
    var total = 0
    var problems = 0
    var first = Date.distantFuture
    var last = Date.distantPast

    mutating func add(_ sev: FindingSeverity, _ t: Date) {
        total += 1
        if sev == .bad { problems += 1 }
        if sev > worst { worst = sev }
        if t < first { first = t }
        if t > last { last = t }
    }
}

nonisolated struct LanePick: Sendable {
    let sev: FindingSeverity
    let index: Int
    let time: Date
}

nonisolated struct LanePicks: Sendable {
    var picks: [String: [Int: LanePick]] = [:]
    var counts: [String: LaneCount] = [:]
}

nonisolated enum TimelineBuilder {
    /// Dots per lane: one per slot of the strip, the worst of the slot.
    static let slots = 360
    static let captureLane = "Capture"

    /// The slot of a time `offset` seconds into a strip of `span` seconds. Multiplied before the
    /// division: `offset / span * slots` put 20 of the 360 exact slot boundaries into the slot
    /// before (26:00 of a 30-day log, 2 h slots, fell into 24–26 and hid that slot's event).
    static func slot(_ offset: Double, span: Double) -> Int {
        min(slots - 1, max(0, Int(offset * Double(slots) / span + 1e-9)))
    }

    static func build(warn: [WarnFact], times ctx: RuleContext, flows: [TCPFlow], findings: [Finding],
                      start: Date?, end: Date?) -> Timeline {
        var lo = start, hi = end
        for f in findings where f.source != .engine {
            lo = min(lo ?? f.firstSeen, f.firstSeen)
            hi = max(hi ?? f.lastSeen, f.lastSeen)
        }
        guard let lo, var hi else { return .empty }
        if hi.timeIntervalSince(lo) < 60 { hi = lo.addingTimeInterval(60) }
        let span = hi.timeIntervalSince(lo)
        func slot(_ d: Date) -> Int { Self.slot(d.timeIntervalSince(lo), span: span) }

        struct Acc {
            var best: [Int: TimelineEvent] = [:]
            var bars: [TimelineEvent] = []
            var worst = FindingSeverity.info
            var total = 0
            var problems = 0
            var first = Date.distantFuture
            var last = Date.distantPast
            mutating func merge(_ c: LaneCount) {
                total += c.total
                problems += c.problems
                worst = max(worst, c.worst)
                first = min(first, c.first)
                last = max(last, c.last)
            }
            mutating func note(_ e: TimelineEvent) {
                total += 1
                if e.severity == .bad { problems += 1 }
                worst = max(worst, e.severity)
                first = min(first, e.time)
                last = max(last, e.end ?? e.time)
            }
        }
        var lanes: [String: Acc] = [:]
        var nextID = 1
        func add(_ lane: String, _ e: TimelineEvent, _ s: Int) {
            var a = lanes[lane] ?? Acc()
            a.note(e)
            if let cur = a.best[s] {
                if e.severity > cur.severity { a.best[s] = e }
            } else {
                a.best[s] = e
            }
            lanes[lane] = a
        }

        // Warning lines and traps: the worst per slot is picked first (on every core), and only
        // those get a label (a busy log has tens of thousands of them).
        let frozen = ctx
        let start = lo
        let parts = Parallel.chunks(warn.count, minimum: 3_000) { a, b -> LanePicks in
            var part = LanePicks()
            for i in a..<b {
                let w = warn[i]
                let t = frozen.time(w.address, received: w.received, device: w.deviceTime)
                let lane = frozen.device(w.address, hostname: w.hostname, isTrap: w.isTrap)
                let sev: FindingSeverity = w.isTrap ? (w.severity <= .warning ? .warn : .info)
                    : (w.severity <= .error ? .bad : .warn)
                let s = Self.slot(t.timeIntervalSince(start), span: span)
                part.counts[lane, default: LaneCount()].add(sev, t)
                if let cur = part.picks[lane]?[s], cur.sev >= sev { continue }
                part.picks[lane, default: [:]][s] = LanePick(sev: sev, index: i, time: t)
            }
            return part
        }
        var picks: [String: [Int: LanePick]] = [:]
        for part in parts {
            for (lane, c) in part.counts { lanes[lane, default: Acc()].merge(c) }
            for (lane, bySlot) in part.picks {
                for (s, p) in bySlot {
                    if let cur = picks[lane]?[s], cur.sev > p.sev || (cur.sev == p.sev && cur.time <= p.time) { continue }
                    picks[lane, default: [:]][s] = p
                }
            }
        }
        for (lane, bySlot) in picks {
            for (s, p) in bySlot {
                let w = warn[p.index]
                let target: JumpTarget = w.isTrap
                    ? .log("host:\(w.address) vendor:trap")
                    : .log(ctx.hostTerm(address: w.address, name: lane) + " sev:<=warn")
                let label = (w.isTrap ? "Trap " : "\(w.severity.label) ") + FText.excerpt(w.text, max: 80)
                lanes[lane]?.best[s] = TimelineEvent(id: nextID, time: p.time, kind: w.isTrap ? .trap : .log,
                                                     severity: p.sev, label: label, target: target)
                nextID += 1
            }
        }
        for f in flows where f.health != .ok {
            let e = TimelineEvent(id: nextID, time: f.firstTime, end: f.firstTime.addingTimeInterval(f.duration), kind: .flow,
                                  severity: f.health == .bad ? .bad : .warn,
                                  label: "\(f.clientEndpoint) → \(f.serverEndpoint): \(f.reasons.first ?? "")",
                                  target: .flow(FlowRef(key: f.key, packetID: f.firstPacketID)))
            add(captureLane, e, slot(f.firstTime))
            nextID += 1
        }
        for f in findings where f.source != .engine {
            let lane = f.device ?? ((f.source == .packets || f.source == .flows) ? captureLane : (f.client ?? captureLane))
            let e = TimelineEvent(id: nextID, time: f.firstSeen, end: f.lastSeen, kind: .finding, severity: f.severity,
                                  label: f.title, target: .finding(f.id))
            nextID += 1
            var a = lanes[lane] ?? Acc()
            a.note(e)
            a.bars.append(e)
            lanes[lane] = a
        }
        let built = lanes.map { name, a in
            TimelineLane(id: name, events: (a.bars + a.best.values).sorted { $0.time < $1.time }, worst: a.worst,
                         total: a.total, problems: a.problems, first: a.first, last: a.last)
        }
        .sorted { a, b in
            if a.worst != b.worst { return a.worst > b.worst }
            if (a.id == captureLane) != (b.id == captureLane) { return b.id == captureLane }
            if a.problems != b.problems { return a.problems > b.problems }
            return a.id.localizedStandardCompare(b.id) == .orderedAscending
        }
        return Timeline(lanes: built, start: lo, end: hi)
    }
}
