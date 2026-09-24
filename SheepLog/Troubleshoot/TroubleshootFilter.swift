import Foundation

/// What the Troubleshoot list shows: the category chip, the text filter, "Problems only" and the
/// time range dragged on the timeline, together — the list is their intersection. The chips
/// count everything but the chip itself; the heading counts the range. Kept apart from the
/// view so the combinations are tested without one.
nonisolated struct TroubleshootFilter: Equatable, Sendable {
    var category: FindingCategory?
    var text = ""
    var problemsOnly = false
    var range: ClosedRange<Date>?

    var needle: String { text.trimmingCharacters(in: .whitespaces).lowercased() }

    func inRange(_ f: Finding) -> Bool {
        guard let r = range else { return true }
        return !(f.lastSeen < r.lowerBound || f.firstSeen > r.upperBound)
    }

    func matchesText(_ f: Finding) -> Bool {
        let n = needle
        guard !n.isEmpty else { return true }
        return f.title.lowercased().contains(n) || f.detail.lowercased().contains(n)
            || (f.device?.lowercased().contains(n) ?? false) || (f.client?.lowercased().contains(n) ?? false)
            || f.category.label.lowercased().contains(n)
    }

    /// Every filter but the category chip: what the chips count. (They counted the whole
    /// analysis: "Link 5" over a range that held one link finding, and a click showed one.)
    func unchipped(_ findings: [Finding]) -> [Finding] {
        findings.filter { (!problemsOnly || $0.severity >= .warn) && inRange($0) && matchesText($0) }
    }

    /// A timeline click on `f`: each filter that hides it is lifted, the others stay.
    mutating func reveal(_ f: Finding) {
        if category != nil, f.category != category { category = nil }
        if !needle.isEmpty, !matchesText(f) { text = "" }
        if problemsOnly, f.severity < .warn { problemsOnly = false }
        if !inRange(f) { range = nil }
    }

    /// The list.
    func rows(_ findings: [Finding]) -> [Finding] {
        unchipped(findings).filter { category == nil || $0.category == category }
    }

    /// "All" and a chip per category left by the other filters — and the chosen one even when
    /// they leave nothing of it: its chip vanished while it still filtered the list (a range or
    /// "Problems only" that hid its findings left an empty list and no chip selected to undo).
    struct Chip: Hashable, Identifiable, Sendable {
        let category: FindingCategory?
        let count: Int
        var id: String { category?.rawValue ?? "all" }
    }

    func chips(_ findings: [Finding]) -> [Chip] {
        let base = unchipped(findings)
        var counts: [FindingCategory: Int] = [:]
        for f in base { counts[f.category, default: 0] += 1 }
        var out = [Chip(category: nil, count: base.count)]
        for c in FindingCategory.allCases where counts[c] != nil || c == category {
            out.append(Chip(category: c, count: counts[c] ?? 0))
        }
        return out
    }

    /// The pane's heading: problems and warnings of the analysis — of the selected time range
    /// when there is one (the counts stayed the whole analysis's while the list showed one
    /// minute of it).
    static func heading(_ findings: [Finding], range: ClosedRange<Date>?, wide: Bool = false) -> String {
        let span = range.map { " between \(Self.time($0.lowerBound, wide: wide)) and \(Self.time($0.upperBound, wide: wide))" } ?? ""
        let shown = range.map { r in findings.filter { !($0.lastSeen < r.lowerBound || $0.firstSeen > r.upperBound) } } ?? findings
        let bad = shown.filter { $0.severity == .bad }.count
        let warn = shown.filter { $0.severity == .warn }.count
        guard bad + warn > 0 else {
            guard range != nil else { return "Nothing wrong that SheepLog can see." }
            let outside = findings.filter { $0.severity >= .warn }.count
            return "Nothing wrong\(span)" + (outside > 0 ? " (\(Format.count(outside)) problem\(outside == 1 ? "" : "s") and warning\(outside == 1 ? "" : "s") outside it)." : ".")
        }
        var parts: [String] = []
        if bad > 0 { parts.append("\(Format.count(bad)) problem\(bad == 1 ? "" : "s")") }
        if warn > 0 { parts.append("\(Format.count(warn)) warning\(warn == 1 ? "" : "s")") }
        let devices = Set(shown.filter { $0.severity >= .warn }.compactMap(\.device))
        let tail = devices.count == 1 ? " on \(devices.first!)" : (devices.count > 1 ? " across \(devices.count) devices" : "")
        return parts.joined(separator: ", ") + span + tail + "."
    }

    /// A time of the range: with the day when the data covers more than one (a 10:05 of two
    /// days was ambiguous in an exported report).
    static func time(_ d: Date, wide: Bool) -> String { wide ? Format.dayClock.string(from: d) : FText.clock(d) }

    /// What the list is filtered by, in words ("Link, problems and warnings only, 10:05:00–10:12:00,
    /// matching “core”"); nil when it shows everything.
    func scope(wide: Bool = false) -> String? {
        var parts: [String] = []
        if let category { parts.append(category.title) }
        if problemsOnly { parts.append("problems and warnings only") }
        if let range { parts.append("\(Self.time(range.lowerBound, wide: wide))–\(Self.time(range.upperBound, wide: wide))") }
        if !needle.isEmpty { parts.append("matching “\(text.trimmingCharacters(in: .whitespaces))”") }
        return parts.isEmpty ? nil : parts.joined(separator: ", ")
    }

    /// The Markdown report of what the list shows: its heading follows the range, and it says
    /// which filters and range it used, and how many of the findings that is.
    func report(_ findings: [Finding], summary: AnalysisSummary, timeline: Timeline, generated: Date) -> String {
        let wide = Self.wide(summary: summary, timeline: timeline)
        let shown = rows(findings)
        return ReportText.findings(shown, summary: summary, timeline: timeline,
                                   heading: Self.heading(findings, range: range, wide: wide),
                                   scope: scope(wide: wide), generated: generated, total: findings.count)
    }

    /// The data covers more than one calendar day.
    static func wide(summary: AnalysisSummary, timeline: Timeline) -> Bool {
        let a = summary.start ?? (timeline.isEmpty ? nil : timeline.start)
        let b = summary.end ?? (timeline.isEmpty ? nil : timeline.end)
        guard let a, let b else { return false }
        return !Calendar.gregorian.isDate(a, inSameDayAs: b)
    }
}
