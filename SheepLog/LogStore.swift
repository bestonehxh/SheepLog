import Combine
import Foundation
import Synchronization

/// The in-memory ring of received lines plus everything the panes read off it: the filtered
/// view, per-source counters, rates. **Main-actor only.** Servers hand it batches via `ingest`.
///
/// CONTRACT (implemented by the Syslog work package; signatures are fixed):
/// - `entries` is chronological, capped at `limit` (oldest dropped in chunks).
/// - `visible` is `entries` after the source/severity/query filter, chronological; the display
///   order (`newestFirst`) is applied by `visibleEntry(atRow:)` and friends.
/// - Filtering runs off the main actor for a full re-scan (query change) and incrementally
///   for each ingested batch; `generation` increments whenever `visible` is replaced.
///
/// Performance notes:
/// - `@Published` arrays are mutated with a swap (take the value out, mutate the now-unique
///   buffer, put it back) so an append never copies the whole ring.
/// - Every line carries an absolute sequence number (its position in the stream of lines ever
///   appended); `visibleSeq` holds those for `visible`, which makes eviction and merging a
///   background re-scan with the batches that arrived meanwhile a binary search.
@MainActor
final class LogStore: ObservableObject {
    @Published private(set) var entries: [LogEntry] = []
    /// The filtered lines, **always chronological** (oldest first) — appending a batch is then an
    /// amortised O(batch) append. The display order is applied by the reader: use
    /// `visibleEntry(atRow:)` / `visibleCount`, which honour `newestFirst`.
    @Published private(set) var visible: [LogEntry] = []
    @Published private(set) var generation: Int = 0

    /// The filter box text and its parse error, if any.
    @Published var queryText: String = "" {
        didSet { if queryText != oldValue { scheduleQueryParse() } }
    }
    /// A Log export is being written (the Export button says so on every appearance of the pane).
    @Published var isExporting = false
    @Published var regexMode: Bool = false {
        didSet { if regexMode != oldValue { applyQueryText() } }
    }
    @Published private(set) var queryError: String? {
        didSet { queryErrorIsNotice = queryError != nil && queryError == noticeText }
    }
    /// True when `queryError` is a notice about a filter that *is* applied (a regex that may
    /// be slow, or one stopped as too slow) rather than a parse error that kept the old one.
    @Published private(set) var queryErrorIsNotice = false
    private var noticeText: String?
    @Published private(set) var query: Query = .empty

    @Published var newestFirst: Bool = true {
        didSet { if newestFirst != oldValue { generation += 1 } }
    }
    /// While paused, batches are still counted and buffered on disk but not appended to `entries`.
    @Published var paused: Bool = false {
        didSet {
            if oldValue, !paused { resume() }
            if paused, resumeNote != nil { resumeNote = nil }
        }
    }
    /// Why the table was resumed by something other than the Resume button (a Troubleshoot
    /// evidence "Show" whose lines were held back by Pause); the footer says it.
    @Published private(set) var resumeNote: String?
    /// Sidebar source selection (address) — nil = all sources.
    @Published var selectedSource: String? {
        didSet { if selectedSource != oldValue { requestRescan() } }
    }
    /// Severities currently shown. All eight by default; the pane filters severity with `sev:` in
    /// the filter field (no control sets this mask today — API and tests).
    @Published var severityMask: Set<Severity> = Set(Severity.allCases) {
        didSet { if severityMask != oldValue { requestRescan() } }
    }

    @Published private(set) var sources: [SourceStats] = []
    @Published private(set) var totalReceived: Int = 0
    @Published private(set) var dropped: Int = 0
    /// The part of `dropped` that was lost rather than rolled out of the ring: batches the
    /// main thread could not take in (a flood), lines past the pause buffer. The rest of
    /// `dropped` are the oldest lines making room (still in the disk log, if it is on).
    @Published private(set) var lost: Int = 0
    /// Messages per second over the last few seconds.
    @Published private(set) var rate: Double = 0
    /// Indexed by `Severity.rawValue`, over `entries`.
    @Published private(set) var severityCounts: [Int] = Array(repeating: 0, count: 8)
    /// Lines held back while `paused` (appended on resume).
    @Published private(set) var pausedCount: Int = 0

    /// The most lines kept in `entries`. Lowering it trims at once (and gives the memory back);
    /// values below 1 act as 1.
    var limit: Int = 100_000 {
        didSet { if limit < oldValue { trimToLimit() } }
    }
    var diskLogger: DiskLogger? {
        didSet { diskSink.logger = diskLogger }
    }
    /// `diskLogger`, handed to the listener queues (they write received lines to disk
    /// themselves, before a batch can be dropped on its way here).
    let diskSink = DiskSink()

    /// Per-source vendor overrides, handed to the listener queue.
    let vendorOverrides = VendorOverrideMap()

    /// The most lines kept while paused; past this they count as dropped.
    static let pauseCapacity = 50_000

    // Visible bookkeeping
    private var visibleSeq: [Int] = []
    /// Absolute sequence number of `entries[0]`.
    private var evictedTotal = 0
    /// Rows appended to / evicted from `visible` since `generation` last changed — the table
    /// uses the deltas to keep its scroll position anchored.
    private(set) var visibleAppended = 0
    private(set) var visibleEvicted = 0

    private var activeFilter = LogFilter.all
    private var rescanGeneration = 0
    private var rescanPending = false
    private var rescanTask: Task<Void, Never>?
    /// One re-parse per source address (an override on B must not cancel A's).
    private var reparseTasks: [String: Task<Void, Never>] = [:]
    private var queryTask: Task<Void, Never>?

    private var sourceMap: [String: SourceStats] = [:]
    /// `sourceMap`'s keys in numeric-aware address order, kept sorted on insert so the 4 Hz
    /// publish does not re-sort every source with Foundation string compares.
    private var sourceOrder: [String] = []
    private var detected: [String: Vendor] = [:]
    private var sourcesPublishScheduled = false
    private var lastSourcesPublish = -Double.infinity      // sourcesClock() seconds
    /// What the 4 Hz Sources publish is timed on: the monotonic clock (a wall clock set back an
    /// hour after a publish froze Sources and the sidebar count for that hour). Tests put a
    /// clock of their own here and step it.
    var sourcesClock: () -> Double = { Monotonic.now() }

    private var pausedQueue: [LogEntry] = []
    private var pausedBytes = 0
    /// Lines received while paused, held back from the table (Troubleshoot reads them too: a
    /// paused Log pane is about what the user is reading, not about what the network did).
    var heldEntries: [LogEntry] { pausedQueue }
    /// The overrides the held lines were last re-parsed for (`heldEntriesForAnalysis`).
    private var heldReparsedFor: [String: Int] = [:]

    /// `heldEntries` as the vendor overrides of the moment read them: an override set while the
    /// Log was paused re-parsed the ring at once but the held lines only at Resume, so
    /// Troubleshoot analysed them as the old vendor (a FortiGate forced by its override read as
    /// "Other": its interface-down was no finding until Resume). The re-parsed lines replace the
    /// held ones (their source counters follow), so Resume finds them done.
    func heldEntriesForAnalysis() -> [LogEntry] {
        // Once per override change (the analysis runs every 2 s while paused; lines held after
        // the change were parsed with it).
        guard !pausedQueue.isEmpty, !overrideChangedAtID.isEmpty, heldReparsedFor != overrideChangedAtID else { return pausedQueue }
        heldReparsedFor = overrideChangedAtID
        let fresh = reparsedForOverrideChanges(pausedQueue, accounted: true)
        var bytes = 0
        for e in fresh { bytes += Self.cost(e) }
        pausedQueue = fresh
        pausedBytes = bytes
        return fresh
    }

    /// Some of `ids` are held back by Pause (not in the table).
    func holdsAny(ids: [Int]) -> Bool {
        guard paused, !pausedQueue.isEmpty, !ids.isEmpty else { return false }
        let want = Set(ids)
        return pausedQueue.contains { want.contains($0.id) }
    }

    /// Resumes the table and says why (the footer shows `note` until the next Pause or Clear).
    func resume(note: String) {
        guard paused else { return }
        paused = false
        resumeNote = note
    }

    /// How many of `ids` are still in memory (in the ring, or held back by Pause).
    func countPresent(ids: [Int]) -> Int {
        guard !ids.isEmpty else { return 0 }
        let want = Set(ids)
        var n = 0
        entries.withUnsafeBufferPointer { buf in
            for e in buf where want.contains(e.id) { n += 1 }
        }
        for e in pausedQueue where want.contains(e.id) { n += 1 }
        return n
    }
    /// `cost` summed over `entries`.
    private(set) var entryBytes = 0
    /// Addresses not given a Sources row because `maxSources` were already tracked (their
    /// lines are kept and filterable as usual). Spoofed UDP sources are free to send.
    private(set) var untrackedSources = 0
    private var untrackedSeen: Set<String> = []
    static var maxSources = 5_000

    private var rateCount = 0
    private var rateWindow: [Int] = []
    private var rateTimer: Timer?

    init() {}

    // MARK: - Ingest

    /// Append a batch (already parsed). Called by SyslogServer / TrapReceiver on the main actor.
    func ingest(_ batch: [LogEntry]) { ingest(batch, writtenToDisk: false) }

    /// `writtenToDisk`: the listener already handed these lines to `diskSink` (syslog).
    func ingest(_ batch: [LogEntry], writtenToDisk: Bool) {
        guard !batch.isEmpty else { return }
        totalReceived += batch.count
        if !writtenToDisk { diskLogger?.append(batch) }
        let batch = reparsedForOverrideChanges(batch, accounted: false)
        account(batch)
        rateCount += batch.count
        ensureRateTimer()
        if paused { hold(batch) } else { append(batch) }
    }

    /// Queues a batch while paused, up to `pauseCapacity` lines and half the `byteBudget`; the
    /// rest is lost.
    private func hold(_ batch: [LogEntry]) {
        let room = max(0, Self.pauseCapacity - pausedQueue.count)
        var bytes = pausedBytes
        var k = 0
        while k < min(room, batch.count) {
            let c = Self.cost(batch[k])
            if bytes + c > Self.byteBudget / 2 { break }
            bytes += c
            k += 1
        }
        pausedBytes = bytes
        if k >= batch.count {
            pausedQueue.append(contentsOf: batch)
        } else {
            pausedQueue.append(contentsOf: batch.prefix(k))
            dropped += batch.count - k
            lost += batch.count - k
        }
        pausedCount = pausedQueue.count
    }

    private func append(_ batch: [LogEntry]) {
        var counts = severityCounts
        for e in batch { counts[e.severity.rawValue] += 1 }
        let seqStart = evictedTotal + entries.count

        var ring = entries
        entries = []
        ring.append(contentsOf: batch)

        if !rescanPending {
            let filter = activeFilter
            if filter.passesAll {
                appendVisible(batch, seqs: Array(seqStart..<(seqStart + batch.count)))
            } else {
                var hits: [LogEntry] = []
                var seqs: [Int] = []
                for (k, e) in batch.enumerated() where filter.matches(e) {
                    hits.append(e)
                    seqs.append(seqStart + k)
                }
                if !hits.isEmpty { appendVisible(hits, seqs: seqs) }
                reportTrippedRegex(filter)
            }
        }

        // Evict by count (`limit`, 10 % at a time) and by memory (`byteBudget`: 100,000 lines
        // of 64 KB datagrams would otherwise hold ~20 GB).
        var bytes = entryBytes
        for e in batch { bytes += Self.cost(e) }
        let cap = max(1, limit)
        var n = ring.count > cap ? min(ring.count, ring.count - cap + cap / 10) : 0
        for i in 0..<n { bytes -= Self.cost(ring[i]) }
        if bytes > Self.byteBudget {
            let target = Self.byteBudget / 10 * 9
            while n < ring.count - 1, bytes > target {
                bytes -= Self.cost(ring[n])
                n += 1
            }
        }
        entryBytes = bytes
        if n > 0 {
            for i in 0..<n { counts[ring[i].severity.rawValue] -= 1 }
            ring.removeFirst(n)
            evictedTotal += n
            dropped += n
            entries = ring
            evictVisible()
        } else {
            entries = ring
        }
        severityCounts = counts
    }

    /// The most memory the kept lines may hold (approximate: their strings plus overhead).
    static var byteBudget = 512 * 1024 * 1024

    /// Approximate bytes one line holds.
    static func cost(_ e: LogEntry) -> Int {
        var n = 200 + e.raw.utf8.count + e.message.utf8.count + e.hostname.utf8.count + e.program.utf8.count
        for f in e.fields { n += 32 + f.key.utf8.count + f.value.utf8.count }
        return n
    }

    /// Lines received but discarded before they reached the store (a listener whose batches
    /// the main thread could not keep up with). Counted as received and dropped.
    func noteDropped(_ n: Int) {
        guard n > 0 else { return }
        totalReceived += n
        dropped += n
        lost += n
    }

    private func appendVisible(_ add: [LogEntry], seqs: [Int]) {
        var v = visible
        visible = []
        v.append(contentsOf: add)
        visible = v
        visibleSeq.append(contentsOf: seqs)
        visibleAppended += add.count
    }

    /// Drop the visible rows whose line left the ring.
    private func evictVisible() {
        let k = Self.lowerBound(visibleSeq, evictedTotal)
        guard k > 0 else { return }
        var v = visible
        visible = []
        v.removeFirst(k)
        visible = v
        visibleSeq.removeFirst(k)
        visibleEvicted += k
    }

    /// Drop the oldest lines down to `limit` now (the limit was lowered). Copies the survivors
    /// into fresh arrays so the old, larger buffers are actually freed.
    private func trimToLimit() {
        let cap = max(1, limit)
        let n = entries.count - cap
        guard n > 0 else { return }
        var counts = severityCounts
        let ring = entries
        for i in 0..<n {
            counts[ring[i].severity.rawValue] -= 1
            entryBytes -= Self.cost(ring[i])
        }
        entries = Array(ring[n...])
        evictedTotal += n
        dropped += n
        severityCounts = counts
        let k = Self.lowerBound(visibleSeq, evictedTotal)
        if k > 0 {
            visible = Array(visible[k...])
            visibleSeq = Array(visibleSeq[k...])
            visibleEvicted += k
        }
    }

    private func resume() {
        guard !pausedQueue.isEmpty else { pausedCount = 0; return }
        // Held lines were counted per source when they arrived; an override set meanwhile
        // re-parses them now (their severity moves in the source's counters too).
        let q = reparsedForOverrideChanges(pausedQueue, accounted: true)
        pausedQueue = []
        pausedBytes = 0
        pausedCount = 0
        append(q)
    }

    func clear() {
        rescanGeneration += 1
        rescanTask?.cancel()
        rescanPending = false
        // "Exported 1,204 lines to x.csv" stayed in the footer of the emptied table (an export
        // still writing sets it again when done: its file is what the note names).
        if exportNote != nil { exportNote = nil }
        if resumeNote != nil { resumeNote = nil }
        evictedTotal += entries.count
        entries = []
        entryBytes = 0
        pausedQueue = []
        pausedBytes = 0
        pausedCount = 0
        severityCounts = Array(repeating: 0, count: 8)
        replaceVisible([], seqs: [])
    }

    // MARK: - Display-order access (for the table)

    var visibleCount: Int { visible.count }

    /// The entry shown on `row`, honouring `newestFirst`. Traps on a row out of range: AppKit
    /// callers, which may hold a row count from before the last publish, use
    /// `visibleEntryIfPresent(atRow:)`.
    func visibleEntry(atRow row: Int) -> LogEntry {
        newestFirst ? visible[visible.count - 1 - row] : visible[row]
    }

    /// `visibleEntry(atRow:)`, or nil when `row` no longer exists (the table asked with a stale
    /// row count after a re-scan or eviction shrank `visible`).
    func visibleEntryIfPresent(atRow row: Int) -> LogEntry? {
        guard row >= 0, row < visible.count else { return nil }
        return visibleEntry(atRow: row)
    }

    /// True when the line with sequence number `seq` has left the ring.
    func isEvicted(seq: Int) -> Bool { seq < evictedTotal }

    /// The absolute sequence number of the line on `row` (stable across appends and evictions).
    func visibleSeq(atRow row: Int) -> Int? {
        let n = visibleSeq.count
        guard row >= 0, row < n else { return nil }
        return newestFirst ? visibleSeq[n - 1 - row] : visibleSeq[row]
    }

    /// The row currently showing the line with sequence number `seq`, if it is visible.
    func visibleRow(forSeq seq: Int) -> Int? {
        let i = Self.lowerBound(visibleSeq, seq)
        guard i < visibleSeq.count, visibleSeq[i] == seq else { return nil }
        return newestFirst ? visibleSeq.count - 1 - i : i
    }

    /// The row currently showing entry `id` (linear; use `visibleRow(forSeq:)` on hot paths).
    func visibleRow(forID id: Int) -> Int? {
        let v = visible
        guard let i = v.lastIndex(where: { $0.id == id }) else { return nil }
        return newestFirst ? v.count - 1 - i : i
    }

    func entry(id: Int) -> LogEntry? {
        // The inspector asks for its line on every publish (10 a second under traffic): the
        // last answer's place in the ring (a sequence number, stable across appends and
        // evictions) is checked first, not a walk of up to 2,000,000 lines each time.
        if let c = entryLookup, c.id == id {
            let i = c.seq - evictedTotal
            if i >= 0, i < entries.count, entries[i].id == id { return entries[i] }
        }
        let e = entries
        let found: Int? = e.withUnsafeBufferPointer { buf in
            var i = buf.count - 1
            while i >= 0 {
                if buf[i].id == id { return i }
                i -= 1
            }
            return nil
        }
        guard let found else { return nil }
        entryLookup = (id, evictedTotal + found)
        return e[found]
    }

    private var entryLookup: (id: Int, seq: Int)?

    /// Lines at error severity or worse received since `date` (scans back from the newest).
    func problemCount(since date: Date) -> Int {
        let e = entries
        return e.withUnsafeBufferPointer { buf in
            var n = 0
            var i = buf.count - 1
            while i >= 0, buf[i].received >= date {
                if buf[i].severity.rawValue <= Severity.error.rawValue { n += 1 }
                i -= 1
            }
            return n
        }
    }

    // MARK: - Query

    private func scheduleQueryParse() {
        queryTask?.cancel()
        queryTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(200))
            guard !Task.isCancelled else { return }
            self?.applyQueryText()
        }
    }

    /// Parse `queryText` now (the debounce calls this; tests may too). A parse error keeps the
    /// previous query.
    func applyQueryText() {
        queryTask?.cancel()
        do {
            let q = try Query.parse(queryText, regexWords: regexMode)
            // A pattern shaped like a catastrophic one runs (guarded) with a warning.
            let warning = q.leaves.lazy.compactMap { leaf -> String? in
                if case .regex(let p) = leaf { return RegexLint.warning(p) }
                return nil
            }.first
            noticeText = warning
            if queryError != warning { queryError = warning }
            if q != query {
                query = q
                requestRescan()
            }
        } catch {
            queryError = (error as? QueryError)?.message ?? error.localizedDescription
        }
    }

    /// Says so when the filter's regular expression was given up on (it then matches nothing
    /// more, so the list is incomplete).
    private func reportTrippedRegex(_ filter: LogFilter) {
        guard !filter.regexes.isEmpty, let r = filter.trippedRegex else { return }
        let text = "Regular expression /\(r.pattern)/ is too slow on these lines and was stopped — "
            + "the list is incomplete; simplify it (no nested quantifiers such as (a+)+ or .*.*)"
        noticeText = text
        if queryError != text { queryError = text }
    }

    /// "Show" on Sources / Status: every line of one source. An existing query would silently
    /// hide some or all of them, so it is cleared too.
    func showSource(_ address: String) {
        if !queryText.isEmpty { queryText = "" }
        queryTask?.cancel()
        if queryError != nil { queryError = nil }
        if !query.isEmpty { query = .empty }
        if selectedSource != address { selectedSource = address } else { requestRescan() }
    }

    /// Appends a term to the filter text (context-menu "Filter this host" …) and applies it.
    func appendToQuery(_ term: String) {
        // The rows on screen are the last filter that worked: a text that does not parse (an
        // open quote, a trailing OR still being typed) is replaced by that filter, narrowed by
        // the term — appended to the broken text, the click did nothing but change the error.
        let parses = (try? Query.parse(queryText, regexWords: regexMode)) != nil
        queryText = Self.appending(term, to: parses ? queryText : query.source)
        applyQueryText()
    }

    /// `text` AND `term`. AND binds tighter than OR, so a filter with a top-level OR / NOR is
    /// grouped first: "sev:err OR sev:warn" + "host:X" is "(sev:err OR sev:warn) host:X", not
    /// "sev:err OR (sev:warn host:X)".
    nonisolated static func appending(_ term: String, to text: String) -> String {
        let t = text.trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty else { return term }
        var depth = 0
        var topLevelOr = false
        for token in (try? QueryLexer.tokenize(t)) ?? [] {
            switch token {
            case .lparen: depth += 1
            case .rparen: depth -= 1
            case .or, .nor: if depth == 0 { topLevelOr = true }
            default: break
            }
        }
        return topLevelOr ? "(\(t)) \(term)" : "\(t) \(term)"
    }

    // MARK: - Full re-scan

    private func currentFilter() -> LogFilter {
        LogFilter(query: query, source: selectedSource, mask: severityMask)
    }

    /// Recompute `visible` from `entries` with the current filter. The scan runs detached; a
    /// newer request supersedes an older one (generation check), and lines that arrived while
    /// it ran are filtered on completion.
    @discardableResult
    func requestRescan() -> Task<Void, Never>? {
        rescanGeneration += 1
        rescanTask?.cancel()
        let filter = currentFilter()
        activeFilter = filter
        let gen = rescanGeneration
        if filter.passesAll {
            rescanPending = false
            rescanTask = nil
            replaceVisible(entries, seqs: Array(evictedTotal..<(evictedTotal + entries.count)))
            return nil
        }
        rescanPending = true
        let snap = entries
        let base = evictedTotal
        let task = Task.detached(priority: .userInitiated) { [weak self] in
            guard let result = LogStore.scan(snap, base: base, filter: filter) else { return }
            await self?.finishRescan(gen: gen, hits: result.hits, seqs: result.seqs,
                                     snapEnd: base + snap.count, filter: filter)
        }
        rescanTask = task
        return task
    }

    /// The filter over a snapshot. nil when cancelled.
    nonisolated static func scan(_ snap: [LogEntry], base: Int, filter: LogFilter)
        -> (hits: [LogEntry], seqs: [Int])? {
        var hits: [LogEntry] = []
        var seqs: [Int] = []
        let cancelled: Bool = snap.withUnsafeBufferPointer { buf in
            for i in 0..<buf.count {
                if i & 8191 == 0, Task.isCancelled { return true }
                if filter.matches(buf[i]) {
                    hits.append(buf[i])
                    seqs.append(base + i)
                }
            }
            return false
        }
        return cancelled ? nil : (hits, seqs)
    }

    private func finishRescan(gen: Int, hits: [LogEntry], seqs: [Int], snapEnd: Int, filter: LogFilter) {
        guard gen == rescanGeneration else { return }
        rescanPending = false
        var v = hits
        var s = seqs
        let k = Self.lowerBound(s, evictedTotal)
        if k > 0 { v.removeFirst(k); s.removeFirst(k) }
        let e = entries
        let tailStart = max(0, snapEnd - evictedTotal)
        if tailStart < e.count {
            for i in tailStart..<e.count where filter.matches(e[i]) {
                v.append(e[i])
                s.append(evictedTotal + i)
            }
        }
        replaceVisible(v, seqs: s)
        reportTrippedRegex(filter)
    }

    /// A new `visible` (not an append): the table reloads rather than follows deltas.
    private func replaceVisible(_ v: [LogEntry], seqs: [Int]) {
        visible = v
        visibleSeq = seqs
        visibleAppended = 0
        visibleEvicted = 0
        generation += 1
    }

    /// Waits for the in-flight re-scan / re-parse (tests).
    func settle() async {
        while let (address, t) = reparseTasks.first {
            await t.value
            if reparseTasks[address] == t { reparseTasks[address] = nil }
        }
        while let t = rescanTask {
            await t.value
            if rescanTask == t { break }
        }
    }

    // MARK: - Sources

    private func account(_ batch: [LogEntry]) {
        var lastAddress = ""
        var current: SourceStats?
        var override: Vendor?
        func flush() {
            if let c = current { sourceMap[c.address] = c }
        }
        for e in batch {
            if current == nil || e.sourceAddress != lastAddress {
                flush()
                lastAddress = e.sourceAddress
                override = vendorOverrides.get(lastAddress)
                if let known = sourceMap[lastAddress] {
                    current = known
                } else if sourceMap.count < Self.maxSources {
                    current = SourceStats(address: lastAddress, vendorOverride: override,
                                          firstSeen: e.received, lastSeen: e.received)
                    insertSourceOrder(lastAddress)
                } else {
                    // A flood of (spoofed) source addresses: no row each — the Sources list and
                    // its sorted insert would grow without bound.
                    current = nil
                    if untrackedSeen.count < 1_000_000, untrackedSeen.insert(lastAddress).inserted { untrackedSources += 1 }
                    continue
                }
            }
            current!.count += 1
            current!.bySeverity[e.severity.rawValue] += 1
            current!.lastSeen = e.received
            // A trap's "hostname" is its sender's address (or a v1 agent-addr, another device
            // when a proxy forwards it): it must not rename a source its syslog lines named
            // (CORE-SW1 flipping to "10.1.0.1" on every linkDown).
            if e.transport != .trap, !e.hostname.isEmpty, current!.hostname != e.hostname { current!.hostname = e.hostname }
            if let override {
                current!.vendor = override
            } else {
                let v = e.vendor
                if v != current!.vendor, v != .snmpTrap && v != .unknown || current!.vendor == .unknown {
                    current!.vendor = v
                }
                if v != .unknown, v != .snmpTrap, detected[lastAddress] != v { detected[lastAddress] = v }
            }
        }
        flush()
        scheduleSourcesPublish()
    }

    /// The vendor auto-detection last produced for `address` (ignores the override).
    func detectedVendor(for address: String) -> Vendor {
        detected[address] ?? .unknown
    }

    private func scheduleSourcesPublish() {
        let wait = Self.sourcesPublishDelay(sinceLast: sourcesClock() - lastSourcesPublish)
        if wait == 0 {
            publishSources()
            return
        }
        guard !sourcesPublishScheduled else { return }
        sourcesPublishScheduled = true
        Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(Int(wait * 1000) + 1))
            self?.publishSources()
        }
    }

    nonisolated static let sourcesPublishInterval = 0.25

    /// How long the next 4 Hz publish waits: 0 = now, never more than the interval. (Measured
    /// on the monotonic clock: with `Date()` a clock set back an hour after a publish made
    /// the wait an hour — Sources and the sidebar count froze.)
    nonisolated static func sourcesPublishDelay(sinceLast: Double) -> Double {
        sinceLast >= sourcesPublishInterval || sinceLast < 0 ? 0 : sourcesPublishInterval - sinceLast
    }

    /// Publish the sorted source list now (the ingest path throttles this to 4 Hz).
    func publishSources() {
        sourcesPublishScheduled = false
        lastSourcesPublish = sourcesClock()
        let list = sourceOrder.compactMap { sourceMap[$0] }
        if list != sources { sources = list }
    }

    private func insertSourceOrder(_ address: String) {
        var lo = 0, hi = sourceOrder.count
        while lo < hi {
            let mid = (lo + hi) >> 1
            if sourceOrder[mid].compare(address, options: .numeric) == .orderedAscending { lo = mid + 1 } else { hi = mid }
        }
        sourceOrder.insert(address, at: lo)
    }

    // MARK: - Rate

    private func ensureRateTimer() {
        guard rateTimer == nil else { return }
        let t = Timer(timeInterval: 1, repeats: true) { [weak self] timer in
            // A released store (tests, a replaced model) must not leave the timer running.
            guard self != nil else { timer.invalidate(); return }
            MainActor.assumeIsolated { self?.tickRate() }
        }
        RunLoop.main.add(t, forMode: .common)
        rateTimer = t
    }

    private func tickRate() {
        rateWindow.append(rateCount)
        rateCount = 0
        if rateWindow.count > 3 { rateWindow.removeFirst(rateWindow.count - 3) }
        let r = Double(rateWindow.reduce(0, +)) / Double(max(1, rateWindow.count))
        if r != rate { rate = r }
        if rateWindow.count == 3, rateWindow.allSatisfy({ $0 == 0 }) {
            rateTimer?.invalidate()
            rateTimer = nil
            rateWindow = []
            if rate != 0 { rate = 0 }
        }
    }

    // MARK: - Vendor override

    /// Load the persisted overrides (no re-parse; nothing has arrived yet).
    func seedVendorOverrides(_ map: [String: Vendor]) {
        for (address, vendor) in map where vendorOverrides.get(address) != vendor {
            vendorOverrides.set(vendor, for: address)
            if var s = sourceMap[address] { s.vendorOverride = vendor; s.vendor = vendor; sourceMap[address] = s }
        }
    }

    /// Force a vendor for every line from `address` (nil restores auto-detection). Re-parses
    /// the existing lines of that source.
    func setVendorOverride(_ vendor: Vendor?, for address: String) {
        vendorOverrides.set(vendor, for: address)
        overrideChangedAtID[address] = IDCounter.shared.current
        if var s = sourceMap[address] {
            s.vendorOverride = vendor
            s.vendor = vendor ?? detected[address] ?? s.vendor
            sourceMap[address] = s
            publishSources()
        }
        let snap = entries
        let base = evictedTotal
        reparseTasks[address]?.cancel()
        reparseTasks[address] = Task.detached(priority: .userInitiated) { [weak self] in
            var updates: [(seq: Int, entry: LogEntry)] = []
            for (i, e) in snap.enumerated() {
                if i & 4095 == 0, Task.isCancelled { return }
                guard e.sourceAddress == address, e.transport != .trap else { continue }
                let raw = RawSyslog(received: e.received, sourceAddress: e.sourceAddress,
                                    sourcePort: e.sourcePort, transport: e.transport, text: e.raw)
                updates.append((base + i, SyslogParser.parse(raw, id: e.id, vendorOverride: vendor)))
            }
            guard !Task.isCancelled else { return }
            await self?.applyReparse(updates, address: address, vendor: vendor)
        }
    }

    private func applyReparse(_ updates: [(seq: Int, entry: LogEntry)], address: String, vendor: Vendor?) {
        // A re-parse that was superseded (cancelled too late to stop) must not overwrite the
        // newer override's result.
        guard vendorOverrides.get(address) == vendor else { return }
        guard !updates.isEmpty else { return }
        var ring = entries
        entries = []
        var counts = severityCounts
        for u in updates {
            let i = u.seq - evictedTotal
            guard i >= 0, i < ring.count, ring[i].id == u.entry.id else { continue }
            replace(&ring[i], with: u.entry, counts: &counts)
        }
        entries = ring
        severityCounts = counts
        requestRescan()
    }

    /// One line of the ring replaced by a new version of itself: counters and bytes follow.
    private func replace(_ old: inout LogEntry, with new: LogEntry, counts: inout [Int]) {
        counts[old.severity.rawValue] -= 1
        counts[new.severity.rawValue] += 1
        entryBytes += Self.cost(new) - Self.cost(old)
        recountSource(old, as: new)
        old = new
    }

    /// A line already counted in its source's row changed severity (re-parsed): the row's
    /// Errors / Warnings follow.
    private func recountSource(_ old: LogEntry, as new: LogEntry) {
        guard old.severity != new.severity, var s = sourceMap[old.sourceAddress] else { return }
        s.bySeverity[old.severity.rawValue] -= 1
        s.bySeverity[new.severity.rawValue] += 1
        sourceMap[old.sourceAddress] = s
        scheduleSourcesPublish()
    }

    /// Per address: the last entry id handed out when its vendor override last changed. Ids are
    /// reserved before a listener takes its overrides snapshot (`SyslogListener.flush`), so a
    /// line with a higher id was parsed with the new override — whatever the wall clock did.
    private var overrideChangedAtID: [String: Int] = [:]

    /// A listener parses a batch with the overrides of that moment and hands it over up to a
    /// few hundred ms later (longer while paused): a line whose id was reserved before its
    /// source's override last changed may carry the old vendor. Those are parsed again with the
    /// override in force now; no other line is touched. `accounted`: the lines are already in
    /// their sources' counters (held lines).
    private func reparsedForOverrideChanges(_ batch: [LogEntry], accounted: Bool) -> [LogEntry] {
        guard !overrideChangedAtID.isEmpty else { return batch }
        var out = batch
        var lastAddress: String?
        var changedAt: Int?
        for i in out.indices where out[i].transport != .trap {
            let e = out[i]
            if e.sourceAddress != lastAddress {
                lastAddress = e.sourceAddress
                changedAt = overrideChangedAtID[e.sourceAddress]
            }
            guard let changedAt, e.id <= changedAt else { continue }
            let raw = RawSyslog(received: e.received, sourceAddress: e.sourceAddress, sourcePort: e.sourcePort,
                                transport: e.transport, text: e.raw)
            let fresh = SyslogParser.parse(raw, id: e.id, vendorOverride: vendorOverrides.get(e.sourceAddress))
            if accounted { recountSource(e, as: fresh) }
            out[i] = fresh
        }
        return out
    }

    /// Puts new versions of lines in place, matched by id (traps named again once the MIBs
    /// have loaded). Lines no longer in the ring (or held while paused) are skipped.
    func replaceEntries(_ updated: [LogEntry]) {
        guard !updated.isEmpty else { return }
        var byID = Dictionary(updated.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        var ring = entries
        entries = []
        var counts = severityCounts
        for i in ring.indices {
            guard let u = byID.removeValue(forKey: ring[i].id) else { continue }
            replace(&ring[i], with: u, counts: &counts)
            if byID.isEmpty { break }
        }
        entries = ring
        severityCounts = counts
        if !byID.isEmpty, !pausedQueue.isEmpty {
            for i in pausedQueue.indices {
                guard let u = byID.removeValue(forKey: pausedQueue[i].id) else { continue }
                pausedBytes += Self.cost(u) - Self.cost(pausedQueue[i])
                recountSource(pausedQueue[i], as: u)
                pausedQueue[i] = u
            }
        }
        requestRescan()
    }

    // MARK: - Export

    /// The visible lines in display order — a snapshot the export can format off the main actor.
    var exportRows: [LogEntry] { newestFirst ? visible.reversed() : visible }

    /// What the last export wrote ("Exported 1,204 lines to x.csv"), for the footer; nil
    /// after a failure (the error sheet says it) and while one runs.
    @Published private(set) var exportNote: String?

    /// Export… after the save panel: waits for a vendor re-parse or filter re-scan still under
    /// way (a vendor picked in Sources a moment before exported the old vendor, severity and
    /// fields — and, under a vendor: or f: filter, the old rows), then snapshots the lines
    /// shown and formats and writes them off the main actor. Returns the error text, or nil;
    /// `exportNote` says what was written. A Clear, a limit change or eviction during the write
    /// does not touch the snapshot.
    func export(to url: URL, csv: Bool) async -> String? {
        isExporting = true
        exportNote = nil
        await settle()
        let rows = exportRows
        // A paused table is what is exported; the lines Pause holds back are not in the file.
        let held = paused ? pausedCount : 0
        PendingWrites.begin()          // ⌘Q waits for the write
        let failure = await Task.detached(priority: .userInitiated) {
            defer { PendingWrites.end() }
            return Self.writeExport(rows, csv: csv, to: url)
        }.value
        isExporting = false
        if failure == nil {
            exportNote = "Exported \(Format.count(rows.count)) \(rows.count == 1 ? "line" : "lines") to \(url.lastPathComponent)"
                + (held > 0 ? " — the table as paused; \(Format.count(held)) newer \(held == 1 ? "line" : "lines") held back \(held == 1 ? "is" : "are") not in it" : "")
        }
        return failure
    }

    /// The Export save panel's message: what the file will hold (a paused table's newer lines
    /// are not in it — "the N lines shown" alone read as everything received).
    static func exportPanelMessage(shown: Int, held: Int) -> String {
        "Save the \(Format.count(shown)) \(shown == 1 ? "line" : "lines") shown"
            + (held > 0 ? " (the table is paused: the \(Format.count(held)) newer \(held == 1 ? "line" : "lines") held back \(held == 1 ? "is" : "are") not included)" : "")
            + ". Name it .csv for a spreadsheet, .log for raw lines."
    }

    /// Formats and writes (off the main actor); nil on success, else the error text.
    nonisolated static func writeExport(_ rows: [LogEntry], csv: Bool, to url: URL) -> String? {
        let text = csv ? exportCSV(rows) : exportText(rows)
        do {
            try text.write(to: url, atomically: true, encoding: .utf8)
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    /// The visible lines as text (raw lines, newline-separated) / CSV.
    func exportText() -> String { Self.exportText(exportRows) }

    func exportCSV() -> String { Self.exportCSV(exportRows) }

    nonisolated static func exportText(_ rows: [LogEntry]) -> String {
        guard !rows.isEmpty else { return "" }
        var out = ""
        out.reserveCapacity(rows.reduce(0) { $0 + $1.raw.utf8.count + 1 })
        for e in rows {
            // One entry per line: an embedded line break is written as rsyslog does (#012).
            out += DiskLogger.oneLine(e.raw)
            out += "\n"
        }
        return out
    }

    /// One pass into one pre-sized string (no per-row column arrays, no `joined`).
    nonisolated static func exportCSV(_ rows: [LogEntry]) -> String {
        var out = "received,host,vendor,severity,facility,program,message,raw\r\n"
        out.reserveCapacity(rows.reduce(64) { $0 + 2 * $1.raw.utf8.count + 96 })
        var stamp = StampWriter()
        for e in rows {
            stamp.append(e.received, to: &out)
            out += ","; Format.appendCSV(&out, e.displayHost)
            out += ","; out += e.vendor.label
            out += ","; out += e.severity.name
            out += ","; out += e.facility.name
            out += ","; Format.appendCSV(&out, e.program)
            out += ","; Format.appendCSV(&out, e.message)
            out += ","; Format.appendCSV(&out, e.raw)
            out += "\r\n"
        }
        return out
    }

    /// `Format.stamp` for many dates in a row: the date and time to the second formatted once
    /// per second, the milliseconds appended — a `DateFormatter` call per row was over half of
    /// a 100k-line CSV export. Same text: the formatter rounds to the nearest millisecond
    /// (`floor(ms since 1970 + 0.5)`, checked against it in `Round10InteractionTests`).
    nonisolated struct StampWriter {
        private static let seconds = Format.gregorian("yyyy-MM-dd HH:mm:ss")
        private var second = Double.nan
        private var prefix = ""

        mutating func append(_ date: Date, to out: inout String) {
            let u = ((date.timeIntervalSinceReferenceDate + 978_307_200) * 1000 + 0.5).rounded(.down)
            var ms = u.truncatingRemainder(dividingBy: 1000)
            if ms < 0 { ms += 1000 }
            let s = u - ms
            if s != second {
                second = s
                prefix = Self.seconds.string(from: Date(timeIntervalSince1970: s / 1000))
            }
            out += prefix
            let m = Int(ms)
            out += m < 10 ? ".00" : m < 100 ? ".0" : "."
            out += String(m)
        }

        func string(_ date: Date) -> String {
            var copy = self
            var out = ""
            copy.append(date, to: &out)
            return out
        }
    }

    // MARK: - Helpers

    static func lowerBound(_ a: [Int], _ x: Int) -> Int {
        var lo = 0, hi = a.count
        while lo < hi {
            let mid = (lo + hi) >> 1
            if a[mid] < x { lo = mid + 1 } else { hi = mid }
        }
        return lo
    }

    /// Next unique entry id (monotonic, process-wide).
    nonisolated static func nextID() -> Int { IDCounter.shared.next() }

    /// `count` consecutive ids in one lock; returns the first (a batch parsed in parallel).
    nonisolated static func reserveIDs(_ count: Int) -> Int { IDCounter.shared.reserve(count) }
}

/// Back-pressure between a receive thread and the main actor. Each batch handed to the main
/// queue holds a slot until the main actor has taken it in (`leave`); with every slot taken the
/// producer drops the batch instead (counted) — a main thread busy for a few seconds under a
/// 100k lines/s flood does not queue hundreds of MB of closures.
nonisolated final class BacklogGate: Sendable {
    let slots: Int
    private struct State { var inFlight = 0, droppedSinceTake = 0, droppedTotal = 0 }
    private let state = Mutex(State())

    init(slots: Int) { self.slots = max(1, slots) }

    /// Takes a slot for a batch of `count` items, or counts them as dropped.
    func tryEnter(count: Int) -> Bool {
        state.withLock { s in
            if s.inFlight < slots { s.inFlight += 1; return true }
            s.droppedSinceTake += count
            s.droppedTotal += count
            return false
        }
    }

    /// The consumer finished a batch. Returns what was dropped since the last call (so the
    /// consumer can count it where it counts drops).
    @discardableResult
    func leave() -> Int {
        state.withLock { s in
            s.inFlight = max(0, s.inFlight - 1)
            defer { s.droppedSinceTake = 0 }
            return s.droppedSinceTake
        }
    }

    var batchesInFlight: Int { state.withLock { $0.inFlight } }
    var droppedTotal: Int { state.withLock { $0.droppedTotal } }
}

/// The current disk logger, shared with the listener threads.
nonisolated final class DiskSink: Sendable {
    private let current = Mutex<DiskLogger?>(nil)

    var logger: DiskLogger? {
        get { current.withLock { $0 } }
        set { current.withLock { $0 = newValue } }
    }

    /// Enqueued under the lock: once the setter has returned, every batch handed to the old
    /// logger is on that logger's queue, ahead of its `retire`.
    func append(_ raws: [RawSyslog]) { current.withLock { $0?.append(raws: raws) } }
}

nonisolated final class IDCounter: Sendable {
    static let shared = IDCounter()
    private let value = Mutex(0)
    func next() -> Int { value.withLock { $0 += 1; return $0 } }
    /// The last id handed out.
    var current: Int { value.withLock { $0 } }
    /// `count` consecutive ids; returns the first.
    func reserve(_ count: Int) -> Int {
        value.withLock { v in
            let first = v + 1
            v += max(0, count)
            return first
        }
    }
}

/// Lock-protected address → vendor map: the listener queue takes a snapshot per batch, the
/// store reads it per source run.
nonisolated final class VendorOverrideMap: Sendable {
    private let map = Mutex<[String: Vendor]>([:])

    func get(_ address: String) -> Vendor? {
        map.withLock { $0.isEmpty ? nil : $0[address] }
    }

    func set(_ vendor: Vendor?, for address: String) {
        map.withLock { $0[address] = vendor }
    }

    func snapshot() -> [String: Vendor] { map.withLock { $0 } }
}

// MARK: - The log matcher

/// Source + severity mask + compiled query. Immutable and Sendable, so a background re-scan
/// can use it.
nonisolated struct LogFilter: Sendable {
    let matcher: LogMatcher?
    let source: String?
    let severityBits: UInt8
    /// The query's regular expressions (usually none).
    let regexes: [GuardedRegex]

    static let all = LogFilter(matcher: nil, source: nil, severityBits: 0xFF)

    init(matcher: LogMatcher?, source: String?, severityBits: UInt8) {
        self.matcher = matcher
        self.source = source
        self.severityBits = severityBits
        regexes = matcher?.regexes ?? []
    }

    /// A regular expression of this filter was given up on as too slow.
    var trippedRegex: GuardedRegex? { regexes.first { $0.tripped } }

    init(query: Query, source: String?, mask: Set<Severity>) {
        var bits: UInt8 = 0
        for s in mask { bits |= 1 << UInt8(s.rawValue) }
        self.init(matcher: query.root.map(LogMatcher.compile), source: source, severityBits: bits)
    }

    var passesAll: Bool { matcher == nil && source == nil && severityBits == 0xFF }

    func matches(_ e: LogEntry) -> Bool {
        if severityBits != 0xFF, severityBits & (1 << UInt8(e.severity.rawValue)) == 0 { return false }
        if let source, e.sourceAddress != source { return false }
        guard let matcher else { return true }
        return matcher.matches(e)
    }
}

/// A case-insensitive substring needle, lower-cased once.
nonisolated struct Needle: Sendable {
    let text: String
    let lower: [UInt8]
    let ascii: Bool
    /// All digits (`53`, `0000000013`): field values compare as whole numbers.
    let isNumber: Bool
    /// `text` without leading zeros ("0" for zero), when `isNumber`.
    let numberText: String
    /// A complete IPv4 / IPv6 address: a field value equals it exactly (`src:10.1.1.1` is not
    /// 10.1.1.10), as `host:` does.
    let address: AddressNeedle?
    /// `text` holds a `*`: a field value must match it as a shell glob.
    let glob: Glob?
    /// `text` is a subnet (`10.1.0.0/24`): a field value must be an address inside it.
    let cidr: CIDR?

    init(_ text: String) {
        self.text = text
        ascii = text.utf8.allSatisfy { $0 < 0x80 }
        lower = text.utf8.map { ($0 >= 0x41 && $0 <= 0x5A) ? $0 | 0x20 : $0 }
        isNumber = Self.isDigits(text)
        numberText = isNumber ? Self.stripZeros(text) : ""
        address = !isNumber && LogMatcher.isFullAddress(text) ? AddressNeedle(text) : nil
        glob = Glob(text)
        cidr = text.contains("/") ? CIDR(text) : nil
    }

    static func isDigits(_ s: String) -> Bool {
        !s.isEmpty && s.utf8.allSatisfy { $0 >= 0x30 && $0 <= 0x39 }
    }

    static func stripZeros(_ s: String) -> String {
        let t = s.drop { $0 == "0" }
        return t.isEmpty ? "0" : String(t)
    }

    func found(in hay: String) -> Bool {
        if lower.isEmpty { return true }
        guard ascii else { return hay.range(of: text, options: .caseInsensitive) != nil }
        if let r = hay.utf8.withContiguousStorageIfAvailable({ Self.search($0, lower) }) { return r }
        var h = hay
        return h.withUTF8 { Self.search($0, lower) }
    }

    /// Prefix, case-insensitive.
    func isPrefix(of hay: String) -> Bool {
        if lower.isEmpty { return true }
        guard ascii else { return hay.range(of: text, options: [.caseInsensitive, .anchored]) != nil }
        var h = hay
        return h.withUTF8 { buf in
            guard buf.count >= lower.count else { return false }
            for j in 0..<lower.count {
                var c = buf[j]
                if c >= 0x41, c <= 0x5A { c |= 0x20 }
                if c != lower[j] { return false }
            }
            return true
        }
    }

    static func search(_ h: UnsafeBufferPointer<UInt8>, _ needle: [UInt8]) -> Bool {
        let m = needle.count, len = h.count
        guard m <= len, let hp = h.baseAddress else { return false }
        return needle.withUnsafeBufferPointer { nb -> Bool in
            guard let np = nb.baseAddress else { return true }
            let first = np[0]
            let isLetter = first >= 0x61 && first <= 0x7A
            let firstUpper = isLetter ? first & ~0x20 : first
            var i = 0
            let last = len - m
            // The next occurrence of each case of the first byte, found with memchr and reused
            // until the scan passes it (re-running memchr for the case that is absent at every
            // hit made a long line quadratic). `Int.max` = no more occurrences.
            var nextLower = -1, nextUpper = isLetter ? -1 : Int.max
            func find(_ c: UInt8, from i: Int) -> Int {
                guard let p = memchr(hp + i, Int32(c), len - i) else { return Int.max }
                return hp.distance(to: p.assumingMemoryBound(to: UInt8.self))
            }
            while i <= last {
                if nextLower < i { nextLower = find(first, from: i) }
                if nextUpper < i { nextUpper = find(firstUpper, from: i) }
                let next = min(nextLower, nextUpper)
                if next > last { return false }
                var j = 1
                while j < m {
                    var c = hp[next + j]
                    if c >= 0x41, c <= 0x5A { c |= 0x20 }
                    if c != np[j] { break }
                    j += 1
                }
                if j == m { return true }
                i = next + 1
            }
            return false
        }
    }
}

/// A complete address from a filter. IPv6 has many spellings (`2001:DB8:0:0::1`, `2001:db8::1`
/// — what inet_ntop prints for a peer — `2001:0db8::0001`): those compare by value.
nonisolated struct AddressNeedle: Sendable {
    let text: String
    private let v6: [UInt8]?

    init(_ text: String) {
        self.text = text
        v6 = text.contains(":") ? CIDR.bytes(of: text) : nil
    }

    func matches(_ s: String) -> Bool {
        if s.caseInsensitiveCompare(text) == .orderedSame { return true }
        guard let v6, s.contains(":") else { return false }
        return CIDR.bytes(of: s) == v6
    }
}

/// A complete IPv4 / IPv6 address typed as a bare word (or phrase): found in a line's text only
/// as a whole address. As a plain substring `10.0.0.2` also found 10.0.0.20–29 and 110.0.0.2,
/// so every evidence filter that named a neighbor, a login source or a client showed the lines
/// of the addresses that start or end with its digits. `10.0.0.` (a prefix) stays a substring;
/// `raw:10.0.0.2` (logs) / `info:10.0.0.2` (packets) is the substring when one is wanted.
nonisolated struct AddressWord: Sendable {
    let text: String
    let v6: Bool
    /// The address's bytes (4 or 16).
    let bytes: [UInt8]
    /// Lower-cased spellings to look for: as typed and, for IPv6, inet_ntop's (what a device
    /// that prints addresses with inet_ntop writes: `2001:DB8:0:0::1` typed finds `2001:db8::1`).
    let forms: [[UInt8]]
    /// A link-local address's zone as typed (`fe80::1%en0` → "en0", lower-cased): the address
    /// written with another zone is another host; written without one it may be this one.
    let zone: [UInt8]?
    /// IPv6: the longest group without its leading zeros (`db8` of 2001:db8::2 is shorter than
    /// `2001`) — every spelling of the address holds it (`2001:0DB8:0:0:0:0:0:2`,
    /// `2001:db8:0::2`), so only lines that do are parsed for an address of that value.
    let anchor: [UInt8]?

    init?(_ s: String) {
        guard LogMatcher.isFullAddress(s), let b = CIDR.bytes(of: s) else { return nil }
        text = s
        bytes = b
        v6 = b.count == 16
        let (address, zone) = CIDR.splitZone(s)
        self.zone = zone.map { Array($0.lowercased().utf8) }
        var f = [Array(address.lowercased().utf8)]
        var anchor: [UInt8]?
        if v6 {
            var a = in6_addr()
            withUnsafeMutableBytes(of: &a) { raw in for i in 0..<16 { raw[i] = b[i] } }
            var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            if inet_ntop(AF_INET6, &a, &buf, socklen_t(buf.count)) != nil {
                let canon = Array(String(cString: buf).lowercased().utf8)
                if canon != f[0] { f.append(canon) }
            }
            for g in 0..<8 {
                let v = UInt16(b[2 * g]) << 8 | UInt16(b[2 * g + 1])
                guard v != 0 else { continue }
                let hex = Array(String(v, radix: 16).utf8)
                if hex.count > (anchor?.count ?? 0) { anchor = hex }
            }
        }
        forms = f
        self.anchor = anchor
    }

    /// `s` is this address (IPv6 compared by value).
    func equals(_ s: String) -> Bool {
        if s.caseInsensitiveCompare(text) == .orderedSame { return true }
        guard v6, s.contains(":") else { return false }
        return CIDR.bytes(of: s) == bytes
    }

    /// The address appears in `hay` as a whole address — IPv6 in any spelling (round 17: as
    /// typed or in inet_ntop's form only, so `2001:db8::2` missed a device's
    /// `2001:0db8:0000:0000:0000:0000:0000:0002` and `2001:DB8:0:0::2`).
    func found(in hay: String) -> Bool {
        var h = hay
        return h.withUTF8 { buf in
            if forms.contains(where: { f in Self.anyHit(f, in: buf) { Self.whole(buf, $0, $0 + f.count, v6: v6) && zoneMatches(buf, $0 + f.count) } }) {
                return true
            }
            guard let anchor else { return false }
            return Self.anyHit(anchor, in: buf) { at in byValue(buf, around: at, anchorLength: anchor.count) }
        }
    }

    /// The IPv6 token around a hit of the anchor, parsed: this address as a whole. The token is
    /// the run of hex digits, `:` and `.` around it; when it does not parse, the parts after a
    /// single `:` are tried (ASA "outside:2001:db8::2", where "de:" glued "outside" on), and a
    /// trailing `.` / `:` is dropped ("… from 2001:db8::2.").
    private func byValue(_ h: UnsafeBufferPointer<UInt8>, around at: Int, anchorLength: Int) -> Bool {
        @inline(__always) func tokenByte(_ c: UInt8) -> Bool { Self.isHex(c) || c == 0x3A || c == 0x2E }
        var s = at, e = at + anchorLength
        while s > 0, tokenByte(h[s - 1]) { s -= 1 }
        while e < h.count, tokenByte(h[e]) { e += 1 }
        guard e - s <= 128 else { return false }
        var end = e
        while end > s, h[end - 1] == 0x2E || (h[end - 1] == 0x3A && !(end - 2 >= s && h[end - 2] == 0x3A)) { end -= 1 }
        // Every spelling ends with the address's last group ("…:2", "…:0002", "…::" for 0):
        // a token that ends otherwise is another address — told without parsing it (most of a
        // busy log's addresses share the /32 the anchor is from). A dotted IPv4 tail is parsed.
        var j = end, last: UInt32 = 0, digits = 0
        while j > s, Self.isHex(h[j - 1]) {
            let c = h[j - 1] | 0x20
            if digits < 8 { last |= UInt32(c <= 0x39 ? c - 0x30 : c - 0x61 + 10) << (4 * digits) }
            digits += 1; j -= 1
        }
        if !(j > s && h[j - 1] == 0x2E), digits > 4 || last != UInt32(bytes[14]) << 8 | UInt32(bytes[15]) { return false }
        // The token as it stands, then from after each single ':' before the anchor.
        func tryAt(_ start: Int) -> Bool {
            end - start >= 2 && end - start <= 45 && parses(h, start, end) && Self.whole(h, start, end, v6: true) && zoneMatches(h, end)
        }
        if tryAt(s) { return true }
        var k = s
        while k < at {
            if h[k] == 0x3A, h[k + 1] != 0x3A, k == s || h[k - 1] != 0x3A, tryAt(k + 1) { return true }
            k += 1
        }
        return false
    }

    /// `h[start..<end]` is an IPv6 address equal to this one. Parsed by hand (inet_pton and a
    /// buffer per hit made a filter of one address over 100,000 lines full of addresses of
    /// its /32 seven times slower than a word); a dotted IPv4 tail goes to inet_pton.
    private func parses(_ h: UnsafeBufferPointer<UInt8>, _ start: Int, _ end: Int) -> Bool {
        var groups = SIMD8<UInt16>(), n = 0, gap = -1
        var i = start
        if i + 1 < end, h[i] == 0x3A, h[i + 1] == 0x3A { gap = 0; i += 2 }
        while i < end {
            var v: UInt16 = 0, digits = 0
            while i < end, Self.isHex(h[i]) {
                guard digits < 4 else { return false }
                let c = h[i] | 0x20
                v = v << 4 | UInt16(c <= 0x39 ? c - 0x30 : c - 0x61 + 10)
                digits += 1; i += 1
            }
            if i < end, h[i] == 0x2E { return parsesSlow(h, start, end) }
            guard digits > 0, n < 8 else { return false }
            groups[n] = v; n += 1
            if i == end { break }
            guard h[i] == 0x3A else { return false }
            i += 1
            if i < end, h[i] == 0x3A {
                guard gap < 0 else { return false }
                gap = n; i += 1
                if i == end { break }
            } else if i == end { return false }
        }
        var full = SIMD8<UInt16>()
        if gap >= 0 {
            guard n < 8 else { return false }
            for k in 0..<gap { full[k] = groups[k] }
            let tail = n - gap
            for k in 0..<tail { full[8 - tail + k] = groups[gap + k] }
        } else {
            guard n == 8 else { return false }
            full = groups
        }
        for k in 0..<8 where full[k] != UInt16(bytes[2 * k]) << 8 | UInt16(bytes[2 * k + 1]) { return false }
        return true
    }

    private func parsesSlow(_ h: UnsafeBufferPointer<UInt8>, _ start: Int, _ end: Int) -> Bool {
        withUnsafeTemporaryAllocation(of: CChar.self, capacity: 48) { buf -> Bool in
            for i in start..<end { buf[i - start] = CChar(bitPattern: h[i]) }
            buf[end - start] = 0
            var a = in6_addr()
            guard inet_pton(AF_INET6, buf.baseAddress!, &a) == 1 else { return false }
            return withUnsafeBytes(of: &a) { raw in (0..<16).allSatisfy { raw[$0] == bytes[$0] } }
        }
    }

    /// The address ending at `end` carries no zone, or the one asked for (`%en0` is not `%en1`
    /// nor `%en01`). Always true for an address typed without a zone.
    private func zoneMatches(_ h: UnsafeBufferPointer<UInt8>, _ end: Int) -> Bool {
        guard let zone, end < h.count, h[end] == 0x25 else { return true }
        let z = end + 1
        guard z + zone.count <= h.count else { return false }
        for k in 0..<zone.count {
            var c = h[z + k]
            if c >= 0x41, c <= 0x5A { c |= 0x20 }
            if c != zone[k] { return false }
        }
        return z + zone.count == h.count || !CIDR.isZoneByte(h[z + zone.count])
    }

    @inline(__always) static func isDigit(_ c: UInt8) -> Bool { c >= 0x30 && c <= 0x39 }
    @inline(__always) static func isHex(_ c: UInt8) -> Bool { let l = c | 0x20; return isDigit(c) || (l >= 0x61 && l <= 0x66) }
    @inline(__always) static func isAlnum(_ c: UInt8) -> Bool { let l = c | 0x20; return isDigit(c) || (l >= 0x61 && l <= 0x7A) }

    /// Each place `n` (lower-case ASCII) occurs in `h` case-insensitively, until `accept` takes
    /// one. The first byte is found with memchr (both cases), as `Needle.search` does: a 256-term
    /// filter of addresses over 100,000 lines compared every byte of every line 256 times.
    static func anyHit(_ n: [UInt8], in h: UnsafeBufferPointer<UInt8>, _ accept: (Int) -> Bool) -> Bool {
        let m = n.count, len = h.count
        guard m > 0, m <= len, let base = h.baseAddress else { return false }
        let first = n[0]
        let other: UInt8? = first >= 0x61 && first <= 0x7A ? first & ~0x20 : nil
        let last = len - m
        var i = 0
        while i <= last {
            var at = Int.max
            if let p = memchr(base + i, Int32(first), last - i + 1) { at = base.distance(to: p.assumingMemoryBound(to: UInt8.self)) }
            if let o = other, let p = memchr(base + i, Int32(o), min(at, last + 1) - i) {
                at = min(at, base.distance(to: p.assumingMemoryBound(to: UInt8.self)))
            }
            if at > last { return false }
            var j = 1
            while j < m {
                var c = h[at + j]
                if c >= 0x41, c <= 0x5A { c |= 0x20 }
                if c != n[j] { break }
                j += 1
            }
            if j == m, accept(at) { return true }
            i = at + 1
        }
        return false
    }

    /// `h[start..<end]` is not part of a longer address or number: IPv4 — no digit (or a
    /// digit and a dot) before, no digit (or a dot and a digit) after, so "10.0.0.2." ending
    /// a sentence and "inside:10.0.0.2/22" are found; IPv6 — no hex digit, letter or dot
    /// next to it and no further group after (`:` + hex), a `:` before only after a word
    /// (ASA "outside:2001:db8::1").
    static func whole(_ h: UnsafeBufferPointer<UInt8>, _ start: Int, _ end: Int, v6: Bool) -> Bool {
        if start > 0 {
            let b = h[start - 1]
            if v6 {
                if isAlnum(b) || b == 0x2E { return false }
                if b == 0x3A {
                    var k = start - 2, word = false, nonHex = false
                    while k >= 0, isAlnum(h[k]) || h[k] == 0x5F || h[k] == 0x2D {
                        word = true
                        if !isHex(h[k]) { nonHex = true }
                        k -= 1
                    }
                    if !(word && nonHex) { return false }
                }
            } else {
                if isDigit(b) { return false }
                if b == 0x2E, start >= 2, isDigit(h[start - 2]) { return false }
            }
        }
        if end < h.count {
            let a = h[end]
            let next: UInt8? = end + 1 < h.count ? h[end + 1] : nil
            if v6 {
                if isAlnum(a) { return false }
                if a == 0x3A, let n = next, isHex(n) || n == 0x3A { return false }
                if a == 0x2E, let n = next, isDigit(n) { return false }
            } else {
                if isDigit(a) { return false }
                if a == 0x2E, let n = next, isDigit(n) { return false }
            }
        }
        return true
    }
}

/// `word:<text>` (logs): the text as a whole word of the line — no letter or digit right
/// before or after it, and not followed by `.`, `/` or `:` and a digit (a sub-interface or a
/// deeper port). Interface names in evidence filters: as a plain word `Gi1/0/1` also showed
/// Gi1/0/10–19 and `ether1` ether10.
nonisolated struct WholeWord: Sendable {
    let text: String
    let lower: [UInt8]

    init(_ text: String) {
        self.text = text
        lower = Array(text.lowercased().utf8)
    }

    func found(in hay: String) -> Bool {
        guard !lower.isEmpty else { return true }
        var h = hay
        return h.withUTF8 { buf in
            let m = lower.count, len = buf.count
            guard m <= len else { return false }
            let firstAlnum = AddressWord.isAlnum(lower[0]), lastAlnum = AddressWord.isAlnum(lower[m - 1])
            return AddressWord.anyHit(lower, in: buf) { i in
                let before: UInt8 = i > 0 ? buf[i - 1] : 0x20
                let end = i + m
                let after: UInt8 = end < len ? buf[end] : 0x20
                let next: UInt8 = end + 1 < len ? buf[end + 1] : 0x20
                let okBefore = !firstAlnum || !AddressWord.isAlnum(before)
                let okAfter = !lastAlnum || (!AddressWord.isAlnum(after)
                    && !((after == 0x2E || after == 0x2F || after == 0x3A) && AddressWord.isDigit(next)))
                return okBefore && okAfter
            }
        }
    }
}

/// An IPv4 or IPv6 subnet (`10.1.0.0/24`, `2001:db8::/32`), as ACLs and firewall rules write
/// them: `host:` and address fields match the addresses inside it.
nonisolated struct CIDR: Sendable {
    /// 4 or 16 bytes, host bits cleared.
    let network: [UInt8]
    let prefix: Int

    init?(_ text: String) {
        guard let slash = text.firstIndex(of: "/"), let bits = Int(text[text.index(after: slash)...]),
              let bytes = Self.bytes(of: String(text[..<slash])), (0...(bytes.count * 8)).contains(bits) else { return nil }
        prefix = bits
        network = Self.masked(bytes, bits)
    }

    /// An IPv6 address and its zone (`fe80::1%en0` → "fe80::1", "en0"; what `ndp -a`,
    /// `ifconfig` and Wireshark print for a link-local neighbor); nil zone when there is none.
    static func splitZone(_ s: String) -> (address: String, zone: String?) {
        guard s.contains(":"), let pct = s.firstIndex(of: "%") else { return (s, nil) }
        let zone = s[s.index(after: pct)...]
        guard !zone.isEmpty, zone.utf8.allSatisfy(isZoneByte) else { return (s, nil) }
        return (String(s[..<pct]), String(zone))
    }

    /// A byte of an interface name as a zone writes it (`en0`, `Gi0/0/1`, `eth1.100`, `vlan-10`).
    @inline(__always) static func isZoneByte(_ c: UInt8) -> Bool {
        AddressWord.isAlnum(c) || c == 0x2E || c == 0x5F || c == 0x2D || c == 0x2F
    }

    /// The address's bytes (IPv4: 4, IPv6: 16), or nil when `s` is not an address. An IPv6
    /// zone (`%en0`) is not part of the address.
    static func bytes(of s: String) -> [UInt8]? {
        var v4 = in_addr(), v6 = in6_addr()
        if s.contains(":") {
            guard inet_pton(AF_INET6, splitZone(s).address, &v6) == 1 else { return nil }
            return withUnsafeBytes(of: &v6) { Array($0) }
        }
        guard s.split(separator: ".", omittingEmptySubsequences: false).count == 4, inet_pton(AF_INET, s, &v4) == 1 else { return nil }
        return withUnsafeBytes(of: &v4) { Array($0) }
    }

    private static func masked(_ b: [UInt8], _ bits: Int) -> [UInt8] {
        var out = b
        for i in out.indices {
            let keep = max(0, min(8, bits - i * 8))
            out[i] &= keep == 0 ? 0 : UInt8(truncatingIfNeeded: 0xFF << (8 - keep))
        }
        return out
    }

    func contains(_ address: String) -> Bool {
        guard let b = Self.bytes(of: address), b.count == network.count else { return false }
        return Self.masked(b, prefix) == network
    }
}

/// A `*` pattern, matched like a shell glob against the whole value, case-insensitively:
/// `core-*` = starts with "core-", `*-sw1` = ends with "-sw1", `10.*.0.1`, `*` = anything.
nonisolated struct Glob: Sendable {
    /// The text between the stars (first = prefix, last = suffix).
    let parts: [String]

    /// nil when `pattern` has no `*`.
    init?(_ pattern: String) {
        guard pattern.contains("*") else { return nil }
        parts = pattern.split(separator: "*", omittingEmptySubsequences: false).map(String.init)
    }

    func matches(_ s: String) -> Bool {
        var lo = s.startIndex
        let last = parts.count - 1
        for (i, p) in parts.enumerated() where !p.isEmpty {
            let options: String.CompareOptions = i == 0 ? [.caseInsensitive, .anchored]
                : i == last ? [.caseInsensitive, .anchored, .backwards] : .caseInsensitive
            guard lo <= s.endIndex, let r = s.range(of: p, options: options, range: lo..<s.endIndex) else { return false }
            lo = r.upperBound
        }
        return true
    }
}

/// A field name compared case-insensitively against `LogField.key` — ASCII bytes lower-cased
/// once, with an O(1) length check first (`String.count` and `caseInsensitiveCompare` per
/// field per line were the cost of every `f:`/`src:`/`dst:` scan).
nonisolated struct KeyName: Sendable {
    let text: String
    let lower: [UInt8]
    let ascii: Bool

    init(_ text: String) {
        self.text = text
        ascii = text.utf8.allSatisfy { $0 < 0x80 }
        lower = text.utf8.map { ($0 >= 0x41 && $0 <= 0x5A) ? $0 | 0x20 : $0 }
    }

    /// Equal, case-insensitively — or equal up to a numeric instance suffix, so `f:ifIndex=3`
    /// finds a trap var-bind named `ifIndex.3` (`Common` does not match `Common.Username`).
    func matches(_ key: String) -> Bool {
        guard ascii else { return key.caseInsensitiveCompare(text) == .orderedSame }
        let kc = key.utf8.count
        guard kc == lower.count || kc > lower.count + 1 else { return false }
        var k = key
        return k.withUTF8 { buf in
            for j in 0..<lower.count {
                var c = buf[j]
                if c >= 0x41, c <= 0x5A { c |= 0x20 }
                if c != lower[j] { return false }
            }
            guard kc > lower.count else { return true }
            guard buf[lower.count] == 0x2E else { return false }
            for j in (lower.count + 1)..<kc where !(buf[j] == 0x2E || (buf[j] >= 0x30 && buf[j] <= 0x39)) { return false }
            return true
        }
    }
}

/// The query tree compiled against `LogEntry` (keys resolved, needles lower-cased once). The
/// boolean structure mirrors `Query.matches` exactly.
nonisolated indirect enum LogMatcher: Sendable {
    case and(LogMatcher, LogMatcher)
    case or(LogMatcher, LogMatcher)
    case all([LogMatcher])
    case any([LogMatcher])
    case not(LogMatcher)
    case never
    case raw(QueryOp, Needle)
    /// A bare word or phrase: the raw line — and, for a trap (whose raw text is dotted OIDs),
    /// the message with the resolved names too.
    case word(Needle)
    /// A bare complete IPv4 / IPv6 address: that address as a whole in the raw line (trap
    /// message too) — not 10.0.0.20 for `10.0.0.2`.
    case address(AddressWord)
    /// `word:x`: x as a whole word of the raw line (trap message too).
    case wholeWord(WholeWord)
    case message(QueryOp, Needle)
    case regex(GuardedRegex)
    case host(QueryOp, Needle)
    /// `host:` with a `*`: a shell glob against the address or the hostname (`host:core-*`,
    /// `host:*-sw1`, `host:*` = every line).
    case hostGlob(QueryOp, Glob)
    /// `host:` with a subnet: the source address (or a hostname that is an address) inside it.
    case hostCIDR(QueryOp, CIDR)
    /// `host:` with a complete IPv4/IPv6 address: that address exactly (`host:10.1.0.1` must
    /// not also show 10.1.0.10–19; `host:10.1.0.` is the prefix form).
    case hostExact(QueryOp, AddressNeedle)
    case severity(QueryOp, Int)
    case facility(QueryOp, Int)
    case vendor(QueryOp, Set<Vendor>)
    case program(QueryOp, Needle)
    /// `app:sshd$`: that program and no longer one (`app:sshd` also found sshd-session).
    case programIs(QueryOp, String)
    case pid(QueryOp, String)
    case port(QueryOp, Int)
    case transport(QueryOp, String)
    /// A vendor field: `op` is the operator on the value; `keys` are alternatives (src: → srcip/src/source).
    case field(keys: [KeyName], op: QueryOp, value: Needle, negate: Bool)
    case fieldExists(keys: [KeyName], negate: Bool)
    /// `key:value` for a key that is not one of the log keys (or a log key whose value does
    /// not parse, like `sev:high`): the line's field of that name when it has one, else
    /// `fallback` (the literal text `key:value`, or the log key's own meaning).
    case keyOr(key: KeyName, op: QueryOp, value: Needle, fallback: LogMatcher)

    /// Every regular expression in the tree (to tell whether one was given up on).
    var regexes: [GuardedRegex] {
        switch self {
        case .and(let a, let b), .or(let a, let b): return a.regexes + b.regexes
        case .all(let xs), .any(let xs): return xs.flatMap(\.regexes)
        case .not(let a): return a.regexes
        case .keyOr(_, _, _, let fallback): return fallback.regexes
        case .regex(let r): return [r]
        default: return []
        }
    }

    /// AND / OR chains become flat lists, gathered iteratively: the parser's chains are as
    /// deep as they are long, and a re-scan evaluates on a 512 KB task stack.
    private static func flatten(_ node: QueryNode, and: Bool) -> [LogMatcher] {
        var stack = [node], out: [LogMatcher] = []
        while let q = stack.popLast() {
            switch q {
            case .and(let a, let b) where and, .or(let a, let b) where !and:
                stack.append(b)
                stack.append(a)
            default:
                out.append(compile(q))
            }
        }
        return out
    }

    static func compile(_ node: QueryNode) -> LogMatcher {
        switch node {
        case .and:
            let xs = flatten(node, and: true)
            return xs.count == 1 ? xs[0] : .all(xs)
        case .or:
            let xs = flatten(node, and: false)
            return xs.count == 1 ? xs[0] : .any(xs)
        case .not(let a): return .not(compile(a))
        case .text(let t): return compileWord(t)
        case .regex(let r): return .regex(GuardedRegex(r))
        case .field(let key, let op, let value): return compileField(key, op, value)
        }
    }

    /// Bare words that name a vendor (`palo THREAT`, `huawei IFNET/4`, `cx "LOG_CRIT"`): they
    /// also match every line of that vendor, since the raw text of a PAN-OS CSV row or a
    /// Huawei line never says "palo" / "huawei". Short or generic aliases (ap, hp, cp, check,
    /// snmp, other) stay plain words.
    static let vendorWords: [String: Set<Vendor>] = {
        var map: [String: Set<Vendor>] = [:]
        let skip: Set<String> = ["ap", "hp", "cp", "check", "controller", "snmp", "pan", "other", "unknown", "generic"]
        for v in Vendor.allCases {
            for a in v.filterAliases where !skip.contains(a) { map[a, default: []].insert(v) }
            map[v.shortLabel.lowercased(), default: []].insert(v)
        }
        map["—"] = nil
        map["pan-os"] = [.paloAlto]
        return map
    }()

    /// A bare word: raw text (trap message too) — or, when it names a vendor, that vendor's
    /// lines. A bare `key=value` (`action=deny`, `srcip=10.1.1.1`) is that field on a line that
    /// has it (FortiOS writes `action="deny"` with quotes the raw text search misses, and the raw
    /// text of a 10.1.1.10 line contains "srcip=10.1.1.1"), else the raw text search.
    private static func compileWord(_ t: String) -> LogMatcher {
        if let a = AddressWord(t) { return .address(a) }
        var m = LogMatcher.word(Needle(t))
        if let vendors = vendorWords[t.lowercased()] { m = .or(m, .vendor(.eq, vendors)) }
        if let eq = t.firstIndex(of: "="), eq != t.startIndex {
            let key = String(t[..<eq]), value = String(t[t.index(after: eq)...])
            if !value.isEmpty, key.first!.isLetter,
               key.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" || $0 == "." || $0 == "-" }) {
                m = .keyOr(key: KeyName(key), op: .eq, value: Needle(value), fallback: m)
            }
        }
        return m
    }

    /// A complete IPv4 or IPv6 address (not a prefix such as `10.1.0.` or `fe80::`… with a
    /// trailing separator).
    static func isFullAddress(_ s: String) -> Bool {
        guard let last = s.last, last != ".", last != ":" else { return false }
        var v4 = in_addr(), v6 = in6_addr()
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        if parts.count == 4, inet_pton(AF_INET, s, &v4) == 1 { return true }
        // `fe80::1%en0`: a link-local address with its zone, as ndp / ifconfig / Wireshark
        // print it (it was plain text: `host:` and `ip:` with it found nothing).
        let (address, zone) = CIDR.splitZone(s)
        guard let end = address.last, end != ":", zone != nil || !s.contains("%") else { return false }
        return s.contains(":") && inet_pton(AF_INET6, address, &v6) == 1
    }

    private static func keys(_ names: [String]) -> [KeyName] { names.map(KeyName.init) }

    /// `key=value` inside an `f:` term: the **first** operator in the text splits it (so
    /// `f:note=a>=b` is note = "a>=b"), the two-character spelling winning at that position.
    static func splitFieldTerm(_ value: String) -> (key: String, op: QueryOp, value: String)? {
        let u = Array(value.utf8)
        var i = 1                                       // a key needs at least one character
        while i < u.count {
            let c = u[i], nx: UInt8 = i + 1 < u.count ? u[i + 1] : 0
            var op: QueryOp?
            var width = 1
            switch c {
            case 0x21 where nx == 0x3D: op = .ne; width = 2                    // !=
            case 0x3E: if nx == 0x3D { op = .ge; width = 2 } else { op = .gt }  // >= >
            case 0x3C: if nx == 0x3D { op = .le; width = 2 } else { op = .lt }  // <= <
            case 0x3D: op = .eq                                                 // =
            default: break
            }
            if let op {
                return (String(decoding: u[..<i], as: UTF8.self), op,
                        String(decoding: u[(i + width)...], as: UTF8.self))
            }
            i += 1
        }
        return nil
    }

    private static func compileField(_ key: String, _ op: QueryOp, _ value: String) -> LogMatcher {
        /// The line's own field `key` when it has one (`severity:high` on a PAN-OS THREAT row,
        /// `service:22`, `proto:tcp`), else `fallback`.
        func fieldOr(_ fallback: LogMatcher) -> LogMatcher {
            .keyOr(key: KeyName(key), op: op, value: Needle(value), fallback: fallback)
        }
        /// An unknown key is plain text: `foo:bar` searches the raw line for "foo:bar" (so
        /// `in:ether1`, `https://…` and `fe80::1` work as typed) unless the line has a field
        /// named `foo`.
        func literal() -> LogMatcher { .raw(op == .ne ? .ne : .eq, Needle("\(key):\(value)")) }
        switch key {
        case "host", "hostname", "ip":
            if isFullAddress(value) { return .hostExact(op, AddressNeedle(value)) }
            // `host:SW1$`: that name (or address) and no longer one — `host:SW1` is a prefix
            // and also SW10–19 (a relay's findings named each switch that way).
            if value.count > 1, value.hasSuffix("$"), op == .eq || op == .ne {
                return .hostExact(op, AddressNeedle(String(value.dropLast())))
            }
            if let c = CIDR(value), op == .eq || op == .ne { return .hostCIDR(op, c) }
            if let g = Glob(value), op == .eq || op == .ne { return .hostGlob(op, g) }
            return .host(op, Needle(value))
        case "sev", "severity", "level":
            // `severity:` / `level:` equal to a name is also the line's own field of that name:
            // PAN-OS THREAT "critical" is syslog error (critical/high → error), so
            // `severity:critical` compared on the syslog number alone missed exactly the rows
            // asked for (`severity:high` already went to the field). `sev:` is the syslog
            // severity only.
            func one(_ word: String, _ s: Severity) -> LogMatcher {
                let syslog = LogMatcher.severity(.eq, s.rawValue)
                guard key != "sev" else { return syslog }
                return .or(syslog, .field(keys: [KeyName(key)], op: .eq, value: Needle(word), negate: false))
            }
            // `sev:warn,err` = any of the listed severities (`!=` = none of them).
            if value.contains(","), op == .eq || op == .ne {
                let parts = value.split(separator: ",").compactMap { w in Severity.parse(String(w)).map { (String(w), $0) } }
                guard !parts.isEmpty else { return fieldOr(literal()) }
                let any = LogMatcher.any(parts.map { one($0.0, $0.1) })
                return op == .eq ? any : .not(any)
            }
            guard let s = Severity.parse(value) else { return fieldOr(op == .eq || op == .ne ? literal() : .never) }
            if op == .eq { return one(value, s) }
            if op == .ne { return .not(one(value, s)) }
            return .severity(op, s.rawValue)
        case "facility", "fac":
            guard let f = Facility.parse(value) else { return fieldOr(op == .eq || op == .ne ? literal() : .never) }
            return .facility(op, f.rawValue)
        case "vendor":
            // An exact alias wins over prefixes ("cp" = Check Point, not also ClearPass "cppm").
            let v = value.lowercased()
            let exact = Vendor.allCases.filter { $0.filterAliases.contains(v) || $0.shortLabel.lowercased() == v }
            let set = Set(exact.isEmpty ? Vendor.parse(value) : exact)
            guard !set.isEmpty else { return fieldOr(op == .eq || op == .ne ? literal() : .never) }
            return .vendor(op, set)
        case "app", "program", "prog", "tag":
            if value.count > 1, value.hasSuffix("$"), op == .eq || op == .ne { return .programIs(op, String(value.dropLast())) }
            return .program(op, Needle(value))
        case "msg", "message": return .message(op, Needle(value))
        case "raw": return .raw(op, Needle(value))
        case "word":
            guard op == .eq || op == .ne else { return fieldOr(.never) }
            // A complete address is that address as a whole, as a bare one is: `word:10.0.0.1`
            // missed "10.0.0.1:514" (a word may not go on with ":" and a digit — a channelized
            // port) and an IPv6 address written another way.
            if let a = AddressWord(value) { return fieldOr(op == .eq ? .address(a) : .not(.address(a))) }
            let w = LogMatcher.wholeWord(WholeWord(value))
            return fieldOr(op == .eq ? w : .not(w))
        case "pid": return .pid(op, value)
        case "port":
            // The syslog datagram's source port. `sport:` / `dport:` are the line's own fields
            // (a firewall's), like any other key — `sport:514` used to fall back to the syslog
            // source port and match nearly every line without a `sport` field.
            guard let p = Int(value) else { return fieldOr(op == .eq || op == .ne ? literal() : .never) }
            return .port(op, p)
        case "transport":
            return .transport(op, value.lowercased())
        case "proto":
            // A firewall line's protocol field (PAN-OS "tcp", FortiOS / Check Point "6"), like
            // any other key — not the syslog transport (that is `transport:`; otherwise
            // `proto:udp` would match every line received over UDP).
            return fieldOr(op == .eq || op == .ne ? literal() : .never)
        case "src": return .field(keys: keys(["srcip", "src", "source", "src_ip"]), op: op, value: Needle(value), negate: false)
        case "dst": return .field(keys: keys(["dstip", "dst", "destination", "dst_ip"]), op: op, value: Needle(value), negate: false)
        case "f", "field":
            // f:key=value, f:key>=100, f:key (exists)
            if let t = splitFieldTerm(value) {
                return .field(keys: [KeyName(t.key)], op: t.op, value: Needle(t.value), negate: op == .ne)
            }
            return .fieldExists(keys: [KeyName(value)], negate: op == .ne)
        default:
            // An IPv6 address that starts with a letter (`fe80::1`, `fd00::2`) reads as a key:
            // it is the address, as a whole, like any other bare address.
            if op == .eq || op == .ne, let a = AddressWord("\(key):\(value)") {
                return op == .eq ? .address(a) : .not(.address(a))
            }
            return fieldOr(op == .eq || op == .ne ? literal() : .never)
        }
    }

    func matches(_ e: LogEntry) -> Bool {
        switch self {
        case .and(let a, let b): return a.matches(e) && b.matches(e)
        case .or(let a, let b): return a.matches(e) || b.matches(e)
        case .all(let xs):
            for x in xs where !x.matches(e) { return false }
            return true
        case .any(let xs):
            for x in xs where x.matches(e) { return true }
            return false
        case .not(let a): return !a.matches(e)
        case .never: return false
        case .raw(let op, let n): return Self.text(e.raw, op, n)
        case .word(let n):
            return n.found(in: e.raw) || (e.transport == .trap && n.found(in: e.message))
        case .address(let a):
            return a.found(in: e.raw) || (e.transport == .trap && a.found(in: e.message))
        case .wholeWord(let w):
            return w.found(in: e.raw) || (e.transport == .trap && w.found(in: e.message))
        case .message(let op, let n): return Self.text(e.message, op, n)
        case .regex(let r): return r.matches(e.raw) || (e.transport == .trap && r.matches(e.message))
        case .hostExact(let op, let a):
            let hit = a.matches(e.sourceAddress) || (!e.hostname.isEmpty && a.matches(e.hostname))
            switch op {
            case .eq: return hit
            case .ne: return !hit
            default: return QueryMatch.compare(e.sourceAddress, op, a.text)
            }
        case .host(let op, let n):
            switch op {
            case .eq: return n.isPrefix(of: e.sourceAddress) || (!e.hostname.isEmpty && n.isPrefix(of: e.hostname))
            case .ne: return !n.isPrefix(of: e.sourceAddress) && !(!e.hostname.isEmpty && n.isPrefix(of: e.hostname))
            default: return QueryMatch.compare(e.sourceAddress, op, n.text)
            }
        case .hostCIDR(let op, let c):
            let hit = c.contains(e.sourceAddress) || (!e.hostname.isEmpty && c.contains(e.hostname))
            return op == .ne ? !hit : hit
        case .hostGlob(let op, let g):
            let hit = g.matches(e.sourceAddress) || (!e.hostname.isEmpty && g.matches(e.hostname))
            return op == .ne ? !hit : hit
        case .severity(let op, let v): return QueryMatch.compare(e.severity.rawValue, op, v)
        case .facility(let op, let v): return QueryMatch.compare(e.facility.rawValue, op, v)
        case .vendor(let op, let set):
            switch op {
            case .eq: return set.contains(e.vendor)
            case .ne: return !set.contains(e.vendor)
            default: return false
            }
        case .program(let op, let n): return Self.text(e.program, op, n)
        case .programIs(let op, let v):
            let hit = e.program.caseInsensitiveCompare(v) == .orderedSame
            return op == .ne ? !hit : hit
        case .pid(let op, let v):
            guard let pid = e.pid else { return op == .ne }
            switch op {
            case .eq: return pid == v
            case .ne: return pid != v
            default: return QueryMatch.compare(pid, op, v)
            }
        case .port(let op, let v): return QueryMatch.compare(Int(e.sourcePort), op, v)
        case .transport(let op, let v):
            switch op {
            case .eq: return e.transport.rawValue == v
            case .ne: return e.transport.rawValue != v
            default: return false
            }
        case .field(let keys, let op, let n, let negate):
            return Self.field(e, keys, op, n) != negate
        case .fieldExists(let keys, let negate):
            return Self.lookup(e, keys) != nil ? !negate : negate
        case .keyOr(let key, let op, let n, let fallback):
            if Self.lookup(e, [key]) != nil { return Self.field(e, [key], op, n) }
            return fallback.matches(e)
        }
    }

    private static func text(_ hay: String, _ op: QueryOp, _ n: Needle) -> Bool {
        switch op {
        case .eq: return n.found(in: hay)
        case .ne: return !n.found(in: hay)
        default: return QueryMatch.compare(hay, op, n.text)
        }
    }

    private static func lookup(_ e: LogEntry, _ keys: [KeyName]) -> String? {
        for f in e.fields {
            for k in keys where k.matches(f.key) { return f.value }
        }
        return nil
    }

    /// `=` on a field value: a prefix (`f:srcip=10.1.` , `f:level=warn`), except that a
    /// number only equals the same number (`f:dstport=53` is not 5353 or 530), a complete
    /// address only that address (`f:srcip=10.1.1.1` is not 10.1.1.10), and a `*` is a glob
    /// (`f:srcip=10.1.1.1*` is the prefix again, `f:user=*admin`).
    private static func valueMatches(_ n: Needle, _ value: String) -> Bool {
        if let c = n.cidr { return c.contains(value) }
        if let g = n.glob { return g.matches(value) }
        if let a = n.address { return a.matches(value) }
        guard n.isNumber, Needle.isDigits(value) else { return n.isPrefix(of: value) }
        return Needle.stripZeros(value) == n.numberText
    }

    private static func field(_ e: LogEntry, _ keys: [KeyName], _ op: QueryOp, _ n: Needle) -> Bool {
        switch op {
        case .eq:
            for f in e.fields where keys.contains(where: { $0.matches(f.key) }) {
                if valueMatches(n, f.value) { return true }
            }
            return false
        case .ne:
            for f in e.fields where keys.contains(where: { $0.matches(f.key) }) {
                if valueMatches(n, f.value) { return false }
            }
            return true
        default:
            guard let v = lookup(e, keys) else { return false }
            return QueryMatch.compare(v, op, n.text)
        }
    }
}
