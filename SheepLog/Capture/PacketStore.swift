import Combine
import Foundation
import Synchronization

/// Set when a file load has been replaced (another file, Clear, a live capture): the
/// background reader stops.
nonisolated final class LoadCancel: Sendable {
    private let flag = Atomic<Bool>(false)
    var isCancelled: Bool { flag.load(ordering: .relaxed) }
    func cancel() { flag.store(true, ordering: .relaxed) }
}

/// The packet ring (live or from a file) and its filtered view. Main-actor only.
///
/// - `packets` is chronological and capped at `limit`; past it the oldest 10 % go in one step
///   (ids are frame numbers and are never renumbered once shown).
/// - Frame numbers and relative times belong to the store: the first packet after `clear()`,
///   `beginLive` or `load` is frame 1 at 0.000000 s, whatever the capture thread counted.
/// - `visible` is `packets` through the current query, chronological. Appends grow it in place
///   (`generation` unchanged, so a table can just note the new rows); anything else that
///   replaces it (a rescan, an eviction, a clear) bumps `generation`.
/// - A query change re-filters everything off the main actor; a result is dropped if another
///   query, clear or load started meanwhile.
///
/// `packets` and `visible` are not `@Published`: a `@Published` array copies its whole buffer on
/// every in-place mutation (the wrapper has no `_modify`). They are plain stored properties
/// mutated in place, announced through `objectWillChange` before each change.
@MainActor
final class PacketStore: ObservableObject {
    /// Mutated in place; every change is preceded by one `objectWillChange.send()`. (No property
    /// observers: a `willSet` would force a copy of the whole array on every append.)
    private(set) var packets: [Packet] = []
    private(set) var visible: [Packet] = []
    @Published private(set) var generation: Int = 0

    @Published var queryText: String = "" {
        didSet { if queryText != oldValue { scheduleQuery() } }
    }
    @Published private(set) var queryError: String? {
        didSet { queryErrorIsNotice = queryError != nil && queryError == noticeText }
    }
    /// True when `queryError` is a notice about a filter that *is* applied (a slow regex).
    @Published private(set) var queryErrorIsNotice = false
    private var noticeText: String?
    @Published private(set) var query: Query = .empty
    @Published var paused: Bool = false {
        didSet { if oldValue, !paused { flushPaused() } }
    }

    @Published private(set) var totalReceived: Int = 0
    @Published private(set) var totalBytes: Int = 0
    @Published private(set) var dropped: Int = 0
    /// The part of `dropped` that never reached the ring: kernel drops (pcap_stats), batches
    /// the main thread could not take in, packets past the pause buffer. The rest are the
    /// oldest packets making room — a 1,000,000-packet file in a 200,000 ring is not "800,000
    /// dropped".
    @Published private(set) var lost: Int = 0
    @Published private(set) var rate: Double = 0
    /// nil while live; the file that was opened otherwise.
    @Published private(set) var fileURL: URL?
    /// libpcap link type of the current data (1 = Ethernet), for saving.
    @Published private(set) var linkType: Int32 = 1
    /// The opened classic pcap file's header snapshot length (written back on Save); nil live.
    private(set) var fileSnapLength: Int?

    /// A file is being read in the background.
    @Published private(set) var isLoading = false
    /// A file is being written in the background (`save(to:completion:)`).
    @Published private(set) var isSaving = false
    /// How many packets the running save writes (for "Saving 1,204 filtered packets…").
    @Published private(set) var savingCount = 0
    /// The last file error (read or write), for the pane to show.
    @Published var lastError: String?

    /// Ring size. Lowering it trims the ring at once; values below 1 count as 1.
    var limit: Int = 200_000 {
        didSet { if limit < oldValue { trimToLimit() } }
    }

    /// Which live capture may still deliver: bumped by `beginLive` and `load`, so a batch from a
    /// capture that was stopped or replaced (still queued on the main queue) is dropped.
    private(set) var liveSession = 0
    /// Set by the capture engine: stops a running capture before a file replaces the packets.
    var stopLiveCapture: (() -> Void)?

    private var matcher: PacketMatcher?
    private var pausedBuffer: [Packet] = []
    /// Packets held back while paused (received, not in the table yet).
    var pausedCount: Int { pausedBuffer.count }
    private var rescanToken = 0
    private var loadToken = 0
    private var loadCancel: LoadCancel?
    private var saveToken = 0
    private var queryTask: Task<Void, Never>?
    private var rateTimer: Timer?
    /// Timed on `Monotonic.now()`: a clock set back during a live capture froze pkt/s.
    private var rateSamples: [(time: Double, count: Int)] = []
    private var lastIngest = -Double.infinity
    /// The next frame number, and the timestamp of frame 1 (relative times are measured from it).
    private var nextID = 1
    private var firstTime: Double?
    /// The source's own numbering matches the store's (checked once per source), so batches
    /// are kept as they are.
    private var aligned = false

    private var effectiveLimit: Int { max(1, limit) }

    init() {}

    /// What the ring holds, as far as an analysis is concerned: which capture (`epoch`), its
    /// first and last frame and how many. A pane that analysed at one stamp has nothing new to
    /// analyse while the stamp is the same — a publish that changed nothing, one that arrived
    /// after the analysis had already read the packets, or a Packets filter rescan (it bumps
    /// `generation` but replaces only the rows shown).
    nonisolated struct DataStamp: Equatable, Sendable {
        let epoch: Int
        let first: Int
        let last: Int
        let count: Int
    }

    var dataStamp: DataStamp {
        DataStamp(epoch: epoch, first: packets.first?.id ?? 0, last: packets.last?.id ?? 0, count: packets.count)
    }

    /// Bumped by every Clear (and so every file load and live start): frame numbers start over
    /// at 1, so a frame number kept from before names another packet.
    private(set) var epoch = 0

    // MARK: Ingest

    func ingest(_ batch: [Packet]) {
        guard !batch.isEmpty else { return }
        let batch = numbered(batch)
        totalReceived += batch.count
        var bytes = 0
        for p in batch { bytes += p.length }
        totalBytes += bytes
        lastIngest = Monotonic.now()
        startRateTimer()
        if paused {
            pausedBuffer.append(contentsOf: batch)
            if pausedBuffer.count > effectiveLimit {
                let n = pausedBuffer.count - effectiveLimit
                pausedBuffer.removeFirst(n)
                dropped += n
                lost += n
            }
            return
        }
        append(batch)
    }

    /// A batch from the live capture started as `session` (see `liveSession`).
    func ingestLive(_ batch: [Packet], session: Int) {
        guard session == liveSession, fileURL == nil else { return }
        ingest(batch)
    }

    /// Frame numbers from `nextID`, relative times from the store's first packet. The capture
    /// thread and the file reader already number 1, 2, 3 … from their own first packet, so the
    /// common case (checked on the first packet) keeps the batch as it is.
    private func numbered(_ batch: [Packet]) -> [Packet] {
        let first = batch[0]
        if firstTime == nil {
            firstTime = first.timestamp.timeIntervalSince1970
            aligned = first.id == 1 && abs(first.relative) < 1e-9
        }
        let base = firstTime ?? 0
        defer { nextID += batch.count }
        if aligned, first.id == nextID { return batch }
        aligned = false
        var out: [Packet] = []
        out.reserveCapacity(batch.count)
        var id = nextID
        for p in batch {
            out.append(Packet(id: id, timestamp: p.timestamp, relative: p.timestamp.timeIntervalSince1970 - base,
                              length: p.length, captured: p.captured, data: p.data, decoded: p.decoded))
            id += 1
        }
        return out
    }

    /// Kernel drops reported by the capture engine (pcap_stats deltas).
    func addKernelDrops(_ n: Int) {
        guard n > 0 else { return }
        dropped += n
        lost += n
    }

    private func append(_ batch: [Packet]) {
        let limit = effectiveLimit
        let matched: [Packet]
        if let matcher {
            matched = batch.filter { matcher.matches($0) }
            reportTrippedRegex(matcher)
        } else {
            matched = batch
        }
        objectWillChange.send()
        let overflow = packets.count + batch.count - limit
        if overflow > 0 {
            let evicted = min(packets.count + batch.count, max(overflow, limit / 10))
            packets.append(contentsOf: batch)
            packets.removeFirst(evicted)
            dropped += evicted
            let firstID = packets.first?.id ?? Int.max
            let cut = Self.lowerBound(visible, id: firstID)
            let from = Self.lowerBound(matched, id: firstID)
            if cut > 0 || from < matched.count {
                visible.removeFirst(cut)
                visible.append(contentsOf: matched[from...])
            }
            generation += 1
        } else {
            packets.append(contentsOf: batch)
            if !matched.isEmpty { visible.append(contentsOf: matched) }
        }
    }

    /// Drop the oldest packets beyond `limit` now (Settings lowered it).
    private func trimToLimit() {
        let excess = packets.count - effectiveLimit
        guard excess > 0 else { return }
        objectWillChange.send()
        packets.removeFirst(excess)
        dropped += excess
        if let first = packets.first?.id {
            let cut = Self.lowerBound(visible, id: first)
            if cut > 0 { visible.removeFirst(cut) }
        }
        generation += 1
    }

    private func flushPaused() {
        guard !pausedBuffer.isEmpty else { return }
        let pending = pausedBuffer
        pausedBuffer = []
        append(pending)
    }

    func clear() {
        epoch += 1
        rescanToken += 1
        loadToken += 1
        loadCancel?.cancel()
        loadCancel = nil
        objectWillChange.send()
        packets = []
        visible = []
        pausedBuffer = []
        generation += 1
        totalReceived = 0
        totalBytes = 0
        dropped = 0
        lost = 0
        rate = 0
        rateSamples = []
        fileURL = nil
        fileSnapLength = nil
        isLoading = false
        nextID = 1
        firstTime = nil
        aligned = false
    }

    /// A live capture starts: empty the ring and remember the interface's link type.
    func beginLive(linkType: Int32) {
        clear()
        liveSession += 1
        self.linkType = linkType
    }

    // MARK: Files

    /// Replace the contents with a file's packets (pcap or pcapng).
    /// Throws at once when libpcap cannot open the file; the packets then arrive in batches
    /// from a background read (`isLoading` is true meanwhile). A running live capture is stopped
    /// first, and anything it still had in flight is dropped.
    func load(from url: URL) throws {
        try load(from: url, completion: nil)
    }

    func load(from url: URL, completion: (@MainActor @Sendable () -> Void)?) throws {
        let lt = try PcapFile.linkType(of: url)
        stopLiveCapture?()
        liveSession += 1
        clear()
        // Pause freezes a live table. Left on, a file opened while paused would go entirely into
        // the pause buffer: an empty table saying "No packets … open a .pcap", Save disabled.
        if paused { paused = false }
        fileURL = url
        fileSnapLength = PcapFile.headerSnapLength(of: url)
        linkType = lt
        isLoading = true
        loadToken += 1
        let token = loadToken
        let cancel = LoadCancel()
        loadCancel = cancel
        // Back-pressure: the reader decodes faster than the main actor appends; unbounded, a
        // 1,000,000-packet file would queue ~all of itself as blocks on the main queue (hundreds
        // of MB) before the ring could drop the oldest. At most 4 batches in flight.
        let inFlight = DispatchSemaphore(value: 4)
        Task.detached(priority: .userInitiated) { [weak self] in
            var failure: String?
            do {
                _ = try PcapFile.read(url, while: { !cancel.isCancelled }) { batch in
                    inFlight.wait()
                    DispatchQueue.main.async {
                        defer { inFlight.signal() }
                        guard let self, self.loadToken == token else { return }
                        self.ingest(batch)
                    }
                }
            } catch {
                failure = error.localizedDescription
            }
            let message = failure
            DispatchQueue.main.async {
                guard let self, self.loadToken == token else { return }
                self.isLoading = false
                self.rate = 0
                if let message { self.lastError = "\(url.lastPathComponent): \(message)" }
                completion?()
            }
        }
    }

    /// What `save` writes: `visible`, or every packet when the filter is empty.
    var packetsToSave: [Packet] { query.isEmpty ? packets : visible }

    /// Write `visible` (or all, when the filter is empty) as a classic pcap file, on the
    /// calling thread (tests, small captures). The pane uses `save(to:completion:)`.
    func save(to url: URL) throws {
        try PcapFile.write(packetsToSave, linkType: linkType, to: url, snapLength: fileSnapLength)
    }

    /// Write off the main actor (200k packets are ~100 MB of `fwrite`); `isSaving` is true
    /// meanwhile. `completion` gets nil or the error text, on the main actor.
    func save(to url: URL, completion: @escaping @MainActor (String?) -> Void) {
        let snapshot = packetsToSave, lt = linkType, snap = fileSnapLength
        saveToken += 1
        let token = saveToken
        savingCount = snapshot.count
        isSaving = true
        PendingWrites.begin()          // ⌘Q waits for the write
        Task.detached(priority: .userInitiated) { [weak self] in
            var failure: String?
            do { try PcapFile.write(snapshot, linkType: lt, to: url, snapLength: snap) } catch { failure = error.localizedDescription }
            PendingWrites.end()
            let message = failure
            await MainActor.run {
                if let self, self.saveToken == token { self.isSaving = false }
                completion(message)
            }
        }
    }

    // MARK: Query

    private func scheduleQuery() {
        queryTask?.cancel()
        queryTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(200))
            guard !Task.isCancelled else { return }
            self?.applyQueryNow()
        }
    }

    /// Parse `queryText` now (skipping the debounce). `synchronous` re-filters on the calling
    /// thread (tests); otherwise the full rescan runs off the main actor.
    func applyQueryNow(synchronous: Bool = false) {
        queryTask?.cancel()
        let q: Query
        do {
            q = try Query.parse(queryText)
            let warning = q.leaves.lazy.compactMap { leaf -> String? in
                if case .regex(let p) = leaf { return RegexLint.warning(p) }
                return nil
            }.first
            noticeText = warning
            if queryError != warning { queryError = warning }
        } catch {
            queryError = (error as? QueryError)?.message ?? error.localizedDescription
            return
        }
        guard q != query || synchronous else { return }
        query = q
        matcher = q.isEmpty ? nil : PacketMatcher(q)
        rescan(synchronous: synchronous)
    }

    private func rescan(synchronous: Bool) {
        rescanToken += 1
        let token = rescanToken
        guard let m = matcher else {
            objectWillChange.send()
            visible = packets
            generation += 1
            return
        }
        let snapshot = packets
        let lastID = snapshot.last?.id
        if synchronous {
            finishRescan(token: token, result: Self.filter(snapshot, with: m), lastID: lastID, matcher: m)
            return
        }
        Task.detached(priority: .userInitiated) { [weak self] in
            let result = PacketStore.filter(snapshot, with: m)
            await self?.finishRescan(token: token, result: result, lastID: lastID, matcher: m)
        }
    }

    private func finishRescan(token: Int, result: [Packet], lastID: Int?, matcher m: PacketMatcher) {
        guard token == rescanToken else { return }
        var v = result
        if let first = packets.first?.id {
            let cut = Self.lowerBound(v, id: first)
            if cut > 0 { v.removeFirst(cut) }
        } else {
            v = []
        }
        let tailStart = lastID.map { Self.lowerBound(packets, id: $0 + 1) } ?? 0
        if tailStart < packets.count {
            for p in packets[tailStart...] where m.matches(p) { v.append(p) }
        }
        objectWillChange.send()
        visible = v
        generation += 1
        reportTrippedRegex(m)
    }

    /// Says so when the filter's regular expression was given up on as too slow.
    private func reportTrippedRegex(_ m: PacketMatcher) {
        guard !m.regexes.isEmpty, let r = m.trippedRegex else { return }
        let text = "Regular expression /\(r.pattern)/ is too slow and was stopped — the list is incomplete. "
            + "Simplify it (no nested quantifiers such as (a+)+ or .*.*)"
        noticeText = text
        if queryError != text { queryError = text }
    }

    /// Filter off the main actor, chunked over the cores for big inputs.
    nonisolated static func filter(_ packets: [Packet], with matcher: PacketMatcher?) -> [Packet] {
        guard let matcher else { return packets }
        let n = packets.count
        if n < 16_384 { return packets.filter { matcher.matches($0) } }
        let chunks = min(64, max(2, ProcessInfo.processInfo.activeProcessorCount * 2))
        let size = (n + chunks - 1) / chunks
        let slots = ResultSlots(count: chunks)
        DispatchQueue.concurrentPerform(iterations: chunks) { i in
            let lo = i * size, hi = min(n, lo + size)
            guard lo < hi else { return }
            var out: [Packet] = []
            for j in lo..<hi where matcher.matches(packets[j]) { out.append(packets[j]) }
            slots.set(i, out)
        }
        return slots.joined()
    }

    /// First index whose packet id is ≥ `id` (ids ascend within the ring).
    nonisolated static func lowerBound(_ list: [Packet], id: Int) -> Int {
        var lo = 0, hi = list.count
        while lo < hi {
            let mid = (lo + hi) / 2
            if list[mid].id < id { lo = mid + 1 } else { hi = mid }
        }
        return lo
    }

    /// Frame `id` is still in the ring (filtered out or not).
    func contains(id: Int) -> Bool {
        let i = Self.lowerBound(packets, id: id)
        return i < packets.count && packets[i].id == id
    }

    /// The index of frame `id` in `visible`, if shown.
    func visibleIndex(of id: Int) -> Int? {
        let i = Self.lowerBound(visible, id: id)
        return i < visible.count && visible[i].id == id ? i : nil
    }

    // MARK: Rate

    private func startRateTimer() {
        guard rateTimer == nil else { return }
        rateSamples = [(Monotonic.now(), totalReceived)]
        let t = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.tickRate() }
        }
        RunLoop.main.add(t, forMode: .common)
        rateTimer = t
    }

    private func tickRate() {
        let now = Monotonic.now()
        rateSamples.append((now, totalReceived))
        rateSamples.removeAll { now - $0.time > 3.05 }
        if let first = rateSamples.first, let last = rateSamples.last, last.time > first.time {
            let r = Double(last.count - first.count) / (last.time - first.time)
            if abs(r - rate) > 0.01 { rate = max(0, r) }
        }
        if now - lastIngest > 4 {
            rate = 0
            rateTimer?.invalidate()
            rateTimer = nil
        }
    }
}

/// Per-chunk results written from `concurrentPerform`. `@unchecked` without a lock by design:
/// each iteration writes only its own index, and `joined()` runs after `concurrentPerform` returns.
nonisolated private final class ResultSlots: @unchecked Sendable {
    private let slots: UnsafeMutablePointer<[Packet]>
    private let count: Int

    init(count: Int) {
        self.count = count
        slots = .allocate(capacity: count)
        slots.initialize(repeating: [], count: count)
    }

    deinit {
        slots.deinitialize(count: count)
        slots.deallocate()
    }

    func set(_ i: Int, _ v: [Packet]) { slots[i] = v }

    func joined() -> [Packet] {
        var total = 0
        for i in 0..<count { total += slots[i].count }
        var out: [Packet] = []
        out.reserveCapacity(total)
        for i in 0..<count { out.append(contentsOf: slots[i]) }
        return out
    }
}

// MARK: - The packet matcher (every "Packet key" of the grammar)

/// A `Query` compiled for packets: keys resolved and values pre-parsed once, so a 200k rescan
/// is a tight loop.
nonisolated struct PacketMatcher: Sendable {
    enum Side: Sendable { case either, source, destination }

    enum Address: Sendable {
        case exact([UInt8])
        case prefix([UInt8])
        case cidr(UInt32, UInt32)
        /// A complete IPv6 address, compared by value (`2001:0db8:0:0::1` is the decoder's
        /// `2001:db8::1`), and an IPv6 subnet (`2001:db8::/32`).
        case exact6([UInt8])
        case cidr6(CIDR)
    }

    enum Proto: Sendable {
        case tcp, udp, icmp, icmp6, arp, ip, ipv4, ipv6
        case number(QueryOp, Int)
        case name([UInt8])
    }

    enum Leaf: Sendable {
        case text([UInt8])
        /// Bounded per string and given up on when it keeps being slow: `(a+)+$` against a
        /// 30-character Info is enough to hang a re-scan.
        case regex(GuardedRegex)
        case address(Side, Address)
        case port(Side, QueryOp, Int)
        case proto(Proto)
        case vlan(QueryOp, Int)
        case mac([UInt8])
        case length(QueryOp, Int)
        case frame(QueryOp, Int)
        /// `frame:a OR frame:b OR …` folded into one lookup (the Flows pane's "Show packets").
        case frames(Set<Int>)
        case flags([UInt8])
        case sni([UInt8])
        case host([UInt8])
        case info([UInt8])
        case never
    }

    indirect enum Node: Sendable {
        case and(Node, Node)
        case or(Node, Node)
        case all([Node])
        case any([Node])
        case not(Node)
        case leaf(Leaf)
    }

    let root: Node?
    /// The regular expressions in the tree (to tell whether one was given up on).
    let regexes: [GuardedRegex]

    init(_ query: Query) {
        let r = query.root.map(Self.compile)
        root = r
        func collect(_ n: Node?) -> [GuardedRegex] {
            switch n {
            case .and(let a, let b)?, .or(let a, let b)?: return collect(a) + collect(b)
            case .all(let xs)?, .any(let xs)?: return xs.flatMap { collect($0) }
            case .not(let a)?: return collect(a)
            case .leaf(.regex(let x))?: return [x]
            default: return []
            }
        }
        regexes = collect(r)
    }

    /// A regex of this filter that was stopped as too slow.
    var trippedRegex: GuardedRegex? { regexes.first { $0.tripped } }

    func matches(_ p: Packet) -> Bool {
        guard let root else { return true }
        return Self.eval(root, p)
    }

    private static func eval(_ n: Node, _ p: Packet) -> Bool {
        switch n {
        case .and(let a, let b): return eval(a, p) && eval(b, p)
        case .or(let a, let b): return eval(a, p) || eval(b, p)
        case .all(let xs):
            for x in xs where !eval(x, p) { return false }
            return true
        case .any(let xs):
            for x in xs where eval(x, p) { return true }
            return false
        case .not(let a): return !eval(a, p)
        case .leaf(let l): return leaf(l, p)
        }
    }

    // MARK: Compile

    private static func compile(_ n: QueryNode) -> Node {
        switch n {
        case .and: return compileAnd(n)
        case .or: return compileOr(n)
        case .not(let a): return .not(compile(a))
        case .text(let t): return .leaf(.text(folded(t)))
        case .regex(let r): return .leaf(.regex(GuardedRegex(r)))
        case .field(let key, let op, let value): return field(key, op, value)
        }
    }

    /// An OR chain with its `frame:N` terms gathered into one set, so fifty of them cost one
    /// hash lookup per packet instead of fifty comparisons.
    private static func compileOr(_ n: QueryNode) -> Node {
        var terms: [QueryNode] = []
        var stack = [n]
        while let q = stack.popLast() {
            if case .or(let a, let b) = q { stack.append(b); stack.append(a) } else { terms.append(q) }
        }
        var frames = Set<Int>()
        var rest: [Node] = []
        for t in terms {
            if case .field(let key, .eq, let value) = t, key == "frame",
               let id = Int(value.trimmingCharacters(in: .whitespaces)) {
                frames.insert(id)
            } else {
                rest.append(compile(t))
            }
        }
        var nodes = rest
        if frames.count == 1, let id = frames.first { nodes.insert(.leaf(.frame(.eq, id)), at: 0) }
        else if !frames.isEmpty { nodes.insert(.leaf(.frames(frames)), at: 0) }
        // One flat list, not a left-deep chain: evaluation recursion stays as shallow as the
        // parentheses (a 256-term query on a 512 KB worker stack).
        return nodes.count == 1 ? nodes[0] : .any(nodes)
    }

    /// An AND chain as one flat list (iteratively: the chain is as deep as it is long).
    private static func compileAnd(_ n: QueryNode) -> Node {
        var stack = [n], parts: [Node] = []
        while let q = stack.popLast() {
            if case .and(let a, let b) = q { stack.append(b); stack.append(a) } else { parts.append(compile(q)) }
        }
        return parts.count == 1 ? parts[0] : .all(parts)
    }

    private static func field(_ key: String, _ op: QueryOp, _ value: String) -> Node {
        // `!=` is "not equal" for every key (a missing field is "not equal").
        if op == .ne, !(key == "len" || key == "frame") {
            return .not(field(key, .eq, value))
        }
        let v = value.trimmingCharacters(in: .whitespaces)
        switch key {
        case "ip", "addr", "src", "dst":
            let side: Side = key == "src" ? .source : key == "dst" ? .destination : .either
            return .leaf(.address(side, address(v)))
        case "port", "sport", "dport":
            let side: Side = key == "sport" ? .source : key == "dport" ? .destination : .either
            guard let n = portNumber(v) else { return .leaf(.never) }
            return .leaf(.port(side, op, n))
        case "proto", "protocol":
            return .leaf(.proto(proto(v, op)))
        case "vlan":
            guard let n = Int(v) else { return .leaf(.never) }
            return .leaf(.vlan(op, n))
        case "mac", "eth":
            return .leaf(.mac(folded(v.replacingOccurrences(of: "-", with: ":"))))
        case "len", "length":
            guard let n = Int(v) else { return .leaf(.never) }
            return .leaf(.length(op, n))
        case "frame":
            guard let n = Int(v) else { return .leaf(.never) }
            return .leaf(.frame(op, n))
        case "flags", "flag":
            return .leaf(.flags(folded(v.replacingOccurrences(of: " ", with: ""))))
        case "sni":
            return .leaf(.sni(folded(v)))
        case "host":
            return .leaf(.host(folded(v)))
        case "info":
            return .leaf(.info(folded(v)))
        default:
            // Not a packet key ("http://…", "Seq:…"): search the words as typed.
            let opText = op == .eq ? "" : op.rawValue
            return .leaf(.text(folded("\(key):\(opText)\(value)")))
        }
    }

    private static func address(_ v: String) -> Address {
        if let slash = v.firstIndex(of: "/"), let bits = Int(v[v.index(after: slash)...]), (0...32).contains(bits),
           let net = ipv4Value(String(v[..<slash])) {
            let mask: UInt32 = bits == 0 ? 0 : ~UInt32(0) << UInt32(32 - bits)
            return .cidr(net & mask, mask)
        }
        if v.contains(":") {
            if v.contains("/"), let c = CIDR(v), c.network.count == 16 { return .cidr6(c) }
            if let b = CIDR.bytes(of: v), b.count == 16 { return .exact6(b) }
        }
        var s = v.lowercased()
        if s.hasSuffix("*") { s.removeLast(); return .prefix(folded(s)) }
        if ipv4Value(s) != nil || (s.contains(":") && s.split(separator: ":", omittingEmptySubsequences: false).count >= 3
                                    && (s.contains("::") || s.split(separator: ":").count == 8)) {
            return .exact(folded(s))
        }
        return .prefix(folded(s))
    }

    static func ipv4Value(_ s: String) -> UInt32? {
        var value: UInt32 = 0
        var octets = 0
        var cur: UInt32 = 0
        var digits = 0
        for c in s.utf8 {
            if c == 0x2e {
                guard digits > 0, cur <= 255 else { return nil }
                value = value << 8 | cur
                octets += 1
                cur = 0
                digits = 0
            } else if c >= 0x30, c <= 0x39 {
                cur = cur * 10 + UInt32(c - 0x30)
                digits += 1
                guard digits <= 3 else { return nil }
            } else {
                return nil
            }
        }
        guard digits > 0, cur <= 255, octets == 3 else { return nil }
        return value << 8 | cur
    }

    private static let portNames: [String: Int] = [
        "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "dns": 53, "domain": 53, "dhcp": 67, "bootps": 67,
        "bootpc": 68, "tftp": 69, "http": 80, "ntp": 123, "snmp": 161, "snmptrap": 162, "bgp": 179,
        "ldap": 389, "https": 443, "smb": 445, "syslog": 514, "ldaps": 636, "radius": 1812,
        "radius-acct": 1813, "rdp": 3389, "mdns": 5353,
    ]

    private static func portNumber(_ v: String) -> Int? {
        if let n = Int(v) { return n }
        return portNames[v.lowercased()]
    }

    private static func proto(_ v: String, _ op: QueryOp) -> Proto {
        if let n = Int(v) { return .number(op, n) }
        switch v.lowercased() {
        case "tcp": return .tcp
        case "udp": return .udp
        case "icmp": return .icmp
        case "icmpv6", "icmp6": return .icmp6
        case "arp": return .arp
        case "ip": return .ip
        case "ipv4", "ip4": return .ipv4
        case "ipv6", "ip6": return .ipv6
        default: return .name(folded(v))
        }
    }

    // MARK: Evaluate

    private static func leaf(_ l: Leaf, _ p: Packet) -> Bool {
        // Frame-number and length keys never need the decode: answer them before touching it.
        switch l {
        case .never: return false
        case .frame(let op, let n): return QueryMatch.compare(p.id, op, n)
        case .frames(let set): return set.contains(p.id)
        case .length(let op, let n): return QueryMatch.compare(p.length, op, n)
        default: break
        }
        let d = p.decoded
        switch l {
        case .never, .frame, .frames, .length:
            return false
        case .text(let n):
            return contains(d.info, n) || contains(d.source, n) || contains(d.destination, n)
                || contains(d.protocolName, n)
        case .regex(let r):
            return r.matches(d.info) || r.matches(d.source) || r.matches(d.destination) || r.matches(d.protocolName)
        case .address(let side, let a):
            switch side {
            case .source: return address(a, d.source)
            case .destination: return address(a, d.destination)
            case .either: return address(a, d.source) || address(a, d.destination)
            }
        case .port(let side, let op, let n):
            let sp = d.sourcePort.map(Int.init), dp = d.destinationPort.map(Int.init)
            switch side {
            case .source: return sp.map { QueryMatch.compare($0, op, n) } ?? false
            case .destination: return dp.map { QueryMatch.compare($0, op, n) } ?? false
            case .either:
                return (sp.map { QueryMatch.compare($0, op, n) } ?? false)
                    || (dp.map { QueryMatch.compare($0, op, n) } ?? false)
            }
        case .proto(let pr):
            switch pr {
            case .tcp: return d.tcp != nil || d.ip?.proto == 6
            case .udp: return d.udp != nil || d.ip?.proto == 17
            case .icmp: return d.ip?.proto == 1
            case .icmp6: return d.ip?.proto == 58
            case .arp: return d.arp != nil || d.etherType == 0x0806 || d.protocolName == "ARP"
            case .ip: return d.ip != nil
            case .ipv4: return d.ip?.version == 4
            case .ipv6: return d.ip?.version == 6
            case .number(let op, let n): return d.ip.map { QueryMatch.compare(Int($0.proto), op, n) } ?? false
            case .name(let n):
                return hasPrefix(d.protocolName, n) || (d.app.map { hasPrefix($0.name, n) } ?? false)
            }
        case .vlan(let op, let n):
            return d.vlan.map { QueryMatch.compare(Int($0), op, n) } ?? false
        case .mac(let n):
            return contains(d.sourceMAC, n) || contains(d.destinationMAC, n)
                || (d.arp.map { contains($0.senderMAC, n) || contains($0.targetMAC, n) } ?? false)
        case .flags(let n):
            guard let t = d.tcp else { return false }
            return contains(t.flags.label.replacingOccurrences(of: " ", with: ""), n)
        case .sni(let n):
            if case .tlsClientHello(let sni?, _) = d.app { return contains(sni, n) }
            return false
        case .host(let n):
            switch d.app {
            case .httpRequest(_, _, let host?): return contains(host, n)
            case .tlsClientHello(let sni?, _): return contains(sni, n)
            case .dns(let q?, _, _, _): return contains(q, n)
            default: return false
            }
        case .info(let n):
            return contains(d.info, n)
        }
    }

    private static func address(_ a: Address, _ s: String) -> Bool {
        switch a {
        case .exact(let e): return s.utf8.count == e.count && hasPrefix(s, e)
        case .prefix(let pre): return hasPrefix(s, pre)
        case .cidr(let net, let mask):
            guard let v = ipv4Value(s) else { return false }
            return v & mask == net
        case .exact6(let b): return s.contains(":") && CIDR.bytes(of: s) == b
        case .cidr6(let c): return s.contains(":") && c.contains(s)
        }
    }

    // MARK: ASCII case-folding search (no allocation, no locale)

    static func folded(_ s: String) -> [UInt8] {
        s.utf8.map { $0 >= 0x41 && $0 <= 0x5a ? $0 | 0x20 : $0 }
    }

    @inline(__always) private static func fold(_ c: UInt8) -> UInt8 { c >= 0x41 && c <= 0x5a ? c | 0x20 : c }

    static func contains(_ hay: String, _ needle: [UInt8]) -> Bool {
        if needle.isEmpty { return true }
        var s = hay
        return s.withUTF8 { h in
            let n = needle.count, m = h.count
            guard m >= n else { return false }
            let first = needle[0]
            var i = 0
            while i <= m - n {
                if fold(h[i]) == first {
                    var j = 1
                    while j < n, fold(h[i + j]) == needle[j] { j += 1 }
                    if j == n { return true }
                }
                i += 1
            }
            return false
        }
    }

    static func hasPrefix(_ hay: String, _ needle: [UInt8]) -> Bool {
        var s = hay
        return s.withUTF8 { h in
            guard h.count >= needle.count else { return false }
            for j in 0..<needle.count where fold(h[j]) != needle[j] { return false }
            return true
        }
    }
}
