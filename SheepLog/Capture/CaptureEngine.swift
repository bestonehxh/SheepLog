import CPcap
import Combine
import Foundation
import Synchronization
import SystemConfiguration

/// Live capture through libpcap (CPcap module). Promiscuous by default so mirrored (SPAN) traffic
/// arriving on the port is seen. Decodes on its own thread and hands `PacketStore.ingest` a batch
/// every ~100 ms.
///
/// Lifecycle: the read-loop thread owns the `pcap_t` once started and closes it itself after its
/// last `pcap_next_ex` / `pcap_stats`, so `stop()` never closes a handle the thread may still be
/// using (it breaks the loop and waits for it). The read timeout (100 ms) and immediate mode are
/// set before `pcap_activate`, so a loop blocked in the kernel on an idle interface sees the break
/// within one timeout — BPF has no way to wake a blocked read.
@MainActor
final class CaptureEngine: ObservableObject {
    @Published private(set) var isRunning = false
    @Published private(set) var lastError: String?
    /// A non-fatal note from activation (`PCAP_WARNING_*`), e.g. promiscuous mode not supported.
    @Published private(set) var warning: String?
    @Published private(set) var interfaceName: String = ""
    /// What the running capture was started with (Settings may have changed since: they apply
    /// at the next Start).
    @Published private(set) var runningPromiscuous = false
    @Published private(set) var runningFilter = ""
    /// Kernel-reported drops (pcap_stats).
    @Published private(set) var kernelDropped: Int = 0

    private let store: PacketStore
    private var handle: PcapHandle?
    private var reader: CaptureReader?
    private var runID = 0
    private var openObserver: NSObjectProtocol?

    init(store: PacketStore) {
        self.store = store
        // A file opened while capturing stops the capture first.
        store.stopLiveCapture = { [weak self] in self?.stop() }
        // ⌘O works from every pane: switch to Packets and ask for a file.
        openObserver = NotificationCenter.default.addObserver(forName: .sheepLogOpenPcap, object: nil, queue: .main) { _ in
            MainActor.assumeIsolated { PacketFileActions.open() }
        }
        let demoPane = CommandLine.value(after: "-demoPane")
        if demoPane == "packets" || (demoPane == nil && (DemoFlags.capture != nil || DemoFlags.pcap != nil)) {
            DispatchQueue.main.async { AppModel.shared.mainPane = .packets }
        }
    }

    /// The last reference going away mid-capture must not leave the read thread running (and
    /// the BPF device open) forever: break the loop; the thread closes the handle as it exits.
    isolated deinit {
        handle?.breakLoop()
        reader?.requestStop()
        if let openObserver { NotificationCenter.default.removeObserver(openObserver) }
    }

    /// Every interface libpcap can open, with its addresses; loopback and down interfaces last.
    /// Cached for 2 s — `pcap_findalldevs` walks every interface and can take tens of ms, and the
    /// shell calls this on the main thread (Start, Settings).
    nonisolated static func interfaces() -> [CaptureInterface] {
        interfaces(maxAge: 2)
    }

    /// `maxAge: 0` always rescans (a picker being refreshed off the main thread).
    nonisolated static func interfaces(maxAge: Double) -> [CaptureInterface] {
        InterfaceCache.shared.value(maxAge: maxAge, scan: scanInterfaces)
    }

    /// BSD name → the name System Settings shows ("Wi-Fi", "Ethernet Adapter", "Thunderbolt Bridge").
    nonisolated private static func displayNames() -> [String: String] {
        var out: [String: String] = [:]
        guard let all = SCNetworkInterfaceCopyAll() as? [SCNetworkInterface] else { return out }
        for i in all {
            guard let bsd = SCNetworkInterfaceGetBSDName(i) as String?,
                  let label = SCNetworkInterfaceGetLocalizedDisplayName(i) as String? else { continue }
            out[bsd] = label
        }
        return out
    }

    nonisolated private static func scanInterfaces() -> [CaptureInterface] {
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        var list: UnsafeMutablePointer<pcap_if_t>?
        guard pcap_findalldevs(&list, &errbuf) == 0 else { return [] }
        defer { if let list { pcap_freealldevs(list) } }
        let displayNames = Self.displayNames()
        var out: [CaptureInterface] = []
        var cur = list
        while let dev = cur {
            let d = dev.pointee
            let name = String(cString: d.name)
            let desc = d.description.map { String(cString: $0) } ?? displayNames[name] ?? ""
            var v4: [String] = [], v6: [String] = []
            var a = d.addresses
            while let addr = a {
                if let sa = addr.pointee.addr, let text = Self.text(sa) {
                    if sa.pointee.sa_family == UInt8(AF_INET) { v4.append(text) } else { v6.append(text) }
                }
                a = addr.pointee.next
            }
            out.append(CaptureInterface(name: name, description: desc, addresses: v4 + v6,
                                        isUp: d.flags & UInt32(PCAP_IF_UP) != 0,
                                        isLoopback: d.flags & UInt32(PCAP_IF_LOOPBACK) != 0))
            cur = d.next
        }
        func rank(_ i: CaptureInterface) -> Int {
            let en = i.name.hasPrefix("en")
            if i.isLoopback { return 5 }
            if i.isUp, !i.addresses.isEmpty { return en ? 0 : 1 }
            if i.isUp { return en ? 2 : 3 }
            return 4
        }
        return out.sorted {
            let a = rank($0), b = rank($1)
            return a != b ? a < b : $0.name.localizedStandardCompare($1.name) == .orderedAscending
        }
    }

    /// Numeric text of an AF_INET / AF_INET6 sockaddr (nil for link-layer addresses).
    nonisolated private static func text(_ sa: UnsafeMutablePointer<sockaddr>) -> String? {
        let family = Int32(sa.pointee.sa_family)
        guard family == AF_INET || family == AF_INET6 else { return nil }
        let len = socklen_t(family == AF_INET ? MemoryLayout<sockaddr_in>.size : MemoryLayout<sockaddr_in6>.size)
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(sa, len, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { return nil }
        return PcapFile.errorText(host)
    }

    /// libpcap's complaint about a capture filter compiled for `linkType`, or nil when it
    /// compiles. No device is opened (a settings field can check as the user types).
    nonisolated static func filterError(_ filter: String, linkType: Int32 = 1) -> String? {
        let f = filter.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !f.isEmpty else { return nil }
        if let tooLong = filterLengthError(f) { return tooLong }
        guard let dead = pcap_open_dead(linkType, 262_144) else { return "libpcap could not check the filter" }
        defer { pcap_close(dead) }
        var program = bpf_program()
        guard pcap_compile(dead, &program, f, optimizeFilter(f), bpf_u_int32(PCAP_NETMASK_UNKNOWN)) == 0 else {
            return "Bad capture filter: \(String(cString: pcap_geterr(dead)))"
        }
        pcap_freecode(&program)
        return nil
    }

    /// libpcap's BPF optimiser is super-linear: `host a or host b or …` with 700 hosts
    /// (13 KB) took 15 s to compile — on the main thread, since `start` compiles there. Long
    /// filters are compiled unoptimised (still correct; 0.3 s at 8 KB), and past 8 KB refused.
    nonisolated static let maxFilterLength = 8_192
    nonisolated static let optimizeLimit = 1_024

    nonisolated static func filterLengthError(_ f: String) -> String? {
        f.utf8.count > maxFilterLength
            ? "Capture filter too long (\(f.utf8.count) bytes; at most \(maxFilterLength)). Use a shorter expression, e.g. a net instead of many hosts."
            : nil
    }

    nonisolated static func optimizeFilter(_ f: String) -> Int32 { f.utf8.count <= optimizeLimit ? 1 : 0 }

    /// `bpfFilter` is a libpcap filter expression ("not port 22"); empty = everything.
    /// Starting while running restarts the capture (the old run is stopped first).
    func start(interface: String, promiscuous: Bool, bpfFilter: String, snapLength: Int = 262_144) {
        if isRunning || handle != nil { stop() }
        lastError = nil
        warning = nil
        if let tooLong = Self.filterLengthError(bpfFilter.trimmingCharacters(in: .whitespacesAndNewlines)) {
            lastError = tooLong
            return
        }
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        guard let p = pcap_create(interface, &errbuf) else {
            lastError = "Cannot open \(interface): \(PcapFile.errorText(errbuf))"
            return
        }
        // Everything that shapes the read loop is set before activation (after it they fail
        // with PCAP_ERROR_ACTIVATED): the 100 ms timeout bounds how long a stop waits.
        pcap_set_snaplen(p, Int32(clamping: max(64, snapLength)))
        pcap_set_promisc(p, promiscuous ? 1 : 0)
        pcap_set_timeout(p, 100)
        pcap_set_buffer_size(p, 16 << 20)
        pcap_set_immediate_mode(p, 1)
        let status = pcap_activate(p)
        if status < 0 {
            let detail = String(cString: pcap_geterr(p))
            let base = String(cString: pcap_statustostr(status))
            pcap_close(p)
            if status == PCAP_ERROR_PERM_DENIED || detail.localizedCaseInsensitiveContains("permission denied") {
                lastError = "No permission to capture on \(interface) (/dev/bpf* is not readable). "
                    + "Install Wireshark's ChmodBPF, or run `sudo chmod o+rw /dev/bpf*` (until the next restart)."
            } else if status == PCAP_ERROR_NO_SUCH_DEVICE {
                lastError = "Cannot capture on \(interface): no such interface."
            } else {
                lastError = "Cannot capture on \(interface): \(detail.isEmpty ? base : detail)"
            }
            return
        }
        if status > 0 {
            // PCAP_WARNING_PROMISC_NOTSUP (lo0, some USB adapters), PCAP_WARNING_TSTAMP_TYPE_NOTSUP,
            // PCAP_WARNING: the capture runs.
            let detail = String(cString: pcap_geterr(p))
            warning = status == PCAP_WARNING_PROMISC_NOTSUP
                ? "\(interface) does not support promiscuous mode; only traffic to and from this Mac is seen."
                : (detail.isEmpty ? String(cString: pcap_statustostr(status)) : detail)
        }
        let filter = bpfFilter.trimmingCharacters(in: .whitespacesAndNewlines)
        if !filter.isEmpty {
            var program = bpf_program()
            if pcap_compile(p, &program, filter, Self.optimizeFilter(filter), bpf_u_int32(PCAP_NETMASK_UNKNOWN)) != 0 {
                lastError = "Bad capture filter: \(String(cString: pcap_geterr(p)))"
                pcap_close(p)
                return
            }
            let set = pcap_setfilter(p, &program)
            pcap_freecode(&program)
            if set != 0 {
                lastError = "Bad capture filter: \(String(cString: pcap_geterr(p)))"
                pcap_close(p)
                return
            }
        }
        let lt = pcap_datalink(p)
        store.beginLive(linkType: lt)
        let session = store.liveSession
        kernelDropped = 0
        interfaceName = interface
        runningPromiscuous = promiscuous
        runningFilter = bpfFilter

        runID += 1
        let run = runID
        let h = PcapHandle(p)
        handle = h
        let gate = BacklogGate(slots: CaptureReader.backlogSlots)
        let store = self.store
        let reader = CaptureReader(handle: h, linkType: lt, deliver: { batch in
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    // Session, not run: the final batch of a stopped run still lands, but
                    // nothing from it lands after a restart or a file load.
                    store.ingestLive(batch, session: session)
                    let lost = gate.leave()
                    if lost > 0, session == store.liveSession { store.addKernelDrops(lost) }
                }
            }
        }, stats: { [weak self] drops in
            DispatchQueue.main.async {
                guard let self, self.runID == run else { return }
                // pcap_stats counts are absolute (and 32-bit): hand the store the increase.
                let delta = Self.dropIncrease(from: self.kernelDropped, to: drops)
                self.kernelDropped = drops
                self.store.addKernelDrops(delta)
            }
        }, finalStats: { [weak self] drops in
            // The run's last reading, taken after Stop (its regular readings are ignored once
            // Stop has moved `runID` on): drops since the last one that counted. Nothing once
            // another run, a file or a restart has replaced this capture's packets.
            DispatchQueue.main.async {
                guard let self, session == self.store.liveSession, self.store.fileURL == nil else { return }
                let delta = Self.dropIncrease(from: self.kernelDropped, to: drops)
                self.kernelDropped = drops
                self.store.addKernelDrops(delta)
            }
        }, failed: { [weak self] message in
            DispatchQueue.main.async {
                guard let self, self.runID == run else { return }
                self.lastError = "Capture on \(interface) stopped: \(message)"
                self.stop()
            }
        }, gate: gate)
        self.reader = reader
        reader.start()
        isRunning = true
    }

    /// The drops since the last reading. `ps_drop` is a 32-bit counter: a SPAN port dropping
    /// at line rate for days wraps it, and the increase is then counted across the wrap (a
    /// plain difference would be negative and lose every drop until the next reading).
    nonisolated static func dropIncrease(from old: Int, to new: Int) -> Int {
        if new >= old { return new - old }
        let wrap = 1 << 32
        return old < wrap && new < wrap ? new + wrap - old : new
    }

    /// Break the read loop and wait (≤ 2 s; normally ≤ one 100 ms read timeout) for the thread,
    /// which closes the handle on its way out. Safe to call twice or when not running.
    func stop() {
        guard let handle else { isRunning = false; return }
        runID += 1              // late stats / failure callbacks of this run are ignored
        handle.breakLoop()
        reader?.requestStop()
        reader?.join(timeout: 2)
        self.handle = nil
        reader = nil
        isRunning = false
    }
}

/// Seconds on a clock that a changed system time (NTP step, the user setting the clock, a
/// time-zone change is harmless anyway) never moves, and that keeps counting through sleep
/// (`CLOCK_MONOTONIC_RAW` = `mach_continuous_time`). For every interval and deadline: on a wall
/// clock stepped back an hour, a live capture's batch (flushed "100 ms after the last flush")
/// and a walk's rows would wait that hour, and so would an SNMP request's timeout.
nonisolated enum Monotonic {
    static func now() -> Double { Double(clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)) / 1_000_000_000 }
}

/// `pcap_findalldevs` results, shared by every caller for `maxAge` seconds. The scan itself
/// runs outside the lock.
nonisolated final class InterfaceCache: Sendable {
    static let shared = InterfaceCache()
    private let state = Mutex<(value: [CaptureInterface], at: Double)>(([], -Double.infinity))

    func value(maxAge: Double, scan: () -> [CaptureInterface]) -> [CaptureInterface] {
        let cached: [CaptureInterface]? = state.withLock { s in
            let age = Monotonic.now() - s.at
            return age >= 0 && age < maxAge ? s.value : nil
        }
        if let cached { return cached }
        let fresh = scan()
        state.withLock { $0 = (fresh, Monotonic.now()) }
        return fresh
    }
}

/// The `pcap_t` shared between the main actor (break) and the read thread (read, stats, close).
nonisolated final class PcapHandle: Sendable {
    private let p: Mutex<OpaquePointer?>

    init(_ p: sending OpaquePointer) { self.p = Mutex(p) }

    /// The raw handle for the read loop. Valid until `close()`, which the read loop itself calls
    /// after its last use.
    var pointer: OpaquePointer? { p.withLock { $0 } }

    /// `pcap_breakloop` only sets a flag, so it is safe from any thread while the handle is open.
    func breakLoop() {
        p.withLock { if let h = $0 { pcap_breakloop(h) } }
    }

    /// Idempotent.
    func close() {
        p.withLock { h in
            if let h { pcap_close(h) }
            h = nil
        }
    }

    deinit { close() }
}

/// The blocking `pcap_next_ex` loop on its own `Thread`: copy, decode, batch (100 ms or
/// 2,000 packets), and report drops once a second. Owns the handle's closing.
nonisolated final class CaptureReader: Sendable {
    private let handle: PcapHandle
    private let linkType: Int32
    private let deliver: @Sendable ([Packet]) -> Void
    private let stats: @Sendable (Int) -> Void
    /// The drops once more after the loop has ended (the regular reading comes once a second:
    /// the drops of a run's last second were never counted).
    private let finalStats: (@Sendable (Int) -> Void)?
    private let failed: @Sendable (String) -> Void
    private let gate: BacklogGate?
    private let done = DispatchSemaphore(value: 0)
    private let stopping = Atomic(false)
    /// When Stop was asked for, in µs since 1970 (the clock BPF stamps packets with).
    private let stopMicros = Atomic(Int.max)
    /// The loop's clock (tests pass one they move by hand).
    private let clock: @Sendable () -> Double

    static let maxBatch = 2_000
    static let flushInterval: Double = 0.1
    /// After Stop the packets the kernel had already captured are read: those stamped up to
    /// `drainPast` after the moment of Stop (per-CPU stamps may be a little out of order), for
    /// at most `drainSeconds` of the thread's time (a 48 MB backlog of small packets under a
    /// sanitizer). `stop()` waits 2 s for it; what is read later still lands in the table.
    static let drainPast: Double = 0.05
    static let drainSeconds: Double = 10
    /// Batches that may wait for the main actor at once (100k packets/s while the main thread
    /// is busy for a few seconds would queue hundreds of MB of batches).
    static let backlogSlots = 32

    private static let running = Atomic(0)
    /// Read loops currently running (tests; a leak shows up here).
    static var activeCount: Int { running.load(ordering: .sequentiallyConsistent) }

    init(handle: PcapHandle, linkType: Int32,
         deliver: @escaping @Sendable ([Packet]) -> Void,
         stats: @escaping @Sendable (Int) -> Void,
         finalStats: (@Sendable (Int) -> Void)? = nil,
         failed: @escaping @Sendable (String) -> Void,
         gate: BacklogGate? = nil,
         clock: @escaping @Sendable () -> Double = Monotonic.now) {
        self.handle = handle
        self.linkType = linkType
        self.deliver = deliver
        self.stats = stats
        self.finalStats = finalStats
        self.failed = failed
        self.gate = gate
        self.clock = clock
    }

    /// Hands a batch on unless the consumer is `backlogSlots` batches behind (then it is
    /// dropped and counted by the gate).
    private func send(_ batch: [Packet]) {
        if let gate, !gate.tryEnter(count: batch.count) { return }
        deliver(batch)
    }

    /// The thread keeps the reader alive until the loop ends; the reader keeps no reference
    /// to the thread (no cycle).
    func start() {
        Self.running.add(1, ordering: .sequentiallyConsistent)
        let t = Thread { [self] in self.run() }
        t.name = "SheepLog.capture"
        t.qualityOfService = .userInitiated
        t.start()
    }

    func requestStop() {
        var tv = timeval()
        gettimeofday(&tv, nil)
        _ = stopMicros.compareExchange(expected: Int.max, desired: Int(tv.tv_sec) * 1_000_000 + Int(tv.tv_usec),
                                       ordering: .sequentiallyConsistent)
        stopping.store(true, ordering: .sequentiallyConsistent)
    }

    /// Wait for the loop to finish (after `requestStop` + `PcapHandle.breakLoop`, or the end
    /// of a file handle).
    func join(timeout: Double) {
        if done.wait(timeout: .now() + timeout) == .success { done.signal() }
    }

    private var isStopping: Bool { stopping.load(ordering: .sequentiallyConsistent) }

    private func run() {
        defer {
            handle.close()
            Self.running.subtract(1, ordering: .sequentiallyConsistent)
            done.signal()
        }
        guard let p = handle.pointer else { return }
        var batch: [Packet] = []
        batch.reserveCapacity(Self.maxBatch)
        var id = 0
        var first: Double?
        let clock = self.clock
        var lastFlush = clock()
        var lastStats = lastFlush
        var hdr: UnsafeMutablePointer<pcap_pkthdr>?
        var bytes: UnsafePointer<UInt8>?
        var failure: String?
        let linkType = self.linkType
        /// The packet `pcap_next_ex` just returned, into `batch`.
        func take(_ h: pcap_pkthdr, _ bytes: UnsafePointer<UInt8>) {
            id += 1
            let ts = Double(h.ts.tv_sec) + Double(h.ts.tv_usec) / 1_000_000
            if first == nil { first = ts }
            let caplen = Int(h.caplen)
            let raw = UnsafeRawBufferPointer(start: bytes, count: caplen)
            batch.append(Packet(id: id, timestamp: Date(timeIntervalSince1970: ts), relative: ts - (first ?? ts),
                                length: Int(h.len), captured: caplen, data: Data(raw),
                                decoded: PacketDecoder.decode(raw, linkType: linkType)))
        }
        loop: while !isStopping {
            let r = autoreleasepool { () -> Int32 in
                let r = pcap_next_ex(p, &hdr, &bytes)
                if r == 1, let h = hdr?.pointee, let bytes { take(h, bytes) }
                return r
            }
            if r == -2 { break }
            if r < 0 {
                failure = String(cString: pcap_geterr(p))
                break loop
            }
            let now = clock()
            // A clock that went backwards (never the monotonic one; a replaced one in tests)
            // counts as "time to flush", not as a wait until it catches up.
            let sinceFlush = now - lastFlush, sinceStats = now - lastStats
            if batch.count >= Self.maxBatch || (!batch.isEmpty && (sinceFlush >= Self.flushInterval || sinceFlush < 0)) {
                send(batch)
                batch = []
                batch.reserveCapacity(Self.maxBatch)
                lastFlush = now
            }
            if sinceStats >= 1 || sinceStats < 0 {
                lastStats = now
                var st = pcap_stat()
                if pcap_stats(p, &st) == 0 { stats(Int(st.ps_drop) + Int(st.ps_ifdrop)) }
            }
        }
        // Stopped: the packets the kernel captured before Stop are still in BPF's buffers (and
        // libpcap's). Left there they were gone without a trace — neither shown nor counted as
        // dropped (393 of a lo0 flood's last 266,000 in one run). Read without blocking up to
        // the first packet clearly stamped after the Stop.
        if failure == nil, isStopping {
            var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
            let stopAt = Double(stopMicros.load(ordering: .sequentiallyConsistent)) / 1_000_000
            let until = clock() + Self.drainSeconds
            var breaks = 0
            if pcap_setnonblock(p, 1, &errbuf) == 0 {
                drain: while clock() < until {
                    let r = autoreleasepool { () -> Int32 in
                        let r = pcap_next_ex(p, &hdr, &bytes)
                        guard r == 1, let h = hdr?.pointee, let bytes else { return r }
                        let ts = Double(h.ts.tv_sec) + Double(h.ts.tv_usec) / 1_000_000
                        if ts > stopAt + Self.drainPast { return 2 }
                        take(h, bytes)
                        return r
                    }
                    switch r {
                    case 1:
                        if batch.count >= Self.maxBatch {
                            send(batch)
                            batch = []
                            batch.reserveCapacity(Self.maxBatch)
                        }
                    case -2 where breaks == 0:
                        breaks += 1              // the break Stop asked for, still pending
                    default:
                        break drain              // empty (0), past the Stop (2), an error
                    }
                }
            }
        }
        if !batch.isEmpty { send(batch) }
        if let finalStats {
            var st = pcap_stat()
            if pcap_stats(p, &st) == 0 { finalStats(Int(st.ps_drop) + Int(st.ps_ifdrop)) }
        }
        if let failure, !isStopping { failed(failure) }
    }
}
