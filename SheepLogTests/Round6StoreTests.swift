import XCTest
@testable import SheepLog

/// Round 6: LogStore consistency under interleaved ingest / re-scan / eviction / vendor override /
/// severity mask / source / order / pause, checked against a fresh filter of `entries`.
@MainActor
final class Round6StoreTests: XCTestCase {
    /// SplitMix64: a seeded, reproducible sequence.
    struct Rng: RandomNumberGenerator {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x9E37_79B9_7F4A_7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
            z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
            return z ^ (z >> 31)
        }
    }

    static let addresses = (1...12).map { "10.60.0.\($0)" }

    /// One line of a random shape (Forti, Huawei, Other, a key=value line an override turns into
    /// Forti) with a random severity.
    static func rawLine(_ rng: inout Rng, address: String, n: Int) -> RawSyslog {
        let sev = Int.random(in: 0...7, using: &rng)
        let level = Severity(rawValue: Int.random(in: 0...7, using: &rng))!.name
        let text: String
        switch Int.random(in: 0...3, using: &rng) {
        case 0:
            text = "<\(184 + sev)>date=2026-09-23 time=10:15:32 devname=\"FGT-\(n % 5)\" devid=\"FGT60F\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"\(level)\" srcip=10.2.\(n % 250).5 action=\"deny\""
        case 1:
            text = "<\(184 + sev)>Sep 23 2026 10:15:32 HW-\(n % 5) %%01IFNET/\(Int.random(in: 0...7, using: &rng))/LINK_STATE(l)[\(n)]:The line protocol on port \(n % 48) went down."
        case 2:
            text = "<\(184 + sev)>Sep 23 10:15:32 host-\(n % 7) sshd[\(n)]: Failed password for admin port \(n % 9)"
        default:
            // Plain key=value text: Other by detection, FortiOS (severity from level=) when forced.
            text = "<\(184 + sev)>Sep 23 10:15:32 box-\(n % 3) app: level=\(level) type=traffic subtype=local msg=\"n\(n)\""
        }
        return RawSyslog(received: Date(), sourceAddress: address, sourcePort: 514, transport: .udp, text: text)
    }

    static let queries = ["", "sev:<=warn", "down", "host:10.60.0.1", "vendor:forti", "f:level=err OR huawei",
                          "-sshd", "type=traffic", "/port [0-9]$/", "host:box-*", "src:10.2.7.5", "(", "a OR"]

    /// Everything that must hold once the store has settled.
    private func checkInvariants(_ store: LogStore, _ where_: String, file: StaticString = #filePath, line: UInt = #line) {
        let f = LogFilter(query: store.query, source: store.selectedSource, mask: store.severityMask)
        let expected = store.entries.filter { f.matches($0) }.map(\.id)
        XCTAssertEqual(store.visible.map(\.id), expected, "visible ≠ filter(entries) \(where_)", file: file, line: line)
        var counts = Array(repeating: 0, count: 8)
        for e in store.entries { counts[e.severity.rawValue] += 1 }
        XCTAssertEqual(store.severityCounts, counts, "severityCounts \(where_)", file: file, line: line)
        XCTAssertEqual(store.entryBytes, store.entries.reduce(0) { $0 + LogStore.cost($1) }, "entryBytes \(where_)", file: file, line: line)
        XCTAssertEqual(Set(store.entries.map(\.id)).count, store.entries.count, "duplicate ids \(where_)", file: file, line: line)
        XCTAssertLessThanOrEqual(store.entries.count, max(1, store.limit), "over the limit \(where_)", file: file, line: line)
        // Rows ↔ sequence numbers ↔ entries agree in both orders.
        for row in [0, store.visibleCount / 2, store.visibleCount - 1] where row >= 0 && row < store.visibleCount {
            let seq = store.visibleSeq(atRow: row)
            XCTAssertNotNil(seq, file: file, line: line)
            if let seq { XCTAssertEqual(store.visibleRow(forSeq: seq), row, "row/seq \(where_)", file: file, line: line) }
            XCTAssertEqual(store.visibleRow(forID: store.visibleEntry(atRow: row).id), row, file: file, line: line)
        }
        // Every syslog line is what the parser makes of its raw text with the override in force now.
        for e in store.entries where e.transport != .trap {
            let want = SyslogParser.parse(RawSyslog(received: e.received, sourceAddress: e.sourceAddress, sourcePort: e.sourcePort,
                                                    transport: e.transport, text: e.raw),
                                          id: e.id, vendorOverride: store.vendorOverrides.get(e.sourceAddress))
            if want.vendor != e.vendor || want.severity != e.severity {
                XCTFail("line \(e.id) from \(e.sourceAddress) is \(e.vendor)/\(e.severity), override says \(want.vendor)/\(want.severity) \(where_)",
                        file: file, line: line)
                return
            }
        }
        // Per-source counters: every line received, each counted once.
        store.publishSources()
        let perSource = store.sources.reduce(0) { $0 + $1.count }
        XCTAssertEqual(perSource, store.totalReceived, "source counts \(where_)", file: file, line: line)
        for s in store.sources {
            XCTAssertEqual(s.bySeverity.reduce(0, +), s.count, "\(s.address) bySeverity \(where_)", file: file, line: line)
        }
    }

    func testRandomInterleavingsKeepVisibleConsistent() async {
        for seed: UInt64 in [1, 2, 3, 42, 2026] {
            await runInterleaving(seed: seed, steps: 400)
        }
    }

    private func runInterleaving(seed: UInt64, steps: Int) async {
        var rng = Rng(state: seed)
        let store = LogStore()
        store.limit = Int.random(in: 200...600, using: &rng)
        var n = 0
        var lastGeneration = store.generation
        /// Batches parsed (with the overrides of their moment) but not yet handed to the store —
        /// the listener's batch on its way to the main queue.
        var inFlight: [[LogEntry]] = []
        func batch(_ rng: inout Rng) -> [LogEntry] {
            let raws = (0..<Int.random(in: 1...40, using: &rng)).map { _ -> RawSyslog in
                n += 1
                return Self.rawLine(&rng, address: Self.addresses.randomElement(using: &rng)!, n: n)
            }
            return SyslogListener.parseBatch(raws, overrides: store.vendorOverrides.snapshot())
        }
        for step in 0..<steps {
            switch Int.random(in: 0...15, using: &rng) {
            case 0...3: store.ingest(batch(&rng))
            case 4: inFlight.append(batch(&rng))
            case 5: if !inFlight.isEmpty { store.ingest(inFlight.removeFirst()) }
            case 6:
                store.queryText = Self.queries.randomElement(using: &rng)!
                store.applyQueryText()
            case 7:
                store.severityMask = Set(Severity.allCases.filter { _ in Bool.random(using: &rng) || Bool.random(using: &rng) })
            case 8: store.selectedSource = Bool.random(using: &rng) ? nil : Self.addresses.randomElement(using: &rng)
            case 9: store.newestFirst.toggle()
            case 10:
                let v: Vendor? = [nil, .fortigate, .huawei, .unknown, .paloAlto].randomElement(using: &rng)!
                store.setVendorOverride(v, for: Self.addresses.randomElement(using: &rng)!)
            case 11: store.limit = Int.random(in: 100...600, using: &rng)
            case 12: store.paused.toggle()
            case 13: if Int.random(in: 0...9, using: &rng) == 0 { store.clear() }
            case 14: await Task.yield()
            default: await store.settle()
            }
            XCTAssertGreaterThanOrEqual(store.generation, lastGeneration, "generation went back (seed \(seed), step \(step))")
            lastGeneration = store.generation
            if step % 50 == 49, !store.paused, inFlight.isEmpty {
                await store.settle()
                checkInvariants(store, "seed \(seed) step \(step)")
            }
        }
        for b in inFlight { store.ingest(b) }
        store.paused = false
        await store.settle()
        checkInvariants(store, "seed \(seed) end")
    }

    // MARK: - Vendor override vs lines on their way

    private static let kvLine = "<190>Sep 23 10:15:32 box app: level=error type=traffic subtype=local msg=\"x\""

    func testOverrideReachesLinesHeldWhilePaused() async {
        let store = LogStore()
        store.paused = true
        store.ingest([parsedLine(Self.kvLine, from: "10.61.0.1", id: LogStore.nextID())])
        XCTAssertEqual(store.pausedCount, 1)
        store.setVendorOverride(.fortigate, for: "10.61.0.1")
        await store.settle()
        store.paused = false
        await store.settle()
        XCTAssertEqual(store.entries.first?.vendor, .fortigate, "a held line keeps the vendor of before the override")
        XCTAssertEqual(store.entries.first?.severity, .error)
        XCTAssertEqual(store.severityCounts[Severity.error.rawValue], 1)
    }

    func testOverrideReachesLinesParsedBeforeItWasSet() async {
        // The listener parsed a batch with the old overrides; the batch reaches the main actor
        // after the user picked a vendor (and after the re-parse of what was already there).
        let store = LogStore()
        // Received an hour "later" than the override change: the wall clock was stepped back since.
        let early = SyslogListener.parseBatch([RawSyslog(received: Date().addingTimeInterval(3_600), sourceAddress: "10.61.0.2", sourcePort: 514,
                                                         transport: .udp, text: Self.kvLine)],
                                              overrides: store.vendorOverrides.snapshot())
        XCTAssertEqual(early.first?.vendor, .unknown)
        store.setVendorOverride(.fortigate, for: "10.61.0.2")
        await store.settle()
        store.ingest(early)
        await store.settle()
        XCTAssertEqual(store.entries.first?.vendor, .fortigate)
        XCTAssertEqual(store.entries.first?.program, "traffic/local")
        // Clearing it goes back to detection for a batch parsed while it was set.
        let late = SyslogListener.parseBatch([RawSyslog(received: Date(), sourceAddress: "10.61.0.2", sourcePort: 514,
                                                        transport: .udp, text: Self.kvLine)],
                                             overrides: store.vendorOverrides.snapshot())
        XCTAssertEqual(late.first?.vendor, .fortigate)
        store.setVendorOverride(nil, for: "10.61.0.2")
        await store.settle()
        store.ingest(late)
        await store.settle()
        XCTAssertEqual(store.entries.map(\.vendor), [.unknown, .unknown])
    }

    func testReparseKeepsSourceSeverityCountsInStep() async {
        let store = LogStore()
        store.ingest((0..<5).map { _ in parsedLine(Self.kvLine, from: "10.61.0.3", id: LogStore.nextID()) })
        store.publishSources()
        XCTAssertEqual(store.sources.first?.bySeverity[Severity.info.rawValue], 5, "PRI 190 = local7.info")
        store.setVendorOverride(.fortigate, for: "10.61.0.3")
        await store.settle()
        store.publishSources()
        let s = store.sources.first { $0.address == "10.61.0.3" }
        XCTAssertEqual(s?.bySeverity[Severity.error.rawValue], 5, "level=error once FortiOS is forced")
        XCTAssertEqual(s?.errorCount, 5)
        XCTAssertEqual(s?.count, 5)
    }

    /// The Sources list is republished at most 0.25 s after a change whatever the wall clock
    /// did (a clock set back an hour after a publish made the old wait an hour).
    func testSourcesPublishWaitIsBoundedWhateverTheClockDid() async throws {
        XCTAssertEqual(LogStore.sourcesPublishDelay(sinceLast: -3_600), 0)
        XCTAssertEqual(LogStore.sourcesPublishDelay(sinceLast: 10), 0)
        XCTAssertEqual(LogStore.sourcesPublishDelay(sinceLast: 0.1), 0.15, accuracy: 1e-9)
        for s in stride(from: -5.0, through: 5.0, by: 0.05) {
            XCTAssertLessThanOrEqual(LogStore.sourcesPublishDelay(sinceLast: s), LogStore.sourcesPublishInterval)
        }
        let store = LogStore()
        store.ingest([parsedLine("<13>a", from: "10.63.0.1", id: LogStore.nextID())])
        store.ingest([parsedLine("<13>b", from: "10.63.0.2", id: LogStore.nextID())])
        try await Task.sleep(for: .milliseconds(400))
        XCTAssertEqual(store.sources.map(\.address), ["10.63.0.1", "10.63.0.2"])
    }

    /// Round 8: the throttle reads an injected clock. In production it is the monotonic one
    /// (seconds since boot, not since 2001 — a wall clock here is caught); a clock stepped back
    /// an hour right after a publish (what a wall clock does when NTP corrects it) must not
    /// hold the next publish for that hour.
    func testSourcesThrottleClockIsMonotonicAndAStepBackDoesNotFreezeIt() async throws {
        let store = LogStore()
        XCTAssertEqual(store.sourcesClock(), Monotonic.now(), accuracy: 1, "Sources is timed on the monotonic clock")
        XCTAssertGreaterThan(abs(store.sourcesClock() - Date().timeIntervalSinceReferenceDate), 86_400,
                             "not the wall clock")

        let clock = LockedBox(1_000.0)
        store.sourcesClock = { clock.value }
        store.ingest([parsedLine("<13>a", from: "10.64.0.1", id: LogStore.nextID())])
        XCTAssertEqual(store.sources.map(\.address), ["10.64.0.1"], "the first publish is immediate")
        clock.mutate { $0 = 1_000.1 }
        store.ingest([parsedLine("<13>b", from: "10.64.0.2", id: LogStore.nextID())])
        XCTAssertEqual(store.sources.count, 1, "100 ms after a publish: held for the rest of the 250 ms")
        try await Task.sleep(for: .milliseconds(300))
        XCTAssertEqual(store.sources.count, 2)
        // The injected clock says 10 s went by (really a few ms): published at once — the
        // throttle reads this clock, not one of its own.
        clock.mutate { $0 = 1_010 }
        store.ingest([parsedLine("<13>c", from: "10.64.0.3", id: LogStore.nextID())])
        XCTAssertEqual(store.sources.count, 3, "the throttle is timed on sourcesClock")
        // The clock goes back an hour after that publish.
        clock.mutate { $0 -= 3_600 }
        store.ingest([parsedLine("<13>d", from: "10.64.0.4", id: LogStore.nextID())])
        try await Task.sleep(for: .milliseconds(400))
        XCTAssertEqual(store.sources.map(\.address), ["10.64.0.1", "10.64.0.2", "10.64.0.3", "10.64.0.4"],
                       "a clock set back an hour must not freeze Sources")
    }

    // MARK: - Ids, rate

    func testIDsFromParallelListenersNeverCollide() {
        let got = LockedBox<[Int]>([])
        DispatchQueue.concurrentPerform(iterations: 8) { k in
            for _ in 0..<50 {
                let raws = (0..<(1 + k * 97 % 700)).map { i in
                    RawSyslog(received: Date(), sourceAddress: "10.62.0.\(k)", sourcePort: 514, transport: .udp, text: "<13>x \(i)")
                }
                let ids = SyslogListener.parseBatch(raws, overrides: [:]).map(\.id)
                got.mutate { $0.append(contentsOf: ids) }
            }
        }
        XCTAssertEqual(Set(got.value).count, got.value.count)
    }

    func testRateCountsHeldLinesOnceAcrossPauseAndResume() async throws {
        let store = LogStore()
        store.paused = true
        store.ingest((0..<30).map { _ in parsedLine("<13>held", id: LogStore.nextID()) })
        store.paused = false
        store.ingest((0..<20).map { _ in parsedLine("<13>live", id: LogStore.nextID()) })
        XCTAssertEqual(store.totalReceived, 50)
        XCTAssertEqual(store.entries.count, 50)
        try await Task.sleep(for: .milliseconds(1_150))
        XCTAssertEqual(store.rate, 50, accuracy: 0.001, "the resumed lines are not counted again")
    }
}

extension Round6StoreTests {
    /// `sev:warn,err` is any of the listed severities; `sev!=warn,err` none of them.
    @MainActor func testSeverityLists() async throws {
        let store = LogStore()
        store.ingest([parsedLine("<12>Sep 23 10:15:32 h app: w"),    // user.warning
                      parsedLine("<11>Sep 23 10:15:32 h app: e"),    // user.error
                      parsedLine("<14>Sep 23 10:15:32 h app: i")])   // user.info
        store.queryText = "sev:warn,err"; store.applyQueryText(); await store.settle()
        XCTAssertEqual(Set(store.visible.map(\.message)), ["w", "e"])
        store.queryText = "sev!=warn,err"; store.applyQueryText(); await store.settle()
        XCTAssertEqual(store.visible.map(\.message), ["i"])
    }
}
