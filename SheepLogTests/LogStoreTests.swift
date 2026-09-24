import Combine
import XCTest
@testable import SheepLog

@MainActor
final class LogStoreTests: XCTestCase {
    private static let base = Date(timeIntervalSince1970: 1_790_000_000)

    /// Synthetic lines parsed through the real parser: 20 sources, every severity, a mix of
    /// vendors; every 7th line mentions "port 1/1/24".
    private static func makeEntries(_ count: Int, startID: Int = 1) -> [LogEntry] {
        (0..<count).map { i in
            let sev = i % 8
            let pri = 23 * 8 + sev
            let host = "10.1.0.\(i % 20 + 1)"
            let text: String
            switch i % 4 {
            case 0: text = "<\(pri)>Sep 23 10:15:32 sw-\(i % 20) lldpd[\(i % 900)]: neighbor change on port 1/1/\(i % 7 == 0 ? 24 : i % 23) seq \(i)"
            case 1: text = "<\(pri)>date=2026-09-23 time=10:15:32 devname=\"FGT-\(i % 20)\" devid=\"FGT60F\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"\(Severity(rawValue: sev)!.name)\" srcip=10.2.\(i % 250).5 dstip=8.8.8.8 action=\"accept\" msg=\"port 1/1/\(i % 7 == 0 ? 24 : 3)\""
            case 2: text = "<\(pri)>Sep 23 2026 10:15:32 HW-\(i % 20) %%01IFNET/\(sev)/LINK_STATE(l)[\(i)]:The line protocol on port 1/1/\(i % 7 == 0 ? 24 : 5) went down."
            default: text = "<\(pri)>Sep 23 10:15:32 host-\(i % 20) sshd[\(i)]: Failed password for admin from 203.0.113.\(i % 250) port \(40000 + i % 20000) ssh2 \(i % 7 == 0 ? "port 1/1/24" : "")"
            }
            return parsedLine(text, from: host, received: base.addingTimeInterval(Double(i) / 1000), id: startID + i)
        }
    }

    private func ingest(_ store: LogStore, _ entries: [LogEntry], batch: Int = 2_000) {
        var i = 0
        while i < entries.count {
            store.ingest(Array(entries[i..<min(entries.count, i + batch)]))
            i += batch
        }
    }

    private func filter(_ store: LogStore, _ text: String) async {
        store.queryText = text
        store.applyQueryText()
        await store.settle()
    }

    // MARK: - Performance

    func testIngestAndRescan100k() async {
        let entries = Self.makeEntries(100_000)
        let store = LogStore()
        store.limit = 100_000

        let t0 = Date()
        ingest(store, entries)
        let ingestTime = Date().timeIntervalSince(t0)
        XCTAssertEqual(store.entries.count, 100_000)
        XCTAssertEqual(store.visible.count, 100_000)
        XCTAssertEqual(store.totalReceived, 100_000)

        let expected = entries.filter { $0.severity.rawValue <= 4 && $0.raw.lowercased().contains("port 1/1/24") }.count
        XCTAssertGreaterThan(expected, 1000)

        let t1 = Date()
        await filter(store, "sev:<=warn \"port 1/1/24\"")
        let rescanTime = Date().timeIntervalSince(t1)
        XCTAssertEqual(store.visible.count, expected)
        XCTAssertNil(store.queryError)

        // The raw scan alone, off the main actor's bookkeeping.
        let q = try! Query.parse("sev:<=warn \"port 1/1/24\"")
        let f = LogFilter(query: q, source: nil, mask: Set(Severity.allCases))
        let snap = store.entries
        let t2 = Date()
        let hits = LogStore.scan(snap, base: 0, filter: f)
        let scanTime = Date().timeIntervalSince(t2)
        XCTAssertEqual(hits?.hits.count, expected)

        print("[perf] ingest 100,000 lines in batches of 2,000: \(Int(ingestTime * 1000)) ms; full re-scan: \(Int(rescanTime * 1000)) ms (scan alone \(Int(scanTime * 1000)) ms, \(expected) hits)")
        XCTAssertWithinBudget(ingestTime, 2.0)
        XCTAssertWithinBudget(rescanTime, 0.3)

        // Incremental: new lines are filtered as they arrive.
        let more = Self.makeEntries(2_000, startID: 200_001)
        store.ingest(more)
        let expectedMore = more.filter { $0.severity.rawValue <= 4 && $0.raw.lowercased().contains("port 1/1/24") }.count
        XCTAssertEqual(store.visible.count, expected - store.visibleEvicted + expectedMore)
        XCTAssertTrue(store.visible.allSatisfy { $0.severity.rawValue <= 4 })
    }

    // MARK: - Ring

    func testRingEvictionDropsOldestTenPercent() {
        let store = LogStore()
        store.limit = 1_000
        let entries = Self.makeEntries(1_500)
        ingest(store, entries, batch: 100)
        // 1,100 > 1,000 → drop 200 (to 900); then 1,000 is not > 1,000; … 1,100 → 900 again, …
        XCTAssertLessThanOrEqual(store.entries.count, 1_000)
        XCTAssertEqual(store.dropped, 1_500 - store.entries.count)
        XCTAssertEqual(store.entries.first?.id, entries[1_500 - store.entries.count].id)
        XCTAssertEqual(store.entries.last?.id, entries.last?.id)
        XCTAssertEqual(store.severityCounts.reduce(0, +), store.entries.count)
        XCTAssertEqual(store.visible.map(\.id), store.entries.map(\.id))
        XCTAssertEqual(store.totalReceived, 1_500)
    }

    func testEvictionWithFilterKeepsVisibleConsistent() async {
        let store = LogStore()
        store.limit = 1_000
        await filter(store, "sev:err")
        ingest(store, Self.makeEntries(5_000), batch: 250)
        let expected = store.entries.filter { $0.severity == .error }.map(\.id)
        XCTAssertEqual(store.visible.map(\.id), expected)
    }

    // MARK: - Filter semantics

    func testSeverityComparisons() async {
        let store = LogStore()
        ingest(store, Self.makeEntries(800))
        await filter(store, "sev:<=warn")
        XCTAssertEqual(store.visible.count, 500)
        XCTAssertTrue(store.visible.allSatisfy { $0.severity.rawValue <= Severity.warning.rawValue })
        await filter(store, "sev:>=warn")
        XCTAssertEqual(store.visible.count, 400)
        XCTAssertTrue(store.visible.allSatisfy { $0.severity >= .warning })
        await filter(store, "sev:warning")
        XCTAssertEqual(store.visible.count, 100)
        await filter(store, "sev:<err")
        XCTAssertEqual(Set(store.visible.map(\.severity)), [.emergency, .alert, .critical])
        await filter(store, "sev:4")
        XCTAssertEqual(Set(store.visible.map(\.severity)), [.warning])
        await filter(store, "-sev:<=err")
        XCTAssertTrue(store.visible.allSatisfy { $0.severity > .error })
    }

    func testFieldKeys() async {
        let store = LogStore()
        let entries = Self.makeEntries(400)
        ingest(store, entries)
        await filter(store, "vendor:forti")
        XCTAssertEqual(store.visible.count, 100)
        await filter(store, "f:srcip=10.2.1.")
        XCTAssertEqual(store.visible.map(\.id), entries.filter { $0.field("srcip")?.hasPrefix("10.2.1.") == true }.map(\.id))
        await filter(store, "src:10.2.1.")
        XCTAssertEqual(store.visible.count, entries.filter { $0.field("srcip")?.hasPrefix("10.2.1.") == true }.count)
        // A complete address is exact ("Filter This Host" on 10.1.0.2 must not add 10.1.0.20);
        // the prefix form ends with the separator.
        await filter(store, "host:10.1.0.2")
        XCTAssertTrue(store.visible.allSatisfy { $0.sourceAddress == "10.1.0.2" })
        XCTAssertEqual(store.visible.count, 20)
        await filter(store, "-host:10.1.0.2")
        XCTAssertEqual(store.visible.count, 380)
        await filter(store, "host:10.1.0.")
        XCTAssertEqual(store.visible.count, 400)
        await filter(store, "app:sshd port:514 transport:udp")
        XCTAssertEqual(store.visible.count, 100)
        await filter(store, "program:IFNET msg:down")
        XCTAssertEqual(store.visible.count, 100)
        await filter(store, "failed OR /LINK_STATE\\(l\\)/")
        XCTAssertEqual(store.visible.count, 200)
        await filter(store, "(vendor:huawei OR vendor:forti) -\"port 1/1/24\"")
        XCTAssertTrue(store.visible.allSatisfy { !$0.raw.contains("port 1/1/24") && ($0.vendor == .huawei || $0.vendor == .fortigate) })
        await filter(store, "facility:local7")
        XCTAssertEqual(store.visible.count, 400)
    }

    func testSourceAndSeverityMask() async {
        let store = LogStore()
        ingest(store, Self.makeEntries(400))
        store.selectedSource = "10.1.0.3"
        await store.settle()
        XCTAssertEqual(store.visible.count, 20)
        store.severityMask = [.error]
        await store.settle()
        XCTAssertTrue(store.visible.allSatisfy { $0.severity == .error && $0.sourceAddress == "10.1.0.3" })
        store.selectedSource = nil
        store.severityMask = Set(Severity.allCases)
        await store.settle()
        XCTAssertEqual(store.visible.count, 400)
    }

    func testQueryErrorKeepsPreviousQuery() async {
        let store = LogStore()
        ingest(store, Self.makeEntries(80))
        await filter(store, "sev:err")
        XCTAssertEqual(store.visible.count, 10)
        await filter(store, "(unclosed")
        XCTAssertNotNil(store.queryError)
        XCTAssertEqual(store.visible.count, 10)
        XCTAssertEqual(store.query.source, "sev:err")
        await filter(store, "")
        XCTAssertNil(store.queryError)
        XCTAssertEqual(store.visible.count, 80)
    }

    // MARK: - Order, pause, sources

    func testNewestFirstRowMapping() {
        let store = LogStore()
        let entries = Self.makeEntries(10)
        ingest(store, entries)
        store.newestFirst = true
        XCTAssertEqual(store.visibleEntry(atRow: 0).id, entries.last!.id)
        XCTAssertEqual(store.visibleRow(forID: entries.first!.id), 9)
        store.newestFirst = false
        XCTAssertEqual(store.visibleEntry(atRow: 0).id, entries.first!.id)
        if let seq = store.visibleSeq(atRow: 3) { XCTAssertEqual(store.visibleRow(forSeq: seq), 3) } else { XCTFail() }
        XCTAssertEqual(store.visibleCount, 10)
        XCTAssertEqual(store.entry(id: entries[4].id)?.raw, entries[4].raw)
    }

    func testPauseQueuesAndResumeAppends() {
        let store = LogStore()
        store.paused = true
        ingest(store, Self.makeEntries(300), batch: 100)
        XCTAssertEqual(store.entries.count, 0)
        XCTAssertEqual(store.pausedCount, 300)
        XCTAssertEqual(store.totalReceived, 300)
        store.paused = false
        XCTAssertEqual(store.entries.count, 300)
        XCTAssertEqual(store.visible.count, 300)
        XCTAssertEqual(store.pausedCount, 0)
        XCTAssertEqual(store.dropped, 0)
    }

    func testSourcesCounters() {
        let store = LogStore()
        ingest(store, Self.makeEntries(400))
        store.publishSources()
        XCTAssertEqual(store.sources.count, 20)
        XCTAssertEqual(store.sources.map(\.address).prefix(3), ["10.1.0.1", "10.1.0.2", "10.1.0.3"], "numeric-aware order")
        XCTAssertEqual(store.sources.last?.address, "10.1.0.20")
        let s = store.sources[0]
        XCTAssertEqual(s.count, 20)
        XCTAssertEqual(s.bySeverity.reduce(0, +), 20)
        XCTAssertFalse(s.hostname.isEmpty)
    }

    // MARK: - Vendor override

    func testVendorOverrideReparses() async {
        let store = LogStore()
        let line = "<14>Sep 23 10:15:32 fw devname=FGT1 type=traffic subtype=forward level=error srcip=1.1.1.1"
        let batch = (0..<50).map { i in
            parsedLine(line, from: i % 2 == 0 ? "10.9.0.1" : "10.9.0.2", received: Self.base, id: 5_000 + i)
        }
        store.ingest(batch)
        XCTAssertTrue(store.entries.allSatisfy { $0.vendor == .unknown && $0.severity == .info })
        store.setVendorOverride(.fortigate, for: "10.9.0.1")
        XCTAssertEqual(store.vendorOverrides.get("10.9.0.1"), .fortigate)
        await store.settle()
        let one = store.entries.filter { $0.sourceAddress == "10.9.0.1" }
        let two = store.entries.filter { $0.sourceAddress == "10.9.0.2" }
        XCTAssertEqual(one.count, 25)
        XCTAssertTrue(one.allSatisfy { $0.vendor == .fortigate && $0.program == "traffic/forward" && $0.severity == .error })
        XCTAssertTrue(two.allSatisfy { $0.vendor == .unknown })
        XCTAssertEqual(store.entries.map(\.id), batch.map(\.id), "ids and order kept")
        XCTAssertEqual(store.severityCounts[Severity.error.rawValue], 25)
        XCTAssertEqual(store.sources.first { $0.address == "10.9.0.1" }?.vendorOverride, .fortigate)
        await filter(store, "vendor:forti")
        XCTAssertEqual(store.visible.count, 25)
        store.setVendorOverride(nil, for: "10.9.0.1")
        await store.settle()
        XCTAssertTrue(store.entries.allSatisfy { $0.vendor == .unknown })
    }

    // MARK: - Export

    func testExportCSVQuoting() {
        let store = LogStore()
        store.newestFirst = false
        store.ingest([parsedLine("<11>Sep 23 10:15:32 sw1 app: said \"hi\", then\nleft", received: Self.base)])
        let csv = store.exportCSV()
        let lines = csv.components(separatedBy: "\r\n")
        XCTAssertEqual(lines[0], "received,host,vendor,severity,facility,program,message,raw")
        XCTAssertTrue(lines[1].contains(",sw1,Other,error,user,app,\"said \"\"hi\"\", then\nleft\",\"<11>Sep 23"), lines[1])
        XCTAssertEqual(Format.csvField("plain"), "plain")
        XCTAssertEqual(Format.csvField("a,b"), "\"a,b\"")
        XCTAssertEqual(Format.csvField("q\"q"), "\"q\"\"q\"")
        // One entry per line in the .log export: the embedded line break is written as #012.
        XCTAssertEqual(store.exportText(), "<11>Sep 23 10:15:32 sw1 app: said \"hi\", then#012left\n")
        // Formula-looking cells are defused for spreadsheets.
        XCTAssertEqual(Format.csvField("=HYPERLINK(\"http://x\")"), "\"'=HYPERLINK(\"\"http://x\"\")\"")
        XCTAssertEqual(Format.csvField("+1"), "'+1")
        XCTAssertEqual(Format.csvField("@SUM(A1)"), "'@SUM(A1)")
    }

    func testDiskLoggerKeepsOneEntryPerLine() throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "sheeplog-test-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let logger = DiskLogger(directory: dir)
        logger.append([parsedLine("<13>Sep 23 10:15:32 h app: first\n2026-09-23T10:15:33 10.9.9.9 <9>forged\r\nline",
                                  from: "10.1.0.7", received: Self.base, transport: .tcp)])
        logger.close()
        let text = try String(contentsOf: try XCTUnwrap(logger.currentFile), encoding: .utf8)
        XCTAssertEqual(text.split(separator: "\n").count, 1, text)
        XCTAssertTrue(text.hasSuffix(" 10.1.0.7 <13>Sep 23 10:15:32 h app: first#0122026-09-23T10:15:33 10.9.9.9 <9>forged#015#012line\n"), text)
    }

    func testClear() {
        let store = LogStore()
        ingest(store, Self.makeEntries(100))
        let gen = store.generation
        store.clear()
        XCTAssertTrue(store.entries.isEmpty)
        XCTAssertTrue(store.visible.isEmpty)
        XCTAssertEqual(store.severityCounts.reduce(0, +), 0)
        XCTAssertGreaterThan(store.generation, gen)
        ingest(store, Self.makeEntries(10))
        XCTAssertEqual(store.visible.count, 10)
    }

    // MARK: - Adversarial review (each test pins a defect that was found and fixed)

    func testLoweringTheLimitTrimsImmediately() async {
        let store = LogStore()
        store.limit = 100_000
        let entries = Self.makeEntries(100_000)
        ingest(store, entries)
        await filter(store, "sev:<=warn")
        store.limit = 1_000
        XCTAssertEqual(store.entries.count, 1_000, "trimmed at once, not on the next batch")
        XCTAssertEqual(store.entries.last?.id, entries.last?.id)
        XCTAssertEqual(store.dropped, 99_000)
        XCTAssertEqual(store.severityCounts.reduce(0, +), 1_000)
        XCTAssertEqual(store.visible.map(\.id), store.entries.filter { $0.severity <= .warning }.map(\.id))
        XCTAssertEqual(store.totalReceived, store.entries.count + store.dropped, "no line lost at the ring level")
        // Nonsense limits do not crash.
        store.limit = 0
        XCTAssertEqual(store.entries.count, 1)
        store.limit = -5
        ingest(store, Self.makeEntries(10))
        XCTAssertEqual(store.entries.count, 1)
    }

    func testRowAccessOutOfRangeIsSafe() async {
        let store = LogStore()
        ingest(store, Self.makeEntries(100))
        let staleRow = store.visibleCount - 1           // what the table last saw
        await filter(store, "sev:err")                  // the filter shrinks `visible` under it
        XCTAssertNil(store.visibleEntryIfPresent(atRow: staleRow))
        XCTAssertNil(store.visibleEntryIfPresent(atRow: -1))
        XCTAssertEqual(store.visibleEntryIfPresent(atRow: 0)?.id, store.visibleEntry(atRow: 0).id)
    }

    func testSelectionOfAnEvictedLineIsReported() {
        let store = LogStore()
        store.limit = 100
        let entries = Self.makeEntries(100)
        ingest(store, entries)
        let seq = store.visibleSeq(atRow: store.visibleCount - 1)!   // newest first: the oldest line
        XCTAssertFalse(store.isEvicted(seq: seq))
        ingest(store, Self.makeEntries(50, startID: 1_000))
        XCTAssertTrue(store.isEvicted(seq: seq))
        XCTAssertNil(store.entry(id: entries[0].id))
    }

    func testOverridesOnTwoSourcesBothReparse() async {
        let store = LogStore()
        let line = "<14>Sep 23 10:15:32 fw devname=FGT1 type=traffic subtype=forward level=error srcip=1.1.1.1"
        let batch = (0..<40).map { i in
            parsedLine(line, from: i % 2 == 0 ? "10.9.0.1" : "10.9.0.2", received: Self.base, id: 7_000 + i)
        }
        store.ingest(batch)
        store.setVendorOverride(.fortigate, for: "10.9.0.1")
        store.setVendorOverride(.fortigate, for: "10.9.0.2")     // must not cancel the first re-parse
        await store.settle()
        XCTAssertTrue(store.entries.allSatisfy { $0.vendor == .fortigate }, "\(store.entries.map(\.vendor))")
    }

    func testStaleReparseDoesNotWin() async {
        let store = LogStore()
        let line = "<14>Sep 23 10:15:32 fw devname=FGT1 type=traffic subtype=forward level=error srcip=1.1.1.1"
        store.ingest((0..<5_000).map { i in
            parsedLine(line, from: "10.9.0.1", received: Self.base, id: 9_000 + i)
        })
        for _ in 0..<5 {
            store.setVendorOverride(.fortigate, for: "10.9.0.1")
            store.setVendorOverride(nil, for: "10.9.0.1")
        }
        await store.settle()
        try? await Task.sleep(for: .milliseconds(200))
        XCTAssertTrue(store.entries.allSatisfy { $0.vendor == .unknown })
        XCTAssertEqual(store.severityCounts.reduce(0, +), store.entries.count)
    }

    func testIncrementalLinesDuringAPendingRescanAreKept() async {
        let store = LogStore()
        store.limit = 50_000
        ingest(store, Self.makeEntries(40_000))
        store.queryText = "sev:err"
        store.applyQueryText()                 // full re-scan in flight …
        store.queryText = "sev:<=err"
        store.applyQueryText()                 // … superseded by a newer one
        let more = Self.makeEntries(20_000, startID: 100_000)   // arrives meanwhile, evicts the oldest
        ingest(store, more, batch: 1_000)
        await store.settle()
        XCTAssertEqual(store.visible.map(\.id), store.entries.filter { $0.severity <= .error }.map(\.id))
    }

    func testDottedFieldKeysAndOperatorsInValues() async {
        let store = LogStore()
        let cp = "<14>Sep 23 10:15:32 cppm01 CPPM_RADIUS_Logs 1 1 0 Common.Username=alice,Common.Service=Corp,Common.Login-Status=REJECT,Common.Note=a>=b"
        let e = parsedLine(cp, from: "10.1.1.1", received: Self.base)
        store.ingest([e] + Self.makeEntries(40, startID: 10))
        await filter(store, "f:Common.Username=ali")
        XCTAssertEqual(store.visible.map(\.id), [1])
        await filter(store, "f:common.note=a>=b")
        XCTAssertEqual(store.visible.map(\.id), [1], "the first operator splits key and value")
        await filter(store, "f:Common.Username!=alice vendor:clearpass")
        XCTAssertTrue(store.visible.isEmpty)
        await filter(store, "host:cppm")
        XCTAssertEqual(store.visible.map(\.id), [1], "host: prefix-matches the hostname too")
    }

    func testShowSourceClearsTheQuery() async {
        let store = LogStore()
        ingest(store, Self.makeEntries(400))
        await filter(store, "sev:err")
        store.showSource("10.1.0.3")
        await store.settle()
        XCTAssertEqual(store.queryText, "")
        XCTAssertEqual(store.visible.count, 20)
    }

    func testSourcesKeepNumericOrderAsNewOnesArrive() {
        let store = LogStore()
        for host in ["10.0.0.10", "10.0.0.2", "10.0.0.1", "10.0.0.100", "10.0.0.9"] {
            store.ingest([parsedLine("<13>x", from: host, received: Self.base, id: LogStore.nextID())])
        }
        store.publishSources()
        XCTAssertEqual(store.sources.map(\.address), ["10.0.0.1", "10.0.0.2", "10.0.0.9", "10.0.0.10", "10.0.0.100"])
    }

    func testExportOf100kLinesIsQuick() {
        let store = LogStore()
        store.newestFirst = false
        ingest(store, Self.makeEntries(100_000))
        let t0 = Date()
        let csv = store.exportCSV()
        let csvTime = Date().timeIntervalSince(t0)
        let t1 = Date()
        let text = store.exportText()
        let textTime = Date().timeIntervalSince(t1)
        print("[perf] export 100,000 lines: CSV \(Int(csvTime * 1000)) ms, text \(Int(textTime * 1000)) ms")
        XCTAssertEqual(csv.utf8.reduce(0) { $1 == 0x0A ? $0 + 1 : $0 }, 100_001)
        XCTAssertEqual(text.utf8.reduce(0) { $1 == 0x0A ? $0 + 1 : $0 }, 100_000)
        XCTAssertWithinBudget(csvTime, 0.6)
        // Same bytes as the per-row definition.
        let first = store.visible[0]
        XCTAssertTrue(csv.contains("\r\n" + Format.stamp.string(from: first.received) + ","), "stamp format kept")
    }

    func testTrapBatchPublishesOnce() {
        let store = LogStore()
        let traps = TrapReceiver(store: store)
        var sends = 0
        let sub = traps.objectWillChange.sink { sends += 1 }
        let now = Date()
        traps.ingest((0..<200).map { i in i % 4 == 0 ? .invalid : .v3(source: "10.0.0.\(i % 5)", port: 162, received: now) })
        sub.cancel()
        XCTAssertEqual(traps.v3Count, 150)
        XCTAssertEqual(traps.trapCount, 150)
        XCTAssertEqual(traps.invalidCount, 50)
        XCTAssertLessThanOrEqual(sends, 3, "one publish per counter per batch, not per trap")
        XCTAssertEqual(store.entries.count, 150)
    }

    func testParallelBatchParseKeepsOrderIdsAndOverrides() {
        let raws = (0..<3_000).map { i in
            RawSyslog(received: Self.base, sourceAddress: "10.1.0.\(i % 3)", sourcePort: 514, transport: .udp,
                      text: "<14>Sep 23 10:15:32 h\(i) app[\(i)]: line \(i) devname=F type=traffic subtype=fwd level=error logid=1 devid=x")
        }
        let out = SyslogListener.parseBatch(raws, overrides: ["10.1.0.1": .unknown])
        XCTAssertEqual(out.count, raws.count)
        XCTAssertEqual(out.map(\.raw), raws.map(\.text), "arrival order kept")
        XCTAssertEqual(Set(out.map(\.id)).count, raws.count)
        XCTAssertEqual(zip(out, out.dropFirst()).allSatisfy { $1.id == $0.id + 1 }, true, "consecutive ids")
        for (e, r) in zip(out, raws) {
            let serial = SyslogParser.parse(r, id: e.id, vendorOverride: r.sourceAddress == "10.1.0.1" ? .unknown : nil)
            XCTAssertEqual(e.vendor, serial.vendor)
            XCTAssertEqual(e.fields, serial.fields)
            XCTAssertEqual(e.hostname, serial.hostname)
        }
        XCTAssertEqual(out.filter { $0.vendor == .fortigate }.count, 2_000)
    }

    // MARK: - Listener lifecycle

    private static func openFDs() -> Int {
        (try? FileManager.default.contentsOfDirectory(atPath: "/dev/fd").count) ?? -1
    }

    func testSyslogListenerRestartLeaksNoDescriptors() {
        let port = TestSockets.freePort()
        let before = Self.openFDs()
        for _ in 0..<20 {
            guard case .success(let u) = SocketFactory.bind(type: SOCK_DGRAM, port: port),
                  case .success(let t) = SocketFactory.bind(type: SOCK_STREAM, port: port) else {
                return XCTFail("rebinding \(port) right after stop failed")
            }
            let l = SyslogListener(overrides: VendorOverrideMap(), deliver: { _ in }, clientsChanged: { _ in })
            l.start(udpFD: u, tcpFD: t)
            l.stop()
        }
        XCTAssertEqual(Self.openFDs(), before)
    }

    func testTrapListenerRebindsRightAfterCancel() throws {
        let port = TestSockets.freePort()
        let before = Self.openFDs()
        for _ in 0..<20 {
            let l = try TrapListener(port: port) { _ in }
            l.resume()
            l.cancel()
        }
        XCTAssertEqual(Self.openFDs(), before)
    }

    func testSyslogListenerSurvivesAClientWithoutNewlines() throws {
        let port = TestSockets.freePort()
        guard case .success(let t) = SocketFactory.bind(type: SOCK_STREAM, port: port) else { return XCTFail() }
        let got = LockedBox<[LogEntry]>([])
        let l = SyslogListener(overrides: VendorOverrideMap(), deliver: { b in got.mutate { $0 += b } },
                               clientsChanged: { _ in })
        l.start(udpFD: -1, tcpFD: t)
        defer { l.stop() }
        let fd = try XCTUnwrap(TestSockets.connectTCP(port))
        let junk = [UInt8](repeating: 0x41, count: 3 * 1024 * 1024)
        var sent = 0
        while sent < junk.count {
            let n = junk.withUnsafeBytes { send(fd, $0.baseAddress! + sent, junk.count - sent, 0) }
            guard n > 0 else { break }
            sent += n
        }
        let tail = Array("\n<13>Sep 23 10:15:32 h app: after the flood\n".utf8)
        _ = tail.withUnsafeBytes { send(fd, $0.baseAddress, tail.count, 0) }
        close(fd)
        let deadline = Date().addingTimeInterval(3)
        while Date() < deadline, got.value.isEmpty { usleep(20_000) }
        usleep(150_000)
        XCTAssertEqual(got.value.map(\.message), ["after the flood"])
    }

    // MARK: - Disk logger

    func testDiskLoggerWritesLines() throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "sheeplog-test-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let logger = DiskLogger(directory: dir)
        let entries = Self.makeEntries(3)
        logger.append(entries)
        logger.close()
        let file = try XCTUnwrap(logger.currentFile)
        XCTAssertEqual(file.lastPathComponent, "\(DiskLogger.dayString(Date())).log")
        let text = try String(contentsOf: file, encoding: .utf8)
        let lines = text.split(separator: "\n")
        XCTAssertEqual(lines.count, 3)
        XCTAssertTrue(lines[0].contains(" 10.1.0.1 <184>Sep 23"), String(lines[0]))
        XCTAssertTrue(lines[0].hasPrefix("20"))
        XCTAssertTrue(lines[0].prefix(24).contains("."), "milliseconds")
    }
}
