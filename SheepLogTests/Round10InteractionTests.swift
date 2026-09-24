import AppKit
import SwiftUI
import XCTest
@testable import SheepLog

/// A TCP listener on 127.0.0.1 that accepts clients and reads until they close.
nonisolated final class LoopbackTCPServer: @unchecked Sendable {
    let port: UInt16
    private let fd: Int32
    private let stopped = LockedBox(false)

    init() throws {
        let s = socket(AF_INET, SOCK_STREAM, 0)
        var yes: Int32 = 1
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        let addr = TestSockets.address(0, loopback: true)
        guard TestSockets.withSockaddr(addr, { Darwin.bind(s, $0, $1) }) == 0, listen(s, 4) == 0 else {
            close(s)
            throw SNMPError.network("loopback listener")
        }
        fd = s
        port = TestSockets.boundPort(s)
        let stopped = self.stopped
        Thread {
            var p = pollfd(fd: s, events: Int16(POLLIN), revents: 0)
            while !stopped.value {
                guard poll(&p, 1, 50) > 0 else { continue }
                let c = accept(s, nil, nil)
                guard c >= 0 else { continue }
                var buf = [UInt8](repeating: 0, count: 4096)
                while !stopped.value, recv(c, &buf, buf.count, 0) > 0 {}
                close(c)
            }
            close(s)
        }.start()
    }

    func stop() { stopped.mutate { $0 = true } }
}

/// Round 10: scripted interaction sequences for what round 9 left (vendor override × Show ×
/// counts × Export × disk; Status "Show" while paused; Export racing Clear / a limit change /
/// eviction; MIB remove / reload / replace while traps arrive; Flows re-analysis during a live
/// capture) plus a sweep of other sequences — and the round's regressions.
@MainActor
final class Round10InteractionTests: XCTestCase {
    private var windows: [NSWindow] = []
    private var cleanup: [URL] = []

    override func tearDown() async throws {
        for w in windows { w.close() }
        windows = []
        for u in cleanup { try? FileManager.default.removeItem(at: u) }
        cleanup = []
    }

    // MARK: - Harness (the round-9 grid, plus counters)

    private final class SelectionBox { var id: Int? }

    private struct Grid {
        let coordinator: LogTableView.Coordinator
        let table: LogNSTableView
        let box: SelectionBox
    }

    private func grid(_ store: LogStore) -> Grid {
        let box = SelectionBox()
        let binding = Binding<Int?>(get: { box.id }, set: { box.id = $0 })
        let c = LogTableView.Coordinator(store: store)
        c.parent = LogTableView(store: store, selectedID: binding)
        let scroll = LogTableView.makeScrollView(coordinator: c)
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1000, height: 500), styleMask: [.titled], backing: .buffered, defer: false)
        w.isReleasedWhenClosed = false
        scroll.frame = NSRect(x: 0, y: 0, width: 1000, height: 500)
        w.contentView = scroll
        w.layoutIfNeeded()
        windows.append(w)
        return Grid(coordinator: c, table: scroll.documentView as! LogNSTableView, box: box)
    }

    private func settle(_ store: LogStore, _ g: Grid) async {
        await store.settle()
        g.coordinator.sync(force: false)
        // Row shifts are throttled to ten a second (a deferred one is scheduled).
        try? await Task.sleep(for: .milliseconds(120))
        g.coordinator.sync(force: false)
    }

    private func tempDir(_ tag: String) -> URL {
        let u = FileManager.default.temporaryDirectory.appending(path: "SheepLogR10-\(tag)-\(UUID().uuidString)", directoryHint: .isDirectory)
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        cleanup.append(u)
        return u
    }

    private func waitUntil(_ timeout: Double = 5, _ condition: () -> Bool) async {
        let end = Date().addingTimeInterval(timeout)
        while !condition(), Date() < end { try? await Task.sleep(for: .milliseconds(10)) }
    }

    /// `visible` = a fresh filter of `entries`; the table's rows; selection vs inspector; the
    /// severity counters = the ring; every source's severities add up to its count.
    private func check(_ store: LogStore, _ g: Grid?, _ step: String, file: StaticString = #filePath, line: UInt = #line) {
        let f = LogFilter(query: store.query, source: store.selectedSource, mask: store.severityMask)
        XCTAssertEqual(store.visible.map(\.id), store.entries.filter { f.matches($0) }.map(\.id),
                       "visible ≠ filter(entries) \(step)", file: file, line: line)
        var counts = Array(repeating: 0, count: 8)
        for e in store.entries { counts[e.severity.rawValue] += 1 }
        XCTAssertEqual(store.severityCounts, counts, "severity counters \(step)", file: file, line: line)
        store.publishSources()
        for s in store.sources {
            XCTAssertEqual(s.bySeverity.reduce(0, +), s.count, "\(s.address) severities ≠ lines \(step)", file: file, line: line)
        }
        guard let g else { return }
        XCTAssertEqual(g.table.numberOfRows, store.visibleCount, "table rows \(step)", file: file, line: line)
        let selected = g.table.selectedRowIndexes
        if let id = g.box.id {
            XCTAssertNotNil(store.entry(id: id), "inspector on a line that left the ring \(step)", file: file, line: line)
            if let row = store.visibleRow(forID: id) {
                XCTAssertTrue(selected.contains(row), "inspector's line visible but not selected \(step)", file: file, line: line)
            } else {
                XCTAssertTrue(selected.isEmpty, "rows selected while the inspector's line is filtered out \(step)", file: file, line: line)
            }
        } else {
            XCTAssertTrue(selected.isEmpty, "rows selected with no inspector line \(step)", file: file, line: line)
        }
    }

    private static func diskLines(_ dir: URL) -> [String] {
        let files = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []
        return files.filter { $0.pathExtension == "log" }
            .flatMap { ((try? String(contentsOf: $0, encoding: .utf8)) ?? "").split(separator: "\n").map(String.init) }
    }

    /// A FortiGate event line (FortiOS detection: severity from level=, not the PRI).
    static let fortiLevels = ["error", "warning", "information", "critical", "notice"]
    static func forti(_ n: Int, tag: String = "r10") -> String {
        "<13>date=2026-09-24 time=10:00:\(String(format: "%02d", n % 60)) devname=\"FGT-A\" devid=\"FGT60F\" logid=\"0100032001\" "
            + "type=\"event\" subtype=\"system\" level=\"\(fortiLevels[n % fortiLevels.count])\" msg=\"\(tag) line \(n)\""
    }

    /// The count in `exportNote` ("Exported 1,204 lines to x.csv").
    private static func noteCount(_ note: String?) -> Int? {
        guard let note, note.hasPrefix("Exported ") else { return nil }
        return Int(note.dropFirst(9).prefix { $0.isNumber || $0 == "," }.filter(\.isNumber))
    }

    // MARK: - 1. Vendor override × Show × counts × Export × disk log

    func testVendorOverrideWithShowCountsExportAndDisk() async throws {
        let tmp = tempDir("override")
        let logs = tmp.appending(path: "logs", directoryHint: .isDirectory)
        let store = LogStore()
        let logger = DiskLogger(directory: logs)
        store.diskLogger = logger
        let fw = "10.9.7.1", other = "10.9.7.2"
        var raws: [String] = []
        // What a listener does: ids first, then the overrides of that moment.
        func batch(_ range: Range<Int>) -> [LogEntry] {
            range.map { n in
                let from = n % 3 == 2 ? other : fw
                let text = from == other ? "<11>Sep 24 10:00:00 sw1 app: r10 other \(n)" : Self.forti(n)
                raws.append(text)
                let id = LogStore.nextID()
                return parsedLine(text, from: from, id: id, vendor: store.vendorOverrides.get(from))
            }
        }
        store.ingest(batch(0..<300))
        let g = grid(store)
        await settle(store, g)
        XCTAssertTrue(store.entries.filter { $0.sourceAddress == fw }.allSatisfy { $0.vendor == .fortigate })

        // Sources "Show" on the firewall, a line selected.
        store.showSource(fw)
        await settle(store, g)
        check(store, g, "show")
        XCTAssertTrue(store.visible.allSatisfy { $0.sourceAddress == fw })
        g.table.selectRowIndexes(IndexSet(integer: 3), byExtendingSelection: false)
        let selectedID = try XCTUnwrap(g.box.id)

        // Paused, more lines held; then the vendor is forced to Other.
        store.paused = true
        store.ingest(batch(300..<360))
        XCTAssertEqual(store.pausedCount, 60)
        store.setVendorOverride(.unknown, for: fw)
        // The re-parse runs off the main actor: `visible` still holds the old versions now —
        // an Export snapshot taken at this moment (the old Export did) carried FortiOS.
        XCTAssertTrue(store.exportRows.contains { $0.vendor == .fortigate }, "the window the export must wait out")
        let csvURL = tmp.appending(path: "shown.csv")
        let failure = await store.export(to: csvURL, csv: true)
        XCTAssertNil(failure)
        let csv = try String(contentsOf: csvURL, encoding: .utf8)
        let rows = csv.components(separatedBy: "\r\n").dropFirst().filter { !$0.isEmpty }
        XCTAssertEqual(rows.count, store.visibleCount)
        XCTAssertEqual(Self.noteCount(store.exportNote), rows.count, store.exportNote ?? "no note")
        XCTAssertFalse(csv.contains(",Fortinet FortiOS,"), "the export kept the vendor from before the override")
        XCTAssertEqual(rows.filter { $0.contains(",Other,notice,") }.count, rows.count, "re-parsed vendor and severity (PRI 13)")
        await settle(store, g)
        check(store, g, "override while paused")
        XCTAssertTrue(store.visible.allSatisfy { $0.vendor == .unknown && $0.severity == .notice })
        XCTAssertEqual(g.box.id, selectedID, "the selected line stays selected across the re-parse")

        // Resume: the held lines are parsed again too, and counted again in their source.
        store.paused = false
        await settle(store, g)
        check(store, g, "resumed")
        let fwLines = store.entries.filter { $0.sourceAddress == fw }
        XCTAssertEqual(fwLines.count, 240)
        XCTAssertTrue(fwLines.allSatisfy { $0.vendor == .unknown && $0.severity == .notice })
        store.publishSources()
        let fwRow = try XCTUnwrap(store.sources.first { $0.address == fw })
        XCTAssertEqual(fwRow.vendor, .unknown)
        XCTAssertEqual(fwRow.bySeverity[Severity.notice.rawValue], 240, "\(fwRow.bySeverity)")
        XCTAssertEqual(store.detectedVendor(for: fw), .fortigate, "Auto still names what was detected")

        // The .log export: the raw lines as received, in display order.
        let logURL = tmp.appending(path: "shown.log")
        let exported = await store.export(to: logURL, csv: false)
        XCTAssertNil(exported)
        let text = try String(contentsOf: logURL, encoding: .utf8).split(separator: "\n").map(String.init)
        XCTAssertEqual(text, store.exportRows.map(\.raw))

        // Disk log: every line once, as received — an override re-parses, it never re-writes.
        logger.sync()
        let disk = Self.diskLines(logs)
        XCTAssertEqual(disk.count, raws.count, "lines on disk")
        for r in raws { XCTAssertEqual(disk.filter { $0.hasSuffix(" " + r) }.count, 1, r) }

        // Back to Auto: FortiOS again, severities from level=.
        store.setVendorOverride(nil, for: fw)
        await settle(store, g)
        check(store, g, "auto again")
        for e in store.entries where e.sourceAddress == fw {
            XCTAssertEqual(e.vendor, .fortigate)
            XCTAssertEqual(e.fields.first { $0.key == "level" }.flatMap { Severity.parse($0.value) }, e.severity,
                           "level= decides again: \(e.raw)")
        }
        // A filter on the vendor sees the change at once.
        store.queryText = "vendor:forti"
        store.applyQueryText()
        await settle(store, g)
        XCTAssertEqual(store.visibleCount, 240)
        store.setVendorOverride(.unknown, for: fw)
        let failure2 = await store.export(to: csvURL, csv: true)
        XCTAssertNil(failure2)
        XCTAssertEqual(Self.noteCount(store.exportNote), 0, "under vendor:forti nothing is left once the vendor is forced")
        await settle(store, g)
        check(store, g, "vendor filter after override")

        // Clear: an export says it wrote nothing; disk untouched.
        store.clear()
        await settle(store, g)
        let exported2 = await store.export(to: logURL, csv: false)
        XCTAssertNil(exported2)
        XCTAssertEqual(store.exportNote, "Exported 0 lines to shown.log")
        logger.sync()
        XCTAssertEqual(Self.diskLines(logs).count, raws.count)
        logger.retire()
    }

    // MARK: - 2. Status "Show" while paused → Resume → Clear

    func testStatusShowWhilePausedThenResumeThenClear() async throws {
        let store = LogStore()
        let a = "10.9.8.1", b = "10.9.8.2"
        store.ingest((0..<50).map { parsedLine("<11>Sep 24 10:00:00 swA app: a \($0)", from: a, id: LogStore.nextID()) })
        let g = grid(store)
        await settle(store, g)
        g.table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
        store.paused = true
        // B starts talking only after Pause; A goes on too.
        store.ingest((0..<40).map { parsedLine("<11>Sep 24 10:00:00 swB app: b \($0)", from: b, id: LogStore.nextID()) })
        store.ingest((50..<60).map { parsedLine("<11>Sep 24 10:00:00 swA app: a \($0)", from: a, id: LogStore.nextID()) })
        store.publishSources()
        XCTAssertEqual(store.sources.first { $0.address == b }?.count, 40, "Status / Sources count held lines")

        // Status ▸ Top talkers ▸ Show on B.
        store.showSource(b)
        await settle(store, g)
        check(store, g, "show B paused")
        XCTAssertEqual(store.visibleCount, 0)
        XCTAssertNotNil(g.box.id, "filtered out keeps the inspector on the line (only a line gone from the ring clears it)")
        let text = LogView.noMatchText(entries: store.entries.count, query: !store.query.isEmpty, source: store.selectedSource,
                                       masked: false, held: store.paused ? store.pausedCount : 0)
        XCTAssertTrue(text.contains("50 newer lines are waiting") && text.contains("Resume"), text)
        XCTAssertEqual(LogView.noMatchText(entries: 50, query: false, source: b, masked: false, held: 0),
                       "None of the 50 lines match source 10.9.8.2.")

        // Show on A: its lines from before Pause only.
        store.showSource(a)
        await settle(store, g)
        check(store, g, "show A paused")
        XCTAssertEqual(store.visibleCount, 50)
        store.showSource(b)
        await settle(store, g)

        // Resume: B's lines appear under the source filter; A's held ones join the ring.
        store.paused = false
        await settle(store, g)
        check(store, g, "resumed")
        XCTAssertEqual(store.visibleCount, 40)
        XCTAssertEqual(store.entries.count, 100)
        g.table.selectRowIndexes(IndexSet(integer: 5), byExtendingSelection: false)
        XCTAssertNotNil(g.box.id)

        // Clear: nothing shown, no inspector; the counters since launch stay.
        store.clear()
        await settle(store, g)
        check(store, g, "cleared")
        XCTAssertNil(g.box.id)
        XCTAssertEqual(store.selectedSource, b, "the source capsule stays")
        store.publishSources()
        XCTAssertEqual(store.sources.first { $0.address == b }?.count, 40)
        store.ingest([parsedLine("<11>Sep 24 10:00:00 swB app: after", from: b, id: LogStore.nextID())])
        await settle(store, g)
        check(store, g, "after clear")
        XCTAssertEqual(store.visibleCount, 1)
    }

    // MARK: - 3. Export racing Clear, a limit change and eviction

    func testExportRacingClearLimitChangeAndEviction() async throws {
        let tmp = tempDir("export")
        for variant in ["clear", "limit", "evict", "filter"] {
            for yields in [0, 1, 3, 8] {
                let tag = "\(variant) after \(yields) yields"
                let store = LogStore()
                store.newestFirst = false
                store.limit = 20_000
                var n = 0
                func lines(_ count: Int) -> [LogEntry] {
                    (0..<count).map { _ in
                        n += 1
                        return parsedLine("<11>Sep 24 10:00:00 sw app: r10exp \(n) end", from: "10.9.9.\(n % 4)", id: LogStore.nextID())
                    }
                }
                store.ingest(lines(20_000))
                let before = store.visibleCount
                let csv = yields % 2 == 1
                let url = tmp.appending(path: "\(variant)-\(yields).\(csv ? "csv" : "log")")
                let export = Task { await store.export(to: url, csv: csv) }
                for _ in 0..<yields { await Task.yield() }
                switch variant {
                case "clear": store.clear()
                case "limit": store.limit = 1_000
                case "evict": store.ingest(lines(15_000))                 // 10 % chunks roll out
                default:
                    store.queryText = "r10exp 1"
                    store.applyQueryText()                               // a re-scan in flight
                }
                let failure = await export.value
                XCTAssertNil(failure, tag)
                XCTAssertFalse(store.isExporting, tag)
                let written = try String(contentsOf: url, encoding: .utf8)
                    .components(separatedBy: csv ? "\r\n" : "\n").filter { !$0.isEmpty }
                let body = csv ? Array(written.dropFirst()) : written
                let count = try XCTUnwrap(Self.noteCount(store.exportNote), "\(tag): \(store.exportNote ?? "no note")")
                XCTAssertEqual(body.count, count, "\(tag): the note says what the file holds")
                XCTAssertTrue([before, store.visibleCount].contains(count), "\(tag): \(count) is neither snapshot (\(before) / \(store.visibleCount))")
                // One consistent snapshot: consecutive lines, no gap, no repeat.
                let numbers = body.compactMap { l -> Int? in
                    guard let r = l.range(of: "r10exp ") else { return nil }
                    return Int(l[r.upperBound...].prefix { $0.isNumber })
                }
                XCTAssertEqual(numbers.count, body.count, tag)
                if variant != "filter" {
                    XCTAssertTrue(zip(numbers, numbers.dropFirst()).allSatisfy { $1 == $0 + 1 }, "\(tag): not one snapshot")
                }
            }
        }
    }

    // MARK: - 4 & 6. MIBs removed / replaced while traps arrive

    private static let fortinetMIBs = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .appending(path: "Tests/mibs/fortinet", directoryHint: .isDirectory)

    /// fgTrapHaSwitch with fnSysSerial.0; `partial` adds a var-bind under fnSystem that no
    /// module defines (the trap stays "not fully named" and waits for a later import).
    private static func haTrap(_ n: Int, partial: Bool) -> ReceivedTrap {
        var vbs = [VarBind(OID([1, 3, 6, 1, 4, 1, 12356, 100, 1, 1, 1, 0]), .octetString(Data("FG\(n)".utf8)))]
        if partial { vbs.append(VarBind(OID([1, 3, 6, 1, 4, 1, 12356, 100, 1, 1, 99, 0]), .integer(Int64(n)))) }
        return .trap(SNMPTrap(received: Date(), sourceAddress: "10.0.0.1", sourcePort: 162, version: .v2c, community: "public",
                              trapOID: OID([1, 3, 6, 1, 4, 1, 12356, 101, 2, 0, 401]), uptime: 1, agentAddress: nil,
                              varBinds: vbs))
    }

    func testMIBRemovedAndReplacedWhileTrapsArrive() async throws {
        let tmp = tempDir("mibs")
        let store = LogStore()
        let receiver = TrapReceiver(store: store)
        let reg = MIBRegistry()
        reg.userFolderOverride = tmp.appending(path: "folder", directoryHint: .isDirectory)
        reg.loadNow(bundled: MIBRegistry.bundledURLs())
        receiver.registry = reg
        reg.importFiles([Self.fortinetMIBs])
        await waitUntil(20) { !reg.isLoading }
        func arrive(_ range: Range<Int>) { receiver.ingest(range.map { Self.haTrap($0, partial: $0 % 2 == 1) }) }
        func programs() -> [String] { store.entries.filter { $0.transport == .trap }.map(\.program) }
        func idle() async throws {
            await waitUntil(20) { !reg.isLoading }
            try await Task.sleep(for: .milliseconds(30))
            await store.settle()
        }
        let dotted = "fortinet.101.2.0.401"                            // FORTINET-CORE-MIB stays
        arrive(0..<2)
        XCTAssertEqual(programs(), ["fgTrapHaSwitch", "fgTrapHaSwitch"])

        // The module is removed while traps keep coming: the ones named from it keep their
        // names (fully named or not); later ones are dotted.
        let module = try XCTUnwrap(reg.modules.first { $0.name == "FORTINET-FORTIGATE-MIB" })
        reg.remove(module)
        arrive(2..<4)                                                   // still the old index
        try await idle()
        arrive(4..<6)
        try await idle()
        XCTAssertEqual(programs(), Array(repeating: "fgTrapHaSwitch", count: 4) + [dotted, dotted],
                       "old lines keep their names; new traps are dotted")

        // A new version of the module (the notification renamed) imported while traps arrive:
        // named lines stay as they are; the dotted ones are named in place; new ones by it.
        let renamedDir = tmp.appending(path: "renamed", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: renamedDir, withIntermediateDirectories: true)
        let original = try String(contentsOf: Self.fortinetMIBs.appending(path: "FORTINET-FORTIGATE-MIB.mib"), encoding: .utf8)
        try original.replacingOccurrences(of: "fgTrapHaSwitch", with: "fgTrapHaFailover")
            .write(to: renamedDir.appending(path: "FORTINET-FORTIGATE-MIB.mib"), atomically: true, encoding: .utf8)
        reg.importFiles([renamedDir])
        arrive(6..<8)                                                   // before its index
        try await idle()
        arrive(8..<10)
        try await idle()
        XCTAssertEqual(programs(), Array(repeating: "fgTrapHaSwitch", count: 4) + Array(repeating: "fgTrapHaFailover", count: 6))

        // A second import replacing that module again (the original back): the same rule.
        reg.importFiles([Self.fortinetMIBs])
        arrive(10..<12)
        try await idle()
        arrive(12..<14)
        try await idle()
        XCTAssertEqual(programs(), Array(repeating: "fgTrapHaSwitch", count: 4) + Array(repeating: "fgTrapHaFailover", count: 6)
                       + ["fgTrapHaFailover", "fgTrapHaFailover", "fgTrapHaSwitch", "fgTrapHaSwitch"])
        XCTAssertEqual(reg.modules.filter { $0.name == "FORTINET-FORTIGATE-MIB" }.count, 1)
        // The table and the counters follow.
        XCTAssertEqual(store.visible.map(\.program), store.entries.map(\.program))
        check(store, nil, "after the imports")
    }

    /// Reload (MIBs ▸ Reload) during a walk in the Test pane: every row named, none twice.
    func testMIBReloadDuringAWalk() async throws {
        let base = OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 2])                  // ifDescr
        let mib = (1...1_500).map { VarBind(base.appending(UInt32($0)), .octetString(Data("port \($0)".utf8))) }
        let agent = try FakeAgent(mib: mib)
        agent.bulkCap = 5
        let m = SNMPTestModel.shared
        let saved = (m.host, m.port, m.credentials, m.oidText)
        defer {
            agent.stop()
            m.host = saved.0; m.port = saved.1; m.applyCredentials(saved.2); m.oidText = saved.3
            let account = "127.0.0.1:\(agent.port)"
            SNMPTestModel.keychainQueue.async { KeychainStore.delete(account: account) }
        }
        m.setTarget("127.0.0.1:\(agent.port)")
        m.version = .v2c
        m.community = "public"
        m.timeout = 2
        m.walk(base)
        await waitUntil(5) { m.rows.count > 50 }
        MIBRegistry.shared.reload()
        await waitUntil(30) { !m.isRunning && !MIBRegistry.shared.isLoading }
        XCTAssertFalse(m.isRunning)
        XCTAssertEqual(m.rows.count, 1_500, m.heading)
        XCTAssertEqual(Set(m.rows.map(\.oid)).count, 1_500, "a row twice")
        XCTAssertEqual(Set(m.rows.map(\.id)).count, 1_500)
        XCTAssertTrue(m.rows.allSatisfy { $0.name.hasPrefix("ifDescr.") }, m.rows.first { !$0.name.hasPrefix("ifDescr.") }?.name ?? "")
    }

    // MARK: - 5. Flows: selection and ladder event across re-analyses (ring eviction)

    /// A long conversation (spaced data exchanges: one ladder event each) after a short one.
    private static func conversations() -> [Packet] {
        var a = TCPFlowDemo.Script(firstID: 1, offset: 0, client: "10.1.0.5", clientPort: 50_000, server: "10.2.0.1", serverPort: 443)
        a.handshake(rtt: 0.01)
        a.c(0.02, [.psh, .ack], len: 100)
        a.s(0.03, [.psh, .ack], len: 200)
        a.c(0.04, [.fin, .ack]); a.s(0.05, [.fin, .ack]); a.c(0.06, .ack)
        var b = TCPFlowDemo.Script(firstID: a.nextID, offset: 0.1, client: "10.1.0.5", clientPort: 50_001, server: "10.2.0.2", serverPort: 443)
        b.handshake(rtt: 0.01)
        for k in 0..<20 {
            let t = 0.1 + Double(k) * 0.3
            b.c(t, [.psh, .ack], len: 100 + k)
            b.s(t + 0.02, [.psh, .ack], len: 1_000 + k)
            b.c(t + 0.04, .ack)
        }
        return (a.packets + b.packets).sorted { $0.timestamp == $1.timestamp ? $0.id < $1.id : $0.timestamp < $1.timestamp }
    }

    func testFlowSelectionAndEventSurviveReanalysisWithEviction() throws {
        let all = Self.conversations()
        let flows1 = TCPFlowAnalyzer.analyze(all)
        XCTAssertEqual(flows1.count, 2)
        let long = try XCTUnwrap(flows1.first { $0.serverPort == 443 && $0.server == "10.2.0.2" })
        var state = FlowSelectionState()
        state.selection = long.id
        state.selectionChanged(in: flows1)
        let chosen = long.events[12]
        state.event = chosen.id

        // The ring evicts the short conversation and the long one's first frames.
        let firstKept = long.firstPacketID + 10
        let kept = all.filter { $0.id >= firstKept }
        let flows2 = TCPFlowAnalyzer.analyze(kept)
        let before = state.selection
        state.apply(flows2, previous: flows1)
        if state.selection != before { state.selectionChanged(in: flows2) }
        let flow = try XCTUnwrap(flows2.first { $0.id == state.selection }, "the conversation was lost")
        XCTAssertEqual(flow.key, long.key)
        let event = try XCTUnwrap(flow.events.first { $0.id == state.event }, "the ladder event was lost")
        XCTAssertEqual(event.packetIDs, chosen.packetIDs, "the ladder shows another event's frames")
        // What the integer id alone would have shown after the eviction.
        XCTAssertNotEqual(flow.events.first { $0.id == chosen.id }?.packetIDs, chosen.packetIDs,
                          "the sequence must move the events (else it tests nothing)")

        // "Show packets" on it: exactly its frames in Packets.
        let store = PacketStore()
        store.ingest(kept)
        store.queryText = FlowView.packetFilter(event.packetIDs, flow: flow)
        store.applyQueryNow(synchronous: true)
        XCTAssertEqual(store.visible.map(\.id), event.packetIDs)

        // The event's own frames evicted too: no event rather than another one.
        let kept3 = all.filter { $0.id > chosen.packetIDs.max()! }
        let flows3 = TCPFlowAnalyzer.analyze(kept3)
        state.apply(flows3, previous: flows2)
        XCTAssertNotNil(flows3.first { $0.id == state.selection }, "\(String(describing: state.selection)) \(flows3.map(\.id)) \(String(describing: state.key)) \(flows3.map(\.key))")
        XCTAssertNil(state.event)

        // "Follow TCP stream" on a frame whose conversation left the ring: not kept waiting
        // (it would jump to whatever reuses that 4-tuple later).
        let short = try XCTUnwrap(flows1.first { $0.server == "10.2.0.1" })
        state.pendingRequest = FlowSelectRequest(key: short.key, packetID: short.firstPacketID)
        let sel = state.selection
        state.apply(flows3, previous: flows3)
        XCTAssertNil(state.pendingRequest)
        XCTAssertEqual(state.selection, sel)
        // A frame newer than the analysis waits for the next one.
        state.pendingRequest = FlowSelectRequest(key: FlowKey("10.1.0.5", 50_002, "10.2.0.3", 443, proto: 6),
                                                 packetID: (all.map(\.id).max() ?? 0) + 5)
        state.apply(TCPFlowAnalyzer.analyze(kept3), previous: flows3)
        XCTAssertNotNil(state.pendingRequest)
    }

    /// A live lo0 capture of a TCP conversation while the Packets filter changes and the flows
    /// are re-analysed: the analysis ignores the filter, the selection stays on the
    /// conversation, "Show packets" gives exactly the event's frames.
    func testFlowsReanalysedDuringALiveCaptureWhileTheFilterChanges() async throws {
        try XCTSkipUnless(FileManager.default.isReadableFile(atPath: "/dev/bpf0"), "no /dev/bpf access")
        let model = AppModel.shared
        let packets = model.packets
        let saved = model.settings
        let server = try LoopbackTCPServer()
        defer {
            server.stop()
            model.capture.stop()
            model.settings = saved
            model.dismissAllErrors()
            packets.queryText = ""
            packets.applyQueryNow(synchronous: true)
            packets.clear()
        }
        packets.clear()
        model.settings.captureInterface = "lo0"
        model.settings.captureFilter = "tcp port \(server.port)"
        model.startCapture()
        model.dismissAllErrors()
        XCTAssertTrue(model.capture.isRunning, model.capture.lastError ?? "")
        let stop = LockedBox(false)
        let port = server.port
        let client = Thread {
            guard let fd = TestSockets.connectTCP(port) else { return }
            var k = 0
            while !stop.value {
                k += 1
                let b = Array("r10 flow \(k)\n".utf8)
                _ = b.withUnsafeBytes { Darwin.send(fd, $0.baseAddress, b.count, 0) }
                usleep(20_000)
            }
            close(fd)
        }
        client.start()
        await waitUntil(5) { packets.packets.count > 20 }
        var state = FlowSelectionState()
        var previous: [TCPFlow] = []
        let filters = ["tcp", "port:\(port)", "flags:psh", "\"unfinished", "", "NOT tcp", "len:>60"]
        for round in 0..<8 {
            packets.queryText = filters[round % filters.count]
            packets.applyQueryNow()
            let snapshot = packets.packets
            let flows = await Task.detached { TCPFlowAnalyzer.analyze(snapshot) }.value
            let before = state.selection
            state.apply(flows, previous: previous)
            if state.selection != before { state.selectionChanged(in: flows) }
            if state.selection == nil, let f = flows.first(where: { $0.serverPort == port }) {
                state.selection = f.id
                state.selectionChanged(in: flows)
                state.event = f.events.count > 3 ? f.events[3].id : nil
            }
            previous = flows
            let flow = try XCTUnwrap(flows.first { $0.id == state.selection }, "round \(round)")
            XCTAssertEqual(flow.serverPort, port, "round \(round)")
            XCTAssertEqual(flows.count, TCPFlowAnalyzer.analyze(snapshot).count, "the filter does not change the analysis")
            if let id = state.event {
                let event = try XCTUnwrap(flow.events.first { $0.id == id }, "round \(round): a stale event id")
                // Show packets during the next re-analysis.
                let filter = FlowView.packetFilter(event.packetIDs, flow: flow)
                NotificationCenter.default.post(name: .sheepLogPacketFilter, object: filter)
                XCTAssertEqual(packets.queryText, filter)
                await waitUntil {
                    let m = packets.query.isEmpty ? nil : PacketMatcher(packets.query)
                    return packets.visible.map(\.id) == PacketStore.filter(packets.packets, with: m).map(\.id)
                }
                XCTAssertEqual(Set(packets.visible.map(\.id)), Set(event.packetIDs.filter { packets.contains(id: $0) }), "round \(round)")
            }
            try await Task.sleep(for: .milliseconds(120))
        }
        stop.mutate { $0 = true }
    }

    // MARK: - 7. Sweep

    /// Newest first toggled while a filter re-scan is still running.
    func testNewestFirstToggledWhileARescanIsInFlight() async throws {
        let store = LogStore()
        store.ingest((0..<60_000).map { parsedLine("<\($0 % 8 + 8)>Sep 24 10:00:00 sw app: r10 \($0)", from: "10.9.1.\($0 % 5)", id: LogStore.nextID()) })
        let g = grid(store)
        await settle(store, g)
        g.table.selectRowIndexes(IndexSet(integer: 2), byExtendingSelection: false)
        for (k, q) in ["sev:err", "sev:<=warn host:10.9.1.3", "r10 1", "", "NOT host:10.9.1.0"].enumerated() {
            store.queryText = q
            store.applyQueryText()
            store.newestFirst.toggle()                  // while the re-scan runs
            g.coordinator.sync(force: false)
            if k % 2 == 0 { store.newestFirst.toggle() }
            store.ingest((0..<500).map { parsedLine("<11>Sep 24 10:00:00 sw app: late \(k) \($0)", from: "10.9.1.3", id: LogStore.nextID()) })
            await settle(store, g)
            check(store, g, "[\(q)] newest first \(store.newestFirst)")
            if store.visibleCount > 0 {
                let first = store.visibleEntry(atRow: 0).id, last = store.visibleEntry(atRow: store.visibleCount - 1).id
                XCTAssertEqual(first < last, !store.newestFirst, q)
                g.table.selectRowIndexes(IndexSet(integer: min(3, store.visibleCount - 1)), byExtendingSelection: false)
            }
        }
    }

    /// Pause → the buffer limit lowered → Resume.
    func testPauseThenLimitLoweredThenResume() async throws {
        let store = LogStore()
        func lines(_ r: Range<Int>) -> [LogEntry] {
            r.map { parsedLine("<\($0 % 8 + 8)>Sep 24 10:00:00 sw app: r10 \($0)", from: "10.9.2.\($0 % 3)", id: LogStore.nextID()) }
        }
        store.ingest(lines(0..<5_000))
        let g = grid(store)
        store.showSource("10.9.2.1")
        await settle(store, g)
        g.table.selectRowIndexes(IndexSet(integer: store.visibleCount - 1), byExtendingSelection: false)   // the oldest line
        store.paused = true
        store.ingest(lines(5_000..<8_000))
        store.limit = 1_000
        await settle(store, g)
        check(store, g, "limit lowered while paused")
        XCTAssertEqual(store.entries.count, 1_000)
        XCTAssertNil(g.box.id, "the inspector kept a line the limit threw out")
        store.paused = false
        await settle(store, g)
        check(store, g, "resumed")
        XCTAssertLessThanOrEqual(store.entries.count, 1_000)
        XCTAssertEqual(store.entries.last?.message, "r10 7999")
        XCTAssertEqual(store.totalReceived, 8_000)
        XCTAssertEqual(store.dropped, 8_000 - store.entries.count, "rolled out")
        XCTAssertEqual(store.lost, 0, "nothing was lost, only rolled out")
        store.publishSources()
        XCTAssertEqual(store.sources.map(\.count).reduce(0, +), 8_000)
    }

    /// Clear while a vendor re-parse is still running, lines arriving.
    func testClearWhileAVendorReparseIsInFlight() async throws {
        let store = LogStore()
        let fw = "10.9.3.1"
        store.ingest((0..<40_000).map { parsedLine(Self.forti($0), from: fw, id: LogStore.nextID()) })
        let g = grid(store)
        await settle(store, g)
        store.setVendorOverride(.unknown, for: fw)
        store.clear()
        store.ingest((0..<100).map { parsedLine(Self.forti($0, tag: "after"), from: fw, id: LogStore.nextID(), vendor: .unknown) })
        await settle(store, g)
        check(store, g, "cleared during the re-parse")
        XCTAssertEqual(store.entries.count, 100)
        XCTAssertTrue(store.entries.allSatisfy { $0.vendor == .unknown && $0.severity == .notice })
        store.publishSources()
        XCTAssertEqual(store.sources.first?.count, 40_100)
    }

    /// Interfaces on a v1 agent without ifXTable, then the same agent as v2c.
    func testInterfacesOnAV1AgentWithoutIfXTableThenV2c() async throws {
        var mib: [VarBind] = [VarBind(OID([1, 3, 6, 1, 2, 1, 1, 3, 0]), .timeTicks(900_000))]
        for col: UInt32 in [1, 2, 3, 5, 7, 8, 9, 10, 16] {
            for i: UInt32 in 1...3 {
                let v: SNMPValue
                switch col {
                case 2: v = .octetString(Data("eth\(i)".utf8))
                case 5: v = .gauge32(1_000_000_000)
                case 9: v = .timeTicks(100)
                case 10, 16: v = .counter32(4242 * i)
                default: v = .integer(Int64(col == 8 && i == 3 ? 2 : 1))
                }
                mib.append(VarBind(OID([1, 3, 6, 1, 2, 1, 2, 2, 1, col, i]), v))
            }
        }
        mib.sort { $0.oid < $1.oid }
        let agent = try FakeAgent(mib: mib)
        let m = SNMPTestModel.shared
        let saved = (m.host, m.port, m.credentials, m.oidText)
        defer {
            agent.stop()
            m.host = saved.0; m.port = saved.1; m.applyCredentials(saved.2); m.oidText = saved.3
            let account = "127.0.0.1:\(agent.port)"
            SNMPTestModel.keychainQueue.async { KeychainStore.delete(account: account) }
        }
        m.setTarget("127.0.0.1:\(agent.port)")
        m.community = "public"
        m.timeout = 1
        m.retries = 0
        for version in [SNMPVersion.v1, .v2c, .v1] {
            m.version = version
            m.walkInterfaces()
            await waitUntil(10) { !m.isRunning }
            XCTAssertEqual(m.interfaces.map(\.name), ["eth1", "eth2", "eth3"], "\(version): \(m.heading) \(m.subtitle)")
            XCTAssertTrue(m.subtitle.contains("ifTable only"), "\(version): \(m.subtitle)")
            XCTAssertEqual(m.resultView, .interfaces, "\(version)")
            if case .failure? = m.outcome { XCTFail("\(version): \(m.heading)") }
            XCTAssertEqual(m.interfaces.first { $0.index == 3 }?.oper, "down", "\(version)")
        }
    }

    /// A walk cancelled and at once restarted on another host: nothing of the first lands in
    /// the second's table.
    func testWalkCancelledAndRestartedOnAnotherHost() async throws {
        let base = OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 2])
        func agent(_ tag: String) throws -> FakeAgent {
            let a = try FakeAgent(mib: (1...800).map { VarBind(base.appending(UInt32($0)), .octetString(Data("\(tag)-\($0)".utf8))) })
            a.bulkCap = 4
            return a
        }
        let a = try agent("A"), b = try agent("B")
        let m = SNMPTestModel.shared
        let saved = (m.host, m.port, m.credentials, m.oidText)
        defer {
            a.stop(); b.stop()
            m.host = saved.0; m.port = saved.1; m.applyCredentials(saved.2); m.oidText = saved.3
            for p in [a.port, b.port] {
                let account = "127.0.0.1:\(p)"
                SNMPTestModel.keychainQueue.async { KeychainStore.delete(account: account) }
            }
        }
        m.version = .v2c
        m.community = "public"
        m.timeout = 2
        for delay in [0, 30, 150] {
            m.setTarget("127.0.0.1:\(a.port)")
            m.walk(base)
            try await Task.sleep(for: .milliseconds(delay))
            m.cancel()
            m.setTarget("127.0.0.1:\(b.port)")
            m.walk(base)
            await waitUntil(15) { !m.isRunning }
            try await Task.sleep(for: .milliseconds(250))            // late chunks from A's batcher
            XCTAssertEqual(m.rows.count, 800, "delay \(delay): \(m.heading)")
            XCTAssertTrue(m.rows.allSatisfy { $0.value.hasPrefix("B-") }, "delay \(delay): A's rows in B's table")
            XCTAssertTrue(m.heading.contains("127.0.0.1"), m.heading)
        }
    }

    /// The trap receiver stopped while a batch is on its way to the main actor, then started
    /// again on the same port.
    func testTrapReceiverStoppedWhileABatchIsNamed() async throws {
        let store = LogStore()
        let receiver = TrapReceiver(store: store)
        let port = TestSockets.freePort(SOCK_DGRAM)
        for cycle in 0..<3 {
            receiver.start(port: port)
            XCTAssertTrue(receiver.isRunning, receiver.lastError ?? "")
            let before = store.entries.count
            for k in 0..<300 { TestSockets.sendUDP(Round5TrapTests.linkDown(Int64(cycle * 1_000 + k)), to: port) }
            if cycle == 1 { try await Task.sleep(for: .milliseconds(5)) }      // a batch in the main queue
            receiver.stop()
            XCTAssertFalse(receiver.isRunning)
            try await Task.sleep(for: .milliseconds(300))
            let traps = store.entries.dropFirst(before)
            let markers = traps.compactMap { e -> Int? in
                guard let r = e.raw.range(of: "1.3.6.1.2.1.2.2.1.1.") else { return nil }
                return Int(e.raw[r.upperBound...].prefix { $0.isNumber })
            }
            XCTAssertEqual(Set(markers).count, markers.count, "cycle \(cycle): a trap twice")
            XCTAssertEqual(store.entries.filter { $0.transport == .trap }.count, receiver.trapCount, "cycle \(cycle)")
            XCTAssertTrue(traps.allSatisfy { $0.program == "linkDown" }, "cycle \(cycle)")
        }
        receiver.start(port: port)
        TestSockets.sendUDP(Round5TrapTests.linkDown(9_999), to: port)
        await waitUntil { store.entries.contains { $0.raw.contains("1.3.6.1.2.1.2.2.1.1.9999=") } }
        XCTAssertTrue(store.entries.contains { $0.raw.contains("1.3.6.1.2.1.2.2.1.1.9999=") })
        receiver.stop()
        check(store, nil, "traps")
    }

    // MARK: - Performance work (the Debug budgets the round-8 rewrite broke)

    /// The CSV export formats the time to the second once per second and appends the
    /// milliseconds: it must print exactly what `Format.stamp` prints, rounding included.
    func testStampWriterMatchesTheFormatter() {
        var rng = SystemRandomNumberGenerator()
        let base = Date().timeIntervalSinceReferenceDate
        var writer = LogStore.StampWriter()
        var mismatches: [String] = []
        for i in 0..<40_000 {
            let t: Double
            switch i % 5 {
            case 0: t = base + Double.random(in: -1e9...1e9, using: &rng)
            case 1: t = (base + Double(Int.random(in: -100_000...100_000, using: &rng))).rounded(.down) + 0.9995
                + Double.random(in: -0.0006...0.0006, using: &rng)
            case 2: t = (base + Double(Int.random(in: -100_000...100_000, using: &rng))).rounded(.down)
                + Double(Int.random(in: 0...999, using: &rng)) / 1000
            case 3: t = base + Double(i) / 1000           // consecutive lines, the cache's case
            default: t = Double(Int.random(in: -3_000_000_000...3_000_000_000, using: &rng)) + Double.random(in: 0..<1, using: &rng)
            }
            let d = Date(timeIntervalSinceReferenceDate: t)
            var out = ""
            writer.append(d, to: &out)
            let want = Format.stamp.string(from: d)
            if out != want, mismatches.count < 5 { mismatches.append("\(t): \(out) ≠ \(want)") }
        }
        XCTAssertEqual(mismatches, [])
    }

    /// The memchr CSV cell writer against the definition it replaced.
    func testCSVCellsMatchTheDefinition() {
        func reference(_ s: String) -> String {
            if let first = s.utf8.first, [0x3D, 0x2B, 0x2D, 0x40, 0x09, 0x0D].contains(first) { return reference("'" + s) }
            guard s.utf8.contains(where: { $0 == 0x2C || $0 == 0x22 || $0 == 0x0A || $0 == 0x0D }) else { return s }
            return "\"" + s.replacingOccurrences(of: "\"", with: "\"\"") + "\""
        }
        let cells = ["", "plain", "a,b", "\"", "\"\"", "say \"hi\"", "end\"", "\"start", "line\nbreak", "cr\rhere",
                     "=HYPERLINK(\"x\")", "+1", "-2", "@x", "\ttab", "\rcr", "ไทย,\"ภาษา\"", "emoji 🐑 \"q\" , x",
                     String(repeating: "\"a", count: 1000), "no special at all but long " + String(repeating: "x", count: 5000)]
        for c in cells {
            var out = "prefix,"
            Format.appendCSV(&out, c)
            XCTAssertEqual(out, "prefix," + reference(c), c.prefix(40).description)
        }
    }

    /// `TCPFlags` / `TCPSequenceAnalysis.Flags` concrete set operations = OptionSet's meaning.
    func testConcreteFlagOperations() {
        for a in 0...255 {
            for b in [0, 1, 2, 3, 0x10, 0x12, 0x18, 0xFF, a ^ 0x5A] {
                let x = TCPFlags(rawValue: UInt8(a)), y = TCPFlags(rawValue: UInt8(b))
                XCTAssertEqual(x.contains(y), a & b == b)
                XCTAssertEqual(x.isDisjoint(with: y), a & b == 0)
                XCTAssertEqual(x.subtracting(y).rawValue, UInt8(a & ~b & 0xFF))
                XCTAssertEqual(x.union(y).rawValue, UInt8(a | b))
                var z = x
                let r = z.insert(y)
                XCTAssertEqual(z.rawValue, UInt8(a | b))
                XCTAssertEqual(r.inserted, a & b != b)
                XCTAssertEqual(r.memberAfterInsert.rawValue, a & b == b ? UInt8(a & b) : UInt8(b))
                var w = x
                XCTAssertEqual(w.remove(y)?.rawValue, a & b == 0 ? nil : UInt8(a & b))
                XCTAssertEqual(w.rawValue, UInt8(a & ~b & 0xFF))
            }
        }
        XCTAssertEqual(([.syn, .ack] as TCPFlags).rawValue, 0x12)
        XCTAssertTrue(([] as TCPFlags).isEmpty)
        let resent = TCPSequenceAnalysis.Flags.resent
        XCTAssertEqual(resent.rawValue, 0b111_1000_0000)
        XCTAssertFalse(resent.isDisjoint(with: .outOfOrder))
        XCTAssertTrue(resent.isDisjoint(with: .dupAck))
    }
}
