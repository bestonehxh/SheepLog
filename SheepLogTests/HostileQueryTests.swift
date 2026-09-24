import XCTest
@testable import SheepLog

/// Round 3: filters typed (or pasted) into the filter box are run against hostile lines. A
/// backtracking regular expression or a pathological query must never freeze the app.
@MainActor
final class HostileQueryTests: XCTestCase {
    private static func entries(_ texts: [String], source: String = "10.9.9.9") -> [LogEntry] {
        let first = LogStore.reserveIDs(texts.count)
        return texts.enumerated().map { i, t in
            parsedLine(t, from: source, id: first + i)
        }
    }

    /// `(a+)+$` against "aaaa…a!" is exponential in the run length for a backtracking engine:
    /// 26 a's is ~10^8 steps per line. A full re-scan of such lines must stop within ~1 s and
    /// say why, and the lines ingested afterwards (filtered on the main thread) must not hang.
    func testCatastrophicRegexIsStoppedWithinASecond() async {
        let store = LogStore()
        store.limit = 10_000
        let hostile = Self.entries((0..<40).map { i in "<13>Sep 23 10:15:32 h app: " + String(repeating: "a", count: 26 + i % 3) + "!" })
        let normal = Self.entries((0..<2_000).map { "<13>Sep 23 10:15:32 h app: line \($0) ok" })
        store.ingest(normal)
        store.ingest(hostile)
        let t0 = Date()
        store.queryText = "/(a+)+$/"
        store.applyQueryText()
        await store.settle()
        let rescan = Date().timeIntervalSince(t0)
        XCTAssertWithinBudget(rescan, 1.5, "the re-scan ran \(rescan) s")
        XCTAssertNotNil(store.queryError)
        XCTAssertTrue(store.queryError?.localizedCaseInsensitiveContains("slow") ?? false, store.queryError ?? "")
        XCTAssertTrue(store.queryErrorIsNotice, "the filter is applied; this is a notice, not a parse error")

        // New hostile lines arriving with the tripped filter are matched on the main actor.
        let t1 = Date()
        store.ingest(Self.entries((0..<500).map { _ in "<13>Sep 23 10:15:32 h app: " + String(repeating: "a", count: 30) + "!" }))
        XCTAssertWithinBudget(Date().timeIntervalSince(t1), 0.5)
    }

    /// A polynomial blow-up (no nested quantifier) on long lines: `.*.*.*=` against 16 KB of 'x'.
    func testPolynomialRegexOnLongLinesIsBounded() async {
        let store = LogStore()
        store.limit = 10_000
        store.ingest(Self.entries((0..<200).map { _ in "<13>Sep 23 10:15:32 h app: " + String(repeating: "x", count: 60_000) }))
        let t0 = Date()
        store.queryText = "/.*.*.*=/"
        store.applyQueryText()
        await store.settle()
        XCTAssertWithinBudget(Date().timeIntervalSince(t0), 2.0)
        XCTAssertEqual(store.visible.count, 0)
    }

    /// The guard must not change what an ordinary regex finds, and it must stay cheap.
    func testGuardedRegexMatchesLikeFirstMatch() {
        let lines = (0..<5_000).map { "Failed password for admin\($0 % 7) from 203.0.113.\($0 % 250) port \($0)" }
        for p in ["admin[35]", "203\\.0\\.113\\.1\\d\\b", "^failed", "port \\d{4}$", "(?i)ADMIN"] {
            let re = try! NSRegularExpression(pattern: p, options: [.caseInsensitive])
            let g = GuardedRegex(p)
            for s in lines {
                XCTAssertEqual(g.matches(s), re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil, "\(p) on \(s)")
            }
            XCTAssertFalse(g.tripped)
        }
    }

    /// Only the first 16 KB of a line are searched.
    func testRegexLooksAtTheFirst16KB() {
        let g = GuardedRegex("needle")
        XCTAssertTrue(g.matches(String(repeating: "x", count: 16_000) + "needle"))
        XCTAssertFalse(g.matches(String(repeating: "x", count: 70_000) + "needle"))
    }

    func testNestedQuantifierWarning() {
        XCTAssertNotNil(RegexLint.warning("(a+)+$"))
        XCTAssertNotNil(RegexLint.warning("(.*a){20}"))
        XCTAssertNotNil(RegexLint.warning("(x|x)*y"))
        XCTAssertNotNil(RegexLint.warning("^(\\w+\\s?)*$"))
        XCTAssertNil(RegexLint.warning("(\\d+\\.){3}\\d+"))
        XCTAssertNil(RegexLint.warning("error.*timeout"))
        XCTAssertNil(RegexLint.warning("\\(a+\\)+"))
        XCTAssertNil(RegexLint.warning("[(a+)+]"))
    }

    func testWarningShownButFilterApplied() async {
        let store = LogStore()
        store.ingest(Self.entries(["<13>Sep 23 10:15:32 h app: xxxy", "<13>Sep 23 10:15:32 h app: zzz"]))
        store.queryText = "/(x+)+y/"
        store.applyQueryText()
        await store.settle()
        XCTAssertEqual(store.visible.count, 1)
        XCTAssertTrue(store.queryError?.localizedCaseInsensitiveContains("slow") ?? false)
        XCTAssertTrue(store.queryErrorIsNotice)
        store.queryText = "\"unterminated"
        store.applyQueryText()
        XCTAssertFalse(store.queryErrorIsNotice)
    }

    /// Pasted garbage: 20,000 nested parentheses, 20,000 NOTs, 50,000 words. Parsing either
    /// fails with a message or yields a query whose evaluation cannot overflow a 512 KB stack.
    func testHugeAndDeeplyNestedQueriesAreRefused() {
        let deep = String(repeating: "(", count: 20_000) + "a" + String(repeating: ")", count: 20_000)
        XCTAssertThrowsError(try Query.parse(deep))
        XCTAssertThrowsError(try Query.parse(String(repeating: "NOT ", count: 20_000) + "a"))
        XCTAssertThrowsError(try Query.parse(Array(repeating: "a", count: 50_000).joined(separator: " ")))
        XCTAssertNoThrow(try Query.parse(Array(repeating: "a", count: 100).joined(separator: " OR ")))
        XCTAssertNoThrow(try Query.parse(String(repeating: "(", count: 20) + "a" + String(repeating: ")", count: 20)))
    }

    /// The longest accepted query is evaluated on a secondary thread's small stack.
    func testLongestAcceptedQueryRunsOnASmallStack() {
        var words = Array(repeating: "x", count: Query.maxTerms)
        words[0] = String(repeating: "(", count: Query.maxDepth - 1) + "x" + String(repeating: ")", count: Query.maxDepth - 1)
        guard let q = try? Query.parse(words.joined(separator: " ")) else { return XCTFail("the limit itself must parse") }
        let e = Self.entries(["<13>Sep 23 10:15:32 h app: x"])[0]
        let done = expectation(description: "ran")
        let t = Thread {
            let f = LogFilter(query: q, source: nil, mask: Set(Severity.allCases))
            XCTAssertTrue(f.matches(e))
            done.fulfill()
        }
        t.stackSize = 256 * 1024
        t.start()
        wait(for: [done], timeout: 10)
    }

    func testRegexCacheIsBounded() {
        for i in 0..<500 { _ = QueryMatch.regex("pattern\(i)") }
        XCTAssertLessThanOrEqual(RegexCache.shared.count, 65)
    }

    /// Packets: the same guard (a regex against short Info strings is enough to hang).
    func testPacketRegexIsGuarded() {
        let m = PacketMatcher(try! Query.parse("/(a+)+$/"))
        var d = Decoded()
        d.info = String(repeating: "a", count: 28) + "!"
        let p = Packet(id: 1, timestamp: Date(), relative: 0, length: 60, captured: 60, data: Data(count: 60), decoded: d)
        let t0 = Date()
        for _ in 0..<200 { _ = m.matches(p) }
        XCTAssertWithinBudget(Date().timeIntervalSince(t0), 1.5)
    }
}
