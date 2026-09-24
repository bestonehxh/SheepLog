import XCTest
@testable import SheepLog

/// Round 6: the header parser against RFC 5424 §6 / RFC 3164 §4 clause by clause, vendor field
/// names against the vendors' own documentation, and the filter grammar on queries an engineer
/// pastes.
@MainActor
final class Round6SyslogTests: XCTestCase {
    private func parse(_ text: String, from address: String = "10.1.0.1") -> LogEntry {
        parsedLine(text, from: address)
    }

    // MARK: - RFC 5424 §6.2.1 PRI / RFC 3164 §4.1.1

    func testPRIZeroIsKernEmergency() {
        let e = parse("<0>Oct 11 22:14:15 mymachine su: 'su root' failed")
        XCTAssertEqual(e.priority, 0)
        XCTAssertEqual(e.facility, .kern)
        XCTAssertEqual(e.severity, .emergency)
        XCTAssertEqual(e.hostname, "mymachine")
        XCTAssertEqual(e.program, "su")
        XCTAssertEqual(e.message, "'su root' failed")
    }

    func testPRI191And192() {
        let a = parse("<191>Oct 11 22:14:15 host app: x")
        XCTAssertEqual(a.priority, 191)
        XCTAssertEqual(a.facility, .local7)
        XCTAssertEqual(a.severity, .debug)
        // 192 is out of range: no PRI; the whole line is the message (RFC 3164 §4.3.3).
        let b = parse("<192>Oct 11 22:14:15 host app: x")
        XCTAssertNil(b.priority)
        XCTAssertEqual(b.facility, .user)
        XCTAssertEqual(b.severity, .notice)
        XCTAssertEqual(b.message, "<192>Oct 11 22:14:15 host app: x")
    }

    func testDatagramThatIsOnlyAPRI() {
        let e = parse("<13>")
        XCTAssertEqual(e.priority, 13)
        XCTAssertEqual(e.message, "")
        XCTAssertEqual(e.hostname, "")
        XCTAssertEqual(e.program, "")
        XCTAssertNil(e.pid)
        XCTAssertNil(e.deviceTime)
        XCTAssertEqual(e.vendor, .unknown)
    }

    func testWhitespaceOnlyMessage() {
        XCTAssertEqual(parse("<13>   ").message, "")
        let e = parse("<13>1 2026-09-23T10:15:32Z host app - - -")
        XCTAssertEqual(e.message, "")
        XCTAssertEqual(e.hostname, "host")
        XCTAssertEqual(parse("<13>Sep 23 10:15:32 host app:    ").program, "app")
    }

    // MARK: - RFC 5424 §6.2 HEADER NILVALUE per field, §6.3 SD, §6.4 MSG

    func testEveryHeaderFieldNil() {
        let e = parse("<13>1 - - - - - -")
        XCTAssertNil(e.deviceTime)
        XCTAssertEqual(e.hostname, "")
        XCTAssertEqual(e.program, "")
        XCTAssertNil(e.pid)
        XCTAssertNil(e.field("msgid"))
        XCTAssertEqual(e.message, "")
        XCTAssertTrue(e.fields.isEmpty)
    }

    func testEachNilFieldAlone() {
        let full = "<13>1 2026-09-23T10:15:32Z host app 42 ID7 - body"
        let base = parse(full)
        XCTAssertEqual(base.hostname, "host"); XCTAssertEqual(base.program, "app")
        XCTAssertEqual(base.pid, "42"); XCTAssertEqual(base.field("msgid"), "ID7"); XCTAssertEqual(base.message, "body")
        XCTAssertEqual(parse("<13>1 2026-09-23T10:15:32Z - app 42 ID7 - body").hostname, "")
        XCTAssertEqual(parse("<13>1 2026-09-23T10:15:32Z host - 42 ID7 - body").program, "")
        XCTAssertNil(parse("<13>1 2026-09-23T10:15:32Z host app - ID7 - body").pid)
        XCTAssertNil(parse("<13>1 2026-09-23T10:15:32Z host app 42 - - body").field("msgid"))
        XCTAssertNil(parse("<13>1 - host app 42 ID7 - body").deviceTime)
        XCTAssertEqual(parse("<13>1 - host app 42 ID7 - body").message, "body")
    }

    func testStructuredDataRFCExamples() {
        // RFC 5424 §6.5 example 3 and 4, plus every escape of §6.3.3.
        let e = parse("<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"]")
        XCTAssertEqual(e.field("sd.exampleSDID@32473.iut"), "3")
        XCTAssertEqual(e.field("sd.exampleSDID@32473.eventSource"), "Application")
        XCTAssertEqual(e.field("sd.exampleSDID@32473.eventID"), "1011")
        XCTAssertEqual(e.field("sd.examplePriority@32473.class"), "high")
        XCTAssertEqual(e.message, "")
        let esc = parse(#"<13>1 2026-09-23T10:15:32Z h a - - [x@1 q="a\"b" s="c\\d" r="e\]f" o="g\nh"] msg"#)
        XCTAssertEqual(esc.field("sd.x@1.q"), "a\"b")
        XCTAssertEqual(esc.field("sd.x@1.s"), "c\\d")
        XCTAssertEqual(esc.field("sd.x@1.r"), "e]f")
        XCTAssertEqual(esc.field("sd.x@1.o"), "g\\nh", "a backslash before any other character is kept")
        XCTAssertEqual(esc.message, "msg")
    }

    func testBOMBeforeMessageIsStripped() {
        let e = parse("<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - \u{FEFF}'su root' failed for lonvick on /dev/pts/8")
        XCTAssertEqual(e.message, "'su root' failed for lonvick on /dev/pts/8")
        XCTAssertEqual(e.facility, .auth)
        XCTAssertEqual(e.severity, .critical)
        XCTAssertEqual(e.deviceTime?.timeIntervalSince1970 ?? 0, 1_065_910_455.003, accuracy: 0.0005)
    }

    func testTimestampForms() {
        func t(_ ts: String) -> Double? { parse("<13>1 \(ts) h a - - - m").deviceTime?.timeIntervalSince1970 }
        XCTAssertEqual(t("1985-04-12T23:20:50.52Z")!, 482_196_050.52, accuracy: 0.0001)
        XCTAssertEqual(t("1985-04-12T19:20:50.52-04:00")!, 482_196_050.52, accuracy: 0.0001)
        XCTAssertEqual(t("2003-10-11T22:14:15.003Z")!, 1_065_910_455.003, accuracy: 0.0001)
        XCTAssertEqual(t("2003-08-24T05:14:15.000003-07:00")!, 1_061_727_255.000003, accuracy: 0.0000005)
        XCTAssertEqual(t("2026-09-23T17:15:32+07:00")!, t("2026-09-23T10:15:32Z")!)
        XCTAssertEqual(t("2038-01-19T03:14:08Z")!, 2_147_483_648)
        XCTAssertEqual(t("2106-02-07T06:28:16Z")!, 4_294_967_296)
        // RFC 5424 §6.2.3.1 examples of invalid timestamps parse leniently or not at all, never crash.
        _ = t("2003-08-24T05:14:15.000000003-07:00")
        _ = t("2003-10-11T22:14:15.003Z ")
    }

    func testFieldLengthLimitsOfRFC5424AreKept() {
        let host = String(repeating: "h", count: 255)
        let app = String(repeating: "a", count: 48)
        let procid = String(repeating: "7", count: 128)
        let msgid = String(repeating: "M", count: 32)
        let e = parse("<13>1 2026-09-23T10:15:32Z \(host) \(app) \(procid) \(msgid) - body")
        XCTAssertEqual(e.hostname, host)
        XCTAssertEqual(e.program, app)
        XCTAssertEqual(e.pid, procid)
        XCTAssertEqual(e.field("msgid"), msgid)
        XCTAssertEqual(e.message, "body")
    }

    func testRFC5424MessageBeginningWithPercents() {
        // RFC 5424 §6.5 example 2: not Huawei, not a tag.
        let e = parse("<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts.")
        XCTAssertEqual(e.vendor, .unknown)
        XCTAssertEqual(e.hostname, "192.0.2.1")
        XCTAssertEqual(e.program, "myproc")
        XCTAssertEqual(e.pid, "8710")
        XCTAssertEqual(e.message, "%% It's time to make the do-nuts.")
    }

    // MARK: - RFC 3164 §4.1.2 HEADER / §4.1.3 TAG

    func testTagOf32CharactersBeforeColonOrBracket() {
        let tag = "abcdefghijklmnopqrstuvwxyz012345"
        XCTAssertEqual(tag.count, 32)
        let a = parse("<13>Sep 23 10:15:32 host \(tag): msg")
        XCTAssertEqual(a.program, tag); XCTAssertEqual(a.message, "msg")
        let b = parse("<13>Sep 23 10:15:32 host \(tag)[99]: msg")
        XCTAssertEqual(b.program, tag); XCTAssertEqual(b.pid, "99"); XCTAssertEqual(b.message, "msg")
    }

    func testTagWithSlash() {
        let a = parse("<22>Sep 23 10:15:32 mail postfix/smtpd[1234]: connect from x")
        XCTAssertEqual(a.program, "postfix/smtpd"); XCTAssertEqual(a.pid, "1234")
        let b = parse("<13>Sep 23 10:15:32 host sshd/1234: hi")
        XCTAssertEqual(b.program, "sshd/1234"); XCTAssertEqual(b.message, "hi")
    }

    func testIPv6LiteralHostname() throws {
        let e = parse("<13>Sep 23 10:15:32 2001:db8::1 sshd[7]: Accepted publickey")
        XCTAssertEqual(e.hostname, "2001:db8::1")
        XCTAssertEqual(e.program, "sshd")
        XCTAssertEqual(e.message, "Accepted publickey")
        // "2001" is the address, not the year of the timestamp.
        let year = Calendar(identifier: .gregorian).component(.year, from: try XCTUnwrap(e.deviceTime))
        XCTAssertGreaterThan(year, 2020)
        let g = parse("<13>Sep 23 10:15:32 2003:e2:1f00::5 sshd: hi")
        XCTAssertEqual(g.hostname, "2003:e2:1f00::5")
        // A real trailing year still reads as one (Cisco "… 2026: ", or before the host).
        let y = parse("<13>Sep 23 10:15:32 2019: %SYS-5-CONFIG_I: Configured")
        XCTAssertEqual(Calendar(identifier: .gregorian).component(.year, from: try XCTUnwrap(y.deviceTime)), 2019)
        let z = parse("<13>Sep 23 10:15:32 2019 host app: x")
        XCTAssertEqual(Calendar(identifier: .gregorian).component(.year, from: try XCTUnwrap(z.deviceTime)), 2019)
        XCTAssertEqual(z.hostname, "host")
        let f = parse("<13>Sep 23 10:15:32 fe80::1 kernel: link up")
        XCTAssertEqual(f.hostname, "fe80::1")
        XCTAssertEqual(f.program, "kernel")
    }

    func testDashAsRFC3164HostnameMeansNone() {
        // rsyslog / relays write "-" for an unknown host (RFC 5424's NILVALUE); it is no name.
        let e = parse("<13>Sep 23 10:15:32 - sshd[1]: hi", from: "10.9.9.9")
        XCTAssertEqual(e.hostname, "")
        XCTAssertEqual(e.displayHost, "10.9.9.9")
        XCTAssertEqual(e.program, "sshd")
        XCTAssertEqual(e.message, "hi")
    }

    func testRFC3164Examples() {
        let a = parse("<13>Feb  5 17:32:18 10.0.0.99 Use the BFG!")
        XCTAssertEqual(a.hostname, "10.0.0.99")
        XCTAssertEqual(a.message, "Use the BFG!")
        let b = parse("Use the BFG!")
        XCTAssertNil(b.priority)
        XCTAssertEqual(b.message, "Use the BFG!")
    }

    // MARK: - Vendor field names as the vendors document them

    /// PAN-OS 10/11 "Syslog Field Descriptions": the variable names of the Traffic and Threat
    /// log formats (what a custom log format and a copied filter use).
    func testPaloFieldNamesFollowPANOSDocumentation() throws {
        let lines = try String(contentsOf: CorpusTests.dir.appending(path: "paloalto.log"), encoding: .utf8)
            .split(separator: "\n").map(String.init)
        let traffic = parse(try XCTUnwrap(lines.first { $0.contains(",TRAFFIC,end,") }))
        XCTAssertEqual(traffic.field("from"), "trust")
        XCTAssertEqual(traffic.field("to"), "untrust")
        XCTAssertEqual(traffic.field("inbound_if"), "ethernet1/2")
        XCTAssertEqual(traffic.field("outbound_if"), "ethernet1/1")
        XCTAssertEqual(traffic.field("logset"), "default")
        XCTAssertEqual(traffic.field("sessionid"), "123456")
        XCTAssertEqual(traffic.field("repeatcnt"), "1")
        XCTAssertEqual(traffic.field("bytes_sent"), "98")
        XCTAssertEqual(traffic.field("bytes_received"), "98")
        XCTAssertEqual(traffic.field("packets"), "2")
        XCTAssertEqual(traffic.field("elapsed"), "0")
        XCTAssertEqual(traffic.field("category"), "any")
        XCTAssertEqual(traffic.field("srcloc"), "10.0.0.0-10.255.255.255")
        XCTAssertEqual(traffic.field("dstloc"), "United States")
        XCTAssertEqual(traffic.field("session_end_reason"), "aged-out")
        for k in ["src", "dst", "rule", "app", "action", "sport", "dport", "proto", "bytes"] {
            XCTAssertNotNil(traffic.field(k), k)
        }
        let vuln = parse(try XCTUnwrap(lines.first { $0.contains(",THREAT,vulnerability,") }))
        XCTAssertEqual(vuln.field("from"), "trust")
        XCTAssertEqual(vuln.field("threatid"), "Apache Log4j Remote Code Execution Vulnerability(91991)")
        XCTAssertEqual(vuln.field("category"), "code-execution")
        XCTAssertEqual(vuln.field("severity"), "critical")
        XCTAssertEqual(vuln.field("direction"), "client-to-server")
        XCTAssertEqual(vuln.field("action"), "reset-both")
        XCTAssertEqual(vuln.field("srcloc"), "10.0.0.0-10.255.255.255")
        XCTAssertEqual(vuln.field("contenttype"), "text/html")
    }

    func testAOS8BodyKeyValuesAreFields() {
        // `f:username=` / `username:alice` must work on an AOS 8 line as they do on any line with
        // key=value pairs.
        let e = parse("<133>Sep 23 10:12:01 2026 MM-1 authmgr[4211]: <522008> <4211> <NOTI> <MM-1 10.1.1.10>  User Authentication Successful: username=alice MAC=02:00:5e:10:00:01 IP=10.20.0.15 role=employee VLAN=20 AP=AP-Lobby SSID=Corp auth method=802.1x auth server=CPPM")
        XCTAssertEqual(e.vendor, .arubaOS)
        XCTAssertEqual(e.field("code"), "522008")
        XCTAssertEqual(e.field("username"), "alice")
        XCTAssertEqual(e.field("role"), "employee")
        XCTAssertEqual(e.field("SSID"), "Corp")
    }

    // MARK: - Filter grammar on pasted queries

    private func q(_ text: String, regex: Bool = false) throws -> QueryNode? {
        try Query.parse(text, regexWords: regex).root
    }

    func testPastedQueriesParse() throws {
        XCTAssertEqual(try q("a\u{3000}b"), .and(.text("a"), .text("b")), "full-width space separates")
        XCTAssertEqual(try q("a or b"), .or(.text("a"), .text("b")))
        XCTAssertEqual(try q("a and b"), .and(.text("a"), .text("b")))
        XCTAssertEqual(try q("host:core-sw_1.lab"), .field(key: "host", op: .eq, value: "core-sw_1.lab"))
        XCTAssertEqual(try q("sev:WARN"), .field(key: "sev", op: .eq, value: "WARN"))
        XCTAssertEqual(try q("-\"exact phrase\""), .not(.text("exact phrase")))
        XCTAssertEqual(try q("NOT NOT a"), .not(.not(.text("a"))))
        XCTAssertEqual(try q("(a)(b)"), .and(.text("a"), .text("b")))
        XCTAssertEqual(try q("🔥 ล้มเหลว"), .and(.text("🔥"), .text("ล้มเหลว")))
        XCTAssertEqual(try q("f:msg="), .field(key: "f", op: .eq, value: "msg="))
        XCTAssertEqual(try q("/a\\/b/"), .regex("a\\/b"))
        XCTAssertEqual(try q("host:\"CORE SW\""), .field(key: "host", op: .eq, value: "CORE SW"))
        XCTAssertEqual(try q("a NOR b"), .and(.not(.text("a")), .not(.text("b"))))
        XCTAssertEqual(try q("-"), .text("-"))
    }

    /// `a NOR b NOR c` reads as "none of a, b, c" — not (a OR b) AND NOT c, which is what a
    /// left-associative NOR makes of it.
    func testNORChainIsNoneOf() throws {
        let lines = ["a", "b", "c", "d"].enumerated().map { i, w in parsedLine("<13>Sep 23 10:15:32 h app: \(w)x", id: i + 1) }
        XCTAssertEqual(try matching("ax NOR bx", lines), [3, 4])
        XCTAssertEqual(try matching("ax NOR bx NOR cx", lines), [4])
        XCTAssertEqual(try matching("ax NOR bx NOR cx NOR dx", lines), [])
        XCTAssertEqual(try matching("(ax NOR bx) OR dx", lines), [3, 4])
    }

    func testNegatedPhraseStaysAPhrase() throws {
        // `"host:x y"` is a phrase; `-"host:x y"` must be NOT that phrase, not NOT host = "x y".
        XCTAssertEqual(try q("\"host:x y\""), .text("host:x y"))
        XCTAssertEqual(try q("-\"host:x y\""), .not(.text("host:x y")))
        XCTAssertEqual(try q("!\"sev:err\""), .not(.text("sev:err")))
    }

    func testIncompleteQueriesAreErrorsNotCrashes() {
        for text in ["\"unterminated", "a OR", "()", "a AND", "AND a", "NOT", "(a", "a)", "a OR OR b",
                     "host:\"abc", "/unterminated", "/[/", String(repeating: "a ", count: 500)] {
            XCTAssertThrowsError(try Query.parse(text), text)
        }
    }

    func testRegexSlashEscapedAndMatches() async {
        let store = LogStore()
        store.ingest([parse("<13>Sep 23 10:15:32 h app: GET https://example.com/a/b ok"),
                      parse("<13>Sep 23 10:15:32 h app: nothing here")])
        store.queryText = #"/https?:\/\/example/"#
        store.applyQueryText()
        await store.settle()
        XCTAssertNil(store.queryError)
        XCTAssertEqual(store.visible.count, 1)
    }

    func testTypingAnUnbalancedQuoteKeepsTheLastFilter() async {
        let store = LogStore()
        store.ingest([parse("<13>Sep 23 10:15:32 h app: link down"), parse("<13>Sep 23 10:15:32 h app: link up")])
        store.queryText = "down"
        store.applyQueryText()
        await store.settle()
        XCTAssertEqual(store.visible.count, 1)
        store.queryText = "down \"link"
        store.applyQueryText()
        await store.settle()
        XCTAssertEqual(store.queryError, "Unterminated quote")
        XCTAssertFalse(store.queryErrorIsNotice)
        XCTAssertEqual(store.query.source, "down")
        XCTAssertEqual(store.visible.count, 1)
    }

    private func matching(_ query: String, _ lines: [LogEntry]) throws -> [Int] {
        let f = LogFilter(query: try Query.parse(query), source: nil, mask: Set(Severity.allCases))
        return lines.filter { f.matches($0) }.map(\.id)
    }

    func testCompleteAddressInAFieldIsExact() throws {
        // As `host:10.1.0.1` is not 10.1.0.10–19, `src:`/`dst:`/`f:srcip=` with a complete
        // address must not match 10.1.1.10 or 10.1.1.100.
        let lines = ["10.1.1.1", "10.1.1.10", "10.1.1.100"].enumerated().map { i, ip in
            parsedLine("<189>date=2026-09-23 time=10:15:32 devname=\"FGT\" devid=\"FGT60F\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"notice\" srcip=\(ip) dstip=\(ip) action=\"deny\"", id: i + 1)
        }
        XCTAssertEqual(try matching("src:10.1.1.1", lines), [1])
        XCTAssertEqual(try matching("dst:10.1.1.1", lines), [1])
        XCTAssertEqual(try matching("f:srcip=10.1.1.1", lines), [1])
        XCTAssertEqual(try matching("srcip:10.1.1.1", lines), [1])
        XCTAssertEqual(try matching("srcip=10.1.1.1", lines), [1])
        XCTAssertEqual(try matching("f:srcip!=10.1.1.1", lines), [2, 3])
        XCTAssertEqual(try matching("src:10.1.1.", lines), [1, 2, 3], "a prefix still works")
        XCTAssertEqual(try matching("src:10.1.1.1*", lines), [1, 2, 3], "and the explicit prefix")
    }

    /// A pasted subnet (`10.1.0.0/24`, `2001:db8::/32`) — the way ACLs and firewall rules name
    /// addresses — matches the addresses inside it, for host: and for address fields.
    func testCIDRInHostAndFields() throws {
        let lines = [("10.1.0.7", "10.9.9.9"), ("10.1.1.7", "10.1.0.200"), ("2001:db8::5", "2001:db9::1")].enumerated().map { i, p in
            parsedLine("<189>date=2026-09-23 time=10:15:32 devname=\"FGT\" devid=\"FGT60F\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"notice\" srcip=\(p.1) dstip=8.8.8.8 action=\"deny\"",
                       from: p.0, id: i + 1)
        }
        XCTAssertEqual(try matching("host:10.1.0.0/24", lines), [1])
        XCTAssertEqual(try matching("host:10.1.0.0/16", lines), [1, 2])
        XCTAssertEqual(try matching("-host:10.1.0.0/24", lines), [2, 3])
        XCTAssertEqual(try matching("host:2001:db8::/32", lines), [3])
        XCTAssertEqual(try matching("src:10.1.0.0/24", lines), [2])
        XCTAssertEqual(try matching("f:srcip=10.0.0.0/8", lines), [1, 2])
        XCTAssertEqual(try matching("srcip:10.9.9.9/32", lines), [1])
        XCTAssertEqual(try matching("f:srcip!=10.0.0.0/8", lines), [3])
        XCTAssertEqual(try matching("host:0.0.0.0/0", lines), [1, 2])
        // Not a subnet: stays text / prefix as before.
        XCTAssertEqual(try matching("host:10.1.0.0/33", lines), [])
        XCTAssertEqual(try matching("f:action=deny/allow", lines), [])
    }

    /// An IPv6 address has many spellings (`2001:DB8:0:0::1` = `2001:db8::1`, what inet_ntop
    /// prints for the peer): a complete address compares as an address, not as text.
    func testIPv6AddressSpellingsAreTheSameAddress() throws {
        let lines = [parsedLine("<189>date=2026-09-23 time=10:15:32 devname=\"FGT\" devid=\"FGT60F\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"notice\" srcip=2001:db8::5 dstip=8.8.8.8 action=\"deny\"",
                                from: "2001:db8::1", id: 1),
                     parsedLine("<13>Sep 23 10:15:32 h app: x", from: "2001:db8::10", id: 2)]
        XCTAssertEqual(try matching("host:2001:DB8:0:0::1", lines), [1])
        XCTAssertEqual(try matching("host:2001:0db8::0001", lines), [1])
        XCTAssertEqual(try matching("-host:2001:DB8::1", lines), [2])
        XCTAssertEqual(try matching("f:srcip=2001:DB8:0::5", lines), [1])
        XCTAssertEqual(try matching("src:2001:db8:0:0:0:0:0:5", lines), [1])
    }

    func testHostWildcard() throws {
        let lines = [parsedLine("<13>Sep 23 10:15:32 CORE-SW1 app: a", from: "10.1.0.1", id: 1),
                     parsedLine("<13>Sep 23 10:15:32 ACC-SW7 app: b", from: "10.2.0.1", id: 2),
                     parsedLine("<13>no header", from: "10.3.0.1", id: 3)]
        XCTAssertEqual(try matching("host:*", lines), [1, 2, 3])
        XCTAssertEqual(try matching("host:core-*", lines), [1])
        XCTAssertEqual(try matching("host:*-SW*", lines), [1, 2])
        XCTAssertEqual(try matching("host:10.*.0.1", lines), [1, 2, 3])
        XCTAssertEqual(try matching("-host:acc*", lines), [1, 3])
    }

    func testVendorDocumentFiltersWork() throws {
        let forti = parsedLine("<189>date=2026-09-23 time=10:15:32 devname=\"FGT\" devid=\"FGT60F\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"notice\" srcip=10.1.0.5 dstip=8.8.8.8 action=\"deny\" policyid=1", id: 1)
        let cp = parsedLine("<134>1 2026-09-23T03:15:32Z cp-gw-01 CheckPoint 26045 - [action:\"Drop\"; src:\"203.0.113.50\"; dst:\"10.1.0.80\"; service:\"22\"; rule_name:\"Cleanup rule\"; product:\"VPN-1 & FireWall-1\"]", id: 2)
        let lines = [forti, cp]
        XCTAssertEqual(try matching("f:srcip=10.", lines), [1])
        XCTAssertEqual(try matching("f:action=deny", lines), [1])
        XCTAssertEqual(try matching("action=deny", lines), [1])
        XCTAssertEqual(try matching("action:drop", lines), [2])
        XCTAssertEqual(try matching("f:rule_name=\"Cleanup rule\"", lines), [2])
        XCTAssertEqual(try matching("service:22", lines), [2])
    }
}
