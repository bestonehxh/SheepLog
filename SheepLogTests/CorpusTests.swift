import XCTest
@testable import SheepLog

/// Real-shaped device logs (Tests/corpus/<vendor>.log, one line each; expectations in the
/// matching .expect file) parsed through the real parser, then filtered the way a network
/// engineer would type it.
@MainActor
final class CorpusTests: XCTestCase {
    struct Line {
        let file: String
        let index: Int
        let text: String
        let severity: String
        let hostname: String?
        let program: String?
        let minFields: Int
        let time: String?
        var key: String { "\(file):\(index)" }
    }

    static let dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .appending(path: "Tests/corpus", directoryHint: .isDirectory)

    /// File order also numbers the source addresses: file k, line i → 192.168.k.(i+1).
    static let files: [(String, Vendor)] = [
        ("arubacx", .arubaCX), ("arubaos", .arubaOS), ("arubasw", .arubaSwitch), ("clearpass", .clearPass),
        ("huawei", .huawei), ("checkpoint", .checkPoint), ("paloalto", .paloAlto), ("fortigate", .fortigate),
        ("other", .unknown),
    ]

    /// 2026-09-24 12:00 local — the day after the corpus lines were "sent".
    static let received: Date = {
        var c = DateComponents()
        c.year = 2026; c.month = 9; c.day = 24; c.hour = 12
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = .current
        return cal.date(from: c)!
    }()

    static func loadCorpus() throws -> [Line] {
        var out: [Line] = []
        for (file, _) in files {
            let log = try String(contentsOf: dir.appending(path: "\(file).log"), encoding: .utf8)
            let exp = try String(contentsOf: dir.appending(path: "\(file).expect"), encoding: .utf8)
            let lines = log.split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
            let expects = exp.split(separator: "\n", omittingEmptySubsequences: true)
            XCTAssertEqual(lines.count, expects.count, "\(file): .log and .expect differ in length")
            for (i, (text, e)) in zip(lines, expects).enumerated() {
                let c = e.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
                precondition(c.count == 5, "\(file).expect line \(i + 1)")
                out.append(Line(file: file, index: i, text: text, severity: c[0],
                                hostname: c[1] == "-" ? nil : c[1], program: c[2] == "-" ? nil : c[2],
                                minFields: Int(c[3]) ?? 0, time: c[4] == "-" ? nil : c[4]))
            }
        }
        return out
    }

    static func address(_ l: Line) -> String {
        let k = (files.firstIndex { $0.0 == l.file } ?? 0) + 1
        return "192.168.\(k).\(l.index + 1)"
    }

    static func parse(_ l: Line, id: Int = 1) -> LogEntry {
        parsedLine(l.text, from: address(l), received: received, id: id)
    }

    /// "2026-09-23T10:15:32[.fff]" = local wall time; with "Z" / "+hh:mm" = absolute.
    static func expectedDate(_ s: String) -> Date? {
        if s.hasSuffix("Z") || s.dropFirst(19).contains("+") || s.dropFirst(19).contains("-") {
            let f = ISO8601DateFormatter()
            f.formatOptions = s.contains(".") ? [.withInternetDateTime, .withFractionalSeconds] : [.withInternetDateTime]
            return f.date(from: s)
        }
        let parts = s.split(separator: "T")
        let d = parts[0].split(separator: "-").compactMap { Int($0) }
        let tf = parts[1].split(separator: ".")
        let t = tf[0].split(separator: ":").compactMap { Int($0) }
        var c = DateComponents()
        c.year = d[0]; c.month = d[1]; c.day = d[2]; c.hour = t[0]; c.minute = t[1]; c.second = t[2]
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = .current
        var date = cal.date(from: c)!
        if tf.count > 1, let ms = Double("0." + tf[1]) { date += ms }
        return date
    }

    // MARK: - Every line

    func testCorpusShape() throws {
        let lines = try Self.loadCorpus()
        XCTAssertGreaterThanOrEqual(lines.count, 60)
        var perFile: [String: Int] = [:]
        for l in lines { perFile[l.file, default: 0] += 1 }
        for (file, _) in Self.files { XCTAssertGreaterThanOrEqual(perFile[file] ?? 0, 7, file) }
    }

    func testEveryLineParses() throws {
        let lines = try Self.loadCorpus()
        let vendorOf = Dictionary(uniqueKeysWithValues: Self.files)
        var misdetected: [String] = []
        for l in lines {
            let e = Self.parse(l)
            let where_ = "\(l.key) «\(l.text.prefix(90))»"
            if e.vendor != vendorOf[l.file] { misdetected.append("\(l.key) → \(e.vendor)") }
            XCTAssertEqual(e.vendor, vendorOf[l.file], "vendor \(where_)")
            XCTAssertEqual(e.severity.name, l.severity, "severity \(where_)")
            if let h = l.hostname {
                XCTAssertEqual(e.hostname, h, "hostname \(where_)")
            } else {
                XCTAssertEqual(e.hostname, "", "no hostname expected \(where_)")
            }
            if let p = l.program { XCTAssertEqual(e.program, p, "program \(where_)") }
            XCTAssertGreaterThanOrEqual(e.fields.count, l.minFields, "fields \(where_): \(e.fields.map(\.key))")
            if let t = l.time {
                let want = try XCTUnwrap(Self.expectedDate(t), "bad expectation \(t)")
                XCTAssertNotNil(e.deviceTime, "deviceTime missing \(where_)")
                if let got = e.deviceTime {
                    XCTAssertEqual(got.timeIntervalSince1970, want.timeIntervalSince1970, accuracy: 0.002, "deviceTime \(where_)")
                }
            }
            // Nothing is lost: the message is a suffix of the raw line and the raw is verbatim.
            XCTAssertEqual(e.raw, l.text)
            XCTAssertTrue(l.text.hasSuffix(e.message), "message is not the tail of the line \(where_)")
            XCTAssertFalse(e.message.isEmpty, "empty message \(where_)")
        }
        XCTAssertEqual(misdetected, [], "misdetections")
    }

    /// Structured vendors expose the fields an engineer filters on, under stable names.
    func testKeyFieldsPerVendor() throws {
        let lines = try Self.loadCorpus()
        func entry(_ key: String) -> LogEntry { Self.parse(lines.first { $0.key == key }!) }
        XCTAssertEqual(entry("huawei:2").field("NeighborAddress"), "10.0.0.2")
        XCTAssertEqual(entry("huawei:1").field("Command"), "display interface brief")
        XCTAssertEqual(entry("huawei:1").field("VpnName"), "")
        XCTAssertEqual(entry("huawei:5").field("Reason"), "The link protocol is down")
        XCTAssertEqual(entry("huawei:5").field("ifName"), "10GE1/0/24")
        XCTAssertEqual(entry("clearpass:4").field("Action Key"), "")
        XCTAssertEqual(entry("clearpass:4").field("Timestamp"), "Sep 23, 2026 10:16:20 ICT")
        XCTAssertEqual(entry("clearpass:4").field("Description"), "Failed to connect to AD server ad01.corp.example: timeout")
        XCTAssertEqual(entry("clearpass:1").field("Common.Enforcement-Profiles"), "[Allow Access Profile], Corp-VLAN20")
        XCTAssertEqual(entry("paloalto:1").field("action"), "deny")
        XCTAssertEqual(entry("paloalto:1").field("dport"), "445")
        XCTAssertEqual(entry("paloalto:2").field("misc"), "example.com/a,b?x=1")
        XCTAssertEqual(entry("paloalto:3").field("severity"), "critical")
        XCTAssertEqual(entry("paloalto:7").field("user"), "corp\\alice")
        XCTAssertEqual(entry("paloalto:7").field("src"), "10.1.0.5")
        XCTAssertEqual(entry("paloalto:8").field("client_os_ver"), "Microsoft Windows 11 Pro , 64-bit")
        XCTAssertNil(entry("paloalto:9").field("bytes"), "DECRYPTION column 31 is not a byte count")
        XCTAssertEqual(entry("fortigate:1").field("policyname"), "LAN-to-WAN")
        XCTAssertEqual(entry("fortigate:1").field("action"), "close")
        XCTAssertEqual(entry("checkpoint:2").field("protection_name"), "Apache Log4j Remote Code Execution (CVE-2021-44228)")
        XCTAssertEqual(entry("checkpoint:0").field("loguid"), "{0x66f0e0a4,0x0,0x3000000a,0xc0000000}")
        XCTAssertEqual(entry("arubasw:3").field("module"), "802.1x")
        XCTAssertEqual(entry("other:0").field("seq"), "123")
        XCTAssertEqual(entry("other:12").field("COMMAND"), "/usr/bin/systemctl")
    }

    // MARK: - Speed

    /// Every corpus line parses in well under 50 µs with optimisation (Release); the Debug
    /// build (-Onone, what `xcodebuild test` runs) gets ten times the room.
    func testEveryLineIsFast() throws {
        let lines = try Self.loadCorpus()
        #if DEBUG
        let bound = 500e-6
        #else
        let bound = 50e-6
        #endif
        let n = 2_000
        var worst: (String, Double) = ("", 0)
        for l in lines {
            let raw = RawSyslog(received: Self.received, sourceAddress: Self.address(l), sourcePort: 514,
                                transport: .udp, text: l.text)
            _ = SyslogParser.parse(raw, id: 0)        // warm
            let t0 = DispatchTime.now().uptimeNanoseconds
            var sink = 0
            for i in 0..<n { sink &+= SyslogParser.parse(raw, id: i).fields.count }
            let per = Double(DispatchTime.now().uptimeNanoseconds - t0) / 1e9 / Double(n)
            XCTAssertGreaterThan(sink, -1)
            if per > worst.1 { worst = (l.key, per) }
            XCTAssertWithinBudget(per, bound, "\(l.key) takes \(Int(per * 1e6)) µs per parse")
        }
        print("[corpus] slowest line \(worst.0): \(String(format: "%.1f", worst.1 * 1e6)) µs")
    }

    /// XCTest's own measurement: 10k parses cycling through the corpus.
    func testParseThroughputMeasure() throws {
        let raws = try Self.loadCorpus().map {
            RawSyslog(received: Self.received, sourceAddress: Self.address($0), sourcePort: 514, transport: .udp, text: $0.text)
        }
        measure {
            var sink = 0
            for i in 0..<10_000 { sink &+= SyslogParser.parse(raws[i % raws.count], id: i).fields.count }
            XCTAssertGreaterThan(sink, 0)
        }
    }

    // MARK: - Filters an engineer would type

    private var keyOf: [Int: String] = [:]

    /// A store holding the whole corpus plus three traps (keys trap:0 linkDown, trap:1
    /// coldStart, trap:2 authenticationFailure).
    private func corpusStore() throws -> LogStore {
        let lines = try Self.loadCorpus()
        var entries: [LogEntry] = []
        for l in lines {
            let e = Self.parse(l, id: LogStore.nextID())
            keyOf[e.id] = l.key
            entries.append(e)
        }
        let reg = MIBRegistry()
        reg.loadNow(bundled: MIBRegistry.bundledURLs())
        let ifIndex = OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 3])
        let traps: [SNMPTrap] = [
            SNMPTrap(received: Self.received, sourceAddress: "10.1.0.30", sourcePort: 50000, version: .v2c,
                     community: "public", trapOID: OID([1, 3, 6, 1, 6, 3, 1, 1, 5, 3]), uptime: 12345, agentAddress: nil,
                     varBinds: [VarBind(ifIndex, .integer(3)),
                                VarBind(OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 7, 3]), .integer(1)),
                                VarBind(OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 3]), .integer(2)),
                                VarBind(OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 3]), .octetString(Data("GigabitEthernet0/3".utf8)))]),
            SNMPTrap(received: Self.received, sourceAddress: "10.1.0.31", sourcePort: 50001, version: .v2c,
                     community: "public", trapOID: OID([1, 3, 6, 1, 6, 3, 1, 1, 5, 1]), uptime: 5, agentAddress: nil, varBinds: []),
            SNMPTrap(received: Self.received, sourceAddress: "10.1.0.32", sourcePort: 50002, version: .v1,
                     community: "public", trapOID: OID([1, 3, 6, 1, 6, 3, 1, 1, 5, 5]), uptime: 7, agentAddress: "10.1.0.32", varBinds: []),
        ]
        for (i, t) in traps.enumerated() {
            let e = TrapReceiver.entry(for: t, registry: reg)
            keyOf[e.id] = "trap:\(i)"
            entries.append(e)
        }
        let store = LogStore()
        store.ingest(entries)
        return store
    }

    private func hits(_ store: LogStore, _ q: String, file: StaticString = #filePath, line: UInt = #line) async -> Set<String> {
        store.queryText = q
        store.applyQueryText()
        XCTAssertNil(store.queryError, "\(q): \(store.queryError ?? "")", file: file, line: line)
        await store.settle()
        return Set(store.visible.compactMap { keyOf[$0.id] })
    }

    private func expect(_ store: LogStore, _ q: String, _ keys: [String], file: StaticString = #filePath, line: UInt = #line) async {
        let got = await hits(store, q, file: file, line: line)
        XCTAssertEqual(got.sorted(), Set(keys).sorted(), "query «\(q)»", file: file, line: line)
    }

    func testVendorQueries() async throws {
        let s = try corpusStore()
        // Aruba AOS-CX
        await expect(s, #"cx "LOG_CRIT" OR "LOG_ALERT""#, ["arubacx:3", "arubacx:4"])
        await expect(s, "vendor:aos-cx sev:<=err", ["arubacx:3", "arubacx:4", "arubacx:5"])
        await expect(s, "host:CX6300-CORE- f:module=AMM -lldp", ["arubacx:1", "arubacx:6", "arubacx:8", "arubacx:9"])   // 8, 9: round 14's SD lines
        // Aruba AOS 8 / IAP
        await expect(s, "vendor:iap sev:<=warn", ["arubaos:1", "arubaos:4", "arubaos:5", "arubaos:7", "arubaos:9"])
        await expect(s, "f:username=alice", ["arubaos:0"])
        await expect(s, "vendor:aos8 username:bob", ["arubaos:1"])
        await expect(s, "aos8 \"is down\"", ["arubaos:7", "arubaos:9"])
        await expect(s, #"authmgr "Authentication failed""#, ["arubaos:1"])
        await expect(s, "aos8 host:MD-7210-1 NOT stm", ["arubaos:1", "arubaos:4"])
        // Aruba AOS-S
        await expect(s, "vendor:procurve ports off-line", ["arubasw:0", "arubasw:7"])
        await expect(s, "vendor:aos-s (FFI OR 802.1x)", ["arubasw:2", "arubasw:3"])
        await expect(s, "host:SW-5406R- -f:module=ports", ["arubasw:3", "arubasw:5"])
        // ClearPass
        await expect(s, "clearpass Login-Status=REJECT", ["clearpass:0"])
        await expect(s, "f:Common.Username=alice OR f:TACACS.Username=netadmin", ["clearpass:0", "clearpass:2"])
        await expect(s, "vendor:cppm sev:<=warn", ["clearpass:0", "clearpass:2", "clearpass:3", "clearpass:4"])
        // Huawei
        await expect(s, #"huawei IFNET/4 "DOWN state""#, ["huawei:0", "huawei:7"])
        // (round 15: HW-NE40E's OSPF neighbor 10.0.0.10 too; its BGP peer lines are error-level)
        await expect(s, "vendor:vrp f:NeighborAddress=10.0.0.", ["huawei:2", "huawei:10", "huawei:11", "huawei:12"])
        await expect(s, "huawei sev:<=err -OSPF", ["huawei:5", "huawei:8", "huawei:9"])
        // Check Point
        await expect(s, #"checkpoint action:"Drop""#, ["checkpoint:0"])
        await expect(s, "checkpoint f:action=Drop", ["checkpoint:0"])
        await expect(s, "vendor:cp sev:<=err", ["checkpoint:2", "checkpoint:3"])
        await expect(s, "checkpoint src:203.0.113.", ["checkpoint:0"])
        // Palo Alto
        await expect(s, "palo THREAT sev:<=err", ["paloalto:3"])
        await expect(s, "vendor:pan action=deny", ["paloalto:1"])
        await expect(s, "palo f:dport=443 -src:10.1.0.5", ["paloalto:3"])
        await expect(s, "palo gateway-connected", ["paloalto:8"])
        // Field names as PAN-OS documents them (from/to zones, session_end_reason, …).
        await expect(s, "f:session_end_reason=policy-deny", ["paloalto:1"])
        await expect(s, "palo from:trust to:untrust action:deny", ["paloalto:1"])
        await expect(s, "vendor:pan f:inbound_if=ethernet1/2 threatid:*Log4j*", ["paloalto:3"])
        // FortiGate
        await expect(s, "vendor:forti action=deny", ["fortigate:0", "fortigate:6"])
        await expect(s, "f:srcip=10.1. -f:dstport=53", ["fortigate:1", "fortigate:2", "fortigate:4", "fortigate:7"])
        await expect(s, "forti sev:<=warn type=utm", ["fortigate:4", "fortigate:5"])
        // Other
        // Round 17 added CORE-RTR1's OSPF authentication lines (other 81–82).
        await expect(s, "host:CORE- NOT lldp", ["other:1", "other:2", "other:80", "other:81"])
        await expect(s, #"vendor:other sshd "Failed password""#, ["other:8"])
        await expect(s, "app:%ASA-4 OR app:%LINK", ["other:0", "other:6", "other:35", "other:36", "other:68"])
        // Traps
        await expect(s, "trap linkDown", ["trap:0"])
        await expect(s, "vendor:trap f:ifIndex=3", ["trap:0"])
        // "trap" is also a plain word: Huawei's LLDP/4/NBRCHGTRAP contains it.
        // A bare word is also a raw substring: Junos's SNMP_TRAP_LINK_DOWN lines (round 17) say "trap".
        await expect(s, "trap sev:<=warn", ["trap:0", "trap:1", "trap:2", "huawei:4", "other:76", "other:78"])
        await expect(s, "vendor:trap -linkDown", ["trap:1", "trap:2"])
    }

    func testGrammarSemantics() async throws {
        let s = try corpusStore()
        let all = try Self.loadCorpus()
        // sev:>=notice = notice or less severe (rawValue >= 5); sev:<=warn = warning or worse.
        let noticeOrLess = await hits(s, "sev:>=notice")
        XCTAssertEqual(noticeOrLess, Set(s.entries.filter { $0.severity.rawValue >= 5 }.compactMap { keyOf[$0.id] }))
        XCTAssertTrue(noticeOrLess.contains("arubacx:6"), "debug is below notice")
        XCTAssertFalse(noticeOrLess.contains("arubacx:0"), "warning is above notice")
        let warnOrWorse = await hits(s, "sev:<=warn")
        XCTAssertEqual(warnOrWorse, Set(s.entries.filter { $0.severity.rawValue <= 4 }.compactMap { keyOf[$0.id] }))
        await expect(s, "sev:>=notice vendor:other host:web01",
                     ["other:7", "other:8", "other:9", "other:11", "other:12", "other:13", "other:18"])
        await expect(s, "sev:<=warn host:web01", ["other:10"])
        // A leading "-" inside quotes is text, not negation.
        await expect(s, #""-Excessive""#, ["arubasw:2"])
        // Keys are case-insensitive.
        await expect(s, "F:srcip=10.1.0.9", ["fortigate:7"])
        await expect(s, "Host:web01", ["other:7", "other:8", "other:9", "other:10", "other:11", "other:12", "other:13", "other:18"])
        // host: on a complete address is exact; a trailing dot is the prefix form; it matches
        // the source address or the hostname.
        await expect(s, "host:192.168.9.1", ["other:0"])
        await expect(s, "host:10.1.0.20", ["arubasw:0"])
        await expect(s, "host:10.1.", ["arubaos:5", "arubasw:0", "clearpass:3", "trap:0", "trap:1", "trap:2"])
        let huaweiByAddress = await hits(s, "host:192.168.5.")
        XCTAssertEqual(huaweiByAddress.count, all.filter { $0.file == "huawei" }.count)
        await expect(s, "-host:192.168.9. host:192.168.9", [])
        // An unknown key is a text search for "key:value" (unless the line has that field).
        await expect(s, "in:ether1", ["other:15"])
        await expect(s, "foo:bar", [])
        await expect(s, "service:22", ["checkpoint:0"])
        // A log key whose value does not parse falls back to the line's field of that name.
        await expect(s, "severity:high", ["checkpoint:3", "paloalto:10"])
        // …but a severity word that parses is the syslog severity (PAN-OS "critical" → error).
        await expect(s, "severity:informational vendor:palo",
                     ["paloalto:0", "paloalto:2", "paloalto:6", "paloalto:7", "paloalto:8", "paloalto:9", "paloalto:11", "paloalto:13",
                      "paloalto:15", "paloalto:17"])      // round 17: link-change / HA2 link up
        await expect(s, "proto:udp vendor:palo", ["paloalto:0"])
        // Numbers are whole: 44 is not 443/445; leading zeros do not matter.
        await expect(s, "f:dport=44", [])
        await expect(s, "f:dport=443", ["paloalto:3", "paloalto:9"])
        await expect(s, "f:logid=13 forti", ["fortigate:0", "fortigate:1", "fortigate:7"])
        // Values that name a field (key=value as a bare word) also match the field; the
        // vendor word "aruba" covers all four Aruba families.
        await expect(s, "action:Accept", ["checkpoint:1", "checkpoint:4", "checkpoint:6", "fortigate:7"])
        await expect(s, "aruba sev:<=crit", ["arubacx:3", "arubacx:4", "arubaos:7"])
        await expect(s, "f:User=admin", ["huawei:1", "clearpass:5", "fortigate:2"])
        // vendor: takes an exact alias over a prefix: "cp" is Check Point, not also ClearPass ("cppm").
        await expect(s, "vendor:cp sev:<=err", ["checkpoint:2", "checkpoint:3"])
    }

    /// The one-line fixtures every vendor contributes to Tests/replay.sh are in the corpus too.
    func testReplayScriptSendsTheCorpus() throws {
        let script = try String(contentsOf: Self.dir.deletingLastPathComponent().appending(path: "replay.sh"), encoding: .utf8)
        XCTAssertTrue(script.contains("corpus"), "replay.sh sends Tests/corpus/*.log")
    }
}
