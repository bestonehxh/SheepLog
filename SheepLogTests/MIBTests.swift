import XCTest
@testable import SheepLog

@MainActor
final class MIBTests: XCTestCase {
    /// The bundled MIBs: from the app bundle when the tests run inside the host app, else
    /// straight from the repository.
    static func bundledURLs() -> [URL] {
        let fromBundle = MIBRegistry.bundledURLs()
        if fromBundle.count >= 60 { return fromBundle }
        let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appending(path: "SheepLog/MIBs")
        return ((try? FileManager.default.contentsOfDirectory(at: repo, includingPropertiesForKeys: nil)) ?? [])
            .filter { $0.pathExtension == "mib" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    private static var cached: MIBRegistry?

    private func registry() -> MIBRegistry {
        if let r = Self.cached { return r }
        let r = MIBRegistry()
        r.userFolderOverride = FileManager.default.temporaryDirectory.appending(path: "SheepLogMIBTests-\(UUID().uuidString)")
        r.loadNow(bundled: Self.bundledURLs())
        Self.cached = r
        return r
    }

    func testEveryBundledModuleParsesWithoutErrors() {
        let urls = Self.bundledURLs()
        XCTAssertEqual(urls.count, 63)
        let reg = registry()
        XCTAssertEqual(reg.modules.count, 63)
        for m in reg.modules {
            XCTAssertEqual(m.errors, [], m.name)
            XCTAssertTrue(m.builtIn)
        }
        XCTAssertGreaterThan(reg.nodeCount, 2_000)
        // Everything the bundled set imports is bundled (RFC-1212 only supplies a macro).
        let missing = reg.modules.filter { !$0.missingImports.isEmpty }.map { "\($0.name): \($0.missingImports)" }
        XCTAssertEqual(missing, [])
    }

    func testNameLookups() {
        let reg = registry()
        let ifOperStatus = OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 8])
        XCTAssertEqual(reg.oid(forName: "IF-MIB::ifOperStatus"), ifOperStatus)
        XCTAssertEqual(reg.oid(forName: "ifOperStatus"), ifOperStatus)
        XCTAssertEqual(reg.oid(forName: "ifoperstatus"), ifOperStatus)
        XCTAssertEqual(reg.oid(forName: "ifDescr.1"), OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1]))
        XCTAssertEqual(reg.oid(forName: ".1.3.6.1.2.1.1"), .system)
        XCTAssertEqual(reg.oid(forName: "1.3.6.1.2.1.1.5.0"), .sysName)
        XCTAssertEqual(reg.oid(forName: "enterprises.14823"), OID([1, 3, 6, 1, 4, 1, 14823]))
        XCTAssertEqual(reg.oid(forName: "sysUpTime"), OID([1, 3, 6, 1, 2, 1, 1, 3]))
        XCTAssertEqual(reg.oid(forName: "ifXTable"), .ifXTable)
        XCTAssertEqual(reg.oid(forName: "snmpTrapOID.0"), .snmpTrapOID)
        XCTAssertNil(reg.oid(forName: "noSuchThingAnywhere"))
        XCTAssertNil(reg.oid(forName: "IF-MIB::sysDescr"))

        XCTAssertEqual(reg.name(for: ifOperStatus.appending(24)), "ifOperStatus.24")
        XCTAssertEqual(reg.qualifiedName(for: ifOperStatus.appending(24)), "IF-MIB::ifOperStatus.24")
        XCTAssertEqual(reg.name(for: .sysDescr), "sysDescr.0")
        XCTAssertEqual(reg.name(for: OID([1, 3, 6, 1, 4, 1, 99999, 1])), "enterprises.99999.1")
        XCTAssertEqual(reg.name(for: OID([1, 3, 6, 1, 6, 3, 1, 1, 5, 3])), "linkDown")
        XCTAssertEqual(reg.name(for: OID([1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6, 5])), "ifHCInOctets.5")

        let c = reg.completions(prefix: "ifOper")
        XCTAssertTrue(c.contains("ifOperStatus"), "\(c)")
        XCTAssertEqual(c, c.sorted { $0.lowercased() < $1.lowercased() })
        XCTAssertTrue(reg.completions(prefix: "IF-MIB::ifAdmin").contains("ifAdminStatus"))
        XCTAssertLessThanOrEqual(reg.completions(prefix: "i", limit: 5).count, 5)
    }

    func testKindsAndTree() {
        let reg = registry()
        func kind(_ name: String) -> String? { reg.oid(forName: name).flatMap { reg.exactNode($0)?.kind } }
        XCTAssertEqual(kind("ifTable"), "table")
        XCTAssertEqual(kind("ifEntry"), "row")
        XCTAssertEqual(kind("ifDescr"), "column")
        XCTAssertEqual(kind("ifHCInOctets"), "column")
        XCTAssertEqual(kind("sysDescr"), "scalar")
        XCTAssertEqual(kind("linkDown"), "notification")
        XCTAssertEqual(kind("ifMIB"), "module")
        XCTAssertEqual(kind("system"), "node")

        let kids = reg.children(of: OID([1, 3, 6, 1, 2, 1]))
        XCTAssertEqual(kids.first?.name, "system")
        XCTAssertTrue(kids.contains { $0.name == "interfaces" })
        XCTAssertEqual(kids.map { $0.oid }, kids.map { $0.oid }.sorted())
        XCTAssertEqual(reg.children(of: OID([1])).first?.name, "org")
        // lldp lives under iso(1).std(0) which no bundled module names — it still hangs off iso.
        XCTAssertFalse(reg.children(of: OID([1, 3, 6, 1, 4, 1])).isEmpty, "enterprises has vendor subtrees (net-snmp, UCD)")
    }

    func testFormatting() {
        let reg = registry()
        let ifOper = OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 24])
        XCTAssertEqual(reg.format(VarBind(ifOper, .integer(1))), "up(1)")
        XCTAssertEqual(reg.format(VarBind(ifOper, .integer(2))), "down(2)")
        XCTAssertEqual(reg.format(VarBind(ifOper, .integer(99))), "99")
        // ifType through the IANAifType textual convention.
        XCTAssertEqual(reg.format(VarBind(OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 3, 1]), .integer(6))), "ethernetCsmacd(6)")
        // ifPhysAddress: PhysAddress DISPLAY-HINT "1x:".
        let mac = VarBind(OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 6, 3]), .octetString(Data([0x00, 0x1A, 0x1E, 0xAA, 0xBB, 0xCC])))
        XCTAssertEqual(reg.format(mac), "00:1a:1e:aa:bb:cc")
        // sysUpTime pretty.
        let up = reg.format(VarBind(.sysUpTime, .timeTicks(8_640_000 + 366_100)))
        XCTAssertTrue(up.hasPrefix("1d 01:01:01"), up)
        // OID values by name.
        XCTAssertEqual(reg.format(VarBind(.sysObjectID, .oid(OID([1, 3, 6, 1, 4, 1, 99999, 1])))), "enterprises.99999.1")
        XCTAssertEqual(reg.format(VarBind(.snmpTrapOID, .oid(OID([1, 3, 6, 1, 6, 3, 1, 1, 5, 4])))), "linkUp")
        // TruthValue through SNMPv2-TC.
        XCTAssertEqual(reg.format(VarBind(OID([1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 16, 2]), .integer(1))), "true(1)")
        XCTAssertEqual(reg.format(VarBind(OID([1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 14, 2]), .integer(1))), "enabled(1)")
        // DateAndTime (hrSystemDate).
        let date = VarBind(OID([1, 3, 6, 1, 2, 1, 25, 1, 2, 0]), .octetString(Data([0x07, 0xEA, 9, 23, 14, 5, 3, 4, 0x2B, 7, 0])))
        XCTAssertEqual(reg.format(date), "2026-09-23 14:05:03.4 +07:00")
        // DisplayString stays text.
        XCTAssertEqual(reg.format(VarBind(.sysDescr, .octetString(Data("Aruba JL658A".utf8)))), "Aruba JL658A")
    }

    func testDisplayHintEngine() {
        XCTAssertEqual(MIBFormat.octets([10, 1, 0, 1], hint: "1d.1d.1d.1d"), "10.1.0.1")
        XCTAssertEqual(MIBFormat.octets([0xDE, 0xAD, 0xBE, 0xEF], hint: "1x:"), "de:ad:be:ef")
        XCTAssertEqual(MIBFormat.octets(Array("hello".utf8), hint: "255a"), "hello")
        XCTAssertEqual(MIBFormat.octets([0x01, 0x02, 0x03, 0x04], hint: "2x-"), "0102-0304")
        XCTAssertEqual(MIBFormat.integer(1234, hint: "d-2"), "12.34")
        XCTAssertEqual(MIBFormat.integer(-5, hint: "d-2"), "-0.05")
        XCTAssertEqual(MIBFormat.integer(255, hint: "x"), "ff")
        XCTAssertNil(MIBFormat.octets([1], hint: "zz"))
        XCTAssertEqual(MIBFormat.bits([0b1010_0000], labels: [0: "a", 1: "b", 2: "c"]), "a(0) c(2)")
    }

    func testParserConstructs() {
        let text = """
        TEST-MIB DEFINITIONS ::= BEGIN
        IMPORTS
            OBJECT-TYPE, Integer32 FROM SNMPv2-SMI  -- comment -- DisplayString FROM SNMPv2-TC;
        -- a comment with "quotes" and ::= inside
        testRoot OBJECT IDENTIFIER ::= { iso org(3) dod(6) 1 4 1 424242 }
        Colour ::= TEXTUAL-CONVENTION
            DISPLAY-HINT "d"
            STATUS current
            DESCRIPTION "A ""colour"" -- not a comment"
            SYNTAX INTEGER { red(1), green(2), -- inline
                             blue(3) }
        Flags ::= TEXTUAL-CONVENTION STATUS current DESCRIPTION "bits" SYNTAX BITS { a(0), b(1) }
        TestEntry ::= SEQUENCE { testIndex Integer32, testColour Colour }
        testTable OBJECT-TYPE SYNTAX SEQUENCE OF TestEntry MAX-ACCESS not-accessible STATUS current
            DESCRIPTION "t" ::= { testRoot 1 }
        testEntry OBJECT-TYPE SYNTAX TestEntry MAX-ACCESS not-accessible STATUS current
            DESCRIPTION "e" INDEX { testIndex } ::= { testTable 1 }
        testIndex OBJECT-TYPE SYNTAX Integer32 (1..2147483647) MAX-ACCESS not-accessible STATUS current
            DESCRIPTION "i" ::= { testEntry 1 }
        testColour OBJECT-TYPE SYNTAX Colour MAX-ACCESS read-only STATUS current
            DESCRIPTION "c" DEFVAL { red } ::= { testEntry 2 }
        testName OBJECT-TYPE SYNTAX DisplayString (SIZE (0..255)) ACCESS read-only STATUS mandatory
            DESCRIPTION "n" ::= { testRoot 2 }
        testTrap TRAP-TYPE ENTERPRISE testRoot VARIABLES { testName } DESCRIPTION "v1 trap" ::= 7
        gibberish WIBBLE-MACRO FOO BAR ::= { testRoot 9 }
        END
        """
        let r = MIBParser.parse(text, fileName: "x")
        XCTAssertEqual(r.moduleName, "TEST-MIB")
        XCTAssertEqual(r.imports["SNMPv2-SMI"], ["OBJECT-TYPE", "Integer32"])
        XCTAssertEqual(r.imports["SNMPv2-TC"], ["DisplayString"])
        let byName = Dictionary(r.nodes.map { ($0.name, $0) }, uniquingKeysWith: { a, _ in a })
        XCTAssertEqual(byName["org"]?.parent, "iso")
        XCTAssertEqual(byName["dod"]?.arcs, [6])
        XCTAssertEqual(byName["testRoot"]?.parent, "dod")
        XCTAssertEqual(byName["testRoot"]?.arcs, [1, 4, 1, 424242])
        XCTAssertEqual(byName["testTable"]?.kind, "table")
        XCTAssertEqual(byName["testEntry"]?.kind, "row")
        XCTAssertEqual(byName["testIndex"]?.kind, "column")
        XCTAssertEqual(byName["testColour"]?.syntax, "Colour")
        XCTAssertEqual(byName["testName"]?.kind, "scalar")
        XCTAssertEqual(byName["testName"]?.access, "read-only")
        XCTAssertEqual(byName["testTrap"]?.parent, "testRoot")
        XCTAssertEqual(byName["testTrap"]?.arcs, [0, 7])
        XCTAssertEqual(byName["testTrap"]?.kind, "notification")
        XCTAssertEqual(r.textualConventions["Colour"]?.enums, [1: "red", 2: "green", 3: "blue"])
        XCTAssertEqual(r.textualConventions["Colour"]?.description, "A \"colour\" -- not a comment")
        XCTAssertEqual(r.textualConventions["Flags"]?.syntax, "BITS")
        XCTAssertNil(r.textualConventions["TestEntry"])
        XCTAssertEqual(r.errors.count, 1, "\(r.errors)")   // the WIBBLE-MACRO line

        // Linked through a registry: TC enums reach the column.
        let reg = MIBRegistry()
        let dir = FileManager.default.temporaryDirectory.appending(path: "SheepLogParser-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let file = dir.appending(path: "TEST-MIB.mib")
        try? text.write(to: file, atomically: true, encoding: .utf8)
        reg.loadNow(bundled: Self.bundledURLs(), user: [file])
        let col = OID([1, 3, 6, 1, 4, 1, 424242, 1, 1, 2, 5])
        XCTAssertEqual(reg.name(for: col), "testColour.5")
        XCTAssertEqual(reg.format(VarBind(col, .integer(3))), "blue(3)")
        XCTAssertEqual(reg.name(for: OID([1, 3, 6, 1, 4, 1, 424242, 0, 7])), "testTrap")
        let mod = reg.modules.first { $0.name == "TEST-MIB" }
        XCTAssertEqual(mod?.builtIn, false)
        XCTAssertEqual(mod?.errors.count, 1)
    }

    func testMissingImportsAndLastResortLinking() {
        let text = """
        VENDOR-MIB DEFINITIONS ::= BEGIN
        IMPORTS enterprises FROM SNMPv2-SMI vendorRoot FROM VENDOR-SMI-MIB;
        sloppy OBJECT IDENTIFIER ::= { ifMIB 99 }
        lost OBJECT IDENTIFIER ::= { vendorRoot 1 }
        END
        """
        let dir = FileManager.default.temporaryDirectory.appending(path: "SheepLogVendor-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let file = dir.appending(path: "VENDOR-MIB")
        try? text.write(to: file, atomically: true, encoding: .utf8)
        let reg = MIBRegistry()
        reg.loadNow(bundled: Self.bundledURLs(), user: [file])
        // `ifMIB` is not imported, but IF-MIB defines it: linked as a last resort.
        XCTAssertEqual(reg.oid(forName: "sloppy"), OID([1, 3, 6, 1, 2, 1, 31, 99]))
        XCTAssertNil(reg.oid(forName: "lost"))
        let mod = reg.modules.first { $0.name == "VENDOR-MIB" }
        XCTAssertEqual(mod?.missingImports, ["VENDOR-SMI-MIB"])
        XCTAssertEqual(mod?.nodeCount, 1)
    }

    func testParserSurvivesGarbageAndTruncation() {
        var rng = SystemRandomNumberGenerator()
        for url in Self.bundledURLs().prefix(12) {
            guard let text = try? String(contentsOf: url, encoding: .utf8) else { continue }
            for _ in 0..<4 {
                let cut = Int.random(in: 0...text.utf8.count, using: &rng)
                let prefix = String(decoding: Array(text.utf8).prefix(cut), as: UTF8.self)
                _ = MIBParser.parse(prefix, fileName: "cut")
            }
        }
        let alphabet = Array("{}()::=--\"'abcXYZ019 \n.,;OBJECT-TYPE SYNTAX INTEGER END BEGIN DEFINITIONS MACRO".utf8)
        for _ in 0..<300 {
            let bytes = (0..<Int.random(in: 0...400, using: &rng)).map { _ in alphabet.randomElement(using: &rng)! }
            _ = MIBParser.parse(String(decoding: bytes, as: UTF8.self), fileName: "fuzz")
        }
    }

    func testTrapEntryNaming() {
        let reg = registry()
        let trap = SNMPTrap(received: Date(), sourceAddress: "10.1.0.1", sourcePort: 50000, version: .v2c,
                            community: "public", trapOID: OID([1, 3, 6, 1, 6, 3, 1, 1, 5, 3]), uptime: 12345,
                            agentAddress: nil,
                            varBinds: [VarBind(OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 7]), .integer(7)),
                                       VarBind(OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 7, 7]), .integer(1)),
                                       VarBind(OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 7]), .integer(2))])
        let e = TrapReceiver.entry(for: trap, registry: reg)
        XCTAssertEqual(e.program, "linkDown")
        XCTAssertEqual(e.severity, .warning)
        XCTAssertEqual(e.vendor, .snmpTrap)
        XCTAssertEqual(e.transport, .trap)
        XCTAssertEqual(e.facility, .local0)
        XCTAssertEqual(e.message, "linkDown ifIndex.7=7, ifAdminStatus.7=up(1), ifOperStatus.7=down(2)")
        XCTAssertEqual(e.field("ifOperStatus.7"), "down(2)")
        XCTAssertEqual(e.field("trap_oid"), "1.3.6.1.6.3.1.1.5.3")
        XCTAssertEqual(e.field("version"), "v2c")
        XCTAssertEqual(e.field("community"), "public")
        XCTAssertEqual(e.field("uptime"), "00:02:03")

        let v1 = SNMPTrap(received: Date(), sourceAddress: "192.0.2.9", sourcePort: 162, version: .v1, community: "public",
                          trapOID: OID([1, 3, 6, 1, 4, 1, 99999, 0, 5]), uptime: nil, agentAddress: "10.9.9.9", varBinds: [])
        let e1 = TrapReceiver.entry(for: v1, registry: reg)
        XCTAssertEqual(e1.hostname, "10.9.9.9")
        XCTAssertEqual(e1.sourceAddress, "192.0.2.9")
        XCTAssertEqual(e1.severity, .notice)
        XCTAssertEqual(e1.program, "enterprises.99999.0.5")
    }

    func testLoadTimeIsReasonable() {
        let urls = Self.bundledURLs()
        let start = Date()
        let reg = MIBRegistry()
        reg.loadNow(bundled: urls)
        XCTAssertWithinBudget(Date().timeIntervalSince(start), 10)
    }
}

// MARK: - Adversarial review: parser robustness, registry state, lookups

extension MIBTests {
    private func tempDir(_ tag: String) -> URL {
        let dir = FileManager.default.temporaryDirectory.appending(path: "SheepLog\(tag)-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func write(_ text: String, _ name: String, in dir: URL) -> URL {
        let url = dir.appending(path: name)
        try? text.write(to: url, atomically: true, encoding: .utf8)
        return url
    }

    /// Waits until the registry has installed everything that was queued.
    private func settle(_ reg: MIBRegistry, timeout: TimeInterval = 20) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while reg.isLoading, Date() < deadline { try await Task.sleep(for: .milliseconds(10)) }
        XCTAssertFalse(reg.isLoading, "registry never settled")
    }

    private static let vendorTC = """
    ACME-TC-MIB DEFINITIONS ::= BEGIN
    IMPORTS enterprises, MODULE-IDENTITY FROM SNMPv2-SMI TEXTUAL-CONVENTION FROM SNMPv2-TC;
    acme OBJECT IDENTIFIER ::= { enterprises 424243 }
    AcmeState ::= TEXTUAL-CONVENTION STATUS current DESCRIPTION "s" SYNTAX INTEGER { idle(1), busy(2) }
    AcmeFlags ::= TEXTUAL-CONVENTION STATUS current DESCRIPTION "f" SYNTAX BITS { red(0), green(1), blue(2), ninth(9) }
    END
    """

    /// Two modules in one file are two modules: a third file importing from the first one
    /// must link without missing imports.
    func testTwoModulesInOneFile() {
        let both = Self.vendorTC + "\n" + """
        ACME-MIB DEFINITIONS ::= BEGIN
        IMPORTS OBJECT-TYPE FROM SNMPv2-SMI acme, AcmeState FROM ACME-TC-MIB;
        acmeState OBJECT-TYPE SYNTAX AcmeState MAX-ACCESS read-only STATUS current DESCRIPTION "x" ::= { acme 1 }
        END
        """
        let results = MIBParser.parseModules(both, fileName: "acme")
        XCTAssertEqual(results.map(\.moduleName), ["ACME-TC-MIB", "ACME-MIB"])
        XCTAssertEqual(results[0].textualConventions.keys.sorted(), ["AcmeFlags", "AcmeState"])
        XCTAssertEqual(results[1].nodes.map(\.name), ["acmeState"])

        let dir = tempDir("TwoModules")
        let file = write(both, "acme.my", in: dir)
        let other = write("""
            ACME-EXTRA-MIB DEFINITIONS ::= BEGIN
            IMPORTS OBJECT-TYPE FROM SNMPv2-SMI acme, AcmeFlags FROM ACME-TC-MIB;
            acmeFlags OBJECT-TYPE SYNTAX AcmeFlags MAX-ACCESS read-only STATUS current DESCRIPTION "x" ::= { acme 2 }
            END
            """, "ACME-EXTRA-MIB.mib", in: dir)
        let reg = MIBRegistry()
        reg.loadNow(bundled: Self.bundledURLs(), user: [file, other])
        for name in ["ACME-TC-MIB", "ACME-MIB", "ACME-EXTRA-MIB"] {
            let m = reg.modules.first { $0.name == name }
            XCTAssertNotNil(m, name)
            XCTAssertEqual(m?.missingImports, [], name)
            XCTAssertEqual(m?.errors, [], name)
        }
        // INTEGER enum and BITS through a textual convention defined in another module.
        let base = OID([1, 3, 6, 1, 4, 1, 424243])
        XCTAssertEqual(reg.format(VarBind(base.appending([1, 0]), .integer(2))), "busy(2)")
        XCTAssertEqual(reg.format(VarBind(base.appending([2, 0]), .octetString(Data([0b1010_0000, 0b0100_0000])))),
                       "red(0) blue(2) ninth(9)")
    }

    /// "-----" (odd number of dashes) leaves a lone "-" after the comments; it must not swallow
    /// the next definition.
    func testOddDashSeparatorLine() {
        let r = MIBParser.parse("""
            X-MIB DEFINITIONS ::= BEGIN
            -----
            a OBJECT IDENTIFIER ::= { enterprises 1 }
            ---------------------------------------------------------------------------
            b OBJECT IDENTIFIER ::= { a 2 }
            END
            """, fileName: "x")
        XCTAssertEqual(r.nodes.map(\.name), ["a", "b"])
        XCTAssertEqual(r.errors, [])
    }

    func testParserOddButLegalShapes() {
        let text = "\u{FEFF}" + [
            "WEIRD-MIB DEFINITIONS ::= BEGIN",
            "IMPORTS OBJECT-TYPE, Integer32 FROM SNMPv2-SMI;",
            "-- child before parent (forward reference)",
            "wChild\tOBJECT-TYPE SYNTAX INTEGER { up(1), -- one",
            "    down(2) } MAX-ACCESS read-only STATUS current DESCRIPTION \"-- not a comment\" ::= { wEntry 3 }",
            "wEntry OBJECT-TYPE SYNTAX WEntry MAX-ACCESS not-accessible STATUS current DESCRIPTION \"e\"",
            "    INDEX { IMPLIED wName } ::= { wTable 1 }",
            "wTable OBJECT-TYPE SYNTAX SEQUENCE OF WEntry MAX-ACCESS not-accessible STATUS current DESCRIPTION \"t\" ::= { wRoot 1 }",
            "wName OBJECT-TYPE SYNTAX OCTET STRING MAX-ACCESS not-accessible STATUS current DESCRIPTION \"n\"",
            "    DEFVAL { { 'ff'H, \"}\" } } ::= { wEntry 1 }",
            "wRoot OBJECT IDENTIFIER ::= { iso(1) 3 6 1 4 1 424244 }",
            "wZero OBJECT IDENTIFIER ::= { iso(1) 3 }",
            "END",
        ].joined(separator: "\r\n")
        let r = MIBParser.parse(text, fileName: "w")
        XCTAssertEqual(r.moduleName, "WEIRD-MIB")
        XCTAssertEqual(r.errors, [])
        let byName = Dictionary(r.nodes.map { ($0.name, $0) }, uniquingKeysWith: { a, _ in a })
        XCTAssertEqual(byName["wChild"]?.enums, [1: "up", 2: "down"])
        XCTAssertEqual(byName["wChild"]?.kind, "column")
        XCTAssertEqual(byName["wChild"]?.description, "-- not a comment")
        XCTAssertEqual(byName["wEntry"]?.kind, "row")
        XCTAssertEqual(byName["wRoot"]?.parent, "1")
        XCTAssertEqual(byName["wRoot"]?.arcs, [3, 6, 1, 4, 1, 424244])
        XCTAssertEqual(byName["wZero"]?.arcs, [3])

        let dir = tempDir("Weird")
        let reg = MIBRegistry()
        reg.loadNow(bundled: Self.bundledURLs(), user: [write(text, "WEIRD-MIB", in: dir)])
        XCTAssertEqual(reg.oid(forName: "wChild"), OID([1, 3, 6, 1, 4, 1, 424244, 1, 1, 3]))
    }

    /// A 20,000-object vendor MIB (~5 MB) parses and links in well under 2 s (Debug build).
    func testLargeVendorMIBIsFast() {
        var text = """
        BIG-MIB DEFINITIONS ::= BEGIN
        IMPORTS enterprises, OBJECT-TYPE, Integer32 FROM SNMPv2-SMI DisplayString FROM SNMPv2-TC;
        big OBJECT IDENTIFIER ::= { enterprises 424245 }

        """
        for t in 0..<400 {
            text += """
            bigTable\(t) OBJECT-TYPE SYNTAX SEQUENCE OF BigEntry\(t) MAX-ACCESS not-accessible STATUS current
                DESCRIPTION "Table \(t) of the synthetic vendor MIB, with a description long enough to look like the real thing."
                ::= { big \(t + 1) }
            bigEntry\(t) OBJECT-TYPE SYNTAX BigEntry\(t) MAX-ACCESS not-accessible STATUS current
                DESCRIPTION "Row." INDEX { bigIndex\(t) } ::= { bigTable\(t) 1 }

            """
            for c in 0..<48 {
                text += """
                bigCol\(t)x\(c) OBJECT-TYPE SYNTAX INTEGER { enabled(1), disabled(2), -- inline
                        unknown(3) } MAX-ACCESS read-only STATUS current
                    DESCRIPTION "Column \(c) of table \(t). Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do
                    eiusmod tempor incididunt ut labore et dolore magna aliqua -- not a comment."
                    DEFVAL { enabled } ::= { bigEntry\(t) \(c + 1) }

                """
            }
        }
        text += "END\n"
        XCTAssertGreaterThan(text.utf8.count, 5_000_000)
        let t0 = Date()
        let r = MIBParser.parse(text, fileName: "big")
        let parse = Date().timeIntervalSince(t0)
        XCTAssertEqual(r.nodes.count, 1 + 400 * 50)
        XCTAssertEqual(r.errors, [])
        let t1 = Date()
        let idx = MIBIndex.build([MIBParsedFile(result: r, url: nil, builtIn: false)])
        let link = Date().timeIntervalSince(t1)
        XCTAssertGreaterThan(idx.objectCount, 20_000)
        print("20k-object MIB: \(text.utf8.count) bytes, parse \(parse) s, link \(link) s")
        XCTAssertWithinBudget(parse + link, 2)
    }

    /// Two imports in flight (or an import during the launch load) must not drop each other.
    func testConcurrentImportsKeepEachOther() async throws {
        let src = tempDir("ImportSrc")
        let a = write(Self.vendorTC, "ACME-TC-MIB.mib", in: src)
        let b = write("""
            OTHER-MIB DEFINITIONS ::= BEGIN
            IMPORTS enterprises FROM SNMPv2-SMI;
            other OBJECT IDENTIFIER ::= { enterprises 424246 }
            END
            """, "OTHER-MIB.mib", in: src)
        let reg = MIBRegistry()
        reg.userFolderOverride = tempDir("ImportDst")
        reg.loadNow(bundled: Self.bundledURLs())
        reg.importFiles([a])
        reg.importFiles([b])
        try await settle(reg)
        let names = Set(reg.modules.map(\.name))
        XCTAssertTrue(names.isSuperset(of: ["ACME-TC-MIB", "OTHER-MIB", "IF-MIB"]), "\(names.count) modules")
    }

    /// Re-importing a module under another file name replaces it (file and entry), and a
    /// selected `.DS_Store` is not a module.
    func testReimportSameModuleReplacesAndHiddenFilesAreSkipped() async throws {
        let src = tempDir("Reimport")
        let first = write(Self.vendorTC, "acme-v1.my", in: src)
        let second = write(Self.vendorTC.replacingOccurrences(of: "busy(2)", with: "busy(2), broken(3)"), "acme-v2.my", in: src)
        let ds = write("\u{0}\u{0}\u{0}\u{1}Bud1", ".DS_Store", in: src)
        let dst = tempDir("ReimportDst")
        let reg = MIBRegistry()
        reg.userFolderOverride = dst
        reg.loadNow(bundled: Self.bundledURLs())
        reg.importFiles([first, ds])
        try await settle(reg)
        reg.importFiles([second])
        try await settle(reg)
        XCTAssertEqual(reg.modules.filter { $0.name == "ACME-TC-MIB" }.count, 1)
        XCTAssertFalse(reg.modules.contains { $0.name.hasPrefix(".") })
        let files = (try? FileManager.default.contentsOfDirectory(atPath: dst.path)) ?? []
        XCTAssertEqual(files.sorted(), ["acme-v2.my"])
        // Importing the whole folder (500 files) does not block the caller.
        let many = tempDir("Many")
        for k in 0..<500 {
            _ = write("M\(k)-MIB DEFINITIONS ::= BEGIN\nIMPORTS enterprises FROM SNMPv2-SMI;\nm\(k) OBJECT IDENTIFIER ::= { enterprises \(500_000 + k) }\nEND\n",
                      "M\(k)-MIB.mib", in: many)
        }
        let t0 = Date()
        reg.importFiles([many])
        XCTAssertWithinBudget(Date().timeIntervalSince(t0), 0.1, "copying 500 files must not run on the main thread")
        XCTAssertTrue(reg.isLoading)
        try await settle(reg)
        XCTAssertEqual(reg.modules.filter { $0.name.hasPrefix("M") && $0.name.hasSuffix("-MIB") && !$0.builtIn }.count, 500)
        XCTAssertEqual(reg.oid(forName: "m499"), OID([1, 3, 6, 1, 4, 1, 500_499]))
    }

    /// Removing a module others import relinks them and reports the missing import.
    func testRemovingAnImportedModuleReportsMissingImports() async throws {
        let src = tempDir("RemoveSrc")
        let tc = write(Self.vendorTC, "ACME-TC-MIB.mib", in: src)
        let user = write("""
            ACME-MIB DEFINITIONS ::= BEGIN
            IMPORTS OBJECT-TYPE FROM SNMPv2-SMI acme, AcmeState FROM ACME-TC-MIB;
            acmeState OBJECT-TYPE SYNTAX AcmeState MAX-ACCESS read-only STATUS current DESCRIPTION "x" ::= { acme 1 }
            END
            """, "ACME-MIB.mib", in: src)
        let reg = MIBRegistry()
        reg.userFolderOverride = tempDir("RemoveDst")
        reg.loadNow(bundled: Self.bundledURLs())
        reg.importFiles([tc, user])
        try await settle(reg)
        XCTAssertEqual(reg.modules.first { $0.name == "ACME-MIB" }?.missingImports, [])
        let tcModule = try XCTUnwrap(reg.modules.first { $0.name == "ACME-TC-MIB" })
        reg.remove(tcModule)
        try await settle(reg)
        XCTAssertNil(reg.modules.first { $0.name == "ACME-TC-MIB" })
        XCTAssertEqual(reg.modules.first { $0.name == "ACME-MIB" }?.missingImports, ["ACME-TC-MIB"])
        XCTAssertNil(reg.oid(forName: "acmeState"))
    }

    func testLookupEdgeCases() {
        let reg = registry()
        XCTAssertEqual(reg.name(for: OID([1])), "iso")
        XCTAssertEqual(reg.name(for: OID([])), "")
        XCTAssertEqual(reg.qualifiedName(for: OID([1, 3, 6, 1])), "SNMPv2-SMI::internet")
        XCTAssertNil(reg.oid(forName: "NOT-LOADED-MIB::ifDescr"))
        XCTAssertNil(reg.oid(forName: "IF-MIB::"))
        XCTAssertNil(reg.oid(forName: "::"))
        XCTAssertNil(reg.oid(forName: "."))
        XCTAssertEqual(reg.oid(forName: "ifDescr."), OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 2]))
        XCTAssertEqual(reg.oid(forName: "1.3.6.1."), OID([1, 3, 6, 1]))
        XCTAssertEqual(reg.oid(forName: "ifDescr.1.2.3"), OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1, 2, 3]))
        XCTAssertEqual(reg.oid(forName: "   ifDescr.1"), OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1]))
        XCTAssertNil(reg.oid(forName: "ifDescr.x"))
        XCTAssertEqual(reg.completions(prefix: "IFOPER"), reg.completions(prefix: "ifoper"))
        XCTAssertTrue(reg.completions(prefix: "SYSUP").contains("sysUpTime"))
        XCTAssertEqual(reg.completions(prefix: ""), [])
        XCTAssertEqual(reg.search("IFHCIN").first?.name, "ifHCInOctets")
    }

    func testDisplayHintEdgeCases() {
        // DateAndTime, 8- and 11-byte forms, and a bogus direction byte.
        XCTAssertEqual(MIBFormat.dateAndTime([0x07, 0xEA, 9, 23, 14, 5, 3, 4]), "2026-09-23 14:05:03.4")
        XCTAssertEqual(MIBFormat.dateAndTime([0x07, 0xEA, 9, 23, 14, 5, 3, 4, 0x2D, 5, 30]), "2026-09-23 14:05:03.4 -05:30")
        XCTAssertEqual(MIBFormat.dateAndTime([0x07, 0xEA, 9, 23, 14, 5, 3, 4, 0, 5, 30]), "2026-09-23 14:05:03.4")
        XCTAssertNil(MIBFormat.dateAndTime([1, 2, 3]))
        // The generic engine on the same hint.
        XCTAssertEqual(MIBFormat.octets([0x07, 0xEA, 9, 23, 14, 5, 3, 4, 0x2B, 7, 0], hint: MIBFormat.dateAndTimeHint),
                       "2026-9-23,14:5:3.4,+7:0")
        XCTAssertEqual(MIBFormat.octets(Array("héllo".utf8), hint: "255t"), "héllo")
        XCTAssertEqual(MIBFormat.octets([3, 1, 2, 3, 0xFF], hint: "*1d."), "1.2.3.")   // 0xFF = 255 repeats of nothing: no crash, no hang
        XCTAssertEqual(MIBFormat.octets([], hint: "1x:"), "")
        XCTAssertNotNil(MIBFormat.octets([1, 2, 3], hint: "0x"))       // zero-length spec: no hang
        XCTAssertNil(MIBFormat.octets([1], hint: "99999999999x"))
    }
}

extension MIBTests {
    /// The batch path gives exactly what the per-var-bind calls give, and a 10,000-row walk
    /// is described fast (it runs on the main actor as rows arrive).
    func testDescribeMatchesPerVarBindAndIsFast() {
        let reg = registry()
        var vbs: [VarBind] = []
        for col: UInt32 in [1, 2, 3, 5, 7, 8, 10, 16] {
            for i in 1...600 {
                let oid = OID([1, 3, 6, 1, 2, 1, 2, 2, 1, col, UInt32(i)])
                vbs.append(VarBind(oid, col == 2 ? .octetString(Data("port\(i)".utf8)) : .integer(Int64(i % 3 + 1))))
            }
        }
        for i in 1...2_000 {   // multi-arc index, unknown enterprise subtree, OID values
            vbs.append(VarBind(OID([1, 3, 6, 1, 2, 1, 4, 20, 1, 1, 10, 0, UInt32(i / 250), UInt32(i % 250)]), .ipAddress("10.0.0.1")))
            vbs.append(VarBind(OID([1, 3, 6, 1, 4, 1, 99999, 1, UInt32(i)]), .oid(OID([1, 3, 6, 1, 2, 1, 1]))))
        }
        vbs.append(VarBind(OID([1]), .null))
        let batch = reg.describe(vbs)
        for (vb, d) in zip(vbs, batch) {
            XCTAssertEqual(d.name, reg.name(for: vb.oid))
            XCTAssertEqual(d.value, reg.format(vb))
        }
        let t0 = Date()
        _ = reg.describe(Array(vbs.prefix(10_000)))
        let elapsed = Date().timeIntervalSince(t0)
        print("describe 10,000 var-binds: \(elapsed) s")
        XCTAssertWithinBudget(elapsed, 0.25)
    }
}

// MARK: - Round 2: values as the Test pane and the trap log show them

extension MIBTests {
    func testFormattingOfCommonObjects() {
        let reg = registry()
        let ifEntry = OID.ifTable.appending(1)
        // PhysAddress "1x:" — a MAC, leading zeros kept.
        XCTAssertEqual(reg.format(VarBind(ifEntry.appending([6, 12]), .octetString(Data([0x00, 0x72, 0xd4, 0xd9, 0x5a, 0xce])))),
                       "00:72:d4:d9:5a:ce")
        XCTAssertEqual(reg.format(VarBind(ifEntry.appending([6, 1]), .octetString(Data()))), "", "lo0 has no MAC")
        // TimeTicks: duration plus the raw ticks.
        XCTAssertEqual(reg.format(VarBind(.sysUpTime, .timeTicks(39_489))), "\(Format.uptime(ticks: 39_489)) (39489)")
        // Enumerations by name.
        XCTAssertEqual(reg.format(VarBind(ifEntry.appending([8, 3]), .integer(2))), "down(2)")
        XCTAssertEqual(reg.format(VarBind(ifEntry.appending([8, 3]), .integer(9))), "9", "unknown enum value stays a number")
        // Counter64 in full.
        XCTAssertEqual(reg.format(VarBind(OID.ifXTable.appending([1, 6, 12]), .counter64(18_446_744_073_709_551_615))),
                       "18446744073709551615")
        // DisplayString: UTF-8 text as is; binary as hex, not U+FFFD and control bytes.
        XCTAssertEqual(reg.format(VarBind(.sysDescr, .octetString(Data("Switch ไทย — v2".utf8)))), "Switch ไทย — v2")
        XCTAssertEqual(reg.format(VarBind(.sysDescr, .octetString(Data([0x00, 0x1a, 0xff, 0x80, 0x07])))), "00 1a ff 80 07")
        XCTAssertEqual(reg.format(VarBind(.sysDescr, .octetString(Data([0x41, 0x42, 0x07, 0x43])))), "41 42 07 43")
        XCTAssertEqual(reg.format(VarBind(.sysName, .octetString(Data("core-1\0".utf8)))), "core-1", "C string NUL dropped")
        XCTAssertEqual(reg.format(VarBind(.sysDescr, .octetString(Data("line 1\r\nline 2".utf8)))), "line 1\r\nline 2")
        // An object with no hint: the plain rule (printable UTF-8 or hex).
        XCTAssertEqual(reg.format(VarBind(OID([1, 3, 6, 1, 4, 1, 99999, 1]), .octetString(Data([0xde, 0xad, 0xbe, 0xef])))), "de ad be ef")
    }

    /// Trap log fields: v1 carries agent-addr and (RFC 3584) snmpTrapEnterprise.0; a v2 trap
    /// without snmpTrapOID.0 is not named after zeroDotZero.
    func testTrapEntryFieldsV1AndMissingTrapOID() throws {
        let reg = registry()
        let v1 = BER.encodeSequence([BER.encodeInteger(0), BER.encodeOctets(Array("public".utf8)),
                                     TrapV1PDU(enterprise: OID([1, 3, 6, 1, 4, 1, 14823]), agentAddress: "10.2.2.2",
                                               genericTrap: 0, specificTrap: 0, timeStamp: 77, varBinds: []).encoded()])
        guard case .trap(let t1) = TrapListener.decode(v1, host: "10.0.0.2", port: 162, received: Date()).item else {
            return XCTFail("v1 not decoded")
        }
        let e1 = TrapReceiver.entry(for: t1, registry: reg)
        XCTAssertEqual(e1.program, "coldStart")
        XCTAssertEqual(e1.severity, .warning)
        XCTAssertEqual(e1.field("snmpTrapEnterprise.0"), "enterprises.14823")
        XCTAssertEqual(e1.field("agent_addr"), "10.2.2.2")
        XCTAssertEqual(e1.hostname, "10.2.2.2")

        let noOID = CommunityMessage.encode(version: .v2c, community: "public",
                                            pdu: SNMPPDU(type: BER.trapV2, requestID: 1,
                                                         varBinds: [VarBind(.sysUpTimeInstance, .timeTicks(5))]).encoded())
        guard case .trap(let t2) = TrapListener.decode(noOID, host: "10.0.0.3", port: 162, received: Date()).item else {
            return XCTFail("v2 not decoded")
        }
        XCTAssertEqual(TrapReceiver.entry(for: t2, registry: reg).program, "snmpTrap")
        let warm = SNMPTrap(received: Date(), sourceAddress: "10.0.0.4", sourcePort: 162, version: .v2c, community: "c",
                            trapOID: OID([1, 3, 6, 1, 6, 3, 1, 1, 5, 2]), uptime: nil, agentAddress: nil, varBinds: [])
        XCTAssertEqual(TrapReceiver.entry(for: warm, registry: reg).severity, .warning, "warmStart like coldStart")
    }

    /// A vendor folder with a README next to the MIBs: the README is not imported as a
    /// "module" full of errors; a broken MIB still is (with its errors and missing imports).
    func testFolderImportSkipsNonMIBFiles() throws {
        let src = tempDir("Import"), user = tempDir("User")
        defer { try? FileManager.default.removeItem(at: src); try? FileManager.default.removeItem(at: user) }
        try "Load these into your NMS.\n".write(to: src.appending(path: "README.txt"), atomically: true, encoding: .utf8)
        try "-- notes\nTEST-OK-MIB DEFINITIONS ::= BEGIN\nIMPORTS enterprises FROM SNMPv2-SMI;\ntestOk OBJECT IDENTIFIER ::= { enterprises 99998 }\nEND\n"
            .write(to: src.appending(path: "TEST-OK-MIB.my"), atomically: true, encoding: .utf8)
        try "TEST-BROKEN-MIB DEFINITIONS\n    ::= BEGIN\nIMPORTS Foo FROM NOWHERE-MIB;\nbroken OBJECT-TYPE\n  SYNTAX Foo\n"
            .write(to: src.appending(path: "TEST-BROKEN-MIB"), atomically: true, encoding: .utf8)
        XCTAssertFalse(MIBRegistry.looksLikeMIB(src.appending(path: "README.txt")))
        XCTAssertTrue(MIBRegistry.looksLikeMIB(src.appending(path: "TEST-BROKEN-MIB")))

        let reg = MIBRegistry()
        reg.userFolderOverride = user
        reg.loadNow(bundled: Self.bundledURLs())
        let before = reg.modules.count
        reg.importFiles([src])
        let end = Date().addingTimeInterval(10)
        while reg.modules.count < before + 2, Date() < end { RunLoop.main.run(until: Date().addingTimeInterval(0.02)) }
        let mine = reg.modules.filter { !$0.builtIn }.map(\.name).sorted()
        XCTAssertEqual(mine, ["TEST-BROKEN-MIB", "TEST-OK-MIB"])
        XCTAssertFalse(FileManager.default.fileExists(atPath: user.appending(path: "README.txt").path))
        let broken = try XCTUnwrap(reg.modules.first { $0.name == "TEST-BROKEN-MIB" })
        XCTAssertEqual(broken.missingImports, ["NOWHERE-MIB"])
    }
}
