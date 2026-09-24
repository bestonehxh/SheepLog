import XCTest
@testable import SheepLog

/// Round 5: vendor MIB bundles (Tests/mibs/…, written in the shapes of the real Fortinet, Palo
/// Alto and Aruba modules) imported the way "Add files…" does it, into a registry that also has
/// the bundled standard modules.
@MainActor
final class Round5MIBTests: XCTestCase {
    static let mibDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .appending(path: "Tests/mibs")

    private var folders: [URL] = []

    override func tearDown() async throws {
        for f in folders { try? FileManager.default.removeItem(at: f) }
    }

    private func registry() -> MIBRegistry {
        let r = MIBRegistry()
        let folder = FileManager.default.temporaryDirectory.appending(path: "SheepLogRound5MIBs-\(UUID().uuidString)", directoryHint: .isDirectory)
        folders.append(folder)
        r.userFolderOverride = folder
        r.loadNow(bundled: MIBTests.bundledURLs())
        return r
    }

    private func settle(_ reg: MIBRegistry) async {
        let deadline = Date().addingTimeInterval(20)
        while reg.isLoading, Date() < deadline { try? await Task.sleep(for: .milliseconds(10)) }
        XCTAssertFalse(reg.isLoading)
    }

    private func imported(_ reg: MIBRegistry) -> [MIBModule] { reg.modules.filter { !$0.builtIn } }

    private func assertClean(_ reg: MIBRegistry, _ names: [String], file: StaticString = #filePath, line: UInt = #line) {
        for name in names {
            guard let m = reg.modules.first(where: { $0.name == name }) else {
                XCTFail("\(name) not loaded: \(reg.modules.filter { !$0.builtIn }.map(\.name))", file: file, line: line)
                continue
            }
            XCTAssertFalse(m.builtIn, name, file: file, line: line)
            XCTAssertEqual(m.errors, [], name, file: file, line: line)
            XCTAssertEqual(m.missingImports, [], name, file: file, line: line)
            XCTAssertGreaterThan(m.nodeCount, 0, name, file: file, line: line)
        }
    }

    // MARK: Fortinet

    func testFortinetBundle() async throws {
        let reg = registry()
        reg.importFiles([Self.mibDir.appending(path: "fortinet")])
        await settle(reg)
        assertClean(reg, ["FORTINET-CORE-MIB", "FORTINET-FORTIGATE-MIB"])
        XCTAssertEqual(imported(reg).count, 2)

        let cpu = try XCTUnwrap(reg.oid(forName: "fgSysCpuUsage.0"))
        XCTAssertEqual(cpu, OID([1, 3, 6, 1, 4, 1, 12356, 101, 4, 1, 3, 0]))
        XCTAssertEqual(reg.oid(forName: "FORTINET-FORTIGATE-MIB::fgSysCpuUsage"), OID([1, 3, 6, 1, 4, 1, 12356, 101, 4, 1, 3]))
        XCTAssertEqual(reg.name(for: cpu), "fgSysCpuUsage.0")
        XCTAssertEqual(reg.oid(forName: "fnSysSerial.0"), OID([1, 3, 6, 1, 4, 1, 12356, 100, 1, 1, 1, 0]))

        // Enum labels from the vendor TCs — one of this module's, one imported from the core MIB,
        // and one TC that is itself defined as another module's TC.
        let ha = try XCTUnwrap(reg.oid(forName: "fgHaSystemMode.0"))
        XCTAssertEqual(reg.format(VarBind(ha, .integer(3))), "activePassive(3)")
        let sync = try XCTUnwrap(reg.oid(forName: "fgHaAutoSync.0"))
        XCTAssertEqual(reg.format(VarBind(sync, .integer(2))), "enabled(2)")
        let proto = try XCTUnwrap(reg.oid(forName: "fgSessProto.42"))
        XCTAssertEqual(reg.format(VarBind(proto, .integer(6))), "tcp(6)")
        let vd = try XCTUnwrap(reg.oid(forName: "fgVdEntOpMode.1"))
        XCTAssertEqual(reg.format(VarBind(vd, .integer(1))), "nat(1)")
        XCTAssertEqual(reg.exactNode(OID([1, 3, 6, 1, 4, 1, 12356, 101, 3, 2, 1, 1, 5]))?.kind, "column")

        // A trap names itself and its var-binds.
        let trapOID = try XCTUnwrap(reg.oid(forName: "fgTrapHaSwitch"))
        XCTAssertEqual(trapOID, OID([1, 3, 6, 1, 4, 1, 12356, 101, 2, 0, 401]))
        let trap = SNMPTrap(received: Date(), sourceAddress: "10.0.0.1", sourcePort: 162, version: .v2c, community: "public",
                            trapOID: trapOID, uptime: 100, agentAddress: nil,
                            varBinds: [VarBind(try XCTUnwrap(reg.oid(forName: "fnSysSerial.0")), .octetString(Data("FG100F0000000001".utf8)))])
        let e = TrapReceiver.entry(for: trap, registry: reg)
        XCTAssertEqual(e.program, "fgTrapHaSwitch")
        XCTAssertEqual(e.field("fnSysSerial.0"), "FG100F0000000001")
    }

    // MARK: Palo Alto

    func testPaloAltoBundle() async throws {
        let reg = registry()
        reg.importFiles([Self.mibDir.appending(path: "paloalto")])
        await settle(reg)
        assertClean(reg, ["PAN-GLOBAL-REG", "PAN-GLOBAL-TC", "PAN-COMMON-MIB", "PAN-PRODUCTS-MIB", "PAN-TRAPS"])

        XCTAssertEqual(reg.oid(forName: "panRoot"), OID([1, 3, 6, 1, 4, 1, 25461]))
        XCTAssertEqual(reg.oid(forName: "panGlobalRegModule"), OID([1, 3, 6, 1, 4, 1, 25461, 1, 1, 1]), "a forward reference")
        XCTAssertEqual(reg.oid(forName: "panPA-5250"), OID([1, 3, 6, 1, 4, 1, 25461, 1, 2, 51]))
        XCTAssertEqual(reg.name(for: OID([1, 3, 6, 1, 4, 1, 25461, 1, 2, 51])), "panPA-5250", "a sysObjectID names the model")
        let ha = try XCTUnwrap(reg.oid(forName: "panSysHAState.0"))
        XCTAssertEqual(reg.format(VarBind(ha, .integer(4))), "active-primary(4)")
        let util = try XCTUnwrap(reg.oid(forName: "panSessionUtilization.0"))
        XCTAssertEqual(reg.format(VarBind(util, .integer(37))), "37")

        // A PAN-OS trap: named, its var-binds named, the severity enum labelled.
        let trapOID = try XCTUnwrap(reg.oid(forName: "panHAStateChangeTrap"))
        XCTAssertEqual(trapOID, OID([1, 3, 6, 1, 4, 1, 25461, 2, 3, 3, 2, 0, 543]))
        let objs = OID([1, 3, 6, 1, 4, 1, 25461, 2, 3, 3, 1])
        let trap = SNMPTrap(received: Date(), sourceAddress: "10.0.0.2", sourcePort: 162, version: .v2c, community: "public",
                            trapOID: trapOID, uptime: 100, agentAddress: nil,
                            varBinds: [VarBind(objs.appending([6, 0]), .octetString(Data("PA-FW-01".utf8))),
                                       VarBind(objs.appending([7, 0]), .integer(4))])
        let e = TrapReceiver.entry(for: trap, registry: reg)
        XCTAssertEqual(e.program, "panHAStateChangeTrap")
        XCTAssertEqual(e.field("panHostname.0"), "PA-FW-01")
        XCTAssertEqual(e.field("panSeverity.0"), "high(4)")
        XCTAssertEqual(reg.exactNode(trapOID)?.kind, "notification")
    }

    // MARK: Aruba

    func testArubaBundleWithABrokenSibling() async throws {
        let dir = Self.mibDir.appending(path: "aruba")
        let reg = registry()
        reg.importFiles([dir])
        await settle(reg)
        let good = ["ARUBAWIRED-NETWORKING-OID", "ARUBAWIRED-POWERSUPPLY-MIB", "ARUBAWIRED-CAPABILITIES",
                    "ARUBA-MIB", "ARUBA-TC", "WLSX-SWITCH-MIB", "WLSX-TRAP-MIB", "ARUBA-LEGACY-TRAPS"]
        assertClean(reg, good)
        XCTAssertFalse(imported(reg).contains { $0.name.hasPrefix("README") }, "the bundle's README is not a module")

        // The broken sibling reports what is wrong, and keeps what it could read.
        let broken = try XCTUnwrap(reg.modules.first { $0.name == "ARUBAWIRED-FAN-MIB" })
        XCTAssertFalse(broken.errors.isEmpty)
        XCTAssertTrue(broken.errors.contains { $0.contains("END") }, "\(broken.errors)")
        XCTAssertTrue(broken.errors.contains { $0.contains("arubaWiredFanRPM") }, "\(broken.errors)")
        XCTAssertNotNil(reg.oid(forName: "arubaWiredFanName"))

        // AOS-CX: an enterprise registered with several arcs, a TC with hyphenated labels.
        XCTAssertEqual(reg.oid(forName: "arubaWiredNetworking"), OID([1, 3, 6, 1, 4, 1, 47196, 4, 1, 1]))
        let psu = try XCTUnwrap(reg.oid(forName: "arubaWiredPSUState.1.3.2"))
        XCTAssertEqual(reg.format(VarBind(psu, .integer(3))), "fault-input(3)")
        XCTAssertEqual(reg.name(for: psu), "arubaWiredPSUState.1.3.2")
        // AGENT-CAPABILITIES: a registration node, nothing of its VARIATION leaks into IF-MIB.
        XCTAssertEqual(reg.exactNode(try XCTUnwrap(reg.oid(forName: "arubaWiredAosCx1008")))?.kind, "node")
        let admin = try XCTUnwrap(reg.oid(forName: "ifAdminStatus.3"))
        XCTAssertEqual(reg.format(VarBind(admin, .integer(3))), "testing(3)")
        XCTAssertEqual(reg.exactNode(OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 7]))?.module, "IF-MIB")

        // Controllers (14823): OBJECT-IDENTITY branches, a TC from the second module of a file.
        let role = try XCTUnwrap(reg.oid(forName: "wlsxSwitchRole.0"))
        XCTAssertEqual(role, OID([1, 3, 6, 1, 4, 1, 14823, 2, 2, 1, 1, 2, 0]))
        XCTAssertEqual(reg.format(VarBind(role, .integer(1))), "master(1)")
        let down = try XCTUnwrap(reg.oid(forName: "wlsxNAccessPointIsDown"))
        let t2 = SNMPTrap(received: Date(), sourceAddress: "10.0.0.3", sourcePort: 162, version: .v2c, community: "public",
                          trapOID: down, uptime: 1, agentAddress: nil,
                          varBinds: [VarBind(try XCTUnwrap(reg.oid(forName: "wlsxTrapAPStatus.0")), .integer(2))])
        let e2 = TrapReceiver.entry(for: t2, registry: reg)
        XCTAssertEqual(e2.program, "wlsxNAccessPointIsDown")
        XCTAssertEqual(e2.field("wlsxTrapAPStatus.0"), "down(2)")

        // SMIv1 TRAP-TYPE: enterprise.0.specific, as a v1 trap translates (RFC 3584).
        let restart = try XCTUnwrap(reg.oid(forName: "legacyControllerRestart"))
        XCTAssertEqual(restart, OID([1, 3, 6, 1, 4, 1, 14823, 9, 0, 1]))
        let reason = try XCTUnwrap(reg.oid(forName: "legacyReason.0"))
        XCTAssertEqual(reg.format(VarBind(reason, .integer(2))), "watchdog(2)")
    }

    // MARK: Re-import

    /// A newer version of one file replaces the old one (same file name, and the same module
    /// under another file name); the other modules stay.
    func testReimportingANewerVersionReplacesIt() async throws {
        let reg = registry()
        reg.importFiles([Self.mibDir.appending(path: "paloalto")])
        await settle(reg)
        XCTAssertNil(reg.oid(forName: "panNewObjectInV2"))
        let before = imported(reg).count

        let scratch = FileManager.default.temporaryDirectory.appending(path: "SheepLogRound5MIBv2-\(UUID().uuidString)", directoryHint: .isDirectory)
        folders.append(scratch)
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        var text = try String(contentsOf: Self.mibDir.appending(path: "paloalto/pan-common-mib.my"), encoding: .utf8)
        text = text.replacingOccurrences(of: "\nEND", with: """

            panNewObjectInV2 OBJECT-TYPE
            	SYNTAX		Integer32
            	MAX-ACCESS	read-only
            	STATUS		current
            	DESCRIPTION	"Added in the newer version."
            	::= { panSys 99 }

            END
            """)
        text = text.replacingOccurrences(of: "panSysHAMode OBJECT-TYPE", with: "panSysHAModeRenamed OBJECT-TYPE")
        let same = scratch.appending(path: "pan-common-mib.my")
        try text.write(to: same, atomically: true, encoding: .utf8)
        reg.importFiles([same])
        await settle(reg)
        XCTAssertEqual(imported(reg).count, before)
        XCTAssertEqual(reg.oid(forName: "panNewObjectInV2"), OID([1, 3, 6, 1, 4, 1, 25461, 2, 3, 2, 1, 99]))
        XCTAssertNil(reg.oid(forName: "panSysHAMode"), "the old version's objects are gone")
        assertClean(reg, ["PAN-COMMON-MIB", "PAN-TRAPS"])

        // The same module under another file name (a vendor renamed the file) replaces it too.
        let renamed = scratch.appending(path: "PAN-COMMON-MIB-v3.txt")
        try text.replacingOccurrences(of: "panNewObjectInV2", with: "panNewObjectInV3").write(to: renamed, atomically: true, encoding: .utf8)
        reg.importFiles([renamed])
        await settle(reg)
        XCTAssertEqual(imported(reg).filter { $0.name == "PAN-COMMON-MIB" }.count, 1)
        XCTAssertNotNil(reg.oid(forName: "panNewObjectInV3"))
        XCTAssertNil(reg.oid(forName: "panNewObjectInV2"))
        let files = try FileManager.default.contentsOfDirectory(atPath: reg.userFolder.path)
        XCTAssertFalse(files.contains("pan-common-mib.my"), "the replaced file is removed from the MIB folder: \(files)")
    }

    /// A module whose header comment mentions DEFINITIONS before the real header is still
    /// recognised when a folder is imported (only files that look like MIBs are taken).
    func testHeaderCommentMentioningDefinitions() throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "SheepLogRound5Look-\(UUID().uuidString)", directoryHint: .isDirectory)
        folders.append(dir)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appending(path: "VENDOR-X-MIB.my")
        try """
        -- VENDOR-X-MIB: DEFINITIONS for the X agent, see the release notes.
        -- Copyright (c) Vendor X.
        VENDOR-X-MIB DEFINITIONS ::= BEGIN
        IMPORTS enterprises FROM SNMPv2-SMI;
        vendorX OBJECT IDENTIFIER ::= { enterprises 99992 }
        END
        """.write(to: url, atomically: true, encoding: .utf8)
        XCTAssertTrue(MIBRegistry.looksLikeMIB(url))
        XCTAssertFalse(MIBRegistry.looksLikeMIB(Self.mibDir.appending(path: "aruba/README.txt")))
    }

    /// A parser detail on its own: a module with no END, followed in the same file by another
    /// module, is two modules (the first one reported), not one module swallowing the second.
    func testMissingENDBeforeTheNextModule() {
        let text = """
        A-MIB DEFINITIONS ::= BEGIN
        IMPORTS enterprises FROM SNMPv2-SMI;
        a OBJECT IDENTIFIER ::= { enterprises 99991 }
        B-MIB DEFINITIONS ::= BEGIN
        IMPORTS a FROM A-MIB;
        b OBJECT IDENTIFIER ::= { a 1 }
        END
        """
        let r = MIBParser.parseModules(text, fileName: "x")
        XCTAssertEqual(r.map(\.moduleName), ["A-MIB", "B-MIB"])
        XCTAssertTrue(r[0].errors.contains { $0.contains("END") }, "\(r[0].errors)")
        XCTAssertEqual(r[1].errors, [])
        XCTAssertEqual(r[1].nodes.map(\.name), ["b"])
        XCTAssertEqual(r[1].imports["A-MIB"], ["a"])
    }
}
