import Foundation

/// The screenshot / demo launch arguments the Packets, Flows, SNMP Test and MIBs panes act on
/// (CLAUDE.md, "Launch arguments"), read in one place, and the once-per-launch guard their hooks
/// share. The shell's own (`-demoPane`, `-demoShot`, `-demoWindow`, `-demoSettings`, …) are read
/// in SheepLogApp / AppModel.
enum DemoFlags {
    // Packets and Flows
    /// `-demoPcap <file>`: open a capture file.
    static let pcap = CommandLine.value(after: "-demoPcap")
    /// `-demoCapture 1 [-demoInterface lo0]`: start a live capture at launch.
    static let capture = CommandLine.value(after: "-demoCapture")
    static let interface = CommandLine.value(after: "-demoInterface")
    /// `-demoFilter <query>` · `-demoSelect <frame|proto|text>`: the Packets filter / selection.
    static let filter = CommandLine.value(after: "-demoFilter")
    static let select = CommandLine.value(after: "-demoSelect")
    /// `-demoFlows 1`: synthetic TCP flows instead of the packets.
    static let flows = CommandLine.value(after: "-demoFlows") == "1"
    /// `-demoFlowSelect <id|largest>` · `-demoFlowsExport <file.png>`.
    static let flowSelect = CommandLine.value(after: "-demoFlowSelect")
    static let flowsExport = CommandLine.value(after: "-demoFlowsExport")

    // SNMP and MIBs (`-demoSNMP [host[:port]]` is parsed by `SNMPTestModel.demoHost`)
    static let snmpOID = CommandLine.value(after: "-demoSNMPOID")
    /// `user:authpw:privpw` (v3 SHA / AES-128).
    static let snmpUser = CommandLine.value(after: "-demoSNMPUser")
    /// `quick|walk|interfaces`.
    static let snmpAction = CommandLine.value(after: "-demoSNMPAction")
    /// `-demoMIBs <object>`: open the MIBs pane with that object revealed.
    static let mibs = CommandLine.value(after: "-demoMIBs")
    /// `-demoMIBFolder <dir>` · `-demoMIBImport <file or folder>`.
    static let mibFolder = CommandLine.value(after: "-demoMIBFolder")
    static let mibImport = CommandLine.value(after: "-demoMIBImport")

    private static var ran: Set<String> = []

    /// True the first time it is asked for `hook` in this launch (a pane appearing again, or a
    /// reload, must not run its demo again).
    static func firstRun(_ hook: String) -> Bool { ran.insert(hook).inserted }

    /// `-demoPcap <file>`: opens it unless the Packets pane already shows it. True when it did.
    @discardableResult
    static func openPcap() -> Bool {
        guard let path = pcap, AppModel.shared.packets.fileURL?.path != path else { return false }
        PacketFileActions.load(URL(fileURLWithPath: path))
        return true
    }
}
