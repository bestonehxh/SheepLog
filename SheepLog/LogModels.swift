import Foundation

// MARK: - Syslog value types (shared contract — every module codes against these)

nonisolated enum Severity: Int, Codable, CaseIterable, Sendable, Comparable {
    case emergency = 0, alert, critical, error, warning, notice, info, debug

    static func < (a: Severity, b: Severity) -> Bool { a.rawValue < b.rawValue }

    /// The short label the grid shows.
    var label: String {
        switch self {
        case .emergency: "EMERG"
        case .alert: "ALERT"
        case .critical: "CRIT"
        case .error: "ERR"
        case .warning: "WARN"
        case .notice: "NOTI"
        case .info: "INFO"
        case .debug: "DEBUG"
        }
    }

    var name: String {
        switch self {
        case .emergency: "emergency"
        case .alert: "alert"
        case .critical: "critical"
        case .error: "error"
        case .warning: "warning"
        case .notice: "notice"
        case .info: "info"
        case .debug: "debug"
        }
    }

    /// Accepts "err", "error", "warn", "warning", "crit", "emerg", "3", … (case-insensitive).
    static func parse(_ text: String) -> Severity? {
        let t = text.lowercased().trimmingCharacters(in: .whitespaces)
        if let n = Int(t), let s = Severity(rawValue: n) { return s }
        switch t {
        case "emerg", "emergency", "panic": return .emergency
        case "alert": return .alert
        case "crit", "critical": return .critical
        case "err", "error", "errors": return .error
        case "warn", "warning", "warnings": return .warning
        case "notice", "noti", "notification": return .notice
        case "info", "informational", "information": return .info
        case "debug", "dbg": return .debug
        default: return nil
        }
    }
}

nonisolated enum Facility: Int, Codable, CaseIterable, Sendable {
    case kern = 0, user, mail, daemon, auth, syslog, lpr, news, uucp, cron, authpriv, ftp, ntp,
         security, console, solarisCron, local0, local1, local2, local3, local4, local5, local6, local7

    var name: String {
        switch self {
        case .kern: "kern"
        case .user: "user"
        case .mail: "mail"
        case .daemon: "daemon"
        case .auth: "auth"
        case .syslog: "syslog"
        case .lpr: "lpr"
        case .news: "news"
        case .uucp: "uucp"
        case .cron: "cron"
        case .authpriv: "authpriv"
        case .ftp: "ftp"
        case .ntp: "ntp"
        case .security: "security"
        case .console: "console"
        case .solarisCron: "solaris-cron"
        case .local0: "local0"
        case .local1: "local1"
        case .local2: "local2"
        case .local3: "local3"
        case .local4: "local4"
        case .local5: "local5"
        case .local6: "local6"
        case .local7: "local7"
        }
    }

    static func parse(_ text: String) -> Facility? {
        let t = text.lowercased()
        if let n = Int(t) { return Facility(rawValue: n) }
        return Facility.allCases.first { $0.name == t }
    }
}

/// Which device family a line came from, decided from the message shape (or overridden per source).
nonisolated enum Vendor: String, Codable, CaseIterable, Sendable {
    case arubaCX, arubaOS, arubaSwitch, clearPass, huawei, checkPoint, paloAlto, fortigate, snmpTrap, unknown

    var label: String {
        switch self {
        case .arubaCX: "Aruba AOS-CX"
        case .arubaOS: "Aruba AOS 8 / IAP"
        case .arubaSwitch: "Aruba AOS-S"
        case .clearPass: "Aruba ClearPass"
        case .huawei: "Huawei VRP"
        case .checkPoint: "Check Point"
        case .paloAlto: "Palo Alto PAN-OS"
        case .fortigate: "Fortinet FortiOS"
        case .snmpTrap: "SNMP trap"
        case .unknown: "Other"
        }
    }

    /// The 6–9 character word the grid column shows.
    var shortLabel: String {
        switch self {
        case .arubaCX: "ArubaCX"
        case .arubaOS: "ArubaOS"
        case .arubaSwitch: "ArubaSw"
        case .clearPass: "ClearPass"
        case .huawei: "Huawei"
        case .checkPoint: "CheckPt"
        case .paloAlto: "PaloAlto"
        case .fortigate: "Forti"
        case .snmpTrap: "Trap"
        case .unknown: "—"
        }
    }

    /// Words the `vendor:` filter accepts for this vendor (all lower-case, prefix match on any).
    var filterAliases: [String] {
        switch self {
        case .arubaCX: ["aruba", "arubacx", "aos-cx", "aoscx", "cx"]
        case .arubaOS: ["aruba", "arubaos", "aos8", "controller", "iap", "ap"]
        case .arubaSwitch: ["aruba", "arubasw", "aos-s", "aoss", "procurve", "hp"]
        case .clearPass: ["clearpass", "cppm", "aruba"]
        case .huawei: ["huawei", "vrp"]
        case .checkPoint: ["checkpoint", "cp", "check"]
        case .paloAlto: ["palo", "paloalto", "pan", "panos"]
        case .fortigate: ["forti", "fortigate", "fortinet", "fgt"]
        case .snmpTrap: ["trap", "snmp"]
        case .unknown: ["other", "unknown", "generic"]
        }
    }

    static func parse(_ text: String) -> [Vendor] {
        let t = text.lowercased()
        return Vendor.allCases.filter { v in v.filterAliases.contains { $0.hasPrefix(t) || t.hasPrefix($0) } }
    }
}

nonisolated enum Transport: String, Codable, Sendable {
    case udp, tcp, trap, file
}

nonisolated struct LogField: Sendable, Hashable, Codable {
    let key: String
    let value: String
    init(_ key: String, _ value: String) { self.key = key; self.value = value }
}

/// One received line, fully parsed. Immutable; `id` is the arrival order and is unique for the
/// life of the process.
nonisolated struct LogEntry: Identifiable, Sendable {
    let id: Int
    let received: Date
    /// The timestamp inside the message, when the header carried one.
    let deviceTime: Date?
    /// The UDP/TCP peer address, textual ("10.1.0.1", "fe80::1").
    let sourceAddress: String
    let sourcePort: UInt16
    let transport: Transport
    let facility: Facility
    let severity: Severity
    /// The raw PRI value, nil when the line had none.
    let priority: Int?
    /// HOSTNAME from the header, "" when absent.
    let hostname: String
    /// APP-NAME / process / module ("sshd", "lldpd", "SHELL/5", "TRAFFIC/end"), "" when absent.
    let program: String
    let pid: String?
    /// The message body after the header (what the Message column shows).
    let message: String
    /// The complete line exactly as received (after framing removal).
    let raw: String
    let vendor: Vendor
    /// Vendor-specific fields in document order (Forti key=value, Palo CSV columns, …).
    let fields: [LogField]

    var displayHost: String { hostname.isEmpty ? sourceAddress : hostname }

    func field(_ key: String) -> String? {
        fields.first { $0.key.caseInsensitiveCompare(key) == .orderedSame }?.value
    }

    /// A copy with a different vendor and field set — what a per-source override produces.
    func replacingVendor(_ vendor: Vendor, fields: [LogField]) -> LogEntry {
        LogEntry(id: id, received: received, deviceTime: deviceTime, sourceAddress: sourceAddress,
                 sourcePort: sourcePort, transport: transport, facility: facility, severity: severity,
                 priority: priority, hostname: hostname, program: program, pid: pid, message: message,
                 raw: raw, vendor: vendor, fields: fields)
    }
}

/// Per-source counters the sidebar and the Sources pane show. `id` is the source address.
nonisolated struct SourceStats: Identifiable, Sendable, Equatable {
    var id: String { address }
    let address: String
    var hostname: String = ""
    /// The vendor most recently detected (or the override, when set).
    var vendor: Vendor = .unknown
    var vendorOverride: Vendor? = nil
    var count: Int = 0
    /// Indexed by `Severity.rawValue`.
    var bySeverity: [Int] = Array(repeating: 0, count: 8)
    var firstSeen: Date
    var lastSeen: Date

    var displayName: String { hostname.isEmpty ? address : hostname }
}
