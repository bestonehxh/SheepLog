import Foundation

// MARK: - SNMP value types (shared contract)

nonisolated struct OID: Hashable, Sendable, Comparable, CustomStringConvertible, Codable {
    var parts: [UInt32]

    init(_ parts: [UInt32]) { self.parts = parts }

    /// Accepts "1.3.6.1.2.1.1.1.0" or ".1.3.6.1.2.1.1.1.0".
    init?(string: String) {
        var s = string.trimmingCharacters(in: .whitespaces)
        if s.hasPrefix(".") { s.removeFirst() }
        guard !s.isEmpty else { return nil }
        var out: [UInt32] = []
        for piece in s.split(separator: ".", omittingEmptySubsequences: false) {
            guard let n = UInt32(piece) else { return nil }
            out.append(n)
        }
        self.parts = out
    }

    var description: String { "." + parts.map(String.init).joined(separator: ".") }
    var dotted: String { parts.map(String.init).joined(separator: ".") }

    func isPrefix(of other: OID) -> Bool {
        parts.count <= other.parts.count && other.parts.starts(with: parts)
    }

    func appending(_ n: UInt32) -> OID { OID(parts + [n]) }
    func appending(_ suffix: [UInt32]) -> OID { OID(parts + suffix) }
    var parent: OID? { parts.isEmpty ? nil : OID(Array(parts.dropLast())) }

    static func < (a: OID, b: OID) -> Bool {
        for (x, y) in zip(a.parts, b.parts) where x != y { return x < y }
        return a.parts.count < b.parts.count
    }

    // Well-known roots
    static let system = OID([1, 3, 6, 1, 2, 1, 1])
    static let sysDescr = OID([1, 3, 6, 1, 2, 1, 1, 1, 0])
    static let sysObjectID = OID([1, 3, 6, 1, 2, 1, 1, 2, 0])
    static let sysUpTime = OID([1, 3, 6, 1, 2, 1, 1, 3, 0])
    static let sysContact = OID([1, 3, 6, 1, 2, 1, 1, 4, 0])
    static let sysName = OID([1, 3, 6, 1, 2, 1, 1, 5, 0])
    static let sysLocation = OID([1, 3, 6, 1, 2, 1, 1, 6, 0])
    static let ifNumber = OID([1, 3, 6, 1, 2, 1, 2, 1, 0])
    static let ifTable = OID([1, 3, 6, 1, 2, 1, 2, 2])
    static let ifXTable = OID([1, 3, 6, 1, 2, 1, 31, 1, 1])
    static let snmpTrapOID = OID([1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0])
    static let sysUpTimeInstance = OID([1, 3, 6, 1, 2, 1, 1, 3, 0])
    static let enterprises = OID([1, 3, 6, 1, 4, 1])
}

nonisolated enum SNMPValue: Sendable, Equatable {
    case integer(Int64)
    case octetString(Data)
    case null
    case oid(OID)
    case ipAddress(String)
    case counter32(UInt32)
    case gauge32(UInt32)
    case timeTicks(UInt32)
    case opaque(Data)
    case counter64(UInt64)
    case noSuchObject
    case noSuchInstance
    case endOfMibView

    var typeName: String {
        switch self {
        case .integer: "INTEGER"
        case .octetString: "STRING"
        case .null: "NULL"
        case .oid: "OID"
        case .ipAddress: "IpAddress"
        case .counter32: "Counter32"
        case .gauge32: "Gauge32"
        case .timeTicks: "TimeTicks"
        case .opaque: "Opaque"
        case .counter64: "Counter64"
        case .noSuchObject: "noSuchObject"
        case .noSuchInstance: "noSuchInstance"
        case .endOfMibView: "endOfMibView"
        }
    }

    var isException: Bool {
        switch self {
        case .noSuchObject, .noSuchInstance, .endOfMibView: true
        default: false
        }
    }

    /// A plain rendering with no MIB knowledge (the registry adds enum labels and hints).
    var display: String {
        switch self {
        case .integer(let v): String(v)
        case .octetString(let d): Self.displayString(d)
        case .null: ""
        case .oid(let o): o.description
        case .ipAddress(let s): s
        case .counter32(let v), .gauge32(let v): String(v)
        case .timeTicks(let v): "\(v) (\(Format.uptime(ticks: UInt64(v))))"
        case .opaque(let d): d.map { String(format: "%02x", $0) }.joined(separator: " ")
        case .counter64(let v): String(v)
        case .noSuchObject: "No Such Object"
        case .noSuchInstance: "No Such Instance"
        case .endOfMibView: "End of MIB view"
        }
    }

    /// Printable UTF-8 stays text; anything else is shown as hex bytes ("00 1a 1e aa bb cc").
    static func displayString(_ data: Data) -> String {
        // Agents pad fixed-size strings with NULs; a trailing run of them is not "binary".
        var d = data
        while let last = d.last, last == 0 { d.removeLast() }
        if let s = String(data: d, encoding: .utf8),
           s.unicodeScalars.allSatisfy({ $0 == "\n" || $0 == "\t" || $0 == "\r" || ($0.value >= 32 && $0.value != 127) }) {
            return s
        }
        return d.map { String(format: "%02x", $0) }.joined(separator: " ")
    }

    var intValue: Int64? {
        switch self {
        case .integer(let v): v
        case .counter32(let v), .gauge32(let v), .timeTicks(let v): Int64(v)
        case .counter64(let v): Int64(clamping: v)
        default: nil
        }
    }
}

nonisolated struct VarBind: Sendable, Equatable, Identifiable {
    var id: OID { oid }
    let oid: OID
    let value: SNMPValue
    init(_ oid: OID, _ value: SNMPValue) { self.oid = oid; self.value = value }
}

nonisolated enum SNMPVersion: String, Codable, CaseIterable, Sendable {
    case v1, v2c, v3
    var label: String { rawValue }
    var wireValue: Int { switch self { case .v1: 0; case .v2c: 1; case .v3: 3 } }
}

nonisolated enum AuthProtocol: String, Codable, CaseIterable, Sendable {
    case none, md5, sha1, sha224, sha256, sha384, sha512
    var label: String {
        switch self {
        case .none: "none"
        case .md5: "MD5"
        case .sha1: "SHA-1"
        case .sha224: "SHA-224"
        case .sha256: "SHA-256"
        case .sha384: "SHA-384"
        case .sha512: "SHA-512"
        }
    }
}

nonisolated enum PrivProtocol: String, Codable, CaseIterable, Sendable {
    /// `aes192` / `aes256` extend the localized key the Reeder / Cisco way (net-snmp's
    /// AES192C / AES256C — Cisco, Palo Alto, Fortinet, Aruba); `aes192b` / `aes256b` the
    /// Blumenthal way (draft-blumenthal-aes-usm-04 §3.1.2.1, net-snmp's AES192 / AES256).
    case none, des, aes128, aes192, aes256, aes192b, aes256b
    var label: String {
        switch self {
        case .none: "none"
        case .des: "DES"
        case .aes128: "AES-128"
        case .aes192: "AES-192"
        case .aes256: "AES-256"
        case .aes192b: "AES-192 (Blumenthal)"
        case .aes256b: "AES-256 (Blumenthal)"
        }
    }

    /// The same cipher and key size with the other key extension (AES-192/256 only).
    var otherKeyExtension: PrivProtocol? {
        switch self {
        case .aes192: .aes192b
        case .aes256: .aes256b
        case .aes192b: .aes192
        case .aes256b: .aes256
        default: nil
        }
    }
}

nonisolated struct SNMPCredentials: Codable, Sendable, Equatable {
    var version: SNMPVersion = .v2c
    var community: String = "public"
    var username: String = ""
    var authProtocol: AuthProtocol = .sha1
    var authPassword: String = ""
    var privProtocol: PrivProtocol = .aes128
    var privPassword: String = ""
    var contextName: String = ""

    /// noAuthNoPriv / authNoPriv / authPriv, derived from the two protocols.
    var securityLevel: String {
        guard version == .v3 else { return community }
        if authProtocol == .none { return "noAuthNoPriv" }
        return privProtocol == .none ? "authNoPriv" : "authPriv"
    }
}

nonisolated struct SNMPTarget: Codable, Sendable, Equatable, Hashable {
    var host: String
    var port: UInt16 = 161
    var timeout: Double = 2
    var retries: Int = 2
}

nonisolated struct EngineInfo: Sendable, Equatable {
    let engineID: Data
    let boots: UInt32
    let time: UInt32
    var engineIDHex: String { engineID.map { String(format: "%02x", $0) }.joined(separator: ":") }
}

nonisolated enum SNMPError: Error, LocalizedError, Sendable, Equatable {
    case timeout
    case network(String)
    case decode(String)
    case unknownUser
    case wrongDigest
    case unknownEngineID
    case notInTimeWindow
    case unsupportedSecurityLevel
    case decryptionError
    case response(status: Int, index: Int)
    case cancelled
    /// The agent decrypts with the same AES key size extended the other way (the associated
    /// value is the protocol that worked).
    case privKeyExtension(PrivProtocol)

    var errorDescription: String? {
        switch self {
        case .timeout: "No response (timeout). Check the address, that the SNMP port is reachable, and the community / user."
        case .network(let s): "Network error: \(s)"
        case .decode(let s): "Bad response: \(s)"
        case .unknownUser: "SNMPv3: unknown user name."
        case .wrongDigest: "SNMPv3: authentication failed (wrong auth password or protocol)."
        case .unknownEngineID: "SNMPv3: unknown engine ID."
        case .notInTimeWindow: "SNMPv3: not in time window (engine clock out of sync)."
        case .unsupportedSecurityLevel: "SNMPv3: the agent does not accept this security level for the user."
        case .decryptionError: "SNMPv3: decryption failed (wrong priv password or protocol)."
        case .response(let status, let index): "Agent error: \(SNMPError.statusName(status)) (index \(index))."
        case .cancelled: "Cancelled."
        case .privKeyExtension(let works): "SNMPv3: the agent decrypts with \(works.label) — the same key size, extended the other way."
        }
    }

    static func statusName(_ s: Int) -> String {
        let names = ["noError", "tooBig", "noSuchName", "badValue", "readOnly", "genErr", "noAccess",
                     "wrongType", "wrongLength", "wrongEncoding", "wrongValue", "noCreation",
                     "inconsistentValue", "resourceUnavailable", "commitFailed", "undoFailed",
                     "authorizationError", "notWritable", "inconsistentName"]
        return s >= 0 && s < names.count ? names[s] : "error \(s)"
    }
}

/// One object from a MIB module.
nonisolated struct MIBNode: Sendable, Equatable, Identifiable {
    var id: OID { oid }
    let name: String
    let oid: OID
    let module: String
    var syntax: String? = nil
    var enums: [Int64: String]? = nil
    var displayHint: String? = nil
    var access: String? = nil
    var status: String? = nil
    var description: String? = nil
    /// "table", "row", "column", "scalar", "node", "notification", "module"
    var kind: String = "node"
}

nonisolated struct MIBModule: Sendable, Identifiable, Equatable {
    var id: String { name }
    let name: String
    let path: URL?
    let builtIn: Bool
    var nodeCount: Int
    var missingImports: [String]
    var errors: [String]
}

/// A received trap / inform, already decoded.
nonisolated struct SNMPTrap: Sendable {
    let received: Date
    let sourceAddress: String
    let sourcePort: UInt16
    let version: SNMPVersion
    let community: String
    /// v2c: snmpTrapOID.0 value; v1: enterprise + generic/specific mapped to the v2 OID.
    let trapOID: OID
    let uptime: UInt32?
    /// v1 only: agent-addr.
    let agentAddress: String?
    let varBinds: [VarBind]
}
