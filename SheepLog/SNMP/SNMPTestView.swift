import AppKit
import Combine
import Security
import Synchronization
import SwiftUI
import UniformTypeIdentifiers

// MARK: - Keychain

/// Communities and v3 passwords, per `<host>:<port>`, service `Bestchaan.SheepLog`. The whole
/// `SNMPCredentials` is stored as JSON so a recent target restores its version and user too.
nonisolated enum KeychainStore {
    static let service = "Bestchaan.SheepLog"

    private static func query(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    @discardableResult
    static func save(_ data: Data, account: String) -> Bool {
        let q = query(account)
        let update: [String: Any] = [kSecValueData as String: data]
        let status = SecItemUpdate(q as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var add = q
            add[kSecValueData as String] = data
            add[kSecAttrLabel as String] = "SheepLog SNMP \(account)"
            return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
        }
        return status == errSecSuccess
    }

    static func load(account: String) -> Data? {
        var q = query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess else { return nil }
        return out as? Data
    }

    static func delete(account: String) {
        SecItemDelete(query(account) as CFDictionary)
    }

    static func saveCredentials(_ c: SNMPCredentials, account: String) {
        if let data = try? JSONEncoder().encode(c) { save(data, account: account) }
    }

    static func loadCredentials(account: String) -> SNMPCredentials? {
        guard let data = load(account: account) else { return nil }
        return try? JSONDecoder().decode(SNMPCredentials.self, from: data)
    }

    /// The target's entry (`host:port`, `[v6]:port`). Earlier builds saved IPv6 targets
    /// unbracketed (`::1:1161`) — still found, and moved to the bracketed name.
    static func loadCredentials(host: String, port: UInt16) -> SNMPCredentials? {
        let account = SNMPTestModel.keychainAccount(host: host, port: port)
        if let c = loadCredentials(account: account) { return c }
        let legacy = "\(host):\(port)"
        guard legacy != account, let c = loadCredentials(account: legacy) else { return nil }
        saveCredentials(c, account: account)
        delete(account: legacy)
        return c
    }

    static func saveCredentials(_ c: SNMPCredentials, host: String, port: UInt16) {
        saveCredentials(c, account: SNMPTestModel.keychainAccount(host: host, port: port))
    }
}

// MARK: - Rows

nonisolated struct VarBindRow: Identifiable, Sendable {
    let id: Int
    let oid: OID
    let oidText: String
    let name: String
    let type: String
    let value: String
    let isBad: Bool
    /// name + value, lower-cased once (the filter runs over 10,000 rows per keystroke).
    let search: String

    init(id: Int, oid: OID, oidText: String, name: String, type: String, value: String, isBad: Bool) {
        self.id = id
        self.oid = oid
        self.oidText = oidText
        self.name = name
        self.type = type
        self.value = value
        self.isBad = isBad
        search = name.lowercased() + "\u{1F}" + value.lowercased()
    }
}

nonisolated struct InterfaceRow: Identifiable, Sendable {
    var id: UInt32 { index }
    let index: UInt32
    var name = ""
    /// ifDescr ("GigabitEthernet1/0/1"); `name` prefers ifName ("Gi1/0/1") when there is one.
    var descr = ""
    var alias = ""
    var type = ""
    var admin = ""
    var oper = ""
    var speedBits: UInt64 = 0
    var inOctets: UInt64 = 0
    var outOctets: UInt64 = 0
    var inErrors: UInt64 = 0
    var outErrors: UInt64 = 0
    var lastChange: UInt32 = 0
    /// sysUpTime − ifLastChange, in ticks: how long ago the port last changed state (nil when
    /// sysUpTime was not read).
    var sinceChange: UInt32?
    /// Sorts on the age (unknown last).
    var sinceChangeSort: UInt32 { sinceChange ?? .max }

    /// In + out errors (the Errors column sorts on it).
    var totalErrors: UInt64 { inErrors &+ outErrors }

    var speedText: String {
        guard speedBits > 0 else { return "" }
        let units: [(UInt64, String)] = [(1_000_000_000_000, "Tb/s"), (1_000_000_000, "Gb/s"), (1_000_000, "Mb/s"), (1_000, "kb/s")]
        for (u, name) in units where speedBits >= u {
            let v = Double(speedBits) / Double(u)
            return v == v.rounded() ? "\(Int(v)) \(name)" : String(format: "%.1f %@", v, name)
        }
        return "\(speedBits) b/s"
    }
}

// MARK: - Model

@MainActor
final class SNMPTestModel: ObservableObject {
    static let shared = SNMPTestModel()

    enum Outcome {
        case success(summary: String, facts: [(String, String)])
        /// `title` and `hint` are worded for the target and version the run used.
        case failure(SNMPError, context: String, title: String, hint: String)
    }

    enum ResultView: String, CaseIterable { case varBinds = "Var-binds", interfaces = "Interfaces" }

    // Form
    @Published var host = ""
    @Published var port: UInt16 = 161 {
        didSet { if UInt16(portText.trimmingCharacters(in: .whitespaces)) != port { portText = String(port) } }
    }
    @Published var version: SNMPVersion = .v2c
    @Published var community = "public"
    @Published var username = ""
    @Published var authProtocol: AuthProtocol = .sha1
    @Published var authPassword = ""
    @Published var privProtocol: PrivProtocol = .aes128
    @Published var privPassword = ""
    @Published var contextName = ""
    @Published var timeout: Double = 2
    @Published var retries = 2
    @Published var oidText = ""

    // State
    @Published private(set) var running: String?
    @Published private(set) var heading = "Ask a device."
    @Published private(set) var subtitle = "SNMP v1, v2c and v3 (USM): GET, GETNEXT, GETBULK walks and interface tables"
    @Published private(set) var outcome: Outcome?
    @Published private(set) var rows: [VarBindRow] = []
    @Published private(set) var displayed: [VarBindRow] = []
    @Published private(set) var interfaces: [InterfaceRow] = []
    @Published var resultView: ResultView = .varBinds
    @Published private(set) var footer = ""
    @Published var filter = "" { didSet { recompute() } }
    @Published var sortOrder: [KeyPathComparator<VarBindRow>] = [] { didSet { recompute() } }
    @Published var interfaceSort: [KeyPathComparator<InterfaceRow>] = [KeyPathComparator(\.index)] {
        didSet { interfaces.sort(using: interfaceSort) }
    }

    private var task: Task<Void, Never>?
    private var pending: [VarBind] = []
    private var flushScheduled = false
    private var nextRowID = 0
    /// Bumped per operation; walk chunks carry it.
    private var runID = 0
    private var activeTarget: SNMPTarget?
    private var activeCredentials: SNMPCredentials?
    private var observers: [NSObjectProtocol] = []

    private init() {
        let s = AppModel.shared.settings
        timeout = Self.clampTimeout(s.snmpTimeout)
        retries = Self.clampRetries(s.snmpRetries)
        applyCredentials(Self.formDefaults(s.snmpDefaults))
        let nc = NotificationCenter.default
        observers.append(nc.addObserver(forName: .sheepLogSNMPTarget, object: nil, queue: .main) { note in
            let address = note.object as? String
            MainActor.assumeIsolated {
                guard let address, !address.isEmpty else { return }
                SNMPTestModel.shared.setTarget(address)
            }
        })
        observers.append(nc.addObserver(forName: .sheepLogSNMPOID, object: nil, queue: .main) { note in
            let text = note.object as? String
            MainActor.assumeIsolated {
                guard let text else { return }
                SNMPTestModel.shared.oidText = text
            }
        })
    }

    var isRunning: Bool { running != nil }
    /// Starting an operation while one runs cancels the running one (its late result is
    /// dropped), so the buttons only need a host.
    var canRun: Bool { !host.trimmingCharacters(in: .whitespaces).isEmpty }

    /// The Port field as typed; `port` follows it while it holds a valid port.
    @Published var portText = "161" {
        didSet { if let p = UInt16(portText.trimmingCharacters(in: .whitespaces)), p > 0, p != port { port = p } }
    }

    /// Why the Port field cannot be used, in words (nil when it is fine).
    var portProblem: String? { Self.portProblem(portText) }

    nonisolated static func portProblem(_ text: String) -> String? {
        let t = text.trimmingCharacters(in: .whitespaces)
        if t.isEmpty { return "Enter a UDP port from 1 to 65535 (SNMP agents listen on 161)." }
        guard t.allSatisfy({ $0.isASCII && $0.isNumber }) else {
            return "“\(t)” is not a port number — enter 1 to 65535 (SNMP agents listen on 161)."
        }
        guard let n = Int(t.prefix(9)), t.count < 10, n >= 1, n <= 65_535 else {
            return "Port \(t) is out of range — UDP ports are 1 to 65535 (SNMP agents listen on 161)."
        }
        return nil
    }

    /// Splits what was typed into the Host field: "10.1.0.1", "switch-1:1161", "::1",
    /// "fe80::1%en0", "[::1]", "[::1]:1161". `port` is nil when the text names none.
    nonisolated static func splitAddress(_ text: String) -> (host: String, port: UInt16?, problem: String?) {
        let s = text.trimmingCharacters(in: .whitespaces)
        if s.hasPrefix("[") {
            guard let close = s.firstIndex(of: "]") else {
                return (s, nil, "“\(s)” has “[” without “]” — write an IPv6 address as [2001:db8::1] or [2001:db8::1]:161.")
            }
            let inner = String(s[s.index(after: s.startIndex)..<close])
            let rest = s[s.index(after: close)...]
            if inner.isEmpty { return (s, nil, "“\(s)” has no address between the brackets.") }
            if rest.isEmpty { return (inner, nil, nil) }
            guard rest.hasPrefix(":") else {
                return (inner, nil, "“\(s)”: after “]” only “:port” may follow.")
            }
            let p = String(rest.dropFirst())
            if let problem = portProblem(p) { return (inner, nil, problem) }
            return (inner, UInt16(p), nil)
        }
        let colons = s.filter { $0 == ":" }.count
        if colons == 1, let c = s.firstIndex(of: ":") {
            let h = String(s[..<c]), p = String(s[s.index(after: c)...])
            if h.isEmpty { return (s, nil, "“\(s)” has a port but no host.") }
            if let problem = portProblem(p) { return (h, nil, problem) }
            return (h, UInt16(p), nil)
        }
        // Two or more colons: a bare IPv6 address — its port goes in the Port field.
        return (s, nil, nil)
    }

    /// Moves a port typed into the Host field ("10.1.0.1:1161", "[::1]:1161") into the Port
    /// field and drops IPv6 brackets. The problem with the form, if any.
    private func normalizeTarget() -> String? {
        let split = Self.splitAddress(host)
        if let problem = split.problem { return problem }
        if split.host != host.trimmingCharacters(in: .whitespaces) { host = split.host }
        if let p = split.port {
            port = p
            portText = String(p)
        }
        return portProblem
    }

    /// Keychain account for a target: `host:port`, IPv6 literals in brackets (`[::1]:1161`).
    nonisolated static func keychainAccount(host: String, port: UInt16) -> String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }

    /// "10.1.0.1", "switch:1161", "[::1]:1161" — how a target is written back to the user.
    nonisolated static func display(host: String, port: UInt16) -> String {
        if port == 161 { return host }
        return keychainAccount(host: host, port: port)
    }

    var credentials: SNMPCredentials {
        SNMPCredentials(version: version, community: community, username: username,
                        authProtocol: authProtocol, authPassword: authPassword,
                        privProtocol: authProtocol == .none ? .none : privProtocol,
                        privPassword: privPassword, contextName: contextName)
    }

    var target: SNMPTarget {
        SNMPTarget(host: host.trimmingCharacters(in: .whitespaces), port: port, timeout: Self.clampTimeout(timeout),
                   retries: Self.clampRetries(retries))
    }

    /// What a run uses whatever was typed (Settings' fields are free text, and settings.json
    /// or a Recent entry can hold anything): 0.2 … 60 s, 0 … 10 retries. Unclamped, 10⁹
    /// retries made Quick test against a silent device run for ever, and Int.max overflowed.
    nonisolated static let timeoutRange: ClosedRange<Double> = 0.2...60
    nonisolated static let retryRange: ClosedRange<Int> = 0...10

    nonisolated static func clampTimeout(_ t: Double) -> Double {
        t.isFinite ? min(timeoutRange.upperBound, max(timeoutRange.lowerBound, t)) : 2
    }

    nonisolated static func clampRetries(_ r: Int) -> Int { min(retryRange.upperBound, max(retryRange.lowerBound, r)) }


    /// The form's starting credentials from settings.json. Secrets are never written there
    /// (`AppSettings.encoded` blanks them), so an empty community is "not stored", not "use an
    /// empty community": the form keeps "public" (every launch after the first settings save
    /// started with an empty Community, and v2c tests timed out as "wrong community").
    nonisolated static func formDefaults(_ stored: SNMPCredentials) -> SNMPCredentials {
        var c = stored
        if c.community.isEmpty { c.community = SNMPCredentials().community }
        return c
    }

    func applyCredentials(_ c: SNMPCredentials) {
        version = c.version
        community = c.community
        username = c.username
        authProtocol = c.authProtocol
        authPassword = c.authPassword
        privProtocol = c.privProtocol
        privPassword = c.privPassword
        contextName = c.contextName
    }

    /// "10.1.0.1", "10.1.0.1:1161", "[fe80::1]:161".
    func setTarget(_ address: String) {
        let split = Self.splitAddress(address)
        if let p = split.port { port = p }
        host = split.host
        loadSavedCredentials()
    }

    func fill(from t: SNMPTarget) {
        host = t.host
        port = t.port
        timeout = t.timeout
        retries = t.retries
        loadSavedCredentials()
    }

    /// Keychain reads and writes can block for a long time (a locked keychain, an access
    /// prompt): they run on their own serial queue, never on the main thread. A load that
    /// finishes after the form moved on (another target, or credentials set explicitly) is dropped.
    static let keychainQueue = DispatchQueue(label: "SheepLog.snmp.keychain", qos: .userInitiated)
    private var keychainGeneration = 0

    private func loadSavedCredentials() {
        keychainGeneration += 1
        let generation = keychainGeneration
        let h = host.trimmingCharacters(in: .whitespaces), p = port
        let account = Self.keychainAccount(host: h, port: p)
        Self.keychainQueue.async {
            guard let saved = KeychainStore.loadCredentials(host: h, port: p) else { return }
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    let m = SNMPTestModel.shared
                    guard m.keychainGeneration == generation,
                          Self.keychainAccount(host: m.host.trimmingCharacters(in: .whitespaces), port: m.port) == account else { return }
                    m.applyCredentials(saved)
                }
            }
        }
    }

    /// Screenshot helpers (with the shell's `-demoShot`):
    /// `-demoSNMP host[:port]` opens the Test pane on that target, `-demoSNMPAction
    /// quick|walk|interfaces` runs it (`-demoSNMPOID` sets the object, `-demoSNMPUser u:authpw:privpw`
    /// switches to v3 SHA/AES-128); `-demoMIBs <name>` opens the MIBs pane.
    /// `-demoSNMP` alone (or followed by a boolean-ish value such as `1` / `YES`, or by the next
    /// flag) opens the pane without touching the Host field; `-demoSNMP 10.1.0.1:1161` sets it.
    nonisolated static func demoHost(_ arguments: [String]) -> (open: Bool, host: String?) {
        guard let i = arguments.firstIndex(of: "-demoSNMP") else { return (false, nil) }
        guard i + 1 < arguments.count else { return (true, nil) }
        let v = arguments[i + 1].trimmingCharacters(in: .whitespaces)
        if v.isEmpty || v.hasPrefix("-") || v.allSatisfy(\.isNumber)
            || ["yes", "no", "true", "false"].contains(v.lowercased()) { return (true, nil) }
        return (true, v)
    }

    static func applyDemoArguments() {
        guard DemoFlags.firstRun("snmp") else { return }
        let m = shared
        if DemoFlags.mibs != nil {
            AppModel.shared.mainPane = .mibs
        }
        let demo = demoHost(CommandLine.arguments)
        guard demo.open else { return }
        AppModel.shared.mainPane = .snmpTest
        if let host = demo.host { m.setTarget(host) }
        if let oid = DemoFlags.snmpOID { m.oidText = oid }
        if let user = DemoFlags.snmpUser {
            let p = user.split(separator: ":").map(String.init)
            if p.count == 3 {
                m.keychainGeneration += 1        // saved credentials must not overwrite these
                m.version = .v3
                m.username = p[0]
                m.authProtocol = .sha1
                m.authPassword = p[1]
                m.privProtocol = .aes128
                m.privPassword = p[2]
            }
        }
        let action = DemoFlags.snmpAction ?? ""
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
            MainActor.assumeIsolated {
                switch action {
                case "quick": m.quickTest()
                case "walk": m.walk()
                case "interfaces": m.walkInterfaces()
                default: break
                }
            }
        }
    }

    // MARK: Operations

    nonisolated static let systemOIDs: [OID] = [.sysDescr, .sysObjectID, .sysUpTime, .sysContact, .sysName, .sysLocation, .ifNumber]

    func quickTest() {
        start("Quick test") { client, model in
            var engine: EngineInfo?
            if client.credentials.version == .v3 { engine = try await client.discover() }
            var reply: SNMPReply
            do {
                reply = try await client.get(Self.systemOIDs)
                try Task.checkCancellation()
            } catch let e as SNMPError {
                guard case .response = e else { throw e }
                // v1 agents fail the whole GET when one object is missing (ifNumber on a
                // printer, say): ask one by one. Cancel still cancels.
                var vbs: [VarBind] = []
                var last: SNMPReply?
                for oid in Self.systemOIDs {
                    do {
                        let r = try await client.get([oid])
                        vbs += r.varBinds
                        last = r
                    } catch SNMPError.cancelled {
                        throw SNMPError.cancelled
                    } catch SNMPError.response {
                        continue
                    }
                }
                guard let last else { throw e }
                try Task.checkCancellation()
                reply = SNMPReply(varBinds: vbs, rtt: last.rtt, engine: last.engine)
            }
            engine = reply.engine ?? engine
            model.replaceRows(reply.varBinds)
            model.resultView = .varBinds
            model.succeeded(reply: reply, engine: engine, operation: "GET", system: true)
        }
    }

    func get() {
        guard let oid = resolveOID(forGet: true) else { return }
        start("Get") { client, model in
            let reply = try await client.get([oid])
            try Task.checkCancellation()
            model.replaceRows(reply.varBinds)
            model.resultView = .varBinds
            model.succeeded(reply: reply, engine: reply.engine, operation: "GET")
        }
    }

    func getNext() {
        guard let oid = resolveOID(forGet: false) else { return }
        start("Get next") { client, model in
            let reply = try await client.getNext([oid])
            try Task.checkCancellation()
            model.replaceRows(reply.varBinds)
            model.resultView = .varBinds
            if let vb = reply.varBinds.first { model.oidText = vb.oid.dotted }
            model.succeeded(reply: reply, engine: reply.engine, operation: "GETNEXT")
        }
    }

    func walk(_ explicit: OID? = nil) {
        guard let root = explicit ?? resolveOID(forGet: false) else { return }
        if let explicit { oidText = explicit.dotted }
        start("Walk") { client, model in
            model.replaceRows([])
            model.resultView = .varBinds
            let reply = try await client.walk(root, progress: model.progressSink())
            try Task.checkCancellation()
            model.flushPending()
            model.completeRows(reply.varBinds)
            model.succeeded(reply: reply, engine: reply.engine, operation: reply.operation)
        }
    }

    func getOne(_ oid: OID) {
        oidText = oid.dotted
        start("Get") { client, model in
            let reply = try await client.get([oid])
            try Task.checkCancellation()
            model.replaceRows(reply.varBinds)
            model.succeeded(reply: reply, engine: reply.engine, operation: "GET")
        }
    }

    func walkInterfaces() {
        start("Interfaces") { client, model in
            model.replaceRows([])
            model.interfaces = []
            let started = Monotonic.now()
            let a = try await client.walk(.ifTable, cap: SNMPClient.interfaceWalkCap, progress: model.progressSink())
            // ifXTable is optional (v1 agents, old gear) — but a Cancel must still cancel.
            var b: SNMPReply?
            var noX: String?
            do {
                b = try await client.walk(.ifXTable, cap: SNMPClient.interfaceWalkCap, progress: model.progressSink())
                if b?.varBinds.isEmpty ?? true { noX = "the agent has no ifXTable" }
            } catch SNMPError.cancelled {
                throw SNMPError.cancelled
            } catch {
                b = nil
                noX = "ifXTable: \((error as? SNMPError)?.errorDescription ?? error.localizedDescription)"
            }
            // ifLastChange is a sysUpTime value: the age of a change is uptime − ifLastChange.
            var uptime: UInt32?
            if let r = try? await client.get([.sysUpTime]), case .timeTicks(let t)? = r.varBinds.first?.value { uptime = t }
            try Task.checkCancellation()
            model.flushPending()
            let all = a.varBinds + (b?.varBinds ?? [])
            model.completeRows(all)
            model.interfaces = Self.joinInterfaces(ifTable: a.varBinds, ifXTable: b?.varBinds ?? [], sysUpTime: uptime)
                .sorted(using: model.interfaceSort)
            model.resultView = .interfaces
            let total = SNMPReply(varBinds: all, rtt: Monotonic.now() - started, engine: a.engine,
                                  truncated: a.truncated || (b?.truncated ?? false),
                                  requests: a.requests + (b?.requests ?? 0), operation: a.operation,
                                  stopReason: a.stopReason ?? b?.stopReason)
            model.succeeded(reply: total, engine: a.engine, operation: a.operation, interfaces: model.interfaces.count)
            model.subtitle = Self.interfacesSubtitle(count: model.interfaces.count, noIfXTable: noX, truncated: total.truncated)
        }
    }

    func cancel() {
        task?.cancel()
    }

    /// The Interfaces table under the filter field (500-port chassis): name, ifDescr, alias,
    /// type, admin/oper status or the index.
    var shownInterfaces: [InterfaceRow] {
        let f = filter.trimmingCharacters(in: .whitespaces).lowercased()
        guard !f.isEmpty else { return interfaces }
        return interfaces.filter { r in
            String(r.index) == f || [r.name, r.descr, r.alias, r.type, r.oper, r.admin].contains { $0.lowercased().contains(f) }
        }
    }

    private func resolveOID(forGet: Bool) -> OID? {
        let text = oidText.trimmingCharacters(in: .whitespaces)
        let registry = MIBRegistry.shared
        guard !text.isEmpty else {
            if forGet {
                formFailure("Get needs an object: type a name (sysDescr, ifOperStatus.3) or a numeric OID.",
                            hint: "Walk and Get next start at 1.3.6.1.2.1 (mib-2) when the field is empty.",
                            heading: "Which object?")
                return nil
            }
            return OID([1, 3, 6, 1, 2, 1])
        }
        guard var oid = registry.oid(forName: text) else {
            formFailure("“\(text)” is not a known object name or a numeric OID.",
                        hint: "Names come from the loaded MIBs (MIBs pane) — import the vendor’s MIB, or use the numeric OID.",
                        heading: "Which object?")
            return nil
        }
        if let problem = Self.oidProblem(oid) {
            formFailure(problem, hint: "SNMP OIDs start 1.3.6.1… (iso.org.dod.internet); 0.x and 2.x are the other two roots.",
                        heading: "Which object?")
            return nil
        }
        // A scalar asked for by name alone means its instance: sysDescr → sysDescr.0.
        if forGet, let n = registry.exactNode(oid), n.kind == "scalar" { oid = oid.appending(0) }
        return oid
    }

    /// The host answered the request with ICMP port unreachable (`SNMPError.network`'s text).
    nonisolated static func isPortUnreachable(_ text: String) -> Bool { text.contains("ICMP port unreachable") }

    /// An OID BER cannot carry as typed (X.690 §8.19.4: the first arc is 0, 1 or 2, and under
    /// 0 or 1 the second is below 40) — the encoder would send another OID (3.6.1 as 2.6.1,
    /// 1.45 as 2.5) and the walk would come back empty or wrong with no error.
    nonisolated static func oidProblem(_ oid: OID) -> String? {
        let p = oid.parts
        guard let first = p.first else { return nil }
        if first > 2 { return "“\(oid.dotted)” is not a valid OID: the first number is 0, 1 or 2." }
        if first < 2, p.count > 1, p[1] >= 40 {
            return "“\(oid.dotted)” is not a valid OID: under \(first) the second number is below 40."
        }
        return nil
    }

    /// Stops the running operation without a trace: its late result, error or chunks can no
    /// longer reach the form (the run id moved on).
    private func abandonRunning() {
        guard let old = task else { return }
        old.cancel()
        task = nil
        runID += 1
        running = nil
        pending = []
    }

    /// A problem with what was typed (not with the device): shown in the result card.
    private func formFailure(_ message: String, hint: String, heading: String) {
        abandonRunning()
        outcome = .failure(.decode(message), context: "form", title: message, hint: hint)
        self.heading = heading
    }

    private func start(_ label: String, _ body: @escaping @MainActor (SNMPClient, SNMPTestModel) async throws -> Void) {
        guard canRun else { return }
        if let problem = normalizeTarget() {
            formFailure(problem, hint: "Host takes a name or an address (IPv6 as 2001:db8::1 or [2001:db8::1]:161); the port goes in Port.",
                        heading: "Check the target.")
            return
        }
        // A new operation replaces the running one (Quick test twice, Walk during a Get…).
        abandonRunning()
        let client = SNMPClient(target: target, credentials: credentials)
        // The run uses the credentials on screen: a Keychain load still on its way (a slow or
        // prompting keychain after picking a Recent target) must not replace them afterwards,
        // or the form would show v3 / another community next to a result obtained with these.
        keychainGeneration += 1
        // What this run asked, as asked: the result card, the Recent list and the Keychain
        // entry describe it even if the form is edited while it runs.
        activeTarget = client.target
        activeCredentials = client.credentials
        runID += 1
        let run = runID
        running = label
        outcome = nil
        // The last run's "Stopped." / "… did not answer." must not stay up while this one runs.
        heading = "Asking \(client.target.host)…"
        subtitle = "\(label) — \(Self.display(host: client.target.host, port: client.target.port)) · \(client.credentials.version.label)"
        task = Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                try await body(client, self)
            } catch {
                // Replaced by a newer operation: that one owns the form now.
                guard self.runID == run else { return }
                self.flushPending()
                let e = (error as? SNMPError) ?? (error is CancellationError ? .cancelled : .network(error.localizedDescription))
                self.failed(e, label: label)
            }
            guard self.runID == run else { return }
            self.running = nil
            self.task = nil
        }
    }

    private func succeeded(reply: SNMPReply, engine: EngineInfo?, operation: String, system: Bool = false,
                           interfaces: Int? = nil) {
        let registry = MIBRegistry.shared
        var parts: [String] = []
        let c = activeCredentials ?? credentials
        let t = activeTarget ?? target
        if c.version == .v3 {
            parts.append("SNMPv3 \(c.securityLevel) OK")
            if let engine {
                parts.append("engineID \(engine.engineIDHex)")
                parts.append("boots \(engine.boots)")
            }
        } else {
            parts.append("SNMP\(c.version.label) OK")
        }
        // A walk's time is many round trips, not one.
        parts.append(reply.requests > 1 ? "\(Format.count(reply.requests)) requests in \(Format.ms(reply.rtt))"
                                        : "RTT \(Format.ms(reply.rtt))")
        var facts: [(String, String)] = []
        var sysName: String?
        if system {
            let byOID = Dictionary(reply.varBinds.map { ($0.oid, $0) }, uniquingKeysWith: { a, _ in a })
            func text(_ oid: OID) -> String? {
                guard let vb = byOID[oid], !vb.value.isException else { return nil }
                return registry.format(vb)
            }
            if let v = text(.sysName), !v.isEmpty { sysName = v }
            facts.append(("sysName", text(.sysName) ?? "—"))
            facts.append(("sysDescr", text(.sysDescr) ?? "—"))
            if let vb = byOID[.sysObjectID], case .oid(let o) = vb.value {
                let vendor = Self.vendor(for: o).map { " · \($0)" } ?? ""
                facts.append(("sysObjectID", "\(registry.qualifiedName(for: o)) (\(o.dotted))\(vendor)"))
            } else {
                facts.append(("sysObjectID", "—"))
            }
            if let vb = byOID[.sysUpTime], case .timeTicks(let t) = vb.value {
                facts.append(("sysUpTime", Format.uptime(ticks: UInt64(t))))
            } else {
                facts.append(("sysUpTime", "—"))
            }
            facts.append(("sysContact", text(.sysContact) ?? "—"))
            facts.append(("sysLocation", text(.sysLocation) ?? "—"))
            facts.append(("ifNumber", text(.ifNumber) ?? "—"))
        }
        outcome = .success(summary: parts.joined(separator: " · "), facts: facts)
        let who = sysName ?? t.host
        heading = "\(who) answered in \(Format.ms(reply.rtt))."
        if let interfaces {
            subtitle = Self.interfacesSubtitle(count: interfaces, noIfXTable: nil, truncated: reply.truncated)
        } else if system, !reply.varBinds.isEmpty, reply.varBinds.allSatisfy(\.value.isException) {
            // net-snmp answers an unknown v3 context (or a view without `system`) this way.
            subtitle = c.version == .v3 && !c.contextName.isEmpty
                ? "The agent answered but has no system objects in context “\(c.contextName)” — check the Context field."
                : "The agent answered but shows none of the system objects — check the view this community or user may read."
        } else {
            subtitle = "\(operation) \(Self.keychainAccount(host: t.host, port: t.port)) · \(c.version.label)" + (reply.truncated ? " · stopped at \(Format.count(SNMPClient.walkCap)) var-binds" : "")
            if let why = reply.stopReason { subtitle += " · stopped early — \(why)" }
        }
        footer = "\(Format.count(reply.varBinds.count)) var-binds · \(Format.ms(reply.rtt)) · \(reply.operation) ×\(reply.requests)"
            + (reply.truncated ? " · truncated" : "")
        remember()
    }

    private func failed(_ e: SNMPError, label: String) {
        if e == .cancelled {
            heading = "Stopped."
            subtitle = "\(label) cancelled after \(Format.count(rows.count)) var-binds"
            outcome = nil
            footer = rows.isEmpty ? "" : "\(Format.count(rows.count)) var-binds · cancelled"
            return
        }
        let t = activeTarget ?? target
        let c = activeCredentials ?? credentials
        outcome = .failure(e, context: label, title: Self.title(for: e, target: t),
                           hint: Self.hint(for: e, target: t, version: c.version))
        switch e {
        case .timeout: heading = "\(t.host) did not answer."
        case .network(let text) where Self.isPortUnreachable(text):
            heading = "\(t.host) has no SNMP agent on UDP \(t.port)."
        case .network: heading = "\(t.host) is not reachable."
        default: heading = "\(t.host) answered with an error."
        }
        subtitle = "\(label) — \(Self.display(host: t.host, port: t.port)) · \(c.version.label)"
    }

    /// "24 interfaces from ifTable + ifXTable", or what is missing: without ifXTable the
    /// counters are the 32-bit ones (they wrap at 4 GB) and names / aliases are ifDescr only.
    nonisolated static func interfacesSubtitle(count: Int, noIfXTable: String?, truncated: Bool) -> String {
        var s = "\(Format.count(count)) interfaces from ifTable"
        s += noIfXTable.map { " only — \($0); 32-bit counters, no aliases" } ?? " + ifXTable"
        if truncated { s += " · stopped at \(Format.count(SNMPClient.interfaceWalkCap)) var-binds, the last columns may be empty" }
        return s
    }

    private func remember() {
        let t = activeTarget ?? target
        let c = activeCredentials ?? credentials
        AppModel.shared.rememberTarget(t)
        Self.keychainQueue.async { KeychainStore.saveCredentials(c, host: t.host, port: t.port) }
    }

    /// The result card's first line. `SNMPError.timeout`'s own text names UDP 161 whatever the
    /// port; this one says what was actually tried.
    static func title(for e: SNMPError, target t: SNMPTarget) -> String {
        guard e == .timeout else { return e.errorDescription ?? "Failed." }
        let tries = clampRetries(t.retries) + 1
        let seconds = clampTimeout(t.timeout)
        let wait = seconds == seconds.rounded() ? String(Int(seconds)) : String(format: "%.1f", seconds)
        return "No response from \(display(host: t.host, port: t.port)) (UDP \(t.port)) — \(tries) \(tries == 1 ? "try" : "tries") × \(wait) s."
    }

    static func hint(for e: SNMPError, target t: SNMPTarget, version: SNMPVersion) -> String {
        switch e {
        case .timeout:
            version == .v3
                ? "Check the address, that UDP \(t.port) is open on the way, and that the device allows SNMP from this Mac’s IP. A wrong v3 user or auth password comes back as an error, but a wrong priv password or protocol looks exactly like this (the agent drops what it cannot decrypt) — Quick test tells them apart."
                : "A wrong community looks exactly like this — agents silently drop requests with a community they do not know. Also check the address, that UDP \(t.port) is open on the way, and that the device allows SNMP from this Mac’s IP."
        case .network(let text) where isPortUnreachable(text):
            "The host answered, with ICMP port unreachable: nothing listens on UDP \(t.port). Check the port, and that the SNMP agent is enabled on the device."
        case .network: "Check the host name or address, and that this Mac has a route to it."
        case .decode(let text) where text.contains("context"):
            "Clear the Context field, or use a context the device defines (a VRF or VLAN instance name)."
        case .decode(let text) where text.hasSuffix("report)"):
            "The agent turned the request down before reading it — check the SNMP version and security settings."
        case .decode: "The agent sent something SheepLog could not read — try another SNMP version."
        case .unknownUser: "The user name is case-sensitive and must exist in the device’s SNMPv3 user table."
        case .wrongDigest: "The device knows this user, but the auth key does not match — check the auth protocol (MD5 / SHA-1 / SHA-2) and the auth password."
        case .unknownEngineID: "The device’s engine ID changed during the test — run it again."
        case .notInTimeWindow: "The engine clock moved twice in a row — run it again. If it repeats, the device’s engine boots / time may be stuck."
        case .unsupportedSecurityLevel: "The user exists, but not at this security level — match Auth and Priv to the device’s user."
        case .decryptionError: "Check the priv protocol (DES / AES-128 / AES-192 / AES-256) and the priv password. AES-192/256 also come in a Blumenthal variant (net-snmp agents built with AES256 rather than AES256C)."
        case .privKeyExtension(let works): "Choose \(works.label) in Priv. AES-192/256 keys are extended two ways — the Reeder/Cisco way (Cisco, Palo Alto, Fortinet, Aruba) and the Blumenthal way (net-snmp built with AES192/AES256) — and this agent uses the other one."
        case .response(let status, _):
            status == 2 ? "The object does not exist on this agent (v1 noSuchName) — check the OID."
                : "The agent refused the request — check the OID and the view this community or user may read."
        case .cancelled: ""
        }
    }

    static func vendor(for sysObjectID: OID) -> String? {
        guard OID.enterprises.isPrefix(of: sysObjectID), sysObjectID.parts.count > 6 else { return nil }
        switch sysObjectID.parts[6] {
        case 14823: return "Aruba"
        case 47196: return "Aruba CX (HPE)"
        case 11: return "HPE / Aruba (ProCurve)"
        case 2011: return "Huawei"
        case 2620: return "Check Point"
        case 25461: return "Palo Alto Networks"
        case 12356: return "Fortinet"
        case 9: return "Cisco"
        case 8072: return "net-snmp"
        case 311: return "Microsoft"
        case 63: return "Apple"
        default: return nil
        }
    }

    // MARK: Rows

    private func makeRows(_ vbs: [VarBind]) -> [VarBindRow] {
        let described = MIBRegistry.shared.describe(vbs)
        return zip(vbs, described).map { vb, d in
            nextRowID += 1
            let bad = vb.value.isException || d.value.hasPrefix("down(") || d.value.hasPrefix("lowerLayerDown(")
            return VarBindRow(id: nextRowID, oid: vb.oid, oidText: vb.oid.dotted, name: d.name,
                              type: vb.value.typeName, value: d.value, isBad: bad)
        }
    }

    /// After a walk: the rows shown so far are a prefix of `all` (chunks still in the batcher
    /// are not) — append the rest instead of rebuilding 10,000 rows (and their row ids).
    func completeRows(_ all: [VarBind]) {
        pending = []
        flushScheduled = false
        if rows.count <= all.count, zip(rows, all).allSatisfy({ $0.oid == $1.oid }) {
            if rows.count < all.count {
                rows += makeRows(Array(all[rows.count...]))
                recompute()
            }
        } else {
            replaceRows(all)
        }
    }

    func replaceRows(_ vbs: [VarBind]) {
        pending = []
        rows = makeRows(vbs)
        recompute()
    }

    /// The walk's progress callback. Chunks are collected on the calling (socket) thread and
    /// handed to the main actor at most 10× a second — not one main-queue hop per GETBULK — and
    /// tagged with the run that asked for them, so a late chunk from a cancelled walk can never
    /// land in the next one's table.
    func progressSink() -> @Sendable ([VarBind]) -> Void {
        let run = runID
        let batcher = ChunkBatcher(interval: 0.1) { batch in
            DispatchQueue.main.async {
                MainActor.assumeIsolated { SNMPTestModel.shared.enqueue(batch, run: run) }
            }
        }
        return { chunk in batcher.add(chunk) }
    }

    /// Chunks for the operation running now.
    func enqueue(_ chunk: [VarBind]) { enqueue(chunk, run: runID) }

    /// Walk chunks land here (on the main actor) and reach the table at most 10× a second.
    func enqueue(_ chunk: [VarBind], run: Int) {
        guard isRunning, run == runID else { return }
        pending += chunk
        guard !flushScheduled else { return }
        flushScheduled = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
            MainActor.assumeIsolated { SNMPTestModel.shared.flushPending() }
        }
    }

    func flushPending() {
        flushScheduled = false
        guard !pending.isEmpty else { return }
        rows += makeRows(pending)
        pending = []
        recompute()
        footer = "\(Format.count(rows.count)) var-binds…"
    }

    private func recompute() {
        var list = rows
        let f = filter.trimmingCharacters(in: .whitespaces).lowercased()
        if !f.isEmpty {
            let oidPrefix = f.hasPrefix(".") ? String(f.dropFirst()) : f
            list = list.filter { $0.search.contains(f) || $0.oidText.hasPrefix(oidPrefix) }
        }
        if !sortOrder.isEmpty { list.sort(using: sortOrder) }
        displayed = list
    }

    func tsv(_ list: [VarBindRow]) -> String {
        list.map { "\($0.oidText)\t\($0.name)\t\($0.type)\t\($0.value)" }.joined(separator: "\n")
    }

    func csv(_ list: [VarBindRow]) -> String {
        // Values are device-controlled (sysDescr, ifAlias…): a cell starting with = + - @ or a
        // tab/CR would run as a formula in Excel / Numbers — prefix an apostrophe (OWASP), as
        // the log export does.
        func q(_ s: String) -> String {
            var v = s
            if let c = v.first, "=+-@\t\r".contains(c) { v = "'" + v }
            return "\"" + v.replacingOccurrences(of: "\"", with: "\"\"") + "\""
        }
        return (["OID,Name,Type,Value"] + list.map { [q($0.oidText), q($0.name), q($0.type), q($0.value)].joined(separator: ",") })
            .joined(separator: "\n") + "\n"
    }

    func exportCSV() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.commaSeparatedText]
        // ":" of an IPv6 address shows up as "/" in Finder.
        let base = target.host.isEmpty ? "snmp" : target.host.replacingOccurrences(of: ":", with: "-")
        panel.nameFieldStringValue = "\(base)-snmp.csv"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { try csv(displayed).write(to: url, atomically: true, encoding: .utf8) }
        catch { AppModel.shared.report("Could not write \(url.lastPathComponent).", detail: error.localizedDescription) }
    }

    // MARK: Interfaces

    static func joinInterfaces(ifTable: [VarBind], ifXTable: [VarBind], sysUpTime: UInt32? = nil) -> [InterfaceRow] {
        let registry = MIBRegistry.shared
        var rows: [UInt32: InterfaceRow] = [:]
        var hcIn: [UInt32: UInt64] = [:], hcOut: [UInt32: UInt64] = [:], high: [UInt32: UInt64] = [:]
        var names: [UInt32: String] = [:]
        func label(_ vb: VarBind) -> String {
            let s = registry.format(vb)
            if let p = s.firstIndex(of: "("), s.hasSuffix(")") { return String(s[..<p]) }
            return s
        }
        func u64(_ v: SNMPValue) -> UInt64 {
            switch v {
            case .counter64(let x): x
            case .counter32(let x), .gauge32(let x), .timeTicks(let x): UInt64(x)
            case .integer(let x): UInt64(clamping: x)
            default: 0
            }
        }
        let entry = OID.ifTable.appending(1)
        for vb in ifTable where entry.isPrefix(of: vb.oid) && vb.oid.parts.count == entry.parts.count + 2 {
            let col = vb.oid.parts[entry.parts.count]
            let idx = vb.oid.parts[entry.parts.count + 1]
            var r = rows[idx] ?? InterfaceRow(index: idx)
            switch col {
            case 2: r.name = vb.value.display; r.descr = r.name
            case 3: r.type = label(vb)
            case 5: r.speedBits = u64(vb.value)
            case 7: r.admin = label(vb)
            case 8: r.oper = label(vb)
            case 9: if case .timeTicks(let t) = vb.value { r.lastChange = t }
            case 10: r.inOctets = u64(vb.value)
            case 14: r.inErrors = u64(vb.value)
            case 16: r.outOctets = u64(vb.value)
            case 20: r.outErrors = u64(vb.value)
            default: break
            }
            rows[idx] = r
        }
        let xEntry = OID.ifXTable.appending(1)
        for vb in ifXTable where xEntry.isPrefix(of: vb.oid) && vb.oid.parts.count == xEntry.parts.count + 2 {
            let col = vb.oid.parts[xEntry.parts.count]
            let idx = vb.oid.parts[xEntry.parts.count + 1]
            if rows[idx] == nil { rows[idx] = InterfaceRow(index: idx) }
            switch col {
            case 1: names[idx] = vb.value.display
            case 6: hcIn[idx] = u64(vb.value)
            case 10: hcOut[idx] = u64(vb.value)
            case 15: high[idx] = u64(vb.value)
            case 18: rows[idx]?.alias = vb.value.display
            default: break
            }
        }
        for (idx, var r) in rows {
            if let n = names[idx], !n.isEmpty { r.name = n }
            if let v = hcIn[idx] { r.inOctets = v }
            if let v = hcOut[idx] { r.outOctets = v }
            // ifSpeed (bit/s) is exact up to 4.29 Gb/s; ifHighSpeed is in whole Mb/s. Use the
            // latter only when it says more: ifSpeed saturated (4294967295), 0, or a 10G+
            // port — not to round 748.8 Mb/s down to 748.
            if let h = high[idx], h > 0, h &* 1_000_000 >= r.speedBits &+ 1_000_000 { r.speedBits = h &* 1_000_000 }
            // ifLastChange is sysUpTime at the change (0 = before the agent started): the age
            // is the difference. Unknown when the uptime wrapped past it (497 days).
            if let up = sysUpTime, up >= r.lastChange { r.sinceChange = up - r.lastChange }
            rows[idx] = r
        }
        return rows.values.sorted { $0.index < $1.index }
    }
}

// MARK: - View

struct SNMPTestView: View {
    @ObservedObject private var model = SNMPTestModel.shared
    @ObservedObject private var app = AppModel.shared
    @ObservedObject private var mibs = MIBRegistry.shared
    @FocusState private var oidFocused: Bool
    @State private var revealCommunity = false
    @State private var selection = Set<VarBindRow.ID>()
    @State private var suggestions: [String] = []

    var body: some View {
        VStack(spacing: 0) {
            PaneHeader(eyebrow: "SNMP", heading: model.heading, subtitle: model.subtitle) {
                recentMenu
            }
            .paneColumn()
            .padding(.top, Metrics.headerTop)
            .padding(.bottom, 12)

            PaneStrip { strip }

            PaneBody {
                targetGroup
                objectGroup
                if let outcome = model.outcome { resultCard(outcome) }
                results
            }
        }
    }

    // MARK: Strip

    @ViewBuilder
    private var strip: some View {
        Button("Quick test") { model.quickTest() }
            .buttonStyle(.borderedProminent)
            .tint(Theme.accent)
            .keyboardShortcut(.return, modifiers: .command)
            .disabled(!model.canRun)
        Button("Get") { model.get() }.disabled(!model.canRun)
        Button("Get next") { model.getNext() }.disabled(!model.canRun)
        Button("Walk") { model.walk() }.disabled(!model.canRun)
        Button("Interfaces") { model.walkInterfaces() }.disabled(!model.canRun)
        Spacer(minLength: 0)
        if let running = model.running {
            ProgressView().controlSize(.small)
            Text(running == "Walk" || running == "Interfaces" ? "\(running) · \(Format.count(model.rows.count))" : running)
                .font(.system(size: 12))
                .foregroundStyle(Theme.dimText)
                .monospacedDigit()
            Button("Cancel") { model.cancel() }
                .keyboardShortcut(.cancelAction)
        }
    }

    private var recentMenu: some View {
        Menu("Recent") {
            if app.settings.recentTargets.isEmpty {
                Text("No targets yet")
            }
            ForEach(app.settings.recentTargets, id: \.self) { t in
                Button(SNMPTestModel.display(host: t.host, port: t.port)) { model.fill(from: t) }
            }
        }
        .fixedSize()
    }

    // MARK: Target

    /// Which AES-192/256 to pick: the key is extended two ways and nothing on the wire says which.
    static let privHelp = "AES-192 and AES-256 keys are extended two ways. Cisco, Palo Alto, Fortinet, Aruba: AES-192 / AES-256 "
        + "(the Reeder/Cisco extension, net-snmp's AES192C / AES256C). net-snmp/Linux agents built with AES192 / AES256 "
        + "(not AES256C): AES-192 / AES-256 (Blumenthal). AES-128 and DES need no extension. "
        + "A wrong choice looks like a wrong priv password; SheepLog then tries the other extension once and says which one works."

    private var targetGroup: some View {
        PaneGroup("Target") {
            KeyValueRow("Host") {
                TextField("10.1.0.1 or switch.example.net", text: $model.host)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12, design: .monospaced))
                    .accessibilityLabel("Host")
                    .onSubmit { model.quickTest() }        // Return runs Quick test
                    .valueControl()
            }
            KeyValueRow("Port") {
                TextField("161", text: $model.portText)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityLabel("Port")
                    .onSubmit { model.quickTest() }
                    .valueNumber()
            }
            if let problem = model.portProblem {
                NoteRow(text: problem, systemImage: "exclamationmark.triangle", tint: Theme.warn)
            }
            KeyValueRow("Version") {
                Picker("SNMP version", selection: $model.version) {
                    ForEach(SNMPVersion.allCases, id: \.self) { Text($0.label).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .tint(Theme.accent)
                .fixedSize()
                .accessibilityLabel("SNMP version")
            }
            if model.version == .v3 {
                KeyValueRow("User") {
                    TextField("", text: $model.username)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(size: 12, design: .monospaced))
                        .valueControl()
                }
                KeyValueRow("Auth") {
                    HStack(spacing: 8) {
                        Picker("Auth protocol", selection: $model.authProtocol) {
                            ForEach(AuthProtocol.allCases, id: \.self) { Text($0.label).tag($0) }
                        }
                        .labelsHidden()
                        .frame(width: 170)
                        SecureField("auth password", text: $model.authPassword)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 200)
                            .disabled(model.authProtocol == .none)
                    }
                }
                KeyValueRow("Priv", help: Self.privHelp) {
                    HStack(spacing: 8) {
                        Picker("Priv protocol", selection: $model.privProtocol) {
                            ForEach(PrivProtocol.allCases, id: \.self) { Text($0.label).tag($0) }
                        }
                        .labelsHidden()
                        .frame(width: 170)
                        .disabled(model.authProtocol == .none)
                        SecureField("priv password", text: $model.privPassword)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 200)
                            .disabled(model.authProtocol == .none || model.privProtocol == .none)
                    }
                }
                KeyValueRow("Context", help: "SNMPv3 context name — empty for the default context. Some devices use it for VRFs or VLAN instances.") {
                    TextField("optional", text: $model.contextName)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(size: 12, design: .monospaced))
                        .valueControl()
                }
                if shortPassword {
                    NoteRow(text: "SNMPv3 passwords shorter than 8 characters are rejected by most agents (RFC 3414 recommends at least 8).",
                            systemImage: "exclamationmark.triangle", tint: Theme.warn)
                }
            } else {
                KeyValueRow("Community") {
                    HStack(spacing: 6) {
                        Group {
                            if revealCommunity {
                                TextField("", text: $model.community)
                            } else {
                                SecureField("", text: $model.community)
                            }
                        }
                        .textFieldStyle(.roundedBorder)
                        .font(.system(size: 12, design: .monospaced))
                        .frame(width: 228)
                        Button { revealCommunity.toggle() } label: {
                            Image(systemName: revealCommunity ? "eye.slash" : "eye")
                        }
                        .buttonStyle(.borderless)
                        .help(revealCommunity ? "Hide the community" : "Show the community")
                        .accessibilityLabel(revealCommunity ? "Hide the community" : "Show the community")
                    }
                }
            }
            KeyValueRow("Timeout / retries") {
                HStack(spacing: 6) {
                    TextField("", value: $model.timeout, format: .number)
                        .textFieldStyle(.roundedBorder)
                        .valueNumber(60)
                    Text("s").font(.system(size: 12)).foregroundStyle(Theme.faintText)
                    Stepper(value: $model.retries, in: 0...10) {
                        Text(model.retries == 1 ? "1 retry" : "\(model.retries) retries").font(.system(size: 12)).foregroundStyle(Theme.text2)
                    }
                    .padding(.leading, 10)
                }
            }
        }
    }

    private var shortPassword: Bool {
        guard model.authProtocol != .none else { return false }
        if !model.authPassword.isEmpty && model.authPassword.count < 8 { return true }
        return model.privProtocol != .none && !model.privPassword.isEmpty && model.privPassword.count < 8
    }

    // MARK: Object

    private var objectGroup: some View {
        PaneGroup("Object", accessory: presetsMenu) {
            KeyValueRow("OID", help: "A name (sysDescr, IF-MIB::ifOperStatus, ifDescr.3) or a numeric OID (1.3.6.1.2.1.1). Get on a scalar name reads its .0 instance.") {
                VStack(alignment: .leading, spacing: 4) {
                    TextField("system  ·  ifTable  ·  1.3.6.1.4.1.14823", text: $model.oidText)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(size: 12, design: .monospaced))
                        .frame(width: 420)
                        .focused($oidFocused)
                        .onSubmit {
                            suggestions = []
                            model.get()
                        }
                        .onExitCommand { suggestions = [] }
                    if oidFocused && !suggestions.isEmpty {
                        completionList
                    } else if let resolved = resolvedText {
                        Text(resolved)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(Theme.faintText)
                            .identifierText()
                            .frame(width: 420, alignment: .leading)
                    }
                }
            }
        }
        .onChange(of: model.oidText) { _, text in updateSuggestions(text) }
    }

    private var resolvedText: String? {
        let t = model.oidText.trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty, let oid = mibs.oid(forName: t) else { return nil }
        if t.first?.isNumber == true || t.first == "." { return mibs.qualifiedName(for: oid) }
        return oid.dotted
    }

    private func updateSuggestions(_ text: String) {
        let t = text.trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty, t.first?.isLetter == true, !t.contains(".") else { suggestions = []; return }
        let list = mibs.completions(prefix: t, limit: 8)
        suggestions = (list.count == 1 && list[0].caseInsensitiveCompare(t) == .orderedSame) ? [] : list
    }

    private var completionList: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(suggestions, id: \.self) { name in
                Button {
                    model.oidText = name
                    suggestions = []
                } label: {
                    HStack {
                        Text(name).font(.system(size: 12, design: .monospaced)).foregroundStyle(Theme.text)
                        Spacer()
                        if let oid = mibs.oid(forName: name) {
                            Text(oid.dotted).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(Theme.faintText)
                        }
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.vertical, 4)
        .frame(width: 420, alignment: .leading)
        .panelCard(cornerRadius: Metrics.field)
    }

    private static let presets: [(String, OID)] = [
        ("system", .system),
        ("interfaces (ifTable)", .ifTable),
        ("ifXTable", .ifXTable),
        ("ipAddrTable", OID([1, 3, 6, 1, 2, 1, 4, 20])),
        ("ipNetToMediaTable (ARP)", OID([1, 3, 6, 1, 2, 1, 4, 22])),
        ("dot1dTpFdbTable (MAC table)", OID([1, 3, 6, 1, 2, 1, 17, 4, 3])),
        ("lldpRemTable", OID([1, 0, 8802, 1, 1, 2, 1, 4, 1])),
        ("entPhysicalTable", OID([1, 3, 6, 1, 2, 1, 47, 1, 1, 1])),
        ("hrSystem", OID([1, 3, 6, 1, 2, 1, 25, 1])),
    ]

    private static let enterprisePresets: [(String, OID)] = [
        ("Aruba", OID([1, 3, 6, 1, 4, 1, 14823])),
        ("Aruba CX", OID([1, 3, 6, 1, 4, 1, 47196])),
        ("HPE ProCurve", OID([1, 3, 6, 1, 4, 1, 11])),
        ("Huawei", OID([1, 3, 6, 1, 4, 1, 2011])),
        ("Check Point", OID([1, 3, 6, 1, 4, 1, 2620])),
        ("Palo Alto", OID([1, 3, 6, 1, 4, 1, 25461])),
        ("Fortinet", OID([1, 3, 6, 1, 4, 1, 12356])),
    ]

    private var presetsMenu: some View {
        Menu("Presets") {
            ForEach(Self.presets, id: \.0) { name, oid in
                Button("\(name) — \(oid.dotted)") { model.oidText = oid.dotted }
            }
            Divider()
            ForEach(Self.enterprisePresets, id: \.0) { name, oid in
                Button("\(name) — \(oid.dotted)") { model.oidText = oid.dotted }
            }
        }
        .fixedSize()
    }

    // MARK: Result card

    @ViewBuilder
    private func resultCard(_ outcome: SNMPTestModel.Outcome) -> some View {
        switch outcome {
        case .success(let summary, let facts):
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(Theme.ok)
                    Text(summary)
                        .font(.system(size: 12.5, weight: .semibold))
                        .foregroundStyle(Theme.text)
                        .textSelection(.enabled)
                        .identifierText()
                    Spacer(minLength: 0)
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 11)
                ForEach(Array(facts.enumerated()), id: \.offset) { _, fact in
                    Rectangle().fill(Theme.hairlineSoft).frame(height: 0.5)
                    // Values on the Target / Object groups' value column (key 200 + 12 there,
                    // 196 + 16 here); sysDescr may wrap (one line would cut it to "Kernel…13432").
                    FactRow(key: fact.0, value: fact.1, keyWidth: Metrics.key - 4, monoLines: 3)
                }
            }
            .background(Theme.ok.opacity(0.07))
            .panelCard()
        case .failure(_, _, let title, let hint):
            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(systemName: "xmark.octagon.fill").foregroundStyle(Theme.err)
                    Text(title)
                        .font(.system(size: 12.5, weight: .semibold))
                        .foregroundStyle(Theme.text)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if !hint.isEmpty {
                    Text(hint)
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.text2)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.leading, 24)
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.err.opacity(0.08))
            .panelCard()
        }
    }

    // MARK: Results

    @ViewBuilder
    private var results: some View {
        if !model.rows.isEmpty || model.isRunning || !model.interfaces.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 10) {
                    if !model.interfaces.isEmpty {
                        Picker("Results as", selection: $model.resultView) {
                            ForEach(SNMPTestModel.ResultView.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                        }
                        .pickerStyle(.segmented)
                        .labelsHidden()
                        .frame(width: 200)
                    } else {
                        Text("Results").font(.system(size: 16.5, weight: .semibold)).foregroundStyle(Theme.text)
                    }
                    Spacer(minLength: 0)
                    TextField(model.resultView == .interfaces && !model.interfaces.isEmpty
                              ? "Filter name, alias, type or status" : "Filter name or value", text: $model.filter)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 220)
                        .controlSize(.small)
                }
                if model.resultView == .interfaces && !model.interfaces.isEmpty {
                    interfaceTable
                } else {
                    varBindTable
                }
                HStack(spacing: 8) {
                    Text(model.footer)
                        .font(.system(size: 11.5))
                        .foregroundStyle(Theme.faintText)
                        .monospacedDigit()
                    Spacer(minLength: 0)
                    CopyButton("Copy", value: model.tsv(model.displayed), bordered: true)
                        .controlSize(.small)
                    Button("Export CSV…") { model.exportCSV() }
                        .controlSize(.small)
                        .disabled(model.displayed.isEmpty)
                }
            }
        }
    }

    private var varBindTable: some View {
        Table(model.displayed, selection: $selection, sortOrder: $model.sortOrder) {
            TableColumn("OID", value: \.oid) { row in
                Text(row.oidText).font(.system(size: 11.5, design: .monospaced)).foregroundStyle(Theme.dimText)
            }
            .width(min: 120, ideal: 220)
            TableColumn("Name", value: \.name) { row in
                Text(row.name).font(.system(size: 12, design: .monospaced))
            }
            .width(min: 120, ideal: 200)
            TableColumn("Type", value: \.type) { row in
                Text(row.type).font(.system(size: 11.5)).foregroundStyle(Theme.dimText)
            }
            .width(min: 60, ideal: 80, max: 120)
            TableColumn("Value", value: \.value) { row in
                Text(row.value)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(row.isBad ? Theme.err : Theme.text)
                    .help(row.value)
            }
            .width(min: 160, ideal: 360)
        }
        .contextMenu(forSelectionType: VarBindRow.ID.self) { ids in
            let chosen = model.displayed.filter { ids.contains($0.id) }
            if !chosen.isEmpty {
                Button("Copy OID") { copy(chosen.map(\.oidText).joined(separator: "\n")) }
                Button("Copy Value") { copy(chosen.map(\.value).joined(separator: "\n")) }
                Button("Copy Row") { copy(model.tsv(chosen)) }
                if chosen.count == 1, let row = chosen.first {
                    Divider()
                    Button("Walk This Subtree") { model.walk(row.oid) }.disabled(!model.canRun)
                    Button("Get This") { model.getOne(row.oid) }.disabled(!model.canRun)
                }
            }
        }
        .overlay {
            if model.displayed.isEmpty {
                TableEmptyOverlay(text: model.isRunning ? "Waiting for the agent…" : (model.filter.isEmpty ? "No var-binds. Walk a parent OID (system, ifTable) to list what is under it." : "Nothing matches the filter."))
            }
        }
        .tablePanel(minHeight: 320)
        .frame(height: 460)
    }

    /// Every column fits the 1000 pt window. The pane's table is ~720 pt there and
    /// SwiftUI's inset table puts ~17 pt between columns, so eleven columns cannot fit at any
    /// readable width: Admin and Oper share "Status", the two error counters share "Errors",
    /// Type shows a short name and Since change the age of the last change (full values in the tooltips).
    private var interfaceTable: some View {
        Table(of: InterfaceRow.self, sortOrder: $model.interfaceSort) {
            Group {
                TableColumn("#", value: \InterfaceRow.index) { r in
                    Text(String(r.index)).font(.system(size: 11.5, design: .monospaced)).foregroundStyle(Theme.dimText)
                        .help("ifIndex \(r.index)")
                }
                .width(30)
                TableColumn("Name", value: \InterfaceRow.name) { r in
                    Text(r.name).font(.system(size: 12, design: .monospaced)).identifierText()
                        .help(r.descr.isEmpty || r.descr == r.name ? r.name : "\(r.name) — ifDescr \(r.descr)")
                }
                .width(min: 64, ideal: 76, max: 200)
                TableColumn("Alias", value: \InterfaceRow.alias) { r in
                    Text(r.alias).font(.system(size: 12)).foregroundStyle(Theme.text2).proseText().help(r.alias)
                }
                .width(min: 50, ideal: 50)
                TableColumn("Type", value: \InterfaceRow.type) { r in
                    Text(Self.shortType(r.type)).font(.system(size: 11.5)).foregroundStyle(Theme.dimText).proseText()
                        .help(r.type)
                }
                .width(52)
                TableColumn("Status", value: \InterfaceRow.oper) { r in
                    Text(Self.statusText(admin: r.admin, oper: r.oper)).font(.system(size: 12, weight: .medium))
                        .foregroundStyle(r.oper == "up" ? Theme.ok : (r.admin == "down" ? Theme.faintText : Theme.err))
                        .proseText()
                        .help("Admin \(r.admin.isEmpty ? "—" : r.admin) · oper \(r.oper.isEmpty ? "—" : r.oper)")
                }
                .width(76)
            }
            Group {
                TableColumn("Speed", value: \InterfaceRow.speedBits) { r in
                    Text(r.speedText).font(.system(size: 12)).monospacedDigit()
                        .frame(maxWidth: .infinity, alignment: .trailing)
                }
                .width(54)
                TableColumn("In", value: \InterfaceRow.inOctets) { r in
                    Text(Format.bytes(Int(clamping: r.inOctets))).font(.system(size: 12)).monospacedDigit()
                        .frame(maxWidth: .infinity, alignment: .trailing)
                }
                .width(58)
                TableColumn("Out", value: \InterfaceRow.outOctets) { r in
                    Text(Format.bytes(Int(clamping: r.outOctets))).font(.system(size: 12)).monospacedDigit()
                        .frame(maxWidth: .infinity, alignment: .trailing)
                }
                .width(58)
                TableColumn("Errors", value: \InterfaceRow.totalErrors) { r in
                    Text("\(Format.count(Int(clamping: r.inErrors))) / \(Format.count(Int(clamping: r.outErrors)))")
                        .font(.system(size: 12)).monospacedDigit()
                        .foregroundStyle(r.totalErrors > 0 ? Theme.warn : Theme.dimText)
                        .frame(maxWidth: .infinity, alignment: .trailing)
                        .help("In errors / out errors (ifInErrors / ifOutErrors)")
                }
                .width(46)
                TableColumn("Since change", value: \InterfaceRow.sinceChangeSort) { r in
                    Text(Self.changeText(r)).font(.system(size: 11.5)).monospacedDigit().foregroundStyle(Theme.dimText)
                        .help(Self.changeHelp(r))
                }
                .width(80)
            }
        } rows: {
            ForEach(model.shownInterfaces) { TableRow($0) }
        }
        .tablePanel(minHeight: 320)
        .frame(height: 460)
    }

    /// "up", "down", "admin down" (admin down wins: the port is shut, not broken).
    static func statusText(admin: String, oper: String) -> String {
        if admin == "down" { return "admin down" }
        return oper.isEmpty ? admin : oper
    }

    /// How long ago the port changed state ("3d 04h", under "Since change"); without sysUpTime
    /// the uptime at the change, marked as such ("at 00:00:35") — never an uptime that reads
    /// like an age.
    static func changeText(_ r: InterfaceRow) -> String {
        if let age = r.sinceChange { return shortAge(ticks: age) }
        return "at " + shortAge(ticks: r.lastChange)
    }

    static func changeHelp(_ r: InterfaceRow) -> String {
        let at = "ifLastChange: sysUpTime \(Format.uptime(ticks: UInt64(r.lastChange)))"
        guard let age = r.sinceChange else { return "Last state change at \(at) (sysUpTime not read, so no age)" }
        return "Last state change \(Format.uptime(ticks: UInt64(age))) ago (\(at))"
            + (r.lastChange == 0 ? " — 0: no change since the agent started" : "")
    }

    /// sysUpTime ticks as "12d 03h" / "03:04:05" (the full form is the tooltip).
    static func shortAge(ticks: UInt32) -> String {
        let s = Int(ticks / 100)
        let d = s / 86_400, h = (s % 86_400) / 3600
        if d > 0 { return String(format: "%dd %02dh", d, h) }
        return String(format: "%02d:%02d:%02d", h, (s % 3600) / 60, s % 60)
    }

    /// `ethernetCsmacd` → `ethernet` and the like; unknown types unchanged.
    static func shortType(_ t: String) -> String {
        let base = t.split(separator: "(").first.map(String.init) ?? t
        switch base {
        case "ethernetCsmacd", "fastEther", "gigabitEthernet": return "ethernet"
        case "softwareLoopback": return "loopback"
        case "ieee8023adLag": return "LAG"
        case "l2vlan": return "VLAN"
        case "l3ipvlan": return "L3 VLAN"
        case "propVirtual": return "virtual"
        case "ieee80211": return "Wi-Fi"
        case "mplsTunnel": return "MPLS"
        default: return base
        }
    }

    private func copy(_ s: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
    }
}


/// Collects walk chunks on the socket thread and emits them at most every `interval` seconds
/// (and once more `interval` after the last one, so a slow agent's rows still show up).
nonisolated final class ChunkBatcher: Sendable {
    private struct State {
        var buffer: [VarBind] = []
        var last = -Double.infinity
        var timerArmed = false
    }
    private let state = Mutex(State())
    private let interval: TimeInterval
    private let emit: @Sendable ([VarBind]) -> Void
    private let clock: @Sendable () -> Double

    init(interval: TimeInterval, clock: @escaping @Sendable () -> Double = Monotonic.now,
         emit: @escaping @Sendable ([VarBind]) -> Void) {
        self.interval = interval
        self.clock = clock
        self.emit = emit
    }

    func add(_ chunk: [VarBind]) {
        let out: [VarBind] = state.withLock { s in
            s.buffer += chunk
            guard !s.timerArmed else { return [] }      // an armed timer owns the next emission
            let elapsed = clock() - s.last
            // Never longer than `interval`, whatever the clock did (a clock stepped back an
            // hour must not hold the walk's rows for that hour).
            let wait = elapsed < 0 ? 0 : interval - elapsed
            if wait <= 0 {
                let out = s.buffer
                s.buffer = []
                s.last = clock()
                return out
            }
            s.timerArmed = true
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + wait) { [self] in
                self.fire()
            }
            return []
        }
        if !out.isEmpty { emit(out) }
    }

    private func fire() {
        let out: [VarBind] = state.withLock { s in
            s.timerArmed = false
            let out = s.buffer
            s.buffer = []
            if !out.isEmpty { s.last = clock() }
            return out
        }
        if !out.isEmpty { emit(out) }
    }
}
