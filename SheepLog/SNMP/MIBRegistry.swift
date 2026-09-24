import Combine
import Foundation

/// Every loaded MIB module, and the OID ⇄ name lookups the app makes. The 63 standard modules
/// bundled in the app load at launch; user files live in
/// `~/Library/Application Support/SheepLog/MIBs/` and are re-loaded at launch.
/// Parsing, copying and linking run on a background serial queue that owns the parsed files;
/// the finished index is swapped in on the main actor, where every lookup happens.
@MainActor
final class MIBRegistry: ObservableObject {
    static let shared = MIBRegistry()

    @Published private(set) var modules: [MIBModule] = []
    @Published private(set) var nodeCount: Int = 0
    @Published private(set) var isLoading = false
    /// Bumped whenever a new index is installed (views that cache names can refresh).
    @Published private(set) var generation = 0

    private var index = MIBIndex.build([])
    /// The parsed files. Only touched on `queue`: every relink applies its change to the latest
    /// state there, so two imports (or an import during the launch load) in flight cannot
    /// drop each other's modules.
    private let state = MIBLoadState()
    private var inFlight = 0
    private var loaded = false
    /// True from the launch `loadAll` until its index is installed: names looked up meanwhile
    /// are dotted OIDs (a trap that arrives in the first seconds after launch).
    private(set) var isFirstLoadPending = false
    private var firstLoadWaiters: [@MainActor () -> Void] = []
    private let queue = DispatchQueue(label: "SheepLog.mibs", qos: .userInitiated)

    /// Tests point these elsewhere.
    var userFolderOverride: URL?

    init() {}

    /// Loads the bundled modules, then the user folder. Idempotent.
    func loadAll() {
        guard !loaded else { return }
        loaded = true
        if generation == 0 { isFirstLoadPending = true }
        applyDemoFolders()
        let folder = userFolder
        enqueue { state in
            let bundled = Self.bundledURLs()
            let user = Self.mibFiles(in: folder)
            state.files = Self.parse(bundled.map { ($0, true) } + user.map { ($0, false) })
            return []
        }
    }

    private var demoApplied = false

    /// Screenshot helpers: `-demoMIBFolder <dir>` uses that folder instead of the user's MIB
    /// folder, and `-demoMIBImport <file or folder>` imports it after launch as "Add files…"
    /// would (into the demo folder — a scratch one when none is given — never the real one).
    private func applyDemoFolders() {
        guard !demoApplied else { return }
        demoApplied = true
        let importPath = DemoFlags.mibImport
        if let dir = DemoFlags.mibFolder {
            userFolderOverride = URL(fileURLWithPath: dir, isDirectory: true)
        } else if importPath != nil {
            userFolderOverride = FileManager.default.temporaryDirectory
                .appending(path: "SheepLogDemoMIBs-\(ProcessInfo.processInfo.processIdentifier)", directoryHint: .isDirectory)
        }
        if let importPath {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                MainActor.assumeIsolated { self.importFiles([URL(fileURLWithPath: importPath)]) }
            }
        }
    }

    /// Re-reads everything from disk.
    func reload() {
        loaded = false
        loadAll()
    }

    /// Synchronous load, for tests and tools.
    func loadNow(bundled: [URL], user: [URL] = []) {
        let files = Self.parse(bundled.map { ($0, true) } + user.map { ($0, false) })
        let idx = MIBIndex.build(files)
        queue.sync { state.files = files }
        install(idx)
        loaded = true
    }

    /// Copies the files into the user folder and loads them (a folder is walked recursively;
    /// hidden files such as `.DS_Store` are skipped). A module that replaces one of the same
    /// name from another user file removes that file. The copying happens off the main thread.
    func importFiles(_ urls: [URL]) {
        let folder = userFolder
        loaded = true
        enqueue { state in
            let fm = FileManager.default
            try? fm.createDirectory(at: folder, withIntermediateDirectories: true)
            var sources: [URL] = []
            for url in urls {
                var isDir: ObjCBool = false
                guard fm.fileExists(atPath: url.path, isDirectory: &isDir) else { continue }
                // From a folder only what looks like a MIB module: vendor bundles carry
                // README.txt / release notes, which would become "modules" full of errors.
                if isDir.boolValue { sources += Self.mibFiles(in: url).filter(Self.looksLikeMIB) }
                else if !url.lastPathComponent.hasPrefix(".") { sources.append(url) }
            }
            var added: [URL] = []
            var problems: [String] = []
            for src in sources {
                if let why = Self.importProblem(src) {
                    problems.append("\(Self.safeFileName(src.lastPathComponent)): \(why)")
                    continue
                }
                let dest = folder.appending(path: Self.importedName(src.lastPathComponent))
                if src.standardizedFileURL.path == dest.standardizedFileURL.path { added.append(dest); continue }
                do {
                    // The file's bytes, never the link: a symlink copied as such would keep
                    // pointing wherever it pointed (and be re-read from there at every launch).
                    let data = try Data(contentsOf: src.resolvingSymlinksInPath())
                    // The atomic write replaces an earlier copy only once the new one is complete
                    // (removed first, a write that failed — disk full, ⌘Q — lost the module).
                    // A link or folder in the way goes first: the rename would not replace a folder.
                    if let type = try? fm.attributesOfItem(atPath: dest.path)[.type] as? FileAttributeType,
                       type != .typeRegular {
                        try? fm.removeItem(at: dest)
                    }
                    try data.write(to: dest, options: .atomic)
                    added.append(dest)
                } catch {
                    problems.append("\(Self.safeFileName(src.lastPathComponent)): \(error.localizedDescription)")
                }
            }
            guard !added.isEmpty else { return problems }
            let addedPaths = Set(added.map { $0.standardizedFileURL.path })
            let fresh = Self.parse(added.map { ($0, false) })
            let newNames = Set(fresh.map(\.result.moduleName))
            let folderPath = folder.standardizedFileURL.path
            var kept: [MIBParsedFile] = []
            for f in state.files {
                guard let u = f.url else { kept.append(f); continue }
                let path = u.standardizedFileURL.path
                if addedPaths.contains(path) { continue }            // re-import of the same file
                if !f.builtIn, newNames.contains(f.result.moduleName), path.hasPrefix(folderPath) {
                    // Same module from another user file: the new one replaces it, on disk too
                    // (otherwise which one wins would depend on file names at the next launch).
                    try? fm.removeItem(at: u)
                    continue
                }
                kept.append(f)
            }
            // Other modules of a file we just deleted go with it.
            let gone = Set(state.files.compactMap(\.url).filter { !fm.fileExists(atPath: $0.path) }
                .map { $0.standardizedFileURL.path })
            state.files = kept.filter { f in f.url.map { !gone.contains($0.standardizedFileURL.path) } ?? true } + fresh
            return problems
        }
    }

    func remove(_ module: MIBModule) {
        guard !module.builtIn, let path = module.path else { return }
        let folder = userFolder.standardizedFileURL.path
        let target = path.standardizedFileURL.path
        enqueue { state in
            if target.hasPrefix(folder) { try? FileManager.default.removeItem(at: path) }
            state.files.removeAll { $0.url?.standardizedFileURL.path == target }
            return []
        }
    }

    var userFolder: URL {
        userFolderOverride ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appending(path: "SheepLog/MIBs", directoryHint: .isDirectory)
    }

    // MARK: Lookups

    /// Longest-prefix node for an OID.
    func node(for oid: OID) -> MIBNode? { index.longestPrefix(oid) }

    /// The node with exactly this OID.
    func exactNode(_ oid: OID) -> MIBNode? { index.byOID[oid] }

    /// "ifOperStatus.24", "sysDescr.0", "enterprises.12356.101.4.1.3.0" — the best name plus the
    /// remaining suffix; a fully unknown OID comes back dotted.
    func name(for oid: OID) -> String { index.name(for: oid, qualified: false) }

    /// "IF-MIB::ifOperStatus.24".
    func qualifiedName(for oid: OID) -> String { index.name(for: oid, qualified: true) }

    /// "ifDescr", "IF-MIB::ifDescr", "ifDescr.1", "1.3.6.1.2.1.2.2.1.2", ".1.3.6…" → OID.
    func oid(forName name: String) -> OID? { index.oid(forName: name) }

    /// The value with MIB knowledge applied: enum labels (`up(1)`), DISPLAY-HINT (MAC
    /// addresses as `00:1a:…`), TimeTicks as a duration, OIDs by name.
    func format(_ vb: VarBind) -> String { index.format(vb) }

    /// Names and values for a batch of var-binds (walk results) — much cheaper than calling
    /// `name(for:)` and `format(_:)` per var-bind.
    func describe(_ vbs: [VarBind]) -> [(name: String, value: String)] { index.describe(vbs) }

    /// Names starting with `prefix` (case-insensitive), for the OID field's completion.
    func completions(prefix: String, limit: Int = 20) -> [String] { index.completions(prefix: prefix, limit: limit) }

    /// Children of a node, for the browser tree (direct children, sorted by arc).
    func children(of oid: OID) -> [MIBNode] { index.children[oid] ?? [] }

    /// All nodes whose name contains `text` (case-insensitive), sorted by OID.
    func search(_ text: String, limit: Int = 500) -> [MIBNode] {
        let t = text.lowercased()
        guard !t.isEmpty else { return [] }
        var out: [MIBNode] = []
        let lower = index.sortedLower
        for (k, n) in index.sorted.enumerated() where lower[k].contains(t) {
            out.append(n)
            if out.count >= limit { break }
        }
        return out
    }

    /// Syntax with textual conventions followed to the base type ("INTEGER", "OCTET STRING", "BITS").
    func baseSyntax(of node: MIBNode) -> String? { index.baseSyntax(node.syntax) }

    // MARK: Loading

    /// Runs `change` on the queue against the current parsed files, rebuilds the index, and
    /// installs it on the main actor. `change` returns problems to report.
    private func enqueue(_ change: @escaping @Sendable (MIBLoadState) -> [String]) {
        inFlight += 1
        isLoading = true
        let state = self.state
        queue.async {
            let problems = change(state)
            let idx = MIBIndex.build(state.files)
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    self.inFlight -= 1
                    self.install(idx)
                    if !problems.isEmpty {
                        AppModel.shared.report("Could not copy \(problems.count == 1 ? "a file" : "\(problems.count) files") into the MIB folder.",
                                               detail: problems.prefix(10).joined(separator: "\n"))
                    }
                }
            }
        }
    }

    private func install(_ idx: MIBIndex) {
        index = idx
        modules = idx.modules
        nodeCount = idx.objectCount
        isLoading = inFlight > 0
        generation += 1
        if isFirstLoadPending, inFlight == 0 {
            isFirstLoadPending = false
            let waiters = firstLoadWaiters
            firstLoadWaiters = []
            for w in waiters { w() }
        }
        if inFlight == 0, !installWaiters.isEmpty {
            let waiters = installWaiters
            installWaiters = []
            for w in waiters { w() }
        }
    }

    private var installWaiters: [@MainActor () -> Void] = []

    /// Runs `body` once the next index is installed with no other load or import still under
    /// way (the launch load, an import, a removal) — never at once.
    func whenNextIndexInstalled(_ body: @escaping @MainActor () -> Void) {
        installWaiters.append(body)
    }

    /// Runs `body` once the launch load has installed its index (now, when it has or when no
    /// load is under way).
    func whenFirstLoadFinishes(_ body: @escaping @MainActor () -> Void) {
        if isFirstLoadPending { firstLoadWaiters.append(body) } else { body() }
    }

    /// One entry per module (a file may hold several).
    nonisolated static func parse(_ urls: [(URL, Bool)]) -> [MIBParsedFile] {
        urls.flatMap { url, builtIn in
            MIBParser.parseModules(contentsOf: url).map { MIBParsedFile(result: $0, url: url, builtIn: builtIn) }
        }
    }

    nonisolated static func bundledURLs() -> [URL] {
        (Bundle.main.urls(forResourcesWithExtension: "mib", subdirectory: nil) ?? [])
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    /// The largest MIB file imported (the biggest real vendor MIBs are a few MB).
    nonisolated static let maxImportSize = 20 * 1024 * 1024

    /// Why `url` is not imported, or nil: not a regular file (a device, a FIFO, a folder), a
    /// symbolic link to something that is not a MIB module (`/etc/passwd`), larger than
    /// `maxImportSize`, or binary (NUL bytes: a zip, an executable).
    nonisolated static func importProblem(_ url: URL) -> String? {
        var st = stat()
        guard lstat(url.path(percentEncoded: false), &st) == 0 else { return "cannot be read" }
        let isLink = st.st_mode & S_IFMT == S_IFLNK
        let real = isLink ? url.resolvingSymlinksInPath() : url
        guard stat(real.path(percentEncoded: false), &st) == 0 else { return "a symbolic link to nothing" }
        guard st.st_mode & S_IFMT == S_IFREG else { return "not a regular file" }
        guard st.st_size <= off_t(maxImportSize) else {
            return "\(st.st_size / (1024 * 1024)) MB — larger than the \(maxImportSize / (1024 * 1024)) MB limit for a MIB file"
        }
        guard let h = try? FileHandle(forReadingFrom: real) else { return "cannot be read" }
        defer { try? h.close() }
        let head = (try? h.read(upToCount: 65_536)) ?? Data()
        if head.contains(0) { return "a binary file, not a MIB module" }
        if isLink, !looksLikeMIB(real) {
            return "a symbolic link to \(real.path(percentEncoded: false)), which is not a MIB module"
        }
        return nil
    }

    /// A file name for the MIB folder: no path separators, NULs or control characters, not
    /// hidden, not `.`/`..`, at most 200 bytes.
    nonisolated static func safeFileName(_ name: String) -> String {
        var s = String(name.unicodeScalars.map { $0 == "/" || $0 == ":" || $0.value < 0x20 || $0.value == 0x7F ? "_" : Character($0) })
        while s.hasPrefix(".") { s.removeFirst() }
        if s.utf8.count > 200 { s = String(s.prefix(200)) }
        return s.isEmpty ? "unnamed.mib" : s
    }

    /// A SMI module says `DEFINITIONS ::= BEGIN` near its top (after comments): look at the
    /// first 64 KB.
    nonisolated static func looksLikeMIB(_ url: URL) -> Bool {
        guard let h = try? FileHandle(forReadingFrom: url) else { return false }
        defer { try? h.close() }
        let head = (try? h.read(upToCount: 65_536)) ?? Data()
        let text = String(decoding: head, as: UTF8.self)
        // Any occurrence: a header comment ("-- DEFINITIONS for the … agent") may come first.
        var from = text.startIndex
        while let r = text.range(of: "DEFINITIONS", range: from..<text.endIndex) {
            if text[r.upperBound...].prefix(64).contains("::=") { return true }
            from = r.upperBound
        }
        return false
    }

    /// The extensions `mibFiles` loads from the MIB folder.
    nonisolated static let mibExtensions: Set<String> = ["mib", "my", "txt", ""]

    /// The name a chosen file gets in the MIB folder: `FOO-MIB.smi` / `.mi2` / `.asn1` gain
    /// `.mib` — copied under their own name they loaded for this session and were skipped by
    /// every later load (Reload, the next launch).
    nonisolated static func importedName(_ name: String) -> String {
        let safe = safeFileName(name)
        return mibExtensions.contains(URL(fileURLWithPath: safe).pathExtension.lowercased()) ? safe : safe + ".mib"
    }

    /// `.mib`, `.my`, `.txt` and extension-less files under `folder`, recursively.
    nonisolated static func mibFiles(in folder: URL) -> [URL] {
        let fm = FileManager.default
        guard let e = fm.enumerator(at: folder, includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey],
                                    options: [.skipsHiddenFiles]) else { return [] }
        var out: [URL] = []
        for case let url as URL in e {
            let values = try? url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
            guard values?.isRegularFile == true, (values?.fileSize ?? 0) < 32 << 20 else { continue }
            let ext = url.pathExtension.lowercased()
            if mibExtensions.contains(ext) { out.append(url) }
        }
        return out.sorted { $0.path < $1.path }
    }
}

/// The registry's parsed files; only ever touched on the registry's serial queue.
nonisolated final class MIBLoadState: @unchecked Sendable {
    var files: [MIBParsedFile] = []
}

nonisolated struct MIBParsedFile: Sendable {
    let result: MIBParseResult
    let url: URL?
    let builtIn: Bool
}

// MARK: - The linked index (immutable, built off the main actor)

nonisolated final class MIBIndex: Sendable {
    let modules: [MIBModule]
    let byOID: [OID: MIBNode]
    let byName: [String: [MIBNode]]
    let sorted: [MIBNode]
    /// `sorted[i].name.lowercased()`, for the browser search (no lower-casing per keystroke).
    let sortedLower: [String]
    let children: [OID: [MIBNode]]
    let tcs: [String: MIBRawNode]
    /// Lower-cased unique names, sorted, paired with their display spelling.
    let names: [(lower: String, name: String)]
    /// OBJECT-TYPE / notification / identity nodes defined by modules (not the seeded roots).
    let objectCount: Int

    static let wellKnown: [(String, [UInt32])] = [
        ("ccitt", [0]), ("iso", [1]), ("joint-iso-ccitt", [2]),
        ("org", [1, 3]), ("dod", [1, 3, 6]), ("internet", [1, 3, 6, 1]),
        ("directory", [1, 3, 6, 1, 1]), ("mgmt", [1, 3, 6, 1, 2]), ("mib-2", [1, 3, 6, 1, 2, 1]),
        ("transmission", [1, 3, 6, 1, 2, 1, 10]),
        ("experimental", [1, 3, 6, 1, 3]), ("private", [1, 3, 6, 1, 4]), ("enterprises", [1, 3, 6, 1, 4, 1]),
        ("security", [1, 3, 6, 1, 5]), ("snmpV2", [1, 3, 6, 1, 6]), ("snmpDomains", [1, 3, 6, 1, 6, 1]),
        ("snmpProxys", [1, 3, 6, 1, 6, 2]), ("snmpModules", [1, 3, 6, 1, 6, 3]),
        ("zeroDotZero", [0, 0]),
    ]

    /// Symbols a module may import that are macros or ASN.1/SMI base types, not objects.
    static let intrinsic: Set<String> = [
        "OBJECT-TYPE", "TRAP-TYPE", "MODULE-IDENTITY", "OBJECT-IDENTITY", "NOTIFICATION-TYPE",
        "TEXTUAL-CONVENTION", "OBJECT-GROUP", "NOTIFICATION-GROUP", "MODULE-COMPLIANCE",
        "AGENT-CAPABILITIES", "Counter", "Gauge", "TimeTicks", "IpAddress", "NetworkAddress", "Opaque",
        "Counter32", "Gauge32", "Counter64", "Integer32", "Unsigned32", "ObjectName", "ObjectSyntax",
        "DisplayString", "PhysAddress",
    ]

    /// Legacy SMIv1 copies of objects the SMIv2 modules also define — they lose OID ties.
    static let legacyModules: Set<String> = ["RFC1213-MIB", "RFC1155-SMI", "RFC-1215", "RFC1158-MIB"]

    private init(modules: [MIBModule], byOID: [OID: MIBNode], byName: [String: [MIBNode]], sorted: [MIBNode],
                 children: [OID: [MIBNode]], tcs: [String: MIBRawNode], names: [(lower: String, name: String)],
                 objectCount: Int) {
        self.modules = modules
        self.byOID = byOID
        self.byName = byName
        self.sorted = sorted
        self.sortedLower = sorted.map { $0.name.lowercased() }
        self.children = children
        self.tcs = tcs
        self.names = names
        self.objectCount = objectCount
    }

    static func build(_ input: [MIBParsedFile]) -> MIBIndex {
        let (byModule, order) = choose(input)
        var linker = Linker(byModule: byModule, order: order)
        var modules: [MIBModule] = []
        modules.reserveCapacity(order.count)
        for m in order { modules.append(linker.link(m)) }
        linker.finishNames()
        linker.markColumns()
        let byOID = linker.byOID
        let sorted = byOID.values.sorted { $0.oid < $1.oid }
        modules.sort { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        return MIBIndex(modules: modules, byOID: byOID, byName: linker.byName, sorted: sorted,
                        children: tree(sorted, byOID), tcs: linker.tcs, names: uniqueNames(sorted),
                        objectCount: linker.objectCount)
    }

    /// One file per module name (a user file replaces a bundled module of the same name), in
    /// link order: bundled modules first, then by name.
    private static func choose(_ input: [MIBParsedFile]) -> (byModule: [String: MIBParsedFile], order: [String]) {
        var byModule: [String: MIBParsedFile] = [:]
        var order: [String] = []
        for f in input {
            let name = f.result.moduleName
            if let existing = byModule[name] {
                if existing.builtIn && !f.builtIn { byModule[name] = f }
                else if existing.builtIn == f.builtIn { byModule[name] = f }
            } else {
                byModule[name] = f
                order.append(name)
            }
        }
        order.sort { a, b in
            let fa = byModule[a]!, fb = byModule[b]!
            if fa.builtIn != fb.builtIn { return fa.builtIn }
            return a < b
        }
        return (byModule, order)
    }

    /// Tree: each node under its nearest existing ancestor.
    private static func tree(_ sorted: [MIBNode], _ byOID: [OID: MIBNode]) -> [OID: [MIBNode]] {
        var children: [OID: [MIBNode]] = [:]
        for n in sorted {
            var parts = n.oid.parts
            while !parts.isEmpty {
                parts.removeLast()
                let p = OID(parts)
                if byOID[p] != nil {
                    children[p, default: []].append(n)
                    break
                }
            }
        }
        return children
    }

    /// Lower-cased unique names, sorted, paired with their display spelling.
    private static func uniqueNames(_ sorted: [MIBNode]) -> [(lower: String, name: String)] {
        var seen = Set<String>()
        var names: [(lower: String, name: String)] = []
        for n in sorted {
            let l = n.name.lowercased()
            if seen.insert(l).inserted { names.append((l, n.name)) }
        }
        names.sort { $0.lower < $1.lower }
        return names
    }

    /// The symbol tables of every module, name resolution across imports, and the nodes built so
    /// far.
    private struct Linker {
        let byModule: [String: MIBParsedFile]
        var defs: [String: [String: MIBRawNode]] = [:]
        var importedFrom: [String: [String: String]] = [:]
        var definers: [String: [String]] = [:]
        var tcs: [String: MIBRawNode] = [:]
        var tcModule: [String: String] = [:]
        var tcsByModule: [String: [String: MIBRawNode]] = [:]
        let known = Dictionary(MIBIndex.wellKnown.map { ($0.0, OID($0.1)) }, uniquingKeysWith: { a, _ in a })

        var memo: [String: OID] = [:]
        var failed: Set<String> = []
        /// Keys being resolved right now: `a ::= { b 1 }`, `b ::= { a 1 }` must end, and a cycle
        /// through several modules that each define the name must not be explored once per path
        /// (exponential in the depth limit).
        var inProgress: Set<String> = []

        var byOID: [OID: MIBNode] = [:]
        var byName: [String: [MIBNode]] = [:]
        var seededNames = Set(MIBIndex.wellKnown.map(\.0))
        var objectCount = 0

        init(byModule: [String: MIBParsedFile], order: [String]) {
            self.byModule = byModule
            for m in order { addSymbols(of: m) }
            for (name, oid) in MIBIndex.wellKnown {
                let n = MIBNode(name: name, oid: OID(oid), module: "SNMPv2-SMI", kind: "node")
                byOID[n.oid] = n
            }
        }

        private mutating func addSymbols(of m: String) {
            let r = byModule[m]!.result
            var table: [String: MIBRawNode] = [:]
            for n in r.nodes where table[n.name] == nil {
                table[n.name] = n
                definers[n.name, default: []].append(m)
            }
            defs[m] = table
            var imp: [String: String] = [:]
            for (from, syms) in r.imports { for s in syms { imp[s] = from } }
            importedFrom[m] = imp
            tcsByModule[m] = r.textualConventions
            for (k, v) in r.textualConventions {
                // Global fallback: SMIv2 over the legacy v1 copies, then the richer definition.
                if let old = tcModule[k] {
                    let oldLegacy = MIBIndex.legacyModules.contains(old), newLegacy = MIBIndex.legacyModules.contains(m)
                    let oldRich = tcs[k]?.displayHint != nil || tcs[k]?.enums != nil
                    let newRich = v.displayHint != nil || v.enums != nil
                    guard (oldLegacy && !newLegacy) || (oldLegacy == newLegacy && newRich && !oldRich)
                        || !byModule[m]!.builtIn else { continue }
                }
                tcs[k] = v
                tcModule[k] = m
            }
        }

        /// A textual convention as `module` sees it: its own, then what it imports, then global.
        func tcLookup(_ name: String, from module: String) -> (MIBRawNode, String)? {
            if let t = tcsByModule[module]?[name] { return (t, module) }
            if let from = importedFrom[module]?[name], let t = tcsByModule[from]?[name] { return (t, from) }
            if let t = tcs[name], let m = tcModule[name] { return (t, m) }
            return nil
        }

        mutating func resolve(_ name: String, in module: String, depth: Int) -> OID? {
            if let n = UInt32(name) { return OID([n]) }
            let key = module + "::" + name
            if let o = memo[key] { return o }
            if failed.contains(key) || depth > 48 || inProgress.contains(key) { return nil }
            inProgress.insert(key)
            defer { inProgress.remove(key) }
            var result: OID?
            if let raw = defs[module]?[name] {
                if raw.parent != name, let p = resolve(raw.parent, in: module, depth: depth + 1) {
                    result = p.appending(raw.arcs)
                }
            } else if let from = importedFrom[module]?[name], defs[from]?[name] != nil {
                result = resolve(name, in: from, depth: depth + 1)
            } else if let k = known[name] {
                result = k
            } else if let others = definers[name] {
                for m in others where m != module {
                    if let o = resolve(name, in: m, depth: depth + 1) { result = o; break }
                }
            }
            if let result { memo[key] = result } else { failed.insert(key) }
            return result
        }

        /// The nodes of module `m`, and its entry in the module list (what it could not resolve).
        mutating func link(_ m: String) -> MIBModule {
            let f = byModule[m]!
            var missing: [String] = []
            var missingSet: Set<String> = []
            var count = 0
            for raw in f.result.nodes {
                guard let parentOID = resolve(raw.parent, in: m, depth: 0) else {
                    let reason: String
                    if let from = importedFrom[m]?[raw.parent], byModule[from] == nil { reason = from }
                    else { reason = raw.parent }
                    if missingSet.insert(reason).inserted, missing.count < 100 { missing.append(reason) }
                    continue
                }
                // SMI's limit; a chain of long arc lists could otherwise build OIDs of thousands
                // of arcs (the tree pass is quadratic in the length).
                guard parentOID.parts.count + raw.arcs.count <= 128 else { continue }
                var node = MIBNode(name: raw.name, oid: parentOID.appending(raw.arcs), module: m,
                                   syntax: raw.syntax, enums: raw.enums, displayHint: raw.displayHint,
                                   access: raw.access, status: raw.status, description: raw.description,
                                   kind: raw.kind)
                inheritConvention(&node, syntax: raw.syntax, module: m)
                count += 1
                byName[raw.name.lowercased(), default: []].append(node)
                if let existing = byOID[node.oid] {
                    let replace = seededNames.contains(existing.name) && existing.module == "SNMPv2-SMI"
                        && existing.syntax == nil && existing.description == nil
                        || (MIBIndex.legacyModules.contains(existing.module) && !MIBIndex.legacyModules.contains(m))
                    if replace { byOID[node.oid] = node }
                } else {
                    byOID[node.oid] = node
                }
            }
            seededNames.subtract(f.result.nodes.map(\.name))
            // Imports from modules that are not loaded (macro-only modules like RFC-1212 are fine).
            for (from, syms) in f.result.imports where byModule[from] == nil {
                if syms.contains(where: { !MIBIndex.intrinsic.contains($0) }), missingSet.insert(from).inserted, missing.count < 100 {
                    missing.append(from)
                }
            }
            if missingSet.count > missing.count { missing.append("… \(missingSet.count - missing.count) more") }
            objectCount += count
            return MIBModule(name: m, path: f.url, builtIn: f.builtIn, nodeCount: count,
                             missingImports: missing, errors: f.result.errors)
        }

        /// Enums and hints inherited from a textual convention (through at most 8 levels).
        private func inheritConvention(_ node: inout MIBNode, syntax: String?, module m: String) {
            guard var t = syntax else { return }
            var ctx = m
            for _ in 0..<8 {
                guard let (tc, owner) = tcLookup(t, from: ctx) else { break }
                if node.enums == nil, let e = tc.enums, !e.isEmpty { node.enums = e }
                if node.displayHint == nil, let h = tc.displayHint { node.displayHint = h }
                guard let next = tc.syntax, next != t else { break }
                t = next
                ctx = owner
            }
        }

        /// Seeded roots are findable by name too.
        mutating func finishNames() {
            for (name, oid) in MIBIndex.wellKnown where byName[name.lowercased()] == nil {
                if let n = byOID[OID(oid)] { byName[name.lowercased()] = [n] }
            }
        }

        /// Columns across modules: a leaf OBJECT-TYPE whose parent is a row.
        mutating func markColumns() {
            for (oid, n) in byOID where n.kind == "scalar" {
                if let p = oid.parent, byOID[p]?.kind == "row" {
                    var c = n
                    c.kind = "column"
                    byOID[oid] = c
                }
            }
            for (k, list) in byName {
                byName[k] = list.map { n in
                    if n.kind == "scalar", let p = n.oid.parent, byOID[p]?.kind == "row" {
                        var c = n; c.kind = "column"; return c
                    }
                    return n
                }
            }
        }
    }

    // MARK: Lookups

    func longestPrefix(_ oid: OID) -> MIBNode? {
        guard !sorted.isEmpty, !oid.parts.isEmpty else { return nil }
        // Binary search: the last node ≤ oid.
        var lo = 0, hi = sorted.count
        while lo < hi {
            let mid = (lo + hi) / 2
            if sorted[mid].oid <= oid { lo = mid + 1 } else { hi = mid }
        }
        if lo > 0 {
            let cand = sorted[lo - 1]
            if Self.hasPrefix(oid.parts, cand.oid.parts) { return cand }
            // The answer is a prefix of the common prefix of the candidate and the OID.
            var common: [UInt32] = []
            for (a, b) in zip(cand.oid.parts, oid.parts) { if a == b { common.append(a) } else { break } }
            while !common.isEmpty {
                if let n = byOID[OID(common)] { return n }
                common.removeLast()
            }
        }
        return nil
    }

    /// `OID.isPrefix(of:)` without its temporary array (this runs per var-bind).
    @inline(__always)
    static func hasPrefix(_ a: [UInt32], _ p: [UInt32]) -> Bool {
        a.count >= p.count && a[..<p.count].elementsEqual(p)
    }

    /// Nodes with no children in the tree (columns, scalars, notifications): the longest-prefix
    /// answer for every OID under them, whatever the index.
    private func isLeaf(_ n: MIBNode) -> Bool { children[n.oid] == nil }

    /// `longestPrefix` for a run of OIDs in walk order: when the previous answer was a leaf
    /// that is a prefix of this OID too (the next row of the same column) it is the answer
    /// again — no search.
    func longestPrefix(_ oid: OID, hint: MIBNode?) -> MIBNode? {
        if let h = hint, Self.hasPrefix(oid.parts, h.oid.parts), isLeaf(h) { return h }
        return longestPrefix(oid)
    }

    /// Name and formatted value for a batch of var-binds (a walk chunk): one longest-prefix
    /// search per column instead of two per var-bind.
    func describe(_ vbs: [VarBind]) -> [(name: String, value: String)] {
        var hint: MIBNode?
        return vbs.map { vb in
            let n = longestPrefix(vb.oid, hint: hint)
            if let n { hint = n }
            return (name(vb.oid, node: n, qualified: false), format(vb, prefixNode: n))
        }
    }

    func name(for oid: OID, qualified: Bool) -> String {
        name(oid, node: longestPrefix(oid), qualified: qualified)
    }

    private func name(_ oid: OID, node: MIBNode?, qualified: Bool) -> String {
        guard let n = node else { return oid.dotted }
        let suffix = oid.parts.dropFirst(n.oid.parts.count)
        let base = qualified ? "\(n.module)::\(n.name)" : n.name
        return suffix.isEmpty ? base : base + "." + suffix.map(String.init).joined(separator: ".")
    }

    func preferred(_ list: [MIBNode], module: String?) -> MIBNode? {
        var candidates = list
        if let module {
            candidates = list.filter { $0.module.caseInsensitiveCompare(module) == .orderedSame }
        }
        return candidates.first { !Self.legacyModules.contains($0.module) } ?? candidates.first
    }

    func oid(forName raw: String) -> OID? {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        // "ifDescr." / "1.3.6.1." — a trailing dot (half-typed or pasted) means the same object.
        if s.count > 1, s.hasSuffix("."), !s.hasSuffix("..") { s.removeLast() }
        guard !s.isEmpty else { return nil }
        if let first = s.first, first == "." || first.isNumber { return OID(string: s) }
        var module: String?
        var rest = Substring(s)
        if let r = s.range(of: "::") {
            module = String(s[..<r.lowerBound])
            rest = s[r.upperBound...]
        }
        let pieces = rest.split(separator: ".", omittingEmptySubsequences: false)
        guard let head = pieces.first, !head.isEmpty else { return nil }
        var suffix: [UInt32] = []
        for p in pieces.dropFirst() {
            guard let n = UInt32(p) else { return nil }
            suffix.append(n)
        }
        let list = byName[head.lowercased()] ?? []
        let exact = list.filter { $0.name == head }
        guard let node = preferred(exact.isEmpty ? list : exact, module: module) else { return nil }
        return node.oid.appending(suffix)
    }

    func completions(prefix raw: String, limit: Int) -> [String] {
        var p = raw.trimmingCharacters(in: .whitespaces)
        if let r = p.range(of: "::") { p = String(p[r.upperBound...]) }
        let lower = p.lowercased()
        guard !lower.isEmpty else { return [] }
        var lo = 0, hi = names.count
        while lo < hi {
            let mid = (lo + hi) / 2
            if names[mid].lower < lower { lo = mid + 1 } else { hi = mid }
        }
        var out: [String] = []
        var i = lo
        while i < names.count, names[i].lower.hasPrefix(lower), out.count < limit {
            out.append(names[i].name)
            i += 1
        }
        return out
    }

    func baseSyntax(_ syntax: String?) -> String? {
        guard var t = syntax else { return nil }
        for _ in 0..<8 {
            guard let tc = tcs[t], let next = tc.syntax, next != t else { break }
            t = next
        }
        return t
    }

    // MARK: Formatting

    func format(_ vb: VarBind) -> String { format(vb, prefixNode: longestPrefix(vb.oid)) }

    /// `prefixNode` = `longestPrefix(vb.oid)`, already looked up.
    func format(_ vb: VarBind, prefixNode: MIBNode?) -> String {
        let object = prefixNode.flatMap { $0.kind == "column" || $0.kind == "scalar" ? $0 : nil }
        switch vb.value {
        case .timeTicks(let t):
            return "\(Format.uptime(ticks: UInt64(t))) (\(t))"
        case .oid(let o):
            return name(for: o, qualified: false)
        case .integer(let v):
            guard let node = object else { return String(v) }
            if let label = node.enums?[v] { return "\(label)(\(v))" }
            if let hint = node.displayHint, let s = MIBFormat.integer(v, hint: hint) { return s }
            return String(v)
        case .octetString(let d):
            guard let node = object else { return vb.value.display }
            let bytes = [UInt8](d)
            if baseSyntax(node.syntax) == "BITS", let e = node.enums {
                return MIBFormat.bits(bytes, labels: e)
            }
            if let hint = node.displayHint {
                if hint == MIBFormat.dateAndTimeHint, let s = MIBFormat.dateAndTime(bytes) { return s }
                if let s = MIBFormat.octets(bytes, hint: hint) { return s }
            }
            return vb.value.display
        default:
            return vb.value.display
        }
    }
}

// MARK: - DISPLAY-HINT (RFC 2579 §3.1)

nonisolated enum MIBFormat {
    static let dateAndTimeHint = "2d-1d-1d,1d:1d:1d.1d,1a1d:1d"

    /// INTEGER hints: "d", "d-2" (implied decimal point), "x", "o", "b".
    static func integer(_ v: Int64, hint: String) -> String? {
        guard let f = hint.first else { return nil }
        switch f {
        case "d":
            let rest = hint.dropFirst()
            guard rest.hasPrefix("-"), let places = Int(rest.dropFirst()), places > 0, places < 19 else { return String(v) }
            let neg = v < 0
            var digits = String(v.magnitude)
            while digits.count <= places { digits = "0" + digits }
            let cut = digits.index(digits.endIndex, offsetBy: -places)
            return (neg ? "-" : "") + digits[..<cut] + "." + digits[cut...]
        case "x": return String(v, radix: 16)
        case "o": return String(v, radix: 8)
        case "b": return String(v, radix: 2)
        default: return nil
        }
    }

    private struct Spec {
        var star = false
        var length = 0
        var format: Character = "x"
        var separator: Character?
        var terminator: Character?
    }

    static func octets(_ data: [UInt8], hint: String) -> String? {
        let chars = Array(hint)
        var specs: [Spec] = []
        var k = 0
        while k < chars.count {
            var s = Spec()
            if chars[k] == "*" { s.star = true; k += 1 }
            var num = 0, hasNum = false
            while k < chars.count, let d = chars[k].wholeNumberValue, chars[k].isASCII {
                num = num * 10 + d; hasNum = true; k += 1
                if num > 65_535 { return nil }
            }
            guard hasNum, k < chars.count, "xdoat".contains(chars[k]) else { return nil }
            s.length = num
            s.format = chars[k]
            k += 1
            if k < chars.count, !chars[k].isNumber, chars[k] != "*" { s.separator = chars[k]; k += 1 }
            if s.star, k < chars.count, !chars[k].isNumber, chars[k] != "*" { s.terminator = chars[k]; k += 1 }
            specs.append(s)
        }
        guard !specs.isEmpty else { return nil }
        var out = ""
        var pos = 0
        var si = 0
        while pos < data.count {
            let spec = specs[min(si, specs.count - 1)]
            si += 1
            var reps = 1
            if spec.star { reps = Int(data[pos]); pos += 1 }
            for r in 0..<reps {
                guard pos < data.count, spec.length > 0 else { break }
                let take = min(spec.length, data.count - pos)
                let chunk = Array(data[pos..<(pos + take)])
                pos += take
                switch spec.format {
                case "a", "t":
                    // A DisplayString / SnmpAdminString holding binary (a MAC in sysDescr, a
                    // mis-typed column) would print as U+FFFD and control bytes: give up on the
                    // hint and let the caller show hex.
                    // Trailing NULs (C strings from some agents) are dropped, not shown as hex.
                    var body = chunk[...]
                    while body.last == 0 { body = body.dropLast() }
                    guard let text = String(bytes: body, encoding: .utf8), printable(text) else { return nil }
                    out += text
                case "x":
                    out += chunk.map { String(format: "%02x", $0) }.joined()
                case "d", "o":
                    var v: UInt64 = 0
                    for b in chunk.prefix(8) { v = (v << 8) | UInt64(b) }
                    out += String(v, radix: spec.format == "d" ? 10 : 8)
                default: break
                }
                let lastInGroup = r == reps - 1
                if pos < data.count, let sep = spec.separator, !(spec.star && lastInGroup && spec.terminator != nil) {
                    out.append(sep)
                }
            }
            if spec.star, let t = spec.terminator, pos < data.count { out.append(t) }
            if spec.length == 0 && !spec.star { break }
        }
        return out
    }

    /// Text a DisplayString may show as is: no control characters except tab / CR / LF.
    static func printable(_ s: String) -> Bool {
        s.unicodeScalars.allSatisfy { $0 == "\n" || $0 == "\t" || $0 == "\r" || ($0.value >= 32 && $0.value != 127) }
    }

    /// SNMPv2-TC DateAndTime: "2026-09-23 14:05:03.4 +07:00".
    static func dateAndTime(_ d: [UInt8]) -> String? {
        guard d.count == 8 || d.count == 11 else { return nil }
        let year = Int(d[0]) << 8 | Int(d[1])
        var s = String(format: "%04d-%02d-%02d %02d:%02d:%02d.%d", year, d[2], d[3], d[4], d[5], d[6], d[7])
        // Direction must be '+' or '-' (RFC 2579); anything else would print a control byte.
        if d.count == 11, d[8] == 0x2B || d[8] == 0x2D {
            s += String(format: " %@%02d:%02d", String(UnicodeScalar(d[8])), d[9], d[10])
        }
        return s
    }

    /// BITS: the set bits by label, "up(0) down(3)".
    static func bits(_ d: [UInt8], labels: [Int64: String]) -> String {
        var set: [String] = []
        for (byteIndex, byte) in d.enumerated() {
            for bit in 0..<8 where byte & (0x80 >> bit) != 0 {
                let n = Int64(byteIndex * 8 + bit)
                set.append("\(labels[n] ?? "b")(\(n))")
            }
        }
        let hex = d.map { String(format: "%02x", $0) }.joined(separator: " ")
        return set.isEmpty ? hex : set.joined(separator: " ")
    }
}
