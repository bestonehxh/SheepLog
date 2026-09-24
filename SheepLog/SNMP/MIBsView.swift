import AppKit
import SwiftUI

/// Loaded modules (bundled + user), and a browser over the linked OID tree.
struct MIBsView: View {
    @ObservedObject private var mibs = MIBRegistry.shared
    @State private var selectedModule: MIBModule.ID?
    @State private var search = ""
    @FocusState private var searchFocused: Bool
    @State private var selectedNode: OID?
    @State private var expanded: Set<OID> = [OID([1]), OID([1, 3]), OID([1, 3, 6]), OID([1, 3, 6, 1])]

    var body: some View {
        let _ = PaneProbe.ran("body.mibs")
        VStack(spacing: 0) {
            PaneHeader(eyebrow: "SNMP",
                       heading: "\(Format.count(mibs.modules.count)) modules, \(Format.count(mibs.nodeCount)) objects.",
                       subtitle: subtitle)
                .paneColumn()
                .padding(.top, Metrics.headerTop)
                .padding(.bottom, 12)

            PaneStrip {
                Button("Add files…") { addFiles() }
                    .buttonStyle(.borderedProminent)
                    .tint(Theme.accent)
                Button("Reveal folder") { revealFolder() }
                Button("Reload") { mibs.reload() }
                Spacer(minLength: 0)
                if mibs.isLoading {
                    ProgressView().controlSize(.small)
                    Text("Linking…").font(.system(size: 12)).foregroundStyle(Theme.dimText)
                }
            }

            PaneBody {
                moduleTable
                if let m = selectedModuleValue, !m.errors.isEmpty {
                    PaneGroup("Errors in \(m.name)") {
                        ForEach(Array(m.errors.prefix(20).enumerated()), id: \.offset) { _, e in
                            NoteRow(text: e, systemImage: "exclamationmark.triangle", tint: Theme.warn)
                        }
                    }
                }
                PaneSection("Browse", note: "the linked OID tree") {
                    HStack(alignment: .top, spacing: 14) {
                        browser
                        detail
                    }
                }
            }
        }
        .paneKeyCommands(find: { searchFocused = true })
        .onChange(of: mibs.generation, initial: true) { _, _ in revealDemoNode() }
    }

    /// `-demoMIBs ifOperStatus`: open the tree down to that object and select it.
    private func revealDemoNode() {
        guard selectedNode == nil, let name = DemoFlags.mibs,
              let oid = mibs.oid(forName: name) else { return }
        var parts = oid.parts
        while !parts.isEmpty { parts.removeLast(); expanded.insert(OID(parts)) }
        selectedNode = oid
    }

    /// Your modules first — the ones with errors or missing imports on top — then the bundled
    /// ones, so a folder import is not lost among 63 standard modules with its broken file
    /// off-screen.
    private var orderedModules: [MIBModule] {
        func rank(_ m: MIBModule) -> Int {
            if m.builtIn { return 2 }
            return m.errors.isEmpty && m.missingImports.isEmpty ? 1 : 0
        }
        return mibs.modules.enumerated().sorted { a, b in
            let ra = rank(a.element), rb = rank(b.element)
            return ra != rb ? ra < rb : a.offset < b.offset
        }.map(\.element)
    }

    private var subtitle: String {
        let mine = mibs.modules.filter { !$0.builtIn }
        guard !mine.isEmpty else { return "Bundled standard MIBs plus what you add" }
        let bad = mine.filter { !$0.errors.isEmpty || !$0.missingImports.isEmpty }.count
        let yours = "\(Format.count(mine.count)) of yours"
        return bad == 0 ? "Bundled standard MIBs plus \(yours), all linked"
            : "Bundled standard MIBs plus \(yours) — \(bad) with errors or missing imports (listed first)"
    }

    private var selectedModuleValue: MIBModule? {
        guard let id = selectedModule else { return nil }
        return mibs.modules.first { $0.id == id }
    }

    // MARK: Modules

    private var moduleTable: some View {
        Table(orderedModules, selection: $selectedModule) {
            TableColumn("Name") { m in
                Text(m.name).font(.system(size: 12, design: .monospaced))
            }
            .width(min: 160, ideal: 240)
            TableColumn("Objects") { m in
                Text(Format.count(m.nodeCount)).font(.system(size: 12)).monospacedDigit()
            }
            .width(min: 50, ideal: 70, max: 90)
            TableColumn("Source") { m in
                Text(m.builtIn ? "Bundled" : "Your files")
                    .font(.system(size: 12))
                    .foregroundStyle(m.builtIn ? Theme.dimText : Theme.accent)
            }
            .width(min: 60, ideal: 80, max: 100)
            TableColumn("Missing imports") { m in
                Text(m.missingImports.joined(separator: ", "))
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.warn)
                    .help(m.missingImports.joined(separator: ", "))
            }
            .width(min: 100, ideal: 220)
            TableColumn("Errors") { m in
                Text(m.errors.isEmpty ? "0" : String(m.errors.count))
                    .font(.system(size: 12))
                    .monospacedDigit()
                    .foregroundStyle(m.errors.isEmpty ? Theme.faintText : Theme.err)
                    .help(m.errors.prefix(5).joined(separator: "\n"))
            }
            .width(min: 40, ideal: 50, max: 70)
        }
        .contextMenu(forSelectionType: MIBModule.ID.self) { ids in
            let chosen = mibs.modules.filter { ids.contains($0.id) }
            if let m = chosen.first, chosen.count == 1 {
                if let path = m.path {
                    Button("Reveal in Finder") { NSWorkspace.shared.activateFileViewerSelecting([path]) }
                }
                Button("Remove") { mibs.remove(m) }
                    .disabled(m.builtIn)
            }
        }
        .overlay {
            if mibs.modules.isEmpty {
                TableEmptyOverlay(text: mibs.isLoading ? "Loading MIBs…" : "No modules loaded. Press Reload, or Add files… to import your MIBs.")
            }
        }
        .tablePanel(minHeight: 200)
        .frame(height: 260)
    }

    private func addFiles() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = true
        panel.canChooseFiles = true
        panel.message = "MIB files (.mib, .my, .txt or no extension) or folders of them"
        panel.prompt = "Add"
        guard panel.runModal() == .OK, !panel.urls.isEmpty else { return }
        mibs.importFiles(panel.urls)
    }

    private func revealFolder() {
        let folder = mibs.userFolder
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        NSWorkspace.shared.open(folder)
    }

    // MARK: Browser

    private struct TreeRow: Identifiable {
        var id: OID { node.oid }
        let node: MIBNode
        let depth: Int
        let hasChildren: Bool
    }

    private var roots: [MIBNode] {
        [OID([0]), OID([1]), OID([2])].compactMap { oid in
            guard let n = mibs.exactNode(oid) else { return nil }
            return oid == OID([1]) || !mibs.children(of: oid).isEmpty ? n : nil
        }
    }

    private var visibleRows: [TreeRow] {
        _ = mibs.generation
        let q = search.trimmingCharacters(in: .whitespaces)
        if !q.isEmpty {
            return mibs.search(q, limit: 400).map { TreeRow(node: $0, depth: 0, hasChildren: false) }
        }
        var out: [TreeRow] = []
        func add(_ n: MIBNode, depth: Int) {
            let kids = mibs.children(of: n.oid)
            out.append(TreeRow(node: n, depth: depth, hasChildren: !kids.isEmpty))
            guard expanded.contains(n.oid), out.count < 5000 else { return }
            for k in kids { add(k, depth: depth + 1) }
        }
        for r in roots { add(r, depth: 0) }
        return out
    }

    private var browser: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass").font(.system(size: 11)).foregroundStyle(Theme.faintText)
                TextField("Search names", text: $search)
                    .textFieldStyle(.plain)
                    .font(.system(size: 12))
                    .focused($searchFocused)
                    .onExitCommand { search = "" }
                    .help("Object names, e.g. ifOperStatus or sysDescr. ⌘F to focus, Esc to clear")
                    .accessibilityLabel("Search names")
                if !search.isEmpty {
                    Button { search = "" } label: { Image(systemName: "xmark.circle.fill") }
                        .buttonStyle(.borderless)
                        .foregroundStyle(Theme.faintText)
                        .help("Clear the search (Esc)")
                        .accessibilityLabel("Clear the search")
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            Rectangle().fill(Theme.hairline).frame(height: 0.5)
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(visibleRows) { row in treeRow(row) }
                }
                .padding(.vertical, 4)
            }
        }
        .frame(minWidth: 320, maxWidth: .infinity)
        .frame(height: 440)
        .panelCard()
    }

    private func treeRow(_ row: TreeRow) -> some View {
        let n = row.node
        let isSelected = selectedNode == n.oid
        let searching = !search.trimmingCharacters(in: .whitespaces).isEmpty
        return HStack(spacing: 5) {
            if !searching {
                Button {
                    if expanded.contains(n.oid) { expanded.remove(n.oid) } else { expanded.insert(n.oid) }
                } label: {
                    Image(systemName: expanded.contains(n.oid) ? "chevron.down" : "chevron.right")
                        .font(.system(size: 9, weight: .semibold))
                        .foregroundStyle(Theme.faintText)
                        .frame(width: 12)
                        .opacity(row.hasChildren ? 1 : 0)
                }
                .buttonStyle(.plain)
                .disabled(!row.hasChildren)
                .accessibilityLabel(expanded.contains(n.oid) ? "Collapse \(n.name)" : "Expand \(n.name)")
                .accessibilityHidden(!row.hasChildren)
            }
            Text(n.name)
                .font(.system(size: 12, design: .monospaced))
                .foregroundStyle(Theme.text)
            Text(searching ? n.oid.dotted : String(n.oid.parts.last ?? 0))
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(Theme.faintText)
            if n.kind != "node" {
                Text(n.kind)
                    .font(.system(size: 10))
                    .foregroundStyle(kindColor(n.kind))
            }
            Spacer(minLength: 0)
        }
        .lineLimit(1)
        .padding(.leading, 8 + CGFloat(row.depth) * 14)
        .padding(.trailing, 8)
        .padding(.vertical, 3)
        .background(isSelected ? Theme.selectedAccent : Color.clear)
        .contentShape(Rectangle())
        .onTapGesture { selectedNode = n.oid }
        .onTapGesture(count: 2) {
            if row.hasChildren {
                if expanded.contains(n.oid) { expanded.remove(n.oid) } else { expanded.insert(n.oid) }
            }
        }
    }

    private func kindColor(_ kind: String) -> Color {
        switch kind {
        case "table", "row": Theme.accent
        case "notification": Theme.warn
        case "column", "scalar": Theme.ok
        default: Theme.faintText
        }
    }

    // MARK: Detail

    @ViewBuilder
    private var detail: some View {
        if let oid = selectedNode, let n = mibs.exactNode(oid) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .firstTextBaseline) {
                    Text(n.name).font(.system(size: 15, weight: .semibold, design: .monospaced)).foregroundStyle(Theme.text)
                        .textSelection(.enabled)
                    Spacer(minLength: 0)
                    Button("Use in SNMP test") { useInTest(n) }
                        .buttonStyle(.borderedProminent)
                        .tint(Theme.accent)
                        .controlSize(.small)
                }
                GroupedList {
                    FactRow(key: "Module", value: n.module, keyWidth: 90)
                    FactRow(key: "OID", value: n.oid.dotted, keyWidth: 90)
                    FactRow(key: "Kind", value: n.kind, mono: false, copyable: false, keyWidth: 90)
                    if let s = n.syntax { FactRow(key: "Syntax", value: s, keyWidth: 90) }
                    if let a = n.access { FactRow(key: "Access", value: a, mono: false, copyable: false, keyWidth: 90) }
                    if let s = n.status { FactRow(key: "Status", value: s, mono: false, copyable: false, keyWidth: 90) }
                    if let h = n.displayHint { FactRow(key: "Hint", value: h, keyWidth: 90) }
                    if let e = n.enums, !e.isEmpty {
                        FactRow(key: "Values",
                                value: e.sorted { $0.key < $1.key }.map { "\($0.value)(\($0.key))" }.joined(separator: ", "),
                                mono: false, keyWidth: 90)
                    }
                }
                if let d = n.description, !d.isEmpty {
                    ScrollView {
                        Text(Self.cleanDescription(d))
                            .font(.system(size: 11.5))
                            .foregroundStyle(Theme.text2)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(10)
                    }
                    .frame(maxHeight: 180)
                    .background(RoundedRectangle(cornerRadius: Metrics.field).fill(Theme.well))
                }
                Spacer(minLength: 0)
            }
            .frame(width: 400, height: 440, alignment: .top)
        } else {
            Text("Select an object to see its syntax, access and description.")
                .hint()
                .frame(width: 400, height: 440, alignment: .center)
        }
    }

    /// MIB descriptions are indented to the column of the opening quote; drop that indent.
    static func cleanDescription(_ s: String) -> String {
        let lines = s.components(separatedBy: "\n")
        let indents = lines.dropFirst().filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
            .map { $0.prefix { $0 == " " }.count }
        let cut = indents.min() ?? 0
        return ([lines.first ?? ""] + lines.dropFirst().map { String($0.dropFirst(min(cut, $0.prefix { $0 == " " }.count))) })
            .joined(separator: "\n")
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func useInTest(_ n: MIBNode) {
        _ = SNMPTestModel.shared
        NotificationCenter.default.post(name: .sheepLogSNMPOID, object: n.oid.dotted)
        AppModel.shared.mainPane = .snmpTest
    }
}
