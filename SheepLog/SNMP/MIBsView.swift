import AppKit
import SwiftUI

/// Loaded modules (bundled + user), and a browser over the linked OID tree. SNMP ▸ MIBs, the
/// LabDC way: the counts as the header's state, the modules table in the column, then the tree
/// and an inspector of label-above facts divided by one hairline.
struct MIBsView: View {
    @ObservedObject private var mibs = MIBRegistry.shared
    @State private var selectedModule: MIBModule.ID?
    @State private var search = ""
    @FocusState private var searchFocused: Bool
    @State private var selectedNode: OID?
    @State private var expanded: Set<OID> = [OID([1]), OID([1, 3]), OID([1, 3, 6]), OID([1, 3, 6, 1])]

    private static let browseHeight: CGFloat = 440
    private static let inspectorWidth: CGFloat = 380

    var body: some View {
        let _ = PaneProbe.ran("body.mibs")
        VStack(spacing: 0) {
            PaneHeader(pane: .mibs,
                       status: "\(Format.count(mibs.modules.count)) modules, \(Format.count(mibs.nodeCount)) objects",
                       detail: headerDetail, problem: badModules > 0) {
                Button("Reveal folder") { revealFolder() }.buttonStyle(.quietLink).fixedSize()
                Button("Reload") { mibs.reload() }.buttonStyle(.quietLink).fixedSize()
                Button("Add files…") { addFiles() }.buttonStyle(.quietPrimary).fixedSize()
            }
            .paneColumn()
            .padding(.top, Metrics.headerTop)
            .padding(.bottom, 14)

            PaneBody(spacing: 28) {
                moduleTable
                if let m = selectedModuleValue, !m.errors.isEmpty {
                    PaneGroup("Errors in \(m.name)") {
                        ForEach(Array(m.errors.prefix(20).enumerated()), id: \.offset) { _, e in
                            NoteRow(text: e, tint: Theme.warn)
                        }
                    }
                }
                PaneSection("Browse") {
                    HStack(alignment: .top, spacing: 0) {
                        browser
                        Rectangle().fill(Theme.hairline).frame(width: 1, height: Self.browseHeight)
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
        #if DEBUG
        // `-demoMIBModule IF-MIB` (Debug): select that module's row (screenshots of the table).
        if selectedModule == nil, let module = CommandLine.value(after: "-demoMIBModule"),
           mibs.modules.contains(where: { $0.id == module }) {
            selectedModule = module
        }
        #endif
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

    /// Your modules with errors or missing imports (listed first in the table).
    private var badModules: Int {
        mibs.modules.filter { !$0.builtIn && (!$0.errors.isEmpty || !$0.missingImports.isEmpty) }.count
    }

    /// The facts after the counts: linking, what you added and how it linked.
    private var headerDetail: String {
        if mibs.isLoading { return "Linking…" }
        let mine = mibs.modules.filter { !$0.builtIn }.count
        guard mine > 0 else { return "the bundled standard MIBs" }
        let yours = "\(Format.count(mine)) of yours"
        let bad = badModules
        return bad == 0 ? "\(yours), all linked" : "\(yours) · \(bad) with errors or missing imports, listed first"
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
            .width(min: 150, ideal: 220)
            TableColumn("Objects") { m in
                Text(Format.count(m.nodeCount)).font(.system(size: 12)).monospacedDigit()
            }
            .width(min: 50, ideal: 70, max: 90)
            TableColumn("Source") { m in
                Text(m.builtIn ? "Bundled" : "Your files")
                    .font(.system(size: 12))
                    .foregroundStyle(m.builtIn ? Theme.dimText : Theme.text)
            }
            .width(min: 60, ideal: 80, max: 100)
            TableColumn("Missing imports") { m in
                Text(m.missingImports.joined(separator: ", "))
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.err)
                    .help(m.missingImports.joined(separator: ", "))
            }
            .width(min: 90, ideal: 160)
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
        .quietTable(selection: selectedModule)
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
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                TextField("Search names", text: $search)
                    .textFieldStyle(.quiet)
                    .focused($searchFocused)
                    .onExitCommand { search = "" }
                    .help("Object names, e.g. ifOperStatus or sysDescr. ⌘F to focus, Esc to clear")
                    .accessibilityLabel("Search names")
                if !search.isEmpty {
                    Button { search = "" } label: { Text("Clear").font(Theme.caption) }
                        .buttonStyle(.quietLink)
                        .help("Clear the search (Esc)")
                        .accessibilityLabel("Clear the search")
                }
            }
            .frame(maxWidth: 320, alignment: .leading)
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(visibleRows) { row in treeRow(row).id(row.id) }
                    }
                    .padding(.bottom, 4)
                }
                // A revealed object (-demoMIBs) is brought into view; a click on a row
                // already in view does not move the list.
                .onChange(of: selectedNode, initial: true) { _, oid in
                    guard let oid else { return }
                    DispatchQueue.main.async { proxy.scrollTo(oid) }
                }
            }
        }
        .padding(.trailing, 20)
        .frame(minWidth: 300, maxWidth: .infinity, alignment: .leading)
        .frame(height: Self.browseHeight)
    }

    private func treeRow(_ row: TreeRow) -> some View {
        let n = row.node
        let isSelected = selectedNode == n.oid
        let searching = !search.trimmingCharacters(in: .whitespaces).isEmpty
        return HStack(spacing: 6) {
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
                .font(.system(size: 12, weight: isSelected ? .semibold : .regular, design: .monospaced))
                .foregroundStyle(Theme.text)
            Text(searching ? n.oid.dotted : String(n.oid.parts.last ?? 0))
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(Theme.faintText)
            Spacer(minLength: 8)
            if n.kind != "node" {
                Text(n.kind)
                    .font(Theme.caption)
                    .foregroundStyle(Theme.faintText)
            }
        }
        .lineLimit(1)
        .padding(.leading, 10 + CGFloat(row.depth) * 14)
        .padding(.trailing, 8)
        .padding(.vertical, 4)
        // The quiet selection: the tables' fill with a 2 pt ink edge on the left.
        .background {
            if isSelected {
                HStack(spacing: 0) {
                    Rectangle().fill(Theme.text).frame(width: 2)
                    Rectangle().fill(Theme.selectedAccent)
                }
            }
        }
        .contentShape(Rectangle())
        .onTapGesture { selectedNode = n.oid }
        .onTapGesture(count: 2) {
            if row.hasChildren {
                if expanded.contains(n.oid) { expanded.remove(n.oid) } else { expanded.insert(n.oid) }
            }
        }
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }

    // MARK: Detail

    /// The selected object as LabDC's inspector: the name large, a muted line under it, the one
    /// action, then label-above rows with hairlines and a Copy on what is worth pasting, and the
    /// description as plain prose.
    @ViewBuilder
    private var detail: some View {
        if let oid = selectedNode, let n = mibs.exactNode(oid) {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(n.name)
                            .font(Theme.subtitle)
                            .tracking(-0.4)
                            .foregroundStyle(Theme.text)
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                            .accessibilityAddTraits(.isHeader)
                        Text([n.kind == "node" ? nil : n.kind, n.module].compactMap { $0 }.joined(separator: " · "))
                            .font(Theme.detail)
                            .foregroundStyle(Theme.text2)
                    }
                    Button("Use in SNMP test") { useInTest(n) }
                        .buttonStyle(.quietLink)
                        .padding(.top, 12)
                        .padding(.bottom, 14)
                    GroupedList {
                        InspectorRow(label: "Module", value: n.module, mono: true, copy: true)
                        InspectorRow(label: "OID", value: n.oid.dotted, mono: true, copy: true)
                        InspectorRow(label: "Kind", value: n.kind)
                        if let s = n.syntax { InspectorRow(label: "Syntax", value: s, mono: true, copy: true) }
                        if let a = n.access { InspectorRow(label: "Access", value: a) }
                        if let s = n.status { InspectorRow(label: "Status", value: s) }
                        if let h = n.displayHint { InspectorRow(label: "Display hint", value: h, mono: true, copy: true) }
                        if let e = n.enums, !e.isEmpty {
                            InspectorRow(label: "Values",
                                         value: e.sorted { $0.key < $1.key }.map { "\($0.value)(\($0.key))" }.joined(separator: ", "),
                                         copy: true)
                        }
                    }
                    if let d = n.description, !d.isEmpty {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Description").font(Theme.caption).foregroundStyle(Theme.text2)
                            Text(Self.cleanDescription(d))
                                .font(Theme.body)
                                .foregroundStyle(Theme.text)
                                .lineSpacing(2)
                                .textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .padding(.top, 18)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 24)
                .padding(.trailing, 14)
                .padding(.bottom, 16)
            }
            .frame(width: Self.inspectorWidth, height: Self.browseHeight, alignment: .top)
        } else {
            Text("Select an object to see its syntax, access and description.")
                .hint()
                .padding(.leading, 24)
                .frame(width: Self.inspectorWidth, height: Self.browseHeight, alignment: .topLeading)
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

/// One fact of the MIBs inspector (LabDC's InspectorRow): the label above the value, a Copy
/// word at the right for what is worth pasting.
private struct InspectorRow: View {
    let label: String
    let value: String
    var mono = false
    var copy = false

    var body: some View {
        HStack(alignment: .lastTextBaseline, spacing: 16) {
            VStack(alignment: .leading, spacing: 4) {
                Text(label).font(Theme.caption).foregroundStyle(Theme.text2)
                Text(value)
                    .font(mono ? Theme.mono : Theme.body)
                    .foregroundStyle(Theme.text)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            if copy { CopyButton(value: value, help: "Copy the \(label.lowercased())") }
        }
        .padding(.vertical, 9)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
