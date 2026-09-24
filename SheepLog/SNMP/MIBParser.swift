import Foundation

/// A tolerant SMIv1/SMIv2 module parser: OBJECT IDENTIFIER assignments, OBJECT-TYPE,
/// MODULE-IDENTITY, OBJECT-IDENTITY, NOTIFICATION-TYPE, TEXTUAL-CONVENTION (enums +
/// DISPLAY-HINT), IMPORTS. Anything it cannot read is skipped and reported, never fatal.
nonisolated struct MIBRawNode: Sendable, Equatable {
    let name: String
    /// Parent symbol name (e.g. "ifEntry") and the arc(s) under it; a fully numeric parent is
    /// allowed ("iso" / "1").
    let parent: String
    let arcs: [UInt32]
    var kind: String = "node"
    var syntax: String? = nil
    var enums: [Int64: String]? = nil
    var displayHint: String? = nil
    var access: String? = nil
    var status: String? = nil
    var description: String? = nil
}

nonisolated struct MIBParseResult: Sendable {
    let moduleName: String
    let nodes: [MIBRawNode]
    /// module → symbols imported from it.
    let imports: [String: [String]]
    /// Textual conventions defined here: name → (syntax, enums, hint).
    let textualConventions: [String: MIBRawNode]
    let errors: [String]
}

nonisolated enum MIBParser {
    /// The first module in `text` (see `parseModules` for files that hold several).
    static func parse(_ text: String, fileName: String) -> MIBParseResult {
        parseModules(text, fileName: fileName)[0]
    }

    /// Every module in `text`, in order — vendor files often carry a `…-TC-MIB` or `…-SMI`
    /// module followed by the MIB that imports from it. Never empty.
    static func parseModules(_ text: String, fileName: String) -> [MIBParseResult] {
        var p = Parser(tokens: Tokenizer.tokenize(text), fileName: fileName)
        return p.run()
    }

    /// Reads a file as UTF-8 (falling back to Latin-1, which never fails).
    static func parse(contentsOf url: URL) -> MIBParseResult {
        parseModules(contentsOf: url)[0]
    }

    static func parseModules(contentsOf url: URL) -> [MIBParseResult] {
        let name = url.deletingPathExtension().lastPathComponent
        guard let data = try? Data(contentsOf: url) else {
            return [MIBParseResult(moduleName: name, nodes: [], imports: [:], textualConventions: [:],
                                   errors: ["cannot read \(url.lastPathComponent)"])]
        }
        let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1)
            ?? String(decoding: data, as: UTF8.self)
        return parseModules(text, fileName: name)
    }
}

// MARK: - Tokens

nonisolated struct MIBToken: Sendable, Equatable {
    enum Kind: Sendable { case word, number, string, symbol }
    let kind: Kind
    let text: String
    let line: Int
}

nonisolated enum Tokenizer {
    static func tokenize(_ text: String) -> [MIBToken] {
        let b = Array(text.utf8)
        var out: [MIBToken] = []
        out.reserveCapacity(b.count / 6)
        var i = 0
        var line = 1
        let n = b.count

        func isAlpha(_ c: UInt8) -> Bool { (c >= 65 && c <= 90) || (c >= 97 && c <= 122) }
        func isDigit(_ c: UInt8) -> Bool { c >= 48 && c <= 57 }
        func slice(_ from: Int, _ to: Int) -> String { String(decoding: b[from..<to], as: UTF8.self) }

        while i < n {
            let c = b[i]
            if c == 10 { line += 1; i += 1; continue }
            if c == 32 || c == 9 || c == 13 || c == 12 || c == 11 { i += 1; continue }
            // Comment: "--" to end of line or to the next "--".
            if c == 45, i + 1 < n, b[i + 1] == 45 {
                i += 2
                while i < n, b[i] != 10 {
                    if b[i] == 45, i + 1 < n, b[i + 1] == 45 { i += 2; break }
                    i += 1
                }
                continue
            }
            if c == 34 { // "string", "" is an embedded quote
                let startLine = line
                var j = i + 1
                var s: [UInt8] = []
                while j < n {
                    if b[j] == 34 {
                        if j + 1 < n, b[j + 1] == 34 { s.append(34); j += 2; continue }
                        break
                    }
                    if b[j] == 10 { line += 1 }
                    s.append(b[j])
                    j += 1
                }
                out.append(MIBToken(kind: .string, text: String(decoding: s, as: UTF8.self), line: startLine))
                i = min(n, j + 1)
                continue
            }
            if c == 39 { // 'hex'H / 'bin'B
                var j = i + 1
                while j < n, b[j] != 39, b[j] != 10 { j += 1 }
                if j < n, b[j] == 39 { j += 1 }
                if j < n, isAlpha(b[j]) { j += 1 }
                out.append(MIBToken(kind: .string, text: slice(i, j), line: line))
                i = j
                continue
            }
            if isAlpha(c) || c == 95 {
                var j = i + 1
                while j < n {
                    let d = b[j]
                    if isAlpha(d) || isDigit(d) || d == 95 { j += 1; continue }
                    if d == 45 {
                        if j + 1 < n, b[j + 1] == 45 { break }   // comment follows
                        j += 1; continue
                    }
                    break
                }
                var end = j
                while end > i + 1, b[end - 1] == 45 { end -= 1 }   // no trailing hyphen
                out.append(MIBToken(kind: .word, text: slice(i, end), line: line))
                i = end
                continue
            }
            if isDigit(c) || (c == 45 && i + 1 < n && isDigit(b[i + 1])) {
                var j = i + 1
                while j < n, isDigit(b[j]) { j += 1 }
                out.append(MIBToken(kind: .number, text: slice(i, j), line: line))
                i = j
                continue
            }
            if c == 58, i + 2 < n, b[i + 1] == 58, b[i + 2] == 61 {
                out.append(MIBToken(kind: .symbol, text: "::=", line: line)); i += 3; continue
            }
            if c == 46, i + 1 < n, b[i + 1] == 46 {
                out.append(MIBToken(kind: .symbol, text: "..", line: line)); i += 2; continue
            }
            if c >= 128 { i += 1; continue }   // stray non-ASCII outside strings
            // A lone "-" means nothing in SMI (negative numbers are handled above). It shows up
            // after separator lines with an odd number of dashes ("-----": "--" "--" "-"), and
            // as a symbol it would make the parser skip the next definition.
            if c == 45 { i += 1; continue }
            out.append(MIBToken(kind: .symbol, text: String(UnicodeScalar(c)), line: line))
            i += 1
        }
        return out
    }
}

// MARK: - Parser

nonisolated private struct Parser {
    let tokens: [MIBToken]
    let fileName: String
    var i = 0
    var moduleName = ""
    var nodes: [MIBRawNode] = []
    var imports: [String: [String]] = [:]
    var tcs: [String: MIBRawNode] = [:]
    var errors: [String] = []
    /// Problems past `maxErrors`, counted only.
    var extraErrors = 0
    /// Names already in `nodes` (O(1) check for named intermediate arcs).
    var nodeNames: Set<String> = []
    /// Modules finished earlier in the same file.
    var finished: [MIBParseResult] = []
    /// The current module's END was seen.
    var ended = false

    init(tokens: [MIBToken], fileName: String) {
        self.tokens = tokens
        self.fileName = fileName
    }

    static let macroInvocations: Set<String> = [
        "OBJECT-TYPE", "MODULE-IDENTITY", "OBJECT-IDENTITY", "NOTIFICATION-TYPE", "OBJECT-GROUP",
        "NOTIFICATION-GROUP", "MODULE-COMPLIANCE", "AGENT-CAPABILITIES",
    ]

    // Token helpers
    var atEnd: Bool { i >= tokens.count }
    func peek(_ k: Int = 0) -> String? { i + k < tokens.count ? tokens[i + k].text : nil }
    func peekToken(_ k: Int = 0) -> MIBToken? { i + k < tokens.count ? tokens[i + k] : nil }
    mutating func next() -> MIBToken? {
        guard i < tokens.count else { return nil }
        defer { i += 1 }
        return tokens[i]
    }
    mutating func accept(_ s: String) -> Bool {
        if peek() == s, tokens[i].kind != .string { i += 1; return true }
        return false
    }
    var line: Int { i < tokens.count ? tokens[i].line : (tokens.last?.line ?? 0) }

    /// Skips a balanced `{ … }` / `( … )` / `[ … ]` group starting at the current token.
    mutating func skipBalanced() {
        guard let open = peekToken(), open.kind == .symbol else { return }
        let close: String
        switch open.text {
        case "{": close = "}"
        case "(": close = ")"
        case "[": close = "]"
        default: return
        }
        var depth = 0
        while let t = next() {
            if t.kind == .symbol {
                if t.text == open.text { depth += 1 }
                else if t.text == close { depth -= 1; if depth == 0 { return } }
            }
        }
    }

    mutating func run() -> [MIBParseResult] {
        // Header: NAME DEFINITIONS [tags] ::= BEGIN
        if let d = tokens.firstIndex(where: { $0.kind == .word && $0.text == "DEFINITIONS" }), d > 0 {
            moduleName = tokens[d - 1].text
            i = d + 1
            while !atEnd, !accept("BEGIN") { i += 1 }
        } else {
            moduleName = fileName
            note("no 'DEFINITIONS ::= BEGIN' header")
        }
        body()
        if !ended { note("the module has no END (the file may be cut short)") }
        finishModule()
        return finished
    }

    /// Errors kept per module (a 20 MB file of junk makes one per construct), and how much of
    /// a token an error quotes (a 1 MB "word").
    static let maxErrors = 200
    static let quoteLength = 64

    static func quote(_ s: String) -> String {
        s.utf8.count <= quoteLength ? s : String(s.prefix(quoteLength)) + "…"
    }

    mutating func note(_ message: String) {
        if errors.count < Parser.maxErrors { errors.append(message) } else { extraErrors += 1 }
    }

    /// Closes the current module and starts over with empty tables.
    mutating func finishModule() {
        fixColumns()
        if extraErrors > 0 { errors.append("… and \(extraErrors) more problems") }
        extraErrors = 0
        if moduleName.utf8.count > 128 { moduleName = Parser.quote(moduleName) }
        finished.append(MIBParseResult(moduleName: moduleName, nodes: nodes, imports: imports,
                                       textualConventions: tcs, errors: errors))
        nodes = []
        imports = [:]
        tcs = [:]
        errors = []
        nodeNames = []
    }

    /// Finishes the current module and starts `name` at its `DEFINITIONS … ::= BEGIN` (the
    /// current token is the name).
    mutating func startModule(_ name: String) {
        finishModule()
        moduleName = name
        ended = false
        i += 2
        while !atEnd, !accept("BEGIN") { i += 1 }
    }

    mutating func body() {
        var guardCounter = 0
        while !atEnd {
            let before = i
            statement()
            if i == before { i += 1 }        // never stall
            guardCounter += 1
            if guardCounter > tokens.count + 10 { break }
        }
    }

    mutating func statement() {
        guard let t0 = peekToken() else { return }
        if t0.kind == .word {
            switch t0.text {
            case "IMPORTS": i += 1; parseImports(); return
            case "EXPORTS": i += 1; while !atEnd, !accept(";") { i += 1 }; return
            case "END":
                i += 1
                ended = true
                // Another module in the same file: it is a module of its own (other files
                // import from it by name).
                if peek(1) == "DEFINITIONS", let next = peekToken(), next.kind == .word {
                    startModule(next.text)
                }
                return
            default: break
            }
        }
        guard t0.kind == .word, let t1 = peek(1) else { unknown(); return }
        let name = t0.text
        if t1 == "DEFINITIONS" {
            // The next module's header with no END before it: the previous module was cut
            // short. It must not swallow this one (whose objects other modules import).
            note("line \(t0.line): no END before module \(Parser.quote(name))")
            startModule(name)
            return
        }
        if t1 == "MACRO" {
            i += 2
            while let t = next(), !(t.kind == .word && t.text == "END") {}
            return
        }
        if t1 == "OBJECT", peek(2) == "IDENTIFIER", peek(3) == "::=" {
            i += 4
            let startLine = t0.line
            addOIDNodes(name: name, value: parseOIDValue(), kind: "node", line: startLine)
            return
        }
        if t1 == "::=" {
            i += 2
            typeAssignment(name)
            return
        }
        if Parser.macroInvocations.contains(t1) {
            i += 2
            macroInvocation(name: name, macro: t1, line: t0.line)
            return
        }
        if t1 == "TRAP-TYPE" {
            i += 2
            trapType(name: name, line: t0.line)
            return
        }
        unknown()
    }

    mutating func unknown() {
        let start = peekToken()
        note("line \(start?.line ?? 0): skipped unknown construct starting at '\(Parser.quote(start?.text ?? ""))'")
        while !atEnd, !accept("::=") { i += 1 }
        skipValue()
    }

    mutating func skipValue() {
        guard let t = peekToken() else { return }
        if t.kind == .symbol, t.text == "{" { skipBalanced(); return }
        i += 1
        while let p = peekToken(), p.kind == .symbol, p.text == "{" || p.text == "(" { skipBalanced() }
    }

    mutating func parseImports() {
        var pending: [String] = []
        while let t = next() {
            if t.kind == .symbol, t.text == ";" { break }
            if t.kind == .word, t.text == "FROM" {
                guard let m = next() else { break }
                imports[m.text, default: []].append(contentsOf: pending)
                pending = []
                continue
            }
            if t.kind == .word { pending.append(t.text) }
        }
    }

    // MARK: Types

    struct TypeInfo {
        var syntax: String
        var enums: [Int64: String]?
        var isBits = false
        var isSequence = false
    }

    mutating func parseType() -> TypeInfo {
        if peek() == "[" { skipBalanced() }
        _ = accept("IMPLICIT") || accept("EXPLICIT")
        guard let t = next() else { return TypeInfo(syntax: "") }
        var info: TypeInfo
        switch t.text {
        case "OCTET":
            _ = accept("STRING")
            info = TypeInfo(syntax: "OCTET STRING")
        case "OBJECT":
            _ = accept("IDENTIFIER")
            info = TypeInfo(syntax: "OBJECT IDENTIFIER")
        case "SEQUENCE":
            if accept("OF") {
                let entry = next()?.text ?? ""
                info = TypeInfo(syntax: "SEQUENCE OF \(entry)")
            } else {
                skipBalanced()
                info = TypeInfo(syntax: "SEQUENCE", isSequence: true)
            }
        case "CHOICE":
            skipBalanced()
            info = TypeInfo(syntax: "CHOICE", isSequence: true)
        default:
            info = TypeInfo(syntax: t.text, isBits: t.text == "BITS")
        }
        if peek() == "{", !info.isSequence {
            info.enums = parseNamedNumbers()
        }
        while let p = peekToken(), p.kind == .symbol, p.text == "(" { skipBalanced() }
        return info
    }

    /// `{ up(1), down(2) }` (also tolerates missing commas).
    mutating func parseNamedNumbers() -> [Int64: String] {
        var out: [Int64: String] = [:]
        guard accept("{") else { return out }
        while let t = peekToken(), !(t.kind == .symbol && t.text == "}") {
            i += 1
            if t.kind == .word, accept("(") {
                if let num = peekToken(), num.kind == .number, let v = Int64(num.text) {
                    out[v] = t.text
                    i += 1
                }
                while !atEnd, !accept(")") { i += 1 }
            }
        }
        _ = accept("}")
        return out
    }

    mutating func typeAssignment(_ name: String) {
        if accept("TEXTUAL-CONVENTION") {
            var node = MIBRawNode(name: name, parent: "", arcs: [], kind: "tc")
            while let t = peekToken() {
                if t.kind == .word {
                    switch t.text {
                    case "DISPLAY-HINT":
                        i += 1
                        if peekToken()?.kind == .string { node.displayHint = next()?.text }
                        continue
                    case "STATUS": i += 1; node.status = next()?.text; continue
                    case "DESCRIPTION":
                        i += 1
                        if peekToken()?.kind == .string { node.description = next()?.text }
                        continue
                    case "REFERENCE": i += 1; if peekToken()?.kind == .string { i += 1 }; continue
                    case "SYNTAX":
                        i += 1
                        let ti = parseType()
                        node.syntax = ti.syntax
                        node.enums = ti.enums
                        tcs[name] = node
                        return
                    default: break
                    }
                }
                note("line \(t.line): unexpected '\(Parser.quote(t.text))' in TEXTUAL-CONVENTION \(Parser.quote(name))")
                return
            }
            return
        }
        // Plain type assignment: `DisplayString ::= OCTET STRING`, `IfEntry ::= SEQUENCE {…}`.
        let ti = parseType()
        if !ti.isSequence {
            tcs[name] = MIBRawNode(name: name, parent: "", arcs: [], kind: "tc", syntax: ti.syntax, enums: ti.enums)
        }
    }

    // MARK: Values

    struct OIDElement {
        var name: String?
        var number: UInt32?
    }

    mutating func parseOIDValue() -> [OIDElement]? {
        guard accept("{") else {
            note("line \(line): expected '{' for an OID value")
            skipValue()
            return nil
        }
        var out: [OIDElement] = []
        while let t = next() {
            if t.kind == .symbol, t.text == "}" {
                // SMI allows 128 sub-identifiers per OID; a value of 100,000 arcs made the
                // index build quadratic.
                guard out.count <= 128 else {
                    note("line \(t.line): OID value with \(out.count) arcs (at most 128)")
                    return nil
                }
                return out
            }
            switch t.kind {
            case .word:
                var e = OIDElement(name: t.text, number: nil)
                if accept("(") {
                    if let n = peekToken(), n.kind == .number { e.number = UInt32(n.text); i += 1 }
                    while !atEnd, !accept(")") { i += 1 }
                }
                out.append(e)
            case .number:
                out.append(OIDElement(name: nil, number: UInt32(t.text)))
            default:
                break
            }
        }
        note("unterminated OID value")
        return nil
    }

    /// Emits the node (and any named intermediate arcs like `org(3)`).
    mutating func addOIDNodes(name: String, value: [OIDElement]?, kind: String, line: Int,
                              configure: (inout MIBRawNode) -> Void = { _ in }) {
        guard let value, let first = value.first else {
            note("line \(line): \(name) has no OID value")
            return
        }
        var parent: String
        if let n = first.number { parent = String(n) }
        else if let nm = first.name { parent = nm }
        else { return }
        var arcs: [UInt32] = []
        let rest = value.dropFirst()
        for (k, e) in rest.enumerated() {
            guard let num = e.number else {
                note("line \(line): \(name): symbolic arc '\(e.name ?? "?")' without a number")
                return
            }
            let isLast = k == rest.count - 1
            if let nm = e.name, !isLast {
                if nodeNames.insert(nm).inserted {
                    nodes.append(MIBRawNode(name: nm, parent: parent, arcs: arcs + [num]))
                }
                parent = nm
                arcs = []
            } else {
                arcs.append(num)
            }
        }
        var node = MIBRawNode(name: name, parent: parent, arcs: arcs, kind: kind)
        configure(&node)
        nodes.append(node)
        nodeNames.insert(name)
    }

    mutating func macroInvocation(name: String, macro: String, line: Int) {
        var syntax: TypeInfo?
        var access: String?
        var status: String?
        var description: String?
        var hint: String?
        var isRow = false
        while let t = peekToken() {
            if t.kind == .symbol, t.text == "::=" { break }
            i += 1
            if t.kind == .symbol, t.text == "{" || t.text == "(" { i -= 1; skipBalanced(); continue }
            guard t.kind == .word else { continue }
            switch t.text {
            case "SYNTAX":
                let ti = parseType()
                if syntax == nil { syntax = ti }
            case "MAX-ACCESS", "ACCESS":
                let v = next()?.text
                if access == nil { access = v }
            case "MIN-ACCESS":
                i += 1
            case "STATUS":
                let v = next()?.text
                if status == nil { status = v }
            case "DESCRIPTION":
                if peekToken()?.kind == .string {
                    let v = next()?.text
                    if description == nil { description = v }
                }
            case "DISPLAY-HINT":
                if peekToken()?.kind == .string { hint = next()?.text }
            case "INDEX", "AUGMENTS":
                isRow = true
                skipBalanced()
            default:
                break
            }
        }
        guard accept("::=") else {
            note("line \(line): \(name) \(macro) has no '::='")
            return
        }
        let kind: String
        switch macro {
        case "OBJECT-TYPE":
            if syntax?.syntax.hasPrefix("SEQUENCE OF") == true { kind = "table" }
            else if isRow { kind = "row" }
            else { kind = "scalar" }
        case "MODULE-IDENTITY": kind = "module"
        case "NOTIFICATION-TYPE": kind = "notification"
        default: kind = "node"
        }
        let value = parseOIDValue()
        let isObject = macro == "OBJECT-TYPE"
        addOIDNodes(name: name, value: value, kind: kind, line: line) { n in
            if isObject {
                n.syntax = syntax?.syntax
                n.enums = syntax?.enums
                n.access = access
                n.displayHint = hint
            }
            n.status = status
            n.description = description
        }
    }

    mutating func trapType(name: String, line: Int) {
        var enterprise: String?
        var description: String?
        while let t = peekToken() {
            if t.kind == .symbol, t.text == "::=" { break }
            i += 1
            if t.kind == .symbol, t.text == "{" { i -= 1; skipBalanced(); continue }
            guard t.kind == .word else { continue }
            switch t.text {
            case "ENTERPRISE": enterprise = next()?.text
            case "DESCRIPTION":
                if peekToken()?.kind == .string { description = next()?.text }
            default: break
            }
        }
        guard accept("::="), let enterprise, let numTok = next(), numTok.kind == .number,
              let n = UInt32(numTok.text) else {
            note("line \(line): TRAP-TYPE \(name) is incomplete")
            return
        }
        nodes.append(MIBRawNode(name: name, parent: enterprise, arcs: [0, n], kind: "notification",
                                status: "current", description: description))
    }

    /// Leaf OBJECT-TYPEs under a row of this module are columns.
    mutating func fixColumns() {
        let rows = Set(nodes.filter { $0.kind == "row" }.map(\.name))
        guard !rows.isEmpty else { return }
        for k in nodes.indices where nodes[k].kind == "scalar" && rows.contains(nodes[k].parent) {
            nodes[k].kind = "column"
        }
    }
}
