import Foundation
import Synchronization

// MARK: - The one filter grammar (log lines and packets share it)
//
//   login failed            both words (implicit AND), case-insensitive substring
//   "login failed"          exact phrase
//   a OR b, a AND b         boolean operators (case-insensitive words), AND binds tighter than OR
//   NOT a, -a, !a           negation
//   a NOR b                 = NOT a AND NOT b
//   ( … )                   grouping
//   key:value               field term; the matcher decides what keys mean (host:, sev:, vendor:,
//   key:<=value             app:, f:srcip=…, src:, dst:, port:, proto:, vlan:, …). Operators on the
//   key>=value              value: =, !=, <, <=, >, >= (a bare `key:value` is `=`).
//   /regex/                 a regular expression term; with `regex: true` every bare word is one.

nonisolated enum QueryOp: String, Sendable { case eq = "=", ne = "!=", lt = "<", le = "<=", gt = ">", ge = ">=" }

nonisolated indirect enum QueryNode: Sendable, Equatable {
    /// A bare word or quoted phrase.
    case text(String)
    /// A regular expression (already validated).
    case regex(String)
    /// `key:value` with an operator.
    case field(key: String, op: QueryOp, value: String)
    case and(QueryNode, QueryNode)
    case or(QueryNode, QueryNode)
    case not(QueryNode)
}

nonisolated struct QueryError: Error, LocalizedError, Sendable, Equatable {
    let message: String
    var errorDescription: String? { message }
}

/// A parsed filter. `matches` takes a closure that says whether one **leaf** matches an item; the
/// boolean structure is evaluated here so every module gets the same semantics.
nonisolated struct Query: Sendable, Equatable {
    let root: QueryNode?
    let source: String

    var isEmpty: Bool { root == nil }

    static let empty = Query(root: nil, source: "")

    /// The most terms (words, phrases, keys, regexes) and the deepest nesting (parentheses and
    /// NOTs) a filter may have. The tree is evaluated recursively — on a background task's
    /// 512 KB stack for a re-scan — so a pasted wall of text must be refused, not crash.
    static let maxTerms = 256
    static let maxDepth = 32

    static func parse(_ text: String, regexWords: Bool = false) throws -> Query {
        let tokens = try QueryLexer.tokenize(text)
        if tokens.isEmpty { return .empty }
        let terms = tokens.reduce(0) { n, t in
            switch t {
            case .word, .phrase, .regex: n + 1
            default: n
            }
        }
        guard terms <= maxTerms else {
            throw QueryError(message: "Filter too long (\(terms) terms; at most \(maxTerms))")
        }
        var parser = QueryParser(tokens: tokens, regexWords: regexWords)
        let node = try parser.parseOr()
        if let t = parser.peek { throw QueryError(message: "Unexpected \(t.describe)") }
        return Query(root: node, source: text)
    }

    /// Evaluate against one item. `leaf` answers `.text`, `.regex` and `.field` nodes.
    func matches(_ leaf: (QueryNode) -> Bool) -> Bool {
        guard let root else { return true }
        return Self.eval(root, leaf)
    }

    private static func eval(_ n: QueryNode, _ leaf: (QueryNode) -> Bool) -> Bool {
        switch n {
        case .and(let a, let b): return eval(a, leaf) && eval(b, leaf)
        case .or(let a, let b): return eval(a, leaf) || eval(b, leaf)
        case .not(let a): return !eval(a, leaf)
        default: return leaf(n)
        }
    }

    /// Every leaf in the tree, for highlighting.
    var leaves: [QueryNode] {
        var out: [QueryNode] = []
        func walk(_ n: QueryNode) {
            switch n {
            case .and(let a, let b), .or(let a, let b): walk(a); walk(b)
            case .not(let a): walk(a)
            default: out.append(n)
            }
        }
        if let root { walk(root) }
        return out
    }
}

// MARK: - Helpers every matcher needs

nonisolated enum QueryMatch {
    /// Case-insensitive, non-locale substring test (the cheap one).
    static func contains(_ haystack: String, _ needle: String) -> Bool {
        haystack.range(of: needle, options: .caseInsensitive) != nil
    }

    /// Compare two strings as numbers when both parse, else as case-insensitive text.
    static func compare(_ lhs: String, _ op: QueryOp, _ rhs: String) -> Bool {
        if let a = Double(lhs), let b = Double(rhs) {
            switch op {
            case .eq: return a == b
            case .ne: return a != b
            case .lt: return a < b
            case .le: return a <= b
            case .gt: return a > b
            case .ge: return a >= b
            }
        }
        let c = lhs.caseInsensitiveCompare(rhs)
        switch op {
        case .eq: return contains(lhs, rhs)
        case .ne: return !contains(lhs, rhs)
        case .lt: return c == .orderedAscending
        case .le: return c != .orderedDescending
        case .gt: return c == .orderedDescending
        case .ge: return c != .orderedAscending
        }
    }

    static func compare(_ lhs: Int, _ op: QueryOp, _ rhs: Int) -> Bool {
        switch op {
        case .eq: return lhs == rhs
        case .ne: return lhs != rhs
        case .lt: return lhs < rhs
        case .le: return lhs <= rhs
        case .gt: return lhs > rhs
        case .ge: return lhs >= rhs
        }
    }

    /// A regex, compiled once per pattern and cached. Case-insensitive.
    static func regex(_ pattern: String) -> NSRegularExpression? {
        RegexCache.shared.get(pattern)
    }

    /// One guarded match (first 16 KB, 50 ms at most). Filters use `GuardedRegex`, which also
    /// gives up on a pattern that keeps being slow.
    static func regexMatches(_ pattern: String, _ text: String) -> Bool {
        guard let re = regex(pattern) else { return false }
        return GuardedRegex.match(re, text).hit
    }
}

/// A user's regular expression, run so that it cannot hang the app. NSRegularExpression (ICU)
/// backtracks: `(a+)+$` against 30 a's and a '!' is a billion steps, `.*.*.*=` against a 16 KB
/// line is cubic. So:
/// - only the first `lineCap` UTF-16 units of a line are searched;
/// - each match is abandoned after `matchDeadline` (ICU's progress callback lets us stop it);
/// - once the pattern has cost `totalBudget` in slow matches (or hit the deadline
///   `maxTimeouts` times), it `trips`: every later call answers false at once, and the store
///   says why.
/// Thread-safe (a packet re-scan runs chunks in parallel).
nonisolated final class GuardedRegex: Sendable {
    static let lineCap = 16_384
    static let matchDeadline: UInt64 = 50_000_000          // ns
    /// Time spent in matches slower than `slowMatch`, after which the pattern trips.
    static let totalBudget: UInt64 = 750_000_000            // ns
    static let slowMatch: UInt64 = 200_000                  // ns
    static let maxTimeouts = 4

    let pattern: String
    let re: NSRegularExpression?
    private struct Cost { var slowTime: UInt64 = 0, timeouts = 0, tripped = false }
    private let cost = Mutex(Cost())

    init(_ pattern: String) {
        self.pattern = pattern
        re = QueryMatch.regex(pattern)
    }

    /// True once the pattern was given up on (it then matches nothing).
    var tripped: Bool { cost.withLock { $0.tripped } }

    func matches(_ s: String) -> Bool {
        guard let re, !tripped else { return false }
        let r = Self.match(re, s)
        if r.elapsed >= Self.slowMatch {
            cost.withLock { c in
                c.slowTime &+= r.elapsed
                if r.timedOut { c.timeouts += 1 }
                if c.slowTime >= Self.totalBudget || c.timeouts >= Self.maxTimeouts { c.tripped = true }
            }
        }
        return r.hit
    }

    /// One bounded search. `timedOut` = abandoned at the deadline (counts as no match).
    static func match(_ re: NSRegularExpression, _ s: String) -> (hit: Bool, timedOut: Bool, elapsed: UInt64) {
        let length = min((s as NSString).length, lineCap)
        let start = clock_gettime_nsec_np(CLOCK_UPTIME_RAW)
        var hit = false, timedOut = false, k = 0
        re.enumerateMatches(in: s, options: [.reportProgress], range: NSRange(location: 0, length: length)) { r, _, stop in
            if r != nil { hit = true; stop.pointee = true; return }
            k &+= 1
            if k & 15 == 0, clock_gettime_nsec_np(CLOCK_UPTIME_RAW) &- start > matchDeadline {
                timedOut = true
                stop.pointee = true
            }
        }
        return (hit, timedOut, clock_gettime_nsec_np(CLOCK_UPTIME_RAW) &- start)
    }
}

/// A cheap look at a pattern for the classic catastrophic shapes: a group holding an unbounded
/// quantifier (or an alternation) that is itself repeated without bound or 10+ times —
/// `(a+)+`, `(.*a){20}`, `(x|x)*`, `(\w+\s?)*`. `(\d+\.){3}` is fine. Only a warning: the
/// match itself is guarded either way.
nonisolated enum RegexLint {
    static let message = "Warning: this pattern may be too slow (a repeated group with a quantifier inside); it is stopped if it keeps taking long"
    // (No trailing period: the Syslog pane wraps the text in a sentence of its own.)

    static func warning(_ pattern: String) -> String? {
        let c = Array(pattern.unicodeScalars)
        var i = 0
        // Per open group: does it hold an unbounded quantifier or a '|'?
        var stack: [Bool] = []
        var inClass = false
        while i < c.count {
            let ch = c[i]
            if ch == "\\" { i += 2; continue }
            if inClass {
                if ch == "]" { inClass = false }
                i += 1
                continue
            }
            switch ch {
            case "[": inClass = true
            case "(": stack.append(false)
            case "|", "*", "+":
                if !stack.isEmpty { stack[stack.count - 1] = true }
            case "{":
                if let (_, max) = braces(c, i), max == nil, !stack.isEmpty { stack[stack.count - 1] = true }
            case ")":
                let risky = stack.popLast() ?? false
                if risky, repeatsHeavily(c, i + 1) { return message }
                // The enclosing group inherits the risk (`((a+))+`).
                if risky, !stack.isEmpty { stack[stack.count - 1] = true }
            default: break
            }
            i += 1
        }
        return nil
    }

    /// `{n}`, `{n,}`, `{n,m}` at `i`: (n, m), m nil when unbounded.
    private static func braces(_ c: [Unicode.Scalar], _ i: Int) -> (Int, Int?)? {
        guard i < c.count, c[i] == "{" else { return nil }
        var j = i + 1, a = "", b = "", comma = false
        while j < c.count, c[j] != "}" {
            if c[j] == "," { comma = true } else if comma { b.unicodeScalars.append(c[j]) } else { a.unicodeScalars.append(c[j]) }
            j += 1
        }
        guard j < c.count, let n = Int(a) else { return nil }
        if !comma { return (n, n) }
        if b.isEmpty { return (n, nil) }
        guard let m = Int(b) else { return nil }
        return (n, m)
    }

    /// A quantifier right after a group that repeats it without bound or 10+ times.
    private static func repeatsHeavily(_ c: [Unicode.Scalar], _ i: Int) -> Bool {
        guard i < c.count else { return false }
        if c[i] == "*" || c[i] == "+" { return true }
        if let (_, max) = braces(c, i) { return max.map { $0 >= 10 } ?? true }
        return false
    }
}

nonisolated final class RegexCache: Sendable {
    static let shared = RegexCache()
    private let cache = Mutex<[String: NSRegularExpression]>([:])

    var count: Int { cache.withLock { $0.count } }

    func get(_ pattern: String) -> NSRegularExpression? {
        cache.withLock { cache in
            if let r = cache[pattern] { return r }
            guard let r = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return nil }
            if cache.count > 64 { cache.removeAll() }
            cache[pattern] = r
            return r
        }
    }
}

// MARK: - Lexer / parser

nonisolated enum QueryToken: Equatable, Sendable {
    case word(String)          // bare word, may contain ':' and operators (split by the parser)
    case phrase(String)        // "quoted"
    case regex(String)         // /pattern/
    case and, or, not, nor
    case lparen, rparen

    var describe: String {
        switch self {
        case .word(let w): "'\(w)'"
        case .phrase(let p): "\"\(p)\""
        case .regex(let r): "/\(r)/"
        case .and: "AND"
        case .or: "OR"
        case .not: "NOT"
        case .nor: "NOR"
        case .lparen: "("
        case .rparen: ")"
        }
    }
}

nonisolated enum QueryLexer {
    static func tokenize(_ text: String) throws -> [QueryToken] {
        var out: [QueryToken] = []
        let chars = Array(text)
        var i = 0
        func flushWord(_ w: String) {
            guard !w.isEmpty else { return }
            switch w.uppercased() {
            case "AND", "&&": out.append(.and)
            case "OR", "||": out.append(.or)
            case "NOT": out.append(.not)
            case "NOR": out.append(.nor)
            default:
                if w.hasPrefix("-") || w.hasPrefix("!"), w.count > 1 {
                    out.append(.not)
                    out.append(.word(String(w.dropFirst())))
                } else {
                    out.append(.word(w))
                }
            }
        }
        while i < chars.count {
            let c = chars[i]
            if c.isWhitespace { i += 1; continue }
            if c == "(" { out.append(.lparen); i += 1; continue }
            if c == ")" { out.append(.rparen); i += 1; continue }
            // `-"a phrase"` / `!"host:x y"`: NOT the phrase (a quoted `key:value` is text, with or
            // without the minus in front); `-(a OR b)` / `!(a b)`: NOT the group (it was the
            // word "-" AND the group — the opposite of what was typed, silently); `-/re/` /
            // `!/re/`: NOT the regex (it was NOT the text "/re/", which hid nothing).
            if c == "-" || c == "!", i + 1 < chars.count, chars[i + 1] == "\"" || chars[i + 1] == "(" || chars[i + 1] == "/" {
                out.append(.not); i += 1; continue
            }
            if c == "\"" {
                var j = i + 1; var s = ""
                while j < chars.count, chars[j] != "\"" { s.append(chars[j]); j += 1 }
                guard j < chars.count else { throw QueryError(message: "Unterminated quote") }
                out.append(.phrase(s)); i = j + 1; continue
            }
            if c == "/" {
                var j = i + 1; var s = ""
                while j < chars.count, chars[j] != "/" {
                    if chars[j] == "\\", j + 1 < chars.count { s.append(chars[j]); j += 1 }
                    s.append(chars[j]); j += 1
                }
                guard j < chars.count else { throw QueryError(message: "Unterminated /regex/") }
                guard QueryMatch.regex(s) != nil else {
                    throw QueryError(message: "Invalid regular expression /\(s)/")
                }
                out.append(.regex(s)); i = j + 1; continue
            }
            // A bare word: runs to whitespace or a paren; `key:"quoted value"` keeps its quotes'
            // content as part of the word.
            var w = ""; var j = i
            while j < chars.count, !chars[j].isWhitespace, chars[j] != "(", chars[j] != ")" {
                if chars[j] == "\"" {
                    var k = j + 1
                    while k < chars.count, chars[k] != "\"" { w.append(chars[k]); k += 1 }
                    guard k < chars.count else { throw QueryError(message: "Unterminated quote") }
                    j = k + 1
                    continue
                }
                w.append(chars[j]); j += 1
            }
            flushWord(w); i = j
        }
        return out
    }
}

nonisolated struct QueryParser {
    let tokens: [QueryToken]
    let regexWords: Bool
    var pos = 0
    /// Open parentheses + NOTs around the current term (`Query.maxDepth` at most).
    private var depth = 0

    init(tokens: [QueryToken], regexWords: Bool) {
        self.tokens = tokens
        self.regexWords = regexWords
    }

    var peek: QueryToken? { pos < tokens.count ? tokens[pos] : nil }
    mutating func next() -> QueryToken? { defer { pos += 1 }; return peek }

    mutating func parseOr() throws -> QueryNode {
        var left = try parseAnd()
        // `a NOR b NOR c` = none of them: a NOR after a NOR adds one more NOT term (a
        // left-associative NOR would read it as (a OR b) AND NOT c).
        var afterNOR = false
        while let t = peek, t == .or || t == .nor {
            _ = next()
            let right = try parseAnd()
            if t == .or { left = .or(left, right) }
            else if afterNOR { left = .and(left, .not(right)) }
            else { left = .and(.not(left), .not(right)) }
            afterNOR = t == .nor
        }
        return left
    }

    mutating func parseAnd() throws -> QueryNode {
        var left = try parseUnary()
        while let t = peek {
            if t == .and { _ = next(); left = .and(left, try parseUnary()); continue }
            if t == .or || t == .nor || t == .rparen { break }
            // Implicit AND between adjacent terms.
            left = .and(left, try parseUnary())
        }
        return left
    }

    mutating func parseUnary() throws -> QueryNode {
        guard let t = next() else { throw QueryError(message: "Expected a term") }
        switch t {
        case .not, .lparen:
            depth += 1
            defer { depth -= 1 }
            guard depth <= Query.maxDepth else {
                throw QueryError(message: "Filter nested too deeply (more than \(Query.maxDepth) levels of ( ) and NOT)")
            }
            if t == .not { return .not(try parseUnary()) }
            let n = try parseOr()
            guard next() == .rparen else { throw QueryError(message: "Missing )") }
            return n
        case .rparen: throw QueryError(message: "Unexpected )")
        case .and, .or, .nor: throw QueryError(message: "Unexpected \(t.describe)")
        case .phrase(let p): return .text(p)
        case .regex(let r): return .regex(r)
        case .word(let w): return try Self.term(w, regexWords: regexWords)
        }
    }

    /// `key:value`, `key:<=value`, `key>=value`, `key!=value` or a plain word.
    static func term(_ w: String, regexWords: Bool) throws -> QueryNode {
        // key>=value / key<=value / key!=value / key<value / key>value / key=value (no colon)
        for op in [QueryOp.ge, .le, .ne, .lt, .gt] {
            if let r = w.range(of: op.rawValue), r.lowerBound != w.startIndex, !w[..<r.lowerBound].contains(":") {
                let key = String(w[..<r.lowerBound]), value = String(w[r.upperBound...])
                if isKey(key), !value.isEmpty { return .field(key: key.lowercased(), op: op, value: value) }
            }
        }
        if let c = w.firstIndex(of: ":"), c != w.startIndex {
            let key = String(w[..<c])
            var value = String(w[w.index(after: c)...])
            if isKey(key), !value.isEmpty {
                var op = QueryOp.eq
                for candidate in [QueryOp.ge, .le, .ne, .lt, .gt, .eq] where value.hasPrefix(candidate.rawValue) {
                    op = candidate
                    value = String(value.dropFirst(candidate.rawValue.count))
                    break
                }
                guard !value.isEmpty else { throw QueryError(message: "\(key): needs a value") }
                return .field(key: key.lowercased(), op: op, value: value)
            }
        }
        if regexWords {
            guard QueryMatch.regex(w) != nil else {
                throw QueryError(message: "Invalid regular expression: \(w)")
            }
            return .regex(w)
        }
        return .text(w)
    }

    private static func isKey(_ s: String) -> Bool {
        !s.isEmpty && s.allSatisfy { $0.isLetter || $0.isNumber || $0 == "_" || $0 == "." || $0 == "-" }
            && s.first!.isLetter
    }
}
