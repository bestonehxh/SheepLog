import Foundation

/// Vendor detection by message shape, and per-vendor field extraction. See the design notes in
/// CLAUDE.md for each format. Implemented by the Syslog work package.
///
/// Everything here scans the message's UTF-8 bytes directly (memmem / manual loops) — no
/// regular expressions — since `detect` runs for every received line.
nonisolated enum VendorParsers {
    /// Decide the vendor from the header pieces and the message body.
    static func detect(hostname: String, program: String, message: String) -> Vendor {
        var m = message
        return m.withUTF8 { detectBytes(VPBytes($0)) }
    }

    /// Extract ordered fields for a known vendor. May also return a better `program` and a
    /// vendor-authoritative severity (Huawei's digit, Forti's level=, Palo's severity column).
    static func fields(for vendor: Vendor, hostname: String, program: String, message: String)
        -> (fields: [LogField], program: String?, severity: Severity?) {
        var m = message
        return m.withUTF8 { buf -> ([LogField], String?, Severity?) in
            let b = VPBytes(buf)
            switch vendor {
            case .arubaCX: return arubaCX(b)
            case .arubaOS: return arubaOS(b)
            case .arubaSwitch: return arubaSwitch(b)
            case .clearPass: return clearPass(b)
            case .huawei: return huawei(b)
            case .checkPoint: return checkPoint(b)
            case .paloAlto: return paloAlto(b)
            case .fortigate: return fortigate(b)
            case .snmpTrap: return ([], nil, nil)
            case .unknown:
                let kv = keyValues(b, from: 0, stripTrailingPunctuation: true)
                return (kv.count >= 3 ? kv : [], nil, nil)
            }
        }
    }

    // MARK: - Detection

    static func detectBytes(_ b: VPBytes) -> Vendor {
        let i = b.skipSpaces(0)
        guard b.n - i >= 4 else { return .unknown }
        if b.hasPrefix("Event|", at: i) { return .arubaCX }
        if b[i] == VPByte.one, b[i + 1] == VPByte.comma, paloType(b, from: i) != nil { return .paloAlto }
        if b[i] == VPByte.lt, aos8Header(b, from: i) != nil { return .arubaOS }
        if b.contains("logid="), b.contains("type="), b.contains("devid=") || b.contains("devname=") {
            return .fortigate
        }
        if huaweiHeader(b) != nil { return .huawei }
        if let lb = checkPointBracket(b, from: i), b.find("\";", from: lb) != nil || b.find("\"]", from: lb) != nil {
            return .checkPoint
        }
        if b.hasPrefix("CPPM_", at: i) || clearPassStart(b) != nil { return .clearPass }
        if checkPointKeyValueRun(b, from: i) { return .checkPoint }
        if aossHeader(b, from: i) != nil { return .arubaSwitch }
        return .unknown
    }

    /// Check Point's `key=value; key=value; …` form: the body starts with a `key=` whose value
    /// ends at a `;`, has at least two `;`, and names `product=` (every Check Point record
    /// does) — so a web app's `user=…; action=login;` is not taken for Check Point.
    static func checkPointKeyValueRun(_ b: VPBytes, from i: Int) -> Bool {
        var q = i
        while q < b.n, VPByte.isKeyChar(b[q]) { q += 1 }
        guard q > i, VPByte.isAlpha(b[i]), b.at(q) == VPByte.eq else { return false }
        // The first value runs to a `;` before the next space-separated `key=` would start.
        var r = q + 1
        if b.at(r) == VPByte.quote, let close = b.find("\"", from: r + 1) { r = close + 1 }
        while r < b.n, b[r] != VPByte.semicolon, b[r] != VPByte.eq { r += 1 }
        guard b.at(r) == VPByte.semicolon else { return false }
        return b.hasAtLeast(2, of: VPByte.semicolon) && b.contains("product=")
    }

    // MARK: - Aruba AOS-CX: Event|1302|LOG_WARN|AMM|1/1|text

    static func arubaCX(_ b: VPBytes) -> ([LogField], String?, Severity?) {
        let i = b.skipSpaces(0)
        guard b.hasPrefix("Event|", at: i) else { return ([], nil, nil) }
        var parts: [String] = []
        var p = i + 6
        while parts.count < 4 {
            guard let bar = b.find("|", from: p) else { break }
            parts.append(b.str(p, bar))
            p = bar + 1
        }
        var out: [LogField] = []
        let names = ["event_id", "log_type", "module", "slot"]
        for (k, v) in zip(names, parts) where !v.isEmpty { out.append(LogField(k, v)) }
        var sev: Severity?
        if parts.count > 1 { sev = Self.arubaCXSeverity(parts[1]) }
        return (out, nil, sev)
    }

    static func arubaCXSeverity(_ s: String) -> Severity? {
        var t = s.uppercased()
        if t.hasPrefix("LOG_") { t.removeFirst(4) }
        switch t {
        case "EMER", "EMERG", "EMERGENCY": return .emergency
        case "ALERT", "ALRT": return .alert
        case "CRIT", "CRITICAL": return .critical
        case "ERR", "ERROR": return .error
        case "WARN", "WARNING": return .warning
        case "NOTICE", "NOTI": return .notice
        case "INFO": return .info
        case "DEBUG", "DBG": return .debug
        default: return Severity.parse(t)
        }
    }

    // MARK: - Aruba AOS 8 / IAP: <522008> [<4211>] <NOTI> [<MM-1 10.1.1.10> | |AP x@ip cli|] text

    struct AOS8Header { var code: String; var level: String; var device: String?; var end: Int }

    static func aos8Header(_ b: VPBytes, from start: Int) -> AOS8Header? {
        var p = start
        guard b.at(p) == VPByte.lt else { return nil }
        var q = p + 1
        while q < b.n, VPByte.isDigit(b[q]) { q += 1 }
        guard q - p - 1 == 6, b.at(q) == VPByte.gt else { return nil }
        let code = b.str(p + 1, q)
        p = b.skipSpaces(q + 1)
        // optional <pid>
        if b.at(p) == VPByte.lt {
            var r = p + 1
            while r < b.n, VPByte.isDigit(b[r]) { r += 1 }
            if r > p + 1, b.at(r) == VPByte.gt { p = b.skipSpaces(r + 1) }
        }
        guard b.at(p) == VPByte.lt, let close = b.find(">", from: p + 1), close - p - 1 <= 5 else { return nil }
        let level = b.str(p + 1, close)
        guard aos8Severity(level) != nil else { return nil }
        p = b.skipSpaces(close + 1)
        var device: String?
        if b.at(p) == VPByte.lt, let c = b.find(">", from: p + 1) {
            device = b.str(p + 1, c); p = b.skipSpaces(c + 1)
        } else if b.at(p) == VPByte.bar, let c = b.find("|", from: p + 1) {
            device = b.str(p + 1, c); p = b.skipSpaces(c + 1)
        }
        return AOS8Header(code: code, level: level, device: device, end: p)
    }

    static func aos8Severity(_ s: String) -> Severity? {
        switch s.uppercased() {
        case "EMRG", "EMERG": return .emergency
        case "ALRT", "ALERT": return .alert
        case "CRIT": return .critical
        case "ERRS", "ERR", "ERROR": return .error
        case "WARN": return .warning
        case "NOTI", "NOTICE": return .notice
        case "INFO": return .info
        case "DBUG", "DEBUG": return .debug
        default: return nil
        }
    }

    static func arubaOS(_ b: VPBytes) -> ([LogField], String?, Severity?) {
        guard let h = aos8Header(b, from: b.skipSpaces(0)) else { return ([], nil, nil) }
        var out = [LogField("code", h.code), LogField("level", h.level)]
        if let d = h.device, !d.isEmpty { out.append(LogField("device", d)) }
        // The body's `username=alice MAC=… role=… SSID=…` pairs (authmgr, stm), filterable as
        // `f:username=alice` like the same pairs on any other line.
        out.append(contentsOf: keyValues(b, from: h.end, stripTrailingPunctuation: true))
        return (out, nil, aos8Severity(h.level))
    }

    // MARK: - Aruba AOS-S / ProCurve: 00076 ports: port 24 is now off-line

    static func aossHeader(_ b: VPBytes, from start: Int) -> (event: String, module: String, end: Int)? {
        guard b.n - start > 8 else { return nil }
        for k in start..<(start + 5) where !VPByte.isDigit(b[k]) { return nil }
        guard b[start + 5] == VPByte.space else { return nil }
        var q = start + 6
        let ms = q
        // Module names: ports, FFI, mgr, dhcp-snoop, 802.1x, …
        while q < b.n, VPByte.isAlnum(b[q]) || b[q] == VPByte.dash || b[q] == VPByte.underscore || b[q] == VPByte.dot { q += 1 }
        guard q > ms, VPByte.isAlnum(b[ms]), b.at(q) == VPByte.colon else { return nil }
        return (b.str(start, start + 5), b.str(ms, q), q + 1)
    }

    static func arubaSwitch(_ b: VPBytes) -> ([LogField], String?, Severity?) {
        guard let h = aossHeader(b, from: b.skipSpaces(0)) else { return ([], nil, nil) }
        return ([LogField("event_id", h.event), LogField("module", h.module)], h.module, nil)
    }

    // MARK: - ClearPass: … Common.Username=alice,Common.Service=Corp,Common.Login-Status=REJECT,…

    private static let clearPassPrefixes = ["Common.", "RADIUS.", "Auth.", "TACACS.", "Endpoint.", "Session."]

    /// Where the first `Prefix.Key=` pair starts.
    static func clearPassStart(_ b: VPBytes) -> Int? {
        var best: Int?
        for prefix in clearPassPrefixes {
            var from = 0
            while let at = b.find(prefix, from: from) {
                from = at + 1
                if let best, at >= best { break }
                if at > 0 {
                    let prev = b[at - 1]
                    guard prev == VPByte.comma || prev == VPByte.space else { continue }
                }
                var q = at + prefix.utf8.count
                let ks = q
                while q < b.n, VPByte.isKeyChar(b[q]) { q += 1 }
                if q > ks, b.at(q) == VPByte.eq { best = at; break }
            }
        }
        return best
    }

    /// A ClearPass key at `k`: a letter, then letters/digits/`.`/`-`/`_` and single spaces
    /// (system events and audit records use "Action Key=", "Event Source="), then `=`. Returns
    /// the index of the `=`.
    private static func clearPassKeyEnd(_ b: VPBytes, _ k: Int) -> Int? {
        guard VPByte.isAlpha(b.at(k)) else { return nil }
        var q = k
        while q < b.n, q - k < 48 {
            let c = b[q]
            if VPByte.isKeyChar(c) { q += 1; continue }
            if c == VPByte.space, b[q - 1] != VPByte.space, VPByte.isAlpha(b.at(q + 1)) { q += 1; continue }
            break
        }
        return b.at(q) == VPByte.eq ? q : nil
    }

    static func clearPass(_ b: VPBytes) -> ([LogField], String?, Severity?) {
        var out: [LogField] = []
        var program: String?
        var start: Int?
        // Syslog export header: "CPPM_<Category> <id> <seq> <total> key=value,…"
        let i = b.skipSpaces(0)
        if b.hasPrefix("CPPM_", at: i) {
            var q = i
            while q < b.n, b[q] != VPByte.space { q += 1 }
            program = b.str(i, q)
            q = b.skipSpaces(q)
            for _ in 0..<3 {
                var r = q
                while r < b.n, VPByte.isDigit(b[r]) { r += 1 }
                guard r > q, b.at(r) == VPByte.space else { break }
                q = b.skipSpaces(r)
            }
            if clearPassKeyEnd(b, q) != nil { start = q }
        }
        if start == nil { start = clearPassStart(b) }
        guard var pos = start else { return ([], program, nil) }
        while pos < b.n {
            guard let eq = clearPassKeyEnd(b, pos) else { break }
            let key = b.str(pos, eq)
            let vs = eq + 1
            // The value runs to the next ", Key=" (commas inside values stay).
            var end = b.n
            var j = vs
            while j < b.n {
                if b[j] == VPByte.comma, clearPassKeyEnd(b, b.skipSpaces(j + 1)) != nil { end = j; break }
                j += 1
            }
            out.append(LogField(key, b.str(vs, end).trimmingCharacters(in: .whitespaces)))
            pos = b.skipSpaces(end + 1)
        }
        var sev: Severity?
        for f in out {
            let k = f.key.lowercased()
            if k.hasSuffix(".login-status") || k.hasSuffix(".auth-status") {
                switch f.value.uppercased() {
                case "REJECT", "FAILED", "FAIL": sev = .error
                case "TIMEOUT": sev = .warning
                case "ACCEPT", "SUCCESS": sev = .info
                default: break
                }
            } else if k == "level" {
                sev = Severity.parse(f.value) ?? sev
            }
            if sev != nil { break }
        }
        return (out, program, sev)
    }

    // MARK: - Huawei VRP: %%01IFNET/4/LINK_STATE(l)[12]:text

    struct HuaweiHeader { var module: String; var severity: Int; var mnemonic: String; var kind: String?; var seq: String?; var end: Int }

    static func huaweiHeader(_ b: VPBytes) -> HuaweiHeader? {
        var from = 0
        while let pct = b.find("%%", from: from), pct < 256 {
            from = pct + 1
            var q = pct + 2
            guard VPByte.isDigit(b.at(q)), VPByte.isDigit(b.at(q + 1)) else { continue }
            q += 2
            let ms = q
            while q < b.n, VPByte.isAlnum(b[q]) || b[q] == VPByte.underscore || b[q] == VPByte.dash { q += 1 }
            guard q > ms, b.at(q) == VPByte.slash else { continue }
            let module = b.str(ms, q)
            q += 1
            let ss = q
            while q < b.n, VPByte.isDigit(b[q]) { q += 1 }
            guard q > ss, q - ss <= 2, b.at(q) == VPByte.slash else { continue }
            let sev = Int(b.str(ss, q)) ?? 5
            q += 1
            let ns = q
            while q < b.n, VPByte.isAlnum(b[q]) || b[q] == VPByte.underscore || b[q] == VPByte.dash || b[q] == VPByte.dot { q += 1 }
            guard q > ns else { continue }
            let name = b.str(ns, q)
            var kind: String?
            if b.at(q) == VPByte.lparen, let c = b.find(")", from: q + 1), c - q <= 4 {
                kind = b.str(q + 1, c); q = c + 1
            }
            var seq: String?
            if b.at(q) == VPByte.lbracket, let c = b.find("]", from: q + 1), c - q <= 12 {
                seq = b.str(q + 1, c); q = c + 1
            }
            guard b.at(q) == VPByte.colon else { continue }
            return HuaweiHeader(module: module, severity: sev, mnemonic: name, kind: kind, seq: seq, end: q + 1)
        }
        return nil
    }

    static func huawei(_ b: VPBytes) -> ([LogField], String?, Severity?) {
        guard let h = huaweiHeader(b) else { return ([], nil, nil) }
        var out = [LogField("module", h.module), LogField("severity", String(h.severity)),
                   LogField("mnemonic", h.mnemonic)]
        if let k = h.kind { out.append(LogField("type", k)) }
        if let s = h.seq { out.append(LogField("seq", s)) }
        out.append(contentsOf: huaweiParameters(b, from: h.end))
        return (out, "\(h.module)/\(h.severity)/\(h.mnemonic)", Severity(rawValue: h.severity))
    }

    /// The `(Key=value, Key="value", …)` list most VRP messages end with — `ifName`,
    /// `NeighborAddress`, `UserName`, `Command` become filterable fields (`f:ifName=10GE1/0/24`).
    static func huaweiParameters(_ b: VPBytes, from start: Int) -> [LogField] {
        // The list closes the message (a trailing "." or spaces may follow).
        var close = b.n - 1
        while close > start, b[close] == VPByte.space || b[close] == VPByte.dot { close -= 1 }
        guard close > start, b[close] == 0x29 else { return [] }
        // Its "(" is the first one after which a `Key=` starts.
        var from = start
        var open: Int?
        while let lp = b.find("(", from: from), lp < close {
            var q = lp + 1
            let ks = q
            while q < close, VPByte.isKeyChar(b[q]) { q += 1 }
            if q > ks, VPByte.isAlpha(b[ks]), b.at(q) == VPByte.eq { open = lp; break }
            from = lp + 1
        }
        guard let open else { return [] }
        var out: [LogField] = []
        var pos = open + 1
        while pos < close {
            let ks = pos
            while pos < close, VPByte.isKeyChar(b[pos]) { pos += 1 }
            guard pos > ks, b.at(pos) == VPByte.eq else { break }
            let key = b.str(ks, pos)
            pos += 1
            var value: String
            if b.at(pos) == VPByte.quote, let q = b.find("\"", from: pos + 1), q < close {
                value = b.str(pos + 1, q)
                pos = q + 1
                while pos < close, b[pos] != VPByte.comma { pos += 1 }
            } else {
                // To the next ", Key=" (a value may itself contain ", ").
                let vs = pos
                var e = close
                var j = pos
                while j < close {
                    if b[j] == VPByte.comma {
                        let k = b.skipSpaces(j + 1)
                        var kk = k
                        while kk < close, VPByte.isKeyChar(b[kk]) { kk += 1 }
                        if kk > k, b.at(kk) == VPByte.eq { e = j; break }
                    }
                    j += 1
                }
                value = b.str(vs, e).trimmingCharacters(in: .whitespaces)
                pos = e
            }
            out.append(LogField(key, value))
            pos = b.skipSpaces(pos + 1)
        }
        return out
    }

    // MARK: - Check Point: [k:"v"; k:"v"] (log_exporter) or k=v; runs

    private static func checkPointBracketLooksRight(_ b: VPBytes, _ lb: Int) -> Bool {
        // `[word:"`
        var q = lb + 1
        let ks = q
        while q < b.n, VPByte.isKeyChar(b[q]) { q += 1 }
        return q > ks && b.at(q) == VPByte.colon && b.at(q + 1) == VPByte.quote
    }

    /// The first `[word:"` in the text (an earlier `[0]` or `[pid]` is skipped). Looks at the
    /// first few brackets only, so a long line without one stays cheap.
    static func checkPointBracket(_ b: VPBytes, from start: Int = 0) -> Int? {
        var from = start
        var tries = 0
        while tries < 8, let lb = b.find("[", from: from) {
            if checkPointBracketLooksRight(b, lb) { return lb }
            from = lb + 1
            tries += 1
        }
        return nil
    }

    static func checkPoint(_ b: VPBytes) -> ([LogField], String?, Severity?) {
        var out: [LogField] = []
        if let lb = checkPointBracket(b) {
            var q = lb + 1
            while q < b.n {
                while q < b.n, b[q] == VPByte.space || b[q] == VPByte.semicolon { q += 1 }
                if b.at(q) == VPByte.rbracket || q >= b.n { break }
                let ks = q
                while q < b.n, b[q] != VPByte.colon, b[q] != VPByte.rbracket { q += 1 }
                guard b.at(q) == VPByte.colon else { break }
                let key = b.str(ks, q).trimmingCharacters(in: .whitespaces)
                q += 1
                var value: [UInt8] = []
                if b.at(q) == VPByte.quote {
                    q += 1
                    while q < b.n {
                        let c = b[q]
                        if c == VPByte.backslash, q + 1 < b.n { value.append(b[q + 1]); q += 2; continue }
                        if c == VPByte.quote { q += 1; break }
                        value.append(c); q += 1
                    }
                } else {
                    // Unquoted: runs to `;` or the closing `]`, but a nested `[…]` is kept whole.
                    var depth = 0
                    while q < b.n {
                        let c = b[q]
                        if c == VPByte.lbracket { depth += 1 }
                        else if c == VPByte.rbracket { if depth == 0 { break }; depth -= 1 }
                        else if c == VPByte.semicolon, depth == 0 { break }
                        value.append(c); q += 1
                    }
                }
                if !key.isEmpty { out.append(LogField(key, String(decoding: value, as: UTF8.self))) }
            }
        } else {
            // key=value; key="value"; …
            var q = 0
            while q < b.n {
                while q < b.n, b[q] == VPByte.space || b[q] == VPByte.semicolon { q += 1 }
                let ks = q
                while q < b.n, VPByte.isKeyChar(b[q]) { q += 1 }
                let keyEnd = q
                guard keyEnd > ks, b.at(q) == VPByte.eq else {
                    while q < b.n, b[q] != VPByte.semicolon { q += 1 }
                    continue
                }
                q += 1
                var value: String
                if b.at(q) == VPByte.quote, let close = b.find("\"", from: q + 1) {
                    value = b.str(q + 1, close)
                    q = close + 1
                    while q < b.n, b[q] != VPByte.semicolon { q += 1 }
                } else {
                    let vs = q
                    while q < b.n, b[q] != VPByte.semicolon { q += 1 }
                    value = b.str(vs, q).trimmingCharacters(in: .whitespaces)
                }
                out.append(LogField(b.str(ks, keyEnd), value))
            }
        }
        var sev: Severity?
        if let s = out.first(where: { $0.key == "severity" || $0.key == "level" })?.value {
            sev = checkPointSeverity(s)
        }
        let program = out.first(where: { $0.key == "product" })?.value
        return (out, program, sev)
    }

    /// Check Point words (Critical/High/Medium/Low/Informational) and its 0–4 scale.
    static func checkPointSeverity(_ s: String) -> Severity? {
        switch s.lowercased().trimmingCharacters(in: .whitespaces) {
        case "critical", "4": return .critical
        case "high", "3": return .error
        case "medium", "2": return .warning
        case "low", "informational", "info", "1", "0": return .info
        default: return Severity.parse(s)
        }
    }

    // MARK: - Palo Alto CSV

    private static let paloTypes: Set<String> = [
        "TRAFFIC", "THREAT", "SYSTEM", "CONFIG", "USERID", "HIPMATCH", "GLOBALPROTECT", "DECRYPTION", "AUTH",
    ]

    /// Column 3 (0-based) of a `1,…` line when it is one of the known log types.
    static func paloType(_ b: VPBytes, from start: Int) -> String? {
        var commas = 0
        var q = start
        var colStart = start
        while q < b.n, q - start < 200 {
            if b[q] == VPByte.comma {
                commas += 1
                if commas == 3 { colStart = q + 1 }
                if commas == 4 {
                    let t = b.str(colStart, q)
                    return paloTypes.contains(t) ? t : nil
                }
            }
            q += 1
        }
        return nil
    }

    /// RFC 4180-ish: quoted fields may contain commas and doubled quotes.
    static func csv(_ b: VPBytes, from start: Int) -> [String] {
        var out: [String] = []
        out.reserveCapacity(64)
        var q = start
        while q <= b.n {
            if b.at(q) == VPByte.quote {
                var value: [UInt8] = []
                q += 1
                while q < b.n {
                    if b[q] == VPByte.quote {
                        if b.at(q + 1) == VPByte.quote { value.append(VPByte.quote); q += 2; continue }
                        q += 1
                        break
                    }
                    value.append(b[q]); q += 1
                }
                out.append(String(decoding: value, as: UTF8.self))
                while q < b.n, b[q] != VPByte.comma { q += 1 }
                q += 1
            } else {
                let s = q
                while q < b.n, b[q] != VPByte.comma { q += 1 }
                out.append(b.str(s, q))
                q += 1
            }
            if q > b.n { break }
        }
        return out
    }

    /// Column names as PAN-OS documents them ("Syslog Field Descriptions": the variable names a
    /// custom log format uses — `from`/`to` for the zones, `inbound_if`, `sessionid`,
    /// `session_end_reason`, …), so a field name copied from Palo Alto's docs filters.
    private static let paloTraffic: [(Int, String)] = [
        (7, "src"), (8, "dst"), (9, "natsrc"), (10, "natdst"), (11, "rule"), (12, "srcuser"),
        (13, "dstuser"), (14, "app"), (15, "vsys"), (16, "from"), (17, "to"), (18, "inbound_if"),
        (19, "outbound_if"), (20, "logset"), (22, "sessionid"), (23, "repeatcnt"), (24, "sport"),
        (25, "dport"), (26, "natsport"), (27, "natdport"), (28, "flags"), (29, "proto"),
        (30, "action"), (31, "bytes"), (32, "bytes_sent"), (33, "bytes_received"), (34, "packets"),
        (35, "start"), (36, "elapsed"), (37, "category"), (39, "seqno"), (40, "actionflags"),
        (41, "srcloc"), (42, "dstloc"), (44, "pkts_sent"), (45, "pkts_received"), (46, "session_end_reason"),
    ]
    private static let paloThreat: [(Int, String)] = Array(paloTraffic.prefix(22)) + [
        (30, "action"), (31, "misc"), (32, "threatid"), (33, "category"), (34, "severity"), (35, "direction"),
        (36, "seqno"), (37, "actionflags"), (38, "srcloc"), (39, "dstloc"), (41, "contenttype"),
        (42, "pcap_id"), (43, "filedigest"), (44, "cloud"), (45, "url_idx"), (46, "user_agent"),
        (47, "filetype"), (48, "xff"), (49, "referer"),
    ]
    private static let paloSystem: [(Int, String)] = [
        (7, "vsys"), (8, "eventid"), (9, "object"), (12, "module"), (13, "severity"), (14, "description"),
    ]
    private static let paloConfig: [(Int, String)] = [
        (7, "host"), (8, "vsys"), (9, "cmd"), (10, "admin"), (11, "client"), (12, "result"), (13, "path"),
    ]
    /// DECRYPTION shares TRAFFIC's first 31 columns; column 31 is the tunnel ID, not bytes.
    private static let paloDecryption: [(Int, String)] = paloTraffic.filter { $0.0 <= 30 }
    private static let paloUserID: [(Int, String)] = [
        (7, "vsys"), (8, "src"), (9, "user"), (10, "datasourcename"), (11, "eventid"), (12, "repeatcnt"),
        (13, "timeout"), (14, "sport"), (15, "dport"), (16, "datasource"), (17, "datasourcetype"),
    ]
    private static let paloGlobalProtect: [(Int, String)] = [
        (7, "vsys"), (8, "eventid"), (9, "stage"), (10, "authmethod"), (11, "tunneltype"), (12, "srcuser"),
        (13, "srcregion"), (14, "machinename"), (15, "public_ip"), (17, "private_ip"), (19, "hostid"),
        (21, "client_ver"), (22, "client_os"), (23, "client_os_ver"), (25, "reason"), (26, "error"),
        (27, "description"), (28, "status"), (29, "location"), (31, "connect_method"), (32, "error_code"),
        (33, "portal"), (41, "gateway"),
    ]

    static func paloAlto(_ b: VPBytes) -> ([LogField], String?, Severity?) {
        let cols = csv(b, from: b.skipSpaces(0))
        guard cols.count > 4 else { return ([], nil, nil) }
        let type = cols[3], subtype = cols[4]
        var out = [LogField("type", type), LogField("subtype", subtype)]
        if !cols[2].isEmpty { out.append(LogField("serial", cols[2])) }
        let map: [(Int, String)]
        switch type {
        case "TRAFFIC": map = paloTraffic
        case "DECRYPTION": map = paloDecryption
        case "THREAT": map = paloThreat
        case "SYSTEM": map = paloSystem
        case "CONFIG": map = paloConfig
        case "USERID": map = paloUserID
        case "GLOBALPROTECT": map = paloGlobalProtect
        default: map = []
        }
        if map.isEmpty {
            for i in 5..<cols.count where !cols[i].isEmpty { out.append(LogField("col\(i)", cols[i])) }
        } else {
            for (i, name) in map where i < cols.count && !cols[i].isEmpty {
                out.append(LogField(name, cols[i]))
            }
        }
        var sev: Severity?
        if type == "THREAT", cols.count > 34 { sev = paloSeverity(cols[34]) }
        if type == "SYSTEM", cols.count > 13 { sev = paloSeverity(cols[13]) }
        // GLOBALPROTECT / DECRYPTION / CONFIG rows carry "0" as the subtype; GlobalProtect's
        // event ID ("gateway-connected", "portal-auth") says what happened instead.
        var program = type
        if type == "GLOBALPROTECT", cols.count > 8, !cols[8].isEmpty { program += "/\(cols[8])" }
        else if !subtype.isEmpty, subtype != "0" { program += "/\(subtype)" }
        return (out, program, sev)
    }

    static func paloSeverity(_ s: String) -> Severity? {
        switch s.lowercased() {
        case "critical", "high": return .error
        case "medium": return .warning
        case "low", "informational": return .info
        default: return nil
        }
    }

    // MARK: - Fortigate: date=… devname="FGT" … type="traffic" subtype="forward" level="notice"

    static func fortigate(_ b: VPBytes) -> ([LogField], String?, Severity?) {
        // `config log syslogd setting / set format csv`: the same pairs, comma-separated
        // (`date=2026-09-23,time=10:15:32,devname="FGT60F",…`).
        let csv = b.find("logid=").map { $0 > 0 && b[$0 - 1] == VPByte.comma } ?? false
        let out = keyValues(b, from: 0, stripTrailingPunctuation: false, separator: csv ? VPByte.comma : VPByte.space)
        var type: String?, subtype: String?, level: String?
        for f in out {
            switch f.key {
            case "type": type = f.value
            case "subtype": subtype = f.value
            case "level": level = f.value
            default: break
            }
        }
        var program: String?
        if let type { program = subtype.map { "\(type)/\($0)" } ?? type }
        return (out, program, level.flatMap { Severity.parse($0) })
    }

    /// The device's own clock from a vendor's fields, for a line whose header had no timestamp:
    /// FortiOS `eventtime=` (epoch s/ms/µs/ns by length) or `date=` + `time=` + `tz=`;
    /// Check Point `time:` (epoch seconds).
    static func deviceTime(for vendor: Vendor, fields: [LogField]) -> Date? {
        switch vendor {
        case .fortigate:
            var date: String?, time: String?, tz: String?, event: String?
            for f in fields {
                switch f.key {
                case "date": date = f.value
                case "time": time = f.value
                case "tz": tz = f.value
                case "eventtime": event = f.value
                default: break
                }
            }
            if let event, let d = epochDate(event) { return d }
            guard let date, let time else { return nil }
            return SyslogParser.parseHeader("\(date)T\(time)\(tz ?? "")", now: Date()).time
        case .checkPoint:
            return fields.first(where: { $0.key == "time" }).flatMap { epochDate($0.value) }
        default:
            return nil
        }
    }

    /// Epoch seconds / ms / µs / ns (decided by the digit count), 2000…2199 only.
    static func epochDate(_ s: String) -> Date? {
        let u = s.utf8
        guard (9...20).contains(u.count), u.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }), let v = Double(s) else { return nil }
        let secs = u.count >= 18 ? v / 1e9 : u.count >= 15 ? v / 1e6 : u.count >= 12 ? v / 1e3 : v
        guard secs >= 946_684_800, secs < 7_258_118_400 else { return nil }
        return Date(timeIntervalSince1970: secs)
    }

    /// `key=value key="quoted value" …` pairs anywhere in the text (`separator` a comma for
    /// FortiOS's CSV format: `key=value,key="quoted value",…`).
    static func keyValues(_ b: VPBytes, from start: Int, stripTrailingPunctuation: Bool,
                          separator: UInt8 = VPByte.space) -> [LogField] {
        var out: [LogField] = []
        var q = start
        while q < b.n {
            q = b.skipSpaces(q)
            while separator != VPByte.space, q < b.n, b[q] == separator { q = b.skipSpaces(q + 1) }
            let ks = q
            while q < b.n, VPByte.isKeyChar(b[q]) { q += 1 }
            guard q > ks, b.at(q) == VPByte.eq, VPByte.isAlpha(b[ks]) else {
                if q == ks { q += 1 }
                while q < b.n, b[q] != separator, b[q] != VPByte.space { q += 1 }
                continue
            }
            let key = b.str(ks, q)
            q += 1
            if b.at(q) == VPByte.quote {
                let vs = q + 1
                var e = vs
                while e < b.n, b[e] != VPByte.quote { e += (b[e] == VPByte.backslash ? 2 : 1) }
                e = min(e, b.n)
                out.append(LogField(key, b.str(vs, e)))
                q = e + 1
            } else {
                let vs = q
                while q < b.n, b[q] != separator, separator == VPByte.space || b[q] != VPByte.space { q += 1 }
                var e = q
                if stripTrailingPunctuation {
                    while e > vs, b[e - 1] == VPByte.comma || b[e - 1] == VPByte.semicolon { e -= 1 }
                }
                out.append(LogField(key, b.str(vs, e)))
            }
        }
        return out
    }
}

// MARK: - Byte helpers

/// ASCII constants and classes.
nonisolated enum VPByte {
    static let space: UInt8 = 0x20, comma: UInt8 = 0x2C, semicolon: UInt8 = 0x3B, colon: UInt8 = 0x3A
    static let eq: UInt8 = 0x3D, quote: UInt8 = 0x22, lt: UInt8 = 0x3C, gt: UInt8 = 0x3E
    static let bar: UInt8 = 0x7C, dash: UInt8 = 0x2D, underscore: UInt8 = 0x5F, dot: UInt8 = 0x2E
    static let slash: UInt8 = 0x2F, backslash: UInt8 = 0x5C, lparen: UInt8 = 0x28
    static let lbracket: UInt8 = 0x5B, rbracket: UInt8 = 0x5D, one: UInt8 = 0x31

    @inline(__always) static func isDigit(_ c: UInt8) -> Bool { c >= 0x30 && c <= 0x39 }
    @inline(__always) static func isAlpha(_ c: UInt8) -> Bool { (c | 0x20) >= 0x61 && (c | 0x20) <= 0x7A }
    @inline(__always) static func isAlnum(_ c: UInt8) -> Bool { isDigit(c) || isAlpha(c) }
    @inline(__always) static func isKeyChar(_ c: UInt8) -> Bool {
        isAlnum(c) || c == underscore || c == dot || c == dash
    }
}

/// A read-only view of a string's UTF-8 bytes, valid inside `withUTF8`.
nonisolated struct VPBytes {
    let p: UnsafeBufferPointer<UInt8>
    let n: Int

    init(_ p: UnsafeBufferPointer<UInt8>) { self.p = p; n = p.count }

    @inline(__always) subscript(_ i: Int) -> UInt8 { p[i] }
    @inline(__always) func at(_ i: Int) -> UInt8 { i < n ? p[i] : 0 }

    func str(_ a: Int, _ e: Int) -> String {
        guard a < e, e <= n else { return "" }
        return String(decoding: UnsafeBufferPointer(rebasing: p[a..<e]), as: UTF8.self)
    }

    func skipSpaces(_ i: Int) -> Int {
        var q = i
        while q < n, p[q] == VPByte.space || p[q] == 0x09 { q += 1 }
        return q
    }

    func hasPrefix(_ s: StaticString, at i: Int) -> Bool {
        let m = s.utf8CodeUnitCount
        guard i + m <= n, let base = p.baseAddress else { return false }
        return memcmp(base + i, s.utf8Start, m) == 0
    }

    func find(_ needle: String, from start: Int = 0) -> Int? {
        guard start < n, let base = p.baseAddress else { return nil }
        var needle = needle
        return needle.withUTF8 { nb -> Int? in
            guard let nbase = nb.baseAddress, nb.count > 0,
                  let hit = memmem(base + start, n - start, nbase, nb.count) else { return nil }
            return base.distance(to: hit.assumingMemoryBound(to: UInt8.self))
        }
    }

    func contains(_ needle: String) -> Bool { find(needle) != nil }

    /// At least `k` occurrences of `c` — memchr hops, stops at the k-th (the detector only needs
    /// "≥ 2 semicolons", and counting every byte of every `action=` line would dominate it).
    func hasAtLeast(_ k: Int, of c: UInt8) -> Bool {
        guard let base = p.baseAddress else { return k <= 0 }
        var found = 0, i = 0
        while found < k, i < n, let hit = memchr(base + i, Int32(c), n - i) {
            found += 1
            i = base.distance(to: hit.assumingMemoryBound(to: UInt8.self)) + 1
        }
        return found >= k
    }
}
