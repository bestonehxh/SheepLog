import Foundation

/// One raw datagram / framed line, before parsing.
nonisolated struct RawSyslog: Sendable {
    let received: Date
    let sourceAddress: String
    let sourcePort: UInt16
    let transport: Transport
    let text: String
}

/// Pure functions: raw text → LogEntry. Header parsing (PRI, RFC 3164 / 5424), then vendor
/// detection + field extraction (VendorParsers.swift).
///
/// The header is scanned by hand over the string's UTF-8 bytes (no regular expressions, one
/// pass, no intermediate arrays) because this runs for every received line on the listener
/// queue — tens of thousands of times a second in a burst.
nonisolated enum SyslogParser {
    /// `vendorOverride` forces the vendor for this source (from the Sources pane).
    static func parse(_ raw: RawSyslog, id: Int, vendorOverride: Vendor? = nil) -> LogEntry {
        let h = parseHeader(raw.text, now: raw.received)
        let facility: Facility
        let priSeverity: Severity
        if let pri = h.pri {
            facility = Facility(rawValue: pri >> 3) ?? .user
            priSeverity = Severity(rawValue: pri & 7) ?? .notice
        } else {
            facility = .user
            priSeverity = .notice
        }
        // Everything below is shown (and the message searched); `raw` stays the bytes as sent.
        // Control characters a sender embeds (ESC sequences, NUL, BEL, backspaces) are
        // neutralised in what is displayed; an absurd hostname or tag is cut short.
        let message = DisplayText.neutralize(h.message, keepLineBreaks: true)
        let vendor = vendorOverride
            ?? VendorParsers.detect(hostname: h.hostname, program: h.program, message: message)
        let v = VendorParsers.fields(for: vendor, hostname: h.hostname, program: h.program, message: message)
        var fields = h.fields
        for k in fields.indices where DisplayText.needsNeutralizing(fields[k].value, keepLineBreaks: false) {
            fields[k] = LogField(fields[k].key, DisplayText.neutralize(fields[k].value, keepLineBreaks: false))
        }
        if fields.isEmpty { fields = v.fields } else { fields.append(contentsOf: v.fields) }
        if fields.count > DisplayText.maxFields {
            let extra = fields.count - (DisplayText.maxFields - 1)       // the note is the 1,000th
            fields.removeLast(extra)
            fields.append(LogField("truncated_fields", "\(extra) more not kept"))
        }
        var hostname = h.hostname
        if hostname.isEmpty, vendor == .fortigate,
           let dev = v.fields.first(where: { $0.key == "devname" })?.value {
            hostname = dev
        }
        hostname = DisplayText.label(hostname, max: DisplayText.maxHostname)
        let program = DisplayText.label(v.program ?? h.program, max: DisplayText.maxProgram)
        // FortiOS (no header by default) and Check Point carry the device's own clock in fields.
        let deviceTime = h.time ?? VendorParsers.deviceTime(for: vendor, fields: v.fields)
        return LogEntry(id: id, received: raw.received, deviceTime: deviceTime,
                        sourceAddress: raw.sourceAddress, sourcePort: raw.sourcePort,
                        transport: raw.transport, facility: facility,
                        severity: v.severity ?? priSeverity, priority: h.pri,
                        hostname: hostname, program: program, pid: h.pid.map { DisplayText.label($0, max: 128) },
                        message: message, raw: raw.text, vendor: vendor, fields: fields)
    }

    /// What the header scan produced. `fields` holds RFC 5424 MSGID and structured data
    /// (`sd.<id>.<param>`).
    struct Header: Sendable {
        var pri: Int?
        var time: Date?
        var hostname = ""
        var program = ""
        var pid: String?
        var message = ""
        var fields: [LogField] = []
    }

    static func parseHeader(_ text: String, now: Date) -> Header {
        var copy = text
        return copy.withUTF8 { buf in
            var scan = HeaderScan(buf, now: now)
            return scan.run()
        }
    }
}

// MARK: - Display safety

/// What a sender controls ends up in table cells, the inspector, the clipboard and — through
/// "Copy" or the `.log` export — in a terminal. Control characters are neutralised in the
/// fields shown (never in `raw`, which stays the bytes as received):
/// - C0 controls except tab (and, in a message, line breaks), DEL and the C1 range
///   (U+0080–U+009F: U+009B is a one-byte CSI to many terminals) become U+FFFD;
/// - a hostname / tag / pid additionally loses bidi overrides and zero-width characters (a
///   hostname that renders as another name) and is cut to a sane length.
nonisolated enum DisplayText {
    static let maxHostname = 255
    static let maxProgram = 128
    /// Fields kept per line (a 64 KB line of `a=1 ` would otherwise make 16,000).
    static let maxFields = 1_000

    @inline(__always) private static func isC0(_ b: UInt8, keepLineBreaks: Bool) -> Bool {
        b < 0x20 && b != 0x09 && !(keepLineBreaks && (b == 0x0A || b == 0x0D))
    }

    /// True when `neutralize` would change `s` (a byte scan; no allocation).
    static func needsNeutralizing(_ s: String, keepLineBreaks: Bool) -> Bool {
        var prev: UInt8 = 0
        for b in s.utf8 {
            if isC0(b, keepLineBreaks: keepLineBreaks) || b == 0x7F { return true }
            if prev == 0xC2, b >= 0x80, b <= 0x9F { return true }
            prev = b
        }
        return false
    }

    static func neutralize(_ s: String, keepLineBreaks: Bool) -> String {
        guard needsNeutralizing(s, keepLineBreaks: keepLineBreaks) else { return s }
        var out = String.UnicodeScalarView()
        for u in s.unicodeScalars {
            let v = u.value
            if (v < 0x20 && isC0(UInt8(v), keepLineBreaks: keepLineBreaks)) || (v >= 0x7F && v <= 0x9F) {
                out.append("\u{FFFD}")
            } else {
                out.append(u)
            }
        }
        return String(out)
    }

    /// Bidi embeddings / overrides / isolates, zero-width characters and the BOM.
    @inline(__always) static func isInvisibleFormat(_ v: UInt32) -> Bool {
        (0x200B...0x200F).contains(v) || (0x202A...0x202E).contains(v) || (0x2066...0x2069).contains(v)
            || v == 0xFEFF || v == 0x061C
    }

    /// A one-line label (hostname, program, pid): no controls of any kind, no invisible
    /// formatting characters, at most `max` bytes of UTF-8 (cut at a character boundary).
    static func label(_ s: String, max: Int) -> String {
        let u = s.utf8
        var clean = u.count <= max
        if clean {
            for b in u where b < 0x20 || b == 0x7F || b >= 0xC2 { clean = false; break }
        }
        if clean { return s }
        var out = String.UnicodeScalarView()
        var bytes = 0
        for sc in s.unicodeScalars {
            let v = sc.value
            let r: Unicode.Scalar = v < 0x20 || (v >= 0x7F && v <= 0x9F) || isInvisibleFormat(v) ? "\u{FFFD}" : sc
            let w = UTF8.width(r)
            if bytes + w > max { break }
            out.append(r)
            bytes += w
        }
        return String(out)
    }
}

// MARK: - Header scanner

nonisolated struct HeaderScan {
    private let b: UnsafeBufferPointer<UInt8>
    private let n: Int
    private let now: Date
    private var h = SyslogParser.Header()

    init(_ buf: UnsafeBufferPointer<UInt8>, now: Date) {
        b = buf
        n = buf.count
        self.now = now
    }

    // ASCII
    private static let sp: UInt8 = 0x20, tab: UInt8 = 0x09, lt: UInt8 = 0x3C, gt: UInt8 = 0x3E
    private static let colon: UInt8 = 0x3A, dash: UInt8 = 0x2D, plus: UInt8 = 0x2B, dot: UInt8 = 0x2E
    private static let lbr: UInt8 = 0x5B, rbr: UInt8 = 0x5D, quote: UInt8 = 0x22, bslash: UInt8 = 0x5C
    private static let eq: UInt8 = 0x3D, percent: UInt8 = 0x25

    @inline(__always) private func at(_ i: Int) -> UInt8 { i < n ? b[i] : 0 }
    @inline(__always) private static func isDigit(_ c: UInt8) -> Bool { c >= 0x30 && c <= 0x39 }
    @inline(__always) private static func isAlpha(_ c: UInt8) -> Bool {
        (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A)
    }

    private func str(_ a: Int, _ e: Int) -> String {
        guard a < e else { return "" }
        return String(decoding: UnsafeBufferPointer(rebasing: b[a..<e]), as: UTF8.self)
    }

    private func digits(_ i: Int, _ count: Int) -> Int? {
        guard i + count <= n else { return nil }
        var v = 0
        for k in i..<(i + count) {
            let c = b[k]
            guard Self.isDigit(c) else { return nil }
            v = v * 10 + Int(c - 0x30)
        }
        return v
    }

    private func skipSpaces(_ p: Int) -> Int {
        var q = p
        while q < n, b[q] == Self.sp || b[q] == Self.tab { q += 1 }
        return q
    }

    private func tokenEnd(_ p: Int) -> Int {
        var q = p
        while q < n, b[q] != Self.sp { q += 1 }
        return q
    }

    mutating func run() -> SyslogParser.Header {
        var p = skipSpaces(0)
        // <PRI>
        if at(p) == Self.lt {
            var q = p + 1, v = 0, count = 0
            while q < n, count < 3, Self.isDigit(b[q]) { v = v * 10 + Int(b[q] - 0x30); q += 1; count += 1 }
            if count > 0, at(q) == Self.gt, v <= 191 {
                h.pri = v
                p = q + 1
            }
        }
        p = skipSpaces(p)
        // RFC 5424: VERSION "1" SP TIMESTAMP …
        if at(p) == 0x31, at(p + 1) == Self.sp, parse5424(from: p + 2) { return h }
        // Cisco IOS: "123: " sequence number, then an optional "HOST: " (logging origin-id)
        // and a "*" / "." clock-state mark before the timestamp.
        p = ciscoPrefix(p)
        // RFC 3164 / ISO / NX-OS timestamp
        if let ts = parseTimestamp(at: p) {
            h.time = ts.date
            p = ts.end
            if at(p) == Self.colon { p += 1 }        // Cisco-style "…:32: "
            else if at(p) == Self.sp, at(p + 1) == Self.colon, at(p + 2) == Self.sp { p += 2 }   // IOS XR "…:10.123 : ifmgr[…]"
            p = skipZoneName(p)                      // Cisco "10:15:32.123 ICT: "
            p = skipSpaces(p)
            hostAndTag(from: p)
        } else if at(p) == Self.percent, let tag = parseTag(at: p) {
            // No timestamp, but a Cisco-style mnemonic ("%LINK-3-UPDOWN: …") is the program.
            h.program = tag.program
            h.pid = tag.pid
            h.message = str(tag.end, n)
        } else {
            // No header at all: the message is the whole text (after the PRI).
            h.message = str(p, n)
        }
        return h
    }

    // MARK: RFC 5424

    private mutating func parse5424(from start: Int) -> Bool {
        var q = start
        var time: Date?
        if at(q) == Self.dash, at(q + 1) == Self.sp || q + 1 >= n {
            q += 1
        } else if let ts = parseISO(at: q) {
            time = ts.date
            q = ts.end
        } else if let ts = epochStamp(at: q), at(ts.end) == Self.sp {
            // Cisco Meraki: `1 1790134440.123456789 MS220-8P events port 3 status changed …` —
            // version 1, then epoch seconds, the device, the log category and the text (no
            // PROCID / MSGID / SD). Read as RFC 5424, the whole line was the message, no host.
            h.time = ts.date
            q = ts.end + 1
            let he = tokenEnd(q)
            guard he > q, isHostname(q, he) else { return false }
            h.hostname = str(q, he)
            q = skipSpaces(he)
            let pe = tokenEnd(q)
            h.program = str(q, pe)
            h.message = str(skipSpaces(pe), n)
            return true
        } else {
            return false
        }
        guard q >= n || at(q) == Self.sp else { return false }
        h.time = time
        q += 1
        func field(_ q: inout Int) -> String? {
            guard q < n else { return nil }
            let e = tokenEnd(q)
            let s = (e == q + 1 && b[q] == Self.dash) ? nil : str(q, e)
            q = min(n, e + 1)
            return s
        }
        h.hostname = field(&q) ?? ""
        h.program = field(&q) ?? ""
        h.pid = field(&q)
        if let msgid = field(&q) { h.fields.append(LogField("msgid", msgid)) }
        // STRUCTURED-DATA
        if at(q) == Self.dash, at(q + 1) == Self.sp || q + 1 >= n {
            q += 1
        } else if at(q) == Self.lbr, let sd = parseSD(at: q) {
            h.fields.append(contentsOf: sd.fields)
            q = sd.end
        }
        if at(q) == Self.sp { q += 1 }
        // UTF-8 BOM
        if at(q) == 0xEF, at(q + 1) == 0xBB, at(q + 2) == 0xBF { q += 3 }
        h.message = str(q, n)
        return true
    }

    /// `[id p="v" …][id2 …]`. Returns nil when the brackets are not well-formed SD (Check Point's
    /// `[key:"value"; …]` for example), so the caller leaves them in the message.
    private func parseSD(at start: Int) -> (fields: [LogField], end: Int)? {
        var q = start
        var out: [LogField] = []
        func isNameChar(_ c: UInt8) -> Bool {
            c > 32 && c < 127 && c != Self.eq && c != Self.rbr && c != Self.quote && c != Self.sp
        }
        while at(q) == Self.lbr {
            q += 1
            let idStart = q
            while q < n, isNameChar(b[q]) { q += 1 }
            guard q > idStart else { return nil }
            let id = str(idStart, q)
            while true {
                if at(q) == Self.rbr { q += 1; break }
                guard at(q) == Self.sp else { return nil }
                q = skipSpaces(q)
                if at(q) == Self.rbr { q += 1; break }
                let nameStart = q
                while q < n, isNameChar(b[q]) { q += 1 }
                guard q > nameStart, at(q) == Self.eq, at(q + 1) == Self.quote else { return nil }
                let name = str(nameStart, q)
                q += 2
                var value: [UInt8] = []
                var closed = false
                while q < n {
                    let c = b[q]
                    if c == Self.bslash, q + 1 < n {
                        let nx = b[q + 1]
                        if nx == Self.quote || nx == Self.bslash || nx == Self.rbr {
                            value.append(nx); q += 2; continue
                        }
                    }
                    if c == Self.quote { closed = true; q += 1; break }
                    value.append(c); q += 1
                }
                guard closed else { return nil }
                out.append(LogField("sd.\(id).\(name)", String(decoding: value, as: UTF8.self)))
            }
        }
        return (out, q)
    }

    /// `1790134440.123456789`: Unix seconds (10 digits) with a fraction (Meraki).
    private func epochStamp(at p: Int) -> (date: Date, end: Int)? {
        guard let secs = digits(p, 10), at(p + 10) == Self.dot, Self.isDigit(at(p + 11)) else { return nil }
        var q = p + 11
        let fracStart = q
        while q < n, Self.isDigit(b[q]), q - fracStart < 9 { q += 1 }
        while q < n, Self.isDigit(b[q]) { q += 1 }
        var frac = 0.0, scale = 0.1
        for k in fracStart..<min(q, fracStart + 6) { frac += Double(b[k] - 0x30) * scale; scale /= 10 }
        return (Date(timeIntervalSince1970: Double(secs) + frac), q)
    }

    /// Cisco IOS XR's node before the timestamp: `RP/0/RSP0/CPU0:Sep 23 …`, `0/RP0/CPU0:2026 …`
    /// (letters and digits in three or more `/` parts, a colon, the time right after it), with
    /// `logging hostnameprefix`'s `HOST ` in front. Returns where the timestamp starts.
    private func xrNode(at start: Int) -> (host: Range<Int>?, node: Range<Int>, next: Int)? {
        func node(_ p: Int) -> Int? {
            var q = p, slashes = 0
            while q < n, q - p < 40 {
                let c = b[q]
                if Self.isAlpha(c) || Self.isDigit(c) { q += 1; continue }
                if c == 0x2F, q > p, b[q - 1] != 0x2F { slashes += 1; q += 1; continue }
                break
            }
            guard slashes >= 2, at(q) == Self.colon, b[q - 1] != 0x2F, parseTimestamp(at: q + 1) != nil else { return nil }
            return q
        }
        if let q = node(start) { return (nil, start..<q, q + 1) }
        let e = tokenEnd(start)
        guard e > start, isHostname(start, e) else { return nil }
        let r = skipSpaces(e)
        guard let q = node(r) else { return nil }
        return (start..<e, r..<q, q + 1)
    }

    // MARK: Timestamps

    private func parseTimestamp(at p: Int) -> (date: Date?, end: Int)? {
        let c = at(p)
        if Self.isDigit(c) {
            if let iso = parseISO(at: p) { return iso }
            // NX-OS: "2026 Sep 23 10:15:35"
            if let y = digits(p, 4), (1970...2199).contains(y), at(p + 4) == Self.sp, Self.isAlpha(at(p + 5)) {
                return parse3164(at: p + 5, year: y)
            }
            return nil
        }
        if Self.isAlpha(c) { return parse3164(at: p) }
        return nil
    }

    /// Cisco IOS puts `count: ` (its syslog message counter), `HOST: ` (logging origin-id
    /// hostname), `seq: ` (service sequence-numbers, e.g. `000034: `) and `*` (clock not
    /// synchronised) / `.` (synchronised, not by NTP) in front of the timestamp:
    /// `<189>35: CORE-RTR1: 000034: *Sep 23 10:15:32.123: %SYS-5-…`. Skips them when a
    /// timestamp follows; records the hostname, the counter (`seq`) and the sequence number
    /// (`seqno`).
    private mutating func ciscoPrefix(_ start: Int) -> Int {
        var p = start
        // "35: "
        if let r = counter(at: p), timestampFollows(r) || originHost(at: r) != nil || sequenceBeforeTimestamp(r)
            || (at(r) == Self.percent && Self.isAlpha(at(r + 1))) || xrNode(at: r) != nil {
            h.fields.append(LogField("seq", str(p, counterDigitsEnd(p))))
            p = r
        }
        // IOS XR: "[HOST ]RP/0/RSP0/CPU0:Sep 23 …" (the node is a field; the hostname only
        // with `logging hostnameprefix`). The node was read as the message, the program lost.
        if let xr = xrNode(at: p) {
            if let host = xr.host { h.hostname = str(host.lowerBound, host.upperBound) }
            h.fields.append(LogField("node", str(xr.node.lowerBound, xr.node.upperBound)))
            return xr.next
        }
        // "CORE-RTR1: "
        if let host = originHost(at: p) {
            h.hostname = str(p, host.end)
            p = host.next
        }
        // "000034: "
        if let r = counter(at: p), timestampFollows(r) {
            h.fields.append(LogField("seqno", str(p, counterDigitsEnd(p))))
            p = r
        }
        // "*Sep 23 …" / ".Sep 23 …"
        if at(p) == 0x2A || at(p) == Self.dot, parseTimestamp(at: p + 1) != nil { p += 1 }
        return p
    }

    /// `NNN: ` (1–10 digits, a colon, a space) at `p`: where what follows it starts.
    private func counter(at p: Int) -> Int? {
        let q = counterDigitsEnd(p)
        guard q > p, at(q) == Self.colon, at(q + 1) == Self.sp else { return nil }
        return skipSpaces(q + 1)
    }

    private func counterDigitsEnd(_ p: Int) -> Int {
        var q = p
        while q < n, q - p < 10, Self.isDigit(b[q]) { q += 1 }
        return q
    }

    /// A `seq: ` counter directly followed by a timestamp.
    private func sequenceBeforeTimestamp(_ p: Int) -> Bool {
        guard let r = counter(at: p) else { return false }
        return timestampFollows(r)
    }

    /// `HOST: ` directly followed by a timestamp (optionally marked `*` / `.`), or by a
    /// `seq: ` and then the timestamp. A token of digits only is a counter, not a host.
    private func originHost(at p: Int) -> (end: Int, next: Int)? {
        guard Self.isAlpha(at(p)) || Self.isDigit(at(p)) else { return nil }
        let e = tokenEnd(p)
        guard e - p >= 2, b[e - 1] == Self.colon, isHostname(p, e - 1) else { return nil }
        if (p..<(e - 1)).allSatisfy({ Self.isDigit(b[$0]) }) { return nil }
        let r = skipSpaces(e)
        guard timestampFollows(r) || sequenceBeforeTimestamp(r) else { return nil }
        return (e - 1, r)
    }

    private func timestampFollows(_ p: Int) -> Bool {
        let q = (at(p) == 0x2A || at(p) == Self.dot) ? p + 1 : p
        return parseTimestamp(at: q) != nil
    }

    /// A time-zone abbreviation after a Cisco timestamp (` ICT:`, ` PST:`) is skipped and the
    /// time read as local. (` UTC` / ` GMT` are read by the timestamp parser as offset 0.)
    private func skipZoneName(_ p: Int) -> Int {
        guard at(p) == Self.sp else { return p }
        var q = p + 1
        while q < n, q - p <= 6, b[q] >= 0x41, b[q] <= 0x5A { q += 1 }
        let len = q - p - 1
        guard len >= 2, len <= 5, at(q) == Self.colon, at(q + 1) == Self.sp else { return p }
        return q + 1
    }

    /// ` UTC` / ` GMT` followed by `:`, a space or the end.
    private func zoneIsUTC(_ q: Int) -> Bool {
        let a = at(q), c1 = at(q + 1), c2 = at(q + 2), e = at(q + 3)
        let utc = a == 0x55 && c1 == 0x54 && c2 == 0x43, gmt = a == 0x47 && c1 == 0x4D && c2 == 0x54
        return (utc || gmt) && (e == Self.colon || e == Self.sp || q + 3 >= n)
    }

    /// `yyyy-mm-dd[T ]hh:mm:ss[.frac][Z|±hh:mm|±hhmm]`
    private func parseISO(at p: Int) -> (date: Date?, end: Int)? {
        guard let y = digits(p, 4), at(p + 4) == Self.dash, let mo = digits(p + 5, 2),
              at(p + 7) == Self.dash, let d = digits(p + 8, 2) else { return nil }
        let sep = at(p + 10)
        guard sep == 0x54 || sep == 0x74 || sep == Self.sp,
              let hh = digits(p + 11, 2), at(p + 13) == Self.colon, let mm = digits(p + 14, 2),
              at(p + 16) == Self.colon, let ss = digits(p + 17, 2) else { return nil }
        var q = p + 19
        var frac = 0.0
        if at(q) == Self.dot || at(q) == 0x2C, Self.isDigit(at(q + 1)) {
            q += 1
            frac = fraction(&q)
        }
        var offset: Int?
        if at(q) == 0x5A || at(q) == 0x7A { offset = 0; q += 1 }
        else if let tz = parseOffset(at: q) { offset = tz.seconds; q = tz.end }
        let date = Self.makeDate(y, mo, d, hh, mm, ss, frac, offset)
        return (date, q)
    }

    /// Digits after the decimal point, as a fraction (integer accumulate, one division).
    private func fraction(_ q: inout Int) -> Double {
        var v = 0, div = 1
        while q < n, Self.isDigit(b[q]) {
            if div < 1_000_000_000 { v = v * 10 + Int(b[q] - 0x30); div *= 10 }
            q += 1
        }
        return Double(v) / Double(div)
    }

    /// `+07:00`, `-0800`, `+07`.
    private func parseOffset(at q: Int) -> (seconds: Int, end: Int)? {
        let s = at(q)
        guard s == Self.plus || s == Self.dash, let oh = digits(q + 1, 2), oh <= 14 else { return nil }
        var e = q + 3
        var om = 0
        if at(e) == Self.colon, let m = digits(e + 1, 2) { om = m; e += 3 }
        else if let m = digits(e, 2) { om = m; e += 2 }
        let sec = oh * 3600 + om * 60
        return (s == Self.dash ? -sec : sec, e)
    }

    private static let months: [(UInt8, UInt8, UInt8)] = [
        (0x6A, 0x61, 0x6E), (0x66, 0x65, 0x62), (0x6D, 0x61, 0x72), (0x61, 0x70, 0x72),
        (0x6D, 0x61, 0x79), (0x6A, 0x75, 0x6E), (0x6A, 0x75, 0x6C), (0x61, 0x75, 0x67),
        (0x73, 0x65, 0x70), (0x6F, 0x63, 0x74), (0x6E, 0x6F, 0x76), (0x64, 0x65, 0x63),
    ]

    private func month(at p: Int) -> Int? {
        guard p + 3 < n, b[p + 3] == Self.sp else { return nil }
        let a = b[p] | 0x20, c1 = b[p + 1] | 0x20, c2 = b[p + 2] | 0x20
        // Index loop (the enumerated() iterator cost more than the compare in the hot path).
        var i = 0
        while i < 12 {
            let m = Self.months[i]
            if m.0 == a, m.1 == c1, m.2 == c2 { return i + 1 }
            i += 1
        }
        return nil
    }

    /// `Mmm dd hh:mm:ss`, `Mmm dd yyyy hh:mm:ss`, `Mmm dd hh:mm:ss yyyy`, with optional
    /// fractional seconds and a trailing numeric offset.
    private func parse3164(at p: Int, year givenYear: Int? = nil) -> (date: Date?, end: Int)? {
        guard let mo = month(at: p) else { return nil }
        var q = skipSpaces(p + 4)
        var day = 0
        guard Self.isDigit(at(q)) else { return nil }
        day = Int(b[q] - 0x30); q += 1
        if Self.isDigit(at(q)) { day = day * 10 + Int(b[q] - 0x30); q += 1 }
        guard at(q) == Self.sp else { return nil }
        q += 1
        var year: Int? = givenYear
        if year == nil, let y = digits(q, 4), at(q + 4) == Self.sp, Self.isDigit(at(q + 5)) {
            year = y
            q += 5
        }
        var hh = 0
        guard Self.isDigit(at(q)) else { return nil }
        hh = Int(b[q] - 0x30); q += 1
        if Self.isDigit(at(q)) { hh = hh * 10 + Int(b[q] - 0x30); q += 1 }
        guard at(q) == Self.colon, let mm = digits(q + 1, 2), at(q + 3) == Self.colon,
              let ss = digits(q + 4, 2) else { return nil }
        q += 6
        var frac = 0.0
        if at(q) == Self.dot, Self.isDigit(at(q + 1)) {
            q += 1
            frac = fraction(&q)
        }
        var offset: Int?
        if at(q) == 0x5A { offset = 0; q += 1 }
        else if let tz = parseOffset(at: q) { offset = tz.seconds; q = tz.end }
        else if at(q) == Self.sp, zoneIsUTC(q + 1) { offset = 0; q += 4 }
        // A trailing year ends at a space, the end, or a colon that ends the header ("… 2026: ");
        // "2001:db8::1" / "2003:e2::5" after the time are IPv6 hostnames, not the years 2001 / 2003.
        if year == nil, at(q) == Self.sp, let y = digits(q + 1, 4), (1970...2199).contains(y),
           q + 5 >= n || at(q + 5) == Self.sp
            || (at(q + 5) == Self.colon && (q + 6 >= n || at(q + 6) == Self.sp)) {
            year = y
            q += 5
        }
        if let year {
            return (Self.makeDate(year, mo, day, hh, mm, ss, frac, offset), q)
        }
        // No year: this year; last year when that would put the line more than a day ahead
        // (a Dec 31 line read on Jan 1); next year when that is at most a day ahead (a device
        // whose clock already passed midnight on New Year's Eve).
        let thisYear = Self.localYear(of: now)
        var date = Self.makeDate(thisYear, mo, day, hh, mm, ss, frac, offset)
        if let d = date {
            let ahead = d.timeIntervalSince(now)
            if ahead > 86_400 {
                date = Self.makeDate(thisYear - 1, mo, day, hh, mm, ss, frac, offset)
            } else if ahead < -300 * 86_400,
                      let next = Self.makeDate(thisYear + 1, mo, day, hh, mm, ss, frac, offset),
                      next.timeIntervalSince(now) <= 86_400 {
                date = next
            }
        }
        return (date, q)
    }

    // MARK: HOSTNAME TAG[pid]:

    private mutating func hostAndTag(from start: Int) {
        var p = start
        let e1 = tokenEnd(p)
        let tok1Last = e1 > p ? b[e1 - 1] : 0
        var tokHasBracket = false
        for k in p..<e1 where b[k] == Self.lbr { tokHasBracket = true; break }
        if (tok1Last == Self.colon || tokHasBracket), let tag = parseTag(at: p) {
            h.program = tag.program
            h.pid = tag.pid
            h.message = str(tag.end, n)
            return
        }
        // Aruba AOS-S without a hostname: "00076 ports: …" — the event number is not a host.
        if isAOSSEvent(p, e1) {
            h.message = str(p, n)
            return
        }
        var hostEnd = e1
        if e1 > p, !isHostname(p, e1), let comma = unifiHostEnd(p, e1) { hostEnd = comma }
        if e1 > p, hostEnd < e1 || isHostname(p, e1) {
            // "-" is a relay's "no hostname" (RFC 5424's NILVALUE), not a device called "-".
            h.hostname = hostEnd - p == 1 && b[p] == Self.dash ? "" : str(p, hostEnd)
            p = skipSpaces(e1)
            // Cisco ASA with a hostname: "ASA-FW01 : %ASA-4-106023: …"
            if at(p) == Self.colon, at(p + 1) == Self.sp, at(skipSpaces(p + 1)) == Self.percent {
                p = skipSpaces(p + 1)
            }
            if let tag = parseTag(at: p) {
                h.program = tag.program
                h.pid = tag.pid
                p = tag.end
            } else if let topics = mikroTikTopics(at: p) {
                h.program = str(p, topics)
                p = skipSpaces(topics)
            }
        }
        h.message = str(p, n)
    }

    /// `NNNNN` followed by ` module:` (an AOS-S event number as the first token of the body).
    private func isAOSSEvent(_ p: Int, _ e: Int) -> Bool {
        guard e - p == 5 else { return false }
        for k in p..<e where !Self.isDigit(b[k]) { return false }
        let m = e + 1
        guard at(e) == Self.sp, Self.isAlpha(at(m)) || Self.isDigit(at(m)) else { return false }
        let me = tokenEnd(m)
        return me - m >= 2 && b[me - 1] == Self.colon
    }

    /// UniFi devices send `name,f4e2c6aabbcc,v6.6.55` as the hostname: the name before the
    /// first comma is the host when a 12-digit hex MAC follows it. Returns the comma's index.
    private func unifiHostEnd(_ p: Int, _ e: Int) -> Int? {
        var c = p
        while c < e, b[c] != 0x2C { c += 1 }
        guard c > p, c < e, isHostname(p, c) else { return nil }
        var q = c + 1, hex = 0
        while q < e, b[q] != 0x2C {
            let x = b[q] | 0x20
            guard Self.isDigit(b[q]) || (x >= 0x61 && x <= 0x66) else { return nil }
            hex += 1; q += 1
        }
        return hex == 12 ? c : nil
    }

    /// MikroTik RouterOS topics after the hostname: `system,info,account ` (lower-case words
    /// joined by commas, at least two). Returns the end of the token.
    private func mikroTikTopics(at p: Int) -> Int? {
        guard at(p) >= 0x61, at(p) <= 0x7A else { return nil }
        var q = p, commas = 0
        while q < n, q - p < 64 {
            let c = b[q]
            if (c >= 0x61 && c <= 0x7A) || Self.isDigit(c) { q += 1; continue }
            if c == 0x2C, b[q - 1] != 0x2C { commas += 1; q += 1; continue }
            break
        }
        guard commas >= 1, b[q - 1] != 0x2C, q >= n || b[q] == Self.sp else { return nil }
        return q
    }

    private func isHostname(_ a: Int, _ e: Int) -> Bool {
        guard e - a <= 255 else { return false }
        for k in a..<e {
            let c = b[k]
            if Self.isAlpha(c) || Self.isDigit(c) || c == Self.dash || c == Self.dot || c == 0x5F { continue }
            if c == Self.colon, k < e - 1 { continue }       // IPv6, but not a trailing tag colon
            return false
        }
        return true
    }

    /// `prog:`, `prog[123]:`, `prog[123] `, Cisco `%FAC-5-MNEMONIC:` — returns where the message
    /// starts. A double `%%` is Huawei's marker (the vendor parser reads it), never a tag.
    private func parseTag(at start: Int) -> (program: String, pid: String?, end: Int)? {
        var q = start
        if at(q) == Self.percent {
            guard Self.isAlpha(at(q + 1)) else { return nil }
            q += 1
        }
        while q < n, q - start < 48 {
            let c = b[q]
            if Self.isAlpha(c) || Self.isDigit(c) || c == Self.dash || c == 0x5F || c == Self.dot
                || c == 0x2F || c == 0x40 { q += 1 } else { break }
        }
        guard q > start else { return nil }
        let program = str(start, q)
        var pid: String?
        if at(q) == Self.lbr {
            let ps = q + 1
            var r = ps
            while r < n, b[r] != Self.rbr, b[r] != Self.sp, r - ps < 24 { r += 1 }
            guard at(r) == Self.rbr else { return nil }
            pid = str(ps, r)
            q = r + 1
            if at(q) == Self.colon { q += 1 } else if at(q) != Self.sp { return nil }
        } else if at(q) == Self.colon, at(q + 1) == Self.sp || q + 1 >= n {
            q += 1
        } else {
            return nil
        }
        if at(q) == Self.sp { q += 1 }
        return (program, pid, q)
    }

    // MARK: Calendar arithmetic (no Calendar / DateFormatter on the hot path)

    /// Follows a time-zone change (travel, an automatic zone): a copy of `TimeZone.current`
    /// taken at first use dated every later zone-less timestamp in the old zone. The default
    /// zone, as the tables' formatters use (it is the system zone unless set).
    /// (`AppModel` resets the cached system zone on `NSSystemTimeZoneDidChange`.)
    static var localZone: TimeZone { NSTimeZone.default }

    /// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant's algorithm).
    static func daysFromCivil(_ y0: Int, _ m: Int, _ d: Int) -> Int {
        let y = m <= 2 ? y0 - 1 : y0
        let era = (y >= 0 ? y : y - 399) / 400
        let yoe = y - era * 400
        let mp = (m + 9) % 12
        let doy = (153 * mp + 2) / 5 + d - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146_097 + doe - 719_468
    }

    static func makeDate(_ y: Int, _ mo: Int, _ d: Int, _ hh: Int, _ mm: Int, _ ss: Int,
                         _ frac: Double, _ offset: Int?) -> Date? {
        guard (1...12).contains(mo), (1...31).contains(d), hh < 24, mm < 60, ss <= 60 else { return nil }
        let wall = Double(daysFromCivil(y, mo, d) * 86_400 + hh * 3600 + mm * 60 + ss) + frac
        if let offset { return Date(timeIntervalSince1970: wall - Double(offset)) }
        let guess = Date(timeIntervalSince1970: wall)
        let first = localZone.secondsFromGMT(for: guess)
        let second = localZone.secondsFromGMT(for: Date(timeIntervalSince1970: wall - Double(first)))
        return Date(timeIntervalSince1970: wall - Double(second))
    }

    static func localYear(of date: Date) -> Int {
        let local = date.timeIntervalSince1970 + Double(localZone.secondsFromGMT(for: date))
        let days = Int((local / 86_400).rounded(.down))
        // civil_from_days
        let z = days + 719_468
        let era = (z >= 0 ? z : z - 146_096) / 146_097
        let doe = z - era * 146_097
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        let mp = (5 * doy + 2) / 153
        let m = mp < 10 ? mp + 3 : mp - 9
        return yoe + era * 400 + (m <= 2 ? 1 : 0)
    }
}
