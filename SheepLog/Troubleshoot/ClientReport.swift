import Foundation

// MARK: - Which client

/// A client as typed: a MAC in any of the usual spellings, or an IPv4 / IPv6 address.
nonisolated enum ClientID: Sendable, Equatable {
    case mac(String)
    case ip(String)

    /// "02:00:5e:10:00:01", "02-00-5E-10-00-01", "0200.5e10.0001", "02005e100001", "10.1.20.50", "fe80::1".
    static func parse(_ text: String) -> ClientID? {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty else { return nil }
        if FText.isIPv4(t) { return .ip(t) }
        let hex = t.lowercased().filter { $0 != ":" && $0 != "-" && $0 != "." }
        if hex.count == 12, hex.allSatisfy(\.isHexDigit),
           t.allSatisfy({ $0.isHexDigit || ":-.".contains($0) }) {
            var out = ""
            for (i, c) in hex.enumerated() {
                if i > 0, i % 2 == 0 { out += ":" }
                out.append(c)
            }
            return .mac(out)
        }
        var a6 = in6_addr()
        if t.contains(":"), inet_pton(AF_INET6, t, &a6) == 1 { return .ip(t.lowercased()) }
        return nil
    }

    var text: String { switch self { case .mac(let m): m; case .ip(let a): a } }

    /// How a MAC appears in logs: colons, dashes, Cisco dots, bare hex.
    static func spellings(ofMAC m: String) -> [String] {
        let hex = m.replacingOccurrences(of: ":", with: "")
        let pairs = stride(from: 0, to: 12, by: 2).map { i -> String in
            let a = hex.index(hex.startIndex, offsetBy: i)
            return String(hex[a..<hex.index(a, offsetBy: 2)])
        }
        let quads = stride(from: 0, to: 12, by: 4).map { i -> String in
            let a = hex.index(hex.startIndex, offsetBy: i)
            return String(hex[a..<hex.index(a, offsetBy: 4)])
        }
        return [pairs.joined(separator: ":"), pairs.joined(separator: "-"), quads.joined(separator: "."), hex]
    }
}

// MARK: - The report

/// Everything SheepLog knows about one endpoint, as one narrative: who it is, where it is
/// connected, what the log says, its DHCP / DNS / ARP packets, its TCP conversations, the
/// findings about it, and what to do next. Built off the main actor.
nonisolated struct ClientReport: Sendable {
    nonisolated struct LogLine: Sendable, Identifiable {
        let id: Int
        let time: Date
        let device: String
        let severity: Severity
        let message: String
    }

    nonisolated struct FlowLine: Sendable, Identifiable {
        let id: Int
        let text: String
        let health: TCPFlow.Health
        let ref: FlowRef
    }

    let query: String
    let client: ClientID
    var macs: [String] = []
    var ips: [String] = []
    var identity: [String] = []
    var location: [String] = []
    var findings: [Finding] = []
    var logLines: [LogLine] = []
    var logTotal = 0
    var dhcp: [String] = []
    var dns: [String] = []
    var arp: [String] = []
    var packetTotal = 0
    var packetIDs: [Int] = []
    var flows: [FlowLine] = []
    var flowTotal = 0
    var nextSteps: [String] = []
    var generated = Date()
    var dataStart: Date?
    var dataEnd: Date?
    /// `PacketStore.epoch` of the packets the report was read from: after a Clear the same frame
    /// numbers — and the same `ip:` filter — are another capture's.
    var packetEpoch = 0
    /// Every log line and frame it counts (whether they are still in memory).
    var logIDs: [Int] = []
    var packetHitIDs: [Int] = []

    /// What its links open, as the findings' evidence is (`TroubleshootJump.show(_:epoch:)`: said,
    /// not opened, once it has rolled out or the capture was cleared).
    var logEvidence: Evidence {
        Evidence(kind: .logLines, label: "\(Format.count(logTotal)) log line\(logTotal == 1 ? "" : "s")", ids: logIDs, query: logQuery)
    }

    var packetEvidence: Evidence {
        Evidence(kind: .packets, label: "\(Format.count(packetTotal)) packets", ids: packetHitIDs, query: packetQuery)
    }

    func flowEvidence(_ f: FlowLine) -> Evidence {
        Evidence(kind: .flows, label: "flow", ids: [f.id], query: "", flows: [f.ref])
    }

    var title: String {
        switch client {
        case .mac(let m): "Client \(m)"
        case .ip(let a): "Client \(a)"
        }
    }

    var logQuery: String {
        let terms = (ips + macs).map { FText.quote($0) }
        return terms.count == 1 ? terms[0] : "(" + terms.joined(separator: " OR ") + ")"
    }

    var packetQuery: String {
        let terms = ips.map { "ip:\($0)" } + macs.map { "mac:\($0)" }
        return terms.joined(separator: " OR ")
    }

    static let maxLogLines = 40

    static func build(_ text: String, input: TroubleshootInput, findings: [Finding]) -> ClientReport? {
        guard let id = ClientID.parse(text) else { return nil }
        var r = ClientReport(query: text, client: id)
        r.generated = input.now
        switch id {
        case .mac(let m): r.macs = [m]
        case .ip(let a): r.ips = [a]
        }
        let pk = PacketScan.scan(input.packets)
        // Who else it is: MAC ↔ IP from DHCP and ARP.
        var sources: [String] = []
        switch id {
        case .mac(let m):
            if let ack = pk.dhcp.last(where: { $0.clientMAC == m && $0.type == "ACK" && $0.yourIP != nil }), let ip = ack.yourIP {
                r.ips.append(ip); sources.append("IP \(ip) (DHCP ACK at \(FText.clock(ack.time)))")
            } else if let a = pk.arp.last(where: { $0.senderMAC == m && $0.senderIP != "0.0.0.0" }) {
                r.ips.append(a.senderIP); sources.append("IP \(a.senderIP) (ARP at \(FText.clock(a.time)))")
            }
        case .ip(let ip):
            if let a = pk.arp.last(where: { $0.senderIP == ip }) {
                r.macs.append(a.senderMAC); sources.append("MAC \(a.senderMAC) (ARP at \(FText.clock(a.time)))")
            } else if let ack = pk.dhcp.last(where: { $0.yourIP == ip && $0.type == "ACK" }) {
                r.macs.append(ack.clientMAC); sources.append("MAC \(ack.clientMAC) (DHCP ACK at \(FText.clock(ack.time)))")
            }
        }
        r.identity = sources

        // Log lines that mention any of its names.
        let needles = r.macs.flatMap(ClientID.spellings(ofMAC:)) + r.ips
        let hits = ClientSearch.lines(input.entries, needles: needles)
        r.logTotal = hits.count
        r.logIDs = hits.map(\.id)
        r.packetEpoch = input.packetEpoch
        let devices = DeviceNames(input.entries)
        for e in hits.suffix(maxLogLines) {
            r.logLines.append(LogLine(id: e.id, time: e.deviceTime ?? e.received, device: devices.name(e), severity: e.severity,
                                      message: FText.excerpt(e.message, max: 160)))
        }
        // Where it is connected, from what the lines say.
        var seen = Set<String>()
        for e in hits.reversed() {
            let dev = devices.name(e)
            var parts: [String] = []
            for k in ["port", "Port", "interface", "Interface", "NAS-Port-Id", "Common.NAS-Port-Id", "AP", "ap_name", "SSID", "VLAN", "vlan"] {
                if let v = e.field(k), !v.isEmpty { parts.append("\(k.replacingOccurrences(of: "Common.", with: "")) \(v)") }
            }
            if parts.isEmpty {
                if let p = FText.token(after: "port ", in: e.message), p != "-" { parts.append("port \(p)") }
                else if let i = FText.token(after: "interface ", in: e.message) { parts.append("interface \(i)") }
            }
            guard !parts.isEmpty else { continue }
            let text = "\(dev) — \(parts.joined(separator: ", "))"
            if seen.insert(text).inserted {
                r.location.append("\(text) (log line at \(FText.clock(e.deviceTime ?? e.received)))")
            }
            if r.location.count >= 4 { break }
        }
        // … and from a bridge forwarding table in an SNMP walk.
        for m in r.macs {
            for s in input.snmp.reversed() {
                if let port = ClientSearch.fdbPort(mac: m, in: s) { r.location.append("\(s.name) — \(port) (bridge table, SNMP walk at \(FText.clock(s.taken)))"); break }
            }
        }

        // Packets.
        let macSet = Set(r.macs), ipSet = Set(r.ips)
        for d in pk.dhcp where macSet.contains(d.clientMAC) {
            var s = "\(FText.clock(d.time))  \(d.type)\(d.relayHop ? " (relayed)" : "")"
            if let y = d.yourIP { s += " → \(y)" }
            if let srv = d.server, d.type != "Discover" && d.type != "Request" { s += " from \(srv)" }
            if let l = d.lease { s += ", lease \(FText.duration(Double(l)))" }
            if let v = d.vlan { s += " (VLAN \(v))" }
            r.dhcp.append(s)
        }
        if r.location.isEmpty, let v = pk.dhcp.last(where: { macSet.contains($0.clientMAC) && $0.vlan != nil })?.vlan {
            r.location.append("VLAN \(v) (its DHCP packets are tagged with it; the switch port is not known)")
        }
        let discovers = pk.dhcp.filter { macSet.contains($0.clientMAC) && $0.type == "Discover" }
        let offered = pk.dhcp.contains { macSet.contains($0.clientMAC) && $0.type == "Offer" }
        let acked = pk.dhcp.contains { macSet.contains($0.clientMAC) && $0.type == "ACK" }
        var dnsFail = 0, dnsTotal = 0
        var resolvers = Set<String>()
        var failedNames: [String: Int] = [:]
        struct QK: Hashable { let port: UInt16; let server: String; let txid: UInt16 }
        var open: [QK: DNSFact] = [:]
        for d in pk.dns.sorted(by: { $0.time < $1.time }) where ipSet.contains(d.client) {
            let k = QK(port: d.clientPort, server: d.server, txid: d.txid)
            if !d.isResponse { dnsTotal += 1; resolvers.insert(d.server); open[k] = d; continue }
            if open.removeValue(forKey: k) != nil, d.rcode != 0 {
                dnsFail += 1
                failedNames[d.name, default: 0] += 1
            }
        }
        let unanswered = open.count
        if dnsTotal > 0 {
            r.dns.append("\(dnsTotal) queries to \(FText.list(resolvers.sorted(), max: 3)); \(dnsFail) failed (SERVFAIL / NXDOMAIN / REFUSED), \(unanswered) unanswered.")
            for (name, n) in failedNames.sorted(by: { $0.value > $1.value }).prefix(5) { r.dns.append("failed: \(name) ×\(n)") }
        }
        for a in pk.arp where macSet.contains(a.senderMAC) || ipSet.contains(a.senderIP) || ipSet.contains(a.targetIP) {
            if r.arp.count >= 12 { break }
            r.arp.append(a.isRequest
                ? "\(FText.clock(a.time))  who has \(a.targetIP)? tell \(a.senderIP) (\(a.senderMAC))"
                : "\(FText.clock(a.time))  \(a.senderIP) is at \(a.senderMAC)")
        }
        let packetHits = ClientSearch.packets(input.packets, ips: ipSet, macs: macSet)
        r.packetTotal = packetHits.count
        r.packetIDs = Array(packetHits.prefix(50))
        r.packetHitIDs = packetHits

        // Conversations.
        let mine = input.flows.filter { ipSet.contains($0.client) || ipSet.contains($0.server) }
        r.flowTotal = mine.count
        let ordered = mine.sorted { ($0.health == .bad ? 0 : $0.health == .warn ? 1 : 2, $0.firstTime) < ($1.health == .bad ? 0 : $1.health == .warn ? 1 : 2, $1.firstTime) }
        for f in ordered.prefix(20) {
            let problems = f.reasons.isEmpty ? "healthy" : f.reasons.prefix(2).joined(separator: "; ")
            r.flows.append(FlowLine(id: f.id, text: "\(FText.clock(f.firstTime))  \(f.clientEndpoint) → \(f.serverEndpoint) (\(f.application)) — \(problems)",
                                    health: f.health, ref: FlowRef(key: f.key, packetID: f.firstPacketID, lastPacketID: f.lastPacketID)))
        }

        // Findings about it (its address as a whole address: 10.1.30.1 is not in a finding about 10.1.30.14).
        let names = Set(r.macs + r.ips)
        r.findings = findings.filter { f in
            if let c = f.client, names.contains(c) { return true }
            return names.contains { n in
                f.title.withCString { ClientSearch.contains($0, n) } || f.detail.withCString { ClientSearch.contains($0, n) }
            }
        }

        // What to do.
        var steps: [String] = []
        if !discovers.isEmpty && !offered {
            steps.append("It asked for an address \(discovers.count) times and got no Offer: check the DHCP scope and relay for its VLAN\(discovers.first?.vlan.map { " (\($0))" } ?? "").")
        } else if offered && !acked && !discovers.isEmpty {
            steps.append("It was offered an address but never got an ACK: look for a NAK or a second DHCP server.")
        }
        if dnsTotal > 0, dnsFail + unanswered > 0, Double(dnsFail + unanswered) / Double(dnsTotal) >= 0.3 {
            steps.append("Many of its DNS lookups failed: check the resolver it uses (\(FText.list(resolvers.sorted(), max: 2))).")
        }
        if let bad = mine.first(where: { $0.health == .bad }) {
            steps.append("Show the flow \(bad.clientEndpoint) → \(bad.serverEndpoint): \(bad.reasons.first ?? "problem").")
        }
        for f in r.findings.sorted(by: { $0.severity > $1.severity }) {
            for s in f.nextSteps.prefix(2) where !steps.contains(s) { steps.append(s) }
            if steps.count >= 8 { break }
        }
        if !r.location.contains(where: { $0.contains(" — ") }) && (r.logTotal > 0 || r.packetTotal > 0) {
            steps.append("Find its switch port: show mac address-table address \(r.macs.first ?? "<its MAC>"), or walk the bridge table (dot1dTpFdbPort) on the SNMP Test pane.")
        }
        if r.logTotal == 0 && r.packetTotal == 0 && r.flowTotal == 0 {
            steps.append("Nothing SheepLog holds mentions \(text): check the spelling, or capture on its switch port (SPAN) and try again.")
        }
        r.nextSteps = steps
        let times = input.entries.map { $0.deviceTime ?? $0.received } + input.packets.map(\.timestamp)
        r.dataStart = times.min()
        r.dataEnd = times.max()
        return r
    }

    // MARK: Markdown

    var markdown: String {
        var md = "# \(title)\n\n"
        md += "_SheepLog troubleshooting report · \(ReportText.stamp(generated))"
        if let a = dataStart, let b = dataEnd { md += " · data \(ReportText.stamp(a)) – \(ReportText.stamp(b))" }
        md += "_\n\n"
        var also: [String] = []
        if case .ip = client, !macs.isEmpty { also.append(contentsOf: identity) }
        if case .mac = client, !ips.isEmpty { also.append(contentsOf: identity) }
        if !also.isEmpty { md += "**Also known as:** " + also.joined(separator: " · ") + "\n\n" }
        md += "## Where it is\n\n"
        md += location.isEmpty ? "Not known — no log line or bridge table names its switch port.\n\n" : location.map { "- \(ReportText.escape($0))" }.joined(separator: "\n") + "\n\n"
        md += "## Findings (\(findings.count))\n\n"
        if findings.isEmpty { md += "No finding is about this client.\n\n" }
        for f in findings {
            md += "- **\(f.severity.word)** — \(ReportText.escape(f.title))  \n  \(ReportText.escape(f.detail))\n"
        }
        if !findings.isEmpty { md += "\n" }
        md += "## Log lines (\(Format.count(logTotal)))\n\n"
        if logLines.isEmpty { md += "No syslog line or trap mentions it.\n\n" } else {
            if logTotal > logLines.count { md += "The last \(logLines.count) of \(Format.count(logTotal)):\n\n" }
            md += "| Time | Device | Severity | Message |\n|---|---|---|---|\n"
            for l in logLines {
                md += "| \(FText.clock(l.time)) | \(ReportText.cell(l.device)) | \(l.severity.label) | \(ReportText.cell(l.message)) |\n"
            }
            md += "\n"
        }
        md += "## DHCP\n\n" + (dhcp.isEmpty ? "No DHCP packets of this client in the capture.\n\n" : dhcp.map { "- `\($0)`" }.joined(separator: "\n") + "\n\n")
        md += "## DNS\n\n" + (dns.isEmpty ? "No DNS queries from this client in the capture.\n\n" : dns.map { "- \(ReportText.escape($0))" }.joined(separator: "\n") + "\n\n")
        md += "## ARP\n\n" + (arp.isEmpty ? "No ARP packets about this client in the capture.\n\n" : arp.map { "- `\($0)`" }.joined(separator: "\n") + "\n\n")
        md += "## TCP flows (\(flowTotal))\n\n"
        if flows.isEmpty { md += "No TCP conversation of this client in the capture.\n\n" } else {
            for f in flows { md += "- \(f.health == .ok ? "✓" : f.health == .warn ? "⚠︎" : "✗") \(ReportText.escape(f.text))\n" }
            if flowTotal > flows.count { md += "- … \(flowTotal - flows.count) more\n" }
            md += "\n"
        }
        md += "Packets involving it: \(Format.count(packetTotal)).\n\n"
        md += "## Next steps\n\n"
        md += nextSteps.isEmpty ? "Nothing stands out.\n" : nextSteps.enumerated().map { "\($0.offset + 1). \(ReportText.escape($0.element))" }.joined(separator: "\n") + "\n"
        return md
    }
}

// MARK: - Searching for a client

nonisolated enum ClientSearch {
    /// Lines whose raw text holds any of `needles` (case-insensitive; an address only as a whole address).
    static func lines(_ entries: [LogEntry], needles: [String]) -> [LogEntry] {
        guard !needles.isEmpty, !entries.isEmpty else { return [] }
        let n = entries.count
        let chunks = max(1, min(ProcessInfo.processInfo.activeProcessorCount * 3, n / 2_000))
        let per = (n + chunks - 1) / chunks
        let slots = ChunkSlots<[LogEntry]>(chunks)
        DispatchQueue.concurrentPerform(iterations: chunks) { c in
            var out: [LogEntry] = []
            let lo = c * per, hi = min(n, lo + per)
            if lo < hi {
                for i in lo..<hi {
                    let e = entries[i]
                    let hit = e.raw.withCString { s in needles.contains { contains(s, $0) } }
                        || (e.transport == .trap && e.message.withCString { s in needles.contains { contains(s, $0) } })
                    if hit { out.append(e) }
                }
            }
            slots.set(c, out)
        }
        return slots.values.flatMap { $0 }
    }

    /// `needle` in `s` with no address character glued to either side (10.1.1.1 is not in 10.1.1.10).
    /// For an IPv4 address only digits and dots glue: `inside:10.1.0.80/22` (ASA), `10.1.0.5:51234`
    /// and `[10.1.0.5]` hold it — a colon was taken as part of a longer IPv6 / MAC address and
    /// every ASA line missed.
    static func contains(_ s: UnsafePointer<CChar>, _ needle: String) -> Bool {
        let v4 = FText.isIPv4(needle)
        return needle.withCString { np -> Bool in
            let len = strlen(np)
            var p = s
            while let hit = strcasestr(p, np) {
                let before: CChar = hit == s ? 0 : hit[-1]
                let after = hit[len]
                func glued(_ c: CChar) -> Bool {
                    if v4 { return (c >= 48 && c <= 57) || c == 46 }
                    return (c >= 48 && c <= 57) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70) || c == 46 || c == 58
                }
                // "10.1.1.1." at the end of a sentence still counts.
                let afterOK = !glued(after) || (after == 46 && !(hit[len + 1] >= 48 && hit[len + 1] <= 57))
                if !glued(before) && afterOK { return true }
                p = UnsafePointer(hit) + 1
            }
            return false
        }
    }

    /// Frame numbers of packets from or to the client.
    static func packets(_ packets: [Packet], ips: Set<String>, macs: Set<String>) -> [Int] {
        var out: [Int] = []
        for p in packets {
            let d = p.decoded
            if let ip = d.ip, ips.contains(ip.source) || ips.contains(ip.destination) { out.append(p.id); continue }
            if let a = d.arp, ips.contains(a.senderIP) || ips.contains(a.targetIP) || macs.contains(a.senderMAC) { out.append(p.id); continue }
            if macs.contains(d.sourceMAC) || macs.contains(d.destinationMAC) { out.append(p.id) }
        }
        return out
    }

    static let fdb = OID([1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2])          // dot1dTpFdbPort.<mac>
    static let qfdb = OID([1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2])   // dot1qTpFdbPort.<vlan>.<mac>
    static let basePortIfIndex = OID([1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 2])

    /// The port a bridge table (BRIDGE-MIB / Q-BRIDGE-MIB) in a walk puts `mac` on.
    static func fdbPort(mac: String, in s: SNMPSnapshot) -> String? {
        let arcs = mac.split(separator: ":").compactMap { UInt32($0, radix: 16) }
        guard arcs.count == 6 else { return nil }
        var bridgePort: UInt32?
        var vlan: UInt32?
        if let v = s.values[fdb.appending(arcs)], let n = UInt32(v.prefix { $0.isNumber }) { bridgePort = n }
        else {
            for (oid, v) in s.values where qfdb.isPrefix(of: oid) && oid.parts.count == qfdb.parts.count + 7
                && Array(oid.parts.suffix(6)) == arcs {
                bridgePort = UInt32(v.prefix { $0.isNumber })
                vlan = oid.parts[qfdb.parts.count]
                break
            }
        }
        guard let bp = bridgePort, bp > 0 else { return nil }
        var name = "bridge port \(bp)"
        if let v = s.values[basePortIfIndex.appending(bp)], let ifIndex = UInt32(v.prefix { $0.isNumber }) {
            if let row = s.interfaces.first(where: { $0.index == ifIndex }), !row.name.isEmpty { name = row.name }
            else { name = "ifIndex \(ifIndex)" }
        }
        return vlan.map { "\(name), VLAN \($0)" } ?? name
    }
}

/// Device names for log lines (a trap's host is its address; the syslog hostname is nicer).
nonisolated struct DeviceNames {
    private var byAddress: [String: String] = [:]

    init(_ entries: [LogEntry]) {
        for e in entries where e.transport != .trap && !e.hostname.isEmpty { byAddress[e.sourceAddress] = e.hostname }
    }

    func name(_ e: LogEntry) -> String {
        if e.transport == .trap { return byAddress[e.sourceAddress] ?? e.displayHost }
        return e.hostname.isEmpty ? (byAddress[e.sourceAddress] ?? e.sourceAddress) : e.hostname
    }
}

// MARK: - The whole report

nonisolated enum ReportText {
    static let stampFormat = Format.gregorian("yyyy-MM-dd HH:mm:ss")

    static func stamp(_ d: Date) -> String { stampFormat.string(from: d) }

    /// Markdown-safe inline text.
    static func escape(_ s: String) -> String {
        var out = ""
        for ch in s {
            if "*_`[]<>|\\".contains(ch) { out.append("\\") }
            out.append(ch)
        }
        return out.replacingOccurrences(of: "\n", with: " ")
    }

    static func cell(_ s: String) -> String { escape(s) }

    /// Every finding (as filtered on screen) and the timeline, for a ticket or a hand-over.
    /// `total`: how many findings the analysis had (the report says how many of them it shows).
    static func findings(_ findings: [Finding], summary: AnalysisSummary, timeline: Timeline, heading: String,
                         scope: String?, generated: Date, total: Int? = nil) -> String {
        var md = "# SheepLog troubleshooting report\n\n"
        md += "_\(stamp(generated))"
        if let a = summary.start, let b = summary.end { md += " · data \(stamp(a)) – \(stamp(b))" }
        md += "_\n\n"
        md += "**\(escape(heading))**\n\n"
        md += "Analysed: \(Format.count(summary.lines)) syslog lines, \(Format.count(summary.traps)) traps from \(Format.count(summary.devices)) device\(summary.devices == 1 ? "" : "s"); "
            + "\(Format.count(summary.packets)) packets; \(Format.count(summary.flows)) TCP flows; SNMP results from \(summary.snmpWalks) device\(summary.snmpWalks == 1 ? "" : "s").\n\n"
        if let total {
            md += "Shown: \(total == findings.count ? "all \(Format.count(total))" : "\(Format.count(findings.count)) of \(Format.count(total))") finding\(total == 1 ? "" : "s")"
                + (scope.map { " — \(escape($0))" } ?? "") + ".\n\n"
        } else if let scope {
            md += "Shown: \(escape(scope)).\n\n"
        }
        for sev in [FindingSeverity.bad, .warn, .info] {
            let list = findings.filter { $0.severity == sev }
            guard !list.isEmpty else { continue }
            md += "## \(sev == .bad ? "Problems" : sev == .warn ? "Warnings" : "Notes") (\(list.count))\n\n"
            for f in list {
                md += "### \(escape(f.title))\n\n"
                var meta = ["\(f.category.title)", "\(FText.clock(f.firstSeen))" + (f.lastSeen > f.firstSeen ? "–\(FText.clock(f.lastSeen))" : "")]
                if f.count > 1 { meta.append("\(Format.count(f.count))×") }
                if let d = f.device { meta.append(d + (f.deviceAddress.map { $0 == d ? "" : " (\($0))" } ?? "")) }
                if let c = f.client { meta.append("client \(c)") }
                md += "_" + meta.map(escape).joined(separator: " · ") + "_\n\n"
                md += escape(f.detail) + "\n\n"
                if !f.evidence.isEmpty {
                    md += "Evidence: " + f.evidence.map { e in
                        switch e.kind {
                        case .flows: return escape(e.label) + " — " + e.flows.prefix(3).map { "\($0.key)" }.joined(separator: ", ")
                        default: return escape(e.label) + (e.query.isEmpty ? "" : " — filter `\(e.query.replacingOccurrences(of: "`", with: "'"))`")
                        }
                    }.joined(separator: "; ") + "\n\n"
                }
                if !f.nextSteps.isEmpty {
                    md += "Next steps:\n\n" + f.nextSteps.map { "- \(escape($0))" }.joined(separator: "\n") + "\n\n"
                }
            }
        }
        if findings.isEmpty {
            // A filter that hides every finding is not "nothing wrong".
            md += (total ?? 0) > 0 ? "No finding matches what was shown.\n\n" : "Nothing wrong that SheepLog can see.\n\n"
        }
        if !timeline.isEmpty {
            md += "## Timeline\n\n"
            md += "\(stamp(timeline.start)) – \(stamp(timeline.end))\n\n"
            md += timeline.summaryLines().map { "- \(escape($0))" }.joined(separator: "\n") + "\n\n"
        }
        if !summary.notes.isEmpty {
            md += "## Not checked\n\n" + summary.notes.map { "- \(escape($0))" }.joined(separator: "\n") + "\n"
        }
        return md
    }
}
