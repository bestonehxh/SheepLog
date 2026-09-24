import Foundation

// MARK: - Session model

/// How a client authenticated.
nonisolated enum AuthMethod: Sendable, Equatable, Hashable {
    /// RADIUS Access-Request whose User-Name is the client's MAC, no EAP.
    case macAuth
    /// 802.1X with this EAP method ("PEAP", "EAP-TLS", "PEAP/MSCHAPv2", "802.1X" when only the identity was seen).
    case dot1x(String)
    /// A MAC-auth attempt, then 802.1X for the same client within 60 s.
    case macThenDot1x(String)
    /// WPA-PSK: a 4-way handshake with no EAP before it.
    case psk
    /// An open network with a captive portal (a redirect or an intercepted probe), nothing else.
    case captive
    case unknown

    var label: String {
        switch self {
        case .macAuth: "MAC auth"
        case .dot1x(let m): m == "802.1X" ? "802.1X" : "802.1X \(m)"
        case .macThenDot1x(let m): m == "802.1X" ? "MAC → 802.1X" : "MAC → 802.1X \(m)"
        case .psk: "PSK"
        case .captive: "Captive portal"
        case .unknown: "Other"
        }
    }

    var isDot1x: Bool { if case .dot1x = self { true } else if case .macThenDot1x = self { true } else { false } }
    var isMAC: Bool { self == .macAuth || { if case .macThenDot1x = self { true } else { false } }() }
}

/// The method filter of the pane's strip.
nonisolated enum AuthMethodFilter: String, CaseIterable, Sendable {
    case all = "All", dot1x = "802.1X", mac = "MAC", psk = "PSK", captive = "Captive"

    func matches(_ s: AuthSession) -> Bool {
        switch self {
        case .all: true
        case .dot1x: s.method.isDot1x
        case .mac: s.method.isMAC
        case .psk: s.method == .psk
        case .captive: s.captive || s.method == .captive
        }
    }
}

nonisolated enum AuthResult: Sendable, Equatable {
    case accepted
    case rejected(String)
    case timeout(String)
    case inProgress

    var label: String {
        switch self {
        case .accepted: "Accept"
        case .rejected: "Reject"
        case .timeout: "Timeout"
        case .inProgress: "In progress"
        }
    }

    var detail: String? {
        switch self {
        case .rejected(let s), .timeout(let s): s
        default: nil
        }
    }

    var isFailure: Bool { if case .rejected = self { true } else if case .timeout = self { true } else { false } }

    /// Sort order: failures first.
    var rank: Int {
        switch self {
        case .rejected: 0
        case .timeout: 1
        case .inProgress: 2
        case .accepted: 3
        }
    }
}

nonisolated enum AuthHealth: Int, Sendable, Comparable {
    case bad = 0, warn = 1, ok = 2
    static func < (a: AuthHealth, b: AuthHealth) -> Bool { a.rawValue < b.rawValue }
}

/// The three lifelines of the ladder.
nonisolated enum AuthLifeline: Int, Sendable, Comparable, CaseIterable {
    case client = 0, nas = 1, server = 2
    static func < (a: AuthLifeline, b: AuthLifeline) -> Bool { a.rawValue < b.rawValue }

    var title: String {
        switch self {
        case .client: "Client"
        case .nas: "Switch / AP"
        case .server: "RADIUS"
        }
    }
}

nonisolated struct AuthEvent: Identifiable, Sendable {
    nonisolated enum Kind: Sendable, Equatable {
        case eapol
        case eapRequest, eapResponse, eapSuccess, eapFailure
        /// Consecutive TLS rounds of PEAP / EAP-TLS / TTLS / FAST, drawn as one row.
        case tlsRounds(Int)
        /// EAPOL-Key message 1…4 of the 4-way handshake; 0 = group key.
        case key(Int)
        case radiusRequest, radiusChallenge, radiusAccept, radiusReject, accounting, coa
        case dhcp, dns
        case captiveProbe, captiveRedirect, captiveLogin, captivePassed, captivePortalPage
    }

    let id: Int
    /// Seconds since the session's first event.
    let time: Double
    let kind: Kind
    let from: AuthLifeline
    let to: AuthLifeline
    let label: String
    /// A second line of attributes (User-Name, Calling-Station-Id, VLAN …), when there is one.
    let detail: String?
    let problem: String?
    let packetIDs: [Int]
    /// Seconds since the session start of the last packet (a grouped row spans time).
    var endTime: Double? = nil

    var isGroup: Bool { if case .tlsRounds = kind { true } else { false } }
}

nonisolated struct AuthSession: Identifiable, Sendable {
    let id: Int
    /// The client MAC (`aa:bb:cc:dd:ee:ff`), `user:<name>` when RADIUS carried no MAC, or
    /// `port:<authenticator MAC>` for a switch port's requests that no supplicant answered.
    let client: String
    /// EAP identity or RADIUS User-Name (a MAC identity is shown as the MAC).
    let user: String?
    let method: AuthMethod
    /// A captive portal was seen (on its own, or after PSK / 802.1X).
    let captive: Bool
    let portalHost: String?
    let result: AuthResult
    /// For MAC → 802.1X: how the MAC stage ended.
    let macStageResult: AuthResult?
    /// NAS-Identifier / NAS-IP-Address / the authenticator's MAC.
    let nas: String?
    let nasIP: String?
    let nasMAC: String?
    /// NAS-Port-Id / NAS-Port.
    let port: String?
    let ssid: String?
    let vlan: String?
    let role: String?
    /// Framed-IP-Address or the DHCP address.
    let ip: String?
    let serverIP: String?
    let firstTime: Date
    let duration: Double
    let retries: Int
    /// Access-Request → answer, per answered request (seconds).
    let radiusRTTs: [Double]
    let events: [AuthEvent]
    let health: AuthHealth
    let reasons: [String]
    let notes: [String]
    let packetIDs: [Int]
    let hasRADIUS: Bool
    let hasClientSide: Bool
    let eapMethod: String?

    var lifelines: [AuthLifeline] {
        var out: [AuthLifeline] = []
        if hasClientSide || !hasRADIUS { out.append(.client) }
        out.append(.nas)
        if hasRADIUS { out.append(.server) }
        return out
    }

    var methodLabel: String {
        captive && method != .captive ? method.label + " + Captive" : method.label
    }

    /// "Corp-WiFi" / "Gi1/0/5" / the NAS.
    var nasAndPort: String {
        var parts: [String] = []
        if let nas { parts.append(nas) }
        if let ssid { parts.append(ssid) } else if let port { parts.append(port) }
        return parts.joined(separator: " · ")
    }

    var vlanRole: String {
        [vlan.map { "VLAN \($0)" }, role].compactMap { $0 }.joined(separator: " · ")
    }

    /// A switch port's own attempt: its requests went unanswered, no client is known.
    var isPortOnly: Bool { client.hasPrefix("port:") }

    var firstPacketID: Int { packetIDs.min() ?? 0 }
    var lastPacketID: Int { packetIDs.max() ?? 0 }

    var searchText: String {
        [client, user ?? "", nas ?? "", nasIP ?? "", nasMAC ?? "", port ?? "", ssid ?? "", methodLabel, result.label,
         result.detail ?? "", vlan ?? "", role ?? "", ip ?? "", serverIP ?? "", portalHost ?? "",
         reasons.joined(separator: " ")].joined(separator: "\n").lowercased()
    }
}

// MARK: - Building sessions

nonisolated enum AuthSessions {
    /// Idle time that ends an attempt (and the MAC → 802.1X window).
    static let idleSplit: Double = 60
    /// How long captive-portal steps (the user typing a password) may follow.
    static let captiveWindow: Double = 600
    /// Accepted but no DHCP after this: the VLAN may have no DHCP.
    static let dhcpGrace: Double = 10
    /// A conversation with no answer for this long before the capture ended has stopped.
    static let stallAfter: Double = 30
    /// A switch port's EAP-Request Identity unanswered this long: no supplicant there.
    static let supplicantWait: Double = 5

    /// The client of a port's own attempt (group-addressed requests nobody answered).
    static func portClient(_ authenticator: String) -> String { "port:" + authenticator }

    static func build(_ packets: [Packet]) -> [AuthSession] { build(packets) { false } }

    static func build(_ packets: [Packet], isCancelled: () -> Bool) -> [AuthSession] {
        var run = Run()
        var obs: [Obs] = []
        for (i, p) in packets.enumerated() {
            if i & 0x3FFF == 0, isCancelled() { return [] }
            guard let f = AuthDecoder.classify(p) else { continue }
            obs.append(Obs(index: i, time: p.timestamp.timeIntervalSince1970, frame: f))
            if case .dhcp(let type, let mac, let yi) = f, type == "ACK", let mac, let yi { run.ipToMAC[yi] = mac }
            if case .dhcp = f { run.sawDHCP = true }
        }
        guard !obs.isEmpty else { return [] }
        // Capture order is almost always time order; a merged capture is not.
        var sorted = true
        for k in 1..<obs.count where obs[k].time < obs[k - 1].time { sorted = false; break }
        if !sorted { obs.sort { ($0.time, $0.index) < ($1.time, $1.index) } }
        run.captureEnd = packets.map { $0.timestamp.timeIntervalSince1970 }.max() ?? obs.last!.time
        // Every client's EAP-Response by id, in time order: whether a group-addressed request
        // was also answered by another client (the same id on two ports) is known ahead.
        for o in obs {
            if case .eapol(let f) = o.frame, let eap = f.eap, eap.isResponse {
                run.responses[eap.id, default: []].append((o.time, packets[o.index].decoded.sourceMAC))
            }
        }
        for (n, o) in obs.enumerated() {
            if n & 0x3FFF == 0, isCancelled() { return [] }
            run.handle(o, packets[o.index])
        }
        run.finishPorts()
        var sessions: [AuthSession] = []
        for b in run.builders where b.hasAuthContent {
            sessions.append(b.finish(id: sessions.count + 1, run: run))
        }
        return sessions
    }

    struct Obs {
        let index: Int
        let time: Double
        let frame: AuthDecoder.Frame
    }

    // MARK: Per-packet state

    struct RadiusKey: Hashable {
        let nas: String
        let nasPort: UInt16
        let server: String
        let serverPort: UInt16
        let id: UInt8
    }

    struct PendingRadius {
        let builder: Int
        var authenticator: [UInt8]
        var first: Double
        var last: Double
        var transmissions: Int
        var answered: Bool
        var eventIndex: Int
        let isAccounting: Bool
    }

    struct PendingHTTP {
        let client: String
        let host: String?
        let method: String
        let path: String
        let isProbe: Bool
    }

    /// Everything one pass carries between packets.
    struct Run {
        var builders: [Builder] = []
        var current: [String: Int] = [:]
        var ipToMAC: [String: String] = [:]
        var sawDHCP = false
        var captureEnd: Double = 0
        var pendingRadius: [RadiusKey: PendingRadius] = [:]
        var pendingHTTP: [String: PendingHTTP] = [:]
        /// Supporting events (DHCP, probes) seen before any session of their client: a captive
        /// session created later takes the ones of the minute before it.
        var recent: [String: [Builder.Raw]] = [:]
        /// The builders bound to each authenticator MAC (a frame between the two, or a reply to
        /// its group-addressed request), newest last — a dictionary: a backwards scan of every
        /// builder per frame was quadratic (10,000 attempts took 7 s). A group-addressed EAP frame
        /// from the authenticator goes to the one of them whose exchange it continues (EAP ids).
        var bound: [String: [Int]] = [:]
        /// Clients that sent EAPOL to the PAE group address with no authenticator known yet, and
        /// when. On a wired port both sides may address every EAPOL frame to the group: the
        /// switch's frames then belong to the one client that is talking.
        var groupTalkers: [String: Double] = [:]
        /// Group-addressed EAP-Requests no client could be named for yet, per authenticator (a
        /// switch asking a port whose device has not said anything). The client whose
        /// EAP-Response carries the request's id takes it; what nobody answers is, at the end, an
        /// attempt of the port itself: "no supplicant answered".
        var portFrames: [String: [PortFrame]] = [:]
        /// Clients' EAP-Responses by EAP id, in time order (filled before the pass).
        var responses: [UInt8: [(time: Double, client: String)]] = [:]

        /// Another client than `client` answered EAP id `id` between `t0` and `t1`: a request of
        /// that id then could have been either's.
        func contested(_ id: UInt8, from t0: Double, to t1: Double, except client: String) -> Bool {
            guard let list = responses[id] else { return false }
            var lo = 0, hi = list.count
            while lo < hi { let mid = (lo + hi) / 2; if list[mid].time < t0 { lo = mid + 1 } else { hi = mid } }
            var k = lo
            while k < list.count, list[k].time <= t1 {
                if list[k].client != client { return true }
                k += 1
            }
            return false
        }

        struct PortFrame {
            let frame: AuthDecoder.EAPOLFrame
            let time: Double
            let packet: Int
            let eapID: UInt8
            let identity: Bool
        }

        // MARK: Attempt selection

        enum Trigger {
            case eapolStart, identity, eapOther, keyM1, keyOther
            case accessRequest(hasEAP: Bool)
            case captive
        }

        /// The builder for an auth packet of `client`, starting a new attempt when this one ends the last.
        /// `authenticator`: the AP / switch MAC of an EAPOL frame. Another one than the attempt's means
        /// the client roamed: EAP state belongs to one authenticator, so what follows is a new attempt
        /// (the abandoned exchange and the new one were one attempt, named after the second AP).
        mutating func builder(for client: String, _ trigger: Trigger, at t: Double, authenticator: String? = nil) -> Int {
            if let i = current[client] {
                var b = builders[i]
                let roamed = authenticator.map { a in b.nasMAC.map { $0 != a } ?? false } ?? false
                var split = roamed || t - b.last > AuthSessions.idleSplit
                if !split {
                    switch trigger {
                    case .eapolStart:
                        split = (b.eapExchanged || b.isFinal || b.keySeen) && !b.macOnly
                    case .identity:
                        split = b.isFinal && !b.macOnly
                    case .keyM1:
                        split = b.m4 > 0 || b.eapFailed || b.radiusRejected
                    case .accessRequest(let hasEAP):
                        split = b.isFinal && !(b.macOnly && hasEAP)
                    case .captive:
                        split = false
                    case .eapOther, .keyOther:
                        split = false
                    }
                } else if case .captive = trigger, t - b.last <= AuthSessions.captiveWindow {
                    split = false
                }
                if !split {
                    // MAC auth, then 802.1X: keep the MAC stage's outcome, clear the finals.
                    if b.macOnly, b.macStage == nil {
                        switch trigger {
                        case .eapolStart, .identity, .eapOther, .accessRequest(hasEAP: true):
                            b.enterDot1xAfterMAC()
                            builders[i] = b
                        default: break
                        }
                    }
                    return i
                }
            }
            builders.append(Builder(client: client, first: t))
            current[client] = builders.count - 1
            return builders.count - 1
        }

        /// The current attempt of `client` for a supporting packet (DHCP, DNS, HTTP), when one is near.
        func supporting(_ client: String, at t: Double) -> Int? {
            guard let i = current[client] else { return nil }
            let b = builders[i]
            let window = b.captive ? AuthSessions.captiveWindow : AuthSessions.idleSplit
            return t - b.last <= window ? i : nil
        }

        mutating func remember(_ client: String, _ raw: Builder.Raw) {
            var list = recent[client] ?? []
            list.removeAll { raw.time - $0.time > AuthSessions.idleSplit }
            list.append(raw)
            if list.count > 32 { list.removeFirst(list.count - 32) }
            recent[client] = list
        }

        // MARK: Packets

        mutating func handle(_ o: Obs, _ p: Packet) {
            switch o.frame {
            case .eapol(let f): eapol(f, o, p)
            case .radius(let r): radius(r, o, p)
            case .dhcp(let type, let mac, let yi): dhcp(type, mac, yi, o, p)
            case .dns(let q, let isResponse, let answers, let rcode): dns(q, isResponse, answers, rcode, o, p)
            case .httpRequest(let method, let host, let path): httpRequest(method, host, path, o, p)
            case .httpResponse(let status, let location, let body): httpResponse(status, location, body, o, p)
            case .tlsHello(let sni): tlsHello(sni, o, p)
            }
        }

        static let paeGroup: Set<String> = ["01:80:c2:00:00:03", "01:80:c2:00:00:0e", "01:80:c2:00:00:00", "ff:ff:ff:ff:ff:ff"]

        /// A group (multicast / broadcast) MAC: never a client or an authenticator.
        static func isGroup(_ mac: String) -> Bool {
            paeGroup.contains(mac) || mac.hasPrefix("01:") || mac.hasPrefix("33:33")
        }

        mutating func eapol(_ f: AuthDecoder.EAPOLFrame, _ o: Obs, _ p: Packet) {
            let src = p.decoded.sourceMAC, dst = p.decoded.destinationMAC
            var fromAuthenticator = false
            if let eap = f.eap { fromAuthenticator = !eap.isResponse }
            else if let key = f.key {
                let m = key.message
                fromAuthenticator = m == .unknown ? key.ack : m.fromAuthenticator
            }
            var client = fromAuthenticator ? dst : src
            let authenticator = fromAuthenticator ? src : dst
            guard !client.isEmpty else { return }
            // A switch sends its EAP-Request Identity (on some ports every EAPOL frame) to the
            // PAE group address (01:80:c2:00:00:03). Whose it is follows from the replies: the
            // exchange it continues (by EAP id) among the clients bound to that authenticator,
            // the one client that asked for an exchange (EAPOL-Start), else it waits for the
            // client whose EAP-Response carries its id — and if nobody answers, it is the port's
            // own attempt ("no supplicant answered on port …").
            if Self.isGroup(client) {
                guard fromAuthenticator, !authenticator.isEmpty, !Self.isGroup(authenticator) else { return }
                switch groupTarget(f, from: authenticator, at: o.time) {
                case .client(let c): client = c
                case .port(let id, let identity):
                    portFrames[authenticator, default: []].append(
                        PortFrame(frame: f, time: o.time, packet: p.id, eapID: id, identity: identity))
                    return
                case .nobody: return
                }
            }
            // A reply to a request that waited for its client: the request joins the client's attempt first.
            if !fromAuthenticator, let eap = f.eap, eap.isResponse, !portFrames.isEmpty {
                adoptPortRequest(for: client, answering: eap.id,
                                 authenticator: Self.isGroup(authenticator) ? nil : authenticator, at: o.time)
            }
            let i = builder(for: client, Self.trigger(f), at: o.time, authenticator: Self.isGroup(authenticator) ? nil : authenticator)
            if !Self.isGroup(authenticator) {
                bind(i, to: authenticator, at: o.time)
            } else if !fromAuthenticator, builders[i].nasMAC == nil {
                if groupTalkers.count >= 64 { groupTalkers = groupTalkers.filter { o.time - $0.value <= AuthSessions.idleSplit } }
                groupTalkers[client] = o.time
            }
            builders[i].eapol(f, time: o.time, packet: p.id, fromAuthenticator: fromAuthenticator)
        }

        static func trigger(_ f: AuthDecoder.EAPOLFrame) -> Trigger {
            if f.typeRaw == 1 { return .eapolStart }
            if let eap = f.eap, eap.type == 1 { return .identity }
            if let key = f.key { return key.message == .m1 ? .keyM1 : .keyOther }
            return .eapOther
        }

        mutating func bind(_ i: Int, to authenticator: String, at t: Double) {
            builders[i].nasMAC = authenticator
            var list = bound[authenticator] ?? []
            if list.last != i, !list.contains(i) {
                if list.count >= 16 { list.removeAll { t - builders[$0].last > AuthSessions.idleSplit } }
                list.append(i)
            }
            bound[authenticator] = list
            groupTalkers[builders[i].client] = nil
        }

        enum GroupTarget {
            case client(String)
            /// Held for the client that answers it (EAP id), else the port's own attempt.
            case port(id: UInt8, identity: Bool)
            case nobody
        }

        /// Whose exchange a group-addressed frame from `authenticator` continues: among the
        /// clients bound to it and the clients talking to the group with no authenticator yet,
        /// the one whose exchange its EAP id continues. Never a guess between two clients: an id
        /// two exchanges could take is nobody's.
        func groupTarget(_ f: AuthDecoder.EAPOLFrame, from authenticator: String, at t: Double) -> GroupTarget {
            var pool = (bound[authenticator] ?? []).filter { i in
                builders[i].nasMAC == authenticator && t - builders[i].last <= AuthSessions.idleSplit
            }
            for (c, at) in groupTalkers where t - at <= AuthSessions.idleSplit {
                if let i = current[c], builders[i].nasMAC == nil, !pool.contains(i) { pool.append(i) }
            }
            func only(_ list: [Int]) -> GroupTarget? { list.count == 1 ? .client(builders[list[0]].client) : nil }
            // Without an EAP id to go by, only where no other client could own it.
            guard let eap = f.eap else { return only(pool) ?? .nobody }
            if eap.isRequest {
                let matches = pool.filter { builders[$0].awaits(request: eap.id, at: t) }
                if matches.count == 1, contested(eap.id, from: t, to: t + 1, except: builders[matches[0]].client) {
                    return eap.type == 1 ? .port(id: eap.id, identity: true) : .nobody
                }
                if let o = only(matches) { return o }
                if matches.count > 1 { return eap.type == 1 ? .port(id: eap.id, identity: true) : .nobody }
                if eap.type == 1 {
                    // A new exchange: the one client that asked for it with an EAPOL-Start.
                    if let o = only(pool.filter { builders[$0].startPending }) { return o }
                    return .port(id: eap.id, identity: true)
                }
                // No id matched (an authenticator with random ids): the one exchange there is.
                if let o = only(pool) { return o }
                return pool.isEmpty ? .port(id: eap.id, identity: false) : .nobody
            }
            // Success / Failure carry the id of the response they end.
            let exact = pool.filter { builders[$0].lastEAPResponseID == Int(eap.id) }
            if let o = only(exact) { return o }
            if exact.count > 1 { return .nobody }
            let next = pool.filter { builders[$0].lastEAPResponseID.map { UInt8(truncatingIfNeeded: $0 &+ 1) == eap.id } ?? false }
            if let o = only(next) { return o }
            if next.count > 1 { return .nobody }
            return only(pool) ?? .nobody
        }

        /// `client` answered EAP id `id`: the group-addressed request of that id waiting for its
        /// client (on `authenticator`, on the one the client is bound to, or — a reply to the
        /// group from a client not bound yet — on the one authenticator that has it) joins the
        /// client's attempt, with its retransmissions. When the reply could answer requests of
        /// two ports (the same id at the same moment), none is given to it: they are marked
        /// answered (no "no supplicant" attempt for them) and belong to nobody.
        mutating func adoptPortRequest(for client: String, answering id: UInt8, authenticator: String?, at t: Double) {
            func candidates(_ a: String) -> [Int] {
                guard let list = portFrames[a] else { return [] }
                return list.indices.filter { list[$0].eapID == id && list[$0].time <= t && t - list[$0].time <= AuthSessions.idleSplit }
            }
            var holders: [String]
            if let a = authenticator {
                holders = [a]
            } else if let i = current[client], let a = builders[i].nasMAC, t - builders[i].last <= AuthSessions.idleSplit {
                holders = [a]
            } else {
                holders = Array(portFrames.keys)
            }
            holders = holders.filter { !candidates($0).isEmpty }
            guard !holders.isEmpty else { return }
            // One holder, and its same-id sends form one retransmission chain (each ≥ 1 s after
            // the one before): the request this reply answers.
            if holders.count == 1, let a = holders.first, let list = portFrames[a] {
                let idx = candidates(a)
                let chain = zip(idx, idx.dropFirst()).allSatisfy { list[$1].time - list[$0].time >= 1 }
                if chain, !contested(id, from: list[idx[0]].time, to: t + 1, except: client) {
                    let frames = idx.map { list[$0] }
                    var rest = list
                    for k in idx.reversed() { rest.remove(at: k) }
                    portFrames[a] = rest.isEmpty ? nil : rest
                    for pf in frames {
                        let i = builder(for: client, Self.trigger(pf.frame), at: pf.time, authenticator: a)
                        bind(i, to: a, at: pf.time)
                        builders[i].first = min(builders[i].first, pf.time)
                        builders[i].eapol(pf.frame, time: pf.time, packet: pf.packet, fromAuthenticator: true)
                    }
                    return
                }
            }
            for a in holders {
                guard var list = portFrames[a] else { continue }
                for k in candidates(a).reversed() { list.remove(at: k) }
                portFrames[a] = list.isEmpty ? nil : list
            }
        }

        /// Requests nobody answered: one attempt per authenticator port and minute-long spell,
        /// when it asked for an identity ("no supplicant answered").
        mutating func finishPorts() {
            for a in portFrames.keys.sorted() {
                guard let list = portFrames[a]?.sorted(by: { $0.time < $1.time }) else { continue }
                var spell: [PortFrame] = []
                func flush() {
                    defer { spell = [] }
                    guard spell.contains(where: \.identity) else { return }
                    var b = Builder(client: AuthSessions.portClient(a), first: spell[0].time)
                    b.nasMAC = a
                    b.portOnly = true
                    // A client that talked on this port before: it stopped answering (gave up
                    // after a failure, or left) — not a port with no supplicant at all.
                    let t0 = spell[0].time
                    if let i = (bound[a] ?? []).filter({ builders[$0].last <= t0 && !builders[$0].portOnly })
                        .max(by: { builders[$0].last < builders[$1].last }) {
                        b.portLastClient = (builders[i].client, builders[i].last, builders[i].eapFailed || builders[i].radiusRejected)
                    }
                    for pf in spell { b.eapol(pf.frame, time: pf.time, packet: pf.packet, fromAuthenticator: true) }
                    builders.append(b)
                }
                for pf in list {
                    if let l = spell.last, pf.time - l.time > AuthSessions.idleSplit { flush() }
                    spell.append(pf)
                }
                flush()
            }
            portFrames = [:]
        }

        mutating func radius(_ r: AuthDecoder.RadiusPacket, _ o: Obs, _ p: Packet) {
            guard let ip = p.decoded.ip, let udp = p.decoded.udp else { return }
            guard r.code != 12, r.code != 13 else { return }   // Status-Server: no client
            let isRequest = [1, 4, 40, 43].contains(r.code)
            // CoA / Disconnect requests come from the server (dynamic authorization client) to
            // the NAS, their ACK / NAK back; everything else the other way round.
            let serverToNAS = r.code == 40 || r.code == 43
            let senderIsNAS = [1, 4, 41, 42, 44, 45].contains(r.code)
            let nasIP = senderIsNAS ? ip.source : ip.destination
            let nasPort = senderIsNAS ? udp.sourcePort : udp.destinationPort
            let serverIP = senderIsNAS ? ip.destination : ip.source
            let serverPort = senderIsNAS ? udp.destinationPort : udp.sourcePort
            let key = RadiusKey(nas: nasIP, nasPort: nasPort, server: serverIP, serverPort: serverPort, id: r.id)
            if isRequest {
                let client = Self.radiusClient(r, p)
                if var pending = pendingRadius[key], pending.authenticator == r.authenticator,
                   o.time - pending.last < AuthSessions.idleSplit {
                    // A retransmission of a request already seen.
                    pending.transmissions += 1
                    pending.last = o.time
                    pendingRadius[key] = pending
                    builders[pending.builder].radiusRetransmission(pending, r, time: o.time, packet: p.id)
                    return
                }
                let isAccounting = r.code == 4
                let i: Int
                if isAccounting || serverToNAS {
                    guard let c = client, let found = current[c],
                          o.time - builders[found].last <= AuthSessions.captiveWindow else { return }
                    i = found
                } else {
                    guard let c = client else { return }
                    i = builder(for: c, .accessRequest(hasEAP: r.hasEAP), at: o.time)
                }
                let event = builders[i].radius(r, time: o.time, packet: p.id, nasIP: nasIP, serverIP: serverIP,
                                               fromServer: serverToNAS, isRequest: true, rtt: nil)
                pendingRadius[key] = PendingRadius(builder: i, authenticator: r.authenticator, first: o.time, last: o.time,
                                                   transmissions: 1, answered: false, eventIndex: event,
                                                   isAccounting: isAccounting)
            } else {
                guard var pending = pendingRadius[key] else { return }
                let rtt = pending.answered ? nil : o.time - pending.last
                pending.answered = true
                pendingRadius[key] = pending
                let i = pending.builder
                _ = builders[i].radius(r, time: o.time, packet: p.id, nasIP: nasIP, serverIP: serverIP,
                                       fromServer: !senderIsNAS, isRequest: false, rtt: rtt)
                builders[i].answered(pending)
            }
        }

        /// Calling-Station-Id (any MAC spelling), a MAC User-Name, the User-Name, or the frame's source MAC.
        static func radiusClient(_ r: AuthDecoder.RadiusPacket, _ p: Packet) -> String? {
            if let c = r.callingStationId, let mac = AuthDecoder.macPrefix(c)?.mac { return mac }
            if let u = r.userName, let mac = AuthDecoder.normalisedMAC(u) { return mac }
            if let u = r.userName, !u.isEmpty { return "user:\(u)" }
            return p.decoded.sourceMAC.isEmpty ? nil : p.decoded.sourceMAC
        }

        mutating func dhcp(_ type: String, _ mac: String?, _ yi: String?, _ o: Obs, _ p: Packet) {
            guard let client = mac ?? (p.decoded.sourceMAC.isEmpty ? nil : p.decoded.sourceMAC) else { return }
            let fromClient = ["Discover", "Request", "Decline", "Release", "Inform", "BOOTP Request"].contains(type)
            let label = "DHCP \(type)" + (yi.map { " \($0)" } ?? "")
            let raw = Builder.Raw(time: o.time, kind: .dhcp, from: fromClient ? .client : .nas, to: fromClient ? .nas : .client,
                                  label: label, detail: nil, packets: [p.id])
            if let i = supporting(client, at: o.time) {
                builders[i].dhcp(type, yi, raw)
            } else {
                remember(client, raw)
            }
        }

        mutating func dns(_ q: String?, _ isResponse: Bool, _ answers: Int, _ rcode: Int, _ o: Obs, _ p: Packet) {
            guard isResponse, rcode == 0, answers > 0, let ip = p.decoded.ip else { return }
            let client = ipToMAC[ip.destination] ?? p.decoded.destinationMAC
            guard let i = supporting(client, at: o.time), !builders[i].dnsOK else { return }
            let raw = Builder.Raw(time: o.time, kind: .dns, from: .nas, to: .client,
                                  label: "DNS answer" + (q.map { " \($0)" } ?? "") + " — network usable",
                                  detail: nil, packets: [p.id])
            builders[i].dnsOK = true
            builders[i].add(raw)
        }

        static func flowKey(_ p: Packet, reversed: Bool) -> String? {
            guard let ip = p.decoded.ip, let tcp = p.decoded.tcp else { return nil }
            return reversed ? "\(ip.destination):\(tcp.destinationPort)-\(ip.source):\(tcp.sourcePort)"
                            : "\(ip.source):\(tcp.sourcePort)-\(ip.destination):\(tcp.destinationPort)"
        }

        mutating func httpRequest(_ method: String, _ host: String?, _ path: String, _ o: Obs, _ p: Packet) {
            guard let ip = p.decoded.ip, let key = Self.flowKey(p, reversed: false) else { return }
            let client = ipToMAC[ip.source] ?? p.decoded.sourceMAC
            let bare = host.map(AuthDecoder.bareHost)
            let probe = AuthDecoder.isProbeHost(host)
            let i = supporting(client, at: o.time)
            let portal = i.flatMap { builders[$0].portalHost }
            let toPortal = bare != nil && bare == portal
            guard probe || toPortal else { return }
            if pendingHTTP.count > 4096 { pendingHTTP.removeAll() }
            pendingHTTP[key] = PendingHTTP(client: client, host: bare, method: method, path: path, isProbe: probe)
            let shortPath = path.count > 40 ? String(path.prefix(40)) + "…" : path
            if toPortal, let i {
                let isPost = method == "POST"
                let raw = Builder.Raw(time: o.time, kind: .captiveLogin, from: .client, to: .nas,
                                      label: "HTTP \(method) \(bare ?? "")\(shortPath)" + (isPost ? " — portal login" : ""),
                                      detail: nil, packets: [p.id])
                if isPost { builders[i].captiveLogin = true; builders[i].add(raw) }
                else if !builders[i].portalPageSeen { builders[i].portalPageSeen = true; builders[i].add(raw) }
                return
            }
            let raw = Builder.Raw(time: o.time, kind: .captiveProbe, from: .client, to: .nas,
                                  label: "HTTP \(method) \(bare ?? "")\(shortPath) — portal check", detail: nil, packets: [p.id])
            if let i {
                // One probe row per session (they repeat every few seconds while a portal is up).
                if builders[i].probeRows < 2 { builders[i].probeRows += 1; builders[i].add(raw) }
            } else {
                remember(client, raw)
            }
        }

        mutating func httpResponse(_ status: Int, _ location: String?, _ body: [UInt8]?, _ o: Obs, _ p: Packet) {
            guard let key = Self.flowKey(p, reversed: true), let req = pendingHTTP.removeValue(forKey: key) else { return }
            let client = req.client
            let locationHost = location.flatMap(AuthDecoder.urlHost)
            if (300...399).contains(status), let lh = locationHost, let i = supporting(client, at: o.time),
               let portal = builders[i].portalHost, req.host == portal {
                builders[i].add(Builder.Raw(time: o.time, kind: .captiveLogin, from: .nas, to: .client,
                                            label: "HTTP \(status) → \(lh) (portal, after login)", detail: location, packets: [p.id]))
                return
            }
            if (300...399).contains(status), let lh = locationHost, lh != req.host || req.isProbe {
                let i = builder(for: client, .captive, at: o.time)
                builders[i].pullRecent(recent.removeValue(forKey: client) ?? [], before: o.time)
                builders[i].captiveRedirect(to: lh, raw: Builder.Raw(
                    time: o.time, kind: .captiveRedirect, from: .nas, to: .client,
                    label: "HTTP \(status) → \(lh) (captive portal)", detail: location, packets: [p.id]))
                return
            }
            guard req.isProbe else { return }
            let ok = status == 204 || (status == 200 && (body.map { $0.isEmpty || AuthDecoder.isProbeSuccessBody($0) } ?? true))
            if !ok, status == 200 {
                // The portal answered the probe itself with its login page.
                let i = builder(for: client, .captive, at: o.time)
                builders[i].pullRecent(recent.removeValue(forKey: client) ?? [], before: o.time)
                builders[i].captiveRedirect(to: req.host ?? "portal", raw: Builder.Raw(
                    time: o.time, kind: .captivePortalPage, from: .nas, to: .client,
                    label: "HTTP 200 from \(req.host ?? "probe") is a portal page, not the probe answer",
                    detail: nil, packets: [p.id]), intercepted: true)
                return
            }
            guard ok, let i = supporting(client, at: o.time) else { return }
            if builders[i].captive, !builders[i].captivePassed {
                builders[i].captivePassed = true
                builders[i].add(Builder.Raw(time: o.time, kind: .captivePassed, from: .nas, to: .client,
                                            label: "HTTP \(status) from \(req.host ?? "probe") — portal passed, internet reachable",
                                            detail: nil, packets: [p.id]))
            } else if !builders[i].captive, !builders[i].probeOK {
                builders[i].probeOK = true
                builders[i].add(Builder.Raw(time: o.time, kind: .captivePassed, from: .nas, to: .client,
                                            label: "HTTP \(status) from \(req.host ?? "probe") — internet reachable",
                                            detail: nil, packets: [p.id]))
            }
        }

        mutating func tlsHello(_ sni: String, _ o: Obs, _ p: Packet) {
            guard let ip = p.decoded.ip else { return }
            let client = ipToMAC[ip.source] ?? p.decoded.sourceMAC
            guard let i = supporting(client, at: o.time), let portal = builders[i].portalHost,
                  AuthDecoder.bareHost(sni) == portal, !builders[i].portalTLS else { return }
            builders[i].portalTLS = true
            builders[i].add(Builder.Raw(time: o.time, kind: .captiveLogin, from: .client, to: .nas,
                                        label: "HTTPS to \(portal) — portal login page (encrypted)", detail: nil, packets: [p.id]))
        }
    }

    // MARK: One attempt

    struct Builder {
        struct Raw {
            var time: Double
            var kind: AuthEvent.Kind
            var from: AuthLifeline
            var to: AuthLifeline
            var label: String
            var detail: String?
            var problem: String? = nil
            var packets: [Int]
            /// Part of a TLS exchange (PEAP / EAP-TLS / TTLS / FAST, not its start).
            var tlsRound = false
            var clientResponse = false
            /// Seconds since the session start of the row's last packet (set by `events`).
            var endTime: Double? = nil
            /// When the last retransmission joined to the row arrived (absolute: rows pulled in
            /// front later move the session start).
            var endAt: Double? = nil
        }

        let client: String
        var first: Double
        var last: Double
        var raws: [Raw] = []

        // 802.1X
        var starts = 0
        var eapRequestsUnanswered = 0
        var lastEAPRequestID: Int?
        var eapResponses = 0
        var eapTypes: [UInt8] = []
        var identity: String?
        var eapSucceeded = false
        var eapFailed = false
        var eapRequestRetries = 0
        var nasMAC: String?
        /// The id of the client's last EAP-Response, and whether the exchange waits for the
        /// authenticator's next request (the last EAP frame was that response).
        var lastEAPResponseID: Int?
        var awaitingRequest = false
        var lastEAPRequestAt: Double = 0
        /// The client sent an EAPOL-Start that no request has answered yet.
        var startPending = false
        /// No client is known: group-addressed requests of a switch port nobody answered.
        var portOnly = false
        /// The client last seen on that port before (when it had failed).
        var portLastClient: (client: String, last: Double, failed: Bool)?
        // 4-way
        var m1 = 0, m2 = 0, m3 = 0, m4 = 0
        var group = 0
        // RADIUS
        var radiusSeen = false
        var userName: String?
        var macAuthRequest = false
        var accessRequestWithEAP = false
        var radiusAccepted = false
        var radiusRejected = false
        var replyMessage: String?
        var acceptTime: Double?
        var nasIdentifier: String?
        var nasIPAddress: String?
        var nasSourceIP: String?
        var nasPortId: String?
        var nasPort: String?
        var ssid: String?
        var vlan: String?
        var role: String?
        var framedIP: String?
        var serverIP: String?
        var rtts: [Double] = []
        var radiusRetries = 0
        var unansweredTransmissions = 0
        var hasPassword = false
        // MAC → 802.1X
        var macStage: AuthResult?
        // Network evidence
        var dhcpDiscovers = 0, dhcpOffers = 0, dhcpAcks = 0, dhcpNaks = 0
        var dhcpIP: String?
        var firstDHCP: Double?
        var dnsOK = false
        var probeOK = false
        var probeRows = 0
        // Captive portal
        var captive = false
        var portalHost: String?
        var captiveLogin = false
        var captivePassed = false
        var portalPageSeen = false
        var portalTLS = false
        var intercepted = false

        init(client: String, first: Double) {
            self.client = client
            self.first = first
            self.last = first
        }

        /// A group-addressed EAP-Request with this id continues this exchange: the next one after
        /// the client's response, or a retransmission of the one it has not answered.
        /// (A retransmission comes a retransmission timer later, ≥ 1 s: the same id a moment
        /// after is another port's request.)
        func awaits(request id: UInt8, at t: Double) -> Bool {
            if awaitingRequest, let r = lastEAPResponseID, UInt8(truncatingIfNeeded: r &+ 1) == id { return true }
            return eapRequestsUnanswered > 0 && lastEAPRequestID == Int(id) && t - lastEAPRequestAt >= 1
        }

        var eapExchanged: Bool { eapResponses > 0 || !eapTypes.isEmpty || eapSucceeded || eapFailed || lastEAPRequestID != nil }
        var keySeen: Bool { m1 + m2 + m3 + m4 + group > 0 }
        var isFinal: Bool { eapSucceeded || eapFailed || radiusAccepted || radiusRejected }
        /// A MAC-auth attempt with no EAP (yet).
        var macOnly: Bool { macAuthRequest && !accessRequestWithEAP && !eapExchanged && starts == 0 && macStage == nil }
        var hasAuthContent: Bool { !raws.isEmpty && (radiusSeen || starts > 0 || eapExchanged || keySeen || captive) }

        mutating func add(_ r: Raw) {
            raws.append(r)
            last = max(last, r.time)
        }

        mutating func enterDot1xAfterMAC() {
            macStage = radiusAccepted ? .accepted : radiusRejected ? .rejected(replyMessage ?? "Access-Reject") : .inProgress
            radiusAccepted = false
            radiusRejected = false
            replyMessage = nil
            acceptTime = nil
        }

        /// Supporting rows of the minute before a captive portal showed up (the DHCP, the first probes).
        mutating func pullRecent(_ list: [Raw], before t: Double) {
            let taken = list.filter { t - $0.time <= AuthSessions.idleSplit && $0.time <= t }
            guard !taken.isEmpty else { return }
            for r in taken {
                if r.kind == .dhcp {
                    countDHCP(r.label, nil)
                    if firstDHCP == nil { firstDHCP = r.time }
                }
                if r.kind == .captiveProbe { probeRows += 1 }
                raws.append(r)
                first = min(first, r.time)
            }
            // Not sorted here: a pending Access-Request keeps its row by index (a retransmission
            // joined the DHCP Discover pulled in front of it). `finish` orders the rows by time.
        }

        // MARK: EAPOL

        mutating func eapol(_ f: AuthDecoder.EAPOLFrame, time t: Double, packet: Int, fromAuthenticator: Bool) {
            let from: AuthLifeline = fromAuthenticator ? .nas : .client
            let to: AuthLifeline = fromAuthenticator ? .client : .nas
            if let eap = f.eap {
                var raw = Raw(time: t, kind: .eapol, from: from, to: to, label: eap.summary, detail: nil, packets: [packet])
                if eap.isRequest {
                    raw.kind = .eapRequest
                    if lastEAPRequestID == Int(eap.id), eapRequestsUnanswered > 0 { eapRequestRetries += 1 }
                    lastEAPRequestID = Int(eap.id)
                    lastEAPRequestAt = t
                    eapRequestsUnanswered += 1
                    awaitingRequest = false
                    startPending = false
                } else if eap.isResponse {
                    raw.kind = .eapResponse
                    raw.clientResponse = true
                    eapResponses += 1
                    eapRequestsUnanswered = 0
                    lastEAPResponseID = Int(eap.id)
                    awaitingRequest = true
                    if let id = eap.identity, eap.type == 1, !id.isEmpty { identity = id }
                } else if eap.isSuccess {
                    raw.kind = .eapSuccess
                    eapSucceeded = true
                    eapFailed = false
                } else if eap.isFailure {
                    raw.kind = .eapFailure
                    eapFailed = true
                    eapSucceeded = false
                    raw.problem = "EAP-Failure"
                }
                if eap.isSuccess || eap.isFailure { awaitingRequest = false; startPending = false }
                noteMethod(eap)
                if let type = eap.type, AuthDecoder.isTLSMethod(type), eap.tls?.start != true { raw.tlsRound = true }
                add(raw)
                return
            }
            if let key = f.key {
                let m = key.message
                var label = "EAPOL-Key \(m.label)"
                var kind = AuthEvent.Kind.key(m.number)
                switch m {
                case .m1: m1 += 1; label += " (ANonce)"
                case .m2: m2 += 1; label += " (SNonce, MIC)"
                case .m3: m3 += 1; label += " (install, GTK)"
                case .m4: m4 += 1
                case .group1, .group2: group += 1; kind = .key(0)
                case .requestFailure: kind = .key(0)
                case .unknown: label = "EAPOL-Key (\(key.descriptorName))"; kind = .key(0)
                }
                var raw = Raw(time: t, kind: kind, from: from, to: to, label: label, detail: nil, packets: [packet])
                if m == .requestFailure { raw.problem = "MIC failure reported by the client" }
                add(raw)
                return
            }
            var raw = Raw(time: t, kind: .eapol, from: from, to: to, label: f.summary, detail: nil, packets: [packet])
            if f.typeRaw == 1 { starts += 1; startPending = true; awaitingRequest = false }
            if f.typeRaw == 2 { raw.detail = "the client ended its 802.1X session" }
            add(raw)
        }

        mutating func noteMethod(_ eap: AuthDecoder.EAPPacket) {
            guard let t = eap.type, t != 1, t != 2, t != 3 else { return }
            if eap.isRequest || !eapTypes.contains(t) {
                eapTypes.removeAll { $0 == t }
                eapTypes.append(t)
            }
        }

        /// PEAP, EAP-TLS, "PEAP/MSCHAPv2" (inner method visible), nil when only the identity was seen.
        var eapMethodName: String? {
            let outer = eapTypes.last { AuthDecoder.isTLSMethod($0) }
            if let outer {
                let name = AuthDecoder.eapTypeName(outer)
                if outer != 13, eapTypes.contains(26) { return name + "/MSCHAPv2" }
                if outer != 13, eapTypes.contains(6) { return name + "/GTC" }
                return name
            }
            if let t = eapTypes.last {
                if t == 254 { return "WPS" }
                return AuthDecoder.eapTypeName(t)
            }
            return nil
        }

        // MARK: RADIUS

        /// Adds the RADIUS row; returns its index (for retransmissions).
        mutating func radius(_ r: AuthDecoder.RadiusPacket, time t: Double, packet: Int, nasIP: String, serverIP s: String,
                             fromServer: Bool, isRequest: Bool, rtt: Double?) -> Int {
            radiusSeen = true
            let from: AuthLifeline = fromServer ? .server : .nas
            let to: AuthLifeline = fromServer ? .nas : .server
            var kind: AuthEvent.Kind
            var label = r.codeName
            var details: [String] = []
            let inner = r.eap.map { " (\($0.summary))" } ?? ""
            switch r.code {
            case 1:
                kind = .radiusRequest
                serverIP = s
                nasSourceIP = nasIP
                if let u = r.userName { userName = u }
                if r.hasEAP { accessRequestWithEAP = true }
                if !r.hasEAP, let u = r.userName, let mac = AuthDecoder.normalisedMAC(u),
                   mac == client || AuthDecoder.macPrefix(r.callingStationId ?? "")?.mac == mac || client.hasPrefix("user:") {
                    macAuthRequest = true
                }
                if r.hasPassword { hasPassword = true }
                if let v = r.nasIdentifier { nasIdentifier = v }
                if let v = r.nasIPAddress { nasIPAddress = v }
                if let v = r.nasPortId { nasPortId = v }
                if let v = r.string(5) { nasPort = v }
                if let v = r.ssid { ssid = v }
                label += " id=\(r.id)" + inner
                if !r.hasEAP, let u = r.userName {
                    label += " · User-Name \(AuthDecoder.normalisedMAC(u) ?? u)"
                    if r.hasPassword { details.append("User-Password (present)") }
                }
                if let c = r.callingStationId { details.append("Calling-Station-Id \(c)") }
                if r.hasEAP, let u = r.userName { details.insert("User-Name \(u)", at: 0) }
                if let v = r.nasPortId ?? r.string(5).map({ "NAS-Port \($0)" }) { details.append(v.hasPrefix("NAS-Port") ? v : "NAS-Port-Id \(v)") }
                if let v = r.ssid { details.append("SSID \(v)") }
                if r.eapFragments > 1 { details.append("EAP-Message in \(r.eapFragments) attributes") }
            case 2:
                kind = .radiusAccept
                radiusAccepted = true
                radiusRejected = false
                acceptTime = t
                if let v = r.vlan { vlan = v }
                if let v = r.role { role = v }
                if let v = r.framedIP { framedIP = v }
                label += inner
                if let v = r.vlan { label += " · VLAN \(v)" }
                if let v = r.role { label += " · role \(v)" }
                if let v = r.string(27) { details.append("Session-Timeout \(v) s") }
                for a in r.attributes where a.vendor != nil { details.append("\(a.name) \(a.display)") }
            case 3:
                kind = .radiusReject
                radiusRejected = true
                radiusAccepted = false
                replyMessage = r.replyMessage
                label += inner
                if let m = r.replyMessage { label += " · \"\(m)\"" }
            case 11:
                kind = .radiusChallenge
                label += " id=\(r.id)" + inner
            case 4:
                kind = .accounting
                if let v = r.framedIP { framedIP = v }
                label = "Accounting-Request" + (r.acctStatus.map { " \($0)" } ?? "")
                if let v = r.framedIP { label += " · IP \(v)" }
                if let v = r.string(49) { details.append("Acct-Terminate-Cause \(v)") }
                if let v = r.string(44) { details.append("Acct-Session-Id \(v)") }
            case 5:
                kind = .accounting
            default:
                kind = .coa
                if let m = r.replyMessage { label += " · \(m)" }
            }
            var raw = Raw(time: t, kind: kind, from: from, to: to, label: label,
                          detail: details.isEmpty ? nil : details.joined(separator: " · "), packets: [packet])
            if let eap = r.eap {
                if let type = eap.type, AuthDecoder.isTLSMethod(type), eap.tls?.start != true, r.code == 1 || r.code == 11 {
                    raw.tlsRound = true
                    raw.clientResponse = r.code == 1 && eap.isResponse
                }
                if eap.isResponse, eap.type == 1, let id = eap.identity, !id.isEmpty, identity == nil { identity = id }
                noteMethod(eap)
                if eap.isSuccess { eapSucceeded = true }
                if eap.isFailure { eapFailed = true }
            }
            if let rtt {
                if kind == .radiusAccept || kind == .radiusReject || kind == .radiusChallenge { rtts.append(rtt) }
                raw.label += " · \(AuthSessions.msText(rtt))"
            }
            if kind == .radiusReject { raw.problem = "Access-Reject" }
            add(raw)
            return raws.count - 1
        }

        mutating func radiusRetransmission(_ pending: PendingRadius, _ r: AuthDecoder.RadiusPacket, time t: Double, packet: Int) {
            radiusRetries += 1
            guard pending.eventIndex < raws.count else { return }
            // The retransmission joins its request's row (drawn "×n").
            raws[pending.eventIndex].packets.append(packet)
            raws[pending.eventIndex].endAt = t
            if !pending.answered {
                unansweredTransmissions = max(unansweredTransmissions, pending.transmissions)
                raws[pending.eventIndex].problem = "no answer (\(pending.transmissions) transmissions)"
            }
            last = max(last, t)
        }

        mutating func answered(_ pending: PendingRadius) {
            guard pending.eventIndex < raws.count else { return }
            if pending.transmissions > 1 {
                raws[pending.eventIndex].problem = nil
                raws[pending.eventIndex].detail = [raws[pending.eventIndex].detail, "answered after \(pending.transmissions - 1) retr\(pending.transmissions == 2 ? "y" : "ies")"]
                    .compactMap { $0 }.joined(separator: " · ")
            }
            if unansweredTransmissions == pending.transmissions { unansweredTransmissions = 0 }
        }

        // MARK: Network evidence

        mutating func countDHCP(_ label: String, _ yi: String?) {
            if label.hasPrefix("DHCP Discover") { dhcpDiscovers += 1 }
            if label.hasPrefix("DHCP Offer") { dhcpOffers += 1 }
            if label.hasPrefix("DHCP ACK") { dhcpAcks += 1 }
            if label.hasPrefix("DHCP NAK") { dhcpNaks += 1 }
        }

        mutating func dhcp(_ type: String, _ yi: String?, _ raw: Raw) {
            countDHCP(raw.label, yi)
            if firstDHCP == nil { firstDHCP = raw.time }
            if type == "ACK", let yi { dhcpIP = yi }
            var r = raw
            if type == "NAK" { r.problem = "DHCP NAK" }
            add(r)
        }

        mutating func captiveRedirect(to host: String, raw: Raw, intercepted i: Bool = false) {
            if !captive || portalHost == nil { portalHost = host }
            captive = true
            if i { intercepted = true }
            add(raw)
        }

        // MARK: Finish

        func finish(id: Int, run: Run) -> AuthSession {
            let end = run.captureEnd
            let method: AuthMethod
            let eapName = eapMethodName
            // The client spoke 802.1X (a Start, a Response, or EAP inside RADIUS). Requests alone
            // followed by MAC auth are the switch's dot1x → MAB fallback: MAC auth.
            let clientDidEAP = eapResponses > 0 || accessRequestWithEAP || starts > 0 || eapSucceeded || eapFailed
            let dot1x = clientDidEAP || (eapExchanged && !macAuthRequest)
            if macStage != nil { method = .macThenDot1x(eapName ?? "802.1X") }
            else if dot1x { method = .dot1x(eapName ?? "802.1X") }
            else if macAuthRequest { method = .macAuth }
            else if keySeen { method = .psk }
            else if captive { method = .captive }
            else { method = .unknown }

            var reasons: [String] = []
            var notes: [String] = []
            var health = AuthHealth.ok
            func bad(_ s: String) { reasons.append(s); health = .bad }
            func warn(_ s: String) { reasons.append(s); if health == .ok { health = .warn } }

            // In time order (rows pulled in front of a captive session were appended; capture order within a time).
            let ordered = raws.enumerated().sorted { ($0.element.time, $0.offset) < ($1.element.time, $1.offset) }.map {
                var r = $0.element
                if let end = r.endAt { r.endTime = end - first }
                return r
            }
            let lastRaw = ordered.last
            let silentFor = end - last
            let server = serverIP ?? "the RADIUS server"
            let methodName = eapName ?? "802.1X"
            let reply = replyMessage.map { " — server said: \"\($0)\"" } ?? ""

            var result: AuthResult
            let fourWayComplete = m4 > 0
            if portOnly {
                let port = nasMAC ?? "?"
                let asked = raws.filter { $0.kind == .eapRequest }.count
                if asked >= 2 || silentFor >= AuthSessions.supplicantWait {
                    result = .timeout("no supplicant answered on port \(port)")
                    let unanswered = "No 802.1X supplicant answered on switch port \(port): \(asked == 1 ? "its EAP-Request Identity" : "\(asked) EAP-Request Identity") went unanswered."
                    if let c = portLastClient {
                        warn(unanswered + " \(c.client) was on this port until \(AuthSessions.msText(first - c.last)) earlier (\(c.failed ? "its authentication failed" : "it authenticated")) "
                             + "and has stopped answering — \(c.failed ? "a supplicant gives up after failures until it is reconnected" : "it left, or its supplicant was turned off").")
                    } else {
                        warn(unanswered + " The device there has 802.1X turned off or no supplicant at all (a printer, phone or camera); with MAC auth bypass (MAB) the switch lets it in by its MAC instead.")
                    }
                } else {
                    result = .inProgress
                    notes.append("The switch asked port \(port) for an identity; nothing had answered when the capture ended.")
                }
            } else if eapFailed || radiusRejected {
                result = .rejected(replyMessage ?? (eapFailed ? "EAP-Failure" : "Access-Reject"))
                if method == .macAuth || (macStage == nil && macAuthRequest && !dot1x) {
                    bad("MAC auth rejected: \(client) is not an allowed endpoint on the RADIUS server\(reply)")
                } else if eapName == nil {
                    bad("\(eapFailed ? "EAP-Failure" : "Access-Reject") right after the identity: user unknown, or no policy matched\(reply)")
                } else if eapName == "EAP-TLS" {
                    bad("EAP-Failure after EAP-TLS: client certificate rejected (expired, revoked, wrong CA) or the client does not trust the server certificate\(reply)")
                } else if eapFailed {
                    bad("EAP-Failure after \(methodName): wrong password or certificate not trusted\(reply)")
                } else {
                    bad("RADIUS Access-Reject after \(methodName)\(reply)")
                }
            } else if eapSucceeded || radiusAccepted {
                result = .accepted
                if keySeen && !fourWayComplete && m1 > 0 {
                    bad("\(methodName) accepted, but the 4-way handshake stopped after message \(m3 > 0 ? "3/4" : m2 > 0 ? "2/4" : "1/4"): the client and AP disagree on the key (PMK)")
                }
            } else if fourWayComplete {
                result = .accepted
            } else if m2 > 0 && m3 == 0 && (m1 >= 2 || silentFor >= 5) {
                result = .rejected("wrong PSK")
                bad("4-way handshake stopped after message 2/4: the AP did not accept the client's key — wrong PSK (passphrase)")
            } else if m1 > 0 && m2 == 0 && (m1 >= 3 || silentFor >= 5) {
                result = .timeout("no 2/4 after \(m1)× 1/4")
                bad("4-way handshake stopped after message 1/4 (\(m1)× 1/4, no 2/4): wrong PSK on the client, or the client left")
            } else if unansweredTransmissions >= 3 || (unansweredTransmissions >= 1 && silentFor >= AuthSessions.stallAfter && !hasClientSide) {
                result = .timeout("RADIUS server did not answer")
                bad("RADIUS server \(server) did not answer \(unansweredTransmissions) request\(unansweredTransmissions == 1 ? "" : "s"): server down, firewall, or the NAS is not a client there (shared secret)")
            } else if starts >= 3 && !eapExchanged {
                result = .timeout("no answer to EAPOL-Start")
                bad("The switch / AP did not answer \(starts) EAPOL-Starts: 802.1X is not enabled on this port or SSID")
            } else if eapRequestRetries >= 2 && eapResponses == 0 {
                result = .timeout("client did not answer")
                bad("The client did not answer \(eapRequestRetries + 1) EAP-Requests: no 802.1X supplicant, or it is not set up for this network")
            } else if captive && captivePassed {
                result = .accepted
            } else if !captive, let lastRaw, silentFor >= AuthSessions.stallAfter, !(macStage == .accepted) {
                result = .timeout("stopped")
                bad("Stopped after \(lastRaw.label): no answer for \(Int(silentFor)) s")
            } else {
                result = .inProgress
                if captive { notes.append("Waiting at the captive portal when the capture ended.") }
                else { notes.append("Still in progress when the capture ended.") }
            }
            if let macStage, case .rejected = macStage {
                notes.append("MAC auth was rejected first; the client then used 802.1X.")
            } else if macStage == .accepted {
                notes.append("MAC auth was accepted first; the client then used 802.1X.")
            }

            // Warnings on an otherwise good attempt.
            let retries = radiusRetries + max(0, starts - 1) + max(0, m1 - 1) + eapRequestRetries
            if health == .ok {
                if radiusRetries > 0 { warn("RADIUS answered only after \(radiusRetries) retr\(radiusRetries == 1 ? "y" : "ies")") }
                if let slow = rtts.max(), slow > 1 { warn("Slow RADIUS: an answer took \(AuthSessions.msText(slow))") }
                if m1 > 1 && fourWayComplete { warn("4-way handshake needed \(m1)× message 1/4") }
            }
            let accepted = result == .accepted
            let clientSide = hasClientSide
            if accepted, captive, !captivePassed {
                warn("Captive portal redirect to \(portalHost ?? "the portal") not completed")
            }
            if accepted, let acceptAt = acceptTime ?? (fourWayComplete ? ordered.last(where: { $0.kind == .key(4) })?.time : nil) {
                let vlanText = vlan.map { "VLAN \($0)" } ?? "the client's VLAN"
                if dhcpDiscovers > 0 && dhcpOffers == 0 && dhcpAcks == 0 {
                    bad("Accepted, but \(dhcpDiscovers)× DHCP Discover got no Offer: \(vlanText) may have no DHCP server or relay")
                } else if dhcpNaks > 0 && dhcpAcks == 0 {
                    warn("DHCP NAK: the client asked for an address of another subnet (the VLAN changed?)")
                } else if firstDHCP == nil && clientSide && end - acceptAt >= AuthSessions.dhcpGrace && !dnsOK && !probeOK {
                    // Only where this client's own frames are in the capture: on an uplink SPAN
                    // its DHCP may simply not pass the capture point.
                    warn("Accepted but no DHCP within \(Int(AuthSessions.dhcpGrace)) s: \(vlanText) may have no DHCP")
                } else if firstDHCP == nil && !clientSide && run.sawDHCP && end - acceptAt >= AuthSessions.dhcpGrace {
                    notes.append("No DHCP from this client in the capture (other clients' DHCP is there).")
                } else if let d = firstDHCP, d - acceptAt > AuthSessions.dhcpGrace {
                    warn("DHCP started \(Int(d - acceptAt)) s after the accept")
                }
            }
            if method == .macAuth, lastEAPRequestID != nil, eapResponses == 0 {
                notes.append("The switch asked for 802.1X first; the client did not answer, so it fell back to MAC auth (MAB).")
            }
            if hasPassword && !dot1x && !macAuthRequest { notes.append("PAP / CHAP login (User-Password present, not shown).") }
            if !clientSide && radiusSeen { notes.append("Captured on the wired side: RADIUS only, no client frames (802.1X EAPOL is visible only on the client's own link).") }

            var marked = ordered
            if portOnly, case .timeout = result, let i = marked.lastIndex(where: { $0.kind == .eapRequest }) {
                marked[i].problem = "no supplicant answered"
            } else if case .timeout(let why) = result, why.hasPrefix("no 2/4"),
               let i = marked.lastIndex(where: { $0.kind == .key(1) }) {
                marked[i].problem = "no 2/4 from the client"
            } else if result == .rejected("wrong PSK"), let i = marked.lastIndex(where: { $0.kind == .key(2) }) {
                marked[i].problem = "no 3/4: the AP rejected this 2/4 (MIC)"
            } else if case .timeout(let why) = result, why == "no answer to EAPOL-Start",
                      let i = marked.lastIndex(where: { $0.label == "EAPOL-Start" }) {
                marked[i].problem = "no EAP-Request from the switch / AP"
            } else if case .timeout(let why) = result, why == "stopped", !marked.isEmpty, marked[marked.count - 1].problem == nil {
                marked[marked.count - 1].problem = "no answer for \(Int(silentFor)) s"
            }
            let events = AuthSessions.events(marked, first: first, methodName: methodName)
            let userShown: String? = {
                let u = identity ?? userName
                guard let u else { return nil }
                return AuthDecoder.normalisedMAC(u) ?? u
            }()
            var ids: [Int] = []
            for r in raws { ids += r.packets }
            return AuthSession(
                id: id, client: client, user: userShown, method: method, captive: captive, portalHost: portalHost,
                result: result, macStageResult: macStage,
                nas: nasIdentifier ?? nasIPAddress ?? nasSourceIP ?? nasMAC, nasIP: nasIPAddress ?? nasSourceIP, nasMAC: nasMAC,
                port: nasPortId ?? nasPort.map { "port \($0)" }, ssid: ssid, vlan: vlan, role: role, ip: framedIP ?? dhcpIP,
                serverIP: serverIP, firstTime: Date(timeIntervalSince1970: first), duration: max(0, last - first),
                retries: retries, radiusRTTs: rtts, events: events, health: health, reasons: reasons, notes: notes,
                packetIDs: ids.sorted(), hasRADIUS: radiusSeen, hasClientSide: clientSide, eapMethod: eapName)
        }

        var hasClientSide: Bool {
            raws.contains { $0.from == .client || $0.to == .client }
        }
    }

    // MARK: Rows for the ladder

    /// TLS runs grouped ("PEAP · TLS handshake ×4"), identical consecutive rows merged ("×3").
    static func events(_ raws: [Builder.Raw], first: Double, methodName: String) -> [AuthEvent] {
        var grouped: [Builder.Raw] = []
        var i = 0
        while i < raws.count {
            if raws[i].tlsRound {
                var j = i
                while j < raws.count, raws[j].tlsRound { j += 1 }
                let run = raws[i..<j]
                if run.count >= 3 {
                    let clientRounds = run.filter { $0.clientResponse && $0.from == .client }.count
                    let rounds = clientRounds > 0 ? clientRounds : run.filter(\.clientResponse).count
                    let from = run.map(\.from).min() ?? .client
                    let to = run.flatMap { [$0.from, $0.to] }.max() ?? .nas
                    let eap = run.filter { $0.kind == .eapRequest || $0.kind == .eapResponse }.count
                    let radius = run.count - eap
                    var parts: [String] = []
                    if eap > 0 { parts.append("\(eap) EAP") }
                    if radius > 0 { parts.append("\(radius) RADIUS") }
                    var g = Builder.Raw(time: run.first!.time, kind: .tlsRounds(max(1, rounds)), from: from, to: to,
                                        label: "\(methodName) · TLS handshake ×\(max(1, rounds))",
                                        detail: parts.joined(separator: " + ") + " packets", packets: run.flatMap(\.packets))
                    g.problem = run.compactMap(\.problem).first
                    g.endTime = run.last!.time - first
                    grouped.append(g)
                    i = j
                    continue
                }
            }
            grouped.append(raws[i])
            i += 1
        }
        var merged: [Builder.Raw] = []
        var counts: [Int] = []
        for r in grouped {
            if let lastR = merged.last, lastR.label == r.label, lastR.from == r.from, lastR.to == r.to, lastR.kind == r.kind,
               !r.kind.isFinal {
                merged[merged.count - 1].packets += r.packets
                merged[merged.count - 1].endTime = r.time - first
                if merged[merged.count - 1].problem == nil { merged[merged.count - 1].problem = r.problem }
                counts[counts.count - 1] += 1
            } else {
                merged.append(r)
                counts.append(1)
            }
        }
        var out: [AuthEvent] = []
        out.reserveCapacity(merged.count)
        for (k, r) in merged.enumerated() {
            let n = max(counts[k], r.packets.count > 1 && !r.kind.isGroupKind ? r.packets.count : 1)
            var label = n > 1 ? "\(r.label) ×\(n)" : r.label
            if n > 1, let end = r.endTime, end - (r.time - first) >= 0.5 {
                label += " over \(AuthSessions.msText(end - (r.time - first)))"
            }
            out.append(AuthEvent(id: k + 1, time: r.time - first, kind: r.kind, from: r.from, to: r.to, label: label,
                                 detail: r.detail, problem: r.problem, packetIDs: r.packets, endTime: r.endTime))
        }
        return out
    }

    static func msText(_ s: Double) -> String {
        let ms = s * 1000
        if ms < 10 { return String(format: "%.1f ms", ms) }
        if ms < 1_000 { return String(format: "%.0f ms", ms) }
        if ms < 10_000 { return String(format: "%.2f s", s) }
        return String(format: "%.1f s", s)
    }
}

nonisolated extension AuthEvent.Kind {
    /// Outcomes are never merged into a "×n" row.
    var isFinal: Bool {
        switch self {
        case .eapSuccess, .eapFailure, .radiusAccept, .radiusReject: true
        default: false
        }
    }

    var isGroupKind: Bool { if case .tlsRounds = self { true } else { false } }
}

// MARK: - Copy summary

nonisolated enum AuthSummary {
    private static let stamp = Format.gregorian("yyyy-MM-dd HH:mm:ss.SSS xxx")

    static func healthWord(_ h: AuthHealth) -> String {
        switch h { case .ok: "healthy"; case .warn: "warning"; case .bad: "problem" }
    }

    /// One session, for a ticket or a chat.
    static func text(_ s: AuthSession) -> String {
        var lines: [String] = []
        lines.append("Authentication — client \(s.client)" + (s.user.map { ", user \($0)" } ?? ""))
        var result = "Method: \(s.methodLabel) · Result: \(s.result.label)"
        if let d = s.result.detail { result += " (\(d))" }
        lines.append(result)
        lines.append("Health: \(healthWord(s.health))" + (s.reasons.isEmpty ? "" : " — " + s.reasons.joined(separator: "; ")))
        var where_: [String] = []
        if let n = s.nas { where_.append("NAS \(n)" + (s.nasIP.map { $0 == n ? "" : " (\($0))" } ?? "")) }
        if let p = s.port { where_.append(p) }
        if let ssid = s.ssid { where_.append("SSID \(ssid)") }
        if let m = s.nasMAC { where_.append("authenticator \(m)") }
        if let sv = s.serverIP { where_.append("RADIUS server \(sv)") }
        if !where_.isEmpty { lines.append(where_.joined(separator: " · ")) }
        var got: [String] = []
        if let v = s.vlan { got.append("VLAN \(v)") }
        if let r = s.role { got.append("role \(r)") }
        if let ip = s.ip { got.append("IP \(ip)") }
        if let p = s.portalHost { got.append("portal \(p)") }
        if !got.isEmpty { lines.append(got.joined(separator: " · ")) }
        var timing = "Start: \(stamp.string(from: s.firstTime)), duration \(AuthSessions.msText(s.duration)), retries \(s.retries)"
        if !s.radiusRTTs.isEmpty {
            let avg = s.radiusRTTs.reduce(0, +) / Double(s.radiusRTTs.count)
            timing += ", RADIUS RTT avg \(AuthSessions.msText(avg)) / max \(AuthSessions.msText(s.radiusRTTs.max() ?? 0))"
        }
        lines.append(timing)
        lines.append("Frames \(s.firstPacketID)–\(s.lastPacketID) (\(s.packetIDs.count) packets)")
        lines.append("Steps:")
        for e in s.events.prefix(200) {
            var line = String(format: "  +%.3f s  ", e.time) + "\(e.from.title) → \(e.to.title)  \(e.label)"
            if let d = e.detail { line += "  [\(d)]" }
            if let p = e.problem { line += "  ⚠ \(p)" }
            lines.append(line)
        }
        if s.events.count > 200 { lines.append("  … \(s.events.count - 200) more") }
        for n in s.notes { lines.append("Note: \(n)") }
        return lines.joined(separator: "\n") + "\n"
    }

    /// Every session shown, one line each, then the problems.
    static func overview(_ sessions: [AuthSession], source: String) -> String {
        let failed = sessions.filter { $0.result.isFailure }.count
        var lines = ["Authentication — \(source): \(sessions.count) attempt\(sessions.count == 1 ? "" : "s"), \(failed) failed"]
        for s in sessions {
            var l = "\(stamp.string(from: s.firstTime))  \(s.client)  \(s.user ?? "—")  \(s.methodLabel)  \(s.result.label)"
            if !s.nasAndPort.isEmpty { l += "  \(s.nasAndPort)" }
            if !s.vlanRole.isEmpty { l += "  \(s.vlanRole)" }
            if let ip = s.ip { l += "  \(ip)" }
            if !s.reasons.isEmpty { l += "  — " + s.reasons.joined(separator: "; ") }
            lines.append(l)
        }
        return lines.joined(separator: "\n") + "\n"
    }
}
