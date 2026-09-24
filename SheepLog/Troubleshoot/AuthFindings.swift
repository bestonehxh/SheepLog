import Foundation

/// Authentication sessions as Troubleshoot findings: every failed or troubled session becomes
/// one finding a network engineer can act on, with the packets as evidence.
nonisolated enum AuthFindings {
    static func findings(from packets: [Packet]) -> [Finding] {
        let sessions = AuthSessions.build(packets)
        var out: [Finding] = []
        for s in sessions where s.health != .ok {
            let who = s.user.map { "\($0) (\(s.client))" } ?? s.client
            let place = [s.nas, s.ssid.map { "SSID \($0)" }, s.port.map { "port \($0)" }]
                .compactMap { $0 }.joined(separator: " · ")
            let severity: FindingSeverity = s.health == .bad ? .bad : .warn
            let title: String
            switch s.result {
            case .rejected(let why):
                title = "\(who) was rejected (\(s.method.label)\(why.isEmpty ? "" : ": \(why)"))."
            case .timeout(let why):
                title = "\(who) timed out during \(s.method.label)\(why.isEmpty ? "" : ": \(why)")."
            case .inProgress:
                title = "\(who) never finished \(s.method.label)."
            case .accepted:
                title = "\(who) was accepted (\(s.method.label)) but had trouble afterwards."
            }
            var detail = s.reasons.joined(separator: " ")
            if !place.isEmpty { detail += " Seen on \(place)." }
            if !s.notes.isEmpty { detail += " " + s.notes.joined(separator: " ") }
            var steps: [String] = []
            switch s.result {
            case .rejected:
                steps.append(s.method.isDot1x ? "Check the user's credentials and that the client trusts the RADIUS server certificate."
                                              : "Check the MAC / PSK on the NAS and the RADIUS server's policy for this client.")
            case .timeout:
                steps.append(s.hasRADIUS ? "Check that the RADIUS server is reachable from \(s.nas ?? "the NAS") and the shared secret matches."
                                         : "Capture on the switch/controller uplink to see whether RADIUS answered.")
            default: break
            }
            if s.ip == nil, s.result == .accepted {
                steps.append("Check that VLAN \(s.vlan ?? "?") has a DHCP scope reachable from this port.")
            }
            steps.append("Open Authentication and select \(s.client) to see every step with timings.")
            let query = s.packetIDs.count <= 50
                ? s.packetIDs.map { "frame:\($0)" }.joined(separator: " OR ")
                : "frame:>=\(s.packetIDs.min() ?? 0) frame:<=\(s.packetIDs.max() ?? 0) (\(AuthDecoder.packetFilterPreset))"
            out.append(Finding(id: "auth|\(s.client)|\(Int(s.firstTime.timeIntervalSince1970))",
                               rule: "auth.session", severity: severity, category: .auth, source: .auth,
                               title: title, detail: detail,
                               evidence: [Evidence(kind: .packets, label: "\(s.packetIDs.count) packets", ids: s.packetIDs, query: query)],
                               firstSeen: s.firstTime, lastSeen: s.firstTime.addingTimeInterval(s.duration),
                               count: max(1, s.retries + 1), device: s.nas, deviceAddress: s.nasIP,
                               client: s.client, nextSteps: steps))
        }
        return out
    }
}
