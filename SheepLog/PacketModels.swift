import Foundation

// MARK: - Packet capture value types (shared contract)

nonisolated struct MACAddress: Hashable, Sendable, CustomStringConvertible {
    let bytes: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8)
    init(_ b: [UInt8]) { bytes = (b[0], b[1], b[2], b[3], b[4], b[5]) }
    var description: String {
        String(format: "%02x:%02x:%02x:%02x:%02x:%02x", bytes.0, bytes.1, bytes.2, bytes.3, bytes.4, bytes.5)
    }
    static func == (a: MACAddress, b: MACAddress) -> Bool { a.description == b.description }
    func hash(into h: inout Hasher) { h.combine(description) }
    var isBroadcast: Bool { bytes.0 == 0xff && bytes.1 == 0xff && bytes.2 == 0xff && bytes.3 == 0xff && bytes.4 == 0xff && bytes.5 == 0xff }
    var isMulticast: Bool { bytes.0 & 1 == 1 }
}

nonisolated struct IPHeader: Sendable, Equatable {
    let version: Int          // 4 or 6
    let source: String
    let destination: String
    let proto: UInt8          // 6 TCP, 17 UDP, 1 ICMP, 58 ICMPv6, …
    let ttl: UInt8
    let identification: UInt16
    let dontFragment: Bool
    let moreFragments: Bool
    let fragmentOffset: UInt16
    let headerLength: Int
    let totalLength: Int
    let dscp: UInt8
}

nonisolated struct TCPFlags: OptionSet, Sendable, Hashable {
    let rawValue: UInt8
    static let fin = TCPFlags(rawValue: 0x01)
    static let syn = TCPFlags(rawValue: 0x02)
    static let rst = TCPFlags(rawValue: 0x04)
    static let psh = TCPFlags(rawValue: 0x08)
    static let ack = TCPFlags(rawValue: 0x10)
    static let urg = TCPFlags(rawValue: 0x20)
    static let ece = TCPFlags(rawValue: 0x40)
    static let cwr = TCPFlags(rawValue: 0x80)

    // Concrete set operations: OptionSet's defaults go through SetAlgebra's generic witnesses
    // (several calls per `contains`), which in a Debug build were a third of the flow
    // analysis. Same results; these are what direct calls pick.
    init(rawValue: UInt8) { self.rawValue = rawValue }
    init(arrayLiteral elements: TCPFlags...) {
        var r: UInt8 = 0
        for e in elements { r |= e.rawValue }
        self.init(rawValue: r)
    }
    var isEmpty: Bool { rawValue == 0 }
    func contains(_ member: TCPFlags) -> Bool { rawValue & member.rawValue == member.rawValue }
    func isDisjoint(with other: TCPFlags) -> Bool { rawValue & other.rawValue == 0 }
    func union(_ other: TCPFlags) -> TCPFlags { TCPFlags(rawValue: rawValue | other.rawValue) }
    func intersection(_ other: TCPFlags) -> TCPFlags { TCPFlags(rawValue: rawValue & other.rawValue) }
    func subtracting(_ other: TCPFlags) -> TCPFlags { TCPFlags(rawValue: rawValue & ~other.rawValue) }
    @discardableResult
    mutating func insert(_ member: TCPFlags) -> (inserted: Bool, memberAfterInsert: TCPFlags) {
        let had = contains(member)
        let after = had ? intersection(member) : member
        self = union(member)
        return (!had, after)
    }
    @discardableResult
    mutating func remove(_ member: TCPFlags) -> TCPFlags? {
        let gone = intersection(member)
        self = subtracting(member)
        return gone.isEmpty ? nil : gone
    }

    /// "SYN", "SYN, ACK", "PSH, ACK", "FIN, ACK", "RST" — Wireshark order.
    var label: String {
        var out: [String] = []
        if contains(.fin) { out.append("FIN") }
        if contains(.syn) { out.append("SYN") }
        if contains(.rst) { out.append("RST") }
        if contains(.psh) { out.append("PSH") }
        if contains(.ack) { out.append("ACK") }
        if contains(.urg) { out.append("URG") }
        if contains(.ece) { out.append("ECE") }
        if contains(.cwr) { out.append("CWR") }
        return out.joined(separator: ", ")
    }
}

nonisolated struct TCPHeader: Sendable, Equatable {
    let sourcePort: UInt16
    let destinationPort: UInt16
    let sequence: UInt32
    let acknowledgment: UInt32
    let flags: TCPFlags
    let window: UInt16
    let headerLength: Int
    /// Bytes of payload after the TCP header.
    let payloadLength: Int
    let mss: UInt16?
    let windowScale: UInt8?
    let sackPermitted: Bool
    let sackBlocks: Int
    let timestampValue: UInt32?
    let timestampEcho: UInt32?
    /// The SACK blocks' edges as sent (left, right, left, right, …; at most 4 blocks) — the
    /// flow analysis needs them as Wireshark does. Additive, defaulted.
    var sackEdges: [UInt32] = []
}

nonisolated struct UDPHeader: Sendable, Equatable {
    let sourcePort: UInt16
    let destinationPort: UInt16
    let length: Int
    let payloadLength: Int
}

nonisolated struct ICMPHeader: Sendable, Equatable {
    let type: UInt8
    let code: UInt8
    let identifier: UInt16?
    let sequence: UInt16?
}

nonisolated struct ARPInfo: Sendable, Equatable {
    let isRequest: Bool
    let senderMAC: String
    let senderIP: String
    let targetMAC: String
    let targetIP: String
}

/// What the application layer looked like, when a decoder recognised it (by port + shape).
nonisolated enum AppLayer: Sendable, Equatable {
    case httpRequest(method: String, path: String, host: String?)
    case httpResponse(status: Int, reason: String)
    case tlsClientHello(sni: String?, version: String)
    case tlsServerHello(version: String)
    case tlsOther(recordType: String)
    case dns(query: String?, isResponse: Bool, answers: Int, rcode: Int)
    case dhcp(messageType: String, clientMAC: String?, yourIP: String?)
    case snmp(version: String, community: String?, pduType: String)
    case syslog(priority: Int?, preview: String)
    case radius(code: String, id: UInt8)
    case ntp
    case ssh(banner: String?)
    case other(name: String)

    var name: String {
        switch self {
        case .httpRequest, .httpResponse: "HTTP"
        case .tlsClientHello, .tlsServerHello, .tlsOther: "TLS"
        case .dns: "DNS"
        case .dhcp: "DHCP"
        case .snmp: "SNMP"
        case .syslog: "Syslog"
        case .radius: "RADIUS"
        case .ntp: "NTP"
        case .ssh: "SSH"
        case .other(let n): n
        }
    }
}

nonisolated struct Decoded: Sendable, Equatable {
    var sourceMAC: String = ""
    var destinationMAC: String = ""
    var vlan: UInt16? = nil
    var etherType: UInt16 = 0
    var ip: IPHeader? = nil
    var tcp: TCPHeader? = nil
    var udp: UDPHeader? = nil
    var icmp: ICMPHeader? = nil
    var arp: ARPInfo? = nil
    var app: AppLayer? = nil
    /// Offset of the transport payload in `Packet.data` (or of the whole L3 payload for others).
    var payloadOffset: Int = 0
    /// The Protocol column: the top-most recognised layer ("TCP", "HTTP", "TLS", "DNS", "ARP", "ICMP", "LLDP", …).
    var protocolName: String = ""
    /// The Info column, Wireshark-style one-liner.
    var info: String = ""

    var source: String { ip?.source ?? arp?.senderIP ?? sourceMAC }
    var destination: String { ip?.destination ?? arp?.targetIP ?? destinationMAC }
    var sourcePort: UInt16? { tcp?.sourcePort ?? udp?.sourcePort }
    var destinationPort: UInt16? { tcp?.destinationPort ?? udp?.destinationPort }
}

nonisolated struct Packet: Identifiable, Sendable {
    /// 1-based frame number within the store / file.
    let id: Int
    let timestamp: Date
    /// Seconds since the first packet of the store / file.
    let relative: Double
    /// Bytes on the wire.
    let length: Int
    /// Bytes captured (`data.count`).
    let captured: Int
    let data: Data
    let decoded: Decoded
}

/// A TCP/UDP conversation key, direction-independent.
nonisolated struct FlowKey: Hashable, Sendable, CustomStringConvertible {
    let addressA: String
    let portA: UInt16
    let addressB: String
    let portB: UInt16
    let proto: UInt8

    /// Canonical: (A, portA) is the lexically smaller endpoint.
    init(_ a: String, _ pa: UInt16, _ b: String, _ pb: UInt16, proto: UInt8) {
        if (a, pa) <= (b, pb) {
            addressA = a; portA = pa; addressB = b; portB = pb
        } else {
            addressA = b; portA = pb; addressB = a; portB = pa
        }
        self.proto = proto
    }

    var description: String { "\(addressA):\(portA) ⇄ \(addressB):\(portB)" }
}

nonisolated struct CaptureInterface: Identifiable, Sendable, Equatable, Hashable {
    var id: String { name }
    let name: String
    let description: String
    let addresses: [String]
    let isUp: Bool
    let isLoopback: Bool

    /// "Wi-Fi (en0) — 192.168.1.36", "Ethernet Adapter (en2)", "utun3".
    var pickerTitle: String {
        // System Settings already writes "Ethernet Adapter (en2)" for some adapters.
        let label = description.isEmpty ? name : (description.contains("(\(name))") ? description : "\(description) (\(name))")
        return addresses.isEmpty ? label : "\(label) — \(addresses.first ?? "")"
    }
}
