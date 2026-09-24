import Foundation

/// Wireshark's TCP sequence analysis, segment by segment: `tcp_analyze_sequence_number` in
/// epan/dissectors/packet-tcp.c (release 4.6), with the SACK-option and initial-RTT steps
/// `dissect_tcp` runs around it, so that retransmission / fast retransmission / spurious
/// retransmission / out-of-order / duplicate ACK / keep-alive / zero-window-probe verdicts are
/// the ones tshark prints for the same frames.
///
/// The order of the checks, as Wireshark makes them:
/// 1. zero-window probe (1 byte at the next sequence number into a closed window) — done;
///    zero window; keep-alive (0–1 byte one below the next sequence number); window update;
///    keep-alive ACK / zero-window-probe ACK — done; duplicate ACK (no data, same ACK, same
///    non-zero window, at the next sequence number).
/// 2. For data / SYN / FIN: a keep-alive is nothing more. **Spurious** when the peer's last ACK
///    already covers the whole segment. Otherwise, only a segment below the next sequence
///    number goes on. `t` = time since the *peer's last segment* (any segment). **Fast** when
///    `t` < 20 ms, the peer has sent ≥ 2 duplicate ACKs in a row and either the segment starts
///    at the peer's ACK or the peer's last segment carried SACK blocks that do not cover it.
///    **Out-of-order** when `t` < the initial RTT (last bare SYN → first non-SYN segment with
///    ACK, 3 ms before one is known), the bytes are not in a segment captured earlier and still
///    unacknowledged, and the segment does not end exactly at the next sequence number (unless
///    the last segment that advanced it carried no data). Anything else: **retransmission**.
///
/// Wireshark quirks kept on purpose (they decide its verdicts): the SACK "not covered" test
/// compares the raw sequence number with SACK edges stored relative to the sender's ISN, so it
/// almost never finds a cover — during SACK recovery nearly every resend within 20 ms of the
/// peer's dup ACKs is "fast"; a sequence number 0 means "not seen yet"; `t` counts from the
/// peer's last segment of any kind, so a duplicate ACK just before a hole-filling segment turns
/// "out of order" into "retransmission".
nonisolated struct TCPSequenceAnalysis: Sendable {
    nonisolated struct Flags: OptionSet, Sendable, Hashable {
        let rawValue: UInt16
        static let zeroWindowProbe = Flags(rawValue: 1 << 0)
        static let zeroWindow = Flags(rawValue: 1 << 1)
        static let keepAlive = Flags(rawValue: 1 << 2)
        static let windowUpdate = Flags(rawValue: 1 << 3)
        static let keepAliveAck = Flags(rawValue: 1 << 4)
        static let zeroWindowProbeAck = Flags(rawValue: 1 << 5)
        static let dupAck = Flags(rawValue: 1 << 6)
        static let retransmission = Flags(rawValue: 1 << 7)
        static let fastRetransmission = Flags(rawValue: 1 << 8)
        static let outOfOrder = Flags(rawValue: 1 << 9)
        static let spuriousRetransmission = Flags(rawValue: 1 << 10)
        /// A segment beyond the next sequence number: something before it was not captured.
        static let previousSegmentNotCaptured = Flags(rawValue: 1 << 11)
        /// The segment acknowledges data the capture never saw.
        static let ackedUnseenSegment = Flags(rawValue: 1 << 12)

        /// Any of the four "old data" verdicts.
        static let resent: Flags = [.retransmission, .fastRetransmission, .outOfOrder, .spuriousRetransmission]

        // Concrete set operations (see `TCPFlags`: the generic defaults dominated Debug runs).
        init(rawValue: UInt16) { self.rawValue = rawValue }
        init(arrayLiteral elements: Flags...) {
            var r: UInt16 = 0
            for e in elements { r |= e.rawValue }
            self.init(rawValue: r)
        }
        var isEmpty: Bool { rawValue == 0 }
        func contains(_ member: Flags) -> Bool { rawValue & member.rawValue == member.rawValue }
        func isDisjoint(with other: Flags) -> Bool { rawValue & other.rawValue == 0 }
        func union(_ other: Flags) -> Flags { Flags(rawValue: rawValue | other.rawValue) }
        func intersection(_ other: Flags) -> Flags { Flags(rawValue: rawValue & other.rawValue) }
        func subtracting(_ other: Flags) -> Flags { Flags(rawValue: rawValue & ~other.rawValue) }
        @discardableResult
        mutating func insert(_ member: Flags) -> (inserted: Bool, memberAfterInsert: Flags) {
            let had = contains(member)
            let after = had ? intersection(member) : member
            self = union(member)
            return (!had, after)
        }
        @discardableResult
        mutating func remove(_ member: Flags) -> Flags? {
            let gone = intersection(member)
            self = subtracting(member)
            return gone.isEmpty ? nil : gone
        }
    }

    /// Wireshark's cap on the segments it remembers per side while they wait for an ACK.
    static let maxUnacked = 10_000
    /// A resend this soon (ns) after the peer's last segment can answer its duplicate ACKs.
    static let fastWindowNS: Int64 = 20_000_000
    /// The out-of-order threshold (ns) before the initial RTT is known.
    static let defaultOOOThresholdNS: Int64 = 3_000_000

    private struct Unacked {
        var seq: UInt32
        let nextseq: UInt32
    }

    private struct Side {
        var baseSeq: UInt32?
        /// 0 = not known yet (as in Wireshark).
        var nextseq: UInt32 = 0
        var maxseqtobeacked: UInt32 = 0
        var lastack: UInt32 = 0
        var lastackTime: Int64?
        var window: UInt32 = .max
        var dupacknum = 0
        var lastsegmentflags: Flags = []
        var lastacklen: UInt32 = 0
        /// Sent, not yet acknowledged; oldest first (Wireshark keeps them newest first).
        var segments: [Unacked] = []
        /// The ACK of the last purge and whether a segment was added since (a purge with the
        /// same ACK and nothing new changes nothing — skipped).
        var purgedAck: UInt32?
        var addedSincePurge = false
        /// The SACK edges of this side's last segment, relative to the peer's base sequence
        /// number (left, right, …).
        var sack: [UInt32] = []
    }

    private var client = Side()
    private var server = Side()
    private var mruSYN: Int64?
    /// Last bare SYN → first segment with ACK and without SYN (Wireshark's iRTT), in ns.
    private(set) var initialRTT: Int64?

    init() {}

    // Sequence-space comparisons (packet-tcp.h's LT_SEQ …).
    @inline(__always) static func lt(_ a: UInt32, _ b: UInt32) -> Bool { Int32(bitPattern: a &- b) < 0 }
    @inline(__always) static func le(_ a: UInt32, _ b: UInt32) -> Bool { Int32(bitPattern: a &- b) <= 0 }
    @inline(__always) static func gt(_ a: UInt32, _ b: UInt32) -> Bool { Int32(bitPattern: a &- b) > 0 }
    @inline(__always) static func ge(_ a: UInt32, _ b: UInt32) -> Bool { Int32(bitPattern: a &- b) >= 0 }

    /// Analyses one segment (capture order) and returns Wireshark's flags for it. `timeNS` is
    /// the capture time in nanoseconds (any fixed origin).
    mutating func analyse(fromClient: Bool, timeNS: Int64, tcp: TCPHeader) -> Flags {
        let flags: Flags
        if fromClient {
            flags = Self.analyse(fwd: &client, rev: &server, timeNS: timeNS, tcp: tcp, irtt: initialRTT)
        } else {
            flags = Self.analyse(fwd: &server, rev: &client, timeNS: timeNS, tcp: tcp, irtt: initialRTT)
        }
        // dissect_tcp, after the analysis: the most recent bare SYN, then the initial RTT.
        let f = tcp.flags
        if f.contains(.syn), !f.contains(.ack) { mruSYN = timeNS }
        if f.contains(.ack), !f.contains(.syn), let syn = mruSYN, initialRTT == nil {
            let d = timeNS - syn
            // nstime_is_zero: a zero delta leaves it unset.
            if d != 0 { initialRTT = d }
        }
        return flags
    }

    private static func analyse(fwd: inout Side, rev: inout Side, timeNS t: Int64, tcp: TCPHeader, irtt: Int64?) -> Flags {
        let f = tcp.flags
        let seq = tcp.sequence, ack = tcp.acknowledgment
        let seglen = UInt32(truncatingIfNeeded: max(0, tcp.payloadLength))
        let window = UInt32(tcp.window)
        let synFin = f.contains(.syn) || f.contains(.fin)
        let sfr = synFin || f.contains(.rst)

        // Base sequence numbers (relative numbering; the SACK edges are stored relative).
        if fwd.baseSeq == nil { fwd.baseSeq = f.contains(.syn) ? seq : seq &- 1 }
        if rev.baseSeq == nil, f.contains(.ack) { rev.baseSeq = ack &- 1 }
        if !fwd.sack.isEmpty { fwd.sack = [] }

        var ta = Flags(rawValue: 0)
        forward: do {
            if seglen == 1, seq == fwd.nextseq, rev.window == 0 {
                ta.insert(.zeroWindowProbe)
                break forward
            }
            if window == 0, !sfr { ta.insert(.zeroWindow) }
            if fwd.nextseq != 0, gt(seq, fwd.nextseq), !f.contains(.rst) { ta.insert(.previousSegmentNotCaptured) }
            if seglen <= 1, seq == fwd.nextseq &- 1, !sfr { ta.insert(.keepAlive) }
            if seglen == 0, window != 0, window != fwd.window, seq == fwd.nextseq, ack == fwd.lastack, !sfr {
                ta.insert(.windowUpdate)
            }
            if seglen == 0, window != 0, window == fwd.window, seq == fwd.nextseq, ack == fwd.lastack,
               rev.lastsegmentflags.contains(.keepAlive), !sfr {
                ta.insert(.keepAliveAck)
                break forward
            }
            if seglen == 0, window == 0, window == fwd.window, seq == fwd.nextseq,
               ack == fwd.lastack || ack == fwd.lastack &+ 1,
               rev.lastsegmentflags.contains(.zeroWindowProbe), !sfr {
                ta.insert(.zeroWindowProbeAck)
                // The receiver took the probe's byte after all.
                if ack == fwd.lastack &+ 1 {
                    rev.nextseq = ack
                    rev.maxseqtobeacked = ack
                }
                break forward
            }
            if seglen == 0, window != 0, window == fwd.window, seq == fwd.nextseq, ack == fwd.lastack, !sfr {
                fwd.dupacknum += 1
                ta.insert(.dupAck)
            }
        }
        if ack != fwd.lastack { fwd.dupacknum = 0 }

        // ACKED LOST PACKET: an ACK beyond anything the peer was seen to send.
        if rev.maxseqtobeacked != 0, gt(ack, rev.maxseqtobeacked), f.contains(.ack) {
            if ack == fwd.lastack &+ 1, seq == fwd.nextseq, rev.lastsegmentflags.contains(.zeroWindowProbe) {
                rev.nextseq = ack
                rev.maxseqtobeacked = ack
                ta.insert(.windowUpdate)
            } else {
                var tailLE: UInt32 = 0, tailRE: UInt32 = 0
                for u in rev.segments.reversed() {
                    if tailLE == tailRE { tailLE = u.seq; tailRE = u.nextseq }
                    if ge(u.seq, ack) {
                        if u.nextseq == tailLE { tailLE = u.seq } else { tailLE = u.seq; tailRE = u.nextseq }
                    }
                }
                rev.maxseqtobeacked = ack == tailLE && gt(tailRE, ack) ? tailRE : ack
                ta.insert(.ackedUnseenSegment)
            }
        }

        // RETRANSMISSION / FAST RETRANSMISSION / OUT-OF-ORDER / SPURIOUS
        var notAdvanced = fwd.nextseq != 0 && lt(seq, fwd.nextseq)
        if seglen > 0 || synFin {
            check: do {
                if ta.contains(.keepAlive) { break check }
                // New data starting one below the next sequence number (after a probe).
                if seglen > 1, fwd.nextseq &- 1 == seq { notAdvanced = false }
                if seglen > 0, rev.lastack != 0, le(seq &+ seglen, rev.lastack) {
                    ta.insert(.spuriousRetransmission)
                    break check
                }
                let end = seq &+ seglen
                guard notAdvanced else { break check }
                let dt: Int64 = rev.lastackTime.map { t > $0 ? t - $0 : 0 } ?? .max
                // Fast retransmission first (tcp_fastrt_precedence, on by default).
                if dt < fastWindowNS, rev.dupacknum >= 2 {
                    if rev.lastack == seq {
                        ta.insert(.fastRetransmission)
                        break check
                    }
                    if !rev.sack.isEmpty {
                        var sacked = false
                        var i = 0
                        while !sacked, i + 1 < rev.sack.count {
                            // Plain comparisons, raw against relative, as Wireshark does.
                            sacked = seq >= rev.sack[i] && end <= rev.sack[i + 1]
                            i += 2
                        }
                        if !sacked {
                            ta.insert(.fastRetransmission)
                            break check
                        }
                    }
                }
                let threshold = irtt ?? defaultOOOThresholdNS
                var alreadySeen = false
                for u in fwd.segments.reversed() where ge(seq, u.seq) && le(end, u.nextseq) {
                    alreadySeen = true
                    break
                }
                if dt < threshold, !alreadySeen {
                    if fwd.nextseq != end &+ (synFin ? 1 : 0) || fwd.lastacklen == 0 {
                        ta.insert(.outOfOrder)
                        break check
                    }
                }
                ta.insert(.retransmission)
            }
        }

        // Remember the segment, move the next sequence number.
        var nextseq = seq &+ seglen
        if seglen > 0 || synFin, fwd.segments.count < maxUnacked {
            if synFin { nextseq &+= 1 }
            fwd.segments.append(Unacked(seq: seq, nextseq: nextseq))
            fwd.addedSincePurge = true
        }
        if fwd.nextseq == 0 || gt(nextseq, fwd.nextseq &+ (synFin ? 1 : 0)) { fwd.lastacklen = seglen }
        if gt(nextseq, fwd.nextseq) || fwd.nextseq == 0, !ta.contains(.zeroWindowProbe) {
            fwd.nextseq = nextseq
        }
        if seq == fwd.maxseqtobeacked || fwd.maxseqtobeacked == 0, !ta.contains(.zeroWindowProbe) {
            fwd.maxseqtobeacked = fwd.nextseq
        }
        fwd.window = window
        fwd.lastack = ack
        fwd.lastackTime = t
        fwd.lastsegmentflags = ta

        // Forget what this acknowledges.
        if !rev.segments.isEmpty, rev.addedSincePurge || rev.purgedAck != ack {
            // One pass, compacting in place: a segment the ACK covers (or ends at) goes, one it
            // cuts into starts at the ACK, the rest stay.
            var kept = 0
            let n = rev.segments.count
            rev.segments.withUnsafeMutableBufferPointer { b in
                for k in 0..<n {
                    var u = b[k]
                    if ack != u.nextseq {
                        if gt(ack, u.seq) && le(ack, u.nextseq) {
                            u.seq = ack
                        } else if !gt(u.nextseq, ack) {
                            continue
                        }
                        b[kept] = u
                        kept += 1
                    }
                }
            }
            if kept < n { rev.segments.removeLast(n - kept) }
        }
        rev.purgedAck = ack
        rev.addedSincePurge = false

        // The SACK option is dissected after the analysis: it stores this side's blocks and
        // turns a "window update" carrying SACK blocks into a duplicate ACK.
        if tcp.sackBlocks > 0 {
            let base = rev.baseSeq ?? 0
            fwd.sack = tcp.sackEdges.map { $0 &- base }
            if ta.contains(.windowUpdate) {
                ta.remove(.windowUpdate)
                ta.insert(.dupAck)
                fwd.dupacknum += 1
            }
        }
        return ta
    }
}
