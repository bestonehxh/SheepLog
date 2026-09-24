import CPcap
import Foundation

/// Reading and writing capture files through libpcap (pcap_open_offline handles both pcap and
/// pcapng).
///
/// Limits worth knowing:
/// - libpcap gives a file one link type (the first interface's). A pcapng whose interfaces have
///   different link types is read up to the first packet of another type; the error says so.
/// - Classic pcap stores seconds as a signed 32-bit number: 1901 … 2038 round-trip exactly.
/// - Lengths are 32-bit per packet; files larger than 2 GB read fine (libpcap reads
///   sequentially), but the ring keeps only the newest `PacketStore.limit` packets.
/// - A file still being written ends mid-record: the complete packets are kept and the error
///   says the file ends in the middle of a packet.
nonisolated enum PcapFile {
    static let batchSize = 5_000
    /// The dead handle's snap length for writing. Longer packets are written truncated to it
    /// (wire length kept): libpcap refuses to read a record longer than the file's maximum.
    static let writeSnapLength = 262_144

    /// Reads every packet, decoding as it goes. Returns the link type.
    /// Packets that were read before an error are handed to `sink` before the error is thrown.
    static func read(_ url: URL, sink: ([Packet]) -> Void) throws -> Int32 {
        try read(url, while: { true }, sink: sink)
    }

    /// `read`, stopping (quietly, with what was read so far) once `keepGoing` says no — a load
    /// replaced by another file, Clear or a live capture must not decode the rest of a big
    /// file for nothing.
    static func read(_ url: URL, while keepGoing: () -> Bool, sink: ([Packet]) -> Void) throws -> Int32 {
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        guard let p = pcap_open_offline(url.path(percentEncoded: false), &errbuf) else {
            throw openError(errorText(errbuf), url: url)
        }
        defer { pcap_close(p) }
        let linkType = pcap_datalink(p)
        var batch: [Packet] = []
        batch.reserveCapacity(batchSize)
        var id = 0
        var first: Double?
        var hdr: UnsafeMutablePointer<pcap_pkthdr>?
        var bytes: UnsafePointer<UInt8>?
        while true {
            if id % 1_000 == 0, !keepGoing() { return linkType }
            let r = pcap_next_ex(p, &hdr, &bytes)
            if r == 1, let h = hdr?.pointee, let bytes {
                id += 1
                let ts = Double(h.ts.tv_sec) + Double(h.ts.tv_usec) / 1_000_000
                if first == nil { first = ts }
                let caplen = Int(h.caplen)
                let raw = UnsafeRawBufferPointer(start: bytes, count: caplen)
                batch.append(Packet(id: id, timestamp: Date(timeIntervalSince1970: ts), relative: ts - (first ?? ts),
                                    length: Int(h.len), captured: caplen, data: Data(raw),
                                    decoded: PacketDecoder.decode(raw, linkType: linkType)))
                if batch.count >= batchSize {
                    sink(batch)
                    batch.removeAll(keepingCapacity: true)
                }
            } else if r == -2 {
                break
            } else if r == 0 {
                continue
            } else {
                if !batch.isEmpty { sink(batch) }
                throw readError(String(cString: pcap_geterr(p)), after: id, url: url)
            }
        }
        if !batch.isEmpty { sink(batch) }
        return linkType
    }

    /// Opens the file and reports its link type without reading packets (fails fast on a file
    /// libpcap cannot read).
    static func linkType(of url: URL) throws -> Int32 {
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        guard let p = pcap_open_offline(url.path(percentEncoded: false), &errbuf) else {
            throw openError(errorText(errbuf), url: url)
        }
        defer { pcap_close(p) }
        return pcap_datalink(p)
    }

    /// The snapshot length a classic pcap file's header states (nil for pcapng or a file that
    /// cannot be read). libpcap reports a clamped value (262,144), not the header's (tcpdump on
    /// macOS writes 524,288), so a saved copy would differ from the file in its header.
    static func headerSnapLength(of url: URL) -> Int? {
        guard let h = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? h.close() }
        guard let d = try? h.read(upToCount: 24), d.count == 24 else { return nil }
        let b = [UInt8](d)
        let le = UInt32(b[0]) | UInt32(b[1]) << 8 | UInt32(b[2]) << 16 | UInt32(b[3]) << 24
        let little: Bool
        switch le {
        case 0xA1B2C3D4, 0xA1B23C4D: little = true
        case 0xD4C3B2A1, 0x4D3CB2A1: little = false
        default: return nil
        }
        let s = Array(b[16..<20])
        let v = little ? UInt32(s[0]) | UInt32(s[1]) << 8 | UInt32(s[2]) << 16 | UInt32(s[3]) << 24
                       : UInt32(s[3]) | UInt32(s[2]) << 8 | UInt32(s[1]) << 16 | UInt32(s[0]) << 24
        return v > 0 && v <= UInt32(Int32.max) ? Int(v) : nil
    }

    /// `snapLength`: the header value to write (the opened file's own, so saving an unfiltered
    /// file gives the same bytes); used only when every packet fits in it.
    static func write(_ packets: [Packet], linkType: Int32, to url: URL, snapLength: Int? = nil) throws {
        let largest = packets.reduce(0) { max($0, min($1.data.count, writeSnapLength)) }
        let headerSnap = snapLength.flatMap { $0 >= largest && $0 <= Int(Int32.max) ? $0 : nil } ?? writeSnapLength
        guard let dead = pcap_open_dead(linkType, Int32(headerSnap)) else {
            throw error("pcap_open_dead failed for link type \(linkType)", url: url)
        }
        defer { pcap_close(dead) }
        guard let dumper = pcap_dump_open(dead, url.path(percentEncoded: false)) else {
            throw error(String(cString: pcap_geterr(dead)), url: url)
        }
        let user = UnsafeMutablePointer<UInt8>(dumper)
        var hdr = pcap_pkthdr()
        for pkt in packets {
            let t = pkt.timestamp.timeIntervalSince1970
            var sec = t.isFinite ? t.rounded(.down) : 0
            var usec = t.isFinite ? ((t - sec) * 1_000_000).rounded() : 0
            if usec >= 1_000_000 { sec += 1; usec -= 1_000_000 }
            hdr.ts.tv_sec = Int(max(-9e18, min(9e18, sec)))
            hdr.ts.tv_usec = Int32(max(0, min(999_999, usec)))
            let caplen = min(pkt.data.count, writeSnapLength)
            hdr.caplen = UInt32(caplen)
            hdr.len = UInt32(clamping: max(pkt.length, pkt.data.count))
            pkt.data.prefix(caplen).withUnsafeBytes { raw in
                guard let base = raw.bindMemory(to: UInt8.self).baseAddress else {
                    var zero: UInt8 = 0
                    pcap_dump(user, &hdr, &zero)
                    return
                }
                pcap_dump(user, &hdr, base)
            }
        }
        let flushed = pcap_dump_flush(dumper)
        pcap_dump_close(dumper)
        if flushed != 0 { throw error("Could not write every packet (disk full?)", url: url) }
    }

    /// A libpcap `errbuf` as text.
    static func errorText(_ buf: [CChar]) -> String {
        let bytes = buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self)
    }

    /// libpcap's open errors, in words ("unknown file format" is anything that is not a capture).
    private static func openError(_ message: String, url: URL) -> NSError {
        if message.localizedCaseInsensitiveContains("unknown file format")
            || message.localizedCaseInsensitiveContains("bad dump file format") {
            return error("\(url.lastPathComponent) is not a pcap or pcapng capture file (libpcap: \(message)).", url: url)
        }
        if message.localizedCaseInsensitiveContains("truncated dump file") {
            return error("\(url.lastPathComponent) is empty or cut short before its first packet (libpcap: \(message)).", url: url)
        }
        return error(message, url: url)
    }

    /// libpcap's mid-file errors, in words.
    private static func readError(_ message: String, after count: Int, url: URL) -> NSError {
        let kept = count == 1 ? "the 1 packet" : "the \(count) packets"
        if message.localizedCaseInsensitiveContains("truncated") {
            return error("The file ends in the middle of a packet (still being written?); \(kept) before it were read. (libpcap: \(message))", url: url)
        }
        if message.localizedCaseInsensitiveContains("different from the type of the first interface")
            || message.localizedCaseInsensitiveContains("link-layer type") || message.localizedCaseInsensitiveContains("link type") {
            return error("The file mixes interfaces of different link types, and libpcap reads one link type per file; \(kept) before the first packet of another link type were read. (libpcap: \(message))", url: url)
        }
        return error("\(message) (after \(count) packets)", url: url)
    }

    private static func error(_ message: String, url: URL) -> NSError {
        NSError(domain: "SheepLog.PcapFile", code: 1, userInfo: [
            NSLocalizedDescriptionKey: message.isEmpty ? "libpcap could not read \(url.lastPathComponent)" : message,
            NSFilePathErrorKey: url.path(percentEncoded: false),
        ])
    }
}
