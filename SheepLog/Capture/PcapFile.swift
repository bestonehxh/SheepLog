import CPcap
import Foundation

/// Reading and writing capture files through libpcap (pcap_open_offline handles both pcap and
/// pcapng).
///
/// Limits worth knowing:
/// - libpcap gives a file one link type (the first interface's). A pcapng whose interfaces have
///   different link types is read up to the first packet of another type; the error says so.
/// - Classic pcap stores seconds as a signed 32-bit number: 1901 … 2038 round-trip exactly.
///   Times read are clamped to 1901 … 2106 (`PacketTime`): pcapng can say anything.
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
        let p = try openOffline(url)
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
                let ts = PacketTime.seconds(h.ts.tv_sec, h.ts.tv_usec)
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
        let p = try openOffline(url)
        defer { pcap_close(p) }
        return pcap_datalink(p)
    }

    /// libpcap's reader on `url`, which must be a regular file (a symlink to one is followed).
    /// Opened here without blocking and checked on the descriptor: `pcap_open_offline` on a FIFO
    /// (from the open panel or `-demoPcap`) blocked in open() forever, on the main thread — and
    /// a check by path before it could be raced by a FIFO swapped in.
    static func openOffline(_ url: URL) throws -> OpaquePointer {
        let fd = try openRegular(url)
        // Reads block as usual from here (a regular file never waits anyway).
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK)
        guard let fp = fdopen(fd, "rb") else {
            let e = errno
            Darwin.close(fd)
            throw error("\(url.path(percentEncoded: false)): \(String(cString: strerror(e)))", url: url)
        }
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        // On failure libpcap leaves the stream to its caller (pcap_open_offline closes it itself).
        guard let p = pcap_fopen_offline(fp, &errbuf) else {
            fclose(fp)
            throw openError(errorText(errbuf), url: url)
        }
        return p
    }

    /// A read-only descriptor on `url` when it is a regular file; the error says what it is otherwise.
    static func openRegular(_ url: URL) throws -> Int32 {
        let path = url.path(percentEncoded: false)
        let fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else {
            let e = errno
            throw error("\(path): \(String(cString: strerror(e)))", url: url)
        }
        var st = stat()
        guard fstat(fd, &st) == 0, st.st_mode & S_IFMT == S_IFREG else {
            Darwin.close(fd)
            throw error("\(url.lastPathComponent) is not a regular file (a folder, a pipe or a device), so it cannot be read as a capture.", url: url)
        }
        return fd
    }

    /// The snapshot length a classic pcap file's header states (nil for pcapng or a file that
    /// cannot be read). libpcap reports a clamped value (262,144), not the header's (tcpdump on
    /// macOS writes 524,288), so a saved copy would differ from the file in its header.
    static func headerSnapLength(of url: URL) -> Int? {
        guard let fd = try? openRegular(url) else { return nil }
        let h = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
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
    /// Written next to `url` under a temporary name and renamed over it when complete: a Save
    /// that fails part-way (disk full) or is cut short never leaves a truncated capture under the
    /// chosen name, nor destroys the file it was replacing (libpcap truncated it on open).
    /// The temporary file is created 0600 — or with the mode of the file it replaces — and is
    /// written through the descriptor that created it: created 0644 and renamed over a 0600
    /// capture it made RADIUS / SNMP traffic world-readable, and re-opened by path it followed a
    /// symlink swapped in meanwhile.
    static func write(_ packets: [Packet], linkType: Int32, to url: URL, snapLength: Int? = nil) throws {
        let dir = url.deletingLastPathComponent()
        let temp = dir.appendingPathComponent(".\(url.lastPathComponent).sheeplog-\(UUID().uuidString.prefix(8))")
        var existing = stat()
        let replacing = stat(url.path(percentEncoded: false), &existing) == 0 && existing.st_mode & S_IFMT == S_IFREG
        let mode: mode_t = replacing ? existing.st_mode & 0o7777 : 0o600
        // A folder that takes no new file (but lets an existing one be overwritten) is written in
        // place. Only over a file that is there: a new name the folder refused as a temporary
        // file (a full disk) was created in place, part-written, and left behind.
        let fd = open(temp.path(percentEncoded: false), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else {
            let e = errno
            if FileManager.default.fileExists(atPath: url.path(percentEncoded: false)), e != ENOSPC {
                return try dump(packets, linkType: linkType, snapLength: snapLength, reportAs: url) { dead in
                    pcap_dump_open(dead, url.path(percentEncoded: false))
                }
            }
            throw error("Could not create the file: \(String(cString: strerror(e)))" + (e == ENOSPC ? " (the disk is full)" : ""), url: url)
        }
        // Exactly the replaced file's mode (open's mode is narrowed by the umask).
        if mode != 0o600 { _ = fchmod(fd, mode) }
        do {
            try dump(packets, linkType: linkType, snapLength: snapLength, reportAs: url) { dead in
                // pcap_dump_fopen leaves its stream open when it refuses the link type but closes it
                // when the header cannot be written: the link type is tried on /dev/null first, so
                // the descriptor is closed exactly once on every path — by us until fdopen takes
                // it, then by the stream (libpcap's failure, or pcap_dump_close).
                guard let probe = pcap_dump_open(dead, "/dev/null") else { Darwin.close(fd); return nil }
                pcap_dump_close(probe)
                guard let fp = fdopen(fd, "wb") else { Darwin.close(fd); return nil }
                return pcap_dump_fopen(dead, fp)
            }
            guard rename(temp.path(percentEncoded: false), url.path(percentEncoded: false)) == 0 else {
                throw error(String(cString: strerror(errno)), url: url)
            }
        } catch {
            unlink(temp.path(percentEncoded: false))
            throw error
        }
    }

    /// Writes `packets` through the dumper `open` returns (nil: it closed whatever it opened).
    private static func dump(_ packets: [Packet], linkType: Int32, snapLength: Int?, reportAs reported: URL,
                             open: (OpaquePointer) -> OpaquePointer?) throws {
        let largest = packets.reduce(0) { max($0, min($1.data.count, writeSnapLength)) }
        let headerSnap = snapLength.flatMap { $0 >= largest && $0 <= Int(Int32.max) ? $0 : nil } ?? writeSnapLength
        guard let dead = pcap_open_dead(linkType, Int32(headerSnap)) else {
            throw error("pcap_open_dead failed for link type \(linkType)", url: reported)
        }
        defer { pcap_close(dead) }
        guard let dumper = open(dead) else {
            throw error(String(cString: pcap_geterr(dead)), url: reported)
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
        // A write that failed earlier (the disk filled part-way) leaves the stream's error flag
        // set even when the last flush has nothing left to write: both are checked.
        let flushed = pcap_dump_flush(dumper)
        let failed = flushed != 0 || ferror(pcap_dump_file(dumper)) != 0
        let e = errno
        pcap_dump_close(dumper)
        if failed {
            throw error("Could not write every packet: \(String(cString: strerror(e == 0 ? EIO : e)))"
                        + (e == ENOSPC ? " (the disk is full)" : ""), url: reported)
        }
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

/// Packet times UncleSpy can do arithmetic on. libpcap hands over whatever a file says: a pcapng
/// `if_tsoffset` of 0x7ffffffffffffffa makes tv_sec Int64.max, and two packets 10^16 µs apart
/// overflowed the flow analysis's nanoseconds — Flows and Troubleshoot crashed on opening the
/// file. Times are clamped where packets enter (the packet is kept) to what 32-bit capture
/// seconds can say: classic pcap's signed seconds back to 1901, unsigned ones up to 2106 — 204
/// years, whose nanoseconds still fit an Int64.
nonisolated enum PacketTime {
    /// 1901-12-13T20:45:52Z (Int32.min seconds).
    static let earliest = -2_147_483_648.0
    /// 2106-02-07T06:28:15Z (UInt32.max seconds).
    static let latest = 4_294_967_295.0

    /// `t` within [earliest, latest]; NaN is the Unix epoch.
    static func clamped(_ t: Double) -> Double {
        guard !t.isNaN else { return 0 }
        return min(max(t, earliest), latest)
    }

    /// A capture header's seconds + microseconds, clamped.
    static func seconds(_ sec: Int, _ usec: Int32) -> Double {
        clamped(Double(sec) + Double(usec) / 1_000_000)
    }
}

nonisolated extension Int {
    /// `Int(d)` that saturates instead of trapping: NaN is 0, anything past Int's range its end.
    /// For times and durations that come from packet data (`Int(Double)` traps on 1e19 and NaN).
    init(saturating d: Double) {
        if d.isNaN { self = 0 }
        else if d >= Double(Int.max) { self = .max }       // 2^63: one past Int.max
        else if d <= Double(Int.min) { self = .min }
        else { self = Int(d) }
    }
}

nonisolated extension Int64 {
    /// `Int64(d)` that saturates instead of trapping (see `Int(saturating:)`).
    init(saturating d: Double) { self = Int64(Int(saturating: d)) }
}
