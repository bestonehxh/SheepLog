import Combine
import Darwin
import Foundation
import Synchronization

/// UDP + TCP syslog listener (RFC 3164 / RFC 5424 / RFC 6587 framing). Parses off the main
/// actor and hands `LogStore.ingest` a batch every ~100 ms.
@MainActor
final class SyslogServer: ObservableObject {
    @Published private(set) var isRunning = false
    @Published private(set) var lastError: String?
    @Published private(set) var udpPort: UInt16 = 0
    @Published private(set) var tcpPort: UInt16 = 0
    /// Open TCP client connections right now.
    @Published private(set) var tcpClients: Int = 0

    private let store: LogStore
    private var listener: SyslogListener?
    private var generation = 0
    /// The most TCP clients at once (`SyslogListener.maxClients`; tests lower it).
    var maxTCPClients = 512
    /// The TCP client limit `lastError` reports (cleared once the clients drop below it).
    private var clientLimitReported: Int?

    static func clientLimitText(_ limit: Int) -> String {
        "More than \(limit) syslog TCP clients: further connections are refused until some close (UDP is not affected)."
    }

    init(store: LogStore) { self.store = store }

    /// Binds both sockets (IPv4 + IPv6). A bind failure sets `lastError` and leaves
    /// `isRunning` false; a port of 0 disables that transport.
    func start(udpPort: UInt16, tcpPort: UInt16) {
        stop()
        lastError = nil
        clientLimitReported = nil
        #if DEBUG
        SyslogDiagnostics.installIfRequested(store: store)
        #endif

        // A GUI app starts with a soft limit of 256 descriptors: a few hundred TCP clients plus
        // the log file, the BPF device and SNMP sockets would hit EMFILE.
        _ = SocketFactory.raiseDescriptorLimit()

        var errors: [String] = []
        let udpFD = Self.open(SOCK_DGRAM, port: udpPort, errors: &errors)
        let tcpFD = Self.open(SOCK_STREAM, port: tcpPort, errors: &errors)
        if !errors.isEmpty { lastError = errors.joined(separator: " ") }
        self.udpPort = udpFD >= 0 ? udpPort : 0
        self.tcpPort = tcpFD >= 0 ? tcpPort : 0
        guard udpFD >= 0 || tcpFD >= 0 else {
            isRunning = false
            if lastError == nil { lastError = "Both syslog ports are 0, so nothing was opened." }
            return
        }
        generation += 1
        let l = makeListener(generation: generation)
        l.start(udpFD: udpFD, tcpFD: tcpFD)
        listener = l
        isRunning = true
    }

    /// "udp 514 · tcp 514": the ports open right now.
    var portsText: String {
        var parts: [String] = []
        if udpPort > 0 { parts.append("udp \(udpPort)") }
        if tcpPort > 0 { parts.append("tcp \(tcpPort)") }
        return parts.joined(separator: " · ")
    }

    /// A bound socket for `port`, or -1 (port 0 = that transport is off; a failure's sentence
    /// is added to `errors`).
    private static func open(_ type: Int32, port: UInt16, errors: inout [String]) -> Int32 {
        guard port > 0 else { return -1 }
        switch SocketFactory.bind(type: type, port: port) {
        case .success(let fd): return fd
        case .failure(let e):
            errors.append(e.message(transport: type == SOCK_STREAM ? "TCP" : "UDP", port: port))
            return -1
        }
    }

    private func makeListener(generation gen: Int) -> SyslogListener {
        let store = self.store
        // At most `slots` batches waiting for the main actor; past that the listener drops
        // (and counts) rather than queueing without bound while the main thread is busy.
        let gate = BacklogGate(slots: SyslogListener.backlogSlots)
        let l = SyslogListener(
            overrides: store.vendorOverrides,
            deliver: { batch in
                DispatchQueue.main.async {
                    MainActor.assumeIsolated {
                        store.ingest(batch, writtenToDisk: true)
                        store.noteDropped(gate.leave())
                    }
                }
            },
            clientsChanged: { [weak self] n in
                DispatchQueue.main.async {
                    MainActor.assumeIsolated {
                        // A count from a listener that was already replaced (off/on quickly)
                        // must not overwrite the new one's.
                        guard let self, self.isRunning, self.generation == gen else { return }
                        if self.tcpClients != n { self.tcpClients = n }
                        // "further connections are refused until some close": once they have,
                        // the running listener is no longer shown as failed.
                        if let limit = self.clientLimitReported, n < limit, self.lastError == Self.clientLimitText(limit) {
                            self.lastError = nil
                            self.clientLimitReported = nil
                        }
                    }
                }
            },
            gate: gate)
        let disk = store.diskSink
        l.rawSink = { raws in disk.append(raws) }
        l.maxClients = maxTCPClients
        l.onLinesLost = { n in
            DispatchQueue.main.async { MainActor.assumeIsolated { store.noteDropped(n) } }
        }
        l.onClientLimit = { [weak self] limit in
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    guard let self, self.isRunning, self.generation == gen else { return }
                    self.lastError = Self.clientLimitText(limit)
                    self.clientLimitReported = limit
                }
            }
        }
        return l
    }

    func stop() {
        listener?.stop()
        listener = nil
        if isRunning { isRunning = false }
        if udpPort != 0 { udpPort = 0 }
        if tcpPort != 0 { tcpPort = 0 }
        if tcpClients != 0 { tcpClients = 0 }
    }
}

// MARK: - Sockets

nonisolated struct SocketError: Error {
    let errno: Int32

    func message(transport: String, port: UInt16) -> String {
        let name = SocketError.errnoName(errno)
        switch errno {
        case EADDRINUSE: return "\(transport) port \(port) is already in use (\(name))."
        case EACCES: return "\(transport) port \(port) needs administrator rights (\(name))."
        default:
            let text = String(cString: strerror(errno))
            return "\(transport) port \(port) could not be opened: \(text) (\(name))."
        }
    }

    static func errnoName(_ e: Int32) -> String {
        switch e {
        case EADDRINUSE: "EADDRINUSE"
        case EACCES: "EACCES"
        case EADDRNOTAVAIL: "EADDRNOTAVAIL"
        case EAFNOSUPPORT: "EAFNOSUPPORT"
        case EPERM: "EPERM"
        case EMFILE: "EMFILE"
        case ENOBUFS: "ENOBUFS"
        case EINVAL: "EINVAL"
        default: "errno \(e)"
        }
    }
}

nonisolated enum SocketFactory {
    /// Raises the soft RLIMIT_NOFILE towards the hard limit (at most `wanted`, and macOS's
    /// OPEN_MAX for setrlimit). Returns the soft limit in force afterwards.
    @discardableResult
    static func raiseDescriptorLimit(wanted: Int = 8_192) -> Int {
        var rl = rlimit()
        guard getrlimit(RLIMIT_NOFILE, &rl) == 0 else { return -1 }
        let target = min(rlim_t(max(0, wanted)), rl.rlim_max, rlim_t(OPEN_MAX))
        if target > rl.rlim_cur {
            var want = rl
            want.rlim_cur = target
            if setrlimit(RLIMIT_NOFILE, &want) != 0 {
                want.rlim_cur = min(target, 4_096)
                _ = setrlimit(RLIMIT_NOFILE, &want)
            }
            _ = getrlimit(RLIMIT_NOFILE, &rl)
        }
        return Int(clamping: rl.rlim_cur)
    }

    /// A non-blocking dual-stack socket bound to `port` (listening, for TCP). Falls back to
    /// IPv4-only when the IPv6 socket cannot be created or bound.
    static func bind(type: Int32, port: UInt16) -> Result<Int32, SocketError> {
        // A dual-stack IPv6 socket binds even while another program holds the port for IPv4
        // (`nc -ul 514`, a second syslog daemon) — and then every IPv4 device's lines go to
        // that program while this one says it is listening. Probe the IPv4 side first.
        if let e = probe4(type: type, port: port) { return .failure(e) }
        switch bind6(type: type, port: port) {
        case .success(let fd): return .success(fd)
        case .failure(let e6):
            switch bind4(type: type, port: port) {
            case .success(let fd): return .success(fd)
            case .failure(let e4):
                // Report the more telling of the two (an in-use port beats "no IPv6").
                return .failure(e6.errno == EADDRINUSE || e6.errno == EACCES ? e6 : e4)
            }
        }
    }

    private static func configure(_ fd: Int32) {
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        // As large a receive buffer as the kernel allows (the default 8 MB kern.ipc.maxsockbuf
        // admits ~7 MB): a burst is queued in the kernel instead of dropped while the parser
        // catches up.
        for mb in [7, 4, 1] {
            var size = Int32(mb * 1024 * 1024)
            if setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, socklen_t(MemoryLayout<Int32>.size)) == 0 { break }
        }
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
    }

    private static func finish(_ fd: Int32, type: Int32) -> Result<Int32, SocketError> {
        if type == SOCK_STREAM, listen(fd, 128) != 0 {
            let e = errno
            close(fd)
            return .failure(SocketError(errno: e))
        }
        return .success(fd)
    }

    private static func bind6(type: Int32, port: UInt16) -> Result<Int32, SocketError> {
        let fd = socket(AF_INET6, type, 0)
        guard fd >= 0 else { return .failure(SocketError(errno: errno)) }
        var zero: Int32 = 0
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, socklen_t(MemoryLayout<Int32>.size))
        configure(fd)
        var addr = sockaddr_in6()
        addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        addr.sin6_family = sa_family_t(AF_INET6)
        addr.sin6_port = port.bigEndian
        addr.sin6_addr = in6addr_any
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
        guard rc == 0 else {
            let e = errno
            close(fd)
            return .failure(SocketError(errno: e))
        }
        return finish(fd, type: type)
    }

    /// Binds (and closes) an IPv4 socket with SO_REUSEADDR on `port`: nil when the port is
    /// free for IPv4, else why not. `EADDRNOTAVAIL`/`EAFNOSUPPORT` (no IPv4) are not errors.
    private static func probe4(type: Int32, port: UInt16) -> SocketError? {
        let fd = socket(AF_INET, type, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        guard bindAny4(fd, port: port) != 0 else { return nil }
        let e = errno
        return e == EADDRINUSE || e == EACCES ? SocketError(errno: e) : nil
    }

    /// `bind` to 0.0.0.0:`port`; the return code of `bind`.
    private static func bindAny4(_ fd: Int32, port: UInt16) -> Int32 {
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr = in_addr(s_addr: INADDR_ANY)
        return withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
    }

    private static func bind4(type: Int32, port: UInt16) -> Result<Int32, SocketError> {
        let fd = socket(AF_INET, type, 0)
        guard fd >= 0 else { return .failure(SocketError(errno: errno)) }
        configure(fd)
        guard bindAny4(fd, port: port) == 0 else {
            let e = errno
            close(fd)
            return .failure(SocketError(errno: e))
        }
        return finish(fd, type: type)
    }

    /// Textual peer address and port of any `sockaddr_storage`; IPv4-mapped IPv6 is shown as
    /// plain IPv4. (The listener's fast path for IPv4 peers is `SyslogListener.peer`.)
    static func describe(_ storage: UnsafePointer<sockaddr_storage>) -> (String, UInt16) {
        switch Int32(storage.pointee.ss_family) {
        case AF_INET:
            return storage.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { p in
                (ipv4(UInt32(bigEndian: p.pointee.sin_addr.s_addr)), UInt16(bigEndian: p.pointee.sin_port))
            }
        case AF_INET6:
            return storage.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { p in
                let port = UInt16(bigEndian: p.pointee.sin6_port)
                var a = p.pointee.sin6_addr
                let bytes = withUnsafeBytes(of: &a) { Array($0) }
                if bytes[0..<10].allSatisfy({ $0 == 0 }), bytes[10] == 0xFF, bytes[11] == 0xFF {
                    let v4 = UInt32(bytes[12]) << 24 | UInt32(bytes[13]) << 16 | UInt32(bytes[14]) << 8 | UInt32(bytes[15])
                    return (ipv4(v4), port)
                }
                var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                inet_ntop(AF_INET6, &a, &buf, socklen_t(INET6_ADDRSTRLEN))
                return (text(ofCBuffer: buf), port)
            }
        default:
            return ("?", 0)
        }
    }

    /// A C string held in a fixed buffer (inet_ntop output): the bytes up to the first NUL, or
    /// the whole buffer when there is none — never reads past its end.
    static func text(ofCBuffer buf: [CChar]) -> String {
        let end = buf.firstIndex(of: 0) ?? buf.count
        return String(decoding: buf[..<end].map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    static func ipv4(_ v: UInt32) -> String {
        "\(v >> 24).\((v >> 16) & 0xFF).\((v >> 8) & 0xFF).\(v & 0xFF)"
    }
}

// MARK: - This Mac's addresses

/// This Mac's IPv4 addresses — what to type into a device's syslog / SNMP trap settings.
nonisolated enum HostAddresses {
    private static let cache = Mutex<(at: Double, value: [(interface: String, address: String)])?>(nil)

    static let cacheSeconds: Double = 5

    static func same(_ a: [(interface: String, address: String)], _ b: [(interface: String, address: String)]) -> Bool {
        a.count == b.count && zip(a, b).allSatisfy { $0.interface == $1.interface && $0.address == $1.address }
    }

    /// Every IPv4 address on an up, non-loopback interface: (interface, address), en* first.
    /// Cached for 5 s: views call this from their initialisers, i.e. on every parent redraw.
    static func ipv4() -> [(interface: String, address: String)] {
        let now = CFAbsoluteTimeGetCurrent()
        if let c = cache.withLock({ $0 }), now - c.at < cacheSeconds { return c.value }
        let fresh = scanIPv4()
        cache.withLock { $0 = (now, fresh) }
        return fresh
    }

    private static func scanIPv4() -> [(interface: String, address: String)] {
        var out: [(String, String)] = []
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let p = cursor {
            defer { cursor = p.pointee.ifa_next }
            let flags = Int32(p.pointee.ifa_flags)
            guard let sa = p.pointee.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET),
                  flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0 else { continue }
            let name = String(cString: p.pointee.ifa_name)
            let addr = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                SocketFactory.ipv4(UInt32(bigEndian: $0.pointee.sin_addr.s_addr))
            }
            if addr.hasPrefix("169.254.") { continue }
            out.append((name, addr))
        }
        return out.sorted { a, b in
            let ea = a.0.hasPrefix("en"), eb = b.0.hasPrefix("en")
            if ea != eb { return ea }
            return a.0.compare(b.0, options: .numeric) == .orderedAscending
        }
    }

    /// The first non-loopback en* IPv4 (else any).
    static func primaryIPv4() -> String? { ipv4().first?.address }

    /// Global IPv6 addresses (2000::/3) on up, non-loopback interfaces — the listeners are
    /// dual-stack, so a device can be pointed at one of these too. Not cached (rarely drawn).
    static func ipv6Global() -> [(interface: String, address: String)] {
        var out: [(String, String)] = []
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let p = cursor {
            defer { cursor = p.pointee.ifa_next }
            let flags = Int32(p.pointee.ifa_flags)
            guard let sa = p.pointee.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET6),
                  flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0 else { continue }
            let text: String? = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                var a = sin6.pointee.sin6_addr
                guard (a.__u6_addr.__u6_addr8.0 & 0xE0) == 0x20 else { return nil }   // 2000::/3 only
                var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                guard inet_ntop(AF_INET6, &a, &buf, socklen_t(INET6_ADDRSTRLEN)) != nil else { return nil }
                return String(decoding: buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
            }
            if let text { out.append((String(cString: p.pointee.ifa_name), text)) }
        }
        return out
    }
}

// MARK: - RFC 6587 framing

/// Splits a TCP byte stream into syslog messages. Octet-counted frames (`<len> <msg>`) are
/// recognised per message by leading digits + a space followed by `<` (the PRI); anything
/// else is newline-delimited (`\n`, `\r\n` or `\0`).
nonisolated enum SyslogFraming {
    /// The longest frame accepted (an octet count above this is not treated as one). A
    /// newline-delimited line that grows past it is dropped by `SyslogFramer`.
    static let maxFrame = 1024 * 1024

    /// Removes and returns every complete message at the front of `buffer`.
    static func split(buffer: inout Data) -> [Data] {
        var out: [Data] = []
        var consumed = 0
        buffer.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            let b = raw.bindMemory(to: UInt8.self)
            let n = b.count
            var p = 0
            while p < n {
                // Skip inter-frame delimiters.
                while p < n, b[p] == 0x0A || b[p] == 0x0D || b[p] == 0x00 { p += 1 }
                consumed = p
                guard p < n else { break }
                // Octet counting?
                var q = p, len = 0
                while q < n, q - p < 9, b[q] >= 0x30, b[q] <= 0x39 { len = len * 10 + Int(b[q] - 0x30); q += 1 }
                let digits = q - p
                if digits > 0, q == n { break }                     // "123" — need more bytes
                if digits > 0, b[q] == 0x20, len > 0, len <= maxFrame, q + 1 >= n || b[q + 1] == 0x3C {
                    guard q + 1 < n else { break }                  // "123 " — need more
                    let start = q + 1
                    guard start + len <= n else { break }           // incomplete frame
                    out.append(trimmed(b, start, start + len))
                    p = start + len
                    consumed = p
                    continue
                }
                // Newline-delimited (an unterminated tail waits; `SyslogFramer` caps it).
                var e = p
                while e < n, b[e] != 0x0A, b[e] != 0x00 { e += 1 }
                if e == n { break }
                out.append(trimmed(b, p, e))
                p = e + 1
                consumed = p
            }
        }
        if consumed > 0 {
            if consumed >= buffer.count { buffer.removeAll(keepingCapacity: true) }
            else { buffer.removeSubrange(buffer.startIndex..<(buffer.startIndex + consumed)) }
        }
        return out.filter { !$0.isEmpty }
    }

    /// What is left when the peer closes: one last unterminated message.
    static func drain(buffer: inout Data) -> [Data] {
        var out = split(buffer: &buffer)
        if !buffer.isEmpty {
            let rest = buffer.withUnsafeBytes { raw in trimmed(raw.bindMemory(to: UInt8.self), 0, raw.count) }
            if !rest.isEmpty { out.append(rest) }
            buffer.removeAll()
        }
        return out
    }

    private static func trimmed(_ b: UnsafeBufferPointer<UInt8>, _ a: Int, _ e: Int) -> Data {
        var end = e
        while end > a, b[end - 1] == 0x0A || b[end - 1] == 0x0D || b[end - 1] == 0x00 { end -= 1 }
        guard end > a, let base = b.baseAddress else { return Data() }
        return Data(bytes: base + a, count: end - a)
    }

    /// UTF-8, falling back to ISO-8859-1 (every byte sequence is valid Latin-1).
    static func decode(_ bytes: UnsafeBufferPointer<UInt8>) -> String {
        if let s = String(validating: bytes, as: UTF8.self) { return s }
        return String(bytes: bytes, encoding: .isoLatin1) ?? String(decoding: bytes, as: UTF8.self)
    }

    static func decode(_ data: Data) -> String {
        data.withUnsafeBytes { decode($0.bindMemory(to: UInt8.self)) }
    }
}

/// One TCP connection's framing state: the partial message plus a cap. A peer that sends more
/// than `SyslogFraming.maxFrame` bytes without a delimiter has that line dropped (counted in
/// `droppedBytes`) and the rest of it skipped up to its newline, so the buffer never grows
/// past about `maxFrame` + one read.
nonisolated struct SyslogFramer {
    private var buffer = Data()
    private var discarding = false
    private(set) var droppedBytes = 0
    /// Lines thrown away (over `maxFrame`, or partial ones dropped for the shared budget).
    private(set) var droppedLines = 0

    var bufferedBytes: Int { buffer.count }

    /// Feed one read; returns every message completed by it.
    mutating func append(_ bytes: UnsafeRawBufferPointer) -> [Data] {
        guard let base = bytes.baseAddress, bytes.count > 0 else { return [] }
        var start = 0
        if discarding {
            // Skip to the end of the runaway line.
            var k = 0
            while k < bytes.count, bytes[k] != 0x0A, bytes[k] != 0x00 { k += 1 }
            droppedBytes += k
            guard k < bytes.count else { return [] }
            discarding = false
            start = k + 1
        }
        guard start < bytes.count else { return [] }
        buffer.append(base.advanced(by: start).assumingMemoryBound(to: UInt8.self), count: bytes.count - start)
        let frames = SyslogFraming.split(buffer: &buffer)
        // What is left is one incomplete message; octet-counted frames up to maxFrame fit,
        // with room for their length prefix.
        if buffer.count > SyslogFraming.maxFrame + 16 {
            droppedBytes += buffer.count
            droppedLines += 1
            buffer = Data()
            discarding = true
        }
        return frames
    }

    /// Throws away the partial message held so far (and the rest of it, up to its newline):
    /// the listener's memory budget for all clients' partial lines ran out.
    mutating func dropPartial() {
        guard !buffer.isEmpty else { return }
        droppedBytes += buffer.count
        droppedLines += 1
        buffer = Data()
        discarding = true
    }

    /// The peer closed: the last unterminated message, unless it was being dropped.
    mutating func finish() -> [Data] {
        defer { buffer = Data(); discarding = false }
        if discarding { return [] }
        return SyslogFraming.drain(buffer: &buffer)
    }
}

// MARK: - The listener (all state confined to its serial queue)

/// Owns the sockets and dispatch sources. Every mutable property is touched only on `queue`
/// (hence `@unchecked Sendable`); `start`/`stop` hop onto it synchronously.
nonisolated final class SyslogListener: @unchecked Sendable {
    typealias Deliver = @Sendable ([LogEntry]) -> Void

    private let queue = DispatchQueue(label: "sheeplog.syslog", qos: .userInitiated)
    private let overrides: VendorOverrideMap
    private let deliver: Deliver
    private let clientsChanged: @Sendable (Int) -> Void
    /// Back-pressure towards the consumer (nil = deliver everything).
    private let gate: BacklogGate?

    /// Batches that may wait for the main actor at once (see `BacklogGate`).
    static let backlogSlots = 32

    // Limits against hostile or broken peers. Set before `start`.
    /// The most TCP clients at once; further connections are accepted and closed at once.
    var maxClients = 512
    /// A TCP client holding an unfinished line this long without completing a message is
    /// disconnected (slowloris: one byte a minute).
    var idleTimeout: TimeInterval = 300
    /// A TCP client that sends nothing at all for this long is disconnected (dead peers whose
    /// FIN never came, connections opened and left open to use up the client slots).
    var silentTimeout: TimeInterval = 3_600
    /// The most bytes of unterminated partial lines held for all TCP clients together.
    var partialBudget = 64 * 1024 * 1024
    /// Told (on the listener queue) the first time a connection is refused at `maxClients`.
    var onClientLimit: (@Sendable (Int) -> Void)?
    /// Told (on the listener queue) how many TCP lines were thrown away in framing — a line
    /// over 1 MB, a partial line over the shared budget or left by a stalled client. They
    /// never reach the store or the disk log, so the store counts them as lost. Set before `start`.
    var onLinesLost: (@Sendable (Int) -> Void)?
    /// Every received line, before parsing and before the backlog gate may drop the batch
    /// (the disk log). Set before `start`.
    var rawSink: (@Sendable ([RawSyslog]) -> Void)?

    // queue-confined
    private var sources: [DispatchSourceProtocol] = []
    private var listenSource: DispatchSourceProtocol?
    private var idleTimer: DispatchSourceTimer?
    private var acceptPaused = false
    private var clients: [Int32: Client] = [:]
    private var batch: [RawSyslog] = []
    private var batchBytes = 0
    private var flushScheduled = false
    private var stopped = false
    private let recvBuffer: UnsafeMutableRawPointer
    private static let recvSize = 65_536
    private var v4Names: [UInt32: String] = [:]
    private let group = DispatchGroup()
    private var partialBytes = 0
    private var limitReported = false
    private var refusedClients = 0
    /// Connections refused at `maxClients` (tests, diagnostics).
    var refusedCount: Int { queue.sync { refusedClients } }

    /// A batch is handed on at 5,000 lines or this many bytes, whichever comes first.
    static let flushBytes = 4 * 1024 * 1024

    private final class Client {
        let fd: Int32
        let address: String
        let port: UInt16
        var framer = SyslogFramer()
        var source: DispatchSourceRead?
        /// Last byte received / last complete message (or empty buffer).
        var lastByte: UInt64
        var lastProgress: UInt64
        init(fd: Int32, address: String, port: UInt16, now: UInt64) {
            self.fd = fd; self.address = address; self.port = port; lastByte = now; lastProgress = now
        }
    }

    init(overrides: VendorOverrideMap, deliver: @escaping Deliver, clientsChanged: @escaping @Sendable (Int) -> Void,
         gate: BacklogGate? = nil) {
        self.overrides = overrides
        self.deliver = deliver
        self.clientsChanged = clientsChanged
        self.gate = gate
        recvBuffer = UnsafeMutableRawPointer.allocate(byteCount: Self.recvSize + 1, alignment: 16)
    }

    deinit { recvBuffer.deallocate() }

    private static func now() -> UInt64 { clock_gettime_nsec_np(CLOCK_UPTIME_RAW) }

    /// Open TCP clients (tests).
    var clientCount: Int { queue.sync { clients.count } }

    func start(udpFD: Int32, tcpFD: Int32) {
        queue.sync {
            if tcpFD >= 0, idleTimeout > 0 {
                let t = DispatchSource.makeTimerSource(queue: queue)
                let every = max(0.05, min(idleTimeout / 4, 30))
                t.schedule(deadline: .now() + every, repeating: every, leeway: .milliseconds(Int(every * 100)))
                t.setEventHandler { [weak self] in self?.closeIdleClients() }
                idleTimer = t
                t.activate()
            }
            if udpFD >= 0 {
                let s = DispatchSource.makeReadSource(fileDescriptor: udpFD, queue: queue)
                s.setEventHandler { [weak self] in self?.readUDP(udpFD) }
                addCancelHandler(s, fd: udpFD)
                sources.append(s)
                s.activate()
            }
            if tcpFD >= 0 {
                let s = DispatchSource.makeReadSource(fileDescriptor: tcpFD, queue: queue)
                s.setEventHandler { [weak self] in self?.accept(tcpFD) }
                addCancelHandler(s, fd: tcpFD)
                sources.append(s)
                listenSource = s
                s.activate()
            }
        }
    }

    /// Cancels every source (each cancel handler closes its fd) and waits for the handlers,
    /// so the ports are free again when this returns. Delivers what was still batched.
    func stop() {
        queue.sync {
            guard !stopped else { return }
            stopped = true
            idleTimer?.cancel()
            idleTimer = nil
            for s in sources { s.cancel() }
            // A suspended source never runs its cancel handler (the fd would leak).
            if acceptPaused, let s = listenSource { acceptPaused = false; s.resume() }
            listenSource = nil
            sources.removeAll()
            // A line still being received (no newline yet) is delivered as it stands: at ⌘Q a
            // device's last message is worth more than a clean frame boundary.
            let now = Date()
            for c in clients.values {
                for f in c.framer.finish() {
                    add(RawSyslog(received: now, sourceAddress: c.address, sourcePort: c.port,
                                  transport: .tcp, text: SyslogFraming.decode(f)), bytes: f.count)
                }
                c.source?.cancel()
            }
            clients.removeAll()
            partialBytes = 0
            flush()
        }
        _ = group.wait(timeout: .now() + 2)
    }

    private func pauseAccepting() {
        guard !acceptPaused, !stopped, let s = listenSource else { return }
        acceptPaused = true
        s.suspend()
        queue.asyncAfter(deadline: .now() + .milliseconds(250)) { [weak self] in
            guard let self, self.acceptPaused, let s = self.listenSource else { return }
            self.acceptPaused = false
            s.resume()
        }
    }

    private func addCancelHandler(_ s: DispatchSourceProtocol, fd: Int32) {
        group.enter()
        let g = group
        s.setCancelHandler {
            close(fd)
            g.leave()
        }
    }

    // MARK: UDP

    private func readUDP(_ fd: Int32) {
        var storage = sockaddr_storage()
        var got = 0
        var now = Date()
        while true {
            if got & 63 == 63 { now = Date() }        // one clock read per 64 datagrams
            var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let n = withUnsafeMutablePointer(to: &storage) { sp in
                sp.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    recvfrom(fd, recvBuffer, Self.recvSize, 0, $0, &len)
                }
            }
            if n < 0 { break }                    // EAGAIN (drained) or an error
            got += 1
            var count = n
            let bytes = recvBuffer.assumingMemoryBound(to: UInt8.self)
            while count > 0, bytes[count - 1] == 0x0A || bytes[count - 1] == 0x0D || bytes[count - 1] == 0x00 { count -= 1 }
            guard count > 0 else { continue }
            let (address, port) = peer(&storage)
            let text = SyslogFraming.decode(UnsafeBufferPointer(start: bytes, count: count))
            add(RawSyslog(received: now, sourceAddress: address, sourcePort: port, transport: .udp, text: text), bytes: count)
            if got >= 20_000 { break }            // let TCP and flushes breathe; the source fires again
        }
    }

    private func peer(_ storage: inout sockaddr_storage) -> (String, UInt16) {
        if Int32(storage.ss_family) == AF_INET6 {
            // Fast path for IPv4-mapped addresses (the common case on a dual-stack socket).
            let mapped: (UInt32, UInt16)? = withUnsafePointer(to: &storage) { sp in
                sp.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { p in
                    let a = p.pointee.sin6_addr.__u6_addr.__u6_addr32
                    guard a.0 == 0, a.1 == 0, a.2 == UInt32(0xFFFF).bigEndian else { return nil }
                    return (UInt32(bigEndian: a.3), UInt16(bigEndian: p.pointee.sin6_port))
                }
            }
            if let (v4, port) = mapped { return (name(v4), port) }
        } else if Int32(storage.ss_family) == AF_INET {
            let (v4, port): (UInt32, UInt16) = withUnsafePointer(to: &storage) { sp in
                sp.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { p in
                    (UInt32(bigEndian: p.pointee.sin_addr.s_addr), UInt16(bigEndian: p.pointee.sin_port))
                }
            }
            return (name(v4), port)
        }
        return withUnsafePointer(to: &storage) { SocketFactory.describe($0) }
    }

    private func name(_ v4: UInt32) -> String {
        if let s = v4Names[v4] { return s }
        if v4Names.count > 4096 { v4Names.removeAll() }
        let s = SocketFactory.ipv4(v4)
        v4Names[v4] = s
        return s
    }

    // MARK: TCP

    private func accept(_ listenFD: Int32) {
        // A bounded number per event: a connection flood must not keep this serial queue from
        // reading UDP (the source fires again while the backlog is non-empty).
        var accepted = 0
        while accepted < 256 {
            var storage = sockaddr_storage()
            var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let fd = withUnsafeMutablePointer(to: &storage) { sp in
                sp.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.accept(listenFD, $0, &len) }
            }
            if fd < 0 {
                // Out of descriptors: the listening socket stays readable, so the source would
                // fire in a tight loop. Pause accepting for a moment instead.
                if errno == EMFILE || errno == ENFILE { pauseAccepting() }
                break
            }
            accepted += 1
            if clients.count >= maxClients {
                // Refused: closed at once (the peer sees the connection end). One report.
                Darwin.close(fd)
                refusedClients += 1
                if !limitReported {
                    limitReported = true
                    onClientLimit?(maxClients)
                }
                continue
            }
            var one: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            let flags = fcntl(fd, F_GETFL, 0)
            _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
            let (address, port) = peer(&storage)
            let client = Client(fd: fd, address: address, port: port, now: Self.now())
            let s = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
            s.setEventHandler { [weak self] in self?.readTCP(fd) }
            addCancelHandler(s, fd: fd)
            client.source = s
            clients[fd] = client
            s.activate()
            clientsChanged(clients.count)
        }
    }

    private func readTCP(_ fd: Int32) {
        guard let client = clients[fd] else { return }
        var closed = false
        var reads = 0
        var frames: [Data] = []
        let heldBefore = client.framer.bufferedBytes
        let droppedBefore = client.framer.droppedLines
        defer {
            let lost = client.framer.droppedLines - droppedBefore
            if lost > 0 { onLinesLost?(lost) }
        }
        while reads < 64 {
            let n = recv(fd, recvBuffer, Self.recvSize, 0)
            if n > 0 {
                // Frame each read as it comes, so a peer without newlines is capped at ~1 MB
                // instead of piling up 64 reads first.
                frames += client.framer.append(UnsafeRawBufferPointer(start: recvBuffer, count: n))
                reads += 1
                continue
            }
            if n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { closed = true }
            break
        }
        if reads > 0 {
            let t = Self.now()
            client.lastByte = t
            if !frames.isEmpty || client.framer.bufferedBytes == 0 { client.lastProgress = t }
        }
        // Every client may hold up to ~1 MB of an unterminated line; together they share
        // `partialBudget` (512 clients × 1 MB would be half a gigabyte).
        partialBytes += client.framer.bufferedBytes - heldBefore
        if partialBytes > partialBudget, client.framer.bufferedBytes > 0 {
            partialBytes -= client.framer.bufferedBytes
            client.framer.dropPartial()
        }
        if closed {
            partialBytes -= client.framer.bufferedBytes
            frames += client.framer.finish()
        }
        let now = Date()
        for f in frames {
            add(RawSyslog(received: now, sourceAddress: client.address, sourcePort: client.port,
                          transport: .tcp, text: SyslogFraming.decode(f)), bytes: f.count)
        }
        if closed { drop(client) }
    }

    private func drop(_ client: Client) {
        client.source?.cancel()               // the cancel handler closes the fd
        client.source = nil
        clients.removeValue(forKey: client.fd)
        clientsChanged(clients.count)
    }

    /// Disconnects a client that has held an unterminated line for `idleTimeout` without
    /// finishing a message (a slowloris sends one byte a minute: bytes, but no progress), or
    /// that has sent nothing at all for `silentTimeout`. The partial line is discarded.
    private func closeIdleClients() {
        let now = Self.now()
        let stalled = UInt64(idleTimeout * 1_000_000_000)
        let silent = UInt64(max(idleTimeout, silentTimeout) * 1_000_000_000)
        for c in Array(clients.values)
        where (c.framer.bufferedBytes > 0 && now &- c.lastProgress > stalled) || now &- c.lastByte > silent {
            partialBytes -= c.framer.bufferedBytes
            if c.framer.bufferedBytes > 0 { onLinesLost?(1) }      // its unfinished line
            drop(c)
        }
        if clients.count < maxClients { limitReported = false }
    }

    // MARK: Batching

    /// Queue a received line; parsing happens per batch in `flush`, across cores, so the
    /// receive loop only reads and decodes (a single-threaded parser in the loop let the kernel
    /// buffer overflow under a burst).
    private func add(_ raw: RawSyslog, bytes: Int) {
        batch.append(raw)
        batchBytes += bytes
        if batch.count >= 5_000 || batchBytes >= Self.flushBytes {
            flush()
        } else if !flushScheduled {
            flushScheduled = true
            queue.asyncAfter(deadline: .now() + .milliseconds(100)) { [weak self] in
                guard let self else { return }
                self.flushScheduled = false
                self.flush()
            }
        }
    }

    private func flush() {
        guard !batch.isEmpty else { return }
        let b = batch
        batch = []
        batchBytes = 0
        batch.reserveCapacity(1024)
        rawSink?(b)
        // The main actor is this many batches behind: drop (counted by the gate) before
        // spending the parse on lines nobody can take in.
        if let gate, !gate.tryEnter(count: b.count) { return }
        deliver(Self.parseBatch(b, overrides: overrides.snapshot()))
    }

    /// Parse a batch in arrival order with consecutive ids; chunks of 512 lines run in parallel.
    /// The ids are reserved **before** `overrides` is read: `LogStore` tells a line parsed with
    /// an override that has changed since by its id.
    static func parseBatch(_ raws: [RawSyslog], overrides readOverrides: @autoclosure () -> [String: Vendor]) -> [LogEntry] {
        let n = raws.count
        guard n > 0 else { return [] }
        let first = LogStore.reserveIDs(n)
        let overrides = readOverrides()
        @Sendable func one(_ i: Int) -> LogEntry {
            let r = raws[i]
            return SyslogParser.parse(r, id: first + i, vendorOverride: overrides.isEmpty ? nil : overrides[r.sourceAddress])
        }
        let chunk = 512
        let chunks = (n + chunk - 1) / chunk
        if chunks == 1 { return (0..<n).map(one) }
        return [LogEntry](unsafeUninitializedCapacity: n) { buf, count in
            let out = OutputSlots(base: buf.baseAddress!)
            DispatchQueue.concurrentPerform(iterations: chunks) { c in
                let lo = c * chunk, hi = min(n, lo + chunk)
                for i in lo..<hi { (out.base + i).initialize(to: one(i)) }
            }
            count = n
        }
    }

    /// Disjoint slots of one output buffer, written from `concurrentPerform` workers.
    private struct OutputSlots: @unchecked Sendable { let base: UnsafeMutablePointer<LogEntry> }
}

// MARK: - Debug diagnostics (stress checks without driving the UI)

#if DEBUG
/// Only with the `-syslogDiagnostics` launch argument, Debug builds only. Prints the ring
/// counters once a second (`lost` must stay 0: every received line is in `entries`, was evicted
/// or is held while paused), and reacts to signals the stress scripts send:
/// SIGUSR1 = lower the in-memory limit to 1,000 (as the Settings field does, not persisted);
/// SIGUSR2 = switch the syslog listener off and on 20 times in a row.
@MainActor
enum SyslogDiagnostics {
    private static var installed = false
    private static var signalSources: [DispatchSourceSignal] = []
    private static var timer: Timer?

    static func installIfRequested(store: LogStore) {
        guard !installed, CommandLine.arguments.contains("-syslogDiagnostics") else { return }
        installed = true
        for sig in [SIGUSR1, SIGUSR2] {
            signal(sig, SIG_IGN)
            let s = DispatchSource.makeSignalSource(signal: sig, queue: .main)
            s.setEventHandler {
                MainActor.assumeIsolated {
                    let t0 = Date()
                    if sig == SIGUSR1 {
                        store.limit = 1_000
                        report(store, "limit→1000 in \(Int(Date().timeIntervalSince(t0) * 1000)) ms")
                    } else {
                        for _ in 0..<20 { AppModel.shared.stopSyslog(); AppModel.shared.startSyslog() }
                        let s = AppModel.shared.syslog
                        report(store, "20x off/on in \(Int(Date().timeIntervalSince(t0) * 1000)) ms running=\(s.isRunning) error=\(s.lastError ?? "none")")
                    }
                }
            }
            s.resume()
            signalSources.append(s)
        }
        let t = Timer(timeInterval: 1, repeats: true) { _ in
            MainActor.assumeIsolated { report(store, "tick") }
        }
        RunLoop.main.add(t, forMode: .common)
        timer = t
    }

    private static func report(_ store: LogStore, _ what: String) {
        let lost = store.totalReceived - store.entries.count - store.dropped - store.pausedCount
        print("[diag] \(what) received=\(store.totalReceived) entries=\(store.entries.count) dropped=\(store.dropped) paused=\(store.pausedCount) visible=\(store.visibleCount) lost=\(lost) tcpClients=\(AppModel.shared.syslog.tcpClients) rate=\(Int(store.rate))")
        fflush(stdout)
    }
}
#endif
