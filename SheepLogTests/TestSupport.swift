import Darwin
import Foundation
@testable import SheepLog

// Fixtures shared by the syslog and shell tests: one line builder, loopback sockets, a box for
// values a listener queue writes.

/// `text` as received from `address`, run through the real parser.
func parsedLine(_ text: String, from address: String = "10.1.0.1", received: Date = Date(),
                transport: Transport = .udp, id: Int = 1, vendor: Vendor? = nil) -> LogEntry {
    SyslogParser.parse(RawSyslog(received: received, sourceAddress: address, sourcePort: 514,
                                 transport: transport, text: text), id: id, vendorOverride: vendor)
}

/// IPv4 loopback sockets for the listener tests.
nonisolated enum TestSockets {
    /// `0.0.0.0:port`, or `127.0.0.1:port` with `loopback`.
    static func address(_ port: UInt16, loopback: Bool = false) -> sockaddr_in {
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr = in_addr(s_addr: loopback ? inet_addr("127.0.0.1") : INADDR_ANY)
        return addr
    }

    static func withSockaddr<R>(_ addr: sockaddr_in, _ body: (UnsafePointer<sockaddr>, socklen_t) -> R) -> R {
        var a = addr
        return withUnsafePointer(to: &a) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { body($0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
    }

    /// The port an IPv4 socket bound to `fd` has.
    static func boundPort(_ fd: Int32) -> UInt16 {
        var bound = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &bound) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        return UInt16(bigEndian: bound.sin_port)
    }

    /// A port the kernel just handed out (bound to 0 and released).
    static func freePort(_ type: Int32 = SOCK_DGRAM) -> UInt16 {
        let fd = socket(AF_INET, type, 0)
        defer { close(fd) }
        _ = withSockaddr(address(0)) { Darwin.bind(fd, $0, $1) }
        return boundPort(fd)
    }

    /// Another program holding only `0.0.0.0:port` (IPv4), like `nc -ul <port>`; port 0 = any
    /// free one. nil when the bind failed.
    static func holdIPv4(_ type: Int32, port: UInt16 = 0) -> (fd: Int32, port: UInt16)? {
        let fd = socket(AF_INET, type, 0)
        guard fd >= 0 else { return nil }
        guard withSockaddr(address(port), { Darwin.bind(fd, $0, $1) }) == 0 else { close(fd); return nil }
        if type == SOCK_STREAM { listen(fd, 4) }
        return (fd, boundPort(fd))
    }

    /// Each line as one datagram to 127.0.0.1:`port`.
    static func sendUDP(_ lines: [String], to port: UInt16) {
        let s = socket(AF_INET, SOCK_DGRAM, 0)
        defer { close(s) }
        let to = address(port, loopback: true)
        for line in lines {
            let b = Array(line.utf8)
            _ = withSockaddr(to) { sendto(s, b, b.count, 0, $0, $1) }
        }
    }

    /// A TCP client connected to 127.0.0.1:`port` (SIGPIPE off); nil when the connect failed.
    static func connectTCP(_ port: UInt16) -> Int32? {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        guard withSockaddr(address(port, loopback: true), { connect(fd, $0, $1) }) == 0 else { close(fd); return nil }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        return fd
    }
}

/// A value shared with a listener queue in tests.
nonisolated final class LockedBox<T>: @unchecked Sendable {
    private var v: T
    private let lock = NSLock()
    init(_ v: T) { self.v = v }
    var value: T { lock.lock(); defer { lock.unlock() }; return v }
    func mutate(_ f: (inout T) -> Void) { lock.lock(); f(&v); lock.unlock() }
}

/// Keychain calls from tests, prompt-proof: a Debug build signed differently from the one that
/// created an item makes macOS ask for access, and the call blocks until someone answers — a
/// whole unattended suite stalled for 25 minutes on it. `body` runs on its own thread; nil when
/// it has not finished within `timeout` (the caller skips). The thread may stay blocked.
nonisolated enum KeychainProbe {
    static func run<T: Sendable>(timeout: Double = 5, _ body: @escaping @Sendable () -> T) -> T? {
        let box = LockedBox<T?>(nil)
        let done = DispatchSemaphore(value: 0)
        Thread {
            let v = body()
            box.mutate { $0 = v }
            done.signal()
        }.start()
        guard done.wait(timeout: .now() + timeout) == .success else { return nil }
        return box.value
    }

    /// Fire and forget (clean-up in a `defer`): never waits.
    static func later(_ body: @escaping @Sendable () -> Void) {
        Thread { body() }.start()
    }
}

// Trap, SNMP and capture tests.
nonisolated extension TestSockets {
    /// `datagram` to 127.0.0.1:`port`, `times` times, from `fd` (or a socket of its own).
    static func sendUDP(_ datagram: [UInt8], to port: UInt16, times: Int = 1, from fd: Int32? = nil) {
        let s = fd ?? socket(AF_INET, SOCK_DGRAM, 0)
        defer { if fd == nil { close(s) } }
        let to = address(port, loopback: true)
        for _ in 0..<times { _ = withSockaddr(to) { sendto(s, datagram, datagram.count, 0, $0, $1) } }
    }
}
