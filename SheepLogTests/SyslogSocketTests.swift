import Darwin
import XCTest
@testable import SheepLog

/// The listener's sockets against a port another program already holds.
final class SyslogSocketTests: XCTestCase {
    /// `nc -ul 514` running: the dual-stack IPv6 socket used to bind anyway (SO_REUSEADDR on a
    /// datagram socket), the pane said "Listening on udp 514", and every IPv4 device's lines
    /// went to the other program. The bind must fail with "already in use".
    func testUDPPortHeldByIPv4ProgramIsReported() throws {
        let (held, port) = try XCTUnwrap(TestSockets.holdIPv4(SOCK_DGRAM))
        defer { close(held) }
        switch SocketFactory.bind(type: SOCK_DGRAM, port: port) {
        case .success(let fd):
            close(fd)
            XCTFail("UDP \(port) is held by another IPv4 socket, yet the bind succeeded")
        case .failure(let e):
            XCTAssertEqual(e.errno, EADDRINUSE)
            XCTAssertTrue(e.message(transport: "UDP", port: port).contains("already in use"))
        }
    }

    func testTCPPortHeldByIPv4ProgramIsReported() throws {
        let (held, port) = try XCTUnwrap(TestSockets.holdIPv4(SOCK_STREAM))
        defer { close(held) }
        switch SocketFactory.bind(type: SOCK_STREAM, port: port) {
        case .success(let fd):
            close(fd)
            XCTFail("TCP \(port) is held by another IPv4 socket, yet the bind succeeded")
        case .failure(let e):
            XCTAssertEqual(e.errno, EADDRINUSE)
        }
    }

    /// Our own sockets can be closed and bound again at once (off/on in the sidebar).
    func testRebindAfterClose() throws {
        let (probe, port) = try XCTUnwrap(TestSockets.holdIPv4(SOCK_DGRAM))
        close(probe)
        for type in [SOCK_DGRAM, SOCK_STREAM] {
            for _ in 0..<3 {
                guard case .success(let fd) = SocketFactory.bind(type: type, port: port) else {
                    return XCTFail("rebind \(type) on \(port) failed")
                }
                close(fd)
            }
        }
    }
}
