import AppKit
import Darwin
import Synchronization
import XCTest
@testable import SheepLog

/// Round 18: the listeners driven with live traffic and an exact account of every line (sent =
/// in memory + on disk + counted as lost), paused-Log sequences, routing authentication and
/// neighbor traps, IPv6 zones and whole addresses in brackets, load, and a sweep.
@MainActor
final class Round18Tests: XCTestCase {
    private var cleanup: [URL] = []
    private var savedSettings: AppSettings?
    private var clients: [LineClient] = []
    private var senders: [UDPSender] = []

    override func tearDown() async throws {
        for c in clients { c.close() }
        clients = []
        for s in senders { s.stop() }
        senders = []
        let app = AppModel.shared
        app.stopSyslog()
        app.stopTraps()
        app.syslog.maxTCPClients = 512
        if let s = savedSettings { app.settings = s; savedSettings = nil }
        app.dismissAllErrors()
        app.logs.paused = false
        app.logs.regexMode = false
        app.logs.limit = 100_000
        app.logs.queryText = ""
        app.logs.applyQueryText()
        app.logs.clear()
        app.mainPane = .status
        for u in cleanup { try? FileManager.default.removeItem(at: u) }
        cleanup = []
        try? await Task.sleep(for: .milliseconds(30))
    }

    // MARK: - Harness

    private func spin(_ ms: Int = 30) async { try? await Task.sleep(for: .milliseconds(ms)) }

    private func waitUntil(_ timeout: Double = 5, _ condition: () -> Bool) async {
        let end = Date().addingTimeInterval(timeout)
        while !condition(), Date() < end { await spin(10) }
    }

    /// The kernel's UDP counters: datagrams to a port nobody holds, and datagrams dropped
    /// because the receiving socket's buffer was full (`struct udpstat`, netinet/udp_var.h).
    nonisolated struct UDPStats {
        let noPort: Int
        let fullSocket: Int

        static func now() -> UDPStats {
            var buf = [UInt32](repeating: 0, count: 64)
            var len = buf.count * 4
            _ = buf.withUnsafeMutableBytes { sysctlbyname("net.inet.udp.stats", $0.baseAddress, &len, nil, 0) }
            return UDPStats(noPort: Int(buf[4]), fullSocket: Int(buf[6]))
        }

        func since(_ before: UDPStats) -> UDPStats {
            UDPStats(noPort: noPort - before.noPort, fullSocket: fullSocket - before.fullSocket)
        }
    }

    nonisolated static func tcpLine(_ tag: String, _ n: Int) -> String { "<134>Sep 23 10:15:32 \(tag) app: tcp line \(n)" }
    nonisolated static func udpLine(_ tag: String, _ n: Int) -> String { "<134>Sep 23 10:15:32 \(tag) app: udp line \(n)" }

    /// Runs each job on a thread of its own; how many returned true.
    private func parallel(_ jobs: [@Sendable () -> Bool]) async -> Int {
        let done = LockedBox<Int>(0), ok = LockedBox<Int>(0)
        for j in jobs {
            Thread.detachNewThread {
                let r = j()
                if r { ok.mutate { $0 += 1 } }
                done.mutate { $0 += 1 }
            }
        }
        await waitUntil(60) { done.value == jobs.count }
        return ok.value
    }

    /// A TCP device on 127.0.0.1: a flood on its own thread, or a burst sent in full (every
    /// byte acknowledged by the receiving kernel) before `burst` returns.
    nonisolated final class LineClient: @unchecked Sendable {
        let fd: Int32
        let tag: String
        private let stopFlag = Atomic<Bool>(false)
        /// Lines handed to the kernel (a flood's count; `send` accepted every byte of them).
        let sent = Atomic<Int>(0)
        let failed = Atomic<Bool>(false)
        private let done = DispatchSemaphore(value: 0)
        private let running = Atomic<Bool>(false)
        private let closed = Atomic<Bool>(false)

        init?(port: UInt16, tag: String) {
            guard let s = TestSockets.connectTCP(port) else { return nil }
            fd = s
            self.tag = tag
        }

        /// `count` lines, then waits until the peer's kernel has acknowledged every byte.
        @discardableResult
        func burst(_ count: Int) -> Bool {
            var text = ""
            let start = sent.load(ordering: .relaxed)
            for n in start..<(start + count) { text += Round18Tests.tcpLine(tag, n) + "\n" }
            let bytes = Array(text.utf8)
            var off = 0
            while off < bytes.count {
                let w = bytes.withUnsafeBytes { send(fd, $0.baseAddress! + off, bytes.count - off, 0) }
                if w <= 0 { failed.store(true, ordering: .relaxed); return false }
                off += w
            }
            sent.store(start + count, ordering: .relaxed)
            return waitAcknowledged()
        }

        /// Every byte written has left this socket's send buffer (SO_NWRITE = 0).
        func waitAcknowledged(timeout: Double = 5) -> Bool {
            let end = Date().addingTimeInterval(timeout)
            while Date() < end, !failed.load(ordering: .relaxed) {     // (a reset peer never acknowledges)
                var n: Int32 = 0
                var len = socklen_t(4)
                if getsockopt(fd, SOL_SOCKET, SO_NWRITE, &n, &len) != 0 { return false }
                if n == 0 { return true }
                usleep(1_000)
            }
            return false
        }

        /// Lines until `stopSending`, ~`perSecond` of them.
        func flood(perSecond: Int = 3_000) {
            stopFlag.store(false, ordering: .relaxed)
            running.store(true, ordering: .relaxed)
            let tag = self.tag
            Thread.detachNewThread { [self] in
                var n = sent.load(ordering: .relaxed)
                let every = max(1, perSecond / 1_000)
                while !stopFlag.load(ordering: .relaxed) {
                    let line = Round18Tests.tcpLine(tag, n) + "\n"
                    let w = line.withCString { send(fd, $0, strlen($0), 0) }
                    if w <= 0 { failed.store(true, ordering: .relaxed); break }
                    n += 1
                    sent.store(n, ordering: .relaxed)
                    if n % every == 0 { usleep(1_000) }
                }
                done.signal()
            }
        }

        func stopSending() {
            guard running.exchange(false, ordering: .relaxed) else { return }
            stopFlag.store(true, ordering: .relaxed)
            _ = done.wait(timeout: .now() + 5)
            _ = waitAcknowledged()
        }

        func close() {
            stopSending()
            guard !closed.exchange(true, ordering: .relaxed) else { return }
            Darwin.close(fd)
        }

        /// The peer closed the connection (a read returns 0 / an error without blocking).
        var peerClosed: Bool {
            var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            guard poll(&p, 1, 0) > 0 else { return false }
            var b: UInt8 = 0
            return recv(fd, &b, 1, MSG_PEEK | MSG_DONTWAIT) <= 0
        }
    }

    /// Syslog datagrams to 127.0.0.1:`port`, paced so the listener keeps up (a loss must be the
    /// app's, not a full kernel buffer's — `UDPStats` counts those anyway).
    nonisolated final class UDPSender: @unchecked Sendable {
        let tag: String
        let port: UInt16
        private let fd: Int32
        let sent = Atomic<Int>(0)
        private let stopFlag = Atomic<Bool>(false)
        private let running = Atomic<Bool>(false)
        private let done = DispatchSemaphore(value: 0)
        /// A datagram of its own per line (default: a syslog line; traps set this).
        let make: @Sendable (String, Int) -> [UInt8]

        init(port: UInt16, tag: String, make: @escaping @Sendable (String, Int) -> [UInt8] = { Array(Round18Tests.udpLine($0, $1).utf8) }) {
            self.port = port
            self.tag = tag
            self.make = make
            fd = socket(AF_INET, SOCK_DGRAM, 0)
        }

        deinit { Darwin.close(fd) }

        func send(_ count: Int) {
            let to = TestSockets.address(port, loopback: true)
            let start = sent.load(ordering: .relaxed)
            for n in start..<(start + count) {
                let d = make(tag, n)
                _ = TestSockets.withSockaddr(to) { sendto(fd, d, d.count, 0, $0, $1) }
            }
            sent.store(start + count, ordering: .relaxed)
        }

        func flood(perSecond: Int = 4_000) {
            stopFlag.store(false, ordering: .relaxed)
            running.store(true, ordering: .relaxed)
            Thread.detachNewThread { [self] in
                let every = max(1, perSecond / 1_000)
                while !stopFlag.load(ordering: .relaxed) {
                    send(1)
                    if sent.load(ordering: .relaxed) % every == 0 { usleep(1_000) }
                }
                done.signal()
            }
        }

        func stop() {
            guard running.exchange(false, ordering: .relaxed) else { return }
            stopFlag.store(true, ordering: .relaxed)
            _ = done.wait(timeout: .now() + 5)
        }
    }

    /// A v2c trap whose sysName.0 says `tag` + `n` (so each one can be found).
    nonisolated static func trapDatagram(_ tag: String, _ n: Int) -> [UInt8] {
        let pdu = SNMPPDU(type: BER.trapV2, requestID: Int32(n & 0x7FFF_FFFF), varBinds: [
            VarBind(OID.sysUpTimeInstance, .timeTicks(42)),
            VarBind(OID.snmpTrapOID, .oid(OID([1, 3, 6, 1, 6, 3, 1, 1, 5, 3]))),
            VarBind(OID([1, 3, 6, 1, 2, 1, 1, 5, 0]), .octetString(Data("\(tag)-\(n)".utf8))),
        ])
        return CommunityMessage.encode(version: .v2c, community: "public", pdu: pdu.encoded())
    }

    /// Per tag: the line numbers in memory (ring + held by Pause), one pass.
    private func tally(udp: Bool = false) -> [String: [Int]] {
        let app = AppModel.shared
        let word = udp ? "udp line " : "tcp line "
        var out: [String: [Int]] = [:]
        for e in app.logs.entries + app.logs.heldEntries {
            guard let r = e.message.range(of: word), let n = Int(e.message[r.upperBound...]) else { continue }
            out[e.hostname, default: []].append(n)
        }
        return out
    }

    private func numbers(_ tag: String, udp: Bool = false) -> [Int] { tally(udp: udp)[tag] ?? [] }

    private func trapNumbers(_ tag: String) -> [Int] {
        AppModel.shared.logs.entries.compactMap { e -> Int? in
            guard e.transport == .trap, let r = e.message.range(of: "\(tag)-") else { return nil }
            return Int(e.message[r.upperBound...].prefix { $0.isNumber })
        }
    }

    /// Every client's lines 0..<sent in memory, each once.
    private func assertEveryLine(_ cs: [LineClient], _ what: String, file: StaticString = #filePath, line: UInt = #line) async {
        let end = Date().addingTimeInterval(15)
        var t = tally()
        while !cs.allSatisfy({ (t[$0.tag]?.count ?? 0) >= $0.sent.load(ordering: .relaxed) }), Date() < end {
            await spin(100)
            t = tally()
        }
        for c in cs {
            let got = t[c.tag] ?? []
            let sent = c.sent.load(ordering: .relaxed)
            XCTAssertEqual(got.count, sent, "\(what): \(c.tag) sent \(sent), \(got.count) in memory", file: file, line: line)
            XCTAssertEqual(Set(got), Set(0..<sent), "\(what): \(c.tag) lines missing or doubled", file: file, line: line)
        }
    }

    /// The UDP account: what was sent = what is in memory + what the kernel dropped for a full
    /// buffer. (The kernel's count of datagrams to closed ports is system-wide and this Mac has
    /// other senders: it is only printed.)
    private func assertUDP(_ s: UDPSender, since before: UDPStats, _ what: String, file: StaticString = #filePath, line: UInt = #line) async {
        let sent = s.sent.load(ordering: .relaxed)
        await waitUntil(10) { numbers(s.tag, udp: true).count >= sent }
        let got = numbers(s.tag, udp: true)
        let k = UDPStats.now().since(before)
        XCTAssertEqual(Set(got).count, got.count, "\(what): doubled datagrams", file: file, line: line)
        XCTAssertLessThanOrEqual(got.count, sent, file: file, line: line)
        XCTAssertGreaterThanOrEqual(got.count + k.fullSocket, sent,
                                    "\(what): sent \(sent), \(got.count) in memory, \(k.fullSocket) dropped by the kernel for a full buffer (\(k.noPort) to closed ports, system-wide)", file: file, line: line)
    }

    private func startSyslog(udp: UInt16, tcp: UInt16) {
        let app = AppModel.shared
        if savedSettings == nil { savedSettings = app.settings }
        app.dismissAllErrors()
        app.logs.clear()
        app.settings.logLimit = AppModel.maxLogLimit     // (settings win over logs.limit at every change)
        app.settings.syslogUDPPort = udp
        app.settings.syslogTCPPort = tcp
        app.startSyslog()
        XCTAssertTrue(app.syslog.isRunning, app.syslog.lastError ?? "")
    }

    private func connect(_ n: Int, port: UInt16, prefix: String) -> [LineClient] {
        let cs = (0..<n).compactMap { LineClient(port: port, tag: "\(prefix)\($0)") }
        XCTAssertEqual(cs.count, n, "clients connected")
        clients += cs
        return cs
    }

    private func sender(_ port: UInt16, _ tag: String) -> UDPSender {
        let s = UDPSender(port: port, tag: tag)
        senders.append(s)
        return s
    }

    // MARK: - 1. Listeners under live traffic

    /// Apply ports moving only the TCP port under an 8-client flood: the clients stay (their
    /// connections do not depend on the listening socket), every line they sent arrives, the
    /// new port accepts and the old one is closed. It restarted the listener: every client was
    /// disconnected and what it had in flight was lost.
    func testApplyPortsMovingOnlyTCPKeepsTheClients() async throws {
        let app = AppModel.shared
        let udp = TestSockets.freePort(SOCK_DGRAM), tcp1 = TestSockets.freePort(SOCK_STREAM), tcp2 = TestSockets.freePort(SOCK_STREAM)
        startSyslog(udp: udp, tcp: tcp1)
        let cs = connect(8, port: tcp1, prefix: "mt")
        for c in cs { c.flood() }
        await waitUntil { app.syslog.tcpClients == 8 && app.logs.totalReceived > 3_000 }
        app.settings.syslogTCPPort = tcp2
        XCTAssertTrue(app.listenerPortsChanged)
        app.restartListeners()
        XCTAssertNil(app.lastError, app.lastError ?? "")
        XCTAssertEqual([app.syslog.udpPort, app.syslog.tcpPort], [udp, tcp2])
        XCTAssertFalse(app.listenerPortsChanged)
        await spin(300)
        XCTAssertTrue(cs.allSatisfy { !$0.failed.load(ordering: .relaxed) && !$0.peerClosed }, "a TCP client was disconnected")
        XCTAssertEqual(app.syslog.tcpClients, 8)
        let late = try XCTUnwrap(LineClient(port: tcp2, tag: "mtNew"), "the new TCP port accepts")
        clients.append(late)
        late.burst(100)
        XCTAssertNil(TestSockets.connectTCP(tcp1).map { fd -> Int32 in close(fd); return fd }, "the old TCP port still accepts")
        for c in cs { c.stopSending() }
        await assertEveryLine(cs + [late], "TCP moved")
        XCTAssertEqual(app.logs.lost, 0)
    }

    /// Both ports moved at once under a TCP flood and a UDP stream: the clients stay and the
    /// UDP stream loses nothing (the new port is bound before the old one is let go, and what
    /// the old socket still held is read).
    func testApplyPortsMovingBothUnderAFlood() async throws {
        let app = AppModel.shared
        let udp1 = TestSockets.freePort(SOCK_DGRAM), udp2 = TestSockets.freePort(SOCK_DGRAM)
        let tcp1 = TestSockets.freePort(SOCK_STREAM), tcp2 = TestSockets.freePort(SOCK_STREAM)
        startSyslog(udp: udp1, tcp: tcp1)
        let cs = connect(6, port: tcp1, prefix: "mb")
        for c in cs { c.flood() }
        let before = UDPStats.now()
        let u = sender(udp1, "mbu")
        u.flood()
        await waitUntil { app.syslog.tcpClients == 6 && app.logs.totalReceived > 3_000 }
        u.stop()                                    // what follows goes to the old port: nobody's
        app.settings.syslogUDPPort = udp2
        app.settings.syslogTCPPort = tcp2
        app.restartListeners()
        XCTAssertNil(app.lastError, app.lastError ?? "")
        XCTAssertEqual([app.syslog.udpPort, app.syslog.tcpPort], [udp2, tcp2])
        await spin(300)
        XCTAssertTrue(cs.allSatisfy { !$0.failed.load(ordering: .relaxed) && !$0.peerClosed }, "a TCP client was disconnected")
        XCTAssertEqual(app.syslog.tcpClients, 6)
        let u2 = sender(udp2, "mbu2")
        u2.send(200)
        for c in cs { c.stopSending() }
        await assertEveryLine(cs, "both moved")
        await assertUDP(u, since: before, "old UDP port")
        await assertUDP(u2, since: before, "new UDP port")
    }

    /// At the client limit during Apply: the connected clients stay on, a new connection to
    /// the new port is refused while they are all there and accepted once one leaves.
    func testApplyPortsAtTheClientLimit() async throws {
        let app = AppModel.shared
        let udp = TestSockets.freePort(SOCK_DGRAM), tcp1 = TestSockets.freePort(SOCK_STREAM), tcp2 = TestSockets.freePort(SOCK_STREAM)
        if savedSettings == nil { savedSettings = app.settings }
        app.syslog.maxTCPClients = 4
        startSyslog(udp: udp, tcp: tcp1)
        let cs = connect(4, port: tcp1, prefix: "lim")
        for c in cs { c.flood(perSecond: 2_000) }
        await waitUntil { app.syslog.tcpClients == 4 }
        let refused = try XCTUnwrap(LineClient(port: tcp1, tag: "limX"))
        clients.append(refused)
        await waitUntil { refused.peerClosed }
        XCTAssertTrue(refused.peerClosed, "a fifth client is refused")
        XCTAssertEqual(app.syslog.lastError, SyslogServer.clientLimitText(4))
        app.dismissAllErrors()
        app.settings.syslogTCPPort = tcp2
        app.restartListeners()
        XCTAssertEqual(app.syslog.tcpPort, tcp2)
        await spin(200)
        XCTAssertTrue(cs.allSatisfy { !$0.failed.load(ordering: .relaxed) && !$0.peerClosed }, "a client was disconnected")
        XCTAssertEqual(app.syslog.tcpClients, 4)
        let second = try XCTUnwrap(LineClient(port: tcp2, tag: "limY"))
        clients.append(second)
        await waitUntil { second.peerClosed }
        XCTAssertTrue(second.peerClosed, "still at the limit on the new port")
        cs[0].close()
        await waitUntil { app.syslog.tcpClients == 3 }
        XCTAssertNil(app.syslog.lastError, "the limit note goes once a client has left")
        let third = try XCTUnwrap(LineClient(port: tcp2, tag: "limZ"))
        clients.append(third)
        XCTAssertTrue(third.burst(50))
        for c in cs.dropFirst() { c.stopSending() }
        await assertEveryLine(Array(cs.dropFirst()) + [third], "at the limit")
        XCTAssertEqual(numbers("lim0").count, cs[0].sent.load(ordering: .relaxed), "the client that left: every line it sent")
        // At the limit again, then TCP switched off: the limit note goes with it.
        let fifth = try XCTUnwrap(LineClient(port: tcp2, tag: "limW"))
        clients.append(fifth)
        await waitUntil { fifth.peerClosed && app.syslog.lastError != nil }
        XCTAssertEqual(app.syslog.lastError, SyslogServer.clientLimitText(4))
        app.settings.syslogTCPPort = 0
        app.restartListeners()
        XCTAssertNil(app.syslog.lastError, "a limit note with TCP off")
        await waitUntil { app.syslog.tcpClients == 0 }
        XCTAssertEqual(app.syslog.tcpClients, 0)
    }

    /// The trap port and the syslog UDP port trade places while both receive: every datagram
    /// sent before Apply is read (from the socket that is let go too) and nothing is sent to a
    /// port nobody holds after Apply; each listener then gets its own traffic on its new port.
    func testTrapAndSyslogUDPPortsTradePlacesUnderAFlood() async throws {
        let app = AppModel.shared
        let a = TestSockets.freePort(SOCK_DGRAM), b = TestSockets.freePort(SOCK_DGRAM), tcp = TestSockets.freePort(SOCK_STREAM)
        startSyslog(udp: a, tcp: tcp)
        app.settings.trapPort = b
        app.startTraps()
        XCTAssertTrue(app.traps.isRunning)
        let cs = connect(3, port: tcp, prefix: "tr")
        for c in cs { c.flood() }
        let before = UDPStats.now()
        let s = sender(a, "tru")
        let t = UDPSender(port: b, tag: "trt", make: Round18Tests.trapDatagram)
        senders.append(t)
        s.flood(perSecond: 3_000)
        t.flood(perSecond: 2_000)
        await waitUntil { app.logs.totalReceived > 3_000 }
        s.stop(); t.stop()
        app.settings.syslogUDPPort = b
        app.settings.trapPort = a
        app.restartListeners()
        XCTAssertNil(app.lastError, app.lastError ?? "")
        XCTAssertEqual(app.syslog.udpPort, b)
        XCTAssertEqual(app.traps.port, a)
        await spin(200)
        XCTAssertTrue(cs.allSatisfy { !$0.failed.load(ordering: .relaxed) && !$0.peerClosed }, "a TCP client was disconnected")
        await assertUDP(s, since: before, "syslog before the trade")
        let tSent = t.sent.load(ordering: .relaxed)
        await waitUntil(10) { self.trapNumbers("trt").count >= tSent }
        let k = UDPStats.now().since(before)
        XCTAssertGreaterThanOrEqual(trapNumbers("trt").count + k.fullSocket, tSent, "traps sent before the trade")
        XCTAssertEqual(Set(trapNumbers("trt")).count, trapNumbers("trt").count)
        // Each on its new port.
        let s2 = sender(b, "tru2"); s2.send(100)
        let t2 = UDPSender(port: a, tag: "trt2", make: Round18Tests.trapDatagram); senders.append(t2); t2.send(100)
        await assertUDP(s2, since: before, "syslog on the trap's old port")
        await waitUntil { self.trapNumbers("trt2").count >= 100 }
        XCTAssertEqual(trapNumbers("trt2").count, 100)
        for c in cs { c.stopSending() }
        await assertEveryLine(cs, "trade")
    }

    /// The log folder changed, then disk logging switched off and on again, during a TCP flood:
    /// every line is in memory; on disk each line is whole and written once, the two folders
    /// together hold every line up to the switch-off, and per client the lines missing on disk
    /// are one run (the time it was off).
    func testDiskLogFolderChangeAndOffOnDuringATCPFlood() async throws {
        let app = AppModel.shared
        let root = FileManager.default.temporaryDirectory.appending(path: "SheepLogR18Disk-\(UUID().uuidString)", directoryHint: .isDirectory)
        cleanup.append(root)
        let dirA = root.appending(path: "a"), dirB = root.appending(path: "b")
        let udp = TestSockets.freePort(SOCK_DGRAM), tcp = TestSockets.freePort(SOCK_STREAM)
        startSyslog(udp: udp, tcp: tcp)
        app.settings.logDirectory = dirA.path
        app.settings.diskLogging = true
        let cs = connect(4, port: tcp, prefix: "dk")
        for c in cs { c.flood() }
        await waitUntil { app.logs.totalReceived > 2_000 }
        let loggerA = try XCTUnwrap(app.logs.diskLogger)
        app.settings.logDirectory = dirB.path
        await waitUntil { app.logs.totalReceived > 5_000 }
        let loggerB = try XCTUnwrap(app.logs.diskLogger)
        app.settings.diskLogging = false
        await waitUntil { app.logs.totalReceived > 8_000 }
        app.settings.diskLogging = true
        let loggerB2 = try XCTUnwrap(app.logs.diskLogger)
        await waitUntil { app.logs.totalReceived > 11_000 }
        for c in cs { c.stopSending() }
        await assertEveryLine(cs, "disk switches")
        for l in [loggerA, loggerB, loggerB2] { l.sync() }
        var onDisk: [String: [Int]] = [:]
        for dir in [dirA, dirB] {
            for f in (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? [] {
                let text = try String(contentsOf: f, encoding: .utf8)
                for l in text.split(separator: "\n") where l.contains(" dk") {
                    // "<received> 127.0.0.1 <raw>": the raw line whole, at the end.
                    guard let r = l.range(of: "<134>Sep 23 10:15:32 "), let w = l.range(of: "tcp line "), let n = Int(l[w.upperBound...]) else {
                        XCTFail("not a whole line on disk: \(l)"); continue
                    }
                    let tag = String(l[r.upperBound...].prefix { $0 != " " })
                    onDisk[tag, default: []].append(n)
                }
            }
        }
        for c in cs {
            let ns = onDisk[c.tag] ?? []
            XCTAssertEqual(Set(ns).count, ns.count, "\(c.tag): a line written twice")
            let sorted = ns.sorted()
            // One gap at most (the time disk logging was off), and the lines before it complete.
            let gaps = zip(sorted, sorted.dropFirst()).filter { $1 != $0 + 1 }
            XCTAssertLessThanOrEqual(gaps.count, 1, "\(c.tag): lines missing on disk outside the off time: \(gaps.prefix(5))")
            XCTAssertEqual(sorted.first, 0, "\(c.tag): the first lines are on disk")
            XCTAssertEqual(sorted.last, c.sent.load(ordering: .relaxed) - 1, "\(c.tag): the last lines are on disk")
        }
    }

    /// Start all, ⌘⇧L and the sidebar's switch while TCP clients stream: nothing re-binds
    /// the running listener (no client dropped). Stop all right after a burst: every line the
    /// clients' kernels had delivered is kept — the listener reads what its sockets still hold
    /// before closing them (it closed them with unread data, which also reset the peers).
    func testStartAllStopAllWhileTCPClientsStream() async throws {
        let app = AppModel.shared
        let udp = TestSockets.freePort(SOCK_DGRAM), tcp = TestSockets.freePort(SOCK_STREAM)
        startSyslog(udp: udp, tcp: tcp)
        app.settings.trapPort = TestSockets.freePort(SOCK_DGRAM)
        let cs = connect(8, port: tcp, prefix: "sa")
        for c in cs { c.flood() }
        await waitUntil { app.syslog.tcpClients == 8 && app.logs.totalReceived > 2_000 }
        app.startAll()
        app.startSyslogIfStopped()
        XCTAssertTrue(app.traps.isRunning)
        await spin(200)
        XCTAssertTrue(cs.allSatisfy { !$0.failed.load(ordering: .relaxed) && !$0.peerClosed }, "Start all / ⌘⇧L re-bound the listener")
        for c in cs { c.stopSending() }
        await assertEveryLine(cs, "before Stop all")
        // Bursts delivered to this Mac, then Stop all at once.
        let total = await parallel(cs.map { c in { c.burst(20_000) } })
        XCTAssertEqual(total, 8, "every burst acknowledged")
        app.stopAll()
        await assertEveryLine(cs, "Stop all right after a burst")
        XCTAssertFalse(app.syslog.isRunning)
        app.startAll()
        XCTAssertTrue(app.syslog.isRunning)
        let again = try XCTUnwrap(LineClient(port: tcp, tag: "saNew"))
        clients.append(again)
        XCTAssertTrue(again.burst(10))
        await assertEveryLine([again], "after Start all")
    }

    /// A transport that could not be opened at start (TCP held by another program) retried by
    /// Apply ports while UDP keeps receiving a stream: UDP is never closed (it was: the whole
    /// listener restarted, and what arrived meanwhile went to a port nobody held); once the
    /// port is free, Apply opens TCP beside the running UDP socket.
    func testRetryAFailedTransportWhileTheOtherReceives() async throws {
        let app = AppModel.shared
        let udp = TestSockets.freePort(SOCK_DGRAM)
        let held = try XCTUnwrap(TestSockets.holdIPv4(SOCK_STREAM))
        var holder: Int32? = held.fd
        defer { if let h = holder { close(h) } }
        startSyslog(udp: udp, tcp: held.port)
        XCTAssertEqual(app.syslog.tcpPort, 0)
        app.dismissAllErrors()
        let before = UDPStats.now()
        let u = sender(udp, "rtu")
        u.flood()
        await waitUntil { numbers("rtu", udp: true).count > 500 }
        for _ in 0..<5 {
            app.restartListeners()
            XCTAssertEqual(app.lastError, "Syslog still cannot open TCP \(held.port), so it stays on UDP \(udp) only.")
            app.dismissAllErrors()
            await spin(50)
        }
        close(held.fd); holder = nil
        app.restartListeners()
        XCTAssertNil(app.lastError, app.lastError ?? "")
        XCTAssertEqual([app.syslog.udpPort, app.syslog.tcpPort], [udp, held.port])
        XCTAssertNil(app.syslog.lastError, "the start's TCP failure is over")
        let c = try XCTUnwrap(LineClient(port: held.port, tag: "rtc"))
        clients.append(c)
        XCTAssertTrue(c.burst(500))
        await spin(100)
        u.stop()
        await assertUDP(u, since: before, "UDP while TCP was retried")
        await assertEveryLine([c], "TCP opened in place")

        // The trap receiver failing to start while syslog's TCP clients stream: Apply starts
        // it; the clients are not touched.
        let tHeld = try XCTUnwrap(TestSockets.holdIPv4(SOCK_DGRAM))
        app.settings.trapPort = tHeld.port
        app.startTraps()
        XCTAssertFalse(app.traps.isRunning)
        app.dismissAllErrors()
        c.flood()
        close(tHeld.fd)
        app.restartListeners()
        XCTAssertTrue(app.traps.isRunning)
        await spin(200)
        XCTAssertFalse(c.failed.load(ordering: .relaxed) || c.peerClosed)
        c.stopSending()
        await assertEveryLine([c], "traps retried")
    }

    /// ⌘Q (shutdownForQuit) right after TCP bursts and a UDP burst with the disk log on: every
    /// line this Mac had received is in the file — also those still in the sockets' buffers
    /// (they were closed unread) and in the accept queue.
    func testQuitMidFloodWritesEveryReceivedLine() async throws {
        let app = AppModel.shared
        let dir = FileManager.default.temporaryDirectory.appending(path: "SheepLogR18Quit-\(UUID().uuidString)", directoryHint: .isDirectory)
        cleanup.append(dir)
        let udp = TestSockets.freePort(SOCK_DGRAM), tcp = TestSockets.freePort(SOCK_STREAM)
        startSyslog(udp: udp, tcp: tcp)
        app.settings.logDirectory = dir.path
        app.settings.diskLogging = true
        let cs = connect(8, port: tcp, prefix: "q")
        await waitUntil { app.syslog.tcpClients == 8 }
        let before = UDPStats.now()
        let u = sender(udp, "qu")
        let ok = await parallel(cs.map { c in { c.burst(15_000) } } + [{ u.send(5_000); return true }])
        XCTAssertEqual(ok, 9)
        // Connected after the listener's last look: still in the accept queue at ⌘Q.
        let late = try XCTUnwrap(LineClient(port: tcp, tag: "qLate"))
        clients.append(late)
        XCTAssertTrue(late.burst(300))
        app.shutdownForQuit()
        var onDisk: [String: Set<Int>] = [:]
        var lines = 0
        for f in (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? [] {
            for l in try String(contentsOf: f, encoding: .utf8).split(separator: "\n") {
                lines += 1
                guard let r = l.range(of: "<134>Sep 23 10:15:32 "), let w = l.range(of: " line ") else { continue }
                let tag = String(l[r.upperBound...].prefix { $0 != " " })
                if let n = Int(l[w.upperBound...]) { onDisk[tag, default: []].insert(n) }
            }
        }
        for c in cs + [late] {
            XCTAssertEqual(onDisk[c.tag]?.count ?? 0, c.sent.load(ordering: .relaxed), "\(c.tag): lines received before ⌘Q missing on disk")
        }
        let k = UDPStats.now().since(before)
        XCTAssertGreaterThanOrEqual((onDisk["qu"]?.count ?? 0) + k.fullSocket, 5_000, "UDP lines received before ⌘Q missing on disk")
        XCTAssertEqual(lines, onDisk.values.reduce(0) { $0 + $1.count }, "a line written twice")
        app.settings.diskLogging = false
    }

    /// The listener on its own, its queue held up (a slow main thread / parse): what the
    /// kernel holds for it — datagrams past one read event's 20,000, a client still in the
    /// accept queue — when it is stopped is read, not thrown away with the socket.
    func testListenerStopReadsWhatItsSocketsHold() throws {
        let pU = TestSockets.freePort(SOCK_DGRAM), pT = TestSockets.freePort(SOCK_STREAM)
        let udpFD = try SocketFactory.bind(type: SOCK_DGRAM, port: pU).get()
        let tcpFD = try SocketFactory.bind(type: SOCK_STREAM, port: pT).get()
        let got = LockedBox<[String]>([])
        let held = LockedBox<Bool>(false)
        let release = DispatchSemaphore(value: 0)
        let l = SyslogListener(overrides: VendorOverrideMap(), deliver: { batch in
            var first = false
            held.mutate { if !$0 { $0 = true; first = true } }
            if first { release.wait() }             // the listener's queue is held up here
            got.mutate { $0 += batch.map(\.hostname) }
        }, clientsChanged: { _ in })
        l.start(udpFD: udpFD, tcpFD: tcpFD)
        defer { l.stop() }
        TestSockets.sendUDP([Self.udpLine("stall", 0)], to: pU)
        let end = Date().addingTimeInterval(3)
        while !held.value, Date() < end { usleep(5_000) }
        XCTAssertTrue(held.value)
        // Meanwhile: datagrams, and a client in the accept queue with its lines.
        let before = UDPStats.now()
        let s = UDPSender(port: pU, tag: "ku")
        s.send(24_000)
        let c = try XCTUnwrap(LineClient(port: pT, tag: "kt"))
        defer { c.close() }
        XCTAssertTrue(c.burst(2_000))
        let stopped = DispatchSemaphore(value: 0)
        Thread.detachNewThread { l.stop(); stopped.signal() }
        usleep(100_000)                             // stop waits for the queue
        release.signal()
        XCTAssertEqual(stopped.wait(timeout: .now() + 10), .success)
        SyslogListener.waitForParser()              // (round 19: parsed off the listener queue)
        let k = UDPStats.now().since(before)
        let hosts = got.value
        XCTAssertEqual(hosts.filter { $0 == "kt" }.count, 2_000, "a client still in the accept queue at stop")
        XCTAssertEqual(hosts.filter { $0 == "ku" }.count + k.fullSocket, 24_000,
                       "datagrams in the socket at stop (\(k.fullSocket) dropped by the kernel for a full buffer)")
    }

    /// The trap listener's socket at stop: traps it had not read yet are read and handed over.
    func testTrapListenerStopReadsWhatItsSocketHolds() throws {
        let port = TestSockets.freePort(SOCK_DGRAM)
        let got = LockedBox<Int>(0)
        let held = LockedBox<Bool>(false)
        let release = DispatchSemaphore(value: 0)
        let l = try TrapListener(port: port, deliver: { batch in
            var first = false
            held.mutate { if !$0 { $0 = true; first = true } }
            if first { release.wait() }
            got.mutate { $0 += batch.count }
        })
        l.resume()
        let s = UDPSender(port: port, tag: "kt", make: Round18Tests.trapDatagram)
        s.send(1)
        let end = Date().addingTimeInterval(3)
        while !held.value, Date() < end { usleep(5_000) }
        XCTAssertTrue(held.value)
        let before = UDPStats.now()
        s.send(6_000)                               // past one read event's 2,000
        let rest = LockedBox<Int>(0)
        let stopped = DispatchSemaphore(value: 0)
        Thread.detachNewThread { let r = l.cancelAndDrain(); rest.mutate { $0 = r.count }; stopped.signal() }
        usleep(100_000)
        release.signal()
        XCTAssertEqual(stopped.wait(timeout: .now() + 10), .success)
        let k = UDPStats.now().since(before)
        XCTAssertEqual(got.value + rest.value + k.fullSocket, 6_001, "traps in the socket at stop")
    }

    // MARK: - 2. A paused Log

    /// `n` parsed lines from a few hosts, every fourth an error.
    static func batch(_ from: Int, _ n: Int, host: String = "P", address: String = "10.18.0.1") -> [LogEntry] {
        (from..<(from + n)).map { k in
            let sev = k % 4 == 0 ? 3 : 6
            return SyslogParser.parse(RawSyslog(received: Round13Tests.at(Double(k)), sourceAddress: address, sourcePort: 514, transport: .udp,
                                                text: "<\(8 + sev)>Sep 23 10:15:32 \(host)\(k % 3) app: line \(k) " + (sev == 3 ? "link errdisable" : "all good")),
                                      id: LogStore.nextID())
        }
    }

    /// The store's own invariants: the table is a fresh filter of the ring, the counters add up.
    private func assertConsistent(_ what: String, file: StaticString = #filePath, line: UInt = #line) async {
        let logs = AppModel.shared.logs
        await logs.settle()
        let f = LogFilter(query: logs.query, source: logs.selectedSource, mask: logs.severityMask)
        XCTAssertEqual(logs.visible.map(\.id), logs.entries.filter { f.matches($0) }.map(\.id), "\(what): the table is not the filter of the ring", file: file, line: line)
        XCTAssertEqual(logs.severityCounts.reduce(0, +), logs.entries.count, "\(what): severity counts", file: file, line: line)
        XCTAssertEqual(logs.pausedCount, logs.heldEntries.count, "\(what): held count", file: file, line: line)
    }

    /// Paused, the `.*` toggle on and off (a filter whose meaning changes with it), more lines
    /// held meanwhile, Resume: the table is the regex filter of everything, nothing lost.
    func testPausedRegexToggle() async throws {
        let logs = AppModel.shared.logs
        logs.clear()
        logs.limit = 100_000
        logs.ingest(Self.batch(0, 400))
        logs.queryText = "errdis.*le"
        logs.applyQueryText()
        await assertConsistent("literal")
        XCTAssertEqual(logs.visible.count, 0, "as text, nothing says errdis.*le")
        logs.paused = true
        logs.ingest(Self.batch(400, 200))
        logs.regexMode = true
        await assertConsistent("regex on while paused")
        XCTAssertEqual(logs.visible.count, 100)
        logs.ingest(Self.batch(600, 200))
        logs.regexMode = false
        logs.ingest(Self.batch(800, 100))
        logs.regexMode = true
        XCTAssertEqual(logs.pausedCount, 500)
        logs.paused = false
        await assertConsistent("resumed")
        XCTAssertEqual(logs.entries.count, 900)
        XCTAssertEqual(logs.visible.count, 225, "every error line, held ones too")
        logs.regexMode = false
        await assertConsistent("regex off")
        XCTAssertEqual(logs.visible.count, 0)
    }

    /// Paused with lines held, Clear, more lines, Resume: the held lines went with the Clear
    /// (not appended later), the new ones appear; the counters follow.
    func testPausedClearResume() async throws {
        let logs = AppModel.shared.logs
        logs.clear()
        logs.limit = 100_000
        logs.ingest(Self.batch(0, 300))
        logs.paused = true
        logs.ingest(Self.batch(300, 120))
        let received = logs.totalReceived
        logs.clear()
        XCTAssertEqual([logs.entries.count, logs.pausedCount, logs.visible.count], [0, 0, 0])
        XCTAssertTrue(logs.paused, "Clear leaves Pause on")
        logs.ingest(Self.batch(420, 30))
        XCTAssertEqual(logs.pausedCount, 30)
        logs.paused = false
        await assertConsistent("after Clear while paused")
        XCTAssertEqual(logs.entries.map { $0.message }, (420..<450).map { "line \($0) " + ($0 % 4 == 0 ? "link errdisable" : "all good") })
        XCTAssertEqual(logs.totalReceived, received + 30)
    }

    /// Export while paused: the file holds the table as shown (the held lines are not in it) —
    /// and the note says so; the save panel says it before (it said only "the N lines shown",
    /// and "Exported N lines" read as everything received).
    func testExportWhilePausedSaysWhatItHolds() async throws {
        let logs = AppModel.shared.logs
        logs.clear()
        logs.limit = 100_000
        logs.ingest(Self.batch(0, 200))
        logs.paused = true
        logs.ingest(Self.batch(200, 75))
        let url = FileManager.default.temporaryDirectory.appending(path: "SheepLogR18-\(UUID().uuidString).log")
        cleanup.append(url)
        XCTAssertEqual(LogStore.exportPanelMessage(shown: logs.visibleCount, held: logs.pausedCount),
                       "Save the 200 lines shown (the table is paused: the 75 newer lines held back are not included). Name it .csv for a spreadsheet, .log for raw lines.")
        let failure = await logs.export(to: url, csv: false)
        XCTAssertNil(failure)
        let text = try String(contentsOf: url, encoding: .utf8)
        XCTAssertEqual(text.split(separator: "\n").count, 200)
        XCTAssertEqual(logs.exportNote, "Exported 200 lines to \(url.lastPathComponent) — the table as paused; 75 newer lines held back are not in it")
        logs.paused = false
        let again = await logs.export(to: url, csv: false)
        XCTAssertNil(again)
        XCTAssertEqual(logs.exportNote, "Exported 275 lines to \(url.lastPathComponent)")
        XCTAssertEqual(LogStore.exportPanelMessage(shown: 275, held: 0), "Save the 275 lines shown. Name it .csv for a spreadsheet, .log for raw lines.")
    }

    /// Paused with lines held, the buffer lowered below what is kept, Resume: the ring is at
    /// the new limit, the newest lines are the ones kept (held ones included), the rest counted
    /// as rolled out (not lost).
    func testPausedLimitLoweredThenResume() async throws {
        let app = AppModel.shared, logs = app.logs
        if savedSettings == nil { savedSettings = app.settings }
        logs.clear()
        app.settings.logLimit = 10_000
        let dropped = logs.dropped, lost = logs.lost
        logs.ingest(Self.batch(0, 5_000))
        logs.paused = true
        logs.ingest(Self.batch(5_000, 3_000))
        app.settings.logLimit = 1_000                // Settings' field, clamped at 1,000
        XCTAssertEqual(logs.limit, 1_000)
        XCTAssertEqual(logs.entries.count, 1_000)
        XCTAssertEqual(logs.pausedCount, 3_000, "held lines are not trimmed while paused")
        await assertConsistent("lowered while paused")
        logs.paused = false
        await assertConsistent("resumed into a smaller buffer")
        XCTAssertLessThanOrEqual(logs.entries.count, 1_000)
        XCTAssertEqual(logs.entries.last?.message, "line 7999 all good", "the newest line is kept")
        XCTAssertEqual(logs.lost, lost, "rolled out, not lost")
        XCTAssertEqual(logs.dropped - dropped + logs.entries.count, 8_000, "every line is kept or counted")
    }

    /// Paused: lines from a relayed FortiGate held as "Other", its vendor override set, more lines,
    /// Resume: every line of it (held before and after the override) is FortiGate in the table,
    /// the source's error count follows.
    func testPausedOverrideResume() async throws {
        let logs = AppModel.shared.logs
        logs.clear()
        let addr = "10.18.\(Int.random(in: 1..<250)).\(Int.random(in: 1..<250))"     // Sources rows outlive Clear
        func forti(_ k: Int) -> LogEntry {
            SyslogParser.parse(RawSyslog(received: Round13Tests.at(Double(k)), sourceAddress: addr, sourcePort: 514, transport: .udp,
                                         text: "<189>relay: devname=\"FGT-R18\" logid=\"0100032001\" type=\"event\" subtype=\"system\" level=\"error\" msg=\"line \(k)\""),
                               id: LogStore.nextID(), vendorOverride: logs.vendorOverrides.get(addr))
        }
        logs.ingest((0..<10).map(forti))
        logs.paused = true
        logs.ingest((10..<20).map(forti))
        AppModel.shared.setVendorOverride(.fortigate, for: addr)
        defer { AppModel.shared.setVendorOverride(nil, for: addr) }
        logs.ingest((20..<30).map(forti))
        logs.paused = false
        await waitUntil { logs.entries.filter { $0.sourceAddress == addr }.allSatisfy { $0.vendor == .fortigate } }
        await assertConsistent("override while paused")
        let mine = logs.entries.filter { $0.sourceAddress == addr }
        XCTAssertEqual(mine.count, 30)
        XCTAssertEqual(mine.filter { $0.vendor != .fortigate }.count, 0)
        XCTAssertEqual(mine.filter { $0.severity == .error }.count, 30, "level=\"error\" read by the FortiGate parser")
        logs.publishSources()
        XCTAssertEqual(logs.sources.first { $0.address == addr }?.bySeverity[Severity.error.rawValue], 30)
    }

    /// Paused while a vendor's traps arrive unnamed (its MIB not loaded), the MIB imported, then
    /// Resume: the held traps are named too (not only those already in the table), and the
    /// filter on the name finds them all.
    func testPausedTrapsNamedByAMIBImport() async throws {
        let app = AppModel.shared, logs = app.logs
        if savedSettings == nil { savedSettings = app.settings }
        let tmp = FileManager.default.temporaryDirectory.appending(path: "SheepLogR18MIB-\(UUID().uuidString)", directoryHint: .isDirectory)
        cleanup.append(tmp)
        let registry = MIBRegistry()
        registry.userFolderOverride = tmp.appending(path: "mibs", directoryHint: .isDirectory)
        registry.loadNow(bundled: MIBRegistry.bundledURLs())
        app.traps.registry = registry
        defer { app.traps.registry = .shared }
        logs.clear()
        let port = TestSockets.freePort(SOCK_DGRAM)
        app.settings.trapPort = port
        app.startTraps()
        XCTAssertTrue(app.traps.isRunning)
        for n in 0..<10 { TestSockets.sendUDP(Round9InteractionTests.fortiTrap(n), to: port) }
        await waitUntil { logs.entries.filter { $0.transport == .trap }.count == 10 }
        logs.paused = true
        for n in 10..<25 { TestSockets.sendUDP(Round9InteractionTests.fortiTrap(n), to: port) }
        await waitUntil { logs.pausedCount == 15 }
        XCTAssertEqual(logs.pausedCount, 15)
        registry.importFiles([URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appending(path: "Tests/mibs/fortinet")])
        await waitUntil(20) { !registry.isLoading && logs.heldEntries.allSatisfy { $0.program == "fgTrapHaSwitch" } }
        XCTAssertEqual(logs.heldEntries.filter { $0.program != "fgTrapHaSwitch" }.count, 0, "held traps not named")
        XCTAssertEqual(logs.entries.filter { $0.transport == .trap && $0.program != "fgTrapHaSwitch" }.count, 0)
        logs.paused = false
        logs.queryText = "app:fgTrapHaSwitch"
        logs.applyQueryText()
        await assertConsistent("named traps resumed")
        XCTAssertEqual(logs.visible.count, 25)
    }

    // MARK: - 3. Routing traps, IPv6 zones, whole addresses

    static let registry: MIBRegistry = {
        let r = MIBRegistry()
        r.loadNow(bundled: MIBRegistry.bundledURLs())
        return r
    }()

    static func arcs(_ ip: String) -> [UInt32] { ip.split(separator: ".").map { UInt32($0)! } }

    /// A v2c trap from `from` at `t` s after `Round13Tests.t0`, named with the bundled MIBs only.
    static func trapEntry(_ oid: [UInt32], _ vbs: [VarBind], from: String, at t: Double, id: Int) -> LogEntry {
        let trap = SNMPTrap(received: Round13Tests.at(t), sourceAddress: from, sourcePort: 50_000, version: .v2c,
                            community: "public", trapOID: OID(oid), uptime: 100, agentAddress: nil, varBinds: vbs)
        return TrapReceiver.entry(for: trap, registry: registry, id: id)
    }

    static let ospf: [UInt32] = [1, 3, 6, 1, 2, 1, 14]

    /// ospfIfAuthFailure (or, with `config`, ospfIfConfigError) as RFC 4750 sends it:
    /// ospfRouterId, ospfIfIpAddress, ospfAddressLessIf, ospfPacketSrc, ospfConfigErrorType,
    /// ospfPacketType.
    static func ospfAuthTrap(_ t: Double, from: String = "10.1.0.30", src: String = "10.0.12.2", type: Int64 = 6,
                             config: Bool = false, id: Int) -> LogEntry {
        let ifIP = "10.0.12.1"
        return trapEntry(ospf + [16, 2, config ? 4 : 6], [
            VarBind(OID(ospf + [1, 1, 0]), .ipAddress("10.255.0.1")),
            VarBind(OID(ospf + [7, 1, 1] + arcs(ifIP) + [0]), .ipAddress(ifIP)),
            VarBind(OID(ospf + [7, 1, 2] + arcs(ifIP) + [0]), .integer(0)),
            VarBind(OID(ospf + [16, 1, 4, 0]), .ipAddress(src)),
            VarBind(OID(ospf + [16, 1, 2, 0]), .integer(type)),
            VarBind(OID(ospf + [16, 1, 3, 0]), .integer(1)),
        ], from: from, at: t, id: id)
    }

    /// ospfNbrStateChange: ospfRouterId, ospfNbrIpAddr, ospfNbrAddressLessIndex, ospfNbrRtrId, ospfNbrState.
    static func ospfNeighborTrap(_ t: Double, from: String = "10.1.0.30", ip: String = "10.0.12.2", rid: String = "10.0.12.2",
                                 state: Int64, id: Int) -> LogEntry {
        trapEntry(ospf + [16, 2, 2], [
            VarBind(OID(ospf + [1, 1, 0]), .ipAddress("10.255.0.1")),
            VarBind(OID(ospf + [10, 1, 1] + arcs(ip) + [0]), .ipAddress(ip)),
            VarBind(OID(ospf + [10, 1, 2] + arcs(ip) + [0]), .integer(0)),
            VarBind(OID(ospf + [10, 1, 3] + arcs(ip) + [0]), .ipAddress(rid)),
            VarBind(OID(ospf + [10, 1, 6] + arcs(ip) + [0]), .integer(state)),
        ], from: from, at: t, id: id)
    }

    /// bgpEstablished / bgpBackwardTransition (RFC 4273's bgp.0.n, or RFC 1657's bgp.7.n):
    /// bgpPeerLastError and bgpPeerState of the peer's bgpPeerTable row.
    static func bgpTrap(_ t: Double, from: String = "10.1.0.31", peer: String, established: Bool, error: [UInt8] = [0, 0],
                        rfc1657: Bool = false, id: Int) -> LogEntry {
        let bgp: [UInt32] = [1, 3, 6, 1, 2, 1, 15]
        return trapEntry(bgp + [rfc1657 ? 7 : 0, established ? 1 : 2], [
            VarBind(OID(bgp + [3, 1, 14] + arcs(peer)), .octetString(Data(error))),
            VarBind(OID(bgp + [3, 1, 2] + arcs(peer)), .integer(established ? 6 : 1)),
        ], from: from, at: t, id: id)
    }

    static func kindText(_ e: LogEntry) -> String { LineClassifier.trap(e).map { "\($0)" } ?? "nil" }

    /// OSPF-TRAP-MIB and BGP4-MIB traps read into routing facts — with only the bundled MIBs
    /// loaded they are named "mib-2.14.16.2.6" (no dotted OID to look up) and were nothing.
    func testRoutingTrapsAreRead() {
        XCTAssertEqual(Self.ospfAuthTrap(0, id: 1).program, "mib-2.14.16.2.6", "the name the bundled MIBs give it")
        XCTAssertEqual(Self.kindText(Self.ospfAuthTrap(0, id: 1)), Round17Tests.ospfAuth("10.0.12.2"))
        XCTAssertEqual(Self.kindText(Self.ospfAuthTrap(0, type: 5, id: 1)), Round17Tests.ospfAuth("10.0.12.2"), "authTypeMismatch")
        XCTAssertEqual(Self.kindText(Self.ospfAuthTrap(0, type: 6, config: true, id: 1)), Round17Tests.ospfAuth("10.0.12.2"), "ospfIfConfigError authFailure")
        XCTAssertEqual(Self.kindText(Self.ospfAuthTrap(0, type: 2, config: true, id: 1)), "nil", "an area mismatch is no authentication failure")
        XCTAssertEqual(Self.kindText(Self.ospfNeighborTrap(0, rid: "2.2.2.2", state: 1, id: 1)), Round17Tests.ospf("2.2.2.2", false), "Down, by router ID")
        XCTAssertEqual(Self.kindText(Self.ospfNeighborTrap(0, rid: "2.2.2.2", state: 3, id: 1)), Round17Tests.ospf("2.2.2.2", false), "Full → Init: lost")
        XCTAssertEqual(Self.kindText(Self.ospfNeighborTrap(0, rid: "2.2.2.2", state: 8, id: 1)), Round17Tests.ospf("2.2.2.2", true))
        XCTAssertEqual(Self.kindText(Self.ospfNeighborTrap(0, rid: "2.2.2.2", state: 4, id: 1)), "nil", "2-Way: where two DROthers stay")
        func bgp(_ n: String, _ up: Bool) -> String { "routing(proto: \"BGP\", neighbor: \"\(n)\", up: \(up))" }
        XCTAssertEqual(Self.kindText(Self.bgpTrap(0, peer: "10.0.0.2", established: false, error: [4, 0], id: 1)), bgp("10.0.0.2", false))
        XCTAssertEqual(Self.kindText(Self.bgpTrap(0, peer: "10.0.0.2", established: false, error: [4, 0], rfc1657: true, id: 1)), bgp("10.0.0.2", false))
        XCTAssertEqual(Self.kindText(Self.bgpTrap(0, peer: "10.0.0.2", established: true, id: 1)), bgp("10.0.0.2", true))
        XCTAssertEqual(Self.kindText(Self.bgpTrap(0, peer: "10.0.0.2", established: false, error: [2, 5], id: 1)),
                       "routingAuth(proto: \"BGP\", neighbor: \"10.0.0.2\")", "OPEN Message Error / Authentication Failure")
        // A var-bind value with spaces ("02 05") is one value.
        let vbs = RoutingTrap.varBinds("SNMPv2c trap 1.3.6.1.2.1.15.0.2 1.3.6.1.2.1.15.3.1.14.10.0.0.2=02 05 1.3.6.1.2.1.15.3.1.2.10.0.0.2=1")
        XCTAssertEqual(vbs.map { "\($0.oid)=\($0.value)" }, ["1.3.6.1.2.1.15.3.1.14.10.0.0.2=02 05", "1.3.6.1.2.1.15.3.1.2.10.0.0.2=1"])
        XCTAssertEqual(RoutingTrap.number("authFailure(6)"), 6)
        XCTAssertEqual(RoutingTrap.number("full", names: RoutingTrap.ospfStates), 8)
    }

    /// The findings they make: OSPF packets failing authentication, a BGP session down, a BGP
    /// authentication failure — each with a trap evidence filter that shows exactly its traps
    /// (not the other neighbor's, nor the device's link traps); the adjacency / session coming
    /// up afterwards clears it; a device that reports the same by syslog and trap is one finding.
    func testRoutingTrapFindings() throws {
        let noise = [Self.ospfAuthTrap(5, src: "10.0.12.20", id: 90),
                     Self.bgpTrap(6, peer: "10.0.0.20", established: true, id: 91),
                     Self.trapEntry([1, 3, 6, 1, 6, 3, 1, 1, 5, 4], [], from: "10.1.0.30", at: 7, id: 92)]
        let ospfAuth = (0..<3).map { Self.ospfAuthTrap(Double($0) * 20, id: $0 + 1) }
        var r = Round13Tests.analyze(ospfAuth + noise, now: Round13Tests.at(600))
        var f = try XCTUnwrap(r.findings.first { $0.rule == "routing.authFail" && $0.title.contains("10.0.12.2 ") })
        XCTAssertEqual(f.title, "OSPF packets from 10.0.12.2 on 10.1.0.30 fail authentication: 3 rejected (\(Round13Tests.clock(0))–\(Round13Tests.clock(40))).")
        XCTAssertEqual(f.source, .traps)
        XCTAssertTrue(f.detail.contains("the two ends have different keys"), f.detail)
        XCTAssertEqual(f.evidence.map(\.kind), [.traps])
        XCTAssertEqual(try Round16Tests.shown(f.evidence[0].query, ospfAuth + noise), [1, 2, 3], f.evidence[0].query)
        // The adjacency reaching Full afterwards: fixed.
        r = Round13Tests.analyze(ospfAuth + [Self.ospfNeighborTrap(60, state: 8, id: 4)], now: Round13Tests.at(600))
        XCTAssertEqual(r.findings.filter { $0.rule.hasPrefix("routing") }.map(\.title), [])

        // A BGP session down by trap only.
        let down = Self.bgpTrap(0, peer: "10.0.0.2", established: false, error: [4, 0], id: 10)
        r = Round13Tests.analyze([down] + noise, now: Round13Tests.at(600))
        f = try XCTUnwrap(r.findings.first { $0.rule == "routing.neighbor" })
        XCTAssertEqual(f.title, "BGP neighbor 10.0.0.2 on 10.1.0.31 went down at \(Round13Tests.clock(0)) and has not come back.")
        XCTAssertEqual(f.source, .traps)
        XCTAssertEqual(try Round16Tests.shown(f.evidence[0].query, [down] + noise), [10], f.evidence[0].query)
        r = Round13Tests.analyze([down, Self.bgpTrap(30, peer: "10.0.0.2", established: true, id: 11)], now: Round13Tests.at(600))
        XCTAssertEqual(r.findings.filter { $0.rule.hasPrefix("routing") }.map(\.title), [], "established again")

        // BGP OPEN authentication failure.
        let auth = (0..<2).map { Self.bgpTrap(Double($0) * 30, peer: "10.0.0.2", established: false, error: [2, 5], id: 20 + $0) }
        r = Round13Tests.analyze(auth + noise, now: Round13Tests.at(600))
        f = try XCTUnwrap(r.findings.first { $0.rule == "routing.authFail" && $0.title.hasPrefix("BGP") })
        XCTAssertEqual(f.title, "BGP session with 10.0.0.2 on 10.1.0.31 fails authentication: 2 attempts ended with an authentication failure (\(Round13Tests.clock(0))–\(Round13Tests.clock(30))).")
        XCTAssertEqual(try Round16Tests.shown(f.evidence[0].query, auth + noise), [20, 21], f.evidence[0].query)

        // Syslog and trap from the same router: one finding, both kinds of evidence.
        var lines = Round13Tests.Lines()
        lines.nextID = 50
        lines.add(100, "R1", "%OSPF-4-ERRRCV: Received invalid packet: Mismatched Authentication type. Input packet specified type 0, we use type 2 from 10.0.12.2, GigabitEthernet0/1",
                  sev: 4, address: "10.1.0.30")
        let syslog = lines.entries
        r = Round13Tests.analyze(syslog + ospfAuth, now: Round13Tests.at(600))
        let both = r.findings.filter { $0.rule == "routing.authFail" }
        XCTAssertEqual(both.count, 1, both.map(\.title).joined(separator: " | "))
        XCTAssertEqual(both.first?.count, 4)
        XCTAssertEqual(both.first?.evidence.map(\.kind), [.logLines, .traps])
    }

    /// IPv6 link-local addresses with a zone (`fe80::1%en0`, as ndp / ifconfig / Wireshark print
    /// them): a bare search finds the address with that zone or none (not another zone), in any
    /// spelling; `host:` / `ip:` compare the address (a peer's address carries no zone) — they
    /// found nothing. `word:` with a complete address is that address as a whole: it missed
    /// "10.0.0.1:514" and other IPv6 spellings. Brackets, quotes and `[addr]:port` are whole.
    func testIPv6ZonesAndWholeAddressesInBrackets() throws {
        let lines = [
            "neighbor fe80::1%en0 up",            // 1
            "neighbor fe80::1 up",                // 2
            "neighbor fe80::1%en1 up",            // 3
            "neighbor FE80:0:0:0::1%EN0 up",      // 4
            "peer [10.0.0.1]:514 closed",         // 5
            "peer \"10.0.0.1\" closed",           // 6
            "peer 10.0.0.1:514 closed",           // 7
            "peer [2001:db8::1]:514 closed",      // 8
            "peer \"2001:db8::1\" closed",        // 9
            "peer (10.0.0.1) closed",             // 10
            "peer <2001:db8::1> closed",          // 11
            "peer 10.0.0.10:514 closed",          // 12
            "peer [2001:db8::10]:514 closed",     // 13
            "peer '10.0.0.1' closed",             // 14
            "peer [2001:0db8:0::1]:514 closed",   // 15
            "neighbor fe80::1%en01 up",           // 16
            "neighbor fe80::1%Gi0/0/1 up",        // 17
            "src=[fe80::1%en0]:514",              // 18
        ]
        var entries = lines.enumerated().map { Round16Tests.line($0.element, id: $0.offset + 1) }
        entries.append(Round16Tests.line("from link local", id: 100, from: "fe80::1"))
        func shown(_ q: String) throws -> [Int] { try Round16Tests.shown(q, entries) }
        XCTAssertEqual(try shown("fe80::1%en0"), [1, 2, 4, 18])
        XCTAssertEqual(try shown("\"fe80::1%en0\""), [1, 2, 4, 18], "quoted (as FText.quote writes it)")
        XCTAssertEqual(try shown("fe80::1%gi0/0/1"), [2, 17])
        XCTAssertEqual(try shown("fe80::1"), [1, 2, 3, 4, 16, 17, 18])
        XCTAssertEqual(try shown("host:fe80::1%en0"), [100])
        XCTAssertEqual(try shown("ip:fe80::1%en0"), [100])
        XCTAssertEqual(try shown("host:fe80::1"), [100])
        XCTAssertEqual(try shown("-host:fe80::1%en0").contains(100), false)
        XCTAssertEqual(try shown("10.0.0.1"), [5, 6, 7, 10, 14])
        XCTAssertEqual(try shown("word:10.0.0.1"), [5, 6, 7, 10, 14])
        XCTAssertEqual(try shown("2001:db8::1"), [8, 9, 11, 15])
        XCTAssertEqual(try shown("word:2001:db8::1"), [8, 9, 11, 15])
        XCTAssertEqual(try shown("-word:10.0.0.1").filter { $0 <= 18 }, [1, 2, 3, 4, 8, 9, 11, 12, 13, 15, 16, 17, 18])
        XCTAssertEqual(try shown("word:ether1"), [], "a word that is no address stays a word")
        // Parsing: a zone is no part of the address; a zone-less trailing "%" is not one.
        XCTAssertEqual(CIDR.bytes(of: "fe80::1%en0"), CIDR.bytes(of: "fe80::1"))
        XCTAssertTrue(LogMatcher.isFullAddress("fe80::1%en0"))
        XCTAssertFalse(LogMatcher.isFullAddress("fe80::1%"))
        XCTAssertFalse(LogMatcher.isFullAddress("fe80::%en0"), "a prefix with a zone")
        // Packets: ip: / src: / a bare address with a zone match the frame's address.
        let v6: (String) -> [UInt8] = { s in CIDR.bytes(of: s)! }
        let frame = PacketFixture.ether(type: 0x86DD, PacketFixture.ipv6(src: v6("fe80::1"), dst: v6("fe80::2"), next: 17,
                                                                          PacketFixture.udp(5000, 514, Array("hi".utf8))))
        let p = TroubleshootFixture.packet(frame, at: Round13Tests.at(0), id: 1, start: Round13Tests.t0)
        for q in ["ip:fe80::1%en0", "src:fe80::1%en0", "fe80::1%en0", "ip:fe80::2%en0"] {
            XCTAssertTrue(PacketMatcher(try Query.parse(q)).matches(p), q)
        }
        XCTAssertFalse(PacketMatcher(try Query.parse("dst:fe80::1%en0")).matches(p))
    }

    // MARK: - 4. Load

    /// Round 17's worst case for the by-value IPv6 search (100,000 lines, most naming addresses
    /// of the same /32) through the store's ingest with an IPv6 filter in force, re-scans with
    /// the new forms (a zone, `word:` with an address), and the 100k CSV / log export.
    func testLoadIPv6WorstCaseIngestFilterAndExport() async throws {
        let entries = Round17Tests.v6Entries(100_000)
        let store = LogStore()
        store.limit = 100_000
        store.newestFirst = false
        func apply(_ q: String) async -> Double {
            let t = Monotonic.now()
            store.queryText = q
            store.applyQueryText()
            await store.settle()
            return Monotonic.now() - t
        }
        _ = await apply("2001:db8::2")
        let t0 = Monotonic.now()
        var i = 0
        while i < entries.count {
            store.ingest(Array(entries[i..<min(entries.count, i + 2_000)]))
            i += 2_000
        }
        let ingest = Monotonic.now() - t0
        func expected(_ q: String) throws -> Int {
            let f = LogFilter(query: try Query.parse(q), source: nil, mask: Set(Severity.allCases))
            return entries.filter { f.matches($0) }.count
        }
        XCTAssertEqual(store.visible.count, try expected("2001:db8::2"))
        var report = ["ingest 100,000 with «2001:db8::2» in force: \(Int(ingest * 1000)) ms"]
        var worst = 0.0
        for q in ["2001:db8::abc", "fe80::1%en0", "word:2001:db8::1", "host:10.1.0.7 2001:db8:3::5", "\"port 1/1/24\""] {
            let t = await apply(q)
            worst = max(worst, t)
            XCTAssertEqual(store.visible.count, try expected(q), q)
            report.append("re-scan «\(q)»: \(Int(t * 1000)) ms, \(store.visible.count) hits")
        }
        _ = await apply("")
        let t1 = Monotonic.now()
        let csv = store.exportCSV()
        let csvTime = Monotonic.now() - t1
        let t2 = Monotonic.now()
        let text = store.exportText()
        let textTime = Monotonic.now() - t2
        XCTAssertEqual(csv.utf8.reduce(0) { $1 == 0x0A ? $0 + 1 : $0 }, 100_001)
        XCTAssertEqual(text.utf8.reduce(0) { $1 == 0x0A ? $0 + 1 : $0 }, 100_000)
        report.append("export CSV \(Int(csvTime * 1000)) ms, log \(Int(textTime * 1000)) ms")
        print("MEASURE r18 load (\(PerfBudget.skipReason ?? "budgets enforced")): " + report.joined(separator: "; "))
        XCTAssertWithinBudget(ingest, 2.0, "ingest")
        XCTAssertWithinBudget(worst, 0.3, "re-scan")
        XCTAssertWithinBudget(csvTime, 0.6, "CSV")
        XCTAssertWithinBudget(textTime, 0.6, "log")
    }

    // MARK: - 5. Sweep: sequences nobody had scripted

    /// Sequence A: TCP switched off by Apply ports (port 0) while clients stream and UDP
    /// receives, then on again. The clients' lines up to the switch are all kept (read before
    /// they are disconnected), UDP never closes, the re-opened TCP port accepts.
    func testTCPTurnedOffAndOnByApplyUnderAFlood() async throws {
        let app = AppModel.shared
        let udp = TestSockets.freePort(SOCK_DGRAM), tcp = TestSockets.freePort(SOCK_STREAM)
        startSyslog(udp: udp, tcp: tcp)
        let cs = connect(4, port: tcp, prefix: "off")
        await waitUntil { app.syslog.tcpClients == 4 }
        let before = UDPStats.now()
        let u = sender(udp, "offu")
        u.flood()
        let acked = await parallel(cs.map { c in { c.burst(5_000) } })
        XCTAssertEqual(acked, 4)
        app.settings.syslogTCPPort = 0
        app.restartListeners()
        XCTAssertNil(app.lastError, app.lastError ?? "")
        XCTAssertEqual([app.syslog.udpPort, app.syslog.tcpPort], [udp, 0])
        await waitUntil { cs.allSatisfy(\.peerClosed) && app.syslog.tcpClients == 0 }
        XCTAssertTrue(cs.allSatisfy(\.peerClosed), "TCP off disconnects the clients")
        XCTAssertEqual(app.syslog.tcpClients, 0)
        await assertEveryLine(cs, "TCP switched off")
        XCTAssertNil(TestSockets.connectTCP(tcp).map { fd -> Int32 in close(fd); return fd }, "TCP is off")
        app.settings.syslogTCPPort = tcp
        app.restartListeners()
        XCTAssertNil(app.lastError, app.lastError ?? "")
        XCTAssertEqual([app.syslog.udpPort, app.syslog.tcpPort], [udp, tcp])
        let again = try XCTUnwrap(LineClient(port: tcp, tag: "offB"))
        clients.append(again)
        XCTAssertTrue(again.burst(1_000))
        u.stop()
        await assertEveryLine([again], "TCP on again")
        await assertUDP(u, since: before, "UDP through TCP off and on")
    }

    /// A TCP socket added to a running listener (TCP off, then on) still has the stalled-client
    /// check: a client holding an unfinished line is closed after `idleTimeout` and its line
    /// counted as lost. (The timer was made only at start, for a TCP socket given then.)
    func testStalledClientCheckFollowsATCPSocketAddedLater() throws {
        let pU = TestSockets.freePort(SOCK_DGRAM), pT = TestSockets.freePort(SOCK_STREAM)
        let lost = LockedBox<Int>(0)
        let l = SyslogListener(overrides: VendorOverrideMap(), deliver: { _ in }, clientsChanged: { _ in })
        l.idleTimeout = 0.2
        l.onLinesLost = { n in lost.mutate { $0 += n } }
        l.start(udpFD: try SocketFactory.bind(type: SOCK_DGRAM, port: pU).get(), tcpFD: -1)
        defer { l.stop() }
        l.replaceTCP(try SocketFactory.bind(type: SOCK_STREAM, port: pT).get())
        let c = try XCTUnwrap(LineClient(port: pT, tag: "slow"))
        defer { c.close() }
        _ = "<134>Sep 23 10:15:32 slow app: never finished".withCString { send(c.fd, $0, strlen($0), 0) }
        let end = Date().addingTimeInterval(5)
        while !c.peerClosed, Date() < end { usleep(20_000) }
        XCTAssertTrue(c.peerClosed, "the stalled client was not closed")
        XCTAssertEqual(lost.value, 1)
    }

    /// Sequence B: the Log paused while the sidebar's syslog switch goes off and on three times,
    /// TCP devices reconnecting each time and sending a burst: after Resume every line each
    /// device had delivered is in the table once, nothing counted lost.
    func testPausedLogThroughSyslogSwitchOffOnWithReconnectingDevices() async throws {
        let app = AppModel.shared, logs = app.logs
        let udp = TestSockets.freePort(SOCK_DGRAM), tcp = TestSockets.freePort(SOCK_STREAM)
        startSyslog(udp: udp, tcp: tcp)
        logs.paused = true
        let lost = logs.lost
        var all: [LineClient] = []
        for round in 0..<3 {
            let cs = connect(4, port: tcp, prefix: "sw\(round)-")
            all += cs
            await waitUntil { app.syslog.tcpClients == 4 }
            let acked = await parallel(cs.map { c in { c.burst(2_500) } })
            XCTAssertEqual(acked, 4)
            app.stopSyslog()                          // the switch off: reads what the sockets hold
            app.startSyslog()
            XCTAssertTrue(app.syslog.isRunning)
        }
        await waitUntil { logs.pausedCount >= 30_000 }
        XCTAssertEqual(logs.pausedCount, 30_000, "held while paused")
        logs.paused = false
        await assertEveryLine(all, "after Resume")
        XCTAssertEqual(logs.lost, lost)
        await assertConsistent("paused through switch off/on")
    }

    /// Sequence C: the log folder set to one that must not receive files ("/") mid-flood, then
    /// back to a good one: one error sheet (not one per batch), the lines keep arriving in
    /// memory, and from the switch back every line is on disk once.
    func testDiskLogToAnUnsuitableFolderAndBackMidFlood() async throws {
        let app = AppModel.shared
        let dir = FileManager.default.temporaryDirectory.appending(path: "SheepLogR18Bad-\(UUID().uuidString)", directoryHint: .isDirectory)
        cleanup.append(dir)
        let udp = TestSockets.freePort(SOCK_DGRAM), tcp = TestSockets.freePort(SOCK_STREAM)
        startSyslog(udp: udp, tcp: tcp)
        app.settings.logDirectory = dir.path
        app.settings.diskLogging = true
        let cs = connect(3, port: tcp, prefix: "bad")
        for c in cs { c.flood() }
        await waitUntil { app.logs.totalReceived > 1_000 }
        app.settings.logDirectory = "/"
        await waitUntil { app.lastError != nil }
        await waitUntil { app.logs.totalReceived > 4_000 }
        XCTAssertEqual(app.lastError, "Log lines are not being written to disk.")
        XCTAssertTrue(app.lastErrorDetail?.contains("the log folder is set to / (the whole disk)") ?? false, app.lastErrorDetail ?? "")
        XCTAssertEqual(app.pendingErrors.count, 0, "reported once")
        let atSwitchBack = numbers("bad0").count
        app.settings.logDirectory = dir.path
        let good = try XCTUnwrap(app.logs.diskLogger)
        await waitUntil { app.logs.totalReceived > 7_000 }
        for c in cs { c.stopSending() }
        await assertEveryLine(cs, "unsuitable folder and back")
        good.sync()
        var onDisk: [String: [Int]] = [:]
        for f in (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? [] {
            for l in try String(contentsOf: f, encoding: .utf8).split(separator: "\n") {
                guard let r = l.range(of: "<134>Sep 23 10:15:32 "), let w = l.range(of: "tcp line "), let n = Int(l[w.upperBound...]) else { continue }
                onDisk[String(l[r.upperBound...].prefix { $0 != " " }), default: []].append(n)
            }
        }
        for c in cs {
            let ns = onDisk[c.tag] ?? []
            XCTAssertEqual(Set(ns).count, ns.count, "\(c.tag): a line written twice")
            let sent = c.sent.load(ordering: .relaxed)
            XCTAssertTrue(Set(ns).isSuperset(of: Set(min(sent, atSwitchBack + 1_500)..<sent)), "\(c.tag): lines after the switch back missing on disk")
        }
        XCTAssertFileExists(dir)
        XCTAssertFalse(FileManager.default.fileExists(atPath: "/\(DiskLogger.dayString(Date())).log"), "a file was written to /")
    }

    private func XCTAssertFileExists(_ url: URL, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path(percentEncoded: false)), url.path, file: file, line: line)
    }

    /// Stop (the sidebar switch, ⌘Q) while devices keep flooding as fast as they can: reading
    /// what the sockets hold must not turn into reading the flood — the main thread waits for it
    /// (unbounded, the first version of the drain took 45 s here). Measured in Debug on Low
    /// Power: Stop 1.8 s, Apply 2.6 s — without any drain 1.3 s / 0.1 s: most of it is the
    /// listener queue's own backlog of 8 flooding clients, which Stop waits behind.
    func testStopUnderASustainedFloodReturnsPromptly() async throws {
        let app = AppModel.shared
        let udp = TestSockets.freePort(SOCK_DGRAM), tcp = TestSockets.freePort(SOCK_STREAM)
        startSyslog(udp: udp, tcp: tcp)
        let cs = connect(8, port: tcp, prefix: "fast")
        for c in cs { c.flood(perSecond: 5_000_000) }
        let us = (0..<2).map { sender(udp, "fastu\($0)") }
        for u in us { u.flood(perSecond: 5_000_000) }
        await waitUntil { app.logs.totalReceived > 50_000 }
        // Under a sanitizer or on Low Power everything is several times slower; unbounded was 45 s.
        let bound: Double = PerfBudget.enforced ? 4 : 20
        let t = Monotonic.now()
        app.stopSyslog()
        let took = Monotonic.now() - t
        print("MEASURE r18 stop under a sustained flood: \(Int(took * 1000)) ms")
        XCTAssertLessThan(took, bound, "Stop kept reading the flood")
        // Moving the ports under the same flood is bounded too.
        startSyslog(udp: udp, tcp: tcp)
        let cs2 = connect(8, port: tcp, prefix: "fast2")
        for c in cs2 { c.flood(perSecond: 5_000_000) }
        await waitUntil { app.logs.totalReceived > 50_000 }
        app.settings.syslogUDPPort = TestSockets.freePort(SOCK_DGRAM)
        app.settings.syslogTCPPort = 0
        let t2 = Monotonic.now()
        app.restartListeners()
        let took2 = Monotonic.now() - t2
        print("MEASURE r18 Apply (TCP off) under a sustained flood: \(Int(took2 * 1000)) ms")
        XCTAssertLessThan(took2, bound, "Apply kept reading the flood")
    }
}
