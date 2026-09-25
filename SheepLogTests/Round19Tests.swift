import AppKit
import CPcap
import Darwin
import Synchronization
import XCTest
@testable import SheepLog

/// Round 19: the paths rounds 17–18 had not driven with live traffic and an exact account —
/// the trap receiver's port move, a live capture under a lo0 flood (Stop, restart, Save, Clear,
/// Open, ⌘Q), an SNMP walk through port changes, Stop / Apply under a flood, and the disk log's
/// line order across an off / on.
@MainActor
final class Round19Tests: XCTestCase {
    typealias UDPSender = Round18Tests.UDPSender
    typealias UDPStats = Round18Tests.UDPStats
    typealias LineClient = Round18Tests.LineClient

    private var cleanup: [URL] = []
    private var savedSettings: AppSettings?
    private var senders: [UDPSender] = []
    private var clients: [LineClient] = []
    private var holders: [Int32] = []

    override func tearDown() async throws {
        for s in senders { s.stop() }
        senders = []
        for c in clients { c.close() }
        clients = []
        for h in holders { close(h) }
        holders = []
        let app = AppModel.shared
        app.stopCapture()
        app.stopSyslog()
        app.stopTraps()
        SyslogListener.waitForParser()
        if let s = savedSettings { app.settings = s; savedSettings = nil }
        app.dismissAllErrors()
        app.packets.paused = false
        app.packets.queryText = ""
        app.packets.applyQueryNow(synchronous: true)
        app.packets.clear()
        app.logs.paused = false
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

    private func keepSettings() {
        let app = AppModel.shared
        if savedSettings == nil { savedSettings = app.settings }
        app.dismissAllErrors()
        app.settings.logLimit = AppModel.maxLogLimit     // (settings win over logs.limit at every change)
    }

    private func hold(_ type: Int32) throws -> (fd: Int32, port: UInt16) {
        let h = try XCTUnwrap(TestSockets.holdIPv4(type))
        holders.append(h.fd)
        return h
    }

    private func trapSender(_ port: UInt16, _ tag: String) -> UDPSender {
        let s = UDPSender(port: port, tag: tag, make: Round18Tests.trapDatagram)
        senders.append(s)
        return s
    }

    /// The trap numbers of `tag` in memory.
    private func trapNumbers(_ tag: String) -> [Int] {
        AppModel.shared.logs.entries.compactMap { e -> Int? in
            guard e.transport == .trap, let r = e.message.range(of: "\(tag)-") else { return nil }
            return Int(e.message[r.upperBound...].prefix { $0.isNumber })
        }
    }

    /// The syslog numbers of `tag` ("udp line n" / "tcp line n") in memory.
    private func lineNumbers(_ tag: String, _ word: String) -> [Int] {
        AppModel.shared.logs.entries.compactMap { e -> Int? in
            guard e.hostname == tag, let r = e.message.range(of: word) else { return nil }
            return Int(e.message[r.upperBound...])
        }
    }

    /// Traps sent to a port that stayed open all along: every one is in memory once, or was
    /// dropped by the kernel for a full buffer.
    private func assertEveryTrap(_ s: UDPSender, since before: UDPStats, _ what: String,
                                 file: StaticString = #filePath, line: UInt = #line) async {
        let sent = s.sent.load(ordering: .relaxed)
        await waitUntil(10) { self.trapNumbers(s.tag).count >= sent }
        let got = trapNumbers(s.tag)
        let k = UDPStats.now().since(before)
        XCTAssertEqual(Set(got).count, got.count, "\(what): a trap twice", file: file, line: line)
        XCTAssertGreaterThanOrEqual(got.count + k.fullSocket, sent,
                                    "\(what): sent \(sent), \(got.count) in memory, \(k.fullSocket) dropped for a full buffer (\(k.noPort) to closed ports, system-wide)",
                                    file: file, line: line)
    }

    private func startTraps(_ port: UInt16) {
        let app = AppModel.shared
        app.settings.trapPort = port
        app.startTraps()
        XCTAssertTrue(app.traps.isRunning, app.traps.lastError ?? "")
        XCTAssertEqual(app.traps.port, port)
    }

    private func startSyslog(udp: UInt16, tcp: UInt16) {
        let app = AppModel.shared
        app.settings.syslogUDPPort = udp
        app.settings.syslogTCPPort = tcp
        app.startSyslog()
        XCTAssertTrue(app.syslog.isRunning, app.syslog.lastError ?? "")
    }

    // MARK: - 1. The trap receiver's port move

    /// Apply ports with a trap port another program holds, ten times, while a device sends a
    /// trap storm to the current port: the receiver stays on its port and every trap is in
    /// memory. It stopped, failed to bind the new port and bound the old one again: 2,762 of
    /// 13,747 traps went to a port nobody held in between.
    func testTrapMoveToAPortInUseLosesNoTrap() async throws {
        let app = AppModel.shared
        keepSettings()
        let p1 = TestSockets.freePort(SOCK_DGRAM)
        startTraps(p1)
        let held = try hold(SOCK_DGRAM)
        let before = UDPStats.now()
        let t = trapSender(p1, "inuse")
        t.flood(perSecond: 3_000)
        await waitUntil { self.trapNumbers("inuse").count > 300 }
        for _ in 0..<10 {
            app.settings.trapPort = held.port
            app.restartListeners()
            XCTAssertEqual(app.lastError, "The trap receiver could not move to UDP \(held.port), so it stays on UDP \(p1).")
            XCTAssertTrue(app.lastErrorDetail?.contains("lsof -nP -iUDP:\(held.port)") == true, app.lastErrorDetail ?? "")
            XCTAssertTrue(app.traps.isRunning)
            XCTAssertEqual(app.traps.port, p1)
            app.dismissAllErrors()
            await spin(30)
        }
        t.stop()
        await assertEveryTrap(t, since: before, "failed moves")
    }

    /// A successful move under a storm: what the old port received before Apply is read (from
    /// the socket that is let go too), the new port takes traps from the moment Apply returns —
    /// a device already sending there loses nothing after that — and the old one is closed.
    func testTrapMoveInPlaceUnderAStorm() async throws {
        let app = AppModel.shared
        keepSettings()
        let p1 = TestSockets.freePort(SOCK_DGRAM), p2 = TestSockets.freePort(SOCK_DGRAM)
        startTraps(p1)
        let before = UDPStats.now()
        let old = trapSender(p1, "mvold")
        old.flood(perSecond: 3_000)
        await waitUntil { self.trapNumbers("mvold").count > 500 }
        let early = trapSender(p2, "mvnew")          // a device already set to the new port
        early.flood(perSecond: 2_000)
        await spin(100)
        let sentBefore = old.sent.load(ordering: .relaxed)
        app.settings.trapPort = p2
        app.restartListeners()
        XCTAssertNil(app.lastError, app.lastError ?? "")
        XCTAssertEqual(app.traps.port, p2)
        let newAfter = early.sent.load(ordering: .relaxed)
        await spin(300)
        old.stop()
        early.stop()
        let sentNew = early.sent.load(ordering: .relaxed)
        await waitUntil(10) { self.trapNumbers("mvold").filter { $0 < sentBefore }.count >= sentBefore }
        let k = UDPStats.now().since(before)
        let gotOld = Set(trapNumbers("mvold"))
        XCTAssertGreaterThanOrEqual(gotOld.filter { $0 < sentBefore }.count + k.fullSocket, sentBefore,
                                    "traps sent to the old port before Apply")
        await waitUntil(10) { Set(self.trapNumbers("mvnew")).filter { $0 >= newAfter }.count >= sentNew - newAfter }
        let gotNew = trapNumbers("mvnew")
        XCTAssertEqual(Set(gotNew).count, gotNew.count, "a trap twice")
        XCTAssertGreaterThanOrEqual(Set(gotNew).filter { $0 >= newAfter }.count + k.fullSocket, sentNew - newAfter,
                                    "traps sent to the new port after Apply")
        // The old port is closed.
        let stale = trapSender(p1, "mvstale")
        stale.send(20)
        await spin(300)
        XCTAssertTrue(trapNumbers("mvstale").isEmpty, "the old port still listens")
    }

    /// Traps onto the UDP port syslog leaves in the same Apply (syslog moves first, then the
    /// trap socket is swapped in place) under storms on both: nothing sent to a port that stays
    /// open is lost; each then receives on its new port. And when syslog cannot move (its new
    /// port is held), the trap receiver keeps its port — SheepLog's own clash is explained.
    func testTrapsOntoThePortSyslogLeavesUnderStorms() async throws {
        let app = AppModel.shared
        keepSettings()
        let a = TestSockets.freePort(SOCK_DGRAM), b = TestSockets.freePort(SOCK_DGRAM), c = TestSockets.freePort(SOCK_DGRAM)
        let tcp = TestSockets.freePort(SOCK_STREAM)
        startSyslog(udp: a, tcp: tcp)
        startTraps(b)
        let cs = (0..<3).compactMap { LineClient(port: tcp, tag: "own\($0)") }
        clients += cs
        for cl in cs { cl.flood() }
        let before = UDPStats.now()
        let t = trapSender(b, "ownt")
        t.flood(perSecond: 3_000)
        await waitUntil { self.trapNumbers("ownt").count > 300 }

        // Syslog cannot move (c is held): the traps stay on b, their storm untouched.
        let heldC = try XCTUnwrap(TestSockets.holdIPv4(SOCK_DGRAM, port: c))
        app.settings.syslogUDPPort = c
        app.settings.trapPort = a
        app.restartListeners()
        XCTAssertEqual(app.syslog.udpPort, a)
        XCTAssertEqual(app.traps.port, b)
        XCTAssertTrue(app.traps.isRunning)
        XCTAssertTrue(app.lastError?.hasPrefix("Syslog could not move to UDP \(c)") == true, app.lastError ?? "nil")
        let trapSheet = app.pendingErrors.first
        XCTAssertEqual(trapSheet?.message, "The trap receiver could not move to UDP \(a), so it stays on UDP \(b).")
        XCTAssertTrue(trapSheet?.detail?.contains("SheepLog’s own syslog listener is listening there") == true, trapSheet?.detail ?? "")
        app.dismissAllErrors()
        close(heldC.fd)

        // Now it can: syslog to c, traps onto a.
        let beforeMove = t.sent.load(ordering: .relaxed)
        app.restartListeners()
        XCTAssertNil(app.lastError, app.lastError ?? "")
        XCTAssertEqual(app.syslog.udpPort, c)
        XCTAssertEqual(app.traps.port, a)
        await spin(200)
        t.stop()
        // b closed only now, in the second Apply: everything sent to it before is in memory.
        await waitUntil(10) { Set(self.trapNumbers("ownt")).filter { $0 < beforeMove }.count >= beforeMove }
        let k = UDPStats.now().since(before)
        let got = trapNumbers("ownt")
        XCTAssertEqual(Set(got).count, got.count, "a trap twice")
        XCTAssertGreaterThanOrEqual(Set(got).filter { $0 < beforeMove }.count + k.fullSocket, beforeMove,
                                    "traps sent to the trap port before it moved")
        let t2 = trapSender(a, "ownt2"); t2.send(100)
        let s2 = UDPSender(port: c, tag: "owns2"); senders.append(s2); s2.send(100)
        await waitUntil { self.trapNumbers("ownt2").count >= 100 && self.lineNumbers("owns2", "udp line ").count >= 100 }
        XCTAssertEqual(trapNumbers("ownt2").count, 100)
        XCTAssertEqual(lineNumbers("owns2", "udp line ").count, 100)
        XCTAssertTrue(cs.allSatisfy { !$0.failed.load(ordering: .relaxed) && !$0.peerClosed }, "a TCP client was disconnected")
        for cl in cs { cl.stopSending() }
        for cl in cs {
            let n = cl.sent.load(ordering: .relaxed)
            await waitUntil(15) { self.lineNumbers(cl.tag, "tcp line ").count >= n }
            XCTAssertEqual(Set(lineNumbers(cl.tag, "tcp line ")), Set(0..<n), "\(cl.tag)")
        }
    }

    // MARK: - 2. A live capture under a lo0 flood

    /// A datagram whose payload says `R19|tag|n|`.
    nonisolated static func capDatagram(_ tag: String, _ n: Int) -> [UInt8] { Array("R19|\(tag)|\(n)|".utf8) }

    nonisolated static func capNumber(_ p: Packet, tag: String) -> Int? {
        let marker = Data("R19|\(tag)|".utf8)
        guard let r = p.data.range(of: marker) else { return nil }
        let rest = p.data[r.upperBound...].prefix { $0 != UInt8(ascii: "|") }
        return Int(String(decoding: rest, as: UTF8.self))
    }

    private func capNumbers(_ tag: String, in packets: [Packet]? = nil) -> [Int] {
        (packets ?? AppModel.shared.packets.packets).compactMap { Self.capNumber($0, tag: tag) }
    }

    private func requireCapture() throws {
        guard FileManager.default.isReadableFile(atPath: "/dev/bpf0") else { throw XCTSkip("/dev/bpf0 is not readable") }
    }

    /// A UDP port with a socket bound on it that is never read (no ICMP port-unreachable on
    /// lo0), and a live capture of `udp and dst port <it>` on lo0 through the app.
    private func startLoopCapture(limit: Int = AppModel.maxPacketLimit) throws -> UInt16 {
        try requireCapture()
        let app = AppModel.shared
        keepSettings()
        let sink = try hold(SOCK_DGRAM)
        app.packets.clear()
        app.settings.packetLimit = limit
        app.settings.captureInterface = "lo0"
        app.settings.captureFilter = "udp and dst port \(sink.port)"
        app.startCapture()
        app.dismissAllErrors()                 // lo0: "does not support promiscuous mode"
        XCTAssertTrue(app.capture.isRunning, app.capture.lastError ?? "")
        return sink.port
    }

    private func capSender(_ port: UInt16, _ tag: String) -> UDPSender {
        let s = UDPSender(port: port, tag: tag, make: Round19Tests.capDatagram)
        senders.append(s)
        return s
    }

    /// lo0 opened as the engine opens it, `udp and dst port <port>`, with a kernel buffer of
    /// `buffer` bytes.
    nonisolated static func openLoop(port: UInt16, buffer: Int32) -> (handle: PcapHandle, linkType: Int32)? {
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        guard let p = pcap_create("lo0", &errbuf) else { return nil }
        pcap_set_snaplen(p, 262_144)
        pcap_set_promisc(p, 0)
        pcap_set_timeout(p, 100)
        pcap_set_buffer_size(p, buffer)
        pcap_set_immediate_mode(p, 1)
        guard pcap_activate(p) >= 0 else { pcap_close(p); return nil }
        var program = bpf_program()
        guard pcap_compile(p, &program, "udp and dst port \(port)", 1, bpf_u_int32(PCAP_NETMASK_UNKNOWN)) == 0 else {
            pcap_close(p); return nil
        }
        let set = pcap_setfilter(p, &program)
        pcap_freecode(&program)
        guard set == 0 else { pcap_close(p); return nil }
        let lt = pcap_datalink(p)
        return (PcapHandle(p), lt)
    }

    /// The read loop held up (its first batch waits, as behind a busy consumer) while packets
    /// pile up in the kernel, then stopped: every packet captured before Stop is handed over,
    /// or counted as dropped by the kernel in the last reading. The loop ended at Stop and left
    /// BPF's buffers unread — 30,000 packets gone without a trace, and with a small buffer the
    /// drops of the run's last second were never counted.
    func testCaptureStopReadsWhatTheKernelHeld() throws {
        try requireCapture()
        for (buffer, name) in [(Int32(16 << 20), "16 MB"), (Int32(256 << 10), "256 KB")] {
            let sink = try hold(SOCK_DGRAM)
            let (handle, lt) = try XCTUnwrap(Self.openLoop(port: sink.port, buffer: buffer))
            let got = LockedBox<[Int]>([])
            let held = LockedBox(false)
            let release = DispatchSemaphore(value: 0)
            let finalDrops = LockedBox<Int?>(nil)
            let tag = "kh\(buffer)"
            let reader = CaptureReader(handle: handle, linkType: lt, deliver: { batch in
                var first = false
                held.mutate { if !$0 { $0 = true; first = true } }
                if first { release.wait() }
                got.mutate { $0 += batch.compactMap { Round19Tests.capNumber($0, tag: tag) } }
            }, stats: { _ in }, finalStats: { d in finalDrops.mutate { $0 = d } }, failed: { _ in })
            reader.start()
            let s = capSender(sink.port, tag)
            s.send(1)
            let end = Date().addingTimeInterval(5)
            while !held.value, Date() < end { usleep(5_000) }
            XCTAssertTrue(held.value, name)
            s.send(30_000)                              // into BPF while the loop waits
            reader.requestStop()
            handle.breakLoop()
            release.signal()
            reader.join(timeout: 30)
            let n = got.value
            let drops = finalDrops.value ?? 0
            print("MEASURE r19 capture stop with \(name): 30,001 sent, \(n.count) read, \(drops) dropped by the kernel")
            XCTAssertNotNil(finalDrops.value, "\(name): the last reading of the drops")
            XCTAssertEqual(Set(n).count, n.count, "\(name): a packet twice")
            XCTAssertEqual(n.count + drops, 30_001, "\(name): captured = handed over + kernel drops")
            if buffer == 16 << 20 { XCTAssertEqual(drops, 0) } else { XCTAssertGreaterThan(drops, 0) }
        }
    }

    /// Stop under an 8-thread lo0 flood, three times: everything each sender had sent when Stop
    /// was pressed is in memory once (or counted as a kernel drop); frame numbers are 1…n.
    func testCaptureStopUnderALoopFlood() async throws {
        let app = AppModel.shared
        let port = try startLoopCapture()
        for round in 0..<3 {
            let ss = (0..<8).map { capSender(port, "fl\(round)x\($0)") }
            for s in ss { s.flood(perSecond: 5_000_000) }
            await spin(1_200)
            let ks = ss.map { $0.sent.load(ordering: .relaxed) }
            app.stopCapture()
            for s in ss { s.stop() }
            await spin(300)
            await waitUntil(10) { zip(ss, ks).allSatisfy { s, k in self.capNumbers(s.tag).filter { $0 < k }.count >= k } }
            var missing = 0
            for (s, k) in zip(ss, ks) {
                let n = capNumbers(s.tag)
                XCTAssertEqual(Set(n).count, n.count, "\(s.tag): a packet twice")
                missing += k - Set(n.filter { $0 < k }).count
            }
            print("MEASURE r19 capture stop under a flood \(round): \(ks.reduce(0, +)) sent before Stop, \(missing) missing, \(app.packets.lost) lost, \(app.capture.kernelDropped) kernel drops")
            XCTAssertLessThanOrEqual(missing, app.packets.lost, "round \(round): captured before Stop, neither shown nor counted")
            let ids = app.packets.packets.map(\.id)
            XCTAssertEqual(ids, Array(1..<(ids.count + 1)))
            XCTAssertEqual(app.packets.totalReceived, app.packets.packets.count)
            app.packets.clear()
            app.startCapture(); app.dismissAllErrors()
            XCTAssertTrue(app.capture.isRunning)
        }
    }

    private func tempURL(_ name: String) -> URL {
        let dir = FileManager.default.temporaryDirectory.appending(path: "SheepLogR19-\(UUID().uuidString)", directoryHint: .isDirectory)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        cleanup.append(dir)
        return dir.appending(path: name)
    }

    private func readFile(_ url: URL) throws -> [Packet] {
        var out: [Packet] = []
        _ = try PcapFile.read(url) { out += $0 }
        return out
    }

    private func save(_ url: URL) async -> String? {
        let done = LockedBox<String??>(nil)
        AppModel.shared.packets.save(to: url) { e in done.mutate { $0 = .some(e) } }
        await waitUntil(30) { done.value != nil }
        return done.value ?? "never finished"
    }

    /// Save while a flood is captured: the file holds exactly what the table showed when Save
    /// was pressed (count, first and last packet) — unfiltered, right after a filter change
    /// (it wrote the previous filter's 106,000 packets of every conversation while the filter
    /// shown matched one), and paused (without the packets Pause holds back).
    func testSaveWhileCapturingWritesWhatIsShown() async throws {
        let app = AppModel.shared
        let port = try startLoopCapture()
        let ss = (0..<4).map { capSender(port, "sv\($0)") }
        for s in ss { s.flood(perSecond: 20_000) }
        await waitUntil(20) { app.packets.packets.count > 80_000 }

        let shown = app.packets.packetsToSave
        let a = tempURL("a.pcap")
        let e1 = await save(a)
        XCTAssertNil(e1)
        let fa = try readFile(a)
        XCTAssertEqual(fa.count, shown.count)
        XCTAssertEqual(fa.first?.data, shown.first?.data)
        XCTAssertEqual(fa.last?.data, shown.last?.data, "the last packet shown")

        // Right after a filter change: one sender's packets (by its source port).
        let one = try XCTUnwrap(app.packets.packets.first { Self.capNumber($0, tag: "sv1") != nil }?.decoded.sourcePort)
        app.packets.queryText = "sport:\(one)"
        app.packets.applyQueryNow()
        let b = tempURL("b.pcap")
        let ring = app.packets.packets
        let e2 = await save(b)
        XCTAssertNil(e2)
        let fb = try readFile(b)
        let expected = ring.filter { $0.decoded.sourcePort == one }
        XCTAssertEqual(fb.count, expected.count, "the filter in force when Save was pressed")
        XCTAssertTrue(fb.allSatisfy { Self.capNumber($0, tag: "sv1") != nil }, "another conversation in the file")
        XCTAssertEqual(fb.last?.data, expected.last?.data)
        await waitUntil { app.packets.visible.allSatisfy { $0.decoded.sourcePort == one } }

        // Paused: the table as it stands.
        app.packets.queryText = ""
        app.packets.applyQueryNow(synchronous: true)
        app.packets.paused = true
        await spin(300)
        let frozen = app.packets.visible
        XCTAssertGreaterThan(app.packets.pausedCount, 0)
        let c = tempURL("c.pcap")
        let e3 = await save(c)
        XCTAssertNil(e3)
        let fc = try readFile(c)
        XCTAssertEqual(fc.count, frozen.count)
        XCTAssertEqual(fc.last?.data, frozen.last?.data, "the last packet shown while paused")
        app.packets.paused = false
        for s in ss { s.stop() }
    }

    /// Clear, an interface change + restart and a file opened, each while a flood is captured,
    /// then ⌘Q with a Save still writing: Clear splits the flood into what was before (gone
    /// with it) and after (frames from 1), nothing missing or doubled; a restart starts again at
    /// frame 1 with none of the old run's packets landing later; a file replaces the capture
    /// and no live packet follows it; ⌘Q waits for the Save, whose file is whole.
    func testClearRestartOpenAndQuitWhileCapturing() async throws {
        let app = AppModel.shared
        let port = try startLoopCapture()
        let ss = (0..<4).map { capSender(port, "cl\($0)") }
        for s in ss { s.flood(perSecond: 20_000) }
        await waitUntil(20) { app.packets.packets.count > 50_000 }

        // Clear.
        let before = app.packets.packets
        let lostBefore = app.packets.lost          // (Clear starts the count again)
        app.packets.clear()
        await spin(800)
        let ks = ss.map { $0.sent.load(ordering: .relaxed) }
        app.stopCapture()
        await spin(300)
        await waitUntil(10) { zip(ss, ks).allSatisfy { s, k in
            Set(self.capNumbers(s.tag, in: before)).union(self.capNumbers(s.tag)).filter { $0 < k }.count >= k } }
        let after = app.packets.packets
        for (s, k) in zip(ss, ks) {
            let a = Set(capNumbers(s.tag, in: before)), b = capNumbers(s.tag, in: after)
            XCTAssertTrue(a.isDisjoint(with: b), "\(s.tag): a packet before and after Clear")
            XCTAssertEqual(Set(b).count, b.count)
            XCTAssertLessThanOrEqual(k - a.union(b).filter { $0 < k }.count, lostBefore + app.packets.lost,
                                     "\(s.tag): lost across Clear (\(lostBefore) before it, kernel drops \(app.capture.kernelDropped))")
        }
        XCTAssertEqual(after.map(\.id), Array(1..<(after.count + 1)), "frames from 1 after Clear")
        XCTAssertEqual(app.packets.totalReceived, after.count)

        // Interface change + restart, and back.
        app.startCapture(); app.dismissAllErrors()
        await spin(300)
        let other = CaptureEngine.interfaces().first { !$0.isLoopback && $0.isUp }?.name ?? "en0"
        app.settings.captureInterface = other
        app.startCapture(); app.dismissAllErrors()
        XCTAssertTrue(app.capture.isRunning, app.capture.lastError ?? "")
        XCTAssertEqual(app.capture.interfaceName, other)
        await spin(500)
        XCTAssertTrue(app.packets.packets.isEmpty, "the lo0 run's packets landed in the \(other) run")
        app.settings.captureInterface = "lo0"
        app.startCapture(); app.dismissAllErrors()
        await spin(800)
        let ks2 = ss.map { $0.sent.load(ordering: .relaxed) }
        app.stopCapture()
        await spin(300)
        let ids = app.packets.packets.map(\.id)
        XCTAssertEqual(ids.first, 1)
        XCTAssertEqual(ids, Array(1..<(ids.count + 1)))
        for (s, k) in zip(ss, ks2) {
            let n = capNumbers(s.tag).sorted()
            let gaps = zip(n, n.dropFirst()).filter { $1 != $0 + 1 }.count
            XCTAssertLessThanOrEqual(gaps, app.packets.lost, "\(s.tag): a hole in the restarted run")
            XCTAssertEqual(n.last.map { $0 >= k - 1 }, true, "\(s.tag): the last packets before Stop")
        }

        // A file opened while capturing.
        app.startCapture(); app.dismissAllErrors()
        await spin(300)
        let pcap = CaptureGroundTruthTests.pcapDir.appending(path: "dns-mdns.pcap")
        let fileCount = try readFile(pcap).count
        PacketFileActions.load(pcap)
        XCTAssertFalse(app.capture.isRunning)
        await waitUntil { !app.packets.isLoading }
        await spin(800)
        XCTAssertEqual(app.packets.packets.count, fileCount)
        XCTAssertEqual(app.packets.totalReceived, fileCount)
        XCTAssertFalse(app.packets.packets.contains { p in (0..<4).contains { Self.capNumber(p, tag: "cl\($0)") != nil } },
                       "a live packet after the file")

        // ⌘Q with a Save of 150,000 packets still writing.
        app.packets.clear()
        app.startCapture(); app.dismissAllErrors()
        await waitUntil(20) { app.packets.packets.count > 150_000 }
        let q = tempURL("q.pcap")
        let snap = app.packets.packetsToSave
        app.packets.save(to: q) { _ in }
        app.shutdownForQuit()
        XCTAssertFalse(app.capture.isRunning)
        let fq = try readFile(q)
        XCTAssertEqual(fq.count, snap.count, "the file saved at ⌘Q")
        XCTAssertEqual(fq.last?.data, snap.last?.data)
        for s in ss { s.stop() }
    }

    // MARK: - 3. An SNMP walk through port changes

    private static let labPort: UInt16 = {
        let env = ProcessInfo.processInfo.environment
        return (env["SNMP_LAB_PORT"] ?? env["TEST_RUNNER_SNMP_LAB_PORT"]).flatMap(UInt16.init) ?? 1161
    }()

    /// `Tests/snmp-lab.sh` answering (SHEEPLOG_SNMP_LAB=1, or a Get within a second).
    private func labClient() async throws -> SNMPClient {
        let target = SNMPTarget(host: "127.0.0.1", port: Self.labPort, timeout: 2, retries: 1)
        let client = SNMPClient(target: target, credentials: SNMPCredentials(version: .v2c, community: "public"), engines: EngineCache())
        let env = ProcessInfo.processInfo.environment
        if env["SHEEPLOG_SNMP_LAB"] == "1" || env["TEST_RUNNER_SHEEPLOG_SNMP_LAB"] == "1" { return client }
        let probe = SNMPClient(target: SNMPTarget(host: "127.0.0.1", port: Self.labPort, timeout: 1, retries: 0),
                               credentials: SNMPCredentials(version: .v2c, community: "public"), engines: EngineCache())
        guard (try? await probe.get([.sysName])) != nil else {
            throw XCTSkip("Start Tests/snmp-lab.sh (or set SHEEPLOG_SNMP_LAB=1) to run the live walk.")
        }
        return client
    }

    /// Whole-tree and Interfaces walks against the lab while Apply ports moves the syslog and
    /// trap ports back and forth under floods and the trap receiver is switched off and on:
    /// each walk ends with the var-binds a quiet walk got, in the same order.
    func testSNMPWalkThroughPortChanges() async throws {
        let client = try await labClient()
        let app = AppModel.shared
        keepSettings()
        let quiet = try await client.walk(OID([1, 3, 6, 1])).varBinds.map(\.oid)
        let quietIf = try await client.walk(.ifTable, cap: SNMPClient.interfaceWalkCap).varBinds.map(\.oid)
        XCTAssertGreaterThan(quiet.count, 1_000)
        let ports = (0..<2).map { _ in (udp: TestSockets.freePort(SOCK_DGRAM), tcp: TestSockets.freePort(SOCK_STREAM), trap: TestSockets.freePort(SOCK_DGRAM)) }
        startSyslog(udp: ports[0].udp, tcp: ports[0].tcp)
        startTraps(ports[0].trap)
        let cs = (0..<4).compactMap { LineClient(port: ports[0].tcp, tag: "snmp\($0)") }
        clients += cs
        for c in cs { c.flood() }
        let u = UDPSender(port: ports[0].udp, tag: "snmpu"); senders.append(u); u.flood()
        let t = trapSender(ports[0].trap, "snmpt"); t.flood(perSecond: 2_000)

        for round in 0..<2 {
            let progress = LockedBox(0)
            let walk = Task.detached { try await client.walk(OID([1, 3, 6, 1])) { vbs in
                DispatchQueue.main.async { progress.mutate { $0 += vbs.count } }     // as the Test pane does
            } }
            let ifWalk = Task.detached { try await client.walk(.ifTable, cap: SNMPClient.interfaceWalkCap) }
            var applies = 0
            let end = Date().addingTimeInterval(20)
            while progress.value < quiet.count || applies < 6, Date() < end {
                let p = ports[(applies + round + 1) % 2]
                app.settings.syslogUDPPort = p.udp
                app.settings.syslogTCPPort = p.tcp
                app.settings.trapPort = p.trap
                app.restartListeners()
                XCTAssertNil(app.lastError, app.lastError ?? "")
                app.stopTraps()
                app.startTraps()
                applies += 1
                await spin(20)
            }
            let w = try await walk.value
            let wi = try await ifWalk.value
            print("MEASURE r19 walk through \(applies) Applies: \(w.varBinds.count) var-binds (quiet \(quiet.count)), ifTable \(wi.varBinds.count)")
            XCTAssertFalse(w.truncated)
            XCTAssertEqual(w.varBinds.map(\.oid), quiet, "round \(round): the whole-tree walk")
            XCTAssertEqual(wi.varBinds.map(\.oid), quietIf, "round \(round): the ifTable walk")
            await waitUntil { progress.value >= quiet.count }
            XCTAssertEqual(progress.value, quiet.count, "chunks handed to the main thread")
        }
        XCTAssertTrue(cs.allSatisfy { !$0.failed.load(ordering: .relaxed) && !$0.peerClosed }, "a TCP client was disconnected")
    }

    // MARK: - 4. Stop / Apply under a flood

    /// Stop and Apply ports under an unpaced 8-client + 2-sender flood no longer wait behind
    /// the parse: it ran on the listener queue, and they waited for every read event already
    /// queued (each up to 64 reads per client, parsed) and then for the parse of what the
    /// drain read — Stop 0.5–3.2 s, Apply (TCP off) 2.6 s, Debug on Low Power. Every line still
    /// reaches the disk before the backlog gate may drop it (Round18Tests' accounts).
    func testStopAndApplyUnderAFloodDoNotWaitForTheParser() async throws {
        let app = AppModel.shared
        keepSettings()
        var stops: [Double] = [], applies: [Double] = []
        for round in 0..<3 {
            let udp = TestSockets.freePort(SOCK_DGRAM), tcp = TestSockets.freePort(SOCK_STREAM)
            app.logs.clear()
            startSyslog(udp: udp, tcp: tcp)
            var cs = (0..<8).compactMap { LineClient(port: tcp, tag: "lat\(round)x\($0)") }
            clients += cs
            for c in cs { c.flood(perSecond: 5_000_000) }
            let us = (0..<2).map { UDPSender(port: udp, tag: "latu\(round)x\($0)") }
            senders += us
            for s in us { s.flood(perSecond: 5_000_000) }
            await waitUntil { app.logs.totalReceived > 50_000 }
            app.settings.syslogUDPPort = TestSockets.freePort(SOCK_DGRAM)
            app.settings.syslogTCPPort = 0
            let t0 = Monotonic.now()
            app.restartListeners()
            applies.append(Monotonic.now() - t0)
            for c in cs { c.close() }
            startSyslog(udp: udp, tcp: tcp)
            cs = (0..<8).compactMap { LineClient(port: tcp, tag: "lat\(round)y\($0)") }
            clients += cs
            for c in cs { c.flood(perSecond: 5_000_000) }
            await waitUntil { app.logs.totalReceived > 100_000 }
            let t1 = Monotonic.now()
            app.stopSyslog()
            stops.append(Monotonic.now() - t1)
            for s in us { s.stop() }
            for c in cs { c.close() }
            SyslogListener.waitForParser()
        }
        print("MEASURE r19 under an 8-client flood: Stop \(stops.map { Int($0 * 1000) }) ms, Apply (TCP off) \(applies.map { Int($0 * 1000) }) ms")
        // The drain still reads what the sockets held and, under a flood that goes on, up to
        // `drainSeconds` more; unbounded it was 45 s. Sanitizers / Low Power: several times slower.
        let bound: Double = PerfBudget.enforced ? 1.0 : 3.0
        XCTAssertLessThan(stops.max() ?? 0, bound)
        XCTAssertLessThan(applies.max() ?? 0, PerfBudget.enforced ? 0.5 : 1.0, "Apply waited behind the parse")
    }

    /// The parser slowed down (a busy Mac, a sanitizer): the listener does not read ahead of it
    /// without bound — TCP devices are held back by their windows, as when the parse ran on the
    /// listener queue — so a flood loses nothing at the backlog gate; after Stop every line is
    /// delivered once and on the disk sink.
    func testSlowParserHoldsTCPBackInsteadOfDropping() throws {
        let port = TestSockets.freePort(SOCK_STREAM)
        let t = try SocketFactory.bind(type: SOCK_STREAM, port: port).get()
        let gate = BacklogGate(slots: SyslogListener.backlogSlots)
        let got = LockedBox<[String: [Int]]>([:])
        let raw = LockedBox(0)
        let l = SyslogListener(overrides: VendorOverrideMap(), deliver: { batch in
            usleep(15_000)                                  // a slow parse / main thread
            got.mutate { d in
                for e in batch {
                    if let r = e.message.range(of: "tcp line "), let n = Int(e.message[r.upperBound...]) { d[e.hostname, default: []].append(n) }
                }
            }
            _ = gate.leave()
        }, clientsChanged: { _ in }, gate: gate)
        l.rawSink = { raws in raw.mutate { $0 += raws.count } }
        l.start(udpFD: -1, tcpFD: t)
        let cs = (0..<4).compactMap { LineClient(port: port, tag: "slow\($0)") }
        clients += cs
        for c in cs { c.flood(perSecond: 5_000_000) }
        usleep(3_000_000)
        for c in cs { c.stopSending() }
        // Read and parsed as it goes (not by Stop's drain, which reads a socket's whole backlog
        // at once and may overflow the gate while the main thread waits for it, as before).
        let sent = cs.reduce(0) { $0 + $1.sent.load(ordering: .relaxed) }
        let end = Date().addingTimeInterval(60)
        while got.value.values.reduce(0, { $0 + $1.count }) < sent, Date() < end { usleep(20_000) }
        XCTAssertEqual(gate.droppedTotal, 0, "lines dropped at the backlog gate: the reader outran the parser")
        l.stop()
        SyslogListener.waitForParser()
        XCTAssertEqual(raw.value, sent, "on the disk sink")
        for c in cs {
            let n = got.value[c.tag] ?? []
            XCTAssertEqual(n, Array(0..<c.sent.load(ordering: .relaxed)), "\(c.tag): delivered in order, once")
        }
    }

    // MARK: - 5. The disk log's line order

    /// Every line of the log file(s) in `dir`, per sender tag, in file order.
    private func fileOrder(_ dir: URL) throws -> [String: [Int]] {
        var order: [String: [Int]] = [:]
        for f in (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? [] {
            for l in try String(contentsOf: f, encoding: .utf8).split(separator: "\n") {
                guard let r = l.range(of: "<134>Sep 23 10:15:32 "), let w = l.range(of: "tcp line "), let n = Int(l[w.upperBound...]) else { continue }
                order[String(l[r.upperBound...].prefix { $0 != " " }), default: []].append(n)
            }
        }
        return order
    }

    /// Disk logging switched off and on (and the folder away and back) twenty times under an
    /// unpaced 6-client flood: each client's lines are in the file in the order sent. The new
    /// logger wrote while the one just retired still wrote its backlog to the same file — up to
    /// 4 steps back per client ("… 34944 34945 34946 2324 2325 …").
    func testDiskLogOffOnKeepsEachDevicesOrder() async throws {
        let app = AppModel.shared
        keepSettings()
        let root = FileManager.default.temporaryDirectory.appending(path: "SheepLogR19Order-\(UUID().uuidString)", directoryHint: .isDirectory)
        cleanup.append(root)
        let dir = root.appending(path: "a"), other = root.appending(path: "b")
        let udp = TestSockets.freePort(SOCK_DGRAM), tcp = TestSockets.freePort(SOCK_STREAM)
        app.logs.clear()
        startSyslog(udp: udp, tcp: tcp)
        app.settings.logDirectory = dir.path
        app.settings.diskLogging = true
        let cs = (0..<6).compactMap { LineClient(port: tcp, tag: "ord\($0)") }
        clients += cs
        for c in cs { c.flood(perSecond: 5_000_000) }
        await waitUntil { app.logs.totalReceived > 30_000 }
        var loggers: [DiskLogger] = []
        for i in 0..<20 {
            if let l = app.logs.diskLogger { loggers.append(l) }
            if i % 4 == 3 {
                app.settings.logDirectory = other.path
                if let l = app.logs.diskLogger { loggers.append(l) }
                app.settings.logDirectory = dir.path
            } else {
                app.settings.diskLogging = false
                app.settings.diskLogging = true
            }
            await spin(20)
        }
        for c in cs { c.stopSending() }
        await spin(300)
        app.stopSyslog()
        if let l = app.logs.diskLogger { loggers.append(l) }
        for l in loggers { l.sync() }
        let order = try fileOrder(dir)
        for c in cs {
            let ns = order[c.tag] ?? []
            let back = zip(ns, ns.dropFirst()).filter { $1 <= $0 }
            XCTAssertTrue(back.isEmpty, "\(c.tag): \(back.count) steps back in the file, first \(back.prefix(3))")
            XCTAssertEqual(ns.first, 0)
        }
    }

    /// A settings change that has nothing to do with the disk log (the packet buffer, an
    /// auto-start switch) keeps the logger. The folder's URL gains a trailing "/" once the
    /// logger has created it, so the comparison said "another folder" and replaced the logger
    /// at every later change — under traffic the new one's lines went into the file before the
    /// old one's backlog.
    func testUnrelatedSettingsChangeKeepsTheDiskLogger() async throws {
        let app = AppModel.shared
        keepSettings()
        let dir = FileManager.default.temporaryDirectory.appending(path: "SheepLogR19Keep-\(UUID().uuidString)", directoryHint: .isDirectory)
        cleanup.append(dir)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path))
        app.settings.logDirectory = dir.path
        app.settings.diskLogging = true
        let logger = try XCTUnwrap(app.logs.diskLogger)
        app.logs.ingest([parsedLine("<134>Sep 23 10:15:32 keep app: one")])
        logger.sync()
        XCTAssertTrue(FileManager.default.fileExists(atPath: dir.path), "the logger created the folder")
        app.settings.packetLimit = 123_000
        app.settings.trapAutoStart.toggle()
        XCTAssertTrue(app.logs.diskLogger === logger, "an unrelated settings change replaced the disk logger")
        app.settings.logDirectory = dir.path + "/"
        XCTAssertTrue(app.logs.diskLogger === logger, "the same folder spelled with a trailing /")
        XCTAssertTrue(logger.sameFolder(as: URL(fileURLWithPath: dir.path + "/")))
        XCTAssertFalse(logger.sameFolder(as: dir.appending(path: "sub")))
    }
}
