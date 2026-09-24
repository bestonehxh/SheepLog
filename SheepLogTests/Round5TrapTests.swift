import Darwin
import XCTest
@testable import SheepLog

/// Round 5: traps received in the last 100 ms before ⌘Q (the listener's batching window) reach
/// the store and the disk log.
@MainActor
final class Round5TrapTests: XCTestCase {
    private var temp: URL!

    override func setUp() async throws {
        temp = FileManager.default.temporaryDirectory.appending(path: "SheepLogRound5Traps-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: temp, withIntermediateDirectories: true)
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: temp)
    }

    /// A v2c linkDown trap for ifIndex `n`.
    static func linkDown(_ n: Int64) -> [UInt8] {
        let pdu = SNMPPDU(type: BER.trapV2, requestID: Int32(n), varBinds: [
            VarBind(OID.sysUpTimeInstance, .timeTicks(4242)),
            VarBind(OID.snmpTrapOID, .oid(OID([1, 3, 6, 1, 6, 3, 1, 1, 5, 3]))),
            VarBind(OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 1, UInt32(n)]), .integer(n)),
        ])
        return BER.encodeSequence([BER.encodeInteger(1), BER.encodeOctets(Array("public".utf8)), pdu.encoded()])
    }

    private static func lines(in dir: URL) -> [String] {
        let files = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []
        return files.filter { $0.pathExtension == "log" }
            .flatMap { ((try? String(contentsOf: $0, encoding: .utf8)) ?? "").split(separator: "\n").map(String.init) }
    }

    /// A trap still in the listener's 100 ms batch when ⌘Q runs `shutdownForQuit`
    /// (`traps.stop()` and then `diskLogger.close()`): `stop()` used to hand it to
    /// `DispatchQueue.main.async`, which never runs after the app exits — it was in neither the
    /// table nor the disk log.
    func testStopTakesInTheBatchedTrapsSynchronously() throws {
        let store = LogStore()
        let logger = DiskLogger(directory: temp)
        store.diskLogger = logger
        let traps = TrapReceiver(store: store)
        traps.registry = MIBRegistry()
        let port = TestSockets.freePort()
        traps.start(port: port)
        XCTAssertTrue(traps.isRunning, traps.lastError ?? "")

        TestSockets.sendUDP(Self.linkDown(7), to: port)
        let end = Date().addingTimeInterval(1)
        while traps.batchedCount == 0, Date() < end { usleep(1_000) }
        XCTAssertEqual(traps.batchedCount, 1, "the trap is read and waiting for the 100 ms flush")

        traps.stop()                       // what shutdownForQuit does, then…
        logger.close()                     // …the disk log is closed, and the process exits
        XCTAssertEqual(store.entries.count, 1, "in the store before stop() returned")
        XCTAssertEqual(traps.trapCount, 1)
        XCTAssertEqual(store.entries.first?.transport, .trap)
        let onDisk = Self.lines(in: temp)
        XCTAssertEqual(onDisk.count, 1, "\(onDisk)")
        XCTAssertTrue(onDisk.first?.contains("SNMPv2c trap 1.3.6.1.6.3.1.1.5.3 1.3.6.1.2.1.2.2.1.1.7=7") ?? false, "\(onDisk)")
        logger.retire()
    }

    /// A batch flushed to the main queue while the main thread is busy (the ⌘Q handler itself):
    /// the main-queue block never runs, but the listener queue already wrote it to the disk log,
    /// and it is not written twice when the main queue does get to it.
    func testFlushedBatchIsOnDiskBeforeTheMainQueueTakesIt() throws {
        let store = LogStore()
        let logger = DiskLogger(directory: temp)
        store.diskLogger = logger
        let traps = TrapReceiver(store: store)
        traps.registry = MIBRegistry()
        let port = TestSockets.freePort()
        traps.start(port: port)
        for n in 1...3 { TestSockets.sendUDP(Self.linkDown(Int64(n)), to: port) }
        usleep(400_000)                     // main thread busy: the 100 ms flush is queued on it
        traps.stop()
        logger.sync()
        XCTAssertEqual(Self.lines(in: temp).count, 3, "\(Self.lines(in: temp))")
        XCTAssertEqual(store.entries.count, 0, "the main queue has not run yet")
        // Now the main queue runs the delivered batch: in the table, not on disk a second time.
        let end = Date().addingTimeInterval(3)
        while store.entries.count < 3, Date() < end { RunLoop.main.run(until: Date().addingTimeInterval(0.02)) }
        XCTAssertEqual(store.entries.count, 3)
        logger.sync()
        XCTAssertEqual(Self.lines(in: temp).count, 3, "written once")
        logger.retire()
    }

    /// A trap flood the main thread cannot take (the backlog gate drops batches): every trap is
    /// still in the disk log, as syslog lines are.
    func testDroppedTrapBatchesStillReachTheDisk() throws {
        let logger = DiskLogger(directory: temp)
        let sink = DiskSink()
        sink.logger = logger
        let gate = BacklogGate(slots: 1)
        let delivered = LockedBox(0)
        let port = TestSockets.freePort()
        let l = try TrapListener(port: port, deliver: { b in delivered.mutate { $0 += b.count } }, gate: gate)
        l.rawSink = { sink.append($0) }
        l.resume()
        for round in 0..<3 {
            for n in 0..<50 { TestSockets.sendUDP(Self.linkDown(Int64(round * 100 + n)), to: port) }
            usleep(250_000)
        }
        l.cancel()
        logger.sync()
        XCTAssertLessThan(delivered.value, 150, "the gate (never left) dropped later batches")
        XCTAssertEqual(Self.lines(in: temp).count, 150)
        logger.retire()
    }
}
