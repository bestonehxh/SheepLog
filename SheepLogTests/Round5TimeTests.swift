import CPcap
import Darwin
import XCTest
@testable import SheepLog

/// Round 5: sleep, a stepped system clock, time zones.
final class Round5TimeTests: XCTestCase {
    /// The walk batcher emits at most every 100 ms. It measured that on the wall clock: with the
    /// system time stepped back an hour (NTP, or the user fixing it) the next emission waited an
    /// hour — a walk's rows stopped appearing.
    func testChunkBatcherSurvivesAClockSteppedBack() {
        let clock = LockedBox(10_000.0)          // moved by hand
        let got = LockedBox(0)
        let b = ChunkBatcher(interval: 0.1, clock: { clock.value }) { chunk in got.mutate { $0 += chunk.count } }
        b.add([VarBind(OID([1, 3, 1]), .integer(1))])
        XCTAssertEqual(got.value, 1, "the first chunk goes at once")
        clock.mutate { $0 = 10_000 - 3_600 }
        b.add([VarBind(OID([1, 3, 2]), .integer(2))])
        let end = Date().addingTimeInterval(1)
        while got.value < 2, Date() < end { usleep(5_000) }
        XCTAssertEqual(got.value, 2, "emitted within the interval, not an hour later")
    }

    /// The live capture's read loop flushes its batch 100 ms after the previous flush. With the
    /// wall clock stepped back an hour it held packets until 2,000 had piled up (on a quiet
    /// interface: for the hour). Fed through a pipe here, one packet at a time, with its clock
    /// jumping back between them.
    func testCaptureLoopFlushesAfterTheClockJumpsBack() throws {
        var fds: [Int32] = [0, 0]
        XCTAssertEqual(pipe(&fds), 0)
        let writer = FileHandle(fileDescriptor: fds[1], closeOnDealloc: true)
        // pcap file header (microsecond, Ethernet), then records written as the test goes.
        var header = Data()
        func le32(_ v: UInt32) -> [UInt8] { withUnsafeBytes(of: v.littleEndian) { Array($0) } }
        func le16(_ v: UInt16) -> [UInt8] { withUnsafeBytes(of: v.littleEndian) { Array($0) } }
        header += le32(0xa1b2c3d4) + le16(2) + le16(4) + le32(0) + le32(0) + le32(65535) + le32(1)
        writer.write(header)
        let frame = PacketFixture.udp4(40000, 53, PacketFixture.dnsQuery("clock.example"))
        func record(_ sec: UInt32) -> Data {
            Data(le32(sec) + le32(0) + le32(UInt32(frame.count)) + le32(UInt32(frame.count))) + frame
        }
        guard let file = fdopen(fds[0], "r") else { return XCTFail("fdopen") }
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        writer.write(record(1_700_000_000))      // pcap reads the header when opened
        let p = try XCTUnwrap(pcap_fopen_offline(file, &errbuf))
        let clock = LockedBox(50_000.0)          // moved by hand
        let got = LockedBox(0)
        let reader = CaptureReader(handle: PcapHandle(p), linkType: 1, deliver: { batch in got.mutate { $0 += batch.count } },
                                   stats: { _ in }, failed: { _ in }, clock: { clock.value })
        reader.start()
        usleep(150_000)
        XCTAssertEqual(got.value, 0, "one packet read, the 100 ms have not passed on the loop's clock")
        clock.mutate { $0 = 50_000 - 3_600 }                // the system time is stepped back an hour
        writer.write(record(1_700_000_001))
        let end = Date().addingTimeInterval(2)
        while got.value < 2, Date() < end { usleep(5_000) }
        XCTAssertEqual(got.value, 2, "flushed at the next packet, not an hour (or 2,000 packets) later")
        try writer.close()                       // EOF ends the loop
        reader.join(timeout: 2)
    }

    /// The engine-time estimate counts on the monotonic clock: it goes on through sleep (as the
    /// agent's own clock does) and a stepped system clock does not move it.
    func testEngineTimeEstimateUsesTheMonotonicClock() {
        var e = EngineCache.Entry(engineID: [1, 2, 3, 4, 5], boots: 4, time: 1_000,
                                  learned: Date().addingTimeInterval(-7_200), synced: true)
        XCTAssertEqual(Int(e.estimatedTime), 1_000, accuracy: 1, "a wall-clock date an hour off is not used")
        e.learnedAt = Monotonic.now() - 8 * 3_600              // learned before an 8-hour sleep
        XCTAssertEqual(Int(e.estimatedTime), 1_000 + 8 * 3_600, accuracy: 1)
        e.learnedAt = Monotonic.now() + 60                    // a future stamp never goes back
        XCTAssertEqual(e.estimatedTime, 1_000)
    }

    /// No wall-clock intervals in the loops that time things (a lint: `Date()` differences and
    /// `CFAbsoluteTimeGetCurrent` in the capture loop, SNMP deadlines and the walk batcher).
    func testTimingCodeUsesTheMonotonicClock() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        for file in ["SheepLog/Capture/CaptureEngine.swift", "SheepLog/SNMP/SNMPClient.swift"] {
            let text = try String(contentsOf: root.appending(path: file), encoding: .utf8)
            XCTAssertFalse(text.contains("CFAbsoluteTimeGetCurrent"), file)
            XCTAssertFalse(text.contains("Date().timeIntervalSince("), file)
        }
    }
}
