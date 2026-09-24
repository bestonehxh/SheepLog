import Combine
import XCTest
@testable import SheepLog

@MainActor
final class PacketStoreTests: XCTestCase {
    private typealias F = PacketFixture

    /// A few dozen decoded templates, re-stamped with running frame numbers.
    private static let templates: [(Data, Decoded)] = {
        var frames: [Data] = []
        for i in 0..<16 {
            let host = "10.1.\(i).\(i + 10)"
            frames.append(F.tcp4(src: host, 50000 + i, 443, flags: 0x02, options: F.synOptions))
            frames.append(F.tcp4(src: "93.184.216.34", dst: host, 443, 50000 + i, seq: 9, ack: 1, flags: 0x12, options: F.synOptions))
            frames.append(F.tcp4(src: host, 50000 + i, 443, seq: 1, ack: 10, flags: 0x10))
            frames.append(F.tcp4(src: host, 50000 + i, 80, seq: 1, ack: 1, flags: 0x18,
                                 Array("GET /x HTTP/1.1\r\nHost: web\(i).example\r\n\r\n".utf8)))
            frames.append(F.udp4(src: host, 40000 + i, 53, F.dnsQuery("q\(i).example.com")))
        }
        return frames.map { ($0, PacketDecoder.decode($0)) }
    }()

    private func makePackets(_ n: Int, from start: Int = 1) -> [Packet] {
        let t = Self.templates
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        return (0..<n).map { k in
            let i = start + k
            let (data, decoded) = t[i % t.count]
            return Packet(id: i, timestamp: base.addingTimeInterval(Double(i) * 0.0001), relative: Double(i) * 0.0001,
                          length: data.count, captured: data.count, data: data, decoded: decoded)
        }
    }

    func testIngest200kUnder3Seconds() {
        let store = PacketStore()
        store.limit = 200_000
        let all = makePackets(200_000)
        let batches = stride(from: 0, to: all.count, by: 2_000).map { Array(all[$0..<min($0 + 2_000, all.count)]) }
        let start = Date()
        for b in batches { store.ingest(b) }
        let elapsed = Date().timeIntervalSince(start)
        print("[timing] ingest 200,000 packets in 100 batches: \(String(format: "%.3f", elapsed)) s")
        XCTAssertWithinBudget(elapsed, 3)
        XCTAssertEqual(store.packets.count, 200_000)
        XCTAssertEqual(store.visible.count, 200_000)
        XCTAssertEqual(store.totalReceived, 200_000)
        XCTAssertEqual(store.dropped, 0)

        // With a filter active the per-batch (incremental) match runs on the main actor.
        let filtered = PacketStore()
        filtered.queryText = "proto:tcp dport:443 flags:syn"
        filtered.applyQueryNow(synchronous: true)
        let start2 = Date()
        for b in batches { filtered.ingest(b) }
        let elapsed2 = Date().timeIntervalSince(start2)
        print("[timing] ingest 200,000 packets with a filter: \(String(format: "%.3f", elapsed2)) s")
        XCTAssertWithinBudget(elapsed2, 3)
        XCTAssertEqual(filtered.visible.count, 200_000 / 5)
    }

    /// Like `makePackets`, but every packet decoded on its own (own string buffers), as captured.
    private func makeDecodedPackets(_ n: Int) -> [Packet] {
        let t = Self.templates
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        return (1...n).map { i in
            let data = t[i % t.count].0
            return Packet(id: i, timestamp: base.addingTimeInterval(Double(i) * 0.0001), relative: Double(i) * 0.0001,
                          length: data.count, captured: data.count, data: data, decoded: PacketDecoder.decode(data))
        }
    }

    func testFullRescan200kUnder400ms() async throws {
        let store = PacketStore()
        store.limit = 200_000
        let all = makeDecodedPackets(200_000)
        for s in stride(from: 0, to: all.count, by: 2_000) { store.ingest(Array(all[s..<min(s + 2_000, all.count)])) }
        let q = try Query.parse("proto:tcp dport:443 flags:syn")
        let matcher = PacketMatcher(q)
        let start = Date()
        let result = PacketStore.filter(store.packets, with: matcher)
        let elapsed = Date().timeIntervalSince(start)
        print("[timing] full rescan 'proto:tcp dport:443 flags:syn' over 200,000: \(String(format: "%.1f", elapsed * 1000)) ms")
        XCTAssertWithinBudget(elapsed, 0.4)
        // SYN to 443 (1 of 5 templates) — the SYN/ACK comes *from* 443, so dport excludes it.
        XCTAssertEqual(result.count, 40_000)
        XCTAssertTrue(result.allSatisfy { $0.decoded.tcp?.flags == .syn && $0.decoded.tcp?.destinationPort == 443 })
        XCTAssertEqual(result.map(\.id), result.map(\.id).sorted())

        // A bare-word scan (the slow path) for the record.
        let start2 = Date()
        let words = PacketStore.filter(store.packets, with: PacketMatcher(try Query.parse("example")))
        print("[timing] full rescan bare word over 200,000: \(String(format: "%.1f", Date().timeIntervalSince(start2) * 1000)) ms")
        XCTAssertEqual(words.count, 40_000)

        // The store's own async path lands the same result.
        let gen = store.generation
        store.queryText = "proto:tcp dport:443 flags:syn"
        store.applyQueryNow()
        for _ in 0..<200 where store.generation == gen { try await Task.sleep(for: .milliseconds(10)) }
        XCTAssertEqual(store.visible.count, 40_000)
        XCTAssertNil(store.queryError)
    }

    func testStaleRescanLoses() async throws {
        let store = PacketStore()
        store.ingest(makePackets(50_000))
        store.queryText = "proto:udp"
        store.applyQueryNow()
        store.queryText = "dport:80"
        store.applyQueryNow()
        try await Task.sleep(for: .milliseconds(500))
        XCTAssertEqual(store.visible.count, 10_000)
        XCTAssertTrue(store.visible.allSatisfy { $0.decoded.tcp?.destinationPort == 80 })
    }

    func testDebounceAndQueryError() async throws {
        let store = PacketStore()
        store.ingest(makePackets(100))
        store.queryText = "(proto:tcp"
        try await Task.sleep(for: .milliseconds(400))
        XCTAssertNotNil(store.queryError)
        XCTAssertEqual(store.visible.count, 100)
        store.queryText = "proto:udp"
        try await Task.sleep(for: .milliseconds(400))
        XCTAssertNil(store.queryError)
        XCTAssertEqual(store.visible.count, 20)
    }

    func testRingEviction() {
        let store = PacketStore()
        store.limit = 1_000
        store.queryText = "proto:udp"
        store.applyQueryNow(synchronous: true)
        let all = makePackets(1_500)
        var gen = store.generation
        for s in stride(from: 0, to: 1_000, by: 100) { store.ingest(Array(all[s..<s + 100])) }
        XCTAssertEqual(store.packets.count, 1_000)
        XCTAssertEqual(store.generation, gen, "appends do not bump the generation")
        gen = store.generation
        store.ingest(Array(all[1_000..<1_100]))
        // Over the limit: the oldest 10 % (100) go in one step… plus the overflow.
        XCTAssertEqual(store.packets.count, 1_000)
        XCTAssertEqual(store.packets.first?.id, 101)
        XCTAssertEqual(store.packets.last?.id, 1_100)
        XCTAssertEqual(store.dropped, 100)
        XCTAssertGreaterThan(store.generation, gen)
        XCTAssertEqual(store.visible.first.map(\.id).map { $0 >= 101 }, true)
        XCTAssertEqual(store.visible.count, store.packets.filter { $0.decoded.udp != nil }.count)
        store.ingest(Array(all[1_100..<1_500]))
        XCTAssertLessThanOrEqual(store.packets.count, 1_000)
        XCTAssertEqual(store.packets.last?.id, 1_500)
        XCTAssertEqual(store.dropped, 500)
        XCTAssertEqual(store.totalReceived, 1_500)
        XCTAssertEqual(store.visible.map(\.id), store.visible.map(\.id).sorted())

        store.addKernelDrops(7)
        XCTAssertEqual(store.dropped, 507)
        store.clear()
        XCTAssertTrue(store.packets.isEmpty && store.visible.isEmpty)
        XCTAssertEqual(store.dropped, 0)
    }

    func testPauseBuffersThenResumes() {
        let store = PacketStore()
        store.ingest(makePackets(10))
        store.paused = true
        store.ingest(makePackets(10, from: 11))
        XCTAssertEqual(store.visible.count, 10)
        XCTAssertEqual(store.totalReceived, 20)
        store.paused = false
        XCTAssertEqual(store.visible.count, 20)
        XCTAssertEqual(store.visible.last?.id, 20)
    }

    // MARK: Review

    /// Observers (SwiftUI, Combine sinks, the Flows analyser) must never find the ring or the
    /// view transiently empty while a batch is appended or evicted. Each `objectWillChange` is a
    /// moment an observer may look at the store.
    func testObserversNeverSeeTransientEmptyArrays() {
        let store = PacketStore()
        store.limit = 1_000
        var packetCounts: [Int] = []
        var visibleCounts: [Int] = []
        let sink = store.objectWillChange.sink { _ in
            packetCounts.append(store.packets.count)
            visibleCounts.append(store.visible.count)
        }
        let all = makePackets(3_000)
        for s in stride(from: 0, to: all.count, by: 250) { store.ingest(Array(all[s..<s + 250])) }
        store.queryText = "proto:udp"
        store.applyQueryNow(synchronous: true)
        for s in stride(from: 0, to: 1_000, by: 250) { store.ingest(makePackets(250, from: 3_001 + s)) }
        sink.cancel()
        let p = packetCounts.drop { $0 == 0 }, v = visibleCounts.drop { $0 == 0 }
        XCTAssertFalse(p.isEmpty)
        XCTAssertFalse(p.contains(0), "packets seen empty: \(Array(p.prefix(30)))")
        XCTAssertFalse(v.contains(0), "visible seen empty: \(Array(v.prefix(30)))")
    }

    /// Frame numbers and relative times belong to the store: after Clear they start again at 1
    /// and 0, even though the capture thread keeps counting.
    func testIDsAndRelativeTimeRestartAfterClear() {
        let store = PacketStore()
        store.beginLive(linkType: 1)
        store.ingest(makePackets(10))
        store.clear()
        store.ingest(makePackets(10, from: 11))
        XCTAssertEqual(store.packets.map(\.id), Array(1...10))
        XCTAssertEqual(store.packets.first?.relative ?? -1, 0, accuracy: 1e-9)
        XCTAssertEqual(store.packets.last?.relative ?? -1, 0.0009, accuracy: 1e-6)
        XCTAssertEqual(store.visibleIndex(of: 1), 0)
        // Paused packets are numbered when they arrive, not when they are shown.
        store.paused = true
        store.ingest(makePackets(5, from: 500))
        store.paused = false
        XCTAssertEqual(store.packets.map(\.id).suffix(5), [11, 12, 13, 14, 15])
    }

    /// A file opened during a live capture stops the capture, and a live batch still in flight
    /// never lands in the file's packets.
    func testLoadDuringLiveCaptureStopsItAndDropsLateBatches() async throws {
        let url = FileManager.default.temporaryDirectory.appending(path: "SheepLogTests-\(UUID().uuidString).pcap")
        defer { try? FileManager.default.removeItem(at: url) }
        try PcapFile.write(makePackets(30), linkType: 1, to: url)
        let store = PacketStore()
        var stopped = 0
        store.stopLiveCapture = { stopped += 1 }
        store.beginLive(linkType: 1)
        let session = store.liveSession
        store.ingestLive(makePackets(5), session: session)
        XCTAssertEqual(store.packets.count, 5)
        let done = expectation(description: "loaded")
        try store.load(from: url) { done.fulfill() }
        XCTAssertEqual(stopped, 1)
        store.ingestLive(makePackets(5, from: 6), session: session)     // late delivery from the old run
        await fulfillment(of: [done], timeout: 5)
        XCTAssertEqual(store.packets.count, 30)
        XCTAssertEqual(store.fileURL, url)
    }

    func testLimitLoweredAtRuntimeAndNonPositive() {
        let store = PacketStore()
        store.limit = 1_000
        store.queryText = "proto:udp"
        store.applyQueryNow(synchronous: true)
        store.ingest(makePackets(1_000))
        store.limit = 400
        XCTAssertLessThanOrEqual(store.packets.count, 400)
        XCTAssertEqual(store.packets.last?.id, 1_000)
        XCTAssertEqual(store.visible.count, store.packets.filter { $0.decoded.udp != nil }.count)
        XCTAssertEqual(store.visible.first.map { $0.id >= store.packets.first!.id }, true)
        // A zero or negative limit (a bad Settings value) must not trap, paused or not.
        store.limit = -5
        store.ingest(makePackets(10, from: 1_001))
        store.paused = true
        store.ingest(makePackets(10, from: 1_011))
        store.paused = false
        XCTAssertGreaterThanOrEqual(store.packets.count, 1)
    }

    func testQueryErrorClearedByEmptyQuery() {
        let store = PacketStore()
        store.ingest(makePackets(20))
        store.queryText = "(proto:tcp"
        store.applyQueryNow(synchronous: true)
        XCTAssertNotNil(store.queryError)
        store.queryText = ""
        store.applyQueryNow(synchronous: true)
        XCTAssertNil(store.queryError)
        XCTAssertEqual(store.visible.count, 20)
    }

    /// "Show packets" from the Flows pane builds `frame:a OR frame:b OR …` with 50 terms.
    func testFrameOrOf50TermsIsFast() throws {
        let all = makePackets(200_000)
        let ids = (0..<50).map { 1_000 + $0 * 3_001 }
        let q = try Query.parse(ids.map { "frame:\($0)" }.joined(separator: " OR "))
        let matcher = PacketMatcher(q)
        // Against one frame: term (the floor for any scan of 200k packets in this build).
        let one = PacketMatcher(try Query.parse("frame:1000"))
        let s0 = Date()
        XCTAssertEqual(PacketStore.filter(all, with: one).count, 1)
        let floor = Date().timeIntervalSince(s0)
        let start = Date()
        let result = PacketStore.filter(all, with: matcher)
        let elapsed = Date().timeIntervalSince(start)
        print("[timing] frame: OR ×50 over 200,000: \(String(format: "%.1f", elapsed * 1000)) ms (one term: \(String(format: "%.1f", floor * 1000)) ms)")
        XCTAssertEqual(result.map(\.id), ids)
        XCTAssertWithinBudget(elapsed, max(0.05, floor * 3), "50 OR-ed frame terms cost about one")
        guard case .leaf(.frames(let set))? = matcher.root else { return XCTFail("not folded into one set") }
        XCTAssertEqual(set.count, 50)
        // Mixed with other terms the set still answers correctly.
        let mixed = PacketMatcher(try Query.parse("frame:5 OR frame:7 OR proto:arp OR (frame:9 proto:udp)"))
        XCTAssertEqual(PacketStore.filter(Array(all.prefix(20)), with: mixed).map(\.id), [5, 7, 9].filter { id in
            id != 9 || all[8].decoded.udp != nil
        })
        XCTAssertFalse(PacketMatcher(try Query.parse("NOT (frame:5 OR frame:6)")).matches(all[4]))
        XCTAssertTrue(PacketMatcher(try Query.parse("NOT (frame:5 OR frame:6)")).matches(all[6]))
    }

    /// Saving runs off the main actor and reports when it is done.
    func testSaveInBackground() async throws {
        let url = FileManager.default.temporaryDirectory.appending(path: "SheepLogTests-\(UUID().uuidString).pcap")
        defer { try? FileManager.default.removeItem(at: url) }
        let store = PacketStore()
        store.ingest(makePackets(20_000))
        let done = expectation(description: "saved")
        var failure: String?
        store.save(to: url) { error in failure = error; done.fulfill() }
        XCTAssertTrue(store.isSaving)
        await fulfillment(of: [done], timeout: 10)
        XCTAssertNil(failure)
        XCTAssertFalse(store.isSaving)
        var n = 0
        _ = try PcapFile.read(url) { n += $0.count }
        XCTAssertEqual(n, 20_000)
    }

    // MARK: Every packet key

    private func packet(_ data: Data, id: Int = 1) -> Packet {
        Packet(id: id, timestamp: Date(), relative: 0, length: data.count, captured: data.count, data: data,
               decoded: PacketDecoder.decode(data))
    }

    private func m(_ q: String, _ p: Packet, file: StaticString = #filePath, line: UInt = #line) -> Bool {
        do { return PacketMatcher(try Query.parse(q)).matches(p) } catch {
            XCTFail("\(q): \(error)", file: file, line: line)
            return false
        }
    }

    func testEveryPacketKey() {
        let syn = packet(F.tcp4(src: "10.1.0.9", dst: "93.184.216.34", 51234, 443, flags: 0x02, options: F.synOptions), id: 42)
        let hello = packet(F.tcp4(51234, 443, seq: 1, ack: 1, flags: 0x18, F.clientHello(sni: "www.example.com")))
        let get = packet(F.tcp4(51234, 80, seq: 1, ack: 1, flags: 0x18,
                                Array("GET / HTTP/1.1\r\nHost: intranet.local\r\n\r\n".utf8), vlan: 30))
        let dns = packet(F.udp4(40000, 53, F.dnsQuery("mail.example.org")))
        let arp = packet(F.arp(request: true))
        let icmp = packet(F.icmpEcho(request: true))

        // ip: (either side, exact, prefix, CIDR, !=)
        XCTAssertTrue(m("ip:93.184.216.34", syn))
        XCTAssertTrue(m("ip:10.1.0.9", syn))
        XCTAssertFalse(m("ip:10.1.0.90", syn))
        XCTAssertTrue(m("ip:10.1.", syn))
        XCTAssertTrue(m("ip:10.0.0.0/8", syn))
        XCTAssertFalse(m("ip:192.168.0.0/16", syn))
        XCTAssertTrue(m("ip:!=192.168.1.1", syn))
        // src: / dst:
        XCTAssertTrue(m("src:10.1.0.9", syn))
        XCTAssertFalse(m("src:93.184.216.34", syn))
        XCTAssertTrue(m("dst:93.184.216.34", syn))
        XCTAssertTrue(m("dst:10.1.0.1", arp))
        // port: / sport: / dport:
        XCTAssertTrue(m("port:443", syn))
        XCTAssertTrue(m("port:51234", syn))
        XCTAssertTrue(m("port:https", syn))
        XCTAssertFalse(m("port:22", syn))
        XCTAssertTrue(m("port:!=22", syn))
        XCTAssertTrue(m("sport:51234", syn))
        XCTAssertFalse(m("sport:443", syn))
        XCTAssertTrue(m("dport:443", syn))
        XCTAssertTrue(m("dport:<1024", syn))
        XCTAssertFalse(m("dport:>1024", syn))
        XCTAssertFalse(m("dport:443", arp))
        // proto:
        XCTAssertTrue(m("proto:tcp", syn))
        XCTAssertTrue(m("proto:tcp", hello))
        XCTAssertFalse(m("proto:udp", syn))
        XCTAssertTrue(m("proto:udp", dns))
        XCTAssertTrue(m("proto:dns", dns))
        XCTAssertTrue(m("proto:tls", hello))
        XCTAssertTrue(m("proto:http", get))
        XCTAssertTrue(m("proto:arp", arp))
        XCTAssertTrue(m("proto:icmp", icmp))
        XCTAssertTrue(m("proto:17", dns))
        XCTAssertTrue(m("proto:6", syn))
        XCTAssertTrue(m("proto:ipv4", syn))
        XCTAssertFalse(m("proto:ipv6", syn))
        XCTAssertTrue(m("proto:!=tcp", dns))
        // vlan:
        XCTAssertTrue(m("vlan:30", get))
        XCTAssertFalse(m("vlan:30", syn))
        XCTAssertTrue(m("vlan:>=10", get))
        XCTAssertTrue(m("vlan:!=30", syn))
        // mac:
        XCTAssertTrue(m("mac:00:1c:0e", syn))
        XCTAssertTrue(m("mac:AA-BB-CC-DD-EE-FF", syn))
        XCTAssertFalse(m("mac:12:34", syn))
        // len:
        XCTAssertTrue(m("len:66", syn))
        XCTAssertTrue(m("len:>=60", syn))
        XCTAssertFalse(m("len:<60", syn))
        XCTAssertFalse(m("len>1000", syn))
        // frame:
        XCTAssertTrue(m("frame:42", syn))
        XCTAssertTrue(m("frame:>=40", syn))
        XCTAssertFalse(m("frame:1", syn))
        // flags:
        XCTAssertTrue(m("flags:syn", syn))
        XCTAssertFalse(m("flags:ack", syn))
        XCTAssertTrue(m("flags:psh,ack", hello))
        XCTAssertFalse(m("flags:syn", dns))
        // sni:
        XCTAssertTrue(m("sni:example.com", hello))
        XCTAssertFalse(m("sni:example.com", get))
        // host: (HTTP Host / SNI / DNS name)
        XCTAssertTrue(m("host:intranet", get))
        XCTAssertTrue(m("host:www.example", hello))
        XCTAssertTrue(m("host:mail.example.org", dns))
        XCTAssertFalse(m("host:intranet", dns))
        // info:
        XCTAssertTrue(m("info:\"Who has\"", arp))
        XCTAssertTrue(m("info:SACK_PERM", syn))
        XCTAssertFalse(m("info:SACK_PERM", dns))
        // Bare words: info + source + destination + protocol
        XCTAssertTrue(m("who", arp))
        XCTAssertTrue(m("93.184", syn))
        XCTAssertTrue(m("dns", dns))
        XCTAssertTrue(m("\"Client Hello\"", hello))
        XCTAssertTrue(m("/Seq=\\d+ Win/", syn))
        // Boolean structure
        XCTAssertTrue(m("proto:udp OR flags:syn", syn))
        XCTAssertFalse(m("proto:tcp NOT dport:443", syn))
        XCTAssertTrue(m("(dport:80 OR dport:443) -proto:udp", hello))
        // Not a packet key: searched as typed.
        XCTAssertFalse(m("foo:bar", syn))
        // The context-menu conversation filter matches its own packet.
        XCTAssertTrue(m(PacketTableController.conversationFilter(syn.decoded), syn))
    }
}
