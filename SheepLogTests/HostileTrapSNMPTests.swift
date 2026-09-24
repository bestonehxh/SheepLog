import Darwin
import XCTest
@testable import SheepLog

/// Round 3: traps and SNMP answers come from the network — decode them, bound them, and never
/// let a spoofed or oversized one do more than a normal one would.
@MainActor
final class HostileTrapSNMPTests: XCTestCase {
    private func v2Trap(_ varBinds: [VarBind], inform: Bool = false, community: String = "public") -> [UInt8] {
        let all = [VarBind(.sysUpTimeInstance, .timeTicks(42)), VarBind(.snmpTrapOID, .oid(OID([1, 3, 6, 1, 6, 3, 1, 1, 5, 3])))] + varBinds
        return CommunityMessage.encode(version: .v2c, community: community,
                                       pdu: SNMPPDU(type: inform ? BER.informRequest : BER.trapV2, requestID: 77, varBinds: all).encoded())
    }

    /// SEQUENCE nested 10,000 deep as a var-bind value (and as the whole datagram): rejected
    /// without recursion.
    func testBERDepthBombIsRejected() {
        var bomb: [UInt8] = [0x05, 0x00]
        for _ in 0..<10_000 { bomb = BER.tlv(0x30, bomb) }
        XCTAssertEqual(TrapListener.decode(bomb, host: "10.0.0.9", port: 162, received: Date()).item.isInvalid, true)
        // Inside a var-bind.
        let vb = BER.encodeSequence([BER.encodeOID(OID([1, 3, 6, 1, 2, 1, 1, 5, 0])), bomb])
        let pdu = BER.encodeSequence([BER.encodeInteger(1), BER.encodeInteger(0), BER.encodeInteger(0), BER.encodeSequence([vb])], tag: BER.trapV2)
        let msg = BER.encodeSequence([BER.encodeInteger(1), BER.encodeOctets(Array("public".utf8)), pdu])
        XCTAssertEqual(TrapListener.decode(msg, host: "10.0.0.9", port: 162, received: Date()).item.isInvalid, true)
    }

    /// A 64 KB trap with 10,000 var-binds: at most 1,000 become fields (plus a note), and
    /// naming it is quick.
    func testTenThousandVarBindsAreCapped() throws {
        let vbs = (0..<10_000).map { VarBind(OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 8, UInt32($0)]), .integer(1)) }
        let bytes = v2Trap(vbs)
        guard case .trap(let t) = TrapListener.decode(bytes, host: "10.0.0.9", port: 162, received: Date()).item else {
            return XCTFail("not decoded")
        }
        XCTAssertEqual(t.varBinds.count, 10_000)
        let reg = MIBRegistry()
        reg.loadNow(bundled: MIBRegistry.bundledURLs())
        let t0 = Date()
        let e = TrapReceiver.entry(for: t, registry: reg)
        XCTAssertWithinBudget(Date().timeIntervalSince(t0), 1.0)
        XCTAssertLessThanOrEqual(e.fields.count, TrapReceiver.maxVarBinds + 6)
        XCTAssertTrue(e.fields.contains { $0.key == "varbinds_truncated" && $0.value.hasPrefix("9000") })
    }

    /// The inform acknowledgement goes to whatever source the datagram claims: it must never
    /// be larger than the request. Sloppy encodings the re-encoder "fixes" (a 4-byte Counter32
    /// with the top bit set gains a 0 byte; a 0-byte IpAddress becomes 4) used to make it grow.
    func testInformAckIsNeverLargerThanTheRequest() throws {
        let sloppyCounter = BER.encodeSequence([BER.encodeOID(OID([1, 3, 6, 1, 2, 1, 2, 2, 1, 10, 1])), [0x41, 0x04, 0x80, 0, 0, 0]])
        let emptyIP = BER.encodeSequence([BER.encodeOID(OID([1, 3, 6, 1, 2, 1, 4, 20, 1, 1, 1])), [0x40, 0x00]])
        let head = [VarBind(.sysUpTimeInstance, .timeTicks(42)), VarBind(.snmpTrapOID, .oid(OID([1, 3, 6, 1, 6, 3, 1, 1, 5, 3])))]
        let list = BER.encodeSequence(head.map { BER.encodeSequence([BER.encodeOID($0.oid), BER.encodeValue($0.value)]) }
                                      + Array(repeating: sloppyCounter, count: 50) + Array(repeating: emptyIP, count: 50))
        let pdu = BER.encodeSequence([BER.encodeInteger(77), BER.encodeInteger(0), BER.encodeInteger(0), list], tag: BER.informRequest)
        let msg = BER.encodeSequence([BER.encodeInteger(1), BER.encodeOctets(Array("public".utf8)), pdu])
        let decoded = TrapListener.decode(msg, host: "10.0.0.9", port: 162, received: Date())
        let ack = try XCTUnwrap(decoded.informResponse)
        XCTAssertLessThanOrEqual(ack.count, msg.count)
        let m = try CommunityMessage.decode(ack)
        XCTAssertEqual(m.pdu?.type, BER.response)
        XCTAssertEqual(m.pdu?.requestID, 77)
        // A well-formed inform is acknowledged by re-encoding (same size).
        let clean = v2Trap([VarBind(OID([1, 3, 6, 1, 2, 1, 1, 5, 0]), .octetString(Data("x".utf8)))], inform: true)
        XCTAssertEqual(TrapListener.decode(clean, host: "h", port: 1, received: Date()).informResponse?.count, clean.count)
    }

    /// A v1 trap with an enterprise OID of 1,000 arcs and agent-addr fields of the wrong length.
    func testV1TrapOddities() throws {
        let enterprise = OID([1, 3, 6, 1, 4, 1] + (0..<994).map { UInt32($0 % 100) })
        for addr in [[UInt8](), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], [UInt8](repeating: 0xAB, count: 300)] {
            let pdu = BER.encodeSequence([BER.encodeOID(enterprise), BER.tlv(BER.ipAddress, addr), BER.encodeInteger(6),
                                          BER.encodeInteger(1), BER.encodeUnsigned(5, tag: BER.timeTicks),
                                          BER.encodeVarBinds([])], tag: BER.trapV1)
            let msg = BER.encodeSequence([BER.encodeInteger(0), BER.encodeOctets(Array("public".utf8)), pdu])
            guard case .trap(let t) = TrapListener.decode(msg, host: "10.0.0.9", port: 162, received: Date()).item else {
                return XCTFail("v1 not decoded (\(addr.count)-byte agent-addr)")
            }
            let e = TrapReceiver.entry(for: t, registry: MIBRegistry())
            XCTAssertEqual(e.hostname, "10.0.0.9", "an agent-addr of \(addr.count) bytes is not a host")
            XCTAssertLessThanOrEqual(e.fields.first { $0.key == "agent_addr" }?.value.utf8.count ?? 0, 64)
        }
    }

    /// v3 traps are counted, not decoded.
    func testV3TrapIsCountedOnly() {
        let v3 = BER.encodeSequence([BER.encodeInteger(3), BER.encodeSequence([BER.encodeInteger(1), BER.encodeInteger(65507),
                                     BER.encodeOctets([0]), BER.encodeInteger(3)]), BER.encodeOctets([0x30, 0x00]), BER.encodeSequence([])])
        guard case .v3 = TrapListener.decode(v3, host: "h", port: 1, received: Date()).item else { return XCTFail("not v3") }
    }

    /// A trap listener whose consumer is stalled keeps at most `slots` batches in flight.
    func testTrapFloodIsBoundedByTheGate() throws {
        let port = TestSockets.freePort()
        let gate = BacklogGate(slots: 2)
        let got = LockedBox(0)
        let l = try TrapListener(port: port, deliver: { b in got.mutate { $0 += b.count } }, gate: gate)
        l.resume()
        defer { l.cancel() }
        let trap = v2Trap([])
        for _ in 0..<5 {
            TestSockets.sendUDP(trap, to: port, times: 100)
            usleep(200_000)
        }
        XCTAssertEqual(gate.batchesInFlight, 2)
        XCTAssertEqual(got.value + gate.droppedTotal, 500)
        XCTAssertGreaterThan(gate.droppedTotal, 0)
    }

    /// An inform flood (a spoofed source makes us a reflector) is acknowledged at most
    /// `maxAcksPerSecond` times a second.
    func testInformAcksAreRateLimited() throws {
        let port = TestSockets.freePort()
        let l = try TrapListener(port: port, deliver: { _ in })
        l.resume()
        defer { l.cancel() }
        let s = socket(AF_INET, SOCK_DGRAM, 0)
        defer { close(s) }
        var big: Int32 = 4 << 20
        setsockopt(s, SOL_SOCKET, SO_RCVBUF, &big, socklen_t(MemoryLayout<Int32>.size))
        var tv = timeval(tv_sec: 0, tv_usec: 300_000)
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        TestSockets.sendUDP(v2Trap([], inform: true), to: port, times: 1_500, from: s)
        var acks = 0
        var buf = [UInt8](repeating: 0, count: 2_048)
        while recv(s, &buf, buf.count, 0) > 0 { acks += 1 }
        XCTAssertGreaterThan(acks, 0)
        XCTAssertLessThanOrEqual(acks, 2 * TrapListener.maxAcksPerSecond, "two one-second windows at most")
    }

    // MARK: - SNMP client

    /// A "response" with the right request-id but from another source port (a spoofer on the
    /// path, or another host) is never accepted: the socket is connected to the agent.
    func testResponseFromAnotherPortIsIgnored() async throws {
        let (agent, port) = try XCTUnwrap(TestSockets.holdIPv4(SOCK_DGRAM))
        let spoofer = socket(AF_INET, SOCK_DGRAM, 0)
        defer { close(agent); close(spoofer) }
        let answered = LockedBox(0)
        let fdA = agent, fdS = spoofer
        let t = Thread {
            var buf = [UInt8](repeating: 0, count: 65_536)
            var from = sockaddr_storage()
            var flen = socklen_t(MemoryLayout<sockaddr_storage>.size)
            var tv = timeval(tv_sec: 2, tv_usec: 0)
            setsockopt(fdA, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
            let n = withUnsafeMutablePointer(to: &from) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fdA, &buf, buf.count, 0, $0, &flen) } }
            guard n > 0, let m = try? CommunityMessage.decode(Array(buf[0..<n])), let pdu = m.pdu else { return }
            let reply = CommunityMessage.encode(version: .v2c, community: "public",
                                                pdu: SNMPPDU(type: BER.response, requestID: pdu.requestID,
                                                             varBinds: [VarBind(.sysName, .octetString(Data("spoofed".utf8)))]).encoded())
            _ = reply.withUnsafeBytes { r in
                withUnsafePointer(to: &from) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fdS, r.baseAddress, r.count, 0, $0, flen) } }
            }
            answered.mutate { $0 += 1 }
        }
        t.start()
        let client = SNMPClient(target: SNMPTarget(host: "127.0.0.1", port: port, timeout: 0.8, retries: 0),
                                credentials: SNMPCredentials(version: .v2c, community: "public"), engines: EngineCache())
        do {
            let r = try await client.get([.sysName])
            XCTFail("accepted a reply from another port: \(r.varBinds)")
        } catch SNMPError.timeout {
            XCTAssertEqual(answered.value, 1, "the spoofed reply was sent")
        }
    }

    func testEngineCacheIsBounded() {
        let c = EngineCache()
        for i in 0..<5_000 {
            c.set("host\(i):161", .init(engineID: [1, 2, 3, 4, 5], boots: 1, time: 1, learned: Date(), synced: true))
            _ = c.key("k\(i)") { [UInt8(i & 255)] }
        }
        XCTAssertLessThanOrEqual(c.counts.engines, EngineCache.maxEntries)
        XCTAssertLessThanOrEqual(c.counts.keys, EngineCache.maxEntries)
    }
}

private extension ReceivedTrap {
    var isInvalid: Bool { if case .invalid = self { return true }; return false }
}
