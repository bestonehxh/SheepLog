import CommonCrypto
import CryptoKit
import Darwin
import Foundation
import Synchronization

/// The result of one request.
nonisolated struct SNMPReply: Sendable {
    let varBinds: [VarBind]
    /// Round-trip of the (last) request, seconds.
    let rtt: TimeInterval
    /// v3 only: the engine the reply came from.
    let engine: EngineInfo?
    /// A walk stopped at the 10,000 var-bind safety cap.
    var truncated: Bool = false
    /// How many request/response exchanges it took (walks).
    var requests: Int = 1
    /// "GET", "GETNEXT", "GETBULK".
    var operation: String = "GET"
    /// Why a walk ended early, when the agent misbehaved ("OID not increasing: … — a buggy
    /// agent"); net-snmp's snmpwalk stops there with an error too.
    var stopReason: String? = nil
}

/// SNMP v1 / v2c / v3 (USM) over UDP. Own BER codec, no net-snmp. One instance per target;
/// safe to call from any task. Every call runs its blocking socket work on a background
/// queue; cancelling the calling task ends it with `SNMPError.cancelled`.
nonisolated final class SNMPClient: Sendable {
    let target: SNMPTarget
    let credentials: SNMPCredentials
    let engines: EngineCache

    /// Walks stop here and return what they have with `truncated = true`.
    static let walkCap = 10_000
    /// The Interfaces view's table walks: ifTable has 22 columns and a walk returns them one
    /// after another, so `walkCap` cut a 500-port chassis's last columns (out errors, out
    /// octets) off — blank cells, while the rows looked complete. 20,000 interfaces × 22.
    static let interfaceWalkCap = 440_000

    init(target: SNMPTarget, credentials: SNMPCredentials) {
        self.target = target
        self.credentials = credentials
        self.engines = .shared
    }

    init(target: SNMPTarget, credentials: SNMPCredentials, engines: EngineCache) {
        self.target = target
        self.credentials = credentials
        self.engines = engines
    }

    func get(_ oids: [OID]) async throws -> SNMPReply {
        try await run { s in
            let pdu = try s.request(BER.getRequest, oids.map { VarBind($0, .null) })
            return s.reply(pdu.varBinds, operation: "GET")
        }
    }

    func getNext(_ oids: [OID]) async throws -> SNMPReply {
        try await run { s in
            let pdu = try s.request(BER.getNextRequest, oids.map { VarBind($0, .null) })
            return s.reply(pdu.varBinds, operation: "GETNEXT")
        }
    }

    /// v2c/v3 only; v1 callers should use getNext (on v1 this does a GETNEXT).
    func getBulk(_ oids: [OID], nonRepeaters: Int = 0, maxRepetitions: Int = 20) async throws -> SNMPReply {
        // RFC 3416 §4.2.3: N = max(min(non-repeaters, L), 0), M = max(max-repetitions, 0). Agents
        // clamp too, but some answer genErr to out-of-range values — send them in range.
        let nonRepeaters = min(max(0, nonRepeaters), oids.count)
        let maxRepetitions = min(max(0, maxRepetitions), Int(Int32.max))
        return try await run { s in
            if s.version == .v1 {
                let pdu = try s.request(BER.getNextRequest, oids.map { VarBind($0, .null) })
                return s.reply(pdu.varBinds, operation: "GETNEXT")
            }
            let pdu = try s.request(BER.getBulkRequest, oids.map { VarBind($0, .null) },
                                    nonRepeaters: nonRepeaters, maxRepetitions: maxRepetitions)
            return s.reply(pdu.varBinds, operation: "GETBULK")
        }
    }

    /// Walks the subtree under `root` (GETBULK on v2c/v3, GETNEXT on v1). `progress` receives
    /// each chunk as it arrives; the returned reply carries everything and the total time.
    func walk(_ root: OID, progress: (@Sendable ([VarBind]) -> Void)? = nil) async throws -> SNMPReply {
        try await run { s in try s.walk(root, cap: SNMPClient.walkCap, progress: progress) }
    }

    /// `walk` with another var-bind cap (the Interfaces view's whole-table walks).
    func walk(_ root: OID, cap: Int, progress: (@Sendable ([VarBind]) -> Void)? = nil) async throws -> SNMPReply {
        try await run { s in try s.walk(root, cap: cap, progress: progress) }
    }

    /// v3 engine discovery (and time sync). On v1/v2c returns nil.
    func discover() async throws -> EngineInfo? {
        guard credentials.version == .v3 else { return nil }
        return try await run { s in
            try s.discover(force: true)
            return s.engineInfo
        }
    }

    // MARK: Plumbing

    /// The socket work runs on a background queue. Cancelling the calling task answers
    /// `.cancelled` right away — it does not wait for the worker to notice (up to one 100 ms
    /// poll slice, or a slow getaddrinfo for a host name); the worker stops on its own and its
    /// late result is dropped.
    private func run<T: Sendable>(_ body: @escaping @Sendable (SNMPSession) throws -> T) async throws -> T {
        let token = CancelToken()
        let target = self.target, credentials = self.credentials, engines = self.engines
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<T, Error>) in
                // Registered before the worker starts: a cancel that already happened resumes now.
                if !token.onCancel({ cont.resume(throwing: SNMPError.cancelled) }) { return }
                DispatchQueue.global(qos: .userInitiated).async {
                    let result: Result<T, Error>
                    do {
                        let session = try SNMPSession(target: target, credentials: credentials,
                                                      engines: engines, token: token)
                        result = .success(try body(session))
                    } catch {
                        result = .failure(token.isCancelled ? SNMPError.cancelled : error)
                    }
                    // Exactly one resume: either this one or the cancel handler's.
                    if token.finish() { cont.resume(with: result) }
                }
            }
        } onCancel: {
            token.cancel()
        }
    }
}

/// Cancellation shared by the calling task and the socket worker. `onCancel` runs at most
/// once, and never after `finish()` — so a continuation is resumed exactly once by whichever
/// side gets there first. Handlers run outside the lock.
nonisolated final class CancelToken: Sendable {
    private struct State {
        var cancelled = false
        var finished = false
        var handler: (@Sendable () -> Void)?
    }
    private let state = Mutex(State())

    var isCancelled: Bool { state.withLock { $0.cancelled } }

    func cancel() {
        let h: (@Sendable () -> Void)? = state.withLock { s in
            s.cancelled = true
            let h = s.finished ? nil : s.handler
            s.handler = nil
            if h != nil { s.finished = true }
            return h
        }
        h?()
    }

    /// Installs the cancel handler. Already cancelled: runs it now and returns false.
    @discardableResult
    func onCancel(_ h: @escaping @Sendable () -> Void) -> Bool {
        let runNow = state.withLock { s in
            if s.cancelled, !s.finished {
                s.finished = true
                return true
            }
            s.handler = h
            return false
        }
        if runNow { h() }
        return !runNow
    }

    /// The worker is done. True if it gets to deliver its result (no cancel delivered first).
    func finish() -> Bool {
        state.withLock { s in
            guard !s.finished else { return false }
            s.finished = true
            s.handler = nil
            return true
        }
    }
}

// MARK: - Engine cache (v3)

/// What we know about each authoritative engine (per host:port), the localized keys, and
/// the privacy salt counters. Shared by every client; guarded by a lock.
nonisolated final class EngineCache: Sendable {
    static let shared = EngineCache()

    nonisolated struct Entry: Sendable {
        var engineID: [UInt8]
        var boots: UInt32
        var time: UInt32
        var learned: Date
        /// boots/time came from an authenticated message.
        var synced: Bool
        /// `learned` on the monotonic clock (counts through sleep like the agent's own clock;
        /// a stepped system clock does not move it).
        var learnedAt: Double = Monotonic.now()

        /// The engine's clock now, estimated from when we learned it.
        var estimatedTime: UInt32 {
            let delta = max(0, Monotonic.now() - learnedAt)
            return time &+ UInt32(min(delta, Double(UInt32.max / 2)))
        }
    }

    private struct State {
        var entries: [String: Entry] = [:]
        var keys: [String: [UInt8]] = [:]
        var salt64 = UInt64.random(in: 0...UInt64.max)
        var salt32 = UInt32.random(in: 0...UInt32.max)
    }
    private let state = Mutex(State())

    init() {}

    /// Engines and localized keys kept (one per target / user / password seen this session;
    /// a scan of a /16 or a script trying passwords must not grow them forever). Past the cap
    /// the table starts over — a later request simply rediscovers / re-localizes.
    static let maxEntries = 1_024

    func entry(_ key: String) -> Entry? { state.withLock { $0.entries[key] } }
    func set(_ key: String, _ e: Entry) {
        state.withLock { s in
            if s.entries[key] == nil, s.entries.count >= Self.maxEntries { s.entries.removeAll(keepingCapacity: true) }
            s.entries[key] = e
        }
    }
    func remove(_ key: String) { state.withLock { $0.entries[key] = nil } }

    /// The key cached under `id`, else `compute()` (run outside the lock: 1 MB of hashing).
    func key(_ id: String, compute: () -> [UInt8]) -> [UInt8] {
        if let k = state.withLock({ $0.keys[id] }) { return k }
        let k = compute()
        state.withLock { s in
            if s.keys.count >= Self.maxEntries { s.keys.removeAll(keepingCapacity: true) }
            s.keys[id] = k
        }
        return k
    }

    /// Cached engines / keys (tests).
    var counts: (engines: Int, keys: Int) { state.withLock { ($0.entries.count, $0.keys.count) } }

    func nextSalt64() -> UInt64 { state.withLock { $0.salt64 &+= 1; return $0.salt64 } }
    func nextSalt32() -> UInt32 { state.withLock { $0.salt32 &+= 1; return $0.salt32 } }
}

// MARK: - USM crypto (RFC 3414, 7860, 3826, Reeder and Blumenthal key extensions)

nonisolated enum USM {
    static let usmStats = OID([1, 3, 6, 1, 6, 3, 15, 1, 1])
    static let unsupportedSecLevels = usmStats.appending([1, 0])
    static let notInTimeWindows = usmStats.appending([2, 0])
    static let unknownUserNames = usmStats.appending([3, 0])
    static let unknownEngineIDs = usmStats.appending([4, 0])
    static let wrongDigests = usmStats.appending([5, 0])
    static let decryptionErrors = usmStats.appending([6, 0])

    static func digestLength(_ p: AuthProtocol) -> Int {
        switch p {
        case .none: 0
        case .md5: 16
        case .sha1: 20
        case .sha224: 28
        case .sha256: 32
        case .sha384: 48
        case .sha512: 64
        }
    }

    /// msgAuthenticationParameters length (HMAC truncation).
    static func macLength(_ p: AuthProtocol) -> Int {
        switch p {
        case .none: 0
        case .md5, .sha1: 12
        case .sha224: 16
        case .sha256: 24
        case .sha384: 32
        case .sha512: 48
        }
    }

    static func hash(_ p: AuthProtocol, _ data: [UInt8]) -> [UInt8] {
        switch p {
        case .none: return []
        case .md5: return Array(Insecure.MD5.hash(data: data))
        case .sha1: return Array(Insecure.SHA1.hash(data: data))
        case .sha224:
            var out = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
            data.withUnsafeBytes { _ = CC_SHA224($0.baseAddress, CC_LONG(data.count), &out) }
            return out
        case .sha256: return Array(SHA256.hash(data: data))
        case .sha384: return Array(SHA384.hash(data: data))
        case .sha512: return Array(SHA512.hash(data: data))
        }
    }

    /// Ku: the hash of the password repeated to 1,048,576 bytes (RFC 3414 A.2).
    static func passwordToKey(_ password: String, _ p: AuthProtocol) -> [UInt8] {
        passwordToKey(bytes: Array(password.utf8), p)
    }

    /// The same over raw bytes (the Reeder key extension feeds a key back in as the "password").
    static func passwordToKey(bytes pw: [UInt8], _ p: AuthProtocol) -> [UInt8] {
        guard !pw.isEmpty, p != .none else { return hash(p, []) }
        let total = 1_048_576
        var buf: [UInt8] = []
        buf.reserveCapacity(total + pw.count)
        while buf.count < total { buf.append(contentsOf: pw) }
        buf.removeLast(buf.count - total)
        return hash(p, buf)
    }

    /// Kul = H(Ku ‖ engineID ‖ Ku).
    static func localize(_ ku: [UInt8], engineID: [UInt8], _ p: AuthProtocol) -> [UInt8] {
        hash(p, ku + engineID + ku)
    }

    static func localizedKey(password: String, engineID: [UInt8], _ p: AuthProtocol) -> [UInt8] {
        localize(passwordToKey(password, p), engineID: engineID, p)
    }

    static func hmac(_ p: AuthProtocol, key: [UInt8], data: [UInt8]) -> [UInt8] {
        let alg: Int
        switch p {
        case .none: return []
        case .md5: alg = kCCHmacAlgMD5
        case .sha1: alg = kCCHmacAlgSHA1
        case .sha224: alg = kCCHmacAlgSHA224
        case .sha256: alg = kCCHmacAlgSHA256
        case .sha384: alg = kCCHmacAlgSHA384
        case .sha512: alg = kCCHmacAlgSHA512
        }
        var out = [UInt8](repeating: 0, count: digestLength(p))
        key.withUnsafeBytes { k in
            data.withUnsafeBytes { d in
                CCHmac(CCHmacAlgorithm(alg), k.baseAddress, key.count, d.baseAddress, data.count, &out)
            }
        }
        return out
    }

    /// The truncated MAC that goes into msgAuthenticationParameters.
    static func mac(_ p: AuthProtocol, key: [UInt8], message: [UInt8]) -> [UInt8] {
        Array(hmac(p, key: key, data: message).prefix(macLength(p)))
    }

    /// Key material the privacy protocol needs: DES 16 (key + pre-IV), AES 16/24/32.
    static func privKeyLength(_ p: PrivProtocol) -> Int {
        switch p {
        case .none: 0
        case .des, .aes128: 16
        case .aes192, .aes192b: 24
        case .aes256, .aes256b: 32
        }
    }

    /// Key extension of draft-blumenthal-aes-usm-04 §3.1.2.1 (net-snmp's AES192 / AES256 when
    /// built with them, pysnmp's `AesBlumenthal`): append the hash of the key so far until long
    /// enough — Kul' = Kul ‖ H(Kul) ‖ H(Kul ‖ H(Kul)) ‖ …, truncated.
    static func extendKeyBlumenthal(_ kul: [UInt8], to needed: Int, _ p: AuthProtocol) -> [UInt8] {
        var key = kul
        guard !key.isEmpty else { return key }
        while key.count < needed { key += hash(p, key) }
        return Array(key.prefix(needed))
    }

    /// Key extension of draft-reeder-snmpv3-usm-3desede-00 §2.1 (what net-snmp's AES-192/256
    /// "C" variants, Cisco and pysnmp's `AesReeder` do): run the whole password-to-key algorithm
    /// again with the key so far as the password, localize, append — until long enough:
    /// K1 = Kul, K2 = localize(P2K(K1)), key = K1 ‖ K2 ‖ …
    static func extendKey(_ kul: [UInt8], to needed: Int, engineID: [UInt8], _ p: AuthProtocol) -> [UInt8] {
        var key = kul
        guard !key.isEmpty else { return key }
        while key.count < needed {
            key += localize(passwordToKey(bytes: key, p), engineID: engineID, p)
        }
        return Array(key.prefix(needed))
    }

    static func privKey(password: String, auth: AuthProtocol, priv: PrivProtocol, engineID: [UInt8]) -> [UInt8] {
        let kul = localizedKey(password: password, engineID: engineID, auth)
        switch priv {
        case .aes192b, .aes256b: return extendKeyBlumenthal(kul, to: privKeyLength(priv), auth)
        default: return extendKey(kul, to: privKeyLength(priv), engineID: engineID, auth)
        }
    }

    // Encryption. `salt` is what goes into msgPrivacyParameters.

    static func desSalt(boots: UInt32, counter: UInt32) -> [UInt8] { be32(boots) + be32(counter) }
    static func aesSalt(_ v: UInt64) -> [UInt8] { be32(UInt32(v >> 32)) + be32(UInt32(truncatingIfNeeded: v)) }

    static func encrypt(_ p: PrivProtocol, key: [UInt8], boots: UInt32, time: UInt32, salt: [UInt8],
                        plaintext: [UInt8]) throws -> [UInt8] {
        switch p {
        case .none: return plaintext
        case .des:
            guard key.count >= 16, salt.count == 8 else { throw SNMPError.decryptionError }
            let iv = zip(key[8..<16], salt).map { $0 ^ $1 }
            var padded = plaintext
            while padded.count % 8 != 0 { padded.append(0) }
            return try ccCrypt(CCOperation(kCCEncrypt), key: Array(key[0..<8]), iv: iv, input: padded)
        case .aes128, .aes192, .aes256, .aes192b, .aes256b:
            guard key.count >= privKeyLength(p), salt.count == 8 else { throw SNMPError.decryptionError }
            let iv = be32(boots) + be32(time) + salt
            return try aesCFB(CCOperation(kCCEncrypt), key: Array(key.prefix(privKeyLength(p))), iv: iv, input: plaintext)
        }
    }

    static func decrypt(_ p: PrivProtocol, key: [UInt8], boots: UInt32, time: UInt32, salt: [UInt8],
                        ciphertext: [UInt8]) throws -> [UInt8] {
        switch p {
        case .none: return ciphertext
        case .des:
            guard key.count >= 16, salt.count == 8, ciphertext.count % 8 == 0 else { throw SNMPError.decryptionError }
            let iv = zip(key[8..<16], salt).map { $0 ^ $1 }
            return try ccCrypt(CCOperation(kCCDecrypt), key: Array(key[0..<8]), iv: iv, input: ciphertext)
        case .aes128, .aes192, .aes256, .aes192b, .aes256b:
            guard key.count >= privKeyLength(p), salt.count == 8 else { throw SNMPError.decryptionError }
            let iv = be32(boots) + be32(time) + salt
            return try aesCFB(CCOperation(kCCDecrypt), key: Array(key.prefix(privKeyLength(p))), iv: iv, input: ciphertext)
        }
    }

    private static func ccCrypt(_ op: CCOperation, key: [UInt8], iv: [UInt8], input: [UInt8]) throws -> [UInt8] {
        guard !input.isEmpty else { return [] }
        var out = [UInt8](repeating: 0, count: input.count + kCCBlockSizeDES)
        var moved = 0
        let status = CCCrypt(op, CCAlgorithm(kCCAlgorithmDES), CCOptions(0), key, key.count, iv,
                             input, input.count, &out, out.count, &moved)
        guard status == CCCryptorStatus(kCCSuccess) else { throw SNMPError.decryptionError }
        return Array(out.prefix(moved))
    }

    private static func aesCFB(_ op: CCOperation, key: [UInt8], iv: [UInt8], input: [UInt8]) throws -> [UInt8] {
        guard !input.isEmpty else { return [] }
        var ref: CCCryptorRef?
        var status = CCCryptorCreateWithMode(op, CCMode(kCCModeCFB), CCAlgorithm(kCCAlgorithmAES),
                                             CCPadding(ccNoPadding), iv, key, key.count, nil, 0, 0,
                                             CCModeOptions(0), &ref)
        guard status == CCCryptorStatus(kCCSuccess), let ref else { throw SNMPError.decryptionError }
        defer { CCCryptorRelease(ref) }
        var out = [UInt8](repeating: 0, count: input.count + kCCBlockSizeAES128)
        var moved = 0
        status = CCCryptorUpdate(ref, input, input.count, &out, out.count, &moved)
        guard status == CCCryptorStatus(kCCSuccess) else { throw SNMPError.decryptionError }
        var total = moved
        status = out.withUnsafeMutableBytes { buf in
            CCCryptorFinal(ref, buf.baseAddress! + total, buf.count - total, &moved)
        }
        guard status == CCCryptorStatus(kCCSuccess) else { throw SNMPError.decryptionError }
        total += moved
        return Array(out.prefix(total))
    }

    static func be32(_ v: UInt32) -> [UInt8] {
        [UInt8(v >> 24), UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)]
    }
}

// MARK: - SNMPv3 message (RFC 3412 / 3414)

nonisolated struct V3Flags {
    static let auth: UInt8 = 0x01
    static let priv: UInt8 = 0x02
    static let reportable: UInt8 = 0x04
}

/// A decoded (and, when keys were given, verified + decrypted) SNMPv3 message.
nonisolated struct V3Message: Sendable {
    var msgID: Int32
    var maxSize: Int
    var flags: UInt8
    var securityModel: Int
    var engineID: [UInt8]
    var boots: UInt32
    var time: UInt32
    var userName: [UInt8]
    var authParams: [UInt8]
    var privParams: [UInt8]
    var contextEngineID: [UInt8]
    var contextName: [UInt8]
    var pdu: SNMPPDU
}

/// Encodes and decodes USM messages for one user. The keys are already localized to the
/// authoritative engine.
nonisolated struct USMSecurity: Sendable {
    var userName: String
    var auth: AuthProtocol
    var priv: PrivProtocol
    var authKey: [UInt8]
    var privKey: [UInt8]

    static let noAuth = USMSecurity(userName: "", auth: .none, priv: .none, authKey: [], privKey: [])

    var flags: UInt8 {
        var f: UInt8 = 0
        if auth != .none { f |= V3Flags.auth }
        if auth != .none, priv != .none { f |= V3Flags.priv }
        return f
    }

    /// `salt` for priv: DES 8 bytes (boots ‖ counter), AES 8 bytes (64-bit counter).
    func encode(msgID: Int32, reportable: Bool, engineID: [UInt8], boots: UInt32, time: UInt32,
                contextEngineID: [UInt8], contextName: String, pdu: SNMPPDU, salt: [UInt8]) throws -> [UInt8] {
        let scoped = BER.encodeSequence([
            BER.encodeOctets(contextEngineID),
            BER.encodeOctets(Array(contextName.utf8)),
            pdu.encoded(),
        ])
        var f = flags
        if reportable { f |= V3Flags.reportable }
        var msgData = scoped
        var privParams: [UInt8] = []
        if f & V3Flags.priv != 0 {
            let cipher = try USM.encrypt(priv, key: privKey, boots: boots, time: time, salt: salt, plaintext: scoped)
            msgData = BER.encodeOctets(cipher)
            privParams = salt
        }
        let macLen = f & V3Flags.auth != 0 ? USM.macLength(auth) : 0
        let privTLV = BER.encodeOctets(privParams)
        let secParams = BER.encodeSequence([
            BER.encodeOctets(engineID),
            BER.encodeInteger(Int64(boots)),
            BER.encodeInteger(Int64(time)),
            BER.encodeOctets(Array(userName.utf8)),
            BER.encodeOctets([UInt8](repeating: 0, count: macLen)),
            privTLV,
        ])
        var message = BER.encodeSequence([
            BER.encodeInteger(3),
            BER.encodeSequence([
                BER.encodeInteger(Int64(msgID)),
                BER.encodeInteger(65507),
                BER.encodeOctets([f]),
                BER.encodeInteger(3),
            ]),
            BER.encodeOctets(secParams),
            msgData,
        ])
        if macLen > 0 {
            // Everything after the (zeroed) auth parameters is privParams TLV + msgData.
            let offset = message.count - msgData.count - privTLV.count - macLen
            let digest = USM.mac(auth, key: authKey, message: message)
            message.replaceSubrange(offset..<(offset + macLen), with: digest)
        }
        return message
    }

    /// Parses a v3 message. When the message says it is authenticated the digest is checked
    /// (`.wrongDigest`), when encrypted it is decrypted (`.decryptionError`).
    func decode(_ bytes: [UInt8]) throws -> V3Message {
        var outer = BERReader(bytes)
        var r = try outer.readSequence()
        guard try r.readInteger() == 3 else { throw SNMPError.decode("not an SNMPv3 message") }
        var g = try r.readSequence()
        let msgID = try g.readInteger()
        let maxSize = try g.readInteger()
        let flagBytes = try g.readOctets()
        let model = try g.readInteger()
        guard flagBytes.count == 1 else { throw SNMPError.decode("bad msgFlags") }
        let f = flagBytes[0]
        guard model == 3 else { throw SNMPError.decode("security model \(model) is not USM") }
        var sp = try r.read(BER.octetString).reader
        var s = try sp.readSequence()
        let engineID = try s.readOctets()
        // SnmpEngineID is SIZE(5..32) (RFC 3411); empty is the discovery probe.
        guard engineID.count <= 32 else { throw SNMPError.decode("engine ID longer than 32 bytes") }
        let boots = try s.readInteger()
        let time = try s.readInteger()
        let user = try s.readOctets()
        let authTLV = try s.read(BER.octetString)
        let privParams = try s.readOctets()
        let data = try r.readTLV()

        if f & V3Flags.auth != 0 {
            guard auth != .none else { throw SNMPError.unsupportedSecurityLevel }
            guard authTLV.count == USM.macLength(auth) else {
                // Not a password problem: the agent computes this protocol's digest another way
                // (a 16-byte "SHA-256" is a pre-RFC 7860 implementation). Said at once — the
                // request is not retried until it times out.
                if authTLV.count == 0 { throw SNMPError.wrongDigest }
                throw SNMPError.decode("the agent's authentication code is \(authTLV.count) bytes; \(auth.label) "
                    + "uses \(USM.macLength(auth)) (RFC 3414 / 7860) — the agent implements \(auth.label) differently. "
                    + "Try another authentication protocol the agent supports")
            }
            var zeroed = bytes
            zeroed.replaceSubrange(authTLV.range, with: [UInt8](repeating: 0, count: authTLV.count))
            let expected = USM.mac(auth, key: authKey, message: zeroed)
            guard constantTimeEqual(expected, authTLV.content) else { throw SNMPError.wrongDigest }
        }

        var scopedTLV: TLV
        if f & V3Flags.priv != 0 {
            guard f & V3Flags.auth != 0, priv != .none else { throw SNMPError.unsupportedSecurityLevel }
            guard data.tag == BER.octetString else { throw SNMPError.decryptionError }
            let plain = try USM.decrypt(priv, key: privKey, boots: UInt32(truncatingIfNeeded: boots),
                                        time: UInt32(truncatingIfNeeded: time), salt: privParams,
                                        ciphertext: data.content)
            var pr = BERReader(plain)
            guard let t = try? pr.read(BER.sequence) else { throw SNMPError.decryptionError }
            scopedTLV = t
        } else {
            guard data.tag == BER.sequence else { throw SNMPError.decode("expected a plaintext scopedPDU") }
            scopedTLV = data
        }
        let ctxEngine: [UInt8], ctxName: [UInt8], pdu: SNMPPDU
        do {
            var sc = scopedTLV.reader
            ctxEngine = try sc.readOctets()
            ctxName = try sc.readOctets()
            pdu = try SNMPPDU.decode(try sc.readTLV())
        } catch SNMPError.decode where f & V3Flags.priv != 0 {
            // The digest was fine but the decrypted scopedPDU does not parse: the priv key
            // (password or protocol) is wrong. Only here — a malformed header stays `.decode`.
            throw SNMPError.decryptionError
        }
        return V3Message(msgID: Int32(truncatingIfNeeded: msgID), maxSize: Int(clamping: maxSize), flags: f,
                         securityModel: Int(model), engineID: engineID,
                         boots: UInt32(truncatingIfNeeded: boots), time: UInt32(truncatingIfNeeded: time),
                         userName: user, authParams: authTLV.content, privParams: privParams,
                         contextEngineID: ctxEngine, contextName: ctxName, pdu: pdu)
    }

    /// Reads just msgID and the header — used to tell a stray datagram from ours before the
    /// (possibly failing) security checks.
    static func peekMsgID(_ bytes: [UInt8]) -> Int32? {
        var outer = BERReader(bytes)
        guard var r = try? outer.readSequence(), (try? r.readInteger()) == 3,
              var g = try? r.readSequence(), let id = try? g.readInteger() else { return nil }
        return Int32(truncatingIfNeeded: id)
    }

    private func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count { diff |= a[i] ^ b[i] }
        return diff == 0
    }
}

// MARK: - UDP

nonisolated final class UDPEndpoint {
    private(set) var fd: Int32 = -1
    let host: String
    let port: UInt16
    /// Every address the name resolved to, in getaddrinfo order; `current` is connected.
    private var addresses: [(family: Int32, addr: [UInt8])] = []
    private var current = 0
    /// The last datagram sent, re-sent when an address turns out to be dead.
    private var lastSent: [UInt8]?

    init(host: String, port: UInt16) throws {
        self.host = host
        self.port = port
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_DGRAM
        hints.ai_protocol = IPPROTO_UDP
        var res: UnsafeMutablePointer<addrinfo>?
        let h = host.trimmingCharacters(in: CharacterSet(charactersIn: "[] "))
        let rc = getaddrinfo(h, String(port), &hints, &res)
        guard rc == 0, let first = res else {
            throw SNMPError.network("cannot resolve \(host): \(String(cString: gai_strerror(rc)))")
        }
        defer { freeaddrinfo(res) }
        var p: UnsafeMutablePointer<addrinfo>? = first
        while let ai = p {
            if let sa = ai.pointee.ai_addr {
                let bytes = [UInt8](UnsafeRawBufferPointer(start: sa, count: Int(ai.pointee.ai_addrlen)))
                addresses.append((ai.pointee.ai_family, bytes))
            }
            p = ai.pointee.ai_next
        }
        var lastErr: Int32 = 0
        for k in addresses.indices {
            let e = open(k)
            if e == 0 { current = k; return }
            lastErr = e
        }
        throw SNMPError.network("cannot open UDP to \(host): \(String(cString: strerror(lastErr)))")
    }

    /// Opens and connects a socket to `addresses[k]`, replacing the current one. 0 or errno.
    private func open(_ k: Int) -> Int32 {
        let a = addresses[k]
        let s = socket(a.family, SOCK_DGRAM, IPPROTO_UDP)
        guard s >= 0 else { return errno }
        let rc = a.addr.withUnsafeBytes {
            connect(s, $0.baseAddress!.assumingMemoryBound(to: sockaddr.self), socklen_t(a.addr.count))
        }
        guard rc == 0 else { let e = errno; Darwin.close(s); return e }
        var big: Int32 = 1 << 20
        setsockopt(s, SOL_SOCKET, SO_RCVBUF, &big, socklen_t(MemoryLayout<Int32>.size))
        // macOS refuses to send a UDP datagram larger than SO_SNDBUF (net.inet.udp.maxdgram,
        // 9216 by default) with EMSGSIZE — a GET of a few hundred OIDs is bigger than that.
        var send: Int32 = 65_535
        setsockopt(s, SOL_SOCKET, SO_SNDBUF, &send, socklen_t(MemoryLayout<Int32>.size))
        if fd >= 0 { Darwin.close(fd) }
        fd = s
        return 0
    }

    /// ICMP port unreachable from this address: move to the next one the name resolved to
    /// ("localhost" → ::1 first, while the agent often listens on 127.0.0.1 only) and re-send.
    private func failover() -> Bool {
        var k = current + 1
        while k < addresses.count {
            if open(k) == 0 {
                current = k
                if let packet = lastSent {
                    _ = packet.withUnsafeBytes { Darwin.send(fd, $0.baseAddress, $0.count, 0) }
                }
                return true
            }
            k += 1
        }
        return false
    }

    /// One receive buffer per endpoint (a 64 KB zero-filled allocation per datagram adds up
    /// over a 500-request walk). Big enough for the largest UDP payload.
    private var buf = [UInt8](repeating: 0, count: 65_536)

    deinit { if fd >= 0 { Darwin.close(fd) } }

    func send(_ bytes: [UInt8]) throws {
        lastSent = bytes
        while true {
            let n = bytes.withUnsafeBytes { Darwin.send(fd, $0.baseAddress, $0.count, 0) }
            if n >= 0 { return }
            let e = errno
            if e == EINTR { continue }
            if e == ECONNREFUSED {
                // A refusal left over from the previous datagram: this one may still get through.
                if failover() { return }
                throw refused
            }
            throw SNMPError.network("send failed: \(String(cString: strerror(e)))")
        }
    }

    private var refused: SNMPError {
        .network("\(host) refused UDP \(port) (ICMP port unreachable) — SNMP is not listening there")
    }

    /// The next datagram, or nil at the deadline. Polls in 100 ms slices to notice cancellation.
    func receive(until deadline: Date, token: CancelToken) throws -> [UInt8]? {
        try receive(untilMonotonic: Monotonic.now() + deadline.timeIntervalSinceNow, token: token)
    }

    /// `deadline` on `Monotonic` (a system clock stepped back must not stretch the timeout).
    func receive(untilMonotonic deadline: Double, token: CancelToken) throws -> [UInt8]? {
        while true {
            if token.isCancelled { throw SNMPError.cancelled }
            let remaining = deadline - Monotonic.now()
            if remaining <= 0 { return nil }
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let r = poll(&pfd, 1, Int32(max(1, min(remaining, 0.1) * 1000)))
            if r < 0 {
                let e = errno
                if e == EINTR { continue }
                throw SNMPError.network("poll failed: \(String(cString: strerror(e)))")
            }
            if r == 0 { continue }
            let n = recv(fd, &buf, buf.count, 0)
            if n < 0 {
                let e = errno
                if e == EINTR || e == EAGAIN { continue }
                if e == ECONNREFUSED {
                    if failover() { continue }
                    throw refused
                }
                throw SNMPError.network("receive failed: \(String(cString: strerror(e)))")
            }
            return Array(buf[0..<n])
        }
    }
}

// MARK: - Session (one call, one background thread)

nonisolated final class SNMPSession {
    let target: SNMPTarget
    let credentials: SNMPCredentials
    let engines: EngineCache
    let token: CancelToken
    let socket: UDPEndpoint
    var version: SNMPVersion { credentials.version }
    private(set) var lastRTT: TimeInterval = 0
    private(set) var requests = 0

    private var cacheKey: String { "\(target.host.lowercased()):\(target.port)" }

    init(target: SNMPTarget, credentials: SNMPCredentials, engines: EngineCache, token: CancelToken) throws {
        self.target = target
        self.credentials = credentials
        self.engines = engines
        self.token = token
        if token.isCancelled { throw SNMPError.cancelled }
        socket = try UDPEndpoint(host: target.host, port: target.port)
    }

    var engineInfo: EngineInfo? {
        guard version == .v3, let e = engines.entry(cacheKey) else { return nil }
        return EngineInfo(engineID: Data(e.engineID), boots: e.boots, time: e.estimatedTime)
    }

    func reply(_ vbs: [VarBind], operation: String, truncated: Bool = false, rtt: TimeInterval? = nil) -> SNMPReply {
        SNMPReply(varBinds: vbs, rtt: rtt ?? lastRTT, engine: engineInfo, truncated: truncated,
                  requests: max(1, requests), operation: operation)
    }

    /// Sends, retries with fresh ids, returns the first datagram `accept` recognises.
    /// `accept` returns nil for datagrams that are not ours; throwing ends the exchange.
    private func exchange<T>(build: (Int32) throws -> [UInt8], accept: ([UInt8], Set<Int32>) throws -> T?) throws -> T {
        var ids = Set<Int32>()
        let attempts = min(max(0, target.retries), 100) + 1
        for _ in 0..<attempts {
            if token.isCancelled { throw SNMPError.cancelled }
            let id = Int32.random(in: 1...Int32.max)
            ids.insert(id)
            let packet = try build(id)
            let started = Monotonic.now()
            try socket.send(packet)
            let deadline = started + max(0.05, target.timeout)
            while let datagram = try socket.receive(untilMonotonic: deadline, token: token) {
                if let result = try accept(datagram, ids) {
                    lastRTT = Monotonic.now() - started
                    requests += 1
                    return result
                }
            }
        }
        throw SNMPError.timeout
    }

    /// One request of any type; error-status ≠ 0 throws `.response`.
    func request(_ type: UInt8, _ vbs: [VarBind], nonRepeaters: Int = 0, maxRepetitions: Int = 0) throws -> SNMPPDU {
        let pdu: SNMPPDU
        if version == .v3 {
            pdu = try v3Request(type, vbs, nonRepeaters: nonRepeaters, maxRepetitions: maxRepetitions)
        } else {
            pdu = try communityRequest(type, vbs, nonRepeaters: nonRepeaters, maxRepetitions: maxRepetitions)
        }
        if pdu.errorStatus != 0 { throw SNMPError.response(status: pdu.errorStatus, index: pdu.errorIndex) }
        return pdu
    }

    private func communityRequest(_ type: UInt8, _ vbs: [VarBind], nonRepeaters: Int, maxRepetitions: Int) throws -> SNMPPDU {
        try exchange(build: { id in
            CommunityMessage.encode(version: version, community: credentials.community,
                                    pdu: SNMPPDU(type: type, requestID: id, errorStatus: nonRepeaters,
                                                 errorIndex: maxRepetitions, varBinds: vbs).encoded())
        }, accept: { bytes, ids in
            guard let m = try? CommunityMessage.decode(bytes), let pdu = m.pdu,
                  pdu.type == BER.response, ids.contains(pdu.requestID) else { return nil }
            return pdu
        })
    }

    // MARK: v3

    nonisolated private enum V3Outcome {
        case response(SNMPPDU)
        case report(OID, V3Message)
    }

    /// Passwords never appear in the key cache's ids, only their SHA-256.
    private static func fingerprint(_ s: String) -> String {
        SHA256.hash(data: Data(s.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private func security(engineID: [UInt8], priv: PrivProtocol? = nil) -> USMSecurity {
        var c = credentials
        if let priv { c.privProtocol = priv }
        let hex = engineID.map { String(format: "%02x", $0) }.joined()
        let authKey = c.authProtocol == .none ? [] :
            engines.key("a|\(c.authProtocol.rawValue)|\(hex)|\(Self.fingerprint(c.authPassword))") {
                USM.localizedKey(password: c.authPassword, engineID: engineID, c.authProtocol)
            }
        let privKey = (c.authProtocol == .none || c.privProtocol == .none) ? [] :
            engines.key("p|\(c.authProtocol.rawValue)|\(c.privProtocol.rawValue)|\(hex)|\(Self.fingerprint(c.privPassword))") {
                USM.privKey(password: c.privPassword, auth: c.authProtocol, priv: c.privProtocol, engineID: engineID)
            }
        return USMSecurity(userName: c.username, auth: c.authProtocol,
                           priv: c.authProtocol == .none ? .none : c.privProtocol,
                           authKey: authKey, privKey: privKey)
    }

    private func salt(for sec: USMSecurity, boots: UInt32) -> [UInt8] {
        switch sec.priv {
        case .none: []
        case .des: USM.desSalt(boots: boots, counter: engines.nextSalt32())
        default: USM.aesSalt(engines.nextSalt64())
        }
    }

    /// One v3 exchange with the security in `sec` (noAuth for discovery).
    private func v3Exchange(_ type: UInt8, _ vbs: [VarBind], nonRepeaters: Int, maxRepetitions: Int,
                            sec: USMSecurity, engine: EngineCache.Entry?) throws -> V3Outcome {
        let engineID = engine?.engineID ?? []
        return try exchange(build: { id in
            let boots = engine?.boots ?? 0
            let time = engine?.estimatedTime ?? 0
            let pdu = SNMPPDU(type: type, requestID: id, errorStatus: nonRepeaters,
                              errorIndex: maxRepetitions, varBinds: vbs)
            return try sec.encode(msgID: id, reportable: true, engineID: engineID, boots: boots, time: time,
                                  contextEngineID: engineID, contextName: credentials.contextName, pdu: pdu,
                                  salt: salt(for: sec, boots: boots))
        }, accept: { bytes, ids in
            guard let msgID = USMSecurity.peekMsgID(bytes), ids.contains(msgID) else { return nil }
            // Digest first, then decrypt (inside decode). A decrypted scopedPDU that does not
            // parse is `.decryptionError`; a malformed header stays `.decode`.
            let m = try sec.decode(bytes)
            if m.pdu.type == BER.report {
                return .report(m.pdu.varBinds.first?.oid ?? OID([]), m)
            }
            guard m.pdu.type == BER.response else { return nil }
            if sec.auth != .none, m.flags & V3Flags.auth == 0 { throw SNMPError.wrongDigest }
            // A response comes from the authoritative engine we addressed (RFC 3414 §3.2 step 3).
            if !engineID.isEmpty, m.engineID != engineID { return nil }
            if m.flags & V3Flags.auth != 0 { learnTime(m, fromReport: false) }
            return .response(m.pdu)
        })
    }

    /// An empty GET: discovery, time synchronisation, the priv diagnosis.
    private func probe(_ sec: USMSecurity, engine: EngineCache.Entry?) throws -> V3Outcome {
        try v3Exchange(BER.getRequest, [], nonRepeaters: 0, maxRepetitions: 0, sec: sec, engine: engine)
    }

    /// Discovery: the (unauthenticated) report names the engine. The only place the cached
    /// engine ID may change.
    private func learnEngine(_ m: V3Message) {
        guard !m.engineID.isEmpty else { return }
        engines.set(cacheKey, EngineCache.Entry(engineID: m.engineID, boots: m.boots, time: m.time,
                                                learned: Date(), synced: false))
    }

    /// Boots/time from a message of the engine we already know. Never switches the engine ID —
    /// an unauthenticated report must not be able to redirect us to another engine (and
    /// another key localisation). Authenticated responses only move the clock forward
    /// (RFC 3414 §3.2 step 7b); a notInTimeWindows report (an agent reboot) resets it.
    @discardableResult
    private func learnTime(_ m: V3Message, fromReport: Bool) -> Bool {
        guard let e = engines.entry(cacheKey), e.engineID == m.engineID else { return false }
        let authenticated = m.flags & V3Flags.auth != 0
        if !fromReport, e.synced, m.boots < e.boots || (m.boots == e.boots && m.time < e.time) { return true }
        engines.set(cacheKey, EngineCache.Entry(engineID: e.engineID, boots: m.boots, time: m.time,
                                                learned: Date(), synced: authenticated))
        return true
    }

    /// Engine discovery (RFC 3414 §4): an unauthenticated probe learns the engine ID, then for
    /// auth levels an authenticated probe learns (or confirms) boots/time.
    func discover(force: Bool) throws {
        if !force, let e = engines.entry(cacheKey), e.synced || credentials.authProtocol == .none { return }
        engines.remove(cacheKey)
        switch try probe(.noAuth, engine: nil) {
        case .report(_, let m):
            guard !m.engineID.isEmpty else { throw SNMPError.decode("discovery report without an engine ID") }
            learnEngine(m)
        case .response:
            throw SNMPError.decode("the agent answered discovery without a report")
        }
        guard credentials.authProtocol != .none else { return }
        // Time synchronisation with an authenticated probe.
        let sec = security(engineID: engines.entry(cacheKey)?.engineID ?? [])
        for attempt in 0..<2 {
            let outcome: V3Outcome
            do {
                outcome = try probe(sec, engine: engines.entry(cacheKey))
            } catch SNMPError.timeout where sec.priv != .none {
                // net-snmp silently drops what it cannot decrypt. The engine answered the
                // discovery probe a moment ago, so ask again without privacy: if the digest is
                // accepted, the priv password or protocol is what is wrong.
                try diagnosePrivTimeout(sec)
                throw SNMPError.timeout
            }
            switch outcome {
            case .response:
                return
            case .report(let oid, let m):
                if oid == USM.notInTimeWindows, attempt == 0, learnTime(m, fromReport: true) { continue }
                if oid == USM.decryptionErrors { try tryOtherKeyExtension(sec) }
                try throwReport(oid)
            }
        }
    }

    private func diagnosePrivTimeout(_ sec: USMSecurity) throws {
        var authOnly = sec
        authOnly.priv = .none
        let outcome: V3Outcome
        do {
            outcome = try probe(authOnly, engine: engines.entry(cacheKey))
        } catch SNMPError.timeout {
            return
        }
        switch outcome {
        case .response:
            try tryOtherKeyExtension(sec)
            throw SNMPError.decryptionError
        case .report(let oid, _):
            if oid == USM.unsupportedSecLevels || oid == USM.notInTimeWindows {
                try tryOtherKeyExtension(sec)
                throw SNMPError.decryptionError
            }
            try throwReport(oid)
        }
    }

    /// AES-192/256 keys are extended two ways (Reeder/Cisco and Blumenthal) and nothing on the
    /// wire says which: when the privacy part failed, try the other one once — if the agent
    /// answers, say which to pick instead of "wrong priv password".
    private func tryOtherKeyExtension(_ sec: USMSecurity) throws {
        guard let other = sec.priv.otherKeyExtension, let engine = engines.entry(cacheKey) else { return }
        let alt = security(engineID: engine.engineID, priv: other)
        if case .response? = try? probe(alt, engine: engines.entry(cacheKey)) {
            throw SNMPError.privKeyExtension(other)
        }
    }

    private func throwReport(_ oid: OID) throws -> Never {
        switch oid {
        case USM.unknownUserNames: throw SNMPError.unknownUser
        case USM.wrongDigests: throw SNMPError.wrongDigest
        case USM.unsupportedSecLevels: throw SNMPError.unsupportedSecurityLevel
        case USM.decryptionErrors: throw SNMPError.decryptionError
        case USM.notInTimeWindows: throw SNMPError.notInTimeWindow
        case USM.unknownEngineIDs: throw SNMPError.unknownEngineID
        default:
            if let text = Self.reportText(oid) { throw SNMPError.decode(text) }
            throw SNMPError.decode("agent sent a report: \(oid.parts.isEmpty ? "(no var-binds)" : oid.dotted)")
        }
    }

    /// Reports outside USM (SNMP-MPD-MIB, SNMP-TARGET-MIB), in words. A context name the agent
    /// does not have is the common one (a typo in the Context field, or a VRF the device lacks).
    /// `SNMPError` has no case for these, so they travel as `.decode` with a message that
    /// `SNMPTestModel.hint(for:)` recognises.
    static func reportText(_ oid: OID) -> String? {
        let mpd = OID([1, 3, 6, 1, 6, 3, 11, 2, 1]), target = OID([1, 3, 6, 1, 6, 3, 12, 1])
        let p = oid.parts
        if mpd.isPrefix(of: oid), p.count > mpd.parts.count {
            switch p[mpd.parts.count] {
            case 1: return "the agent does not support the USM security model (snmpUnknownSecurityModels report)"
            case 2: return "the agent found the message invalid (snmpInvalidMsgs report)"
            case 3: return "the agent has no handler for this request type (snmpUnknownPDUHandlers report)"
            default: return nil
            }
        }
        if target.isPrefix(of: oid), p.count > target.parts.count {
            switch p[target.parts.count] {
            case 4: return "the SNMPv3 context is not available (snmpUnavailableContexts report)"
            case 5: return "the agent has no SNMPv3 context by that name (snmpUnknownContexts report)"
            default: return nil
            }
        }
        return nil
    }

    private func v3Request(_ type: UInt8, _ vbs: [VarBind], nonRepeaters: Int, maxRepetitions: Int) throws -> SNMPPDU {
        try discover(force: false)
        var resynced = false
        var rediscovered = false
        while true {
            guard let engine = engines.entry(cacheKey) else { throw SNMPError.unknownEngineID }
            let sec = security(engineID: engine.engineID)
            let outcome: V3Outcome
            do {
                outcome = try v3Exchange(type, vbs, nonRepeaters: nonRepeaters, maxRepetitions: maxRepetitions,
                                         sec: sec, engine: engine)
            } catch SNMPError.timeout where sec.priv != .none {
                // An agent drops what it cannot decrypt: after a change of priv password or
                // protocol (the engine cached as synced from an earlier run) this is silence.
                // The engine is discovered again next time — with the priv check `discover`
                // runs — rather than trusted.
                engines.remove(cacheKey)
                throw SNMPError.timeout
            }
            switch outcome {
            case .response(let pdu):
                return pdu
            case .report(let oid, let m):
                // The agent rebooted (boots moved on) or our clock estimate drifted: take the
                // engine's boots/time from the report and try exactly once more.
                if oid == USM.notInTimeWindows, !resynced, learnTime(m, fromReport: true) {
                    resynced = true
                    continue
                }
                if oid == USM.unknownEngineIDs, !rediscovered {
                    rediscovered = true
                    try discover(force: true)
                    continue
                }
                try throwReport(oid)
            }
        }
    }

    // MARK: Walk

    func walk(_ root: OID, cap: Int = SNMPClient.walkCap, progress: (@Sendable ([VarBind]) -> Void)?) throws -> SNMPReply {
        let started = Monotonic.now()
        let useBulk = version != .v1
        var all: [VarBind] = []
        var current = root
        var maxRep = 20
        var truncated = false
        var stopReason: String?
        walking: while true {
            if token.isCancelled { throw SNMPError.cancelled }
            let pdu: SNMPPDU
            do {
                pdu = useBulk
                    ? try request(BER.getBulkRequest, [VarBind(current, .null)], nonRepeaters: 0, maxRepetitions: maxRep)
                    : try request(BER.getNextRequest, [VarBind(current, .null)])
            } catch SNMPError.response(let status, _) where status == 2 && !useBulk {
                break walking                       // v1 noSuchName = end of MIB
            } catch SNMPError.response(let status, _) where status == 1 && useBulk && maxRep > 1 {
                maxRep = max(1, maxRep / 2)          // tooBig: ask for fewer
                continue
            }
            var chunk: [VarBind] = []
            var done = pdu.varBinds.isEmpty
            var previous = current
            for vb in pdu.varBinds {
                // Any exception ends the walk (net-snmp's snmpwalk does the same): a GETNEXT/
                // GETBULK should only ever produce endOfMibView, but agents also send
                // noSuchObject / noSuchInstance at the end of a view.
                if vb.value.isException || !root.isPrefix(of: vb.oid) || vb.oid == root { done = true; break }
                if !(previous < vb.oid) {                        // not increasing: agent loop / bug
                    stopReason = "OID not increasing: the agent sent \(vb.oid.dotted) after \(previous.dotted)"
                    done = true
                    break
                }
                if all.count + chunk.count >= cap { truncated = true; done = true; break }
                chunk.append(vb)
                previous = vb.oid
            }
            if !chunk.isEmpty {
                all += chunk
                progress?(chunk)
            }
            if done { break }
            current = previous
        }
        if all.isEmpty, !root.parts.isEmpty {
            // The root may itself be an instance (sysDescr.0): answer it with a GET.
            do {
                let pdu = try request(BER.getRequest, [VarBind(root, .null)])
                if let vb = pdu.varBinds.first, vb.oid == root, !vb.value.isException, vb.value != .null {
                    all = [vb]
                    progress?(all)
                }
            } catch SNMPError.cancelled {
                throw SNMPError.cancelled
            } catch {
                // Not an instance (v1 noSuchName and the like): the walk is simply empty.
            }
        }
        var r = reply(all, operation: useBulk ? "GETBULK" : "GETNEXT", truncated: truncated,
                      rtt: Monotonic.now() - started)
        r.stopReason = stopReason
        return r
    }
}
