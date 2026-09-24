import XCTest
@testable import SheepLog

/// One real-shaped fixture per vendor (no customer data), header variants, and TCP framing.
/// The same lines are sent by `Tests/replay.sh`.
final class SyslogParserTests: XCTestCase {
    static let received = date(2026, 9, 23, 10, 15, 40)

    static func date(_ y: Int, _ mo: Int, _ d: Int, _ h: Int, _ mi: Int, _ s: Int,
                     zone: TimeZone = .current) -> Date {
        var c = DateComponents()
        c.year = y; c.month = mo; c.day = d; c.hour = h; c.minute = mi; c.second = s
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = zone
        return cal.date(from: c)!
    }

    /// `parsedLine` received at `Self.received` (the year of a 3164 timestamp follows it).
    private func parse(_ text: String, from address: String = "10.1.0.1", received: Date = received,
                       override: Vendor? = nil) -> LogEntry {
        parsedLine(text, from: address, received: received, vendor: override)
    }

    // MARK: - Vendors

    static let arubaCX = "<187>1 2026-09-23T10:15:32.123+07:00 CX-6300-01 lldpd 2512 - - Event|1302|LOG_WARN|AMM|1/1|LLDP neighbor 10.1.0.9 removed on port 1/1/24"
    static let arubaOS = "<133>Sep 23 10:12:01 2026 MM-1 authmgr[4211]: <522008> <4211> <NOTI> <MM-1 10.1.1.10>  User Authentication Successful: username=alice MAC=02:00:5e:10:00:01 IP=10.20.0.15 role=employee VLAN=20 AP=AP-Lobby SSID=Corp"
    static let arubaIAP = "<132>Sep 23 10:12:05 2026 10.1.1.21 cli[3510]: <341004> <WARN> |AP IAP-305-Lobby@10.1.1.21 cli| Recv image upgrade request"
    static let arubaSwitch = "<14> Sep 23 10:15:32 10.1.0.20 00076 ports: port 1/1/24 is now off-line"
    static let clearPass = "<14>Sep 23 10:15:32 cppm01 CPPM_RADIUS_Logs 1234 1 0 Common.Username=alice,Common.Service=Corp Wireless 802.1X,Common.Login-Status=REJECT,Common.Roles=[Employee], [User Authenticated],RADIUS.Auth-Source=AD:ad01.corp.example,Common.NAS-IP-Address=10.1.1.10"
    static let huawei = "<187>Sep 23 2026 10:15:32 HW-CE6881 %%01IFNET/4/LINK_STATE(l)[12]:The line protocol IP on the interface 10GE1/0/24 has entered the DOWN state."
    static let checkPoint = "<134>1 2026-09-23T03:15:32Z cp-gw-01 CheckPoint 26045 - [action:\"Drop\"; flags:\"411908\"; ifdir:\"inbound\"; ifname:\"eth1\"; origin:\"10.1.0.2\"; product:\"VPN-1 & FireWall-1\"; src:\"203.0.113.50\"; dst:\"10.1.0.80\"; proto:\"6\"; service:\"22\"; severity:\"High\"]"
    static let checkPointKV = "<13>Sep 23 10:15:32 cp-mgmt time=1790139332; action=Accept; product=VPN-1 & FireWall-1; src=10.1.0.5; dst=8.8.8.8; service=53; level=Low;"
    static let paloTraffic = "<14>Sep 23 10:15:32 PA-3220 1,2026/09/23 10:15:32,012801012345,TRAFFIC,end,2561,2026/09/23 10:15:32,10.1.0.5,8.8.8.8,203.0.113.10,8.8.8.8,allow-dns,corp\\alice,,dns-base,vsys1,trust,untrust,ethernet1/2,ethernet1/1,default,,123456,1,53012,53,41234,53,0x400064,udp,allow,196,98,98,2,2026/09/23 10:15:02,0,any,,7300000000000000,0x0,10.0.0.0-10.255.255.255,United States,,1,1"
    static let paloThreat = "<12>Sep 23 10:16:01 PA-3220 1,2026/09/23 10:16:01,012801012345,THREAT,url,2561,2026/09/23 10:16:01,10.1.0.5,93.184.216.34,203.0.113.10,93.184.216.34,allow-web,corp\\alice,,web-browsing,vsys1,trust,untrust,ethernet1/2,ethernet1/1,default,,123457,1,53100,80,41300,80,0x40b000,tcp,alert,\"example.com/a,b?x=1\",(9999),malware,high,client-to-server,7300000000000001"
    static let paloSystem = "<14>Sep 23 10:17:00 PA-3220 1,2026/09/23 10:17:00,012801012345,SYSTEM,general,2561,2026/09/23 10:17:00,,general,,0,0,general,medium,\"User admin logged in via Web from 10.1.0.5 using https\",1234,0x0,0,0,0,0,,PA-3220"
    static let fortigate = "<189>date=2026-09-23 time=10:15:32 devname=\"FGT-60F-Branch\" devid=\"FGT60FTK20000000\" eventtime=1790139332000000000 tz=\"+0700\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"warning\" vd=\"root\" srcip=10.1.0.5 srcport=53012 srcintf=\"internal\" dstip=8.8.8.8 dstport=53 dstintf=\"wan1\" action=\"deny\" policyid=1 service=\"DNS\" proto=17"
    static let generic = "<13>Sep 23 10:15:32 linux-box sshd[1234]: Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2"
    static let genericKV = "<12>Sep 23 10:15:32 fw1 kernel: IN=eth0 OUT= SRC=203.0.113.9 DST=10.1.0.5 PROTO=TCP DPT=22"

    func testArubaCX() {
        let e = parse(Self.arubaCX)
        XCTAssertEqual(e.vendor, .arubaCX)
        XCTAssertEqual(e.severity, .warning, "LOG_WARN overrides the PRI severity")
        XCTAssertEqual(e.priority, 187)
        XCTAssertEqual(e.facility, .local7)
        XCTAssertEqual(e.hostname, "CX-6300-01")
        XCTAssertEqual(e.program, "lldpd")
        XCTAssertEqual(e.pid, "2512")
        XCTAssertEqual(e.field("event_id"), "1302")
        XCTAssertEqual(e.field("module"), "AMM")
        XCTAssertEqual(e.field("slot"), "1/1")
        XCTAssertEqual(e.deviceTime?.timeIntervalSince1970 ?? 0,
                       Self.date(2026, 9, 23, 3, 15, 32, zone: TimeZone(identifier: "UTC")!).timeIntervalSince1970 + 0.123,
                       accuracy: 0.0005)
        XCTAssertTrue(e.message.hasPrefix("Event|1302|"))
    }

    func testArubaOS8() {
        let e = parse(Self.arubaOS)
        XCTAssertEqual(e.vendor, .arubaOS)
        XCTAssertEqual(e.severity, .notice)
        XCTAssertEqual(e.hostname, "MM-1")
        XCTAssertEqual(e.program, "authmgr")
        XCTAssertEqual(e.pid, "4211")
        XCTAssertEqual(e.field("code"), "522008")
        XCTAssertEqual(e.field("level"), "NOTI")
        XCTAssertEqual(e.field("device"), "MM-1 10.1.1.10")
        XCTAssertEqual(e.deviceTime, Self.date(2026, 9, 23, 10, 12, 1))
    }

    func testArubaIAP() {
        let e = parse(Self.arubaIAP)
        XCTAssertEqual(e.vendor, .arubaOS)
        XCTAssertEqual(e.severity, .warning)
        XCTAssertEqual(e.hostname, "10.1.1.21")
        XCTAssertEqual(e.program, "cli")
        XCTAssertEqual(e.field("code"), "341004")
        XCTAssertEqual(e.field("device"), "AP IAP-305-Lobby@10.1.1.21 cli")
    }

    func testArubaSwitch() {
        let e = parse(Self.arubaSwitch)
        XCTAssertEqual(e.vendor, .arubaSwitch)
        XCTAssertEqual(e.severity, .info)
        XCTAssertEqual(e.hostname, "10.1.0.20")
        XCTAssertEqual(e.program, "ports")
        XCTAssertEqual(e.field("event_id"), "00076")
        XCTAssertEqual(e.field("module"), "ports")
        XCTAssertEqual(e.message, "00076 ports: port 1/1/24 is now off-line")
    }

    func testClearPass() {
        let e = parse(Self.clearPass)
        XCTAssertEqual(e.vendor, .clearPass)
        XCTAssertEqual(e.severity, .error, "REJECT → error")
        XCTAssertEqual(e.hostname, "cppm01")
        XCTAssertEqual(e.field("Common.Username"), "alice")
        XCTAssertEqual(e.field("Common.Service"), "Corp Wireless 802.1X")
        XCTAssertEqual(e.field("Common.Roles"), "[Employee], [User Authenticated]")
        XCTAssertEqual(e.field("RADIUS.Auth-Source"), "AD:ad01.corp.example")
        XCTAssertEqual(e.field("Common.NAS-IP-Address"), "10.1.1.10")
        let ok = parse(Self.clearPass.replacingOccurrences(of: "REJECT", with: "ACCEPT"))
        XCTAssertEqual(ok.severity, .info)
    }

    func testHuawei() {
        let e = parse(Self.huawei)
        XCTAssertEqual(e.vendor, .huawei)
        XCTAssertEqual(e.severity, .warning, "the digit is authoritative over PRI 187 (error)")
        XCTAssertEqual(e.priority, 187)
        XCTAssertEqual(e.hostname, "HW-CE6881")
        XCTAssertEqual(e.program, "IFNET/4/LINK_STATE")
        XCTAssertEqual(e.field("module"), "IFNET")
        XCTAssertEqual(e.field("mnemonic"), "LINK_STATE")
        XCTAssertEqual(e.field("seq"), "12")
        XCTAssertEqual(e.deviceTime, Self.date(2026, 9, 23, 10, 15, 32))
    }

    func testCheckPointLogExporter() {
        let e = parse(Self.checkPoint)
        XCTAssertEqual(e.vendor, .checkPoint)
        XCTAssertEqual(e.severity, .error, "High → error")
        XCTAssertEqual(e.hostname, "cp-gw-01")
        XCTAssertEqual(e.program, "VPN-1 & FireWall-1")
        XCTAssertEqual(e.pid, "26045")
        XCTAssertEqual(e.field("action"), "Drop")
        XCTAssertEqual(e.field("src"), "203.0.113.50")
        XCTAssertEqual(e.field("service"), "22")
        XCTAssertTrue(e.message.hasPrefix("[action:"), "not valid SD, so it stays in the message")
    }

    func testCheckPointKeyValue() {
        let e = parse(Self.checkPointKV)
        XCTAssertEqual(e.vendor, .checkPoint)
        XCTAssertEqual(e.hostname, "cp-mgmt")
        XCTAssertEqual(e.severity, .info)
        XCTAssertEqual(e.program, "VPN-1 & FireWall-1")
        XCTAssertEqual(e.field("action"), "Accept")
        XCTAssertEqual(e.field("dst"), "8.8.8.8")
    }

    func testPaloTraffic() {
        let e = parse(Self.paloTraffic)
        XCTAssertEqual(e.vendor, .paloAlto)
        XCTAssertEqual(e.hostname, "PA-3220")
        XCTAssertEqual(e.program, "TRAFFIC/end")
        XCTAssertEqual(e.severity, .info, "TRAFFIC has no severity column: PRI 14 stays")
        XCTAssertEqual(e.field("src"), "10.1.0.5")
        XCTAssertEqual(e.field("dst"), "8.8.8.8")
        XCTAssertEqual(e.field("rule"), "allow-dns")
        XCTAssertEqual(e.field("srcuser"), "corp\\alice")
        XCTAssertEqual(e.field("app"), "dns-base")
        XCTAssertEqual(e.field("sport"), "53012")
        XCTAssertEqual(e.field("dport"), "53")
        XCTAssertEqual(e.field("proto"), "udp")
        XCTAssertEqual(e.field("action"), "allow")
        XCTAssertEqual(e.field("bytes"), "196")
    }

    func testPaloThreatQuotedComma() {
        let e = parse(Self.paloThreat)
        XCTAssertEqual(e.vendor, .paloAlto)
        XCTAssertEqual(e.program, "THREAT/url")
        XCTAssertEqual(e.severity, .error, "high → error")
        XCTAssertEqual(e.field("misc"), "example.com/a,b?x=1")
        XCTAssertEqual(e.field("threatid"), "(9999)")
        XCTAssertEqual(e.field("category"), "malware")
        XCTAssertEqual(e.field("direction"), "client-to-server")
        XCTAssertEqual(e.field("action"), "alert")
    }

    func testPaloSystem() {
        let e = parse(Self.paloSystem)
        XCTAssertEqual(e.vendor, .paloAlto)
        XCTAssertEqual(e.severity, .warning, "medium → warning")
        XCTAssertEqual(e.field("eventid"), "general")
        XCTAssertEqual(e.field("module"), "general")
        XCTAssertEqual(e.field("description"), "User admin logged in via Web from 10.1.0.5 using https")
    }

    func testFortigate() {
        let e = parse(Self.fortigate)
        XCTAssertEqual(e.vendor, .fortigate)
        XCTAssertEqual(e.hostname, "FGT-60F-Branch", "devname when the header has no hostname")
        XCTAssertEqual(e.program, "traffic/forward")
        XCTAssertEqual(e.severity, .warning)
        // No syslog header: the device time comes from eventtime= (nanoseconds since 1970).
        XCTAssertEqual(e.deviceTime?.timeIntervalSince1970 ?? 0, 1_790_139_332, accuracy: 0.001)
        XCTAssertEqual(e.field("devid"), "FGT60FTK20000000")
        XCTAssertEqual(e.field("srcip"), "10.1.0.5")
        XCTAssertEqual(e.field("dstintf"), "wan1")
        XCTAssertEqual(e.field("action"), "deny")
    }

    func testGenericAndKeyValue() {
        let e = parse(Self.generic)
        XCTAssertEqual(e.vendor, .unknown)
        XCTAssertEqual(e.severity, .notice)
        XCTAssertEqual(e.facility, .user)
        XCTAssertEqual(e.hostname, "linux-box")
        XCTAssertEqual(e.program, "sshd")
        XCTAssertEqual(e.pid, "1234")
        XCTAssertTrue(e.fields.isEmpty)
        XCTAssertEqual(e.message, "Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2")

        let kv = parse(Self.genericKV)
        XCTAssertEqual(kv.vendor, .unknown)
        XCTAssertEqual(kv.program, "kernel")
        XCTAssertEqual(kv.field("SRC"), "203.0.113.9")
        XCTAssertEqual(kv.field("DPT"), "22")
    }

    func testOverrideForcesVendor() {
        let line = "<14>Sep 23 10:15:32 fw devname=FGT1 type=traffic subtype=forward level=error srcip=1.1.1.1"
        XCTAssertEqual(parse(line).vendor, .unknown, "no logid= → not detected")
        let e = parse(line, override: .fortigate)
        XCTAssertEqual(e.vendor, .fortigate)
        XCTAssertEqual(e.program, "traffic/forward")
        XCTAssertEqual(e.severity, .error)
    }

    // MARK: - Headers

    func testRFC5424StructuredData() {
        let e = parse("<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][meta seq=\"7\" note=\"a \\\"quoted\\] word\"] \u{FEFF}An application event log entry")
        XCTAssertEqual(e.facility, .local4)
        XCTAssertEqual(e.severity, .notice)
        XCTAssertEqual(e.hostname, "mymachine.example.com")
        XCTAssertEqual(e.program, "evntslog")
        XCTAssertNil(e.pid)
        XCTAssertEqual(e.field("msgid"), "ID47")
        XCTAssertEqual(e.field("sd.exampleSDID@32473.iut"), "3")
        XCTAssertEqual(e.field("sd.exampleSDID@32473.eventID"), "1011")
        XCTAssertEqual(e.field("sd.meta.note"), "a \"quoted] word")
        XCTAssertEqual(e.message, "An application event log entry")
        XCTAssertEqual(e.deviceTime?.timeIntervalSince1970 ?? 0, 1_065_910_455.003, accuracy: 0.0005)
    }

    func testRFC5424NilValues() {
        let e = parse("<34>1 - - - - - - hello")
        XCTAssertEqual(e.facility, .auth)
        XCTAssertEqual(e.severity, .critical)
        XCTAssertNil(e.deviceTime)
        XCTAssertEqual(e.hostname, "")
        XCTAssertEqual(e.program, "")
        XCTAssertEqual(e.message, "hello")
    }

    func testRFC3164YearInference() {
        // No year: the current year …
        let e = parse("<13>Sep 23 10:15:32 host app: x")
        XCTAssertEqual(e.deviceTime, Self.date(2026, 9, 23, 10, 15, 32))
        // … unless that is more than a day in the future: then last year.
        let newYear = Self.date(2026, 1, 1, 0, 30, 0)
        let late = parse("<13>Dec 31 23:59:00 host app: x", received: newYear)
        XCTAssertEqual(late.deviceTime, Self.date(2025, 12, 31, 23, 59, 0))
        // Single-digit day, space padded
        let pad = parse("<13>Sep  3 01:02:03 host app: x")
        XCTAssertEqual(pad.deviceTime, Self.date(2026, 9, 3, 1, 2, 3))
        XCTAssertEqual(pad.hostname, "host")
    }

    func testRFC3164TrailingYearAndNoHostname() {
        let e = parse("<13>Sep 23 10:15:32 2025 sshd[9]: y")
        XCTAssertEqual(e.deviceTime, Self.date(2025, 9, 23, 10, 15, 32))
        XCTAssertEqual(e.hostname, "")
        XCTAssertEqual(e.program, "sshd")
        XCTAssertEqual(e.pid, "9")
        XCTAssertEqual(e.message, "y")
    }

    func testISOTimestamps() {
        let utc = parse("<13>2026-09-23T03:15:32.250Z sw1 app: m")
        XCTAssertEqual(utc.deviceTime, Self.date(2026, 9, 23, 3, 15, 32, zone: TimeZone(identifier: "UTC")!).addingTimeInterval(0.25))
        XCTAssertEqual(utc.hostname, "sw1")
        let offset = parse("<13>2026-09-23T10:15:32+07:00 sw1 app: m")
        XCTAssertEqual(offset.deviceTime, Self.date(2026, 9, 23, 3, 15, 32, zone: TimeZone(identifier: "UTC")!))
        let local = parse("<13>2026-09-23 10:15:32 sw1 app: m")
        XCTAssertEqual(local.deviceTime, Self.date(2026, 9, 23, 10, 15, 32))
        XCTAssertEqual(local.program, "app")
    }

    func testNoHeader() {
        let e = parse("<34>just some text: here")
        XCTAssertEqual(e.priority, 34)
        XCTAssertEqual(e.facility, .auth)
        XCTAssertEqual(e.severity, .critical)
        XCTAssertEqual(e.message, "just some text: here")
        XCTAssertEqual(e.hostname, "")
        let bare = parse("hello world")
        XCTAssertNil(bare.priority)
        XCTAssertEqual(bare.facility, .user)
        XCTAssertEqual(bare.severity, .notice)
        XCTAssertEqual(bare.message, "hello world")
        XCTAssertEqual(bare.raw, "hello world")
        let badPRI = parse("<999>oops")
        XCTAssertNil(badPRI.priority)
        XCTAssertEqual(badPRI.message, "<999>oops")
    }

    // MARK: - TCP framing (RFC 6587)

    private func strings(_ frames: [Data]) -> [String] { frames.map { String(decoding: $0, as: UTF8.self) } }

    func testFramingNewlines() {
        var buf = Data("<13>a\n<14>b\r\n<15>c\0<16>partial".utf8)
        XCTAssertEqual(strings(SyslogFraming.split(buffer: &buf)), ["<13>a", "<14>b", "<15>c"])
        XCTAssertEqual(String(decoding: buf, as: UTF8.self), "<16>partial")
        buf.append(contentsOf: Array(" end\n".utf8))
        XCTAssertEqual(strings(SyslogFraming.split(buffer: &buf)), ["<16>partial end"])
        XCTAssertTrue(buf.isEmpty)
    }

    func testFramingOctetCounted() {
        let m1 = "<13>1 - h a - - - one", m2 = "<14>two\nwith newline inside"
        var buf = Data("\(m1.utf8.count) \(m1)\(m2.utf8.count) \(m2)".utf8)
        XCTAssertEqual(strings(SyslogFraming.split(buffer: &buf)), [m1, m2])
        XCTAssertTrue(buf.isEmpty)
        // Split across reads, including inside the length.
        let whole = Data("\(m1.utf8.count) \(m1)".utf8)
        var part = whole.prefix(1)
        XCTAssertEqual(SyslogFraming.split(buffer: &part).count, 0)
        part.append(whole.dropFirst(1).prefix(5))
        XCTAssertEqual(SyslogFraming.split(buffer: &part).count, 0)
        part.append(whole.dropFirst(6))
        XCTAssertEqual(strings(SyslogFraming.split(buffer: &part)), [m1])
    }

    func testFramingMixedAndDigitsWithoutPRI() {
        var buf = Data("12 <13>abcdefgh<14>line\n404 not found\n".utf8)
        XCTAssertEqual(strings(SyslogFraming.split(buffer: &buf)), ["<13>abcdefgh", "<14>line", "404 not found"])
        var tail = Data("<13>unterminated".utf8)
        XCTAssertEqual(strings(SyslogFraming.drain(buffer: &tail)), ["<13>unterminated"])
    }

    func testLatin1Fallback() {
        let bytes: [UInt8] = [0x3C, 0x31, 0x33, 0x3E, 0x63, 0x61, 0x66, 0xE9]  // "<13>caf\xE9"
        let s = bytes.withUnsafeBufferPointer { SyslogFraming.decode($0) }
        XCTAssertEqual(s, "<13>café")
    }

    // MARK: - Adversarial review (each test pins a defect that was found and fixed)

    func testYearRolloverForward() {
        // The device clock is a few seconds ahead across New Year: "Jan  1" received on Dec 31
        // belongs to next year, not to eleven months ago.
        let eve = Self.date(2026, 12, 31, 23, 59, 50)
        let e = parse("<13>Jan  1 00:00:05 host app: x", received: eve)
        XCTAssertEqual(e.deviceTime, Self.date(2027, 1, 1, 0, 0, 5))
        // Ordinary lines from earlier in the year stay in this year.
        let old = parse("<13>Jan  1 00:00:05 host app: x", received: Self.received)
        XCTAssertEqual(old.deviceTime, Self.date(2026, 1, 1, 0, 0, 5))
    }

    /// `<0>` … `<191>`, at most three digits; anything else is not a PRI (user.notice then).
    func testPRIBounds() {
        XCTAssertEqual(parse("<191>x").priority, 191)
        for bad in ["<192>x", "<1911>x", "<-1>x", "<999999>x", "<>x", "<1a>x", "<0000>x",
                    "<" + String(repeating: "9", count: 5000) + ">x"] {
            let e = parse(bad)
            XCTAssertNil(e.priority, bad)
            XCTAssertEqual(e.facility, .user, bad)
        }
        XCTAssertEqual(parse("<13>message").message, "message")
        XCTAssertEqual(parse("<13>").message, "")
        XCTAssertEqual(parse("<13").message, "<13")
        XCTAssertEqual(parse("").message, "")
    }

    func testCiscoMnemonicIsTheProgram() {
        let e = parse("<189>Mar  1 00:04:49 router1 %SYS-5-CONFIG_I: Configured from console by vty0 (10.0.0.1)")
        XCTAssertEqual(e.vendor, .unknown)
        XCTAssertEqual(e.hostname, "router1")
        XCTAssertEqual(e.program, "%SYS-5-CONFIG_I")
        XCTAssertEqual(e.message, "Configured from console by vty0 (10.0.0.1)")
        let bare = parse("<189>%LINK-3-UPDOWN: Interface Gi0/1, changed state to down")
        XCTAssertEqual(bare.vendor, .unknown)
        XCTAssertEqual(bare.program, "%LINK-3-UPDOWN")
        XCTAssertEqual(bare.message, "Interface Gi0/1, changed state to down")
        // Huawei's double %% must not be eaten as a tag.
        XCTAssertEqual(parse(Self.huawei).vendor, .huawei)
        XCTAssertEqual(parse("<187>Sep 23 2026 10:15:32 HW %%01SHELL/5/CMDRECORD[3]:Recorded command").vendor, .huawei)
    }

    func testHuaweiFormatVersions() {
        for v in ["01", "10"] {
            let e = parse("<187>Sep 23 2026 10:15:32 HW-CE %%\(v)IFNET/2/LINK_STATE(l)[7]:down")
            XCTAssertEqual(e.vendor, .huawei, v)
            XCTAssertEqual(e.severity, .critical, v)
            XCTAssertEqual(e.program, "IFNET/2/LINK_STATE", v)
        }
    }

    func testAOS8ErrsLevel() {
        let e = parse("<131>Sep 23 10:12:05 2026 MM-1 stm[3510]: <501218> <ERRS> <MM-1 10.1.1.10> Station failed")
        XCTAssertEqual(e.vendor, .arubaOS)
        XCTAssertEqual(e.severity, .error)
        XCTAssertEqual(e.field("level"), "ERRS")
    }

    func testFortigateUnquotedDevname() {
        let e = parse("<189>date=2026-09-23 time=10:15:32 devname=FGT-Edge devid=FGT60F logid=0100032001 type=event subtype=system level=information msg=\"Administrator admin logged in\"")
        XCTAssertEqual(e.vendor, .fortigate)
        XCTAssertEqual(e.hostname, "FGT-Edge")
        XCTAssertEqual(e.severity, .info)
        XCTAssertEqual(e.program, "event/system")
        XCTAssertEqual(e.field("msg"), "Administrator admin logged in")
    }

    func testCheckPointBracketsAfterAnotherBracketAndNested() {
        // A bracket before the log_exporter block, and a bracketed unquoted value inside it.
        let line = "<134>Sep 23 10:15:32 cp-gw-01 fw [0]: [action:\"Drop\"; rule_name:\"[Internal] Deny\"; layers:[a:1;b:2]; src:\"203.0.113.50\"; severity:\"Medium\"]"
        let e = parse(line)
        XCTAssertEqual(e.vendor, .checkPoint)
        XCTAssertEqual(e.field("action"), "Drop")
        XCTAssertEqual(e.field("rule_name"), "[Internal] Deny")
        XCTAssertEqual(e.field("layers"), "[a:1;b:2]")
        XCTAssertEqual(e.field("src"), "203.0.113.50", "fields after a nested bracket are still read")
        XCTAssertEqual(e.severity, .warning)
    }

    func testLoadgenLinesAreNotMisdetected() {
        for i in [0, 1, 7, 12345] {
            let line = "<\(184 + i % 8)>Sep 23 10:15:32 flood-\(i % 16) loadgen[\(i % 997)]: flood line \(i) port 1/1/\(i % 48) seq=\(i) src=10.9.\(i % 250).\(i % 200) action=pass"
            let e = parse(line)
            XCTAssertEqual(e.vendor, .unknown, line)
            XCTAssertEqual(e.program, "loadgen")
            XCTAssertEqual(e.field("seq"), "\(i)")
            XCTAssertEqual(e.field("action"), "pass")
        }
    }

    func testMalformedInputNeverCrashes() {
        let nasty = ["<", "<1", "<13>1", "<13>1 ", "<13>1 2026-09-23T", "<13>1 - - - - - [", "<13>1 - - - - - [a b=\"",
                     "<13>1 - - - - - [a b=\"x\\", "Sep", "Sep ", "Sep 3", "Sep 31 99:99:99 h a: b", "<13>Jan 1 00:00:00 a[",
                     "1,", "1,a,b,TRAFFIC", "1,a,b,TRAFFIC,end,\"unterminated", "Event|", "Event|1|", "<123456>", "<123456> <ERRS",
                     "%%01", "%%01A/", "%%01A/9/", "%%01A/99/B(", "[a:\"", "[a:\"x\";", "a=\"\\", "12345 x:", "00076 ",
                     "Common.A=", "Common.A=,", "logid= type= devid=", "2026-02-30T25:61:61Z h a: b", "\u{FEFF}", "\0\0\0",
                     "%", "%A", "%A:", "[x:[[[[", "[x:[;]"]
        for s in nasty {
            _ = parse(s)
            _ = parse("<13>" + s)
            for v in Vendor.allCases { _ = parse(s, override: v) }
        }
    }

    // MARK: - TCP framing, adversarial

    func testFramerDropsAnUndelimitedFlood() {
        var framer = SyslogFramer()
        let chunk = [UInt8](repeating: 0x41, count: 64 * 1024)
        var frames: [Data] = []
        for _ in 0..<48 {                                  // 3 MB, no delimiter
            frames += chunk.withUnsafeBytes { framer.append($0) }
            XCTAssertLessThanOrEqual(framer.bufferedBytes, SyslogFraming.maxFrame + chunk.count)
        }
        XCTAssertTrue(frames.isEmpty, "an over-long line is dropped, not emitted in pieces")
        XCTAssertGreaterThan(framer.droppedBytes, 2 * 1024 * 1024)
        // The rest of the runaway line is skipped up to its newline; the next line is intact.
        frames += Array("AAAA tail\n<13>after\n".utf8).withUnsafeBytes { framer.append($0) }
        XCTAssertEqual(strings(frames), ["<13>after"])
        XCTAssertEqual(framer.bufferedBytes, 0)
    }

    func testFramerKeepsLongButLegalFrames() {
        var framer = SyslogFramer()
        let body = "<13>" + String(repeating: "x", count: 300_000)
        let bytes = Array("\(body.utf8.count) \(body)".utf8)
        var frames: [Data] = []
        var i = 0
        while i < bytes.count {
            let end = min(bytes.count, i + 65_536)
            frames += bytes[i..<end].withUnsafeBytes { framer.append($0) }
            i = end
        }
        XCTAssertEqual(frames.count, 1)
        XCTAssertEqual(frames.first?.count, body.utf8.count)
        XCTAssertEqual(framer.droppedBytes, 0)
        // An unterminated last line is delivered when the peer closes.
        var tail = SyslogFramer()
        _ = Array("<13>last words".utf8).withUnsafeBytes { tail.append($0) }
        XCTAssertEqual(strings(tail.finish()), ["<13>last words"])
    }

    func testFramingHugeOctetCountDoesNotWaitForever() {
        var buf = Data("999999999 <13>x\n<14>y\n".utf8)
        XCTAssertEqual(strings(SyslogFraming.split(buffer: &buf)), ["999999999 <13>x", "<14>y"])
    }

    func testFramingOnASliceWithNonZeroStartIndex() {
        let whole = Data("junk<13>a\n<14>b\n<15>c".utf8)
        var slice = whole[4...]
        XCTAssertEqual(slice.startIndex, 4)
        XCTAssertEqual(strings(SyslogFraming.split(buffer: &slice)), ["<13>a", "<14>b"])
        XCTAssertEqual(String(decoding: slice, as: UTF8.self), "<15>c")
    }

    func testCBufferTextStopsAtTheEnd() {
        XCTAssertEqual(SocketFactory.text(ofCBuffer: [0x31, 0x2E, 0x32, 0, 0x39]), "1.2")
        XCTAssertEqual(SocketFactory.text(ofCBuffer: [0x61, 0x62]), "ab", "no NUL: bounded by the buffer")
        XCTAssertEqual(SocketFactory.text(ofCBuffer: []), "")
    }

    // MARK: - Needle search

    func testNeedleSearchIsLinearOnLongLines() {
        // Many lowercase 'e's and no 'E' anywhere: the search must not re-scan the rest of the
        // line for the other case at every hit.
        let hay = String(repeating: "e", count: 65_000) + "rror"
        let n = Needle("error")
        let miss = Needle("ex")
        let start = Date()
        for _ in 0..<40 {
            XCTAssertTrue(n.found(in: hay))
            XCTAssertFalse(miss.found(in: hay))
        }
        let elapsed = Date().timeIntervalSince(start)
        XCTAssertWithinBudget(elapsed, 0.5, "\(elapsed) s")
        XCTAssertTrue(Needle("ERROR").found(in: "an Error here"))
        XCTAssertTrue(Needle("1/1/24").found(in: "port 1/1/24"))
        XCTAssertFalse(Needle("abc").found(in: "ab"))
    }

    // MARK: - Speed

    func testParseSpeed() {
        let lines = [Self.arubaCX, Self.arubaOS, Self.arubaSwitch, Self.clearPass, Self.huawei, Self.checkPoint,
                     Self.paloTraffic, Self.paloThreat, Self.fortigate, Self.generic]
        let start = Date()
        var n = 0
        for i in 0..<20_000 {
            n &+= parse(lines[i % lines.count]).fields.count
        }
        let elapsed = Date().timeIntervalSince(start)
        print("[perf] parsed 20,000 mixed vendor lines in \(Int(elapsed * 1000)) ms (\(Int(20_000 / elapsed)) lines/s, Debug)")
        XCTAssertGreaterThan(n, 0)
        XCTAssertWithinBudget(elapsed, 10)
    }
}
