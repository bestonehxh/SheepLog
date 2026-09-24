#!/usr/bin/env python3
"""Generates Tests/corpus/<vendor>.log + <vendor>.expect (one line each, same order).

.expect columns (tab-separated): severity, hostname ("-" = none), program ("-" = none),
minimum field count, device time ("-" = none; "YYYY-MM-DDTHH:MM:SS[.fff]" = local wall
time; with Z / +hh:mm = absolute).
"""
import datetime as dt
import os
import sys

out = sys.argv[1]
os.makedirs(out, exist_ok=True)


def epoch(iso):
    return int(dt.datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp())


corpus = {}

# ---------------------------------------------------------------- Aruba AOS-CX 10.x
corpus["arubacx"] = [
    ('<187>1 2026-09-23T10:15:32.123+07:00 CX6300-CORE-01 lldpd 2512 - - Event|1302|LOG_WARN|AMM|1/1|LLDP neighbor 10.1.0.9 removed on port 1/1/24',
     "warning", "CX6300-CORE-01", "lldpd", 4, "2026-09-23T10:15:32.123+07:00"),
    ('<190>1 2026-09-23T10:15:40.512004+07:00 CX6300-CORE-01 intfd 1633 - - Event|403|LOG_INFO|AMM|1/1|Link status for interface 1/1/24 is down',
     "info", "CX6300-CORE-01", "intfd", 4, "2026-09-23T10:15:40.512+07:00"),
    ('<189>1 2026-09-23T10:16:02+07:00 CX8360-AGG-02 hpe-config 2211 - - Event|6801|LOG_NOTICE|UKWN|-|Configuration change by admin via REST: interface 1/1/12 no shutdown',
     "notice", "CX8360-AGG-02", "hpe-config", 4, "2026-09-23T10:16:02+07:00"),
    ('<185>1 2026-09-23T03:17:10.000Z CX6300-ACC-12 ops-switchd 1432 - - Event|1105|LOG_CRIT|AMM|1/1|Power supply 2 in slot 1/1 failed',
     "critical", "CX6300-ACC-12", "ops-switchd", 4, "2026-09-23T03:17:10Z"),
    ('<177>1 2026-09-23T03:17:11Z CX6300-ACC-12 fand 1433 - - Event|1403|LOG_ALERT|AMM|1/1|Fan tray 1 fault detected, system temperature rising',
     "alert", "CX6300-ACC-12", "fand", 4, "2026-09-23T03:17:11Z"),
    ('<187>Sep 23 10:18:00 CX6200-ACC-03 port-access[3201]: Event|10505|LOG_ERR|AMM|1/1|Port 1/1/7 MAC-auth failed for client 02:00:5e:10:00:22',
     "error", "CX6200-ACC-03", "port-access", 4, "2026-09-23T10:18:00"),
    ('<191>1 2026-09-23T10:19:00+07:00 CX6300-CORE-01 ntpd 1502 - - Event|1101|LOG_DEBUG|AMM|-|NTP server 10.1.0.1 selected as reference',
     "debug", "CX6300-CORE-01", "ntpd", 4, "2026-09-23T10:19:00+07:00"),
    ('<190>1 2026-09-23T10:20:05.250+07:00 CX6300-CORE-01 hpe-restd 3345 - - Event|4691|LOG_INFO|UKWN|1|User admin logged in from 10.1.0.5 through REST session',
     "info", "CX6300-CORE-01", "hpe-restd", 4, "2026-09-23T10:20:05.250+07:00"),
    # Round 14: RFC 5424 structured data before the Event text — a port down and up again.
    ('<190>1 2026-09-23T10:21:00.123+07:00 CX6300-CORE-01 intfd 1633 - [origin enterpriseId="47196"][meta sequenceId="12"] Event|403|LOG_INFO|AMM|1/1|Link status for interface 1/1/5 is down',
     "info", "CX6300-CORE-01", "intfd", 6, "2026-09-23T10:21:00.123+07:00"),
    ('<190>1 2026-09-23T10:21:30.123+07:00 CX6300-CORE-01 intfd 1633 - [origin enterpriseId="47196"] Event|404|LOG_INFO|AMM|1/1|Link status for interface 1/1/5 is up',
     "info", "CX6300-CORE-01", "intfd", 5, "2026-09-23T10:21:30.123+07:00"),
]

# ---------------------------------------------------------------- Aruba AOS 8 / Instant AP
corpus["arubaos"] = [
    ('<133>Sep 23 10:12:01 2026 MM-1 authmgr[4211]: <522008> <4211> <NOTI> <MM-1 10.1.1.10>  User Authentication Successful: username=alice MAC=02:00:5e:10:00:01 IP=10.20.0.15 role=employee VLAN=20 AP=AP-Lobby SSID=Corp auth method=802.1x auth server=CPPM',
     "notice", "MM-1", "authmgr", 12, "2026-09-23T10:12:01"),
    ('<131>Sep 23 10:12:03 2026 MD-7210-1 authmgr[4211]: <522275> <4211> <ERRS> <MD-7210-1 10.1.1.11>  User Authentication failed. username=bob MAC=02:00:5e:10:00:02 IP=0.0.0.0 auth method=802.1x auth server=CPPM',
     "error", "MD-7210-1", "authmgr", 8, "2026-09-23T10:12:03"),
    ('<134>Sep 23 10:12:04 2026 MD-7210-1 stm[3456]: <501093> <3456> <NOTI> <MD-7210-1 10.1.1.11>  Auth success: 02:00:5e:10:00:03: AP 10.1.2.21-24:de:c6:aa:bb:cc-AP-315-Floor2',
     "notice", "MD-7210-1", "stm", 3, "2026-09-23T10:12:04"),
    ('<135>Sep 23 10:12:05 2026 MD-7210-1 stm[3456]: <501106> <3456> <DBUG> <MD-7210-1 10.1.1.11>  Deauth to sta: 02:00:5e:10:00:03: Ageout AP 10.1.2.21-24:de:c6:aa:bb:cc-AP-315-Floor2 Sapcp Ageout',
     "debug", "MD-7210-1", "stm", 3, "2026-09-23T10:12:05"),
    ('<132>Sep 23 10:12:06 2026 MD-7210-1 sapd[2345]: <404400> <WARN> |AP AP-315-Floor2@10.1.2.21 sapd|  AM: Interfering AP detected with SSID Guest and BSSID 02:00:5e:aa:bb:01',
     "warning", "MD-7210-1", "sapd", 3, "2026-09-23T10:12:06"),
    ('<132>Sep 23 10:12:07 2026 10.1.1.21 cli[3510]: <341004> <WARN> |AP IAP-305-Lobby@10.1.1.21 cli| Recv image upgrade request',
     "warning", "10.1.1.21", "cli", 3, "2026-09-23T10:12:07"),
    ('<134>Sep 23 10:12:08 2026 20:4c:03:aa:bb:cc sapd[1996]: <326278> <NOTI> |AP 20:4c:03:aa:bb:cc@10.1.1.22 sapd|  AM: New Node Detected Node = 02:00:5e:10:00:05 SSID = Corp BSSID 20:4c:03:aa:bb:c0',
     "notice", "20:4c:03:aa:bb:cc", "sapd", 3, "2026-09-23T10:12:08"),
    ('<130>Sep 23 10:12:09 2026 MM-1 fpapps[3001]: <399816> <CRIT> <MM-1 10.1.1.10>  Controller-to-controller IPsec tunnel to 10.1.1.12 is down',
     "critical", "MM-1", "fpapps", 3, "2026-09-23T10:12:09"),
    ('<133>Sep 23 10:12:10 MM-1 mgmd[2511]: <506010> <NOTI> <MM-1 10.1.1.10>  Heartbeat miss from MD 10.1.1.11',
     "notice", "MM-1", "mgmd", 3, "2026-09-23T10:12:10"),
    # AP down, as the controller reports it (the second type engineers filter on after auth)
    ('<132>Sep 23 10:12:11 2026 MM-1 stm[3456]: <303022> <3456> <WARN> <MM-1 10.1.1.10>  AP AP-315-Floor2 is down; last heard from 10.1.2.21',
     "warning", "MM-1", "stm", 3, "2026-09-23T10:12:11"),
]

# ---------------------------------------------------------------- Aruba AOS-S / ProCurve 16.x
corpus["arubasw"] = [
    ('<14> Sep 23 10:15:32 10.1.0.20 00076 ports: port 24 is now off-line',
     "info", "10.1.0.20", "ports", 2, "2026-09-23T10:15:32"),
    ('<14>Sep 23 10:15:40 SW-2930F-01 00076 ports: port 1/1/24 is now on-line',
     "info", "SW-2930F-01", "ports", 2, "2026-09-23T10:15:40"),
    ('<12>Sep 23 10:16:00 SW-2930F-01 00331 FFI: port 1/1/5-Excessive CRC/alignment errors. See help.',
     "warning", "SW-2930F-01", "FFI", 2, "2026-09-23T10:16:00"),
    ('<14>Sep 23 10:16:10 SW-5406R-CORE 02101 802.1x: port A5 - client 02:00:5e:10:00:07 authenticated',
     "info", "SW-5406R-CORE", "802.1x", 2, "2026-09-23T10:16:10"),
    ('<13>Sep 23 10:16:20 SW-5406R-CORE 00435 ports: port B2 is Blocked by STP',
     "notice", "SW-5406R-CORE", "ports", 2, "2026-09-23T10:16:20"),
    ('<14>Sep 23 10:16:30 SW-5406R-CORE 00179 mgr: SME SSH from 10.1.0.5 - MANAGER Mode',
     "info", "SW-5406R-CORE", "mgr", 2, "2026-09-23T10:16:30"),
    ('<12>Sep 23 10:16:40 SW-2930F-01 03129 dhcp-snoop: Ceasing untrusted server logs for 5 min',
     "warning", "SW-2930F-01", "dhcp-snoop", 2, "2026-09-23T10:16:40"),
    ('<14>Sep 23 10:16:50 00076 ports: port 12 is now off-line',
     "info", "-", "ports", 2, "2026-09-23T10:16:50"),
]

# ---------------------------------------------------------------- ClearPass 6.x
corpus["clearpass"] = [
    ('<14>Sep 23 10:15:32 cppm01 CPPM_RADIUS_Logs 1234 1 0 Common.Username=alice,Common.Service=Corp Wireless 802.1X,Common.Login-Status=REJECT,Common.Roles=[Employee], [User Authenticated],RADIUS.Auth-Source=AD:ad01.corp.example,Common.NAS-IP-Address=10.1.1.10',
     "error", "cppm01", "CPPM_RADIUS_Logs", 6, "2026-09-23T10:15:32"),
    ('<14>Sep 23 10:15:40 cppm01 CPPM_RADIUS_Logs 1235 1 0 Common.Username=bob,Common.Service=Corp Wireless 802.1X,Common.Login-Status=ACCEPT,Common.Roles=[Employee],Common.Enforcement-Profiles=[Allow Access Profile], Corp-VLAN20,RADIUS.Acct-Framed-IP-Address=10.20.0.16,Common.NAS-IP-Address=10.1.1.10,Common.Host-MAC-Address=02005e100002',
     "info", "cppm01", "CPPM_RADIUS_Logs", 8, "2026-09-23T10:15:40"),
    ('<14>Sep 23 10:16:00 cppm01 CPPM_TACACS_Logs 1236 1 0 TACACS.Username=netadmin,TACACS.Service=Network Device Admin,TACACS.Auth-Status=REJECT,TACACS.Remote-Address=10.1.0.5,TACACS.NAS-IP-Address=10.1.0.20,TACACS.Privilege-Level=15',
     "error", "cppm01", "CPPM_TACACS_Logs", 6, "2026-09-23T10:16:00"),
    ('<14>2026-09-23 10:16:10,123 10.1.1.50 CPPM_Session_Logs 1237 1 0 Common.Username=carol,Common.Service=Guest Access,Common.Login-Status=TIMEOUT,Common.Request-Timestamp=2026-09-23 10:16:10+07,Common.Error-Code=9002,Common.Alerts=RADIUS Request timed out',
     "warning", "10.1.1.50", "CPPM_Session_Logs", 6, "2026-09-23T10:16:10.123"),
    ('<11>Sep 23 10:16:20 cppm01 CPPM_System_Events 1238 1 0 Source=Policy Server,Level=ERROR,Category=Authentication,Description=Failed to connect to AD server ad01.corp.example: timeout,Action Key=,Timestamp=Sep 23, 2026 10:16:20 ICT',
     "error", "cppm01", "CPPM_System_Events", 5, "2026-09-23T10:16:20"),
    ('<13>Sep 23 10:16:30 cppm01 CPPM_Audit_Records 1239 1 0 Name=Corp Wireless 802.1X,Category=Services,Action=MODIFY,User=admin,Timestamp=Sep 23, 2026 10:16:30 ICT',
     "notice", "cppm01", "CPPM_Audit_Records", 5, "2026-09-23T10:16:30"),
    ('<14>Sep 23 10:16:40 cppm01 CPPM_Endpoint_Logs 1240 1 0 Endpoint.MAC-Address=02005e100009,Endpoint.Device-Category=SmartDevice,Endpoint.Device-OS-Family=Apple,Endpoint.Status=Known',
     "info", "cppm01", "CPPM_Endpoint_Logs", 4, "2026-09-23T10:16:40"),
]

# ---------------------------------------------------------------- Huawei VRP (S57xx / CE / AR)
corpus["huawei"] = [
    ('<187>Sep 23 2026 10:15:32 HW-CE6881 %%01IFNET/4/LINK_STATE(l)[12]:The line protocol IP on the interface 10GE1/0/24 has entered the DOWN state.',
     "warning", "HW-CE6881", "IFNET/4/LINK_STATE", 4, "2026-09-23T10:15:32"),
    ('<189>Sep 23 2026 10:15:40 S5720-CORE %%01SHELL/5/CMDRECORD(s)[13]:Recorded command information. (Task=VT0, Ip=10.1.0.5, VpnName=, User=admin, AuthenticationMethod="Local-user", Command="display interface brief")',
     "notice", "S5720-CORE", "SHELL/5/CMDRECORD", 10, "2026-09-23T10:15:40"),
    ('<188>Sep 23 2026 10:16:00 S5720-CORE %%01OSPF/3/NBR_CHG_DOWN(l)[14]:Neighbor event:neighbor state changed to Down. (ProcessId=1, NeighborAddress=10.0.0.2, NeighborEvent=KillNbr, NeighborPreviousState=Full, NeighborCurrentState=Down)',
     "error", "S5720-CORE", "OSPF/3/NBR_CHG_DOWN", 9, "2026-09-23T10:16:00"),
    ('<190>Sep 23 2026 10:16:10 S5720-CORE %%01AAA/6/LOCALACCOUNT_LOGIN(s)[15]:Local account admin login succeeded. (UserIp=10.1.0.5, UserName=admin)',
     "info", "S5720-CORE", "AAA/6/LOCALACCOUNT_LOGIN", 6, "2026-09-23T10:16:10"),
    ('<188>Sep 23 2026 10:16:20 S5720-ACC-07 %%01LLDP/4/NBRCHGTRAP(l)[16]:Neighbor information of the interface was changed. (NeighborIndex=1, Action=delete, Interface=GigabitEthernet0/0/12, RemoteChassisType=4, RemoteChassisId=02:00:5e:aa:bb:07, RemotePortIdType=5, RemotePortId=GE0/0/1, RemoteSystemName=AP-Lobby)',
     "warning", "S5720-ACC-07", "LLDP/4/NBRCHGTRAP", 12, "2026-09-23T10:16:20"),
    ('<185>Sep 23 2026 10:16:30+07:00 HW-CE6881 %%01IFNET/1/linkDown_active(l):CID=0x80fa0002-alarmID=0x08520003;The interface status changes. (ifName=10GE1/0/24, AdminStatus=UP, OperStatus=DOWN, Reason=The link protocol is down, mainIfname=10GE1/0/24)',
     "alert", "HW-CE6881", "IFNET/1/linkDown_active", 8, "2026-09-23T10:16:30+07:00"),
    ('<189>Sep 23 2026 10:16:40 HW-AR6120 %%01SSH/5/SSH_USER_LOGIN(s)[17]:The SSH user succeeded in logging in. (ServiceType=stelnet, UserName=admin, UserAddress=10.1.0.5, LocalAddress=10.1.0.1, VPNInstanceName=_public_)',
     "notice", "HW-AR6120", "SSH/5/SSH_USER_LOGIN", 9, "2026-09-23T10:16:40"),
    ('<188>Sep 23 2026 10:16:50 S5720-CORE %%01IFNET/4/IF_STATE(l)[18]:Interface GigabitEthernet0/0/3 has turned into DOWN state.',
     "warning", "S5720-CORE", "IFNET/4/IF_STATE", 4, "2026-09-23T10:16:50"),
]

# ---------------------------------------------------------------- Check Point R81 (log_exporter)
T = lambda iso: epoch(iso)
corpus["checkpoint"] = [
    ('<134>1 2026-09-23T03:15:32Z cp-gw-01 CheckPoint 26045 - [action:"Drop"; flags:"411908"; ifdir:"inbound"; ifname:"eth1"; logid:"0"; loguid:"{0x66f0e0a4,0x0,0x3000000a,0xc0000000}"; origin:"10.1.0.2"; originsicname:"CN=cp-gw-01,O=cp-mgmt..abcd12"; sequencenum:"4"; time:"%d"; version:"5"; dst:"10.1.0.80"; inzone:"External"; layer_name:"Network"; match_id:"4"; outzone:"Internal"; product:"VPN-1 & FireWall-1"; proto:"6"; rule_action:"Drop"; rule_name:"Cleanup rule"; s_port:"51234"; service:"22"; service_id:"ssh"; src:"203.0.113.50"]' % T("2026-09-23T03:15:32Z"),
     "info", "cp-gw-01", "VPN-1 & FireWall-1", 24, "2026-09-23T03:15:32Z"),
    ('<134>1 2026-09-23T03:15:40Z cp-gw-01 CheckPoint 26045 - [action:"Accept"; ifdir:"outbound"; ifname:"eth0"; origin:"10.1.0.2"; time:"%d"; dst:"8.8.8.8"; product:"VPN-1 & FireWall-1"; proto:"17"; rule_name:"DNS out"; s_port:"53012"; service:"53"; service_id:"domain-udp"; src:"10.1.0.5"; xlatesrc:"203.0.113.10"]' % T("2026-09-23T03:15:40Z"),
     "info", "cp-gw-01", "VPN-1 & FireWall-1", 14, "2026-09-23T03:15:40Z"),
    ('<132>1 2026-09-23T03:16:00Z cp-gw-01 CheckPoint 26045 - [action:"Prevent"; confidence_level:"5"; origin:"10.1.0.2"; time:"%d"; attack:"Remote Code Execution"; attack_info:"Apache Log4j Remote Code Execution (CVE-2021-44228)"; dst:"10.1.0.80"; performance_impact:"2"; product:"IPS"; protection_id:"asm_dynamic_prop_CVE_2021_44228"; protection_name:"Apache Log4j Remote Code Execution (CVE-2021-44228)"; protection_type:"IPS"; proto:"6"; service:"443"; severity:"Critical"; src:"198.51.100.23"]' % T("2026-09-23T03:16:00Z"),
     "critical", "cp-gw-01", "IPS", 16, "2026-09-23T03:16:00Z"),
    ('<132>1 2026-09-23T03:16:10Z cp-gw-01 CheckPoint 26045 - [action:"Detect"; origin:"10.1.0.2"; time:"%d"; confidence_level:"3"; dst:"10.1.0.44"; file_name:"invoice.docm"; malware_action:"Malicious file"; product:"Threat Emulation"; protection_name:"Gen.Win.Macro.a"; severity:"High"; src:"192.0.2.77"; te_verdict_determined_by:"Emulators: win10"]' % T("2026-09-23T03:16:10Z"),
     "error", "cp-gw-01", "Threat Emulation", 12, "2026-09-23T03:16:10Z"),
    ('<134>1 2026-09-23T03:16:20Z cp-mgmt CheckPoint 18215 - [action:"Accept"; origin:"10.1.0.3"; time:"%d"; administrator:"admin"; client_ip:"10.1.0.5"; machine:"ADMIN-PC"; operation:"Log In"; operation_number:"10"; product:"SmartConsole"; subject:"Administrator Login"; status:"Success"]' % T("2026-09-23T03:16:20Z"),
     "info", "cp-mgmt", "SmartConsole", 11, "2026-09-23T03:16:20Z"),
    ('<133>1 2026-09-23T03:16:30Z cp-gw-01 CheckPoint 26045 - [action:"Key Install"; origin:"10.1.0.2"; time:"%d"; community:"Branch-VPN"; ike:"Main Mode completion."; peer_gateway:"198.51.100.7"; product:"VPN-1 & FireWall-1"; scheme:"IKE"; vpn_feature_name:"VPN"]' % T("2026-09-23T03:16:30Z"),
     "notice", "cp-gw-01", "VPN-1 & FireWall-1", 9, "2026-09-23T03:16:30Z"),
    ('<13>Sep 23 10:16:40 cp-mgmt time=%d; action=Accept; product=VPN-1 & FireWall-1; src=10.1.0.5; dst=8.8.8.8; service=53; level=Low;' % T("2026-09-23T03:16:40Z"),
     "info", "cp-mgmt", "VPN-1 & FireWall-1", 7, "2026-09-23T10:16:40"),
]

# ---------------------------------------------------------------- Palo Alto PAN-OS 10.2 / 11 CSV


def row(n, cols):
    r = [""] * n
    for k, v in cols.items():
        r[k] = v
    def q(v):
        return '"' + v.replace('"', '""') + '"' if ("," in v or '"' in v) else v
    return ",".join(q(v) for v in r)


def common(t, typ, sub):
    return {0: "1", 1: t, 2: "012801012345", 3: typ, 4: sub, 5: "2561", 6: t}


def traffic(t, sub, src, dst, rule, app, sport, dport, proto, action, nbytes, country="United States"):
    c = common(t, "TRAFFIC", sub)
    c.update({7: src, 8: dst, 9: "203.0.113.10" if action == "allow" else "0.0.0.0", 10: dst if action == "allow" else "0.0.0.0",
              11: rule, 12: "corp\\alice", 14: app, 15: "vsys1", 16: "trust", 17: "untrust",
              18: "ethernet1/2", 19: "ethernet1/1", 20: "default", 21: t, 22: "123456", 23: "1",
              24: sport, 25: dport, 26: "41234" if action == "allow" else "0", 27: dport if action == "allow" else "0",
              28: "0x400064", 29: proto, 30: action, 31: nbytes, 32: "98", 33: str(int(nbytes) - 98), 34: "2",
              35: t, 36: "0", 37: "any", 38: "0", 39: "7300000000000000", 40: "0x8000000000000000",
              41: "10.0.0.0-10.255.255.255", 42: country, 44: "1", 45: "1",
              46: "aged-out" if action == "allow" else "policy-deny", 47: "0", 48: "0", 49: "0", 50: "0",
              52: "PA-3220", 53: "from-policy", 65: "a1b2c3d4-0000-4000-8000-000000000001", 67: "0",
              102: "2026-09-23T10:15:32.123+07:00", 105: "infrastructure", 106: "networking",
              107: "network-protocol", 108: "3", 110: app, 114: "0"})
    return row(115, c)


def threat(t, sub, src, dst, app, dport, action, misc, tid, cat, sev):
    c = common(t, "THREAT", sub)
    c.update({7: src, 8: dst, 9: "203.0.113.10", 10: dst, 11: "allow-web", 12: "corp\\alice", 14: app,
              15: "vsys1", 16: "trust", 17: "untrust", 18: "ethernet1/2", 19: "ethernet1/1", 20: "default",
              21: t, 22: "123457", 23: "1", 24: "53100", 25: dport, 26: "41300", 27: dport, 28: "0x40b000",
              29: "tcp", 30: action, 31: misc, 32: tid, 33: cat, 34: sev, 35: "client-to-server",
              36: "7300000000000001", 37: "0x8000000000000000", 38: "10.0.0.0-10.255.255.255",
              39: "United States", 41: "text/html", 42: "0", 54: "0", 55: "0", 56: "0", 57: "0",
              59: "PA-3220", 69: "unknown", 70: "AppThreat-8800-8000", 76: "a1b2c3d4-0000-4000-8000-000000000002",
              107: "2026-09-23T10:16:01.456+07:00", 111: "internet-utility", 112: "general-internet",
              113: "browser-based", 114: "4"})
    return row(120, c)


def system(t, eventid, module, sev, desc):
    c = common(t, "SYSTEM", "general" if eventid == "general" else "auth")
    c.update({8: eventid, 10: "0", 11: "0", 12: module, 13: sev, 14: desc, 15: "1234", 16: "0x0",
              17: "0", 18: "0", 19: "0", 20: "0", 22: "PA-3220", 23: "0", 24: "0",
              25: "2026-09-23T10:17:00.000+07:00"})
    return row(26, c)


pa_hdr = "<14>Sep 23 %s PA-3220 "
corpus["paloalto"] = [
    (pa_hdr % "10:15:32" + traffic("2026/09/23 10:15:32", "end", "10.1.0.5", "8.8.8.8", "allow-dns", "dns-base", "53012", "53", "udp", "allow", "196"),
     "info", "PA-3220", "TRAFFIC/end", 20, "2026-09-23T10:15:32"),
    ("<12>Sep 23 10:15:33 PA-3220 " + traffic("2026/09/23 10:15:33", "deny", "10.1.0.7", "198.51.100.80", "block-smb-out", "ms-ds-smb-base", "51000", "445", "tcp", "deny", "74"),
     "warning", "PA-3220", "TRAFFIC/deny", 20, "2026-09-23T10:15:33"),
    ("<14>1 2026-09-23T10:16:01+07:00 PA-3220 - - - - " + threat("2026/09/23 10:16:01", "url", "10.1.0.5", "93.184.216.34", "web-browsing", "80", "alert", "example.com/a,b?x=1", "(9999)", "computer-and-internet-info", "informational"),
     "info", "PA-3220", "THREAT/url", 25, "2026-09-23T10:16:01+07:00"),
    ("<10>Sep 23 10:16:05 PA-3220 " + threat("2026/09/23 10:16:05", "vulnerability", "198.51.100.23", "10.1.0.80", "web-browsing", "443", "reset-both", "", "Apache Log4j Remote Code Execution Vulnerability(91991)", "code-execution", "critical"),
     "error", "PA-3220", "THREAT/vulnerability", 25, "2026-09-23T10:16:05"),
    ("<12>Sep 23 10:16:06 PA-3220 " + threat("2026/09/23 10:16:06", "spyware", "10.1.0.44", "192.0.2.66", "dns-base", "53", "sinkhole", "evil.example.net", "generic:evil.example.net(109010001)", "dns-c2", "medium"),
     "warning", "PA-3220", "THREAT/spyware", 25, "2026-09-23T10:16:06"),
    ("<12>Sep 23 10:17:00 PA-3220 " + system("2026/09/23 10:17:00", "auth-fail", "general", "medium", "failed authentication for user 'admin'. Reason: Invalid username/password. From: 10.1.0.99."),
     "warning", "PA-3220", "SYSTEM/auth", 6, "2026-09-23T10:17:00"),
    ("<14>Sep 23 10:17:10 PA-3220 " + row(28, {**common("2026/09/23 10:17:10", "CONFIG", "0"), 7: "10.1.0.5", 8: "vsys1", 9: "set", 10: "admin", 11: "Web", 12: "Succeeded", 13: " vsys  vsys1 rulebase security rules  allow-dns", 16: "1235", 17: "0x0", 18: "0", 19: "0", 20: "0", 21: "0", 23: "PA-3220", 27: "2026-09-23T10:17:10.000+07:00"}),
     "info", "PA-3220", "CONFIG", 8, "2026-09-23T10:17:10"),
    ("<14>Sep 23 10:17:20 PA-3220 " + row(36, {**common("2026/09/23 10:17:20", "USERID", "login"), 7: "vsys1", 8: "10.1.0.5", 9: "corp\\alice", 10: "DC01", 11: "login", 12: "1", 13: "2700", 14: "0", 15: "0", 16: "agent", 17: "AD", 18: "1236", 19: "0x0", 20: "0", 21: "0", 22: "0", 23: "0", 25: "PA-3220", 26: "1", 28: "1970/01/01 07:00:00", 29: "0", 30: "0x0", 31: "alice", 33: "2026-09-23T10:17:20.000+07:00"}),
     "info", "PA-3220", "USERID/login", 6, "2026-09-23T10:17:20"),
    ("<14>Sep 23 10:17:30 PA-3220 " + row(49, {**common("2026/09/23 10:17:30", "GLOBALPROTECT", "0"), 7: "vsys1", 8: "gateway-connected", 9: "connected", 11: "IPSec", 12: "corp\\bob", 13: "TH", 14: "BOB-LAPTOP", 15: "198.51.100.44", 16: "::", 17: "10.250.0.12", 18: "::", 19: "8b4f1c2e-aaaa-bbbb-cccc-000000000001", 21: "6.2.4-18", 22: "Windows", 23: "Microsoft Windows 11 Pro , 64-bit", 24: "1", 28: "success", 30: "0", 31: "on-demand", 32: "0", 33: "gp-portal", 34: "1237", 35: "0x0", 36: "2026-09-23T10:17:30.000+07:00", 37: "automatic", 38: "12", 39: "1", 41: "gp-gw-hq", 42: "0", 43: "0", 44: "0", 45: "0", 47: "PA-3220", 48: "1"}),
     "info", "PA-3220", "GLOBALPROTECT/gateway-connected", 8, "2026-09-23T10:17:30"),
    ("<14>Sep 23 10:17:40 PA-3220 " + row(95, {**common("2026/09/23 10:17:40", "DECRYPTION", "0"), 7: "10.1.0.5", 8: "142.250.66.78", 9: "203.0.113.10", 10: "142.250.66.78", 11: "decrypt-web", 12: "corp\\alice", 14: "ssl", 15: "vsys1", 16: "trust", 17: "untrust", 18: "ethernet1/2", 19: "ethernet1/1", 20: "default", 21: "2026/09/23 10:17:40", 22: "123460", 23: "1", 24: "53300", 25: "443", 26: "41500", 27: "443", 28: "0x400000", 29: "tcp", 30: "allow", 31: "0", 60: "www.google.com", 90: "2026-09-23T10:17:40.000+07:00"}),
     "info", "PA-3220", "DECRYPTION", 20, "2026-09-23T10:17:40"),
]

# ---------------------------------------------------------------- FortiOS 7.x


def ns(iso):
    return epoch(iso) * 1_000_000_000 + 123456789


corpus["fortigate"] = [
    ('<189>date=2026-09-23 time=10:15:32 devname="FGT-60F-Branch" devid="FGT60FTK20000000" eventtime=%d tz="+0700" logid="0000000013" type="traffic" subtype="forward" level="warning" vd="root" srcip=10.1.0.5 srcport=53012 srcintf="internal" dstip=8.8.8.8 dstport=53 dstintf="wan1" action="deny" policyid=1 service="DNS" proto=17' % ns("2026-09-23T10:15:32+07:00"),
     "warning", "FGT-60F-Branch", "traffic/forward", 18, "2026-09-23T10:15:32.123+07:00"),
    ('<189>date=2026-09-23 time=10:15:40 devname="FGT-100F-HQ" devid="FGT1HFTK21000000" eventtime=%d tz="+0700" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.1.0.7 srcport=51514 srcintf="port1" srcintfrole="lan" dstip=142.250.66.78 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=91234567 proto=6 action="close" policyid=5 policytype="policy" poluuid="1c2d3e4f-aaaa-51ee-bbbb-cccccccccccc" policyname="LAN-to-WAN" service="HTTPS" trandisp="snat" transip=203.0.113.10 transport=51514 appid=40568 app="Google.Services" appcat="General.Interest" apprisk="elevated" duration=12 sentbyte=2210 rcvdbyte=58210 sentpkt=18 rcvdpkt=45 utmaction="allow" countapp=1 osname="Windows" mastersrcmac="02:00:5e:10:00:07" srcmac="02:00:5e:10:00:07" srcserver=0' % ns("2026-09-23T10:15:40+07:00"),
     "notice", "FGT-100F-HQ", "traffic/forward", 40, "2026-09-23T10:15:40.123+07:00"),
    ('<190>date=2026-09-23 time=10:16:00 devname="FGT-100F-HQ" devid="FGT1HFTK21000000" eventtime=%d tz="+0700" logid="0100032001" type="event" subtype="system" level="information" vd="root" logdesc="Admin login successful" sn="1790133360" user="admin" ui="https(10.1.0.5)" method="https" srcip=10.1.0.5 dstip=10.1.0.1 action="login" status="success" reason="none" profile="super_admin" msg="Administrator admin logged in successfully from https(10.1.0.5)"' % ns("2026-09-23T10:16:00+07:00"),
     "info", "FGT-100F-HQ", "event/system", 20, "2026-09-23T10:16:00.123+07:00"),
    ('<189>date=2026-09-23 time=10:16:10 devname="FGT-100F-HQ" devid="FGT1HFTK21000000" eventtime=%d tz="+0700" logid="0101037138" type="event" subtype="vpn" level="notice" vd="root" logdesc="IPsec connection status changed" msg="IPsec connection status change" action="tunnel-up" remip=198.51.100.7 locip=203.0.113.10 remport=500 locport=500 outintf="wan1" cookies="1a2b3c4d5e6f7a8b/9c8d7e6f5a4b3c2d" user="N/A" group="N/A" useralt="N/A" xauthuser="N/A" xauthgroup="N/A" assignip=N/A vpntunnel="HQ-to-Branch" tunnelip=N/A tunnelid=1234567 tunneltype="ipsec" duration=0 sentbyte=0 rcvdbyte=0 nextstat=0' % ns("2026-09-23T10:16:10+07:00"),
     "notice", "FGT-100F-HQ", "event/vpn", 30, "2026-09-23T10:16:10.123+07:00"),
    ('<188>date=2026-09-23 time=10:16:20 devname="FGT-100F-HQ" devid="FGT1HFTK21000000" eventtime=%d tz="+0700" logid="0316013056" type="utm" subtype="webfilter" eventtype="ftgd_blk" level="warning" vd="root" policyid=5 sessionid=91234600 srcip=10.1.0.44 srcport=52011 srcintf="port1" srcintfrole="lan" dstip=192.0.2.66 dstport=443 dstintf="wan1" dstintfrole="wan" proto=6 service="HTTPS" hostname="malware.example.net" profile="default" action="blocked" reqtype="direct" url="https://malware.example.net/" sentbyte=517 rcvdbyte=0 direction="outgoing" msg="URL belongs to a denied category in policy" method="domain" cat=26 catdesc="Malicious Websites"' % ns("2026-09-23T10:16:20+07:00"),
     "warning", "FGT-100F-HQ", "utm/webfilter", 30, "2026-09-23T10:16:20.123+07:00"),
    ('<185>date=2026-09-23 time=10:16:30 devname="FGT-100F-HQ" devid="FGT1HFTK21000000" eventtime=%d tz="+0700" logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" vd="root" severity="critical" srcip=198.51.100.23 srccountry="Reserved" dstip=10.1.0.80 srcintf="wan1" srcintfrole="wan" dstintf="dmz" dstintfrole="dmz" sessionid=91234700 action="dropped" proto=6 service="HTTPS" policyid=9 attack="Apache.Log4j.Error.Log.Remote.Code.Execution" srcport=40404 dstport=443 direction="outgoing" attackid=51006 profile="protect_http_server" ref="http://www.fortinet.com/ids/VID51006" incidentserialno=12345678 msg="applications3: Apache.Log4j.Error.Log.Remote.Code.Execution," crscore=50 craction=4096 crlevel="critical"' % ns("2026-09-23T10:16:30+07:00"),
     "alert", "FGT-100F-HQ", "utm/ips", 30, "2026-09-23T10:16:30.123+07:00"),
    ('<189>date=2026-09-23 time=10:16:40 devname="FGT-60F-Branch" devid="FGT60FTK20000000" eventtime=%d tz="+0700" logid="0001000014" type="traffic" subtype="local" level="notice" vd="root" srcip=203.0.113.9 srcport=40511 srcintf="wan1" srcintfrole="wan" dstip=203.0.113.1 dstport=161 dstintf="root" dstintfrole="undefined" sessionid=5512 proto=17 action="deny" policyid=0 policytype="local-in-policy" service="SNMP" trandisp="noop" app="SNMP" duration=0 sentbyte=0 rcvdbyte=0 sentpkt=0 rcvdpkt=0 appcat="unscanned"' % ns("2026-09-23T10:16:40+07:00"),
     "notice", "FGT-60F-Branch", "traffic/local", 25, "2026-09-23T10:16:40.123+07:00"),
    ('<189>Sep 23 10:16:50 FGT-60F-Branch date=2026-09-23 time=10:16:50 devname="FGT-60F-Branch" devid="FGT60FTK20000000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.1.0.9 srcport=50000 srcintf="internal" dstip=10.2.0.10 dstport=22 dstintf="HQ-to-Branch" action="accept" policyid=3 service="SSH" proto=6',
     "notice", "FGT-60F-Branch", "traffic/forward", 18, "2026-09-23T10:16:50"),
    # Round 13: an interface down and up — the state is status=, the message never says "link".
    ('<188>date=2026-09-23 time=10:30:00 devname="FGT-100F-HQ" devid="FGT1HFTK21000000" eventtime=1790134200123456789 tz="+0700" logid="0100020022" type="event" subtype="system" level="warning" vd="root" logdesc="Interface status changed" action="interface-stat-change" status="DOWN" msg="Interface port3 changed status to DOWN."',
     "warning", "FGT-100F-HQ", "event/system", 15, "2026-09-23T10:30:00.123+07:00"),
    ('<189>date=2026-09-23 time=10:30:40 devname="FGT-100F-HQ" devid="FGT1HFTK21000000" eventtime=1790134240123456789 tz="+0700" logid="0100020022" type="event" subtype="system" level="notice" vd="root" logdesc="Interface status changed" action="interface-stat-change" status="UP" msg="Interface port3 changed status to UP."',
     "notice", "FGT-100F-HQ", "event/system", 15, "2026-09-23T10:30:40.123+07:00"),
]

# ---------------------------------------------------------------- Other (must stay .unknown)
corpus["other"] = [
    ('<187>123: Sep 23 10:15:32.123: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down',
     "error", "-", "%LINK-3-UPDOWN", 0, "2026-09-23T10:15:32.123"),
    ('<189>124: CORE-RTR1: Sep 23 10:15:33.456 UTC: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (10.1.0.5)',
     "notice", "CORE-RTR1", "%SYS-5-CONFIG_I", 0, "2026-09-23T10:15:33.456Z"),
    ('<189>125: CORE-RTR1: *Sep 23 10:15:34.789: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to down',
     "notice", "CORE-RTR1", "%LINEPROTO-5-UPDOWN", 0, "2026-09-23T10:15:34.789"),
    ('<189>126: CORE-RTR1: Sep 23 10:15:35.000 ICT: %LLDP-5-NEIGHBOR_ADDED: LLDP neighbor SW-2930F-01 added on GigabitEthernet0/2',
     "notice", "CORE-RTR1", "%LLDP-5-NEIGHBOR_ADDED", 0, "2026-09-23T10:15:35"),
    ('<189>2026 Sep 23 10:15:35 N9K-LEAF-01 %ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/1 is down (Link failure)',
     "notice", "N9K-LEAF-01", "%ETHPORT-5-IF_DOWN_LINK_FAILURE", 0, "2026-09-23T10:15:35"),
    ('<166>Sep 23 2026 10:15:36: %ASA-6-302013: Built outbound TCP connection 12345 for outside:8.8.8.8/443 (8.8.8.8/443) to inside:10.1.0.5/51234 (203.0.113.10/51234)',
     "info", "-", "%ASA-6-302013", 0, "2026-09-23T10:15:36"),
    ('<164>Sep 23 2026 10:15:37 ASA-FW01 : %ASA-4-106023: Deny tcp src outside:203.0.113.9/51234 dst inside:10.1.0.80/22 by access-group "outside_in" [0x0, 0x0]',
     "warning", "ASA-FW01", "%ASA-4-106023", 0, "2026-09-23T10:15:37"),
    ('<86>Sep 23 10:15:38 web01 sshd[1234]: Accepted publickey for deploy from 10.1.0.5 port 51234 ssh2: ED25519 SHA256:q9Yx2bXgT0y',
     "info", "web01", "sshd", 0, "2026-09-23T10:15:38"),
    ('<38>Sep 23 10:15:39 web01 sshd[1240]: Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2',
     "info", "web01", "sshd", 0, "2026-09-23T10:15:39"),
    ('<30>Sep 23 10:15:40 web01 systemd[1]: Started Session 42 of user deploy.',
     "info", "web01", "systemd", 0, "2026-09-23T10:15:40"),
    ('<4>Sep 23 10:15:41 web01 kernel: [123456.789012] e1000e: eth0 NIC Link is Down',
     "warning", "web01", "kernel", 0, "2026-09-23T10:15:41"),
    ('<78>Sep 23 10:16:01 web01 CRON[2345]: (root) CMD (run-parts /etc/cron.hourly)',
     "info", "web01", "CRON", 0, "2026-09-23T10:16:01"),
    ('<85>Sep 23 10:16:02 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx',
     "notice", "web01", "sudo", 4, "2026-09-23T10:16:02"),
    ('<13>1 2026-09-23T10:16:03.123456+07:00 web01 myapp 4321 - - hello from rsyslog',
     "notice", "web01", "myapp", 0, "2026-09-23T10:16:03.123+07:00"),
    ('<30>Sep 23 10:16:04 RB4011-HQ system,info,account user admin logged in from 10.1.0.5 via winbox',
     "info", "RB4011-HQ", "system,info,account", 0, "2026-09-23T10:16:04"),
    ('<30>Sep 23 10:16:05 RB4011-HQ firewall,info input: in:ether1 out:(unknown 0), src-mac 02:00:5e:aa:bb:cc, proto TCP (SYN), 203.0.113.9:51234->203.0.113.1:22, len 60',
     "info", "RB4011-HQ", "firewall,info", 0, "2026-09-23T10:16:05"),
    ('<4>Sep 23 10:16:06 ER-4 kernel: [WAN_LOCAL-default-D]IN=eth0 OUT= MAC=02:00:5e:aa:bb:cc:02:00:5e:dd:ee:ff:08:00 SRC=203.0.113.9 DST=203.0.113.1 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=4242 DF PROTO=TCP SPT=51234 DPT=22 WINDOW=29200 RES=0x00 SYN URGP=0',
     "warning", "ER-4", "kernel", 10, "2026-09-23T10:16:06"),
    ('<30>Sep 23 10:16:07 U6-Pro-Lobby,f4e2c6aabbcc,v6.6.55.15189 hostapd: ra0: STA 02:00:5e:10:00:09 IEEE 802.11: associated',
     "info", "U6-Pro-Lobby", "hostapd", 0, "2026-09-23T10:16:07"),
    # "action=" + two semicolons, but not Check Point (no product=)
    ('<85>Sep 23 10:16:09 web01 portal-auth[812]: user=alice; action=login; result=failure; src=10.1.0.5',
     "notice", "web01", "portal-auth", 4, "2026-09-23T10:16:09"),
    # An IPv6 host whose address starts like a year (2001:), and a relay's "-" for no hostname
    ('<38>Sep 23 10:16:10 2001:db8::10 sshd[2200]: Accepted publickey for deploy from 2001:db8::5 port 50222 ssh2',
     "info", "2001:db8::10", "sshd", 0, "2026-09-23T10:16:10"),
    ('<13>Sep 23 10:16:11 - logger: relayed without a hostname',
     "notice", "-", "logger", 0, "2026-09-23T10:16:11"),
    # Round 13: other vendors' classic forms, where the mnemonic sits in the message (Junos),
    # the program (NX-OS, ASA) or a topic list (MikroTik) — each read by the Troubleshoot rules.
    # Juniper Junos: an OSPF neighbour lost and back, a commit, a power supply (PEM) removed.
    ('<28>Sep 23 10:16:12 MX204-EDGE rpd[1811]: RPD_OSPF_NBRDOWN: OSPF neighbor 10.0.12.2 (realm ospf-v2 xe-0/0/1.0 area 0.0.0.0) state changed from Full to Down due to InactivityTimer (event reason: BFD session timed out and neighbor was declared dead)',
     "warning", "MX204-EDGE", "rpd", 0, "2026-09-23T10:16:12"),
    ('<29>Sep 23 10:16:52 MX204-EDGE rpd[1811]: RPD_OSPF_NBRUP: OSPF neighbor 10.0.12.2 (realm ospf-v2 xe-0/0/1.0 area 0.0.0.0) state changed from Loading to Full due to LoadDone (event reason: OSPF loading completed)',
     "notice", "MX204-EDGE", "rpd", 0, "2026-09-23T10:16:52"),
    ("<189>Sep 23 10:17:00 MX204-EDGE mgd[4410]: UI_COMMIT: User 'netops' requested 'commit' operation (comment: none)",
     "notice", "MX204-EDGE", "mgd", 0, "2026-09-23T10:17:00"),
    ('<188>Sep 23 10:17:30 MX204-EDGE chassisd[1509]: CHASSISD_FRU_OFFLINE_NOTICE: Taking PEM 1 offline: Removal',
     "warning", "MX204-EDGE", "chassisd", 0, "2026-09-23T10:17:30"),
    # MikroTik RouterOS: a port down and back.
    ('<30>Sep 23 10:16:13 RB4011-HQ interface,info ether5 link down',
     "info", "RB4011-HQ", "interface,info", 0, "2026-09-23T10:16:13"),
    ('<30>Sep 23 10:16:41 RB4011-HQ interface,info ether5 link up (speed 1G, full duplex)',
     "info", "RB4011-HQ", "interface,info", 0, "2026-09-23T10:16:41"),
    # Ubiquiti UniFi switch (TRAPMGR, the port after "Link Down:") and EdgeOS (kernel): down and back.
    ('<30>Sep 23 10:16:14 USW-24-PoE,f4e2c6ddeeff,v6.6.61.15220: switch: TRAPMGR: Link Down: 0/9',
     "info", "USW-24-PoE", "switch", 0, "2026-09-23T10:16:14"),
    ('<30>Sep 23 10:16:44 USW-24-PoE,f4e2c6ddeeff,v6.6.61.15220: switch: TRAPMGR: Link Up: 0/9',
     "info", "USW-24-PoE", "switch", 0, "2026-09-23T10:16:44"),
    ('<3>Sep 23 10:16:15 ER-4 kernel: [ 9812.100211] eth1: link down',
     "error", "ER-4", "kernel", 0, "2026-09-23T10:16:15"),
    ('<6>Sep 23 10:16:45 ER-4 kernel: [ 9842.100211] eth1: link up, 1000Mbps, full-duplex, lpa 0xC1E1',
     "info", "ER-4", "kernel", 0, "2026-09-23T10:16:45"),
    # Cisco NX-OS: a port down and up again (IF_UP says no "link"), OSPF down and FULL again.
    ('<189>2026 Sep 23 10:17:00 N9K-LEAF-02 %ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/7 is down (Link failure)',
     "notice", "N9K-LEAF-02", "%ETHPORT-5-IF_DOWN_LINK_FAILURE", 0, "2026-09-23T10:17:00"),
    ('<189>2026 Sep 23 10:17:30 N9K-LEAF-02 %ETHPORT-5-IF_UP: Interface Ethernet1/7 is up in mode trunk',
     "notice", "N9K-LEAF-02", "%ETHPORT-5-IF_UP", 0, "2026-09-23T10:17:30"),
    ('<189>2026 Sep 23 10:18:00 N9K-LEAF-02 %OSPF-5-ADJCHANGE: ospf-100 [7243] Nbr 10.0.13.2 on Ethernet1/49 went DOWN',
     "notice", "N9K-LEAF-02", "%OSPF-5-ADJCHANGE", 0, "2026-09-23T10:18:00"),
    ('<189>2026 Sep 23 10:18:40 N9K-LEAF-02 %OSPF-5-ADJCHANGE: ospf-100 [7243] Nbr 10.0.13.2 on Ethernet1/49 went FULL',
     "notice", "N9K-LEAF-02", "%OSPF-5-ADJCHANGE", 0, "2026-09-23T10:18:40"),
    # Cisco ASA: an interface's line protocol down and up, and a write memory.
    ('<164>Sep 23 2026 10:19:00 ASA-FW02 : %ASA-4-411002: Line protocol on Interface outside, changed state to down',
     "warning", "ASA-FW02", "%ASA-4-411002", 0, "2026-09-23T10:19:00"),
    ('<164>Sep 23 2026 10:19:30 ASA-FW02 : %ASA-4-411001: Line protocol on Interface outside, changed state to up',
     "warning", "ASA-FW02", "%ASA-4-411001", 0, "2026-09-23T10:19:30"),
    ("<165>Sep 23 2026 10:19:50 ASA-FW02 : %ASA-5-111008: User 'admin' executed the 'write memory' command.",
     "notice", "ASA-FW02", "%ASA-5-111008", 0, "2026-09-23T10:19:50"),
    # Round 14: more vendors' forms, each read by the Troubleshoot rules.
    # Arista EOS: a port's line protocol down and up, a configuration from the console, a BGP
    # session reset (the NOTIFICATION is why the peer went down — not a second down).
    ('<187>Sep 23 10:20:00 LEAF-EOS-1 Ebra: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet5, changed state to down',
     "error", "LEAF-EOS-1", "Ebra", 0, "2026-09-23T10:20:00"),
    ('<189>Sep 23 10:20:30 LEAF-EOS-1 Ebra: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet5, changed state to up',
     "notice", "LEAF-EOS-1", "Ebra", 0, "2026-09-23T10:20:30"),
    ('<189>Sep 23 10:21:00 LEAF-EOS-1 ConfigAgent: %SYS-5-CONFIG_I: Configured from console by admin on vty3 (10.0.0.5)',
     "notice", "LEAF-EOS-1", "ConfigAgent", 0, "2026-09-23T10:21:00"),
    ('<187>Sep 23 10:21:20 LEAF-EOS-1 Bgp: %BGP-3-NOTIFICATION: received from neighbor 10.0.0.2 (VRF default AS 65002) 4/0 (Hold Timer Expired Error/Unspecific) 0 bytes',
     "error", "LEAF-EOS-1", "Bgp", 0, "2026-09-23T10:21:20"),
    ('<189>Sep 23 10:21:20 LEAF-EOS-1 Bgp: %BGP-5-ADJCHANGE: peer 10.0.0.2 (VRF default AS 65002) old state Established event HoldTimerExpired new state Idle',
     "notice", "LEAF-EOS-1", "Bgp", 0, "2026-09-23T10:21:20"),
    ('<189>Sep 23 10:21:50 LEAF-EOS-1 Bgp: %BGP-5-ADJCHANGE: peer 10.0.0.2 (VRF default AS 65002) old state OpenConfirm event RecvKeepAlive new state Established',
     "notice", "LEAF-EOS-1", "Bgp", 0, "2026-09-23T10:21:50"),
    # Extreme EXOS: the event name in angle brackets, a port down and up.
    ('<30>Sep 23 10:22:00 X460-G2 <Info:vlan.msgs.portLinkStateDown> Port 1:5 link down',
     "info", "X460-G2", "-", 0, "2026-09-23T10:22:00"),
    ('<30>Sep 23 10:22:30 X460-G2 <Info:vlan.msgs.portLinkStateUp> Port 1:5 link UP at speed 1 Gbps and full-duplex',
     "info", "X460-G2", "-", 0, "2026-09-23T10:22:30"),
    # Ruckus ICX: "Interface ethernet 1/1/5, state down" (no "link"), and up again.
    ('<14>Sep 23 10:23:00 ICX7150-SW1 System: Interface ethernet 1/1/5, state down',
     "info", "ICX7150-SW1", "System", 0, "2026-09-23T10:23:00"),
    ('<14>Sep 23 10:23:40 ICX7150-SW1 System: Interface ethernet 1/1/5, state up',
     "info", "ICX7150-SW1", "System", 0, "2026-09-23T10:23:40"),
    # Cisco Meraki MS: version 1, epoch seconds, the device, the category ("events").
    ('<134>1 1790133840.123456789 MS220-8P events port 3 status changed from 1Gfdx to down',
     "info", "MS220-8P", "events", 0, "2026-09-23T03:24:00.123Z"),
    ('<134>1 1790133870.123456789 MS220-8P events port 3 status changed from down to 1Gfdx',
     "info", "MS220-8P", "events", 0, "2026-09-23T03:24:30.123Z"),
    # Cisco IOS XR: the node before the time (no hostname, then `logging hostnameprefix`).
    ('<187>100: RP/0/RSP0/CPU0:Sep 23 10:25:00.123 UTC: ifmgr[245]: %PKT_INFRA-LINK-3-UPDOWN : Interface GigabitEthernet0/0/0/1, changed state to Down',
     "error", "-", "ifmgr", 2, "2026-09-23T10:25:00.123Z"),
    ('<189>101: RP/0/RSP0/CPU0:Sep 23 10:25:30.123 UTC: ifmgr[245]: %PKT_INFRA-LINK-3-UPDOWN : Interface GigabitEthernet0/0/0/1, changed state to Up',
     "notice", "-", "ifmgr", 2, "2026-09-23T10:25:30.123Z"),
    ("<189>102: XR-PE1 RP/0/RSP0/CPU0:Sep 23 10:25:40.123 UTC: config[65727]: %MGBL-CONFIG-6-DB_COMMIT : Configuration committed by user 'admin'. Use 'show configuration commit changes 1000000021' to view the changes.",
     "notice", "XR-PE1", "config", 2, "2026-09-23T10:25:40.123Z"),
]

total = 0
for name, lines in corpus.items():
    with open(os.path.join(out, name + ".log"), "w") as f:
        for l in lines:
            assert "\n" not in l[0]
            f.write(l[0] + "\n")
    with open(os.path.join(out, name + ".expect"), "w") as f:
        for l in lines:
            f.write("\t".join(str(x) for x in l[1:]) + "\n")
    total += len(lines)
    print(f"{name:12} {len(lines)}")
print("total", total)
