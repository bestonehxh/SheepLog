#!/usr/bin/env bash
# Sends one line of every vendor format SheepLog knows to a syslog listener — first over UDP,
# then over TCP with RFC 6587 octet counting — and optionally floods COUNT more lines over UDP
# as fast as possible for the performance check.
#
#   Tests/replay.sh [host] [port] [count]      defaults: 127.0.0.1 514 0
#
# The samples are the fixtures in SheepLogTests/SyslogParserTests.swift followed by every line
# of the real-shaped corpus in Tests/corpus/*.log (CorpusTests.swift asserts how each parses).
# CORPUS_ONLY=1 sends just the corpus.
set -euo pipefail

HOST="${1:-127.0.0.1}"
PORT="${2:-514}"
COUNT="${3:-0}"
CORPUS="$(cd "$(dirname "$0")" && pwd)/corpus"

exec python3 - "$HOST" "$PORT" "$COUNT" "$CORPUS" "${CORPUS_ONLY:-0}" <<'PY'
import glob, os, socket, sys, time

host, port, count = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
corpus_dir, corpus_only = sys.argv[4], sys.argv[5] == "1"

SAMPLES = [
    # Aruba AOS-CX
    '<187>1 2026-09-23T10:15:32.123+07:00 CX-6300-01 lldpd 2512 - - Event|1302|LOG_WARN|AMM|1/1|LLDP neighbor 10.1.0.9 removed on port 1/1/24',
    # Aruba AOS 8 controller / IAP
    '<133>Sep 23 10:12:01 2026 MM-1 authmgr[4211]: <522008> <4211> <NOTI> <MM-1 10.1.1.10>  User Authentication Successful: username=alice MAC=02:00:5e:10:00:01 IP=10.20.0.15 role=employee VLAN=20 AP=AP-Lobby SSID=Corp',
    '<132>Sep 23 10:12:05 2026 10.1.1.21 cli[3510]: <341004> <WARN> |AP IAP-305-Lobby@10.1.1.21 cli| Recv image upgrade request',
    # Aruba AOS-S / ProCurve
    '<14> Sep 23 10:15:32 10.1.0.20 00076 ports: port 1/1/24 is now off-line',
    # ClearPass
    '<14>Sep 23 10:15:32 cppm01 CPPM_RADIUS_Logs 1234 1 0 Common.Username=alice,Common.Service=Corp Wireless 802.1X,Common.Login-Status=REJECT,Common.Roles=[Employee], [User Authenticated],RADIUS.Auth-Source=AD:ad01.corp.example,Common.NAS-IP-Address=10.1.1.10',
    # Huawei VRP
    '<187>Sep 23 2026 10:15:32 HW-CE6881 %%01IFNET/4/LINK_STATE(l)[12]:The line protocol IP on the interface 10GE1/0/24 has entered the DOWN state.',
    # Check Point (log_exporter, and key=value;)
    '<134>1 2026-09-23T03:15:32Z cp-gw-01 CheckPoint 26045 - [action:"Drop"; flags:"411908"; ifdir:"inbound"; ifname:"eth1"; origin:"10.1.0.2"; product:"VPN-1 & FireWall-1"; src:"203.0.113.50"; dst:"10.1.0.80"; proto:"6"; service:"22"; severity:"High"]',
    '<13>Sep 23 10:15:32 cp-mgmt time=1790139332; action=Accept; product=VPN-1 & FireWall-1; src=10.1.0.5; dst=8.8.8.8; service=53; level=Low;',
    # Palo Alto (TRAFFIC, THREAT with a quoted comma, SYSTEM)
    '<14>Sep 23 10:15:32 PA-3220 1,2026/09/23 10:15:32,012801012345,TRAFFIC,end,2561,2026/09/23 10:15:32,10.1.0.5,8.8.8.8,203.0.113.10,8.8.8.8,allow-dns,corp\\alice,,dns-base,vsys1,trust,untrust,ethernet1/2,ethernet1/1,default,,123456,1,53012,53,41234,53,0x400064,udp,allow,196,98,98,2,2026/09/23 10:15:02,0,any,,7300000000000000,0x0,10.0.0.0-10.255.255.255,United States,,1,1',
    '<12>Sep 23 10:16:01 PA-3220 1,2026/09/23 10:16:01,012801012345,THREAT,url,2561,2026/09/23 10:16:01,10.1.0.5,93.184.216.34,203.0.113.10,93.184.216.34,allow-web,corp\\alice,,web-browsing,vsys1,trust,untrust,ethernet1/2,ethernet1/1,default,,123457,1,53100,80,41300,80,0x40b000,tcp,alert,"example.com/a,b?x=1",(9999),malware,high,client-to-server,7300000000000001',
    '<14>Sep 23 10:17:00 PA-3220 1,2026/09/23 10:17:00,012801012345,SYSTEM,general,2561,2026/09/23 10:17:00,,general,,0,0,general,medium,"User admin logged in via Web from 10.1.0.5 using https",1234,0x0,0,0,0,0,,PA-3220',
    # Fortigate
    '<189>date=2026-09-23 time=10:15:32 devname="FGT-60F-Branch" devid="FGT60FTK20000000" eventtime=1790139332000000000 tz="+0700" logid="0000000013" type="traffic" subtype="forward" level="warning" vd="root" srcip=10.1.0.5 srcport=53012 srcintf="internal" dstip=8.8.8.8 dstport=53 dstintf="wan1" action="deny" policyid=1 service="DNS" proto=17',
    # Other (plain, and generic key=value)
    '<13>Sep 23 10:15:32 linux-box sshd[1234]: Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2',
    '<12>Sep 23 10:15:32 fw1 kernel: IN=eth0 OUT= SRC=203.0.113.9 DST=10.1.0.5 PROTO=TCP DPT=22',
    # RFC 5424 with structured data
    '<165>1 2026-09-23T03:15:32.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] An application event log entry',
]

corpus = []
for path in sorted(glob.glob(os.path.join(corpus_dir, "*.log"))):
    with open(path, encoding="utf-8") as f:
        corpus += [l.rstrip("\n") for l in f if l.strip()]
if corpus_only:
    SAMPLES = corpus
else:
    SAMPLES = SAMPLES + corpus
if not corpus:
    print(f"(no corpus found in {corpus_dir})")

family = socket.AF_INET6 if ":" in host else socket.AF_INET
target = (host, port)

udp = socket.socket(family, socket.SOCK_DGRAM)
udp.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
for line in SAMPLES:
    udp.sendto(line.encode(), target)
print(f"UDP  sent {len(SAMPLES)} sample lines to {host}:{port}")

try:
    tcp = socket.create_connection(target, timeout=3)
    payload = b"".join(str(len(s.encode())).encode() + b" " + s.encode() for s in SAMPLES)
    tcp.sendall(payload)
    tcp.close()
    print(f"TCP  sent {len(SAMPLES)} sample lines (octet-counted) to {host}:{port}")
except OSError as e:
    print(f"TCP  could not connect to {host}:{port}: {e}")

if count > 0:
    lines = []
    for i in range(count):
        sev = i % 8
        lines.append(f"<{184 + sev}>Sep 23 10:15:32 flood-{i % 16} loadgen[{i % 997}]: flood line {i} port 1/1/{i % 48} "
                     f"seq={i} src=10.9.{i % 250}.{i % 200} action=pass".encode())
    start = time.perf_counter()
    for data in lines:
        while True:
            try:
                udp.sendto(data, target)
                break
            except (BlockingIOError, OSError):
                time.sleep(0.0005)       # the local send buffer is full: back off briefly
    elapsed = time.perf_counter() - start
    rate = count / elapsed if elapsed > 0 else float("inf")
    print(f"UDP  flooded {count:,} lines in {elapsed:.3f} s ({rate:,.0f} lines/s)")
PY
