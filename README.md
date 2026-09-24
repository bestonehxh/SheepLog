<p align="center">
  <img src=".github/icon.png" width="128" alt="SheepLog app icon">
</p>

# 🐑 SheepLog

**Syslog viewer, SNMP tester and packet capture for network engineers — a native macOS app.**

[![Download SheepLog for macOS](https://img.shields.io/badge/Download-SheepLog_1.5_for_macOS-2ea44f?style=for-the-badge&logo=apple&logoColor=white)](https://github.com/bestonehxh/SheepLog/releases/latest)

**[Get the latest release →](https://github.com/bestonehxh/SheepLog/releases/latest)** — download `SheepLog-1.5.zip`, unzip, and drag **SheepLog.app** into `Applications`. The build is not notarised: on first launch right-click the app and choose Open.

Syslog viewer, SNMP tester and packet capture for network engineers — a native macOS app in
the Sheep family (SheepTerm · SheepText · SheepTap · SheepPing · SheepDrop · SheepArt ·
SheepRadius). No agents, no daemons, no Homebrew: copy the app, start it, point your devices at
your Mac.

## Syslog

- Listens on UDP and TCP 514 (RFC 3164, RFC 5424, octet-counted and newline framing) — no
  administrator rights needed on macOS 26.
- Knows the log shapes of Aruba AOS-CX, Aruba AOS 8 / Instant AP, Aruba AOS-S, ClearPass,
  Huawei VRP, Check Point, Palo Alto PAN-OS and Fortinet FortiOS: vendor, real severity and
  the vendor's own fields (Forti `srcip=`, Palo TRAFFIC columns, Huawei module/mnemonic, …)
  are parsed out and shown beside each line.
- One filter box: `login failed -keepalive host:10.1.0.9 sev:<=warn`, with `AND` / `OR` /
  `NOT` / `NOR`, parentheses, phrases, regex, and field terms (`vendor:forti`, `app:sshd`,
  `f:srcip=10.1.20.44`).
- Per-source counters, severity chips, pause, newest-first, export to .log / .csv, optional
  raw log files per day on disk. 100,000 lines in memory by default.
- SNMPv1/v2c traps and informs (UDP 162) arrive in the same list, named from the MIBs.

## SNMP

- v1, v2c and v3 (MD5 / SHA-1 / SHA-2 auth, DES / AES-128 / AES-192 / AES-256 priv), all
  implemented in the app.
- Quick Test (system group + reachability + RTT), Get, Get Next, Walk (GETBULK), and an
  Interfaces table (ifTable + ifXTable joined).
- 63 standard MIBs bundled; drop in your vendor's MIB files and OIDs get names, enums and
  display hints. A MIB browser with search.

## Capture

- Live capture on any interface through libpcap, promiscuous by default, so a switch's mirror
  (SPAN) port plugged into the Mac is fully visible. Opens and saves .pcap / .pcapng.
- Decodes Ethernet, VLAN, ARP, IPv4/IPv6, TCP/UDP/ICMP, LLDP, and HTTP / TLS (SNI) / DNS /
  DHCP / SNMP / Syslog / RADIUS / SSH by port and shape.
- **TCP flows**: every conversation gets a health verdict and a ladder diagram — SYN, SYN/ACK,
  request, grouped data segments, ACKs, FIN/RST with timings — and retransmissions, duplicate
  ACKs, zero windows, resets and slow responses are marked in red so you can see which part of
  the exchange is the problem.

## Requirements

macOS 26.4 (Tahoe) or later, Apple Silicon. Packet capture needs read access to `/dev/bpf*`
(Wireshark's ChmodBPF, or `sudo chmod g+rw /dev/bpf*`).
