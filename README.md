<p align="center">
  <img src=".github/icon.png" width="128" alt="UncleSpy app icon">
</p>

# UncleSpy

**Syslog viewer, SNMP tester and packet capture for network engineers — a native macOS app.** Formerly SheepLog.

[![Download UncleSpy for macOS](https://img.shields.io/badge/Download-UncleSpy_1.10_for_macOS-2ea44f?style=for-the-badge&logo=apple&logoColor=white)](https://github.com/bestonehxh/SheepLog/releases/latest)

**[Get the latest release →](https://github.com/bestonehxh/SheepLog/releases/latest)** — download `UncleSpy-1.10.zip`, unzip, and drag **UncleSpy.app** into `Applications`. The build is not notarised: on first launch right-click the app and choose Open.

One app for the three things you reach for when a network misbehaves: the devices' syslog, an
SNMP walk, and a packet capture of the SPAN port — plus a Troubleshoot page that reads all three
and tells you what went wrong. No agents, no daemons, no Homebrew: copy the app, start it,
point your devices at your Mac. An installed SheepLog keeps its settings, MIBs and log files.

## Syslog

- Listens on UDP and TCP 514 (RFC 3164, RFC 5424, octet-counted and newline framing) — no
  administrator rights needed on macOS 26.
- Knows the log shapes of Aruba AOS-CX, Aruba AOS 8 / Instant AP, Aruba AOS-S, ClearPass,
  Huawei VRP, Check Point, Palo Alto PAN-OS and Fortinet FortiOS: vendor, real severity and
  the vendor's own fields (Forti `srcip=`, Palo TRAFFIC columns, Huawei module/mnemonic, …)
  are parsed out and shown beside each line. Cisco IOS / NX-OS / ASA / IOS XR, Junos, Arista,
  MikroTik, Ubiquiti, Meraki and Linux lines are read for what they say too.
- One filter box: `login failed -keepalive host:10.1.0.9 sev:<=warn`, with `AND` / `OR` /
  `NOT` / `NOR`, parentheses, phrases, regex, whole IPv4 / IPv6 addresses and subnets, and
  field terms (`vendor:forti`, `app:sshd`, `f:srcip=10.1.20.44`, `word:Gi1/0/1`).
- Per-source counters and vendor overrides, pause, newest-first, export to .log / .csv, optional
  raw log files per day on disk. 100,000 lines in memory by default; 200,000 lines a second
  received without loss.
- SNMPv1/v2c traps and informs (UDP 162) arrive in the same list, named from the MIBs.

## Troubleshoot

- Reads the syslog lines, the capture and the SNMP walks together and lists findings in plain
  sentences: a flapping port, an OSPF or BGP neighbour that went down, a spanning-tree storm, a
  failed-login burst, a DHCP server that should not be there, DNS that stopped answering, a TCP
  service refusing or retransmitting, a port discarding packets, a configuration change just
  before the trouble started.
- A timeline per device, category words with counts, a Problems-only switch, and a filter in
  the same grammar as the Log. Every finding links to its evidence: the log lines, the packets,
  the conversation, the SNMP test.
- Type a client's MAC or IP for a report of everything seen about that client — DHCP, DNS, ARP,
  authentication, the switch port and the log lines that name it.

## SNMP

- v1, v2c and v3 (MD5 / SHA-1 / SHA-2 auth, DES / AES-128 / AES-192 / AES-256 priv), all
  implemented in the app.
- Quick Test (system group + reachability + RTT), Get, Get Next, Walk (GETBULK), and an
  Interfaces table (ifTable + ifXTable joined) with errors, discards and time since the last
  link change.
- 63 standard MIBs bundled; drop in your vendor's MIB files and OIDs get names, enums and
  display hints — traps that arrived before the import are renamed too. A MIB browser with
  search.

## Capture

- Live capture on any interface through libpcap, promiscuous by default, so a switch's mirror
  (SPAN) port plugged into the Mac is fully visible. Opens and saves .pcap / .pcapng.
- Decodes Ethernet, VLAN, ARP, IPv4/IPv6, TCP/UDP/ICMP, LLDP / CDP, and HTTP / TLS (SNI) /
  DNS / DHCP / SNMP / Syslog / RADIUS / EAP / SSH by port and shape. The same filter grammar as
  the Log (`proto:tcp port:443 OR ip:10.1.0.1 flags:syn`).
- **TCP flows**: every conversation gets a health verdict and a ladder diagram — SYN, SYN/ACK,
  request, grouped data segments, ACKs, FIN/RST with timings — and retransmissions, duplicate
  ACKs, zero windows, resets and slow responses are marked in red so you can see which part of
  the exchange is the problem. The sequence analysis matches Wireshark's.
- **Authentication**: 802.1X (PEAP, EAP-TLS, …), MAC authentication, WPA2-PSK handshakes and
  captive portals by client, each as a ladder between the client, the switch or AP and the RADIUS
  server — with the RADIUS attributes, the VLAN and role returned, and where a failed attempt
  stopped.

## The look

Monochrome and quiet: one page per job, the state written as words, red only for what went
wrong. Light and dark.

## Requirements

macOS 26.4 (Tahoe) or later, Apple Silicon. Packet capture needs read access to `/dev/bpf*`
(Wireshark's ChmodBPF, or `sudo chmod g+rw /dev/bpf*`).

## The Sheep family 🐑

UncleSpy is one of a few small native macOS apps for network engineers:

|  | App | What it does |
|---|---|---|
| <img src="https://raw.githubusercontent.com/bestonehxh/SheepTerm/main/.github/icon.png?v=3" width="48" height="48" alt="SheepTerm"> | **[SheepTerm](https://github.com/bestonehxh/SheepTerm)**<br>[⬇️ Download](https://github.com/bestonehxh/SheepTerm/releases/latest) | SSH / Serial / local-shell terminal for network engineers |
| <img src="https://raw.githubusercontent.com/bestonehxh/SheepText/main/.github/icon.png?v=3" width="48" height="48" alt="SheepText"> | **[SheepText](https://github.com/bestonehxh/SheepText)**<br>[⬇️ Download](https://github.com/bestonehxh/SheepText/releases/latest) | Fast text editor with tree-sitter highlighting and a JavaScript plugin system |
| <img src="https://raw.githubusercontent.com/bestonehxh/SheepDrop/main/.github/icon.png?v=3" width="48" height="48" alt="SheepDrop"> | **[SheepDrop](https://github.com/bestonehxh/SheepDrop)**<br>[⬇️ Download](https://github.com/bestonehxh/SheepDrop/releases/latest) | SFTP / SCP / FTP / TFTP file transfer — client and built-in server |
| <img src="https://raw.githubusercontent.com/bestonehxh/SheepTap/main/.github/icon.png?v=3" width="48" height="48" alt="SheepTap"> | **[SheepTap](https://github.com/bestonehxh/SheepTap)**<br>[⬇️ Download](https://github.com/bestonehxh/SheepTap/releases/latest) | Menu-bar viewer for your Mac's network interfaces with click-to-copy |
| <img src="https://raw.githubusercontent.com/bestonehxh/SheepPing/main/.github/icon.png?v=3" width="48" height="48" alt="SheepPing"> | **[SheepPing](https://github.com/bestonehxh/SheepPing)**<br>[⬇️ Download](https://github.com/bestonehxh/SheepPing/releases/latest) | Continuous multi-host ping monitor with per-host logs and CSV export |
| <img src="https://raw.githubusercontent.com/bestonehxh/LabDC/main/.github/icon.png" width="48" height="48" alt="LabDC"> | **[LabDC](https://github.com/bestonehxh/LabDC)**<br>[⬇️ Download](https://github.com/bestonehxh/LabDC/releases/latest) | Active Directory–compatible domain controller with RADIUS for 802.1X and a lab CA |
| <img src="https://raw.githubusercontent.com/bestonehxh/Paddock/main/.github/icon.png" width="48" height="48" alt="Paddock"> | **[Paddock](https://github.com/bestonehxh/Paddock)**<br>[⬇️ Download](https://github.com/bestonehxh/Paddock/releases/latest) | VM control and console for standalone ESXi hosts — power, snapshots, guest files and scripts, no vCenter |
