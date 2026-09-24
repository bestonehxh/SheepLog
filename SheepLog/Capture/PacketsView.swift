import AppKit
import Combine
import SwiftUI
import UniformTypeIdentifiers

/// The Packets pane: header with Start/Stop and file actions, the filter strip, the packet
/// table (AppKit, for 200k rows), and a resizable detail area (decode tree + hex dump).
struct PacketsView: View {
    @ObservedObject private var model = AppModel.shared
    @StateObject private var table = PacketTableController()
    @State private var interfaces: [CaptureInterface] = []
    /// Table share of the height; remembered across launches.
    @AppStorage("SheepLog.packetsSplit") private var storedSplit: Double = 0.6
    private var split: Binding<CGFloat> {
        Binding(get: { CGFloat(min(0.85, max(0.2, storedSplit))) }, set: { storedSplit = Double($0) })
    }

    var body: some View {
        VStack(spacing: 0) {
            PacketsHeader(interfaces: interfaces)
                .paneColumn()
                .padding(.top, Metrics.headerTop)
                .padding(.bottom, 12)
            PacketsStrip(interfaces: interfaces)
            // VSplitView ignores ideal heights and opens 50/50; this split opens 60/40 and keeps
            // the fraction the user drags to.
            PacketsSplit(fraction: split) {
                PacketsTableArea(controller: table)
                    .paneColumn()
                    .padding(.top, 12)
                    .padding(.bottom, 8)
            } bottom: {
                PacketDetailArea(controller: table)
                    .paneColumn()
                    .padding(.top, 8)
                    .padding(.bottom, 14)
            }
        }
        .paneKeyCommands(copy: { table.copySelectedRows() })
        .onAppear { PacketsDemo.run(table: table) }
        .task {
            // Off the main thread (pcap_findalldevs walks every interface), and again every few
            // seconds while the pane is open so a cable plugged in / a VPN coming up shows in the
            // picker without reopening the pane.
            LeakProbe.add("Packets.interfaceLoop")
            defer { LeakProbe.remove("Packets.interfaceLoop") }
            while !Task.isCancelled {
                let fresh = await Task.detached(priority: .utility) { CaptureEngine.interfaces(maxAge: 0) }.value
                if fresh != interfaces { interfaces = fresh }
                try? await Task.sleep(for: .seconds(5))
            }
        }
    }
}

/// A vertical split with a draggable hairline: `fraction` of the height on top (table ≥ 180 pt,
/// detail ≥ 150 pt).
private struct PacketsSplit<Top: View, Bottom: View>: View {
    @Binding var fraction: CGFloat
    @ViewBuilder var top: Top
    @ViewBuilder var bottom: Bottom
    @State private var dragStart: CGFloat?

    var body: some View {
        GeometryReader { geo in
            let h = geo.size.height
            let topH = min(max(180, h * fraction), max(180, h - 150 - 9))
            VStack(spacing: 0) {
                top.frame(height: topH)
                Rectangle()
                    .fill(Theme.hairline)
                    .frame(height: 1)
                    .padding(.vertical, 4)
                    .contentShape(Rectangle())
                    .onHover { inside in if inside { NSCursor.resizeUpDown.push() } else { NSCursor.pop() } }
                    .gesture(DragGesture(minimumDistance: 1)
                        .onChanged { g in
                            let start = dragStart ?? topH
                            if dragStart == nil { dragStart = topH }
                            fraction = min(max(180, start + g.translation.height), max(180, h - 159)) / max(1, h)
                        }
                        .onEnded { _ in dragStart = nil })
                bottom.frame(maxHeight: .infinity)
            }
        }
    }
}

// MARK: - Header

private struct PacketsHeader: View {
    @ObservedObject private var model = AppModel.shared
    @ObservedObject private var store = AppModel.shared.packets
    @ObservedObject private var capture = AppModel.shared.capture
    let interfaces: [CaptureInterface]

    var body: some View {
        PaneHeader(eyebrow: "Capture", heading: heading, subtitle: subtitle) {
            Button {
                if capture.isRunning { model.stopCapture() } else { model.startCapture() }
            } label: {
                Text(capture.isRunning ? "Stop" : "Start").frame(minWidth: 36)
            }
            .buttonStyle(.borderedProminent)
            .tint(Theme.accent)
            .keyboardShortcut("e", modifiers: .command)
            .help(capture.isRunning ? "Stop capturing (⌘E)" : "Start capturing on the chosen interface (⌘E)")
            Button("Open…") { PacketFileActions.open() }
                .buttonStyle(.bordered)
                .help("Open a .pcap or .pcapng file (⌘O)")
            Button(store.isSaving ? "Saving…" : "Save…") { PacketFileActions.save() }
                .buttonStyle(.bordered)
                .disabled(store.packets.isEmpty || store.isSaving)
                .help(store.query.isEmpty ? "Save every packet as .pcap" : "Save the filtered packets as .pcap")
            Button("Clear") { store.clear() }
                .buttonStyle(.bordered)
                .disabled(store.packets.isEmpty && store.fileURL == nil)
        }
    }

    private var heading: String {
        if capture.isRunning { return "Capturing on \(capture.interfaceName)." }
        if let url = store.fileURL {
            if store.isLoading {
                return store.totalReceived == 0 ? "Opening \(url.lastPathComponent)…"
                    : "Opening \(url.lastPathComponent)… \(Format.count(store.totalReceived)) packets read"
            }
            // The ring keeps the newest `limit` packets: say so, or the count reads as the file's.
            if store.totalReceived > store.packets.count {
                return "\(url.lastPathComponent) — showing the last \(Format.count(store.packets.count)) of \(Format.count(store.totalReceived)) packets."
            }
            return "\(url.lastPathComponent) — \(Format.count(store.totalReceived)) packets."
        }
        return "Not capturing."
    }

    private var subtitle: String {
        var parts = ["\(Format.count(store.packets.count)) packets", Format.bytes(store.totalBytes)]
        if capture.isRunning || store.rate > 0 { parts.append("\(Format.count(Int(store.rate.rounded()))) pkt/s") }
        parts.append("\(Format.count(store.lost)) dropped")
        if !store.query.isEmpty { parts.append("\(Format.count(store.visible.count)) shown") }
        if store.paused { parts.append("paused") }
        if store.isSaving {
            parts.append(store.query.isEmpty ? "saving \(Format.count(store.savingCount)) packets…"
                                             : "saving \(Format.count(store.savingCount)) filtered packets…")
        }
        if capture.isRunning, let w = capture.warning { parts.append(w) }
        var s = parts.joined(separator: " · ")
        let name = capture.isRunning ? capture.interfaceName : chosenInterface
        if store.fileURL == nil, let iface = interfaces.first(where: { $0.name == name }), !iface.addresses.isEmpty {
            s += " — \(iface.name) " + iface.addresses.prefix(3).joined(separator: ", ")
        }
        return s
    }

    private var chosenInterface: String {
        model.settings.captureInterface.isEmpty
            ? (interfaces.first { !$0.isLoopback && $0.isUp }?.name ?? "")
            : model.settings.captureInterface
    }
}

// MARK: - Strip

private struct PacketsStrip: View {
    @ObservedObject private var model = AppModel.shared
    @ObservedObject private var store = AppModel.shared.packets
    @ObservedObject private var capture = AppModel.shared.capture
    let interfaces: [CaptureInterface]
    @FocusState private var filterFocused: Bool

    var body: some View {
        PaneStrip {
            FilterField(text: $store.queryText, prompt: "proto:tcp port:443 OR ip:10.1.0.1 flags:syn",
                        error: store.queryError,
                        help: "Words search Info, addresses and protocol. Keys: ip: src: dst: port: sport: dport: proto: vlan: mac: len: frame: flags: sni: host: info: — with AND / OR / NOT / ( ). ⌘F to focus, Esc to clear",
                        focus: $filterFocused,
                        onSubmit: { store.applyQueryNow() },
                        onClear: { store.applyQueryNow() })
                .frame(minWidth: 220, maxWidth: .infinity)
            Button { store.paused.toggle() } label: {
                Text(store.paused ? "Resume" : "Pause").frame(minWidth: 46)     // no jump on Pause
            }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .help(store.paused ? "Show the packets that arrived while paused" : "Freeze the table; packets keep being received")
            Picker("Capture interface", selection: $model.settings.captureInterface) {
                Text("Automatic").tag("")
                if let extra = InterfacePicker.extraRow(selected: model.settings.captureInterface, among: interfaces) {
                    Text(extra).tag(model.settings.captureInterface)
                }
                ForEach(interfaces) { i in
                    Text(i.pickerTitle).tag(i.name)
                }
            }
            .labelsHidden()
            .controlSize(.small)
            .frame(width: 190)
            .disabled(capture.isRunning)
            .help("Interface to capture on")
            Toggle("Promiscuous", isOn: $model.settings.capturePromiscuous)
                .toggleStyle(.checkbox)
                .controlSize(.small)
                .disabled(capture.isRunning)
                .help("Required to see mirrored (SPAN) traffic that is not addressed to this Mac.")
            Button("TCP flows ›") { model.mainPane = .flows }
                .buttonStyle(.borderless)
                .controlSize(.small)
                .foregroundStyle(Theme.accent)
                .help("Analyse the packets in memory as TCP conversations — all of them, the filter here does not apply (⌘7)")
        }
        .paneKeyCommands(find: { filterFocused = true })
    }
}

// MARK: - Table area

struct PacketsTableArea: View {
    @ObservedObject private var store = AppModel.shared.packets
    @ObservedObject var controller: PacketTableController

    static func pausedText(_ waiting: Int) -> String {
        waiting == 0 ? "Paused. New packets are held until you press Resume."
                     : "Paused — \(Format.count(waiting)) \(waiting == 1 ? "packet is" : "packets are") waiting. Press Resume to show them."
    }

    static let emptyText = "No packets. Pick an interface and press Start, or open a .pcap. To see a switch’s mirror port, plug it into this Mac and keep Promiscuous on."

    var body: some View {
        VStack(spacing: 0) {
            table
            Rectangle().fill(Theme.hairlineSoft).frame(height: 0.5)
            PacketsFooter(controller: controller)
        }
        .tablePanel(minHeight: 120)
    }

    private var table: some View {
        ZStack(alignment: .bottom) {
            PacketTableView(controller: controller)
            if store.visible.isEmpty {
                TableEmptyOverlay(text: store.packets.isEmpty
                                  ? (store.isLoading ? "Reading…"
                                     : store.paused ? Self.pausedText(store.pausedCount) : Self.emptyText)
                                  : "No packets match the filter.")
                    .allowsHitTesting(false)
            }
            if controller.showJump {
                Button {
                    controller.jumpToLatest()
                } label: {
                    Label("Jump to latest", systemImage: "arrow.down")
                        .font(.system(size: 11.5, weight: .medium))
                }
                .buttonStyle(.bordered)
                .buttonBorderShape(.capsule)
                .controlSize(.small)
                .tint(Theme.accent)
                .shadow(color: .black.opacity(0.12), radius: 4, y: 1)
                .padding(.bottom, 12)
            } else if let error = store.queryError {
                // As on the Log: the field's red border alone did not say what is wrong, nor
                // that the table still shows the previous filter.
                let tint = store.queryErrorIsNotice ? Theme.caution : Theme.err
                Text(LogView.filterBanner(error, isNotice: store.queryErrorIsNotice))
                    .font(.system(size: 11.5, weight: .medium))
                    .foregroundStyle(tint)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(Capsule().fill(Theme.panel))
                    .overlay(Capsule().strokeBorder(tint.opacity(0.5), lineWidth: 0.5))
                    .shadow(color: .black.opacity(0.12), radius: 6, y: 2)
                    .padding(.bottom, 12)
                    .allowsHitTesting(false)
            }
        }
    }
}

/// "12,431 shown of 77,234 · 112 MB · capture.pcap" and the time format, under the table.
struct PacketsFooter: View {
    @ObservedObject private var store = AppModel.shared.packets
    @ObservedObject var controller: PacketTableController

    var body: some View {
        HStack(spacing: 8) {
            Text(PacketsFooter.text(shown: store.visible.count, inMemory: store.packets.count,
                                    received: store.totalReceived, bytes: store.totalBytes,
                                    filtered: !store.query.isEmpty, file: store.fileURL?.lastPathComponent,
                                    waiting: store.pausedCount))
                .font(.system(size: 11))
                .foregroundStyle(Theme.dimText)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: 8)
            Picker("Time", selection: $controller.absoluteTime) {
                Text("Relative").tag(false)
                Text("Time of day").tag(true)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .controlSize(.mini)
            .fixedSize()
            .help("Time column: seconds since the first packet, or the arrival time of day (HH:mm:ss.SSS)")
        }
        .padding(.horizontal, 10)
        .frame(height: 26)
    }

    nonisolated static func text(shown: Int, inMemory: Int, received: Int, bytes: Int, filtered: Bool, file: String?,
                                 waiting: Int = 0) -> String {
        var parts: [String] = []
        if filtered {
            parts.append("\(Format.count(shown)) shown of \(Format.count(inMemory))")
        } else {
            parts.append("\(Format.count(inMemory)) packets")
        }
        // Held back by Pause is not "rolled out": say it apart.
        if waiting > 0 { parts.append("\(Format.count(waiting)) waiting (paused)") }
        let arrived = received - waiting
        if arrived > inMemory { parts.append("the last \(Format.count(inMemory)) of \(Format.count(arrived)) kept") }
        parts.append(Format.bytes(bytes))
        parts.append(file ?? "live")
        return parts.joined(separator: " · ")
    }
}

// MARK: - Detail area

private struct PacketDetailArea: View {
    @ObservedObject var controller: PacketTableController

    var body: some View {
        HSplitView {
            VStack(alignment: .leading, spacing: 6) {
                Text("Decode").groupTitle().padding(.horizontal, 2)
                PacketDecodeTree(packet: controller.selected, linkType: AppModel.shared.packets.linkType)
                    .panelCard()
            }
            .frame(minWidth: 200, idealWidth: 460, maxWidth: .infinity)
            .padding(.trailing, 5)
            VStack(alignment: .leading, spacing: 6) {
                Text("Bytes").groupTitle().padding(.horizontal, 2)
                PacketHexView(packet: controller.selected)
                    .panelCard()
            }
            .frame(minWidth: 525, idealWidth: 560, maxWidth: .infinity)   // 16 bytes/line at 11.5 pt; fits the 1000 pt window
            .padding(.leading, 5)
        }
    }
}

// MARK: - Decode tree

nonisolated struct PacketDetailNode: Identifiable, Sendable {
    let id: String
    let title: String
    var children: [PacketDetailNode] = []
}

private struct PacketDecodeTree: View {
    let packet: Packet?
    let linkType: Int32
    /// Frame and Ethernet start folded (Wireshark habit) so IP / transport / application show.
    /// Keyed by layer ("ip", "tcp.flags"), not by packet: like Wireshark, what you opened stays
    /// open as you walk the packets; a node a packet does not have is simply not drawn.
    @State private var collapsed: Set<String> = ["frame", "eth", "ip.flags", "tcp.flags"]

    var body: some View {
        if let packet {
            ScrollView([.vertical, .horizontal]) {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(PacketDetailBuilder.tree(for: packet, linkType: linkType)) { node in
                        rows(node, depth: 0)
                    }
                }
                .padding(.vertical, 6)
                .padding(.horizontal, 8)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .id(packet.id)      // a new packet starts at the top, not where the last was scrolled
        } else {
            TableEmptyOverlay(text: "Select a packet to see its layers.")
        }
    }

    private func rows(_ node: PacketDetailNode, depth: Int) -> AnyView {
        let open = !collapsed.contains(node.id)
        return AnyView(
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 4) {
                    if node.children.isEmpty {
                        Color.clear.frame(width: 10, height: 10)
                    } else {
                        Image(systemName: open ? "chevron.down" : "chevron.right")
                            .font(.system(size: 8.5, weight: .bold))
                            .foregroundStyle(Theme.faintText)
                            .frame(width: 10)
                    }
                    Text(node.title)
                        .font(.system(size: 11.5, weight: depth == 0 ? .semibold : .regular, design: .monospaced))
                        .foregroundStyle(depth == 0 ? Theme.text : Theme.text2)
                        .lineLimit(1)
                        .fixedSize()
                        .textSelection(.enabled)
                }
                .padding(.leading, CGFloat(depth) * 16)
                .padding(.vertical, 2)
                .contentShape(Rectangle())
                .onTapGesture {
                    guard !node.children.isEmpty else { return }
                    if open { collapsed.insert(node.id) } else { collapsed.remove(node.id) }
                }
                if open {
                    ForEach(node.children) { child in rows(child, depth: depth + 1) }
                }
            }
        )
    }
}

/// Builds the decode tree (Frame / Ethernet / IP / transport / application) for one packet.
nonisolated enum PacketDetailBuilder {
    static func tree(for p: Packet, linkType: Int32) -> [PacketDetailNode] {
        let d = p.decoded
        var out: [PacketDetailNode] = []
        let stamp = Format.stamp.string(from: p.timestamp)
        out.append(PacketDetailNode(id: "frame", title: "Frame \(p.id): \(p.length) bytes on wire, \(p.captured) bytes captured", children: [
            leaf("frame.no", "Frame number: \(p.id)"),
            leaf("frame.time", "Arrival time: \(stamp)"),
            leaf("frame.rel", "Time since first frame: \(String(format: "%.6f", p.relative)) s"),
            leaf("frame.len", "Frame length: \(p.length) bytes"),
            leaf("frame.cap", "Capture length: \(p.captured) bytes"),
            leaf("frame.link", "Link type: \(linkName(linkType)) (\(linkType))"),
        ]))

        if !d.sourceMAC.isEmpty || !d.destinationMAC.isEmpty {
            var kids: [PacketDetailNode] = []
            if !d.destinationMAC.isEmpty { kids.append(leaf("eth.dst", "Destination: \(d.destinationMAC)\(macNote(d.destinationMAC))")) }
            if !d.sourceMAC.isEmpty { kids.append(leaf("eth.src", "Source: \(d.sourceMAC)")) }
            if let vlan = d.vlan { kids.append(leaf("eth.vlan", "802.1Q VLAN ID: \(vlan)")) }
            kids.append(leaf("eth.type", "Type: \(PacketNames.etherType(d.etherType) ?? "Unknown") (\(PacketFormat.hex4(d.etherType)))"))
            let title = linkType == 1 ? "Ethernet II, Src: \(d.sourceMAC), Dst: \(d.destinationMAC)" : "Link layer, Src: \(d.sourceMAC)"
            out.append(PacketDetailNode(id: "eth", title: title, children: kids))
        }

        if let ip = d.ip {
            var kids: [PacketDetailNode] = []
            let protoName = PacketNames.ipProto(ip.proto) ?? "Unknown"
            if ip.version == 4 {
                kids = [
                    leaf("ip.ver", "Version: 4"),
                    leaf("ip.hl", "Header length: \(ip.headerLength) bytes"),
                    leaf("ip.dscp", "DSCP: \(ip.dscp)\(dscpName(ip.dscp))"),
                    leaf("ip.len", "Total length: \(ip.totalLength)"),
                    leaf("ip.id", "Identification: \(PacketFormat.hex4(ip.identification)) (\(ip.identification))"),
                    PacketDetailNode(id: "ip.flags", title: "Flags: \(Self.ipFlagsTitle(df: ip.dontFragment, mf: ip.moreFragments))", children: [
                        leaf("ip.flags.df", "Don't fragment: \(ip.dontFragment ? "Set" : "Not set")"),
                        leaf("ip.flags.mf", "More fragments: \(ip.moreFragments ? "Set" : "Not set")"),
                    ]),
                    leaf("ip.frag", "Fragment offset: \(ip.fragmentOffset)"),
                    leaf("ip.ttl", "Time to live: \(ip.ttl)"),
                    leaf("ip.proto", "Protocol: \(protoName) (\(ip.proto))"),
                    leaf("ip.src", "Source address: \(ip.source)"),
                    leaf("ip.dst", "Destination address: \(ip.destination)"),
                ]
            } else {
                kids = [
                    leaf("ip.ver", "Version: 6"),
                    leaf("ip.dscp", "Traffic class DSCP: \(ip.dscp)\(dscpName(ip.dscp))"),
                    leaf("ip.len", "Payload length: \(ip.totalLength - 40)"),
                    leaf("ip.hl", "Header length (with extensions): \(ip.headerLength) bytes"),
                    leaf("ip.proto", "Next header (upper layer): \(protoName) (\(ip.proto))"),
                    leaf("ip.ttl", "Hop limit: \(ip.ttl)"),
                ]
                if ip.fragmentOffset > 0 || ip.moreFragments || ip.identification != 0 {
                    kids.append(leaf("ip.frag", "Fragment offset: \(ip.fragmentOffset), more fragments: \(ip.moreFragments ? "yes" : "no"), ID: \(ip.identification)"))
                }
                kids.append(leaf("ip.src", "Source address: \(ip.source)"))
                kids.append(leaf("ip.dst", "Destination address: \(ip.destination)"))
            }
            let title = "Internet Protocol Version \(ip.version), Src: \(ip.source), Dst: \(ip.destination)"
            out.append(PacketDetailNode(id: "ip", title: title, children: kids))
        }

        if let a = d.arp {
            out.append(PacketDetailNode(id: "arp", title: "\(d.protocolName == "RARP" ? "Reverse Address Resolution Protocol" : "Address Resolution Protocol") (\(a.isRequest ? "request" : "reply"))", children: [
                leaf("arp.op", "Opcode: \(Self.arpOpcode(isRequest: a.isRequest, rarp: d.protocolName == "RARP"))"),
                leaf("arp.smac", "Sender MAC address: \(a.senderMAC)"),
                leaf("arp.sip", "Sender IP address: \(a.senderIP)"),
                leaf("arp.tmac", "Target MAC address: \(a.targetMAC)"),
                leaf("arp.tip", "Target IP address: \(a.targetIP)"),
            ]))
        }

        if let t = d.tcp {
            var kids: [PacketDetailNode] = [
                leaf("tcp.sp", "Source port: \(t.sourcePort)"),
                leaf("tcp.dp", "Destination port: \(t.destinationPort)"),
                leaf("tcp.seq", "Sequence number: \(t.sequence)"),
                leaf("tcp.ack", "Acknowledgment number: \(t.acknowledgment)"),
                leaf("tcp.hl", "Header length: \(t.headerLength) bytes"),
            ]
            let names: [(TCPFlags, String)] = [(.cwr, "Congestion Window Reduced (CWR)"), (.ece, "ECN-Echo (ECE)"),
                                               (.urg, "Urgent (URG)"), (.ack, "Acknowledgment (ACK)"), (.psh, "Push (PSH)"),
                                               (.rst, "Reset (RST)"), (.syn, "Syn (SYN)"), (.fin, "Fin (FIN)")]
            kids.append(PacketDetailNode(id: "tcp.flags",
                                         title: "Flags: \(PacketFormat.hex(UInt64(t.flags.rawValue), digits: 3)) (\(t.flags.rawValue == 0 ? "none" : t.flags.label))",
                                         children: names.map { f, n in leaf("tcp.flags.\(f.rawValue)", "\(n): \(t.flags.contains(f) ? "Set" : "Not set")") }))
            kids.append(leaf("tcp.win", "Window: \(t.window)"))
            kids.append(leaf("tcp.len", "TCP payload: \(t.payloadLength) bytes"))
            var opts: [PacketDetailNode] = []
            if let mss = t.mss { opts.append(leaf("tcp.opt.mss", "Maximum segment size: \(mss) bytes")) }
            if let ws = t.windowScale { opts.append(leaf("tcp.opt.ws", "Window scale: \(ws) (multiply by \(1 << Int(min(ws, 14))))")) }
            if t.sackPermitted { opts.append(leaf("tcp.opt.sackp", "SACK permitted")) }
            if t.sackBlocks > 0 { opts.append(leaf("tcp.opt.sack", "SACK: \(t.sackBlocks) block\(t.sackBlocks == 1 ? "" : "s")")) }
            if let v = t.timestampValue, let e = t.timestampEcho { opts.append(leaf("tcp.opt.ts", "Timestamps: TSval \(v), TSecr \(e)")) }
            if !opts.isEmpty { kids.append(PacketDetailNode(id: "tcp.opts", title: "Options", children: opts)) }
            let title = "Transmission Control Protocol, Src Port: \(t.sourcePort), Dst Port: \(t.destinationPort), Seq: \(t.sequence)\(t.flags.contains(.ack) ? ", Ack: \(t.acknowledgment)" : ""), Len: \(t.payloadLength)"
            out.append(PacketDetailNode(id: "tcp", title: title, children: kids))
        }

        if let u = d.udp {
            out.append(PacketDetailNode(id: "udp", title: "User Datagram Protocol, Src Port: \(u.sourcePort), Dst Port: \(u.destinationPort)", children: [
                leaf("udp.sp", "Source port: \(u.sourcePort)"),
                leaf("udp.dp", "Destination port: \(u.destinationPort)"),
                leaf("udp.len", "Length: \(u.length)"),
                leaf("udp.pl", "UDP payload: \(u.payloadLength) bytes"),
            ]))
        }

        if let i = d.icmp {
            let v6 = d.ip?.version == 6
            var kids: [PacketDetailNode] = [
                leaf("icmp.type", "Type: \(i.type)"),
                leaf("icmp.code", "Code: \(i.code)"),
            ]
            if let id = i.identifier { kids.append(leaf("icmp.id", "Identifier: \(PacketFormat.hex4(id)) (\(id))")) }
            if let seq = i.sequence { kids.append(leaf("icmp.seq", "Sequence number: \(seq)")) }
            out.append(PacketDetailNode(id: "icmp", title: "\(v6 ? "Internet Control Message Protocol v6" : "Internet Control Message Protocol"): \(d.info)", children: kids))
        }

        if let app = d.app {
            out.append(PacketDetailNode(id: "app", title: appTitle(app), children: appFields(app)))
        } else if d.ip == nil, d.arp == nil, !d.protocolName.isEmpty {
            out.append(PacketDetailNode(id: "l2", title: d.protocolName, children: [leaf("l2.info", d.info)]))
        }
        return out
    }

    /// "Don't fragment", "More fragments", both, or "none".
    nonisolated static func ipFlagsTitle(df: Bool, mf: Bool) -> String {
        let set = [df ? "Don't fragment" : nil, mf ? "More fragments" : nil].compactMap { $0 }
        return set.isEmpty ? "none" : set.joined(separator: ", ")
    }

    /// ARP 1 / 2, RARP 3 / 4 (RFC 903).
    nonisolated static func arpOpcode(isRequest: Bool, rarp: Bool) -> String {
        isRequest ? (rarp ? "reverse request (3)" : "request (1)") : (rarp ? "reverse reply (4)" : "reply (2)")
    }

    private static func leaf(_ id: String, _ title: String) -> PacketDetailNode {
        PacketDetailNode(id: id, title: title)
    }

    private static func appTitle(_ a: AppLayer) -> String {
        switch a {
        case .httpRequest, .httpResponse: "Hypertext Transfer Protocol"
        case .tlsClientHello, .tlsServerHello, .tlsOther: "Transport Layer Security"
        case .dns: "Domain Name System"
        case .dhcp: "Dynamic Host Configuration Protocol"
        case .snmp: "Simple Network Management Protocol"
        case .syslog: "Syslog message"
        case .radius: "RADIUS Protocol"
        case .ntp: "Network Time Protocol"
        case .ssh: "SSH Protocol"
        case .other(let n): n
        }
    }

    private static func appFields(_ a: AppLayer) -> [PacketDetailNode] {
        switch a {
        case .httpRequest(let method, let path, let host):
            return [leaf("app.method", "Method: \(method)"), leaf("app.path", "Request URI: \(path)"),
                    leaf("app.host", "Host: \(host ?? "—")")]
        case .httpResponse(let status, let reason):
            return [leaf("app.status", "Status code: \(status)"), leaf("app.reason", "Reason: \(reason)")]
        case .tlsClientHello(let sni, let version):
            return [leaf("app.hs", "Handshake: Client Hello"), leaf("app.sni", "Server name (SNI): \(sni ?? "—")"),
                    leaf("app.ver", "Version: \(version)")]
        case .tlsServerHello(let version):
            return [leaf("app.hs", "Handshake: Server Hello"), leaf("app.ver", "Version: \(version)")]
        case .tlsOther(let record):
            return [leaf("app.rec", "Record: \(record)")]
        case .dns(let query, let isResponse, let answers, let rcode):
            return [leaf("app.qr", isResponse ? "Response" : "Query"), leaf("app.q", "Query name: \(query ?? "—")"),
                    leaf("app.an", "Answer RRs: \(answers)"),
                    leaf("app.rcode", "Reply code: \(PacketNames.dnsRcode(rcode)) (\(rcode))")]
        case .dhcp(let type, let mac, let yi):
            return [leaf("app.type", "Message type: \(type)"), leaf("app.mac", "Client MAC: \(mac ?? "—")"),
                    leaf("app.yi", "Your (client) IP: \(yi ?? "0.0.0.0")")]
        case .snmp(let version, let community, let pdu):
            return [leaf("app.ver", "Version: \(version)"), leaf("app.comm", "Community: \(community ?? "— (v3)")"),
                    leaf("app.pdu", "PDU: \(pdu)")]
        case .syslog(let pri, let preview):
            var kids: [PacketDetailNode] = []
            if let pri {
                let fac = pri >> 3
                let facility = fac < PacketNames.syslogFacilities.count ? PacketNames.syslogFacilities[fac] : "\(fac)"
                kids.append(leaf("app.pri", "Priority: <\(pri)> \(facility).\(PacketNames.syslogSeverities[pri & 7])"))
            }
            kids.append(leaf("app.msg", "Message: \(preview)"))
            return kids
        case .radius(let code, let id):
            return [leaf("app.code", "Code: \(code)"), leaf("app.id", "Packet identifier: \(id)")]
        case .ntp:
            return [leaf("app.ntp", "NTP")]
        case .ssh(let banner):
            return [leaf("app.banner", banner.map { "Protocol: \($0)" } ?? "Encrypted packet")]
        case .other(let name):
            return [leaf("app.name", name)]
        }
    }

    private static func linkName(_ lt: Int32) -> String {
        switch lt {
        case 0: "NULL/Loopback"
        case 1: "Ethernet"
        case 12, 14, 101: "Raw IP"
        case 108: "OpenBSD loopback"
        case 113: "Linux cooked"
        case 276: "Linux cooked v2"
        default: "DLT \(lt)"
        }
    }

    private static func macNote(_ mac: String) -> String {
        if mac == "ff:ff:ff:ff:ff:ff" { return " (broadcast)" }
        if let first = mac.split(separator: ":").first, let v = UInt8(first, radix: 16), v & 1 == 1 { return " (multicast)" }
        return ""
    }

    private static func dscpName(_ d: UInt8) -> String {
        switch d {
        case 0: " (CS0, best effort)"
        case 46: " (EF)"
        case 8, 16, 24, 32, 40, 48, 56: " (CS\(d / 8))"
        case 10, 12, 14, 18, 20, 22, 26, 28, 30, 34, 36, 38: " (AF\(d / 8)\((d % 8) / 2))"
        default: ""
        }
    }
}

// MARK: - Hex dump

struct PacketHexView: View {
    let packet: Packet?

    /// Lines per Text block: a 64 KB packet is 4,096 lines and a 256 KB one 16,384 — one giant
    /// Text laid that out on every selection (hundreds of ms); lazy 1 KB blocks cost what is seen.
    static let blockLines = 64

    var body: some View {
        if let packet {
            let blocks = (packet.data.count + Self.blockLines * 16 - 1) / (Self.blockLines * 16)
            ScrollView([.vertical, .horizontal]) {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(0..<max(1, blocks), id: \.self) { b in
                        Text(Self.dump(packet.data, lines: b * Self.blockLines..<(b + 1) * Self.blockLines))
                            .font(.system(size: 11.5, design: .monospaced))
                            .foregroundStyle(Theme.text2)
                            .textSelection(.enabled)
                            .fixedSize()
                    }
                }
                .padding(.vertical, 8)
                .padding(.horizontal, 10)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .id(packet.id)      // a new packet starts at its first byte
        } else {
            TableEmptyOverlay(text: "Select a packet to see its bytes.")
        }
    }

    /// 16 bytes per line: offset, hex (8 + 8), ASCII. The offset has 4 hex digits, more when the
    /// packet is longer than 64 KB (so offsets never wrap).
    nonisolated static func dump(_ data: Data) -> String {
        dump(data, lines: 0..<(data.count + 15) / 16)
    }

    nonisolated static func dump(_ data: Data, lines: Range<Int>) -> String {
        let hex = PacketFormat.hexChars
        var digits = 4
        while data.count - 1 >= 1 << (digits * 4), digits < 16 { digits += 1 }
        var out: [UInt8] = []
        out.reserveCapacity(lines.count * (digits + 70))
        data.withUnsafeBytes { raw in
            var off = max(0, lines.lowerBound) * 16
            let end = min(raw.count, lines.upperBound * 16)
            while off < end {
                let n = min(16, raw.count - off)
                for shift in stride(from: (digits - 1) * 4, through: 0, by: -4) { out.append(hex[(off >> shift) & 0xf]) }
                out.append(0x20); out.append(0x20)
                for i in 0..<16 {
                    if i == 8 { out.append(0x20) }
                    if i < n {
                        let v = raw[off + i]
                        out.append(hex[Int(v >> 4)]); out.append(hex[Int(v & 0xf)])
                    } else {
                        out.append(0x20); out.append(0x20)
                    }
                    out.append(0x20)
                }
                out.append(0x20)
                for i in 0..<n {
                    let v = raw[off + i]
                    out.append(v >= 0x20 && v < 0x7f ? v : 0x2e)
                }
                off += 16
                if off < end { out.append(0x0a) }
            }
        }
        return String(decoding: out, as: UTF8.self)
    }
}

// MARK: - Open / Save

@MainActor
enum PacketFileActions {
    static func open() {
        AppModel.shared.mainPane = .packets
        let panel = NSOpenPanel()
        panel.title = "Open Capture File"
        panel.message = "A .pcap, .pcapng or .cap file (tcpdump, Wireshark, switches)."
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        load(url)
    }

    static func load(_ url: URL) {
        if AppModel.shared.capture.isRunning { AppModel.shared.stopCapture() }
        do {
            try AppModel.shared.packets.load(from: url)
        } catch {
            AppModel.shared.report("Cannot open \(url.lastPathComponent).", detail: error.localizedDescription)
        }
    }

    /// `SheepLog-20260924-081530.pcap` — Gregorian digits whatever the Mac's calendar (a plain
    /// `DateFormatter` writes `SheepLog-25690924-…` on a Thai-calendar Mac).
    nonisolated static func saveName(date: Date) -> String {
        "SheepLog-\(Format.compactStamp.string(from: date)).pcap"
    }

    static func save() {
        let store = AppModel.shared.packets
        let panel = NSSavePanel()
        panel.title = store.query.isEmpty ? "Save Packets" : "Save Filtered Packets"
        let n = store.packetsToSave.count
        panel.message = store.query.isEmpty
            ? "Saves all \(Format.count(n)) packets in memory as a classic pcap file (tcpdump, Wireshark)."
            : "Saves the \(Format.count(n)) packets the filter shows (of \(Format.count(store.packets.count))) as a classic pcap file."
        panel.nameFieldStringValue = saveName(date: Date())
        panel.allowedContentTypes = [UTType(filenameExtension: "pcap") ?? .data]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        // 200k packets are ~100 MB of fwrite: off the main thread, with "Saving…" meanwhile.
        store.save(to: url) { error in
            if let error { AppModel.shared.report("Cannot save \(url.lastPathComponent).", detail: error) }
        }
    }
}

// MARK: - Demo hooks

/// `-demoCapture`, `-demoPcap`, `-demoFilter`, `-demoSelect` (DemoFlags), once per launch.
@MainActor
private enum PacketsDemo {
    static func run(table: PacketTableController) {
        guard DemoFlags.firstRun("packets") else { return }
        if DemoFlags.capture == "1" {
            if let iface = DemoFlags.interface {
                let s = AppModel.shared.settings
                AppModel.shared.capture.start(interface: iface, promiscuous: s.capturePromiscuous, bpfFilter: s.captureFilter)
            } else {
                AppModel.shared.startCapture()
            }
        }
        DemoFlags.openPcap()
        if let q = DemoFlags.filter {
            AppModel.shared.packets.queryText = q
            AppModel.shared.packets.applyQueryNow()
        }
        table.demoSelect = DemoFlags.select
    }
}

// MARK: - The AppKit table

/// Owns the NSTableView's data source / delegate, follows the store, keeps the selection by
/// frame id, and publishes what SwiftUI needs (selected packet, the Jump pill). The class holds
/// the following and scrolling; the extensions below are the data source, copying and menus.
@MainActor
final class PacketTableController: NSObject, ObservableObject {
    @Published private(set) var selected: Packet?
    @Published private(set) var showJump = false
    @Published var absoluteTime = false {
        didSet { tableView?.reloadData(); restoreSelection() }
    }

    weak var tableView: PacketNSTableView?
    var demoSelect: String?

    private let store = AppModel.shared.packets
    private var shownCount = 0
    private var shownGeneration = -1
    private var refreshScheduled = false
    private var atBottom = true
    private var selectedIDs: Set<Int> = []
    private var restoring = false
    private var subscriptions: Set<AnyCancellable> = []

    private static let monoFont = NSFont.monospacedSystemFont(ofSize: 11.5, weight: .regular)

    override init() {
        super.init()
        LeakProbe.add("PacketTableController")
    }

    deinit { LeakProbe.remove("PacketTableController") }

    enum Column: String, CaseIterable {
        case no, clock, time, src, dst, proto, len, vlan, info
        var title: String {
            switch self {
            case .no: "No."
            case .clock: "Time of day"
            case .time: "Relative"
            case .src: "Source"
            case .dst: "Destination"
            case .proto: "Protocol"
            case .len: "Length"
            case .vlan: "VLAN"
            case .info: "Info"
            }
        }
        var width: CGFloat {
            switch self {
            case .no: 70
            case .clock: 100
            case .time: 84
            case .src, .dst: 150
            case .proto: 72
            case .len: 60
            case .vlan: 48
            case .info: 420
            }
        }
        var rightAligned: Bool { self == .no || self == .len || self == .vlan }
    }

    func attach(_ tv: PacketNSTableView, scrollView: NSScrollView) {
        tableView = tv
        subscriptions.removeAll()
        store.objectWillChange
            .sink { [weak self] _ in self?.scheduleRefresh() }
            .store(in: &subscriptions)
        AppModel.shared.capture.objectWillChange
            .sink { [weak self] _ in self?.scheduleRefresh() }
            .store(in: &subscriptions)
        NotificationCenter.default.publisher(for: NSView.boundsDidChangeNotification, object: scrollView.contentView)
            .sink { [weak self] _ in self?.scrolled() }
            .store(in: &subscriptions)
        // The time-of-day cells were made in the old zone (travel, or the Mac's zone set by
        // location): redraw them in the new one.
        NotificationCenter.default.publisher(for: .NSSystemTimeZoneDidChange)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in self?.timeZoneChanged() }
            .store(in: &subscriptions)
        shownGeneration = -1
        refresh()
    }

    func timeZoneChanged() {
        NSTimeZone.resetSystemTimeZone()
        guard let tv = tableView else { return }
        let rows = tv.selectedRowIndexes
        restoring = true
        tv.reloadData()
        tv.selectRowIndexes(rows, byExtendingSelection: false)
        restoring = false
    }

    /// Tests stand in for a running capture.
    var liveOverride: Bool?
    private var isLive: Bool { liveOverride ?? AppModel.shared.capture.isRunning }

    /// `refresh()` now instead of on the next main-queue turn (tests).
    func refreshNow() {
        refreshScheduled = false
        refresh()
    }

    private func scheduleRefresh() {
        guard !refreshScheduled else { return }
        refreshScheduled = true
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.refreshScheduled = false
            self.refresh()
        }
    }

    private func refresh() {
        guard let tv = tableView else { return }
        let count = store.visible.count
        if store.generation != shownGeneration || count < shownCount {
            // The packet at the top of the view (recorded while the rows still matched the
            // store), to keep it there: the ring dropping its oldest 10 % (a long capture)
            // shifts every row up by thousands, and the rows being read must not scroll away.
            let anchor = self.anchor
            shownGeneration = store.generation
            shownCount = count
            tv.reloadData()
            restoreSelection()
            // After a Clear (or a filter with no match) the next packets follow the bottom again,
            // and "Jump to latest" is not offered for a table that was never scrolled away.
            if count == 0 { atBottom = true }
            if isLive, atBottom, !store.paused, count > 0 {
                scrollToRow(count - 1)
            } else if let anchor {
                restore(anchor)
            }
        } else if count > shownCount {
            shownCount = count
            tv.noteNumberOfRowsChanged()
            if isLive, atBottom, !store.paused { scrollToRow(count - 1) }
        }
        applyDemoSelection()
        updateJump()
        recordAnchor()
    }

    /// The first row in view: its packet id and how far its top is below the view's top.
    private var anchor: (id: Int, offset: CGFloat)?

    /// Only while the table's rows are the store's (same generation): after an eviction and
    /// before the reload, row N is another packet.
    private func recordAnchor() {
        guard let tv = tableView, let clip = tv.enclosingScrollView?.contentView, shownCount > 0,
              store.generation == shownGeneration else { anchor = nil; return }
        let row = tv.row(at: NSPoint(x: 1, y: clip.bounds.minY + 1))
        guard let p = packet(at: row) else { anchor = nil; return }
        anchor = (p.id, tv.rect(ofRow: row).minY - clip.bounds.minY)
    }

    private func restore(_ anchor: (id: Int, offset: CGFloat)) {
        guard let tv = tableView, let scroll = tv.enclosingScrollView else { return }
        let clip = scroll.contentView
        let row: Int
        if let i = store.visibleIndex(of: anchor.id), i < shownCount {
            row = i
        } else if let first = store.visible.first, first.id > anchor.id {
            row = 0                               // the anchor rolled out: the oldest left
        } else {
            return                                 // filtered out: the view stays where it was
        }
        let y = max(0, tv.rect(ofRow: row).minY - anchor.offset)
        clip.scroll(to: NSPoint(x: clip.bounds.minX, y: min(y, max(0, Self.rowsHeight(tv) - clip.bounds.height))))
        scroll.reflectScrolledClipView(clip)
    }

    private func scrolled() {
        guard let tv = tableView, let clip = tv.enclosingScrollView?.contentView else { return }
        atBottom = clip.bounds.maxY >= Self.rowsHeight(tv) - tv.rowHeight * 1.5
        updateJump()
        recordAnchor()
    }

    /// Where the last row ends. Not the table's frame: that is re-tiled lazily, and right after a
    /// reload it can still be the old height — after Clear, the first packets' scroll to the
    /// bottom then read as "scrolled away" (no following, "Jump to latest" shown).
    private static func rowsHeight(_ tv: NSTableView) -> CGFloat {
        tv.numberOfRows > 0 ? tv.rect(ofRow: tv.numberOfRows - 1).maxY : 0
    }

    private func updateJump() {
        let show = isLive && !atBottom && shownCount > 0
        if show != showJump { showJump = show }
    }

    func jumpToLatest() {
        guard tableView != nil, shownCount > 0 else { return }
        atBottom = true
        scrollToRow(shownCount - 1)
        updateJump()
    }

    private func restoreSelection() {
        guard let tv = tableView else { return }
        restoring = true
        defer { restoring = false }
        var rows = IndexSet()
        for id in selectedIDs {
            if let i = store.visibleIndex(of: id), i < shownCount { rows.insert(i) }
        }
        tv.selectRowIndexes(rows, byExtendingSelection: false)
        // Filtered out keeps the detail on the packet; gone from the ring (rolled out, Clear,
        // another file) clears it — it described a packet that no longer exists.
        if rows.isEmpty, let s = selected, !store.contains(id: s.id) {
            selectedIDs = []
            selected = nil
        }
    }

    private func applyDemoSelection() {
        guard let want = demoSelect, let tv = tableView, shownCount > 0 else { return }
        let v = store.visible
        var row: Int?
        if let id = Int(want) {
            row = store.visibleIndex(of: id)
        } else {
            row = v.prefix(shownCount).firstIndex {
                $0.decoded.protocolName.caseInsensitiveCompare(want) == .orderedSame
                    || $0.decoded.info.localizedCaseInsensitiveContains(want)
            }
        }
        guard let row else { return }
        demoSelect = nil
        tv.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
        scrollToRow(row)
    }

    /// Scroll only once the scroll view has a real size: a file's first batch lands within
    /// milliseconds of the pane appearing, before AppKit has laid the table out, and a scroll
    /// computed against a zero-height clip view is lost. Retries for up to 2 s.
    private func scrollToRow(_ row: Int, attempt: Int = 0) {
        guard let tv = tableView, let scroll = tv.enclosingScrollView else { return }
        if tv.window == nil || scroll.contentView.bounds.height < tv.rowHeight || scroll.needsLayout {
            guard attempt < 40 else { return }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) { [weak self] in
                self?.scrollToRow(row, attempt: attempt + 1)
            }
            return
        }
        guard row >= 0, row < tv.numberOfRows else { return }
        tv.scrollRowToVisible(row)
    }

    private func packet(at row: Int) -> Packet? {
        let v = store.visible
        return row >= 0 && row < v.count ? v[row] : nil
    }
}

// MARK: - Data source / delegate

extension PacketTableController: NSTableViewDataSource, NSTableViewDelegate {
    func numberOfRows(in tableView: NSTableView) -> Int { shownCount }

    /// New row views are faded in from alpha 0, and the fade only runs when the window draws: on
    /// an occluded window (a file opened behind another app, a -demoShot) the table would look
    /// empty until something forced a redraw. A packet list gains nothing from the fade.
    func tableView(_ tableView: NSTableView, rowViewForRow row: Int) -> NSTableRowView? {
        (tableView.makeView(withIdentifier: PacketRowView.identifier, owner: self) as? PacketRowView) ?? PacketRowView()
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard let tableColumn, let col = Column(rawValue: tableColumn.identifier.rawValue) else { return nil }
        let cell = (tableView.makeView(withIdentifier: tableColumn.identifier, owner: self) as? PacketCellView)
            ?? PacketCellView(identifier: tableColumn.identifier, rightAligned: col.rightAligned, font: Self.monoFont)
        guard let p = packet(at: row) else {
            cell.set("", color: .labelColor)
            return cell
        }
        let d = p.decoded
        switch col {
        case .no: cell.set(String(p.id), color: Self.dimColor)
        case .clock:
            // Wall-clock time of the frame; the full date is in the tooltip.
            cell.set(Format.clock.string(from: p.timestamp), color: Self.text2Color)
            cell.toolTip = Format.stamp.string(from: p.timestamp)
        case .time:
            cell.set(absoluteTime ? Format.clock.string(from: p.timestamp) : String(format: "%.6f", p.relative),
                     color: Self.dimColor)
        case .src: cell.set(d.source, color: Self.textColor)
        case .dst: cell.set(d.destination, color: Self.textColor)
        case .proto: cell.set(d.protocolName, color: Self.protocolColor(d))
        case .len: cell.set(String(p.length), color: Self.text2Color)
        case .vlan: cell.set(d.vlan.map { String($0) } ?? "", color: Self.text2Color)
        case .info: cell.set(d.info, color: Self.textColor)
        }
        return cell
    }

    // One NSColor each (bridging a SwiftUI Color per cell per row is the cell's main cost).
    private static let dimColor = NSColor(Theme.dimText)
    private static let textColor = NSColor(Theme.text)
    private static let text2Color = NSColor(Theme.text2)
    private static let errColor = NSColor(Theme.err)
    private static let warnColor = NSColor(Theme.warn)
    private static let accentColor = NSColor(Theme.accent)

    static func protocolColor(_ d: Decoded) -> NSColor {
        // The RST flag itself — not any Info containing the letters ("/FIRST", "BURST").
        if d.tcp?.flags.contains(.rst) == true { return errColor }
        if let i = d.icmp, (d.ip?.version == 4 && i.type == 3) || (d.ip?.version == 6 && i.type == 1) {
            return errColor
        }
        switch d.protocolName {
        case "TCP": return textColor
        case "UDP": return text2Color
        case "HTTP", "TLS": return accentColor
        case "DNS", "MDNS", "LLMNR", "DHCP", "DHCPv6", "ARP": return dimColor
        case "ICMP", "ICMPv6": return warnColor
        default: return text2Color
        }
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        guard !restoring, let tv = tableView else { return }
        let rows = tv.selectedRowIndexes
        let v = store.visible
        selectedIDs = Set(rows.compactMap { $0 < v.count ? v[$0].id : nil })
        let focus = tv.selectedRow
        let p = focus >= 0 && focus < v.count ? v[focus] : nil
        if p?.id != selected?.id || (p == nil) != (selected == nil) { selected = p }
    }
}

// MARK: - Copy and menus

extension PacketTableController: NSMenuDelegate {
    func copySelectedRows() {
        guard let tv = tableView else { return }
        let v = store.visible
        let columns = displayedColumns()
        let lines = tv.selectedRowIndexes.compactMap { $0 < v.count ? v[$0] : nil }
            .map { Self.rowText($0, columns: columns, absoluteTime: absoluteTime) }
        guard !lines.isEmpty else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(lines.joined(separator: "\n") + "\n", forType: .string)
    }

    /// The columns on screen, in the order the user arranged them (a copied row reads like the
    /// table: a hidden column is left out, a moved one moves).
    func displayedColumns() -> [Column] {
        guard let tv = tableView else { return Column.allCases }
        return tv.tableColumns.filter { !$0.isHidden }.compactMap { Column(rawValue: $0.identifier.rawValue) }
    }

    /// Every column, in the default order.
    static func rowText(_ p: Packet) -> String { rowText(p, columns: Column.allCases, absoluteTime: false) }

    /// Tab-separated, one field per column. Time of day is the full stamp (date and ms), as the
    /// cell's tooltip; Relative follows the column's own setting.
    static func rowText(_ p: Packet, columns: [Column], absoluteTime: Bool) -> String {
        let d = p.decoded
        return columns.map { col -> String in
            switch col {
            case .no: String(p.id)
            case .clock: Format.stamp.string(from: p.timestamp)
            case .time: absoluteTime ? Format.stamp.string(from: p.timestamp) : String(format: "%.6f", p.relative)
            case .src: d.source
            case .dst: d.destination
            case .proto: d.protocolName
            case .len: String(p.length)
            case .vlan: d.vlan.map { String($0) } ?? ""
            case .info: d.info
            }
        }.joined(separator: "\t")
    }

    @objc func toggleAbsoluteTime(_ sender: Any?) { absoluteTime.toggle() }

    /// Header menu: show or hide a column (Info always stays).
    @objc func toggleColumn(_ sender: Any?) {
        guard let raw = (sender as? NSMenuItem)?.representedObject as? String, let tv = tableView,
              let col = tv.tableColumn(withIdentifier: NSUserInterfaceItemIdentifier(raw)), raw != Column.info.rawValue else { return }
        col.isHidden.toggle()
        Self.saveHiddenColumns(tv)
    }

    private static let hiddenColumnsKey = "SheepLog.packets.hiddenColumns"

    /// Hidden columns are remembered (not by the tests, whose host is the app itself).
    static func saveHiddenColumns(_ tv: NSTableView) {
        guard !AppSettings.isRunningTests else { return }
        UserDefaults.standard.set(tv.tableColumns.filter(\.isHidden).map(\.identifier.rawValue), forKey: hiddenColumnsKey)
    }

    static func restoreHiddenColumns(_ tv: NSTableView) {
        guard !AppSettings.isRunningTests,
              let hidden = UserDefaults.standard.stringArray(forKey: hiddenColumnsKey) else { return }
        for c in tv.tableColumns where c.identifier.rawValue != Column.info.rawValue {
            c.isHidden = hidden.contains(c.identifier.rawValue)
        }
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        if menu.identifier == NSUserInterfaceItemIdentifier("header") { fillHeaderMenu(menu) } else { fillRowMenu(menu) }
    }

    /// Show or hide each column (Info always stays).
    private func fillHeaderMenu(_ menu: NSMenu) {
        for col in Column.allCases where col != .info {
            let item = NSMenuItem(title: col.title, action: #selector(toggleColumn(_:)), keyEquivalent: "")
            item.target = self
            item.representedObject = col.rawValue
            let shown = tableView?.tableColumn(withIdentifier: NSUserInterfaceItemIdentifier(col.rawValue))?.isHidden == false
            item.state = shown ? .on : .off
            menu.addItem(item)
        }
        menu.addItem(.separator())
        menu.addItem(timeOfDayItem())
    }

    /// Actions on the clicked packet.
    private func fillRowMenu(_ menu: NSMenu) {
        guard let tv = tableView, let p = packet(at: tv.clickedRow) else { return }
        func add(_ title: String, _ action: Selector, enabled: Bool = true) {
            let item = NSMenuItem(title: title, action: enabled ? action : nil, keyEquivalent: "")
            item.target = self
            item.representedObject = p.id
            item.isEnabled = enabled
            menu.addItem(item)
        }
        add("Copy info", #selector(copyInfo(_:)))
        add("Copy row", #selector(copyRow(_:)))
        menu.addItem(.separator())
        // A frame with no address (a truncated one, a loopback frame of another family) has
        // nothing to filter on: `src:` alone is the text "src:", which hid every packet.
        let src = p.decoded.source, dst = p.decoded.destination
        add(src.isEmpty ? "Filter this source" : "Filter this source (\(src))", #selector(filterSource(_:)), enabled: !src.isEmpty)
        add(dst.isEmpty ? "Filter this destination" : "Filter this destination (\(dst))", #selector(filterDestination(_:)),
            enabled: !dst.isEmpty)
        add("Filter this conversation", #selector(filterConversation(_:)), enabled: !src.isEmpty && !dst.isEmpty)
        menu.addItem(.separator())
        add("Show in TCP flows", #selector(followStream(_:)), enabled: p.decoded.tcp != nil)
        menu.addItem(.separator())
        menu.addItem(timeOfDayItem())
    }

    private func timeOfDayItem() -> NSMenuItem {
        let item = NSMenuItem(title: "Relative column shows time of day", action: #selector(toggleAbsoluteTime(_:)), keyEquivalent: "")
        item.target = self
        item.state = absoluteTime ? .on : .off
        return item
    }

    private func menuPacket(_ sender: Any?) -> Packet? {
        guard let id = (sender as? NSMenuItem)?.representedObject as? Int, let i = store.visibleIndex(of: id) else { return nil }
        return store.visible[i]
    }

    @objc func copyInfo(_ sender: Any?) {
        guard let p = menuPacket(sender) else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(p.decoded.info, forType: .string)
    }

    @objc func copyRow(_ sender: Any?) {
        guard let p = menuPacket(sender) else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(Self.rowText(p, columns: displayedColumns(), absoluteTime: absoluteTime), forType: .string)
    }

    private func setFilter(_ text: String) {
        store.queryText = text
        store.applyQueryNow()
    }

    @objc func filterSource(_ sender: Any?) {
        guard let p = menuPacket(sender) else { return }
        setFilter("src:\(p.decoded.source)")
    }

    @objc func filterDestination(_ sender: Any?) {
        guard let p = menuPacket(sender) else { return }
        setFilter("dst:\(p.decoded.destination)")
    }

    @objc func filterConversation(_ sender: Any?) {
        guard let p = menuPacket(sender) else { return }
        setFilter(Self.conversationFilter(p.decoded))
    }

    static func conversationFilter(_ d: Decoded) -> String {
        var s = "ip:\(d.source) ip:\(d.destination)"
        if let sp = d.sourcePort, let dp = d.destinationPort { s += " port:\(sp) port:\(dp)" }
        return s
    }

    @objc func followStream(_ sender: Any?) {
        guard let p = menuPacket(sender), let t = p.decoded.tcp, let ip = p.decoded.ip else { return }
        // The frame, not just the 4-tuple: a reused 4-tuple is several conversations, and the
        // Flows pane selects the one this frame belongs to (and the event that carries it).
        let request = FlowSelectRequest(key: FlowKey(ip.source, t.sourcePort, ip.destination, t.destinationPort, proto: 6),
                                        packetID: p.id)
        AppModel.shared.mainPane = .flows
        // AppModel keeps it until the Flows pane appears and takes it.
        NotificationCenter.default.post(name: .sheepLogSelectFlow, object: request)
    }

    /// Double-click a row: show only its conversation (Wireshark's "Conversation Filter").
    @objc func doubleClicked(_ sender: Any?) {
        guard let tv = tableView, let p = packet(at: tv.clickedRow),
              !p.decoded.source.isEmpty, !p.decoded.destination.isEmpty else { return }
        setFilter(Self.conversationFilter(p.decoded))
    }
}

/// ⌘C copies the selected rows.
final class PacketNSTableView: NSTableView {
    weak var controller: PacketTableController?

    @objc func copy(_ sender: Any?) { controller?.copySelectedRows() }

    override func validateUserInterfaceItem(_ item: any NSValidatedUserInterfaceItem) -> Bool {
        if item.action == #selector(copy(_:)) { return selectedRow >= 0 }
        return super.validateUserInterfaceItem(item)
    }

    override func keyDown(with event: NSEvent) {
        if event.modifierFlags.intersection(.deviceIndependentFlagsMask) == .command,
           event.charactersIgnoringModifiers == "c" {
            controller?.copySelectedRows()
            return
        }
        super.keyDown(with: event)
    }
}

/// A row view that is never transparent (see `tableView(_:rowViewForRow:)`).
final class PacketRowView: NSTableRowView {
    static let identifier = NSUserInterfaceItemIdentifier("packetRow")

    override init(frame: NSRect) {
        super.init(frame: frame)
        identifier = Self.identifier
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not used") }

    override var alphaValue: CGFloat {
        get { super.alphaValue }
        set { super.alphaValue = 1 }
    }
}

final class PacketCellView: NSTableCellView {
    private let label = NSTextField(labelWithString: "")

    init(identifier: NSUserInterfaceItemIdentifier, rightAligned: Bool, font: NSFont) {
        super.init(frame: .zero)
        self.identifier = identifier
        label.font = font
        label.lineBreakMode = .byTruncatingTail
        label.usesSingleLineMode = true
        label.cell?.truncatesLastVisibleLine = true
        label.alignment = rightAligned ? .right : .left
        label.translatesAutoresizingMaskIntoConstraints = false
        label.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        addSubview(label)
        textField = label
        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 4),
            label.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -4),
            label.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not used") }

    func set(_ text: String, color: NSColor) {
        if label.stringValue != text { label.stringValue = text }
        label.textColor = color
    }
}

struct PacketTableView: NSViewRepresentable {
    let controller: PacketTableController

    func makeNSView(context: Context) -> NSScrollView { Self.makeScrollView(controller: controller) }

    /// The scroll view, table, columns and menus, attached to `controller` (tests build it the
    /// same way).
    static func makeScrollView(controller: PacketTableController) -> NSScrollView {
        let tv = PacketNSTableView()
        tv.controller = controller
        tv.style = .plain
        tv.rowHeight = 22
        tv.usesAlternatingRowBackgroundColors = false
        tv.gridStyleMask = []
        tv.intercellSpacing = NSSize(width: 2, height: 0)
        tv.allowsMultipleSelection = true
        tv.allowsColumnReordering = true
        tv.allowsColumnResizing = true
        tv.columnAutoresizingStyle = .lastColumnOnlyAutoresizingStyle
        tv.backgroundColor = .clear
        tv.usesAutomaticRowHeights = false
        for col in PacketTableController.Column.allCases {
            let c = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(col.rawValue))
            c.title = col.title
            c.width = col.width
            c.minWidth = col == .info ? 120 : 32
            if col == .info { c.maxWidth = 100_000; c.resizingMask = .autoresizingMask } else { c.resizingMask = .userResizingMask }
            c.headerCell.alignment = col.rightAligned ? .right : .left
            tv.addTableColumn(c)
        }
        PacketTableController.restoreHiddenColumns(tv)
        let header = NSMenu()
        header.identifier = NSUserInterfaceItemIdentifier("header")
        header.delegate = controller
        tv.headerView?.menu = header
        let menu = NSMenu()
        menu.delegate = controller
        tv.menu = menu
        tv.dataSource = controller
        tv.delegate = controller
        tv.target = controller
        tv.doubleAction = #selector(PacketTableController.doubleClicked(_:))

        let scroll = NSScrollView()
        scroll.documentView = tv
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.autohidesScrollers = true
        scroll.drawsBackground = false
        scroll.borderType = .noBorder
        scroll.contentView.postsBoundsChangedNotifications = true
        controller.attach(tv, scrollView: scroll)
        return scroll
    }

    func updateNSView(_ nsView: NSScrollView, context: Context) {}
}

/// The capture-interface pickers (Packets and Settings): the chosen interface always has a row.
/// With none (the list still loading, or an adapter unplugged since) the picker showed a blank
/// title — SwiftUI: "the selection is invalid and does not have an associated tag".
nonisolated enum InterfacePicker {
    static func extraRow(selected: String, among interfaces: [CaptureInterface]) -> String? {
        guard !selected.isEmpty, !interfaces.contains(where: { $0.name == selected }) else { return nil }
        return interfaces.isEmpty ? selected : "\(selected) — not present (Automatic is used)"
    }
}
