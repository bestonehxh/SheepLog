import AppKit
import Combine
import SwiftUI

/// Every address that has sent a line, with its counters and a per-source vendor override.
struct SourcesView: View {
    @ObservedObject private var model = AppModel.shared
    @ObservedObject private var store = AppModel.shared.logs
    @State private var sortOrder = [KeyPathComparator(\SourceStats.count, order: .reverse)]
    @State private var selection: SourceStats.ID?

    private var rows: [SourceStats] { store.sources.sorted(using: sortOrder) }

    var body: some View {
        VStack(spacing: 0) {
            PaneHeader(eyebrow: "Syslog", heading: heading, subtitle: subtitle)
                .paneColumn()
                .padding(.top, Metrics.headerTop)
                .padding(.bottom, 12)

            ZStack {
                table
                if store.sources.isEmpty {
                    TableEmptyOverlay(text: "No devices yet. Point a device’s syslog at this Mac and it appears here with its vendor, line count and last-seen time.")
                        .allowsHitTesting(false)
                }
            }
            .tablePanel()
            .paneColumn()
            .padding(.vertical, 16)
        }
    }

    private var heading: String {
        switch store.sources.count {
        case 0: "No devices are talking yet."
        case 1: "1 device is talking."
        default: "\(store.sources.count) devices are talking."
        }
    }

    private var subtitle: String {
        "Every address that has sent a line since launch. When a vendor is detected wrongly, pick the right one and that source’s lines are parsed again."
    }

    private var table: some View {
        // Show is in the Hostname cell, the context menu and double-click — a trailing column
        // of its own is pushed off-screen with Last seen in a narrow window. Vendor is the
        // column that gives way.
        Table(rows, selection: $selection, sortOrder: $sortOrder) {
            TableColumn("Hostname", value: \SourceStats.displayName) { s in
                HStack(spacing: 7) {
                    Circle().fill(Theme.vendorColor(s.vendor)).frame(width: 7, height: 7)
                        .accessibilityHidden(true)
                    Text(s.displayName).identifierText()
                    Spacer(minLength: 4)
                    Button { show(s.address) } label: {
                        Image(systemName: "arrow.right.circle").font(.system(size: 12))
                    }
                    .buttonStyle(.borderless)
                    .foregroundStyle(Theme.dimText)
                    .help("Show this source’s lines")
                    .accessibilityLabel("Show \(s.displayName)’s lines")
                }
            }
            .width(min: 110, ideal: 140, max: 260)

            TableColumn("Address", value: \SourceStats.address) { s in
                Text(s.address)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(Theme.text2)
                    .identifierText()
            }
            .width(min: 84, ideal: 100, max: 180)

            TableColumn("Vendor", value: \SourceStats.vendorLabel) { s in
                VendorOverridePicker(source: s, detected: store.detectedVendor(for: s.address))
            }
            .width(min: 100, ideal: 116)

            TableColumn("Lines", value: \SourceStats.count) { s in
                Text(Format.count(s.count)).monospacedDigit()
            }
            .width(58)

            TableColumn("Errors", value: \SourceStats.errorCount) { s in
                Text(Format.count(s.errorCount)).monospacedDigit()
                    .foregroundStyle(s.errorCount > 0 ? Theme.err : Theme.faintText)
            }
            .width(50)

            TableColumn("Warnings", value: \SourceStats.warningCount) { s in
                Text(Format.count(s.warningCount)).monospacedDigit()
                    .foregroundStyle(s.warningCount > 0 ? Theme.caution : Theme.faintText)
            }
            .width(64)

            TableColumn("Last seen", value: \SourceStats.lastSeen) { s in
                TimelineView(.periodic(from: .now, by: 1)) { ctx in
                    Text(SourcesView.relative(s.lastSeen, now: ctx.date))
                        .monospacedDigit()
                        .foregroundStyle(Theme.text2)
                }
            }
            .width(70)
        }
        .contextMenu(forSelectionType: SourceStats.ID.self) { ids in
            if let s = store.sources.first(where: { ids.contains($0.id) }), ids.count == 1 {
                Button("Show this source’s lines") { show(s.address) }
                Button("Copy address") { copy(s.address) }
                if !s.hostname.isEmpty { Button("Copy hostname") { copy(s.hostname) } }
            }
        } primaryAction: { ids in
            if let s = store.sources.first(where: { ids.contains($0.id) }) { show(s.address) }
        }
        .tableStyle(.inset(alternatesRowBackgrounds: false))
        .scrollContentBackground(.hidden)
    }

    private func show(_ address: String) {
        store.showSource(address)       // also clears a query that would hide them
        model.mainPane = .log
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    static func relative(_ date: Date, now: Date) -> String {
        let s = max(0, Int(now.timeIntervalSince(date)))
        if s < 1 { return "now" }
        if s < 60 { return "\(s) s ago" }
        if s < 3600 { return "\(s / 60) min ago" }
        if s < 86_400 { return "\(s / 3600) h ago" }
        return "\(s / 86_400) d ago"
    }
}

/// "Auto (detected: X)" or a forced vendor; writes through `AppModel.setVendorOverride`.
struct VendorOverridePicker: View {
    /// The syslog formats a source can be forced to (and the one in force, if it is not one).
    static func choices(current: Vendor?) -> [Vendor] {
        Vendor.allCases.filter { $0 != .snmpTrap || $0 == current }
    }

    let source: SourceStats
    let detected: Vendor

    var body: some View {
        Picker("Vendor", selection: Binding<Vendor?>(
            get: { source.vendorOverride },
            set: { AppModel.shared.setVendorOverride($0, for: source.address) })) {
            // The short name: "Auto (detected: Palo Alto PAN-OS)" is cut to "Auto (detected:
            // Palo Alto PA…" in the column, hiding the part that matters.
            Text("Auto · \(detected == .unknown ? "Other" : detected.shortLabel)")
                .help("Detected automatically: \(detected.label)")
                .tag(Vendor?.none)
            Divider()
            // "SNMP trap" is how traps arrive, not a syslog format a source can be parsed as
            // (forced on a syslog source it stripped every field); one set earlier still shows.
            ForEach(VendorOverridePicker.choices(current: source.vendorOverride), id: \.self) { v in
                Text(v.label).tag(Vendor?.some(v))
            }
        }
        .labelsHidden()
        .pickerStyle(.menu)
        .controlSize(.small)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

extension SourceStats {
    /// emergency … error.
    nonisolated var errorCount: Int { bySeverity.prefix(4).reduce(0, +) }
    nonisolated var warningCount: Int { bySeverity.count > 4 ? bySeverity[4] : 0 }
    nonisolated var vendorLabel: String { (vendorOverride ?? vendor).label }
}
