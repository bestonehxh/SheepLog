import AppKit
import SwiftUI

/// The family's "Quiet" look (LabDC, formerly SheepAuth — owner, 27 Sep 2026): simple, refined,
/// monochrome, no icons. Hierarchy comes from type size, weight and whitespace; state is written
/// as words; the only colour is a muted red for what went wrong. Warm ivory page / near-black in
/// dark mode, the sidebar one shade off the page. Every page takes its values from here.
enum Theme {
    // Surfaces
    /// The page ground.
    static let content = dynamic(light: 0xFBFAF7, dark: 0x141413)
    /// Cards are gone in Quiet: tables and lists sit flat on the page (the symbol stays for the
    /// call sites that asked for a panel ground).
    static let panel = dynamic(light: 0xFBFAF7, dark: 0x141413)
    static let sidebar = dynamic(light: 0xF3F1EC, dark: 0x1B1B1A)
    /// Inset fill for code and copyable values.
    static let well = dynamic(light: 0xF1EFEA, dark: 0x1E1E1D)

    // Text
    static let text = dynamic(light: 0x141414, dark: 0xF1F0EC)
    static let text2 = dynamic(light: 0x8A8984, dark: 0x7B7A76)
    static let dimText = dynamic(light: 0x8A8984, dark: 0x7B7A76)
    /// Darker than LabDC's own faint (0xA3A29C): it must hold 3:1 on the sidebar (round 6's
    /// contrast test), which the original misses at 2.27:1.
    static let faintText = dynamic(light: 0x888780, dark: 0x747376)

    // Lines / fills
    static let hairline = dynamic(light: 0xE6E4DE, dark: 0x262624)
    static let hairlineSoft = dynamic(light: 0xE6E4DE, dark: 0x262624)
    static let hover = dynamicAlpha(light: (0x141414, 0.04), dark: (0xF1F0EC, 0.05))
    /// Field borders and the inactive switch track.
    static let control = dynamic(light: 0xD9D7D0, dark: 0x3A3A38)
    /// The selected row of a table (with a 2 pt ink edge on the left).
    static let selectedAccent = dynamic(light: 0xEFEDE7, dark: 0x20201F)

    // Accent + status — Quiet has no accent hue: actions and selection are ink, state is words,
    // and the one colour is a muted red for what went wrong.
    static let accent = dynamic(light: 0x141414, dark: 0xF1F0EC)
    static let ok = dynamic(light: 0x8A8984, dark: 0x7B7A76)
    static let warn = dynamic(light: 0x9B3B2E, dark: 0xE08A7C)
    /// The one warning colour: what went wrong, destructive actions.
    static let err = dynamic(light: 0x9B3B2E, dark: 0xE08A7C)
    /// A warning-severity line is not "wrong" yet: it reads as plain ink, the word WARN carries it.
    static let caution = dynamic(light: 0x8A8984, dark: 0x7B7A76)
    static let live = dynamic(light: 0x8A8984, dark: 0x7B7A76)

    /// Severity tints for the log grid: only real problems carry colour (the words carry the rest).
    static func severityTint(_ s: Severity) -> Color? {
        switch s {
        case .emergency, .alert, .critical, .error: return err
        case .warning: return nil
        default: return nil
        }
    }

    /// Quiet reads vendors as words, not hues: one muted tone for every vendor (the dots that
    /// used the hue are gone from the panes).
    static func vendorColor(_ v: Vendor) -> Color {
        dynamic(light: 0x8A8984, dark: 0x7B7A76)
    }

    // MARK: Type (the Quiet scale: 28 title · 20 name · 13 body · 11 labels)

    static let pageTitle = Font.system(size: 28, weight: .light)
    static let subtitle = Font.system(size: 20, weight: .regular)
    /// The Overview numbers.
    static let metric = Font.system(size: 30, weight: .regular).monospacedDigit()
    /// Row titles, section titles.
    static let emphasis = Font.system(size: 13, weight: .semibold)
    static let body = Font.system(size: 13)
    static let detail = Font.system(size: 12)
    static let caption = Font.system(size: 11)
    static let mono = Font.system(size: 12, design: .monospaced)

    static func dynamic(light: UInt32, dark: UInt32) -> Color {
        Color(nsColor: nsDynamic(light: light, dark: dark))
    }

    static func nsDynamic(light: UInt32, dark: UInt32) -> NSColor {
        NSColor(name: nil) { appearance in
            let isDark = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            return nsColor(isDark ? dark : light)
        }
    }

    /// The selected-row tint as an `NSColor`, for the AppKit tables (Log, Packets): Quiet's
    /// selected row — a quiet fill, drawn with its 2 pt ink edge by `SoftSelectionRowView`.
    static let nsSelectedAccent = nsDynamic(light: 0xEFEDE7, dark: 0x20201F)
    /// The ink for the selection's left edge, as an `NSColor`.
    static let nsText = nsDynamic(light: 0x141414, dark: 0xF1F0EC)
    /// The page ground, as an `NSColor` (the AppKit tables draw their own background).
    static let nsContent = nsDynamic(light: 0xFBFAF7, dark: 0x141413)
    static let nsMuted = nsDynamic(light: 0x8A8984, dark: 0x7B7A76)
    static let nsFaint = nsDynamic(light: 0x888780, dark: 0x747376)
    static let nsErr = nsDynamic(light: 0x9B3B2E, dark: 0xE08A7C)

    static func nsDynamicAlpha(light: (UInt32, CGFloat), dark: (UInt32, CGFloat)) -> NSColor {
        NSColor(name: nil) { appearance in
            let isDark = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            let pick = isDark ? dark : light
            return nsColor(pick.0).withAlphaComponent(pick.1)
        }
    }

    static func dynamicAlpha(light: (UInt32, CGFloat), dark: (UInt32, CGFloat)) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            let isDark = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            let pick = isDark ? dark : light
            return nsColor(pick.0).withAlphaComponent(pick.1)
        })
    }

    static func nsColor(_ hex: UInt32) -> NSColor {
        NSColor(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255,
                green: CGFloat((hex >> 8) & 0xFF) / 255,
                blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
    }
}

enum Metrics {
    static let card: CGFloat = 8
    static let field: CGFloat = 8
    static let row: CGFloat = 6
    static let key: CGFloat = 200
    static let control: CGFloat = 260
    static let numberField: CGFloat = 90
    static let prose: CGFloat = 560
    /// 30 pt (SheepRadius build 32): the traffic lights end ~26 pt down, both columns level.
    static let titleBar: CGFloat = 30
    /// Above a pane's first line, under the band — same on every pane.
    static let headerTop: CGFloat = 10
    static let titleBarFullScreen: CGFloat = 12
    static let sidebar: CGFloat = 220
    static let minimumWindow: CGFloat = 1000
}

/// Behind-window vibrancy — kept for the shell's material, unused by the Quiet surfaces (flat
/// colours only).
struct VisualEffectBackground: NSViewRepresentable {
    let material: NSVisualEffectView.Material

    func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = material
        view.blendingMode = .behindWindow
        view.state = .followsWindowActiveState
        return view
    }

    func updateNSView(_ nsView: NSVisualEffectView, context: Context) {
        nsView.material = material
    }
}

/// The pane column: everything except two gutters that grow with the pane.
nonisolated enum PaneColumn {
    // LabDC's page insets are 48 pt; a narrow window gives some of it back to the tables.
    static let gutterFraction: CGFloat = 0.04
    static let minGutter: CGFloat = 32
    static let maxGutter: CGFloat = 48

    static func gutter(available: CGFloat) -> CGFloat {
        guard available > 0 else { return minGutter }
        return min(maxGutter, max(minGutter, available * gutterFraction))
    }
}
