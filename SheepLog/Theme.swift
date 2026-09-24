import AppKit
import SwiftUI

/// Sheep-family tokens, lifted from SheepRadius / SheepDrop (design v2) so the apps read as
/// siblings. Only the accent differs per app: SheepLog is plum (icon tile #B8407E → #933265).
enum Theme {
    // Surfaces
    static let content = dynamic(light: 0xF7F7F8, dark: 0x232326)
    static let panel = dynamic(light: 0xFFFFFF, dark: 0x2A2A2E)
    static let sidebar = dynamic(light: 0xF6F6F8, dark: 0x2C2C2E)
    static let well = dynamicAlpha(light: (0x000000, 0.045), dark: (0xFFFFFF, 0.08))

    // Text
    static let text = dynamic(light: 0x1D1D1F, dark: 0xF5F5F7)
    static let text2 = dynamic(light: 0x3A3A3C, dark: 0xD1D1D6)
    static let dimText = dynamic(light: 0x6E6E73, dark: 0xAEAEB2)
    static let faintText = dynamic(light: 0x86868B, dark: 0x8E8E93)

    // Lines / fills
    static let hairline = dynamicAlpha(light: (0x000000, 0.10), dark: (0xFFFFFF, 0.14))
    static let hairlineSoft = dynamicAlpha(light: (0x000000, 0.07), dark: (0xFFFFFF, 0.10))
    static let hover = dynamicAlpha(light: (0x000000, 0.04), dark: (0xFFFFFF, 0.07))
    static let control = dynamicAlpha(light: (0x000000, 0.055), dark: (0xFFFFFF, 0.12))
    static let selectedAccent = dynamicAlpha(light: (0xB8407E, 0.13), dark: (0xE87AAD, 0.18))

    // Accent + status
    static let accent = dynamic(light: 0xB8407E, dark: 0xE87AAD)
    /// Light 0x2A9662, not the family's 0x30A46C: "Listening" / "udp 514" in it measured 2.95:1
    /// on the content ground (2.92:1 on the sidebar); this is ≥ 3.4:1, the same green.
    static let ok = dynamic(light: 0x2A9662, dark: 0x4ED48A)
    static let warn = dynamic(light: 0xB8451F, dark: 0xFF8A5C)
    static let err = dynamic(light: 0xB8451F, dark: 0xFF8A5C)
    /// Amber for a *warning-severity* line — distinct from `warn`/`err` (the family's orange-red) so
    /// a WARN pill and an ERR pill can be told apart in a column of them.
    static let caution = dynamic(light: 0xA85B00, dark: 0xF0A030)
    static let live = dynamic(light: 0x30D158, dark: 0x30D158)

    /// Severity tints for the log grid: only problems carry colour.
    static func severityTint(_ s: Severity) -> Color? {
        switch s {
        case .emergency, .alert, .critical, .error: return err
        case .warning: return caution
        default: return nil
        }
    }

    /// One hue per vendor, used only on the dot and the vendor column.
    static func vendorColor(_ v: Vendor) -> Color {
        switch v {
        case .arubaCX, .arubaOS, .arubaSwitch, .clearPass: return dynamic(light: 0xE0562A, dark: 0xF07A52)
        case .huawei: return dynamic(light: 0xCF0A2C, dark: 0xF04A64)
        case .checkPoint: return dynamic(light: 0xE8318A, dark: 0xF56AAE)
        case .paloAlto: return dynamic(light: 0xFA582D, dark: 0xFF8A5C)
        case .fortigate: return dynamic(light: 0xC4232B, dark: 0xF05A62)
        case .snmpTrap: return dynamic(light: 0x5B7BD5, dark: 0x8FA8F0)
        case .unknown: return dynamic(light: 0x8E8E93, dark: 0x8E8E93)
        }
    }

    static func dynamic(light: UInt32, dark: UInt32) -> Color {
        Color(nsColor: nsDynamic(light: light, dark: dark))
    }

    static func nsDynamic(light: UInt32, dark: UInt32) -> NSColor {
        NSColor(name: nil) { appearance in
            let isDark = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            return nsColor(isDark ? dark : light)
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
    static let card: CGFloat = 10
    static let field: CGFloat = 8
    static let row: CGFloat = 6
    static let key: CGFloat = 200
    static let control: CGFloat = 260
    static let numberField: CGFloat = 90
    static let prose: CGFloat = 560
    /// 30 pt (SheepRadius build 32): the traffic lights end ~26 pt down, both columns level.
    static let titleBar: CGFloat = 30
    /// Above a pane's first line, under the band — same on every pane.
    static let headerTop: CGFloat = 2
    static let titleBarFullScreen: CGFloat = 12
    static let sidebar: CGFloat = 212
    static let minimumWindow: CGFloat = 1000
}

/// Behind-window vibrancy — the standard macOS sidebar material.
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
    static let gutterFraction: CGFloat = 0.03
    static let minGutter: CGFloat = 20
    static let maxGutter: CGFloat = 96

    static func gutter(available: CGFloat) -> CGFloat {
        guard available > 0 else { return minGutter }
        return min(maxGutter, max(minGutter, available * gutterFraction))
    }
}
