import AppKit
import SwiftUI

@main
struct SheepLogApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .windowStyle(.hiddenTitleBar)
        .defaultSize(width: 1280, height: 820)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("Open Capture File…") { NotificationCenter.default.post(name: .sheepLogOpenPcap, object: nil) }
                    .keyboardShortcut("o", modifiers: .command)
                Button("Start Syslog Listener") { AppModel.shared.startSyslogIfStopped() }
                    .keyboardShortcut("l", modifiers: [.command, .shift])
                Button("Clear Log") { AppModel.shared.logs.clear() }
                    .keyboardShortcut("k", modifiers: .command)
            }
            CommandGroup(replacing: .appSettings) {
                Button("Settings…") { AppModel.shared.mainPane = .settings }
                    .keyboardShortcut(",", modifiers: .command)
            }
            // View ▸ the eight panes, in sidebar order, ⌘1 … ⌘8.
            CommandGroup(before: .toolbar) {
                ForEach(Array(PaneShortcut.all.enumerated()), id: \.offset) { i, item in
                    Button(item.title) { AppModel.shared.mainPane = item.pane }
                        .keyboardShortcut(PaneShortcut.key(at: i), modifiers: .command)
                }
                Divider()
            }
            CommandGroup(replacing: .help) { }
        }
    }
}

/// The View menu's pane list: sidebar order and sidebar words.
enum PaneShortcut {
    /// ⌘1 … ⌘9, then ⌘0 for the tenth pane; an eleventh would get no shortcut — a two-digit
    /// string is not a `Character`, and that crashed the app when the tenth pane arrived.
    static func key(at index: Int) -> KeyEquivalent {
        switch index {
        case 0..<9: KeyEquivalent(Character(String(index + 1)))
        case 9: "0"
        default: KeyEquivalent(Character(UnicodeScalar(0xF700 + UInt32(index))!))   // unassigned function-key range
        }
    }

    static let all: [(pane: MainPane, title: String)] = [
        (.status, "Status"), (.troubleshoot, "Troubleshoot"), (.log, "Log"), (.sources, "Sources"), (.snmpTest, "SNMP Test"),
        (.mibs, "MIBs"), (.packets, "Packets"), (.flows, "TCP Flows"), (.auth, "Authentication"), (.settings, "Settings"),
    ]
}

/// The last pane shown, restored at the next launch (not by demo runs or tests, which also
/// must not overwrite it: they share the installed app's defaults domain).
enum LastPane {
    static let key = "SheepLog.lastPane"

    static var isEphemeralRun: Bool {
        Chrome.isCapturing || CommandLine.value(after: "-demoSettings") != nil
            || CommandLine.value(after: "-demoPane") != nil
            || AppSettings.isRunningTests
    }

    static func restore() -> MainPane? {
        guard !isEphemeralRun else { return nil }
        return restore(from: .standard)
    }

    /// The pane the defaults name; nil for anything else stored under the key (a number, an
    /// array, a pane an older or newer build had).
    static func restore(from defaults: UserDefaults) -> MainPane? {
        guard let raw = defaults.object(forKey: key) as? String else { return nil }
        return MainPane(rawValue: raw)
    }

    static func save(_ pane: MainPane) {
        guard !isEphemeralRun else { return }
        UserDefaults.standard.set(pane.rawValue, forKey: key)
    }
}

/// Cross-pane requests. The panes that post these may use the string literals; the names must
/// stay identical. `object` types: openPcap nil · snmpTarget String ("host" or "host:port") ·
/// snmpOID String (dotted) · selectFlow FlowSelectRequest (key + frame; a bare FlowKey is accepted too) ·
/// packetFilter String (packet filter text).
/// The receiver of each exists before any pane does (CaptureEngine, SNMPTestModel, AppModel),
/// so a request posted together with the pane switch is never lost.
extension Notification.Name {
    static let sheepLogOpenPcap = Notification.Name("SheepLog.openPcap")
    static let sheepLogSNMPTarget = Notification.Name("SheepLog.snmpTarget")
    static let sheepLogSNMPOID = Notification.Name("SheepLog.snmpOID")
    static let sheepLogSelectFlow = Notification.Name("SheepLog.selectFlow")
    static let sheepLogPacketFilter = Notification.Name("SheepLog.packetFilter")
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    /// One window: View ▸ Show Tab Bar offered a "+" that opened a second SheepLog window on the
    /// same listeners and stores (and a second Flows analysis).
    func applicationWillFinishLaunching(_ notification: Notification) {
        NSWindow.allowsAutomaticWindowTabbing = false
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        if let raw = CommandLine.value(after: "-demoAppearance") {
            switch raw.lowercased() {
            case "dark": NSApp.appearance = NSAppearance(named: .darkAqua)
            case "light": NSApp.appearance = NSAppearance(named: .aqua)
            default: break
            }
        }
        // Before startup: whatever startup opens (a demo capture file, an SNMP target) wins.
        if let last = LastPane.restore() { AppModel.shared.mainPane = last }
        AppModel.shared.startup()
        if let p = CommandLine.value(after: "-demoPane"), let pane = MainPane(rawValue: p) { AppModel.shared.mainPane = pane }
        applyDemoWindowSize()
        captureDemoShot()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    func applicationWillTerminate(_ notification: Notification) {
        AppModel.shared.shutdownForQuit()
    }

    /// `-demoShot <path.png>` — draw the window to a PNG and quit (screenshots without Screen
    /// Recording permission; same mechanism as SheepRadius).
    private func captureDemoShot() {
        guard let path = CommandLine.value(after: "-demoShot") else { return }
        let seconds = CommandLine.value(after: "-demoShotDelay").flatMap(Double.init) ?? 2.5
        NSApp.activate(ignoringOtherApps: true)
        DispatchQueue.main.asyncAfter(deadline: .now() + seconds) {
            let hosting = NSApp.windows.first { $0.isVisible && $0.attachedSheet != nil }
            guard let window = hosting?.attachedSheet ?? NSApp.windows.first(where: { $0.isVisible }),
                  let view = window.contentView,
                  let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else {
                print("[shot] no window"); exit(1)
            }
            view.cacheDisplay(in: view.bounds, to: rep)
            guard let data = rep.representation(using: .png, properties: [:]) else { print("[shot] no png"); exit(1) }
            do {
                try data.write(to: URL(fileURLWithPath: path), options: .atomic)
                print("[shot] \(Int(view.bounds.width))x\(Int(view.bounds.height)) \(path)")
            } catch {
                print("[shot] \(error.localizedDescription)"); exit(1)
            }
            AppModel.shared.shutdownForQuit()
            exit(0)
        }
    }

    /// `-demoWindow 1280x820`
    private func applyDemoWindowSize() {
        guard let raw = CommandLine.value(after: "-demoWindow") else { return }
        let parts = raw.lowercased().split(separator: "x").compactMap { Double($0) }
        guard parts.count == 2, parts[0] >= 200, parts[1] >= 200 else { return }
        DispatchQueue.main.async {
            guard let window = NSApp.windows.first(where: { $0.isVisible }) else { return }
            window.setContentSize(NSSize(width: parts[0], height: parts[1]))
            window.setFrameOrigin(NSPoint(x: 40, y: 60))
        }
    }
}
