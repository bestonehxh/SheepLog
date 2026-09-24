import AppKit
import SwiftUI

enum Chrome {
    static let isCapturing = CommandLine.value(after: "-demoShot") != nil
}

/// Family shell (SheepRadius build 18+): a fixed 212 pt vibrant sidebar that owns the
/// traffic-light row, and a solid main column showing the selected pane.
struct ContentView: View {
    @ObservedObject private var model = AppModel.shared
    @Environment(\.controlActiveState) private var controlActiveState

    var body: some View {
        HStack(spacing: 0) {
            SidebarView()
                .frame(width: Metrics.sidebar)
            Rectangle()
                .fill(Theme.hairline)
                .frame(width: 0.5)
            VStack(spacing: 0) {
                Color.clear
                    .frame(height: model.isFullScreen ? Metrics.titleBarFullScreen : Metrics.titleBar)
                mainColumn
            }
            .background(Theme.content)
        }
        .background {
            if Chrome.isCapturing {
                Theme.sidebar.ignoresSafeArea()
            } else {
                VisualEffectBackground(material: .sidebar).ignoresSafeArea()
            }
        }
        .frame(minWidth: Metrics.minimumWindow, minHeight: 640)
        .modifier(FullscreenSync())
        .ignoresSafeArea(.container, edges: .top)
        .sheet(isPresented: errorBinding) {
            ErrorSheet(message: model.lastError ?? "", detail: model.lastErrorDetail) {
                model.clearError()
            }
        }
        .environment(\.controlActiveState, Chrome.isCapturing ? .key : controlActiveState)
        .onChange(of: model.mainPane) { _, pane in LastPane.save(pane) }
    }

    private var errorBinding: Binding<Bool> {
        // The test host keeps `lastError` for assertions but never shows the sheet.
        Binding(get: { model.lastError != nil && !AppSettings.isRunningTests }, set: { if !$0 { model.clearError() } })
    }

    @ViewBuilder
    private var mainColumn: some View {
        switch model.mainPane {
        case .status: StatusView()
        case .troubleshoot: TroubleshootView()
        case .log: LogView()
        case .sources: SourcesView()
        case .snmpTest: SNMPTestView()
        case .mibs: MIBsView()
        case .packets: PacketsView()
        case .flows: FlowView()
        case .auth: AuthView()
        case .settings: SettingsView()
        }
    }
}

/// Fullscreen tracking for the traffic-light spacer (SheepTerm / SheepRadius shape).
struct FullscreenSync: ViewModifier {
    @ObservedObject private var model = AppModel.shared

    func body(content: Content) -> some View {
        content
            .onAppear {
                model.isFullScreen = NSApp.keyWindow?.styleMask.contains(.fullScreen) ?? false
            }
            .onReceive(NotificationCenter.default.publisher(for: NSWindow.willEnterFullScreenNotification)) { _ in set(true) }
            .onReceive(NotificationCenter.default.publisher(for: NSWindow.willExitFullScreenNotification)) { _ in set(false) }
            .onReceive(NotificationCenter.default.publisher(for: NSWindow.didEnterFullScreenNotification)) { _ in set(true) }
            .onReceive(NotificationCenter.default.publisher(for: NSWindow.didExitFullScreenNotification)) { _ in set(false) }
    }

    private func set(_ fullscreen: Bool) {
        guard model.isFullScreen != fullscreen else { return }
        var transaction = Transaction()
        transaction.disablesAnimations = true
        withTransaction(transaction) { model.isFullScreen = fullscreen }
    }
}
