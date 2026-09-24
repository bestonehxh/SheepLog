import Foundation

/// What the Flows and Authentication panes last drew and how many analyses they started — for
/// tests that host the real views in a window and drive them (Debug only; the calls compile to
/// nothing in Release). Written from the views' bodies, so it is what reached the screen.
@MainActor
enum PaneProbe {
    /// The ladder side: the conversation / attempt shown, and the frames of the selected step.
    struct Ladder: Equatable, CustomStringConvertible {
        var id: Int
        /// The flow key's text, or the client MAC.
        var subject: String
        var firstFrame: Int
        /// The selected step's frames; nil when no step is selected.
        var eventFrames: [Int]?
        var description: String { "#\(id) \(subject) from frame \(firstFrame), step \(eventFrames.map { "\($0)" } ?? "none")" }
    }

    #if DEBUG
    private(set) static var flowsLadder: Ladder?
    private(set) static var flowAnalyses = 0
    private(set) static var authLadder: Ladder?
    private(set) static var authAnalyses = 0
    /// How many times the Authentication table's rows were filtered and sorted.
    private(set) static var authRowSorts = 0
    private(set) static var troubleshootAnalyses = 0
    #endif

    @inline(__always)
    static func drewFlow(_ flow: TCPFlow?, event: Int?) {
        #if DEBUG
        flowsLadder = flow.map { f in
            Ladder(id: f.id, subject: "\(f.clientEndpoint) → \(f.serverEndpoint)", firstFrame: f.firstPacketID,
                   eventFrames: event.flatMap { id in f.events.first { $0.id == id }?.packetIDs })
        }
        #endif
    }

    @inline(__always)
    static func drewAuth(_ session: AuthSession?, event: Int?) {
        #if DEBUG
        authLadder = session.map { s in
            Ladder(id: s.id, subject: s.client, firstFrame: s.firstPacketID,
                   eventFrames: event.flatMap { id in s.events.first { $0.id == id }?.packetIDs })
        }
        #endif
    }

    #if DEBUG
    private static var buttons: [String: (enabled: Bool, action: @MainActor () -> Void)] = [:]
    #endif

    /// A button as last drawn (`"flows.Show packets"`): its action — the same call the Button
    /// makes — and whether it was enabled. SwiftUI buttons are no NSButtons, and a unit-test host
    /// has no accessibility tree to press them through.
    @inline(__always)
    static func button(_ name: String, enabled: Bool = true, _ action: @escaping @MainActor () -> Void) {
        #if DEBUG
        buttons[name] = (enabled, action)
        #endif
    }

    /// Presses the button `name` as last drawn; false when it was not drawn or was disabled.
    @discardableResult
    static func press(_ name: String) -> Bool {
        #if DEBUG
        guard let b = buttons[name], b.enabled else { return false }
        b.action()
        return true
        #else
        return false
        #endif
    }

    #if DEBUG
    private static var taps: [String: @MainActor (CGPoint) -> Void] = [:]
    #endif

    /// A tap target as last drawn (`"auth.ladder"`): the same closure its `onTapGesture` runs,
    /// taking a point in the target's own coordinates.
    @inline(__always)
    static func tapTarget(_ name: String, _ action: @escaping @MainActor (CGPoint) -> Void) {
        #if DEBUG
        taps[name] = action
        #endif
    }

    /// Taps `name` at `point`; false when it was not drawn.
    @discardableResult
    static func tap(_ name: String, at point: CGPoint) -> Bool {
        #if DEBUG
        guard let t = taps[name] else { return false }
        t(point)
        return true
        #else
        return false
        #endif
    }

    /// Forgets the buttons (a test starting on a fresh view).
    static func reset() {
        #if DEBUG
        buttons = [:]
        taps = [:]
        flowsLadder = nil
        authLadder = nil
        #endif
    }

    @inline(__always)
    static func flowAnalysisStarted() {
        #if DEBUG
        flowAnalyses += 1
        #endif
    }

    @inline(__always)
    static func authRowsSorted() {
        #if DEBUG
        authRowSorts += 1
        #endif
    }

    #if DEBUG
    /// When each Troubleshoot analysis started (`Monotonic.now()`).
    private(set) static var troubleshootAnalysisTimes: [Double] = []
    #endif

    @inline(__always)
    static func troubleshootAnalysisStarted() {
        #if DEBUG
        troubleshootAnalyses += 1
        troubleshootAnalysisTimes.append(Monotonic.now())
        if troubleshootAnalysisTimes.count > 256 { troubleshootAnalysisTimes.removeFirst(128) }
        #endif
    }

    @inline(__always)
    static func authAnalysisStarted() {
        #if DEBUG
        authAnalyses += 1
        #endif
    }
}
