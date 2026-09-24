import Foundation

/// Live-instance counters for what a pane creates each time it appears (table coordinators,
/// controllers, refresh loops, analyses). Debug builds only; `PaneSwitchLeakTests` switches
/// panes a few hundred times and checks that every count comes back to where it started.
/// Release builds compile the calls away.
nonisolated enum LeakProbe {
    #if DEBUG
    private static let lock = NSLock()
    nonisolated(unsafe) private static var counts: [String: Int] = [:]
    #endif

    @inline(__always)
    static func add(_ name: String, _ delta: Int = 1) {
        #if DEBUG
        lock.lock(); counts[name, default: 0] += delta; lock.unlock()
        #endif
    }

    @inline(__always)
    static func remove(_ name: String) { add(name, -1) }

    /// Every counter (Debug); empty in Release.
    static var snapshot: [String: Int] {
        #if DEBUG
        lock.lock(); defer { lock.unlock() }
        return counts
        #else
        return [:]
        #endif
    }

    static func count(_ name: String) -> Int { snapshot[name] ?? 0 }
}
