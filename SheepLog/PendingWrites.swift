import Foundation
import Synchronization

/// Files the user asked for that are being written off the main actor — a Log export, a packet
/// Save (~100 MB of `fwrite` for 200k packets): ⌘Q waits for them (`AppModel.shutdownForQuit`).
/// Quitting used to exit mid-write: the Save left a truncated capture under the chosen name, the
/// export no file at all, and neither said so.
nonisolated enum PendingWrites {
    private static let group = DispatchGroup()
    private static let count = Mutex(0)

    /// Called on the caller's actor before the write is handed off (a quit in between waits too).
    static func begin() {
        count.withLock { $0 += 1 }
        group.enter()
    }

    static func end() {
        count.withLock { $0 -= 1 }
        group.leave()
    }

    static var inFlight: Int { count.withLock { $0 } }

    /// Waits until every write has finished; false when `timeout` ran out first.
    @discardableResult
    static func wait(timeout: Double) -> Bool {
        group.wait(timeout: .now() + timeout) == .success
    }
}
