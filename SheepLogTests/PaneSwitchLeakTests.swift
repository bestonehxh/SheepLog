import AppKit
import Darwin
import SwiftUI
import XCTest
@testable import SheepLog

/// Long-running behaviour: an engineer flips between panes all week. Every pane appearance
/// creates coordinators, controllers, refresh loops and SwiftUI subscriptions; after hundreds of
/// switches none of them may be left behind. Proxies (no Instruments): `LeakProbe` instance
/// counters, the observer table of `NotificationCenter.default`, open file descriptors and
/// threads of this process.
@MainActor
final class PaneSwitchLeakTests: XCTestCase {
    private var window: NSWindow?
    private var savedPane: MainPane = .log

    override func setUp() async throws {
        ObserverCensus.install()
        savedPane = AppModel.shared.mainPane
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1280, height: 820),
                         styleMask: [.titled, .resizable], backing: .buffered, defer: false)
        w.isReleasedWhenClosed = false
        w.contentView = NSHostingView(rootView: ContentView())
        w.orderFront(nil)
        window = w
    }

    override func tearDown() async throws {
        window?.contentView = nil
        window?.close()
        window = nil
        AppModel.shared.mainPane = savedPane
        await spin(0.2)
    }

    private func spin(_ seconds: Double) async {
        try? await Task.sleep(for: .milliseconds(Int(seconds * 1000)))
    }

    /// Block observers SheepLog's code registers with `NotificationCenter.default` and has not
    /// removed — its cross-pane requests (`SheepLog.*`), the full-screen `.onReceive`s and the
    /// packet table's scroll subscription (counted by `ObserverCensus` from the moment it is
    /// installed). AppKit / SwiftUI register many more for their own views; those are reported
    /// (`frameworkObserverCount`), not asserted on: they depend on what the rest of the suite
    /// left on screen (a sheet, a popover) and on the framework's own leak below.
    static func notificationObserverCount() -> Int {
        ObserverCensus.byName.filter { isOwn($0.0) }.reduce(0) { $0 + $1.1 }
    }

    static func isOwn(_ name: String) -> Bool {
        name.hasPrefix("SheepLog.") || ownFrameworkNames.contains(name)
    }

    static let ownFrameworkNames: Set<String> = [
        "NSWindowWillEnterFullScreenNotification", "NSWindowDidEnterFullScreenNotification",
        "NSWindowWillExitFullScreenNotification", "NSWindowDidExitFullScreenNotification",
        "NSViewBoundsDidChangeNotification",
    ]

    static func frameworkObserverCount() -> Int {
        ObserverCensus.byName.filter { !isOwn($0.0) && !swiftUIBridgeNames.contains($0.0) }.reduce(0) { $0 + $1.1 }
    }

    /// macOS 26/27 SwiftUI: every `TextField` / `SecureField` that moves into a window registers
    /// these four window observers (`AppKitTextInputSuggestionsBridge.setUpNotifications`) and
    /// never removes them — 4 more per text field per pane appearance, each run on every window
    /// move / resign-key. Not SheepLog's code (an `NSTextField` in a representable adds none); the
    /// test reports the number instead of failing on it.
    static let swiftUIBridgeNames: Set<String> = [
        "NSWindowDidMoveNotification", "NSWindowWillStartLiveResizeNotification",
        "NSWindowDidResignMainNotification", "NSWindowDidResignKeyNotification",
    ]

    static func ownObserverNames() -> [String: Int] {
        Dictionary(uniqueKeysWithValues: ObserverCensus.byName.filter { isOwn($0.0) })
    }

    static func diff(_ a: [String: Int], _ b: [String: Int]) -> String {
        Set(a.keys).union(b.keys).compactMap { k in
            let d = (b[k] ?? 0) - (a[k] ?? 0)
            return d == 0 ? nil : "\(k) \(d > 0 ? "+" : "")\(d)"
        }.sorted().joined(separator: ", ")
    }

    static func bridgeObserverCount() -> Int {
        ObserverCensus.byName.filter { swiftUIBridgeNames.contains($0.0) }.reduce(0) { $0 + $1.1 }
    }

    /// What may differ without being a leak: a pane leaking per appearance adds one or more per
    /// switch of that pane (≥ 25 over 200 switches of eight panes); AppKit's own registrations
    /// under the same names (a sheet another suite left closing) add a handful once.
    static let slack = 8

    static func openDescriptors() -> Int {
        (0..<Int32(4096)).reduce(0) { n, fd in fcntl(fd, F_GETFD) != -1 ? n + 1 : n }
    }

    static func threadCount() -> Int {
        var list: thread_act_array_t?
        var count: mach_msg_type_number_t = 0
        guard task_threads(mach_task_self_, &list, &count) == KERN_SUCCESS, let list else { return -1 }
        for i in 0..<Int(count) { mach_port_deallocate(mach_task_self_, list[i]) }
        vm_deallocate(mach_task_self_, vm_address_t(UInt(bitPattern: list)),
                      vm_size_t(Int(count) * MemoryLayout<thread_act_t>.stride))
        return Int(count)
    }

    private struct Sample: Equatable, CustomStringConvertible {
        var probes: [String: Int]
        var observers: Int
        var descriptors: Int
        var threads: Int
        var description: String {
            "probes \(probes.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: " ")) · "
                + "SheepLog's NotificationCenter observers \(observers) · fds \(descriptors) · threads \(threads)"
        }
    }

    private func sample() -> Sample {
        Sample(probes: LeakProbe.snapshot.filter { $0.value != 0 }, observers: Self.notificationObserverCount(),
               descriptors: Self.openDescriptors(), threads: Self.threadCount())
    }

    func testTwoHundredPaneSwitchesLeaveNothingBehind() async throws {
        let model = AppModel.shared
        let panes = MainPane.allCases
        // Warm up: every pane once (lazy singletons, SwiftUI's own caches), then settle on Status.
        for p in panes { model.mainPane = p; await spin(0.05) }
        model.mainPane = .status
        await spin(1.5)
        let before = sample()
        let namesBefore = Self.ownObserverNames()
        let frameworkBefore = Self.frameworkObserverCount()
        let bridgeBefore = Self.bridgeObserverCount()

        for i in 0..<200 {
            model.mainPane = panes[i % panes.count]
            await spin(0.02)
        }
        model.mainPane = .status
        await spin(1.5)
        // Other suites' leftovers (a SwiftUI teardown, a sheet) may still be settling: give the
        // count a few seconds to come back before calling it a leak.
        for _ in 0..<50 where Self.notificationObserverCount() > before.observers + Self.slack
            || Self.openDescriptors() > before.descriptors + Self.slack { await spin(0.1) }
        let after = sample()
        print("[leak] before 200 pane switches: \(before)")
        print("[leak] after  200 pane switches: \(after)")
        print("[leak] SwiftUI text-field bridge observers (framework leak): \(bridgeBefore) → \(Self.bridgeObserverCount())")
        print("[leak] other AppKit/SwiftUI observers: \(frameworkBefore) → \(Self.frameworkObserverCount())")

        // Nothing pane-owned is alive on Status.
        for name in ["LogTable.Coordinator", "PacketTableController", "Packets.interfaceLoop",
                     "Flows.analysis", "Flows.scheduled"] {
            XCTAssertEqual(LeakProbe.count(name), before.probes[name] ?? 0, "\(name) left behind")
        }
        XCTAssertEqual(LeakProbe.count("Status.addressLoop"), before.probes["Status.addressLoop"] ?? 0, "one address loop for the one Status pane")
        XCTAssertEqual(after.probes, before.probes)
        // SheepLog's own and SwiftUI's `.onReceive` registrations come and go with the views.
        XCTAssertLessThanOrEqual(after.observers, before.observers + Self.slack,
                                 "NotificationCenter observers grew: \(before.observers) → \(after.observers): \(Self.diff(namesBefore, Self.ownObserverNames()))")
        XCTAssertLessThanOrEqual(after.descriptors, before.descriptors + Self.slack, "file descriptors grew")
        XCTAssertLessThanOrEqual(after.threads, before.threads + 8, "threads grew")
    }

    /// The pane-owned objects exist while their pane is shown (the probes count something).
    func testProbesSeeThePanes() async throws {
        let model = AppModel.shared
        model.mainPane = .log
        await spin(0.3)
        XCTAssertGreaterThanOrEqual(LeakProbe.count("LogTable.Coordinator"), 1)
        model.mainPane = .packets
        await spin(0.3)
        XCTAssertGreaterThanOrEqual(LeakProbe.count("PacketTableController"), 1)
        XCTAssertGreaterThanOrEqual(LeakProbe.count("Packets.interfaceLoop"), 1)
        model.mainPane = .status
        await spin(0.5)
        XCTAssertGreaterThanOrEqual(LeakProbe.count("Status.addressLoop"), 1, "the Status pane follows address changes")
        model.mainPane = .log
        await spin(0.5)
        XCTAssertEqual(LeakProbe.count("Status.addressLoop"), 0, "and stops when it goes")
    }
}

/// Counts live block observers of `NotificationCenter.default` by exchanging the add / remove
/// methods (once per process). Tokens are tracked by identity, so a `removeObserver:` for an
/// object that was never a token (AppKit's dealloc housekeeping) does not count.
nonisolated final class ObserverCensus: @unchecked Sendable {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var tokens = [ObjectIdentifier: String]()
    nonisolated(unsafe) private static var installed = false
    nonisolated(unsafe) private static var deliveries = [String: Int]()

    static func delivered(_ name: String) { lock.lock(); deliveries[name, default: 0] += 1; lock.unlock() }
    static func deliveries(_ name: String) -> Int { lock.lock(); defer { lock.unlock() }; return deliveries[name] ?? 0 }

    static var live: Int { lock.lock(); defer { lock.unlock() }; return tokens.count }

    static func install() {
        lock.lock(); defer { lock.unlock() }
        guard !installed else { return }
        installed = true
        let cls: AnyClass = NotificationCenter.self
        let pairs: [(Selector, Selector)] = [
            (NSSelectorFromString("addObserverForName:object:queue:usingBlock:"),
             #selector(NotificationCenter.census_addObserver(forName:object:queue:using:))),
            (NSSelectorFromString("removeObserver:"), #selector(NotificationCenter.census_removeObserver(_:))),
            (NSSelectorFromString("removeObserver:name:object:"),
             #selector(NotificationCenter.census_removeObserver(_:name:object:))),
        ]
        for (original, replacement) in pairs {
            guard let a = class_getInstanceMethod(cls, original), let b = class_getInstanceMethod(cls, replacement) else { continue }
            method_exchangeImplementations(a, b)
        }
    }

    static func added(_ token: AnyObject, name: String) { lock.lock(); tokens[ObjectIdentifier(token)] = name; lock.unlock() }

    /// Live registrations per notification name, most first.
    static var byName: [(String, Int)] {
        lock.lock(); defer { lock.unlock() }
        return Dictionary(grouping: tokens.values, by: { $0 }).map { ($0.key, $0.value.count) }.sorted { $0.1 > $1.1 }
    }
    static func removed(_ token: Any) {
        let o = token as AnyObject
        lock.lock(); tokens[ObjectIdentifier(o)] = nil; lock.unlock()
    }
}

extension NotificationCenter {
    @objc dynamic func census_addObserver(forName name: NSNotification.Name?, object obj: Any?, queue: OperationQueue?,
                                          using block: @escaping @Sendable (Notification) -> Void) -> NSObjectProtocol {
        let counted: @Sendable (Notification) -> Void = { note in
            ObserverCensus.delivered(note.name.rawValue)
            block(note)
        }
        let token = census_addObserver(forName: name, object: obj, queue: queue, using: counted)
        if self === NotificationCenter.default { ObserverCensus.added(token, name: name?.rawValue ?? "(any)") }
        return token
    }

    @objc dynamic func census_removeObserver(_ observer: Any) {
        if self === NotificationCenter.default { ObserverCensus.removed(observer) }
        census_removeObserver(observer)
    }

    @objc dynamic func census_removeObserver(_ observer: Any, name: NSNotification.Name?, object: Any?) {
        if self === NotificationCenter.default { ObserverCensus.removed(observer) }   // a token has one name
        census_removeObserver(observer, name: name, object: object)
    }
}
