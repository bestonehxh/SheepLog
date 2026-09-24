import Foundation
import MachO
import XCTest

/// Time and memory budgets are checked only in a plain run. Under the Address, Thread or
/// Undefined Behavior Sanitizer everything is several times slower (and TSan's shadow memory
/// counts as footprint), so the assertion is skipped — the test itself still runs, which is the
/// point of a sanitizer pass. `SHEEPLOG_NO_PERF_ASSERTS=1` (for xcodebuild:
/// `TEST_RUNNER_SHEEPLOG_NO_PERF_ASSERTS=1`) skips them on a loaded machine too, and so does
/// Low Power Mode.
enum PerfBudget {
    static let skipReason: String? = {
        let env = ProcessInfo.processInfo.environment
        if let v = env["SHEEPLOG_NO_PERF_ASSERTS"], !v.isEmpty, v != "0" { return "SHEEPLOG_NO_PERF_ASSERTS" }
        // Low Power Mode (a MacBook on battery) halves the clocks: every budget here was set on
        // full ones (decode 4 µs → 8 µs per packet, export 0.43 s → 0.86 s, same build).
        if ProcessInfo.processInfo.isLowPowerModeEnabled { return "Low Power Mode" }
        let inserted = (env["DYLD_INSERT_LIBRARIES"] ?? "").lowercased()
        for s in ["asan", "tsan", "ubsan"] where inserted.contains(s) { return "DYLD_INSERT_LIBRARIES has \(s)" }
        // Xcode may link the runtime instead of inserting it: look at the loaded images.
        for i in 0..<_dyld_image_count() {
            guard let c = _dyld_get_image_name(i) else { continue }
            let name = String(cString: c).lowercased()
            for s in ["libclang_rt.asan", "libclang_rt.tsan", "libclang_rt.ubsan"] where name.contains(s) {
                return "\(s) is loaded"
            }
        }
        return nil
    }()

    static var enforced: Bool { skipReason == nil }
}

/// `XCTAssertLessThan` for a time or memory budget: skipped under a sanitizer (see `PerfBudget`).
func XCTAssertWithinBudget<T: Comparable>(_ value: @autoclosure () throws -> T, _ limit: @autoclosure () throws -> T,
                                          _ message: @autoclosure () -> String = "",
                                          file: StaticString = #filePath, line: UInt = #line) {
    guard let v = try? value(), let l = try? limit() else {
        XCTFail("budget expression threw", file: file, line: line)
        return
    }
    if let reason = PerfBudget.skipReason {
        print("[perf] budget not checked (\(reason)): \(v) vs \(l) \(message())")
        return
    }
    XCTAssertLessThan(v, l, message(), file: file, line: line)
}
