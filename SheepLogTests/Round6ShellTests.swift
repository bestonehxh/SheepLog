import AppKit
import Darwin
import SwiftUI
import XCTest
@testable import SheepLog

/// Round 6: the shell — settings edge cases, quit ordering, the error queue, contrast of the
/// status tokens, number fields under a Thai locale.
@MainActor
final class Round6ShellTests: XCTestCase {
    private var model: AppModel { AppModel.shared }
    private var savedSettings = AppSettings()

    override func setUp() async throws {
        savedSettings = model.settings
        model.dismissAllErrors()
    }

    override func tearDown() async throws {
        model.stopSyslog()
        model.stopTraps()
        model.settings = savedSettings
        model.dismissAllErrors()
    }

    // MARK: - Contrast (WCAG 2.x relative luminance)

    private static func rgb(_ c: Color, dark: Bool) -> (Double, Double, Double) {
        let ns = NSColor(c)
        var out = (0.0, 0.0, 0.0)
        NSAppearance(named: dark ? .darkAqua : .aqua)!.performAsCurrentDrawingAppearance {
            let s = ns.usingColorSpace(.sRGB)!
            out = (Double(s.redComponent), Double(s.greenComponent), Double(s.blueComponent))
        }
        return out
    }

    static func luminance(_ c: (Double, Double, Double)) -> Double {
        func lin(_ v: Double) -> Double { v <= 0.04045 ? v / 12.92 : pow((v + 0.055) / 1.055, 2.4) }
        return 0.2126 * lin(c.0) + 0.7152 * lin(c.1) + 0.0722 * lin(c.2)
    }

    static func contrast(_ a: Color, _ b: Color, dark: Bool) -> Double {
        let la = luminance(rgb(a, dark: dark)), lb = luminance(rgb(b, dark: dark))
        return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)
    }

    /// Status words ("Listening", "udp 514", "3 err") are drawn in these tokens on the content,
    /// panel and sidebar grounds: at least 3:1 in both appearances (WCAG 1.4.11 / large text).
    func testStatusTokensReachThreeToOne() {
        let tokens: [(String, Color)] = [("ok", Theme.ok), ("err", Theme.err), ("warn", Theme.warn),
                                         ("caution", Theme.caution), ("accent", Theme.accent), ("faintText", Theme.faintText)]
        let grounds: [(String, Color)] = [("content", Theme.content), ("panel", Theme.panel), ("sidebar", Theme.sidebar)]
        for dark in [false, true] {
            for (tn, t) in tokens {
                for (gn, g) in grounds {
                    let r = Self.contrast(t, g, dark: dark)
                    XCTAssertGreaterThanOrEqual(r, 3.0, "\(tn) on \(gn) \(dark ? "dark" : "light"): \(String(format: "%.2f", r)):1")
                }
            }
        }
    }

    // MARK: - Settings

    func testLogDirectoryWithTildeIsTheHomeFolder() {
        var s = AppSettings()
        s.logDirectory = "~/Library/Logs/SheepLogRound6"
        XCTAssertEqual(s.logDirectoryURL.path(percentEncoded: false),
                       NSHomeDirectory() + "/Library/Logs/SheepLogRound6")
        s.logDirectory = "~"
        XCTAssertEqual(s.logDirectoryURL.standardizedFileURL.path(percentEncoded: false).trimmingCharacters(in: CharacterSet(charactersIn: "/")),
                       NSHomeDirectory().trimmingCharacters(in: CharacterSet(charactersIn: "/")))
        // A relative path is taken from the home folder too (a GUI app's working directory is /).
        s.logDirectory = "Logs/SheepLogRound6"
        XCTAssertEqual(s.logDirectoryURL.path(percentEncoded: false), NSHomeDirectory() + "/Logs/SheepLogRound6")
        // Absolute paths are untouched.
        s.logDirectory = "/tmp/sheeplog-r6"
        XCTAssertEqual(s.logDirectoryURL, URL(fileURLWithPath: "/tmp/sheeplog-r6"))
    }

    func testTenMegabyteSettingsFileDecodesQuickly() throws {
        // A settings.json grown by hand or by a bug: junk keys and a huge recent-targets list.
        var json = "{\"logLimit\": 5000, \"junk\": \"" + String(repeating: "x", count: 5_000_000) + "\", \"recentTargets\": ["
        let target = "{\"host\": \"10.0.0.1\", \"port\": 161, \"timeout\": 2, \"retries\": 2},"
        json += String(repeating: target, count: 5_000_000 / target.utf8.count)
        json += "{\"host\": \"last\", \"port\": 161, \"timeout\": 2, \"retries\": 2}]}"
        let data = Data(json.utf8)
        XCTAssertGreaterThan(data.count, 9_000_000)
        let t0 = Date()
        let s = try XCTUnwrap(AppSettings.decode(data))
        let took = Date().timeIntervalSince(t0)
        XCTAssertEqual(s.logLimit, 5000)
        XCTAssertEqual(s.recentTargets.count, AppSettings.recentTargetLimit)
        XCTAssertWithinBudget(took, 3.0)
    }

    func testTestRunNeverWritesTheLastPane() {
        let before = UserDefaults.standard.string(forKey: LastPane.key)
        XCTAssertTrue(LastPane.isEphemeralRun)
        LastPane.save(before == MainPane.flows.rawValue ? .mibs : .flows)
        XCTAssertEqual(UserDefaults.standard.string(forKey: LastPane.key), before)
        XCTAssertNil(LastPane.restore())
    }

    /// The Settings number fields take what a Thai keyboard types (๐–๙) and a leading zero.
    func testNumberFieldsUnderAThaiLocale() throws {
        let th = Locale(identifier: "th_TH")
        let port = IntegerFormatStyle<UInt16>(locale: th).grouping(.never)
        XCTAssertEqual(try port.parseStrategy.parse("๕๑๔"), 514)
        XCTAssertEqual(try port.parseStrategy.parse("0514"), 514)
        XCTAssertThrowsError(try port.parseStrategy.parse("70000"), "out of range is refused, the field keeps its value")
        let lines = IntegerFormatStyle<Int>(locale: th)
        XCTAssertEqual(try lines.parseStrategy.parse("๑๐๐,๐๐๐"), 100_000)
        XCTAssertEqual(try FloatingPointFormatStyle<Double>(locale: th).parseStrategy.parse("๒.๕"), 2.5)
    }

    // MARK: - Sources / Status ordering

    /// 500 sources, most with the same count, republished 4×/s: the Sources table (sorted by
    /// Lines) and Status's top talkers keep ties in address order, so rows do not swap places
    /// between publishes.
    func testTiesKeepAddressOrderAcrossPublishes() async throws {
        let store = LogStore()
        for round in 0..<3 {
            var batch: [LogEntry] = []
            for i in (0..<500).reversed() {
                batch.append(parsedLine("<13>x", from: "10.64.\(i / 250).\(i % 250)", id: LogStore.nextID()))
            }
            if round == 2 { batch.append(parsedLine("<13>x", from: "10.64.1.7", id: LogStore.nextID())) }
            store.ingest(batch)
            store.publishSources()
            let byLines = store.sources.sorted(using: [KeyPathComparator(\SourceStats.count, order: .reverse)])
            XCTAssertEqual(byLines.first?.address, round == 2 ? "10.64.1.7" : "10.64.0.0")
            let ties = byLines.filter { $0.count == round + 1 }.map(\.address)
            XCTAssertEqual(ties, store.sources.filter { $0.count == round + 1 }.map(\.address), "ties in address order")
            let top = Array(store.sources.sorted { $0.count > $1.count }.prefix(8)).map(\.address)
            XCTAssertEqual(Array(top.dropFirst(round == 2 ? 1 : 0).prefix(3)), ["10.64.0.0", "10.64.0.1", "10.64.0.2"])
        }
    }

    // MARK: - Errors

    func testFiftyIdenticalErrorsInASecondShowOneSheet() {
        for _ in 0..<50 { model.report("Log lines are not being written to disk.", detail: "ENOSPC") }
        XCTAssertEqual(model.lastError, "Log lines are not being written to disk.")
        XCTAssertEqual(model.pendingErrors.count, 0)
        for i in 0..<50 { model.report("Could not save \(i % 3).csv.") }
        XCTAssertEqual(model.pendingErrors.count, 3, "each different error once")
    }

    // MARK: - Quit

    /// ⌘Q with a line just received: the listeners stop (handing their last batch to the disk
    /// log) before the disk logger is closed, so the line is in today's file.
    func testQuitWritesTheLastLinesBeforeClosingTheDiskLog() async throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "sheeplog-r6-quit-\(UUID().uuidString)", directoryHint: .isDirectory)
        defer { try? FileManager.default.removeItem(at: dir) }
        let port = TestSockets.freePort(SOCK_DGRAM)
        model.settings.syslogUDPPort = port
        model.settings.syslogTCPPort = 0
        model.settings.logDirectory = dir.path(percentEncoded: false)
        model.settings.diskLogging = true
        model.startSyslog()
        XCTAssertTrue(model.syslog.isRunning)
        TestSockets.sendUDP(["<13>Sep 24 10:00:00 quit-host app: the very last line"], to: port)
        // Read by the listener (its 100 ms batch has not been handed on yet).
        try await Task.sleep(for: .milliseconds(30))
        model.shutdownForQuit()
        let logger = try XCTUnwrap(model.logs.diskLogger)
        let text = try String(contentsOf: logger.todaysFile, encoding: .utf8)
        XCTAssertTrue(text.contains("the very last line"), text)
        XCTAssertFalse(model.syslog.isRunning)
    }
}
