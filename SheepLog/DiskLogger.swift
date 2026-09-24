import Darwin
import Foundation

/// Appends raw lines to `<directory>/YYYY-MM-DD.log`, rotating at midnight. Thread-safe;
/// writes are serialised on its own queue so the main actor never blocks on disk.
///
/// All mutable state except `file` is confined to `queue`; `file` (read from any thread via
/// `currentFile`) is guarded by `lock`.
///
/// Hostile-input rules: every line is one line (line breaks and every other control character
/// a sender embeds are written as rsyslog's `#ooo` octal escapes, so `cat`/`tail -f` of the
/// file cannot be driven by ESC sequences); files are created 0600 and never through a
/// symlink; a folder that is `/`, a system folder or a file is refused; a folder removed while
/// running is re-created; a failing disk (ENOSPC) is reported once, not per line.
nonisolated final class DiskLogger: @unchecked Sendable {
    let directory: URL

    private let queue = DispatchQueue(label: "sheeplog.disklogger", qos: .utility)
    private let lock = NSLock()
    private var file: URL?
    // queue-confined
    private var fd: Int32 = -1
    private var openedIdentity: (dev: dev_t, ino: ino_t)?
    private var lastIdentityCheck: UInt64 = 0
    private var day = ""
    private var reportedError = false
    private var stampSecond = -1
    private var stampPrefix = ""
    private var retired = false

    /// Told (on the logger's queue) the first time a write or open fails.
    private let onError: (@Sendable (String) -> Void)?

    init(directory: URL, onError: (@Sendable (String) -> Void)? = nil) {
        self.directory = directory
        self.onError = onError
    }

    /// Every queued write holds a reference, so by now the queue is idle: close the file a
    /// caller forgot to `close()` instead of leaking the descriptor.
    deinit { if fd >= 0 { Darwin.close(fd) } }

    /// One line per entry: "<received ISO8601> <sourceAddress> <raw>".
    func append(_ entries: [LogEntry]) {
        guard !entries.isEmpty else { return }
        queue.async { [self] in write(entries.count) { i in (entries[i].received, entries[i].sourceAddress, entries[i].raw) } }
    }

    /// The same lines straight from a listener's queue, before parsing and before the batch
    /// may be dropped on its way to the main actor (a flood the main thread cannot keep up
    /// with, or ⌘Q with batches still queued): the file gets every line received.
    func append(raws: [RawSyslog]) {
        guard !raws.isEmpty else { return }
        queue.async { [self] in write(raws.count) { i in (raws[i].received, raws[i].sourceAddress, raws[i].text) } }
    }

    /// Flushes and closes synchronously. Later appends reopen the file.
    func close() {
        queue.sync {
            closeFile()
            day = ""
        }
    }

    /// Closes for good: this logger was replaced or disk logging was turned off. An append
    /// still on its way from a listener thread must not reopen the file afterwards. Lines
    /// queued before this call are still written. `wait: false` returns at once (the app: a
    /// logger with a burst still to write would hold the main thread until it is done).
    func retire(wait: Bool = true) {
        let work: @Sendable () -> Void = { [self] in
            retired = true
            closeFile()
            day = ""
        }
        if wait { queue.sync(execute: work) } else { queue.async(execute: work) }
    }

    /// Waits until every queued write is done (tests).
    func sync() { queue.sync {} }

    var currentFile: URL? {
        lock.lock(); defer { lock.unlock() }
        return file
    }

    /// The file today's lines go to (whether or not it exists yet).
    var todaysFile: URL { directory.appending(path: "\(Self.dayString(Date())).log") }

    /// Why `directory` must not receive log files, or nil. `/`, the system's own folders and
    /// a path that is a file are refused (a mistyped setting must not scatter files there).
    static func unsuitableReason(_ directory: URL) -> String? {
        let path = directory.standardizedFileURL.resolvingSymlinksInPath().path(percentEncoded: false)
        let trimmed = path.count > 1 && path.hasSuffix("/") ? String(path.dropLast()) : path
        if trimmed.isEmpty || trimmed == "/" { return "the log folder is set to / (the whole disk)" }
        let system = ["/System", "/bin", "/sbin", "/usr", "/dev", "/etc", "/private/etc", "/var", "/private/var",
                      "/Library", "/Applications", "/cores", "/opt"]
        let allowedUnder = ["/usr/local", "/opt/", "/private/var/folders", "/var/folders", "/Library/Logs"]
        if system.contains(where: { trimmed == $0 || trimmed.hasPrefix($0 + "/") }),
           !allowedUnder.contains(where: { trimmed.hasPrefix($0) }) {
            return "the log folder \(trimmed) is a system folder"
        }
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: trimmed, isDirectory: &isDir), !isDir.boolValue {
            return "the log folder \(trimmed) is a file, not a folder"
        }
        return nil
    }

    /// The volume name when `directory` is on `/Volumes/<name>/…` and that volume is not
    /// mounted (an unplugged USB disk, a network share that went away).
    static func missingVolume(_ directory: URL) -> String? {
        let parts = directory.standardizedFileURL.path(percentEncoded: false).split(separator: "/", omittingEmptySubsequences: true)
        guard parts.count >= 2, parts[0] == "Volumes" else { return nil }
        let name = String(parts[1])
        let mountPoint = "/Volumes/\(name)"
        var ls = stat()
        guard lstat(mountPoint, &ls) == 0 else { return name }
        if ls.st_mode & S_IFMT == S_IFLNK { return nil }            // "/Volumes/Macintosh HD" → /
        var st = statfs()
        guard statfs(mountPoint, &st) == 0 else { return name }
        let on = withUnsafeBytes(of: st.f_mntonname) { raw in
            String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
        }
        // A plain folder left behind on the startup disk is not the volume.
        return on == mountPoint ? nil : name
    }

    // MARK: - Queue-confined

    private func write(_ count: Int, _ line: (Int) -> (received: Date, address: String, raw: String)) {
        guard !retired else { return }
        let today = Self.dayString(Date())
        if today != day || fd < 0 || fileWasRemoved() {
            open(day: today)
        }
        guard fd >= 0 else { return }
        var data = Data()
        data.reserveCapacity(count * 160)
        for i in 0..<count {
            let e = line(i)
            data.append(contentsOf: stamp(e.received).utf8)
            data.append(0x20)
            Self.appendOneLine(e.address, to: &data)
            data.append(0x20)
            Self.appendOneLine(e.raw, to: &data)
            data.append(0x0A)
        }
        let ok = data.withUnsafeBytes { raw -> Int32 in
            var p = 0
            while p < raw.count {
                let n = Darwin.write(fd, raw.baseAddress! + p, raw.count - p)
                if n > 0 { p += n; continue }
                if n < 0, errno == EINTR { continue }
                return n < 0 ? errno : EIO
            }
            return 0
        }
        if ok != 0 {
            report("SheepLog: writing \(currentFile?.path ?? "the log file") failed: \(String(cString: strerror(ok)))"
                   + (ok == ENOSPC ? " (the disk is full)" : "") + ". Lines are kept in memory only until this is fixed.")
        } else {
            // Writing works (again): a later failure is worth another report.
            reportedError = false
        }
    }

    /// The folder (or today's file) was deleted or replaced under us: the descriptor still
    /// writes, into a file no one can see. Checked at most once a second.
    private func fileWasRemoved() -> Bool {
        let now = clock_gettime_nsec_np(CLOCK_UPTIME_RAW)
        guard now &- lastIdentityCheck > 1_000_000_000, let id = openedIdentity, let url = currentFile else { return false }
        lastIdentityCheck = now
        var st = stat()
        guard lstat(url.path(percentEncoded: false), &st) == 0 else { return true }
        return st.st_dev != id.dev || st.st_ino != id.ino
    }

    private func closeFile() {
        if fd >= 0 {
            fsync(fd)
            Darwin.close(fd)
        }
        fd = -1
        openedIdentity = nil
    }

    private func open(day today: String) {
        closeFile()
        day = today
        let url = directory.appending(path: "\(today).log")
        if let why = Self.unsuitableReason(directory) {
            report("SheepLog: not writing log files: \(why). Choose another folder in Settings.")
            return
        }
        if let disk = Self.missingVolume(directory) {
            // Not "permission denied" (creating /Volumes/<name> is refused): the disk is gone.
            report("SheepLog: the disk “\(disk)” that holds the log folder is not connected. "
                   + "Lines are written again as soon as it is back; meanwhile they are kept in memory only.")
            return
        }
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        } catch {
            report("SheepLog: cannot create the log folder \(directory.path(percentEncoded: false)): \(error.localizedDescription)")
            return
        }
        // O_NOFOLLOW: a symlink planted as today's file is not followed; 0600: the lines may
        // hold credentials and internal addresses.
        let path = url.path(percentEncoded: false)
        let f = Darwin.open(path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard f >= 0 else {
            let e = errno
            report("SheepLog: cannot open \(path): \(String(cString: strerror(e)))"
                   + (e == ELOOP ? " (it is a symbolic link)" : ""))
            return
        }
        var st = stat()
        if fstat(f, &st) == 0 {
            guard st.st_mode & S_IFMT == S_IFREG else {
                Darwin.close(f)
                report("SheepLog: cannot write \(path): not a regular file")
                return
            }
            // A file from an older build (0644) is tightened too.
            if st.st_mode & 0o077 != 0 { fchmod(f, 0o600) }
            openedIdentity = (st.st_dev, st.st_ino)
        }
        lastIdentityCheck = clock_gettime_nsec_np(CLOCK_UPTIME_RAW)
        fd = f
        lock.lock(); file = url; lock.unlock()
    }

    private func report(_ message: String) {
        guard !reportedError else { return }
        reportedError = true
        NSLog("%@", message)
        onError?(message)
    }

    /// `2026-09-23T10:15:32.123+07:00`, the seconds part cached.
    private func stamp(_ date: Date) -> String {
        let t = date.timeIntervalSince1970
        let sec = Int(t.rounded(.down))
        if sec != stampSecond {
            stampSecond = sec
            stampPrefix = isoSeconds.string(from: Date(timeIntervalSince1970: Double(sec)))
        }
        let ms = min(999, Int((t - Double(sec)) * 1000))
        // prefix is "yyyy-MM-ddTHH:mm:ss+hh:mm"; insert .SSS before the zone.
        let msText = ms < 10 ? "00\(ms)" : ms < 100 ? "0\(ms)" : "\(ms)"
        guard stampPrefix.count > 19 else { return stampPrefix }
        let idx = stampPrefix.index(stampPrefix.startIndex, offsetBy: 19)
        return "\(stampPrefix[..<idx]).\(msText)\(stampPrefix[idx...])"
    }

    private let isoSeconds: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        f.timeZone = .current
        return f
    }()

    /// The raw text as one line, control characters written as rsyslog writes them (`#ooo`,
    /// octal: `#012` for a line break, `#033` for ESC): a TCP frame or a datagram may carry a
    /// `\n` inside one message — written verbatim it split the entry and let a sender forge
    /// whole lines of the saved log — and ESC / CSI sequences would drive the terminal of
    /// whoever `cat`s the file. Tab stays. C1 controls (U+0080–U+009F, UTF-8 `C2 80`–`C2 9F`)
    /// are written by code point (`#233` for U+009B CSI).
    static func appendOneLine(_ raw: String, to data: inout Data) {
        let u = raw.utf8
        guard needsEscaping(u) else {
            data.append(contentsOf: u)
            return
        }
        var pendingC2 = false
        for c in u {
            if pendingC2 {
                pendingC2 = false
                if c >= 0x80, c <= 0x9F { appendOctal(c, to: &data); continue }
                data.append(0xC2)
            }
            if c == 0xC2 { pendingC2 = true; continue }
            if (c < 0x20 && c != 0x09) || c == 0x7F { appendOctal(c, to: &data) } else { data.append(c) }
        }
        if pendingC2 { data.append(0xC2) }
    }

    private static func needsEscaping(_ u: String.UTF8View) -> Bool {
        var prev: UInt8 = 0
        for c in u {
            if (c < 0x20 && c != 0x09) || c == 0x7F { return true }
            if prev == 0xC2, c >= 0x80, c <= 0x9F { return true }
            prev = c
        }
        return false
    }

    private static func appendOctal(_ c: UInt8, to data: inout Data) {
        data.append(0x23)                                   // #
        data.append(0x30 + (c >> 6))
        data.append(0x30 + ((c >> 3) & 7))
        data.append(0x30 + (c & 7))
    }

    static func oneLine(_ raw: String) -> String {
        guard needsEscaping(raw.utf8) else { return raw }
        var d = Data()
        appendOneLine(raw, to: &d)
        return String(decoding: d, as: UTF8.self)
    }

    static func dayString(_ date: Date) -> String {
        let c = Calendar(identifier: .gregorian).dateComponents(in: .current, from: date)
        return String(format: "%04d-%02d-%02d", c.year ?? 0, c.month ?? 0, c.day ?? 0)
    }
}
