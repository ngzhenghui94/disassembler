import AppKit
import DisasmCore
import Foundation
import Observation

enum Destination: Hashable {
    case code(UInt64)              // an address inside a procedure
    case xrefs(UInt64, String)     // everything that references an address (string, import, data)
}

/// Per-app launch options and the breakpoints that survive rebuilds (address breakpoints don't).
struct DebugSettings: Codable, Equatable {
    var android: AndroidDebugOptions?
    var arguments = ""
    var environment = ""             // KEY=VALUE per line
    var presets: Set<String> = []
    var symbols: [String] = []
    var exceptions: Set<String> = []
    var disabled: Set<String> = []   // BreakpointSpec ids

    static let presetVariables: [(name: String, env: String, help: String)] = [
        ("Zombie Objects", "NSZombieEnabled=YES", "Freed Obj-C objects stay alive as zombies that log any message sent to them"),
        ("Malloc Scribble", "MallocScribble=1", "Fill new allocations with 0xAA and freed memory with 0x55"),
        ("Malloc Guard Edges", "MallocGuardEdges=1", "Put guard pages before and after large allocations"),
        ("Malloc Stack Logging", "MallocStackLogging=1", "Record allocation backtraces for leaks and malloc_history"),
    ]

    var environmentEntries: [String] {
        Self.presetVariables.filter { presets.contains($0.name) }.map(\.env)
            + environment.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }.filter { $0.contains("=") }
    }
}

enum InspectorTab: String, CaseIterable { case variables = "Variables", registers = "Registers", memory = "Memory" }

struct SourceHeader: Hashable {
    let location: String   // "File.swift:42"
    let text: String       // that line of source, if the file is on disk
}

@Observable @MainActor
final class Document {
    var url: URL?
    var bundleURL: URL?
    var bundleBinaries: [URL] = []
    var slices: [ArchSlice] = []
    var arch = ""
    var analysis: Analysis?
    var canDebug: Bool { analysis != nil }
    var isAndroid: Bool { analysis?.macho.isELF == true }
    var loading = false
    var error: String?
    var showImporter = false
    var destination: Destination?
    private(set) var history: [Destination] = []
    private var loadToken = UUID()

    var crash: CrashReport?
    var crashError: String?

    private var debugInfo: URL?
    var debugInfoReady: Bool { debugInfo != nil }
    var sidebarTab = SidebarTab.procedures
    var sourceHeaders: [UInt64: [UInt64: SourceHeader]] = [:]   // function start -> first instruction of each source line
    private var sourceFiles: [String: [Substring]] = [:]

    var session: DebugController?
    var tracer: FridaSession?
    var fridaPID = ""
    var fridaPort = ""
    var fridaDevice = ""
    var fridaPython = ""
    var fridaSymbol = ""
    var fridaOutput = ""
    var fridaCursor = 0
    private var sessionToken = UUID()
    var breakpoints: Set<UInt64> = []   // address breakpoints in the open binary
    var settings = DebugSettings() { didSet { saveSettings() } }
    var variables: [DebugVariable] = []
    var selectedFrame = 0
    var inspectorTab = InspectorTab.variables
    var memoryExpression = ""
    var memory: (address: UInt64, bytes: [UInt8])?
    var memoryMessage: String?
    var debugState = ""
    var isRunning = false
    var pc: UInt64?
    var stopFrames: [DebugFrame] = []
    var registers: [[String]] = []
    var changedRegisters: Set<String> = []   // changed since the previous stop
    var console = ""

    var recents: [URL] = (UserDefaults.standard.stringArray(forKey: "recents") ?? []).map { URL(fileURLWithPath: $0) }
    var gotoRequests = 0   // bumped by ⌘L; the toolbar field focuses itself

    // MARK: - Opening

    func open(_ picked: URL) {
        remember(picked)
        if picked.pathExtension == "ips" { return openCrash(picked) }
        if let exe = Bundle(url: picked)?.executableURL {
            bundleURL = picked
            bundleBinaries = [exe]
            Task {
                let all = await Task.detached { MachO.binaries(inBundle: picked) }.value
                if bundleURL == picked, !all.isEmpty { bundleBinaries = all }
            }
            openBinary(exe)
        } else {
            bundleURL = nil
            bundleBinaries = []
            openBinary(picked)
        }
    }

    func openBinary(_ exe: URL) {
        stopDebugging()
        detachFrida()
        url = exe; error = nil; analysis = nil; destination = nil; history = []; slices = []
        breakpoints = []
        settings = Self.loadSettings(for: launchURL)
        do {
            slices = try MachO.slices(of: Data(contentsOf: exe, options: .mappedIfSafe))
        } catch {
            self.error = error.localizedDescription
            return
        }
        #if arch(arm64)
        let preferred = slices.first { $0.arch.hasPrefix("arm64") }
        #else
        let preferred = slices.first { $0.arch == "x86_64" }
        #endif
        load((preferred ?? slices[0]).arch)
    }

    func load(_ arch: String) {
        guard let slice = slices.first(where: { $0.arch == arch }), let exe = url else { return }
        let token = UUID()
        loadToken = token
        let bundle = bundleURL
        self.arch = arch; loading = true; analysis = nil; error = nil; destination = nil; history = []
        debugInfo = nil; sourceHeaders = [:]
        Task {
            let result = await Task.detached(priority: .userInitiated) { Result { try Analysis(slice: slice) } }.value
            guard loadToken == token else { return }   // superseded by another open/arch switch
            loading = false
            switch result {
            case .success(let a):
                analysis = a
                destination = (a.macho.entry ?? a.functions.first?.start).map { .code($0) }
                guard !a.macho.isELF else { return }
                let uuid = a.macho.uuid
                let info = await Task.detached { SourceLines.debugInfo(for: exe, bundle: bundle, uuid: uuid) }.value
                if loadToken == token { debugInfo = info }
            case .failure(let e):
                error = e.localizedDescription
            }
        }
    }

    func openCrash(_ file: URL) {
        do {
            let report = try CrashReport(data: Data(contentsOf: file))
            crash = report; crashError = nil; sidebarTab = .crash
            // Not this build? Open the crashed binary itself when it's on this Mac (macOS often redacts the path).
            if analysis.map({ !report.contains($0.macho) }) ?? true, let p = report.procPath,
               FileManager.default.fileExists(atPath: p) {
                open(Self.enclosingApp(of: URL(fileURLWithPath: p)) ?? URL(fileURLWithPath: p))
            }
        } catch {
            crash = nil; sidebarTab = .crash
            crashError = error.localizedDescription
        }
    }

    private static func enclosingApp(of exe: URL) -> URL? {
        var u = exe
        while u.path != "/" {
            u.deleteLastPathComponent()
            if u.pathExtension == "app" { return u }
        }
        return nil
    }

    // MARK: - Navigation

    private func remember(_ url: URL) {
        recents = Array(([url] + recents.filter { $0 != url }).prefix(10))
        UserDefaults.standard.set(recents.map(\.path), forKey: "recents")
    }

    func clearRecents() {
        recents = []
        UserDefaults.standard.removeObject(forKey: "recents")
    }

    func go(_ d: Destination) {
        if let cur = destination, cur != d { history.append(cur) }
        destination = d
    }

    func back() {
        if let d = history.popLast() { destination = d }
    }

    /// Accepts a hex address (with or without 0x) or an exact procedure/import name.
    func goTo(_ text: String) -> Bool {
        guard let a = analysis else { return false }
        let t = text.trimmingCharacters(in: .whitespaces)
        let hex = t.hasPrefix("0x") ? String(t.dropFirst(2)) : t
        if let addr = UInt64(hex, radix: 16), a.function(containing: addr) != nil {
            go(.code(addr))
            return true
        }
        if let f = a.functions.first(where: { $0.name == t }) {
            go(.code(f.start))
            return true
        }
        if let i = a.imports.first(where: { $0.name == t }) {
            go(.xrefs(i.stub, i.name))
            return true
        }
        return false
    }

    /// Where clicking a referenced address should land.
    func follow(_ addr: UInt64) {
        guard let a = analysis else { return }
        go(a.function(containing: addr) != nil ? .code(addr) : .xrefs(addr, a.name(of: addr)))
    }

    /// Return addresses point after the call; land on the call instruction itself.
    func goToReturnAddress(_ addr: UInt64) {
        guard let a = analysis, let f = a.function(containing: addr &- 1),
              let call = a.instructions[f.lines].last(where: { $0.address < addr }) else { return follow(addr) }
        go(.code(call.address))
    }

    // MARK: - Source lines

    func loadSource(for f: Function) async {
        guard sourceHeaders[f.start] == nil, let a = analysis, let info = debugInfo else { return }
        let addrs = a.instructions[f.lines].map(\.address)
        let arch = arch, base = a.macho.textBase
        let lines = await Task.detached { SourceLines.lookup(addrs, debugInfo: info, arch: arch, loadAddress: base) }.value
        guard analysis?.macho.uuid == a.macho.uuid else { return }
        var headers: [UInt64: SourceHeader] = [:]
        var previous: SourceLine?
        for addr in addrs {
            guard let l = lines[addr], l != previous else { continue }
            previous = l
            headers[addr] = SourceHeader(location: "\(URL(fileURLWithPath: l.file).lastPathComponent):\(l.line)",
                                         text: sourceText(l))
        }
        sourceHeaders[f.start] = headers
    }

    private func sourceText(_ l: SourceLine) -> String {
        if sourceFiles[l.file] == nil {
            sourceFiles[l.file] = (try? String(contentsOfFile: l.file, encoding: .utf8))?.split(separator: "\n", omittingEmptySubsequences: false) ?? []
        }
        let lines = sourceFiles[l.file]!
        return lines.indices.contains(l.line - 1) ? lines[l.line - 1].trimmingCharacters(in: .whitespaces) : ""
    }

    // MARK: - Debugging

    /// The executable to run: the bundle's main program, even when a framework inside it is open.
    var launchURL: URL? { bundleURL.flatMap { Bundle(url: $0)?.executableURL } ?? url }

    var runningPID: pid_t? {
        guard let exe = launchURL?.resolvingSymlinksInPath() else { return nil }
        return NSWorkspace.shared.runningApplications
            .first { $0.executableURL?.resolvingSymlinksInPath() == exe }?.processIdentifier
    }

    /// Keyed by the resolved path so /tmp vs /private/tmp (or any symlinked folder) share one entry.
    private static func settingsKey(_ exe: URL) -> String { "debug:" + exe.resolvingSymlinksInPath().path }

    private static func loadSettings(for exe: URL?) -> DebugSettings {
        guard let exe, let data = UserDefaults.standard.data(forKey: settingsKey(exe)),
              let s = try? JSONDecoder().decode(DebugSettings.self, from: data) else { return DebugSettings() }
        return s
    }

    private func saveSettings() {
        guard let exe = launchURL, let data = try? JSONEncoder().encode(settings) else { return }
        UserDefaults.standard.set(data, forKey: Self.settingsKey(exe))
    }

    func launch() {
        if isAndroid {
            sidebarTab = .debug
            startSession((settings.android ?? AndroidDebugOptions()).command(launch: true, arch: analysis?.macho.arch ?? ""))
        } else { startSession(["mode": "launch"]) }
    }

    func attach() {
        if isAndroid {
            sidebarTab = .debug
            startSession((settings.android ?? AndroidDebugOptions()).command(launch: false, arch: analysis?.macho.arch ?? ""))
            return
        }
        guard let pid = runningPID else {
            debugState = "\(launchURL?.lastPathComponent ?? "App") isn't running"
            return
        }
        startSession(["mode": "attach", "pid": Int(pid)])
    }

    private func startSession(_ command: [String: Any]) {
        guard let module = url, let analysis else { return }
        stopDebugging()
        console = ""; debugState = "Starting…"
        do {
            let token = UUID()
            sessionToken = token
            var cmd = command
            if !isAndroid { cmd["executable_path"] = launchURL?.path ?? module.path }
            cmd["arguments"] = settings.arguments
            cmd["environment"] = settings.environmentEntries
            cmd["breakpoints"] = allBreakpoints.map { $0.command(enabled: isEnabled($0)) }
            session = try DebugController(options: cmd, module: module, analysis: analysis) { [weak self] e in
                Task { @MainActor in self?.handle(e, token) }
            }
        } catch {
            debugState = "Can't start lldb: \(error.localizedDescription)"
        }
    }

    func attachFrida() {
        do {
            detachFrida()
            var options: [String: Any] = ["pid": Int(fridaPID) ?? 0, "device": fridaDevice]
            if !fridaPort.isEmpty { options["port"] = Int(fridaPort) ?? 0 }
            if !fridaPython.isEmpty { options["python_path"] = fridaPython }
            tracer = try FridaSession(options: options)
            fridaOutput = "Connecting…"; fridaCursor = 0
        } catch { fridaOutput = error.localizedDescription }
    }

    func traceFrida() {
        guard let tracer, let url else { return }
        do { _ = try tracer.trace(["module": url.lastPathComponent, "symbol": fridaSymbol]) }
        catch { fridaOutput = error.localizedDescription }
    }

    func refreshFrida() {
        guard let status = tracer?.status(after: fridaCursor) else { return }
        fridaCursor = status["cursor"] as? Int ?? fridaCursor
        if let events = status["events"] as? [[String: Any]], !events.isEmpty {
            let lines = events.compactMap { item -> String? in
                guard let event = item["event"] as? [String: Any] else { return nil }
                if event["event"] as? String == "attached" { return "Attached. Ready to trace native exports." }
                guard let data = try? JSONSerialization.data(withJSONObject: event, options: [.sortedKeys]) else { return nil }
                return String(decoding: data, as: UTF8.self)
            }
            fridaOutput = (fridaOutput + "\n" + lines.joined(separator: "\n")).split(separator: "\n").suffix(100).joined(separator: "\n")
        }
    }

    func detachFrida() { tracer?.terminate(); tracer = nil }

    func stopDebugging() {
        session?.terminate()
        session = nil
        isRunning = false; pc = nil; stopFrames = []; registers = []; changedRegisters = []
        variables = []; selectedFrame = 0; memory = nil; memoryMessage = nil
    }

    func send(_ cmd: String) { session?.send(["cmd": cmd]) }

    func selectFrame(_ index: Int) { session?.send(["cmd": "frame", "index": index]) }

    /// Accepts an address, a register name, or any expression lldb can evaluate (`&count`, `$x0 + 8`).
    func readMemory(_ expression: String) {
        let expr = expression.trimmingCharacters(in: .whitespaces)
        guard !expr.isEmpty else { return }
        memoryExpression = expr
        inspectorTab = .memory
        guard session != nil, !isRunning else {
            memoryMessage = "Memory can be read while the app is stopped."
            return
        }
        session?.send(["cmd": "memory", "expr": expr, "size": 256])
    }

    // MARK: - Breakpoints

    var allBreakpoints: [BreakpointSpec] {
        settings.exceptions.sorted().map { .exception($0) } + settings.symbols.map { .symbol($0) } + breakpoints.sorted().map { .address($0) }
    }

    func isEnabled(_ b: BreakpointSpec) -> Bool { !settings.disabled.contains(b.id) }

    func setEnabled(_ b: BreakpointSpec, _ on: Bool) {
        if on { settings.disabled.remove(b.id) } else { settings.disabled.insert(b.id) }
        session?.send(["cmd": "bp_enable", "id": b.id, "enabled": on])
    }

    func add(_ b: BreakpointSpec) {
        switch b {
        case .address(let a): breakpoints.insert(a)
        case .symbol(let name): if !settings.symbols.contains(name) { settings.symbols.append(name) }
        case .exception(let lang): settings.exceptions.insert(lang)
        }
        settings.disabled.remove(b.id)
        session?.send(b.command(enabled: true))
    }

    func remove(_ b: BreakpointSpec) {
        switch b {
        case .address(let a): breakpoints.remove(a)
        case .symbol(let name): settings.symbols.removeAll { $0 == name }
        case .exception(let lang): settings.exceptions.remove(lang)
        }
        settings.disabled.remove(b.id)
        session?.send(["cmd": "bp_remove", "id": b.id])
    }

    func toggleBreakpoint(_ addr: UInt64) {
        breakpoints.contains(addr) ? remove(.address(addr)) : add(.address(addr))
    }

    static let exceptionLabels = ["objc": "Objective-C exceptions", "swift": "Swift errors", "cpp": "C++ exceptions"]

    func label(_ b: BreakpointSpec) -> String {
        switch b {
        case .address(let a): analysis?.name(of: a) ?? hex(a)
        case .symbol(let name): name
        case .exception(let lang): "Thrown " + (Self.exceptionLabels[lang] ?? lang)
        }
    }

    // MARK: - Events

    private func handle(_ e: DebugEvent, _ token: UUID) {
        guard session != nil, token == sessionToken else { return }   // ignore events from an earlier session
        switch e.event {
        case "running":
            isRunning = true; pc = nil; debugState = "Running"
        case "stopped":
            isRunning = false
            debugState = e.reason ?? "Stopped"
            // Name the breakpoint instead of lldb's internal "breakpoint 2.1".
            if let id = e.breakpoint, let b = allBreakpoints.first(where: { $0.id == id }) {
                let thread = debugState.components(separatedBy: ":").first ?? "Stopped"
                if case .exception = b { debugState = thread + ": " + label(b) } else { debugState = thread + ": breakpoint at " + label(b) }
            }
            stopFrames = e.frames ?? []
            variables = e.variables ?? []
            let frame = e.selectedFrame ?? 0
            let old = Dictionary(registers.compactMap { $0.count == 2 ? ($0[0], $0[1]) : nil }, uniquingKeysWith: { a, _ in a })
            registers = e.registers ?? []
            // Only diff consecutive stops of the same frame; switching frames isn't a change.
            changedRegisters = old.isEmpty || frame != selectedFrame ? []
                : Set(registers.compactMap { $0.count == 2 && old[$0[0]] != $0[1] ? $0[0] : nil })
            selectedFrame = frame
            pc = e.pc
            showStop(frame)
            if inspectorTab == .memory, !memoryExpression.isEmpty { readMemory(memoryExpression) }   // keep the dump live
        case "memory":
            memoryMessage = e.message
            if let addr = e.addr.flatMap({ UInt64($0.dropFirst(2), radix: 16) }), let bytes = e.hex.flatMap(HexDump.bytes(fromHex:)) {
                memory = (addr, bytes)
            } else {
                memory = nil
            }
        case "detached":
            stopDebugging(); debugState = "Detached"
        case "exited":
            debugState = "Exited" + (e.code.map { " (status \($0))" } ?? "") + (e.message.map { $0.isEmpty ? "" : ": \($0)" } ?? "")
            isRunning = false; pc = nil
        case "output":
            console += e.text ?? ""
            if console.count > 200_000 { console = String(console.suffix(100_000)) }
        case "error":
            console += "error: \(e.message ?? "")\n"
        default:
            break
        }
    }

    /// Shows the selected frame, or for a fresh stop the nearest frame inside this binary.
    private func showStop(_ frame: Int) {
        if frame > 0 {
            if stopFrames.indices.contains(frame), let addr = stopFrames[frame].fileAddr { goToReturnAddress(addr) }
            return
        }
        guard let first = stopFrames.firstIndex(where: { $0.fileAddr != nil }), let addr = stopFrames[first].fileAddr else { return }
        if first > 0 {
            goToReturnAddress(addr)
        } else if case .code(let cur) = destination, let a = analysis,
                  a.function(containing: cur)?.start == a.function(containing: addr)?.start {
            destination = .code(addr)   // stepping within a function shouldn't flood Back history
        } else {
            go(.code(addr))
        }
    }
}
