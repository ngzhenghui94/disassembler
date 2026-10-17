import AppKit
import DisasmCore
import Foundation
import Observation

enum Destination: Hashable {
    case code(UInt64)              // an address inside a procedure
    case xrefs(UInt64, String)     // everything that references an address (string, import, data)
}

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

    var session: LLDBSession?
    private var sessionToken = UUID()
    var breakpoints: Set<UInt64> = []
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
        url = exe; error = nil; analysis = nil; destination = nil; history = []; slices = []
        breakpoints = []
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

    func launch() { startSession(["cmd": "launch", "path": launchURL?.path ?? ""]) }

    func attach() {
        guard let pid = runningPID else {
            debugState = "\(launchURL?.lastPathComponent ?? "App") isn't running"
            return
        }
        startSession(["cmd": "attach", "pid": Int(pid)])
    }

    private func startSession(_ command: [String: Any]) {
        guard let module = url?.path else { return }
        stopDebugging()
        console = ""; debugState = "Starting…"
        do {
            let token = UUID()
            sessionToken = token
            let s = try LLDBSession { [weak self] e in Task { @MainActor in self?.handle(e, token) } }
            session = s
            var cmd = command
            cmd["module"] = module
            cmd["breakpoints"] = Array(breakpoints)
            if !arch.contains(" ") { cmd["arch"] = arch }
            s.send(cmd)
        } catch {
            debugState = "Can't start lldb: \(error.localizedDescription)"
        }
    }

    func stopDebugging() {
        session?.terminate()
        session = nil
        isRunning = false; pc = nil; stopFrames = []; registers = []; changedRegisters = []
    }

    func send(_ cmd: String) { session?.send(["cmd": cmd]) }

    func toggleBreakpoint(_ addr: UInt64) {
        if breakpoints.remove(addr) != nil {
            session?.send(["cmd": "unbreak", "addr": addr])
        } else {
            breakpoints.insert(addr)
            session?.send(["cmd": "break", "addr": addr])
        }
    }

    private func handle(_ e: DebugEvent, _ token: UUID) {
        guard session != nil, token == sessionToken else { return }   // ignore events from an earlier session
        switch e.event {
        case "running":
            isRunning = true; pc = nil; debugState = "Running"
        case "stopped":
            isRunning = false
            debugState = e.reason ?? "Stopped"
            stopFrames = e.frames ?? []
            let old = Dictionary(registers.compactMap { $0.count == 2 ? ($0[0], $0[1]) : nil }, uniquingKeysWith: { a, _ in a })
            registers = e.registers ?? []
            changedRegisters = old.isEmpty ? [] : Set(registers.compactMap { $0.count == 2 && old[$0[0]] != $0[1] ? $0[0] : nil })
            pc = e.pc
            // Show where we stopped, or the nearest caller inside this binary.
            if let first = stopFrames.firstIndex(where: { $0.fileAddr != nil }), let addr = stopFrames[first].fileAddr {
                if first > 0 {
                    goToReturnAddress(addr)
                } else if case .code(let cur) = destination, let a = analysis,
                          a.function(containing: cur)?.start == a.function(containing: addr)?.start {
                    destination = .code(addr)   // stepping within a function shouldn't flood Back history
                } else {
                    go(.code(addr))
                }
            }
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
}
