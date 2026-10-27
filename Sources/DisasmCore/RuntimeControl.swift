import Foundation

/// A bounded, cursor-based log shared by the UI helpers and MCP callers.
final class RuntimeEvents: @unchecked Sendable {
    private let condition = NSCondition()
    private var events: [(Int, [String: Any])] = []
    private var sequence = 0
    private var state = "starting"
    private var snapshot: [String: Any]?
    private var lastError: [String: Any]?

    func append(_ event: [String: Any]) {
        condition.lock(); defer { condition.broadcast(); condition.unlock() }
        sequence += 1
        events.append((sequence, event))
        if events.count > 200 { events.removeFirst(events.count - 200) }
        if let name = event["event"] as? String {
            if ["running", "stopped", "exited", "detached", "attached"].contains(name) { state = name }
            if name == "error" { lastError = event; if state == "starting" { state = "error" } }
            if name == "stopped" { snapshot = event }
        }
    }

    func read(after: Int? = nil, waitMS: Int = 0) -> [String: Any] {
        condition.lock(); defer { condition.unlock() }
        let cursor = after ?? sequence, deadline = Date().addingTimeInterval(Double(waitMS) / 1000)
        while sequence <= cursor && waitMS > 0 {
            if !condition.wait(until: deadline) { break }
        }
        let first = events.first?.0 ?? sequence + 1
        return ["state": state, "cursor": sequence, "dropped": max(0, first - (after ?? 0) - 1),
                "last_error": lastError ?? [:],
                "snapshot": state == "stopped" ? snapshot ?? [:] : NSNull(),
                "events": events.filter { $0.0 > (after ?? 0) }.map { ["id": $0.0, "event": $0.1] as [String: Any] }]
    }
}

public struct AndroidDebugOptions: Codable, Sendable, Equatable {
    public var device = ""
    public var package = ""
    public var pid = ""
    public var remotePath = ""
    public var serverPath = ""
    public var adbPath = ""
    public init() {}

    public func command(launch: Bool, arch: String) -> [String: Any] {
        ["mode": launch ? "android_launch" : "android_attach", "device": device, "package": package,
         "pid": Int(pid) ?? 0, "remote_path": remotePath,
         "server_path": serverPath.isEmpty ? Self.defaultServer(arch) : serverPath,
         "adb_path": adbPath.isEmpty ? Self.defaultADB : adbPath]
    }

    public static var defaultADB: String {
        ["/opt/homebrew/bin/adb", "/usr/local/bin/adb", NSHomeDirectory() + "/Library/Android/sdk/platform-tools/adb"]
            .first { FileManager.default.isExecutableFile(atPath: $0) } ?? "/opt/homebrew/bin/adb"
    }

    public static func defaultServer(_ arch: String) -> String {
        NSHomeDirectory() + "/Library/Application Support/Disassembler/Tools/android-\(arch)/lldb-server"
    }
}

public final class DebugController: @unchecked Sendable {
    let events = RuntimeEvents()
    private let session: LLDBSession

    public init(options: [String: Any], module: URL, analysis: Analysis,
                onEvent: @escaping @Sendable (DebugEvent) -> Void = { _ in }) throws {
        let command = try Self.startCommand(options, module: module, analysis: analysis)
        let log = events
        session = try LLDBSession { event in
            if let data = try? JSONEncoder().encode(event), let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                log.append(json)
            }
            onEvent(event)
        }
        session.send(command)
    }

    public func terminate() { session.terminate() }
    deinit { terminate() }

    public func send(_ command: [String: Any]) { session.send(command) }

    static func integer(_ value: Any?, name: String, range: ClosedRange<Int>) throws -> Int {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              let result = Int(number.stringValue), range.contains(result) else {
            throw MachOError(message: "\(name) must be an integer in \(range)")
        }
        return result
    }

    static func startCommand(_ a: [String: Any], module: URL, analysis: Analysis) throws -> [String: Any] {
        guard let mode = a["mode"] as? String, ["launch", "attach", "android_launch", "android_attach"].contains(mode) else {
            throw MachOError(message: "mode must be launch, attach, android_launch or android_attach")
        }
        let android = mode.hasPrefix("android_")
        guard android == analysis.macho.isELF else { throw MachOError(message: "ELF targets need an android_* mode; macOS targets need launch or attach") }
        var c: [String: Any] = ["cmd": mode, "module": module.path, "path": module.path,
                               "arch": analysis.macho.arch, "args": a["arguments"] as? String ?? ""]
        if !android, let executable = a["executable_path"] as? String {
            guard executable.hasPrefix("/"), FileManager.default.isExecutableFile(atPath: executable) else { throw MachOError(message: "executable_path must be a local executable") }
            c["path"] = executable
        }
        if mode.hasSuffix("attach") { c["pid"] = try integer(a["pid"], name: "pid", range: 1...Int(Int32.max)) }
        if let value = a["breakpoints"] {
            guard let specs = value as? [[String: Any]], specs.count <= 256 else { throw MachOError(message: "breakpoints must be an array of at most 256 entries") }
            c["breakpoints"] = try specs.map(Self.breakpoint)
        }
        if let value = a["environment"] {
            guard let env = value as? [String], env.allSatisfy({ $0.contains("=") && !$0.contains("\0") }) else { throw MachOError(message: "environment must contain KEY=VALUE strings") }
            c["env"] = env
        }
        if android {
            let adb = a["adb_path"] as? String ?? AndroidDebugOptions.defaultADB
            let server = a["server_path"] as? String ?? AndroidDebugOptions.defaultServer(analysis.macho.arch)
            guard adb.hasPrefix("/"), FileManager.default.isExecutableFile(atPath: adb) else { throw MachOError(message: "Set adb_path to an installed Android platform-tools adb executable") }
            guard server.hasPrefix("/"), FileManager.default.isReadableFile(atPath: server) else { throw MachOError(message: "Set server_path to the Android NDK lldb-server for the target ABI") }
            let package = a["package"] as? String ?? "", device = a["device"] as? String ?? ""
            guard package.isEmpty || package.range(of: "^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+$", options: .regularExpression) != nil else { throw MachOError(message: "Invalid Android package name") }
            guard !device.contains("\0"), device.count <= 256 else { throw MachOError(message: "Invalid device serial") }
            c.merge(["adb": adb, "server": server, "package": package, "device": device]) { _, new in new }
            if mode == "android_launch" {
                guard let path = a["remote_path"] as? String, path.hasPrefix("/"), !path.contains("\0") else { throw MachOError(message: "remote_path must be the absolute device path of an executable, not a .so") }
                c["remote_path"] = path
            }
        }
        return c
    }

    static func breakpoint(_ a: [String: Any]) throws -> [String: Any] {
        let spec: BreakpointSpec
        switch a["kind"] as? String {
        case "address":
            let address: UInt64?
            if let text = a["address"] as? String { address = UInt64(text.hasPrefix("0x") ? String(text.dropFirst(2)) : text, radix: 16) }
            else { address = (a["addr"] as? NSNumber).flatMap { CFGetTypeID($0) != CFBooleanGetTypeID() ? UInt64($0.stringValue) : nil } }
            guard let address else { throw MachOError(message: "address must be a hexadecimal file address") }
            spec = .address(address)
        case "symbol":
            guard let name = a["name"] as? String, !name.isEmpty, name.count <= 4096 else { throw MachOError(message: "A symbol breakpoint needs a name") }
            spec = .symbol(name)
        case "exception":
            guard let lang = a["lang"] as? String, ["cpp", "objc", "swift"].contains(lang) else { throw MachOError(message: "Unsupported exception language") }
            spec = .exception(lang)
        default: throw MachOError(message: "Breakpoint kind must be address, symbol or exception")
        }
        if let enabled = a["enabled"] {
            guard let number = enabled as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { throw MachOError(message: "enabled must be a boolean") }
        }
        return spec.command(enabled: a["enabled"] as? Bool ?? true)
    }

    func control(_ a: [String: Any]) throws -> [String: Any] {
        guard let action = a["action"] as? String,
              ["continue", "pause", "step", "next", "stepi", "nexti", "finish", "frame", "detach", "stop"].contains(action) else {
            throw MachOError(message: "Unknown debugger action")
        }
        var command: [String: Any] = ["cmd": action]
        if action == "frame" { command["index"] = try Self.integer(a["index"], name: "index", range: 0...99) }
        return request(command)
    }

    func memory(_ a: [String: Any]) throws -> [String: Any] {
        let size = try Self.integer(a["size"] ?? 256, name: "size", range: 1...65536)
        guard let expr = a["expression"] as? String, !expr.isEmpty, expr.count <= 4096 else { throw MachOError(message: "A memory expression is required") }
        return request(["cmd": "memory", "expr": expr, "size": size])
    }

    func request(_ command: [String: Any]) -> [String: Any] {
        let id = UUID().uuidString
        var command = command; command["requestID"] = id
        session.send(command)
        return ["accepted": true, "request_id": id]
    }
}
