import Foundation

extension ProviderServer {
    static let runtimeTools: [(name: String, description: String)] = [
        ("android_targets", "List ADB devices and process PIDs/names on the selected authorized device. Select device when more than one is connected. Use an authorized PID with debug_start or frida_attach. Does not require an analysis session."),
        ("debug_start", "Start LLDB for the selected analysis session. Android modes deploy an ABI-matching lldb-server through ADB; package uses run-as for a debuggable app. android_launch runs an existing device executable, android_attach attaches to a PID. A .so itself is not executable. Use debug_state to await stops."),
        ("debug_state", "Read debugger state, stopped-thread frames/registers/variables and cursor-based events. File addresses match the analyzed binary; frame pc values are runtime addresses. Retains 200 events and reports dropped events. Poll after=cursor with wait_ms up to 1000."),
        ("debug_control", "Continue, pause, step, next, stepi, nexti, finish, select frame, detach, or stop. Stop kills only a process launched by this session; attached processes are detached. Returns request_id; debug_state reports completion/events."),
        ("debug_breakpoint", "Set, enable/disable or remove an address, symbol or exception breakpoint. Addresses are hexadecimal file addresses, not runtime addresses. Use the returned id to remove a breakpoint."),
        ("debug_memory", "Read 1–65536 bytes from a stopped process. expression is a runtime address, register such as $pc, or LLDB expression. The memory event in debug_state carries the matching requestID, address and hex bytes or error."),
        ("frida_attach", "Attach Frida to an authorized PID through USB (device ID optional) or an existing localhost port forward to Frida Server/Gadget. Requires matching Frida Python bindings and target server/Gadget. Does not root or modify app packages. Poll frida_events for attached/modules or errors."),
        ("frida_trace", "Add/remove a native function trace. Supply loaded module name and either exported symbol or hex offset from module base (not a file offset). Captures 0–8 raw pointer-sized arguments and, at function entries, the return value. Offsets that are not exports or functions in this analysis report retval null unless function_start is true; set it only for a real function entry, since a mid-function return hook can crash the target. Distinct traces must be 16+ bytes apart. At most 64 hooks and 100 calls/sec; dropped events are reported. No Java hooks or stepping; use LLDB for breakpoints/stepping."),
        ("frida_events", "Read Frida status and cursor-based events: attached includes loaded modules, hook confirms runtime address, trace includes thread/args/retval, error includes requestID. Retains 200 events, reports buffer drops and sampling drops. Poll after=cursor."),
        ("frida_detach", "Unload this session's Frida hooks and detach without terminating the target process."),
    ]

    static func runtimeSchema(_ name: String) -> [String: Any]? {
        let string: [String: Any] = ["type": "string"]
        let integer: [String: Any] = ["type": "integer"]
        var p: [String: Any] = ["database": ["type": "string", "description": "Analysis session_id returned by idb_open; defaults to most recent session."]]
        var required: [String] = []
        switch name {
        case "android_targets":
            p = ["adb_path": string, "device": string]
        case "debug_start":
            p.merge(["mode": ["type": "string", "enum": ["launch", "attach", "android_launch", "android_attach"]],
                     "pid": ["type": "integer", "minimum": 1], "device": string, "package": string,
                     "remote_path": string, "server_path": string, "adb_path": string, "arguments": string,
                     "executable_path": ["type": "string", "description": "Local macOS host executable when analyzing a library; defaults to the input binary"],
                     "environment": ["type": "array", "items": string, "description": "Local macOS launch only: KEY=VALUE entries"],
                     "breakpoints": ["type": "array", "maxItems": 256, "items": ["type": "object", "properties": breakpointProperties]]]) { _, n in n }
            required = ["mode"]
        case "debug_state":
            p["after"] = ["type": "integer", "minimum": 0]
            p["wait_ms"] = ["type": "integer", "minimum": 0, "maximum": 1000]
        case "debug_control":
            p["action"] = ["type": "string", "enum": ["continue", "pause", "step", "next", "stepi", "nexti", "finish", "frame", "detach", "stop"]]
            p["index"] = integer
            required = ["action"]
        case "debug_breakpoint":
            p.merge(breakpointProperties) { _, n in n }
            p["action"] = ["type": "string", "enum": ["set", "remove"]]
            p["id"] = string
            required = ["action"]
        case "debug_memory":
            p["expression"] = string
            p["size"] = ["type": "integer", "minimum": 1, "maximum": 65536]
            required = ["expression"]
        case "frida_attach":
            p.merge(["pid": ["type": "integer", "minimum": 1], "device": string,
                     "port": ["type": "integer", "minimum": 1, "maximum": 65535], "python_path": string]) { _, n in n }
            required = ["pid"]
        case "frida_trace":
            p.merge(["action": ["type": "string", "enum": ["add", "remove"]], "id": string,
                     "module": string, "symbol": string, "offset": string,
                     "argument_count": ["type": "integer", "minimum": 0, "maximum": 8], "function_start": ["type": "boolean"]]) { _, n in n }
        case "frida_events":
            p["after"] = ["type": "integer", "minimum": 0]
            p["wait_ms"] = ["type": "integer", "minimum": 0, "maximum": 1000]
        case "frida_detach": break
        default: return nil
        }
        return ["type": "object", "properties": p, "required": required, "additionalProperties": false]
    }

    static var breakpointProperties: [String: Any] {
        ["kind": ["type": "string", "enum": ["address", "symbol", "exception"]],
         "address": ["type": "string", "description": "Hexadecimal file address, e.g. 0x430"],
         "name": ["type": "string"], "lang": ["type": "string", "enum": ["cpp", "objc", "swift"]], "enabled": ["type": "boolean"]]
    }

    func runtimeCall(_ name: String, _ a: [String: Any]) throws -> Any {
        if name == "android_targets" {
            let adb = a["adb_path"] as? String ?? AndroidDebugOptions.defaultADB
            guard adb.hasPrefix("/"), FileManager.default.isExecutableFile(atPath: adb) else { throw MachOError(message: "Set adb_path to the platform-tools adb executable") }
            let lines = try Analysis.run(adb, ["devices"]).split(separator: "\n").dropFirst()
            let devices = lines.compactMap { line -> [String: String]? in
                let parts = line.split(whereSeparator: \.isWhitespace)
                guard parts.count >= 2 else { return nil }
                return ["id": String(parts[0]), "status": String(parts[1])]
            }
            let ready = devices.filter { $0["status"] == "device" }
            let selected = a["device"] as? String ?? (ready.count == 1 ? ready[0]["id"] : nil)
            guard let selected else { return ["devices": devices, "processes": []] as [String: Any] }
            guard ready.contains(where: { $0["id"] == selected }) else { throw MachOError(message: "Select an authorized connected device") }
            let rows = try Analysis.run(adb, ["-s", selected, "shell", "ps -A -o PID,NAME"]).split(separator: "\n").dropFirst()
            let processes = rows.compactMap { line -> [String: Any]? in
                let parts = line.split(maxSplits: 1, whereSeparator: \.isWhitespace)
                guard parts.count == 2, let pid = Int(parts[0]) else { return nil }
                return ["pid": pid, "name": parts[1].trimmingCharacters(in: .whitespaces)]
            }
            return ["devices": devices, "selected": selected, "processes": processes] as [String: Any]
        }
        let s = try session(a)
        if name == "frida_attach" {
            if let tracer = tracers[s.id], ["starting", "attached"].contains(tracer.status()["state"] as? String ?? "") {
                throw MachOError(message: "Detach the current Frida session first")
            }
            tracers.removeValue(forKey: s.id)?.terminate()
            tracers[s.id] = try FridaSession(options: a)
            return ["accepted": true, "session_id": s.id]
        }
        if name.hasPrefix("frida_") {
            guard let tracer = tracers[s.id] else { throw MachOError(message: "Call frida_attach first") }
            switch name {
            case "frida_trace":
                // An offset at a function this analysis knows is safe to trace to its return.
                var a = a
                if a["module"] as? String == URL(fileURLWithPath: s.inputPath).lastPathComponent,
                   let offset = a["offset"] as? String, let n = UInt64(offset.hasPrefix("0x") ? String(offset.dropFirst(2)) : offset, radix: 16),
                   s.analysis.functions.contains(where: { $0.start == n }) { a["function_start"] = true }
                return try tracer.trace(a)
            case "frida_detach":
                return tracer.detach()
            default:
                let after = try a["after"].map { try DebugController.integer($0, name: "after", range: 0...Int.max) }
                let wait = try DebugController.integer(a["wait_ms"] ?? 0, name: "wait_ms", range: 0...1000)
                return tracer.status(after: after, waitMS: wait)
            }
        }
        if name == "debug_start" {
            if let current = debuggers[s.id], ["starting", "stopped", "running"].contains(current.events.read()["state"] as? String ?? "") {
                throw MachOError(message: "A debugger is already active for this session; stop or detach it first")
            }
            debuggers.removeValue(forKey: s.id)?.terminate()
            let picked = URL(fileURLWithPath: s.inputPath)
            debuggers[s.id] = try DebugController(options: a, module: Bundle(url: picked)?.executableURL ?? picked, analysis: s.analysis)
            return ["accepted": true, "session_id": s.id, "state": "starting"]
        }
        guard let debugger = debuggers[s.id] else { throw MachOError(message: "No debugger for this analysis session; call debug_start first") }
        switch name {
        case "debug_state":
            let after = try a["after"].map { try DebugController.integer($0, name: "after", range: 0...Int.max) }
            let wait = try DebugController.integer(a["wait_ms"] ?? 0, name: "wait_ms", range: 0...1000)
            return debugger.events.read(after: after, waitMS: wait)
        case "debug_control": return try debugger.control(a)
        case "debug_memory": return try debugger.memory(a)
        case "debug_breakpoint":
            if a["action"] as? String == "remove" {
                guard let id = a["id"] as? String, !id.isEmpty else { throw MachOError(message: "Breakpoint id is required") }
                return debugger.request(["cmd": "bp_remove", "id": id])
            }
            guard a["action"] as? String == "set" else { throw MachOError(message: "Breakpoint action must be set or remove") }
            let command = try DebugController.breakpoint(a)
            return debugger.request(command).merging(["id": command["id"]!]) { _, n in n }
        default: throw MachOError(message: "Unknown runtime tool \(name)")
        }
    }
}
