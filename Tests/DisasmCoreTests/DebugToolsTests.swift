import Foundation
import Testing
@testable import DisasmCore

@Test func agentDebuggerToolsAreDiscoverable() throws {
    let reply = try #require(ProviderServer().handle(["id": 1, "method": "tools/list"])?["result"] as? [String: Any])
    let tools = try #require(reply["tools"] as? [[String: Any]])
    for name in ["debug_start", "debug_state", "debug_control", "debug_breakpoint", "debug_memory", "frida_attach", "frida_trace", "frida_events", "frida_detach"] {
        let tool = try #require(tools.first { $0["name"] as? String == name })
        let schema = try #require(tool["inputSchema"] as? [String: Any])
        #expect(schema["properties"] is [String: Any])
    }
}

@Test func runtimeEventsRetainStateAndReportLostHistory() throws {
    let events = RuntimeEvents()
    events.append(["event": "stopped", "pc": 42])
    for i in 0..<250 { events.append(["event": "output", "text": "\(i)"]) }
    let state = events.read(after: 0)
    #expect(state["cursor"] as? Int == 251)
    #expect(state["dropped"] as? Int == 51)
    #expect((state["events"] as? [Any])?.count == 200)
    #expect((state["snapshot"] as? [String: Any])?["pc"] as? Int == 42)
    events.append(["event": "error", "message": "Bad expression", "requestID": "request"])
    #expect(events.read()["state"] as? String == "stopped")
    events.append(["event": "running"])
    #expect(events.read()["snapshot"] is NSNull)
    #expect((events.read(after: 253)["events"] as? [Any])?.isEmpty == true)
}

@Test func runtimeValidatesAgentArguments() throws {
    for value: Any in [true, -1, 1.5, "2", Double.infinity, UInt64.max] {
        #expect(throws: MachOError.self) { _ = try DebugController.integer(value, name: "pid", range: 1...100) }
    }
    #expect(try DebugController.integer(Int.max, name: "cursor", range: 0...Int.max) == Int.max)
    #expect(throws: MachOError.self) { _ = try DebugController.integer(UInt64.max, name: "cursor", range: 0...Int.max) }
    #expect(throws: MachOError.self) { _ = try FridaSession.traceCommand(["module": "lib.so", "symbol": "f", "offset": "0x10"]) }
    #expect(throws: MachOError.self) { _ = try FridaSession.traceCommand(["module": "lib.so", "offset": "-1"]) }
    #expect(throws: MachOError.self) { _ = try FridaSession.traceCommand(["module": "lib.so", "symbol": "f", "argument_count": 9]) }
    #expect(throws: MachOError.self) { _ = try FridaSession.traceCommand(["action": "remove"]) }
    let command = try FridaSession.traceCommand(["module": "lib.so", "offset": "0x123", "argument_count": 0])
    #expect(command["offset"] as? String == "123")
    #expect(command["count"] as? Int == 0)
    #expect(command["function_start"] as? Bool == false)
    #expect(try FridaSession.traceCommand(["module": "lib.so", "offset": "10", "function_start": true])["function_start"] as? Bool == true)
}

@Test func fridaRejectsAmbiguousUSBDevices() throws {
    let harness = #"""
import sys, types, io
class Device:
    type = 'usb'
    def attach(self, pid): raise AssertionError('Must not attach to an ambiguous device')
manager = types.SimpleNamespace(enumerate_devices=lambda: [Device(), Device()])
sys.modules['frida'] = types.SimpleNamespace(get_device_manager=lambda: manager)
sys.stdin = io.StringIO('{"cmd":"attach","pid":42,"device":""}\n')
exec(sys.argv[1])
"""#
    let output = try Analysis.run("/usr/bin/python3", ["-c", harness, FridaSession.script])
    #expect(output.contains("Select exactly one connected USB Frida device"))
    #expect(!output.contains("Must not attach"))
}

@Test(.timeLimit(.minutes(1))) func agentCanDriveLocalDebugger() throws {
    let bin = try fixtureBinary(arch: "arm64", strip: false, optimize: false)
    defer { try? FileManager.default.removeItem(at: bin.deletingLastPathComponent()) }
    let server = ProviderServer()
    _ = try server.call("idb_open", ["input_path": bin.path])
    _ = try server.call("debug_start", ["mode": "launch", "breakpoints": [BreakpointSpec.symbol("helper").command(enabled: true)]])
    defer { _ = try? server.call("debug_control", ["action": "stop"]) }
    func waitFor(_ state: String) throws -> [String: Any] {
        for _ in 0..<20 {
            let result = try #require(try server.call("debug_state", ["wait_ms": 500]) as? [String: Any])
            if result["state"] as? String == state { return result }
            #expect(result["state"] as? String != "error", "\(result)")
        }
        Issue.record("Never reached \(state)")
        return [:]
    }
    let stopped = try waitFor("stopped")
    let snapshot = try #require(stopped["snapshot"] as? [String: Any])
    #expect((snapshot["frames"] as? [[String: Any]])?.isEmpty == false)
    #expect((snapshot["registers"] as? [[String]])?.isEmpty == false)
    let memory = try #require(try server.call("debug_memory", ["expression": "$pc", "size": 16]) as? [String: Any])
    let request = try #require(memory["request_id"] as? String)
    var received = false
    for _ in 0..<20 {
        let status = try #require(try server.call("debug_state", ["wait_ms": 100]) as? [String: Any])
        if let events = status["events"] as? [[String: Any]], events.contains(where: { ($0["event"] as? [String: Any])?["requestID"] as? String == request && (($0["event"] as? [String: Any])?["hex"] as? String)?.count == 32 }) {
            received = true; break
        }
    }
    #expect(received)
    #expect(throws: MachOError.self) { _ = try server.call("debug_control", ["action": "shell"]) }
    #expect(throws: MachOError.self) { _ = try server.call("debug_memory", ["expression": "$pc", "size": 0]) }
    _ = try server.call("debug_control", ["action": "continue"])
    _ = try waitFor("exited")
}

@Test(.timeLimit(.minutes(1))) func agentCanDebugLibraryInLocalHost() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("disasm-host-\(UUID())")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let library = directory.appendingPathComponent("libsample.dylib")
    let host = directory.appendingPathComponent("host")
    try "int helper(int n) { return n + 1; }".write(to: directory.appendingPathComponent("library.c"), atomically: true, encoding: .utf8)
    try "extern int helper(int); int main(void) { return helper(21); }".write(to: directory.appendingPathComponent("host.c"), atomically: true, encoding: .utf8)
    _ = try Analysis.run("/usr/bin/xcrun", ["clang", "-g", "-O0", "-dynamiclib", directory.appendingPathComponent("library.c").path, "-o", library.path])
    _ = try Analysis.run("/usr/bin/xcrun", ["clang", "-g", "-O0", directory.appendingPathComponent("host.c").path, library.path, "-o", host.path])
    let server = ProviderServer()
    defer { server.shutdown() }
    _ = try server.call("idb_open", ["input_path": library.path])
    _ = try server.call("debug_start", ["mode": "launch", "executable_path": host.path,
                                       "breakpoints": [["kind": "symbol", "name": "helper"]]])
    var cursor = 0
    for _ in 0..<20 {
        let result = try #require(try server.call("debug_state", ["after": cursor, "wait_ms": 500]) as? [String: Any])
        cursor = result["cursor"] as? Int ?? cursor
        if result["state"] as? String == "stopped" {
            let snapshot = try #require(result["snapshot"] as? [String: Any])
            #expect(snapshot["breakpoint"] as? String == "s:helper")
            #expect(snapshot["pc"] != nil)
            return
        }
        #expect(result["state"] as? String != "error", "\(result)")
    }
    Issue.record("Library breakpoint never stopped in its host executable")
}

@Test func fridaCommandsAfterHelperExitDoNotKillHost() throws {
    let session = try FridaSession(options: ["pid": 1, "python_path": "/usr/bin/false"])
    #expect(session.status(waitMS: 1000)["state"] as? String == "detached")
    usleep(100_000)
    // Without SIGPIPE ignored, writing to the exited helper terminates the test process.
    _ = try session.trace(["module": "lib.so", "symbol": "f"])
    _ = session.detach()
}
