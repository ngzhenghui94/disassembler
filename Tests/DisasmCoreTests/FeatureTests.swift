import Foundation
import Testing
@testable import DisasmCore

private func helperAndMain(_ a: Analysis) throws -> (helper: Function, main: Function) {
    let main = try #require(a.functions.first { $0.name == "_main" })
    let helper = try #require(a.functions.first { $0.name == "_helper" })
    return (helper, main)
}

@Test func crashReportMapsFramesToThisBuild() throws {
    let a = try Analysis(slice: fixture(arch: "arm64", strip: false))
    let (helper, main) = try helperAndMain(a)
    let uuid = try #require(a.macho.uuid).uuidString.lowercased()
    let ips = """
    {"app_name":"t","app_version":"1.0","bug_type":"309"}
    {"procName":"t","procPath":"/tmp/t","exception":{"type":"EXC_BAD_ACCESS","signal":"SIGSEGV","subtype":"KERN_INVALID_ADDRESS at 0x0"},
     "usedImages":[{"name":"t","uuid":"\(uuid)","path":"/tmp/t"},{"name":"libsystem_c.dylib","uuid":"11111111-2222-3333-4444-555555555555"}],
     "threads":[{"id":1,"frames":[{"imageIndex":1,"imageOffset":16}]},
                {"triggered":true,"queue":"com.apple.main-thread","frames":[{"imageIndex":0,"imageOffset":\(helper.start - a.macho.textBase)},{"imageIndex":0,"imageOffset":\(main.start + 8 - a.macho.textBase)}]}]}
    """
    let report = try CrashReport(data: Data(ips.utf8))
    #expect(report.title == "t 1.0")
    #expect(report.exception.contains("EXC_BAD_ACCESS SIGSEGV"))
    #expect(report.contains(a.macho))
    let crashed = try #require(report.threads.first)
    #expect(crashed.crashed && crashed.title.contains("main-thread"))
    #expect(report.address(of: crashed.frames[0], in: a.macho) == helper.start)
    #expect(a.function(containing: try #require(report.address(of: crashed.frames[1], in: a.macho)))?.name == "_main")
    #expect(report.address(of: report.threads[1].frames[0], in: a.macho) == nil, "frame from another image")
    #expect(throws: MachOError.self) { try CrashReport(data: Data("{}\n{}".utf8)) }
}

@Test func sourceLinesFromDebugMap() throws {
    let bin = try fixtureBinary(arch: "arm64", strip: false)
    let a = try Analysis(slice: MachO.slices(of: Data(contentsOf: bin))[0])
    let (helper, _) = try helperAndMain(a)
    let info = SourceLines.debugInfo(for: bin, bundle: nil, uuid: a.macho.uuid)
    let lines = SourceLines.lookup(a.instructions[helper.lines].map(\.address), debugInfo: info, arch: "arm64", loadAddress: a.macho.textBase)
    let first = try #require(lines[helper.start])
    #expect(first.file.hasSuffix("/t.c") && first.line == 3)
}

@Test func bundleBinaries() throws {
    let bin = try fixtureBinary(arch: "arm64", strip: false)
    let app = bin.deletingLastPathComponent().appendingPathComponent("Foo.app")
    let fm = FileManager.default
    for d in ["Contents/MacOS", "Contents/Frameworks/Bar.framework/Versions/A", "Contents/Resources"] {
        try fm.createDirectory(at: app.appendingPathComponent(d), withIntermediateDirectories: true)
    }
    try fm.copyItem(at: bin, to: app.appendingPathComponent("Contents/MacOS/Foo"))
    try fm.copyItem(at: bin, to: app.appendingPathComponent("Contents/Frameworks/Bar.framework/Versions/A/Bar"))
    try fm.createSymbolicLink(atPath: app.appendingPathComponent("Contents/Frameworks/Bar.framework/Bar").path, withDestinationPath: "Versions/A/Bar")
    try Data(repeating: 0x41, count: 10_000).write(to: app.appendingPathComponent("Contents/Resources/big.txt"))
    try #"<plist version="1.0"><dict><key>CFBundleExecutable</key><string>Foo</string></dict></plist>"#
        .write(to: app.appendingPathComponent("Contents/Info.plist"), atomically: true, encoding: .utf8)
    let found = MachO.binaries(inBundle: app).map(\.lastPathComponent)
    #expect(found == ["Foo", "Bar"])
}

/// Collects helper events, answering each stop with the next command until the process exits.
private func debugRun(_ launch: [String: Any], onStop: @escaping (DebugEvent, Int) -> [String: Any]?) async throws -> (stops: [DebugEvent], other: [DebugEvent], output: String, exit: DebugEvent?) {
    let (events, sink) = AsyncStream.makeStream(of: DebugEvent.self)
    let session = try LLDBSession { sink.yield($0) }
    defer { session.terminate() }
    session.send(launch)
    var stops: [DebugEvent] = [], other: [DebugEvent] = [], output = ""
    for await e in events {
        switch e.event {
        case "stopped":
            stops.append(e)
            session.send(onStop(e, stops.count) ?? ["cmd": "continue"])
        case "exited": return (stops, other, output, e)
        case "output": output += e.text ?? ""
        case "running": break
        default:
            other.append(e)
            if e.event == "memory" { session.send(["cmd": "continue"]) }
        }
    }
    return (stops, other, output, nil)
}

@Test(.timeLimit(.minutes(1))) func debuggerStopsAtBreakpointAndExits() async throws {
    let bin = try fixtureBinary(arch: "arm64", strip: false)
    let a = try Analysis(slice: MachO.slices(of: Data(contentsOf: bin))[0])
    let (helper, _) = try helperAndMain(a)
    let run = try await debugRun(["cmd": "launch", "path": bin.path, "module": bin.path, "arch": "arm64",
                                  "breakpoints": [BreakpointSpec.address(helper.start).command(enabled: true)]]) { _, _ in nil }
    let stop = try #require(run.stops.first, "never stopped; output: \(run.output)")
    #expect(run.other.filter { $0.event == "error" }.isEmpty, "\(run.other.map { $0.message ?? "" })")
    #expect(stop.pc == helper.start)
    // main tail-calls helper (`b _helper`), so helper's frame is the only one in this binary.
    #expect(stop.frames?.first?.fileAddr == helper.start && stop.frames?.first?.function == "helper")
    #expect(stop.breakpoint == BreakpointSpec.address(helper.start).id)
    #expect(stop.registers?.contains { $0.first == "x0" } == true)
    #expect(run.output.contains("hello-from-fixture"))
    #expect(run.exit?.code == 3, "helper(argc=1) returns 1 * 2 + 1")
}

@Test(.timeLimit(.minutes(1))) func debuggerLineStepsVariablesMemoryAndLaunchOptions() async throws {
    let bin = try fixtureBinary(arch: "arm64", strip: false, optimize: false)
    let run = try await debugRun(["cmd": "launch", "path": bin.path, "module": bin.path, "arch": "arm64",
                                  "args": "one 'two words'", "env": ["FIXTURE_MODE=testing"],
                                  "breakpoints": [BreakpointSpec.symbol("helper").command(enabled: true),
                                                  BreakpointSpec.symbol("never_called_symbol").command(enabled: false),
                                                  BreakpointSpec.exception("objc").command(enabled: true)]]) { _, n in
        switch n {
        case 1: ["cmd": "next"]                      // over `int doubled = x * 2;`
        case 2: ["cmd": "frame", "index": 1]         // select main's frame
        case 3: ["cmd": "memory", "expr": "sp", "size": 32]
        default: nil
        }
    }
    #expect(run.other.filter { $0.event == "error" }.isEmpty, "\(run.other.map { $0.message ?? "" })")
    try #require(run.stops.count >= 3, "stops: \(run.stops.map { $0.reason ?? "" }); output: \(run.output)")
    let atHelper = run.stops[0], stepped = run.stops[1], inMain = run.stops[2]
    #expect(atHelper.breakpoint == "s:helper")
    #expect(atHelper.variables?.first { $0.name == "x" }?.value == "3", "argc is 3: program, one, 'two words'")
    let firstLine = try #require(atHelper.frames?.first?.line), nextLine = try #require(stepped.frames?.first?.line)
    #expect(firstLine == "t.c:4" && nextLine == "t.c:5", "\(firstLine) -> \(nextLine)")
    #expect(stepped.variables?.first { $0.name == "doubled" }?.value == "6")
    #expect(inMain.selectedFrame == 1 && inMain.variables?.contains { $0.name == "argc" } == true)
    let mem = try #require(run.other.first { $0.event == "memory" })
    #expect(mem.hex?.count == 64 && mem.addr?.hasPrefix("0x") == true, "\(mem.message ?? "")")
    #expect(run.output.contains("mode=testing doubled=6"))
    #expect(run.exit?.code == 7)
}

@Test func hexDump() {
    #expect(HexDump.bytes(fromHex: "0aff10") == [0x0a, 0xff, 0x10])
    #expect(HexDump.bytes(fromHex: "abc") == nil && HexDump.bytes(fromHex: "zz") == nil)
    let bytes = Array("Hello, memory!\n\0ABC".utf8)
    let lines = HexDump.format(0x16fdff000, bytes).split(separator: "\n")
    #expect(lines.count == 2)
    #expect(lines[0] == "000000016fdff000  48 65 6c 6c 6f 2c 20 6d 65 6d 6f 72 79 21 0a 00  Hello, memory!..")
    #expect(lines[1] == "000000016fdff010  41 42 43                                         ABC")
}
