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
    #expect(first.file.hasSuffix("/t.c") && first.line == 2)
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

@Test(.timeLimit(.minutes(1))) func debuggerStopsAtBreakpointAndExits() async throws {
    let bin = try fixtureBinary(arch: "arm64", strip: false)
    let a = try Analysis(slice: MachO.slices(of: Data(contentsOf: bin))[0])
    let (helper, _) = try helperAndMain(a)
    let (events, sink) = AsyncStream.makeStream(of: DebugEvent.self)
    let session = try LLDBSession { sink.yield($0) }
    session.send(["cmd": "launch", "path": bin.path, "module": bin.path, "arch": "arm64", "breakpoints": [helper.start]])
    var stopped: DebugEvent?, exited: DebugEvent?, output = ""
    for await e in events {
        switch e.event {
        case "stopped" where stopped == nil:
            stopped = e
            session.send(["cmd": "continue"])
        case "exited": exited = e
        case "output": output += e.text ?? ""
        case "error": Issue.record("debugger error: \(e.message ?? "")")
        default: break
        }
        if exited != nil { break }
    }
    session.terminate()
    let stop = try #require(stopped, "never stopped; output: \(output)")
    #expect(stop.pc == helper.start)
    // main tail-calls helper (`b _helper`), so helper's frame is the only one in this binary.
    #expect(stop.frames?.first?.fileAddr == helper.start && stop.frames?.first?.function == "helper")
    #expect(stop.registers?.contains { $0.first == "x0" } == true)
    #expect(output.contains("hello-from-fixture"))
    #expect(exited?.code == 3, "helper(argc=1) returns 3")
}
