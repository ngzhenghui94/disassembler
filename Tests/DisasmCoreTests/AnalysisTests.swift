import Foundation
import Testing
@testable import DisasmCore

/// Compiles a tiny C program and checks the whole pipeline: parsing, functions, calls, string xrefs.
func fixtureBinary(arch: String, strip: Bool, optimize: Bool = true) throws -> URL {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("disasm-test-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let src = dir.appendingPathComponent("t.c"), bin = dir.appendingPathComponent("t")
    try """
    #include <stdio.h>
    #include <stdlib.h>
    __attribute__((noinline)) int helper(int x) {
      int doubled = x * 2;
      const char *mode = getenv("FIXTURE_MODE");
      printf("mode=%s doubled=%d\\n", mode ? mode : "none", doubled);
      return doubled + 1;
    }
    int main(int argc, char **argv) { puts("hello-from-fixture"); return helper(argc); }
    """.write(to: src, atomically: true, encoding: .utf8)
    // Separate compile and link: debug info stays in t.o behind the binary's debug map, like an Xcode Debug build.
    _ = try Analysis.run("/usr/bin/xcrun", ["clang", "-g", optimize ? "-O1" : "-O0", "-arch", arch, "-c", src.path, "-o", dir.appendingPathComponent("t.o").path])
    _ = try Analysis.run("/usr/bin/xcrun", ["clang", "-arch", arch, dir.appendingPathComponent("t.o").path, "-o", bin.path])
    if strip { _ = try Analysis.run("/usr/bin/xcrun", ["strip", bin.path]) }
    return bin
}

func fixture(arch: String, strip: Bool) throws -> ArchSlice {
    try MachO.slices(of: Data(contentsOf: fixtureBinary(arch: arch, strip: strip)))[0]
}

@Test(arguments: ["arm64", "x86_64"], [false, true])
func pipeline(arch: String, strip: Bool) throws {
    let a = try Analysis(slice: fixture(arch: arch, strip: strip))
    #expect(a.macho.arch == arch)

    let entry = try #require(a.macho.entry)
    let main = try #require(a.function(containing: entry))
    if !strip { #expect(main.name == "_main") }

    let str = try #require(a.strings.first { $0.value == "hello-from-fixture" })
    let strRefs = a.xrefs[str.address] ?? []
    #expect(strRefs.contains { main.start <= $0 && $0 < main.end }, "string xref from main")
    #expect(a.instructions[main.lines].contains { $0.comment.contains("hello-from-fixture") })

    // main calls helper directly and puts through a stub.
    let calls = a.instructions[main.lines].compactMap(\.target)
    let helper = try #require(calls.compactMap { t in a.functions.first { $0.start == t && $0.start != main.start } }.first)
    if !strip { #expect(helper.name == "_helper") }
    #expect(a.xrefs[helper.start]?.isEmpty == false)
    #expect(a.imports.contains { $0.name == "_puts" })
}

@Test func fatBinary() throws {
    let slices = try MachO.slices(of: Data(contentsOf: URL(fileURLWithPath: "/bin/ls")))
    #expect(slices.count >= 2)
    #expect(Set(slices.map(\.arch)).count == slices.count)
}

@Test func rejectsGarbage() {
    #expect(throws: MachOError.self) { try MachO.slices(of: Data("not a binary".utf8)) }
    #expect(throws: MachOError.self) { try MachO.slices(of: Data([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 1])) }
}
