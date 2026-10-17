import Foundation
import Testing
@testable import DisasmCore

private let source = """
#include <stdio.h>
#include <stdlib.h>
int g;
__attribute__((noinline)) int helper(int x) {
  int doubled = x * 2;
  const char *mode = getenv("FIXTURE_MODE");
  printf("mode=%s doubled=%d\\n", mode ? mode : "none", doubled);
  return doubled + 1;
}
__attribute__((noinline)) int loop(int n, int *a) {
  int s = 0;
  for (int i = 0; i < n; i++) { if (a[i] > 3) s += a[i]; else s -= 1; }
  while (s > 100) s /= 2;
  g = s;
  return s;
}
int main(int argc, char **argv) { puts("hello-from-fixture"); return helper(argc) + loop(argc, (int *)argv); }
"""

private func build(_ arch: String, _ opt: String) throws -> Analysis {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("decomp-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let src = dir.appendingPathComponent("d.c"), bin = dir.appendingPathComponent("d")
    try source.write(to: src, atomically: true, encoding: .utf8)
    _ = try Analysis.run("/usr/bin/xcrun", ["clang", opt, "-arch", arch, src.path, "-o", bin.path])
    return try Analysis(slice: MachO.slices(of: Data(contentsOf: bin))[0])
}

private func code(_ a: Analysis, _ name: String) throws -> String {
    Decompiler.decompile(a, try #require(a.functions.first { $0.name == name })).joined(separator: "\n")
}

@Test(arguments: ["arm64", "x86_64"], ["-O0", "-O1"])
func decompiles(arch: String, opt: String) throws {
    let a = try build(arch, opt)
    let helper = try code(a, "_helper"), loop = try code(a, "_loop"), main = try code(a, "_main")
    if ProcessInfo.processInfo.environment["DUMP_PSEUDO"] != nil { print("=== \(arch) \(opt)\n\(helper)\n\(loop)\n\(main)") }
    for c in [helper, loop, main] {
        #expect(!c.contains("asm {"), "\(c)")
        #expect(!c.contains("goto"), "\(c)")
    }
    #expect(helper.contains("getenv(\"FIXTURE_MODE\")"), "\(helper)")
    #expect(helper.contains("printf(\"mode=%s doubled=%d\\n\""), "\(helper)")
    #expect(main.contains("puts(\"hello-from-fixture\")"), "\(main)")
    #expect(main.contains("helper(") && main.contains("loop("), "\(main)")
    #expect(loop.contains("while") || loop.contains("do {"), "\(loop)")
    #expect(loop.contains("g = "), "\(loop)")
}

@Test func decompilesObjectiveC() throws {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("decomp-objc-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let src = dir.appendingPathComponent("o.m"), bin = dir.appendingPathComponent("o")
    try """
    #import <Foundation/Foundation.h>
    @interface Greeter : NSObject
    - (NSString *)greet:(int)n;
    @end
    @implementation Greeter
    - (NSString *)greet:(int)n { return [NSString stringWithFormat:@"hello %d", n]; }
    - (NSString *)description { return [[super description] stringByAppendingString:@"!"]; }
    @end
    __attribute__((noinline)) int both(int a, int b) { return a == 3 && b == 4; }
    int main(void) { @autoreleasepool { NSLog(@"%@ %d", [[Greeter new] greet:2], both(3, 4)); } return 0; }
    """.write(to: src, atomically: true, encoding: .utf8)
    _ = try Analysis.run("/usr/bin/xcrun", ["clang", "-O1", "-fobjc-arc", "-arch", "arm64", "-framework", "Foundation", src.path, "-o", bin.path])
    let a = try Analysis(slice: MachO.slices(of: Data(contentsOf: bin))[0])
    #expect(!a.macho.binds.isEmpty, "chained fixups decoded")
    let greet = try code(a, "-[Greeter greet:]"), desc = try code(a, "-[Greeter description]"), both = try code(a, "_both")
    #expect(greet.contains("[NSString stringWithFormat:@\"hello %d\""), "\(greet)")
    #expect(desc.contains("[super description]") && desc.contains("stringByAppendingString:@\"!\""), "\(desc)")
    #expect(both.contains("&&") && !both.contains("asm"), "\(both)")
}

/// Bugs found in the audit: each one used to drop or invent data flow.
@Test(arguments: ["arm64", "x86_64"])
func decompilerRegressions(arch: String) throws {
    func build(_ src: String, _ opt: String) throws -> Analysis {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("decomp-reg-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let c = dir.appendingPathComponent("r.c"), bin = dir.appendingPathComponent("r.dylib")
        try src.write(to: c, atomically: true, encoding: .utf8)
        _ = try Analysis.run("/usr/bin/xcrun", ["clang", opt, "-arch", arch, "-dynamiclib", "-undefined", "dynamic_lookup", c.path, "-o", bin.path])
        return try Analysis(slice: MachO.slices(of: Data(contentsOf: bin))[0])
    }
    let a = try build("""
    extern int g1(int);
    const char *msg = "initial";
    __attribute__((noinline)) double fret(double a, double b) { return a * b + 1.0; }
    __attribute__((noinline)) int sw(int x, int y) { int k = y * 3; switch (x) { case 0: return k; case 1: return k + 1; case 2: return k * 2; case 3: return k - 7; case 4: return k ^ 5; case 5: return k | 9; default: return 0; } }
    __attribute__((noinline)) const char *getmsg(void) { return msg; }
    __attribute__((noinline)) int fcmp(double a, double b) { return a < b ? g1(1) : g1(2); }
    """, "-O1")
    let fret = try code(a, "_fret"), sw = try code(a, "_sw"), getmsg = try code(a, "_getmsg"), fcmp = try code(a, "_fcmp")
    #expect(fret.contains("return") && fret.contains("*") && !fret.hasPrefix("void"), "float result kept: \(fret)")
    // x86 dispatches through a jump table: `rax = y * 3` must survive the computed jump.
    #expect(arch == "x86_64" ? sw.contains("rax = rsi + rsi * 2") : sw.contains("arg1 + (arg1 << 1)"), "value used by switch cases kept: \(sw)")
    #expect(getmsg.contains("return msg;"), "mutable global is read, not replaced by its initializer: \(getmsg)")
    #expect(!fcmp.contains("cmp_l") && !fcmp.contains("asm"), "float compare modelled: \(fcmp)")

    if arch == "x86_64" {
        let oz = try build("extern int g1(int);\n__attribute__((noinline)) int five(void) { return g1(5) + 3; }", "-Oz")
        #expect(try code(oz, "_five").contains("g1(5)"), "push $5; pop %rdi")
    }
}
