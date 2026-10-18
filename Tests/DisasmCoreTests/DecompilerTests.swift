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
@Test(arguments: ["arm64", "arm64e", "x86_64"])
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
    #expect(arch == "x86_64" ? sw.contains("rax = rsi + rsi * 2") || sw.contains("rax = arg1 + arg1 * 2") : sw.contains("arg1 + (arg1 << 1)"),
            "value used by switch cases kept: \(sw)")
    #expect(getmsg.contains("return msg;"), "mutable global is read, not replaced by its initializer: \(getmsg)")
    #expect(!fcmp.contains("cmp_l") && !fcmp.contains("asm"), "float compare modelled: \(fcmp)")

    // Jump tables become a switch (x86 tables live in __text and must not be decoded as code); case 8 falls into 9.
    let sw2 = try build("""
    extern int g1(int);
    __attribute__((noinline)) int sw(int x, int y) { switch (x) { case 1: return g1(y); case 2: return g1(y + 1); case 3: return y * 2; case 4: return g1(y - 7); case 5: return y ^ 5; case 6: return g1(9); case 7: return g1(y*y); case 8: y += 4; case 9: return y | 1; case 10: return g1(3); case 11: return g1(y+11); default: return 0; } }
    #include <string.h>
    __attribute__((noinline)) long inner(long a, long b, long c) { return a * b - c; }
    __attribute__((noinline)) long outer(long a, long b, long c) { return inner(a, b, c) + 1; }
    __attribute__((noinline)) size_t len(const char *s) { return strlen(s) + 1; }
    """, "-O2")
    let switchCode = try code(sw2, "_sw")
    #expect(switchCode.contains("switch (arg0) {") && switchCode.contains("case 8:") && switchCode.contains("case 9:")
            && !switchCode.contains("goto *") && !switchCode.contains("asm"), "\(switchCode)")
    // Arguments passed through untouched come from the callee's signature (internal or a known C function).
    #expect(try code(sw2, "_outer").contains("inner(arg0, arg1, arg2)"))
    #expect(try code(sw2, "_len").contains("strlen(arg0)"))

    if arch == "x86_64" {
        let oz = try build("extern int g1(int);\n__attribute__((noinline)) int five(void) { return g1(5) + 3; }", "-Oz")
        #expect(try code(oz, "_five").contains("g1(5)"), "push $5; pop %rdi")
    }
}

/// `ccmp` folds into the flag pair for one condition (and its complement); a reader asking anything else gets asm.
@Test func conditionalCompareAnswersOneQuestion() throws {
    let a = try Analysis(slice: fixture(arch: "arm64", strip: false))
    let d = FunctionDecompiler(a, a.functions[0])
    var next: UInt64 = 0x1000
    func ins(_ m: String, _ o: String) -> Instruction {
        next += 4
        return Instruction(address: next, bytes: "", mnemonic: m, operands: o, comment: "", target: nil)
    }
    let ccmp = ins("ccmp", "x1, #0x2, #0x0, eq")
    let folded = { (s: [Stmt]) in s.contains { if case .set("cmp_t", _) = $0.kind { true } else { false } } }
    #expect(folded(d.liftARM(ccmp, following: [ins("b.ne", "0x10"), ins("cset", "w0, eq")][...])))
    #expect(!folded(d.liftARM(ccmp, following: [ins("b.ne", "0x10"), ins("cset", "w0, lt")][...])))
    #expect(folded(d.liftARM(ccmp, following: [ins("b.ne", "0x10"), ins("cmp", "x3, #0x1"), ins("cset", "w0, lt")][...])),
            "a later compare ends the old flags")
}

/// Flag readers are found along the fallthrough and at conditional-branch targets, up to the next flag write.
@Test func flagReadersFollowBranches() {
    func ins(_ addr: UInt64, _ m: String, _ o: String, _ t: UInt64? = nil) -> Instruction {
        Instruction(address: addr, bytes: "", mnemonic: m, operands: o, comment: "", target: t)
    }
    let code = [ins(0, "b.ne", "0x20", 0x20), ins(4, "cset", "w0, eq"), ins(8, "cmp", "x1, #0x3"), ins(12, "cset", "w2, lt"),
                ins(0x20, "csel", "x0, x1, x2, lt"), ins(0x24, "ret", "")]
    let at = { (a: UInt64) -> ArraySlice<Instruction>? in code.firstIndex { $0.address == a }.map { code[$0...] } }
    #expect(FunctionDecompiler.flagReaders(code[...], at).sorted() == ["eq", "lt", "ne"], "lt at the branch target, not after the cmp")
}

/// x29 is the frame pointer on Apple arm64: Swift's async-frame marking of it is not program data.
@Test func framePointerWritesAreBookkeeping() throws {
    let a = try Analysis(slice: fixture(arch: "arm64", strip: false))
    let d = FunctionDecompiler(a, a.functions[0])
    let orr = Instruction(address: 0x1000, bytes: "", mnemonic: "orr", operands: "x29, x29, #0x1000000000000000", comment: "", target: nil)
    #expect(d.liftARM(orr, following: [][...]).isEmpty)
}
