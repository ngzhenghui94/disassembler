import Foundation
import Testing
@testable import DisasmCore

@Test func signaturesValidateAndDecode() throws {
    let signature = try FunctionSignature(returnType: .pointer, parameters: [FunctionParameter(name: "buffer", type: .pointer)])
    #expect(try JSONDecoder().decode(FunctionSignature.self, from: JSONEncoder().encode(signature)) == signature)
    #expect(FunctionType.int32.cName == "int32_t")
    #expect(FunctionType.pointer.cName == "void *")
    for name in ["", "bad-name", "return", "x0", "rax", "xmm0", "sp_0", "var_8", "arg0", "stack0", "loc_1000", "hello); evil(", "ümlaut"] {
        #expect(throws: (any Error).self) { try FunctionParameter(name: name, type: .int64) }
    }
    for name in ["arg", "argc", "argv", "argument", "arg2value"] {
        #expect(try FunctionParameter(name: name, type: .int64).name == name)
    }
    #expect(throws: (any Error).self) { try FunctionParameter(name: "arg9999999999999999999999999", type: .int64) }
    #expect(throws: (any Error).self) { try FunctionParameter(name: "value", type: .void) }
    #expect(throws: (any Error).self) {
        try FunctionSignature(returnType: .void, parameters: [FunctionParameter(name: "value", type: .int32), FunctionParameter(name: "value", type: .uint64)])
    }
    for json in [
        #"{"returnType":"double","parameters":[]}"#,
        #"{"returnType":"struct Foo","parameters":[]}"#,
        #"{"returnType":"int64","parameters":[{"name":"value","type":"void"}]}"#,
        #"{"returnType":"void","parameters":[{"name":"bad;","type":"int32"}]}"#,
        #"{"returnType":"void","parameters":[{"name":"same","type":"int32"},{"name":"same","type":"int32"}]}"#
    ] {
        #expect(throws: (any Error).self) { try JSONDecoder().decode(FunctionSignature.self, from: Data(json.utf8)) }
    }
}

private func signatureFixture(_ arch: String) throws -> Analysis {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("signature-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    let source = dir.appendingPathComponent("fixture.c"), binary = dir.appendingPathComponent("fixture.dylib")
    try """
    long sink;
    __attribute__((noinline)) long loaded(long *p, long n) { return *p + n; }
    __attribute__((noinline)) long combine(long a, long b) { return a + b; }
    __attribute__((noinline)) long caller(long a, long b) { return combine(a, b) + 1; }
    __attribute__((noinline)) long tail(long a, long b) { return combine(a, b); }
    __attribute__((noinline)) long effect(long value) { sink = value; return value + 9; }
    """.write(to: source, atomically: true, encoding: .utf8)
    _ = try Analysis.run("/usr/bin/xcrun", ["clang", "-O1", "-arch", arch, "-dynamiclib", source.path, "-o", binary.path])
    return try Analysis(slice: MachO.slices(of: Data(contentsOf: binary))[0])
}

@Test(arguments: ["arm64", "x86_64"])
func signaturesDriveDefinitionsAndCallers(arch: String) throws {
    let analysis = try signatureFixture(arch)
    func function(_ name: String) throws -> Function { try #require(analysis.functions.first { $0.name == "_" + name }) }
    func code(_ name: String, _ signatures: [UInt64: FunctionSignature]) throws -> String {
        Decompiler.decompile(analysis, try function(name), signatures: signatures).joined(separator: "\n")
    }
    let loaded = try function("loaded"), combine = try function("combine")
    let signature = try FunctionSignature(returnType: .int32, parameters: [
        FunctionParameter(name: "buffer", type: .pointer), FunctionParameter(name: "delta", type: .int16),
        FunctionParameter(name: "unused", type: .uint64)
    ])
    let definition = try code("loaded", [loaded.start: signature])
    #expect(definition.hasPrefix("int32_t loaded(void * buffer, int16_t delta, uint64_t unused) {"), "\(definition)")
    #expect(definition.contains("buffer") && definition.contains("delta") && definition.contains("return (int32_t)"), "\(definition)")
    #expect(!definition.contains("arg0") && !definition.contains("arg1"), "\(definition)")

    // Populate inferred-count caches, then edit and replace the same callee without reloading the binary.
    _ = try code("caller", [:])
    let zero = try FunctionSignature(returnType: .uint8, parameters: [])
    let edited = try code("caller", [combine.start: zero])
    #expect(edited.contains("combine()") && edited.contains("(uint8_t)"), "\(edited)")
    #expect(try code("combine", [combine.start: zero]).hasPrefix("uint8_t combine(void) {"))
    let one = try FunctionSignature(returnType: .int32, parameters: [FunctionParameter(name: "number", type: .int32)])
    let d = FunctionDecompiler(analysis, try function("caller"), signatures: [combine.start: one])
    _ = d.prepare()
    let calls = d.blocks.flatMap(\.stmts).flatMap(\.exprs).flatMap { expression -> [Expr] in
        var result: [Expr] = []
        _ = expression.map { if case .call = $0 { result.append($0) }; return $0 }
        return result
    }
    #expect(calls.count == 1)
    if case .call(_, let args)? = calls.first {
        #expect(args.count == 1)
        #expect(args.first == .fn("(int32_t)", [.v(d.abi.args[0])]))
    }
    #expect(try code("caller", [:]).contains("combine(arg0, arg1)"))
    let tailDecompiler = FunctionDecompiler(analysis, try function("caller"), signatures: [combine.start: zero])
    let target = tailDecompiler.callee(combine.start)
    tailDecompiler.blocks = [Block(start: tailDecompiler.f.start, stmts: [Stmt(kind: .ijump(target))])]
    #expect(tailDecompiler.convertIndirectTailCalls(2))
    let returned = try #require(tailDecompiler.blocks[0].stmts.last)
    #expect(tailDecompiler.render(returned)?.contains("combine()") == true)

    let void = try FunctionSignature(returnType: .void, parameters: [FunctionParameter(name: "number", type: .int64)])
    let voidDefinition = try code("effect", [(try function("effect")).start: void])
    #expect(voidDefinition.contains("sink = number;") && voidDefinition.contains("return;") && !voidDefinition.contains("return number"), "\(voidDefinition)")
    let voidTail = try code("tail", [combine.start: void])
    #expect(voidTail.contains("combine(") && !voidTail.contains("return combine("), "\(voidTail)")
    let lifted = FunctionDecompiler(analysis, try function("caller"), signatures: [combine.start: void])
    let statement = lifted.call(lifted.callee(combine.start))
    if case .eval(.call) = statement.kind {} else { Issue.record("A void call must not assign a result") }
    #expect(statement.clobbers.contains(lifted.abi.ret))
    let voidIndirect = FunctionDecompiler(analysis, try function("caller"), signatures: [combine.start: void])
    let voidTarget = voidIndirect.callee(combine.start)
    voidIndirect.blocks = [Block(start: voidIndirect.f.start, stmts: [Stmt(kind: .ijump(voidTarget))])]
    #expect(voidIndirect.convertIndirectTailCalls(2))
    if case .ret(nil)? = voidIndirect.blocks[0].stmts.last?.kind {} else { Issue.record("A void tail call must return no value") }
    #expect(voidIndirect.blocks[0].stmts.contains { if case .eval(.call) = $0.kind { true } else { false } })

    let excess = try FunctionSignature(returnType: .int64, parameters: (0..<9).map { try FunctionParameter(name: "parameter\($0)", type: .int64) })
    #expect(throws: (any Error).self) { try excess.validate(for: analysis.macho) }
    #expect(Decompiler.decompile(analysis, loaded, signatures: [loaded.start: excess]).first?.contains("stack arguments are not supported") == true)
    let collision = try FunctionSignature(returnType: .void, parameters: [FunctionParameter(name: "sink", type: .int64)])
    #expect(throws: (any Error).self) { try collision.validate(for: analysis.macho) }
}

@Test func windowsScalarABIAndShadowSpace() throws {
    let analysis = try Analysis(slice: MachO.slices(of: peFixture())[0])
    let d = FunctionDecompiler(analysis, analysis.functions[0])
    #expect(d.abi.args == ["rcx", "rdx", "r8", "r9"])
    #expect(d.abi.clobbered.contains("xmm5") && !d.abi.clobbered.contains("xmm6"))
    #expect(!d.abi.clobbered.contains("rdi") && !d.abi.clobbered.contains("rsi"))
    d.blocks = [Block(start: d.f.start, stmts: [
        Stmt(kind: .set("rcx", .c(1))), Stmt(kind: .set("rdx", .c(2))),
        Stmt(kind: .set("r8", .c(3))), Stmt(kind: .set("r9", .c(4))),
        Stmt(kind: .set("sp_0", .c(99))), Stmt(kind: .set("sp_18", .c(98))),
        Stmt(kind: .set("sp_20", .c(5))), d.call(.global("unknown"))
    ])]
    d.inferCallArguments()
    if case .set(_, .call(_, let args))? = d.blocks.first?.stmts.last?.kind {
        #expect(args == [.v("rcx"), .v("rdx"), .v("r8"), .v("r9"), .v("stack0")])
    } else { Issue.record("Expected inferred Windows call") }
    let four = try FunctionSignature(returnType: .int64, parameters: (0..<4).map { try FunctionParameter(name: "parameter\($0)", type: .int64) })
    try four.validate(for: analysis.macho)
    let five = try FunctionSignature(returnType: .int64, parameters: (0..<5).map { try FunctionParameter(name: "parameter\($0)", type: .int64) })
    #expect(throws: (any Error).self) { try five.validate(for: analysis.macho) }
    let iat = try #require(analysis.binds.first { $0.value == "puts" }?.key)
    #expect(analysis.names.filter { $0.value == "puts" }.count > 1, "Fixture has an IAT and thunk sharing the imported name")
    let zero = try FunctionSignature(returnType: .void, parameters: [])
    let entry = try #require(analysis.functions.first { $0.name == "exported" })
    let imported = FunctionDecompiler(analysis, entry, signatures: [iat: zero])
    let target = try #require(imported.slotTarget(iat))
    #expect(imported.editedSignature(target) == zero)
    let importedCode = Decompiler.decompile(analysis, entry, signatures: [iat: zero]).joined(separator: "\n")
    #expect(importedCode.contains("puts();"), "\(importedCode)")

    let native = try Analysis(slice: fixture(arch: "x86_64", strip: false))
    #expect(FunctionDecompiler(native, native.functions[0]).abi.args == ABI.x86_64.args, "Mach-O must retain SysV registers")
}

@Test(arguments: ["xorps", "xorpd"])
func vectorXorOnlyZerosIdenticalOperands(mnemonic: String) throws {
    let analysis = try Analysis(slice: fixture(arch: "x86_64", strip: false))
    let d = FunctionDecompiler(analysis, analysis.functions[0])
    func lift(_ operands: String) -> [Stmt] {
        d.liftX86(Instruction(address: 0x1000, bytes: "", mnemonic: mnemonic, operands: operands, comment: "", target: nil), prev: nil)
    }
    let same = lift("%xmm0, %xmm0")
    #expect(same.contains { if case .set("xmm0", .c(0)) = $0.kind { true } else { false } })
    let different = lift("%xmm1, %xmm0")
    #expect(different.contains { if case .asm = $0.kind { true } else { false } })
    #expect(!different.contains { if case .set(_, .c(0)) = $0.kind { true } else { false } })
    #expect(different.first?.uses.contains("xmm1") == true && different.first?.defs.contains("xmm0") == true)
    #expect(!lift("%xmm0").contains { if case .set = $0.kind { true } else { false } })
}
