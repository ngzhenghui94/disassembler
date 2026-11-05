import Foundation
import Testing
@testable import DisasmCore

@Test func signatureOverridesPersistAndInvalidateCallerCaches() throws {
    let binary = try fixtureBinary(arch: "arm64", strip: false)
    defer { try? FileManager.default.removeItem(at: binary.deletingLastPathComponent()) }
    let analysis = try Analysis(slice: MachO.slices(of: Data(contentsOf: binary))[0])
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("signature-test-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: root) }
    let store = SignatureStore(binary: analysis.macho, root: root)
    let helper = try #require(analysis.functions.first { $0.name == "_helper" })
    let main = try #require(analysis.functions.first { $0.name == "_main" })
    let signature = try FunctionSignature(returnType: .int32, parameters: [FunctionParameter(name: "count", type: .int32)])
    let mainSignature = try FunctionSignature(returnType: .int32, parameters: [FunctionParameter(name: "argc", type: .int32)])
    try store.save(signature, at: helper.start, in: analysis)
    try SignatureStore(binary: analysis.macho, root: root).save(mainSignature, at: main.start, in: analysis)
    #expect(try store.load(for: analysis) == [helper.start: signature, main.start: mainSignature])
    #expect(throws: (any Error).self) { try store.save(signature, at: helper.start + 1, in: analysis) }
    let otherBinary = try fixtureBinary(arch: "arm64", strip: false)
    defer { try? FileManager.default.removeItem(at: otherBinary.deletingLastPathComponent()) }
    let other = try Analysis(slice: MachO.slices(of: Data(contentsOf: otherBinary))[0])
    #expect(try SignatureStore(binary: other.macho, root: root).load(for: other).isEmpty)

    let server = ProviderServer()
    server.sessions["typed"] = ProviderServer.Session(id: "typed", inputPath: binary.path, analysis: analysis,
        debugInfo: binary, signatureStore: store)
    server.order = ["typed"]
    func code(_ function: Function) throws -> String {
        let value = try server.call("decompile", ["addr": "0x" + String(function.start, radix: 16)])
        return try #require((value as? [String: Any])?["code"] as? String)
    }
    #expect(try code(helper).contains("int32_t helper(int32_t count)"))
    let callerBefore = try code(main)
    let address = "0x" + String(helper.start, radix: 16)
    _ = try server.call("function_signature", ["addr": address, "action": "set", "signature": [
        "returnType": "void", "parameters": [["name": "count", "type": "int32"]]
    ]])
    #expect(try code(helper).contains("void helper(int32_t count)"))
    #expect(try code(main) != callerBefore)
    let prior = try store.load(for: analysis)
    #expect(throws: (any Error).self) {
        _ = try server.call("function_signature", ["addr": address, "action": "set", "signature": [
            "returnType": "int32", "parameters": [["name": "bad); injected()", "type": "int32"]]
        ]])
    }
    #expect(try store.load(for: analysis) == prior)
    _ = try server.call("function_signature", ["addr": address, "action": "reset"])
    #expect(try store.load(for: analysis) == [main.start: mainSignature])
    #expect(try code(helper).contains("int64_t helper(int64_t arg0)"))
    #expect(try Data(contentsOf: binary) == analysis.macho.data)
}

@Test func importedSignaturesPersistAndChangeCallArguments() throws {
    let analysis = try Analysis(slice: MachO.slices(of: peFixture())[0])
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("import-signature-\(UUID())")
    defer { try? FileManager.default.removeItem(at: root) }
    let store = SignatureStore(binary: analysis.macho, root: root)
    let imported = try #require(analysis.imports.first { $0.name == "puts" })
    let function = try #require(analysis.functions.first { $0.name == "exported" })
    let server = ProviderServer()
    server.sessions["pe"] = ProviderServer.Session(id: "pe", inputPath: "/unused/fixture.exe", analysis: analysis,
        debugInfo: URL(fileURLWithPath: "/unused/fixture.exe"), signatureStore: store)
    server.order = ["pe"]
    let address = "0x" + String(imported.stub, radix: 16)
    _ = try server.call("function_signature", ["addr": address, "action": "set", "signature": [
        "returnType": "void", "parameters": []
    ]])
    let saved = try SignatureStore(binary: analysis.macho, root: root).load(for: analysis)
    #expect(saved[imported.stub]?.returnType == .void)
    let result = try server.call("decompile", ["addr": "0x" + String(function.start, radix: 16)]) as? [String: Any]
    #expect((result?["code"] as? String)?.contains("puts();") == true)
    _ = try server.call("function_signature", ["addr": address, "action": "reset"])
    let inferred = try server.call("decompile", ["addr": "0x" + String(function.start, radix: 16)]) as? [String: Any]
    #expect((inferred?["code"] as? String)?.contains("puts(\"hello-from-windows\")") == true)
}
