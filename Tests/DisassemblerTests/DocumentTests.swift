import Foundation
import Testing
@testable import DisasmCore
@testable import Disassembler

@MainActor
private func waitForDocument(_ ready: () -> Bool) async throws {
    while !ready() {
        try Task.checkCancellation()
        await Task.yield()
    }
}

@Test(.timeLimit(.minutes(1))) @MainActor
func failedOpenClearsPendingDocumentAndCanRecover() async throws {
    let doc = Document()
    let binary = URL(fileURLWithPath: "/bin/ls")
    let missing = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    doc.openBinary(binary)
    #expect(doc.loading)
    doc.sourceHeaders = [1: [1: SourceHeader(location: "old.c:1", text: "old source")]]
    doc.go(.code(1))
    doc.go(.code(2))

    // Both opens run on the main actor before the first analysis can publish.
    doc.openBinary(missing)
    #expect(doc.url == missing)
    #expect(doc.error != nil)
    #expect(doc.analysis == nil)
    #expect(!doc.loading)
    #expect(doc.arch.isEmpty)
    #expect(doc.slices.isEmpty)
    #expect(doc.destination == nil)
    #expect(doc.history.isEmpty)
    #expect(!doc.debugInfoReady)
    #expect(doc.sourceHeaders.isEmpty)

    doc.openBinary(binary)
    #expect(doc.loading)
    #expect(doc.error == nil)
    try await waitForDocument { !doc.loading }
    #expect(doc.url == binary)
    #expect(doc.error == nil)
    #expect(doc.analysis != nil)
}

@Test(.timeLimit(.minutes(1)), arguments: [false, true]) @MainActor
func documentReloadReadsFreshSource(reopen: Bool) async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("disasm-document-\(UUID())")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let source = directory.appendingPathComponent("main.c")
    let object = directory.appendingPathComponent("main.o")
    let binary = directory.appendingPathComponent("main")
    let original = "int main(void) { return 1; } // original source"
    let updated = "int main(void) { return 2; } // updated source"
    try original.write(to: source, atomically: true, encoding: .utf8)
    _ = try Analysis.run("/usr/bin/xcrun", ["clang", "-g", "-O0", "-c", source.path, "-o", object.path])
    // Isolate atos's UUID cache across fixtures, while preserving this binary's UUID on reload.
    _ = try Analysis.run("/usr/bin/xcrun", ["clang", "-Wl,-random_uuid", object.path, "-o", binary.path])

    let doc = Document()
    doc.openBinary(binary)
    try await waitForDocument { !doc.loading }
    let analysis = try #require(doc.analysis)
    try await waitForDocument { doc.debugInfoReady }
    let function = try #require(analysis.functions.first { $0.name == "_main" })
    await doc.loadSource(for: function)
    #expect(doc.sourceHeaders[function.start]?.values.contains { $0.text == original } == true)

    // Keep the binary (and its UUID) unchanged, as when revisiting a build after editing its source.
    try updated.write(to: source, atomically: true, encoding: .utf8)
    if reopen { doc.openBinary(binary) } else { doc.load(doc.arch) }
    #expect(doc.loading)
    #expect(doc.analysis == nil)
    #expect(!doc.debugInfoReady)
    #expect(doc.sourceHeaders.isEmpty)
    try await waitForDocument { !doc.loading }
    let reloaded = try #require(doc.analysis)
    #expect(reloaded.macho.uuid == analysis.macho.uuid)
    try await waitForDocument { doc.debugInfoReady }
    let reloadedFunction = try #require(reloaded.functions.first { $0.name == "_main" })
    await doc.loadSource(for: reloadedFunction)
    #expect(doc.sourceHeaders[reloadedFunction.start]?.values.contains { $0.text == updated } == true)
    #expect(doc.sourceHeaders[reloadedFunction.start]?.values.contains { $0.text == original } == false)

    doc.openBinary(directory.appendingPathComponent("missing"))
    #expect(doc.error != nil)
    #expect(doc.analysis == nil)
    #expect(!doc.loading)
    #expect(!doc.debugInfoReady)
    #expect(doc.sourceHeaders.isEmpty)
}
