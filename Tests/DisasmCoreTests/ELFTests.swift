import Foundation
import Testing
@testable import DisasmCore

func androidFixture(_ arch: String, stripped: Bool = false) -> URL {
    URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .appendingPathComponent("Fixtures/\(arch)\(stripped ? "-stripped" : "").so")
}

@Test(arguments: ["arm64", "arm", "arm-thumb", "arm-mixed", "x86_64", "x86_64-got", "x86"], [false, true])
func androidLibraryPipeline(arch: String, stripped: Bool) throws {
    let data = try Data(contentsOf: androidFixture(arch, stripped: stripped))
    let a = try Analysis(slice: MachO.slices(of: data)[0])
    #expect(a.macho.arch == (arch.hasPrefix("arm-") ? "arm" : arch == "x86_64-got" ? "x86_64" : arch))
    #expect(a.macho.dylibs.contains("libfixture-dep.so"))
    let f = try #require(a.functions.first { $0.name == "Java_com_example_Test_value" })
    #expect(a.instructions[f.lines].count > 5)
    #expect(a.instructions[f.lines].allSatisfy { !$0.bytes.isEmpty && !$0.mnemonic.isEmpty })
    let string = try #require(a.strings.first { $0.value == "hello-from-android" })
    #expect(a.macho.bytes(at: string.address, 19) == Data("hello-from-android\0".utf8))
    #expect(a.imports.contains { $0.name == "puts" })
    let puts = try #require(a.imports.first { $0.name == "puts" })
    #expect(a.instructions[f.lines].contains { $0.target == puts.stub || $0.dataRefs.contains(puts.stub) }, "Imported call must decode correctly, including stripped Thumb")
    if arch == "arm-thumb" || arch == "arm-mixed" {
        #expect(a.instructions[f.lines].first?.bytes.count == 4, "Thumb prologue is a 2-byte push")
    }
    if arch == "arm-mixed" {
        let target = try #require(a.instructions[f.lines].first { $0.mnemonic == "blx" && $0.target.flatMap(a.function) != nil }?.target)
        #expect(a.instruction(at: target)?.mnemonic == "push")
        #expect(a.instruction(at: target)?.bytes.count == 8, "ARM helper prologue is 4 bytes")
    }
    if a.macho.supportsPseudocode {
        #expect(a.xrefs[string.address]?.isEmpty == false)
        let imported = try #require(a.imports.first { $0.name == "puts" })
        #expect(a.xrefs[imported.stub]?.isEmpty == false)
        let code = Decompiler.decompile(a, f).joined(separator: "\n")
        #expect(code.contains("puts(\"hello-from-android\")"), "\(code)")
        #expect(code.contains("printf(\"android-value=%d\\n\", "), "\(code)")
        #expect(!code.contains("asm {"), "\(code)")
        let counter = try #require(a.functions.first { $0.name == "read_counter" })
        let counterCode = Decompiler.decompile(a, counter).joined(separator: "\n")
        #expect(counterCode.contains("external_counter"), "\(counterCode)")
    }
}

@Test func malformedAndroidLibraries() throws {
    let original = try Data(contentsOf: androidFixture("arm64"))
    for count in [0, 4, 16, 63, original.count - 1] {
        #expect(throws: MachOError.self) {
            _ = try Analysis(slice: MachO.slices(of: Data(original.prefix(count)))[0])
        }
    }
    // Endianness, machine, overflowing table offset/count, sectionless input and invalid string table.
    for (offset, replacement) in [(5, [UInt8(2)]), (18, [0xff, 0xff]), (40, Array(repeating: 0xff, count: 8)),
                                  (60, [0xff, 0xff]), (40, Array(repeating: 0, count: 8)), (62, [0xfe, 0xff])] {
        var data = original
        data.replaceSubrange(offset..<offset + replacement.count, with: replacement)
        #expect(throws: MachOError.self) { _ = try Analysis(slice: MachO.slices(of: data)[0]) }
    }
}

@Test(arguments: ["arm64", "x86_64-got"]) func androidProviderSession(arch: String) throws {
    let server = ProviderServer()
    let result = try server.call("idb_open", ["input_path": androidFixture(arch, stripped: true).path]) as? [String: Any]
    #expect(result?["success"] as? Bool == true)
    let lookup = try server.call("lookup_funcs", ["queries": ["Java_com_example_Test_value"]]) as? [[String: Any]]
    let function = try #require(lookup?.first?["fn"] as? [String: Any])
    let addr = try #require(function["addr"] as? String)
    let code = try server.call("decompile", ["addr": addr]) as? [String: Any]
    #expect((code?["code"] as? String)?.contains("hello-from-android") == true)
    let resultCallees = try server.call("callees", ["addrs": [addr]]) as? [[String: Any]]
    let callees = try #require(resultCallees?.first?["callees"] as? [[String: Any]])
    #expect(callees.contains { $0["name"] as? String == "puts" && $0["type"] as? String == "external" })
}

@Test func androidConditionalBranchTargets() {
    let (instructions, _) = Analysis.parseObjdump("""
         100: d108          \tbne\t0x114 <done>
         102: f040 8007     \tbne.w\t0x114 <done>
         106: eafffffe      \tb\t0x106 <loop>
         10a: 1b000000      \tblne\t0x112 <helper>
         10e: f000 e800     \tblxne\t0x114 <arm_helper>
    """)
    #expect(instructions.map(\.target) == [0x114, 0x114, 0x106, 0x112, 0x114])
    #expect(Analysis.isCall("blne") && Analysis.isCall("blne.w") && Analysis.isCall("blxne"))
    #expect(!Analysis.isCall("bls") && !Analysis.isCall("ble.w"))
}

@Test func androidUnmappedStringsAreNotRuntimeAddresses() throws {
    var data = try Data(contentsOf: androidFixture("arm64"))
    let m = try MachO(slice: MachO.slices(of: data)[0])
    let index = try #require(m.sections.firstIndex { $0.name == ".rodata" })
    let header = Int(try Reader(data: data).u64(40)) + index * 64
    // Like .debug_str: a file-backed string section which is not loaded into memory.
    data.replaceSubrange(header + 8..<header + 16, with: [0x20, 0, 0, 0, 0, 0, 0, 0])
    let a = try Analysis(slice: MachO.slices(of: data)[0])
    #expect(a.strings.isEmpty)
}
