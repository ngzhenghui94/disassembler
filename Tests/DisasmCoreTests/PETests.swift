import Foundation
import Testing
@testable import DisasmCore

private func pePut<T: FixedWidthInteger>(_ value: T, _ data: inout Data, _ offset: Int) {
    var little = value.littleEndian
    withUnsafeBytes(of: &little) { data.replaceSubrange(offset..<offset + $0.count, with: $0) }
}

/// A deterministic linked PE32+ image; no Windows SDK, compiler, or linker is needed by these tests.
func peFixture(dll: Bool = false) -> Data {
    var data = Data(repeating: 0, count: 0xc00)
    func u16(_ value: UInt16, _ off: Int) { pePut(value, &data, off) }
    func u32(_ value: UInt32, _ off: Int) { pePut(value, &data, off) }
    func u64(_ value: UInt64, _ off: Int) { pePut(value, &data, off) }
    func bytes(_ values: [UInt8], _ off: Int) { data.replaceSubrange(off..<off + values.count, with: values) }
    func text(_ value: String, _ off: Int) { bytes(Array(value.utf8) + [0], off) }
    u16(0x5a4d, 0); u32(0x80, 0x3c)
    u32(0x4550, 0x80); u16(0x8664, 0x84); u16(4, 0x86)
    u16(240, 0x94); u16(dll ? 0x2022 : 0x22, 0x96)
    let opt = 0x98
    u16(0x20b, opt); u32(0x200, opt + 4); u32(0x600, opt + 8)
    u32(0x1000, opt + 16); u32(0x1000, opt + 20); u64(0x140000000, opt + 24)
    u32(0x1000, opt + 32); u32(0x200, opt + 36)
    u16(6, opt + 40); u16(6, opt + 48)
    u32(0x5000, opt + 56); u32(0x400, opt + 60); u16(3, opt + 68)
    u64(0x100000, opt + 72); u64(0x1000, opt + 80)
    u64(0x100000, opt + 88); u64(0x1000, opt + 96); u32(16, opt + 108)
    func directory(_ index: Int, _ rva: UInt32, _ size: UInt32) {
        u32(rva, opt + 112 + index * 8); u32(size, opt + 116 + index * 8)
    }
    directory(0, 0x2100, 0xc0); directory(1, 0x2200, 40)
    directory(3, 0x3000, 24); directory(12, 0x2280, 24)
    func section(_ index: Int, _ name: String, _ size: UInt32, _ rva: UInt32, _ rawSize: UInt32, _ offset: UInt32, _ flags: UInt32) {
        let off = 0x188 + index * 40
        text(name, off); u32(size, off + 8); u32(rva, off + 12)
        u32(rawSize, off + 16); u32(offset, off + 20); u32(flags, off + 36)
    }
    section(0, ".text", 0x40, 0x1000, 0x200, 0x400, 0x60000020)
    section(1, ".rdata", 0x400, 0x2000, 0x400, 0x600, 0x40000040)
    section(2, ".pdata", 24, 0x3000, 0x200, 0xa00, 0x40000040)
    section(3, ".bss", 0x100, 0x4000, 0, 0, 0xc0000080)
    data.replaceSubrange(0x400..<0x600, with: repeatElement(UInt8(0xcc), count: 0x200))
    bytes([0x48, 0x83, 0xec, 0x28,                       // sub $40, %rsp (shadow space + alignment)
           0x48, 0x8d, 0x0d, 0xf5, 0x0f, 0, 0,         // lea hello(%rip), %rcx
           0xff, 0x15, 0x6f, 0x12, 0, 0,               // call *puts IAT(%rip)
           0xe8, 0x0a, 0, 0, 0,                        // call helper
           0x48, 0x83, 0xc4, 0x28, 0xc3], 0x400)
    bytes([0xb8, 42, 0, 0, 0, 0xc3], 0x420)
    bytes([0x31, 0xc0, 0xc3], 0x430)
    bytes([0xff, 0x25, 0x42, 0x12, 0, 0], 0x438)       // jmp *puts IAT(%rip)
    text("hello-from-windows", 0x600)
    bytes(Array("wide-windows".utf16.flatMap { [UInt8($0 & 0xff), UInt8($0 >> 8)] }) + [0, 0], 0x640)
    // Named, ordinal-only, and forwarded exports.
    u32(0x2130, 0x70c); u32(1, 0x710); u32(3, 0x714); u32(1, 0x718)
    u32(0x2140, 0x71c); u32(0x2150, 0x720); u32(0x2160, 0x724)
    text("fixture.dll", 0x730)
    u32(0x1000, 0x740); u32(0x1030, 0x744); u32(0x21a0, 0x748)
    u32(0x2180, 0x750); u16(0, 0x760); text("exported", 0x780)
    text("KERNEL32.Sleep", 0x7a0)
    // One normal descriptor followed by the mandatory all-zero terminator.
    u32(0x2260, 0x800); u32(0x2240, 0x80c); u32(0x2280, 0x810)
    text("msvcrt.dll", 0x840)
    for off in [0x860, 0x880] { u64(0x22a0, off); u64(0x8000000000000007, off + 8) }
    u16(0, 0x8a0); text("puts", 0x8a2)
    bytes([1, 4, 1, 0, 4, 0x42, 0, 0], 0x8c0) // UWOP_ALLOC_SMALL: 40-byte stack allocation.
    bytes([1, 0, 0, 0], 0x8d0)
    u32(0x1000, 0xa00); u32(0x101b, 0xa04); u32(0x22c0, 0xa08)
    u32(0x1020, 0xa0c); u32(0x1026, 0xa10); u32(0x22d0, 0xa14)
    return data
}

private func parsePE(_ data: Data) throws -> MachO {
    try MachO(slice: MachO.slices(of: data)[0])
}

@Test(arguments: [false, true]) func windowsPEHeadersAndTables(dll: Bool) throws {
    let data = peFixture(dll: dll), m = try parsePE(data)
    #expect(m.isPE && !m.isELF && m.arch == "x86_64" && m.supportsPseudocode)
    #expect(m.typeName == (dll ? "DLL" : "Executable"))
    #expect(m.textBase == 0x140000000 && m.entry == 0x140001000)
    #expect(m.sections.map(\.name) == [".text", ".rdata", ".pdata", ".bss"])
    #expect(m.dylibs == ["msvcrt.dll"])
    #expect(m.binds[0x140002280] == "puts")
    #expect(m.binds[0x140002288] == "msvcrt.dll!#7")
    #expect(m.symbols.contains { $0.name == "exported" && $0.address == 0x140001000 })
    #expect(m.symbols.contains { $0.name == "ordinal_2" && $0.address == 0x140001030 })
    #expect(!m.symbols.contains { $0.address == 0x1400021a0 })
    #expect(m.functionStarts == [0x140001000, 0x140001020, 0x140001030])
    #expect(m.section(containing: 0x140004050)?.name == ".bss")
    #expect(m.bytes(at: 0x140004000, 1) == nil)
    #expect(m.sections.first { $0.name == ".bss" }?.isCString == false)
    #expect(m.bytes(at: 0x14000103f, 2) == nil, "Do not read section raw padding as virtual code")
    #expect(m.bytes(at: 0x140000000, 2) == Data([0x4d, 0x5a]))
    #expect(m.data == data, "Parsing must not alter the image")
}

@Test(arguments: [false, true]) func windowsPEAnalysis(dll: Bool) throws {
    let a = try Analysis(slice: MachO.slices(of: peFixture(dll: dll))[0])
    let f = try #require(a.functions.first { $0.name == "exported" })
    #expect(f.start == 0x140001000 && f.end <= 0x140001020)
    #expect(a.functions.contains { $0.start == 0x140001020 })
    #expect(a.instructions[f.lines].contains { $0.target == 0x140001020 })
    #expect(a.instructions.allSatisfy { !$0.bytes.isEmpty && a.macho.section(containing: $0.address)?.isCode == true })
    #expect(a.strings.contains { $0.value == "hello-from-windows" && $0.address == 0x140002000 })
    #expect(a.strings.contains { $0.value == "wide-windows" && $0.address == 0x140002040 })
    #expect(a.imports.contains { $0.name == "puts" && $0.stub == 0x140002280 })
    #expect(a.imports.contains { $0.name == "msvcrt.dll!#7" && $0.stub == 0x140002288 })
    #expect(a.names[0x140002280] == "puts", "IAT addresses can be signature-override targets")
    #expect(a.names[0x140001038] == "puts", "Import jump thunks must resolve")
    #expect(a.xrefs[0x140002000]?.contains(0x140001004) == true)
    #expect(a.xrefs[0x140002280]?.contains(0x14000100b) == true)
    #expect(a.xrefs[0x140001020]?.contains(0x140001011) == true)
    #expect(a.instruction(at: 0x14000100b)?.comment.contains("puts") == true)
}

@Test func windowsPEZeroFillTailAndCertificateFileOffsets() throws {
    var data = peFixture()
    pePut(UInt32(0x600), &data, 0x1b8) // Virtual .rdata extends beyond its initialized bytes.
    pePut(UInt32(0xc00), &data, 0x128) // Certificates use file offsets, not image RVAs.
    pePut(UInt32(8), &data, 0x12c)
    data.append(contentsOf: [8, 0, 0, 0, 0, 2, 2, 0])
    let a = try Analysis(slice: MachO.slices(of: data)[0])
    #expect(a.macho.section(containing: 0x140002500)?.name == ".rdata")
    #expect(a.macho.bytes(at: 0x140002400, 1) == nil)
    #expect(a.strings.contains { $0.value == "hello-from-windows" })
    #expect(a.strings.allSatisfy { $0.address < 0x140002400 })
    pePut(UInt32(9), &data, 0x12c)
    #expect(throws: MachOError.self) { _ = try parsePE(data) }
}

@Test func windowsPEImportLookupFallbackAndNoEntryDLL() throws {
    var data = peFixture(dll: true)
    pePut(UInt32(0), &data, 0x800) // OriginalFirstThunk may be omitted in an unbound image.
    pePut(UInt32(0), &data, 0xa8)
    let m = try parsePE(data)
    #expect(m.entry == nil && m.binds[0x140002280] == "puts")
}

@Test func windowsPEExportAliasesAndEmptyTable() throws {
    var data = peFixture(dll: true)
    pePut(UInt32(1), &data, 0x714)
    pePut(UInt32(2), &data, 0x718)
    pePut(UInt32(0x2190), &data, 0x754)
    pePut(UInt16(0), &data, 0x762)
    data.replaceSubrange(0x790..<0x796, with: Array("alias\0".utf8))
    let m = try parsePE(data)
    #expect(Set(m.symbols.map(\.name)) == ["exported", "alias"])
    pePut(UInt32(0), &data, 0x714)
    pePut(UInt32(0), &data, 0x718)
    pePut(UInt32(0), &data, 0x71c)
    #expect(try parsePE(data).symbols.isEmpty)
}

@Test func windowsPERejectsTruncationAndUnsupportedFormats() throws {
    let original = peFixture()
    for count in [0, 1, 2, 63, 0x83, 0x97, 0x187, 0x227, original.count - 1] {
        #expect(throws: MachOError.self) { _ = try parsePE(Data(original.prefix(count))) }
    }
    for (off, value) in [(0x84, UInt16(0x14c)), (0x84, UInt16(0xaa64)), (0x98, UInt16(0x10b)), (0x94, UInt16(111))] {
        var data = original
        pePut(value, &data, off)
        #expect(throws: MachOError.self) { _ = try parsePE(data) }
    }
    #expect(throws: MachOError.self) { _ = try MachO(slice: ArchSlice(arch: "arm64", data: original)) }
}

@Test func windowsPERejectsMalformedBoundaries() {
    // Header offsets/counts, alignments, section ranges, directory ranges, exports, imports, and unwind ranges.
    let mutations: [(Int, UInt32)] = [
        (0x3c, UInt32.max), (0x3c, 0x20), (0x80, 0),
        (0xd0, 0x1000), (0xd4, 0x200), (0xb8, 0), (0xbc, 0x300), (0x104, 17),
        (0x194, UInt32.max), (0x198, UInt32.max), (0x19c, UInt32.max),
        (0x1bc, 0x1000), (0x1c4, 0x400),
        (0x108, 0x4000), (0x114, 19), (0x120, 0x3fe), (0x124, 40),
        (0x714, UInt32.max), (0x71c, 0x23ff), (0x750, 0x4000), (0x760, 0xffff),
        (0x800, 0x4000), (0x80c, 0x23ff), (0x810, 0x23ff),
        (0xa00, 0x2000), (0xa04, 0x1041), (0xa0c, 0x1000), (0xa14, 0x4000)
    ]
    for (off, value) in mutations {
        var data = peFixture()
        pePut(value, &data, off)
        // Ensure a string pointer to the last section byte cannot find a terminator.
        data[0x9ff] = 0x41
        #expect(throws: MachOError.self) { _ = try parsePE(data) }
    }
    var overflow = peFixture()
    pePut(UInt64.max, &overflow, 0xb0)
    #expect(throws: MachOError.self) { _ = try parsePE(overflow) }
    var descriptors = peFixture()
    pePut(UInt32(20), &descriptors, 0x114)
    #expect(throws: MachOError.self) { _ = try parsePE(descriptors) }
    var thunks = peFixture()
    pePut(UInt32(0x23f8), &thunks, 0x800)
    pePut(UInt64(0x8000000000000007), &thunks, 0x9f8)
    #expect(throws: MachOError.self) { _ = try parsePE(thunks) }
    var unterminatedIAT = peFixture()
    pePut(UInt64(1), &unterminatedIAT, 0x890)
    #expect(throws: MachOError.self) { _ = try parsePE(unterminatedIAT) }
    var boundOnly = peFixture()
    pePut(UInt32(0), &boundOnly, 0x800)
    pePut(UInt64(0x7ffb12345678), &boundOnly, 0x880)
    #expect(throws: MachOError.self) { _ = try parsePE(boundOnly) }
}
