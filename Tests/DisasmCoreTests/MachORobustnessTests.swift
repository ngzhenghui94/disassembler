import Foundation
import Testing
@testable import DisasmCore

private func put<T: FixedWidthInteger>(_ value: T, in data: inout Data, at offset: Int, bigEndian: Bool = false) {
    var encoded = bigEndian ? value.bigEndian : value.littleEndian
    withUnsafeBytes(of: &encoded) { data.replaceSubrange(offset..<offset + $0.count, with: $0) }
}

private func loadCommand(_ type: UInt32, size: Int) -> Data {
    var data = Data(repeating: 0, count: size)
    put(type, in: &data, at: 0)
    put(UInt32(size), in: &data, at: 4)
    return data
}

private func thinMachO(_ commands: [Data] = [], payload: Data = Data(), fileType: UInt32 = 2) -> Data {
    var data = Data(repeating: 0, count: 32)
    put(UInt32(0xfeed_facf), in: &data, at: 0)
    put(UInt32(0x0100_000c), in: &data, at: 4)
    put(fileType, in: &data, at: 12)
    put(UInt32(commands.count), in: &data, at: 16)
    put(UInt32(commands.reduce(0) { $0 + $1.count }), in: &data, at: 20)
    for command in commands { data.append(command) }
    data.append(payload)
    return data
}

private func parseMachO(_ data: Data) throws -> MachO {
    try MachO(slice: ArchSlice(arch: "arm64", data: data))
}

private func section64(addr: UInt64, size: UInt64, offset: UInt32 = 0, flags: UInt32 = 0) -> Data {
    var data = Data(repeating: 0, count: 80)
    data.replaceSubrange(0..<6, with: Data("__test".utf8))
    data.replaceSubrange(16..<22, with: Data("__DATA".utf8))
    put(addr, in: &data, at: 32)
    put(size, in: &data, at: 40)
    put(offset, in: &data, at: 48)
    put(flags, in: &data, at: 64)
    return data
}

private func segment64(vmaddr: UInt64 = 0x1000, vmsize: UInt64 = 0x1000, fileoff: UInt64 = 0,
                       filesize: UInt64 = 0, section: Data? = nil, name: String = "__TEXT") -> Data {
    var data = loadCommand(0x19, size: 72 + (section?.count ?? 0))
    data.replaceSubrange(8..<8 + name.utf8.count, with: Data(name.utf8))
    put(vmaddr, in: &data, at: 24)
    put(vmsize, in: &data, at: 32)
    put(fileoff, in: &data, at: 40)
    put(filesize, in: &data, at: 48)
    if let section {
        put(UInt32(1), in: &data, at: 64)
        data.replaceSubrange(72..<data.count, with: section)
    }
    return data
}

private func linkedit(_ type: UInt32, offset: UInt32, size: UInt32) -> Data {
    var command = loadCommand(type, size: 16)
    put(offset, in: &command, at: 8)
    put(size, in: &command, at: 12)
    return command
}

private func fatMachO(count: Int = 1, wide: Bool = false) -> Data {
    let thin = thinMachO(), stride = wide ? 32 : 20, tableEnd = 8 + count * stride
    var data = Data(repeating: 0, count: tableEnd)
    put(UInt32(wide ? 0xcafe_babf : 0xcafe_babe), in: &data, at: 0, bigEndian: true)
    put(UInt32(count), in: &data, at: 4, bigEndian: true)
    for i in 0..<count {
        let base = 8 + i * stride
        put(UInt32(0x0100_000c), in: &data, at: base, bigEndian: true)
        if wide {
            put(UInt64(tableEnd + i * thin.count), in: &data, at: base + 8, bigEndian: true)
            put(UInt64(thin.count), in: &data, at: base + 16, bigEndian: true)
        } else {
            put(UInt32(tableEnd + i * thin.count), in: &data, at: base + 8, bigEndian: true)
            put(UInt32(thin.count), in: &data, at: base + 12, bigEndian: true)
        }
        data.append(thin)
    }
    return data
}

@Test(arguments: [false, true]) func rejectsEmptyAndTruncatedFatHeaders(wide: Bool) {
    let empty = fatMachO(count: 0, wide: wide)
    #expect(throws: MachOError.self) { try MachO.slices(of: empty) }
    let valid = fatMachO(wide: wide)
    for count in [0, 4, 7, 8, wide ? 39 : 27, valid.count - 1] {
        #expect(throws: MachOError.self) { try MachO.slices(of: Data(valid.prefix(count))) }
    }
    var huge = valid
    put(UInt32.max, in: &huge, at: 4, bigEndian: true)
    #expect(throws: MachOError.self) { try MachO.slices(of: huge) }
}

@Test func rejectsUnrepresentableFatRanges() {
    for field in [16, 24] {
        var data = fatMachO(wide: true)
        put(UInt64.max, in: &data, at: field, bigEndian: true)
        #expect(throws: MachOError.self) { try MachO.slices(of: data) }
    }
    var overlappingHeader = fatMachO()
    put(UInt32(8), in: &overlappingHeader, at: 16, bigEndian: true)
    #expect(throws: MachOError.self) { try MachO.slices(of: overlappingHeader) }
}

@Test(arguments: [false, true]) func fatSlicesAreNotSilentlyCapped(wide: Bool) throws {
    let slices = try MachO.slices(of: fatMachO(count: 65, wide: wide))
    #expect(slices.count == 65)
    #expect(Set(slices.map(\.arch)).count == 65)
    for slice in slices { #expect(try MachO(slice: slice).fileType == 2) }
}

@Test func rejectsTruncatedMachOHeadersAndCommandTables() {
    let valid = thinMachO([loadCommand(0x777, size: 8)])
    for count in [4, 12, 28, 31, 32, 39] {
        #expect(throws: MachOError.self) { try parseMachO(Data(valid.prefix(count))) }
    }
    for (field, value) in [(16, UInt32.max), (20, UInt32.max), (20, 0), (36, 0), (36, 16)] {
        var data = valid
        put(value, in: &data, at: field)
        #expect(throws: MachOError.self) { try parseMachO(data) }
    }
    var leftover = valid
    put(UInt32(0), in: &leftover, at: 16)
    #expect(throws: MachOError.self) { try parseMachO(leftover) }
}

@Test(arguments: [UInt32(0x19), 0x2, 0x26, 0x8000_0028, 0xc, 0x8000_0018, 0x8000_001f, 0xd, 0x1b, 0x29, 0x8000_0034])
func rejectsCommandsReadingAdjacentRecords(type: UInt32) {
    let data = thinMachO([loadCommand(type, size: 8), loadCommand(0x777, size: 80)])
    #expect(throws: MachOError.self) { try parseMachO(data) }
}

@Test func rejectsSectionTablesOutsideTheirCommand() {
    var segment = segment64()
    put(UInt32(1), in: &segment, at: 64)
    #expect(throws: MachOError.self) { try parseMachO(thinMachO([segment, loadCommand(0x777, size: 80)])) }
    put(UInt32.max, in: &segment, at: 64)
    #expect(throws: MachOError.self) { try parseMachO(thinMachO([segment])) }
}

@Test func rejectsOverflowingAndUnbackedRanges() {
    let badSegments = [
        segment64(vmaddr: UInt64.max, vmsize: 1),
        segment64(fileoff: UInt64.max, filesize: 1),
        segment64(fileoff: 104, filesize: 1),
        segment64(section: section64(addr: UInt64.max, size: 2, flags: 1)),
        segment64(section: section64(addr: 0x1fff, size: 2, flags: 1)),
        segment64(section: section64(addr: 0x1000, size: 1, offset: 184))
    ]
    for segment in badSegments {
        #expect(throws: MachOError.self) { try parseMachO(thinMachO([segment])) }
    }
    let main = loadCommand(0x8000_0028, size: 24)
    var badMain = main
    put(UInt64.max, in: &badMain, at: 8)
    #expect(throws: MachOError.self) { try parseMachO(thinMachO([segment64(), badMain])) }
}

@Test(arguments: [UInt32(1), 0xc, 0x12]) func acceptsVirtualSectionsAndPageZero(flags: UInt32) throws {
    let pageZero = segment64(vmaddr: 0, vmsize: 0x1000, name: "__PAGEZERO")
    let virtual = segment64(fileoff: UInt64.max, section: section64(addr: 0x1000, size: 0x1000, offset: UInt32.max, flags: flags))
    let macho = try parseMachO(thinMachO([pageZero, virtual]))
    #expect(macho.sections.count == 1)
    #expect(macho.section(containing: 0x1fff) != nil)
    #expect(macho.bytes(at: 0x1000, 1) == nil)
}

@Test func acceptsObjectSectionsAndExactFileBoundaries() throws {
    // MH_OBJECT uses an unnamed segment containing sections with their final segment names.
    let segment = segment64(vmaddr: 0, vmsize: 4, fileoff: 184, filesize: 4,
                            section: section64(addr: 0, size: 4, offset: 184), name: "")
    let macho = try parseMachO(thinMachO([segment], payload: Data([1, 2, 3, 4]), fileType: 1))
    #expect(macho.bytes(at: 0, 4) == Data([1, 2, 3, 4]))
    #expect(macho.bytes(at: 4, 0) == Data())
    #expect(macho.bytes(at: 4, 1) == nil)
    #expect(macho.bytes(at: UInt64.max, 1) == nil)
    #expect(macho.bytes(at: UInt64.max, Int.max) == nil)
    #expect(macho.bytes(at: 0, -1) == nil)
    #expect(macho.pointer(at: 0) == nil)
}

@Test func readerRejectsOverflowWithoutAllocatingRanges() throws {
    let reader = Reader(data: Data([1, 2, 3, 4]))
    for (off, size) in [(Int.max, 1), (1, Int.max), (-1, 1), (0, -1)] {
        #expect(throws: MachOError.self) { try reader.range(off, size) }
    }
    #expect(try reader.u32(0) == 0x0403_0201)
    #expect(try reader.bytes(4, 0).isEmpty)
}

@Test func symbolAndDylibStringsStayWithinDeclaredTables() throws {
    var symtab = loadCommand(0x2, size: 24)
    put(UInt32(56), in: &symtab, at: 8)
    put(UInt32(1), in: &symtab, at: 12)
    put(UInt32(72), in: &symtab, at: 16)
    put(UInt32(3), in: &symtab, at: 20)
    var symbols = Data(repeating: 0, count: 16)
    put(UInt32(1), in: &symbols, at: 0)
    symbols[4] = 0x0e
    symbols.append(contentsOf: [0, 0x78, 0x79, 0])
    #expect(throws: MachOError.self) { try parseMachO(thinMachO([symtab], payload: symbols)) }
    put(UInt32(4), in: &symtab, at: 20)
    #expect(try parseMachO(thinMachO([symtab], payload: symbols)).symbols.first?.name == "xy")
    put(UInt32(4), in: &symbols, at: 0)
    #expect(throws: MachOError.self) { try parseMachO(thinMachO([symtab], payload: symbols)) }
    put(UInt32(0), in: &symbols, at: 0)
    put(UInt32(0), in: &symtab, at: 20)
    #expect(try parseMachO(thinMachO([symtab], payload: symbols)).symbols.isEmpty)
    var dylib = loadCommand(0xc, size: 32)
    put(UInt32(24), in: &dylib, at: 8)
    dylib.replaceSubrange(24..<32, with: repeatElement(UInt8(0x78), count: 8))
    #expect(throws: MachOError.self) { try parseMachO(thinMachO([dylib], payload: Data([0]))) }
    dylib[31] = 0
    #expect(try parseMachO(thinMachO([dylib])).dylibs == ["xxxxxxx"])
}

@Test func rejectsMalformedFunctionStarts() throws {
    let invalid: [[UInt8]] = [[0x80], [1], Array(repeating: 0x80, count: 10) + [0], Array(repeating: 0xff, count: 9) + [2, 0]]
    for payload in invalid {
        let command = linkedit(0x26, offset: 48, size: UInt32(payload.count))
        #expect(throws: MachOError.self) { try parseMachO(thinMachO([command], payload: Data(payload))) }
    }
    let command = linkedit(0x26, offset: 48, size: 4)
    #expect(try parseMachO(thinMachO([command], payload: Data([1, 0x80, 1, 0]))).functionStarts == [1, 129])
    let overflow = linkedit(0x26, offset: 120, size: 2)
    #expect(throws: MachOError.self) {
        try parseMachO(thinMachO([segment64(vmaddr: UInt64.max - 1, vmsize: 1), overflow], payload: Data([2, 0])))
    }
    #expect(throws: MachOError.self) { try parseMachO(thinMachO([linkedit(0x26, offset: 48, size: 2)], payload: Data([0]))) }
}

private func chainedMachO(pointerFormat: UInt16 = 2, importFormat: UInt32 = 1) -> Data {
    let stride = importFormat == 1 ? 4 : importFormat == 2 ? 8 : 16
    var fixups = Data(repeating: 0, count: 60 + stride)
    put(UInt32(28), in: &fixups, at: 4)
    put(UInt32(60), in: &fixups, at: 8)
    put(UInt32(60 + stride), in: &fixups, at: 12)
    put(UInt32(1), in: &fixups, at: 16)
    put(importFormat, in: &fixups, at: 20)
    put(UInt32(1), in: &fixups, at: 28)
    put(UInt32(8), in: &fixups, at: 32)
    put(UInt32(24), in: &fixups, at: 36)
    put(UInt16(4096), in: &fixups, at: 40)
    put(pointerFormat, in: &fixups, at: 42)
    put(UInt16(1), in: &fixups, at: 56)
    fixups.append(contentsOf: [0x5f, 0x78, 0])
    var pointer = Data(repeating: 0, count: 8)
    put(UInt64(1) << ([UInt16(1), 9, 12].contains(pointerFormat) ? 62 : 63), in: &pointer, at: 0)
    return thinMachO([segment64(fileoff: 120, filesize: 8), linkedit(0x8000_0034, offset: 128, size: UInt32(fixups.count))], payload: pointer + fixups)
}

@Test(arguments: [UInt16(1), 2, 6, 9, 12], [UInt32(1), 2, 3])
func acceptsSupportedChainedBindings(pointerFormat: UInt16, importFormat: UInt32) throws {
    let macho = try parseMachO(chainedMachO(pointerFormat: pointerFormat, importFormat: importFormat))
    #expect(macho.binds == [0x1000: "_x"])
    #expect(macho.pointer(at: 0x1000) != nil)
}

@Test func rejectsChainedFixupsOutsideTheirPayload() {
    let valid = chainedMachO()
    for (offset, value) in [(116, UInt32(27)), (132, UInt32.max), (136, UInt32.max), (140, UInt32.max),
                            (144, UInt32.max), (156, 2), (160, UInt32.max), (164, 22)] {
        var data = valid
        put(value, in: &data, at: offset)
        #expect(throws: MachOError.self) { try parseMachO(data) }
    }
    var unterminated = valid
    unterminated[unterminated.count - 1] = 0x78
    unterminated.append(0)
    #expect(throws: MachOError.self) { try parseMachO(unterminated) }
    var ordinal = valid
    put((UInt64(1) << 63) | 1, in: &ordinal, at: 120)
    #expect(throws: MachOError.self) { try parseMachO(ordinal) }
    var escapedChain = valid
    put((UInt64(1) << 63) | (UInt64(2) << 51), in: &escapedChain, at: 120)
    #expect(throws: MachOError.self) { try parseMachO(escapedChain) }
    for (offset, value) in [(168, UInt16(0)), (184, UInt16(2)), (186, UInt16(4095)), (186, UInt16(0x8000))] {
        var data = valid
        put(value, in: &data, at: offset)
        #expect(throws: MachOError.self) { try parseMachO(data) }
    }
}

@Test func unsupportedChainedMetadataFailsExplicitly() {
    func expectUnsupported(_ data: Data) {
        do {
            _ = try parseMachO(data)
            Issue.record("Unsupported chained metadata was silently accepted")
        } catch let error as MachOError {
            #expect(error.message.hasPrefix("Unsupported"), "\(error)")
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }
    for offset in [128, 148, 152] {
        var data = chainedMachO()
        put(UInt32(99), in: &data, at: offset)
        expectUnsupported(data)
    }
    var data = chainedMachO()
    put(UInt16(3), in: &data, at: 170)
    expectUnsupported(data)
    data = chainedMachO()
    put(UInt16(0x8000), in: &data, at: 186)
    expectUnsupported(data)
}

@Test func emptyChainedTablesIgnoreUnusedFormats() throws {
    var data = chainedMachO()
    put(UInt32(0), in: &data, at: 132) // no starts
    put(UInt32(0), in: &data, at: 144) // no imports
    put(UInt32(99), in: &data, at: 148)
    put(UInt32(99), in: &data, at: 152)
    #expect(try parseMachO(data).binds.isEmpty)
    data = chainedMachO()
    put(UInt16(0), in: &data, at: 184) // no pages
    put(UInt16(0), in: &data, at: 168)
    put(UInt16(99), in: &data, at: 170)
    #expect(try parseMachO(data).binds.isEmpty)
}

@Test func stubDecoderDoesNotReadPastSmallStubRecords() throws {
    var section = section64(addr: 0x1000, size: 8, offset: 184, flags: 0x8000_0008)
    section.replaceSubrange(0..<7, with: Data("__stubs".utf8))
    put(UInt32(4), in: &section, at: 72)
    let segment = segment64(fileoff: 184, filesize: 8, section: section)
    let macho = try parseMachO(thinMachO([segment], payload: Data(repeating: 0, count: 8)))
    #expect(macho.stubSlots().isEmpty)
}

@Test func dataInCodeRejectsTruncationAndEscapingRanges() throws {
    let segment = segment64(fileoff: 120, filesize: 4)
    var entry = Data(repeating: 0, count: 8)
    put(UInt32(120), in: &entry, at: 0)
    put(UInt16(4), in: &entry, at: 4)
    let valid = thinMachO([segment, linkedit(0x29, offset: 124, size: 8)], payload: Data([1, 2, 3, 4]) + entry)
    #expect(try parseMachO(valid).dataInCode.first?.length == 4)
    for (offset, value) in [(116, UInt32(7)), (116, UInt32(16)), (124, UInt32(121))] {
        var data = valid
        put(value, in: &data, at: offset)
        #expect(throws: MachOError.self) { try parseMachO(data) }
    }
}

@Test func providerRecoversAfterMalformedMachOOpen() throws {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("malformed-macho-\(UUID().uuidString)")
    try fatMachO(count: 0).write(to: url)
    defer { try? FileManager.default.removeItem(at: url) }
    let server = ProviderServer()
    func call(_ id: Int, _ name: String, _ arguments: [String: Any]) throws -> [String: Any] {
        let response = try #require(server.handle(["jsonrpc": "2.0", "id": id, "method": "tools/call",
                                                   "params": ["name": name, "arguments": arguments]]))
        return try #require(response["result"] as? [String: Any])
    }
    #expect(try call(1, "idb_open", ["input_path": url.path])["isError"] as? Bool == true)
    let valid = try fixtureBinary(arch: "arm64", strip: false)
    let opened = try call(2, "idb_open", ["input_path": valid.path, "preferred_session_id": "recovered"])
    #expect(opened["isError"] as? Bool == false)
    let content = try #require(opened["structuredContent"] as? [String: Any])
    #expect((content["result"] as? [String: Any])?["success"] as? Bool == true)
    #expect(try call(3, "idb_close", ["database": "recovered", "save": false])["isError"] as? Bool == false)
}
