import Foundation

/// Android's little-endian ELF32/ELF64 images, mapped into the shared analysis model.
struct ELF {
    let arch: String
    let fileType: UInt32
    var segments: [Segment] = []
    var sections: [Section] = []
    var symbols: [Symbol] = []
    var functionStarts: [UInt64] = []
    var entry: UInt64?
    var dylibs: [String] = []
    var binds: [UInt64: String] = [:]
    var armModes: [UInt64: Bool] = [:] // address -> Thumb, including ELF mapping symbols

    static func arch(_ r: Reader) throws -> String {
        guard try r.u32(0) == 0x464c457f, try r.u8(5) == 1, try r.u8(6) == 1 else {
            throw MachOError(message: "Only little-endian ELF version 1 is supported")
        }
        switch (try r.u8(4), try r.u16(18)) {
        case (2, 183): return "arm64"
        case (2, 62): return "x86_64"
        case (1, 40): return "arm"
        case (1, 3): return "x86"
        default: throw MachOError(message: "Unsupported ELF architecture (expected Android ARM, ARM64, x86 or x86_64)")
        }
    }

    init(_ r: Reader) throws {
        arch = try Self.arch(r)
        let wide = try r.u8(4) == 2
        let word = wide ? 8 : 4
        func uint(_ offset: Int) throws -> UInt64 { try wide ? r.u64(offset) : UInt64(r.u32(offset)) }
        func invalid(_ message: String) -> MachOError { MachOError(message: "Malformed ELF: " + message) }
        func range(_ offset: UInt64, _ size: UInt64) throws -> Range<Int> {
            guard offset <= UInt64(r.data.count), size <= UInt64(r.data.count) - offset else {
                throw invalid("file range is out of bounds")
            }
            return Int(offset)..<Int(offset + size)
        }
        func table(_ offset: UInt64, _ count: UInt64, _ stride: UInt64, minimum: Int) throws -> [Int] {
            guard stride >= minimum, stride <= UInt64(r.data.count), count <= UInt64(r.data.count) / stride else {
                throw invalid("invalid table entry size or count")
            }
            _ = try range(offset, count * stride)
            return (0..<Int(count)).map { Int(offset) + $0 * Int(stride) }
        }
        _ = try r.bytes(0, wide ? 64 : 52)
        guard try r.u32(20) == 1, try r.u16(wide ? 52 : 40) == (wide ? 64 : 52) else {
            throw invalid("invalid header version or size")
        }
        fileType = UInt32(try r.u16(16))
        guard fileType == 2 || fileType == 3 else {
            throw MachOError(message: "Open a linked ELF executable or .so library, not an object or core file")
        }
        let start = try uint(24)
        if start != 0 { entry = arch == "arm" ? start & ~1 : start }

        let phoff = try uint(wide ? 32 : 28), shoff = try uint(wide ? 40 : 32)
        let phsize = UInt64(try r.u16(wide ? 54 : 42)), phcount = UInt64(try r.u16(wide ? 56 : 44))
        let shsize = UInt64(try r.u16(wide ? 58 : 46))
        var shcount = UInt64(try r.u16(wide ? 60 : 48)), namesIndex = UInt64(try r.u16(wide ? 62 : 50))
        guard shoff != 0 else { throw MachOError(message: "ELF files without section headers are not supported") }
        _ = try range(shoff, wide ? 64 : 40)
        if shcount == 0 { shcount = try uint(Int(shoff) + (wide ? 32 : 20)) }
        if namesIndex == 0xffff { namesIndex = UInt64(try r.u32(Int(shoff) + (wide ? 40 : 24))) }
        let headers = try table(shoff, shcount, shsize, minimum: wide ? 64 : 40)
        guard namesIndex > 0, namesIndex < headers.count else { throw invalid("missing section name table") }

        struct Header {
            let name, type: UInt32
            let flags, addr, offset, size, stride: UInt64
            let link: Int
        }
        let raw: [Header] = try headers.map { o in
            let h = Header(name: try r.u32(o), type: try r.u32(o + 4), flags: try uint(o + 8),
                           addr: try uint(o + (wide ? 16 : 12)), offset: try uint(o + (wide ? 24 : 16)),
                           size: try uint(o + (wide ? 32 : 20)), stride: try uint(o + (wide ? 56 : 36)),
                           link: Int(try r.u32(o + (wide ? 40 : 24))))
            guard h.addr <= UInt64.max - h.size, h.offset <= UInt32.max, h.size <= Int.max else {
                throw invalid("section address or size overflows")
            }
            if h.type != 0 && h.type != 8 { _ = try range(h.offset, h.size) }
            return h
        }
        func string(_ index: UInt64, in section: Int) throws -> String {
            guard raw.indices.contains(section), raw[section].type == 3 else { throw invalid("invalid string table") }
            let h = raw[section]
            guard index < h.size else { throw invalid("string offset is out of bounds") }
            let bytes = r.data[Int(h.offset + index)..<Int(h.offset + h.size)]
            guard let end = bytes.firstIndex(of: 0) else { throw invalid("unterminated string") }
            return String(decoding: bytes[..<end], as: UTF8.self)
        }
        for h in raw {
            let name = try string(UInt64(h.name), in: Int(namesIndex))
            let code = h.flags & 4 != 0
            let strings = h.type == 1 && h.flags & 2 != 0 && !code && (h.flags & 0x20 != 0 || name == ".rodata" || name.hasPrefix(".rodata."))
            sections.append(Section(segment: "", name: name, addr: h.addr, size: h.size, offset: UInt32(h.offset),
                                    flags: code ? 0x8000_0000 : (strings ? 2 : 0), isMapped: h.flags & 2 != 0))
        }
        for o in try table(phoff, phcount, phsize, minimum: wide ? 56 : 32) where try r.u32(o) == 1 {
            let flags = try r.u32(o + (wide ? 4 : 24))
            let offset = try uint(o + (wide ? 8 : 4)), addr = try uint(o + (wide ? 16 : 8))
            let size = try uint(o + (wide ? 32 : 16)), memorySize = try uint(o + (wide ? 40 : 20))
            _ = try range(offset, size)
            guard size <= memorySize, addr <= UInt64.max - memorySize else { throw invalid("invalid load segment") }
            segments.append(Segment(name: flags & 1 != 0 ? "__TEXT" : "LOAD", vmaddr: addr, vmsize: memorySize,
                                    fileoff: offset, filesize: size))
        }
        guard !segments.isEmpty else { throw invalid("no loadable segments") }

        var symbolNames: [Int: [String]] = [:]
        for (index, h) in raw.enumerated() where h.type == 2 || h.type == 11 {
            guard h.stride != 0, h.size % h.stride == 0 else { throw invalid("invalid symbol table size") }
            var names: [String] = []
            for o in try table(h.offset, h.size / h.stride, h.stride, minimum: wide ? 24 : 16) {
                let name = try string(UInt64(r.u32(o)), in: h.link)
                names.append(name)
                let type = try r.u8(o + (wide ? 4 : 12)) & 0xf
                let section = Int(try r.u16(o + (wide ? 6 : 14)))
                guard section > 0, section < raw.count, !name.isEmpty else { continue }
                var addr = try uint(o + (wide ? 8 : 4))
                if arch == "arm" {
                    if type == 2 { armModes[addr & ~1] = addr & 1 != 0 }
                    if name == "$t" || name.hasPrefix("$t.") { armModes[addr] = true }
                    if name == "$a" || name.hasPrefix("$a.") { armModes[addr] = false }
                }
                guard !name.hasPrefix("$"), [0, 1, 2, 10].contains(type) else { continue }
                if arch == "arm", type == 2 { addr &= ~1 } // Thumb function values carry the instruction-set bit.
                symbols.append(Symbol(name: name, address: addr, section: section + 1))
                if type == 2 || type == 10 { functionStarts.append(addr) }
            }
            symbolNames[index] = names
        }
        for h in raw where h.type == 6 {
            guard h.stride != 0, h.size % h.stride == 0 else { throw invalid("invalid dynamic table size") }
            for o in try table(h.offset, h.size / h.stride, h.stride, minimum: word * 2) {
                let tag = try uint(o)
                if tag == 0 { break }
                if tag == 1 { dylibs.append(try string(uint(o + word), in: h.link)) }
            }
        }
        for h in raw where h.type == 4 || h.type == 9 {
            guard h.stride != 0, h.size % h.stride == 0, let names = symbolNames[h.link] else {
                throw invalid("invalid relocation table")
            }
            for o in try table(h.offset, h.size / h.stride, h.stride, minimum: word * (h.type == 4 ? 3 : 2)) {
                let addr = try uint(o), info = try uint(o + word)
                let index = Int(info >> (wide ? 32 : 8))
                guard index < names.count else { throw invalid("relocation symbol is out of bounds") }
                if index > 0, !names[index].isEmpty { binds[addr] = names[index] }
            }
        }
    }
}
