import Foundation

/// Linked Windows AMD64 PE32+ images in the shared analysis address space (preferred, unslid VAs).
struct PE {
    let arch: String
    let fileType: UInt32
    var segments: [Segment] = []
    var sections: [Section] = []
    var symbols: [Symbol] = []
    var functionStarts: [UInt64] = []
    var entry: UInt64?
    var dylibs: [String] = []
    var binds: [UInt64: String] = [:]

    static func header(_ r: Reader) throws -> Int {
        guard try r.u16(0) == 0x5a4d else { throw MachOError(message: "Not a Windows PE image") }
        try r.range(0, 64)
        let off = Int(try r.u32(0x3c))
        guard off >= 64 else { throw MachOError(message: "Malformed PE: NT headers overlap DOS header") }
        try r.range(off, 24)
        guard try r.u32(off) == 0x4550 else { throw MachOError(message: "Not a Windows PE image (missing PE signature)") }
        return off
    }

    static func arch(_ r: Reader) throws -> String {
        let off = try header(r)
        let machine = try r.u16(off + 4)
        guard machine == 0x8664 else {
            throw MachOError(message: "Unsupported PE machine 0x\(String(machine, radix: 16)); only Windows x86-64 is supported")
        }
        let size = Int(try r.u16(off + 20))
        guard size >= 112 else { throw MachOError(message: "Malformed PE: truncated PE32+ optional header") }
        try r.range(off + 24, size)
        guard try r.u16(off + 24) == 0x20b else {
            throw MachOError(message: "Unsupported PE optional-header format; expected PE32+ (64-bit)")
        }
        return "x86_64"
    }

    init(_ r: Reader) throws {
        arch = try Self.arch(r)
        let nt = try Self.header(r), opt = nt + 24
        func invalid(_ message: String) -> MachOError { MachOError(message: "Malformed PE: " + message) }
        let characteristics = try r.u16(nt + 22)
        guard characteristics & 2 != 0, characteristics & 0x100 == 0 else {
            throw MachOError(message: "Open a linked Windows x86-64 PE executable or DLL, not a COFF object")
        }
        fileType = characteristics & 0x2000 != 0 ? 6 : 2
        let base = try r.u64(opt + 24), imageSize = UInt64(try r.u32(opt + 56))
        let headerSize = UInt64(try r.u32(opt + 60))
        let optionalSize = Int(try r.u16(nt + 20)), sectionCount = Int(try r.u16(nt + 6))
        let sectionTable = opt + optionalSize
        guard sectionCount > 0, sectionCount <= 96 else { throw invalid("invalid section count") }
        try r.range(sectionTable, sectionCount * 40)
        guard imageSize > 0, base <= UInt64.max - imageSize,
              headerSize >= UInt64(sectionTable + sectionCount * 40), headerSize <= imageSize,
              headerSize <= UInt64(r.data.count) else { throw invalid("invalid image or header size") }
        let sectionAlignment = try r.u32(opt + 32), fileAlignment = try r.u32(opt + 36)
        guard sectionAlignment > 0, fileAlignment > 0,
              sectionAlignment & (sectionAlignment - 1) == 0, fileAlignment & (fileAlignment - 1) == 0,
              sectionAlignment >= fileAlignment,
              (sectionAlignment >= 0x1000 ? (fileAlignment >= 0x200 && fileAlignment <= 0x10000) : sectionAlignment == fileAlignment),
              headerSize % UInt64(fileAlignment) == 0, imageSize % UInt64(sectionAlignment) == 0 else {
            throw invalid("invalid section/file alignment")
        }

        struct Mapping {
            let rva, size, offset, fileSize: UInt64
            let code: Bool
        }
        var mappings: [Mapping] = []
        segments.append(Segment(name: "Headers", vmaddr: base, vmsize: headerSize, fileoff: 0, filesize: headerSize))
        for i in 0..<sectionCount {
            let off = sectionTable + i * 40
            let name = try r.fixedString(off, 8)
            let virtualSize = UInt64(try r.u32(off + 8)), rva = UInt64(try r.u32(off + 12))
            let rawSize = UInt64(try r.u32(off + 16)), rawOffset = UInt64(try r.u32(off + 20))
            let size = virtualSize == 0 ? rawSize : virtualSize
            let flags = try r.u32(off + 36), code = flags & 0x2000_0000 != 0
            guard rva >= headerSize, rva % UInt64(sectionAlignment) == 0,
                  rva <= imageSize, max(size, rawSize) <= imageSize - rva else { throw invalid("section exceeds image") }
            if rawSize > 0 {
                guard rawOffset >= headerSize, rawOffset % UInt64(fileAlignment) == 0,
                      rawSize % UInt64(fileAlignment) == 0,
                      rawOffset <= UInt64(r.data.count), rawSize <= UInt64(r.data.count) - rawOffset else {
                    throw invalid("section file range is out of bounds or unaligned")
                }
            }
            for prior in mappings {
                guard size == 0 || prior.size == 0 || rva >= prior.rva + prior.size || prior.rva >= rva + size else {
                    throw invalid("overlapping virtual sections")
                }
                guard rawSize == 0 || prior.fileSize == 0 || rawOffset >= prior.offset + prior.fileSize || prior.offset >= rawOffset + rawSize else {
                    throw invalid("overlapping section file ranges")
                }
            }
            mappings.append(Mapping(rva: rva, size: size, offset: rawOffset, fileSize: rawSize, code: code))
            segments.append(Segment(name: name, vmaddr: base + rva, vmsize: size, fileoff: rawOffset, filesize: min(size, rawSize)))
            // Readable initialized data can contain strings; analysis filters binary records and padding.
            let strings = !code && rawSize > 0 && flags & 0x4000_0040 == 0x4000_0040
            sections.append(Section(segment: "", name: name, addr: base + rva, size: size, offset: UInt32(rawOffset),
                                    flags: code ? 0x8000_0000 : (strings ? 2 : rawSize == 0 ? 1 : 0)))
        }
        func mapped(_ rva: UInt64, _ size: UInt64) throws -> (offset: Int, end: Int) {
            guard rva < imageSize, size <= imageSize - rva else { throw invalid("RVA exceeds image") }
            if rva < headerSize {
                guard size <= headerSize - rva else { throw invalid("RVA crosses header boundary") }
                return (Int(rva), Int(headerSize))
            }
            guard let m = mappings.first(where: { rva >= $0.rva && rva - $0.rva < $0.size }),
                  rva - m.rva < m.fileSize, size <= min(m.size, m.fileSize) - (rva - m.rva) else {
                throw invalid("RVA is not backed by section data")
            }
            return (Int(m.offset + rva - m.rva), Int(m.offset + min(m.size, m.fileSize)))
        }
        func string(_ rva: UInt64) throws -> String {
            let range = try mapped(rva, 1)
            return try r.cString(range.offset, end: range.end)
        }
        func codeSection(_ rva: UInt64) -> Int? {
            mappings.firstIndex { $0.code && rva >= $0.rva && rva - $0.rva < min($0.size, $0.fileSize) }
        }
        let start = UInt64(try r.u32(opt + 16))
        if start != 0 {
            guard codeSection(start) != nil else { throw invalid("entry point is not file-backed executable code") }
            entry = base + start
        } else if fileType != 6 {
            throw invalid("executable has no entry point")
        }
        let directoryCount = Int(try r.u32(opt + 108))
        guard directoryCount <= (optionalSize - 112) / 8 else { throw invalid("data directories exceed optional header") }
        var directories: [(rva: UInt64, size: UInt64)] = []
        for i in 0..<directoryCount {
            let rva = UInt64(try r.u32(opt + 112 + i * 8)), size = UInt64(try r.u32(opt + 116 + i * 8))
            if size > 0 {
                guard rva > 0 else { throw invalid("data directory has a null RVA") }
                if i == 4 { // The certificate directory uses a file offset, not an RVA.
                    guard rva <= UInt64(r.data.count), size <= UInt64(r.data.count) - rva else { throw invalid("certificate range exceeds file") }
                } else { _ = try mapped(rva, size) }
            }
            directories.append((rva, size))
        }
        func directory(_ index: Int) -> (rva: UInt64, size: UInt64)? {
            guard index < directories.count, directories[index].size > 0 else { return nil }
            return directories[index]
        }
        if let d = directory(0) {
            guard d.size >= 40 else { throw invalid("truncated export directory") }
            let off = try mapped(d.rva, 40).offset
            let ordinalBase = UInt64(try r.u32(off + 16))
            let count = UInt64(try r.u32(off + 20)), nameCount = UInt64(try r.u32(off + 24))
            let functions = try mapped(UInt64(r.u32(off + 28)), count * 4).offset
            let names = nameCount == 0 ? 0 : try mapped(UInt64(r.u32(off + 32)), nameCount * 4).offset
            let ordinals = nameCount == 0 ? 0 : try mapped(UInt64(r.u32(off + 36)), nameCount * 2).offset
            var exportNames: [Int: [String]] = [:]
            for i in 0..<Int(nameCount) {
                let ordinal = Int(try r.u16(ordinals + i * 2))
                guard ordinal < count else { throw invalid("export ordinal exceeds function table") }
                let name = try string(UInt64(r.u32(names + i * 4)))
                guard !name.isEmpty else { throw invalid("empty export name") }
                exportNames[ordinal, default: []].append(name)
            }
            for i in 0..<Int(count) {
                let rva = UInt64(try r.u32(functions + i * 4))
                guard rva != 0 else { continue } // An unused ordinal is a hole, not address zero.
                if rva >= d.rva && rva - d.rva < d.size {
                    let forwarder = try mapped(rva, 1)
                    _ = try r.cString(forwarder.offset, end: min(forwarder.end, forwarder.offset + Int(d.size - (rva - d.rva))))
                    continue // Forwarded exports have no code or data address in this image.
                }
                guard let section = mappings.firstIndex(where: { rva >= $0.rva && rva - $0.rva < $0.size }) else {
                    throw invalid("export target is outside sections")
                }
                for name in exportNames[i] ?? ["ordinal_\(ordinalBase + UInt64(i))"] {
                    symbols.append(Symbol(name: name, address: base + rva, section: section + 1))
                }
                if codeSection(rva) != nil { functionStarts.append(base + rva) }
            }
        }
        if let d = directory(1) {
            var cursor: UInt64 = 0, terminated = false
            while cursor + 20 <= d.size {
                let off = try mapped(d.rva + cursor, 20).offset
                let lookup = UInt64(try r.u32(off)), timestamp = try r.u32(off + 4)
                let chain = try r.u32(off + 8), nameRVA = UInt64(try r.u32(off + 12)), iat = UInt64(try r.u32(off + 16))
                if lookup == 0 && timestamp == 0 && chain == 0 && nameRVA == 0 && iat == 0 { terminated = true; break }
                guard nameRVA != 0, iat != 0 else { throw invalid("incomplete import descriptor") }
                let library = try string(nameRVA)
                guard !library.isEmpty else { throw invalid("empty import library name") }
                dylibs.append(library)
                let table = lookup == 0 ? iat : lookup
                var index: UInt64 = 0
                while true {
                    let off = try mapped(table + index * 8, 8).offset
                    let slot = try mapped(iat + index * 8, 8).offset
                    let value = try r.u64(off)
                    if value == 0 {
                        guard try r.u64(slot) == 0 else { throw invalid("unterminated import address table") }
                        break
                    }
                    let name: String
                    if value & 0x8000_0000_0000_0000 != 0 {
                        guard value & 0x7fff_ffff_ffff_0000 == 0 else { throw invalid("invalid ordinal import") }
                        name = "\(library)!#\(value & 0xffff)"
                    } else {
                        guard value <= UInt32.max else { throw invalid("invalid import name RVA (bound IAT without lookup table is unsupported)") }
                        _ = try mapped(value, 3)
                        name = try string(value + 2)
                        guard !name.isEmpty else { throw invalid("empty imported symbol name") }
                    }
                    binds[base + iat + index * 8] = name
                    index += 1
                }
                cursor += 20
            }
            guard terminated else { throw invalid("unterminated import descriptor table") }
        }
        if let d = directory(3) {
            guard d.size % 12 == 0 else { throw invalid("invalid exception directory size") }
            let off = try mapped(d.rva, d.size).offset
            var previousEnd: UInt64 = 0
            for i in 0..<Int(d.size / 12) {
                let begin = UInt64(try r.u32(off + i * 12)), end = UInt64(try r.u32(off + i * 12 + 4))
                let unwind = UInt64(try r.u32(off + i * 12 + 8))
                guard let section = codeSection(begin), begin < end,
                      end <= mappings[section].rva + min(mappings[section].size, mappings[section].fileSize),
                      begin >= previousEnd, unwind != 0 else { throw invalid("invalid runtime-function range") }
                _ = try mapped(unwind, 4)
                functionStarts.append(base + begin)
                previousEnd = end
            }
        }
        functionStarts = Array(Set(functionStarts)).sorted()
    }
}
