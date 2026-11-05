import Foundation

public struct MachOError: Error, LocalizedError {
    public let message: String
    public init(message: String) { self.message = message }
    public var errorDescription: String? { message }
}

/// Bounds-checked little-endian reads; every offset comes from an untrusted file.
struct Reader {
    let data: Data

    @discardableResult
    func range(_ off: Int, _ len: Int) throws -> Range<Int> {
        guard off >= 0, len >= 0, off <= data.count, len <= data.count - off else {
            throw MachOError(message: "Truncated or malformed file (read \(len) bytes at 0x\(String(off, radix: 16)))")
        }
        return off..<off + len
    }
    func bytes(_ off: Int, _ len: Int) throws -> Data {
        data.subdata(in: try range(off, len))
    }
    private func value<T>(_ off: Int, as type: T.Type) throws -> T {
        try range(off, MemoryLayout<T>.size)
        return data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: off, as: type) }
    }
    func u8(_ off: Int) throws -> UInt8 { try value(off, as: UInt8.self) }
    func u16(_ off: Int) throws -> UInt16 { try value(off, as: UInt16.self) }
    func u32(_ off: Int) throws -> UInt32 { try value(off, as: UInt32.self) }
    func u64(_ off: Int) throws -> UInt64 { try value(off, as: UInt64.self) }
    func fixedString(_ off: Int, _ len: Int) throws -> String {
        String(decoding: data[try range(off, len)].prefix { $0 != 0 }, as: UTF8.self)
    }
    func cString(_ off: Int, end: Int) throws -> String {
        guard end <= data.count, off >= 0, off < end,
              let nul = data[off..<end].firstIndex(of: 0) else {
            throw MachOError(message: "Unterminated or out-of-range string")
        }
        return String(decoding: data[off..<nul], as: UTF8.self)
    }
}

/// One architecture inside a (possibly fat) file.
public struct ArchSlice: Sendable, Identifiable, Hashable {
    public let arch: String
    public let data: Data
    public var id: String { arch }
}

public struct Segment: Sendable, Hashable {
    public let name: String
    public let vmaddr, vmsize, fileoff, filesize: UInt64
}

public struct Section: Sendable, Hashable {
    public let segment, name: String
    public let addr, size: UInt64
    public let offset, flags: UInt32
    public var reserved2: UInt32 = 0                         // stub size for symbol stub sections
    public var isMapped: Bool = true
    public var isCode: Bool { flags & 0x8000_0000 != 0 }   // S_ATTR_PURE_INSTRUCTIONS
    public var isCString: Bool { flags & 0xff == 0x2 }       // S_CSTRING_LITERALS
    public var fullName: String { segment.isEmpty ? name : "\(segment),\(name)" }
}

public struct Symbol: Sendable, Hashable {
    public let name: String
    public let address: UInt64
    public let section: Int   // 1-based section ordinal
}

public struct MachO: Sendable {
    public let arch: String
    public let fileType: UInt32
    public private(set) var segments: [Segment] = []
    public private(set) var sections: [Section] = []
    public private(set) var symbols: [Symbol] = []
    public private(set) var functionStarts: [UInt64] = []
    public private(set) var entry: UInt64?
    public private(set) var dylibs: [String] = []
    public private(set) var uuid: UUID?
    public private(set) var binds: [UInt64: String] = [:]   // pointer slot -> imported symbol (chained fixups)
    public private(set) var dataInCode: [(addr: UInt64, length: Int, fileOffset: Int)] = []   // jump tables etc. inside __text
    var armModes: [UInt64: Bool] = [:]
    let reader: Reader

    public var data: Data { reader.data }
    public var isELF: Bool { data.starts(with: [0x7f, 0x45, 0x4c, 0x46]) }
    public var isPE: Bool { data.starts(with: [0x4d, 0x5a]) }
    public var supportsPseudocode: Bool { arch.hasPrefix("arm64") || arch == "x86_64" }
    public var typeName: String {
        if isPE { return fileType == 6 ? "DLL" : "Executable" }
        return (isELF ? [2: "Executable", 3: "Shared library"] : [2: "Executable", 6: "Dylib", 8: "Bundle"])[Int(fileType)] ?? "\(fileType)"
    }
    public var textBase: UInt64 { isELF || isPE ? segments.map(\.vmaddr).min() ?? 0 : segments.first { $0.name == "__TEXT" }?.vmaddr ?? 0 }

    /// Splits a fat file into slices; a thin file yields one slice.
    public static func slices(of data: Data) throws -> [ArchSlice] {
        let r = Reader(data: data)
        if try r.u32(0) == 0x464c457f { return [ArchSlice(arch: try ELF.arch(r), data: data)] }
        if try r.u16(0) == 0x5a4d { return [ArchSlice(arch: try PE.arch(r), data: data)] }
        let magic = UInt32(bigEndian: try r.u32(0))
        guard magic == 0xcafe_babe || magic == 0xcafe_babf else {
            let m = try r.u32(0)
            guard m == 0xfeed_facf else {
                throw MachOError(message: m == 0xfeed_face ? "32-bit Mach-O is not supported" : "Not a Mach-O, ELF or Windows PE file")
            }
            try r.range(0, 32)
            return [ArchSlice(arch: archName(try r.u32(4), try r.u32(8)), data: data)]
        }
        let is64 = magic == 0xcafe_babf
        let count = Int(UInt32(bigEndian: try r.u32(4))), stride = is64 ? 32 : 20
        guard count > 0 else { throw MachOError(message: "Fat file has no architecture slices") }
        try r.range(8, count * stride)
        var result: [ArchSlice] = []
        for i in 0..<count {
            let base = 8 + i * stride
            let cpu = UInt32(bigEndian: try r.u32(base)), sub = UInt32(bigEndian: try r.u32(base + 4))
            let offset = is64 ? UInt64(bigEndian: try r.u64(base + 8)) : UInt64(UInt32(bigEndian: try r.u32(base + 8)))
            let length = is64 ? UInt64(bigEndian: try r.u64(base + 16)) : UInt64(UInt32(bigEndian: try r.u32(base + 12)))
            guard let off = Int(exactly: offset), let size = Int(exactly: length), size >= 28,
                  off >= 8 + count * stride else { throw MachOError(message: "Invalid fat slice range") }
            var name = archName(cpu, sub)
            if result.contains(where: { $0.arch == name }) { name += " #\(i + 1)" }
            result.append(ArchSlice(arch: name, data: try r.bytes(off, size)))
        }
        return result
    }

    /// Every Mach-O file inside a bundle (main executable, frameworks, dylibs, plugins, extensions, XPC services),
    /// main executable first. Symlinks are skipped so framework `Versions/Current` aliases aren't listed twice.
    public static func binaries(inBundle bundle: URL) -> [URL] {
        let keys: Set<URLResourceKey> = [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey]
        guard let walker = FileManager.default.enumerator(at: bundle, includingPropertiesForKeys: Array(keys)) else { return [] }
        var found: [URL] = []
        for case let url as URL in walker {
            guard let v = try? url.resourceValues(forKeys: keys), v.isRegularFile == true, v.isSymbolicLink != true,
                  (v.fileSize ?? 0) >= 4096, let h = try? FileHandle(forReadingFrom: url) else { continue }
            let head = (try? h.read(upToCount: 8)) ?? Data()
            try? h.close()
            guard head.count == 8 else { continue }
            let r = Reader(data: head)
            let magic = (try? r.u32(0)) ?? 0, count = UInt32(bigEndian: (try? r.u32(4)) ?? 0)
            // 0xcafebabe is shared with Java class files; a real fat header has only a few slices.
            if magic == 0xfeed_facf || ((magic == 0xbeba_feca || magic == 0xbfba_feca) && count > 0 && count < 16) {
                found.append(url.standardizedFileURL)
            }
        }
        let main = Bundle(url: bundle)?.executableURL?.resolvingSymlinksInPath().path
        func rank(_ u: URL) -> Int { u.resolvingSymlinksInPath().path == main ? 0 : 1 }
        return found.sorted { (rank($0), $0.path) < (rank($1), $1.path) }
    }

    static func archName(_ cpu: UInt32, _ sub: UInt32) -> String {
        switch cpu {
        case 0x0100_000c: return sub & 0x00ff_ffff == 2 ? "arm64e" : "arm64"
        case 0x0100_0007: return "x86_64"
        default: return "cpu 0x\(String(cpu, radix: 16))"
        }
    }

    public init(slice: ArchSlice) throws {
        let r = Reader(data: slice.data)
        reader = r
        arch = slice.arch
        if try r.u16(0) == 0x5a4d {
            let pe = try PE(r)
            guard arch == pe.arch else { throw MachOError(message: "PE architecture does not match its slice") }
            fileType = pe.fileType
            segments = pe.segments; sections = pe.sections; symbols = pe.symbols
            functionStarts = pe.functionStarts; entry = pe.entry; dylibs = pe.dylibs; binds = pe.binds
            return
        }
        if try r.u32(0) == 0x464c457f {
            let elf = try ELF(r)
            guard arch == elf.arch else { throw MachOError(message: "ELF architecture does not match its slice") }
            fileType = elf.fileType
            segments = elf.segments; sections = elf.sections; symbols = elf.symbols
            functionStarts = elf.functionStarts; entry = elf.entry; dylibs = elf.dylibs; binds = elf.binds
            armModes = elf.armModes
            return
        }
        guard try r.u32(0) == 0xfeed_facf else { throw MachOError(message: "Only 64-bit Mach-O slices are supported") }
        try r.range(0, 32)
        fileType = try r.u32(12)
        let ncmds = Int(try r.u32(16)), commandsSize = Int(try r.u32(20))
        let commandsEnd = try r.range(32, commandsSize).upperBound
        guard ncmds <= commandsSize / 8 else { throw MachOError(message: "Load command count exceeds its table") }
        var off = 32
        var symtab: (symoff: Int, nsyms: Int, stroff: Int, strsize: Int)?
        var starts: (off: Int, size: Int)?
        var entryOff: UInt64?
        var fixups: (off: Int, size: Int)?
        var dic: (off: Int, size: Int)?
        for _ in 0..<ncmds {
            guard commandsEnd - off >= 8 else { throw MachOError(message: "Truncated load command") }
            let cmd = try r.u32(off), size = Int(try r.u32(off + 4))
            let minimum: Int
            switch cmd {
            case 0x19: minimum = 72
            case 0x2, 0x8000_0028, 0xc, 0x8000_0018, 0x8000_001f, 0xd, 0x1b: minimum = 24
            case 0x26, 0x29, 0x8000_0034: minimum = 16
            default: minimum = 8
            }
            guard size >= minimum, size % 8 == 0, size <= commandsEnd - off else {
                throw MachOError(message: "Bad load command size")
            }
            switch cmd {
            case 0x19: // LC_SEGMENT_64
                let seg = Segment(name: try r.fixedString(off + 8, 16), vmaddr: try r.u64(off + 24),
                                  vmsize: try r.u64(off + 32), fileoff: try r.u64(off + 40), filesize: try r.u64(off + 48))
                guard seg.vmsize <= UInt64.max - seg.vmaddr, seg.filesize <= UInt64.max - seg.vmaddr,
                      seg.filesize <= UInt64.max - seg.fileoff else { throw MachOError(message: "Overflowing segment range") }
                if seg.filesize > 0 {
                    guard seg.fileoff <= UInt64(r.data.count), seg.filesize <= UInt64(r.data.count) - seg.fileoff else {
                        throw MachOError(message: "Segment extends beyond file")
                    }
                }
                segments.append(seg)
                let nsects = Int(try r.u32(off + 64))
                guard nsects <= (size - 72) / 80 else { throw MachOError(message: "Sections exceed their load command") }
                for s in 0..<nsects {
                    let so = off + 72 + s * 80
                    let sec = Section(segment: try r.fixedString(so + 16, 16), name: try r.fixedString(so, 16),
                                      addr: try r.u64(so + 32), size: try r.u64(so + 40),
                                      offset: try r.u32(so + 48), flags: try r.u32(so + 64), reserved2: try r.u32(so + 72))
                    guard sec.size <= UInt64.max - sec.addr, sec.addr >= seg.vmaddr,
                          sec.addr - seg.vmaddr <= seg.vmsize, sec.size <= seg.vmsize - (sec.addr - seg.vmaddr) else {
                        throw MachOError(message: "Section exceeds its segment address range")
                    }
                    let kind = sec.flags & 0xff
                    let zeroFill = kind == 1 || kind == 0xc || kind == 0x12
                    if !zeroFill && sec.size > 0 {
                        let fileOff = UInt64(sec.offset)
                        guard fileOff >= seg.fileoff, fileOff - seg.fileoff <= seg.filesize,
                              sec.size <= seg.filesize - (fileOff - seg.fileoff),
                              fileOff <= UInt64(r.data.count), sec.size <= UInt64(r.data.count) - fileOff else {
                            throw MachOError(message: "Section exceeds its segment file range")
                        }
                    }
                    sections.append(sec)
                }
            case 0x2: // LC_SYMTAB
                symtab = (Int(try r.u32(off + 8)), Int(try r.u32(off + 12)), Int(try r.u32(off + 16)), Int(try r.u32(off + 20)))
            case 0x26: // LC_FUNCTION_STARTS
                starts = (Int(try r.u32(off + 8)), Int(try r.u32(off + 12)))
            case 0x8000_0028: // LC_MAIN
                entryOff = try r.u64(off + 8)
            case 0xc, 0x8000_0018, 0x8000_001f, 0xd: // LC_LOAD_DYLIB, _WEAK_, LC_REEXPORT_DYLIB, LC_ID_DYLIB
                let nameOff = Int(try r.u32(off + 8))
                guard nameOff >= 24, nameOff < size else { throw MachOError(message: "Invalid dylib name offset") }
                let name = try r.cString(off + nameOff, end: off + size)
                if cmd != 0xd { dylibs.append(name) }
            case 0x1b: // LC_UUID
                uuid = try r.bytes(off + 8, 16).withUnsafeBytes { UUID(uuid: $0.loadUnaligned(as: uuid_t.self)) }
            case 0x29: // LC_DATA_IN_CODE: { u32 fileoff, u16 length, u16 kind } entries
                dic = (Int(try r.u32(off + 8)), Int(try r.u32(off + 12)))
            case 0x8000_0034: // LC_DYLD_CHAINED_FIXUPS
                fixups = (Int(try r.u32(off + 8)), Int(try r.u32(off + 12)))
            default: break
            }
            off += size
        }
        guard off == commandsEnd else { throw MachOError(message: "Load commands do not fill their declared table") }
        if let e = entryOff {
            guard e <= UInt64.max - textBase else { throw MachOError(message: "Overflowing entry point") }
            entry = textBase + e
        }
        if let st = symtab {
            try r.range(st.symoff, st.nsyms * 16)
            let stringsEnd = try r.range(st.stroff, st.strsize).upperBound
            for i in 0..<st.nsyms {
                let o = st.symoff + i * 16
                let type = try r.u8(o + 4)
                // Skip debug (N_STAB) entries; keep only symbols defined in a section (N_SECT).
                guard type & 0xe0 == 0, type & 0x0e == 0x0e else { continue }
                let strx = Int(try r.u32(o))
                guard strx != 0 else { continue } // n_strx == 0 denotes an unnamed symbol.
                guard strx < st.strsize else { throw MachOError(message: "Symbol name exceeds its string table") }
                let name = try r.cString(st.stroff + strx, end: stringsEnd)
                if !name.isEmpty { symbols.append(Symbol(name: name, address: try r.u64(o + 8), section: Int(try r.u8(o + 5)))) }
            }
        }
        if let fs = starts {
            // ULEB128 deltas from the __TEXT segment start, zero-terminated.
            let end = try r.range(fs.off, fs.size).upperBound
            var addr = textBase, i = fs.off, shift: UInt64 = 0, value: UInt64 = 0
            var terminated = fs.size == 0
            while i < end {
                let b = try r.u8(i); i += 1
                guard shift < 64, shift != 63 || b & 0x7e == 0 else { throw MachOError(message: "Overflowing function-start delta") }
                value |= UInt64(b & 0x7f) << shift
                if b & 0x80 != 0 { shift += 7; continue }
                if value == 0 { terminated = true; break }
                guard value <= UInt64.max - addr else { throw MachOError(message: "Overflowing function-start address") }
                addr += value
                functionStarts.append(addr)
                value = 0; shift = 0
            }
            guard terminated else { throw MachOError(message: "Unterminated function starts") }
        }
        if let fx = fixups { binds = try chainedBinds(fx.off, size: fx.size) }
        if let d = dic {
            try r.range(d.off, d.size)
            guard d.size % 8 == 0 else { throw MachOError(message: "Truncated data-in-code entry") }
            for i in 0..<d.size / 8 {
                let fileOff = UInt64(try r.u32(d.off + i * 8)), length = UInt64(try r.u16(d.off + i * 8 + 4))
                guard let seg = segments.first(where: { fileOff >= $0.fileoff && fileOff - $0.fileoff <= $0.filesize && length <= $0.filesize - (fileOff - $0.fileoff) }),
                      fileOff - seg.fileoff <= seg.vmsize, length <= seg.vmsize - (fileOff - seg.fileoff) else {
                    throw MachOError(message: "Data-in-code range exceeds its segment")
                }
                dataInCode.append((seg.vmaddr + (fileOff - seg.fileoff), Int(length), Int(fileOff)))
            }
        }
    }

    /// Stub address -> the pointer slot it jumps through, decoded from __stubs/__auth_stubs (otool doesn't disassemble them).
    public func stubSlots() -> [UInt64: UInt64] {
        var result: [UInt64: UInt64] = [:]
        for sec in sections where sec.isCode && sec.name.hasSuffix("stubs") && sec.name != "__objc_stubs" && sec.reserved2 > 0 {
            let size = UInt64(sec.reserved2)
            let kind = sec.flags & 0xff
            guard size >= (arch == "x86_64" ? 6 : 8), kind != 1, kind != 0xc, kind != 0x12 else { continue }
            for k in 0..<min(sec.size / size, UInt64(data.count) / size) {   // size comes from the file
                let addr = sec.addr + k * size, off = Int(sec.offset) + Int(k * size)
                if arch == "x86_64" {   // jmp *disp32(%rip)
                    guard (try? reader.u16(off)) == 0x25ff, let disp = try? reader.u32(off + 2) else { continue }
                    result[addr] = UInt64(bitPattern: Int64(bitPattern: addr &+ 6) &+ Int64(Int32(bitPattern: disp)))
                    continue
                }
                guard let w0 = try? reader.u32(off), let w1 = try? reader.u32(off + 4), w0 & 0x9f00_0000 == 0x9000_0000 else { continue }
                let pages = (w0 >> 5 & 0x7ffff) << 2 | w0 >> 29 & 3                 // 21-bit signed page delta
                let imm = (Int64(Int32(bitPattern: pages << 11)) >> 11) << 12
                let page = UInt64(bitPattern: Int64(bitPattern: addr & ~0xfff) &+ imm)
                let imm12 = UInt64(w1 >> 10 & 0xfff)
                if w1 & 0xffc0_0000 == 0x9100_0000 { result[addr] = page &+ imm12 }            // add x17, x17, #off
                else if w1 & 0xffc0_0000 == 0xf940_0000 { result[addr] = page &+ (imm12 * 8) }   // ldr x16, [x16, #off]
            }
        }
        return result
    }

    /// Walks every chain in LC_DYLD_CHAINED_FIXUPS and records which slots bind to which import.
    /// shortcut: rebases remain heuristic; unsupported chained encodings fail explicitly until a decoder is added.
    func chainedBinds(_ base: Int, size: Int) throws -> [UInt64: String] {
        let r = reader
        let end = try r.range(base, size).upperBound
        func checked(_ off: Int, _ length: Int) throws -> Int {
            guard off >= base, off <= end, length >= 0, length <= end - off else {
                throw MachOError(message: "Chained fixup data exceeds its payload")
            }
            return off
        }
        _ = try checked(base, 28)
        guard try r.u32(base) == 0 else { throw MachOError(message: "Unsupported chained fixup version") }
        let startsOffset = Int(try r.u32(base + 4))
        let importsCount = Int(try r.u32(base + 16)), format = try r.u32(base + 20)
        var names: [String] = []
        if importsCount > 0 {
            guard try r.u32(base + 24) == 0 else { throw MachOError(message: "Unsupported compressed chained symbols") }
            let importsOff = try checked(base + Int(r.u32(base + 8)), 0)
            let symbolsOff = try checked(base + Int(r.u32(base + 12)), 0)
            guard importsOff >= base + 28, symbolsOff >= base + 28 else { throw MachOError(message: "Chained import table overlaps its header") }
            let stride: Int
            switch format {
            case 1: stride = 4
            case 2: stride = 8
            case 3: stride = 16
            default: throw MachOError(message: "Unsupported chained import format \(format)")
            }
            _ = try checked(importsOff, importsCount * stride)
            for i in 0..<importsCount {
                let nameOff = format == 3 ? Int(try r.u64(importsOff + i * stride) >> 32) : Int(try r.u32(importsOff + i * stride) >> 9)
                names.append(try r.cString(checked(symbolsOff + nameOff, 1), end: end))
            }
        }
        guard startsOffset != 0 else { return [:] }
        guard startsOffset >= 28 else { throw MachOError(message: "Chained starts overlap their header") }
        let startsOff = try checked(base + startsOffset, 4)
        var result: [UInt64: String] = [:]
        let segCount = Int(try r.u32(startsOff))
        guard segCount <= segments.count else { throw MachOError(message: "Chained fixups reference missing segments") }
        _ = try checked(startsOff + 4, segCount * 4)
        for s in 0..<segCount {
            let infoOff = Int(try r.u32(startsOff + 4 + s * 4))
            guard infoOff != 0 else { continue }
            guard infoOff >= 4 + segCount * 4 else { throw MachOError(message: "Chained segment info overlaps its table") }
            let info = try checked(startsOff + infoOff, 4)
            let infoSize = Int(try r.u32(info))
            guard infoSize >= 22 else { throw MachOError(message: "Truncated chained segment info") }
            _ = try checked(info, infoSize)
            let pageSize = Int(try r.u16(info + 4)), ptrFormat = try r.u16(info + 6), pageCount = Int(try r.u16(info + 20))
            guard pageCount <= (infoSize - 22) / 2, pageCount == 0 || pageSize >= 8 else {
                throw MachOError(message: "Invalid chained fixup page table")
            }
            guard pageCount > 0 else { continue }
            let arm64e = ptrFormat == 1 || ptrFormat == 9 || ptrFormat == 12
            let is64 = ptrFormat == 2 || ptrFormat == 6
            guard arm64e || is64 else { throw MachOError(message: "Unsupported chained pointer format \(ptrFormat)") }
            let seg = segments[s]
            for p in 0..<pageCount {
                let start = try r.u16(info + 22 + p * 2)
                guard start != 0xffff else { continue }
                guard start & 0x8000 == 0 else { throw MachOError(message: "Unsupported multi-start chained fixup page") }
                guard Int(start) < pageSize else { throw MachOError(message: "Chained fixup starts outside its page") }
                let pageEnd = (p + 1) * pageSize
                var offInSeg = p * pageSize + Int(start)
                while true {
                    guard offInSeg <= pageEnd - 8, UInt64(offInSeg) <= seg.filesize, 8 <= seg.filesize - UInt64(offInSeg),
                          UInt64(offInSeg) <= seg.vmsize, 8 <= seg.vmsize - UInt64(offInSeg) else {
                        throw MachOError(message: "Chained pointer exceeds its page or segment")
                    }
                    let v = try r.u64(Int(seg.fileoff) + offInSeg)
                    let isBind = arm64e ? v >> 62 & 1 == 1 : v >> 63 == 1
                    if isBind {
                        let ordinal = Int(v & (arm64e && ptrFormat != 12 ? 0xffff : 0xff_ffff))
                        guard ordinal < names.count else { throw MachOError(message: "Chained bind ordinal exceeds imports") }
                        result[seg.vmaddr + UInt64(offInSeg)] = names[ordinal]
                    }
                    let next = arm64e ? Int(v >> 51 & 0x7ff) * 8 : Int(v >> 51 & 0xfff) * 4
                    if next == 0 { break }
                    offInSeg += next
                }
            }
        }
        return result
    }

    public func section(containing addr: UInt64) -> Section? {
        sections.first { $0.isMapped && addr >= $0.addr && addr - $0.addr < $0.size }
    }

    /// Bytes at a VM address, if they are backed by file data.
    public func bytes(at addr: UInt64, _ count: Int) -> Data? {
        guard count >= 0, let seg = segments.first(where: { addr >= $0.vmaddr && addr - $0.vmaddr <= $0.filesize && UInt64(count) <= $0.filesize - (addr - $0.vmaddr) }) else { return nil }
        let (offset, overflow) = seg.fileoff.addingReportingOverflow(addr - seg.vmaddr)
        guard !overflow, let off = Int(exactly: offset) else { return nil }
        return try? reader.bytes(off, count)
    }

    /// Reads a pointer-sized value at a VM address, if it is backed by file data.
    func pointer(at addr: UInt64) -> UInt64? {
        let size: UInt64 = isELF && !supportsPseudocode ? 4 : 8
        guard let seg = segments.first(where: { addr >= $0.vmaddr && addr - $0.vmaddr <= $0.filesize && size <= $0.filesize - (addr - $0.vmaddr) }) else { return nil }
        let (offset, overflow) = seg.fileoff.addingReportingOverflow(addr - seg.vmaddr)
        guard !overflow, let off = Int(exactly: offset) else { return nil }
        return try? size == 4 ? UInt64(reader.u32(off)) : reader.u64(off)
    }
}
