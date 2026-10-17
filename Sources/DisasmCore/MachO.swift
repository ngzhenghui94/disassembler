import Foundation

public struct MachOError: Error, LocalizedError {
    public let message: String
    public var errorDescription: String? { message }
}

/// Bounds-checked little-endian reads; every offset comes from an untrusted file.
struct Reader {
    let data: Data

    func bytes(_ off: Int, _ len: Int) throws -> Data {
        guard off >= 0, len >= 0, off <= data.count - len else {
            throw MachOError(message: "Truncated or malformed file (read \(len) bytes at 0x\(String(off, radix: 16)))")
        }
        return data.subdata(in: off..<off + len)
    }
    func u8(_ off: Int) throws -> UInt8 { try bytes(off, 1)[0] }
    func u16(_ off: Int) throws -> UInt16 { try bytes(off, 2).withUnsafeBytes { $0.loadUnaligned(as: UInt16.self) } }
    func u32(_ off: Int) throws -> UInt32 { try bytes(off, 4).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) } }
    func u64(_ off: Int) throws -> UInt64 { try bytes(off, 8).withUnsafeBytes { $0.loadUnaligned(as: UInt64.self) } }
    func fixedString(_ off: Int, _ len: Int) throws -> String {
        String(decoding: try bytes(off, len).prefix { $0 != 0 }, as: UTF8.self)
    }
    func cString(_ off: Int) -> String {
        guard off >= 0, off < data.count else { return "" }
        let end = data[off...].firstIndex(of: 0) ?? data.count
        return String(decoding: data[off..<end], as: UTF8.self)
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
    public var isCode: Bool { flags & 0x8000_0000 != 0 }   // S_ATTR_PURE_INSTRUCTIONS
    public var isCString: Bool { flags & 0xff == 0x2 }       // S_CSTRING_LITERALS
    public var fullName: String { "\(segment),\(name)" }
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
    let reader: Reader

    public var data: Data { reader.data }
    public var textBase: UInt64 { segments.first { $0.name == "__TEXT" }?.vmaddr ?? 0 }

    /// Splits a fat file into slices; a thin file yields one slice.
    public static func slices(of data: Data) throws -> [ArchSlice] {
        let r = Reader(data: data)
        let magic = UInt32(bigEndian: try r.u32(0))
        guard magic == 0xcafe_babe || magic == 0xcafe_babf else {
            let m = try r.u32(0)
            guard m == 0xfeed_facf else {
                throw MachOError(message: m == 0xfeed_face ? "32-bit Mach-O is not supported" : "Not a Mach-O file")
            }
            return [ArchSlice(arch: archName(try r.u32(4), try r.u32(8)), data: data)]
        }
        let is64 = magic == 0xcafe_babf
        let count = Int(UInt32(bigEndian: try r.u32(4)))
        var result: [ArchSlice] = []
        for i in 0..<min(count, 64) {
            let base = 8 + i * (is64 ? 32 : 20)
            let cpu = UInt32(bigEndian: try r.u32(base)), sub = UInt32(bigEndian: try r.u32(base + 4))
            let off = is64 ? Int(truncatingIfNeeded: UInt64(bigEndian: try r.u64(base + 8))) : Int(UInt32(bigEndian: try r.u32(base + 8)))
            let size = is64 ? Int(truncatingIfNeeded: UInt64(bigEndian: try r.u64(base + 16))) : Int(UInt32(bigEndian: try r.u32(base + 12)))
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
        guard try r.u32(0) == 0xfeed_facf else { throw MachOError(message: "Only 64-bit Mach-O slices are supported") }
        fileType = try r.u32(12)
        let ncmds = Int(try r.u32(16))
        var off = 32
        var symtab: (symoff: Int, nsyms: Int, stroff: Int)?
        var starts: (off: Int, size: Int)?
        var entryOff: UInt64?
        for _ in 0..<ncmds {
            let cmd = try r.u32(off), size = Int(try r.u32(off + 4))
            guard size >= 8 else { throw MachOError(message: "Bad load command size") }
            switch cmd {
            case 0x19: // LC_SEGMENT_64
                segments.append(Segment(name: try r.fixedString(off + 8, 16), vmaddr: try r.u64(off + 24),
                                        vmsize: try r.u64(off + 32), fileoff: try r.u64(off + 40), filesize: try r.u64(off + 48)))
                for s in 0..<Int(try r.u32(off + 64)) {
                    let so = off + 72 + s * 80
                    sections.append(Section(segment: try r.fixedString(so + 16, 16), name: try r.fixedString(so, 16),
                                            addr: try r.u64(so + 32), size: try r.u64(so + 40),
                                            offset: try r.u32(so + 48), flags: try r.u32(so + 64)))
                }
            case 0x2: // LC_SYMTAB
                symtab = (Int(try r.u32(off + 8)), Int(try r.u32(off + 12)), Int(try r.u32(off + 16)))
            case 0x26: // LC_FUNCTION_STARTS
                starts = (Int(try r.u32(off + 8)), Int(try r.u32(off + 12)))
            case 0x8000_0028: // LC_MAIN
                entryOff = try r.u64(off + 8)
            case 0xc, 0x8000_0018, 0x8000_001f, 0xd: // LC_LOAD_DYLIB, _WEAK_, LC_REEXPORT_DYLIB, LC_ID_DYLIB
                if cmd != 0xd { dylibs.append(r.cString(off + Int(try r.u32(off + 8)))) }
            case 0x1b: // LC_UUID
                uuid = try r.bytes(off + 8, 16).withUnsafeBytes { UUID(uuid: $0.loadUnaligned(as: uuid_t.self)) }
            default: break
            }
            off += size
        }
        if let e = entryOff { entry = textBase + e }
        if let st = symtab {
            for i in 0..<st.nsyms {
                let o = st.symoff + i * 16
                let type = try r.u8(o + 4)
                // Skip debug (N_STAB) entries; keep only symbols defined in a section (N_SECT).
                guard type & 0xe0 == 0, type & 0x0e == 0x0e else { continue }
                let name = r.cString(st.stroff + Int(try r.u32(o)))
                if !name.isEmpty { symbols.append(Symbol(name: name, address: try r.u64(o + 8), section: Int(try r.u8(o + 5)))) }
            }
        }
        if let fs = starts {
            // ULEB128 deltas from the __TEXT segment start, zero-terminated.
            var addr = textBase, i = fs.off, shift: UInt64 = 0, value: UInt64 = 0
            while i < fs.off + fs.size {
                let b = try r.u8(i); i += 1
                value |= UInt64(b & 0x7f) << shift
                if b & 0x80 != 0 { shift += 7; if shift > 63 { break }; continue }
                if value == 0 { break }
                addr &+= value
                functionStarts.append(addr)
                value = 0; shift = 0
            }
        }
    }

    public func section(containing addr: UInt64) -> Section? {
        sections.first { addr >= $0.addr && addr < $0.addr + $0.size }
    }

    /// Reads a pointer-sized value at a VM address, if it is backed by file data.
    func pointer(at addr: UInt64) -> UInt64? {
        guard let seg = segments.first(where: { addr >= $0.vmaddr && addr - $0.vmaddr + 8 <= $0.filesize }) else { return nil }
        return try? reader.u64(Int(truncatingIfNeeded: seg.fileoff &+ (addr - seg.vmaddr)))
    }
}
