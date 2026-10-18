import Foundation

public struct Instruction: Sendable, Identifiable, Hashable {
    public let address: UInt64
    public let bytes: String
    public let mnemonic: String
    public let operands: String
    public internal(set) var comment: String
    public internal(set) var target: UInt64?    // direct branch/call destination
    public internal(set) var dataRefs: [UInt64] = []  // data addresses this instruction materializes
    public var id: UInt64 { address }
}

public struct Function: Sendable, Identifiable, Hashable {
    public let name: String
    public let start, end: UInt64
    public let lines: Range<Int>   // indices into Analysis.instructions
    public var id: UInt64 { start }
}

public struct StringRef: Sendable, Identifiable, Hashable {
    public let address: UInt64
    public let value: String
    public let section: String
    public var id: UInt64 { address }
}

public struct Import: Sendable, Identifiable, Hashable {
    public let name: String
    public let stub: UInt64
    public var id: UInt64 { stub }
}

public struct Analysis: Sendable {
    public let macho: MachO
    public let instructions: [Instruction]
    public let functions: [Function]
    public let strings: [StringRef]
    public let imports: [Import]
    public let names: [UInt64: String]
    public let xrefs: [UInt64: [UInt64]]   // referenced address -> referencing instruction addresses
    public let binds: [UInt64: String]     // GOT/pointer slot -> imported symbol, demangled
    let stringAt: [UInt64: String]

    public init(slice: ArchSlice) throws {
        let macho = try MachO(slice: slice)
        self.macho = macho

        var names: [UInt64: String] = [:]
        let demangled = Self.demangle(macho.symbols.map(\.name))
        for (sym, name) in zip(macho.symbols, demangled) where names[sym.address] == nil {
            names[sym.address] = name
        }
        if let e = macho.entry, names[e] == nil { names[e] = "EntryPoint" }

        var strings: [StringRef] = [], empty: [UInt64] = []   // "" is referenced (e.g. @"") but not worth listing
        for sec in macho.sections where sec.isCString {
            guard let bytes = try? macho.reader.bytes(Int(sec.offset), Int(sec.size)) else { continue }
            var start = 0
            for (i, b) in bytes.enumerated() where b == 0 {
                if i > start {
                    strings.append(StringRef(address: sec.addr + UInt64(start),
                                             value: String(decoding: bytes[start..<i], as: UTF8.self), section: sec.name))
                } else if i == 0 || bytes[i - 1] == 0 {
                    empty.append(sec.addr + UInt64(i))
                }
                start = i + 1
            }
        }
        self.strings = strings
        stringAt = Dictionary(strings.map { ($0.address, $0.value) } + empty.map { ($0, "") }, uniquingKeysWith: { a, _ in a })

        let symbolAddress = Dictionary(macho.symbols.map { ($0.name, $0.address) }, uniquingKeysWith: { a, _ in a })
        // x86 instructions vary in length, so decoding a jump table in __text loses sync with the code after it.
        // Disassemble a copy whose data-in-code bytes are 1-byte NOPs; the ranges are dropped below.
        var text = slice.data
        if macho.arch == "x86_64" {
            for d in macho.dataInCode where d.fileOffset >= 0 && d.fileOffset + d.length <= text.count {
                text.replaceSubrange(d.fileOffset..<d.fileOffset + d.length, with: repeatElement(0x90, count: d.length))
            }
        }
        var ins = Self.parseOtool(try Self.otool(text), symbolAddress)
        // otool decodes jump tables in __text as (junk) instructions; the file marks them as data.
        if !macho.dataInCode.isEmpty {
            let ranges = macho.dataInCode.map { $0.addr..<($0.addr + UInt64($0.length)) }.sorted { $0.lowerBound < $1.lowerBound }
            var r = 0   // both lists are in address order: one pass
            ins.removeAll { i in
                while r < ranges.count, ranges[r].upperBound <= i.address { r += 1 }
                return r < ranges.count && ranges[r].contains(i.address)
            }
        }
        var stubs: [UInt64: String] = [:]
        for i in ins where i.target != nil && i.comment.hasPrefix("symbol stub for: ") {
            stubs[i.target!] = String(i.comment.dropFirst("symbol stub for: ".count))
        }
        for (stub, slot) in macho.stubSlots() where stubs[stub] == nil {
            if let name = macho.binds[slot] { stubs[stub] = name }
        }
        let stubAddrs = Array(stubs.keys)
        for (addr, name) in zip(stubAddrs, Self.demangle(stubAddrs.map { stubs[$0]! })) { stubs[addr] = name }
        imports = stubs.map { Import(name: $0.value, stub: $0.key) }.sorted { $0.name < $1.name }
        for (addr, name) in stubs where names[addr] == nil { names[addr] = name }
        let slots = Array(macho.binds.keys)
        binds = Dictionary(uniqueKeysWithValues: zip(slots, Self.demangle(slots.map { macho.binds[$0]! })))
        self.names = names

        // Function boundaries: symbols in code sections + LC_FUNCTION_STARTS + entry point.
        var starts = Set(macho.functionStarts)
        for s in macho.symbols where s.section > 0 && s.section <= macho.sections.count && macho.sections[s.section - 1].isCode {
            starts.insert(s.address)
        }
        if let e = macho.entry { starts.insert(e) }
        if let first = ins.first { starts.insert(first.address) }
        let sortedStarts = starts.sorted()
        var functions: [Function] = []
        for (k, s) in sortedStarts.enumerated() {
            let lo = Self.lowerBound(ins, s)
            let hi = k + 1 < sortedStarts.count ? Self.lowerBound(ins, sortedStarts[k + 1]) : ins.count
            guard lo < hi, ins[lo].address == s else { continue }
            let end = hi < ins.count ? ins[hi].address : ins[hi - 1].address + UInt64(max(ins[hi - 1].bytes.count / 2, 1))
            functions.append(Function(name: names[s] ?? "sub_\(String(s, radix: 16))", start: s, end: end, lines: lo..<hi))
        }
        self.functions = functions

        let isARM = macho.arch.hasPrefix("arm64")
        for f in functions {
            var pages: [String: UInt64] = [:]   // register number -> ADRP page, reset per function
            for i in f.lines {
                if isARM { Self.trackADRP(&ins[i], &pages) } else { Self.ripRelative(&ins[i]) }
            }
        }

        var xrefs: [UInt64: [UInt64]] = [:]
        for i in ins.indices {
            if let t = ins[i].target { xrefs[t, default: []].append(ins[i].address) }
            guard let ref = ins[i].dataRefs.first else { continue }
            var resolved = [ref]
            if macho.section(containing: ref)?.name == "__cfstring" {
                // CFString: { isa, flags, char *str, length }; otool can't follow chained fixups here.
                if let p = Self.derefTarget(macho, ref + 16, stringAt, names), stringAt[p] != nil {
                    resolved.append(p)
                    if ins[i].comment.contains("bad cfstring ref") { ins[i].comment = "" }
                }
            } else if stringAt[ref] == nil, names[ref] == nil, let p = Self.derefTarget(macho, ref, stringAt, names) { resolved.append(p) }
            ins[i].dataRefs = resolved
            for r in resolved { xrefs[r, default: []].append(ins[i].address) }
            if ins[i].comment.isEmpty, resolved.count == 1, let b = binds[ref] { ins[i].comment = "→ " + b }
            if ins[i].comment.isEmpty { ins[i].comment = Self.label(resolved.last!, macho, stringAt, names, via: resolved.count > 1) }
        }
        self.xrefs = xrefs
        instructions = ins
    }

    public func function(containing addr: UInt64) -> Function? {
        var lo = 0, hi = functions.count
        while lo < hi { let m = (lo + hi) / 2; if functions[m].start <= addr { lo = m + 1 } else { hi = m } }
        guard lo > 0, addr < functions[lo - 1].end else { return nil }
        return functions[lo - 1]
    }

    public func instruction(at addr: UInt64) -> Instruction? {
        let i = Self.lowerBound(instructions, addr)
        return i < instructions.count && instructions[i].address == addr ? instructions[i] : nil
    }

    public func name(of addr: UInt64) -> String {
        if let n = names[addr] { return n }
        if let f = function(containing: addr) { return addr == f.start ? f.name : "\(f.name)+0x\(String(addr - f.start, radix: 16))" }
        return "0x" + String(addr, radix: 16)
    }

    // MARK: - otool

    static func otool(_ data: Data) throws -> String {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("disasm-\(UUID().uuidString)")
        try data.write(to: tmp)
        defer { try? FileManager.default.removeItem(at: tmp) }
        // shortcut: whole __text is decoded and held in memory at once; page by function if huge apps get slow.
        return try run("/usr/bin/otool", ["-tvVj", tmp.path])
    }

    static func demangle(_ names: [String]) -> [String] {
        let mangled = names.indices.filter { names[$0].hasPrefix("_$s") || names[$0].hasPrefix("$s") || names[$0].hasPrefix("_T0") }
        guard !mangled.isEmpty else { return names }
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("demangle-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmp) }
        guard (try? mangled.map { names[$0] }.joined(separator: "\n").write(to: tmp, atomically: false, encoding: .utf8)) != nil,
              let out = try? run("/usr/bin/xcrun", ["swift-demangle", "--compact"], stdin: tmp) else { return names }
        let lines = out.split(separator: "\n", omittingEmptySubsequences: false)
        guard lines.count >= mangled.count else { return names }
        var result = names
        for (k, i) in mangled.enumerated() { result[i] = String(lines[k]) }
        return result
    }

    static func run(_ exe: String, _ args: [String], stdin: URL? = nil) throws -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: exe)
        p.arguments = args
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        if let stdin { p.standardInput = try FileHandle(forReadingFrom: stdin) }
        try p.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        guard p.terminationStatus == 0 else {
            throw MachOError(message: "\(URL(fileURLWithPath: exe).lastPathComponent) failed (exit \(p.terminationStatus))")
        }
        return String(decoding: data, as: UTF8.self)
    }

    /// Parses `otool -tvVj` lines: address \t bytes \t mnemonic \t operands [; or ## comment].
    static func parseOtool(_ text: String, _ symbolAddress: [String: UInt64] = [:]) -> [Instruction] {
        var result: [Instruction] = []
        for line in text.split(separator: "\n") {
            let parts = line.split(separator: "\t", maxSplits: 3, omittingEmptySubsequences: false)
            guard parts.count >= 3, let addr = UInt64(parts[0], radix: 16) else { continue }
            var ops = parts.count > 3 ? Substring(parts[3]) : ""
            var comment = ""
            if let r = ops.range(of: "##") ?? ops.range(of: " ; ") {
                comment = ops[r.upperBound...].trimmingCharacters(in: .whitespaces)
                ops = ops[..<r.lowerBound]
            }
            let mnemonic = String(parts[2])
            let operands = ops.trimmingCharacters(in: .whitespaces)
            result.append(Instruction(address: addr, bytes: parts[1].trimmingCharacters(in: .whitespaces),
                                      mnemonic: mnemonic, operands: operands, comment: comment,
                                      target: isBranch(mnemonic) ? branchTarget(operands, symbolAddress) : nil))
        }
        return result
    }

    static func isBranch(_ m: String) -> Bool {
        m == "b" || m == "bl" || m.hasPrefix("b.") || m.hasPrefix("bc.") || m.hasPrefix("cb") || m.hasPrefix("tb")
            || m.hasPrefix("j") || m.hasPrefix("call")
    }

    /// Last operand is either `0x…` or, when symbols exist, `name` / `name+0x…`.
    static func branchTarget(_ operands: String, _ symbolAddress: [String: UInt64]) -> UInt64? {
        // otool quotes names with characters like `$`, `:` or `[` (Obj-C stubs and methods): bl "_objc_msgSend$foo:"
        if operands.hasSuffix("\""), let q = operands.dropLast().split(separator: "\"").last { return symbolAddress[String(q)] }
        guard !operands.contains(where: { "*([".contains($0) }),
              let last = operands.split(whereSeparator: { $0 == " " || $0 == "," }).last else { return nil }
        if last.hasPrefix("0x") { return UInt64(last.dropFirst(2), radix: 16) }
        let parts = last.split(separator: "+", maxSplits: 1)
        guard let base = symbolAddress[String(parts[0])] else { return nil }
        return parts.count == 2 ? imm(parts[1]).map { base &+ UInt64(bitPattern: $0) } : base
    }

    static func imm(_ s: Substring) -> Int64? {
        var t = s.trimmingCharacters(in: .whitespaces)[...]
        if t.hasPrefix("#") { t = t.dropFirst() }
        let neg = t.hasPrefix("-")
        if neg { t = t.dropFirst() }
        guard let v = t.hasPrefix("0x") ? Int64(t.dropFirst(2), radix: 16) : Int64(t) else { return nil }
        return neg ? -v : v
    }

    static func reg(_ s: Substring) -> String? {
        let t = s.trimmingCharacters(in: .whitespaces)
        guard t.count > 1, t.first == "x" || t.first == "w", Int(t.dropFirst()) != nil else { return nil }
        return String(t.dropFirst())
    }

    /// Resolves ADRP + ADD/LDR/STR pairs into absolute addresses (what Hopper shows as string/data refs).
    static func trackADRP(_ ins: inout Instruction, _ pages: inout [String: UInt64]) {
        let m = ins.mnemonic
        let ops = ins.operands.components(separatedBy: ", ").map { Substring($0) }
        if m == "adrp", let d = ops.first.flatMap(reg), let page = ins.comment.split(separator: " ").first.flatMap({ UInt64($0.dropFirst(2), radix: 16) }) {
            pages[d] = page
            return
        }
        var addr: UInt64?
        if m == "add", ops.count == 3, let s = reg(ops[1]), let p = pages[s], let v = imm(ops[2]) {
            addr = UInt64(bitPattern: Int64(bitPattern: p) &+ v)
        } else if m.hasPrefix("ld") || m.hasPrefix("st"), ins.operands.hasSuffix("]"), let open = ins.operands.lastIndex(of: "[") {
            let inner = ins.operands[ins.operands.index(after: open)..<ins.operands.index(before: ins.operands.endIndex)]
                .components(separatedBy: ", ").map { Substring($0) }
            if let s = reg(inner[0]), let p = pages[s], inner.count <= 2, let v = inner.count == 2 ? imm(inner[1]) : 0 {
                addr = UInt64(bitPattern: Int64(bitPattern: p) &+ v)
            }
        }
        if let addr { ins.dataRefs = [addr] }
        // Conservatively forget registers this instruction may overwrite.
        // After a call or an unconditional transfer, the next instruction is reached from elsewhere: the pages
        // tracked in address order no longer describe it.
        if m.hasPrefix("bl") || ["b", "br", "braa", "brab", "braaz", "brabz", "ret", "retaa", "retab", "brk", "udf"].contains(m) {
            pages.removeAll(); return
        }
        if let d = ops.first.flatMap(reg) { pages[d] = nil }
        if m.hasPrefix("ldp") || m.hasPrefix("ldnp"), ops.count > 1, let d2 = reg(ops[1]) { pages[d2] = nil }
    }

    /// x86_64: disp(%rip) is relative to the next instruction.
    static func ripRelative(_ ins: inout Instruction) {
        guard let r = ins.operands.range(of: "(%rip)") else { return }
        let before = ins.operands[..<r.lowerBound]
        let dispText = before.split(whereSeparator: { $0 == " " || $0 == "," || $0 == "$" }).last ?? "0"
        guard let disp = imm(dispText) else { return }
        let next = Int64(bitPattern: ins.address) &+ Int64(ins.bytes.count / 2)
        ins.dataRefs = [UInt64(bitPattern: next &+ disp)]
    }

    /// Follows a pointer slot (selref, classref, GOT, const) to a known string or symbol.
    /// shortcut: decodes chained-fixup rebases by trying the low 36/43-bit target as a vmaddr or image offset;
    /// a full dyld_chained_fixups parser would be exact.
    static func derefTarget(_ m: MachO, _ addr: UInt64, _ strings: [UInt64: String], _ names: [UInt64: String]) -> UInt64? {
        guard let sec = m.section(containing: addr), !sec.isCode, !sec.isCString, let raw = m.pointer(at: addr) else { return nil }
        for low in [raw, raw & 0xf_ffff_ffff, raw & 0x7ff_ffff_ffff, raw & 0xffff_ffff] {
            for cand in [low, m.textBase &+ low] where low != 0 && (strings[cand] != nil || names[cand] != nil) { return cand }
        }
        return nil
    }

    static func label(_ addr: UInt64, _ m: MachO, _ strings: [UInt64: String], _ names: [UInt64: String], via: Bool) -> String {
        let prefix = via ? "→ " : ""
        if let s = strings[addr] { return prefix + "\"\(s.count > 80 ? s.prefix(80) + "…" : s)\"" }
        if let n = names[addr] { return prefix + n }
        if let sec = m.section(containing: addr) { return "\(sec.fullName)+0x\(String(addr - sec.addr, radix: 16))" }
        return "0x" + String(addr, radix: 16)
    }

    static func lowerBound(_ ins: [Instruction], _ addr: UInt64) -> Int {
        var lo = 0, hi = ins.count
        while lo < hi { let m = (lo + hi) / 2; if ins[m].address < addr { lo = m + 1 } else { hi = m } }
        return lo
    }
}
