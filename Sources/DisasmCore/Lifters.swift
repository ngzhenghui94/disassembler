import Foundation

// Instruction → IR lifting from otool's text syntax. Anything not modelled becomes an `asm { … }` statement
// that keeps its registers alive, so the output stays correct where it isn't pretty.

extension FunctionDecompiler {
    enum Loc { case slot(String), mem(Expr) }

    static func splitOperands(_ s: String) -> [String] {
        var out: [String] = [], cur = "", depth = 0
        for ch in s {
            if ch == "[" || ch == "(" { depth += 1 }
            if ch == "]" || ch == ")" { depth -= 1 }
            if ch == ",", depth == 0 {
                out.append(cur.trimmingCharacters(in: .whitespaces)); cur = ""
            } else {
                cur.append(ch)
            }
        }
        let last = cur.trimmingCharacters(in: .whitespaces)
        if !last.isEmpty { out.append(last) }
        return out
    }

    static func immediate(_ s: String) -> Int64? {
        var t = Substring(s.trimmingCharacters(in: .whitespaces))
        if t.hasPrefix("#") || t.hasPrefix("$") { t = t.dropFirst() }
        let neg = t.hasPrefix("-")
        if neg { t = t.dropFirst() }
        guard let u = t.hasPrefix("0x") ? UInt64(t.dropFirst(2), radix: 16) : UInt64(t) else { return nil }
        let v = Int64(bitPattern: u)
        return neg ? 0 &- v : v
    }

    func inside(_ t: UInt64) -> Bool { t >= f.start && t < f.end }

    func addrExpr(_ addr: UInt64) -> Expr {
        if let s = a.stringAt[addr] { return .str(s) }
        if let n = a.names[addr] { return symbolValue(n) }
        return .c(Int64(bitPattern: addr))
    }

    /// The address an ADRP+ADD / LEA / ADR materializes.
    func refAddress(_ ins: Instruction) -> Expr? {
        let refs = ins.dataRefs
        if let ref = refs.first, a.macho.section(containing: ref)?.name == "__cfstring" {
            if refs.count >= 2, let s = a.stringAt[refs[1]] { return .raw("@" + quote(s)) }
            if let r = ins.comment.range(of: "Objc cfstring ref: "), !ins.comment.contains("bad cfstring") { return .raw(String(ins.comment[r.upperBound...])) }
        }
        return refs.first.map(addrExpr)
    }

    /// The value an ADRP+LDR / RIP-relative load reads, following resolved pointer slots (GOT, selrefs, classrefs).
    func slotValue(_ ins: Instruction, _ size: Int) -> Expr? {
        guard let slot = ins.dataRefs.first else { return nil }
        if let v = slotTarget(slot) { return v }
        guard isConstantSlot(slot) else { return .load(addrExpr(slot), size) }   // a mutable global: read it
        let c = ins.comment
        for p in ["literal pool symbol address: ", "Objc class ref: "] {
            if let r = c.range(of: p) { return symbolValue(String(c[r.upperBound...]).trimmingCharacters(in: .whitespaces)) }
        }
        if let r = c.range(of: "Objc selector ref: ") { return .raw("@selector(\(c[r.upperBound...]))") }
        if ins.dataRefs.count >= 2 { return addrExpr(ins.dataRefs[1]) }
        return .load(addrExpr(slot), size)
    }

    /// What a pointer slot holds, when the file says: an imported symbol, a selector, a class or a local symbol/string.
    func slotTarget(_ slot: UInt64) -> Expr? {
        guard isConstantSlot(slot) else { return nil }
        if let b = a.binds[slot] { return symbolValue(b) }
        guard let t = Analysis.derefTarget(a.macho, slot, a.stringAt, a.names) else { return nil }
        if a.macho.section(containing: slot)?.name.contains("selref") == true, let s = a.stringAt[t] { return .raw("@selector(\(s))") }
        return addrExpr(t)
    }

    /// GOT, selector/class refs and other read-only-after-load pointers. A `__data` pointer is a variable whose
    /// initial value is in the file but whose current value isn't.
    func isConstantSlot(_ addr: UInt64) -> Bool {
        guard let s = a.macho.section(containing: addr) else { return false }
        return s.segment == "__DATA_CONST" || s.segment == "__AUTH_CONST" || s.name == "__const"
            || ["__got", "__auth_got", "__auth_ptr", "__la_symbol_ptr", "__nl_symbol_ptr"].contains(s.name)
            || (s.name.hasPrefix("__objc_") && s.name.hasSuffix("refs"))
    }

    func symbolValue(_ n: String) -> Expr {
        n.hasPrefix("_OBJC_CLASS_$_") ? .raw(String(n.dropFirst(14))) : .global(n)
    }

    /// `*(0x…)` of a pointer slot reads what the slot points at.
    func resolveSlot(_ e: Expr) -> Expr {
        guard case .load(.c(let k), 8) = e, let v = slotTarget(UInt64(bitPattern: k)) else { return e }
        return v
    }

    func callee(_ t: UInt64) -> Expr {
        let name = a.name(of: t)
        calleeAddress[name] = t
        return .global(name)
    }

    func call(_ t: Expr) -> Stmt { Stmt(kind: .set(abi.ret, .call(t, [])), clobbers: abi.clobbered.filter { $0 != abi.ret }) }

    func asm(_ ins: Instruction, defs: [String], uses: [String]) -> [Stmt] {
        let text = ins.operands.isEmpty ? ins.mnemonic : "\(ins.mnemonic) \(ins.operands)"
        return [Stmt(kind: .asm(text), clobbers: defs, asmUses: uses)]
    }

    func flags(_ l: Expr, _ r: Expr) -> [Stmt] { [Stmt(kind: .set("cmp_l", l)), Stmt(kind: .set("cmp_r", r))] }

    func condition(_ cc: String) -> Expr? {
        let l = Expr.v("cmp_l"), r = Expr.v("cmp_r")
        switch cc {
        case "eq", "e", "z": return .bin("==", l, r)
        case "ne", "nz": return .bin("!=", l, r)
        case "hs", "cs", "ge", "ae", "nb", "nc", "nl": return .bin(">=", l, r)
        case "lo", "cc", "lt", "b", "c", "nae", "l", "nge": return .bin("<", l, r)
        case "hi", "gt", "a", "nbe", "g", "nle": return .bin(">", l, r)
        case "ls", "le", "be", "na", "ng": return .bin("<=", l, r)
        case "mi", "s": return .bin("<", .bin("-", l, r), .c(0))
        case "pl", "ns": return .bin(">=", .bin("-", l, r), .c(0))
        case "vs", "o": return .raw("OVERFLOW")
        case "vc", "no": return .raw("!OVERFLOW")
        case "al": return .c(1)
        default: return nil
        }
    }

    // MARK: - arm64

    static let armShifts: Set<String> = ["lsl", "lsr", "asr", "ror", "uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx"]
    static let armLoads: Set<String> = ["ldr", "ldur", "ldrb", "ldurb", "ldrh", "ldurh", "ldrsb", "ldursb", "ldrsh", "ldursh", "ldrsw", "ldursw",
                                        "ldar", "ldarb", "ldarh", "ldapr", "ldaprb", "ldaprh", "ldxr", "ldaxr", "ldp", "ldnp", "ldpsw"]
    static let armStores: Set<String> = ["str", "stur", "strb", "sturb", "strh", "sturh", "stlr", "stlrb", "stlrh", "stp", "stnp"]
    static let armBinary: [String: String] = [
        "add": "+", "adds": "+", "sub": "-", "subs": "-", "and": "&", "ands": "&", "orr": "|", "eor": "^", "mul": "*",
        "sdiv": "/", "udiv": "/", "lsl": "<<", "lsr": ">>", "asr": "s>>", "lslv": "<<", "lsrv": ">>", "asrv": "s>>",
        "fadd": "+", "fsub": "-", "fmul": "*", "fdiv": "/", "smull": "*", "umull": "*",
    ]

    /// Canonical register: x0…x30, sp, zr, v0…v31 (w/x and b/h/s/d/q views share one name).
    func armReg(_ t: String) -> String? {
        switch t {
        case "sp", "wsp": return "sp"
        case "xzr", "wzr": return "zr"
        case "fp": return "x29"
        case "lr": return "x30"
        default: break
        }
        guard let first = t.first else { return nil }
        let rest = t.dropFirst().prefix { $0.isNumber }
        guard let n = Int(rest), rest.count == t.count - 1 || first == "v" else { return nil }
        if (first == "x" || first == "w") && n <= 30 { return "x\(n)" }
        if "bhsdqv".contains(first) && n <= 31 { return "v\(n)" }
        return nil
    }

    func armValue(_ t: String) -> Expr? {
        if let r = armReg(t) { return r == "zr" ? .c(0) : .v(r) }
        if t.hasPrefix("#"), let k = Self.immediate(t) { return .c(k) }
        if t.hasPrefix("#") { return .raw(String(t.dropFirst())) }   // float immediates
        return nil
    }

    func applyShift(_ e: Expr, _ t: String) -> Expr {
        let p = t.split(separator: " ")
        let amt = p.count > 1 ? Self.immediate(String(p[1])) ?? 0 : 0
        switch p[0] {
        case "lsl": return .bin("<<", e, .c(amt))
        case "lsr", "ror": return .bin(">>", e, .c(amt))
        case "asr": return .bin("s>>", e, .c(amt))
        case "uxtb": return .bin("<<", .bin("&", e, .c(0xff)), .c(amt))
        case "uxth": return .bin("<<", .bin("&", e, .c(0xffff)), .c(amt))
        default: return .bin("<<", e, .c(amt))
        }
    }

    func armOperand(_ ops: [String], _ k: Int) -> Expr? {
        guard k < ops.count, let v = armValue(ops[k]) else { return nil }
        if k + 1 < ops.count, let w = ops[k + 1].split(separator: " ").first, Self.armShifts.contains(String(w)) {
            return applyShift(v, ops[k + 1])
        }
        return v
    }

    func slot(base: String, off: Int64) -> Loc? {
        if base == "sp", off >= 0 { return .slot("sp_" + String(off, radix: 16)) }
        if base == abi.fp, off < 0 { return .slot("var_" + String(0 &- off, radix: 16)) }
        return nil
    }

    /// What a condition-flag consumer (b.cc, csel, cset, ccmp, …) tests.
    func consumerCondition(_ ins: Instruction) -> String? {
        if ins.mnemonic.hasPrefix("b.") { return String(ins.mnemonic.dropFirst(2)) }
        let consumers: Set<String> = ["csel", "fcsel", "csinc", "csinv", "csneg", "cset", "csetm", "cinc", "cinv", "cneg", "ccmp", "ccmn", "fccmp", "fccmpe"]
        return consumers.contains(ins.mnemonic) ? Self.splitOperands(ins.operands).last : nil
    }

    static func nzcvSatisfies(_ cc: String, _ f: Int64) -> Bool? {
        let n = f & 8 != 0, z = f & 4 != 0, c = f & 2 != 0, v = f & 1 != 0
        switch cc {
        case "eq": return z
        case "ne": return !z
        case "hs", "cs": return c
        case "lo", "cc": return !c
        case "hi": return c && !z
        case "ls": return !c || z
        case "ge": return n == v
        case "lt": return n != v
        case "gt": return !z && n == v
        case "le": return z || n != v
        default: return nil
        }
    }

    /// `cmp a, b; ccmp c, d, #nzcv, cc1; b.cc2` is `a cc1 b && c cc2 d` (or `||` when nzcv satisfies cc2).
    /// The combined test is stored back into the flag pair in the shape the consumer's condition reads.
    /// The encoding only answers cc2 and its complement, so every later reader of these flags must ask one of those.
    func liftConditionalCompare(_ ins: Instruction, _ ops: [String], following: ArraySlice<Instruction>) -> [Stmt]? {
        guard ops.count == 4, let x = armOperand(ops, 0), var y = armOperand(ops, 1), let nzcv = Self.immediate(ops[2]),
              let c1 = condition(ops[3]), let next = following.first, let cc2 = consumerCondition(next), let c2 = condition(cc2),
              let holds = Self.nzcvSatisfies(cc2, nzcv) else { return nil }
        let alias = ["cs": "hs", "cc": "lo"]
        let complement = ["eq": "ne", "ne": "eq", "hs": "lo", "lo": "hs", "hi": "ls", "ls": "hi", "ge": "lt", "lt": "ge", "gt": "le", "le": "gt"]
        let asked = alias[cc2] ?? cc2
        let flagWriters: Set<String> = ["cmp", "cmn", "tst", "fcmp", "fcmpe", "adds", "subs", "ands", "bics", "negs", "ngcs", "adcs", "sbcs",
                                        "ccmp", "ccmn", "fccmp", "fccmpe"]
        for later in following.prefix(64) {
            let m = later.mnemonic
            if let cc = consumerCondition(later).map({ alias[$0] ?? $0 }), cc != asked, cc != complement[asked] { return nil }
            if flagWriters.contains(m) || m.hasPrefix("bl") || ["b", "br", "braa", "brab", "ret", "retaa", "retab"].contains(m) { break }
        }
        if ins.mnemonic == "ccmn" { y = .un("-", y) }
        let test = c2.map { $0 == .v("cmp_l") ? x : $0 == .v("cmp_r") ? y : $0 }
        let result: Expr = holds ? .bin("||", negate(c1), test) : .bin("&&", c1, test)
        let t = Expr.v("cmp_t")
        let pair: [(String, Expr)] = switch cc2 {
        case "eq", "hs", "cs", "ge": [("cmp_l", t), ("cmp_r", .c(1))]
        case "ne", "hi", "gt": [("cmp_l", t), ("cmp_r", .c(0))]
        case "lo", "cc", "lt": [("cmp_r", t), ("cmp_l", .c(0))]
        default: [("cmp_r", t), ("cmp_l", .c(1))]
        }
        return [Stmt(kind: .set("cmp_t", result))] + pair.map { Stmt(kind: .set($0.0, $0.1)) }
    }

    static func calleeSaved(_ r: String) -> Bool {
        if r.hasPrefix("x"), let n = Int(r.dropFirst()) { return n >= 19 }
        if r.hasPrefix("v"), let n = Int(r.dropFirst()) { return (8...15).contains(n) }
        return false
    }

    /// Registers and base of an arm64 load/store, if every register is callee-saved and the base is sp/x29.
    func frameAccess(_ ins: Instruction) -> (regs: [String], load: Bool)? {
        let m = ins.mnemonic
        guard Self.armLoads.contains(m) || Self.armStores.contains(m) else { return nil }
        let ops = Self.splitOperands(ins.operands)
        let n = m.hasSuffix("p") ? 2 : 1
        guard ops.count > n, ops[n].hasPrefix("["),
              let base = Self.splitOperands(String(ops[n].dropFirst().prefix { $0 != "]" })).first.flatMap(armReg),
              base == "sp" || base == abi.fp else { return nil }
        let regs = ops.prefix(n).compactMap(armReg)
        guard regs.count == n, regs.allSatisfy(Self.calleeSaved) else { return nil }
        return (regs, Self.armLoads.contains(m))
    }

    /// Instructions that save callee-saved registers on entry (before anything writes them or calls out) and
    /// restore them on the way out (followed only by frame teardown and a return or tail jump). A spill of x19–x28
    /// in the body is real data flow and stays.
    func computeFrameSaves(_ insns: [Instruction]) -> Set<UInt64> {
        var result = Set<UInt64>(), written = Set<String>(), called = false
        for (k, ins) in insns.enumerated() {
            if let acc = frameAccess(ins) {
                // fp/lr saves are frame linkage wherever they are (shrink-wrapped and Swift async frames included).
                if acc.regs.allSatisfy({ $0 == "x29" || $0 == "x30" }) { result.insert(ins.address) }
                if !acc.load, !called, written.isDisjoint(with: acc.regs) { result.insert(ins.address) }
                if acc.load, isEpilogue(insns, from: k + 1) { result.insert(ins.address) }
            }
            if ins.mnemonic.hasPrefix("bl") { called = true }
            let ops = Self.splitOperands(ins.operands)
            if !Self.armStores.contains(ins.mnemonic), let d = ops.first.flatMap(armReg) { written.insert(d) }
        }
        return result
    }

    func isEpilogue(_ insns: [Instruction], from k: Int) -> Bool {
        for ins in insns[k..<min(k + 24, insns.count)] {
            let m = ins.mnemonic
            if ["ret", "retaa", "retab", "b", "br", "braa", "brab", "braaz", "brabz"].contains(m) { return true }
            if frameAccess(ins)?.load == true { continue }
            if Self.armLoads.contains(m) || Self.armStores.contains(m) || m.hasPrefix("bl") || m.hasPrefix("b.") || m.hasPrefix("cb") { return false }
            if m.hasPrefix("tb"), !(ins.operands.hasPrefix("x16") || ins.operands.hasPrefix("x17")) { return false }   // PAC check uses x16
        }
        return false
    }

    /// An instruction with a branch target whose meaning isn't modelled still has that edge in the CFG.
    func keepEdge(_ ins: Instruction, _ stmts: [Stmt]) -> [Stmt] {
        guard let t = ins.target, inside(t), stmts.last.map({ if case .asm = $0.kind { true } else { false } }) == true,
              !ins.mnemonic.hasPrefix("bl"), !ins.mnemonic.hasPrefix("call") else { return stmts }
        return stmts + [Stmt(kind: .branch(.raw("__asm_condition(\"\(ins.mnemonic)\")"), t))]
    }

    func liftARM(_ ins: Instruction, following: ArraySlice<Instruction>) -> [Stmt] {
        let m = ins.mnemonic
        let ops = Self.splitOperands(ins.operands)
        let regsUsed = ops.flatMap { $0.split(whereSeparator: { " [],!".contains($0) }) }.compactMap { armReg(String($0)) }.filter { $0 != "zr" }
        let carry = ["adc", "adcs", "sbc", "sbcs", "ngc", "ngcs"].contains(m)   // read the carry flag; the -s forms set flags
        let fallback = {
            self.keepEdge(ins, self.asm(ins, defs: (ops.first.flatMap { self.armReg($0) }.map { [$0] } ?? []) + (carry && m.hasSuffix("s") ? ABI.flags : []),
                                        uses: regsUsed + (carry ? ABI.flags : [])))
        }
        if m.hasPrefix("pac") || m.hasPrefix("aut") || m.hasPrefix("xpac") || ["nop", "hint", "bti", "prfm", "prfum", "yield", "clrex", "dmb", "dsb", "isb"].contains(m) {
            return []
        }
        let d = ops.first.flatMap { armReg($0) }
        func set(_ e: Expr) -> [Stmt] {
            guard let d, d != "zr", d != "sp" else { return [] }
            return [Stmt(kind: .set(d, e))]
        }
        func op(_ k: Int) -> Expr? { armOperand(ops, k) }

        switch m {
        case "ret", "retaa", "retab":
            return [Stmt(kind: .ret(nil))]
        case "b":
            guard let t = ins.target else { return fallback() }
            return [Stmt(kind: inside(t) ? .jump(t) : .ret(.call(callee(t), [])))]
        case "bl":
            guard let t = ins.target else { return fallback() }
            return [call(callee(t))]
        case "blr", "blraa", "blrab", "blraaz", "blrabz":
            guard let r = d else { return fallback() }
            return [call(.v(r))]
        case "br":
            guard let r = d else { return fallback() }
            return [Stmt(kind: .ijump(.v(r)))]
        case "braa", "brab", "braaz", "brabz":
            guard let r = d else { return fallback() }
            return [Stmt(kind: .ret(.call(.v(r), [])))]
        case "cbz", "cbnz":
            guard let x = op(0), let t = ins.target else { return fallback() }
            return [Stmt(kind: .branch(.bin(m == "cbz" ? "==" : "!=", x, .c(0)), t))]
        case "tbz", "tbnz":
            guard let x = op(0), ops.count > 1, let bit = Self.immediate(ops[1]), let t = ins.target else { return fallback() }
            return [Stmt(kind: .branch(.bin(m == "tbz" ? "==" : "!=", .bin("&", x, .c(1 << bit)), .c(0)), t))]
        case _ where m.hasPrefix("b.") || m.hasPrefix("bc."):
            guard let c = condition(String(m.split(separator: ".", maxSplits: 1).last ?? "")), let t = ins.target else { return fallback() }
            return [Stmt(kind: .branch(c, t))]
        case "brk", "udf", "hlt":
            return [Stmt(kind: .halt("__builtin_trap()"))]
        case "adrp":
            guard let page = ins.comment.split(separator: " ").first.flatMap({ Self.immediate(String($0)) }) else { return fallback() }
            return set(.c(page))
        case "adr":
            if let e = refAddress(ins) { return set(e) }
            guard ops.count > 1, let t = Self.immediate(ops[1]) else { return fallback() }
            // otool prints `adr x10, #16`: an offset from this instruction, not an address.
            return set(addrExpr(ins.address &+ UInt64(bitPattern: t)))
        case "mov", "movz", "fmov":
            guard let s = op(1) else { return fallback() }
            if d == abi.fp, s == .v("sp") { return [] }
            return set(s)
        case "movk":
            guard let d, let imm = Self.immediate(ops[1]) else { return fallback() }
            let sh = ops.count > 2 ? Self.immediate(String(ops[2].split(separator: " ").last ?? "")) ?? 0 : 0
            return set(.bin("|", .bin("&", .v(d), .c(~(0xffff << sh))), .c(imm << sh)))
        case "movn":
            guard let s = op(1) else { return fallback() }
            return set(.un("~", s))
        case "mvn":
            guard let s = op(1) else { return fallback() }
            return set(.un("~", s))
        case "neg", "negs", "fneg":
            guard let s = op(1) else { return fallback() }
            return set(.un("-", s)) + (m == "negs" ? flags(.v(d ?? "zr"), .c(0)) : [])
        case "cmp", "fcmp", "fcmpe":
            guard let x = op(0) else { return fallback() }
            return flags(x, op(1) ?? .c(0))
        case "cmn":
            guard let x = op(0), let y = op(1) else { return fallback() }
            return flags(x, .un("-", y))
        case "tst":
            guard let x = op(0), let y = op(1) else { return fallback() }
            return flags(.bin("&", x, y), .c(0))
        case "csel", "fcsel", "csinc", "csinv", "csneg":
            guard ops.count == 4, let x = op(1), let y = op(2), let c = condition(ops[3]) else { return fallback() }
            let other: Expr = switch m {
            case "csinc": .bin("+", y, .c(1))
            case "csinv": .un("~", y)
            case "csneg": .un("-", y)
            default: y
            }
            return set(.ite(c, x, other))
        case "cset", "csetm":
            guard ops.count == 2, let c = condition(ops[1]) else { return fallback() }
            return set(m == "cset" ? c : .ite(c, .c(-1), .c(0)))
        case "cinc", "cinv", "cneg":
            guard ops.count == 3, let x = op(1), let c = condition(ops[2]) else { return fallback() }
            let alt: Expr = m == "cinc" ? .bin("+", x, .c(1)) : m == "cinv" ? .un("~", x) : .un("-", x)
            return set(.ite(c, alt, x))
        case "madd", "msub", "smaddl", "umaddl", "smsubl", "umsubl", "fmadd", "fmsub":
            guard let x = op(1), let y = op(2), let z = op(3) else { return fallback() }
            let p = Expr.bin("*", x, y)
            return set(m.contains("sub") ? .bin("-", z, p) : .bin("+", p, z))
        case "mneg":
            guard let x = op(1), let y = op(2) else { return fallback() }
            return set(.un("-", .bin("*", x, y)))
        case "smulh", "umulh":
            guard let x = op(1), let y = op(2) else { return fallback() }
            return set(.fn("__mulh", [x, y]))
        case "clz", "cls", "rbit", "rev", "rev16", "rev32", "abs", "fabs", "fsqrt", "frintm", "frintp", "frintz", "frinta", "frintn":
            guard let x = op(1) else { return fallback() }
            return set(.fn("__" + m, [x]))
        case "sxtb", "sxth", "sxtw", "uxtw":
            guard let x = op(1) else { return fallback() }
            return set(x)
        case "uxtb", "uxth":
            guard let x = op(1) else { return fallback() }
            return set(.bin("&", x, .c(m == "uxtb" ? 0xff : 0xffff)))
        case _ where m.hasPrefix("fcvt") || m == "scvtf" || m == "ucvtf":
            guard let x = op(1) else { return fallback() }
            return set(x)
        case "ubfx", "sbfx", "ubfiz", "sbfiz", "bfi", "bfxil":
            guard let d, let x = op(1), ops.count == 4, let lsb = Self.immediate(ops[2]), let w = Self.immediate(ops[3]), w < 64 else { return fallback() }
            let mask = Expr.c((1 << w) &- 1)
            switch m {
            case "ubfx", "sbfx": return set(.bin("&", .bin(m == "sbfx" ? "s>>" : ">>", x, .c(lsb)), mask))
            case "ubfiz", "sbfiz": return set(.bin("<<", .bin("&", x, mask), .c(lsb)))
            case "bfi": return set(.bin("|", .bin("&", .v(d), .c(~(((1 << w) &- 1) << lsb))), .bin("<<", .bin("&", x, mask), .c(lsb))))
            default: return set(.bin("|", .bin("&", .v(d), .c(~((1 << w) &- 1))), .bin("&", .bin(">>", x, .c(lsb)), mask)))
            }
        case _ where Self.armLoads.contains(m) || Self.armStores.contains(m):
            return armMemory(ins, m, ops) ?? fallback()
        case "eor" where ops.count >= 3 && armReg(ops[1]) == "x30" && armReg(ops[2]) == "x30":
            return set(.c(0))   // arm64e return-address authentication check: always passes in pseudocode
        case _ where Self.armBinary[m] != nil || m == "bic" || m == "bics" || m == "orn" || m == "eon":
            guard let d, ops.count >= 3, let x = op(1), let y = op(2) else { return fallback() }
            if d == "sp" || (d == abi.fp && x == .v("sp")) { return [] }   // frame setup
            if m == "add", !ins.dataRefs.isEmpty, let e = refAddress(ins) { return set(e) }
            if (m == "add" || m == "sub"), x == .v("sp") || x == .v(abi.fp), case .c(let k) = y,
               case .slot(let s)? = slot(base: x == .v("sp") ? "sp" : abi.fp, off: m == "add" ? k : 0 &- k) {
                return set(.un("&", .v(s)))
            }
            let e: Expr = switch m {
            case "bic", "bics": .bin("&", x, .un("~", y))
            case "orn": .bin("|", x, .un("~", y))
            case "eon": .bin("^", x, .un("~", y))
            default: .bin(Self.armBinary[m]!, x, y)
            }
            let result = d == "zr" ? e : Expr.v(d)
            let setsFlags = ["adds", "subs", "ands", "bics"].contains(m)
            return set(e) + (setsFlags ? flags(result, .c(0)) : [])
        default:
            if ["ccmp", "ccmn", "fccmp", "fccmpe"].contains(m) {
                return liftConditionalCompare(ins, ops, following: following) ?? asm(ins, defs: ABI.flags, uses: regsUsed + ABI.flags)
            }
            if let dot = m.firstIndex(of: "."), ["mov", "movi", "fmov"].contains(m[..<dot]), ops.count == 2, let s = op(1) {
                return set(s)   // whole-register vector moves and splats of 0
            }
            return fallback()
        }
    }

    func armMemory(_ ins: Instruction, _ m: String, _ ops: [String]) -> [Stmt]? {
        let pair = m.hasSuffix("p") || m == "ldpsw"
        let regCount = pair ? 2 : 1
        guard ops.count > regCount else { return nil }
        let regs = ops.prefix(regCount).compactMap(armReg)
        guard regs.count == regCount else { return nil }
        let memTok = ops[regCount]
        let isLoad = Self.armLoads.contains(m)
        let size: Int = {
            if m.hasSuffix("sw") { return 4 }
            if !pair, m.hasSuffix("b") { return 1 }
            if !pair, m.hasSuffix("h") { return 2 }
            switch ops[0].first { case "w", "s": return 4; case "q": return 16; case "h": return 2; case "b": return 1; default: return 8 }
        }()
        func value(_ r: String) -> Expr { r == "zr" ? .c(0) : .v(r) }
        func access(_ loc: Loc, _ k: Int) -> Stmt? {
            let r = regs[k]
            switch loc {
            case .slot(let s): return isLoad ? (r == "zr" ? nil : Stmt(kind: .set(r, .v(s)))) : Stmt(kind: .set(s, value(r)))
            case .mem(let e): return isLoad ? (r == "zr" ? nil : Stmt(kind: .set(r, .load(e, size)))) : Stmt(kind: .store(e, value(r), size))
            }
        }

        guard memTok.hasPrefix("[") else {
            // pc-relative literal
            guard isLoad, let t = Self.immediate(memTok) else { return nil }
            return [Stmt(kind: .set(regs[0], ins.dataRefs.isEmpty ? .load(addrExpr(UInt64(bitPattern: t)), size) : slotValue(ins, size)!))]
        }
        let pre = memTok.hasSuffix("!")
        let inner = memTok.drop { $0 == "[" }.prefix { $0 != "]" }
        let parts = Self.splitOperands(String(inner))
        guard let base = parts.first.flatMap(armReg) else { return nil }
        if frameSaves.contains(ins.address) { return [] }   // prologue saves and epilogue restores

        if !ins.dataRefs.isEmpty, base != "sp", base != abi.fp, regCount == 1 {
            if isLoad, regs[0].hasPrefix("v"), size == 4 || size == 8, let lit = floatLiteral(ins.dataRefs[0], size) {
                return [Stmt(kind: .set(regs[0], lit))]
            }
            if isLoad, let v = slotValue(ins, size) { return [Stmt(kind: .set(regs[0], v))] }
            if !isLoad { return [Stmt(kind: .store(addrExpr(ins.dataRefs[0]), value(regs[0]), size))] }
        }

        var off: Int64 = 0
        var index: Expr?
        if parts.count >= 2 {
            if let k = Self.immediate(parts[1]) { off = k }
            else if let ix = armValue(parts[1]) { index = parts.count >= 3 ? applyShift(ix, parts[2]) : ix }
            else { return nil }
        }
        let post = ops.count > regCount + 1 ? Self.immediate(ops[regCount + 1]) : nil
        var out: [Stmt] = []
        var accessOff = off
        if pre, base != "sp" {
            out.append(Stmt(kind: .set(base, .bin("+", .v(base), .c(off)))))
            accessOff = 0
        }
        // `ldp x0, x1, [x0]`: both addresses use the old x0, so the load that overwrites the base goes last.
        let order = isLoad && regCount == 2 && regs[0] == base ? [1, 0] : Array(0..<regCount)
        for k in order {
            let o = accessOff &+ Int64(k * size)
            let loc: Loc
            if index == nil, let s = slot(base: base, off: o) {
                loc = s
            } else {
                var e: Expr = .v(base)
                if let index { e = .bin("+", e, index) }
                loc = .mem(o == 0 ? e : .bin("+", e, .c(o)))
            }
            if let s = access(loc, k) { out.append(s) }
        }
        if let post, base != "sp" { out.append(Stmt(kind: .set(base, .bin("+", .v(base), .c(post))))) }
        return out
    }

    // MARK: - x86_64 (AT&T syntax)

    indirect enum XOp: Equatable {
        case reg(String)
        case imm(Int64)
        case mem(base: String?, index: String?, scale: Int64, disp: String)
        case label(String)
        case indirect(XOp)
        case unsupported
    }

    static let x86Regs: [String: String] = {
        var d: [String: String] = [:]
        let legacy: [(String, [String])] = [
            ("rax", ["eax", "ax", "al"]), ("rbx", ["ebx", "bx", "bl"]), ("rcx", ["ecx", "cx", "cl"]),
            // ah/bh/ch/dh are bits 8-15: not modelled, so instructions using them stay asm.
            ("rdx", ["edx", "dx", "dl"]), ("rsi", ["esi", "si", "sil"]), ("rdi", ["edi", "di", "dil"]),
            ("rbp", ["ebp", "bp", "bpl"]), ("rsp", ["esp", "sp", "spl"]), ("rip", []),
        ]
        for (q, names) in legacy { d[q] = q; for n in names { d[n] = q } }
        for n in 8...15 { for s in ["", "d", "w", "b"] { d["r\(n)\(s)"] = "r\(n)" } }
        for n in 0...15 { for p in ["xmm", "ymm"] { d["\(p)\(n)"] = "xmm\(n)" } }
        return d
    }()

    static let x86Bases: Set<String> = ["mov", "add", "sub", "imul", "and", "or", "xor", "shl", "shr", "sar", "sal", "cmp", "test", "lea",
                                        "push", "pop", "inc", "dec", "neg", "not", "call", "jmp", "ret", "leave", "nop", "idiv", "div"]
    static let x86CCs: Set<String> = ["e", "ne", "z", "nz", "l", "le", "g", "ge", "b", "be", "a", "ae", "s", "ns", "nb", "nae", "nbe",
                                      "na", "nl", "nle", "ng", "nge", "c", "nc", "o", "no"]

    func parseX86(_ t: String) -> XOp {
        if t.hasPrefix("*") { return .indirect(parseX86(String(t.dropFirst()))) }
        if t.hasPrefix("%") { return Self.x86Regs[String(t.dropFirst())].map { .reg($0) } ?? .unsupported }
        if t.hasPrefix("$") { return Self.immediate(t).map { .imm($0) } ?? .unsupported }
        guard let open = t.firstIndex(of: "(") else { return .label(t) }
        let disp = String(t[..<open])
        if disp.contains(":") { return .unsupported }   // segment-relative (TLS)
        let inner = t[t.index(after: open)...].dropLast().split(separator: ",", omittingEmptySubsequences: false).map { $0.trimmingCharacters(in: .whitespaces) }
        func reg(_ s: String?) -> String? { s.flatMap { $0.hasPrefix("%") ? Self.x86Regs[String($0.dropFirst())] : nil } }
        return .mem(base: reg(inner.first), index: reg(inner.count > 1 ? inner[1] : nil),
                    scale: inner.count > 2 ? Self.immediate(inner[2]) ?? 1 : 1, disp: disp)
    }

    func liftX86(_ ins: Instruction, prev: Instruction?) -> [Stmt] {
        var m = ins.mnemonic
        var size = 8
        let ops = Self.splitOperands(ins.operands).map(parseX86)
        let regsUsed = Self.splitOperands(ins.operands).flatMap { $0.split(whereSeparator: { "%(),*$ ".contains($0) }) }.compactMap { Self.x86Regs[String($0)] }
        // Unmodelled integer instructions mostly set the flags; SSE ones don't. adc/sbb also read the carry.
        let integer = !regsUsed.contains { $0.hasPrefix("xmm") }
        let carry = m.hasPrefix("adc") || m.hasPrefix("sbb")
        let fallback = {
            self.keepEdge(ins, self.asm(ins, defs: (ops.last.flatMap { if case .reg(let r) = $0 { [r] } else { nil } } ?? []) + (integer ? ABI.flags : []),
                                        uses: regsUsed + (carry ? ABI.flags : [])))
        }
        if m == "endbr64" || m.hasPrefix("nop") { return [] }
        if ops.contains(.unsupported) { return fallback() }

        // Normalize mnemonic and operand size.
        var cc: String?
        var zeroExtend = false
        if let last = m.last, let s = ["b": 1, "w": 2, "l": 4, "q": 8][String(last)], !Self.x86Bases.contains(m), Self.x86Bases.contains(String(m.dropLast())) {
            m = String(m.dropLast()); size = s
        } else if m.hasPrefix("movz") || m.hasPrefix("movs"), m.count == 6 {
            size = ["b": 1, "w": 2, "l": 4][String(m[m.index(m.startIndex, offsetBy: 4)])] ?? 8
            zeroExtend = m.hasPrefix("movz")
            m = "mov"
        } else if m == "movabsq" {
            m = "mov"
        } else if m.hasPrefix("cmov") {
            var c = String(m.dropFirst(4))
            if !Self.x86CCs.contains(c) { c = String(c.dropLast()) }
            cc = c; m = "cmov"
        } else if m.hasPrefix("set"), Self.x86CCs.contains(String(m.dropFirst(3))) {
            cc = String(m.dropFirst(3)); m = "set"; size = 1
        } else if m.hasPrefix("j"), m != "jmp", m != "jmpq", Self.x86CCs.contains(String(m.dropFirst())) {
            cc = String(m.dropFirst()); m = "jcc"
        }
        if m == "jmpq" { m = "jmp" }

        func read(_ o: XOp) -> Expr? {
            switch o {
            case .reg(let r): return .v(r)
            case .imm(let k): return .c(k)
            case .mem(let base, let index, let scale, let disp):
                if base == "rip" { return ins.dataRefs.isEmpty ? (Self.immediate(disp) == nil ? .load(.global(disp), size) : nil) : slotValue(ins, size) }
                switch loc(base, index, scale, disp) {
                case .slot(let s)?: return .v(s)
                case .mem(let e)?: return .load(e, size)
                case nil: return nil
                }
            case .label(let l): return Self.immediate(l).map { .load(addrExpr(UInt64(bitPattern: $0)), size) }
            default: return nil
            }
        }
        func address(_ o: XOp) -> Expr? {
            guard case .mem(let base, let index, let scale, let disp) = o else { return nil }
            if base == "rip" { return ins.dataRefs.isEmpty ? (Self.immediate(disp) == nil ? .global(disp) : nil) : refAddress(ins) }
            switch loc(base, index, scale, disp) {
            case .slot(let s)?: return .un("&", .v(s))
            case .mem(let e)?: return e
            case nil: return nil
            }
        }
        func write(_ o: XOp, _ e: Expr) -> [Stmt]? {
            switch o {
            case .reg(let r): return r == "rsp" ? [] : [Stmt(kind: .set(r, e))]
            case .mem(let base, let index, let scale, let disp):
                if base == "rip" {
                    if let t = ins.dataRefs.first { return [Stmt(kind: .store(addrExpr(t), e, size))] }
                    return Self.immediate(disp) == nil ? [Stmt(kind: .store(.global(disp), e, size))] : nil
                }
                switch loc(base, index, scale, disp) {
                case .slot(let s)?: return [Stmt(kind: .set(s, e))]
                case .mem(let a)?: return [Stmt(kind: .store(a, e, size))]
                case nil: return nil
                }
            default: return nil
            }
        }
        /// A floating-point source operand; a constant-pool load becomes its literal value.
        func sseRead(_ o: XOp, _ size: Int) -> Expr? {
            if case .mem(base: "rip", _, _, _) = o, let addr = ins.dataRefs.first, let lit = floatLiteral(addr, size) { return lit }
            return read(o)
        }

        switch m {
        case "pop":
            // `push $5; pop %rdi` is how -Oz loads small constants; other pushes and pops are frame bookkeeping.
            if let prev, prev.mnemonic.hasPrefix("push"), ops.count == 1, let p = Self.splitOperands(prev.operands).first {
                switch parseX86(p) {
                case .imm(let k): return write(ops[0], .c(k)) ?? []
                case .reg(let r) where r != "rbp": return write(ops[0], .v(r)) ?? []
                default: break
                }
            }
            return []
        case "push", "leave", "cltq", "cwtl", "cdqe":
            return []
        case "addsd", "addss", "subsd", "subss", "mulsd", "mulss", "divsd", "divss":
            size = m.hasSuffix("sd") ? 8 : 4
            guard ops.count == 2, let x = read(ops[1]), let y = sseRead(ops[0], size) else { return fallback() }
            return write(ops[1], .bin(["add": "+", "sub": "-", "mul": "*", "div": "/"][String(m.prefix(3))]!, x, y)) ?? fallback()
        case "movsd", "movss", "movaps", "movapd", "movups", "movupd", "movq", "movd", "cvtsi2sd", "cvtsi2ss", "cvtsi2sdl", "cvtsi2sdq",
             "cvtsi2ssl", "cvtsi2ssq", "cvttsd2si", "cvttss2si", "cvtss2sd", "cvtsd2ss", "sqrtsd", "sqrtss":
            size = m.hasSuffix("ss") || m.hasSuffix("2ss") || m == "movd" ? 4 : 8
            guard ops.count == 2, let x = sseRead(ops[0], size) else { return fallback() }
            return write(ops[1], m.hasPrefix("sqrt") ? .fn("sqrt", [x]) : x) ?? fallback()
        case "xorps", "xorpd" where ops.count == 2 && ops[0] == ops[1]:
            return write(ops[1], .c(0)) ?? fallback()
        case "ucomiss", "ucomisd", "comiss", "comisd":
            guard ops.count == 2, let x = read(ops[1]), let y = read(ops[0]) else { return fallback() }
            return flags(x, y)
        case "ret":
            return [Stmt(kind: .ret(nil))]
        case "ud2", "int3", "hlt":
            return [Stmt(kind: .halt("__builtin_trap()"))]
        case "mov":
            guard ops.count == 2, var s = read(ops[0]) else { return fallback() }
            if ops[0] == .reg("rsp"), ops[1] == .reg("rbp") { return [] }
            if zeroExtend, case .reg = ops[0] { s = .bin("&", s, .c(size == 1 ? 0xff : 0xffff)) }
            return write(ops[1], s) ?? fallback()
        case "lea":
            guard ops.count == 2, let s = address(ops[0]) else { return fallback() }
            return write(ops[1], s) ?? fallback()
        case "add", "sub", "and", "or", "xor", "imul", "shl", "sal", "shr", "sar":
            if ops.count == 3, m == "imul", let x = read(ops[0]), let y = read(ops[1]) { return write(ops[2], .bin("*", y, x)) ?? fallback() }
            guard let dst = ops.last, ops.count <= 2 else { return fallback() }
            if dst == .reg("rsp") { return [] }
            if m == "xor", ops.count == 2, ops[0] == ops[1] { return (write(dst, .c(0)) ?? fallback()) }
            let src: Expr? = ops.count == 1 ? .c(1) : read(ops[0])
            guard let s = src, let dv = read(dst) else { return fallback() }
            let o = ["add": "+", "sub": "-", "and": "&", "or": "|", "xor": "^", "imul": "*", "shl": "<<", "sal": "<<", "shr": ">>", "sar": "s>>"][m]!
            guard let w = write(dst, .bin(o, dv, s)) else { return fallback() }
            let result: Expr = if case .reg(let r) = dst { .v(r) } else { read(dst)! }
            return w + flags(result, .c(0))
        case "inc", "dec", "neg", "not":
            guard ops.count == 1, let v = read(ops[0]) else { return fallback() }
            let e: Expr = m == "inc" ? .bin("+", v, .c(1)) : m == "dec" ? .bin("-", v, .c(1)) : .un(m == "neg" ? "-" : "~", v)
            guard let w = write(ops[0], e) else { return fallback() }
            return m == "not" ? w : w + flags(read(ops[0])!, .c(0))
        case "cmp":
            guard ops.count == 2, let x = read(ops[1]), let y = read(ops[0]) else { return fallback() }
            return flags(x, y)
        case "test":
            guard ops.count == 2, let x = read(ops[1]), let y = read(ops[0]) else { return fallback() }
            return flags(x == y ? x : .bin("&", x, y), .c(0))
        case "cqto", "cltd", "cqo", "cdq":
            return [Stmt(kind: .set("rdx", .bin(">>", .v("rax"), .c(63))))]
        case "idiv", "div":
            guard ops.count == 1, let s = read(ops[0]) else { return fallback() }
            return [Stmt(kind: .set("rdx", .bin("%", .v("rax"), s))), Stmt(kind: .set("rax", .bin("/", .v("rax"), s)))]
        case "set":
            guard let cc, let c = condition(cc), ops.count == 1 else { return fallback() }
            return write(ops[0], c) ?? fallback()
        case "cmov":
            guard let cc, let c = condition(cc), ops.count == 2, let s = read(ops[0]), let dv = read(ops[1]) else { return fallback() }
            return write(ops[1], .ite(c, s, dv)) ?? fallback()
        case "jcc":
            guard let cc, let c = condition(cc), let t = ins.target else { return fallback() }
            if cc == "p" || cc == "np" {   // NaN test after ucomis*: reads the flags, keeps its edge
                return keepEdge(ins, asm(ins, defs: [], uses: ABI.flags))
            }
            return [Stmt(kind: .branch(c, t))]
        case "jmp", "call":
            guard ops.count == 1 else { return fallback() }
            let fn: Expr
            if case .indirect(let inner) = ops[0] {
                guard let v = read(inner) else { return fallback() }
                fn = v
            } else if let t = ins.target {
                if m == "jmp", inside(t) { return [Stmt(kind: .jump(t))] }
                fn = callee(t)
            } else {
                return fallback()
            }
            if m == "call" { return [call(fn)] }
            if case .indirect = ops[0], !isTailSlot(fn) { return [Stmt(kind: .ijump(fn))] }
            return [Stmt(kind: .ret(.call(fn, [])))]
        default:
            return fallback()
        }
    }

    func floatLiteral(_ addr: UInt64, _ size: Int) -> Expr? {
        guard let sec = a.macho.section(containing: addr), sec.segment == "__TEXT", !sec.isCode, !sec.isCString,
              let raw = try? a.macho.reader.bytes(Int(sec.offset) + Int(addr - sec.addr), size) else { return nil }
        let v = raw.withUnsafeBytes { size == 8 ? $0.loadUnaligned(as: Double.self) : Double($0.loadUnaligned(as: Float.self)) }
        return .raw(v == v.rounded() && abs(v) < 1e15 ? String(format: "%.1f", v) : "\(v)")
    }

    /// `jmp *slot(%rip)` through a GOT/stub slot is a tail call; `jmp *%reg` is usually a switch table.
    func isTailSlot(_ e: Expr) -> Bool {
        switch e { case .global, .raw: true; case .load(.global, _): true; default: false }
    }

    func loc(_ base: String?, _ index: String?, _ scale: Int64, _ disp: String) -> Loc? {
        guard let d = disp.isEmpty ? 0 : Self.immediate(disp) else { return nil }
        if index == nil, let base {
            if base == "rsp", d >= 0 { return .slot("sp_" + String(d, radix: 16)) }
            if base == "rbp", d < 0 { return .slot("var_" + String(0 &- d, radix: 16)) }
        }
        var e: Expr?
        if let base { e = .v(base) }
        if let index {
            let ix: Expr = scale == 1 ? .v(index) : .bin("*", .v(index), .c(scale))
            e = e.map { .bin("+", $0, ix) } ?? ix
        }
        if d != 0 || e == nil { e = e.map { .bin("+", $0, .c(d)) } ?? .c(d) }
        return .mem(e!)
    }
}
