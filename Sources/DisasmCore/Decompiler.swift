import Foundation

// A Hopper-style decompiler: lifts a function's instructions to a small IR, builds the CFG, runs liveness,
// dead-code elimination and expression propagation, recovers if/else and loops, and prints pseudo-C.
// Lifters for arm64 and x86_64 live in Lifters.swift.

// MARK: - IR

indirect enum Expr: Hashable {
    case v(String)                 // register, stack slot or argument
    case c(Int64)
    case str(String)               // C string literal
    case global(String)            // address of a named symbol
    case raw(String)               // pre-rendered text: @selector(…), class names, @"…"
    case bin(String, Expr, Expr)
    case un(String, Expr)          // - ~ ! &
    case fn(String, [Expr])        // pure builtin (clz, mulh, …)
    case load(Expr, Int)           // *(sized *)address
    case call(Expr, [Expr])
    case ite(Expr, Expr, Expr)

    var children: [Expr] {
        switch self {
        case .bin(_, let a, let b): [a, b]
        case .un(_, let a), .load(let a, _): [a]
        case .fn(_, let args): args
        case .call(let t, let args): [t] + args
        case .ite(let c, let a, let b): [c, a, b]
        default: []
        }
    }

    /// Bottom-up rewrite.
    func map(_ f: (Expr) -> Expr) -> Expr {
        let m: Expr = switch self {
        case .bin(let o, let a, let b): .bin(o, a.map(f), b.map(f))
        case .un(let o, let a): .un(o, a.map(f))
        case .fn(let n, let args): .fn(n, args.map { $0.map(f) })
        case .load(let a, let s): .load(a.map(f), s)
        case .call(let t, let args): .call(t.map(f), args.map { $0.map(f) })
        case .ite(let c, let a, let b): .ite(c.map(f), a.map(f), b.map(f))
        default: self
        }
        return f(m)
    }

    func any(_ p: (Expr) -> Bool) -> Bool { p(self) || children.contains { $0.any(p) } }
    var vars: [String] { if case .v(let n) = self { return [n] }; return children.flatMap(\.vars) }
    var hasCall: Bool { any { if case .call = $0 { true } else { false } } }
    /// Stack slots count as memory: their address can escape into a callee or pointer store.
    var readsMemory: Bool {
        any { switch $0 { case .load, .call: true; case .v(let n): isSlot(n); default: false } }
    }
    var nodes: Int { 1 + children.reduce(0) { $0 + $1.nodes } }
    var callCount: Int { (hasCallHere ? 1 : 0) + children.reduce(0) { $0 + $1.callCount } }
    private var hasCallHere: Bool { if case .call = self { true } else { false } }
}

func isSlot(_ n: String) -> Bool { n.hasPrefix("sp_") || n.hasPrefix("var_") }

struct Stmt {
    enum Kind {
        case set(String, Expr)
        case store(Expr, Expr, Int)    // address, value, size
        case eval(Expr)                // a call whose result is unused
        case ret(Expr?)
        case jump(UInt64)
        case branch(Expr, UInt64)
        case ijump(Expr)
        case halt(String)
        case asm(String)
    }
    var kind: Kind
    var clobbers: [String] = []        // registers a call or asm block overwrites
    var asmUses: [String] = []

    var defs: [String] { if case .set(let n, _) = kind { [n] + clobbers } else { clobbers } }
    var uses: [String] {
        switch kind {
        case .set(_, let e), .eval(let e), .branch(let e, _), .ijump(let e): e.vars
        case .store(let a, let v, _): a.vars + v.vars
        case .ret(let e): e?.vars ?? []
        case .asm: asmUses
        case .jump, .halt: []
        }
    }
    var exprs: [Expr] {
        switch kind {
        case .set(_, let e), .eval(let e), .branch(let e, _), .ijump(let e): [e]
        case .store(let a, let v, _): [a, v]
        case .ret(let e): e.map { [$0] } ?? []
        default: []
        }
    }
    func mapExprs(_ f: (Expr) -> Expr) -> Stmt {
        var s = self
        switch kind {
        case .set(let n, let e): s.kind = .set(n, e.map(f))
        case .store(let a, let v, let z): s.kind = .store(a.map(f), v.map(f), z)
        case .eval(let e): s.kind = .eval(e.map(f))
        case .branch(let e, let t): s.kind = .branch(e.map(f), t)
        case .ijump(let e): s.kind = .ijump(e.map(f))
        case .ret(let e): s.kind = .ret(e?.map(f))
        default: break
        }
        return s
    }
    var isTerminator: Bool {
        switch kind { case .jump, .branch, .ret, .ijump, .halt: true; default: false }
    }
    var writesMemory: Bool {
        switch kind {
        case .store, .asm: true
        case .set(let n, let e): isSlot(n) || e.hasCall
        case .eval(let e): e.hasCall
        default: false
        }
    }
}

struct ABI {
    let args: [String], ret: String, clobbered: [String], sp: String, fp: String
    static let flags = ["cmp_l", "cmp_r"]
    static let arm64 = ABI(args: (0...7).map { "x\($0)" }, ret: "x0",
                           clobbered: (0...17).map { "x\($0)" } + (0...7).map { "v\($0)" } + (16...31).map { "v\($0)" } + flags,
                           sp: "sp", fp: "x29")
    static let x86_64 = ABI(args: ["rdi", "rsi", "rdx", "rcx", "r8", "r9"], ret: "rax",
                            clobbered: ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"] + (0...15).map { "xmm\($0)" } + flags,
                            sp: "rsp", fp: "rbp")
}

struct Block {
    let start: UInt64
    var stmts: [Stmt] = []
    var succs: [Int] = []
    var preds: [Int] = []
}

// MARK: - Driver

public enum Decompiler {
    /// Pseudo-C for one function, one line per element.
    public static func decompile(_ a: Analysis, _ f: Function) -> [String] {
        guard !f.lines.isEmpty else { return ["// \(f.name): no instructions"] }
        return FunctionDecompiler(a, f).run()
    }
}

final class FunctionDecompiler {
    let a: Analysis
    let f: Function
    let isARM: Bool
    let abi: ABI
    var blocks: [Block] = []
    var index: [UInt64: Int] = [:]

    init(_ a: Analysis, _ f: Function) {
        self.a = a
        self.f = f
        isARM = a.macho.arch.hasPrefix("arm64")
        abi = isARM ? .arm64 : .x86_64
    }

    func run() -> [String] {
        let insns = Array(a.instructions[f.lines])
        let lifted = insns.indices.map { k in
            isARM ? liftARM(insns[k], next: k + 1 < insns.count ? insns[k + 1] : nil) : liftX86(insns[k])
        }
        buildBlocks(insns, lifted)
        canonicalizeStackAddresses()
        inferCallArguments()
        let returnsValue = blocks.contains { $0.stmts.contains { s in
            if case .ret(_?) = s.kind { return true }   // tail call
            return s.defs.contains(abi.ret)
        } }
        for b in blocks.indices {
            for s in blocks[b].stmts.indices {
                if case .ret(nil) = blocks[b].stmts[s].kind, returnsValue { blocks[b].stmts[s].kind = .ret(.v(abi.ret)) }
            }
        }
        let params = abi.args.indices.filter { liveness().liveIn[0].contains(abi.args[$0]) }
        let paramCount = (params.max() ?? -1) + 1
        blocks[0].stmts.insert(contentsOf: (0..<paramCount).map { Stmt(kind: .set(abi.args[$0], .v("arg\($0)"))) }, at: 0)
        copyFlagsIntoSuccessors()
        optimize()
        while simplifyCFG() { optimize() }

        let args = (0..<paramCount).map { "int64_t arg\($0)" }.joined(separator: ", ")
        var out = ["\(returnsValue ? "int64_t" : "void") \(pretty(f.name))(\(args)) {"]
        out += structure()
        out.append("}")
        return out
    }

    func buildBlocks(_ insns: [Instruction], _ lifted: [[Stmt]]) {
        let addrs = Set(insns.map(\.address))
        var leaders: Set<UInt64> = [insns[0].address]
        for (k, stmts) in lifted.enumerated() {
            for s in stmts {
                switch s.kind {
                case .jump(let t), .branch(_, let t): if addrs.contains(t) { leaders.insert(t) }
                default: break
                }
            }
            if stmts.last?.isTerminator == true, k + 1 < insns.count { leaders.insert(insns[k + 1].address) }
        }
        for (k, ins) in insns.enumerated() {
            if leaders.contains(ins.address) {
                index[ins.address] = blocks.count
                blocks.append(Block(start: ins.address))
            }
            blocks[blocks.count - 1].stmts += lifted[k]
        }
        link()
    }

    func link() {
        index = Dictionary(uniqueKeysWithValues: blocks.enumerated().map { ($1.start, $0) })
        for i in blocks.indices { blocks[i].preds = [] }
        for i in blocks.indices {
            let next = i + 1 < blocks.count ? [i + 1] : []
            switch blocks[i].stmts.last?.kind {
            case .jump(let t)?: blocks[i].succs = index[t].map { [$0] } ?? []
            case .branch(_, let t)?: blocks[i].succs = Array(Set((index[t].map { [$0] } ?? []) + next))
            case .ret?, .ijump?, .halt?: blocks[i].succs = []
            default: blocks[i].succs = next
            }
            for s in blocks[i].succs { blocks[s].preds.append(i) }
        }
    }

    /// Drops branches whose condition folded to a constant (PAC checks, `x != x`) and, when there is no
    /// computed jump that could reach them, the blocks nothing reaches any more.
    func simplifyCFG() -> Bool {
        var changed = mergeBlocks()
        for b in blocks.indices {
            guard case .branch(.c(let k), let t)? = blocks[b].stmts.last?.kind else { continue }
            if k == 0 { blocks[b].stmts.removeLast() } else { blocks[b].stmts[blocks[b].stmts.count - 1].kind = .jump(t) }
            changed = true
        }
        guard changed else { return false }
        link()
        _ = mergeBlocks()
        let computed = blocks.contains { if case .ijump? = $0.stmts.last?.kind { true } else { false } }
        if !computed {
            var seen: Set<Int> = [0], work = [0]
            while let b = work.popLast() { for s in blocks[b].succs where seen.insert(s).inserted { work.append(s) } }
            if seen.count < blocks.count {
                blocks = blocks.indices.filter(seen.contains).map { blocks[$0] }
                link()
            }
        }
        return true
    }

    /// Joins a block into its predecessor when it is that block's only successor and only reached from it.
    func mergeBlocks() -> Bool {
        var merged = false
        var i = blocks.count - 2
        while i >= 0 {
            if blocks[i].succs == [i + 1], blocks[i + 1].preds == [i] {
                if case .jump? = blocks[i].stmts.last?.kind { blocks[i].stmts.removeLast() }
                blocks[i].stmts += blocks[i + 1].stmts
                blocks[i].succs = blocks[i + 1].succs
                blocks.remove(at: i + 1)
                merged = true
            }
            i -= 1
        }
        if merged { link() }
        return merged
    }

    /// `cmp a, b; b.gt X; b.lt Y` tests the same flags in two blocks. Re-stating the compare at the top of the
    /// second block (when its operands are unchanged) lets both tests fold into plain conditions.
    func copyFlagsIntoSuccessors() {
        let liveIn = liveness().liveIn
        for b in blocks.indices where blocks[b].preds.count == 1 && ABI.flags.allSatisfy(liveIn[b].contains) {
            let p = blocks[b].preds[0], st = blocks[p].stmts
            var copies: [Stmt] = []
            for flag in ABI.flags {
                guard let i = st.lastIndex(where: { $0.defs.contains(flag) }), case .set(_, let e) = st[i].kind,
                      !st[(i + 1)...].contains(where: { s in s.writesMemory || !Set(s.defs).isDisjoint(with: e.vars) && !s.defs.allSatisfy(ABI.flags.contains) })
                else { copies = []; break }
                copies.append(st[i])
            }
            blocks[b].stmts.insert(contentsOf: copies, at: 0)
        }
    }

    /// Arguments are x0…xk (rdi…) where k is the highest argument register written since the previous call
    /// in the same block, raised to what the callee is known to take.
    func inferCallArguments() {
        // Outgoing stack arguments (variadic on arm64, 7th+ elsewhere) are slots the function never reads.
        let readSlots = Set(blocks.flatMap { $0.stmts.flatMap(\.uses) }.filter(isSlot))
        for b in blocks.indices {
            var defined = Set<Int>()
            var stackArgs: [Int64: Int] = [:]
            var selector: String?
            for s in blocks[b].stmts.indices {
                let st = blocks[b].stmts[s]
                let target: Expr?
                switch st.kind {
                case .set(_, .call(let t, [])), .eval(.call(let t, [])), .ret(.call(let t, [])?): target = t
                default: target = nil
                }
                if let target {
                    let known = objcArgCount(target, selector)
                    let k = known.map { $0 - 1 } ?? max(defined.max() ?? -1, minArgs(target, selector) - 1)
                    var args = (0..<min(k + 1, abi.args.count)).map { Expr.v(abi.args[$0]) }
                    var n: Int64 = 0
                    while let at = stackArgs[n * 8] {
                        let name = "stack\(n)"
                        if case .set(_, let v) = blocks[b].stmts[at].kind { blocks[b].stmts[at].kind = .set(name, v) }
                        args.append(.v(name))
                        n += 1
                    }
                    blocks[b].stmts[s] = st.mapExprs { if case .call(let t, []) = $0 { .call(t, args) } else { $0 } }
                    defined = []; selector = nil; stackArgs = [:]
                    continue
                }
                if case .set(let n, _) = st.kind, n.hasPrefix("sp_"), !readSlots.contains(n), let k = Int64(n.dropFirst(3), radix: 16) {
                    stackArgs[k] = s
                }
                if case .set(abi.args[1], .raw(let r)) = st.kind, r.hasPrefix("@selector(") { selector = String(r.dropFirst(10).dropLast()) }
                // A register written and then consumed before the call was scratch, not an argument.
                let flagWrite: Bool = if case .set(let n, _) = st.kind { n.hasPrefix("cmp_") } else { false }
                if !flagWrite { for u in st.uses { if let i = abi.args.firstIndex(of: u) { defined.remove(i) } } }
                for d in st.defs { if let i = abi.args.firstIndex(of: d) { defined.insert(i) } }
            }
        }
    }

    /// `mov x9, sp; str x8, [x9, #8]` stores to a stack slot like `str x8, [sp, #8]` does.
    func canonicalizeStackAddresses() {
        func offset(_ e: Expr, _ copies: [String: Int64]) -> Int64? {
            switch e {
            case .v(let n): n == abi.sp ? 0 : copies[n]
            case .bin("+", .v(let n), .c(let k)): offset(.v(n), copies).map { $0 &+ k }
            default: nil
            }
        }
        for b in blocks.indices {
            var copies: [String: Int64] = [:]
            for i in blocks[b].stmts.indices {
                var st = blocks[b].stmts[i].mapExprs { e in
                    if case .load(let addr, _) = e, let k = offset(addr, copies), k >= 0 { return .v("sp_" + String(k, radix: 16)) }
                    return e
                }
                if case .store(let addr, let v, _) = st.kind, let k = offset(addr, copies), k >= 0 { st.kind = .set("sp_" + String(k, radix: 16), v) }
                blocks[b].stmts[i] = st
                for d in st.defs { copies[d] = nil }
                if case .set(let r, let e) = st.kind, let k = offset(e, copies) { copies[r] = k }
            }
        }
    }

    /// A message send's selector fixes its register arguments: receiver, selector, one per colon.
    func objcArgCount(_ t: Expr, _ selector: String?) -> Int? {
        guard case .global(let raw) = t else { return nil }
        let n = pretty(raw)
        if n.hasPrefix("objc_msgSend$") { return 2 + n.filter { $0 == ":" }.count }
        if n.hasPrefix("objc_msgSend"), let selector { return 2 + selector.filter { $0 == ":" }.count }
        return nil
    }

    func minArgs(_ t: Expr, _ selector: String?) -> Int {
        guard case .global(let raw) = t else { return 0 }
        let n = pretty(raw)
        if n.hasPrefix("objc_msgSend$") { return 2 + n.filter { $0 == ":" }.count }
        if n.hasPrefix("objc_msgSend") { return 2 + (selector?.filter { $0 == ":" }.count ?? 0) }
        let oneArg = ["objc_retain", "objc_release", "objc_autorelease", "objc_claimAutoreleased", "objc_unsafeClaimAutoreleased",
                      "swift_retain", "swift_release", "swift_bridgeObjectRe", "free", "_Block_release", "_Block_copy"]
        return oneArg.contains { n.hasPrefix($0) } ? 1 : 0
    }

    // MARK: - Dataflow

    func liveness() -> (liveIn: [Set<String>], liveOut: [Set<String>]) {
        let n = blocks.count
        var gen = [Set<String>](repeating: [], count: n), kill = gen
        for b in 0..<n {
            for s in blocks[b].stmts {
                for u in s.uses where !kill[b].contains(u) { gen[b].insert(u) }
                kill[b].formUnion(s.defs)
            }
        }
        var liveIn = gen, liveOut = [Set<String>](repeating: [], count: n)
        var changed = true
        while changed {
            changed = false
            for b in (0..<n).reversed() {
                var out = Set<String>()
                for s in blocks[b].succs { out.formUnion(liveIn[s]) }
                let inn = gen[b].union(out.subtracting(kill[b]))
                if inn != liveIn[b] || out != liveOut[b] { liveIn[b] = inn; liveOut[b] = out; changed = true }
            }
        }
        return (liveIn, liveOut)
    }

    /// Registers and flags are temporaries; stack slots and arguments keep their assignments.
    func isTemp(_ n: String) -> Bool { !isSlot(n) && !n.hasPrefix("arg") && n != abi.sp && n != abi.fp }

    func optimize() {
        for _ in 0..<64 {
            var changed = propagateConstants()
            let liveOut = liveness().liveOut
            for b in blocks.indices {
                propagateArgumentCopies(b)
                if eliminateDeadCode(b, liveOut[b]) { changed = true }
                if propagate(b, liveOut[b]) { changed = true }
                blocks[b].stmts = blocks[b].stmts.map { $0.mapExprs { simplifyNode(self.resolveSlot($0)) } }
            }
            if !changed { break }
        }
    }

    func eliminateDeadCode(_ b: Int, _ liveOut: Set<String>) -> Bool {
        var live = liveOut, kept: [Stmt] = [], changed = false
        for var s in blocks[b].stmts.reversed() {
            if case .set(let n, .v(let m)) = s.kind, n == m { changed = true; continue }
            if case .set(let n, let e) = s.kind, isTemp(n), !live.contains(n) {
                changed = true
                guard e.hasCall else { continue }
                s.kind = .eval(e)
            }
            live.subtract(s.defs)
            live.formUnion(s.uses)
            kept.append(s)
        }
        blocks[b].stmts = kept.reversed()
        return changed
    }

    /// A register defined exactly once, to a constant, and not live on entry: that definition reaches every use.
    func propagateConstants() -> Bool {
        var defCount: [String: Int] = [:], value: [String: Expr] = [:]
        for b in blocks { for s in b.stmts { for d in s.defs { defCount[d, default: 0] += 1 }
            if case .set(let r, let e) = s.kind { value[r] = e } } }
        let liveIn = liveness().liveIn[0]
        let constants = value.filter { r, e in
            guard defCount[r] == 1, isTemp(r), !liveIn.contains(r) else { return false }
            switch e { case .c, .str, .raw, .global: return true; default: return false }
        }
        guard !constants.isEmpty else { return false }
        var changed = false
        for b in blocks.indices {
            for i in blocks[b].stmts.indices {
                let before = blocks[b].stmts[i].uses
                guard before.contains(where: { constants[$0] != nil }) else { continue }
                blocks[b].stmts[i] = blocks[b].stmts[i].mapExprs { if case .v(let n) = $0, let c = constants[n] { c } else { $0 } }
                changed = changed || blocks[b].stmts[i].uses != before
            }
        }
        return changed
    }

    /// `x19 = arg0` makes every later read of x19 (until it is reassigned) a read of arg0.
    func propagateArgumentCopies(_ b: Int) {
        var st = blocks[b].stmts
        for i in st.indices {
            guard case .set(let r, .v(let s)) = st[i].kind, s.hasPrefix("arg"), isTemp(r) else { continue }
            for k in (i + 1)..<st.count {
                st[k] = st[k].mapExprs { $0 == .v(r) ? .v(s) : $0 }
                if st[k].defs.contains(r) { break }
            }
        }
        blocks[b].stmts = st
    }

    /// Folds single-use temporaries into their use when nothing in between changes their value.
    func propagate(_ b: Int, _ liveOut: Set<String>) -> Bool {
        var st = blocks[b].stmts, changed = false, i = 0
        while i < st.count {
            if inline(&st, i, liveOut) { changed = true; i = max(i - 1, 0) } else { i += 1 }
        }
        blocks[b].stmts = st
        return changed
    }

    func inline(_ st: inout [Stmt], _ i: Int, _ liveOut: Set<String>) -> Bool {
        guard case .set(let r, let e) = st[i].kind, isTemp(r), e.nodes <= 48 else { return false }
        var count = 0, first: Int?, redefined = false
        for k in (i + 1)..<st.count {
            let n = st[k].uses.filter { $0 == r }.count
            if n > 0 { count += n; first = first ?? k }
            if st[k].defs.contains(r) { redefined = true; break }
        }
        guard count == 1, let j = first, redefined || !liveOut.contains(r) else { return false }
        if case .asm = st[j].kind { return false }
        let ev = Set(e.vars), reads = e.readsMemory, calls = e.hasCall
        let blocked = st[(i + 1)..<j].contains { m in
            !ev.isDisjoint(with: m.defs) || (reads && m.writesMemory) || (calls && m.exprs.contains { $0.readsMemory })
        }
        if blocked { return false }
        if calls {
            // Keep call order: only nest into a call's own arguments, never beside another call.
            let inJ = st[j].exprs.reduce(0) { $0 + $1.callCount }
            let topCall: Bool = switch st[j].kind {
            case .set(_, .call), .eval(.call), .ret(.call?): true
            default: false
            }
            if inJ > 1 || (inJ == 1 && !topCall) { return false }
        }
        st[j] = st[j].mapExprs { $0 == .v(r) ? e : $0 }
        st.remove(at: i)
        return true
    }

    // MARK: - Structuring

    struct Region { var to: Int; var follow: Int?; var loopHead: Int?; var loopExit: Int? }

    var lines: [String] = []
    var gotoTargets = Set<Int>()
    var emitted = Set<Int>()

    func structure() -> [String] {
        lines = []
        gotoTargets = []
        emitted = []
        _ = emit(0, Region(to: blocks.count), 1)
        return lines.compactMap { line in
            guard line.hasPrefix("\u{0}") else { return line }
            let b = Int(line.dropFirst())!
            return gotoTargets.contains(b) ? label(b) + ":" : nil
        }
    }

    func label(_ b: Int) -> String { "loc_" + String(blocks[b].start, radix: 16) }
    func line(_ text: String, _ indent: Int) { lines.append(String(repeating: "    ", count: indent) + text) }

    /// Emits blocks [from, r.to) in address order; returns whether control can fall off the end.
    @discardableResult
    func emit(_ from: Int, _ r: Region, _ ind: Int, noLoopAt: Int? = nil, skipBranchOf: Int? = nil) -> Bool {
        var i = from, falls = true
        while i < r.to {
            if emitted.contains(i) { i += 1; continue }   // a return block already inlined at its only jump
            if i != noLoopAt, let latch = blocks[i].preds.filter({ $0 >= i && $0 < r.to }).max() {
                i = emitLoop(i, latch, r, ind)
                falls = true
                continue
            }
            lines.append("\u{0}\(i)")
            emitted.insert(i)
            for s in blocks[i].stmts { if let t = render(s) { line(t, ind) } }
            let isLast = i + 1 == r.to
            switch blocks[i].stmts.last?.kind {
            case .jump(let t)?:
                jump(index[t], from: i, r, ind, isLast: isLast, raw: t)
                falls = false
                i += 1
            case .branch(let c, let t)?:
                falls = true
                if i == skipBranchOf { falls = false; i += 1; continue }
                guard let ti = index[t] else { line("if (\(render(c))) goto 0x\(String(t, radix: 16));", ind); i += 1; continue }
                let inRegion = { (x: Int) in x < r.to || x == r.follow }
                if ti == r.loopExit { line("if (\(render(c))) break;", ind); i += 1 }
                else if ti == r.loopHead { line("if (\(render(c))) continue;", ind); i += 1 }
                else if ti == i + 1 { i += 1 }
                else if ti > i + 1, inRegion(ti) {
                    var inner = r
                    if case .jump(let e)? = blocks[ti - 1].stmts.last?.kind, let ei = index[e], ei > ti, inRegion(ei) {
                        inner.to = ti; inner.follow = ei
                        line("if (\(render(negate(c)))) {", ind)
                        emit(i + 1, inner, ind + 1)
                        line("} else {", ind)
                        inner.to = ei
                        emit(ti, inner, ind + 1)
                        line("}", ind)
                        i = ei
                    } else {
                        inner.to = ti; inner.follow = ti
                        line("if (\(render(negate(c)))) {", ind)
                        emit(i + 1, inner, ind + 1)
                        line("}", ind)
                        i = ti
                    }
                } else if isInlinableExit(ti) {
                    line("if (\(render(c))) {", ind)
                    emitInline(ti, ind + 1)
                    line("}", ind)
                    i += 1
                } else {
                    gotoTargets.insert(ti)
                    line("if (\(render(c))) goto \(label(ti));", ind)
                    i += 1
                }
            case .ret?, .ijump?, .halt?:
                falls = false
                i += 1
            default:
                falls = true
                i += 1
            }
        }
        if falls, r.to != r.follow, r.to < blocks.count { jump(r.to, from: r.to - 1, r, ind, isLast: true, raw: blocks[r.to].start) }
        return falls
    }

    func jump(_ ti: Int?, from i: Int, _ r: Region, _ ind: Int, isLast: Bool, raw: UInt64) {
        guard let ti else { return line("goto 0x\(String(raw, radix: 16));", ind) }
        if ti == r.loopHead { if !(isLast && r.follow == ti) { line("continue;", ind) } }
        else if ti == r.loopExit { line("break;", ind) }
        else if isLast && ti == r.follow {}
        else if ti == i + 1 && !isLast {}
        else if isInlinableExit(ti) { emitInline(ti, ind) }
        else { gotoTargets.insert(ti); line("goto \(label(ti));", ind) }
    }

    /// A short block that only one jump reaches and that leaves the function can be written at that jump.
    func isInlinableExit(_ b: Int) -> Bool {
        guard blocks[b].preds.count == 1, blocks[b].succs.isEmpty, !emitted.contains(b), blocks[b].stmts.count <= 16 else { return false }
        switch blocks[b].stmts.last?.kind { case .ret?, .halt?: return true; default: return false }
    }

    func emitInline(_ b: Int, _ ind: Int) {
        emitted.insert(b)
        for s in blocks[b].stmts { if let t = render(s) { line(t, ind) } }
    }

    func emitLoop(_ h: Int, _ l: Int, _ r: Region, _ ind: Int) -> Int {
        let x = l + 1
        let body = Region(to: x, follow: h, loopHead: h, loopExit: x)
        if case .branch(let c, let t)? = blocks[l].stmts.last?.kind, index[t] == h {
            line("do {", ind)
            emit(h, body, ind + 1, noLoopAt: h, skipBranchOf: l)
            line("} while (\(render(c)));", ind)
        } else if h != l, blocks[h].stmts.count == 1, case .branch(let c, let t)? = blocks[h].stmts.last?.kind, index[t] == x,
                  case .jump(let j)? = blocks[l].stmts.last?.kind, index[j] == h {
            lines.append("\u{0}\(h)")
            line("while (\(render(negate(c)))) {", ind)
            emit(h + 1, body, ind + 1)
            line("}", ind)
        } else {
            line("while (true) {", ind)
            emit(h, body, ind + 1, noLoopAt: h)
            line("}", ind)
        }
        return x
    }

    // MARK: - Rendering

    func render(_ s: Stmt) -> String? {
        switch s.kind {
        case .set(let n, let e): "\(n) = \(render(e));"
        case .store(let addr, let v, let size): "\(render(.load(addr, size))) = \(render(v));"
        case .eval(let e): render(e) + ";"
        case .ret(let e): e.map { "return \(render($0));" } ?? "return;"
        case .ijump(let e): "goto *\(wrap(e, 2));"
        case .halt(let t): t + ";"
        case .asm(let t): "asm { \(t) }"
        case .jump, .branch: nil
        }
    }

    static let precedence: [String: Int] = [
        "*": 3, "/": 3, "%": 3, "+": 4, "-": 4, "<<": 5, ">>": 5, "<": 6, "<=": 6, ">": 6, ">=": 6,
        "==": 7, "!=": 7, "&": 8, "^": 9, "|": 10, "&&": 11, "||": 12,
    ]

    func render(_ e: Expr) -> String { renderPrec(e).0 }
    func wrap(_ e: Expr, _ p: Int) -> String { let (t, q) = renderPrec(e); return q > p ? "(\(t))" : t }

    func renderPrec(_ e: Expr) -> (String, Int) {
        switch e {
        case .v(let n): return (n, 0)
        case .c(let k): return (constant(k), k < 0 ? 2 : 0)
        case .str(let s): return (quote(s), 0)
        case .global(let n): return ("&" + pretty(n), 2)
        case .raw(let t): return (t, 0)
        case .un(let o, let x): return (o + wrap(x, 2), 2)
        case .fn(let n, let args): return (n + "(" + args.map(render).joined(separator: ", ") + ")", 0)
        case .ite(let c, let x, let y): return ("\(wrap(c, 12)) ? \(wrap(x, 13)) : \(wrap(y, 13))", 13)
        case .bin(let o, let x, let y):
            let p = Self.precedence[o] ?? 13
            return ("\(wrap(x, p)) \(o) \(wrap(y, p - 1))", p)
        case .call(let t, let args): return (renderCall(t, args), 0)
        case .load(let addr, let size):
            if let slot = stackSlot(addr) { return (slot, 0) }
            if case .global(let n) = addr { return (pretty(n), 0) }
            let type = [1: "uint8_t", 2: "uint16_t", 4: "int32_t", 16: "int128_t"][size].map { "(\($0) *)" } ?? ""
            return ("*" + type + wrap(addr, type.isEmpty ? 2 : 0), 2)
        }
    }

    /// `sp`/`fp` arithmetic that survived as an address (e.g. via `mov x9, sp`) still names its slot.
    func stackSlot(_ addr: Expr) -> String? {
        switch addr {
        case .v(abi.sp): "sp_0"
        case .bin("+", .v(abi.sp), .c(let k)) where k >= 0: "sp_" + String(k, radix: 16)
        case .bin("-", .v(abi.fp), .c(let k)) where k > 0: "var_" + String(k, radix: 16)
        default: nil
        }
    }

    func renderCall(_ t: Expr, _ args: [Expr]) -> String {
        if case .global(let raw) = t {
            let n = pretty(raw)
            if n.hasPrefix("objc_msgSend$"), let recv = args.first {
                return objc(recv, String(n.dropFirst("objc_msgSend$".count)), Array(args.dropFirst(2)))
            }
            if n.hasPrefix("objc_msgSend"), args.count >= 2, case .raw(let sel) = args[1], sel.hasPrefix("@selector(") {
                let recv: Expr = n.hasPrefix("objc_msgSendSuper") ? .raw("super") : args[0]
                return objc(recv, String(sel.dropFirst(10).dropLast()), Array(args.dropFirst(2)))
            }
            return n + "(" + args.map(render).joined(separator: ", ") + ")"
        }
        return "(*\(wrap(t, 2)))(" + args.map(render).joined(separator: ", ") + ")"
    }

    func objc(_ recv: Expr, _ sel: String, _ args: [Expr]) -> String {
        let parts = sel.split(separator: ":", omittingEmptySubsequences: false).dropLast(sel.hasSuffix(":") ? 1 : 0)
        guard sel.contains(":") else { return "[\(render(recv)) \(sel)]" }
        let pieces = parts.enumerated().map { k, p in "\(p):\(k < args.count ? render(args[k]) : "?")" }
        let variadic = args.dropFirst(parts.count).map { ", " + render($0) }.joined()   // e.g. dictionaryWithObjectsAndKeys:
        return "[\(render(recv)) \(pieces.joined(separator: " "))\(variadic)]"
    }

    func constant(_ k: Int64) -> String {
        if k < 0 { return k == .min ? "0x8000000000000000" : "-" + constant(-k) }
        return k < 10 ? String(k) : "0x" + String(k, radix: 16)
    }

    func quote(_ s: String) -> String {
        var out = "\""
        for ch in s.unicodeScalars {
            switch ch {
            case "\n": out += "\\n"
            case "\t": out += "\\t"
            case "\r": out += "\\r"
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            default: out.unicodeScalars.append(ch)
            }
        }
        return out + "\""
    }
}

/// C symbols carry a leading underscore in Mach-O; Swift and Obj-C names don't need stripping.
func pretty(_ n: String) -> String {
    n.hasPrefix("_") && !n.hasPrefix("_$") && n.count > 1 ? String(n.dropFirst()) : n
}

// MARK: - Simplification

let inverse = ["==": "!=", "!=": "==", "<": ">=", ">=": "<", ">": "<=", "<=": ">"]

func negate(_ e: Expr) -> Expr {
    if case .bin(let o, let x, let y) = e, let inv = inverse[o] { return .bin(inv, x, y) }
    if case .un("!", let x) = e { return x }
    return .un("!", e)
}

func fold(_ o: String, _ x: Int64, _ y: Int64) -> Int64? {
    switch o {
    case "+": x &+ y
    case "-": x &- y
    case "*": x &* y
    case "&": x & y
    case "|": x | y
    case "^": x ^ y
    case "<<": (0..<64).contains(y) ? x << y : nil
    case ">>": (0..<64).contains(y) ? Int64(bitPattern: UInt64(bitPattern: x) >> UInt64(y)) : nil
    case "/": y != 0 && !(x == .min && y == -1) ? x / y : nil
    case "%": y != 0 && !(x == .min && y == -1) ? x % y : nil
    case "==": x == y ? 1 : 0
    case "!=": x != y ? 1 : 0
    case "<": x < y ? 1 : 0
    case "<=": x <= y ? 1 : 0
    case ">": x > y ? 1 : 0
    case ">=": x >= y ? 1 : 0
    default: nil
    }
}

func simplify(_ e: Expr) -> Expr { e.map(simplifyNode) }

func simplifyNode(_ e: Expr) -> Expr {
    switch e {
    case .bin(let o, .c(let x), .c(let y)):
        if let r = fold(o, x, y) { return .c(r) }
    case .bin("+", let x, .c(0)), .bin("-", let x, .c(0)), .bin("|", let x, .c(0)), .bin("^", let x, .c(0)),
         .bin("<<", let x, .c(0)), .bin(">>", let x, .c(0)), .bin("*", let x, .c(1)), .bin("/", let x, .c(1)),
         .bin("+", .c(0), let x), .bin("|", .c(0), let x):
        return x
    case .bin("&", let x, let y) where x == y, .bin("|", let x, let y) where x == y:
        return x
    case .bin("+", .bin("+", let x, .c(let k1)), .c(let k2)), .bin("+", .bin("+", .c(let k1), let x), .c(let k2)):
        return simplifyNode(.bin("+", x, .c(k1 &+ k2)))
    case .bin("-", .bin("+", let x, .c(let k1)), .c(let k2)):
        return simplifyNode(.bin("+", x, .c(k1 &- k2)))
    case .bin("+", .bin("-", let x, .c(let k1)), .c(let k2)), .bin("-", .bin("-", let x, .c(let k1)), .c(let k2)):
        let k = if case .bin("+", _, _) = e { k2 &- k1 } else { 0 &- (k1 &+ k2) }
        return simplifyNode(.bin("+", x, .c(k)))
    case .bin("+", let x, .c(let k)) where k < 0 && k != .min:
        return .bin("-", x, .c(-k))
    case .bin("-", let x, .c(let k)) where k < 0 && k != .min:
        return .bin("+", x, .c(-k))
    case .bin("+", let x, .un("-", let y)):
        return .bin("-", x, y)
    case .bin("-", .c(0), let x):
        return .un("-", x)
    case .bin(let o, let x, let y) where x == y && !x.hasCall && ["-", "^", "!=", "<", ">", "==", "<=", ">="].contains(o):
        return .c(["==", "<=", ">="].contains(o) ? 1 : 0)
    case .bin("==", let x, .c(1)) where isBoolean(x), .bin(">", let x, .c(0)) where isBoolean(x),
         .bin(">=", let x, .c(1)) where isBoolean(x), .bin("<", .c(0), let x) where isBoolean(x),
         .bin("<=", .c(1), let x) where isBoolean(x):
        return x
    case .bin("&&", .c(let k), let x), .bin("&&", let x, .c(let k)):
        return k == 0 ? .c(0) : x
    case .bin("||", .c(let k), let x), .bin("||", let x, .c(let k)):
        return k != 0 ? .c(1) : x
    case .bin(let o, .bin("-", let x, let y), .c(0)) where inverse[o] != nil:
        return .bin(o, x, y)   // flags from subs: (a - b) < 0 → a < b
    case .bin("!=", let x, .c(0)) where isBoolean(x):
        return x
    case .bin("==", let x, .c(0)) where isBoolean(x):
        return negate(x)
    case .ite(let c, .c(1), .c(0)):
        return c
    case .ite(let c, .c(0), .c(1)):
        return negate(c)
    case .ite(let c, let x, let y) where x == y && !c.hasCall:
        return x
    case .un("!", .un("!", let x)):
        return x
    case .un("!", let x) where isBoolean(x):
        return negate(x)
    case .un("-", .c(let k)) where k != .min:
        return .c(-k)
    case .un("~", .c(let k)):
        return .c(~k)
    case .un("-", .un("-", let x)), .un("~", .un("~", let x)):
        return x
    case .un("&", .load(let x, _)):
        return x
    default: break
    }
    return e
}

func isBoolean(_ e: Expr) -> Bool {
    if case .bin(let o, _, _) = e { return inverse[o] != nil || o == "&&" || o == "||" }
    if case .un("!", _) = e { return true }
    return false
}
