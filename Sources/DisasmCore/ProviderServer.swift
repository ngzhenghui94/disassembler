import Foundation

/// An MCP server speaking the "headless" IDA-MCP tool profile that REA's `ida` provider drives
/// (idb_open/idb_list/idb_close/server_health plus read-only analysis tools), backed by `Analysis`.
/// Point REA at it with REA_IDA_MCP_CONFIG; see README.
public final class ProviderServer {
    struct Session {
        let id: String
        let inputPath: String
        let analysis: Analysis
        let debugInfo: URL
        var pseudocode: [UInt64: [String]] = [:]
        var regexMatches: [String: [StringRef]] = [:]
    }

    static let tools: [(name: String, description: String)] = [
        ("idb_open", "Analyze a Mach-O file and register it as a session."),
        ("idb_list", "List open sessions."),
        ("idb_close", "Close a session."),
        ("server_health", "Report the session's input, image base and readiness."),
        ("list_funcs", "Page through functions."),
        ("lookup_funcs", "Resolve function names or addresses to their function."),
        ("find_regex", "Search strings in the binary with a regular expression."),
        ("decompile", "No decompiler: returns the function's original source lines from debug info when available."),
        ("disasm", "Disassemble a function."),
        ("callees", "Functions and imports a function calls."),
        ("xrefs_to", "Code and data references to an address."),
    ]

    var sessions: [String: Session] = [:]
    var order: [String] = []

    public init() {}

    /// Handles one JSON-RPC message; returns the response, or nil for notifications.
    public func handle(_ message: [String: Any]) -> [String: Any]? {
        guard let id = message["id"] else { return nil }
        let method = message["method"] as? String ?? ""
        let params = message["params"] as? [String: Any] ?? [:]
        func reply(_ result: Any) -> [String: Any] { ["jsonrpc": "2.0", "id": id, "result": result] }
        switch method {
        case "initialize":
            return reply([
                "protocolVersion": params["protocolVersion"] as? String ?? "2025-06-18",
                "capabilities": ["tools": [:] as [String: Any]],
                "serverInfo": ["name": "disassembler-mcp", "version": "1.0"],
            ] as [String: Any])
        case "ping":
            return reply([:] as [String: Any])
        case "tools/list":
            return reply(["tools": Self.tools.map {
                ["name": $0.name, "description": $0.description,
                 "inputSchema": ["type": "object", "additionalProperties": true] as [String: Any]] as [String: Any]
            }])
        case "tools/call":
            let name = params["name"] as? String ?? ""
            let args = params["arguments"] as? [String: Any] ?? [:]
            do {
                let value = try call(name, args)
                let text = String(decoding: (try? JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed])) ?? Data(), as: UTF8.self)
                return reply(["content": [["type": "text", "text": text]], "structuredContent": ["result": value], "isError": false] as [String: Any])
            } catch {
                return reply(["content": [["type": "text", "text": error.localizedDescription]], "isError": true] as [String: Any])
            }
        default:
            return ["jsonrpc": "2.0", "id": id, "error": ["code": -32601, "message": "Method not found: \(method)"] as [String: Any]]
        }
    }

    // MARK: - Tools

    func call(_ name: String, _ a: [String: Any]) throws -> Any {
        switch name {
        case "idb_open": return try open(a)
        case "idb_list":
            return ["sessions": order.compactMap { sessions[$0] }.map {
                ["session_id": $0.id, "input_path": $0.inputPath, "owned": true, "backend": "worker", "is_active": true] as [String: Any]
            }]
        case "idb_close":
            let s = try session(a)
            sessions[s.id] = nil
            order.removeAll { $0 == s.id }
            return ["success": true, "session_id": s.id, "saved": false, "owned": true, "backend": "worker"] as [String: Any]
        case "server_health":
            let s = try session(a)
            return ["status": "ok", "input_path": s.inputPath, "idb_path": NSNull(), "imagebase": hex(s.analysis.macho.textBase),
                    "auto_analysis_ready": true, "module": URL(fileURLWithPath: s.inputPath).lastPathComponent] as [String: Any]
        case "list_funcs": return try listFuncs(a)
        case "lookup_funcs":
            let s = try session(a)
            let queries = (a["queries"] as? [String]) ?? [a["queries"] as? String].compactMap { $0 }
            return queries.map { q -> [String: Any] in
                if let f = lookup(q, in: s.analysis) { return ["query": q, "fn": fn(f), "error": NSNull()] }
                return ["query": q, "fn": NSNull(), "error": "No function matches \(q)"]
            }
        case "find_regex": return try findRegex(a)
        case "disasm": return try disasm(a)
        case "decompile": return try decompile(a)
        case "callees": return try callees(a)
        case "xrefs_to": return try xrefsTo(a)
        default: throw MachOError(message: "Unknown tool \(name)")
        }
    }

    func open(_ a: [String: Any]) throws -> Any {
        guard let path = a["input_path"] as? String else { throw MachOError(message: "idb_open needs input_path") }
        let picked = URL(fileURLWithPath: path)
        let exe = Bundle(url: picked)?.executableURL ?? picked
        let slices = try MachO.slices(of: Data(contentsOf: exe, options: .mappedIfSafe))
        #if arch(arm64)
        let slice = slices.first { $0.arch.hasPrefix("arm64") } ?? slices[0]
        #else
        let slice = slices.first { $0.arch == "x86_64" } ?? slices[0]
        #endif
        let analysis = try Analysis(slice: slice)
        let id = (a["preferred_session_id"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? UUID().uuidString
        sessions[id] = Session(id: id, inputPath: path, analysis: analysis,
                               debugInfo: SourceLines.debugInfo(for: exe, bundle: nil, uuid: analysis.macho.uuid))
        order.removeAll { $0 == id }
        order.append(id)
        return ["success": true, "session": ["session_id": id, "input_path": path, "arch": slice.arch] as [String: Any]] as [String: Any]
    }

    func session(_ a: [String: Any]) throws -> Session {
        if let id = a["database"] as? String {
            guard let s = sessions[id] else { throw MachOError(message: "No open session \(id)") }
            return s
        }
        guard let last = order.last, let s = sessions[last] else { throw MachOError(message: "No open session; call idb_open first") }
        return s
    }

    func listFuncs(_ a: [String: Any]) throws -> Any {
        let s = try session(a)
        let q = (a["queries"] as? [String: Any]) ?? (a["queries"] as? [[String: Any]])?.first ?? [:]
        let fns = s.analysis.functions
        let offset = min(max(q["offset"] as? Int ?? 0, 0), fns.count)
        let end = min(offset + min(max(q["count"] as? Int ?? 100, 1), 1000), fns.count)
        return [["data": fns[offset..<end].map(fn), "next_offset": end < fns.count ? end : NSNull()] as [String: Any]]
    }

    func findRegex(_ a: [String: Any]) throws -> Any {
        var s = try session(a)
        let pattern = a["pattern"] as? String ?? ".*"
        let matches: [StringRef]
        if let cached = s.regexMatches[pattern] {
            matches = cached
        } else {
            let re = try NSRegularExpression(pattern: pattern)
            matches = s.analysis.strings.filter { re.firstMatch(in: $0.value, range: NSRange($0.value.startIndex..., in: $0.value)) != nil }
            s.regexMatches[pattern] = matches
            sessions[s.id] = s
        }
        let offset = min(max(a["offset"] as? Int ?? 0, 0), matches.count)
        let end = min(offset + min(max(a["limit"] as? Int ?? 100, 1), 1000), matches.count)
        return ["matches": matches[offset..<end].map { ["addr": hex($0.address), "string": $0.value] },
                "cursor": end < matches.count ? ["next": end] : ["done": true]] as [String: Any]
    }

    func disasm(_ a: [String: Any]) throws -> Any {
        let s = try session(a)
        guard let addr = (a["addr"] as? String).flatMap(parseAddress), let f = s.analysis.function(containing: addr) else {
            return ["asm": NSNull(), "error": "No function at \(a["addr"] ?? "?")", "cursor": ["done": true]] as [String: Any]
        }
        let ins = s.analysis.instructions[f.lines]
        let offset = min(max(a["offset"] as? Int ?? 0, 0), ins.count)
        let end = min(offset + min(max(a["max_instructions"] as? Int ?? 100, 1), 5000), ins.count)
        let lines = ins.dropFirst(offset).prefix(end - offset).map { i -> [String: Any] in
            // REA keeps only the instruction text, so stub names and string literals go inline.
            let text = i.operands.isEmpty ? i.mnemonic : "\(i.mnemonic) \(i.operands)"
            return ["addr": hex(i.address), "instruction": i.comment.isEmpty ? text : "\(text) ; \(i.comment)"]
        }
        return ["asm": ["name": f.name, "start_ea": hex(f.start), "lines": lines] as [String: Any],
                "cursor": end < ins.count ? ["next": end] : ["done": true]] as [String: Any]
    }

    func decompile(_ a: [String: Any]) throws -> Any {
        var s = try session(a)
        guard let addr = (a["addr"] as? String).flatMap(parseAddress), let f = s.analysis.function(containing: addr) else {
            return ["code": NSNull(), "error": "No function at \(a["addr"] ?? "?")", "cursor": ["done": true]] as [String: Any]
        }
        let lines: [String]
        if let cached = s.pseudocode[f.start] {
            lines = cached
        } else {
            lines = sourceListing(f, s)
            s.pseudocode[f.start] = lines
            sessions[s.id] = s
        }
        let offset = min(max(a["offset"] as? Int ?? 0, 0), lines.count)
        let end = min(offset + min(max(a["max_lines"] as? Int ?? 100, 1), 5000), lines.count)
        return ["code": lines[offset..<end].joined(separator: "\n"), "cursor": end < lines.count ? ["next": end] : ["done": true],
                "line_count": end - offset, "total_lines": lines.count] as [String: Any]
    }

    /// There's no decompiler, so this returns what is real: the function's own source lines from debug info,
    /// labelled as such, or a one-line note. It never invents code.
    func sourceListing(_ f: Function, _ s: Session) -> [String] {
        let a = s.analysis
        let found = SourceLines.lookup(a.instructions[f.lines].map(\.address), debugInfo: s.debugInfo,
                                       arch: a.macho.arch, loadAddress: a.macho.textBase)
        let byFile = Dictionary(grouping: found.values, by: \.file)
        guard let (file, refs) = byFile.max(by: { $0.value.count < $1.value.count }) else {
            return ["// Pseudocode unavailable: Disassembler has no decompiler and \(f.name) has no debug line info. Use the assembly."]
        }
        let lo = refs.map(\.line).min()!, hi = refs.map(\.line).max()!
        var out = ["// Not decompiled: original source of \(f.name) from debug info, \(file):\(lo)-\(hi)."]
        if byFile.count > 1 {
            out.append("// Also contains code from: " + byFile.keys.filter { $0 != file }.sorted().joined(separator: ", "))
        }
        if let text = try? String(contentsOfFile: file, encoding: .utf8) {
            let src = text.split(separator: "\n", omittingEmptySubsequences: false)
            if lo <= src.count {   // stale debug info can point past the end of an edited file
                for n in lo...min(hi, src.count) { out.append(String(format: "/* %4d */ ", n) + src[n - 1]) }
            }
        } else {
            out.append("// Source file isn't readable here; lines referenced: " + Set(refs.map(\.line)).sorted().map(String.init).joined(separator: ", "))
        }
        return out
    }

    func callees(_ a: [String: Any]) throws -> Any {
        let s = try session(a)
        let an = s.analysis
        let limit = a["limit"] as? Int ?? 500
        let addrs = (a["addrs"] as? [String]) ?? [a["addrs"] as? String].compactMap { $0 }
        return addrs.map { q -> [String: Any] in
            guard let addr = parseAddress(q), let f = an.function(containing: addr) else {
                return ["callees": NSNull(), "error": "No function at \(q)"]
            }
            let stubs = Dictionary(an.imports.map { ($0.stub, $0.name) }, uniquingKeysWith: { x, _ in x })
            var seen = Set<UInt64>(), out: [[String: Any]] = []
            for i in an.instructions[f.lines] {
                guard let t = i.target, !seen.contains(t) else { continue }
                let isCall = i.mnemonic.hasPrefix("bl") || i.mnemonic.hasPrefix("call")
                if let name = stubs[t], isCall || i.mnemonic == "b" || i.mnemonic.hasPrefix("jmp") {
                    seen.insert(t)
                    out.append(["addr": hex(t), "name": name, "type": "external"])
                } else if let callee = an.function(containing: t), callee.start == t, callee.start != f.start,
                          isCall || i.mnemonic == "b" || i.mnemonic.hasPrefix("jmp") {   // calls and tail calls
                    seen.insert(t)
                    out.append(["addr": hex(t), "name": callee.name, "type": "internal"])
                }
            }
            return ["callees": Array(out.prefix(limit)), "more": out.count > limit]
        }
    }

    func xrefsTo(_ a: [String: Any]) throws -> Any {
        let s = try session(a)
        let an = s.analysis
        let limit = a["limit"] as? Int ?? 1000
        let addrs = (a["addrs"] as? [String]) ?? [a["addrs"] as? String].compactMap { $0 }
        return addrs.map { q -> [String: Any] in
            guard let addr = parseAddress(q) else { return ["xrefs": NSNull(), "error": "Bad address \(q)"] }
            let refs = (an.xrefs[addr] ?? []).map { src -> [String: Any] in
                ["addr": hex(src), "type": an.instruction(at: src)?.target == addr ? "code" : "data",
                 "fn": an.function(containing: src).map(fn) ?? NSNull()]
            }
            return ["xrefs": Array(refs.prefix(limit)), "more": refs.count > limit]
        }
    }

    // MARK: - Helpers

    func fn(_ f: Function) -> [String: Any] { ["addr": hex(f.start), "name": f.name, "size": hex(f.end - f.start)] }

    func hex(_ v: UInt64) -> String { "0x" + String(v, radix: 16) }

    func parseAddress(_ s: String) -> UInt64? {
        let t = s.trimmingCharacters(in: .whitespaces).lowercased()
        return t.hasPrefix("0x") ? UInt64(t.dropFirst(2), radix: 16) : nil
    }

    /// Hex address (entry or interior), exact name, or the name with Mach-O's leading underscore.
    func lookup(_ q: String, in a: Analysis) -> Function? {
        if let addr = parseAddress(q) { return a.function(containing: addr) }
        return a.functions.first { $0.name == q } ?? a.functions.first { $0.name == "_" + q }
    }
}
