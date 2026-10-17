import Foundation
import Testing
@testable import DisasmCore

/// Replays the call sequence REA's headless IDA provider makes, checking the fields it validates.
@Test func providerServerSpeaksReaHeadlessProfile() throws {
    let bin = try fixtureBinary(arch: "arm64", strip: false)
    let server = ProviderServer()
    var nextID = 0
    func rpc(_ method: String, _ params: [String: Any] = [:]) throws -> [String: Any] {
        nextID += 1
        let response = try #require(server.handle(["jsonrpc": "2.0", "id": nextID, "method": method, "params": params]))
        return try #require(response["result"] as? [String: Any], "\(response)")
    }
    func tool(_ name: String, _ args: [String: Any]) throws -> Any {
        let r = try rpc("tools/call", ["name": name, "arguments": args])
        #expect(r["isError"] as? Bool == false, "\(name): \(r["content"] ?? "")")
        // REA unwraps FastMCP's {"result": value} wrapper.
        return try #require((r["structuredContent"] as? [String: Any])?["result"])
    }

    #expect(server.handle(["jsonrpc": "2.0", "method": "notifications/initialized"]) == nil)
    let initialized = try rpc("initialize", ["protocolVersion": "2025-06-18"])
    #expect(initialized["protocolVersion"] as? String == "2025-06-18")
    let names = Set((try rpc("tools/list")["tools"] as? [[String: Any]] ?? []).compactMap { $0["name"] as? String })
    #expect(names.isSuperset(of: ["idb_open", "idb_list", "idb_close", "server_health", "list_funcs", "lookup_funcs",
                                   "find_regex", "decompile", "disasm", "callees", "xrefs_to"]))

    let opened = try #require(try tool("idb_open", ["input_path": bin.path, "mode": "force_headless", "preferred_session_id": "rea-1"]) as? [String: Any])
    #expect(opened["success"] as? Bool == true)
    #expect((opened["session"] as? [String: Any])?["session_id"] as? String == "rea-1")
    let db: [String: Any] = ["database": "rea-1"]
    let listed = try #require((try tool("idb_list", [:]) as? [String: Any])?["sessions"] as? [[String: Any]])
    #expect(listed.count == 1 && listed[0]["owned"] as? Bool == true && listed[0]["backend"] as? String == "worker"
            && listed[0]["is_active"] as? Bool == true && listed[0]["input_path"] as? String == bin.path)
    let health = try #require(try tool("server_health", db) as? [String: Any])
    #expect(health["status"] as? String == "ok" && health["auto_analysis_ready"] as? Bool == true && health["imagebase"] as? String == "0x100000000")

    // list_funcs pages are a one-element array with data + next_offset.
    let page = try #require((try tool("list_funcs", db.merging(["queries": ["offset": 0, "count": 100]]) { $1 }) as? [[String: Any]])?.first)
    let fns = try #require(page["data"] as? [[String: Any]])
    #expect(fns.contains { $0["name"] as? String == "_main" } && page["next_offset"] is NSNull)

    // Lookup by name (with or without Mach-O's underscore) and by interior address returns the entry.
    let helper = try #require(((try tool("lookup_funcs", db.merging(["queries": ["helper"]]) { $1 }) as? [[String: Any]])?.first)?["fn"] as? [String: Any])
    let helperAddr = try #require(helper["addr"] as? String)
    #expect(helper["name"] as? String == "_helper")
    let interior = "0x" + String(UInt64(helperAddr.dropFirst(2), radix: 16)! + 4, radix: 16)
    let byAddr = (try tool("lookup_funcs", db.merging(["queries": [interior]]) { $1 }) as? [[String: Any]])?.first
    #expect((byAddr?["fn"] as? [String: Any])?["addr"] as? String == helperAddr)
    let missing = (try tool("lookup_funcs", db.merging(["queries": ["nope"]]) { $1 }) as? [[String: Any]])?.first
    #expect(missing?["fn"] is NSNull && missing?["error"] is String)

    // disasm identifies the same function REA resolved.
    let asmPage = try #require(try tool("disasm", db.merging(["addr": helperAddr, "offset": 0, "max_instructions": 100]) { $1 }) as? [String: Any])
    let asm = try #require(asmPage["asm"] as? [String: Any])
    #expect(asm["start_ea"] as? String == helperAddr && asm["name"] as? String == "_helper")
    #expect(((asm["lines"] as? [[String: Any]])?.count ?? 0) > 3 && (asmPage["cursor"] as? [String: Any])?["done"] as? Bool == true)

    // "decompile" returns the real source lines, labelled as not decompiled.
    let code = try #require((try tool("decompile", db.merging(["addr": helperAddr, "offset": 0, "max_lines": 100]) { $1 }) as? [String: Any])?["code"] as? String)
    #expect(code.hasPrefix("// Not decompiled: original source of _helper") && code.contains("int doubled = x * 2;"), "\(code)")

    // main calls puts (import) and tail-calls helper (internal).
    let mainAddr = try #require(fns.first { $0["name"] as? String == "_main" }?["addr"] as? String)
    let callees = try #require(((try tool("callees", db.merging(["addrs": [mainAddr], "limit": 500]) { $1 }) as? [[String: Any]])?.first)?["callees"] as? [[String: Any]])
    #expect(callees.contains { $0["name"] as? String == "_puts" && $0["type"] as? String == "external" })
    #expect(callees.contains { $0["addr"] as? String == helperAddr && $0["type"] as? String == "internal" })

    let xrefs = try #require(((try tool("xrefs_to", db.merging(["addrs": [helperAddr], "limit": 1000]) { $1 }) as? [[String: Any]])?.first)?["xrefs"] as? [[String: Any]])
    #expect(xrefs.contains { $0["type"] as? String == "code" && ($0["fn"] as? [String: Any])?["addr"] as? String == mainAddr })

    // REA lists strings with find_regex("(?s).*") and follows the cursor.
    let strings = try #require(try tool("find_regex", db.merging(["pattern": "(?s).*", "offset": 0, "limit": 100]) { $1 }) as? [String: Any])
    #expect((strings["matches"] as? [[String: Any]])?.contains { $0["string"] as? String == "hello-from-fixture" } == true)
    #expect((strings["cursor"] as? [String: Any])?["done"] as? Bool == true)

    let closed = try #require(try tool("idb_close", db.merging(["save": false]) { $1 }) as? [String: Any])
    #expect(closed["success"] as? Bool == true && closed["saved"] as? Bool == false && closed["owned"] as? Bool == true)
    #expect(((try tool("idb_list", [:]) as? [String: Any])?["sessions"] as? [Any])?.isEmpty == true)

    // Errors come back as MCP tool errors, not crashes.
    let bad = try rpc("tools/call", ["name": "idb_open", "arguments": ["input_path": "/nonexistent"]])
    #expect(bad["isError"] as? Bool == true)
}
