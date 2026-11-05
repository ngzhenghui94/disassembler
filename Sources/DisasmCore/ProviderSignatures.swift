import Foundation

extension ProviderServer {
    static func signatureSchema(_ name: String) -> [String: Any]? {
        guard name == "function_signature" else { return nil }
        let type: [String: Any] = ["type": "string", "enum": FunctionType.allCases.map(\.rawValue)]
        let parameter: [String: Any] = ["type": "object", "properties": [
            "name": ["type": "string"],
            "type": ["type": "string", "enum": FunctionType.allCases.filter { $0 != .void }.map(\.rawValue)]
        ], "required": ["name", "type"], "additionalProperties": false]
        return ["type": "object", "properties": [
            "database": ["type": "string"],
            "addr": ["type": "string", "description": "Hexadecimal function entry or import address"],
            "action": ["type": "string", "enum": ["get", "set", "reset"]],
            "signature": ["type": "object", "properties": [
                "returnType": type, "parameters": ["type": "array", "maxItems": 8, "items": parameter]
            ], "required": ["returnType", "parameters"], "additionalProperties": false]
        ], "required": ["addr", "action"], "additionalProperties": false]
    }

    func functionSignature(_ arguments: [String: Any]) throws -> Any {
        guard arguments["database"] == nil || arguments["database"] is String else {
            throw MachOError(message: "database must be an analysis session_id string")
        }
        guard Set(arguments.keys).isSubset(of: ["database", "addr", "action", "signature"]),
              let action = arguments["action"] as? String, ["get", "set", "reset"].contains(action),
              let text = arguments["addr"] as? String, let address = parseAddress(text) else {
            throw MachOError(message: "function_signature needs action (get, set or reset) and a hexadecimal addr")
        }
        var session = try session(arguments)
        guard session.analysis.function(containing: address)?.start == address || session.analysis.imports.contains(where: { $0.stub == address }) else {
            throw MachOError(message: "Signatures require a function entry or import address")
        }
        let store = session.signatureStore
        var signatures = try store.load(for: session.analysis)
        if action == "set" {
            guard let object = arguments["signature"] as? [String: Any], Set(object.keys) == ["returnType", "parameters"],
                  let parameters = object["parameters"] as? [[String: Any]], parameters.count <= 8,
                  parameters.allSatisfy({ Set($0.keys) == ["name", "type"] }) else {
                throw MachOError(message: "signature needs returnType and parameters containing name and type")
            }
            let signature = try JSONDecoder().decode(FunctionSignature.self, from: JSONSerialization.data(withJSONObject: object))
            try store.save(signature, at: address, in: session.analysis)
            signatures[address] = signature
        } else {
            guard arguments["signature"] == nil else { throw MachOError(message: "Only set accepts a signature") }
            if action == "reset" {
                try store.save(nil, at: address, in: session.analysis)
                signatures[address] = nil
            }
        }
        if session.signatures != signatures {
            session.signatures = signatures
            session.pseudocode.removeAll()
            sessions[session.id] = session
        }
        let value: Any = try signatures[address].map { try JSONSerialization.jsonObject(with: JSONEncoder().encode($0)) } ?? NSNull()
        return ["addr": hex(address), "signature": value, "source": signatures[address] == nil ? "inferred" : "user", "saved": action != "get"] as [String: Any]
    }
}
