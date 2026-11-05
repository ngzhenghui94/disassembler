import Foundation

/// ABI scalar types supported by editable signatures. Floating-point, aggregates and variadics are not supported.
public enum FunctionType: String, CaseIterable, Codable, Sendable {
    case void, int8, uint8, int16, uint16, int32, uint32, int64, uint64, pointer

    public var cName: String {
        switch self {
        case .void: "void"
        case .pointer: "void *"
        default: rawValue + "_t"
        }
    }
}

public struct FunctionParameter: Codable, Equatable, Sendable {
    public let name: String
    public let type: FunctionType

    public init(name: String, type: FunctionType) throws {
        let bytes = Array(name.utf8)
        let letter = { (b: UInt8) in (65...90).contains(b) || (97...122).contains(b) || b == 95 }
        guard let first = bytes.first, letter(first), bytes.dropFirst().allSatisfy({ letter($0) || (48...57).contains($0) }) else {
            throw SignatureError("Parameter names must be ASCII C identifiers.")
        }
        let reserved: Set<String> = ["auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long", "register", "restrict", "return", "short", "signed", "sizeof", "static", "struct", "switch", "typedef", "union", "unsigned", "void", "volatile", "while", "_Bool", "_Complex", "_Imaginary", "asm", "bool", "true", "false", "nullptr", "class", "new", "delete", "this", "template", "operator", "int8_t", "uint8_t", "int16_t", "uint16_t", "int32_t", "uint32_t", "int64_t", "uint64_t"]
        let argumentSuffix = name.dropFirst(3)
        let generatedArgument = name.hasPrefix("arg") && !argumentSuffix.isEmpty && argumentSuffix.allSatisfy(\.isNumber)
        guard !reserved.contains(name), !name.hasPrefix("_"),
              !generatedArgument, !["sp_", "var_", "stack", "loc_", "cmp_"].contains(where: name.hasPrefix),
              !["sp", "zr", "fp", "lr", "super", "OVERFLOW", "sqrt", "int128_t"].contains(name),
              FunctionDecompiler.x86Regs[name] == nil,
              !["x", "w", "v", "s", "d", "q"].contains(where: { name.hasPrefix($0) && Int(name.dropFirst()) != nil }) else {
            throw SignatureError("Parameter name '\(name)' is reserved by C or the decompiler.")
        }
        guard type != .void else { throw SignatureError("A parameter cannot have type void.") }
        self.name = name
        self.type = type
    }

    private enum CodingKeys: CodingKey { case name, type }
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(name: c.decode(String.self, forKey: .name), type: c.decode(FunctionType.self, forKey: .type))
    }
}

public struct FunctionSignature: Codable, Equatable, Sendable {
    public let returnType: FunctionType
    public let parameters: [FunctionParameter]

    public init(returnType: FunctionType, parameters: [FunctionParameter]) throws {
        guard Set(parameters.map(\.name)).count == parameters.count else {
            throw SignatureError("Parameter names must be unique.")
        }
        self.returnType = returnType
        self.parameters = parameters
    }

    /// Only scalar register arguments are supported; stack arguments must not be silently truncated.
    public func validate(for binary: MachO) throws {
        guard binary.supportsPseudocode else { throw SignatureError("Signatures are not supported for \(binary.arch).") }
        let count = binary.arch.hasPrefix("arm64") ? 8 : (binary.isPE ? 4 : 6)
        guard parameters.count <= count else {
            throw SignatureError("\(binary.arch) \(binary.isPE ? "Windows" : "native") signatures support at most \(count) register parameters; stack arguments are not supported.")
        }
        let symbols = Set(binary.symbols.map { pretty($0.name) } + binary.binds.values.map(pretty))
        if let collision = parameters.first(where: { symbols.contains($0.name) }) {
            throw SignatureError("Parameter '\(collision.name)' collides with a binary symbol.")
        }
    }

    private enum CodingKeys: CodingKey { case returnType, parameters }
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(returnType: c.decode(FunctionType.self, forKey: .returnType), parameters: c.decode([FunctionParameter].self, forKey: .parameters))
    }
}

private struct SignatureError: LocalizedError {
    let errorDescription: String?
    init(_ message: String) { errorDescription = message }
}
