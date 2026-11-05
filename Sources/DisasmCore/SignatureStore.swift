import CryptoKit
import Foundation

/// Overrides belong to the exact slice bytes, never merely to a path or a reused build UUID.
public struct SignatureStore: Sendable {
    private let directory: URL

    public init(binary: MachO, root: URL? = nil) {
        let root = root ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Disassembler/Signatures", isDirectory: true)
        let digest = SHA256.hash(data: binary.data).map { String(format: "%02x", $0) }.joined()
        directory = root.appendingPathComponent(digest, isDirectory: true)
    }

    public func load(for analysis: Analysis) throws -> [UInt64: FunctionSignature] {
        guard FileManager.default.fileExists(atPath: directory.path) else { return [:] }
        let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
        var result: [UInt64: FunctionSignature] = [:]
        for file in files where file.pathExtension == "json" {
            guard let address = UInt64(file.deletingPathExtension().lastPathComponent, radix: 16),
                  analysis.function(containing: address)?.start == address || analysis.imports.contains(where: { $0.stub == address }) else {
                throw MachOError(message: "Invalid saved signature address: \(file.lastPathComponent)")
            }
            let signature = try JSONDecoder().decode(FunctionSignature.self, from: Data(contentsOf: file))
            try signature.validate(for: analysis.macho)
            result[address] = signature
        }
        return result
    }

    public func save(_ signature: FunctionSignature?, at address: UInt64, in analysis: Analysis) throws {
        guard analysis.function(containing: address)?.start == address || analysis.imports.contains(where: { $0.stub == address }) else {
            throw MachOError(message: "Signatures require a function entry or import address")
        }
        let file = directory.appendingPathComponent(String(address, radix: 16) + ".json")
        if let signature {
            try signature.validate(for: analysis.macho)
            let data = try JSONEncoder().encode(signature)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            // One atomic file per function prevents unrelated edits in another session from being lost.
            try data.write(to: file, options: .atomic)
        } else if FileManager.default.fileExists(atPath: file.path) {
            try FileManager.default.removeItem(at: file)
        }
    }
}
