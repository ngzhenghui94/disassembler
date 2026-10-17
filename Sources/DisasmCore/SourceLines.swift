import Foundation

public struct SourceLine: Sendable, Hashable {
    public let file: String   // absolute path as recorded in the debug info
    public let line: Int
}

public enum SourceLines {
    /// Finds debug info for a binary: an adjacent `.dSYM` with the same UUID, or one Spotlight indexed
    /// (Xcode archives, DerivedData). Falls back to the binary itself, whose debug map points at the
    /// `.o` files of a Debug build.
    public static func debugInfo(for exe: URL, bundle: URL?, uuid: UUID?) -> URL {
        guard let uuid else { return exe }
        for candidate in [bundle, exe].compactMap({ $0?.appendingPathExtension("dSYM") })
        where FileManager.default.fileExists(atPath: candidate.path) {
            if let out = try? Analysis.run("/usr/bin/xcrun", ["dwarfdump", "--uuid", candidate.path]), out.contains(uuid.uuidString) {
                return candidate
            }
        }
        if let out = try? Analysis.run("/usr/bin/mdfind", ["com_apple_xcode_dsym_uuids == \(uuid.uuidString)"]),
           let path = out.split(separator: "\n").first {
            return URL(fileURLWithPath: String(path))
        }
        return exe
    }

    /// Maps unslid addresses to file:line using `atos`. Addresses without line info are omitted.
    public static func lookup(_ addresses: [UInt64], debugInfo: URL, arch: String, loadAddress: UInt64) -> [UInt64: SourceLine] {
        guard !addresses.isEmpty else { return [:] }
        let input = FileManager.default.temporaryDirectory.appendingPathComponent("atos-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: input) }
        guard (try? addresses.map { "0x" + String($0, radix: 16) }.joined(separator: "\n")
            .write(to: input, atomically: false, encoding: .utf8)) != nil else { return [:] }
        var args = ["atos", "--fullPath", "-o", debugInfo.path, "-l", "0x" + String(loadAddress, radix: 16), "-f", input.path]
        if !arch.contains(" ") { args += ["-arch", arch] }   // "arm64e #2"-style duplicate slices aren't valid -arch names
        guard let out = try? Analysis.run("/usr/bin/xcrun", args) else { return [:] }
        let lines = out.split(separator: "\n", omittingEmptySubsequences: false)
        var result: [UInt64: SourceLine] = [:]
        for (addr, line) in zip(addresses, lines) {
            // "func (in Module) (/path/file.swift:42)"
            guard line.hasSuffix(")"), let open = line.range(of: " (/", options: .backwards) else { continue }
            let loc = line[line.index(after: open.lowerBound)...].dropFirst().dropLast()
            // Line 0 is compiler-generated code with no source line.
            guard let colon = loc.lastIndex(of: ":"), let n = Int(loc[loc.index(after: colon)...]), n > 0 else { continue }
            result[addr] = SourceLine(file: String(loc[..<colon]), line: n)
        }
        return result
    }
}
