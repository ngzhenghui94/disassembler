import Foundation

public enum HexDump {
    /// "0aff10" -> [0x0a, 0xff, 0x10]; nil for odd-length or non-hex input.
    public static func bytes(fromHex hex: String) -> [UInt8]? {
        guard hex.count.isMultiple(of: 2) else { return nil }
        var result: [UInt8] = []
        result.reserveCapacity(hex.count / 2)
        var i = hex.startIndex
        while i < hex.endIndex {
            let next = hex.index(i, offsetBy: 2)
            guard let b = UInt8(hex[i..<next], radix: 16) else { return nil }
            result.append(b)
            i = next
        }
        return result
    }

    /// Classic hex dump: address, 16 bytes, printable ASCII.
    public static func format(_ base: UInt64, _ bytes: [UInt8]) -> String {
        stride(from: 0, to: bytes.count, by: 16).map { off in
            let row = bytes[off..<min(off + 16, bytes.count)]
            let hexPart = row.map { String(format: "%02x", $0) }.joined(separator: " ")
            let ascii = String(row.map { (0x20..<0x7f).contains($0) ? Character(UnicodeScalar($0)) : "." })
            return String(format: "%016llx  ", base &+ UInt64(off)) + hexPart.padding(toLength: 47, withPad: " ", startingAt: 0) + "  " + ascii
        }.joined(separator: "\n")
    }
}
