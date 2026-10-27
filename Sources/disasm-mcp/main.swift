import DisasmCore
import Foundation

// MCP over stdio: one JSON-RPC message per line in, one per line out. Nothing else may go to stdout.
let server = ProviderServer()
while let line = readLine(strippingNewline: true) {
    guard let data = line.data(using: .utf8),
          let message = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { continue }
    if let response = server.handle(message), var out = try? JSONSerialization.data(withJSONObject: response) {
        out.append(UInt8(ascii: "\n"))
        FileHandle.standardOutput.write(out)
    }
}
server.shutdown()
