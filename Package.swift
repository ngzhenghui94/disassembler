// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "Disassembler",
    platforms: [.macOS(.v14)],
    targets: [
        .target(name: "DisasmCore"),
        .executableTarget(name: "Disassembler", dependencies: ["DisasmCore"]),
        .executableTarget(name: "disasm-mcp", dependencies: ["DisasmCore"]),
        .testTarget(name: "DisasmCoreTests", dependencies: ["DisasmCore"]),
    ]
)
