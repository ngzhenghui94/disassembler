# Disassembler

A Hopper-style macOS app for reading Mach-O apps and Android native libraries, with local debugging for macOS apps.

- **Disassembly** of arm64/x86_64 Mach-O files, fat binaries and `.app` bundles (including their frameworks and plugins)
- **Android `.so` libraries**: ELF assembly, procedures, imports, strings and sections for ARM64, ARMv7/Thumb,
  x86_64 and x86, including stripped libraries. ARM64/x86_64 also support pseudocode and string cross-references.
- **Procedures, imports, strings and cross-references**, with ADRP/selector/GOT references resolved
- **Decompiler**: pseudo-C for any procedure (⌥↩), with recovered `if`/`else`, loops, `switch` statements
  from jump tables, call arguments (from known C/runtime signatures and each callee's own parameters),
  string/CFString literals, imported symbols and Obj-C message sends written as `[receiver selector:arg]`
- **Source lines** next to the assembly, from a `.dSYM` or a Debug build's debug map
- **Crash reports**: open a `.ips` file and jump from each frame to the faulting instruction
- **Live debugging** through LLDB:
  - breakpoints on instructions, function names, and thrown Obj-C exceptions / Swift errors / C++ exceptions
  - step by source line (F6/F7/F8) or by instruction (⌃F6/⌃F7), with a selectable call stack
  - local variables, registers (changes highlighted) and a memory viewer that takes addresses, registers or expressions
  - per-app launch arguments, environment variables and presets such as Zombie Objects and Malloc Scribble

## Download

Get the notarized build from [Releases](https://github.com/ngzhenghui94/disassembler/releases/latest), unzip it and
move **Disassembler.app** to /Applications.

## Requirements

macOS 14+ with Xcode (or the Command Line Tools) installed. Instruction decoding uses the system `otool` for Mach-O
and `xcrun llvm-objdump` for ELF (no Android SDK is required),
source lines use `atos`, and debugging uses LLDB's Python API.

## Build

```sh
./build.sh            # builds build/Disassembler.app
./build.sh --install  # also replaces /Applications/Disassembler.app
swift test            # parser, crash report, source line, hex dump and LLDB tests
scripts/release.sh    # Developer ID sign, notarize, staple, zip; add --publish for a GitHub release
```

Open a binary from the app (⌘O), by dropping a file on the window, or from a terminal:

```sh
open -a Disassembler --args /path/to/YourApp.app [/path/to/crash.ips]
```

Debugging works for apps you build yourself; macOS doesn't allow attaching to hardened or system apps.

Open an extracted Android `.so` with ⌘O, drag and drop, or the same terminal command above. Android files use
static analysis: Run/Attach and macOS source-line lookup are unavailable. The 32-bit architectures show assembly;
their pseudocode view explains this limitation. APK/AAR/JAR archives and ELF files with section headers removed
are not supported. Stripped internal functions are recovered from direct calls where possible; missing symbols
and ARM/Thumb mapping information can limit recovery. Standard ELF REL/RELA imports are read; Android packed
relocations are not expanded.

The small Android test libraries are built from `Tests/DisasmCoreTests/Fixtures/android.c` and committed so
`swift test` needs no Android toolchain. To regenerate them, run `sh Tests/DisasmCoreTests/Fixtures/build.sh`
with Homebrew `lld` and `llvm` installed. Header parsing follows the [ELF specification](https://gabi.xinuos.com/elf/).

## Using it from REA (reverse-engineer-anything)

The app bundles `disasm-mcp`, an MCP server that speaks the headless profile of
[REA](https://github.com/morluto/rea)'s IDA provider, backed by this disassembler's engine. Point REA at the
bundled registration and its native tools (`open_binary`, `analyze_function`, `procedure_assembly`, `xrefs`,
string and procedure search, …) run on it:

```sh
claude mcp add-json rea '{"command":"npx","args":["-y","rea-agents@6.4.0","mcp"],
  "env":{"REA_IDA_MCP_CONFIG":"/Applications/Disassembler.app/Contents/Resources/rea-ida-mcp.json"}}' -s user
```

REA selects it automatically for Mach-O targets, or explicitly with `provider_id: "ida"` (CLI: `--provider ida`).
What to expect:

- Results are labelled with REA's "IDA Pro MCP adapter" identity because they flow through that adapter;
  the MCP `serverInfo` in each Evidence record says `disassembler-mcp`.
- `procedure_pseudo_code` returns the built-in decompiler's pseudo-C. When the build has debug info, the
  function's original source lines follow it as a commented trailer.
- REA's headless profile doesn't offer direct callers; use `xrefs` on the function address instead.
- Mach-O (arm64 slice preferred on Apple silicon) and Android ELF `.so` libraries. Select `provider_id: "ida"`
  explicitly for ELF targets. PE files are not supported.
