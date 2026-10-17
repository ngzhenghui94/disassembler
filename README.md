# Disassembler

A Hopper-style macOS app for reading and debugging your own Mach-O apps.

- **Disassembly** of arm64/x86_64 Mach-O files, fat binaries and `.app` bundles (including their frameworks and plugins)
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

macOS 14+ with Xcode (or the Command Line Tools) installed. Instruction decoding uses the system `otool`,
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
- Mach-O only (arm64 slice preferred on Apple silicon). Use another REA provider for ELF or PE files.
