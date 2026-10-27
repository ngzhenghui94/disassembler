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

Open an extracted Android `.so` with ⌘O, drag and drop, or the same terminal command above. Use the Debug sidebar
to attach to its Android process or launch its host executable through ADB. The 32-bit architectures show assembly;
their pseudocode view explains this limitation. APK/AAR/JAR archives and ELF files with section headers removed
are not supported. Stripped internal functions are recovered from direct calls where possible; missing symbols
and ARM/Thumb mapping information can limit recovery. Standard ELF REL/RELA imports are read; Android packed
relocations are not expanded.

The small Android test libraries are built from `Tests/DisasmCoreTests/Fixtures/android.c` and committed so
`swift test` needs no Android toolchain. To regenerate them, run `sh Tests/DisasmCoreTests/Fixtures/build.sh`
with Homebrew `lld` and `llvm` installed. Header parsing follows the [ELF specification](https://gabi.xinuos.com/elf/).

## Android debugging and agent controls

Agents can drive the bundled MCP server directly over stdio. Register this server alongside REA; REA's static
analysis adapter does not expose the live debugging tools:

```json
{"mcpServers":{"disassembler":{"command":"/Applications/Disassembler.app/Contents/MacOS/disasm-mcp","args":[]}}}
```

The same registration is bundled as `Contents/Resources/disassembler-mcp.json`. All runtime tools have explicit
input schemas. `android_targets` discovers devices and process IDs. Open the matching local `.so` with `idb_open`,
then pass its returned `session_id` as `database` to subsequent calls (otherwise the latest analysis is selected).

1. `debug_start`: use `android_attach` with `pid`, or `android_launch` with an absolute `remote_path` to the host
   executable. Supply `server_path` to an Android NDK `lldb-server` matching the target ABI. The default is
   `~/Library/Application Support/Disassembler/Tools/android-<arch>/lldb-server`. ADB is detected from Homebrew or
   the standard Android SDK location; `adb_path` and `device` override it. `package` uses `run-as` for a debuggable app.
2. `debug_state`: poll with `after` set to the last `cursor` and `wait_ms` up to 1000. Stops include registers,
   variables, stack frames and addresses matching static analysis. `pc` in frames is a runtime address;
   `fileAddr` belongs to the opened binary. Initial launch may stop in Android's linker; continue to the breakpoint.
3. `debug_breakpoint`: set/remove symbol or hexadecimal file-address breakpoints. Set the same breakpoint with
   `enabled: false` to disable it. Initial `breakpoints` can be supplied to `debug_start`.
4. `debug_control`: continue, pause, step/next, stepi/nexti, finish, frame, stop or detach. `debug_memory` reads
   a runtime address, register (`$pc`) or LLDB expression. Requests return IDs; poll for matching command/memory/error
   events and new stop events. Acceptance means queued, not completed. `stop` kills only targets launched by this
   session; attached targets are detached and resumed. Closing the analysis or MCP input also cleans up the session.

The app's Debug sidebar uses these same engines. Android requires an authorized ADB connection and permission to
debug the target: a process you own or a debuggable package. The app does not root devices or change security policy.
It copies the process executable locally to let LLDB resolve its loader, deploys a temporary server, binds it to
device loopback and removes its files and port forward on cleanup. Use the same library build as the running target.

Frida adds native function tracing while the process runs. Install matching Frida Python bindings and Frida
Server or Gadget yourself. `python_path` selects the interpreter; the default is
`~/Library/Application Support/Disassembler/Tools/frida/bin/python3`. `frida_attach` takes a PID and optional USB
`device`, or `port` for an existing localhost forward to Server/Gadget. It does not deploy a server or repackage apps.
`frida_events` reports attachment and loaded modules. `frida_trace` adds a hook using `module` plus an exported
`symbol` or hexadecimal `offset` from the loaded module base. Set `argument_count` from 0 to 8 to capture raw values.
Trace events include thread ID, runtime address, arguments and, at function entries, the return value. Hooking the
return of a mid-function address can crash the target, so offsets that are neither exports nor functions in the open
analysis are traced on entry only (`retval: null`) unless `function_start: true` is passed. Misaligned ARM addresses
are rejected; give ARM32 Thumb code with bit 0 set. Traces must be at least 16 bytes apart (or at the same address),
because Frida's patch covers up to 16 bytes and overlapping patches restore corrupted code on detach. Remove a hook
with `action: "remove"` and its `id`; `frida_detach` removes hooks without killing the target. Poll for its completion.
Frida does not provide instruction stepping here; use LLDB for that. Avoid simultaneous LLDB and Frida sessions
on the same process because both can modify function instructions.

Both event logs retain 200 events and report lost history with `dropped`. Frida permits 64 hooks and samples at most
100 calls/second, reporting additional losses as `dropped` events. These are debugging traces, not a lossless profiler.
No Java hooks, arbitrary injected scripts or APK repackaging are included. ARM64 has live device coverage; ARM32
and x86 require their own matching servers and have only static-analysis test coverage here.

An opt-in integration test compiles and deploys temporary native fixtures, checks MCP breakpoints/stepping/memory,
safe detach and optionally Frida tracing, then removes its fixtures. It requires one ARM64 device, Xcode and Homebrew lld:

```sh
swift build --product disasm-mcp
python3 scripts/test-android-runtime.py --server /path/to/android-arm64/lldb-server \
  --gadget /path/to/frida-gadget-android-arm64.so --python /path/to/frida-venv/bin/python3
```

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
