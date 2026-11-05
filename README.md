# Disassembler

A Hopper-style macOS app for reading Mach-O apps, Android native libraries and Windows x86-64 binaries, with local debugging for macOS apps.

- **Disassembly** of arm64/x86_64 Mach-O files, fat binaries and `.app` bundles (including their frameworks and plugins)
- **Android `.so` libraries**: ELF assembly, procedures, imports, strings and sections for ARM64, ARMv7/Thumb,
  x86_64 and x86, including stripped libraries. ARM64/x86_64 also support pseudocode and string cross-references.
- **Windows `.exe` and `.dll` files**: PE32+ x86-64 assembly, exports, imports, strings, cross-references and pseudocode using the Windows calling convention
- **Editable function signatures**: integer/pointer parameter types and names, return types and exact argument counts, saved for the binary and applied to callers
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

### 1.1.0

Adds Windows x86-64 PE analysis and persistent typed signatures for procedures and imports.
Also hardens malformed Mach-O handling, prevents stale document loads, and fixes LLDB startup-event
ordering and incorrect SIMD zero recovery. See the format and signature limitations below.

## Requirements

macOS 14+ with Xcode (or the Command Line Tools) installed. Instruction decoding uses the system `otool` for Mach-O
and `xcrun llvm-objdump` for ELF and PE (no Android or Windows SDK is required for analysis),
source lines use `atos`, and debugging uses LLDB's Python API.

## Build

```sh
./build.sh            # builds build/Disassembler.app
./build.sh --install  # also replaces /Applications/Disassembler.app
swift test            # binary bounds, analysis, document reload, crash/source and LLDB tests
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

## Windows binaries

Open a linked x86-64 PE32+ `.exe` or `.dll` with ⌘O or drag and drop. Analysis uses the preferred image-base
addresses, normal imports and their IAT slots, exports, exception-table function starts and direct calls.
Pseudocode uses Windows x64 argument registers and skips the 32-byte shadow space when recovering stack arguments.
ASCII byte strings and ASCII text encoded as UTF-16LE are listed. Parsing validates file-backed RVA ranges;
zero-filled sections are not mistaken for bytes in the file.

This is static analysis, not Windows execution: Run/Attach are disabled for PE files. PE32/x86, ARM/ARM64 PE
and COFF object files are unsupported. PDB types/source, managed .NET IL, delay imports, TLS callback discovery,
resources and relocation application are not implemented. Forwarded exports have no local code address and
are not listed as local functions. Function ends remain inferred. Packed binaries and indirect control flow
can limit recovery; a directory spanning multiple mappings or a bound IAT without a lookup table is rejected.

## Editing types and signatures

Select a procedure and click **Edit Signature…**, or select an imported function in **Imports** and use the same
button in its references view. Set the return type and add parameters in calling order. **Save** updates the
definition and callers, including argument counts, typed casts and void-return behavior. **Use Inferred Signature**
removes the override. Unknown imports often need an explicit signature to recover pass-through arguments correctly.
These declarations are analyst input, not verified source types; a wrong declaration can make pseudocode misleading.

Supported types are `void` (return only), signed/unsigned 8-, 16-, 32- and 64-bit integers, and `void *`.
Editable parameters must fit the ABI's argument registers: eight on ARM64, six on SysV x86-64, four on Windows x64.
Floating-point, structs, custom typedefs, variadic declarations and editable stack parameters are rejected/not offered.
Parameter names must be unique C identifiers and cannot collide with symbols or reserved decompiler names.

Overrides are atomic JSON files under `~/Library/Application Support/Disassembler/Signatures/`, keyed by the
SHA-256 of the exact architecture slice. The input binary is never changed. Moving an identical binary retains
its overrides; rebuilding it starts a separate set. UI and MCP share storage. MCP reloads overrides before
decompiling; reopen the binary in an already-open UI window to pick up external edits.

The MCP `function_signature` tool takes a function entry or import address and `action: "get"`, `"set"` or `"reset"`.
For example, pass these tool arguments (use the address from the current analysis):

```json
{
  "database": "your-session-id",
  "addr": "0x140001000",
  "action": "set",
  "signature": {
    "returnType": "int32",
    "parameters": [{"name": "count", "type": "int32"}]
  }
}
```

MCP type names are `void`, `int8`, `uint8`, `int16`, `uint16`, `int32`, `uint32`, `int64`, `uint64`, `pointer`.
Omit `signature` for `get`/`reset`. Signature changes invalidate cached pseudocode for all callers in the session.


## Input validation and loading

Mach-O parsing checks universal-binary tables, load-command boundaries, segment/section ranges,
symbol strings, function-start deltas and chained-fixup payloads before using them. Empty architecture
lists, truncated records and overflowing addresses return errors in both the app and MCP server.
A failed MCP open leaves existing analysis sessions intact.

Chained imports support formats 1–3 and pointer formats 1, 2, 6, 9 and 12. Unsupported nonempty
encodings, compressed symbol tables and multi-start pages return explicit errors rather than silently
omitting bindings. Chained rebasing remains heuristic.

Opening or reloading a binary invalidates earlier analysis and source lookups and clears cached source
text, so a failed open cannot be replaced by a previous file's delayed result. LLDB command handling and
event processing are synchronized so startup breakpoint events wait until the process is registered.

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
- Mach-O (arm64 slice preferred on Apple silicon), Android ELF `.so` libraries and Windows x86-64 PE32+ executables/DLLs.
  Select `provider_id: "ida"` explicitly for ELF or PE targets.
