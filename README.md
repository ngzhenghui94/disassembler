# Disassembler

A Hopper-style macOS app for reading and debugging your own Mach-O apps.

- **Disassembly** of arm64/x86_64 Mach-O files, fat binaries and `.app` bundles (including their frameworks and plugins)
- **Procedures, imports, strings and cross-references**, with ADRP/selector/GOT references resolved
- **Source lines** next to the assembly, from a `.dSYM` or a Debug build's debug map
- **Crash reports**: open a `.ips` file and jump from each frame to the faulting instruction
- **Live debugging** through LLDB: breakpoints, stepping, registers, backtrace and program output

## Requirements

macOS 14+ with Xcode (or the Command Line Tools) installed. Instruction decoding uses the system `otool`,
source lines use `atos`, and debugging uses LLDB's Python API.

## Build

```sh
./build.sh            # builds build/Disassembler.app
./build.sh --install  # also replaces /Applications/Disassembler.app
swift test            # parser, crash report, source line and LLDB tests
```

Open a binary from the app (⌘O), by dropping a file on the window, or from a terminal:

```sh
open -a Disassembler --args /path/to/YourApp.app [/path/to/crash.ips]
```

Debugging works for apps you build yourself; macOS doesn't allow attaching to hardened or system apps.
