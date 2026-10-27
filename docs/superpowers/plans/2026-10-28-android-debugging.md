# Android debugging implementation plan

**Goal:** Agents can drive Android native debugging and Frida tracing through MCP, with the app sharing the same engines.

**Architecture:** Extend the existing LLDB JSON helper for remote Android sessions. Add structured MCP controls and bounded event buffers. Run Frida through its Python bindings in an optional helper, keeping tracing independent of LLDB.

**Scope:** Native libraries/processes; source debugging when symbols exist. Frida traces native exports or addresses with raw argument/return values. No Java debugger, root installation, security-policy changes, arbitrary script console, or application repackaging.

## Tasks

- [x] LLDB remote sessions: add validated ADB/run-as setup, attach by PID and launch a remote executable, module matching, breakpoints, stepping, registers, memory, and detach/cleanup. Keep existing macOS launch behavior. Add failure/validation tests before implementation.
- [x] Agent controls: expose `debug_start`, `debug_state`, `debug_control`, `debug_breakpoint`, `debug_memory` with explicit schemas and per-analysis session ownership. Test a complete MCP debugging sequence on the approved connected device.
- [x] Frida tracing: expose `frida_attach`, `frida_trace`, `frida_events`, `frida_detach`. Resolve native module exports/addresses, cap argument counts and event retention, unload hooks on detach. Test native trace events against a temporary process if device permissions permit.
- [x] App: Android settings and attach/launch controls in the existing Debug sidebar, plus Frida trace controls. Explain missing tools and device permissions; preserve macOS controls/settings.
- [x] Delivery: run the full suite, review the combined change, build/install `/Applications/Disassembler.app`, verify the installed MCP and UI, clean temporary device artifacts, commit and push to `main`.

## Validation and constraints

- Device tests are authorized for temporary native test binaries only; do not attach to unrelated apps.
- ADB forwards bind on loopback; server must not listen publicly. Never root the device or weaken SELinux/ptrace protections.
- Closing an attached session detaches and resumes the target; only explicitly launched test processes may be killed on cleanup.
- Reject unsupported command names, invalid PIDs/ports/ranges, missing binaries and ambiguous device selection before starting work.
- Each MCP status response carries state, monotonically increasing event IDs and dropped-event information; buffers remain bounded.
- Disconnect, failed setup and analysis-session closure must release owned forwards/helpers/hooks without touching unrelated sessions.

## Verification

- `swift test`: 27 tests pass, including local MCP debugging, host/dylib launch, input validation, cursor retention and ambiguous Frida USB rejection.
- Installed build: `./build.sh --install`, signature verification and launch passed.
- Installed MCP on the authorized ARM64 device: launch, symbol/address breakpoints, registers, memory, instruction step, stop, natural-exit cleanup, failed-start cleanup, attach/detach, Frida export/offset hooks, argument/return capture, removal and EOF cleanup passed.
- App smoke: Android breakpoint showed argument 21, source stepping advanced a line, and Frida displayed calls returning 43.
- Temporary device binaries, processes and forwards removed. Direct stdio server registered in Codex as `disassembler`.
- Live coverage is ARM64 with a shell-owned fixture and Frida Gadget. Other ABIs, run-as packages and Frida Server deployment were not live-tested.
