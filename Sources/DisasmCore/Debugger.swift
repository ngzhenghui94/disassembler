import Foundation

public struct DebugFrame: Sendable, Decodable, Hashable {
    public let module: String
    public let function: String
    public let pc: UInt64
    public let fileAddr: UInt64?   // unslid address, set only for frames in the analyzed binary
    public let line: String?       // "File.swift:42" when the frame has debug info
}

public struct DebugVariable: Sendable, Decodable, Hashable, Identifiable {
    public let id = UUID()
    public let name: String
    public let type: String
    public let value: String
    public let children: [DebugVariable]?   // one level deep, for structs, classes and pointers

    enum CodingKeys: String, CodingKey { case name, type, value, children }
}

public struct DebugEvent: Sendable, Decodable {
    public let event: String       // running | stopped | exited | output | error | memory
    public var reason: String?
    public var message: String?
    public var text: String?
    public var code: Int?
    public var pc: UInt64?
    public var frames: [DebugFrame]?
    public var selectedFrame: Int?
    public var registers: [[String]]?
    public var variables: [DebugVariable]?
    public var breakpoint: String?   // our id of the breakpoint that was hit
    public var addr: String?         // memory: hex address that was read
    public var hex: String?          // memory: bytes as hex
}

/// What a breakpoint stops on. `id` is stable so the helper can find, toggle and delete it.
public enum BreakpointSpec: Sendable, Hashable, Codable {
    case address(UInt64)     // unslid address in the analyzed binary
    case symbol(String)      // function name, in any loaded image
    case exception(String)   // "objc", "swift" or "cpp"

    public var id: String {
        switch self {
        case .address(let a): "a:\(a)"
        case .symbol(let s): "s:\(s)"
        case .exception(let l): "e:\(l)"
        }
    }

    public func command(enabled: Bool) -> [String: Any] {
        var c: [String: Any] = ["cmd": "bp_set", "id": id, "enabled": enabled]
        switch self {
        case .address(let a): c["kind"] = "address"; c["addr"] = a
        case .symbol(let s): c["kind"] = "symbol"; c["name"] = s
        case .exception(let l): c["kind"] = "exception"; c["lang"] = l
        }
        return c
    }
}

/// Drives LLDB through its Python API (shipped with Xcode) in a helper process, speaking JSON lines.
public final class LLDBSession: @unchecked Sendable {
    private let process = Process()
    private let input = Pipe()
    private let lock = NSLock()
    private var buffer = Data()

    public init(onEvent: @escaping @Sendable (DebugEvent) -> Void) throws {
        let lldbPython = try Analysis.run("/usr/bin/xcrun", ["lldb", "-P"]).trimmingCharacters(in: .whitespacesAndNewlines)
        process.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        process.arguments = ["python3", "-u", "-c", Self.script, lldbPython]
        let out = Pipe()
        process.standardOutput = out
        process.standardError = out   // Python tracebacks surface as console output
        process.standardInput = input
        out.fileHandleForReading.readabilityHandler = { [weak self] h in
            let d = h.availableData
            if d.isEmpty {
                h.readabilityHandler = nil
                onEvent(DebugEvent(event: "exited", message: "Debugger helper exited"))
                return
            }
            self?.consume(d).forEach(onEvent)
        }
        try process.run()
    }

    deinit { terminate() }

    private func consume(_ d: Data) -> [DebugEvent] {
        lock.lock(); defer { lock.unlock() }
        buffer.append(d)
        var events: [DebugEvent] = []
        while let nl = buffer.firstIndex(of: UInt8(ascii: "\n")) {
            let line = buffer[buffer.startIndex..<nl]
            buffer = Data(buffer[buffer.index(after: nl)...])
            if let e = try? JSONDecoder().decode(DebugEvent.self, from: line) {
                events.append(e)
            } else if !line.isEmpty {
                events.append(DebugEvent(event: "output", text: String(decoding: line, as: UTF8.self) + "\n"))
            }
        }
        return events
    }

    public func send(_ command: [String: Any]) {
        guard process.isRunning, var data = try? JSONSerialization.data(withJSONObject: command) else { return }
        data.append(UInt8(ascii: "\n"))
        try? input.fileHandleForWriting.write(contentsOf: data)
    }

    /// Closing stdin makes the helper kill the debuggee and exit.
    public func terminate() {
        try? input.fileHandleForWriting.close()
    }

    static let script = #"""
import sys, os, json, shlex, threading
sys.path.insert(0, sys.argv[1])
import lldb

lock = threading.Lock()
def emit(**kw):
    with lock:
        sys.stdout.write(json.dumps(kw) + "\n")
        sys.stdout.flush()

dbg = lldb.SBDebugger.Create()
dbg.SetAsync(True)
listener = dbg.GetListener()
st = {"target": None, "process": None, "module": None, "uuid": None, "path": None}
bps = {}   # our id -> lldb breakpoint id
LANGS = {"objc": lldb.eLanguageTypeObjC, "swift": lldb.eLanguageTypeSwift, "cpp": lldb.eLanguageTypeC_plus_plus}

def file_addr(load):
    a = lldb.SBAddress(load, st["target"])
    m = a.GetModule()
    if st["uuid"] and m.IsValid() and m.GetUUIDString() == st["uuid"]:
        return a.GetFileAddress()
    return None

def find_module():
    m = st["target"].FindModule(lldb.SBFileSpec(st["path"]))
    if m.IsValid():
        st["module"], st["uuid"] = m, m.GetUUIDString()
        return True
    return False

def set_bp(spec):
    t, bid, kind = st["target"], spec["id"], spec["kind"]
    if bid in bps:
        t.BreakpointDelete(bps.pop(bid))
    if kind == "address":
        if st["module"] is None and not find_module():
            emit(event="error", message="Binary isn't loaded in the debugged process; breakpoint at 0x%x not set" % spec["addr"])
            return
        bp = t.BreakpointCreateBySBAddress(st["module"].ResolveFileAddress(spec["addr"]))
    elif kind == "symbol":
        bp = t.BreakpointCreateByName(spec["name"])
    else:
        bp = t.BreakpointCreateForException(LANGS[spec["lang"]], False, True)
    if not bp.IsValid():
        emit(event="error", message="Couldn't create breakpoint " + bid)
        return
    bp.SetEnabled(spec.get("enabled", True))
    bps[bid] = bp.GetID()

def var_json(v, depth=0):
    value, summary = v.GetValue(), v.GetSummary()
    d = {"name": v.GetName() or "?", "type": v.GetDisplayTypeName() or v.GetTypeName() or "",
         "value": " ".join(s for s in (value, summary) if s) or ""}
    n = v.GetNumChildren()
    if depth == 0 and n:
        d["children"] = [var_json(v.GetChildAtIndex(i), 1) for i in range(min(n, 50))]
    return d

def snapshot(selected=None):
    p = st["process"]
    th = p.GetSelectedThread() if selected is not None else None
    if th is None:
        for t in p:
            if t.GetStopReason() not in (lldb.eStopReasonNone, lldb.eStopReasonInvalid):
                th = t
                break
        th = th or p.GetSelectedThread()
        p.SetSelectedThread(th)
        th.SetSelectedFrame(0)
    frames = []
    for i in range(min(th.GetNumFrames(), 100)):
        f = th.GetFrameAtIndex(i)
        le = f.GetLineEntry()
        frames.append({"module": f.GetModule().GetFileSpec().GetFilename() or "?",
                       "function": f.GetDisplayFunctionName() or f.GetFunctionName() or "?",
                       "pc": f.GetPC(), "fileAddr": file_addr(f.GetPC()),
                       "line": "%s:%d" % (le.GetFileSpec().GetFilename(), le.GetLine()) if le.IsValid() and le.GetLine() else None})
    index = th.GetSelectedFrame().GetFrameID()
    f = th.GetFrameAtIndex(index)
    regs = []
    sets = f.GetRegisters()
    if sets.GetSize() > 0:
        for r in sets.GetValueAtIndex(0):
            regs.append([r.GetName(), r.GetValue() or ""])
    variables = [var_json(v) for v in f.GetVariables(True, True, False, True)]
    hit = None
    if th.GetStopReason() == lldb.eStopReasonBreakpoint:
        lldb_id = th.GetStopReasonDataAtIndex(0)
        hit = next((k for k, v in bps.items() if v == lldb_id), None)
    emit(event="stopped", reason="Thread %d: %s" % (th.GetIndexID(), th.GetStopDescription(256) or "stopped"),
         pc=file_addr(th.GetFrameAtIndex(0).GetPC()), frames=frames, selectedFrame=index,
         registers=regs, variables=variables, breakpoint=hit)

def read_memory(p, expr, size):
    f = p.GetSelectedThread().GetSelectedFrame()
    try:
        addr = int(expr, 0)
    except ValueError:
        reg = f.FindRegister(expr.lstrip("$"))
        if reg.IsValid():
            addr = reg.GetValueAsUnsigned()
        else:
            v = f.EvaluateExpression(expr)
            if v.GetError().Fail():
                emit(event="memory", message=v.GetError().GetCString() or "Can't evaluate " + expr)
                return
            addr = v.GetValueAsUnsigned()
    err = lldb.SBError()
    data = p.ReadMemory(addr, size, err)
    if err.Fail():
        emit(event="memory", addr="0x%x" % addr, message=err.GetCString())
    else:
        emit(event="memory", addr="0x%x" % addr, hex=data.hex())

def drain():
    p = st["process"]
    for get in (p.GetSTDOUT, p.GetSTDERR):
        while True:
            s = get(4096)
            if not s:
                break
            emit(event="output", text=s)

def events():
    ev = lldb.SBEvent()
    while True:
        if not listener.WaitForEvent(1, ev) or not lldb.SBProcess.EventIsProcessEvent(ev):
            continue
        if st["process"] is None:
            continue
        drain()
        if ev.GetType() & lldb.SBProcess.eBroadcastBitStateChanged:
            s = lldb.SBProcess.GetStateFromEvent(ev)
            if s == lldb.eStateStopped and not lldb.SBProcess.GetRestartedFromEvent(ev):
                if st["module"] is None:
                    find_module()
                snapshot()
            elif s == lldb.eStateRunning:
                emit(event="running")
            elif s in (lldb.eStateExited, lldb.eStateCrashed, lldb.eStateDetached):
                p = st["process"]
                emit(event="exited", code=p.GetExitStatus(), message=p.GetExitDescription() or "")

threading.Thread(target=events, daemon=True).start()

def new_target(path, arch):
    old = st["process"]
    if old is not None and old.IsValid():
        old.Kill()
    st.update(process=None, module=None, uuid=None)
    bps.clear()
    t = dbg.CreateTargetWithFileAndArch(path, arch) if path else dbg.CreateTarget("")
    if not t.IsValid():
        raise Exception("Can't create a debug target for " + str(path))
    st["target"] = t
    return t

def handle(c):
    cmd = c["cmd"]
    p = st["process"]
    if cmd == "launch":
        st["path"] = c["module"]
        t = new_target(c["path"], c.get("arch"))
        find_module()
        for spec in c.get("breakpoints", []):
            set_bp(spec)
        info = lldb.SBLaunchInfo(shlex.split(c.get("args", "")))
        info.SetEnvironmentEntries(c.get("env", []), True)
        info.SetWorkingDirectory(os.path.dirname(c["path"]))
        err = lldb.SBError()
        st["process"] = t.Launch(info, err)
        if err.Fail():
            emit(event="exited", code=-1, message="Launch failed: " + err.GetCString())
    elif cmd == "attach":
        st["path"] = c["module"]
        t = new_target(None, None)
        err = lldb.SBError()
        st["process"] = t.AttachToProcessWithID(listener, c["pid"], err)
        if err.Fail():
            emit(event="exited", code=-1, message="Attach failed: " + err.GetCString())
            return
        find_module()
        for spec in c.get("breakpoints", []):
            set_bp(spec)
    elif cmd == "bp_set" and st["target"] is not None:
        set_bp(c)
    elif cmd == "bp_remove" and c["id"] in bps:
        st["target"].BreakpointDelete(bps.pop(c["id"]))
    elif cmd == "bp_enable" and c["id"] in bps:
        st["target"].FindBreakpointByID(bps[c["id"]]).SetEnabled(c["enabled"])
    elif p is None:
        if cmd not in ("bp_set", "bp_remove", "bp_enable"):
            emit(event="error", message="No process")
    elif cmd == "continue":
        p.Continue()
    elif cmd == "pause":
        p.Stop()
    elif cmd in ("stepi", "nexti"):
        p.GetSelectedThread().StepInstruction(cmd == "nexti")
    elif cmd in ("next", "step"):
        th = p.GetSelectedThread()
        if th.GetFrameAtIndex(0).GetLineEntry().IsValid():
            th.StepOver() if cmd == "next" else th.StepInto()
        else:
            th.StepInstruction(cmd == "next")   # no line info here: step one instruction
    elif cmd == "finish":
        th = p.GetSelectedThread()
        th.StepOutOfFrame(th.GetSelectedFrame())
    elif cmd == "frame":
        p.GetSelectedThread().SetSelectedFrame(c["index"])
        snapshot(selected=c["index"])
    elif cmd == "memory":
        read_memory(p, c["expr"].strip(), c.get("size", 256))
    elif cmd == "kill":
        p.Kill()

for line in sys.stdin:
    try:
        handle(json.loads(line))
    except Exception as e:
        emit(event="error", message=str(e))

p = st["process"]
if p is not None and p.IsValid():
    p.Kill()
os._exit(0)
"""#
}
