import Foundation

public struct DebugFrame: Sendable, Decodable, Hashable {
    public let module: String
    public let function: String
    public let pc: UInt64
    public let fileAddr: UInt64?   // unslid address, set only for frames in the analyzed binary
}

public struct DebugEvent: Sendable, Decodable {
    public let event: String       // running | stopped | exited | output | error
    public var reason: String?
    public var message: String?
    public var text: String?
    public var code: Int?
    public var pc: UInt64?
    public var frames: [DebugFrame]?
    public var registers: [[String]]?
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
import sys, os, json, threading
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
bps = {}

def file_addr(load):
    a = lldb.SBAddress(load, st["target"])
    m = a.GetModule()
    if st["uuid"] and m.IsValid() and m.GetUUIDString() == st["uuid"]:
        return a.GetFileAddress()
    return None

def find_module():
    t = st["target"]
    m = t.FindModule(lldb.SBFileSpec(st["path"]))
    if m.IsValid():
        st["module"], st["uuid"] = m, m.GetUUIDString()
        return True
    return False

def set_bp(addr):
    if addr in bps:
        return
    if st["module"] is None and not find_module():
        emit(event="error", message="Binary isn't loaded in the debugged process, breakpoint at 0x%x not set" % addr)
        return
    bp = st["target"].BreakpointCreateBySBAddress(st["module"].ResolveFileAddress(addr))
    bps[addr] = bp.GetID()

def snapshot():
    p = st["process"]
    th = None
    for t in p:
        if t.GetStopReason() not in (lldb.eStopReasonNone, lldb.eStopReasonInvalid):
            th = t
            break
    th = th or p.GetSelectedThread()
    p.SetSelectedThread(th)
    frames = []
    for i in range(min(th.GetNumFrames(), 100)):
        f = th.GetFrameAtIndex(i)
        frames.append({"module": f.GetModule().GetFileSpec().GetFilename() or "?",
                       "function": f.GetDisplayFunctionName() or f.GetFunctionName() or "?",
                       "pc": f.GetPC(), "fileAddr": file_addr(f.GetPC())})
    regs = []
    f0 = th.GetFrameAtIndex(0)
    sets = f0.GetRegisters()
    if sets.GetSize() > 0:
        for r in sets.GetValueAtIndex(0):
            regs.append([r.GetName(), r.GetValue() or ""])
    emit(event="stopped", reason="Thread %d: %s" % (th.GetIndexID(), th.GetStopDescription(256) or "stopped"),
         pc=file_addr(f0.GetPC()), frames=frames, registers=regs)

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
        for a in c.get("breakpoints", []):
            set_bp(a)
        info = lldb.SBLaunchInfo(c.get("args", []))
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
        for a in c.get("breakpoints", []):
            set_bp(a)
    elif cmd == "break" and st["target"] is not None:
        set_bp(c["addr"])
    elif cmd == "unbreak" and c["addr"] in bps:
        st["target"].BreakpointDelete(bps.pop(c["addr"]))
    elif p is None:
        emit(event="error", message="No process")
    elif cmd == "continue":
        p.Continue()
    elif cmd == "pause":
        p.Stop()
    elif cmd in ("stepi", "nexti"):
        p.GetSelectedThread().StepInstruction(cmd == "nexti")
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
