import Foundation

public struct DebugFrame: Sendable, Codable, Hashable {
    public let module: String
    public let function: String
    public let pc: UInt64
    public let fileAddr: UInt64?   // unslid address, set only for frames in the analyzed binary
    public let line: String?       // "File.swift:42" when the frame has debug info
}

public struct DebugVariable: Sendable, Codable, Hashable, Identifiable {
    public let id = UUID()
    public let name: String
    public let type: String
    public let value: String
    public let children: [DebugVariable]?   // one level deep, for structs, classes and pointers

    enum CodingKeys: String, CodingKey { case name, type, value, children }
}

public struct DebugEvent: Sendable, Codable {
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
    public var requestID: String?
    public var command: String?
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
        signal(SIGPIPE, SIG_IGN)   // a write after lldb exits must fail, not kill the host
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

    /// Closing stdin detaches attached targets and stops targets launched by this session.
    public func terminate() {
        try? input.fileHandleForWriting.close()
    }

    static let script = #"""
import sys, os, json, shlex, threading, subprocess, select, time, uuid, re, tempfile
sys.path.insert(0, sys.argv[1])
import lldb

lock = threading.Lock()
def emit(**kw):
    with lock:
        try:
            sys.stdout.write(json.dumps(kw) + "\n")
            sys.stdout.flush()
        except BrokenPipeError:
            pass

dbg = lldb.SBDebugger.Create()
dbg.SetAsync(True)
dbg.SetInputFileHandle(open(os.devnull, "r"), True)
listener = dbg.GetListener()
st = {"target": None, "process": None, "module": None, "uuid": None, "path": None, "owned": False}
remote = {}
remote_lock = threading.RLock()
bps = {}   # our id -> lldb breakpoint id
LANGS = {"objc": lldb.eLanguageTypeObjC, "swift": lldb.eLanguageTypeSwift, "cpp": lldb.eLanguageTypeC_plus_plus}

def file_addr(load):
    a = lldb.SBAddress(load, st["target"])
    m = a.GetModule()
    if m.IsValid() and ((st["uuid"] and m.GetUUIDString() == st["uuid"]) or m == st["module"]):
        return a.GetFileAddress()
    return None

def find_module():
    matches = [m for m in st["target"].modules if (st["uuid"] and m.GetUUIDString() == st["uuid"]) or
               (not st["uuid"] and m.GetFileSpec().GetFilename() == os.path.basename(st["path"]))]
    m = matches[0] if len(matches) == 1 else st["target"].FindModule(lldb.SBFileSpec(st["path"]))
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

def read_memory(p, expr, size, request_id=None):
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
                emit(event="memory", requestID=request_id, message=v.GetError().GetCString() or "Can't evaluate " + expr)
                return
            addr = v.GetValueAsUnsigned()
    err = lldb.SBError()
    data = p.ReadMemory(addr, size, err)
    if err.Fail():
        emit(event="memory", requestID=request_id, addr="0x%x" % addr, message=err.GetCString())
    else:
        emit(event="memory", requestID=request_id, addr="0x%x" % addr, hex=data.hex())

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
        if st["process"] is None or lldb.SBProcess.GetProcessFromEvent(ev).GetUniqueID() != st["process"].GetUniqueID():
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
                cleanup_remote(p.GetUniqueID())
                emit(event="detached" if s == lldb.eStateDetached else "exited", code=p.GetExitStatus(), message=p.GetExitDescription() or "")

threading.Thread(target=events, daemon=True).start()

def new_target(path, arch):
    old = st["process"]
    if old is not None and old.IsValid():
        old.Kill() if st["owned"] else old.Detach()
    cleanup_remote()
    st.update(process=None, module=None, uuid=None)
    bps.clear()
    t = dbg.CreateTargetWithFileAndArch(path, arch) if path else dbg.CreateTarget("")
    if not t.IsValid():
        raise Exception("Can't create a debug target for " + str(path))
    st["target"] = t
    return t

def adb(args, data=None, check=True):
    r = subprocess.run(remote["adb"] + args, input=data, stdin=subprocess.DEVNULL if data is None else None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    if check and r.returncode:
        raise Exception("ADB: " + r.stderr.decode(errors="replace").strip() + " " + r.stdout.decode(errors="replace").strip())
    return r.stdout

def shell(args, data=None, check=True):
    return adb(["shell", shlex.join(remote.get("prefix", []) + args)], data, check)

def cleanup_remote(process_id=None):
    with remote_lock:
        if process_id is not None and remote.get("process") != process_id:
            return
        _cleanup_remote()

def _cleanup_remote():
    if not remote:
        return
    if remote.get("forward"):
        try: adb(["forward", "--remove", remote["forward"]], check=False)
        except Exception: pass
    helper = remote.get("helper")
    if helper is not None:
        helper.terminate()
        try: helper.wait(timeout=3)
        except subprocess.TimeoutExpired: helper.kill()
    if remote.get("dir"):
        try: shell(["rm", "-rf", remote["dir"]], check=False)
        except Exception: pass
    if remote.get("local"):
        remote["local"].cleanup()
    remote.clear()

def android_start(c):
    new_target(None, None)
    st["path"], st["owned"] = c["module"], c["cmd"] == "android_launch"
    remote["adb"] = [c["adb"]]
    device = c.get("device", "")
    devices = [line.split() for line in adb(["devices"]).decode().splitlines()[1:] if line.strip()]
    if not device:
        ready = [row[0] for row in devices if len(row) > 1 and row[1] == "device"]
        if len(ready) != 1: raise Exception("Select exactly one authorized Android device with device=<serial>")
        device = ready[0]
    remote["adb"] += ["-s", device]
    package = c.get("package", "")
    remote["prefix"] = ["run-as", package] if package else []
    # run-as enforces the application's debuggable flag and UID without changing device security.
    if package: shell(["id"])
    remote["dir"] = ("./cache/" if package else "/data/local/tmp/") + "disassembler-" + uuid.uuid4().hex
    shell(["mkdir", "-m", "700", remote["dir"]])
    server = remote["dir"] + "/lldb-server"
    with open(c["server"], "rb") as f:
        shell(["sh", "-c", "cat > " + shlex.quote(server)], f.read())
    shell(["chmod", "700", server])
    args = [server, "gdbserver", "--pipe", "1", "127.0.0.1:0"]
    if st["owned"]:
        args += ["--", c["remote_path"]] + shlex.split(c.get("args", ""))
    else:
        args += ["--attach", str(c["pid"])]
    helper = subprocess.Popen(remote["adb"] + ["shell", shlex.join(remote["prefix"] + args)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    remote["helper"] = helper
    output = b""
    deadline = time.monotonic() + 15
    port = None
    while time.monotonic() < deadline:
        if select.select([helper.stdout], [], [], 0.1)[0]:
            chunk = os.read(helper.stdout.fileno(), 4096)
            if not chunk: break
            output += chunk
            match = re.search(rb"(?:^|\n)([0-9]{1,5})\x00", output)
            if match:
                port = int(match.group(1)); break
        if helper.poll() is not None: break
    if not port:
        raise Exception("Android lldb-server did not start: " + output.decode(errors="replace")[-2000:])
    local_port = int(adb(["forward", "tcp:0", "tcp:%d" % port]).strip())
    remote["forward"] = "tcp:%d" % local_port
    err = lldb.SBError()
    triples = {"arm64": "aarch64-linux-android", "arm": "armv7-linux-androideabi", "x86": "i386-linux-android", "x86_64": "x86_64-linux-android"}
    dbg.SetAsync(False)
    executable = c["remote_path"] if st["owned"] else shell(["readlink", "/proc/%d/exe" % c["pid"]]).decode().strip()
    remote["local"] = tempfile.TemporaryDirectory(prefix="disassembler-android-")
    local_executable = os.path.join(remote["local"].name, os.path.basename(executable))
    with open(local_executable, "wb") as f: f.write(shell(["cat", executable]))
    t = dbg.CreateTarget(local_executable, triples[c["arch"]], "remote-linux", False, err)
    t.GetModuleAtIndex(0).SetPlatformFileSpec(lldb.SBFileSpec(executable))
    t.AddModule(c["module"], triples[c["arch"]], None)
    if err.Fail() or not t.IsValid(): raise Exception("Can't create Android target: " + str(err))
    st["target"] = t
    find_module()
    for spec in c.get("breakpoints", []): set_bp(spec)
    with remote_lock:
        st["process"] = t.ConnectRemote(listener, "connect://127.0.0.1:%d" % local_port, "gdb-remote", err)
        remote["process"] = st["process"].GetUniqueID()
    dbg.SetAsync(True)
    if err.Fail(): raise Exception("Android connection failed: " + str(err))
    find_module()
    state = st["process"].GetState()
    if state == lldb.eStateStopped:
        snapshot()
    elif state in (lldb.eStateExited, lldb.eStateCrashed, lldb.eStateDetached):
        cleanup_remote(st["process"].GetUniqueID())
        emit(event="detached" if state == lldb.eStateDetached else "exited", code=st["process"].GetExitStatus())

def handle(c):
    cmd = c["cmd"]
    p = st["process"]
    if cmd in ("memory", "frame", "step", "next", "stepi", "nexti", "finish") and (p is None or p.GetState() != lldb.eStateStopped):
        raise Exception("This command requires a stopped process")
    if cmd in ("android_launch", "android_attach"):
        try: android_start(c)
        except Exception:
            p = st["process"]
            if p is not None and p.IsValid(): p.Kill() if st["owned"] else p.Detach()
            cleanup_remote()
            dbg.SetAsync(True)
            raise
    elif cmd == "launch":
        st["path"] = c["module"]
        t = new_target(c["path"], c.get("arch"))
        st["owned"] = True
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
        st["owned"] = False
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
        err = p.Continue()
        if err.Fail(): raise Exception(str(err))
    elif cmd == "pause":
        err = p.Stop()
        if err.Fail(): raise Exception(str(err))
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
        if c["index"] >= p.GetSelectedThread().GetNumFrames(): raise Exception("Frame index is out of range")
        p.GetSelectedThread().SetSelectedFrame(c["index"])
        snapshot(selected=c["index"])
    elif cmd == "memory":
        read_memory(p, c["expr"].strip(), c.get("size", 256), c.get("requestID"))
    elif cmd in ("detach", "stop"):
        if cmd == "detach" or not st["owned"]:
            err = p.Detach()
            if err.Fail(): raise Exception(str(err))
            result = "detached"
        else:
            err = p.Kill()
            if err.Fail(): raise Exception(str(err))
            result = "exited"
        cleanup_remote()
        st["process"] = None
        emit(event=result, message="Stopped by client")
    elif cmd == "kill":
        p.Kill()

try:
    for line in sys.stdin:
        c = {}
        try:
            c = json.loads(line)
            handle(c)
            if c.get("requestID"): emit(event="command", command=c["cmd"], requestID=c["requestID"])
        except Exception as e:
            emit(event="error", message=str(e), requestID=c.get("requestID"))
finally:
    p = st["process"]
    if p is not None and p.IsValid():
        p.Kill() if st["owned"] else p.Detach()
    cleanup_remote()

os._exit(0)
"""#
}
