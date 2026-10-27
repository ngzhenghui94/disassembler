import Foundation

/// Optional Frida Python bindings keep instrumentation out of the app process.
public final class FridaSession: @unchecked Sendable {
    let events = RuntimeEvents()
    private let process = Process()
    private let input = Pipe()
    private let lock = NSLock()
    private var buffer = Data()

    public static var defaultPython: String {
        NSHomeDirectory() + "/Library/Application Support/Disassembler/Tools/frida/bin/python3"
    }

    public init(options: [String: Any]) throws {
        let pid = try DebugController.integer(options["pid"], name: "pid", range: 1...Int(Int32.max))
        let python = options["python_path"] as? String ?? Self.defaultPython
        guard python.hasPrefix("/"), FileManager.default.isExecutableFile(atPath: python) else {
            throw MachOError(message: "Set python_path to a Python interpreter with the frida package installed")
        }
        let device = options["device"] as? String ?? ""
        let port = try options["port"].map { try DebugController.integer($0, name: "port", range: 1...65535) }
        guard device.count <= 256, !device.contains("\0") else { throw MachOError(message: "Invalid Frida device ID") }
        process.executableURL = URL(fileURLWithPath: python)
        process.arguments = ["-u", "-c", Self.script]
        let out = Pipe()
        process.standardInput = input
        process.standardOutput = out
        process.standardError = out
        let log = events
        out.fileHandleForReading.readabilityHandler = { [weak self] h in
            let data = h.availableData
            if data.isEmpty { h.readabilityHandler = nil; log.append(["event": "detached"]); return }
            self?.consume(data)
        }
        signal(SIGPIPE, SIG_IGN)   // a write after Python exits must fail, not kill the host
        try process.run()
        var command: [String: Any] = ["cmd": "attach", "pid": pid, "device": device]
        if let port { command["port"] = port }
        send(command)
    }

    deinit { terminate() }
    public func terminate() { try? input.fileHandleForWriting.close() }
    public func detach() -> [String: Any] {
        let request = UUID().uuidString
        send(["cmd": "detach", "requestID": request])
        return ["accepted": true, "request_id": request]
    }
    public func status(after: Int? = nil, waitMS: Int = 0) -> [String: Any] { events.read(after: after, waitMS: waitMS) }

    private func consume(_ data: Data) {
        lock.lock(); defer { lock.unlock() }
        buffer.append(data)
        while let nl = buffer.firstIndex(of: 10) {
            let line = buffer[..<nl]
            if let event = try? JSONSerialization.jsonObject(with: line) as? [String: Any] { events.append(event) }
            else { events.append(["event": "error", "message": String(decoding: line, as: UTF8.self)]) }
            buffer.removeSubrange(...nl)
        }
    }

    private func send(_ command: [String: Any]) {
        guard var data = try? JSONSerialization.data(withJSONObject: command) else { return }
        data.append(10)
        try? input.fileHandleForWriting.write(contentsOf: data)
    }

    public func trace(_ a: [String: Any]) throws -> [String: Any] {
        var command = try Self.traceCommand(a)
        let request = UUID().uuidString
        command["requestID"] = request
        send(command)
        return ["accepted": true, "request_id": request, "id": command["id"]!]
    }

    static func traceCommand(_ a: [String: Any]) throws -> [String: Any] {
        let action = a["action"] as? String ?? "add"
        if action == "remove" {
            guard let id = a["id"] as? String, !id.isEmpty, id.count <= 256 else { throw MachOError(message: "Trace id is required") }
            return ["cmd": "remove", "id": id]
        }
        guard action == "add", let module = a["module"] as? String, !module.isEmpty, module.count <= 4096 else {
            throw MachOError(message: "Trace action must be add/remove; add requires a loaded module name")
        }
        let count = try DebugController.integer(a["argument_count"] ?? 4, name: "argument_count", range: 0...8)
        var c: [String: Any] = ["cmd": "add", "id": UUID().uuidString, "module": module, "count": count,
                                "function_start": a["function_start"] as? Bool ?? false]
        if let symbol = a["symbol"] as? String, !symbol.isEmpty, symbol.count <= 4096, a["offset"] == nil {
            c["symbol"] = symbol
        } else if let offset = a["offset"] as? String, a["symbol"] == nil,
                  let n = UInt64(offset.hasPrefix("0x") ? String(offset.dropFirst(2)) : offset, radix: 16) {
            c["offset"] = String(n, radix: 16)
        } else { throw MachOError(message: "Provide either an exported symbol or a hexadecimal offset from the loaded module base") }
        return c
    }

    static let script = #"""
import sys, json, threading
lock = threading.Lock()
def emit(**event):
    with lock:
        try: print(json.dumps(event), flush=True)
        except BrokenPipeError: pass
try:
    import frida
except ImportError:
    emit(event="error", message="Frida Python bindings missing; install frida in the selected Python environment")
    sys.exit(1)

source = r'''
const hooks = new Map();
let budget = 100, lost = 0;
setInterval(() => { if (lost) send({event:'dropped', count:lost}); lost=0; budget=100; }, 1000);
rpc.exports = {
  modules() { return Process.enumerateModules().map(m => ({name:m.name, path:m.path, base:m.base.toString(), size:m.size})); },
  add(c) {
    if (hooks.size >= 64) throw new Error('Maximum 64 active traces');
    const m = Process.getModuleByName(c.module);
    if (!c.symbol && uint64('0x'+c.offset).compare(uint64(m.size)) >= 0) throw new Error('Offset is outside the module');
    const address = c.symbol ? m.getExportByName(c.symbol) : m.base.add(ptr('0x'+c.offset));
    const code = Process.findRangeByAddress(address.and(Process.arch === 'arm' ? ptr('0xfffffffe') : ptr('0xffffffffffffffff')));
    if (!code || !code.protection.includes('x')) throw new Error('Trace address is not executable');
    if (!c.symbol && (address.compare(m.base) < 0 || address.compare(m.base.add(m.size)) >= 0)) throw new Error('Offset is outside the module');
    // Patching mid-instruction corrupts the target's code.
    const bits = address.and(3).toInt32();
    if ((Process.arch === 'arm64' && bits) || (Process.arch === 'arm' && bits === 2)) throw new Error('Trace address is not instruction-aligned' + (Process.arch === 'arm' ? '; set bit 0 for Thumb code' : ''));
    // Frida patches up to 16 bytes; a second hook inside that patch restores corrupted code on detach.
    const code0 = address.and(ptr('0xfffffffffffffffe'));
    for (const [id, h] of hooks) {
      const other = h.address.and(ptr('0xfffffffffffffffe'));
      const near = code0.compare(other) > 0 ? code0.sub(other) : other.sub(code0);
      if (!code0.equals(other) && near.compare(ptr(16)) < 0) throw new Error('Trace address is within 16 bytes of trace ' + id + '; remove it first');
    }
    // onLeave rewrites the return address, which corrupts control flow unless this is a function entry.
    const entry = c.symbol || c.function_start || m.enumerateExports().some(e => e.address.equals(address));
    const record = (ctx, args) => {
      if (budget <= 0) { lost++; return false; }
      budget--;
      ctx.args = Array.from({length:c.count}, (_, i) => args[i].toString());
      ctx.started = Date.now();
      return true;
    };
    const hook = entry ? Interceptor.attach(address, {
      onEnter(args) { this.record = record(this, args); },
      onLeave(retval) {
        if (this.record) send({event:'trace', id:c.id, thread:this.threadId, address:address.toString(), args:this.args, retval:retval.toString(), time:this.started});
      }
    }) : Interceptor.attach(address, function (args) {
      if (record(this, args)) send({event:'trace', id:c.id, thread:this.threadId, address:address.toString(), args:this.args, retval:null, time:this.started});
    });
    hooks.set(c.id, {hook, address});
    return {id:c.id, address:address.toString(), retval:!!entry};
  },
  remove(id) { if (!hooks.has(id)) throw new Error('Unknown trace id'); hooks.get(id).hook.detach(); hooks.delete(id); }
};
'''
session = script = None
def message(m, data):
    if m['type'] == 'send': emit(**m['payload'])
    elif m['type'] == 'error': emit(event='error', message=m.get('description', str(m)))
def detach():
    global session, script
    if script:
        try: script.unload()
        except Exception: pass
        script = None
    if session:
        try: session.detach()
        except Exception: pass
        session = None
try:
    for line in sys.stdin:
        c = {}
        try:
            c = json.loads(line)
            if c['cmd'] == 'attach':
                manager = frida.get_device_manager()
                if c.get('port'):
                    device = manager.add_remote_device('127.0.0.1:%d' % c['port'])
                elif c['device']:
                    device = frida.get_device(c['device'], timeout=5)
                else:
                    devices = [d for d in manager.enumerate_devices() if d.type == 'usb']
                    if len(devices) != 1: raise Exception('Select exactly one connected USB Frida device with device=<id>, or supply a localhost port')
                    device = devices[0]
                session = device.attach(c['pid'])
                session.on('detached', lambda reason, crash=None: emit(event='detached', reason=reason))
                script = session.create_script(source)
                script.on('message', message)
                script.load()
                emit(event='attached', pid=c['pid'], modules=script.exports_sync.modules())
            elif c['cmd'] == 'add':
                if script is None: raise Exception('Frida is not attached; await attached, or detach and retry')
                result = script.exports_sync.add(c)
                emit(event='hook', requestID=c['requestID'], **result)
            elif c['cmd'] == 'remove':
                if script is None: raise Exception('Frida is not attached; await attached, or detach and retry')
                script.exports_sync.remove(c['id'])
                emit(event='removed', id=c['id'], requestID=c['requestID'])
            elif c['cmd'] == 'detach':
                detach()
                emit(event='detached', requestID=c['requestID'])
        except Exception as e:
            emit(event='error', message=str(e), requestID=c.get('requestID'))
finally:
    detach()
"""#
}
