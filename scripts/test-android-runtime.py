#!/usr/bin/env python3
"""Opt-in device test. Deploys only temporary native fixtures, then removes them."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import time
import uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--mcp', default='.build/debug/disasm-mcp')
parser.add_argument('--server', required=True, help='Android ARM64 lldb-server on this Mac')
parser.add_argument('--gadget', help='Optional official ARM64 Frida Gadget .so')
parser.add_argument('--python', help='Python with matching Frida bindings')
a = parser.parse_args()
repo = Path(__file__).resolve().parent.parent

def run(args):
    return subprocess.check_output(args, stderr=subprocess.STDOUT, text=True, timeout=30).strip()

rows = [r.split() for r in run(['adb', 'devices']).splitlines()[1:] if r.strip()]
ready = [r[0] for r in rows if len(r) > 1 and r[1] == 'device']
assert len(ready) == 1, 'Connect exactly one authorized device'
adb = ['adb', '-s', ready[0]]
assert run(adb + ['shell', 'getprop ro.product.cpu.abi']) == 'arm64-v8a'
remote = '/data/local/tmp/disasm-test-' + uuid.uuid4().hex
server_dirs = run(adb + ['shell', 'find /data/local/tmp -maxdepth 1 -type d -name \"disassembler-*\"'])
p = subprocess.Popen([a.mcp], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
sequence = 0

def call(name, **args):
    global sequence
    sequence += 1
    p.stdin.write(json.dumps(dict(id=sequence, method='tools/call', params=dict(name=name, arguments=args))) + '\n')
    p.stdin.flush()
    result = json.loads(p.stdout.readline())['result']
    assert not result.get('isError'), result
    return result['structuredContent']['result']

def wait(tool, predicate, after=0):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        state = call(tool, after=after, wait_ms=500)
        assert not state['last_error'], state['last_error']
        if predicate(state):
            return state
        after = state['cursor']
    raise AssertionError('Timed out: ' + str(state))

def event(state, name, request=None):
    return next((e['event'] for e in state['events'] if e['event']['event'] == name
                 and (request is None or e['event'].get('requestID') == request)), None)

def control(action):
    cursor = call('debug_state')['cursor']
    reply = call('debug_control', action=action)
    return cursor, reply['request_id']

owned_pids = []
forward = None

def launch(preload=False):
    command = (f'LD_PRELOAD={remote}/libfrida-gadget.so ' if preload else '') + f'{remote}/live-host > {remote}/output 2>&1 & echo $!'
    pid = int(run(adb + ['shell', command]))
    owned_pids.append(pid)
    return pid

try:
    with tempfile.TemporaryDirectory(prefix='disasm-device-test-') as tmp:
        tmp = Path(tmp)
        base = ['xcrun', 'clang', '--target=aarch64-linux-android21', '-fuse-ld=/opt/homebrew/opt/lld/bin/ld.lld',
                '-nostdlib', '-fPIC', '-fno-stack-protector', '-g', '-O0', '-Wl,--build-id=sha1']
        fixture = repo / 'Tests/DisasmCoreTests/Fixtures'
        run(base + ['-shared', '-Wl,-soname,libdisasm-live.so', str(fixture / 'live-library.c'), '-o', str(tmp / 'libdisasm-live.so')])
        run(base + ['-pie', str(fixture / 'live-host.c'), '-L' + str(tmp), '-ldisasm-live', '-Wl,-rpath,$ORIGIN',
                    '-Wl,-e,_start', '-Wl,--dynamic-linker=/system/bin/linker64', '-o', str(tmp / 'live-host')])
        short_source = tmp / 'short-host.c'
        short_source.write_text((fixture / 'live-host.c').read_text().replace('i < 3000', 'i < 5'))
        run(base + ['-pie', str(short_source), '-L' + str(tmp), '-ldisasm-live', '-Wl,-rpath,$ORIGIN',
                    '-Wl,-e,_start', '-Wl,--dynamic-linker=/system/bin/linker64', '-o', str(tmp / 'short-host')])
        run(adb + ['shell', 'mkdir -m 700 ' + remote])
        for name in ['libdisasm-live.so', 'live-host', 'short-host']:
            run(adb + ['push', str(tmp / name), remote + '/' + name])
        run(adb + ['shell', 'chmod 700 ' + remote + '/live-host ' + remote + '/short-host'])
        targets = call('android_targets')
        assert len(targets['devices']) >= 1 and targets['processes']
        call('idb_open', input_path=str(tmp / 'libdisasm-live.so'))
        call('debug_start', mode='android_launch', remote_path=remote + '/live-host', server_path=os.path.abspath(a.server),
             breakpoints=[dict(kind='symbol', name='debug_helper')])
        first = wait('debug_state', lambda s: s['state'] == 'stopped')
        cursor, _ = control('continue')
        stopped = wait('debug_state', lambda s: (event(s, 'stopped') or {}).get('breakpoint') == 's:debug_helper', cursor)
        snapshot = stopped['snapshot']
        assert snapshot['frames'][0]['module'] == 'libdisasm-live.so'
        assert snapshot['pc'] == snapshot['frames'][0]['fileAddr']
        assert dict(snapshot['registers'])['x0'].endswith('0015')
        memory = call('debug_memory', expression='$pc', size=16)
        state = wait('debug_state', lambda s: event(s, 'memory', memory['request_id']), stopped['cursor'])
        assert len(event(state, 'memory', memory['request_id'])['hex']) == 32
        cursor, _ = control('stepi')
        stepped = wait('debug_state', lambda s: event(s, 'stopped'), cursor)
        assert stepped['snapshot']['pc'] != snapshot['pc']
        call('debug_breakpoint', action='set', kind='address', address=hex(snapshot['pc']), enabled=False)
        call('debug_breakpoint', action='remove', id='a:' + str(snapshot['pc']))
        cursor, _ = control('stop')
        wait('debug_state', lambda s: s['state'] == 'exited', cursor)
        print('PASS Android MCP launch, symbol/address breakpoints, registers, memory, instruction step, stop', flush=True)

        call('debug_start', mode='android_launch', remote_path=remote + '/short-host', server_path=os.path.abspath(a.server))
        wait('debug_state', lambda s: s['state'] == 'stopped')
        cursor, _ = control('continue')
        wait('debug_state', lambda s: s['state'] == 'exited', cursor)
        assert run(adb + ['shell', 'find /data/local/tmp -maxdepth 1 -type d -name "disassembler-*"']) == server_dirs
        print('PASS natural process exit cleans remote server resources', flush=True)
        call('debug_start', mode='android_launch', remote_path=remote + '/missing-host', server_path=os.path.abspath(a.server))
        deadline = time.monotonic() + 30
        cursor = 0
        while time.monotonic() < deadline:
            state = call('debug_state', after=cursor, wait_ms=500)
            cursor = state['cursor']
            if state['last_error']:
                break
        assert state['last_error'], 'Missing executable did not report a setup error'
        assert run(adb + ['shell', 'find /data/local/tmp -maxdepth 1 -type d -name "disassembler-*"']) == server_dirs
        print('PASS failed setup reports an error and cleans remote resources', flush=True)


        pid = launch()
        call('debug_start', mode='android_attach', pid=pid, server_path=os.path.abspath(a.server))
        wait('debug_state', lambda s: s['state'] == 'stopped')
        cursor, _ = control('stop')
        wait('debug_state', lambda s: s['state'] == 'detached', cursor)
        before = int(run(adb + ['shell', f'wc -c < {remote}/output']))
        time.sleep(.15)
        after = int(run(adb + ['shell', f'wc -c < {remote}/output']))
        assert after > before, 'Attached target did not resume after detach'
        print('PASS Android MCP attach, detach resumes target', flush=True)

        if a.gadget:
            run(adb + ['push', os.path.abspath(a.gadget), remote + '/libfrida-gadget.so'])
            config = tmp / 'libfrida-gadget.config'
            config.write_text(json.dumps(dict(interaction=dict(type='listen', address='127.0.0.1', port=27043, on_load='resume'))))
            run(adb + ['push', str(config), remote + '/libfrida-gadget.config'])
            forward = run(adb + ['forward', 'tcp:0', 'tcp:27043'])
            pid = launch(preload=True)
            time.sleep(.5)
            options = dict(pid=pid, port=int(forward))
            if a.python:
                options['python_path'] = a.python
            call('frida_attach', **options)
            attached = wait('frida_events', lambda s: s['state'] == 'attached')
            modules = event(attached, 'attached')['modules']
            module = next(m for m in modules if m['name'] == 'libdisasm-live.so')
            trace = call('frida_trace', module='libdisasm-live.so', symbol='debug_helper', argument_count=1)
            state = wait('frida_events', lambda s: event(s, 'trace'), attached['cursor'])
            captured = event(state, 'trace')
            assert captured['args'] == ['0x15'] and captured['retval'] == '0x2b'
            reply = call('frida_trace', action='remove', id=trace['id'])
            wait('frida_events', lambda s: event(s, 'removed', reply['request_id']), state['cursor'])
            offset = hex(int(captured['address'], 16) - int(module['base'], 16))
            trace2 = call('frida_trace', module='libdisasm-live.so', offset=offset, argument_count=1)
            state = wait('frida_events', lambda s: any(e['event'].get('id') == trace2['id'] and e['event']['event'] == 'trace' for e in s['events']), state['cursor'])
            reply = call('frida_detach')
            wait('frida_events', lambda s: event(s, 'detached', reply['request_id']), state['cursor'])
            run(adb + ['shell', f'kill -0 {pid}'])
            print('PASS Frida MCP attach, export/offset hooks, raw argument/return, remove and detach', flush=True)
        call('idb_close')
        call('idb_open', input_path=str(tmp / 'libdisasm-live.so'))
        pid = launch()
        call('debug_start', mode='android_attach', pid=pid, server_path=os.path.abspath(a.server))
        wait('debug_state', lambda s: s['state'] == 'stopped')
        before = int(run(adb + ['shell', f'wc -c < {remote}/output']))
        p.stdin.close()
        p.wait(timeout=30)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            after = int(run(adb + ['shell', f'wc -c < {remote}/output']))
            dirs = run(adb + ['shell', 'find /data/local/tmp -maxdepth 1 -type d -name "disassembler-*"'])
            if after > before and dirs == server_dirs:
                break
            time.sleep(.2)
        assert after > before and dirs == server_dirs, 'MCP EOF did not detach/clean up its server'
        print('PASS MCP EOF resumes attached target and removes temporary server directories', flush=True)
finally:
    p.stdin.close()
    p.wait(timeout=30)
    for pid in owned_pids:
        try:
            if run(adb + ['shell', f'readlink /proc/{pid}/exe']) == remote + '/live-host':
                run(adb + ['shell', f'kill {pid}'])
        except subprocess.CalledProcessError:
            pass
    if forward:
        run(adb + ['forward', '--remove', 'tcp:' + forward])
    run(adb + ['shell', 'rm -rf ' + shlex.quote(remote)])
