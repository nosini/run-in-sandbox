#!/usr/bin/env -S python3 -I
"""Finite, isolated Weston/PipeWire integration test for the managed backend.

Requires the experimental delegation services/policy and render helper already
installed on a dedicated VM. Run as its ordinary user under dbus-run-session.
Never connects to the desktop compositor, audio graph or session bus.
"""
import argparse
from contextlib import contextmanager
import importlib.util
import json
import math
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import time
import wave

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "access_probe", Path(__file__).with_name("access.py"))
access = importlib.util.module_from_spec(spec)
spec.loader.exec_module(access)
probe = access.probe

PAYLOAD = r'''
import fcntl, json, os, subprocess, sys
from pathlib import Path
assert os.getgroups() == []
status = Path('/proc/self/status').read_text()
assert 'CapEff:\t0000000000000000' in status and 'Seccomp:\t2' in status
assert sorted(os.listdir('/proc/self/fd')) == ['0', '1', '2', '3']
assert not Path('/run/probe/pipewire-0').exists()
assert not Path('/run/probe/admin-native').exists()
fd = os.open('/dev/dri/renderD128', os.O_RDWR | os.O_CLOEXEC)
fcntl.ioctl(fd, 0xc0406400, bytearray(64), True)
os.close(fd)
def run(*args, success=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=25)
    if success:
        assert result.returncode == 0, (args, result.stdout, result.stderr)
    else:
        assert result.returncode != 0, (args, 'unexpectedly permitted')
    return result
print(run('/probe/media-client', *sys.argv[1:]).stdout, flush=True)
sinks = run('/usr/bin/pactl', 'list', 'short', 'sinks').stdout
assert 'probe_sink' in sinks, sinks
sources = run('/usr/bin/pactl', 'list', 'short', 'sources').stdout
assert 'probe_source' not in sources, sources
print('Restricted Pulse source listing: ' + repr(sources), flush=True)
run('/usr/bin/pactl', 'load-module', 'module-null-sink', success=False)
for source in ('@DEFAULT_SOURCE@', 'probe_sink.monitor', 'probe_source'):
    result = run('/usr/bin/parecord', '--raw', '--device=' + source,
                 '--format=s16le', '--rate=48000', '--channels=1', '/tmp/record.raw',
                 success=False)
    assert 'No such entity' in result.stderr, (source, result.stderr)
    assert not Path('/tmp/record.raw').exists() or Path('/tmp/record.raw').stat().st_size == 0
run('/usr/bin/paplay', '--device=probe_sink', '/probe/tone.wav')
print(json.dumps({'playback_drained': True, 'test_source_hidden': True,
                  'default_explicit_monitor_capture_denied': True,
                  'module_loading_denied': True, 'no_groups_caps_or_setup_fds': True}), flush=True)
'''


def wait_for(path, processes):
    for _ in range(100):
        for process in processes:
            probe.require(process.poll() is None, f"fixture exited: {process.args}")
        if path.exists():
            return
        time.sleep(.05)
    raise RuntimeError(f"fixture did not create {path}")


@contextmanager
def fixtures(checkout, root, runtime, renderer):
    processes, logs = [], []
    # Do not let shell overrides redirect a fixture to the desktop graph or
    # replace the private configuration/data lookup paths.
    inherited = {key: value for key, value in os.environ.items()
                 if not key.startswith(('PIPEWIRE_', 'WIREPLUMBER_', 'PULSE_'))}
    env = dict(inherited, GIO_USE_VFS='local', PIPEWIRE_REMOTE='pipewire-0',
               XDG_RUNTIME_DIR=str(runtime),
               PIPEWIRE_RUNTIME_DIR=str(runtime),
               XDG_CONFIG_HOME=str(root / 'config'),
               XDG_DATA_HOME=str(root / 'data'), XDG_STATE_HOME=str(root / 'state'))
    # Private D-Bus is supplied by dbus-run-session; do not inherit a desktop bus.
    probe.require('DBUS_SESSION_BUS_ADDRESS' in env, 'run under dbus-run-session')
    config = root / 'config'
    (config / 'pipewire/pipewire.conf.d').mkdir(parents=True)
    (config / 'wireplumber/wireplumber.conf.d').mkdir(parents=True)
    scripts = root / 'data/wireplumber/scripts/sandbox-game'
    scripts.mkdir(parents=True)
    for name in ('sandbox-access.lua', 'deny-restricted-capture.lua'):
        (scripts / name).write_bytes((checkout / 'audio' / name).read_bytes())
    (config / 'wireplumber/wireplumber.conf.d/60-sandbox-audio.conf').write_bytes(
        (checkout / 'audio/60-sandbox-audio.conf').read_bytes())
    (config / 'wireplumber/wireplumber.conf.d/90-probe.conf').write_text('''
wireplumber.profiles = { main = {
  hardware.audio = disabled
  hardware.bluetooth = disabled
  hardware.video-capture = disabled
} }
''')
    (config / 'pipewire/sandbox-pulse.conf').write_bytes(
        (checkout / 'audio/sandbox-pulse.conf').read_bytes())
    (config / 'pipewire/pipewire.conf.d/90-probe.conf').write_text('''
context.spa-libs = { audiotestsrc = audiotestsrc/libspa-audiotestsrc }
context.objects = [
 { factory = adapter args = {
   factory.name = support.null-audio-sink node.name = probe_sink
   media.class = Audio/Sink audio.position = [ MONO ] object.linger = true
 } }
 { factory = adapter args = {
   factory.name = audiotestsrc node.name = probe_source
   media.class = Audio/Source audio.position = [ MONO ] object.linger = true
 } }
]
''')
    def start(name, command, **extra):
        log = (root / (name + '.log')).open('w')
        logs.append(log)
        process = subprocess.Popen(command, stdout=log, stderr=log,
                                   env=dict(env, **extra), start_new_session=True)
        processes.append(process)
        return process
    try:
        start('weston', ['weston', '--backend=headless', '--renderer=' + renderer,
                         '--shell=kiosk-shell.so', '--no-config', '--idle-time=0',
                         '--socket=wayland-probe'])
        wait_for(runtime / 'wayland-probe', processes)
        start('pipewire', ['pipewire'])
        wait_for(runtime / 'pipewire-0', processes)
        start('wireplumber', ['wireplumber'])
        (runtime / 'restricted').mkdir(mode=0o700)
        start('restricted-pulse', ['pipewire', '-c', 'sandbox-pulse.conf'],
              PULSE_RUNTIME_PATH=str(runtime / 'restricted'))
        wait_for(runtime / 'restricted/native', processes)
        # An unrestricted control endpoint on the same PRIVATE graph is the
        # playback oracle. It is never delegated or mounted into the sandbox.
        (runtime / 'admin').mkdir(mode=0o700)
        start('admin-pulse', ['pipewire-pulse'], PULSE_RUNTIME_PATH=str(runtime / 'admin'))
        wait_for(runtime / 'admin/native', processes)
        admin = dict(env, PULSE_SERVER='unix:' + str(runtime / 'admin/native'))
        for _ in range(100):
            result = subprocess.run(['pactl', 'list', 'short', 'sinks'], env=admin,
                                    capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and 'probe_sink' in result.stdout:
                break
            time.sleep(.05)
        else:
            raise RuntimeError('private sink did not become available')
        sources = subprocess.check_output(['pactl', 'list', 'short', 'sources'], env=admin, text=True)
        probe.require('probe_sink.monitor' in sources and 'probe_source' in sources,
                      f'control recording sources missing: {sources}')
        yield admin
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
        for process in reversed(processes):
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        for log in logs:
            log.close()


def worker(namespace, mounts, uid, gid, helper, seccomp, require_hardware):
    probe.checked(probe.libc.setns(namespace, probe.CLONE_NEWUSER), 'setns')
    os.setresgid(0, 0, 0)
    os.setresuid(0, 0, 0)
    os.setgroups([])
    host_uid = int(Path('/proc/self/uid_map').read_text().split()[1])
    probe.checked(probe.libc.unshare(probe.CLONE_NEWNS), 'mount namespace')
    probe.mount(None, '/', None, probe.MS_REC | probe.MS_PRIVATE)
    probe.mount('tmpfs', '/tmp', 'tmpfs', flags=6, options='mode=0700,size=16m')
    os.chdir('/tmp')
    for name, fd in mounts.items():
        access.attach(fd, name)
    probe.checked(probe.libc.prctl(4, 1, 0, 0, 0), 'dumpability')
    probe.checked(probe.libc.unshare(probe.CLONE_NEWUSER), 'child user namespace')
    Path('/proc/self/setgroups').write_text('deny')
    Path('/proc/self/uid_map').write_text(f'{uid} 0 1\n')
    Path('/proc/self/gid_map').write_text(f'{gid} 0 1\n')
    probe.checked(probe.libc.prctl(4, 1, 0, 0, 0), 'child dumpability')
    os.lseek(helper, 0, os.SEEK_SET)
    os.lseek(seccomp, 0, os.SEEK_SET)
    command = [
        'bwrap', '--unshare-all', '--unshare-user', '--disable-userns',
        '--die-with-parent', '--new-session', '--clearenv',
        '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'HOME', '/tmp',
        '--setenv', 'XDG_RUNTIME_DIR', '/run/probe',
        '--setenv', 'WAYLAND_DISPLAY', 'wayland-probe',
        '--setenv', 'PULSE_SERVER', 'unix:/run/probe/native',
        '--ro-bind', '/usr', '/usr', '--ro-bind', '/etc', '/etc',
        '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev',
        '--tmpfs', '/tmp', '--dir', '/run/probe', '--chmod', '0700', '/run/probe',
        '--ro-bind', '/tmp/display/wayland-probe', '/run/probe/wayland-probe',
        '--ro-bind', '/tmp/audio/native', '/run/probe/native',
        '--ro-bind', '/tmp/assets', '/probe',
        '--dev-bind', '/tmp/devices/renderD128', '/dev/dri/renderD128',
        '--ro-bind-data', str(helper), '/sandbox-landlock', '--seccomp', str(seccomp),
        '--', '/usr/bin/python3', '-I', '/sandbox-landlock',
        '--ro', '/usr', '--ro', '/etc', '--ro', '/proc', '--ro', '/probe',
        '--rw', '/dev', '--rw', '/tmp', '--rw', '/run/probe',
        '--', '/usr/bin/python3', '-I', '-c', PAYLOAD,
    ]
    if require_hardware:
        command.append('--require-hardware')
    result = subprocess.run(command, pass_fds=(helper, seccomp), capture_output=True,
                            text=True, timeout=80, env={'PATH': '/usr/bin:/bin'})
    print(result.stdout, end='', flush=True)
    probe.require(result.returncode == 0, result.stderr)
    probe.require('no Landlock' not in result.stderr, result.stderr)
    print(json.dumps({'transient_host_uid': host_uid, 'protected_media_client': True}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--device-dir', type=Path, required=True)
    parser.add_argument('--require-hardware', action='store_true',
                        help='fail unless EGL renders on the mapped DRM node without software fallback')
    parser.add_argument('--weston-renderer', choices=('pixman', 'gl'),
                        help='private compositor renderer (default: gl for hardware checks, otherwise pixman)')
    args = parser.parse_args()
    probe.require(os.getuid() != 0, 'run as an ordinary user')
    checkout = Path(__file__).resolve().parents[2]
    # Keep logs on failure/success for inspection; caller chooses the scratch dir.
    root = args.work_dir.resolve()
    root.mkdir(parents=True, exist_ok=False)
    assets = root / 'assets'
    assets.mkdir()
    xml = '/usr/share/wayland-protocols/stable/xdg-shell/xdg-shell.xml'
    subprocess.run(['wayland-scanner', 'client-header', xml,
                    str(assets / 'xdg-shell-client-protocol.h')], check=True)
    subprocess.run(['wayland-scanner', 'private-code', xml,
                    str(assets / 'xdg-shell-protocol.c')], check=True)
    flags = subprocess.check_output(['pkg-config', '--cflags', '--libs',
                                    'egl', 'gl', 'wayland-client', 'wayland-egl'], text=True).split()
    subprocess.run(['gcc', '-Wall', '-Wextra', '-Werror', '-O2', '-I', str(assets),
                    str(Path(__file__).with_name('media-client.c')),
                    str(assets / 'xdg-shell-protocol.c'), '-o', str(assets / 'media-client'),
                    *flags], check=True)
    with wave.open(str(assets / 'tone.wav'), 'wb') as output:
        output.setparams((1, 2, 48000, 0, 'NONE', 'not compressed'))
        output.writeframes(b''.join(struct.pack('<h', int(12000 * math.sin(2 * math.pi * 440 * i / 48000)))
                                   for i in range(96000)))
    helper = os.memfd_create('probe-landlock', os.MFD_CLOEXEC)
    os.write(helper, (checkout / 'sandbox-landlock').read_bytes())
    seccomp = os.memfd_create('probe-seccomp', os.MFD_CLOEXEC)
    subprocess.run([sys.executable, '-I', str(checkout / 'sandbox-seccomp')], stdout=seccomp, check=True)
    namespace, mounts = None, {}
    try:
        with tempfile.TemporaryDirectory(prefix='rt-', dir=root) as short:
            runtime = Path(short)
            probe.require(len(str(runtime / 'restricted/native').encode()) < 104,
                          'use a shorter --work-dir for Unix socket paths')
            renderer = args.weston_renderer or ('gl' if args.require_hardware else 'pixman')
            with fixtures(checkout, root, runtime, renderer) as admin:
                recording = (root / 'monitor.raw').open('wb')
                recorder = subprocess.Popen(['parecord', '--raw', '--device=probe_sink.monitor',
                                             '--format=s16le', '--rate=48000', '--channels=1'],
                                            env=admin, stdout=recording, stderr=subprocess.PIPE)
                try:
                    time.sleep(.3)
                    probe.require(recorder.poll() is None, 'control monitor capture failed')
                    namespace = access.allocate(f'sg-media-{os.getpid()}')
                    for name, path in {'display': runtime, 'audio': runtime / 'restricted',
                                       'assets': assets, 'devices': args.device_dir.resolve()}.items():
                        mounts[name] = probe.delegate(path, namespace, True)
                    sys.stdout.flush()
                    pid = os.fork()
                    if pid == 0:
                        try:
                            worker(namespace, mounts, os.getuid(), os.getgid(), helper, seccomp,
                                   args.require_hardware)
                        except BaseException as error:
                            print(f'media worker: {error}', file=sys.stderr, flush=True)
                            os._exit(1)
                        os._exit(0)
                    _, status = os.waitpid(pid, 0)
                    probe.require(status == 0, f'worker failed: {status}')
                finally:
                    recorder.terminate()
                    _, error = recorder.communicate(timeout=5)
                    recording.close()
                probe.require(recorder.returncode in (0, -signal.SIGTERM), repr(error))
                samples = struct.unpack('<' + 'h' * ((root / 'monitor.raw').stat().st_size // 2),
                                        (root / 'monitor.raw').read_bytes())
                loud = sum(abs(sample) > 1000 for sample in samples)
                probe.require(loud > 20000, f'playback monitor had insufficient signal: {loud}')
                print(json.dumps({'monitor_nonzero_samples': loud, 'private_graph_playback_verified': True}))
    finally:
        for fd in list(mounts.values()) + [helper, seccomp] + ([] if namespace is None else [namespace]):
            os.close(fd)
    print('PASS: real Wayland/EGL and playback-only Pulse clients through managed idmaps')


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        sys.exit(f'systemd media probe: {error}')
