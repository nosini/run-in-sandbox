#!/usr/bin/env python3
"""Administrator setup, invoked by install.sh. Currently supports openSUSE RPMs."""
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile

SOURCE = Path(__file__).resolve().parent
CONFIG = Path('/etc/sandbox-game')
STATE = CONFIG / 'systemd-backend.json'
USERS = CONFIG / 'systemd-render-users'
UNITDIR = Path('/usr/local/lib/systemd/system')
HELPER = Path('/usr/local/libexec/sandbox-game/systemd-render-devices')
RULE = Path('/etc/udev/rules.d/99-sandbox-game-render.rules')
DROPIN = Path('/etc/systemd/system/systemd-nsresourced.service.d/50-sandbox-game-overlay.conf')
MODULE = 'sandbox_game_systemd'
REGISTRY = Path('/run/systemd/nsresource/registry')
SOCKETS = ('systemd-nsresourced.socket', 'systemd-mountfsd.socket')
SERVICES = ('systemd-nsresourced.service', 'systemd-mountfsd.service')
RENDER = 'sandbox-game-render-devices.service'
MOUNT = 'run-sandboxgame-render.mount'
FILES = (HELPER, RULE, DROPIN, UNITDIR / RENDER, UNITDIR / MOUNT)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def output(*args):
    return run(*args, stdout=subprocess.PIPE).stdout.strip()


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
    sys.modules[name] = module
    loader.exec_module(module)
    return module


def trusted(path, directory=False):
    """Reject links and writable/non-root ancestors of administrator files."""
    for parent in reversed(path.parents):
        st = parent.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
                f'unsafe administrator directory: {parent}')
    if path.exists() or path.is_symlink():
        st = path.lstat()
        kind = stat.S_ISDIR if directory else stat.S_ISREG
        require(kind(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
                f'unsafe administrator path: {path}')


def write(path, data, mode=0o644):
    # Check ancestors before creating them, including an existing dangling link.
    missing = []
    parent = path.parent
    while not parent.exists() and not parent.is_symlink():
        missing.append(parent)
        parent = parent.parent
    trusted(parent, directory=True)
    for parent in reversed(missing):
        parent.mkdir(mode=0o755)
    trusted(path)
    fd, temporary = tempfile.mkstemp(prefix='.sandbox-game-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            os.fchmod(stream.fileno(), mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def users(values):
    require(0 < len(values) <= 32, 'supply 1 to 32 non-root numeric host UIDs')
    result = set()
    for value in values:
        require(re.fullmatch(r'[1-9][0-9]*', value) and int(value) < 2**32 - 1,
                f'invalid non-root host UID: {value}')
        account = pwd.getpwuid(int(value))
        require(account.pw_gid == int(value),
                f'UID {value}: the systemd backend requires matching primary UID and GID '
                f'(primary group {account.pw_gid}); see "Your account\'s group" in '
                'systemd-backend/README.md')
        result.add(int(value))
    return sorted(result)


def components(uid):
    """Require distro managers, workers, library and units from one source build.

    GetInfo reports worker versions. The RPM checks also catch mixed managers,
    modified binaries, and local replacements of the vendor service units.
    """
    require(platform.freedesktop_os_release().get('ID') == 'opensuse-tumbleweed',
            'administrator setup currently supports openSUSE Tumbleweed only')
    require(shutil.which('rpm'), 'administrator setup requires RPM package verification')
    paths = [Path('/usr/lib/systemd') / name for name in
             ('systemd-nsresourced', 'systemd-nsresourcework', 'systemd-mountfsd', 'systemd-mountwork')]
    for binary in paths[:]:
        require(binary.is_file(), f'missing {binary}; install systemd-container 261.4 or later')
        linked = output('ldd', str(binary))
        match = re.search(r'libsystemd-shared\S* => (\S+)', linked)
        require(match, f'cannot identify {binary}\'s shared systemd library')
        paths.append(Path(match[1]).resolve())
    for unit in (*SOCKETS, *SERVICES):
        expected = Path('/usr/lib/systemd/system') / unit
        actual = output('systemctl', 'show', unit, '-p', 'FragmentPath', '--value')
        require(Path(actual) == expected, f'{unit} must use its matching vendor unit: {actual}')
        # Administrator drop-ins are allowed; overriding ExecStart is not.
        if unit in SERVICES:
            start = output('systemctl', 'show', unit, '-p', 'ExecStart', '--value')
            require(f'path=/usr/lib/systemd/{unit[:-8]} ;' in start,
                    f'{unit} overrides the vendor executable')
            pid = output('systemctl', 'show', unit, '-p', 'MainPID', '--value')
            if pid not in ('', '0'):
                require(Path(f'/proc/{int(pid)}/exe').samefile(Path('/usr/lib/systemd') / unit[:-8]),
                        f'{unit} still runs a replaced binary; stop managed namespaces and restart the service')
        paths.append(expected)
    builds = set()
    for path in set(paths):
        version = output('rpm', '-qf', '--qf', '%{VERSION}', str(path))
        parsed = uid.managed_version(version)
        require(parsed is not None and parsed >= (261, 4),
                f'{path}: systemd {version} is unsupported; need stable 261.4 or later')
        builds.add(output('rpm', '-qf', '--qf', '%{SOURCERPM}', str(path)))
        records = output('rpm', '-qf', '--qf', '[%{FILENAMES}\t%{FILEDIGESTS}\n]', str(path))
        digest = next((line.split('\t', 1)[1] for line in records.splitlines()
                       if line.split('\t', 1)[0] == str(path)), None)
        require(digest and len(digest) == 64 and hashlib.sha256(path.read_bytes()).hexdigest() == digest,
                f'{path} differs from its RPM; reinstall matching systemd packages')
    require(len(builds) == 1, 'systemd managers, workers, shared library and units must come from one source RPM build')


def idle():
    for service in SERVICES:
        count = output('systemctl', 'show', service, '-p', 'NFileDescriptorStore', '--value')
        require(count in ('', '0'), 'delegation resources are in use; stop games and other managed namespaces first')
    # Live ranges are tracked in the registry even when PID 1's descriptor
    # store is empty. Do not revoke GPU access or remove policy under them.
    require(not any(REGISTRY.glob('*.userns')),
            'managed namespaces are in use; stop games and other managed namespaces first')


def enabled(unit):
    return subprocess.run(['systemctl', 'is-enabled', '--quiet', unit]).returncode == 0


def install(values):
    allowed = users(values)
    uid = load('sandbox_uid', SOURCE.parent / 'sandbox-uid')
    components(uid)
    idle()
    selinux = Path('/sys/fs/selinux/enforce').exists()
    commands = ['udevadm', 'modprobe']
    if selinux:
        commands += ['checkmodule', 'semodule_package', 'semodule', 'restorecon']
    for command in commands:
        require(shutil.which(command), f'missing administrator dependency: {command}')
    for path in FILES:
        if path.parent.exists():
            trusted(path)
    if STATE.exists():
        trusted(STATE)
        state = json.loads(STATE.read_text())
        require(state.get('format') == 1, 'unknown administrator installation format')
    else:
        require(not any(p.exists() or p.is_symlink() for p in FILES),
                'administrator fixture files already exist; remove the manual setup before installing')
        if selinux:
            modules = output('semodule', '-l').splitlines()
            require(not any(line.split()[0] == MODULE for line in modules),
                    'manual sandbox_game_systemd policy exists; remove it before installing')
        state = {'format': 1, 'sockets_enabled': {s: enabled(s) for s in SOCKETS}, 'selinux': selinux}
        write(STATE, (json.dumps(state, indent=2) + '\n').encode())
    # Revoke before replacing the helper or changing the configured user list.
    if (UNITDIR / RENDER).exists():
        run('systemctl', 'stop', RENDER)
    if selinux:
        with tempfile.TemporaryDirectory(prefix='sandbox-policy-', dir=CONFIG) as tmp:
            mod, pp = str(Path(tmp) / f'{MODULE}.mod'), str(Path(tmp) / f'{MODULE}.pp')
            run('checkmodule', '-M', '-m', '-o', mod, str(SOURCE / f'{MODULE}.te'))
            run('semodule_package', '-o', pp, '-m', mod)
            run('semodule', '-i', pp)
    write(HELPER, (SOURCE / 'systemd-render-devices').read_bytes(), 0o755)
    write(RULE, (SOURCE / 'systemd-render-devices.rules').read_bytes())
    for name in (RENDER, MOUNT):
        write(UNITDIR / name, (SOURCE / name).read_bytes())
    write(USERS, ''.join(f'{value}\n' for value in allowed).encode())
    write(DROPIN, b'[Unit]\nRequires=modprobe@overlay.service\nAfter=modprobe@overlay.service\n')
    if selinux:
        run('restorecon', str(HELPER), str(RULE), str(USERS), str(STATE), str(DROPIN),
            str(UNITDIR / RENDER), str(UNITDIR / MOUNT))
    run('modprobe', 'overlay')
    run('systemctl', 'daemon-reload')
    run('udevadm', 'verify', str(RULE))
    run('udevadm', 'control', '--reload')
    run('systemctl', 'enable', '--now', *SOCKETS)
    why = uid.managed_available()
    require(why is None, f'delegation services unavailable: {why}')
    run('systemctl', 'enable', '--now', RENDER)
    print('Systemd backend administrator setup installed. No per-user setting was changed.')
    print('Render access is granted to UIDs: ' + ', '.join(map(str, allowed)))


def uninstall():
    if not STATE.exists():
        print('No packaged systemd backend administrator setup is installed.')
        return
    trusted(STATE)
    state = json.loads(STATE.read_text())
    require(state.get('format') == 1, 'unknown administrator installation format')
    idle()
    for path in FILES:
        if path.exists() or path.is_symlink():
            trusted(path)
    # Remove the event hook first; queued calls are blocked by --disable.
    RULE.unlink(missing_ok=True)
    run('udevadm', 'control', '--reload')
    run('udevadm', 'settle')
    if (UNITDIR / RENDER).exists():
        run('systemctl', 'disable', '--now', RENDER)
        run('systemctl', 'stop', MOUNT)
    # Never disable a shared socket that was enabled before this installation.
    for socket in SOCKETS:
        if not state['sockets_enabled'][socket]:
            run('systemctl', 'disable', '--now', socket)
    # Stop idle managers before removing their additional SELinux permissions.
    run('systemctl', 'stop', *SERVICES)
    if state['selinux'] and any(line.split()[0] == MODULE for line in output('semodule', '-l').splitlines()):
        run('semodule', '-r', MODULE)
    for path in FILES:
        path.unlink(missing_ok=True)
    STATE.unlink()
    run('systemctl', 'daemon-reload')
    print('Systemd backend administrator setup removed; render aliases revoked.')
    print(f'Kept {USERS}, per-user installs, settings and captures.')


def main():
    require(os.geteuid() == 0, 'run administrator setup as root')
    # sudo normally supplies this; also make direct root invocations predictable.
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    require(len(sys.argv) >= 2, 'expected install UID... or uninstall')
    if sys.argv[1] == 'install':
        install(sys.argv[2:])
    elif sys.argv[1:] == ['uninstall']:
        uninstall()
    else:
        raise RuntimeError('expected install UID... or uninstall')


if __name__ == '__main__':
    sys.dont_write_bytecode = True
    try:
        main()
    except (RuntimeError, OSError, KeyError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(f'systemd backend setup: {error}')
