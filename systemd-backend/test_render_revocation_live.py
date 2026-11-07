#!/usr/bin/env -S python3 -I
"""Live revocation test for a dedicated VM installation of the render helper.

Temporarily empties the helper's UID allowlist, then restores it. Refuses to
run unless that file contains exactly the requested test UID. Requires the
test delegation services, SELinux module and render helper/unit already set up.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "access_probe", Path(__file__).resolve().parent / "probes" / "access.py")
access = importlib.util.module_from_spec(spec)
spec.loader.exec_module(access)
probe = access.probe
CONFIG = Path("/etc/sandbox-game/systemd-render-users")
SERVICE = "sandbox-game-render-devices.service"

PAYLOAD = r"""
import errno, fcntl, os, stat
path = '/dev/dri/renderD128'
assert os.getgroups() == []
fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
fcntl.ioctl(fd, 0xc0406400, bytearray(64), True)
os.close(fd)
print('READY', flush=True)
assert input() == 'continue'
def refused():
    st = os.stat(path)
    assert stat.S_IMODE(st.st_mode) == 0
    try:
        fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
    except PermissionError:
        return
    os.close(fd)
    raise RuntimeError('retired bind-mounted alias could still be opened')
refused()
print('REVOKED', flush=True)
assert input() == 'continue'
refused()
assert sorted(os.listdir('/proc/self/fd')) == ['0', '1', '2', '3']
print('OLD_INODE_STILL_REVOKED', flush=True)
"""


def client(args):
    probe.require(os.getuid() != 0, "client must be unprivileged")
    uid, gid = os.getuid(), os.getgid()
    checkout = Path(__file__).resolve().parents[1]
    helper = os.memfd_create("probe-landlock", os.MFD_CLOEXEC)
    os.write(helper, (checkout / "sandbox-landlock").read_bytes())
    seccomp = os.memfd_create("probe-seccomp", os.MFD_CLOEXEC)
    subprocess.run([sys.executable, "-I", str(checkout / "sandbox-seccomp")],
                   stdout=seccomp, check=True, env={"PATH": "/usr/bin:/bin"})
    control = socket.socket(fileno=args.control_fd)
    namespace = access.allocate(f"sg-revoke-{os.getpid()}")
    mapped = probe.delegate(Path(f"/run/sandboxgame/render/{uid}"), namespace, True)
    probe.checked(probe.libc.setns(namespace, probe.CLONE_NEWUSER), "setns")
    os.setresgid(0, 0, 0)
    os.setresuid(0, 0, 0)
    os.setgroups([])
    probe.checked(probe.libc.unshare(probe.CLONE_NEWNS), "mount namespace")
    probe.mount(None, "/", None, probe.MS_REC | probe.MS_PRIVATE)
    probe.mount("tmpfs", "/tmp", "tmpfs", flags=6, options="mode=0700,size=16m")
    os.chdir("/tmp")
    access.attach(mapped, "devices")
    probe.checked(probe.libc.prctl(4, 1, 0, 0, 0), "dumpability")
    probe.checked(probe.libc.unshare(probe.CLONE_NEWUSER), "child user namespace")
    Path("/proc/self/setgroups").write_text("deny")
    Path("/proc/self/uid_map").write_text(f"{uid} 0 1\n")
    Path("/proc/self/gid_map").write_text(f"{gid} 0 1\n")
    probe.checked(probe.libc.prctl(4, 1, 0, 0, 0), "child dumpability")
    os.lseek(helper, 0, os.SEEK_SET)
    os.lseek(seccomp, 0, os.SEEK_SET)
    command = [
        "bwrap", "--unshare-all", "--unshare-user", "--disable-userns",
        "--die-with-parent", "--new-session", "--clearenv",
        "--ro-bind", "/usr", "/usr", "--ro-bind", "/etc", "/etc",
        "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64", "--proc", "/proc", "--dev", "/dev",
        "--tmpfs", "/tmp", "--dev-bind", "/tmp/devices/renderD128", "/dev/dri/renderD128",
        "--ro-bind-data", str(helper), "/sandbox-landlock", "--seccomp", str(seccomp),
        "--", "/usr/bin/python3", "-I", "/sandbox-landlock", "--ro", "/usr",
        "--ro", "/etc", "--ro", "/proc", "--rw", "/dev",
        "--", "/usr/bin/python3", "-I", "-c", PAYLOAD,
    ]
    process = subprocess.Popen(command, pass_fds=(helper, seccomp), stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                               env={"PATH": "/usr/bin:/bin"})
    try:
        for expected in ("READY", "REVOKED", "OLD_INODE_STILL_REVOKED"):
            message = process.stdout.readline().strip()
            if message != expected:
                _, error = process.communicate(timeout=5)
                raise RuntimeError(f"payload expected {expected}, got {message!r}: {error}")
            control.send(message.encode())
            if expected != "OLD_INODE_STILL_REVOKED":
                probe.require(control.recv(4096) == b"continue", "controller handshake")
                process.stdin.write("continue\n")
                process.stdin.flush()
        _, error = process.communicate(timeout=5)
        probe.require(process.returncode == 0 and "no Landlock" not in error, error)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        control.close()
        for fd in (namespace, mapped, helper, seccomp):
            os.close(fd)


def controller(args):
    probe.require(os.geteuid() == 0, "controller requires root on the dedicated test VM")
    original = CONFIG.read_bytes()
    probe.require(original == f"{args.uid}\n".encode(),
                  "requires a fixture allowlist containing exactly the test UID and newline")
    account = pwd.getpwuid(args.uid)
    probe.require(args.uid != 0, "test UID must not be root")
    alias = Path(f"/run/sandboxgame/render/{args.uid}/renderD128")
    old = alias.stat()
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    def unprivileged():
        os.setgroups([])
        os.setgid(account.pw_gid)
        os.setuid(args.uid)
    process = subprocess.Popen([
        sys.executable, "-I", str(Path(__file__).resolve()), "client",
        "--control-fd", str(child.fileno()),
    ], preexec_fn=unprivileged, pass_fds=(child.fileno(),),
        env={"PATH": "/usr/bin:/bin", "HOME": account.pw_dir})
    child.close()
    parent.settimeout(30)
    try:
        probe.require(parent.recv(4096) == b"READY", "initial GPU open failed")
        if args.cycle_mount:
            subprocess.run(["systemctl", "stop", "run-sandboxgame-render.mount"], check=True)
        else:
            CONFIG.write_bytes(b"")
            subprocess.run(["systemctl", "reload", SERVICE], check=True)
        probe.require(not alias.exists(), "revoked alias remains published")
        parent.send(b"continue")
        probe.require(parent.recv(4096) == b"REVOKED", "held bind mount was not revoked")
        CONFIG.write_bytes(original)
        subprocess.run(["systemctl", "start", SERVICE], check=True)
        subprocess.run(["systemctl", "reload", SERVICE], check=True)
        current = alias.stat()
        probe.require((current.st_dev, current.st_ino) != (old.st_dev, old.st_ino),
                      "regrant reused revoked inode")
        parent.send(b"continue")
        probe.require(parent.recv(4096) == b"OLD_INODE_STILL_REVOKED",
                      "regrant revived old bind-mounted alias")
        probe.require(process.wait(timeout=10) == 0, "client failed")
        print(json.dumps({"mode": "mount-cycle" if args.cycle_mount else "allowlist",
                          "initial_drm_ioctl": True, "bound_alias_revoked": True,
                          "regrant_uses_fresh_inode": True, "old_inode_stays_revoked": True}))
    finally:
        parent.close()
        if process.poll() is None:
            process.kill()
            process.wait()
        CONFIG.write_bytes(original)
        subprocess.run(["systemctl", "start", SERVICE], check=True)
        subprocess.run(["systemctl", "reload", SERVICE], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    root = commands.add_parser("run", help="administrator controller on the test VM")
    root.add_argument("--uid", type=int, required=True)
    root.add_argument("--cycle-mount", action="store_true",
                      help="stop/restart the runtime mount instead of changing the allowlist")
    child = commands.add_parser("client", help=argparse.SUPPRESS)
    child.add_argument("--control-fd", type=int, required=True)
    args = parser.parse_args()
    (controller if args.command == "run" else client)(args)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        sys.exit(f"render revocation test: {error}")
