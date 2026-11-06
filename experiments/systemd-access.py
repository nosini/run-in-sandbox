#!/usr/bin/env -S python3 -I
"""Test idmapped sockets and cross-namespace access; optional render-node alias.

Run from a checkout with the delegation services available:
  python3 -I experiments/systemd-access.py --work-dir /path/to/scratch
  ... --device-dir /path/to/caller-owned/render-alias-directory

The optional alias must already exist; this script never creates device nodes,
changes device permissions, sets ACLs, or installs service policy.
"""
import argparse
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "storage_probe", Path(__file__).with_name("systemd-backend.py"))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

PAYLOAD = r"""
import fcntl, json, os, socket, struct
from pathlib import Path
assert os.getgroups() == [], 'caller supplementary groups leaked'
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.settimeout(5)
    client.connect('/run/probe/allowed')
    peer = json.loads(client.recv(4096))
    assert peer['uid'] == int(os.environ['HOST_UID']), peer
    assert peer['gid'] == int(os.environ['HOST_UID']), peer
assert not Path('/run/probe/hidden').exists()
assert not Path('/run/probe/private').exists()
if os.environ['GPU'] == '1':
    fd = os.open('/dev/dri/renderD128', os.O_RDWR | os.O_CLOEXEC)
    version = bytearray(64)
    fcntl.ioctl(fd, 0xc0406400, version, True)  # DRM_IOCTL_VERSION on 64-bit Linux
    os.close(fd)
    assert any(struct.unpack_from('iii', version)), 'missing DRM driver version'
assert sorted(os.listdir('/proc/self/fd')) == ['0', '1', '2', '3']
print('socket peer credentials, selected socket only, render alias if requested: PASS')
"""


@contextmanager
def server(directory):
    listeners = []
    previous = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.chdir(directory)
        for name in ("allowed", "hidden"):
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(name)  # avoid sockaddr_un's short absolute-path limit
            os.chmod(name, 0o600)
            listener.listen(8)
            listeners.append(listener)
    finally:
        os.fchdir(previous)
        os.close(previous)
    pid = os.fork()
    if pid == 0:
        listeners[1].close()
        try:
            while True:
                client, _ = listeners[0].accept()
                with client:
                    _, uid, gid = struct.unpack(
                        "3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    client.sendall(json.dumps({"uid": uid, "gid": gid}).encode())
        except BaseException:
            os._exit(1)
    for listener in listeners:
        listener.close()
    try:
        yield
    finally:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        os.waitpid(pid, 0)


def allocate(name):
    namespace = probe.empty_namespace()
    try:
        _, fds = probe.call("io.systemd.NamespaceResource", "AllocateUserRange", {
            "name": name, "size": 65536, "target": 0,
            "userNamespaceFileDescriptor": 0,
        }, [namespace])
        for fd in fds:
            os.close(fd)
        return namespace
    except BaseException:
        os.close(namespace)
        raise


def attach(fd, name):
    os.mkdir(name)
    probe.checked(probe.libc.syscall(429, fd, b"", -100, name.encode(), 0x4),
                  f"move_mount {name}")


def connect(path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(path)
        return json.loads(client.recv(4096))


def read_at(fd):
    opened = os.open("private", os.O_RDONLY | os.O_CLOEXEC, dir_fd=fd)
    try:
        return os.read(opened, 128)
    finally:
        os.close(opened)


def worker(namespace, sockets, own, peer, devices, raw, uid, gid, helper, seccomp):
    probe.checked(probe.libc.setns(namespace, probe.CLONE_NEWUSER), "setns")
    os.setresgid(0, 0, 0)
    os.setresuid(0, 0, 0)
    os.setgroups([])
    host_uid = int(Path("/proc/self/uid_map").read_text().split()[1])
    probe.checked(probe.libc.unshare(probe.CLONE_NEWNS), "unshare mounts")
    probe.mount(None, "/", None, probe.MS_REC | probe.MS_PRIVATE)
    probe.mount("tmpfs", "/tmp", "tmpfs", flags=6, options="mode=0700,size=16m")
    os.chdir("/tmp")
    attach(sockets, "sockets")
    attach(own, "data")
    if devices is not None:
        attach(devices, "devices")
        def raw_gpu():
            fd = os.open("/dev/dri/renderD128", os.O_RDWR | os.O_CLOEXEC)
            os.close(fd)
        probe.denied(raw_gpu, "raw root-owned GPU node")
    probe.require(Path("data/private").read_text() == "private\n", "own mapped read")
    peer_errno = probe.denied(lambda: read_at(peer), "other live namespace's idmapped capture")
    raw_errno = probe.denied(lambda: connect(f"/proc/self/fd/{raw}/allowed"),
                             "caller-owned raw socket")
    mapped = connect("/tmp/sockets/allowed")
    probe.require(mapped == {"uid": host_uid, "gid": host_uid}, f"socket credentials: {mapped}")
    os.close(raw)
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
        "--setenv", "HOST_UID", str(host_uid),
        "--setenv", "GPU", "1" if devices is not None else "0",
        "--ro-bind", "/usr", "/usr", "--ro-bind", "/etc", "/etc",
        "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64", "--proc", "/proc", "--dev", "/dev",
        "--tmpfs", "/tmp", "--ro-bind", "/tmp/sockets/allowed", "/run/probe/allowed",
        "--ro-bind-data", str(helper), "/sandbox-landlock", "--seccomp", str(seccomp),
    ]
    if devices is not None:
        command += ["--dev-bind", "/tmp/devices/renderD128", "/dev/dri/renderD128"]
    command += [
        "--", "/usr/bin/python3", "-I", "/sandbox-landlock",
        "--ro", "/usr", "--ro", "/etc", "--ro", "/proc", "--rw", "/dev",
        "--rw", "/run/probe", "--", "/usr/bin/python3", "-I", "-c", PAYLOAD,
    ]
    result = subprocess.run(command, pass_fds=(helper, seccomp), capture_output=True,
                            text=True, timeout=30, env={"PATH": "/usr/bin:/bin"})
    probe.require(result.returncode == 0, f"bwrap payload: {result.stdout} {result.stderr}")
    probe.require("no Landlock" not in result.stderr, "Landlock unavailable")
    print(json.dumps({"host_uid": host_uid, "raw_socket_errno": raw_errno,
                      "peer_capture_errno": peer_errno, "idmapped_socket": True,
                      "bwrap_seccomp_landlock": True, "render_alias": devices is not None}),
          flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--device-dir", type=Path)
    args = parser.parse_args()
    probe.require(os.getuid() != 0, "run as an ordinary user")
    probe.require(os.uname().machine in ("x86_64", "aarch64"), "unsupported syscall ABI")
    checkout = Path(__file__).resolve().parents[1]
    helper = os.memfd_create("probe-landlock", os.MFD_CLOEXEC)
    os.write(helper, (checkout / "sandbox-landlock").read_bytes())
    seccomp = os.memfd_create("probe-seccomp", os.MFD_CLOEXEC)
    subprocess.run([sys.executable, "-I", str(checkout / "sandbox-seccomp")],
                   stdout=seccomp, check=True, env={"PATH": "/usr/bin:/bin"})
    namespaces, mounts = [], []
    try:
        with tempfile.TemporaryDirectory(prefix="access-", dir=args.work_dir.resolve()) as tmp:
            root = Path(tmp)
            (root / "sockets").mkdir(mode=0o755)
            for i in range(2):
                directory = root / f"data{i}"
                directory.mkdir(mode=0o700)
                (directory / "private").write_text("private\n")
                (directory / "private").chmod(0o600)
            with server(root / "sockets"):
                setups = []
                for i in range(2):
                    namespace = allocate(f"sg-access-{os.getpid()}-{i}")
                    namespaces.append(namespace)
                    sockets = probe.delegate(root / "sockets", namespace, True)
                    mounts.append(sockets)
                    data = probe.delegate(root / f"data{i}", namespace, False)
                    mounts.append(data)
                    devices = None
                    if args.device_dir:
                        devices = probe.delegate(args.device_dir.resolve(), namespace, True)
                        mounts.append(devices)
                    setups.append((namespace, sockets, data, devices))
                for i, (namespace, sockets, own, devices) in enumerate(setups):
                    raw = os.open(root / "sockets", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                    sys.stdout.flush()
                    pid = os.fork()
                    if pid == 0:
                        try:
                            worker(namespace, sockets, own, setups[1-i][2], devices, raw,
                                   os.getuid(), os.getgid(), helper, seccomp)
                        except BaseException as error:
                            print(f"access worker: {error}", file=sys.stderr, flush=True)
                            os._exit(1)
                        os._exit(0)
                    os.close(raw)
                    _, status = os.waitpid(pid, 0)
                    probe.require(status == 0, f"worker failed: wait status {status}")
    finally:
        for fd in mounts + namespaces + [helper, seccomp]:
            os.close(fd)
    print("PASS: idmapped socket access, transient peer credentials, cross-namespace denial")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        sys.exit(f"systemd access probe: {error}")
