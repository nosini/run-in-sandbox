#!/usr/bin/env -S python3 -I
"""Disposable, unprivileged nsresourced/mountfsd experiment; not a launcher.

Run from a checkout on a host with both systemd sockets active:
    python3 -I systemd-backend/probes/storage.py --work-dir /path/to/scratch

Only synthetic files are delegated. Two independent allocations reuse the
same storage, checking on-disk ownership and persistence after each exits.
No packages, policies, services or existing captures are changed by this script.
"""
import argparse
import array
import ctypes
import errno
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile


CLONE_NEWUSER, CLONE_NEWNS = 0x10000000, 0x20000
MS_REC, MS_PRIVATE = 16384, 1 << 18
libc = ctypes.CDLL(None, use_errno=True)

PAYLOAD = r"""
import ctypes, errno, os
from pathlib import Path
assert os.getuid() == int(os.environ['PROBE_UID'])
assert os.getgroups() == [], 'caller supplementary groups leaked'
status = Path('/proc/self/status').read_text()
assert 'Seccomp:\t2\n' in status
assert 'CapEff:\t0000000000000000\n' in status
Path('/game/protected').write_text('bwrap + seccomp + Landlock\n')
Path('/home/game/protected').write_text('save\n')
try:
    Path('/blocked/escape').write_text('bad')
except PermissionError:
    pass
else:
    raise RuntimeError('Landlock did not restrict the private root filesystem')
libc = ctypes.CDLL(None, use_errno=True)
assert libc.unshare(0x10000000) == -1
assert ctypes.get_errno() in (errno.EPERM, errno.EACCES)
assert sorted(os.listdir('/proc/self/fd')) == ['0', '1', '2', '3']
print('bwrap + seccomp + Landlock: PASS')
"""


def checked(result, operation):
    if result < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), operation)
    return result


def mount(source, target, kind, flags=0, options=None):
    checked(libc.mount(source and source.encode(), target.encode(),
                       kind and kind.encode(), ctypes.c_ulong(flags),
                       options and options.encode()), f"mount {target}")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def call(interface, method, parameters, fds):
    """One Varlink call with SCM_RIGHTS, including fragmented replies."""
    received = []
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(30)
            connection.connect(f"/run/systemd/{interface}")
            request = json.dumps({"method": f"{interface}.{method}",
                                  "parameters": parameters}).encode() + b"\0"
            sent = connection.sendmsg([request], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                                   array.array("i", fds))])
            connection.sendall(request[sent:])
            reply = b""
            while b"\0" not in reply:
                data, ancillary, flags, _ = connection.recvmsg(
                    65536, socket.CMSG_SPACE(16 * array.array("i").itemsize),
                    socket.MSG_CMSG_CLOEXEC)
                for level, kind, value in ancillary:
                    if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                        ids = array.array("i")
                        ids.frombytes(value[:len(value) - len(value) % ids.itemsize])
                        received.extend(ids)
                require(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC),
                        "truncated Varlink reply")
                require(bool(data), "Varlink connection closed before reply")
                reply += data
                require(len(reply) <= 1024 * 1024, "oversized Varlink reply")
            response = json.loads(reply.split(b"\0", 1)[0])
            require("error" not in response, f"{method}: {response}")
            require(not response.get("continues"), "unexpected streaming reply")
            return response.get("parameters", {}), received
    except BaseException:
        for fd in received:
            os.close(fd)
        raise


def empty_namespace():
    """Keep an empty namespace alive by FD after its creator has exited."""
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    pid = os.fork()
    if pid == 0:
        parent.close()
        try:
            checked(libc.unshare(CLONE_NEWUSER), "unshare user namespace")
            fd = os.open("/proc/self/ns/user", os.O_RDONLY | os.O_CLOEXEC)
            socket.send_fds(child, [b"namespace"], [fd])
        except BaseException as error:
            child.send(str(error).encode())
            os._exit(1)
        os._exit(0)
    child.close()
    try:
        parent.settimeout(10)
        data, fds, _, _ = socket.recv_fds(parent, 4096, 1)
        _, status = os.waitpid(pid, 0)
        require(status == 0 and len(fds) == 1, f"empty namespace: {data!r}")
        return fds[0]
    finally:
        parent.close()


def delegate(directory, namespace, read_only):
    fd = os.open(directory, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        result, fds = call("io.systemd.MountFileSystem", "MountDirectory", {
            "directoryFileDescriptor": 0, "userNamespaceFileDescriptor": 1,
            "mode": "root", "readOnly": read_only,
            "allowInteractiveAuthentication": False,
        }, [fd, namespace])
    finally:
        os.close(fd)
    try:
        index = result["mountFileDescriptor"]
        require(type(index) is int and 0 <= index < len(fds), "bad mount FD index")
        return fds.pop(index)
    finally:
        for fd in fds:
            os.close(fd)


def denied(action, description, codes=(errno.EACCES, errno.EPERM)):
    try:
        action()
    except OSError as error:
        require(error.errno in codes, f"{description}: unexpected {error}")
        return error.errno
    raise RuntimeError(f"unexpected access: {description}")


def protected_payload(uid, helper, seccomp):
    game = os.open("merged", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    home = os.open("storage/home", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.lseek(helper, 0, os.SEEK_SET)
        os.lseek(seccomp, 0, os.SEEK_SET)
        result = subprocess.run([
            "bwrap", "--unshare-all", "--unshare-user", "--disable-userns",
            "--die-with-parent", "--new-session", "--clearenv",
            "--setenv", "PATH", "/usr/bin", "--setenv", "HOME", "/home/game",
            "--setenv", "PROBE_UID", str(uid),
            "--ro-bind", "/usr", "/usr", "--ro-bind", "/etc", "/etc",
            "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
            "--symlink", "usr/lib64", "/lib64", "--proc", "/proc",
            "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/blocked",
            "--bind-fd", str(game), "/game",
            "--bind-fd", str(home), "/home/game",
            "--ro-bind-data", str(helper), "/sandbox-landlock",
            "--seccomp", str(seccomp), "--chdir", "/game", "--",
            "/usr/bin/python3", "-I", "/sandbox-landlock",
            "--rw", "/game", "--rw", "/home/game", "--rw", "/dev",
            "--ro", "/usr", "--ro", "/etc", "--ro", "/proc",
            "--", "/usr/bin/python3", "-I", "-c", PAYLOAD,
        ], pass_fds=(game, home, helper, seccomp), capture_output=True, text=True,
            env={"PATH": "/usr/bin:/bin"}, timeout=30)
        require(result.returncode == 0,
                f"protected payload: {result.returncode}: {result.stdout} {result.stderr}")
        require("no Landlock" not in result.stderr, "Landlock unavailable")
    finally:
        os.close(game)
        os.close(home)


def worker(namespace, mounts, root, iteration, uid, gid, helper, seccomp):
    # Resolve the private fixture directory before changing identities. Only
    # this cwd and the deliberate negative-test FD survive into setup.
    os.chdir(root)
    raw = os.open("outside", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    checked(libc.setns(namespace, CLONE_NEWUSER), "setns managed namespace")
    os.setresgid(0, 0, 0)
    os.setresuid(0, 0, 0)
    os.setgroups([])
    managed_map = Path("/proc/self/uid_map").read_text().strip()
    checked(libc.unshare(CLONE_NEWNS), "unshare mount namespace")
    mount(None, "/", None, MS_REC | MS_PRIVATE)
    # Staging lives only in this mount namespace. bwrap canonicalizes even
    # --bind-fd paths, so placing it under a private host home does not work.
    # The small tmpfs holds mount points only; capture data stays on disk.
    mount("tmpfs", "/tmp", "tmpfs", flags=6, options="mode=0700,size=16m")
    os.chdir("/tmp")
    for name, fd in zip(("lower", "storage"), mounts):
        os.mkdir(name)
        # move_mount is syscall 429 on x86_64 and aarch64. Detached mounts
        # already belong to this namespace, courtesy of mountfsd.
        checked(libc.syscall(429, fd, b"", -100, name.encode(), 0x4),
                f"move_mount {name}")
    os.mkdir("merged")
    mount("overlay", "merged", "overlay", options=(
        "lowerdir=lower,upperdir=storage/rw,workdir=storage/work,userxattr"))
    expected = "original\n" if iteration == 1 else "copy-up 1\n"
    require(Path("merged/original").read_text() == expected, "overlay read/persistence")
    denied(lambda: Path("lower/original").write_text("bad"), "read-only lower",
           (errno.EROFS,))
    # Deliberately retain a directory FD: lack of a pathname alone would not
    # establish that ordinary permissions protect the caller's other files.
    def read_private():
        fd = os.open("private", os.O_RDONLY, dir_fd=raw)
        os.close(fd)
    private_errno = denied(read_private, "caller-owned private file via raw FD")
    # This directory is world writable: any denial here comes from more than
    # the ordinary permissions on the directory.
    def raw_create():
        fd = os.open("forbidden", os.O_CREAT | os.O_WRONLY, 0o600, dir_fd=raw)
        os.close(fd)
    raw_errno = denied(raw_create, "persistent transient-ID inode on raw mount")
    Path("merged/original").write_text(f"copy-up {iteration}\n")
    Path("merged/new").write_text(f"new {iteration}\n")
    if iteration == 2:
        require(Path("storage/home/save").read_text() == "save 1\n", "save persistence")
        require(not Path("merged/deleted").exists(), "whiteout persistence")
    else:
        Path("merged/deleted").unlink()
    Path("storage/home/save").write_text(f"save {iteration}\n")
    # A child userns maps managed root to the game's usual UID/GID. The
    # service's 64K mapping stays intact in the parent namespace.
    # setresuid reset dumpability; otherwise proc gives the mapping files to
    # initial-namespace root, which cannot be written by our managed root.
    checked(libc.prctl(4, 1, 0, 0, 0), "PR_SET_DUMPABLE")
    checked(libc.unshare(CLONE_NEWUSER), "unshare game namespace")
    Path("/proc/self/setgroups").write_text("deny")
    Path("/proc/self/uid_map").write_text(f"{uid} 0 1\n")
    Path("/proc/self/gid_map").write_text(f"{gid} 0 1\n")
    require(os.getuid() == uid and os.getgid() == gid, "game identity")
    Path("merged/child").write_text(f"child {iteration}\n")
    # Older service versions forget restrictions in a child namespace. Keep
    # going to test bwrap too, but report the persistent inode to the parent;
    # main then fails the probe after collecting both launches' results.
    try:
        raw_create()
    except OSError as error:
        require(error.errno in (errno.EPERM, errno.EACCES), f"nested raw write: {error}")
        child_raw_errno = error.errno
    else:
        child_raw_errno = 0
    os.close(raw)
    checked(libc.prctl(4, 1, 0, 0, 0), "PR_SET_DUMPABLE before bwrap")
    protected_payload(uid, helper, seccomp)
    return {"iteration": iteration, "game_uid": os.getuid(),
            "managed_uid_map": managed_map,
            "private_file_errno": private_errno, "raw_write_errno": raw_errno,
            "nested_raw_write_errno": child_raw_errno,
            "copy_up": True, "nested_write": True, "bwrap_seccomp_landlock": True}


def run_once(root, iteration, helper, seccomp):
    namespace = empty_namespace()
    mounts = []
    try:
        _, extra = call("io.systemd.NamespaceResource", "AllocateUserRange", {
            "name": f"sg-probe-{os.getpid()}-{iteration}", "size": 65536,
            "target": 0, "userNamespaceFileDescriptor": 0,
        }, [namespace])
        for fd in extra:
            os.close(fd)
        for directory, read_only in ((root / "lower", True), (root / "storage", False)):
            mounts.append(delegate(directory, namespace, read_only))
        sys.stdout.flush()
        pid = os.fork()
        if pid == 0:
            try:
                result = worker(namespace, mounts, root, iteration, os.getuid(), os.getgid(),
                                helper, seccomp)
                print(json.dumps(result), flush=True)
            except BaseException as error:
                print(f"probe worker: {error}", file=sys.stderr, flush=True)
                os._exit(1)
            os._exit(0)
        _, status = os.waitpid(pid, 0)
        require(status == 0, f"worker failed: wait status {status}")
    finally:
        for fd in mounts:
            os.close(fd)
        os.close(namespace)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, required=True,
                        help="existing scratch directory; fixtures are automatically removed")
    args = parser.parse_args()
    require(os.getuid() != 0, "run as a regular user, not root")
    require(os.uname().machine in ("x86_64", "aarch64"), "unsupported syscall ABI")
    checkout = Path(__file__).resolve().parents[2]
    helper = os.memfd_create("probe-landlock", os.MFD_CLOEXEC)
    os.write(helper, (checkout / "sandbox-landlock").read_bytes())
    seccomp = os.memfd_create("probe-seccomp", os.MFD_CLOEXEC)
    subprocess.run([sys.executable, "-I", str(checkout / "sandbox-seccomp")],
                   stdout=seccomp, check=True, env={"PATH": "/usr/bin:/bin"})
    nested_policy_enforced = True
    with tempfile.TemporaryDirectory(prefix="systemd-probe-", dir=args.work_dir.resolve()) as tmp:
        root = Path(tmp)
        for name in ("lower", "storage/rw", "storage/work", "storage/home", "outside"):
            (root / name).mkdir(parents=True, exist_ok=True)
        (root / "outside").chmod(0o777)
        (root / "outside/private").write_text("private\n")
        (root / "outside/private").chmod(0o600)
        for name in ("original", "deleted"):
            (root / "lower" / name).write_text("original\n")
        for iteration in (1, 2):
            run_once(root, iteration, helper, seccomp)
            require((root / "lower/original").read_text() == "original\n", "lower changed")
            for name in ("storage/rw/original", "storage/rw/new", "storage/rw/child",
                         "storage/home/save", "storage/rw/protected", "storage/home/protected"):
                st = (root / name).stat()
                require((st.st_uid, st.st_gid) == (os.getuid(), os.getuid()),
                        f"unexpected disk ownership: {name}: {st.st_uid}:{st.st_gid}")
            print(json.dumps({"iteration": iteration, "disk_owner": os.getuid(),
                              "persistent_storage": True}), flush=True)
            leaked = root / "outside/forbidden"
            if leaked.exists():
                nested_policy_enforced = False
                print(json.dumps({"iteration": iteration, "raw_inode_uid": leaked.stat().st_uid,
                                  "nested_policy_enforced": False}), flush=True)
                leaked.unlink()
    os.close(helper)
    os.close(seccomp)
    require(nested_policy_enforced,
            "nested namespace escaped transient-ID write policy; "
            "kernel overlay/bwrap/persistence passed, but this service version is unsuitable")
    print("PASS: managed namespace, idmapped kernel overlay, child UID, persistence, access checks")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        sys.exit(f"systemd backend probe: {error}")
