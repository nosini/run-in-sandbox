#!/usr/bin/env python3
"""The seccomp allowlist, SANDBOX_SECCOMP_POLICY=allowlist.

Runs real sandboxes, like test_security.py, whose helpers it borrows. With
TEST_SECCOMP_ALLOWLIST=1 every test of test_security.py's sandbox classes runs
a second time under the allowlist as well; see docs/seccomp-allowlist.md.
"""
import errno
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_security                                # noqa: E402

ROOT = test_security.ROOT
# Not a name of our own for SecurityTests: discovery would run it twice.
Security = test_security.SecurityTests.__dict__

# The numbers differ by table: x86_64, then i386 as int 0x80 takes them, and
# aarch64. io_setup stands in for any call left off the list: it would
# succeed, or fail with something other than ENOSYS, without the filter.
NATIVE = {
    "x86_64": {"io_setup": 206, "setns": 308, "chroot": 161, "keyctl": 250,
               "unshare": 272, "clone3": 435, "personality": 135},
    "aarch64": {"io_setup": 0, "setns": 268, "chroot": 51, "keyctl": 219,
                "unshare": 97, "clone3": 435, "personality": 92},
}
I386 = {"io_setup": 245, "setns": 346, "chroot": 61, "keyctl": 288, "unshare": 310,
        "clone3": 435, "personality": 136, "getpid": 20}
CLONE_NEWUSER, READ_IMPLIES_EXEC = 0x10000000, 0x0400000

# Prints what each call returned: the result, or minus its errno.
NATIVE_PROBE = r"""
import ctypes, json, os, socket, subprocess, sys, threading
nr = json.loads(sys.argv[1])
libc = ctypes.CDLL(None, use_errno=True)
def call(name, *args):
    r = libc.syscall(ctypes.c_long(nr[name]), *(ctypes.c_long(a) for a in args))
    return r if r >= 0 else -ctypes.get_errno()
aio = ctypes.c_ulong(0)
print("io_setup", call("io_setup", 1, ctypes.addressof(aio)))
print("setns", call("setns", -1, 0))
print("chroot", call("chroot", 0))
print("keyctl", call("keyctl", 0, 0, 0))
print("unshare", call("unshare", 0x10000000))
print("clone3", call("clone3", 0, 0))
print("personality", call("personality", 0xffffffff), call("personality", 0x0400000))
done = []
t = threading.Thread(target=done.append, args=(1,))
t.start(); t.join()
child = subprocess.run(["/bin/sh", "-c", "exit 3"]).returncode
a, b = socket.socketpair(); a.send(b"x")
print("thread", len(done), "child", child, "pair", b.recv(1).decode())
"""

# int 0x80 from 64-bit code is an i386 syscall, filtered by the i386 table.
I386_PROBE = r"""
import ctypes, json, mmap, sys
nr = json.loads(sys.argv[1])
page = mmap.mmap(-1, 4096, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS | 0x40,
                 prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
base = ctypes.addressof(ctypes.c_char.from_buffer(page))
def i386(n, a=0, b=0, c=0):
    code = b"\x53"                                     # push rbx
    for op, value in zip((0xB8, 0xBB, 0xB9, 0xBA), (n, a, b, c)):
        code += bytes([op]) + (value & 0xFFFFFFFF).to_bytes(4, "little")
    code += b"\xcd\x80\x5b\xc3"                        # int 0x80; pop rbx; ret
    ctypes.memmove(base, code, len(code))
    return ctypes.CFUNCTYPE(ctypes.c_int)(base)()
args = base + 2048                                     # socketcall's, below 4 GiB
ctypes.memmove(args, (ctypes.c_uint32 * 3)(38, 5, 0), 12)   # AF_ALG, SEQPACKET
print("io_setup", i386(nr["io_setup"], 1, args))
print("setns", i386(nr["setns"], -1, 0))
print("chroot", i386(nr["chroot"], 0))
print("keyctl", i386(nr["keyctl"]))
print("unshare", i386(nr["unshare"], 0x10000000))
print("clone3", i386(nr["clone3"]))
print("personality", i386(nr["personality"], 0xffffffff), i386(nr["personality"], 0x0400000))
print("getpid", int(i386(nr["getpid"]) > 0))
print("socketcall", i386(102, 1, args))
"""

# A 32-bit program of the system's 32-bit glibc, linked without its start
# files (no 32-bit development package needed): threads, a child, sockets.
PROBE32 = r"""
extern int printf(const char *, ...);
extern long syscall(long, ...);
extern int *__errno_location(void);
extern int pthread_create(unsigned long *, const void *, void *(*)(void *), void *);
extern int pthread_join(unsigned long, void **);
extern int socket(int, int, int);
extern int fork(void);
extern int waitpid(int, int *, int);
extern void exit(int);
extern void _exit(int);

static void *thread(void *arg) { return arg; }

static long call(long nr, long a, long b) {
    long r = syscall(nr, a, b, 0);
    return r < 0 ? -*__errno_location() : r;
}

__attribute__((force_align_arg_pointer)) void start(void) {
    unsigned long t; void *out = 0; int status = -1, child;
    int threaded = pthread_create(&t, 0, thread, (void *)42) == 0
        && pthread_join(t, &out) == 0 && out == (void *)42;
    child = fork();
    if (child == 0)
        _exit(7);
    waitpid(child, &status, 0);
    printf("thread %d child %d unix %d io_setup %ld setns %ld keyctl %ld alg %d\n",
           threaded, (status >> 8) & 0xff, socket(1, 1, 0) >= 0, call(245, 1, 0),
           call(346, -1, 0), call(288, 0, 0),
           socket(38, 5, 0) < 0 ? *__errno_location() : 0);
    exit(0);
}
"""


def results(stdout):
    return {line.split()[0]: line.split()[1:] for line in stdout.splitlines() if line.strip()}


class SeccompAllowlistTests(unittest.TestCase):
    reclaim = Security["reclaim"]
    cli = Security["cli"]
    run_guest = Security["run_guest"]
    launch_named = Security["launch_named"]
    attach = Security["attach"]

    def setUp(self):
        Security["setUp"](self)
        self.env["SANDBOX_SECCOMP_POLICY"] = "allowlist"
        for key in ("SANDBOX_SECCOMP", "SANDBOX_SEPARATE_UID"):
            self.env.pop(key, None)
        self.families = test_security.load_seccomp().socketcall_closable() \
            or os.uname().machine != "x86_64"

    def native(self):
        nr = NATIVE.get(os.uname().machine)
        if nr is None:
            self.skipTest(f"no syscall numbers here for {os.uname().machine}")
        (self.game / "probe.py").write_text(NATIVE_PROBE)
        return json.dumps(nr)

    def test_unlisted_calls_fail_with_enosys_and_the_denylist_keeps_its_errnos(self):
        nr = self.native()
        got = results(self.run_guest(f"python3 /game/probe.py '{nr}'").stdout)
        self.assertEqual(got["io_setup"], [str(-errno.ENOSYS)])
        # setns and chroot, which the denylist leaves alone, are off the list.
        self.assertEqual(got["setns"], [str(-errno.ENOSYS)])
        self.assertEqual(got["chroot"], [str(-errno.ENOSYS)])
        self.assertEqual(got["keyctl"], [str(-errno.EPERM)])
        self.assertEqual(got["unshare"], [str(-errno.EPERM)])
        self.assertEqual(got["clone3"], [str(-errno.ENOSYS)])
        self.assertEqual(got["personality"], ["0", str(-errno.ENOSYS)])
        self.assertEqual(got["thread"], ["1", "child", "3", "pair", "x"])
        # The default is still the denylist: the same call gets through it.
        del self.env["SANDBOX_SECCOMP_POLICY"]
        got = results(self.run_guest(f"python3 /game/probe.py '{nr}'").stdout)
        self.assertNotEqual(got["io_setup"], [str(-errno.ENOSYS)])
        self.assertNotEqual(got["personality"][1], str(-errno.ENOSYS))

    def test_log_mode_logs_what_the_allowlist_would_refuse(self):
        nr = self.native()
        self.env["SANDBOX_SECCOMP"] = "log"
        result = self.run_guest(f"python3 /game/probe.py '{nr}'")
        got = results(result.stdout)
        self.assertNotEqual(got["io_setup"], [str(-errno.ENOSYS)])
        self.assertNotEqual(got["setns"], [str(-errno.ENOSYS)])
        self.assertEqual(got["clone3"], [str(-errno.ENOSYS)])     # as ever
        self.assertIn("logging, NOT blocking", result.stderr)

    def test_an_unknown_policy_stops_the_launch(self):
        self.env["SANDBOX_SECCOMP_POLICY"] = "allowlst"
        result = self.cli("--headless", self.game, "/bin/sh", "-c", 'touch "$HOME/ran"',
                          check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SANDBOX_SECCOMP_POLICY=allowlst", result.stderr)
        self.assertIn("not starting unconfined", result.stderr)
        self.assertFalse(list(self.home.glob("game-sandboxes/*/home/ran")))

    def test_the_i386_abi_recovers_nothing(self):
        if os.uname().machine != "x86_64":
            self.skipTest("int 0x80 is x86_64's")
        (self.game / "probe.py").write_text(I386_PROBE)
        nr = json.dumps(I386)
        outside = subprocess.run(["python3", self.game / "probe.py", nr],
                                 capture_output=True, text=True, timeout=15)
        if outside.returncode != 0:
            self.skipTest("no 32-bit syscalls on this kernel (ia32_emulation=0)")
        got = results(self.run_guest(f"python3 /game/probe.py '{nr}'").stdout)
        self.assertEqual(got["io_setup"], [str(-errno.ENOSYS)])
        self.assertEqual(got["setns"], [str(-errno.ENOSYS)])
        self.assertEqual(got["chroot"], [str(-errno.ENOSYS)])
        self.assertEqual(got["keyctl"], [str(-errno.EPERM)])
        self.assertEqual(got["unshare"], [str(-errno.EPERM)])
        self.assertEqual(got["clone3"], [str(-errno.ENOSYS)])
        self.assertEqual(got["personality"], ["0", str(-errno.ENOSYS)])
        self.assertEqual(got["getpid"], ["1"])
        if self.families:
            self.assertEqual(got["socketcall"], [str(-errno.EAFNOSUPPORT)])

    def test_32_bit_programs_run(self):
        libc, loader = Path("/usr/lib/libc.so.6"), "/usr/lib/ld-linux.so.2"
        if os.uname().machine != "x86_64" or not libc.exists() or not shutil.which("gcc"):
            self.skipTest("needs x86_64, gcc and the 32-bit glibc in /usr/lib")
        source = self.base / "probe32.c"
        source.write_text(PROBE32)
        built = subprocess.run(
            ["gcc", "-m32", "-O1", "-nostdlib", "-nostartfiles", "-fno-pie", "-no-pie",
             "-e", "start", f"-Wl,--dynamic-linker={loader}", "-o", self.game / "probe32",
             source, libc], capture_output=True, text=True, timeout=60)
        if built.returncode != 0:
            self.skipTest(f"cannot link a 32-bit program here: {built.stderr.strip()}")
        result = self.run_guest("/game/probe32")
        self.assertEqual(result.returncode, 0, result.stderr)
        got = result.stdout.split()
        self.assertEqual(got[:6], ["thread", "1", "child", "7", "unix", "1"], result.stdout)
        self.assertEqual(got[6:12], ["io_setup", str(-errno.ENOSYS), "setns", str(-errno.ENOSYS),
                                     "keyctl", str(-errno.EPERM)])
        if self.families:
            self.assertEqual(got[12:], ["alg", str(errno.EAFNOSUPPORT)])

    def test_attached_programs_are_under_the_games_policy(self):
        # Started by the sandbox's own starter, they inherit its filter;
        # sandbox-attach's environment has no say in it.
        nr = self.native()
        name = "allowlist-attach-" + self.base.name
        self.launch_named(name, "/bin/sh", "-c", "echo ready; exec sleep 60")
        for policy in ("denylist", None):
            env = dict(self.env)
            env.pop("SANDBOX_SECCOMP_POLICY")
            if policy:
                env["SANDBOX_SECCOMP_POLICY"] = policy
            result = subprocess.run(
                [str(ROOT / "sandbox-attach"), "--name", name, "--exec", "--",
                 "python3", "/game/probe.py", nr],
                env=env, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            got = results(result.stdout)
            self.assertEqual(got["io_setup"], [str(-errno.ENOSYS)], policy)
            self.assertEqual(got["setns"], [str(-errno.ENOSYS)], policy)
            self.assertEqual(got["chroot"], [str(-errno.ENOSYS)], policy)

    def test_network_under_the_allowlist(self):
        if not shutil.which("pasta"):
            self.skipTest("pasta (package passt) is not installed")
        # Interfaces through netlink, a UDP and a TCP socket, a resolver
        # lookup; the internet itself is test_security's to check.
        result = self.run_guest(
            "python3 -c \"import socket\n"
            "print(len(socket.if_nameindex()) > 1)\n"
            "u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.connect(('192.0.2.1', 9))\n"
            "t = socket.socket(); t.bind(('127.0.0.1', 0)); t.listen()\n"
            "c = socket.create_connection(t.getsockname()); a, _ = t.accept()\n"
            "c.send(b'x'); print(a.recv(1).decode())\n"
            "print(bool(socket.getaddrinfo('localhost', 80)))\"", "--net")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.split(), ["True", "x", "True"])

    def test_wine_runs_under_the_allowlist(self):
        # The system's Wine, as a native command: prefix creation, wineserver,
        # services and both the 64-bit and the WoW64 cmd.exe.
        if not shutil.which("wine"):
            self.skipTest("wine is not installed")
        result = subprocess.run(
            [str(ROOT / "sandbox-game"), "--headless", "--env", "WINEDEBUG=-all",
             self.game, "/bin/sh", "-c",
             "wine cmd /c echo hello64 && "
             "wine 'C:\\windows\\syswow64\\cmd.exe' /c echo hello32; "
             "status=$?; wineserver -w; exit $status"],
            env=self.env, capture_output=True, text=True, stdin=subprocess.DEVNULL,
            timeout=600)
        self.assertEqual(result.returncode, 0, result.stderr[-3000:])
        self.assertIn("hello64", result.stdout)
        self.assertIn("hello32", result.stdout)


def allowlisted(base):
    """BASE's tests, under the allowlist."""
    def setUp(self):
        base.setUp(self)
        self.env["SANDBOX_SECCOMP_POLICY"] = "allowlist"
    return type(f"Allowlist{base.__name__}", (base,), {"setUp": setUp})


def load_tests(loader, standard, pattern):
    if os.environ.get("TEST_SECCOMP_ALLOWLIST") == "1":
        for base in (test_security.SecurityTests, test_security.SeparateUidTests,
                     test_security.SystemdBackendTests):
            standard.addTests(loader.loadTestsFromTestCase(allowlisted(base)))
    return standard


if __name__ == "__main__":
    unittest.main()
