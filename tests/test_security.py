#!/usr/bin/env python3
"""Run on the host: python3 -m unittest discover -s tests -v.

Uses real bubblewrap for filesystem/namespace checks and temporary command
recorders for display policy checks, without opening a game window.
"""
import ctypes
import importlib.util
from importlib.machinery import SourceFileLoader
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load_seccomp():
    # A script without .py, so spelled out; no bytecode left next to it.
    loader = SourceFileLoader("sandbox_seccomp", str(ROOT / "sandbox-seccomp"))
    module = importlib.util.module_from_spec(
        importlib.util.spec_from_loader(loader.name, loader))
    sys.dont_write_bytecode, saved = True, sys.dont_write_bytecode
    try:
        loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = saved
    return module


SOCKET_PROBE = r"""
import ctypes, errno, mmap, os, socket, sys


def refused(family, kind=socket.SOCK_DGRAM, pair=False):
    try:
        made = (socket.socketpair if pair else socket.socket)(family, kind)
    except OSError as e:
        return e.errno == errno.EAFNOSUPPORT
    for s in made if pair else (made,):
        s.close()
    return False


def i386(nr, a, b, c, via_socketcall=False):
    # Raw int 0x80 from 64-bit code, which the kernel takes as an i386
    # syscall; socketcall's argument block has to sit below 4 GiB (MAP_32BIT).
    page = mmap.mmap(-1, 4096, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS | 0x40,
                     prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    base = ctypes.addressof(ctypes.c_char.from_buffer(page))
    ctypes.memmove(base + 2048, (ctypes.c_uint32 * 3)(a, b, c), 12)
    regs = (102, 1, base + 2048, 0) if via_socketcall else (nr, a, b, c)
    code = b"\x53"                                     # push rbx
    for op, value in zip((0xB8, 0xBB, 0xB9, 0xBA), regs):  # mov eax/ebx/ecx/edx
        code += bytes([op]) + value.to_bytes(4, "little")
    code += b"\xcd\x80\x5b\xc3"                        # int 0x80; pop rbx; ret
    ctypes.memmove(base, code, len(code))
    return ctypes.CFUNCTYPE(ctypes.c_int)(base)()


AF_ALG, AF_VSOCK, AF_TIPC, AF_BLUETOOTH, AF_CAN = 38, 40, 30, 31, 29
if sys.argv[1] == "native":
    for family in (socket.AF_UNIX, socket.AF_INET, socket.AF_INET6, socket.AF_NETLINK):
        socket.socket(family, socket.SOCK_DGRAM).close()
    assert all(refused(f) for f in (AF_ALG, AF_VSOCK, AF_TIPC, AF_BLUETOOTH, AF_CAN))
    print("unix inet inet6 netlink open; alg vsock tipc bluetooth can refused")
    # socket() is 41 on x86_64, 198 on aarch64.
    nr = {"x86_64": 41, "aarch64": 198}[os.uname().machine]
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.syscall(nr, ctypes.c_long(1 << 32 | socket.AF_UNIX), socket.SOCK_STREAM, 0)
    assert fd == -1 and ctypes.get_errno() == errno.EAFNOSUPPORT, fd
    assert refused(AF_TIPC, socket.SOCK_SEQPACKET, pair=True)
    for s in socket.socketpair():
        s.close()
    print("high bits refused; socketpair tipc refused")
else:
    SEQPACKET = 5
    print(i386(359, socket.AF_UNIX, socket.SOCK_STREAM, 0),
          i386(359, AF_ALG, SEQPACKET, 0),
          i386(359, socket.AF_UNIX, socket.SOCK_STREAM, 0, via_socketcall=True),
          i386(359, AF_ALG, SEQPACKET, 0, via_socketcall=True))
"""


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="sandbox-game-test-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.home = self.base / "home"
        self.game = self.base / "games" / "Game"
        self.runtime = self.base / "run"
        for path in (self.home, self.game, self.runtime):
            path.mkdir(parents=True)
        self.env = {**os.environ, "HOME": str(self.home),
                    "XDG_RUNTIME_DIR": str(self.runtime),
                    "XDG_CONFIG_HOME": str(self.home / ".config"),
                    "REVIEW_SECRET": "must-not-leak"}
        for key in ("MANGOHUD", "PROTON_DIR", "MKXP_DIR", "XDG_DATA_HOME",
                    "SANDBOX_GPU_CARD"):
            self.env.pop(key, None)
        # A tools folder of the test's own, never the real one.
        self.tools = self.base / "tools"
        self.env["SANDBOX_TOOLS_DIR"] = str(self.tools)

    def cli(self, *args, check=True):
        # No terminal on stdin, or anything that asks first (--delete,
        # --reset-install) would wait for an answer that never comes.
        result = subprocess.run([str(ROOT / "sandbox-game"), *map(str, args)],
                                env=self.env, capture_output=True, text=True,
                                stdin=subprocess.DEVNULL, timeout=15)
        # A failed launch says why: CalledProcessError would keep stderr to itself.
        if check and result.returncode != 0:
            self.fail(f"sandbox-game exited {result.returncode}:\n{result.stderr}")
        return result

    def run_guest(self, script, *options):
        return self.cli("--headless", *options, self.game, "/bin/sh", "-ec", script)

    def test_name_derives_from_folder_and_rejects_traversal(self):
        alias = self.base / "alias"
        alias.symlink_to(self.game)
        name = self.cli("--print-name", self.game).stdout.strip()
        # The folder name alone, so a sandbox stays findable by eye and keeps
        # its saves when the library moves.
        self.assertEqual(name, "game")
        # realpath() resolves the selection, so a symlink is the same sandbox.
        self.assertEqual(name, self.cli("--print-name", alias).stdout.strip())
        # The name is a path component under ~/game-sandboxes, so it must not
        # be able to climb out of it.
        for invalid in ("../escape", ".", "..", "/tmp/escape"):
            self.assertNotEqual(self.cli("--name", invalid, "--print-name",
                                         self.game, check=False).returncode, 0)

    def test_capture_folder_is_deletable_after_a_run(self):
        name = self.cli("--print-name", self.game).stdout.strip()
        self.run_guest("true")
        capture = self.home / "game-sandboxes" / name
        self.assertTrue(capture.is_dir())
        # Overlayfs leaves workdir/work at mode 0000. Left alone it makes the
        # whole capture folder undeletable in a file manager until chmod-ed.
        stranded = capture / "work" / "work"
        self.assertTrue(not stranded.exists()
                        or os.access(stranded, os.R_OK | os.X_OK),
                        f"{stranded} left inaccessible")
        # The real complaint: this must not need a chmod first.
        shutil.rmtree(capture)

    def test_environment_is_allowlisted_and_overrides_are_explicit(self):
        result = self.run_guest('test -z "${REVIEW_SECRET+x}"; '
                                'test "$PATH" = /usr/bin:/bin; '
                                'test "$EXPLICIT" = yes; '
                                'test "$XDG_CONFIG_HOME" = "$HOME/.config"',
                                "--env", "EXPLICIT=yes")
        self.assertEqual(result.returncode, 0)

    def test_command_reaches_the_game_as_written(self):
        # systemd-run expands ${VAR} in its command line unless told not to,
        # which blanked `b=${f##*/}` in the NW.js launch script.
        # Only systemd-run does that, and it is only in the way when the
        # launcher can reach the user manager -- through the real runtime dir,
        # not the private one the other tests use. Without it this would pass
        # having tested nothing, so skip instead.
        if "XDG_RUNTIME_DIR" not in os.environ:
            self.skipTest("no XDG_RUNTIME_DIR, so no systemd user manager")
        self.env["XDG_RUNTIME_DIR"] = os.environ["XDG_RUNTIME_DIR"]
        literal = "${f##*/} ${HOME} ${REVIEW_SECRET+x}"
        result = self.cli("--headless", self.game, "/bin/sh", "-c",
                          'printf %s "$0"', literal)
        if "no systemd user manager" in result.stderr:
            self.skipTest("systemd user manager unreachable; scope not used")
        self.assertEqual(result.stdout, literal)

    def test_scope_leaves_the_desktop_a_core(self):
        # Needs the user manager, as above. Read from out here: the game sees
        # no cgroup tree. The scope is named after the launcher's PID.
        if "XDG_RUNTIME_DIR" not in os.environ:
            self.skipTest("no XDG_RUNTIME_DIR, so no systemd user manager")
        cpus = len(os.sched_getaffinity(0))
        if cpus < 2:
            self.skipTest("one CPU: nothing to leave over")
        self.env["XDG_RUNTIME_DIR"] = os.environ["XDG_RUNTIME_DIR"]
        proc = subprocess.Popen(
            [str(ROOT / "sandbox-game"), "--headless", self.game, "sleep", "60"],
            env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, text=True)
        self.addCleanup(proc.kill)
        uid = os.getuid()
        manager = Path(f"/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service")
        scope = None
        for _ in range(100):
            scope = next(manager.glob(f"**/sandbox-game-game-{proc.pid}.scope"), None)
            if scope or proc.poll() is not None:
                break
            time.sleep(0.1)
        cpu_max = (scope / "cpu.max").read_text().split() \
            if scope and (scope / "cpu.max").exists() else None
        self.cli("--stop", "game", check=False)
        stderr = proc.communicate(timeout=15)[1]
        if "no systemd user manager" in stderr:
            self.skipTest("systemd user manager unreachable; scope not used")
        if "cpu controller delegated" in stderr:
            # Said at launch, which is all the launcher can do about it.
            self.skipTest("no cpu controller delegated to the user manager (as warned)")
        self.assertIsNotNone(scope, stderr)
        self.assertEqual(cpu_max, [str((cpus - 1) * 100000), "100000"],
                         "no CPU cap, and no warning about it either")

    def test_sys_describes_devices_not_the_machine(self):
        # The device half of /sys, where GPUs, CPUs and input are found; not
        # the cgroup tree naming every app running, nor modules, kernel or
        # firmware. Nor, in /proc, the boot command line (the root
        # filesystem's UUID, often) or the loaded modules.
        result = self.run_guest("ls /sys; test -e /sys/devices/system/cpu/online; "
                                "for d in fs module kernel firmware power; do "
                                "test ! -e /sys/$d || echo exposed: $d; done; "
                                "for f in cmdline modules; do "
                                "test ! -s /proc/$f || echo exposed: $f; done")
        self.assertEqual(result.stdout.split(), ["block", "bus", "class", "dev", "devices"],
                         result.stderr)

    def test_home_devices_network_and_overlay_are_isolated(self):
        (self.home / "host-secret").write_text("private")
        (self.game / "original").write_text("original")
        shm = Path("/dev/shm") / self.base.name
        shm.write_text("host shared memory")
        self.addCleanup(shm.unlink, missing_ok=True)
        result = self.run_guest(
            'test ! -e "$HOME/host-secret"; '
            f'test ! -e /dev/shm/{shm.name}; '
            'test ! -e /dev/input; test ! -e /dev/snd; '
            'test ! -e /tmp/.Xauthority; test -z "${DISPLAY+x}"; '
            'printf changed > /game/original; '
            'printf save > "$HOME/save"; readlink /proc/self/ns/net')
        self.assertNotEqual(result.stdout.strip(), os.readlink("/proc/self/ns/net"))
        self.assertEqual((self.game / "original").read_text(), "original")
        name = self.cli("--print-name", self.game).stdout.strip()
        capture = self.home / "game-sandboxes" / name
        self.assertEqual((capture / "home" / "save").read_text(), "save")
        self.assertEqual((capture / "rw" / "original").read_text(), "changed")

    def test_guest_is_filtered_and_cannot_nest_user_namespaces(self):
        # unshare -U is refused twice over, by --disable-userns and the filter.
        # keyctl is refused by the filter alone: unfiltered, these arguments
        # get EINVAL rather than EPERM. 250 is keyctl on x86_64, 288 on i386.
        probe = ("import ctypes, errno, os, sys; "
                 "nr = {'x86_64': 250, 'i686': 288}.get(os.uname().machine); "
                 "l = ctypes.CDLL(None, use_errno=True); "
                 "sys.exit(nr is not None and "
                 "(l.syscall(nr, 0, 0, 0) != -1 or ctypes.get_errno() != errno.EPERM))")
        result = self.run_guest('grep -q "^Seccomp:[[:space:]]*2" /proc/self/status; '
                                '! unshare -U true 2>/dev/null; '
                                f'python3 -c "{probe}"')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_only_ordinary_socket_families(self):
        # The families games use open; the rest are refused, also when asked
        # for with high bits set (the kernel reads an int), through socketpair,
        # and through the i386 syscalls that 64-bit code reaches with int 0x80.
        if not load_seccomp().socketcall_closable():
            self.skipTest("this system's 32-bit glibc makes sockets through "
                          "socketcall, so families are not filtered")
        (self.game / "probe.py").write_text(SOCKET_PROBE)
        on_x86 = os.uname().machine == "x86_64"
        if on_x86:
            outside = subprocess.run(["python3", self.game / "probe.py", "i386"],
                                     capture_output=True, text=True, timeout=15)
            # No 32-bit syscalls here (ia32_emulation=0): nothing to check.
            on_x86 = outside.returncode == 0
        result = self.run_guest("python3 /game/probe.py native"
                                + ("; python3 /game/probe.py i386" if on_x86 else ""))
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(lines[0], "unix inet inet6 netlink open; "
                                   "alg vsock tipc bluetooth can refused")
        self.assertEqual(lines[1], "high bits refused; socketpair tipc refused")
        if on_x86:
            # Direct i386 socket() sees the family; socketcall() cannot.
            fd, alg, via_socketcall, alg_via_socketcall = map(int, lines[2].split())
            self.assertGreaterEqual(fd, 0)
            self.assertEqual((alg, via_socketcall, alg_via_socketcall), (-97, -97, -97))

    def test_socket_families_are_filtered_only_where_socketcall_can_close(self):
        seccomp = load_seccomp()

        def i386_libc(path, kernel):
            # An ELF header, one PT_NOTE program header, and the GNU ABI tag.
            header = b"\x7fELF\x01\x01\x01" + bytes(9) + struct.pack(
                "<HHIIIIIHHHHHH", 3, 3, 1, 0, 52, 0, 0, 52, 32, 1, 0, 0, 0)
            phdr = struct.pack("<8I", 4, 84, 0, 0, 32, 32, 4, 4)
            note = struct.pack("<3I", 4, 16, 1) + b"GNU\0" + struct.pack("<4I", 0, *kernel)
            path.write_bytes(header + phdr + note)
            return str(path)

        old = i386_libc(self.base / "old.so", (3, 2, 0))
        new = i386_libc(self.base / "new.so", (4, 3, 0))
        # An i386 ELF that does not say: assumed to use socketcall.
        untagged = self.base / "untagged.so"
        untagged.write_bytes(Path(new).read_bytes()[:52].replace(
            struct.pack("<HH", 32, 1), struct.pack("<HH", 32, 0)))
        self.assertEqual(seccomp.min_kernel(new), (4, 3, 0))
        self.assertEqual(seccomp.min_kernel(untagged), seccomp.UNKNOWN)
        self.assertIsNone(seccomp.min_kernel(sys.executable))   # not i386
        for libcs, closable in (((new,), True), ((new, old), False), ((), True),
                                ((new, str(untagged)), False)):
            seccomp.I386_LIBCS = libcs
            self.assertEqual(seccomp.socketcall_closable(), closable, libcs)
        # i386 syscalls come natively on an i386 host, as compat on x86_64;
        # neither table on aarch64.
        seccomp.I386_LIBCS = (old,)
        for native, filtered in ((seccomp.ARCH_X86, False), (seccomp.ARCH_X86_64, False),
                                 (seccomp.ARCH_AARCH64, True)):
            host = type("Lib", (), {"seccomp_arch_native": lambda self, n=native: n})()
            self.assertEqual(seccomp.families_filtered(host), filtered, hex(native))
        if os.uname().machine != "x86_64":
            return
        # With an old one installed, no socket rule at all: libseccomp would
        # carry it over to socketcall and cut 32-bit programs off from sockets.
        for libcs, filtered in (((new,), True), ((old,), False)):
            seccomp.I386_LIBCS = libcs
            lib = seccomp.load_lib()
            lib.seccomp_export_pfc.argtypes = [ctypes.c_void_p, ctypes.c_int]
            with tempfile.TemporaryFile() as out:
                lib.seccomp_export_pfc(seccomp.build(lib), out.fileno())
                out.seek(0)
                self.assertEqual(b'"socketcall"' in out.read(), filtered, libcs)

    def test_descriptors_from_outside_are_closed(self):
        # A descriptor inherited from outside names something past every
        # mount, and /proc/self/fd/N reopens it; so only 0-2 go in.
        (self.home / "host-secret").write_text("private")
        outside = os.open(self.home, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, outside)
        stray = subprocess.run([str(ROOT / "sandbox-game"), "--headless", self.game,
                                "/bin/sh", "-c", f"cat /proc/self/fd/{outside}/host-secret"],
                               env=self.env, capture_output=True, text=True,
                               pass_fds=(outside,), timeout=15)
        self.assertNotIn("private", stray.stdout)
        # Nor read through as it is, whatever its number: Landlock does not
        # stop that. 300 is past bash's own 255.
        secret = os.open(self.home / "host-secret", os.O_RDONLY)
        high = os.dup2(secret, 300)
        os.close(secret)
        self.addCleanup(os.close, high)
        stray = subprocess.run([str(ROOT / "sandbox-game"), "--headless", self.game,
                                "python3", "-c", "import os; print(os.read(300, 100))"],
                               env=self.env, capture_output=True, text=True,
                               pass_fds=(high,), timeout=15)
        self.assertNotIn("private", stray.stdout)
        self.assertIn("Bad file descriptor", stray.stderr)

    def test_game_can_reopen_its_own_output(self):
        # `echo ... >/dev/stderr` opens the file behind the descriptor afresh,
        # and from Nautilus that is the launch log, in no mount: allowed, as
        # far as the descriptor goes -- written, not read back.
        out, err = self.base / "out.log", self.base / "err.log"
        probe = ('echo out >/dev/stdout; echo err >>/dev/stderr; '
                 'python3 -c "open(\'/dev/stdout\').read()" 2>/dev/null '
                 '&& echo readable >>/dev/stderr || true')
        with open(out, "w") as o, open(err, "w") as e:
            rc = subprocess.run([str(ROOT / "sandbox-game"), "--headless", self.game,
                                 "/bin/sh", "-ec", probe], env=self.env, stdout=o,
                                stderr=e, stdin=subprocess.DEVNULL, timeout=15).returncode
        self.assertEqual(rc, 0, err.read_text())
        self.assertEqual(out.read_text(), "out\n")
        self.assertIn("err", err.read_text().splitlines())
        self.assertNotIn("readable", err.read_text())
        # An anonymous file takes no Landlock rule; the launch goes on, and
        # the descriptor works as it is.
        memfd = os.memfd_create("output")
        self.addCleanup(os.close, memfd)
        rc = subprocess.run([str(ROOT / "sandbox-game"), "--headless", self.game, "echo", "hi"],
                            env=self.env, stdout=memfd, stderr=subprocess.DEVNULL,
                            stdin=subprocess.DEVNULL, timeout=15).returncode
        os.lseek(memfd, 0, os.SEEK_SET)
        self.assertEqual((rc, os.read(memfd, 100)), (0, b"hi\n"))

    def test_reopened_output_goes_no_further_than_the_descriptor(self):
        # Rights follow how each descriptor was opened: a read-only stdout is
        # not written through /proc/self/fd, a write-only stdin not read.
        kept, secret = self.base / "kept", self.base / "secret"
        kept.write_text("keep\n")
        secret.write_text("secret\n")
        with open(kept) as ro, open(secret, "a") as wo:
            rc = subprocess.run([str(ROOT / "sandbox-game"), "--headless", self.game, "/bin/sh", "-c",
                                 "(echo overwritten >/proc/self/fd/1) 2>/dev/null && exit 3; "
                                 "(cat /proc/self/fd/0 >/dev/null) 2>/dev/null && exit 4; exit 0"],
                                env=self.env, stdin=wo, stdout=ro, stderr=subprocess.DEVNULL,
                                timeout=15).returncode
        self.assertEqual(rc, 0, "3: read-only stdout written, 4: write-only stdin read")
        self.assertEqual(kept.read_text(), "keep\n")
        # A terminal on stdout is bound onto /dev/console by bwrap. That is the
        # same file as stdout, so it opens as far as stdout goes -- but no
        # ioctls on a new descriptor, by either path; a rule of the console's
        # own used to allow them.
        probe = ('import errno, os, termios\n'
                 'def ioctl(path):\n'
                 '    try: termios.tcgetattr(os.open(path, os.O_WRONLY)); return "ok"\n'
                 '    except (OSError, termios.error) as e: return errno.errorcode[e.args[0]]\n'
                 'print("stdout", ioctl("/dev/stdout"), "console", ioctl("/dev/console"),\n'
                 '      file=open(os.environ["OUT"], "w"))\n')
        (self.game / "tty.py").write_text(probe)
        result_file = self.home / "game-sandboxes" / "game" / "home" / "result"
        leader, follower = os.openpty()
        self.addCleanup(os.close, leader)
        with os.fdopen(follower, "w") as tty:
            subprocess.run([str(ROOT / "sandbox-game"), "--headless", "--env",
                            "OUT=" + str(self.home / "result"), self.game,
                            "python3", "/game/tty.py"],
                           env=self.env, stdin=subprocess.DEVNULL, stdout=tty,
                           stderr=subprocess.DEVNULL, timeout=15)
        self.assertEqual(result_file.read_text().split(), ["stdout", "EACCES", "console", "EACCES"])

    def test_landlock_holds_the_game_to_its_mounts(self):
        # Wired in: the command starts with the helper, given the mounts.
        args = self.recorded_args()
        start = next(i for i, a in enumerate(args)
                     if a == "/run/sandbox-landlock" and args[i + 1:i + 2] == ["--ls"])
        rules = args[start + 1:args.index("--", start)]
        pairs = list(zip(rules[::2], rules[1::2]))
        for rule in (("--ls", "/"), ("--ro", "/usr"), ("--ro", "/etc"), ("--rw", "/game"),
                     ("--rw", str(self.home)), ("--rw", "/tmp"), ("--ls", "/dev"),
                     ("--rw", "/dev/null"), ("--rw", "/dev/shm"), ("--rw", "/dev/pts")):
            self.assertIn(rule, pairs)
        self.assertNotIn(("--rw", "/dev"), pairs)     # not wholesale: see the GPU test
        # /dev as bwrap makes it still works under that list.
        self.run_guest("echo x > /dev/null; head -c 8 /dev/urandom > /dev/shm/t; "
                       "test -s /dev/shm/t; rm /dev/shm/t; python3 -c 'import os, pty; pty.openpty()'")
        # And it holds: given a few paths, the helper refuses the rest -- here
        # on the host, since inside the sandbox nothing else is there to try.
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        if libc.syscall(ctypes.c_long(444), None, ctypes.c_size_t(0), ctypes.c_uint32(1)) < 1:
            self.skipTest("no Landlock in this kernel")
        (self.home / "host-secret").write_text("private")
        allowed = self.base / "allowed"
        allowed.mkdir()
        (allowed / "fine").write_text("fine")
        result = subprocess.run(
            [str(ROOT / "sandbox-landlock"), "--ro", "/usr", "--ro", "/etc", "--rw", str(allowed),
             "--", "/bin/sh", "-c",
             f'cat {allowed}/fine; echo w > {allowed}/new; cat {self.home}/host-secret'],
            capture_output=True, text=True, timeout=15)
        self.assertEqual(result.stdout, "fine")
        self.assertTrue((allowed / "new").exists())
        self.assertIn("Permission denied", result.stderr)

    def test_shared_tools_are_read_only(self):
        # Shared by every sandbox, so a game that could write here could plant
        # code that later runs inside every other game's sandbox.
        (self.tools / "Cheat Engine").mkdir(parents=True)
        (self.tools / "Cheat Engine" / "ce.exe").write_text("tool")
        result = self.run_guest('test "$(cat "/tools/Cheat Engine/ce.exe")" = tool; '
                                '! touch "/tools/Cheat Engine/planted" 2>/dev/null')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.tools / "Cheat Engine" / "planted").exists())

    def test_attach_uses_target_root_and_cwd(self):
        (self.home / "host-secret").write_text("private")
        self.tools.mkdir()
        (self.tools / "tool").write_text("tool")
        name = "attach-" + self.base.name
        proc = subprocess.Popen(
            [str(ROOT / "sandbox-game"), "--headless", "--name", name,
             str(self.game), "/bin/sh", "-c", 'echo ready; exec sleep 30'],
            env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def stop():
            if proc.poll() is None:
                proc.terminate()
            proc.communicate(timeout=10)
        self.addCleanup(stop)
        self.assertEqual(proc.stdout.readline().strip(), "ready")
        result = subprocess.run(
            [str(ROOT / "sandbox-attach"), "--name", name, "--exec", "--",
             "/bin/sh", "-ec", 'test "$(pwd)" = /; test -d /game; '
             'test ! -e "$HOME/host-secret"; test -z "${REVIEW_SECRET+x}"; '
             # A host path into the tools folder arrives as its /tools path.
             'test "$(cat "$0")" = tool; '
             'printf attached > "$HOME/attached"', str(self.tools / "tool")],
            env=self.env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.home / "game-sandboxes" / name / "home" / "attached").is_file())
        # A descriptor handed to sandbox-attach stays outside: what is attached
        # runs without Landlock, and namespaces do not revoke an open file.
        secret = os.open(self.home / "host-secret", os.O_RDONLY)
        self.addCleanup(os.close, secret)
        leak = subprocess.run(
            [str(ROOT / "sandbox-attach"), "--name", name, "--exec", "--", "/bin/sh", "-c",
             f"cat <&{secret}"],
            env=self.env, capture_output=True, text=True, pass_fds=(secret,), timeout=15)
        self.assertNotIn("private", leak.stdout)

    def test_preferences_save_explicit_permissions(self):
        bindir = self.home / ".local" / "bin"
        bindir.mkdir(parents=True)
        for script in ("sandbox-game", "sandbox-game-lib"):
            (bindir / script).symlink_to(ROOT / script)
        zenity = bindir / "zenity"
        zenity.write_text(
            '#!/bin/sh\ncase "$*" in\n'
            '  *--forms*) printf "%s\\n" "$TEST_FORM" ;;\n'
            'esac\n')
        zenity.chmod(0o755)
        self.env["PATH"] = str(bindir) + ":/usr/bin:/bin"
        self.env["NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"] = str(self.game)
        self.env["TEST_FORM"] = "\t".join([
            "Host X11 (other X apps can watch and control it)", "Off",
            "Newest installed (auto)", "Off", "This game only"])
        result = subprocess.run([str(ROOT / "Sandbox game preferences")],
                                env=self.env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        name = self.cli("--print-name", self.game).stdout.strip()
        settings = (self.home / ".config" / "sandbox-game" / "games" / name).read_text()
        for entry in ("host_x11=1", "wayland=0", "gamescope=0", "net=0"):
            self.assertIn(entry, settings.splitlines())

    def test_launcher_looks_past_junk_for_the_game(self):
        # An uninstaller alone at the top, the game in bin/: the game is what
        # gets launched, not the one candidate found first.
        (self.game / "unins000.exe").write_text("x")
        (self.game / "bin").mkdir()
        (self.game / "bin" / "game.exe").write_text("x")
        bindir = self.home / ".local" / "bin"
        bindir.mkdir(parents=True)
        # Where install.sh puts it: the stand-in below is no checkout.
        helpers = self.home / ".local" / "lib" / "sandbox-game"
        helpers.mkdir(parents=True)
        (helpers / "sandbox-game-lib").symlink_to(ROOT / "sandbox-game-lib")
        recorded = self.base / "launched"
        stub = bindir / "sandbox-game"
        stub.write_text('#!/bin/sh\n'
                        f'[ "$1" = --print-name ] && exec "{ROOT / "sandbox-game"}" "$@"\n'
                        f'printf "%s\\n" "$@" > "{recorded}"\n')
        stub.chmod(0o755)
        self.env["PATH"] = "/usr/bin:/bin"
        self.env["NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"] = str(self.game)
        result = subprocess.run([str(ROOT / "Sandbox game")], env=self.env,
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        launched = recorded.read_text().splitlines()
        self.assertIn("/game/bin/game.exe", launched)
        self.assertNotIn("/game/unins000.exe", launched)

    def test_nwjs_file_name_case_follows_the_preference(self):
        # An RPG Maker MV game: nwjs-casefold.js is bound in read-only and
        # package.json names it, until the preferences say casefold=0 -- then
        # it is neither bound nor left in package.json.
        (self.game / "www").mkdir()
        (self.game / "www" / "index.html").write_text("")
        (self.game / "package.json").write_text('{"name": "", "main": "www/index.html"}')
        nwjs = self.base / "nwjs"
        nwjs.mkdir()
        (nwjs / "nw").write_text("#!/bin/sh\n")
        (nwjs / "nw").chmod(0o755)
        self.env["NWJS_DIR"] = str(nwjs)
        bindir = self.home / ".local" / "bin"
        bindir.mkdir(parents=True)
        helpers = self.home / ".local" / "lib" / "sandbox-game"
        helpers.mkdir(parents=True)
        for helper in ("sandbox-game-lib", "nwjs-casefold.js"):
            (helpers / helper).symlink_to(ROOT / helper)
        recorded = self.base / "launched"
        stub = bindir / "sandbox-game"
        stub.write_text('#!/bin/sh\n'
                        f'[ "$1" = --print-name ] && exec "{ROOT / "sandbox-game"}" "$@"\n'
                        f'printf "%s\\0" "$@" > "{recorded}"\n')
        stub.chmod(0o755)
        self.env["PATH"] = "/usr/bin:/bin"
        self.env["NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"] = str(self.game)

        def launch():
            result = subprocess.run([str(ROOT / "Sandbox game")], env=self.env,
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            return recorded.read_text().split("\0")[:-1]

        def fix_package(args, casefold):
            # The package.json fix is handed to the command inside the
            # sandbox, after "_", the name and the app path.
            package = self.base / "package.json"
            package.write_text((self.game / "package.json").read_text())
            fix = args[args.index("_") + 3]
            subprocess.run(["python3", "-c", fix, str(package), "game", casefold],
                           check=True, capture_output=True)
            return json.loads(package.read_text())

        args = launch()
        mount = ["--ro", str(helpers / "nwjs-casefold.js"), "/nwjs-casefold.js"]
        self.assertIn(mount, [args[i:i + 3] for i in range(len(args))])
        on = fix_package(args, "1")
        self.assertEqual((on["name"], on["inject_js_start"]), ("game", "/nwjs-casefold.js"))
        # Turned off after a launch that had it on: the entry comes out again.
        (self.game / "package.json").write_text(json.dumps(on))
        name = self.cli("--print-name", self.game).stdout.strip()
        config = self.home / ".config" / "sandbox-game" / "games"
        config.mkdir(parents=True)
        (config / name).write_text("casefold=0\n")
        args = launch()
        self.assertNotIn("/nwjs-casefold.js", args)
        self.assertNotIn("inject_js_start", fix_package(args, ""))
        # A script the game injects itself is never replaced or removed.
        (self.game / "package.json").write_text('{"name": "x", "inject_js_start": "own.js"}')
        for casefold in ("1", ""):
            self.assertEqual(fix_package(args, casefold)["inject_js_start"], "own.js")

    def test_a_game_can_turn_off_the_defaults_gamescope_options(self):
        # The defaults say fullscreen at 1920x1080. A game's own "no override,
        # not fullscreen" has to be written, as an empty value, or the
        # defaults' options come back at launch; while an unchanged answer
        # keeps the game following the defaults.
        bindir = self.home / ".local" / "bin"
        bindir.mkdir(parents=True)
        for script in ("sandbox-game", "sandbox-game-lib"):
            (bindir / script).symlink_to(ROOT / script)
        zenity = bindir / "zenity"
        zenity.write_text('#!/bin/sh\ncase "$*" in\n'
                          '  *Gamescope\\ options*) printf "%s\\n" "$TEST_GS_FORM" ;;\n'
                          '  *--forms*) printf "%s\\n" "$TEST_FORM" ;;\n'
                          'esac\n')
        zenity.chmod(0o755)
        config = self.home / ".config" / "sandbox-game"
        config.mkdir(parents=True)
        (config / "defaults").write_text("gamescope_args=-f -W 1920 -H 1080\n")
        self.env["PATH"] = str(bindir) + ":/usr/bin:/bin"
        self.env["NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"] = str(self.game)
        self.env["TEST_FORM"] = "\t".join(["X11, in gamescope (private Xwayland)", "", "", "",
                                           "This game only"])
        name = self.cli("--print-name", self.game).stdout.strip()
        own = config / "games" / name

        def save(gs_form):
            self.env["TEST_GS_FORM"] = gs_form
            result = subprocess.run([str(ROOT / "Sandbox game preferences")], env=self.env,
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            return [l for l in own.read_text().splitlines() if l.startswith("gamescope_args")]

        def effective():
            return subprocess.run(["bash", "-c", f'. "{ROOT / "sandbox-game-lib"}"; '
                                   f'NAME={name}; cfg_get gamescope_args unset'],
                                  env=self.env, capture_output=True, text=True).stdout.strip()

        self.assertEqual(save("1920x1080\tYes"), [])            # as inherited: no line
        self.assertEqual(effective(), "-f -W 1920 -H 1080")
        self.assertEqual(save("Game default (no override)\tNo"), ["gamescope_args="])
        self.assertEqual(effective(), "")

    def test_mkxp_config_keeps_the_runtimes_settings(self):
        # However the runtime's mkxp.json is laid out -- here on one line,
        # after a comment with a brace in it -- its settings carry over into
        # the game's, with gameFolder added.
        mkxp = self.base / "mkxp-z"
        mkxp.mkdir()
        (mkxp / "mkxp-z").write_text("#!/bin/sh\n")
        (mkxp / "mkxp-z").chmod(0o755)
        (mkxp / "mkxp.json").write_text(
            '// the runtime config {\n'
            '{"rgssVersion": 3, "fontSub": ["Arial>Liberation Sans"], "RTP": ["/rtp"]}\n')
        self.recorded_args("--mkxp=" + str(mkxp))
        config = (self.home / "game-sandboxes" / "game" / "mkxp.json").read_text()
        for setting in ('"rgssVersion": 3', '"fontSub"', '"RTP"', '"gameFolder": "/game"'):
            self.assertIn(setting, config)
        self.assertTrue(config.startswith("// the runtime config {\n{\n"), config)

    def test_proton_wayland_does_not_fall_back_to_host_x(self):
        proton = self.base / "proton"
        proton.mkdir()
        binary = proton / "proton"
        binary.write_text("#!/bin/sh\nexit 0\n")
        binary.chmod(0o755)
        args = self.recorded_args("--wayland", "--proton=" + str(proton))
        self.assertNotIn("DISPLAY", args)
        self.assertNotIn("/tmp/.Xauthority", args)
        self.assertIn("STEAM_COMPAT_CONFIG", args)

    def test_ntsync_only_for_proton(self):
        # A young driver: Wine's thread synchronisation needs it, nothing else.
        proton = self.base / "proton"
        proton.mkdir()
        binary = proton / "proton"
        binary.write_text("#!/bin/sh\nexit 0\n")
        binary.chmod(0o755)
        args = self.recorded_args("--proton=" + str(proton))
        i = args.index("/dev/ntsync")
        self.assertEqual(args[i - 1:i + 2], ["--dev-bind-try", "/dev/ntsync", "/dev/ntsync"])
        self.assertNotIn("/dev/ntsync", self.recorded_args())

    def test_check_reports_every_protection(self):
        result = self.cli("--check", check=False)
        lines = result.stdout.splitlines()
        marks = {line.split()[1]: line.split()[0] for line in lines}
        self.assertEqual(list(marks), ["sandbox", "seccomp", "landlock", "limits", "sound",
                                       "gpu", "gamescope", "network", "ntsync"], result.stdout)
        self.assertTrue(set(marks.values()) <= {"ok", "--", "!!"}, result.stdout)
        # Exit status 1 exactly when something a sandbox should have is missing:
        # here at least the playback-only server, the test runtime dir having none.
        self.assertEqual(marks["sound"], "!!")
        self.assertEqual(result.returncode, 1)
        filtered = load_seccomp().socketcall_closable() or os.uname().machine != "x86_64"
        self.assertEqual(marks["seccomp"], "ok" if filtered else "--")

    def test_proton_under_gamescope_uses_its_xwayland(self):
        # Wine's Wayland driver needs protocols gamescope's server lacks, and
        # Proton's Wayland setting leaves Wine nothing else: under gamescope,
        # Proton is kept to gamescope's Xwayland even with --wayland.
        proton = self.base / "proton"
        proton.mkdir()
        (proton / "proton").write_text("#!/bin/sh\nexit 0\n")
        (proton / "proton").chmod(0o755)
        args = self.recorded_args("--gamescope", "--wayland", "--proton=" + str(proton))
        self.assertIn("gamescope", args)
        self.assertNotIn("STEAM_COMPAT_CONFIG", args)
        self.assertNotIn("--expose-wayland", args)
        # Not Proton: --wayland under gamescope still gets gamescope's socket.
        self.assertIn("--expose-wayland", self.recorded_args("--gamescope", "--wayland"))

    def test_machine_identifiers_are_stand_ins(self):
        read = lambda path: Path(path).read_text().strip()
        probe = ('printf "%s|%s|%s|" "$(cat /proc/sys/kernel/random/boot_id)" '
                 '"$(cat /proc/sys/kernel/hostname)" "$(ls -A /etc/ssh 2>/dev/null | wc -l)"; '
                 'for f in /sys/class/net/*/address; do printf "%s," "$(cat "$f")"; done; '
                 'printf "|%s" "$(cat /etc/machine-id 2>/dev/null)"')
        boot, host, ssh, macs, mid = self.run_guest(probe).stdout.split("|")
        self.assertNotEqual(boot, read("/proc/sys/kernel/random/boot_id"))
        self.assertEqual(host, "localhost")
        self.assertEqual(ssh, "0")
        self.assertEqual(macs.split(",")[:-1],
                         [""] * len(list(Path("/sys/class/net").glob("*/address"))))
        if not Path("/etc/machine-id").exists():
            return
        # A game of its own gets an id of its own, the same every launch...
        self.assertNotIn(mid, ("", read("/etc/machine-id")))
        self.assertEqual(self.run_guest("cat /etc/machine-id").stdout.strip(), mid)
        # ...but one that already has saves keeps what it saw before, in case
        # it keyed them to that.
        played = self.base / "games" / "Played"
        played.mkdir()
        (self.home / "game-sandboxes" / "played" / "home").mkdir(parents=True)
        (self.home / "game-sandboxes" / "played" / "home" / "save").write_text("x")
        seen = self.cli("--headless", played, "/bin/cat", "/etc/machine-id").stdout.strip()
        self.assertEqual(seen, read("/etc/machine-id"))

    def test_network_reaches_the_internet_and_nothing_else(self):
        if not shutil.which("pasta"):
            self.skipTest("pasta (package passt) is not installed")
        import socket
        ip = shutil.which("ip") or "/usr/sbin/ip"
        addrs = json.loads(subprocess.run([ip, "-j", "addr", "show", "scope", "global"],
                                          capture_output=True, text=True, check=True).stdout)
        own = [a["local"] for link in addrs for a in link.get("addr_info", [])
               if a.get("family") == "inet"]
        if not own:
            self.skipTest("no IPv4 address on this machine")
        routes = json.loads(subprocess.run([ip, "-j", "-4", "route", "show", "default"],
                                           capture_output=True, text=True).stdout or "[]")
        gateway = next((r["gateway"] for r in routes if "gateway" in r), None)
        if gateway is None:
            self.skipTest("no IPv4 default gateway to stand in for the LAN")
        # Something listening on this machine, as a local service would be.
        listener = socket.socket()
        listener.bind(("0.0.0.0", 0))
        listener.listen()
        self.addCleanup(listener.close)
        port = listener.getsockname()[1]
        try:
            socket.create_connection(("codeberg.org", 443), timeout=5).close()
            online = True
        except OSError:
            online = False
        (self.game / "probe.py").write_text(f"""
import errno, json, shutil, socket, subprocess
def tcp(host, port):
    try:
        socket.create_connection((host, port), timeout=5).close()
        return "open"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e))
def https():
    import urllib.request
    try:
        return urllib.request.urlopen("https://codeberg.org", timeout=10).status
    except OSError as e:
        return str(e)
def refused(make):
    try:
        make().close()
        return "allowed"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e))
ip = shutil.which("ip") or "/usr/sbin/ip"
def ip_rc(*args):
    return subprocess.run([ip, *args], capture_output=True).returncode
links = json.loads(subprocess.run([ip, "-j", "link"], capture_output=True, text=True).stdout)
iface = next(l["ifname"] for l in links if l["ifname"] != "lo")
print(json.dumps({{
    "resolv": open("/etc/resolv.conf").read(),
    "own": tcp({own[0]!r}, {port}),
    "gateway": tcp({gateway!r}, {port}),
    "internet": tcp("codeberg.org", 443) if {online} else "skipped",
    "https": https() if {online} else "skipped",
    "unlock": subprocess.run([ip, "rule", "del", "priority", "100"],
                             capture_output=True).returncode,
    # Last, so that one which did get through cannot spoil the checks above.
    "packet": refused(lambda: socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                            socket.htons(0x0003))),
    "raw_ip": refused(lambda: socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                            socket.IPPROTO_RAW)),
    "link_add": ip_rc("link", "add", "sbxtest0", "type", "dummy"),
    "addr_add": ip_rc("addr", "add", "10.9.9.9/32", "dev", iface),
    "link_down": ip_rc("link", "set", iface, "down"),
}}))
""")
        result = self.cli("--headless", "--net", self.game, "python3", "/game/probe.py",
                          check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        seen = json.loads(result.stdout)
        self.assertIn("nameserver 169.254.1.1", seen["resolv"])
        self.assertNotEqual(seen["own"], "open", "reached a service on this machine")
        # EACCES is the rule refusing it; ECONNREFUSED or a timeout would only
        # mean nothing answered there, which proves nothing about the LAN.
        self.assertEqual(seen["gateway"], "EACCES", "the LAN was not refused")
        self.assertNotEqual(seen["unlock"], 0, "the game could remove the LAN block")
        # The rules act at routing. Raw packets skip routing, and pasta passes
        # on whatever reaches it, so the LAN block holds only as long as the
        # game can write nothing but routed traffic -- and cannot add, change
        # or take down an interface. No capabilities over the namespace does
        # that; for packet sockets the filter refuses the family as well.
        self.assertIn(seen["packet"], ("EAFNOSUPPORT", "EPERM", "EACCES"),
                      "raw packet socket allowed")
        self.assertIn(seen["raw_ip"], ("EPERM", "EACCES"), "raw IP socket allowed")
        for change in ("link_add", "addr_add", "link_down"):
            self.assertNotEqual(seen[change], 0, f"the game could {change.replace('_', ' ')}")
        if online:
            self.assertEqual(seen["internet"], "open")
            # Verified, so the CA certificates made it in as well.
            self.assertEqual(seen["https"], 200)

    def test_network_helper_is_named_after_the_game_and_ends_with_it(self):
        # Proxies that route by process (mihomo's PROCESS-NAME) go by the
        # executable's file, so that is what has to carry the game's name.
        if not shutil.which("pasta"):
            self.skipTest("pasta (package passt) is not installed")
        import time
        names = {"named-game-pasta", "named-game-pasta.avx2"}
        def running():
            found = []
            for p in Path("/proc").glob("[0-9]*"):
                try:
                    exe = os.readlink(p / "exe")
                except OSError:
                    continue
                if os.path.basename(exe) in names:
                    found.append(exe)
            return found
        proc = subprocess.Popen([str(ROOT / "sandbox-game"), "--headless", "--net",
                                 "--name", "named-game", self.game, "sleep", "60"],
                                env=self.env, stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE, text=True)
        self.addCleanup(proc.stderr.close)
        self.addCleanup(proc.kill)
        for _ in range(100):
            if running() or proc.poll() is not None:
                break
            time.sleep(0.1)
        self.assertTrue(running(), f"no process runs from {names}: {proc.stderr.read() if proc.poll() is not None else ''}")
        self.cli("--stop", "named-game")
        proc.wait(timeout=10)
        time.sleep(0.3)
        self.assertEqual(running(), [], "pasta outlived the game")

    def test_stop_ends_only_the_named_sandbox_and_counts_as_clean(self):
        # "game" and "game-2": a prefix match would take the wrong one down.
        import time
        def launch(name):
            proc = subprocess.Popen(
                [str(ROOT / "sandbox-game"), "--headless", "--name", name,
                 self.game, "/bin/sh", "-c", "touch /tmp/up; exec sleep 60"],
                env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            self.addCleanup(proc.stderr.close)
            self.addCleanup(proc.kill)
            # Up once its bwrap is: that is what --stop goes looking for.
            home = self.home / "game-sandboxes" / name / "home"
            for _ in range(100):
                if subprocess.run(["pgrep", "-f", f"bwrap .*--bind {home} "],
                                  capture_output=True).stdout:
                    return proc
                time.sleep(0.1)
            self.fail(f"{name} did not start: {proc.stderr.read()}")
        first = launch("game")
        second = launch("game-2")
        time.sleep(0.3)

        missing = self.cli("--stop", "no-such-game", check=False)
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("no running sandbox named 'no-such-game'", missing.stderr)
        # An empty name is a mistake, not --stop-all: nothing may be stopped.
        empty = self.cli("--stop=", check=False)
        self.assertNotEqual(empty.returncode, 0)
        self.assertEqual(empty.stdout, "")

        self.assertEqual(self.cli("--stop", "game").stdout.strip(), "stopped game")
        first.wait(timeout=10)
        self.assertEqual(first.returncode, 0, first.stderr.read())
        self.assertFalse((self.home / "game-sandboxes" / "game" / ".stopped").exists())
        self.assertIsNone(second.poll(), "stopping 'game' also ended 'game-2'")

        self.assertEqual(self.cli("--stop-all").stdout.strip(), "stopped game-2")
        second.wait(timeout=10)
        self.assertEqual(second.returncode, 0)

    def test_list_reset_install_and_delete(self):
        (self.game / "www").mkdir()
        (self.game / "www" / "data.js").write_text("original\n")
        (self.game / "www" / "old.js").write_text("original\n")
        # Saves as three engines keep them in the install: RPG Maker MV/MZ,
        # Ren'Py, and RPG Maker XP/VX/VX Ace (a file, not a folder).
        # And one nested deep, where no depth limit may lose it.
        self.run_guest("mkdir -p /game/www/save /game/game/saves /game/a/b/c/d/e/saves; "
                       "echo s > /game/www/save/file1.rpgsave; "
                       "echo r > /game/game/saves/1-1-LT1.save; echo x > /game/Save01.rxdata; "
                       "echo d > /game/a/b/c/d/e/saves/slot.dat; "
                       "echo changed > /game/www/data.js; rm /game/www/old.js; "
                       'echo cfg > "$HOME/config"; sleep 1', "--name", "managed")
        capture = self.home / "game-sandboxes" / "managed"

        listing = self.cli("--list").stdout
        self.assertRegex(listing, r"(?m)^managed\s+\S+\s+(<1m|\dm)\s+\d{4}-\d\d-\d\d ")

        result = self.cli("--reset-install", "managed")
        for kept in ("www/save", "game/saves", "Save01.rxdata", "a/b/c/d/e/saves"):
            self.assertIn(f"kept: {kept}", result.stdout)
        seen = self.run_guest("cat /game/www/data.js /game/www/old.js /game/www/save/file1.rpgsave "
                              "/game/game/saves/1-1-LT1.save /game/Save01.rxdata "
                              "/game/a/b/c/d/e/saves/slot.dat",
                              "--name", "managed").stdout.split()
        self.assertEqual(seen, ["original", "original", "s", "r", "x", "d"])  # saves kept, the rest undone
        self.assertEqual((capture / "home" / "config").read_text(), "cfg\n")
        self.assertIn("nothing changed", self.cli("--reset-install", "managed").stdout)
        # A directory the game made and left empty is a change too.
        (capture / "rw" / "created-dir").mkdir()
        self.assertIn("created-dir", self.cli("--reset-install", "managed").stdout)
        self.assertFalse((capture / "rw" / "created-dir").exists())

        # Never while it runs, and only ever a name under ~/game-sandboxes.
        import time
        proc = subprocess.Popen([str(ROOT / "sandbox-game"), "--headless", "--name", "managed",
                                 self.game, "sleep", "60"], env=self.env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)
        for _ in range(100):
            if "running" in self.cli("--list").stdout:
                break
            time.sleep(0.1)
        refused = self.cli("--delete", "managed", check=False)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("is running", refused.stderr)
        self.cli("--stop", "managed")
        proc.wait(timeout=10)
        for bad in ("../home", "no-such-game"):
            self.assertNotEqual(self.cli("--delete", bad, check=False).returncode, 0)
        self.cli("--delete", "managed")
        self.assertFalse(capture.exists())

    def test_help_and_completion_know_every_option(self):
        # Taken from the option parser itself, so neither can fall behind it.
        import re
        script = (ROOT / "sandbox-game").read_text()
        parser = script[script.index('while [ "$#" -gt 0 ]; do'):]
        parser = parser[:parser.index("\ndone\n")]
        options = set(re.findall(r"^\s+(?:-h\|)?(--[a-z0-9-]+)(?:=\*)?\)", parser, re.M))
        self.assertIn("--proton", options)
        help_text = self.cli("--help").stdout
        completion = (ROOT / "completions" / "sandbox-game").read_text()
        for option in sorted(options):
            self.assertIn(option, help_text, f"--help does not mention {option}")
            self.assertRegex(completion, rf"(?<![\w-]){re.escape(option)}(?![\w-])",
                             f"completion does not offer {option}")

    def test_completion_lists_options_and_the_game_folder(self):
        bash_completion = Path("/usr/share/bash-completion/bash_completion")
        if not bash_completion.exists():
            self.skipTest("bash-completion is not installed")
        (self.game / "bin").mkdir()
        (self.game / "bin" / "game.exe").write_text("")
        (self.game / "read me.txt").write_text("")
        def tab(*words):
            script = f"""
                source {bash_completion} 2>/dev/null
                source {ROOT / "completions" / "sandbox-game"}
                COMP_WORDS=(sandbox-game "$@"); COMP_CWORD=$(( ${{#COMP_WORDS[@]}} - 1 ))
                COMP_LINE="${{COMP_WORDS[*]}}"; COMP_POINT=${{#COMP_LINE}}
                _sandbox_game sandbox-game "${{COMP_WORDS[COMP_CWORD]}}" \\
                    "${{COMP_WORDS[COMP_CWORD-1]}}" 2>/dev/null
                printf '%s\\n' "${{COMPREPLY[@]}}"
            """
            return subprocess.run(["bash", "-c", script, "tab", *words], env=self.env,
                                  capture_output=True, text=True).stdout.split("\n")[:-1]
        self.assertEqual(tab("--pro"), ["--proton"])      # plain; = is typed
        self.assertEqual(tab(str(self.game), "/g"), ["/game/"])
        self.assertEqual(sorted(tab(str(self.game), "/game/")),
                         ["/game/bin/", "/game/read me.txt"])
        self.assertEqual(tab(str(self.game), "/game/bin/g"), ["/game/bin/game.exe"])

    def preferences(self, form, game=None):
        """Run the preferences dialog on `game` with a zenity that answers
        every form with `form` and records what it was offered."""
        bindir = self.home / ".local" / "bin"         # where the dialog looks
        bindir.mkdir(parents=True, exist_ok=True)
        for script in ("sandbox-game", "sandbox-game-lib"):
            if not (bindir / script).exists():
                (bindir / script).symlink_to(ROOT / script)
        # The first form of a run is the main one; no answer is Cancel.
        offered = self.base / "offered"
        offered.unlink(missing_ok=True)
        (bindir / "zenity").write_text(
            f'#!/bin/sh\ncase "$*" in *--forms*)\n'
            f'  [ -e "{offered}" ] || printf "%s\\n" "$@" > "{offered}"\n'
            '  [ -n "$TEST_FORM" ] || exit 1\n'
            '  printf "%s\\n" "$TEST_FORM" ;; esac\n')
        (bindir / "zenity").chmod(0o755)
        game = game or self.game
        self.env["PATH"] = str(bindir) + ":/usr/bin:/bin"
        self.env["NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"] = str(game)
        self.env["TEST_FORM"] = "\t".join(form)
        subprocess.run([str(ROOT / "Sandbox game preferences")], env=self.env,
                       capture_output=True, timeout=15, check=True)       # Cancel exits 0
        lines = offered.read_text().splitlines()
        combos = {lines[i][len("--add-combo="):]: lines[i + 1][len("--combo-values="):].split("|")
                  for i in range(len(lines) - 1) if lines[i].startswith("--add-combo=")}
        name = self.cli("--print-name", game).stdout.strip()
        settings = self.home / ".config" / "sandbox-game" / "games" / name
        saved = dict(l.split("=", 1) for l in settings.read_text().splitlines() if "=" in l) \
            if settings.exists() else {}
        return combos, saved

    def test_display_choices_save_what_they_say(self):
        # One Display choice, saved as the keys the launcher reads. X11 in
        # gamescope is gamescope=0: the launcher puts gamescope around private
        # Xwayland itself, and a later switch to Wayland does not find it
        # pinned on.
        def save(display):
            return self.preferences([display, "Off", "Newest installed (auto)", "Off",
                                     "This game only"])[1]
        keys = lambda d: (d["wayland"], d["gamescope"], d["host_x11"])
        self.assertEqual(keys(save("X11, in gamescope (private Xwayland)")), ("0", "0", "0"))
        self.assertEqual(keys(save("Native Wayland")), ("1", "0", "0"))
        self.assertEqual(keys(save("Native Wayland, in gamescope")), ("1", "1", "0"))
        self.assertEqual(keys(save("Host X11 (other X apps can watch and control it)")),
                         ("0", "0", "1"))

    def test_preferences_offer_only_what_the_game_can_do(self):
        all_four = ["Native Wayland", "Native Wayland, in gamescope",
                    "X11, in gamescope (private Xwayland)",
                    "Host X11 (other X apps can watch and control it)"]
        # A Windows game: Wine's Wayland driver cannot run inside gamescope,
        # so that is not offered -- and one saved with it opens as what it
        # gets, X11 in gamescope.
        proton = self.base / "games" / "Win"
        proton.mkdir()
        (proton / "game.exe").write_text("x")
        name = self.cli("--print-name", proton).stdout.strip()
        config = self.home / ".config" / "sandbox-game" / "games"
        config.mkdir(parents=True)
        (config / name).write_text("wayland=1\ngamescope=1\n")
        combos, _ = self.preferences([], proton)                 # cancelled: nothing saved
        self.assertEqual(combos["Display"][0], "X11, in gamescope (private Xwayland)")
        self.assertEqual(sorted(combos["Display"]), sorted(set(all_four) - {all_four[1]}))
        self.assertIn("Proton version", combos)
        # A Ren'Py build without SDL's Wayland driver: X11 only.
        renpy = self.base / "games" / "Old"
        lib = renpy / "lib" / f"py3-linux-{os.uname().machine}"
        lib.mkdir(parents=True)
        (renpy / "renpy").mkdir()
        (renpy / "Old.sh").write_text("#!/bin/sh\n")
        (lib / "librenpython.so").write_bytes(b"\0SDL X11 video driver\0")
        combos, _ = self.preferences([], renpy)
        self.assertEqual(sorted(combos["Display"]), sorted(all_four[2:]))
        self.assertNotIn("Proton version", combos)            # not a Proton game
        # A native game that can do Wayland gets all four, and no Proton row.
        native = self.base / "games" / "Native"
        native.mkdir()
        (native / "run.sh").write_text("#!/bin/sh\n")
        combos, _ = self.preferences([], native)
        self.assertEqual(sorted(combos["Display"]), sorted(all_four))
        self.assertNotIn("Proton version", combos)
        self.assertNotIn("File names", combos)                # not an NW.js game

    def test_nwjs_games_can_turn_off_file_name_case_correction(self):
        rpgm = self.base / "games" / "Rpgm"
        (rpgm / "www").mkdir(parents=True)
        (rpgm / "www" / "index.html").write_text("")
        combos, _ = self.preferences([], rpgm)
        self.assertEqual(combos["File names"][0], "Ignore case, like Windows")  # the default
        _, saved = self.preferences(["Native Wayland", "", "Match exactly", "Off",
                                     "This game only"], rpgm)
        self.assertEqual(saved["casefold"], "0")
        combos, saved = self.preferences(["Native Wayland", "", "", "Off",
                                          "This game only"], rpgm)
        self.assertEqual(combos["File names"][0], "Match exactly")
        self.assertEqual(saved["casefold"], "0")                # untouched: kept

    def recorded_args(self, *options):
        """Record the final bwrap invocation; no display/audio service is used."""
        bindir = self.base / "bin"
        bindir.mkdir(exist_ok=True)
        recorder = bindir / "bwrap"
        recorder.write_text('#!/usr/bin/python3\nimport json,sys\n'
                            'if sys.argv[1:] == ["--help"]: print("--overlay")\n'
                            'else: print(json.dumps(sys.argv[1:]))\n')
        recorder.chmod(0o755)
        gs = bindir / "gamescope"
        gs.write_text("#!/bin/sh\nexit 99\n")
        gs.chmod(0o755)
        self.env["PATH"] = str(bindir) + ":/usr/bin:/bin"
        # A real Unix socket satisfies validation without a real compositor;
        # made once, however many times a test records.
        if not (self.runtime / "wayland-0").exists():
            import socket
            sock = socket.socket(socket.AF_UNIX)
            sock.bind(str(self.runtime / "wayland-0"))
            self.addCleanup(sock.close)
        self.env["WAYLAND_DISPLAY"] = "wayland-0"
        self.env["DISPLAY"] = ":123"
        return json.loads(self.cli(*options, self.game, "/bin/true").stdout)

    def test_title_bars_get_the_desktops_button_layout(self):
        # GTK-drawn title bars read their buttons from GNOME's settings, which
        # are not in the sandbox: that one value goes in, read-only, through
        # GLib's keyfile backend. Anything but a plain layout stays out.
        self.recorded_args()                          # sets up PATH and bin/
        gsettings = self.base / "bin" / "gsettings"
        keyfile = str(self.home / ".config" / "glib-2.0" / "settings" / "keyfile")
        saved = self.home / "game-sandboxes" / "game" / "gsettings"
        def with_layout(output, *options):
            gsettings.write_text(f"#!/bin/sh\nprintf '%s\\n' {output!r}\n")
            gsettings.chmod(0o755)
            saved.unlink(missing_ok=True)
            return self.recorded_args(*options)
        args = with_layout("'appmenu:minimize,maximize,close'")
        i = args.index(keyfile)
        self.assertEqual(args[i - 2:i], ["--ro-bind", str(saved)])
        self.assertIn("GSETTINGS_BACKEND", args)
        self.assertEqual(saved.read_text(), "[org/gnome/desktop/wm/preferences]\n"
                                            "button-layout='appmenu:minimize,maximize,close'\n")
        self.assertNotIn("GSETTINGS_BACKEND", with_layout("'close'\n[evil]\nkey=1"))
        self.assertNotIn("GSETTINGS_BACKEND", with_layout("'appmenu:close'", "--headless"))

    def test_default_display_is_private(self):
        args = self.recorded_args()
        self.assertIn("gamescope", args)
        self.assertNotIn("/tmp/.Xauthority", args)
        self.assertNotIn("DISPLAY", args)
        # Audio is always on: games that find no sound device refuse to start.
        self.assertIn(str(self.runtime / "pulse"), args)
        self.assertIn(str(self.runtime / "pipewire-0"), args)
        self.assertIn("--dev", args)
        for option in ("--unshare-user", "--disable-userns", "--seccomp"):
            self.assertIn(option, args)

    def test_gamescope_alone_is_told_of_the_desktop_socket(self):
        # Under gamescope the desktop's Wayland socket goes in away from the
        # runtime dir, named only in gamescope's environment, and the game's
        # own Landlock layer below gamescope connects to sockets only where it
        # may write -- which is nowhere above that one.
        host, inside = str(self.runtime / "wayland-0"), "/run/host-wayland/wayland-0"
        args = self.recorded_args()
        i = args.index(host)
        self.assertEqual(args[i - 1:i + 2], ["--ro-bind", host, inside])
        self.assertNotIn("WAYLAND_DISPLAY", args)       # not for the sandbox as a whole
        gs = args.index("gamescope")
        self.assertEqual(args[gs - 2:gs], ["env", "WAYLAND_DISPLAY=" + inside])
        inner = args.index("--", gs) + 1
        self.assertEqual(args[inner], "/run/sandbox-landlock")
        rules = args[inner + 1:args.index("--", inner)]
        for option in ("--unix-connect-where-writable", "--no-abstract-scope"):
            self.assertIn(option, rules)
        writable = [rules[k + 1] for k, r in enumerate(rules) if r == "--rw"]
        self.assertFalse([w for w in writable if inside == w or inside.startswith(w.rstrip("/") + "/")],
                         "a writable rule covers the desktop's socket")
        self.assertEqual(args[-1], "/bin/true")
        # Native Wayland talks to the desktop directly, as before.
        direct = self.recorded_args("--wayland")
        i = direct.index(host)
        self.assertEqual(direct[i + 1], str(self.runtime / "wayland-0"))
        self.assertNotIn("--unix-connect-where-writable", direct)

    def test_inner_domain_connects_only_where_it_may_write(self):
        # What keeps the game off the desktop's socket: from the inner layer, a
        # socket under a read-only rule refuses the connection; one under a
        # writable rule (gamescope's own, sound) takes it. The outer layer,
        # gamescope's, reaches both.
        landlock = str(ROOT / "sandbox-landlock")
        if subprocess.run([landlock, "--has-unix-connect"]).returncode != 0:
            self.skipTest("this kernel's Landlock cannot restrict connecting to sockets")
        import socket
        (self.base / "ro").mkdir()
        (self.base / "rw").mkdir()
        servers = []
        for path in (self.base / "ro" / "wayland-0", self.base / "rw" / "gamescope-0"):
            srv = socket.socket(socket.AF_UNIX)
            srv.bind(str(path))
            srv.listen()
            self.addCleanup(srv.close)
            servers.append(str(path))
        probe = self.base / "try.py"
        probe.write_text("import socket, sys\n"
                         "for p in sys.argv[1:]:\n"
                         "    c = socket.socket(socket.AF_UNIX)\n"
                         "    try: c.connect(p); print('connected')\n"
                         "    except OSError as e: print(e.strerror.replace(' ', '_'))\n")
        rules = ["--ro", "/usr", "--ro", "/proc", "--ro", str(probe), "--ro", str(ROOT),
                 "--ro", str(self.base / "ro"), "--rw", str(self.base / "rw")]
        outer = subprocess.run([landlock, *rules, "--", sys.executable, str(probe), *servers],
                               capture_output=True, text=True, timeout=15).stdout.split()
        inner = subprocess.run([landlock, *rules, "--", landlock, *rules,
                                "--unix-connect-where-writable", "--no-abstract-scope", "--",
                                sys.executable, str(probe), *servers],
                               capture_output=True, text=True, timeout=15).stdout.split()
        self.assertEqual(outer, ["connected", "connected"])
        self.assertEqual(inner, ["Permission_denied", "connected"])

    def test_inner_landlock_domain_keeps_out_of_its_parent(self):
        # The layer below gamescope: from inside it, gamescope's descriptors
        # are out of reach -- neither pidfd_getfd nor /proc/PID/fd. The parent
        # lets any process trace it, so Yama's ptrace_scope is not what says no.
        probe = self.base / "steal.py"
        probe.write_text(
            "import ctypes, os, subprocess, sys\n"
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "if sys.argv[1] == 'parent':\n"
            "    held = os.open('/etc/hostname', os.O_RDONLY)\n"
            "    libc.prctl(0x59616d61, ctypes.c_ulong(-1), 0, 0, 0)\n"
            "    sys.exit(subprocess.run(sys.argv[2:] + [sys.executable, __file__, 'child',\n"
            "                            str(os.getpid()), str(held)]).returncode)\n"
            "pid, fd = int(sys.argv[2]), int(sys.argv[3])\n"
            "got = libc.syscall(438, os.pidfd_open(pid), fd, 0)\n"
            "try:\n"
            "    os.close(os.open(f'/proc/{pid}/fd/{fd}', os.O_RDONLY)); via_proc = True\n"
            "except OSError:\n"
            "    via_proc = False\n"
            "print(got >= 0, via_proc)\n")
        landlock = str(ROOT / "sandbox-landlock")
        rules = ["--ro", "/usr", "--ro", "/proc", "--ro", "/etc", "--ro", str(self.base),
                 "--ro", str(ROOT)]
        def steal(*inner):
            return subprocess.run([landlock, *rules, "--", sys.executable, str(probe), "parent",
                                   *inner], capture_output=True, text=True, timeout=15).stdout.split()
        if steal() != ["True", "True"]:
            self.skipTest("taking a parent's descriptor is refused here even in one domain")
        self.assertEqual(steal(landlock, *rules, "--no-abstract-scope", "--"), ["False", "False"])

    def test_playback_only_server_replaces_the_desktop_sockets(self):
        # With the sandbox sound server up, the game gets its socket alone --
        # never the PipeWire one, which would get around it.
        import socket
        (self.runtime / "sandbox-pulse").mkdir()
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(str(self.runtime / "sandbox-pulse" / "native"))
        self.addCleanup(sock.close)
        args = self.recorded_args()
        bind = args.index(str(self.runtime / "sandbox-pulse" / "native"))
        self.assertEqual(args[bind - 1:bind + 2], ["--ro-bind",
                         str(self.runtime / "sandbox-pulse" / "native"),
                         str(self.runtime / "pulse" / "native")])
        self.assertNotIn(str(self.runtime / "pipewire-0"), args)
        self.assertNotIn(str(self.runtime / "pulse"), args)

    def test_games_can_play_but_not_record(self):
        # Against the real sandbox sound server (install.sh --restrict-audio).
        # Every refusal is checked by trying, not by reading permissions:
        # WirePlumber links streams with its own rights, whatever a client can
        # see, so only a recording that comes back empty proves anything.
        real_rt = os.environ.get("XDG_RUNTIME_DIR")
        if not real_rt or not Path(real_rt, "sandbox-pulse", "native").is_socket():
            self.skipTest("no playback-only sound server (install.sh --restrict-audio)")
        if not all(shutil.which(t) for t in ("pactl", "pacat", "parec")):
            self.skipTest("pactl, pacat and parec are needed (pulseaudio-utils)")
        self.env["XDG_RUNTIME_DIR"] = real_rt
        # Something else playing, outside the sandbox, silently: a stream the
        # game could try to record on its own.
        other = subprocess.Popen(["pacat", "--playback", "--volume=0",
                                  "--client-name=sandbox-test-other", "/dev/zero"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(other.wait)
        self.addCleanup(other.terminate)
        import time
        time.sleep(0.5)
        # Recording has to fail, and fail at once: a stream merely left
        # unlinked would hang every Proton game's start-up for 30 s, since
        # Wine opens one to probe formats. timeout's 124 means it hung.
        result = self.run_guest(r'''
            set +e    # refusals are what is being checked for
            recorded() {
                timeout 5 parec --raw "$@" > /tmp/recorded 2>/dev/null
                rc=$?
                printf '%s:%s' "$(wc -c < /tmp/recorded)" "$rc"
            }
            other=$(pactl list short sink-inputs 2>/dev/null | head -n1 | cut -f1)
            printf 'play=%s\n' "$(head -c 96000 /dev/zero | timeout 5 pacat --playback --raw \
                                   >/dev/null 2>&1; echo $?)"
            printf 'module=%s\n' "$(pactl load-module module-null-sink >/dev/null 2>&1; echo $?)"
            printf 'mic=%s\n' "$(recorded -d @DEFAULT_SOURCE@)"
            printf 'monitor=%s\n' "$(recorded -d @DEFAULT_MONITOR@)"
            printf 'other=%s\n' "$( [ -n "$other" ] && recorded --monitor-stream="$other" || echo none)"
        ''')
        seen = dict(line.split("=", 1) for line in result.stdout.split())
        self.assertEqual(seen["play"], "0", "playback failed")
        self.assertNotEqual(seen["module"], "0", "the game could load a sound server module")
        for what, label in (("mic", "the microphone"), ("monitor", "what is playing"),
                            ("other", "another app's stream")):
            if seen[what] == "none":
                continue
            recorded, rc = seen[what].split(":")
            self.assertEqual(recorded, "0", f"the game recorded {label}")
            self.assertNotEqual(rc, "124", f"recording {label} hung instead of failing")

    def test_gpu_render_nodes_only(self):
        # Drawing needs the render nodes. The card nodes add modesetting, and
        # with it far more of the driver: under gamescope they are there only
        # because it will not start unless the driver reports one, and
        # Landlock lets nothing open them; without gamescope they are not there.
        def landlock_rules(args):
            start = next(i for i, a in enumerate(args)
                         if a == "/run/sandbox-landlock" and args[i + 1:i + 2] == ["--ls"])
            rules = args[start + 1:args.index("--", start)]
            return list(zip(rules[::2], rules[1::2]))
        cards = [str(c) for c in Path("/dev").glob("dri/card*")]
        args = self.recorded_args()                            # gamescope
        self.assertNotIn("/dev/dri", args)
        for node in Path("/dev").glob("dri/renderD*"):
            self.assertIn(str(node), args)
            self.assertIn(("--rw", str(node)), landlock_rules(args))
        for card in cards:
            self.assertIn(card, args)
            self.assertNotIn(("--rw", card), landlock_rules(args))
        native = self.recorded_args("--wayland")
        self.assertFalse([a for a in native if a.startswith("/dev/dri/card")])
        self.env["SANDBOX_GPU_CARD"] = "1"
        if Path("/dev/dri").is_dir():
            self.assertIn("/dev/dri", self.recorded_args())

    def test_host_display_requires_explicit_option(self):
        args = self.recorded_args("--host-x11")
        self.assertNotIn("gamescope", args)
        self.assertIn("DISPLAY", args)
        self.assertNotIn("WAYLAND_DISPLAY", args)

    def test_native_wayland_does_not_expose_host_x(self):
        args = self.recorded_args("--wayland")
        self.assertNotIn("gamescope", args)
        self.assertNotIn("DISPLAY", args)
        self.assertIn("SDL_VIDEODRIVER", args)

    def test_renpy_without_wayland_driver_gets_xwayland(self):
        # Ren'Py builds its SDL into lib/*linux-ARCH/; one without the Wayland
        # driver cannot run under --wayland, so it gets the private Xwayland.
        (self.game / "renpy").mkdir()
        lib = self.game / "lib" / f"py3-linux-{os.uname().machine}"
        lib.mkdir(parents=True)
        engine = lib / "librenpython.so"
        engine.write_bytes(b"\0SDL X11 video driver\0")
        args = self.recorded_args("--wayland")
        self.assertIn("gamescope", args)
        self.assertNotIn("SDL_VIDEODRIVER", args)
        self.assertNotIn("DISPLAY", args)
        # A build with the driver keeps native Wayland.
        engine.write_bytes(b"\0SDL X11 video driver\0SDL Wayland video driver\0")
        args = self.recorded_args("--wayland")
        self.assertNotIn("gamescope", args)
        self.assertIn("SDL_VIDEODRIVER", args)
        # The arch folder may be a symlink; it is searched all the same.
        engine.write_bytes(b"\0SDL X11 video driver\0")
        real = self.game / "lib" / "real"
        lib.rename(real)
        lib.symlink_to("real")
        self.assertIn("gamescope", self.recorded_args("--wayland"))


if __name__ == "__main__":
    if not shutil.which("bwrap"):
        raise SystemExit("Run on the host: bwrap is required")
    unittest.main()
