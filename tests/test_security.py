#!/usr/bin/env python3
"""Run on the host: python3 -m unittest discover -s tests -v.

Uses real bubblewrap for filesystem/namespace checks and temporary command
recorders for display policy checks, without opening a game window.
"""
import ctypes
import glob
import importlib.util
from importlib.machinery import SourceFileLoader
import ipaddress
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
from unittest import mock

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


class RuntimeAndNetworkPolicyTests(unittest.TestCase):
    def test_architecture_specific_dotnet_root_precedes_generic_root(self):
        source = (ROOT / "sandbox-game").read_text()
        functions = source.split("dotnet_root()", 1)[1].split("\nDOTNET_ARGS=()", 1)[0]
        functions = "dotnet_root()" + functions
        with tempfile.TemporaryDirectory(prefix="sandbox-game-dotnet-test-") as tmp:
            base = Path(tmp)
            generic, specific, explicit = [base / name for name in ("generic", "specific", "explicit")]
            for root in (generic, specific, explicit):
                (root / "host" / "fxr").mkdir(parents=True)
                (root / "shared" / "Microsoft.NETCore.App").mkdir(parents=True)
            for machine, arch in (("x86_64", "X64"), ("aarch64", "ARM64")):
                env = {**os.environ, "DOTNET_ROOT": str(generic), "TEST_ARCH": machine,
                       f"DOTNET_ROOT_{arch}": str(specific)}
                def discover(spec="auto"):
                    return subprocess.run(
                        ["bash", "-c", 'uname() { echo "$TEST_ARCH"; };\n' + functions
                         + '\nfind_dotnet "$1"', "test", spec], env=env,
                        capture_output=True, text=True, check=True).stdout.strip()
                with self.subTest(arch=arch):
                    self.assertEqual(discover(), str(specific))
                    self.assertEqual(discover(str(explicit)), str(explicit))
                    env[f"DOTNET_ROOT_{arch}"] = str(base / "missing")
                    self.assertEqual(discover(), str(generic))
                    env.pop(f"DOTNET_ROOT_{arch}")
                    self.assertEqual(discover(), str(generic))

    def test_host_prohibitions_precede_lan_allowances_for_both_families(self):
        helper = (ROOT / "sandbox-game").read_text().split("NET_HELPER <<'EOF'", 1)[1]
        helper = helper.split("\n", 1)[1].split("\nEOF", 1)[0]
        addresses = ["192.0.2.5", "198.51.100.5", "2001:db8:1::5", "2001:db8:2::5"]
        links = [{"link_type": "ether", "addr_info": [
                    {"local": a, "prefixlen": 24 if ":" not in a else 64}]} for a in addresses]
        # A DHCPv6 address is a /128; its network comes as an on-link route.
        links.append({"ifname": "eth1", "link_type": "ether", "addr_info": [
                        {"local": "2001:db8:3::5", "prefixlen": 128}]})
        links.append({"ifname": "tun0", "link_type": "none", "addr_info": [
                        {"local": "fdfe:dcba:9876::1", "prefixlen": 126}]})
        routes = {"-4": [{"dst": "default", "gateway": "192.0.2.1", "dev": "eth1"},
                         {"dst": "203.0.113.0/24", "dev": "eth1"},
                         {"dst": "198.18.0.0/15", "dev": "tun0"},
                         {"dst": "1.1.1.1", "gateway": "192.0.2.1", "dev": "eth1"},
                         {"dst": "192.0.2.5", "dev": "eth1", "table": "local",
                          "type": "local"}],
                  "-6": [{"dst": "2001:db8:3::/64", "dev": "eth1"},
                         {"dst": "fd10:0:7::/48", "gateway": "fe80::1", "dev": "eth1"},
                         {"dst": "2001:db8:4::/64", "gateway": "fe80::1", "dev": "eth1"},
                         {"dst": "fdfe:dcba:9876::/64", "dev": "tun0"},
                         {"dst": "default", "dev": "tun0", "table": "2022"}]}
        allowed = [["192.0.2.0/24", "", ""], ["198.51.100.0/24", "", ""],
                   ["2001:db8::/32", "tcp", "443"]]
        for whole_lan in ("0", "1"):
            batches = {}
            def run(args, **kwargs):
                if args[1:3] == ["-j", "addr"]:
                    return subprocess.CompletedProcess(args, 0, stdout=json.dumps(links))
                if args[3:4] == ["route"]:
                    return subprocess.CompletedProcess(args, 0, stdout=json.dumps(routes[args[2]]))
                if "-batch" in args:
                    batches[args[1]] = kwargs["input"].splitlines()
                return subprocess.CompletedProcess(args, 0)
            with self.subTest(whole_lan=whole_lan), \
                    mock.patch.object(sys, "argv", ["helper", "123", "169.254.1.1", "pidfile",
                                                    "pasta", "02:00:00:00:00:01", whole_lan,
                                                    json.dumps(allowed)]), \
                    mock.patch("shutil.which", return_value="ip"), \
                    mock.patch("os.open", return_value=31), \
                    mock.patch("fcntl.ioctl", return_value=32), \
                    mock.patch("subprocess.run", side_effect=run):
                exec(compile(helper, "NET_HELPER", "exec"), {})
                for address in addresses:
                    rules = batches["-6" if ":" in address else "-4"]
                    host = next(r for r in rules if f" to {address} prohibit" in r)
                    allowance = next(r for r in rules if "priority 95" in r)
                    self.assertLess(int(host.split()[3]), int(allowance.split()[3]))
                    self.assertLess(rules.index(host), rules.index(allowance))
                # pasta answers only DNS at its address and passes the rest on.
                self.assertEqual([r for r in batches["-4"] if " to 169.254.1.1 " in r],
                                 [f"rule add priority 90 to 169.254.1.1 ipproto {p} dport 53"
                                  " lookup main" for p in ("udp", "tcp")])
                refused = {v: {r.split()[5] for r in batches[v] if "priority 100" in r}
                           for v in ("-4", "-6")}
                if whole_lan == "0":
                    self.assertLessEqual({"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4",
                                          "255.255.255.255/32"}, refused["-4"])
                    self.assertLessEqual({"2001:db8:2::/64", "2001:db8:3::/64", "fc00::/7",
                                          "ff00::/8"}, refused["-6"])
                # Not the internet behind a router or a tunnel.
                self.assertFalse({"1.1.1.1/32", "198.18.0.0/15"} & refused["-4"])
                self.assertFalse({"2001:db8:4::/64", "fdfe:dcba:9876::/64"} & refused["-6"])
                if whole_lan == "1":
                    self.assertEqual(refused, {"-4": {"0.0.0.0/8"}, "-6": set()})


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
        for key in ("MANGOHUD", "PROTON_DIR", "MKXP_DIR", "PGMMV_DIR", "SANDBOX_DIALOG", "XDG_DATA_HOME",
                    "SANDBOX_GPU_CARD", "DOTNET_ROOT", "DOTNET_ROOT_X64", "DOTNET_ROOT_ARM64"):
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

    def test_manager_install_then_launch_keeps_one_prefix(self):
        import runpy
        Library = runpy.run_path(str(ROOT / "sandbox-manager-lib.py"))["Library"]
        library = Library(ROOT / "sandbox-game", ROOT, ROOT / "Sandbox game", home=self.home,
                          config=self.home / ".config/sandbox-game")
        proton = self.base / "test-proton"
        proton.mkdir()
        (proton / "proton").write_text('#!/bin/sh\nshift\nexec "$@"\n')
        (proton / "proton").chmod(0o755)
        installer = self.game / "setup.exe"
        installer.write_text('''#!/bin/sh
set -e
test "$STEAM_COMPAT_DATA_PATH" = /compat
test ! -e /proc/self/fd/18
mkdir -p /compat/pfx/drive_c/Test
printf '#!/bin/sh\nprintf played > /compat/pfx/drive_c/Test/played\n' > /compat/pfx/drive_c/Test/play.exe
chmod +x /compat/pfx/drive_c/Test/play.exe
''')
        installer.chmod(0o755)
        entry = library.create("Installed game", str(proton))
        def run(**kwargs):
            command, _ = library.command(entry, **kwargs)
            self.cli("--headless", *[word for word in command[1:] if not word.startswith("--gamescope")])
        run(installer=installer)
        entry["program"] = library.programs(entry)[0][0]
        run()
        self.assertEqual((library.capture(entry["name"]) / "compat/pfx/drive_c/Test/played").read_text(), "played")
        self.assertEqual(json.loads((library.capture(entry["name"]) / "source.json").read_text())["directory"],
                         entry["directory"])

    def test_same_sandbox_cannot_be_launched_concurrently(self):
        import fcntl
        process = subprocess.Popen([str(ROOT / "sandbox-game"), "--headless", "--name", "exclusive",
                                    str(self.game), "/bin/sleep", "30"], env=self.env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def stop_process():
            if process.poll() is None:
                process.kill()
            process.wait(timeout=8)
        self.addCleanup(stop_process)
        lock = self.home / "game-sandboxes/exclusive.run-lock"
        deadline = time.monotonic() + 8
        locked = False
        while time.monotonic() < deadline:
            try:
                with lock.open("a") as stream:
                    try:
                        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        locked = True
                        break
            except FileNotFoundError:
                pass
            time.sleep(0.05)
        self.assertTrue(locked, "first launch never acquired the sandbox lock")
        result = self.cli("--headless", "--name", "exclusive", self.game, "/bin/true", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already running", result.stderr)
        deleting = self.cli("--delete", "exclusive", check=False)
        self.assertNotEqual(deleting.returncode, 0)
        self.assertIn("running", deleting.stderr)
        while time.monotonic() < deadline:
            running = subprocess.run([str(ROOT / "sandbox-attach"), "--list"], env=self.env,
                                     capture_output=True, text=True, check=True)
            if "exclusive" in running.stdout:
                break
            time.sleep(0.05)
        self.cli("--stop", "exclusive")
        process.wait(timeout=8)

    def test_launch_refused_by_the_lock_creates_nothing(self):
        import fcntl
        sandboxes = self.home / "game-sandboxes"
        sandboxes.mkdir()
        # As --delete holds it while removing the capture folder.
        with (sandboxes / "held.run-lock").open("a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            result = self.cli("--headless", "--name", "held", self.game, "/bin/true", check=False)
        self.assertIn("already running", result.stderr)
        self.assertFalse((sandboxes / "held").exists())

    def test_only_the_launcher_holds_the_sandbox_lock(self):
        # fuse-overlayfs daemonizes, so it must not take the lock along.
        self.use_fuse_overlay()
        import time
        merged = self.home / "game-sandboxes/held/merged"
        # Last, after a failed test killed the launcher before its cleanup.
        self.addCleanup(lambda: os.path.ismount(merged) and subprocess.run(["fusermount3", "-u", str(merged)]))
        process = subprocess.Popen([str(ROOT / "sandbox-game"), "--headless", "--name", "held",
                                    str(self.game), "/bin/sleep", "30"], env=self.env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(process.wait)
        self.addCleanup(process.kill)
        lock = str(self.home / "game-sandboxes/held.run-lock")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            running = subprocess.run([str(ROOT / "sandbox-attach"), "--list"], env=self.env,
                                     capture_output=True, text=True, check=True)
            if "held" in running.stdout:
                break
            time.sleep(0.05)
        self.assertTrue(os.path.ismount(merged), "fuse-overlayfs never mounted the game")
        holders = set()
        for fd in Path("/proc").glob("[0-9]*/fd/*"):
            try:
                if os.readlink(fd) == lock:
                    holders.add(int(fd.parts[2]))
            except OSError:
                pass
        self.assertEqual(holders, {process.pid})
        self.cli("--stop", "held")
        process.wait(timeout=10)

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

    def test_game_folder_must_be_a_folder(self):
        # A file there would reach bwrap as the overlay's lower layer, which
        # fails with a bare "Invalid argument".
        exe = self.game / "game.exe"
        exe.touch()
        result = self.cli("--headless", exe, "/game/game.exe", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be the game's folder", result.stderr)

    def test_proton_writes_go_nowhere(self):
        proton = self.base / "proton"
        proton.mkdir()
        (proton / "dist.lock").write_text("")
        (proton / "proton").write_text("#!/bin/sh -e\nprintf locked > /proton/dist.lock\n"
                                       "printf new > /proton/new\n")
        (proton / "proton").chmod(0o755)
        self.cli("--headless", "--proton=" + str(proton), self.game, "/game/game.exe")
        self.assertEqual((proton / "dist.lock").read_text(), "")
        self.assertEqual(sorted(p.name for p in proton.iterdir()), ["dist.lock", "proton"])

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

    def use_fuse_overlay(self):
        if not shutil.which("fuse-overlayfs") or not Path("/dev/fuse").exists():
            self.skipTest("fuse-overlayfs and /dev/fuse are needed")
        bwrap = shutil.which("bwrap")
        self.assertIsNotNone(bwrap, "bubblewrap is needed")
        wrappers = self.base / "fuse-bin"
        wrappers.mkdir()
        # Only hide the built-in overlay capability. All launches still use
        # real bubblewrap and real FUSE mounts.
        wrapper = wrappers / "bwrap"
        wrapper.write_text("#!/usr/bin/env python3\nimport os, sys\n"
                           "if sys.argv[1:] == ['--help']: sys.exit(0)\n"
                           f"os.execv({bwrap!r}, ['bwrap', *sys.argv[1:]])\n")
        wrapper.chmod(0o755)
        self.env["PATH"] = str(wrappers) + os.pathsep + self.env["PATH"]

    def test_fuse_paths_are_literal_and_writes_stay_in_the_capture(self):
        self.use_fuse_overlay()
        original_home = self.home
        for part in ("game", "home", "proton"):
            for index, name in enumerate(("plain", "comma,dir", "colon:dir", "back\\slash")):
                with self.subTest(part=part, name=name):
                    folder = self.base / part / name
                    folder.mkdir(parents=True)
                    self.home = folder if part == "home" else original_home
                    self.env["HOME"] = str(self.home)
                    game = folder if part == "game" else self.game
                    (game / "asset").write_text("original")
                    (game / "removed").write_text("original")
                    options = []
                    if part == "proton":
                        (folder / "proton").write_text(
                            '#!/bin/sh\nshift\nprintf changed > /proton/runtime-write\nexec "$@"\n')
                        (folder / "proton").chmod(0o755)
                        options = [f"--proton={folder}"]
                    # Each case has fresh persistent state, then reuses it.
                    sandbox = f"literal-{part}-{index}"
                    capture = self.home / "game-sandboxes" / sandbox
                    result = self.cli("--headless", "--name", sandbox, *options, game,
                                      "/bin/sh", "-ec", 'cat /game/asset; '
                                      'printf changed > /game/asset; rm /game/removed')
                    self.assertEqual(result.stdout, "original")
                    self.assertEqual((game / "asset").read_text(), "original")
                    self.assertTrue((game / "removed").exists())
                    self.assertEqual((capture / "rw/asset").read_text(), "changed")
                    self.assertEqual(self.cli("--headless", "--name", sandbox, *options, game,
                                             "/bin/sh", "-ec", 'test ! -e /game/removed; '
                                             'cat /game/asset').stdout, "changed")
                    self.assertFalse(os.path.ismount(capture / "merged"))
                    self.assertFalse((capture / "proton").exists())
                    self.assertFalse((folder / "runtime-write").exists())

    def test_fuse_lower_paths_cannot_add_an_outside_directory(self):
        self.use_fuse_overlay()
        for proton in (False, True):
            with self.subTest(proton=proton):
                lower = self.base / f"lower-{proton}"
                outside = self.base / f"outside-{proton}"
                for directory in (lower, outside):
                    directory.mkdir()
                (outside / "private-marker").write_text("outside the chosen directory")
                selected = Path(str(lower) + ":" + str(outside))
                selected.mkdir(parents=True)
                (selected / "selected-marker").write_text("selected")
                options = []
                if proton:
                    # Let the old, wrongly split lower layer start too, so
                    # the test detects the unintended contents in /proton.
                    for directory in (lower, selected):
                        runtime = directory / "proton"
                        runtime.write_text('#!/bin/sh\nshift\nexec "$@"\n')
                        runtime.chmod(0o755)
                    options = [f"--proton={selected}"]
                mount = "/proton" if proton else "/game"
                result = self.cli("--headless", "--name", f"layers-{proton}", *options,
                                  self.game if proton else selected, "/bin/sh", "-ec",
                                  f'test ! -e {mount}/private-marker; cat {mount}/selected-marker')
                self.assertEqual(result.stdout, "selected")

    def test_environment_is_allowlisted_and_overrides_are_explicit(self):
        result = self.run_guest('test -z "${REVIEW_SECRET+x}"; '
                                'test "$PATH" = /usr/bin:/bin; '
                                'test "$EXPLICIT" = yes; '
                                'test "$XDG_CONFIG_HOME" = "$HOME/.config"',
                                "--env", "EXPLICIT=yes")
        self.assertEqual(result.returncode, 0)

    def test_game_starts_with_no_signals_ignored(self):
        # sandbox-landlock is Python, which ignores SIGPIPE and SIGXFSZ; an
        # ignored signal stays ignored across exec.
        result = self.run_guest("grep '^SigIgn:' /proc/self/status")
        self.assertEqual(result.stdout.split(), ["SigIgn:", "0" * 16])

    def test_landlock_helper_runs_no_code_from_the_game_home(self):
        # sandbox-landlock is Python and runs before it restricts itself, with
        # the capture home as $HOME. A .pth file the game left in its user
        # site-packages would run there, outside Landlock, at the next launch.
        self.run_guest("true")
        version = "python%d.%d" % sys.version_info[:2]
        site = (self.home / "game-sandboxes" / "game" / "home" / ".local" / "lib"
                / version / "site-packages")
        site.mkdir(parents=True)
        (site / "planted.pth").write_text(
            "import os; open(os.path.expanduser('~/planted-ran'), 'w').close()\n")
        self.run_guest("true")
        self.assertFalse((site.parents[3] / "planted-ran").exists(),
                         "sandbox-landlock ran a .pth file from the game's home")

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
        # Nor is it in the sandbox's pid 1, bwrap, which keeps its own
        # environment: the outer bwrap's child, read from out here.
        outer = next(p for p in Path("/proc").glob("[0-9]*")
                     if (p / "cmdline").read_bytes().split(b"\0")[0].endswith(b"bwrap")
                     and f"game-sandboxes/{name}/home".encode() in (p / "cmdline").read_bytes()
                     and os.path.samestat(os.stat(p / "ns" / "user"), os.stat("/proc/self/ns/user")))
        pid1 = (outer / "task" / outer.name / "children").read_text().split()[0]
        self.assertEqual(Path("/proc", pid1, "environ").read_bytes(), b"")
        # A descriptor handed to sandbox-attach stays outside: what is attached
        # runs without Landlock, and namespaces do not revoke an open file.
        secret = os.open(self.home / "host-secret", os.O_RDONLY)
        self.addCleanup(os.close, secret)
        leak = subprocess.run(
            [str(ROOT / "sandbox-attach"), "--name", name, "--exec", "--", "/bin/sh", "-c",
             f"cat <&{secret}"],
            env=self.env, capture_output=True, text=True, pass_fds=(secret,), timeout=15)
        self.assertNotIn("private", leak.stdout)

    def test_attached_programs_take_nothing_from_the_game(self):
        # What is attached runs above the game's Landlock domain, able to read
        # the game's memory, so the game does not get to choose what it runs:
        # no rc file from the game's $HOME for the shell, no PATH from a
        # process the game started -- here a "wineserver" of its own -- for a
        # native command.
        name = "env-" + self.base.name
        proc = subprocess.Popen(
            [str(ROOT / "sandbox-game"), "--headless", "--name", name, str(self.game),
             "/bin/sh", "-c",
             'mkdir "$HOME/evil"; printf "#!/bin/sh\\ntouch \\"\\$HOME/planted-ran\\"\\n" '
             '> "$HOME/evil/true"; chmod +x "$HOME/evil/true"; '
             'echo "touch \\"\\$HOME/planted-ran\\"" > "$HOME/.bashrc"; '
             'cp /bin/sleep "$HOME/wineserver"; '
             'PATH="$HOME/evil:/usr/bin:/bin" "$HOME/wineserver" 30 & '
             'sleep 0.3; echo ready; exec sleep 30'],
            env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def stop():
            if proc.poll() is None:
                proc.terminate()
            proc.communicate(timeout=10)
        self.addCleanup(stop)
        self.assertEqual(proc.stdout.readline().strip(), "ready")
        home = self.home / "game-sandboxes" / name / "home"
        for mode in (["--exec", "--", "true"], ["--shell"]):
            result = subprocess.run(
                [str(ROOT / "sandbox-attach"), "--name", name, *mode], env=self.env,
                input='test "$PATH" = /usr/bin:/bin && echo clean\n',
                capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((home / "planted-ran").exists(), f"{mode[0]} ran the game's code")
        self.assertIn("clean", result.stdout)

    def launch_named(self, name, *command):
        """A sandbox running COMMAND, once it has printed a line."""
        proc = subprocess.Popen(
            [str(ROOT / "sandbox-game"), "--headless", "--name", name, str(self.game), *command],
            env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def stop():
            if proc.poll() is None:
                proc.terminate()
            proc.communicate(timeout=10)
        self.addCleanup(stop)
        self.assertEqual(proc.stdout.readline().strip(), "ready", proc.stderr.read()
                         if proc.poll() is not None else "")
        return proc

    def attach(self, name, *args, **kwargs):
        return subprocess.run([str(ROOT / "sandbox-attach"), "--name", name, *args],
                              env=self.env, capture_output=True, text=True, timeout=15, **kwargs)

    def test_attached_programs_live_above_the_game(self):
        # What is attached runs under the game's Landlock rules, so a game
        # that takes it over gains nothing -- but in a domain above the
        # game's: it can read the game's memory, as Cheat Engine does under
        # Proton, and the game cannot reach into it. The game lets anyone
        # trace it, so Yama's ptrace_scope is not what decides.
        name = "above-" + self.base.name
        home = self.home / "game-sandboxes" / name / "home"
        (self.game / "probe.py").write_text(
            "import ctypes, os, time\n"
            "ctypes.CDLL(None).prctl(0x59616d61, ctypes.c_ulong(-1), 0, 0, 0)\n"
            "print('ready', flush=True)\n"
            "target = os.path.expanduser('~/target')\n"
            "while not os.path.exists(target):\n"
            "    time.sleep(0.1)\n"
            "try:\n"
            "    open(f'/proc/{open(target).read().strip()}/environ', 'rb').read()\n"
            "    verdict = 'reached'\n"
            "except OSError:\n"
            "    verdict = 'refused'\n"
            "open(os.path.expanduser('~/verdict'), 'w').write(verdict)\n"
            "time.sleep(30)\n")
        self.launch_named(name, "python3", "/game/probe.py")
        target = subprocess.Popen(
            [str(ROOT / "sandbox-attach"), "--name", name, "--exec", "--", "/bin/sh", "-c",
             'echo $$ > "$HOME/target.new"; mv "$HOME/target.new" "$HOME/target"; exec sleep 20'],
            env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        self.addCleanup(target.wait)
        self.addCleanup(target.terminate)
        for _ in range(100):
            if (home / "verdict").exists():
                break
            time.sleep(0.1)
        self.assertEqual((home / "verdict").read_text(), "refused",
                         "the game reached into an attached program")
        reader = self.attach(name, "--exec", "--", "python3", "-c", (
            "import ctypes, os\n"
            "game = next(p for p in os.listdir('/proc') if p.isdigit() and\n"
            "            open(f'/proc/{p}/cmdline', 'rb').read() == b'python3\\0/game/probe.py\\0')\n"
            "start = int(open(f'/proc/{game}/maps').readline().split('-')[0], 16)\n"
            "class iovec(ctypes.Structure):\n"
            "    _fields_ = [('base', ctypes.c_void_p), ('len', ctypes.c_size_t)]\n"
            "buf = ctypes.create_string_buffer(4)\n"
            "got = ctypes.CDLL(None).process_vm_readv(int(game),\n"
            "    ctypes.byref(iovec(ctypes.addressof(buf), 4)), 1,\n"
            "    ctypes.byref(iovec(start, 4)), 1, 0)\n"
            "print(buf.raw if got == 4 else 'refused')\n"
            "try:\n"
            "    open('/attached-probe', 'w')\n"
            "    print('root writable')\n"
            "except OSError:\n"
            "    print('root refused')\n"))
        self.assertEqual(reader.returncode, 0, reader.stderr)
        self.assertEqual(reader.stdout.splitlines(), ["b'\\x7fELF'", "root refused"])

    def test_game_cannot_use_the_attach_socket(self):
        # Only a process outside the sandbox may have something started in
        # the domain above the game's; the game may not remove the socket
        # either, or put one of its own in its place.
        result = self.run_guest(
            "python3 - <<'EOF'\n"
            "import json, os, socket\n"
            "s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)\n"
            "s.connect('/run/sandbox-attach/socket')\n"
            "socket.send_fds(s, [json.dumps({'argv': ['touch', '/game/started']}).encode()],\n"
            "                [0, 1, 2])\n"
            "try:\n"
            "    print('answer', s.recv(100))\n"
            "except ConnectionResetError:\n"
            "    print('answer', b'')\n"
            "try:\n"
            "    os.unlink('/run/sandbox-attach/socket')\n"
            "    print('removed')\n"
            "except OSError:\n"
            "    print('kept')\n"
            "EOF\n"
            "sleep 0.5; test ! -e /game/started && echo 'not started'")
        self.assertEqual(result.stdout.splitlines(), ["answer b''", "kept", "not started"])

    def test_attach_runs_a_terminal_and_passes_the_exit_status_on(self):
        name = "tty-" + self.base.name
        self.launch_named(name, "/bin/sh", "-c", "echo ready; exec sleep 30")
        self.assertEqual(self.attach(name, "--exec", "--", "sh", "-c", "exit 7").returncode, 7)
        self.assertEqual(self.attach(name, "--exec", "--", "sh", "-c",
                                     "kill -TERM $$").returncode, 143)
        # In a terminal, the shell gets one of the sandbox's own, with job
        # control, rather than ours.
        master, slave = os.openpty()
        shell = subprocess.Popen([str(ROOT / "sandbox-attach"), "--name", name, "--shell"],
                                 env={**self.env, "TERM": "xterm"}, stdin=slave, stdout=slave,
                                 stderr=slave, start_new_session=True)
        os.close(slave)
        self.addCleanup(os.close, master)
        out = b""
        while not out.endswith(b"$ "):              # the prompt: it is reading
            out += os.read(master, 4096)
        os.write(master, b'tty; case $- in *m*) echo job-control; esac; exit 3\n')
        while True:
            try:
                data = os.read(master, 4096)
            except OSError:
                break
            if not data:
                break
            out += data
        self.assertEqual(shell.wait(timeout=10), 3, out)
        self.assertIn(b"/dev/pts/", out)
        self.assertIn(b"job-control", out)
        self.assertNotIn(b"no job control", out)

    def test_attach_cannot_be_steered_into_another_sandbox(self):
        # A process that names another sandbox's capture home on its command
        # line, the way that sandbox's bwrap does, and that comes first in
        # /proc. A game can make one: /proc lists PIDs as strings, so it only
        # has to run through PIDs until its own sorts before its pid 1's. It
        # stands in here in a user namespace of its own, started before the
        # victim. Attaching to the victim must still land in the victim.
        victim_home = self.home / "game-sandboxes" / "victim" / "home"
        decoy = subprocess.Popen(
            ["unshare", "--user", "/bin/bash", "-c",
             'echo ready; exec -a bwrap /bin/bash -c "sleep 30; :" --bind "$0" "$1"',
             str(victim_home), str(self.home)],
            stdout=subprocess.PIPE, text=True)
        self.addCleanup(decoy.kill)
        self.assertEqual(decoy.stdout.readline().strip(), "ready")
        victim = subprocess.Popen(
            [str(ROOT / "sandbox-game"), "--headless", "--name", "victim",
             str(self.game), "/bin/sh", "-c", "echo ready; exec sleep 30"],
            env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def stop():
            if victim.poll() is None:
                victim.terminate()
            victim.communicate(timeout=10)
        self.addCleanup(stop)
        self.assertEqual(victim.stdout.readline().strip(), "ready")
        listed = subprocess.run([str(ROOT / "sandbox-attach"), "--list"], env=self.env,
                                capture_output=True, text=True, timeout=15).stdout
        self.assertEqual([line.split()[0] for line in listed.splitlines()[1:]], ["victim"])
        result = subprocess.run(
            [str(ROOT / "sandbox-attach"), "--name", "victim", "--exec", "--",
             "/bin/sh", "-c", 'printf attached > "$HOME/attached"'],
            env=self.env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((victim_home / "attached").is_file(), "attached somewhere else")

    def test_preferences_save_explicit_permissions(self):
        bindir = self.home / ".local" / "bin"
        bindir.mkdir(parents=True)
        for script in ("sandbox-game", "sandbox-game-lib"):
            (bindir / script).symlink_to(ROOT / script)
        self.env["NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"] = str(self.game)
        self.prepare_dialog([
            "Host X11 (other X apps can watch and control it)", "Off",
            "Newest installed (auto)", "Off", "Off", "This game only"])
        result = subprocess.run([str(ROOT / "Sandbox game preferences")],
                                env=self.env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        name = self.cli("--print-name", self.game).stdout.strip()
        settings = (self.home / ".config" / "sandbox-game" / "games" / name).read_text()
        for entry in ("host_x11=1", "wayland=0", "gamescope=0", "net=0", "mod_loaders=0"):
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
        self.assertNotIn("--mod-loaders", launched)
        # The mod loaders preference reaches a Proton game's command line.
        name = self.cli("--print-name", self.game).stdout.strip()
        config = self.home / ".config" / "sandbox-game" / "games"
        config.mkdir(parents=True)
        (config / name).write_text("mod_loaders=1\n")
        result = subprocess.run([str(ROOT / "Sandbox game")], env=self.env,
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--mod-loaders", recorded.read_text().splitlines())
        self.assertNotIn("--steam", recorded.read_text().splitlines())
        (config / name).write_text("steam=1\n")
        result = subprocess.run([str(ROOT / "Sandbox game")], env=self.env,
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--steam", recorded.read_text().splitlines())

    def test_nwjs_runs_under_the_games_name_without_a_copy(self):
        # The runtime's nw, under the game's name beside links to the rest of
        # it, and the same file: a copy would fill /tmp, which is memory.
        (self.game / "www").mkdir()
        (self.game / "www" / "index.html").write_text("")
        (self.game / "package.json").write_text('{"name": "", "main": "www/index.html"}')
        nwjs = self.base / "nwjs"
        nwjs.mkdir()
        (nwjs / "nw").write_text('#!/bin/sh\n[ "$0" -ef /nwjs/nw ] && echo same\n'
                                 '[ -e "${0%/*}/resources.pak" ] && echo linked\n'
                                 'echo "${0##*/}"\n')
        (nwjs / "nw").chmod(0o755)
        (nwjs / "resources.pak").write_text("")
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
        self.env["NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"] = str(self.game)
        path = self.env["PATH"]
        self.env["PATH"] = "/usr/bin:/bin"
        result = subprocess.run([str(ROOT / "Sandbox game")], env=self.env,
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.env["PATH"] = path
        args = recorded.read_text().split("\0")[:-1]
        # What the launcher binds, and the command it runs, in a real sandbox;
        # the display options are not what this is about.
        binds = [x for i, a in enumerate(args) if a == "--ro" for x in args[i:i + 3]]
        command = args[args.index(str(self.game)) + 1:]
        result = self.cli("--headless", *binds, self.game, *command)
        self.assertEqual(result.stdout.split(), ["same", "linked", "Game"])

    def test_nwjs_file_name_case_and_webgl_follow_the_preferences(self):
        # An RPG Maker MV game: nwjs-casefold.js is bound in read-only and
        # package.json names it, until the preferences say casefold=0 -- then
        # it is neither bound nor left in package.json. WebGL goes on ANGLE's
        # Vulkan backend only when webgl=vulkan asks for it.
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
        self.assertEqual(args[-1], "x11")                     # nothing added
        (self.home / ".config" / "sandbox-game").mkdir(parents=True)
        (self.home / ".config" / "sandbox-game" / "defaults").write_text("wayland=1\n")
        self.assertEqual(launch()[-1], "wayland")             # not on Wayland either
        on = fix_package(args, "1")
        self.assertEqual((on["name"], on["inject_js_start"]), ("game", "/nwjs-casefold.js"))
        # Turned off after a launch that had it on: the entry comes out again.
        (self.game / "package.json").write_text(json.dumps(on))
        name = self.cli("--print-name", self.game).stdout.strip()
        config = self.home / ".config" / "sandbox-game" / "games"
        config.mkdir(parents=True)
        (config / name).write_text("casefold=0\nwayland=1\nwebgl=vulkan\n")
        args = launch()
        self.assertNotIn("/nwjs-casefold.js", args)
        self.assertEqual(args[-3:], ["wayland", "--use-angle=vulkan",
                                     "--enable-features=Vulkan,DefaultANGLEVulkan,VulkanFromANGLE"])
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
        config = self.home / ".config" / "sandbox-game"
        config.mkdir(parents=True)
        (config / "defaults").write_text("gamescope_args=-f -W 1920 -H 1080\n")
        self.env["PATH"] = str(bindir) + ":/usr/bin:/bin"
        self.env["NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"] = str(self.game)
        self.prepare_dialog(["X11, in gamescope (private Xwayland)", "", "", "",
                             "", "This game only"])
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

    def test_saving_defaults_keeps_their_hidden_gamescope_arguments(self):
        (self.game / "run.sh").write_text("#!/bin/sh\n")
        config = self.home / ".config" / "sandbox-game"
        (config / "games").mkdir(parents=True)
        defaults = config / "defaults"
        own = config / "games" / "game"
        own.write_text("gamescope_args=-r 30\n")
        form = ["X11, in gamescope (private Xwayland)", "Off", "Off", "All games (defaults)"]
        for initial in ("--adaptive-sync -r 60", ""):
            for resolution, fullscreen in (("Game default (no override)", "No"), ("1280x720", "Yes")):
                with self.subTest(initial=initial, resolution=resolution, fullscreen=fullscreen):
                    defaults.write_text("gamescope_args=" + initial + "\n")
                    self.env["TEST_GS_FORM"] = resolution + "\t" + fullscreen
                    self.preferences(form)
                    settings = dict(line.split("=", 1) for line in defaults.read_text().splitlines()
                                    if "=" in line)
                    visible = "-W 1280 -H 720 -f" if fullscreen == "Yes" else ""
                    expected = " ".join(part for part in (visible, initial) if part)
                    self.assertEqual(settings.get("gamescope_args", ""), expected)
                    self.assertEqual(own.read_text(), "gamescope_args=-r 30\n")

    def test_saving_game_keeps_inherited_hidden_gamescope_arguments(self):
        (self.game / "run.sh").write_text("#!/bin/sh\n")
        config = self.home / ".config" / "sandbox-game"
        config.mkdir(parents=True)
        defaults = config / "defaults"
        defaults.write_text("gamescope_args=--adaptive-sync -r 60\n")
        self.env["TEST_GS_FORM"] = "1280x720\tYes"
        _, saved = self.preferences(["X11, in gamescope (private Xwayland)", "Off", "Off", "This game only"])
        self.assertEqual(saved["gamescope_args"], "-W 1280 -H 720 -f --adaptive-sync -r 60")
        self.assertEqual(defaults.read_text(), "gamescope_args=--adaptive-sync -r 60\n")

    def test_pgmmv_launcher_and_preferences_agree(self):
        # Encrypted project data is recognised without parsing it. Selecting
        # the Windows player or the project must keep the same sandbox key.
        project = self.game / "Resources" / "Data" / "Project.json"
        project.parent.mkdir(parents=True)
        project.write_bytes(b"enc\0not-json")
        exe = self.game / "player.exe"
        exe.touch()
        bindir = self.home / ".local" / "bin"
        bindir.mkdir(parents=True)
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
        self.env["PGMMV_DIR"] = str(self.base / "player bundle")
        for selection in (self.game, exe, project, project.parent, project.parent.parent):
            with self.subTest(selection=selection):
                self.env["NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"] = str(selection)
                result = subprocess.run([str(ROOT / "Sandbox game")], env=self.env,
                                        capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                args = recorded.read_text().splitlines()
                self.assertEqual(args[-1], str(self.game))
                self.assertIn("--pgmmv=" + self.env["PGMMV_DIR"], args)
                self.assertNotIn("--proton", args)
                combos, _ = self.preferences([], selection, gamedir=self.game)
                self.assertNotIn("Proton version", combos)
                self.assertNotIn("Mod loaders", combos)
        # A shipped Linux launcher remains the first choice for the folder.
        (self.game / "native.sh").write_text("#!/bin/sh\n")
        self.env["NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"] = str(self.game)
        result = subprocess.run([str(ROOT / "Sandbox game")], env=self.env,
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(recorded.read_text().splitlines()[-1], "/game/native.sh")

    def test_pgmmv_bundle_and_display(self):
        bundle = self.home / ".local" / "opt" / "pgmmv-player-decrypt-1"
        (bundle / "bin").mkdir(parents=True)
        player = bundle / "bin" / "pgmmv-player"
        player.write_text("#!/bin/sh\n")
        player.chmod(0o755)
        for display, session in (([], "x11"), (["--wayland"], "wayland"),
                                 (["--headless"], "x11")):
            with self.subTest(display=display):
                args = self.recorded_args("--pgmmv", *display)
                self.assertIn(["--ro-bind", str(bundle), "/pgmmv"],
                              [args[i:i + 3] for i in range(len(args))])
                self.assertIn(["--setenv", "XDG_SESSION_TYPE", session],
                              [args[i:i + 3] for i in range(len(args))])
                self.assertIn(["--ro", "/pgmmv"],
                              [args[i:i + 2] for i in range(len(args))])
                self.assertEqual(args[-3:], ["/pgmmv/bin/pgmmv-player",
                                             "--game-dir=/game", "/bin/true"])
        # The command is optional, and an explicit environment path wins.
        self.env["PGMMV_DIR"] = str(bundle)
        result = self.cli("--headless", "--pgmmv=/missing", self.game)
        self.assertEqual(json.loads(result.stdout)[-2:],
                         ["/pgmmv/bin/pgmmv-player", "--game-dir=/game"])
        self.env.pop("PGMMV_DIR")
        result = self.cli("--headless", "--pgmmv=/missing", self.game, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PGMMV_DIR", result.stderr)
        for other in ("--proton", "--mkxp"):
            result = self.cli("--pgmmv", other, self.game, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("mutually exclusive", result.stderr)

    def test_pgmmv_writes_stay_in_the_sandbox(self):
        bundle = self.base / "player bundle"
        (bundle / "bin").mkdir(parents=True)
        player = bundle / "bin" / "pgmmv-player"
        player.write_text('#!/bin/sh -e\n'
                          'test "$1" = --game-dir=/game\n'
                          'test "$(pwd)" = /game\n'
                          'test ! -w /pgmmv/bin/pgmmv-player\n'
                          'printf log > action_log.txt\n'
                          'mkdir -p "$XDG_DATA_HOME/pgmmv-player/game/save"\n'
                          'printf save > "$XDG_DATA_HOME/pgmmv-player/game/save/slot1"\n')
        player.chmod(0o755)
        self.cli("--headless", "--pgmmv=" + str(bundle), self.game)
        self.assertFalse((self.game / "action_log.txt").exists())
        capture = self.home / "game-sandboxes" / "game"
        self.assertEqual((capture / "rw" / "action_log.txt").read_text(), "log")
        self.assertEqual((capture / "home" / ".local" / "share" / "pgmmv-player" /
                          "game" / "save" / "slot1").read_text(), "save")

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

    def test_proton_is_an_overlay_the_game_can_write_to(self):
        # Valve's Proton locks dist.lock in its own folder before it starts
        # anything; the writes must stay out of the install itself.
        proton = self.base / "proton"
        proton.mkdir()
        (proton / "proton").write_text("#!/bin/sh\nexit 0\n")
        (proton / "proton").chmod(0o755)
        args = self.recorded_args("--proton=" + str(proton))
        i = args.index("--tmp-overlay")
        self.assertEqual(args[i - 2:i + 2],
                         ["--overlay-src", str(proton), "--tmp-overlay", "/proton"])
        self.assertNotIn("--ro-bind", [args[j - 1] for j, a in enumerate(args) if a == "/proton"])
        # Landlock must let Proton write there too.
        landlock = args[args.index("/run/sandbox-landlock", i):]
        self.assertEqual(landlock[landlock.index("/proton") - 1], "--rw")

    def test_mod_loaders_prefer_the_games_dlls_unless_told_otherwise(self):
        # BepInEx's winhttp.dll and the like only load when Wine takes the
        # game's copy over its own. An explicit WINEDLLOVERRIDES comes after,
        # since Wine gives the last entry for a DLL the say.
        proton = self.base / "proton"
        proton.mkdir()
        (proton / "proton").write_text("#!/bin/sh\nexit 0\n")
        (proton / "proton").chmod(0o755)
        mods = "winhttp,version,winmm,dinput8,dsound,dwmapi=n,b"
        def overrides(*options):
            args = self.recorded_args("--proton=" + str(proton), *options)
            return [args[i + 2] for i, a in enumerate(args)
                    if a == "--setenv" and args[i + 1] == "WINEDLLOVERRIDES"]
        self.assertEqual(overrides(), [])
        self.assertEqual(overrides("--mod-loaders"), [mods])
        self.assertEqual(overrides("--mod-loaders", "--env", "WINEDLLOVERRIDES=winhttp=b"),
                         [mods, mods + ";winhttp=b"])
        result = self.cli("--headless", "--mod-loaders", self.game, "/bin/true", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("needs --proton", result.stderr)

    def test_proton_starts_programs_as_non_steam_unless_asked(self):
        # Through steam.exe, Wine passes for a running Steam client, and a
        # launcher that can sign in through Steam offers only a login that
        # cannot work here. UMU_ID selects umu's non-Steam start in the builds
        # that have it; --steam keeps steam.exe, and --env still has the last say.
        proton = self.base / "proton"
        proton.mkdir()
        (proton / "proton").write_text("#!/bin/sh\nexit 0\n")
        (proton / "proton").chmod(0o755)
        def umu_ids(*options):
            args = self.recorded_args("--proton=" + str(proton), *options)
            return [args[i + 2] for i, a in enumerate(args)
                    if a == "--setenv" and args[i + 1] == "UMU_ID"]
        self.assertEqual(umu_ids(), ["umu-default"])
        self.assertEqual(umu_ids("--steam"), [])
        self.assertEqual(umu_ids("--env", "UMU_ID=umu-123"), ["umu-default", "umu-123"])
        self.assertNotIn("UMU_ID", self.recorded_args())

    def test_wine_leaves_gnutls_a_default_priority(self):
        # Wine empties GnuTLS's system priority file unless one is set; where
        # GnuTLS defaults to @SYSTEM that left GStreamer's HTTPS, through GLib,
        # without ciphers. GLib gets NORMAL by name; the file stays Wine's,
        # since any other one makes Wine's schannel give up its own priorities.
        cli = shutil.which("gnutls-cli")
        if not cli:
            self.skipTest("gnutls-cli is not installed")
        proton = self.base / "GE-Test"
        (proton / "files" / "bin").mkdir(parents=True)
        for f in (proton / "proton", proton / "files" / "bin" / "wine"):
            f.write_text("#!/bin/sh\n")
            f.chmod(0o755)
        self.env["PROTON_DIR"] = str(proton)
        # As Wine's crypt32 does: /dev/null, unless something is set already.
        script = ('echo "${GNUTLS_SYSTEM_PRIORITY_FILE-unset}"; '
                  'export GNUTLS_SYSTEM_PRIORITY_FILE="${GNUTLS_SYSTEM_PRIORITY_FILE:-/dev/null}"; '
                  'gnutls-cli --priority "$G_TLS_GNUTLS_PRIORITY" --list | grep "^Protocols"')
        out = self.run_guest(script, "--with-proton").stdout.splitlines()
        self.assertEqual(out[0], "unset")
        self.assertIn("VERS-TLS1.2", out[1])
        self.assertEqual(self.run_guest('echo "${G_TLS_GNUTLS_PRIORITY-unset}"').stdout.strip(), "unset")

    def test_proton_finds_this_systems_gstreamer_plugins_first(self):
        # Proton's own plugins are built for Steam's runtime and some cannot
        # load outside it; the system's come first, where it has any.
        proton = self.base / "proton"
        proton.mkdir()
        (proton / "proton").write_text("#!/bin/sh\nexit 0\n")
        (proton / "proton").chmod(0o755)
        args = self.recorded_args("--proton=" + str(proton))
        found = [d for d in ("/usr/lib64/gstreamer-1.0", "/usr/lib/x86_64-linux-gnu/gstreamer-1.0",
                             "/usr/lib/gstreamer-1.0", "/usr/lib32/gstreamer-1.0",
                             "/usr/lib/i386-linux-gnu/gstreamer-1.0") if os.path.isdir(d)]
        values = [args[i + 2] for i, a in enumerate(args) if a == "--setenv" and args[i + 1] == "GST_PLUGIN_PATH_1_0"]
        self.assertEqual(values, [":".join(found)] if found else [])
        self.assertNotIn("GST_PLUGIN_PATH_1_0", self.recorded_args())
        result = self.cli("--headless", "--steam", self.game, "/bin/true", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("needs --proton", result.stderr)

    def test_proton_sandbox_lasts_until_wine_is_done(self):
        # A launcher that starts the game and is then closed ends proton run;
        # the sandbox waits for Wine's last program, and keeps Proton's status.
        proton = self.base / "proton"
        (proton / "files" / "bin").mkdir(parents=True)
        (proton / "proton").write_text(
            '#!/bin/sh\n'
            '( sleep 1; echo game >> "$HOME/order"; : > /tmp/game-done ) &\n'
            'echo launcher >> "$HOME/order"\n'
            'exit 3\n')
        (proton / "files" / "bin" / "wineserver").write_text(
            '#!/bin/sh\n'
            'while [ ! -e /tmp/game-done ]; do sleep 0.1; done\n'
            'echo "wineserver $1 $WINEPREFIX" >> "$HOME/order"\n')
        for f in (proton / "proton", proton / "files" / "bin" / "wineserver"):
            f.chmod(0o755)
        result = self.cli("--headless", "--proton=" + str(proton), "--name", "wine-lasts",
                          self.game, "/game/game.exe", check=False)
        self.assertEqual(result.returncode, 3, result.stderr)
        order = (self.home / "game-sandboxes" / "wine-lasts" / "home" / "order").read_text().split("\n")
        self.assertEqual(order[:3], ["launcher", "game", "wineserver -w /compat/pfx"])

    def test_damaged_registry_comes_back_from_the_last_whole_copy(self):
        # wineserver never syncs its registry saves: a crash soon after one can
        # leave system.reg and user.reg empty, and Wine then refuses the prefix.
        proton = self.base / "proton"
        proton.mkdir()
        def launch(script):
            (proton / "proton").write_text("#!/bin/sh\n" + script)
            (proton / "proton").chmod(0o755)
            return self.cli("--headless", "--proton=" + str(proton), "--name", "registry",
                            self.game, "/game/game.exe")
        capture = self.home / "game-sandboxes" / "registry"
        pfx, copies = capture / "compat" / "pfx", capture / "registry-backup"
        whole = {f: f"WINE REGISTRY Version 2\n;; {f}\n" for f in ("system.reg", "user.reg", "userdef.reg")}
        launch("mkdir -p /compat/pfx\n"
               'for f in system user userdef; do printf "WINE REGISTRY Version 2\\n;; %s.reg\\n" $f'
               " > /compat/pfx/$f.reg; done\n")
        for f, text in whole.items():
            self.assertEqual((copies / f).read_text(), text)
        # A crash right after a save: the renamed files never got their data.
        (pfx / "system.reg").write_bytes(b"")
        (pfx / "user.reg").write_bytes(b"")
        result = launch('cat /compat/pfx/system.reg /compat/pfx/user.reg > "$HOME/seen"\n')
        self.assertEqual((capture / "home" / "seen").read_text(), whole["system.reg"] + whole["user.reg"])
        self.assertIn("system.reg was damaged", result.stderr)
        self.assertIn("user.reg was damaged", result.stderr)
        self.assertNotIn("userdef.reg was damaged", result.stderr)
        self.assertEqual((pfx / "system.reg.damaged").read_bytes(), b"")

        # The prefix is the game's to write in: a link it leaves there takes no
        # host file into the copies, and nothing is written through one.
        secret = self.base / "secret"
        secret.write_text("WINE REGISTRY Version 2\n;; host secret\n")
        victim = self.base / "victim"
        victim.write_bytes(b"")
        launch(f"ln -sf {secret} /compat/pfx/system.reg\nln -sf {victim} /compat/pfx/user.reg\n")
        launch("")
        self.assertEqual((copies / "system.reg").read_text(), whole["system.reg"])
        self.assertEqual(victim.read_bytes(), b"")
        host_dir = self.base / "elsewhere"
        host_dir.mkdir()
        (host_dir / "system.reg").write_bytes(b"")
        launch(f"rm -rf /compat/pfx\nln -s {host_dir} /compat/pfx\n")
        launch("")
        self.assertEqual((host_dir / "system.reg").read_bytes(), b"")
        self.assertEqual(sorted(p.name for p in host_dir.iterdir()), ["system.reg"])

        # A prefix made again is a new one: the old one's copies are not its.
        (capture / "compat" / "pfx").unlink()
        launch("mkdir /compat/pfx\n: > /compat/pfx/system.reg\n")
        launch("")
        self.assertEqual((pfx / "system.reg").read_bytes(), b"")
        self.assertFalse((copies / "system.reg").exists())

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

    def test_private_hosts_file_is_the_games_alone(self):
        host = Path("/etc/hosts").read_text() if Path("/etc/hosts").exists() else ""
        out = self.run_guest(
            'cat /etc/hosts; echo ---; getent ahosts lobby.example; echo ---; '
            '{ echo x >> /etc/hosts; } 2>/dev/null && echo wrote || echo refused; '
            'command -v pkexec || true',
            "--add-host", "10.0.50.105 lobby.example other.example",
            "--add-host", "255.255.221.21 sentry.io").stdout
        hosts, lookup, rest = out.split("---\n")
        # Configured entries lead the private file.
        self.assertEqual(hosts.splitlines()[1:3], ["10.0.50.105 lobby.example other.example",
                                                   "255.255.221.21 sentry.io"])
        self.assertEqual({line.split()[0] for line in lookup.splitlines()}, {"10.0.50.105"})
        self.assertIn("refused", rest)
        self.assertNotIn("/run/sandbox-bin", rest)
        self.assertEqual(Path("/etc/hosts").read_text() if Path("/etc/hosts").exists() else "", host)
        self.assertFalse((self.home / "game-sandboxes" / "game" / "hosts").exists())
        # Without --hosts, the host's own.
        self.assertEqual(self.run_guest("cat /etc/hosts").stdout, host)

    def test_private_hosts_remove_inherited_conflicts_and_keep_other_aliases(self):
        fixture = self.base / "inherited-hosts"
        fixture.write_text("127.0.0.1 localhost\n"
                           "192.0.2.10 Lobby.Example kept.example # keep this comment\n"
                           "2001:db8::10 lobby.example ipv6-kept.example\n"
                           "192.0.2.11 lobby.example # no aliases left\n"
                           "# lobby.example in a comment\n")
        probe = ('cat /etc/hosts; echo ---; python3 -c \'import json, socket; '
                 'print(json.dumps({n: sorted({a[4][0] for a in socket.getaddrinfo(n, 80)}) '
                 'for n in ("lobby.example", "kept.example", "ipv6-kept.example")}))\'')
        for writable in (False, True):
            with self.subTest(writable=writable):
                options = ["--hosts-writable"] if writable else []
                args = ["bwrap", "--dev-bind", "/", "/", "--ro-bind", str(fixture), "/etc/hosts",
                        str(ROOT / "sandbox-game"), "--headless", *options,
                        "--add-host", "10.0.50.105 lobby.example", str(self.game), "/bin/sh", "-ec", probe]
                result = subprocess.run(args, env=self.env, stdin=subprocess.DEVNULL,
                                        capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                hosts, lookups = result.stdout.split("---\n")
                self.assertEqual(json.loads(lookups), {"lobby.example": ["10.0.50.105"],
                                                     "kept.example": ["192.0.2.10"],
                                                     "ipv6-kept.example": ["2001:db8::10"]})
                self.assertIn("192.0.2.10 kept.example # keep this comment\n", hosts)
                self.assertIn("# no aliases left\n", hosts)
                self.assertIn("# lobby.example in a comment\n", hosts)
                if writable:
                    kept = self.home / "game-sandboxes" / "game" / "hosts"
                    with kept.open("a") as f:
                        f.write("192.0.2.20 LOBBY.EXAMPLE edited.example\n")
                    updated = self.run_guest(probe, "--hosts-writable", "--add-host",
                                             "10.0.50.106 lobby.example").stdout
                    hosts, lookups = updated.split("---\n")
                    self.assertEqual(json.loads(lookups)["lobby.example"], ["10.0.50.106"])
                    self.assertIn("192.0.2.20 edited.example\n", hosts)

    def test_writable_hosts_file_keeps_the_games_edits(self):
        host = Path("/etc/hosts").read_text() if Path("/etc/hosts").exists() else ""
        # What a launcher that edits /etc/hosts through pkexec does.
        self.run_guest('cp /etc/hosts /tmp/new; echo "10.9.9.9 app.example" >> /tmp/new; '
                       'pkexec --disable-internal-agent cp /tmp/new /etc/hosts',
                       "--hosts-writable", "--add-host", "10.0.50.105 lobby.example")
        kept = self.home / "game-sandboxes" / "game" / "hosts"
        self.assertIn("10.9.9.9 app.example", kept.read_text())
        # Next time the preferences' entries are rewritten, and the game's stay.
        out = self.run_guest("cat /etc/hosts", "--hosts-writable",
                             "--add-host", "10.0.50.106 lobby.example").stdout
        self.assertEqual(out.splitlines()[1], "10.0.50.106 lobby.example")
        self.assertIn("10.9.9.9 app.example", out.splitlines())
        self.assertNotIn("10.0.50.105", out)
        self.assertEqual(out.count("# sandbox-game: end"), 1)
        self.assertEqual(Path("/etc/hosts").read_text() if Path("/etc/hosts").exists() else "", host)
        # And with no entries left, none of the block.
        out = self.run_guest("cat /etc/hosts", "--hosts-writable").stdout
        self.assertNotIn("sandbox-game", out)
        self.assertIn("10.9.9.9 app.example", out.splitlines())

    def test_dotnet_runtime_only_when_asked(self):
        def install(root):
            (root / "host" / "fxr" / "10.0.12").mkdir(parents=True)
            (root / "shared" / "Microsoft.NETCore.App" / "10.0.12").mkdir(parents=True)
            return root
        script = ('echo "${DOTNET_ROOT-unset} $PATH"; ls /dotnet/host/fxr 2>&1 || true; '
                  '{ touch /dotnet/x; } 2>/dev/null && echo writable || true')
        out = self.run_guest(script, f"--dotnet={install(self.base / 'dotnet')}").stdout.splitlines()
        self.assertEqual(out[:2], ["/dotnet /usr/bin:/bin:/dotnet", "10.0.12"])
        self.assertNotIn("writable", out)
        out = self.run_guest(script).stdout
        self.assertTrue(out.startswith("unset /usr/bin:/bin\n"), out)
        self.assertNotIn("10.0.12", out)
        # Found in ~/.dotnet, where a user's install usually is -- unless the
        # machine has one of its own, which is looked for first.
        install(self.home / ".dotnet")
        if not any(Path(p).exists() for p in ("/etc/dotnet", "/usr/share/dotnet", "/usr/lib64/dotnet",
                                              "/usr/lib/dotnet", "/opt/dotnet")):
            self.assertIn("10.0.12", self.run_guest(script, "--dotnet").stdout)
        result = self.cli("--headless", f"--dotnet={self.base}", self.game, "/bin/true", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no .NET runtime at", result.stderr)

    def test_native_programs_can_be_given_proton(self):
        proton = self.base / "GE-Test"
        (proton / "files" / "bin").mkdir(parents=True)
        for f in (proton / "proton", proton / "files" / "bin" / "wine"):
            f.write_text("#!/bin/sh\n")
            f.chmod(0o755)
        self.env["PROTON_DIR"] = str(proton)
        script = ('test -x /proton/files/bin/wine && echo found; '
                  '{ touch /proton/x; } 2>/dev/null && echo writable || true; pwd')
        result = self.run_guest(script, "--with-proton")
        self.assertEqual(result.stdout.splitlines(), ["found", "/game"])
        self.assertIn("its Wine is /proton/files/bin/wine", result.stderr)
        self.assertNotIn("found", self.run_guest(script).stdout)
        self.assertIn("/dev/ntsync", self.recorded_args("--with-proton"))
        refused = self.cli("--headless", "--with-proton", "--proton", self.game, "game.exe", check=False)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("--proton already", refused.stderr)

    def test_lan_allowances_need_the_internet(self):
        for option in (["--lan"], ["--allow-lan", "10.0.50.105"]):
            result = self.cli("--headless", *option, self.game, "/bin/true", check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("need it", result.stderr)

    def test_check_reports_every_protection(self):
        result = self.cli("--check", check=False)
        lines = result.stdout.splitlines()
        marks = {line.split()[1]: line.split()[0] for line in lines}
        self.assertEqual(list(marks), ["flock", "sandbox", "seccomp", "landlock", "limits", "sound",
                                       "gpu", "gamescope", "network", "ntsync", "32-bit"], result.stdout)
        self.assertTrue(set(marks.values()) <= {"ok", "--", "!!"}, result.stdout)
        # Exit status 1 exactly when something a sandbox should have is missing:
        # here at least the playback-only server, the test runtime dir having none.
        self.assertEqual(marks["sound"], "!!")
        self.assertEqual(result.returncode, 1)
        filtered = load_seccomp().socketcall_closable() or os.uname().machine != "x86_64"
        self.assertEqual(marks["seccomp"], "ok" if filtered else "--")

    def test_check_names_what_32_bit_wine_cannot_find(self):
        # Proton runs on the system's libraries: a 32-bit Wine driver that
        # links one the system has no 32-bit copy of is named, while Wine's
        # own modules beside the driver are not. Each library comes with the
        # Protons that want it, once each, however many times one is found.
        gcc = shutil.which("gcc")
        if not gcc or not os.path.exists("/usr/lib/ld-linux.so.2"):
            self.skipTest("needs gcc and a 32-bit glibc")
        tools = self.home / ".local/share/Steam/compatibilitytools.d"
        proton, other = tools / "Proton Test", tools / "Other-Proton"
        drivers = proton / "files" / "lib" / "wine" / "i386-unix"
        stubs = self.base / "stubs"
        for folder in (drivers, stubs):
            folder.mkdir(parents=True)
        (proton / "proton").write_text("#!/bin/sh\n")
        (proton / "proton").chmod(0o755)
        source = self.base / "empty.c"
        source.write_text("int sandbox_test;\n")

        def build(path, *links):
            built = subprocess.run([gcc, "-m32", "-shared", "-nostdlib", f"-Wl,-soname,{path.name}",
                                    "-o", str(path), str(source), *links], capture_output=True, text=True)
            if built.returncode:
                self.skipTest("cannot build 32-bit libraries: " + built.stderr)

        build(drivers / "ntdll.so")
        build(stubs / "libsandbox-gone.so.1")
        build(drivers / "winex11.so", "-L", str(drivers), "-l:ntdll.so",
              "-L", str(stubs), "-l:libsandbox-gone.so.1")
        shutil.copytree(proton, other)
        build(other / "files/lib/wine/i386-unix/winepulse.so", "-L", str(stubs), "-l:libsandbox-gone.so.1")
        shutil.rmtree(stubs)
        self.env["PROTON_DIR"] = str(proton)

        def line():
            result = self.cli("--check", check=False)
            return next(l for l in result.stdout.splitlines() if l.split()[1] == "32-bit")

        found = line()
        self.assertEqual(found.split()[0], "!!", found)
        self.assertIn("lack libsandbox-gone.so.1 (Proton Test, Other-Proton): install", found)
        self.assertNotIn("ntdll.so", found)
        build(drivers / "winex11.so", "-L", str(drivers), "-l:ntdll.so")
        self.assertIn("lack libsandbox-gone.so.1 (Other-Proton): install", line())
        shutil.rmtree(other)
        self.assertNotIn("libsandbox-gone.so.1", line())
        # A WoW64 build has no 32-bit drivers, and needs no 32-bit libraries.
        shutil.rmtree(proton / "files")
        self.assertEqual(line().split()[0], "--")

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

    def test_split_display_keeps_native_wayland_and_private_x11_available(self):
        proton = self.base / "proton"
        proton.mkdir()
        (proton / "proton").write_text("#!/bin/sh\nexit 0\n")
        (proton / "proton").chmod(0o755)
        args = self.recorded_args("--wayland-x11", "--proton=" + str(proton),
                                  "--x11-exe=Vendor Launcher.exe")
        self.assertIn("gamescope", args)
        self.assertLess(args.index("--gamescope-on-demand"), args.index("gamescope"))
        self.assertNotIn("--gamescope-on-demand", self.recorded_args("--gamescope", "--proton=" + str(proton)))
        self.assertIn("WINE_GRAPHICS_DRIVER", args)
        self.assertEqual(args[args.index("WINE_GRAPHICS_DRIVER") + 1], "wayland")
        self.assertEqual(args[args.index("PROTON_USE_X11_EXCLUSIVE") + 1], "Vendor Launcher.exe")
        self.assertNotIn("--expose-wayland", args)
        self.assertNotIn("STEAM_COMPAT_CONFIG", args)
        self.assertNotIn("/tmp/.Xauthority", args)
        self.assertNotIn(":123", args)  # recorded_args deliberately supplies a host DISPLAY
        inner = args.index("--unix-connect-where-writable")
        rules = args[args.index("/run/sandbox-landlock", args.index("gamescope")):inner]
        self.assertEqual(rules[rules.index("--unix-connect") + 1], "/run/host-wayland/wayland-0")
        self.assertFalse([r for k, r in enumerate(rules[1:]) if rules[k] == "--rw"
                          and r.startswith("/run/host-wayland")])
        self.assertIn("WAYLAND_DISPLAY=/run/host-wayland/wayland-0", args[inner:])
        # Gamescope's WSI layer hooks nothing beside the desktop's socket, and
        # would only ask about every swapchain: it stays out of the game, and
        # out of what sandbox-attach starts, which gets the environment gamescope
        # gave the starter, not what is set after it.
        self.assertEqual(args[args.index("DISABLE_GAMESCOPE_WSI") + 1], "1")
        self.assertLess(args.index("DISABLE_GAMESCOPE_WSI"), args.index("gamescope"))
        self.assertNotIn("DISABLE_GAMESCOPE_WSI", self.recorded_args("--gamescope", "--proton=" + str(proton)))
        # Split display is its own: an added --wayland asks nothing of gamescope.
        both = self.recorded_args("--wayland", "--wayland-x11", "--proton=" + str(proton))
        self.assertNotIn("--expose-wayland", both)
        self.assertNotIn("STEAM_COMPAT_CONFIG", both)
        self.assertIn("WINE_GRAPHICS_DRIVER", both)

    def test_split_display_keeps_gamescope_windowed(self):
        proton = self.base / "proton"
        proton.mkdir()
        (proton / "proton").write_text("#!/bin/sh\nexit 0\n")
        (proton / "proton").chmod(0o755)
        args = self.recorded_args("--wayland-x11", "--proton=" + str(proton),
                                  "--gamescope=-f -W 1920 -H 1080 --fullscreen")
        gs = args.index("gamescope")
        self.assertEqual(args[gs + 1:args.index("--", gs)], ["-W", "1920", "-H", "1080"])
        # Not split: fullscreen as asked.
        args = self.recorded_args("--proton=" + str(proton), "--gamescope=-f -W 1920 -H 1080")
        self.assertIn("-f", args[args.index("gamescope"):])

    def fake_compositor(self, outputs):
        """Serve wl_output and xdg-output for OUTPUTS on the test's Wayland socket.

        Each output is (mode width, mode height, transform, logical x, y, w, h).
        """
        import socket, threading
        path = self.runtime / "wayland-0"
        server = socket.socket(socket.AF_UNIX)
        server.bind(str(path))
        server.listen()
        self.addCleanup(server.close)

        def event(obj, opcode, payload=b""):
            return struct.pack("=II", obj, (8 + len(payload)) << 16 | opcode) + payload

        def string(text):
            raw = text.encode() + b"\0"
            return struct.pack("=I", len(raw)) + raw + b"\0" * (-len(raw) % 4)

        def serve(conn):
            data, registry, bound = b"", None, {}
            with conn:
                while True:
                    while len(data) < 8 or len(data) < struct.unpack_from("=II", data)[1] >> 16:
                        chunk = conn.recv(65536)
                        if not chunk:
                            return
                        data += chunk
                    obj, word = struct.unpack_from("=II", data)
                    body, data = data[8:word >> 16], data[word >> 16:]
                    opcode, out = word & 0xffff, b""
                    if obj == 1 and opcode == 1:                 # get_registry
                        registry = struct.unpack_from("=I", body)[0]
                        for i in range(len(outputs)):
                            out += event(registry, 0, struct.pack("=I", i + 1) + string("wl_output")
                                         + struct.pack("=I", 4))
                        out += event(registry, 0, struct.pack("=I", 100)
                                     + string("zxdg_output_manager_v1") + struct.pack("=I", 3))
                    elif obj == 1 and opcode == 0:               # sync
                        out = event(struct.unpack_from("=I", body)[0], 0, struct.pack("=I", 0))
                    elif obj == registry:                        # bind
                        name = struct.unpack_from("=I", body)[0]
                        size = struct.unpack_from("=I", body, 4)[0]
                        new = struct.unpack_from("=I", body, 8 + (size + 3) // 4 * 4 + 4)[0]
                        bound[new] = name
                        if name <= len(outputs):
                            w, h, transform = outputs[name - 1][:3]
                            out = event(new, 0, struct.pack("=5i", 0, 0, 600, 340, 0) + string("Make")
                                        + string("Model") + struct.pack("=i", transform))
                            out += event(new, 1, struct.pack("=Iiii", 3, w, h, 60000))
                            out += event(new, 2)
                    elif bound.get(obj) == 100 and opcode == 1:  # get_xdg_output
                        new, output = struct.unpack_from("=II", body)
                        lx, ly, lw, lh = outputs[bound[output] - 1][3:]
                        out = event(new, 0, struct.pack("=ii", lx, ly)) + event(new, 1, struct.pack("=ii", lw, lh))
                    conn.sendall(out)

        def accept():
            while True:
                try:
                    conn, _ = server.accept()
                except OSError:
                    return
                threading.Thread(target=serve, args=(conn,), daemon=True).start()
        threading.Thread(target=accept, daemon=True).start()

    def test_split_display_x11_screen_covers_wines_desktop(self):
        # Wine's Wayland driver sets the monitors out at their own pixel sizes;
        # X11 windows placed on that desktop must lie on gamescope's X screen
        # too, or clicks land away from where the pointer is drawn.
        proton = self.base / "proton"
        proton.mkdir()
        (proton / "proton").write_text("#!/bin/sh\nexit 0\n")
        (proton / "proton").chmod(0o755)
        def nested(*options):
            args = self.recorded_args("--wayland-x11", "--proton=" + str(proton), *options)
            gs = args[args.index("gamescope") + 1:]
            return gs[:gs.index("--")]
        # Two 4K monitors at 150%, side by side: 2560 logical pixels apart, but
        # 3840 real ones each.
        self.fake_compositor([(3840, 2160, 0, 2560, 0, 2560, 1440),
                              (3840, 2160, 0, 0, 0, 2560, 1440)])
        self.assertEqual(nested(), ["-w", "7680", "-h", "2160"])
        self.assertEqual(nested("--gamescope=-W 1920 -H 1080"), ["-W", "1920", "-H", "1080", "-w", "7680", "-h", "2160"])
        # A size set by hand is left alone.
        self.assertEqual(nested("--gamescope=-w 2560 -h 1440"), ["-w", "2560", "-h", "1440"])
        # Not split display: gamescope's screen is the game's, as before.
        args = self.recorded_args("--gamescope", "--proton=" + str(proton))
        self.assertNotIn("-w", args[args.index("gamescope"):])

    def test_split_display_x11_screen_turns_with_its_monitor(self):
        proton = self.base / "proton"
        proton.mkdir()
        (proton / "proton").write_text("#!/bin/sh\nexit 0\n")
        (proton / "proton").chmod(0o755)
        # A 1920x1080 panel turned upright beside a 2560x1440 one, both at 100%.
        self.fake_compositor([(2560, 1440, 0, 0, 0, 2560, 1440),
                              (1920, 1080, 1, 2560, 0, 1080, 1920)])
        args = self.recorded_args("--wayland-x11", "--proton=" + str(proton))
        gs = args.index("gamescope")
        self.assertEqual(args[gs + 1:gs + 5], ["-w", "3640", "-h", "1920"])

    def test_split_display_without_monitor_layout_still_starts(self):
        proton = self.base / "proton"
        proton.mkdir()
        (proton / "proton").write_text("#!/bin/sh\nexit 0\n")
        (proton / "proton").chmod(0o755)
        # recorded_args' socket accepts no connections: no layout, no -w.
        args = self.recorded_args("--wayland-x11", "--proton=" + str(proton))
        self.assertEqual(args[args.index("gamescope") + 1], "--")

    def test_split_executable_option_needs_a_value(self):
        for options in (["--x11-exe", "--net"], ["--x11-exe", ""]):
            with self.subTest(options=options):
                result = self.cli("--proton", "--wayland-x11", *options, self.game, "play.exe", check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("--x11-exe needs an executable name", result.stderr)

    def test_split_display_gamescope_comes_and_goes_beside_the_game(self):
        # Closing gamescope's window ends the X11 programs in it, not the game
        # beside it; the next X11 program opens it again, on the same DISPLAY.
        import socket
        import threading
        listener = socket.socket(socket.AF_UNIX)
        self.addCleanup(listener.close)
        listener.bind(str(self.runtime / "wayland-split"))
        listener.listen()
        listener.settimeout(8)
        def serve():
            # The first connection asks for the monitor layout before the
            # sandbox starts, and gets no answer it can use; the second is the
            # game's.
            for _ in range(2):
                connection, _ = listener.accept()
                with connection:
                    connection.sendall(b"wayland")
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.env["WAYLAND_DISPLAY"] = "wayland-split"
        self.env["DISPLAY"] = ":123"
        # Gamescope as far as the sandbox sees it: an Xwayland display of its
        # choosing, with a lock file naming it and an abstract socket, and its
        # X11 programs gone when its window is closed. Real bwrap mounts and
        # both Landlock domains around it.
        gamescope = self.game / "gamescope"
        gamescope.write_text('''#!/usr/bin/python3
import array, os, signal, socket
log = open(os.path.expanduser("~/gamescope.log"), "a", buffering=1)
def terminated(*_):
    log.write("terminated\\n")
    os._exit(0)
signal.signal(signal.SIGTERM, terminated)
log.write(f"started {'DISPLAY' in os.environ} {os.environ.get('WAYLAND_DISPLAY')}\\n")
n = 1
while os.path.exists(f"/tmp/.X{n}-lock"):
    n += 1
with open(f"/tmp/.X{n}-lock", "w") as lock:
    lock.write("%10d\\0" % os.getpid())   # as wlroots writes it
server = socket.socket(socket.AF_UNIX)
server.bind(f"\\0/tmp/.X11-unix/X{n}")
server.listen()
clients = []
while True:
    client, _ = server.accept()
    clients.append(client)
    data, anc, _, _ = client.recvmsg(64, socket.CMSG_SPACE(4))
    if data == b"close":
        os.unlink(f"/tmp/.X{n}-lock")
        os._exit(0)
    fds = array.array("i")
    for _, _, raw in anc:
        fds.frombytes(raw)
    client.sendall(data + b" " + (os.read(fds[0], 64) if fds else b""))
''')
        gamescope.chmod(0o755)
        self.env["PATH"] = str(self.game) + ":/usr/bin:/bin"
        proton = self.base / "proton"
        proton.mkdir()
        (proton / "proton").write_text('#!/bin/sh\nshift\nexec "$@"\n')
        (proton / "proton").chmod(0o755)
        probe = '''
import array, os, socket, sys
assert os.environ["WINE_GRAPHICS_DRIVER"] == "wayland"
assert os.environ["DISPLAY"] == ":0"
assert "STEAM_COMPAT_CONFIG" not in os.environ
assert not os.path.exists("/tmp/.X11-unix/X123")
with socket.socket(socket.AF_UNIX) as client:
    client.settimeout(3)
    client.connect(os.environ["WAYLAND_DISPLAY"])
    print(client.recv(64).decode())
def x11(message, fd=None):
    client = socket.socket(socket.AF_UNIX)
    client.settimeout(5)
    client.connect("/tmp/.X11-unix/X0")
    client.sendmsg([message], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))] if fd else [])
    return client
r, w = os.pipe()
os.write(w, b"descriptor")
launcher = x11(b"launcher", r)
print(launcher.recv(64).decode())
print(x11(b"close").recv(64) == launcher.recv(64) == b"")
print(x11(b"again").recv(64).decode().strip())
sys.exit(3)
'''
        result = self.cli("--wayland-x11", "--proton=" + str(proton), "--name", "split",
                          "--env=PATH=/game:/usr/bin:/bin", self.game, "/usr/bin/python3", "-c", probe,
                          check=False)
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["wayland", "launcher descriptor", "True", "again"])
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        log = (self.home / "game-sandboxes" / "split" / "home" / "gamescope.log").read_text()
        self.assertEqual(log.splitlines(), ["started False /run/host-wayland/wayland-0"] * 2 + ["terminated"])

    def test_split_mangohud_keeps_config_but_disables_x11_shortcut_polling(self):
        self.recorded_args()  # command recorders and the validated Wayland socket
        wrapper = self.base / "bin" / "mangohud"
        wrapper.write_text('#!/bin/sh\nexec "$@"\n')
        wrapper.chmod(0o755)
        proton = self.base / "proton"
        proton.mkdir()
        (proton / "proton").write_text('#!/bin/sh\nexit 0\n')
        (proton / "proton").chmod(0o755)
        config = self.home / ".config" / "MangoHud"
        config.mkdir(parents=True)
        (config / "MangoHud.conf").write_text('fps_limit=60\ntoggle_hud=F12\n')

        def settings(*options):
            args = self.recorded_args("--proton=" + str(proton), *options)
            values = {args[i + 1]: args[i + 2] for i, a in enumerate(args) if a == "--setenv"}
            if "--mangohud" in options:
                self.assertIn("mangohud", args)
                self.assertIn(str(config), args)
            return values.get("MANGOHUD_CONFIG")

        bindings = {"toggle_hud", "toggle_hud_position", "toggle_preset", "reset_fps_metrics",
                    "toggle_fps_limit", "toggle_logging", "reload_cfg", "upload_log", "upload_logs"}
        default = settings("--wayland-x11", "--mangohud")
        values = dict(option.split("=", 1) if "=" in option else (option, "1")
                      for option in default.split(","))
        self.assertEqual(values.pop("read_cfg"), "1")
        self.assertEqual(values, dict.fromkeys(bindings, ""))
        custom = settings("--wayland-x11", "--mangohud",
                          "--env=MANGOHUD_CONFIG=read_cfg,fps_limit=40,toggle_hud=F12,permit_upload=1")
        values = dict(option.split("=", 1) if "=" in option else (option, "1")
                      for option in custom.split(","))
        self.assertEqual(values.pop("read_cfg"), "1")
        self.assertEqual(values.pop("fps_limit"), "40")
        self.assertEqual(values.pop("permit_upload"), "1")
        self.assertEqual(values, dict.fromkeys(bindings, ""))
        empty = settings("--wayland-x11", "--mangohud", "--env=MANGOHUD_CONFIG=")
        self.assertFalse(empty.startswith(","))
        self.assertIsNone(settings("--wayland-x11"))
        self.assertIsNone(settings("--wayland", "--mangohud"))

    def test_split_mode_rejects_incompatible_display_options(self):
        for options, message in ((["--wayland-x11"], "needs --proton"),
                                 (["--x11-exe=Launcher.exe"], "needs --wayland-x11"),
                                 (["--proton", "--wayland-x11", "--headless"], "--headless cannot"),
                                 (["--proton", "--wayland-x11", "--host-x11"], "--host-x11 cannot")):
            with self.subTest(options=options):
                result = self.cli(*options, self.game, "play.exe", check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)

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

    def test_standard_input_reaches_the_game_with_and_without_network(self):
        payload = "input for the game\n"
        for options in ([], ["--net"]):
            for terminal in (False, True):
                with self.subTest(options=options, terminal=terminal):
                    if options and not shutil.which("pasta"):
                        self.skipTest("pasta (package passt) is not installed")
                    script = ('test -t 0; ' if terminal else '') + (
                        'IFS= read -r line; printf "%s\\n" "$line"')
                    args = [str(ROOT / "sandbox-game"), "--headless", *options,
                            self.game, "/bin/sh", "-ec", script]
                    kwargs = dict(env=self.env, capture_output=True, text=True, timeout=15)
                    if terminal:
                        master, slave = os.openpty()
                        try:
                            os.write(master, payload.encode())
                            result = subprocess.run(args, stdin=slave, **kwargs)
                        finally:
                            os.close(slave)
                            os.close(master)
                    else:
                        result = subprocess.run(args, input=payload, **kwargs)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, payload)

    def test_network_card_keeps_its_address_between_launches(self):
        # The kernel gives pasta's interface a random MAC at each start, and a
        # launcher that ties its saved login to the "device" forgot it every
        # time. Each sandbox keeps one of its own; none is the real card's.
        if not shutil.which("pasta"):
            self.skipTest("pasta (package passt) is not installed")
        probe = ("import fcntl, socket, struct\n"
                 "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
                 "for _, name in socket.if_nameindex():\n"
                 "    if name != 'lo':\n"
                 "        req = struct.pack('256s', name.encode())\n"
                 "        print(fcntl.ioctl(s.fileno(), 0x8927, req)[18:24].hex(':'))\n")
        (self.game / "mac.py").write_text(probe)
        def macs(*options):
            result = self.cli("--headless", "--net", *options, self.game, "python3", "/game/mac.py")
            return result.stdout.split()
        first = macs()
        self.assertEqual(len(first), 1, first)
        self.assertEqual(int(first[0][:2], 16) & 3, 2, first)   # locally administered, unicast
        self.assertEqual(macs(), first)
        self.assertNotEqual(macs("--name", "other-sandbox"), first)
        host = {Path(f).read_text().strip() for f in glob.glob("/sys/class/net/*/address")}
        self.assertNotIn(first[0], host)
        # --mac-vendor: the prefix of the card the default route uses, when
        # that names a manufacturer, else Realtek's; the rest made up. Kept
        # apart, so switching back finds the first address again.
        route = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True).stdout.split()
        card = route[route.index("dev") + 1] if "dev" in route else ""
        try:
            own = Path(f"/sys/class/net/{card}/address").read_text().strip()
        except OSError:
            own = ""
        expected = own[:8] if own and int(own[:2], 16) & 3 == 0 and own[:8] != "00:00:00" else "00:e0:4c"
        vendor = macs("--mac-vendor")
        self.assertEqual(vendor[0][:8], expected, (vendor, own))
        self.assertNotIn(vendor[0], host)
        self.assertEqual(macs("--mac-vendor"), vendor)
        self.assertEqual(macs(), first)
        refused = self.cli("--headless", "--mac-vendor", self.game, "/bin/true", check=False)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("needs --net", refused.stderr)

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
            socket.create_connection(("example.com", 443), timeout=5).close()
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
        return urllib.request.urlopen("https://example.com", timeout=10).status
    except OSError as e:
        return str(e)
def udp_send(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendto(b"M-SEARCH", (host, port))
        return "sent"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e))
    finally:
        s.close()
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
    "dns_other_port": tcp("169.254.1.1", {port}),
    "multicast": udp_send("239.255.255.250", 1900),
    "internet": tcp("example.com", 443) if {online} else "skipped",
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
        # pasta answers only DNS at its address; the rest would go to
        # whatever really has that address, on this machine or the LAN.
        self.assertEqual(seen["dns_other_port"], "EACCES",
                         "the DNS address was open beyond DNS")
        # Discovery goes out to the LAN by multicast.
        self.assertEqual(seen["multicast"], "EACCES", "multicast reached the LAN")
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

    def test_lan_allowances_open_only_what_they_name(self):
        if not shutil.which("pasta"):
            self.skipTest("pasta (package passt) is not installed")
        ip = shutil.which("ip") or "/usr/sbin/ip"
        routes = json.loads(subprocess.run([ip, "-j", "-4", "route", "show", "default"],
                                           capture_output=True, text=True).stdout or "[]")
        gateway = next((r["gateway"] for r in routes if "gateway" in r), None)
        addrs = json.loads(subprocess.run([ip, "-j", "addr", "show", "scope", "global"],
                                          capture_output=True, text=True, check=True).stdout)
        own = [a["local"] for link in addrs for a in link.get("addr_info", [])
               if a.get("family") == "inet"]
        if gateway is None or not own:
            self.skipTest("no IPv4 default gateway and address to stand in for the LAN")
        # A service on every host interface, including addresses that pasta
        # does not copy into the sandbox on a multihomed host.
        import socket
        listener = socket.socket()
        listener.bind(("0.0.0.0", 0))
        listener.listen()
        self.addCleanup(listener.close)
        port = listener.getsockname()[1]
        for address in own:
            socket.create_connection((address, port), timeout=3).close()
            listener.accept()[0].close()
        (self.game / "probe.py").write_text("""
import errno, json, socket, sys
def tcp(host, port):
    try:
        socket.create_connection((host, port), timeout=3).close()
        return "open"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e))
print(json.dumps([tcp(host, int(port)) for host, port in zip(sys.argv[1::2], sys.argv[2::2])]))
""")
        def probe(*options):
            result = self.cli("--headless", "--net", *options, self.game, "python3", "/game/probe.py",
                              gateway, 80, gateway, 81,
                              *[value for address in own for value in (address, port)], check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)
        # EACCES is the rule refusing it; anything else got past the rules.
        allowed, other_port, *this_pc = probe("--allow-lan", f"{gateway}:80/tcp")
        self.assertNotEqual(allowed, "EACCES")
        self.assertEqual(other_port, "EACCES")
        self.assertNotIn("open", this_pc)
        allowed, other_port, *this_pc = probe("--lan")
        self.assertNotEqual(allowed, "EACCES")
        self.assertNotEqual(other_port, "EACCES")
        self.assertNotIn("open", this_pc, "--lan let the game reach this machine")
        # Explicit addresses and a covering subnet must retain the host block.
        networks = [str(ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}").network)
                    for link in addrs for a in link.get("addr_info", []) if a.get("family") == "inet"]
        for allowance in (", ".join(f"{address}:{port}" for address in own), ", ".join(networks)):
            self.assertNotIn("open", probe("--allow-lan", allowance)[2:], allowance)

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

    def test_stop_kills_only_sandboxes_still_running(self):
        # Stand-ins for outer bwraps. "stuck" ignores TERM, so after the wait
        # --stop has to kill it. "reused" goes on TERM and its PID becomes
        # some other program: the stand-in turns into one, so that PID is
        # still alive but no longer a sandbox, and must be left alone.
        script = ("import os, signal, sys, time\n"
                  "if sys.argv[1] == 'stuck': signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                  "else: signal.signal(signal.SIGTERM, lambda *_: "
                  "os.execv('/bin/sleep', ['sleep', '60']))\n"
                  "print(flush=True); time.sleep(60)\n")
        procs = {}
        for name in ("stuck", "reused"):
            home = self.home / "game-sandboxes" / name / "home"
            home.mkdir(parents=True)
            procs[name] = subprocess.Popen(
                ["/bin/bash", "-c", 'exec -a bwrap python3 -c "$0" "$1" --bind "$2" "$3"',
                 script, name, str(home), str(self.home)], stdout=subprocess.PIPE, text=True)
            self.addCleanup(procs[name].kill)
            procs[name].stdout.readline()             # signal handling set up
        self.assertEqual(self.cli("--stop-all").stdout.split(), ["stopped", "reused",
                                                                 "stopped", "stuck"])
        self.assertEqual(procs["stuck"].wait(timeout=5), -9)
        self.assertIsNone(procs["reused"].poll(), "a PID no longer a sandbox's was killed")

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

    def prepare_dialog(self, form, launch_with=""):
        self.env["SANDBOX_DIALOG"] = str(ROOT / "tests" / "dialog_recorder.py")
        self.env["DIALOG_RECORD"] = str(self.base / "offered.json")
        self.env["TEST_FORM"] = json.dumps(form)
        self.env["TEST_LAUNCH_WITH"] = launch_with

    def test_stop_script_requires_a_confirmed_gui_response(self):
        bindir = self.home / ".local" / "bin"
        bindir.mkdir(parents=True)
        helpers = self.home / ".local" / "lib" / "sandbox-game"
        helpers.mkdir(parents=True)
        (helpers / "sandbox-game-lib").symlink_to(ROOT / "sandbox-game-lib")
        stopped = self.base / "stopped"
        stub = bindir / "sandbox-game"
        stub.write_text('#!/bin/sh\n'
                        f'[ "$1" = --print-name ] && exec "{ROOT / "sandbox-game"}" "$@"\n'
                        f'printf "%s\\n" "$@" > "{stopped}"\n')
        stub.chmod(0o755)
        self.prepare_dialog([])
        self.env["NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"] = str(self.game)
        for response in ("1", "2"):
            self.env["DIALOG_EXIT"] = response
            subprocess.run([str(ROOT / "Stop sandboxed game")], env=self.env,
                           capture_output=True, timeout=15)
            self.assertFalse(stopped.exists())
        self.env["DIALOG_EXIT"] = "0"
        result = subprocess.run([str(ROOT / "Stop sandboxed game")], env=self.env,
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stopped.read_text().splitlines(), ["--stop", "game"])

    def preferences(self, form, game=None, gamedir=None, launch_with=""):
        """Simulate edits in the single preferences window; empty form cancels."""
        bindir = self.home / ".local" / "bin"
        bindir.mkdir(parents=True, exist_ok=True)
        for script in ("sandbox-game", "sandbox-game-lib"):
            if not (bindir / script).exists():
                (bindir / script).symlink_to(ROOT / script)
        self.prepare_dialog(form, launch_with)
        game = game or self.game
        self.env["PATH"] = str(bindir) + ":/usr/bin:/bin"
        self.env["NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"] = str(game)
        subprocess.run([str(ROOT / "Sandbox game preferences")], env=self.env,
                       capture_output=True, timeout=15, check=True)
        import runpy
        module = runpy.run_path(str(ROOT / "sandbox-game-dialog"))
        state = module["Preferences"](json.loads(Path(self.env["DIALOG_RECORD"]).read_text()))
        if launch_with:
            state.set_runtime("proton" if launch_with == "Proton (Windows .exe)" else "auto")
        def current_first(current, choices):
            return [current] + [c for c in choices if c != current]
        combos = {"Display": current_first(module["DISPLAY_CHOICES"][state.display],
                                          [module["DISPLAY_CHOICES"][d] for d in state.displays]),
                  "MangoHud overlay": ["Off (forced: hangs NW.js)"] if state.engine == "nwjs" else ["Off", "On"]}
        if state.proton_controls:
            combos["Proton version"] = [state.values.get("proton", "auto")]
            combos["Mod loaders"] = ["Off"]
        if state.engine == "nwjs":
            combos["File names"] = current_first("Match exactly" if state.values["casefold"] == "0" else
                                                 "Ignore case, like Windows", ["Ignore case, like Windows", "Match exactly"])
            combos["WebGL"] = current_first("Vulkan" if state.values["webgl"] == "vulkan" else
                                            "Chromium's default", ["Chromium's default", "Vulkan"])
        name = self.cli("--print-name", gamedir or game).stdout.strip()
        settings = self.home / ".config" / "sandbox-game" / "games" / name
        saved = dict(l.split("=", 1) for l in settings.read_text().splitlines() if "=" in l) \
            if settings.exists() else {}
        return combos, saved

    def test_forced_proton_skips_detected_native_launchers(self):
        bindir = self.home / ".local" / "bin"
        bindir.mkdir(parents=True)
        helpers = self.home / ".local" / "lib" / "sandbox-game"
        helpers.mkdir(parents=True)
        (helpers / "sandbox-game-lib").symlink_to(ROOT / "sandbox-game-lib")
        recorded = self.base / "launched"
        stub = bindir / "sandbox-game"
        stub.write_text('#!/bin/sh\n'
                        f'[ "$1" = --print-name ] && exec "{ROOT / "sandbox-game"}" "$@"\n'
                        f'printf "%s\\n" "$@" > "{recorded}"\n')
        stub.chmod(0o755)
        config = self.home / ".config" / "sandbox-game"
        (config / "games").mkdir(parents=True)
        (config / "defaults").write_text("launch_with=proton\nproton=GE-Test\nmod_loaders=1\n")
        self.env["PATH"] = "/usr/bin:/bin"
        builds = {
            "pgmmv": "data/project.json", "rgss": "Game.ini",
            "nwjs": "www/index.html", "native": "start.sh",
        }
        for engine, marker in builds.items():
            game = self.base / "games" / engine
            entry = game / marker
            entry.parent.mkdir(parents=True)
            entry.write_text("Library=RGSS301.dll\n")
            exe = game / "game.exe"
            exe.touch()
            for selection in (game, entry, exe):
                with self.subTest(engine=engine, selection=selection):
                    self.env["NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"] = str(selection)
                    result = subprocess.run([str(ROOT / "Sandbox game")], env=self.env,
                                            capture_output=True, text=True, timeout=15)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    args = recorded.read_text().splitlines()
                    self.assertEqual(args[-2:], [str(game), "/game/game.exe"])
                    self.assertIn("--proton=GE-Test", args)
                    self.assertIn("--mod-loaders", args)
                    self.assertNotIn("--pgmmv", args)
                    self.assertNotIn("--mkxp", args)
        # A per-game auto choice overrides the library's forced Proton.
        (config / "games" / "native").write_text("launch_with=auto\n")
        self.env["NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"] = str(game)
        result = subprocess.run([str(ROOT / "Sandbox game")], env=self.env,
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(recorded.read_text().splitlines()[-1], "/game/start.sh")
        # Never pass a Linux launcher to Proton when no Windows build exists.
        (config / "games" / "native").write_text("launch_with=proton\n")
        exe.unlink()
        self.env["SANDBOX_DIALOG"] = str(ROOT / "tests" / "dialog_recorder.py")
        error = self.base / "error-dialog"
        self.env["DIALOG_RECORD"] = str(error)
        result = subprocess.run([str(ROOT / "Sandbox game")], env=self.env,
                                capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Proton requested, but no Windows .exe", error.read_text())

    def stub_launcher(self, then=""):
        """sandbox-game for the Nautilus scripts: records its arguments, then runs THEN."""
        bindir = self.home / ".local" / "bin"
        bindir.mkdir(parents=True, exist_ok=True)
        helpers = self.home / ".local" / "lib" / "sandbox-game"
        helpers.mkdir(parents=True, exist_ok=True)
        if not (helpers / "sandbox-game-lib").exists():
            (helpers / "sandbox-game-lib").symlink_to(ROOT / "sandbox-game-lib")
        recorded = self.base / "launched"
        stub = bindir / "sandbox-game"
        stub.unlink(missing_ok=True)
        stub.write_text('#!/bin/sh\n'
                        f'[ "$1" = --print-name ] && exec "{ROOT / "sandbox-game"}" "$@"\n'
                        f'printf "%s\\n" "$@" > "{recorded}"\n{then}\n')
        stub.chmod(0o755)
        self.env["PATH"] = "/usr/bin:/bin"
        return recorded

    def dotnet_launcher(self):
        """A game folder like EpinelPS's: a .sh starting a .NET launcher, Windows programs beside."""
        game = self.base / "games" / "Epinelps"
        (game / "launcher").mkdir(parents=True)
        (game / "start.sh").write_text("#!/bin/sh\nexec /game/launcher/App\n")
        shutil.copyfile("/bin/true", game / "launcher" / "App")   # a real ELF program, as .NET's starter is
        (game / "launcher" / "App.runtimeconfig.json").write_text(
            '{"runtimeOptions": {"framework": {"name": "Microsoft.NETCore.App", "version": "10.0.0"}}}')
        (game / "launcher" / "Utility.exe").write_text("x")
        return game

    def test_standalone_linux_launcher_is_native_and_script_stays_preferred(self):
        recorded = self.stub_launcher()
        binary = self.game / "Game.x86_64"
        shutil.copyfile("/bin/true", binary)
        binary.chmod(0o755)
        (self.game / "Game.pck").write_bytes(b"pack")
        (self.game / "Game.exe").write_bytes(b"windows")
        for selection in (self.game, binary):
            self.env["NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"] = str(selection)
            result = subprocess.run([str(ROOT / "Sandbox game")], env=self.env,
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            args = recorded.read_text().splitlines()
            self.assertEqual(args[-2:], [str(self.game), "/game/Game.x86_64"])
            self.assertFalse(any(arg.startswith("--proton") for arg in args))
        (self.game / "start.sh").write_text("#!/bin/sh\n")
        args = self.launch_with(recorded, self.game, "")
        self.assertEqual(args[-1], "/game/start.sh")
        # A saved Proton override still selects the Windows build.
        args = self.launch_with(recorded, self.game, "launch_with=proton\n")
        self.assertIn("--proton", args)
        self.assertEqual(args[-1], "/game/Game.exe")

    def test_native_binary_permission_repair_only_changes_the_sandbox_overlay(self):
        recorded = self.stub_launcher()
        binary = self.game / "Game ; $(touch unexpected).x86_64"
        shutil.copyfile("/bin/true", binary)
        binary.chmod(0o644)
        args = self.launch_with(recorded, self.game, "")
        command = args[args.index(str(self.game)) + 1:]
        self.assertEqual(command, ["/game/" + binary.name])
        # The backend repairs it, whoever starts it.
        self.assertEqual(self.cli("--headless", self.game, *command).returncode, 0)
        self.assertEqual(binary.stat().st_mode & 0o111, 0)
        captured = self.home / "game-sandboxes/game/rw" / binary.name
        self.assertTrue(captured.stat().st_mode & 0o100)
        self.assertFalse((self.game / "unexpected").exists())
        self.assertFalse((self.home / "game-sandboxes/game/rw/unexpected").exists())
        # An update replaces the copy rather than hiding behind it.
        update = self.base / "update"
        shutil.copyfile("/bin/false", update)
        update.chmod(0o644)
        os.utime(update, (1, 1))
        update.replace(binary)
        self.assertEqual(self.cli("--headless", self.game, *command, check=False).returncode, 1)
        self.assertEqual(captured.read_bytes(), Path("/bin/false").read_bytes())
        # With its bit back, the install shows through again.
        binary.chmod(0o755)
        self.assertEqual(self.cli("--headless", self.game, *command, check=False).returncode, 1)
        self.assertFalse(captured.exists())

    def test_data_files_are_never_run_and_scripts_run_through_their_interpreter(self):
        data = self.game / "readme.txt"
        data.write_text("echo SCRIPT-RAN\n")
        result = self.cli("--headless", self.game, "/game/readme.txt", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("SCRIPT-RAN", result.stdout)
        self.assertFalse((self.home / "game-sandboxes/game/rw/readme.txt").exists())
        recorded = self.stub_launcher()
        self.env["NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"] = str(data)
        subprocess.run([str(ROOT / "Sandbox game")], env=self.env, capture_output=True, timeout=15)
        self.assertEqual(recorded.read_text().splitlines()[-1], "/game/readme.txt")
        (self.game / "Game.sh").write_text("#!/bin/sh -e\r\necho \"ran $0\"\n")
        (self.game / "plain.sh").write_text("echo \"plain $0\"\n")
        for script in ("Game.sh", "plain.sh"):
            with self.subTest(script=script):
                result = self.cli("--headless", self.game, "/game/" + script)
                self.assertTrue(result.stdout.endswith(f" /game/{script}\n"), result.stdout)
                self.assertFalse((self.home / "game-sandboxes/game/rw" / script).exists())

    def test_executable_copy_never_follows_links_the_game_left_in_rw(self):
        (self.game / "bin").mkdir()
        shutil.copyfile("/bin/true", self.game / "bin/Game")
        outside = self.base / "outside"
        outside.mkdir()
        rw = self.home / "game-sandboxes/game/rw"
        rw.mkdir(parents=True)
        (rw / "bin").symlink_to(outside, target_is_directory=True)
        self.cli("--headless", self.game, "/game/bin/Game", check=False)
        self.assertEqual(list(outside.iterdir()), [])

    def launch_with(self, recorded, game, prefs):
        """Launch GAME from Nautilus with these per-game preferences; the arguments passed on."""
        config = self.home / ".config" / "sandbox-game" / "games"
        config.mkdir(parents=True, exist_ok=True)
        (config / self.cli("--print-name", game).stdout.strip()).write_text(prefs)
        self.env["NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"] = str(game)
        result = subprocess.run([str(ROOT / "Sandbox game")], env=self.env,
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        return recorded.read_text().splitlines()

    def test_launcher_gives_dotnet_only_to_programs_needing_it(self):
        recorded = self.stub_launcher()
        game = self.dotnet_launcher()
        args = self.launch_with(recorded, game, "dotnet=1\n")
        self.assertEqual(args[-2:], [str(game), "/game/start.sh"])
        self.assertIn("--dotnet", args)
        self.assertNotIn("--dotnet", self.launch_with(recorded, game, "dotnet=0\n"))
        # Opt-in: off unless the preferences say so.
        self.assertNotIn("--dotnet", self.launch_with(recorded, game, ""))
        # Not for a program that brings its own runtime.
        (game / "launcher" / "App.runtimeconfig.json").write_text(
            '{"runtimeOptions": {"includedFrameworks": [{"name": "Microsoft.NETCore.App"}]}}')
        self.assertNotIn("--dotnet", self.launch_with(recorded, game, "dotnet=1\n"))
        # Nor for the Windows programs beside it, run with Proton instead.
        (game / "launcher" / "App.runtimeconfig.json").write_text(
            '{"runtimeOptions": {"framework": {"name": "Microsoft.NETCore.App"}}}')
        self.assertNotIn("--dotnet", self.launch_with(recorded, game, "dotnet=1\nlaunch_with=proton\n"))

    def test_launcher_gives_proton_to_native_programs_only(self):
        recorded = self.stub_launcher()
        game = self.dotnet_launcher()
        self.assertIn("--with-proton=GE-Test", self.launch_with(recorded, game, "with_proton=GE-Test\n"))
        self.assertIn("--with-proton", self.launch_with(recorded, game, "with_proton=auto\n"))
        for prefs in ("with_proton=\n", "", "with_proton=auto\nlaunch_with=proton\n"):
            args = self.launch_with(recorded, game, prefs)
            self.assertFalse([a for a in args if a.startswith("--with-proton")], (prefs, args))

    def test_launcher_passes_lan_preferences_only_with_the_internet(self):
        recorded = self.stub_launcher()
        (self.game / "run.sh").write_text("#!/bin/sh\n")
        args = self.launch_with(recorded, self.game, "net=1\nlan_allow=10.0.50.105:443, 192.168.1.0/24\n")
        self.assertIn("--net", args)
        self.assertIn("--allow-lan=10.0.50.105:443, 192.168.1.0/24", args)
        self.assertNotIn("--lan", args)
        # The whole LAN covers the list.
        args = self.launch_with(recorded, self.game, "net=1\nlan=1\nlan_allow=10.0.50.105\n")
        self.assertIn("--lan", args)
        self.assertFalse([a for a in args if a.startswith("--allow-lan")])
        args = self.launch_with(recorded, self.game, "net=0\nlan=1\nlan_allow=10.0.50.105\n")
        self.assertFalse([a for a in args if a.startswith(("--net", "--lan", "--allow-lan"))], args)

    def test_launcher_passes_hosts_preferences_behind_their_switch(self):
        recorded = self.stub_launcher()
        (self.game / "run.sh").write_text("#!/bin/sh\n")
        args = self.launch_with(recorded, self.game,
                                "private_hosts=1\nhosts_writable=1\n"
                                "hosts=10.0.50.105 a.example b.example, 255.255.221.21 sentry.io,\n")
        for flag in ("--hosts", "--add-host=10.0.50.105 a.example b.example",
                     "--add-host=255.255.221.21 sentry.io", "--hosts-writable"):
            self.assertIn(flag, args)
        self.assertEqual(len([a for a in args if a.startswith("--add-host")]), 2)
        args = self.launch_with(recorded, self.game, "private_hosts=0\nhosts=10.0.0.1 x\nhosts_writable=1\n")
        self.assertFalse([a for a in args if a.startswith(("--hosts", "--add-host"))], args)

    def test_failure_window_points_dotnet_programs_at_the_preference(self):
        self.stub_launcher('echo "You must install .NET to run this application." >&2; exit 131')
        game = self.dotnet_launcher()
        self.env["SANDBOX_DIALOG"] = str(ROOT / "tests" / "dialog_recorder.py")
        self.env["DIALOG_RECORD"] = str(self.base / "shown.json")
        self.env["NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"] = str(game)
        config = self.home / ".config" / "sandbox-game" / "games"
        config.mkdir(parents=True)
        for prefs, hint in (("", 'turn on ".NET runtime" in Sandbox game preferences'),
                            ("dotnet=1\n", "not a version it accepts")):
            (config / "epinelps").write_text(prefs)
            result = subprocess.run([str(ROOT / "Sandbox game")], env=self.env,
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 131)
            shown = json.loads((self.base / "shown.json").read_text())
            self.assertEqual(shown[0], "log")
            self.assertTrue(shown[-1].startswith("This is a .NET program" if not prefs else "The sandbox"))
            self.assertIn(hint, shown[-1])
            self.assertIn("You must install .NET", shown[-1])
        # Nothing about .NET for other failures.
        self.stub_launcher("exit 1")
        subprocess.run([str(ROOT / "Sandbox game")], env=self.env, capture_output=True, timeout=15)
        self.assertNotIn(".NET", json.loads((self.base / "shown.json").read_text())[-1])

    def test_preferences_offer_and_save_the_dotnet_runtime(self):
        game = self.dotnet_launcher()
        self.env["TEST_VALUES"] = json.dumps({"dotnet": "1"})
        _, saved = self.preferences(["Native Wayland", "Off", "Off", "This game only"], game)
        self.assertTrue(json.loads(Path(self.env["DIALOG_RECORD"]).read_text())["dotnet"])
        self.assertEqual(saved["dotnet"], "1")
        # Not offered for a game without such a program.
        (self.game / "run.sh").write_text("#!/bin/sh\n")
        self.preferences([], self.game)
        self.assertFalse(json.loads(Path(self.env["DIALOG_RECORD"]).read_text())["dotnet"])

    def test_preferences_save_proton_for_native_programs(self):
        game = self.dotnet_launcher()
        self.env["TEST_VALUES"] = json.dumps({"with_proton": "auto"})
        _, saved = self.preferences(["Native Wayland", "Off", "Off", "This game only"], game)
        self.assertEqual(saved["with_proton"], "auto")
        self.env["TEST_VALUES"] = json.dumps({"with_proton": ""})
        _, saved = self.preferences(["Native Wayland", "Off", "Off", "This game only"], game)
        self.assertNotIn("with_proton", saved)          # none, as the defaults have none

    def test_preferences_save_lan_allowances(self):
        (self.game / "run.sh").write_text("#!/bin/sh\n")
        self.env["TEST_VALUES"] = json.dumps({"lan_allow": "10.0.50.105:443"})
        _, saved = self.preferences(["Native Wayland", "Off", "On", "This game only"])
        self.assertEqual((saved["net"], saved["lan"], saved["lan_allow"]), ("1", "0", "10.0.50.105:443"))
        # Hidden without the internet, the list is kept as it was.
        self.env["TEST_VALUES"] = json.dumps({"lan_allow": ""})
        _, saved = self.preferences(["Native Wayland", "Off", "Off", "This game only"])
        self.assertEqual((saved["net"], saved["lan_allow"]), ("0", "10.0.50.105:443"))
        # A list the window would have refused is not saved however it arrives.
        self.env["TEST_VALUES"] = json.dumps({"lan_allow": "nas.local"})
        with self.assertRaises(subprocess.CalledProcessError) as refused:
            self.preferences(["Native Wayland", "Off", "On", "This game only"])
        self.assertIn(b"nas.local", refused.exception.stderr)
        _, saved = self.preferences([])                  # cancelled: still as before
        self.assertEqual(saved["lan_allow"], "10.0.50.105:443")

    def test_game_settings_leave_hidden_defaults_alone(self):
        # Hidden behind the Internet switch, the LAN settings are not the
        # game's to save: written with built-in values, they would override
        # the defaults for that game from then on.
        (self.game / "run.sh").write_text("#!/bin/sh\n")
        config = self.home / ".config" / "sandbox-game"
        config.mkdir(parents=True)
        (config / "defaults").write_text("lan=1\nlan_allow=10.0.50.105\nhosts_writable=1\n")
        _, saved = self.preferences(["Native Wayland", "Off", "Off", "This game only"])
        self.assertEqual(saved["net"], "0")
        for key in ("lan", "lan_allow", "hosts_writable"):
            self.assertNotIn(key, saved)
        # What the game's own file already has is kept, hidden or not.
        settings = config / "games" / self.cli("--print-name", self.game).stdout.strip()
        settings.write_text(settings.read_text() + "lan=0\n")
        _, saved = self.preferences(["Native Wayland", "Off", "Off", "This game only"])
        self.assertEqual(saved["lan"], "0")

    def test_preferences_save_hosts_entries(self):
        (self.game / "run.sh").write_text("#!/bin/sh\n")
        self.env["TEST_VALUES"] = json.dumps({
            "private_hosts": "1", "hosts": "10.0.50.105 a.example\n255.255.221.21 sentry.io",
            "hosts_writable": "1"})
        _, saved = self.preferences(["Native Wayland", "Off", "Off", "This game only"])
        self.assertEqual((saved["private_hosts"], saved["hosts"], saved["hosts_writable"]),
                         ("1", "10.0.50.105 a.example, 255.255.221.21 sentry.io", "1"))
        # Hidden behind their switch, the entries are kept as they were.
        self.env["TEST_VALUES"] = json.dumps({"private_hosts": "0", "hosts": ""})
        _, saved = self.preferences(["Native Wayland", "Off", "Off", "This game only"])
        self.assertEqual(saved["private_hosts"], "0")
        self.assertEqual(saved["hosts"], "10.0.50.105 a.example, 255.255.221.21 sentry.io")
        self.env["TEST_VALUES"] = json.dumps({"private_hosts": "1", "hosts": "sentry.io 255.255.221.21"})
        with self.assertRaises(subprocess.CalledProcessError) as refused:
            self.preferences(["Native Wayland", "Off", "Off", "This game only"])
        self.assertIn(b"sentry.io", refused.exception.stderr)

    def test_runtime_choice_updates_preferences_and_can_be_cancelled(self):
        (self.game / "www").mkdir()
        (self.game / "www" / "index.html").touch()
        (self.game / "game.exe").touch()
        combos, saved = self.preferences([
            "Native Wayland", "On", "GE-Test", "Off", "Off", "This game only"
        ], launch_with="Proton (Windows .exe)")
        self.assertEqual(saved["launch_with"], "proton")
        self.assertEqual(saved["proton"], "GE-Test")
        self.assertEqual(saved["mangohud"], "1")
        self.assertIn("Proton version", combos)
        self.assertNotIn("Native Wayland, in gamescope", combos["Display"])
        self.assertNotIn("File names", combos)
        self.assertNotIn("WebGL", combos)
        # Cancelling the main form must not save the tentative runtime choice.
        combos, cancelled = self.preferences([], launch_with="Automatic")
        self.assertEqual(cancelled, saved)
        self.assertNotIn("Proton version", combos)
        self.assertIn("File names", combos)
        self.assertIn("Off (forced: hangs NW.js)", combos["MangoHud overlay"])
        _, automatic = self.preferences([
            "Native Wayland", "", "", "", "Off", "This game only"
        ], launch_with="Automatic")
        self.assertEqual(automatic["launch_with"], "auto")
        self.assertEqual(automatic["proton"], "GE-Test")

    def test_display_choices_save_what_they_say(self):
        # One Display choice, saved as the keys the launcher reads. X11 in
        # gamescope is gamescope=0: the launcher puts gamescope around private
        # Xwayland itself, and a later switch to Wayland does not find it
        # pinned on.
        def save(display):
            return self.preferences([display, "Off", "Newest installed (auto)", "Off", "Off",
                                     "This game only"])[1]
        keys = lambda d: (d["wayland"], d["gamescope"], d["host_x11"])
        self.assertEqual(keys(save("X11, in gamescope (private Xwayland)")), ("0", "0", "0"))
        self.assertEqual(keys(save("Native Wayland")), ("1", "0", "0"))
        self.assertEqual(keys(save("Native Wayland, in gamescope")), ("1", "1", "0"))
        self.assertEqual(keys(save("Host X11 (other X apps can watch and control it)")),
                         ("0", "0", "1"))

    def test_split_display_is_saved_and_forwarded_to_the_cli(self):
        (self.game / "play.exe").touch()
        self.env["TEST_VALUES"] = json.dumps({"x11_exe": "Vendor Launcher.exe"})
        _, saved = self.preferences(["Native Wayland + private X11 (split)", "Off", "auto", "Off", "Off",
                                     "This game only"])
        self.assertEqual((saved["wayland"], saved["wayland_x11"], saved["gamescope"]), ("1", "1", "0"))
        self.assertEqual(saved["x11_exe"], "Vendor Launcher.exe")
        recorded = self.stub_launcher()
        args = self.launch_with(recorded, self.game, "".join(f"{key}={value}\n" for key, value in saved.items()))
        self.assertIn("--wayland-x11", args)
        self.assertIn("--x11-exe=Vendor Launcher.exe", args)
        self.assertNotIn("--wayland", args)

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
        self.assertEqual(sorted(combos["Display"]), sorted((set(all_four) - {all_four[1]}) |
                         {"Native Wayland + private X11 (split)"}))
        self.assertIn("Proton version", combos)
        self.assertEqual(combos["Mod loaders"][0], "Off")
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
        self.assertNotIn("Mod loaders", combos)
        # A native game that can do Wayland gets all four, and no Proton row.
        native = self.base / "games" / "Native"
        native.mkdir()
        (native / "run.sh").write_text("#!/bin/sh\n")
        combos, _ = self.preferences([], native)
        self.assertEqual(sorted(combos["Display"]), sorted(all_four))
        self.assertNotIn("Proton version", combos)
        self.assertNotIn("File names", combos)                # not an NW.js game
        self.assertNotIn("WebGL", combos)

    def test_nwjs_games_choose_file_name_case_and_webgl(self):
        rpgm = self.base / "games" / "Rpgm"
        (rpgm / "www").mkdir(parents=True)
        (rpgm / "www" / "index.html").write_text("")
        combos, _ = self.preferences([], rpgm)                  # the defaults
        self.assertEqual(combos["File names"][0], "Ignore case, like Windows")
        self.assertEqual(combos["WebGL"][0], "Chromium's default")
        _, saved = self.preferences(["Native Wayland", "", "Match exactly", "Vulkan", "Off",
                                     "This game only"], rpgm)
        self.assertEqual((saved["casefold"], saved["webgl"]), ("0", "vulkan"))
        combos, saved = self.preferences(["Native Wayland", "", "", "", "Off",
                                          "This game only"], rpgm)
        self.assertEqual((combos["File names"][0], combos["WebGL"][0]),
                         ("Match exactly", "Vulkan"))
        self.assertEqual((saved["casefold"], saved["webgl"]), ("0", "vulkan"))  # kept

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

    def test_expand_environment_detection_survives_sigpipe(self):
        # The switch is named early in a long help text. Piped into grep -q,
        # which leaves at the first match, systemd-run died of SIGPIPE on its
        # next write, pipefail failed the test and the switch was left out.
        self.recorded_args()                          # sets up PATH and bin/
        log = self.base / "systemd-run.log"
        systemd_run = self.base / "bin" / "systemd-run"
        systemd_run.write_text(
            '#!/bin/sh\n'
            'if [ "$1" = --help ]; then\n'
            '    printf -- "--expand-environment=BOOL\\n"; sleep 0.3\n'
            '    i=0; while [ $i -lt 2000 ]; do printf "%064d\\n" 0; i=$((i+1)); done\n'
            '    exit 0\n'
            'fi\n'
            f'printf "%s\\n" "$*" >> {str(log)!r}\n'
            'while [ "$1" != -- ]; do shift; done; shift; exec "$@"\n')
        systemd_run.chmod(0o755)
        self.recorded_args()
        launch = log.read_text().splitlines()[-1]
        self.assertTrue("--expand-environment=no" in launch.split(),
                        "the scope was started without --expand-environment=no")

    def test_hardware_identifiers_are_covered(self):
        # World-readable, and each enough to tell this machine apart: monitor
        # EDIDs, disk serials in SCSI VPD pages, LUKS and LVM UUIDs, and
        # Thunderbolt device IDs. Checked against what this machine has.
        import glob
        patterns = ("/sys/class/drm/card*-*/edid", "/sys/bus/thunderbolt/devices/*/unique_id",
                    "/sys/bus/scsi/devices/*/vpd_pg80", "/sys/bus/scsi/devices/*/vpd_pg83",
                    "/sys/block/*/dm/uuid")
        present = {os.path.realpath(f) for p in patterns for f in glob.glob(p)
                   if os.access(f, os.R_OK)}
        if not present:
            self.skipTest("none of these identifiers on this machine")
        args = self.recorded_args()
        empty = str(self.home / "game-sandboxes" / "game" / ".empty")
        covered = {args[i + 2] for i, a in enumerate(args)
                   if a == "--ro-bind-try" and args[i + 1] == empty}
        self.assertEqual(present - covered, set())

    def test_attach_socket_is_made_above_the_game(self):
        # Under gamescope the game's sandbox-landlock runs in gamescope's
        # domain when it makes the socket: that layer may write there, the
        # game's may not. Without gamescope it is made before any layer.
        def layers(args):
            starts = [i for i, a in enumerate(args)
                      if a == "/run/sandbox-landlock" and args[i + 1:i + 2] == ["--ls"]]
            return [args[i + 1:args.index("--", i)] for i in starts]
        def pairs(layer):
            return list(zip(layer, layer[1:]))
        args = self.recorded_args()                            # gamescope
        self.assertIn(("--dir", "/run/sandbox-attach"), pairs(args))
        outer, inner = layers(args)
        self.assertIn(("--rw", "/run/sandbox-attach"), pairs(outer))
        self.assertNotIn(("--attach", "/run/sandbox-attach"), pairs(outer))
        self.assertIn(("--attach", "/run/sandbox-attach"), pairs(inner))
        self.assertNotIn("/run/sandbox-attach", [b for a, b in pairs(inner) if a != "--attach"])
        (only,) = layers(self.recorded_args("--wayland"))
        self.assertEqual([b for a, b in pairs(only) if b == "/run/sandbox-attach"],
                         ["/run/sandbox-attach"])
        self.assertIn(("--attach", "/run/sandbox-attach"), pairs(only))

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
        # --unix-connect: that one socket, and nothing else where it is.
        probe.write_text(probe.read_text() + "try: open(sys.argv[1] + '-new', 'w'); print('created')\n"
                         "except OSError as e: print(e.strerror.replace(' ', '_'))\n")
        granted = subprocess.run([landlock, *rules, "--", landlock, *rules, "--unix-connect", servers[0],
                                  "--unix-connect-where-writable", "--no-abstract-scope", "--",
                                  sys.executable, str(probe), *servers],
                                 capture_output=True, text=True, timeout=15).stdout.split()
        self.assertEqual(granted, ["connected", "connected", "Permission_denied"])

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
                                  "--client-name=sandbox-test-other",
                                  "--stream-name=sandbox-test-title", "/dev/zero"],
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
            printf 'seen=%s\n' "$(pactl list sink-inputs clients 2>/dev/null | grep -c sandbox-test)"
            printf 'clients=%s\n' "$(pactl list short clients 2>/dev/null | wc -l)"
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
        # Other applications' streams and clients: titles, programs, PIDs.
        # The one client left is the game's own pactl.
        self.assertEqual(seen["seen"], "0", "the game could see another application's stream")
        self.assertEqual(seen["clients"], "1", "the game could see other clients")
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
