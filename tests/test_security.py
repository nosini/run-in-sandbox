#!/usr/bin/env python3
"""Run on the host: python3 -m unittest discover -s tests -v.

Uses real bubblewrap for filesystem/namespace checks and temporary command
recorders for display policy checks, without opening a game window.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


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
        for key in ("MANGOHUD", "PROTON_DIR", "MKXP_DIR", "XDG_DATA_HOME"):
            self.env.pop(key, None)
        # A tools folder of the test's own, never the real one.
        self.tools = self.base / "tools"
        self.env["SANDBOX_TOOLS_DIR"] = str(self.tools)

    def cli(self, *args, check=True):
        return subprocess.run([str(ROOT / "sandbox-game"), *map(str, args)],
                              env=self.env, capture_output=True, text=True,
                              timeout=15, check=check)

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
            "Host X11 (allows access to other X apps)", "Off", "On",
            "Newest installed (auto)", "This game only"])
        result = subprocess.run([str(ROOT / "Sandbox game preferences")],
                                env=self.env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        name = self.cli("--print-name", self.game).stdout.strip()
        settings = (self.home / ".config" / "sandbox-game" / "games" / name).read_text()
        for entry in ("host_x11=1", "wayland=0", "gamescope=0"):
            self.assertIn(entry, settings.splitlines())

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

        self.assertEqual(self.cli("--stop", "game").stdout.strip(), "stopped game")
        first.wait(timeout=10)
        self.assertEqual(first.returncode, 0, first.stderr.read())
        self.assertFalse((self.home / "game-sandboxes" / "game" / ".stopped").exists())
        self.assertIsNone(second.poll(), "stopping 'game' also ended 'game-2'")

        self.assertEqual(self.cli("--stop-all").stdout.strip(), "stopped game-2")
        second.wait(timeout=10)
        self.assertEqual(second.returncode, 0)

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
        # A real Unix socket satisfies validation without a real compositor.
        import socket
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(str(self.runtime / "wayland-0"))
        self.addCleanup(sock.close)
        self.env["WAYLAND_DISPLAY"] = "wayland-0"
        self.env["DISPLAY"] = ":123"
        return json.loads(self.cli(*options, self.game, "/bin/true").stdout)

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


if __name__ == "__main__":
    if not shutil.which("bwrap"):
        raise SystemExit("Run on the host: bwrap is required")
    unittest.main()
