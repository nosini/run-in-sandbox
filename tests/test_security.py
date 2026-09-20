#!/usr/bin/env python3
"""Run on the host: python3 -m unittest discover -s tests -v.

Uses real bubblewrap for filesystem/namespace checks and temporary command
recorders for display/audio policy checks, without opening a game window.
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
        for key in ("MANGOHUD", "PROTON_DIR", "MKXP_DIR"):
            self.env.pop(key, None)

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
            'test ! -e "$XDG_RUNTIME_DIR/pulse/native"; '
            'test ! -e "$XDG_RUNTIME_DIR/pipewire-0"; '
            'test ! -e /tmp/.Xauthority; test -z "${DISPLAY+x}"; '
            'printf changed > /game/original; '
            'printf save > "$HOME/save"; readlink /proc/self/ns/net')
        self.assertNotEqual(result.stdout.strip(), os.readlink("/proc/self/ns/net"))
        self.assertEqual((self.game / "original").read_text(), "original")
        name = self.cli("--print-name", self.game).stdout.strip()
        capture = self.home / "game-sandboxes" / name
        self.assertEqual((capture / "home" / "save").read_text(), "save")
        self.assertEqual((capture / "rw" / "original").read_text(), "changed")

    def test_attach_uses_target_root_and_cwd(self):
        (self.home / "host-secret").write_text("private")
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
             'printf attached > "$HOME/attached"'],
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
            "Newest installed (auto)", "Host audio (allows microphone recording)",
            "This game only"])
        result = subprocess.run([str(ROOT / "Sandbox game preferences")],
                                env=self.env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        name = self.cli("--print-name", self.game).stdout.strip()
        settings = (self.home / ".config" / "sandbox-game" / "games" / name).read_text()
        for entry in ("host_x11=1", "audio=1", "wayland=0", "gamescope=0"):
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

    def test_default_display_is_private_and_audio_is_absent(self):
        args = self.recorded_args()
        self.assertIn("gamescope", args)
        self.assertNotIn("/tmp/.Xauthority", args)
        self.assertNotIn("DISPLAY", args)
        self.assertNotIn(str(self.runtime / "pulse"), args)
        self.assertNotIn(str(self.runtime / "pipewire-0"), args)
        self.assertIn("--dev", args)

    def test_host_display_and_audio_require_explicit_options(self):
        args = self.recorded_args("--host-x11", "--audio")
        self.assertNotIn("gamescope", args)
        self.assertIn("DISPLAY", args)
        self.assertIn(str(self.runtime / "pulse"), args)
        self.assertIn(str(self.runtime / "pipewire-0"), args)
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
