"""Preference policy and GTK signal tests; GUI tests need a display server."""
import itertools
import os
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = runpy.run_path(str(ROOT / "sandbox-game-dialog"))
Preferences = MODULE["Preferences"]


class PreferencePolicyTests(unittest.TestCase):
    def test_switching_runtime_preserves_edits_and_omits_hidden_settings(self):
        state = Preferences({"engine": "nwjs", "can_proton": True, "values": {
            "mangohud": "1", "proton": "GE-Test", "casefold": "0", "webgl": "vulkan"}})
        self.assertNotIn("mangohud", state.result())
        self.assertNotIn("proton", state.result())
        state.display = "wayland-gamescope"
        state.set_runtime("proton")
        self.assertEqual(state.display, "x11")
        self.assertEqual(state.result()["mangohud"], "1")
        self.assertEqual(state.result()["proton"], "GE-Test")
        self.assertNotIn("webgl", state.result())
        state.set_runtime("auto")
        self.assertEqual(state.result()["casefold"], "0")
        self.assertEqual(state.result()["webgl"], "vulkan")

    def test_gamescope_response_contains_only_editable_controls(self):
        state = Preferences({"engine": "native", "values": {
            "gamescope_args": "--fullscreen --output-height 1080 -W 1920 --adaptive-sync -r 60"}})
        state.resolution = ""
        state.fullscreen = False
        self.assertEqual(state.result()["gamescope_resolution"], "")
        self.assertEqual(state.result()["gamescope_fullscreen"], "0")
        self.assertNotIn("gamescope_args", state.result())
        self.assertNotIn("--adaptive-sync", repr(state.result()))
        state.display = "wayland"
        self.assertNotIn("gamescope_resolution", state.result())
        self.assertNotIn("gamescope_fullscreen", state.result())
        state.scope = "clear"
        self.assertEqual(state.result(), {"scope": "clear"})

    def test_dotnet_only_for_native_programs_needing_it(self):
        state = Preferences({"engine": "native", "dotnet": True, "values": {"dotnet": "1"}})
        self.assertEqual(state.result()["dotnet"], "1")
        state.set_runtime("proton")                  # the .exe under Proton instead
        self.assertNotIn("dotnet", state.result())
        plain = Preferences({"engine": "native", "values": {"dotnet": "1"}})
        self.assertNotIn("dotnet", plain.result())


class GtkDialogTests(unittest.TestCase):
    ids = itertools.count()
    @classmethod
    def setUpClass(cls):
        try:
            cls.Gio, cls.Gtk, cls.Adw = MODULE["gtk_modules"]()
        except (ImportError, ValueError):
            raise unittest.SkipTest("GTK 4 / libadwaita Python bindings are unavailable")
        if not cls.Gtk.init_check():
            raise unittest.SkipTest("GTK needs a display (run with xvfb-run)")
        cls.Adw.init()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="sandbox-theme-test-")
        self.addCleanup(self.tmp.cleanup)
        self.theme_file = Path(self.tmp.name) / "interface"

    def create(self, mode, request):
        app = self.Gtk.Application(application_id=f"eu.nosini.SandboxGame.Test{next(self.ids)}",
                                   flags=self.Gio.ApplicationFlags.NON_UNIQUE)
        app.register(None)
        self.responses = []
        appearance = MODULE["Appearance"](self.Adw, self.theme_file)
        dialog = MODULE["Dialog"](self.Gtk, app, mode, request,
                                  lambda code, response: self.responses.append((code, response)), appearance)
        self.addCleanup(dialog.window.destroy)
        self.app = app
        return dialog

    def test_dark_theme_previews_then_cancel_restores_without_saving(self):
        dialog = self.create("preferences", {"engine": "native"})
        dialog.widgets["appearance"].set_selected(2)
        self.assertTrue(dialog.appearance.manager.get_dark())
        self.assertFalse(self.theme_file.exists())
        dialog.cancel()
        self.assertFalse(self.theme_file.exists())
        self.assertEqual(dialog.appearance.manager.get_color_scheme(), self.Adw.ColorScheme.DEFAULT)

    def test_saved_dark_theme_is_used_by_other_dialogs(self):
        dialog = self.create("preferences", {"engine": "native"})
        dialog.widgets["appearance"].set_selected(2)
        dialog.save_preferences()
        self.assertEqual(self.theme_file.read_text(), "theme=dark\n")
        self.assertNotIn("theme", self.responses[0][1])  # independent of game/default scope
        message = self.create("error", {"text": "Game failed"})
        self.assertTrue(message.appearance.manager.get_dark())
        light = self.create("preferences", {"engine": "native"})
        light.widgets["appearance"].set_selected(1)
        self.assertFalse(light.appearance.manager.get_dark())
        light.save_preferences()
        self.assertEqual(self.theme_file.read_text(), "theme=light\n")

    def test_launcher_changes_controls_inside_the_same_window(self):
        dialog = self.create("preferences", {"engine": "nwjs", "can_proton": True,
                                              "values": {"mangohud": "1", "proton": "GE-Test"}})
        window = dialog.window
        self.assertTrue(dialog.rows["webgl"].get_visible())
        self.assertFalse(dialog.rows["proton"].get_visible())
        self.assertFalse(dialog.widgets["mangohud"].get_sensitive())
        dialog.widgets["launch_with"].set_selected(1)
        self.assertIs(dialog.window, window)
        self.assertEqual(len(self.app.get_windows()), 1)
        self.assertFalse(dialog.rows["webgl"].get_visible())
        self.assertTrue(dialog.rows["proton"].get_visible())
        self.assertTrue(dialog.widgets["mangohud"].get_sensitive())
        self.assertTrue(dialog.widgets["mangohud"].get_active())
        self.assertNotIn("wayland-gamescope", [v for v, _ in dialog.choices["display"]])
        dialog.widgets["display"].set_selected(0)  # direct Wayland
        self.assertFalse(dialog.rows["resolution"].get_visible())
        dialog.widgets["display"].set_selected(1)  # private Xwayland
        self.assertTrue(dialog.rows["resolution"].get_visible())
        self.assertEqual(self.responses, [])
        dialog.save_preferences()
        self.assertEqual(self.responses[0][0], 0)
        self.assertEqual(self.responses[0][1]["launch_with"], "proton")
        self.assertEqual(self.responses[0][1]["proton"], "GE-Test")

    def test_dotnet_switch_only_for_programs_needing_it(self):
        dialog = self.create("preferences", {"engine": "native", "dotnet": True})
        self.assertTrue(dialog.rows["dotnet"].get_visible())
        dialog.widgets["dotnet"].set_active(True)
        dialog.save_preferences()
        self.assertEqual(self.responses[0][1]["dotnet"], "1")
        self.assertFalse(self.create("preferences", {"engine": "native"}).rows["dotnet"].get_visible())

    def test_cancel_after_editing_returns_no_preferences(self):
        dialog = self.create("preferences", {"engine": "pgmmv", "can_proton": True})
        dialog.widgets["launch_with"].set_selected(1)
        dialog.widgets["net"].set_active(True)
        dialog.cancel()
        self.assertEqual(self.responses, [(1, None)])

    def test_picker_returns_selection_and_messages_use_literal_text(self):
        dialog = self.create("pick", {"items": ["setup.exe", "game.exe"]})
        dialog.listbox.select_row(dialog.listbox.get_row_at_index(1))
        dialog.save_pick()
        self.assertEqual(self.responses, [(0, "game.exe")])
        message = self.create("error", {"text": "<b>game</b> & log"})
        label = message.body.get_first_child()
        self.assertEqual(label.get_label(), "<b>game</b> & log")
        self.assertFalse(label.get_use_markup())

    def test_log_bytes_open_and_close_with_strict_and_surrogateescape_stdin(self):
        # Exercise main's input decoding and the real GTK application loop.
        # A watchdog makes the old invisible-window failure exit promptly.
        script = r'''
import os, runpy, sys
from gi.repository import GLib
path = sys.argv[1]
module = runpy.run_path(path)
main = module["main"]
original = main.__globals__["Dialog"]
def inspect_dialog(*args):
    dialog = original(*args)
    buffer = dialog.body.get_first_child().get_buffer()
    text = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), True)
    assert text == "caf\ufffd\nUTF-8: caf\u00e9\n", repr(text)
    def close():
        if not dialog.window.get_mapped():
            return True
        dialog.buttons.get_first_child().emit("clicked")
        print("window opened and closed", flush=True)
        return False
    GLib.timeout_add(50, close)
    return dialog
main.__globals__["Dialog"] = inspect_dialog
GLib.timeout_add(2000, lambda: os._exit(3))
sys.argv = [path, "log"]
sys.exit(main())
'''
        for errors in ("strict", "surrogateescape"):
            with self.subTest(errors=errors):
                env = {**os.environ, "PYTHONIOENCODING": "utf-8:" + errors}
                result = subprocess.run(
                    [sys.executable, "-c", script, str(Path(__file__).resolve().parents[1] / "sandbox-game-dialog")],
                    input=b"caf\xe9\nUTF-8: caf\xc3\xa9\n", capture_output=True, env=env, timeout=5, check=False)
                self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
                self.assertIn(b"window opened and closed", result.stdout)
