"""Preference policy and GTK signal tests; GUI tests need a display server."""
import itertools
import runpy
import unittest
from pathlib import Path

MODULE = runpy.run_path(str(Path(__file__).resolve().parents[1] / "sandbox-game-dialog"))
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

    def test_gamescope_edits_preserve_other_options(self):
        state = Preferences({"engine": "native", "values": {
            "gamescope_args": "--fullscreen --output-height 1080 -W 1920 --adaptive-sync -r 60"}})
        state.resolution = ""
        state.fullscreen = False
        self.assertEqual(state.result()["gamescope_args"], "--adaptive-sync -r 60")
        state.display = "wayland"
        self.assertNotIn("gamescope_args", state.result())
        state.scope = "clear"
        self.assertEqual(state.result(), {"scope": "clear"})


class GtkDialogTests(unittest.TestCase):
    ids = itertools.count()
    @classmethod
    def setUpClass(cls):
        try:
            cls.Gio, cls.Gtk = MODULE["gtk_modules"]()
        except (ImportError, ValueError):
            raise unittest.SkipTest("GTK 4 Python bindings are unavailable")
        if not cls.Gtk.init_check():
            raise unittest.SkipTest("GTK needs a display (run with xvfb-run)")

    def create(self, mode, request):
        app = self.Gtk.Application(application_id=f"eu.nosini.SandboxGame.Test{next(self.ids)}",
                                   flags=self.Gio.ApplicationFlags.NON_UNIQUE)
        app.register(None)
        self.responses = []
        dialog = MODULE["Dialog"](self.Gtk, app, mode, request,
                                  lambda code, response: self.responses.append((code, response)))
        self.addCleanup(dialog.window.destroy)
        self.app = app
        return dialog

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
