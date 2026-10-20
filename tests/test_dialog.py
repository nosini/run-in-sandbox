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
    def test_split_display_round_trip_and_runtime_switch(self):
        state = Preferences({"engine": "proton", "values": {
            "wayland": "1", "wayland_x11": "1", "gamescope": "1", "x11_exe": "Launcher.exe"}})
        self.assertEqual(state.display, "wayland-x11")
        self.assertTrue(state.uses_gamescope)
        saved = state.result()
        # gamescope is implied: saved as 0, so no other engine reads gamescope into it.
        self.assertEqual((saved["wayland"], saved["wayland_x11"], saved["gamescope"]), ("1", "1", "0"))
        self.assertEqual(saved["x11_exe"], "Launcher.exe")
        state.display = "wayland"
        self.assertEqual(state.result()["wayland_x11"], "0")
        self.assertNotIn("x11_exe", state.result())
        native = Preferences({"engine": "native", "values": saved})
        self.assertEqual(native.display, "wayland")
        x11 = Preferences({"engine": "proton", "values": {**saved, "wayland": "0"}})
        self.assertEqual(x11.display, "x11")

    def test_unknown_engine_keeps_split_display(self):
        # The manager sends no engine for a game whose folder is gone.
        state = Preferences({"engine": "", "values": {
            "wayland": "1", "wayland_x11": "1", "gamescope": "1", "x11_exe": "Launcher.exe"}})
        self.assertEqual(state.display, "wayland-x11")
        self.assertEqual(state.result()["wayland_x11"], "1")
        self.assertEqual(state.result()["x11_exe"], "Launcher.exe")
        self.assertIn("wayland-gamescope", state.displays)

    def test_split_executable_with_control_characters_is_refused(self):
        state = Preferences({"engine": "proton", "values": {
            "wayland": "1", "wayland_x11": "1", "x11_exe": "Launcher.exe\t"}})
        self.assertIn("X11 executable", state.error())
        state.values["x11_exe"] = " Vendor Launcher.exe "
        self.assertIsNone(state.error())
        self.assertEqual(state.result()["x11_exe"], "Vendor Launcher.exe")
        # Not shown, not checked.
        state.values["x11_exe"] = "Launcher.exe\t"
        state.display = "wayland"
        self.assertIsNone(state.error())

    def test_switching_runtime_preserves_edits_and_omits_hidden_settings(self):
        state = Preferences({"engine": "nwjs", "can_proton": True, "values": {
            "mangohud": "1", "proton": "GE-Test", "casefold": "0", "webgl": "vulkan", "steam": "1",
            "hide_tray": "1"}})
        self.assertNotIn("mangohud", state.result())
        self.assertNotIn("proton", state.result())
        self.assertNotIn("steam", state.result())
        self.assertNotIn("hide_tray", state.result())
        state.display = "wayland-gamescope"
        state.set_runtime("proton")
        self.assertEqual(state.display, "x11")
        self.assertEqual(state.result()["mangohud"], "1")
        self.assertEqual(state.result()["proton"], "GE-Test")
        self.assertEqual(state.result()["steam"], "1")
        self.assertEqual(state.result()["hide_tray"], "1")
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

    def test_lan_controls_show_only_with_the_internet(self):
        state = Preferences({"engine": "native", "values": {
            "net": "0", "lan": "1", "lan_allow": "10.0.50.105:443"}})
        self.assertFalse(state.lan_controls)
        # Hidden, they are left for the saved file to keep.
        self.assertNotIn("lan", state.result())
        self.assertNotIn("lan_allow", state.result())
        state.values["net"] = "1"
        self.assertTrue(state.lan_controls)
        self.assertFalse(state.lan_allow_controls)    # the whole LAN covers it
        self.assertEqual(state.result()["lan"], "1")
        self.assertNotIn("lan_allow", state.result())
        state.values["lan"] = "0"
        state.values["lan_allow"] = " 10.0.50.105:443  192.168.1.0/24,,[fd00::1]:80/udp "
        self.assertEqual(state.result()["lan_allow"], "10.0.50.105:443, 192.168.1.0/24, [fd00::1]:80/udp")
        self.assertIsNone(state.error())
        state.values["lan_allow"] = "10.0.50.105:443, 127.0.0.1"
        self.assertIn("127.0.0.1", state.error())

    def test_hosts_entries_and_writing_follow_the_private_hosts_switch(self):
        state = Preferences({"engine": "proton", "values": {
            "private_hosts": "0", "hosts": "10.0.50.105 a.example b.example", "hosts_writable": "1"}})
        self.assertEqual(state.result()["private_hosts"], "0")
        self.assertNotIn("hosts", state.result())
        self.assertNotIn("hosts_writable", state.result())
        state.values["private_hosts"] = "1"
        state.values["hosts"] = "10.0.50.105   a.example b.example\n\n255.255.221.21 sentry.io\n"
        self.assertEqual(state.result()["hosts"], "10.0.50.105 a.example b.example, 255.255.221.21 sentry.io")
        self.assertEqual(state.result()["hosts_writable"], "1")
        self.assertEqual(MODULE["hosts_lines"](state.result()["hosts"]),
                         "10.0.50.105 a.example b.example\n255.255.221.21 sentry.io")
        state.values["hosts"] = "sentry.io 255.255.221.21"
        self.assertIn("address", state.error())
        state.scope = "clear"
        self.assertIsNone(state.error())

    def test_dotnet_only_for_native_programs_needing_it(self):
        state = Preferences({"engine": "native", "dotnet": True, "values": {"dotnet": "1"}})
        self.assertEqual(state.result()["dotnet"], "1")
        state.set_runtime("proton")                  # the .exe under Proton instead
        self.assertNotIn("dotnet", state.result())
        plain = Preferences({"engine": "native", "values": {"dotnet": "1"}})
        self.assertNotIn("dotnet", plain.result())

    def test_native_proton_only_for_native_programs_beside_windows_ones(self):
        state = Preferences({"engine": "native", "can_proton": True, "values": {"with_proton": "GE-Test"}})
        self.assertEqual(state.result()["with_proton"], "GE-Test")
        state.set_runtime("proton")
        self.assertNotIn("with_proton", state.result())
        plain = Preferences({"engine": "native", "values": {"with_proton": "auto"}})
        self.assertNotIn("with_proton", plain.result())

    def test_dialog_and_launcher_accept_the_same_lan_lists(self):
        samples = ["10.0.50.105:443", "10.0.50.105", "192.168.1.0/24, 10.0.0.1:80/tcp",
                   "[fd00::1]:443", "fd00::/64", "10.0.0.1:8000-8100/udp", "10.0.0.1/udp",
                   "127.0.0.1", "0.0.0.0/0", "::/0", "10.0.0.1:0", "10.0.0.1:70000",
                   "10.0.0.1:90-80", "nas.local", "10.0.0.1:443/sctp", "[10.0.0.1]:80", "224.0.0.1"]
        for sample in samples:
            with self.subTest(sample=sample):
                launcher = subprocess.run([str(ROOT / "sandbox-game"), "--net", "--allow-lan", sample,
                                           "--print-name", "/"], capture_output=True, text=True)
                self.assertEqual(MODULE["lan_error"](sample) is None, launcher.returncode == 0,
                                 launcher.stderr)

    def test_dialog_and_launcher_accept_the_same_hosts_entries(self):
        samples = ["10.0.0.1 a.example", "10.0.0.1 a.example b_c.example, ::1 local", "10.0.0.1",
                   "a.example 10.0.0.1", "10.0.0.1 -a", "10.0.0.1 a..b", "10.0.0.1 a/b"]
        for sample in samples:
            with self.subTest(sample=sample):
                launcher = subprocess.run([str(ROOT / "sandbox-game"), "--add-host", sample,
                                           "--print-name", "/"], capture_output=True, text=True)
                self.assertEqual(MODULE["hosts_error"](sample) is None, launcher.returncode == 0,
                                 launcher.stderr)


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

    def test_split_display_shows_optional_executable_inside_preferences(self):
        dialog = self.create("preferences", {"engine": "proton"})
        index = [key for key, _ in dialog.choices["display"]].index("wayland-x11")
        dialog.widgets["display"].set_selected(index)
        self.assertTrue(dialog.rows["x11_exe"].get_visible())
        self.assertTrue(dialog.split_note.get_visible())
        # gamescope stays windowed in split display; its resolution still applies.
        self.assertTrue(dialog.rows["resolution"].get_visible())
        self.assertFalse(dialog.rows["fullscreen"].get_visible())
        dialog.widgets["x11_exe"].set_text("Launcher.exe\t")
        dialog.save_preferences()
        self.assertEqual(self.responses, [])
        self.assertIn("X11 executable", dialog.error_note.get_label())
        dialog.widgets["x11_exe"].set_text("Launcher.exe")
        dialog.save_preferences()
        saved = self.responses[0][1]
        self.assertEqual(saved["wayland_x11"], "1")
        self.assertEqual(saved["x11_exe"], "Launcher.exe")

    def test_native_proton_choice_starts_at_none(self):
        dialog = self.create("preferences", {"engine": "native", "can_proton": True, "protons": ["GE-Test"]})
        self.assertTrue(dialog.rows["with_proton"].get_visible())
        self.assertEqual(dialog.choices["with_proton"][:3],
                         [("", "None"), ("auto", "Newest installed (auto)"), ("GE-Test", "GE-Test")])
        dialog.save_preferences()
        self.assertEqual(self.responses[0][1]["with_proton"], "")
        dialog.widgets["with_proton"].set_selected(2)
        dialog.save_preferences()
        self.assertEqual(self.responses[1][1]["with_proton"], "GE-Test")
        self.assertFalse(self.create("preferences", {"engine": "nwjs", "can_proton": True})
                         .rows["with_proton"].get_visible())

    def test_lan_controls_appear_with_the_internet_and_bad_entries_block_saving(self):
        dialog = self.create("preferences", {"engine": "native"})
        self.assertFalse(dialog.rows["lan"].get_visible())
        self.assertFalse(dialog.rows["lan_allow"].get_visible())
        dialog.widgets["net"].set_active(True)
        self.assertTrue(dialog.rows["lan"].get_visible())
        self.assertTrue(dialog.rows["lan_allow"].get_visible())
        dialog.widgets["lan"].set_active(True)
        self.assertFalse(dialog.rows["lan_allow"].get_visible())
        dialog.widgets["lan"].set_active(False)
        dialog.widgets["lan_allow"].set_text("10.0.50.105:443, nas.local")
        dialog.save_preferences()
        self.assertEqual(self.responses, [])
        self.assertIn("nas.local", dialog.error_note.get_label())
        dialog.widgets["lan_allow"].set_text("10.0.50.105:443")
        dialog.save_preferences()
        saved = self.responses[0][1]
        self.assertEqual((saved["net"], saved["lan"], saved["lan_allow"]), ("1", "0", "10.0.50.105:443"))

    def test_hosts_entries_appear_with_their_switch_and_bad_entries_block_saving(self):
        dialog = self.create("preferences", {"engine": "native"})
        self.assertFalse(dialog.rows["hosts"].get_visible())
        self.assertFalse(dialog.rows["hosts_writable"].get_visible())
        dialog.widgets["private_hosts"].set_active(True)
        self.assertTrue(dialog.rows["hosts"].get_visible())
        self.assertTrue(dialog.rows["hosts_writable"].get_visible())
        dialog.widgets["hosts"].get_buffer().set_text("10.0.50.105 a.example\nsentry.io")
        dialog.save_preferences()
        self.assertEqual(self.responses, [])
        self.assertIn("sentry.io", dialog.error_note.get_label())
        dialog.widgets["hosts"].get_buffer().set_text("10.0.50.105 a.example\n255.255.221.21 sentry.io")
        dialog.widgets["hosts_writable"].set_active(True)
        dialog.save_preferences()
        saved = self.responses[0][1]
        self.assertEqual((saved["private_hosts"], saved["hosts"], saved["hosts_writable"]),
                         ("1", "10.0.50.105 a.example, 255.255.221.21 sentry.io", "1"))

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


class NetworkCardPreferenceTests(unittest.TestCase):
    def test_card_address_kind_is_offered_and_saved_only_with_the_internet(self):
        state = Preferences({"engine": "proton", "values": {"net": "0", "mac_vendor": "1"}})
        self.assertNotIn("mac_vendor", state.result())
        state.values["net"] = "1"
        self.assertEqual(state.result()["mac_vendor"], "1")

