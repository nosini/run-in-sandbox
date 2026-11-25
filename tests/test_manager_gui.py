"""Exercise the desktop manager's real GTK controls with an isolated library."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"), "needs a display")
class ManagerGuiTests(unittest.TestCase):
    def test_defaults_window_without_selection_reads_saves_and_cancels(self):
        try:
            import gi
            gi.require_version("Gtk", "4.0")
            gi.require_version("Adw", "1")
        except (ImportError, ValueError):
            self.skipTest("GTK 4 and libadwaita are not installed")
        script = r'''
import os, runpy, sys, traceback
from pathlib import Path
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gio, GLib, Gtk
module = runpy.run_path(sys.argv[1])
config = Path.home() / ".config/sandbox-game"
defaults = config / "defaults"
own = config / "games/unselected"
before = defaults.read_bytes()
game_before = own.read_bytes()
stage = 0
failure = []

def children(widget):
    yield widget
    child = widget.get_first_child()
    while child:
        yield from children(child)
        child = child.get_next_sibling()

def tick():
    global stage
    app = Gio.Application.get_default()
    if not app or not hasattr(app, "manager"):
        return True
    manager = app.manager
    try:
        assert manager.selected is None
        if stage == 0:
            app.activate_action("defaults", None)
            assert manager.defaults_window
        elif stage in (1, 2, 3):
            pane = manager.defaults_preferences
            if pane is None:
                return True
            window = manager.defaults_window
            assert pane.state.scope == "all"
            assert "scope" not in pane.widgets
            if stage == 1:
                assert pane.selected("separate_uid") == "systemd"
                assert pane.selected("seccomp_policy") == "allowlist"
                assert pane.selected("webgl") == "vulkan"
                for key in ("proton", "casefold", "webgl", "dotnet", "with_proton"):
                    assert pane.rows[key].get_visible(), key
                app.activate_action("defaults", None)
                assert manager.defaults_window is window
                pane.widgets["net"].set_active(True)
                pane.widgets["separate_uid"].set_selected(1)
                pane.env.get_buffer().set_text("CANCELLED=1")
                pane.widgets["appearance"].set_selected(2)
                window.close()
                assert defaults.read_bytes() == before
                assert own.read_bytes() == game_before
                assert not (config / "interface").exists()
                assert manager.appearance.saved_theme == "system"
                app.activate_action("defaults", None)
            elif stage == 2:
                assert not pane.widgets["net"].get_active()
                assert pane.selected("separate_uid") == "systemd"
                assert pane.selected("appearance") == "system"
                buffer = pane.env.get_buffer()
                assert buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False) == "DEFAULT=1"
                pane.widgets["net"].set_active(True)
                pane.widgets["separate_uid"].set_selected(2)
                pane.widgets["seccomp_policy"].set_selected(1)
                buffer.set_text("env=BAD=1")
                pane.save()
                assert pane.error_note.get_visible()
                assert defaults.read_bytes() == before
                buffer.set_text("DEFAULT=2\nSECOND=3")
                next(w for w in children(window) if isinstance(w, Gtk.Button)
                     and w.get_label() == "Save defaults").emit("clicked")
                assert not pane.error_note.get_visible(), pane.error_note.get_label()
                values = manager.library.scope_settings(None, defaults=True)
                assert values["net"] == "1"
                assert values["separate_uid"] == "1"
                assert values["seccomp_policy"] == "denylist"
                assert values["env"] == "DEFAULT=2 SECOND=3"
                assert values["webgl"] == "vulkan"
                assert values["gamescope_args"] == "-r 60"
                assert values["future_setting"] == "keep"
                assert own.read_bytes() == game_before
                assert not manager.library.root.exists()
                window.close()
                app.activate_action("defaults", None)
            else:
                assert pane.widgets["net"].get_active()
                assert pane.selected("separate_uid") == "1"
                assert pane.selected("seccomp_policy") == "denylist"
                window.close()
                manager.window.close()
                print("Defaults window passed", flush=True)
                return False
        stage += 1
        return True
    except BaseException:
        failure.append(traceback.format_exc())
        app.quit()
        return False

def expired():
    failure.append("Timed out at defaults stage " + str(stage))
    app = Gio.Application.get_default()
    if app:
        app.quit()
    return False
GLib.timeout_add(100, tick)
GLib.timeout_add_seconds(15, expired)
code = module["main"]()
if failure:
    print("\n".join(failure), file=sys.stderr)
    sys.exit(1)
sys.exit(code)
'''
        with tempfile.TemporaryDirectory(prefix="manager-defaults-gui-") as temporary:
            env = {**os.environ, "HOME": temporary, "XDG_CONFIG_HOME": str(Path(temporary) / ".config"),
                   "XDG_DATA_HOME": str(Path(temporary) / ".local/share")}
            env.pop("PROTON_DIR", None)
            config = Path(temporary) / ".config/sandbox-game"
            (config / "games").mkdir(parents=True)
            (config / "defaults").write_text("net=0\nseparate_uid=systemd\nseccomp_policy=allowlist\n"
                "seccomp=enforce\ncasefold=0\nwebgl=vulkan\nenv=DEFAULT=1\n"
                "gamescope_args=-r 60\nfuture_setting=keep\n")
            (config / "games/unselected").write_text("net=1\nseparate_uid=0\nenv=GAME=1\n")
            result = subprocess.run([sys.executable, "-c", script, str(ROOT / "sandbox-manager")],
                                    env=env, capture_output=True, text=True, timeout=25)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Defaults window passed", result.stdout)

    def test_saving_defaults_refreshes_an_open_game_pane(self):
        try:
            import gi
            gi.require_version("Gtk", "4.0")
            gi.require_version("Adw", "1")
        except (ImportError, ValueError):
            self.skipTest("GTK 4 and libadwaita are not installed")
        script = r'''
import runpy, sys, traceback
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gio, GLib
module = runpy.run_path(sys.argv[1])
stage = 0
failure = []

def tick():
    global stage
    app = Gio.Application.get_default()
    if not app or not hasattr(app, "manager"):
        return True
    manager = app.manager
    try:
        if stage == 0:
            entry = manager.library.create("Defaults refresh")
            (manager.library.config / "games" / entry["name"]).unlink()
            manager.reload(entry["name"])
        elif stage == 1:
            if not manager.selected or not hasattr(manager, "preferences"):
                return True
            pane = manager.preferences
            assert pane.state.scope == "game"
            assert pane.state.display == "wayland", pane.state.display
            pane.widgets["net"].set_active(True)
            app.activate_action("defaults", None)
        elif stage == 2:
            defaults = manager.defaults_preferences
            if defaults is None:
                return True
            keys = [value for value, _ in defaults.choices["display"]]
            defaults.widgets["display"].set_selected(keys.index("x11"))
            defaults.widgets["appearance"].set_selected(2)
            defaults.save()
        elif stage == 3:
            pane = manager.preferences
            assert pane.state.display == "x11", pane.state.display
            assert pane.selected("appearance") == "dark", pane.selected("appearance")
            assert pane.widgets["net"].get_active(), "unsaved game edit was clobbered"
            manager.defaults_window.close()
            manager.window.close()
            print("Defaults refresh passed", flush=True)
            return False
        stage += 1
        return True
    except BaseException:
        failure.append(traceback.format_exc())
        app.quit()
        return False

def expired():
    failure.append("Timed out at defaults refresh stage " + str(stage))
    app = Gio.Application.get_default()
    if app:
        app.quit()
    return False
GLib.timeout_add(100, tick)
GLib.timeout_add_seconds(15, expired)
code = module["main"]()
if failure:
    print("\n".join(failure), file=sys.stderr)
    sys.exit(1)
sys.exit(code)
'''
        with tempfile.TemporaryDirectory(prefix="manager-defaults-refresh-") as temporary:
            env = {**os.environ, "HOME": temporary, "XDG_CONFIG_HOME": str(Path(temporary) / ".config"),
                   "XDG_DATA_HOME": str(Path(temporary) / ".local/share")}
            env.pop("PROTON_DIR", None)
            config = Path(temporary) / ".config/sandbox-game"
            config.mkdir(parents=True)
            (config / "defaults").write_text("wayland=1\nhost_x11=0\n")
            result = subprocess.run([sys.executable, "-c", script, str(ROOT / "sandbox-manager")],
                                    env=env, capture_output=True, text=True, timeout=25)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Defaults refresh passed", result.stdout)

    def test_saving_defaults_refreshes_a_game_pane_showing_the_defaults_scope(self):
        try:
            import gi
            gi.require_version("Gtk", "4.0")
            gi.require_version("Adw", "1")
        except (ImportError, ValueError):
            self.skipTest("GTK 4 and libadwaita are not installed")
        script = r'''
import runpy, sys, traceback
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gio, GLib
module = runpy.run_path(sys.argv[1])
stage = 0
failure = []

def tick():
    global stage
    app = Gio.Application.get_default()
    if not app or not hasattr(app, "manager"):
        return True
    manager = app.manager
    try:
        if stage == 0:
            entry = manager.library.create("Defaults all scope")
            (manager.library.config / "games" / entry["name"]).unlink()
            manager.reload(entry["name"])
        elif stage == 1:
            if not manager.selected or not hasattr(manager, "preferences"):
                return True
            pane = manager.preferences
            assert pane.state.scope == "game"
            assert pane.state.display == "wayland", pane.state.display
            # Save for: All games (defaults), so the pane shows that file.
            pane.widgets["scope"].set_selected(1)
            assert pane.state.scope == "all"
            app.activate_action("defaults", None)
        elif stage == 2:
            defaults = manager.defaults_preferences
            if defaults is None:
                return True
            keys = [value for value, _ in defaults.choices["display"]]
            defaults.widgets["display"].set_selected(keys.index("x11"))
            defaults.env.get_buffer().set_text("DEFAULT=2")
            defaults.widgets["appearance"].set_selected(2)
            defaults.save()
        else:
            pane = manager.preferences
            assert pane.state.scope == "all", pane.state.scope
            assert pane.state.display == "x11", pane.state.display
            assert pane.selected("appearance") == "dark", pane.selected("appearance")
            buffer = pane.env.get_buffer()
            text = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False)
            assert text == "DEFAULT=2", text
            assert not pane.error_note.get_visible(), pane.error_note.get_label()
            manager.defaults_window.close()
            manager.window.close()
            print("Defaults all-scope refresh passed", flush=True)
            return False
        stage += 1
        return True
    except BaseException:
        failure.append(traceback.format_exc())
        app.quit()
        return False

def expired():
    failure.append("Timed out at defaults all-scope stage " + str(stage))
    app = Gio.Application.get_default()
    if app:
        app.quit()
    return False
GLib.timeout_add(100, tick)
GLib.timeout_add_seconds(15, expired)
code = module["main"]()
if failure:
    print("\n".join(failure), file=sys.stderr)
    sys.exit(1)
sys.exit(code)
'''
        with tempfile.TemporaryDirectory(prefix="manager-defaults-all-scope-") as temporary:
            env = {**os.environ, "HOME": temporary, "XDG_CONFIG_HOME": str(Path(temporary) / ".config"),
                   "XDG_DATA_HOME": str(Path(temporary) / ".local/share")}
            env.pop("PROTON_DIR", None)
            config = Path(temporary) / ".config/sandbox-game"
            config.mkdir(parents=True)
            (config / "defaults").write_text("wayland=1\nhost_x11=0\n")
            result = subprocess.run([sys.executable, "-c", script, str(ROOT / "sandbox-manager")],
                                    env=env, capture_output=True, text=True, timeout=25)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Defaults all-scope refresh passed", result.stdout)

    def test_clearing_a_game_does_not_resave_its_environment(self):
        try:
            import gi
            gi.require_version("Gtk", "4.0")
            gi.require_version("Adw", "1")
        except (ImportError, ValueError):
            self.skipTest("GTK 4 and libadwaita are not installed")
        script = r'''
import runpy, sys, traceback
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gio, GLib
module = runpy.run_path(sys.argv[1])
stage = 0
failure = []

def tick():
    global stage
    app = Gio.Application.get_default()
    if not app or not hasattr(app, "manager"):
        return True
    manager = app.manager
    try:
        if stage == 0:
            entry = manager.library.create("Env clear")
            name = entry["name"]
            manager.library.update_settings(name, {"env": "GAME=1"})
            manager.library.update_settings(name, {"env": "DEFAULT=1"}, defaults=True)
            manager.reload(name)
        else:
            if not manager.selected or not hasattr(manager, "preferences"):
                return True
            pane = manager.preferences
            name = manager.selected["name"]
            buffer = pane.env.get_buffer()
            text = lambda: buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False)
            assert text() == "GAME=1", text()
            pane.widgets["scope"].set_selected(2)  # Clear this game's settings
            pane.save()
            own = manager.library.scope_settings(name)
            assert "env" not in own, own
            pane.widgets["scope"].set_selected(0)  # This game only
            # The cleared list is gone, not waiting to be saved back.
            assert text() == "", text()
            pane.save()
            own = manager.library.scope_settings(name)
            assert "env" not in own, own
            assert manager.library.settings(name)["env"] == "DEFAULT=1"
            manager.window.close()
            print("Env clear passed", flush=True)
            return False
        stage += 1
        return True
    except BaseException:
        failure.append(traceback.format_exc())
        app.quit()
        return False

def expired():
    failure.append("Timed out at env clear stage " + str(stage))
    app = Gio.Application.get_default()
    if app:
        app.quit()
    return False
GLib.timeout_add(100, tick)
GLib.timeout_add_seconds(15, expired)
code = module["main"]()
if failure:
    print("\n".join(failure), file=sys.stderr)
    sys.exit(1)
sys.exit(code)
'''
        with tempfile.TemporaryDirectory(prefix="manager-env-clear-") as temporary:
            env = {**os.environ, "HOME": temporary, "XDG_CONFIG_HOME": str(Path(temporary) / ".config"),
                   "XDG_DATA_HOME": str(Path(temporary) / ".local/share")}
            env.pop("PROTON_DIR", None)
            result = subprocess.run([sys.executable, "-c", script, str(ROOT / "sandbox-manager")],
                                    env=env, capture_output=True, text=True, timeout=25)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Env clear passed", result.stdout)

    def test_saving_game_details_never_freezes_the_window(self):
        try:
            import gi
            gi.require_version("Gtk", "4.0")
            gi.require_version("Adw", "1")
        except (ImportError, ValueError):
            self.skipTest("GTK 4 and libadwaita are not installed")
        script = r'''
import runpy, sys, threading, time, traceback
from pathlib import Path
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gio, GLib, Gtk
module = runpy.run_path(sys.argv[1])
stage = 0
failure = []

def children(widget):
    yield widget
    child = widget.get_first_child()
    while child:
        yield from children(child)
        child = child.get_next_sibling()

def button(widget, label):
    return next(w for w in children(widget) if isinstance(w, Gtk.Button) and w.get_label() == label)

def tick():
    global stage
    app = Gio.Application.get_default()
    if not app or not hasattr(app, "manager"):
        return True
    manager = app.manager
    try:
        if stage == 0:
            entry = manager.library.create("Slow save")
            manager.reload(entry["name"])
        elif stage == 1:
            if not manager.selected:
                return True
            display = next(w for w in children(manager.overview) if isinstance(w, Gtk.Entry) and
                            w.get_placeholder_text() == "Display name")
            display.set_text("Renamed while busy")
            # A refresh holds the library's lock: saving the details must
            # not freeze the window while the save waits for it.
            original = manager.library.update_entry
            release = threading.Event()
            def slow(name, **changes):
                if changes.get("title_custom"):
                    release.wait(10)
                return original(name, **changes)
            manager.library.update_entry = slow
            manager.slow_release = release
            manager.frozen_at = time.monotonic()
            button(manager.overview, "Save game details").emit("clicked")
        elif stage == 2:
            release = manager.slow_release
            if release is None:
                return True
            assert time.monotonic() - manager.frozen_at < 5, "the window froze while saving"
            assert manager.library.entry(manager.selected["name"])["title"] == "Slow save"
            release.set()
        else:
            if manager.library.entry(manager.selected["name"])["title"] != "Renamed while busy":
                return True
            manager.window.close()
            print("Slow save passed", flush=True)
            return False
        stage += 1
        return True
    except BaseException:
        failure.append(traceback.format_exc())
        app.quit()
        return False

def expired():
    failure.append("Timed out at slow save stage " + str(stage))
    app = Gio.Application.get_default()
    if app:
        app.quit()
    return False
GLib.timeout_add(100, tick)
GLib.timeout_add_seconds(15, expired)
code = module["main"]()
if failure:
    print("\n".join(failure), file=sys.stderr)
    sys.exit(1)
sys.exit(code)
'''
        with tempfile.TemporaryDirectory(prefix="manager-slow-save-") as temporary:
            env = {**os.environ, "HOME": temporary, "XDG_CONFIG_HOME": str(Path(temporary) / ".config"),
                   "XDG_DATA_HOME": str(Path(temporary) / ".local/share")}
            env.pop("PROTON_DIR", None)
            result = subprocess.run([sys.executable, "-c", script, str(ROOT / "sandbox-manager")],
                                    env=env, capture_output=True, text=True, timeout=25)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Slow save passed", result.stdout)

    def test_settings_loading_never_reads_the_description_cache_off_thread(self):
        try:
            import gi
            gi.require_version("Gtk", "4.0")
            gi.require_version("Adw", "1")
        except (ImportError, ValueError):
            self.skipTest("GTK 4 and libadwaita are not installed")
        script = r'''
import runpy, sys, threading, traceback
from pathlib import Path
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gio, GLib, Gtk
module = runpy.run_path(sys.argv[1])
stage = 0
failure = []

class Guarded(dict):
    """Fails when anything but the main thread reads the description cache."""
    def _check(self):
        assert threading.current_thread() is threading.main_thread(), \
            "the settings worker read the description cache"
    def __contains__(self, key):
        self._check()
        return dict.__contains__(self, key)
    def __getitem__(self, key):
        self._check()
        return dict.__getitem__(self, key)
    def get(self, key, default=None):
        self._check()
        return dict.get(self, key, default)

def tick():
    global stage
    app = Gio.Application.get_default()
    if not app or not hasattr(app, "manager"):
        return True
    manager = app.manager
    try:
        if stage == 0:
            game = Path.home() / "Games/Native Game"
            game.mkdir(parents=True)
            (game / "play.sh").write_text("#!/bin/sh\n")
            entry = manager.library.add_existing(game)
            manager.reload(entry["name"])
        elif stage == 1:
            if not manager.selected or not hasattr(manager, "preferences"):
                return True
            # reload() rebinds this cache; a worker reading it raced a
            # KeyError into a toast over a discarded answer.
            manager.descriptions = Guarded(manager.descriptions)
            manager.build_settings(manager.selected)
        else:
            child = manager.settings_page.get_first_child()
            if isinstance(child, Gtk.Label):
                assert "Loading settings" in child.get_label(), child.get_label()
                return True
            assert child is manager.preferences.body, child
            manager.window.close()
            print("Settings cache passed", flush=True)
            return False
        stage += 1
        return True
    except BaseException:
        failure.append(traceback.format_exc())
        app.quit()
        return False

def expired():
    failure.append("Timed out at settings cache stage " + str(stage))
    app = Gio.Application.get_default()
    if app:
        app.quit()
    return False
GLib.timeout_add(100, tick)
GLib.timeout_add_seconds(15, expired)
code = module["main"]()
if failure:
    print("\n".join(failure), file=sys.stderr)
    sys.exit(1)
sys.exit(code)
'''
        with tempfile.TemporaryDirectory(prefix="manager-settings-cache-") as temporary:
            env = {**os.environ, "HOME": temporary, "XDG_CONFIG_HOME": str(Path(temporary) / ".config"),
                   "XDG_DATA_HOME": str(Path(temporary) / ".local/share")}
            env.pop("PROTON_DIR", None)
            result = subprocess.run([sys.executable, "-c", script, str(ROOT / "sandbox-manager")],
                                    env=env, capture_output=True, text=True, timeout=25)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Settings cache passed", result.stdout)

    def test_create_select_program_save_settings_and_confirm_delete(self):
        try:
            import gi
            gi.require_version("Gtk", "4.0")
            gi.require_version("Adw", "1")
        except (ImportError, ValueError):
            self.skipTest("GTK 4 and libadwaita are not installed")
        script = r'''
import json, os, runpy, subprocess, sys, threading, time, traceback
from pathlib import Path
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk
module = runpy.run_path(sys.argv[1])
steps = [0]
failure = []
calls = []
proton_scans = []
icon_calls = []
active_icons = [0]
shortcuts = []
search_release = threading.Event()

def children(widget):
    yield widget
    child = widget.get_first_child()
    while child:
        yield from children(child)
        child = child.get_next_sibling()

def button(widget, label):
    return next(w for w in children(widget) if isinstance(w, Gtk.Button) and w.get_label() == label)

def tick():
    app = Gio.Application.get_default()
    if not app or not hasattr(app, "manager"):
        return True
    manager = app.manager
    try:
        stage = steps[0]
        if stage == 0:
            assert manager.content.get_visible_child_name() == "empty"
            protons = manager.library.protons
            manager.library.protons = lambda: proton_scans.append(1) or protons()
            icon = manager.library.icon
            def counted_icon(entry):
                active_icons[0] += 1
                icon_calls.append((entry["name"], active_icons[0]))
                try:
                    return icon(entry)
                finally:
                    active_icons[0] -= 1
            manager.library.icon = counted_icon
            manager.add_game()
            dialog = next(w for w in Gtk.Window.get_toplevels() if w.get_title() == "Add game")
            name = next(w for w in children(dialog) if isinstance(w, Gtk.Entry) and
                        (w.get_placeholder_text() or "").startswith("Game name"))
            name.set_text("GUI Test Game")
            button(dialog, "Add game").emit("clicked")
        elif stage == 1:
            if not manager.selected or not hasattr(manager, "preferences"):
                return True
            entry = manager.selected
            assert entry["title"] == "GUI Test Game"
            assert manager.content.get_visible_child_name() == "detail"
            manager.location_filter.set_selected(2)
            manager.listbox.invalidate_filter()
            assert not manager.rows[entry["name"]].get_child_visible()
            manager.location_filter.set_selected(1)
            manager.listbox.invalidate_filter()
            assert manager.rows[entry["name"]].get_child_visible()
            manager.location_filter.set_selected(0)
            # What runs the game, under its title and found by the search.
            row = manager.rows[entry["name"]]
            assert row.state.get_label() == "Choose a launcher · Windows program · Proton", row.state.get_label()
            manager.search.set_text("proton")
            manager.listbox.invalidate_filter()
            assert row.get_child_visible()
            manager.search.set_text("mkxp")
            manager.listbox.invalidate_filter()
            assert not row.get_child_visible()
            manager.search.set_text("")
            manager.listbox.invalidate_filter()
            assert not manager.play.get_sensitive()
            assert len(proton_scans) == 1, proton_scans
            preferences = manager.preferences
            buffer = preferences.env.get_buffer()
            text = lambda: buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False)
            # Each scope edits its own file's variables, not the merged view.
            assert text() == ""
            scope = preferences.widgets["scope"]
            scope.set_selected(1)
            assert text() == "DXVK_HUD=1"
            assert preferences.selected("separate_uid") == "systemd"
            assert preferences.selected("seccomp_policy") == "allowlist"
            scope.set_selected(0)
            assert preferences.selected("separate_uid") == ""
            preferences.widgets["separate_uid"].set_selected(1)
            preferences.widgets["seccomp_policy"].set_selected(1)
            preferences.widgets["seccomp"].set_selected(1)
            preferences.widgets["net"].set_active(True)
            # A pasted line of several variables is several; the file's own
            # env= in front is not a variable called env.
            buffer.set_text("env=WINE_GRAPHICS_DRIVER=x11")
            preferences.save()
            assert "env=" in preferences.error_note.get_label()
            assert "WINE_GRAPHICS_DRIVER" not in manager.library.settings(entry["name"])["env"]
            buffer.set_text("WINE_GRAPHICS_DRIVER=x11 WINEDLLOVERRIDES=lsteamclient=d\n")
            preferences.save()
            assert manager.library.settings(entry["name"])["env"] == \
                "WINE_GRAPHICS_DRIVER=x11 WINEDLLOVERRIDES=lsteamclient=d"
            buffer.set_text("WINE_GRAPHICS_DRIVER=x11")
            preferences.save()
            assert manager.library.settings(entry["name"])["net"] == "1"
            assert manager.library.settings(entry["name"])["env"] == "WINE_GRAPHICS_DRIVER=x11"
            assert manager.library.scope_settings(entry["name"], True)["env"] == "DXVK_HUD=1"
            assert manager.library.scope_settings(entry["name"])["separate_uid"] == "0"
            assert manager.library.scope_settings(entry["name"])["seccomp_policy"] == "denylist"
            assert manager.library.scope_settings(entry["name"])["seccomp"] == "enforce"
            assert manager.library.scope_settings(entry["name"], True)["separate_uid"] == "systemd"
            prefix = manager.library.capture(entry["name"]) / "compat/pfx/drive_c/Example"
            prefix.mkdir(parents=True)
            (prefix / "play.exe").write_text("game")
            manager.scan_programs(entry, rescan=True)
        elif stage == 2:
            entry = manager.selected
            choices = [w for w in children(manager.program_list) if isinstance(w, Gtk.Button)
                       and w.get_label() == "Use for Play"]
            if not choices:
                return True
            # A fresh save elsewhere must not be overwritten by this stale snapshot.
            manager.library.update_entry(entry["name"], arguments="--kept")
            # A slow refresh holds the library's lock: choosing a program
            # must leave the window responsive while the save waits for it.
            original = manager.library.update_entry
            release = threading.Event()
            def slow(name, **changes):
                if changes.get("program"):
                    release.wait(10)
                return original(name, **changes)
            manager.library.update_entry = slow
            manager.slow_release = release
            manager.frozen_at = time.monotonic()
            choices[0].emit("clicked")
        elif stage == 3:
            release = manager.slow_release
            if release is None:
                return True
            # The main loop kept running while the choice waits for the lock.
            assert time.monotonic() - manager.frozen_at < 5, "the window froze while choosing"
            assert manager.selected["program"] == "", manager.selected["program"]
            release.set()
        elif stage == 4:
            entry = manager.selected
            if entry["program"] != "/compat/pfx/drive_c/Example/play.exe":
                return True
            assert manager.library.entry(entry["name"])["arguments"] == "--kept"
            # Icons are extracted one at a time, and selecting a game asks for none.
            assert icon_calls and max(depth for _, depth in icon_calls) == 1, icon_calls
            name = entry["name"]
            import struct, zlib
            def chunk(kind, data):
                return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
            png = Path.home() / "icon.png"
            png.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
                            + chunk(b"IDAT", zlib.compress(b"\0\xff\0\0\xff")) + chunk(b"IEND", b""))
            manager.icon_loaded(name, png)
            assert manager.rows[name].icon.get_storage_type() != Gtk.ImageType.ICON_NAME
            # A program without an icon brings the generic one back.
            manager.icon_loaded(name, None)
            for image in (manager.rows[name].icon, manager.game_icon):
                assert image.get_icon_name() == "applications-games-symbolic"
            assert manager.play.get_sensitive()
            def start(entry, **kwargs):
                calls.append((entry["name"], kwargs))
                return subprocess.Popen(["/bin/true"])
            manager.library.start = start
            manager.play.emit("clicked")
        elif stage == 5:
            if not calls:
                return True
            assert len(calls) == 1
            opened = []
            manager.open_path = opened.append
            drive = manager.library.capture(manager.selected["name"]) / "compat/pfx/drive_c"
            locate = button(manager.overview, "Locate game")
            name = manager.selected["name"]
            # A running sandbox's Windows drive is its game's to change.
            manager.running.add(name)
            manager.update_state()
            assert not locate.get_sensitive()
            manager.locate(manager.selected)
            assert opened == [], opened
            manager.running.discard(name)
            manager.processes.pop(name, None)
            manager.update_state()
            # Started elsewhere and not polled yet: its lock says it runs.
            held = manager.library.sandbox_lock(name)
            assert held is not None
            manager.locate(manager.selected)
            os.close(held)
            assert opened == [], opened
            assert locate.get_sensitive()
            manager.locate(manager.selected)
            assert opened == [drive], opened
            drive.rename(drive.with_name("moved"))
            drive.symlink_to("moved")
            manager.locate(manager.selected)
            assert opened == [drive], opened
            drive.unlink()
            drive.with_name("moved").rename(drive)
            shortcut = Path.home() / f".local/share/applications/sandbox-game-{manager.selected['name']}.desktop"
            menu = next(w for w in children(manager.overview) if isinstance(w, Gtk.CheckButton)
                        and w.get_label() == "Show in the applications menu")
            desktop = next(w for w in children(manager.overview) if isinstance(w, Gtk.CheckButton)
                           and w.get_label() == "Place a shortcut on the desktop")
            # No ~/Desktop in this home.
            assert not desktop.get_sensitive()
            menu.set_active(True)
            shortcuts.append((menu, shortcut))
            manager.confirm_operation(manager.selected, "delete")
            dialog = manager.window.get_visible_dialog()
            assert isinstance(dialog, Adw.AlertDialog)
            button(dialog, "Cancel").emit("clicked")
            assert manager.library.capture(manager.selected["name"]).is_dir()
            manager.tabs.set_visible_child_name("logs")
            log_path = manager.library.log_path(manager.selected["name"])
            log_path.write_bytes(b"windows \xff\x00 log")
            manager.update_log()
            buffer = manager.log_view.get_buffer()
            text = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False)
            assert "\ufffd" in text and "\x00" not in text, repr(text)
            log_path.unlink()
            log_path.mkdir()
            manager.update_log()
            text = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False)
            assert "Cannot read the launch log" in text, repr(text)
            manager.search.set_text("no matching game")
            manager.listbox.invalidate_filter()
            assert not manager.rows[manager.selected["name"]].get_child_visible()
            manager.search.set_text("")
            manager.listbox.invalidate_filter()
            root = Path.home() / "External Games"
            for parent in ("Native", "Copies/one", "Copies/two"):
                folder = root / parent / ("Moved Game" if parent == "Native" else "Duplicate Game")
                folder.mkdir(parents=True)
                (folder / "play.sh").write_text("#!/bin/sh\n")
            for sandbox in ("moved-game", "duplicate-game"):
                manager.library.capture(sandbox).mkdir()
            manager.game_folders()
            dialog = next(w for w in Gtk.Window.get_toplevels() if w.get_title() == "Game folders")
            location = next(w for w in children(dialog) if isinstance(w, Gtk.Entry) and
                            w.get_placeholder_text() == "Folder path")
            location.set_text("relative/path")
            button(dialog, "Add").emit("clicked")
            assert not manager.library.game_folders()
            location.set_text(str(root))
            # Saving also adds a path that has been typed but not yet added.
            button(dialog, "Save and search").emit("clicked")
        elif stage == 6:
            # Shown first, then again with what the background search reconnected.
            if len(manager.entries) != 3 or manager.search_pending or manager.search_request \
                    or manager.count.get_label() == "Refreshing library…":
                return True
            menu, shortcut = shortcuts[0]
            assert shortcut.is_file(), shortcut
            info = Gio.DesktopAppInfo.new_from_filename(str(shortcut))
            assert info.get_name() == "GUI Test Game"
            assert info.get_commandline().endswith(" --launch gui-test-game"), info.get_commandline()
            assert manager.library.game_folders() == [Path.home() / "External Games"]
            moved = next(e for e in manager.entries if e["name"] == "moved-game")
            assert moved["directory"] == str(Path.home() / "External Games/Native/Moved Game")
            assert moved["title"] == "Moved Game"
            ambiguous = next(e for e in manager.entries if e["name"] == "duplicate-game")
            assert not ambiguous["directory"]
            manager.locate(ambiguous)
        elif stage == 7:
            dialogs = [w for w in Gtk.Window.get_toplevels() if w.get_title() == "Matching game folders"]
            if not dialogs:
                return True
            chosen = str(Path.home() / "External Games/Copies/two/Duplicate Game")
            button(dialogs[0], chosen).emit("clicked")
        elif stage == 8:
            entry = next(e for e in manager.entries if e["name"] == "duplicate-game")
            if not entry["directory"]:
                return True
            chosen = str(Path.home() / "External Games/Copies/two/Duplicate Game")
            assert entry["directory"] == chosen
            assert entry["title"] == "Duplicate Game"
            saved = json.loads((manager.library.capture(entry["name"]) / "manager.json").read_text())
            assert saved["directory"] == chosen
            # Saved as shown: the name is not pinned, and may follow the folder.
            button(manager.overview, "Save game details").emit("clicked")
            saved = json.loads((manager.library.capture(entry["name"]) / "manager.json").read_text())
            assert "title_custom" not in saved
            display_name = next(w for w in children(manager.overview) if isinstance(w, Gtk.Entry) and
                                w.get_placeholder_text() == "Display name")
            display_name.set_text(entry["name"])
            button(manager.overview, "Save game details").emit("clicked")
        elif stage == 9:
            # The details save happens off the main thread: wait for it.
            saved = json.loads((manager.library.capture("duplicate-game") / "manager.json").read_text())
            entry = next(e for e in manager.entries if e["name"] == "duplicate-game")
            if "title_custom" not in saved or entry["title"] != "duplicate-game":
                return True
            assert saved["title"] == "duplicate-game"
            assert next(e for e in manager.library.entries() if e["name"] == "duplicate-game")["title"] \
                == "duplicate-game"
            # One match is offered, never taken unasked.
            single = Path.home() / "External Games/Native/Single Game"
            single.mkdir()
            (single / "play.sh").write_text("#!/bin/sh\n")
            manager.library.capture("single-game").mkdir()
            manager.locate(manager.library.entry("single-game"))
        elif stage == 10:
            dialogs = [w for w in Gtk.Window.get_toplevels()
                       if w.get_title() == "Matching game folders" and w.get_visible()]
            if not dialogs:
                return True
            single = str(Path.home() / "External Games/Native/Single Game")
            assert button(dialogs[0], single)
            button(dialogs[0], "Cancel").emit("clicked")
            assert manager.library.entry("single-game")["directory"] == ""
            manager.game_folders()
            dialog = next(w for w in Gtk.Window.get_toplevels() if w.get_title() == "Game folders")
            button(dialog, "Remove").emit("clicked")
            button(dialog, "Cancel").emit("clicked")
            assert len(manager.library.game_folders()) == 1
            manager.game_folders()
            dialog = next(w for w in Gtk.Window.get_toplevels() if w.get_title() == "Game folders")
            button(dialog, "Remove").emit("clicked")
            button(dialog, "Save and search").emit("clicked")
        elif stage == 11:
            if manager.library.game_folders():
                return True
            # The library is shown before the game folder search finishes.
            refresh = manager.library.refresh
            def held_refresh():
                search_release.wait(20)
                return refresh()
            manager.library.refresh = held_refresh
            manager.reload(search=True)
        elif stage == 12:
            if manager.count.get_label() == "Refreshing library…":
                return True
            assert "searching game folders" in manager.count.get_label(), manager.count.get_label()
            assert len(manager.rows) == 4 and manager.selected, manager.rows
            search_release.set()
        elif stage == 13:
            if manager.search_request:
                return True
            assert manager.count.get_label() == "4 sandboxes", manager.count.get_label()
            manager.window.close()
            print("GUI lifecycle passed", flush=True)
            return False
        steps[0] += 1
        return True
    except BaseException:
        failure.append(traceback.format_exc())
        app.quit()
        return False

def expired():
    failure.append("Timed out at GUI stage " + str(steps[0]))
    app = Gio.Application.get_default()
    if app:
        app.quit()
    return False
GLib.timeout_add(150, tick)
GLib.timeout_add_seconds(25, expired)
result = module["main"]()
if failure:
    print("\n".join(failure), file=sys.stderr)
    sys.exit(1)
sys.exit(result)
'''
        with tempfile.TemporaryDirectory(prefix="manager-gui-") as temporary:
            env = {**os.environ, "HOME": temporary, "XDG_CONFIG_HOME": str(Path(temporary) / ".config"),
                   "XDG_DATA_HOME": str(Path(temporary) / ".local/share")}
            env.pop("PROTON_DIR", None)
            defaults = Path(temporary) / ".config/sandbox-game/defaults"
            defaults.parent.mkdir(parents=True)
            defaults.write_text("env=DXVK_HUD=1\nseparate_uid=systemd\nseccomp_policy=allowlist\n")
            result = subprocess.run([sys.executable, "-c", script, str(ROOT / "sandbox-manager")],
                                    env=env, capture_output=True, text=True, timeout=35)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("GUI lifecycle passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
