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
    def test_create_select_program_save_settings_and_confirm_delete(self):
        try:
            import gi
            gi.require_version("Gtk", "4.0")
            gi.require_version("Adw", "1")
        except (ImportError, ValueError):
            self.skipTest("GTK 4 and libadwaita are not installed")
        script = r'''
import os, runpy, subprocess, sys, traceback
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
            scope.set_selected(0)
            preferences.widgets["net"].set_active(True)
            buffer.set_text("WINE_GRAPHICS_DRIVER=x11")
            preferences.save()
            assert manager.library.settings(entry["name"])["net"] == "1"
            assert manager.library.settings(entry["name"])["env"] == "WINE_GRAPHICS_DRIVER=x11"
            assert manager.library.scope_settings(entry["name"], True)["env"] == "DXVK_HUD=1"
            prefix = manager.library.capture(entry["name"]) / "compat/pfx/drive_c/Example"
            prefix.mkdir(parents=True)
            (prefix / "play.exe").write_text("game")
            manager.scan_programs(entry, rescan=True)
        elif stage == 2:
            choices = [w for w in children(manager.program_list) if isinstance(w, Gtk.Button)
                       and w.get_label() == "Use for Play"]
            if not choices:
                return True
            choices[0].emit("clicked")
            assert manager.selected["program"] == "/compat/pfx/drive_c/Example/play.exe"
            assert manager.play.get_sensitive()
            def start(entry, **kwargs):
                calls.append((entry["name"], kwargs))
                return subprocess.Popen(["/bin/true"])
            manager.library.start = start
            manager.play.emit("clicked")
        elif stage == 3:
            if not calls:
                return True
            assert len(calls) == 1
            opened = []
            manager.open_path = opened.append
            drive = manager.library.capture(manager.selected["name"]) / "compat/pfx/drive_c"
            manager.locate(manager.selected)
            assert opened == [drive], opened
            drive.rename(drive.with_name("moved"))
            drive.symlink_to("moved")
            manager.locate(manager.selected)
            assert opened == [drive], opened
            drive.unlink()
            drive.with_name("moved").rename(drive)
            manager.confirm_operation(manager.selected, "delete")
            dialog = manager.window.get_visible_dialog()
            assert isinstance(dialog, Adw.AlertDialog)
            button(dialog, "Cancel").emit("clicked")
            assert manager.library.capture(manager.selected["name"]).is_dir()
            manager.tabs.set_visible_child_name("logs")
            manager.library.log_path(manager.selected["name"]).write_bytes(b"windows \xff log")
            manager.update_log()
            buffer = manager.log_view.get_buffer()
            assert "\ufffd" in buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False)
            manager.search.set_text("no matching game")
            manager.listbox.invalidate_filter()
            assert not manager.rows[manager.selected["name"]].get_child_visible()
            manager.search.set_text("")
            manager.listbox.invalidate_filter()
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
            defaults.write_text("env=DXVK_HUD=1\n")
            result = subprocess.run([sys.executable, "-c", script, str(ROOT / "sandbox-manager")],
                                    env=env, capture_output=True, text=True, timeout=35)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("GUI lifecycle passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
