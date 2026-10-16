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
import json, os, runpy, subprocess, sys, traceback
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
            # Icons are extracted one at a time, and selecting a game asks for none.
            assert icon_calls and max(depth for _, depth in icon_calls) == 1, icon_calls
            name = manager.selected["name"]
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
        elif stage == 4:
            if len(manager.entries) != 3:
                return True
            assert manager.library.game_folders() == [Path.home() / "External Games"]
            moved = next(e for e in manager.entries if e["name"] == "moved-game")
            assert moved["directory"] == str(Path.home() / "External Games/Native/Moved Game")
            assert moved["title"] == "Moved Game"
            ambiguous = next(e for e in manager.entries if e["name"] == "duplicate-game")
            assert not ambiguous["directory"]
            manager.locate(ambiguous)
        elif stage == 5:
            dialogs = [w for w in Gtk.Window.get_toplevels() if w.get_title() == "Matching game folders"]
            if not dialogs:
                return True
            chosen = str(Path.home() / "External Games/Copies/two/Duplicate Game")
            button(dialogs[0], chosen).emit("clicked")
        elif stage == 6:
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
            saved = json.loads((manager.library.capture(entry["name"]) / "manager.json").read_text())
            assert saved["title_custom"] is True
            assert saved["title"] == entry["name"]
            assert next(e for e in manager.library.entries() if e["name"] == entry["name"])["title"] == entry["name"]
            # One match is offered, never taken unasked.
            single = Path.home() / "External Games/Native/Single Game"
            single.mkdir()
            (single / "play.sh").write_text("#!/bin/sh\n")
            manager.library.capture("single-game").mkdir()
            manager.locate(manager.library.entry("single-game"))
        elif stage == 7:
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
        elif stage == 8:
            if manager.library.game_folders():
                return True
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
