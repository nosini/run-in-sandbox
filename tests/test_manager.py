"""Manager storage and launch contracts; GTK integration runs on a display."""
import importlib.machinery
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader("manager_core", str(ROOT / "sandbox-manager-lib.py"))
spec = importlib.util.spec_from_loader(loader.name, loader)
core = importlib.util.module_from_spec(spec)
loader.exec_module(core)


class LibraryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.library = core.Library(ROOT / "sandbox-game", ROOT, ROOT / "Sandbox game",
                                    home=self.home, config=self.home / "config")

    def test_new_install_and_game_use_the_same_persistent_prefix(self):
        entry = self.library.create("NIKKE", "/runners/DWProton", internet=True)
        installer = self.home / "downloads" / "setup with spaces.exe"
        installer.parent.mkdir()
        installer.write_text("installer")
        install, env = self.library.command(entry, installer=installer)
        self.assertIsNone(env)
        self.assertIn("--proton=/runners/DWProton", install)
        self.assertIn("--net", install)
        self.assertEqual(install[-2:], [entry["directory"], "/installer/setup with spaces.exe"])
        prefix = self.library.capture(entry["name"]) / "compat/pfx/drive_c/NIKKE"
        prefix.mkdir(parents=True)
        game = prefix / "nikke_launcher.exe"
        game.write_text("game")
        entry["program"] = "/compat/pfx/drive_c/NIKKE/nikke_launcher.exe"
        entry["arguments"] = '--region "some region"'
        play, _ = self.library.command(entry)
        self.assertEqual(play[-3:], [entry["program"], "--region", "some region"])
        self.assertEqual(install[install.index("--name") + 1], play[play.index("--name") + 1])
        self.assertEqual(self.library.programs(entry), [(entry["program"], "C:\\NIKKE\\nikke_launcher.exe")])

    def test_msi_install_has_separate_argv_and_does_not_execute_shell_text(self):
        entry = self.library.create("$(touch bad) game")
        installer = self.home / "a; touch bad.msi"
        installer.touch()
        command, _ = self.library.command(entry, installer=installer)
        self.assertEqual(command[-3:], ["msiexec", "/i", "/installer/a; touch bad.msi"])
        self.assertFalse((self.home / "bad").exists())

    def test_existing_captures_are_discovered_without_fabricating_a_launcher(self):
        capture = self.library.root / "old-game"
        capture.mkdir(parents=True)
        entry, = self.library.entries()
        self.assertEqual(entry["name"], "old-game")
        self.assertEqual(entry["selection"], "")
        core.atomic_write(capture / "source.json", json.dumps({"directory": "/games/old"}))
        self.assertEqual(self.library.entries()[0]["selection"], "/games/old")

    def test_installation_filters_use_location_instead_of_runtime(self):
        internal = self.library.create("Internal game")
        external = {**internal, "name": "external", "title": "External game",
                    "directory": str(self.home / "games"), "kind": "existing"}
        self.assertTrue(self.library.matches(internal, "GAME", "sandbox"))
        self.assertFalse(self.library.matches(internal, "", "external"))
        self.assertTrue(self.library.matches(external, "external", "external"))
        self.assertFalse(self.library.matches(external, "internal", "all"))
        self.assertEqual(self.library.installation({**internal, "kind": "existing"}), "sandbox")
        unknown = {**external, "directory": ""}
        self.assertTrue(self.library.matches(unknown))
        self.assertFalse(self.library.matches(unknown, "", "external"))
        # A location found beforehand is used as it is.
        self.assertTrue(self.library.matches(external, "", "sandbox", "sandbox"))

    def test_icon_discovery_does_not_follow_links_to_host_files(self):
        entry = self.library.create("game")
        original = self.home / "private.ico"
        original.write_bytes(b"private")
        (Path(entry["directory"]) / "icon.ico").symlink_to(original)
        self.assertEqual(self.library.icon_sources(entry), [])

    def native_game(self, path):
        path.mkdir(parents=True)
        (path / "play.sh").write_text("#!/bin/sh\n")
        return path

    def test_search_locations_persist_deduplicate_and_allow_unmounted_drives(self):
        drive = self.home / "unmounted drive"
        self.library.save_game_folders([drive, drive / "."])
        self.assertEqual(self.library.game_folders(), [drive])
        self.assertFalse(drive.exists())
        other = core.Library(ROOT / "sandbox-game", ROOT, ROOT / "Sandbox game",
                             home=self.home, config=self.library.config)
        self.assertEqual(other.game_folders(), [drive])
        with self.assertRaisesRegex(ValueError, "absolute"):
            self.library.save_game_folders(["relative/games"])
        self.assertEqual(self.library.game_folders(), [drive])
        self.library.save_game_folders([])
        self.assertEqual(self.library.game_folders(), [])

    def test_refresh_finds_legacy_capture_by_folder_name_without_using_display_title(self):
        capture = self.library.capture("original-game")
        capture.mkdir(parents=True)
        core.atomic_write(capture / "manager.json", json.dumps({"title": "My custom title"}))
        location = self.home / "Games"
        game = self.native_game(location / "Native" / "Original -- Game")
        self.library.save_game_folders([location])
        entry, = self.library.refresh()
        self.assertEqual(entry["name"], "original-game")
        self.assertEqual(entry["title"], "My custom title")
        self.assertEqual(entry["directory"], str(game))
        self.assertEqual(self.library.entries(), [entry])

    def test_manual_and_automatic_locate_replace_the_fallback_display_name(self):
        root = self.home / "Games"
        for name, folder in (("manual-game", "Manual Game"), ("automatic-game", "Automatic Game")):
            self.library.capture(name).mkdir(parents=True)
            self.native_game(root / folder)
        manual = next(e for e in self.library.entries() if e["name"] == "manual-game")
        updated = self.library.reconnect(manual, root / "Manual Game")
        self.assertEqual(updated["title"], "Manual Game")
        self.library.save_game_folders([root])
        entries = {e["name"]: e for e in self.library.refresh()}
        self.assertEqual(entries["automatic-game"]["title"], "Automatic Game")
        self.assertEqual(entries["manual-game"]["title"], "Manual Game")
        for name, entry in entries.items():
            saved = core.read_json(self.library.capture(name) / "manager.json")
            self.assertEqual(saved["title"], entry["title"])
            self.assertEqual(entry["name"], name)

    def test_refresh_repairs_display_names_for_previously_located_games(self):
        game = self.native_game(self.home / "Games/Original Game")
        entry = dict(name="original-game", title="original-game", kind="existing",
                     directory=str(game), selection=str(game), program="", arguments="")
        self.library.save_entry(entry)
        with patch.object(self.library, "describe", side_effect=AssertionError("Already located")):
            updated, = self.library.refresh()
        self.assertEqual(updated["title"], "Original Game")
        self.assertEqual(updated["directory"], str(game))

    def test_explicit_display_name_equal_to_sandbox_name_is_preserved(self):
        self.library.capture("original-game").mkdir(parents=True)
        entry, = self.library.entries()
        entry.update(title_custom=True)
        self.library.save_entry(entry)
        game = self.native_game(self.home / "Games/Original Game")
        self.library.save_game_folders([game.parent])
        updated, = self.library.refresh()
        self.assertEqual(updated["title"], "original-game")
        self.assertEqual(self.library.entries()[0]["title"], "original-game")
        self.assertEqual(self.library.add_existing(game, entry["name"])["title"], "original-game")

    def test_managed_install_titles_do_not_use_the_internal_game_folder_name(self):
        entry = self.library.create("managed-game")
        updated, = self.library.refresh()
        self.assertEqual(updated["title"], entry["title"])

    def test_moved_launcher_reconnect_keeps_metadata_settings_and_saves(self):
        old = self.native_game(self.home / "old" / "Original game")
        entry = self.library.add_existing(old / "play.sh")
        entry.update(title="Renamed title", arguments="--test", custom="keep")
        self.library.save_entry(entry)
        self.library.update_settings(entry["name"], {"net": "1"})
        save = self.library.capture(entry["name"]) / "home/save.dat"
        save.parent.mkdir()
        save.write_text("progress")
        root = self.home / "new"
        root.mkdir()
        moved = root / old.name
        old.rename(moved)
        self.library.save_game_folders([root])
        updated, = self.library.refresh()
        self.assertEqual(updated["selection"], str(moved / "play.sh"))
        self.assertEqual(updated["directory"], str(moved))
        for key in ("name", "title", "program", "arguments", "custom"):
            self.assertEqual(updated[key], entry[key])
        self.assertEqual(self.library.settings(entry["name"])["net"], "1")
        self.assertEqual(save.read_text(), "progress")

    def test_ambiguous_matches_need_a_choice_and_manual_reconnect_preserves_details(self):
        capture = self.library.capture("same-game")
        capture.mkdir(parents=True)
        entry, = self.library.entries()
        entry.update(title="Custom title", arguments="--keep")
        self.library.save_entry(entry)
        games = [self.native_game(self.home / parent / "Same Game") for parent in ("one", "two")]
        self.library.save_game_folders([self.home / "one", self.home / "two", self.home / "one"])
        self.assertEqual(self.library.find_game_folders([entry])[entry["name"]], sorted(map(str, games)))
        self.assertEqual(self.library.refresh(), [entry])
        chosen = self.library.reconnect(entry, games[1])
        self.assertEqual(chosen["directory"], str(games[1]))
        self.assertEqual(chosen["title"], "Custom title")
        self.assertEqual(chosen["arguments"], "--keep")

    def test_search_leaves_valid_internal_and_unavailable_games_alone(self):
        internal = self.library.create("Managed")
        outside = self.native_game(self.home / "original" / "External")
        external = self.library.add_existing(outside)
        root = self.home / "other"
        self.native_game(root / "External")
        self.native_game(root / "Managed")
        self.library.save_game_folders([root, self.home / "unmounted"])
        self.assertEqual(self.library.refresh(), sorted([internal, external], key=lambda e: e["title"].casefold()))
        outside.rename(outside.with_name("renamed"))
        self.library.save_game_folders([self.home / "unmounted"])
        self.assertEqual(self.library.refresh(), self.library.entries())

    def test_search_skips_symlinks_sandbox_contents_and_deep_folders(self):
        capture = self.library.capture("find-me")
        capture.mkdir(parents=True)
        entry, = self.library.entries()
        root = self.home / "search"
        root.mkdir()
        outside = self.native_game(self.home / "private" / "Find Me")
        (root / "Find Me").symlink_to(outside, target_is_directory=True)
        self.native_game(root / "one/two/three/Find Me")
        self.native_game(capture / "game/Find Me")
        self.library.save_game_folders([root, capture])
        self.assertEqual(self.library.find_game_folders([entry]), {entry["name"]: []})
        # The configured root itself and the third level are included.
        allowed = self.native_game(root / "one/two/Find Me")
        self.assertEqual(self.library.find_game_folders([entry]), {entry["name"]: [str(allowed)]})

    def test_matching_requires_a_supported_game_and_confined_selected_launcher(self):
        old = self.native_game(self.home / "old" / "Original game")
        entry = self.library.add_existing(old / "play.sh")
        root = self.home / "new"
        candidate = root / old.name
        candidate.mkdir(parents=True)
        (candidate / "play.sh").symlink_to(old / "play.sh")
        self.library.save_game_folders([root])
        self.assertEqual(self.library.find_game_folders([entry]), {entry["name"]: []})
        (candidate / "play.sh").unlink()
        entry.update(selection=str(self.home / "absent/Original game"), directory=str(self.home / "absent/Original game"))
        self.assertEqual(self.library.find_game_folders([entry]), {entry["name"]: []})

    def test_overlapping_search_roots_each_get_their_full_search_depth(self):
        self.library.capture("find-me").mkdir(parents=True)
        entry, = self.library.entries()
        root = self.home / "search"
        nested = root / "one/two"
        game = self.native_game(nested / "three/four/Find Me")
        for locations in ([nested, root], [root, nested]):
            self.library.save_game_folders(locations)
            self.assertEqual(self.library.find_game_folders([entry]), {entry["name"]: [str(game)]})

    def test_reconnect_keeps_details_edited_while_search_was_running(self):
        self.library.capture("game").mkdir(parents=True)
        entry, = self.library.entries()
        edited = {**entry, "title": "New title", "arguments": "--keep"}
        self.library.save_entry(edited)
        game = self.native_game(self.home / "games/Game")
        updated = self.library.reconnect(entry, game)
        self.assertEqual(updated["title"], edited["title"])
        self.assertEqual(updated["arguments"], edited["arguments"])

    def test_refresh_does_not_overwrite_a_location_changed_during_search(self):
        self.library.capture("game").mkdir(parents=True)
        entry, = self.library.entries()
        automatic = self.native_game(self.home / "automatic/Game")
        manual = self.native_game(self.home / "manual/Game")
        def search(entries):
            self.library.reconnect(entry, manual)
            return {entry["name"]: [str(automatic)]}
        with patch.object(self.library, "find_game_folders", side_effect=search):
            updated, = self.library.refresh()
        self.assertEqual(updated["directory"], str(manual))

    def icon_library(self):
        """A library whose icon helper never runs: subprocess.run is patched in each test."""
        helpers = self.home / "helpers"
        helpers.mkdir()
        (helpers / "sandbox-game-icon").write_text("")
        library = core.Library(ROOT / "sandbox-game", helpers, ROOT / "Sandbox game",
                               home=self.home, config=self.home / "config")
        entry = library.create("game")
        for name in ("a.exe", "b.exe"):
            (Path(entry["directory"]) / name).write_bytes(b"MZ")
        return library, entry

    @staticmethod
    def finished(code, output=b""):
        return subprocess.CompletedProcess([], code, output, b"")

    def test_icon_failures_of_the_environment_are_not_remembered(self):
        library, entry = self.icon_library()
        metadata = library.capture(entry["name"]) / "icon.json"
        for failure in (OSError("no bwrap"), self.finished(1), self.finished(-11)):
            with self.subTest(failure=failure), patch("subprocess.run", side_effect=[failure]) as run:
                self.assertIsNone(library.icon(entry))
                self.assertEqual(run.call_count, 1)
                self.assertFalse(metadata.exists())
        # Every file answered: that is remembered, and nothing runs again.
        with patch("subprocess.run", return_value=self.finished(library.NO_ICON)) as run:
            self.assertIsNone(library.icon(entry))
            self.assertEqual(run.call_count, 2)
        self.assertFalse(json.loads(metadata.read_text())["found"])
        with patch("subprocess.run") as run:
            self.assertIsNone(library.icon(entry))
            run.assert_not_called()

    def test_a_slow_file_does_not_stop_the_others_or_get_remembered(self):
        library, entry = self.icon_library()
        slow = subprocess.TimeoutExpired("bwrap", 5)
        with patch("subprocess.run", side_effect=[slow, self.finished(library.NO_ICON)]) as run:
            self.assertIsNone(library.icon(entry))
            self.assertEqual(run.call_count, 2)
        self.assertFalse((library.capture(entry["name"]) / "icon.json").exists())
        with patch("subprocess.run", side_effect=[slow, self.finished(0, b"png")]):
            path = library.icon(entry)
        self.assertEqual(path.read_bytes(), b"png")

    def test_deleted_and_outdated_icon_images_are_made_again(self):
        library, entry = self.icon_library()
        with patch("subprocess.run", return_value=self.finished(0, b"first")):
            first = library.icon(entry)
        first.unlink()
        with patch("subprocess.run", return_value=self.finished(0, b"again")) as run:
            self.assertEqual(library.icon(entry).read_bytes(), b"again")
            run.assert_called_once()
        os.utime(Path(entry["directory"]) / "a.exe", ns=(1, 1))
        with patch("subprocess.run", return_value=self.finished(0, b"changed")):
            second = library.icon(entry)
        self.assertNotEqual(second, first)
        self.assertEqual(sorted(path.name for path in second.parent.iterdir()), [second.name])

    def test_icon_decoder_reads_the_checked_file_not_its_path(self):
        library, entry = self.icon_library()
        with patch("subprocess.run", return_value=self.finished(library.NO_ICON)) as run:
            library.icon(entry)
        for call in run.call_args_list:
            self.assertIsInstance(call.kwargs["stdin"], int)
            self.assertFalse([word for word in call.args[0] if word.endswith(".exe")])
        # A folder swapped for a link after listing: the opened file is outside.
        game = Path(entry["directory"])
        sub = game / "sub"
        sub.mkdir()
        (sub / "icon.png").write_bytes(b"png")
        listed = sub / "icon.png"
        outside = self.home / "private"
        outside.mkdir()
        (outside / "icon.png").write_bytes(b"private")
        shutil.rmtree(sub)
        sub.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            library.open_icon_file(listed, [game])
        (game / "link.png").symlink_to(game / "a.exe")
        with self.assertRaises(OSError):
            library.open_icon_file(game / "link.png", [game])
        os.close(library.open_icon_file(game / "a.exe", [game]))

    def test_import_uses_canonical_detection_and_explicit_name_for_old_captures(self):
        game = self.home / "games" / "Native Game"
        game.mkdir(parents=True)
        (game / "play.sh").write_text("#!/bin/sh\n")
        entry = self.library.add_existing(game, "old-capture")
        command, env = self.library.command(entry)
        self.assertEqual(command, [str(ROOT / "Sandbox game")])
        self.assertEqual(env["SANDBOX_GAME_NAME"], "old-capture")
        self.assertEqual(env["SANDBOX_BACKEND"], str(ROOT / "sandbox-game"))
        self.assertEqual(env["NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"], str(game))

    def test_native_binary_exports_can_be_imported_and_automatically_located(self):
        root = self.home / "Games"
        for filename, name in (("Game.x86_64", "godot-export"), ("Game", "native-export")):
            game = root / name
            game.mkdir(parents=True)
            binary = game / filename
            shutil.copyfile("/bin/true", binary)
            binary.chmod(0o644)
            (game / "Game.pck").write_bytes(b"pack")
            for selection in (game, binary):
                with self.subTest(selection=selection):
                    entry = self.library.add_existing(selection)
                    self.assertEqual(entry["engine"], "native")
                    self.assertEqual(entry["directory"], str(game))
            # Simulate a legacy capture with no recorded install location.
            (self.library.capture(entry["name"]) / "manager.json").unlink()
        self.library.save_game_folders([root])
        for entry in self.library.refresh():
            self.assertEqual(entry["engine"], "native")
            self.assertTrue(Path(entry["directory"]).is_dir())
            command, env = self.library.command(entry)
            self.assertEqual(command, [str(ROOT / "Sandbox game")])
            self.assertEqual(env["NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"], entry["directory"])

    def test_shared_libraries_data_and_external_symlinks_are_not_native_launchers(self):
        game = self.home / "Games/Not runnable"
        game.mkdir(parents=True)
        (game / "Game.pck").write_bytes(b"pack")
        # A shared object's ELF header has no program entry point.
        header = bytearray(Path("/bin/true").read_bytes()[:64])
        header[24:32] = bytes(8)
        (game / "library").write_bytes(header)
        shutil.copyfile("/bin/true", game / "libgame.so")
        (game / "outside.x86_64").symlink_to("/bin/true")
        (game / "fake.x86_64").write_bytes(b"\x7fELF")
        self.assertEqual(self.library.describe(game, "test")["engine"], "")
        with self.assertRaisesRegex(ValueError, "No supported game"):
            self.library.add_existing(game)

    def test_settings_keep_unknown_keys_and_defaults_separate(self):
        entry = self.library.create("game")
        name = entry["name"]
        self.library.update_settings(name, {"net": "1", "env": "A=default", "casefold": "0"}, defaults=True)
        self.library.update_settings(name, {"custom_option": "keep", "net": "0"})
        self.library.save_preferences(name, {"scope": "game", "mangohud": "1"})
        saved = core.read_settings(self.library.config / "games" / name)
        self.assertEqual(saved["custom_option"], "keep")
        self.assertNotIn("casefold", saved)
        self.assertNotIn("env", saved)
        self.assertEqual(self.library.settings(name)["env"], "A=default")
        self.library.save_preferences(name, {"scope": "all", "net": "1"})
        self.assertEqual(self.library.settings(name)["net"], "0")
        self.library.save_preferences(name, {"scope": "clear"})
        self.assertEqual(self.library.settings(name)["net"], "1")

    def test_different_games_with_the_same_folder_name_get_separate_sandboxes(self):
        entries = []
        for parent in ("one", "two"):
            game = self.home / parent / "Same name"
            game.mkdir(parents=True)
            (game / "play.sh").write_text("#!/bin/sh\n")
            entries.append(self.library.add_existing(game))
        self.assertNotEqual(entries[0]["name"], entries[1]["name"])
        self.assertEqual(len(self.library.entries()), 2)

    def test_display_edits_preserve_other_gamescope_options(self):
        entry = self.library.create("game")
        self.library.update_settings(entry["name"], {"gamescope_args": "--adaptive-sync -r 60 -W 100 -H 100"})
        self.library.save_preferences(entry["name"], {"scope": "game", "gamescope_resolution": "1920x1080",
                                                     "gamescope_fullscreen": "1"})
        value = self.library.settings(entry["name"])["gamescope_args"]
        self.assertEqual(value, "-W 1920 -H 1080 -f --adaptive-sync -r 60")

    def test_split_display_flags_preserve_executable_names_with_spaces(self):
        entry = self.library.create("game")
        self.library.update_settings(entry["name"], {"wayland": "1", "wayland_x11": "1",
            "x11_exe": "Vendor Launcher.exe", "gamescope_args": "-W 1920 -H 1080"})
        flags = self.library.flags(entry)
        self.assertIn("--wayland-x11", flags)
        self.assertIn("--x11-exe=Vendor Launcher.exe", flags)
        self.assertIn("--gamescope=-W 1920 -H 1080", flags)
        self.assertNotIn("--wayland", flags)
        self.library.update_settings(entry["name"], {"wayland": "0"})
        self.assertNotIn("--wayland-x11", self.library.flags(entry))

    def test_program_selection_refuses_traversal_external_links_and_missing_files(self):
        entry = self.library.create("game")
        game = Path(entry["directory"])
        secret = self.home / "private.exe"
        secret.write_text("private")
        (game / "external.exe").symlink_to(secret)
        for target in ("/etc/passwd", "/game/../private.exe", "/game/external.exe",
                       "/compat/pfx/drive_c/../../private.exe", "/game/missing.exe"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.library.program_host(entry, target)
        self.assertEqual(self.library.programs(entry), [])

    def test_upper_layer_program_overrides_the_original(self):
        entry = self.library.create("game")
        lower = Path(entry["directory"]) / "play.exe"
        lower.write_text("original")
        upper = self.library.capture(entry["name"]) / "rw/play.exe"
        upper.parent.mkdir()
        upper.write_text("update")
        self.assertEqual(self.library.program_host(entry, "/game/play.exe"), upper)
        self.assertEqual(self.library.programs(entry), [("/game/play.exe", "play.exe")])

    def test_prefix_links_do_not_make_the_manager_scan_the_host_home(self):
        entry = self.library.create("game")
        external = self.home / "outside"
        (external / "drive_c").mkdir(parents=True)
        (external / "drive_c/private.exe").write_text("host file")
        compat = self.library.capture(entry["name"]) / "compat"
        compat.mkdir()
        (compat / "pfx").symlink_to(external, target_is_directory=True)
        self.assertEqual(self.library.programs(entry), [])
        with self.assertRaises(ValueError):
            self.library.program_host(entry, "/compat/pfx/drive_c/private.exe")

    def test_running_sandbox_cannot_be_started_a_second_time(self):
        entry = self.library.create("game")
        with patch.object(self.library, "running", return_value={entry["name"]}), \
                patch("subprocess.Popen") as popen:
            with self.assertRaisesRegex(ValueError, "running"):
                self.library.start(entry)
            popen.assert_not_called()

    def test_names_and_settings_cannot_escape_their_files(self):
        for name in ("..", ".", "../other", "/other", "game\nother"):
            with self.assertRaises(ValueError):
                self.library.capture(name)
        entry = self.library.create("game")
        for changes in ({"net": "1\nenv=bad"}, {"../other": "value"}):
            with self.assertRaises(ValueError):
                self.library.update_settings(entry["name"], changes)
        (self.library.root / "linked").symlink_to(self.home, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.library.capture("linked")
        self.assertEqual(len(self.library.entries()), 1)

    def test_x11_display_keeps_its_gamescope_resolution_and_fullscreen(self):
        entry = self.library.create("game")
        # What the preferences window returns for "X11, in gamescope".
        self.library.save_preferences(entry["name"], {
            "scope": "game", "wayland": "0", "gamescope": "0", "host_x11": "0",
            "net": "0", "gamescope_resolution": "1920x1080", "gamescope_fullscreen": "1"})
        self.assertIn("--gamescope=-W 1920 -H 1080 -f", self.library.flags(entry))
        with patch.dict(os.environ, {"PROTON_VER": "GE-Test"}):
            self.assertIn("--proton=GE-Test", self.library.flags(entry))

    def test_manager_and_file_manager_launcher_pass_the_same_options(self):
        config = self.home / ".config/sandbox-game"
        library = core.Library(ROOT / "sandbox-game", ROOT, ROOT / "Sandbox game", home=self.home, config=config)
        game = self.home / "Games/Windows Game"
        game.mkdir(parents=True)
        (game / "Game.exe").write_text("game")
        entry = library.add_existing(game / "Game.exe")
        (config / "games").mkdir(parents=True, exist_ok=True)
        (config / "defaults").write_text("env=DXVK_HUD=1\nmangohud=1\n")
        (config / "games" / entry["name"]).write_text(
            "gamescope=0\nwayland=0\ngamescope_args=-W 1280 -H 720 -f\nnet=1\nlan_allow=10.0.0.5\n"
            "private_hosts=1\nhosts=10.0.0.5 a.example, 10.0.0.6 b.example\nproton=GE-Test\nmod_loaders=1\n")
        recorded = self.home / "recorded"
        stub = self.home / "sandbox-game"
        stub.write_text(f'#!/bin/sh\n[ "$1" = --print-name ] && exec "{ROOT / "sandbox-game"}" "$@"\n'
                        f'printf "%s\\n" "$@" > "{recorded}"\n')
        stub.chmod(0o755)
        (self.home / ".local/lib/sandbox-game").mkdir(parents=True)
        (self.home / ".local/lib/sandbox-game/sandbox-game-lib").symlink_to(ROOT / "sandbox-game-lib")
        env = {**os.environ, "HOME": str(self.home), "XDG_CONFIG_HOME": str(self.home / ".config"),
               "SANDBOX_BACKEND": str(stub), "SANDBOX_GAME_NAME": entry["name"],
               "NAUTILUS_SCRIPT_SELECTED_FILE_PATHS": str(game / "Game.exe"), "PATH": "/usr/bin:/bin"}
        env.pop("PROTON_VER", None)
        result = subprocess.run([str(ROOT / "Sandbox game")], env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        launched = recorded.read_text().splitlines()
        self.assertEqual(launched[-2:], [str(game), "/game/Game.exe"])
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PROTON_VER", None)
            flags = library.flags(entry)
        self.assertEqual(sorted(launched[:-2]), sorted(flags[1:]))
        self.assertIn("--gamescope=-W 1280 -H 720 -f", flags)
        # The launcher's log is the one the manager shows.
        self.assertTrue(library.log_path(entry["name"]).exists())
        self.assertFalse((self.home / "game-sandboxes/Windows Game-lastrun.log").exists())

    def test_starting_through_the_file_manager_launcher_keeps_its_log(self):
        game = self.home / "My Game"
        game.mkdir()
        (game / "play.sh").write_text("#!/bin/sh\n")
        entry = self.library.add_existing(game)
        self.library.log_path(entry["name"]).write_text("previous run")
        with patch.object(self.library, "running", return_value=set()), patch("subprocess.Popen") as popen:
            self.library.start(entry)
        popen.assert_called_once()
        self.assertEqual(self.library.log_path(entry["name"]).read_text(), "previous run")

    def test_environment_editor_writes_only_the_chosen_files_own_list(self):
        entry = self.library.create("game")
        name = entry["name"]
        self.library.update_settings(name, {"env": "DXVK_HUD=1"}, defaults=True)
        self.library.save_preferences(name, {"scope": "game", "env": ""})
        self.assertNotIn("env", self.library.scope_settings(name))
        self.assertEqual(self.library.settings(name)["env"], "DXVK_HUD=1")
        self.library.save_preferences(name, {"scope": "game", "env": "GAME=1"})
        self.library.save_preferences(name, {"scope": "all", "env": "ALL=1"})
        self.assertEqual(self.library.scope_settings(name)["env"], "GAME=1")
        self.assertEqual(self.library.scope_settings(name, True)["env"], "ALL=1")
        # A file that says "no variables" keeps saying it.
        self.library.update_settings(name, {"env": ""})
        self.library.save_preferences(name, {"scope": "game", "env": ""})
        self.assertEqual(self.library.settings(name)["env"], "")
        for bad in ("NAME", "1A=b", "A=b\nB=c"):
            with self.subTest(env=bad), self.assertRaises(ValueError):
                self.library.save_preferences(name, {"scope": "game", "env": bad})

    def test_saved_preferences_match_the_file_manager_window(self):
        entry = self.library.create("game")
        name = entry["name"]
        self.library.update_settings(name, {"gamescope_args": "-W 1280 -H 720"}, defaults=True)
        self.library.save_preferences(name, {"scope": "game", "gamescope_resolution": "1280x720",
                                             "gamescope_fullscreen": "0"})
        # Equal to the defaults: the game keeps following them.
        self.assertNotIn("gamescope_args", self.library.scope_settings(name))
        for result in ({"lan_allow": "not-an-address"}, {"hosts": "10.0.0.1"}, {"unknown_key": "1"}):
            with self.subTest(result=result), self.assertRaises(ValueError):
                self.library.save_preferences(name, {"scope": "game", **result})

    def test_installers_in_shared_folders_see_only_their_own_files(self):
        entry = self.library.create("game")
        for folder in (self.home, self.home / "Downloads"):
            with self.subTest(folder=folder):
                folder.mkdir(exist_ok=True)
                installer = folder / "setup_game.exe"
                installer.write_text("installer")
                (folder / "setup_game-1.bin").write_text("data")
                (folder / "private.txt").write_text("secret")
                command, _ = self.library.command(entry, installer=installer)
                self.assertNotIn(str(folder), command)
                binds = [command[i + 1:i + 3] for i, word in enumerate(command[:command.index("--")])
                         if word == "--ro"]
                self.assertEqual(sorted(binds), [[str(installer), "/installer/setup_game.exe"],
                                         [str(folder / "setup_game-1.bin"), "/installer/setup_game-1.bin"]][::-1])
        msi = self.home / "Downloads/package.msi"
        msi.write_text("msi")
        (msi.parent / "Data1.cab").write_text("cabinet")
        command, _ = self.library.command(entry, installer=msi)
        self.assertIn("/installer/Data1.cab", command)
        dedicated = self.home / "Downloads/Game Setup"
        (dedicated / "data").mkdir(parents=True)
        (dedicated / "setup.exe").write_text("installer")
        command, _ = self.library.command(entry, installer=dedicated / "setup.exe")
        self.assertEqual(command[command.index("--ro") + 1:command.index("--ro") + 3], [str(dedicated), "/installer"])

    def test_windows_drive_must_be_a_real_folder_in_the_sandbox(self):
        entry = self.library.create("game")
        prefix = self.library.capture(entry["name"]) / "compat/pfx"
        prefix.mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "no Windows drive"):
            self.library.windows_drive(entry["name"])
        (prefix / "evil.html").write_text("<script></script>")
        (prefix / "drive_c").symlink_to("evil.html")
        with self.assertRaisesRegex(ValueError, "not a folder"):
            self.library.windows_drive(entry["name"])
        (prefix / "drive_c").unlink()
        (prefix / "drive_c").write_text("a file")
        with self.assertRaises(ValueError):
            self.library.windows_drive(entry["name"])
        self.assertEqual(self.library.programs(entry), [])
        (prefix / "drive_c").unlink()
        (prefix / "drive_c").mkdir()
        self.assertEqual(self.library.windows_drive(entry["name"]), prefix / "drive_c")

    def test_new_sandbox_does_not_reuse_a_deleted_ones_settings_or_log(self):
        first = self.library.create("Foo")
        self.library.update_settings(first["name"], {"private_hosts": "1", "env": "OLD=1"})
        shutil.rmtree(self.library.capture(first["name"]))   # --delete keeps the preferences
        second = self.library.create("Foo")
        self.assertNotEqual(second["name"], first["name"])
        self.assertNotIn("env", self.library.settings(second["name"]))
        self.library.log_path("bar").write_text("old log")
        self.assertNotEqual(self.library.create("Bar")["name"], "bar")

    def test_log_reading_tolerates_windows_encodings_and_bounds_large_logs(self):
        entry = self.library.create("game")
        self.library.log_path(entry["name"]).write_bytes(b"x" * 300000 + b"\xff error")
        log = self.library.read_log(entry["name"])
        self.assertLessEqual(len(log), 256 * 1024)
        self.assertTrue(log.endswith("\ufffd error"))


if __name__ == "__main__":
    unittest.main()
