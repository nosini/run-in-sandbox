"""Library, preferences and process operations for the desktop manager.

No GTK imports here: every game and installer still runs through sandbox-game.
Metadata lives outside the writable mounts handed to games.
"""
import json
import hashlib
import os
import re
import shlex
import signal
import stat
import subprocess
import tempfile
import threading
from pathlib import Path


NAME = re.compile(r"[A-Za-z0-9._-]+")
# Where removable drives are mounted. See Library.folder_state.
REMOVABLE_ROOTS = (Path("/run/media"), Path("/media"), Path("/mnt"))


def valid_name(name):
    return bool(NAME.fullmatch(name)) and name not in (".", "..")


def read_json(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def atomic_write(path, text, mode=None):
    """Replace PATH with TEXT, a str or bytes, never leaving a partial file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    binary = isinstance(text, bytes)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb" if binary else "w", encoding=None if binary else "utf-8",
                                         dir=path.parent, prefix=".manager-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(text)
            if mode is not None:
                os.fchmod(stream.fileno(), mode)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def mount_point(path):
    """The mount point holding PATH, or its nearest existing parent."""
    path = Path(os.path.abspath(path))
    while not os.path.ismount(path):
        path = path.parent
    return path


def fstab_mount_points(fstab=Path("/etc/fstab")):
    try:
        lines = fstab.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    points = []
    for line in lines:
        fields = line.split()
        if len(fields) >= 2 and not fields[0].startswith("#") and fields[1].startswith("/"):
            # Blanks in paths are written as octal escapes: \040 for a space.
            points.append(Path(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), fields[1])))
    return points


def read_settings(path):
    values = {}
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            key, separator, value = line.partition("=")
            if separator and not key.lstrip().startswith("#"):
                values[key.strip()] = value.strip()
    except FileNotFoundError:
        pass
    return values


def desktop_string(text):
    """TEXT as a desktop entry string value."""
    text = text.replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t").replace("\r", "\\r")
    return "\\s" + text[1:] if text.startswith(" ") else text


# Characters the desktop entry spec says an Exec argument must be quoted for.
EXEC_RESERVED = re.compile(r"""[\s"'\\><~|&;$*?#()`]""")


def desktop_exec_argument(text):
    """TEXT as one argument of a desktop entry's Exec key: quoted only when it
    must be, as menu editors take a quoted program for a missing one."""
    text = text.replace("%", "%%")
    if text and not EXEC_RESERVED.search(text):
        return text
    for char in ('\\', '"', '`', '$'):
        text = text.replace(char, '\\' + char)
    # The string parser undoes one level of backslashes before Exec is split.
    return '"' + text.replace('\\', '\\\\') + '"'


class Library:
    SHORTCUTS = ("menu", "desktop")

    def __init__(self, backend, helpers, launcher, home=None, config=None, data=None, desktop=None):
        self.backend = Path(backend)
        self.helpers = Path(helpers)
        self.launcher = Path(launcher)
        self.home = Path(home) if home is not None else Path.home()
        self.root = self.home / "game-sandboxes"
        self.config = Path(config) if config is not None else Path(
            os.environ.get("XDG_CONFIG_HOME") or self.home / ".config") / "sandbox-game"
        self.data = Path(data) if data is not None else Path(
            os.environ.get("XDG_DATA_HOME") or self.home / ".local/share")
        self.desktop = Path(desktop) if desktop is not None else None
        # One folder search or reconnect at a time, each over what the last saved.
        self.lock = threading.RLock()

    def capture(self, name):
        if not valid_name(name):
            raise ValueError("Invalid sandbox name")
        path = self.root / name
        if path.is_symlink():
            raise ValueError("Sandbox folders must not be symbolic links")
        return path

    def entries(self):
        if not self.root.exists():
            return []
        entries = [self.load_entry(capture) for capture in self.root.iterdir()
                   if capture.is_dir() and not capture.is_symlink() and valid_name(capture.name)]
        return sorted(entries, key=lambda entry: entry["title"].casefold())

    def entry(self, name):
        """One entry as entries() shows it, read afresh."""
        return self.load_entry(self.capture(name))

    def load_entry(self, capture, display=True):
        entry = read_json(capture / "manager.json")
        source = read_json(capture / "source.json")
        # Defaults also make captures created before the manager visible.
        entry.update(name=capture.name, title=str(entry.get("title", capture.name)))
        entry.setdefault("kind", "existing")
        entry.setdefault("selection", source.get("directory", ""))
        entry.setdefault("directory", source.get("directory", ""))
        entry.setdefault("program", "")
        entry.setdefault("arguments", "")
        if display:
            entry["title"] = self.display_title(entry)
        return entry

    def update_entry(self, name, derive_title=False, **changes):
        """Change only these fields of the entry as saved now, keeping whatever
        else changed since it was shown: a game reconnected meanwhile, say."""
        entry = {**self.load_entry(self.capture(name), display=False), **changes}
        if derive_title:
            entry["title"] = self.display_title(entry)
        self.save_entry(entry)
        return self.entry(name)

    @staticmethod
    def display_title(entry):
        title = entry.get("title", entry["name"])
        if entry.get("kind") == "existing" and title == entry["name"] \
                and not entry.get("title_custom") and entry.get("directory"):
            return Path(entry["directory"]).name or title
        return title

    def save_entry(self, entry):
        if entry.get("kind") not in ("windows", "existing"):
            raise ValueError("Unknown sandbox type")
        for key in ("name", "title", "directory", "selection", "program", "arguments", "volume"):
            if not isinstance(entry.get(key, ""), str) or "\0" in entry.get(key, ""):
                raise ValueError(f"Invalid {key}")
        if not entry["title"].strip():
            raise ValueError("Give the sandbox a name")
        shlex.split(entry.get("arguments", ""))
        atomic_write(self.capture(entry["name"]) / "manager.json",
                     json.dumps(entry, ensure_ascii=False, indent=2) + "\n")

    def installation(self, entry):
        """Describe where the installed game lives, independently of its runner."""
        directory = entry.get("directory", "")
        if directory:
            if Path(directory).resolve().is_relative_to(self.capture(entry["name"]).resolve()):
                return "sandbox"
            return "external"
        if entry.get("kind") == "windows":
            return "sandbox"
        return "unknown"

    def matches(self, entry, query="", location="all", installation=None):
        """INSTALLATION, when known, saves looking at the game's folder again."""
        return query.casefold() in entry["title"].casefold() and (
            location == "all" or (installation or self.installation(entry)) == location)

    def game_folders(self):
        folders = read_json(self.config / "game-folders.json").get("folders", [])
        if not isinstance(folders, list):
            return []
        return [Path(folder) for folder in folders
                if isinstance(folder, str) and "\0" not in folder and Path(folder).is_absolute()]

    @staticmethod
    def game_folder_path(text):
        """A search location as typed, checked without touching the disk:
        unmounted drives are valid settings too."""
        text = str(text).strip()
        if not text or "\0" in text:
            raise ValueError("Enter a folder path")
        path = Path(text).expanduser()
        if not path.is_absolute():
            raise ValueError("Game folder locations must be absolute paths")
        return path

    def save_game_folders(self, folders):
        paths = []
        for folder in folders:
            # Never create these folders.
            path = str(self.game_folder_path(folder).resolve())
            if path not in paths:
                paths.append(path)
        atomic_write(self.config / "game-folders.json", json.dumps({"folders": paths}, indent=2) + "\n")

    def folder_state(self, entry):
        """present; missing, to be searched for; or unavailable: on a drive
        that is not mounted, which keeps its saved location until it is back."""
        selection = entry.get("selection", "")
        if not selection:
            return "missing"
        path = Path(selection)
        try:
            if path.exists():
                return "present"
            volume = entry.get("volume")
            if volume:
                return "missing" if os.path.ismount(volume) else "unavailable"
            # Located before the volume was recorded: a mount point on the way
            # that is not mounted, from fstab or for a removable drive.
            for point in fstab_mount_points():
                if point != Path("/") and path.is_relative_to(point) and not os.path.ismount(point):
                    return "unavailable"
            existing = path.parent
            while not existing.exists():
                existing = existing.parent
            if any(path.is_relative_to(root) and not mount_point(existing).is_relative_to(root)
                   for root in REMOVABLE_ROOTS):
                return "unavailable"
        except OSError:
            return "unavailable"
        return "missing"

    def sandbox_names(self, folders):
        """sandbox-game's own names for FOLDERS: derive_name, NAME_MAP and all."""
        if not folders:
            return []
        result = subprocess.run(["bash", "-c", '. "$1/sandbox-game-lib" && derive_names', "names",
                                 str(self.helpers)], input=b"".join(os.fsencode(f) + b"\0" for f in folders),
                                capture_output=True, check=True, timeout=60)
        names = [os.fsdecode(name) for name in result.stdout.split(b"\0")[:-1]]
        if len(names) != len(folders):
            raise ValueError("Cannot name game folders")
        return names

    def walk_game_folders(self):
        """(folder, resolved) for the game folders and three levels below them:
        no symbolic links, nothing inside a sandbox."""
        visited, folders = {}, {}
        captures = self.root.resolve()
        pending = [(folder, 0) for folder in self.game_folders()]
        while pending:
            folder, depth = pending.pop()
            try:
                if folder.is_symlink() or not folder.is_dir():
                    continue
                resolved = folder.resolve()
                if visited.get(resolved, 4) <= depth or resolved.is_relative_to(captures):
                    continue
                visited[resolved] = depth
                folders.setdefault(resolved, folder)
                if depth < 3:
                    with os.scandir(folder) as children:
                        pending.extend((Path(child.path), depth + 1) for child in children
                                       if not child.name.startswith(".") and child.is_dir(follow_symlinks=False))
            except (OSError, RuntimeError):
                continue  # unavailable drives must not hide the rest of the library
        return [(folder, resolved) for resolved, folder in folders.items()]

    def find_game_folders(self, entries):
        """Match known games under configured roots; never execute game launchers."""
        return {name: sorted(matches) for name, matches in self.search_game_folders(entries).items()}

    def search_game_folders(self, entries):
        """{name: {selection: game folder}} for each of ENTRIES."""
        found = {entry["name"]: {} for entry in entries}
        wanted = [entry for entry in entries
                  if entry.get("kind") == "existing" and self.installation(entry) != "sandbox"]
        folders = self.walk_game_folders() if wanted else []
        if not folders:
            return found
        # Folders are named as sandbox-game names them. A sandbox goes by its
        # recorded folder's name or, recorded before folders were, its own; a
        # renamed display title must not change which files a sandbox uses.
        recorded = [entry["directory"] for entry in wanted if entry.get("directory")]
        names = self.sandbox_names([folder for folder, _ in folders] + recorded)
        recorded_names = iter(names[len(folders):])
        keys = {}
        for entry in wanted:
            keys.setdefault(next(recorded_names) if entry.get("directory") else entry["name"], []).append(entry)
        for (_, resolved), name in zip(folders, names):
            for entry in keys.get(name, []):
                selection = resolved
                if entry.get("directory") and entry.get("selection"):
                    try:
                        selection = resolved / Path(entry["selection"]).relative_to(entry["directory"])
                    except ValueError:
                        continue
                try:
                    if not selection.exists() or not selection.resolve().is_relative_to(resolved):
                        continue
                    info = self.describe(selection, entry["name"])
                except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
                    continue
                if info.get("engine") and Path(info["directory"]).resolve() == resolved:
                    found[entry["name"]][str(selection)] = str(resolved)
        return found

    def reconnect(self, entry, selection):
        with self.lock:
            selection = Path(selection).resolve(strict=True)
            info = self.describe(selection, entry["name"])
            if not info.get("engine"):
                raise ValueError("No supported game was found. Select its launcher or game folder.")
            # Over the entry as saved now: a background search must keep any
            # details edited since it started.
            return self.update_entry(entry["name"], derive_title=True, selection=str(selection),
                                     directory=info["directory"], engine=info["engine"],
                                     volume=str(mount_point(info["directory"])))

    def refresh(self):
        """entries(), once missing games found in the game folders are reconnected."""
        with self.lock:
            entries = self.entries()
            states = {entry["name"]: self.folder_state(entry) for entry in entries
                      if entry.get("kind") == "existing"}
            found = self.search_game_folders([entry for entry in entries
                                              if states.get(entry["name"]) == "missing"])
            # A folder several sandboxes match, or another one uses, is left to
            # Locate game: two sandboxes would otherwise share one game folder.
            claims = {}
            for matches in found.values():
                for folder in set(matches.values()):
                    claims[folder] = claims.get(folder, 0) + 1
            for entry in entries:
                if states.get(entry["name"]) != "missing" and entry.get("directory"):
                    claims[str(Path(entry["directory"]).resolve())] = 2
            for index, entry in enumerate(entries):
                matches = found.get(entry["name"], {})
                if len(matches) != 1:
                    continue
                (selection, folder), = matches.items()
                if claims[folder] > 1:
                    continue
                try:
                    latest = self.entry(entry["name"])
                    if any(latest.get(key) != entry.get(key) for key in ("kind", "directory", "selection")):
                        entries[index] = latest  # located by hand meanwhile
                        continue
                    entries[index] = self.reconnect(entry, selection)
                except (OSError, ValueError, subprocess.SubprocessError):
                    pass  # a drive may disappear during scanning
            # Which drive each game is on, to tell it missing from unplugged later.
            for index, entry in enumerate(entries):
                if states.get(entry["name"]) == "present" and entry.get("directory") and not entry.get("volume"):
                    try:
                        entries[index] = self.update_entry(entry["name"],
                                                           volume=str(mount_point(entry["directory"])))
                    except (OSError, ValueError):
                        pass
            return sorted(entries, key=lambda entry: entry["title"].casefold())

    def icon_sources(self, entry):
        """Only the selected executable and nearby files; never search the host."""
        return self.icon_files(entry)[0]

    def icon_files(self, entry):
        """The candidate files, and the folders they must stay inside."""
        candidates = []
        if entry.get("program"):
            try:
                candidates.append(self.program_host(entry, entry["program"]))
            except ValueError:
                pass
        elif entry.get("selection") and Path(entry["selection"]).is_file():
            candidates.append(Path(entry["selection"]))
        directory = entry.get("directory", "")
        roots = []
        for executable in candidates[:]:
            roots.append(executable.parent)
            for suffix in (".ico", ".png"):
                candidates.append(executable.with_suffix(suffix))
        if directory:
            roots.append(Path(directory))
        for root in dict.fromkeys(roots):
            for relative in ("icon.png", "icon.ico", "game.png", "game.ico",
                             "window_icon.png", "game/gui/window_icon.png"):
                candidates.append(root / relative)
            # An imported folder may not have a selected launcher yet.
            try:
                candidates.extend(sorted(root.glob("*.exe"))[:12])
                candidates.extend(sorted(root.glob("*.ico"))[:8])
            except OSError:
                pass
        safe = []
        for path in dict.fromkeys(candidates):
            try:
                if path.suffix.lower() not in (".exe", ".ico", ".png") or not path.is_file():
                    continue
                # Games can plant symlinks, including icon.png -> a host file.
                if not any(path.resolve().is_relative_to(root.resolve()) for root in roots):
                    continue
                safe.append(path)
            except OSError:
                continue
        return safe[:32], roots

    @staticmethod
    def open_icon_file(path, roots):
        """Open PATH, without following a link, only if what was opened lies inside ROOTS.

        Checked on the open descriptor: a game that swaps the file for a link
        after it was listed can no longer change what the decoder reads."""
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            opened = Path(os.readlink(f"/proc/self/fd/{fd}"))
            if not stat.S_ISREG(os.fstat(fd).st_mode) or \
                    not any(opened.is_relative_to(root.resolve()) for root in roots):
                raise OSError(f"{path} is not a file inside the game")
            return fd
        except BaseException:
            os.close(fd)
            raise

    NO_ICON = 3  # sandbox-game-icon's status for a file without a usable icon

    def icon(self, entry):
        sources, roots = self.icon_files(entry)
        fingerprint = []
        for path in sources:
            try:
                info = path.stat()
                fingerprint.append([str(path), info.st_size, info.st_mtime_ns])
            except OSError:
                pass
        key = hashlib.sha256(json.dumps(fingerprint).encode()).hexdigest()
        capture = self.capture(entry["name"])
        metadata = read_json(capture / "icon.json")
        cached = capture / "icons" / (key + ".png")
        if cached.is_file():
            return cached
        if metadata.get("key") == key and metadata.get("found") is False:
            return None
        helper = self.helpers / "sandbox-game-icon"
        if not helper.is_file():
            return None
        result = None
        # Only an answer from every file is remembered as "no icon": a missing
        # bwrap, a broken GdkPixbuf or a busy system says nothing about them.
        definite = True
        for path in sources:
            try:
                fd = self.open_icon_file(path, roots)
            except OSError:
                continue  # changed since it was listed
            try:
                # The parser/decoder gets one open file, no home, display or network.
                # New GdkPixbuf builds invoke their own Glycin sandbox, so
                # permit that nested decoder while isolating the PE reader too.
                args = ["bwrap", "--unshare-all", "--unshare-user",
                        "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--clearenv",
                        "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib",
                        "--symlink", "usr/lib64", "/lib64", "--dev", "/dev", "--tmpfs", "/tmp",
                        "--proc", "/proc", "--setenv", "HOME", "/tmp",
                        "--ro-bind", str(helper), "/extract.py",
                        "--chdir", "/", "/usr/bin/python3", "-I", "/extract.py", "-"]
                output = subprocess.run(args, stdin=fd, capture_output=True, check=False, timeout=5)
            except subprocess.TimeoutExpired:
                definite = False
                continue  # this file may just be slow; the others still get a turn
            except OSError:
                definite = False
                break  # no isolation available: keep the generic icon for now
            finally:
                os.close(fd)
            if output.returncode == 0 and output.stdout:
                result = output.stdout
                break
            # No icon in it, or the helper's CPU limit ended it: that file's answer.
            if output.returncode not in (self.NO_ICON, 128 + signal.SIGXCPU, 128 + signal.SIGKILL):
                definite = False
                break
        if result:
            atomic_write(cached, result)
        if result or definite:
            atomic_write(capture / "icon.json", json.dumps({"key": key, "found": bool(result)}))
            for old in cached.parent.glob("*.png"):
                if old != cached:
                    old.unlink(missing_ok=True)  # made for files that have changed since
        return cached if result else None

    def create(self, title, proton="auto", internet=False):
        if not title.strip():
            raise ValueError("Give the sandbox a name")
        if any(c in proton for c in "\r\n\0") or "\0" in title:
            raise ValueError("Invalid sandbox name or runner path")
        stem = re.sub(r"[^a-z0-9._-]+", "-", title.lower()).strip(".-") or "game"
        self.root.mkdir(parents=True, exist_ok=True)
        for index in range(1, 10000):
            name = stem if index == 1 else f"{stem}-{index}"
            capture = self.capture(name)
            # --delete keeps a sandbox's preferences, and a log from before
            # logs moved into the folder stays too: a new sandbox must not
            # pick up either under a reused name.
            if (self.config / "games" / name).exists() or self.old_log_path(name).exists():
                continue
            try:
                capture.mkdir()
                break
            except FileExistsError:
                continue
        else:
            raise ValueError("Too many sandboxes with this name")
        directory = capture / "game"
        directory.mkdir()
        entry = dict(name=name, title=title.strip(), kind="windows", directory=str(directory),
                     selection=str(directory), program="", arguments="")
        self.save_entry(entry)
        self.update_settings(name, {"proton": proton, "net": "1" if internet else "0",
                                    "wayland": "0", "host_x11": "0", "gamescope": "1"})
        return entry

    def describe(self, selection, name):
        """Use the same engine detection as the file manager, without a GUI."""
        script = '''
set -e
. "$1/sandbox-game-lib"
resolve_selection "$2"
NAME="$3"
game_engine "$2" auto
renpy=0; dotnet=0; windows=0
if renpy_without_wayland "$R_GAMEDIR"; then renpy=1; fi
if is_dotnet "$R_GAMEDIR"; then dotnet=1; fi
if has_windows_exe "$R_GAMEDIR"; then windows=1; fi
python3 - "$R_GAMEDIR" "$R_ENGINE" "$renpy" "$dotnet" "$windows" <<'PY'
import json, sys
d, engine, renpy, dotnet, windows = sys.argv[1:]
print(json.dumps(dict(directory=d, engine=engine, renpy_x11=renpy == "1",
                     dotnet=dotnet == "1", can_proton=windows == "1")))
PY
'''
        result = subprocess.run(["bash", "-c", script, "describe", str(self.helpers),
                                 str(selection), name], check=True, capture_output=True,
                                text=True, timeout=20)
        return json.loads(result.stdout)

    def add_existing(self, selection, name=None):
        selection = Path(selection).resolve(strict=True)
        info = self.describe(selection, name or "unused")
        if not info["engine"]:
            raise ValueError("No supported game was found. Select its launcher or game folder.")
        if name is None:
            name = subprocess.run([str(self.backend), "--print-name", info["directory"]],
                                  check=True, capture_output=True, text=True, timeout=10).stdout.strip()
            stem = name
            index = 1
            while self.capture(name).exists():
                capture = self.capture(name)
                prior = read_json(capture / "manager.json") or read_json(capture / "source.json")
                directory = prior.get("directory", "")
                if not directory or Path(directory).resolve() == Path(info["directory"]).resolve():
                    if prior.get("kind") == "windows":
                        return {**prior, "name": name}
                    break
                index += 1
                name = f"{stem}-{index}"
        capture = self.capture(name)
        prior = read_json(capture / "manager.json")
        entry = dict(prior, name=name, title=prior.get("title", Path(info["directory"]).name),
                     kind="existing", selection=str(selection), directory=info["directory"],
                     program="", arguments="", engine=info["engine"],
                     volume=str(mount_point(info["directory"])))
        entry["title"] = self.display_title(entry)
        self.save_entry(entry)
        return entry

    def settings(self, name):
        defaults = read_settings(self.config / "defaults")
        own = read_settings(self.config / "games" / name)
        # As cfg_wayland_x11: split display goes with the file that chose the display.
        if own.keys() & {"wayland", "gamescope", "host_x11"}:
            defaults.pop("wayland_x11", None)
        return {**defaults, **own}

    def scope_settings(self, name, defaults=False):
        """One file's own values, for editors that write back to that file."""
        self.capture(name)
        return read_settings(self.config / "defaults" if defaults else self.config / "games" / name)

    def update_settings(self, name, changes, defaults=False):
        self.capture(name)
        path = self.config / "defaults" if defaults else self.config / "games" / name
        values = read_settings(path)
        for key, value in changes.items():
            if not re.fullmatch(r"[a-z][a-z_0-9]*", key) or not isinstance(value, str) \
                    or any(c in value for c in "\r\n\0"):
                raise ValueError("Settings cannot contain line breaks")
            values[key] = value
        atomic_write(path, "# sandbox-game preferences\n" + "".join(
            f"{key}={value}\n" for key, value in values.items()))

    def shared(self, name, function, *args):
        """Run sandbox-game-lib code, so preferences mean what they do in the file manager."""
        self.capture(name)
        script = ('set -uo pipefail\n. "$1/sandbox-game-lib"\n'
                  'CFGDIR="$2" NAME="$3" SANDBOX="$4"\nshift 4\n' + function)
        return subprocess.run(["bash", "-c", script, "shared", str(self.helpers), str(self.config), name,
                               str(self.backend), *args], stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, errors="replace", timeout=20)

    def save_preferences(self, name, result):
        saved = self.shared(name, 'prefs_save "$1"', json.dumps(result))
        if saved.returncode:
            raise ValueError(saved.stderr.strip() or "Cannot save preferences")

    def protons(self):
        result = subprocess.run([str(self.backend), "--list-proton"], capture_output=True,
                                check=True, text=True, timeout=10)
        return result.stdout.splitlines()

    def running(self):
        """Ask the existing namespace-aware process scanner, never trust metadata."""
        attach = self.backend.with_name("sandbox-attach")
        result = subprocess.run([str(attach), "--list"], capture_output=True, text=True,
                                check=True, timeout=10)
        return {line.split()[0] for line in result.stdout.splitlines()[1:] if line.split()}

    def flags(self, entry):
        """The file-manager launcher's own translation, for a program run under Proton."""
        result = self.shared(entry["name"], 'GAMEDIR="$1" APPDIR="" PROTON=1 MKXP=0 PGMMV=0 ALLOW_MANGOHUD=1\n'
                             'pref_flags\nprintf "%s\\0" "${FLAG[@]}"\n', entry.get("directory", ""))
        if result.returncode:
            raise ValueError(result.stderr.strip() or "Cannot read this sandbox's settings")
        return [str(self.backend), *result.stdout.split("\0")[:-1]]

    def user_dirs(self):
        """{"DESKTOP": path, ...} as set in user-dirs.dirs."""
        try:
            text = (Path(os.environ.get("XDG_CONFIG_HOME") or self.home / ".config") / "user-dirs.dirs") \
                .read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        folders = {}
        for match in re.finditer(r'^\s*XDG_([A-Z]+)_DIR="([^"\n]*)"', text, re.M):
            value = match[2]
            if value.startswith("$HOME"):
                value = str(self.home.resolve()) + value[len("$HOME"):]
            if value.startswith("/"):
                folders[match[1]] = Path(value)
        return folders

    def shared_folder(self, folder):
        """Folders that collect unrelated files: home, its parents and the XDG user folders."""
        folder = folder.resolve()
        home = self.home.resolve()
        if home.is_relative_to(folder) or folder in (Path("/tmp"), Path("/var/tmp")):
            return True
        folders = {home / name for name in ("Desktop", "Documents", "Downloads", "Music", "Pictures",
                                            "Public", "Templates", "Videos")}
        folders.update(self.user_dirs().values())
        return any(folder == path.resolve() for path in folders)

    def desktop_folder(self):
        """The desktop folder, or None without one. Never created here: a
        desktop set to home, as user-dirs.dirs turns it off, is none either."""
        folder = self.desktop or self.user_dirs().get("DESKTOP", self.home / "Desktop")
        try:
            if folder.is_dir() and folder.resolve() != self.home.resolve():
                return folder
        except OSError:
            pass
        return None

    def shortcut_path(self, name, where):
        self.capture(name)
        if where == "menu":
            return self.data / "applications" / f"sandbox-game-{name}.desktop"
        if where == "desktop":
            folder = self.desktop_folder()
            if folder is None:
                raise ValueError("There is no desktop folder to place a shortcut in")
            return folder / f"sandbox-game-{name}.desktop"
        raise ValueError("Unknown shortcut location")

    def shortcuts(self, name):
        """{"menu": bool, "desktop": bool}: which shortcuts to this sandbox exist."""
        found = {}
        for where in self.SHORTCUTS:
            try:
                found[where] = self.shortcut_path(name, where).is_file()
            except ValueError:
                found[where] = False
        return found

    def shortcut_text(self, entry, icon=None):
        manager = self.backend.with_name("sandbox-manager")
        return "".join(line + "\n" for line in (
            "[Desktop Entry]", "Type=Application",
            "Name=" + desktop_string(entry["title"]),
            "Comment=Play in its sandbox",
            "Exec=" + desktop_exec_argument(str(manager)) + " --launch " + entry["name"],
            # Hidden from menus once the manager is uninstalled.
            "TryExec=" + desktop_string(str(manager)),
            "Icon=" + desktop_string(str(icon) if icon else "applications-games"),
            "Terminal=false", "Categories=Game;"))

    def write_shortcut(self, path, text, where):
        if path.is_file() and not path.is_symlink() and path.read_text(encoding="utf-8", errors="replace") == text:
            return
        # Desktops start only executable launchers there, GNOME's only trusted ones too.
        atomic_write(path, text, mode=0o755 if where == "desktop" else 0o644)
        if where == "desktop":
            try:
                subprocess.run(["gio", "set", "--", str(path), "metadata::trusted", "true"],
                               stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
            except (OSError, subprocess.SubprocessError):
                pass

    def set_shortcut(self, name, where, enabled, icon=None):
        path = self.shortcut_path(name, where)
        if enabled:
            self.write_shortcut(path, self.shortcut_text(self.entry(name), icon), where)
        else:
            path.unlink(missing_ok=True)

    def refresh_shortcuts(self, entry, icon=None):
        """Keep existing shortcuts' names and icons as the library shows them."""
        for where, present in self.shortcuts(entry["name"]).items():
            if present:
                self.write_shortcut(self.shortcut_path(entry["name"], where),
                                    self.shortcut_text(entry, icon), where)

    def remove_shortcuts(self, name):
        for where, present in self.shortcuts(name).items():
            if present:
                self.shortcut_path(name, where).unlink(missing_ok=True)

    def installer_binds(self, installer):
        """Read-only installer media, never a whole home or downloads folder."""
        folder = installer.parent
        if not self.shared_folder(folder):
            return ["--ro", str(folder), "/installer"]
        # Only the installer and the files installers are known to need beside
        # them: split archives (setup-1.bin) and an MSI's external cabinets.
        parts = re.compile(re.escape(installer.stem) + r"-\d+\.bin", re.I)
        binds = []
        for path in sorted(folder.iterdir()):
            if path != installer and not parts.fullmatch(path.name) and not (
                    installer.suffix.lower() == ".msi" and path.suffix.lower() == ".cab"):
                continue
            if path.is_symlink() or not path.is_file():
                continue
            binds += ["--ro", str(path), "/installer/" + path.name]
        return binds

    def command(self, entry, installer=None, tool=None, program=None):
        if entry["kind"] == "existing" and not installer and not tool and not program:
            selection = Path(entry["selection"])
            if not entry["selection"] or not selection.exists():
                raise ValueError("The game folder is missing. Use Locate game to reconnect it.")
            return [str(self.launcher)], {**os.environ,
                "NAUTILUS_SCRIPT_SELECTED_FILE_PATHS": str(selection),
                "SANDBOX_BACKEND": str(self.backend),
                "SANDBOX_GAME_NAME": entry["name"]}
        flags = self.flags(entry)
        # Proton's steam.exe (the Steam setting) waits only for a command
        # ending in .exe; anything else it hands to ShellExecute and returns
        # at once, and Proton, then the sandbox, exits with the program barely
        # started. Plain Wine, without that setting, waits for either.
        if installer is not None:
            installer = Path(installer).resolve(strict=True)
            if not installer.is_file() or installer.suffix.lower() not in (".exe", ".msi"):
                raise ValueError("Select a Windows .exe or .msi installer")
            # Installer media stay read-only; all installed files go into this sandbox.
            flags += self.installer_binds(installer)
            target = "/installer/" + installer.name
            command = ["msiexec.exe", "/i", target] if installer.suffix.lower() == ".msi" else [target]
        elif tool:
            if tool not in ("winecfg", "regedit", "cmd"):
                raise ValueError("Unknown Wine tool")
            # cmd would inherit steam.exe's console, which is the launch log
            # with nothing to read; wineconsole gives it a window and waits.
            command = ["wineconsole.exe", "cmd.exe"] if tool == "cmd" else [tool + ".exe"]
        else:
            target = program or entry.get("program", "")
            if not target:
                raise ValueError("Choose the installed game or launcher on the Programs page first")
            self.program_host(entry, target)
            command = [target, *shlex.split(entry.get("arguments", ""))]
        return [*flags, "--", entry["directory"], *command], None

    def windows_drive(self, name):
        """The prefix's C: drive, only as a real folder: games can replace any part of the path."""
        path = self.capture(name)
        for part in ("compat", "pfx", "drive_c"):
            path = path / part
            if path.is_symlink():
                raise ValueError("The Windows drive is not a folder in this sandbox")
            if not path.is_dir():
                raise ValueError("This sandbox has no Windows drive yet")
        return path

    def program_host(self, entry, program):
        """Translate only files actually exposed as this sandbox's game or C: drive."""
        capture = self.capture(entry["name"])
        if program.startswith("/compat/pfx/drive_c/"):
            root = self.windows_drive(entry["name"])
            relative = program[len("/compat/pfx/drive_c/"):]
            candidates = [(root, root / relative)]
        elif program.startswith("/game/"):
            relative = program[len("/game/"):]
            candidates = [(root, root / relative) for root in
                          (capture / "rw", Path(entry["directory"]))]
        else:
            raise ValueError("Select a program inside this sandbox")
        if ".." in Path(relative).parts or Path(relative).is_absolute():
            raise ValueError("Select a program inside this sandbox")
        for root, path in candidates:
            if path.is_file() and path.resolve().is_relative_to(root.resolve()):
                return path
            if path.exists():  # a whiteout or directory also hides the lower file
                break
        raise ValueError("The selected program no longer exists in this sandbox")

    def programs(self, entry):
        capture = self.capture(entry["name"])
        roots = [(Path(entry["directory"]), "/game"), (capture / "rw", "/game")]
        try:
            roots.insert(0, (self.windows_drive(entry["name"]), "/compat/pfx/drive_c"))
        except ValueError:
            pass
        found = {}
        for root, prefix in roots:
            if not root.is_dir():
                continue
            if root == capture / "rw" and not root.resolve().is_relative_to(capture.resolve()):
                continue
            for folder, dirs, files in os.walk(root, followlinks=False):
                dirs[:] = [d for d in dirs if d.lower() not in
                           ("windows", "$recycle.bin", "system volume information")]
                for filename in files:
                    if not filename.lower().endswith(".exe"):
                        continue
                    path = Path(folder) / filename
                    relative = path.relative_to(root).as_posix()
                    target = prefix + "/" + relative
                    try:
                        self.program_host(entry, target)
                    except ValueError:
                        continue
                    found[target] = ("C:\\" + relative.replace("/", "\\")) \
                        if prefix.startswith("/compat") else relative
        return sorted(found.items(), key=lambda pair: (
            bool(re.search(r"unins|crash|redist|setup|install|helper", pair[1], re.I)),
            pair[1].casefold()))

    def start(self, entry, **kwargs):
        if entry["name"] in self.running():
            raise ValueError("This sandbox is running. Stop it before starting another program.")
        command, env = self.command(entry, **kwargs)
        if command == [str(self.launcher)]:
            # The file-manager launcher writes this same log itself.
            return subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, start_new_session=True)
        path = self.log_path(entry["name"])
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as log:
            return subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL,
                                    stdout=log, stderr=subprocess.STDOUT, start_new_session=True)

    def log_path(self, name):
        return self.capture(name) / "lastrun.log"

    def old_log_path(self, name):
        """Beside the folder, where launches before logs moved into it left them."""
        self.capture(name)
        return self.root / (name + "-lastrun.log")

    def read_log(self, name):
        path = self.log_path(name)
        if not path.exists():
            path = self.old_log_path(name)
        try:
            with path.open("rb") as stream:
                stream.seek(0, 2)
                size = stream.tell()
                stream.seek(max(0, size - 256 * 1024))
                return stream.read().decode("utf-8", errors="replace")
        except FileNotFoundError:
            return "No launch log yet."

    def stats(self, name):
        total = last = 0
        try:
            for line in (self.capture(name) / "playtime").read_text().splitlines():
                start, seconds = map(int, line.split())
                total += seconds
                last = max(last, start + seconds)
        except (OSError, ValueError):
            pass
        return total, last

    def operate(self, name, operation):
        self.capture(name)
        if operation not in ("stop", "delete", "reset-install"):
            raise ValueError("Unknown sandbox operation")
        result = subprocess.run([str(self.backend), "--" + operation, name],
                                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                errors="replace", timeout=40)
        if result.returncode:
            raise ValueError(result.stderr.strip() or result.stdout.strip() or "Operation failed")
        if operation == "delete":
            self.remove_shortcuts(name)
        return result.stdout
