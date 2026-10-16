"""Library, preferences and process operations for the desktop manager.

No GTK imports here: every game and installer still runs through sandbox-game.
Metadata lives outside the writable mounts handed to games.
"""
import json
import os
import re
import shlex
import subprocess
import tempfile
from pathlib import Path


NAME = re.compile(r"[A-Za-z0-9._-]+")


def valid_name(name):
    return bool(NAME.fullmatch(name)) and name not in (".", "..")


def read_json(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def atomic_write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".manager-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(text)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


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


class Library:
    def __init__(self, backend, helpers, launcher, home=None, config=None):
        self.backend = Path(backend)
        self.helpers = Path(helpers)
        self.launcher = Path(launcher)
        self.home = Path(home) if home is not None else Path.home()
        self.root = self.home / "game-sandboxes"
        self.config = Path(config) if config is not None else Path(
            os.environ.get("XDG_CONFIG_HOME") or self.home / ".config") / "sandbox-game"

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
        entries = []
        for capture in self.root.iterdir():
            if not capture.is_dir() or capture.is_symlink() or not valid_name(capture.name):
                continue
            entry = read_json(capture / "manager.json")
            source = read_json(capture / "source.json")
            # Defaults also make captures created before the manager visible.
            entry.update(name=capture.name, title=str(entry.get("title", capture.name)))
            entry.setdefault("kind", "existing")
            entry.setdefault("selection", source.get("directory", ""))
            entry.setdefault("directory", source.get("directory", ""))
            entry.setdefault("program", "")
            entry.setdefault("arguments", "")
            entries.append(entry)
        return sorted(entries, key=lambda entry: entry["title"].casefold())

    def save_entry(self, entry):
        if entry.get("kind") not in ("windows", "existing"):
            raise ValueError("Unknown sandbox type")
        for key in ("name", "title", "directory", "selection", "program", "arguments"):
            if not isinstance(entry.get(key, ""), str) or "\0" in entry.get(key, ""):
                raise ValueError(f"Invalid {key}")
        if not entry["title"].strip():
            raise ValueError("Give the sandbox a name")
        shlex.split(entry.get("arguments", ""))
        atomic_write(self.capture(entry["name"]) / "manager.json",
                     json.dumps(entry, ensure_ascii=False, indent=2) + "\n")

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
            # --delete keeps a sandbox's preferences, and its log stays too:
            # a new sandbox must not pick up either under a reused name.
            if (self.config / "games" / name).exists() or self.log_path(name).exists():
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
        entry = dict(name=name, title=prior.get("title", Path(info["directory"]).name),
                     kind="existing", selection=str(selection), directory=info["directory"],
                     program="", arguments="", engine=info["engine"])
        self.save_entry(entry)
        return entry

    def settings(self, name):
        return {**read_settings(self.config / "defaults"),
                **read_settings(self.config / "games" / name)}

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

    def shared_folder(self, folder):
        """Folders that collect unrelated files: home, its parents and the XDG user folders."""
        folder = folder.resolve()
        home = self.home.resolve()
        if home.is_relative_to(folder) or folder in (Path("/tmp"), Path("/var/tmp")):
            return True
        folders = {home / name for name in ("Desktop", "Documents", "Downloads", "Music", "Pictures",
                                            "Public", "Templates", "Videos")}
        try:
            text = (Path(os.environ.get("XDG_CONFIG_HOME") or self.home / ".config") / "user-dirs.dirs") \
                .read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        for match in re.finditer(r'^\s*XDG_[A-Z]+_DIR="([^"\n]*)"', text, re.M):
            value = match[1]
            if value.startswith("$HOME"):
                value = str(home) + value[len("$HOME"):]
            if value.startswith("/"):
                folders.add(Path(value))
        return any(folder == path.resolve() for path in folders)

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
            if not selection.exists():
                raise ValueError("The game folder is missing. Use Locate game to reconnect it.")
            return [str(self.launcher)], {**os.environ,
                "NAUTILUS_SCRIPT_SELECTED_FILE_PATHS": str(selection),
                "SANDBOX_BACKEND": str(self.backend),
                "SANDBOX_GAME_NAME": entry["name"]}
        flags = self.flags(entry)
        if installer is not None:
            installer = Path(installer).resolve(strict=True)
            if not installer.is_file() or installer.suffix.lower() not in (".exe", ".msi"):
                raise ValueError("Select a Windows .exe or .msi installer")
            # Installer media stay read-only; all installed files go into this sandbox.
            flags += self.installer_binds(installer)
            target = "/installer/" + installer.name
            command = ["msiexec", "/i", target] if installer.suffix.lower() == ".msi" else [target]
        elif tool:
            if tool not in ("winecfg", "regedit", "cmd"):
                raise ValueError("Unknown Wine tool")
            command = [tool]
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
        self.capture(name)
        return self.root / (name + "-lastrun.log")

    def read_log(self, name):
        try:
            with self.log_path(name).open("rb") as stream:
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
        return result.stdout
