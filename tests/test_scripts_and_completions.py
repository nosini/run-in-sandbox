#!/usr/bin/env python3
"""Regression tests for the Nautilus scripts, install.sh, get-satellite.sh,
nwjs-casefold.js and the shell completions.

Run on the host: python3 -m unittest tests.test_scripts_and_completions -v
"""
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAFE_PATH = "/usr/bin:/bin"


def read(name):
    return (ROOT / name).read_text(encoding="utf-8")


def shell_function(name, path):
    """The top-level bash function $name as written in $path."""
    match = re.search(rf"^{re.escape(name)}\(\) \{{.*?^\}}\n",
                      read(path), re.M | re.S)
    if not match:
        raise AssertionError(f"function {name} not found in {path}")
    return match.group(0)


class ScriptTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="sandbox-scripts-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)

    def write_exec(self, path, body):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        path.chmod(0o755)
        return path

    def game_home(self):
        """A throwaway HOME with a game folder and the shared library."""
        home = self.base / "home"
        game = home / "game"
        game.mkdir(parents=True)
        helpers = home / ".local" / "lib" / "sandbox-game"
        helpers.mkdir(parents=True)
        (helpers / "sandbox-game-lib").symlink_to(ROOT / "sandbox-game-lib")
        return home, game.resolve()

    def backend(self):
        """A sandbox-game stand-in that records how it was called."""
        record = self.base / "record"
        backend = self.write_exec(self.base / "backend", f"""#!/bin/bash
printf '%s\\n' "$*" >> {shlex.quote(str(record))}
[ "$1" != --print-name ] || printf '%s\\n' "${{FAKE_NAME:-derived}}"
exit 0
""")
        return backend, record

    def dialog(self, rc):
        return self.write_exec(self.base / "dialog", f"""#!/bin/bash
case "${{1:-}}" in
    pick|preferences) cat >/dev/null 2>&1 || true ;;
esac
exit {rc}
""")

    def script_env(self, home, **extra):
        env = {**os.environ,
               "HOME": str(home),
               "PATH": SAFE_PATH,
               "XDG_CONFIG_HOME": str(home / ".config"),
               "XDG_DATA_HOME": str(home / ".local" / "share")}
        env.pop("SANDBOX_BACKEND", None)
        env.pop("SANDBOX_GAME_NAME", None)
        env.pop("SANDBOX_DIALOG", None)
        env.update({key: str(value) for key, value in extra.items()})
        return env


class NautilusScriptTests(ScriptTestCase):
    def test_pick_cancels_quietly_but_reports_a_dialog_failure(self):
        harness = self.base / "pick.sh"
        harness.write_text(
            "die() { printf 'DIE:%s\\n' \"$1\" >&2; exit 1; }\n"
            "dialog() { cat >/dev/null; exit \"${DIALOG_RC:-0}\"; }\n"
            + shell_function("pick", "Sandbox game")
            + '\nif pick "$@"; then printf "PICKED=<%s>\\n" "$PICKED";'
              ' else printf "CANCELLED\\n"; fi\n',
            encoding="utf-8")

        def run(*args, rc=0):
            env = {**os.environ, "DIALOG_RC": str(rc), "PATH": SAFE_PATH}
            return subprocess.run(["bash", str(harness), *args], env=env,
                                  capture_output=True, text=True)

        chosen = run("/games", "/games/one")
        self.assertEqual(chosen.returncode, 0)
        self.assertEqual(chosen.stdout, "PICKED=</games/one>\n")

        cancelled = run("/games", "/games/a", "/games/b", rc=1)
        self.assertEqual(cancelled.returncode, 0)
        self.assertEqual(cancelled.stdout, "CANCELLED\n")
        self.assertEqual(cancelled.stderr, "")

        broken = run("/games", "/games/a", "/games/b", rc=2)
        self.assertNotEqual(broken.returncode, 0)
        self.assertEqual(broken.stdout, "")
        self.assertIn("Cannot show the launcher picker", broken.stderr)

        # The callers must carry the picker's status, not turn a failure into
        # "nothing chosen" and exit 0.
        game = read("Sandbox game")
        self.assertNotIn('LAUNCHER="$(pick', game)
        self.assertEqual(game.count('pick "$GAMEDIR"'), 3)
        self.assertEqual(game.count("LAUNCHER=\"$PICKED\""), 3)

    def test_preferences_and_stop_honour_backend_and_game_name(self):
        home, game = self.game_home()
        backend, record = self.backend()

        prefs = subprocess.run(
            [str(ROOT / "Sandbox game preferences")],
            env=self.script_env(home, SANDBOX_BACKEND=backend,
                                SANDBOX_GAME_NAME="custom",
                                SANDBOX_DIALOG=self.dialog(1),
                                NAUTILUS_SCRIPT_SELECTED_FILE_PATHS=str(game) + "\n"),
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
        self.assertEqual(prefs.returncode, 0, prefs.stderr)
        lines = record.read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines[0], f"--print-name --name custom {game}")
        record.unlink()

        stop = subprocess.run(
            [str(ROOT / "Stop sandboxed game")],
            env=self.script_env(home, SANDBOX_BACKEND=backend,
                                SANDBOX_GAME_NAME="custom",
                                SANDBOX_DIALOG=self.dialog(0),
                                NAUTILUS_SCRIPT_SELECTED_FILE_PATHS=str(game) + "\n"),
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
        self.assertEqual(stop.returncode, 0, stop.stderr)
        lines = record.read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines[0], f"--print-name --name custom {game}")
        self.assertEqual(lines[1], "--stop derived")
        record.unlink()

        # Without the override the name still comes from the folder.
        stop = subprocess.run(
            [str(ROOT / "Stop sandboxed game")],
            env=self.script_env(home, SANDBOX_BACKEND=backend,
                                SANDBOX_DIALOG=self.dialog(0),
                                NAUTILUS_SCRIPT_SELECTED_FILE_PATHS=str(game) + "\n"),
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
        self.assertEqual(stop.returncode, 0, stop.stderr)
        lines = record.read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines[0], f"--print-name {game}")
        self.assertEqual(lines[1], "--stop derived")

    def test_die_prints_filenames_without_escape_processing(self):
        name = r"a\nb\tc\\d%s"
        for script in ("Sandbox game", "Sandbox game preferences",
                       "Stop sandboxed game"):
            with self.subTest(script=script):
                harness = ("notify-send() { :; }\n"
                           + shell_function("die", script)
                           + '\ndie "$1"\n')
                result = subprocess.run(
                    ["bash", "-c", harness, "die-test", name],
                    env={**os.environ, "PATH": SAFE_PATH},
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr, name + "\n")
                self.assertEqual(result.stdout, "")


class InstallCleanupTests(ScriptTestCase):
    def test_one_exit_trap_cleans_the_download_and_selinux_trees(self):
        source = read("install.sh")
        self.assertEqual(len(re.findall(r"(?m)^trap\b", source)), 1)
        self.assertIn("trap cleanup_tmp EXIT", source)
        self.assertNotIn('trap \'rm -rf', source)
        self.assertRegex(source,
                         r'TMP="\$\(mktemp -d\)"; CLEANUP_DIRS\+=\("\$TMP"\)')
        self.assertRegex(source,
                         r'BUILD="\$\(mktemp -d\)"; CLEANUP_DIRS\+=\("\$BUILD"\)')

        start = source.index("CLEANUP_DIRS=()")
        end = source.index("trap cleanup_tmp EXIT") + len("trap cleanup_tmp EXIT")
        dirs = self.base / "dirs"
        harness = "set -euo pipefail\n" + source[start:end] + textwrap.dedent(f"""

            TMP="$(mktemp -d {shlex.quote(str(self.base / 'tmp.XXXXXX'))})"
            CLEANUP_DIRS+=("$TMP")
            BUILD="$(mktemp -d {shlex.quote(str(self.base / 'build.XXXXXX'))})"
            CLEANUP_DIRS+=("$BUILD")
            printf '%s\\n%s\\n' "$TMP" "$BUILD" > {shlex.quote(str(dirs))}
            """)
        result = subprocess.run(["bash", "-c", harness], capture_output=True,
                                text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        made = [Path(line) for line in dirs.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(made), 2)
        for path in made:
            self.assertFalse(path.exists(), f"{path} was left behind")


class SatelliteTests(ScriptTestCase):
    def satellite_copy(self, text=None):
        root = self.base / "root"
        root.mkdir()
        script = root / "get-satellite.sh"
        script.write_text(text if text is not None else read("get-satellite.sh"),
                          encoding="utf-8")
        return root, script

    def satellite_stubs(self, commit='7fac1ea497ca248c6b0032efcbd55dbd98b47925'):
        stubbin = self.base / "bin"
        stubbin.mkdir()
        self.write_exec(stubbin / "pkg-config", "#!/bin/bash\nexit 0\n")
        self.write_exec(stubbin / "clang", "#!/bin/bash\nexit 0\n")
        self.write_exec(stubbin / "cargo", """#!/bin/bash
mkdir -p "$CARGO_TARGET_DIR/release"
printf 'binary\\n' > "$CARGO_TARGET_DIR/release/xwayland-satellite"
""")
        mark = self.base / "checked-out"
        log = self.base / "git.log"
        self.write_exec(stubbin / "git", f"""#!/bin/bash
printf '%s\\n' "$*" >> {shlex.quote(str(log))}
case "$*" in
    *" rev-parse FETCH_HEAD")
        printf '%s\\n' "${{FAKE_REV:-{commit}}}" ;;
    *" checkout "*)
        [ -z {shlex.quote(str(mark))} ] || : > {shlex.quote(str(mark))}
        work=""
        previous=""
        for argument in "$@"; do
            [ "$previous" != -C ] || work=$argument
            previous=$argument
        done
        [ -z "$work" ] || printf 'licence\\n' > "$work/LICENSE" ;;
esac
exit 0
""")
        return stubbin, mark, log

    def test_fetched_commit_is_checked_before_checkout(self):
        stubbin, mark, log = self.satellite_stubs()
        _, script = self.satellite_copy()
        env = {**os.environ, "PATH": str(stubbin) + ":" + SAFE_PATH,
               "FAKE_REV": "0" * 40,
               "SATELLITE_BUILD_DIR": str(self.base / "build")}
        result = subprocess.run(["bash", str(script), "--from-source"], env=env,
                                capture_output=True, text=True, timeout=60)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Fetched source is not commit", result.stderr)
        self.assertFalse(mark.exists(), "git checkout ran before the commit check")
        self.assertNotIn("checkout", log.read_text(encoding="utf-8"))

    def test_source_build_checks_out_with_hooks_disabled(self):
        stubbin, mark, log = self.satellite_stubs()
        root, script = self.satellite_copy()
        env = {**os.environ, "PATH": str(stubbin) + ":" + SAFE_PATH,
               "SATELLITE_BUILD_DIR": str(self.base / "build")}
        result = subprocess.run(["bash", str(script), "--from-source"], env=env,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(mark.exists())
        checkout = [line for line in log.read_text(encoding="utf-8").splitlines()
                    if " checkout " in line]
        self.assertEqual(len(checkout), 1)
        self.assertIn("core.hooksPath=/dev/null", checkout[0])
        self.assertTrue((root / "sandbox-xwayland-satellite").exists())
        self.assertTrue((root / "satellite-LICENSE").exists())

    def test_downloaded_hash_is_taken_from_the_file_itself(self):
        asset = b"satellite payload\n"
        text = read("get-satellite.sh")
        digest = hashlib.sha256(asset).hexdigest()
        text = re.sub(r"(?m)^SHA256=.*$", f"SHA256={digest}", text)
        self.assertNotIn("sha256sum --check", text)
        root, script = self.satellite_copy(text)

        stubbin = self.base / "bin"
        stubbin.mkdir()
        asset_file = self.base / "asset"
        asset_file.write_bytes(asset)
        self.write_exec(stubbin / "curl", f"""#!/bin/bash
out=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) out=$2; shift 2 ;;
        *) shift ;;
    esac
done
cat {shlex.quote(str(asset_file))} > "$out"
""")
        commit = re.search(r"(?m)^COMMIT=(\S+)$", text).group(1)
        self.write_exec(stubbin / "tar", f"""#!/bin/bash
destination=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -C) destination=$2; shift 2 ;;
        *) shift ;;
    esac
done
mkdir -p "$destination/xwayland-satellite"
printf '%s\\n' {shlex.quote(commit)} > "$destination/xwayland-satellite/COMMIT"
printf 'licence\\n' > "$destination/xwayland-satellite/LICENSE"
printf 'binary\\n' > "$destination/xwayland-satellite/xwayland-satellite"
""")

        # A backslash and a newline in the work directory used to split the
        # "hash  filename" line that sha256sum --check read.
        build = self.base / "build\\slash\nnewline"
        env = {**os.environ, "PATH": str(stubbin) + ":" + SAFE_PATH,
               "SATELLITE_BUILD_DIR": str(build)}
        result = subprocess.run(["bash", str(script)], env=env,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Installed", result.stdout)
        self.assertTrue((root / "sandbox-xwayland-satellite").exists())
        self.assertTrue((root / "satellite-LICENSE").exists())


class CasefoldTests(ScriptTestCase):
    HARNESS = r"""
const real = require("fs");
const path = require("path");
const url = require("url");
const util = require("util");
const vm = require("vm");
const os = require("os");

const source = real.readFileSync(process.argv[2], "utf8");
const root = real.mkdtempSync(path.join(os.tmpdir(), "casefold-test-"));
process.on("exit", () => real.rmSync(root, { recursive: true, force: true }));
real.mkdirSync(path.join(root, "img/pictures"), { recursive: true });
real.writeFileSync(path.join(root, "img/pictures/b.png"), "PNGDATA");
real.mkdirSync(path.join(root, "save"));
real.writeFileSync(path.join(root, "save/Old.sav"), "OLD");

const seen = [];
const fake = {};
for (const name of ["existsSync", "readdirSync", "readFileSync", "writeFileSync",
                    "mkdirSync", "openSync", "statSync", "lstatSync", "accessSync",
                    "realpathSync", "readlinkSync", "opendirSync",
                    "createReadStream", "watch", "watchFile", "unwatchFile",
                    "exists", "access", "stat", "lstat", "readFile", "readdir",
                    "realpath", "readlink", "opendir", "open", "writeFile",
                    "appendFileSync", "appendFile", "mkdir", "createWriteStream",
                    "unlinkSync", "unlink", "rmSync", "rm", "rmdirSync", "rmdir",
                    "truncateSync", "truncate", "chmodSync", "chmod",
                    "utimesSync", "utimes", "copyFileSync", "copyFile", "cpSync",
                    "cp", "linkSync", "link", "renameSync", "rename",
                    "symlinkSync", "symlink"]) {
    if (typeof real[name] === "function") fake[name] = real[name].bind(real);
}
fake.constants = real.constants;
fake.promises = {};
fake.readFileSync = function (...args) {
    seen.push(args[0]);
    return real.readFileSync(...args);
};
fake.exists = function (p, callback) { real.exists(p, callback); };
Object.defineProperty(fake.exists, util.promisify.custom, {
    value: (p) => new Promise((resolve) => fake.exists(p, resolve)),
});
let throwWrite = false;
fake.writeFileSync = function (...args) {
    if (throwWrite) {
        real.writeFileSync(...args);
        throw new Error("partial write");
    }
    return real.writeFileSync(...args);
};

const context = {
    require: (id) => id === "fs" ? fake : id === "path" ? path
                 : id === "url" ? url : id === "util" ? util : require(id),
    nw: { __dirname: root },
    location: { protocol: "chrome-extension:", host: "abc" },
    document: { baseURI: "chrome-extension://abc/" },
    process, Buffer, URL, Promise, Symbol, Map, Set, JSON, console,
    globalThis: null,
};
context.globalThis = context;
vm.createContext(context);
vm.runInContext(source, context);

(async () => {
    const result = {};
    const wrong = path.join(root, "img/pictures/B.png");
    result.bufferContent = fake.readFileSync(Buffer.from(wrong)).toString();
    result.bufferStaysBuffer = Buffer.isBuffer(seen[seen.length - 1]);
    result.bufferResolved = path.relative(root, seen[seen.length - 1].toString());

    const fileUrl = url.pathToFileURL(path.join(root, "img/pictures/B.PNG"));
    result.urlContent = fake.readFileSync(fileUrl).toString();
    result.urlStaysUrl = seen[seen.length - 1] instanceof URL;
    result.urlResolved = path.relative(root, url.fileURLToPath(seen[seen.length - 1]));

    const other = new URL("https://example.com/x");
    try { fake.readFileSync(other); } catch (error) {
        result.nonFileError = error.code;
    }
    result.nonFileUntouched = seen[seen.length - 1] === other;

    result.promisified = await Promise.all([
        util.promisify(fake.exists)(path.join(root, "img/pictures/b.png")),
        util.promisify(fake.exists)(new URL("file://" + path.join(root, "none"))),
    ]);

    try { fake.readFileSync(path.join(root, "save/OLD.sav")); } catch (_) {}
    throwWrite = true;
    try { fake.writeFileSync(path.join(root, "save/NEW.sav"), "NEW"); }
    catch (_) { result.writeThrew = true; }
    throwWrite = false;
    try {
        result.recovered = fake.readFileSync(path.join(root, "save/New.SAV")).toString();
    } catch (error) {
        result.recovered = "ERR:" + error.code;
    }
    console.log(JSON.stringify(result));
})().catch((error) => { console.error(error); process.exit(1); });
"""

    def test_buffer_file_url_promisify_and_throwing_write(self):
        if not shutil.which("node"):
            self.skipTest("node is unavailable")
        harness = self.base / "harness.js"
        harness.write_text(self.HARNESS, encoding="utf-8")
        result = subprocess.run(["node", str(harness), str(ROOT / "nwjs-casefold.js")],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        got = json.loads(result.stdout)
        self.assertEqual(got["bufferContent"], "PNGDATA")
        self.assertTrue(got["bufferStaysBuffer"])
        self.assertEqual(got["bufferResolved"], "img/pictures/b.png")
        self.assertEqual(got["urlContent"], "PNGDATA")
        self.assertTrue(got["urlStaysUrl"])
        self.assertEqual(got["urlResolved"], "img/pictures/b.png")
        self.assertEqual(got["nonFileError"], "ERR_INVALID_URL_SCHEME")
        self.assertTrue(got["nonFileUntouched"])
        self.assertEqual(got["promisified"], [True, False])
        self.assertTrue(got["writeThrew"])
        self.assertEqual(got["recovered"], "NEW")

    def test_unused_inside_helper_is_gone(self):
        self.assertNotIn("function inside(", read("nwjs-casefold.js"))


class CompletionTests(ScriptTestCase):
    def setUp(self):
        super().setUp()
        self.home = self.base / "home"
        self.cwd = self.base / "cwd"
        (self.home / "game-sandboxes" / "mygame").mkdir(parents=True)
        (self.cwd / "-gamedir").mkdir(parents=True)
        (self.cwd / "-gamedir" / "-cmd").write_text("", encoding="utf-8")
        (self.cwd / "~otheruser" / "game" / "gamedata").mkdir(parents=True)
        (self.home / "game-sandboxes" / "mygame" / "gamedata").mkdir()

    def complete(self, file, command, *words):
        script = f"""
            source {shlex.quote(str(ROOT / "completions" / file))}
            _init_completion() {{
                cur=${{COMP_WORDS[COMP_CWORD]}}
                prev=${{COMP_WORDS[COMP_CWORD-1]}}
                words=("${{COMP_WORDS[@]}}")
                cword=$COMP_CWORD
                return 0
            }}
            _filedir() {{
                local arg=${{1-}}
                if [[ $arg == -d ]]; then
                    COMPREPLY=($(compgen -d -- "$cur"))
                else
                    COMPREPLY=($(compgen -f -- "$cur"))
                fi
            }}
            COMP_WORDS=("$@")
            COMP_CWORD=$(( ${{#COMP_WORDS[@]}} - 1 ))
            COMP_LINE="${{COMP_WORDS[*]}}"; COMP_POINT=${{#COMP_LINE}}
            {command} "${{COMP_WORDS[COMP_CWORD]}}" "${{COMP_WORDS[COMP_CWORD-1]}}"
            if (( ${{#COMPREPLY[@]}} )); then
                printf '%s\\n' "${{COMPREPLY[@]}}"
            fi
        """
        result = subprocess.run(
            ["bash", "-c", script, "complete", *words],
            cwd=self.cwd,
            env={**os.environ, "HOME": str(self.home), "PATH": SAFE_PATH},
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.splitlines()

    def test_completion_init_receives_the_function_arguments(self):
        script = """
            _comp_initialize() { printf '%s\\n' "$@"; }
            source "$1"
            _sandbox_game_init alpha beta gamma
        """
        result = subprocess.run(
            ["bash", "-c", script, "init",
             str(ROOT / "completions/sandbox-game")],
            env={**os.environ, "PATH": SAFE_PATH}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(),
                         ["-s", "--", "alpha", "beta", "gamma"])

        script = """
            _init_completion() { printf '%s\\n' "$@"; }
            source "$1"
            _sandbox_game_init alpha beta gamma
        """
        result = subprocess.run(
            ["bash", "-c", script, "init",
             str(ROOT / "completions/sandbox-game")],
            env={**os.environ, "PATH": SAFE_PATH}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(),
                         ["-s", "alpha", "beta", "gamma"])

        record = self.base / "init.args"
        script = f"""
            _comp_initialize() {{
                printf '%s\\n' "$@" > {shlex.quote(str(record))}
                cur=${{COMP_WORDS[COMP_CWORD]}}
                prev=${{COMP_WORDS[COMP_CWORD-1]}}
                words=("${{COMP_WORDS[@]}}")
                cword=$COMP_CWORD
                return 0
            }}
            _filedir() {{ COMPREPLY=(); }}
            source "$1"
            COMP_WORDS=(sandbox-attach --na)
            COMP_CWORD=1
            _sandbox_attach sandbox-attach --na --name
        """
        result = subprocess.run(
            ["bash", "-c", script, "init",
             str(ROOT / "completions/sandbox-attach")],
            env={**os.environ, "PATH": SAFE_PATH}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(record.read_text(encoding="utf-8").splitlines(),
                         ["-s", "--", "sandbox-attach", "--na", "--name"])

    def test_sandbox_game_respects_double_dash_and_space_only_options(self):
        self.assertEqual(self.complete("sandbox-game", "_sandbox_game",
                                       "sandbox-game", "--", "-"),
                         ["-gamedir"])
        self.assertEqual(self.complete("sandbox-game", "_sandbox_game",
                                       "sandbox-game", "--", "-g"),
                         ["-gamedir"])
        self.assertEqual(self.complete("sandbox-game", "_sandbox_game",
                                       "sandbox-game", "--", "-gamedir", "-"),
                         ["-cmd"])
        self.assertEqual(self.complete("sandbox-game", "_sandbox_game",
                                       "sandbox-game", "--delete=my"), [])
        self.assertEqual(self.complete("sandbox-game", "_sandbox_game",
                                       "sandbox-game", "--reset-install=my"), [])
        self.assertEqual(self.complete("sandbox-game", "_sandbox_game",
                                       "sandbox-game", "--delete", "my"),
                         ["mygame"])
        self.assertEqual(self.complete("sandbox-game", "_sandbox_game",
                                       "sandbox-game", "--reset-install", "my"),
                         ["mygame"])
        # --stop and --name do parse =NAME, so both spellings complete.
        self.assertEqual(self.complete("sandbox-game", "_sandbox_game",
                                       "sandbox-game", "--name=my"),
                         ["--name=mygame"])

    def test_tilde_expansion_does_not_mangle_another_users_path(self):
        self.assertEqual(self.complete("sandbox-game", "_sandbox_game",
                                       "sandbox-game",
                                       "~/game-sandboxes/mygame", "g"),
                         ["gamedata/"])
        # A literal ~otheruser directory must not become $HOMEotheruser.
        self.assertEqual(self.complete("sandbox-game", "_sandbox_game",
                                       "sandbox-game", "~otheruser/game", "g"),
                         ["gamedata/"])

    def test_sandbox_attach_respects_double_dash_and_put_values(self):
        self.assertEqual(self.complete("sandbox-attach", "_sandbox_attach",
                                       "sandbox-attach", "--", "-"),
                         ["-gamedir"])
        self.assertEqual(self.complete("sandbox-attach", "_sandbox_attach",
                                       "sandbox-attach", "--exec", "--", "-g"),
                         ["-gamedir"])
        self.assertEqual(self.complete("sandbox-attach", "_sandbox_attach",
                                       "sandbox-attach", "--put", "x", "-g"),
                         ["-gamedir"])
        self.assertEqual(self.complete("sandbox-attach", "_sandbox_attach",
                                       "sandbox-attach", "--put", "-g"),
                         ["-gamedir"])
        self.assertEqual(self.complete("sandbox-attach", "_sandbox_attach",
                                       "sandbox-attach", "program", "-"),
                         ["-gamedir"])

        # --name=PREFIX split by -s sets prev=--name and cur=PREFIX with skip=0.
        stubbin = self.base / "attach-bin"
        stubbin.mkdir()
        self.write_exec(stubbin / "sandbox-attach",
                        "#!/bin/bash\nprintf 'NAME PID\\nmygame 123\\nother 456\\n'\n")
        script = f"""
            source {shlex.quote(str(ROOT / "completions/sandbox-attach"))}
            _init_completion() {{
                cur=my
                prev=--name
                words=(sandbox-attach --name=my)
                cword=1
                return 0
            }}
            _filedir() {{ COMPREPLY=(); }}
            _sandbox_attach sandbox-attach --name=my
            printf '%s\\n' "${{COMPREPLY[@]}}"
        """
        result = subprocess.run(
            ["bash", "-c", script],
            env={**os.environ, "PATH": str(stubbin) + ":" + SAFE_PATH},
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["mygame"])


class SharedLibTests(ScriptTestCase):
    """sandbox-game-lib, sourced as the scripts that share it source it."""

    def lib(self, body, *args, cwd=None, env=None):
        script = f'. {shlex.quote(str(ROOT / "sandbox-game-lib"))}\n' + body
        return subprocess.run(["bash", "-c", script, "lib", *args], cwd=cwd,
                              env=env or {**os.environ, "HOME": str(self.base)},
                              capture_output=True, text=True, timeout=30)

    def bound(self, home, *argv):
        result = subprocess.run(
            ["bash", "-c", '. "$1"; shift; bound_capture "$@"; printf %s "$BOUND"',
             "bound", str(ROOT / "sandbox-game-lib"), *argv],
            env={**os.environ, "HOME": str(home), "PATH": SAFE_PATH},
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_bound_capture_stops_where_the_command_starts(self):
        home = self.base / "home"
        victim = home / "game-sandboxes" / "victim" / "home"
        victim.mkdir(parents=True)
        mine = home / "game-sandboxes" / "mine" / "home"
        mine.mkdir(parents=True)
        # A bwrap without -- whose command binds one of our captures is not
        # one of our sandboxes: from the command on, the arguments are the
        # game's, and a --bind there may name anything at all.
        self.assertEqual(self.bound(home, "bwrap", "/usr/bin/tool",
                                    "--bind", str(victim), "/x"), "")
        self.assertEqual(self.bound(home, "bwrap", "--ro-bind", "/usr", "/usr",
                                    "/usr/bin/tool", "--bind", str(victim), "/x"), "")
        # An option bwrap does not know ends the scan at the word after it,
        # as sandbox-uid's sources() treats one.
        self.assertEqual(self.bound(home, "bwrap", "--unknown", "value",
                                    "--bind", str(victim), "/x"), "")
        # What bwrap itself binds still names the sandbox, and -- still ends
        # its options, a "--" an option's value not among them.
        self.assertEqual(self.bound(home, "bwrap", "--bind", str(mine), "/home"), "mine")
        self.assertEqual(self.bound(home, "bwrap", "--bind", str(mine), "/home", "--",
                                    "--bind", str(victim), "/x"), "mine")
        self.assertEqual(self.bound(home, "bwrap", "--setenv", "KEY", "--",
                                    "--bind", str(mine), "/x"), "mine")

    def test_find_call_sites_take_folders_named_like_predicates(self):
        # find's -- ends only its options, never its predicates: a game folder
        # beginning with "-" (or named "!") used to fail the search silently.
        for name in ("-MyGame", "!"):
            with self.subTest(name=name):
                game = self.base / name
                arch = game / "lib" / f"linux-{os.uname().machine}"
                (game / "renpy").mkdir(parents=True)
                arch.mkdir(parents=True)
                (game / "Start.sh").write_text("", encoding="utf-8")
                (game / "Game.rgss3a").write_text("", encoding="utf-8")
                (game / "Game.exe").write_bytes(b"MZ")
                (arch / "librenpython.so").write_text(
                    "SDL X11 video driver", encoding="utf-8")
                result = self.lib(
                    'printf "scripts: %s\\n" "$(native_scripts "$1")"\n'
                    'printf "exes: %s\\n" "$(find_exes "$1" | cut -f2)"\n'
                    'is_rgss "$1" && echo "rgss: yes"\n'
                    'has_windows_exe "$1" && echo "exe: yes"\n'
                    'renpy_without_wayland "$1" && echo "renpy-x11: yes"\n'
                    'printf "abs: %s\\n" "$(native_scripts "$2")"\n',
                    name, str(game), cwd=self.base)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), [
                    f"scripts: ./{name}/Start.sh",
                    f"exes: ./{name}/Game.exe",
                    "rgss: yes",
                    "exe: yes",
                    "renpy-x11: yes",
                    f"abs: {game}/Start.sh",
                ])

    def test_uid_helper_is_resolved_when_the_lib_is_sourced_by_file_name(self):
        # ${BASH_SOURCE%/*} on a slashless name is the file itself; the helper
        # is beside the real file, not inside a folder named after it.
        libdir = self.base / "lib"
        libdir.mkdir()
        shutil.copy(ROOT / "sandbox-game-lib", libdir / "sandbox-game-lib")
        helper = self.write_exec(libdir / "sandbox-uid", "#!/bin/sh\nexit 0\n")
        result = subprocess.run(
            ["bash", "-c", 'source sandbox-game-lib; printf "%s\\n" "$SANDBOX_UID_HELPER"'],
            cwd=libdir, env={**os.environ, "PATH": SAFE_PATH},
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(helper))

    def test_a_lock_that_cannot_be_taken_is_reported(self):
        # A failed redirection on the bare exec special builtin ends a
        # POSIX-mode shell outright; command exec leaves it to the caller,
        # which says why instead.
        home = self.base / "home"
        locks = home / ".config" / "sandbox-game" / ".locks"
        (locks / "game-game").mkdir(parents=True)   # a lock target that is a folder
        result = subprocess.run(
            ["bash", "--posix", "-c",
             '. "$1"; NAME=game; prefs_save \'{"scope":"game"}\'; echo SURVIVED',
             "prefs", str(ROOT / "sandbox-game-lib")],
            env={**os.environ, "HOME": str(home),
                 "XDG_CONFIG_HOME": str(home / ".config")},
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Cannot lock game", result.stderr)


class LayerRelocationTests(ScriptTestCase):
    def test_relocate_layers_moves_a_layer_the_game_left_closed(self):
        # A game can leave its rw/ at mode 000; moving a folder writes its
        # "..", so the relocation opens what it moves.
        cap = self.base / "cap"
        (cap / "rw").mkdir(parents=True)
        (cap / "work").mkdir()
        (cap / "rw" / "save.txt").write_text("", encoding="utf-8")
        harness = (shell_function("unlock_dirs", "sandbox-game")
                   + shell_function("relocate_layers", "sandbox-game")
                   + textwrap.dedent(f"""
                     chmod 000 {shlex.quote(str(cap / 'rw'))}
                     relocate_layers {shlex.quote(str(cap))} || exit 1
                     [ -d {shlex.quote(str(cap / 'overlay' / 'rw'))} ] || {{ echo no-rw; exit 1; }}
                     [ -f {shlex.quote(str(cap / 'overlay' / 'rw' / 'save.txt'))} ] || {{ echo no-file; exit 1; }}
                     [ -e {shlex.quote(str(cap / 'work'))} ] && {{ echo work-left; exit 1; }}
                     echo moved
                     """))
        result = subprocess.run(["bash", "-c", harness], capture_output=True,
                                text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "moved\n")


class FailedLaunchLogTests(ScriptTestCase):
    """Where "Sandbox game" leaves the log of a launch that never began."""

    def failing_launch(self, home, game, backend, dialog):
        return subprocess.run(
            [str(ROOT / "Sandbox game")],
            env=self.script_env(home, SANDBOX_BACKEND=str(backend),
                                SANDBOX_DIALOG=str(dialog),
                                NAUTILUS_SCRIPT_SELECTED_FILE_PATHS=str(game) + "\n"),
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)

    def failing_backend(self, rc):
        # Fails before writing the pre-launch boundary: as a second launch of
        # a running game would.
        return self.write_exec(self.base / f"backend-{rc}", f"""#!/bin/bash
case "$1" in
    --print-name) printf 'derived\\n'; exit 0 ;;
esac
printf 'the game is already running\\n' >&2
exit {rc}
""")

    def test_a_failure_before_the_boundary_keeps_lastrun_and_gets_its_own_log(self):
        home, game = self.game_home()
        (game / "Start.sh").write_text("", encoding="utf-8")
        backend = self.failing_backend(23)
        shown = self.base / "shown"
        dialog = self.write_exec(self.base / "dialog",
                                 f"#!/bin/bash\ncat > {shlex.quote(str(shown))}\nexit 0\n")
        cap = home / "game-sandboxes" / "derived"
        cap.mkdir(parents=True)
        (cap / "lastrun.log").write_text("a previous run's log\n", encoding="utf-8")

        result = self.failing_launch(home, game, backend, dialog)
        self.assertEqual(result.returncode, 23, result.stderr)
        # lastrun.log may belong to a game still running: not overwritten.
        self.assertEqual((cap / "lastrun.log").read_text(encoding="utf-8"),
                         "a previous run's log\n")
        # The failure has a log of its own, past the EXIT trap's reach.
        failed = cap / "launch-failed.log"
        self.assertIn("the game is already running", failed.read_text(encoding="utf-8"))
        # And the dialog names that one, not the launch folder it just deleted.
        self.assertIn(f"log: {failed}", shown.read_text(encoding="utf-8"))
        self.assertEqual(list(cap.glob(".launch.*")), [])

    def test_a_failure_with_no_lastrun_log_takes_the_name_itself(self):
        home, game = self.game_home()
        (game / "Start.sh").write_text("", encoding="utf-8")
        backend = self.failing_backend(1)
        shown = self.base / "shown"
        dialog = self.write_exec(self.base / "dialog",
                                 f"#!/bin/bash\ncat > {shlex.quote(str(shown))}\nexit 0\n")
        cap = home / "game-sandboxes" / "derived"

        result = self.failing_launch(home, game, backend, dialog)
        self.assertEqual(result.returncode, 1, result.stderr)
        log = cap / "lastrun.log"
        self.assertIn("the game is already running", log.read_text(encoding="utf-8"))
        self.assertIn(f"log: {log}", shown.read_text(encoding="utf-8"))
        self.assertFalse((cap / "launch-failed.log").exists())


class InstallAdminModeTests(ScriptTestCase):
    """The administrator modes of install.sh touch neither source nor sound."""

    def stub(self, name, body):
        return self.write_exec(self.base / "bin" / name, body)

    def sound_server_present(self, home):
        # A previous --restrict-audio: what used to make every mode check
        # the running PipeWire's version.
        service = home / ".config" / "systemd" / "user" / "sandbox-pulse.service"
        service.parent.mkdir(parents=True)
        service.write_text("", encoding="utf-8")
        return service

    def pipewire_probe(self):
        log = self.base / "pw-cli.log"
        self.stub("pw-cli", f'printf "%s\\n" "$@" > {shlex.quote(str(log))}\nexit 0\n')
        return log

    def admin_env(self, home):
        return {**os.environ, "HOME": str(home),
                "XDG_CONFIG_HOME": str(home / ".config"),
                "XDG_DATA_HOME": str(home / ".local" / "share"),
                "PATH": str(self.base / "bin") + os.pathsep + SAFE_PATH}

    def test_piped_uninstall_selinux_needs_no_source_and_asks_no_sound_server(self):
        # Removing the module from a pipe: nothing is beside the script, so
        # there is no source to read, and the mode has no business with the
        # user's sound setup either.
        home = self.base / "home"
        home.mkdir()
        self.sound_server_present(home)
        self.stub("id", 'printf "0\\n"')          # the administrator's identity
        self.stub("semodule", "exit 0")           # -l names nothing: not loaded
        pw_log = self.pipewire_probe()
        curl_log = self.base / "curl.log"
        self.stub("curl", f'printf "%s\\n" "$@" > {shlex.quote(str(curl_log))}; exit 1\n')
        result = subprocess.run(["bash", "-s", "--", "--uninstall-selinux"],
                                input=read("install.sh"), text=True,
                                env=self.admin_env(home), cwd=self.base,
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("is not loaded", result.stdout)
        self.assertFalse(curl_log.exists(), "the removal downloaded a source tree")
        self.assertFalse(pw_log.exists(),
                         "the removal asked the sound server for its version")

    def test_selinux_mode_leaves_the_sound_server_alone(self):
        # From a checkout, so the source is there to be read: the policy mode
        # still has nothing to do with the user's sound setup.
        checkout = self.base / "checkout"
        checkout.mkdir()
        shutil.copy2(ROOT / "install.sh", checkout / "install.sh")
        shutil.copy2(ROOT / "sandbox-game", checkout / "sandbox-game")
        shutil.copy2(ROOT / "sandbox-game-lib", checkout / "sandbox-game-lib")
        home = self.base / "home"
        home.mkdir()
        self.sound_server_present(home)
        self.stub("id", 'printf "0\\n"')
        self.stub("semodule", "exit 0")
        pw_log = self.pipewire_probe()
        result = subprocess.run(["bash", str(checkout / "install.sh"), "--selinux"],
                                text=True, env=self.admin_env(home), cwd=self.base,
                                capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(pw_log.exists(),
                         "the policy mode asked the sound server for its version")


if __name__ == "__main__":
    unittest.main()
