# run-in-sandbox

Run a downloaded game in a bwrap sandbox, from the file manager or the shell.

Games from itch.io, a jam page, or a random archive are unpacked and run as your
user with your whole home directory in reach. This puts one between them and
you:

- **No network.** `--unshare-all` takes the net namespace with it.
- **No `$HOME`.** The real one is not bound at all; a fresh, empty one is
  redirected into the capture directory.
- **No writes to the install.** The game directory is presented at `/game` as an
  overlay, so the copy on disk is never modified and every write is captured.
- **Everything in one folder.** `~/game-sandboxes/<name>/` holds the saves, the
  configs, the Wine prefix — delete it and the game is factory-fresh.

It is not a security boundary against something actively trying to escape. It is
a boundary against a game that reads too much, writes where it should not, or
phones home.

Four engines are handled without being told which is which: RPG Maker MV/MZ
(NW.js), Ren'Py and other native `.sh` games, RPG Maker XP/VX/VX Ace (natively,
via mkxp-z — no Wine), and Windows `.exe` games via Proton.

## Install

```sh
D=~/.local/share/nautilus/scripts
install -Dm755 sandbox-game              ~/.local/bin/sandbox-game
install -Dm755 sandbox-attach            ~/.local/bin/sandbox-attach
install -Dm644 sandbox-game-lib          ~/.local/bin/sandbox-game-lib
install -Dm755 "Sandbox game"            "$D/Sandbox game"
install -Dm755 "Sandbox game preferences" "$D/Sandbox game preferences"
```

`sandbox-game-lib` is mode 644 and goes in `~/.local/bin`, not the scripts
directory: it holds the parts the launcher and the preferences dialog must agree
on, and Nautilus lists anything in that directory as a menu entry of its own.

Then right-click a game folder in Nautilus → **Scripts** → **Sandbox game**.

## Dependencies

Package names vary between distributions; the binary is what matters, and the
names below are the common ones. Where a name differs sharply it is called out.

### Required

| Binary | Usual package | Why |
|---|---|---|
| `bwrap` | `bubblewrap` | the sandbox itself |
| `bash` ≥ 4.0 | `bash` | `mapfile`, associative arrays, `${var,,}` |
| `awk`, `sed`, `find`, `sort`, `realpath` | `gawk`, `sed`, `findutils`, `coreutils` | standard, present everywhere |

Nothing else is needed for the CLI. `bwrap` does not need to be setuid on any
current distribution — unprivileged user namespaces cover it. If yours disables
them (`kernel.unprivileged_userns_clone=0`, or an AppArmor restriction on
Ubuntu 24.04+), nothing here will run until that is lifted.

### Required for the Nautilus scripts

| Binary | Usual package | Why |
|---|---|---|
| `nautilus` | `nautilus` | the scripts are Nautilus scripts |
| `zenity` | `zenity` | launcher picker, error window, the whole preferences dialog |
| `notify-send` | `libnotify` / `libnotify-bin` / `libnotify-tools` | fallback when zenity is missing |

The preferences dialog refuses to start without zenity. The launcher degrades to
`notify-send` and, failing that, to silence.

Only the two scripts are Nautilus-specific, and only for how they learn what was
selected — `sandbox-game` itself has no GUI dependency at all. Another file
manager with a scripts or custom-actions feature can call them the same way if
it sets `NAUTILUS_SCRIPT_SELECTED_FILE_PATHS`; otherwise they fall back to the
working directory.

### Per feature

| Feature | Needs | Notes |
|---|---|---|
| overlay on a `bwrap` built without `--overlay` | `fuse-overlayfs` | fallback only |
| `--mangohud` | `mangohud` | |
| MangoHud in a 32-bit game | the 32-bit libraries | `lib32-mangohud`, `mangohud-32bit`, `mangohud.i686`, `mangohud:i386` — pick your distro's spelling |
| `--gamescope` | `gamescope` | |
| `--gamescope` **and** `--mangohud` | `mangoapp` | bundled with `mangohud` on some distributions, a separate package on others |
| resolution list in the gamescope dialog | `xrandr` or `wlr-randr` | `xrandr` may live in `xorg-xrandr` or `x11-xserver-utils` |
| `sandbox-attach` | `nsenter` | `util-linux`, installed practically everywhere |

`bwrap --overlay` is the preferred path and is compiled in on most
distributions — check with `bwrap --help | grep overlay` — and `fuse-overlayfs`
is only the fallback for builds that lack it. A missing `mangoapp` is a warning,
not an error: the game still starts, without the overlay.

### Per engine

None of these are packaged with the project; each is found at runtime, and only
the ones you actually use need to exist.

#### RPG Maker MV/MZ — NW.js

Any Linux NW.js build. Searched for under `~/.config/nvm`,
`~/.local/share/nwjs` and `~/nwjs` as a directory named `nwjs-*linux*`, newest
by version; `NWJS_DIR=/path` overrides. Downloading a build from
[nwjs.io](https://nwjs.io/) and unpacking it into `~/.local/share/nwjs/` works,
as does `npm install -g nw`, which lands one at
`.../node_modules/nw/nwjs-*-linux-x64` — the search finds that as-is.

#### Windows games — Proton

Any Proton install, meaning any directory holding an executable `proton`
script — that test also rejects the plain Wine builds people drop into
`compatibilitytools.d`. Searched under Steam's `compatibilitytools.d` and
`steamapps/common`, native and Flatpak, plus
`/usr/share/steam/compatibilitytools.d`; newest wins, ranked by the timestamp in
each `version` file. `--proton=VER` matches by name substring or takes a path,
and `PROTON_DIR=/path` overrides the search entirely. `sandbox-game
--list-proton` prints what it found.

Steam does not have to be running, or even installed, as long as a Proton
directory exists somewhere on the list — unpacking a Proton-GE release into
`~/.steam/root/compatibilitytools.d/` is enough. The prefix is always built
fresh under the capture directory, so existing Steam prefixes are never touched,
and the Proton install is mounted read-only.

#### RPG Maker XP/VX/VX Ace — mkxp-z

[mkxp-z](https://github.com/mkxp-z/mkxp-z) reimplements the RGSS runtimes, so
these games run as native Linux programs with no Wine anywhere.

**Getting a binary is the awkward part.** The project publishes no tagged
release builds — the binaries only exist as GitHub Actions artifacts. Open the
[Actions tab](https://github.com/mkxp-z/mkxp-z/actions), pick a recent
successful run, and take the Linux artifact from its Artifacts section. For
reference, one such artifact is
[actions/runs/31271704080/artifacts/9026102487](https://github.com/mkxp-z/mkxp-z/actions/runs/31271704080/artifacts/9026102487).

Two things about those downloads:

- **You must be signed in to GitHub.** Artifact links are not public. An
  anonymous `curl` or `wget` gets an HTML login page saved under the name of a
  zip, which then fails to unpack for no obvious reason. Download it in a
  browser that is logged in.
- **Artifacts expire**, 90 days after the run by default. A link that worked
  once will eventually 404, including the one above — take a current run rather
  than assuming an old link still resolves.

Building from source is the other option, and the only one if you want something
newer than the last successful CI run.

Unpack the archive whole into `~/.local/share/mkxp-z/`, so the binary sits
directly beside the rest:

```
~/.local/share/mkxp-z/
├── mkxp-z.x86_64
├── mkxp.json
├── scripts/preload/
└── stdlib/
```

That layout is not optional: mkxp-z resolves `stdlib/`, `scripts/` and
`mkxp.json` relative to *its own binary*, never the working directory, so a
binary moved out on its own will not start. Also searched under
`~/.local/lib/mkxp*`, `~/mkxp*`, `~/Games/mkxp*` and `/opt/mkxp*`;
`MKXP_DIR=/path` overrides.

Japanese games want a Japanese font installed — VL Gothic is the usual one — for
`fontSub` in `mkxp.json` to have anything to substitute.

## Usage

### From Nautilus

**Sandbox game** — right-click the game folder, or the thing inside it that
looks like a launcher: `www`/`index.html`/`package.json` for RPG Maker MV/MZ,
the `.sh`, the `.exe`. Dispatch runs in that order, so a Ren'Py or Unity game
shipping both a `.sh` and a `.exe` runs the Linux build rather than emulating
the Windows one, and an RPG Maker VX Ace game runs under mkxp-z rather than
dragging its `Game.exe` through Wine. Several `.exe` candidates get a picker,
with obvious junk (installers, crash handlers, redistributables) filtered out.

Full output goes to `~/game-sandboxes/<game>-lastrun.log`, and a failure opens
the last 80 lines in a window.

**Sandbox game preferences** — the video backend, MangoHud, gamescope, and the
Proton version, saved per game or as the library-wide default. Turning gamescope
on opens a second dialog for resolution and fullscreen. This is why there is one
launcher entry rather than one per flag combination.

### From the shell

```sh
sandbox-game [--wayland] [--name NAME] [--mangohud] [--gamescope[=ARGS]]
             [--env K=V] [--ro SRC DST] [--proton[=VER]|--mkxp[=DIR]] GAMEDIR CMD...
```

`CMD` refers to the game at `/game`, not at its path on disk:

```sh
sandbox-game ~/Games/SomeRenpyGame /game/SomeRenpyGame.sh
sandbox-game --proton ~/Games/SomeWindowsGame /game/game.exe
sandbox-game --proton=GE-Proton11 ~/Games/Foo /game/bin/foo.exe -windowed
sandbox-game --mkxp ~/Games/SomeVXAceGame          # CMD omitted: the runtime is the program
sandbox-game --gamescope='-f -W 2560 -H 1440' --mangohud ~/Games/Unity /game/game.x86_64
```

| Option | |
|---|---|
| `--wayland` | native Wayland instead of Xwayland. With `--proton` this selects winewayland instead (see below). |
| `--name NAME` | override the sandbox name, otherwise derived from the folder |
| `--mangohud` | the MangoHud overlay. Exporting `MANGOHUD=1` opts in identically. |
| `--gamescope[=ARGS]` | run inside gamescope's nested compositor; `ARGS` is word-split, so quote the lot |
| `--proton[=VER]` | run `CMD` as a Windows program; the sandbox cwd becomes the `.exe`'s own directory, since games routinely load assets relative to it |
| `--mkxp[=DIR]` | run an RGSS game natively under mkxp-z |
| `--env K=V` | set a variable inside the sandbox; repeatable, applied last so it wins |
| `--ro SRC DST` | bind something else in read-only |
| `--print-name` | print the sandbox name for a directory and exit |
| `--list-proton` | list the Proton installs found, newest first |

## Attaching to a running game

Cheat Engine, `regedit` and `winetricks` are only useful if they can see the
game — which means the same Wine session, not merely the same prefix on disk.
Launching a second sandbox does not give you that: `--unshare-all` hands every
launch its own PID and mount namespace, so the new process cannot see the game's
processes, and Wine's server socket lives in `/tmp/.wine-$UID`, a tmpfs private
to each sandbox. Same prefix, second wineserver, no contact.

`sandbox-attach` joins the running sandbox's namespaces instead of creating new
ones. No root: the user namespace is already yours to enter.

```sh
sandbox-attach --list                       # what is running

# get the program in — the capture dir IS $HOME inside, so no restart is needed
cp -r ~/Downloads/CheatEngine ~/game-sandboxes/witcher3/home/

sandbox-attach --name witcher3 ~/game-sandboxes/witcher3/home/CheatEngine/cheatengine-x86_64.exe
```

| Option | |
|---|---|
| `--list` | the running sandboxes: name, pid, and whether Proton is in play |
| `--name NAME` | which one to attach to; optional when only one is running |
| `--shell` | an interactive shell inside, to look around |
| `--exec CMD...` | run a native Linux command inside instead of a Windows one |

Paths under `~/game-sandboxes/<name>/home/` are translated to their location
inside, so you can paste the host path you just copied to.

Windows programs are started with Proton's own `wine` binary against the live
prefix, deliberately **not** with `proton run` — that verb re-enters prefix
setup, which has no business touching a prefix a game is currently using, and in
practice it exits silently without starting anything.

The attached program is as confined as the game: it joins the sandbox's network
namespace too, so it has loopback and nothing else.

Two caveats. Install Cheat Engine into the prefix while the game is *not*
running (a normal `sandbox-game --proton <gamedir> /game/setup.exe`), or use a
portable build copied in as above. And CE's kernel-mode features — DBVM, the
driver — do not work under Wine; scanning, pointer maps and speedhack do.

On a distribution with the Yama LSM set to `ptrace_scope=1`, a sibling process
may not ptrace the game, which is how Wine reads its memory. Check with
`sysctl kernel.yama.ptrace_scope`; absent or `0` is what this needs.

## What lands where

```
~/game-sandboxes/<name>/
├── home/       writes to $HOME — configs, saves, whatever it scatters
├── rw/         writes into the install directory at /game
├── compat/     --proton: the Wine prefix, under pfx/
└── mkxp.json   --mkxp: the runtime config, yours to edit
```

`mkxp.json` is generated from the runtime's own commented one on first launch
and then left alone, so per-game tweaks — a soundfont, RTP paths, `fontSub` —
survive the next start.

The host environment is inherited as it stands (there is no `--clearenv`). The
Wayland socket, PipeWire and PulseAudio sockets, and — on Xwayland — the X
socket and your auth cookie are bound in. `~/.config/MangoHud` is bound back
read-only under `--mangohud`, because `$HOME` is redirected and without it your
`fps_limit` and per-executable configs would silently stop applying.

## Preferences file format

```
~/.config/sandbox-game/games/<name>   per game — wins
~/.config/sandbox-game/defaults       library-wide fallback
```

Plain `key=value`, read rather than sourced, and meant to be edited by hand:

```ini
wayland=0|1
mangohud=0|1
gamescope=0|1
gamescope_args=-f -W 2560 -H 1440
env=WAYLANDDRV_PRIMARY_MONITOR=HDMI-1 SOME_OTHER=value
proton=auto|<install name>
```

The key is the sandbox name, so preferences and captured writes stay in step
even when two games share a folder name. Resolution and fullscreen get a dialog;
anything else in `gamescope_args`, and all of `env`, is set by hand and carried
through saves untouched. `env` values cannot contain spaces — the list is split
on them.

`env` exists because a game started from the file manager inherits *the file
manager's* environment, not the one in your shell, so anything a particular game
needs has to be recorded rather than exported.

## Known rough edges

**RPG Maker MV/MZ is pinned to Xwayland.** Not a limitation of NW.js, which runs
on Wayland fine outside the sandbox. Chromium's Wayland backend segfaults on
startup with no D-Bus session bus, reproducibly, while its X11 backend does not
care. Handing a game the session bus would open the keyring, the portals and
gvfs to it, which is most of what this exists to prevent. A private empty
`dbus-daemon --session` per launch does fix it and exposes nothing; it is not
implemented yet.

**MangoHud is off for RPG Maker MV/MZ.** Its GL shim is `LD_PRELOAD`ed into
every child, and Chromium spawns a zygote and its own sandboxed renderers — the
window never appears and the process hangs until killed. An FPS counter on a 2D
RPG Maker game is no loss.

**`--wayland` is not for every engine.** Stock Ren'Py's bundled SDL is
x11/Xwayland only. Under `--proton` it sets `STEAM_COMPAT_CONFIG=wayland`, which
GE, DW and CachyOS builds honour and stock Valve Proton ignores — so X stays
bound in that case, rather than leaving those builds with no display at all.

**gamescope and the overlay.** `gamescope --mangoapp` is the supported way to
get MangoHud in there, and is what gets used — except when the Wayland socket is
exposed as well (which is what makes winewayland work under gamescope). mangoapp
is a GLFW client: given a `WAYLAND_DISPLAY` it takes the Wayland path, libdecor
cannot find the globals gamescope offers, it falls back to X11, fails there too,
and gamescope's reaper restarts it forever. In that combination the shim is
preloaded into the game instead, against gamescope's general advice. Either
route reads the same config.
