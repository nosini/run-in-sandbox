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
- **Less kernel to aim at.** No nested user namespaces, a seccomp filter
  over the syscalls a game never needs, and memory and task limits, so a
  runaway game cannot take the desktop with it.

The default display uses gamescope's private Xwayland, the device filesystem is
private, and the game's environment starts from an allowlist. Audio is disabled
by default: `--audio` grants host sound playback **and microphone/monitor
recording**. `--host-x11` explicitly grants access to other host X applications.
Neither compatibility option should be enabled for a game you do not trust.

This is not a complete security boundary against actively malicious software.
The host kernel, graphics drivers and exposed display services remain shared.

Four engines are handled without being told which is which: RPG Maker MV/MZ
(NW.js), Ren'Py and other native `.sh` games, RPG Maker XP/VX/VX Ace (natively,
via mkxp-z — no Wine), and Windows `.exe` games via Proton.

## Install

```sh
D=~/.local/share/nautilus/scripts
install -Dm755 sandbox-game              ~/.local/bin/sandbox-game
install -Dm755 sandbox-attach            ~/.local/bin/sandbox-attach
install -Dm755 sandbox-seccomp           ~/.local/bin/sandbox-seccomp
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
| `bwrap` ≥ 0.8 | `bubblewrap` | the sandbox itself; 0.8 added `--disable-userns` |
| `bash` ≥ 4.0 | `bash` | `mapfile`, associative arrays, `${var,,}` |
| `python3` | `python3` | `sandbox-seccomp` compiles the filter with it |
| `libseccomp.so.2` | `libseccomp2` / `libseccomp` | the filter compiler, loaded through ctypes; every systemd install has it, and the Python bindings are *not* needed |
| `awk`, `sed`, `find`, `sort`, `realpath` | `gawk`, `sed`, `findutils`, `coreutils` | standard, present everywhere |

The default graphical mode also requires gamescope and a Wayland session.
`--wayland` bypasses gamescope for native Wayland games; `--headless` requires
neither. `--host-x11` is an explicit, less isolated option for X11 sessions. `bwrap` does not need to be setuid on any
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
| memory and task limits | `systemd-run` and a systemd user session | without one the game still starts, with a warning and no limits |

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

**Sandbox game preferences** — the video backend, audio permission, MangoHud,
gamescope, and the Proton version, saved per game or as the library-wide default. Turning gamescope
on opens a second dialog for resolution and fullscreen. This is why there is one
launcher entry rather than one per flag combination.

### From the shell

```sh
sandbox-game [--wayland] [--name NAME] [--mangohud] [--gamescope[=ARGS]]
             [--host-x11|--headless] [--audio] [--env K=V] [--ro SRC DST]
             [--proton[=VER]|--mkxp[=DIR]] GAMEDIR CMD...
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
| `--host-x11` | use the host X server; permits observing/controlling other X clients, mutually exclusive with `--wayland` and `--gamescope` |
| `--headless` | no display sockets, compositor or GPU devices; mutually exclusive with display flags |
| `--audio` | grant host audio, including microphone and monitor recording; off by default |
| `--mangohud` | the MangoHud overlay. Exporting `MANGOHUD=1` opts in identically. |
| `--gamescope[=ARGS]` | run inside gamescope's nested compositor (default for X11 games); `ARGS` is word-split, so quote the lot |
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
# Replace witcher3 below with the name shown by --list.

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

The host environment is cleared. The launcher supplies `HOME`, user names, a
fixed `/usr/bin:/bin` search path, private XDG directories, locale/timezone/terminal
settings and the selected display variables. Tokens, session-bus addresses and
loader overrides are not inherited; pass necessary game-specific settings with
`--env KEY=VALUE`. Runtime discovery variables (`PROTON_DIR`, `MKXP_DIR`,
`NWJS_DIR`) still work on the host, and `MANGOHUD=1` still selects the overlay.

The default display exposes the Wayland socket for gamescope, which supplies a
private Xwayland server. Native `--wayland` exposes no host X socket or cookie,
including for Proton: builds lacking winewayland must use gamescope instead.
`--host-x11` exposes the host X socket and cookie and does not expose Wayland.
`--headless` exposes neither. No session D-Bus socket is provided.

`/dev` and its shared memory are private. Graphical modes expose GPU devices only
(`/dev/dri` and available NVIDIA device nodes). Host input, camera, sound and
terminal devices are not exposed; controllers requiring raw device access are
currently unavailable. Audio sockets are exposed only with `--audio`, which
includes recording access and is also available in the preferences dialog.
`~/.config/MangoHud` is mounted read-only under `--mangohud`.

## Kernel attack surface and resource limits

**No nested user namespaces.** `bwrap --disable-userns` stops the game from
creating a user namespace of its own. Unprivileged user namespaces are among
the most commonly exploited ways into the kernel: inside one, a process holds
every capability, which puts netfilter, mounts and much else in reach. bwrap
checks that the door is shut before it starts the game.

**A seccomp filter**, compiled by `sandbox-seccomp` on every launch and handed
to bwrap. It starts from Flatpak's denylist, which Steam, Proton and Chromium
already run under, and adds what podman's default blocks that a game has no use
for: `bpf`, `perf_event_open`, `io_uring_*`, kernel-mode `userfaultfd`, the
kernel keyring, new-style mount calls, and namespace creation as a second lock
behind `--disable-userns`. Both the 64-bit and the i386 syscall tables are covered,
since 64-bit code can make 32-bit syscalls too. `sandbox-seccomp` holds the
list and the reasons behind it. There is no socket address-family filter,
because on i386 it cannot be enforced (see the comment there). The launcher
refuses to start if the filter cannot be built.

If a game breaks and the filter is a suspect, run it once from the shell with
`SANDBOX_SECCOMP=log`: every rule then logs instead of blocking. With auditd
running, count the hits with

```sh
sudo ausearch -m SECCOMP -ts recent | grep -o 'arch=[0-9a-f]* syscall=[0-9]*' | sort | uniq -c
```

(without auditd they go to the kernel log, `journalctl -k`). `arch=c000003e`
is 64-bit and `arch=40000003` 32-bit, and the two number syscalls differently;
`ausyscall N` (from the audit package) or `ausyscall i386 N` names them.
`clone3` is left out of the log: glibc tries it for every thread and falls
back to `clone`, and its hits would bury everything else. Expect `clone` from
a `bwrap` under gamescope too -- its image loader trying to sandbox itself.

**Memory and task limits.** The sandbox runs in a transient systemd scope,
`sandbox-game-<name>-<pid>.scope`, capped at 80% of RAM and 4096 tasks. That
turns a leak or a fork bomb into a dead game instead of a frozen desktop, and
gives you a handle on it:

```sh
systemctl --user list-units 'sandbox-game-*'
systemctl --user kill sandbox-game-<name>-<pid>.scope
```

`sandbox-attach` puts the program it brings in under the same filter, and into
the same scope when there is one.

RPG Maker MV/MZ runs with Chromium's own sandbox switched off (`--no-sandbox`):
it is built on the user namespaces this one forbids, and without them NW.js dies
looking for a setuid helper. The sandbox around it is the one that matters here.

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
host_x11=0|1
audio=0|1
gamescope_args=-f -W 2560 -H 1440
env=WAYLANDDRV_PRIMARY_MONITOR=HDMI-1 SOME_OTHER=value
proton=auto|<install name>
```

The key is the sandbox name, so preferences and captured writes stay in step.
Two games whose folders have the same name share a sandbox; give one of them
`--name`, or an entry in `NAME_MAP` at the top of `sandbox-game`, to separate
them. `host_x11=1` opts
into the host X server and overrides the Wayland/gamescope choices; `audio=1`
opts into host audio and recording. `gamescope=0` means automatic: X11 games
still use a private gamescope instance unless `host_x11=1`.
Resolution and fullscreen get a dialog;
anything else in `gamescope_args`, and all of `env`, is set by hand and carried
through saves untouched. `env` values cannot contain spaces — the list is split
on them.

`env` explicitly adds variables to the clean sandbox environment, including
when launching from the file manager.

## Known rough edges

**RPG Maker MV/MZ uses private Xwayland by default.** Not a limitation of NW.js, which runs
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
GE, DW and CachyOS builds honour. Builds without winewayland need the default
gamescope mode; host X is never silently exposed as a fallback.

**gamescope and the overlay.** `gamescope --mangoapp` is the supported way to
get MangoHud in there, and is what gets used — except when the Wayland socket is
exposed as well (which is what makes winewayland work under gamescope). mangoapp
is a GLFW client: given a `WAYLAND_DISPLAY` it takes the Wayland path, libdecor
cannot find the globals gamescope offers, it falls back to X11, fails there too,
and gamescope's reaper restarts it forever. In that combination the shim is
preloaded into the game instead, against gamescope's general advice. Either
route reads the same config.

## Security regression checks

Run on the host with Python 3 and bubblewrap installed:

```sh
python3 tests/test_security.py -v
```

The tests use temporary homes and captures. They exercise real filesystem and
network isolation, the seccomp filter and the user-namespace block, environment
filtering and namespace attachment; display and
audio argument checks use recorders so they do not open windows or record sound.
