# run-in-sandbox

Run a downloaded game in a bwrap sandbox, from the file manager or the shell.

Games from itch.io, a jam page, or a random archive are unpacked and run as your
user with your whole home directory in reach. This puts one between them and
you:

- **No network.** `--unshare-all` takes the net namespace with it. A game that
  needs the internet can be given it, and only it: never the LAN, never a
  service on this machine, never an incoming connection.
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
private, and the game's environment starts from an allowlist. Audio is always
on — too many games refuse to start without a sound device to withhold it — and
by default goes through the host's own PipeWire and Pulse sockets. That
includes **microphone and monitor recording, and loading sound server
modules**, some of which reach the network. `./install.sh --restrict-audio`
makes it playback only; see [Sound](#sound).
`--host-x11` explicitly grants access to other host X applications; do not
enable it for a game you do not trust.

This is not a complete security boundary against actively malicious software.
The host kernel, graphics drivers and exposed display services remain shared.

Four engines are handled without being told which is which: RPG Maker MV/MZ
(NW.js), Ren'Py and other native `.sh` games, RPG Maker XP/VX/VX Ace (natively,
via mkxp-z — no Wine), and Windows `.exe` games via Proton.

## Install

```sh
curl -fsSL https://codeberg.org/nosini/run-in-sandbox/raw/branch/main/install.sh | bash
```

That downloads the current `main` and installs it for your user; no root, and
nothing outside `~/.local`. From a checkout, `./install.sh` installs that
checkout instead. Either way, running it again updates in place, and it warns
about anything missing from the [dependencies](#dependencies) below.

Piping a script from the internet into a shell runs whatever the server sends.
To read it first:

```sh
curl -fsSLO https://codeberg.org/nosini/run-in-sandbox/raw/branch/main/install.sh
less install.sh && bash install.sh
```

`REF=<branch or tag>` installs something other than `main`
(`curl ... | REF=<tag> bash`). To remove the
scripts again, `./install.sh --uninstall`, or through the pipe
`... | bash -s -- --uninstall`. That leaves `~/game-sandboxes` (saves and Wine
prefixes), your preferences and the shared tools folder alone.

`./install.sh --restrict-audio` (or `... | bash -s -- --restrict-audio`)
additionally makes games' sound playback only; see [Sound](#sound). It changes
your sound setup, so it is not done unless asked, and once done every later
install keeps it current. `--uninstall` takes it out again.

What goes where:

| File | Installed to |
|---|---|
| `sandbox-game`, `sandbox-attach`, `sandbox-seccomp` | `~/.local/bin/` |
| `sandbox-game-lib` (mode 644) | `~/.local/bin/` |
| `Sandbox game`, `Sandbox game preferences` | `~/.local/share/nautilus/scripts/` |
| (empty) shared tools folder | `~/.local/share/sandbox-game/tools/` |
| `completions/sandbox-game`, `completions/sandbox-attach` | `~/.local/share/bash-completion/completions/` |

`sandbox-game-lib` goes beside `sandbox-game`, not in the scripts directory: it
holds the parts the launcher and the preferences dialog must agree on, and
Nautilus lists anything in that directory as a menu entry of its own.

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
neither. `--host-x11` is an explicit, less isolated option for X11 sessions.

`bwrap` must **not** be the setuid build: `--disable-userns` does not work
there, so every launch fails. No current distribution needs it, since
unprivileged user namespaces cover what setuid was for. If yours disables them
(`kernel.unprivileged_userns_clone=0`, or an AppArmor restriction on Ubuntu
24.04+), nothing here will run until that is lifted.

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
| Tab completion in bash | `bash-completion` | installed by default on most distributions; the completions are loaded through it |
| `--net` | `pasta` and `ip` | `passt` and `iproute2`; `pasta` is often already there as podman's network backend |
| playback-only sound (`install.sh --restrict-audio`) | PipeWire with `pipewire-pulse`, WirePlumber 0.5 with permission managers, a systemd user session | checked with PipeWire 1.6.9 and WirePlumber 0.5.17; the tests use `pactl`, `pacat` and `parec` (`pulseaudio-utils`) |

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

RPG Maker ships `package.json` with an empty `"name"`, which NW.js refuses to
start with. The launcher fills it in with the game's folder name; the edited
copy is a captured write in `rw/`, and a name that is already set is left alone.

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

**Sandbox game preferences** — the video backend, MangoHud, gamescope, the
Proton version and internet access, saved per game or as the library-wide default. Turning gamescope
on opens a second dialog for resolution and fullscreen. This is why there is one
launcher entry rather than one per flag combination.

### From the shell

```sh
sandbox-game [--wayland] [--name NAME] [--mangohud] [--gamescope[=ARGS]]
             [--host-x11|--headless] [--env K=V] [--ro SRC DST]
             [--proton[=VER]|--mkxp[=DIR]] GAMEDIR CMD...
sandbox-game --stop NAME | --stop-all
sandbox-game --list | --reset-install NAME | --delete NAME
```

`sandbox-game --help` lists the options. With bash-completion, Tab completes
them too, along with running sandboxes after `--stop`, Proton installs after
`--proton=`, and the command: type `/game/` and it lists the game's folder, as
the sandbox will see it.

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
| `--net` | internet access, and only that; see [Network](#network) |
| `--host-x11` | use the host X server; permits observing/controlling other X clients, mutually exclusive with `--wayland` and `--gamescope` |
| `--headless` | no display sockets, compositor or GPU devices; mutually exclusive with display flags |
| `--mangohud` | the MangoHud overlay. Exporting `MANGOHUD=1` opts in identically. |
| `--gamescope[=ARGS]` | run inside gamescope's nested compositor (default for X11 games); `ARGS` is word-split, so quote the lot |
| `--proton[=VER]` | run `CMD` as a Windows program; the sandbox cwd becomes the `.exe`'s own directory, since games routinely load assets relative to it |
| `--mkxp[=DIR]` | run an RGSS game natively under mkxp-z |
| `--env K=V` | set a variable inside the sandbox; repeatable, applied last so it wins |
| `--ro SRC DST` | bind something else in read-only |
| `--print-name` | print the sandbox name for a directory and exit |
| `--list-proton` | list the Proton installs found, newest first |
| `--stop NAME` | end a running sandbox and everything in it (the game, Wine, anything attached); for a game that hangs or holds on to the screen. Names as `sandbox-attach --list` shows them. The launch it ends exits cleanly, so no failure dialog. |
| `--stop-all` | the same, for every running sandbox |
| `--list` | every sandbox: size, time played, when last played, whether running |
| `--reset-install NAME` | discard what the game changed in its install folder; see [Managing sandboxes](#managing-sandboxes) |
| `--delete NAME` | delete a sandbox, saves and all |

## Attaching to a running game

Cheat Engine, `regedit` and `winetricks` are only useful if they can see the
game — which means the same Wine session, not merely the same prefix on disk.
Launching a second sandbox does not give you that: `--unshare-all` hands every
launch its own PID and mount namespace, so the new process cannot see the game's
processes, and Wine's server socket lives in `/tmp/.wine-$UID`, a tmpfs private
to each sandbox. Same prefix, second wineserver, no contact.

`sandbox-attach` joins the running sandbox's namespaces instead of creating new
ones. No root: the user namespace is already yours to enter.

### Cheat Engine

Unpack a portable Cheat Engine once into the shared tools folder:

```
~/.local/share/sandbox-game/tools/
└── Cheat Engine/
    ├── cheatengine-x86_64.exe
    └── ...
```

Every sandbox started from then on has that folder read-only at `/tools`, so
one copy serves the whole library. Then, with the game running:

```sh
sandbox-attach
```

With no program named, it starts `cheatengine-x86_64.exe` from the tools folder
(or `cheatengine-i386.exe` if that is all there is), searched up to three
levels deep, so the subfolder can be called anything. With one game running it
attaches to that; with several it asks which. In Cheat Engine, open the process
list (the computer icon) and pick the game.

Read-only is deliberate: a game that could write to a folder every sandbox
shares could plant code in a tool that later runs inside every other game's
sandbox. Games started before the folder existed don't have it, and
`sandbox-attach` says to restart them. `SANDBOX_TOOLS_DIR=/path` moves the
folder; set it for `sandbox-game` and `sandbox-attach` alike.

### Anything else

```sh
sandbox-attach --list                       # what is running
sandbox-attach --name witcher3 ~/game-sandboxes/witcher3/home/regedit-fix.exe
sandbox-attach --shell                      # a shell inside, to look around
```

| Option | |
|---|---|
| `--list` | the running sandboxes: name, pid, and whether Proton is in play |
| `--name NAME` | which one to attach to; without it, the only one running, or a menu of them |
| `--shell` | an interactive shell inside, to look around |
| `--exec CMD...` | run a native Linux command inside instead of a Windows one |

Host paths under `~/game-sandboxes/<name>/home/` and the tools folder are
translated to where they appear inside (`$HOME` and `/tools`), so you can paste
the host path. The capture home is live: anything copied into it shows up in
the running game at once.

Windows programs are started with Proton's own `wine` binary against the live
prefix, deliberately **not** with `proton run` — that verb re-enters prefix
setup, which has no business touching a prefix a game is currently using, and in
practice it exits silently without starting anything.

The attached program is as confined as the game: it joins the sandbox's network
namespace too, so it has loopback and nothing else.

CE's kernel-mode features — DBVM, the driver — do not work under Wine;
scanning, pointer maps and speedhack do.

On a distribution with the Yama LSM set to `ptrace_scope=1`, a sibling process
may not ptrace the game, which is how Wine reads its memory. Check with
`sysctl kernel.yama.ptrace_scope`; absent or `0` is what this needs.

## What lands where

```
~/game-sandboxes/<name>/
├── home/       writes to $HOME — configs, saves, whatever it scatters
├── rw/         writes into the install directory at /game
├── compat/     --proton: the Wine prefix, under pfx/
├── mkxp.json   --mkxp: the runtime config, yours to edit
├── machine-id  the game's own stand-in for /etc/machine-id
└── playtime    one line per launch: when it started, seconds played
```

### Managing sandboxes

```sh
sandbox-game --list
NAME                                SIZE    PLAYED  LAST PLAYED      STATE
some-game                           1.2G    3h 12m  2026-09-24 18:10 running
```

`SIZE` is what `du` says, which counts blocks shared between games — Proton
files reflinked on XFS or btrfs — once for each of them.

`--reset-install NAME` is for after updating a game. Everything the game wrote
into its own install folder lives in `rw/`, and shadows the install beneath it:
left there, an old copy of a file would hide the updated one. This throws `rw/`
away, and lists what goes first, but keeps any `save` folder in it (RPG Maker
MV and MZ keep their saves inside the install, in `www/save` or `save`), and
leaves `home/` and the Wine prefix alone.

`--delete NAME` removes the whole capture folder; the game's preferences stay.
Both refuse while the game runs, and ask first when run in a terminal.

`mkxp.json` is generated from the runtime's own commented one on first launch
and then left alone, so per-game tweaks — a soundfont, RTP paths, `fontSub` —
survive the next start.

The host environment is cleared. The launcher supplies `HOME`, user names, a
fixed `/usr/bin:/bin` search path, private XDG directories, locale/timezone/terminal
settings and the selected display variables. Tokens, session-bus addresses and
loader overrides are not inherited; pass necessary game-specific settings with
`--env KEY=VALUE`. Variables read on the host still work: the runtime
discovery ones (`PROTON_DIR`, `MKXP_DIR`, `NWJS_DIR`), `SANDBOX_TOOLS_DIR` and
`SANDBOX_SECCOMP`, and `MANGOHUD=1` still selects the overlay.

The default display exposes the Wayland socket for gamescope, which supplies a
private Xwayland server. Native `--wayland` exposes no host X socket or cookie,
including for Proton: builds lacking winewayland must use gamescope instead.
`--host-x11` exposes the host X socket and cookie and does not expose Wayland.
`--headless` exposes neither. No session D-Bus socket is provided.

`/dev` and its shared memory are private. Graphical modes expose GPU devices only
(`/dev/dri` and available NVIDIA device nodes). Host input, camera, sound and
terminal devices are not exposed; controllers requiring raw device access are
currently unavailable. Sound goes through a Pulse socket; see [Sound](#sound).
`~/.config/MangoHud` is mounted read-only under `--mangohud`.

`/etc`, `/sys` and `/proc` come from the host, minus what identifies the
machine. Each game gets a `machine-id` of its own (which engines such as Unity
turn into a device ID), stable across launches; the hostname is `localhost`
and the boot ID is fresh every launch. MAC addresses, disk, NVMe, USB and
battery serials, controller Bluetooth addresses, `/etc/fstab` and the SSH host
keys read as empty. A game that had already run before this existed keeps
seeing the real machine-id, in case it keyed its saves to it; delete its
`machine-id` file to give it a fresh one.

## Network

Off by default. `--net`, or **Network** in the preferences dialog, gives a game
the internet and nothing else:

- It keeps its own network namespace. `pasta` connects that to the internet
  from outside, through ordinary sockets of yours; no port on this machine is
  forwarded in, and nothing comes in from outside.
- Routing rules refuse IPv4's private, shared and link-local space, IPv6's
  link-local space, every address this machine has, and the whole network
  behind each network card, IPv6 prefixes included. So neither the LAN, the
  router's admin page nor a service listening on this machine is reachable.
  The game cannot lift them: they sit in a namespace it has no privileges
  over. Tunnels (a VPN, a proxy in tun mode such as mihomo) are left open
  beyond this machine's own address on them, since what lies behind one is
  the internet, and a fake-IP proxy hands out private IPv6 addresses for
  ordinary sites.
- The CA certificates are mounted too, wherever the distribution keeps them,
  so HTTPS can be verified.
- DNS goes to `169.254.1.1`, which `pasta` forwards to your usual resolver —
  whether that is `127.0.0.53` or the router.
- The sandbox waits for all of that before the game starts, and if any step
  fails the game does not start at all.

`pasta` runs from a copy named after the game — `<name>-pasta`, or
`<name>-pasta.avx2` on CPUs that run its AVX2 build, which is most — kept in
`$XDG_RUNTIME_DIR/sandbox-game/`. A proxy that routes by process can tell games
apart by it; mihomo goes by the executable's file name, so for example:

```yaml
rules:
  - PROCESS-NAME,some-game-pasta.avx2,DIRECT          # one game
  - PROCESS-NAME-REGEX,-pasta(\.avx2)?$,SandboxProxy  # every other sandboxed game
```

`<name>` is the sandbox name, as `sandbox-attach --list` shows it. The copies
are left in place between launches, so a rule never meets a running `pasta`
whose file has gone (`... (deleted)`); they go at logout with the rest of the
runtime directory.

What it does not do: stop the game talking to whatever it likes on the
internet, or sending off what it can read — its own capture folder and the
hardware details listed above, less the identifiers already hidden. Give it to
games that need it, not by default.

## Sound

By default a game gets the desktop's own PipeWire and Pulse sockets, and with
them everything a sound server client can do: record every microphone and
everything playing (a "Monitor of …" source), change volumes, and **load Pulse
modules**, which pipewire-pulse runs with its own rights outside the sandbox.
`module-rtp-send`, `module-tunnel-sink` or `module-roc-sink` would carry audio —
or anything encoded as audio — to any address on the network, from a game that
has none; `module-native-protocol-tcp` would open the sound server to the LAN.

`./install.sh --restrict-audio` makes it playback only:

- **A sound server of the games' own.** A second pipewire-pulse,
  `sandbox-pulse.service`, with one socket and module loading switched off —
  that switch only exists for a whole server, and the desktop's may want it.
  Everything connecting to it gets an access class of its own,
  `sandbox-game`. The game gets this socket alone, where Pulse clients look
  for one, and no PipeWire socket.
- **Nothing to record.** WirePlumber hides every source and microphone, the
  monitor ports of every sink and the link factory from `sandbox-game`
  clients. Hiding alone would not do: WirePlumber links a recording stream to
  the default source on the client's behalf, with its own rights. So a hook
  (`deny-restricted-capture.lua`) refuses a game's recording streams outright,
  failing them at once as if there were no microphone. It is loaded as
  required: if it ever fails to load, WirePlumber does not start, rather than
  games quietly regaining the microphone.

Playback is unaffected for anything that speaks Pulse: SDL, OpenAL (mkxp-z),
Wine and Proton, Chromium (NW.js), FMOD. A game that talks to ALSA and nothing
else stays silent — ALSA's default goes through the PipeWire socket, and
openSUSE's `alsa-plugins-pulse` conflicts with `pipewire-alsa`. Other apps'
playback streams stay visible by name, though not recordable. Nothing else is
affected: the rules match the `sandbox-game` class alone, and what WirePlumber
allows any other client — the stock `restricted` class included — is left as
it was.

What goes where: `~/.config/pipewire/sandbox-pulse.conf`,
`~/.config/systemd/user/sandbox-pulse.service`,
`~/.config/wireplumber/wireplumber.conf.d/60-sandbox-audio.conf` and
`~/.local/share/wireplumber/scripts/sandbox-game/deny-restricted-capture.lua`,
all from `audio/` in this repository. Without the server running, games fall
back to the desktop's sockets, with a warning in the launch log.

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
a `bwrap` under gamescope too — its image loader trying to sandbox itself.

**Memory and task limits.** The sandbox runs in a transient systemd scope,
`sandbox-game-<name>-<pid>.scope`, capped at 80% of RAM and 4096 tasks. That
turns a leak or a fork bomb into a dead game instead of a frozen desktop, and
gives you a handle on it:

```sh
systemctl --user list-units 'sandbox-game-*'
systemctl --user status sandbox-game-<name>-<pid>.scope   # memory and task use
```

To end a sandbox, `sandbox-game --stop NAME` is simpler and works without
systemd too.

`sandbox-attach` puts the program it brings in under the same filter, and into
the same scope when there is one.

RPG Maker MV/MZ runs with Chromium's own sandbox switched off (`--no-sandbox`).
It gives up nothing: Chromium builds that sandbox from the user namespaces
forbidden here, and a page with Node.js in it could not be sandboxed anyway,
since it can open files and start programs. NW.js 0.110 runs the same without
the flag — none of its processes carry a seccomp filter beyond this one — so
it is passed only so that no build goes looking for a setuid helper.

## Preferences file format

```
~/.config/sandbox-game/games/<name>   per game — wins
~/.config/sandbox-game/defaults       library-wide fallback
```

Plain `key=value`, read rather than sourced, and meant to be edited by hand:

```ini
wayland=0|1
mangohud=0|1
net=0|1
gamescope=0|1
host_x11=0|1
gamescope_args=-f -W 2560 -H 1440
env=WAYLANDDRV_PRIMARY_MONITOR=HDMI-1 SOME_OTHER=value
proton=auto|<install name>
```

The key is the sandbox name, so preferences and captured writes stay in step.
Two games whose folders have the same name share a sandbox; give one of them
`--name`, or an entry in `NAME_MAP` at the top of `sandbox-game`, to separate
them.

`host_x11=1` opts into the host X server and overrides the Wayland/gamescope
choices. `gamescope=0` means automatic: X11 games still use a private gamescope
instance unless `host_x11=1`. Resolution and fullscreen get a dialog; anything
else in `gamescope_args`, and all of `env`, is set by hand and carried through
saves untouched. `env` values cannot contain spaces — the list is split on
them.

`env` explicitly adds variables to the clean sandbox environment, including
when launching from the file manager.

## Known rough edges

**RPG Maker MV/MZ on native Wayland runs without a D-Bus session bus.** The
sandbox never provides one: it would open the keyring, the portals and gvfs to
the game. NW.js 0.110 and 0.116 both run on Wayland without it, but one game
(unrecorded) was once seen to segfault at startup on Wayland for want of a bus,
while X11 was fine. If a game does that, set its video backend back to private
Xwayland.

**MangoHud is off for RPG Maker MV/MZ.** Its GL shim is `LD_PRELOAD`ed into
every child, and Chromium spawns a zygote and its own renderer processes — the
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
filtering, the read-only tools folder and namespace attachment; display and
audio argument checks use recorders so they do not open windows or play sound.

They run without the systemd scope, because their private runtime directory
hides the user manager. The exception is the check that commands reach the
game unaltered by `systemd-run`, which uses the real one, and skips when no
user manager is reachable rather than pass having tested nothing.
