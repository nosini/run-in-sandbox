#!/bin/bash
# desktop-gpu-check.sh [--keep-setup] [--game PATH [--name NAME]]... [RESULTS]:
# what the systemd backend does with a real GPU, next to the default backend.
#
# Run it from this checkout in your Wayland desktop session, as yourself,
# with no games running. It installs the administrator setup with sudo
# (see README.md here), runs the same graphics programs as games under
# SANDBOX_SEPARATE_UID=0 and =systemd -- Vulkan and EGL device reports,
# vkcube in a window of its own and inside gamescope -- and removes the
# setup again, unless it was there before or --keep-setup is given.
#
# Nothing of your per-user installation, settings or games is used: the
# games are throwaway folders, their captures in a scratch home that goes
# at the end. The logs stay in RESULTS, by default .gpu-check/DATE in this
# checkout (git ignores it). Windows open for a few seconds each.
#
# With --game, real games instead, one after the other: PATH is what you
# would right-click for "Sandbox game", and it is launched as that does,
# with that game's preferences, but under the systemd backend and in a
# capture of its own, NAME-systemd-test. The game's own capture is not
# touched, nor is its folder. NAME is its sandbox's name, when that is not
# the one its folder gives (one the manager renamed, say). Play a little,
# then quit the game as usual.
set -u
here="$(cd "$(dirname "$(realpath "$0")")" && pwd)"
checkout="$(dirname "$here")"
keep=0 results="" games=() names=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --keep-setup) keep=1; shift ;;
        --game) [ "$#" -ge 2 ] || { echo "--game needs a path" >&2; exit 1; }
                games+=( "$2" ); names+=( "" ); shift 2 ;;
        --name) [ "$#" -ge 2 ] && [ "${#games[@]}" -gt 0 ] \
                    || { echo "--name goes after the --game it names" >&2; exit 1; }
                names[${#names[@]}-1]="$2"; shift 2 ;;
        -*) echo "unknown option: $1" >&2; exit 1 ;;
        *) results="$1"; shift ;;
    esac
done
results="${results:-$checkout/.gpu-check/$(date +%Y%m%d-%H%M%S)}"

die() { echo "desktop-gpu-check: $*" >&2; exit 1; }
[ "$(id -u)" != 0 ] || die "run it as yourself, not as root; it asks for sudo itself"
[ -n "${WAYLAND_DISPLAY:-}" ] && [ -n "${XDG_RUNTIME_DIR:-}" ] \
    || die "run it in your Wayland desktop session (WAYLAND_DISPLAY is not set)"
[ "$(id -g)" = "$(id -u)" ] \
    || die "your primary group is not your uid's number; see \"Your account's group\" in $here/README.md"
compgen -G '/dev/dri/renderD*' >/dev/null || die "no /dev/dri/renderD* here: no GPU to test"

mkdir -p "$results" || die "cannot make $results"
results="$(realpath "$results")"
scratch="$(mktemp -d "${XDG_CACHE_HOME:-$HOME/.cache}/sandbox-gpu-check.XXXXXX")" \
    || die "cannot make a scratch folder"
summary="$results/summary.txt"
: > "$summary"
note() { printf '%s\n' "$*" | tee -a "$summary"; }
have() { command -v "$1" >/dev/null; }

cat <<EOF
This will:
  - install the systemd backend's administrator setup with sudo, for uid $(id -u)
    (sockets for systemd-nsresourced/-mountfsd, a SELinux module, the render
    device helper and its udev rule); removed again at the end
  - $(if [ "${#games[@]}" = 0 ]; then
        echo "run vulkaninfo, eglinfo, vkcube and gamescope as throwaway games under
    both backends; a few windows open for a few seconds each"
      else
        echo "launch ${#games[@]} game(s) of yours under the systemd backend, each in a
    capture of its own (NAME-systemd-test); play a little, then quit it"
      fi)
  - keep its logs in $results
Stop your games first. Press Enter to go on, Ctrl-C to stop.
EOF
read -r _

# What there is to compare with.
{
    echo "== $(date -Is)"; uname -a; grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release
    systemctl --version | head -1
    rpm -q systemd systemd-container gamescope Mesa Mesa-vulkan-device-select libvulkan1 \
        Mesa-demo-egl Mesa-demo-x vulkan-tools 2>&1
    getenforce 2>/dev/null || echo "no getenforce"
    lspci -nnk 2>/dev/null | grep -A3 -E 'VGA|3D|Display'
    ls -l /dev/dri
    for unit in systemd-nsresourced.socket systemd-mountfsd.socket; do
        echo "$unit: $(systemctl is-enabled "$unit" 2>&1) $(systemctl is-active "$unit" 2>&1)"
    done
} > "$results/system.txt" 2>&1
note "system: $(grep PRETTY_NAME "$results/system.txt" | cut -d= -f2), $(grep -m1 '^systemd [0-9]' "$results/system.txt")"

# The administrator setup, and its removal however this ends.
installed_before=0 tidy=1
[ -e /etc/sandbox-game/systemd-backend.json ] && installed_before=1
# The uninstaller keeps the user list and leaves the helper's folder; what
# this made, it takes away too.
[ -e /etc/sandbox-game ] || [ -e /usr/local/libexec/sandbox-game ] && tidy=0
pending=()
remove_setup() {
    # A game cut short is redacted all the same.
    [ "${#pending[@]}" = 0 ] || redact "${pending[@]}"
    if [ "$keep" = 0 ] && [ "$installed_before" = 0 ] && [ -e /etc/sandbox-game/systemd-backend.json ]; then
        echo "Removing the administrator setup again..."
        # nsresourced lets go of a game's namespace a moment after the game
        # is gone, and the uninstaller refuses while one is registered.
        local try
        for try in $(seq 12); do
            sudo sh -c 'ls /run/systemd/nsresource/registry/*.userns' >/dev/null 2>&1 || break
            [ "$try" = 1 ] && echo "Waiting for the games' namespaces to go..."
            sleep 5
        done
        if (cd "$checkout" && sudo ./install.sh --uninstall-systemd-backend) >> "$results/setup.txt" 2>&1; then
            note "setup: removed again"
            if [ "$tidy" = 1 ]; then
                sudo rm -f /etc/sandbox-game/systemd-render-users
                sudo rmdir /etc/sandbox-game /usr/local/libexec/sandbox-game 2>/dev/null
            fi
        else
            note "setup: REMOVAL FAILED, see setup.txt; run: sudo ./install.sh --uninstall-systemd-backend"
        fi
        for unit in systemd-nsresourced.socket systemd-mountfsd.socket; do
            echo "$unit after: $(systemctl is-enabled "$unit" 2>&1) $(systemctl is-active "$unit" 2>&1)"
        done >> "$results/setup.txt"
    fi
    rm -rf "$scratch"
}
trap remove_setup EXIT
trap 'exit 130' INT TERM
if (cd "$checkout" && sudo ./install.sh --systemd-backend "$(id -u)") > "$results/setup.txt" 2>&1; then
    note "setup: installed"
else
    note "setup: FAILED, see setup.txt"
    exit 1
fi
ls -l "/run/sandboxgame/render/$(id -u)" >> "$results/setup.txt" 2>&1
"$checkout/sandbox-uid" managed-available >> "$results/setup.txt" 2>&1 \
    || { note "backend: not available, see setup.txt"; exit 1; }

# Real games, launched as "Sandbox game" launches them.
game_check() { # LABEL SELECTION NAME
    local label="$1" sel gamedir real test cfg capture copied=0 watcher status users
    shift
    sel="$(realpath "$1")" || { note "game: $1 not found"; return; }
    gamedir="$(. "$checkout/sandbox-game-lib" && resolve_selection "$sel" && printf '%s' "$R_GAMEDIR")"
    real="${2:-$("$checkout/sandbox-game" --print-name "$gamedir")}"
    test="$real-systemd-test"
    pending=( "$label" "$sel" "$gamedir" "$real" "$test" )   # see remove_setup
    capture="$HOME/game-sandboxes/$test"
    cfg="${XDG_CONFIG_HOME:-$HOME/.config}/sandbox-game/games"
    note ""
    note "== $label"
    note "preferences: $([ -f "$cfg/$real" ] && echo "the game's own" || echo "defaults (none saved for it)")"
    if [ -f "$cfg/$real" ] && [ ! -e "$cfg/$test" ]; then
        cp "$cfg/$real" "$cfg/$test" && copied=1
    fi
    echo "Starting $gamedir under the systemd backend. Play a little, then quit it."
    # Once it is up and drawing: which render node it got, and what of it has
    # one open -- seen from inside, by a program attached to it.
    # Every 5 seconds while it runs; the last look that found the GPU open
    # is kept, else the last one at all.
    (
        inside="$results/$label-inside.log"
        for _ in $(seq 720); do
            sleep 5
            "$checkout/sandbox-attach" --name "$test" --exec -- /bin/sh -c '
                ls -ln /dev/dri/renderD* 2>&1 | sed "s/^/render node: /"
                for p in /proc/[0-9]*; do
                    if ls -l "$p/fd" 2>/dev/null | grep -q /dev/dri/renderD; then
                        echo "has the GPU open: $(cat "$p/comm") (pid ${p#/proc/})"
                    fi
                done' > "$inside.new" 2>> "$results/$label-attach-errors.log" || continue
            if grep -q '^has the GPU open' "$inside.new" || ! grep -q '^has the GPU open' "$inside" 2>/dev/null; then
                mv -f "$inside.new" "$inside"
            fi
        done
    ) &
    watcher=$!
    NAUTILUS_SCRIPT_SELECTED_FILE_PATHS="$sel" SANDBOX_BACKEND="$checkout/sandbox-game" \
        SANDBOX_GAME_NAME="$test" SANDBOX_SEPARATE_UID=systemd "$checkout/Sandbox game"
    status=$?
    pkill -P "$watcher" 2>/dev/null; kill "$watcher" 2>/dev/null; wait "$watcher" 2>/dev/null
    rm -f "$results/$label-inside.log.new"
    [ "$copied" = 0 ] || rm -f "$cfg/$test"
    cp "$capture/lastrun.log" "$results/$label-lastrun.log" 2>/dev/null
    note "exit: $status"
    note "$(grep -m1 '^render node: ' "$results/$label-inside.log" 2>/dev/null \
            || echo "render node: not seen (the game ended within 5 seconds, or attaching failed)")"
    grep '^has the GPU open: ' "$results/$label-inside.log" 2>/dev/null | tee -a "$summary"
    [ -e "$capture/managed-uid" ] && note "capture: marked for the systemd backend" \
        || note "capture: NOT marked for the systemd backend"
    # On disk the capture stays yours under this backend, owner and group.
    users="$(find "$capture" \( ! -user "$(id -u)" -o ! -group "$(id -u)" \) 2>/dev/null | wc -l)"
    note "capture files not yours, or not your group: $users"
    note "capture size: $(du -sh "$capture" 2>/dev/null | cut -f1)"
    grep -E '^sandbox-(game|uid|landlock): ' "$results/$label-lastrun.log" 2>/dev/null \
        | head -8 | sed 's/^/  /' | tee -a "$summary"
    redact "${pending[@]}"
    pending=()
}
# Which games were tested is nobody else's business: every result file loses
# what names the game -- its folder and sandbox names, the files at its top
# (its .exe among them) -- however they are cased, shortened to a process
# name's 15 characters, or with the characters NW.js's launcher replaces.
redact() { # LABEL SELECTION GAMEDIR NAME...
    python3 -I - "$results" "$@" <<'PY'
import os, re, sys
results, label, sel, gamedir, *names = sys.argv[1:]
# Folder and file names any game might have, which say nothing about it.
COMMON = {"data", "game", "games", "www", "lib", "lib64", "bin", "save", "saves",
          "audio", "img", "js", "fonts", "movies", "locales", "resources", "package.json",
          "index.html", "readme", "readme.txt", "license", "license.txt", "start.sh",
          "game.exe", "nw", "nw.exe", "icon", "icon.png", "credits", "credits.txt", "steam",
          "swiftshader", "plugins", "content", "engine", "mono", "monobleedingedge"}
words = {sel, gamedir, os.path.basename(sel), os.path.basename(gamedir), *names}
try:
    words |= set(os.listdir(gamedir))
except OSError:
    pass
tokens = set()
for word in words:
    for w in (word, os.path.splitext(word)[0], re.sub(r"[^A-Za-z0-9._-]", "_", word)):
        if w in (sel, gamedir) or (len(w) >= 4 and w.lower() not in COMMON):
            tokens.add(w)
            if len(w) > 15:
                tokens.add(w[:15])          # a process's name in /proc/PID/comm
tokens = sorted((t for t in tokens if len(t) >= 4), key=len, reverse=True)
if not tokens:
    sys.exit()
pattern = re.compile("|".join(map(re.escape, tokens)), re.IGNORECASE)
for name in os.listdir(results):
    path = os.path.join(results, name)
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        text = f.read()
    new = pattern.sub(f"<{label}>", text)
    if new != text:
        with open(path, "w", encoding="utf-8", errors="surrogateescape") as f:
            f.write(new)
PY
}
if [ "${#games[@]}" -gt 0 ]; then
    for i in "${!games[@]}"; do
        game_check "game$((i + 1))" "${games[$i]}" "${names[$i]}"
    done
    note ""
    note "Test captures are kept in ~/game-sandboxes/*-systemd-test for another run;"
    note "remove each with: sandbox-game --delete NAME-systemd-test"
    remove_setup
    trap - EXIT
    note "Logs: $results"
    echo
    echo "Done. Tell the agent the results are in $results"
    exit 0
fi

# One throwaway game per backend, so that neither switches the other's capture.
mkdir -p "$scratch/home" "$scratch/games/backend-0" "$scratch/games/backend-systemd"
run() { # NAME BACKEND DISPLAY-OPTION COMMAND...
    local name="$1" backend="$2" display="$3"; shift 3
    local log="$results/$name-$backend.log"
    env HOME="$scratch/home" XDG_CONFIG_HOME="$scratch/home/.config" \
        XDG_DATA_HOME="$scratch/home/.local/share" SANDBOX_TOOLS_DIR="$scratch/tools" \
        SANDBOX_SEPARATE_UID="$backend" \
        timeout 120 "$checkout/sandbox-game" "$display" "$scratch/games/backend-$backend" \
        /bin/sh -c "ls -ln /dev/dri/renderD* 2>&1 | sed 's/^/render node: /'; $*" > "$log" 2>&1
    local status=$?
    echo "exit: $status" >> "$log"
    return "$status"
}
# What each log says about the device, in a line.
vk_device() { grep -m1 -E 'deviceName' "$1" | sed 's/.*= *//'; }
vk_type() { grep -m1 -E 'deviceType' "$1" | sed 's/.*= *//'; }
gl_renderer() { grep -m1 -E 'OpenGL (renderer string|core profile renderer)' "$1" | sed 's/.*: *//'; }

for backend in 0 systemd; do
    note ""
    note "== SANDBOX_SEPARATE_UID=$backend"
    if have vulkaninfo; then
        run vulkaninfo "$backend" --wayland vulkaninfo --summary
        note "vulkan: $(vk_device "$results/vulkaninfo-$backend.log") ($(vk_type "$results/vulkaninfo-$backend.log")), $(tail -1 "$results/vulkaninfo-$backend.log")"
    else
        note "vulkan: skipped, no vulkaninfo (vulkan-tools)"
    fi
    if have eglinfo; then
        run eglinfo "$backend" --wayland eglinfo -B
        # GBM and X11 fail by design (no card node, no X server), so its exit is 2.
        note "egl: $(gl_renderer "$results/eglinfo-$backend.log"), $(tail -1 "$results/eglinfo-$backend.log")"
    else
        note "egl: skipped, no eglinfo (Mesa-demo-egl)"
    fi
    if have vkcube; then
        run vkcube-wayland "$backend" --wayland vkcube --c 300 --wsi wayland
        note "vkcube (wayland): $(grep -m1 'Selected' "$results/vkcube-wayland-$backend.log"), $(tail -1 "$results/vkcube-wayland-$backend.log")"
        if have gamescope; then
            run gamescope "$backend" --gamescope vkcube --c 300 --wsi xcb
            note "vkcube in gamescope: $(grep -m1 'Selected' "$results/gamescope-$backend.log"), $(tail -1 "$results/gamescope-$backend.log")"
            note "gamescope device: $(grep -m1 'selecting physical device' "$results/gamescope-$backend.log" | sed 's/.*vulkan:[^ ]* //')"
            sed 's/\x1b\[[0-9;]*m//g' "$results/gamescope-$backend.log" \
                | grep -E 'Error|Warn.*(drm|DRM|card|render)|Assertion|failed' \
                | head -5 | sed 's/^/  gamescope: /' | tee -a "$summary"
        else
            note "gamescope: skipped, not installed"
        fi
    else
        note "vkcube: skipped, no vkcube (vulkan-tools)"
    fi
    if have glxinfo && have gamescope; then
        run glxinfo-gamescope "$backend" --gamescope glxinfo -B
        note "GL in gamescope's Xwayland: $(gl_renderer "$results/glxinfo-gamescope-$backend.log"), $(tail -1 "$results/glxinfo-gamescope-$backend.log")"
    fi
    # Under the systemd backend the game's render node is the helper's copy,
    # yours and 0600, and the capture is marked as that backend's.
    note "render node in the game: $(grep -h -m1 '^render node: ' "$results"/*-"$backend".log | head -1 | sed 's/^render node: //')"
    capture="$scratch/home/game-sandboxes/backend-$backend"
    if [ -e "$capture/managed-uid" ]; then
        note "capture: marked for the systemd backend"
    else
        note "capture: not marked for the systemd backend"
    fi
done

# The project's own probe, which insists on the hardware path, if it can be built.
note ""
missing=""
for tool in gcc pkg-config weston pipewire wireplumber pactl dbus-run-session wayland-scanner; do
    have "$tool" || missing="$missing $tool"
done
if [ -z "$missing" ]; then
    probe="$scratch/m"
    dbus-run-session -- python3 -I "$checkout/experiments/systemd-media.py" --work-dir "$probe" \
        --device-dir "/run/sandboxgame/render/$(id -u)" --require-hardware \
        > "$results/media-probe.log" 2>&1
    status=$?
    note "hardware media probe: exit $status ($(grep -m1 -oE 'EGL device: renderer=[^;]*; software=[a-z]+; render_node=[[:alnum:]/]+' "$results/media-probe.log"))"
else
    note "hardware media probe: skipped, missing:$missing (and their -devel packages)"
fi

remove_setup
trap - EXIT
note ""
note "Logs: $results"
echo
echo "Done. Tell the agent the results are in $results"
