#!/bin/bash
# desktop-gpu-check.sh [--keep-setup] [RESULTS]: what the systemd backend
# does with a real GPU, next to the default backend.
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
set -u
here="$(cd "$(dirname "$(realpath "$0")")" && pwd)"
checkout="$(dirname "$here")"
keep=0
[ "${1:-}" = --keep-setup ] && { keep=1; shift; }
results="${1:-$checkout/.gpu-check/$(date +%Y%m%d-%H%M%S)}"

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
  - run vulkaninfo, eglinfo, vkcube and gamescope as throwaway games under
    both backends; a few windows open for a few seconds each
  - keep its logs in $results
Stop your games first. Press Enter to go on, Ctrl-C to stop.
EOF
read -r _

# What there is to compare with.
{
    echo "== $(date -Is)"; uname -a; grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release
    systemctl --version | head -1
    rpm -q systemd systemd-container gamescope Mesa Mesa-vulkan-device-select libvulkan1 \
        mesa-demos vulkan-tools 2>&1
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
remove_setup() {
    if [ "$keep" = 0 ] && [ "$installed_before" = 0 ] && [ -e /etc/sandbox-game/systemd-backend.json ]; then
        echo "Removing the administrator setup again..."
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
gl_renderer() { grep -m1 -E 'OpenGL renderer string' "$1" | sed 's/.*: *//'; }

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
        note "egl: $(gl_renderer "$results/eglinfo-$backend.log"), $(tail -1 "$results/eglinfo-$backend.log")"
    else
        note "egl: skipped, no eglinfo (mesa-demos)"
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
