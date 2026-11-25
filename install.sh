#!/usr/bin/env bash
# install.sh [--restrict-audio | --uninstall]
# sudo ./install.sh --systemd-backend UID...
# sudo ./install.sh --uninstall-systemd-backend
# sudo ./install.sh --selinux | --uninstall-selinux
#   Install sandbox-game and sandbox-attach into ~/.local/bin, their helpers
#   (sandbox-seccomp, sandbox-landlock, sandbox-game-lib, nwjs-casefold.js) into
#   ~/.local/lib/sandbox-game, and the Nautilus scripts, for the current user.
#   No root needed; nothing outside ~/.local is touched.
#   The separate --systemd-backend mode installs administrator services and
#   GPU grants for the given host UIDs; it does not install per-user files.
#   --selinux loads the SELinux policy module in selinux/, which confines the
#   pasta that --net starts to a domain of its own; --uninstall-selinux
#   removes it. Neither touches per-user files either.
#
#   --restrict-audio also sets up playback-only sound for the games: a second
#   Pulse server of their own, and WirePlumber rules and a hook that keep them
#   from recording (see audio/sandbox-pulse.conf). That changes your sound
#   setup beyond ~/.local -- files in ~/.config/pipewire, ~/.config/wireplumber
#   and ~/.config/systemd/user, and a WirePlumber restart -- so it is asked for.
#
#   Run from a checkout, it installs that checkout. Run on its own -- as in
#     curl -fsSL https://raw.githubusercontent.com/nosini/run-in-sandbox/main/install.sh | bash
#   -- it downloads the branch named by $REF (default main) first. A root run
#   without a checkout needs REF to name a full commit hash or release tag.
#
#   Running it again updates in place. --uninstall removes the installed
#   scripts, and the sound setup if it is there, and leaves everything else
#   alone: ~/game-sandboxes (saves, Wine prefixes), your preferences and the
#   shared tools folder.
set -euo pipefail

REPO="https://github.com/nosini/run-in-sandbox"
REF="${REF:-main}"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
BIN="$HOME/.local/bin"
# Private helpers: nothing anyone runs by hand, so not on PATH. sandbox-game
# looks here after its own folder (see helper() there).
HELPERS="$HOME/.local/lib/sandbox-game"
SCRIPTS="$DATA/nautilus/scripts"
# Must match sandbox-game's default, which mounts this folder at /tools.
TOOLS="${SANDBOX_TOOLS_DIR:-$DATA/sandbox-game/tools}"
CONF="${XDG_CONFIG_HOME:-$HOME/.config}"

# Runs "$@" MODE NAME DEST once per installed file. The lib is 644 and kept
# out of the scripts dir: Nautilus lists everything there as a menu entry.
each() {
    "$@" 755 sandbox-game             "$BIN"
    "$@" 755 sandbox-attach           "$BIN"
    "$@" 755 sandbox-manager          "$BIN"
    "$@" 755 sandbox-seccomp          "$HELPERS"
    "$@" 755 sandbox-landlock         "$HELPERS"
    "$@" 755 sandbox-uid              "$HELPERS"
    "$@" 644 sandbox-game-lib         "$HELPERS"
    "$@" 755 sandbox-game-dialog      "$HELPERS"
    "$@" 644 sandbox-manager-lib.py   "$HELPERS"
    "$@" 755 sandbox-game-icon        "$HELPERS"
    "$@" 644 nwjs-casefold.js         "$HELPERS"
    "$@" 755 "Sandbox game"             "$SCRIPTS"
    "$@" 755 "Sandbox game preferences" "$SCRIPTS"
    "$@" 755 "Stop sandboxed game"      "$SCRIPTS"
    "$@" 644 eu.nosini.SandboxManager.desktop "$DATA/applications"
}

# Where the helpers used to go, beside sandbox-game on PATH: cleared on every
# install and uninstall, so no stale copy is found first or left behind.
each_old() {
    "$@" - sandbox-seccomp  "$BIN"
    "$@" - sandbox-landlock "$BIN"
    "$@" - sandbox-game-lib "$BIN"
}

# The bash completions, from completions/, where bash-completion looks for a
# user's own: it loads one the first time its command is completed.
each_completion() {
    "$@" 644 sandbox-game   "$DATA/bash-completion/completions"
    "$@" 644 sandbox-attach "$DATA/bash-completion/completions"
}

# The same for --restrict-audio, whose files come from audio/.
each_audio() {
    "$@" 644 sandbox-pulse.conf          "$CONF/pipewire"
    "$@" 644 sandbox-pulse.service       "$CONF/systemd/user"
    "$@" 644 60-sandbox-audio.conf       "$CONF/wireplumber/wireplumber.conf.d"
    "$@" 644 deny-restricted-capture.lua "$DATA/wireplumber/scripts/sandbox-game"
    "$@" 644 sandbox-access.lua          "$DATA/wireplumber/scripts/sandbox-game"
}
# Set to 1 by mark_audio when any of each_audio's files is installed.
AUDIO_PRESENT=0
mark_audio() {
    if [ -e "$3/$2" ] || [ -L "$3/$2" ]; then AUDIO_PRESENT=1; fi
}
# Kept while the audio files and the two restarts are not in step: a failed
# retry then restarts WirePlumber and sandbox-pulse even when every file
# already matches its source. Removed only after both restarts have succeeded.
AUDIO_MARKER="$CONF/sandbox-game/audio-restart-pending"

say()  { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }

# Root piped installs must fetch an immutable source: a branch such as main
# can change between a review and the download. A release tag or full commit
# hash names the same tree every time.
ref_is_pinned() {
    case "$REF" in
        *[!0-9a-f]*) ;;
        *) [ "${#REF}" -eq 40 ] || [ "${#REF}" -eq 64 ] && return 0 ;;
    esac
    [[ "$REF" =~ ^v?[0-9]+(\.[0-9]+)+([._+-][0-9A-Za-z]+)*$ ]]
}

remove_one() {
    [ -e "$3/$2" ] || [ -L "$3/$2" ] || return 0
    rm -f "$3/$2"; say "removed $3/$2"
}
install_one() {
    install -Dm"$1" "$SRC/$2" "$3/$2"; say "installed $3/$2"
    if [ "$2" = eu.nosini.SandboxManager.desktop ]; then
        # Desktop launchers must also work when ~/.local/bin is not on PATH.
        python3 -I - "$3/$2" "$BIN/sandbox-manager" <<'PY'
from pathlib import Path
import re
import sys
path = Path(sys.argv[1])
value = sys.argv[2].replace("%", "%%")
# Quoted only when the desktop entry spec needs it: menu editors take a
# quoted program for a missing one.
if re.search(r"""[\s"'\\><~|&;$*?#()`]""", value):
    for char in ('\\', '"', '`', '$'):
        value = value.replace(char, '\\' + char)
    # Backslashes are escaped once more by the desktop entry string parser.
    value = '"' + value.replace('\\', '\\\\') + '"'
path.write_text(path.read_text().replace('Exec=sandbox-manager', 'Exec=' + value))
PY
    fi
}
install_completion() {
    install -Dm"$1" "$SRC/completions/$2" "$3/$2"; say "installed $3/$2"
}
AUDIO_CHANGED=0
install_audio() {
    cmp -s "$SRC/audio/$2" "$3/$2" && return 0
    install -Dm"$1" "$SRC/audio/$2" "$3/$2"; say "installed $3/$2"
    AUDIO_CHANGED=1
}

# Everything but the explicit administrator modes installs files for the
# current user, under that user's home, so root is the wrong identity for it.
case "${1:-}" in
    --systemd-backend|--uninstall-systemd-backend|--selinux|--uninstall-selinux) ;;
    *)
        if [ "$(id -u)" = 0 ]; then
            echo "this mode installs for the current user; run install.sh as that user, without sudo" >&2
            exit 1
        fi ;;
esac
AUDIO=0
UNINSTALL=0
SYSTEMD_MODE=""
SELINUX_MODE=""
case "${1:-}" in
    --systemd-backend) SYSTEMD_MODE=install; shift ;;
    --uninstall-systemd-backend) SYSTEMD_MODE=uninstall; shift ;;
    --selinux) SELINUX_MODE=install; shift ;;
    --uninstall-selinux) SELINUX_MODE=uninstall; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --restrict-audio) AUDIO=1; shift ;;
esac
if [ -z "$SYSTEMD_MODE" ] && [ "$#" -ne 0 ]; then
    echo "usage: install.sh [--restrict-audio | --uninstall | --systemd-backend UID... | --uninstall-systemd-backend | --selinux | --uninstall-selinux]" >&2
    exit 1
fi
if [ "$UNINSTALL" = 1 ]; then
    each remove_one
    each_old remove_one
    remove_one - sandbox-xwayland-satellite "$HELPERS"
    remove_one - satellite-LICENSE "$HELPERS"
    rmdir "$HELPERS" 2>/dev/null || true
    each_completion remove_one
    rm -f -- "$AUDIO_MARKER"
    AUDIO_PRESENT=0
    each_audio mark_audio
    if [ "$AUDIO_PRESENT" = 1 ]; then
        systemctl --user disable --now sandbox-pulse.service 2>/dev/null || true
        each_audio remove_one
        systemctl --user daemon-reload 2>/dev/null || true
        systemctl --user restart wireplumber 2>/dev/null || true
    fi
    say "left alone: ~/game-sandboxes, ~/.config/sandbox-game, $TOOLS"
    exit 0
fi
if [ -n "$SYSTEMD_MODE" ] && [ "$(id -u)" != 0 ]; then
    echo "the systemd backend administrator setup needs root; rerun this command with sudo" >&2
    exit 1
fi
if [ -n "$SELINUX_MODE" ] && [ "$(id -u)" != 0 ]; then
    echo "loading or removing an SELinux policy module needs root; rerun this command with sudo" >&2
    exit 1
fi
# Once set up, every install keeps it current.
[ ! -e "$CONF/systemd/user/sandbox-pulse.service" ] || AUDIO=1

# ---- find what to install ---------------------------------------------------
# Beside this script when it is in a checkout. Piped into bash there is no
# file at all, so BASH_SOURCE is empty or names a pipe, and nothing is beside it.
SRC=""
here="${BASH_SOURCE[0]:-}"
if [ -n "$here" ] && [ -f "$here" ]; then
    here="$(cd "$(dirname "$here")" && pwd)"
    [ -f "$here/sandbox-game" ] && SRC="$here"
fi
# Removing the SELinux module needs nothing from the source.
if [ -z "$SRC" ] && [ "$SELINUX_MODE" != uninstall ]; then
    if [ "$(id -u)" = 0 ] && ! ref_is_pinned; then
        echo "a root install must download a full commit hash or a release tag; set REF to one, or run install.sh from a checkout" >&2
        exit 1
    fi
    command -v curl >/dev/null || { echo "curl is needed to download" >&2; exit 1; }
    TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
    say "downloading $REPO ($REF)"
    curl --proto '=https' --tlsv1.2 -fsSL "$REPO/archive/$REF.tar.gz" \
        | tar xz -C "$TMP" --strip-components=1 --no-same-owner
    SRC="$TMP"
fi

# Restricted sound relies on the daemon keeping a client to the access class
# of the socket it came through. Older PipeWire lets a Pulse client overwrite
# that class, and with it every rule that makes sound playback only.
if [ "$AUDIO" = 1 ]; then
    pw_version="$(. "$SRC/sandbox-game-lib"; pipewire_version)"
    if [ -z "$pw_version" ]; then
        warn "cannot determine the running PipeWire version; restricted sound needs PipeWire 1.6.6 or later, or a game can bypass it (CVE-2026-5674)"
    elif ! (. "$SRC/sandbox-game-lib"; pipewire_at_least "$pw_version" 1.6.6); then
        warn "PipeWire $pw_version is older than 1.6.6; until PipeWire is updated, a game can bypass the restricted sound (CVE-2026-5674)"
    fi
fi

# ---- install ----------------------------------------------------------------
if [ -n "$SYSTEMD_MODE" ]; then
    python3 -I "$SRC/systemd-backend/install-systemd.py" "$SYSTEMD_MODE" "$@"
    exit
fi
# The policy module for --net's pasta (see selinux/sandbox_pasta.te). Built
# here from its source with the tools semodule comes with, no policy
# development package needed. sandbox-game labels its pasta copies at the next
# launch; one already running stays as it is until its game ends.
if [ "$SELINUX_MODE" = install ]; then
    [ -e /sys/fs/selinux/enforce ] || {
        echo "SELinux is not enabled on this system; the policy module is for systems where it is" >&2
        exit 1; }
    for c in checkmodule semodule_package semodule; do
        command -v "$c" >/dev/null || {
            echo "$c not found (openSUSE: zypper in checkpolicy policycoreutils)" >&2; exit 1; }
    done
    BUILD="$(mktemp -d)"; trap 'rm -rf "$BUILD"' EXIT
    checkmodule -M -m -o "$BUILD/sandbox_pasta.mod" "$SRC/selinux/sandbox_pasta.te"
    semodule_package -o "$BUILD/sandbox_pasta.pp" -m "$BUILD/sandbox_pasta.mod"
    semodule -i "$BUILD/sandbox_pasta.pp"
    say "loaded the SELinux policy module sandbox_pasta: pasta for --net runs as sandbox_pasta_t from each game's next launch"
    exit 0
elif [ "$SELINUX_MODE" = uninstall ]; then
    if command -v semodule >/dev/null && semodule -l | awk '$1 == "sandbox_pasta" { f = 1 } END { exit !f }'; then
        # A pasta still in the domain would be left with a label the policy
        # no longer has, and lose the network it serves.
        labels="$(ps -eo label=)"
        if [[ "$labels" == *:sandbox_pasta_t:* ]]; then
            echo "a game's pasta still runs in sandbox_pasta_t; stop games started with --net first" >&2
            exit 1
        fi
        semodule -r sandbox_pasta
        say "removed the SELinux policy module sandbox_pasta; pasta for --net runs unconfined again"
    else
        say "the SELinux policy module sandbox_pasta is not loaded"
    fi
    exit 0
fi
# The private satellite build travels with its licence; checked before
# anything is installed, so a missing one stops nothing halfway.
SATELLITE=0
if [ -x "$SRC/sandbox-xwayland-satellite" ]; then
    [ -f "$SRC/satellite-LICENSE" ] || {
        echo "sandbox-xwayland-satellite needs satellite-LICENSE beside it; rerun ./get-satellite.sh" >&2
        exit 1; }
    SATELLITE=1
fi
each_old remove_one
each install_one
if [ "$SATELLITE" = 1 ]; then
    install_one 755 sandbox-xwayland-satellite "$HELPERS"
    install -Dm644 "$SRC/satellite-LICENSE" "$HELPERS/satellite-LICENSE"
fi
each_completion install_completion
mkdir -p "$TOOLS"
say "tools folder: $TOOLS (unpack a portable Cheat Engine here)"

if [ "$AUDIO" = 1 ]; then
    mkdir -p "$CONF/sandbox-game"
    audio_retry=0
    [ ! -e "$AUDIO_MARKER" ] || audio_retry=1
    : > "$AUDIO_MARKER"
    each_audio install_audio
    # WirePlumber first: its hook has to be in place before a game can connect.
    # A restart re-links every stream, so expect a moment of silence -- and
    # only when something changed, or a previous run stopped before both
    # restarts had succeeded.
    systemctl --user daemon-reload
    if [ "$AUDIO_CHANGED" = 1 ] || [ "$audio_retry" = 1 ]; then
        systemctl --user restart wireplumber
        systemctl --user enable sandbox-pulse.service
        systemctl --user restart sandbox-pulse.service
        rm -f -- "$AUDIO_MARKER"
    else
        rm -f -- "$AUDIO_MARKER"
        systemctl --user enable --now sandbox-pulse.service
    fi
    for _ in $(seq 20); do
        [ -S "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/sandbox-pulse/native" ] && break
        sleep 0.2
    done
    if [ -S "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/sandbox-pulse/native" ]; then
        say "playback-only sound for games: on"
    else
        warn "sandbox-pulse did not come up -- see: systemctl --user status sandbox-pulse"
    fi
elif [ ! -e "$CONF/systemd/user/sandbox-pulse.service" ]; then
    say "note: games can record and load sound server modules; ./install.sh --restrict-audio stops that"
fi

# ---- check what it needs ----------------------------------------------------
# Warnings, not failures: most of these only matter for some games, and the
# launcher names what is missing when it gets there anyway.
if ! command -v bwrap >/dev/null; then
    warn "bwrap not found -- install bubblewrap; nothing runs without it"
elif [[ "$(bwrap --help 2>&1)" != *--disable-userns* ]]; then   # grep -q can SIGPIPE bwrap
    warn "bwrap is older than 0.8 (no --disable-userns); sandbox-game will refuse to start"
fi
# The real test of python3 and libseccomp is building the filter.
"$HELPERS/sandbox-seccomp" --status >/dev/null 2>&1 \
    || warn "sandbox-seccomp cannot build the filter -- needs python3 and libseccomp.so.2"
command -v gamescope >/dev/null \
    || warn "gamescope not found -- the default display mode needs it (--wayland does not)"
command -v systemd-run >/dev/null \
    || warn "systemd-run not found -- games will run without memory and task limits"
command -v pasta >/dev/null \
    || warn "pasta not found -- games can only be offered internet access with it (package passt)"
command -v flock >/dev/null \
    || warn "flock not found -- install util-linux; sandbox launches need it"
"$HELPERS/sandbox-game-dialog" check >/dev/null 2>&1 \
    || warn "GTK 4 / libadwaita / Python PyGObject not found -- the Nautilus dialogs need them"
"$BIN/sandbox-manager" --check >/dev/null 2>&1 \
    || warn "Sandbox Manager needs GTK 4, libadwaita >= 1.5 and Python PyGObject"
case ":$PATH:" in
    *":$BIN:"*) ;;
    *) warn "$BIN is not on PATH -- the Nautilus scripts find it anyway, but add it to use the commands from a shell" ;;
esac

say "done. Open Sandbox Manager from your applications, or run sandbox-manager."
say "You can also right-click a game folder in Nautilus -> Scripts -> Sandbox game."
