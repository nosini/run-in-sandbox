#!/usr/bin/env bash
# install.sh [--restrict-audio] [--uninstall]
#   Install sandbox-game and sandbox-attach into ~/.local/bin, their helpers
#   (sandbox-seccomp, sandbox-landlock, sandbox-game-lib) into
#   ~/.local/lib/sandbox-game, and the Nautilus scripts, for the current user.
#   No root needed; nothing outside ~/.local is touched.
#
#   --restrict-audio also sets up playback-only sound for the games: a second
#   Pulse server of their own, and WirePlumber rules and a hook that keep them
#   from recording (see audio/sandbox-pulse.conf). That changes your sound
#   setup beyond ~/.local -- files in ~/.config/pipewire, ~/.config/wireplumber
#   and ~/.config/systemd/user, and a WirePlumber restart -- so it is asked for.
#
#   Run from a checkout, it installs that checkout. Run on its own -- as in
#     curl -fsSL https://codeberg.org/nosini/run-in-sandbox/raw/branch/main/install.sh | bash
#   -- it downloads the branch named by $REF (default main) first.
#
#   Running it again updates in place. --uninstall removes the installed
#   scripts, and the sound setup if it is there, and leaves everything else
#   alone: ~/game-sandboxes (saves, Wine prefixes), your preferences and the
#   shared tools folder.
set -euo pipefail

REPO="https://codeberg.org/nosini/run-in-sandbox"
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
    "$@" 755 sandbox-seccomp          "$HELPERS"
    "$@" 755 sandbox-landlock         "$HELPERS"
    "$@" 644 sandbox-game-lib         "$HELPERS"
    "$@" 755 "Sandbox game"             "$SCRIPTS"
    "$@" 755 "Sandbox game preferences" "$SCRIPTS"
    "$@" 755 "Stop sandboxed game"      "$SCRIPTS"
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
}

say()  { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }

remove_one() {
    [ ! -e "$3/$2" ] || { rm -f "$3/$2"; say "removed $3/$2"; }
}
install_one() {
    install -Dm"$1" "$SRC/$2" "$3/$2"; say "installed $3/$2"
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

AUDIO=0
case "${1:-}" in
    --uninstall)
        each remove_one
        each_old remove_one
        rmdir "$HELPERS" 2>/dev/null || true
        each_completion remove_one
        if [ -e "$CONF/systemd/user/sandbox-pulse.service" ]; then
            systemctl --user disable --now sandbox-pulse.service 2>/dev/null || true
            each_audio remove_one
            systemctl --user daemon-reload 2>/dev/null || true
            systemctl --user restart wireplumber 2>/dev/null || true
        fi
        say "left alone: ~/game-sandboxes, ~/.config/sandbox-game, $TOOLS"
        exit 0 ;;
    --restrict-audio) AUDIO=1; shift ;;
esac
[ "$#" -eq 0 ] || { echo "usage: install.sh [--restrict-audio] [--uninstall]" >&2; exit 1; }
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
if [ -z "$SRC" ]; then
    command -v curl >/dev/null || { echo "curl is needed to download" >&2; exit 1; }
    TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
    say "downloading $REPO ($REF)"
    curl -fsSL "$REPO/archive/$REF.tar.gz" | tar xz -C "$TMP" --strip-components=1
    SRC="$TMP"
fi

# ---- install ----------------------------------------------------------------
each install_one
each_old remove_one
each_completion install_completion
mkdir -p "$TOOLS"
say "tools folder: $TOOLS (unpack a portable Cheat Engine here)"

if [ "$AUDIO" = 1 ]; then
    each_audio install_audio
    # WirePlumber first: its hook has to be in place before a game can connect.
    # A restart re-links every stream, so expect a moment of silence -- and
    # only when something changed.
    systemctl --user daemon-reload
    if [ "$AUDIO_CHANGED" = 1 ]; then
        systemctl --user restart wireplumber
        systemctl --user enable sandbox-pulse.service
        systemctl --user restart sandbox-pulse.service
    else
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
elif ! bwrap --help 2>&1 | grep -q -- --disable-userns; then
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
command -v zenity >/dev/null \
    || warn "zenity not found -- the Nautilus scripts need it for their dialogs"
case ":$PATH:" in
    *":$BIN:"*) ;;
    *) warn "$BIN is not on PATH -- the Nautilus scripts find it anyway, but add it to use the commands from a shell" ;;
esac

say "done. Right-click a game folder in Nautilus -> Scripts -> Sandbox game"
