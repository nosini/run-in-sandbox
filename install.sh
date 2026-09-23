#!/usr/bin/env bash
# install.sh [--uninstall]
#   Install sandbox-game, sandbox-attach, sandbox-seccomp and the Nautilus
#   scripts for the current user. No root needed; nothing outside ~/.local is
#   touched.
#
#   Run from a checkout, it installs that checkout. Run on its own -- as in
#     curl -fsSL https://codeberg.org/nosini/run-in-sandbox/raw/branch/main/install.sh | bash
#   -- it downloads the branch named by $REF (default main) first.
#
#   Running it again updates in place. --uninstall removes the installed
#   scripts and leaves everything else alone: ~/game-sandboxes (saves, Wine
#   prefixes), your preferences and the shared tools folder.
set -euo pipefail

REPO="https://codeberg.org/nosini/run-in-sandbox"
REF="${REF:-main}"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
BIN="$HOME/.local/bin"
SCRIPTS="$DATA/nautilus/scripts"
# Must match sandbox-game's default, which mounts this folder at /tools.
TOOLS="${SANDBOX_TOOLS_DIR:-$DATA/sandbox-game/tools}"

# Runs "$@" MODE NAME DEST once per installed file. The lib is 644 and kept
# out of the scripts dir: Nautilus lists everything there as a menu entry.
each() {
    "$@" 755 sandbox-game             "$BIN"
    "$@" 755 sandbox-attach           "$BIN"
    "$@" 755 sandbox-seccomp          "$BIN"
    "$@" 644 sandbox-game-lib         "$BIN"
    "$@" 755 "Sandbox game"             "$SCRIPTS"
    "$@" 755 "Sandbox game preferences" "$SCRIPTS"
}

say()  { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }

remove_one() {
    [ ! -e "$3/$2" ] || { rm -f "$3/$2"; say "removed $3/$2"; }
}
install_one() {
    install -Dm"$1" "$SRC/$2" "$3/$2"; say "installed $3/$2"
}

if [ "${1:-}" = --uninstall ]; then
    each remove_one
    say "left alone: ~/game-sandboxes, ~/.config/sandbox-game, $TOOLS"
    exit 0
fi
[ "$#" -eq 0 ] || { echo "usage: install.sh [--uninstall]" >&2; exit 1; }

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
mkdir -p "$TOOLS"
say "tools folder: $TOOLS (unpack a portable Cheat Engine here)"

# ---- check what it needs ----------------------------------------------------
# Warnings, not failures: most of these only matter for some games, and the
# launcher names what is missing when it gets there anyway.
if ! command -v bwrap >/dev/null; then
    warn "bwrap not found -- install bubblewrap; nothing runs without it"
elif ! bwrap --help 2>&1 | grep -q -- --disable-userns; then
    warn "bwrap is older than 0.8 (no --disable-userns); sandbox-game will refuse to start"
fi
# The real test of python3 and libseccomp is building the filter.
"$BIN/sandbox-seccomp" >/dev/null 2>&1 \
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
