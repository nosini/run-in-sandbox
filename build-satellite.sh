#!/usr/bin/env bash
# Build our private satellite helper without replacing the system package.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "$0")" && pwd)"
BUILD_DIR="${SATELLITE_BUILD_DIR:-$ROOT/.satellite-build}"
# The reviewed fork commit with the popup lifetime fixes. Moving to another
# one is a change to this line, never whatever the branch says today.
REPO=https://github.com/nosini/xwayland-satellite.git
COMMIT=c9933c44553bac6bc318ca28ead9ddf4dc576036
for tool in git cargo pkg-config clang; do
    command -v "$tool" >/dev/null || { echo "Missing build tool: $tool" >&2; exit 1; }
done
pkg-config --exists xcb xcb-cursor || {
    echo 'Build needs the XCB and xcb-util-cursor development packages; see docs/satellite.md.' >&2
    exit 1
}
mkdir -p "$BUILD_DIR"
BUILD_DIR="$(cd -- "$BUILD_DIR" && pwd)"
SOURCE="$(mktemp -d "$BUILD_DIR/source.XXXXXX")"
# -f: Git writes its pack files read-only.
trap 'rm -rf -- "$SOURCE"' EXIT
git -C "$SOURCE" init --quiet
git -C "$SOURCE" fetch --quiet --depth 1 "$REPO" "$COMMIT"
git -C "$SOURCE" -c advice.detachedHead=false checkout --quiet FETCH_HEAD
[ "$(git -C "$SOURCE" rev-parse HEAD)" = "$COMMIT" ] || {
    echo "Fetched source is not commit $COMMIT" >&2; exit 1; }
export CARGO_TARGET_DIR="$BUILD_DIR/target"
cargo build --manifest-path "$SOURCE/Cargo.toml" --locked --release
install -m755 "$CARGO_TARGET_DIR/release/xwayland-satellite" "$ROOT/sandbox-xwayland-satellite"
install -m644 "$SOURCE/LICENSE" "$ROOT/satellite-LICENSE"
printf 'Built %s\nRun ./install.sh to use it from the installed launcher.\n' "$ROOT/sandbox-xwayland-satellite"
