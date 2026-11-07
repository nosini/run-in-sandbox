#!/usr/bin/env bash
# Build our private satellite helper without replacing the system package.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "$0")" && pwd)"
BUILD_DIR="${SATELLITE_BUILD_DIR:-$ROOT/.satellite-build}"
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
trap 'rm -r -- "$SOURCE"' EXIT
git clone --quiet --depth 1 https://github.com/nosini/xwayland-satellite.git "$SOURCE"
export CARGO_TARGET_DIR="$BUILD_DIR/target"
cargo build --manifest-path "$SOURCE/Cargo.toml" --locked --release
install -m755 "$CARGO_TARGET_DIR/release/xwayland-satellite" "$ROOT/sandbox-xwayland-satellite"
install -m644 "$SOURCE/LICENSE" "$ROOT/satellite-LICENSE"
printf 'Built %s\nRun ./install.sh to use it from the installed launcher.\n' "$ROOT/sandbox-xwayland-satellite"
