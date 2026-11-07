#!/usr/bin/env bash
# Get our private satellite helper without replacing the system package: the
# fork's prebuilt x86_64 release, or with --from-source a build of it here.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "$0")" && pwd)"
BUILD_DIR="${SATELLITE_BUILD_DIR:-$ROOT/.satellite-build}"
# The reviewed fork commit with the popup lifetime fixes, and the release
# built from it. Moving to another one is a change to these lines, never
# whatever the branch or the tag says today.
REPO=https://github.com/nosini/xwayland-satellite
COMMIT=7fac1ea497ca248c6b0032efcbd55dbd98b47925
TAG=sandbox-0.8.3-1
ASSET=xwayland-satellite-x86_64-linux.tar.gz
SHA256=ec463aead189d010fe5d8c64b6333e6f9bab1170611490dcbd057cfc318f79c4

FROM_SOURCE=0
case "$*" in
    "") ;;
    --from-source) FROM_SOURCE=1 ;;
    *) echo "usage: get-satellite.sh [--from-source]" >&2; exit 1 ;;
esac
if [ "$FROM_SOURCE" = 0 ] && [ "$(uname -m)" != x86_64 ]; then
    echo "No prebuilt satellite for $(uname -m); building from source." >&2
    FROM_SOURCE=1
fi
if [ "$FROM_SOURCE" = 1 ]; then
    for tool in git cargo pkg-config clang; do
        command -v "$tool" >/dev/null || { echo "Missing build tool: $tool" >&2; exit 1; }
    done
    pkg-config --exists xcb xcb-cursor || {
        echo 'Build needs the XCB and xcb-util-cursor development packages; see docs/satellite.md.' >&2
        exit 1
    }
else
    for tool in curl sha256sum tar; do
        command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 1; }
    done
fi
mkdir -p "$BUILD_DIR"
BUILD_DIR="$(cd -- "$BUILD_DIR" && pwd)"
WORK="$(mktemp -d "$BUILD_DIR/work.XXXXXX")"
# -f: Git writes its pack files read-only.
trap 'rm -rf -- "$WORK"' EXIT

if [ "$FROM_SOURCE" = 1 ]; then
    git -C "$WORK" init --quiet
    git -C "$WORK" fetch --quiet --depth 1 "$REPO.git" "$COMMIT"
    git -C "$WORK" -c advice.detachedHead=false checkout --quiet FETCH_HEAD
    [ "$(git -C "$WORK" rev-parse HEAD)" = "$COMMIT" ] || {
        echo "Fetched source is not commit $COMMIT" >&2; exit 1; }
    export CARGO_TARGET_DIR="$BUILD_DIR/target"
    cargo build --manifest-path "$WORK/Cargo.toml" --locked --release
    BIN="$CARGO_TARGET_DIR/release/xwayland-satellite"
    LICENSE="$WORK/LICENSE"
else
    curl -fsSL --proto '=https' -o "$WORK/$ASSET" "$REPO/releases/download/$TAG/$ASSET"
    printf '%s  %s\n' "$SHA256" "$WORK/$ASSET" | sha256sum --check --quiet --status - || {
        echo "Downloaded $ASSET does not match its pinned SHA-256; not installing it" >&2; exit 1; }
    tar -xzf "$WORK/$ASSET" -C "$WORK" --no-same-owner
    [ "$(cat "$WORK/xwayland-satellite/COMMIT")" = "$COMMIT" ] || {
        echo "Release $TAG was not built from commit $COMMIT" >&2; exit 1; }
    BIN="$WORK/xwayland-satellite/xwayland-satellite"
    LICENSE="$WORK/xwayland-satellite/LICENSE"
fi
install -m755 "$BIN" "$ROOT/sandbox-xwayland-satellite"
install -m644 "$LICENSE" "$ROOT/satellite-LICENSE"
printf 'Installed %s\nRun ./install.sh to use it from the installed launcher.\n' "$ROOT/sandbox-xwayland-satellite"
