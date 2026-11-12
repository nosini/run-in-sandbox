#!/bin/bash
# desktop-venus-check.sh [--only MODE/DISPLAY]... [RESULTS]: can games use the GPU through Mesa Venus
# instead of the render node, and at what cost?
#
# Run it from this checkout in your Wayland desktop session, as yourself.
# Needs virglrenderer-test-server and libvulkan_virtio; nothing is
# installed or changed. It starts a Venus render server of its own, then
# runs the same probes five times: games as they run now (direct) and
# through Venus (venus), each in a window on the desktop and inside a
# nested gamescope, and once more through Venus in a gamescope whose
# Xwayland runs without glamor, so without DRI3. Each run sits under the project's seccomp allowlist and
# its Landlock domains, the render node allowed to gamescope's domain only.
# vkcube windows open for a few seconds each.
#
# --only picks runs by name, e.g. --only venus/gamescope-noglamor.
#
# The logs stay in RESULTS, by default .gpu-check/venus-DATE in this
# checkout (git ignores it); summary.txt there is the short version.
set -u
here="$(cd "$(dirname "$(realpath "$0")")" && pwd)"
checkout="$(dirname "$here")"
runs=() results=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --only) [ "$#" -ge 2 ] || { echo "--only needs a run name" >&2; exit 1; }
                runs+=( "$2" ); shift 2 ;;
        -*) echo "unknown option: $1" >&2; exit 1 ;;
        *) results="$1"; shift ;;
    esac
done
[ "${#runs[@]}" -gt 0 ] || runs=( direct/desktop direct/gamescope venus/desktop venus/gamescope
                                   venus/gamescope-noglamor )
results="${results:-$checkout/.gpu-check/venus-$(date +%Y%m%d-%H%M%S)}"

die() { echo "desktop-venus-check: $*" >&2; exit 1; }
[ "$(id -u)" != 0 ] || die "run it as yourself, not as root"
[ -n "${WAYLAND_DISPLAY:-}" ] && [ -n "${XDG_RUNTIME_DIR:-}" ] \
    || die "run it in your Wayland desktop session (WAYLAND_DISPLAY is not set)"
compgen -G '/dev/dri/renderD*' >/dev/null || die "no /dev/dri/renderD* here: no GPU to test"
for tool in bwrap gamescope vulkaninfo vkcube virgl_test_server bc python3; do
    command -v "$tool" >/dev/null || die "$tool not found"
done
[ -e /usr/share/vulkan/icd.d/virtio_icd.x86_64.json ] || die "libvulkan_virtio is not installed"

mkdir -p "$results" || die "cannot make $results"
results="$(realpath "$results")"
scratch="$(mktemp -d "${XDG_RUNTIME_DIR}/venus-check.XXXXXX")" || die "cannot make a scratch folder"
summary="$results/summary.txt"
: > "$summary"
note() { printf '%s\n' "$*" | tee -a "$summary"; }

{
    echo "== $(date -Is)"; uname -r; grep -E '^PRETTY_NAME=' /etc/os-release
    echo "desktop: ${XDG_CURRENT_DESKTOP:-?}"
    rpm -q Mesa libvulkan_radeon libvulkan_virtio libvirglrenderer1 virglrenderer-test-server \
        gamescope vulkan-tools Mesa-demo-egl Mesa-demo-x bubblewrap 2>&1
    ls -l /dev/dri
    vulkaninfo --summary 2>&1 | grep -E 'deviceName|driverName|driverInfo'
} > "$results/system.txt" 2>&1

server=""
cleanup() {
    [ -z "$server" ] || kill "$server" 2>/dev/null
    rm -rf "$scratch"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# One render process per game, as the mode would have it: without
# --multi-clients the server forks a child for every connection. Only the
# GPU's drivers: with lavapipe there too, Zink picks that CPU device.
export VENUS_SOCKET="$scratch/venus.sock"
VK_LOADER_DRIVERS_DISABLE='*lvp*' virgl_test_server --venus --no-virgl --socket-path "$VENUS_SOCKET" > "$results/server.log" 2>&1 &
server=$!
for _ in $(seq 50); do [ -S "$VENUS_SOCKET" ] && break; sleep 0.1; done
[ -S "$VENUS_SOCKET" ] || die "the Venus server did not start; see $results/server.log"

for run in "${runs[@]}"; do
    mode="${run%/*}" display="${run#*/}"
    log="$results/$mode-$display.log"
    echo "== $mode, $display"
    timeout 180 "$here/sandboxed.sh" "$mode" "$display" /run/check/probe.sh > "$log" 2>&1
    status=$?
    grep '^RESULT ' "$log" | sed 's/^RESULT //' | tee -a "$summary"
    [ "$status" = 0 ] || note "$mode/$display: ended with status $status, see $(basename "$log")"
    [ "$display" != desktop ] \
        || grep -E '^VK_[A-Za-z0-9_]+$' "$log" | LC_ALL=C sort -u > "$results/$mode-extensions.txt" || true
done

if [ -s "$results/direct-extensions.txt" ] && [ -s "$results/venus-extensions.txt" ]; then
    missing="$(LC_ALL=C comm -23 "$results/direct-extensions.txt" "$results/venus-extensions.txt")"
    note "extensions the GPU has and Venus does not offer: $(echo "$missing" | grep -c .)"
    echo "$missing" | sed 's/^/  /' | tee -a "$summary"
fi
note "Venus server log: $(grep -c . "$results/server.log") lines"
echo
echo "Results in $results"
