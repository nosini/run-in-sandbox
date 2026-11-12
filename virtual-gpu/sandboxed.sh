#!/bin/bash
# sandboxed.sh MODE DISPLAY CMD...: run CMD as a game would run in the
# virtualized GPU mode (MODE venus) or as games run now (MODE direct).
#
# bwrap with the project's seccomp allowlist, then two Landlock domains as
# sandbox-game builds them: the outer one, gamescope's place, may open the
# render nodes; the inner one, the game's, may in direct mode only. In venus
# mode the game reaches the GPU through the Venus socket alone.
# DISPLAY desktop: CMD talks to the desktop's Wayland socket itself.
# DISPLAY gamescope: gamescope runs in the outer domain, nested on the
# desktop, as under sandbox-game, and CMD runs inside it, in the inner one.
# DISPLAY gamescope-noglamor: the same, its Xwayland started without glamor.
# Needs VENUS_SOCKET in venus mode.
set -euo pipefail
mode=$1 display=$2; shift 2
here="$(cd "$(dirname "$(realpath "$0")")" && pwd)"
checkout="$(dirname "$here")"

nodes=(); for n in /dev/dri/renderD*; do [ -c "$n" ] && nodes+=( "$n" ); done
bw=( --ro-bind /usr /usr --symlink usr/lib64 /lib64 --symlink usr/lib /lib
     --symlink usr/bin /bin --symlink usr/sbin /sbin --ro-bind /etc /etc
     --dev /dev --proc /proc --ro-bind /sys /sys --tmpfs /tmp --dir /tmp/.X11-unix
     --tmpfs /run --perms 0700 --dir /run/user/1
     --ro-bind "$here" /run/check --ro-bind "$checkout/sandbox-landlock" /run/sandbox-landlock
     --bind "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" /run/host-wayland/wayland-0
     --clearenv --setenv PATH /usr/bin --setenv LANG C.UTF-8
     --setenv XDG_RUNTIME_DIR /run/user/1 --setenv HOME /tmp
     --unshare-all --die-with-parent --new-session )
for n in "${nodes[@]}"; do bw+=( --dev-bind "$n" "$n" ); done
common=( --ls / --ro /usr --ro /etc --ro /sys --ro /run/check --ro /run/sandbox-landlock
         --rw /tmp --rw /proc --ls /dev --rw /dev/null --rw /dev/zero --rw /dev/full
         --rw /dev/random --rw /dev/urandom --rw /dev/shm --rw /dev/pts --rw /run/user/1 )
outer=( "${common[@]}" --unix-connect /run/host-wayland/wayland-0 ); inner=( "${common[@]}" )
for n in "${nodes[@]}"; do outer+=( --rw "$n" ); done
# What the game alone is given.
game=( env CHECK_MODE="$mode" CHECK_DISPLAY="$display" )
if [ "$mode" = venus ]; then
    bw+=( --bind "$VENUS_SOCKET" /run/venus.sock )
    outer+=( --unix-connect /run/venus.sock ); inner+=( --unix-connect /run/venus.sock )
    game+=( VK_DRIVER_FILES=/usr/share/vulkan/icd.d/virtio_icd.x86_64.json VN_DEBUG=vtest
            VTEST_SOCKET_NAME=/run/venus.sock LIBGL_ALWAYS_SOFTWARE=1
            MESA_LOADER_DRIVER_OVERRIDE=zink )
else
    for n in "${nodes[@]}"; do inner+=( --rw "$n" ); done
fi

if [ "$display" = gamescope-noglamor ]; then
    bw+=( --ro-bind "$(command -v Xwayland)" /run/xwayland-real
          --ro-bind "$here/xwayland-no-glamor" /usr/bin/Xwayland )
    outer+=( --ro /run/xwayland-real )
fi
if [ "$display" != desktop ]; then
    # Nested gamescope will not start without the card nodes in sight; it
    # never opens them, and no Landlock rule lets anything else do so.
    for n in /dev/dri/card*; do [ -c "$n" ] && bw+=( --dev-bind "$n" "$n" ); done
    run=( env WAYLAND_DISPLAY=/run/host-wayland/wayland-0 gamescope -W 1280 -H 720 -- )
    inner+=( --unix-connect-where-writable --no-abstract-scope )
else
    run=()
    game+=( WAYLAND_DISPLAY=/run/host-wayland/wayland-0 )
    inner+=( --unix-connect /run/host-wayland/wayland-0 )
fi

exec 9< <(SANDBOX_SECCOMP_POLICY=allowlist python3 -I "$checkout/sandbox-seccomp")
exec bwrap "${bw[@]}" --seccomp 9 -- \
    /run/sandbox-landlock "${outer[@]}" -- ${run[@]+"${run[@]}"} \
    /run/sandbox-landlock "${inner[@]}" -- "${game[@]}" "$@"
