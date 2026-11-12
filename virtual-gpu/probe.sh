#!/bin/bash
# probe.sh: inside sandboxed.sh; prints "RESULT name: value" lines.
# CHECK_MODE and CHECK_DISPLAY say where it runs. The extension list goes
# to stdout as bare names, for the caller to compare.
set -u
r() { echo "RESULT $CHECK_MODE/$CHECK_DISPLAY $*"; }

node=$(ls /dev/dri/renderD* 2>/dev/null | head -1)
if [ -n "$node" ]; then
    r "render node open: $(python3 -I -c "import os,sys
try: os.open(sys.argv[1], os.O_RDWR); print('opens')
except OSError as e: print('refused,', e.strerror)" "$node")"
else
    r "render node open: none present"
fi
r "inherited GPU descriptors: $(ls -l /proc/self/fd/ 2>/dev/null | grep -c -E '/dev/dri|anon_inode:\[?drm' )"
r "vulkan device: $(vulkaninfo --summary 2>&1 | grep -m1 deviceName | sed 's/.*= //')"

# Frames of a trivial scene, as fast as the present mode allows: what each
# frame costs on top of the drawing.
frames=3000
for pm in 0 1 2; do
    start=$(date +%s.%N)
    if vkcube --c "$frames" --present_mode "$pm" > /tmp/cube.log 2>&1; then
        end=$(date +%s.%N)
        r "vkcube: $frames frames in $(echo "$end - $start" | bc | cut -c1-6) s (present mode $pm)"
        r "vkcube WSI: $(grep -E -m3 'Selected WSI|Gamescope WSI\] (Made|Creating)|Falling back|not supported' /tmp/cube.log | tr '\n' ' ')"
        break
    fi
    [ "$pm" != 2 ] || r "vkcube: FAILED: $(grep -v -E '^Selected|shader cache' /tmp/cube.log | tail -1)"
done

if [ "$CHECK_DISPLAY" = desktop ]; then
    vulkaninfo > /tmp/vulkaninfo.txt 2>&1
    LC_ALL=C awk '$1 ~ /^VK_[A-Za-z0-9_]+$/ && $2 == ":" { print $1 }' /tmp/vulkaninfo.txt | sort -u
    r "HDR10 surface formats: $(grep -a -c COLOR_SPACE_HDR10_ST2084 /tmp/vulkaninfo.txt)"
    WAYLAND_DEBUG=1 vkcube --c 30 > /tmp/wl.log 2>&1
    r "buffers to the compositor: $(grep -c 'zwp_linux_buffer_params_v1#[0-9]*.create_immed\|\.create_immed(' /tmp/wl.log) dma-buf, $(grep -c 'wl_shm_pool#[0-9]*.create_buffer' /tmp/wl.log) shared memory"
    if command -v eglinfo >/dev/null; then
        r "OpenGL on Wayland: $(eglinfo -B -p wayland 2>&1 | grep -m1 'core profile renderer' | sed 's/.*renderer: //')"
        [ "$CHECK_MODE" != venus ] || r "OpenGL on Wayland without LIBGL_ALWAYS_SOFTWARE: $(env -u LIBGL_ALWAYS_SOFTWARE eglinfo -B -p wayland 2>&1 | grep -m1 'core profile renderer' | sed 's/.*renderer: //')"
    else
        r "OpenGL on Wayland: eglinfo not installed (Mesa-demo-egl)"
    fi
else
    if command -v glxinfo >/dev/null; then
        glxinfo -B > /tmp/glx.log 2>&1
        r "OpenGL in gamescope: $(grep -m1 'renderer string' /tmp/glx.log | sed 's/.*string: //')"
        grep -q 'renderer string' /tmp/glx.log \
            || r "glxinfo said: $(grep -v -E '^\s*$|Gamescope WSI|^ +[a-zA-Z]+:' /tmp/glx.log | tail -3 | tr '\n' ' ')"
        [ "$CHECK_MODE" != venus ] || r "OpenGL in gamescope without LIBGL_ALWAYS_SOFTWARE: $(env -u LIBGL_ALWAYS_SOFTWARE glxinfo -B 2>&1 | grep -m1 'renderer string' | sed 's/.*string: //')"
        [ "$CHECK_MODE" != venus ] || r "OpenGL in gamescope without Zink settings: $(env -u LIBGL_ALWAYS_SOFTWARE -u MESA_LOADER_DRIVER_OVERRIDE glxinfo -B 2>&1 | grep -m1 'renderer string' | sed 's/.*string: //')"
    else
        r "OpenGL in gamescope: glxinfo not installed (Mesa-demo-x)"
    fi
    r "DISPLAY: ${DISPLAY:-unset}, GAMESCOPE_WAYLAND_DISPLAY: ${GAMESCOPE_WAYLAND_DISPLAY:-unset}"
    x="${DISPLAY#*:}"; x="/tmp/.X11-unix/X${x%%.*}"
    r "X11 DRI3Open: $(python3 -I /run/check/dri3_open_probe.py "$x" 2>&1 | tail -1)"
fi
