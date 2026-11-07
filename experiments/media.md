# Managed display and audio experiment

[`systemd-media.py`](systemd-media.py) runs real Wayland/EGL and Pulse clients
through the proposed systemd backend. It creates a disposable headless Weston
compositor and a private PipeWire graph with the checkout's **unchanged**
playback-only Pulse configuration and WirePlumber scripts. It does not use the
VM's desktop compositor or audio graph. Hardware discovery is disabled in the
private WirePlumber instance; the graph has only a synthetic sink and source.

Use the dedicated VM setup from [README.md](README.md) and the
[render-helper instructions](../systemd-backend/render-devices.md). The delegation daemons and
workers must be the tested 261.4 versions, with the [service SELinux module](../systemd-backend/README.md)
installed before the first daemon start. Load overlayfs before starting the
namespace service as described in [README.md](README.md). The module includes directory-FD access for `init_var_run_t`, which
PID 1 may assign when it creates the runtime mountpoint's parent. Earlier tests
used a manually created parent with `var_run_t`; that alone did not cover this
service-created directory. Neither rule grants home-file data access.

The VM also needs Weston (including kiosk shell), a compiler, pkg-config,
Wayland scanner and protocol XML, EGL/OpenGL and Wayland development files,
PipeWire, WirePlumber, Pulse utilities and `dbus-run-session`. On the tested
openSUSE VM, `wayland-protocols-devel` supplied the missing XML. `libpulse-devel`
was also installed during preparation, though the final test uses Pulse
utilities rather than compiling a Pulse client.

Run as the ordinary user from the checkout, under a **new private session bus**:

```sh
dbus-run-session -- python3 -I experiments/systemd-media.py \
  --work-dir "$HOME/work/run-in-sandbox/media-run" \
  --device-dir "/run/sandboxgame/render/$(id -u)"
```

Choose a new, short scratch path: Unix socket paths are limited in length.
The script retains its build, logs and monitor recording in that directory.
It terminates its fixture processes and removes their runtime sockets on exit.
It does not install services, change device permissions, or install policy.

It allocates a managed namespace and delegates fixture directories and the
render aliases with `MountDirectory(mode=root)`. In a child namespace, bwrap
binds only the selected Wayland socket and restricted Pulse socket. The native
PipeWire and unrestricted control Pulse sockets are absent from the sandbox.
The clients run with the existing seccomp and Landlock helpers, no effective
capabilities, no supplementary groups and no inherited setup descriptors.

The finite [C graphics client](media-client.c) negotiates an xdg-shell window,
creates an EGL/OpenGL context, clears it to a known colour and verifies a pixel
with `glReadPixels`. After swapping the buffer it waits for a Wayland frame
callback, proving the compositor processed the submitted frame. A callback is
not proof that a physical display scanned out the image. The client reports
its renderer rather than assuming that opening a DRM device implies hardware
acceleration. The protected payload also opens the mapped render alias and
performs the previously tested DRM version ioctl.

For audio, a two-second tone must finish playback and drain. An unrestricted
control client outside the sandbox records the private sink's monitor and
checks that substantial nonzero audio arrived. Before testing denials, the
control endpoint must see both that monitor and the synthetic source. The
restricted client must not see the synthetic source, must fail to load a
module, and must fail promptly when recording from the default source,
explicit synthetic source, or explicit sink monitor. Recording attempts must
produce no data. A timeout is a failure, not evidence that capture is denied.

## Results on the development VM, 2026-11-06

The complete test passed with SELinux enforcing and the updated service-wide
development module. Wayland/EGL returned pixel `64,128,191` and received its
frame callback. Audio playback drained and the independent private monitor
recording contained over 29,000 samples above the signal threshold. All three
recording attempts failed with `No such entity`; module loading failed too.

Pulse still enumerated `probe_sink.monitor`, synthesized from the visible sink,
although recording from it was denied. The test checks that denial directly;
an empty source listing would be an incorrect requirement on this version.
The real synthetic source remained hidden. No production audio-policy change
was needed for transient client UIDs.

The reported renderer was **llvmpipe (LLVM 23.1.2)**. This demonstrates actual
software rendering and Wayland protocol/buffer transport, not accelerated
rendering through the alias. The VM has a virtio GPU; real GPU acceleration,
DMA-BUF interoperability, Vulkan rendering, nested gamescope/Xwayland, and an
actual native or Proton game still need separate validation. Physical GPU
unplug/replug and boot ordering are also outside this test. The production
launcher and installer remain unchanged.

## Hardware-required mode (2026-11-07)

`--require-hardware` defaults the private Weston compositor to its GL renderer
and makes the client fail on software rendering or missing evidence that EGL
uses the mapped render node. `--weston-renderer pixman|gl` can select the fixture
renderer explicitly. Ordinary runs retain the pixman default and allow software.

The client reports the renderer and queries the EGL display's associated device
using [EGL_EXT_device_query](https://registry.khronos.org/EGL/extensions/EXT/EGL_EXT_device_query.txt).
It checks the device's software extension and known software renderer names,
and requires [EGL_EXT_device_drm_render_node](https://registry.khronos.org/EGL/extensions/EXT/EGL_EXT_device_drm_render_node.txt)
to identify the mapped `/dev/dri/renderD128`. Missing query support fails
conservatively. Pixel readback and a frame callback are checked in either mode.
The VM reports llvmpipe, software=yes and no render node; hardware-required
mode correctly fails, including with a GL compositor. No accelerated result
is claimed. Vulkan, DMA-BUF and other GPU selections still need separate tests.

The complete ordinary media check passed again, including playback verified
by the control recording and denied source/monitor capture. Other attempts
intermittently failed Pulse connection setup with `Protocol error`; the probe
keeps those as failures and does not reinterpret them as recording denial.
Media startup stability remains open. See the [validation runbook](../systemd-backend/validation.md)
for storage, graphics and the pending boot/hardware checks.
