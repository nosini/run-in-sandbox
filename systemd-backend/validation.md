# Systemd backend validation

The backend remains opt-in. Storage and namespace tests cover several
filesystems; accelerated graphics, physical GPU lifecycle and boot ordering
still need validation on a suitable dedicated machine.

## Storage and namespace lifetime

Install the [administrator setup](README.md) on a dedicated test VM first.
The VM needs the ext4/XFS utilities and loop-mount support. From a complete
checkout, run as the ordinary test user:

```sh
run="$HOME/work/run-in-sandbox/validation-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$run"
sudo python3 -I systemd-backend/test_storage_live.py \
  --uid "$(id -u)" --work-dir "$run/storage"
```

The controller formats only freshly created sparse image files, mounts them
alongside a private tmpfs fixture, and runs the launcher tests as the specified
ordinary user. On SELinux systems, fresh fixture roots receive their normal
home-path labels before user files are created. No additional policy is loaded.

The baseline uses the work directory's filesystem. For tmpfs, ext4 and XFS,
the default matrix tests the source and capture both on that filesystem,
only the source there, and only the capture there. The other side uses the
baseline filesystem. Eight checks run in each layout:

- transient identities, ownership and persistence across allocations;
- switching available backends without losing saves or overlay data;
- live edits through `sandbox-attach --put`;
- listing, reset-install and deletion;
- no supplementary groups, capabilities or setup descriptors in the game;
- repeated exits/stops, with namespace registry entries released;
- concurrent captures with separate overlays and saves, including stopping
  one while the other keeps running;
- public foreign-owned game data and refusal to delegate its closed directory.

Logs and `results.json` remain in the work directory. Unavailable services,
skipped checks and empty test runs are failures, even if unittest exits zero.
The controller unmounts
fixtures and removes their images even if tests fail. If unmounting fails,
cleanup stops and keeps the image: finish the test processes before retrying
the unmount. A narrower run is also available:

```sh
sudo python3 -I systemd-backend/test_storage_live.py \
  --uid "$(id -u)" --work-dir "$run/xfs" --filesystems xfs --layouts both
```

Public foreign-owned sources can be read and new files/saves captured without
changing their originals. Their existing permissions remain enforced. On the
tested kernel, replacing a lower inode whose owner is outside the managed
mapping also failed with `EOVERFLOW` ("Value too large for defined data type").
Use a copy owned by the launching user when the game needs to change those
existing files. Arbitrary foreign ownership and ACL support is not established.
The tested directory mapping produced a read-only overlay when the caller's
primary GID differed from their UID. Setup and launch now refuse that identity
layout explicitly; supporting it remains open.

## Graphics evidence

The [media probe](../experiments/media.md) creates a private headless compositor
and audio graph. Ordinary mode allows software rendering and reports it.
A DRM open or ioctl alone is not acceleration evidence. To require hardware:

```sh
dbus-run-session -- python3 -I experiments/systemd-media.py \
  --work-dir "$HOME/work/run-in-sandbox/m-hw" \
  --device-dir "/run/sandboxgame/render/$(id -u)" --require-hardware
```

Choose a fresh, short work path; Unix socket path limits apply. Hardware mode
uses a GL compositor by default. The client checks its actual EGL display/device,
rejects identified software rendering, and requires that device to report the
mapped `/dev/dri/renderD128`. Missing device-query/render-node information also
fails conservatively. A failed query alone does not prove a GPU cannot render.
`--weston-renderer pixman` or `--weston-renderer gl` selects the private compositor
explicitly; this does not bypass the hardware requirement.

Both modes check pixel readback and a compositor frame callback. The probe
currently binds `renderD128`; other GPU selections need separate coverage.
Passing EGL does not establish DMA-BUF transport, Vulkan, gamescope, Xwayland
or Proton behavior. On the VM, `--gamescope` aborts identically under
`SANDBOX_SEPARATE_UID=0` and `systemd`: gamescope selects llvmpipe and fails
`vkAllocateMemory` before showing anything. llvmpipe has no
`VK_EXT_physical_device_drm`, so the card/render node matching gamescope does
on real GPUs is not exercised there. Those require their own workloads and renderer/device
evidence. Physical hotplug tests need disposable hardware without disrupting
another user.

## On a desktop with a GPU

[`desktop-gpu-check.sh`](desktop-gpu-check.sh) runs the graphics checks on
an ordinary openSUSE Tumbleweed desktop, in its Wayland session, with no
games running:

```sh
systemd-backend/desktop-gpu-check.sh
```

It installs the administrator setup with sudo and removes it again at the
end (keeping one that was there before, or with `--keep-setup`). Then it
runs `vulkaninfo`, `eglinfo`, `vkcube` in a window and inside gamescope, and
`glxinfo` in gamescope's Xwayland, as throwaway games under
`SANDBOX_SEPARATE_UID=0` and `systemd`, and the hardware-only media probe
when its build tools are there. Missing tools are skipped and named
(`vulkan-tools`, `mesa-demos`, `gamescope`). Your per-user installation,
settings and games are not used. Logs and `summary.txt` stay in
`.gpu-check/DATE` in the checkout.

With `--game PATH` (repeatable; `--name NAME` after one whose sandbox was
renamed) it launches your own games instead, as "Sandbox game" does and with
their preferences, but under the systemd backend and in a capture of their
own, `NAME-systemd-test`; the game's own capture and folder stay as they
are. It records the render node the game got, which of its processes have
the GPU open, and whether the capture stays yours on disk.

Results on an RX 9070 XT desktop (Mesa 26.2.5, gamescope 3.16.31): under
the systemd backend the game had the helper's render node copy, and Vulkan,
`vkcube` in a window and in nested gamescope, and Xwayland's OpenGL all ran
on the GPU, the same as under the default backend.

## Boot ordering

Use a dedicated VM or agree a reboot window with everyone using a shared VM.
Keep the task's durable VM hold through reboot and preserve its SSH recovery
path. Record the run directory in the task notes so it can be restored after
reconnecting. Before rebooting:

```sh
cat /proc/sys/kernel/random/boot_id > "$run/boot-before"
systemctl is-enabled sandbox-game-render-devices.service \
  systemd-nsresourced.socket systemd-mountfsd.socket
sudo systemctl reboot
```

After reconnecting, restore `run` to the same directory. Verify a new boot ID
and inspect activation from that boot, rather than manually starting a service
and treating it as boot coverage:

```sh
test "$(cat "$run/boot-before")" != "$(cat /proc/sys/kernel/random/boot_id)"
systemctl status sandbox-game-render-devices.service run-sandboxgame-render.mount \
  systemd-nsresourced.socket systemd-mountfsd.socket
systemctl show sandbox-game-render-devices.service run-sandboxgame-render.mount \
  systemd-user-sessions.service -p Id -p ActiveEnterTimestampMonotonic
systemctl show systemd-nsresourced.service -p Requires -p After
sudo journalctl -b -u sandbox-game-render-devices.service \
  -u run-sandboxgame-render.mount -u modprobe@overlay.service \
  -u systemd-nsresourced.service -u systemd-mountfsd.service
findmnt /run/sandboxgame/render
ls -l "/run/sandboxgame/render/$(id -u)"
```

The render service must start after its mount and before user sessions. The
store must be its dedicated device-enabled tmpfs, with aliases only for the
allowlisted users. Overlay loading must precede namespace-service startup.
On SELinux systems, check enforcing mode, loaded policy and new delegation
AVCs. Then repeat an ordinary unprivileged launch and the storage/media probes,
plus service/mount stop and regrant. These reboot checks have not yet run.

## Results and open checks

Btrfs, tmpfs, ext4 and XFS passed the same-filesystem matrix with SELinux
enforcing. Separate source/capture layouts were also exercised. Testing found
truncated namespace names colliding between concurrent launches; the shorter
name now preserves the complete PID even after UID prefixing. A buffered
readiness read in the test helper also dropped subsequent output; it now
leaves the pipe unbuffered until readiness is consumed.

EGL rendered the expected pixel and received a frame callback with llvmpipe.
The device report identified software rendering and no render node; hardware
mode correctly rejected it, including with a GL compositor. This is software
path validation, not an accelerated result.

The complete private media probe passed playback and recording/module denial.
Earlier attempts intermittently failed Pulse connection setup with "Protocol
error"; these remain failures, not evidence of recording denial. The same
failure occurs with no sandbox: about 1 in 75 short `pactl` clients of the
restricted server (`audio/sandbox-pulse.conf`) on the probe's private graph,
and none of the unrestricted server's. pipewire-pulse 1.6.9 (and master)
replies to SET_CLIENT_NAME after its first sync even when WirePlumber has
not yet let the client see its own client object; the reply then carries
index 4294967295 and libpulse rejects it. This affects the restricted sound
server under every backend. Fixing it would mean patching PipeWire, which
this project does not carry; it is a known limitation.

Boot checks, accelerated OpenGL/Vulkan, DMA-BUF, gamescope/Xwayland, actual
games, multiple physical GPUs and physical hotplug remain unvalidated.

One full-suite run made alongside the loop-mount matrix also saw a single
ordinary-backend overlay mount fail with `EPERM`. Twelve focused repetitions
passed, as did the later full suite and two more run during a complete
storage matrix; its cause remains unconfirmed. Keep this
stress result in scope before declaring general-use readiness.
