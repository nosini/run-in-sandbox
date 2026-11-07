# Development

This is for working on the sandbox itself. For installing and using it, see
the [README](../README.md).

## Running the tests

The tests are in `tests/` and use Python's `unittest`. They make temporary
homes and captures and launch real sandboxes, so they need what a launch
needs: bubblewrap built with `--overlay`, pasta and `ip` for the
network tests, and GTK 4 with libadwaita for the desktop app's tests. From
the checkout:

```sh
python3 tests/test_security.py -v                 # sandbox and launcher checks
GDK_BACKEND=x11 GSK_RENDERER=gl xvfb-run -a -s "-screen 0 1200x900x24" \
  dbus-run-session -- python3 -m unittest discover -s tests   # everything
```

The security tests exercise real filesystem and network isolation, the
seccomp filter and the user-namespace block, environment filtering, the
read-only tools folder and namespace attachment. Display and audio checks
record bwrap's arguments instead of opening windows or playing sound.

They run without the systemd scope, because their private runtime directory
hides the user manager. The exception is the check that commands reach the
game unaltered by `systemd-run`, which uses the real one, and skips when no
user manager is reachable rather than pass having tested nothing.

Tests that need something missing skip rather than fail: the subordinate-uid
backend's tests need `newuidmap` and a range in `/etc/subuid`, the systemd
backend's tests need its [administrator setup](../systemd-backend/README.md),
and the live audio test needs `./install.sh --restrict-audio`. A test run
inside a container usually lacks a recent enough bubblewrap and these
services, so most of the suite needs a real machine or a VM.

The systemd backend has further checks that need root, a dedicated machine
and its administrator setup; [systemd-backend/validation.md](../systemd-backend/validation.md)
describes them: the storage matrix over several filesystems, the render-copy
lifecycle tests, the desktop GPU check and the reboot check.

The optional satellite backend has an integration test using real Xwayland
windows on a private headless Weston. It needs `weston`, `xwayland-satellite`,
`Xwayland`, libX11 and a kernel with Landlock Unix-socket restrictions:

```sh
TEST_SATELLITE=1 python3 tests/test_security.py -v \
  SecurityTests.test_live_satellite_windows_and_internal_socket_isolation
```

It checks window creation and closure, direct desktop Wayland access, and
refusal of connections to satellite's internal Wayland socket through the
actual sandbox. It does not exercise Wine, GPU rendering or desktop input.
The supervisor's startup, failure and cleanup tests in `test_x11_server.py`
also run without a display or bubblewrap.

## Probes for the systemd backend

[`systemd-backend/probes/`](../systemd-backend/probes/) holds standalone
scripts that drive nsresourced and mountfsd directly, without the launcher.
They predate the backend and are kept to check a system's services and the
render copies on their own:

- `access.py` makes two managed namespaces with their own idmapped storage
  and checks socket access through an idmapped folder, the transient peer
  credentials, that neither namespace reaches the other's files, and with
  `--device-dir` a DRM ioctl through a render copy.
- `media.py` runs a real Wayland/EGL client (`media-client.c`) and Pulse
  clients through a managed namespace against a private headless Weston and
  PipeWire graph, using the checkout's playback-only sound configuration.
  `--require-hardware` fails unless EGL renders on the mapped render node.
- `storage.py` checks managed allocation, idmapped mounts, kernel overlay
  copy-up and persistence across two allocations; the other two import it.

Run them as an ordinary user from the checkout, with a fresh, short
`--work-dir` (Unix socket paths are limited in length).

## Findings worth knowing

### mountfsd and nsresourced

- `MountDirectory(mode=root)` maps a single id: the caller's uid, which it
  also uses as the gid. The kernel refuses writes to any inode whose owner or
  group the mapping lacks, even by its owner (`EACCES`, or `EOVERFLOW` on
  rename), so the backend needs the primary group to have the uid's number.
- mountfsd clones only one mount. A folder with another mount between it and
  a folder already delegated needs a delegation of its own.
- Changing to the managed root clears the process's dumpable flag. It has to
  be set again before writing a child namespace's `uid_map`, and before pasta
  can open the launcher's `/proc/PID/ns/net`.
- nsresourced shortens long namespace names, which once made concurrent
  launches collide; the launcher uses short names with the PID in hex.
- nsresourced unregisters a namespace a moment after its last process ends,
  so anything that checks the registry right after a game exits must wait.
- systemd 261.3's write restriction did not hold in a child user namespace:
  a child could create files owned by the transient uid in a folder it was
  never given. 261.4 fixed this, hence the version requirement.
- The write restriction is a BPF program nsresourced loads once per boot and
  keeps pinned under `/sys/fs/bpf/systemd/`. It needs overlayfs loaded first
  (it reads the module's types), and on SELinux systems `sys_admin` for the
  same lookup; otherwise it refuses every overlay mount until reboot.
  Restarting the service doesn't replace it, and deleting the pins leaves the
  old programs attached and the restriction checking stale maps. If it never
  attaches, launches still work but nothing restricts writes, which is why
  a test checks for its `EPERM` (plain permission refusals are `EACCES`).
- Both services take descriptors over Varlink. When SELinux refuses one, the
  kernel drops it silently: the caller gets `ENXIO` and mountfsd's debug log
  says `SCM_RIGHTS truncated`; the audit log shows the cause. Receiving a
  descriptor is checked against its open mode: `read` for `O_RDONLY`, only
  `ioctl` for `O_PATH`. The launcher passes folders as `O_PATH` for that.
- openSUSE's audit rules begin with `-a never,task`, so audit records carry
  no syscall. Remove that rule temporarily to see which call was denied.
- Fedora's policy, which openSUSE's follows, gives mountfsd almost nothing:
  it was permissive until v45.8. Our module's comparison with it is in
  [systemd-backend/README.md](../systemd-backend/README.md).

### Storage and identities

- The kernel overlay ignores fuse-overlayfs's opaque and whiteout marks
  (`user.fuseoverlayfs.opaque`, `.wh..wh..opq`, `.wh.NAME` files);
  switching a capture to the systemd backend converts them.
- Changing an overlay's upper folder while it is mounted is undefined, under
  fuse-overlayfs and the kernel alike. `sandbox-attach --put` is the
  supported way to change a running game's files.
- Game files owned by another user can be read and new files saved, but
  replacing such a file can fail with `EOVERFLOW`, since its owner is not
  mapped. A copy of the game owned by you avoids that.
- Unit files under `/usr/local` are not available when PID 1 builds the
  boot transaction on openSUSE, where it is a separate subvolume; the
  administrator setup installs its units in `/etc/systemd/system`.

### Display, sound and network

- Through an idmapped folder, a desktop socket needs no ACL; the listener
  sees the game's transient uid as the peer.
- bwrap resolves even `--bind-fd` sources to paths, so a mount point staged
  under a home folder the namespace cannot enter fails. The probes use a
  private tmpfs over `/tmp` for mount points.
- pipewire-pulse answers `SET_CLIENT_NAME` before WirePlumber has let a
  restricted client see its own object; about 1 in 75 short clients of the
  playback-only server then fail with "Protocol error". This is PipeWire's,
  under every backend.
- The playback-only server still lists the sink's `.monitor`; recording from
  it is refused. Test the refusal, not the listing.
- To test that a game cannot reach host addresses, use an address distinct
  from the one pasta copies into the namespace: that one is local to the
  guest, so a refused connection there proves nothing.
- On a VM with only llvmpipe, gamescope aborts with
  `VK_ERROR_OUT_OF_DEVICE_MEMORY` under every backend; GPU checks need a real
  GPU. On a desktop GPU, frames reached the compositor and gamescope as
  DMA-BUF under both the default and the systemd backend.
- MangoHud can crash in its exit handler after mkxp-z closes its Wayland
  connection (exit 134 after "Shutting down."), independent of the sandbox.
