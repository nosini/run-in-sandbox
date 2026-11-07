# To do

## A systemd backend for a uid of its own

`SANDBOX_SEPARATE_UID=1` serves the game's folder and Proton through
`fuse-overlayfs`, because the kernel's overlay cannot copy up your files for a
uid that is not yours without an idmapped mount, and idmapping a host
filesystem takes root. That costs speed on every file the game reads, and a
change made straight in `rw/` while the game runs is not seen
(`sandbox-attach --put` is the way round that for now).

systemd-mountfsd and systemd-nsresourced hand out idmapped mounts and user
namespaces to unprivileged users, which would let the kernel's overlay back
these sandboxes. That is a second backend beside the subordinate-uid one, not
a change to `fuse_overlay()`:

| Now (`/etc/subuid`) | With mountfsd and nsresourced |
|---|---|
| each sandbox keeps BASE + 50000 + INDEX | each running namespace gets a transient range of 64K |
| your uid is root for setup; the sandbox's uid is the game's usual one | MountDirectory needs its own map, and shows your files as the namespace's root |
| `home/`, `rw/` and the prefix belong to the sandbox's uid | storage stays yours, or the foreign range's, and is idmapped |
| one shared group gets Wayland and sound | socket access has to follow the allocated ids |
| the render group, mapped from `/etc/subgid`, gets the GPU | needs another way: that extra gid does not fit the map |

Those assumptions run through `layout()`, `inside_launch()`, the socket ACLs
in sandbox-game and the choice of namespace for pasta.

Outline:

1. Allocate a managed user namespace per launch (nsresourced).
2. Get idmapped mounts of the game folder, Proton and the capture's storage
   (mountfsd).
3. Build kernel overlays in that namespace.
4. A child namespace that shows its root as the game's usual uid.
5. bwrap in there, with seccomp, Landlock and the namespaces as they are.
6. Adapt GPU and socket access, pasta, and the capture commands (`--delete`,
   `--reset-install`, `sandbox-uid run`, `sandbox-attach`).

To settle first:

- The game still has a host uid of its own, apart from you and from other
  sandboxes, but its files may belong to you on disk, reached through the
  mount's mapping. That changes the ownership-based isolation the current
  backend relies on; test what a game can reach that way.
- Opt-in, where the services exist: openSUSE Tumbleweed ships them (systemd
  261) with their sockets disabled by default. Debian 13's systemd 257 lacks
  the directory API. Keep the subordinate-uid backend as the fallback.
- Even the kernel's overlay does not promise that a change made straight in
  `rw/` during a run is seen; keep `sandbox-attach --put`.

### First experiment (2026-11-06)

The standalone [systemd backend probe](experiments/README.md) now exercises
managed allocation, idmapped game/capture directories, kernel overlay copy-up,
persistence across allocations, and a child namespace running bwrap with the
existing seccomp and Landlock helpers. Those mechanism checks passed on a
development VM; the launcher is unchanged.

The complete probe fails on systemd 261.3: its transient-ID write restriction
can be bypassed by the proposed child namespace. Stock SELinux policy also
blocks directory delegation; mechanism testing required temporary exceptions
for the two service domains, removed afterward. A follow-up test with the
openSUSE 261.4 daemons and their matching workers/library passed the complete
probe, including the child-namespace restriction. Enforcing SELinux policy
was subsequently tested with a small service-wide policy module: all probes
pass with SELinux enforcing. Idmapped socket access needs no ACL changes and
preserves the transient peer credentials. A caller-owned render-device alias
allows a DRM ioctl with no supplementary groups. Managed pasta passes DNS,
public IPv4 HTTP and private/host-route prohibitions. These are synthetic
fixtures, not real game rendering or display/audio protocol tests.

The [GPU lifecycle prototype](systemd-backend/render-devices.md) adds a root helper,
udev/systemd fixtures and a dedicated runtime tmpfs. Its 21 lifecycle tests and
live bind-mounted-alias allowlist/mount-stop revocation/regrant tests pass with
SELinux enforcing. Stopping the service also prevents queued events regranting.
The real udev change hook and runtime mount recreation also pass; physical
unplug/replug, reboot ordering and production packaging still need validation.

The [display/audio probe](experiments/media.md) now passes a real Wayland/EGL
window and playback-only Pulse clients through managed idmaps, bwrap, seccomp
and Landlock with SELinux enforcing. It checks rendered pixels, a compositor
frame callback and independently recorded playback, plus rejected source/monitor
recording and module loading. Rendering is llvmpipe on the VM; hardware
acceleration, DMA-BUF, Vulkan and gamescope/Proton remain unvalidated.

The launcher integration below covers namespace lifetime, capture migration,
attachment, maintenance and network policy. Administrator packaging and
accelerated rendering/gamescope validation remain open, along with public IPv6
traffic and other source filesystems. See the experiment notes for exact
coverage and setup/cleanup commands.

### Implementation handoff: next steps

`SANDBOX_SEPARATE_UID=systemd` is now a selectable launch path (step 1
below). The administrator pieces (service SELinux policy, render-copy helper)
are packaged by the explicit installer modes in step 4.
One-time administrator setup is accepted (including service SELinux policy and
GPU provisioning); ordinary launches must remain unprivileged. There is no
per-game SELinux policy or relabeling step.

1. **Opt-in launch path: done (2026-11-06).**
   - `sandbox-uid managed-launch CAP -- BWRAP...` takes the bwrap command
     `sandbox-game` builds. It delegates each folder of yours that bwrap reads
     from (or the folder of yours a file or socket is in), read-only unless a
     writable bind or an overlay's upper/work needs it, and mounts them back at
     their own paths. Paths you can't reach get a tmpfs covering them in that
     namespace only, as `stage()` does. It then mounts kernel overlays
     (`fsopen`, `lowerdir+`, `userxattr`), relays output, enters the child
     namespace and execs bwrap in the same process, so no setup descriptors or
     helper processes outlive it. mountfsd clones only one mount, so a folder
     with another mount between it and an already delegated one gets its own
     delegation. Sources that are neither yours nor reachable stop the launch.
   - `CAP/managed-uid` (storage format `1`) makes the setting stick, as
     `CAP/uid` does. Switching backends keeps the capture. From `1`,
     `reclaim` runs first. On entering `systemd`, `managed-adopt` adds
     `user.overlay.opaque` where fuse-overlayfs left
     `user.fuseoverlayfs.opaque` or `.wh..wh..opq` (the kernel reads neither),
     and turns `.wh.NAME` files into device whiteouts. fuse-overlayfs reads the
     kernel's marks once `work/work` is gone, which `unwork` now also does for
     this backend. Unavailable services stop the launch before anything changes.
   - The Wayland and playback-only Pulse sockets reach the game through
     `/run/user/UID` delegated read-only. No ACLs; without the sandbox's Pulse
     server there is no sound, as under `1`. `/dev/dri/renderD*` binds become
     `/run/sandboxgame/render/UID/renderD*` copies when present, otherwise a
     warning and software rendering.
   - `--stop` and `--list` work: you hold every capability in the managed
     namespace and the namespaces below it. Attachment is covered in step 3.
   - The SELinux module (now `systemd-backend/sandbox_game_systemd.te`)
     grants on the `user_home_type` and `user_tmp_type` attributes instead of
     `user_home_t` alone: the launcher's tools and Steam's Proton live in
     `data_home_t`, the sockets in `user_tmp_t`.
   - Tested on the VM (systemd 261.4 from the repository, SELinux enforcing):
     a native payload writes, exits and relaunches under another transient
     range with its data intact, and on disk everything stays the caller's.
     Also tested: real Wayland (`vkcube` on GNOME), a DRM ioctl through the
     render copy, Proton with its throwaway `/proton` overlay, switching
     `1 -> systemd -> unset -> 0 -> systemd`, and launches killed during setup
     (no leftover processes, allocations or mounts). `SystemdBackendTests` in
     `tests/test_security.py` cover this and skip without the services. The
     full suite passed: 245 tests, 3 skipped.
   - Tested later in step 5: a caller whose primary GID differs from UID gets
     an unwritable overlay with this mapping. Setup/launch now refuse that
     unsupported identity before changing the capture. mountfsd maps the
     caller's uid number for gids too, so new files get gid = uid.
   - `--host-x11` (2026-11-07): binding `~/.Xauthority` made mountfsd delegate
     your home, which SELinux refused (`user_home_dir_t`, ENXIO); under `1`
     the 0600 file was unreadable to the sandbox's uid. sandbox-game now
     passes a copy (`--ro-bind-data`), so nothing is delegated for it. A real
     X11 handshake with the cookie passes under `systemd`; tests cover all
     three backends.

2. **Namespace lifetime and the full network policy: done (2026-11-06).**
   - `sandbox-uid managed-launch --net SPEC` creates the game's network
     namespace itself, in the managed namespace, before bwrap, which keeps it
     (`--share-net`, added by sandbox-uid). The game has no capabilities in
     the namespace that owns it.
   - pasta (the copy named after the game) runs `--foreground` from the host
     network, as the managed root, under a keeper process. The kernel signals
     the keeper when the outer bwrap ends (`PR_SET_PDEATHSIG`; pasta's own
     would be cleared when it drops to nobody), and the keeper then ends
     pasta. There's no pid file, and bwrap's info and block descriptors
     aren't used under this backend. sandbox-uid waits for pasta's default
     route, then applies the rules.
   - `NET_HELPER` now computes the rules first; called without a pid, it only
     prints them with pasta's settings as JSON, which `sandbox-game` passes to
     sandbox-uid. The other backends apply them as before.
   - `pasta` must open `/proc/PID/ns/net` of the launcher, so the launcher sets
     itself dumpable again after changing to the managed root.
   - sandbox-uid records the managed namespace (`CAP/.managed-userns`, device
     and inode). `sandbox_user` recognises the outer bwrap by its user
     namespace's parent being that one, replacing the uid-range check.
   - Tested on the VM, as `SystemdBackendTests`:
     - the existing internet, LAN-allowance, MAC, stdin and pasta-naming
       tests, run under this backend;
     - the game can't change rules or links;
     - nothing reaches a port the game listens on, from any host address
       (also a new test for the other backends);
     - two games with their own pastas, where stopping one leaves the
       other's DNS working;
     - `--list` ignores a sandbox whose recorded namespace doesn't match.
   - IPv6, tested by hand: in a root-made dual-stack namespace on the VM
     (dummy interface, `2001:db8:1::/64` and `fd12:3456::/64`), the LAN, ULA
     and multicast are refused while public addresses go to pasta. The
     results were identical under `systemd` and `0`. The VM has no IPv6, so
     public IPv6 traffic itself is untested.

3. **Attachment and capture maintenance: done (2026-11-06).**
   - `sandbox-attach` finds the live namespace through `CAP/.managed-userns`
     (see step 2), selects bwrap's child rather than the output relay or pasta
     keeper, and enters the allocated namespace first. There it drops the
     supplementary groups before entering bwrap's child namespace, which
     denies `setgroups`, as the game's uid and gid.
   - `--exec`, shells, terminal relaying and `--put` work. Keep `--put` as
     the supported way to change live overlay content; editing raw `rw/`
     during a run remains unsupported. Attached programs keep the existing
     environment, descriptor and Landlock protections.
   - `sandbox-uid run` runs directly as you for a managed capture, whose
     files already belong to you. List, reset-install and delete use the
     existing maintenance path and are covered under this backend too.
   - Switching away from a subordinate uid removes its access/default ACL
     entries after reclaim, before releasing the uid. Failure retains the
     uid metadata so cleanup can be retried. Cleanup never allocates a uid.
     Progress output for large first migrations remains an optional improvement.
   - VM verification with SELinux enforcing: full suite 267 tests, 3 skipped.
     New cleanup regressions also fail when their fixes are removed.

4. **Administrator setup and availability checks: done (2026-11-07).**
   - `sudo ./install.sh --systemd-backend UID...` installs the render helper,
     dedicated tmpfs mount, service, complete UID allowlist and udev rule.
     Explicit updates revoke old aliases before changing helper/configuration.
     Ordinary per-user installs remain separate. openSUSE Tumbleweed only;
     other distributions are not planned (decided 2026-11-07).
   - The installer verifies managers, workers, linked shared library and vendor
     units against one unmodified source RPM build, stable 261.4 or later.
     It installs the service-wide SELinux module before socket activation,
     preloads overlayfs, and installs a required overlay boot-ordering drop-in.
     Existing policy covers runtime parents created manually and by PID 1.
   - Each launch queries both live workers' GetInfo versions and the directory
     API. Old, unknown or mismatched versions are refused before a capture is
     changed. The subordinate-UID backend remains available; an unavailable
     explicit/sticky systemd selection never silently falls back.
   - `sudo ./install.sh --uninstall-systemd-backend` disables the event hook,
     revokes aliases, stops the service/mount, removes packaged files/policy,
     and restores prior socket enablement. Captures, per-user tools and the
     root allowlist stay. Interrupted installations can also be removed.
     Both modes refuse active delegation resources, checking the namespace
     registry as well as PID 1's descriptor store.
   - Verified with SELinux enforcing: install, repeat install, interrupted
     install cleanup, unit/udev validation, removal and original socket-state
     preservation. Full suite: 276 tests, 3 skipped; 14 focused setup tests;
     21 render lifecycle tests; live allowlist and mount-cycle revocation.
     A running game blocks install/removal and keeps working. Physical GPU
     hotplug, boot testing and acceleration remain in step 5.

5. **Graphics and lifecycle validation: in progress (2026-11-07).**
   - Added `systemd-backend/test_storage_live.py`: Btrfs baseline plus tmpfs,
     ext4 and XFS, with source/capture together and split across filesystems.
     Eight checks per layout cover ownership/persistence, switching backends,
     attachment, maintenance, dropped groups/caps/descriptors, repeated
     allocation release and concurrent captures. All ten layouts pass (80
     checks, none skipped) after correcting buffered readiness reads that lost
     test output. The controller rejects unavailable services, skipped checks
     and empty runs so missing coverage cannot report success.
   - Concurrent launches exposed nsresourced shortening the UID-prefixed
     `sandbox-game-PID` names and dropping PID digits. Short hex-PID names
     retain uniqueness even with ten-digit caller UIDs. The deterministic
     regression fails with the previous name; live concurrent tests pass.
   - Public foreign-owned game data can be read, new files/saves captured, and
     closed directories remain refused. Existing permissions remain enforced;
     replacement of lower inodes with unmapped ownership can fail EOVERFLOW.
     Games needing those writes should use a caller-owned source copy.
     Accepted as a documented limitation (2026-11-07).
   - A caller with primary GID != UID produced a read-only overlay. Setup
     and launch now reject this unsupported identity explicitly, with unit
     checks and a real mismatched-GID process verifying new/existing captures
     stay untouched.
   - Why, probed 2026-11-07 with a real uid 1500/gid 100 (`users`) account:
     mountfsd's `root` mapping maps the uid number only, for both owner and
     group, and the kernel refuses any write to an inode with an unmapped
     owner or group (`HAS_UNMAPPED_ID`), even for its owner: `EACCES` on the
     capture (overlay `work/work`, so read-only), `EACCES` connecting to the
     desktop's Wayland/Pulse sockets, and copy-up `EACCES`/rename `EOVERFLOW`
     on game files. Inside, the owner may chgrp to the namespace's gid 0
     (your uid number on disk), which fixes the capture, but the game folder,
     Proton and the desktop's sockets would need the same on every launch.
     Done instead (2026-11-07): uid = gid stays required, and
     systemd-backend/README.md ("Your account's group") explains moving the
     account to a group of its own (Tumbleweed's default now). Launch checks
     the group of what the game writes to, connects to or copies up from,
     and adopting a capture checks all of it once, naming the `chgrp -R`.
     Verified with a real migrated account: `usermod -g` regroups the home
     folder itself; files put back in `users` are refused with the right
     commands, and the launch works after running them. Full suite 299, 4 skipped.
   - The EGL probe now reports the actual EGL device/render node, and
     `--require-hardware` rejects software or missing device evidence. It uses
     a GL compositor by default. This VM reports llvmpipe/no render node and
     correctly fails that requirement; no acceleration is claimed.
   - Complete private media playback/recording-denial checks passed again.
     The intermittent Pulse `Protocol error` is not this backend's: with no
     sandbox at all, about 1 in 75 short clients of the restricted server
     fail (8/600; the unrestricted server on the same graph: 0/600). pipewire-pulse
     (1.6.9 and master) answers SET_CLIENT_NAME at its first sync, before
     WirePlumber has let the client see its own object, and sends index
     4294967295, which libpulse rejects. It affects `--restrict-audio` under
     every backend. The fix would be in PipeWire (wait for that object
     before replying); not patched here, accepted as a known limitation
     (2026-11-07). Commands and limitations are in the [validation runbook](systemd-backend/validation.md).
   - Full regression suite with the identity guards: 289 tests, 4 skipped;
     with the `--host-x11` fix, 293 tests, 4 skipped (2026-11-07).
     One earlier overlapping stress run saw an ordinary overlay mount EPERM;
     12 targeted repetitions and the later full suite passed. Two more full
     suites run during the complete storage matrix (2026-11-07) all passed,
     with the matrix's 10 layouts. Not reproduced; cause unconfirmed.
   - Run accelerated OpenGL and Vulkan rendering through the mapped alias on
     suitable hardware; report the selected renderer/device and reject software
     fallback when claiming acceleration. Exercise DMA-BUF transport, gamescope,
     Xwayland, a native game and a Proton game. Check whether card-node metadata
     access needed by gamescope requires additional handling.
   - On the user's desktop (2026-11-07; RX 9070 XT, Mesa 26.2.5, gamescope
     3.16.31, systemd 261.4; `desktop-gpu-check.sh`): under `systemd` the game
     had the helper's copy of renderD128 (yours, 0600) and the capture was
     marked; `vulkaninfo` lists the RX 9070 XT (RADV) first; `vkcube` drew 300
     frames on it in a desktop window and inside nested gamescope, which
     selected it too; glxinfo in gamescope's Xwayland reports radeonsi.
     Identical to `0`, gamescope's PipeWire/"Compositor released us" errors
     included. So nested gamescope needs no extra card-node handling.
     Window presentation to the compositor and to gamescope went through
     DMA-BUF implicitly; not checked on its own. Still open: EGL directly
     (no mesa-demos there), and a real native and Proton game.
   - gamescope on the VM (2026-11-07, 3.16.31 nested in GNOME): under `0` and
     `systemd` alike it selects llvmpipe, then aborts on `vkAllocateMemory`
     (`VK_ERROR_OUT_OF_DEVICE_MEMORY`) before any window; unsandboxed
     headless gamescope runs. llvmpipe lacks `VK_EXT_physical_device_drm`, so
     gamescope's card/render node matching is never reached there: the
     card-node question needs a real GPU.
   - The VM's llvmpipe result neither proves nor rules out acceleration through
     this backend. Opening the alias and a DRM version ioctl are already proven;
     accelerated rendering is not. Suitable hardware access must be provided
     within the authorized test environment; desktop access is not implied.
   - Validate physical GPU unplug/replug, stale device-number reuse, multiple
     GPUs, reboot ordering, allowlist changes and orderly service/mount stops.
     Existing tests cover synthetic lifecycle cases, a real udev change event
     and live alias revocation/regrant, not physical hotplug or reboot.
     Suitable GPU access and agreement on a shared-VM reboot window are still
     pending; no reboot has been performed.
   - Storage/lifetime checks above cover these four filesystems and public
     foreign ownership, repeated starts/stops, concurrent games and capture
     operations. Keep testing other filesystem/ownership combinations and
     existing backends. Do not enable the backend by default based on probes.

### Resume information

- Start with [experiment coverage/setup](experiments/README.md),
  [administrator setup](systemd-backend/README.md),
  [GPU provisioning](systemd-backend/render-devices.md), and
  [validation commands and remaining checks](systemd-backend/validation.md).
  [Real display/audio results](experiments/media.md) and the probe scripts contain
  working setup details; they are not production launcher code.
- The VM now runs systemd 261.4 from the Tumbleweed repository (upgraded
  2026-11-06; PID 1 included). On it, the setup for this backend is: build and
  `systemd-backend/README.md` (module, `modprobe overlay`, sockets) and, for
  the GPU, `systemd-backend/render-devices.md`.
- After the latest step 5 tests, administrator setup was uninstalled, render
  aliases revoked, the policy removed and the original disabled/inactive socket
  state restored. VM source copies, captures and storage fixtures were removed;
  results were collected locally and this task's VM hold was released. Shared
  BPF pins and other tasks' work/holds remain. Reinstall administrator setup
  before a future boot check and acquire a new task hold for detached work.
- Logs: `~/run-in-sandbox/reviews/systemd-launch-20261106/` and
  `systemd-net-20261106/` (suite logs and state), and the earlier
  `systemd-{2614,access,render-lifecycle,media}-20261106/`.
  Attachment/maintenance logs are in `systemd-attach-20261106/`;
  `final-suite.log` covers the finished step 3 changes.
  Packaging/setup logs are in `systemd-package-20261106/`.
  Step 5 storage/graphics logs are in `systemd-validation-20261107/`; the
  later suite reruns, `--host-x11`, Pulse race and overlap logs in
  `systemd-step5b-20261107/`.
  Shared memory note `~/memory/systemd-idmapped-directory-delegation.md` has
  cross-project findings, including policy/overlay startup ordering and labels.
