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
below). The installer is unchanged; the administrator pieces (service SELinux
policy, render-copy helper) are in `systemd-backend/`, set up by hand.
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
   - Not yet tested: a caller whose gid differs from their uid. mountfsd maps
     the caller's uid number for gids too, so new files get gid = uid.
     `--host-x11` delegates `$HOME` itself for the X authority file
     (`user_home_dir_t`, perhaps not in `user_home_type`).

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

4. **Package administrator setup and backend availability checks.**
   - Integrate the render helper, dedicated tmpfs mount, service, UID allowlist
     and udev rules from `systemd-backend/` into install.sh; include removal and
     revocation behavior.
   - Package and review the service-wide SELinux module for supported systems.
     Install policy before first daemon activation and load overlayfs before
     initializing nsresourced's BPF restrictions. Cover both manually created
     `var_run_t` and PID1-created `init_var_run_t` runtime parents.
   - Use matching delegation managers, workers, shared library and service units.
     Merely finding MountDirectory is insufficient: the proposed child namespace
     bypasses the transient-write restriction in tested 261.3; tested 261.4
     passes. Gate unsupported versions/setups and explain setup failures.
   - Keep the subordinate-UID backend available. Reject an explicitly requested
     unavailable backend clearly; never silently reinterpret existing captures
     using another backend. Document selection, installation and rollback.

5. **Complete graphics and lifecycle validation before normal use.**
   - Run accelerated OpenGL and Vulkan rendering through the mapped alias on
     suitable hardware; report the selected renderer/device and reject software
     fallback when claiming acceleration. Exercise DMA-BUF transport, gamescope,
     Xwayland, a native game and a Proton game. Check whether card-node metadata
     access needed by gamescope requires additional handling.
   - The VM's llvmpipe result neither proves nor rules out acceleration through
     this backend. Opening the alias and a DRM version ioctl are already proven;
     accelerated rendering is not. Suitable hardware access must be provided
     within the authorized test environment; desktop access is not implied.
   - Validate physical GPU unplug/replug, stale device-number reuse, multiple
     GPUs, reboot ordering, allowlist changes and orderly service/mount stops.
     Existing tests cover synthetic lifecycle cases, a real udev change event
     and live alias revocation/regrant, not physical hotplug or reboot.
   - Test other source filesystems and sources owned by another user, repeated
     starts/stops, concurrent games, capture operations and existing-backend
     regressions. Do not enable the new backend by default based on probes alone.

### Resume information

- Start with [experiment coverage/setup](experiments/README.md),
  [administrator setup](systemd-backend/README.md),
  [GPU provisioning](systemd-backend/render-devices.md), and
  [real display/audio results](experiments/media.md). The probe scripts contain
  working setup details; they are not production launcher code.
- The VM now runs systemd 261.4 from the Tumbleweed repository (upgraded
  2026-11-06; PID 1 included). On it, the setup for this backend is: build and
  `systemd-backend/README.md` (module, `modprobe overlay`, sockets) and, for
  the GPU, `systemd-backend/render-devices.md`.
- After the step 1, step 2 and step 3 tests, the module, render helper and test
  captures were removed and the sockets stopped. The services' BPF pins from that run were
  left in place: they were created with the policy loaded.
- Logs: `~/run-in-sandbox/reviews/systemd-launch-20261106/` and
  `systemd-net-20261106/` (suite logs and state), and the earlier
  `systemd-{2614,access,render-lifecycle,media}-20261106/`.
  Attachment/maintenance logs are in `systemd-attach-20261106/`;
  `final-suite.log` covers the finished step 3 changes.
  Shared memory note `~/memory/systemd-idmapped-directory-delegation.md` has
  cross-project findings, including policy/overlay startup ordering and labels.
