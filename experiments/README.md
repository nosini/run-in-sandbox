# systemd backend experiment

`systemd-backend.py` exercises the namespace and storage path proposed in
[TODO.md](../TODO.md). It is a disposable integration probe, separate from
the launcher. It delegates only synthetic directories, removes them on exit,
and never opens existing game captures. It needs Python 3, bubblewrap with
`--bind-fd`, libseccomp, Landlock, and systemd's `MountDirectory` API (258+).
The service's write restrictions also need to survive child user namespaces;
the API's presence alone is insufficient.

On a test machine, start the two sockets if they are not already active:

```sh
sudo systemctl start systemd-nsresourced.socket systemd-mountfsd.socket
mkdir -p ~/run-in-sandbox/builds/systemd-probe
python3 -I experiments/systemd-backend.py \
  --work-dir ~/run-in-sandbox/builds/systemd-probe
```

Run the script as an ordinary user from a complete checkout. It compiles the
checkout's seccomp filter and uses its Landlock helper. It changes no service
configuration or policy. If the sockets were originally inactive, stop both
sockets and services after testing:

```sh
sudo systemctl stop systemd-mountfsd.socket systemd-mountfsd.service \
  systemd-nsresourced.socket systemd-nsresourced.service
```

Each run makes two independent managed namespaces with different allocation
names, retaining one caller-owned capture between them. It checks:

- A 64K transient UID/GID allocation through nsresourced, without newuidmap.
- Read-only game and writable capture mounts through mountfsd, using `mode=root`.
- A kernel overlay whose upper and work directories share the capture mount.
- Reads, copy-up, new files, a deletion whiteout, and home writes.
- Persistence with the next allocation, and caller ownership of written files
  on disk rather than ownership by the transient UID.
- A child namespace mapping managed root to the caller's usual UID/GID.
- Real bwrap with the project's seccomp and Landlock helpers: no effective
  capabilities, blocked user-namespace creation, no leaked setup descriptors,
  and a Landlock-denied write to an otherwise writable sandbox directory.
- Denial of reads from a caller-owned 0600 file through an intentionally kept
  raw directory FD. This tests permissions even if a pathname becomes reachable.
- Denial of persistent writes through an undelegated, world-writable directory,
  both before and after entering the child user namespace.

The negative tests intentionally keep a raw directory FD during setup. It is
closed before bwrap; the payload sees only its standard descriptors. The probe
does not run untrusted programs. A nested-policy failure is reported after both
launches so that their other results remain visible; exit status 1 means the
full probe did not pass.

## Results, 2026-11-06

Tested on openSUSE with systemd/systemd-container 261.3 and kernel 7.2.8,
with a caller-owned Btrfs fixture. These are development VM results, not a
test of a desktop game or the existing launcher.

The namespace, idmapped kernel overlay, persistence, child UID, bwrap, seccomp
and Landlock checks passed. Two launches used different transient bases,
1262419968 and 1151270912, while both captures stayed UID/GID 1000 on disk.
Reads through the raw FD to the caller-owned private file failed with EACCES.

Two blockers were reproduced:

1. **SELinux service policy.** In enforcing mode, `systemd_mountfsd_t` cannot
   receive/read a `user_home_t` directory FD or use the user-namespace FDs.
   `systemd_nsresourced_t` also cannot receive the returned directory mount FD.
   The services return `io.systemd.System`/ENXIO, and mountfsd's debug journal
   says `SCM_RIGHTS truncated`; the audit log identifies the SELinux denial.
   For the mechanism tests only, both service domains were temporarily made
   permissive. Other domains and the BPF policy remained enforcing. Both
   exceptions, a temporary debug drop-in, and the started services/sockets
   were removed afterward. A production solution needs service policy support;
   these results do not demonstrate operation with the stock enforcing policy.
2. **Nested BPF restriction gap in 261.3.** A raw write fails with EPERM in
   the managed namespace, but succeeds after the child user namespace is
   created. The resulting persistent inode is owned by the transient host UID.
   This happened with both allocations. The probe reports it and exits 1 after
   cleanup. It is not an escape from the tested bwrap/Landlock payload, which
   has no such raw FD. It does invalidate relying on this service version to
   enforce the proposed transient-storage rule through child namespaces.

The source research in TODO.md used newer openSUSE 261.4 code, including
stronger descendant-namespace and overlay checks. Follow-up runtime results
for that version are below.
The service's intended persistence rules are described in the upstream
[nsresourced documentation](https://www.freedesktop.org/software/systemd/man/latest/systemd-nsresourced.service.html).

Two setup details matter: changing to managed root clears dumpability, so it
must be restored before writing the child namespace's `/proc/self/*_map`
files. Also, bwrap canonicalizes even `--bind-fd` sources; staging beneath an
untraversable host home fails. The probe uses a small private tmpfs over `/tmp`
in its mount namespace, holding mount points only, without changing host paths.

## Follow-up: 261.4 (2026-11-06)

The complete probe **passed** with openSUSE's signed 261.4-1.1 packages.
Both iterations returned EPERM for raw writes in the managed namespace and
its child. Copy-up, persistence, caller ownership on disk and the protected
bwrap payload all continued to work. The two transient bases were 1659895808
and 2555904. This resolves the observed 261.3 child-namespace restriction gap
for this tested setup.

Only the delegation daemons, their worker executables and matching private
shared library were used from the downloaded RPMs. The VM's installed systemd
and PID 1 were not upgraded. Temporary service overrides selected the private
copies; worker paths were bound inside the services' mount namespaces only.
Running worker executable hashes were checked against the private copies.
The same temporary SELinux exceptions were needed for the mechanism test;
this does not establish that stock enforcing SELinux works with 261.4.

The 261.4 namespace service must load overlayfs before loading its BPF
program: the checks depend on the module's BTF type information. The newer
package's unit adds `Wants=`/`After=modprobe@overlay.service`. Testing private
binaries with the older unit initially retained a fail-closed BPF attachment
that rejected overlay mounts. A clean service start with overlayfs already
loaded, after removing only this experiment's pinned v2 attachments, passed.
Use matching service units as well as matching binaries for deployment.

## Before launcher integration

The access and network experiments below resolve several of the initial
questions. Still needed: actual display/audio clients and GPU rendering,
installation/udev support, capture maintenance and attachment, two concurrent
game processes, other source filesystems and sources owned by another user.
Existing subordinate-owned captures need an explicit storage migration design.

No backend switch, automatic migration, GUI preference, installer change or
fallback change is part of this experiment. `sandbox-attach --put` remains
necessary for supported writes to a running overlay; live edits to its raw
upper directory are not made safe by switching from FUSE to the kernel.

## Enforcing SELinux, sockets and GPU access

The storage probe now passes with **SELinux enforcing** and the explicit
[`sandbox_game_systemd_probe.te`](selinux/sandbox_game_systemd_probe.te) module.
No service domain is permissive. This is a development module for the tested
openSUSE policy, not an installer-ready policy for every distribution. It
extends existing service domains, with no game labels or per-game policies.
It permits directory/namespace descriptor handling and the privileged
namespace operations the delegation services perform. Their Varlink caller
ownership checks remain in place. It does not grant general home-file data
access to mountfsd; the process-type file read rule is for namespace proc files.

On an isolated test system with SELinux development tools installed:

```sh
probe_dir="$HOME/run-in-sandbox/builds/systemd-probe"
mkdir -p "$probe_dir"
checkmodule -M -m -o "$probe_dir/sandbox_game_systemd_probe.mod" \
  experiments/selinux/sandbox_game_systemd_probe.te
semodule_package -o "$probe_dir/sandbox_game_systemd_probe.pp" \
  -m "$probe_dir/sandbox_game_systemd_probe.mod"
sudo semodule -i "$probe_dir/sandbox_game_systemd_probe.pp"
```

Install the module before the first start of the private test daemons, and
preload overlayfs before starting nsresourced. Initializing its BPF policy while
SELinux still denies the required capability can leave a fail-closed overlay
restriction pinned even after installing the module. The disposable VM fixture
was stopped and its own v2 pins recreated after correcting this setup order;
the complete storage probe then passed again.

Installing the module is an administrator operation, once for the services.
The individual probes and sandbox allocations run unprivileged. After testing,
remove it with `sudo semodule -r sandbox_game_systemd_probe`. Keep these build
outputs in a scratch directory; none belongs in the source tree.

[`systemd-access.py`](systemd-access.py) allocates two managed namespaces at
once, each with its own mapped storage. It tests a caller-owned 0600 Unix
socket both directly and through an idmapped directory mount. Raw access fails
with EACCES, while mapped access succeeds. The listener sees the transient
**host UID/GID**, not the desktop user's identity. Through bwrap it sees the
same credentials; only the selected socket is bound, leaving its sibling
socket and private file absent. No socket ACL is changed. A namespace cannot
read the other namespace's private file even through an intentionally retained
FD to the other namespace's idmapped mount. These are kernel/socket fixture
tests, not yet a Wayland or Pulse protocol test.

```sh
python3 -I experiments/systemd-access.py \
  --work-dir ~/run-in-sandbox/builds/systemd-probe
```

GPU access also passed an initial test. An administrator created a
caller-owned alias device node, with the same device number and SELinux label
as the render node, in a caller-owned directory on Btrfs. Delegating that
directory with `mode=root` lets the transient identity open the alias, including
through bwrap, and issue `DRM_IOCTL_VERSION`. Opening the original root-owned
render node fails. All probes now explicitly clear supplementary groups before
entering the child namespace and verify none reach the payload. Thus this path
does not depend on retaining the desktop user's group access.

Given such a **previously provisioned test alias** named `renderD128`:

```sh
python3 -I experiments/systemd-access.py \
  --work-dir ~/run-in-sandbox/builds/systemd-probe \
  --device-dir /path/to/render-alias
```

The follow-up [render-device lifecycle prototype](render-devices.md) now
provides an administrator helper, root-controlled private inode references,
a dedicated runtime tmpfs, and systemd/udev fixtures. It tests removal and
regrant against an alias already bound into a running protected client, with
SELinux enforcing. Actual unplug/replug, reboot and production packaging
remain untested. The original render node's ownership and ACL are unchanged.
Only opening the node and DRM ioctls were tested, not OpenGL/Vulkan rendering
or a game.

## Managed pasta and network policy

[`systemd-network.py`](systemd-network.py) runs pasta in the managed user
namespace while retaining the host network namespace for its outward sockets.
The guest network namespace is owned by the managed namespace. This is a
different placement from the extra parent-namespace lookup used by the
subordinate-UID launcher; the live namespace FD should be retained explicitly
by the future backend. Pasta runs in the foreground for the test and is
terminated/reaped afterward, without a raw persistent pidfile.

The protected bwrap/seccomp/Landlock payload passed a DNS query through pasta
and an HTTP HEAD request to example.com's public IPv4 address. Private-range
route lookups failed. A listener confirmed reachable on the test host's
secondary address was refused by the guest with a routing-policy error, before
any packet could leave. That address must be distinct from the default-interface
address pasta copies into the guest: the copied address is guest-local, so
ECONNREFUSED there alone would not test the host-address prohibition.

To reproduce on an **isolated test VM**, provision a disposable secondary
address (the commands fail if the interface name already exists):

```sh
sudo ip link add sgsdprobe0 type dummy &&
sudo ip address add 192.0.2.123/32 dev sgsdprobe0 &&
sudo ip link set sgsdprobe0 up
python3 -I experiments/systemd-network.py --host-test-address 192.0.2.123
sudo ip link delete sgsdprobe0
```

No LAN endpoint is contacted. This tests the IPv4 policy pattern; IPv6,
incoming-connection rejection, and the launcher's full LAN-allowance logic
still need integration tests. Pasta's host UID was verified to be inside the
managed range, distinct from the caller. Public egress from the game ran with
no effective capabilities, supplementary groups, or ability to create user
namespaces, as in the other protected payload tests.

All three probes passed together with the same 261.4 daemons, matching workers
and private library, enforcing SELinux plus the development module, and
supplementary groups cleared. The temporary policy module, device alias,
network interface, service overrides, private binaries and BPF pins were
removed after testing; the originally inactive services and sockets were stopped.


## Real display and audio clients

The [media probe](media.md) now tests a real xdg-shell/EGL client and Pulse
playback/recording policy through managed idmaps and the protected bwrap
payload. It passed with enforcing SELinux: known pixel readback, compositor
frame callback, independently observed playback, denied recording (including
sink monitor), and denied module loading. The production audio configuration
and WirePlumber scripts work unchanged for the transient client identity.

The test policy needed directory-FD rules for `init_var_run_t` when PID 1
created the render-store parent, in addition to the previously tested manually
created `var_run_t` parent. The runtime fixtures were then removed.
The VM rendered through llvmpipe: accelerated GPU rendering, DMA-BUF, Vulkan,
gamescope and native/Proton games remain untested. See the linked notes for
reproduction and the distinction between socket/device access and rendering.
