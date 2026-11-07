# Administrator setup for the systemd backend

`SANDBOX_SEPARATE_UID=systemd` (see "The systemd backend" in the main
[README](../README.md)) runs unprivileged, but needs administrator setup once.
The backend is opt-in and is never selected automatically.
The [validation runbook](validation.md) records coverage and the remaining checks.

The administrator installer supports **openSUSE Tumbleweed** only, with
matching systemd and systemd-container packages, stable **261.4 or later**.
261.3 lets a nested namespace get round nsresourced's write restrictions.
On SELinux systems, checkmodule, semodule_package, semodule and restorecon
must be installed (the policy development tools).
Each launching user's primary group must have their uid's number; see
[Your account's group](#your-accounts-group).

From a complete checkout, install the ordinary per-user tools first. Stop
games and other users of managed namespaces before installing or updating
the administrator setup. Then run:

```sh
./install.sh
sudo ./install.sh --systemd-backend "$(id -u)"
```

The UID arguments are the complete GPU allowlist, replaced on every run;
for several users, supply all their numeric host UIDs. This grants render
access independently of desktop seats. It does not change the original GPU
device permissions. A regular `./install.sh` never changes this root setup;
rerun the explicit administrator command to update it.

The installer verifies the packaged managers, workers, shared library and
vendor units against one source RPM build, installs the service-wide SELinux
module before socket activation, and loads overlayfs. It installs an overlay
ordering drop-in, enables the delegation sockets, and installs/enables the
render helper, dedicated tmpfs mount, service and udev rule. Updates revoke
old render aliases before replacing the helper or allowlist. Details of the
GPU grants and their revocation limits are in [render-devices.md](render-devices.md).

Administrator files live under `/usr/local/libexec/sandbox-game`,
`/etc/udev/rules.d` and `/etc/systemd/system`. Unit definitions live in `/etc`
so PID 1 can load them before openSUSE mounts the separate `/usr/local`
subvolume; the service waits for the helper's filesystem. Updates move units
from the previous `/usr/local/lib/systemd/system` location automatically.
The root-owned allowlist is `/etc/sandbox-game/systemd-render-users`;
`systemd-backend.json` beside it records the installation and previous socket
enablement. Existing manual fixture installations must be removed first.

Select the backend for a game:

```sh
SANDBOX_SEPARATE_UID=systemd sandbox-game /path/to/game ./start.sh
```

The capture remembers the choice. Ordinary launches need no sudo, polkit
prompt, per-game policy or relabeling. Each launch queries both workers and
requires matching supported version strings and the directory API before
changing the capture. Missing/unsupported services stop the launch; they
never cause a capture to fall back to another backend. For a checkout,
`./sandbox-uid managed-available` runs the same availability check.

## Your account's group

systemd-mountfsd maps one number into the sandbox: your uid's, for owners and
groups alike. The kernel lets no one, not even the owner, write to a file
whose group the mapping lacks, or connect to such a socket. So the backend
needs your primary group to have your uid's number, and everything the game
writes to, connects to or copies up from to belong to it.

Current openSUSE Tumbleweed gives each new account a group of its own with
that number. Older accounts often have `users` (100) instead. The installer
refuses such an account, and the launcher checks your primary group before
changing anything, the whole capture before it converts it to this backend,
and the game's folder, Proton and the desktop's sockets on every launch. It
names what to change. A launch stopped by the last of those leaves the
capture switched; change what it names and launch again.

To move an account (here `alice`, uid 1000) to a group of its own:

```sh
getent group 1000                     # must print nothing, or alice's group
sudo groupadd -g 1000 alice
sudo usermod -g alice -aG users alice # keep `users` as a supplementary group
```

If a group with that number already belongs to someone else, this account
cannot use the backend. `usermod -g` also gives the new group to the files
in your home folder that had the old one, captures and Steam's Proton
included. Then log out completely and back in (reboot if the user manager
lingers), so that the desktop makes its sockets with the new group.

Game folders elsewhere, on another drive say, keep the old group. Give them
the new one as the launcher's message lists them; you own them, so no root
is needed:

```sh
chgrp -R alice /mnt/games/NAME
```

Files you make from then on belong to `alice` rather than `users`: other
members of `users` lose group access to them. The launcher checks the
folders themselves on every launch, and the whole capture once when a game
first switches to this backend; files deeper in a game folder that kept the
old group fail when the game changes them, so regroup folders whole.

## Setup failures and removal

If setup fails, the root-owned state file lets the removal command clean an
interrupted installation too. Fix the reported dependency, package mismatch
or configuration problem and rerun the administrator installation command.
The availability query checks the service version and API, not a complete
namespace/mount launch. A service-policy or kernel/BPF failure can still
stop a launch, which reports the delegation error.

If nsresourced started before the SELinux module was installed or before
overlayfs was loaded, pinned BPF restrictions can refuse overlay mounts even
after setup is corrected. Stop the games, install the policy/setup, and
reboot; restarting the daemon alone does not replace its pinned restriction.
The installer does not delete shared BPF state.

To switch a capture back, launch that game once with `SANDBOX_SEPARATE_UID=1`
(the subordinate-uid backend, which needs its own setup) or
`SANDBOX_SEPARATE_UID=0` (your uid). Its saves and prefix are kept. Then stop
the games and remove the administrator setup:

```sh
sudo ./install.sh --uninstall-systemd-backend
```

Removal disables the event hook, revokes render aliases, stops the service
and mount, removes the packaged policy/helper/units, and disables only the
delegation sockets this installation enabled. Shared idle delegation services
are stopped before policy removal; their vendor units are kept. The GPU
allowlist, per-user tools, settings and captures are kept. A capture still
marked `systemd` refuses to launch after removal until you explicitly switch
it to another available backend. Normal `./install.sh --uninstall` removes
only the per-user installation and its optional sound setup.

## SELinux service policy

[`sandbox_game_systemd.te`](sandbox_game_systemd.te) extends the existing
`systemd_mountfsd_t` and `systemd_nsresourced_t` domains of openSUSE
Tumbleweed's policy. It has no game domain, per-game labels or relabeling.
The services take folders of your home, your runtime directory and game
folders elsewhere (a drive under `/mnt` or `/run/media`, FAT, exFAT, NTFS
or another FUSE filesystem, a folder at `/`) by descriptor, and handle
namespaces; their Varlink checks that the caller owns what it hands over
stay in place. The launcher passes those folders as
`O_PATH` descriptors, so neither service may list them or read files in them,
and neither may issue ioctl calls on them (one read-only command excepted).
Stock policy lets mountfsd mount nothing at all; the module gives it the
capabilities and namespace access its worker needs. nsresourced gets
`sys_admin` only for loading its BPF write restriction (see below).

Upstream policy (Fedora's, which openSUSE's follows) still gives mountfsd no
`setuid`, `setgid`, `sys_admin`, user-namespace or nsfs access, so all of the
module's mountfsd rules go beyond it: they match what upstream already grants
nsresourced, plus `sys_ptrace` inside user namespaces and namespace creation
for the idmapping.
Neither service may take descriptors for your folders upstream. nsresourced's
`sys_admin` is upstream from Fedora v45.22 and openSUSE 20261030; the module
keeps it for older policies.

Without the module the services answer `io.systemd.System` with ENXIO, and
mountfsd's debug log says `SCM_RIGHTS truncated`: SELinux kept the descriptors
from them.

Every rule was checked by removing it on an enforcing Tumbleweed VM and
running the storage tests, the render-alias access probe and the write
restriction check from [validation.md](validation.md); each removal broke one
of them. Rules found unnecessary that way were dropped: `sys_chroot`, reading
the callers' process files, and nsresourced's runtime-directory access,
which stock policy already grants. Of the types for game folders outside
your home, only `mnt_t` was checked so (a game folder under `/mnt` is
refused without it); the others follow from it, untested. A rule refused at
run time shows as an AVC denial; the one for `/proc/pressure` is expected
and harmless.

nsresourced's `sys_admin` is the subtle one. It loads its BPF restriction once
per boot, and keeps it pinned. Without `sys_admin`, libbpf cannot find the
overlay module's types: the restriction then refuses every overlay mount, and
only a reboot replaces it. A restriction whose programs are not attached
fails open: on the VM, launches still worked, but a managed namespace could
write anywhere its uid could. Only the write restriction check notices that.

It was written for and tested on Tumbleweed only. The installer builds and
loads it automatically. To build a temporary manual fixture instead, with the
SELinux development tools:

```sh
dir="$(mktemp -d)"
checkmodule -M -m -o "$dir/sandbox_game_systemd.mod" systemd-backend/sandbox_game_systemd.te
semodule_package -o "$dir/sandbox_game_systemd.pp" -m "$dir/sandbox_game_systemd.mod"
sudo semodule -i "$dir/sandbox_game_systemd.pp"
rm -r "$dir"
```

For a manual fixture, remove it with `sudo semodule -r sandbox_game_systemd`.
Use the administrator uninstaller for a packaged installation.
