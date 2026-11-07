# Administrator setup for the systemd backend

`SANDBOX_SEPARATE_UID=systemd` (see "The systemd backend" in the main
[README](../README.md)) runs unprivileged, but needs administrator setup once.
The backend remains experimental; accelerated rendering and physical GPU
hotplug still need validation. It is never selected automatically.
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
`/usr/local/lib/systemd/system`, `/etc/udev/rules.d` and `/etc/systemd/system`.
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
refuses such an account, and the launcher checks before changing anything:
first your primary group, then the game's folder, Proton, the capture and
the desktop's sockets. It names what to change.

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
The services take folders of your home and your runtime directory by
descriptor, and handle namespaces; their Varlink checks that the caller owns
what it hands over stay in place. It grants no access to file data in your
home. The rule that reads process-type files is for namespace proc files.

Without it the services answer `io.systemd.System` with ENXIO, and mountfsd's
debug log says `SCM_RIGHTS truncated`: SELinux kept the descriptors from them.

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
