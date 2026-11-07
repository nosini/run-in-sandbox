# Render-device lifecycle

This is part of the [systemd backend](README.md); its probes are in
[`probes/`](probes/) and described in
[docs/development.md](../docs/development.md). The administrator
helper provisions render-device aliases for configured host users. It has been
tested on an isolated VM with SELinux enforcing, including a real udev change
event and a protected process using an idmapped, bind-mounted alias. The
launcher uses these aliases when present;
`sudo ./install.sh --systemd-backend UID...` installs this setup persistently.
See [administrator setup](README.md) for installation and removal.

## How it works

[`systemd-render-devices`](systemd-render-devices) reads root-owned
`/etc/sandbox-game/systemd-render-users`, containing one numeric host UID per
line. It grants those users render access independently of desktop seats.
It accepts no caller-selected device, UID, destination or command arguments.

It validates each live `renderD*` against `/sys/class/drm`, the device's
`dev` and `subsystem` attributes, the reverse `/sys/dev/char` link, and the
real `/dev/dri` character device. Primary/card nodes are excluded. The helper
never changes the original device's owner, permissions or ACL.

A dedicated, device-enabled tmpfs at `/run/sandboxgame/render` holds the
aliases. The matching [mount unit](run-sandboxgame-render.mount) bounds it to
4 MiB and 16,384 inodes, with `nosuid,noexec`. A caller-owned alias is published
at `UID/renderD128`, for example. `MountDirectory(mode=root)` maps its owner to
managed root; the game's child namespace then sees its usual UID. No render
group or other desktop supplementary group is retained.

The helper refuses to run unless that directory is a distinct tmpfs with
device nodes enabled. This is necessary because the surrounding `/run` is
normally `nodev`. Aliases cannot hardlink into another filesystem or survive
a reboot. SELinux directory labels follow the trusted runtime parent; device
labels follow their real render nodes.

Each published device is a hardlink to an inode kept under root-only
`.objects/`. On removal, replacement or allowlist revocation, the helper first
changes that inode to root ownership and mode 000, then removes its published
name and private reference. Existing hardlinks and bind mounts consequently
deny **new opens**. A regrant creates a fresh inode; old references stay denied.
Already-open DRM descriptors are not revoked by chmod/chown. Physical unplug
behavior for those descriptors remains the driver's responsibility.

The [udev rule](systemd-render-devices.rules) asks the service to reload on
add/change/remove events; it never runs the helper itself, so every run has the
unit's sandbox. A reload requested while one runs is queued again, not merged
into it. All runs use a root-only lock and inspect current sysfs state after
acquiring it; they take nothing from the event. Each alias records its device's
sysfs and `/dev` inodes, so a device removed and re-added under the same path
before a run gets a fresh alias, and the old one is revoked.
The [oneshot unit](sandbox-game-render-devices.service) enables reconciliation and remains
active to track the mount's lifetime; its boot ordering precedes user sessions.
Reload applies allowlist changes without replacing unchanged aliases. On stop
(including a failed start), it disables reconciliation and revokes aliases
before systemd unmounts the tree; systemd ends a running reload first, and
later events cannot reload the inactive service. The disabled marker also stops
any other helper run from regranting access. An explicit service start enables
it again.

Root-controlled ancestors are opened without following symlinks. Publication
uses a hardlink prepared in the root-only directory and an atomic rename over
the destination; no privileged ownership or permission operation follows a
user-supplied published path. Revocation does not recurse into unexpected
user-created contents. Interrupted creation/publication is repaired on the
next reconciliation.

## Temporary setup on a dedicated test VM

Use a complete checkout, the 261.4 delegation services and the enforcing
SELinux service-policy fixture described in [README.md](README.md). Do not
overwrite an existing helper, configuration or installation. These commands
install runtime units/rules for testing; they do not enable a persistent boot
installation. Run them as the ordinary test user, invoking sudo where shown:

```sh
test ! -e /etc/sandbox-game/systemd-render-users &&
test ! -e /usr/local/libexec/sandbox-game/systemd-render-devices &&
test ! -e /run/systemd/system/sandbox-game-render-devices.service &&
test ! -e /run/systemd/system/run-sandboxgame-render.mount
```

Stop if any of those checks fails. Then:

```sh
sudo install -D -m 0755 systemd-backend/systemd-render-devices \
  /usr/local/libexec/sandbox-game/systemd-render-devices
sudo restorecon /usr/local/libexec/sandbox-game/systemd-render-devices
sudo install -d -m 0755 /etc/sandbox-game
id -u | sudo tee /etc/sandbox-game/systemd-render-users >/dev/null
sudo chmod 0644 /etc/sandbox-game/systemd-render-users
sudo install -m 0644 systemd-backend/run-sandboxgame-render.mount /run/systemd/system/
sudo install -m 0644 systemd-backend/sandbox-game-render-devices.service \
  /run/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start sandbox-game-render-devices.service
sudo install -D -m 0644 systemd-backend/systemd-render-devices.rules \
  /run/udev/rules.d/99-sandbox-game-render-probe.rules
sudo udevadm verify /run/udev/rules.d/99-sandbox-game-render-probe.rules
sudo udevadm control --reload
```

The initial reconciliation handles already-present devices. Subsequent events
use the udev rule. The helper's root executable/configuration are administrator
setup; individual game namespaces and mapped mounts remain unprivileged.

## Validation

Run the isolated lifecycle tests as root on the VM:

```sh
sudo python3 -I systemd-backend/test_render_devices.py -v
```

All **21 tests pass**, covering initial creation, unchanged/reused devices,
devices replaced at the same path, parallel reconciliation, malformed
configuration, source and destination symlinks, primary-node exclusion,
published aliases moved/hardlinked by a user, allowlist revocation and
interrupted creation/publication. They also check queued events after stop and
revocation with invalid config/absent sysfs. They create synthetic sysfs/device
fixtures under a private `/var/lib` test directory and remove them. No physical
device is removed or unbound.

The protected access check runs as the ordinary user:

```sh
mkdir -p ~/run-in-sandbox/builds/systemd-probe
python3 -I systemd-backend/probes/access.py \
  --work-dir ~/run-in-sandbox/builds/systemd-probe \
  --device-dir "/run/sandboxgame/render/$(id -u)"
```

It passes a DRM version ioctl through bwrap, seccomp and Landlock, with no
supplementary groups. Root-owned original render-node access is denied. The
socket and cross-managed-namespace checks continue to pass with this store.

For a dedicated fixture whose allowlist contains exactly the test UID:

```sh
sudo python3 -I systemd-backend/test_render_revocation_live.py run --uid "$(id -u)"
```

This starts an unprivileged managed client, which successfully opens its
bind-mounted alias and issues a DRM ioctl. The controller empties the allowlist
and reconciles through the real service. A new open through the client's
**existing bind mount** fails. Restoring the allowlist publishes a fresh inode,
while the old bind mount remains denied. The controller restores the original
allowlist in its cleanup path. This test passed with SELinux enforcing.

The mount-stop variant also passed:

```sh
sudo python3 -I systemd-backend/test_render_revocation_live.py run \
  --uid "$(id -u)" --cycle-mount
```

It stops the mount through systemd while the protected client holds its device
bind mount. The service's stop hook revokes the inode before teardown. Starting
the service recreates the runtime filesystem and fresh aliases, while the old
client reference remains denied. This covers orderly systemd stop/start;
forcibly killing the stop hook or manually bypassing systemd with umount is not
a supported administrative revocation procedure.

The real udev change hook also republished a deliberately removed alias. Mount
stop/start discarded and rebuilt the runtime tree, and a direct helper call
with the dedicated mount absent refused to create aliases on the surrounding
filesystem. A VM reboot was not performed. Boot
ordering is supplied by the units but has not been validated through reboot.
Rendering workloads and the production installer were separate integration
work.

## Remove the temporary installation

Finish the test clients first. Disable the event hook, revoke the test grants,
then remove the runtime filesystem and fixture files:

```sh
sudo rm /run/udev/rules.d/99-sandbox-game-render-probe.rules
sudo udevadm control --reload
sudo udevadm settle
sudo truncate -s 0 /etc/sandbox-game/systemd-render-users
sudo systemctl reload sandbox-game-render-devices.service
sudo systemctl stop sandbox-game-render-devices.service run-sandboxgame-render.mount
sudo rm /run/systemd/system/sandbox-game-render-devices.service \
  /run/systemd/system/run-sandboxgame-render.mount
sudo rm /usr/local/libexec/sandbox-game/systemd-render-devices \
  /etc/sandbox-game/systemd-render-users
sudo systemctl daemon-reload
sudo rmdir /run/sandboxgame/render /run/sandboxgame
```

Remove `/etc/sandbox-game` and `/usr/local/libexec/sandbox-game` only if they
are empty. The delegation-service and SELinux fixtures have their own cleanup
instructions in [README.md](README.md).
