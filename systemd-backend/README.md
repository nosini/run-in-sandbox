# Administrator setup for the systemd backend

`SANDBOX_SEPARATE_UID=systemd` (see "The systemd backend" in the main
[README](../README.md)) runs unprivileged, but it needs some setup once, as
root. `install.sh` does none of this yet.

1. systemd 261.4 or later, with `systemd-mountfsd` and `systemd-nsresourced`
   (openSUSE: `systemd-container`). 261.3 lets a nested namespace get round
   nsresourced's write restrictions.
2. On SELinux systems, the service policy module below. Install it before the
   two services first start.
3. Load overlayfs before nsresourced starts (newer units do this with
   `modprobe@overlay.service`). Then start the sockets:

   ```sh
   sudo modprobe overlay
   sudo systemctl start systemd-nsresourced.socket systemd-mountfsd.socket
   ```

4. For the GPU, the render-copy helper: [render-devices.md](render-devices.md).
   Without it the game draws in software.

`sandbox-uid managed-available` says whether the services answer.

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

It was written for and tested on Tumbleweed only. To install, with the SELinux
development tools:

```sh
dir="$(mktemp -d)"
checkmodule -M -m -o "$dir/sandbox_game_systemd.mod" systemd-backend/sandbox_game_systemd.te
semodule_package -o "$dir/sandbox_game_systemd.pp" -m "$dir/sandbox_game_systemd.mod"
sudo semodule -i "$dir/sandbox_game_systemd.pp"
rm -r "$dir"
```

If nsresourced started before the module was installed, its BPF restriction
may have been pinned in a state that refuses every overlay mount. Restarting
the service does not replace it; stop the services and reboot.

To remove: `sudo semodule -r sandbox_game_systemd`.
