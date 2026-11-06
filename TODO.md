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
