# SELinux domain for the network's pasta

`sandbox_pasta.te` is a policy module for the `pasta` that `--net` starts:
the copy named after the game in `$XDG_RUNTIME_DIR/sandbox-game/` (see
"Network" in the main [README](../README.md)). It is optional and for SELinux
systems only. Without it, those copies run in the unconfined domain of the
user who started the game. passt's own policy confines the packaged program
(`pasta_t`, entered from files labeled `pasta_exec_t`), but a copy takes the
label of the folder it is copied into.

## Installing

From a checkout:

```sh
sudo ./install.sh --selinux
```

That builds the module with `checkmodule` and `semodule_package` and loads
it with `semodule`. The policy development files are not needed.
`sandbox-game` sees the module at the next launch, labels each game's copies
`sandbox_pasta_exec_t` and its pid file `sandbox_pasta_pid_t`, and `pasta`
runs as `sandbox_pasta_t`. A game already running keeps its unconfined
`pasta` until it ends. `sandbox-game --check` reports which applies on its
`pasta-domain` line, and so does `ps -eZ | grep -- -pasta`.

```sh
sudo ./install.sh --uninstall-selinux
```

removes it. It refuses while a game's `pasta` is still running in the domain:
removing the type underneath it would leave the process with a label the
policy no longer has. Copies labeled by a module since removed show up as
`unlabeled_t`; `sandbox-game` makes them again at the next launch.

## What the domain allows

Each rule is commented in `sandbox_pasta.te`. In short:

- **Getting in.** `unconfined_t` runs `sandbox_pasta_exec_t` into
  `sandbox_pasta_t`. The runtime directory is mounted `nosuid`, so the policy
  must also allow `process2 nosuid_transition` for it. Without that, the
  kernel keeps `pasta` in the launcher's domain and logs a denial, but the
  game's network still works. No `nnp_transition` is needed: neither
  `sandbox-game` nor `sandbox-uid` sets `no_new_privs` before `pasta` starts;
  `pasta` sets it on itself later.
- **What it inherits.** Output to the launcher's pipes, terminal or the game's
  log, written to but never opened.
- **The sandbox's network.** Opening `/proc/PID/ns/net` of the sandbox's
  process, capabilities in the user namespace it starts in (`sys_admin`,
  `net_admin`, `setuid`, `setgid`, `sys_ptrace`), `/dev/net/tun`, netlink,
  the host's routes and addresses under `/proc/net` and `/proc/sys/net`, and
  `/etc/resolv.conf`, also where it links into netconfig's, NetworkManager's
  or systemd-resolved's folder under `/run`.
- **Shutting itself in.** Mounting a `tmpfs` as an empty root in a mount
  namespace of its own.
- **The game's connections.** Outgoing TCP to any port, and UDP bound to any
  port the kernel lets an unprivileged process bind (pasta keeps the game's
  own source port). No `listen`, no `accept`: `-t none -u none` forward
  nothing in. When a connection opens, `pasta` tries to bind its destination
  address to find out whether it is one of the machine's own; the policy
  refuses that bind quietly (`dontaudit`), and `pasta` takes the refusal as
  "not local". The sandbox's routing rules refuse the machine's own
  addresses anyway.
- **Its journal messages,** through `/dev/log`.
- **Labeling.** `unconfined_t` may relabel files to and from the two file
  types, so `sandbox-game` can label the copies and the pid file.

Not allowed: reading the user's files, running programs, connecting to other
processes' sockets, ICMP. Games cannot ping out of a sandbox anyway, so
`pasta` never sees any to forward.

## How it was tested

On openSUSE Tumbleweed (selinux-policy 20261116, passt 20261002), enforcing, with both the default backend and
`SANDBOX_SEPARATE_UID=systemd`:

1. Load the module with `permissive sandbox_pasta_t;` added, launch games with
   `--net` that resolve a name, fetch an HTTPS page and send a UDP DNS query
   to a public resolver, and collect the AVCs from `/var/log/audit/audit.log`.
2. Write the rules from those, drop `permissive`, launch again: the same
   traffic works and no AVC for `sandbox_pasta_t` is logged.
3. Again with dontaudit rules disabled (`sudo semodule -DB`, then
   `sudo semodule -B` to restore them). This exposed the journal's
   `/run/systemd` path; the only remaining denial is the deliberate
   destination-bind refusal above.
4. Without the `process2` rule: `pasta` stays in `unconfined_t`, and the
   denial names only `nosuid_transition` under both backends.
5. Remove the module, launch (copies remade, `pasta` unconfined), load it
   again, launch (copies relabeled, `pasta` confined).
6. With `/etc/resolv.conf` a link (`net_conf_t`) into `/run/NetworkManager/`,
   as on many desktops: the link is followed without a denial.

`tests/test_security.py` checks the domain when the module is loaded
(`test_network_helper_runs_in_its_selinux_domain`) and that the module builds
where `checkmodule` is installed (`test_selinux_policy_module_builds`).
