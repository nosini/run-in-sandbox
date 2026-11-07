# The seccomp allowlist

`SANDBOX_SECCOMP_POLICY=allowlist` makes `sandbox-seccomp` refuse every
syscall a game is not known to need, on top of the default denylist. It is
opt-in; the denylist alone stays the default. The README's
"Kernel attack surface and resource limits" says what it does for a player;
this records how it was built, what has run under it and what has not.
The list itself, with a reason for each group, is in `sandbox-seccomp`.

## How it is put together

- **Denylist first, then the allowlist, as one program.** `sandbox-seccomp`
  builds the denylist exactly as before and a second libseccomp filter with
  the allowlist, then joins the two classic BPF programs: every `ALLOW`
  return in the first becomes a jump to the start of the second. Every
  denylist rule therefore holds unchanged, with its errno, on both syscall
  tables: `EPERM` for the keyring, NUMA, mount and namespace calls and for
  `clone`/`unshare` with `CLONE_NEWUSER`, `EPERM` for kernel-mode
  `userfaultfd`, `ENOSYS` for `clone3`, the new mount API and `io_uring`,
  `EAFNOSUPPORT` for socket families, and the same `socketcall` compromise
  on i386 (families filtered only where every installed 32-bit glibc makes
  sockets through the direct syscall).
- **Why not something simpler.** One libseccomp filter holding both cannot
  work: on i386 libseccomp turns a rule that lets `socket()` through for some
  families into one that lets `socketcall(SYS_SOCKET)` through for all of
  them, with the arguments dropped, and a rule without arguments makes
  libseccomp discard conditional rules for the same call. Two filters stacked
  by the kernel would work for allow/deny, but when both return an errno the
  most recently loaded one decides which, so `keyctl` would turn from `EPERM`
  into `ENOSYS`. The joined program has neither problem; the kernel checks
  it on load like any other, and it stays far below the 4096-instruction
  limit (about 900 instructions on x86_64).
- **Default action `ENOSYS`,** as in podman's default: callers read it as
  "kernel too old" and take their fallback (glibc's `clone3` → `clone` is the
  familiar case); `EPERM` tends to be taken as a real failure, and killing
  would turn a harmless probe into a crash.
- **No fallback.** An unknown `SANDBOX_SECCOMP_POLICY` value, a libseccomp
  that does not know the three Landlock calls (they would get `ENOSYS`, and
  `sandbox-landlock` would carry on as on a kernel without Landlock), a
  program that cannot be joined, or one the kernel refuses: each stops the
  launch with a message. `sandbox-game` already refuses to start when
  `sandbox-seccomp` fails.
- **Log mode.** With `SANDBOX_SECCOMP=log` the second filter's default
  becomes `LOG`; the denylist's own `LOG` returns end the program as before,
  and `clone3` still gets `ENOSYS`. See the limitation on openSUSE below.
- **Architectures.** Both filters cover the native table and its 32-bit one
  (x86_64 + i386, aarch64 + arm); any other architecture gets libseccomp's
  bad-architecture action, a kill, and so do x32 syscall numbers on x86_64
  (checked in the generated program). Names are resolved per table, so
  `mmap2`, `*_time64`, `*32` and `socketcall` apply where they exist.
- **Arguments.** Only `personality()` gains a restriction of its own: plain
  Linux, 32-bit Linux and the query (`0xffffffff`, in both its 32- and
  64-bit spellings). Anything else gets `ENOSYS`, not Flatpak's `EPERM`:
  libseccomp can only say "none of these" with overlapping rules, and which
  of overlapping rules wins is undocumented. `ioctl` is not narrowed for
  `TIOCSTI`/`TIOCLINUX` as Flatpak does, for the same reason; bwrap's
  `--new-session` already leaves the game no controlling terminal to inject
  into, and the sandbox has no virtual console.
- **Speed.** The allowlist uses libseccomp's binary-tree layout. A
  microbenchmark of a million syscalls showed no difference beyond noise
  between no filter, the denylist and the allowlist.

## The list, against the references

It started from podman's default allowlist (containers/common,
`pkg/seccomp/default_linux.go`, main as of 2026-11-07) and Flatpak's filter
(`common/flatpak-run.c`), then was checked against runtime traces. Compared
with podman's unconditional list:

- **Left out:** everything the denylist refuses (keyring, NUMA, mounts,
  `unshare`, `setns`, `pivot_root`, `syslog`, `clone3`, the new mount API);
  `setns` and `chroot` in particular, see below; Linux AIO (`io_*`), POSIX
  message queues, `fanotify_*`, `name_to_handle_at`, `pkey_*`,
  `memfd_secret`, `pidfd_getfd`, `process_mrelease`, `remap_file_pages`,
  `adjtimex`/`clock_adjtime`, `reboot`, `epoll_*_old`, and the old i386
  `signal`/`sigprocmask`. Nothing traced used them, each has a fallback or
  needs a capability, and none is part of what games or Wine do.
- **Added:** `futex_waitv` (Proton's fsync; podman refuses it),
  `userfaultfd` (user-mode only, the denylist refuses the rest; Wine uses it
  for write watches), `kcmp` (Mesa compares file descriptions with it; it
  only works where `ptrace` would, which is allowed), `modify_ldt` (Wine's
  16- and 32-bit code; Flatpak allows it for multiarch), `arch_prctl`, and the
  arm-only `set_tls`, `cacheflush`, `breakpoint`, `arm_*`.
- **Kept for Wine and attachment:** `ptrace`, `process_vm_readv`,
  `process_vm_writev`, `pidfd_open`, `pidfd_send_signal`.

## A second filter for attached programs

The plan asked whether attached programs should get a stricter second filter
so that `setns` and `chroot`, needed by the attachment bootstrap, would not
reach the workload. Every attachment path was checked:

- `sandbox-attach --exec`, `--shell`, `--put` and the Wine mode all send a
  request over `/run/sandbox-attach/socket` to the sandbox's own starter
  (`sandbox-landlock --attach`), which forks the program inside the sandbox.
  It inherits the filter bwrap gave the sandbox, the one the game started
  with; `SANDBOX_SECCOMP_POLICY` in `sandbox-attach`'s environment has no
  effect, and a test checks that.
- The client side runs outside the sandbox: `nsenter --user` into the outer
  bwrap's user namespace (subordinate-uid backend) or `sandbox-uid
  managed-enter` (systemd backend). Neither is under the game's filter, and
  nothing inside the sandbox calls `setns` or `chroot`.
- `sandbox-seccomp CMD...` is no longer used by `sandbox-attach`; it predates
  the starter. The denylist's comment about leaving `setns` and `chroot` to
  `nsenter` was out of date and now says so.

So no attachment needs `setns` or `chroot` under the filter, and the
allowlist leaves both out for the game and attached programs alike, which
gives what the second filter was meant to. A second filter could take little
else away: Cheat Engine needs `ptrace` and `process_vm_*`, the very calls a
compromised game would like. It was not implemented. (The default denylist
still allows `setns` and `chroot`; refusing them there too would be a
separate change to the default.)

## Coverage

All on one test machine, a virtual machine without a GPU: openSUSE
Tumbleweed, kernel 7.2.8, x86_64 with
`ia32_emulation` on and no x32, bubblewrap 0.12.0, libseccomp 2.6.1, passt
2026-06-12, Wine 11.19 (with 32-bit Unix libraries), the 32-bit glibc in
`/usr/lib`, Xvfb, headless Weston, xwayland-satellite. The filter was also
built and loaded (`sandbox-seccomp CMD...`) in a Debian container with
libseccomp 2.5.4, under podman's own filter.

```sh
# everything, default policy (includes tests/test_seccomp_allowlist.py)
GDK_BACKEND=x11 GSK_RENDERER=gl xvfb-run -a -s "-screen 0 1200x900x24" \
  dbus-run-session -- python3 -m unittest discover -s tests
# the sandbox test classes once more under the allowlist, plus its own tests
TEST_SATELLITE=1 TEST_SECCOMP_ALLOWLIST=1 GDK_BACKEND=x11 GSK_RENDERER=gl \
  xvfb-run -a -s "-screen 0 1200x900x24" dbus-run-session -- \
  python3 -m unittest discover -s tests -p test_seccomp_allowlist.py -v
```

`TEST_SECCOMP_ALLOWLIST=1` runs `SecurityTests`, `SeparateUidTests` and
`SystemdBackendTests` from `test_security.py` again with
`SANDBOX_SECCOMP_POLICY=allowlist` in each launch's environment. Results
(2026-11-07): the full suite ran 346 tests, OK, 36 skipped; the allowlist
run 194 tests, OK, 34 skipped (32 systemd backend not set up on the test
machine, no playback-only sound server, no cpu controller delegated).

Exercised under the allowlist:

- **Refusals:** an unlisted call (`io_setup`), `setns`, `chroot` and an odd
  `personality` get `ENOSYS`; `keyctl` and `unshare(CLONE_NEWUSER)` keep
  `EPERM`, `clone3` `ENOSYS`, refused socket families `EAFNOSUPPORT`; the
  same calls get through the default policy and through log mode.
- **Compatibility ABI:** the same calls through `int 0x80` from 64-bit code,
  and `socketcall(SYS_SOCKET, AF_ALG)`, refused with the same errnos.
- **32-bit programs:** a program linked against the system's 32-bit glibc:
  start-up, a thread, a child process, a Unix socket, and the refusals.
- **Threads, child processes, sockets, networking:** Python threads and
  subprocesses, socket pairs, `--net` with netlink interface listing, UDP and
  TCP, name lookup; the existing network tests (internet reachable, LAN and
  host refused, nothing incoming) in the allowlist rerun.
- **Wine:** the system's Wine creating a prefix and running the 64-bit and
  the WoW64 `cmd.exe` in the sandbox, as a native command. Under `strace -f`
  inside the sandbox, the only calls Wine had refused were `clone3`, as under
  the denylist.
- **Attachment:** `sandbox-attach --exec`, `--shell`, `--put`, process memory
  reads from an attached program, and the policy reaching attached programs
  whatever `sandbox-attach`'s environment says.
- **Display:** the live satellite test, real Xwayland windows on a headless
  Weston through the sandbox. Everything else display-related in the suite
  records bwrap's arguments rather than running gamescope.
- **The rest of the isolation suite:** filesystem, overlay, `/etc`,
  environment, Landlock, descriptors, `--check`, required protections,
  subordinate-uid backend.

Not covered:

- **Proton** (none installed on the test machine), DXVK,
  vkd3d-proton, NTSYNC and installers under Proton; the suite's Proton tests
  use a stand-in script.
- **GPUs and gamescope:** the test machine has only llvmpipe, and gamescope
  aborts there.
  Vulkan and GL drivers make many `ioctl`s, which are allowed whole, but
  their other calls were not observed.
- **Real sound** (the playback-only server is not set up on the test machine),
  **NW.js** (RPG Maker MV/MZ), **mkxp-z**, the **PGMMV** player, **.NET**,
  MangoHud, and actual games.
- **The systemd backend** (not set up on the test machine) and
  **aarch64/arm** (no machine).
- **Log mode on openSUSE:** its audit rules begin with `-a never,task`, and
  no `SECCOMP` record appeared, from auditd or in the kernel log, even for a
  call the filter logged. The log-mode tests check that calls get through,
  not that they are recorded. `strace` inside the sandbox stood in for it.
