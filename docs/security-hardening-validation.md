# Security hardening: validation record

What was tested for the work in
[security-hardening-plan.md](security-hardening-plan.md), where, and what was
not. Recorded 2026-11-07; section 4 recorded 2026-11-11.

Test machine: a virtual machine without a GPU, running openSUSE Tumbleweed
20261003, kernel 7.2.8,
systemd 261.4, bwrap 0.12, CPU rendering only (llvmpipe), Landlock ABI 6 or
newer. Its systemd user manager has only the `pids` controller delegated, so
memory and CPU limits cannot be enforced there. The full suite is run with

```sh
GDK_BACKEND=x11 GSK_RENDERER=gl xvfb-run -a -s "-screen 0 1200x900x24" \
    dbus-run-session -- python3 -m unittest discover -s tests
```

## 1. Minimal /etc

`/etc` is now a read-only tmpfs. It holds the entries listed in `ETC_KEEP` in
`sandbox-game`, generated `passwd`, `group` and `nsswitch.conf`, the existing
machine-id and hostname stand-ins, `hosts` (the host's or the private one), and
`resolv.conf` with `--net`. There is no fallback to the host's `/etc`: if the
helper fails, the game does not start.

Automated (`tests/test_security.py`):

- `test_etc_holds_only_what_games_need`: every entry is on the list; every
  host entry not on it is absent; accounts are root, nobody and the player,
  with no GECOS name; `/etc` and the non-writable `hosts` refuse writes;
  `/etc/localtime` is still the host's link; there is no `resolv.conf` without
  `--net`. Also run as `SeparateUidTests`.
- `test_attached_programs_see_the_same_etc`: what `sandbox-attach` starts
  sees the same `/etc` and `passwd`. Also run as `SeparateUidTests`.
- `test_etc_links_stay_links_or_bring_only_their_target`: the helper, run
  against a fake `/etc` with links into `/usr` and `/proc`, into `/etc`, into
  an outside CA location and elsewhere, a symlinked parent folder, a dangling
  link and an unlisted file.
- The existing hosts, network (DNS and verified HTTPS), machine-identifier and
  Landlock tests, unchanged.

By hand on the test machine:

- A world-readable fixture, `/etc/sandbox-hardening-fixture`, created with
  sudo, was absent inside the sandbox. The fixture was removed afterwards.
- With `--net`, `resolv.conf` pointed at pasta's forwarder, `getent hosts`
  resolved, and `curl` and Python fetched `https://example.com` (200).
  `--add-host` names resolved from the private hosts file.
- fontconfig matched Liberation Sans, the time zone was CET through the
  `/etc/localtime` link, `vulkaninfo` found llvmpipe, and
  `wine cmd /c echo` (wine 11.19) ran in a fresh prefix.

Fixed along the way: Landlock gave `--rw` to a tmpfs that bwrap later
remounted read-only (until now only `/etc/ssh`). Such a tmpfs now gets `--ro`.

Not covered:

- Proton, NW.js, mkxp-z, the Pixel Game Maker player and .NET games: none are
  installed on the test machine. Java is installed but was not exercised.
- GPU drivers on real hardware: `/etc/vulkan`, `/etc/glvnd` and `/etc/nvidia`
  do not exist on the test machine. This needs a check on a machine with a GPU.
- Distributions other than openSUSE. The Debian layout (`alternatives`,
  `java-*`) and Fedora/Arch certificate links were checked only through the
  fake-`/etc` helper test.
- The systemd UID backend. Its services are installed on the test machine
  but disabled. When they were started for this run, `systemd-mountfsd`
  refused to mount the test folders (`ENXIO`). Unchanged `HEAD` fails the same
  way, so the cause is that machine's setup, not these changes. The services
  were stopped again. The default and subordinate-UID backends
  were covered.

## 2. Required protections

`require=` in the preferences, per game over the defaults, and `--require`
on the command line, which only adds to it. Requirements are checked before
anything is mounted and again where each protection is applied
(`sandbox-landlock --require`, the limits probe, the sound fallback).
`sandbox-game` reads them itself, so every entry point is covered. The limits
probe now checks that each limit is in force in the trial scope, including the
task limit, not only that its file exists.

Automated:

- `test_required_protections_refuse_before_the_game_runs`: a marker command
  never runs for: a missing playback-only sound server (CLI, game file,
  defaults); `seccomp` and `all` under `SANDBOX_SECCOMP=log`; `private-display`
  with `--host-x11` and with plain `--wayland`; unknown names on the CLI and in
  a file. No mounts are left behind.
- `test_a_game_relaxes_the_defaults_only_in_its_own_preferences`: an empty
  `require=` in the game's file overrides the defaults; `--require` adds but
  never removes; a saved requirement holds when the CLI asks for something
  else.
- `test_required_limits_and_landlock_follow_what_the_machine_can_do`:
  `limits`, `landlock` and `scoped` are refused exactly when `--check` and the
  Landlock ABI say they cannot be had. On the test machine `limits` is really refused,
  for lack of the memory controller. With `scoped` granted, the game cannot
  signal bwrap's pid 1.
- `test_check_shows_saved_requirements`: `--check` lists the defaults'
  requirements and a game's own, with what cannot be met here.
- `SeparateUidTests.test_requirements_hold_under_a_uid_of_its_own`: `audio`
  is met by having no sound; `seccomp` is still refused in log mode; switching
  back to running as you keeps the saved requirement.
- `tests/test_dialog.py` and `tests/test_manager.py`: the preferences window
  (six switches; canonical order; `all`; a display that contradicts
  `private-display`) and `prefs_save` (game, defaults, empty override,
  rejected names).

Not covered:

- A kernel without Landlock, or with an ABI below 6: these paths are tested
  only by comparing against what the kernel reports.
- `private-display` on a kernel whose Landlock cannot restrict Unix-socket
  connections.
- A host with the memory and CPU controllers delegated.
- The systemd backend, as above.

## 3. Seccomp allowlist

Opt-in with `SANDBOX_SECCOMP_POLICY=allowlist`; the denylist stays the
default. The policy, its design, and what was and was not run under it are in
[seccomp-allowlist.md](seccomp-allowlist.md). In short: the denylist and the
allowlist are joined into one BPF program, so every denylist rule keeps its
errno on both syscall tables. Unlisted calls get `ENOSYS`. There is no
fallback to a weaker filter. No second filter for attached programs was
needed, since they are started from inside the sandbox and inherit the game's.
`tests/test_seccomp_allowlist.py` covers the policy itself.
`TEST_SECCOMP_ALLOWLIST=1` re-runs `SecurityTests`, `SeparateUidTests` and
`SystemdBackendTests` under it: 194 tests, 34 skipped. Proton, GPUs, real
sound, the other engines and aarch64 are not covered.

## 4. Wayland security context

Where the desktop's compositor offers Wayland security contexts
(`security-context-v1`), `sandbox-game` asks it for a socket of the sandbox's
own, mounts it over the desktop's for the game, gamescope and satellite alike,
and closes it when the launch ends. Every connection the compositor accepts
through it is marked as sandboxed, and it names the sandbox's windows
`sandbox-game-NAME` whatever they call themselves. A compositor without
security contexts changes nothing; one that offers the manager but refuses to
make a context prints a warning and keeps the desktop's socket.
`sandbox-game --check` says which case this desktop is.

Automated (`tests/test_security.py`, against a faked compositor):

- `test_security_context_gives_the_sandbox_a_socket_of_its_own`: with and
  without `--wayland`, the socket bound into the sandbox is a listener of its
  own, in a `sandbox-game-wayland.` folder of the runtime directory, and not
  the desktop's socket; the security context carries the engine's ID and an
  app ID of `sandbox-game-NAME`; the context's socket listened at the path the
  sandbox got; the folder is gone after the launch; the compositor's end of
  the context reads end-of-file once the launch is over.
- `test_refused_security_context_falls_back_with_a_warning`: a compositor
  that refuses keeps the desktop's socket, warns, and leaves nothing of the
  context in the runtime directory.
- `test_check_reports_the_security_context`: the `--check` line for a
  compositor that gives one and for one that has none.
- `tests/test_manager.py`:
  `test_hidden_taskbar_entry_matches_by_window_class_only_under_proton`:
  every game gets a hidden taskbar entry, but only a Proton game's carries
  `StartupWMClass=steam_app_NAME`; native games rely on KDE naming their
  windows after the entry, so their entries never claim a window class.

By hand on the test machine:

- Full suite with the default policy: 395 tests, OK, 37 skipped — the same
  backend-dependent skips as in the runs above. The run left nothing in the
  VM's home.
- The live checks were rerun against the final helper on the VM's KDE Plasma
  desktop, and passed: the game runs on the compositor's socket for its
  security context, and `--check` reports it.

Not covered:

- Mutter, and any other compositor without security contexts, only through the
  fallback paths the faked-compositor tests exercise; no live run.
- A compositor that offers the manager but refuses a context, live; the
  faked-compositor test stands in for it.
- How compositors other than KWin treat a sandboxed connection, and real GPU
  hardware: as above, not on the test machine.

## Results

- Steps 1–2, full suite on the test machine: 338 tests, 1 failure, 36 skipped. The
  failure was the bash completion missing `--require`; it was fixed and that
  test rerun on its own, and passed. The skips are the 30 systemd-backend
  tests and tests that need hardware or software the test machine lacks.
- Steps 1–3, full suite on the test machine with the default policy: 346 tests, OK,
  36 skipped.
- Steps 1–4, full suite on the test machine with the default policy: 395 tests,
  OK, 37 skipped. The live checks on the VM's KDE Plasma desktop were rerun
  against the final helper and passed; the run left nothing in its home.
