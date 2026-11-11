# Security hardening implementation plan

Status: implemented. Recorded 2026-11-07 for handoff; the three items were
landed as commits `c086430` (the sandbox's own /etc), `a71182e` (saved
requirements) and `c4a04d0` (the opt-in seccomp allowlist). This document
describes the work as planned, not necessarily as shipped.

The requested scope is a minimal `/etc`, explicit requirements for protections,
and an opt-in seccomp allowlist. SELinux/AppArmor integration is excluded.
Executable-memory restrictions are deferred because Wine and JIT-based engines
make them unsuitable as a general default. No changes to existing SELinux service
policy are part of this work.

Implement the first two items before the allowlist. Preserve game
captures, saves and existing backend choices. Follow the testing workflow in
[development.md](development.md); do not treat skipped tests as validation.

## 1. Construct a minimal /etc

The launcher currently mounts host `/etc` read-only and then masks selected
identifiers. This protects integrity but exposes every otherwise readable host
configuration file, including files added later by unrelated software. Replace
that broad bind with an explicit set of required files and directories.

Implementation outline:

1. Inventory configuration needed by native games, Wine/Proton, NW.js, mkxp-z,
   the Pixel Game Maker player, .NET, graphics drivers and optional overlays.
   Review `sandbox-game`, `sandbox-game-lib` and the UID helper's mount handling
   before changing the mount plan.
2. Create a private `/etc` and expose only justified configuration. Candidates
   include loader configuration/cache, NSS configuration, fonts, CA certificates,
   timezone data and driver configuration. These are candidates to validate, not
   permission to bind all their parent directories.
3. Generate minimal identity files where appropriate instead of exposing the
   host's account lists. Keep the sandbox's stable machine ID and hostname
   behavior, including the existing compatibility treatment for older captures.
4. Preserve private hosts-file behavior, writable hosts when explicitly chosen,
   and pasta's resolver setup. Handle distribution symlinks and certificate paths
   outside `/etc`; do not accidentally restore broad host access to satisfy one
   symlink. Mount sources must remain accessible under all three UID backends.
5. Keep configuration read-only except the explicitly writable hosts file.
   Ensure the generated Landlock rules match the new mount plan, and that
   attached programs receive the same view.

Acceptance checks:

- A harmless host configuration fixture outside the allowlist is inaccessible
  from the actual sandbox; required configuration remains usable.
- Host account lists and masked identifiers are not accidentally reintroduced.
- DNS and HTTPS work with internet enabled, while the existing host/LAN
  restrictions still hold. Private/writable hosts behavior remains correct.
- Exercise representative available engines, Proton/Wine, font loading and GPU
  initialization. Include symlinked configuration layouts and both separate-UID
  backends where available. Record distribution and runtime coverage and gaps.
- There is no automatic fallback to exposing all of `/etc` on failure.

Removing host `/usr` is not part of this step: host libraries and tools currently
provide the runtime. Do not turn this into a runtime-packaging migration.

## 2. Add saved requirements for protections

Landlock and missing systemd resource controllers currently produce warnings and
allow a launch with reduced protection. Add an opt-in, saved per-game policy that
refuses launch when the requested guarantees cannot be enforced. Preserve the
existing compatibility behavior for games without such a policy.

Implementation outline:

1. Define requirements in terms of guarantees, not just feature presence:
   filesystem Landlock enforcement; signal/abstract-socket scoping when required;
   pathname Unix-socket restrictions needed for private-compositor isolation;
   effective memory, CPU and task limits; playback-only audio or no audio.
   Detect the necessary ABI features rather than assuming all Landlock-enabled
   kernels provide the same restrictions.
2. Integrate the policy with existing preference parsing, CLI, manager/settings
   and `--check`. Follow existing defaults/per-game precedence and make the
   effective requirements visible. Exact option names are an implementation
   choice; avoid introducing multiple overlapping strict-mode switches.
3. Refuse a launch if a selected display/audio/debug configuration contradicts
   its requirements. For example, a private-display requirement cannot be met by
   host X11, and enforced syscall filtering cannot be met by seccomp log mode.
   Require explicit policy changes to relax a saved requirement.
4. Check effective cgroup enforcement, not merely whether `systemd-run` accepts
   a property. Require the specific controllers needed by the chosen limits.
   Reuse existing limit/controller probes where sound.
5. Fail before executing untrusted code, clean partial launch resources, and
   report the missing guarantee and concrete remedy. A saved policy must apply
   through CLI, manager, shortcuts, installers and namespace attachment as
   appropriate; additional entry points must not bypass it.

Acceptance checks:

- Missing Landlock, insufficient ABI features, missing/delegated controllers,
  unavailable restricted audio and conflicting options produce explicit failures
  when required, while compatibility launches retain their documented behavior.
- A marker program proves untrusted code never executes on requirement failure.
- Saved requirements survive restart, preference inheritance and backend changes.
- Successful launches actually enforce the required restrictions, with negative
  access/resource probes as well as argument-generation tests.

## 3. Develop a seccomp allowlist

The current filter is a denylist. An allowlist can also reject newly introduced
or otherwise unlisted syscalls. This is additional kernel attack-surface
reduction; it is not a reason to discard the existing filter before a replacement
is validated.

Implementation outline:

1. Add the allowlist as an opt-in alternative; keep the current denylist as the
   default during development. Use a reviewed static policy with explanations,
   informed by runtime testing. Observed syscall traces alone do not establish
   that a policy covers valid fallback and error paths.
2. Preserve both native and compatibility-architecture filtering and rejection
   of unsupported architectures. Account for direct i386 socket calls versus
   `socketcall`, and preserve the documented compatibility tradeoff.
3. Preserve meaningful error codes: for example `ENOSYS` for `clone3` fallback
   and `EAFNOSUPPORT` for refused socket families. Do not silently allow an entire
   interface because a runtime probes it.
4. Keep Wine's required cross-process operations working, including `ptrace`.
   Evaluate a second filter installed after namespace entry for attached commands
   so `setns`/`chroot` allowances needed by the attachment bootstrap need not be
   available to the final workload. Audit all attachment paths before tightening
   these calls; do not assume filter stacking can relax an earlier filter.
5. No launch may fall back automatically to a weaker filter on build/load failure.
   Diagnose failures and preserve the strict-policy treatment of logging mode.

Acceptance checks:

- An unlisted syscall is refused, and denied operations cannot be recovered by
  using a compatibility syscall ABI.
- Cover startup, threads, networking, audio, graphics, Wine synchronization,
  child processes, installers and attachment, including supported 32-bit cases.
- Existing isolation tests pass under both policies. Record unavailable runtime
  coverage explicitly and keep the allowlist opt-in until justified.

References for implementation review:

- [Current Flatpak syscall filter](https://github.com/flatpak/flatpak/blob/main/common/flatpak-run.c)
- [Podman/containers-common default allowlist](https://github.com/containers/common/blob/main/pkg/seccomp/default_linux.go)
- [Landlock ABI and enforcement documentation](https://docs.kernel.org/userspace-api/landlock.html)

## Delivery and validation

Keep the three changes independently reviewable. Update the user-facing feature
documentation with actual behavior and limitations, and record detailed coverage
under `docs/`. Tests that need root, systemd services or a real sandbox need a
machine that provides them. Checks on a machine with a real GPU are separate
from checks with CPU rendering only.

The handoff should state what changed, which protections were exercised, exact
test commands/results, skipped coverage, compatibility exceptions and whether the
allowlist is still opt-in. No host configuration changes, commits or
pushes are authorized merely by this planning document.
