#!/bin/bash
# desktop-boot-check.sh before|after: whether the systemd backend's
# administrator setup comes up by itself, in order, after a reboot.
#
#   desktop-boot-check.sh before   installs (or updates) the setup with sudo
#                                  and notes this boot; then reboot
#   desktop-boot-check.sh after    in the new boot's desktop session: checks
#                                  what came up and how, launches a throwaway
#                                  game under the backend, and offers to
#                                  remove the setup again
#
# Each requirement gets a PASS or FAIL line in summary.txt, in
# .gpu-check/boot-DATE in this checkout (git ignores it), beside the units'
# journal of that boot. Nothing of your per-user installation, settings or
# games is used.
set -u
here="$(cd "$(dirname "$(realpath "$0")")" && pwd)"
checkout="$(dirname "$here")"
state="${XDG_STATE_HOME:-$HOME/.local/state}/sandbox-boot-check"
render_users=/etc/sandbox-game/systemd-render-users

die() { echo "desktop-boot-check: $*" >&2; exit 1; }
[ "$(id -u)" != 0 ] || die "run it as yourself, not as root; it asks for sudo itself"

case "${1:-}" in
before)
    results="$checkout/.gpu-check/boot-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$results" "$(dirname "$state")" || die "cannot make $results"
    echo "Installing (or updating) the administrator setup with sudo..."
    if ! (cd "$checkout" && sudo ./install.sh --systemd-backend "$(id -u)") > "$results/setup.txt" 2>&1; then
        tail -5 "$results/setup.txt" >&2
        die "the setup failed; see $results/setup.txt"
    fi
    "$checkout/sandbox-uid" managed-available || die "the backend is not available even before the reboot"
    {
        echo "boot_id=$(cat /proc/sys/kernel/random/boot_id)"
        echo "results=$results"
    } > "$state"
    for unit in sandbox-game-render-devices.service systemd-nsresourced.socket systemd-mountfsd.socket; do
        echo "$unit: $(systemctl is-enabled "$unit" 2>&1)"
    done > "$results/before.txt"
    cat "$results/before.txt"
    echo
    echo "Ready. Reboot, log in, and run: $0 after"
    exit 0 ;;
after) ;;
*) die "say before (then reboot) or after" ;;
esac

[ -f "$state" ] || die "run '$0 before' first, then reboot"
before_id="$(sed -n 's/^boot_id=//p' "$state")"
results="$(sed -n 's/^results=//p' "$state")"
[ -d "$results" ] || die "the results folder $results is gone; start again with before"
summary="$results/summary.txt"
: > "$summary"
note() { printf '%s\n' "$*" | tee -a "$summary"; }
check() { # TEXT CONDITION...: PASS or FAIL, by the condition's status
    local text="$1"; shift
    if "$@" >/dev/null 2>&1; then note "PASS $text"; else note "FAIL $text"; fi
}
mono() { systemctl show "$1" -p "${2:-ActiveEnterTimestampMonotonic}" --value; }
earlier() { [ "$1" -gt 0 ] && [ "$2" -gt 0 ] && [ "$1" -le "$2" ]; }
allows_devices() { [ -n "$1" ] && ! grep -qw nodev <<<"$1"; }
# When UNIT first logged a line matching PATTERN this boot, in seconds since
# boot: the journal keeps what systemd forgets of a unit gone idle.
first() { # UNIT PATTERN
    sudo journalctl -b -o short-monotonic --no-pager -u "$1" 2>/dev/null \
        | grep -m1 -E "$2" | sed -E 's/^\[ *([0-9.]+)\].*/\1/'
}
before_in_boot() { # SECONDS SECONDS
    [ -n "$1" ] && [ -n "$2" ] && awk -v a="$1" -v b="$2" 'BEGIN { exit !(a <= b) }'
}

note "boot: $(date -d "@$(( $(date +%s) - $(cut -d. -f1 /proc/uptime) ))" '+%F %T'), $(grep PRETTY_NAME /etc/os-release | cut -d= -f2), $(systemctl --version | head -1)"
check "a new boot since 'before'" test "$before_id" != "$(cat /proc/sys/kernel/random/boot_id)"

for unit in systemd-nsresourced.socket systemd-mountfsd.socket \
            run-sandboxgame-render.mount sandbox-game-render-devices.service; do
    check "$unit is active ($(systemctl is-enabled "$unit" 2>&1), $(systemctl is-active "$unit" 2>&1))" \
        systemctl is-active --quiet "$unit"
done
mount_up="$(mono run-sandboxgame-render.mount)"
render_up="$(mono sandbox-game-render-devices.service)"
sessions_up="$(mono systemd-user-sessions.service)"
check "the render helper started after its mount" earlier "$mount_up" "$render_up"
check "the render helper started before user sessions" earlier "$render_up" "$sessions_up"

fs="$(findmnt -n -o FSTYPE,OPTIONS /run/sandboxgame/render 2>/dev/null)"
check "the render store is a tmpfs of its own ($fs)" test "${fs%% *}" = tmpfs
check "that tmpfs allows device nodes" allows_devices "$fs"
alias="$(ls -ln "/run/sandboxgame/render/$(id -u)"/renderD* 2>&1)"
note "render copy: $alias"
check "your render node copy is yours alone" eval \
    "stat -c '%u %g %a' /run/sandboxgame/render/$(id -u)/renderD* | grep -qx '$(id -u) $(id -u) 600'"
check "it is the GPU's render node" eval \
    "[ \"\$(stat -c '%t:%T' /run/sandboxgame/render/$(id -u)/renderD* | sort)\" = \"\$(stat -c '%t:%T' /dev/dri/renderD* | sort)\" ]"
copies="$(sudo ls /run/sandboxgame/render 2>/dev/null | grep -E '^[0-9]+$' | tr '\n' ' ')"
allowed="$(sudo cat "$render_users" 2>/dev/null | tr '\n' ' ')"
note "render copies for: ${copies:-none }(allowed: $allowed)"

# A game under the backend: the first use starts systemd-nsresourced, by
# its socket, which has to find overlayfs loaded.
scratch="$(mktemp -d "${XDG_CACHE_HOME:-$HOME/.cache}/sandbox-boot-check.XXXXXX")" || die "no scratch folder"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/home" "$scratch/games/boot-check"
echo original > "$scratch/games/boot-check/file"
env HOME="$scratch/home" XDG_CONFIG_HOME="$scratch/home/.config" \
    XDG_DATA_HOME="$scratch/home/.local/share" SANDBOX_TOOLS_DIR="$scratch/tools" \
    SANDBOX_SEPARATE_UID=systemd timeout 120 "$checkout/sandbox-game" --headless \
    "$scratch/games/boot-check" /bin/sh -c \
    'echo changed >> /game/file && echo saved > "$HOME/save" && cat /game/file' \
    < /dev/null > "$results/launch.log" 2>&1
status=$?
check "a game launches under the backend (exit $status)" test "$status" = 0
check "it changed its game file and saved" eval \
    "grep -qx changed '$results/launch.log' && [ -f '$scratch/home/game-sandboxes/boot-check/home/save' ]"
check "its capture stays yours on disk" eval \
    "[ -z \"\$(find '$scratch/home/game-sandboxes/boot-check' \\( ! -user $(id -u) -o ! -group $(id -u) \\) -print -quit)\" ]"

check "overlayfs is loaded" test -d /sys/module/overlay
check "systemd-nsresourced waits for overlayfs" eval \
    "systemctl show systemd-nsresourced.service -p After -p Requires --value | grep -q modprobe@overlay.service"
overlay_at="$(first modprobe@overlay.service 'Finished|Deactivated')"
nsresourced_at="$(first systemd-nsresourced.service 'Starting|Started')"
check "this boot, overlayfs was loaded (${overlay_at:-?}s) before systemd-nsresourced first started (${nsresourced_at:-?}s)" \
    before_in_boot "$overlay_at" "$nsresourced_at"

if [ -e /sys/fs/selinux/enforce ]; then
    check "SELinux is enforcing" grep -qx 1 /sys/fs/selinux/enforce
    check "the service policy is loaded" eval "sudo semodule -l | grep -qw sandbox_game_systemd"
    # Only the kernel's and the audit's messages: sudo logs this very
    # command line, pattern and all.
    { sudo journalctl -b --no-pager _TRANSPORT=kernel _TRANSPORT=audit 2>/dev/null
      sudo ausearch --input-logs -m AVC,USER_AVC -ts boot < /dev/null 2>/dev/null; } \
        | grep -E 'avc:.*denied' | grep -E 'mountfsd|nsresourced' > "$results/denials.txt"
    # Stock policy keeps systemd-mountfsd out of /proc/pressure, where systemd
    # daemons watch for memory pressure; it does without. Known, harmless.
    psi="$(grep -c proc_psi_t "$results/denials.txt")"
    denials="$(grep -vc proc_psi_t "$results/denials.txt")"
    check "no SELinux denials for the delegation services this boot ($denials; and $psi of the known memory-pressure one)" \
        test "$denials" = 0
else
    note "SELinux: not in use"
fi

# shellcheck disable=SC2024  # the journal goes to a file of yours
sudo journalctl -b --no-pager -u sandbox-game-render-devices.service -u run-sandboxgame-render.mount \
    -u modprobe@overlay.service -u systemd-nsresourced.service -u systemd-mountfsd.service \
    -u systemd-nsresourced.socket -u systemd-mountfsd.socket > "$results/journal.txt" 2>&1
# Failed early unit lookups need not appear in that unit's own journal.
sudo journalctl -b --no-pager _PID=1 \
    | grep -E 'sandbox-game-render|run-sandboxgame|usr-local.mount|/usr/local|ordering cycle|deleted to break' \
    > "$results/boot-ordering.txt"
systemctl show sandbox-game-render-devices.service run-sandboxgame-render.mount \
    systemd-user-sessions.service modprobe@overlay.service systemd-nsresourced.service multi-user.target \
    -p Id -p ActiveEnterTimestampMonotonic -p ExecMainExitTimestampMonotonic \
    -p After -p Requires -p Wants -p LoadState -p FragmentPath > "$results/units.txt" 2>&1

note ""
note "$(grep -c '^PASS' "$summary") passed, $(grep -c '^FAIL' "$summary") failed"
note "Logs: $results"
echo
read -r -p "Remove the administrator setup again? [y/N] " answer
if [[ "$answer" =~ ^[Yy] ]]; then
    if (cd "$checkout" && sudo ./install.sh --uninstall-systemd-backend) > "$results/removal.txt" 2>&1; then
        sudo rm -f "$render_users"
        sudo rmdir /etc/sandbox-game /usr/local/libexec/sandbox-game 2>/dev/null
        rm -f "${XDG_STATE_HOME:-$HOME/.local/state}/sandbox-gpu-check-installed"
        note "setup: removed"
    else
        note "setup: REMOVAL FAILED, see removal.txt"
    fi
else
    note "setup: kept"
fi
rm -f "$state"
echo "Done. Tell the agent the results are in $results"
