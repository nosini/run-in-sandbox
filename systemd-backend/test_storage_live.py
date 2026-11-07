#!/usr/bin/env python3
"""Root controller for disposable filesystem tests on a dedicated VM.

Uses fresh loop images and a tmpfs, runs the real launcher tests as the given
ordinary user, and unmounts/removes images. Never formats an existing device.
Administrator setup must already be installed. Logs remain in --work-dir.
"""
import argparse
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys

TESTS = (
    'test_game_runs_as_a_transient_user_and_its_files_stay_ours',
    'test_switching_backends_keeps_the_capture',
    'test_attach_puts_a_file_where_the_running_game_sees_it',
    'test_list_reset_install_and_delete',
    'test_game_sees_only_its_own_ids_and_no_setup_descriptors',
    'test_repeated_launches_and_stops_release_the_managed_namespace',
    'test_concurrent_captures_keep_their_overlays_and_saves_separate',
    'test_public_game_owned_by_another_user',
)


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def foreign_game(parent):
    foreign = parent / 'foreign-game'
    foreign.mkdir(mode=0o755)
    (foreign / 'original').write_text('foreign original')
    (foreign / 'original').chmod(0o444)
    (foreign / 'closed').mkdir(mode=0o700)
    (foreign / 'closed/secret').write_text('must not be delegated')
    return foreign


def matrix_status(returncode, output):
    count = re.search(r'(?m)^Ran (\d+) tests?\b', output)
    covered = count and int(count[1]) == len(TESTS) and 'skipped=' not in output
    return returncode or (0 if covered else 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uid', type=int, required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--filesystems', nargs='+', choices=('baseline', 'tmpfs', 'ext4', 'xfs'),
                        default=['baseline', 'tmpfs', 'ext4', 'xfs'])
    parser.add_argument('--layouts', nargs='+', choices=('both', 'source-only', 'capture-only'),
                        default=['both', 'source-only', 'capture-only'])
    args = parser.parse_args()
    if os.geteuid() != 0 or args.uid <= 0:
        parser.error('run as root with the non-root test user UID')
    account = pwd.getpwuid(args.uid)
    checkout = Path(__file__).resolve().parents[1]
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    for tool in ('mount', 'umount', 'findmnt', *('mkfs.' + fs for fs in args.filesystems
                                              if fs in ('ext4', 'xfs'))):
        if not shutil.which(tool):
            parser.error(f'missing VM test dependency: {tool}')
    # unittest considers a skipped class successful. Check the real user's
    # availability first, before creating fixtures, and reject skipped/empty
    # runs below so unavailable services cannot become a false passing matrix.
    run(sys.executable, '-I', str(checkout / 'sandbox-uid'), 'managed-available',
        user=account.pw_uid, group=account.pw_gid,
        extra_groups=os.getgrouplist(account.pw_name, account.pw_gid))
    root = args.work_dir.resolve()
    root.mkdir(parents=True, exist_ok=False)
    host = root / 'host'
    host.mkdir()
    os.chown(host, account.pw_uid, account.pw_gid)
    host_foreign = foreign_game(host)
    results = []
    for fs in args.filesystems:
        mountpoint = root / fs
        mountpoint.mkdir()
        image = root / (fs + '.img')
        mounted = False
        try:
            if fs in ('ext4', 'xfs'):
                with image.open('xb') as stream:
                    stream.truncate((256 if fs == 'ext4' else 1024) * 1024 * 1024)
                run('mkfs.' + fs, '-F' if fs == 'ext4' else '-f', str(image),
                    stdout=subprocess.DEVNULL)
                run('mount', '-o', 'loop,nosuid,nodev', str(image), str(mountpoint))
                mounted = True
            elif fs == 'tmpfs':
                run('mount', '-t', 'tmpfs', '-o', 'size=256m,nosuid,nodev', 'tmpfs', str(mountpoint))
                mounted = True
            # A fresh filesystem's root starts unlabeled. Give this synthetic
            # home-filesystem fixture its normal path label before user writes.
            if Path('/sys/fs/selinux/enforce').exists():
                run('restorecon', '-F', str(mountpoint))
            os.chown(mountpoint, account.pw_uid, account.pw_gid)
            mountpoint.chmod(0o755)
            foreign = foreign_game(mountpoint)
            env = {**os.environ, 'HOME': account.pw_dir}
            command = [sys.executable, '-m', 'unittest', 'discover', '-s', str(checkout / 'tests'),
                       '-p', 'test_security.py', '-v']
            for test in TESTS:
                command += ['-k', 'SystemdBackendTests.' + test]
            actual = subprocess.check_output(['findmnt', '-rn', '-T', str(mountpoint),
                                              '-o', 'FSTYPE'], text=True).strip()
            layouts = ['both'] if fs == 'baseline' else args.layouts
            for layout in layouts:
                env['SANDBOX_TEST_TMPDIR'] = str(host if layout == 'source-only' else mountpoint)
                env['SANDBOX_TEST_GAME_TMPDIR'] = str(host if layout == 'capture-only' else mountpoint)
                env['SANDBOX_TEST_FOREIGN_GAME'] = str(host_foreign if layout == 'capture-only' else foreign)
                log_path = root / (fs + '-' + layout + '.log')
                with log_path.open('w') as log:
                    result = subprocess.run(command, cwd=checkout, env=env,
                                            user=account.pw_uid, group=account.pw_gid,
                                            extra_groups=os.getgrouplist(account.pw_name, account.pw_gid),
                                            stdout=log, stderr=subprocess.STDOUT, timeout=240)
                results.append({'fixture': fs, 'filesystem': actual, 'layout': layout,
                                'status': matrix_status(result.returncode, log_path.read_text())})
                print(json.dumps(results[-1]), flush=True)
        finally:
            # A failed unmount deliberately stops cleanup: never remove data
            # underneath a filesystem or unlink an image still in use.
            if mounted:
                run('umount', str(mountpoint))
            image.unlink(missing_ok=True)
    (root / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    if any(result['status'] != 0 for result in results):
        sys.exit('filesystem tests failed; see per-filesystem logs')


if __name__ == '__main__':
    main()
