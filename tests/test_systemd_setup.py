"""Availability gates and administrator setup preflight, without root/services."""
import importlib.machinery
import importlib.util
import hashlib
from contextlib import ExitStack
import errno
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import stat
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
    sys.modules[name] = module
    saved, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = saved
    return module


uid = load('setup_test_uid', ROOT / 'sandbox-uid')
setup = load('setup_test_installer', ROOT / 'systemd-backend/install-systemd.py')


def shell_function(path, name):
    text = Path(path).read_text()
    match = re.search(rf'^{re.escape(name)}\(\) \{{\n.*?^\}}', text,
                      re.MULTILINE | re.DOTALL)
    if match is None:
        raise AssertionError(f'{name} is not defined in {path}')
    return match.group(0)


class AvailabilityTests(unittest.TestCase):
    def test_direct_launch_rejects_different_gid_before_any_setup(self):
        with mock.patch.object(uid.os, 'getuid', return_value=1000), \
             mock.patch.object(uid.os, 'getgid', return_value=12345), \
             mock.patch.object(uid, 'managed_namespace') as allocate, \
             mock.patch.object(uid.os, 'makedirs') as mkdir, \
             mock.patch.object(uid, 'fail', side_effect=RuntimeError):
            with self.assertRaises(RuntimeError):
                uid.managed_launch('/unused', ['bwrap'])
            allocate.assert_not_called()
            mkdir.assert_not_called()

    def test_different_primary_gid_is_refused_before_contacting_services(self):
        with mock.patch.object(uid.os, 'getuid', return_value=1000), \
             mock.patch.object(uid.os, 'getgid', return_value=12345), \
             mock.patch.object(uid, 'varlink') as varlink:
            self.assertIn('requires matching primary UID and GID', uid.managed_available())
            varlink.assert_not_called()

    def test_concurrent_launch_names_survive_uid_prefixing_and_truncation(self):
        names = []
        class Allocating(Exception):
            pass
        def allocated(name):
            names.append(name)
            raise Allocating()
        with mock.patch.object(uid, 'canonical', return_value=['bwrap']), \
             mock.patch.object(uid, 'overlays', return_value=(['bwrap'], [])), \
             mock.patch.object(uid, 'delegations', return_value=[]), \
             mock.patch.object(uid, 'managed_namespace', side_effect=allocated):
            for pid in (123400, 123499):
                with mock.patch.object(uid.os, 'getpid', return_value=pid), self.assertRaises(Allocating):
                    uid.managed_launch('/unused', ['bwrap'])
        for caller in (1000, 4294967294):
            mangled = [f'{caller}-{name}'[:22] for name in names]
            self.assertNotEqual(*mangled)

    def availability(self, first='261.4 (261.4)', second='261.4 (261.4)', mount=True):
        def reply(path, method, params, sock=None):
            if method.endswith('.GetInfo'):
                return {'version': first if path == uid.NSRESOURCE else second}, []
            return {'description': 'MountDirectory' if mount else 'old interface'}, []
        with mock.patch.object(uid, 'varlink', side_effect=reply), \
             mock.patch.object(uid, 'varlink_connect', return_value=mock.MagicMock()):
            return uid.managed_available()

    def test_supported_matching_workers(self):
        self.assertIsNone(self.availability())
        self.assertIsNone(self.availability('262 (262)', '262 (262)'))

    def test_unsafe_or_unknown_versions_are_refused(self):
        for version in ('261.3', '261', '258.9', '', '262~rc1', 'development'):
            with self.subTest(version=version):
                self.assertIn('unsupported systemd version', self.availability(version))

    def test_mixed_workers_are_refused(self):
        self.assertIn('different versions', self.availability(second='262 (262)'))

    def test_missing_directory_api_is_refused(self):
        self.assertIn('lacks MountDirectory', self.availability(mount=False))

    def test_service_error_is_reported(self):
        with mock.patch.object(uid, 'varlink', side_effect=uid.VarlinkError('permission denied')), \
             mock.patch.object(uid, 'varlink_connect', return_value=mock.MagicMock()):
            self.assertIn('permission denied', uid.managed_available())

    def test_each_service_answers_both_questions_on_one_connection(self):
        class FakeSocket:
            made = []

            def __init__(self, *args):
                self.calls = 0
                FakeSocket.made.append(self)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def settimeout(self, timeout):
                pass

            def connect(self, path):
                self.path = path
                info = json.dumps({'parameters': {'version': '261.4 (261.4)'}}).encode() + b'\0'
                desc = json.dumps({'parameters': {'description': 'MountDirectory'}}).encode() + b'\0'
                self.replies = [info, desc]

            def sendmsg(self, data, ancillary):
                self.request = data[0]
                return len(data[0])

            def sendall(self, data):
                self.request += data
                self.calls += 1

            def recvmsg(self, size, space, flags):
                return self.replies.pop(0), [], 0, None

            def close(self):
                pass
        with mock.patch.object(uid.socket, 'socket', FakeSocket):
            self.assertIsNone(uid.managed_available())
        self.assertEqual(len(FakeSocket.made), 2)
        self.assertEqual([s.path for s in FakeSocket.made], [uid.NSRESOURCE, uid.MOUNTFS])
        self.assertEqual([s.calls for s in FakeSocket.made], [2, 2])


class IndexTests(unittest.TestCase):
    def test_an_index_allocated_while_waiting_is_reused(self):
        with tempfile.TemporaryDirectory() as tmp:
            cap = Path(tmp) / 'cap'
            cap.mkdir()
            path = cap / 'uid'

            def lock(fd, operation):
                # The caller that held the lock first wrote its choice.
                path.write_text('7\n')

            with mock.patch.object(uid.fcntl, 'flock', side_effect=lock), \
                 mock.patch.object(uid.os, 'listdir', side_effect=AssertionError):
                self.assertEqual(uid.index_of(str(cap)), 7)
            self.assertEqual(path.read_text(), '7\n')


class ManagedLaunchTests(unittest.TestCase):
    def test_overlay_mounts_are_delegated_when_their_capture_is_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            cap = Path(tmp)
            seen = []

            def delegations(argv, specs, extra, cap=None):
                seen.append(list(extra))
                raise RuntimeError
            with mock.patch.object(uid, 'managed_identity_error', return_value=None), \
                 mock.patch.object(uid, 'group_error', return_value=None), \
                 mock.patch.object(uid, 'canonical', side_effect=lambda argv: argv), \
                 mock.patch.object(uid, 'overlays',
                                   return_value=(['bwrap'], [('/m', [], None, None)])), \
                 mock.patch.object(uid, 'delegations', side_effect=delegations):
                with self.assertRaises(RuntimeError):
                    uid.managed_launch(str(cap), ['bwrap'])
            self.assertIn((str(cap / '.mounts'), True), seen[0])

    def test_a_failed_launch_removes_the_namespace_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            cap = Path(tmp)
            ns = os.open(os.devnull, os.O_RDONLY)
            self.addCleanup(os.close, ns)
            with mock.patch.object(uid, 'managed_identity_error', return_value=None), \
                 mock.patch.object(uid, 'group_error', return_value=None), \
                 mock.patch.object(uid, 'canonical', side_effect=lambda argv: argv), \
                 mock.patch.object(uid, 'overlays', return_value=(['bwrap'], [])), \
                 mock.patch.object(uid, 'delegations', return_value=[('/x', False)]), \
                 mock.patch.object(uid, 'managed_namespace', return_value=ns), \
                 mock.patch.object(uid, 'delegate', side_effect=SystemExit(1)):
                with self.assertRaises(SystemExit):
                    uid.managed_launch(str(cap), ['bwrap'])
            self.assertFalse((cap / '.managed-userns').exists())
            self.assertFalse((cap / '.managed-userns.tmp').exists())

    def test_the_binary_to_exec_is_delegated_from_an_unreachable_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            cap = Path(tmp)
            bindir = cap / 'home/.local/bin'
            bindir.mkdir(parents=True)
            bwrap = bindir / 'bwrap'
            bwrap.write_text('')
            seen = []

            def delegations(argv, specs, extra, cap=None):
                seen.append(list(extra))
                raise RuntimeError

            with mock.patch.object(uid, 'managed_identity_error', return_value=None), \
                 mock.patch.object(uid, 'group_error', return_value=None), \
                 mock.patch.object(uid, 'canonical', side_effect=lambda argv: argv), \
                 mock.patch.object(uid, 'overlays', return_value=([str(bwrap)], [])), \
                 mock.patch.object(uid, 'delegations', side_effect=delegations):
                with self.assertRaises(RuntimeError):
                    uid.managed_launch(str(cap), [str(bwrap)])
            self.assertIn((os.path.realpath(bwrap), False), seen[0])

    def test_the_launch_executes_the_resolved_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            cap = Path(tmp)
            link = cap / 'bwrap-link'
            link.symlink_to('/bin/true')
            ns = os.open(os.devnull, os.O_RDONLY)

            class Warm:
                def __init__(self, slow):
                    pass

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return False

                def hold(self):
                    pass

            patches = [
                mock.patch.object(uid, 'managed_identity_error', return_value=None),
                mock.patch.object(uid, 'group_error', return_value=None),
                mock.patch.object(uid, 'canonical', side_effect=lambda argv: argv),
                mock.patch.object(uid, 'overlays', return_value=([str(link)], [])),
                mock.patch.object(uid, 'delegations', return_value=[]),
                mock.patch.object(uid, 'managed_namespace', return_value=ns),
                mock.patch.object(uid, 'nsresourced_lock', return_value=None),
                mock.patch.object(uid, 'WarmWorker', Warm),
                mock.patch.object(uid.libc, 'setns', return_value=0),
                mock.patch.object(uid.libc, 'prctl', return_value=0),
                mock.patch.object(uid, 'unshare'),
                mock.patch.object(uid, 'mount'),
                mock.patch.object(uid, 'place'),
                mock.patch.object(uid, 'overlay_points', return_value=[]),
                mock.patch.object(uid, 'relay_output'),
                mock.patch.object(uid.os, 'setgroups'),
                mock.patch.object(uid.os, 'setresgid'),
                mock.patch.object(uid.os, 'setresuid'),
                mock.patch.object(uid.os, 'chdir'),
                mock.patch.object(uid.os, 'replace'),
                mock.patch('builtins.open', mock.mock_open()),
            ]
            with ExitStack() as stack:
                for patch in patches:
                    stack.enter_context(patch)
                execv = stack.enter_context(mock.patch.object(uid.os, 'execv'))
                uid.managed_launch(str(cap), [str(link)])
            execv.assert_called_once_with(os.path.realpath(link), [str(link)])


class DelegationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)

    def test_a_try_bind_others_cannot_reach_is_skipped(self):
        private = self.base / 'private'
        private.mkdir(mode=0o700)
        source = private / 'file'
        source.write_text('x')
        argv = ['bwrap', '--ro-bind-try', str(source), '/x']
        stderr = mock.MagicMock()
        with mock.patch.object(uid.os, 'getuid', return_value=os.getuid() + 1), \
             mock.patch.object(uid.sys, 'stderr', stderr):
            self.assertEqual(uid.delegations(argv, []), [])
        self.assertEqual(argv, ['bwrap'])
        text = ''.join(c.args[0] for c in stderr.write.call_args_list)
        self.assertIn(f'sandbox-uid: skipping {source}', text)

    def test_a_missing_try_bind_is_left_for_bwrap_to_skip(self):
        argv = ['bwrap', '--ro-bind-try', str(self.base / 'missing'), '/x']
        stderr = mock.MagicMock()
        with mock.patch.object(uid.sys, 'stderr', stderr):
            self.assertEqual(uid.delegations(argv, []), [])
        self.assertEqual(len(argv), 4)
        stderr.write.assert_not_called()

    def test_a_dangling_try_bind_link_is_dropped_by_delegations(self):
        link = self.base / 'dangling'
        link.symlink_to('missing')
        for option in ('--ro-bind-try', '--bind-try'):
            with self.subTest(option=option):
                argv = ['bwrap', option, str(link), '/x']
                stderr = mock.MagicMock()
                with mock.patch.object(uid.sys, 'stderr', stderr):
                    self.assertEqual(uid.delegations(argv, []), [])
                self.assertEqual(argv, ['bwrap'])
                stderr.write.assert_not_called()

    def test_a_dangling_try_bind_link_does_not_crash_walks(self):
        link = self.base / 'dangling'
        link.symlink_to('missing')
        argv = ['bwrap', '--ro-bind-try', str(link), '/x']
        # sources() keeps dangling links so stage() creates their parent dirs.
        self.assertEqual(uid.sources(argv), [(str(link), False)])
        self.assertEqual(uid.canonical(argv), argv)
        self.assertEqual(uid.group_mismatches(argv, []), [])

    def test_a_binary_under_an_unreachable_home_is_delegated(self):
        home = self.base / 'home'
        bindir = home / '.local/bin'
        bindir.mkdir(parents=True)
        bwrap = bindir / 'bwrap'
        bwrap.write_text('')
        bwrap.chmod(0o755)
        home.chmod(0o700)
        with mock.patch.object(uid, 'mount_points', return_value=set()):
            self.assertEqual(uid.delegations(['bwrap'], [], [(str(bwrap), False)]),
                             [(str(bindir), False)])

    def test_a_binary_in_a_system_folder_adds_no_delegation(self):
        bwrap = shutil.which('bwrap')
        if not bwrap:
            self.skipTest('bwrap is not installed')
        with mock.patch.object(uid, 'mount_points', return_value=set()):
            self.assertEqual(uid.delegations(['bwrap'], [], [(bwrap, False)]), [])

    def test_a_required_bind_others_cannot_reach_still_fails(self):
        private = self.base / 'private'
        private.mkdir(mode=0o700)
        source = private / 'file'
        source.write_text('x')
        argv = ['bwrap', '--ro-bind', str(source), '/x']
        with mock.patch.object(uid.os, 'getuid', return_value=os.getuid() + 1), \
             mock.patch.object(uid, 'fail', side_effect=RuntimeError):
            with self.assertRaises(RuntimeError):
                uid.delegations(argv, [])

    def test_a_file_source_that_is_a_mount_point_is_not_covered(self):
        home = self.base / 'home'
        home.mkdir()
        save = home / 'save'
        save.write_text('s')
        argv = ['bwrap', '--bind', str(self.base), '/base',
                '--ro-bind', str(save), '/save']
        with mock.patch.object(uid, 'mount_points', return_value={str(save)}):
            self.assertEqual(uid.delegations(argv, []),
                             [(str(self.base), True), (str(home), False)])

    def test_the_overlay_mounts_folder_is_covered_by_its_capture(self):
        mounts = self.base / '.mounts'
        mounts.mkdir()
        argv = ['bwrap', '--bind', str(self.base), '/base']
        with mock.patch.object(uid, 'mount_points', return_value=set()):
            self.assertEqual(uid.delegations(argv, [], [(str(mounts), True)]),
                             [(str(self.base), True)])

    def test_overlay_layers_delegate_their_folder_not_the_capture(self):
        cap = self.base / 'cap'
        (cap / 'overlay/rw').mkdir(parents=True)
        (cap / 'overlay/work').mkdir()
        specs = [(str(self.base / 'm'), [], str(cap / 'overlay/rw'),
                  str(cap / 'overlay/work'))]
        with mock.patch.object(uid, 'mount_points', return_value=set()):
            delegated = uid.delegations(['bwrap'], specs, cap=cap)
        self.assertEqual(delegated, [(str(cap / 'overlay'), True)])
        self.assertNotIn(str(cap), [path for path, _ in delegated])

    def test_overlay_layers_at_the_capture_are_refused(self):
        cap = self.base / 'cap'
        (cap / 'rw').mkdir(parents=True)
        (cap / 'work').mkdir()
        specs = [(str(self.base / 'm'), [], str(cap / 'rw'), str(cap / 'work'))]
        with mock.patch.object(uid, 'mount_points', return_value=set()), \
             mock.patch.object(uid, 'fail', side_effect=RuntimeError) as fail:
            with self.assertRaises(RuntimeError):
                uid.delegations(['bwrap'], specs, cap=cap)
        self.assertIn('overlay layers', fail.call_args.args[0])
        self.assertIn(str(cap), fail.call_args.args[0])

    def test_overlay_layers_outside_the_capture_are_refused(self):
        cap = self.base / 'cap'
        cap.mkdir()
        layers = self.base / 'elsewhere'
        (layers / 'rw').mkdir(parents=True)
        (layers / 'work').mkdir()
        specs = [(str(self.base / 'm'), [], str(layers / 'rw'), str(layers / 'work'))]
        with mock.patch.object(uid, 'mount_points', return_value=set()), \
             mock.patch.object(uid, 'fail', side_effect=RuntimeError) as fail:
            with self.assertRaises(RuntimeError):
                uid.delegations(['bwrap'], specs, cap=cap)
        self.assertIn('inside', fail.call_args.args[0])

    def test_a_socket_in_the_runtime_folder_is_refused(self):
        runtime = self.base / 'run'
        runtime.mkdir()
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(str(runtime / 'wayland-0'))
        self.addCleanup(sock.close)
        argv = ['bwrap', '--ro-bind', str(runtime / 'wayland-0'), '/sock']
        with mock.patch.dict(uid.os.environ, {'XDG_RUNTIME_DIR': str(runtime)}), \
             mock.patch.object(uid, 'fail', side_effect=RuntimeError) as fail:
            with self.assertRaises(RuntimeError):
                uid.delegations(argv, [])
        self.assertIn('refusing to delegate the runtime folder', fail.call_args.args[0])

    def test_a_socket_in_a_folder_of_its_own_delegates_only_that_folder(self):
        runtime = self.base / 'run'
        own = runtime / 'sandbox-game-sockets' / 'game.123'
        own.mkdir(parents=True)
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(str(own / 'wayland-0'))
        self.addCleanup(sock.close)
        argv = ['bwrap', '--ro-bind', str(own / 'wayland-0'), '/sock']
        with mock.patch.dict(uid.os.environ, {'XDG_RUNTIME_DIR': str(runtime)}), \
             mock.patch.object(uid, 'mount_points', return_value=set()):
            self.assertEqual(uid.delegations(argv, []), [(str(own), False)])
        # --net delegates the folder of pasta's copies whole: another
        # launch's sockets must not be in it.
        pastas = runtime / 'sandbox-game'
        pastas.mkdir()
        (pastas / 'game-pasta').write_bytes(b'')
        other = runtime / 'sandbox-game-sockets' / 'other.456'
        other.mkdir()
        with mock.patch.dict(uid.os.environ, {'XDG_RUNTIME_DIR': str(runtime)}), \
             mock.patch.object(uid, 'mount_points', return_value=set()):
            wanted = uid.delegations(argv, [], [(str(pastas / 'game-pasta'), False)])
        for folder, _ in wanted:
            self.assertFalse(str(other).startswith(folder.rstrip('/') + '/'), wanted)


class WarmWorkerTests(unittest.TestCase):
    """Idle connections steering the delegations to the warm worker."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.cap = Path(tmp.name) / "cap"
        self.cap.mkdir()

    def launch(self, events, worker=None, lock=None, delegate=None):
        class Stop(Exception):
            pass

        def namespace(name):
            events.append("allocated")
            fd = os.open(os.devnull, os.O_RDONLY)
            self.addCleanup(os.close, fd)
            return fd

        def delegation(path, ns, read_only):
            events.append("delegate")
            return 10
        delegation = delegate or delegation

        patches = [
            mock.patch.object(uid, "managed_identity_error", return_value=None),
            mock.patch.object(uid, "canonical", return_value=["bwrap"]),
            mock.patch.object(uid, "overlays", return_value=(["bwrap"], [])),
            mock.patch.object(uid, "group_mismatches", return_value=[]),
            mock.patch.object(uid, "delegations",
                              return_value=[("/x", True), ("/y", False)]),
            mock.patch.object(uid, "managed_namespace", side_effect=namespace),
            mock.patch.object(uid, "delegate", side_effect=delegation),
            mock.patch.object(uid, "check", side_effect=Stop),
            mock.patch.object(uid, "nsresourced_lock", side_effect=lock or (lambda: None)),
        ]
        if worker is not None:
            patches.append(mock.patch.object(uid, "WarmWorker", worker))
        with ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            with self.assertRaises(Stop):
                uid.managed_launch(str(self.cap), ["bwrap"])

    def test_connections_open_after_allocation_and_close_after_delegation(self):
        events = []

        class Worker:
            def __init__(self, wanted=True):
                pass

            def __enter__(self):
                events.append("warm")
                return self

            def __exit__(self, *exc):
                events.append("closed")

        self.launch(events, Worker)
        self.assertEqual(events, ["allocated", "warm", "delegate", "delegate", "closed"])

    def test_the_lock_spans_allocation_and_delegations_only(self):
        events = []

        def held(fd):
            try:
                os.fstat(fd)
                return True
            except OSError:
                return False

        fd = os.open(os.devnull, os.O_RDONLY)
        self.addCleanup(lambda: held(fd) and os.close(fd))

        class Worker:
            def __init__(self, wanted=True):
                pass

            def __enter__(self):
                events.append(("warm", held(fd)))
                return self

            def __exit__(self, *exc):
                events.append(("closed", held(fd)))

        self.launch(events, Worker, lock=lambda: fd)
        self.assertIn(("warm", True), events)
        self.assertIn(("closed", True), events)
        self.assertFalse(held(fd))           # released before setns, not at exec

    def test_a_slow_delegation_holds_the_workers_for_the_rest(self):
        # A fast allocation, then a cold worker met by the first folder: the
        # remaining folders must go to it, as after a slow allocation.
        events, clock = [], [0.0]

        class Worker:
            def __init__(self, wanted=True):
                events.append(("wanted", wanted))

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                events.append("closed")

            def hold(self):
                events.append("hold")

        def delegation(path, ns, read_only):
            events.append(("delegate", path))
            clock[0] += 1.0 if path == "/x" else 0.01
            return 10

        with mock.patch.object(uid.time, "monotonic", side_effect=lambda: clock[0]):
            self.launch(events, Worker, delegate=delegation)
        self.assertEqual(events[events.index(("wanted", False)):],
                         [("wanted", False), ("delegate", "/x"), "hold",
                          ("delegate", "/y"), "closed"])

    def test_idle_workers_are_counted_by_their_titles(self):
        titles = {"1": b"systemd-nsresourcework: waiting...\0",
                  "2": b"systemd-nsresourcework: processing...\0",
                  "3": b"systemd-nsresourcework: waiting...\0",
                  "4": b"/usr/bin/bash\0"}

        def opened(path, mode="r"):
            return io.BytesIO(titles[path.split("/")[2]])

        with mock.patch.object(uid.os, "listdir", return_value=[*titles, "self"]), \
             mock.patch("builtins.open", side_effect=opened):
            self.assertEqual(uid.idle_workers(), 2)
        with mock.patch.object(uid.os, "listdir", return_value=["4"]), \
             mock.patch("builtins.open", side_effect=opened):
            self.assertIsNone(uid.idle_workers())    # hidepid: none to see

    def test_hold_takes_the_idle_workers_but_one_and_more_when_needed(self):
        with mock.patch.object(uid.socket, "socket", side_effect=lambda *a: mock.Mock()), \
             mock.patch.object(uid.signal, "setitimer") as timer, \
             mock.patch.object(uid, "idle_workers", side_effect=[8, 3, None, 99]):
            with uid.WarmWorker() as worker:
                self.assertEqual(len(worker.sockets), 7)
                worker.hold()                       # a cold one still met
                self.assertEqual(len(worker.sockets), 9)
                worker.hold()                       # titles unseen
                self.assertEqual(len(worker.sockets), 9 + uid.HELD_CONNECTIONS)
                worker.hold()
                self.assertEqual(len(worker.sockets), uid.HELD_MAX)
            timer.assert_any_call(signal.ITIMER_REAL, uid.HELD_TIMEOUT)
            self.assertEqual(timer.call_count, 2)   # armed once, then disarmed
            self.assertEqual(worker.sockets, [])

    def test_nothing_is_held_after_a_fast_allocation(self):
        with mock.patch.object(uid.socket, "socket") as connect, \
             mock.patch.object(uid.signal, "setitimer") as timer:
            with uid.WarmWorker(False) as worker:
                self.assertEqual(worker.sockets, [])
        connect.assert_not_called()
        timer.assert_not_called()

    def test_a_connection_that_fails_to_open_does_not_fail_the_launch(self):
        events = []
        with mock.patch.object(uid.socket, "socket",
                               side_effect=OSError("nsresourced is not there")):
            self.launch(events)
        self.assertEqual(events, ["allocated", "delegate", "delegate"])

    def test_the_alarm_closes_the_held_connections_without_a_thread(self):
        opened = []

        def connection(*args):
            s = mock.Mock()
            opened.append(s)
            return s

        before = signal.getsignal(signal.SIGALRM)
        threads = threading.active_count()
        with mock.patch.object(uid.socket, "socket", side_effect=connection), \
             mock.patch.object(uid, "idle_workers", return_value=None), \
             mock.patch.object(uid.signal, "setitimer") as timer:
            worker = uid.WarmWorker()
            with worker:
                self.assertEqual(len(opened), uid.HELD_CONNECTIONS)
                # setns() needs this process single-threaded.
                self.assertEqual(threading.active_count(), threads)
                timer.assert_called_once_with(signal.ITIMER_REAL, uid.HELD_TIMEOUT)
                alarm = signal.getsignal(signal.SIGALRM)
                alarm(signal.SIGALRM, None)
                for s in opened:
                    s.close.assert_called_once()
                self.assertEqual(worker.sockets, [])
                alarm(signal.SIGALRM, None)    # idempotent
            timer.assert_called_with(signal.ITIMER_REAL, 0)
        self.assertIs(signal.getsignal(signal.SIGALRM), before)
        for s in opened:
            s.close.assert_called_once()


class AllocationTests(unittest.TestCase):
    """AllocateUserRange retried when its workers time out."""

    def timeout(self):
        return uid.VarlinkError("io.systemd.System timed out", "io.systemd.System",
                                {"errno": errno.ETIMEDOUT})

    def allocate(self, outcomes, expect_failure=False):
        calls, fd = [], 7

        def reply(path, method, parameters, fds=()):
            outcome = outcomes[len(calls)]
            calls.append(outcome)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        with mock.patch.object(uid.socket, "socketpair",
                               return_value=(mock.Mock(), mock.Mock())), \
             mock.patch.object(uid.socket, "recv_fds",
                               return_value=(b"ns", [fd], 0, None)), \
             mock.patch.object(uid.os, "fork", return_value=4242), \
             mock.patch.object(uid.os, "waitpid", return_value=(4242, 0)), \
             mock.patch.object(uid.os, "close") as close, \
             mock.patch.object(uid.time, "sleep"), \
             mock.patch.object(uid, "fail", side_effect=RuntimeError) as fail, \
             mock.patch.object(uid, "varlink", side_effect=reply):
            if expect_failure:
                with self.assertRaises(RuntimeError):
                    uid.managed_namespace("sg-test")
                fail.assert_called_once()
                close.assert_called_with(fd)
                return calls
            self.assertEqual(uid.managed_namespace("sg-test"), fd)
            close.assert_not_called()
            return calls

    def test_a_timed_out_allocation_is_retried_and_succeeds(self):
        calls = self.allocate([self.timeout(), self.timeout(), ({}, [])])
        self.assertEqual(len(calls), 3)

    def test_another_error_is_not_retried(self):
        calls = self.allocate([uid.VarlinkError("io.systemd.System denied",
                                                 "io.systemd.System",
                                                 {"errno": errno.EPERM})],
                              expect_failure=True)
        self.assertEqual(len(calls), 1)

    def test_an_allocation_gives_up_after_the_retries(self):
        calls = self.allocate([self.timeout() for _ in range(uid.NSRESOURCE_TRIES)],
                              expect_failure=True)
        self.assertEqual(len(calls), uid.NSRESOURCE_TRIES)


def regrouped(paths, gid):
    """os.stat and os.lstat, with PATHS reported as belonging to GID: no
    chgrp to a group of no one's needed."""
    real = {"stat": os.stat, "lstat": os.lstat}
    paths = {str(p) for p in paths}
    def wrap(name):
        def inner(path, *args, **kwargs):
            st = real[name](path, *args, **kwargs)
            if os.fspath(path) in paths:
                fields = list(st)
                fields[5] = gid
                return os.stat_result(fields)
            return st
        return mock.patch.object(uid.os, name, inner)
    return wrap("stat"), wrap("lstat")


class GroupTests(unittest.TestCase):
    """mountfsd maps your uid's number alone, groups included: what the game
    writes to must be grouped so (see managed_identity_error)."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.me = os.getuid()
        self.other = self.me + 1

    def layout(self):
        b = self.base
        for d in ("game", "cap/overlay/rw/sub", "cap/overlay/work", "cap/home"):
            (b / d).mkdir(parents=True)
        (b / "readonly").write_text("x")
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(str(b / "sock"))
        self.addCleanup(sock.close)
        argv = ["bwrap", "--bind", str(b / "cap/home"), "/home",
                "--ro-bind", str(b / "readonly"), "/r", "--ro-bind", str(b / "sock"), "/s",
                "--bind", "/dev/null", "/dev/null"]
        specs = [(str(b / "m"), [str(b / "game")], str(b / "cap/overlay/rw"), str(b / "cap/overlay/work"))]
        return argv, specs

    def mismatches(self, paths):
        argv, specs = self.layout()
        stat_patch, lstat_patch = regrouped(paths, self.other)
        with stat_patch, lstat_patch, mock.patch.object(uid.os, "getuid", return_value=self.me):
            return [path for path, _ in uid.group_mismatches(argv, specs)]

    def test_paths_grouped_as_the_uid_pass(self):
        if os.getgid() != self.me:
            self.skipTest("this account's own files are not grouped as its uid")
        self.assertEqual(self.mismatches([]), [])

    def test_what_is_written_connected_to_or_copied_up_from_is_checked(self):
        b = self.base
        found = self.mismatches([b / "game", b / "cap/home", b / "cap/overlay/work", b / "sock",
                                 b / "readonly", "/dev/null"])
        # Not a read-only file, and not /dev/null: no folder of ours shares it.
        self.assertEqual(sorted(found), sorted(str(b / p) for p in
                                               ("game", "cap/home", "cap/overlay/work", "sock")))

    def test_message_names_the_fix(self):
        b = self.base
        self.layout()
        st_dir, st_sock = os.stat(b / "game"), os.stat(b / "sock")
        with mock.patch.object(uid.os, "getuid", return_value=1500):
            text = uid.group_error([(str(b / "my game"), st_dir), (str(b / "sock"), st_sock)])
        self.assertIn("chgrp -R 1500 '" + str(b / "my game") + "'", text)
        self.assertIn(str(b / "sock") + ": a socket from before your group changed", text)
        self.assertIn("The account's group", text)
        self.assertIsNone(uid.group_error([]))

    def test_launch_refuses_before_anything_changes(self):
        with mock.patch.object(uid, "managed_identity_error", return_value=None), \
             mock.patch.object(uid, "group_mismatches",
                               return_value=[("/x", os.stat(self.base))]), \
             mock.patch.object(uid, "managed_namespace") as allocate, \
             mock.patch.object(uid.os, "makedirs") as mkdir, \
             mock.patch.object(uid, "fail", side_effect=RuntimeError):
            with self.assertRaises(RuntimeError):
                uid.managed_launch(str(self.base), ["bwrap"])
        allocate.assert_not_called()
        mkdir.assert_not_called()

    def test_adopting_a_capture_with_other_groups_changes_nothing(self):
        cap = self.base / "cap"
        (cap / "overlay" / "rw/sub").mkdir(parents=True)
        (cap / "home").mkdir()
        (cap / "home/save").write_text("s")
        (cap / "overlay" / "rw/sub/.wh..wh..opq").write_text("")
        (cap / "overlay" / "rw/.wh.gone").write_text("")
        (cap / "link").symlink_to("home/save")
        stat_patch, lstat_patch = regrouped([cap / "home/save"], self.other)
        with stat_patch, lstat_patch, mock.patch.object(uid.os, "getuid", return_value=self.me), \
             mock.patch.object(uid, "fail", side_effect=RuntimeError) as fail:
            with self.assertRaises(RuntimeError):
                uid.managed_adopt(str(cap))
        self.assertIn("1 of the files", fail.call_args.args[0])
        self.assertIn(f"chgrp -R {self.me} ", fail.call_args.args[0])
        self.assertTrue((cap / "overlay" / "rw/sub/.wh..wh..opq").exists())
        self.assertTrue((cap / "overlay" / "rw/.wh.gone").is_file())

    def test_links_do_not_count(self):
        if os.getgid() != self.me:
            self.skipTest("this account's own files are not grouped as its uid")
        cap = self.base / "cap"
        cap.mkdir()
        (cap / "link").symlink_to("nowhere")
        stat_patch, lstat_patch = regrouped([cap / "link"], self.other)
        with stat_patch, lstat_patch, mock.patch.object(uid, "fail", side_effect=RuntimeError):
            uid.managed_adopt(str(cap))


class CaptureTests(unittest.TestCase):
    """Switching a capture over, and finding and placing its folders."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)

    def scanned(self):
        """os.scandir, counting the folders it reads."""
        seen, real = [], os.scandir

        def inner(path):
            seen.append(os.fspath(path))
            return real(path)
        return seen, mock.patch.object(uid.os, "scandir", inner)

    def test_adoption_converts_the_marks_in_one_walk(self):
        if os.getgid() != os.getuid():
            self.skipTest("this account's own files are not grouped as its uid")
        cap = self.base / "cap"
        for d in ("overlay/rw/sub", "overlay/rw/kept", "home/saves"):
            (cap / d).mkdir(parents=True)
        (cap / "overlay" / "rw/sub/.wh..wh..opq").write_text("")
        (cap / "overlay" / "rw/.wh.gone").write_text("")
        try:
            os.setxattr(cap / "overlay" / "rw/kept", "user.fuseoverlayfs.opaque", b"y")
            os.mknod(cap / "probe", stat.S_IFCHR, 0)
            os.unlink(cap / "probe")
        except OSError as e:
            self.skipTest(f"no user xattrs or whiteouts here: {e}")
        seen, scandir = self.scanned()
        with scandir:
            uid.managed_adopt(str(cap))
        self.assertEqual(sorted(seen), sorted(set(seen)))
        for d in ("overlay/rw/sub", "overlay/rw/kept"):
            self.assertEqual(os.getxattr(cap / d, "user.overlay.opaque"), b"y")
        self.assertFalse((cap / "overlay" / "rw/sub/.wh..wh..opq").exists())
        self.assertFalse((cap / "overlay" / "rw/.wh.gone").exists())
        st = os.lstat(cap / "overlay" / "rw/gone")
        self.assertTrue(stat.S_ISCHR(st.st_mode))
        self.assertEqual(st.st_rdev, 0)

    def test_a_failed_device_keeps_the_whiteout(self):
        if os.getgid() != os.getuid():
            self.skipTest("this account's own files are not grouped as its uid")
        cap = self.base / "cap"
        (cap / "overlay" / "rw").mkdir(parents=True)
        (cap / "overlay" / "rw/.wh.gone").write_text("")
        with mock.patch.object(uid.os, "mknod", side_effect=OSError("no space")), \
             mock.patch.object(uid, "fail", side_effect=RuntimeError):
            with self.assertRaises(RuntimeError):
                uid.managed_adopt(str(cap))
        self.assertTrue((cap / "overlay" / "rw/.wh.gone").is_file())
        self.assertFalse((cap / "overlay" / "rw/gone").exists())
        self.assertEqual([p.name for p in (cap / "overlay" / "rw").iterdir()], [".wh.gone"])

    def test_a_device_replaces_the_whiteout_only_after_it_exists(self):
        if os.getgid() != os.getuid():
            self.skipTest("this account's own files are not grouped as its uid")
        cap = self.base / "cap"
        (cap / "overlay" / "rw").mkdir(parents=True)
        (cap / "overlay" / "rw/.wh.gone").write_text("")

        def mknod(path, mode, device):
            self.assertEqual(mode, stat.S_IFCHR | 0o000)
            self.assertFalse(Path(path).exists())
            Path(path).write_text("")
        with mock.patch.object(uid.os, "mknod", side_effect=mknod), \
             mock.patch.object(uid, "fail", side_effect=RuntimeError):
            uid.managed_adopt(str(cap))
        self.assertTrue((cap / "overlay" / "rw/gone").exists())
        self.assertFalse((cap / "overlay" / "rw/.wh.gone").exists())
        self.assertEqual({p.name for p in (cap / "overlay" / "rw").iterdir()}, {"gone"})

    def test_an_existing_file_keeps_the_whiteout(self):
        if os.getgid() != os.getuid():
            self.skipTest("this account's own files are not grouped as its uid")
        cap = self.base / "cap"
        (cap / "overlay" / "rw").mkdir(parents=True)
        (cap / "overlay" / "rw/.wh.gone").write_text("")
        (cap / "overlay" / "rw/gone").write_text("kept")
        with mock.patch.object(uid.os, "mknod") as mknod, \
             mock.patch.object(uid, "fail", side_effect=RuntimeError):
            with self.assertRaises(RuntimeError):
                uid.managed_adopt(str(cap))
        mknod.assert_not_called()
        self.assertTrue((cap / "overlay" / "rw/.wh.gone").is_file())
        self.assertEqual((cap / "overlay" / "rw/gone").read_text(), "kept")

    def test_a_folder_it_cannot_read_stops_adoption_with_a_message(self):
        if os.getuid() == 0:
            self.skipTest("root reads any folder")
        cap = self.base / "cap"
        locked = cap / "overlay" / "rw/locked"
        locked.mkdir(parents=True)
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o700)
        with mock.patch.object(uid, "fail", side_effect=RuntimeError) as fail:
            with self.assertRaises(RuntimeError):
                uid.managed_adopt(str(cap))
        self.assertIn("chmod -R u+rwX", fail.call_args.args[0])

    def test_forget_reads_each_entry_once(self):
        cap = self.base / "cap"
        for d in ("overlay/rw/a/b", "home"):
            (cap / d).mkdir(parents=True)
        (cap / "home/save").write_text("s")
        read, real = [], os.getxattr

        def getxattr(path, name, **kwargs):
            read.append((os.fspath(path), name))
            return real(path, name, **kwargs)
        with mock.patch.object(uid.os, "getxattr", getxattr):
            uid.forget(str(cap), 123456)
        self.assertEqual(len(read), len(set(read)))
        self.assertEqual({p for p, _ in read},
                         {str(cap), *(str(p) for p in cap.rglob("*"))})

    def test_forget_without_the_range_warns_and_goes_on(self):
        cap = self.base / "cap"
        cap.mkdir()
        (cap / "uid").write_text("3\n")
        with mock.patch.object(uid.sys, "argv", ["sandbox-uid", "forget", str(cap)]), \
             mock.patch.object(uid, "subordinate", return_value=([], None)), \
             mock.patch.object(uid, "forget") as forget, \
             mock.patch.object(uid.sys, "stderr") as stderr:
            uid.main()
        forget.assert_not_called()
        self.assertIn("its ACL entries stay", "".join(c.args[0] for c in stderr.write.call_args_list))

    def fake_acls(self, user):
        data = uid.acl_pack({(uid.ACL_USER_OBJ, uid.NO_ID): 7,
                             (uid.ACL_USER, user): 6,
                             (uid.ACL_MASK, uid.NO_ID): 7,
                             (uid.ACL_OTHER, uid.NO_ID): 0})
        written = {}

        def getxattr(path, name, **kwargs):
            return data

        def setxattr(path, name, value, **kwargs):
            written[(os.fspath(path), name)] = uid.acl_unpack(value)
        return written, mock.patch.object(uid.os, "getxattr", getxattr), \
            mock.patch.object(uid.os, "setxattr", setxattr)

    def test_forget_drops_acls_from_fifos_and_sockets(self):
        cap = self.base / "cap"
        rw = cap / "overlay/rw"
        rw.mkdir(parents=True)
        fifo = rw / "pipe"
        os.mkfifo(fifo)
        sock_path = rw / "sock"
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(str(sock_path))
        self.addCleanup(sock.close)
        user = 123456
        written, getxattr, setxattr = self.fake_acls(user)
        with getxattr, setxattr:
            uid.forget(str(cap), user)
        for path in (fifo, sock_path):
            self.assertIn((str(path), uid.ACL_ACCESS), written)
            self.assertNotIn((uid.ACL_USER, user), written[(str(path), uid.ACL_ACCESS)])
            self.assertNotIn((str(path), uid.ACL_DEFAULT), written)

    def test_forget_crosses_into_a_separately_mounted_rw(self):
        cap = self.base / "cap"
        rw = cap / "overlay/rw"
        (rw / "sub").mkdir(parents=True)
        save = rw / "sub/save"
        save.write_text("s")
        cap_dev = os.lstat(cap).st_dev
        rw_dev = cap_dev + 1
        real_lstat = os.lstat

        def lstat(path, *args, **kwargs):
            st = real_lstat(path, *args, **kwargs)
            name = os.fspath(path)
            if name == str(rw) or name.startswith(str(rw) + "/"):
                fields = list(st)
                fields[2] = rw_dev
                return os.stat_result(fields)
            return st

        user = 123456
        written, getxattr, setxattr = self.fake_acls(user)
        with mock.patch.object(uid.os, "lstat", lstat), getxattr, setxattr:
            uid.forget(str(cap), user)
        self.assertIn((str(save), uid.ACL_ACCESS), written)

    def test_forget_unlocks_a_folder_the_game_left_at_0000(self):
        cap = self.base / "cap"
        locked = cap / "overlay/rw/locked"
        locked.mkdir(parents=True)
        save = locked / "save"
        save.write_text("s")
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o700)
        user = 123456
        written, getxattr, setxattr = self.fake_acls(user)
        with getxattr, setxattr:
            uid.forget(str(cap), user)
        self.assertIn((str(save), uid.ACL_ACCESS), written)
        self.assertEqual(stat.S_IMODE(os.lstat(locked).st_mode) & 0o700, 0o700)

    def test_a_folder_that_cannot_be_watched_is_not_entered(self):
        rw = self.base / "rw"
        (rw / "sub").mkdir(parents=True)
        (rw / "sub/file").write_text("x")
        fd = os.open(rw, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        dev = os.fstat(fd).st_dev
        closed, real_close = [], os.close

        def close(descriptor):
            closed.append(descriptor)
            real_close(descriptor)

        calls = []

        def add_watch(ino, path, events):
            calls.append(path)
            return -1                     # ELOOP: the folder is a link now

        with mock.patch.object(uid.libc, "inotify_add_watch", side_effect=add_watch), \
             mock.patch.object(uid, "reshare_fd") as reshare, \
             mock.patch.object(uid.os, "close", side_effect=close), \
             mock.patch.object(uid.os, "scandir") as scandir:
            uid.watch_fd(10, 0, {}, fd, os.getuid(), True, dev)
        self.assertEqual(calls, [f"/proc/self/fd/{fd}".encode()])
        reshare.assert_not_called()
        scandir.assert_not_called()
        self.assertEqual(closed, [fd])

    def test_a_folder_replaced_by_a_link_is_not_followed(self):
        rw = self.base / "rw"
        (rw / "sub").mkdir(parents=True)
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "secret").write_text("s")
        fd = os.open(rw, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        dev = os.fstat(fd).st_dev
        (rw / "sub").rename(rw / "old")
        (rw / "sub").symlink_to(outside)
        calls = []

        def add_watch(ino, path, events):
            calls.append(path)
            return len(calls)

        try:
            with mock.patch.object(uid.libc, "inotify_add_watch", side_effect=add_watch), \
                 mock.patch.object(uid, "reshare_fd"), \
                 mock.patch.object(uid, "reshare_at") as reshare:
                uid.watch_name(10, 0, {}, fd, "sub", os.getuid(), dev)
        finally:
            os.close(fd)
        self.assertEqual(calls, [])
        reshare.assert_not_called()

    def test_adoption_ignores_whiteout_names_that_are_not_targets(self):
        cap = self.base / "cap"
        rw = cap / "overlay/rw"
        rw.mkdir(parents=True)
        kept = (".wh.", ".wh...", ".wh....", ".wh..wh.meta")
        for name in kept:
            (rw / name).write_text("")
        (rw / ".wh..wh..opq").mkdir()
        uid.managed_adopt(str(cap))
        for name in kept:
            self.assertTrue((rw / name).is_file(), name)
        self.assertTrue((rw / ".wh..wh..opq").is_dir())
        with self.assertRaises(OSError):
            os.getxattr(rw, "user.overlay.opaque")

    def test_adoption_unlocks_a_read_only_folder_and_restores_it(self):
        cap = self.base / "cap"
        locked = cap / "overlay/rw/locked"
        locked.mkdir(parents=True)
        (locked / ".wh.gone").write_text("")
        locked.chmod(0o500)
        self.addCleanup(locked.chmod, 0o700)

        def mknod(path, mode, device):
            Path(path).write_text("")

        with mock.patch.object(uid.os, "mknod", side_effect=mknod):
            uid.managed_adopt(str(cap))
        self.assertEqual(stat.S_IMODE(os.lstat(locked).st_mode), 0o500)
        self.assertTrue((locked / "gone").exists())
        self.assertFalse((locked / ".wh.gone").exists())

    def test_adoption_retries_a_planted_temporary_name(self):
        cap = self.base / "cap"
        rw = cap / "overlay/rw"
        rw.mkdir(parents=True)
        (rw / ".wh.gone").write_text("")
        planted = rw / f".sandbox-uid-adopt-{os.getpid()}"
        planted.write_text("planted")
        made = []

        def mknod(path, mode, device):
            made.append(Path(path).name)
            if os.path.lexists(path):
                raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), path)
            Path(path).write_text("")

        with mock.patch.object(uid.os, "mknod", side_effect=mknod):
            uid.managed_adopt(str(cap))
        self.assertTrue(planted.exists())
        self.assertTrue((rw / "gone").exists())
        self.assertFalse((rw / ".wh.gone").exists())
        self.assertIn(f".sandbox-uid-adopt-{os.getpid()}-1", made)

    def test_a_folder_below_a_mount_in_a_delegated_one_is_placed(self):
        # ~/Games delegated without the drive mounted at ~/Games/ssd, whose
        # point shows there as an empty folder: the game's folder on that
        # drive gets a way to it of its own.
        games = self.base / "Games"
        (games / "ssd").mkdir(parents=True)
        game = games / "ssd" / "X"
        mounted, attached = [], []
        with mock.patch.object(uid, "mount", lambda src, dst, *a: mounted.append((src, dst))), \
             mock.patch.object(uid, "attach", lambda fd, path: attached.append(path)), \
             mock.patch.object(uid.os, "close"):
            uid.place([(str(games), 10), (str(game), 11)])
        self.assertEqual(mounted, [("tmpfs", str(games / "ssd"))])
        self.assertEqual(attached, [str(games), str(game)])
        self.assertTrue(game.is_dir())

    def bound(self, *argv):
        return subprocess.run(
            ["bash", "-c", '. "$1"; shift; bound_capture "$@"; printf %s "$BOUND"', "bound",
             str(ROOT / "sandbox-game-lib"), *argv],
            env={**os.environ, "HOME": str(self.base / "home")},
            capture_output=True, text=True, check=True).stdout

    def test_a_sandbox_is_found_by_the_real_path_of_its_home(self):
        real = self.base / "big" / "game-sandboxes"
        (real / "witcher3" / "home").mkdir(parents=True)
        (self.base / "home").mkdir()
        (self.base / "home" / "game-sandboxes").symlink_to(real)
        linked = self.base / "home" / "game-sandboxes" / "witcher3" / "home"
        for source in (linked, real / "witcher3" / "home"):
            self.assertEqual(self.bound("bwrap", "--bind", str(source), "/home/me"), "witcher3")
        self.assertEqual(self.bound("bwrap", "--bind", str(real / "a" / "b" / "home"), "/x"), "")
        self.assertEqual(self.bound("bwrap", "--ro-bind", str(linked), "/x"), "")

    def test_bound_capture_stops_at_the_option_terminator(self):
        real = self.base / "home" / "game-sandboxes" / "real" / "home"
        real.mkdir(parents=True)
        spoof = self.base / "home" / "game-sandboxes" / "spoof" / "home"
        spoof.mkdir(parents=True)
        # The game's own arguments after -- cannot name a capture of their own.
        self.assertEqual(self.bound(
            "bwrap", "--bind", str(real), "/home", "--", "--bind", str(spoof), "/x"), "real")
        self.assertEqual(self.bound("bwrap", "--", "--bind", str(spoof), "/x"), "")
        # A -- that is an option's value is not that terminator.
        self.assertEqual(self.bound(
            "bwrap", "--setenv", "KEY", "--", "--bind", str(real), "/x"), "real")
        self.assertEqual(self.bound(
            "bwrap", "--bind", "--", str(real), "--bind", str(real), "/x"), "real")

    def test_bound_capture_rejects_an_invalid_name(self):
        home = self.base / "home"
        (home / "game-sandboxes").mkdir(parents=True)
        for name in ("..", ".locks", "-option", "a/b"):
            source = home / "game-sandboxes" / name / "home"
            source.parent.mkdir(parents=True, exist_ok=True)
            self.assertEqual(self.bound("bwrap", "--bind", str(source), "/home"), "",
                             name)

    def test_names_are_valid_and_never_escape(self):
        def derive(*paths):
            script = (f'. {ROOT / "sandbox-game-lib"}\n'
                      'for p do derive_name "$p"; printf "%s\\n" "$R_NAME"; '
                      'valid_name "$R_NAME" || echo INVALID; done\n')
            return subprocess.run(["bash", "-c", script, "names", *paths],
                                  capture_output=True, text=True, check=True).stdout.split()
        cases = {
            "/": ["game"], "///": ["game"], "/foo/bar///": ["bar"], "foo//": ["foo"],
            "/@": ["game"], "/*": ["game"], "/.": ["game"], "/..": ["game"],
            "/(.)": ["game"], "/(..)": ["game"], "/-": ["game"],
            "/.locks": ["locks"], "/-weird-": ["weird"], "/Foo  Bar": ["foo-bar"],
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(derive(path), expected)
        self.assertNotIn("INVALID", derive(*cases))
        # @ and * must not expand all NAME_MAP entries when NAME_MAP is populated.
        script = (f'. {ROOT / "sandbox-game-lib"}\n'
                  'NAME_MAP[real]="mapped"\n'
                  'for p in /@ "/*"; do derive_name "$p"; printf "%s\\n" "$R_NAME"; done\n')
        result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.split(), ["game", "game"])
        # A user mapping cannot turn into a traversal either.
        script = (f'. {ROOT / "sandbox-game-lib"}\n'
                  'NAME_MAP[odd]="../escape"; derive_name /odd; printf "%s\\n" "$R_NAME"\n')
        result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.strip(), "odd")

    def test_preferences_keep_an_explicit_empty_env(self):
        config = self.base / "config" / "sandbox-game"
        target = config / "games" / "game"
        target.parent.mkdir(parents=True)
        target.write_text("net=1\nenv=\n")
        (config / "defaults").write_text("env=DXVK_HUD=1\n")
        script = (f'CFGDIR={str(config)!r}; NAME=game\n'
                  f'. {ROOT / "sandbox-game-lib"}\n'
                  "prefs_save '{\"scope\":\"game\"}'\n")
        result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = target.read_text().splitlines()
        self.assertIn("env=", lines)
        # An absent key stays absent rather than taking the defaults' value.
        target.write_text("net=1\n")
        result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(line.startswith("env=") for line in target.read_text().splitlines()))

    def test_owner_of_a_namespace_is_told_by_its_parent(self):
        cap = self.base / "cap"
        cap.mkdir()
        child = subprocess.Popen(["unshare", "-U", "sleep", "10"], stderr=subprocess.DEVNULL)
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        for _ in range(100):
            if os.stat(f"/proc/{child.pid}/ns/user").st_ino != os.stat("/proc/self/ns/user").st_ino:
                break
            if child.poll() is not None:
                self.skipTest("cannot make a user namespace here")
            time.sleep(0.02)
        else:
            self.skipTest("cannot make a user namespace here")
        ours = os.stat("/proc/self/ns/user")
        (cap / ".managed-userns").write_text(f"{ours.st_dev} {ours.st_ino}\n")
        self.assertTrue(uid.managed_owns(str(cap), str(child.pid)))
        (cap / ".managed-userns").write_text(f"{ours.st_dev} {ours.st_ino + 1}\n")
        self.assertFalse(uid.managed_owns(str(cap), str(child.pid)))
        self.assertFalse(uid.managed_owns(str(cap), "999999999"))


class AdministratorPreflightTests(unittest.TestCase):
    def test_user_with_different_primary_gid_is_refused(self):
        with mock.patch.object(setup.pwd, 'getpwuid', return_value=SimpleNamespace(pw_gid=12345)):
            with self.assertRaisesRegex(RuntimeError, 'requires matching primary UID and GID'):
                setup.users(['1000'])

    def components(self, mixed=False, modified=False, stale=False):
        def output(*args):
            if args[0] == 'ldd':
                return 'libsystemd-shared-261.4.so => /usr/lib64/systemd/libsystemd-shared-261.4.so'
            if args[0] == 'systemctl':
                unit = args[2]
                if 'FragmentPath' in args:
                    return '/usr/lib/systemd/system/' + unit
                if 'MainPID' in args:
                    return '123' if stale else '0'
                return f'{{ path=/usr/lib/systemd/{unit[:-8]} ; argv[]=... }}'
            if args[0] == 'rpm':
                if '%{VERSION}' in args:
                    return '261.4'
                if '%{SOURCERPM}' in args:
                    return 'different-build' if mixed and args[-1].endswith('nsresourcework') else 'same-build'
                digest = hashlib.sha256(b'changed' if modified else b'packaged').hexdigest()
                return args[-1] + '\t' + digest
            self.fail(args)
        with mock.patch.object(setup.platform, 'freedesktop_os_release', return_value={'ID': 'opensuse-tumbleweed'}), \
             mock.patch.object(setup.shutil, 'which', return_value='/usr/bin/rpm'), \
             mock.patch.object(Path, 'is_file', return_value=True), \
             mock.patch.object(Path, 'read_bytes', return_value=b'packaged'), \
             mock.patch.object(Path, 'samefile', return_value=False), \
             mock.patch.object(setup, 'output', side_effect=output):
            setup.components(uid)

    def test_matching_unmodified_package_components(self):
        self.components()

    def test_mixed_package_builds_are_refused(self):
        with self.assertRaisesRegex(RuntimeError, 'one source RPM build'):
            self.components(mixed=True)

    def test_modified_package_components_are_refused(self):
        with self.assertRaisesRegex(RuntimeError, 'differs from its RPM'):
            self.components(modified=True)

    def test_running_replaced_manager_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, 'still runs a replaced binary'):
            self.components(stale=True)

    def test_unsupported_distribution_is_refused(self):
        with mock.patch.object(setup.platform, 'freedesktop_os_release', return_value={'ID': 'debian'}):
            with self.assertRaisesRegex(RuntimeError, 'Tumbleweed only'):
                setup.components(uid)

    def test_invalid_user_list_changes_nothing(self):
        with mock.patch.object(setup, 'write') as write, mock.patch.object(setup, 'run') as run:
            for values in ([], ['0'], ['-1'], ['4294967295'], ['1000', '../root']):
                with self.subTest(values=values), self.assertRaises((RuntimeError, KeyError)):
                    setup.install(values)
            write.assert_not_called()
            run.assert_not_called()

    def test_busy_delegation_resources_are_refused(self):
        with mock.patch.object(setup, 'output', return_value='2'):
            with self.assertRaisesRegex(RuntimeError, 'resources are in use'):
                setup.idle()

    def test_live_registry_blocks_changes_even_with_empty_descriptor_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry = Path(tmp)
            (registry / 'lock').touch()
            with mock.patch.object(setup, 'REGISTRY', registry), \
                 mock.patch.object(setup, 'output', return_value='0'):
                setup.idle()
                (registry / 'u1234.userns').write_text('{}')
                with self.assertRaisesRegex(RuntimeError, 'managed namespaces are in use'):
                    setup.idle()

    def test_uninstall_without_state_preserves_unmanaged_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            helper = path / 'manual-helper'
            helper.write_text('manual install')
            with mock.patch.object(setup, 'STATE', path / 'absent'), \
                 mock.patch.object(setup, 'HELPER', helper), mock.patch.object(setup, 'run') as run:
                setup.uninstall()
            self.assertEqual(helper.read_text(), 'manual install')
            run.assert_not_called()


class AdministratorLayoutTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.root = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        self.unitdir = self.root / setup.UNITDIR.relative_to('/')
        self.legacy = self.root / setup.LEGACY_UNITDIR.relative_to('/')
        self.wanted = self.root / 'etc/systemd/system/multi-user.target.wants' / setup.RENDER
        mapped = {key: self.root / getattr(setup, key).relative_to('/') for key in
                  ('CONFIG', 'STATE', 'USERS', 'UNITDIR', 'LEGACY_UNITDIR', 'HELPER', 'RULE', 'DROPIN',
                   'POLKIT_DROPIN')}
        for key, value in mapped.items():
            stack.enter_context(mock.patch.object(setup, key, value))
        legacy_files = (self.legacy / setup.RENDER, self.legacy / setup.MOUNT)
        stack.enter_context(mock.patch.object(setup, 'LEGACY_FILES', legacy_files))
        stack.enter_context(mock.patch.object(setup, 'FILES',
            (setup.HELPER, setup.RULE, setup.DROPIN, setup.POLKIT_DROPIN,
             self.unitdir / setup.RENDER, self.unitdir / setup.MOUNT, *legacy_files)))
        # Exercise real file writes/removal, without root or live services.
        stack.enter_context(mock.patch.object(setup, 'trusted'))
        stack.enter_context(mock.patch.object(setup, 'users', return_value=[1000]))
        stack.enter_context(mock.patch.object(setup, 'components'))
        stack.enter_context(mock.patch.object(setup, 'idle'))
        stack.enter_context(mock.patch.object(setup, 'load', return_value=SimpleNamespace(managed_available=lambda: None)))
        stack.enter_context(mock.patch.object(setup.shutil, 'which', return_value='/mock/tool'))
        stack.enter_context(mock.patch.object(setup, 'output', return_value=''))
        stack.enter_context(mock.patch.object(setup, 'enabled', return_value=False))
        self.commands = stack.enter_context(mock.patch.object(setup, 'run', side_effect=self.command))

    def command(self, *args, **kwargs):
        if args[:2] == ('systemctl', 'disable') and setup.RENDER in args:
            self.wanted.unlink(missing_ok=True)
        if args[:2] == ('systemctl', 'enable') and setup.RENDER in args:
            self.wanted.parent.mkdir(parents=True, exist_ok=True)
            if not self.wanted.is_symlink():
                self.wanted.symlink_to('/' + str(self.unitdir.relative_to(self.root) / setup.RENDER))

    def old_install(self):
        setup.STATE.parent.mkdir(parents=True, exist_ok=True)
        setup.STATE.write_text(json.dumps({'format': 1, 'selinux': False,
                                          'sockets_enabled': dict.fromkeys(setup.SOCKETS, False)}))
        self.legacy.mkdir(parents=True)
        for name in (setup.RENDER, setup.MOUNT):
            shutil.copyfile(setup.SOURCE / name, self.legacy / name)
        self.wanted.parent.mkdir(parents=True, exist_ok=True)
        self.wanted.symlink_to('/usr/local/lib/systemd/system/' + setup.RENDER)

    def selinux(self, enabled):
        original = Path.exists

        def exists(path):
            if str(path) == '/sys/fs/selinux/enforce':
                return enabled
            return original(path)
        return mock.patch.object(Path, 'exists', exists)

    def test_reinstall_enabling_selinux_records_and_removes_the_module(self):
        self.old_install()
        sockets = json.loads(setup.STATE.read_text())['sockets_enabled']
        with self.selinux(True):
            setup.install(['1000'])
        state = json.loads(setup.STATE.read_text())
        self.assertTrue(state['selinux'])
        self.assertEqual(state['sockets_enabled'], sockets)
        self.commands.assert_any_call('semodule', '-i', mock.ANY)
        self.commands.reset_mock()
        with self.selinux(True), \
             mock.patch.object(setup, 'output',
                               return_value=f'{setup.MODULE} 1.1'):
            setup.uninstall()
        self.commands.assert_any_call('semodule', '-r', setup.MODULE)
        self.assertFalse(setup.STATE.exists())

    def test_uninstall_warns_when_the_recorded_module_cannot_be_removed(self):
        self.old_install()
        state = json.loads(setup.STATE.read_text())
        state['selinux'] = True
        setup.STATE.write_text(json.dumps(state))
        stderr = io.StringIO()
        with self.selinux(False), mock.patch.object(setup.sys, 'stderr', stderr):
            setup.uninstall()
        self.assertFalse(setup.STATE.exists())
        self.assertEqual([call for call in self.commands.call_args_list
                          if call.args and call.args[0] == 'semodule'], [])
        self.assertIn('could not be removed automatically',
                      stderr.getvalue())
        self.assertIn('SELinux is disabled', stderr.getvalue())

    def test_update_moves_old_units_and_enablement_then_uninstalls(self):
        self.old_install()
        setup.install(['1000'])
        self.assertEqual(self.wanted.readlink(), Path('/etc/systemd/system') / setup.RENDER)
        for name in (setup.RENDER, setup.MOUNT):
            self.assertFalse((self.legacy / name).exists())
            self.assertEqual((self.unitdir / name).read_bytes(), (setup.SOURCE / name).read_bytes())
        self.assertIn(b'SYSTEMD_BYPASS_USERDB=io.systemd.NamespaceResource',
                      setup.POLKIT_DROPIN.read_bytes())
        self.commands.assert_any_call('systemctl', 'try-restart', setup.POLKIT)
        self.commands.reset_mock()
        setup.uninstall()
        self.commands.assert_any_call('systemctl', 'try-restart', setup.POLKIT)
        self.assertFalse(self.wanted.is_symlink())
        self.assertTrue(all(not path.exists() for path in setup.FILES))
        self.assertFalse(setup.STATE.exists())
        self.assertTrue(setup.USERS.exists())

    def test_old_layout_can_be_uninstalled_without_updating(self):
        self.old_install()
        setup.uninstall()
        self.assertFalse(self.wanted.is_symlink())
        self.assertTrue(all(not path.exists() for path in setup.FILES))

    @unittest.skipUnless(shutil.which('systemd-analyze'), 'needs systemd-analyze')
    def test_boot_transaction_finds_render_units_before_usr_local_is_mounted(self):
        setup.install(['1000'])
        # Simulate early boot: /usr/local is not mounted yet. Verify the real
        # installed layout through systemd, including the WantedBy symlink.
        shutil.rmtree(self.root / 'usr/local')
        boot_units = self.root / 'etc/systemd/system'
        (boot_units / 'multi-user.target').write_text('[Unit]\nDescription=Boot fixture\nDefaultDependencies=no\n')
        for name in ('sysinit.target', 'basic.target', 'shutdown.target', 'umount.target',
                     'local-fs-pre.target', 'swap.target'):
            (boot_units / name).write_text('[Unit]\nDescription=Boot fixture\nDefaultDependencies=no\n')
        (boot_units / 'usr-local.mount').write_text(
            '[Mount]\nWhat=tmpfs\nWhere=/usr/local\nType=tmpfs\n')
        result = subprocess.run(['systemd-analyze', 'verify', '--root=' + str(self.root),
                                 '--man=no', '--generators=no', 'multi-user.target'],
                                env={**os.environ, 'SYSTEMD_LOG_LEVEL': 'debug'},
                                text=True, capture_output=True)
        for name in (setup.RENDER, setup.MOUNT, 'usr-local.mount'):
            self.assertIn(f'{name}: Installed new job {name}/start', result.stderr, result.stderr)


class RenderDevicePolicyTests(unittest.TestCase):
    def test_render_mount_sets_per_user_tmpfs_quotas(self):
        text = (ROOT / 'systemd-backend/run-sandboxgame-render.mount').read_text()
        options = next(line.partition('=')[2] for line in text.splitlines()
                       if line.startswith('Options=')).split(',')
        self.assertIn('usrquota', options)
        self.assertIn('usrquota_block_hardlimit=64k', options)
        self.assertIn('usrquota_inode_hardlimit=64', options)

    def test_activation_state_rewrites_without_truncating_to_zero(self):
        helper = load('setup_test_render_helper',
                      ROOT / 'systemd-backend/systemd-render-devices')
        with tempfile.TemporaryDirectory() as tmp:
            state = os.open(tmp, helper.DIRECTORY)
            self.addCleanup(os.close, state)
            marker = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0,
                                     st_nlink=1, st_size=2)
            with mock.patch.object(helper.os, 'fstat', return_value=marker), \
                 mock.patch.object(helper, 'read_root_file', return_value=b'1\n'), \
                 mock.patch.object(helper.os, 'ftruncate') as truncate, \
                 mock.patch.object(helper.os, 'pwrite', wraps=os.pwrite) as pwrite:
                self.assertTrue(helper.activation_state(state, 'enable'))
            pwrite.assert_called_once()
            self.assertEqual(pwrite.call_args.args[1:], (b'1\n', 0))
            truncate.assert_not_called()

    def test_render_helper_needs_no_sockets_and_keeps_device_capabilities(self):
        text = (ROOT / 'systemd-backend/sandbox-game-render-devices.service').read_text()
        lines = {line.strip() for line in text.splitlines()}
        self.assertIn('RestrictAddressFamilies=none', lines)
        self.assertNotIn('RestrictAddressFamilies=AF_UNIX', lines)
        self.assertIn('CapabilityBoundingSet=CAP_MKNOD CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE',
                      lines)
        self.assertNotIn('PrivateDevices=yes', lines)
        for directive in ('PrivateNetwork=yes', 'ProtectKernelTunables=yes',
                          'ProtectKernelModules=yes', 'ProtectKernelLogs=yes',
                          'ProtectControlGroups=yes', 'ProtectClock=yes',
                          'ProtectHostname=yes', 'LockPersonality=yes',
                          'MemoryDenyWriteExecute=yes', 'RestrictRealtime=yes',
                          'RestrictSUIDSGID=yes', 'RestrictNamespaces=yes',
                          'SystemCallArchitectures=native'):
            self.assertIn(directive, lines)

    def test_render_helper_does_not_consult_nss_or_open_sockets(self):
        source = (ROOT / 'systemd-backend/systemd-render-devices').read_text()
        self.assertNotRegex(source, r'\b(?:getpwnam|getgrnam)\b')
        self.assertNotRegex(source, r'(?m)^(?:import|from)\s+socket\b')
        self.assertNotRegex(source, r'\bsocket\.')


class DesktopBootCheckScriptTests(unittest.TestCase):
    def setUp(self):
        self.path = ROOT / 'systemd-backend/desktop-boot-check.sh'

    def test_checks_do_not_eval_interpolated_paths(self):
        text = self.path.read_text()
        self.assertNotRegex(text, r'\beval\b')
        for name in ('render_copy_owned', 'render_copy_matches_device',
                     'launch_file_changed_and_saved', 'capture_is_ours',
                     'nsresourced_waits_for_overlay'):
            self.assertIn(f'{name}() {{', text)

    def test_render_checks_compare_each_alias_with_its_named_device(self):
        owned = shell_function(self.path, 'render_copy_owned')
        matches = shell_function(self.path, 'render_copy_matches_device')
        render_glob = 'for file in "/run/sandboxgame/render/$(id -u)"/renderD*'
        self.assertIn(render_glob, owned)
        self.assertIn(render_glob, matches)
        self.assertIn('name="${file##*/}"', matches)
        self.assertIn('[ -e "/dev/dri/$name" ]', matches)
        self.assertIn('copies', matches)
        self.assertIn('devices', matches)

    def test_overlay_dependency_needs_an_exact_token_in_after_and_requires(self):
        function = shell_function(self.path, 'nsresourced_waits_for_overlay')
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / 'systemctl'
            fake.write_text(
                '#!/bin/bash\n'
                'case "$*" in\n'
                '  *"-p After "*) printf "%s\\n" "$AFTER" ;;\n'
                '  *"-p Requires "*) printf "%s\\n" "$REQUIRES" ;;\n'
                'esac\n')
            fake.chmod(0o755)
            for after, requires, status in (
                    ('modprobe@overlay.service', 'modprobe@overlay.service', 0),
                    ('modprobe@overlay.service', '', 1),
                    ('', 'modprobe@overlay.service', 1),
                    ('xmodprobe@overlay.service', 'modprobe@overlay.service', 1),
                    ('modprobe@overlay.service other.service',
                     'other.service modprobe@overlay.service', 0)):
                with self.subTest(after=after, requires=requires):
                    result = subprocess.run(
                        ['bash', '-c', function + '\nnsresourced_waits_for_overlay'],
                        env={**os.environ, 'PATH': f'{tmp}:{os.environ["PATH"]}',
                             'AFTER': after, 'REQUIRES': requires},
                        text=True, capture_output=True)
                    self.assertEqual(result.returncode, status, result.stderr)


class DesktopGpuCheckScriptTests(unittest.TestCase):
    def setUp(self):
        self.path = ROOT / 'systemd-backend/desktop-gpu-check.sh'

    def test_remove_setup_removes_temporary_config_and_scratch(self):
        function = shell_function(self.path, 'remove_setup')
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = base / 'game-config'
            config.write_text('cfg')
            inside = base / 'inside.new'
            inside.write_text('log')
            scratch = base / 'scratch'
            scratch.mkdir()
            (scratch / 'file').write_text('x')
            script = '\n'.join((
                'set -u',
                'pending=()',
                'keep=0 installed_before=1 tidy=1',
                'marker=""',
                'temporary_config="$TEST_CONFIG"',
                'temporary_inside="$TEST_INSIDE"',
                'watcher=""',
                'scratch="$TEST_SCRATCH"',
                'results="$TEST_BASE"',
                'checkout="$TEST_CHECKOUT"',
                'note() { :; }',
                'redact() { :; }',
                function,
                'remove_setup',
            ))
            result = subprocess.run(
                ['bash', '-c', script],
                env={**os.environ, 'TEST_CONFIG': str(config),
                     'TEST_INSIDE': str(inside), 'TEST_SCRATCH': str(scratch),
                     'TEST_BASE': str(base), 'TEST_CHECKOUT': str(ROOT)},
                text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(config.exists())
            self.assertFalse(inside.exists())
            self.assertFalse(scratch.exists())

    def test_redact_skips_directories_links_and_special_files(self):
        text = self.path.read_text()
        source = text.split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            results = base / 'results'
            results.mkdir()
            token = 'SecretGame'
            regular = results / 'launch.log'
            regular.write_text(f'playing {token}\n')
            (results / 'folder').mkdir()
            target = base / 'target.log'
            target.write_text(token)
            link = results / 'link.log'
            link.symlink_to(target)
            fifo = results / 'pipe'
            os.mkfifo(fifo)
            gamedir = base / 'gamedir'
            gamedir.mkdir()
            result = subprocess.run(
                ['python3', '-I', '-', str(results), 'game1',
                 str(base / 'selection'), str(gamedir), token],
                input=source, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(regular.read_text(), 'playing <game1>\n')
            self.assertTrue((results / 'folder').is_dir())
            self.assertTrue(link.is_symlink())
            self.assertTrue(fifo.exists())
            self.assertEqual(target.read_text(), token)


class SandboxPolicyTests(unittest.TestCase):
    def test_systemd_policy_covers_home_directory_and_var_run(self):
        text = (ROOT / 'systemd-backend/sandbox_game_systemd.te').read_text()
        self.assertIn('module sandbox_game_systemd 1.1;', text)
        self.assertIn('type user_home_dir_t;', text)
        self.assertIn('type var_run_t;', text)
        lines = text.splitlines()
        mount_allow = next(line for line in lines
                           if line.startswith('allow systemd_mountfsd_t {')
                           and ':dir { getattr ioctl };' in line)
        ns_allow = next(line for line in lines
                        if line.startswith('allow systemd_nsresourced_t {')
                        and ':dir { getattr ioctl };' in line)
        mount_xperm = next(line for line in lines
                           if line.startswith('allowxperm systemd_mountfsd_t {')
                           and ':dir ioctl 0x6601;' in line)
        ns_xperm = next(line for line in lines
                        if line.startswith('allowxperm systemd_nsresourced_t {')
                        and ':dir ioctl 0x6601;' in line)
        for rule in (mount_allow, ns_allow, mount_xperm, ns_xperm):
            self.assertIn('user_home_dir_t', rule)
        for rule in (mount_allow, mount_xperm):
            self.assertIn('var_run_t', rule)
        for rule in (ns_allow, ns_xperm):
            self.assertNotIn('var_run_t', rule)

    def test_pasta_tty_rules_forbid_reading_and_dangerous_ioctls(self):
        text = (ROOT / 'selinux/sandbox_pasta.te').read_text()
        self.assertIn('module sandbox_pasta 1.2;', text)
        lines = text.splitlines()
        allow = next(line for line in lines
                     if line.startswith(
                         'allow sandbox_pasta_t { user_tty_device_t user_devpts_t }'
                         ':chr_file'))
        xperm = next(line for line in lines
                     if line.startswith(
                         'allowxperm sandbox_pasta_t { user_tty_device_t user_devpts_t }'
                         ':chr_file ioctl'))
        self.assertNotIn('read', allow)
        for query in ('0x5401', '0x5413', '0x542a'):
            self.assertIn(query, xperm)
        self.assertNotIn('0x5412', text)
        self.assertNotIn('0x541c', text)

    def test_pasta_resolv_conf_can_follow_a_var_run_link(self):
        text = (ROOT / 'selinux/sandbox_pasta.te').read_text()
        require = text.split('require {', 1)[1].split('\n}', 1)[0]
        self.assertIn('type var_t;', require)
        self.assertIn('class lnk_file { read getattr };', require)
        lines = {line.strip() for line in text.splitlines()}
        self.assertIn('allow sandbox_pasta_t var_t:dir search;', lines)
        self.assertIn('allow sandbox_pasta_t var_run_t:lnk_file read;', lines)


class AudioPolicyTests(unittest.TestCase):
    def test_sandbox_pulse_disables_sample_cache_and_bounds_resources(self):
        text = (ROOT / 'audio/sandbox-pulse.conf').read_text()
        properties = re.search(r'^pulse\.properties\s*=\s*\{.*?^\}', text,
                               re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(properties)
        self.assertIn('pulse.max-sample-cache = 0', properties.group(0))
        service = (ROOT / 'audio/sandbox-pulse.service').read_text()
        section = re.search(r'^\[Service\]\s*$(.*?)^\[', service,
                            re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(section)
        body = section.group(1).splitlines()
        self.assertTrue(any(line.startswith('MemoryMax=') for line in body))
        self.assertTrue(any(line.startswith('TasksMax=') for line in body))

    def test_sandbox_pulse_requires_wireplumber_and_drops_privileges(self):
        service = (ROOT / 'audio/sandbox-pulse.service').read_text()
        unit, body = service.split('[Service]', 1)
        requires = [line for line in unit.splitlines() if line.startswith('Requires=')]
        self.assertTrue(any('wireplumber.service' in line.split() for line in requires))
        self.assertIn('NoNewPrivileges=yes', body.splitlines())

    def test_access_script_claims_clients_only_after_activation(self):
        text = (ROOT / 'audio/sandbox-access.lua').read_text()
        activation = text.index('pm:activate')
        hook = text.index('SimpleEventHook')
        self.assertIn('local pm_ready = false', text[:activation])
        self.assertIn('pm_ready = true', text[activation:hook])
        execute = text[hook:]
        self.assertRegex(execute, r'execute = function \(event\)\s+'
                                  r'if not pm_ready then\s+return\s+end')
        self.assertIn('{ metadata.name = "default" }', text)
        self.assertIn('default.audio.sink', text)
        self.assertIn('deny-restricted-capture.lua', text)
