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


class ManagedLaunchTests(unittest.TestCase):
    def test_overlay_mounts_are_delegated_when_their_capture_is_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            cap = Path(tmp)
            seen = []

            def delegations(argv, specs, extra):
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
        for d in ("game", "cap/rw/sub", "cap/work", "cap/home"):
            (b / d).mkdir(parents=True)
        (b / "readonly").write_text("x")
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(str(b / "sock"))
        self.addCleanup(sock.close)
        argv = ["bwrap", "--bind", str(b / "cap/home"), "/home",
                "--ro-bind", str(b / "readonly"), "/r", "--ro-bind", str(b / "sock"), "/s",
                "--bind", "/dev/null", "/dev/null"]
        specs = [(str(b / "m"), [str(b / "game")], str(b / "cap/rw"), str(b / "cap/work"))]
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
        found = self.mismatches([b / "game", b / "cap/home", b / "cap/work", b / "sock",
                                 b / "readonly", "/dev/null"])
        # Not a read-only file, and not /dev/null: no folder of ours shares it.
        self.assertEqual(sorted(found), sorted(str(b / p) for p in
                                               ("game", "cap/home", "cap/work", "sock")))

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
        (cap / "rw/sub").mkdir(parents=True)
        (cap / "home").mkdir()
        (cap / "home/save").write_text("s")
        (cap / "rw/sub/.wh..wh..opq").write_text("")
        (cap / "rw/.wh.gone").write_text("")
        (cap / "link").symlink_to("home/save")
        stat_patch, lstat_patch = regrouped([cap / "home/save"], self.other)
        with stat_patch, lstat_patch, mock.patch.object(uid.os, "getuid", return_value=self.me), \
             mock.patch.object(uid, "fail", side_effect=RuntimeError) as fail:
            with self.assertRaises(RuntimeError):
                uid.managed_adopt(str(cap))
        self.assertIn("1 of the files", fail.call_args.args[0])
        self.assertIn(f"chgrp -R {self.me} ", fail.call_args.args[0])
        self.assertTrue((cap / "rw/sub/.wh..wh..opq").exists())
        self.assertTrue((cap / "rw/.wh.gone").is_file())

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
        for d in ("rw/sub", "rw/kept", "home/saves"):
            (cap / d).mkdir(parents=True)
        (cap / "rw/sub/.wh..wh..opq").write_text("")
        (cap / "rw/.wh.gone").write_text("")
        try:
            os.setxattr(cap / "rw/kept", "user.fuseoverlayfs.opaque", b"y")
            os.mknod(cap / "probe", stat.S_IFCHR, 0)
            os.unlink(cap / "probe")
        except OSError as e:
            self.skipTest(f"no user xattrs or whiteouts here: {e}")
        seen, scandir = self.scanned()
        with scandir:
            uid.managed_adopt(str(cap))
        self.assertEqual(sorted(seen), sorted(set(seen)))
        for d in ("rw/sub", "rw/kept"):
            self.assertEqual(os.getxattr(cap / d, "user.overlay.opaque"), b"y")
        self.assertFalse((cap / "rw/sub/.wh..wh..opq").exists())
        self.assertFalse((cap / "rw/.wh.gone").exists())
        st = os.lstat(cap / "rw/gone")
        self.assertTrue(stat.S_ISCHR(st.st_mode))
        self.assertEqual(st.st_rdev, 0)

    def test_a_failed_device_keeps_the_whiteout(self):
        if os.getgid() != os.getuid():
            self.skipTest("this account's own files are not grouped as its uid")
        cap = self.base / "cap"
        (cap / "rw").mkdir(parents=True)
        (cap / "rw/.wh.gone").write_text("")
        with mock.patch.object(uid.os, "mknod", side_effect=OSError("no space")), \
             mock.patch.object(uid, "fail", side_effect=RuntimeError):
            with self.assertRaises(RuntimeError):
                uid.managed_adopt(str(cap))
        self.assertTrue((cap / "rw/.wh.gone").is_file())
        self.assertFalse((cap / "rw/gone").exists())
        self.assertEqual([p.name for p in (cap / "rw").iterdir()], [".wh.gone"])

    def test_a_device_replaces_the_whiteout_only_after_it_exists(self):
        if os.getgid() != os.getuid():
            self.skipTest("this account's own files are not grouped as its uid")
        cap = self.base / "cap"
        (cap / "rw").mkdir(parents=True)
        (cap / "rw/.wh.gone").write_text("")

        def mknod(path, mode, device):
            self.assertEqual(mode, stat.S_IFCHR | 0o000)
            self.assertFalse(Path(path).exists())
            Path(path).write_text("")
        with mock.patch.object(uid.os, "mknod", side_effect=mknod), \
             mock.patch.object(uid, "fail", side_effect=RuntimeError):
            uid.managed_adopt(str(cap))
        self.assertTrue((cap / "rw/gone").exists())
        self.assertFalse((cap / "rw/.wh.gone").exists())
        self.assertEqual({p.name for p in (cap / "rw").iterdir()}, {"gone"})

    def test_an_existing_file_keeps_the_whiteout(self):
        if os.getgid() != os.getuid():
            self.skipTest("this account's own files are not grouped as its uid")
        cap = self.base / "cap"
        (cap / "rw").mkdir(parents=True)
        (cap / "rw/.wh.gone").write_text("")
        (cap / "rw/gone").write_text("kept")
        with mock.patch.object(uid.os, "mknod") as mknod, \
             mock.patch.object(uid, "fail", side_effect=RuntimeError):
            with self.assertRaises(RuntimeError):
                uid.managed_adopt(str(cap))
        mknod.assert_not_called()
        self.assertTrue((cap / "rw/.wh.gone").is_file())
        self.assertEqual((cap / "rw/gone").read_text(), "kept")

    def test_a_folder_it_cannot_read_stops_adoption_with_a_message(self):
        if os.getuid() == 0:
            self.skipTest("root reads any folder")
        cap = self.base / "cap"
        locked = cap / "rw/locked"
        locked.mkdir(parents=True)
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o700)
        with mock.patch.object(uid, "fail", side_effect=RuntimeError) as fail:
            with self.assertRaises(RuntimeError):
                uid.managed_adopt(str(cap))
        self.assertIn("chmod -R u+rwX", fail.call_args.args[0])

    def test_forget_reads_each_entry_once(self):
        cap = self.base / "cap"
        for d in ("rw/a/b", "home"):
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
