#!/usr/bin/env python3
"""Focused checks for sandbox-uid and sandbox-attach's low-level helpers."""
import ast
import errno
import importlib.util
from importlib.machinery import SourceFileLoader
import io
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load_script(name, path):
    # A script without .py, so spelled out; no bytecode left next to it.
    loader = SourceFileLoader(name, str(path))
    module = importlib.util.module_from_spec(
        importlib.util.spec_from_loader(loader.name, loader))
    sys.dont_write_bytecode, saved = True, sys.dont_write_bytecode
    try:
        loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = saved
    return module


UID = load_script("sandbox_uid_low", ROOT / "sandbox-uid")
ATTACH = (ROOT / "sandbox-attach").read_text()
CLIENT = ATTACH.split("\nread -r -d '' CLIENT <<'EOF' || true\n", 1)[1].split("\nEOF\n", 1)[0]


def client_function(name):
    tree = ast.parse(CLIENT)
    node = next(n for n in tree.body
                if isinstance(n, ast.FunctionDef) and n.name == name)
    module = ast.Module(body=[node], type_ignores=[])
    ast.fix_missing_locations(module)
    return module


class PidValidationTests(unittest.TestCase):
    def test_managed_owns_rejects_anything_but_a_positive_pid(self):
        for pid in ("", "0", "-1", "+1", "01", "../1", "1/2", "abc", " 1"):
            with self.subTest(pid=pid):
                self.assertFalse(UID.managed_owns("/nonexistent", pid))

    def test_managed_enter_rejects_anything_but_a_positive_pid(self):
        for pid in ("0", "-1", "../1", "1/2", "abc"):
            with self.subTest(pid=pid):
                with mock.patch.object(UID.sys, "stderr", new=io.StringIO()), \
                        self.assertRaises(SystemExit) as raised:
                    UID.managed_enter(pid, ["true"])
                self.assertNotEqual(raised.exception.code, 0)


class IdleWorkerTests(unittest.TestCase):
    def test_a_waiting_worker_must_belong_to_root(self):
        titles = {
            "/proc/100/cmdline": UID.NSRESOURCE_WAITING,
            "/proc/200/cmdline": UID.NSRESOURCE_WAITING,
            "/proc/300/cmdline": b"systemd-nsresourcework: busy",
            "/proc/400/cmdline": b"something else",
        }

        def fake_open(path, *_args, **_kwargs):
            return io.BytesIO(titles[str(path)])

        def fake_stat(path):
            owner = 0 if str(path) in ("/proc/1", "/proc/100", "/proc/300") else 1000
            return type("Stat", (), {"st_uid": owner})()

        with mock.patch.object(UID.os, "listdir",
                               return_value=["100", "200", "300", "400", "x"]), \
                mock.patch.object(UID.os, "stat", side_effect=fake_stat), \
                mock.patch("builtins.open", side_effect=fake_open):
            self.assertEqual(UID.idle_workers(), 1)


class StdioTests(unittest.TestCase):
    def test_closed_standard_descriptors_are_occupied_before_internal_ones(self):
        script = r"""
import importlib.util, os, sys
from importlib.machinery import SourceFileLoader
loader = SourceFileLoader("sandbox_uid_stdio", sys.argv[1])
module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
loader.exec_module(module)
for fd in (0, 1, 2):
    try:
        os.close(fd)
    except OSError:
        pass
module.occupy_stdio()
for fd in (0, 1, 2):
    os.fstat(fd)
r, w = os.pipe()
if r < 3 or w < 3:
    os._exit(2)
os.close(r)
os.close(w)
with open(sys.argv[2], "w") as marker:
    marker.write("ok")
"""
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "marker"
            result = subprocess.run(
                [sys.executable, "-I", "-c", script, str(ROOT / "sandbox-uid"),
                 str(marker)],
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(marker.read_text(), "ok")


class ExecBwrapTests(unittest.TestCase):
    def test_a_bare_bwrap_is_found_on_path_and_started_with_no_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            bwrap = Path(tmp) / "bwrap"
            bwrap.write_text("#!/bin/sh\n")
            bwrap.chmod(0o755)
            with mock.patch.dict(os.environ, {"PATH": tmp}), \
                    mock.patch.object(UID.os, "execve") as execve, \
                    mock.patch.object(UID.signal, "signal") as reset:
                UID.exec_bwrap(["bwrap", "--unshare-all"])
            execve.assert_called_once_with(
                str(bwrap.resolve()), ["bwrap", "--unshare-all"], {})
            self.assertEqual(reset.call_args_list, [
                mock.call(signal.SIGPIPE, signal.SIG_DFL),
                mock.call(signal.SIGXFSZ, signal.SIG_DFL)])

    def test_an_absolute_bwrap_is_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            bwrap = Path(tmp) / "bwrap"
            bwrap.write_text("#!/bin/sh\n")
            with mock.patch.object(UID.os, "execve") as execve, \
                    mock.patch.object(UID.signal, "signal"):
                UID.exec_bwrap([str(bwrap), "--version"])
            execve.assert_called_once_with(
                str(bwrap.resolve()), [str(bwrap), "--version"], {})


class OptionScanTests(unittest.TestCase):
    def test_unshare_all_after_bwraps_terminator_is_a_command_argument(self):
        self.assertIsNone(UID.option_index(["--", "--unshare-all"], "--unshare-all"))
        self.assertEqual(UID.option_index(["--unshare-all", "--"], "--unshare-all"), 0)


class RelayOutputTests(unittest.TestCase):
    def test_the_relay_closes_the_dev_null_it_opens(self):
        info = type("Stat", (), {
            "st_mode": stat.S_IFREG | 0o644, "st_uid": 0, "st_dev": 1, "st_ino": 1})()

        def fstat(fd):
            if fd == 1:
                return info
            raise OSError(errno.EBADF, os.strerror(errno.EBADF))

        with mock.patch.object(UID.os, "fstat", side_effect=fstat), \
                mock.patch.object(UID.fcntl, "fcntl", return_value=os.O_WRONLY), \
                mock.patch.object(UID.os, "pipe", return_value=(10, 11)), \
                mock.patch.object(UID.os, "fork", return_value=0), \
                mock.patch.object(UID.os, "dup", return_value=12), \
                mock.patch.object(UID, "close_others"), \
                mock.patch.object(UID.os, "open", return_value=100) as opened, \
                mock.patch.object(UID.os, "dup2") as dup2, \
                mock.patch.object(UID.os, "close") as close, \
                mock.patch.object(UID.os, "read", return_value=b""), \
                mock.patch.object(UID.os, "_exit", side_effect=SystemExit):
            with self.assertRaises(SystemExit):
                UID.relay_output(12345)
        opened.assert_called_once_with("/dev/null", os.O_RDWR)
        self.assertEqual(close.call_args_list, [mock.call(100)])
        self.assertEqual(dup2.call_args_list, [
            mock.call(100, 0), mock.call(100, 1), mock.call(100, 2)])


class WarmWorkerTests(unittest.TestCase):
    def test_a_hold_whose_deadline_has_passed_makes_no_connection(self):
        worker = UID.WarmWorker(wanted=False)
        with mock.patch.object(UID, "idle_workers", return_value=3), \
                mock.patch.object(UID.time, "monotonic", side_effect=[100, 121]), \
                mock.patch.object(UID.socket, "socket") as made, \
                mock.patch.object(UID, "trace"):
            worker.hold()
        made.assert_not_called()
        self.assertEqual(worker.sockets, [])

    def test_each_connect_is_bounded_by_the_time_left_on_the_deadline(self):
        worker = UID.WarmWorker(wanted=False)
        connections = mock.Mock()
        with mock.patch.object(UID, "idle_workers", return_value=3), \
                mock.patch.object(UID.time, "monotonic",
                                  side_effect=[100, 101, 102, 103]), \
                mock.patch.object(UID.socket, "socket", return_value=connections), \
                mock.patch.object(UID.signal, "signal", return_value=object()), \
                mock.patch.object(UID.signal, "setitimer") as timer, \
                mock.patch.object(UID, "trace"):
            worker.hold()
        self.assertEqual(worker.sockets, [connections, connections])
        self.assertEqual(connections.settimeout.call_args_list, [
            mock.call(19), mock.call(None), mock.call(18), mock.call(None)])
        timer.assert_called_once_with(signal.ITIMER_REAL, 17)


class ReapChildTests(unittest.TestCase):
    def test_a_pasta_that_ignores_sigterm_is_killed_without_blocking(self):
        class Clock:
            now = 0

            def monotonic(self):
                return self.now

            def sleep(self, seconds):
                self.now += seconds

        clock = Clock()
        with mock.patch.object(UID.time, "monotonic", clock.monotonic), \
                mock.patch.object(UID.time, "sleep", clock.sleep), \
                mock.patch.object(UID.os, "waitpid", return_value=(0, 0)), \
                mock.patch.object(UID.os, "kill") as kill:
            UID.reap_child(123, grace=0.05)
        self.assertEqual(kill.call_args_list, [
            mock.call(123, signal.SIGTERM), mock.call(123, signal.SIGKILL)])
        self.assertLess(clock.now, 1)


class AttachNameTests(unittest.TestCase):
    def test_name_without_a_value_reports_usage_instead_of_unbound(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [str(ROOT / "sandbox-attach"), "--name"],
                env={**os.environ, "HOME": tmp},
                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 1)
        self.assertIn("--name needs NAME", result.stderr)
        self.assertNotIn("unbound variable", result.stderr)


class ClientWriteTests(unittest.TestCase):
    def test_write_all_loops_through_short_writes_and_eintr(self):
        class Writes:
            def __init__(self):
                self.data = b""
                self.interrupt = True

            def write(self, _fd, view):
                if self.interrupt:
                    self.interrupt = False
                    raise InterruptedError
                part = bytes(view[:2])
                self.data += part
                return len(part)

        writes = Writes()
        namespace = {"os": writes}
        exec(compile(client_function("write_all"), "<client>", "exec"), namespace)
        self.assertTrue(namespace["write_all"](1, b"abcdef"))
        self.assertEqual(writes.data, b"abcdef")

    def test_write_all_reports_a_closed_pty_without_raising(self):
        class Failing:
            def write(self, _fd, _view):
                raise OSError(errno.EIO, os.strerror(errno.EIO))

        namespace = {"os": Failing()}
        exec(compile(client_function("write_all"), "<client>", "exec"), namespace)
        self.assertFalse(namespace["write_all"](1, b"x"))


class ClientWakeTests(unittest.TestCase):
    def test_wake_pipe_is_nonblocking_and_the_handler_never_blocks(self):
        self.assertIn("os.set_blocking(wake_read, False)", CLIENT)
        self.assertIn("os.set_blocking(wake, False)", CLIENT)

        class Full:
            def write(self, _fd, data):
                self.data = data
                raise BlockingIOError

        full = Full()
        namespace = {"os": full, "wake": 7}
        exec(compile(client_function("wake_on_winch"), "<client>", "exec"), namespace)
        namespace["wake_on_winch"](signal.SIGWINCH, None)
        self.assertEqual(full.data, b"x")


if __name__ == "__main__":
    unittest.main()
