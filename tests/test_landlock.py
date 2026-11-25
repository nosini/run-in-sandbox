#!/usr/bin/env python3
"""Focused checks for sandbox-landlock's display and attach connections."""
import array
import errno
import importlib.util
from importlib.machinery import SourceFileLoader
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load_landlock():
    # A script without .py, so spelled out; no bytecode left next to it.
    loader = SourceFileLoader("sandbox_landlock", str(ROOT / "sandbox-landlock"))
    module = importlib.util.module_from_spec(
        importlib.util.spec_from_loader(loader.name, loader))
    sys.dont_write_bytecode, saved = True, sys.dont_write_bytecode
    try:
        loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = saved
    return module


LANDLOCK = load_landlock()


class FakeSelector:
    def __init__(self):
        self.registered = {}

    def register(self, sock, events, data=None):
        self.registered[sock] = (events, data)

    def unregister(self, sock):
        self.registered.pop(sock, None)

    def modify(self, sock, events, data=None):
        self.registered[sock] = (events, data)


class FakeSocket:
    def __init__(self, recv_result=(b"", [], 0)):
        self.recv_result = recv_result
        self.sent = []
        self.closed = False
        self.blocking = True

    def connect(self, address):
        self.address = address

    def recvmsg(self, *_args, **_kwargs):
        return self.recv_result

    def sendmsg(self, buffers, anc=()):
        self.sent.append((buffers, anc))
        return sum(len(part) for part in buffers)

    def setblocking(self, flag):
        self.blocking = flag

    def close(self):
        self.closed = True


class FakeListener:
    def __init__(self, *clients):
        self.clients = list(clients)

    def accept(self):
        return self.clients.pop(0), None


class FakeOwner:
    def __init__(self):
        self.sel = FakeSelector()
        self.links = set()


def make_ondemand(pid=12345):
    ondemand = LANDLOCK.OnDemand.__new__(LANDLOCK.OnDemand)
    ondemand.sel = FakeSelector()
    ondemand.listener = None
    ondemand.command = ["true"]
    ondemand.pid = pid
    ondemand.pidfd = None
    ondemand.display = None
    ondemand.shown = False
    ondemand.served = False
    ondemand.closed_on = False
    ondemand.waiting = []
    ondemand.links = set()
    return ondemand


def read_closed(sock):
    try:
        return sock.recv(1024)
    except ConnectionResetError:
        return b""


def wait_for(path, timeout=5):
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            raise AssertionError(f"{path} did not appear")
        time.sleep(0.01)


class TruncatedMessageTests(unittest.TestCase):
    def test_truncated_descriptors_close_the_link_without_forwarding(self):
        owner = FakeOwner()
        client, server = FakeSocket(), FakeSocket()
        link = LANDLOCK.Link(owner, client, server)
        owner.links.add(link)
        received = os.pipe()
        anc = [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                array.array("i", received).tobytes())]
        client.recv_result = (b"request", anc, socket.MSG_CTRUNC, None)
        link.pump(client, LANDLOCK.selectors.EVENT_READ)
        self.assertTrue(link.closed)
        self.assertTrue(client.closed)
        self.assertTrue(server.closed)
        self.assertNotIn(link, owner.links)
        self.assertEqual(client.sent, [])
        self.assertEqual(server.sent, [])
        self.assertEqual(link.queue[server], [])
        for fd in received:
            with self.assertRaises(OSError):
                os.fstat(fd)


class OnDemandFloodTests(unittest.TestCase):
    def test_accept_closes_clients_beyond_the_waiting_cap(self):
        ondemand = make_ondemand()
        ondemand.connect = lambda: None
        ondemand.waiting = [FakeSocket() for _ in range(LANDLOCK.MAX_WAITING)]
        extra = FakeSocket()
        ondemand.listener = FakeListener(extra)
        ondemand.accept()
        self.assertTrue(extra.closed)
        self.assertEqual(len(ondemand.waiting), LANDLOCK.MAX_WAITING)
        self.assertTrue(all(not client.closed for client in ondemand.waiting))

    def test_accept_closes_clients_beyond_the_link_cap(self):
        ondemand = make_ondemand()
        ondemand.connect = lambda: None
        ondemand.links = {object() for _ in range(LANDLOCK.MAX_LINKS)}
        extra = FakeSocket()
        ondemand.listener = FakeListener(extra)
        ondemand.accept()
        self.assertTrue(extra.closed)
        self.assertEqual(ondemand.waiting, [])

    def test_a_flood_never_grows_waiting_past_the_cap(self):
        ondemand = make_ondemand()
        ondemand.connect = lambda: None
        clients = [FakeSocket() for _ in range(LANDLOCK.MAX_WAITING + 10)]
        ondemand.listener = FakeListener(*clients)
        for _ in clients:
            ondemand.accept()
        self.assertEqual(len(ondemand.waiting), LANDLOCK.MAX_WAITING)
        self.assertEqual(sum(client.closed for client in clients), 10)

    def test_connect_survives_emfile_creating_a_socket(self):
        ondemand = make_ondemand()
        client = FakeSocket()
        ondemand.waiting = [client]
        ondemand.display = 7
        error = OSError(errno.EMFILE, os.strerror(errno.EMFILE))
        with mock.patch.object(LANDLOCK.socket, "socket", side_effect=error):
            ondemand.connect()
        self.assertFalse(client.closed)
        self.assertEqual(ondemand.waiting, [client])
        self.assertEqual(ondemand.links, set())

    def test_connect_survives_emfile_registering_a_link(self):
        ondemand = make_ondemand()
        client = FakeSocket()
        ondemand.waiting = [client]
        ondemand.display = 7
        server = FakeSocket()
        error = OSError(errno.EMFILE, os.strerror(errno.EMFILE))
        with mock.patch.object(LANDLOCK.socket, "socket", return_value=server), \
                mock.patch.object(LANDLOCK, "Link", side_effect=error):
            ondemand.connect()
        self.assertTrue(client.closed)
        self.assertTrue(server.closed)
        self.assertEqual(ondemand.waiting, [])
        self.assertEqual(ondemand.links, set())

    def test_start_survives_fork_eagain(self):
        ondemand = make_ondemand(pid=None)
        waiting = FakeSocket()
        ondemand.waiting = [waiting]
        error = OSError(errno.EAGAIN, os.strerror(errno.EAGAIN))
        with mock.patch.object(LANDLOCK.os, "fork", side_effect=error):
            ondemand.start()
        self.assertIsNone(ondemand.pid)
        self.assertTrue(waiting.closed)
        self.assertEqual(ondemand.waiting, [])

    def test_start_survives_emfile_opening_the_pidfd(self):
        ondemand = make_ondemand(pid=None)
        waiting = FakeSocket()
        ondemand.waiting = [waiting]
        error = OSError(errno.EMFILE, os.strerror(errno.EMFILE))
        with mock.patch.object(LANDLOCK.os, "fork", return_value=12345), \
                mock.patch.object(LANDLOCK.os, "pidfd_open", side_effect=error), \
                mock.patch.object(LANDLOCK, "terminate") as terminate:
            ondemand.start()
        self.assertIsNone(ondemand.pid)
        terminate.assert_called_once_with([12345])
        self.assertTrue(waiting.closed)
        self.assertEqual(ondemand.waiting, [])

    def test_start_survives_emfile_registering_the_pidfd(self):
        ondemand = make_ondemand(pid=None)
        waiting = FakeSocket()
        ondemand.waiting = [waiting]
        pidfd, other = os.pipe()
        self.addCleanup(os.close, other)
        error = OSError(errno.EMFILE, os.strerror(errno.EMFILE))
        with mock.patch.object(LANDLOCK.os, "fork", return_value=12345), \
                mock.patch.object(LANDLOCK.os, "pidfd_open", return_value=pidfd), \
                mock.patch.object(ondemand.sel, "register", side_effect=error), \
                mock.patch.object(LANDLOCK, "terminate") as terminate:
            ondemand.start()
        self.assertIsNone(ondemand.pid)
        terminate.assert_called_once_with([12345])
        self.assertTrue(waiting.closed)
        with self.assertRaises(OSError):
            os.fstat(pidfd)


SERVE_WRAPPER = r"""
import os, runpy, sys, time

module = runpy.run_path(sys.argv[1])
base, outside, timeout = sys.argv[2], sys.argv[3], float(sys.argv[4])
real_external = module["external"]


def external(conn):
    try:
        if conn.getpeername() == b"\0" + outside.encode():
            return True
    except OSError:
        pass
    return real_external(conn)


listener = module["listen"](base)
game = os.fork()
if game == 0:
    while not os.path.exists(os.path.join(base, "game-exit")):
        time.sleep(0.01)
    os._exit(0)
open(os.path.join(base, "ready"), "w").close()
serve = module["serve"]
serve.__globals__["external"] = external
serve.__globals__["ATTACH_TIMEOUT"] = timeout
serve(listener, game)
"""


class AttachServeTests(unittest.TestCase):
    def start_serve(self, base, outside, timeout):
        return subprocess.Popen(
            [sys.executable, "-I", "-c", SERVE_WRAPPER,
             str(ROOT / "sandbox-landlock"), str(base), outside, str(timeout)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def stop_serve(self, process):
        if process.poll() is None:
            process.kill()
            process.wait()
        _, err = process.communicate()
        if err:
            print(err, file=sys.stderr)

    def test_same_namespace_peer_is_not_external(self):
        first, second = socket.socketpair()
        try:
            self.assertFalse(LANDLOCK.external(second))
        finally:
            first.close()
            second.close()

    def test_inner_connection_is_rejected_and_game_exit_is_not_stalled(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            outside = f"outside-{os.getpid()}-{time.monotonic_ns()}"
            process = self.start_serve(base, outside, 5)
            try:
                wait_for(base / "ready")
                inner = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                try:
                    inner.connect(str(base / "socket"))
                    inner.settimeout(3)
                    started = time.monotonic()
                    self.assertEqual(read_closed(inner), b"")
                    self.assertLess(time.monotonic() - started, 1)
                finally:
                    inner.close()

                stalled = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                try:
                    stalled.bind(f"\0{outside}")
                    stalled.connect(str(base / "socket"))
                    stalled.settimeout(5)
                    time.sleep(0.2)
                    started = time.monotonic()
                    (base / "game-exit").touch()
                    process.wait(timeout=3)
                    self.assertLess(time.monotonic() - started, 2)
                    self.assertEqual(process.returncode, 0)
                    self.assertEqual(read_closed(stalled), b"")
                finally:
                    stalled.close()
            finally:
                self.stop_serve(process)

    def test_stalled_request_is_closed_after_its_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            outside = f"outside-{os.getpid()}-{time.monotonic_ns()}"
            timeout = 1.0
            process = self.start_serve(base, outside, timeout)
            try:
                wait_for(base / "ready")
                stalled = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                try:
                    stalled.bind(f"\0{outside}")
                    stalled.connect(str(base / "socket"))
                    stalled.settimeout(timeout / 2)
                    with self.assertRaises(socket.timeout):
                        stalled.recv(1)     # still waiting, not closed at once
                    stalled.settimeout(3)
                    self.assertEqual(read_closed(stalled), b"")
                    self.assertIsNone(process.poll())
                    (base / "game-exit").touch()
                    process.wait(timeout=3)
                    self.assertEqual(process.returncode, 0)
                finally:
                    stalled.close()
            finally:
                self.stop_serve(process)


FAKE_ABI_WRAPPER = r"""
import runpy, sys

module = runpy.run_path(sys.argv[1])


class Syscall:
    restype = None

    def __call__(self, *args):
        return -1


class Libc:
    def __init__(self):
        self.syscall = Syscall()

    def prctl(self, *args):
        return 0


module["ctypes"].CDLL = lambda *args, **kwargs: Libc()
sys.argv = [sys.argv[1]] + sys.argv[2:]
module["main"]()
"""


class WithoutLandlockTests(unittest.TestCase):
    def test_attach_listener_is_not_created_without_landlock(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            marker = base / "ran"
            code = f"from pathlib import Path; Path({str(marker)!r}).write_text('ran')"
            result = subprocess.run(
                [sys.executable, "-I", "-c", FAKE_ABI_WRAPPER,
                 str(ROOT / "sandbox-landlock"), "--attach", str(base), "--",
                 sys.executable, "-I", "-c", code],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(marker.exists())
            self.assertFalse((base / "socket").exists())
            self.assertIn("no Landlock", result.stderr)
            self.assertIn("--attach needs Landlock", result.stderr)


class AttachListenerTests(unittest.TestCase):
    def test_listener_socket_is_private_and_nonblocking(self):
        with tempfile.TemporaryDirectory() as tmp:
            listener = LANDLOCK.listen(tmp)
            try:
                mode = os.stat(os.path.join(tmp, "socket")).st_mode
                self.assertEqual(stat.S_IMODE(mode), 0o600)
                self.assertFalse(listener.getblocking())
            finally:
                listener.close()


if __name__ == "__main__":
    unittest.main()
