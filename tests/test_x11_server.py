"""Private X11 supervisor lifecycle, using real child processes and sockets."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

WRAPPER = """
import runpy, sys
module = runpy.run_path(sys.argv[1])
run = module['beside_x11_server']
run.__globals__['X11_DIR'] = sys.argv[2]
run.__globals__['X11_START_TIMEOUT'] = 1
run(sys.argv[3:])
"""

SERVER = """
import os, signal, socket, struct, sys, time
from pathlib import Path
base = Path(sys.argv[1])
def stop(*_):
    (base / 'server-stopped').touch()
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
time.sleep(0.15)
s = socket.socket(socket.AF_UNIX)
s.bind(str(base / 'X0'))
s.listen()
client, _ = s.accept()
assert client.recv(12) == struct.pack('<BBHHHHH', ord('l'), 0, 11, 0, 0, 0, 0)
(base / 'ready').touch()
client.sendall(struct.pack('<BBHHH', 1, 0, 11, 0, 0))
client.close()
if sys.argv[2] == 'crash':
    while not (base / 'game-started').exists():
        time.sleep(0.01)
    sys.exit(23)
while True:
    time.sleep(1)
"""

GAME = """
import os, signal, sys, time
from pathlib import Path
base = Path(sys.argv[1])
assert (base / 'ready').exists()
assert os.environ['DISPLAY'] == ':0'
def stop(*_):
    (base / 'game-stopped').touch()
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
(base / 'game-started').touch()
if sys.argv[2] != 'wait':
    sys.exit(int(sys.argv[2]))
while True:
    time.sleep(1)
"""


class PrivateX11ServerTests(unittest.TestCase):
    def launch(self, base, server, game):
        return subprocess.Popen(
            [sys.executable, '-I', '-c', WRAPPER, str(ROOT / 'sandbox-landlock'), str(base),
             sys.executable, '-I', '-c', server, str(base), 'crash' if game == 'wait' else 'stay',
             '--', sys.executable, '-I', '-c', GAME, str(base), game],
            env={**os.environ, 'DISPLAY': ':999'}, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True)

    def test_waits_for_x11_setup_and_preserves_game_exit_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            process = self.launch(base, SERVER, '7')
            _, err = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 7, err)
            self.assertTrue((base / 'game-started').exists())
            self.assertTrue((base / 'server-stopped').exists())

    def test_server_crash_stops_the_game(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            process = self.launch(base, SERVER, 'wait')
            _, err = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 1, err)
            self.assertIn('server ended with status 23', err)
            self.assertTrue((base / 'game-stopped').exists())

    def test_server_start_failure_never_launches_the_game(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            process = self.launch(base, 'raise SystemExit(19)', '0')
            _, err = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 1, err)
            self.assertIn('server ended with status 19', err)
            self.assertFalse((base / 'game-started').exists())

    def test_startup_timeout_stops_server_without_starting_game(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            server = SERVER.replace('time.sleep(0.15)', 'time.sleep(30)')
            process = self.launch(base, server, '0')
            _, err = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 1, err)
            self.assertIn('did not become ready', err)
            self.assertTrue((base / 'server-stopped').exists())
            self.assertFalse((base / 'game-started').exists())

    def test_signal_during_startup_stops_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            server = SERVER.replace('time.sleep(0.15)', "(base / 'starting').touch(); time.sleep(30)")
            process = self.launch(base, server, '0')
            import time
            deadline = time.monotonic() + 5
            while not (base / 'starting').exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            process.send_signal(signal.SIGTERM)
            _, err = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 128 + signal.SIGTERM, err)
            self.assertTrue((base / 'server-stopped').exists())
            self.assertFalse((base / 'game-started').exists())


if __name__ == '__main__':
    unittest.main()
