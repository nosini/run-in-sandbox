#!/usr/bin/env -S python3 -I
"""Test pasta from a managed UID range, with the existing network policy.

Uses a disposable network namespace, a DNS query for example.com and one
HTTP HEAD request to its public address. --host-test-address must be an
address provisioned on this test host (for example on a disposable dummy
interface), distinct from pasta's copied primary address. The probe opens a
local listener there and verifies the guest's route policy refuses it.
Requires pasta, iproute2, bubblewrap, and the delegation sockets.
"""
import argparse
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "access_probe", Path(__file__).with_name("systemd-access.py"))
access = importlib.util.module_from_spec(spec)
spec.loader.exec_module(access)
probe = access.probe

PAYLOAD = r"""
import ctypes, errno, os, socket, struct
from pathlib import Path
status = Path('/proc/self/status').read_text()
assert os.getgroups() == [], 'caller supplementary groups leaked'
assert 'Seccomp:\t2\n' in status
assert 'CapEff:\t0000000000000000\n' in status
query = struct.pack('!6H', 1234, 0x100, 1, 0, 0, 0)
query += b'\x07example\x03com\x00' + struct.pack('!HH', 1, 1)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
    client.settimeout(10)
    client.sendto(query, ('169.254.1.1', 53))
    reply = client.recv(4096)
    ident, flags, _, answers, _, _ = struct.unpack('!6H', reply[:12])
    assert ident == 1234 and flags & 0x8000 and flags & 15 == 0 and answers > 0
with socket.create_connection((os.environ['PUBLIC_IP'], 80), timeout=10) as client:
    client.sendall(b'HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n')
    assert client.recv(4096).startswith(b'HTTP/')
# Policy must refuse this locally; ENETUNREACH proves no LAN packet was sent.
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.settimeout(2)
    try:
        client.connect((os.environ['HOST_IP'], int(os.environ['HOST_PORT'])))
    except OSError as error:
        assert error.errno in (errno.ENETUNREACH, errno.EACCES), error
    else:
        raise RuntimeError('host-address prohibition absent')
print('DNS forwarding, public HTTP, host-address prohibition: PASS')
"""


def entered(namespace):
    probe.checked(probe.libc.setns(namespace, probe.CLONE_NEWUSER), "pasta user namespace")
    os.setresgid(0, 0, 0)
    os.setresuid(0, 0, 0)
    os.setgroups([])


def worker(namespace, control, public_ip, host_ip, host_port, helper, seccomp):
    entered(namespace)
    base = int(Path("/proc/self/uid_map").read_text().split()[1])
    probe.checked(probe.libc.prctl(4, 1, 0, 0, 0), "dumpability")
    probe.checked(probe.libc.unshare(0x40000000), "network namespace")
    control.send(json.dumps({"pid": os.getpid(), "base": base}).encode())
    probe.require(control.recv(4096) == b"start", "network startup handshake")
    deadline = time.monotonic() + 15
    while True:
        routes = subprocess.run(["ip", "-j", "-4", "route", "show", "default"],
                                capture_output=True, text=True, check=True)
        if json.loads(routes.stdout):
            break
        probe.require(time.monotonic() < deadline, "pasta did not configure the interface")
        time.sleep(0.05)
    # Same ordering as sandbox-game: allow DNS, prohibit host addresses before
    # any LAN allowance, then prohibit the private/link-local ranges.
    rules = [(90, "169.254.1.1", "lookup", "main"), (94, host_ip, "prohibit")]
    rules += [(100, net, "prohibit") for net in
              ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")]
    for priority, target, *action in rules:
        subprocess.run(["ip", "-4", "rule", "add", "priority", str(priority),
                        "to", target, *action], check=True)
    route = subprocess.run(["ip", "-4", "route", "get", "192.168.123.123"],
                           capture_output=True)
    probe.require(route.returncode != 0, "private-network route not prohibited")
    uid, gid = os.environ["PROBE_UID"], os.environ["PROBE_GID"]
    probe.checked(probe.libc.unshare(probe.CLONE_NEWUSER), "child user namespace")
    Path("/proc/self/setgroups").write_text("deny")
    Path("/proc/self/uid_map").write_text(f"{uid} 0 1\n")
    Path("/proc/self/gid_map").write_text(f"{gid} 0 1\n")
    probe.checked(probe.libc.prctl(4, 1, 0, 0, 0), "child dumpability")
    os.lseek(helper, 0, os.SEEK_SET)
    os.lseek(seccomp, 0, os.SEEK_SET)
    command = [
        "bwrap", "--unshare-all", "--share-net", "--unshare-user", "--disable-userns",
        "--die-with-parent", "--new-session", "--clearenv",
        "--setenv", "PUBLIC_IP", public_ip, "--setenv", "HOST_IP", host_ip,
        "--setenv", "HOST_PORT", str(host_port),
        "--ro-bind", "/usr", "/usr", "--ro-bind", "/etc", "/etc",
        "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64", "--proc", "/proc", "--dev", "/dev",
        "--tmpfs", "/tmp", "--ro-bind-data", str(helper), "/sandbox-landlock",
        "--seccomp", str(seccomp), "--", "/usr/bin/python3", "-I", "/sandbox-landlock",
        "--ro", "/usr", "--ro", "/etc", "--ro", "/proc", "--rw", "/dev",
        "--rw", "/tmp", "--", "/usr/bin/python3", "-I", "-c", PAYLOAD,
    ]
    result = subprocess.run(command, pass_fds=(helper, seccomp), capture_output=True,
                            text=True, timeout=35, env={"PATH": "/usr/bin:/bin"})
    probe.require(result.returncode == 0, f"network payload: {result.stdout} {result.stderr}")
    probe.require("no Landlock" not in result.stderr, "Landlock unavailable")
    print(json.dumps({"managed_base": base, "dns": True, "public_http": True,
                      "private_routes_blocked": True, "host_address_blocked": True,
                      "bwrap_seccomp_landlock": True}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-test-address", required=True,
                        help="existing local IPv4 address distinct from the default interface")
    args = parser.parse_args()
    probe.require(os.getuid() != 0, "run as an ordinary user")
    addresses = socket.getaddrinfo("example.com", 80, socket.AF_INET, socket.SOCK_STREAM)
    public_ip = next((item[4][0] for item in addresses
                      if ipaddress.ip_address(item[4][0]).is_global), None)
    probe.require(public_ip is not None, "example.com did not resolve to a public IPv4 address")
    routes = json.loads(subprocess.run(["ip", "-j", "-4", "route", "get", public_ip],
                                      capture_output=True, text=True, check=True).stdout)
    primary_ip = routes[0]["prefsrc"]
    host_ip = str(ipaddress.IPv4Address(args.host_test_address))
    probe.require(host_ip != primary_ip and not ipaddress.ip_address(host_ip).is_loopback,
                  "host fixture must be a distinct non-loopback address")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind((host_ip, 0))
    listener.listen(2)
    host_port = listener.getsockname()[1]
    # Confirm the fixture is reachable from the host before expecting its
    # failure from the guest. No address belonging to another machine is used.
    with socket.create_connection((host_ip, host_port), timeout=2):
        accepted, _ = listener.accept()
        accepted.close()
    os.environ["PROBE_UID"], os.environ["PROBE_GID"] = str(os.getuid()), str(os.getgid())
    checkout = Path(__file__).resolve().parents[1]
    helper = os.memfd_create("probe-landlock", os.MFD_CLOEXEC)
    os.write(helper, (checkout / "sandbox-landlock").read_bytes())
    seccomp = os.memfd_create("probe-seccomp", os.MFD_CLOEXEC)
    subprocess.run([sys.executable, "-I", str(checkout / "sandbox-seccomp")],
                   stdout=seccomp, check=True, env={"PATH": "/usr/bin:/bin"})
    namespace = access.allocate(f"sg-net-{os.getpid()}")
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    pasta = None
    pid = None
    try:
        sys.stdout.flush()
        pid = os.fork()
        if pid == 0:
            parent.close()
            try:
                listener.close()
                worker(namespace, child, public_ip, host_ip, host_port, helper, seccomp)
            except BaseException as error:
                print(f"network worker: {error}", file=sys.stderr, flush=True)
                os._exit(1)
            os._exit(0)
        child.close()
        parent.settimeout(20)
        ready = json.loads(parent.recv(4096))
        pasta = subprocess.Popen([
            "pasta", "--foreground", "--config-net", "--netns-only",
            "--netns", f"/proc/{ready['pid']}/ns/net", "--no-netns-quit",
            "-t", "none", "-u", "none", "-T", "none", "-U", "none",
            "--map-host-loopback", "none", "--map-guest-addr", "none",
            "--dns-forward", "169.254.1.1", "-4",
        ], preexec_fn=lambda: entered(namespace), env={"PATH": "/usr/bin:/bin"},
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        helper_status = Path(f"/proc/{pasta.pid}/status").read_text()
        helper_uid = int(next(line.split()[1] for line in helper_status.splitlines()
                              if line.startswith("Uid:")))
        probe.require(ready["base"] <= helper_uid < ready["base"] + 65536,
                      f"pasta has unexpected host UID {helper_uid}")
        print(json.dumps({"pasta_host_uid": helper_uid, "caller_uid": os.getuid()}), flush=True)
        parent.send(b"start")
        _, status = os.waitpid(pid, 0)
        pid = None
        probe.require(status == 0, f"network worker failed: wait status {status}")
    finally:
        parent.close()
        child.close()
        listener.close()
        if pid is not None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)
        if pasta is not None:
            pasta.terminate()
            try:
                pasta.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pasta.kill()
                pasta.wait()
        for fd in (namespace, helper, seccomp):
            os.close(fd)
    print("PASS: pasta as a managed UID, DNS/public egress, private/host prohibitions")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        sys.exit(f"systemd network probe: {error}")
