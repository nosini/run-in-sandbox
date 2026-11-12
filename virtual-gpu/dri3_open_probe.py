"""dri3_open_probe.py DISPLAY_SOCKET: ask the X server for a GPU descriptor.

DRI3Open makes the X server open its render node and pass the descriptor
over the connection. A sandbox that denies /dev/dri by path does not see
that: the descriptor was opened outside it. Prints what came back and
whether a DRM ioctl works on it.
"""
import fcntl
import os
import socket
import struct
import sys


def recv_exact(sock, n, fds):
    data = b""
    while len(data) < n:
        msg, anc, _, _ = sock.recvmsg(n - len(data), socket.CMSG_SPACE(4 * 4))
        if not msg:
            raise EOFError("X server closed the connection")
        for level, kind, payload in anc:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                fds.extend(struct.unpack(f"{len(payload) // 4}i", payload[:len(payload) // 4 * 4]))
        data += msg
    return data


def reply(sock, fds):
    while True:
        head = recv_exact(sock, 32, fds)
        if head[0] == 0:
            raise RuntimeError(f"X error {head[1]}")
        if head[0] == 1:
            extra = struct.unpack("=I", head[4:8])[0] * 4
            return head + recv_exact(sock, extra, fds)
        # an event: skip


def pad(b):
    return b + b"\0" * (-len(b) % 4)


def main():
    path = sys.argv[1]
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(path)
    sock.sendall(struct.pack("=BxHHHHxx", ord("l"), 11, 0, 0, 0))
    fds = []
    head = recv_exact(sock, 8, fds)
    if head[0] != 1:
        print(f"connection refused by the X server (status {head[0]})")
        return
    setup = recv_exact(sock, struct.unpack("=H", head[6:8])[0] * 4, fds)
    vendor_len, = struct.unpack("=H", setup[16:18])
    formats = setup[21]
    screen = 32 + vendor_len + (-vendor_len % 4) + 8 * formats
    root, = struct.unpack("=I", setup[screen:screen + 4])

    name = b"DRI3"
    sock.sendall(struct.pack("=BxHHxx", 98, 2 + len(pad(name)) // 4, len(name)) + pad(name))
    r = reply(sock, fds)
    if not r[8]:
        print("DRI3: not offered by this X server")
        return
    opcode = r[9]
    sock.sendall(struct.pack("=BBHII", opcode, 0, 3, 1, 2))  # QueryVersion 1.2
    reply(sock, fds)
    sock.sendall(struct.pack("=BBHII", opcode, 1, 3, root, 0))  # Open
    try:
        reply(sock, fds)
    except RuntimeError as e:
        print(f"DRI3Open refused: {e}")
        return
    if not fds:
        print("DRI3Open: reply without a descriptor")
        return
    fd = fds[0]
    target = os.readlink(f"/proc/self/fd/{fd}")
    buf = bytearray(64)
    try:
        fcntl.ioctl(fd, 0xC0406400, buf)  # DRM_IOCTL_VERSION
        name_len, = struct.unpack("=Q", buf[16:24])
        usable = f"DRM ioctls work on it (driver name length {name_len})"
    except OSError as e:
        usable = f"DRM ioctl refused: {e.strerror}"
    print(f"DRI3Open: got a descriptor for {target}; {usable}")


main()
