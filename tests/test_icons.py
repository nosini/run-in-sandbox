"""PE icon parsing and isolated local icon extraction."""
import importlib.machinery
import importlib.util
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    result = importlib.util.module_from_spec(spec)
    loader.exec_module(result)
    return result


icons = module("game_icons", ROOT / "sandbox-game-icon")
manager = module("icon_manager", ROOT / "sandbox-manager-lib.py")
def png_chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


PNG = (b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
       + png_chunk(b"IDAT", zlib.compress(b"\0\xff\0\0\xff")) + png_chunk(b"IEND", b""))


def png_header(width, height, rest=b""):
    return (b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
            + rest)


def ico(*images):
    """An .ico file holding these (width, data) images."""
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, payload = b"", b""
    for width, data in images:
        entries += struct.pack("<BBBBHHII", width % 256, width % 256, 0, 0, 1, 32, len(data), offset + len(payload))
        payload += data
    return header + entries + payload


try:
    import gi
    gi.require_version("GdkPixbuf", "2.0")
    from gi.repository import GdkPixbuf  # noqa: F401
    HAVE_PIXBUF = True
except (ImportError, ValueError):
    HAVE_PIXBUF = False


def executable():
    data = bytearray(0x600)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x86, 1)
    struct.pack_into("<H", data, 0x94, 224)
    struct.pack_into("<H", data, 0x98, 0x10B)
    struct.pack_into("<II", data, 0x98 + 96 + 16, 0x1000, 0x400)
    struct.pack_into("<IIII", data, 0x98 + 224 + 8, 0x400, 0x1000, 0x400, 0x200)
    def directory(offset, entries):
        struct.pack_into("<HH", data, 0x200 + offset + 12, 0, len(entries))
        for index, entry in enumerate(entries):
            struct.pack_into("<II", data, 0x200 + offset + 16 + index * 8, *entry)
    directory(0, [(3, 0x80000020), (14, 0x80000040)])
    directory(0x20, [(7, 0x80000060)])
    directory(0x40, [(1, 0x80000080)])
    directory(0x60, [(1033, 0xA0)])
    directory(0x80, [(1033, 0xB0)])
    group = struct.pack("<HHHBBBBHHIH", 0, 1, 1, 1, 1, 0, 0, 1, 32, len(PNG), 7)
    struct.pack_into("<IIII", data, 0x2A0, 0x10E0, len(PNG), 0, 0)
    struct.pack_into("<IIII", data, 0x2B0, 0x10C0, len(group), 0, 0)
    data[0x2C0:0x2C0 + len(group)] = group
    data[0x2E0:0x2E0 + len(PNG)] = PNG
    return data


class IconTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def extract(self, data):
        path = self.base / "input"
        path.write_bytes(data)
        with path.open("rb") as stream:
            kind, images = icons.extract(stream)
            return kind, list(images)

    def test_pe_group_icons_reference_image_resource_ids(self):
        kind, (data,) = self.extract(executable())
        self.assertEqual(kind, "ico")
        self.assertEqual(struct.unpack_from("<HHH", data), (0, 1, 1))
        self.assertEqual(data[22:], PNG)

    def test_truncated_and_out_of_bounds_resources_are_refused(self):
        for data in (b"MZ", b"not an icon", executable()[:0x250]):
            with self.subTest(size=len(data)), self.assertRaises((ValueError, struct.error)):
                self.extract(data)
        data = executable()
        struct.pack_into("<I", data, 0x2A0, 0xFFFFFFF0)
        self.assertEqual(self.extract(data), ("ico", []))

    def test_ico_images_are_offered_largest_first(self):
        kind, images = self.extract(ico((16, PNG), (0, png_header(256, 256)), (32, PNG)))
        self.assertEqual(kind, "ico")
        self.assertEqual([icons.dimensions(kind, data) for data in images], [(256, 256), (1, 1), (1, 1)])

    def helper(self, data):
        path = self.base / "input"
        path.write_bytes(data)
        with path.open("rb") as stream:
            return subprocess.run([sys.executable, "-I", str(ROOT / "sandbox-game-icon"), "-"], stdin=stream,
                                  capture_output=True, timeout=20)

    @unittest.skipUnless(HAVE_PIXBUF, "needs GdkPixbuf")
    def test_an_undecodable_large_frame_falls_back_to_a_smaller_one(self):
        broken = png_header(64, 64, png_chunk(b"IDAT", b"not zlib") + png_chunk(b"IEND", b""))
        result = self.helper(ico((64, broken), (1, PNG)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.startswith(b"\x89PNG\r\n\x1a\n"))

    @unittest.skipUnless(HAVE_PIXBUF, "needs GdkPixbuf")
    def test_oversized_and_missing_icons_are_refused_before_decoding(self):
        for data in (png_header(20000, 20000, png_chunk(b"IEND", b"")), b"not an icon",
                     ico((0, png_header(5000, 5000)))):
            with self.subTest(data=data[:24]):
                result = self.helper(data)
                self.assertEqual(result.returncode, icons.NO_ICON, result.stderr)
                self.assertEqual(result.stdout, b"")

    @unittest.skipUnless(os.environ.get("TEST_ICON_SANDBOX"), "needs bwrap and GdkPixbuf")
    def test_embedded_icon_is_decoded_in_isolation_and_cached_as_png(self):
        library = manager.Library(ROOT / "sandbox-game", ROOT, ROOT / "Sandbox game",
                                  home=self.base, config=self.base / "config")
        entry = library.create("Icon test")
        path = Path(entry["directory"]) / "play.exe"
        path.write_bytes(executable())
        icon = library.icon(entry)
        self.assertIsNotNone(icon)
        self.assertTrue(icon.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"))
        stamp = icon.stat().st_mtime_ns
        self.assertEqual(library.icon(entry), icon)
        self.assertEqual(icon.stat().st_mtime_ns, stamp)


if __name__ == "__main__":
    unittest.main()
