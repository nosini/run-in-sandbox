#!/usr/bin/env -S python3 -I
"""Root-only lifecycle/adversarial tests, intended for an isolated test VM."""
import importlib.util
from importlib.machinery import SourceFileLoader
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import traceback
import unittest

sys.dont_write_bytecode = True
loader = SourceFileLoader("render_helper", str(Path(__file__).with_name("systemd-render-devices")))
spec = importlib.util.spec_from_loader(loader.name, loader)
helper = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = helper
loader.exec_module(helper)

UID = 1000


@unittest.skipUnless(os.geteuid() == 0, "requires root in the test VM for synthetic device inodes")
class RenderLifecycle(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sandbox-render-test-", dir="/var/lib")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.paths = helper.Paths(self.root / "etc/users", self.root / "state",
                                  self.root / "sys", self.root / "dev/dri")
        for directory in (self.paths.config.parent, self.paths.devices,
                          self.paths.sysfs / "class/drm", self.paths.sysfs / "dev/char"):
            directory.mkdir(parents=True, exist_ok=True)
        self.paths.config.write_text(f"{UID}\n")
        self.source = self.paths.devices / "renderD128"
        os.mknod(self.source, stat.S_IFCHR | 0o600, os.makedev(226, 128))
        self.sysdev = self.make_sysdev("gpu0")
        self.alias = self.paths.state / str(UID) / "renderD128"
        self.private = self.paths.state / ".objects" / f"{UID}-renderD128"

    def make_sysdev(self, gpu):
        directory = self.paths.sysfs / "devices" / gpu / "drm/renderD128"
        directory.mkdir(parents=True)
        (directory / "dev").write_text("226:128\n")
        (directory / "subsystem").symlink_to(self.paths.sysfs / "class/drm")
        for link in (self.paths.sysfs / "class/drm/renderD128",
                     self.paths.sysfs / "dev/char/226:128"):
            link.unlink(missing_ok=True)
            link.symlink_to(directory)
        return directory

    def reconcile(self, **kwargs):
        kwargs.setdefault("activation", "enable")
        helper.reconcile(self.paths, **kwargs)

    def held(self):
        fd = os.open(self.alias, helper.PATH_ONLY)
        self.addCleanup(os.close, fd)
        return fd

    def revoked(self, fd):
        st = os.fstat(fd)
        self.assertEqual((st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)), (0, 0, 0))

    def assert_private_identity(self):
        self.assertTrue(helper.same_inode(self.private.stat(), self.alias.stat()))
        self.assertEqual(stat.S_IMODE(self.private.parent.stat().st_mode), 0o700)
        self.assertEqual(self.private.parent.stat().st_uid, 0)

    def test_create_and_repeat_preserve_real_device_and_alias_identity(self):
        source_before = self.source.stat()
        self.reconcile()
        alias_before = self.alias.stat()
        self.assertEqual((alias_before.st_uid, alias_before.st_gid), (UID, UID))
        self.assertEqual(stat.S_IMODE(alias_before.st_mode), 0o600)
        self.assertEqual(alias_before.st_rdev, source_before.st_rdev)
        self.assert_private_identity()
        self.reconcile()
        self.assertTrue(helper.same_inode(alias_before, self.alias.stat()))
        self.assertEqual(self.source.stat(), source_before)

    def test_remove_revokes_held_inode_and_moved_hardlink(self):
        self.reconcile()
        old = self.held()
        held = self.alias.with_name("moved-by-user")
        os.link(self.alias, held)
        directory = os.open(self.alias.parent, helper.DIRECTORY)
        self.addCleanup(os.close, directory)
        (self.paths.sysfs / "class/drm/renderD128").unlink()
        self.reconcile()
        self.revoked(old)
        self.assertEqual(held.stat().st_uid, 0)
        self.assertFalse(self.alias.exists())
        # Open relative to a held caller-owned directory FD, so an unrelated
        # 0700 ancestor cannot create a false-positive permissions denial.
        pid = os.fork()
        if pid == 0:
            os.setgroups([])
            os.setresgid(UID, UID, UID)
            os.setresuid(UID, UID, UID)
            try:
                fd = os.open("moved-by-user", os.O_RDWR, dir_fd=directory)
                os.close(fd)
            except PermissionError:
                os._exit(0)
            os._exit(1)
        self.assertEqual(os.waitpid(pid, 0)[1], 0)

    def test_delayed_remove_for_same_live_path_replaces_alias_and_revokes_old(self):
        self.reconcile()
        old = self.held()
        removed = helper.device(self.paths, "renderD128")["sys_path"]
        self.reconcile(removed=removed)
        self.revoked(old)
        self.assertNotEqual(os.fstat(old).st_ino, self.alias.stat().st_ino)
        self.assert_private_identity()

    def test_reused_minor_with_new_sysfs_device_gets_a_fresh_inode(self):
        self.reconcile()
        old = self.held()
        old_path = helper.device(self.paths, "renderD128")["sys_path"]
        self.make_sysdev("gpu1")
        self.reconcile()
        self.revoked(old)
        inode = self.alias.stat().st_ino
        # An old remove event must not erase the currently live new device.
        self.reconcile(removed=old_path)
        self.assertEqual(self.alias.stat().st_ino, inode)
        self.assert_private_identity()

    def test_mismatched_sysfs_number_withholds_and_revokes_alias(self):
        self.reconcile()
        old = self.held()
        (self.sysdev / "dev").write_text("226:0\n")
        self.reconcile()
        self.revoked(old)
        self.assertFalse(self.alias.exists())

    def test_primary_device_cannot_be_smuggled_under_a_render_name(self):
        self.source.unlink()
        os.mknod(self.source, stat.S_IFCHR | 0o600, os.makedev(226, 0))
        self.reconcile()
        self.assertFalse(self.alias.exists())

    def test_user_symlink_is_never_followed_when_publishing_or_retiring(self):
        victim = self.root / "victim"
        victim.write_text("must stay unchanged")
        victim.chmod(0o640)
        before = victim.stat()
        self.reconcile()
        old = self.held()
        self.alias.unlink()
        self.alias.symlink_to(victim)
        self.reconcile()
        self.assert_private_identity()
        self.assertEqual(victim.stat(), before)
        self.alias.unlink()
        self.alias.symlink_to(victim)
        (self.paths.sysfs / "class/drm/renderD128").unlink()
        self.reconcile()
        self.revoked(old)
        self.assertEqual(victim.stat(), before)

    def test_revoking_user_does_not_recurse_into_unexpected_user_contents(self):
        self.reconcile()
        old = self.held()
        private_data = self.alias.with_name("my-file")
        private_data.write_text("do not change")
        os.chown(private_data, UID, UID)
        before = private_data.stat()
        self.paths.config.write_text("")
        self.reconcile()
        self.revoked(old)
        directory = self.alias.parent.stat()
        self.assertEqual((directory.st_uid, stat.S_IMODE(directory.st_mode)), (0, 0))
        self.assertEqual(private_data.stat(), before)
        self.assertEqual(private_data.read_text(), "do not change")

    def test_absent_config_revokes_previous_grants(self):
        self.reconcile()
        old = self.held()
        self.paths.config.unlink()
        self.reconcile()
        self.revoked(old)
        self.assertFalse(self.alias.exists())

    def test_missing_drm_class_is_an_empty_inventory(self):
        self.reconcile()
        old = self.held()
        shutil.rmtree(self.paths.sysfs / "class/drm")
        self.reconcile()
        self.revoked(old)

    def test_world_writable_config_is_rejected(self):
        self.paths.config.chmod(0o666)
        with self.assertRaises(RuntimeError):
            self.reconcile()
        self.assertFalse(self.alias.exists())

    def test_configuration_and_source_symlinks_are_rejected(self):
        original = self.paths.config.with_name("real-users")
        self.paths.config.rename(original)
        self.paths.config.symlink_to(original)
        with self.assertRaises(OSError):
            self.reconcile()
        self.paths.config.unlink()
        original.rename(self.paths.config)
        moved = self.source.with_name("actual-device")
        self.source.rename(moved)
        self.source.symlink_to(moved)
        self.reconcile()
        self.assertFalse(self.alias.exists())

    def test_user_directory_symlink_is_not_followed(self):
        self.paths.state.mkdir()
        victim = self.root / "untouched"
        victim.mkdir(mode=0o700)
        before = victim.stat()
        (self.paths.state / str(UID)).symlink_to(victim)
        with self.assertRaises(OSError):
            self.reconcile()
        self.assertEqual(victim.stat(), before)

    def test_root_and_non_numeric_configurations_are_rejected(self):
        for value in ("0", "-1", "alice", "4294967295"):
            with self.subTest(value=value):
                self.paths.config.write_text(value)
                with self.assertRaises(RuntimeError):
                    self.reconcile()

    def test_multiple_users_get_distinct_revocable_inodes(self):
        self.paths.config.write_text(f"{UID}\n{UID+1}\n")
        self.reconcile()
        other = self.paths.state / str(UID + 1) / "renderD128"
        fd = os.open(other, helper.PATH_ONLY)
        self.addCleanup(os.close, fd)
        self.assertNotEqual(other.stat().st_ino, self.alias.stat().st_ino)
        self.paths.config.write_text(f"{UID}\n")
        self.reconcile()
        self.revoked(fd)
        self.assertEqual(self.alias.stat().st_uid, UID)

    def test_parallel_events_leave_one_consistent_alias(self):
        children = []
        for _ in range(3):
            pid = os.fork()
            if pid == 0:
                try:
                    for _ in range(3):
                        self.reconcile()
                except BaseException:
                    traceback.print_exc()
                    os._exit(1)
                os._exit(0)
            children.append(pid)
        statuses = [os.waitpid(pid, 0)[1] for pid in children]
        self.assertEqual(statuses, [0] * len(children))
        self.assert_private_identity()
        self.assertFalse(any(name.startswith(".publish-")
                             for name in os.listdir(self.private.parent)))

    def test_incomplete_creation_is_retired_and_rebuilt(self):
        self.reconcile()
        old = self.held()
        self.private.with_name(self.private.name + ".json").unlink()
        self.reconcile()
        self.revoked(old)
        self.assertNotEqual(os.fstat(old).st_ino, self.alias.stat().st_ino)
        self.assert_private_identity()

    def test_orphan_metadata_does_not_prevent_recreation(self):
        self.reconcile()
        old = self.held()
        # Simulate interruption after an old object's removal but before its
        # metadata was unlinked. No reference to the old inode is reauthorized.
        fd = os.open(self.private, helper.PATH_ONLY)
        try:
            helper.inode_permissions(fd, 0, 0)
        finally:
            os.close(fd)
        self.alias.unlink()
        self.private.unlink()
        self.reconcile()
        self.revoked(old)
        self.assert_private_identity()

    def test_interrupted_publication_temporary_is_collected(self):
        self.reconcile()
        abandoned = self.private.with_name(".publish-" + "0" * 32)
        os.link(self.private, abandoned)
        self.reconcile()
        self.assertFalse(abandoned.exists())
        self.assert_private_identity()

    def test_stop_disables_queued_events_until_explicit_restart(self):
        self.reconcile()
        old = self.held()
        helper.reconcile(self.paths, activation="disable")
        self.revoked(old)
        helper.reconcile(self.paths)
        self.assertFalse(self.alias.exists())
        helper.reconcile(self.paths, activation="enable")
        self.assert_private_identity()
        self.assertNotEqual(os.fstat(old).st_ino, self.alias.stat().st_ino)

    def test_disable_does_not_need_valid_config_or_a_device_inventory(self):
        self.reconcile()
        old = self.held()
        self.paths.config.write_text("invalid configuration")
        shutil.rmtree(self.paths.sysfs)
        helper.reconcile(self.paths, activation="disable")
        self.revoked(old)
        self.assertFalse(self.alias.exists())


if __name__ == "__main__":
    unittest.main()
