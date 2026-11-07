"""Availability gates and administrator setup preflight, without root/services."""
import importlib.machinery
import importlib.util
import hashlib
from pathlib import Path
import sys
import tempfile
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
    def availability(self, first='261.4 (261.4)', second='261.4 (261.4)', mount=True):
        def reply(path, method, params):
            if method.endswith('.GetInfo'):
                return {'version': first if path == uid.NSRESOURCE else second}, []
            return {'description': 'MountDirectory' if mount else 'old interface'}, []
        with mock.patch.object(uid, 'varlink', side_effect=reply):
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
        with mock.patch.object(uid, 'varlink', side_effect=uid.VarlinkError('permission denied')):
            self.assertIn('permission denied', uid.managed_available())


class AdministratorPreflightTests(unittest.TestCase):
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
