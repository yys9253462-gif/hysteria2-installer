"""Behavior tests for the Web/CLI portal update lock; no service commands run."""
import ast
import io
import os
from pathlib import Path
import re
import select
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import Mock, patch
from urllib.parse import parse_qs

try:
    import fcntl
except ImportError:
    fcntl = None

ROOT = Path(__file__).resolve().parents[1]
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))
NAMES = {'portal_update_process_lock', 'portal_update_restart_prefix', 'portal_start_update',
         '_h_post_do_upgrade', '_h_post_do_upgrade_impl'}
FUNCTIONS = [node for node in ast.walk(TREE)
             if isinstance(node, ast.FunctionDef) and node.name in NAMES]
BUNDLE = ('portal.py', 'portal_assets.py', 'usage-meter-core-20261007-v1.py',
          'usage-meter-readers-20261007-v1.py', 'usage-meter-runtime-20261007-v1.py',
          'usage-meter-xray-config-20261007-v1.py')
# Independent process uses the same flock protocol as install.sh, without importing portal.
PROBE = '''import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit(9)
os.close(fd)
'''
HOLDER = '''import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
print('ready', flush=True)
sys.stdin.buffer.read(1)
os.close(fd)
'''
CHILD = '''import os, sys
os.fstat(int(sys.argv[1]))
os.write(int(sys.argv[2]), b'R')
os.close(int(sys.argv[2]))
assert os.read(int(sys.argv[3]), 3) == b'go\\n'
os.close(int(sys.argv[3]))
sys.stdin.buffer.read(1)
'''


class PortalUpdateFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        for name in BUNDLE:
            (self.base / name).write_bytes(b'# old\n')
        self.lock_path = self.base / '.portal-update.lock'
        self.lock = threading.Lock()
        self.popen = Mock()
        self.fetch = Mock(return_value=b'# new\n')
        self.env = {
            'ast': ast, 'os': os, 'Path': Path, 'fcntl': fcntl, 'uuid': uuid, 'select': select,
            'parse_qs': parse_qs, 're': re, 'shutil': shutil,
            'PORTAL_SELF': self.base / 'portal.py',
            'portal_upgrade_lock': self.lock, 'data': {'port': 18080},
            'resolve_update_ref': lambda ref: 'a' * 40,
            '_remote_blob_sha': lambda *args, **kwargs: 'b' * 40,
            '_fetch_repo_file': self.fetch,
            '_log_ignored': lambda *args: None,
            'portal_update_restart_script': Mock(return_value='exit 0'),
            'subprocess': SimpleNamespace(Popen=self.popen, DEVNULL=subprocess.DEVNULL),
        }
        exec(compile(ast.Module(body=FUNCTIONS, type_ignores=[]), str(ROOT / 'portal.py'), 'exec'), self.env)
        class Handler:
            def is_authenticated(self): return True
            def reply_json(self, code, payload): return code, payload
            def _extend_deadline(self, seconds): pass
        Handler._h_post_do_upgrade = self.env['_h_post_do_upgrade']
        Handler._h_post_do_upgrade_impl = self.env['_h_post_do_upgrade_impl']
        self.Handler = Handler
        # Most tests isolate lock behavior from the host's service manager.
        self.restart_prefix = self.env['portal_update_restart_prefix']
        self.env['portal_update_restart_prefix'] = lambda: ['bash', '-c']
        self.popen.side_effect = self.ready_process

    def ready_process(self, command, **kwargs):
        if kwargs.get('pass_fds'):
            child = subprocess.Popen(command, **kwargs)
            self.addCleanup(lambda: child.wait(timeout=10))
            return child
        return SimpleNamespace(poll=lambda: None)

    def handler(self, body=b'target=portal'):
        handler = self.Handler()
        handler.headers = {'Content-Length': str(len(body))}
        handler.rfile = io.BytesIO(body)
        return handler

    def update(self):
        return self.handler()._h_post_do_upgrade('')

    def probe(self):
        result = subprocess.run([sys.executable, '-I', '-c', PROBE, str(self.lock_path)],
                                capture_output=True, timeout=10)
        self.assertIn(result.returncode, (0, 9), result.stderr.decode())
        return result.returncode

    def spawn(self, code, *args, wait_ready=True, **kwargs):
        child = subprocess.Popen([sys.executable, '-I', '-c', code, *map(str, args)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, **kwargs)
        def finish():
            if child.returncode is not None:
                return
            try:
                child.communicate(b'x', timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=10)
        self.addCleanup(finish)
        if wait_ready:
            self.assertEqual(child.stdout.readline(), b'ready\n')
        return child


@unittest.skipIf(fcntl is None, 'requires POSIX flock; run on Linux')
class PortalUpdateProcessLockTests(PortalUpdateFixture):
    def test_external_lock_rejects_handler_before_backup_or_write(self):
        self.spawn(HOLDER, self.lock_path)
        inode = self.lock_path.stat().st_ino
        status, payload = self.update()
        self.assertEqual(status, 409, payload)
        self.popen.assert_not_called()
        self.assertFalse(list(self.base.glob('*.bak')))
        self.assertFalse(list(self.base.glob('*.new')))
        for name in BUNDLE:
            self.assertEqual((self.base / name).read_bytes(), b'# old\n')
        self.assertEqual(self.lock_path.stat().st_ino, inode)

    def test_real_handler_hands_lock_to_child_until_child_exits(self):
        child = None
        passed_fd = None
        def launch(command, **kwargs):
            nonlocal child, passed_fd
            self.assertEqual(command[:2], ['bash', '-c'])
            self.assertTrue(kwargs['start_new_session'])
            self.assertEqual(len(kwargs['pass_fds']), 3)
            passed_fd = kwargs['pass_fds'][0]
            self.assertEqual(self.probe(), 9)
            child = self.spawn(CHILD, *kwargs['pass_fds'], pass_fds=kwargs['pass_fds'],
                               wait_ready=False, start_new_session=kwargs['start_new_session'])
            return child
        self.popen.side_effect = launch
        status, payload = self.update()
        self.assertEqual(status, 200, payload)
        self.assertIsNotNone(child)
        self.assertFalse(self.lock.locked())
        with self.assertRaises(OSError):
            os.fstat(passed_fd)  # parent closed its copy, without LOCK_UN
        inode = self.lock_path.stat().st_ino
        self.assertEqual(self.probe(), 9)
        self.assertEqual(self.update()[0], 409)  # fresh handler/thread lock is free
        child.communicate(b'x', timeout=10)
        self.assertEqual(child.returncode, 0)
        self.assertEqual(self.probe(), 0)
        self.assertEqual(self.lock_path.stat().st_ino, inode)

    def test_lock_covers_download_backup_write_and_script_generation(self):
        self.fetch.side_effect = lambda *args, **kwargs: (self.assertEqual(self.probe(), 9) or b'# new\n')
        original_copy = shutil.copy2
        def copy(*args, **kwargs):
            self.assertEqual(self.probe(), 9)
            return original_copy(*args, **kwargs)
        original_replace = os.replace
        def replace(*args, **kwargs):
            self.assertEqual(self.probe(), 9)
            return original_replace(*args, **kwargs)
        self.env['portal_update_restart_script'].side_effect = lambda *args: (self.assertEqual(self.probe(), 9) or 'exit 0')
        with patch.object(shutil, 'copy2', side_effect=copy), patch.object(os, 'replace', side_effect=replace):
            self.assertEqual(self.update()[0], 200)
        self.assertEqual(self.probe(), 0)

    def test_systemd_handler_passes_fd_to_independent_scope_command(self):
        self.env['portal_update_restart_prefix'] = self.restart_prefix
        child = None
        def launch(command, **kwargs):
            nonlocal child
            self.assertEqual(command[:3], ['/stub/systemd-run', '--scope', '--quiet'])
            self.assertTrue(command[3].startswith('--unit=hysteria-portal-update-'))
            self.assertEqual(command[4:6], ['bash', '-c'])
            child = self.spawn(CHILD, *kwargs['pass_fds'], pass_fds=kwargs['pass_fds'], wait_ready=False)
            return child
        self.popen.side_effect = launch
        with patch.object(Path, 'is_dir', return_value=True), \
             patch.object(shutil, 'which', return_value='/stub/systemd-run'):
            self.assertEqual(self.update()[0], 200)
        self.assertEqual(self.probe(), 9)
        child.communicate(b'x', timeout=10)
        self.assertEqual(self.probe(), 0)

    def test_systemd_without_runner_fails_before_download_or_write(self):
        self.env['portal_update_restart_prefix'] = self.restart_prefix
        with patch.object(Path, 'is_dir', return_value=True), \
             patch.object(shutil, 'which', return_value=None):
            status, payload = self.update()
        self.assertEqual(status, 500, payload)
        self.fetch.assert_not_called()
        self.popen.assert_not_called()
        self.assertFalse(list(self.base.glob('*.bak')))
        self.assertEqual(self.probe(), 0)

    def test_download_failure_releases_lock(self):
        self.fetch.side_effect = OSError('download failed')
        self.assertEqual(self.update()[0], 500)
        self.assertEqual(self.probe(), 0)
        self.assertFalse(self.lock.locked())

    def test_write_failure_rolls_back_under_lock_then_releases(self):
        original_copy = shutil.copy2
        def copy(*args, **kwargs):
            self.assertEqual(self.probe(), 9)
            return original_copy(*args, **kwargs)
        with patch.object(os, 'replace', side_effect=OSError('replace failed')), \
             patch.object(shutil, 'copy2', side_effect=copy):
            self.assertEqual(self.update()[0], 500)
        self.assertEqual((self.base / 'portal.py').read_bytes(), b'# old\n')
        self.assertEqual(self.probe(), 0)
        self.popen.assert_not_called()

    def assert_original_bundle(self):
        for name in BUNDLE:
            self.assertEqual((self.base / name).read_bytes(), b'# old\n')

    def test_spawn_failure_releases_lock_and_restores_bundle(self):
        self.popen.side_effect = OSError('spawn failed')
        self.assertEqual(self.update()[0], 500)
        self.assert_original_bundle()
        self.assertEqual(self.probe(), 0)
        self.assertFalse(self.lock.locked())

    def test_scope_early_exit_restores_bundle_and_removes_created_files(self):
        (self.base / BUNDLE[-1]).unlink()
        def launch(command, **kwargs):
            child = subprocess.Popen([sys.executable, '-I', '-c', 'raise SystemExit(3)'],
                                     pass_fds=kwargs['pass_fds'])
            self.addCleanup(lambda: child.wait(timeout=10))
            return child
        self.popen.side_effect = launch
        self.assertEqual(self.update()[0], 500)
        for name in BUNDLE[:-1]:
            self.assertEqual((self.base / name).read_bytes(), b'# old\n')
        self.assertFalse((self.base / BUNDLE[-1]).exists())
        self.assertEqual(self.probe(), 0)

    def test_handshake_timeout_restores_bundle_and_closes_gate(self):
        inherited = []
        def launch(command, **kwargs):
            inherited.extend(kwargs['pass_fds'])
            return SimpleNamespace(terminate=lambda: None, wait=lambda **kw: 0)
        self.popen.side_effect = launch
        with patch.object(select, 'select', return_value=([], [], [])):
            self.assertEqual(self.update()[0], 500)
        self.assert_original_bundle()
        for fd in inherited:
            with self.assertRaises(OSError):
                os.fstat(fd)
        self.assertEqual(self.probe(), 0)

    def test_real_bash_handshake_executes_only_after_go_with_high_fds(self):
        # Threaded HTTP servers may have dozens of connections open already.
        reserved = [os.open(os.devnull, os.O_RDONLY) for _ in range(24)]
        self.addCleanup(lambda: [os.close(fd) for fd in reserved])
        marker = self.base / 'script-ran'
        script = 'printf done > ' + shlex.quote(str(marker))
        self.env['portal_update_restart_script'].return_value = script
        children = []
        def launch(command, **kwargs):
            child = subprocess.Popen(command, **kwargs)
            children.append(child)
            self.addCleanup(lambda: child.wait(timeout=10))
            return child
        self.popen.side_effect = launch
        self.assertEqual(self.update()[0], 200)
        children[0].wait(timeout=10)
        self.assertEqual(children[0].returncode, 0)
        self.assertEqual(marker.read_text(), 'done')
        self.assertEqual(self.probe(), 0)

    def test_missing_go_never_executes_script(self):
        marker = self.base / 'must-not-run'
        def launch(command, **kwargs):
            child = subprocess.Popen(command, **kwargs)
            self.addCleanup(lambda: child.wait(timeout=10))
            return child
        self.popen.side_effect = launch
        self.env['portal_update_restart_script'].return_value = 'touch ' + shlex.quote(str(marker))
        # Child really reaches ready, but parent fails before sending go.
        with patch.object(os, 'write', side_effect=OSError('go delivery failed')):
            self.assertEqual(self.update()[0], 500)
        self.assertFalse(marker.exists())
        self.assert_original_bundle()
        self.assertEqual(self.probe(), 0)

    def test_unchanged_bundle_releases_without_spawning(self):
        self.fetch.return_value = b'# old\n'
        self.assertEqual(self.update()[0], 200)
        self.popen.assert_not_called()
        self.assertTrue(self.lock_path.exists())
        self.assertEqual(self.probe(), 0)

    def test_failed_acquisition_closes_its_fd(self):
        acquire = self.env['portal_update_process_lock']
        original_open = os.open
        opened = []
        def open_(*args, **kwargs):
            fd = original_open(*args, **kwargs)
            opened.append(fd)
            return fd
        for error in (BlockingIOError('busy'), OSError('flock failed')):
            with self.subTest(error=type(error).__name__), \
                 patch.object(os, 'open', side_effect=open_), \
                 patch.object(fcntl, 'flock', side_effect=error):
                with self.assertRaises(type(error)):
                    acquire(self.base)
            with self.assertRaises(OSError):
                os.fstat(opened[-1])


class PortalUpdateCompatibilityTests(PortalUpdateFixture):
    def test_no_fcntl_keeps_development_handler_usable(self):
        self.env['fcntl'] = None
        self.assertEqual(self.update()[0], 200)
        self.assertEqual(self.popen.call_args.kwargs.get('pass_fds', ()), ())
        self.assertFalse(self.lock.locked())

    def test_unauthenticated_request_has_no_lock_or_writes(self):
        handler = self.handler()
        handler.is_authenticated = lambda: False
        self.assertEqual(handler._h_post_do_upgrade('')[0], 401)
        self.assertFalse(self.lock_path.exists())
        self.fetch.assert_not_called()

    def test_existing_thread_contention_still_returns_conflict(self):
        self.lock.acquire()
        try:
            self.assertEqual(self.update()[0], 409)
        finally:
            self.lock.release()
        self.assertFalse(self.lock_path.exists())

    def test_invalid_target_does_not_open_lock(self):
        self.assertEqual(self.handler(b'target=invalid')._h_post_do_upgrade('')[0], 400)
        self.assertFalse(self.lock_path.exists())


if __name__ == '__main__':
    unittest.main()
