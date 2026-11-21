"""回归测试：GOST 面板安装暂存清理、启动自检原子写入与回滚免疫 ETXTBSY 及 systemctl 异常。"""

import ast
import os
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
TREE = ast.parse(SRC)


def _extract_fn(name: str):
    for node in ast.walk(TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f'portal.py 中未找到函数 {name}')


def _compile_restore_gost_assets():
    fn_node = _extract_fn('restore_gost_assets')
    body = [stmt for stmt in fn_node.body if not isinstance(stmt, ast.Nonlocal)]
    wrapper = ast.FunctionDef(
        name='restore_gost_assets',
        args=fn_node.args,
        body=body,
        decorator_list=[],
        returns=None,
    )
    mod = ast.Module(body=[wrapper], type_ignores=[])
    ast.fix_missing_locations(mod)
    return compile(mod, str(ROOT / 'portal.py'), 'exec')


def _compile_write_gost_selfcheck():
    fn_node = _extract_fn('write_gost_selfcheck')
    mod = ast.Module(body=[fn_node], type_ignores=[])
    ast.fix_missing_locations(mod)
    return compile(mod, str(ROOT / 'portal.py'), 'exec')


class GostAtomicInstallAndRollbackTests(unittest.TestCase):
    def test_restore_gost_assets_avoids_direct_write_bytes_etxtbsy(self):
        """回滚正在运行的 gost 二进制与敏感配置时必须走同目录原子替换，不能直接 write_bytes。"""
        code = _compile_restore_gost_assets()
        calls = []

        def fake_run(args, **kwargs):
            calls.append(list(args))
            return SimpleNamespace(returncode=0, stdout='', stderr='')

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            gost_binary = root / 'gost'
            gost_binary.write_bytes(b'broken-new-bin')
            gost_cfg = root / 'gost.yml'
            gost_cfg.write_bytes(b'broken-cfg')
            cert_dir = root / 'cert'
            old_assets = {
                gost_binary: (b'old-good-bin', 0o755),
                gost_cfg: (b'old-secret-cfg', 0o600),
            }
            ns = {
                'assets_modified': False,
                'old_assets': old_assets,
                'gost_binary': gost_binary,
                'had_cert_dir': True,
                'cert_dir': cert_dir,
                'data_lock': threading.RLock(),
                'had_proxy_services': False,
                'previous_proxy_services': [],
                'data': {},
                'old_gost_active': True,
                'old_gost_enabled': True,
                'os': os,
                'subprocess': SimpleNamespace(run=fake_run),
            }
            exec(code, ns)
            with mock.patch.object(Path, 'write_bytes', side_effect=OSError(26, 'Text file busy')):
                ns['restore_gost_assets']()

            self.assertEqual(gost_binary.read_bytes(), b'old-good-bin')
            self.assertEqual(gost_cfg.read_bytes(), b'old-secret-cfg')
            # 不得遗留临时文件
            self.assertEqual(sorted(p.name for p in root.iterdir()), ['gost', 'gost.yml'])

    def test_restore_gost_assets_isolates_systemctl_timeout(self):
        """daemon-reload 超时或异常不得阻断后续恢复 enable 与 restart 步骤。"""
        code = _compile_restore_gost_assets()
        calls = []

        def flaky_run(args, **kwargs):
            calls.append(list(args))
            if args == ['systemctl', 'daemon-reload']:
                raise subprocess.TimeoutExpired(args, kwargs.get('timeout', 30))
            return SimpleNamespace(returncode=0, stdout='', stderr='')

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            gost_binary = root / 'gost'
            ns = {
                'assets_modified': False,
                'old_assets': {gost_binary: (b'old-bin', 0o755)},
                'gost_binary': gost_binary,
                'had_cert_dir': True,
                'cert_dir': root / 'cert',
                'data_lock': threading.RLock(),
                'had_proxy_services': False,
                'previous_proxy_services': [],
                'data': {},
                'old_gost_active': True,
                'old_gost_enabled': True,
                'os': os,
                'subprocess': SimpleNamespace(run=flaky_run),
            }
            exec(code, ns)
            ns['restore_gost_assets']()

        self.assertIn(['systemctl', 'daemon-reload'], calls)
        self.assertIn(['systemctl', 'enable', 'gost'], calls)
        self.assertIn(['systemctl', 'reset-failed', 'gost'], calls)
        self.assertIn(['systemctl', 'restart', 'gost'], calls)

    def test_write_gost_selfcheck_is_atomic_and_cleans_temp_on_error(self):
        """write_gost_selfcheck 必须原子写盘，不得直接覆盖目标文件。"""
        code = _compile_write_gost_selfcheck()
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / 'hy2-gost-selfcheck'
            target.write_text('#!/bin/sh\necho old\n', encoding='utf-8')
            ns = {
                'GOST_SELFCHECK_PATH': target,
                'GOST_SELFCHECK_SCRIPT': '#!/bin/sh\necho new\n',
                'os': os,
                '_log_ignored': lambda *a, **k: None,
            }
            exec(code, ns)
            with mock.patch.object(Path, 'write_text', side_effect=AssertionError('不得直接 write_text 覆写目标')):
                ok = ns['write_gost_selfcheck']()
            self.assertTrue(ok)
            self.assertEqual(target.read_text(encoding='utf-8'), '#!/bin/sh\necho new\n')
            self.assertEqual([p.name for p in Path(td).iterdir()], ['hy2-gost-selfcheck'])

    def test_install_gost_uses_random_staging_name_with_cleanup(self):
        """GOST 安装暂存二进制必须带随机后缀并在失败路径清理。"""
        start = SRC.index('        def _h_post_install_gost(self, prefix):')
        end = SRC.index('        def _h_post_install_amneziawg(self, prefix):', start)
        body = SRC[start:end]
        self.assertNotIn("Path('/usr/local/bin/gost.new')", body)
        self.assertIn("Path('/usr/local/bin/gost.new.%s'", body)
        self.assertIn('finally:', body)


if __name__ == '__main__':
    unittest.main()
