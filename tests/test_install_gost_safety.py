"""回归测试：_h_post_install_gost 的 tag 校验、tar 链接成员拦截、原子写盘刷盘与回滚不早退。"""

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


class InstallGostSafetyTests(unittest.TestCase):
    def _gost_body(self) -> str:
        start = SRC.index('        def _h_post_install_gost(self, prefix):')
        end = SRC.index('        def _h_post_install_amneziawg(self, prefix):', start)
        return SRC[start:end]

    def test_install_gost_hardening_guards_present(self):
        body = self._gost_body()
        self.assertNotIn("Path('/etc/systemd/system/gost.service').write_text(", body,
                         'gost.service 必须原子写盘，不得直接 write_text 覆写')
        self.assertIn('_atomic_write_text(', body, 'gost.service 应通过 _atomic_write_text 原子落盘')
        self.assertIn('issym()', body, '解压 gost 归档前必须拦截符号链接/硬链接成员')
        self.assertIn('os.fsync(', body, '替换 gost 二进制与回滚写盘前必须 fsync 刷盘')
        self.assertIn("re.fullmatch(r'v?[0-9A-Za-z][0-9A-Za-z._-]{0,63}'", body,
                      '远程 tag_name 必须经安全版本格式校验')

    def test_restore_gost_assets_continues_remaining_assets_and_service_after_single_failure(self):
        """单个资产回滚失败时，仍须继续恢复其余资产、内存状态与 systemd 服务，再上报错误。"""
        code = _compile_restore_gost_assets()
        calls = []

        def fake_run(args, **kwargs):
            calls.append(list(args))
            return SimpleNamespace(returncode=0, stdout='', stderr='')

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bad_asset = root / 'a_bad_file'
            good_asset = root / 'b_good_file'
            gost_binary = root / 'gost'
            good_asset.write_bytes(b'broken-new')
            gost_binary.write_bytes(b'broken-bin')
            data = {'proxy_services': [{'port': 9999}]}
            old_assets = {
                bad_asset: (b'old-a', 0o600),
                good_asset: (b'old-b', 0o600),
                gost_binary: (b'old-bin', 0o755),
            }
            ns = {
                'assets_modified': False,
                'old_assets': old_assets,
                'gost_binary': gost_binary,
                'had_cert_dir': True,
                'cert_dir': root / 'cert',
                'data_lock': threading.RLock(),
                'had_proxy_services': True,
                'previous_proxy_services': [{'port': 8080}],
                'data': data,
                'old_gost_active': True,
                'old_gost_enabled': True,
                'os': os,
                'subprocess': SimpleNamespace(run=fake_run),
            }
            exec(code, ns)

            real_replace = os.replace

            def flaky_replace(src, dst):
                if Path(dst) == bad_asset:
                    raise OSError('模拟单个文件替换失败')
                return real_replace(src, dst)

            with mock.patch.object(os, 'replace', side_effect=flaky_replace):
                with self.assertRaises(OSError):
                    ns['restore_gost_assets']()

            # 即使首个资产失败，其余资产、内存数据与 systemd 恢复均已完成
            self.assertEqual(good_asset.read_bytes(), b'old-b')
            self.assertEqual(gost_binary.read_bytes(), b'old-bin')
            self.assertEqual(data['proxy_services'], [{'port': 8080}])
            self.assertIn(['systemctl', 'restart', 'gost'], calls)


if __name__ == '__main__':
    unittest.main()
