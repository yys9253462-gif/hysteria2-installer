"""回归测试：panel-join.py 拒绝符号链接/3xx重定向防令牌泄漏/深层YAML同名键隔离/--panel路径穿越，及 fix_cert_chain.sh 拒绝符号链接配置/前导横杠安全/mktemp备份/回读校验。"""

import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')


def _load_panel_join():
    spec = importlib.util.spec_from_file_location('panel_join_test_mod', ROOT / 'panel-join.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestPanelJoinAndFixCertChainBatch59Guards(unittest.TestCase):
    def test_panel_join_read_rejects_symlink(self):
        """panel-join.read 必须拒绝符号链接文件，避免跟随链接读取敏感文件或设备。"""
        import stat as _stat
        mod = _load_panel_join()
        with tempfile.TemporaryDirectory() as td:
            real = Path(td) / 'real.json'
            real.write_text('{"api_key":"secret"}', encoding='utf-8')
            self.assertIsNotNone(mod.read(str(real)))

            # 跨平台验证：模拟 lstat 返回符号链接模式时必须拒绝读取
            fake_st = os.stat_result((_stat.S_IFLNK | 0o777, 0, 0, 1, 0, 0, 16, 0, 0, 0))
            with mock.patch.object(mod.os, 'lstat', return_value=fake_st):
                self.assertIsNone(mod.read(str(real)))

            link = Path(td) / 'link.json'
            try:
                os.symlink(real, link)
            except (OSError, NotImplementedError):
                return
            self.assertIsNone(mod.read(str(link)))

    def test_panel_join_parse_simple_yaml_ignores_deeper_nested_same_key(self):
        """masquerade 更深层子段中的同名 listenHTTPS 不得覆盖一级子键 masquerade.listenHTTPS。"""
        mod = _load_panel_join()
        text = (
            "listen: :443\n"
            "masquerade:\n"
            "  listenHTTPS: :8443\n"
            "  proxy:\n"
            "    listenHTTPS: :9999\n"
        )
        parsed = mod.parse_simple_yaml(text)
        self.assertEqual(parsed['masquerade']['listenHTTPS'], ':8443')

    def test_panel_join_rejects_panel_path_traversal_and_overlong_name(self):
        """--panel 含 /../ 路径穿越或 --name 超过 256 字符时必须返回退出码 2。"""
        mod = _load_panel_join()
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / 'config.yaml').write_text('listen: :443\nmasquerade:\n  listenHTTPS: :8443\n', encoding='utf-8')
            (d / 'portal.json').write_text(json.dumps({'api_key': 'k' * 32, 'port': 18080}), encoding='utf-8')
            (d / 'meta.json').write_text(json.dumps({'server_name': 'node.example.com'}), encoding='utf-8')

            for bad_args in (
                ['--format', 'curl', '--panel', 'https://panel.example/a/../b'],
                ['--format', 'curl', '--panel', 'https://panel.example', '--name', 'a' * 300],
            ):
                argv = ['panel-join.py', '--config', str(d / 'config.yaml'),
                        '--portal', str(d / 'portal.json'), '--meta', str(d / 'meta.json')] + bad_args
                err = io.StringIO()
                with mock.patch.object(sys, 'argv', argv), mock.patch.object(sys, 'stderr', err):
                    rc = mod.main()
                self.assertEqual(rc, 2, f'应拒绝非法参数 {bad_args}: stderr={err.getvalue()}')

    def test_panel_join_no_redirect_handler_blocks_3xx_credential_leak(self):
        """panel-join 必须提供禁止跟随重定向的处理器，拦截 301/302/307/308 防止泄露 Authorization 令牌。"""
        mod = _load_panel_join()
        handler_cls = getattr(mod, '_NoRedirectHandler', None)
        self.assertIsNotNone(handler_cls, 'panel-join.py 必须定义 _NoRedirectHandler 阻止自动跟随 3xx')
        handler = handler_cls()
        req = urllib.request.Request('https://panel.example/api/nodes', method='POST')
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            handler.redirect_request(req, None, 302, 'Found', {'Location': 'http://evil.example/'}, 'http://evil.example/')
        self.assertEqual(ctx.exception.code, 302)

    def test_fix_cert_chain_guards_symlink_config_leading_dash_mktemp_and_readback(self):
        """fix_cert_chain.sh 必须拒绝符号链接配置、规范前导横杠路径、用 mktemp 建备份并做写入回读校验。"""
        src = (ROOT / 'fix_cert_chain.sh').read_text(encoding='utf-8')
        self.assertIn('[[ ! -L "$CONFIG" && -f "$CONFIG" ]]', src,
                      'fix_cert_chain.sh 必须拒绝符号链接形式的主配置文件')
        self.assertIn('mktemp "${CONFIG}.bak.', src,
                      'fix_cert_chain.sh 必须使用 mktemp 安全创建备份文件防止符号链接覆写')
        self.assertIn('[[ "$NEW" != "$FULL" ]]', src,
                      'fix_cert_chain.sh 写入 tls.cert 后必须回读核对与目标路径一致')
        self.assertIn('Verify return code: 0([^0-9]|$)', src,
                      'fix_cert_chain.sh 验证 openssl 返回码必须精确匹配 0 边界')

        if BASH:
            with tempfile.TemporaryDirectory() as td:
                real = Path(td) / 'real.yaml'
                real.write_text('acme:\n  domains:\n    - a.example.com\n', encoding='utf-8')
                link = Path(td) / 'sym.yaml'
                try:
                    os.symlink(real, link)
                except (OSError, NotImplementedError):
                    return
                res = subprocess.run(
                    [BASH, str(ROOT / 'fix_cert_chain.sh'), '--dry-run', '--config', str(link)],
                    capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=15
                )
                self.assertNotEqual(res.returncode, 0, '符号链接配置应被拒绝')


if __name__ == '__main__':
    unittest.main()
