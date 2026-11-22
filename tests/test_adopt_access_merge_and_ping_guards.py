"""回归测试：沿用配置端口严格校验、缺凭据 access 文件重建、CLI 状态合并坏值过滤、出站还原坏条目过滤及 ping 解析编码容错。"""

import ast
import json
import math
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
PORTAL_TREE = ast.parse(PORTAL_SRC)


class AdoptAccessMergeAndPingGuardsTests(unittest.TestCase):
    def test_adopt_locked_rejects_float_and_fullwidth_ports(self):
        """_adopt_locked 必须拒绝小数端口与全角数字端口。"""
        with tempfile.TemporaryDirectory() as td:
            meta = Path(td) / 'client_meta.json'
            meta.write_text('{}', encoding='utf-8')
            for bad_port in (18080.9, '１８０８０', float('inf'), '0'):
                with self.assertRaises(ValueError, msg=f'非法端口 {bad_port!r} 必须被 _adopt_locked 拒绝'):
                    portal._adopt_locked(str(meta), bad_port)

    def test_ensure_portal_access_rebuilds_when_username_or_password_missing_or_non_string(self):
        """portal-access.json 缺少 username/password 或类型非法时必须视为损坏并重建，防止写坏 auth_hash。"""
        for bad_access in ({}, {'username': 'u'}, {'username': '', 'password': 'p'}, {'username': 123, 'password': 'p'}):
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                (root / 'portal-access.json').write_text(json.dumps(bad_access), encoding='utf-8')
                data = {'token': 'tok1', 'api_key': 'k1', 'auth_hash': 'old'}
                meta = {'server_name': 'node.example.com', 'subscription_port': 443}
                access, rebuilt = portal.ensure_portal_access(root, meta, data)
                self.assertTrue(rebuilt, f'损坏凭据 {bad_access!r} 必须触发重建')
                self.assertTrue(isinstance(access.get('username'), str) and access['username'])
                self.assertTrue(isinstance(access.get('password'), str) and access['password'])

    def test_merge_cli_owned_state_ignores_corrupt_critical_fields_and_non_dict(self):
        """merge_cli_owned_state 不得用磁盘上损坏的 port/auth_hash/session_secret/session_epoch 覆盖有效内存值。"""
        data = {
            'port': 28080,
            'auth_hash': 'valid_hash',
            'session_secret': 'valid_secret',
            'api_key': 'valid_key',
            'session_epoch': 3,
            'users': {'admin_master': {'password': 'ok'}},
        }
        # 非字典 disk 不得抛 TypeError
        portal.merge_cli_owned_state(data, 'corrupt')
        portal.merge_cli_owned_state(data, {
            'port': 'bad_port',
            'auth_hash': '',
            'session_secret': None,
            'api_key': 123,
            'session_epoch': True,
            'clash': 'new-clash',
        })
        self.assertEqual(data['port'], 28080)
        self.assertEqual(data['auth_hash'], 'valid_hash')
        self.assertEqual(data['session_secret'], 'valid_secret')
        self.assertEqual(data['api_key'], 'valid_key')
        self.assertEqual(data['session_epoch'], 3)
        self.assertEqual(data['clash'], 'new-clash')

    def test_restore_egress_into_config_ignores_unrenderable_corrupt_outbounds(self):
        """restore_egress_into_config 面对全为缺 addr/url 坏条目的 custom_outbounds 不得改写 config.yaml。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            orig_cfg = 'listen: :443\n'
            (root / 'config.yaml').write_text(orig_cfg, encoding='utf-8')
            (root / 'portal.json').write_text(json.dumps({
                'custom_outbounds': [{'name': 'broken_socks', 'type': 'socks5'}],
                'outbound_mode': 'global',
            }), encoding='utf-8')
            changed = portal.restore_egress_into_config(root)
            self.assertFalse(changed)
            self.assertEqual((root / 'config.yaml').read_text(encoding='utf-8'), orig_cfg)

    def test_ping_one_uses_utf8_replace_and_strict_rtt_regex(self):
        """_ping_one 须带 errors='replace' 并精准解析 RTT，不被前面含 `= 1/2/3` 或 `= ..` 的脏行干扰。"""
        for node in ast.walk(PORTAL_TREE):
            if isinstance(node, ast.FunctionDef) and node.name == '_ping_one':
                src = ast.get_source_segment(PORTAL_SRC, node)
                break
        else:
            self.fail('未找到 _ping_one')
        self.assertIn("errors='replace'", src, '_ping_one 执行 ping 须指定 errors="replace" 防非 UTF-8 崩溃')
        dedented = '\n'.join(line[8:] if line.startswith('        ') else line for line in src.splitlines())
        ns = {
            'os': __import__('os'),
            're': re,
            'math': math,
            'subprocess': type('Sub', (), {
                'run': staticmethod(lambda *a, **kw: subprocess.CompletedProcess(
                    a[0], 0,
                    stdout='meta = ../1.2/3.4\n10 packets transmitted, 10 received, 0% packet loss\nrtt min/avg/max/mdev = 10.1/20.5/30.9/1.2 ms\n',
                    stderr='',
                ))
            }),
        }
        exec(dedented, ns)
        avg, loss = ns['_ping_one'](object(), '223.5.5.5')
        self.assertAlmostEqual(avg, 20.5)
        self.assertAlmostEqual(loss, 0.0)


if __name__ == '__main__':
    unittest.main()
