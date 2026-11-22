"""回归测试：证书自愈脏 SAN/控制字符防护、计量辅助函数类型守卫、prepare/adopt 脏凭据与 allow_nan=False 及启动恢复读盘上限。"""

import ast
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
PORTAL_TREE = ast.parse(PORTAL_SRC)


def _fn_src(name: str) -> str:
    for node in ast.walk(PORTAL_TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(PORTAL_SRC, node)
    raise AssertionError(f'未找到函数 {name}')


class CertTrustAdoptPrepareMeterHelpersAndXrayRecoverGuardsTests(unittest.TestCase):
    def test_sync_cert_trust_ignores_non_str_sans_sanitizes_control_hosts_and_caps_config_size(self):
        """sync_cert_trust 面对非字符串 SAN 不得抛 AttributeError，并清洗含控制字符的旧主机名且限制 config 读取体积。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cert = root / 'cert.pem'
            cert.write_text('dummy-cert', encoding='utf-8')
            meta = root / 'client_meta.json'
            m = {
                'server_name': 'old.example.com\r\n',
                'public_ip': '1.2.3.4\n',
                'cert_type': 'self_signed',
                'is_insecure': True,
            }
            meta.write_text(json.dumps(m), encoding='utf-8')
            with mock.patch.object(portal, '_config_tls_cert_path', return_value=''), \
                 mock.patch.object(portal, '_resolve_live_cert', return_value=(cert, 'good.example.com', [None, 123, '*.wild.example.com', 'san.example.com'], False)):
                changed = portal.sync_cert_trust(m, root, str(meta), config_path=str(root / 'missing.yaml'))
            self.assertTrue(changed)
            self.assertEqual(m['server_name'], 'san.example.com')

        src = _fn_src('sync_cert_trust')
        self.assertIn('allow_nan=False', src)
        self.assertIn('_clean_host_scalar', src)
        self.assertIn('4 * 1024 * 1024', src)

    def test_meter_ledger_helpers_guard_non_dict_unhashable_and_negative_values(self):
        """drop_meter_totals/restore_meter_user/reconcile_meter_usage/legacy_used_bytes 须防护坏容器、不可哈希 uid 与负数。"""
        self.assertFalse(portal.drop_meter_totals('not-a-dict', 'u1'))
        self.assertFalse(portal.drop_meter_totals({'usage_meter': {'totals': {}}}, ['unhashable']))
        self.assertFalse(portal.drop_meter_totals({'usage_meter': {'totals': {}}}, ''))

        portal.restore_meter_user('not-a-dict', 'u1')
        portal.restore_meter_user({'usage_meter': {'retired_users': ['u1']}}, ['unhashable'])

        for bad_data, bad_uid in (('not-dict', 'u1'), ({}, ''), ({}, ['u1']), ({}, None)):
            with self.subTest(bad_data=bad_data, bad_uid=bad_uid):
                with self.assertRaises(ValueError):
                    portal.reconcile_meter_usage(bad_data, bad_uid, 0)

        self.assertEqual(portal.legacy_used_bytes({'users': {'u1': {'used_bytes': -50}}}, 'u1'), 0)
        self.assertEqual(portal.legacy_used_bytes({'users': {'u1': {'used_bytes': 100}}}, ['unhashable']), 0)
        self.assertEqual(portal.legacy_used_bytes({'users': {'u1': {'used_bytes': 100}}}, 'u1'), 100)

    def test_adopt_locked_rejects_blank_or_control_auth_password_and_repairs_blank_session_secret(self):
        """_adopt_locked 不得用纯空白或含控制字符的 auth_password 覆盖机主密码，且须重建纯空白 session_secret。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            meta = root / 'client_meta.json'
            meta.write_text(json.dumps({
                'server_name': 'node.example.com',
                'public_ip': '1.2.3.4',
                'subscription_port': 443,
                'auth_password': '   \r\n',
            }), encoding='utf-8')
            (root / 'portal.json').write_text(json.dumps({
                'port': 18080,
                'token': 'tok1',
                'api_key': 'key1',
                'auth_hash': 'old_hash',
                'session_secret': '   \n',
                'users': {'admin_master': {'password': 'keep_old_password', 'expires_at': 0}},
            }), encoding='utf-8')
            (root / 'portal-access.json').write_text(json.dumps({
                'username': 'admin',
                'password': 'secret',
                'api_key': 'key1',
                'url': 'https://node.example.com:443/tok1/',
            }), encoding='utf-8')
            portal._adopt_locked(str(meta), 18080)
            reloaded = json.loads((root / 'portal.json').read_text(encoding='utf-8'))
            self.assertEqual(reloaded['users']['admin_master']['password'], 'keep_old_password')
            self.assertTrue(reloaded['session_secret'].strip() and '\n' not in reloaded['session_secret'])

        for fn_name in ('_adopt_locked', 'prepare', 'sync_pin', 'repair_missing_api_key'):
            with self.subTest(fn=fn_name):
                self.assertIn('allow_nan=False', _fn_src(fn_name))

    def test_prepare_blocks_script_qr_and_recover_xray_caps_config_size(self):
        """prepare 的二维码降级须拦截 <script/<foreignObject；recover_xray_service_on_start 须限制 xray.json 读盘体积。"""
        prep_src = _fn_src('prepare')
        self.assertIn('<script', prep_src.lower())
        rec_src = _fn_src('recover_xray_service_on_start')
        self.assertIn('4 * 1024 * 1024', rec_src)


if __name__ == '__main__':
    unittest.main()
