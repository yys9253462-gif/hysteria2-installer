"""回归测试：Reality 直链清洗、_valid_port 限长、artifacts 脏 user_id/secret 防护、刷新与合并状态类型守卫及 Reality SNI 清洗。"""

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


def _find_method_src(name: str) -> str:
    for node in ast.walk(PORTAL_TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(PORTAL_SRC, node)
    raise AssertionError(f'未找到函数 {name}')


class RealityUriArtifactsRefreshMergeAndSniGuardsTests(unittest.TestCase):
    def test_reality_uri_for_user_rejects_bad_user_id_and_strips_control_label(self):
        """reality_uri_for_user 应拒绝非串/空/纯空白/含控制字符的 user_id，并剥离 label 控制字符。"""
        rcfg = {
            'port': 8443,
            'dest_sni': 'www.apple.com',
            'public_key': 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde',
            'short_id': 'a1b2c3d4',
        }
        for bad_uid in (None, '', '   ', 123, True, 'u1\r\n'):
            with self.subTest(bad_uid=bad_uid):
                self.assertEqual(portal.reality_uri_for_user(rcfg, bad_uid, '1.2.3.4'), '')

        uri = portal.reality_uri_for_user(rcfg, 'alice', '1.2.3.4', label='Line1\r\nLine2\x7f')
        self.assertTrue(uri.startswith('vless://'))
        self.assertNotIn('%0D', uri)
        self.assertNotIn('%0A', uri)
        self.assertNotIn('%7F', uri)
        self.assertTrue(uri.endswith('#Line1Line2'))

    def test_valid_port_caps_digit_string_length(self):
        """_valid_port 应对超长纯数字字符串短路拒收，避免大整数转换放大。"""
        src = _find_method_src('_valid_port')
        self.assertRegex(src, r'len\(s\)\s*>\s*16|len\(s\)\s*<=\s*16')
        self.assertEqual(portal._valid_port('0' * 10000 + '443'), 0)
        self.assertEqual(portal._valid_port('9' * 5000), 0)
        self.assertEqual(portal._valid_port('443'), 443)

    def test_artifacts_ignores_non_string_or_blank_user_id_and_dirty_anytls_tuic_secrets(self):
        """artifacts 面对非串/空白/控制字符 user_id 及含空白/控制字符的 anytls/tuic secret 不得抛错或下发脏节点。"""
        meta = {'server_name': 'node.example.com', 'public_ip': '1.2.3.4', 'listen_port': 443, 'auth_password': 'pw'}
        rcfg = {
            'port': 8443,
            'dest_sni': 'www.apple.com',
            'public_key': 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde',
            'short_id': 'a1b2c3d4',
        }
        vmess = {'domain': 'vm.example.com', 'port': 2053, 'ws_path': '/ws'}
        anytls = {'domain': 'at.example.com', 'port': 2083, 'secret': 'valid-secret'}
        tuic = {'domain': 'tu.example.com', 'port': 2096, 'secret': 'valid-secret'}

        for bad_uid in (123, True, ['u1'], '   ', 'alice\n'):
            with self.subTest(bad_uid=bad_uid):
                uri, clash_s, sing_s = portal.artifacts(
                    meta, user_id=bad_uid, reality=rcfg, vmess=vmess, anytls=anytls, tuic=tuic
                )
                self.assertTrue(uri.startswith('hysteria2://'))
                clash = json.loads(clash_s)
                self.assertEqual(len(clash['proxies']), 1, f'脏 user_id={bad_uid!r} 不得下发备用协议节点')
                sing = json.loads(sing_s)
                self.assertEqual(len(sing['outbounds']), 1)

        # 合法 user_id 但 anytls / tuic secret 含纯空白或控制字符时应跳过对应协议
        for bad_secret in ('   ', 'sec\r\nret', 'sec\x00ret'):
            with self.subTest(bad_secret=bad_secret):
                _, clash_s, sing_s = portal.artifacts(
                    meta,
                    user_id='alice',
                    anytls={'domain': 'at.example.com', 'port': 2083, 'secret': bad_secret},
                    tuic={'domain': 'tu.example.com', 'port': 2096, 'secret': bad_secret},
                )
                clash = json.loads(clash_s)
                self.assertEqual([p['type'] for p in clash['proxies']], ['hysteria2'])
                sing = json.loads(sing_s)
                self.assertEqual([o['type'] for o in sing['outbounds']], ['hysteria2'])

    def test_merge_cli_owned_state_blocks_corrupt_derived_and_master_fields(self):
        """merge_cli_owned_state 须拦截纯空白/控制字符密钥、非串派生资源以及坏类型机主密码与到期时间。"""
        data = {
            'port': 18080,
            'auth_hash': 'hash_ok',
            'session_secret': 'sec_ok',
            'api_key': 'key_ok',
            'session_epoch': 2,
            'clash': 'clash_ok',
            'sing': 'sing_ok',
            'qr': '<svg>ok</svg>',
            'page_digest': 'deadbeef',
            'users': {'admin_master': {'password': 'pw_ok', 'expires_at': 0}},
        }
        portal.merge_cli_owned_state(data, {
            'auth_hash': '   ',
            'session_secret': 'bad\nsecret',
            'api_key': '\t\n',
            'clash': None,
            'sing': 123,
            'qr': ['not-a-str'],
            'page_digest': '',
            'users': {'admin_master': {'password': 99999, 'expires_at': True}},
        })
        self.assertEqual(data['auth_hash'], 'hash_ok')
        self.assertEqual(data['session_secret'], 'sec_ok')
        self.assertEqual(data['api_key'], 'key_ok')
        self.assertEqual(data['clash'], 'clash_ok')
        self.assertEqual(data['sing'], 'sing_ok')
        self.assertEqual(data['qr'], '<svg>ok</svg>')
        self.assertEqual(data['page_digest'], 'deadbeef')
        self.assertEqual(data['users']['admin_master']['password'], 'pw_ok')
        self.assertEqual(data['users']['admin_master']['expires_at'], 0)

    def test_refresh_portal_state_repairs_bad_token_and_blank_session_secret_with_allow_nan_false(self):
        """_refresh_portal_state 应修复缺失/非法 token 与纯空白/控制字符 session_secret，且落盘强制 allow_nan=False。"""
        src = _find_method_src('_refresh_portal_state')
        self.assertIn('allow_nan=False', src)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            meta_path = root / 'client_meta.json'
            meta_path.write_text(json.dumps({
                'server_name': 'node.example.com',
                'public_ip': '1.2.3.4',
                'listen_port': 443,
                'subscription_port': 8443,
                'auth_password': 'pw1',
                'is_insecure': False,
            }), encoding='utf-8')
            (root / 'portal.json').write_text(json.dumps({
                'token': 'bad/tok\n',
                'session_secret': '   \n',
                'api_key': 'valid_api_key',
                'auth_hash': 'h1',
                'users': {'admin_master': {'password': 'pw1', 'expires_at': 0}},
                'proxy_services': [],
            }), encoding='utf-8')
            (root / 'portal-access.json').write_text(json.dumps({
                'username': 'admin',
                'password': 'secret',
                'api_key': 'valid_api_key',
                'url': 'https://old/',
            }), encoding='utf-8')
            with mock.patch.object(portal, 'sync_cert_trust'), mock.patch.object(portal, 'sync_pin'):
                portal._refresh_portal_state(str(meta_path), config_path=str(root / 'config.yaml'),
                                             precomputed_qr=None)
            reloaded = json.loads((root / 'portal.json').read_text(encoding='utf-8'))
            self.assertTrue(isinstance(reloaded['token'], str) and reloaded['token'] and '/' not in reloaded['token'])
            self.assertNotIn('\n', reloaded['token'])
            self.assertTrue(reloaded['session_secret'].strip() and '\n' not in reloaded['session_secret'])

    def test_generate_and_apply_reality_sanitizes_dest_sni_and_uses_valid_port_for_avoid(self):
        """_generate_and_apply_reality 须清洗 dest_sni 并用 _valid_port 收集避让端口，且安全解析公钥与初始化子进程结果。"""
        src = _find_method_src('_generate_and_apply_reality')
        self.assertIn("_clean_host_scalar(rcfg_old.get('dest_sni'))", src)
        self.assertIn("split(':', 1)[1]", src)
        self.assertIn('_valid_port(m.get(', src)
        self.assertIn('p = None', src)


if __name__ == '__main__':
    unittest.main()
