"""回归测试：sync_pin 空证书路径回落、artifacts 控制字符剥离与 allow_nan=False、users_list_entry 脏数值规整及 prepare 密码控制字符拦截。"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import portal  # noqa: E402


class ArtifactsSyncPinPrepareAndUsersListEntryGuardsTests(unittest.TestCase):
    def test_sync_pin_falls_back_when_live_cert_path_is_empty(self):
        """_resolve_live_cert 返回空路径 '' 时，Path('').exists() 不得误当成当前目录跳过回落 get_cert_pin_sha256。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            meta_path = root / 'client_meta.json'
            m = {'is_insecure': True, 'cert_type': 'self_signed', 'server_name': 'www.bing.com', 'pin_sha256': 'bad'}
            meta_path.write_text(json.dumps(m), encoding='utf-8')
            fake_pin = 'a' * 64
            with patch.object(portal, '_resolve_live_cert', return_value=('', '', [], True)), \
                 patch.object(portal, 'pin_sha256_of_file', side_effect=AssertionError('不应对空路径调用 pin_sha256_of_file')), \
                 patch.object(portal, 'get_cert_pin_sha256', return_value=fake_pin) as mock_fb:
                portal.sync_pin(m, root, meta_path)
            mock_fb.assert_called_once_with(root)
            self.assertEqual(m['pin_sha256'], fake_pin)

    def test_artifacts_strips_control_chars_from_name_password_and_obfs(self):
        """artifacts() 须剥除节点名、密码与混淆密码中的控制/换行字符，防止破坏直链与客户端配置。"""
        meta = {
            'server_name': 'node.example.com',
            'public_ip': '198.51.100.2',
            'listen_port': 443,
            'is_insecure': False,
            'auth_password': 'pw\r\nline',
            'obfs_password': 'obfs\x00key',
        }
        uri, clash_txt, sing_txt = portal.artifacts(meta, name_override='My\r\nNode')
        self.assertNotIn('\r', uri)
        self.assertNotIn('\n', uri)
        clash = json.loads(clash_txt)
        sing = json.loads(sing_txt)
        self.assertEqual(clash['proxies'][0]['name'], 'MyNode')
        self.assertEqual(clash['proxies'][0]['password'], 'pwline')
        self.assertEqual(clash['proxies'][0]['obfs-password'], 'obfskey')
        self.assertEqual(sing['outbounds'][0]['tag'], 'MyNode')
        self.assertEqual(sing['outbounds'][0]['password'], 'pwline')

    def test_users_list_entry_sanitizes_bool_nan_inf_and_corrupt_status(self):
        """users_list_entry 须规整 bool / NaN / Inf / 非字符串脏字段，不输出非法 JSON 或把 True 当成 1 字节限额。"""
        entry = portal.users_list_entry(
            'u1',
            {
                'status': ['bad'],
                'expires_at': float('inf'),
                'limit_bytes': True,
                'used_bytes': float('nan'),
                'created_at': 'not-a-num',
            },
            {},
            1700000000,
            {},
            60,
        )
        self.assertEqual(entry['status'], 'disabled')
        self.assertEqual(entry['expires_at'], 0)
        self.assertEqual(entry['limit_bytes'], 0)
        self.assertEqual(entry['traffic_limit_bytes'], 0)
        self.assertEqual(entry['used_bytes'], 0)
        self.assertEqual(entry['traffic_used_bytes'], 0)
        self.assertEqual(entry['created_at'], 0)
        json.dumps(entry, allow_nan=False)

        # 永久账号（expires_at=None）须原样保留 None
        perm = portal.users_list_entry('u2', {'status': 'active', 'expires_at': None, 'limit_bytes': 1024, 'used_bytes': 512, 'created_at': 1700000000}, {}, 1700000000, {}, 60)
        self.assertIsNone(perm['expires_at'])
        self.assertEqual(perm['limit_bytes'], 1024)
        self.assertEqual(perm['used_bytes'], 512)

    def test_prepare_rejects_control_chars_in_auth_password(self):
        """prepare() 须拒绝 client_meta.json 中含换行或控制字符的 auth_password。"""
        with tempfile.TemporaryDirectory() as td:
            mp = Path(td) / 'client_meta.json'
            mp.write_text(json.dumps({'auth_password': 'pass\r\nword'}), encoding='utf-8')
            with self.assertRaises(ValueError):
                portal.prepare(str(mp), 18080)


if __name__ == '__main__':
    unittest.main()
