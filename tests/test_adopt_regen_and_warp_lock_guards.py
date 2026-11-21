"""回归测试：adopt 端口与 API 密钥校验、regenerate_page 凭据 URL 编码与坏 token 防护、及 _h_post_manage_warp 锁外探测 WARP 后端。"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class AdoptRegenAndWarpLockGuardsTests(unittest.TestCase):
    def test_adopt_locked_rejects_bool_or_out_of_range_port_and_control_api_key(self):
        """_adopt_locked 必须拒绝布尔/越界端口以及含换行、空白或非 ASCII 的 node_api_key。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            meta = root / 'client_meta.json'
            meta.write_text(json.dumps({
                'public_ip': '198.51.100.1', 'server_name': 'node.example.com',
                'listen_port': 443, 'auth_password': 'p', 'obfs_password': 'o',
                'is_insecure': False, 'subscription_port': 8443,
            }), encoding='utf-8')
            (root / 'portal.json').write_text(json.dumps({'port': 18080, 'token': 'tok', 'users': {}}), encoding='utf-8')
            (root / 'portal-access.json').write_text(json.dumps({'username': 'u', 'password': 'p'}), encoding='utf-8')

            for bad_port in (True, False, 0, -1, 70000):
                with self.subTest(bad_port=bad_port):
                    with self.assertRaises(ValueError):
                        portal._adopt_locked(meta, bad_port)

            for bad_key in ('bad\nkey', 'bad key', '中文密钥'):
                with self.subTest(bad_key=bad_key):
                    with self.assertRaises(ValueError):
                        portal._adopt_locked(meta, 18080, node_api_key=bad_key)

    def test_regenerate_page_quotes_credentials_guards_token_and_finite_timestamps(self):
        """regenerate_page 应安全读取 token、URL 编码订阅凭据并过滤非有限时间戳。"""
        src = (ROOT / 'portal.py').read_text(encoding='utf-8')
        s = src.index('    def regenerate_page():')
        e = src.index('    def verify_session(', s)
        body = src[s:e]
        self.assertNotIn("_token = data['token']", body)
        self.assertIn("quote(str(access.get('username', '')), safe='')", body)
        self.assertIn("quote(str(access.get('password', '')), safe='')", body)
        self.assertIn('math.isfinite(t)', body)

    def test_manage_warp_probes_backend_outside_data_lock(self):
        """_h_post_manage_warp 不应在持有 data_lock 期间执行 warp_backend_installed() 文件系统探测。"""
        src = (ROOT / 'portal.py').read_text(encoding='utf-8')
        s = src.index('        def _h_post_manage_warp(self, prefix):')
        e = src.index('        def _h_post_install_xray(self, prefix):', s)
        body = src[s:e]
        lock_pos = body.index('with data_lock:')
        probe_pos = body.index('warp_backend_installed()')
        self.assertLess(probe_pos, lock_pos, 'warp_backend_installed() 应移到 with data_lock: 之前执行')


if __name__ == '__main__':
    unittest.main()
