"""回归测试：kick_hy2_users 与 _enforce_node_access_xray_hy2 校验回环端口范围、secret 合法性及 /online 有界与类型安全解析。"""

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class _FakeResp:
    def __init__(self, data: bytes):
        self._buf = io.BytesIO(data)

    def read(self, n=-1):
        return self._buf.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Hy2RevocationStatsValidationTests(unittest.TestCase):
    def test_kick_hy2_users_rejects_out_of_range_port_and_control_char_secret(self):
        """kick_hy2_users 必须拒绝端口 0 / 99999 以及含换行的 secret，不发起 HTTP 请求。"""
        for url, secret in (
            ('http://127.0.0.1:0', 'sec'),
            ('http://127.0.0.1:99999', 'sec'),
            ('http://127.0.0.1:19996', 'bad\nsecret'),
        ):
            with self.subTest(url=url, secret=secret), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                (root / 'usage-meter-config.json').write_text(
                    json.dumps({'hysteria': {'url': url, 'secret': secret}}), encoding='utf-8')
                with mock.patch.object(portal.urllib.request, 'urlopen') as open_mock:
                    self.assertFalse(portal.kick_hy2_users(root, ['u1']))
                    open_mock.assert_not_called()

    def test_enforce_node_access_raises_runtime_error_for_missing_secret_or_bad_port(self):
        """usage-meter-config.json 缺 secret、含控制字符或端口越界时必须抛明确 RuntimeError 而非 KeyError。"""
        for hc in (
            {'url': 'http://127.0.0.1:19996'},
            {'url': 'http://127.0.0.1:19996', 'secret': ''},
            {'url': 'http://127.0.0.1:19996', 'secret': 'bad\r\nheader'},
            {'url': 'http://127.0.0.1:99999', 'secret': 'ok'},
        ):
            with self.subTest(hc=hc), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                (root / 'usage-meter-config.json').write_text(json.dumps({'hysteria': hc}), encoding='utf-8')
                with self.assertRaises(RuntimeError):
                    portal._enforce_node_access_xray_hy2(root, {'users': {}}, force_ids=('u1',))

    def test_enforce_node_access_rejects_non_dict_or_corrupt_online_response(self):
        """/online 返回非 JSON 对象（如数组）或布尔/非数字会话数时必须抛 RuntimeError 而非 AttributeError/ValueError。"""
        for payload in (b'[]', b'{"u1": true}', b'{"u1": "bad"}'):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                (root / 'usage-meter-config.json').write_text(
                    json.dumps({'hysteria': {'url': 'http://127.0.0.1:19996', 'secret': 'sec'}}),
                    encoding='utf-8',
                )
                with mock.patch.object(portal.urllib.request, 'urlopen', return_value=_FakeResp(payload)):
                    with self.assertRaises(RuntimeError):
                        portal._enforce_node_access_xray_hy2(root, {'users': {}}, force_ids=('u1',))

    def test_enforce_node_access_uses_bounded_read(self):
        """_enforce_node_access_xray_hy2 的 request_stats 必须经 _read_bounded_bytes 限长读取响应。"""
        src = (ROOT / 'portal.py').read_text(encoding='utf-8')
        s = src.index('def _enforce_node_access_xray_hy2(')
        e = src.index('def _apply_xray_access_snapshot(', s)
        self.assertIn('_read_bounded_bytes(response', src[s:e])


if __name__ == '__main__':
    unittest.main()
