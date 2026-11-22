"""回归测试：usage-meter-readers 禁 3xx 重定向防 secret 泄露、read_hysteria 结构校验、parse_xray/parse_events 拒空与控制字符 uid、read_live_connections 读盘拒符号链接与体积上限。"""

import importlib.util
import io
import json
import os
import stat
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def _load_readers():
    spec = importlib.util.spec_from_file_location(
        'usage_meter_readers_batch60',
        ROOT / 'usage-meter-readers-20261007-v1.py',
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestUsageMeterReadersBatch60Guards(unittest.TestCase):
    def test_validate_loopback_xray_addr_rejects_huge_port_digits(self):
        """超长数字端口字符串应快速报 loopback 校验失败而非触发 4300 位整数限制异常。"""
        mod = _load_readers()
        with self.assertRaisesRegex(ValueError, 'xray endpoint must be loopback'):
            mod._validate_loopback_xray_addr('127.0.0.1:' + '9' * 5000)

    def test_no_redirect_handler_blocks_3xx_secret_leak(self):
        """必须提供 _NoRedirectHandler 拒绝 3xx 重定向，防止把 Authorization 密钥发给跳转地址。"""
        mod = _load_readers()
        handler_cls = getattr(mod, '_NoRedirectHandler', None)
        self.assertIsNotNone(handler_cls, 'readers 必须定义 _NoRedirectHandler')
        handler = handler_cls()
        req = urllib.request.Request('http://127.0.0.1:9999/traffic')
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            handler.redirect_request(req, None, 302, 'Found', {}, 'http://evil.example/')
        self.assertEqual(ctx.exception.code, 302)
        ctx.exception.close()

    def test_read_hysteria_validates_counter_structure(self):
        """read_hysteria 必须校验每条用户计数为非负整型字典，拒绝脏值与布尔值。"""
        mod = _load_readers()

        def _make_resp(obj):
            raw = json.dumps(obj).encode('utf-8')

            class _Resp:
                status = 200

                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

                def read(self, n=-1):
                    return raw if n < 0 else raw[:n]

            return _Resp()

        for bad in (
            {'u1': 'not-a-dict'},
            {'': {'tx': 1, 'rx': 2}},
            {'u1': {'tx': True, 'rx': 2}},
            {'u1': {'tx': -1, 'rx': 2}},
        ):
            with mock.patch.object(mod.urllib.request, 'urlopen', return_value=_make_resp(bad)):
                with self.assertRaises(ValueError, msg=f'应拒绝畸形流量响应: {bad!r}'):
                    mod.read_hysteria('http://127.0.0.1:9999', 'sec')

        good = {'alice': {'tx': 100, 'rx': 200}}
        with mock.patch.object(mod.urllib.request, 'urlopen', return_value=_make_resp(good)):
            self.assertEqual(mod.read_hysteria('http://127.0.0.1:9999', 'sec'), good)

    def test_parse_xray_rejects_empty_or_control_uid(self):
        """parse_xray 必须拒绝空用户名及含控制字符的用户名。"""
        mod = _load_readers()
        for bad_name in ('user>>>>>>traffic>>>uplink', 'user>>>a\nb>>>traffic>>>uplink'):
            payload = json.dumps({'stat': [{'name': bad_name, 'value': '10'}]})
            with self.assertRaises(ValueError, msg=f'应拒绝脏 Xray 统计名: {bad_name!r}'):
                mod.parse_xray(payload)

    def test_parse_events_rejects_empty_or_control_uid_and_float_ts(self):
        """parse_events 必须拒绝空/控制字符 uid 及小数浮点时间戳。"""
        mod = _load_readers()
        for bad_row in (
            {'__MONOTONIC_TIMESTAMP': '1', 'MESSAGE': json.dumps({'msg': 'client connected', 'id': '', 'addr': '1.2.3.4:1000'})},
            {'__MONOTONIC_TIMESTAMP': '1', 'MESSAGE': json.dumps({'msg': 'client connected', 'id': 'u\n1', 'addr': '1.2.3.4:1000'})},
            {'__MONOTONIC_TIMESTAMP': 1.5, 'MESSAGE': json.dumps({'msg': 'client connected', 'id': 'u1', 'addr': '1.2.3.4:1000'})},
        ):
            with self.assertRaises(ValueError, msg=f'应拒绝异常事件: {bad_row!r}'):
                mod.parse_events([bad_row])

    def test_read_bounded_json_rejects_symlink_and_oversized_file(self):
        """_read_bounded_json 必须拒绝符号链接与超过上限的配置文件。"""
        mod = _load_readers()
        fn = getattr(mod, '_read_bounded_json', None)
        self.assertIsNotNone(fn, 'readers 必须提供 _read_bounded_json')
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'cfg.json'
            p.write_text('{"ok": true}', encoding='utf-8')
            self.assertEqual(fn(p, max_bytes=1024), {'ok': True})

            fake_symlink = os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 1, 0, 0, 12, 0, 0, 0))
            with mock.patch.object(Path, 'lstat', return_value=fake_symlink):
                with self.assertRaises(ValueError):
                    fn(p, max_bytes=1024)

            with self.assertRaises(ValueError):
                fn(p, max_bytes=4)


if __name__ == '__main__':
    unittest.main()
