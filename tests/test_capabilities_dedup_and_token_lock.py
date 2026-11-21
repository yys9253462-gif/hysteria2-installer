"""回归测试：/api/v1/capabilities 去重子进程调用与过滤非法端口，及 do_GET/do_POST 在锁内安全读取门户 token。"""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')


class CapabilitiesDedupAndTokenLockTests(unittest.TestCase):
    def test_capabilities_calls_singbox_and_bbr_once_and_omits_invalid_ports(self):
        start = SRC.index("                if sub == 'capabilities':")
        end = SRC.index("                if sub.startswith('users/get/'):", start)
        body = SRC[start:end]
        self.assertEqual(body.count('_singbox_version()'), 1,
                         'capabilities 不应为 anytls 和 tuic 重复拉起两次 _singbox_version() 子进程')
        after_bbr_def = body[body.index('def _bbr_now():') + len('def _bbr_now():'):]
        self.assertEqual(after_bbr_def.count('_bbr_now()'), 1,
                         'capabilities 不应为 enabled 与 algo 重复拉起两次 _bbr_now() sysctl 子进程')
        self.assertNotIn("if d_snap['vmess'].get('port') else {}", body,
                         '端口非法字符串（如 bad）不应以 port: None 输出，应以 _valid_port 结果为条件')
        self.assertNotIn("if d_snap['anytls'].get('port') else {}", body)

    def test_do_get_and_do_post_read_portal_token_under_data_lock(self):
        self.assertNotIn("prefix = '/' + data['token'] + '/'", SRC,
                         "do_GET 与 do_POST 不得在 data_lock 外裸读 data['token']，防止并发修改或损坏抛错")


if __name__ == '__main__':
    unittest.main()
