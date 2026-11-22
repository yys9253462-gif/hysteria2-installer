"""回归测试：/auth 与 /api/v1/* 的 Content-Length/端口超长数字防 DoS、node/suspend 落盘异常返回 503、POST proxy-services/list 锁内拷贝、users/renew 拒小数限额及 ip-deny 硬容量上限。"""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')


class TestPortalAuthAndRestV1Batch60Guards(unittest.TestCase):
    def test_node_suspend_catches_durability_and_oserror_with_503(self):
        """POST /api/v1/node/suspend 必须捕获 AtomicWriteDurabilityError 与 OSError 并返回 503，不得直接掐断连接。"""
        start = SRC.index("elif sub == 'node/suspend':")
        end = SRC.index("return self.reply_json(404, {'ok': False, 'error': 'API endpoint not found'})", start)
        block = SRC[start:end]
        self.assertIn('except AtomicWriteDurabilityError:', block)
        self.assertIn('except OSError', block)
        self.assertIn('self.reply_json(503,', block)

    def test_post_proxy_services_list_copies_dicts_inside_lock(self):
        """POST /api/v1/proxy-services/list 与 GET 一致，必须在锁内浅拷贝字典并过滤脏项。"""
        start = SRC.index("elif sub == 'proxy-services/list':")
        end = SRC.index("elif sub == 'proxy-services/delete':", start)
        block = SRC[start:end]
        self.assertIn('[dict(s) for s in proxy_services(data) if isinstance(s, dict)]', block)

    def test_auth_and_api_v1_bound_content_length_and_port_digits(self):
        """/auth 与 /api/v1/* 的 Content-Length、端口与数值参数解析必须限制数字串长度防 4300 位 DoS。"""
        auth_start = SRC.index("if self.path == '/auth':")
        auth_end = SRC.index("if self.path.startswith('/api/v1/'):", auth_start)
        auth_block = SRC[auth_start:auth_end]
        self.assertIn('len(_raw_cl_s) > 10', auth_block)
        self.assertIn('len(_port_s) > 5', auth_block)

        api_start = auth_end
        api_end = SRC.index("if sub == 'users/create':", api_start)
        api_block = SRC[api_start:api_end]
        self.assertIn('len(_raw_cl_s) > 10', api_block)
        self.assertIn('len(sval) > 24', api_block)

    def test_users_renew_rejects_fractional_stored_limit_and_expiry(self):
        """users/renew 面对损坏的非整数浮点 limit_bytes（如 0.5）不得截断成 0 变成不限量。"""
        start = SRC.index("elif sub == 'users/renew':")
        end = SRC.index("elif sub == 'users/ip-deny':", start)
        block = SRC[start:end]
        self.assertIn('raw_limit.is_integer()', block)
        self.assertIn('raw_expiry.is_integer()', block)

    def test_ip_deny_enforces_hard_capacity_bound_after_pruning(self):
        """users/ip-deny 清理过期项后若仍超 4096，必须按最早过期逐条淘汰确保有界内存。"""
        start = SRC.index("elif sub == 'users/ip-deny':")
        end = SRC.index("elif sub == 'users/delete':", start)
        block = SRC[start:end]
        self.assertIn('while len(global_ip_deny) > 4096:', block)


if __name__ == '__main__':
    unittest.main()
