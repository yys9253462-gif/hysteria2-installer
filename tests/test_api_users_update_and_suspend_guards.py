"""回归测试：API users/update 拒绝布尔/浮点/溢出参数、users/renew 防布尔存量字段，及 node/suspend 延长连接死线。"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')


class ApiUsersUpdateAndSuspendGuardsTests(unittest.TestCase):
    def test_users_update_rejects_bool_and_overflow_for_numeric_fields(self):
        start = SRC.index("elif sub == 'users/update':")
        end = SRC.index("elif sub == 'users/renew':", start)
        body = SRC[start:end]
        exp_block = body[body.index("if 'expires_at' in params:"):body.index("if 'ip_limit' in params:")]
        ip_block = body[body.index("if 'ip_limit' in params:"):body.index("if 'status' in params:")]
        self.assertIn('isinstance(', exp_block, 'users/update 的 expires_at 必须显式拦截 bool 等非法类型')
        self.assertIn('bool', exp_block)
        self.assertIn('isinstance(', ip_block, 'users/update 的 ip_limit 必须显式拦截 bool 等非法类型')
        self.assertIn('bool', ip_block)
        self.assertIn('OverflowError', body, 'users/update 数值转换异常捕获必须覆盖 OverflowError')

    def test_users_renew_rejects_bool_stored_expiry_or_limit(self):
        start = SRC.index("elif sub == 'users/renew':")
        end = SRC.index("elif sub == 'users/ip-deny':", start)
        body = SRC[start:end]
        self.assertIn('isinstance(raw_expiry, bool)', body,
                      'users/renew 不得把损坏的布尔 expires_at 当成 1970 年时间戳 1')
        self.assertIn('isinstance(raw_limit, bool)', body,
                      'users/renew 不得把损坏的布尔 limit_bytes 当成 1 字节')

    def test_node_suspend_extends_deadline_for_multi_unit_operations(self):
        start = SRC.index("elif sub == 'node/suspend':")
        end = SRC.index("return self.reply_json(404, {'ok': False, 'error': 'API endpoint not found'})", start)
        body = SRC[start:end]
        self.assertIn('self._extend_deadline(', body,
                      'node/suspend 需操作多个 systemd 单元，必须延长连接死线避免 30 秒断连')


if __name__ == '__main__':
    unittest.main()
