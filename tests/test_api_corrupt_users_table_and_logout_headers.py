"""回归测试：portal.py 所有用户接口不得裸用 data.get('users', {})，且 logout 须锁内读令牌并附安全响应头。"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORTAL = ROOT / 'portal.py'


class ApiCorruptUsersTableAndLogoutHeadersTests(unittest.TestCase):
    def test_no_raw_data_get_users_default_empty_dict_in_code(self):
        """代码行（排除注释）不得出现 data.get('users', {})，防止 data['users'] 损坏为列表/数字时 500。"""
        src = PORTAL.read_text(encoding='utf-8')
        bad_lines = []
        for idx, line in enumerate(src.splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith('#'):
                continue
            if re.search(r"data\.get\(\s*['\"]users['\"]\s*,\s*\{\}\s*\)", line):
                bad_lines.append((idx, line.strip()))
        self.assertEqual(bad_lines, [], f'仍有代码裸用 data.get("users", {{}}): {bad_lines}')

    def test_logout_reads_token_under_lock_and_sets_security_headers(self):
        """logout 分支应在 data_lock 内读取 token 并附带安全响应头。"""
        src = PORTAL.read_text(encoding='utf-8')
        start = src.index("if self.path == prefix + 'logout':")
        end = src.index("if self.path == prefix + 'install-warp':", start)
        block = src[start:end]
        self.assertIn("X-Content-Type-Options", block)
        self.assertIn("X-Frame-Options", block)
        self.assertIn("Referrer-Policy", block)
        self.assertNotIn("data['token']", block, 'logout 在锁外直接读 data["token"]')


if __name__ == '__main__':
    unittest.main()
