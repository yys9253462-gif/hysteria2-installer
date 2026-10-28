"""users/list 不再给每个用户复制节点级 measurement_gaps（2026-10-28）。

gaps 是整台节点共用的计量缺口（最多 100 条）。原来每个用户各带一份，
53 个用户的节点 users/list 达 628 KB，被控制台 256 KiB 读取上限截断。
现在每个用户只带 measurement_gap_count，完整列表在信封里出现一次。
"""
import ast
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_round2_fixes import PortalServer  # noqa: E402


class UsersListGapsTest(PortalServer):
    def api(self, path, payload=None):
        status, body = self.request('/api/v1/' + path, payload,
                                    {'Authorization': 'Bearer ' + self.data['api_key']})
        return status, json.loads(body)

    def test_gaps_once_in_envelope_not_per_user(self):
        for uid in ('gaps_a', 'gaps_b'):
            status, body = self.api('users/create', {'user_id': uid, 'duration_days': 30})
            self.assertEqual(status, 200, body)
        status, body = self.api('users/list')
        self.assertEqual(status, 200, body)
        self.assertIsInstance(body.get('measurement_gaps'), list, '信封里必须有节点级 measurement_gaps')
        users = {u['user_id']: u for u in body['users']}
        for uid in ('gaps_a', 'gaps_b'):
            self.assertNotIn('measurement_gaps', users[uid], '用户里不能再复制整份 gaps')
            self.assertEqual(users[uid]['measurement_gap_count'], len(body['measurement_gaps']))


class UsersListSourceTest(unittest.TestCase):
    def test_both_users_list_handlers_use_list_summary(self):
        # 网页管理通道与 REST API 通道各有一个 users/list，两处都不能再直接展开 usage_summary。
        src = (ROOT / 'portal.py').read_text(encoding='utf-8')
        ast.parse(src)
        self.assertEqual(src.count("'measurement_gaps': node_gaps"), 2)
        self.assertEqual(src.count('summary, node_gaps = usage_list_summary(uid)'), 2)


if __name__ == '__main__':
    unittest.main()
