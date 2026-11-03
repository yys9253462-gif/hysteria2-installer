"""不带 key 的 API 洪水不能挡住控制台（2026-11-03 修）。

旧实现在验 key 之前扣共享的 api 桶（每秒 50 次）：任何人经 masquerade 每秒
打 50 次 /api/v1/x，控制台的 users/set_status / users/delete 全部 429，
撤销卡住。起真门户进程走真实端点。
"""
import http.client
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_portal_auth_surface as surface  # noqa: E402


class ApiBucketSplitTest(surface.EndpointAuthTest):
    def get(self, path, key=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=8)
        try:
            conn.request('GET', path, headers={'Authorization': 'Bearer ' + key} if key else {})
            resp = conn.getresponse()
            resp.read()
            return resp.status
        finally:
            conn.close()

    def test_anonymous_flood_does_not_block_the_console(self):
        statuses = [self.get('/api/v1/users/list') for _ in range(70)]
        self.assertIn(429, statuses, '匿名洪水本身应当被限流')
        self.assertEqual(self.get('/api/v1/users/list', self.data['api_key']), 200,
                         '匿名请求打满了控制台用的 API 桶')


for _name in list(vars(surface.EndpointAuthTest)):
    if _name.startswith('test_'):
        setattr(ApiBucketSplitTest, _name, None)

if __name__ == '__main__':
    unittest.main()
