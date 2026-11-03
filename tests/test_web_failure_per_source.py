"""一个来源的失败请求不能让全节点的 Web 与订阅都 429（2026-11-03 修）。

旧实现的 failures 桶是进程全局的：拿到分享链接（含 token）的人每分钟发
60 次不带凭据的 clash.yaml，管理页和所有人的订阅更新都回 429。
起真门户进程，用 masquerade 写入的 X-Forwarded-For 区分来源。
"""
import base64
import http.client
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_portal_auth_surface as surface  # noqa: E402


class WebFailurePerSourceTest(surface.EndpointAuthTest):
    def get(self, path, source, auth=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=8)
        try:
            headers = {'X-Forwarded-For': source}
            if auth:
                headers['Authorization'] = auth
            conn.request('GET', path, headers=headers)
            resp = conn.getresponse()
            resp.read()
            return resp.status
        finally:
            conn.close()

    def test_one_source_failing_does_not_lock_out_others(self):
        for _ in range(60):
            self.get(self.prefix + 'clash.yaml', '198.51.100.7')
            time.sleep(0.03)  # 不让每秒 50 次的速率桶先触发
        self.assertEqual(self.get(self.prefix + 'clash.yaml', '198.51.100.7'), 429, '失败来源本身应被限流')
        raw = f"{self.access['username']}:{self.access['password']}".encode()
        auth = 'Basic ' + base64.b64encode(raw).decode()
        self.assertEqual(self.get(self.prefix + 'clash.yaml', '203.0.113.9', auth), 200,
                         '一个来源的失败把别的来源也锁住了')

    def test_spoofed_leading_hops_do_not_split_the_bucket(self):
        for i in range(60):
            self.get(self.prefix + 'clash.yaml', '10.%d.0.1, 198.51.100.8' % i)
            time.sleep(0.03)
        self.assertEqual(self.get(self.prefix + 'clash.yaml', '198.51.100.8'), 429,
                         '伪造前置 X-Forwarded-For 绕过了失败计数')


for _name in list(vars(surface.EndpointAuthTest)):
    if _name.startswith('test_'):
        setattr(WebFailurePerSourceTest, _name, None)

if __name__ == '__main__':
    unittest.main()
