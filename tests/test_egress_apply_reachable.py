"""出站 / 分流规则变更必须真正排上下发（2026-11-03 修）。

_egress_pending_count 曾写在 Handler 类体里：_reply_with_egress_apply 按裸名
找不到它，**干净数据**上的每一次「添加规则 / 保存出站 / 切换模式」都在保存
之后抛 NameError 回 500，配置写进 portal.json 却从未下发到 Xray / Hy2。
起真门户进程走真实端点。
"""
import base64
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_portal_auth_surface as surface  # noqa: E402


class EgressApplyReachableTest(surface.EndpointAuthTest):
    def test_rule_add_on_clean_data_is_queued_for_apply(self):
        raw = f"{self.access['username']}:{self.access['password']}".encode()
        auth = 'Basic ' + base64.b64encode(raw).decode()
        status, body = self.request('POST', self.prefix + 'manage-outbounds',
                                    {'action': 'rule-add', 'domain': 'clean.example.com',
                                     'outbound': 'direct'}, auth)
        self.assertEqual(status, 200, body[:300])
        self.assertTrue(json.loads(body).get('ok'), body[:300])


for _name in list(vars(surface.EndpointAuthTest)):
    if _name.startswith('test_'):
        setattr(EgressApplyReachableTest, _name, None)

if __name__ == '__main__':
    unittest.main()
