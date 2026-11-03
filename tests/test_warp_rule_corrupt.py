"""一条坏掉的分流规则不能让所有规则增删都 500（2026-11-03 修）。

同一条路径还撞出另一个 500：_egress_pending_count 写在 Handler 类体里，
_reply_with_egress_apply 按裸名找不到它，所有出站 / 分流变更都在保存后
抛 NameError —— 配置写进 portal.json，却从未下发。

warp_rules 里出现缺 domain 的对象（旧版本或手工编辑留下）时，旧实现在
data_lock 里 `r['domain']` 抛 KeyError：每一次 rule-add / rule-del 都失败。
起一个真门户进程，先把坏规则写进 portal.json，再走真实的 HTTP 端点。
"""
import base64
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_portal_auth_surface as surface  # noqa: E402


class WarpRuleCorruptTest(surface.EndpointAuthTest):
    @classmethod
    def setUpClass(cls):
        original_prepare = surface.portal.prepare

        def prepare(meta, port):
            original_prepare(meta, port)
            p = Path(meta).parent / 'portal.json'
            data = json.loads(p.read_text(encoding='utf-8'))
            data['warp_rules'] = [{'outbound': 'warp_socks'}, 'keep.example.com', 7,
                                  {'domain': 'via.example.com', 'outbound': 'proxy_a'}]
            data['custom_outbounds'] = ['legacy-string-entry',
                                        {'name': 'proxy_a', 'type': 'socks5', 'addr': '127.0.0.1:1'}]
            p.write_text(json.dumps(data), encoding='utf-8')
        surface.portal.prepare = prepare
        try:
            super().setUpClass()
        finally:
            surface.portal.prepare = original_prepare

    def auth(self):
        raw = f"{self.access['username']}:{self.access['password']}".encode()
        return 'Basic ' + base64.b64encode(raw).decode()

    def test_rule_edits_survive_a_malformed_entry(self):
        status, body = self.request('POST', self.prefix + 'manage-outbounds',
                                    {'action': 'rule-del', 'domain': 'gone.example.com'}, self.auth())
        self.assertNotEqual(status, 500, body[:300])
        status, body = self.request('POST', self.prefix + 'manage-outbounds',
                                    {'action': 'rule-add', 'domain': 'new.example.com',
                                     'outbound': 'direct'}, self.auth())
        self.assertEqual(status, 200, body[:300])
        rules = json.loads((self.root / 'portal.json').read_text(encoding='utf-8'))['warp_rules']
        domains = [r['domain'] for r in rules]
        self.assertIn('new.example.com', domains)
        self.assertIn('keep.example.com', domains, '合法规则被一起丢掉了')


    def test_outbound_delete_survives_malformed_entries(self):
        """删除出站时坏条目不能掐断连接（2026-11-03 修）。

        旧实现 o.get 遇到字符串条目在 data_lock 内抛 AttributeError，连接被重置，
        这个出站从面板上永远删不掉。删除时引用它的分流规则一并清掉。
        """
        status, body = self.request('POST', self.prefix + 'manage-outbounds',
                                    {'action': 'delete', 'name': 'proxy_a'}, self.auth())
        self.assertEqual(status, 200, body[:300])
        saved = json.loads((self.root / 'portal.json').read_text(encoding='utf-8'))
        self.assertFalse(any(isinstance(o, dict) and o.get('name') == 'proxy_a'
                             for o in saved['custom_outbounds']))
        self.assertNotIn('via.example.com', [r['domain'] for r in saved['warp_rules']])

# 父类的用例不在这里重复跑。
for _name in list(vars(surface.EndpointAuthTest)):
    if _name.startswith('test_'):
        setattr(WarpRuleCorruptTest, _name, None)
WarpRuleCorruptTest.test_rule_edits_survive_a_malformed_entry = \
    WarpRuleCorruptTest.__dict__['test_rule_edits_survive_a_malformed_entry']

if __name__ == '__main__':
    unittest.main()
