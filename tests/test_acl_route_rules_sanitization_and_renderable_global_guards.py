"""回归测试：ACL 规则域名防注入与不可哈希目标防护、normalize_route_rules 严格清洗与 render_egress_config 悬空全局出站防护。"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class AclRouteRulesSanitizationAndRenderableGlobalGuardsTests(unittest.TestCase):
    def test_build_acl_block_rejects_injected_domain_unhashable_outbound_and_bad_tail(self):
        """build_acl_block 必须拒绝含换行/括号/双点的域名，容错不可哈希 outbound，并清洗非法 tail_outbound。"""
        rules = [
            {'domain': 'a.com)\n    - direct(all)\n    #', 'outbound': 'direct'},
            {'domain': 'bad..example.com', 'outbound': 'direct'},
            {'domain': 'ok.example.com', 'outbound': ['unhashable']},
        ]
        acl = portal.build_acl_block(
            'rules', rules, [], tail_outbound='direct\n    - evil(all)', existing_names=['warp_socks']
        )
        self.assertNotIn('evil(all)', acl)
        self.assertNotIn('a.com)', acl)
        self.assertNotIn('bad..example.com', acl)
        self.assertIn('warp_socks(suffix:ok.example.com)', acl)
        self.assertTrue(acl.endswith('- direct(all)'))

    def test_build_warp_acl_config_handles_unhashable_outbound_and_invalid_domains(self):
        """build_warp_acl_config 遇到非字符串/双点域名与不可哈希 outbound 不得崩溃或写入脏规则。"""
        base = "listen: :443\noutbounds:\n  - name: direct\n    type: direct\n"
        rules = [
            {'domain': True, 'outbound': 'warp_socks'},
            {'domain': 12345, 'outbound': 'warp_socks'},
            {'domain': 'bad..domain.com', 'outbound': 'warp_socks'},
            {'domain': 'good.example.com', 'outbound': ['bad']},
        ]
        rendered = portal.build_warp_acl_config(base, True, rules)
        self.assertNotIn('suffix:true', rendered)
        self.assertNotIn('suffix:12345', rendered)
        self.assertNotIn('bad..domain.com', rendered)
        self.assertIn('warp_socks(suffix:good.example.com)', rendered)

    def test_normalize_route_rules_rejects_non_string_domains_double_dots_and_dirty_outbound(self):
        """normalize_route_rules 仅接受合法字符串域名并过滤双点，且清洗非字符串/非法 outbound。"""
        got = portal.normalize_route_rules([
            {'domain': True, 'outbound': 'direct'},
            {'domain': 123, 'outbound': 'direct'},
            {'domain': 'a..b.com', 'outbound': 'direct'},
            {'domain': 'ok.example.com', 'outbound': ['bad']},
            {'domain': 'ok2.example.com', 'outbound': 'bad\nname'},
        ])
        self.assertEqual(got, [
            {'domain': 'ok.example.com', 'outbound': 'warp_socks'},
            {'domain': 'ok2.example.com', 'outbound': 'warp_socks'},
        ])

    def test_render_egress_config_falls_back_when_custom_outbounds_are_unrenderable(self):
        """全局模式下若自定义出站均损坏不可渲染，绝不可生成指向不存在出站的悬空 global ACL。"""
        base = "listen: :443\noutbounds:\n  - name: direct\n    type: direct\n"
        state = {
            'warp_enabled': False,
            'outbound_mode': 'global',
            'custom_outbounds': [
                {'name': 'broken_socks', 'type': 'socks5', 'addr': 'not-a-host-port'},
            ],
            'warp_rules': [
                {'domain': 'a.example.com', 'outbound': 'broken_socks'},
            ],
        }
        rendered = portal.render_egress_config(base, state)
        self.assertNotIn('broken_socks(all)', rendered)
        self.assertNotIn('broken_socks(suffix:', rendered)
        self.assertIn('- direct(all)', rendered)

    def test_routing_state_and_render_egress_config_handle_non_dict_inputs(self):
        """routing_state 与 render_egress_config 面对非字典入参应安全降级而不抛 AttributeError。"""
        self.assertEqual(portal.routing_state(None)['outbound_mode'], 'rules')
        base = "listen: :443\noutbounds:\n  - name: direct\n    type: direct\n"
        rendered = portal.render_egress_config(base, None)
        self.assertIn('- direct(all)', rendered)


if __name__ == '__main__':
    unittest.main()
