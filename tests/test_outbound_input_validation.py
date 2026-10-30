"""出站/分流配置的输入校验：坏类型必须给出可读错误，而不是 500。

这些函数被「保存出站」「添加分流规则」「应用配置」三条用户路径直接调用，
而表单值来自浏览器、旧版本还允许直接改 portal.json：
  * `.strip()` 对数字/列表抛 AttributeError → 保存 500，页面没有任何提示
  * 代理账号被 str() 成 "['x']" 后仍通过可见 ASCII 校验 → 面板说已保存，
    客户端却拿着完全不同的凭据，只报鉴权失败
  * custom_outbounds 是数字时 `for o in 7` 抛 TypeError → 添加规则 500
"""
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class ValidateOutboundInputTests(unittest.TestCase):
    def test_non_dict_entry_is_rejected_not_raised(self):
        for bad in (None, 7, 'x', ['a'], True):
            with self.subTest(bad=bad):
                ok, cleaned, error = portal.validate_outbound(bad)
                self.assertFalse(ok)
                self.assertIsNone(cleaned)
                self.assertTrue(error)

    def test_numeric_fields_are_rejected_not_raised(self):
        for entry in ({'type': 'http', 'name': 'b', 'url': 123},
                      {'type': 'http', 'name': 'b', 'url': ['http://x']},
                      {'type': 'direct', 'name': 'c', 'mode': 5},
                      {'type': 'socks5', 'name': 'd', 'addr': 12345},
                      {'type': 'socks5', 'name': 'd', 'addr': ['1.2.3.4:1080']}):
            with self.subTest(entry=entry):
                ok, cleaned, error = portal.validate_outbound(entry)
                self.assertFalse(ok, entry)
                self.assertTrue(error)

    def test_non_string_proxy_credentials_are_rejected(self):
        for field in ('username', 'password'):
            for bad in (['x'], 123, {'a': 1}, True):
                with self.subTest(field=field, bad=bad):
                    entry = {'type': 'socks5', 'name': 'e',
                             'addr': '1.2.3.4:1080', field: bad}
                    ok, _, error = portal.validate_outbound(entry)
                    self.assertFalse(ok, entry)
                    self.assertIn(field, error)

    def test_healthy_entries_still_accepted(self):
        cases = (
            {'type': 'socks5', 'name': 'p', 'addr': '1.2.3.4:1080',
             'username': 'u', 'password': 'p@ss-1'},
            {'type': 'http', 'name': 'h', 'url': 'http://1.2.3.4:8080'},
            {'type': 'direct', 'name': 'd', 'mode': '4'},
        )
        for entry in cases:
            with self.subTest(entry=entry):
                ok, cleaned, error = portal.validate_outbound(entry)
                self.assertTrue(ok, error)
                self.assertEqual(cleaned['type'], entry['type'])


class OutboundTargetLookupTests(unittest.TestCase):
    def test_corrupt_container_does_not_raise(self):
        for bad in (None, 7, 'x', [None], ['x'], True):
            with self.subTest(bad=bad):
                self.assertFalse(portal.outbound_target_exists('t', bad))
                # direct / reject 是内建名，任何时候都该成立。
                self.assertTrue(portal.outbound_target_exists('direct', bad))

    def test_configured_outbound_is_found(self):
        self.assertTrue(portal.outbound_target_exists('t', [{'name': 't'}]))


class ConfigTextHelperTests(unittest.TestCase):
    """配置文本助手对非字符串输入不能抛异常。

    这两个函数在「应用出站配置」路径上被调用：config.yaml 读取结果或拼接前的
    快照被改坏成 int/list 时，split/findall 直接抛异常，用户点「应用」就 500。
    """

    def test_outbound_names_in_tolerates_non_string(self):
        for bad in (None, 7, ['x'], {'a': 1}, True):
            with self.subTest(bad=bad):
                self.assertEqual(portal.outbound_names_in(bad), [])

    def test_strip_managed_outbounds_tolerates_non_string(self):
        for bad in (None, 7, ['x'], {'a': 1}, True):
            with self.subTest(bad=bad):
                self.assertEqual(portal.strip_managed_outbounds(bad), '')

    def test_healthy_text_still_parsed(self):
        text = ('outbounds:\n'
                '  - name: direct\n'
                '    type: direct\n')
        self.assertEqual(portal.outbound_names_in(text), ['direct'])
        self.assertEqual(portal.strip_managed_outbounds(text), text)


class AclBlockTests(unittest.TestCase):
    """acl.inline 生成对损坏的规则/出站不能抛异常。

    它在 apply_egress_config 里：异常会让「应用出站配置」永久失败，
    界面只有一句「应用失败」，而内网拦截规则也一起没写进去。
    """

    def test_corrupt_rules_are_skipped(self):
        for rules in (None, 7, 'x', [None], ['x'], [{'domain': 123}],
                      [{'domain': ['a']}], [{'domain': 'a', 'outbound': 5}]):
            with self.subTest(rules=rules):
                block = portal.build_acl_block('rules', rules, [], 'direct')
                # 内网拦截与兜底规则必须始终存在。
                self.assertIn('reject(127.0.0.0/8)', block)
                self.assertIn('direct(all)', block)

    def test_corrupt_outbounds_do_not_raise_in_global_mode(self):
        for outs in (None, 7, 'x', [None], ['x'], [{'name': 'p', 'type': 'socks5'}]):
            with self.subTest(outs=outs):
                block = portal.build_acl_block('global', [], outs, 'direct')
                self.assertIn('reject(127.0.0.0/8)', block)

    def test_healthy_rule_is_rendered(self):
        # 出站名必须真的存在：不存在时有意回落到兜底出站，避免 Hysteria
        # 引用未定义的 outbound 而起不来。
        block = portal.build_acl_block(
            'rules', [{'domain': 'ok.com', 'outbound': 'warp_socks'}], [], 'direct',
            existing_names={'warp_socks'})
        self.assertIn('warp_socks(suffix:ok.com)', block)
        missing = portal.build_acl_block(
            'rules', [{'domain': 'ok.com', 'outbound': 'gone'}], [], 'direct',
            existing_names=set())
        self.assertIn('direct(suffix:ok.com)', missing)
        self.assertNotIn('gone(', missing)


class OutboundNameSafetyTests(unittest.TestCase):
    """历史数据里带换行的出站名必须被丢弃。

    旧版本允许直接改 portal.json，这类名字会让 render_outbound_yaml 写出
    结构错乱的 YAML（后面每一行都被当成新内容），Hysteria 起不来。
    """

    def test_names_with_newlines_are_dropped(self):
        rows = [{'name': 'a\nb', 'type': 'direct'},
                {'name': 'ok', 'type': 'direct'},
                {'name': '1bad', 'type': 'direct'},
                {'name': 'x: y', 'type': 'direct'}]
        self.assertEqual(portal.clean_outbounds(rows), [{'name': 'ok', 'type': 'direct'}])

    def test_rendered_yaml_stays_single_block(self):
        cfg = portal.upsert_outbound_block(
            'listen: :443\n', [{'name': 'a\nb', 'type': 'direct'}])
        self.assertNotIn('a\nb', cfg)
        self.assertIn('listen: :443', cfg)


class WarpAclRuleTests(unittest.TestCase):
    """WARP ACL 的规则容器损坏时不能抛异常（开关/应用配置的必经路径）。"""

    def test_corrupt_rule_container_does_not_raise(self):
        for rules in (7, 'x', [None], ['x'], True):
            with self.subTest(rules=rules):
                block = portal.build_warp_acl_config('listen: :443\n', True, rules)
                self.assertIn('reject(127.0.0.0/8)', block)
                self.assertIn('(all)', block)

    def test_custom_rule_is_rendered(self):
        block = portal.build_warp_acl_config(
            'listen: :443\n', True, [{'domain': 'a.com', 'outbound': 'warp_socks'}])
        self.assertIn('warp_socks(suffix:a.com)', block)


class AclTextHelperTests(unittest.TestCase):
    """acl 文本助手对非字符串输入不能抛异常（同样在「应用配置」路径上）。"""

    def test_strip_acl_block_tolerates_non_string(self):
        for bad in (None, 7, ['x'], {'a': 1}, True):
            with self.subTest(bad=bad):
                self.assertEqual(portal.strip_acl_block(bad), '')

    def test_build_warp_acl_config_tolerates_non_string(self):
        for bad in (None, 7, ['x'], True):
            with self.subTest(bad=bad):
                block = portal.build_warp_acl_config(bad, False, [])
                self.assertIn('reject(127.0.0.0/8)', block)
                self.assertIn('(all)', block)

    def test_strip_acl_block_keeps_obfs_after_acl(self):
        # 真实事故：把 acl 之后的 obfs 段一起删掉，客户端仍带混淆 → 连上没网。
        text = ('listen: :443\n'
                'acl:\n  inline:\n    - direct(all)\n'
                'obfs:\n  type: salamander\n  salamander:\n    password: x\n')
        stripped = portal.strip_acl_block(text)
        self.assertNotIn('acl:', stripped)
        self.assertIn('obfs:', stripped)


class RoutingStateTests(unittest.TestCase):
    def test_corrupt_state_degrades_to_empty_lists(self):
        for data in ({'custom_outbounds': 7, 'warp_rules': 7, 'outbound_mode': 5},
                     {'custom_outbounds': 'x', 'warp_rules': 'x'},
                     {'custom_outbounds': [None], 'warp_rules': None},
                     {'warp_enabled': True, 'warp_rules': None}):
            with self.subTest(data=data):
                state = portal.routing_state(data)
                self.assertIsInstance(state['custom_outbounds'], list)
                self.assertIsInstance(state['warp_rules'], list)
                self.assertIsInstance(state['outbound_mode'], str)
                # 渲染必须能走完（这就是「应用配置」的实际路径）。
                portal.render_egress_config('listen: :443\n', state)

    def test_enabled_defaults_to_builtin_rules(self):
        state = portal.routing_state({'warp_enabled': True})
        self.assertTrue(state['warp_rules'])


if __name__ == '__main__':
    unittest.main()
