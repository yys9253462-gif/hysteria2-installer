"""订阅链接端口解析测试。

来源事故：**用户拿到面板生成的 Clash 订阅链接，在 Clash Verge 里导入失败。**
订阅地址指向 `ushy.teyir.com:8443`，但那台机器上**根本没有 8443 在监听**，
客户端只报一句笼统的「订阅导入失败」，用户完全无从下手。

根因：面板多处用 `m.get("subscription_port", 8443)` 取订阅端口 ——
一旦 `client_meta.json` 里缺这个键（历史遗留 / 手工改过），就兜底成 **8443**。
但 8443 在本项目的端口分配里是**被主动避开**的黑名单成员，
所以这个兜底值在真实部署里**几乎总是错的**。

正确做法：订阅端口的权威来源是 masquerade 的 `listenHTTPS`
（订阅/门户的公网入口就是它），缺失时应回落到它，而不是伪造一个 8443。

本文件锁死这条不变量：**解析结果永远不等于伪造的 8443（除非它真是监听端口）。**
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal


CONFIG_TEMPLATE = """listen: :40401
acme:
  domains:
    - ushy.teyir.com
  type: http
auth:
  type: http
  http:
    url: http://127.0.0.1:34877/auth

masquerade:
  type: proxy
  proxy:
    url: http://127.0.0.1:34877/
    rewriteHost: false
  listenHTTPS: :{port}

obfs:
  type: salamander
  salamander:
    password: "deadbeef"
"""


class SubscriptionPortTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = Path(self.tmp.name) / 'config.yaml'

    def _write_config(self, port):
        self.cfg.write_text(CONFIG_TEMPLATE.format(port=port), encoding='utf-8')

    # ---- read_masquerade_port -------------------------------------------

    def test_reads_plain_listenhttps(self):
        self._write_config(11690)
        self.assertEqual(portal.read_masquerade_port(str(self.cfg)), 11690)

    def test_reads_listenhttps_with_bind_address(self):
        """listenHTTPS 可以写成 `0.0.0.0:11690`，要取端口那一段。"""
        self.cfg.write_text(
            'masquerade:\n  listenHTTPS: 0.0.0.0:11690\n', encoding='utf-8')
        self.assertEqual(portal.read_masquerade_port(str(self.cfg)), 11690)

    def test_trailing_comment_is_ignored(self):
        """YAML 行尾注释合法：`:11690  # 订阅端口` 也要读出 11690（2026-11-12 修）。"""
        for line in ('  listenHTTPS: :11690  # 订阅端口\n', '  listenHTTPS: ":11690" # sub\n',
                     '  listenHTTPS: 0.0.0.0:11690\t# tab\n'):
            with self.subTest(line=line):
                self.cfg.write_text('masquerade:\n' + line, encoding='utf-8')
                self.assertEqual(portal.read_masquerade_port(str(self.cfg)), 11690)

    def test_commented_out_line_is_skipped(self):
        self.cfg.write_text('masquerade:\n  # listenHTTPS: :1111\n  listenHTTPS: :11690\n',
                            encoding='utf-8')
        self.assertEqual(portal.read_masquerade_port(str(self.cfg)), 11690)

    def test_missing_file_returns_none(self):
        self.assertIsNone(portal.read_masquerade_port(str(self.cfg)))

    def test_no_listenhttps_returns_none(self):
        self.cfg.write_text('listen: :40401\n', encoding='utf-8')
        self.assertIsNone(portal.read_masquerade_port(str(self.cfg)))

    # ---- resolve_subscription_port --------------------------------------

    def test_explicit_value_wins(self):
        """client_meta 里有显式值时，它就是权威，不去读 config.yaml。"""
        self._write_config(11690)
        port, src = portal.resolve_subscription_port(
            {'subscription_port': 21000}, str(self.cfg))
        self.assertEqual(port, 21000)
        self.assertEqual(src, 'client_meta')

    def test_missing_key_falls_back_to_config_yaml(self):
        """🔴 核心回归：缺键时**不能**返回 8443，要读 masquerade 的真实端口。"""
        self._write_config(11690)
        port, src = portal.resolve_subscription_port({}, str(self.cfg))
        self.assertEqual(port, 11690)
        self.assertNotEqual(port, 8443, '缺键时绝不能伪造 8443')
        self.assertEqual(src, 'config.yaml')

    def test_missing_key_with_commented_config_line_does_not_fall_back_to_443(self):
        self.cfg.write_text('masquerade:\n  listenHTTPS: :11690  # 订阅端口\n', encoding='utf-8')
        self.assertEqual(portal.resolve_subscription_port({}, str(self.cfg)), (11690, 'config.yaml'))

    def test_explicit_value_as_string_is_accepted(self):
        """JSON 里可能是字符串形式，要能容错。"""
        port, _ = portal.resolve_subscription_port(
            {'subscription_port': '11690'}, str(self.cfg))
        self.assertEqual(port, 11690)

    def test_invalid_explicit_value_falls_through(self):
        """显式值是垃圾（0 / 超范围 / 非数字）时，要往下找，不能原样返回。"""
        self._write_config(11690)
        for bad in (0, 70000, 'abc', '', None):
            with self.subTest(bad=bad):
                port, src = portal.resolve_subscription_port(
                    {'subscription_port': bad}, str(self.cfg))
                self.assertEqual(port, 11690)
                self.assertEqual(src, 'config.yaml')

    def test_both_sources_missing_does_not_return_8443(self):
        """两处都读不到时，也**不该**返回伪造的 8443。"""
        port, src = portal.resolve_subscription_port({}, str(self.cfg))
        self.assertNotEqual(port, 8443)
        self.assertEqual(src, 'fallback')

    def test_none_meta_is_tolerated(self):
        """传 None 不能崩（历史调用点可能给 None）。"""
        self._write_config(11690)
        port, _ = portal.resolve_subscription_port(None, str(self.cfg))
        self.assertEqual(port, 11690)

    def test_8443_only_when_it_really_is_the_listen_port(self):
        """反过来：如果 masquerade 真的监听 8443，那就该返回 8443。"""
        self._write_config(8443)
        port, src = portal.resolve_subscription_port({}, str(self.cfg))
        self.assertEqual(port, 8443)
        self.assertEqual(src, 'config.yaml')


if __name__ == '__main__':
    unittest.main()
