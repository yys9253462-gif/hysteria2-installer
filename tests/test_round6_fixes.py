"""第五轮测试（2026-10-28）发现的缺陷及其修复的回归测试。

覆盖三组修复：
1. 🔴 30 秒连接死线杀死所有慢端点（P1，功能性缺陷）
   - ThreadingHTTPServer 新增 extend_deadline()，慢端点在开跑前续期；
   - Handler 新增 _extend_deadline() 辅助方法；
   - install-gost / install-xray / install-warp / install-amneziawg /
     manage-amneziawg(set_line|update|peer_add) / do-upgrade(portal|awg) /
     speedtest / unlock-check 都必须在慢路径上调用它。
2. AWG endpoint 注入客户端配置（P3，安全）
   - VALID_AWG_ENDPOINT_RE 禁止换行/空白进入 render_client_config；
   - portal 侧三个入口（install-amneziawg / manage-amneziawg peer_add /
     GET awg-conf）都校验；awgctl.sh 侧 validate_endpoint 纵深防御。
3. 测试资产陈旧与错误信息质量（P2/P4）
   - regression-round1-static.sh 第 7 项不再对已迁移的调用点误报；
   - install-warp 失败时不再出现「安装失败: 安装失败」这种零信息报错；
   - 500 响应里的 str(e) 收敛为「异常类型 + 截断消息」。
"""
import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
AWGCTL_SRC = (ROOT / 'awgctl.sh').read_text(encoding='utf-8')
REG_SH_SRC = (ROOT / 'tests' / 'regression-round1-static.sh').read_text(encoding='utf-8')
TREE = ast.parse(PORTAL_SRC)

import sys
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class DeadlineExtensionTest(unittest.TestCase):
    """P1：慢端点必须在开跑前续期连接死线。"""

    def test_server_has_extend_deadline(self):
        self.assertIn('def extend_deadline(self, request, seconds):', PORTAL_SRC)

    def test_handler_has_extend_deadline_helper(self):
        self.assertIn('def _extend_deadline(self, seconds):', PORTAL_SRC)

    def test_extend_deadline_extends_not_shortens(self):
        """续期只能把死线往后推，不能把它缩短（max 语义）。"""
        src = ast.get_source_segment(PORTAL_SRC, TREE) or PORTAL_SRC
        m = re.search(
            r'def extend_deadline\(self, request, seconds\):.*?'
            r'self\.deadlines\[request\] = max\(self\.deadlines\[request\],\s*'
            r'time\.monotonic\(\) \+ seconds\)', PORTAL_SRC, re.S)
        self.assertIsNotNone(m, 'extend_deadline 必须用 max() 保证只延不缩')

    def _find_handler_body(self, name):
        for node in ast.walk(TREE):
            if isinstance(node, ast.FunctionDef) and node.name == name:
                return node
        raise AssertionError('handler %s not found' % name)

    def _calls_extend(self, node):
        for sub in ast.walk(node):
            if (isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Attribute)
                    and sub.func.attr == '_extend_deadline'):
                return True
        return False

    def test_slow_post_handlers_extend_deadline(self):
        expected = ['_h_post_install_gost', '_h_post_install_xray',
                    '_h_post_install_warp', '_h_post_install_amneziawg',
                    '_h_post_do_upgrade_impl']
        missing = [n for n in expected
                   if not self._calls_extend(self._find_handler_body(n))]
        self.assertEqual(missing, [], '这些慢端点必须调用 _extend_deadline: %s' % missing)

    def test_awg_update_and_peer_add_extend_deadline(self):
        """manage-amneziawg 里 update/set_line/peer_add 三条慢路径都要续期。"""
        node = self._find_handler_body('_h_post_manage_amneziawg')
        self.assertTrue(self._calls_extend(node),
                        'manage-amneziawg 的慢路径必须调用 _extend_deadline')

    def test_speedtest_unlock_check_extend_deadline(self):
        for name in ('_h_api_speedtest', '_h_api_unlock_check'):
            node = self._find_handler_body(name)
            self.assertTrue(self._calls_extend(node),
                            '%s 必须调用 _extend_deadline' % name)

    def test_extend_deadline_is_noop_for_unknown_connection(self):
        """连接不在 deadlines 表里时（已结束/续期晚了）必须是无操作。"""
        node = self._find_handler_body('_extend_deadline')
        # Handler._extend_deadline 包 try/except：server 侧 extend_deadline
        # 内部有 `if request in self.deadlines` 守卫。两者任一存在即可。
        self.assertTrue(
            "if request in self.deadlines" in PORTAL_SRC
            or any(isinstance(sub, ast.Try) for sub in ast.walk(node)),
            '续期必须对未知连接安全（守卫或 try/except）')


class AwgEndpointValidationTest(unittest.TestCase):
    """P3：endpoint 格式校验挡住配置行注入。"""

    RE = re.compile(
        r'^[A-Za-z0-9_.\-]+(?::[0-9]{1,5})?$|^\[[0-9A-Fa-f:.]+\](?::[0-9]{1,5})?$')

    def test_regex_is_exposed(self):
        self.assertIn('VALID_AWG_ENDPOINT_RE = re.compile', PORTAL_SRC)

    def test_valid_endpoints_pass(self):
        for ep in ('vpn.example.com', '203.0.113.9', '203.0.113.9:51830',
                   'vpn.example.com:443', '[2001:db8::1]', '[2001:db8::1]:51830',
                   'a.b-c_d.example'):
            self.assertIsNotNone(self.RE.fullmatch(ep), '合法地址被误拒: %r' % ep)

    def test_injection_endpoints_rejected(self):
        payloads = [
            'evil.com\nAllowedIPs = 0.0.0.0/0',   # 换行注入（核心场景）
            'evil.com\r\nJc = 99',                  # CRLF 变体
            'a b',                                  # 空格
            'x; rm -rf /',                          # shell 元字符
            "$(reboot)",                            # 命令替换
            "a\tb",                                 # 制表符
            '',                                     # 空
        ]
        for ep in payloads:
            self.assertIsNone(self.RE.fullmatch(ep), '注入载荷未被拦截: %r' % ep)

    def test_portal_install_route_validates(self):
        self.assertRegex(
            PORTAL_SRC,
            r"VALID_AWG_ENDPOINT_RE\.fullmatch\(endpoint\)")

    def test_portal_conf_route_validates(self):
        self.assertIn("Invalid endpoint format", PORTAL_SRC)

    def test_awgctl_has_validate_endpoint(self):
        self.assertIn('validate_endpoint()', AWGCTL_SRC)
        # 三个 CLI 入口都要调用
        for cmd in ('cmd_install', 'cmd_peer_add', 'cmd_client_conf', 'cmd_qr'):
            m = re.search(r'%s\(\)\s*\{' % cmd, AWGCTL_SRC)
            self.assertIsNotNone(m, '%s 不见了' % cmd)
            body = AWGCTL_SRC[m.start():m.start() + 1500]
            self.assertIn('validate_endpoint', body,
                          '%s 必须校验 endpoint' % cmd)


class ErrorQualityTest(unittest.TestCase):
    """P2：报错必须有可定位的信息，且不无限泄漏内部异常。"""

    def test_install_warp_no_tautology(self):
        """「安装失败: 安装失败」零信息报错必须消失。"""
        self.assertNotIn("'安装失败'", PORTAL_SRC)
        self.assertIn('journalctl -u hysteria-portal -n 50', PORTAL_SRC)

    def test_500_errors_bounded(self):
        """500 响应里的 str(e) 必须带类型前缀并截断。"""
        raw = [m.start() for m in re.finditer(r"'error': str\(e\)}", PORTAL_SRC)]
        self.assertEqual(raw, [], '还有未收敛的裸 str(e) 泄漏点')
        self.assertGreaterEqual(
            len(re.findall(r"'\%s: \%s' \% \(type\(e\)\.__name__, str\(e\)\)\)\[:160\]", PORTAL_SRC)),
            5)

    def test_regression_script_no_stale_false_positive(self):
        """round1-static 第 7 项必须认识 apply_egress_config 新布局。"""
        self.assertIn('apply_egress_config', REG_SH_SRC)
        self.assertIn('applied, error = apply_egress_config(data, data_lock)', REG_SH_SRC)

    def test_stale_query_comment_removed(self):
        """误导排障的「既有端点会因 query 404」陈旧注释必须消失。"""
        self.assertNotIn('改成"全部剥 query"会改变它们的行为', PORTAL_SRC)


class DeadlineBehaviorTest(unittest.TestCase):
    """extend_deadline 的行为级验证（不依赖真实 socket）。"""

    def _make_server_cls(self):
        # 从源码提取 ThreadingHTTPServer 的方法定义，避开完整 serve() 依赖
        ns = {'threading': __import__('threading'),
              'time': __import__('time'),
              'socket': __import__('socket'),
              'HTTPServer': object, 'ThreadingMixIn': object}
        src = ast.get_source_segment(PORTAL_SRC, TREE)
        m = re.search(
            r'(class ThreadingHTTPServer.*?)(?=\n    server = ThreadingHTTPServer)',
            PORTAL_SRC, re.S)
        self.assertIsNotNone(m)
        body = '\n'.join(line[4:] if line.startswith('    ') else line
                         for line in m.group(1).splitlines())
        body = body.replace('ThreadingMixIn, HTTPServer', 'object')
        exec(compile(ast.parse(body), '<test>', 'exec'), ns)
        return ns['ThreadingHTTPServer']

    def test_extend_deadline_only_grows(self):
        cls = self._make_server_cls()
        srv = cls.__new__(cls)
        srv.deadlines = {}
        srv.deadline_lock = __import__('threading').Lock()
        import time as _t
        fake_conn = object()
        srv.deadlines[fake_conn] = _t.monotonic() + 30
        before = srv.deadlines[fake_conn]
        srv.extend_deadline(fake_conn, 600)
        after = srv.deadlines[fake_conn]
        # 续期后死线必须明显晚于原值（原死线 T0+30，新死线 ≈ T0+600，
        # 容忍测试内两次取时间的执行抖动）
        self.assertGreaterEqual(after, before + 550)
        # 缩短型续期不允许把死线拉回
        srv.extend_deadline(fake_conn, 1)
        self.assertGreaterEqual(srv.deadlines[fake_conn], after)

    def test_extend_deadline_unknown_connection_is_noop(self):
        cls = self._make_server_cls()
        srv = cls.__new__(cls)
        srv.deadlines = {}
        srv.deadline_lock = __import__('threading').Lock()
        srv.extend_deadline(object(), 600)   # 不存在 → 无操作，不抛
        self.assertEqual(srv.deadlines, {})


if __name__ == '__main__':
    unittest.main()
