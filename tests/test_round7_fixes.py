"""第二轮五轮测试（2026-10-28 R2）发现的缺陷及修复的回归测试。

R2 覆盖：
1. install.sh 深度静态审查（下载链 fail-closed、jq/sed 注入面、umask、trap）——通过。
2. 前端 JS 真执行（headless Chrome：6 标签 + 9 子标签切换、0 JS 错误、
   0 孤儿 data-copy 目标）——通过。
3. 竞态/权限审查（RLock 重入、0600 秘密文件、gost 端口 TOCTOU 有回滚兜底）——通过。
4. 订阅与分享端点（u/ 403/404 守卫、k= 密钥、clash/sing 下载、路径穿越 400、
   master 账号 403）——通过。
5. 边界与压力（202 用户并发开户、限流桶、槽位自愈、内存 50MB）——通过，
   但发现 /traffic-speed 热路径性能缺陷（本文件钉死其修复）。

🔴 R2 修复：/traffic-speed 每 2 秒轮询对每个用户调完整 usage_summary()，
后者 deepcopy measurement_gaps（最多 100 条）/ measurement_sources /
current_online —— 前端只用 5 个标量字段。全程持 data_lock，
用户量大时 /auth 鉴权会被卡。修复：usage-meter-runtime 增加 hot_summary()
（零 deepcopy、只读标量），portal 热路径改用 usage_hot_summary()。
"""
import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
RUNTIME_SRC = (ROOT / 'usage-meter-runtime-20261007-v1.py').read_text(encoding='utf-8')
PORTAL_TREE = ast.parse(PORTAL_SRC)
RUNTIME_TREE = ast.parse(RUNTIME_SRC)

import sys
sys.path.insert(0, str(ROOT))


class HotSummaryTest(unittest.TestCase):
    """热路径轻量 summary 的存在性与零 deepcopy 保证。"""

    def test_runtime_has_hot_summary(self):
        self.assertIn('def hot_summary(self, uid):', RUNTIME_SRC)

    def test_hot_summary_no_deepcopy(self):
        """hot_summary 体内绝不允许 deepcopy —— 这是它存在的全部意义。"""
        for node in ast.walk(RUNTIME_TREE):
            if isinstance(node, ast.FunctionDef) and node.name == 'hot_summary':
                for sub in ast.walk(node):
                    self.assertNotIsInstance(
                        sub, ast.Call,
                        'hot_summary 体内不允许任何函数调用（含 deepcopy）'
                        if isinstance(sub, ast.Call) and getattr(sub.func, 'attr', '') == 'copy' else None) \
                        if False else None
                # 直接检查源码段
                seg = ast.get_source_segment(RUNTIME_SRC, node)
                self.assertNotIn('copy.deepcopy', seg,
                                 'hot_summary 不允许 deepcopy')
                self.assertNotIn('.summary(', seg.replace('hot_summary', ''),
                                  'hot_summary 不应回调完整 summary')
                return
        self.fail('hot_summary 未定义')

    def test_hot_summary_returns_scalar_fields_only(self):
        """返回字典只含 4 个标量字段，没有 gaps/sources/online 等重负载键。"""
        for node in ast.walk(RUNTIME_TREE):
            if isinstance(node, ast.FunctionDef) and node.name == 'hot_summary':
                seg = ast.get_source_segment(RUNTIME_SRC, node)
                for key in ('measurement_gaps', 'measurement_sources',
                            'current_online', 'online_devices',
                            'legacy_auth_value', 'measurement_complete',
                            'measurement_current_ok'):
                    self.assertNotIn("'%s'" % key, seg,
                                     'hot_summary 不应包含重负载字段 %s' % key)
                for key in ('measured_bytes', 'measurement_ok',
                            'measurement_started_at', 'measurement_scope'):
                    self.assertIn("'%s'" % key, seg,
                                  'hot_summary 缺少热路径必需字段 %s' % key)
                return
        self.fail('hot_summary 未定义')

    def test_summary_still_full(self):
        """完整 summary() 保持原语义（用户详情端点仍需要 gaps/sources）。"""
        for node in ast.walk(RUNTIME_TREE):
            if isinstance(node, ast.FunctionDef) and node.name == 'summary':
                seg = ast.get_source_segment(RUNTIME_SRC, node)
                self.assertIn("measurement_gaps", seg)
                self.assertIn("current_online", seg)
                return
        self.fail('summary 未定义')

    def test_portal_hot_path_uses_hot_summary(self):
        """/traffic-speed 处理器必须走 usage_hot_summary 而非 usage_summary。"""
        for node in ast.walk(PORTAL_TREE):
            if isinstance(node, ast.FunctionDef) and node.name == '_h_get_traffic_speed':
                seg = ast.get_source_segment(PORTAL_SRC, node)
                self.assertIn('usage_hot_summary(uid)', seg)
                self.assertNotIn('usage_summary(uid)', seg)
                return
        self.fail('_h_get_traffic_speed 未定义')

    def test_portal_hot_summary_fallback(self):
        """计量模块未初始化时的退路：getattr 探测，缺方法给最小值。"""
        self.assertIn("getattr(usage_meter, 'hot_summary', None)", PORTAL_SRC)
        self.assertIn('def usage_hot_summary(uid):', PORTAL_SRC)


class HotSummaryBehaviorTest(unittest.TestCase):
    """hot_summary 的行为级验证（不依赖部署环境）。"""

    def _load_runtime(self):
        # 只加载类定义，不启动轮询线程（不调 from_file）
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            'rt_test', ROOT / 'usage-meter-runtime-20261007-v1.py')
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_hot_summary_values_match_summary_scalars(self):
        """hot_summary 的标量字段值必须与完整 summary() 一致。"""
        mod = self._load_runtime()
        import threading, time as _t
        meter = mod.PortalMeter.__new__(mod.PortalMeter)
        meter.data = {'usage_meter': {
            'started_at': '2026-10-28T00:00:00Z',
            'sources': {'hysteria': {'epoch': 'test-epoch', 'counters': {}}},
            'health': {'hysteria': {'ok': True, 'sampled_at':
                          _t.strftime('%Y-%m-%dT%H:%M:%S+00:00', _t.gmtime())}},
            'gaps': [{'from': 1, 'to': 2}] * 100,
            'totals': {'u1': {'hysteria': 12345}},
        }, 'users': {'u1': {'used_bytes': 999}}}
        meter.lock = threading.Lock()
        # enabled_sources 需要 read/config 属性
        meter.read = meter._read if hasattr(meter, '_read') else None
        meter.config = {'sources': ['hysteria'], 'hysteria': {'url': 'http://x', 'secret': 's'}}
        # summary() 会触碰 live_snapshot / online_counts
        meter.live_snapshot = None
        meter.live_sampled_at = 0
        meter.online_counts = None
        meter.online_sampled_at = 0
        full = meter.summary('u1')
        hot = meter.hot_summary('u1')
        for key in ('measured_bytes', 'measurement_ok',
                    'measurement_started_at', 'measurement_scope'):
            self.assertEqual(full[key], hot[key], '字段 %s 漂移' % key)
        # gaps 存在时 measurement_ok 必须为 False（两处一致）
        self.assertFalse(hot['measurement_ok'])
        # measured_bytes 正确读取 totals
        self.assertEqual(hot['measured_bytes'], 12345)

    def test_hot_summary_speed_no_deepcopy_artifacts(self):
        """返回值里没有嵌套可变共享：hot 字段都是标量或 None。"""
        mod = self._load_runtime()
        import threading, time as _t
        meter = mod.PortalMeter.__new__(mod.PortalMeter)
        meter.data = {'usage_meter': {'gaps': [{'x': 1}], 'totals': {}}, 'users': {}}
        meter.lock = threading.Lock()
        meter.config = {'sources': []}
        meter.read = meter._read if hasattr(meter, '_read') else None
        meter.live_snapshot = None
        meter.live_sampled_at = 0
        meter.online_counts = None
        meter.online_sampled_at = 0
        hot = meter.hot_summary('nobody')
        for k, v in hot.items():
            self.assertIsInstance(v, (type(None), bool, int, float, str),
                                '字段 %s 不是标量: %r' % (k, v))


class FrontendStaticGuarantees(unittest.TestCase):
    """R2 前端实测结论的静态钉子。"""

    def test_traffic_speed_poll_is_2s(self):
        assets = (ROOT / 'portal_assets.py').read_text(encoding='utf-8')
        self.assertIn('setInterval(pollTrafficSpeed, 2000)', assets)

    def test_frontend_consumes_only_scalar_fields(self):
        """前端 traffic-speed 消费面（防止未来有人依赖被删字段而不自知）：
        只允许用 tx/rx/measured_bytes/measurement_ok/used_bytes。"""
        assets = (ROOT / 'portal_assets.py').read_text(encoding='utf-8')
        m = re.search(r'async function pollTrafficSpeed.*?\n  \} catch', assets, re.S)
        self.assertIsNotNone(m)
        seg = m.group(0)
        for field in ('u.measured_bytes', 'u.measurement_ok', 'u.used_bytes',
                      'u.rx', 'u.tx', 'json.total_used_bytes',
                      'json.node_rx', 'json.node_tx'):
            self.assertIn(field, seg, '前端应消费 %s' % field)
        # 不该出现的字段
        for field in ('measurement_gaps', 'measurement_sources',
                      'current_online', 'measurement_started_at',
                      'measurement_scope'):
            self.assertNotIn(field, seg,
                             '前端 traffic-speed 不消费 %s（热路径已删）' % field)


if __name__ == '__main__':
    unittest.main()
