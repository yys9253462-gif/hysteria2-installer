import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORTAL_PATH = ROOT / 'portal.py'


def _load_portal_module():
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    spec = importlib.util.spec_from_file_location('portal_batch57_item1', PORTAL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class IpDenyAuthLimiterKickIplimitAndServeStartupGuardTests(unittest.TestCase):
    def test_active_ip_deny_drops_nan_inf_and_handles_unhashable_uid(self):
        mod = _load_portal_module()
        table = {
            'alice': {
                '1.1.1.1': float('nan'),
                '2.2.2.2': float('inf'),
                '3.3.3.3': 2000.0,
                123: 2000.0,
            }
        }
        res = mod.active_ip_deny(table, 'alice', 1000.0)
        self.assertEqual(res, {'3.3.3.3'})
        self.assertNotIn('1.1.1.1', table['alice'])
        self.assertNotIn('2.2.2.2', table['alice'])
        self.assertEqual(mod.active_ip_deny(table, ['unhashable'], 1000.0), set())

    def test_auth_limiter_recovers_from_clock_rollback_and_non_finite_now(self):
        mod = _load_portal_module()
        limiter = mod.AuthLimiter(per_ip_rate=2, per_ip_failures=2, failure_window=60)
        # 在 t=1000 触发失败上限
        limiter.record_failure('1.2.3.4', 1000.0)
        limiter.record_failure('1.2.3.4', 1000.0)
        self.assertTrue(limiter.limited('1.2.3.4', 1005.0))
        # 时钟回拨到 t=500，旧失败记录来自未来，必须被清理而非把用户锁死 500+60 秒
        self.assertFalse(limiter.limited('1.2.3.4', 500.0))
        # 不可哈希 key 与 NaN now 不得抛异常
        self.assertFalse(limiter.limited(['bad'], float('nan')))

    def test_kick_hy2_users_filters_non_str_uids_and_rejects_bare_string(self):
        mod = _load_portal_module()
        sent = []

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout=4):
            sent.append(json.loads(req.data.decode('utf-8')))
            return FakeResp()

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'usage-meter-config.json').write_text(
                json.dumps({'hysteria': {'url': 'http://127.0.0.1:19996', 'secret': 'sec123'}}),
                encoding='utf-8',
            )
            orig = mod.urllib.request.urlopen
            mod.urllib.request.urlopen = fake_urlopen
            try:
                # 混入 None/int 不得因 sorted() 抛 TypeError 跳过合法用户 alice
                self.assertTrue(mod.kick_hy2_users(root, [None, 123, 'alice', '']))
                # 裸字符串不应被当成字符集合拆成 ['a', 'b', 'c']
                self.assertFalse(mod.kick_hy2_users(root, 'abc'))
            finally:
                mod.urllib.request.urlopen = orig
        self.assertEqual(sent, [['alice']])

    def test_plan_reality_iplimit_handles_tuple_blocked_and_nan_timestamps(self):
        mod = _load_portal_module()
        state = {
            'alice': {
                'admitted': {'1.1.1.1': float('nan'), '2.2.2.2': 1000.0},
                'blocked': {'3.3.3.3': (900.0, 950.0), '4.4.4.4': [float('nan'), 950.0]},
            }
        }
        blocked = mod.plan_reality_iplimit(
            {'alice': 1},
            {'alice': {'2.2.2.2', '3.3.3.3'}},
            {'alice': set()},
            state,
            1010.0,
        )
        # 1.1.1.1 的 NaN 时间戳应被清除，tuple 型 blocked['3.3.3.3'] 更新时不应抛 TypeError
        self.assertNotIn('1.1.1.1', state['alice']['admitted'])
        self.assertEqual(blocked, {'alice': {'3.3.3.3'}})
        self.assertEqual(state['alice']['blocked']['3.3.3.3'][1], 1010.0)

        rules = mod.reality_iplimit_rules({'alice': {'3.3.3.3', None, 123}, None: {'1.1.1.1'}})
        self.assertEqual(len(rules), 1)

    def test_persist_interrupted_core_job_scrubs_nan_and_serve_checks_whitespace_api_key(self):
        mod = _load_portal_module()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'portal.json'
            p.write_text('{}', encoding='utf-8')
            data = {'core_upgrade': {'state': 'running'}, 'bad_num': float('nan')}
            self.assertTrue(mod.persist_interrupted_core_job(p, data))
            raw = p.read_text(encoding='utf-8')
            self.assertNotIn('NaN', raw)
            parsed = json.loads(raw)
            self.assertEqual(parsed['core_upgrade']['state'], 'interrupted')
            self.assertIsNone(parsed['bad_num'])

        src = PORTAL_PATH.read_text(encoding='utf-8')
        serve_head = src[src.index('def serve(path):'):src.index('meta_path = portal_path.parent')]
        self.assertIn("startswith('0')", serve_head)
        self.assertIn('ord(ch) <= 32', serve_head)


if __name__ == '__main__':
    unittest.main()
