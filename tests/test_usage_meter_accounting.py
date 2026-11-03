"""真实累计同步、实际采样间隔、可选来源与持久化回滚回归测试。"""
import ast
import copy
import importlib.util
from pathlib import Path
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def _real_safe_int():
    """从 portal.py 里取出真实的 _safe_int。

    🔴 不要在测试里另写一份等价实现：语义一旦漂移，测试就不再证明生产行为。
    """
    tree = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))
    node = next(n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == '_safe_int')
    mod = ast.Module(body=[node], type_ignores=[])
    ast.fix_missing_locations(mod)
    env = {}
    exec(compile(mod, '<safe_int>', 'exec'), env)
    return env['_safe_int']
spec = importlib.util.spec_from_file_location('meter_runtime_test', ROOT / 'usage-meter-runtime-20261007-v1.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class MeterAccountingTest(unittest.TestCase):
    def setUp(self):
        self.data = {'users': {'admin_master': {'used_bytes': 99, 'limit_bytes': 1024, 'password': 'unchanged'}}}
        self.counters = {'hysteria': {'admin_master': {'tx': 0, 'rx': 0}}, 'reality': {}}
        self.samples = []
        self.meter = runtime.PortalMeter(
            self.data, threading.RLock(), lambda: None,
            {'hysteria': {'test': True}},
            read=lambda source, cfg: copy.deepcopy(self.counters[source]),
            epoch=lambda service: 'epoch-1', on_speed=lambda *args: self.samples.append(args))

    def test_corrupt_user_cursor_rebases_without_double_counting(self):
        for old in ({}, None, {'tx': -1, 'rx': 0}):
            with self.subTest(old=old):
                state = {'sources': {'hysteria': {'epoch': 'e', 'counters': {'u': old}}},
                         'totals': {'u': {'hysteria': 100}}}
                result = runtime.core.apply_sample(state, 'hysteria', 'e',
                                                   {'u': {'tx': 15, 'rx': 4}}, 10)
                self.assertEqual(state['totals']['u']['hysteria'], 100)
                self.assertEqual(result['deltas'], {})
                self.assertEqual(state['gaps'][-1]['reason'], 'corrupt_cursor_rebased')
                runtime.core.apply_sample(state, 'hysteria', 'e',
                                          {'u': {'tx': 17, 'rx': 5}}, 11)
                self.assertEqual(state['totals']['u']['hysteria'], 103)

    def test_real_total_updates_display_and_quota_preserving_legacy(self):
        self.meter.poll()
        self.counters['hysteria']['admin_master'] = {'tx': 1048576, 'rx': 2097152}
        self.meter.poll()
        user = self.data['users']['admin_master']
        self.assertEqual(user['used_bytes'], 3145728)
        self.assertGreaterEqual(user['used_bytes'], user['limit_bytes'])
        self.assertEqual(user['legacy_auth_value'], 99)
        self.assertEqual(user['password'], 'unchanged')
        self.assertEqual(self.meter.summary('admin_master')['measured_bytes'], user['used_bytes'])
        self.meter.poll()
        self.assertEqual(user['used_bytes'], 3145728)
        self.assertEqual(self.samples[-1][1:3], (0, 0))

    def test_actual_interval_and_idle_zero(self):
        with patch.object(runtime.time, 'monotonic', side_effect=[100, 105, 112]):
            self.meter.poll()
            self.counters['hysteria']['admin_master']['tx'] = 5 * 1048576
            self.meter.poll()
            self.meter.poll()
        self.assertEqual(self.samples[0][3:], (5, 'hysteria'))
        self.assertEqual(self.samples[0][1] / self.samples[0][3], 1048576)
        self.assertEqual(self.samples[1][1:4], (0, 0, 7))

    def test_disconnected_user_gets_a_zero_speed_sample(self):
        """断开（从计数里消失）的用户补一个 0 速样本，不在 15 秒里继续显示旧网速（2026-11-04 修）。"""
        with patch.object(runtime.time, 'monotonic', side_effect=[100, 105, 110]):
            self.meter.poll()
            self.counters['hysteria']['admin_master']['tx'] = 5 * 1048576
            self.meter.poll()
            self.counters['hysteria'].pop('admin_master')
            self.meter.poll()
        self.assertEqual(self.samples[-1][0], 'admin_master')
        self.assertEqual(self.samples[-1][1:3], (0, 0), self.samples)

    def test_recent_gap_cache_distinguishes_same_length_and_last_timestamp(self):
        recent = '2026-10-30T00:00:00+00:00'
        old = '2000-01-01T00:00:00+00:00'
        with patch.object(runtime.time, 'time', return_value=1793404800):
            first = {'gaps': [{'at': old}, {'at': old}]}
            second = {'gaps': [{'at': recent}, {'at': old}]}
            self.assertEqual(runtime._recent_gaps(first), [])
            self.assertEqual(runtime._recent_gaps(second), [{'at': recent}])

    def test_old_gap_is_incomplete_but_current_health_can_recover(self):
        self.meter.poll()
        self.data['usage_meter']['gaps'] = [{'source': 'hysteria', 'at': '2000-01-01T00:00:00+00:00',
                                             'reason': 'service_restart_unsampled_tail_unknown'}]
        summary = self.meter.summary('admin_master')
        self.assertTrue(summary['measurement_ok'])
        self.assertTrue(summary['measurement_current_ok'])
        self.assertFalse(summary['measurement_complete'])

    def test_optional_reality_and_no_sources(self):
        self.meter.poll()
        self.assertTrue(self.meter.summary('admin_master')['measurement_ok'])
        self.meter.config = {}
        self.assertFalse(self.meter.summary('admin_master')['measurement_ok'])
        self.assertIsNone(self.meter.summary('admin_master')['measured_bytes'])

    def test_hysteria_online_instances_are_exposed_separately(self):
        """核心 /online 是实例数，不冒充 IP 数，也不包含 Reality。"""
        online = {'admin_master': 2}
        self.meter.config['hysteria'] = {'url': 'http://127.0.0.1:19996',
                                         'secret': 'test'}
        self.meter.read = self.meter._read
        with patch.object(runtime.readers, 'read_hysteria',
                          return_value={'admin_master': {'tx': 0, 'rx': 0}}), \
             patch.object(runtime.readers, 'read_hysteria_online', return_value=online), \
             patch.object(runtime.readers, 'service_epoch', return_value='epoch-1'):
            self.meter.epoch = runtime.readers.service_epoch
            self.meter.poll()
        summary = self.meter.summary('admin_master')
        self.assertEqual(summary['online_devices'], 2)
        self.assertEqual(summary['online_devices_scope'],
                         'hysteria_core_instances_only')

    def test_hysteria_online_failure_is_unknown_not_zero(self):
        self.meter.config['hysteria'] = {'url': 'http://127.0.0.1:19996',
                                         'secret': 'test'}
        self.meter.read = self.meter._read
        with patch.object(runtime.readers, 'read_hysteria',
                          return_value={'admin_master': {'tx': 0, 'rx': 0}}), \
             patch.object(runtime.readers, 'read_hysteria_online',
                          side_effect=OSError('unavailable')), \
             patch.object(runtime.readers, 'service_epoch', return_value='epoch-1'):
            self.meter.epoch = runtime.readers.service_epoch
            self.meter.poll()
        self.assertIsNone(self.meter.summary('admin_master')['online_devices'])

    def test_default_reader_skips_uninstalled_xray(self):
        self.meter.read = self.meter._read
        self.meter.config['reality'] = {'binary': str(ROOT / 'nonexistent-xray')}
        self.assertEqual(self.meter.enabled_sources(), ['hysteria'])

    def test_upgrade_preserves_existing_totals_without_requiring_absent_xray(self):
        # 真实旧部署：Hy2 已采集累计，Reality 未安装，used_bytes 却仍为 0。
        self.meter.poll()
        self.counters['hysteria']['admin_master']['tx'] = 12345
        self.meter.poll()
        self.data['users']['admin_master']['used_bytes'] = 0
        self.data['usage_meter']['health']['reality'] = {'ok': False, 'error': 'RuntimeError'}
        with patch.object(runtime.readers, 'read_hysteria', return_value=self.counters['hysteria']):
            upgraded = runtime.PortalMeter(self.data, threading.RLock(), lambda: None,
                {'hysteria': {'url': 'http://127.0.0.1:19996', 'secret': 'test'},
                 'reality': {'binary': str(ROOT / 'nonexistent-xray')}}, epoch=lambda _: 'epoch-1')
            upgraded.poll()
            summary = upgraded.summary('admin_master')
        self.assertTrue(summary['measurement_ok'])
        self.assertEqual(summary['measured_bytes'], 12345)
        self.assertEqual(self.data['users']['admin_master']['used_bytes'], 12345)
        self.assertNotIn('reality', summary['measurement_sources'])
        self.assertEqual(self.data['users']['admin_master']['password'], 'unchanged')

    def test_deleted_user_counter_is_not_recreated_or_charged_on_recreation(self):
        self.meter.poll()
        self.counters['hysteria']['admin_master'] = {'tx': 100, 'rx': 0}
        self.meter.poll()
        self.assertEqual(self.data['users']['admin_master']['used_bytes'], 100)
        del self.data['users']['admin_master']
        portal_module = __import__('portal')
        portal_module.drop_meter_totals(self.data, 'admin_master')
        self.data['usage_meter'].setdefault('sources', {}).setdefault('hysteria', {})
        self.data['usage_meter']['sources']['hysteria']['counters'] = {'admin_master': {'tx': 100, 'rx': 0}}
        self.counters['hysteria']['admin_master'] = {'tx': 120, 'rx': 0}
        self.meter.poll()
        self.assertNotIn('admin_master', self.data['usage_meter']['totals'])
        portal_module.restore_meter_user(self.data, 'admin_master')
        self.data['users']['admin_master'] = {'used_bytes': 0, 'limit_bytes': 1000,
                                              'status': 'active', 'expires_at': 9999999999}
        self.counters['hysteria']['admin_master'] = {'tx': 150, 'rx': 0}
        self.meter.poll()
        self.assertEqual(self.data['users']['admin_master']['used_bytes'], 30)
        self.assertEqual(self.data['usage_meter']['totals']['admin_master']['hysteria'], 30)

    def test_disabled_users_are_not_charged_while_retaining_counter_cursor(self):
        self.meter.poll()
        self.counters['hysteria']['admin_master'] = {'tx': 100, 'rx': 0}
        self.meter.poll()
        self.data['users']['admin_master']['status'] = 'disabled'
        self.meter.user_allowed = lambda user: user.get('status') == 'active'
        self.counters['hysteria']['admin_master'] = {'tx': 140, 'rx': 0}
        self.meter.poll()
        self.assertEqual(self.data['users']['admin_master']['used_bytes'], 100)
        self.assertEqual(self.data['usage_meter']['sources']['hysteria']['counters']['admin_master']['tx'], 140)
        self.data['users']['admin_master']['status'] = 'active'
        self.counters['hysteria']['admin_master'] = {'tx': 150, 'rx': 0}
        self.meter.poll()
        self.assertEqual(self.data['users']['admin_master']['used_bytes'], 100)
        self.counters['hysteria']['admin_master'] = {'tx': 160, 'rx': 0}
        self.meter.poll()
        self.assertEqual(self.data['users']['admin_master']['used_bytes'], 110)

    def test_over_quota_traffic_is_still_metered(self):
        """超额后仍在跑的流量要记账（2026-11-03 修）。

        撤销有延迟或失败时，超额用户的会话还开着。旧实现按 user_access_allowed
        判定，超额即「停用」，这段流量从不进 used_bytes；续费后第一次采样又被当作
        新基线，永久丢失。用门户实际接进计量的判据跑。
        """
        portal_module = __import__('portal')
        self.meter.user_allowed = portal_module.user_metered
        self.data['users']['admin_master'].update(limit_bytes=100, status='active')
        self.meter.poll()
        self.counters['hysteria']['admin_master'] = {'tx': 100, 'rx': 0}
        self.meter.poll()
        self.assertEqual(self.data['users']['admin_master']['used_bytes'], 100)
        self.assertFalse(portal_module.user_access_allowed(self.data['users']['admin_master']))
        self.counters['hysteria']['admin_master'] = {'tx': 160, 'rx': 0}
        self.meter.poll()
        self.assertEqual(self.data['users']['admin_master']['used_bytes'], 160,
                         '超额之后的流量没有记账')
        # 停用的用户照旧不记账。
        self.data['users']['admin_master']['status'] = 'disabled'
        self.counters['hysteria']['admin_master'] = {'tx': 200, 'rx': 0}
        self.meter.poll()
        self.assertEqual(self.data['users']['admin_master']['used_bytes'], 160)

    def test_retired_users_are_forgotten_once_no_source_holds_their_cursor(self):
        """retired_users 不能只增不减（2026-11-03 修）。

        已删用户只要还有数据源留着它的游标就得记住（防止同名重建时把旧计数算进去）；
        服务重启换了 epoch、游标清空后就该忘掉，否则按订单开号删号的节点无界增长。
        """
        portal_module = __import__('portal')
        self.meter.user_allowed = portal_module.user_metered
        self.meter.poll()
        self.data['users']['gone'] = {'password': 'x', 'status': 'active'}
        self.counters['hysteria']['gone'] = {'tx': 50, 'rx': 0}
        self.meter.poll()
        del self.data['users']['gone']
        portal_module.drop_meter_totals(self.data, 'gone')
        self.meter.poll()
        self.assertIn('gone', self.data['usage_meter']['retired_users'], '游标还在时必须记住')
        # 服务重启：新 epoch，计数器里不再有这个用户。
        self.counters['hysteria'].pop('gone')
        self.meter.epoch = lambda service: 'epoch-after-restart'
        self.meter.poll()
        self.assertNotIn('gone', self.data['usage_meter'].get('retired_users', []))

    def test_online_counts_and_their_timestamp_change_together_under_the_lock(self):
        """在线计数与采样时间要在锁内一起换掉（2026-11-04 修）。

        旧实现分两句在锁外赋值，summary() 落在两句之间时拿到 None 计数配新时间，
        在 .get 上抛 AttributeError，用户页 500。这里记录每次赋值时锁是否被持有。
        """
        held = []

        class TrackingLock:
            def __init__(self):
                self.inner = threading.RLock()
                self.depth = 0
            def __enter__(self):
                self.inner.acquire()
                self.depth += 1
            def __exit__(self, *exc):
                self.depth -= 1
                self.inner.release()
                return False

        lock = TrackingLock()
        meter = runtime.PortalMeter(self.data, lock, lambda: None, {'hysteria': {'url': 'http://127.0.0.1:1', 'secret': 's'}},
                                    on_speed=lambda *a: None)
        cls = type(meter)

        class Watched(cls):
            def __setattr__(self, name, value):
                if name in ('online_counts', 'online_sampled_at') and hasattr(self, 'online_sampled_at'):
                    held.append(lock.depth > 0)
                object.__setattr__(self, name, value)

        meter.__class__ = Watched
        orig_read, orig_online = runtime.readers.read_hysteria, runtime.readers.read_hysteria_online
        runtime.readers.read_hysteria = lambda url, secret: {}
        try:
            runtime.readers.read_hysteria_online = lambda url, secret: {'u': 1}
            meter._read('hysteria', {'url': 'http://127.0.0.1:1', 'secret': 's'})
            def boom(url, secret):
                raise OSError('down')
            runtime.readers.read_hysteria_online = boom
            meter._read('hysteria', {'url': 'http://127.0.0.1:1', 'secret': 's'})
        finally:
            runtime.readers.read_hysteria, runtime.readers.read_hysteria_online = orig_read, orig_online
        self.assertTrue(held)
        self.assertTrue(all(held), '在线计数在锁外被赋值')

    def test_core_and_runtime_revision_match(self):
        self.assertEqual(runtime.core.ACCOUNTING_REVISION, runtime.ACCOUNTING_REVISION)

    def test_failed_save_rolls_back_usage_and_emits_no_speed(self):
        self.meter.poll()
        before = copy.deepcopy(self.data)
        self.counters['hysteria']['admin_master']['tx'] = 5000
        self.meter.save = lambda: (_ for _ in ()).throw(OSError('disk failure'))
        self.meter.poll()
        self.assertEqual(self.data, before)
        self.assertEqual(self.samples, [])

    def test_protocol_totals_and_restart_do_not_double_count(self):
        self.meter.config['reality'] = {'test': True}
        self.counters['reality'] = {'admin_master': {'tx': 0, 'rx': 0}}
        self.meter.poll()
        self.counters['hysteria']['admin_master']['tx'] = 10
        self.counters['reality']['admin_master']['rx'] = 20
        self.meter.poll()
        self.assertEqual(self.data['users']['admin_master']['used_bytes'], 30)
        # 门户重启保持游标，重复读取不重复计费。
        self.meter.sample_times = {}
        self.meter.poll()
        self.assertEqual(self.data['users']['admin_master']['used_bytes'], 30)

    def test_adjustment_two_sources_and_restart(self):
        self.meter.config['reality'] = {'test': True}
        self.counters['reality'] = {'admin_master': {'tx': 0, 'rx': 0}}
        self.data['usage_meter'] = {'adjustments': {'admin_master': 7}}
        self.meter.poll()
        self.counters['hysteria']['admin_master']['tx'] = 10
        self.counters['reality']['admin_master']['rx'] = 20
        self.meter.poll()
        self.assertEqual(self.data['users']['admin_master']['used_bytes'], 37)
        self.assertEqual(self.meter.summary('admin_master')['measured_bytes'], 30)
        self.assertEqual(self.meter.hot_summary('admin_master')['measured_bytes'], 30)
        self.data['usage_meter']['adjustments']['admin_master'] = -30
        restarted = runtime.PortalMeter(self.data, threading.RLock(), lambda: None,
            self.meter.config, read=self.meter.read, epoch=self.meter.epoch)
        restarted.poll()
        self.assertEqual(self.data['users']['admin_master']['used_bytes'], 0)
        self.assertEqual(restarted.summary('admin_master')['measured_bytes'], 30)

    def test_invalid_adjustment_fails_atomically_and_recovers(self):
        self.meter.poll()
        self.counters['hysteria']['admin_master']['tx'] = 10
        self.meter.poll()
        for invalid in (None, True, 1.5, '1', -12):
            with self.subTest(invalid=invalid):
                self.data['usage_meter']['adjustments'] = {'admin_master': invalid}
                before = copy.deepcopy(self.data['usage_meter']['totals'])
                self.counters['hysteria']['admin_master']['tx'] = 11
                self.meter.poll()
                self.assertEqual(self.data['users']['admin_master']['used_bytes'], 10)
                self.assertEqual(self.data['usage_meter']['totals'], before)
                self.assertFalse(self.meter.summary('admin_master')['measurement_current_ok'])
                self.assertEqual(self.meter.summary('admin_master')['measured_bytes'], 10)
                self.data['usage_meter']['adjustments']['admin_master'] = 0
                self.counters['hysteria']['admin_master']['tx'] = 10
                self.meter.poll()
        self.counters['hysteria']['admin_master']['tx'] = 11
        self.meter.poll()
        self.assertEqual(self.data['users']['admin_master']['used_bytes'], 11)
        self.assertTrue(self.meter.summary('admin_master')['measurement_current_ok'])
        for invalid in (None, [], 'bad'):
            with self.subTest(container=invalid), self.assertRaises(ValueError):
                runtime.core.adjusted_bytes({'adjustments': invalid}, 'u')

    def test_service_epoch_and_counter_regression(self):
        self.meter.poll()
        self.counters['hysteria']['admin_master']['tx'] = 10
        self.meter.poll()
        self.meter.epoch = lambda service: 'epoch-2'
        self.counters['hysteria']['admin_master']['tx'] = 3
        self.meter.poll()
        self.assertEqual(self.data['users']['admin_master']['used_bytes'], 13)
        self.counters['hysteria']['admin_master']['tx'] = 1
        self.meter.poll()
        self.assertEqual(self.data['users']['admin_master']['used_bytes'], 13)
        self.assertFalse(self.meter.summary('admin_master')['measurement_ok'])

    def test_real_portal_speed_functions_sum_sources_and_expire(self):
        tree = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))
        names = {'_meter_speed_sample', '_h_get_traffic_speed'}
        functions = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name in names]
        # 2026-10-28：热路径改走 usage_hot_summary（见 tests/test_round7_fixes.py）。
        # fixture 同步提供两个入口，行为与 meter.hot_summary / meter.summary 对齐。
        env = {'time': time, 'data_lock': threading.RLock(), 'speed_tracker': {},
               'SPEED_WINDOW_SECONDS': 15, 'data': self.data,
               # 2026-10-31：_h_get_traffic_speed 现在用 _safe_int 兜住
               # used_bytes 的 "12.5"/null/列表（否则 total_used_bytes 的
               # sum() 直接 TypeError，前端每 2 秒的主轮询整块 500）。
               # 取真实实现，别在测试里另写一份。
               '_safe_int': _real_safe_int(),
               'user_table': lambda data: (data.get('users')
                   if isinstance(data.get('users'), dict) else {}),
               'users_list_rows': lambda users: list(users.items())
                   if isinstance(users, dict) else [],
               'usage_summary': lambda uid: self.meter.summary(uid),
               'usage_hot_summary': lambda uid: self.meter.hot_summary(uid)}
        exec(compile(ast.Module(body=functions, type_ignores=[]), 'portal-speed', 'exec'), env)
        class Handler:
            path = '/fixture/check-version'
            def is_authenticated(self): return True
            def reply_json(self, code, payload): return payload
        with patch.object(time, 'monotonic', return_value=100):
            env['_meter_speed_sample']('admin_master', 5 * 1048576, 0, 5, 'hysteria')
            env['_meter_speed_sample']('admin_master', 0, 10 * 1048576, 5, 'reality')
            result = env['_h_get_traffic_speed'](Handler(), '')
        self.assertEqual(result['node_tx'], 1048576)
        self.assertEqual(result['node_rx'], 2097152)
        with patch.object(time, 'monotonic', return_value=116):
            result = env['_h_get_traffic_speed'](Handler(), '')
        self.assertEqual(result['node_tx'], 0)
        self.assertEqual(result['node_rx'], 0)

    def test_actual_auth_handler_rejects_quota_and_page_shows_real_usage(self):
        import io
        import json
        import sys
        sys.path.insert(0, str(ROOT))
        import portal
        self.data['users']['admin_master'].update(status='active', expires_at=9999999999)
        self.meter.poll()
        self.counters['hysteria']['admin_master']['tx'] = 3145728
        self.meter.poll()
        tree = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))
        auth = next(n for n in ast.walk(tree) if isinstance(n, ast.If)
                    and ast.unparse(n.test) == "self.path == '/auth'")
        fn = ast.parse('def handle(self):\n    pass').body[0]
        fn.body = [auth]
        env = {'json': json, 'time': time, 'hmac': __import__('hmac'), 'ipaddress': __import__('ipaddress'), 'live_online_ips': lambda uid: set(), 'data_lock': threading.RLock(), 'data': self.data,
               'user_table': lambda data: (data.get('users')
                   if isinstance(data.get('users'), dict) else {}),
               'user_access_denial': portal.user_access_denial,
               'user_ip_limit': portal.user_ip_limit,
               'auth_rate_key': portal.auth_rate_key}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])), 'auth-quota', 'exec'), env)
        body = json.dumps({'auth': 'unchanged', 'addr': '127.0.0.1:1234'}).encode()
        class Handler:
            client_address = ('127.0.0.1', 12345)
            path = '/auth'
            headers = {'Content-Length': str(len(body))}
            rfile = io.BytesIO(body)
            def auth_rate_limited(self): return False
            def reply_json(self, code, payload): return payload
        response = env['handle'](Handler())
        self.assertFalse(response['ok'])
        self.assertEqual(response['msg'], 'Traffic quota exceeded')
        meta = {'public_ip': '1.2.3.4', 'server_name': 'h.example.com',
                'subscription_port': 8443, 'listen_port': 1, 'hop_port_range': '',
                'auth_password': 'p', 'obfs_password': '', 'cert_type': 'acme',
                'is_insecure': False, 'pin_sha256': ''}
        page = portal.page_html(meta, 'hysteria2://x@h:1/', '#s', 'c', '{}',
                                users=self.data['users'], token='t', session_secret='s')
        self.assertIn('data-user-usage="admin_master">3.00 MB</span>', page)
        self.assertIn('id="total-used-bytes">3.00 MB</span>', page)

    def test_portal_self_update_includes_all_meter_modules(self):
        tree = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))
        fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                  and n.name == '_h_post_do_upgrade_impl')
        loop = next(n for n in ast.walk(fn) if isinstance(n, ast.For)
                    and isinstance(n.target, ast.Tuple)
                    and [x.id for x in n.target.elts] == ['fname', 'marker', 'minsize'])
        files = ast.literal_eval(loop.iter)
        self.assertEqual({item[0] for item in files},
                         {'portal.py', 'portal_assets.py'} |
                         {p.name for p in ROOT.glob('usage-meter-*-v1.py')})
        for name, marker, minimum in files:
            content = (ROOT / name).read_bytes()
            self.assertIn(marker, content)
            self.assertGreaterEqual(len(content), minimum)

    def test_version_endpoint_reports_all_bundle_hashes_and_running_revision(self):
        import hashlib
        import json
        import subprocess
        import urllib.request
        tree = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))
        fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                  and n.name == '_h_get_check_version')
        def blob(path):
            content = Path(path).read_bytes()
            return hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()
        import portal
        env = {'PORTAL_BUNDLE_FILES': portal.PORTAL_BUNDLE_FILES,
               'portal_bundle_version': portal.portal_bundle_version,
               '_remote_root_shas': lambda: None,
               'Path': Path, 'PORTAL_SELF': ROOT / 'portal.py', 'AWG_CTL': ROOT / 'awgctl.sh',
               '_local_blob_sha': blob, '_version_triple': lambda path, name: ('current', 'latest', True),
               '_usage_runtime': runtime, 'usage_meter': self.meter,
               'usage_summary': self.meter.summary, 'MASTER_USER_ID': 'admin_master',
               'subprocess': subprocess, 'urllib': urllib, 'json': json,
               'parse_qs': urllib.parse.parse_qs, 'time': __import__('time'),
               '_ver_cache': {'t':0}, '_core_ver_cache': {'t':0, 'tag':''}, 'core_version_key': lambda value: (), '_log_ignored': lambda where, exc: None}
        exec(compile(ast.Module(body=[fn], type_ignores=[]), 'version-bundle', 'exec'), env)
        class Handler:
            path = '/fixture/check-version'
            def is_authenticated(self): return True
            def reply_json(self, code, payload): return payload
        with patch.object(subprocess, 'run', side_effect=OSError('no binary')), \
             patch.object(urllib.request, 'urlopen', side_effect=OSError('offline')):
            result = env['_h_get_check_version'](Handler(), '')
        bundle = result['portal_bundle']
        self.assertEqual(len(bundle['files']), 6)
        self.assertEqual(bundle['files']['portal.py'], blob(ROOT / 'portal.py'))
        self.assertEqual(bundle['runtime_revision'], runtime.ACCOUNTING_REVISION)
        self.assertTrue(bundle['meter_initialized'])


if __name__ == '__main__':
    unittest.main()
