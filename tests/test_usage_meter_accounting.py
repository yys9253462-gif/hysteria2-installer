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
               'user_access_denial': portal.user_access_denial}
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
