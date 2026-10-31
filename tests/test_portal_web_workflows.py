import ast
import copy
import io
import json
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.parse import urlencode

import sys  # noqa: E402
# 🔴 2026-10-31：CI 用的是 `python3 -m unittest discover -s tests -p 'test_*.py'`，
# 那条命令会把 CWD（仓库根）放进 sys.path；而「文档里教的、人最常敲的」
# `cd tests && python3 -m unittest test_xxx` 不会。用后一种方式时这六个文件
# 报 ModuleNotFoundError: No module named 'portal' —— 看着像代码坏了，其实是
# 加载方式差异。这里补上与其它 38 个测试一致的路径注入，两种跑法都能过。
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parents[1]))

import portal

SOURCE = Path(portal.__file__).read_text(encoding='utf-8')
TREE = ast.parse(SOURCE)


def extract_method(name, namespace):
    node = next(n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef) and n.name == name)
    module = ast.Module(body=[copy.deepcopy(node)], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), '<isolated-web-handler>', 'exec'), namespace)
    return namespace[name]


class WebWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.hdir = self.root / 'etc/hysteria'
        self.hdir.mkdir(parents=True)
        self.data = {'users': {'admin_master': {'password': 'master-test-only', 'status': 'active'}},
                     'proxy_services': [], 'reality_config': {'public_key': 'public-test-only',
                     'private_key': 'private-test-only', 'short_id': 'abcd', 'port': 8443}}
        self.meta = self.hdir / 'client_meta.json'
        self.meta.write_text(json.dumps({'server_name': 'node.example.com', 'public_ip': '203.0.113.10',
                                       'subscription_port': 29421, 'listen_port': 14617}), encoding='utf-8')
        def fake_path(value):
            value = str(value)
            if value.startswith(('/etc/', '/usr/', '/var/')):
                value = str(self.root / value.lstrip('/'))
            return Path(value)
        fake_path('/usr/local/bin/gost').parent.mkdir(parents=True)
        fake_path('/usr/local/bin/gost').write_text('fixture')
        fake_path('/etc/sysctl.d').mkdir(parents=True)
        fake_path('/etc/modules-load.d').mkdir(parents=True)
        self.run = Mock(return_value=SimpleNamespace(returncode=0, stdout='', stderr=b''))
        self.save = Mock()
        self.reload = Mock(return_value=True)
        self.ns = dict(portal.__dict__, Path=fake_path, data=self.data, data_lock=threading.RLock(),
                       save_data=self.save, regenerate_page=self.save, meta_path=self.meta,
                       portal_path=self.hdir / 'portal.json', ip_tracker={}, speed_tracker={},
                       global_ip_deny={}, MASTER_USER_ID='admin_master',
                       VALID_USER_ID_RE=portal.re.compile(r'^[a-zA-Z0-9_.-]{1,64}$'),
                       reload_gost=self.reload, gost_status=Mock(return_value=True),
                       gost_operation_lock=threading.RLock(), reality_apply_lock=threading.Lock(),
                       subprocess=SimpleNamespace(run=self.run, Popen=Mock(), TimeoutExpired=subprocess.TimeoutExpired),
                       write_gost_config=Mock(), _pick_reality_port=Mock(return_value=(8443, 'existing')),
                       unit_suspended=lambda unit: False,
                       apply_xray_config_with_meter=Mock(), apply_xray_config_transaction=Mock(),
                       upsert_managed_inbound=portal.upsert_managed_inbound,
                       vmess_clients=lambda _: [{'id': 'placeholder', 'email': 'placeholder'}],
                       vlessenc_clients=lambda _: [{'id': 'placeholder', 'email': 'placeholder'}],
                       vmess_uuid_for_user=lambda _: '00000000-0000-4000-8000-000000000001',
                       vlessenc_uri_for_user=lambda *a, **kw: 'vlessenc://fixture',
                       vmess_uri_for_user=lambda *a, **kw: 'vmess://fixture',
                       _active_reality_config=lambda: self.data.get('reality_config'),
                       _active_vmess_config=lambda: self.data.get('vmess_config'),
                       _active_vlessenc_config=lambda: self.data.get('vlessenc_config'),
                       _active_anytls_config=lambda: None,
                       _active_tuic_config=lambda: None)
        self.sync = Mock(return_value=True)
        self.handler = SimpleNamespace(is_authenticated=lambda: True, server=SimpleNamespace(),
            _sync_reality_clients=self.sync, _reply_with_warp_apply=lambda payload: self.reply_json(200, payload),
            _generate_and_apply_reality=Mock(), _reality_restart_allowed=Mock(return_value=True),
            _extend_deadline=lambda *args, **kwargs: True,
            check_rate_limit=lambda **kwargs: True, verify_api_key=lambda: True)
        self.handler._manage_proxy_operation = lambda action, params: extract_method('_manage_proxy_operation', self.ns)(self.handler, action, params)
        self.handler._reply_with_egress_apply = lambda payload, kind='outbound': self.reply_json(200, payload)
        self.handler.reply_json = self.reply_json
        self.handler.reply = lambda status, body, *args, **kwargs: self.reply_json(status, body)
        self.handler.send_response = lambda status: setattr(self, 'response', (status, {}))
        self.handler.send_header = lambda *args: None
        self.handler.end_headers = lambda: None
        self.response = None

    def tearDown(self):
        self.tmp.cleanup()

    def reply_json(self, status, payload):
        self.response = (status, payload)
        return self.response

    def invoke(self, name, params):
        body = urlencode(params).encode()
        self.handler.headers = {'Content-Length': str(len(body))}
        self.handler.rfile = io.BytesIO(body)
        method = extract_method(name, self.ns)
        if name == '_ob_manage':
            method(self.handler)
        else:
            method(self.handler, '/test-token/')
        return self.response

    def test_api_renew_cannot_set_quota_on_master_account(self):
        branch = next(n for n in ast.walk(TREE) if isinstance(n, ast.If)
                      and isinstance(n.test, ast.Compare)
                      and any(isinstance(c, ast.Constant) and c.value == 'users/renew'
                              for c in n.test.comparators))
        fn = ast.parse('def renew(self, params, now_ts):\n    pass').body[0]
        fn.body = copy.deepcopy(branch.body)
        exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])),
                     '<renew>', 'exec'), self.ns)
        user = {'password': 'master-test-only', 'status': 'active', 'expires_at': 2085974400,
                'limit_bytes': 0, 'used_bytes': 0}
        self.data['users']['admin_master'] = user
        status, body = self.ns['renew'](self.handler,
            {'user_id': 'admin_master', 'extend_days': 30, 'add_traffic_gb': 1}, 100)
        self.assertEqual(status, 400)
        self.assertIn('Reserved user accounts', body['error'])
        self.assertEqual(user['limit_bytes'], 0)
        self.save.assert_not_called()
        self.sync.assert_not_called()

    def test_api_renew_rejects_corrupt_expiry_without_mutation(self):
        branch = next(n for n in ast.walk(TREE) if isinstance(n, ast.If)
                      and isinstance(n.test, ast.Compare)
                      and any(isinstance(c, ast.Constant) and c.value == 'users/renew'
                              for c in n.test.comparators))
        fn = ast.parse('def renew(self, params, now_ts):\n    pass').body[0]
        fn.body = copy.deepcopy(branch.body)
        exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])),
                     '<renew>', 'exec'), self.ns)
        user = {'expires_at': 'invalid', 'limit_bytes': 100}
        self.data['users']['qa-user'] = user
        status, _ = self.ns['renew'](self.handler, {'user_id': 'qa-user'}, 100)
        self.assertEqual(status, 400)
        self.assertEqual(user, {'expires_at': 'invalid', 'limit_bytes': 100})
        self.save.assert_not_called()
        self.sync.assert_not_called()

    def test_web_create_syncs_reality_clients(self):
        status, _ = self.invoke('_h_post_manage_user', {'action': 'create', 'user_id': 'qa-user'})
        self.assertEqual(status, 302)
        self.sync.assert_called_once()

    def test_web_delete_syncs_reality_clients(self):
        self.data['users']['qa-user'] = {'password': 'qa-only'}
        status, _ = self.invoke('_h_post_manage_user', {'action': 'delete', 'user_id': 'qa-user'})
        self.assertEqual(status, 302)
        self.sync.assert_called_once()

    def test_missing_user_delete_is_not_reported_as_success(self):
        status, _ = self.invoke('_h_post_manage_user', {'action': 'delete', 'user_id': 'not-present'})
        self.assertEqual(status, 404)

    def test_unknown_user_action_is_rejected(self):
        status, _ = self.invoke('_h_post_manage_user', {'action': 'not-an-action', 'user_id': 'qa-user'})
        self.assertEqual(status, 400)

    def test_invalid_user_duration_does_not_create_expired_record(self):
        status, _ = self.invoke('_h_post_manage_user', {'action': 'create', 'user_id': 'qa-user', 'duration_days': '-1'})
        self.assertEqual(status, 400)
        self.assertNotIn('qa-user', self.data['users'])

    def test_reality_enable_checks_failed_restart(self):
        (self.hdir / 'xray.json').write_text('{}')
        self.run.side_effect = lambda args, **kw: SimpleNamespace(returncode=1 if 'restart' in args else 0,
            stdout='inactive', stderr='restart failed')
        status, body = self.invoke('_h_post_manage_reality', {'action': 'toggle'})
        self.assertEqual(status, 500)
        self.assertFalse(body.get('ok'))

    def test_reality_disable_checks_failed_stop(self):
        self.run.side_effect = lambda args, **kw: SimpleNamespace(returncode=1 if 'stop' in args else 0,
            stdout='active', stderr='stop failed')
        status, body = self.invoke('_h_post_manage_reality', {'action': 'toggle'})
        self.assertEqual(status, 500)
        self.assertFalse(body.get('ok'))

    def test_reality_keygen_failure_never_uses_a_shared_static_key(self):
        self.run.return_value = SimpleNamespace(returncode=1, stdout='', stderr='keygen failed')
        generate = extract_method('_generate_and_apply_reality', self.ns)
        old = copy.deepcopy(self.data['reality_config'])
        with self.assertRaises(RuntimeError):
            generate(self.handler, restart=False, force=True)
        self.assertEqual(self.data['reality_config'], old)

    def test_unsupported_bbr_version_does_not_silently_claim_v3(self):
        def run(args, **kw):
            value = 'reno cubic bbr' if 'net.ipv4.tcp_available_congestion_control' in args else 'bbr'
            return SimpleNamespace(returncode=0, stdout=value, stderr='')
        self.run.side_effect = run
        status, body = self.invoke('_h_post_set_bbr', {'version': 'v3'})
        self.assertEqual(status, 409)
        self.assertFalse(body.get('ok'))
        self.assertNotIn('bbr_target_version', self.data)

    def test_bbr_save_failure_rolls_back_sysctl_files_runtime_and_state(self):
        old_target = {'bbr_target_version': 'v1'}
        self.data.update(old_target)
        congestion_reads = [0]
        def run(args, **kw):
            if args == ['sysctl', '-n', 'net.ipv4.tcp_available_congestion_control']:
                return SimpleNamespace(returncode=0, stdout='reno cubic bbr bbr2 bbr3', stderr='')
            if args == ['sysctl', '-n', 'net.ipv4.tcp_available_congestion_control']:
                return SimpleNamespace(returncode=0, stdout='reno cubic bbr bbr2 bbr3', stderr='')
            if args[:2] == ['sysctl', '-n']:
                key = args[2]
                if key == 'net.ipv4.tcp_congestion_control':
                    congestion_reads[0] += 1
                    value = 'cubic' if congestion_reads[0] == 1 else 'bbr2'
                elif key == 'net.core.default_qdisc':
                    value = 'fq'
                else:
                    value = '0'
                return SimpleNamespace(returncode=0, stdout=value, stderr='')
            if args[:2] == ['sysctl', '-p']:
                return SimpleNamespace(returncode=0, stdout='', stderr='')
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        self.run.side_effect = run
        self.ns['save_data'] = Mock(side_effect=OSError('disk full'))
        self.ns['subprocess'].run = self.run
        with patch.dict('os.environ', {'HY2_BBR_TEST_ROOT': str(self.root)}):
            # Redirect the production sysctl paths to a sandbox before the isolated handler runs.
            paths = [self.root / 'etc/modules-load.d/bbr.conf', self.root / 'etc/sysctl.d/99-bbr.conf']
            for path in paths:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('original', encoding='utf-8')
            original_path = self.ns['Path']
            def fake_path(value):
                text = str(value)
                if text in ('/etc/modules-load.d/bbr.conf', '/etc/sysctl.d/99-bbr.conf'):
                    return self.root / text.lstrip('/')
                return original_path(value)
            self.ns['Path'] = fake_path
            status, body = self.invoke('_h_post_set_bbr', {'version': 'v2'})
            self.assertEqual(status, 500, body)
            self.assertEqual(self.data['bbr_target_version'], 'v1')
            self.assertEqual([p.read_text(encoding='utf-8') for p in paths], ['original', 'original'])

    def test_failed_sysctl_is_not_reported_as_reboot_success(self):
        def run(args, **kw):
            return SimpleNamespace(returncode=1 if '-p' in args else 0,
                stdout='reno cubic bbr' if 'net.ipv4.tcp_available_congestion_control' in args else 'cubic',
                stderr='sysctl failed')
        self.run.side_effect = run
        status, body = self.invoke('_h_post_set_bbr', {'version': 'v1'})
        self.assertEqual(status, 500)
        self.assertFalse(body.get('ok'))

    def test_invalid_manual_proxy_port_is_rejected(self):
        status, _ = self.invoke('_h_post_manage_proxy', {'action': 'create', 'type': 'http', 'port': '65536'})
        self.assertEqual(status, 400)
        self.assertEqual(self.data['proxy_services'], [])

    def test_proxy_link_percent_encodes_custom_credentials(self):
        status, body = self.invoke('_h_post_manage_proxy', {'action': 'create', 'type': 'http',
            'username': 'qa@user', 'password': 'a@b/#?'})
        self.assertEqual(status, 200)
        self.assertIn('qa%40user:a%40b%2F%23%3F@', body['url'])

    def test_proxy_apply_failure_rolls_back_new_record(self):
        self.reload.return_value = False
        status, body = self.invoke('_h_post_manage_proxy', {'action': 'create', 'type': 'http'})
        self.assertEqual(status, 500)
        self.assertFalse(body.get('ok'))
        self.assertEqual(self.data['proxy_services'], [])

    def invoke_core_install(self, name='xray'):
        self.handler.path = '/test-token/install-core'
        body = urlencode({'name': name}).encode()
        self.handler.headers = {'Content-Length': str(len(body))}
        self.handler.rfile = io.BytesIO(body)
        return extract_method('_h_post_install_core', self.ns)(self.handler, '/test-token/')

    def test_tls_certificate_validation_rejects_expired_and_future_certificates(self):
        method = extract_method('_vmess_certificate', self.ns)
        fixture_cert = self.root / 'fixture-cert.pem'
        self.ns['_resolve_live_cert'] = Mock(return_value=(fixture_cert,
            'node.example.com', ['node.example.com'], False))
        fixture_cert.write_text('leaf\\nintermediate\\n', encoding='ascii')
        self.ns['_find_cert_key'] = Mock(return_value=self.root / 'key.pem')
        self.ns['_find_cert_key'].return_value.write_text('key', encoding='ascii')
        future = SimpleNamespace(returncode=0, stdout='notBefore=Jan  1 00:00:00 2099 GMT\n')
        self.ns['subprocess'].run = Mock(side_effect=[
            SimpleNamespace(returncode=1, stdout='', stderr='expired'),
            SimpleNamespace(returncode=0, stdout='notAfter=Jan  1 00:00:00 2099 GMT\n'),
            future])
        with self.assertRaisesRegex(RuntimeError, '过期或无效'):
            method(self.handler, 'node.example.com', 'VMess')
        with self.assertRaisesRegex(RuntimeError, '尚未生效'):
            method(self.handler, 'node.example.com', 'VMess')

    def test_api_enforce_node_access_uses_core_lock_without_reopening_it(self):
        handler = extract_method('_sync_reality_clients', self.ns)
        applied = []
        core_fd = 31
        self.ns['apply_access'] = lambda **kwargs: (applied.append(kwargs) or True)
        self.assertTrue(handler(self.handler, core_lock_fd=core_fd))
        self.assertEqual(applied, [{'core_lock_fd': core_fd}])

    def test_core_install_returns_conflict_when_cross_process_lock_is_held(self):
        self.ns['acquire_core_operation_lock'] = Mock(
            side_effect=RuntimeError('another core operation is running'))
        install = self.ns['install_xray_binary'] = Mock()
        status, body = self.invoke_core_install()
        self.assertEqual(status, 409)
        self.assertFalse(body['ok'])
        install.assert_not_called()

    def test_vmess_and_vless_clients_are_refreshed_after_core_lock_acquisition(self):
        source = Path(portal.__file__).read_text(encoding='utf-8')
        for method, builder in (('_apply_vmess_enable', 'vmess_clients'),
                               ('_apply_vlessenc_enable', 'vlessenc_clients')):
            with self.subTest(method=method):
                start = source.index('        def ' + method + '(')
                end = source.find('\n        def ', start + 12)
                body = source[start:end if end >= 0 else len(source)]
                lock = body.index('with core_operation_lock, core_operation_file_lock(), reality_apply_lock:')
                read_clients = body.index('inbound[\'settings\'][\'clients\'] = ' + builder)
                self.assertGreater(read_clients, lock)

    def test_vmess_and_vless_save_failure_restore_xray_and_portal_state(self):
        for method_name, config_key, tag in (
                ('_apply_vmess_enable', 'vmess_config', portal.VMESS_INBOUND_TAG),
                ('_apply_vlessenc_enable', 'vlessenc_config', portal.VLESSENC_INBOUND_TAG)):
            with self.subTest(method=method_name):
                path = self.hdir / 'xray.json'
                original = {'inbounds': [{'tag': portal.REALITY_INBOUND_TAG, 'port': 8443}],
                            'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}]}
                path.write_text(json.dumps(original), encoding='utf-8')
                self.ns['Path'] = lambda value: path if str(value) == '/etc/hysteria/xray.json' else (
                    self.root / 'usr/local/bin/xray' if str(value) == '/usr/local/bin/xray' else Path(value))
                self.ns['Path']('/usr/local/bin/xray').touch()
                self.ns['portal_path'] = self.hdir / 'portal.json'
                self.ns['read_meta_file'] = lambda _: {'server_name': 'node.example.com',
                                                        'public_ip': '203.0.113.10'}
                self.ns['_is_dns_name'] = lambda _: True
                self.handler._vmess_certificate = lambda *a: ('cert.pem', 'key.pem', 'node.example.com')
                self.handler._vmess_ws_path = lambda: '/fixture'
                self.ns['managed_reserved_ports'] = lambda *a, **kw: set()
                self.ns['_pick_reality_port'] = lambda **kw: (2087 if config_key == 'vmess_config' else 2088, '')
                self.ns['generate_vless_encryption_pair'] = lambda: ('decryption', 'encryption')
                self.ns['core_operation_file_lock'] = lambda: __import__('contextlib').nullcontext()
                self.ns['core_operation_lock'] = threading.RLock()
                self.ns['apply_xray_config_with_meter'] = Mock(side_effect=lambda cfg, target, *_:
                    target.write_text(json.dumps(cfg), encoding='utf-8'))
                self.ns['apply_xray_config_transaction'] = Mock(side_effect=lambda cfg, **kw:
                    Path(kw['config_path']).write_text(json.dumps(cfg), encoding='utf-8'))
                self.ns['save_data'] = Mock(side_effect=OSError('disk full'))
                self.data.pop(config_key, None)
                before = copy.deepcopy(original)
                with self.assertRaisesRegex(OSError, 'disk full'):
                    extract_method(method_name, self.ns)(self.handler)
                self.assertEqual(json.loads(path.read_text(encoding='utf-8')), before)
                self.assertNotIn(tag, [item.get('tag') for item in json.loads(path.read_text())['inbounds']])
                self.assertNotIn(config_key, self.data)

    def test_protocol_install_paths_share_cross_process_core_lock(self):
        source = Path(portal.__file__).read_text(encoding='utf-8')
        for handler, action in (('_h_post_manage_vmess', "if action == 'enable':"),
                                ('_h_post_manage_vlessenc', "if action == 'enable':"),
                                ('_h_post_manage_anytls', "if action == 'enable':"),
                                ('_h_post_manage_tuic', "if action == 'enable':")):
            with self.subTest(handler=handler):
                start = source.index('        def ' + handler + '(')
                end = source.find('\n        def ', start + 12)
                body = source[start:end if end >= 0 else len(source)]
                action_start = body.index(action)
                action_end = body.find("if not enabled:", action_start)
                enable_body = body[action_start:action_end if action_end >= 0 else len(body)]
                self.assertIn('core_operation_file_lock()', enable_body)

    def test_core_install_releases_cross_process_lock_after_operation(self):
        acquire = Mock(return_value=17)
        closed = []
        self.ns['acquire_core_operation_lock'] = acquire
        self.ns['os'] = SimpleNamespace(close=closed.append)
        self.ns['install_xray_binary'] = Mock(return_value=(True, 'installed'))
        self.ns['write_xray_unit'] = Mock()
        status, body = self.invoke_core_install()
        self.assertEqual(status, 200)
        self.assertTrue(body['ok'])
        acquire.assert_called_once_with()
        self.assertEqual(closed, [17])

    def invoke_api(self, payload, endpoint='users/create'):
        body = json.dumps(payload).encode()
        self.handler.path = '/api/v1/' + endpoint
        self.handler.headers = {'Content-Length': str(len(body))}
        self.handler.rfile = io.BytesIO(body)
        extract_method('do_POST', self.ns)(self.handler)
        return self.response

    def test_api_update_and_renew_persist_user_changes(self):
        self.data['users']['qa-user'] = {'password': 'old', 'status': 'active',
            'expires_at': 2200000000, 'limit_bytes': 10, 'ip_limit': 0}
        status, _ = self.invoke_api({'user_id': 'qa-user', 'password': 'new', 'ip_limit': 2},
                                    'users/update')
        self.assertEqual(status, 200)
        persisted_update = copy.deepcopy(self.data['users']['qa-user'])
        self.assertEqual(persisted_update['password'], 'new')
        self.assertEqual(persisted_update['ip_limit'], 2)
        self.assertGreaterEqual(self.save.call_count, 2)  # user data plus generated page
        self.save.reset_mock()
        status, _ = self.invoke_api({'user_id': 'qa-user', 'extend_days': 30,
                                    'add_traffic_gb': 1}, 'users/renew')
        self.assertEqual(status, 200)
        persisted_renew = copy.deepcopy(self.data['users']['qa-user'])
        self.assertGreater(persisted_renew['expires_at'], persisted_update['expires_at'])
        self.assertGreater(persisted_renew['limit_bytes'], persisted_update['limit_bytes'])
        self.assertGreaterEqual(self.save.call_count, 2)

    def test_api_update_and_renew_restore_memory_on_save_failure(self):
        original = {'password': 'old', 'status': 'active', 'expires_at': 2200000000,
                    'limit_bytes': 10, 'ip_limit': 0}
        self.data['users']['qa-user'] = copy.deepcopy(original)
        self.ns['save_data'] = Mock(side_effect=OSError('disk full'))
        status, _ = self.invoke_api({'user_id': 'qa-user', 'password': 'new'}, 'users/update')
        self.assertEqual(status, 503)
        self.assertEqual(self.data['users']['qa-user'], original)
        status, _ = self.invoke_api({'user_id': 'qa-user', 'extend_days': 30}, 'users/renew')
        self.assertEqual(status, 503)
        self.assertEqual(self.data['users']['qa-user'], original)

    def test_core_uninstall_checks_protocols_after_acquiring_core_lock(self):
        self.handler.is_authenticated = lambda: True
        self.handler.rfile = io.BytesIO(urlencode({'name': 'xray'}).encode())
        self.handler.headers = {'Content-Length': str(len(urlencode({'name': 'xray'})))}
        events = []
        self.ns['core_operation_lock'] = threading.RLock()
        self.ns['acquire_core_operation_lock'] = Mock(
            side_effect=lambda: (events.append(('lock', None)) or 23))
        self.ns['os'] = SimpleNamespace(close=lambda fd: events.append(('close', fd)))
        def users(_):
            events.append(('check', None))
            return []
        self.handler._core_users = users
        self.ns['subprocess'].run = Mock(return_value=SimpleNamespace(returncode=0))
        self.ns['Path']('/usr/local/bin/xray').touch()
        original = extract_method('_h_post_uninstall_core', self.ns)
        status, body = original(self.handler, '/test-token/')
        self.assertEqual(status, 200, body)
        self.assertEqual(events[0], ('lock', None))
        self.assertEqual(events[1], ('check', None))
        self.assertEqual(events[-1], ('close', 23))

    def test_share_denial_for_corrupt_expiry_returns_403_without_type_error(self):
        handler = extract_method('do_GET', self.ns)
        users = {'qa-user': {'password': 'pass', 'status': 'active',
                             'expires_at': '100', 'view_nonce': 'nonce'}}
        session_secret = 'secret'
        view_key = portal.user_view_key(session_secret, 'qa-user', 'nonce')
        path = '/test-token/u/qa-user/clash.yaml?k=' + view_key
        self.handler.path = path
        self.handler.headers = {}
        self.handler.is_authenticated = lambda: False
        self.handler.rfile = io.BytesIO()
        self.ns.update({'data': {'token': 'test-token', 'users': users,
                                 'session_secret': session_secret},
                        'session_secret': session_secret,
                        'user_table': lambda _: users,
                        'read_meta_file': lambda _: {'server_name': 'node.example.com',
                            'public_ip': '203.0.113.10', 'listen_port': 443,
                            'subscription_port': 8443, 'is_insecure': False},
                        'user_view_key': portal.user_view_key,
                        'user_share_available': portal.user_share_available,
                        'share_unavailable_reason': portal.share_unavailable_reason,
                        'time': portal.time})
        code, body = handler(self.handler)
        self.assertEqual(code, 403)
        self.assertIn('服务已到期'.encode('utf-8'), body)

    def test_api_set_status_persists_and_rolls_back_on_save_failure(self):
        original = {'password': 'qa-pass', 'status': 'active', 'expires_at': 2200000000}
        self.data['users']['qa-user'] = copy.deepcopy(original)
        status, body = self.invoke_api({'user_id': 'qa-user', 'active': False}, 'users/set_status')
        self.assertEqual(status, 200, body)
        self.assertEqual(self.data['users']['qa-user']['status'], 'disabled')
        self.assertGreaterEqual(self.save.call_count, 2)  # persisted state + generated page
        self.save.reset_mock()
        self.ns['save_data'] = Mock(side_effect=OSError('disk full'))
        status, body = self.invoke_api({'user_id': 'qa-user', 'active': True}, 'users/set_status')
        self.assertEqual(status, 503, body)
        self.assertEqual(self.data['users']['qa-user']['status'], 'disabled')

    def test_api_reconciles_absolute_usage_against_measured_ledger(self):
        self.data['users']['qa-user'] = {'password': 'original', 'used_bytes': 50,
                                          'legacy_auth_value': 7, 'expires_at': 2200000000}
        self.data['usage_meter'] = {'totals': {'qa-user': {'hysteria': 40, 'reality': 10}}}
        status, _ = self.invoke_api({'user_id': 'qa-user', 'used_bytes': 999})
        self.assertEqual(status, 200)
        self.assertEqual(self.data['users']['qa-user']['used_bytes'], 999)
        self.assertEqual(self.data['users']['qa-user']['legacy_auth_value'], 7)
        self.assertEqual(self.data['usage_meter']['adjustments']['qa-user'], 949)
        self.assertEqual(self.data['usage_meter']['totals']['qa-user']['hysteria'], 40)

    def test_api_explicit_limit_bytes_is_not_overwritten_by_old_value(self):
        self.data['users']['qa-user'] = {'password': 'original', 'used_bytes': 5,
                                          'limit_bytes': 100, 'expires_at': 2200000000}
        status, _ = self.invoke_api({'user_id': 'qa-user', 'limit_bytes': 50})
        self.assertEqual(status, 200)
        self.assertEqual(self.data['users']['qa-user']['limit_bytes'], 50)

    def test_api_reconciliation_after_replace_failure_keeps_live_state(self):
        self.data['users']['qa-user'] = {'password': 'original', 'used_bytes': 50, 'expires_at': 2200000000}
        self.data['usage_meter'] = {'totals': {'qa-user': {'hysteria': 50}}}
        self.ns['save_data'] = Mock(side_effect=portal.AtomicWriteDurabilityError('directory sync'))
        status, _ = self.invoke_api({'user_id': 'qa-user', 'used_bytes': 0})
        self.assertEqual(status, 503)
        self.assertEqual(self.data['users']['qa-user']['used_bytes'], 0)
        self.assertEqual(self.data['usage_meter']['adjustments']['qa-user'], -50)
        self.sync.assert_called_once()

    def test_api_reconciliation_save_failure_restores_state(self):
        old = {'password': 'original', 'used_bytes': 50, 'expires_at': 2200000000}
        self.data['users']['qa-user'] = dict(old)
        self.data['usage_meter'] = {'totals': {'qa-user': {'hysteria': 50}}}
        before = copy.deepcopy(self.data)
        self.ns['save_data'] = Mock(side_effect=OSError('disk full'))
        status, _ = self.invoke_api({'user_id': 'qa-user', 'used_bytes': 0})
        self.assertEqual(status, 503)
        self.assertEqual(self.data, before)

    def test_api_reconciliation_rejects_corrupt_ledger_without_mutating_user(self):
        old = {'password': 'original', 'used_bytes': 50, 'expires_at': 2200000000}
        self.data['users']['qa-user'] = dict(old)
        self.data['usage_meter'] = {'totals': {'qa-user': {'hysteria': -1}}}
        status, _ = self.invoke_api({'user_id': 'qa-user', 'used_bytes': 999})
        self.assertEqual(status, 409)
        self.assertEqual(self.data['users']['qa-user'], old)
        self.assertNotIn('adjustments', self.data['usage_meter'])

    def test_api_duplicate_create_preserves_existing_usage_and_password(self):
        old = {'password': 'original-test-only', 'used_bytes': 123456, 'expires_at': 2200000000}
        self.data['users']['qa-user'] = dict(old)
        status, _ = self.invoke_api({'user_id': 'qa-user'})
        self.assertEqual(status, 200)
        for key, value in old.items():
            self.assertEqual(self.data['users']['qa-user'][key], value)

    def test_api_create_only_preserves_duplicate_record(self):
        old = {'password': 'original-test-only', 'used_bytes': 123456, 'expires_at': 2200000000}
        self.data['users']['qa-user'] = dict(old)
        status, _ = self.invoke_api({'user_id': 'qa-user', 'create_only': True, 'password': 'replacement'})
        self.assertEqual(status, 409)
        self.assertEqual(self.data['users']['qa-user'], old)

    def test_api_create_only_conflict_with_usage_reconciliation_has_no_side_effects(self):
        old = {'password': 'original-test-only', 'used_bytes': 123456, 'expires_at': 2200000000}
        self.data['users']['qa-user'] = dict(old)
        self.data['usage_meter'] = {'totals': {'qa-user': {'hysteria': 123456}}}
        before = copy.deepcopy(self.data)
        status, _ = self.invoke_api({'user_id': 'qa-user', 'create_only': True,
                                     'password': 'replacement', 'used_bytes': 0})
        self.assertEqual(status, 409)
        self.assertEqual(self.data, before)
        self.save.assert_not_called()
        self.sync.assert_not_called()

    def test_api_explicit_password_upsert_preserves_cumulative_usage(self):
        self.data['users']['qa-user'] = {'password': 'original', 'used_bytes': 123456, 'expires_at': 2200000000}
        status, _ = self.invoke_api({'user_id': 'qa-user', 'password': 'replacement-test-only'})
        self.assertEqual(status, 200)
        self.assertEqual(self.data['users']['qa-user']['used_bytes'], 123456)
        self.assertEqual(self.data['users']['qa-user']['password'], 'replacement-test-only')

    def test_api_invalid_json_shape_and_numeric_parameters_return_400(self):
        for payload in ([], {'user_id': 42}, {'user_id': 'qa-user', 'traffic_gb': 'nan'},
                        {'user_id': 'qa-user', 'duration_days': '-1'}):
            self.assertEqual(self.invoke_api(payload)[0], 400)
        self.assertNotIn('qa-user', self.data['users'])

    def test_web_create_rolls_back_when_reality_sync_fails(self):
        self.sync.return_value = False
        status, _ = self.invoke('_h_post_manage_user', {'action': 'create', 'user_id': 'qa-user'})
        self.assertEqual(status, 503)
        self.assertNotIn('qa-user', self.data['users'])

    def test_web_delete_persists_revocation_when_reality_sync_fails(self):
        old = {'password': 'original-test-only', 'used_bytes': 99}
        self.data['users']['qa-user'] = dict(old)
        self.sync.return_value = False
        self.assertEqual(self.invoke('_h_post_manage_user', {'action': 'delete', 'user_id': 'qa-user'})[0], 503)
        self.assertNotIn('qa-user', self.data['users'])
        self.assertIn('qa-user', self.data['_pending_revocations'])

    def test_http_proxy_username_with_colon_is_rejected(self):
        status, _ = self.invoke('_h_post_manage_proxy', {'action': 'create', 'type': 'http',
                               'username': 'qa:user', 'password': 'test-only'})
        self.assertEqual(status, 400)
        self.assertEqual(self.data['proxy_services'], [])

    def test_socks_proxy_authentication_length_is_validated_in_bytes(self):
        status, _ = self.invoke('_h_post_manage_proxy', {'action': 'create', 'type': 'socks5',
                               'password': 'x' * 256})
        self.assertEqual(status, 400)

    def test_editing_first_global_outbound_preserves_priority(self):
        self.data.update({
            'custom_outbounds': [
                {'name': 'first_proxy', 'type': 'socks5', 'addr': '127.0.0.1:1080'},
                {'name': 'second_proxy', 'type': 'socks5', 'addr': '127.0.0.1:1081'},
            ],
            'outbound_mode': 'global',
        })
        params = {'action': 'save', 'name': 'first_proxy', 'type': 'socks5',
                  'addr': '127.0.0.1:2080'}
        result = self.invoke('_ob_manage', params)
        self.assertEqual(result[0], 200)
        self.assertEqual([item['name'] for item in self.data['custom_outbounds']],
                         ['first_proxy', 'second_proxy'])
        self.assertEqual(self.data['custom_outbounds'][0]['addr'], '127.0.0.1:2080')

    def test_warp_dict_rule_delete_preserves_non_warp_routes(self):
        self.data['warp_rules'] = [{'domain': 'openai.com', 'outbound': 'warp_socks'},
                                   {'domain': 'example.com', 'outbound': 'direct'}]
        self.invoke('_h_post_manage_warp', {'action': 'del_rule', 'domain': 'openai.com'})
        self.assertEqual(self.data['warp_rules'], [{'domain': 'example.com', 'outbound': 'direct'}])

    def test_warp_reset_does_not_override_explicit_custom_direct_rules(self):
        self.data['warp_rules'] = [{'domain': 'openai.com', 'outbound': 'direct'}]
        self.invoke('_h_post_manage_warp', {'action': 'reset_rules'})
        self.assertEqual([r for r in self.data['warp_rules'] if r['domain'] == 'openai.com'],
                         [{'domain': 'openai.com', 'outbound': 'direct'}])

    def test_warp_toggle_does_not_destroy_global_custom_outbound_mode(self):
        state = {'warp_enabled': True, 'outbound_mode': 'global',
                 'warp_rules': ['openai.com'],
                 'custom_outbounds': [{'name': 'qa_proxy', 'type': 'socks5', 'addr': '127.0.0.1:19898'}]}
        original = 'outbounds:\n  - name: direct_ipv4\n    type: direct\n    direct:\n      mode: "4"\n'
        text = portal.render_egress_config(original, state)
        self.assertIn('qa_proxy(all)', text)
        self.assertNotIn('warp_socks(suffix:openai.com)', text)

    def test_stopped_reality_stays_off_during_account_sync(self):
        config = {'inbounds': [{'protocol': 'vless', 'streamSettings': {'security': 'reality'},
                               'settings': {'clients': []}}]}
        (self.hdir / 'xray.json').write_text(json.dumps(config))
        calls=[]
        def run(args,**kwargs):
            calls.append(args)
            return SimpleNamespace(returncode=0,stdout='inactive' if args[:2]==['systemctl','is-active'] else 'fixture-epoch',stderr='')
        self.ns['apply_access']=lambda **kwargs:portal.enforce_node_access(self.hdir,{'users':{}},
            apply_lock=self.ns.get('reality_apply_lock'), skip_anytls=True, skip_tuic=True)
        with patch.object(portal.subprocess,'run',side_effect=run):
            result=extract_method('_sync_reality_clients',self.ns)(self.handler)
        self.assertTrue(result)
        self.assertFalse(any(args[:2]==['systemctl','restart'] for args in calls))

    def test_protocol_port_reference_keeps_shared_xray_listener_open(self):
        config = {'inbounds': [
            {'tag': portal.REALITY_INBOUND_TAG, 'port': 8443},
            {'tag': portal.VMESS_INBOUND_TAG, 'port': 8443},
        ]}
        self.data['reality_config'] = {'port': 8443}
        self.data['vmess_config'] = {'port': 8443}
        with patch.object(portal, '_systemd_state', return_value='inactive'):
            self.assertTrue(portal.protocol_port_in_use(
                8443, 'tcp', self.data, config, exclude_key='reality_config'))

    def test_gost_delete_keeps_shared_listener_firewall_rule(self):
        self.data['proxy_services'] = [
            {'id': 'proxy-a', 'type': 'http', 'port': 8443},
            {'id': 'proxy-b', 'type': 'https', 'port': 8443},
        ]
        self.ns['gost_operation_lock'] = threading.RLock()
        self.ns['save_data'] = Mock()
        self.ns['reload_gost'] = Mock(return_value=True)
        self.ns['protocol_port_in_use'] = lambda port, proto, data, **kwargs: True
        removed = []
        self.ns['firewall_port'] = lambda *a, **kw: removed.append((a, kw))
        status, body = extract_method('_manage_proxy_operation', self.ns)(
            self.handler, 'delete', {'id': 'proxy-a'})
        self.assertEqual(status, 200, body)
        self.assertEqual(removed, [])

    def test_inactive_ufw_is_not_treated_as_blocked_port_failure(self):
        with patch.object(portal.shutil, 'which', side_effect=lambda name: '/usr/sbin/ufw' if name == 'ufw' else None), \
             patch.object(portal.subprocess, 'run', return_value=SimpleNamespace(
                 returncode=0, stdout='Status: inactive', stderr='')) as run:
            self.assertTrue(portal.firewall_port(8443, 'tcp', open_=True))
        self.assertEqual(run.call_count, 1)

    def test_firewall_port_reports_command_failure(self):
        with patch.object(portal.shutil, 'which', side_effect=lambda name: '/usr/sbin/ufw' if name == 'ufw' else None), \
             patch.object(portal.subprocess, 'run', side_effect=[
                 SimpleNamespace(returncode=0, stdout='Status: active'),
                 SimpleNamespace(returncode=1, stdout='')]):
            self.assertFalse(portal.firewall_port(8443, 'tcp', open_=True))

    def test_vmess_disable_reports_firewall_rule_removal_failure(self):
        xray = {'inbounds': [{'tag': portal.VMESS_INBOUND_TAG, 'protocol': 'vmess',
            'port': 2087, 'settings': {'clients': []}}]}
        path = self.hdir / 'xray.json'
        path.write_text(json.dumps(xray), encoding='utf-8')
        self.data['vmess_config'] = {'port': 2087}
        self.ns['Path'] = lambda value: path if str(value) == '/etc/hysteria/xray.json' else Path(value)
        self.ns['has_managed_inbound'] = lambda cfg, tag: any(x.get('tag') == tag for x in cfg.get('inbounds', []))
        self.ns['remove_managed_inbound'] = lambda cfg, tag: cfg.update(
            inbounds=[x for x in cfg['inbounds'] if x.get('tag') != tag])
        self.ns['apply_xray_config_transaction'] = Mock()
        self.ns['unit_suspended'] = lambda _: False
        self.ns['config_section'] = lambda data, key: self.data.get(key, {})
        self.ns['save_data'] = Mock()
        self.ns['regenerate_page'] = Mock()
        self.ns['close_protocol_port'] = Mock(return_value=False)
        status, body = self.invoke('_h_post_manage_vmess', {'action': 'disable'})
        self.assertEqual(status, 500, body)
        self.assertFalse(body['active'])
        self.ns['close_protocol_port'].assert_called_once_with(2087, 'tcp', 'vmess_config')

    def test_reality_disable_closes_old_firewall_port(self):
        config = {'inbounds': [{'protocol': 'vless', 'tag': portal.REALITY_INBOUND_TAG,
            'streamSettings': {'security': 'reality'}, 'settings': {'clients': []}}]}
        (self.hdir / 'xray.json').write_text(json.dumps(config), encoding='utf-8')
        self.data['reality_config']['port'] = 8443
        self.ns['has_managed_inbound'] = lambda *_: True
        self.ns['config_section'] = lambda data, key: self.data.get(key, {})
        calls = []
        def run(args, **kwargs):
            if args[:3] == ['systemctl', 'is-active', 'xray']:
                return SimpleNamespace(returncode=0, stdout='inactive', stderr='')
            return SimpleNamespace(returncode=0, stdout='fixture', stderr='')
        self.ns['apply_xray_config_transaction'] = Mock()
        self.ns['firewall_port'] = lambda *a, **kw: (calls.append((a, kw)) or True)
        self.ns['protocol_port_in_use'] = lambda *args, **kwargs: False
        self.ns['close_protocol_port'] = lambda port, proto, key: (calls.append(((port, proto), {'open_': False, 'exclude_key': key})) or True)
        self.ns['_systemd_state'] = lambda _: 'inactive'
        with patch.object(portal, '_systemd_state', return_value='inactive'), \
             patch.object(self.ns['subprocess'], 'run', side_effect=run):
            status, body = self.invoke('_h_post_manage_reality', {'action': 'toggle'})
        self.assertEqual(status, 200, body)
        self.assertIn(((8443, 'tcp'), {'open_': False, 'exclude_key': 'reality_config'}), calls)

    def test_reality_generation_failure_preserves_old_keys_and_extra_routes(self):
        config = {'inbounds': [{'protocol': 'vless', 'streamSettings': {'security': 'reality'},
                               'settings': {'clients': []}}],
                  'outbounds': [{'protocol': 'freedom', 'tag': 'retain-me'}]}
        (self.hdir / 'xray.json').write_text(json.dumps(config))
        self.ns['apply_xray_config_transaction'] = Mock(side_effect=RuntimeError('failed config check'))
        old = copy.deepcopy(self.data['reality_config'])
        with self.assertRaises(RuntimeError):
            extract_method('_generate_and_apply_reality', self.ns)(self.handler)
        self.assertEqual(self.data['reality_config'], old)
        proposed = self.ns['apply_xray_config_transaction'].call_args.args[0]
        # 用户原有出站必须原样保留；新增的黑洞出站是内网拦截的一部分
        # （2026-10-24 加），排在最后、不会抢默认出站。
        self.assertEqual(proposed['outbounds'][0], config['outbounds'][0])
        self.assertIn({'protocol': 'blackhole', 'tag': 'block-private'},
                      proposed['outbounds'])
        self.assertNotEqual(proposed['outbounds'][0]['protocol'], 'blackhole')

    def test_xray_transaction_invalid_config_keeps_original_bytes(self):
        path = self.hdir / 'xray.json'
        old = b'{"inbounds":[]}'
        path.write_bytes(old)
        def run(args, **kwargs):
            return SimpleNamespace(returncode=1 if '-test' in args else 0, stdout='active')
        with patch.object(portal.subprocess, 'run', side_effect=run):
            with self.assertRaises(RuntimeError):
                portal.apply_xray_config_transaction({'inbounds': []}, str(path), 'fixture-xray')
        self.assertEqual(path.read_bytes(), old)

    def test_xray_transaction_restart_failure_restores_original_bytes(self):
        path = self.hdir / 'xray.json'
        old = b'{"inbounds":[]}'
        path.write_bytes(old)
        failed = False
        def run(args, **kwargs):
            nonlocal failed
            rc = 0
            if args == ['systemctl', 'restart', 'xray'] and not failed:
                failed = True
                rc = 1
            return SimpleNamespace(returncode=rc, stdout='active')
        with patch.object(portal.subprocess, 'run', side_effect=run):
            with self.assertRaises(RuntimeError):
                portal.apply_xray_config_transaction({'inbounds': [{'port': 8443}]}, str(path), 'fixture-xray')
        self.assertEqual(path.read_bytes(), old)

    def test_core_upgrade_rejects_html_download_without_replacing_binary(self):
        binary = self.root / 'hysteria'
        old = b'original-test-binary'
        binary.write_bytes(old)
        self.run.return_value = SimpleNamespace(returncode=0, stdout='Version: v2.12.3\n', stderr='')
        with patch.object(portal.subprocess, 'run', self.run), \
             patch.object(portal.urllib.request, 'urlopen', return_value=io.BytesIO(b'<html>download failed</html>')):
            with self.assertRaises(RuntimeError):
                portal.upgrade_core_binary(str(binary), str(self.root / 'backups'))
        self.assertEqual(binary.read_bytes(), old)

    def test_custom_core_upgrade_requires_explicit_confirmation(self):
        binary = self.root / 'hysteria'
        binary.write_bytes(b'test')
        self.run.return_value = SimpleNamespace(returncode=0, stdout='Version: v2.12.3+custom\n')
        with patch.object(portal.subprocess, 'run', self.run), \
             patch.object(portal.urllib.request, 'urlopen') as download:
            with self.assertRaises(RuntimeError):
                portal.upgrade_core_binary(str(binary), str(self.root / 'backups'))
        download.assert_not_called()

    def test_core_version_comparison_does_not_treat_patch_suffix_as_newer_upstream(self):
        self.assertEqual(portal.core_version_key('2.12.3+custom'), portal.core_version_key('v2.12.3'))
        self.assertGreater(portal.core_version_key('v2.13.0'), portal.core_version_key('2.12.3'))

    def test_explicit_immutable_ref_does_not_make_a_branch_lookup(self):
        with patch.object(portal.urllib.request, 'urlopen') as open_:
            self.assertEqual(portal.resolve_update_ref('a' * 40), 'a' * 40)
        open_.assert_not_called()


if __name__ == '__main__':
    unittest.main()