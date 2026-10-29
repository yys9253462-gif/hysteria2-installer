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
                       portal_path=self.hdir / 'portal.json', ip_tracker={}, speed_tracker={}, MASTER_USER_ID='admin_master',
                       VALID_USER_ID_RE=portal.re.compile(r'^[a-zA-Z0-9_.-]{1,64}$'),
                       reload_gost=self.reload, gost_status=Mock(return_value=True),
                       gost_operation_lock=threading.RLock(), reality_apply_lock=threading.Lock(),
                       subprocess=SimpleNamespace(run=self.run, Popen=Mock(), TimeoutExpired=subprocess.TimeoutExpired),
                       write_gost_config=Mock(), _pick_reality_port=Mock(return_value=(8443, 'existing')),
                       unit_suspended=lambda unit: False,
                       _active_reality_config=lambda: self.data.get('reality_config'),
                       _active_vmess_config=lambda: self.data.get('vmess_config'),
                       _active_vlessenc_config=lambda: self.data.get('vlessenc_config'),
                       _active_anytls_config=lambda: None)
        self.sync = Mock(return_value=True)
        self.handler = SimpleNamespace(is_authenticated=lambda: True, server=SimpleNamespace(),
            _sync_reality_clients=self.sync, _reply_with_warp_apply=lambda payload: self.reply_json(200, payload),
            _generate_and_apply_reality=Mock(), _reality_restart_allowed=Mock(return_value=True),
            check_rate_limit=lambda **kwargs: True, verify_api_key=lambda: True)
        self.handler._manage_proxy_operation = lambda action, params: extract_method('_manage_proxy_operation', self.ns)(self.handler, action, params)
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
        extract_method(name, self.ns)(self.handler, '/test-token/')
        return self.response

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

    def invoke_api(self, payload):
        body = json.dumps(payload).encode()
        self.handler.path = '/api/v1/users/create'
        self.handler.headers = {'Content-Length': str(len(body))}
        self.handler.rfile = io.BytesIO(body)
        extract_method('do_POST', self.ns)(self.handler)
        return self.response

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
        self.ns['apply_access']=lambda:portal.enforce_node_access(self.hdir,{'users':{}})
        with patch.object(portal.subprocess,'run',side_effect=run):
            result=extract_method('_sync_reality_clients',self.ns)(self.handler)
        self.assertTrue(result)
        self.assertFalse(any(args[:2]==['systemctl','restart'] for args in calls))

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