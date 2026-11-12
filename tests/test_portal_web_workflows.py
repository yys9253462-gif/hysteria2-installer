import ast
import copy
import io
import os
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
                       xray_unit_foreign=lambda *a: False, gost_owned=lambda: True,
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
                       _active_tuic_config=lambda: None,
                       _served_singbox_config=lambda cfg, service: cfg,
                       # 真实 firewall_port 会探测本机 ufw/firewalld/nft 并执行；
                       # 默认桩成成功，需要验证防火墙行为的用例自己再覆盖。
                       firewall_port=Mock(return_value=True))
        self.sync = Mock(return_value=True)
        self.handler = SimpleNamespace(is_authenticated=lambda: True, server=SimpleNamespace(),
            _sync_reality_clients=self.sync, _kick_old_password_sessions=Mock(return_value=True),
            _reply_with_warp_apply=lambda payload: self.reply_json(200, payload),
            _generate_and_apply_reality=Mock(), _reality_restart_allowed=Mock(return_value=True),
            _extend_deadline=lambda *args, **kwargs: True,
            check_rate_limit=lambda **kwargs: True, verify_api_key=lambda: True)
        self.handler._manage_proxy_operation = lambda action, params: extract_method('_manage_proxy_operation', self.ns)(self.handler, action, params)
        self.handler._reply_with_egress_apply = lambda payload, kind='outbound': self.reply_json(200, payload)
        self.handler._reply_with_warp_apply = lambda payload: self.reply_json(200, payload)
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
        if name == '_h_post_set_bbr':
            locked = extract_method('_set_bbr_locked', self.ns)
            self.handler._set_bbr_locked = lambda: locked(self.handler)
        if name == '_ob_manage':
            method(self.handler)
        else:
            method(self.handler, '/test-token/')
        return self.response

    def test_api_key_repair_rolls_back_access_file_when_portal_save_fails(self):
        portal_file = self.hdir / 'portal.json'
        old_portal = {'auth_hash': 'a' * 64, 'api_key': '', 'users': {}}
        portal_file.write_text(json.dumps(old_portal), encoding='utf-8')
        access_path = self.hdir / 'portal-access.json'
        old_access = {'username': 'admin', 'password': 'secret', 'api_key': 'old-key'}
        access_path.write_text(json.dumps(old_access), encoding='utf-8')
        real_atomic_write = portal.atomic_write_private
        calls = []
        failed = [False]
        def atomic_write(path, payload):
            calls.append(Path(path))
            if Path(path) == portal_file and not failed[0]:
                failed[0] = True
                raise OSError('disk full')
            return real_atomic_write(path, payload)
        with patch.object(portal, 'atomic_write_private', side_effect=atomic_write):
            with self.assertRaises(SystemExit):
                portal.repair_missing_api_key(portal_file, copy.deepcopy(old_portal))
        self.assertEqual(json.loads(access_path.read_text(encoding='utf-8')), old_access)
        self.assertEqual(json.loads(portal_file.read_text(encoding='utf-8')), old_portal)
        self.assertGreaterEqual(calls.count(access_path), 2)

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

    def test_save_failure_after_create_is_reported_as_server_error(self):
        """建户后保存失败要回 500 并说明原因，不是 400「Bad request」（2026-11-04 修）。"""
        self.ns['regenerate_page'] = Mock(side_effect=OSError('No space left on device'))
        status, body = self.invoke('_h_post_manage_user', {'action': 'create', 'user_id': 'qa-user',
                                                           'password': 'pw-new-user'})
        self.assertEqual(status, 500, body)

    def test_outbound_list_survives_damaged_containers(self):
        """custom_outbounds / warp_rules 损坏时出口列表照常返回（2026-11-04 修）。"""
        self.handler.path = '/test-token/outbounds/list'
        for outs, rules in ((None, None), (7, 7), ([], [5, 'x.com'])):
            with self.subTest(outs=outs, rules=rules):
                self.data['custom_outbounds'] = outs
                self.data['warp_rules'] = rules
                status, body = extract_method('_ob_list', self.ns)(self.handler)
                self.assertEqual(status, 200, body)
                self.assertIsInstance(body['outbounds'], list)
                self.assertTrue(all(isinstance(r, dict) for r in body['rules']))

    def test_egress_worker_save_failure_keeps_other_threads_changes(self):
        """出口应用结果保存失败时不能整份回滚 data（2026-11-04 修）。

        worker 运行期间另一个线程删掉了用户；旧实现 data.clear(); data.update(旧快照)
        把用户救活，并让 worker 带着 OSError 死掉。
        """
        self.data['users']['victim'] = {'password': 'pw-victim', 'status': 'active'}
        calls = {'n': 0}

        def save():
            calls['n'] += 1
            if calls['n'] >= 2:   # 第一次是排队标记，第二次是 worker 写结果
                raise OSError('disk full')

        def apply(data, lock):
            with lock:
                data['users'].pop('victim', None)   # 另一线程在 worker 运行期间删掉了用户
            return True, ''

        class SyncThread:
            def __init__(self, target, daemon=None): self.target = target
            def start(self): self.target()

        self.ns.update(save_data=save, apply_egress_config=apply, warp_apply_lock=threading.Lock(),
                       threading=SimpleNamespace(Thread=SyncThread, Lock=threading.Lock,
                                                 RLock=threading.RLock))
        method = extract_method('_reply_with_egress_apply', self.ns)
        method(self.handler, {'ok': True})
        self.assertNotIn('victim', self.data['users'], '保存失败把别的线程删掉的用户回滚回来了')
        self.assertNotIn('egress_applying', self.data, '应用结果被撤回，界面会一直显示应用中')

    def test_recreating_a_user_with_pending_revocation_is_refused(self):
        """同名旧账号收回未完成时不能重建（2026-11-04 修），否则新账号每 5 秒被踢。"""
        self.data['_pending_revocations'] = ['qa-user']
        status, _ = self.invoke('_h_post_manage_user', {'action': 'create', 'user_id': 'qa-user',
                                                        'password': 'pw-new-user'})
        self.assertEqual(status, 409)
        self.assertNotIn('qa-user', self.data['users'])

    def test_proxy_create_refuses_foreign_gost(self):
        """不是本工具装的 gost 不在这里管理，也不改写它的单元（2026-11-04 修）。"""
        self.ns['gost_owned'] = lambda: False
        reload_gost = self.ns['reload_gost'] = Mock(return_value=True)
        status, body = extract_method('_manage_proxy_operation', self.ns)(
            self.handler, 'create', {'type': 'socks5', 'port': '31080'})
        self.assertEqual(status, 409, body)
        reload_gost.assert_not_called()

    def test_awg_conf_download_extends_the_deadline(self):
        """AWG 配置下载要延长死线，否则 AWG 更新持锁时 30 秒就被掐断（2026-11-06 修）。"""
        extend = self.handler._extend_deadline = Mock(return_value=True)
        self.ns['awg_installed'] = lambda: False
        self.data.setdefault('token', 'test-token')
        self.handler.path = '/test-token/awg-conf?name=c1'
        self.handler.headers = {}
        self.handler.is_authenticated = lambda: True
        self.handler.check_rate_limit = lambda **k: True
        self.handler.reply = lambda status, body=b'', *a, **k: (status, body)
        try:
            extract_method('do_GET', self.ns)(self.handler)
        except Exception:
            pass   # 只关心是否延长了死线；后续分支依赖大量闭包
        self.assertTrue(extend.called, 'AWG 配置下载没有延长死线')
        self.assertGreaterEqual(extend.call_args[0][0], 60)

    def test_concurrent_bbr_request_is_refused(self):
        """BBR 设置串行化：已有一个在应用时第二个回 409（2026-11-06 修）。"""
        lock = self.ns['bbr_apply_lock']
        lock.acquire()
        try:
            status, body = self.invoke('_h_post_set_bbr', {'version': 'v1'})
        finally:
            lock.release()
        self.assertEqual(status, 409, body)

    def test_padded_password_is_rejected_not_trimmed(self):
        """Web 建户不静默去掉密码首尾空白（2026-11-04 修，与 API 同一规则）。"""
        status, _ = self.invoke('_h_post_manage_user', {'action': 'create', 'user_id': 'qa-user',
                                                        'password': 'abc '})
        self.assertEqual(status, 400)
        self.assertNotIn('qa-user', self.data['users'])

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

    def test_reality_rebuild_takes_clients_under_the_apply_lock(self):
        """重建 Reality 时，等锁期间被撤销的用户不能被写回（2026-11-04 修）。

        旧实现在拿 reality_apply_lock 之前就拍好 clients：apply_access 此时撤掉某人并清掉
        待撤销记录，重建拿到锁后写的仍是旧名单，这人又能连 Reality、且不会再被撤销。
        这里让锁在进入时删掉用户，模拟「等锁期间完成了撤销」。
        """
        self.data['users']['gone'] = {'password': 'pw-gone', 'status': 'active', 'expires_at': 4102444800}
        written = {}
        data = self.data

        class RevokingLock:
            def __enter__(self_inner):
                data['users'].pop('gone', None)
            def __exit__(self_inner, *exc):
                return False

        def capture(cfg, *a, **kw):
            written['cfg'] = copy.deepcopy(cfg)
        self.ns.update(reality_apply_lock=RevokingLock(), reality_clients=portal.reality_clients,
                       reality_registry=portal.reality_registry,
                       apply_xray_config_transaction=Mock(side_effect=capture))
        self.data['reality_config'] = {'private_key': 'k' * 43, 'public_key': 'p' * 43,
                                       'short_id': 'abcd1234', 'dest_sni': 'www.apple.com', 'port': 8444}
        portal.reality_registry(self.data)
        generate = extract_method('_generate_and_apply_reality', self.ns)
        try:
            generate(self.handler, restart=False)
        except Exception:
            pass  # 写完配置之后的步骤（重启、防火墙）不在本用例关心范围内
        cfg = written.get('cfg')
        self.assertIsNotNone(cfg, '没有走到写配置那一步')
        inbound = next(i for i in cfg['inbounds'] if i.get('tag') == portal.REALITY_INBOUND_TAG)
        self.assertNotIn('gone', [c.get('email') for c in inbound['settings']['clients']])

    def test_reenabling_reality_rechecks_its_saved_port(self):
        """Reality 已关闭时，保留的端口被别人占了要换一个（2026-11-04 修）。"""
        self.data['reality_config'] = {'private_key': 'k' * 43, 'public_key': 'p' * 43,
                                       'short_id': 'abcd1234', 'dest_sni': 'www.apple.com', 'port': 443}
        picked = {}
        def pick(**kw):
            picked.update(kw)
            raise RuntimeError('stop after picking')
        self.ns.update(_pick_reality_port=pick, has_managed_inbound=portal.has_managed_inbound,
                       REALITY_INBOUND_TAG=portal.REALITY_INBOUND_TAG)
        (self.hdir / 'xray.json').write_text('{"inbounds": []}', encoding='utf-8')
        generate = extract_method('_generate_and_apply_reality', self.ns)
        with self.assertRaises(RuntimeError):
            generate(self.handler, restart=False)
        self.assertEqual(picked.get('preferred'), 443)
        self.assertIs(picked.get('own_active'), False, picked)

    def test_reset_keys_does_not_turn_a_disabled_reality_back_on(self):
        """Reality 已关闭时「重置密钥」回 409，不能顺手把它重新打开（2026-11-04 修）。"""
        self.ns.update(has_managed_inbound=portal.has_managed_inbound,
                       REALITY_INBOUND_TAG=portal.REALITY_INBOUND_TAG)
        self.handler._generate_and_apply_reality = Mock()
        (self.hdir / 'xray.json').write_text('{"inbounds": []}', encoding='utf-8')
        status, body = self.invoke('_h_post_manage_reality', {'action': 'reset'})
        self.assertEqual(status, 409, body)
        self.handler._generate_and_apply_reality.assert_not_called()
        (self.hdir / 'xray.json').write_text(json.dumps({'inbounds': [
            {'tag': portal.REALITY_INBOUND_TAG, 'protocol': 'vless', 'port': 8444}]}), encoding='utf-8')
        status, body = self.invoke('_h_post_manage_reality', {'action': 'reset'})
        self.assertEqual(status, 200, body)
        self.handler._generate_and_apply_reality.assert_called_once()

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

    def test_bbr_applies_when_an_optional_tuning_key_is_missing(self):
        """内核没有 tcp_notsent_lowat 时照样开 BBR，只是不写这一项（2026-11-04 修）。"""
        applied = {}
        def run(args, **kw):
            if args == ['sysctl', '-n', 'net.ipv4.tcp_available_congestion_control']:
                return SimpleNamespace(returncode=0, stdout='reno cubic bbr', stderr='')
            if args == ['sysctl', '-n', 'net.ipv4.tcp_notsent_lowat']:
                return SimpleNamespace(returncode=255, stdout='', stderr='sysctl: cannot stat')
            if args[:2] == ['sysctl', '-n']:
                value = applied.get(args[2], {'net.ipv4.tcp_congestion_control': 'cubic',
                                              'net.core.default_qdisc': 'fq_codel'}.get(args[2], '1'))
                return SimpleNamespace(returncode=0, stdout=value, stderr='')
            if args[:2] == ['sysctl', '-p']:
                for line in Path(args[2]).read_text(encoding='utf-8').splitlines():
                    if '=' in line and not line.startswith('#'):
                        k, v = (x.strip() for x in line.split('=', 1))
                        applied[k] = v
                return SimpleNamespace(returncode=0, stdout='', stderr='')
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        self.run.side_effect = run
        self.ns['subprocess'].run = self.run
        conf = self.root / 'etc/sysctl.d/99-bbr.conf'
        mod = self.root / 'etc/modules-load.d/bbr.conf'
        for path in (conf, mod):
            path.parent.mkdir(parents=True, exist_ok=True)
        original_path = self.ns['Path']
        self.ns['Path'] = lambda value: (self.root / str(value).lstrip('/')
            if str(value) in ('/etc/modules-load.d/bbr.conf', '/etc/sysctl.d/99-bbr.conf') else original_path(value))
        status, body = self.invoke('_h_post_set_bbr', {'version': 'v1'})
        self.assertEqual(status, 200, body)
        text = conf.read_text(encoding='utf-8')
        self.assertIn('net.ipv4.tcp_congestion_control = bbr', text)
        self.assertNotIn('tcp_notsent_lowat', text)

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

    def test_proxy_list_host_is_bracketed_for_ipv6(self):
        """代理列表给前端的 host 要带方括号，前端直接拼进 socks5:// 链接（2026-11-04 修）。"""
        self.meta.write_text(json.dumps({'is_insecure': True, 'public_ip': '2001:db8::7',
                                         'server_name': 'x'}), encoding='utf-8')
        self.ns.update(read_meta_file=portal.read_meta_file, _host_for_url=portal._host_for_url,
                       proxy_services=portal.proxy_services)
        self.handler.reply_json = self.reply_json
        extract_method('_h_get_proxy_services', self.ns)(self.handler, 'proxy-services')
        status, body = self.response
        self.assertEqual(status, 200, body)
        self.assertEqual(body['host'], '[2001:db8::7]')

    def test_proxy_create_survives_a_null_container(self):
        """proxy_services 是 null / 数字时新增代理不能 500（2026-11-03 修）。"""
        for bad in (None, 7):
            with self.subTest(bad=bad):
                self.data['proxy_services'] = bad
                status, body = self.invoke('_h_post_manage_proxy', {'action': 'create', 'type': 'http'})
                self.assertEqual(status, 200, body)
                self.assertEqual(len(self.data['proxy_services']), 1)

    def test_proxy_apply_failure_rolls_back_new_record(self):
        self.reload.return_value = False
        status, body = self.invoke('_h_post_manage_proxy', {'action': 'create', 'type': 'http'})
        self.assertEqual(status, 500)
        self.assertFalse(body.get('ok'))
        self.assertEqual(self.data['proxy_services'], [])

    def test_proxy_save_failure_restores_memory_before_returning_error(self):
        before = copy.deepcopy(self.data['proxy_services'])
        self.ns['save_data'] = Mock(side_effect=OSError('disk full'))
        status, body = self.invoke('_h_post_manage_proxy', {'action': 'create', 'type': 'http'})
        self.assertEqual(status, 500, body)
        self.assertEqual(self.data['proxy_services'], before)
        self.reload.assert_not_called()

    def test_proxy_delete_save_failure_restores_memory(self):
        original = [{'id': 'proxy_fixture', 'type': 'http', 'port': 32001}]
        self.data['proxy_services'] = copy.deepcopy(original)
        self.ns['save_data'] = Mock(side_effect=OSError('disk full'))
        status, body = self.invoke('_h_post_manage_proxy', {'action': 'delete', 'id': 'proxy_fixture'})
        self.assertEqual(status, 500, body)
        self.assertEqual(self.data['proxy_services'], original)
        self.reload.assert_not_called()

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

    def test_core_install_refuses_foreign_xray_unit(self):
        """官方脚本装的 xray.service 不被覆盖，二进制也不替换（2026-11-04 修）。"""
        self.ns['acquire_core_operation_lock'] = Mock(return_value=os.open(os.devnull, os.O_RDONLY))
        self.ns['xray_unit_foreign'] = Mock(return_value=True)
        self.ns['XRAY_FOREIGN_ERROR'] = 'foreign'
        install = self.ns['install_xray_binary'] = Mock(return_value=(True, ''))
        status, body = self.invoke_core_install()
        self.assertEqual(status, 409)
        install.assert_not_called()

    def test_core_install_returns_conflict_when_cross_process_lock_is_held(self):
        self.ns['acquire_core_operation_lock'] = Mock(
            side_effect=RuntimeError('another core operation is running'))
        install = self.ns['install_xray_binary'] = Mock()
        status, body = self.invoke_core_install()
        self.assertEqual(status, 409)
        self.assertFalse(body['ok'])
        install.assert_not_called()

    def test_core_upgrade_marker_save_failure_rolls_back_and_does_not_start_worker(self):
        self.handler._extend_deadline = lambda *args, **kwargs: True
        self.ns['core_operation_lock'] = threading.RLock()
        self.ns['core_operation_file_lock'] = lambda: __import__('contextlib').nullcontext()
        self.ns['core_upgrade_lock'] = threading.RLock()
        self.ns['portal_upgrade_lock'] = threading.Lock()
        self.ns['data'] = self.data
        self.handler._h_post_do_upgrade_impl = lambda _prefix: extract_method(
            '_h_post_do_upgrade_impl', self.ns)(self.handler, _prefix)
        before = copy.deepcopy(self.data)
        self.ns['save_data'] = Mock(side_effect=OSError('disk full'))
        created = []
        self.ns['threading'] = SimpleNamespace(Thread=lambda **kwargs:
            (created.append(kwargs) or SimpleNamespace(start=Mock())))
        self.handler.path = '/test-token/do-upgrade'
        self.handler.headers = {'Content-Length': str(len(urlencode({'target': 'core'})))}
        self.handler.rfile = io.BytesIO(urlencode({'target': 'core'}).encode())
        status, body = extract_method('_h_post_do_upgrade', self.ns)(
            self.handler, '/test-token/')
        self.assertEqual(status, 503, body)
        self.assertEqual(self.data, before)
        self.assertEqual(created, [])

    def test_xray_install_enable_failure_does_not_apply_reality(self):
        self.handler._extend_deadline = lambda *args, **kwargs: True
        self.ns['core_operation_lock'] = threading.RLock()
        self.ns['core_operation_file_lock'] = lambda: __import__('contextlib').nullcontext()
        self.ns['acquire_core_operation_lock'] = Mock(return_value=29)
        self.ns['os'] = SimpleNamespace(close=Mock())
        self.ns['install_xray_binary'] = Mock(return_value=(True, 'installed'))
        self.ns['write_xray_unit'] = Mock()
        self.handler._generate_and_apply_reality = Mock()
        self.run.side_effect = lambda args, **kwargs: SimpleNamespace(
            returncode=1 if args[:3] == ['systemctl', 'enable', 'xray'] else 0,
            stdout='active', stderr='enable failed')
        self.ns['subprocess'].run = self.run
        self.handler.rfile = io.BytesIO(b'')
        self.handler.headers = {'Content-Length': '0'}
        status, body = extract_method('_h_post_install_xray', self.ns)(
            self.handler, '/test-token/')
        self.assertEqual(status, 500, body)
        self.assertIn('开机自启设置失败', body['error'])
        self.handler._generate_and_apply_reality.assert_not_called()

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

    def recover_on_start(self, clients, state='inactive', restart_sticks=True,
                         apply_result=True, suspended=False):
        """跑一次门户启动时的 Xray 对齐；返回 (日志说明, systemctl 调用, apply_access 次数)。"""
        path = self.hdir / 'xray.json'
        path.unlink(missing_ok=True)
        if clients is not None:
            path.write_text(json.dumps({'inbounds': [
                {'tag': portal.VMESS_INBOUND_TAG, 'settings': {'clients': clients}}]}), encoding='utf-8')
        service, calls, applied = {'state': state}, [], []

        def run(args, **kwargs):
            calls.append(args)
            if args[1] == 'restart' and restart_sticks:
                service['state'] = 'active'
            return SimpleNamespace(returncode=0)

        def apply_access():
            applied.append(True)
            return apply_result

        note = portal.recover_xray_service_on_start(
            self.STARTUP_DATA, threading.RLock(), apply_access, lambda unit: suspended, path,
            run=run, systemd_state=lambda unit: service['state'], sleep=lambda seconds: None)
        return note, calls, len(applied)

    STARTUP_DATA = {'users': {'alice': {'status': 'active'}}}

    def test_startup_restarts_a_stopped_xray_and_confirms_it_came_up(self):
        in_sync = portal.vmess_clients(self.STARTUP_DATA)
        self.assertEqual(self.recover_on_start(None), ('', [], 0))
        self.assertEqual(self.recover_on_start(in_sync, state='active'), ('', [], 0))
        self.assertEqual(self.recover_on_start(in_sync),
                         ('启动时恢复了 xray 服务',
                          [['systemctl', 'reset-failed', 'xray'], ['systemctl', 'restart', 'xray']], 0))
        note, calls, _ = self.recover_on_start(in_sync, restart_sticks=False)
        self.assertTrue(note.startswith('启动时恢复 xray 服务失败'), note)
        self.assertIn(['systemctl', 'restart', 'xray'], calls)
        self.assertEqual(self.recover_on_start(in_sync, suspended=True), ('', [], 0))

    def test_startup_rewrites_drifted_clients_and_only_then_starts_xray(self):
        stale = [{'id': portal.vmess_uuid_for_user('bob'), 'email': 'bob'}]
        # 运行中：apply_access 自己改写并重启，不再额外重启。
        self.assertEqual(self.recover_on_start(stale, state='active'),
                         ('启动时按 portal.json 重写了 xray clients',
                          [['systemctl', 'reset-failed', 'xray']], 1))
        # 停着：改写成功后还要把它拉起来。
        note, calls, applied = self.recover_on_start(stale)
        self.assertEqual(note, '启动时按 portal.json 重写了 xray clients；启动时恢复了 xray 服务')
        self.assertEqual((calls[-1], applied), (['systemctl', 'restart', 'xray'], 1))
        # 没改写成功：旧文件里的 bob 可能是该收回的用户，不能拉起。
        note, calls, applied = self.recover_on_start(stale, apply_result=False)
        self.assertEqual(note, '启动时补同步 clients 失败，交给撤销线程重试')
        self.assertNotIn(['systemctl', 'restart', 'xray'], calls)
        self.assertEqual(self.recover_on_start(stale, suspended=True), ('', [], 0))

    def test_vmess_disable_save_failure_restores_inbound_and_state(self):
        path = self.hdir / 'xray.json'
        original = {'inbounds': [{'tag': portal.VMESS_INBOUND_TAG, 'port': 2087,
                                  'protocol': 'vmess', 'settings': {'clients': []}}],
                    'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}]}
        path.write_text(json.dumps(original), encoding='utf-8')
        self.data['vmess_config'] = {'port': 2087, 'uri': 'vmess://fixture'}
        self.ns['Path'] = lambda value: path if str(value) == '/etc/hysteria/xray.json' else Path(value)
        self.ns['has_managed_inbound'] = portal.has_managed_inbound
        self.ns['remove_managed_inbound'] = portal.remove_managed_inbound
        self.ns['core_operation_file_lock'] = lambda: __import__('contextlib').nullcontext()
        self.ns['core_operation_lock'] = threading.RLock()
        self.ns['_systemd_state'] = lambda _: 'inactive'
        self.ns['apply_xray_config_transaction'] = Mock(side_effect=lambda cfg, **kw:
            Path(kw['config_path']).write_text(json.dumps(cfg), encoding='utf-8'))
        self.ns['save_data'] = Mock(side_effect=OSError('disk full'))
        status, body = self.invoke('_h_post_manage_vmess', {'action': 'disable'})
        self.assertEqual(status, 500, body)
        self.assertEqual(json.loads(path.read_text(encoding='utf-8')), original)
        self.assertEqual(self.data['vmess_config']['port'], 2087)

    def test_vmess_enable_restores_portal_state_when_xray_rollback_restart_fails(self):
        self.ns['Path'] = lambda value: (self.hdir / 'xray.json' if str(value) == '/etc/hysteria/xray.json'
                                        else self.root / 'usr/local/bin/xray' if str(value) == '/usr/local/bin/xray'
                                        else Path(value))
        self.ns['Path']('/usr/local/bin/xray').touch()
        self.ns['Path']('/etc/hysteria/xray.json').write_text(
            json.dumps({'inbounds': [], 'outbounds': [{'protocol': 'freedom'}]}), encoding='utf-8')
        self.ns['read_meta_file'] = lambda _: {'server_name': 'node.example.com', 'public_ip': '203.0.113.10'}
        self.ns['_is_dns_name'] = lambda _: True
        self.handler._vmess_certificate = lambda *a: ('cert.pem', 'key.pem', 'node.example.com')
        self.handler._vmess_ws_path = lambda: '/fixture'
        self.ns['managed_reserved_ports'] = lambda *a, **kw: set()
        self.ns['_pick_reality_port'] = lambda **kw: (2087, '')
        self.ns['vmess_clients'] = lambda _: [{'id': 'fixture', 'email': 'placeholder'}]
        self.ns['core_operation_file_lock'] = lambda: __import__('contextlib').nullcontext()
        self.ns['core_operation_lock'] = threading.RLock()
        self.ns['_systemd_state'] = lambda _: 'active'
        self.ns['apply_xray_config_with_meter'] = Mock(side_effect=lambda cfg, target, *_:
            target.write_text(json.dumps(cfg), encoding='utf-8'))
        self.ns['apply_xray_config_transaction'] = Mock(side_effect=RuntimeError('rollback restart failed'))
        self.ns['save_data'] = Mock(side_effect=OSError('disk full'))
        before = copy.deepcopy(self.data)
        with self.assertRaisesRegex(RuntimeError, 'rollback restart failed'):
            extract_method('_apply_vmess_enable', self.ns)(self.handler)
        self.assertNotIn('vmess_config', self.data)
        self.assertEqual(self.data['users'], before['users'])

    def test_vmess_enable_keeps_previously_stopped_xray_off(self):
        self.ns['Path'] = lambda value: (self.hdir / 'xray.json' if str(value) == '/etc/hysteria/xray.json'
                                        else self.root / 'usr/local/bin/xray' if str(value) == '/usr/local/bin/xray'
                                        else Path(value))
        self.ns['Path']('/usr/local/bin/xray').touch()
        self.ns['read_meta_file'] = lambda _: {'server_name': 'node.example.com', 'public_ip': '203.0.113.10'}
        self.ns['_is_dns_name'] = lambda _: True
        self.handler._vmess_certificate = lambda *a: ('cert.pem', 'key.pem', 'node.example.com')
        self.handler._vmess_ws_path = lambda: '/fixture'
        self.ns['managed_reserved_ports'] = lambda *a, **kw: set()
        self.ns['_pick_reality_port'] = lambda **kw: (2087, '')
        self.ns['vmess_clients'] = lambda _: [{'id': 'fixture', 'email': 'placeholder'}]
        self.ns['core_operation_file_lock'] = lambda: __import__('contextlib').nullcontext()
        self.ns['core_operation_lock'] = threading.RLock()
        self.ns['_systemd_state'] = lambda _: 'inactive'
        self.ns['apply_xray_config_with_meter'] = Mock(side_effect=lambda cfg, target, *_:
            target.write_text(json.dumps(cfg), encoding='utf-8'))
        self.ns['apply_xray_config_transaction'] = Mock(side_effect=lambda cfg, **kw:
            Path(kw['config_path']).write_text(json.dumps(cfg), encoding='utf-8'))
        self.ns['save_data'] = Mock(side_effect=OSError('disk full'))
        status, _ = self.invoke('_h_post_manage_vmess', {'action': 'enable'})
        self.assertEqual(status, 500)
        self.assertFalse(any(call.args[0] == ['systemctl', 'restart', 'xray']
                             for call in self.run.call_args_list))

    def test_tuic_disable_save_failure_restores_config_and_service(self):
        config_path = self.hdir / portal.TUIC_CONFIG_NAME
        old_file = b'{"inbounds":[{"type":"tuic","listen_port":41001}]}'
        config_path.write_bytes(old_file)
        old_state = {'enabled': True, 'port': 41001, 'secret': 'fixture'}
        self.data['tuic_config'] = copy.deepcopy(old_state)
        self.ns['portal_path'] = self.hdir / 'portal.json'
        self.ns['TUIC_CONFIG_NAME'] = portal.TUIC_CONFIG_NAME
        self.ns['TUIC_SERVICE'] = 'hy2-tuic'
        self.ns['tuic_apply_lock'] = threading.RLock()
        self.ns['_active_tuic_config'] = lambda: self.data.get('tuic_config')
        self.ns['config_section'] = lambda data, key: data.get(key, {})
        self.ns['_systemd_state'] = lambda _: 'inactive'
        self.ns['_service_stop_confirmed'] = lambda result, state: True
        self.ns['_systemd_service_snapshot'] = lambda _: {'active': 'active', 'enabled': 'disabled'}
        self.ns['_restore_systemd_service_state'] = Mock(return_value=True)
        self.ns['save_data'] = Mock(side_effect=OSError('disk full'))
        self.run.reset_mock()
        status, body = self.invoke('_h_post_manage_tuic', {'action': 'disable'})
        self.assertEqual(status, 500, body)
        self.assertEqual(self.data['tuic_config'], old_state)
        self.assertEqual(config_path.read_bytes(), old_file)
        self.ns['_restore_systemd_service_state'].assert_called_once_with(
            'hy2-tuic', {'active': 'active', 'enabled': 'disabled'})
        self.assertNotIn(['systemctl', 'enable', 'hy2-tuic'], [c.args[0] for c in self.run.call_args_list])

    def test_anytls_disable_save_failure_restores_disabled_boot_state(self):
        config_path = self.hdir / portal.ANYTLS_CONFIG_NAME
        original_file = b'{"inbounds":[{"type":"anytls"}]}'
        config_path.write_bytes(original_file)
        original_cfg = {'enabled': True, 'port': 2096, 'secret': 'fixture'}
        self.data['anytls_config'] = copy.deepcopy(original_cfg)
        self.ns.update({
            'ANYTLS_CONFIG_NAME': portal.ANYTLS_CONFIG_NAME,
            'ANYTLS_SERVICE': 'hy2-anytls',
            'anytls_apply_lock': threading.RLock(),
            '_active_anytls_config': lambda: self.data.get('anytls_config'),
            '_systemd_state': lambda _: 'inactive',
            '_systemd_service_snapshot': lambda _: {'active': 'active', 'enabled': 'disabled'},
            '_restore_systemd_service_state': Mock(return_value=True),
            '_service_stop_confirmed': lambda result, state: True,
            'config_section': lambda data, key: data.get(key, {}),
            'save_data': Mock(side_effect=OSError('disk full')),
        })
        status, body = self.invoke('_h_post_manage_anytls', {'action': 'disable'})
        self.assertEqual(status, 500, body)
        self.assertEqual(self.data['anytls_config'], original_cfg)
        self.assertEqual(config_path.read_bytes(), original_file)
        self.ns['_restore_systemd_service_state'].assert_called_once_with(
            'hy2-anytls', {'active': 'active', 'enabled': 'disabled'})

    def test_anytls_disable_survives_a_corrupt_port(self):
        """端口被改坏时停用 AnyTLS 不能 500（2026-11-03 修，与 VMess / TUIC 对齐）。

        旧实现 int(acfg.get('port') or 0) 在 'abc' 上抛 ValueError：服务已经停了、
        配置文件已删，配置段却没标 enabled=False，面板一直显示「运行中」。
        """
        config_path = self.hdir / portal.ANYTLS_CONFIG_NAME
        config_path.write_bytes(b'{"inbounds":[{"type":"anytls"}]}')
        self.data['anytls_config'] = {'enabled': True, 'port': 'abc', 'secret': 'fixture'}
        self.ns.update({
            'ANYTLS_CONFIG_NAME': portal.ANYTLS_CONFIG_NAME,
            'ANYTLS_SERVICE': 'hy2-anytls',
            'anytls_apply_lock': threading.RLock(),
            '_active_anytls_config': lambda: self.data.get('anytls_config'),
            '_systemd_state': lambda _: 'inactive',
            '_systemd_service_snapshot': lambda _: {'active': 'active', 'enabled': 'enabled'},
            '_restore_systemd_service_state': Mock(return_value=True),
            '_service_stop_confirmed': lambda result, state: True,
            'config_section': lambda data, key: data.get(key, {}),
            '_valid_port': portal._valid_port,
            'save_data': Mock(), 'regenerate_page': Mock(),
            'close_protocol_port': Mock(return_value=True),
        })
        status, body = self.invoke('_h_post_manage_anytls', {'action': 'disable'})
        self.assertEqual(status, 200, body)
        self.assertIs(self.data['anytls_config'].get('enabled'), False)
        self.ns['close_protocol_port'].assert_not_called()

    def test_anytls_enable_failure_restores_new_or_existing_unit(self):
        for old_unit in (None, b'custom previous unit'):
            with self.subTest(old_unit=old_unit):
                unit_path = self.root / 'etc/systemd/system/hy2-anytls.service'
                unit_path.parent.mkdir(parents=True, exist_ok=True)
                unit_path.unlink(missing_ok=True)
                if old_unit is not None:
                    unit_path.write_bytes(old_unit)
                original_cfg = {'enabled': False, 'port': 2096, 'secret': 'fixture'}
                self.data['anytls_config'] = copy.deepcopy(original_cfg)
                self.ns.update({
                    'ANYTLS_SERVICE': 'hy2-anytls',
                    'ANYTLS_CONFIG_NAME': portal.ANYTLS_CONFIG_NAME,
                    'ANYTLS_UNIT_CONTENT': portal.ANYTLS_UNIT_CONTENT,
                    'anytls_apply_lock': threading.RLock(),
                    'read_meta_file': lambda _: {'server_name': 'node.example.com'},
                    '_is_dns_name': lambda _: True,
                    '_singbox_version': lambda: portal.ANYTLS_MIN_SINGBOX,
                    'managed_reserved_ports': lambda *a, **kw: set(),
                    '_pick_reality_port': lambda **kw: (2096, ''),
                    '_systemd_state': lambda _: 'inactive',
                    'anytls_users': lambda _: [],
                    'build_anytls_config': lambda *a: {},
                    'apply_anytls_config': Mock(),
                    '_systemd_service_snapshot': lambda _: {'active': 'inactive', 'enabled': 'disabled'},
                    '_restore_systemd_service_state': Mock(return_value=True),
                    'save_data': Mock(side_effect=OSError('disk full')),
                    'config_section': lambda data, key: data.get(key, {}),
                })
                self.handler._vmess_certificate = lambda *a: ('cert.pem', 'key.pem', 'node.example.com')
                commands = []
                def run(args, **kwargs):
                    commands.append(args)
                    if args[:2] == ['systemctl', 'enable']:
                        return SimpleNamespace(returncode=0)
                    return SimpleNamespace(returncode=0)
                self.ns['subprocess'].run = run
                with patch.object(portal.subprocess, 'run', side_effect=run):
                    with self.assertRaisesRegex(OSError, 'disk full'):
                        extract_method('_apply_anytls_enable', self.ns)(self.handler)
                self.assertEqual(self.data['anytls_config'], original_cfg)
                self.assertEqual(unit_path.read_bytes() if old_unit is not None else None, old_unit)
                self.assertIn(['systemctl', 'daemon-reload'], commands)

    def test_anytls_port_move_closes_the_old_firewall_port(self):
        """协议换端口后收回旧端口的放行规则（2026-11-03 修，与 Reality 一致）。

        旧实现只放行新端口，旧端口的入站规则一直留在 ufw / firewalld 里。
        """
        self.data['anytls_config'] = {'enabled': False, 'port': 2096, 'secret': 'fixture'}
        fw, closed = [], []
        self.ns.update({
            'ANYTLS_SERVICE': 'hy2-anytls',
            'ANYTLS_CONFIG_NAME': portal.ANYTLS_CONFIG_NAME,
            'ANYTLS_UNIT_CONTENT': portal.ANYTLS_UNIT_CONTENT,
            'anytls_apply_lock': threading.RLock(),
            'read_meta_file': lambda _: {'server_name': 'node.example.com'},
            '_is_dns_name': lambda _: True,
            '_singbox_version': lambda: portal.ANYTLS_MIN_SINGBOX,
            'managed_reserved_ports': lambda *a, **kw: set(),
            '_pick_reality_port': lambda **kw: (2097, '原端口 2096 已被占用，自动改用 2097'),
            '_systemd_state': lambda _: 'inactive',
            'anytls_users': lambda _: [],
            'build_anytls_config': lambda *a: {},
            'apply_anytls_config': Mock(),
            '_systemd_service_snapshot': lambda _: {'active': 'inactive', 'enabled': 'disabled'},
            '_restore_systemd_service_state': Mock(return_value=True),
            'save_data': Mock(), 'regenerate_page': Mock(),
            'config_section': lambda data, key: data.get(key, {}),
            '_valid_port': portal._valid_port,
            'firewall_port': lambda port, proto, open_=True: fw.append((port, proto, open_)) or True,
            'close_protocol_port': lambda port, proto, key: closed.append((port, proto, key)) or True,
        })
        self.handler._vmess_certificate = lambda *a: ('cert.pem', 'key.pem', 'node.example.com')
        run = lambda args, **kw: SimpleNamespace(returncode=0, stdout='', stderr='')
        self.ns['subprocess'].run = run
        (self.root / 'etc/systemd/system').mkdir(parents=True, exist_ok=True)
        with patch.object(portal.subprocess, 'run', side_effect=run):
            extract_method('_apply_anytls_enable', self.ns)(self.handler)
        self.assertIn((2097, 'tcp', True), fw)
        self.assertEqual(closed, [(2096, 'tcp', 'anytls_config')])

    def test_tuic_enable_failure_restores_new_or_existing_unit(self):
        for old_unit in (None, b'custom previous unit'):
            with self.subTest(old_unit=old_unit):
                unit_path = self.root / 'etc/systemd/system/hy2-tuic.service'
                unit_path.parent.mkdir(parents=True, exist_ok=True)
                unit_path.unlink(missing_ok=True)
                if old_unit is not None:
                    unit_path.write_bytes(old_unit)
                old_cfg = {'enabled': False, 'port': 41000, 'secret': 'fixture'}
                self.data['tuic_config'] = copy.deepcopy(old_cfg)
                self.ns.update({
                    'TUIC_SERVICE': 'hy2-tuic', 'TUIC_CONFIG_NAME': portal.TUIC_CONFIG_NAME,
                    'TUIC_UNIT_CONTENT': portal.TUIC_UNIT_CONTENT,
                    'tuic_apply_lock': threading.RLock(),
                    'read_meta_file': lambda _: {'server_name': 'node.example.com', 'listen_port': 443},
                    '_is_dns_name': lambda _: True,
                    '_singbox_version': lambda: portal.ANYTLS_MIN_SINGBOX,
                    'pick_tuic_port': lambda *a, **kw: 41001,
                    'tuic_users': lambda _: [], 'build_tuic_config': lambda *a: {},
                    'apply_anytls_config': Mock(),
                    '_systemd_state': lambda _: 'inactive',
                    '_systemd_service_snapshot': lambda _: {'active': 'inactive', 'enabled': 'disabled'},
                    '_restore_systemd_service_state': Mock(return_value=True),
                    'save_data': Mock(side_effect=OSError('disk full')),
                    'config_section': lambda data, key: data.get(key, {}),
                })
                self.handler._vmess_certificate = lambda *a: ('cert.pem', 'key.pem', 'node.example.com')
                commands = []
                def run(args, **kwargs):
                    commands.append(args)
                    return SimpleNamespace(returncode=0)
                self.ns['subprocess'].run = run
                with patch.object(portal.subprocess, 'run', side_effect=run):
                    with self.assertRaisesRegex(OSError, 'disk full'):
                        extract_method('_apply_tuic_enable', self.ns)(self.handler)
                self.assertEqual(self.data['tuic_config'], old_cfg)
                self.assertEqual(unit_path.read_bytes() if old_unit is not None else None, old_unit)
                self.assertIn(['systemctl', 'daemon-reload'], commands)

    def test_anytls_and_tuic_partial_stop_failure_restore_service_state(self):
        for protocol in ('anytls', 'tuic'):
            with self.subTest(protocol=protocol):
                service = 'hy2-' + protocol
                key = protocol + '_config'
                lock_name = protocol + '_apply_lock'
                old = {'enabled': True, 'port': 2096, 'secret': 'fixture'}
                self.data[key] = copy.deepcopy(old)
                self.ns.update({
                    'ANYTLS_CONFIG_NAME': portal.ANYTLS_CONFIG_NAME,
                    'TUIC_CONFIG_NAME': portal.TUIC_CONFIG_NAME,
                    'ANYTLS_SERVICE': 'hy2-anytls', 'TUIC_SERVICE': 'hy2-tuic',
                    lock_name: threading.RLock(),
                    '_active_anytls_config': lambda: self.data.get('anytls_config'),
                    '_active_tuic_config': lambda: self.data.get('tuic_config'),
                    'config_section': lambda data, section: data.get(section, {}),
                    '_systemd_service_snapshot': Mock(return_value={
                        'active': 'active', 'enabled': 'enabled'}),
                    '_restore_systemd_service_state': Mock(return_value=True),
                    '_systemd_state': lambda _: 'active',
                    '_service_stop_confirmed': lambda result, state: False,
                    'save_data': Mock(),
                })
                self.run.reset_mock()
                method_name = '_h_post_manage_' + protocol
                status, _ = self.invoke(method_name, {'action': 'disable'})
                self.assertEqual(status, 500)
                self.assertEqual(self.data[key], old)
                self.ns['_restore_systemd_service_state'].assert_called_with(
                    service, {'active': 'active', 'enabled': 'enabled'})

    def test_tuic_config_read_error_keeps_original_exception_and_state(self):
        old = {'enabled': True, 'port': 41000, 'secret': 'fixture'}
        self.data['tuic_config'] = copy.deepcopy(old)
        self.ns.update({
            'TUIC_SERVICE': 'hy2-tuic', 'TUIC_CONFIG_NAME': portal.TUIC_CONFIG_NAME,
            'TUIC_UNIT_CONTENT': portal.TUIC_UNIT_CONTENT,
            'tuic_apply_lock': threading.RLock(),
            'portal_path': self.hdir / 'portal.json',
            'read_meta_file': lambda _: {'server_name': 'node.example.com', 'listen_port': 443},
            '_is_dns_name': lambda _: True,
            '_singbox_version': lambda: portal.ANYTLS_MIN_SINGBOX,
            'pick_tuic_port': lambda *a, **kw: 41001,
            'tuic_users': lambda _: [],
            'config_section': lambda data, key: data.get(key, {}),
            '_systemd_service_snapshot': lambda _: {'active': 'inactive', 'enabled': 'disabled'},
            '_restore_systemd_service_state': Mock(return_value=True),
            'apply_anytls_config': Mock(),
        })
        self.handler._vmess_certificate = lambda *a: ('cert.pem', 'key.pem', 'node.example.com')
        class BrokenConfigPath:
            def exists(self):
                return True
            def read_bytes(self):
                raise PermissionError('cannot read TUIC config')
        class ConfigParent:
            def __truediv__(self, _):
                return BrokenConfigPath()
        self.ns['portal_path'] = SimpleNamespace(parent=ConfigParent())
        (self.root / 'etc/systemd/system').mkdir(parents=True, exist_ok=True)
        real_path = self.ns['Path']
        self.ns['Path'] = lambda value: (real_path(self.root / 'etc/systemd/system/hy2-tuic.service')
            if str(value) == '/etc/systemd/system/hy2-tuic.service' else real_path(value))
        with self.assertRaisesRegex(PermissionError, 'cannot read TUIC config'):
            extract_method('_apply_tuic_enable', self.ns)(self.handler)
        self.assertEqual(self.data['tuic_config'], old)

    def test_warp_save_failure_restores_memory_and_skips_apply(self):
        original = {'warp_enabled': False, 'warp_rules': [{'domain': 'example.com',
                                                           'outbound': 'direct'}]}
        self.data.update(copy.deepcopy(original))
        self.ns['save_data'] = Mock(side_effect=OSError('disk full'))
        self.ns['warp_backend_installed'] = lambda: True
        scheduled = []
        self.handler._reply_with_warp_apply = Mock(side_effect=lambda payload:
            scheduled.append(payload) or self.reply_json(200, payload))
        status, body = self.invoke('_h_post_manage_warp', {'action': 'enable'})
        self.assertEqual(status, 500, body)
        self.assertEqual({key: self.data[key] for key in original}, original)
        self.assertEqual(scheduled, [])

    def test_install_warp_migrates_legacy_port_under_the_apply_lock(self):
        """旧版 40000 端口的 WARP 出站在应用锁内改成 19898，不再由脚本锁外 sed（2026-11-04 修）。"""
        conf = self.hdir / 'config.yaml'
        conf.write_text('outbounds:\n  - name: warp\n    type: socks5\n    socks5:\n'
                        '      addr: 127.0.0.1:40000\n', encoding='utf-8')
        held = []

        class RecordingLock:
            def __enter__(self_inner):
                held.append(True)
            def __exit__(self_inner, *exc):
                held.append(False)
                return False

        writes = []
        def atomic_write(path, payload):
            writes.append(bool(held) and held[-1])
            Path(path).write_bytes(payload)
        self.ns.update(
            Path=lambda value: conf if str(value) == '/etc/hysteria/config.yaml' else Path(value),
            warp_apply_lock=RecordingLock(), atomic_write_private=atomic_write,
            DEFAULT_WARP_DOMAINS=portal.DEFAULT_WARP_DOMAINS)
        self.run.side_effect = lambda args, **kw: SimpleNamespace(returncode=0, stdout='', stderr='')
        self.handler._reply_with_warp_apply = lambda payload: self.reply_json(200, payload)
        status, body = self.invoke('_h_post_install_warp', {})
        self.assertEqual(status, 200, body)
        self.assertIn('addr: 127.0.0.1:19898', conf.read_text(encoding='utf-8'))
        self.assertEqual(writes, [True], '没有在 warp_apply_lock 内写 config.yaml')
        script = next(c.args[0][2] for c in self.run.call_args_list if c.args[0][:2] == ['bash', '-c'])
        self.assertNotIn('sed -i "s|addr: 127.0.0.1:40000', script)

    def test_warp_cannot_be_enabled_when_not_installed(self):
        """没装 WARP 时开启回 409，不把流量导向没人监听的 19898（2026-11-04 修）。"""
        self.data.update({'warp_enabled': False, 'warp_rules': []})
        self.ns['warp_backend_installed'] = lambda: False
        scheduled = []
        self.handler._reply_with_warp_apply = Mock(side_effect=lambda payload:
            scheduled.append(payload) or self.reply_json(200, payload))
        for action in ('enable', 'toggle'):
            with self.subTest(action=action):
                status, body = self.invoke('_h_post_manage_warp', {'action': action})
                self.assertEqual(status, 409, body)
                self.assertFalse(self.data['warp_enabled'])
                self.assertEqual(self.data['warp_rules'], [])
        self.assertEqual(scheduled, [])
        # 关闭不受影响。
        self.data['warp_enabled'] = True
        status, _ = self.invoke('_h_post_manage_warp', {'action': 'disable'})
        self.assertEqual(status, 200)
        self.assertFalse(self.data['warp_enabled'])

    def test_egress_schedule_save_failure_still_starts_apply_worker(self):
        self.ns['save_data'] = Mock(side_effect=[OSError('disk full')])
        self.ns['_egress_pending_count'] = lambda value: max(0, int(value or 0))
        thread = Mock()
        self.ns['threading'] = SimpleNamespace(Thread=Mock(return_value=thread))
        self.handler.reply_json = Mock(side_effect=self.reply_json)
        apply = extract_method('_reply_with_egress_apply', self.ns)
        apply(self.handler, {'message': 'queued'})
        self.handler.reply_json.assert_called_once()
        self.assertNotIn('egress_applying', self.data)
        self.assertNotIn('_egress_pending', self.data)
        self.ns['threading'].Thread.assert_called_once()
        thread.start.assert_called_once()

    def test_outbound_save_failure_restores_memory_and_skips_apply(self):
        original = {'custom_outbounds': [{'name': 'existing', 'type': 'socks5',
                                         'addr': '127.0.0.1:1080'}],
                    'warp_rules': [{'domain': 'example.com', 'outbound': 'existing'}],
                    'outbound_mode': 'rules'}
        self.data.update(copy.deepcopy(original))
        self.ns['save_data'] = Mock(side_effect=OSError('disk full'))
        scheduled = []
        self.handler._reply_with_egress_apply = Mock(side_effect=lambda payload, kind='outbound':
            scheduled.append((payload, kind)) or self.reply_json(200, payload))
        status, body = self.invoke('_ob_manage', {'action': 'delete', 'name': 'existing'})
        self.assertEqual(status, 500, body)
        for key, value in original.items():
            self.assertEqual(self.data[key], value)
        self.handler._reply_with_egress_apply.assert_not_called()
        self.assertEqual(scheduled, [])

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
        """启用路径必须持有跨进程核心锁 —— 在 handler 里拿，或在它调用的 _apply_*_enable 里拿。

        VMess / VLESS Encryption 的锁在 _apply_*_enable 内部；handler 再套一层会自锁
        （见 test_vmess_and_vlessenc_enable_do_not_deadlock_on_real_locks），
        所以这里接受两处之一，但不接受两处都拿。
        """
        source = Path(portal.__file__).read_text(encoding='utf-8')

        def method_body(name):
            start = source.index('        def ' + name + '(')
            end = source.find('\n        def ', start + 12)
            return source[start:end if end >= 0 else len(source)]

        for handler, inner in (('_h_post_manage_vmess', '_apply_vmess_enable'),
                               ('_h_post_manage_vlessenc', '_apply_vlessenc_enable'),
                               ('_h_post_manage_anytls', '_apply_anytls_enable'),
                               ('_h_post_manage_tuic', '_apply_tuic_enable')):
            with self.subTest(handler=handler):
                body = method_body(handler)
                action_start = body.index("if action == 'enable':")
                action_end = body.find("if not enabled:", action_start)
                enable_body = body[action_start:action_end if action_end >= 0 else len(body)]
                in_handler = 'core_operation_file_lock()' in enable_body
                in_inner = 'core_operation_file_lock()' in method_body(inner)
                self.assertTrue(in_handler or in_inner, '%s 的启用路径没有拿跨进程核心锁' % handler)
                self.assertFalse(in_handler and in_inner, '%s 在两层都拿核心锁，会自锁' % handler)

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

    def test_api_recreate_refused_while_revocation_pending(self):
        """REST users/create 同样拒绝重建收回未完成的同名账号（2026-11-04 修）。"""
        self.data['_pending_revocations'] = ['pend-a']
        status, body = self.invoke_api({'user_id': 'pend-a', 'password': 'pw-pend-a'})
        self.assertEqual(status, 409, body)
        self.assertNotIn('pend-a', self.data['users'])

    def test_corrupt_user_entry_never_500s_any_user_endpoint(self):
        """条目被改成非对象时各用户接口按「不存在 / 覆盖」处理，不 500（2026-11-06 修）。"""
        cases = [({'user_id': 'brokenx', 'extend_days': 30}, 'users/renew', 404),
                 ({'user_id': 'brokenx', 'status': 'disabled'}, 'users/status', 404),
                 ({'user_id': 'brokenx'}, 'users/get/brokenx', 404)]
        for payload, endpoint, want in cases:
            with self.subTest(endpoint=endpoint):
                self.data['users']['brokenx'] = 7
                status, body = self.invoke_api(payload, endpoint=endpoint)
                self.assertEqual(status, want, body)
        for bad in (7, 'x', [1]):
            with self.subTest(api_create=bad):
                self.data['users']['brokenx'] = bad
                status, body = self.invoke_api({'user_id': 'brokenx', 'password': 'pw-fix-entry'})
                self.assertEqual(status, 200, body)
                self.assertIsInstance(self.data['users']['brokenx'], dict)
            with self.subTest(web_create=bad):
                self.data['users']['brokenx'] = bad
                status, body = self.invoke('_h_post_manage_user',
                                           {'action': 'create', 'user_id': 'brokenx',
                                            'password': 'pw-fix-web'})
                self.assertIn(status, (200, 302), body)   # Web 表单成功走 302 回跳
                self.assertIsInstance(self.data['users']['brokenx'], dict)

    def test_api_update_of_a_corrupt_user_entry_is_404(self):
        """用户条目被改成非对象时 users/update 回 404 而不是 500（2026-11-06 修）。"""
        self.data['users']['brokenx'] = 7
        status, body = self.invoke_api({'user_id': 'brokenx', 'ip_limit': 2}, endpoint='users/update')
        self.assertEqual(status, 404, body)

    def test_dot_only_user_ids_cannot_be_created(self):
        """'.' / '..' 开户会让分享链接被折叠成别的地址，开户时就拒绝（2026-11-04 修）。"""
        self.ns['user_id_shareable'] = portal.user_id_shareable
        for uid in ('.', '..', '...'):
            with self.subTest(endpoint='api', uid=uid):
                status, _ = self.invoke_api({'user_id': uid, 'password': 'pw-dots'})
                self.assertEqual(status, 400)
                self.assertNotIn(uid, self.data['users'])
            with self.subTest(endpoint='web', uid=uid):
                status, _ = self.invoke('_h_post_manage_user', {'action': 'create', 'user_id': uid,
                                                                'password': 'pw-dots-web'})
                self.assertEqual(status, 400)
                self.assertNotIn(uid, self.data['users'])
        self.assertTrue(portal.user_id_shareable('a.b'))
        # 历史上已经存在的 '..' 用户仍要能删掉。
        self.data['users']['..'] = {'password': 'pw-legacy', 'status': 'active'}
        status, _ = self.invoke('_h_post_manage_user', {'action': 'delete', 'user_id': '..'})
        self.assertNotEqual(status, 400)
        self.assertNotIn('..', self.data['users'])

    def test_api_rejects_booleans_for_numeric_user_fields(self):
        """布尔值不能被当成数字：ip_limit / expires_at 一直在入口拒绝，traffic_gb 曾漏掉（2026-11-04 修）。

        float(True) == 1.0：{"traffic_gb": true} 会被当成 1 GB 配额。
        """
        self.data['users']['qa-user'] = {'password': 'old', 'status': 'active',
            'expires_at': 2200000000, 'limit_bytes': 10, 'ip_limit': 0}
        before = copy.deepcopy(self.data['users']['qa-user'])
        for field in ('ip_limit', 'expires_at'):
            with self.subTest(endpoint='update', field=field):
                status, _ = self.invoke_api({'user_id': 'qa-user', field: True}, 'users/update')
                self.assertEqual(status, 400)
                self.assertEqual(self.data['users']['qa-user'], before)
        for field in ('ip_limit', 'expires_at', 'duration_days', 'traffic_gb'):
            with self.subTest(endpoint='create', field=field):
                status, _ = self.invoke_api({'user_id': 'fresh-user', 'password': 'pw-x', field: True})
                self.assertEqual(status, 400)
                self.assertNotIn('fresh-user', self.data['users'])

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

    def test_password_change_kicks_sessions_using_the_old_password(self):
        """改密码后，用旧密码连着的 Hy2 会话必须被踢；只改别的字段时不踢（2026-11-03 修）。"""
        kick = self.handler._kick_old_password_sessions = Mock(return_value=True)
        self.data['users']['qa-user'] = {'password': 'old', 'status': 'active',
            'expires_at': 2200000000, 'limit_bytes': 10, 'ip_limit': 0}
        self.assertEqual(self.invoke_api({'user_id': 'qa-user', 'ip_limit': 3}, 'users/update')[0], 200)
        kick.assert_not_called()
        self.assertEqual(self.invoke_api({'user_id': 'qa-user', 'password': 'rotated'}, 'users/update')[0], 200)
        kick.assert_called_once_with('qa-user')
        kick.reset_mock()
        self.assertEqual(self.invoke_api({'user_id': 'qa-user', 'password': 'again', 'duration_days': 30})[0], 200)
        kick.assert_called_once_with('qa-user')
        kick.reset_mock()
        self.assertEqual(self.invoke_api({'user_id': 'fresh-user', 'password': 'pw-new', 'duration_days': 30})[0], 200)
        kick.assert_not_called()

    def test_kick_helper_targets_only_hy2_and_survives_failure(self):
        helper = extract_method('_kick_old_password_sessions', self.ns)
        calls = []
        self.ns['kick_hy2_users'] = lambda root, uids: calls.append(list(uids)) or True
        self.ns.setdefault('_log_ignored', lambda *a: None)
        self.assertTrue(helper(self.handler, 'qa-user'))
        self.assertEqual(calls, [['qa-user']])
        self.ns['kick_hy2_users'] = Mock(side_effect=OSError('stats down'))
        self.assertFalse(helper(self.handler, 'qa-user'))

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

    def test_renewing_a_permanent_user_keeps_it_permanent(self):
        """永久账号（未设到期）续费只加流量，不能被续成「今天 + N 天」（2026-11-12 修）。"""
        for permanent in ({'expires_at': None}, {}):
            with self.subTest(permanent=permanent):
                self.data['users']['perm'] = dict({'password': 'perm-pw', 'status': 'active',
                                                   'limit_bytes': 1024 ** 3, 'used_bytes': 0}, **permanent)
                status, body = self.invoke_api({'user_id': 'perm', 'add_traffic_gb': 1}, 'users/renew')
                self.assertEqual(status, 200, body)
                self.assertIsNone(self.data['users']['perm'].get('expires_at'), 'permanent user got an expiry')
                self.assertEqual(self.data['users']['perm']['limit_bytes'], 2 * 1024 ** 3)
        self.data['users']['dated'] = {'password': 'dated-pw', 'status': 'active', 'expires_at': 2200000000,
                                       'limit_bytes': 0, 'used_bytes': 0}
        self.assertEqual(self.invoke_api({'user_id': 'dated', 'extend_days': 1}, 'users/renew')[0], 200)
        self.assertEqual(self.data['users']['dated']['expires_at'], 2200000000 + 86400)

    def test_interrupted_core_upgrade_status_persists_across_restarts(self):
        path = self.hdir / 'portal.json'
        original = {'core_upgrade': {'state': 'running', 'version': 'v9.9.9'}}
        path.write_text(json.dumps(original), encoding='utf-8')
        first = json.loads(path.read_text(encoding='utf-8'))
        self.assertTrue(portal.persist_interrupted_core_job(path, first))
        second = json.loads(path.read_text(encoding='utf-8'))
        self.assertFalse(portal.persist_interrupted_core_job(path, second))
        self.assertEqual(second['core_upgrade']['state'], 'interrupted')
        self.assertIn('重启打断', second['core_upgrade']['error'])

    def test_core_uninstall_stop_failure_preserves_units_and_binary(self):
        self.handler.is_authenticated = lambda: True
        self.handler.rfile = io.BytesIO(urlencode({'name': 'xray'}).encode())
        self.handler.headers = {'Content-Length': str(len(urlencode({'name': 'xray'})))}
        self.ns['core_operation_lock'] = threading.RLock()
        self.ns['acquire_core_operation_lock'] = Mock(return_value=27)
        self.ns['os'] = SimpleNamespace(close=Mock())
        self.handler._core_users = lambda _: []
        binary = self.ns['Path']('/usr/local/bin/xray')
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_text('xray binary', encoding='utf-8')
        unit = self.ns['Path']('/etc/systemd/system/xray.service')
        unit.parent.mkdir(parents=True, exist_ok=True)
        unit.write_text('xray unit', encoding='utf-8')
        commands = []
        self.ns['subprocess'].run = Mock(side_effect=lambda args, **kw:
            (commands.append(args) or SimpleNamespace(returncode=1 if args[:3] ==
             ['systemctl', 'disable', '--now'] else 0)))
        states = {'hy2-anytls': 'active', 'hy2-tuic': 'active'}
        def run(args, **kwargs):
            commands.append(args)
            if args[:2] == ['systemctl', 'is-enabled']:
                return SimpleNamespace(returncode=0,
                    stdout='disabled' if args[2] == 'hy2-anytls' else 'enabled')
            if args[:3] == ['systemctl', 'disable', '--now'] and args[3] == 'hy2-tuic':
                return SimpleNamespace(returncode=1)
            if args[:2] == ['systemctl', 'disable'] and args[2] == 'hy2-anytls':
                states['hy2-anytls'] = 'inactive'
            if args[:2] == ['systemctl', 'start'] and args[2] == 'hy2-anytls':
                states['hy2-anytls'] = 'active'
            return SimpleNamespace(returncode=0)
        self.handler.rfile = io.BytesIO(urlencode({'name': 'sing-box'}).encode())
        self.handler.headers = {'Content-Length': str(len(urlencode({'name': 'sing-box'})))}
        self.handler._core_users = lambda _: []
        self.ns['subprocess'].run = Mock(side_effect=run)
        self.ns['_systemd_state'] = lambda unit: states[unit]
        self.ns['_service_stop_confirmed'] = portal._service_stop_confirmed
        status, body = extract_method('_h_post_uninstall_core', self.ns)(
            self.handler, '/test-token/')
        self.assertEqual(status, 500, body)
        self.assertTrue(unit.exists())
        self.assertTrue(binary.exists())
        self.assertNotIn(['systemctl', 'daemon-reload'], commands)
        self.assertIn(['systemctl', 'disable', 'hy2-anytls'], commands)
        self.assertIn(['systemctl', 'start', 'hy2-anytls'], commands)
        self.assertNotIn(['systemctl', 'enable', 'hy2-anytls'], commands)

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
        self.ns['subprocess'].run = Mock(return_value=SimpleNamespace(returncode=0, stdout='enabled'))
        self.ns['_systemd_state'] = lambda _: 'inactive'
        self.ns['_service_stop_confirmed'] = portal._service_stop_confirmed
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

    def test_api_set_status_rejects_string_false_without_mutation(self):
        original = {'password': 'qa-pass', 'status': 'active', 'expires_at': 2200000000}
        self.data['users']['qa-user'] = copy.deepcopy(original)
        status, body = self.invoke_api({'user_id': 'qa-user', 'active': 'false'}, 'users/set_status')
        self.assertEqual(status, 400, body)
        self.assertEqual(self.data['users']['qa-user'], original)
        self.sync.assert_not_called()

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

    def test_api_create_save_failure_restores_memory_and_skips_protocol_sync(self):
        portal.reality_registry(self.data)
        before = copy.deepcopy(self.data)
        self.ns['save_data'] = Mock(side_effect=OSError('disk full'))
        status, body = self.invoke_api({'user_id': 'new-user'}, 'users/create')
        self.assertEqual(status, 503, body)
        self.assertEqual(self.data, before)
        self.sync.assert_not_called()

    def test_api_update_save_failure_restores_existing_record(self):
        original = {'password': 'old', 'status': 'active', 'expires_at': 2200000000,
                    'limit_bytes': 10, 'used_bytes': 5, 'ip_limit': 0}
        self.data['users']['qa-user'] = copy.deepcopy(original)
        portal.reality_registry(self.data)
        before = copy.deepcopy(self.data)
        self.ns['save_data'] = Mock(side_effect=OSError('disk full'))
        status, body = self.invoke_api({'user_id': 'qa-user', 'password': 'new'}, 'users/create')
        self.assertEqual(status, 503, body)
        self.assertEqual(self.data, before)
        self.sync.assert_not_called()

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
                        {'user_id': 'qa-user', 'duration_days': '-1'},
                        {'user_id': 'fractional-days', 'duration_days': 1.9},
                        {'user_id': 'fractional-ip-limit', 'ip_limit': 1.5},
                        {'user_id': 'fractional-expiry', 'expires_at': 2200000000.5},
                        {'user_id': 'fractional-limit', 'limit_bytes': 10.25},
                        {'user_id': 'fractional-used', 'used_bytes': 4.5}):
            self.assertEqual(self.invoke_api(payload)[0], 400)
        self.assertNotIn('qa-user', self.data['users'])

    def test_web_create_rolls_back_when_reality_sync_fails(self):
        self.sync.return_value = False
        status, _ = self.invoke('_h_post_manage_user', {'action': 'create', 'user_id': 'qa-user'})
        self.assertEqual(status, 503)
        self.assertNotIn('qa-user', self.data['users'])

    def test_api_delete_save_failure_restores_user_and_queues(self):
        user = {'password': 'delete-me', 'status': 'active', 'used_bytes': 123}
        self.data['users']['qa-user'] = copy.deepcopy(user)
        self.data['_pending_revocations'] = ['other-user']
        self.data['usage_meter'] = {'totals': {'qa-user': {'hysteria': 123}}}
        portal.reality_registry(self.data)
        before = copy.deepcopy(self.data)
        self.ns['save_data'] = Mock(side_effect=OSError('disk full'))
        status, body = self.invoke_api({'user_id': 'qa-user'}, 'users/delete')
        self.assertEqual(status, 503, body)
        self.assertEqual(self.data, before)

    def test_web_delete_persists_revocation_when_reality_sync_fails(self):
        old = {'password': 'original-test-only', 'used_bytes': 99}
        self.data['users']['qa-user'] = dict(old)
        self.sync.return_value = False
        self.assertEqual(self.invoke('_h_post_manage_user', {'action': 'delete', 'user_id': 'qa-user'})[0], 503)
        self.assertNotIn('qa-user', self.data['users'])
        self.assertIn('qa-user', self.data['_pending_revocations'])

    def test_apply_access_save_failure_keeps_revocation_queued(self):
        source = Path(portal.__file__).read_text(encoding='utf-8')
        tree = ast.parse(source)
        serve = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'serve')
        apply_fn = next(n for n in ast.walk(serve)
                        if isinstance(n, ast.FunctionDef) and n.name == 'apply_access')
        ns = dict(self.ns)
        state = {'users': {}, '_pending_revocations': ['qa-user']}
        lock = threading.RLock()
        ns.update(data=state, data_lock=lock, access_apply_lock=threading.RLock(),
                  pending_revocations=portal.pending_revocations,
                  blocked_user_ids=lambda: set(),
                  copy=copy, acquire_core_operation_lock=Mock(return_value=41),
                  os=SimpleNamespace(close=Mock()),
                  enforce_node_access=Mock(return_value=True),
                  save_data=Mock(side_effect=[OSError('disk full'), None]),
                  core_lock_fd=None, portal_path=self.hdir / 'portal.json')
        wrapper = ast.parse('def outer():\n    last_enforced_blocked = None\n    last_enforce_error = ("", 0.0)\n'
                            '    def apply_access(force_ids=(), core_lock_fd=None):\n        pass\n    return apply_access')
        wrapper_fn = wrapper.body[0]
        inner = next(n for n in ast.walk(wrapper_fn)
                     if isinstance(n, ast.FunctionDef) and n.name == 'apply_access')
        inner.body = copy.deepcopy(apply_fn.body)
        exec(compile(ast.fix_missing_locations(wrapper), '<apply-access>', 'exec'), ns)
        apply_fn = ns['outer']()
        self.assertFalse(apply_fn())
        self.assertIn('qa-user', state['_pending_revocations'])
        self.assertEqual(ns['save_data'].call_count, 2)

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

    def test_outbound_save_survives_a_corrupt_container(self):
        """custom_outbounds 是 null / 数字时新增出站照常成功（2026-11-04 修）。"""
        for bad in (None, 7):
            with self.subTest(bad=bad):
                self.data['custom_outbounds'] = bad
                status, body = self.invoke('_ob_manage', {'action': 'save', 'name': 'proxy_b',
                                                          'type': 'socks5', 'addr': '127.0.0.1:1081'})
                self.assertEqual(status, 200, body)
                self.assertEqual([o['name'] for o in self.data['custom_outbounds']], ['proxy_b'])

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

    def _fresh_warp(self, enabled=False):
        self.data.pop('warp_rules', None)
        self.data['warp_enabled'] = enabled

    def test_warp_rule_edits_start_from_the_list_the_page_shows(self):
        """WARP 关着、没保存过名单时页面显示空表；加一个域名不能冒出整套默认名单（2026-11-12 修）。"""
        self._fresh_warp()
        self.assertEqual(portal.routing_state(self.data)['warp_rules'], [])
        status, body = self.invoke('_h_post_manage_warp', {'action': 'add_rule', 'domain': 'netflix.com'})
        self.assertEqual(status, 200, body)
        self.assertEqual(self.data['warp_rules'], [{'domain': 'netflix.com', 'outbound': 'warp_socks'}])
        self.assertEqual(body['rules'], ['netflix.com'])
        # 开着 WARP 时页面显示的就是默认名单，在它上面加。
        self._fresh_warp(enabled=True)
        status, body = self.invoke('_h_post_manage_warp', {'action': 'add_rule', 'domain': 'netflix.com'})
        self.assertEqual(body['rules'], list(portal.DEFAULT_WARP_DOMAINS) + ['netflix.com'])
        # 「恢复预设」照旧补齐默认名单。
        self._fresh_warp()
        status, body = self.invoke('_h_post_manage_warp', {'action': 'reset_rules'})
        self.assertEqual(body['rules'], list(portal.DEFAULT_WARP_DOMAINS))

    def test_warp_switches_materialise_the_default_list_only_when_warp_is_on(self):
        self.ns['warp_backend_installed'] = lambda: True
        for action in ('disable', 'apply'):
            with self.subTest(action=action):
                self._fresh_warp()
                status, body = self.invoke('_h_post_manage_warp', {'action': action})
                self.assertEqual(status, 200, body)
                self.assertNotIn('warp_rules', self.data, 'WARP was off: the default list must stay implicit')
                self.assertEqual(body['rules'], [])
        expected = list(portal.DEFAULT_WARP_DOMAINS)
        for action, enabled in (('enable', False), ('toggle', False), ('disable', True)):
            with self.subTest(action=action, enabled=enabled):
                self._fresh_warp(enabled)
                status, body = self.invoke('_h_post_manage_warp', {'action': action})
                self.assertEqual(status, 200, body)
                self.assertEqual([r['domain'] for r in self.data['warp_rules']], expected)
                self.assertEqual(body['rules'], expected)

    def test_bad_warp_domain_leaves_memory_untouched(self):
        self._fresh_warp()
        status, _ = self.invoke('_h_post_manage_warp', {'action': 'add_rule', 'domain': 'bad domain!'})
        self.assertEqual(status, 400)
        self.assertNotIn('warp_rules', self.data)

    def test_singbox_core_state_covers_both_of_its_units(self):
        """只开 TUIC 时 sing-box 核心不能显示「无服务」；两个单元有一个失败就报失败（2026-11-12 修）。"""
        units = self.root / 'etc/systemd/system'
        units.mkdir(parents=True, exist_ok=True)
        (units / 'hy2-tuic.service').write_text('[Unit]\n', encoding='utf-8')
        (units / 'xray.service').write_text('[Unit]\n', encoding='utf-8')
        states = {'hy2-tuic': 'active', 'xray': 'deactivating'}
        self.ns.update(_singbox_version=lambda: (1, 12, 4), awg_installed=lambda: False,
                       AWG_SVC_NAME='amneziawg-server', _systemd_state=lambda unit: states.get(unit, ''))

        def cores():
            extract_method('_h_get_cores_status', self.ns)(self.handler, 'cores-status')
            status, body = self.response
            self.assertEqual(status, 200, body)
            return {c['id']: c for c in body['cores']}

        current = cores()
        self.assertEqual(current['sing-box']['state'], 'active')
        self.assertIn('hy2-tuic', current['sing-box']['service'])
        self.assertNotIn('units', current['sing-box'])
        self.assertEqual(current['xray']['state'], 'deactivating', 'single-unit cores keep the raw state')
        (units / 'hy2-anytls.service').write_text('[Unit]\n', encoding='utf-8')
        states['hy2-anytls'] = 'failed'
        self.assertEqual(cores()['sing-box']['state'], 'failed')

    def test_warp_toggle_does_not_destroy_global_custom_outbound_mode(self):
        state = {'warp_enabled': True, 'outbound_mode': 'global',
                 'warp_rules': ['openai.com'],
                 'custom_outbounds': [{'name': 'qa_proxy', 'type': 'socks5', 'addr': '127.0.0.1:19898'}]}
        original = 'outbounds:\n  - name: direct_ipv4\n    type: direct\n    direct:\n      mode: "4"\n'
        text = portal.render_egress_config(original, state)
        self.assertIn('qa_proxy(all)', text)
        self.assertNotIn('warp_socks(suffix:openai.com)', text)

    def test_account_sync_includes_anytls_and_tuic_revocation(self):
        source = Path(portal.__file__).read_text(encoding='utf-8')
        apply_access_body = source.split('def apply_access(force_ids=(), core_lock_fd=None):', 1)[1]
        apply_access_body = apply_access_body.split('def expiry_access_worker():', 1)[0]
        self.assertIn('skip_anytls=False, skip_tuic=False', apply_access_body)

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

    def test_vmess_and_vlessenc_disable_keep_stable_identity(self):
        """停用只标 enabled=False，保留 ws_path / 密钥对 / 端口（2026-11-03）。

        旧实现整段删除：再启用时 VMess 换新 ws_path、VLESS-Enc 重新生成密钥对，
        端口回到默认，已下发的订阅全部失效。坏端口值也不能让停用 500。
        """
        cases = (('_h_post_manage_vmess', 'vmess_config', portal.VMESS_INBOUND_TAG, 'vmess',
                  {'port': 31000, 'ws_path': '/keep-this-path', 'uuid': 'u', 'domain': 'node.example.com'}),
                 ('_h_post_manage_vlessenc', 'vlessenc_config', portal.VLESSENC_INBOUND_TAG, 'vless',
                  {'port': 'abc', 'decryption': 'mlkem768x25519plus.native.600s.KEEP',
                   'encryption': 'mlkem768x25519plus.native.0rtt.KEEP', 'domain': 'node.example.com'}))
        for handler, key, tag, protocol, section in cases:
            with self.subTest(handler=handler):
                path = self.hdir / 'xray.json'
                path.write_text(json.dumps({'inbounds': [{'tag': tag, 'protocol': protocol,
                    'port': 31000, 'settings': {'clients': []}}]}), encoding='utf-8')
                self.data[key] = dict(section)
                self.ns.update(
                    Path=lambda value, p=path: p if str(value) == '/etc/hysteria/xray.json' else Path(value),
                    has_managed_inbound=lambda cfg, t: any(x.get('tag') == t for x in cfg.get('inbounds', [])),
                    remove_managed_inbound=lambda cfg, t: cfg.update(
                        inbounds=[x for x in cfg['inbounds'] if x.get('tag') != t]),
                    apply_xray_config_transaction=Mock(), unit_suspended=lambda _: False,
                    config_section=portal.config_section, _valid_port=portal._valid_port,
                    save_data=Mock(), regenerate_page=Mock(), close_protocol_port=Mock(return_value=True))
                status, body = self.invoke(handler, {'action': 'disable'})
                self.assertEqual(status, 200, body)
                kept = self.data[key]
                self.assertIs(kept.get('enabled'), False)
                for field, value in section.items():
                    self.assertEqual(kept.get(field), value, '%s 停用后丢了 %s' % (key, field))

    def test_disabled_section_does_not_reserve_its_port(self):
        """停用后保留的配置段不能继续占着端口，否则别的协议永远选不到它。"""
        data = {'vmess_config': {'enabled': False, 'port': 31000},
                'vlessenc_config': {'enabled': True, 'port': 31001}}
        reserved = portal.managed_reserved_ports({}, data)
        self.assertNotIn(31000, reserved)
        self.assertIn(31001, reserved)
        with patch.object(portal, '_systemd_state', return_value='inactive'):
            self.assertFalse(portal.protocol_port_in_use(31000, 'tcp', data))
            self.assertTrue(portal.protocol_port_in_use(31001, 'tcp', data))

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

    def test_reality_save_failure_restores_xray_config_and_service_states(self):
        xray_path = self.hdir / 'xray.json'
        original = {'inbounds': [{'tag': 'managed-old'}], 'outbounds': [{'protocol': 'freedom'}]}
        xray_path.write_text(json.dumps(original), encoding='utf-8')
        old_reality = copy.deepcopy(self.data['reality_config'])
        service = {'active': 'inactive', 'enabled': 'disabled'}
        commands = []

        def run(args, **kwargs):
            commands.append(args)
            if args[:2] == ['systemctl', 'is-active']:
                return SimpleNamespace(returncode=0, stdout=service['active'])
            if args[:2] == ['systemctl', 'is-enabled']:
                return SimpleNamespace(returncode=0, stdout=service['enabled'])
            if args[:2] == ['systemctl', 'enable']:
                service['enabled'] = 'enabled'
            elif args[:2] == ['systemctl', 'disable']:
                service['enabled'] = 'disabled'
            elif args[:2] == ['systemctl', 'start']:
                service['active'] = 'active'
            elif args[:2] == ['systemctl', 'stop'] or args[:3] == ['systemctl', 'disable', '--now']:
                service['active'] = 'inactive'
            return SimpleNamespace(returncode=0, stdout='')

        self.ns['Path'] = lambda value: xray_path if str(value) == '/etc/hysteria/xray.json' else Path(value)
        self.ns['managed_reserved_ports'] = lambda *a, **kw: set()
        self.ns['_pick_reality_port'] = lambda **kw: (8443, '')
        self.ns['add_private_network_guard'] = lambda cfg: cfg
        self.ns['_systemd_service_snapshot'] = portal._systemd_service_snapshot
        self.ns['_restore_systemd_service_state'] = portal._restore_systemd_service_state
        self.ns['apply_xray_config_transaction'] = Mock(side_effect=lambda cfg, **kw:
            (xray_path.write_text(json.dumps(cfg), encoding='utf-8'),
             service.update(active='active', enabled='enabled')))
        self.ns['save_data'] = Mock(side_effect=OSError('disk full'))
        self.ns['subprocess'].run = run
        with patch.object(portal.subprocess, 'run', side_effect=run):
            with self.assertRaisesRegex(OSError, 'disk full'):
                extract_method('_generate_and_apply_reality', self.ns)(self.handler)
        self.assertEqual(json.loads(xray_path.read_text(encoding='utf-8')), original)
        self.assertEqual(self.data['reality_config'], old_reality)
        self.assertEqual(service, {'active': 'inactive', 'enabled': 'disabled'})
        self.assertIn(['systemctl', 'disable', 'xray'], commands)
        self.assertIn(['systemctl', 'stop', 'xray'], commands)

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

    def test_xray_transaction_preserves_disabled_state_on_enable_failure_rollback(self):
        path = self.hdir / 'xray.json'
        old = b'{"inbounds":[]}'
        path.write_bytes(old)
        commands = []
        state = {'active': False}
        def run(args, **kwargs):
            commands.append(args)
            if args == ['xray-fixture', 'run', '-test', '-c', str(path.with_name('xray.json.portal-candidate.json'))]:
                return SimpleNamespace(returncode=0, stdout='', stderr='')
            if args[:3] == ['systemctl', 'is-active', 'xray']:
                return SimpleNamespace(returncode=0, stdout='active' if state['active'] else 'inactive')
            if args[:3] == ['systemctl', 'is-enabled', 'xray']:
                return SimpleNamespace(returncode=0, stdout='disabled')
            if args[:2] == ['systemctl', 'restart']:
                state['active'] = True
                return SimpleNamespace(returncode=0, stdout='', stderr='')
            if args[:2] == ['systemctl', 'enable']:
                return SimpleNamespace(returncode=1, stdout='', stderr='enable failed')
            if args[:2] == ['systemctl', 'stop']:
                state['active'] = False
            return SimpleNamespace(returncode=0, stdout='inactive', stderr='')
        with patch.object(portal.subprocess, 'run', side_effect=run):
            with self.assertRaisesRegex(RuntimeError, '自启动设置失败'):
                portal.apply_xray_config_transaction({'inbounds': [{'tag': 'vmess-ws-in'}]},
                    str(path), 'xray-fixture', restart=True)
        self.assertEqual(path.read_bytes(), old)
        self.assertIn(['systemctl', 'disable', 'xray'], commands)
        self.assertIn(['systemctl', 'stop', 'xray'], commands)
        self.assertEqual(commands.count(['systemctl', 'restart', 'xray']), 1)

    def test_xray_transaction_without_original_config_stops_failed_candidate(self):
        path = self.hdir / 'xray-new.json'
        commands = []
        state = {'active': False}
        def run(args, **kwargs):
            commands.append(args)
            if args[:3] == ['systemctl', 'is-active', 'xray']:
                return SimpleNamespace(returncode=0, stdout='active' if state['active'] else 'inactive')
            if args[:3] == ['systemctl', 'is-enabled', 'xray']:
                return SimpleNamespace(returncode=0, stdout='disabled')
            if args[:1] == ['xray-fixture']:
                return SimpleNamespace(returncode=0, stdout='', stderr='')
            if args[:2] == ['systemctl', 'restart']:
                state['active'] = True
                return SimpleNamespace(returncode=0, stdout='', stderr='')
            if args[:2] == ['systemctl', 'enable']:
                return SimpleNamespace(returncode=1, stdout='', stderr='enable failed')
            if args[:2] == ['systemctl', 'stop']:
                state['active'] = False
            return SimpleNamespace(returncode=0, stdout='inactive', stderr='')
        with patch.object(portal.subprocess, 'run', side_effect=run):
            with self.assertRaisesRegex(RuntimeError, '自启动设置失败'):
                portal.apply_xray_config_transaction({'inbounds': [{'tag': 'vless-reality-in'}]},
                    str(path), 'xray-fixture', restart=True)
        self.assertFalse(path.exists())
        self.assertFalse(state['active'])
        self.assertIn(['systemctl', 'stop', 'xray'], commands)

    def test_systemd_restore_preserves_enabled_runtime_state(self):
        calls = []
        state = {'active': 'active', 'enabled': 'enabled-runtime'}
        def run(args, **kwargs):
            calls.append(args)
            if args[:2] == ['systemctl', 'is-active']:
                return SimpleNamespace(returncode=0, stdout=state['active'])
            if args[:2] == ['systemctl', 'is-enabled']:
                return SimpleNamespace(returncode=0, stdout=state['enabled'])
            if args[:3] == ['systemctl', 'enable', '--runtime']:
                state['enabled'] = 'enabled-runtime'
                return SimpleNamespace(returncode=0)
            if args[:2] == ['systemctl', 'start']:
                state['active'] = 'active'
                return SimpleNamespace(returncode=0)
            return SimpleNamespace(returncode=0)
        with patch.object(portal.subprocess, 'run', side_effect=run):
            self.assertTrue(portal._restore_systemd_service_state(
                'hy2-anytls', {'active': 'active', 'enabled': 'enabled-runtime'}))
        self.assertIn(['systemctl', 'enable', '--runtime', 'hy2-anytls'], calls)
        self.assertEqual(state, {'active': 'active', 'enabled': 'enabled-runtime'})

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

    def run_verified_core_upgrade(self, suspended):
        """下载、摘要、systemctl 都是桩；只有二进制文件是真的（在临时目录里）。"""
        binary = self.root / 'hysteria'
        old, new = b'\x7fELF old-test-binary', b'\x7fELF new-test-binary'
        binary.write_bytes(old)
        binary.chmod(0o755)
        commands = []
        identity = {'pid': '100'}

        def fake_run(args, **kwargs):
            args = [str(a) for a in args]
            if args[0] == str(binary) or args[0].startswith(str(self.root / '.hysteria-update-')):
                current = Path(args[0]).read_bytes()
                return SimpleNamespace(returncode=0, stderr='',
                                       stdout='Version: %s\n' % ('v2.6.0' if current == old else 'v2.7.0'))
            commands.append(args[:2])
            if args[:2] == ['systemctl', 'start']:
                identity['pid'] = '200'
            if args[:2] == ['systemctl', 'show']:
                state = 'inactive' if suspended else 'active'
                return SimpleNamespace(returncode=0, stderr='', stdout=(
                    'ActiveState=%s\nMainPID=%s\nExecMainStartTimestamp=t%s\n'
                    % (state, identity['pid'], identity['pid'])))
            return SimpleNamespace(returncode=0, stdout='', stderr='')

        with patch.object(portal.subprocess, 'run', side_effect=fake_run), \
             patch.object(portal, 'fetch_text', return_value='{"tag_name": "app/v2.7.0"}'), \
             patch.object(portal, 'fetch_expected_sha256', return_value='0' * 64), \
             patch.object(portal, 'verify_sha256', return_value=True), \
             patch.object(portal.urllib.request, 'urlopen', side_effect=lambda *a, **k: io.BytesIO(new)), \
             patch.object(portal, '_unit_suspended', side_effect=lambda unit: suspended), \
             patch.object(portal.time, 'sleep'):
            result = portal.upgrade_core_binary(str(binary), str(self.root / 'backups'))
        return result, binary.read_bytes() == new, commands

    def test_core_upgrade_while_node_suspended_keeps_new_binary_without_starting(self):
        """与 install.sh 的核心更新一致：停用期间只换二进制，不启动、不回滚。"""
        result, replaced, commands = self.run_verified_core_upgrade(suspended=True)
        self.assertTrue(result['changed'], result)
        self.assertEqual(result['version'], 'v2.7.0')
        self.assertTrue(replaced, '停用期间已校验的新核心被回滚掉了')
        self.assertNotIn(['systemctl', 'start'], commands)
        self.assertNotIn(['systemctl', 'restart'], commands)

    def test_core_upgrade_restarts_and_verifies_when_not_suspended(self):
        result, replaced, commands = self.run_verified_core_upgrade(suspended=False)
        self.assertTrue(result['changed'], result)
        self.assertTrue(replaced)
        self.assertIn(['systemctl', 'start'], commands)

    def test_singbox_disable_works_when_config_file_is_missing(self):
        """配置文件丢了、data 仍是 enabled、服务还在跑：停用必须真的停服务并清掉 enabled，
        否则撤销同步会一直卡在「配置缺失、服务在跑」上。"""
        for name, key, service in (('_h_post_manage_anytls', 'anytls_config', 'hy2-anytls'),
                                   ('_h_post_manage_tuic', 'tuic_config', 'hy2-tuic')):
            with self.subTest(handler=name):
                self.data[key] = {'enabled': True, 'port': 45000, 'secret': 's' * 64,
                                  'domain': 'node.example.com'}
                state = {'value': 'active'}
                commands = []

                def fake_run(args, **kwargs):
                    commands.append(list(args))
                    if args[:2] == ['systemctl', 'disable']:
                        state['value'] = 'inactive'
                    return SimpleNamespace(returncode=0, stdout='', stderr='')

                self.ns.update(
                    subprocess=SimpleNamespace(run=fake_run, TimeoutExpired=subprocess.TimeoutExpired),
                    portal_path=self.hdir / 'portal.json',
                    ANYTLS_CONFIG_NAME=portal.ANYTLS_CONFIG_NAME, ANYTLS_SERVICE='hy2-anytls',
                    TUIC_CONFIG_NAME=portal.TUIC_CONFIG_NAME, TUIC_SERVICE='hy2-tuic',
                    _active_anytls_config=lambda: None, _active_tuic_config=lambda: None,
                    config_section=portal.config_section,
                    _systemd_state=lambda unit: state['value'],
                    _service_stop_confirmed=portal._service_stop_confirmed,
                    _systemd_service_snapshot=lambda unit: {'active': 'active', 'enabled': 'enabled'},
                    _restore_systemd_service_state=lambda unit, snap: True,
                    close_protocol_port=lambda *a: True,
                    anytls_apply_lock=threading.RLock(), tuic_apply_lock=threading.RLock())
                status, payload = self.invoke(name, {'action': 'disable'})
                self.assertEqual(status, 200, payload)
                self.assertNotIn('message', payload, '仍被当成「本来就没有启用」')
                self.assertIn(['systemctl', 'disable', '--now', service], commands)
                self.assertIs(self.data[key]['enabled'], False)
                self.assertEqual(self.data[key]['secret'], 's' * 64)

    def test_vmess_and_vlessenc_enable_do_not_deadlock_on_real_locks(self):
        """用真实的锁类型（不可重入的 threading.Lock + 真 flock）跑启用分支。

        旧实现在 handler 里先拿 core_operation_lock，_apply_*_enable 里又拿一次：
        请求永远挂起，核心锁一直被占，之后每轮撤销都报「another core operation」。
        """
        for handler_name, method in (('_h_post_manage_vmess', '_apply_vmess_enable'),
                                     ('_h_post_manage_vlessenc', '_apply_vlessenc_enable')):
            with self.subTest(handler=handler_name):
                core_lock = threading.Lock()
                lock_dir = self.root / ('locks-' + method)
                lock_dir.mkdir()
                self.ns.update(
                    core_operation_lock=core_lock,
                    core_operation_file_lock=lambda d=lock_dir: portal.core_operation_file_lock(str(d)),
                    reality_apply_lock=threading.Lock(), unit_suspended=lambda unit: False,
                    has_managed_inbound=lambda config, tag: False)

                def inner(ns=self.ns):
                    # 与真实 _apply_*_enable 相同的取锁顺序。
                    with ns['core_operation_lock'], ns['core_operation_file_lock'](), ns['reality_apply_lock']:
                        return {'port': 2087, 'uri': 'vmess://fixture'}

                setattr(self.handler, method, inner)
                result = {}
                worker = threading.Thread(daemon=True, target=lambda: result.update(
                    r=self.invoke(handler_name, {'action': 'enable'})))
                worker.start()
                worker.join(5)
                self.assertFalse(worker.is_alive(), '%s 启用时自锁挂起' % handler_name)
                self.assertEqual(result['r'][0], 200, result.get('r'))
                self.assertFalse(core_lock.locked(), '核心锁在请求结束后仍被占用')

    def test_reality_reset_reply_matches_whether_xray_restarted(self):
        """整机停用时重置密钥只写配置不重启，回复不能说「已重启生效」（2026-11-03）。"""
        for suspended, expected in ((False, '已重置密钥并重启生效'), (True, '恢复节点时生效')):
            with self.subTest(suspended=suspended):
                self.ns['unit_suspended'] = lambda unit, s=suspended: s and unit == 'xray'
                self.ns['core_operation_lock'] = threading.Lock()
                self.ns['core_operation_file_lock'] = lambda: __import__('contextlib').nullcontext()
                self.handler._generate_and_apply_reality = Mock()
                # 重置只对已开启的 Reality 生效（2026-11-04），夹具里放一个 Reality 入站。
                self.ns.update(has_managed_inbound=portal.has_managed_inbound,
                               REALITY_INBOUND_TAG=portal.REALITY_INBOUND_TAG)
                (self.hdir / 'xray.json').write_text(json.dumps({'inbounds': [
                    {'tag': portal.REALITY_INBOUND_TAG, 'protocol': 'vless', 'port': 8444}]}),
                    encoding='utf-8')
                status, payload = self.invoke('_h_post_manage_reality', {'action': 'reset'})
                self.assertEqual(status, 200, payload)
                self.assertIn(expected, payload['message'])
                self.handler._generate_and_apply_reality.assert_called_once_with(True, force=True)

    def test_explicit_immutable_ref_does_not_make_a_branch_lookup(self):
        with patch.object(portal.urllib.request, 'urlopen') as open_:
            self.assertEqual(portal.resolve_update_ref('a' * 40), 'a' * 40)
        open_.assert_not_called()

    def awg_suspended_fixture(self, suspended):
        """整机超额停用时 AWG 的启动类操作必须被拒；awgctl / systemctl 都是桩。"""
        awg_calls = []
        self.ns.update(
            AWG_SVC_NAME='amneziawg-server',
            VALID_AWG_NAME_RE=portal.re.compile(r'^[A-Za-z0-9_.\-]{1,32}$'),
            awg_installed=lambda: True, ensure_awgctl=lambda force=False: True,
            awg_state=lambda: {'line': '3'},
            awg_run=lambda args, timeout=0: awg_calls.append(args) or (0, '', ''),
            awg_err_tail=lambda *a, **kw: '',
            awg_endpoint_error=lambda endpoint: '',
            awg_operation_lock=threading.Lock(),
            unit_suspended=lambda unit: suspended and unit == 'amneziawg-server')
        return awg_calls

    def test_awg_start_actions_are_refused_while_node_is_suspended(self):
        for action, extra in (('start', {}), ('restart', {}), ('update', {}),
                              ('set_line', {'line': '2'})):
            with self.subTest(action=action):
                awg_calls = self.awg_suspended_fixture(True)
                self.run.reset_mock()
                status, payload = self.invoke('_h_post_manage_amneziawg',
                                              dict({'action': action}, **extra))
                self.assertEqual(status, 409, payload)
                self.assertEqual(awg_calls, [])
                self.run.assert_not_called()

    def test_awg_peer_changes_still_work_while_node_is_suspended(self):
        """peer 增删只改文件，服务没跑时 awgctl 不碰接口，停用期间照常可做。"""
        awg_calls = self.awg_suspended_fixture(True)
        status, payload = self.invoke('_h_post_manage_amneziawg',
                                      {'action': 'peer_del', 'name': 'phone'})
        self.assertEqual(status, 200, payload)
        self.assertEqual(awg_calls, [['peer-del', 'phone']])

    def test_awg_start_runs_when_node_is_not_suspended(self):
        self.awg_suspended_fixture(False)
        status, payload = self.invoke('_h_post_manage_amneziawg', {'action': 'start'})
        self.assertEqual(status, 200, payload)
        self.run.assert_called_once()
        self.assertEqual(self.run.call_args[0][0], ['systemctl', 'start', 'amneziawg-server'])


    def test_awg_peer_delete_extends_its_deadline(self):
        """peer_del 排队等 AWG 锁时不能被 30 秒死线掐断（2026-11-04 修）。"""
        self.awg_suspended_fixture(False)
        extended = []
        self.handler._extend_deadline = lambda seconds, heavy=False: extended.append(seconds) or True
        status, payload = self.invoke('_h_post_manage_amneziawg', {'action': 'peer_del', 'name': 'phone'})
        self.assertEqual(status, 200, payload)
        self.assertTrue(extended and max(extended) >= 90, extended)

    def test_awg_service_actions_wait_for_other_awg_operations(self):
        """启停 AWG 要与 peer 增删 / 更新串行（2026-11-04 修）。"""
        self.awg_suspended_fixture(False)
        held = []
        lock = self.ns['awg_operation_lock']
        self.run.side_effect = lambda args, **kw: held.append(lock.locked()) or SimpleNamespace(
            returncode=0, stdout='', stderr='')
        status, payload = self.invoke('_h_post_manage_amneziawg', {'action': 'stop'})
        self.assertEqual(status, 200, payload)
        self.assertEqual(held, [True], '启停 AWG 时没有持有 AWG 操作锁')

if __name__ == '__main__':
    unittest.main()