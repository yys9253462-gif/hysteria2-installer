"""TUIC v5 通道（sing-box 承载，2026-10-31）的回归测试。

锁住的行为：
  * 用户名单与准入判据 user_access_allowed 同源；
  * uuid / 密码由节点 secret 派生：稳定、不可由 user_id 猜出，uuid 合法；
  * 空名单给稳定占位用户；
  * 服务端配置拒绝内网 / 云元数据，ALPN 为 h3；
  * 订阅里的 Clash / sing-box 节点字段正确，并进入 url-test 组；
  * 收回同步与 AnyTLS 同样的规则，且接进了 enforce_node_access；
  * UDP 端口绝不落进 Hy2 端口跳跃区间 20000-40000。
"""
import json
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402

SECRET = 'c' * 64
TCFG = {'enabled': True, 'port': 44300, 'domain': 'hy2.example.com',
        'sni': 'hy2.example.com', 'secret': SECRET}
META = {'server_name': 'hy2.example.com', 'public_ip': '192.0.2.1',
        'listen_port': 443, 'auth_password': 'pw'}


def snapshot(users):
    return {'tuic_config': dict(TCFG), 'users': users}


class TuicUsersTest(unittest.TestCase):
    def test_only_allowed_users_are_listed(self):
        now = int(time.time())
        users = portal.tuic_users(snapshot({
            'ok': {'status': 'active', 'expires_at': now + 3600},
            'off': {'status': 'disabled'},
            'expired': {'status': 'active', 'expires_at': now - 1},
            'over': {'status': 'active', 'limit_bytes': 10, 'used_bytes': 10},
        }))
        self.assertEqual([u['name'] for u in users], ['ok'])

    def test_credentials_are_stable_and_secret_bound(self):
        u, pwd = portal.tuic_credentials_for_user(SECRET, 'alice')
        self.assertEqual((u, pwd), portal.tuic_credentials_for_user(SECRET, 'alice'))
        self.assertEqual(uuid.UUID(u).version, 4)
        other = portal.tuic_credentials_for_user('d' * 64, 'alice')
        self.assertNotEqual(u, other[0])
        self.assertNotEqual(pwd, other[1])
        self.assertNotEqual(u, portal.tuic_credentials_for_user(SECRET, 'bob')[0])

    def test_empty_list_gets_stable_placeholder(self):
        first = portal.tuic_users(snapshot({'off': {'status': 'disabled'}}))
        self.assertEqual([u['name'] for u in first], ['placeholder'])
        self.assertEqual(first, portal.tuic_users(snapshot({'off': {'status': 'disabled'}})))
        self.assertEqual(portal.tuic_users({'tuic_config': 5}),
                         portal.tuic_users({'tuic_config': 'x'}))


class TuicConfigTest(unittest.TestCase):
    def test_server_config(self):
        cfg = portal.build_tuic_config(TCFG, [{'name': 'u', 'uuid': 'x', 'password': 'p'}],
                                       '/c.pem', '/k.pem')
        inbound = cfg['inbounds'][0]
        self.assertEqual(inbound['type'], 'tuic')
        self.assertEqual(inbound['listen_port'], 44300)
        self.assertEqual(inbound['tls']['alpn'], ['h3'])
        self.assertEqual(inbound['tls']['key_path'], '/k.pem')
        rules = cfg['route']['rules']
        reject = [r for r in rules if r.get('action') == 'reject'][0]
        self.assertIn('169.254.0.0/16', reject['ip_cidr'])
        self.assertLess(rules.index({'action': 'resolve'}), rules.index(reject))

    def test_unit_points_at_tuic_config(self):
        self.assertIn('/etc/hysteria/tuic.json', portal.TUIC_UNIT_CONTENT)
        self.assertNotIn('anytls', portal.TUIC_UNIT_CONTENT.lower())

    def test_subscription_contains_tuic_node(self):
        _, clash, sing = portal.artifacts(META, user_id='alice', tuic=TCFG)
        clash = json.loads(clash)
        node = next(p for p in clash['proxies'] if p['type'] == 'tuic')
        u, pwd = portal.tuic_credentials_for_user(SECRET, 'alice')
        self.assertEqual((node['uuid'], node['password'], node['port']), (u, pwd, 44300))
        self.assertEqual(node['alpn'], ['h3'])
        self.assertIn(node['name'], clash['proxy-groups'][0]['proxies'])
        self.assertEqual(clash['proxy-groups'][0]['type'], 'url-test')
        sing = json.loads(sing)
        out = next(o for o in sing['outbounds'] if o['type'] == 'tuic')
        self.assertEqual(out['tls']['server_name'], 'hy2.example.com')
        urltest = next(o for o in sing['outbounds'] if o['type'] == 'urltest')
        self.assertIn(out['tag'], urltest['outbounds'])

    def test_no_node_without_user_or_valid_config(self):
        for kwargs in ({'tuic': TCFG}, {'user_id': 'alice', 'tuic': dict(TCFG, secret='')},
                       {'user_id': 'alice', 'tuic': dict(TCFG, port='abc')},
                       {'user_id': 'alice', 'tuic': dict(TCFG, secret=7)}):
            with self.subTest(kwargs=kwargs):
                _, clash, _ = portal.artifacts(META, **kwargs)
                self.assertFalse(any(p['type'] == 'tuic' for p in json.loads(clash)['proxies']))

    def test_uri(self):
        uri = portal.tuic_uri_for_user(TCFG, 'alice', label='TUIC-alice')
        u, pwd = portal.tuic_credentials_for_user(SECRET, 'alice')
        parts = urlsplit(uri)
        self.assertEqual(parts.scheme, 'tuic')
        self.assertEqual((parts.username, parts.password), (u, pwd))
        self.assertEqual((parts.hostname, parts.port), ('hy2.example.com', 44300))
        q = parse_qs(parts.query)
        self.assertEqual(q['alpn'], ['h3'])
        self.assertEqual(q['sni'], ['hy2.example.com'])
        self.assertEqual(parts.fragment, 'TUIC-alice')
        self.assertEqual(portal.tuic_uri_for_user(None, 'alice'), '')


class TuicSyncTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.applied = []

    def tearDown(self):
        self.tmp.cleanup()

    def write_config(self, users):
        cfg = portal.build_tuic_config(TCFG, portal.tuic_users(snapshot(users)), '/c', '/k')
        (self.root / portal.TUIC_CONFIG_NAME).write_text(json.dumps(cfg), encoding='utf-8')

    def sync(self, snap, active=True):
        return portal.sync_tuic_users(
            self.root, snap,
            apply=lambda cfg, path, restart: self.applied.append((cfg, restart)),
            service_active=lambda: active)

    def test_revoked_user_is_removed_and_service_restarted(self):
        self.write_config({'alice': {}, 'bob': {}})
        self.assertTrue(self.sync(snapshot({'alice': {}, 'bob': {'status': 'disabled'}})))
        cfg, restart = self.applied[-1]
        self.assertEqual([u['name'] for u in cfg['inbounds'][0]['users']], ['alice'])
        self.assertTrue(restart)

    def test_unchanged_and_stopped(self):
        self.write_config({'alice': {}, 'bob': {}})
        self.assertFalse(self.sync(snapshot({'alice': {}, 'bob': {}})))
        self.sync(snapshot({'alice': {}}), active=False)
        self.assertFalse(self.applied[-1][1], '整机停用期间收回不能把 sing-box 拉起来')

    def test_disabled_or_missing_is_ignored(self):
        self.assertFalse(self.sync(snapshot({'alice': {}}), active=False))
        self.write_config({'alice': {}, 'bob': {}})
        snap = snapshot({'alice': {}})
        snap['tuic_config']['enabled'] = False
        self.assertFalse(self.sync(snap))


    def test_corrupt_config_cannot_confirm_sync(self):
        (self.root / portal.TUIC_CONFIG_NAME).write_text('{broken', encoding='utf-8')
        with self.assertRaises(RuntimeError):
            self.sync(snapshot({'alice': {}}))

    def test_missing_config_while_active_cannot_confirm_sync(self):
        with self.assertRaisesRegex(RuntimeError, 'missing while service is active'):
            self.sync(snapshot({'alice': {}}), active=True)
        self.assertEqual(self.applied, [])

    def test_missing_config_while_stopped_needs_no_sync(self):
        self.assertFalse(self.sync(snapshot({'alice': {}}), active=False))

    def test_missing_config_uses_service_state_to_detect_live_instance(self):
        with mock.patch.object(portal, '_systemd_state', return_value='active'):
            with self.assertRaisesRegex(RuntimeError, 'missing while service is active'):
                portal.sync_tuic_users(self.root, snapshot({'alice': {}}))

    def test_missing_config_disabled_snapshot_is_ignored(self):
        self.assertFalse(self.sync({'tuic_config': {'enabled': False}, 'users': {}}, active=True))

    def test_failed_stop_result_never_confirms_shutdown(self):
        from types import SimpleNamespace
        for code, state, expected in ((1, 'inactive', False), (0, '', False),
                                      (0, 'active', False), (0, 'inactive', True),
                                      (0, 'failed', True)):
            with self.subTest(code=code, state=state):
                self.assertEqual(portal._service_stop_confirmed(
                    SimpleNamespace(returncode=code), state), expected)

    def test_enforce_node_access_reports_tuic_failure(self):
        with mock.patch.object(portal, 'sync_anytls_users'), \
                mock.patch.object(portal, 'sync_tuic_users', side_effect=ValueError('x')), \
                mock.patch.object(portal, '_enforce_node_access_xray_hy2', return_value=None) as xray:
            with self.assertRaisesRegex(RuntimeError, 'TUIC'):
                portal.enforce_node_access(self.root, {})
        xray.assert_called_once()


class TuicPortTest(unittest.TestCase):
    def test_never_in_hop_range(self):
        for preferred in (20000, 30000, 40000, 443, 80, True, 'abc', None):
            with self.subTest(preferred=preferred):
                port = portal.pick_tuic_port(preferred, set(), listening=set())
                self.assertFalse(20000 <= port <= 40000)
                lo, hi = portal.TUIC_PORT_RANGE
                self.assertTrue(lo <= port <= hi)

    def test_keeps_active_own_port_but_avoids_taken_saved_port(self):
        self.assertEqual(portal.pick_tuic_port(44300, set(), listening={44300},
                                               own_port_active=True), 44300)
        self.assertNotEqual(portal.pick_tuic_port(44300, {44300}, listening=set(),
                                                  own_port_active=True), 44300)
        with mock.patch.object(portal.random, 'shuffle', lambda values: None):
            self.assertEqual(portal.pick_tuic_port(44300, set(), listening={44300}), 41000)
        self.assertNotEqual(portal.pick_tuic_port(None, {41000}, listening=set()), 41000)
        busy = set(range(41000, 50000)) - {45555}
        self.assertEqual(portal.pick_tuic_port(None, set(), listening=busy), 45555)
        self.assertEqual(portal.pick_tuic_port(None, set(range(41000, 50000)), listening=set()), 0)

    def test_hy2_port_is_blocked(self):
        self.assertNotEqual(portal.pick_tuic_port(44300, {44300}, listening=set()), 44300)


class TuicPanelTest(unittest.TestCase):
    def test_panel_has_tuic_subtab_and_script(self):
        page = portal.page_html(dict(META, cert_type='acme', is_insecure=False, pin_sha256='',
                                     subscription_port=8443, hop_port_range='', obfs_password=''),
                                'hysteria2://x@h:1/', '#s', 'c', '{}', users={}, api_key=None,
                                token='t', session_secret='s')
        self.assertIn('data-subtab="tuic"', page)
        self.assertIn('id="btn-toggle-tuic"', page)
        import portal_assets
        src = Path(portal_assets.__file__).read_text(encoding='utf-8')
        self.assertIn("'tuic-status'", src)
        self.assertIn("'manage-tuic'", src)

    def test_suspend_and_uninstall_cover_tuic(self):
        src = Path(portal.__file__).read_text(encoding='utf-8')
        self.assertRegex(src, r"TRAFFIC_SUSPEND_UNITS = \([^)]*TUIC_SERVICE")
        sh = (Path(portal.__file__).parent / 'install.sh').read_text(encoding='utf-8')
        self.assertIn('hy2-anytls hy2-tuic', sh)


if __name__ == '__main__':
    unittest.main(verbosity=2)
