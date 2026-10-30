"""AnyTLS 通道（sing-box 承载，2026-10-28）的回归测试。

锁住的行为：
  * 用户名单与准入判据 user_access_allowed 同源，停用/到期/超额的用户不在名单里；
  * 密码由节点 secret 派生：稳定、不可由 user_id 猜出；
  * 空名单给占位用户，且占位密码稳定（否则每轮收回都会无谓重启）；
  * 服务端配置拒绝访问内网 / 云元数据；
  * 订阅里的 Clash / sing-box 节点字段正确，并进入 url-test 组；
  * 收回同步：名单变了才重写并重启，停用状态下不动；
  * 端口避让：已启用的 AnyTLS 端口会被其它协议避开，停用后释放。
"""
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402

SECRET = 'a' * 64
ACFG = {'enabled': True, 'port': 2096, 'domain': 'hy2.example.com',
        'sni': 'hy2.example.com', 'secret': SECRET}
META = {'server_name': 'hy2.example.com', 'public_ip': '192.0.2.1',
        'listen_port': 443, 'auth_password': 'pw'}


def snapshot(users):
    return {'anytls_config': dict(ACFG), 'users': users}


class AnytlsUsersTest(unittest.TestCase):
    def test_only_allowed_users_are_listed(self):
        now = int(time.time())
        users = portal.anytls_users(snapshot({
            'ok': {'status': 'active', 'expires_at': now + 3600},
            'legacy': {},  # 缺 status / expires_at 视为正常
            'off': {'status': 'disabled'},
            'expired': {'status': 'active', 'expires_at': now - 1},
            'over': {'status': 'active', 'limit_bytes': 10, 'used_bytes': 10},
        }))
        self.assertEqual([u['name'] for u in users], ['legacy', 'ok'])

    def test_password_is_stable_and_secret_bound(self):
        a = portal.anytls_password_for_user(SECRET, 'alice')
        self.assertEqual(a, portal.anytls_password_for_user(SECRET, 'alice'))
        self.assertNotEqual(a, portal.anytls_password_for_user('b' * 64, 'alice'),
                            '换了 secret 密码却没变：说明密码只由 user_id 决定，可被猜出')
        self.assertNotEqual(a, portal.anytls_password_for_user(SECRET, 'bob'))

    def test_empty_list_gets_stable_placeholder(self):
        first = portal.anytls_users(snapshot({'off': {'status': 'disabled'}}))
        second = portal.anytls_users(snapshot({'off': {'status': 'disabled'}}))
        self.assertEqual([u['name'] for u in first], ['placeholder'])
        self.assertEqual(first, second, '占位密码每次不同会让每轮收回都重启 sing-box')


class AnytlsConfigTest(unittest.TestCase):
    def test_server_config_rejects_private_networks(self):
        cfg = portal.build_anytls_config(ACFG, [{'name': 'u', 'password': 'p'}],
                                         '/c.pem', '/k.pem')
        inbound = cfg['inbounds'][0]
        self.assertEqual(inbound['type'], 'anytls')
        self.assertEqual(inbound['listen_port'], 2096)
        self.assertTrue(inbound['tls']['enabled'])
        self.assertEqual(inbound['tls']['certificate_path'], '/c.pem')
        rules = cfg['route']['rules']
        reject = [r for r in rules if r.get('action') == 'reject']
        self.assertEqual(len(reject), 1)
        for cidr in ('127.0.0.0/8', '169.254.0.0/16', '10.0.0.0/8', 'fc00::/7'):
            self.assertIn(cidr, reject[0]['ip_cidr'])
        # 先解析域名再按 IP 拒：否则用域名访问内网地址可以绕过。
        self.assertLess(rules.index({'action': 'resolve'}), rules.index(reject[0]))

    def test_subscription_contains_anytls_node(self):
        _, clash, sing = portal.artifacts(META, user_id='alice', anytls=ACFG)
        clash = json.loads(clash)
        node = next(p for p in clash['proxies'] if p['type'] == 'anytls')
        self.assertEqual(node['server'], 'hy2.example.com')
        self.assertEqual(node['port'], 2096)
        self.assertEqual(node['password'], portal.anytls_password_for_user(SECRET, 'alice'))
        self.assertEqual(node['client-fingerprint'], 'chrome')
        self.assertIn(node['name'], clash['proxy-groups'][0]['proxies'])
        sing = json.loads(sing)
        out = next(o for o in sing['outbounds'] if o['type'] == 'anytls')
        self.assertEqual(out['server_port'], 2096)
        self.assertTrue(out['tls']['enabled'])
        urltest = next(o for o in sing['outbounds'] if o['type'] == 'urltest')
        self.assertIn(out['tag'], urltest['outbounds'])

    def test_no_node_without_user_or_secret(self):
        _, clash, _ = portal.artifacts(META, anytls=ACFG)
        self.assertFalse(any(p['type'] == 'anytls' for p in json.loads(clash)['proxies']))
        _, clash, _ = portal.artifacts(META, user_id='alice', anytls=dict(ACFG, secret=''))
        self.assertFalse(any(p['type'] == 'anytls' for p in json.loads(clash)['proxies']))

    def test_uri(self):
        uri = portal.anytls_uri_for_user(ACFG, 'alice', label='AnyTLS-alice')
        pwd = portal.anytls_password_for_user(SECRET, 'alice')
        self.assertEqual(uri, f'anytls://{pwd}@hy2.example.com:2096/?sni=hy2.example.com#AnyTLS-alice')


class AnytlsSyncTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.applied = []

    def tearDown(self):
        self.tmp.cleanup()

    def write_config(self, users):
        cfg = portal.build_anytls_config(ACFG, portal.anytls_users(snapshot(users)), '/c', '/k')
        (self.root / portal.ANYTLS_CONFIG_NAME).write_text(json.dumps(cfg), encoding='utf-8')

    def sync(self, snap, active=True):
        return portal.sync_anytls_users(
            self.root, snap,
            apply=lambda cfg, path, restart: self.applied.append((cfg, restart)),
            service_active=lambda: active)

    def test_revoked_user_is_removed_and_service_restarted(self):
        self.write_config({'alice': {}, 'bob': {}})
        changed = self.sync(snapshot({'alice': {}, 'bob': {'status': 'disabled'}}))
        self.assertTrue(changed)
        cfg, restart = self.applied[-1]
        self.assertEqual([u['name'] for u in cfg['inbounds'][0]['users']], ['alice'])
        self.assertTrue(restart, '不重启的话被收回用户已建立的连接不会断开')

    def test_unchanged_list_is_noop(self):
        self.write_config({'alice': {}})
        self.assertFalse(self.sync(snapshot({'alice': {}})))
        self.assertEqual(self.applied, [])

    def test_stopped_service_is_not_started(self):
        self.write_config({'alice': {}, 'bob': {}})
        self.sync(snapshot({'alice': {}}), active=False)
        self.assertFalse(self.applied[-1][1], '整机停用期间收回不能把 sing-box 拉起来')

    def test_disabled_channel_is_ignored(self):
        self.write_config({'alice': {}, 'bob': {}})
        snap = snapshot({'alice': {}})
        snap['anytls_config']['enabled'] = False
        self.assertFalse(self.sync(snap))

    def test_missing_config_is_ignored(self):
        self.assertFalse(self.sync(snapshot({'alice': {}})))


class AnytlsPortTest(unittest.TestCase):
    def test_enabled_port_is_reserved_and_disabled_released(self):
        data = {'anytls_config': dict(ACFG)}
        self.assertIn(2096, portal.managed_reserved_ports(META, data))
        self.assertNotIn(2096, portal.managed_reserved_ports(META, data, exclude_key='anytls_config'))
        data['anytls_config']['enabled'] = False
        self.assertNotIn(2096, portal.managed_reserved_ports(META, data))


class SingboxInstallTest(unittest.TestCase):
    def test_refuses_without_official_digest(self):
        """官方 API 不给 sha256 就不装：镜像下载的内容没有可信基准可比。"""
        release = {'tag_name': 'v1.14.4', 'assets': [
            {'name': 'sing-box-1.14.4-linux-amd64.tar.gz', 'browser_download_url': 'x'}]}

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return json.dumps(release).encode()

        with mock.patch.object(portal, '_singbox_version', return_value=None), \
                mock.patch.object(portal.platform, 'machine', return_value='x86_64'), \
                mock.patch.object(portal.urllib.request, 'urlopen', return_value=Resp()) as urlopen:
            ok, msg = portal.install_singbox()
        self.assertFalse(ok)
        self.assertIn('SHA256', msg)
        self.assertEqual(urlopen.call_count, 1, '没有摘要时不应继续下载安装包')

    def test_existing_new_enough_binary_is_reused(self):
        with mock.patch.object(portal, '_singbox_version', return_value=(1, 14, 4)), \
                mock.patch.object(portal.urllib.request, 'urlopen') as urlopen:
            ok, _ = portal.install_singbox()
        self.assertTrue(ok)
        urlopen.assert_not_called()


class AnytlsPanelTest(unittest.TestCase):
    def test_panel_has_anytls_subtab(self):
        page = portal.page_html(dict(META, cert_type='acme', is_insecure=False, pin_sha256='',
                                     subscription_port=8443, hop_port_range='', obfs_password=''),
                                'hysteria2://x@h:1/', '#s', 'c', '{}', users={}, api_key=None,
                                token='t', session_secret='s')
        self.assertIn('data-subtab="anytls"', page)
        self.assertIn('id="btn-toggle-anytls"', page)


class AnytlsRobustnessTests(unittest.TestCase):
    """2026-10-29 修复的健壮性缺口。"""

    def test_corrupt_config_does_not_raise(self):
        """anytls.json 损坏时只跳过同步，不能让开户/删除全部 503。"""
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'anytls.json').write_text('{"inbounds": [', encoding='utf-8')
            self.assertFalse(portal.sync_anytls_users(root, snapshot([('u1', True)])))

    def test_placeholder_password_is_stable_without_secret(self):
        """secret 缺失时占位密码也必须稳定，否则每轮同步都重启 sing-box。"""
        data = {'anytls_config': {}, 'users': {'u1': {'status': 'active',
                                                       'expires_at': 2085974400}}}
        self.assertEqual(portal.anytls_users(data), portal.anytls_users(data))

    def test_subscription_survives_corrupt_port(self):
        """端口被改坏时跳过该节点，而不是让整页/整份订阅抛异常。"""
        for key, cfg in (('vmess', {'port': 'x', 'domain': 'd', 'ws_path': '/p'}),
                         ('vlessenc', {'port': 'x', 'domain': 'd', 'encryption': 'e'}),
                         ('anytls', {'port': 'x', 'domain': 'd', 'secret': SECRET})):
            with self.subTest(key=key):
                _, clash, _ = portal.artifacts(META, user_id='u1', **{key: cfg})
                types = [p['type'] for p in json.loads(clash)['proxies']]
                self.assertNotIn(key, types)

    def test_clash_fingerprint_key_matches_mihomo(self):
        """mihomo 的字段名是 client-fingerprint（连字符），不是下划线。"""
        _, clash, _ = portal.artifacts(
            META, user_id='u1',
            reality={'port': 2053, 'dest_sni': 'a', 'public_key': 'k', 'short_id': 's'},
            vmess={'port': 2087, 'domain': 'd', 'ws_path': '/p'},
            vlessenc={'port': 2088, 'domain': 'd', 'encryption': 'e'},
            anytls=dict(ACFG))
        for node in json.loads(clash)['proxies']:
            if node['type'] == 'hysteria2':
                continue
            self.assertIn('client-fingerprint', node, node['type'])
            self.assertNotIn('client_fingerprint', node, node['type'])

    def test_valid_port_helper(self):
        self.assertEqual(portal._valid_port('2087'), 2087)
        for bad in ('x', None, True, 0, 70000, 2087.5, ''):
            with self.subTest(bad=bad):
                self.assertEqual(portal._valid_port(bad), 0)


class XrayPinnedVersionTests(unittest.TestCase):
    def test_version_tuple_ordering(self):
        self.assertGreater(portal._version_tuple('26.10.1'),
                           portal._version_tuple(portal.XRAY_PINNED_VERSION))
        self.assertEqual(portal._version_tuple('v26.3.27'), (26, 3, 27))

    def test_short_and_full_spellings_compare_equal(self):
        # Python 元组比较是前缀式：不加长度归一化时 (1, 2, 0) > (1, 2) 为真，
        # 同一个版本写全/写短就会被判成「当前版本更高」，重装被静默拒绝。
        for short, full in (('1.2', '1.2.0'), ('25.9', '25.9.0'), ('1', '1.0.0')):
            with self.subTest(short=short, full=full):
                self.assertEqual(portal._version_tuple(short), portal._version_tuple(full))
                self.assertFalse(portal._version_tuple(full) > portal._version_tuple(short))

    def test_unparseable_version_stays_empty(self):
        for bad in (None, '', 'abc', []):
            with self.subTest(bad=bad):
                self.assertEqual(portal._version_tuple(bad), ())


if __name__ == '__main__':
    unittest.main(verbosity=2)
