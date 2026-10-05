"""Reality 多用户 + 复合订阅的单元测试。

背景（2026-10-03）：
  旧实现的 Reality 是「整台机器一个 UUID」——
    * users/create 返回的 reality_uri 所有人都一样（rcfg['uri']）；
    * xray.json 的 clients 写死 1 个元素；
    * _generate_and_apply_reality 每次都 uuid.uuid4() 重新生成密钥与 UUID，
      刷新一次所有客户端链接全挂。
  这套用例把「一个用户一个 UUID + 链接稳定 + 销户即删」钉死。
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal

META = {
    'is_insecure': True,
    'server_name': 'node.example.com',
    'public_ip': '203.0.113.10',
    'auth_password': 'masterpw',
    'listen_port': 443,
    'obfs_password': 'obfspw',
    'hop_port_range': '20000-40000',
}
RCFG = {
    'public_key': 'PBK_TEST',
    'short_id': 'abcd1234',
    'dest_sni': 'www.apple.com',
    'port': 443,
}


class TestRealityUuidDerivation(unittest.TestCase):
    """凭据来源：**持久化随机值**，而不是从公开的 user_id 派生。

    2026-10-05 起的设计（PR #2）：
      * user_id 是公开的（订阅链接、订单号、客服记录里都有），
        由它 uuid5 派生 ⇒ 知道 user_id 就能算出别人的凭据；
      * 所以新用户发随机 uuid4 并持久化到 data['reality_users']；
      * **但老用户必须原地保留旧的派生值**，否则升级瞬间所有已发出的链接失效
        —— 这条由下面的迁移用例钉死。
    """

    @staticmethod
    def _data_with(*uids):
        return {'users': {u: {'status': 'active'} for u in uids}}

    def test_same_user_gets_same_uuid(self):
        """订阅要能反复拉 —— 同一个用户的 Reality 链接不能变。"""
        data = self._data_with('hy2_alice')
        a = portal.reality_uuid_for_user('hy2_alice', data)
        b = portal.reality_uuid_for_user('hy2_alice', data)
        self.assertEqual(a, b, '同一 user_id 必须始终取到同一个 UUID，否则客户端会被当成新节点')

    def test_different_users_get_different_uuids(self):
        data = self._data_with('hy2_alice', 'hy2_bob')
        a = portal.reality_uuid_for_user('hy2_alice', data)
        b = portal.reality_uuid_for_user('hy2_bob', data)
        self.assertNotEqual(a, b, '多用户共用一个 UUID 意味着任何一个人销户会连累所有人')

    def test_uuid_is_valid_form(self):
        import uuid as _uuid
        data = self._data_with('hy2_alice')
        got = portal.reality_uuid_for_user('hy2_alice', data)
        # 能被 uuid 解析 ⇒ 格式合法（xray 会校验）
        self.assertEqual(str(_uuid.UUID(got)), got)

    def test_new_user_uuid_is_random_v4_not_derived(self):
        """新增用户必须是随机 UUIDv4 —— 不能是 uuid5(user_id)。

        这是本次改动的**核心安全目标**：user_id 公开，派生等于凭据公开。
        """
        import uuid as _uuid
        data = {'users': {'alice': {'status': 'active'}},
                'reality_uuid_version': portal.REALITY_UUID_VERSION}
        got = portal.reality_uuid_for_user('alice', data)
        self.assertEqual(_uuid.UUID(got).version, 4,
                         '新用户凭据必须是随机 v4，不能退回派生')
        self.assertNotEqual(
            got, str(_uuid.uuid5(_uuid.NAMESPACE_URL, 'hy2-portal-reality:alice')),
            '凭据不能等于 uuid5(user_id) 派生值 —— 那样任何人都能算出别人的凭据')

    def test_legacy_namespace_is_preserved_for_migration(self):
        """老库升级必须还原成**升级前那个**派生值，否则存量链接全部失效。

        命名空间与算法写死在 _legacy_reality_uuid 里，改它 =
        所有已发出去的 Reality 链接失效。这条用例就是守它的。
        """
        import uuid as _uuid
        data = {'users': {'alice': {'status': 'active'}}}   # 无 version ⇒ 老库
        got = portal.reality_uuid_for_user('alice', data)
        self.assertEqual(
            got, str(_uuid.uuid5(_uuid.NAMESPACE_URL, 'hy2-portal-reality:alice')),
            '老用户升级后必须拿回原来的派生 UUID')

    def test_migration_happens_only_once(self):
        """迁移只跑一次：升级后新建的用户必须是随机值，不能再走派生。"""
        import uuid as _uuid
        data = {'users': {'old': {}}}                       # 老库
        portal.reality_registry(data)
        self.assertEqual(data.get('reality_uuid_version'),
                         portal.REALITY_UUID_VERSION)
        data['users']['new'] = {}
        portal.reality_registry(data)
        self.assertNotEqual(
            data['reality_users']['new'],
            str(_uuid.uuid5(_uuid.NAMESPACE_URL, 'hy2-portal-reality:new')),
            '版本号升到 2 之后新增的用户必须是随机 UUID，不能继续派生')


class TestRealityRegistry(unittest.TestCase):
    def test_backfills_existing_users(self):
        """升级后老用户也该有 UUID，不需要重新开户。"""
        data = {'users': {'alice': {}, 'bob': {}}}
        reg = portal.reality_registry(data)
        self.assertEqual(len(reg), 2)
        self.assertIn('alice', reg)
        self.assertIn('bob', reg)

    def test_retires_deleted_users_but_keeps_credential(self):
        """销户后凭据**保留**（重开户要拿回同一个 UUID），
        但**不得**再出现在 xray clients 里 —— 保留的是凭据，不是访问权。"""
        data = {'users': {'alice': {}, 'bob': {}}}
        portal.reality_registry(data)
        del data['users']['bob']
        reg = portal.reality_registry(data)
        self.assertIn('bob', reg, '保留窗口内凭据要留着，否则重开户 UUID 会变')
        self.assertNotIn('bob', [c.get('email') for c in portal.reality_clients(data)],
                         '已注销用户绝不能再出现在 xray clients 里')

    def test_deleted_credential_is_reclaimed_after_ttl(self):
        """超过保留窗口才真正回收，避免注册表无限增长。"""
        data = {'users': {'bob': {}}}
        portal.reality_registry(data)
        del data['users']['bob']
        portal.reality_registry(data)
        # 把注销时间往前拨到窗口之外
        data['reality_retired_users']['bob'] = 0
        reg = portal.reality_registry(data)
        self.assertNotIn('bob', reg, '超期必须回收，否则注册表只增不减')

    def test_recreate_gets_same_uuid(self):
        """销户 → 同 user_id 重开户必须拿回同一个 UUID（幂等）。

        旧实现靠 uuid5 天然幂等；改成随机 UUID 后必须靠保留窗口等价，
        否则客户端手里的旧配置在重开户后失效。
        """
        data = {'users': {'bob': {'status': 'active'}},
                'reality_uuid_version': portal.REALITY_UUID_VERSION}
        first = portal.reality_uuid_for_user('bob', data)
        del data['users']['bob']
        portal.reality_registry(data)
        data['users']['bob'] = {'status': 'active'}
        self.assertEqual(portal.reality_uuid_for_user('bob', data), first,
                         '同 user_id 重新开户必须拿回同一 UUID')

    def test_registry_persists_into_data(self):
        data = {'users': {'alice': {}}}
        portal.reality_registry(data)
        self.assertIn('reality_users', data, '注册表要写回 data，否则重启后丢失')


class TestRealityClientsNeverEmpty(unittest.TestCase):
    def test_empty_user_table_still_yields_placeholder(self):
        """clients 为空时 xray 拒绝所有连接，但 systemctl 仍显示 active ——
        极难排查。宁可给一个占位 client。"""
        clients = portal.reality_clients({'users': {}})
        self.assertGreaterEqual(len(clients), 1)
        self.assertIn('id', clients[0])
        self.assertIn('flow', clients[0])

    def test_one_client_per_user(self):
        data = {'users': {'a': {}, 'b': {}, 'c': {}}}
        clients = portal.reality_clients(data)
        self.assertEqual(len(clients), 3)
        emails = sorted(c.get('email', '') for c in clients)
        self.assertEqual(emails, ['a', 'b', 'c'], '每个 user_id 一个 client，且 email 便于排查')

    def test_disabled_user_is_excluded(self):
        """停用的用户不能留在 xray clients 里 ——
        否则「已停用」的买家照旧能用 Reality 连上（Hy2 侧已被拒，
        于是表现为「UDP 断、TCP 通」，最难排查）。"""
        data = {'users': {'a': {'status': 'active'}, 'b': {'status': 'disabled'}}}
        emails = [c.get('email') for c in portal.reality_clients(data)]
        self.assertIn('a', emails)
        self.assertNotIn('b', emails, '停用用户的 Reality 身份必须被摘掉')


class TestRealityUri(unittest.TestCase):
    @staticmethod
    def _data():
        return {'users': {'alice': {'status': 'active'},
                          'bob': {'status': 'active'}},
                'reality_uuid_version': portal.REALITY_UUID_VERSION}

    def test_each_user_gets_own_link(self):
        data = self._data()
        a = portal.reality_uri_for_user(RCFG, 'alice', '203.0.113.10', 'A', data=data)
        b = portal.reality_uri_for_user(RCFG, 'bob', '203.0.113.10', 'B', data=data)
        self.assertNotEqual(a, b)
        self.assertIn(portal.reality_uuid_for_user('alice', data), a)
        self.assertIn(portal.reality_uuid_for_user('bob', data), b)

    def test_link_contains_required_params(self):
        u = portal.reality_uri_for_user(RCFG, 'alice', '203.0.113.10', 'A',
                                        data=self._data())
        for need in ('security=reality', 'pbk=PBK_TEST', 'sid=abcd1234',
                     'sni=www.apple.com', 'flow=xtls-rprx-vision', 'type=tcp'):
            self.assertIn(need, u, f'Reality 链接缺 {need}')

    def test_incomplete_config_returns_empty(self):
        """配置不全时返回空串而不是半截链接 —— 半截链接会让客户端导入失败。"""
        self.assertEqual(portal.reality_uri_for_user({}, 'a', '1.2.3.4'), '')
        self.assertEqual(portal.reality_uri_for_user({'public_key': 'X'}, 'a', '1.2.3.4'), '')


class TestCompositeSubscription(unittest.TestCase):
    @staticmethod
    def _data():
        """带凭据注册表的 data —— Reality 复合订阅现在必须显式带它。"""
        d = {'users': {'alice': {'status': 'active'}},
             'reality_uuid_version': portal.REALITY_UUID_VERSION}
        portal.reality_registry(d)
        return d

    def test_clash_has_both_protocols_and_url_test(self):
        _, clash_s, sing_s = portal.artifacts(
            META, auth_override='pw', name_override='Teyir-Hy2-alice',
            reality=RCFG, user_id='alice', data=self._data())
        clash = json.loads(clash_s)
        types = sorted(p['type'] for p in clash['proxies'])
        self.assertEqual(types, ['hysteria2', 'vless'],
                         '一条订阅里应当同时有 Hy2 与 Reality')
        grp = clash['proxy-groups'][0]
        self.assertEqual(grp['type'], 'url-test',
                         '双通道时策略组必须是 url-test（自动择优），否则用户要手动切')
        self.assertEqual(len(grp['proxies']), 2)

    def test_singbox_has_urltest_outbound(self):
        _, _, sing_s = portal.artifacts(
            META, auth_override='pw', name_override='X',
            reality=RCFG, user_id='alice', data=self._data())
        sing = json.loads(sing_s)
        kinds = [o.get('type') for o in sing['outbounds']]
        self.assertIn('urltest', kinds, 'sing-box 侧也要有 urltest outbound')
        self.assertEqual(sing.get('route', {}).get('final'), 'PROXY',
                         'sing-box 要把 final 指向 urltest 组')

    def test_without_reality_keeps_legacy_shape(self):
        """未启用 Reality 的节点必须保持旧行为 —— 不能被顺手改坏。"""
        _, clash_s, sing_s = portal.artifacts(
            META, auth_override='pw', name_override='X')
        clash = json.loads(clash_s)
        self.assertEqual(len(clash['proxies']), 1)
        self.assertEqual(clash['proxy-groups'][0]['type'], 'select')
        sing = json.loads(sing_s)
        self.assertNotIn('route', sing)

    def test_user_id_none_does_not_add_reality(self):
        """单机管理员视角（不给 user_id）不该凭空多出一个用不上的节点。"""
        _, clash_s, _ = portal.artifacts(
            META, auth_override='pw', name_override='X', reality=RCFG, user_id=None)
        self.assertEqual(len(json.loads(clash_s)['proxies']), 1)

    def test_incomplete_reality_degrades_safely(self):
        """Reality 配置不全时安全降级成单节点，而不是抛异常/半截配置。"""
        _, clash_s, _ = portal.artifacts(
            META, auth_override='pw', name_override='X',
            reality={'port': 443}, user_id='alice', data=self._data())
        self.assertEqual(len(json.loads(clash_s)['proxies']), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
