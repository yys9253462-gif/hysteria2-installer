"""Reality 凭据安全回归：凭据不得由公开的 user_id 派生。

背景（2026-10-05）：
  旧实现 `uuid5(NAMESPACE_URL, 'hy2-portal-reality:' + user_id)` 把凭据
  **完全由 user_id 决定**。而 user_id 是公开的 —— 它出现在订阅链接、
  订单号、客服记录里。于是「知道 user_id」就等于「知道别人的凭据」，
  这是认证边界的实质失效。

  新实现：新用户发随机 uuid4 并持久化；老用户在升级时**原地保留**
  原有的派生值（否则已在客户端里的链接会全部失效）。

这里刻意**走真实的模块导入**，而不是用 ast 抠出几个函数 exec 到裸命名空间 ——
那样做会绕过模块级初始化，恰恰测不出本次修掉的
「读凭据前必须先初始化某个全局」这类耦合。
"""
import copy
import json
import sys
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal

LEGACY_NS = 'hy2-portal-reality:'


def legacy_uuid(uid):
    """升级前的老算法（仅测试用来对照，生产侧见 portal._legacy_reality_uuid）。"""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, LEGACY_NS + str(uid)))


class TestCredentialNotDerivable(unittest.TestCase):
    def test_new_user_credential_is_random(self):
        """新用户凭据必须是随机 v4，且**不等于**由 user_id 派生出来的值。"""
        data = {'users': {'new': {'status': 'active'}},
                'reality_uuid_version': portal.REALITY_UUID_VERSION}
        got = portal.reality_uuid_for_user('new', data)
        self.assertEqual(uuid.UUID(got).version, 4)
        self.assertNotEqual(got, legacy_uuid('new'),
                            '知道 user_id 就能算出凭据 = 认证边界失效')

    def test_two_registries_give_different_credentials(self):
        """同样的 user_id 在两个独立实例上必须得到不同凭据 ——
        派生实现会让它们相同，随机实现不会。"""
        a, b = {}, {}
        for d in (a, b):
            d.update({'users': {'alice': {'status': 'active'}},
                      'reality_uuid_version': portal.REALITY_UUID_VERSION})
        self.assertNotEqual(portal.reality_uuid_for_user('alice', a),
                            portal.reality_uuid_for_user('alice', b))


class TestLegacyMigration(unittest.TestCase):
    def test_existing_user_keeps_derived_uuid(self):
        """老库升级必须还原原派生值 —— 存量链接不能因升级而失效。"""
        data = {'users': {'old': {'status': 'active'}}}     # 无 version ⇒ 老库
        reg = portal.reality_registry(data)
        self.assertEqual(reg['old'], legacy_uuid('old'))

    def test_migration_marks_version(self):
        data = {'users': {'old': {}}}
        portal.reality_registry(data)
        self.assertEqual(data.get('reality_uuid_version'),
                         portal.REALITY_UUID_VERSION)

    def test_user_added_after_migration_is_random(self):
        """迁移只应影响存量用户；迁移之后新增的用户必须走随机分支。"""
        data = {'users': {'old': {}}}
        portal.reality_registry(data)                       # 触发迁移
        data['users']['new'] = {}
        portal.reality_registry(data)
        self.assertNotEqual(data['reality_users']['new'], legacy_uuid('new'))


class TestDisabledAndRetired(unittest.TestCase):
    def test_disabled_user_excluded_from_clients(self):
        data = {'users': {'old': {}, 'disabled': {'status': 'disabled'}}}
        portal.reality_registry(data)
        emails = [c['email'] for c in portal.reality_clients(data)]
        self.assertNotIn('disabled', emails)

    def test_retired_user_excluded_from_clients(self):
        """销户后凭据保留（供重开户复用），但不能再出现在 clients 里。"""
        data = {'users': {'gone': {'status': 'active'}},
                'reality_uuid_version': portal.REALITY_UUID_VERSION}
        portal.reality_registry(data)
        del data['users']['gone']
        portal.reality_registry(data)
        emails = [c['email'] for c in portal.reality_clients(data)]
        self.assertNotIn('gone', emails,
                         '凭据保留 ≠ 访问权保留；销户后必须从 xray 摘掉')
        self.assertTrue(emails, 'clients 不能为空，否则 xray 拒绝所有连接')

    def test_recreate_is_idempotent(self):
        data = {'users': {'bob': {'status': 'active'}},
                'reality_uuid_version': portal.REALITY_UUID_VERSION}
        first = portal.reality_uuid_for_user('bob', data)
        del data['users']['bob']
        portal.reality_registry(data)
        data['users']['bob'] = {'status': 'active'}
        self.assertEqual(portal.reality_uuid_for_user('bob', data), first,
                         '销户重开户必须拿回同一凭据，否则老配置失效')


class TestPersistence(unittest.TestCase):
    def test_survives_json_roundtrip(self):
        """凭据必须真的落在 data 里并能经受 JSON 序列化（重启后仍在）。"""
        data = {'users': {'new': {'status': 'active'}},
                'reality_uuid_version': portal.REALITY_UUID_VERSION}
        new = portal.reality_uuid_for_user('new', data)
        revived = json.loads(json.dumps(data))
        self.assertEqual(portal.reality_uuid_for_user('new', revived), new)

    def test_registry_is_deep_copied_safely(self):
        """深拷贝一份独立实例后，凭据仍一致（结构里没有不可序列化的东西）。"""
        data = {'users': {'new': {'status': 'active'}},
                'reality_uuid_version': portal.REALITY_UUID_VERSION}
        new = portal.reality_uuid_for_user('new', data)
        clone = copy.deepcopy(data)
        self.assertEqual(portal.reality_uuid_for_user('new', clone), new)


class TestCallersPersistCredentials(unittest.TestCase):
    """调用点必须落盘 —— 随机凭据不写盘就只活在内存里。

    save_data() 是 serve() 内的闭包，模块级函数够不到它，
    所以「谁改了注册表谁负责保存」是必须靠调用点守住的约定。
    漏掉的后果很隐蔽：面板重启后同一个 user_id 会**再生成一个不同的 UUID**，
    客户端手里的 Reality 链接失效，而 Hy2 通道完全正常 —— 表现为
    「一个节点好好的、另一个就连不上」，极难定位。
    """

    SRC = (Path(__file__).resolve().parents[1] / 'portal.py').read_text(encoding='utf-8')

    def _branch(self, start, end):
        s = self.SRC
        assert start in s and end in s, '源码结构变了，请更新本用例的分支边界'
        return s[s.index(start):s.index(end, s.index(start))]

    def test_users_create_saves(self):
        seg = self._branch("if sub == 'users/create':", "elif sub == 'users/renew':")
        self.assertIn('reality_registry(', seg, '开户要建凭据')
        self.assertIn('save_data()', seg,
                      '开户新建的随机 UUID 必须当场落盘，否则重启后客户链接失效')

    def test_users_delete_saves(self):
        seg = self._branch("if sub == 'users/delete':", "elif sub == 'users/set_status':")
        self.assertIn('save_data()', seg,
                      '销户会改动 retired 表，必须落盘（否则重开户 UUID 会变）')

    def test_users_set_status_saves(self):
        seg = self._branch("elif sub == 'users/set_status':", "elif sub == 'users/list':")
        self.assertIn('save_data()', seg,
                      '停用/启用要落盘，否则重启后停用被忘掉')
        self.assertIn('_sync_reality_clients()', seg,
                      '停用必须同步 xray，否则买家在 Reality 通道上照旧能连')

    def test_serve_saves_migrated_registry(self):
        seg = self.SRC[self.SRC.index('def serve(path):'):]
        self.assertIn('reality_registry(data)', seg)
        self.assertIn('save_data()', seg, '启动迁移的结果要落盘')


if __name__ == '__main__':
    unittest.main(verbosity=2)
