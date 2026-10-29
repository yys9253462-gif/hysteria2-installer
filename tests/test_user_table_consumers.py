"""损坏的 users 容器不能让协议同步、准入判定与分享渲染抛异常。

真实后果：users 被手工改成 null 后，reality_clients / vmess_clients /
vlessenc_clients 在同步 Xray 入站的锁内抛 AttributeError，停用/到期撤销
半途中断 —— 该被踢下线的用户仍在所有协议上可用，而服务状态全是 active。
"""
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

BAD_TABLES = (None, ['broken'], 'oops', 7, True)


class UserTableConsumersTests(unittest.TestCase):
    def test_protocol_clients_survive_corrupt_table(self):
        for builder in (portal.reality_clients, portal.vmess_clients, portal.vlessenc_clients):
            for bad in BAD_TABLES:
                with self.subTest(builder=builder.__name__, bad=bad):
                    clients = builder({'users': bad})
                    # 空表也必须给占位 client，否则 Xray 起得来但没人能连。
                    self.assertEqual([c['email'] for c in clients], ['placeholder'])

    def test_reality_registry_survives_corrupt_table(self):
        for bad in BAD_TABLES:
            with self.subTest(bad=bad):
                self.assertEqual(portal.reality_registry({'users': bad}), {})

    def test_active_users_skip_corrupt_records(self):
        users = {'good': {'status': 'active'}, 'bad': 'oops', 'disabled': {'status': 'disabled'}}
        self.assertEqual(portal.reality_clients({'users': users})[0]['email'], 'good')
        self.assertEqual(portal.vmess_clients({'users': users})[0]['email'], 'good')
        self.assertEqual(portal.vlessenc_clients({'users': users})[0]['email'], 'good')


if __name__ == '__main__':
    unittest.main()
