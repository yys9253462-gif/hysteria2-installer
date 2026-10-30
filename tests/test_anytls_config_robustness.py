"""AnyTLS 配置损坏时，用户表同步与订阅生成都不能失败。

`anytls_config` 存在 portal.json 里（旧版本可直接编辑）。被改成数字/字符串时：
  * anytls_users 的 `.get('secret')` 抛 AttributeError → sing-box 用户表同步
    整轮失败，界面只显示「启用失败」
  * anytls_uri_for_user 的 int(port) 对 "abc" 抛 ValueError → 该用户整份订阅
    生成失败（连 Hy2 节点也拿不到）
"""
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

GOOD = {'secret': 'test-secret', 'domain': 'a.example.com', 'port': 8443}


class AnytlsConfigRobustnessTests(unittest.TestCase):
    def test_users_sync_survives_corrupt_config(self):
        for bad in (None, 7, 'x', ['a'], {'secret': 123}, {'secret': ['s']}):
            with self.subTest(bad=bad):
                users = portal.anytls_users({'users': {}, 'anytls_config': bad})
                self.assertEqual([u['name'] for u in users], ['placeholder'])

    def test_uri_skips_corrupt_config_or_port(self):
        for bad in (None, 7, 'x', {'secret': 123},
                    dict(GOOD, port='abc'), dict(GOOD, port=True),
                    dict(GOOD, port=70000), dict(GOOD, port=None)):
            with self.subTest(bad=bad):
                self.assertEqual(portal.anytls_uri_for_user(bad, 'u1'), '')

    def test_uri_still_built_for_healthy_config(self):
        uri = portal.anytls_uri_for_user(GOOD, 'u1')
        self.assertTrue(uri.startswith('anytls://'))
        self.assertIn(':8443/', uri)
        self.assertIn('a.example.com', uri)

    def test_config_helper_returns_empty_for_corrupt_values(self):
        for bad in (None, 7, 'x', ['a']):
            with self.subTest(bad=bad):
                self.assertEqual(portal.anytls_config({'anytls_config': bad}), {})
        self.assertEqual(portal.anytls_config(None), {})
        self.assertIs(portal.anytls_config({'anytls_config': GOOD}), GOOD)


class AnytlsSyncRobustnessTests(unittest.TestCase):
    """sync_anytls_users 在 enforce_node_access 顶部调用。

    anytls.json 或快照被改坏时抛异常，会让开户/续费/停用/删除全部 503，
    而且报错写成「Reality sync failed」，完全指不到真正的文件。
    """

    def setUp(self):
        import tempfile
        self.root = Path(tempfile.mkdtemp())

    def sync(self, content, snapshot):
        (self.root / 'anytls.json').write_text(content)
        return portal.sync_anytls_users(self.root, snapshot,
                                        apply=lambda *a, **k: None,
                                        service_active=lambda: False)

    def test_corrupt_config_returns_false(self):
        for content in ('[]', '7', '"x"', '{"inbounds": 7}', '{"inbounds": ["x"]}', 'not json'):
            with self.subTest(content=content):
                self.assertFalse(self.sync(content, {'anytls_config': {'enabled': True}}))

    def test_corrupt_snapshot_returns_false(self):
        for snap in (None, 7, 'x', ['a'], {'anytls_config': 'x'}):
            with self.subTest(snap=snap):
                self.assertFalse(self.sync('{"inbounds": []}', snap))

    def test_healthy_sync_rewrites_users(self):
        content = ('{"inbounds": [{"tag": "%s", "users": []}]}'
                   % portal.ANYTLS_INBOUND_TAG)
        self.assertTrue(self.sync(content, {'users': {}, 'anytls_config': {'enabled': True}}))


if __name__ == '__main__':
    unittest.main()
