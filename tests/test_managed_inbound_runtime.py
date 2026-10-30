import ast
import json
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock

TREE = ast.parse((Path(__file__).resolve().parents[1] / 'portal.py').read_text(encoding='utf-8'))
TAGS = ('vless-reality-in', 'vmess-ws-in', 'vless-enc-in')
NAMES = {'managed_inbound_index', 'has_managed_inbound', 'managed_inbound_active',
         'upsert_managed_inbound', 'remove_managed_inbound',
         '_active_reality_config', '_active_vmess_config', '_active_vlessenc_config'}


def load_functions(installed=True, state='active', ports=(8443,)):
    config = {'inbounds': [{'tag': tag, 'port': 8443, 'protocol': 'vless'} for tag in TAGS]}
    fake_path = Mock()
    fake_path.return_value.is_file.return_value = installed
    fake_path.return_value.exists.return_value = installed
    fake_path.return_value.read_text.return_value = json.dumps(config)
    import copy as _copy
    env = {'Path': fake_path, 'json': json, 'data_lock': threading.RLock(), 'copy': _copy,
           'data': {'reality_config': {'port': 8443}, 'vmess_config': {'port': 8443},
                    'vlessenc_config': {'port': 8443}},
           'REALITY_INBOUND_TAG': TAGS[0], 'VMESS_INBOUND_TAG': TAGS[1],
           'VLESSENC_INBOUND_TAG': TAGS[2], '_systemd_state': Mock(return_value=state),
           '_listening_ports': Mock(return_value=set(ports))}
    nodes = [n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef) and n.name in NAMES]
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<isolated-runtime>', 'exec'), env)
    return env, config


class ManagedInboundRuntimeTests(unittest.TestCase):
    def test_uninstalled_residual_is_not_subscribed(self):
        env, _ = load_functions(installed=False, state='inactive')
        for name in ('_active_reality_config', '_active_vmess_config', '_active_vlessenc_config'):
            with self.subTest(name=name):
                self.assertIsNone(env[name]())

    def test_runtime_matrix(self):
        for tag in TAGS:
            for installed, state, ports, expected in (
                    (False, 'active', (8443,), False),
                    (True, 'inactive', (8443,), False),
                    (True, 'failed', (8443,), False),
                    (True, 'active', (), False),
                    (True, 'active', (8443,), True),
                    (True, '', (8443,), True),
                    (True, '', (), False)):
                with self.subTest(tag=tag, installed=installed, state=state, ports=ports):
                    env, config = load_functions(installed, state, ports)
                    self.assertEqual(env['managed_inbound_active'](config, tag), expected)
                    self.assertFalse(env['managed_inbound_active']({'inbounds': []}, tag))

    def test_residual_config_generates_hysteria_only_subscription(self):
        env, _ = load_functions(installed=False, state='inactive')
        import importlib.util
        source = Path(__file__).resolve().parents[1] / 'portal.py'
        import sys
        sys.path.insert(0, str(source.parent))
        spec = importlib.util.spec_from_file_location('runtime_subscription_portal', source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _, _, sing = module.artifacts(
            {'public_ip': '203.0.113.10', 'server_name': 'node.example.com',
             'listen_port': 443, 'auth_password': 'synthetic-only', 'is_insecure': True},
            auth_override='synthetic-only', user_id='synthetic-user',
            reality=env['_active_reality_config'](),
            vmess=env['_active_vmess_config'](),
            vlessenc=env['_active_vlessenc_config']())
        self.assertEqual([outbound['type'] for outbound in json.loads(sing)['outbounds']],
                         ['hysteria2'])

    def test_live_subscriptions_remain_available(self):
        env, _ = load_functions()
        for name in ('_active_reality_config', '_active_vmess_config', '_active_vlessenc_config'):
            self.assertEqual(env[name](), {'port': 8443})


class InboundConfigShapeTests(unittest.TestCase):
    """xray.json 整体被改坏时，入站定位与写入不能抛异常。

    managed_inbound_index 在撤销、启停、能力清单三条路径上；upsert 在重生成
    Reality/VMess/VLESS-Enc 的锁内。旧写法对 list/str 配置直接 `.get`，
    异常会让「停用/到期用户收回」整轮失败，或让协议启停永远报错。
    """

    def test_index_tolerates_non_dict_config(self):
        env, _ = load_functions()
        for bad in (7, 'x', [None], None, {'inbounds': 'x'}):
            with self.subTest(bad=bad):
                self.assertEqual(env['managed_inbound_index'](bad, TAGS[0]), (-1, None))

    def test_upsert_builds_a_fresh_config_when_input_is_not_a_mapping(self):
        env, _ = load_functions()
        for bad in (7, 'x', [None], None):
            with self.subTest(bad=bad):
                result = env['upsert_managed_inbound'](bad, TAGS[1], {'port': 8443})
                self.assertEqual(result['inbounds'][0]['tag'], TAGS[1])

    def test_upsert_preserves_other_inbounds(self):
        env, _ = load_functions()
        config = {'inbounds': [{'tag': TAGS[0], 'port': 443},
                               {'tag': TAGS[1], 'port': 2087}]}
        result = env['upsert_managed_inbound'](config, TAGS[1], {'port': 2099})
        by_tag = {i['tag']: i for i in result['inbounds']}
        self.assertEqual(by_tag[TAGS[0]]['port'], 443)
        self.assertEqual(by_tag[TAGS[1]]['port'], 2099)


if __name__ == '__main__':
    unittest.main()
