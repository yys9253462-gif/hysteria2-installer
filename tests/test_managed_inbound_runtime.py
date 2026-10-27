import ast
import json
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock

TREE = ast.parse((Path(__file__).resolve().parents[1] / 'portal.py').read_text(encoding='utf-8'))
TAGS = ('vless-reality-in', 'vmess-ws-in', 'vless-enc-in')
NAMES = {'managed_inbound_index', 'has_managed_inbound', 'managed_inbound_active',
         '_active_reality_config', '_active_vmess_config', '_active_vlessenc_config'}


def load_functions(installed=True, state='active', ports=(8443,)):
    config = {'inbounds': [{'tag': tag, 'port': 8443, 'protocol': 'vless'} for tag in TAGS]}
    fake_path = Mock()
    fake_path.return_value.is_file.return_value = installed
    fake_path.return_value.exists.return_value = installed
    fake_path.return_value.read_text.return_value = json.dumps(config)
    env = {'Path': fake_path, 'json': json, 'data_lock': threading.RLock(),
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


if __name__ == '__main__':
    unittest.main()
