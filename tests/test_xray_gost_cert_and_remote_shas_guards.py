import ast
import importlib.util
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORTAL_PATH = ROOT / 'portal.py'


def _load_portal_module():
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    spec = importlib.util.spec_from_file_location('portal_batch56_item2', PORTAL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _extract_serve_defs(names):
    """按函数名提取 portal.py serve() 中的指定嵌套函数源码。"""
    tree = ast.parse(PORTAL_PATH.read_text(encoding='utf-8'))
    serve_fn = next(
        n for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == 'serve'
    )
    wanted = set(names)
    chunks = []
    for node in serve_fn.body:
        if isinstance(node, ast.FunctionDef) and node.name in wanted:
            chunks.append(ast.unparse(node))
    missing = wanted - {
        node.name for node in serve_fn.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted
    }
    if missing:
        raise AssertionError(f'缺少嵌套函数: {sorted(missing)}')
    return '\n\n'.join(chunks)


class XrayGostCertAndRemoteShasGuardTests(unittest.TestCase):
    def test_reload_gost_survives_reload_and_reset_failed_timeouts(self):
        src = _extract_serve_defs(['reload_gost'])
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            if cmd[:2] == ['systemctl', 'reload']:
                raise subprocess.TimeoutExpired(cmd, 5)
            if cmd[:2] == ['systemctl', 'reset-failed']:
                raise subprocess.TimeoutExpired(cmd, 5)
            return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')

        class FakePath:
            def __init__(self, p):
                self._p = Path(p)

            def exists(self):
                return True

        ns = {
            'Path': FakePath,
            'gost_operation_lock': threading.Lock(),
            'ensure_gost_unit': lambda: None,
            'write_gost_config': lambda: None,
            '_unit_suspended': lambda name: False,
            'gost_status': lambda: True,
            'gost_ports_ready': lambda: True,
            'subprocess': type('Sub', (), {
                'run': staticmethod(fake_run),
                'SubprocessError': subprocess.SubprocessError,
            })(),
            'time': type('T', (), {'sleep': staticmethod(lambda _s: None)})(),
            'portal_path': Path('/tmp/portal.py'),
            'json': json,
        }
        exec(compile(src, str(PORTAL_PATH), 'exec'), ns)
        ok = ns['reload_gost']()
        self.assertTrue(ok, f'reload 与 reset-failed 超时后应继续执行 restart 并成功，实际 calls={calls}')
        self.assertIn(['systemctl', 'restart', 'gost'], calls)

    def test_write_gost_config_rejects_leading_zero_port_and_strips_ctrl_chars(self):
        src = _extract_serve_defs(['write_gost_config'])
        written = {}

        def fake_atomic_write(path, payload):
            written['path'] = path
            written['payload'] = payload

        with tempfile.TemporaryDirectory() as tmp:
            portal_file = Path(tmp) / 'portal.py'
            gost_written_ports = []
            data = {
                'proxy_services': [
                    {'type': 'socks5', 'port': '08080', 'username': 'bad', 'password': 'bad'},
                    {'type': 'http', 'port': '10809', 'username': 'u\r\n1\x00', 'password': 'p\x07\n2'},
                ],
            }
            ns = {
                'portal_path': portal_file,
                'data_lock': threading.Lock(),
                'data': data,
                'proxy_services': lambda d: d['proxy_services'],
                'GOST_PRIVATE_BYPASS': 'private-bypass',
                'PRIVATE_REJECT_RULES': ['127.0.0.0/8'],
                'gost_written_ports': gost_written_ports,
                'atomic_write_private': fake_atomic_write,
                'json': json,
                'sys': __import__('sys'),
            }
            exec(compile(src, str(PORTAL_PATH), 'exec'), ns)
            ns['write_gost_config']()

            self.assertEqual(gost_written_ports, [10809])
            cfg = json.loads(written['payload'].decode('utf-8'))
            self.assertEqual(len(cfg['services']), 1)
            auth = cfg['services'][0]['handler']['auth']
            self.assertEqual(auth['username'], 'u1')
            self.assertEqual(auth['password'], 'p2')

    def test_apply_xray_config_transaction_rejects_bad_binary_and_nan(self):
        mod = _load_portal_module()
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / 'xray.json'
            with self.assertRaises(ValueError):
                mod.apply_xray_config_transaction({'inbounds': []}, config_path=str(cfg_path),
                                                  binary='-malicious', restart=False)
            with self.assertRaises(ValueError):
                mod.apply_xray_config_transaction({'inbounds': []}, config_path=str(cfg_path),
                                                  binary='/usr/local/bin/xray\n', restart=False)
            with self.assertRaises(ValueError):
                mod.apply_xray_config_transaction({'bad': float('nan')}, config_path=str(cfg_path),
                                                  binary='/usr/local/bin/xray', restart=False)
            self.assertFalse(cfg_path.with_name(cfg_path.name + '.portal-candidate.json').exists())

    def test_sync_cert_runtime_handles_none_cert_and_record_cert_heal_sanitizes_nan(self):
        mod = _load_portal_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # 传入 None 证书路径不应抛 TypeError
            self.assertFalse(mod.sync_cert_runtime(root, None))
            # 已有 cert-selfheal.json 中含非标准 NaN 与非法 heal_count 时，写入后应产出严格 JSON
            state_path = root / 'cert-selfheal.json'
            state_path.write_text(
                '{"loaded_cert_sha256": "abc123", "heal_count": Infinity, "extra_nan": NaN}',
                encoding='utf-8',
            )
            mod.record_cert_heal(root, {}, {'pin_sha256': 'old'}, {'pin_sha256': 'new'})
            raw = state_path.read_text(encoding='utf-8')
            self.assertNotIn('NaN', raw)
            self.assertNotIn('Infinity', raw)
            parsed = json.loads(raw)
            self.assertEqual(parsed['loaded_cert_sha256'], 'abc123')
            self.assertEqual(parsed['heal_count'], 1)
            self.assertEqual(parsed['last_pin'], 'new')

    def test_remote_root_shas_filters_non_str_name_and_sha(self):
        src = _extract_serve_defs(['_remote_root_shas'])
        payload = json.dumps([
            {'name': ['unhashable'], 'sha': '1111111'},
            {'name': 'portal.py', 'sha': 1234567},
            {'name': 'install.sh', 'sha': 'abcdef1234567'},
        ]).encode('utf-8')

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, _limit=-1):
                return payload

        ns = {
            'time': type('T', (), {'time': staticmethod(lambda: 1000.0)})(),
            '_ver_cache_lock': threading.Lock(),
            '_ver_cache': {'t': 0.0, 'data': None},
            'AWG_REPO': 'example/repo',
            'urllib': type('U', (), {
                'request': type('R', (), {
                    'Request': staticmethod(lambda url, headers=None: url),
                    'urlopen': staticmethod(lambda req, timeout=8: FakeResp()),
                })(),
            })(),
            'json': json,
            '_log_ignored': lambda *args: None,
        }
        exec(compile(src, str(PORTAL_PATH), 'exec'), ns)
        shas = ns['_remote_root_shas']()
        self.assertIsInstance(shas, dict)
        self.assertEqual(shas.get('install.sh'), 'abcdef1234567')
        self.assertEqual(shas.get('portal.py'), '')


if __name__ == '__main__':
    unittest.main()
