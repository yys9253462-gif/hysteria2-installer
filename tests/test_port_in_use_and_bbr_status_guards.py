"""回归测试：protocol_port_in_use/firewall_port 排除键与布尔端口防护，及 _h_get_bbr_status 缺失 modinfo/坏编码容错。"""

import ast
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
TREE = ast.parse(SRC)


def _compile_bbr_status():
    for node in ast.walk(TREE):
        if isinstance(node, ast.FunctionDef) and node.name == '_h_get_bbr_status':
            mod = ast.Module(body=[node], type_ignores=[])
            ast.fix_missing_locations(mod)
            return compile(mod, str(ROOT / 'portal.py'), 'exec')
    raise AssertionError('portal.py 中未找到 _h_get_bbr_status')


class PortInUseAndBbrStatusGuardsTests(unittest.TestCase):
    def test_protocol_port_in_use_respects_exclude_key_rejects_bool_and_corrupt_inbounds(self):
        # 布尔 True 不应被 int(True) 当作端口 1
        self.assertFalse(portal.protocol_port_in_use(True, 'tcp', {'reality_config': {'port': 1}}))
        self.assertFalse(portal.firewall_port(True, 'tcp', open_=True))

        # exclude_key='proxy_services' 时不得把自己判成仍在占用
        with mock.patch.object(portal, '_systemd_state', return_value='inactive'):
            self.assertFalse(portal.protocol_port_in_use(
                8080, 'tcp', {'proxy_services': [{'port': 8080}]}, exclude_key='proxy_services'))
            # 损坏的 xray_config.inbounds（None / 整数）不得抛 TypeError
            self.assertFalse(portal.protocol_port_in_use(
                443, 'tcp', {}, xray_config={'inbounds': None}))
            self.assertFalse(portal.protocol_port_in_use(
                443, 'tcp', {}, xray_config={'inbounds': 123}))

    def test_bbr_status_survives_missing_modinfo_and_corrupt_conf_encoding(self):
        code = _compile_bbr_status()
        with tempfile.TemporaryDirectory() as td:
            bad_conf = Path(td) / '99-bbr.conf'
            bad_conf.write_bytes(b'\xff\xfe\x00broken')

            def fake_run(cmd, **kwargs):
                if cmd[0] == 'modinfo':
                    raise FileNotFoundError('modinfo not installed')
                if cmd[-1] == 'net.ipv4.tcp_congestion_control':
                    return SimpleNamespace(returncode=0, stdout='cubic\n', stderr='')
                if cmd[-1] == 'net.core.default_qdisc':
                    return SimpleNamespace(returncode=0, stdout='fq_codel\n', stderr='')
                if cmd[-1] == 'net.ipv4.tcp_available_congestion_control':
                    return SimpleNamespace(returncode=0, stdout='reno cubic bbr\n', stderr='')
                return SimpleNamespace(returncode=0, stdout='', stderr='')

            ns = {
                'platform': SimpleNamespace(release=lambda: '6.1.0-test'),
                'subprocess': SimpleNamespace(run=fake_run, SubprocessError=Exception),
                'Path': lambda p: bad_conf if str(p) == '/etc/sysctl.d/99-bbr.conf' else Path(p),
                'sysctl_conf_overrides': lambda mapping: [],
                'data_lock': threading.RLock(),
                'data': {'bbr_target_version': ''},
            }
            exec(code, ns)

            replies = []
            handler = SimpleNamespace(
                is_authenticated=lambda: True,
                reply_json=lambda status, payload: replies.append((status, payload)),
            )
            ns['_h_get_bbr_status'](handler, 'bbr-status')
            self.assertEqual(len(replies), 1)
            status, payload = replies[0]
            self.assertEqual(status, 200, payload)
            self.assertTrue(payload['ok'])
            self.assertEqual(payload['current'], 'cubic')
            self.assertIn('bbr', payload['available'])


if __name__ == '__main__':
    unittest.main()
