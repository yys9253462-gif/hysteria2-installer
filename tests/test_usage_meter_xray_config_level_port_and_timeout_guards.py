import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    'um_xray_cfg_b51', REPO / 'usage-meter-xray-config-20261007-v1.py'
)
XCFG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(XCFG)


class TestUsageMeterXrayConfigLevelPortAndTimeoutGuards(unittest.TestCase):
    def test_add_stats_sanitizes_null_or_invalid_client_level_and_detects_string_port_conflict(self):
        """client.level 为 null/布尔/非法字符串时不得污染 policy.levels，且须识别字符串/区间端口冲突。"""
        cfg = {
            'inbounds': [
                {
                    'tag': 'vless-in',
                    'port': 8443,
                    'settings': {
                        'clients': [
                            {'id': 'u1', 'level': None},
                            {'id': 'u2', 'level': True},
                            {'id': 'u3', 'level': 'bad'},
                            {'id': 'u4', 'level': 2},
                        ]
                    },
                }
            ],
            'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}],
        }
        out = XCFG.add_stats(cfg, 19997)
        levels = out['policy']['levels']
        self.assertIn('0', levels)
        self.assertIn('2', levels)
        self.assertNotIn('None', levels)
        self.assertNotIn('True', levels)
        self.assertNotIn('bad', levels)

        # 字符串单端口与端口区间冲突都必须拦住
        for raw_port in ('19997', '19990-20000'):
            conflict_cfg = {
                'inbounds': [{'tag': 'other', 'port': raw_port}],
                'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}],
            }
            with self.assertRaisesRegex(ValueError, 'port conflict'):
                XCFG.add_stats(conflict_cfg, 19997)

    def test_enable_iplimit_routing_retries_on_probe_timeout_and_survives_reset_failed_timeout(self):
        """enable_iplimit_routing 在 reset-failed 或首轮 lsrules 探测超时时须容错重试，不得误回滚。"""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'xray.json'
            cfg = {
                'api': {'tag': 'usage-meter-api', 'services': ['StatsService']},
                'inbounds': [],
                'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}],
            }
            p.write_text(json.dumps(cfg), encoding='utf-8')

            probe_calls = {'n': 0}

            def fake_run(cmd, **kwargs):
                if cmd[:2] == ['systemctl', 'reset-failed']:
                    raise subprocess.TimeoutExpired(cmd, 5)
                if len(cmd) >= 3 and cmd[1:3] == ['api', 'lsrules']:
                    probe_calls['n'] += 1
                    if probe_calls['n'] == 1:
                        raise subprocess.TimeoutExpired(cmd, 5)
                return mock.Mock(returncode=0, stdout=b'', stderr=b'')

            with mock.patch.object(XCFG.subprocess, 'run', side_effect=fake_run), \
                 mock.patch.object(XCFG.time, 'sleep'):
                res = XCFG.enable_iplimit_routing(str(p), '/usr/local/bin/xray', '127.0.0.1:19997')

            self.assertTrue(res['enabled'])
            self.assertTrue(res['changed'])
            self.assertEqual(probe_calls['n'], 2)

    def test_enable_reality_online_sanitizes_null_client_level_and_uses_random_staging_names(self):
        """enable_reality_online 须跳过 null client.level 并为暂存文件加随机后缀防撞名。"""
        src = (REPO / 'usage-meter-xray-config-20261007-v1.py').read_text(encoding='utf-8')
        self.assertIn('secrets.token_hex', src)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'xray.json'
            cfg = {
                'inbounds': [{'tag': 'r', 'settings': {'clients': [{'id': 'u1', 'level': None}]}}],
                'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}],
            }
            p.write_text(json.dumps(cfg), encoding='utf-8')
            with mock.patch.object(XCFG.subprocess, 'run', return_value=mock.Mock(returncode=0)):
                res = XCFG.enable_reality_online(str(p), '/usr/local/bin/xray', '127.0.0.1:19997')
            self.assertTrue(res['changed'])
            saved = json.loads(p.read_text(encoding='utf-8'))
            self.assertNotIn('None', saved['policy']['levels'])
            self.assertTrue(saved['policy']['levels']['0']['statsUserOnline'])


if __name__ == '__main__':
    unittest.main()
