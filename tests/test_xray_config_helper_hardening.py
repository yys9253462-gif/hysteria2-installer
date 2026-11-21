"""回归测试：usage-meter-xray-config 非对象配置拦截、回环端口前置校验、超时重试与回滚写盘异常隔离。"""

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('xray_cfg_mod', ROOT / 'usage-meter-xray-config-20261007-v1.py')
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class XrayConfigHelperHardeningTests(unittest.TestCase):
    def test_non_dict_config_rejected_with_value_error(self):
        with self.assertRaises(ValueError):
            MOD.add_stats(['not-a-dict'], 10085)

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'xray.json'
            p.write_text('[]', encoding='utf-8')
            with self.assertRaises(ValueError):
                MOD.enable_iplimit_routing(str(p), '/usr/local/bin/xray', '127.0.0.1:10085')
            with self.assertRaises(ValueError):
                MOD.enable_reality_online(str(p), '/usr/local/bin/xray', '127.0.0.1:10085')

    def test_invalid_loopback_address_rejected_before_reading_file(self):
        with self.assertRaises(ValueError):
            MOD.enable_reality_online('/nonexistent/xray.json', '/usr/local/bin/xray', '127.0.0.1:notaport')
        with self.assertRaises(ValueError):
            MOD.enable_reality_online('/nonexistent/xray.json', '/usr/local/bin/xray', None)
        with self.assertRaises(ValueError):
            MOD.enable_iplimit_routing('/nonexistent/xray.json', '/usr/local/bin/xray', '127.0.0.1:70000')

    def test_enable_reality_online_retries_on_probe_timeout(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'xray.json'
            p.write_text(json.dumps({
                'inbounds': [{'tag': 'reality-in', 'settings': {'clients': [{'id': 'u1'}]}}],
            }), encoding='utf-8')
            attempts = {'n': 0}

            def fake_run(cmd, **kwargs):
                if 'statsgetallonlineusers' in cmd:
                    attempts['n'] += 1
                    if attempts['n'] == 1:
                        raise subprocess.TimeoutExpired(cmd, 5)
                return subprocess.CompletedProcess(cmd, 0, b'', b'')

            with mock.patch.object(MOD.subprocess, 'run', side_effect=fake_run), \
                 mock.patch.object(MOD.time, 'sleep', return_value=None):
                res = MOD.enable_reality_online(str(p), '/usr/local/bin/xray', '127.0.0.1:10085')
            self.assertTrue(res['enabled'])
            self.assertEqual(attempts['n'], 2)

    def test_rollback_write_oserror_does_not_mask_original_error(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'xray.json'
            p.write_text(json.dumps({
                'inbounds': [{'tag': 'reality-in', 'settings': {'clients': [{'id': 'u1'}]}}],
            }), encoding='utf-8')
            write_calls = {'n': 0}
            real_write = MOD._write_private_bytes

            def flaky_write(target, payload, mode):
                write_calls['n'] += 1
                if write_calls['n'] >= 3:
                    raise OSError('disk full on rollback')
                return real_write(target, payload, mode)

            def fake_run(cmd, **kwargs):
                if cmd[:2] == ['systemctl', 'restart']:
                    raise RuntimeError('primary restart boom')
                return subprocess.CompletedProcess(cmd, 0, b'', b'')

            with mock.patch.object(MOD, '_write_private_bytes', side_effect=flaky_write), \
                 mock.patch.object(MOD.subprocess, 'run', side_effect=fake_run), \
                 mock.patch.object(MOD, '_rollback_restart_xray') as rb_restart:
                with self.assertRaisesRegex(RuntimeError, 'primary restart boom'):
                    MOD.enable_reality_online(str(p), '/usr/local/bin/xray', '127.0.0.1:10085')
            rb_restart.assert_called_once()


if __name__ == '__main__':
    unittest.main()
