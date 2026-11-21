"""回归测试：usage-meter-xray-config 写候选与备份文件必须以私有模式创建，且回滚超时不掩盖原错误。"""
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('um_xray_cfg_test', ROOT / 'usage-meter-xray-config-20261007-v1.py')
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def _sample_xray_cfg():
    return {
        'api': {'tag': 'usage-meter-api', 'services': ['StatsService']},
        'policy': {'levels': {'0': {'statsUserUplink': True, 'statsUserDownlink': True}}},
        'inbounds': [
            {'tag': 'reality-in', 'port': 443, 'protocol': 'vless', 'settings': {'clients': [{'id': 'u1', 'level': 0}]}},
            {'tag': 'usage-meter-api-in', 'listen': '127.0.0.1', 'port': 10085, 'protocol': 'dokodemo-door', 'settings': {'address': '127.0.0.1'}},
        ],
        'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}],
        'routing': {'rules': [{'type': 'field', 'inboundTag': ['usage-meter-api-in'], 'outboundTag': 'usage-meter-api'}]},
    }


class XrayConfigPrivateWriteTests(unittest.TestCase):
    def test_enable_reality_online_cleans_candidate_when_chmod_fails(self):
        with tempfile.TemporaryDirectory() as td:
            cfg_path = Path(td) / 'xray.json'
            cfg_path.write_text(json.dumps(_sample_xray_cfg()), encoding='utf-8')
            with mock.patch.object(mod.os, 'chmod', side_effect=PermissionError('chmod denied')):
                with self.assertRaises(PermissionError):
                    mod.enable_reality_online(str(cfg_path), '/usr/local/bin/xray', '127.0.0.1:10085')
            leftovers = [p.name for p in Path(td).iterdir() if 'candidate' in p.name]
            self.assertEqual(leftovers, [], f'chmod 失败后残留明文候选配置: {leftovers}')

    def test_rollback_restart_timeout_does_not_mask_original_error(self):
        with tempfile.TemporaryDirectory() as td:
            cfg_path = Path(td) / 'xray.json'
            cfg_path.write_text(json.dumps(_sample_xray_cfg()), encoding='utf-8')
            calls = []

            def fake_run(args, **kwargs):
                calls.append(list(args))
                if args[:3] == ['/usr/local/bin/xray', 'run', '-test']:
                    return SimpleNamespace(returncode=0)
                if args[:2] == ['systemctl', 'restart']:
                    if sum(1 for c in calls if c[:2] == ['systemctl', 'restart']) == 1:
                        raise RuntimeError('primary restart boom')
                    raise subprocess.TimeoutExpired(args, 15)
                return SimpleNamespace(returncode=0)

            with mock.patch.object(mod.subprocess, 'run', side_effect=fake_run):
                with self.assertRaisesRegex(RuntimeError, 'primary restart boom'):
                    mod.enable_iplimit_routing(str(cfg_path), '/usr/local/bin/xray', '127.0.0.1:10085')

    def test_candidate_and_backup_created_via_os_open_with_private_mode(self):
        src = (ROOT / 'usage-meter-xray-config-20261007-v1.py').read_text(encoding='utf-8')
        self.assertNotIn('candidate.write_text(', src, '候选配置仍用默认 umask write_text 写入')
        self.assertNotIn('candidate.write_bytes(', src, '回滚候选配置仍用默认 umask write_bytes 写入')
        self.assertNotIn('shutil.copy2(path,backup)', src, '备份仍用 shutil.copy2 存在权限窗口')


if __name__ == '__main__':
    unittest.main()
