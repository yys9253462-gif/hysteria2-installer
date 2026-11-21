"""回归测试：ensure_awgctl 同目录原子刷盘替换与失败清理、cert_status 自愈状态逐项容错、write_xray_unit 坏编码自愈。"""

import ast
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
TREE = ast.parse(SRC)


def _compile_ensure_awgctl():
    for node in ast.walk(TREE):
        if isinstance(node, ast.FunctionDef) and node.name == 'ensure_awgctl':
            mod = ast.Module(body=[node], type_ignores=[])
            ast.fix_missing_locations(mod)
            return compile(mod, str(ROOT / 'portal.py'), 'exec')
    raise AssertionError('portal.py 中未找到 ensure_awgctl')


class AwgctlCertAndXrayUnitSafetyTests(unittest.TestCase):
    def test_ensure_awgctl_uses_same_dir_atomic_replace_fsync_and_cleans_temp_on_failure(self):
        code = _compile_ensure_awgctl()
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / 'hy2-awgctl'
            target.write_bytes(b'#!/bin/bash\n# old hy2-awgctl\n')
            new_bytes = b'#!/bin/bash\n# new hy2-awgctl\n' + b'x' * 2048
            fsync_called = []
            real_fsync = os.fsync

            def track_fsync(fd):
                fsync_called.append(fd)
                return real_fsync(fd)

            ns = {
                'Path': Path,
                'AWG_CTL': str(target),
                'resolve_update_ref': lambda branch: 'a' * 40,
                '_remote_blob_sha': lambda *a, **k: 'b' * 40,
                '_fetch_repo_file': lambda *a, **k: new_bytes,
                'tempfile': tempfile,
                'os': os,
                'shutil': __import__('shutil'),
            }
            exec(code, ns)

            with mock.patch.object(os, 'fsync', side_effect=track_fsync), \
                 mock.patch('shutil.move', side_effect=AssertionError('不得用 shutil.move 跨分区非原子替换')):
                ok = ns['ensure_awgctl'](force=True)
            self.assertTrue(ok)
            self.assertEqual(target.read_bytes(), new_bytes)
            self.assertTrue(fsync_called, 'ensure_awgctl 写盘前必须调用 os.fsync 刷盘')
            self.assertEqual([p.name for p in Path(td).iterdir()], ['hy2-awgctl'])

            # 模拟内容有更新但 os.replace 失败时，必须返回 False 且不得遗留临时文件
            ns['_fetch_repo_file'] = lambda *a, **k: new_bytes + b'\n# v2\n'
            with mock.patch.object(os, 'replace', side_effect=OSError('disk full')):
                ok2 = ns['ensure_awgctl'](force=True)
            self.assertFalse(ok2)
            self.assertEqual([p.name for p in Path(td).iterdir()], ['hy2-awgctl'],
                             'ensure_awgctl 失败后遗留了临时文件')

    def test_cert_status_ignores_bool_or_corrupt_heal_counters_without_losing_last_pin(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cert_file = root / 'cert.pem'
            cert_file.write_text('dummy', encoding='utf-8')
            heal_file = root / 'cert-selfheal.json'
            heal_file.write_text(json.dumps({
                'healed_at': True,
                'heal_count': 'bad-int',
                'last_pin': 'AA:BB:CC',
            }), encoding='utf-8')

            fake_openssl = SimpleNamespace(
                returncode=0,
                stdout='issuer=CN = Test CA\nnotBefore=Jan  1 00:00:00 2026 GMT\nnotAfter=Jan  1 00:00:00 2030 GMT\n',
                stderr='',
            )
            with mock.patch.object(portal, '_resolve_live_cert',
                                   return_value=(cert_file, 'example.com', ['example.com'], False)), \
                 mock.patch.object(portal.subprocess, 'run', return_value=fake_openssl):
                info = portal.cert_status(root, {'server_name': 'example.com'},
                                          selfheal_state_path=str(heal_file))
            self.assertEqual(info['healed_at'], 0, '布尔 True 不应被当成 1970 年的时间戳 1')
            self.assertEqual(info['heal_count'], 0)
            self.assertEqual(info['pin_sha256'], 'AA:BB:CC', '坏计数不应导致 last_pin 被整块跳过')

    def test_write_xray_unit_recovers_from_corrupt_non_utf8_unit_file(self):
        with tempfile.TemporaryDirectory() as td:
            unit_file = Path(td) / 'xray.service'
            unit_file.write_bytes(b'\xff\xfe\x00broken-binary')
            written = []
            with mock.patch.object(portal, 'Path', return_value=unit_file), \
                 mock.patch.object(portal, '_restore_systemd_unit_file',
                                   side_effect=lambda p, b, m: written.append((p, b, m))), \
                 mock.patch.object(portal.subprocess, 'run') as m_run:
                portal.write_xray_unit()
            self.assertEqual(len(written), 1, '损坏的非 UTF-8 xray.service 应触发自愈重写')
            m_run.assert_called_once()


if __name__ == '__main__':
    unittest.main()
