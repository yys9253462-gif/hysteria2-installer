"""回归测试：apply_anytls_config 回滚写盘抛 OSError 时不得掩盖原启动错误，且仍须尝试重启恢复原服务。"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class ApplyAnytlsRollbackIsolationTests(unittest.TestCase):
    def test_restore_file_oserror_does_not_mask_original_error_or_skip_restart(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'anytls.json'
            cfg.write_text('{"inbounds": []}', encoding='utf-8')
            calls = []

            def fake_run(cmd, **kwargs):
                calls.append(list(cmd))
                if cmd[:2] == ['systemctl', 'restart']:
                    if sum(1 for c in calls if c[:2] == ['systemctl', 'restart']) == 1:
                        raise subprocess.CalledProcessError(1, cmd)
                return subprocess.CompletedProcess(cmd, 0, b'', b'')

            with mock.patch.object(portal, '_restore_config_atomically', side_effect=OSError('disk full on rollback')):
                with self.assertRaises(subprocess.CalledProcessError):
                    portal.apply_anytls_config({'inbounds': [{'tag': 'a'}]}, cfg, restart=True, run=fake_run)

            restarts = [c for c in calls if c[:2] == ['systemctl', 'restart']]
            self.assertEqual(len(restarts), 2, f'回滚写盘失败后跳过了第二次 restart: {calls}')


if __name__ == '__main__':
    unittest.main()
