"""回归测试：核心升级失败回滚必须经同目录临时文件原子替换，避免覆写运行中二进制触发 ETXTBSY。"""
import errno
import hashlib
import importlib.util
import io
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('portal_core_rb_test', ROOT / 'portal.py')
portal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(portal)


class CoreUpgradeAtomicRollbackTests(unittest.TestCase):
    def test_rollback_uses_atomic_replace_instead_of_in_place_copy_to_binary(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            binary = root / 'hysteria'
            backup_dir = root / 'backups'
            old_payload = b'\x7fELF-old-hysteria-binary'
            new_payload = b'\x7fELF-new-hysteria-binary'
            binary.write_bytes(old_payload)
            expected_sha = hashlib.sha256(new_payload).hexdigest()

            real_copy2 = shutil.copy2
            real_replace = os.replace
            replaced_targets = []

            def strict_copy2(src, dst, *args, **kwargs):
                # 模拟 Linux 内核：直接向运行中的目标二进制原地 copy2 会触发 ETXTBSY。
                if Path(dst).resolve() == binary.resolve():
                    raise OSError(errno.ETXTBSY, 'Text file busy', str(dst))
                return real_copy2(src, dst, *args, **kwargs)

            def spy_replace(src, dst):
                replaced_targets.append((Path(src).parent.resolve(), Path(dst).resolve()))
                return real_replace(src, dst)

            def fake_run(args, **kwargs):
                if Path(args[0]).resolve() == binary.resolve():
                    return SimpleNamespace(returncode=0, stdout='Version: v2.5.0\n', stderr='')
                return SimpleNamespace(returncode=0, stdout='Version: v2.6.0\n', stderr='')

            with patch.object(portal.platform, 'machine', return_value='x86_64'), \
                 patch.object(portal, 'fetch_text', return_value='{"tag_name":"app/v2.6.0"}'), \
                 patch.object(portal, 'fetch_expected_sha256', return_value=expected_sha), \
                 patch.object(portal.urllib.request, 'urlopen', return_value=io.BytesIO(new_payload)), \
                 patch.object(portal.subprocess, 'run', side_effect=fake_run), \
                 patch.object(portal, '_unit_suspended', return_value=False), \
                 patch.object(portal, '_hy2_runtime_identity', side_effect=[
                     ('active', '100', 't1'),
                     ('failed', '0', 't1'),
                 ]), \
                 patch.object(portal, '_restart_hy2', side_effect=[None, RuntimeError('rollback restart failed')]), \
                 patch.object(portal.time, 'sleep'), \
                 patch.object(portal.shutil, 'copy2', side_effect=strict_copy2), \
                 patch.object(portal.os, 'replace', side_effect=spy_replace):
                with self.assertRaisesRegex(RuntimeError, '新核心未成功加载'):
                    portal._upgrade_core_binary_locked(str(binary), str(backup_dir))

            self.assertEqual(binary.read_bytes(), old_payload)
            # 替换了两次：一次安装新核心，一次同目录原子回滚旧核心。
            self.assertEqual(len(replaced_targets), 2)
            self.assertEqual(replaced_targets[1], (binary.parent.resolve(), binary.resolve()))


if __name__ == '__main__':
    unittest.main()
