"""回归测试：install.sh 的 hy2_tar_find_member 必须校验 tar 退出码与成员唯一性，sync_cert_meta 私有原子落盘。"""
import io
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / 'install.sh').read_text(encoding='utf-8')
BASH = shutil.which('bash')


class InstallTarAndMetaHardeningTests(unittest.TestCase):
    @unittest.skipUnless(BASH, 'requires bash')
    def test_hy2_tar_find_member_rejects_truncated_and_duplicate_archives(self):
        m = re.search(r'(hy2_tar_find_member\(\) \{.*?\n\})', INSTALL, re.S)
        self.assertIsNotNone(m)
        fn_body = m.group(1)
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            # 1) 截断损坏归档（前段含目标文件头，后段被截断导致 tar 返回非零）
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode='w:gz') as tf:
                f1 = tarfile.TarInfo('gost')
                f1.size = 4
                tf.addfile(f1, io.BytesIO(b'bin!'))
                f2 = tarfile.TarInfo('pad.bin')
                pad = os.urandom(65536)
                f2.size = len(pad)
                tf.addfile(f2, io.BytesIO(pad))
            raw = buf.getvalue()
            (td_path / 'trunc.tar.gz').write_bytes(raw[: len(raw) // 2])
            res_trunc = subprocess.run([BASH, '-c', f'{fn_body}\nhy2_tar_find_member "trunc.tar.gz" gost\n'],
                                       cwd=td, capture_output=True, text=True, timeout=15)
            self.assertNotEqual(res_trunc.returncode, 0, f'截断归档被 hy2_tar_find_member 放行: {res_trunc.stdout!r}')

            # 2) 同名重复成员（gost 与 ./gost 同时存在）必须拒绝
            dup_buf = io.BytesIO()
            with tarfile.open(fileobj=dup_buf, mode='w:gz') as tf:
                for name in ('gost', './gost'):
                    info = tarfile.TarInfo(name)
                    info.size = 2
                    tf.addfile(info, io.BytesIO(b'ok'))
            (td_path / 'dup.tar.gz').write_bytes(dup_buf.getvalue())
            res_dup = subprocess.run([BASH, '-c', f'{fn_body}\nhy2_tar_find_member "dup.tar.gz" gost\n'],
                                     cwd=td, capture_output=True, text=True, timeout=15)
            self.assertNotEqual(res_dup.returncode, 0, f'重复同名成员被 hy2_tar_find_member 放行: {res_dup.stdout!r}')

            # 3) 唯一合法成员正常返回
            (td_path / 'good.tar.gz').write_bytes(raw)
            res_ok = subprocess.run([BASH, '-c', f'{fn_body}\nhy2_tar_find_member "good.tar.gz" gost\n'],
                                    cwd=td, capture_output=True, text=True, timeout=15)
            self.assertEqual(res_ok.returncode, 0, res_ok.stderr)
            self.assertEqual(res_ok.stdout.strip(), 'gost')

    def test_sync_cert_meta_writes_private_mktemp_with_chmod_600(self):
        m = re.search(r'(sync_cert_meta\(\) \{.*?\n\})', INSTALL, re.S)
        self.assertIsNotNone(m)
        body = m.group(1)
        self.assertNotIn('local tmp_meta="${HY2_META_FILE}.tmp.$$"', body,
                         'sync_cert_meta 仍使用可预测的 .tmp.$$ 临时名')
        self.assertIn('chmod 600 "$tmp_meta"', body, 'sync_cert_meta 落盘前未确保 600 权限')


if __name__ == '__main__':
    unittest.main()
