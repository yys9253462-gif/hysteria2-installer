"""回归测试：alpine2debian.sh 与 reinstall-debian13.sh 精确匹配目标盘及其分区，不误伤其它磁盘。"""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALPINE_SRC = (ROOT / 'alpine2debian.sh').read_text(encoding='utf-8').replace('\r\n', '\n')
REINSTALL_SRC = (ROOT / 'reinstall-debian13.sh').read_text(encoding='utf-8').replace('\r\n', '\n')
SH = shutil.which('sh') or shutil.which('bash')


def _extract_fn(src, name):
    marker = name + '()'
    if marker not in src:
        raise AssertionError('缺少辅助函数: ' + marker)
    start = src.index(marker)
    end = src.index('\n}\n', start) + 3
    return src[start:end]


@unittest.skipUnless(SH, 'requires sh')
class DiskMatchIsolationTests(unittest.TestCase):
    def test_no_prefix_glob_or_prefix_awk_remains(self):
        self.assertNotIn('for _p in "${_d}"*', ALPINE_SRC)
        self.assertNotIn('$1 ~ "^"d', ALPINE_SRC)
        self.assertNotIn('for _p in "${_d}"*', REINSTALL_SRC)
        self.assertNotIn('blkid "${DISK}"*', REINSTALL_SRC)

    def test_alpine_disk_mounts_avoids_prefix_collision(self):
        fn_src = _extract_fn(ALPINE_SRC, 'disk_mounts')
        with tempfile.TemporaryDirectory() as td:
            mounts = Path(td) / 'mounts'
            mounts.write_text(
                '/dev/sdaa1 /mnt/other-sdaa ext4 rw 0 0\n'
                '/dev/nvme0n10p1 /mnt/other-nvme ext4 rw 0 0\n'
                '/dev/sda1 /mnt/target-sda ext4 rw 0 0\n'
                '/dev/nvme0n1p1 /mnt/target-nvme ext4 rw 0 0\n',
                encoding='utf-8',
            )
            for disk, expected in (
                ('/dev/sda', ['/mnt/target-sda']),
                ('/dev/nvme0n1', ['/mnt/target-nvme']),
                ('/dev/vda', []),
            ):
                res = subprocess.run(
                    [SH, '-c', fn_src + '\ndisk_mounts "$1" "$2"\n', 'sh', disk, mounts.as_posix()],
                    capture_output=True, text=True, encoding='utf-8', timeout=10,
                )
                self.assertEqual(res.returncode, 0, res.stderr)
                got = [line for line in res.stdout.splitlines() if line.strip()]
                self.assertEqual(got, expected, f'disk={disk}')

    def test_disk_devices_in_both_scripts_match_only_own_partitions(self):
        for label, src in (('alpine2debian.sh', ALPINE_SRC), ('reinstall-debian13.sh', REINSTALL_SRC)):
            with self.subTest(script=label), tempfile.TemporaryDirectory() as td:
                fn_src = _extract_fn(src, 'disk_devices')
                devdir = Path(td)
                for name in (
                    'sda', 'sda1', 'sda12', 'sdaa', 'sdaa1', 'sda1x',
                    'nvme0n1', 'nvme0n1p1', 'nvme0n1p10', 'nvme0n10', 'nvme0n10p1',
                ):
                    (devdir / name).write_text('', encoding='utf-8')
                for target, expected_names in (
                    ('sda', ['sda', 'sda1', 'sda12']),
                    ('nvme0n1', ['nvme0n1', 'nvme0n1p1', 'nvme0n1p10']),
                ):
                    res = subprocess.run(
                        [SH, '-c', fn_src + '\ndisk_devices "$1"\n', 'sh', (devdir / target).as_posix()],
                        capture_output=True, text=True, encoding='utf-8', timeout=10,
                    )
                    self.assertEqual(res.returncode, 0, res.stderr)
                    got = sorted(Path(line).name for line in res.stdout.splitlines() if line.strip())
                    self.assertEqual(got, sorted(expected_names), f'{label} target={target}')


if __name__ == '__main__':
    unittest.main()
