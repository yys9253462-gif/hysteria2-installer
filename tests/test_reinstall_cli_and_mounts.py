"""重装脚本参数缺值防护与挂载表精确磁盘匹配回归测试。

旧实现：
1. 带值选项直接 shift 2 未检查参数个数，漏填取值时在 bash 下死循环、在 sh 下报晦涩错误；
2. 检查 /proc/mounts 用 "^"d 前缀匹配，/dev/nvme0n1 会误命中 /dev/nvme0n10p1，/dev/sda 会误命中 /dev/sdaa1。
"""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SRC = (Path(__file__).resolve().parents[1] / 'reinstall-debian13.sh').read_text(encoding='utf-8').replace('\r\n', '\n')
SH = shutil.which('sh') or shutil.which('bash')


@unittest.skipUnless(SH, 'requires sh')
class ReinstallCliAndMountsTests(unittest.TestCase):
    def test_missing_option_value_fails_fast_with_clear_message(self):
        start = SRC.index('# ── 参数解析')
        end = SRC.index('# ── 参数合法性校验', start)
        snippet = 'die() { echo "DIE:$*" >&2; exit 1; }\n' + SRC[start:end]
        for flag in ('--port', '--pwd', '--password', '--disk', '--mirror', '--release', '--swap', '--net'):
            with self.subTest(flag=flag):
                res = subprocess.run(
                    [SH, '-c', snippet, 'sh', flag],
                    capture_output=True, text=True, encoding='utf-8', timeout=5,
                )
                self.assertNotEqual(res.returncode, 0)
                self.assertIn('缺少取值', res.stderr)

    def test_mounts_match_exact_disk_and_partitions_without_prefix_collision(self):
        with tempfile.TemporaryDirectory() as td:
            mounts = Path(td) / 'mounts'
            mounts.write_text(
                '/dev/nvme0n10 /mnt/other-raw ext4 rw 0 0\n'
                '/dev/nvme0n10p1 /mnt/other-part ext4 rw 0 0\n'
                '/dev/sdaa1 /mnt/sdaa-part ext4 rw 0 0\n'
                '/dev/nvme0n1p1 /media/nvme-part iso9660 ro 0 0\n'
                '/dev/sda1 /media/sda-part ext4 rw 0 0\n'
                '/dev/vda /media/vda-raw iso9660 ro 0 0\n',
                encoding='utf-8',
            )
            # 从脚本真实代码中抽取挂载查询逻辑
            self.assertIn('disk_mounts()', SRC, '缺少统一的 disk_mounts 辅助函数')
            fn_start = SRC.index('disk_mounts()')
            fn_end = SRC.index('\n}\n', fn_start) + 3
            fn_src = SRC[fn_start:fn_end]

            def query(disk):
                cmd = fn_src + '\ndisk_mounts "$1" "$2"\n'
                res = subprocess.run(
                    [SH, '-c', cmd, 'sh', disk, mounts.as_posix()],
                    capture_output=True, text=True, encoding='utf-8', timeout=10,
                )
                self.assertEqual(res.returncode, 0, res.stderr)
                return [line for line in res.stdout.splitlines() if line.strip()]

            self.assertEqual(query('/dev/nvme0n1'), ['/media/nvme-part'])
            self.assertEqual(query('/dev/sda'), ['/media/sda-part'])
            self.assertEqual(query('/dev/vda'), ['/media/vda-raw'])
            self.assertEqual(query('/dev/vdb'), [])


if __name__ == '__main__':
    unittest.main()
