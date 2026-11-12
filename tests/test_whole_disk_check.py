"""重装脚本拒绝把分区当成目标磁盘（2026-11-12 修）。

/dev/vda1 也是块设备，alpine2debian.sh / reinstall-debian13.sh 旧实现照收：随后在分区里再建分区表
或只擦掉这个分区，容量按 0 算，装不成系统。执行真实的 is_whole_disk，用临时目录充当 /sys/block。
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SH = shutil.which('sh') or shutil.which('bash')
SCRIPTS = ('alpine2debian.sh', 'reinstall-debian13.sh')


def source(name):
    return (ROOT / name).read_text(encoding='utf-8').replace('\r\n', '\n')


def func(src, name):
    if name + '() {' not in src:
        return ''
    start = src.index(name + '() {')
    return src[start:src.index('\n}\n', start) + 3]


@unittest.skipUnless(SH and os.name != 'nt', 'requires a POSIX sh')
class WholeDiskCheckTests(unittest.TestCase):
    def verdicts(self, script_name, devices):
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            for disk in ('vda', 'nvme0n1'):
                (t / 'sys' / disk).mkdir(parents=True)
            (t / 'by-id').mkdir()
            (t / 'by-id' / 'disk-link').symlink_to('/dev/vda')
            (t / 'by-id' / 'part-link').symlink_to('/dev/vda1')
            out = {}
            for dev in devices:
                path = str(t / 'by-id' / dev) if dev.endswith('-link') else dev
                r = subprocess.run([SH, '-c', func(source(script_name), 'is_whole_disk')
                                    + 'is_whole_disk "$1" && echo WHOLE || echo PART', 'x', path],
                                   capture_output=True, text=True, timeout=20, env=dict(os.environ, SYS_BLOCK=str(t / 'sys')))
                out[dev] = r.stdout.strip()
        return out

    def test_disks_pass_and_partitions_are_refused(self):
        want = {'/dev/vda': 'WHOLE', '/dev/nvme0n1': 'WHOLE', '/dev/vda1': 'PART', '/dev/nvme0n1p1': 'PART',
                'disk-link': 'WHOLE', 'part-link': 'PART'}
        for name in SCRIPTS:
            with self.subTest(script=name):
                self.assertEqual(self.verdicts(name, list(want)), want)

    def test_check_runs_before_the_disk_is_touched(self):
        for name in SCRIPTS:
            with self.subTest(script=name):
                src = source(name)
                block_check = src.index('[ -n "$DISK" ] && [ -b "$DISK" ] || die')
                whole_check = src.index('is_whole_disk "$DISK" || die', block_check)
                first_touch = min(i for i in (src.find('wipe_disk "$DISK"', block_check),
                                              src.find('sfdisk --label dos', block_check)) if i >= 0)
                self.assertLess(whole_check, first_touch)


if __name__ == '__main__':
    unittest.main()
