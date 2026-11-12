"""alpine2debian.sh：--disk 给符号链接时先解析成真实设备（2026-11-13 修）。

is_whole_disk 认 /dev/disk/by-id/... 链接，但后面的分区名按「盘名 + 1 / p1」推导：旧实现推出
/dev/disk/by-id/virtio-xxx1 这种不存在的路径，分区表已经写完、到格式化这步才失败，
盘上数据没了、系统也没装上。这里截取「确认目标盘」与「确定根分区名」两段实际执行。
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SRC = (Path(__file__).resolve().parents[1] / 'alpine2debian.sh').read_text(encoding='utf-8')
SH = shutil.which('sh') or shutil.which('bash')


@unittest.skipUnless(SH and os.name != 'nt', 'requires POSIX sh and symlinks')
class Alpine2DebianDiskSymlinkTests(unittest.TestCase):
    def test_root_partition_is_derived_from_the_real_device(self):
        check = SRC[SRC.index('is_whole_disk "$DISK" || die'):SRC.index('DISK_SIZE_MB=')]
        part_start = SRC.index('case "$DISK" in\n    *nvme*|*mmcblk*|*loop*) ROOT_PART=')
        naming = SRC[part_start:SRC.index('esac\n', part_start) + 5]
        with tempfile.TemporaryDirectory() as tmp:
            device = Path(tmp) / 'vdb'
            device.write_text('', encoding='utf-8')
            link = Path(tmp) / 'virtio-data'
            link.symlink_to(device)
            script = ('is_whole_disk() { :; }\nok() { :; }\ndie() { echo "DIE $*"; exit 1; }\nDISK="$1"\n'
                      + check + naming + 'printf "%s" "$ROOT_PART"')
            run = subprocess.run([SH, '-c', script, 'sh', str(link)], capture_output=True, text=True,
                                 encoding='utf-8', timeout=20)
            self.assertEqual(run.stdout, str(device.resolve()) + '1')


if __name__ == '__main__':
    unittest.main()
