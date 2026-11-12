"""reinstall-debian13.sh 装到的必须是体检、确认过的那块盘（2026-11-13 修）。

旧实现调用 InstallNET 时不传 -setdisk，由它自己挑盘：优先根分区所在盘，救援环境里退到「第一块
有容量的盘」，只排除带 iso9660 签名的；多块盘又有 LVM 时对 debian 还会改成所有磁盘一起分区。
用户按提示用 --disk /dev/vdb 避开救援盘，被清空的却可能是 vda。另外 --disk 给的是
/dev/disk/by-id/... 链接时，「正被挂载」的检查拿链接去对 /proc/mounts，永远对不上。
整个脚本要 root、真块设备与网络；这里截取相应片段实际执行。
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SRC = (Path(__file__).resolve().parents[1] / 'reinstall-debian13.sh').read_text(encoding='utf-8')
SH = shutil.which('sh') or shutil.which('bash')


def run_sh(script, *args):
    return subprocess.run([SH, '-c', script, 'sh', *args], capture_output=True, text=True,
                          encoding='utf-8', timeout=20)


@unittest.skipUnless(SH, 'requires sh')
class ReinstallTargetDiskTests(unittest.TestCase):
    def test_installnet_is_told_which_disk_to_install_on(self):
        start = SRC.index('# 组装参数')
        end = SRC.index('set -- "$@" --cloudkernel 0 --bbr --motd')
        script = ('info() { :; }\nRELEASE=13 PORT=22 PASSWORD=p MIRROR=m SWAP_MB=512 NET_MODE=dhcp DISK=/dev/vdb\n'
                  + SRC[start:end] + '\nprintf "%s\\n" "$@"')
        args = run_sh(script).stdout.split('\n')
        self.assertIn('-setdisk', args, 'InstallNET 会自己挑盘，可能不是体检过的 /dev/vdb')
        self.assertEqual(args[args.index('-setdisk') + 1], '/dev/vdb')

    @unittest.skipIf(os.name == 'nt', 'requires POSIX symlinks')
    def test_a_disk_symlink_is_resolved_before_the_rescue_disk_checks(self):
        start = SRC.index('is_whole_disk "$DISK" || die')
        end = SRC.index('DISK_SIZE_MB=', start)
        with tempfile.TemporaryDirectory() as tmp:
            device = Path(tmp) / 'vdb'
            device.write_text('', encoding='utf-8')
            link = Path(tmp) / 'virtio-data'
            link.symlink_to(device)
            script = ('is_whole_disk() { :; }\ndie() { echo "DIE $*"; exit 1; }\nDISK="$1"\n'
                      + SRC[start:end] + '\nprintf "%s" "$DISK"')
            out = run_sh(script, str(link)).stdout
            self.assertEqual(out, str(device.resolve()))


if __name__ == '__main__':
    unittest.main()
