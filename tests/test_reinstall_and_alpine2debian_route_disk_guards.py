import os
import shutil
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RD13 = REPO / 'reinstall-debian13.sh'
A2D = REPO / 'alpine2debian.sh'


def _find_bash():
    for cand in (r'C:\Program Files\Git\bin\bash.exe', shutil.which('bash')):
        if cand and os.path.isfile(cand):
            return cand
    return None


class TestReinstallAndAlpine2DebianRouteDiskGuards(unittest.TestCase):
    def test_both_scripts_parse_default_route_by_dev_and_via_keywords(self):
        """reinstall-debian13.sh 与 alpine2debian.sh 均须按 dev/via 关键字提取网卡与网关，不得硬编码 $5/$3。"""
        for path in (RD13, A2D):
            src = path.read_text(encoding='utf-8')
            self.assertNotIn("awk '{print $5}'", src, f'{path.name} 仍在硬编码 $5 提取默认路由网卡')
            self.assertNotIn("awk '/default/{print $3}'", src, f'{path.name} 仍在硬编码 $3 提取默认网关')
            self.assertIn('$i=="dev"', src.replace(' ', ''), f'{path.name} 应按 dev 关键字提取默认路由网卡')
            self.assertIn('$i=="via"', src.replace(' ', ''), f'{path.name} 应按 via 关键字提取默认路由网关')

    def test_both_scripts_guard_disk_sectors_before_arithmetic(self):
        """读取 /sys/block/.../size 计算 DISK_SIZE_MB 前必须做纯数字校验防空串算术崩溃。"""
        for path in (RD13, A2D):
            src = path.read_text(encoding='utf-8')
            self.assertIn('_raw_sectors', src, f'{path.name} 计算 DISK_SIZE_MB 前未先清洗扇区数')

    def test_alpine2debian_nvme_glob_and_safe_dd_and_reinstall_download_guards(self):
        """alpine2debian.sh 须覆盖 nvme0n1、跳过 '*' 网卡通配且安全传参给 dd；reinstall-debian13.sh 须限下载大小并私有写盘。"""
        a2d = A2D.read_text(encoding='utf-8')
        rd13 = RD13.read_text(encoding='utf-8')

        self.assertIn('/dev/nvme0n1', a2d)
        self.assertIn('[ "$ifc" = "*" ]', a2d)
        self.assertNotIn("of='$DISK'", a2d)

        self.assertIn('--max-filesize', rd13)
        self.assertIn('umask 077', rd13.split('download_installnet()')[1].split('info "下载 InstallNET.sh"')[0])

    @unittest.skipUnless(_find_bash(), '需要 bash')
    def test_route_parser_handles_proto_static_before_via_and_dev(self):
        """模拟带 proto static 的路由输出，验证关键字提取拿到正确网关与网卡。"""
        bash = _find_bash()
        rd13 = RD13.read_text(encoding='utf-8')
        # 从脚本中抽出解析 MAIN_IFACE / MAIN_GATE 两行并用桩 ip 运行
        iface_line = next(ln for ln in rd13.splitlines() if ln.startswith('MAIN_IFACE='))
        gate_line = next(ln for ln in rd13.splitlines() if ln.startswith('MAIN_GATE='))
        script = f"""
ip() {{
    echo "default proto static via 10.0.0.1 dev ens3 metric 100"
}}
{iface_line}
{gate_line}
printf 'IFACE=%s GATE=%s\\n' "$MAIN_IFACE" "$MAIN_GATE"
"""
        r = subprocess.run([bash, '-c', script], capture_output=True, text=True, encoding='utf-8', timeout=10)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), 'IFACE=ens3 GATE=10.0.0.1')


if __name__ == '__main__':
    unittest.main()
