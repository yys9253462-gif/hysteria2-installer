"""网页「安装 WARP」与 install.sh 用同一套 wireproxy 归属规则（2026-11-03）。

旧版网页脚本既不查也不写 /etc/hysteria/.hy2-warp-owned：
  * 机器上已有别人的 wireproxy 时，直接覆盖它的 unit 与 wp.conf；
  * install.sh 卸载只认这个标记，网页装的 WARP 卸载后仍在跑、开机自启，
    wp.conf 里的私钥也留在盘上。

这里只执行脚本开头的环境检查与归属检查（到写标记为止），路径全部重定向到临时目录，
不下载、不安装、不碰 systemd。
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'portal.py').read_text(encoding='utf-8')
HEADER = '# wireproxy config (managed by hysteria2-installer, do not edit)\n'
UNIT = 'ExecStart=/usr/local/bin/wireproxy -c /etc/wireguard/wp.conf\n'


def guard_section(root):
    script = SOURCE[SOURCE.index("install_warp_sh = r'''") + len("install_warp_sh = r'''"):]
    script = script[:script.index("\n'''")]
    # 守卫段到 claim_warp_assets 定义结束为止；最后补一次调用，代表「真正开始写资产」。
    end = script.index('claim_warp_assets() {')
    end = script.index('\n}\n', end) + 3
    section = script[:end] + 'claim_warp_assets\n'
    for real in ('/usr/local/bin', '/etc/wireguard', '/etc/hysteria', '/etc/systemd/system'):
        section = section.replace(real, str(root) + real)
    return section


@unittest.skipUnless(shutil.which('bash') and shutil.which('curl'), 'needs bash + curl')
class WebWarpOwnershipTests(unittest.TestCase):
    def run_guard(self, setup):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for sub in ('usr/local/bin', 'etc/wireguard', 'etc/hysteria', 'etc/systemd/system'):
                (root / sub).mkdir(parents=True)
            setup(root)
            result = subprocess.run(['bash', '-c', guard_section(root) + '\necho GUARD-PASSED'],
                                    capture_output=True, text=True, timeout=30)
            marker = (root / 'etc/hysteria/.hy2-warp-owned').exists()
            return result, marker

    def test_foreign_wireproxy_is_left_alone(self):
        def setup(root):
            (root / 'usr/local/bin/wireproxy').write_text('someone else')
            (root / 'etc/systemd/system/wireproxy.service').write_text('ExecStart=/opt/x\n')
        result, marker = self.run_guard(setup)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('归属无法确认', result.stderr)
        self.assertNotIn('GUARD-PASSED', result.stdout)
        self.assertFalse(marker)

    def test_marker_is_not_written_before_any_asset(self):
        """下载失败退出时不能留下归属标记（2026-11-04 修）。

        旧实现在下载前就落标记：失败后机主自己装的 wireproxy 会被下次网页安装覆盖、
        被卸载当成本项目的删掉。这里只跑到守卫结束（不调用 claim_warp_assets）就退出。
        """
        script = SOURCE[SOURCE.index("install_warp_sh = r'''") + len("install_warp_sh = r'''"):]
        script = script[:script.index("\n'''")]
        guard_only = script[:script.index('claim_warp_assets() {')]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for sub in ('usr/local/bin', 'etc/wireguard', 'etc/hysteria', 'etc/systemd/system'):
                (root / sub).mkdir(parents=True)
            for real in ('/usr/local/bin', '/etc/wireguard', '/etc/hysteria', '/etc/systemd/system'):
                guard_only = guard_only.replace(real, str(root) + real)
            subprocess.run(['bash', '-c', guard_only + '\nexit 1'], capture_output=True, text=True, timeout=30)
            self.assertFalse((root / 'etc/hysteria/.hy2-warp-owned').exists(),
                             '还没写任何资产就落下了归属标记')

    def test_fresh_install_writes_the_ownership_marker(self):
        result, marker = self.run_guard(lambda root: None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(marker, '网页安装后卸载认不出这是本项目的 WARP')

    def test_older_project_install_is_adopted(self):
        def setup(root):
            (root / 'etc/wireguard/wp.conf').write_text(HEADER + '[Interface]\n')
            (root / 'etc/systemd/system/wireproxy.service').write_text(
                UNIT.replace('/usr/local/bin', str(root) + '/usr/local/bin')
                    .replace('/etc/wireguard', str(root) + '/etc/wireguard'))
            (root / 'usr/local/bin/wireproxy').write_text('ours')
        result, marker = self.run_guard(setup)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(marker)

    def test_uninstall_recognises_what_the_web_install_writes(self):
        """网页脚本写出的 unit 与 wp.conf 必须带卸载认的那两行。"""
        script = SOURCE[SOURCE.index("install_warp_sh = r'''"):]
        self.assertIn(HEADER.strip(), script)
        self.assertIn(UNIT.strip(), script)
        install = (ROOT / 'install.sh').read_text(encoding='utf-8')
        self.assertIn('.hy2-warp-owned', re.search(r'^uninstall_all\(\) \{.*?^\}', install, re.M | re.S).group(0))


if __name__ == '__main__':
    unittest.main()
