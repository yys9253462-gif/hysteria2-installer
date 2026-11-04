"""WARP 安装中途失败后，完整卸载仍清掉本工具下载的 wgcf / wireproxy（2026-11-04 修）。

所有权标记在 wgcf 注册之前就写了；注册失败时 wireproxy.service 还没写，旧卸载条件要求
二者同时存在，二进制与账户文件永久残留。摘出 uninstall_all 里真实的 WARP 判定段执行。
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def block():
    body = re.search(r'^uninstall_all\(\) \{\n.*?^\}', SRC, re.S | re.M).group(0)
    start = body.index('        local managed_wireproxy=0\n')
    end = body.index('        if [[ "$managed_wireproxy" == 1 ]]; then', start)
    return body[start:end]


@unittest.skipUnless(BASH, 'requires bash')
class WarpHalfInstallUninstallTests(unittest.TestCase):
    def run_block(self, with_unit):
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            for d in ('hy', 'bin', 'units', 'wg'):
                (t / d).mkdir()
            (t / 'hy' / '.hy2-warp-owned').write_text('')
            for b in ('wireproxy', 'wgcf'):
                (t / 'bin' / b).write_text('x')
            if with_unit:
                (t / 'units' / 'wireproxy.service').write_text(
                    'ExecStart=/usr/local/bin/wireproxy -c /etc/wireguard/wp.conf\n')
            code = (block().replace('/usr/local/bin', str(t / 'bin'))
                    .replace('/etc/systemd/system', str(t / 'units'))
                    .replace('/etc/wireguard', str(t / 'wg'))
                    .replace('ExecStart=%s/wireproxy -c %s/wp.conf' % (t / 'bin', t / 'wg'),
                             'ExecStart=/usr/local/bin/wireproxy -c /etc/wireguard/wp.conf'))
            script = 'HY2_DIR=%s\nsystemctl() { :; }\nf() {\n%s\necho "M=$managed_wireproxy"\n}\nf' % (t / 'hy', code)
            out = subprocess.run([BASH, '-c', script], capture_output=True, text=True, timeout=20).stdout
            left = sorted(p.name for p in (t / 'bin').iterdir())
        return out, left

    def test_half_install_binaries_are_removed(self):
        out, left = self.run_block(with_unit=False)
        self.assertIn('M=1', out)
        self.assertEqual(left, [])

    def test_full_install_still_removed(self):
        out, left = self.run_block(with_unit=True)
        self.assertIn('M=1', out)
        self.assertEqual(left, [])


if __name__ == '__main__':
    unittest.main()
