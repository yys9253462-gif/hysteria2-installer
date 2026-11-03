"""wireproxy 配置要带上 wgcf 下发的 IPv6 地址与 ::/0（2026-11-03 修）。

旧配置写死 Address = 172.16.0.2/32、AllowedIPs = 0.0.0.0/0：走 WARP 的域名一旦
解析到 IPv6 就连不上。SE 上用真 wgcf 2.2.29 + wireproxy 1.0.9 实测：旧配置
访问 ipv6.icanhazip.com 失败，双栈配置返回 WARP 的 IPv6 出口。
这里执行 install.sh 与门户网页安装脚本里生成 wp.conf 的那一段。
"""
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
BASH = shutil.which('bash')
INSTALL = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')
PORTAL = (ROOT / 'portal.py').read_text(encoding='utf-8').replace('\r\n', '\n')

PROFILE = """[Interface]
PrivateKey = cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MDA=
Address = 172.16.0.2/32, 2606:4700:110:8ccb:b874:3f07:779:12e2/128
DNS = 1.1.1.1
MTU = 1280
[Peer]
PublicKey = bmotDqhyzQIHWaEFEvzKfmb5TG93/eY8L1uZzvVe1JQ=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:2408
"""


def bash_path(path):
    cygpath = shutil.which('cygpath')
    if cygpath:
        return subprocess.run([cygpath, '-u', str(path)], capture_output=True, text=True).stdout.strip()
    return Path(path).as_posix()


@unittest.skipUnless(BASH, 'requires bash')
class WireproxyDualStackTests(unittest.TestCase):
    def render(self, snippet, extra=''):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / 'wgcf.conf').write_text(PROFILE, encoding='utf-8', newline='\r\n')
            script = 'WGCF_CONF="%s"\nWP_CFG="%s"\nWARP_SOCKS_PORT=40000\nWARP_SOCKS_ADDR=127.0.0.1:40000\n%s\n%s\n' % (
                bash_path(td / 'wgcf.conf'), bash_path(td / 'wp.conf'), extra, snippet)
            subprocess.run([BASH, '-c', script], capture_output=True, text=True, timeout=20)
            return (td / 'wp.conf').read_text(encoding='utf-8')

    def check(self, conf):
        self.assertIn('Address = 172.16.0.2/32, 2606:4700:110:8ccb:b874:3f07:779:12e2/128\n', conf)
        self.assertIn('AllowedIPs = 0.0.0.0/0, ::/0\n', conf)
        self.assertNotIn('\r', conf)

    def test_install_sh(self):
        m = re.search(r'\n(    WG_PRIV=\$\(awk .*?\n    cat > "\$WP_CFG" <<EOF\n.*?\nEOF\n)', INSTALL, re.S)
        self.check(self.render(m.group(1)))

    def test_portal_web_install(self):
        m = re.search(r'\n(WG_PRIV=\$\(awk .*?\ncat > "\$WP_CFG" <<WPEOF\n.*?\nWPEOF\n)', PORTAL, re.S)
        snippet = m.group(1).replace('    exit 1\n', '    exit 1\n')
        self.check(self.render(snippet))


if __name__ == '__main__':
    unittest.main()
