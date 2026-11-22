"""回归测试：迁移证书空公钥 SHA256 阻断、系统防火墙前导零端口拦截、WARP/GOST 下载体积上限与私密临时目录。"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def _find_bash():
    for cand in (r'C:\Program Files\Git\bin\bash.exe', shutil.which('bash')):
        if cand and os.path.isfile(cand):
            return cand
    return None


BASH = _find_bash()


def _extract_fn(name):
    m = re.search(rf'^{re.escape(name)}\(\)\s*\{{.*?^\}}', INSTALL_SRC, re.M | re.S)
    if not m:
        raise AssertionError(f'install.sh 中未找到函数 {name}')
    return m.group(0)


class InstallMigrationCertFwLeadingZeroAndWarpGostBoundsGuardsTests(unittest.TestCase):
    @unittest.skipUnless(BASH, 'requires bash')
    def test_migration_cert_rejects_empty_pubkey_instead_of_matching_empty_sha256(self):
        """setup_certificates 迁移复用路径当 openssl 输出空公钥时，不得因空 SHA256 相等而假匹配通过。"""
        fn_body = _extract_fn('setup_certificates')
        with tempfile.TemporaryDirectory() as td:
            c = Path(td) / 'cert.pem'
            k = Path(td) / 'key.pem'
            c.write_text('dummy-cert', encoding='utf-8')
            k.write_text('dummy-key', encoding='utf-8')
            script = f'''set -u
HY2_CERT_DIR="{Path(td).as_posix()}/certs"
HY2_CUSTOM_CERT_FILE="{c.as_posix()}"
HY2_CUSTOM_KEY_FILE="{k.as_posix()}"
PUBLIC_IP="1.2.3.4"
log_err() {{ echo "ERR: $*" >&2; }}
log_info() {{ :; }}
openssl() {{
    # 校验通过但提取公钥输出空串（模拟异常或失败管道）
    return 0
}}
{fn_body}
if setup_certificates; then
    echo "FALSE_MATCH"
    exit 1
fi
echo "REJECTED_EMPTY_PUB=1"
'''
            proc = subprocess.run([BASH, '-s'], input=script, capture_output=True, text=True, encoding='utf-8', timeout=20)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn('REJECTED_EMPTY_PUB=1', proc.stdout)

    @unittest.skipUnless(BASH, 'requires bash')
    def test_setup_system_firewall_rejects_leading_zero_ports(self):
        """setup_system_firewall 须拒绝前导零端口（如 08443），防止传入 ufw/firewalld/nft 异常。"""
        fn_body = _extract_fn('setup_system_firewall')
        script = f'''set -u
HY2_SUB_PORT="0443"
CERT_TYPE="self_signed"
log_err() {{ echo "ERR: $*"; }}
log_step() {{ :; }}
log_info() {{ :; }}
{fn_body}
if setup_system_firewall 08443 "" ""; then
    echo "ACCEPTED_LEADING_ZERO"
    exit 1
fi
HY2_SUB_PORT="8443"
if setup_system_firewall 8443 020000 30000; then
    echo "ACCEPTED_LEADING_ZERO_HOP"
    exit 1
fi
echo "REJECTED_LEADING_ZERO=1"
'''
            # 注：不需要真正动系统防火墙，应在入口校验即 return 1
        proc = subprocess.run([BASH, '-s'], input=script, capture_output=True, text=True, encoding='utf-8', timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('REJECTED_LEADING_ZERO=1', proc.stdout)

    def test_warp_and_gost_installers_bound_curl_and_use_umask_077_tmpdirs(self):
        """install_warp_local_proxy 与 install_gost 的下载须带 --max-filesize 且临时目录用 umask 077。"""
        warp = _extract_fn('install_warp_local_proxy')
        gost = _extract_fn('install_gost')
        self.assertGreaterEqual(warp.count('--max-filesize'), 4)
        self.assertNotIn('TMP_DIR="$(mktemp -d)"', warp)
        self.assertGreaterEqual(gost.count('--max-filesize'), 2)
        self.assertNotIn('TMP_DIR=$(mktemp -d)', gost)


if __name__ == '__main__':
    unittest.main()
