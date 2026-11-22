"""回归测试：证书公私钥防空输入 SHA256 假匹配、Web 证书扫描防词分割/路径穿越、门户整包安全落盘与备份防符号链接。"""

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


class InstallCertKeyEmptyShaWebserverGlobAndBundleGuardsTests(unittest.TestCase):
    @unittest.skipUnless(BASH, 'requires bash')
    def test_cert_key_usable_rejects_empty_pubkey_instead_of_matching_empty_sha256(self):
        """当 openssl x509 -pubkey 与 pkey -pubout 均失败输出空串时，_cert_key_usable 必须返回失败而非空 SHA256 假匹配。"""
        fn = _extract_fn('_cert_key_usable')
        script = f'''set -uo pipefail
openssl() {{
    if [[ "$1" == "x509" && "$*" == *"-checkend"* ]]; then
        return 0
    fi
    if [[ "$1" == "x509" && "$*" == *"-pubkey"* ]]; then
        return 1
    fi
    if [[ "$1" == "pkey" && "$*" == *"-pubout"* ]]; then
        return 1
    fi
    if [[ "$1" == "sha256" ]]; then
        echo "(stdin)= e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        return 0
    fi
    return 1
}}
{fn}
if _cert_key_usable /tmp/fake.crt /tmp/fake.key; then
    echo "FALSE_POSITIVE"
    exit 1
fi
echo "REJECTED_OK"
'''
        res = subprocess.run([BASH, '-s'], input=script, capture_output=True, text=True, encoding='utf-8', timeout=15)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn('REJECTED_OK', res.stdout)

    def test_find_cert_in_webserver_validates_domain_and_avoids_word_splitting(self):
        """find_cert_in_webserver 须拦截非法/穿越域名，并改用 while IFS= read -r 避免路径词分割与通配展开。"""
        fn = _extract_fn('find_cert_in_webserver')
        self.assertNotIn('for c in $(_nginx_cert_candidates)', fn)
        self.assertIn('while IFS= read -r c; do', fn)
        self.assertIn('[[ "$domain" =~ ^([a-zA-Z0-9]', fn)

    def test_portal_ensure_py_and_backup_reconfigure_hardening(self):
        """portal_ensure_py 须对 stage 设 umask 077、挂 RETURN 清理与父目录 fsync；备份轮转须拒符号链接。"""
        ens = _extract_fn('portal_ensure_py')
        self.assertIn('umask 077; mktemp -d "${dest_dir}/.portal-bundle-XXXXXX"', ens)
        self.assertIn('RETURN', ens)
        self.assertIn('os.fsync', ens)

        bak = _extract_fn('backup_state_before_reconfigure')
        self.assertIn('! -L "$_old"', bak)


if __name__ == '__main__':
    unittest.main()
