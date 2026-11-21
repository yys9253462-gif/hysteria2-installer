"""回归测试：DNS API 签发兼容 acme.sh 退出码 2（仍有效跳过）、HY2_CF_KEY 缺邮箱明确报错及 awg_ensure_ctl 原子替换。"""

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / 'install.sh'
BASH = shutil.which('bash')


def _extract_fn(source: str, name: str) -> str:
    match = re.search(rf'^{name}\(\) \{{\n.*?^\}}', source, re.S | re.M)
    if not match:
        raise AssertionError(f'install.sh 中未找到函数 {name}')
    return match.group(0)


@unittest.skipUnless(BASH, '需要 bash 环境')
class DnsApiSkipRcAndAwgCtlAtomicTests(unittest.TestCase):
    def test_dns_api_accepts_acme_exit_code_2_when_cert_is_still_valid(self):
        """重装/重配时 acme.sh --issue 返回 2（未到期跳过），setup_cert_via_dns_api 必须按成功继续安装证书。"""
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        fn = _extract_fn(src, 'setup_cert_via_dns_api')
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            acme_dir = root / '.acme.sh'
            ecc_dir = acme_dir / 'node.example.com_ecc'
            cert_dir = root / 'cert'
            ecc_dir.mkdir(parents=True)
            cert_dir.mkdir(parents=True)
            (ecc_dir / 'fullchain.cer').write_text('CERT', encoding='utf-8')
            (ecc_dir / 'node.example.com.key').write_text('KEY', encoding='utf-8')
            fake_acme = acme_dir / 'acme.sh'
            fake_acme.write_text(
                '#!/usr/bin/env bash\n'
                'if [[ "$1" == "--issue" ]]; then exit 2; fi\n'
                'if [[ "$1" == "--install-cert" ]]; then\n'
                '  while [[ $# -gt 0 ]]; do\n'
                '    case "$1" in\n'
                '      --fullchain-file) printf CERT > "$2"; shift 2 ;;\n'
                '      --key-file) printf KEY > "$2"; shift 2 ;;\n'
                '      *) shift ;;\n'
                '    esac\n'
                '  done\n'
                '  exit 0\n'
                'fi\n'
                'exit 1\n',
                encoding='utf-8',
                newline='\n',
            )
            fake_acme.chmod(0o755)
            script = '\n'.join([
                'set -uo pipefail',
                f'HOME="{root.as_posix()}"',
                f'HY2_CERT_DIR="{cert_dir.as_posix()}"',
                'HY2_CF_TOKEN="cf-test-token"',
                'unset HY2_CF_KEY HY2_CF_EMAIL HY2_ALICLOUD_KEY HY2_ALICLOUD_SECRET HY2_DP_TOKEN',
                'log_info() { :; }; log_warn() { :; }; log_err() { echo "ERR:$*" >&2; }',
                'hy2_acme_ensure() { return 0; }',
                fn,
                'out="$(setup_cert_via_dns_api node.example.com)"; rc=$?',
                'echo "RC=$rc OUT=$out"',
            ])
            res = subprocess.run([BASH, '-c', script], capture_output=True, text=True,
                                 encoding='utf-8', errors='replace', timeout=20)
            self.assertIn('RC=0', res.stdout, res.stdout + res.stderr)
            self.assertIn('acme-node.example.com.crt|', res.stdout)

    def test_dns_api_reports_missing_cf_email_when_cf_key_is_set(self):
        """设置 HY2_CF_KEY 但缺 HY2_CF_EMAIL 时必须返回 1 并提示缺少 HY2_CF_EMAIL。"""
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        fn = _extract_fn(src, 'setup_cert_via_dns_api')
        script = '\n'.join([
            'set -uo pipefail',
            'HY2_CF_KEY="global-key-only"',
            'unset HY2_CF_TOKEN HY2_CF_EMAIL HY2_ALICLOUD_KEY HY2_ALICLOUD_SECRET HY2_DP_TOKEN',
            'log_info() { :; }; log_warn() { echo "WARN:$*" >&2; }; log_err() { echo "ERR:$*" >&2; }',
            'hy2_acme_ensure() { return 0; }',
            fn,
            'setup_cert_via_dns_api node.example.com >/dev/null; echo "RC=$?"',
        ])
        res = subprocess.run([BASH, '-c', script], capture_output=True, text=True,
                             encoding='utf-8', errors='replace', timeout=20)
        self.assertIn('RC=1', res.stdout, res.stdout + res.stderr)
        self.assertIn('HY2_CF_EMAIL', res.stderr)

    def test_awg_ensure_ctl_replaces_binary_atomically(self):
        """awg_ensure_ctl 落地 hy2-awgctl 必须先写同目录临时文件再 mv -f 原子替换。"""
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        fn = _extract_fn(src, 'awg_ensure_ctl')
        self.assertNotIn('install -m 0755 "$src" "$AWG_CTL_BIN"', fn,
                         'awg_ensure_ctl 不得直接 install 覆写正在运行的 $AWG_CTL_BIN')
        self.assertIn('mv -f', fn)


if __name__ == '__main__':
    unittest.main()
