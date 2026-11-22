"""回归测试：install.sh 的 Nginx/DNS 证书域名注入校验、非空落地校验、自愈脚本原子替换与 systemd 清理陷阱。"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = (ROOT / 'install.sh').read_text(encoding='utf-8')


def _find_bash():
    for cand in (r'C:\Program Files\Git\bin\bash.exe', '/bin/bash', '/usr/bin/bash'):
        if Path(cand).is_file():
            return cand
    return shutil.which('bash')


BASH = _find_bash()


def _extract_fn(name):
    if name == 'setup_cert_via_nginx':
        m = re.search(r'^setup_cert_via_nginx\(\)\s*\{.*?\n    return 0\n\}', INSTALL_SH, re.M | re.S)
    else:
        m = re.search(rf'^{re.escape(name)}\(\)\s*\{{.*?^\}}', INSTALL_SH, re.M | re.S)
    if not m:
        raise AssertionError(f'install.sh 中未找到函数 {name}()')
    return m.group(0)


def _run_bash(script):
    env = os.environ.copy()
    if os.name == 'nt':
        env['PATH'] = r'C:\Program Files\Git\bin;C:\Program Files\Git\usr\bin;' + env.get('PATH', '')
    return subprocess.run(
        [BASH, '-s'],
        input=script,
        capture_output=True,
        text=True,
        encoding='utf-8',
        timeout=30,
        env=env,
    )


class InstallCertNginxDnsSelfhealAndSystemdGuardsTests(unittest.TestCase):
    @unittest.skipUnless(BASH, 'requires bash')
    def test_setup_cert_via_nginx_and_dns_reject_malicious_domain_names(self):
        """setup_cert_via_nginx 与 setup_cert_via_dns_api 必须在碰文件/acme.sh 前拦截非法域名防路径穿越与配置注入。"""
        fn_nginx = _extract_fn('setup_cert_via_nginx')
        fn_dns = _extract_fn('setup_cert_via_dns_api')
        script = f'''set -uo pipefail
log_info() {{ :; }}; log_warn() {{ echo "WARN:$*" >&2; }}; log_err() {{ echo "ERR:$*" >&2; }}
port_owner() {{ echo "nginx"; }}
hy2_acme_ensure() {{ echo "UNEXPECTED_ACME" >&2; return 0; }}
{fn_nginx}
{fn_dns}
if (setup_cert_via_nginx "../../etc/evil;bad" "a@example.com") >/dev/null 2>&1; then
  echo "NGINX_ACCEPTED_BAD"
  exit 1
fi
HY2_CF_TOKEN="tok"
if (setup_cert_via_dns_api "../bad domain") >/dev/null 2>&1; then
  echo "DNS_ACCEPTED_BAD"
  exit 1
fi
echo "BOTH_REJECTED"
'''
        proc = _run_bash(script)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('BOTH_REJECTED', proc.stdout)
        self.assertNotIn('UNEXPECTED_ACME', proc.stderr, '非法域名不得走到 hy2_acme_ensure')

    def test_setup_cert_via_nginx_checks_installed_cert_nonempty_and_cleans_tmp(self):
        """setup_cert_via_nginx 必须校验落地证书非空并在失败时回滚，且注册 RETURN 清理临时配置。"""
        body = _extract_fn('setup_cert_via_nginx')
        self.assertRegex(body, r"trap\s+'.*'\s+RETURN", 'setup_cert_via_nginx 应注册 RETURN 清理临时文件')
        self.assertIn('[[ ! -s "$out_cert" || ! -s "$out_key" ]]', body,
                      'setup_cert_via_nginx 在 acme.sh --install-cert 后必须校验目标证书与私钥非空')

    def test_setup_cert_selfheal_writes_script_atomically_and_registers_return_cleanup(self):
        """setup_cert_selfheal 写入 hy2-cert-selfheal.sh 必须走同目录临时文件原子替换，不得直接重定向截断。"""
        body = _extract_fn('setup_cert_selfheal')
        self.assertNotIn('cat > /usr/local/bin/hy2-cert-selfheal.sh', body,
                         '不得直接重定向覆写正在被 timer 调用的 hy2-cert-selfheal.sh')
        self.assertIn('mv -f "$_sh_script_tmp" /usr/local/bin/hy2-cert-selfheal.sh', body)
        self.assertRegex(body, r"trap\s+'.*'\s+RETURN", 'setup_cert_selfheal 必须注册 RETURN 清理所有临时单元文件')

    def test_setup_systemd_rejects_symlink_sysctl_and_registers_return_cleanup(self):
        """setup_systemd 须拒绝符号链接 99-hysteria2.conf，使用 umask 077 暂存并挂 RETURN 清理。"""
        body = _extract_fn('setup_systemd')
        self.assertIn('[[ -L /etc/sysctl.d/99-hysteria2.conf ]]', body,
                      'setup_systemd 必须拒绝向符号链接 /etc/sysctl.d/99-hysteria2.conf 写配置')
        self.assertRegex(body, r"trap\s+'.*'\s+RETURN", 'setup_systemd 必须注册 RETURN 清理临时文件')

    def test_enabled_protocol_ports_validates_port_range(self):
        """enabled_protocol_ports 对 Xray/AnyTLS/TUIC/代理与 AWG 端口均须校验合法范围 1-65535。"""
        body = _extract_fn('enabled_protocol_ports')
        self.assertIn('<= 65535', body)
        self.assertIn('^[1-9][0-9]{0,4}$', body)


if __name__ == '__main__':
    unittest.main()
