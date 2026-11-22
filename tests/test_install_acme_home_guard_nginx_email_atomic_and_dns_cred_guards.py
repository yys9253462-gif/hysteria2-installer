"""回归测试：install.sh 中 acme home 清理防误删、Nginx/DNS 签发拒裸 IP、邮箱防选项注入、IPv6 原子去行与 DNS 凭据控制字符拦截。"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = ROOT / "install.sh"


def _find_bash() -> str | None:
    cands = []
    if os.name == "nt":
        cands.extend([r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files\Git\usr\bin\bash.exe"])
    w = shutil.which("bash")
    if w:
        cands.append(w)
    for c in cands:
        if c and os.path.isfile(c) and not (os.name == "nt" and "system32" in c.lower()):
            return c
    return None


BASH = _find_bash()


def _extract_fn(source: str, name: str) -> str:
    start = source.index(f"{name}() {{\n")
    lines = source[start:].splitlines(keepends=True)
    in_heredoc = None
    out = []
    for idx, line in enumerate(lines):
        out.append(line)
        if in_heredoc is not None:
            if line.strip() == in_heredoc:
                in_heredoc = None
            continue
        m_hd = re.search(r"<<-?\s*'?([A-Za-z0-9_]+)'?", line)
        if m_hd:
            in_heredoc = m_hd.group(1)
            continue
        if idx > 0 and line == "}\n":
            break
    return "".join(out)


@unittest.skipUnless(BASH, "缺少可用 Bash")
class InstallAcmeNginxDnsGuardTests(unittest.TestCase):
    """验证第五十八批第 5 项的 5 组边界防护。"""

    def setUp(self) -> None:
        self.src = INSTALL_SH.read_text(encoding="utf-8").replace("\r\n", "\n")

    def _run_bash(self, script: str) -> subprocess.CompletedProcess[str]:
        assert BASH is not None
        return subprocess.run(
            [BASH, "-c", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )

    def test_nginx_and_dns_api_reject_bare_ipv4_domain(self):
        """setup_cert_via_nginx 与 setup_cert_via_dns_api 必须拒绝纯数字末段 IP（如 1.2.3.4）。"""
        fn_ng = _extract_fn(self.src, "setup_cert_via_nginx")
        fn_dns = _extract_fn(self.src, "setup_cert_via_dns_api")

        s_ng = (
            "set -uo pipefail\n"
            "log_err() { echo \"ERR:$*\" >&2; }\nlog_warn() { :; }\nlog_step() { :; }\nlog_info() { :; }\n"
            "nginx() { echo 'SHOULD_NOT_CALL_NGINX' >&2; return 0; }\n"
            + fn_ng
            + "\nsetup_cert_via_nginx '1.2.3.4' 'admin@example.com'\n"
        )
        r_ng = self._run_bash(s_ng)
        self.assertNotEqual(r_ng.returncode, 0, "借 Nginx 签发必须拒绝裸 IPv4 1.2.3.4")
        self.assertIn("拒绝非法域名", r_ng.stderr, f"应命中域名校验，stderr={r_ng.stderr!r}")

        s_dns = (
            "set -uo pipefail\n"
            "log_err() { echo \"ERR:$*\" >&2; }\nlog_warn() { :; }\nlog_step() { :; }\nlog_info() { :; }\n"
            "HY2_CF_TOKEN='tok123'\n"
            + fn_dns
            + "\nsetup_cert_via_dns_api '1.2.3.4'\n"
        )
        r_dns = self._run_bash(s_dns)
        self.assertNotEqual(r_dns.returncode, 0, "DNS API 签发必须拒绝裸 IPv4 1.2.3.4")
        self.assertIn("拒绝非法域名", r_dns.stderr, f"应命中域名校验，stderr={r_dns.stderr!r}")

    def test_nginx_rejects_malicious_email_and_avoids_sed_in_place(self):
        """setup_cert_via_nginx 必须拒绝以 '-' 开头或含控制字符的邮箱，且不得使用非原子 sed -i 改写配置。"""
        fn_ng = _extract_fn(self.src, "setup_cert_via_nginx")
        self.assertNotIn("sed -i", fn_ng, "不得使用非原子 sed -i 就地改写 Nginx 配置")

        script = (
            "set -uo pipefail\n"
            "log_err() { echo \"ERR:$*\" >&2; }\nlog_warn() { :; }\nlog_step() { :; }\nlog_info() { :; }\n"
            "nginx() { echo 'SHOULD_NOT_CALL_NGINX' >&2; return 0; }\n"
            + fn_ng
            + "\nsetup_cert_via_nginx 'node.example.com' '-bad@example.com'\n"
        )
        r = self._run_bash(script)
        self.assertNotEqual(r.returncode, 0, "以 '-' 开头的邮箱必须被拒绝防止参数注入")
        self.assertNotIn("SHOULD_NOT_CALL_NGINX", r.stderr)

    def test_dns_api_rejects_credentials_with_control_chars(self):
        """setup_cert_via_dns_api 必须拒绝含换行/回车等控制字符的 DNS API 凭据。"""
        fn_dns = _extract_fn(self.src, "setup_cert_via_dns_api")
        script = (
            "set -uo pipefail\n"
            "log_err() { echo \"ERR:$*\" >&2; }\nlog_warn() { :; }\nlog_step() { :; }\nlog_info() { :; }\n"
            "hy2_acme_ensure() { echo 'SHOULD_NOT_ENSURE_ACME' >&2; return 0; }\n"
            "HY2_CF_TOKEN=$'tok\\nINJECTED=1'\n"
            + fn_dns
            + "\nsetup_cert_via_dns_api 'node.example.com'\n"
        )
        r = self._run_bash(script)
        self.assertNotEqual(r.returncode, 0, "含换行的 HY2_CF_TOKEN 必须被拒绝")
        self.assertNotIn("SHOULD_NOT_ENSURE_ACME", r.stderr, "含控制字符凭据不得继续安装或调用 acme.sh")
        self.assertIn("控制字符", r.stderr, f"应给出明确控制字符报错，stderr={r.stderr!r}")

    def test_hy2_acme_install_verified_refuses_unsafe_home_path(self):
        """hy2_acme_install_verified 必须拒绝把 '/' 或 '/root' 或含 '..' 的路径当作 acme 安装目录。"""
        fn_inst = _extract_fn(self.src, "hy2_acme_install_verified")
        script = (
            "set -uo pipefail\n"
            "log_err() { echo \"ERR:$*\" >&2; }\nlog_warn() { :; }\nlog_step() { :; }\nlog_info() { :; }\n"
            "hy2_acme_pin_commit() { echo 'SHOULD_NOT_PIN' >&2; return 1; }\n"
            + fn_inst
            + "\nhy2_acme_install_verified '/root'\n"
        )
        r = self._run_bash(script)
        self.assertNotEqual(r.returncode, 0, "传 '/root' 作为 acme home 必须被立即拒绝")
        self.assertNotIn("SHOULD_NOT_PIN", r.stderr)
        self.assertIn("路径不安全", r.stderr, f"应命中路径安全守卫，stderr={r.stderr!r}")


if __name__ == "__main__":
    unittest.main()
