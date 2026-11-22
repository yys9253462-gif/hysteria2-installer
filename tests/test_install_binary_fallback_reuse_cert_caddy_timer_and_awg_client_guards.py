"""回归测试：install.sh 下载回退防 pipefail 崩溃、复用证书去注释引号、Caddy 域名/清理、续期定时器原子写与 AWG 跳过首客户端。"""
from __future__ import annotations

import os
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


def _to_bash_path(path: Path) -> str:
    s = str(path.resolve())
    if os.name == "nt" and len(s) >= 2 and s[1] == ":":
        return f"/{s[0].lower()}{s[2:].replace(chr(92), '/')}"
    return s.replace("\\", "/")


def _extract_func(src: str, name: str) -> str:
    marker = f"{name}() {{"
    start = src.index(marker)
    end = src.index("\n}\n", start) + 3
    return src[start:end]


@unittest.skipUnless(BASH, "缺少可用 Bash")
class InstallShHardeningBatch57Item10Tests(unittest.TestCase):
    """验证 install.sh 压轴第 10 项的 5 组修复。"""

    def setUp(self) -> None:
        self.src = INSTALL_SH.read_text(encoding="utf-8").replace("\r\n", "\n")
        self.tmp = Path(tempfile.mkdtemp(prefix="hy2-inst10-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

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

    def test_install_binary_fallback_curl_failure_does_not_abort_under_pipefail(self):
        """在 set -eo pipefail 下，GitHub API 与下载站回退均失败时，install_binary 须正常打日志并返回 1 而非中途静默暴毙。"""
        fn_arch = _extract_func(self.src, "hy2_core_asset_arch")
        fn_bin = _extract_func(self.src, "install_binary")
        script = (
            "set -eo pipefail\n"
            "HY2_ARCH=amd64\n"
            "HY2_BIN=/tmp/hy2-fake\n"
            "log_step() { :; }\n"
            "log_info() { :; }\n"
            "log_warn() { echo \"WARN:$*\"; }\n"
            "log_err() { echo \"ERR:$*\"; }\n"
            "curl() { return 6; }\n"
            "jq() { cat >/dev/null; return 0; }\n"
            + fn_arch
            + "\n"
            + fn_bin
            + "\n"
            "install_binary\n"
        )
        res = self._run_bash(script)
        self.assertEqual(res.returncode, 1, f"回退 curl 失败时应走完版本错误分支返回 1，实际 rc={res.returncode}, stdout={res.stdout!r}")
        self.assertIn("ERR:无法确定 Hysteria 2 版本", res.stdout, f"应到达版本获取失败日志，stdout={res.stdout!r}")

    def test_reuse_existing_cert_config_strips_single_quotes_and_inline_comments(self):
        """reuse_existing_cert_config 解析 tls.cert/key 与 acme 域名/邮箱时必须剥离单引号与行尾注释。"""
        fn_reuse = _extract_func(self.src, "reuse_existing_cert_config")
        cert = self.tmp / "fullchain.pem"
        key = self.tmp / "privkey.pem"
        cert.write_text("CERT", encoding="utf-8")
        key.write_text("KEY", encoding="utf-8")
        cfg_tls = self.tmp / "cfg_tls.yaml"
        cfg_tls.write_text(
            f"listen: :443\ntls: # 手工配置\n  cert: '{_to_bash_path(cert)}'  # 叶+链\n  key: '{_to_bash_path(key)}' # 私钥\n",
            encoding="utf-8",
        )
        cfg_acme = self.tmp / "cfg_acme.yaml"
        cfg_acme.write_text(
            "listen: :443\nacme: # 自动签发\n  domains:\n    - 'node.example.com'  # 主域名\n  email: 'admin@example.com'  # 通知邮箱\n",
            encoding="utf-8",
        )

        script_tls = (
            "set -uo pipefail\n"
            f"HY2_CONFIG='{_to_bash_path(cfg_tls)}'\n"
            f"HY2_META_FILE='{_to_bash_path(self.tmp / 'missing.json')}'\n"
            "jq() { return 1; }\n"
            + fn_reuse
            + "\n"
            "reuse_existing_cert_config\n"
            "echo \"CERT=$CERT_FILE|KEY=$KEY_FILE\"\n"
        )
        res_tls = self._run_bash(script_tls)
        self.assertEqual(res_tls.returncode, 0, f"单引号+注释 tls 配置应正常复用，stderr={res_tls.stderr!r}")
        self.assertIn(f"CERT={_to_bash_path(cert)}|KEY={_to_bash_path(key)}", res_tls.stdout)

        script_acme = (
            "set -uo pipefail\n"
            f"HY2_CONFIG='{_to_bash_path(cfg_acme)}'\n"
            f"HY2_META_FILE='{_to_bash_path(self.tmp / 'missing.json')}'\n"
            "SERVER_NAME=''\nACME_EMAIL=''\n"
            "jq() { return 1; }\n"
            + fn_reuse
            + "\n"
            "reuse_existing_cert_config\n"
            "echo \"DOM=$SERVER_NAME|MAIL=$ACME_EMAIL\"\n"
        )
        res_acme = self._run_bash(script_acme)
        self.assertEqual(res_acme.returncode, 0, res_acme.stderr)
        self.assertIn("DOM=node.example.com|MAIL=admin@example.com", res_acme.stdout)

    def test_setup_cert_via_existing_caddy_rejects_leading_hyphen_and_uses_return_trap(self):
        """setup_cert_via_existing_caddy 必须拒绝 '-bad.example.com' 等非法域名并具备 RETURN 清理陷阱。"""
        fn_dom = _extract_func(self.src, "is_valid_domain")
        start = self.src.index("setup_cert_via_existing_caddy() {")
        end = self.src.index("\n# 确保 acme.sh 可用", start)
        fn_caddy = self.src[start:end]
        self.assertIn("trap - RETURN;", fn_caddy, "setup_cert_via_existing_caddy 必须挂 RETURN 临时文件清理陷阱")

        script = (
            "set -uo pipefail\n"
            "log_err() { echo \"ERR:$*\"; }\n"
            "log_step() { :; }\nlog_info() { :; }\nlog_warn() { :; }\n"
            "caddy() { return 0; }\n"
            + fn_dom
            + "\n"
            + fn_caddy
            + "\n"
            "setup_cert_via_existing_caddy '-bad.example.com'\n"
        )
        res = self._run_bash(script)
        self.assertNotEqual(res.returncode, 0, f"前导连字符域名必须被拒绝，stderr={res.stderr!r}")
        self.assertIn("域名格式不合法", res.stdout, f"stdout={res.stdout!r}, stderr={res.stderr!r}")

    def test_hy2_acme_ensure_renew_timer_rejects_malicious_home_and_writes_atomically(self):
        """hy2_acme_ensure_renew_timer 必须拒绝含空白/换行/引号的 home，并使用临时文件原子写入单元。"""
        fn_timer = _extract_func(self.src, "hy2_acme_ensure_renew_timer")
        self.assertIn("mktemp", fn_timer, "应使用 mktemp 原子写入 systemd 单元文件")
        unit_dir = self.tmp / "units"
        unit_dir.mkdir()
        script = (
            "set -uo pipefail\n"
            f"HY2_SYSTEMD_DIR='{_to_bash_path(unit_dir)}'\n"
            "crontab() { return 1; }\n"
            "systemctl() { return 0; }\n"
            + fn_timer
            + "\n"
            "hy2_acme_ensure_renew_timer '/root/bad home'\n"
        )
        res = self._run_bash(script)
        self.assertNotEqual(res.returncode, 0, "含空格的 acme home 必须被拒绝写入 ExecStart")
        self.assertFalse((unit_dir / "hy2-acme-renew.service").exists())

    def test_install_amneziawg_skips_client_arg_when_endpoint_empty_and_validates_client_name(self):
        """install_amneziawg 在 endpoint 为空时不得再追加 --client，且交互输入的非法客户端名必须被拒绝。"""
        fn_awg = _extract_func(self.src, "install_amneziawg")
        self.assertIn('if [[ -n "$endpoint" && "$peer_count" == "0" ]]; then', fn_awg)
        self.assertIn("^[A-Za-z0-9_.-]{1,32}$", fn_awg)


if __name__ == "__main__":
    unittest.main()
