"""回归测试：panel-join.py 读盘上限/超长数字 DoS/非 ASCII 凭据/脏域名与 fix_cert_chain.sh 注释证书行/前导零端口/SNI 消毒。"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PANEL_JOIN_PATH = ROOT / "panel-join.py"
FIX_CERT_PATH = ROOT / "fix_cert_chain.sh"


def _load_panel_join():
    spec = importlib.util.spec_from_file_location("panel_join_t57_7", PANEL_JOIN_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


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


class PanelJoinHardeningTests(unittest.TestCase):
    """验证 panel-join.py 的读盘上限、超长数字 DoS、非 ASCII 凭据与脏域名拦截。"""

    def test_read_enforces_size_limit(self):
        pj = _load_panel_join()
        with tempfile.TemporaryDirectory(prefix="hy2-pj-size-") as td:
            big = Path(td) / "big.yaml"
            big.write_bytes(b"a" * (4 * 1024 * 1024 + 64))
            self.assertIsNone(pj.read(str(big)), "超过 4 MiB 的配置文件必须被拒读")

    def test_huge_port_digits_do_not_crash_with_int_limit_error(self):
        with tempfile.TemporaryDirectory(prefix="hy2-pj-dos-") as td:
            root = Path(td)
            cfg = root / "config.yaml"
            portal_f = root / "portal.json"
            meta_f = root / "client_meta.json"
            huge = "9" * 5000
            cfg.write_text(f"listen: :{huge}\nmasquerade:\n  type: proxy\n  listenHTTPS: :{huge}\n", encoding="utf-8")
            portal_f.write_text(json.dumps({"api_key": "goodkey", "port": huge}), encoding="utf-8")
            meta_f.write_text(json.dumps({"server_name": "node.example.com", "is_insecure": False}), encoding="utf-8")

            proc = subprocess.run(
                [sys.executable, str(PANEL_JOIN_PATH),
                 "--config", str(cfg), "--portal", str(portal_f), "--meta", str(meta_f)],
                capture_output=True, text=True, encoding="utf-8", timeout=15,
            )
            self.assertEqual(proc.returncode, 3, f"超长数字端口应优雅返回 3 而非崩溃，stderr={proc.stderr!r}")
            self.assertNotIn("Traceback", proc.stderr)

    def test_non_ascii_api_key_and_admin_token_with_space_or_non_ascii_rejected(self):
        with tempfile.TemporaryDirectory(prefix="hy2-pj-ascii-") as td:
            root = Path(td)
            cfg = root / "config.yaml"
            portal_f = root / "portal.json"
            meta_f = root / "client_meta.json"
            cfg.write_text("listen: :443\nmasquerade:\n  type: proxy\n  listenHTTPS: :8443\n", encoding="utf-8")
            meta_f.write_text(json.dumps({"server_name": "node.example.com", "is_insecure": False}), encoding="utf-8")

            # 非 ASCII api_key 必须返回 2
            portal_f.write_text(json.dumps({"api_key": "密钥abc", "port": 18080}), encoding="utf-8")
            p1 = subprocess.run(
                [sys.executable, str(PANEL_JOIN_PATH),
                 "--config", str(cfg), "--portal", str(portal_f), "--meta", str(meta_f)],
                capture_output=True, text=True, encoding="utf-8", timeout=15,
            )
            self.assertEqual(p1.returncode, 2, f"非 ASCII api_key 必须被拒，out={p1.stdout!r}, err={p1.stderr!r}")

            # 含空格或非 ASCII 的 admin-token 必须返回 2，不得进入 HTTP 请求层
            portal_f.write_text(json.dumps({"api_key": "goodkey", "port": 18080}), encoding="utf-8")
            for bad_tok in ("jwt with space", "中文token"):
                p2 = subprocess.run(
                    [sys.executable, str(PANEL_JOIN_PATH),
                     "--config", str(cfg), "--portal", str(portal_f), "--meta", str(meta_f),
                     "--register", "--panel", "https://panel.example.com", "--admin-token", bad_tok],
                    capture_output=True, text=True, encoding="utf-8", timeout=15,
                )
                self.assertEqual(p2.returncode, 2, f"非法 admin-token {bad_tok!r} 必须返回 2，stderr={p2.stderr!r}")

    def test_safe_host_and_acme_first_domain_reject_overlong_and_dotdot_hosts(self):
        pj = _load_panel_join()
        self.assertEqual(pj._safe_host(".."), "")
        self.assertEqual(pj._safe_host("-bad.example.com"), "")
        self.assertEqual(pj._safe_host("a" * 260 + ".com"), "")
        self.assertEqual(pj.acme_first_domain("acme:\n  domains:\n    - ..\n    - -bad\n    - good.example.com\n"), "good.example.com")
        self.assertEqual(pj.acme_first_domain("acme:\n  domains: [.., good.example.com]\n"), "good.example.com")


@unittest.skipUnless(BASH, "缺少可用 Bash")
class FixCertChainHardeningTests(unittest.TestCase):
    """验证 fix_cert_chain.sh 的 PEM 注释行排除、前导零端口拦截、回滚陷阱与 SNI 消毒。"""

    def _src(self) -> str:
        return FIX_CERT_PATH.read_text(encoding="utf-8").replace("\r\n", "\n")

    def _func(self, name: str) -> str:
        src = self._src()
        start = src.index(name + " () {")
        return src[start:src.index("\n}\n", start) + 3]

    def test_n_certs_ignores_commented_pem_header_line(self):
        src = self._src()
        n_certs_line = next(l for l in src.splitlines() if l.startswith("n_certs ()"))
        with tempfile.TemporaryDirectory(prefix="hy2-fcc-pem-") as td:
            pem = Path(td) / "leaf.pem"
            pem.write_text(
                "# -----BEGIN CERTIFICATE-----\n"
                "-----BEGIN CERTIFICATE-----\nMIIA\n-----END CERTIFICATE-----\n",
                encoding="utf-8",
            )
            pem_posix = "/" + pem.as_posix()[0].lower() + pem.as_posix()[2:] if os.name == "nt" and pem.as_posix()[1] == ":" else pem.as_posix()
            res = subprocess.run(
                [BASH, "-c", f'{n_certs_line}\nn_certs "{pem_posix}"\n'],
                capture_output=True, text=True, encoding="utf-8", timeout=15,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout.strip(), "1", f"注释行不应计作证书，实际={res.stdout!r}")

    def test_masq_https_port_strips_leading_zero_and_rejects_overlong_or_out_of_range_digits(self):
        with tempfile.TemporaryDirectory(prefix="hy2-fcc-port-") as td:
            cfg = Path(td) / "config.yaml"
            cfg_posix = "/" + cfg.as_posix()[0].lower() + cfg.as_posix()[2:] if os.name == "nt" and cfg.as_posix()[1] == ":" else cfg.as_posix()
            # 既有契约：合法前导零端口须规范化剥零
            cfg.write_text('listen: :443\nmasquerade:\n  listenHTTPS: "0.0.0.0:08443"\n', encoding="utf-8")
            res_ok = subprocess.run(
                [BASH, "-c", self._func("masq_https_port") + f'masq_https_port "{cfg_posix}"\n'],
                capture_output=True, text=True, encoding="utf-8", timeout=15,
            )
            self.assertEqual(res_ok.stdout.strip(), "8443")

            for bad in ("  listenHTTPS: :0\n", "  listenHTTPS: :123456\n", "  listenHTTPS: :" + "9" * 40 + "\n"):
                cfg.write_text("listen: :443\nmasquerade:\n" + bad, encoding="utf-8")
                res = subprocess.run(
                    [BASH, "-c", self._func("masq_https_port") + f'masq_https_port "{cfg_posix}"\n'],
                    capture_output=True, text=True, encoding="utf-8", timeout=15,
                )
                self.assertEqual(res.stdout.strip(), "", f"不应接受非法端口 {bad!r}，实际={res.stdout!r}")

    def test_restore_config_file_has_return_trap_and_cert_sni_sanitizes_malicious_cn(self):
        restore_fn = self._func("restore_config_file")
        self.assertIn("trap - RETURN;", restore_fn, "restore_config_file 必须挂 RETURN 临时文件清理陷阱")

        # 伪造 openssl 输出带非法字符（如 -evil / 分号 / 逗号转义）的 CN
        script = (
            self._func("cert_sni")
            + """
openssl() {
    if [[ "$*" == *subjectAltName* ]]; then
        return 0
    fi
    echo "subject="
    echo "    organizationName          = Foo, Bar"
    echo "    commonName                = -evil;id"
}
cert_sni /dev/null
"""
        )
        res = subprocess.run([BASH, "-c", script], capture_output=True, text=True, encoding="utf-8", timeout=15)
        self.assertEqual(res.stdout.strip(), "", f"含非法字符的 CN 必须被消毒为空，实际={res.stdout!r}")

        # 合法多行 CN（即使 O 字段带逗号）应精确提取
        script_ok = (
            self._func("cert_sni")
            + """
openssl() {
    if [[ "$*" == *subjectAltName* ]]; then
        return 0
    fi
    echo "subject="
    echo "    organizationName          = Foo, Bar"
    echo "    commonName                = node.example.com"
}
cert_sni /dev/null
"""
        )
        res_ok = subprocess.run([BASH, "-c", script_ok], capture_output=True, text=True, encoding="utf-8", timeout=15)
        self.assertEqual(res_ok.stdout.strip(), "node.example.com", f"multiline CN 提取失败，实际={res_ok.stdout!r}")


if __name__ == "__main__":
    unittest.main()
