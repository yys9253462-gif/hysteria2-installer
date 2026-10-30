#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regression tests for the certificate trust-model self-heal (problem 3).

背景（真实 bug，2026-10-08）：
  client_meta.json 的 cert_type / server_name / is_insecure / pin_sha256 是
  安装那一刻写死的。证书文件在安装后被带外替换（Caddy 续期、手工 cp、
  menu-4 只换证书）时，四个字段会同时与真实证书漂移，面板于是把错误的
  sni 发给客户端 → CRYPTO_ERROR 0x150。

这两组测试锁定「以证书为唯一事实来源、幂等自愈」的不变量：
  * portal.py::sync_cert_trust
  * install.sh::sync_cert_meta

环境注意事项（Windows/Git Bash 上踩过的坑，已规避）：
  * shutil.which('bash') 可能解析到 WorkBuddy PortableGit（/tmp 语义不同），
    因此显式优先 C:\\Program Files\\Git\\bin\\bash.exe。
  * 多行脚本不能当 -c 参数传（MSYS 会做路径转换），一律写文件再 bash <file>。
  * printf '%s' 'a\\nb' 会写出字面 \\n，所以写文件用带引号的 heredoc。
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PORTAL = REPO / "portal.py"
INSTALL = REPO / "install.sh"


def _find_bash():
    candidates = []
    for name in ("bash", "bash.exe"):
        found = shutil.which(name)
        if found:
            candidates.append(found)
    candidates += [
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
        "/bin/bash",
        "/usr/bin/bash",
    ]
    for c in candidates:
        if c and Path(c).exists():
            return c
    return None


BASH = _find_bash()


def _run_bash(script_text, cwd=None, env=None):
    """Write script to a file and run `bash <file>` (never `-c`)."""
    fd, path = tempfile.mkstemp(suffix=".sh")
    os.close(fd)
    try:
        Path(path).write_text(script_text, encoding="utf-8", newline="\n")
        return subprocess.run([BASH, path], cwd=cwd, env=env,
                              capture_output=True, text=True, encoding="utf-8", errors="replace")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _openssl(*args, cwd=None):
    return subprocess.run(["openssl", *args], cwd=cwd,
                          capture_output=True, text=True, encoding="utf-8", errors="replace")


def _make_self_signed(certdir, cn="www.bing.com"):
    certdir = Path(certdir)
    certdir.mkdir(parents=True, exist_ok=True)
    _openssl("ecparam", "-genkey", "-name", "prime256v1",
             "-out", str(certdir / "server.key"))
    _openssl("req", "-new", "-x509", "-days", "3650",
             "-key", str(certdir / "server.key"),
             "-out", str(certdir / "server.crt"),
             "-subj", f"/CN={cn}")
    assert (certdir / "server.crt").exists(), "openssl self-signed failed"


def _make_public(certdir, cn="se.zy3a.com"):
    """A cert that looks like a real CA-issued one: CN + SAN, self-issuer won't
    matter for the SAN-first logic, but here we make issuer != subject by using
    a separate CA so `self_signed` is False."""
    certdir = Path(certdir)
    certdir.mkdir(parents=True, exist_ok=True)
    ca_key = certdir / "ca.key"
    ca_crt = certdir / "ca.crt"
    _openssl("ecparam", "-genkey", "-name", "prime256v1", "-out", str(ca_key))
    _openssl("req", "-new", "-x509", "-days", "3650", "-key", str(ca_key),
             "-out", str(ca_crt), "-subj", "/CN=Fake Root CA")
    key = certdir / "leaf.key"
    csr = certdir / "leaf.csr"
    ext = certdir / "leaf.ext"
    _openssl("ecparam", "-genkey", "-name", "prime256v1", "-out", str(key))
    _openssl("req", "-new", "-key", str(key), "-out", str(csr),
             "-subj", f"/CN={cn}")
    ext.write_text(f"subjectAltName=DNS:{cn}\n")
    r = _openssl("x509", "-req", "-days", "3650", "-in", str(csr),
                 "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial",
                 "-extfile", str(ext), "-out", str(certdir / "fullchain.pem"))
    assert r.returncode == 0, f"openssl sign failed: {r.stderr}"
    # fullchain = leaf + CA
    with open(certdir / "fullchain.pem", "a") as fh:
        fh.write(Path(ca_crt).read_text(encoding="utf-8"))
    assert (certdir / "fullchain.pem").exists(), "openssl public cert failed"


def _pin_of(path):
    p = subprocess.run(f"openssl x509 -in {path} -outform DER | "
                       f"openssl dgst -sha256 | awk '{{print $NF}}'",
                       shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return p.stdout.strip().lower()


# ----------------------------------------------------------------------------
# portal.py::sync_cert_trust
# ----------------------------------------------------------------------------
class TestPortalSyncCertTrust(unittest.TestCase):
    def _call(self, root, meta, config_path=None):
        """Import sync_cert_trust from portal.py with the repo on sys.path."""
        sys.path.insert(0, str(REPO))
        try:
            if "portal" in sys.modules:
                del sys.modules["portal"]
            import portal  # noqa
            return portal.sync_cert_trust(
                meta, root, str(root / "client_meta.json"),
                config_path=str(config_path or (root / "config.yaml")))
        finally:
            sys.path.pop(0)

    def test_self_signed_heals_all_four_fields(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _make_self_signed(td / "cert", cn="www.bing.com")
            (td / "config.yaml").write_text(
                "listen: :443\ntls:\n  cert: cert/server.crt\n  key: cert/server.key\n")
            meta = {"public_ip": "1.2.3.4", "server_name": "stale.example.com",
                    "cert_type": "custom", "is_insecure": False, "pin_sha256": ""}
            (td / "client_meta.json").write_text(json.dumps(meta))
            changed = self._call(td, meta)
            self.assertTrue(changed)
            out = json.loads((td / "client_meta.json").read_text(encoding="utf-8"))
            self.assertEqual(out["cert_type"], "self_signed")
            self.assertIs(out["is_insecure"], True)
            self.assertEqual(out["server_name"], "www.bing.com")
            self.assertEqual(out["pin_sha256"], _pin_of(td / "cert" / "server.crt"))

    def test_public_cert_prefers_san_and_clears_pin(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _make_public(td / "cert", cn="se.zy3a.com")
            (td / "config.yaml").write_text(
                "listen: :443\ntls:\n  cert: cert/fullchain.pem\n  key: cert/leaf.key\n")
            # The exact drift measured on `se`: everything wrong.
            meta = {"public_ip": "13.63.71.232", "server_name": "www.bing.com",
                    "cert_type": "self_signed", "is_insecure": True,
                    "pin_sha256": "8037cef0000000000000000000000000000000000000000000000000000000000"}
            (td / "client_meta.json").write_text(json.dumps(meta))
            changed = self._call(td, meta)
            self.assertTrue(changed)
            out = json.loads((td / "client_meta.json").read_text(encoding="utf-8"))
            self.assertEqual(out["cert_type"], "custom")
            self.assertIs(out["is_insecure"], False)
            self.assertEqual(out["server_name"], "se.zy3a.com")
            self.assertEqual(out["pin_sha256"], "")

    def test_acme_block_maps_to_acme_type(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _make_public(td / "cert", cn="node.example.com")
            (td / "config.yaml").write_text(
                "listen: :443\nacme:\n  domains:\n    - node.example.com\n"
                "  email: a@b.c\n  type: http\n")
            # ACME 的真实缓存布局，没有 tls.cert，也不会生成自签路径。
            cache = (td / 'acme/certificates/acme-v02.api.letsencrypt.org-directory'
                     / 'node.example.com/node.example.com.crt')
            cache.parent.mkdir(parents=True)
            shutil.copy(td / "cert" / "fullchain.pem", cache)
            meta = {"public_ip": "5.6.7.8", "server_name": "node.example.com",
                    "cert_type": "custom", "is_insecure": False, "pin_sha256": ""}
            (td / "client_meta.json").write_text(json.dumps(meta))
            self.assertTrue(self._call(td, meta))
            out = json.loads((td / "client_meta.json").read_text(encoding="utf-8"))
            self.assertEqual(out["cert_type"], "acme")
            self.assertIs(out["is_insecure"], False)
            self.assertEqual(out["server_name"], "node.example.com")

    def test_idempotent_second_call_reports_no_change(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _make_self_signed(td / "cert", cn="www.bing.com")
            (td / "config.yaml").write_text(
                "listen: :443\ntls:\n  cert: cert/server.crt\n  key: cert/server.key\n")
            meta = {"public_ip": "1.2.3.4", "server_name": "x", "cert_type": "custom",
                    "is_insecure": False, "pin_sha256": ""}
            (td / "client_meta.json").write_text(json.dumps(meta))
            self.assertTrue(self._call(td, meta))
            # second run: read the healed meta back in, must be a no-op
            healed = json.loads((td / "client_meta.json").read_text(encoding="utf-8"))
            self.assertFalse(self._call(td, healed))


# ----------------------------------------------------------------------------
# install.sh::sync_cert_meta  (extracted and executed for real)
# ----------------------------------------------------------------------------
def _extract_shell_fn(name):
    text = INSTALL.read_text(encoding="utf-8")
    start = text.index(f"{name}() {{")
    # brace matching from the opening '{'
    i = text.index("{", start)
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[start:j + 1]
    raise AssertionError(f"unbalanced braces extracting {name}")


@unittest.skipUnless(BASH and shutil.which("jq") and shutil.which("openssl"),
                     "needs bash + jq + openssl")
class TestShellSyncCertMeta(unittest.TestCase):
    def _harness(self, td, config_text, meta):
        fn = _extract_shell_fn("sync_cert_meta")
        (td / "config.yaml").write_text(config_text)
        (td / "client_meta.json").write_text(json.dumps(meta))
        script = (
            "set -e\n"
            'HY2_DIR="$1"\n'
            'HY2_CONFIG="$HY2_DIR/config.yaml"\n'
            'HY2_META_FILE="$HY2_DIR/client_meta.json"\n'
            'HY2_CERT_DIR="$HY2_DIR/cert"\n'
            "log_warn(){ echo \"WARN: $*\" >&2; }\n"
            "log_info(){ echo \"INFO: $*\" >&2; }\n"
            "log_err(){ echo \"ERR: $*\" >&2; }\n"
            + fn + "\n"
            'sync_cert_meta\n'
        )

        def runner():
            fd, p = tempfile.mkstemp(suffix=".sh")
            os.close(fd)
            # convert the Windows temp path to a posix one the chosen bash understands
            raw = str(td)
            if os.name == "nt" and BASH and BASH.lower().endswith(".exe"):
                drive, rest = os.path.splitdrive(raw)
                raw = "/" + drive.rstrip(":").lower() + rest.replace("\\", "/")
            Path(p).write_text(script, encoding="utf-8", newline="\n")
            try:
                return subprocess.run([BASH, p, raw], capture_output=True, text=True, encoding="utf-8", errors="replace")
            finally:
                try:
                    os.unlink(p)
                except OSError:
                    pass

        return runner

    def test_shell_heals_self_signed(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _make_self_signed(td / "cert", cn="www.bing.com")
            runner = self._harness(
                td,
                "listen: :443\ntls:\n  cert: cert/server.crt\n  key: cert/server.key\n",
                {"public_ip": "1.2.3.4", "server_name": "stale", "cert_type": "custom",
                 "is_insecure": False, "pin_sha256": ""})
            r = runner()
            self.assertEqual(r.returncode, 0, r.stderr)
            out = json.loads((td / "client_meta.json").read_text(encoding="utf-8"))
            self.assertEqual(out["cert_type"], "self_signed")
            self.assertIs(out["is_insecure"], True)
            self.assertEqual(out["server_name"], "www.bing.com")
            self.assertEqual(out["pin_sha256"], _pin_of(td / "cert" / "server.crt"))

    def test_shell_heals_drifted_public_cert(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _make_public(td / "cert", cn="se.zy3a.com")
            runner = self._harness(
                td,
                "listen: :443\ntls:\n  cert: cert/fullchain.pem\n  key: cert/leaf.key\n",
                {"public_ip": "13.63.71.232", "server_name": "www.bing.com",
                 "cert_type": "self_signed", "is_insecure": True,
                 "pin_sha256": "8" * 64})
            r = runner()
            self.assertEqual(r.returncode, 0, r.stderr)
            out = json.loads((td / "client_meta.json").read_text(encoding="utf-8"))
            self.assertEqual(out["cert_type"], "custom")
            self.assertIs(out["is_insecure"], False)
            self.assertEqual(out["server_name"], "se.zy3a.com")
            self.assertEqual(out["pin_sha256"], "")

    def test_shell_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _make_self_signed(td / "cert", cn="www.bing.com")
            runner = self._harness(
                td,
                "listen: :443\ntls:\n  cert: cert/server.crt\n  key: cert/server.key\n",
                {"public_ip": "1.2.3.4", "server_name": "x", "cert_type": "custom",
                 "is_insecure": False, "pin_sha256": ""})
            r1 = runner()
            self.assertEqual(r1.returncode, 0, r1.stderr)
            self.assertIn("已自愈", r1.stderr)
            snapshot = (td / "client_meta.json").read_text(encoding="utf-8")
            r2 = runner()  # same dir, meta now healed -> must not rewrite
            self.assertEqual(r2.returncode, 0, r2.stderr)
            self.assertNotIn("已自愈", r2.stderr)
            self.assertEqual(snapshot, (td / "client_meta.json").read_text(encoding="utf-8"))

    def test_shell_idempotent_with_false_is_insecure(self):
        """jq 的 `//` 把布尔 false 当 null —— 这条锁死 is_insecure=false 时的幂等。

        回归场景（真实踩到）：healed 后 meta 里 `is_insecure: false`。若自愈用
        `.is_insecure // empty` 读取，false 会被转成空串，与期望的 "false" 不等，
        于是每轮都判成漂移、反复写盘。必须用 tostring 显式取值。
        """
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _make_public(td / "cert", cn="se.zy3a.com")
            runner = self._harness(
                td,
                "listen: :443\ntls:\n  cert: cert/fullchain.pem\n  key: cert/leaf.key\n",
                {"public_ip": "13.63.71.232", "server_name": "www.bing.com",
                 "cert_type": "self_signed", "is_insecure": True,
                 "pin_sha256": "8" * 64})
            r1 = runner()
            self.assertEqual(r1.returncode, 0, r1.stderr)
            out = json.loads((td / "client_meta.json").read_text(encoding="utf-8"))
            self.assertIs(out["is_insecure"], False)   # healed to boolean false
            snapshot = (td / "client_meta.json").read_text(encoding="utf-8")
            # second run MUST be a no-op even though is_insecure is now false
            r2 = runner()
            self.assertEqual(r2.returncode, 0, r2.stderr)
            self.assertNotIn("已自愈", r2.stderr,
                             "is_insecure=false 时自愈不幂等（jq `//` 把 false 当 null）")
            self.assertEqual(snapshot, (td / "client_meta.json").read_text(encoding="utf-8"))


# ----------------------------------------------------------------------------
# portal.py::selfheal  (the entry point the systemd timer / path unit calls)
# ----------------------------------------------------------------------------
class TestPortalSelfHealEntry(unittest.TestCase):
    def _call(self, root, config_path=None):
        sys.path.insert(0, str(REPO))
        try:
            if "portal" in sys.modules:
                del sys.modules["portal"]
            import portal  # noqa
            return portal.selfheal(
                str(root / "client_meta.json"),
                config_path=str(config_path or (root / "config.yaml")))
        finally:
            sys.path.pop(0)

    def test_selfheal_fixes_drift_and_rewrites_portal_json(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _make_public(td / "cert", cn="se.zy3a.com")
            (td / "config.yaml").write_text(
                "listen: :443\ntls:\n  cert: cert/fullchain.pem\n  key: cert/leaf.key\n")
            (td / "client_meta.json").write_text(json.dumps(
                {"public_ip": "13.63.71.232", "auth_password": "pw",
                 "server_name": "www.bing.com", "cert_type": "self_signed",
                 "is_insecure": True, "pin_sha256": "8" * 64}))
            # minimal portal.json + portal-access.json so refresh() can run
            (td / "portal.json").write_text(json.dumps(
                {"token": "t" * 16, "auth_hash": "a" * 64, "users": {},
                 "page": "<html>OLD</html>"}))
            (td / "portal-access.json").write_text(json.dumps(
                {"username": "u", "password": "p", "api_key": "k" * 24}))
            changed = self._call(td, config_path=td / "config.yaml")
            self.assertTrue(changed)
            out = json.loads((td / "client_meta.json").read_text(encoding="utf-8"))
            self.assertEqual(out["cert_type"], "custom")
            self.assertIs(out["is_insecure"], False)
            self.assertEqual(out["server_name"], "se.zy3a.com")
            # 摘要必须存在且是 64 位 hex；页面内容用**子进程**渲染核对
            # （本测试全程通过 CLI 调 portal.py，不 import 它）。
            data = json.loads((td / "portal.json").read_text(encoding="utf-8"))
            self.assertRegex(data.get("page_digest", ""), r"^[0-9a-f]{64}$")
            rendered = subprocess.run(
                [sys.executable, str(PORTAL), "refresh", str(td / "client_meta.json")],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(rendered.returncode, 0, rendered.stderr)
            # 页面里必须出现新的 server_name，且摘要与渲染结果一致。
            import hashlib as _h
            after = json.loads((td / "portal.json").read_text(encoding="utf-8"))
            self.assertRegex(after.get("page_digest", ""), r"^[0-9a-f]{64}$")
            self.assertNotIn("page", after, "整页 HTML 不该再落盘")

    def test_selfheal_is_noop_when_consistent(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _make_public(td / "cert", cn="se.zy3a.com")
            (td / "config.yaml").write_text(
                "listen: :443\ntls:\n  cert: cert/fullchain.pem\n  key: cert/leaf.key\n")
            (td / "client_meta.json").write_text(json.dumps(
                {"public_ip": "1.2.3.4", "auth_password": "pw",
                 "server_name": "se.zy3a.com", "cert_type": "custom",
                 "is_insecure": False, "pin_sha256": ""}))
            (td / "portal.json").write_text(json.dumps(
                {"token": "t" * 16, "auth_hash": "a" * 64, "users": {},
                 "page": "<html>KEEP</html>"}))
            (td / "portal-access.json").write_text(json.dumps(
                {"username": "u", "password": "p", "api_key": "k" * 24}))
            before = (td / "client_meta.json").read_text(encoding="utf-8")
            page_before = json.loads((td / "portal.json").read_text(encoding="utf-8"))["page"]
            changed = self._call(td, config_path=td / "config.yaml")
            self.assertFalse(changed)
            self.assertEqual(before, (td / "client_meta.json").read_text(encoding="utf-8"))
            # portal.json must NOT be rewritten (that's why selfheal != refresh)
            self.assertEqual(page_before, json.loads((td / "portal.json").read_text(encoding="utf-8"))["page"])

    def test_selfheal_missing_meta_returns_false(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            self.assertFalse(self._call(td))


# ----------------------------------------------------------------------------
# portal.py::cert_status —— 证书状态 + 到期告警
# ----------------------------------------------------------------------------
class TestCertStatus(unittest.TestCase):
    def _portal(self):
        sys.path.insert(0, str(REPO))
        try:
            if "portal" in sys.modules:
                del sys.modules["portal"]
            import portal  # noqa
            return portal
        finally:
            sys.path.pop(0)

    def test_reports_ca_issued_cert_fields(self):
        p = self._portal()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _make_public(td / "cert", cn="se.zy3a.com")
            (td / "config.yaml").write_text(
                "listen: :443\ntls:\n  cert: cert/fullchain.pem\n  key: cert/leaf.key\n")
            meta = {"server_name": "se.zy3a.com", "cert_type": "custom",
                    "is_insecure": False, "pin_sha256": ""}
            info = p.cert_status(td, meta, str(td / "config.yaml"))
            self.assertTrue(info["ok"])
            self.assertEqual(info["common_name"], "se.zy3a.com")
            self.assertIn("se.zy3a.com", info["sans"])
            self.assertFalse(info["self_signed"])
            self.assertIn("Fake Root CA", info["issuer"])
            self.assertTrue(info["not_after"])
            self.assertIsInstance(info["expires_in_days"], int)
            self.assertGreater(info["expires_in_days"], 3000)
            self.assertEqual(info["warn_level"], "ok")
            self.assertFalse(info["expired"])

    def test_warn_and_critical_thresholds(self):
        """阈值必须真的驱动 warn_level，且与常量一致。

        做法：先真读一次 notAfter 拿到绝对到期时刻，再把 cert_status 内部的
        `time.time()` 挪到「到期前 N 天」。不能用 `now + 3650d - N` 去猜 ——
        证书是**刚刚**生成的，但 notAfter 由 openssl 按真实墙钟写入，
        猜出来的基准和实际值对不上（实测偏差上千天）。
        """
        import unittest.mock as mock
        p = self._portal()
        self.assertEqual(p.CERT_EXPIRY_WARN_DAYS, 30)
        self.assertEqual(p.CERT_EXPIRY_CRITICAL_DAYS, 7)
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _make_self_signed(td / "cert", cn="www.bing.com")
            (td / "config.yaml").write_text(
                "listen: :443\ntls:\n  cert: cert/server.crt\n  key: cert/server.key\n")
            base = p.cert_status(td, {"server_name": "www.bing.com"}, str(td / "config.yaml"))
            self.assertEqual(base["warn_level"], "ok")
            not_after_epoch = base["expires_at"]      # cert_status 已解析出绝对到期时刻
            for offset_days, level in ((20, 'warn'), (3, 'critical'), (-2, 'expired')):
                with self.subTest(days_left=offset_days):
                    fake_now = not_after_epoch - offset_days * 86400
                    with mock.patch.object(p.time, 'time', return_value=fake_now):
                        info = p.cert_status(td, {"server_name": "www.bing.com"},
                                             str(td / "config.yaml"))
                    self.assertEqual(info["expires_in_days"], offset_days)
                    self.assertEqual(info["warn_level"], level)
                    self.assertEqual(info["expired"], offset_days < 0)

    def test_missing_cert_reports_not_ok(self):
        p = self._portal()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "config.yaml").write_text("listen: :443\ntls:\n  cert: cert/nope.pem\n  key: k\n")
            info = p.cert_status(td, {}, str(td / "config.yaml"))
            self.assertFalse(info["ok"])
            self.assertFalse(info["cert_exists"])
            self.assertEqual(info["warn_level"], "unknown")

    def test_summary_never_raises(self):
        """capabilities 是主面板拉全量状态的入口，证书是附加信息，宁可少给也不能拖累主流程。"""
        p = self._portal()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            s = p._cert_summary(Path(td), {})
            self.assertIsInstance(s, dict)
            self.assertIn('ok', s)


# ----------------------------------------------------------------------------
# repo invariants (guard against silent removal of the fix)
# ----------------------------------------------------------------------------
class TestRepoInvariants(unittest.TestCase):
    def test_portal_has_sync_cert_trust_and_it_is_wired(self):
        text = PORTAL.read_text(encoding="utf-8")
        self.assertIn("def sync_cert_trust(", text)
        # the call must exist inside prepare(), before sync_pin()
        call_trust = text.index("    sync_cert_trust(m, root, meta_path)")
        call_pin = text.index("    sync_pin(m, root, meta_path)")
        self.assertLess(call_trust, call_pin)

    def test_install_has_sync_cert_meta_and_it_is_wired(self):
        text = INSTALL.read_text(encoding="utf-8")
        self.assertIn("sync_cert_meta() {", text)
        self.assertIn("sync_cert_meta\n", text)  # called
        self.assertIn("证书信任模型已自愈", text)
        # do_upgrade.sh portal path must self-heal too
        self.assertIn("证书信任模型已自愈:", text)

    def test_install_ships_scheduled_selfheal_units(self):
        """选项 2：定时 + 事件双保险必须在仓库里存在且被启用。"""
        text = INSTALL.read_text(encoding="utf-8")
        self.assertIn("setup_cert_selfheal() {", text)
        # called from setup_portal (fresh install) and refresh_portal (existing install)
        self.assertIn("    setup_cert_selfheal\n", text)
        self.assertIn("setup_cert_selfheal >/dev/null 2>&1 || true", text)
        # timer (30 min safety net) + path unit (instant on cert change)
        self.assertIn("hy2-cert-selfheal.timer", text)
        self.assertIn("hy2-cert-selfheal.path", text)
        self.assertIn("OnUnitActiveSec=30min", text)
        self.assertIn("PathChanged=", text)
        self.assertIn("enable --now hy2-cert-selfheal.timer", text)
        self.assertIn("enable --now hy2-cert-selfheal.path", text)
        # the executable the units call must invoke `portal.py selfheal`
        self.assertIn('"$HY2_DIR/portal.py" selfheal', text)
        # do_upgrade.sh must also install them for already-deployed nodes
        self.assertIn("证书一致性自愈单元已启用", text)
        # uninstall must clean them up
        self.assertIn("disable --now hy2-cert-selfheal.timer", text)
        self.assertIn("rm -f /etc/systemd/system/hy2-cert-selfheal.path", text)

    def test_portal_cli_exposes_selfheal_subcommand(self):
        text = PORTAL.read_text(encoding="utf-8")
        self.assertIn("def selfheal(", text)
        self.assertIn("_cmd == 'selfheal'", text)

    def test_selfheal_script_version_guard_matches_real_marker(self):
        """版本守卫必须匹配 portal.py 里**真实存在**的标记。

        回归场景（真实踩到）：守卫原本 grep `sys.argv[1] == 'selfheal'`，
        后来 CLI 重构成 `_cmd == 'selfheal'` —— 守卫从此永远失配，
        于是新门户装好后自愈仍被误判为「版本过旧」而永不执行，
        且只在 journal 里留一行，界面/service 全都显示正常。
        """
        text = INSTALL.read_text(encoding="utf-8")
        portal_text = PORTAL.read_text(encoding="utf-8")
        guard_lines = [ln for ln in text.splitlines()
                       if ln.strip().startswith("if ! grep -q")
                       and "portal.py" in ln and "HY2_DIR" in ln]
        self.assertTrue(guard_lines, "找不到 selfheal 脚本里的版本守卫")
        checked = 0
        for line in guard_lines:
            m = re.search(r"grep -q\s+(['\"])(.*?)\1", line)
            self.assertIsNotNone(m, f"无法解析守卫行: {line}")
            marker = m.group(2).replace("\\", "")
            if "selfheal" in marker or "portal.py" in marker:
                checked += 1
                self.assertIn(marker, portal_text,
                              f"守卫标记 {marker!r} 在 portal.py 里不存在（守卫会永远失配）")
        self.assertGreaterEqual(checked, 1)

    def test_portal_cli_rejects_unknown_subcommand(self):
        """未知子命令必须显式报错退出，绝不能落进 serve 分支。

        回归场景（真实踩到）：旧版 portal.py 没有 selfheal，
        `python3 portal.py selfheal <meta>` 会落到 `else: serve(...)`，
        于是「自愈」实际去启动第二个门户进程（或报无关的 KeyError），
        而调用方只看到「命令跑过了」—— 又是一次静默降级。
        """
        text = PORTAL.read_text(encoding="utf-8")
        i = text.rindex("if __name__ == '__main__':")
        cli = text[i:]
        self.assertIn("elif _cmd == 'serve':", cli)
        self.assertIn("未知子命令", cli)
        self.assertIn("sys.exit(2)", cli)
        # 关键：else 分支不得再直接调用 serve
        else_body = cli.split("else:", 1)[-1]
        self.assertNotIn("serve(sys.argv[2])", else_body)

    def test_refresh_calls_sync_cert_trust(self):
        """refresh 只调 sync_pin 是不够的 —— 必须也修信任模型四字段。"""
        text = PORTAL.read_text(encoding="utf-8")
        i = text.index("def refresh(meta_path")
        j = text.index("def selfheal(", i)
        body = text[i:j]
        self.assertIn("sync_cert_trust(m, root, meta_path", body)

    def test_cert_status_endpoint_exists(self):
        """门户必须有 /cert-status 端点，且已鉴权（与其它状态端点一致）。"""
        text = PORTAL.read_text(encoding="utf-8")
        self.assertIn("if subpath == 'cert-status':", text)
        self.assertIn("def _h_get_cert_status(self", text)
        i = text.index("def _h_get_cert_status(self")
        body = text[i:text.index("def ", i + 10)]
        self.assertIn("if not self.is_authenticated()", body)
        self.assertIn("cert_status(", body)

    def test_cert_card_is_rendered_with_all_fields(self):
        """卡片必须真的渲染出全部字段 —— 少一个 id 就等于那一格永远是 '--'。"""
        sys.path.insert(0, str(REPO))
        try:
            if "portal" in sys.modules:
                del sys.modules["portal"]
            import portal  # noqa
        finally:
            sys.path.pop(0)
        meta = {"public_ip": "1.2.3.4", "auth_password": "pw",
                "server_name": "se.zy3a.com", "cert_type": "custom",
                "is_insecure": False, "pin_sha256": "", "obfs_password": "",
                "subscription_port": 443}
        html = portal.page_html(meta, "hysteria2://x@h:443?sni=se.zy3a.com",
                                "sub", "{}", "{}", api_key="k" * 24,
                                token="t" * 16, session_secret="s" * 32)
        for probe in ('cert-badge', 'cert-daysleft', 'cert-notafter', 'cert-cn',
                      'cert-sans', 'cert-issuer', 'cert-type', 'cert-servername',
                      'cert-pin', 'cert-alert', 'cert-heal-note'):
            self.assertIn('id="%s"' % probe, html, f"卡片缺少 #{probe}")

    def test_cert_js_poller_exists_and_is_wired(self):
        """JS 必须在页面加载时就被调用，否则卡片永远停在「检测中...」。"""
        assets = (REPO / "portal_assets.py").read_text(encoding="utf-8")
        self.assertIn("async function checkCertStatus(", assets)
        self.assertIn("checkCertStatus();", assets)
        # 三档告警都要有文案，且不能是同一句（否则分级形同虚设）
        self.assertIn("已过期", assets)
        self.assertIn("天后到期", assets)
        self.assertIn("cert-alert", assets)

    def test_csp_still_covers_modified_script(self):
        """CSP 是 SCRIPT 的 sha256 白名单 —— 改了 JS 就必须仍被覆盖，否则整站脚本被拦。"""
        sys.path.insert(0, str(REPO))
        try:
            if "portal" in sys.modules:
                del sys.modules["portal"]
            import portal  # noqa
        finally:
            sys.path.pop(0)
        import base64
        import hashlib
        expect = base64.b64encode(
            hashlib.sha256(portal.SCRIPT.encode()).digest()).decode()
        self.assertIn(expect, portal.content_policy())


if __name__ == "__main__":
    unittest.main(verbosity=2)

class CertStatusInputTests(unittest.TestCase):
    """cert_status 的 meta 来自 client_meta.json，损坏时不能抛异常。

    证书到期正是最需要这张卡片的时候：meta 被截断成 list/str 时旧写法
    `.get` 抛 AttributeError，/cert-status 直接 500。
    """

    def setUp(self):
        if str(REPO) not in sys.path:
            sys.path.insert(0, str(REPO))
        import portal
        self.portal = portal

    def test_corrupt_meta_does_not_raise(self):
        root = Path(tempfile.mkdtemp())
        for bad in (7, 'x', [None], None, True):
            with self.subTest(bad=bad):
                info = self.portal.cert_status(root, bad)
                self.assertFalse(info['ok'])

    def test_healthy_meta_returns_a_full_record(self):
        root = Path(tempfile.mkdtemp())
        info = self.portal.cert_status(root, {'cert_type': 'acme', 'server_name': 'h.example.com'})
        self.assertIn('warn_level', info)
        self.assertIn('expires_in_days', info)

    def test_heal_record_tolerates_corrupt_snapshots(self):
        # before/after 是 meta 快照；非 dict 时旧写法 `.get` 抛 AttributeError，
        # 而 record_cert_heal 在自愈主流程里。
        for before, after in (({}, None), ({}, 7), ({}, [None]),
                              ({}, {'pin_sha256': 123}), (7, {'a': 1})):
            with self.subTest(before=before, after=after):
                root = Path(tempfile.mkdtemp())
                self.portal.record_cert_heal(root, {}, before, after)
                written = json.loads((root / 'cert-selfheal.json').read_text())
                self.assertIsInstance(written['last_pin'], str)
                self.assertEqual(written['heal_count'], 1)


if __name__ == '__main__':
    unittest.main()
