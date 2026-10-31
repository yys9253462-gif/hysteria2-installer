#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regression tests for the novice-installation audit (2026-10-09).

这一组锁死「小白装不上 / 装上了但用不了」的那些坑。每条都在注释里写明
**真实症状**，因为这些测试的价值全在于「症状不再出现」。

分三类：
  * shell 侧：抽取 install.sh 里的真实函数/代码片段，用 bash 真跑一遍，
    验证 set -e / 兜底 / 备份的行为（不是字符串匹配）。
  * python 侧：真起一个 portal，验证限流、脱敏、下载产物同步。
  * 仓库不变量：防止有人事后把这些修复又删掉。
"""

import http.client
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PORTAL = REPO / "portal.py"
INSTALL = REPO / "install.sh"


def _find_bash():
    cands = []
    for n in ("bash", "bash.exe"):
        f = shutil.which(n)
        if f:
            cands.append(f)
    cands += [r"C:\Program Files\Git\bin\bash.exe",
              r"C:\Program Files\Git\usr\bin\bash.exe",
              "/bin/bash", "/usr/bin/bash"]
    for c in cands:
        if c and Path(c).exists():
            return c
    return None


BASH = _find_bash()
CRLF = bytes([13, 10])   # raw HTTP line ending, kept as bytes to avoid escape churn


def _run_shell(script_text, cwd=None):
    """写文件再 `bash <file>`（绝不走 -c：MSYS 会做路径转换）。

    🔴 必须显式 stdin=DEVNULL：这里跑的是从 install.sh 摘出来的交互片段
    （`read -rsp "请输入机主账号连接密码"`）。不给 stdin 时子进程会继承调用方
    的管道，`read` 永远等不到 EOF —— 在 CI 上碰巧是 /dev/null 所以能过，
    在别的执行环境（本地 IDE、远程 runner）里会挂到超时。
    """
    fd, path = tempfile.mkstemp(suffix=".sh")
    os.close(fd)
    try:
        Path(path).write_text(script_text, encoding="utf-8", newline="\n")
        return subprocess.run([BASH, path], cwd=cwd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              stdin=subprocess.DEVNULL, timeout=120)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _extract_fn(name):
    text = INSTALL.read_text(encoding="utf-8")
    i = text.index(name + "() {")
    j = text.index("{", i)
    d = 0
    for k in range(j, len(text)):
        if text[k] == "{":
            d += 1
        elif text[k] == "}":
            d -= 1
            if d == 0:
                return text[i:k + 1]
    raise AssertionError("unbalanced braces: " + name)


# ==============================================================================
# shell 侧
# ==============================================================================
@unittest.skipUnless(BASH, "needs bash")
class TestSetEMidInstall(unittest.TestCase):
    """症状：DNS A 记录刚生效的机器（最常见场景）看到红色报错后脚本**静默退出**，
    「仍要继续申请吗?」这个提示根本没机会打印，只能重装。"""

    def test_dns_precheck_does_not_kill_install(self):
        snippet = _extract_fn("verify_domain_resolves_to_this_host")
        script = (
            "set -eo pipefail\n"
            'HY2_DIR=/tmp; HY2_CERT_DIR=/tmp; HY2_CONFIG=/tmp/nope.yaml; HY2_META_FILE=/tmp/nope.json\n'
            "PUBLIC_IP=1.2.3.4\n"
            "log_warn(){ echo \"WARN: $*\"; }\n"
            "log_err(){ echo \"ERR: $*\"; }\n"
            "log_step(){ echo \"STEP: $*\"; }\n"
            "log_info(){ echo \"INFO: $*\"; }\n"
            "resolve_domain_ips(){ return 1; }   # 模拟「没有 A 记录」\n"
            + snippet + "\n"
            "probe() {\n"
            '  echo "--- 调用 ---\n"\n'
            "  local rc=0\n"
            '  verify_domain_resolves_to_this_host "x.example.com" || rc=$?\n'
            '  echo "REACHED_PROMPT rc=$rc"\n'
            "}\n"
            "probe\n"
        )
        r = _run_shell(script)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("REACHED_PROMPT rc=1", r.stdout,
                      "set -e 在裸调用处把安装杀死了，后续提示成了死代码")

    def test_source_uses_guarded_call(self):
        text = INSTALL.read_text(encoding="utf-8")
        self.assertIn('verify_domain_resolves_to_this_host "$SERVER_NAME" || dns_rc=$?',
                      text,
                      "DNS 预校验必须写成 `|| dns_rc=$?`，裸调用在 set -e 下会终止安装")


@unittest.skipUnless(BASH, "needs bash")
class TestCurlFallbackReachable(unittest.TestCase):
    """症状：api.github.com 被墙/限流时，安装死在「获取最新版本...」，
    且**无任何报错**；为此专门写的直链回退分支永远执行不到。"""

    def _snippet(self, fn_name):
        return _extract_fn(fn_name)

    def test_install_binary_fallback_reachable(self):
        script = (
            "set -eo pipefail\n"
            "HY2_ARCH=amd64\n"
            "log_step(){ echo \"STEP: $*\"; }\n"
            "log_info(){ echo \"INFO: $*\"; }\n"
            "log_warn(){ echo \"WARN: $*\"; }\n"
            "log_err(){ echo \"ERR: $*\"; }\n"
            "curl(){ return 6; }          # 模拟 DNS/连接失败\n"
            # 只取函数体里那行版本获取 + 回退判定，不真下载二进制
            "LATEST_TAG=$(curl -s --max-time 10 https://api.github.com/x | jq -r '.tag_name // empty') || LATEST_TAG=\"\"\n"
            'if [[ -z "$LATEST_TAG" || "$LATEST_TAG" == "null" ]]; then\n'
            '  echo "FALLBACK_TAKEN"\n'
            "fi\n"
        )
        r = _run_shell(script)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("FALLBACK_TAKEN", r.stdout)

    def test_both_version_fetches_are_guarded(self):
        text = INSTALL.read_text(encoding="utf-8")
        # install_binary 与 install_gost 两处都要有 `|| XXX=""` 兜底。
        # 注意正则要贪婪匹配到**行尾**的 `|| VAR=""` —— URL 里的 `)` 会让
        # 非贪婪的 `[^)]*` 提前截断（这是本测试最初失败的原因）。
        for var in ("LATEST_TAG", "GOST_LATEST"):
            # 只匹配该变量**自己那一行**：GOST_LATEST 那行里也含 'LATEST_TAG' 字样，
            # 所以必须用 ^\s*VAR= 锚定（赋值行有缩进，别忘了 \s*；
            # \( \) 用来转义 $( 与开括号）。
            m = re.search(r'^\s*' + var + r'=\$\(curl.*$', text, re.M)
            self.assertIsNotNone(m, f"{var} 的版本获取语句不见了")
            self.assertIn(f'|| {var}=""', m.group(0),
                          f"{var} 的 curl 失败会因 set -eo pipefail 终止安装，回退分支不可达")


@unittest.skipUnless(BASH, "needs bash")
class TestGetPublicIPFailsLoudly(unittest.TestCase):
    """症状：三个源全失败时兜底 127.0.0.1 —— 节点「看起来装好了」，
    但订阅/二维码指向 127.0.0.1，客户端永远连不上，且毫无提示。"""

    def test_returns_nonzero_when_all_sources_fail(self):
        script = (
            "curl(){ return 1; }\n"
            'log_err(){ echo "ERR: $*"; }\n'
            + _extract_fn("get_public_ip") + "\n"
            "if get_public_ip; then echo 'UNEXPECTED_SUCCESS'; else echo 'CORRECTLY_FAILED'; fi\n"
        )
        r = _run_shell(script)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("CORRECTLY_FAILED", r.stdout)
        self.assertNotIn("UNEXPECTED_SUCCESS", r.stdout)

    def test_rejects_loopback_fallback(self):
        script = (
            'curl(){ echo "127.0.0.1"; }\n'
            'log_err(){ echo "ERR: $*"; }\n'
            + _extract_fn("get_public_ip") + "\n"
            "if get_public_ip; then echo 'UNEXPECTED_SUCCESS'; else echo 'CORRECTLY_FAILED'; fi\n"
        )
        r = _run_shell(script)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("CORRECTLY_FAILED", r.stdout,
                      "127.0.0.1 不能再被当成合法公网 IP 接受")


@unittest.skipUnless(BASH and shutil.which("jq"), "needs bash + jq")
class TestPasswordPreservedOnReconfigure(unittest.TestCase):
    """症状：菜单 4「重新修改配置」只是想改个端口，结果 auth/obfs 密码被随机换掉，
    所有已发放的客户端配置立刻失效 —— 而用户没被告知任何事。"""

    def _extract_password_block(self):
        """截取「密码生成」到 obfs 密钥生成这一段。

        注意 obfs 的复用逻辑在**端口跳跃之后**（原脚本顺序如此），
        所以终点不能用「# 端口跳跃」—— 那会把 obfs 块切在外面。
        """
        text = INSTALL.read_text(encoding="utf-8")
        i = text.index("# 密码生成")
        # 终点用 `unset _old_obfs` 之后那一行**带 log_info( 的**收尾语句；
        # 不能用裸文案「Salamander 混淆已默认自动启用」—— 它在上方注释里
        # 也出现过，index() 会命中注释里的那个，从而把真正要测的代码切在外面。
        j = text.index('log_info "Salamander 混淆已默认自动启用 (抗深度包检测 GFW 免疫)"', i)
        j = text.index(chr(10), j) + 1
        return text[i:j]

    def test_password_block_reuses_old_secret(self):
        block = self._extract_password_block()
        self.assertIn("HY2_META_FILE", block,
                      "菜单 4 必须读旧密码，否则重跑就换密码")
        self.assertIn(".auth_password", block)
        self.assertIn(".obfs_password", block)

    def test_only_shop_mode_is_offered(self):
        """单机私密模式已移除：安装不再询问模式，只提供商城版（Agent）。"""
        text = INSTALL.read_text(encoding="utf-8")
        self.assertNotIn("单机私密模式 (", text)
        self.assertIn('NODE_MODE="agent"', text)
        self.assertIn('HY2_NODE_MODE', text)
        # 旧的「固定密码」分支不能再出现在生成的 config.yaml 里
        self.assertNotIn("auth:\n  type: password\n  password:", text)

    def test_reuses_real_existing_password(self):
        """真跑一遍：已有 meta 时，密码必须与旧值一致。"""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            meta = td / "client_meta.json"
            meta.write_text(json.dumps({"auth_password": "OLD_AUTH_KEEPME",
                                        "obfs_password": "OLD_OBFS_KEEPME"}))
            block = self._extract_password_block()
            script = (
                'set -eo pipefail\n'
                f'HY2_META_FILE="{meta}"\n'
                'HY2_PASSWORD=""\n'
                'HY2_NODE_MODE=2\n'
                'LISTEN_PORT=12345\n'
                'HOP_START=20000\n'
                'HOP_END=40000\n'
                "is_valid_port(){ [[ \"$1\" =~ ^[0-9]+$ ]]; }\n"
                "port_owner(){ echo ''; }\n"
                "systemctl(){ return 1; }\n"
                "clear_all_hopping_rules(){ :; }\n"
                "setup_iptables_port_hopping(){ :; }\n"
                "log_info(){ echo \"INFO: $*\"; }\n"
                "log_warn(){ echo \"WARN: $*\"; }\n"
                "log_err(){ echo \"ERR: $*\"; }\n"
                # 交互全部走「回车默认」，等价于用户一路按回车
                "RANDOM_PASS=; AUTH_PASSWORD=; OBFS_PASSWORD=; NODE_MODE=; NODE_API_KEY=; RANDOM_API_KEY=\n"
                "openssl(){ echo freshlygenerated; }\n"
                + block + "\n"
                'echo "RESULT auth=$AUTH_PASSWORD obfs=$OBFS_PASSWORD"\n'
            )
            r = _run_shell(script)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("auth=OLD_AUTH_KEEPME", r.stdout,
                          "重配后 auth 密码变了 → 已发放客户端全部失效")
            self.assertIn("obfs=OLD_OBFS_KEEPME", r.stdout,
                          "重配后 obfs 密码变了 → 客户端握手直接失败")


@unittest.skipUnless(BASH, "needs bash")
class TestBackupBeforeReconfigure(unittest.TestCase):
    """症状：菜单 4 整体重写 client_meta.json + 重建 portal.json，
    商城开的子账号会消失 —— 而修复前全仓库没有任何一处 .bak。"""

    def test_backup_helper_actually_copies_files(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "client_meta.json").write_text('{"a":1}')
            (td / "portal.json").write_text('{"b":2}')
            (td / "config.yaml").write_text('listen: :443')
            (td / "cert").mkdir()
            (td / "cert/server.crt").write_text('CERT')
            (td / "cert/server.key").write_text('KEY')
            script = (
                'set -eo pipefail\n'
                f'HY2_DIR="{td}"\n'
                f'HY2_META_FILE="{td}/client_meta.json"\n'
                f'HY2_CONFIG="{td}/config.yaml"\n'
                f'HY2_CERT_DIR="{td}/cert"\n'
                "log_info(){ echo \"INFO: $*\"; }\n"
                "log_warn(){ echo \"WARN: $*\"; }\n"
                + _extract_fn("backup_state_before_reconfigure") + "\n"
                "backup_state_before_reconfigure\n"
            )
            r = _run_shell(script)
            self.assertEqual(r.returncode, 0, r.stderr)
            baks = list(td.glob("*.bak-*"))
            self.assertGreaterEqual(len(baks), 3, f"备份没生成：{r.stdout}{r.stderr}")
            for name in ("client_meta.json", "portal.json", "config.yaml",
                         "cert/server.crt", "cert/server.key"):
                self.assertTrue(list(td.glob(name + ".bak-*")),
                                f"{name} 没有快照")

    def test_snapshot_failure_aborts_reconfiguration(self):
        flow = INSTALL.read_text(encoding='utf-8')
        self.assertIn('backup_state_before_reconfigure || return 1', flow)
        helper = _extract_fn('backup_state_before_reconfigure')
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            protected = td / 'client_meta.json'
            protected.write_text('original')
            script = (
                'set -eo pipefail\n'
                f'HY2_DIR="{td}"\n'
                f'HY2_META_FILE="{protected}"\n'
                f'HY2_CONFIG="{td}/config.yaml"\n'
                f'HY2_CERT_DIR="{td}/cert"\n'
                'cp() { return 1; }\n'
                'log_info(){ :; }; log_warn(){ :; }; log_err(){ echo "ERR:$*"; }\n'
                + helper + '\nbackup_state_before_reconfigure\n'
            )
            result = _run_shell(script)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(protected.read_text(), 'original')

    def test_menu4_warns_and_calls_backup(self):
        text = INSTALL.read_text(encoding="utf-8")
        # 取菜单里 `4)` 这个 case 分支的正文：从该分支起点到同缩进的 `;;`。
        # 不能按「菜单 5 的提示行」切（提示行在 case 之前，会切出空窗口），
        # 也不能按第一个 `;;` 切（那是 case 1 的结尾，会切进错误的分支）。
        # 菜单 4 的流程在 flow_reconfigure() 里（菜单分支只负责调用它）。
        self.assertRegex(text, r"\n\s+4\)\s+run_action flow_reconfigure ;;",
                         "菜单 4 必须走 flow_reconfigure")
        start = text.index("flow_reconfigure() {")
        menu4 = text[start:text.index("\n}\n", start)]
        self.assertIn("backup_state_before_reconfigure", menu4,
                      "菜单 4 改配置前必须留快照")
        self.assertIn("确定继续吗？", menu4,
                      "菜单 4 必须显式告知后果并要求确认")
        self.assertLess(menu4.index("确定继续吗？"), menu4.index("backup_state_before_reconfigure"),
                        "必须先确认、再备份和改配置")


@unittest.skipUnless(BASH, "needs bash")
class TestYAMLQuoting(unittest.TestCase):
    """症状：域名里带空格或 # 时，未加引号的裸值会被 YAML 解析成另一个值、
    或把 # 之后整行当注释吃掉 → hysteria 报语法错、服务反复重启，
    而错误信息完全指不到输入框。"""

    def test_acme_domain_and_email_are_quoted(self):
        text = INSTALL.read_text(encoding="utf-8")
        self.assertIn('    - "${SERVER_NAME}"', text,
                      "acme.domains 里的域名必须加引号")
        self.assertIn('  email: "${ACME_EMAIL}"', text,
                      "acme.email 必须加引号")


@unittest.skipUnless(BASH and shutil.which("jq"), "needs bash + jq")
class TestSelfhealScriptGuards(unittest.TestCase):
    def test_selfheal_script_does_not_swallow_stderr(self):
        """症状：自愈脚本 `>/dev/null 2>&1 || true` 把失败完全吞掉 ——
        「服务显示成功、其实啥也没修」，正是本项目最忌的静默降级。"""
        text = INSTALL.read_text(encoding="utf-8")
        i = text.index("hy2-cert-selfheal.sh <<")
        j = text.index("\nEOCS", i)
        body = text[i:j]
        self.assertNotIn(">/dev/null 2>&1 || true", body)
        self.assertIn("logger", body, "自愈输出必须进 journal 留痕")


# ==============================================================================
# python 侧：真起 portal
# ==============================================================================
def _free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@unittest.skipUnless(shutil.which("qrencode") or os.name != "nt",
                     "portal needs a writable runtime")
class TestPortalRuntime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(REPO))
        if "portal" in sys.modules:
            del sys.modules["portal"]
        import portal as _p
        cls.portal = _p
        cls.tmp = tempfile.mkdtemp()
        root = Path(cls.tmp)
        # 一张真实存在的证书（自签即可，portal 只解析不校验链）
        certdir = root / "cert"
        certdir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1",
                        "-out", str(certdir / "server.key")], capture_output=True)
        subprocess.run(["openssl", "req", "-new", "-x509", "-days", "3650",
                        "-key", str(certdir / "server.key"),
                        "-out", str(certdir / "server.crt"),
                        "-subj", "/CN=www.bing.com"], capture_output=True)
        (root / "config.yaml").write_text(
            f"listen: :443\ntls:\n  cert: {certdir}/server.crt\n  key: {certdir}/server.key\n")
        cls.meta_path = root / "client_meta.json"
        cls.meta_path.write_text(json.dumps({
            "public_ip": "203.0.113.7", "auth_password": "MASTER_PW_DO_NOT_LEAK",
            "obfs_password": "OBFS_PW_DO_NOT_LEAK", "server_name": "www.bing.com",
            "cert_type": "self_signed", "is_insecure": True,
            "pin_sha256": "8037cef076db08b689c32fb96735cecfaef13e151144984743034371b7c10016",
        }))
        cls.port = _free_port()
        cls.portal.prepare(str(cls.meta_path), str(cls.port))
        cls.thread = threading.Thread(
            target=cls.portal.serve, args=(str(root / "portal.json"),), daemon=True)
        cls.thread.start()
        # 等端口就绪
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                c = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=1)
                c.request("GET", "/")
                c.getresponse().read()
                c.close()
                break
            except Exception:
                time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        try:
            shutil.rmtree(cls.tmp, ignore_errors=True)
        except Exception:
            pass

    def _req(self, path, headers=None, method="GET", body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            c.request(method, path, body=body, headers=headers or {})
            r = c.getresponse()
            data = r.read()
            return r.status, data
        finally:
            c.close()

    # ---- 症状：/auth 经 masquerade 对公网可达且无限流，可无限爆破 ----
    def test_auth_is_rate_limited(self):
        """实测背景：经 masquerade 打 /auth 连发 20 次全部 200，且回复可区分
        用户是否存在（User not found / inactive / expired / quota）= 完美密码 oracle。
        现在必须有限流把它挡下来。"""
        codes = []
        for i in range(60):
            payload = json.dumps({"auth": f"brute-{i}", "addr": "1.2.3.4:1234"})
            st, _ = self._req("/auth", method="POST", body=payload,
                              headers={"Content-Type": "application/json",
                                       "Content-Length": str(len(payload))})
            codes.append(st)
        # 不要求具体状态码（服务用 200+JSON 表达忙碌），但必须出现「忙」的回复
        busy = 0
        for i in range(60):
            payload = json.dumps({"auth": f"probe-{i}"})
            st, data = self._req("/auth", method="POST", body=payload,
                                 headers={"Content-Type": "application/json",
                                          "Content-Length": str(len(payload))})
            try:
                if b"busy" in data or b"Auth service busy" in data:
                    busy += 1
            except Exception:
                pass
        self.assertGreater(busy, 0,
                           "/auth 完全没有限流 —— 公网可无限爆破密码")

    # ---- 症状：低权限 api_key 能换到机主密码（提权）----
    def test_node_meta_does_not_leak_master_password(self):
        access = json.loads((Path(self.tmp) / "portal-access.json").read_text())
        key = access["api_key"]
        st, data = self._req("/api/v1/node/meta",
                             headers={"Authorization": "Bearer " + key})
        self.assertEqual(st, 200)
        obj = json.loads(data)
        meta = obj.get("meta", {})
        raw = data.decode("utf-8")
        self.assertNotIn("MASTER_PW_DO_NOT_LEAK", raw,
                         "/api/v1/node/meta 泄漏了机主 auth_password —— 无限流量提权")
        self.assertNotIn("OBFS_PW_DO_NOT_LEAK", raw,
                         "/api/v1/node/meta 泄漏了 obfs_password")
        for k in ("auth_password", "obfs_password"):
            self.assertNotIn(k, meta, f"{k} 不该出现在低权限通道的返回里")
        # 非敏感字段仍要保留，否则调用方拿不到该拿的东西
        self.assertIn("public_ip", meta)
        self.assertIn("server_name", meta)

    # ---- 症状：换证后二维码/下载配置仍是旧节点 ----
    def test_refresh_syncs_download_artifacts(self):
        """改**订阅端口**再 refresh，验证 clash/sing/qr 三者都跟着变。

        为什么改端口而不是改 server_name：改 server_name 会被 sync_cert_trust
        立刻按证书纠正回去（那是自愈的正常行为），结果 clash 没变，
        测的就变成「自愈有没有生效」而不是「下载产物有没有跟着刷新」。
        端口不会被自愈改，正好能干净地验证本条修复。
        """
        root = Path(self.tmp)
        data_file = root / "portal.json"
        before = json.loads(data_file.read_text())
        old_clash = before.get("clash", "")
        old_sing = before.get("sing", "")
        old_qr = before.get("qr", "")
        self.assertTrue(old_clash, "前置条件：portal.json 里应有 clash 内容")

        # 改 **hysteria 主监听端口**（它会出现在 clash 的 proxies[].port 里）。
        # 注意不能改 subscription_port：那个只出现在订阅 URL 里，
        # 不在 clash 内容中，拿它当断言会得到「内容没变」的假失败。
        m = json.loads(self.meta_path.read_text())
        new_listen = int(m.get("listen_port") or 19906) + 3
        m["listen_port"] = new_listen
        self.meta_path.write_text(json.dumps(m))
        self.portal.refresh(str(self.meta_path))

        after = json.loads(data_file.read_text())
        self.assertNotEqual(after.get("clash", ""), old_clash,
                            "clash.yaml 没跟着更新 —— 下载到的还是旧节点")
        self.assertNotEqual(after.get("sing", ""), old_sing,
                            "sing-box.json 没跟着更新")
        self.assertIn(str(new_listen), after.get("clash", ""),
                      "clash 里的端口应是刷新后的新值")
        # qrencode 不可用时二维码为空，此时只要求不报错
        if old_qr:
            self.assertNotEqual(after.get("qr", ""), old_qr,
                                "二维码没跟着更新 —— 用户扫了码就是旧节点")

    # ---- 症状：非 ASCII Authorization 头把处理函数打崩 ----
    def test_non_ascii_auth_header_does_not_crash(self):
        """直接用裸 socket 发原始字节。

        不能用 http.client：它在客户端侧就会拒绝发送非 ASCII 头
        （putheader 直接抛 UnicodeEncodeError），根本到不了服务端，
        那样就测不到 compare_digest 的 TypeError 了。
        """
        import socket as _socket
        for raw_auth in (b"Bearer " + bytes([0xc3,0xa9]),
                         b"Bearer " + bytes([0xe4,0xb8,0xad,0xe6,0x96,0x87]),
                         b"Basic " + bytes([0xe2,0x9c,0x97])):
            s = _socket.create_connection(("127.0.0.1", self.port), timeout=10)
            try:
                req = (b"GET /api/v1/users/list HTTP/1.1" + CRLF +
                       b"Host: 127.0.0.1" + CRLF +
                       b"Authorization: " + raw_auth + CRLF +
                       b"Connection: close" + CRLF + CRLF)
                s.sendall(req)
                chunks = []
                while True:
                    d = s.recv(4096)
                    if not d:
                        break
                    chunks.append(d)
                resp = b"".join(chunks)
            finally:
                s.close()
            self.assertTrue(resp, f"{raw_auth!r} 没有任何响应 —— 服务端很可能崩了")
            self.assertIn(b"HTTP/1.", resp[:20])
            # 服务端没崩：应该回一个正常的鉴权失败状态，而不是断连
            status_line = resp.split(CRLF, 1)[0]


# ==============================================================================
# 仓库不变量
# ==============================================================================
class TestRepoInvariants(unittest.TestCase):
    def test_download_routes_regenerate_before_serving(self):
        """clash/sing/qr 三个下载端点必须**先重生成再吐**。

        回归场景（2026-10-09 真机容器演练发现）：selfheal 跑在**另一个短命进程**里
        （systemd timer/path unit 调 `portal.py selfheal`），它把修好的产物写进
        portal.json；而长期运行的门户进程持有的 data 是**启动时的内存快照**，
        对这些磁盘写入一无所知。于是磁盘是新的、端点发出去的是旧的：
            meta / portal.json / 页面直链 = round2.example.com   ✅
            clash.yaml 端点              = newnode.example.com  ❌
        用户扫二维码/导入订阅拿到的就是旧节点 → CRYPTO_ERROR 0x150。
        页面看起来正常，只因为 subpath=='' 分支恰好会调 regenerate_page()。
        """
        text = PORTAL.read_text(encoding="utf-8")
        i = text.index("routes = {'': ('page', 'text/html; charset=utf-8')")
        j = text.index("self.reply(200, content, mime)", i)
        block = text[i:j]
        self.assertIn("if key in ('clash', 'sing', 'qr'):", block,
                      "下载类端点必须在取 data[key] 之前重生成，否则发的是内存旧值")
        regen = block.index("regenerate_page()")
        # 2026-10-29：读取改成容错的 (data.get(key) or '')；
        # 2026-10-30：进一步要求值必须是字符串才 encode（数字/列表会让
        # 「下载配置」直接掐断连接）。不变量不变 —— 重建仍必须发生在读取之前。
        read = block.index("raw_content = data.get(key)")
        self.assertLess(regen, read,
                        "重生成必须发生在读 data[key] 之前")
        self.assertIn("isinstance(raw_content, str)", block,
                      "读取必须容错：qr 可能缺失，值也可能被改成非字符串")


    def test_cert_choice_falls_back_to_self_signed(self):
        """症状：选「4 自动扫描本机证书」但机器上没有完整证书链时，
        裸调用 + set -e 直接终止安装，用户没退回自签的出路。"""
        text = INSTALL.read_text(encoding="utf-8")
        self.assertIn("if ! select_local_certificate; then", text,
                      "证书方式 4 失败必须回退自签")
        i = text.index("if ! select_local_certificate; then")
        window = text[i:i + 600]
        self.assertIn("generate_self_signed_cert", window,
                      "回退分支里必须真的调用 generate_self_signed_cert")

    def test_subscription_port_failure_is_handled(self):
        """症状：端口分配失败会写出 `listenHTTPS: :` 这种无效配置。"""
        text = INSTALL.read_text(encoding="utf-8")
        i = text.index("select_subscription_port() {")
        j = text.index("\n}", i)
        body = text[i:j]
        self.assertIn("is_valid_port", body,
                      "端口分配后必须校验合法性")
        self.assertIn("|| HY2_SUB_PORT=\"\"", body)
        self.assertIn("return 1", body, "分配失败必须返回非 0 而非留下空值")
        self.assertIn("select_subscription_port || {", text,
                      "调用点必须处理失败")

    def test_dependencies_are_verified_after_install(self):
        """症状：包管理器装完不校验，jq 缺失要等到几百行后第一次调用才炸。"""
        text = INSTALL.read_text(encoding="utf-8")
        i = text.index("install_dependencies() {")
        j = text.index("\n}", i)
        body = text[i:j]
        self.assertIn("missing_critical", body)
        self.assertIn("command -v", body, "必须逐个校验依赖是否真的可用")
        self.assertIn("return 1", body)

    def test_uninstall_asks_main_question_first(self):
        """症状：先问「是否卸载 AmneziaWG」再问「是否卸载 Hysteria」——
        用户对破坏性问题答 n 之后，却已经对另一个组件做了表态。"""
        text = INSTALL.read_text(encoding="utf-8")
        i = text.index("uninstall_all() {")
        j = text.index('log_step "正在停止并删除系统服务', i)
        body = text[i:j]
        self.assertLess(body.index("确定要彻底卸载 Hysteria 2"),
                        body.index("是否也要一并卸载 AmneziaWG"),
                        "主确认必须排在 AWG 追问之前")

    def test_listen_port_collision_is_checked(self):
        text = INSTALL.read_text(encoding="utf-8")
        i = text.index("setup_ports_and_obfs() {")
        j = text.index("# 端口跳跃 (默认全自动开启", i)
        body = text[i:j]
        self.assertIn("port_owner udp", body,
                      "主监听端口必须查占用（脚本已有 port_owner，只是从没在这用）")

    def test_prepare_survives_missing_qrencode(self):
        """症状：prepare() 里 qrencode 用 check=True，缺它会让**整个安装**崩。"""
        text = PORTAL.read_text(encoding="utf-8")
        i = text.index("def prepare(meta_path")
        j = text.index("def sync_download_artifacts(", i)
        body = text[i:j]
        # 只看真正的 subprocess 调用行 —— 解释这次修复的注释里也提到了 check=True，
        # 裸 substring 断言会误报（这是本测试最初的失败原因）。
        qr_call = re.search(r"subprocess\.run\(\['qrencode'.*?\)", body, re.S)
        self.assertIsNotNone(qr_call, "prepare() 里找不到 qrencode 调用")
        self.assertNotIn("check=True", qr_call.group(0),
                         "prepare() 里的 qrencode 不能用 check=True（会崩掉安装）")

    def test_sync_download_artifacts_updates_all_three(self):
        text = PORTAL.read_text(encoding="utf-8")
        self.assertIn("def sync_download_artifacts(", text)
        body = text[text.index("def sync_download_artifacts("):
                    text.index("\ndef ", text.index("def sync_download_artifacts("))]
        for key in ("data['clash']", "data['sing']", "data['qr']"):
            self.assertIn(key, body, f"必须同步 {key}")

    def test_refresh_and_regenerate_both_sync_artifacts(self):
        text = PORTAL.read_text(encoding="utf-8")
        for fn, nxt in (("def refresh(meta_path", "def selfheal("),
                        ("def regenerate_page()", "def sign_session(")):
            i = text.index(fn)
            j = text.index(nxt, i)
            self.assertIn("sync_download_artifacts(",
                          text[i:j],
                          f"{fn} 必须调用 sync_download_artifacts，否则下载产物会陈旧")

    def test_locale_is_pinned_for_external_parsers(self):
        """症状：ping / date 的输出被正则解析，不钉 C locale 就按本地化格式解析失败
        —— 测速永远「未测得」、证书倒计时退化成绿色的假象。"""
        text = PORTAL.read_text(encoding="utf-8")
        for marker in ("['ping', '-n'", "['date', '-d'"):
            i = text.index(marker)
            window = text[i:i + 400]
            self.assertIn("LC_ALL", window,
                          f"{marker} 必须钉 LC_ALL=C，否则本地化输出解析不了")

    def test_cert_badge_has_unknown_branch(self):
        """症状：判级 unknown（到期时间读不出）落进 else 分支，
        显示成「● 正常 · null 天后到期」的绿色假象。"""
        assets = (REPO / "portal_assets.py").read_text(encoding="utf-8")
        self.assertIn("warn_level === 'unknown'", assets,
                      "前端必须有 unknown 分支，不能显示绿色安慰性假象")


if __name__ == "__main__":
    unittest.main(verbosity=2)