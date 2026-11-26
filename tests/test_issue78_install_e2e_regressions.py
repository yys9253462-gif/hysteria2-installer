"""第 78 号议题与全安装链路扫雷的端到端串联回归测试。

覆盖核心缺陷与全链路扫雷加固：
1. P0（第 78 号议题）：setup_ports_and_obfs 在 en_US.UTF-8 / zh_CN.UTF-8 等非 C 区域下
   校验 NODE_API_KEY 时受区域排序表影响把 [!-~] 误判为纯标点，导致自动生成的
   hy2_sec_<32位十六进制> 必败；现强制在 C 区域校验，并修正提示输出时机。
2. 真正端到端串联：载入 install.sh 真实函数定义，串联执行
   setup_certificates -> setup_ports_and_obfs -> generate_server_config
   -> portal_ensure_py -> setup_portal（调用真实 portal.py prepare / adopt）
   -> setup_system_firewall -> show_client_configs -> show_teyir_access，
   并启动真实门户服务验证 /api/health 与 /api/v1/node/meta（携带 Bearer NODE_API_KEY）。
3. 全安装链路扫雷回归：受限 nftables 容错、缺 ss 时的 port_owner 兜底、
   仅通配符 SAN 证书的 select_local_certificate 回退、show_menu_status 抗异常/SIGPIPE、
   resolve_domain_ips 回退容错、以及同源纯 ASCII 范围正则的区域排序隔离。
"""

import html
import http.client
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
INSTALL = REPO / 'install.sh'
AWGCTL = REPO / 'awgctl.sh'
PORTAL_PY = REPO / 'portal.py'


def _find_bash():
    if os.name == 'nt':
        for cand in (
            r'C:\Program Files\Git\usr\bin\bash.exe',
            r'C:\Program Files\Git\bin\bash.exe',
            shutil.which('bash'),
        ):
            if cand and Path(cand).is_file():
                return cand
        return None
    return shutil.which('bash')


BASH = _find_bash()


def _bash_has_tool(tool_name):
    if not BASH:
        return False
    res = subprocess.run(
        [BASH, '-c', f'command -v {tool_name} >/dev/null 2>&1'],
        capture_output=True, timeout=10,
    )
    return res.returncode == 0


HAS_JQ = _bash_has_tool('jq')
HAS_OPENSSL = _bash_has_tool('openssl')


def _available_utf8_locales():
    """探测本机可用的区域列表，优先包含 en_US.UTF-8 与 zh_CN.UTF-8。"""
    found = []
    if BASH:
        res = subprocess.run(
            [BASH, '-c', 'locale -a 2>/dev/null || true'],
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=10,
        )
        raw = [ln.strip() for ln in res.stdout.splitlines() if ln.strip()]
        preferred = []
        for item in raw:
            low = item.lower().replace('-', '')
            if low in ('en_us.utf8', 'zh_cn.utf8'):
                preferred.append(item)
        others = [
            item for item in raw
            if item not in preferred and 'utf' in item.lower() and not item.upper().startswith('C.')
        ]
        found = preferred + others[:2]
    if 'C.UTF-8' not in found:
        found.append('C.UTF-8')
    if 'C' not in found:
        found.append('C')
    return found


def _extract_fn(source: str, name: str) -> str:
    """用顶格闭合花括号抽取顶层壳函数定义。"""
    match = re.search(rf'^{re.escape(name)}\(\) \{{\n.*?^\}}', source, re.M | re.S)
    if not match:
        raise AssertionError(f'未找到函数定义: {name}()')
    return match.group(0) + '\n'


def _read_install_defs() -> str:
    src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
    return src[:src.index('# 命令行直通参数')]


def _read_portal_bundle_files(src: str):
    """直接从 install.sh 读取门户与计量文件清单，避免测试脚手架硬编码漂移。"""
    m_portal = re.search(r'^PORTAL_FILES="([^"]+)"', src, re.M)
    m_meter = re.search(r'^METER_FILES="([^"]+)"', src, re.M)
    if not m_portal or not m_meter:
        raise AssertionError('无法从 install.sh 解析 PORTAL_FILES 或 METER_FILES')
    return m_portal.group(1).split() + m_meter.group(1).split()


def _with_bash_path(env: dict):
    """Windows 下确保 Git Bash 所在目录位于 PATH 前列，避免找不到 tr / awk / sed。"""
    if os.name == 'nt' and BASH:
        bdir = str(Path(BASH).parent)
        cur = env.get('PATH', '')
        if bdir.lower() not in cur.lower():
            env['PATH'] = bdir + os.pathsep + cur
    return env


def _run_bash_file(script_text: str, stdin_bytes: bytes = b'', env_extra=None, cwd=None):
    """把脚本以纯 LF 落盘再运行，避免命令行长度限制与 Windows 文本模式注入 CR。"""
    with tempfile.TemporaryDirectory(prefix='hy2-issue78-sh-') as td:
        script_path = Path(td) / 'run.sh'
        script_path.write_bytes(script_text.encode('utf-8'))
        env = _with_bash_path(os.environ.copy())
        if env_extra:
            env.update(env_extra)
        proc = subprocess.run(
            [BASH, script_path.as_posix()],
            cwd=cwd or td,
            input=stdin_bytes,
            capture_output=True,
            env=env,
            timeout=60,
        )
        return (
            proc.returncode,
            proc.stdout.decode('utf-8', errors='replace'),
            proc.stderr.decode('utf-8', errors='replace'),
        )


def _free_local_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def _http_get(port: int, path: str, headers=None):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
    try:
        conn.request('GET', path, headers=headers or {})
        resp = conn.getresponse()
        body = resp.read()
        return resp.status, body
    finally:
        conn.close()


class _PortalServeRunner:
    """在当前测试进程内启动真实 portal.py serve 线程，验证落盘配置可真实启动并提供接口。"""

    def __init__(self, portal_json: Path, port: int, lock_path: Path):
        self.portal_json = portal_json
        self.port = port
        self.lock_path = lock_path
        self.proc = None

    def __enter__(self):
        env = os.environ.copy()
        env['HY2_CORE_OPERATION_LOCK'] = str(self.lock_path)
        self.proc = subprocess.Popen(
            [sys.executable, str(self.portal_json.parent / 'portal.py'), 'serve', str(self.portal_json)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        deadline = time.time() + 15
        while time.time() < deadline:
            if self.proc.poll() is not None:
                out, err = self.proc.communicate(timeout=5)
                raise AssertionError(
                    f'portal.py serve 提前退出 (rc={self.proc.returncode}): '
                    f'{out.decode("utf-8", "replace")}{err.decode("utf-8", "replace")}'
                )
            try:
                status, body = _http_get(self.port, '/api/health')
                if status == 200 and b'"ok"' in body:
                    return self
            except OSError:
                time.sleep(0.15)
        raise AssertionError(f'等待门户 127.0.0.1:{self.port}/api/health 就绪超时')

    def __exit__(self, exc_type, exc, tb):
        if self.proc:
            if self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(timeout=5)
            for stream in (self.proc.stdout, self.proc.stderr):
                if stream:
                    stream.close()


@unittest.skipUnless(BASH, '需要 bash 环境')
class Issue78InstallE2ERegressionsTests(unittest.TestCase):
    """从 install.sh 安装主链路一路串联到真实 portal.py prepare / adopt / serve 的回归套件。"""

    def setUp(self):
        self.install_src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        self.awgctl_src = AWGCTL.read_text(encoding='utf-8').replace('\r\n', '\n')

    def _prepare_e2e_workspace(self, root: Path):
        """构造完整隔离测试目录，把真实门户整包与截取后的 install.sh 定义放进同一源码目录。"""
        src_dir = root / 'src'
        hy2_dir = root / 'etc' / 'hysteria'
        systemd_dir = root / 'etc' / 'systemd' / 'system'
        src_dir.mkdir(parents=True, exist_ok=True)
        hy2_dir.mkdir(parents=True, exist_ok=True)
        systemd_dir.mkdir(parents=True, exist_ok=True)

        for fname in _read_portal_bundle_files(self.install_src):
            shutil.copy2(REPO / fname, src_dir / fname)

        defs = _read_install_defs()
        defs = defs.replace('/etc/systemd/system', systemd_dir.as_posix())
        defs_path = src_dir / 'install_defs.sh'
        defs_path.write_bytes(defs.encode('utf-8'))
        return src_dir, hy2_dir, systemd_dir, defs_path

    def _run_chained_install(
        self,
        root: Path,
        stdin_bytes: bytes,
        env_extra=None,
        preserve_portal: bool = False,
        nft_fail_mode: str = 'none',
    ):
        """按真实安装顺序串联运行 install.sh 各核心阶段（含真实 portal.py prepare / adopt）。"""
        src_dir, hy2_dir, systemd_dir, defs_path = self._prepare_e2e_workspace(root)
        py_exe = Path(sys.executable).as_posix()
        lock_file = (root / 'core-operation.lock').as_posix()
        harness = src_dir / 'run_install_e2e.sh'

        if nft_fail_mode == 'ruleset_fail':
            nft_stub = 'nft() { return 1; }'
            cmd_override = (
                'command() {\n'
                '    if [[ "$1" == "-v" && "$2" == "nft" ]]; then return 0; fi\n'
                '    if [[ "$1" == "-v" && ( "$2" == "ufw" || "$2" == "firewall-cmd" ) ]]; then return 1; fi\n'
                '    builtin command "$@"\n'
                '}\n'
            )
        else:
            nft_stub = 'nft() { return 0; }'
            cmd_override = (
                'command() {\n'
                '    if [[ "$1" == "-v" && ( "$2" == "ufw" || "$2" == "firewall-cmd" || "$2" == "nft" || "$2" == "iptables" || "$2" == "ip6tables" ) ]]; then return 1; fi\n'
                '    builtin command "$@"\n'
                '}\n'
            )

        preserve_line = 'PRESERVE_PORTAL=1' if preserve_portal else 'PRESERVE_PORTAL=0'
        fake_bin = root / 'fake-hysteria'
        fake_bin.write_bytes(b'#!/usr/bin/env bash\necho "Version: v2.14.0"\n')
        fake_bin.chmod(0o755)
        script = f'''#!/usr/bin/env bash
set -eo pipefail
export HY2_CORE_OPERATION_LOCK="{lock_file}"
source "{defs_path.as_posix()}"

HY2_DIR="{hy2_dir.as_posix()}"
HY2_CONFIG="${{HY2_DIR}}/config.yaml"
HY2_CERT_DIR="${{HY2_DIR}}/cert"
HY2_META_FILE="${{HY2_DIR}}/client_meta.json"
HY2_BIN="{fake_bin.as_posix()}"
HY2_SERVICE="{(systemd_dir / 'hysteria-server.service').as_posix()}"
HY2_LOG_DROPIN="{(systemd_dir / 'hysteria-server.service.d' / 'loglevel.conf').as_posix()}"
AWG_CONFIG="{(root / 'no-awg.conf').as_posix()}"
PUBLIC_IP="203.0.113.78"
{preserve_line}

# 仅打桩系统特权/网络/守护进程边界；证书、端口校验、配置生成、门户整包校验、
# portal.py prepare/adopt、防火墙容错与凭据展示全部执行真实代码。
python3() {{ "{py_exe}" "$@"; }}
require_systemd_247() {{ return 0; }}
install_dependencies() {{ return 0; }}
port_owner() {{ echo ""; }}
clear_all_hopping_rules() {{ :; }}
setup_iptables_port_hopping() {{ :; }}
setup_cert_selfheal() {{ return 0; }}
systemctl() {{
    if [[ "$1" == "is-active" ]]; then
        if [[ "$*" == *hysteria-portal* ]]; then return 0; fi
        return 3
    fi
    return 0
}}
sleep() {{ :; }}
{nft_stub}
{cmd_override}

setup_certificates
setup_ports_and_obfs
generate_server_config
setup_system_firewall "$LISTEN_PORT" "$HOP_START" "$HOP_END"
show_client_configs
show_teyir_access
printf 'E2E_SUMMARY listen=%s sub=%s local=%s key=%s\\n' "$LISTEN_PORT" "$HY2_SUB_PORT" "$PORTAL_LOCAL_PORT" "$NODE_API_KEY"
'''
        harness.write_bytes(script.encode('utf-8'))
        env = _with_bash_path(os.environ.copy())
        if env_extra:
            env.update(env_extra)
        proc = subprocess.run(
            [BASH, harness.as_posix()],
            cwd=root.as_posix(),
            input=stdin_bytes,
            capture_output=True,
            env=env,
            timeout=90,
        )
        return (
            proc.returncode,
            proc.stdout.decode('utf-8', errors='replace'),
            proc.stderr.decode('utf-8', errors='replace'),
            hy2_dir,
            systemd_dir,
        )

    @unittest.skipUnless(HAS_JQ and HAS_OPENSSL, '端到端串联测试需要 jq 与 openssl')
    def test_e2e_interactive_first_install_auto_generated_api_key_and_live_portal(self):
        """复现第 78 号议题用户交互步骤：选 1 自签 -> 端口 12095 -> 密码回车 -> API Key 回车 -> 真起门户验收。"""
        locales = _available_utf8_locales()
        for loc in locales[:3]:
            with self.subTest(locale=loc), tempfile.TemporaryDirectory(prefix='hy2-e2e-auto-') as td:
                root = Path(td)
                # 交互序列：证书方式 1（自签）、监听端口 12095、密码回车自动生成、API Key 回车自动生成
                rc, out, err, hy2_dir, systemd_dir = self._run_chained_install(
                    root,
                    stdin_bytes=b'1\n12095\n\n\n',
                    env_extra={'LC_ALL': loc, 'LANG': loc},
                    nft_fail_mode='ruleset_fail',
                )
                self.assertEqual(rc, 0, f'locale={loc} 失败:\nSTDOUT:\n{out}\nSTDERR:\n{err}')
                self.assertIn('已生成新的节点通信 API Key。', out)
                self.assertNotIn('NODE_API_KEY 必须是不含空白和控制字符的纯 ASCII 字符串', out + err)
                self.assertIn('已跳过 nftables 自动放行', out)

                summary = re.search(
                    r'E2E_SUMMARY listen=(\d+) sub=(\d+) local=(\d+) key=(\S+)',
                    out,
                )
                self.assertIsNotNone(summary, f'缺少串联汇总输出:\n{out}')
                listen_port, sub_port, local_port, api_key = summary.groups()
                self.assertEqual(listen_port, '12095')
                self.assertTrue(api_key.startswith('hy2_sec_'), f'自动生成的 API Key 格式异常: {api_key}')

                # 核验关键产物全部真实落盘且一致
                cfg_text = (hy2_dir / 'config.yaml').read_text(encoding='utf-8')
                self.assertIn(f'listen: :{listen_port}', cfg_text)
                self.assertIn(f'url: http://127.0.0.1:{local_port}/auth', cfg_text)
                self.assertIn(f'listenHTTPS: :{sub_port}', cfg_text)
                self.assertTrue((hy2_dir / 'usage-meter-config.json').is_file())
                self.assertTrue((systemd_dir / 'hysteria-portal.service').is_file())

                portal_data = json.loads((hy2_dir / 'portal.json').read_text(encoding='utf-8'))
                access_raw = (hy2_dir / 'portal-access.json').read_text(encoding='utf-8')
                access_data = json.loads(access_raw)
                self.assertEqual(portal_data['api_key'], api_key)
                self.assertEqual(access_data['api_key'], api_key)
                self.assertEqual(portal_data['port'], int(local_port))
                self.assertIn(access_data['url'], out)
                self.assertIn(access_data['api_key'], out)

                # 核验页面里的 Teyir 接入卡片与磁盘 portal-access.json 逐字节一致
                m_card = re.search(r'id="teyir-access-json"[^>]*>(.*?)</textarea>', portal_data['page'], re.S)
                self.assertIsNotNone(m_card, '门户首页缺少接入卡片')
                self.assertEqual(html.unescape(m_card.group(1)), access_raw)

                # 真正启动落盘后的 portal.py serve 并走真实 HTTP 接口验收
                with _PortalServeRunner(hy2_dir / 'portal.json', int(local_port), root / 'serve.lock'):
                    st_ok, body_ok = _http_get(
                        int(local_port), '/api/v1/node/meta',
                        headers={'Authorization': f'Bearer {api_key}'},
                    )
                    self.assertEqual(st_ok, 200, body_ok.decode('utf-8', 'replace'))
                    meta_obj = json.loads(body_ok.decode('utf-8'))
                    self.assertEqual(meta_obj['meta']['listen_port'], 12095)
                    self.assertEqual(meta_obj['meta']['subscription_port'], int(sub_port))
                    self.assertEqual(meta_obj['meta']['public_ip'], '203.0.113.78')

                    st_bad, _ = _http_get(
                        int(local_port), '/api/v1/node/meta',
                        headers={'Authorization': 'Bearer wrong-key-rejected'},
                    )
                    self.assertIn(st_bad, (401, 403))

    @unittest.skipUnless(HAS_JQ and HAS_OPENSSL, '端到端串联测试需要 jq 与 openssl')
    def test_e2e_interactive_custom_valid_api_key_then_preserve_reinstall_adopt(self):
        """首次安装自带合法自定义 NODE_API_KEY，随后保留门户重装走真实 portal.py adopt 沿用凭据。"""
        custom_key = 'Hy2_Custom!@#2026-Key~Ok'
        loc = _available_utf8_locales()[0]
        with tempfile.TemporaryDirectory(prefix='hy2-e2e-custom-') as td:
            root = Path(td)
            # 第一轮：交互选 1（自签），端口 12097，密码自定义，API Key 自定义
            rc1, out1, err1, hy2_dir, _ = self._run_chained_install(
                root,
                stdin_bytes=f'1\n12097\nCustomMasterPass99\n{custom_key}\n'.encode('utf-8'),
                env_extra={'LC_ALL': loc, 'LANG': loc},
            )
            self.assertEqual(rc1, 0, f'首次自定义密钥安装失败:\n{out1}\n{err1}')
            self.assertIn('已使用自定义节点通信 API Key。', out1)
            self.assertNotIn('已生成新的节点通信 API Key。', out1)

            portal_v1 = json.loads((hy2_dir / 'portal.json').read_text(encoding='utf-8'))
            access_v1 = json.loads((hy2_dir / 'portal-access.json').read_text(encoding='utf-8'))
            self.assertEqual(portal_v1['api_key'], custom_key)
            self.assertEqual(access_v1['api_key'], custom_key)

            # 第二轮：保留门户重装（修改监听端口到 12098，密码与 API Key 回车沿用）
            rc2, out2, err2, _, _ = self._run_chained_install(
                root,
                stdin_bytes=b'1\n12098\n\n\n',
                env_extra={'LC_ALL': loc, 'LANG': loc},
                preserve_portal=True,
            )
            self.assertEqual(rc2, 0, f'保留门户重装失败:\n{out2}\n{err2}')
            self.assertIn('已沿用现有 API Key。', out2)
            self.assertIn('已沿用现有门户的登录凭据、API Key 与全部用户。', out2)

            portal_v2 = json.loads((hy2_dir / 'portal.json').read_text(encoding='utf-8'))
            access_v2 = json.loads((hy2_dir / 'portal-access.json').read_text(encoding='utf-8'))
            meta_v2 = json.loads((hy2_dir / 'client_meta.json').read_text(encoding='utf-8'))
            self.assertEqual(portal_v2['token'], portal_v1['token'])
            self.assertEqual(portal_v2['api_key'], custom_key)
            self.assertEqual(access_v2['username'], access_v1['username'])
            self.assertEqual(access_v2['password'], access_v1['password'])
            self.assertEqual(meta_v2['listen_port'], 12098)

    @unittest.skipUnless(HAS_JQ and HAS_OPENSSL, '端到端串联测试需要 jq 与 openssl')
    def test_e2e_noninteractive_install_without_preset_api_key(self):
        """免交互模式（环境变量指定端口/密码/自签，stdin 为空）串联至真实 portal.py prepare 与服务探活。"""
        loc = _available_utf8_locales()[0]
        with tempfile.TemporaryDirectory(prefix='hy2-e2e-nonint-') as td:
            root = Path(td)
            rc, out, err, hy2_dir, _ = self._run_chained_install(
                root,
                stdin_bytes=b'',
                env_extra={
                    'LC_ALL': loc,
                    'LANG': loc,
                    'HY2_CERT_TYPE': '1',
                    'HY2_PORT': '12096',
                    'HY2_PASSWORD': 'NonInteractivePass2026',
                    'HY2_NODE_MODE': '2',
                },
            )
            self.assertEqual(rc, 0, f'免交互全链路安装失败:\n{out}\n{err}')
            self.assertIn('已生成新的节点通信 API Key。', out)
            portal_data = json.loads((hy2_dir / 'portal.json').read_text(encoding='utf-8'))
            access_data = json.loads((hy2_dir / 'portal-access.json').read_text(encoding='utf-8'))
            self.assertTrue(portal_data['api_key'].startswith('hy2_sec_'))
            self.assertEqual(portal_data['api_key'], access_data['api_key'])
            with _PortalServeRunner(hy2_dir / 'portal.json', portal_data['port'], root / 'serve.lock'):
                st, body = _http_get(
                    portal_data['port'], '/api/v1/node/meta',
                    headers={'Authorization': f'Bearer {portal_data["api_key"]}'},
                )
                self.assertEqual(st, 200, body.decode('utf-8', 'replace'))
                self.assertEqual(json.loads(body.decode('utf-8'))['meta']['listen_port'], 12096)

    def test_invalid_node_api_key_aborts_without_misleading_info(self):
        """非法 NODE_API_KEY（空白、中文、非 ASCII 重音、超长）必须拦截且绝不提前打印成功生成/沿用提示。"""
        fn_vp = _extract_fn(self.install_src, 'is_valid_port')
        fn_sp = _extract_fn(self.install_src, 'setup_ports_and_obfs')
        cases = [
            ('space_middle', 'bad key', '纯 ASCII'),
            ('space_leading', ' badkey', '纯 ASCII'),
            ('space_trailing', 'badkey ', '纯 ASCII'),
            ('chinese', '中文key', '纯 ASCII'),
            ('latin_accent', 'é_key', '纯 ASCII'),
            ('overlong', 'k' * 257, '256'),
        ]
        loc = _available_utf8_locales()[0]
        for label, bad_key, expect_err in cases:
            with self.subTest(case=label):
                script = (
                    'set -euo pipefail\n'
                    'CYAN="" GREEN="" YELLOW="" PLAIN=""\n'
                    'log_info() { printf "INFO:%s\\n" "$*"; }\n'
                    'log_warn() { printf "WARN:%s\\n" "$*"; }\n'
                    'log_err()  { printf "ERR:%s\\n" "$*" >&2; }\n'
                    'HY2_DIR="/tmp/hy2-nonexistent-issue78"\n'
                    'HY2_META_FILE="/tmp/hy2-nonexistent-issue78/meta.json"\n'
                    'HY2_PORT=12095\n'
                    'HY2_PASSWORD="ValidPass2026"\n'
                    'openssl() { echo "0123456789abcdef0123456789abcdef"; }\n'
                    'port_owner() { echo ""; }\n'
                    'systemctl() { return 1; }\n'
                    'clear_all_hopping_rules() { :; }\n'
                    'setup_iptables_port_hopping() { :; }\n'
                    + fn_vp + '\n' + fn_sp + '\n'
                    'if setup_ports_and_obfs; then echo "UNEXPECTED_OK"; exit 11; fi\n'
                    'echo "REJECTED_OK"\n'
                )
                rc, out, err = _run_bash_file(
                    script,
                    stdin_bytes=(bad_key + '\n').encode('utf-8'),
                    env_extra={'LC_ALL': loc, 'LANG': loc},
                )
                self.assertEqual(rc, 0, f'case={label} out={out} err={err}')
                self.assertIn('REJECTED_OK', out)
                self.assertIn(expect_err, err)
                self.assertNotIn('已生成新的节点通信 API Key', out, '校验失败前不得误报已生成')
                self.assertNotIn('已沿用现有 API Key', out, '校验失败前不得误报已沿用')
                self.assertNotIn('已使用自定义节点通信 API Key', out, '校验失败前不得误报自定义生效')

    def test_locale_collation_isolation_source_and_runtime_guards(self):
        """源码守卫 + 多区域实测：确保 [!-~] / [a-z] / [0-9a-f] 等纯 ASCII 范围正则不受区域排序污染。"""
        # 源码守卫（在无非 C locale 的精简环境中也能钉住回归）
        sp = _extract_fn(self.install_src, 'setup_ports_and_obfs')
        self.assertIn('LC_ALL=C', sp, 'setup_ports_and_obfs 必须在 C 区域下校验 NODE_API_KEY')
        self.assertNotIn('if [[ ! "$NODE_API_KEY" =~ ^[!-~]+$ ]]; then', sp,
                         '不得裸用受区域排序表影响的 [[ ! "$NODE_API_KEY" =~ ^[!-~]+$ ]]')
        for fn_name in (
            'hy2_verify_sha256',
            'is_valid_port',
            'is_valid_domain',
            'is_valid_email',
            'setup_cert_via_existing_caddy',
            'setup_cert_via_nginx',
            'setup_cert_via_dns_api',
            'setup_system_firewall',
        ):
            self.assertIn('LC_ALL=C', _extract_fn(self.install_src, fn_name),
                          f'{fn_name} 缺少 LC_ALL=C 纯 ASCII 区域隔离')
        self.assertIn('LC_ALL=C', _extract_fn(self.awgctl_src, 'validate_endpoint'))
        self.assertIn('LC_ALL=C', _extract_fn(self.awgctl_src, 'detect_wan_iface'))

        # 运行时多区域实测（覆盖宿主机可用全部 UTF-8 区域及 C 区域）
        fn_vp = _extract_fn(self.install_src, 'is_valid_port')
        fn_vd = _extract_fn(self.install_src, 'is_valid_domain')
        fn_ve = _extract_fn(self.install_src, 'is_valid_email')
        fn_sha = _extract_fn(self.install_src, 'hy2_sha256_file') + _extract_fn(self.install_src, 'hy2_verify_sha256')
        fn_sp = _extract_fn(self.install_src, 'setup_ports_and_obfs')
        fn_awg_ep = _extract_fn(self.awgctl_src, 'validate_endpoint')
        py_exe = Path(sys.executable).as_posix()

        for loc in _available_utf8_locales():
            with self.subTest(locale=loc):
                script = (
                    'set -euo pipefail\n'
                    'CYAN="" GREEN="" YELLOW="" PLAIN=""\n'
                    'log_info() { :; }; log_warn() { :; }; log_err() { :; }\n'
                    f'python3() {{ "{py_exe}" "$@"; }}\n'
                    'HY2_DIR="/tmp/hy2-locale-probe"\n'
                    'HY2_META_FILE="/tmp/hy2-locale-probe/meta.json"\n'
                    'HY2_PORT=12095\n'
                    'HY2_PASSWORD="LocalePass2026"\n'
                    'openssl() { echo "0123456789abcdef0123456789abcdef"; }\n'
                    'port_owner() { echo ""; }\n'
                    'systemctl() { return 1; }\n'
                    'clear_all_hopping_rules() { :; }\n'
                    'setup_iptables_port_hopping() { :; }\n'
                    + fn_vp + fn_vd + fn_ve + fn_sha + fn_sp + fn_awg_ep
                    + '''
setup_ports_and_obfs </dev/null || exit 21
[[ "$NODE_API_KEY" == "hy2_sec_0123456789abcdef0123456789abcdef" ]] || exit 22
is_valid_domain "hy2.example.com" || exit 23
if is_valid_domain "é.example.com"; then exit 24; fi
is_valid_email "ops@example.com" || exit 25
if is_valid_email "é@example.com"; then exit 26; fi
if hy2_verify_sha256 "/dev/null" "é123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"; then exit 27; fi
validate_endpoint "vpn.example.com:51820" || exit 28
if validate_endpoint "é.example.com:51820"; then exit 29; fi
echo "LOCALE_ALL_OK"
'''
                )
                rc, out, err = _run_bash_file(script, env_extra={'LC_ALL': loc, 'LANG': loc})
                self.assertEqual(rc, 0, f'locale={loc} out={out} err={err}')
                self.assertIn('LOCALE_ALL_OK', out)

    def test_setup_system_firewall_survives_restricted_nft_errors(self):
        """受限容器或无 nf_tables 内核时 nft list ruleset / list chain 失败不得因 pipefail 中止安装。"""
        fn_fw = _extract_fn(self.install_src, 'setup_system_firewall')
        # 用例 A：nft list ruleset 直接返回非零
        script_a = (
            'set -eo pipefail\n'
            'HY2_SUB_PORT=18080; CERT_TYPE=self_signed\n'
            'log_step() { :; }; log_info() { printf "INFO:%s\\n" "$*"; }\n'
            'log_warn() { printf "WARN:%s\\n" "$*"; }; log_err() { printf "ERR:%s\\n" "$*" >&2; }\n'
            'command() { if [[ "$1" == -v ]]; then [[ "$2" == nft ]]; return; fi; builtin command "$@"; }\n'
            'systemctl() { return 1; }\n'
            'nft() { return 1; }\n'
            + fn_fw
            + 'setup_system_firewall 12095 20000 40000\necho "FW_OK_A"\n'
        )
        rc_a, out_a, err_a = _run_bash_file(script_a)
        self.assertEqual(rc_a, 0, f'out={out_a} err={err_a}')
        self.assertIn('FW_OK_A', out_a)
        self.assertIn('WARN:', out_a)

        # 用例 B：nft list ruleset 返回拦截链，但 nft list chain 返回非零
        script_b = (
            'set -eo pipefail\n'
            'HY2_SUB_PORT=18080; CERT_TYPE=self_signed\n'
            'log_step() { :; }; log_info() { printf "INFO:%s\\n" "$*"; }\n'
            'log_warn() { printf "WARN:%s\\n" "$*"; }; log_err() { printf "ERR:%s\\n" "$*" >&2; }\n'
            'command() { if [[ "$1" == -v ]]; then [[ "$2" == nft ]]; return; fi; builtin command "$@"; }\n'
            'systemctl() { return 1; }\n'
            'nft() {\n'
            '    if [[ "$1 $2" == "list ruleset" ]]; then\n'
            '        printf "table inet fw {\\n  chain input {\\n    type filter hook input priority 0; policy drop;\\n  }\\n}\\n"\n'
            '        return 0\n'
            '    fi\n'
            '    return 1\n'
            '}\n'
            + fn_fw
            + 'setup_system_firewall 12095 20000 40000\necho "FW_OK_B"\n'
        )
        rc_b, out_b, err_b = _run_bash_file(script_b)
        self.assertEqual(rc_b, 0, f'out={out_b} err={err_b}')
        self.assertIn('FW_OK_B', out_b)
        self.assertIn('WARN:', out_b)

    def test_port_owner_survives_missing_ss_under_pipefail(self):
        """精简镜像缺 iproute2（无 ss 命令）时，port_owner 在 set -eo pipefail 下不得以 127 崩盘。"""
        fn_po = _extract_fn(self.install_src, 'port_owner')
        py_exe = Path(sys.executable).as_posix()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as holder:
            holder.bind(('0.0.0.0', 0))
            holder.listen(1)
            busy_port = holder.getsockname()[1]
            free_port = _free_local_port()
            script = (
                'set -eo pipefail\n'
                f'python3() {{ "{py_exe}" "$@"; }}\n'
                'command() {\n'
                '    if [[ "$1" == "-v" && "$2" == "ss" ]]; then return 1; fi\n'
                '    builtin command "$@"\n'
                '}\n'
                + fn_po
                + f'busy_res="$(port_owner tcp {busy_port})"\n'
                + f'free_res="$(port_owner tcp {free_port})"\n'
                + 'printf "BUSY=%s FREE=%s\\n" "$busy_res" "$free_res"\n'
            )
            rc, out, err = _run_bash_file(script)
            self.assertEqual(rc, 0, f'out={out} err={err}')
            self.assertIn('BUSY=unknown FREE=', out)

    @unittest.skipUnless(HAS_OPENSSL, '需要 openssl 生成测试证书')
    def test_select_local_certificate_survives_wildcard_only_san_under_pipefail(self):
        """证书 SAN 仅含通配符 *.example.com 时，select_local_certificate 在 set -eo pipefail 下须正常回退至 CN。"""
        script = (
            'set -eo pipefail\n'
            'GREEN="" YELLOW="" PLAIN=""\n'
            'log_err() { printf "ERR:%s\\n" "$*" >&2; }\n'
            'mkdir -p live/wild acme home\n'
            'openssl req -x509 -newkey rsa:2048 -nodes '
            '-keyout live/wild/privkey.pem -out leaf.pem -days 2 '
            '-subj "/CN=node.example.com" -addext "subjectAltName=DNS:*.example.com" >/dev/null 2>&1\n'
            'cat leaf.pem leaf.pem > live/wild/fullchain.pem\n'
            'find() {\n'
            '    local arg args=()\n'
            '    for arg in "$@"; do\n'
            '        case "$arg" in\n'
            '            /etc/letsencrypt/live) arg="$PWD/live" ;;\n'
            '            /root/.acme.sh) arg="$PWD/acme" ;;\n'
            '            /home) arg="$PWD/home" ;;\n'
            '        esac\n'
            '        args+=("$arg")\n'
            '    done\n'
            '    command find "${args[@]}"\n'
            '}\n'
            'SERVER_NAME=""\n'
            + _extract_fn(self.install_src, 'pem_cert_count')
            + _extract_fn(self.install_src, '_cert_key_usable')
            + _extract_fn(self.install_src, 'is_valid_domain')
            + _extract_fn(self.install_src, '_cert_matches_domain')
            + _extract_fn(self.install_src, 'select_local_certificate')
            + 'select_local_certificate </dev/null\n'
            + 'printf "SNI=%s\\n" "$SERVER_NAME"\n'
        )
        rc, out, err = _run_bash_file(script)
        self.assertEqual(rc, 0, f'out={out} err={err}')
        self.assertIn('SNI=node.example.com', out)

    def test_show_menu_status_survives_failing_binary_under_pipefail(self):
        """主菜单状态栏读取损坏或返回非零的核心二进制时，在 set -eo pipefail 下不得打崩主菜单。"""
        with tempfile.TemporaryDirectory(prefix='hy2-status-probe-') as td:
            root = Path(td)
            bad_bin = root / 'bad-hysteria'
            bad_bin.write_bytes(b'#!/usr/bin/env bash\nexit 1\n')
            bad_bin.chmod(0o755)
            cfg = root / 'config.yaml'
            cfg.write_bytes(b'auth:\n  type: http\n')
            script = (
                'set -eo pipefail\n'
                'GREEN="" RED="" YELLOW="" PLAIN=""\n'
                f'HY2_BIN="{bad_bin.as_posix()}"\n'
                f'HY2_CONFIG="{cfg.as_posix()}"\n'
                f'AWG_CONFIG="{(root / "no-awg.conf").as_posix()}"\n'
                'systemctl() { return 3; }\n'
                'traffic_suspended() { return 1; }\n'
                + _extract_fn(self.install_src, 'unit_state_text')
                + _extract_fn(self.install_src, 'show_menu_status')
                + 'show_menu_status\necho "STATUS_OK"\n'
            )
            rc, out, err = _run_bash_file(script)
            self.assertEqual(rc, 0, f'out={out} err={err}')
            self.assertIn('版本: 未知', out)
            self.assertIn('STATUS_OK', out)

    def test_resolve_domain_ips_survives_failing_resolvers_under_pipefail(self):
        """上游解析命令失败时 resolve_domain_ips 在 set -eo pipefail 下必须顺利走完回退链。"""
        fn_res = _extract_fn(self.install_src, 'resolve_domain_ips')
        script = (
            'set -eo pipefail\n'
            'getent() { return 2; }\n'
            'dig() { return 9; }\n'
            'nslookup() { return 1; }\n'
            'host() { return 1; }\n'
            'python3() { echo "203.0.113.88"; }\n'
            'command() {\n'
            '    if [[ "$1" == -v ]]; then\n'
            '        case "$2" in dig|nslookup|host|python3) return 0 ;; esac\n'
            '    fi\n'
            '    builtin command "$@"\n'
            '}\n'
            + fn_res
            + 'resolve_domain_ips "hy2.example.com" >"$PWD/ips.out"\n'
            + 'printf "IPS=%s\\n" "$(cat "$PWD/ips.out")"\n'
        )
        rc, out, err = _run_bash_file(script)
        self.assertEqual(rc, 0, f'out={out} err={err}')
        self.assertIn('IPS=203.0.113.88', out)


if __name__ == '__main__':
    unittest.main()
