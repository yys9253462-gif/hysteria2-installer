"""回归测试：第 76 号议题（上游迁移 301 与下载站跟随触发退出码 63 导致无法获取版本号）全链路修复验证。"""

from __future__ import annotations

import ast
import base64
import copy
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import portal  # noqa: E402

INSTALL_SH = ROOT / 'install.sh'
PORTAL_PY = ROOT / 'portal.py'


def _find_bash() -> str | None:
    cands = []
    if os.name == 'nt':
        cands.extend([r'C:\Program Files\Git\bin\bash.exe', r'C:\Program Files\Git\usr\bin\bash.exe'])
    w = shutil.which('bash')
    if w:
        cands.append(w)
    for c in cands:
        if c and os.path.isfile(c) and not (os.name == 'nt' and 'system32' in c.lower()):
            return c
    return None


BASH = _find_bash()


def _extract_install_fn(src: str, name: str) -> str:
    m = re.search(rf'^{re.escape(name)}\(\)\s*\{{.*?^\}}', src, re.M | re.S)
    if not m:
        raise AssertionError(f'安装脚本中未找到函数 {name}()')
    return m.group(0)


def _extract_do_upgrade(src: str) -> str:
    m = re.search(r"cat > \"\$HY2_DIR/do_upgrade\.sh\" <<'EOUG'\n(.*?)\nEOUG\n", src, re.S)
    if not m:
        raise AssertionError('安装脚本中未找到内嵌 do_upgrade.sh')
    return m.group(1)


def _run_bash_file(script: str, cwd: Path, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    assert BASH is not None
    env = os.environ.copy()
    if os.name == 'nt':
        env['PATH'] = r'C:\Program Files\Git\bin;C:\Program Files\Git\usr\bin;' + env.get('PATH', '')
    if extra_env:
        env.update(extra_env)
    script_file = cwd / 'case.sh'
    script_file.write_bytes(script.encode('utf-8'))
    return subprocess.run(
        [BASH, script_file.name],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='replace',
        stdin=subprocess.DEVNULL,
        timeout=30,
        env=env,
    )


def _to_posix(path: Path) -> str:
    s = path.resolve().as_posix()
    if os.name == 'nt' and len(s) >= 2 and s[1] == ':':
        return '/' + s[0].lower() + s[2:]
    return s


# 严格模拟真实 curl 行为的桩逻辑：
# 1) 对 download.hysteria.network/app/latest/*，只要同时带重定向跟随(-L)且 --max-filesize < 25149602，
#    即使发 HEAD(-I) 也会返回退出码 63（Maximum file size exceeded），100% 复现第 76 号议题故障；
# 2) 对 api.github.com 的 301 模式，只有带 -L 才会跟随返回 tag_name，否则输出 228 字节 301 JSON；
# 3) 对 github.com/.../releases/latest 网页重定向，仅在允许模式返回 302 Location 头。
REALISTIC_CURL_STUB = r'''
curl() {
  local url="" dest="" follow=0 head=0 fail_http=0 max_fs=0 max_redirs=0
  local arg
  while [[ $# -gt 0 ]]; do
    arg="$1"
    case "$arg" in
      -o) dest="$2"; shift 2;;
      --max-filesize) max_fs="$2"; shift 2;;
      --max-filesize=*)
        echo "BAD_EQUALS_SYNTAX" >&2
        return 2;;
      --max-redirs) max_redirs="$2"; shift 2;;
      --max-time|--connect-timeout|--retry|--retry-delay|-H) shift 2;;
      --location) follow=1; shift;;
      --head) head=1; shift;;
      --fail) fail_http=1; shift;;
      --progress-bar) shift;;
      http://*|https://*) url="$arg"; shift;;
      -[!-]*)
        [[ "$arg" == *L* ]] && follow=1
        [[ "$arg" == *I* ]] && head=1
        [[ "$arg" == *f* ]] && fail_http=1
        shift;;
      *) shift;;
    esac
  done
  printf '%s|follow=%s|head=%s|max_fs=%s|max_redirs=%s\n' \
    "$url" "$follow" "$head" "$max_fs" "$max_redirs" >> "$CURL_LOG"

  case "$url" in
    https://api.github.com/repos/*/releases/latest)
      if [[ "${API_MODE:-ok}" == "fail" ]]; then
        return 22
      fi
      if [[ "${API_MODE:-ok}" == "301" ]]; then
        if [[ "$follow" == "1" ]]; then
          printf '{"tag_name":"%s"}\n' "${API_TAG:-app/v2.14.0}"
          return 0
        fi
        printf '{"message":"Moved Permanently","url":"https://api.github.com/repositories/257434373/releases/latest"}\n'
        return 0
      fi
      printf '{"tag_name":"%s"}\n' "${API_TAG:-app/v2.14.0}"
      return 0
      ;;
    https://download.hysteria.network/app/latest/*)
      # 精确复现 libcurl 行为：HEAD + -L 跟随到 25149602 字节目标文件，与 2MB 上限冲突必报退出码 63
      if [[ "$follow" == "1" && "$max_fs" -gt 0 && "$max_fs" -lt 25149602 ]]; then
        echo "curl: (63) Maximum file size exceeded" >&2
        return 63
      fi
      if [[ "${DL_MODE:-ok}" == "fail" ]]; then
        return 22
      fi
      if [[ "${DL_MODE:-ok}" == "evil" ]]; then
        printf 'HTTP/2 302\r\nlocation: https://download.hysteria.network/app/v2.14.0/../../evil\r\n'
        return 0
      fi
      printf 'HTTP/2 302\r\nlocation: https://download.hysteria.network/app/%s/hysteria-linux-amd64\r\n' "${DL_VER:-v2.14.0}"
      return 0
      ;;
    https://github.com/HyNetworks/hysteria/releases/latest)
      if [[ "${WEB_MODE:-ok}" == "fail" ]]; then
        return 22
      fi
      if [[ "${WEB_MODE:-ok}" == "encoded" ]]; then
        printf 'HTTP/2 302\r\nlocation: https://github.com/HyNetworks/hysteria/releases/tag/app%%2Fv2.14.0?ref=test\r\n'
        return 0
      fi
      if [[ "${WEB_MODE:-ok}" == "evil" ]]; then
        printf 'HTTP/2 302\r\nlocation: https://github.com/HyNetworks/hysteria/releases/tag/app/../../etc/passwd\r\n'
        return 0
      fi
      printf 'HTTP/2 302\r\nlocation: https://github.com/HyNetworks/hysteria/releases/tag/%s\r\n' "${WEB_TAG:-app/v2.14.0}"
      return 0
      ;;
    https://github.com/HyNetworks/hysteria/releases/download/app/v2.14.0/hashes.txt)
      printf '%s  build/hysteria-linux-amd64\n' "$PAYLOAD_SHA" > "$dest"
      return 0
      ;;
    https://github.com/HyNetworks/hysteria/releases/download/app/v2.14.0/hysteria-linux-amd64)
      printf '%s' "$PAYLOAD_B64" | base64 -d > "$dest"
      return 0
      ;;
  esac
  return 22
}
'''


# 当测试环境未预装 jq（如精简 Windows Git Bash）时，用当前 Python 解释器提供与 jq -r 等价的最小回退；
# Linux 测试机与持续集成环境装有真实 jq 时直接走真实 jq。
# 注意必须使用 -c 传递代码而不能用 heredoc，否则会覆盖管道传入的 stdin。
JQ_FALLBACK_SH = r'''
if ! command -v jq >/dev/null 2>&1; then
  jq() {
    local expr="" file=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -r|-e|-c) shift;;
        *)
          if [[ -z "$expr" ]]; then
            expr="$1"
          else
            file="$1"
          fi
          shift;;
      esac
    done
    "$PY_EXE" -c 'import json,sys
expr,path=sys.argv[1],sys.argv[2]
raw=open(path,encoding="utf-8").read() if path else sys.stdin.read()
try: obj=json.loads(raw)
except Exception: sys.exit(5)
if expr==".tag_name // empty":
    val=obj.get("tag_name") if isinstance(obj,dict) else None
    if val not in (None,False,""): print(val)
elif expr==".traffic_suspend.suspended // false":
    ts=obj.get("traffic_suspend") if isinstance(obj,dict) else None
    val=ts.get("suspended") if isinstance(ts,dict) else None
    print("true" if val is True else "false")
else: sys.exit(3)
' "$expr" "$file"
  }
fi
'''


@unittest.skipUnless(BASH, '需要 bash 执行离线壳脚本测试')
class InstallBinaryAndUpgradeIssue76Tests(unittest.TestCase):
    """覆盖 install_binary、do_upgrade.sh core 与 install_gost 的离线真实故障复现与防回归测试。"""

    def setUp(self) -> None:
        self.src = INSTALL_SH.read_text(encoding='utf-8').replace('\r\n', '\n')
        self.tmp = Path(tempfile.mkdtemp(prefix='hy2-issue76-'))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def _run_install_binary_case(self, case_env: dict[str, str],
                                 mutate_fn=None) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
        helpers = '\n'.join(
            _extract_install_fn(self.src, n)
            for n in (
                'hy2_sha256_file',
                'hy2_verify_sha256',
                'hy2_manifest_sha256',
                'hy2_fetch_manifest',
                'hy2_expected_sha256',
                'hy2_core_asset_arch',
            )
        )
        fn = _extract_install_fn(self.src, 'install_binary')
        if mutate_fn is not None:
            fn = mutate_fn(fn)
        case_dir = Path(tempfile.mkdtemp(dir=self.tmp))
        bin_path = case_dir / 'hysteria'
        bin_path.write_bytes(b'OLD_HY2_BINARY')
        curl_log = case_dir / 'curl.log'
        curl_log.write_text('', encoding='utf-8')
        payload = b'#!/bin/sh\necho "Version: v2.14.0"\n'
        payload_sha = hashlib.sha256(payload).hexdigest()
        payload_b64 = base64.b64encode(payload).decode('ascii')
        script = (
            'set -eo pipefail\n'
            'HY2_ARCH=amd64\n'
            f'HY2_BIN="{_to_posix(bin_path)}"\n'
            f'CURL_LOG="{_to_posix(curl_log)}"\n'
            f'PY_EXE="{_to_posix(Path(sys.executable))}"\n'
            f'PAYLOAD_SHA="{payload_sha}"\n'
            f'PAYLOAD_B64="{payload_b64}"\n'
            'log_step() { echo "STEP:$*"; }\n'
            'log_info() { echo "INFO:$*"; }\n'
            'log_warn() { echo "WARN:$*"; }\n'
            'log_err() { echo "ERR:$*"; }\n'
            + JQ_FALLBACK_SH + '\n'
            + helpers + '\n'
            + REALISTIC_CURL_STUB + '\n'
            + fn + '\n'
            'install_binary\n'
        )
        res = _run_bash_file(script, case_dir, extra_env=case_env)
        return res, bin_path, curl_log

    def test_install_binary_handles_api_301_redirect(self):
        """主渠道返回 301 重定向时，必须凭 -fsSL 跟随获取版本并走 HyNetworks/hysteria 校验安装。"""
        res, bin_path, curl_log = self._run_install_binary_case({'API_MODE': '301', 'DL_MODE': 'fail', 'WEB_MODE': 'fail'})
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn('v2.14.0', bin_path.read_text(encoding='utf-8'))
        log = curl_log.read_text(encoding='utf-8')
        self.assertIn('https://api.github.com/repos/HyNetworks/hysteria/releases/latest|follow=1|', log)
        self.assertIn('https://github.com/HyNetworks/hysteria/releases/download/app/v2.14.0/hashes.txt', log)
        self.assertNotIn('apernet/hysteria', log)

    def test_install_binary_download_site_fallback_avoids_curl_exit_63(self):
        """主渠道失败时，官方下载站必须走单跳 HEAD（不带 -L）以避开 25 MB 响应头触发的退出码 63。"""
        res, bin_path, curl_log = self._run_install_binary_case({'API_MODE': 'fail', 'DL_MODE': 'ok', 'WEB_MODE': 'fail'})
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn('v2.14.0', bin_path.read_text(encoding='utf-8'))
        log = curl_log.read_text(encoding='utf-8')
        self.assertIn(
            'https://download.hysteria.network/app/latest/hysteria-linux-amd64|follow=0|head=1|max_fs=2097152|',
            log,
        )
        self.assertNotIn('Maximum file size exceeded', res.stderr)

    def test_install_binary_web_release_redirect_third_tier_fallback(self):
        """接口与下载站均失败时，第三级 GitHub 发布页重定向兜底必须成功（含普通与百分号编码斜杠）。"""
        for mode in ('ok', 'encoded'):
            with self.subTest(web_mode=mode):
                res, bin_path, curl_log = self._run_install_binary_case(
                    {'API_MODE': 'fail', 'DL_MODE': 'fail', 'WEB_MODE': mode}
                )
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertIn('v2.14.0', bin_path.read_text(encoding='utf-8'))
                log = curl_log.read_text(encoding='utf-8')
                self.assertIn('https://github.com/HyNetworks/hysteria/releases/latest|follow=1|head=1|max_fs=2097152|max_redirs=5', log)

    def test_install_binary_fails_closed_when_all_three_sources_fail_or_malicious(self):
        """三路全失败或返回路径穿越标签时必须闭环拒放：返回非 0、原二进制不动、无暂存残留。"""
        for label, env_cfg in (
            ('all_fail', {'API_MODE': 'fail', 'DL_MODE': 'fail', 'WEB_MODE': 'fail'}),
            ('evil_tags', {'API_MODE': 'fail', 'DL_MODE': 'evil', 'WEB_MODE': 'evil'}),
        ):
            with self.subTest(case=label):
                res, bin_path, _ = self._run_install_binary_case(env_cfg)
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertEqual(bin_path.read_bytes(), b'OLD_HY2_BINARY')
                self.assertIn('ERR:无法确定 Hysteria 2 版本', res.stdout)
                leftovers = [p.name for p in bin_path.parent.iterdir() if p.name.startswith('.hysteria.new.')]
                self.assertEqual(leftovers, [], f'失败后残留暂存文件: {leftovers}')

    def test_do_upgrade_core_version_fetch_all_tiers_and_fail_closed(self):
        """内嵌 do_upgrade.sh core 须同步具备 301 跟随、下载站单跳防 63、发布页兜底与闭环拒放。"""
        body = _extract_do_upgrade(self.src)
        self.assertNotIn('apernet/hysteria', body)
        self.assertIn('https://api.github.com/repos/HyNetworks/hysteria/releases/latest', body)
        self.assertIn('curl -fsSI --max-time 20 --max-filesize 2097152 "https://download.hysteria.network/app/latest/${ASSET}"', body)

        def run_case(env_cfg: dict[str, str]):
            case_dir = Path(tempfile.mkdtemp(dir=self.tmp))
            hy_dir = case_dir / 'hy'
            hy_dir.mkdir()
            (hy_dir / 'portal.json').write_text('{"traffic_suspend":{"suspended":true}}', encoding='utf-8')
            bin_path = case_dir / 'hysteria'
            bin_path.write_bytes(b'#!/bin/sh\necho "Version: v2.13.0"\n')
            bin_path.chmod(0o755)
            curl_log = case_dir / 'curl.log'
            curl_log.write_text('', encoding='utf-8')
            payload = b'#!/bin/sh\necho "Version: v2.14.0"\n'
            payload_sha = hashlib.sha256(payload).hexdigest()
            payload_b64 = base64.b64encode(payload).decode('ascii')

            patched = (
                body.replace('/etc/hysteria', _to_posix(hy_dir))
                    .replace('/usr/local/bin/hysteria', _to_posix(bin_path))
            )
            # 在函数前缀注入受控桩并直接执行 core 分支
            wrapper = (
                'set -o pipefail\n'
                f'CURL_LOG="{_to_posix(curl_log)}"\n'
                f'PY_EXE="{_to_posix(Path(sys.executable))}"\n'
                f'PAYLOAD_SHA="{payload_sha}"\n'
                f'PAYLOAD_B64="{payload_b64}"\n'
                'uname() { echo x86_64; }\n'
                'flock() { return 0; }\n'
                'systemctl() { return 0; }\n'
                + JQ_FALLBACK_SH + '\n'
                + REALISTIC_CURL_STUB + '\n'
                'set -- core\n'
                + patched.split('\n', 1)[1]
            )
            res = _run_bash_file(wrapper, case_dir, extra_env=env_cfg)
            return res, bin_path, curl_log

        # 1) API 301 -> 跟随成功
        r1, b1, l1 = run_case({'API_MODE': '301', 'DL_MODE': 'fail', 'WEB_MODE': 'fail'})
        self.assertEqual(r1.returncode, 0, r1.stdout + r1.stderr)
        self.assertIn('v2.14.0', b1.read_text(encoding='utf-8'))
        self.assertIn('api.github.com/repos/HyNetworks/hysteria/releases/latest|follow=1|', l1.read_text(encoding='utf-8'))

        # 2) API 失败 -> 下载站单跳 HEAD 避开退出码 63 成功
        r2, b2, l2 = run_case({'API_MODE': 'fail', 'DL_MODE': 'ok', 'WEB_MODE': 'fail'})
        self.assertEqual(r2.returncode, 0, r2.stdout + r2.stderr)
        self.assertIn('v2.14.0', b2.read_text(encoding='utf-8'))
        self.assertIn('download.hysteria.network/app/latest/hysteria-linux-amd64|follow=0|head=1|max_fs=2097152|', l2.read_text(encoding='utf-8'))

        # 3) 前两路失败 -> 发布页 302 兜底成功
        r3, b3, _ = run_case({'API_MODE': 'fail', 'DL_MODE': 'fail', 'WEB_MODE': 'encoded'})
        self.assertEqual(r3.returncode, 0, r3.stdout + r3.stderr)
        self.assertIn('v2.14.0', b3.read_text(encoding='utf-8'))

        # 4) 三路全失败 -> 闭环拒放，旧核心未改动
        r4, b4, _ = run_case({'API_MODE': 'fail', 'DL_MODE': 'fail', 'WEB_MODE': 'fail'})
        self.assertNotEqual(r4.returncode, 0)
        self.assertIn('v2.13.0', b4.read_text(encoding='utf-8'))

    def test_install_gost_version_fetch_follows_redirects_and_falls_back_cleanly(self):
        """install_gost 获取最新版本必须带 -fsSL --max-redirs 5 --max-filesize 2097152，301 可跟随，失败则回落 v3.3.0。"""
        fn = _extract_install_fn(self.src, 'install_gost')
        m = re.search(r'^\s*GOST_LATEST=\$\(curl.*$', fn, re.M)
        self.assertIsNotNone(m, '未找到 GOST_LATEST 获取行')
        line = m.group(0)
        self.assertIn('-fsSL', line)
        self.assertIn('--max-redirs 5', line)
        self.assertIn('--max-filesize 2097152', line)
        self.assertIn('|| GOST_LATEST=""', line)

        # 提取版本解析与回落语句真跑一遍 301 与失败两种场景
        start = fn.index('GOST_LATEST=$(curl')
        end = fn.index('GOST_VER="${GOST_LATEST#v}"', start)
        snippet = fn[start:end] + 'GOST_VER="${GOST_LATEST#v}"\necho "GOT=$GOST_LATEST|$GOST_VER"\n'
        for mode, expect in (('301', 'GOT=v3.9.9|3.9.9'), ('fail', 'GOT=v3.3.0|3.3.0')):
            with self.subTest(api_mode=mode):
                case_dir = Path(tempfile.mkdtemp(dir=self.tmp))
                curl_log = case_dir / 'curl.log'
                curl_log.write_text('', encoding='utf-8')
                script = (
                    'set -eo pipefail\n'
                    f'CURL_LOG="{_to_posix(curl_log)}"\n'
                    f'PY_EXE="{_to_posix(Path(sys.executable))}"\n'
                    + JQ_FALLBACK_SH + '\n'
                    + REALISTIC_CURL_STUB + '\n'
                    + snippet
                )
                res = _run_bash_file(script, case_dir, extra_env={'API_MODE': mode, 'API_TAG': 'v3.9.9'})
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertIn(expect, res.stdout)


class PortalVersionFetchIssue76Tests(unittest.TestCase):
    """覆盖 portal.py 核心升级与版本检查接口的新仓库迁移、HEAD 探测、发布页兜底及无函数内导入约束。"""

    def test_upgrade_core_binary_uses_hynetworks_and_head_fallbacks(self):
        """_upgrade_core_binary_locked 须请求 HyNetworks/hysteria，且下载站与发布页回退均使用 HEAD 探测。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            binary = root / 'hysteria'
            backup_dir = root / 'backups'
            old_payload = b'\x7fELF-old'
            new_payload = b'\x7fELF-new-hysteria'
            binary.write_bytes(old_payload)
            expected_sha = hashlib.sha256(new_payload).hexdigest()

            class _HeadResp:
                def __init__(self, url: str):
                    self._url = url
                def __enter__(self):
                    return self
                def __exit__(self, *a):
                    return False
                def geturl(self):
                    return self._url

            # 场景一：API 失败 -> 下载站 HEAD 成功 -> 从 HyNetworks 拉 hashes.txt 与二进制
            seen_reqs = []
            seen_fetch_text = []
            seen_sha_urls = []

            def fake_fetch_text(url, timeout=10):
                seen_fetch_text.append(url)
                raise OSError('api rate limited')

            def fake_sha(url, asset):
                seen_sha_urls.append((url, asset))
                return expected_sha

            def fake_urlopen(req, timeout=20):
                seen_reqs.append((req.full_url, req.get_method()))
                if 'download.hysteria.network/app/latest/' in req.full_url:
                    self.assertEqual(req.get_method(), 'HEAD', '下载站探测必须为 HEAD，避免下载 25 MB 二进制流')
                    return _HeadResp('https://download.hysteria.network/app/v2.14.0/hysteria-linux-amd64')
                if 'github.com/HyNetworks/hysteria/releases/download/app/v2.14.0/hysteria-linux-amd64' in req.full_url:
                    return io.BytesIO(new_payload)
                raise AssertionError(f'非预期请求: {req.full_url}')

            def fake_run(args, **kwargs):
                if Path(args[0]).resolve() == binary.resolve():
                    return SimpleNamespace(returncode=0, stdout='Version: v2.13.0\n', stderr='')
                return SimpleNamespace(returncode=0, stdout='Version: v2.14.0\n', stderr='')

            with mock.patch.object(portal.platform, 'machine', return_value='x86_64'), \
                 mock.patch.object(portal, 'fetch_text', side_effect=fake_fetch_text), \
                 mock.patch.object(portal, 'fetch_expected_sha256', side_effect=fake_sha), \
                 mock.patch.object(portal.urllib.request, 'urlopen', side_effect=fake_urlopen), \
                 mock.patch.object(portal.subprocess, 'run', side_effect=fake_run), \
                 mock.patch.object(portal, '_unit_suspended', return_value=True):
                res = portal._upgrade_core_binary_locked(str(binary), str(backup_dir))

            self.assertTrue(res['changed'])
            self.assertEqual(seen_fetch_text, ['https://api.github.com/repos/HyNetworks/hysteria/releases/latest'])
            self.assertEqual(
                seen_sha_urls,
                [('https://github.com/HyNetworks/hysteria/releases/download/app/v2.14.0/hashes.txt', 'hysteria-linux-amd64')],
            )
            self.assertEqual(binary.read_bytes(), new_payload)

            # 场景二：API 与下载站双败 -> 第三级发布页 HEAD 兜底成功
            binary.write_bytes(old_payload)
            seen_reqs_2 = []

            def fake_urlopen_web(req, timeout=20):
                seen_reqs_2.append((req.full_url, req.get_method()))
                if 'download.hysteria.network/app/latest/' in req.full_url:
                    self.assertEqual(req.get_method(), 'HEAD')
                    raise OSError('download site unavailable')
                if req.full_url == 'https://github.com/HyNetworks/hysteria/releases/latest':
                    self.assertEqual(req.get_method(), 'HEAD')
                    return _HeadResp('https://github.com/HyNetworks/hysteria/releases/tag/app%2Fv2.14.0')
                if 'github.com/HyNetworks/hysteria/releases/download/app/v2.14.0/hysteria-linux-amd64' in req.full_url:
                    return io.BytesIO(new_payload)
                raise AssertionError(f'非预期请求: {req.full_url}')

            with mock.patch.object(portal.platform, 'machine', return_value='x86_64'), \
                 mock.patch.object(portal, 'fetch_text', side_effect=OSError('rate limit')), \
                 mock.patch.object(portal, 'fetch_expected_sha256', return_value=expected_sha), \
                 mock.patch.object(portal.urllib.request, 'urlopen', side_effect=fake_urlopen_web), \
                 mock.patch.object(portal.subprocess, 'run', side_effect=fake_run), \
                 mock.patch.object(portal, '_unit_suspended', return_value=True):
                res2 = portal._upgrade_core_binary_locked(str(binary), str(backup_dir))

            self.assertTrue(res2['changed'])
            self.assertIn(('https://github.com/HyNetworks/hysteria/releases/latest', 'HEAD'), seen_reqs_2)

            # 场景三：发布页返回恶意 file:// 或越界路径 -> 必须闭环拒放
            binary.write_bytes(old_payload)
            for bad_url in (
                'file:///releases/tag/app/v2.14.0',
                'https://github.com/HyNetworks/hysteria/releases/tag/app/../../evil',
            ):
                with self.subTest(bad_url=bad_url), \
                     mock.patch.object(portal.platform, 'machine', return_value='x86_64'), \
                     mock.patch.object(portal, 'fetch_text', side_effect=OSError('rate limit')), \
                     mock.patch.object(portal.urllib.request, 'urlopen', side_effect=[OSError('dl'), _HeadResp(bad_url)]), \
                     mock.patch.object(portal, 'fetch_expected_sha256') as mock_sha, \
                     mock.patch.object(portal.subprocess, 'run', side_effect=fake_run):
                    with self.assertRaisesRegex(RuntimeError, '无法确定 Hysteria 版本'):
                        portal._upgrade_core_binary_locked(str(binary), str(backup_dir))
                    mock_sha.assert_not_called()
                    self.assertEqual(binary.read_bytes(), old_payload)

    def test_check_version_uses_hynetworks_and_falls_back_to_web_head(self):
        """_h_get_check_version 须请求 HyNetworks/hysteria，接口限流时通过发布页 HEAD 拿到版本号。"""
        tree = ast.parse(PORTAL_PY.read_text(encoding='utf-8'))
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == '_h_get_check_version')

        # 确认无任何函数内 import
        inner_imports = [n for n in ast.walk(node) if isinstance(n, (ast.Import, ast.ImportFrom))]
        self.assertEqual(inner_imports, [], '_h_get_check_version 内严禁出现函数内 import')

        calls = []

        class _HeadResp:
            def __init__(self, url: str):
                self._url = url
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
            def geturl(self):
                return self._url

        def fake_request(url, headers=None, method=None):
            return SimpleNamespace(full_url=url, headers=headers or {}, method=method or 'GET')

        def fake_urlopen(req, timeout=5):
            calls.append((req.full_url, req.method))
            if 'api.github.com' in req.full_url:
                raise OSError('HTTP 403 rate limited')
            return _HeadResp('https://github.com/HyNetworks/hysteria/releases/tag/app/v2.14.0')

        env = dict(portal.__dict__)
        env.update({
            'parse_qs': parse_qs,
            '_ver_cache_lock': threading.Lock(),
            '_ver_cache': {'t': 1e12, 'shas': {}},
            '_core_ver_cache': {'t': 0.0, 'tag': ''},
            'subprocess': SimpleNamespace(run=lambda *a, **k: SimpleNamespace(stdout='Version: v2.13.0\n')),
            'urllib': SimpleNamespace(request=SimpleNamespace(Request=fake_request, urlopen=fake_urlopen)),
            'PORTAL_SELF': PORTAL_PY,
            '_local_blob_sha': lambda p: 'a' * 40,
            '_remote_root_shas': lambda: {},
            '_version_triple': lambda *a: ('', '', False),
            'usage_meter': None,
            'usage_summary': lambda u: {},
            'MASTER_USER_ID': '__master__',
            'AWG_CTL': '/nonexistent/awgctl',
        })
        exec(compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(node)], type_ignores=[])), '<cv>', 'exec'), env)

        class _Handler:
            path = '/tok/check-version'
            def is_authenticated(self):
                return True
            def reply_json(self, status, payload):
                return status, payload

        st, body = env['_h_get_check_version'](_Handler(), 'check-version')
        self.assertEqual(st, 200)
        self.assertEqual(body['core_latest'], '2.14.0')
        self.assertTrue(body['core_has_update'])
        self.assertEqual(calls, [
            ('https://api.github.com/repos/HyNetworks/hysteria/releases/latest', 'GET'),
            ('https://github.com/HyNetworks/hysteria/releases/latest', 'HEAD'),
        ])

    def test_preserve_head_redirect_handler_keeps_head_on_python311_and_registered_globally(self):
        """全局打开器必须注册 _PreserveHeadRedirectHandler，在 Python 3.9–3.11 重定向时不把 HEAD 降级为 GET。"""
        opener = urllib.request._opener
        self.assertIsNotNone(opener, '门户模块加载后应安装全局打开器')
        handler_names = [type(h).__name__ for h in opener.handlers]
        self.assertIn('GitHubTokenHandler', handler_names)
        redirect_handlers = [h for h in opener.handlers if isinstance(h, urllib.request.HTTPRedirectHandler)]
        self.assertEqual(len(redirect_handlers), 1, f'应仅存在一个重定向处理器，实际: {redirect_handlers}')
        self.assertEqual(type(redirect_handlers[0]).__name__, '_PreserveHeadRedirectHandler')

        # 精确模拟 Python 3.11 标准库基类 redirect_request 未透传 method 的缺陷：
        # 无论当前运行环境是 Python 3.11 还是 3.12+，都必须确认子类显式补回 method='HEAD'。
        handler = portal._PreserveHeadRedirectHandler()
        orig_head = urllib.request.Request('https://download.hysteria.network/app/latest/hysteria-linux-amd64', method='HEAD')
        orig_get = urllib.request.Request('https://api.github.com/repos/HyNetworks/hysteria/releases/latest', method='GET')

        def py311_base_redirect(self_h, req, fp, code, msg, headers, newurl):
            # Python 3.11 构造的新 Request 不带 method 参数（默认为 None -> GET）
            return urllib.request.Request(newurl)

        with mock.patch.object(urllib.request.HTTPRedirectHandler, 'redirect_request', py311_base_redirect):
            redirected_head = handler.redirect_request(
                orig_head, None, 302, 'Found', {}, 'https://download.hysteria.network/app/v2.14.0/hysteria-linux-amd64'
            )
            self.assertEqual(redirected_head.get_method(), 'HEAD')
            self.assertEqual(redirected_head.method, 'HEAD')

            redirected_get = handler.redirect_request(
                orig_get, None, 301, 'Moved Permanently', {}, 'https://api.github.com/repositories/257434373/releases/latest'
            )
            self.assertEqual(redirected_get.get_method(), 'GET')

    def test_global_opener_head_redirect_keeps_head_and_zero_body_over_http(self):
        """走全局打开器发起 HEAD 请求经历 302 跳转时，两跳均须为 HEAD 且响应体为 0 字节。"""
        seen = []

        class _RedirectProbeHandler(BaseHTTPRequestHandler):
            def do_HEAD(self):
                seen.append(('HEAD', self.path))
                if self.path == '/app/latest/hysteria-linux-amd64':
                    self.send_response(302)
                    self.send_header('Location', '/app/v2.14.0/hysteria-linux-amd64')
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header('Content-Length', '25149602')
                self.end_headers()

            def do_GET(self):
                seen.append(('GET', self.path))
                payload = b'SHOULD_NOT_DOWNLOAD_BODY' * 1024
                self.send_response(200)
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, fmt, *args):
                return

        server = HTTPServer(('127.0.0.1', 0), _RedirectProbeHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            # 显式使用当前已加载模块安装好的打开器（防止同进程其他测试替换全局 _opener）
            opener = urllib.request.build_opener(
                portal.GitHubTokenHandler(),
                portal._PreserveHeadRedirectHandler(),
            )
            req = urllib.request.Request(
                f'http://127.0.0.1:{port}/app/latest/hysteria-linux-amd64',
                method='HEAD',
            )
            with opener.open(req, timeout=5) as resp:
                body = resp.read()
                final = resp.geturl()
            self.assertEqual(seen, [
                ('HEAD', '/app/latest/hysteria-linux-amd64'),
                ('HEAD', '/app/v2.14.0/hysteria-linux-amd64'),
            ])
            self.assertEqual(body, b'')
            self.assertTrue(final.endswith('/app/v2.14.0/hysteria-linux-amd64'), final)
        finally:
            server.shutdown()
            server.server_close()

    def test_repo_invariants_no_legacy_apernet_or_bad_curl_flags_or_inner_imports(self):
        """全仓源码不再残留 apernet/hysteria、禁止 --max-filesize= 等号写法、关键文件无函数内 import。"""
        install_text = INSTALL_SH.read_text(encoding='utf-8')
        portal_text = PORTAL_PY.read_text(encoding='utf-8')
        self.assertNotIn('api.github.com/repos/apernet/hysteria', install_text)
        self.assertNotIn('github.com/apernet/hysteria', install_text)
        self.assertNotIn('apernet/hysteria', portal_text)
        self.assertNotIn('--max-filesize=', install_text)
        self.assertNotIn('--max-filesize=', portal_text)

        # 下载站直链探测行在 install.sh 全局（含 install_binary 与 do_upgrade.sh）均不得混用 -L
        dl_lines = [ln for ln in install_text.splitlines() if 'download.hysteria.network/app/latest/' in ln]
        self.assertEqual(len(dl_lines), 2, f'预期 install.sh 中恰有 2 处下载站探测，实际: {dl_lines}')
        for ln in dl_lines:
            self.assertIn('-fsSI ', ln)
            self.assertIn('--max-filesize 2097152', ln)
            self.assertNotIn('-fsSIL', ln)
            self.assertNotIn(' -L ', ln)


if __name__ == '__main__':
    unittest.main(verbosity=2)
