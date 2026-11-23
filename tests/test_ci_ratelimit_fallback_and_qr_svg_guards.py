"""专项回归测试：持续集成令牌注入、安装脚本官方归档免限流回退、二维码注释规范化与容器自适应宽度。"""

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import portal  # noqa: E402
from test_user_modal_singbox import PAYLOAD, modal_block  # noqa: E402

INSTALL_SH = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')
SMOKE_SH = (ROOT / 'tests' / 'portal-py-fetch-smoke.sh').read_text(encoding='utf-8').replace('\r\n', '\n')
TESTS_YML = (ROOT / '.github' / 'workflows' / 'tests.yml').read_text(encoding='utf-8').replace('\r\n', '\n')
BUILD_AWG_YML = (ROOT / '.github' / 'workflows' / 'build-awg.yml').read_text(encoding='utf-8').replace('\r\n', '\n')
NODE = shutil.which('node')


def _find_bash():
    for cand in (r'C:\Program Files\Git\bin\bash.exe', r'C:\Program Files\Git\usr\bin\bash.exe', shutil.which('bash')):
        if cand and Path(cand).is_file():
            return cand
    return None


BASH = _find_bash()

# 模拟真实二维码工具默认输出：含声明头、生成器注释与宽高尺寸
REAL_QRENCODE_SVG = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<!-- Created with qrencode 4.1.1 (https://fukuchi.org/works/qrencode/) -->\n'
    '<svg xmlns="http://www.w3.org/2000/svg" width="228" height="228" viewBox="0 0 65 65">'
    '<rect width="65" height="65" fill="#ffffff"/>'
    '<path d="M4,4h7v7h-7z" fill="#000000"/>'
    '</svg>\n'
)


def _extract_install_fn(name):
    m = re.search(rf'^{re.escape(name)}\(\)\s*\{{.*?^\}}', INSTALL_SH, re.M | re.S)
    if not m:
        raise AssertionError(f'安装脚本中未找到函数 {name}')
    return m.group(0)


def _run_bash(script, cwd):
    env = os.environ.copy()
    if os.name == 'nt':
        env['PATH'] = r'C:\Program Files\Git\bin;C:\Program Files\Git\usr\bin;' + env.get('PATH', '')
    path = Path(cwd) / 'run.sh'
    path.write_text(script, encoding='utf-8', newline='\n')
    return subprocess.run(
        [BASH, path.name],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='replace',
        timeout=30,
        env=env,
    )


def _make_tar_gz(path, members):
    """按给定 (归档成员路径, 字节内容) 列表构造压缩归档包。"""
    with tarfile.open(path, 'w:gz') as tf:
        for arcname, raw in members:
            info = tarfile.TarInfo(name=arcname)
            info.size = len(raw)
            tf.addfile(info, io.BytesIO(raw))


def _blob_sha(raw):
    return hashlib.sha1(f'blob {len(raw)}\x00'.encode('ascii') + raw).hexdigest()


class CiAndInstallerRateLimitFallbackTests(unittest.TestCase):
    def test_workflows_use_node24_checkout_and_pass_token_to_portal_smoke(self):
        """工作流应升级检出组件消除弃用告警，且门户拉取冒烟步骤须注入平台令牌。"""
        self.assertNotIn('actions/checkout@v4', TESTS_YML)
        self.assertIn('actions/checkout@v5', TESTS_YML)
        self.assertNotIn('actions/checkout@v4', BUILD_AWG_YML)
        self.assertIn('actions/checkout@v5', BUILD_AWG_YML)

        smoke_idx = TESTS_YML.index('bash tests/portal-py-fetch-smoke.sh')
        block = TESTS_YML[max(0, smoke_idx - 500):smoke_idx + 80]
        self.assertIn('GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}', block)

        # 冒烟脚本本身必须抽取 curl 包装并落盘临时令牌文件
        self.assertRegex(SMOKE_SH, r'for fn in curl\b')
        self.assertIn('HY2_GITHUB_TOKEN_FILE=', SMOKE_SH)
        self.assertIn('GITHUB_TOKEN', SMOKE_SH)

    def test_no_curl7_incompatible_max_filesize_equals_syntax(self):
        """低版本 curl（如 Debian 12 的 7.88.1）不识别 --max-filesize=N 等号写法，全仓必须统一为空格形式。"""
        for rel in ('install.sh', 'portal.py', 'awgctl.sh', 'reinstall-debian13.sh', 'alpine2debian.sh'):
            text = (ROOT / rel).read_text(encoding='utf-8')
            self.assertNotIn('--max-filesize=', text, f'{rel} 存在低版本 curl 不兼容的 --max-filesize= 等号写法')

    @unittest.skipUnless(BASH, '需要 bash 执行脚本验证')
    def test_portal_remote_blob_shas_falls_back_to_official_archive_when_api_rate_limited(self):
        """目录接口撞限流时，必须自动回退官方提交归档包并算出逐字节一致的对象哈希。"""
        fn = _extract_install_fn('portal_remote_blob_shas')
        p_raw = b'def page_html():\n    return "ok"\n'
        a_raw = b'SCRIPT = r"""ok"""\n'
        ref = 'a' * 40
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            archive = root / 'repo.tar.gz'
            _make_tar_gz(archive, [
                (f'repo-{ref}/portal.py', p_raw),
                (f'repo-{ref}/portal_assets.py', a_raw),
                (f'repo-{ref}/tests/ignored.py', b'nested'),
            ])
            py_exe = Path(sys.executable).as_posix()
            script = f'''set -euo pipefail
AWG_REPO="owner/repo"
_n=0
mktemp() {{ _n=$((_n+1)); : > "./tmp_$_n"; printf './tmp_%s\\n' "$_n"; }}
python3() {{ "{py_exe}" "$@"; }}
curl() {{
  local url="" dest=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o) dest="$2"; shift 2;;
      --max-time|-H) shift 2;;
      http*) url="$1"; shift;;
      *) shift;;
    esac
  done
  case "$url" in
    *api.github.com*/contents/\\?ref=*) return 22;;
    https://github.com/owner/repo/archive/{ref}.tar.gz) cp "./repo.tar.gz" "$dest"; return 0;;
  esac
  return 22
}}
{fn}
portal_remote_blob_shas "{ref}"
'''
            res = _run_bash(script, root)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            lines = {ln.split()[0]: ln.split()[1] for ln in res.stdout.splitlines() if ln.strip()}
            self.assertEqual(lines, {
                'portal.py': _blob_sha(p_raw),
                'portal_assets.py': _blob_sha(a_raw),
            })

    @unittest.skipUnless(BASH, '需要 bash 执行脚本验证')
    def test_portal_remote_blob_shas_rejects_duplicate_or_multi_root_archives(self):
        """异常归档（同名重复文件、多顶层目录或空包）必须闭环拒放。"""
        fn = _extract_install_fn('portal_remote_blob_shas')
        ref = 'b' * 40
        py_exe = Path(sys.executable).as_posix()
        cases = {
            'duplicate': [
                (f'repo-{ref}/portal.py', b'one'),
                (f'repo-{ref}/portal.py', b'two'),
            ],
            'multi_root': [
                (f'repo-{ref}/portal.py', b'one'),
                ('other-root/portal_assets.py', b'two'),
            ],
            'empty': [],
        }
        for label, members in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                _make_tar_gz(root / 'bad.tar.gz', members)
                script = f'''set -u
AWG_REPO="owner/repo"
_n=0
mktemp() {{ _n=$((_n+1)); : > "./tmp_$_n"; printf './tmp_%s\\n' "$_n"; }}
python3() {{ "{py_exe}" "$@"; }}
curl() {{
  local url="" dest=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o) dest="$2"; shift 2;;
      --max-time|-H) shift 2;;
      http*) url="$1"; shift;;
      *) shift;;
    esac
  done
  case "$url" in
    *api.github.com*/contents/\\?ref=*) return 22;;
    https://github.com/owner/repo/archive/{ref}.tar.gz) cp "./bad.tar.gz" "$dest"; return 0;;
  esac
  return 22
}}
{fn}
portal_remote_blob_shas "{ref}"
'''
                res = _run_bash(script, root)
                self.assertNotEqual(res.returncode, 0, f'异常归档 {label} 不应通过: {res.stdout}')

    @unittest.skipUnless(BASH, '需要 bash 执行脚本验证')
    def test_portal_fetch_py_succeeds_under_full_api_ratelimit_and_reports_token_hint_when_all_down(self):
        """接口全限流时可凭订阅源、官方归档与加速源完成整包校验；全不可达时保留三源原因与令牌提示。"""
        fns = ('hy2_git_blob_sha', 'portal_remote_blob_shas', 'portal_verify_blobs',
               'portal_files_ok', 'portal_fetch_files', 'portal_fetch_py')
        helpers = '\n'.join(_extract_install_fn(n) for n in fns)
        ref = 'c' * 40
        meters = (
            'usage-meter-core-20261007-v1.py',
            'usage-meter-readers-20261007-v1.py',
            'usage-meter-runtime-20261007-v1.py',
            'usage-meter-xray-config-20261007-v1.py',
        )
        files = {
            'portal.py': b'def page_html():\n    return "ok"\n',
            'portal_assets.py': b'SCRIPT = r"""ok"""\n',
        }
        for m in meters:
            files[m] = b'ACCOUNTING_REVISION = "2026-10-12-real-usage-v2"\ndef ok():\n    return 1\n'

        py_exe = Path(sys.executable).as_posix()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src_dir = root / 'src'
            src_dir.mkdir()
            for name, raw in files.items():
                (src_dir / name).write_bytes(raw)
            _make_tar_gz(root / 'repo.tar.gz', [(f'repo-{ref}/{n}', r) for n, r in files.items()])
            out_dir = root / 'out'
            out_dir.mkdir()

            # 场景一：api.github.com 全部返回 22（模拟 403 限流），仅主站订阅源 + 官方归档 + 加速源可用
            script_ok = f'''set -u
AWG_REPO="owner/repo"
PORTAL_FILES="portal.py portal_assets.py"
METER_FILES="{' '.join(meters)}"
_n=0
mktemp() {{ _n=$((_n+1)); : > "./tmp_$_n"; printf './tmp_%s\\n' "$_n"; }}
python3() {{ "{py_exe}" "$@"; }}
curl() {{
  local url="" dest=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o) dest="$2"; shift 2;;
      --max-time|-H) shift 2;;
      http*) url="$1"; shift;;
      *) shift;;
    esac
  done
  case "$url" in
    https://api.github.com/*) return 22;;
    https://github.com/owner/repo/commits/main.atom)
      printf '<feed><link href="https://github.com/owner/repo/commit/{ref}"/></feed>'; return 0;;
    https://github.com/owner/repo/archive/{ref}.tar.gz)
      cp "./repo.tar.gz" "$dest"; return 0;;
    https://cdn.jsdelivr.net/gh/owner/repo@{ref}/*)
      cp "./src/$(basename "$url")" "$dest"; return 0;;
  esac
  return 22
}}
{helpers}
portal_fetch_py "./out"
echo "RC=$?"
'''
            res_ok = _run_bash(script_ok, root)
            self.assertEqual(res_ok.returncode, 0, res_ok.stdout + res_ok.stderr)
            self.assertIn('RC=0', res_ok.stdout)
            for name, raw in files.items():
                self.assertEqual((out_dir / name).read_bytes(), raw)

            # 场景二：两个官方身份源同时失败时，必须闭环拒绝且给出令牌配置提示
            script_fail = f'''set -u
AWG_REPO="owner/repo"
PORTAL_FILES="portal.py portal_assets.py"
METER_FILES="{' '.join(meters)}"
_n=0
mktemp() {{ _n=$((_n+1)); : > "./tmp_$_n"; printf './tmp_%s\\n' "$_n"; }}
python3() {{ "{py_exe}" "$@"; }}
curl() {{
  local url=""
  for a in "$@"; do [[ "$a" == http* ]] && url="$a"; done
  case "$url" in
    https://github.com/owner/repo/commits/main.atom)
      printf '<feed><link href="https://github.com/owner/repo/commit/{ref}"/></feed>'; return 0;;
  esac
  return 22
}}
{helpers}
portal_fetch_py "./out"; rc=$?
echo "RC=$rc"
printf 'ERR_BEGIN\\n%s\\nERR_END\\n' "$PORTAL_FETCH_ERR"
'''
            res_fail = _run_bash(script_fail, root)
            self.assertIn('RC=1', res_fail.stdout)
            for needle in ('[GitHub API]', '[jsDelivr]', '[raw.githubusercontent]', '/etc/hysteria/github-token'):
                self.assertIn(needle, res_fail.stdout)

    @unittest.skipUnless(BASH, '需要 bash 执行脚本验证')
    def test_curl_wrapper_survives_set_u_without_token_var(self):
        """开启未定义变量检查且未设令牌路径变量时，请求包装函数不得崩溃。"""
        fn = _extract_install_fn('curl')
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fake_bin = root / 'bin'
            fake_bin.mkdir()
            (fake_bin / 'curl').write_text('#!/usr/bin/env bash\necho "PASSTHROUGH:$*"\n', encoding='utf-8', newline='\n')
            (fake_bin / 'curl').chmod(0o755)
            script = f'''set -euo pipefail
PATH="./bin:$PATH"
unset HY2_GITHUB_TOKEN_FILE
{fn}
curl -fsSL "https://api.github.com/repos/a/b/commits/main"
'''
            res = _run_bash(script, root)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn('PASSTHROUGH:', res.stdout)


class QrSvgCommentNormalizationAndOverflowGuardsTests(unittest.TestCase):
    def test_normalize_qr_svg_strips_prolog_and_comment_and_blocks_xss(self):
        """规范化函数必须剥离声明头与生成器注释，并严格拦截注释包壳与脚本事件载体。"""
        norm = portal._normalize_qr_svg(REAL_QRENCODE_SVG)
        self.assertTrue(norm.startswith('<svg '), norm[:80])
        self.assertNotIn('<?xml', norm)
        self.assertNotIn('Created with qrencode', norm)
        self.assertIn('viewBox="0 0 65 65"', norm)

        # 字节输入与带字节顺序标记、多个注释同样应通过
        bom_multi = ('\ufeff' + '<!-- c1 -->\n' + REAL_QRENCODE_SVG).encode('utf-8')
        self.assertEqual(portal._normalize_qr_svg(bom_multi), norm)

        # 各类恶意或非矢量图输入必须一律拒绝
        bad_inputs = [
            '',
            None,
            '<!-- <svg xmlns="http://www.w3.org/2000/svg"></svg> --><div>not-svg</div>',
            '<div><svg></svg></div>',
            REAL_QRENCODE_SVG.replace('</svg>', '<script>alert(1)</script></svg>'),
            REAL_QRENCODE_SVG.replace('<svg ', '<svg onload="alert(1)" '),
            REAL_QRENCODE_SVG.replace('</svg>', '<foreignObject><body>x</body></foreignObject></svg>'),
            REAL_QRENCODE_SVG.replace('</svg>', '<a href="javascript:alert(1)">x</a></svg>'),
        ]
        for bad in bad_inputs:
            with self.subTest(bad=str(bad)[:45]):
                self.assertEqual(portal._normalize_qr_svg(bad), '')

    def test_share_page_extra_links_and_qr_svg_for_handle_real_qrencode_comment(self):
        """独立分享页、备用直链折叠框与二维码生成函数面对含注释输出必须正常渲染并剥离头部。"""
        page = portal.user_page_html(
            'n.example', 'n.example', 443, 'QUIC', 'bob', {'used_bytes': 0},
            'hysteria2://x@n.example:443', 'clash', '{}', REAL_QRENCODE_SVG, 'tok', 'k', 8443,
            extra_links=[('Reality', 'vless://ok', REAL_QRENCODE_SVG)],
        )
        self.assertNotIn('二维码生成失败', page)
        self.assertNotIn('Created with qrencode', page)
        self.assertIn('viewBox="0 0 65 65"', page)

        # 备用直链也必须拦住事件属性与外联对象，不能只拦 <script
        evil_extra = portal._extra_link_boxes([
            ('BadEvent', 'vless://ev', '<svg onload="alert(1)"></svg>'),
            ('BadFO', 'vless://fo', '<svg><foreignObject><body/></foreignObject></svg>'),
        ])
        self.assertNotIn('onload=', evil_extra)
        self.assertNotIn('foreignObject', evil_extra)

        fake_proc = subprocess.CompletedProcess(['qrencode'], 0, stdout=REAL_QRENCODE_SVG.encode('utf-8'), stderr=b'')
        with mock.patch.object(portal.subprocess, 'run', return_value=fake_proc):
            got = portal.qr_svg_for('hysteria2://x@n.example:443')
        self.assertIsNotNone(got)
        self.assertTrue(got.startswith('<svg '))
        self.assertNotIn('Created with qrencode', got)

    def test_qr_frame_svg_css_prevents_container_overflow(self):
        """样式表必须约束容器内嵌矢量图最大宽度与自适应高度，避免宽图溢出扫码框。"""
        style = portal.STYLE
        m = re.search(r'\.qr-frame\s+svg\s*\{([^}]*)\}', style)
        self.assertIsNotNone(m, '样式表缺少 .qr-frame svg 规则')
        body = m.group(1)
        self.assertIn('display:block', body)
        self.assertIn('max-width:100%', body)
        self.assertIn('height:auto', body)

    @unittest.skipUnless(NODE, '需要 node 验证前端弹窗与卡片渲染逻辑')
    def test_frontend_modal_and_cards_accept_qrencode_comment_and_block_xss(self):
        """前端多用户弹窗、入站代理弹窗与协议卡片须放行含生成器注释的矢量图并拦截伪装载体。"""
        js_user_modal = r"""
const assert = require('assert');
const mk = () => ({textContent: '', innerHTML: '', classList: {add() {}, remove() {}}, querySelectorAll: () => []});
const uModal = mk(), uModalBody = mk(), uModalTitle = mk(), uModalSub = mk(), uModalClose = mk();
const location = {origin: 'https://h.example.com:8443'};
const btn = {dataset: {uid: 'alice', token: 'tok', key: 'kkk'}, addEventListener(type, fn) { this.onclick = fn; }};
const document = {querySelectorAll: sel => (sel === '.btn-user-connect' ? [btn] : [])};
let qrValue = %s;
const fetch = async () => ({status: 200, ok: true, json: async () => (Object.assign({}, %s, {qr_svg: qrValue}))});
%s
(async () => {
  await btn.onclick();
  assert(uModalBody.innerHTML.includes('viewBox="0 0 65 65"'), '带 qrencode 注释的二维码应正常展示: ' + uModalBody.innerHTML);
  assert(!uModalBody.innerHTML.includes('二维码生成失败'), '合法二维码不应误报生成失败');

  qrValue = '<!-- <svg></svg> --><div>fake</div>';
  await btn.onclick();
  assert(uModalBody.innerHTML.includes('二维码生成失败'), '注释包壳的非 SVG 负载必须被拦截');
  assert(!uModalBody.innerHTML.includes('<div>fake</div>'), '恶意节点不得注入容器');
})().catch(e => { console.error(e); process.exitCode = 1; });
""" % (json.dumps(REAL_QRENCODE_SVG), json.dumps(PAYLOAD), modal_block(portal.SCRIPT))
        r1 = subprocess.run([NODE, '-e', js_user_modal], capture_output=True, text=True, encoding='utf-8', timeout=30)
        self.assertEqual(r1.returncode, 0, r1.stderr or r1.stdout)

        # 同时核验前端脚本内全部 7 处正则均已升级，不残留旧版漏注释写法
        self.assertNotIn(r'/^(?:<\?xml[\s\S]*?\?>\s*)?<svg\b/i', portal.SCRIPT)
        self.assertEqual(portal.SCRIPT.count(r'/^(?:(?:<\?xml[\s\S]*?\?>|<!--[\s\S]*?-->)\s*)*<svg\b/i'), 7)


if __name__ == '__main__':
    unittest.main(verbosity=2)
