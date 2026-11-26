"""回归测试：install.sh tar 安全校验、主核心安装、证书复用布尔解析、迁移路径防选项注入与凭据安全输出。"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
INSTALL_SH = (REPO / 'install.sh').read_text(encoding='utf-8')


def _find_bash():
    for cand in (r'C:\Program Files\Git\bin\bash.exe', shutil.which('bash')):
        if cand and Path(cand).is_file():
            return cand
    raise RuntimeError('未找到可用 bash')


def _extract_fn(name):
    marker = f'{name}() {{'
    start = INSTALL_SH.index(marker)
    lines = INSTALL_SH[start:].splitlines()
    out = []
    for i, line in enumerate(lines):
        out.append(line)
        if i > 0 and line == '}':
            break
    return '\n'.join(out) + '\n'


class InstallBinaryTarSafeCertReuseAndTeyirAccessGuardsTests(unittest.TestCase):
    def test_hy2_tar_listing_safe_strips_nested_dot_slash_and_blocks_colon_ctrl(self):
        """hy2_tar_listing_safe 须循环剥离多层 ./ 并拦截冒号与控制字符成员。"""
        fn = _extract_fn('hy2_tar_listing_safe')
        self.assertIn('while [[ "$clean" == ./* ]]; do', fn)
        self.assertIn('[[:cntrl:]]', fn)
        self.assertIn('*:*', fn)

    def test_install_binary_rejects_symlink_and_bounds_fallback_curl(self):
        """install_binary 须拒绝符号链接 HY2_BIN、为接口与发布页探测限制重定向与体积，且下载站直链不得混用 -L 与小体积上限。"""
        fn = _extract_fn('install_binary')
        self.assertIn('[[ -L "$HY2_BIN" ]]', fn)
        self.assertIn('--max-redirs 5 --max-filesize 2097152', fn)
        self.assertIn('mv -f -- "$staged" "$HY2_BIN"', fn)
        # 下载站指向 25 MB 二进制文件，仅允许单跳 HEAD 探测（-fsSI），严禁与 -L 混用触发退出码 63
        dl_lines = [ln for ln in fn.splitlines() if 'download.hysteria.network/app/latest/' in ln]
        self.assertTrue(dl_lines, 'install_binary 缺少官方下载站回退探测语句')
        for ln in dl_lines:
            self.assertIn('-fsSI ', ln, f'官方下载站探测必须采用单跳仅头模式 -fsSI: {ln}')
            self.assertIn('--max-filesize 2097152', ln, f'官方下载站单跳探测须限制体积上限: {ln}')
            self.assertNotIn('-fsSIL', ln, f'官方下载站直链禁止使用 -fsSIL（跟随 25 MB 响应头会触发退出码 63）: {ln}')
            self.assertNotIn(' -L ', ln, f'官方下载站直链禁止混用 -L 重定向跟随: {ln}')

    def test_reuse_existing_cert_and_setup_certificates_guards(self):
        """reuse_existing_cert_config 须拒符号链接并用 has(\"is_insecure\") 保真 false；setup_certificates 须拦截前导 - 迁移证书路径。"""
        fn_reuse = _extract_fn('reuse_existing_cert_config')
        self.assertIn('[[ -L "$HY2_CONFIG" || -L "$HY2_META_FILE" ]]', fn_reuse)
        self.assertIn('if has("is_insecure") then (.is_insecure|tostring) else "" end', fn_reuse)
        self.assertIn('"$cert" != -*', fn_reuse)

        fn_setup = _extract_fn('setup_certificates')
        self.assertIn('"$HY2_CUSTOM_CERT_FILE" == -*', fn_setup)
        self.assertIn('"$HY2_CUSTOM_KEY_FILE" == -*', fn_setup)

    def test_show_teyir_access_rejects_symlink_and_preserves_backslashes(self):
        """show_teyir_access 须拒符号链接并使用 printf 原样输出含反斜杠的密码凭据。"""
        fn = _extract_fn('show_teyir_access')
        self.assertIn('[[ -L "$access" ]]', fn)
        self.assertIn("printf '门户密码         : %b%s%b\\n'", fn)

        bash = _find_bash()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            acc = root / 'portal-access.json'
            acc.write_text('{"url":"https://a/t/","username":"u","password":"p\\\\n\\\\c1","api_key":"k\\\\t2"}', encoding='utf-8')
            p_posix = root.as_posix()
            if len(p_posix) >= 2 and p_posix[1] == ':':
                p_posix = '/' + p_posix[0].lower() + p_posix[2:]
            script = (
                'set -euo pipefail\n'
                'CYAN=""; GREEN=""; YELLOW=""; PLAIN=""\n'
                'log_err() { printf "ERR:%s\\n" "$*" >&2; }\n'
                'require_installed() { return 0; }\n'
                f'HY2_DIR="{p_posix}"\n'
                'jq() {\n'
                '  if [[ "$1" == "-e" ]]; then return 0; fi\n'
                '  case "$2" in\n'
                '    *url*) printf "%s\\n" "https://a/t/" ;;\n'
                '    *username*) printf "%s\\n" "u" ;;\n'
                '    *password*) printf "%s\\n" \'p\\n\\c1\' ;;\n'
                '    *api_key*) printf "%s\\n" \'k\\t2\' ;;\n'
                '  esac\n'
                '}\n'
                + fn
                + 'show_teyir_access\n'
            )
            res = subprocess.run([bash, '-c', script], capture_output=True, text=True, errors='replace', timeout=15)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn(r'p\n\c1', res.stdout)
            self.assertIn(r'k\t2', res.stdout)


if __name__ == '__main__':
    unittest.main()
