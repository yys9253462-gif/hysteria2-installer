"""回归测试：install.sh install_gost 与 setup_portal 符号链接拒绝、umask 077 暂存与路径前置守卫。"""

import shutil
import subprocess
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


class InstallGostAndSetupPortalSymlinkUmaskAndOrderGuardsTests(unittest.TestCase):
    def test_install_gost_guards_symlinks_restore_and_selfcheck_umask(self):
        """install_gost 须前置拒符号链接目标路径、回滚函数拒符号链接目标，且自检暂存用 umask 077。"""
        fn = _extract_fn('install_gost')
        self.assertIn('[[ -L "$HY2_DIR" || -L "$GOST_BIN" || -L "$GOST_CONFIG" || -L "$GOST_UNIT" || -L /usr/local/lib/hy2-gost-selfcheck || -L "$HY2_DIR/.hy2-gost-owned" ]]', fn)
        self.assertIn('[[ ! -L "$_dst" ]] || return 1', fn)
        self.assertIn('_selfcheck_tmp="$(umask 077; mktemp "/usr/local/lib/hy2-gost-selfcheck.XXXXXX")"', fn)

    def test_setup_portal_validates_hy2_dir_upfront_and_guards_chmod_symlinks(self):
        """setup_portal 须在调用 portal.py 之前先拦截符号链接与含控制字符/%/$ 的 HY2_DIR，且 chmod 600 前拒符号链接。"""
        fn = _extract_fn('setup_portal')
        self.assertIn('[[ -L "$HY2_DIR" || "$HY2_DIR" =~ [[:cntrl:]%$] ]]', fn)
        self.assertLess(
            fn.index('[[ -L "$HY2_DIR" || "$HY2_DIR" =~ [[:cntrl:]%$] ]]'),
            fn.index('portal_write_meter_config'),
            'HY2_DIR 安全守卫必须前置在 portal_write_meter_config / portal.py 之前',
        )
        self.assertIn('for _pf in "$HY2_DIR/portal.py" "$HY2_DIR/portal.json" "$HY2_DIR/portal-access.json" "$HY2_META_FILE" "$HY2_CONFIG"; do', fn)
        self.assertIn('[[ ! -L "$_pf" ]]', fn)

        bash = _find_bash()
        script = (
            'set -euo pipefail\n'
            'log_err() { printf "ERR:%s\\n" "$*" >&2; }\n'
            'portal_write_meter_config() { echo "UNEXPECTED_CALL" >&2; exit 99; }\n'
            'portal_ensure_py() { echo "UNEXPECTED_CALL" >&2; exit 99; }\n'
            'HY2_DIR="/tmp/bad%n-dir"\n'
            'PORTAL_BUNDLE_PLACED=1\n'
            + fn
            + 'if setup_portal; then echo "ALLOWED_BAD_DIR"; exit 11; fi\n'
            + 'echo REJECTED_UPFRONT\n'
        )
        res = subprocess.run([bash, '-c', script], capture_output=True, text=True, errors='replace', timeout=15)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn('REJECTED_UPFRONT', res.stdout)
        self.assertNotIn('UNEXPECTED_CALL', res.stderr)


if __name__ == '__main__':
    unittest.main()
