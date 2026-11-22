"""回归测试：install.sh generate_server_config / toggle_warp.sh / sync_cert_meta / refresh_portal 符号链接、端口与写盘返回值守卫。"""

import re
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


class InstallGenerateConfigToggleWarpSyncCertAndRefreshGuardsTests(unittest.TestCase):
    def test_generate_server_config_guards_symlinks_ports_and_toggle_warp_bounds(self):
        """generate_server_config 须拒符号链接、校验三大端口，且 toggle_warp.sh 须拒符号链接配置与限探活大小。"""
        fn = _extract_fn('generate_server_config')
        self.assertIn('[[ -L "$HY2_DIR" || -L "$HY2_CONFIG" ]]', fn)
        self.assertIn('for _vp in "${LISTEN_PORT:-}" "${PORTAL_LOCAL_PORT:-}" "${HY2_SUB_PORT:-}"; do', fn)
        self.assertIn('10#$_vp < 1 || 10#$_vp > 65535', fn)

        m = re.search(r"cat > \"\$HY2_DIR/toggle_warp\.sh\" <<'EOTW'\n(.*?)\nEOTW", INSTALL_SH, re.S)
        self.assertIsNotNone(m)
        tw = m.group(1)
        self.assertIn('[[ ! -L "$CONFIG" && -f "$CONFIG" ]] || exit 1', tw)
        self.assertIn('--max-filesize 65536', tw)
        self.assertIn('[[ ! -L /etc/hysteria/portal.json ]]', tw)

    def test_sync_cert_meta_guards_symlinks_cert_path_ctrl_and_mv_rc(self):
        """sync_cert_meta 须拒符号链接配置/元数据、拦截脏证书路径并联合检查 chmod/mv 返回码。"""
        fn = _extract_fn('sync_cert_meta')
        self.assertIn('[[ -L "$HY2_META_FILE" || -L "$HY2_CONFIG" ]]', fn)
        self.assertIn('[[ "$cert_file" == -* || "$cert_file" =~ [[:cntrl:]] ]]', fn)
        self.assertIn('chmod 600 "$tmp_meta" && mv -f "$tmp_meta" "$HY2_META_FILE"', fn)

        bash = _find_bash()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            meta = root / 'client_meta.json'
            cfg = root / 'config.yaml'
            meta.write_text('{}', encoding='utf-8')
            cfg.write_text('tls:\n  cert: "-evil.crt"\n', encoding='utf-8')

            def to_posix(p):
                s = p.as_posix()
                return '/' + s[0].lower() + s[2:] if len(s) >= 2 and s[1] == ':' else s

            script = (
                'set -euo pipefail\n'
                'log_err() { printf "ERR:%s\\n" "$*" >&2; }\n'
                'log_warn() { :; }; log_info() { :; }\n'
                'jq() { return 0; }\n'
                'config_tls_cert() { printf "%s\\n" "-evil.crt"; }\n'
                'openssl() { echo "UNEXPECTED_OPENSSL:$*" >&2; exit 99; }\n'
                f'HY2_DIR="{to_posix(root)}"\n'
                f'HY2_CERT_DIR="{to_posix(root)}"\n'
                f'HY2_META_FILE="{to_posix(meta)}"\n'
                f'HY2_CONFIG="{to_posix(cfg)}"\n'
                + fn
                + 'if sync_cert_meta; then echo "ALLOWED_DASH_CERT"; exit 11; fi\n'
                + 'echo REJECTED\n'
            )
            res = subprocess.run([bash, '-c', script], capture_output=True, text=True, errors='replace', timeout=15)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn('REJECTED', res.stdout)
            self.assertNotIn('UNEXPECTED_OPENSSL', res.stderr)

    def test_refresh_portal_rejects_symlink_dir_and_files(self):
        """refresh_portal 须拒绝符号链接目录、portal.json 与 portal.py。"""
        fn = _extract_fn('refresh_portal')
        self.assertIn('[[ -L "$HY2_DIR" || -L "$HY2_DIR/portal.json" || -L "$HY2_DIR/portal.py" ]]', fn)


if __name__ == '__main__':
    unittest.main()
