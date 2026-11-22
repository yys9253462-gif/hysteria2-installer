"""回归测试：fix_cert_chain.sh 前导连字符/控制字符/符号链接防护与 panel-join.py 零TOCTOU读盘及HTTPError断连容错。"""

import importlib.util
import io
import os
import re
import shutil
import subprocess
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
FIX_CERT_SH = (REPO / 'fix_cert_chain.sh').read_text(encoding='utf-8')
PANEL_JOIN_SRC = (REPO / 'panel-join.py').read_text(encoding='utf-8')


def _load_panel_join():
    spec = importlib.util.spec_from_file_location('panel_join_mod', REPO / 'panel-join.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _find_bash():
    for cand in (r'C:\Program Files\Git\bin\bash.exe', shutil.which('bash')):
        if cand and Path(cand).is_file():
            return cand
    raise RuntimeError('未找到可用 bash')


def _extract_sh_fn(name):
    m = re.search(rf'^{re.escape(name)}\s*\(\)\s*\{{.*?^\}}', FIX_CERT_SH, re.M | re.S)
    if not m:
        raise AssertionError(f'fix_cert_chain.sh 中未找到函数 {name}')
    return m.group(0) + '\n'


class FixCertChainAndPanelJoinGuardsTests(unittest.TestCase):
    def test_fix_cert_chain_guards_ctrl_chars_leading_dash_and_symlink_writes(self):
        """fix_cert_chain.sh 须在 set_tls_cert/restore_config_file 拒符号链接与控制字符，并对前导 - 路径加 -- 防护。"""
        fn_set = _extract_sh_fn('set_tls_cert')
        fn_rst = _extract_sh_fn('restore_config_file')
        self.assertIn('[[:cntrl:]]', fn_set)
        self.assertIn('"$1" != -* && ! -L "$1" && -f "$1"', fn_set)
        self.assertIn('"$2" != -* && ! -L "$2"', fn_rst)
        self.assertIn('cp -a -- "$1" "$tmp"', fn_rst)
        self.assertIn("grep -Ec '^-----BEGIN CERTIFICATE-----[[:space:]]*$' --", FIX_CERT_SH)
        self.assertIn('dirname -- "$CERT_FILE"', FIX_CERT_SH)

        bash = _find_bash()
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'config.yaml'
            cfg.write_text('tls:\n  cert: "/etc/hysteria/a.crt"\n', encoding='utf-8')
            cfg_posix = cfg.as_posix()
            if len(cfg_posix) >= 2 and cfg_posix[1] == ':':
                cfg_posix = '/' + cfg_posix[0].lower() + cfg_posix[2:]
            # 包含垂直制表符 \x0b（不属于 \n\r\t 但属于 [[:cntrl:]]）必须被 set_tls_cert 拒绝
            script = (
                'set -uo pipefail\n'
                + fn_set
                + f'bad=$"/etc/hysteria/full\x0bchain.pem"\n'
                + f'if set_tls_cert "{cfg_posix}" "$bad"; then echo "ALLOWED_CTRL"; exit 11; fi\n'
                + 'echo REJECTED_CTRL\n'
            )
            res = subprocess.run([bash, '-c', script], capture_output=True, text=True, errors='replace', timeout=15)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn('REJECTED_CTRL', res.stdout)

    def test_panel_join_read_uses_o_nofollow_fstat_and_handles_http_error_read_oserror(self):
        """panel-join.py read() 须支持 O_NOFOLLOW+fstat 防 TOCTOU，且 HTTPError 读取断连不得未捕获崩溃。"""
        self.assertIn('O_NOFOLLOW', PANEL_JOIN_SRC)
        self.assertIn('os.fstat(fd)', PANEL_JOIN_SRC)

        pj = _load_panel_join()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = root / 'config.yaml'
            portal_f = root / 'portal.json'
            meta = root / 'client_meta.json'
            cfg.write_text('listen: :443\nmasquerade:\n  listenHTTPS: :8443\n', encoding='utf-8')
            portal_f.write_text('{"api_key": "testkey1234567890", "port": 22222}\n', encoding='utf-8')
            meta.write_text('{"server_name": "node.example.com", "is_insecure": false}\n', encoding='utf-8')

            class _BrokenHttpErr(urllib.error.HTTPError):
                def __init__(self):
                    super().__init__('https://panel.example.com/api/nodes', 502, 'Bad Gateway', {}, None)

                def read(self, amt=None):
                    raise OSError('connection reset while reading error body')

                def close(self):
                    raise OSError('close failed')

            argv = [
                'panel-join.py',
                '--config', str(cfg),
                '--portal', str(portal_f),
                '--meta', str(meta),
                '--register',
                '--panel', 'https://panel.example.com',
                '--admin-token', 'jwt-token-test-only',
            ]
            err_buf = io.StringIO()
            with patch('sys.argv', argv), \
                    patch.object(pj, '_open_no_redirect', side_effect=_BrokenHttpErr()), \
                    patch('sys.stderr', err_buf):
                rc = pj.main()
            self.assertEqual(rc, 1)
            self.assertIn('HTTP 502', err_buf.getvalue())


if __name__ == '__main__':
    unittest.main()
