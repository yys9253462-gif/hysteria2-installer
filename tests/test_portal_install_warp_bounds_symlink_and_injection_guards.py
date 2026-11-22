"""回归测试：_h_post_install_warp 内嵌安装脚本下载上限、符号链接、双列摘要、配置防注入及 hy2_conf 迁移读盘守卫。"""

import ast
import copy
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import portal  # noqa: E402

SOURCE = (REPO / 'portal.py').read_text(encoding='utf-8')
TREE = ast.parse(SOURCE)


def _find_bash():
    for cand in (r'C:\Program Files\Git\bin\bash.exe', shutil.which('bash')):
        if cand and Path(cand).is_file():
            return cand
    raise RuntimeError('未找到可用 bash')


def _warp_block():
    start = SOURCE.index('def _h_post_install_warp(self, prefix):')
    end = SOURCE.index('def do_HEAD(self):', start)
    return SOURCE[start:end]


class PortalInstallWarpBoundsSymlinkAndInjectionGuardsTests(unittest.TestCase):
    def test_embedded_warp_script_has_filesize_bounds_umask_symlink_and_field_guards(self):
        """内嵌 WARP 安装脚本须对所有 curl 限大小、统一 umask 077、拒符号链接并拦截控制字符字段。"""
        body = _warp_block()
        self.assertIn('[ -L "$WARP_OWNED_MARKER" ]', body)
        self.assertIn('[ -L "$dst" ]', body)
        self.assertIn("trap 'trap - RETURN; rm -f -- \"${tmp:-}\"' RETURN", body)
        self.assertIn('TD=$(umask 077; mktemp -d)', body)
        self.assertNotIn('TD=$(mktemp -d)', body)
        self.assertIn('--max-filesize=2097152', body)
        self.assertIn('--max-filesize=167772160', body)
        self.assertIn('--max-filesize 65536', body)
        self.assertIn('while [[ "$clean" == ./* ]]; do', body)
        self.assertIn('[[ "$WG_PRIV$WG_PUB$WG_EP$WG_ADDR" =~ [[:cntrl:]] ]]', body)
        self.assertIn('[ -L "$WG_DIR" ] || [ -L "$WGCF_ACCT" ] || [ -L "$WGCF_CONF" ] || [ -L "$WP_CFG" ]', body)

    def test_embedded_manifest_sha256_requires_two_fields_and_strips_nested_dot_slash(self):
        """manifest_sha256 须忽略注释行、要求严格双列 NF==2 并剥离多层 ./。"""
        body = _warp_block()
        m_start = body.index('manifest_sha256() {')
        m_end = body.index('\nverify_sha() {', m_start)
        fn_manifest = body[m_start:m_end] + '\n'
        bash = _find_bash()
        digest = 'a' * 64
        with tempfile.TemporaryDirectory() as td:
            man = Path(td) / 'checksums.txt'
            man.write_text(
                f'# comment {digest} wgcf_2.3.0_linux_amd64\n'
                f'{digest} extra_col wgcf_2.3.0_linux_amd64\n'
                f'{digest}  ././wgcf_2.3.0_linux_amd64\n',
                encoding='utf-8',
            )
            man_posix = man.as_posix()
            if len(man_posix) >= 2 and man_posix[1] == ':':
                man_posix = '/' + man_posix[0].lower() + man_posix[2:]
            script = (
                'set -euo pipefail\n'
                + fn_manifest
                + f'out="$(manifest_sha256 "{man_posix}" "wgcf_2.3.0_linux_amd64")"\n'
                + f'[[ "$out" == "{digest}" ]] || {{ echo "GOT:$out"; exit 11; }}\n'
                + 'echo OK\n'
            )
            res = subprocess.run([bash, '-c', script], capture_output=True, text=True, errors='replace', timeout=15)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn('OK', res.stdout)

            # 仅含多列/注释畸形行时必须拒绝
            man.write_text(
                f'# {digest} wgcf_2.3.0_linux_amd64\n'
                f'{digest} wgcf_2.3.0_linux_amd64 extra_junk\n',
                encoding='utf-8',
            )
            script2 = (
                'set -euo pipefail\n'
                + fn_manifest
                + f'if manifest_sha256 "{man_posix}" "wgcf_2.3.0_linux_amd64" >/dev/null; then exit 21; fi\n'
                + 'echo REJECTED\n'
            )
            res2 = subprocess.run([bash, '-c', script2], capture_output=True, text=True, errors='replace', timeout=15)
            self.assertEqual(res2.returncode, 0, res2.stdout + res2.stderr)
            self.assertIn('REJECTED', res2.stdout)

    def test_install_warp_hy2_conf_migration_rejects_symlink_and_oversized_and_tolerates_bad_utf8(self):
        """安装 WARP 成功后迁移 config.yaml 旧 40000 端口须拒绝符号链接/超 4 MiB 并容错坏 UTF-8。"""
        node = next(
            n for n in ast.walk(TREE)
            if isinstance(n, ast.FunctionDef) and n.name == '_h_post_install_warp'
        )
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'config.yaml'
            cfg.write_bytes(b'# bad \xff comment\n  addr: 127.0.0.1:40000\n')
            writes = []
            state = {'warp_enabled': False}
            env = dict(portal.__dict__)
            env.update({
                'Path': lambda p: cfg if str(p) == '/etc/hysteria/config.yaml' else Path(p),
                'data': state,
                'data_lock': threading.RLock(),
                'warp_apply_lock': threading.Lock(),
                '_warp_install_lock': threading.Lock(),
                'subprocess': SimpleNamespace(
                    run=lambda *a, **k: SimpleNamespace(returncode=0, stdout='ok', stderr='')
                ),
                'atomic_write_private': lambda p, b: writes.append((p, b)),
                'save_data': lambda: None,
            })
            exec(compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(node)], type_ignores=[])), '<iw>', 'exec'), env)
            fn = env['_h_post_install_warp']

            class _H:
                def is_authenticated(self): return True
                def _extend_deadline(self, seconds, heavy=False): return True
                def reply_json(self, st, body): return st, body
                def _reply_with_warp_apply(self, payload): return 200, dict(ok=True, **payload)

            # 1) 坏 UTF-8 不崩溃且成功迁移 40000 -> 19898
            st, body = fn(_H(), '/tok/')
            self.assertEqual(st, 200, body)
            self.assertEqual(len(writes), 1)
            self.assertIn(b'127.0.0.1:19898', writes[0][1])

            # 2) 超 4 MiB 不得读取也不得写入
            writes.clear()
            cfg.write_bytes(b'  addr: 127.0.0.1:40000\n' + b'#' * (4 * 1024 * 1024 + 32))
            st2, body2 = fn(_H(), '/tok/')
            self.assertEqual(st2, 200, body2)
            self.assertEqual(writes, [])

            # 3) 符号链接不得读取也不得写入
            cfg.write_text('  addr: 127.0.0.1:40000\n', encoding='utf-8')
            with patch.object(Path, 'is_symlink', autospec=True, side_effect=lambda p: p == cfg):
                st3, body3 = fn(_H(), '/tok/')
            self.assertEqual(st3, 200, body3)
            self.assertEqual(writes, [])


if __name__ == '__main__':
    unittest.main()
