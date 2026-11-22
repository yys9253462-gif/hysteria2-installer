"""回归测试：install.sh 与 awgctl.sh 跨函数 RETURN 陷阱覆写防护与自清不变式。"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')
AWG_SRC = (ROOT / 'awgctl.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def _find_bash():
    for cand in (r'C:\Program Files\Git\bin\bash.exe', shutil.which('bash')):
        if cand and os.path.isfile(cand):
            return cand
    return None


BASH = _find_bash()


def _extract_fn(src, name):
    m = re.search(rf'^{re.escape(name)}\(\)\s*\{{.*?^\}}', src, re.M | re.S)
    if not m:
        raise AssertionError(f'未找到函数 {name}')
    return m.group(0)


class ShellReturnTrapClobberAndCleanupGuardsTests(unittest.TestCase):
    @unittest.skipUnless(BASH, 'requires bash')
    def test_portal_ensure_py_rearms_return_trap_after_portal_fetch_py(self):
        """portal_fetch_py 内部使用并清空 RETURN 陷阱后，portal_ensure_py 仍须在后续失败时清理 stage 与 tmpdir。"""
        fn_body = _extract_fn(INSTALL_SRC, 'portal_ensure_py')
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / 'dest'
            dest.mkdir()
            script = f'''set -u
HY2_DIR="{dest.as_posix()}"
PORTAL_FILES="portal.py portal_assets.py"
METER_FILES="m1.py"
PORTAL_FETCH_ERR=""
PORTAL_FETCH_ALL_VERIFY_FAILED=0
log_err() {{ :; }}
portal_fetch_py() {{
    local out="$1"
    # 模拟 portal_remote_blob_shas 覆盖并清空全局 RETURN 陷阱
    trap 'trap - RETURN' RETURN
    printf 'ok' > "$out/portal.py"
    printf 'ok' > "$out/portal_assets.py"
    printf 'ok' > "$out/m1.py"
    return 0
}}
portal_files_ok() {{ return 0; }}
python3() {{ return 1; }}
{fn_body}
portal_ensure_py || true
'''
            proc = subprocess.run([BASH, '-s'], input=script, capture_output=True, text=True, encoding='utf-8', timeout=20)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            leftovers = [p.name for p in dest.iterdir() if p.name.startswith('.portal-bundle-')]
            self.assertEqual(leftovers, [], f'portal_ensure_py 的 stage 临时目录未清理: {leftovers}')

    def test_setup_cert_via_nginx_arms_trap_after_hy2_acme_ensure(self):
        """setup_cert_via_nginx 必须在 hy2_acme_ensure 之后注册 _nginx_tmp 的 RETURN 清理陷阱，防被覆盖。"""
        body = _extract_fn(INSTALL_SRC, 'setup_cert_via_nginx')
        idx_acme = body.index('hy2_acme_ensure || return 1')
        idx_trap = body.index('_nginx_tmp')
        trap_pos = body.find('RETURN', idx_acme)
        self.assertGreater(trap_pos, idx_acme, 'setup_cert_via_nginx 应在 hy2_acme_ensure 之后注册/重挂 RETURN 陷阱')
        self.assertIn('trap - RETURN', body[idx_acme:])
        self.assertGreater(idx_trap, 0)

    def test_flow_install_reconfigure_and_uninstall_rearm_lock_trap(self):
        """flow_install、flow_reconfigure 与 uninstall_all 调用子函数后须重挂锁释放 RETURN 陷阱。"""
        fi = _extract_fn(INSTALL_SRC, 'flow_install')
        fr = _extract_fn(INSTALL_SRC, 'flow_reconfigure')
        un = _extract_fn(INSTALL_SRC, 'uninstall_all')
        self.assertGreaterEqual(fi.count('trap "$_lock_trap" RETURN'), 3)
        self.assertGreaterEqual(fr.count('trap "$_lock_trap" RETURN'), 2)
        self.assertGreaterEqual(un.count('release_installer_core_lock; fi; trap - RETURN'), 2)

    def test_awgctl_return_traps_self_clear(self):
        """awgctl.sh 全部 RETURN 陷阱均须带 trap - RETURN 自清，防污染调用方作用域。"""
        for name in ('download_binaries', 'write_service', 'peer_apply_live_add', 'cmd_peer_add', 'cmd_peer_del'):
            body = _extract_fn(AWG_SRC, name)
            self.assertIn('RETURN', body, f'{name} 应含 RETURN 陷阱')
            self.assertIn('trap - RETURN', body, f'{name} 的 RETURN 陷阱必须带 trap - RETURN 自清')


if __name__ == '__main__':
    unittest.main()
