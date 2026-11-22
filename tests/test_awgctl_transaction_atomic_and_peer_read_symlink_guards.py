"""回归测试：awgctl.sh 事务快照/原子复制、peer 读取命令（list/client-conf/qr）符号链接拦截与 peer-del 控制字符守卫。"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
AWGCTL = (REPO / 'awgctl.sh').read_text(encoding='utf-8')


def _find_bash():
    for cand in (r'C:\Program Files\Git\bin\bash.exe', shutil.which('bash')):
        if cand and Path(cand).is_file():
            return cand
    raise RuntimeError('未找到可用 bash')


def _extract_fn(name):
    marker = f'{name}() {{'
    start = AWGCTL.index(marker)
    lines = AWGCTL[start:].splitlines()
    out = []
    for i, line in enumerate(lines):
        out.append(line)
        if i > 0 and line == '}':
            break
    return '\n'.join(out) + '\n'


class AwgctlTransactionAtomicAndPeerReadSymlinkGuardsTests(unittest.TestCase):
    def test_transaction_snapshot_and_atomic_helpers_reject_symlinks(self):
        """awg_transaction_snapshot、awg_atomic_copy_file、awg_atomic_install_bin 与 awg_transaction_restore 须拒绝符号链接并补 --。"""
        fn_snap = _extract_fn('awg_transaction_snapshot')
        self.assertGreaterEqual(fn_snap.count('[[ ! -L "$path" ]]'), 2)

        fn_cp = _extract_fn('awg_atomic_copy_file')
        self.assertIn('[[ ! -L "$dst" ]]', fn_cp)
        self.assertIn('dirname -- "$dst"', fn_cp)

        fn_inst = _extract_fn('awg_atomic_install_bin')
        self.assertIn('[[ ! -L "$dst" ]]', fn_inst)
        self.assertIn('dirname -- "$dst"', fn_inst)

        fn_rest = _extract_fn('awg_transaction_restore')
        self.assertIn('[[ ! -L "$AWG_DIR" ]]', fn_rest)
        self.assertIn('dirname -- "$AWG_SERVICE"', fn_rest)
        self.assertIn('rmdir -- "$AWG_DIR"', fn_rest)

    def test_peer_list_client_conf_qr_reject_symlink_peers_and_peer_del_rejects_ctrl(self):
        """cmd_peer_list / cmd_client_conf / cmd_qr 须拒符号链接 peers.json，cmd_peer_del 须拒控制字符名称。"""
        for name in ('cmd_peer_list', 'cmd_client_conf', 'cmd_qr'):
            fn = _extract_fn(name)
            self.assertIn('[[ -L "$AWG_PEERS_FILE" ]]', fn, f'{name} 缺少符号链接拦截')

        fn_del = _extract_fn('cmd_peer_del')
        self.assertIn('[[ "$name" =~ [[:cntrl:]] ]]', fn_del)

        fn_restore = _extract_fn('restore_peer_files')
        self.assertIn('rm -f -- "$AWG_CONFIG"', fn_restore)

    def test_runtime_atomic_copy_and_peer_del_ctrl_behavior(self):
        """真实 bash 行为测试：awg_atomic_copy_file 正常复制与 cmd_peer_del 拒含控制字符名称。"""
        bash = _find_bash()
        fn_del = _extract_fn('cmd_peer_del')
        script = (
            'set -euo pipefail\n'
            'die() { printf "DIE:%s\\n" "$*" >&2; exit 2; }\n'
            'require_root() { :; }\n'
            'require_jq() { :; }\n'
            'peers_init() { :; }\n'
            'peer_exists() { return 0; }\n'
            'AWG_PEERS_FILE="/tmp/nonexistent-peers.json"\n'
            'AWG_CONFIG="/tmp/nonexistent-awg.conf"\n'
            + fn_del
            + 'if ( cmd_peer_del $\'bad\\nname\' ); then exit 11; fi\n'
            + 'echo CTRL_REJECTED\n'
        )
        res = subprocess.run([bash, '-c', script], capture_output=True, text=True, errors='replace', timeout=15)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn('CTRL_REJECTED', res.stdout)
        self.assertIn('DIE:', res.stderr)


if __name__ == '__main__':
    unittest.main()
