"""回归测试：awgctl.sh 热增删防选项注入与空PSK处理、peer-add/del备份失败防残留私钥、peer-list损坏报错与纯数字流量列、原子复制陷阱及write_service防换行注入。"""

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / 'awgctl.sh').read_text(encoding='utf-8')
BASH = shutil.which('bash')


def _extract_fn(name: str) -> str:
    m = re.search(rf'(?m)^{re.escape(name)}\(\)\s*\{{.*?\n\}}', SRC, re.S)
    assert m, f'awgctl.sh 中未找到函数 {name}'
    return m.group(0)


class TestAwgctlLiveOpsBackupCleanupPeerListAndServiceGuards(unittest.TestCase):
    def test_peer_apply_live_add_and_del_block_option_injection_and_empty_psk(self):
        """peer_apply_live_add/del 必须拒绝以横杠开头或含空白控制字符的公钥，且空 psk 不传 preshared-key。"""
        add_body = _extract_fn('peer_apply_live_add')
        del_body = _extract_fn('peer_apply_live_del')

        self.assertIn('"$pub" != -*', add_body)
        self.assertIn('[[ -n "$psk" ]]', add_body)
        self.assertIn('"$pub" != -*', del_body)
        self.assertIn('[[:space:][:cntrl:]]', del_body)

        if BASH:
            # 实跑验证：pub 为 -evil 时不得把 -evil 交给 awg set，必须回落重启
            script = (
                'AWG_BIN=fake_awg; AWG_LINK=awg0; AWG_SERVICE_NAME=amneziawg-server\n'
                'service_active() { return 0; }\n'
                'log_warn() { echo "WARN:$*"; }\n'
                'die() { echo "DIE:$*"; exit 1; }\n'
                'fake_awg() { echo "AWG_CALLED:$*"; return 0; }\n'
                'awg_restart_service() { echo "RESTARTED"; return 0; }\n'
                + del_body + '\n'
                + 'peer_apply_live_del "-evil"\n'
            )
            r = subprocess.run([BASH, '-c', script], capture_output=True, text=True, timeout=15)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn('AWG_CALLED:', r.stdout, '前导横杠公钥不得被传入 awg set')
            self.assertIn('RESTARTED', r.stdout)

    def test_cmd_peer_add_and_del_clean_backup_files_before_die(self):
        """cmd_peer_add 与 cmd_peer_del 在备份失败触发 die（exit 1 不走 RETURN 陷阱）前必须清理已建备份文件。"""
        for name in ('cmd_peer_add', 'cmd_peer_del'):
            body = _extract_fn(name)
            self.assertIn('rm -f "${tmp:-}" "${peers_backup:-}" "${config_backup:-}"; die "无法备份客户端列表"', body)
            self.assertIn('rm -f "${tmp:-}" "${peers_backup:-}" "${config_backup:-}"; die "无法备份服务端配置"', body)

    def test_cmd_peer_list_guards_corrupt_peers_json_and_numeric_transfer_cols(self):
        """cmd_peer_list 遇到损坏 peers.json 必须给中文错误并退出，且 awk 只累加纯数字流量列。"""
        body = _extract_fn('cmd_peer_list')
        self.assertIn('客户端列表无法解析', body)
        self.assertIn('f[2] ~ /^[0-9]+$/ && f[3] ~ /^[0-9]+$/', body)

    def test_atomic_helpers_have_return_trap_and_write_service_blocks_newlines(self):
        """awg_atomic_copy_file/install_bin 必须补 RETURN 清理陷阱，write_service 必须拦路径换行注入。"""
        for fn_name in ('awg_atomic_copy_file', 'awg_atomic_install_bin'):
            body = _extract_fn(fn_name)
            self.assertIn("trap 'trap - RETURN; rm -f \"${tmp:-}\"' RETURN", body)

        ws = _extract_fn('write_service')
        self.assertIn('*$\'\\n\'*', ws, 'write_service 必须拦截含换行控制字符的路径/变量')


if __name__ == '__main__':
    unittest.main()
