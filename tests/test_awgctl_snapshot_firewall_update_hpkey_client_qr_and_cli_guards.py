"""回归测试：awgctl.sh 事务快照防符号链接 AWG_DIR 与 -- 隔离、防火墙仅在真实成功时报告放行/收回、cmd_update 修复脏 HeaderProtectionKey、client-conf/qr 校验名称与损坏 peers.json 报错及 main() 参数校验。"""

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AWGCTL = (ROOT / 'awgctl.sh').read_text(encoding='utf-8')
BASH = shutil.which('bash')


def _extract_fn(name: str) -> str:
    m = re.search(rf'^{re.escape(name)}\(\) \{{.*?\n\}}', AWGCTL, re.M | re.S)
    assert m, f'awgctl.sh 未找到函数 {name}'
    return m.group(0)


class TestAwgctlSnapshotFirewallUpdateHpkeyClientQrAndCliGuards(unittest.TestCase):
    def test_snapshot_rejects_symlink_awg_dir_and_uses_double_dash(self):
        """awg_transaction_snapshot 必须拒绝符号链接 AWG_DIR 并给 cp -a 补 --，restore 给 rm -f 补 --。"""
        snap = _extract_fn('awg_transaction_snapshot')
        self.assertIn('[[ ! -L "$AWG_DIR" ]]', snap)
        self.assertIn('cp -a -- "$path"', snap)
        rest = _extract_fn('awg_transaction_restore')
        self.assertIn('rm -f -- "$path"', rest)

    def test_firewall_helpers_report_success_only_when_commands_succeed(self):
        """allow_firewall 与 revoke_firewall 只有在 ufw/firewall-cmd 真实成功时才输出成功日志，失败必须告警。"""
        allow = _extract_fn('allow_firewall')
        self.assertIn('if ufw allow "${port}/udp" >/dev/null 2>&1; then', allow)
        self.assertIn('log_warn "UFW 放行 ${port}/udp 失败', allow)
        self.assertIn('firewall-cmd --add-port="${port}/udp" --permanent >/dev/null 2>&1', allow)
        self.assertIn('&& firewall-cmd --reload >/dev/null 2>&1 || _fw_rc=$?', allow)
        self.assertIn('if (( _fw_rc == 0 )); then', allow)
        self.assertIn('log_warn "firewalld 放行 ${port}/udp 失败', allow)

        revoke = _extract_fn('revoke_firewall')
        self.assertIn('if ufw delete allow "${port}/udp" >/dev/null 2>&1; then', revoke)
        self.assertIn('firewall-cmd --remove-port="${port}/udp" --permanent >/dev/null 2>&1', revoke)
        self.assertIn('&& firewall-cmd --reload >/dev/null 2>&1 || _fw_rc=$?', revoke)
        self.assertIn('log_warn "firewalld 收回 ${port}/udp 失败', revoke)

    def test_cmd_update_regenerates_dirty_hpkey_and_rejects_blank_or_ctrl_genkey(self):
        """cmd_update 升至 3.x 时遇到含空白/控制字符的脏 HeaderProtectionKey 必须重新生成，且校验新密钥不含控制字符。"""
        upd = _extract_fn('cmd_update')
        self.assertIn('_cur_hp="$(meta_get HeaderProtectionKey)"', upd)
        self.assertIn('$_cur_hp" =~ [[:space:][:cntrl:]]', upd)
        self.assertIn('$_hp_key" =~ [[:space:][:cntrl:]]', upd)

    def test_client_conf_and_qr_validate_name_and_handle_corrupt_peers_json(self):
        """cmd_client_conf 与 cmd_qr 必须校验客户端名称正则并在 peers.json 损坏时给出清晰中文报错。"""
        for fn_name in ('cmd_client_conf', 'cmd_qr'):
            body = _extract_fn(fn_name)
            with self.subTest(fn=fn_name):
                self.assertIn('^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$', body)
                self.assertIn('客户端列表无法解析', body)

    def test_main_rejects_extra_args_for_peer_del_and_unknown_args_for_peer_list(self):
        """main() 必须拒绝 peer-del 多余参数与 peer-list 未知参数。"""
        main_body = _extract_fn('main')
        self.assertIn('[[ $# -eq 1 ]] || die "用法: hy2-awgctl peer-del <名称>"', main_body)
        self.assertIn('peer-list)', main_body)

        if BASH:
            r1 = subprocess.run([BASH, str(ROOT / 'awgctl.sh'), 'peer-del', 'alice', 'extra'],
                                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=15)
            self.assertNotEqual(r1.returncode, 0, 'peer-del 传多余参数必须拒绝')
            r2 = subprocess.run([BASH, str(ROOT / 'awgctl.sh'), 'peer-list', '--unknown-opt'],
                                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=15)
            self.assertNotEqual(r2.returncode, 0, 'peer-list 传未知选项必须拒绝')


if __name__ == '__main__':
    unittest.main()
