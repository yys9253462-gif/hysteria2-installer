"""回归测试：awgctl.sh 防火墙端口范围校验、peer 增删随机私密备份与退出清理陷阱，及自删参数安全传递。"""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AWGCTL = ROOT / 'awgctl.sh'


def _git_bash():
    for candidate in (r'C:\Program Files\Git\bin\bash.exe', r'C:\Program Files\Git\usr\bin\bash.exe'):
        if Path(candidate).is_file():
            return candidate
    return shutil.which('bash')


BASH = _git_bash()


def _extract_fn(src: str, name: str) -> str:
    start = src.index(f'{name}() {{\n')
    end = src.index('\n}\n', start) + 3
    return src[start:end]


class AwgFirewallPeerBackupAndUninstallQuoteTests(unittest.TestCase):
    @unittest.skipUnless(BASH, 'requires bash')
    def test_allow_and_revoke_firewall_reject_out_of_range_or_invalid_ports(self):
        """allow_firewall 与 revoke_firewall 必须校验端口处于 1..65535，拒绝 0 / 70000 / 非数字。"""
        src = AWGCTL.read_text(encoding='utf-8').replace('\r\n', '\n')
        allow_fn = _extract_fn(src, 'allow_firewall')
        revoke_fn = _extract_fn(src, 'revoke_firewall')

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            calls = td_path / 'fw.calls'
            for bad_port in ('0', '65536', '99999', 'abc', ''):
                script = td_path / 'run.sh'
                script.write_text('\n'.join([
                    'set -u',
                    'log_info() { :; }; log_warn() { :; }; log_err() { :; }',
                    f'ufw() {{ if [[ "$1" == status ]]; then echo "Status: active"; return 0; fi; echo "ufw $*" >> "{calls.as_posix()}"; }}',
                    'systemctl() { return 0; }',
                    f'firewall-cmd() {{ echo "fw $*" >> "{calls.as_posix()}"; }}',
                    allow_fn,
                    revoke_fn,
                    f'allow_firewall "{bad_port}" || true',
                    f'revoke_firewall "{bad_port}" || true',
                ]) + '\n', encoding='utf-8', newline='\n')
                subprocess.run([BASH, str(script)], capture_output=True, text=True,
                               encoding='utf-8', errors='replace', timeout=15)
            self.assertFalse(calls.exists(), '非法或越界端口不应触发 ufw / firewall-cmd 操作')

    def test_peer_add_and_del_use_mktemp_backups_with_return_trap_and_safe_uninstall(self):
        """cmd_peer_add / cmd_peer_del 须使用 mktemp 随机备份与 RETURN 清理陷阱，cmd_uninstall 须位置参数传参。"""
        src = AWGCTL.read_text(encoding='utf-8').replace('\r\n', '\n')
        for fn_name in ('cmd_peer_add', 'cmd_peer_del'):
            body = _extract_fn(src, fn_name)
            self.assertNotIn('.peers-backup.$$', body, f'{fn_name} 仍使用可预测的 PID 后缀备份文件名')
            self.assertNotIn('.conf-backup.$$', body, f'{fn_name} 仍使用可预测的 PID 后缀备份文件名')
            self.assertIn('mktemp "${AWG_DIR}/.peers-backup.XXXXXX"', body, f'{fn_name} 应使用 mktemp 创建随机备份')
            self.assertIn('trap \'rm -f', body, f'{fn_name} 缺少 RETURN 备份清理陷阱')

        uninstall = _extract_fn(src, 'cmd_uninstall')
        self.assertNotIn("rm -f '${AWG_CTL_INSTALLED}'", uninstall, 'cmd_uninstall 不得将路径直接拼入单引号命令串')
        self.assertIn('rm -f -- "$1"\' _ "$AWG_CTL_INSTALLED"', uninstall)


if __name__ == '__main__':
    unittest.main()
