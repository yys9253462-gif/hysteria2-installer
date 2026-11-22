"""回归测试：install.sh 核心更新锁防符号链接、AWG 拉取/安装清理陷阱、重配快照防符号链接与旧端口收回状态准确汇报。"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def _find_bash():
    for cand in (r'C:\Program Files\Git\bin\bash.exe', '/bin/bash', '/usr/bin/bash'):
        if Path(cand).is_file():
            return cand
    return shutil.which('bash')


BASH = _find_bash()


def _extract_fn(name: str) -> str:
    m = re.search(rf'^{re.escape(name)}\(\)\s*\{{.*?^\}}', INSTALL_SH, re.M | re.S)
    if not m:
        raise AssertionError(f'install.sh 中未找到函数 {name}()')
    return m.group(0)


def _run_bash(script: str):
    env = os.environ.copy()
    if os.name == 'nt':
        git_usr_bin = r'C:\Program Files\Git\usr\bin'
        git_bin = r'C:\Program Files\Git\bin'
        env['PATH'] = f'{git_bin};{git_usr_bin};' + env.get('PATH', '')
    return subprocess.run(
        [BASH, '-s'],
        input=script,
        capture_output=True,
        text=True,
        encoding='utf-8',
        timeout=30,
        env=env,
    )


class InstallCoreLockAwgFetchBackupSymlinkAndFwCloseGuardsTests(unittest.TestCase):
    def test_flow_update_core_rejects_symlink_lock_and_uses_append_umask_077(self):
        """flow_update_core 必须拒绝符号链接核心锁与二进制路径，且在 umask 077 下以追加方式打开锁文件。"""
        body = _extract_fn('flow_update_core')
        self.assertIn('-L "$_lock_file"', body, 'flow_update_core 必须拒绝符号链接形式的核心升级锁')
        self.assertIn('exec {update_lock_fd}>>"$_lock_file"', body,
                      'flow_update_core 应以追加模式 >> 打开锁文件而非截断模式 >')
        self.assertIn('-L "$HY2_BIN"', body, 'flow_update_core 应拒绝覆盖符号链接形式的核心二进制')

    def test_awg_fetch_and_ensure_ctl_reject_symlink_targets_and_register_return_traps(self):
        """awg_fetch_ctl 与 awg_ensure_ctl 必须拒绝符号链接目标并注册 RETURN 清理陷阱（调用后重挂）。"""
        fetch_body = _extract_fn('awg_fetch_ctl')
        ensure_body = _extract_fn('awg_ensure_ctl')
        self.assertIn('-L "$out"', fetch_body, 'awg_fetch_ctl 写入目标前必须拒绝符号链接 $out')
        self.assertRegex(fetch_body, r"trap\s+'.*'\s+RETURN",
                         'awg_fetch_ctl 必须注册 RETURN 清理陷阱防止残留临时文件')
        self.assertIn('-L "$AWG_CTL_BIN"', ensure_body,
                      'awg_ensure_ctl 必须拒绝符号链接形式的 $AWG_CTL_BIN')
        self.assertGreaterEqual(
            ensure_body.count('trap "$_awg_trap" RETURN'),
            2,
            'awg_ensure_ctl 须挂 RETURN 清理陷阱并在调用 awg_fetch_ctl 后重挂',
        )

    def test_backup_state_before_reconfigure_skips_symlink_sources_and_guards_backup_target(self):
        """backup_state_before_reconfigure 必须跳过符号链接源文件并保护快照目标不被符号链接劫持。"""
        body = _extract_fn('backup_state_before_reconfigure')
        self.assertIn('[[ -L "$f" ]]', body, '快照循环必须显式跳过符号链接源文件')
        self.assertIn('cp -p -- "$f"', body, 'cp -p 必须加 -- 防止路径参数注入')
        self.assertIn('! -L "${f}.bak-${snapshot_id}"', body, '快照目标路径必须校验非符号链接')

    @unittest.skipUnless(BASH, 'requires bash')
    def test_close_replaced_ports_does_not_claim_success_without_active_firewall_or_on_failure(self):
        """无活跃防火墙或规则删除失败时，close_replaced_ports 不得谎报「已收回」。"""
        body = _extract_fn('close_replaced_ports')
        is_valid = _extract_fn('is_valid_port')
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            (td_path / 'portal.json').write_text('{}', encoding='utf-8')
            # 场景 1：无 ufw 且无 firewalld，不应输出「已收回」
            script_none = f'''set -euo pipefail
HY2_DIR="{td_path.as_posix()}"
LISTEN_PORT=51000
HY2_SUB_PORT=52000
log_info() {{ echo "INFO: $*"; }}
log_warn() {{ echo "WARN: $*"; }}
command() {{ if [[ "$1" == -v ]]; then return 1; fi; builtin command "$@"; }}
{is_valid}
{body}
close_replaced_ports 44300 8999
'''
            proc1 = _run_bash(script_none)
            self.assertEqual(proc1.returncode, 0, proc1.stdout + proc1.stderr)
            self.assertNotIn('已收回旧端口', proc1.stdout, '无活跃防火墙时不得谎报已收回端口放行')

            # 场景 2：ufw active 但 delete allow 返回失败，应告警而非谎报已收回
            script_fail = f'''set -euo pipefail
HY2_DIR="{td_path.as_posix()}"
LISTEN_PORT=51000
HY2_SUB_PORT=52000
log_info() {{ echo "INFO: $*"; }}
log_warn() {{ echo "WARN: $*"; }}
ufw() {{ if [[ "$1" == status ]]; then echo "Status: active"; return 0; fi; return 1; }}
systemctl() {{ return 1; }}
command() {{ if [[ "$1" == -v ]]; then [[ "$2" == ufw ]]; return; fi; builtin command "$@"; }}
{is_valid}
{body}
close_replaced_ports 44300 8999
'''
            proc2 = _run_bash(script_fail)
            self.assertEqual(proc2.returncode, 0, proc2.stdout + proc2.stderr)
            self.assertNotIn('已收回旧端口', proc2.stdout, 'ufw 删除失败时不得谎报已收回')
            self.assertIn('WARN:', proc2.stdout, '防火墙删除失败时应发出告警提示')


if __name__ == '__main__':
    unittest.main()
