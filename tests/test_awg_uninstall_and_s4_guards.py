"""回归测试：awgctl.sh 卸载未安装单元时不卡死、非数字 S4 不炸算术错误且备份创建不留明文窗口。"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AWG = (ROOT / 'awgctl.sh').read_text(encoding='utf-8')
BASH = shutil.which('bash')


class AwgUninstallAndS4GuardsTests(unittest.TestCase):
    @unittest.skipUnless(BASH, 'requires bash')
    def test_cmd_uninstall_succeeds_when_service_unit_absent(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            awg_dir = td_path / 'etc/amnezia/amneziawg'
            awg_dir.mkdir(parents=True)
            (awg_dir / 'awg_meta.json').write_text('{"port":"51234"}', encoding='utf-8')
            fake_bin = td_path / 'bin'
            fake_bin.mkdir()
            (fake_bin / 'systemctl').write_bytes(
                b'#!/usr/bin/env bash\n'
                b'case "$1" in\n'
                b'  is-active) echo "inactive"; exit 3 ;;\n'
                b'  is-enabled) echo "not-found"; exit 4 ;;\n'
                b'  stop|disable) echo "Unit not found" >&2; exit 5 ;;\n'
                b'  daemon-reload) exit 0 ;;\n'
                b'esac\n'
                b'exit 0\n'
            )
            os.chmod(fake_bin / 'systemctl', 0o755)
            # 抽取出 cmd_uninstall 并在隔离环境变量下直接跑（跳过 require_root）
            m = re.search(r'(cmd_uninstall\(\) \{.*?\n\})', AWG, re.S)
            self.assertIsNotNone(m)
            script = (
                'set -euo pipefail\n'
                f'AWG_DIR="{awg_dir.as_posix()}"\n'
                f'AWG_META_FILE="{(awg_dir / "awg_meta.json").as_posix()}"\n'
                f'AWG_SERVICE="{(td_path / "etc/systemd/system/amneziawg-server.service").as_posix()}"\n'
                'AWG_SERVICE_NAME="amneziawg-server"\n'
                'AWG_LINK="awg0"\n'
                f'AWG_QUICK_BIN="{(td_path / "none").as_posix()}"\n'
                f'AWG_GO_BIN="{(td_path / "go").as_posix()}"\n'
                f'AWG_BIN="{(td_path / "awg").as_posix()}"\n'
                f'AWG_CTL_INSTALLED="{(td_path / "hy2-awgctl").as_posix()}"\n'
                'log_step(){ :; }; log_info(){ :; }; log_warn(){ :; }; log_err(){ echo "$*" >&2; }\n'
                'die(){ echo "$*" >&2; exit 1; }\n'
                'require_root(){ :; }; meta_get(){ echo ""; }; revoke_firewall(){ :; }; awg_restart_service(){ :; }\n'
                + m.group(1)
                + '\ncmd_uninstall\n'
            )
            env = dict(os.environ, PATH=str(fake_bin) + os.pathsep + os.environ.get('PATH', ''))
            res = subprocess.run([BASH, '-c', script], env=env, capture_output=True, text=True, timeout=15)
            self.assertEqual(res.returncode, 0, res.stderr + res.stdout)
            self.assertFalse(awg_dir.exists(), '半装残留目录未能被 cmd_uninstall 清理')

    def test_s4_numeric_validation_guards_against_corrupt_meta(self):
        self.assertNotIn('[[ -n "$(meta_get S1)" && "$line" == "3" && "${_s4:-0}" -lt 12 ]]', AWG,
                         'cmd_install 对非数字 S4 直接做 -lt 算术比较会报错崩溃')
        self.assertNotIn('if [[ "${s4:-0}" -lt 12 ]]; then', AWG,
                         'cmd_update 对非数字 S4 直接做 -lt 算术比较会报错崩溃')

    def test_peer_backup_uses_umask_077_for_empty_placeholder(self):
        self.assertNotIn('    else\n        : > "$config_backup"\n        chmod 600 "$config_backup"', AWG,
                         '空 config_backup 占位未在 umask 077 下创建')


if __name__ == '__main__':
    unittest.main()
