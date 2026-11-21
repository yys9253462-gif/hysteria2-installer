"""回归测试：awgctl.sh 切换 AWG 3.x 必须校验全部 S1~S4 >= 12，且 cmd_peer_list 不得经 awk -v 传入多行流量数据。"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AWGCTL = ROOT / 'awgctl.sh'
BASH = shutil.which('bash')


@unittest.skipUnless(BASH, '需要 bash 环境')
class AwgctlLine3AndPeerListTests(unittest.TestCase):
    def test_update_to_line3_checks_all_s1_to_s4_ge_12(self):
        """从 2.x 切换到 3.x 时，即使 S4 >= 12，只要 S1/S2/S3 中任一项 < 12 也必须重新生成混淆参数。"""
        src = AWGCTL.read_text(encoding='utf-8').replace('\r\n', '\n')
        start = src.index('        if [[ "$line" == "3" ]]; then')
        end = src.index('        if [[ "$line" == "3" && -z "$(meta_get HeaderProtectionKey)"', start)
        block = src[start:end]

        with tempfile.TemporaryDirectory() as td:
            script = Path(td) / 'check_s1_s4.sh'
            script.write_text('\n'.join([
                'set -euo pipefail',
                'line=3',
                'REGEN=0',
                'log_warn() { :; }',
                'meta_get() {',
                '    case "$1" in',
                '        S1) echo 5 ;;',
                '        S2) echo 20 ;;',
                '        S3) echo 20 ;;',
                '        S4) echo 20 ;;',
                '        *) echo 0 ;;',
                '    esac',
                '}',
                'meta_set() { :; }',
                'gen_obfs_params() {',
                '    REGEN=1',
                '    AWG_JC=5; AWG_JMIN=20; AWG_JMAX=100',
                '    AWG_S1=20; AWG_S2=20; AWG_S3=20; AWG_S4=20',
                '    AWG_H1=100; AWG_H2=200; AWG_H3=300; AWG_H4=400',
                '}',
                'run_block() {',
                block,
                '}',
                'run_block',
                'echo "REGEN=$REGEN"',
            ]) + '\n', encoding='utf-8', newline='\n')
            res = subprocess.run([BASH, str(script)], capture_output=True, text=True,
                                 encoding='utf-8', errors='replace', timeout=15)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn('REGEN=1', res.stdout,
                          'S4>=12 但 S1=5<12 时未重新生成混淆参数，会写出违反 AWG 3.x 约束的配置')

    def test_cmd_peer_list_avoids_awk_dash_v_for_multiline_transfer_data(self):
        """cmd_peer_list 不应通过 awk -v 传入多行 transfer_data，避免 mawk 换行/反斜杠转义失败。"""
        src = AWGCTL.read_text(encoding='utf-8').replace('\r\n', '\n')
        start = src.index('cmd_peer_list() {')
        end = src.index('cmd_client_conf() {', start)
        fn = src[start:end]
        self.assertNotIn('-v tr="$transfer_data"', fn,
                         'cmd_peer_list 仍使用 awk -v 传递多行 transfer_data')
        self.assertIn('ENVIRON[', fn, 'cmd_peer_list 应通过 ENVIRON 读取 transfer_data')


if __name__ == '__main__':
    unittest.main()
