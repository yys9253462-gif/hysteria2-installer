"""回归测试：awgctl.sh detect_wan_iface 拒前导连字符、cmd_install 缺失S2/S3重生成与HP密钥清理及 status/meta 符号链接防护。"""

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
AWG_SRC = (REPO / 'awgctl.sh').read_text(encoding='utf-8')


def _find_bash():
    for cand in (r'C:\Program Files\Git\bin\bash.exe', shutil.which('bash')):
        if cand and Path(cand).is_file():
            return cand
    raise RuntimeError('未找到可用 bash')


def _extract_fn(name):
    m = re.search(rf'^{re.escape(name)}\(\)\s*\{{.*?^\}}', AWG_SRC, re.M | re.S)
    if not m:
        raise AssertionError(f'awgctl.sh 中未找到函数 {name}')
    return m.group(0) + '\n'


class AwgctlInstallWanSEmptyHpAndStatusSymlinkGuardsTests(unittest.TestCase):
    def test_detect_wan_iface_rejects_leading_dash_name(self):
        """detect_wan_iface 须拒绝前导连字符网卡名，避免 iptables -o 参数选项注入。"""
        fn = _extract_fn('detect_wan_iface')
        self.assertIn('"$wan" == -*', fn)

        bash = _find_bash()
        script = (
            'set -euo pipefail\n'
            'log_err() { printf "ERR:%s\\n" "$*" >&2; }\n'
            'ip() { echo "default via 10.0.0.1 dev -evil0"; }\n'
            + fn
            + 'if detect_wan_iface; then echo "ALLOWED_DASH_IFACE"; exit 11; fi\n'
            + 'echo REJECTED\n'
        )
        res = subprocess.run([bash, '-c', script], capture_output=True, text=True, errors='replace', timeout=15)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn('REJECTED', res.stdout)
        self.assertIn('非法', res.stderr)

    def test_cmd_install_sanitizes_hp_key_and_guards_client_meta_symlink(self):
        """cmd_install 须清洗脏 HeaderProtectionKey、校验新生成密钥无空白/控制字符，并拒读符号链接 client_meta.json。"""
        fn = _extract_fn('cmd_install')
        self.assertIn('[[ ! -L /etc/hysteria/client_meta.json && -f /etc/hysteria/client_meta.json ]]', fn)
        self.assertIn('[[ -n "$_cur_hp" && "$_cur_hp" =~ [[:space:][:cntrl:]] ]]', fn)
        self.assertIn('[[ ! "$_hp_key" =~ [[:space:][:cntrl:]] ]]', fn)

    def test_cmd_status_and_uninstall_guard_symlinks_and_double_dash(self):
        """cmd_status 须拒绝符号链接 peers/version 文件，cmd_uninstall 须对 dirname/rmdir/readlink 加 -- 防护。"""
        st = _extract_fn('cmd_status')
        self.assertIn('[[ ! -L "$AWG_PEERS_FILE" && -f "$AWG_PEERS_FILE" ]]', st)
        self.assertIn('[[ ! -L "$AWG_VERSION_FILE" && -f "$AWG_VERSION_FILE" ]]', st)
        un = _extract_fn('cmd_uninstall')
        self.assertIn('rmdir -- "$(dirname -- "$AWG_DIR")"', un)
        self.assertIn('readlink -f -- "$0"', un)


if __name__ == '__main__':
    unittest.main()
