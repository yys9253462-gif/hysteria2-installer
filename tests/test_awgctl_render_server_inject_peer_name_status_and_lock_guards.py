"""回归测试：awgctl.sh 的服务端配置防换行注入与溢出、peer-add 命名收紧、status 版本单行提取及 acquire_lock 防符号链接截断。"""

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AWGCTL = ROOT / 'awgctl.sh'


def _bash():
    git_bash = Path(r'C:\Program Files\Git\bin\bash.exe')
    if git_bash.is_file():
        return str(git_bash)
    return shutil.which('bash')


def _extract(src: str, name: str) -> str:
    m = re.search(rf'^{re.escape(name)}\(\) \{{\n.*?^\}}', src, re.M | re.S)
    if not m:
        raise AssertionError(f'未找到函数 {name}()')
    return m.group(0) + '\n'


class AwgctlRenderServerInjectPeerNameStatusAndLockGuardsTests(unittest.TestCase):
    def setUp(self):
        self.bash = _bash()
        if not self.bash:
            self.skipTest('需要 bash 环境')
        self.src = AWGCTL.read_text(encoding='utf-8').replace('\r\n', '\n')

    def _run(self, script: str) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory(prefix='hy2-awg59-') as td:
            p = Path(td) / 'run.sh'
            p.write_text('set -euo pipefail\n' + script, encoding='utf-8', newline='\n')
            return subprocess.run(
                [self.bash, str(p)],
                cwd=td,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=30,
            )

    def test_render_server_config_blocks_leading_zero_port_and_newline_key_injection(self):
        """render_server_config 须拒绝前导零/超长 port、含换行的 server_private_key/HeaderProtectionKey 与非法混淆参数。"""
        fn_src = _extract(self.src, 'render_server_config')
        self.assertIn('^[1-9][0-9]{0,4}$', fn_src)
        self.assertIn('^[0-9]{1,5}$', fn_src)
        self.assertIn('[[:space:][:cntrl:]]', fn_src)

        # 运行时验证含换行 server_private_key 与前导零端口都会被拦截
        stub = """
die() { echo "DIE:$*" >&2; exit 1; }
require_jq() { :; }
version_line() { echo "3"; }
detect_wan_iface() { echo "eth0"; }
AWG_DIR="."; AWG_CONFIG="./awg0.conf"; AWG_PEERS_FILE="./peers.json"
AWG_SUBNET="10.66.66"; AWG_LINK="awg0"
"""
        r_port = self._run(
            stub
            + 'meta_get() { case "$1" in port) echo "08443" ;; server_private_key) echo "PRIVKEY" ;; *) echo "15" ;; esac; }\n'
            + fn_src
            + 'render_server_config\n'
        )
        self.assertNotEqual(r_port.returncode, 0, '前导零 port 08443 必须被拒绝')

        r_key = self._run(
            stub
            + 'meta_get() { case "$1" in port) echo "51820" ;; server_private_key) printf "KEY\\nPostUp = pwn" ;; *) echo "15" ;; esac; }\n'
            + fn_src
            + 'render_server_config\n'
        )
        self.assertNotEqual(r_key.returncode, 0, '含换行的 server_private_key 必须被拒绝防 PostUp 注入')

    def test_cmd_peer_add_rejects_dot_dotdot_and_leading_hyphen_names(self):
        """cmd_peer_add 须拒绝 '.'、'..' 与以 '-' 开头的客户端名。"""
        fn_src = _extract(self.src, 'cmd_peer_add')
        self.assertIn('^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$', fn_src)
        stub = """
die() { echo "DIE:$*" >&2; exit 1; }
require_root() { :; }
require_jq() { :; }
is_installed() { return 0; }
"""
        for bad in ('.', '..', '-evil', '.hidden'):
            with self.subTest(bad=bad):
                r = self._run(stub + fn_src + f'cmd_peer_add "{bad}"\n')
                self.assertNotEqual(r.returncode, 0, f'客户端名 {bad!r} 必须被拒绝')

    def test_cmd_status_takes_first_version_line_and_acquire_lock_rejects_symlink_and_uses_append(self):
        """cmd_status 解析版本文件须只取首行；acquire_lock 须拒绝符号链接且用追加模式打开锁文件。"""
        st_src = _extract(self.src, 'cmd_status')
        self.assertIn('{print $2; exit}', st_src)

        lk_src = _extract(self.src, 'acquire_lock')
        self.assertIn('-L "$lock_file"', lk_src)
        self.assertIn('exec 9>>"$lock_file"', lk_src)


if __name__ == '__main__':
    unittest.main()
