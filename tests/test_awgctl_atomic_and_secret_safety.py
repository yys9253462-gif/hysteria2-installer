"""回归测试：awgctl.sh 服务端渲染失败清理含私钥临时文件、MTU 下限钳位、write_service/peers_init 原子化与 peer_apply_live_add 密钥清理。"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AWGCTL = ROOT / 'awgctl.sh'
SRC = AWGCTL.read_text(encoding='utf-8')


def _find_bash():
    for candidate in (r'C:\Program Files\Git\usr\bin\bash.exe', r'C:\Program Files\Git\bin\bash.exe', '/bin/bash'):
        if os.path.isfile(candidate):
            return candidate
    found = shutil.which('bash')
    if found and 'system32' not in found.lower():
        return found
    return None


class AwgctlAtomicAndSecretSafetyTests(unittest.TestCase):
    def _fn_body(self, fn_name: str) -> str:
        start = SRC.index(f'{fn_name}() {{')
        end = SRC.index('\n}\n', start) + 3
        return SRC[start:end]

    def test_write_service_and_peers_init_use_atomic_temp_rename(self):
        ws = self._fn_body('write_service')
        self.assertNotIn('cat > "$AWG_SERVICE"', ws,
                         'write_service 不应直接覆写目标单元文件，应经同目录临时文件原子替换')
        self.assertIn('mktemp', ws)
        self.assertIn('mv -f', ws)

        pi = self._fn_body('peers_init')
        self.assertNotIn('echo \'{"peers":[]}\' > "$AWG_PEERS_FILE"', pi,
                         'peers_init 不应以默认 umask 直接重定向写入目标文件')
        self.assertIn('umask 077', pi)
        self.assertIn('mv -f', pi)

    def test_render_server_config_and_peer_live_add_protect_and_clean_secret_temps(self):
        rc = self._fn_body('render_server_config')
        self.assertIn('umask 077', rc, 'render_server_config 含服务端私钥，创建临时文件前应设置 umask 077')
        self.assertIn('rm -f "$tmp"', rc, 'render_server_config 渲染失败时必须清理含私钥的临时文件')
        self.assertIn('1280', rc, 'render_server_config 应对异常 S4 做 MTU 下限钳位')

        pa = self._fn_body('peer_apply_live_add')
        self.assertIn('umask 077', pa, 'peer_apply_live_add 含预共享密钥，创建临时文件前应设置 umask 077')
        self.assertIn('trap', pa, 'peer_apply_live_add 应通过 RETURN 陷阱确保异常路径也清理 psk 临时文件')

    def test_render_server_config_clamps_corrupt_s4_and_cleans_temp_on_jq_failure(self):
        bash = _find_bash()
        if not bash or not shutil.which('jq'):
            self.skipTest('需要 POSIX bash 与 jq')
        with tempfile.TemporaryDirectory() as td:
            td_posix = Path(td).as_posix()
            awg_posix = AWGCTL.as_posix()
            # 1) 验证损坏的 S4=9999 时 MTU 被钳位到 >=1280（而非负数）
            script = f"""
set -euo pipefail
source "{awg_posix}"
AWG_DIR="{td_posix}"
AWG_META_FILE="{td_posix}/meta.json"
AWG_PEERS_FILE="{td_posix}/peers.json"
AWG_CONFIG="{td_posix}/awg0.conf"
detect_wan_iface() {{ echo eth0; }}
cat > "$AWG_META_FILE" <<'EOF'
{{"line":"3","port":"51820","server_private_key":"FAKE_PRIV","server_public_key":"FAKE_PUB","S1":"15","S2":"16","S3":"17","S4":"9999","Jc":"4","Jmin":"8","Jmax":"80","H1":"100","H2":"200","H3":"300","H4":"400"}}
EOF
echo '{{"peers":[]}}' > "$AWG_PEERS_FILE"
render_server_config
grep '^MTU = ' "$AWG_CONFIG"
# 2) 写坏 peers.json 令 jq 失败，验证 render_server_config 返回非零且不遗留 .conf.* 临时文件
printf '{{bad-json' > "$AWG_PEERS_FILE"
if (render_server_config 2>/dev/null); then
    echo "SHOULD_HAVE_FAILED"
    exit 1
fi
leftovers="$(ls -A "{td_posix}" | grep '^\\.conf\\.' || true)"
echo "LEFTOVERS=$leftovers"
"""
            res = subprocess.run([bash, '-c', script], capture_output=True, text=True, timeout=15)
            self.assertEqual(res.returncode, 0, res.stdout + '\n' + res.stderr)
            self.assertIn('MTU = 1280', res.stdout, res.stdout)
            self.assertIn('LEFTOVERS=\n', res.stdout, res.stdout)


if __name__ == '__main__':
    unittest.main()
