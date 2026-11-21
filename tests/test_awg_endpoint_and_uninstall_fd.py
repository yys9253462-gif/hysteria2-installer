"""回归测试：awgctl.sh 渲染客户端 Endpoint 时规范化前导零端口，且卸载自删关闭锁描述符 fd 9。"""
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AWG_SRC = (ROOT / 'awgctl.sh').read_text(encoding='utf-8').replace('\r\n', '\n')
BASH = shutil.which('bash')
JQ = shutil.which('jq')


@unittest.skipUnless(BASH, 'requires bash')
class AwgEndpointAndUninstallFdTests(unittest.TestCase):
    @unittest.skipUnless(JQ, 'requires jq')
    def test_render_client_config_normalizes_leading_zero_endpoint_port(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / 'awg_meta.json').write_text(json.dumps({
                'line': '3', 'port': '55000', 'server_public_key': 'PUBKEY_FAKE',
                'HeaderProtectionKey': 'HPKEY_FAKE', 'Jc': '5', 'Jmin': '8', 'Jmax': '80',
                'S1': '20', 'S2': '30', 'S3': '40', 'S4': '16',
                'H1': '100', 'H2': '200', 'H3': '300', 'H4': '400',
            }), encoding='utf-8')
            (d / 'awg_peers.json').write_text(json.dumps({
                'peers': [{
                    'name': 'phone', 'address': '10.66.66.2',
                    'private_key': 'PRIV_FAKE', 'preshared_key': 'PSK_FAKE',
                    'endpoint': '',
                }]
            }), encoding='utf-8')
            script = r'''
set -euo pipefail
AWGCTL="$1"; DIR="$2"; EP="$3"
MAIN_LINE="$(grep -n '^main "\$@"' "$AWGCTL" | tail -1 | cut -d: -f1)"
source <(head -n $(( MAIN_LINE - 1 )) "$AWGCTL")
AWG_DIR="$DIR"
AWG_META_FILE="${DIR}/awg_meta.json"
AWG_PEERS_FILE="${DIR}/awg_peers.json"
render_client_config phone "$EP"
'''
            for raw_ep, expected_ep in (
                ('vpn.example.com:08080', 'vpn.example.com:8080'),
                ('[2001:db8::1]:05000', '[2001:db8::1]:5000'),
                ('vpn.example.com', 'vpn.example.com:55000'),
            ):
                with self.subTest(endpoint=raw_ep):
                    res = subprocess.run(
                        [BASH, '-c', script, '_', str(ROOT / 'awgctl.sh'), d.as_posix(), raw_ep],
                        capture_output=True, text=True, encoding='utf-8', timeout=15,
                    )
                    self.assertEqual(res.returncode, 0, res.stderr)
                    self.assertIn(f'Endpoint = {expected_ep}', res.stdout)

    def test_uninstall_self_delete_closes_lock_fd_9(self):
        start = AWG_SRC.index('cmd_uninstall() {')
        end = AWG_SRC.index('\ncmd_status() {', start)
        body = AWG_SRC[start:end]
        line = next(
            (ln for ln in body.splitlines() if 'nohup bash -c' in ln and 'AWG_CTL_INSTALLED' in ln),
            '',
        )
        self.assertTrue(line, '未找到延迟自删后台命令')
        self.assertIn('9>&-', line, '卸载延迟自删后台子进程未关闭继承的锁文件描述符 fd 9')


if __name__ == '__main__':
    unittest.main()
