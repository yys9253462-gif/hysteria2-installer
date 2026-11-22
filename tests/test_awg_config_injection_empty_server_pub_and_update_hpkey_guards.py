"""回归测试：awgctl 服务端/客户端配置防换行注入、缺服务端公钥拦截、临时文件清理陷阱与 update 头部保护密钥非空校验。"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AWG_SRC = (ROOT / 'awgctl.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def _find_bash():
    for cand in (r'C:\Program Files\Git\bin\bash.exe', shutil.which('bash')):
        if cand and os.path.isfile(cand):
            return cand
    return None


BASH = _find_bash()
JQ = shutil.which('jq')


def _extract_fn(name):
    m = re.search(rf'^{re.escape(name)}\(\)\s*\{{.*?^\}}', AWG_SRC, re.M | re.S)
    if not m:
        raise AssertionError(f'awgctl.sh 中未找到函数 {name}')
    return m.group(0)


class AwgConfigInjectionEmptyServerPubAndUpdateHpkeyGuardsTests(unittest.TestCase):
    def test_source_guards_in_render_and_update_and_atomic_install(self):
        """检查 render_server_config / render_client_config / cmd_update / awg_atomic_install_bin 防护代码。"""
        srv = _extract_fn('render_server_config')
        cli = _extract_fn('render_client_config')
        upd = _extract_fn('cmd_update')
        ins = _extract_fn('awg_atomic_install_bin')

        self.assertIn('trap - RETURN;', srv)
        self.assertIn('gsub(', srv)
        self.assertIn('[[ -n "$pub" ]]', cli)
        self.assertIn('[[ -n "$_hp_key" ]]', upd)
        self.assertIn('umask 077', ins)

    @unittest.skipUnless(BASH and JQ, 'requires bash and jq')
    def test_runtime_blocks_newline_injection_and_empty_server_pubkey(self):
        """真 bash + jq 运行时验证：脏 peers 换行不得注入 awg0.conf；缺 server_public_key 时 render_client_config 报错。"""
        fns = '\n'.join(
            _extract_fn(n) for n in (
                'require_jq', 'meta_get', 'version_line', 'endpoint_has_port',
                'render_server_config', 'render_client_config',
            )
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            meta = root / 'meta.json'
            peers = root / 'peers.json'
            conf = root / 'awg0.conf'
            meta.write_text(json.dumps({
                'line': '3',
                'port': 51888,
                'endpoint': 'vpn.example.com',
                'server_private_key': 'SRV_PRIV_KEY',
                'server_public_key': '',
                'HeaderProtectionKey': 'HP_KEY',
                'Jc': 4, 'Jmin': 40, 'Jmax': 70,
                'S1': 15, 'S2': 25, 'S3': 10, 'S4': 20,
                'H1': 11, 'H2': 22, 'H3': 33, 'H4': 44,
            }), encoding='utf-8')
            peers.write_text(json.dumps({
                'peers': [
                    {
                        'name': 'evil\nPostUp = id > /tmp/pwned',
                        'private_key': 'P1',
                        'public_key': 'PUB1\nPostUp = pwn',
                        'preshared_key': 'PSK1',
                        'address': '10.66.66.2',
                    },
                    {
                        'name': 'good\n#comment',
                        'private_key': 'P2',
                        'public_key': 'GOOD_PUB_KEY',
                        'preshared_key': 'GOOD_PSK',
                        'address': '10.66.66.3',
                    },
                ]
            }), encoding='utf-8')
            script = f'''set -euo pipefail
AWG_DIR="{root.as_posix()}"
AWG_META_FILE="{meta.as_posix()}"
AWG_PEERS_FILE="{peers.as_posix()}"
AWG_CONFIG="{conf.as_posix()}"
AWG_LINK="awg0"
AWG_SUBNET="10.66.66"
die() {{ echo "DIE: $*" >&2; exit 1; }}
detect_wan_iface() {{ echo "eth0"; }}
{fns}
render_server_config
if ( render_client_config "good" "vpn.example.com" >/dev/null 2>&1 ); then
    echo "EMPTY_PUB_ALLOWED"
    exit 1
fi
echo "EMPTY_PUB_BLOCKED=1"
'''
            proc = subprocess.run([BASH, '-s'], input=script, capture_output=True, text=True, encoding='utf-8', timeout=20)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn('EMPTY_PUB_BLOCKED=1', proc.stdout)
            rendered = conf.read_text(encoding='utf-8')
            self.assertNotIn('PostUp = pwn', rendered)
            self.assertNotIn('PostUp = id', rendered)
            self.assertIn('PublicKey = GOOD_PUB_KEY', rendered)


if __name__ == '__main__':
    unittest.main()
