"""回归测试：awgctl 裸 IPv6 Endpoint 补方括号、脏 peers.json 下 peer-del/peer-add 容错、client-conf 去重与密钥非空校验。"""

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


class AwgPeerDelCorruptIpv6EndpointAndKeygenGuardsTests(unittest.TestCase):
    def test_render_client_config_brackets_bare_ipv6_endpoint(self):
        """render_client_config 对不含端口的裸 IPv6 endpoint 必须补方括号再拼端口。"""
        body = _extract_fn('render_client_config')
        self.assertIn('[${endpoint}]:${port}', body)

    def test_peer_del_and_peer_add_and_client_conf_guard_corrupt_peers_and_keygen(self):
        """cmd_peer_del / cmd_peer_add / cmd_client_conf 须过滤脏条目、去重 first() 并校验密钥非空。"""
        pdel = _extract_fn('cmd_peer_del')
        padd = _extract_fn('cmd_peer_add')
        cconf = _extract_fn('cmd_client_conf')
        inst = _extract_fn('cmd_install')
        self.assertIn('select(type=="object" and .name==$n)', pdel)
        self.assertIn('select(type=="object" and .name != $n)', pdel)
        self.assertIn('if (.peers | type) == "array"', pdel)
        self.assertIn('[[ -n "$priv" && -n "$pub" && -n "$psk" ]]', padd)
        self.assertIn('if (.peers | type) == "array"', padd)
        self.assertIn('first(', cconf)
        self.assertIn('[[ -n "$priv" && -n "$pub" ]]', inst)

    @unittest.skipUnless(BASH and JQ, 'requires bash and jq')
    def test_runtime_bare_ipv6_endpoint_and_corrupt_peers_delete(self):
        """真 bash + jq 运行时验证：裸 IPv6 输出 [2001:db8::1]:51888，含 null/数字脏 peers 时 peer-del 成功删除 alice。"""
        fns = '\n'.join(
            _extract_fn(n) for n in (
                'require_jq', 'meta_get', 'version_line', 'endpoint_has_port',
                'peer_exists', 'peers_init', 'render_client_config', 'cmd_peer_del',
            )
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            meta = root / 'meta.json'
            peers = root / 'peers.json'
            meta.write_text(json.dumps({
                'line': '3',
                'port': 51888,
                'endpoint': '2001:db8::1',
                'server_public_key': 'SRV_PUB',
                'HeaderProtectionKey': 'HP_KEY',
                'Jc': 4, 'Jmin': 40, 'Jmax': 70,
                'S1': 15, 'S2': 25, 'S3': 10, 'S4': 20,
                'H1': 11, 'H2': 22, 'H3': 33, 'H4': 44,
            }), encoding='utf-8')
            peers.write_text(json.dumps({
                'peers': [
                    None,
                    123,
                    {
                        'name': 'alice',
                        'private_key': 'ALICE_PRIV',
                        'public_key': 'ALICE_PUB',
                        'preshared_key': 'ALICE_PSK',
                        'address': '10.66.66.2',
                        'endpoint': '2001:db8::1',
                    },
                    {
                        'name': 'bob',
                        'private_key': 'BOB_PRIV',
                        'public_key': 'BOB_PUB',
                        'preshared_key': 'BOB_PSK',
                        'address': '10.66.66.3',
                        'endpoint': '2001:db8::1',
                    },
                ]
            }), encoding='utf-8')
            script = f'''set -euo pipefail
AWG_DIR="{root.as_posix()}"
AWG_META_FILE="{meta.as_posix()}"
AWG_PEERS_FILE="{peers.as_posix()}"
AWG_CONFIG="{(root / "awg0.conf").as_posix()}"
die() {{ echo "DIE: $*" >&2; exit 1; }}
log_info() {{ :; }}
log_warn() {{ :; }}
require_root() {{ :; }}
render_server_config() {{ :; }}
restore_peer_files() {{ :; }}
peer_apply_live_del() {{ echo "DEL_PUB=$1"; }}
{fns}
CONF="$(render_client_config "alice" "2001:db8::1")"
echo "$CONF" | grep -qF "Endpoint = [2001:db8::1]:51888"
echo "IPV6_OK=1"
cmd_peer_del "alice"
'''
            proc = subprocess.run([BASH, '-s'], input=script, capture_output=True, text=True, encoding='utf-8', timeout=20)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn('IPV6_OK=1', proc.stdout)
            self.assertIn('DEL_PUB=ALICE_PUB', proc.stdout)
            after = json.loads(peers.read_text(encoding='utf-8'))
            self.assertEqual([p['name'] for p in after['peers']], ['bob'])


if __name__ == '__main__':
    unittest.main()
