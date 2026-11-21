"""回归测试：awgctl.sh 脏 peers.json 下的客户端配置渲染、存在性检查与 IP 分配防碰撞及防火墙前导零拦截。"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AWGCTL_SH = (ROOT / 'awgctl.sh').read_text(encoding='utf-8')


def _find_bash():
    for cand in (r'C:\Program Files\Git\bin\bash.exe', '/bin/bash', '/usr/bin/bash'):
        if Path(cand).is_file():
            return cand
    return shutil.which('bash')


BASH = _find_bash()
JQ = shutil.which('jq')


def _extract_fn(name):
    m = re.search(rf'^{re.escape(name)}\(\)\s*\{{.*?^\}}', AWGCTL_SH, re.M | re.S)
    if not m:
        raise AssertionError(f'awgctl.sh 中未找到函数 {name}()')
    return m.group(0)


def _run_bash(script):
    env = os.environ.copy()
    if os.name == 'nt':
        env['PATH'] = r'C:\Program Files\Git\bin;C:\Program Files\Git\usr\bin;' + env.get('PATH', '')
    return subprocess.run(
        [BASH, '-c', script],
        capture_output=True,
        text=True,
        encoding='utf-8',
        timeout=30,
        env=env,
    )


class AwgCorruptPeersClientConfIpAllocAndFwGuardsTests(unittest.TestCase):
    def test_write_service_and_firewall_and_python_isolation(self):
        """write_service 须使用 RETURN 清理，allow/revoke_firewall 须拒前导零端口，python3 须带 -I。"""
        ws = _extract_fn('write_service')
        self.assertRegex(ws, r"trap\s+'.*'\s+RETURN", 'write_service 必须注册 RETURN 清理临时服务文件')
        self.assertIn('umask 077', ws, 'write_service 临时文件应使用 umask 077 创建再 chmod 644')

        for fn_name in ('allow_firewall', 'revoke_firewall'):
            body = _extract_fn(fn_name)
            self.assertIn('^[1-9][0-9]{0,4}$', body, f'{fn_name} 必须拒绝前导零端口')

        self.assertIn('python3 -I -c', _extract_fn('pick_port'))
        self.assertIn('python3 -I -c', _extract_fn('validate_endpoint'))

    def test_jq_readers_filter_non_object_peers_and_reject_null_priv(self):
        """render_client_config / peer_exists / next_peer_address 均须过滤非对象脏 peer 并拒绝空/null 私钥。"""
        for fn_name in ('render_client_config', 'peer_exists', 'next_peer_address'):
            body = _extract_fn(fn_name)
            self.assertIn('select(type=="object"', body,
                          f'{fn_name} 遍历 peers.json 前必须过滤非对象脏条目')
        rc = _extract_fn('render_client_config')
        self.assertIn('[[ "$port" =~ ^[1-9][0-9]{0,4}$ ]]', rc,
                      'render_client_config 渲染 Endpoint 前应校验端口合法性')

    @unittest.skipUnless(BASH and JQ, 'requires bash and jq')
    def test_peer_exists_next_address_and_render_client_config_survive_corrupt_peers(self):
        """peers.json 含 null/非对象脏条目时，peer_exists、next_peer_address 与 render_client_config 均须正常工作且不撞 IP。"""
        fns = '\n'.join(
            _extract_fn(n) for n in (
                'require_jq', 'meta_get', 'version_line', 'endpoint_has_port',
                'peer_exists', 'next_peer_address', 'render_client_config',
            )
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            meta = root / 'meta.json'
            peers = root / 'peers.json'
            meta.write_text(json.dumps({
                'line': '3',
                'port': 51888,
                'endpoint': 'vpn.example.com',
                'server_public_key': 'SRV_PUB_KEY',
                'HeaderProtectionKey': 'HP_KEY',
                'Jc': 4, 'Jmin': 40, 'Jmax': 70,
                'S1': 15, 'S2': 25, 'S3': 10, 'S4': 20,
                'H1': 11, 'H2': 22, 'H3': 33, 'H4': 44,
            }), encoding='utf-8')
            peers.write_text(json.dumps({
                'peers': [
                    None,
                    123,
                    'bad',
                    {
                        'name': 'alice',
                        'private_key': 'ALICE_PRIV',
                        'public_key': 'ALICE_PUB',
                        'preshared_key': 'ALICE_PSK',
                        'address': '10.66.66.2',
                        'endpoint': 'vpn.example.com',
                    },
                    {
                        'name': 'broken_no_priv',
                        'address': '10.66.66.3',
                    },
                ],
            }), encoding='utf-8')
            script = f'''set -euo pipefail
AWG_META_FILE="{meta.as_posix()}"
AWG_PEERS_FILE="{peers.as_posix()}"
AWG_SUBNET="10.66.66"
die() {{ echo "DIE: $*" >&2; exit 1; }}
log_err() {{ echo "ERR: $*" >&2; }}
{fns}
peer_exists "alice"
echo "EXISTS_ALICE=$?"
NEXT_IP="$(next_peer_address)"
echo "NEXT_IP=$NEXT_IP"
CONF="$(render_client_config "alice" "")"
echo "$CONF" | grep -q "PrivateKey = ALICE_PRIV"
echo "$CONF" | grep -q "Endpoint = vpn.example.com:51888"
echo "CONF_OK=1"
if render_client_config "broken_no_priv" "" >/dev/null 2>&1; then
  echo "BROKEN_SHOULD_FAIL"
  exit 1
fi
echo "BROKEN_REJECTED=1"
'''
            proc = _run_bash(script)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn('EXISTS_ALICE=0', proc.stdout)
            self.assertIn('NEXT_IP=10.66.66.4', proc.stdout,
                          '脏条目不得让 next_peer_address 失败回退重复分配已占用的 .2 / .3')
            self.assertIn('CONF_OK=1', proc.stdout)
            self.assertIn('BROKEN_REJECTED=1', proc.stdout,
                          '缺少 private_key 的坏 peer 必须被拒绝，不能写出 PrivateKey = null')


if __name__ == '__main__':
    unittest.main()
