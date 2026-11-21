import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
AWG = (REPO / 'awgctl.sh').read_text(encoding='utf-8')


def _find_bash():
    for cand in (r'C:\Program Files\Git\bin\bash.exe', shutil.which('bash')):
        if cand and os.path.isfile(cand):
            return cand
    return None


def _extract_fn(name: str) -> str:
    m = re.search(rf'^{re.escape(name)}\(\)\s*\{{.*?^\}}', AWG, re.M | re.S)
    if not m:
        raise AssertionError(f'awgctl.sh 中未找到函数 {name}')
    return m.group(0)


class TestAwgCorruptPeersAndDownloadGuards(unittest.TestCase):
    def test_download_binaries_uses_private_temp_max_filesize_and_return_cleanup(self):
        """download_binaries 必须以 umask 077 建临时目录、给 curl 加 --max-filesize 并挂 RETURN 清理。"""
        body = _extract_fn('download_binaries')
        self.assertIn('umask 077', body)
        self.assertIn('--max-filesize', body)
        self.assertIn('RETURN', body)

    def test_cmd_update_requires_jq_before_downloading(self):
        """cmd_update 必须在下载覆盖二进制之前先调用 require_jq。"""
        body = _extract_fn('cmd_update')
        self.assertIn('require_jq', body)
        self.assertLess(body.index('require_jq'), body.index('download_binaries'))

    def test_render_server_config_validates_port_range_and_filters_corrupt_peers(self):
        """render_server_config 必须校验 meta 端口范围并过滤 peers.json 中非对象/缺键脏项。"""
        body = _extract_fn('render_server_config')
        self.assertIn('65535', body)
        self.assertIn('select(type=="object"', body)

    def test_peer_list_status_client_conf_and_qr_guard_against_corrupt_peers(self):
        """cmd_peer_list / cmd_status / cmd_client_conf / cmd_qr 均须过滤非对象 peers 条目。"""
        for fn_name in ('cmd_peer_list', 'cmd_status', 'cmd_client_conf', 'cmd_qr'):
            body = _extract_fn(fn_name)
            self.assertIn('select(type=="object"', body, f'{fn_name} 未过滤 peers.json 中的非对象脏条目')

    @unittest.skipUnless(_find_bash() and shutil.which('jq'), '需要 bash 与 jq 执行真实渲染验证')
    def test_render_server_config_and_peer_list_runtime_skip_null_peer_entries(self):
        """真实运行 render_server_config 与 cmd_peer_list，确认 null/字符串脏条目不会被写进 awg0.conf。"""
        bash = _find_bash()
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            meta = td_path / 'meta.json'
            peers = td_path / 'peers.json'
            conf = td_path / 'awg0.conf'
            meta.write_text(
                '{"line":"3","port":"51820","server_private_key":"PRIVKEY","Jc":"4","Jmin":"10","Jmax":"50",'
                '"S1":"20","S2":"20","S3":"20","S4":"20","H1":"10","H2":"20","H3":"30","H4":"40",'
                '"HeaderProtectionKey":"HPKEY","endpoint":"1.2.3.4"}\n',
                encoding='utf-8',
            )
            peers.write_text(
                '{"peers":[null,"bad",{"name":"alice","public_key":"PUB1","preshared_key":"PSK1",'
                '"address":"10.8.0.2","endpoint":"1.2.3.4","created_at":"2026-01-01T00:00:00Z","enabled":true}]}\n',
                encoding='utf-8',
            )
            script = f"""
set -euo pipefail
source "{(REPO / 'awgctl.sh').as_posix()}"
AWG_DIR="{td_path.as_posix()}"
AWG_META_FILE="{meta.as_posix()}"
AWG_PEERS_FILE="{peers.as_posix()}"
AWG_CONFIG="{conf.as_posix()}"
AWG_LINK="awg0"
AWG_SUBNET="10.8.0"
detect_wan_iface() {{ echo eth0; }}
render_server_config
JSON_OUT="$(cmd_peer_list --json)"
printf 'JSON=%s\n' "$JSON_OUT"
"""
            res = subprocess.run([bash, '-c', script], capture_output=True, text=True, encoding='utf-8', timeout=15)
            self.assertEqual(res.returncode, 0, f'bash 失败:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}')
            conf_text = conf.read_text(encoding='utf-8')
            self.assertIn('PublicKey = PUB1', conf_text)
            self.assertNotIn('PublicKey = null', conf_text)
            self.assertNotIn('AllowedIPs = null/32', conf_text)
            self.assertIn('"name": "alice"', res.stdout)
            self.assertNotIn('"name": null', res.stdout)


if __name__ == '__main__':
    unittest.main()
