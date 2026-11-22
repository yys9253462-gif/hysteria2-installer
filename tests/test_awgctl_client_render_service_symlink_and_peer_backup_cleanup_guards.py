"""回归测试：awgctl.sh 客户端配置渲染防注入/溢出、服务单元防符号链接与 peer 回滚备份防泄漏私钥。"""

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
AWGCTL_SH = (REPO / 'awgctl.sh').read_text(encoding='utf-8')


def _find_bash():
    for cand in (r'C:\Program Files\Git\bin\bash.exe', shutil.which('bash')):
        if cand and Path(cand).is_file():
            return cand
    raise RuntimeError('未找到可用 bash')


def _extract_fn(name):
    marker = f'{name}() {{'
    start = AWGCTL_SH.index(marker)
    lines = AWGCTL_SH[start:].splitlines()
    out = []
    for i, line in enumerate(lines):
        out.append(line)
        if i > 0 and line == '}':
            break
    return '\n'.join(out) + '\n'


class AwgctlClientRenderServiceSymlinkAndPeerBackupCleanupGuardsTests(unittest.TestCase):
    def test_render_client_config_guards_symlink_s4_overflow_hp_and_dirty_endpoint(self):
        """render_client_config 须拒绝符号链接 peers.json、限制 S4 长度、拦截脏 HeaderProtectionKey 与空/脏 endpoint。"""
        fn = _extract_fn('render_client_config')
        self.assertIn('[[ -L "$AWG_PEERS_FILE" ]]', fn)
        self.assertIn('^[0-9]{1,5}$', fn)
        self.assertIn('[[ -n "$endpoint" ]] || die', fn)
        self.assertIn('validate_endpoint "$endpoint"', fn)
        self.assertIn('HeaderProtectionKey', fn)

        bash = _find_bash()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            peers = root / 'peers.json'
            meta = root / 'meta.json'
            peers.write_text(json.dumps({
                'peers': [{
                    'name': 'alice',
                    'private_key': 'privkey123',
                    'preshared_key': 'psk123',
                    'address': '10.66.66.2',
                    'endpoint': '1.2.3.4\nPostUp = evil',
                }]
            }), encoding='utf-8')
            meta.write_text(json.dumps({
                'line': '3',
                'port': 51820,
                'server_public_key': 'srvpub123',
                'HeaderProtectionKey': 'hpkey123',
                'S4': '10', 'Jc': '4', 'Jmin': '50', 'Jmax': '100',
                'S1': '20', 'S2': '30', 'S3': '40',
                'H1': '100', 'H2': '200', 'H3': '300', 'H4': '400',
            }), encoding='utf-8')

            def to_posix(p):
                s = p.as_posix()
                return '/' + s[0].lower() + s[2:] if len(s) >= 2 and s[1] == ':' else s

            script = (
                'set -euo pipefail\n'
                'log_err() { printf "ERR:%s\\n" "$*" >&2; }\n'
                'die() { log_err "$*"; exit 1; }\n'
                'require_jq() { :; }\n'
                f'AWG_META_FILE="{to_posix(meta)}"\n'
                f'AWG_PEERS_FILE="{to_posix(peers)}"\n'
                + _extract_fn('meta_get')
                + _extract_fn('version_line')
                + _extract_fn('endpoint_has_port')
                + _extract_fn('validate_endpoint')
                + fn
                + 'if (render_client_config "alice" ""); then echo "DIRTY_EP_ALLOWED"; exit 11; fi\n'
                + 'out="$(render_client_config "alice" "1.2.3.4")"\n'
                + 'printf "%s\\n" "$out" | grep -qF "Endpoint = 1.2.3.4:51820" || { echo "BAD_OUT:$out"; exit 12; }\n'
                + 'echo OK\n'
            )
            res = subprocess.run([bash, '-c', script], capture_output=True, text=True, errors='replace', timeout=15)
            # 若本机没有 jq 跳过运行段，静态断言已覆盖
            if 'jq: command not found' not in (res.stderr or ''):
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertIn('OK', res.stdout)

    def test_write_service_rejects_symlink_and_systemd_specifiers(self):
        """write_service 须拒绝符号链接 AWG_SERVICE 并拦截含控制字符或 %/$ 的服务单元参数。"""
        fn = _extract_fn('write_service')
        self.assertIn('[[ -L "$AWG_SERVICE" ]]', fn)
        self.assertIn('[[:cntrl:]]', fn)
        self.assertIn('[%\\$]', fn)

    def test_peer_add_and_peer_del_reject_symlinks_and_clean_backups_before_die(self):
        """cmd_peer_add 与 cmd_peer_del 须拒绝符号链接配置，且恢复失败退出前必清理明文私钥备份。"""
        fn_add = _extract_fn('cmd_peer_add')
        fn_del = _extract_fn('cmd_peer_del')
        for label, fn in (('cmd_peer_add', fn_add), ('cmd_peer_del', fn_del)):
            self.assertIn('[[ -L "$AWG_PEERS_FILE" || -L "$AWG_CONFIG" ]]', fn, f'{label} 应拒绝符号链接配置')
            self.assertIn('rm -f -- "${tmp:-}" "${peers_backup:-}" "${config_backup:-}"', fn,
                          f'{label} 失败退出前必须清理临时私钥备份')


if __name__ == '__main__':
    unittest.main()
