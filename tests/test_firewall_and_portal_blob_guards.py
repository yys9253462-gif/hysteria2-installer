"""回归测试：setup_system_firewall 端口校验与无管道策略提取、portal_remote_blob_shas 脏响应过滤与私有暂存。"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / 'install.sh'


def _git_bash():
    for candidate in (r'C:\Program Files\Git\bin\bash.exe', r'C:\Program Files\Git\usr\bin\bash.exe'):
        if Path(candidate).is_file():
            return candidate
    return shutil.which('bash')


BASH = _git_bash()


def _extract_fn(src: str, name: str) -> str:
    start = src.index(f'{name}() {{\n')
    end = src.index('\n}\n', start) + 3
    return src[start:end]


class FirewallAndPortalBlobGuardsTests(unittest.TestCase):
    @unittest.skipUnless(BASH, 'requires bash')
    def test_setup_system_firewall_rejects_empty_or_invalid_ports(self):
        """setup_system_firewall 必须拦截空/非法主端口、订阅端口或倒置跳跃区间，不得写出畸形规则。"""
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        fn = _extract_fn(src, 'setup_system_firewall')
        self.assertNotIn('ufw status | grep', fn, 'ufw status 缺少 2>/dev/null 保护')
        self.assertNotIn('head -n1 | grep -o', fn, '裸 iptables 策略提取应避免 head -n1 管道 SIGPIPE')

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            calls = td_path / 'ufw.calls'
            for sub_port, args in (('', '443 "" ""'), ('18443', '"" "" ""'), ('18443', '443 40000 20000')):
                script = td_path / 'fw.sh'
                script.write_text('\n'.join([
                    'set -u',
                    'CERT_TYPE=self_signed',
                    f'HY2_SUB_PORT="{sub_port}"',
                    'log_step() { :; }; log_info() { :; }; log_warn() { :; }; log_err() { :; }',
                    f'ufw() {{ if [[ "$1" == status ]]; then echo "Status: active"; return 0; fi; echo "$*" >> "{calls.as_posix()}"; }}',
                    fn,
                    f'setup_system_firewall {args}',
                ]) + '\n', encoding='utf-8', newline='\n')
                res = subprocess.run([BASH, str(script)], capture_output=True, text=True,
                                     encoding='utf-8', errors='replace', timeout=15)
                self.assertNotEqual(res.returncode, 0, f'非法端口组合 sub={sub_port!r} args={args} 应返回非零')
                self.assertFalse(calls.exists(), f'非法端口组合不应触发 ufw allow: sub={sub_port!r} args={args}')

    @unittest.skipUnless(BASH, 'requires bash')
    def test_portal_remote_blob_shas_filters_non_string_and_multiline_entries(self):
        """portal_remote_blob_shas 遇到非字符串 sha 或含换行的 name 不得崩溃也不得注入映射行。"""
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        fn = _extract_fn(src, 'portal_remote_blob_shas')
        self.assertIn('umask 077', fn)
        ensure_fn = _extract_fn(src, 'portal_ensure_py')
        self.assertIn('umask 077', ensure_fn)

        payload = [
            {'name': 'portal.py', 'sha': 'a' * 40},
            {'name': 'bad_int_sha.py', 'sha': 12345},
            {'name': 'evil.py\ninjected.py ' + 'b' * 40, 'sha': 'c' * 40},
            {'name': 'space name.py', 'sha': 'd' * 40},
            {'name': 999, 'sha': 'e' * 40},
        ]
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            fixture = td_path / 'contents.json'
            fixture.write_text(json.dumps(payload), encoding='utf-8')
            py_exe = Path(sys.executable).as_posix()
            script = td_path / 'blobs.sh'
            script.write_text('\n'.join([
                'set -euo pipefail',
                'AWG_REPO=example/repo',
                f'python3() {{ "{py_exe}" "$@"; }}',
                'curl() {',
                '  local out=""',
                '  while [[ $# -gt 0 ]]; do',
                '    if [[ "$1" == "-o" ]]; then out="$2"; shift 2; continue; fi',
                '    shift',
                '  done',
                f'  cp "{fixture.as_posix()}" "$out"',
                '}',
                fn,
                'portal_remote_blob_shas ' + ('f' * 40),
            ]) + '\n', encoding='utf-8', newline='\n')
            res = subprocess.run([BASH, str(script)], capture_output=True, text=True,
                                 encoding='utf-8', errors='replace', timeout=15)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            lines = [ln for ln in res.stdout.splitlines() if ln.strip()]
            self.assertEqual(lines, [f'portal.py {"a" * 40}'])


if __name__ == '__main__':
    unittest.main()
