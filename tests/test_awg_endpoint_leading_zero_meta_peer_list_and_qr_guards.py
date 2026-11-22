import ast
import copy
import ipaddress
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORTAL_PATH = ROOT / 'portal.py'
AWGCTL_PATH = ROOT / 'awgctl.sh'


def _bash_exe():
    git_bash = Path(r'C:\Program Files\Git\bin\bash.exe')
    if git_bash.is_file():
        return str(git_bash)
    return shutil.which('bash')


def _extract_fn(src, name):
    m = re.search(rf'^{re.escape(name)}\(\)\s*\{{.*?^\}}', src, re.M | re.S)
    if not m:
        raise AssertionError(f'awgctl.sh 中未找到函数 {name}()')
    return m.group(0)


def _portal_endpoint_checker():
    tree = ast.parse(PORTAL_PATH.read_text(encoding='utf-8'))
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'awg_endpoint_error')
    regex = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.Assign)
        and any(getattr(t, 'id', '') == 'VALID_AWG_ENDPOINT_RE' for t in n.targets)
    )
    env = {'re': re, 'ipaddress': ipaddress}
    exec(compile(ast.Module(body=[copy.deepcopy(regex), copy.deepcopy(fn)], type_ignores=[]),
                 '<awg-endpoint>', 'exec'), env)
    return env['awg_endpoint_error']


class AwgEndpointLeadingZeroMetaPeerListAndQrGuardTests(unittest.TestCase):
    def setUp(self):
        self.awgctl = AWGCTL_PATH.read_text(encoding='utf-8').replace('\r\n', '\n')

    def test_portal_and_awgctl_reject_leading_zero_port_and_overlong_domain(self):
        check = _portal_endpoint_checker()
        overlong = '.'.join(['a' * 50] * 6)  # 305 字符 > 253
        bad_cases = [
            'vpn.example.com:08080',
            '[2001:db8::1]:00443',
            overlong,
            overlong + ':51820',
        ]
        self.assertTrue(check(None))
        for ep in bad_cases:
            with self.subTest(portal_ep=ep):
                self.assertTrue(check(ep), f'门户放过了非法地址: {ep!r}')

        fn = _extract_fn(self.awgctl, 'validate_endpoint')
        bash = _bash_exe()
        if bash and shutil.which('python3'):
            for ep in bad_cases:
                with self.subTest(awgctl_ep=ep):
                    script = 'log_err() { :; }\n' + fn + '\nvalidate_endpoint "$1" && echo OK || echo BAD'
                    proc = subprocess.run([bash, '-c', script, '_', ep], capture_output=True, text=True, timeout=15)
                    self.assertEqual(proc.stdout.strip(), 'BAD', f'awgctl 放过了非法地址: {ep!r}')
        else:
            self.assertIn('^[1-9][0-9]{0,4}$', fn)
            self.assertIn('253', fn)

    def test_awg_rand_rejects_non_integer_bounds(self):
        fn = _extract_fn(self.awgctl, 'awg_rand')
        bash = _bash_exe()
        if not bash:
            self.skipTest('缺少 bash 环境')
        proc = subprocess.run(
            [bash, '-c', fn + '\nawg_rand abc 10'],
            capture_output=True, text=True, timeout=15,
        )
        self.assertNotEqual(proc.returncode, 0, f'awg_rand 不应接受非数字下界，stdout={proc.stdout!r}')

    def test_meta_set_rejects_non_object_and_has_return_trap(self):
        fn = _extract_fn(self.awgctl, 'meta_set')
        self.assertIn('type=="object"', fn)
        self.assertIn('trap - RETURN', fn)

    def test_cmd_peer_list_sanitizes_non_scalar_fields_for_tsv(self):
        fn = _extract_fn(self.awgctl, 'cmd_peer_list')
        self.assertIn('if type=="string" then . else "" end', fn)

    def test_cmd_qr_captures_config_before_piping_to_qrencode(self):
        fn = _extract_fn(self.awgctl, 'cmd_qr')
        self.assertNotIn('render_client_config "$name" "$endpoint" | qrencode', fn)
        self.assertIn('render_client_config "$name" "$endpoint"', fn)


if __name__ == '__main__':
    unittest.main()
