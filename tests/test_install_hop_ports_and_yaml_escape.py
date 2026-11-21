"""回归测试：install.sh 端口跳跃参数防注入与单元原子落盘、YAML 字段安全转义及纯 ASCII 端口解析。"""
import shutil
import subprocess
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


class InstallHopPortsAndYamlEscapeTests(unittest.TestCase):
    def test_select_subscription_port_checks_ascii_digits(self):
        """select_subscription_port 解析 portal.json 字符串端口时必须要求 isascii()，拒绝全角数字。"""
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        fn = _extract_fn(src, 'select_subscription_port')
        self.assertNotIn('_p.strip().isdigit()', fn)
        self.assertEqual(fn.count('_ps.isascii() and _ps.isdigit()'), 2)

    def test_generate_server_config_quotes_acme_and_tls_fields_via_jq(self):
        """generate_server_config 写 SERVER_NAME / ACME_EMAIL / CERT_FILE / KEY_FILE 须经 jq 安全转义。"""
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        fn = _extract_fn(src, 'generate_server_config')
        for raw_tpl in ('- "${SERVER_NAME}"', 'email: "${ACME_EMAIL}"', 'cert: "${CERT_FILE}"', 'key: "${KEY_FILE}"'):
            self.assertNotIn(raw_tpl, fn, f'YAML 模板仍含裸双引号插值: {raw_tpl}')
        for var in ('SERVER_NAME', 'ACME_EMAIL', 'CERT_FILE', 'KEY_FILE'):
            self.assertIn(f'--arg value "${{{var}}}"', fn, f'{var} 应经 jq --arg value 安全转义')

    @unittest.skipUnless(BASH, 'requires bash')
    def test_setup_iptables_port_hopping_rejects_bad_ports_and_writes_unit_atomically(self):
        """setup_iptables_port_hopping 必须校验端口合法与起止顺序，并原子写入 hy2-iptables.service。"""
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        fn = _extract_fn(src, 'setup_iptables_port_hopping')
        is_valid = _extract_fn(src, 'is_valid_port')
        self.assertNotIn('cat > /etc/systemd/system/hy2-iptables.service', fn)

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            unit = td_path / 'hy2-iptables.service'
            calls = td_path / 'iptables.calls'
            patched = fn.replace('/etc/systemd/system/hy2-iptables.service', unit.as_posix())
            for bad_args in ('"443;id" 20000 40000', '443 40000 20000', '0 20000 40000'):
                script = td_path / 'run.sh'
                script.write_text('\n'.join([
                    'set -u',
                    'log_step() { :; }; log_info() { :; }; log_warn() { :; }; log_err() { :; }',
                    f'iptables() {{ echo "$*" >> "{calls.as_posix()}"; return 0; }}',
                    'clear_all_hopping_rules() { :; }',
                    '_hy2_iptables_unit_owned() { return 1; }',
                    is_valid,
                    patched,
                    f'setup_iptables_port_hopping {bad_args}',
                ]) + '\n', encoding='utf-8', newline='\n')
                res = subprocess.run([BASH, str(script)], capture_output=True, text=True,
                                     encoding='utf-8', errors='replace', timeout=15)
                self.assertNotEqual(res.returncode, 0, f'非法端口参数 {bad_args} 应被拒绝')
                self.assertFalse(calls.exists(), f'非法端口参数 {bad_args} 不得执行 iptables')
                self.assertFalse(unit.exists(), f'非法端口参数 {bad_args} 不得生成单元文件')


if __name__ == '__main__':
    unittest.main()
