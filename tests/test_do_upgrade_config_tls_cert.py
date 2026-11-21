"""回归测试：do_upgrade.sh 生成的独立 repair-config.sh 必须自带 config_tls_cert 定义。

此前 install.sh 在第 4064 行才定义 config_tls_cert，而独立落地的 do_upgrade.sh /
repair-config.sh 在第 3141、3242 行直接调用它，运行时报 command not found，导致
自定义证书节点的 client_meta.json 退回自签且证书监控 path 单元盯错目录。
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')
BASH = shutil.which('bash')


def _extract_repair_script():
    m = re.search(
        r"cat > \"\$_bundle_dir/repair-config\.sh\" <<'PORTALREPAIR'\n(.*?)\nPORTALREPAIR\n",
        INSTALL_SRC,
        re.S,
    )
    if not m:
        raise AssertionError('未找到 do_upgrade.sh 内嵌的 PORTALREPAIR 脚本')
    return m.group(1)


@unittest.skipUnless(BASH, 'requires bash')
class DoUpgradeRepairCertHelperTests(unittest.TestCase):
    def test_repair_config_defines_and_runs_config_tls_cert_standalone(self):
        repair = _extract_repair_script()
        self.assertIn('config_tls_cert()', repair, 'repair-config.sh 缺少内联的 config_tls_cert 定义')
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'config.yaml'
            cfg.write_text(
                'listen: :443\n'
                'tls: # 自定义证书\n'
                '  key: "/etc/ssl/private/a.key"\n'
                '  cert: "/etc/caddy/certs/demo.example.com.crt" # 行尾注释\n',
                encoding='utf-8',
            )
            # 在完全不 source install.sh 的独立子 shell 里执行内联定义并验证解析结果
            fn_start = repair.index('config_tls_cert()')
            fn_end = repair.index('\n        }\n', fn_start) + len('\n        }\n')
            fn_def = repair[fn_start:fn_end]
            res = subprocess.run(
                [BASH, '-c', fn_def + '\nconfig_tls_cert "$1"\n', 'bash', cfg.as_posix()],
                capture_output=True, text=True, encoding='utf-8', timeout=10,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout.strip(), '/etc/caddy/certs/demo.example.com.crt')


if __name__ == '__main__':
    unittest.main()
