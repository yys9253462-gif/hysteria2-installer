"""回归测试：portal_write_meter_config 对含引号/反斜杠 secret 生成合法 JSON 且补写 config 刷盘；install_gost 校验版本格式、使用随机暂存并探针验证二进制。"""

import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / 'install.sh'


class MeterSecretJsonAndGostInstallGuardsTests(unittest.TestCase):
    def _extract_fn(self, sig: str, next_sig: str) -> str:
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        start = src.index(sig)
        end = src.index(next_sig, start)
        return src[start:end]

    def test_portal_write_meter_config_safely_serializes_special_secret_and_fsyncs(self):
        """含双引号和反斜杠的 trafficStats.secret 必须序列化为合法 JSON，补写 config.yaml 应刷盘。"""
        body = self._extract_fn('portal_write_meter_config() {', '# config.yaml 里 trafficStats.secret 的原值')
        self.assertIn('os.fsync(fh.fileno())', body)
        self.assertIn('json.dumps(', body)
        self.assertNotIn('"secret": "${_meter_secret}"', body)

        # 真实调用 bash 执行 portal_write_meter_config 验证含双引号和反斜杠的 secret
        bash_exe = shutil.which('bash')
        if os.name == 'nt' and Path(r'C:\Program Files\Git\bin\bash.exe').exists():
            bash_exe = r'C:\Program Files\Git\bin\bash.exe'
        if not bash_exe:
            self.skipTest('当前环境无可用 bash')
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            cfg = td_path / 'config.yaml'
            secret_val = 'my"sec\\ret$123'
            cfg.write_text(f'trafficStats:\n  listen: 127.0.0.1:19996\n  secret: {secret_val}\n', encoding='utf-8')
            py_exe = Path(sys.executable).as_posix()
            runner = td_path / 'run.sh'
            runner.write_bytes((
                f'python3() {{ "{py_exe}" "$@"; }}\n'
                f'{body}\n'
                'log_info() { :; }; log_warn() { :; }; log_err() { echo "$*" >&2; }\n'
                f'traffic_stats_secret() {{ printf "%s" {shlex.quote(secret_val)}; }}\n'
                f'HY2_CONFIG="{cfg.as_posix()}"\n'
                f'HY2_DIR="{td_path.as_posix()}"\n'
                f'portal_write_meter_config "{td_path.as_posix()}"\n'
            ).encode('utf-8'))
            res = subprocess.run([bash_exe, runner.as_posix()], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=15)
            self.assertEqual(res.returncode, 0, res.stderr)
            out = json.loads((td_path / 'usage-meter-config.json').read_text(encoding='utf-8'))
            self.assertEqual(out['hysteria']['secret'], secret_val)

    def test_install_gost_validates_tag_uses_random_staging_and_probes_binary(self):
        """install_gost 必须校验 GOST_LATEST 版本格式、使用 mktemp 随机暂存、探针验证 -V 且原子写入 gost.service。"""
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        start = src.index('install_gost() {')
        end = src.index('\n}\n', src.index('GOST 所有权标记写入失败', start)) + 3
        body = src[start:end]
        self.assertIn('^v?[0-9A-Za-z][0-9A-Za-z._-]{0,63}$', body)
        self.assertIn('mktemp "${GOST_BIN}.new.XXXXXX"', body)
        self.assertNotIn('install -m 755 "$TMP_DIR/$GOST_MEMBER" "${GOST_BIN}.new"', body)
        self.assertIn(' -V ', body)
        self.assertNotIn('cat > /etc/systemd/system/gost.service', body)
        self.assertIn('mktemp "/etc/systemd/system/gost.service.XXXXXX"', body)


if __name__ == '__main__':
    unittest.main()
