"""回归测试：portal_write_meter_config 防止注释 masquerade: 误插与非原子写，以及 Caddy 签发超时自动回滚。"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / 'install.sh'
BASH = shutil.which('bash')
PYTHON = shutil.which('python3') or shutil.which('python')


def _extract_fn(source: str, name: str) -> str:
    # 避开函数内部 heredoc 里的顶格 `}`：按顶格函数头切分到下一节注释或顶格函数结束。
    start = source.index(f'{name}() {{\n')
    lines = source[start:].splitlines(keepends=True)
    in_heredoc = None
    out = []
    for idx, line in enumerate(lines):
        out.append(line)
        if in_heredoc is not None:
            if line.strip() == in_heredoc:
                in_heredoc = None
            continue
        m_hd = re.search(r"<<-?\s*'?([A-Za-z0-9_]+)'?", line)
        if m_hd:
            in_heredoc = m_hd.group(1)
            continue
        if idx > 0 and line == '}\n':
            break
    return ''.join(out)


@unittest.skipUnless(BASH and PYTHON, '需要 bash 与 python 环境')
class MeterConfigAnchorAndCaddyRollbackTests(unittest.TestCase):
    def test_portal_write_meter_config_ignores_commented_masquerade_and_writes_atomically(self):
        """注释中的 masquerade: 不得触发行内误插，且 usage-meter-config.json 必须走临时文件原子替换。"""
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        fn_write = _extract_fn(src, 'portal_write_meter_config')
        fn_secret = _extract_fn(src, 'traffic_stats_secret')
        self.assertIn('mktemp', fn_write, 'usage-meter-config.json 写入必须使用临时文件原子替换')

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = root / 'config.yaml'
            cfg.write_text(
                'listen: :443\n'
                '# 注意：下面的 masquerade: 段不要随意删除\n'
                'auth:\n'
                '  type: http\n'
                'masquerade:\n'
                '  type: proxy\n',
                encoding='utf-8',
                newline='\n',
            )
            root_posix = root.as_posix()
            cfg_posix = cfg.as_posix()
            py_posix = Path(PYTHON).as_posix()
            script = '\n'.join([
                'set -euo pipefail',
                f'HY2_DIR="{root_posix}"',
                f'HY2_CONFIG="{cfg_posix}"',
                'METER_SECRET="AbCdEfGh12345678"',
                f'python3() {{ "{py_posix}" "$@"; }}',
                'log_info() { :; }; log_warn() { :; }; log_err() { echo "ERR:$*" >&2; }',
                fn_secret,
                fn_write,
                f'portal_write_meter_config "{root_posix}"',
            ])
            res = subprocess.run([BASH, '-c', script], capture_output=True, text=True,
                                 encoding='utf-8', errors='replace', timeout=20)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

            updated = cfg.read_text(encoding='utf-8')
            # 注释行必须原样完整保留，绝不能被劈成两半把 trafficStats: 插进注释中间
            self.assertIn('# 注意：下面的 masquerade: 段不要随意删除\n', updated)
            self.assertRegex(updated, r'(?m)^trafficStats:\n  listen: 127\.0\.0\.1:19996\n  secret: AbCdEfGh12345678\n+masquerade:\n')
            meter = json.loads((root / 'usage-meter-config.json').read_text(encoding='utf-8'))
            self.assertEqual(meter['hysteria']['secret'], 'AbCdEfGh12345678')
            # 不应残留任何临时文件
            leftovers = [p.name for p in root.iterdir() if '.tmp.' in p.name]
            self.assertEqual(leftovers, [], f'残留临时文件: {leftovers}')

    def test_setup_cert_via_existing_caddy_rolls_back_appended_block_on_timeout(self):
        """借 Caddy 签发超时失败时，必须回滚自动追加的站点块并重载 Caddy。"""
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        fn_caddy = _extract_fn(src, 'setup_cert_via_existing_caddy')
        fn_decoy = _extract_fn(src, 'caddy_decoy_directives')
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cf = root / 'Caddyfile'
            original = 'prod.example.com {\n    respond "live"\n}\n'
            cf.write_text(original, encoding='utf-8', newline='\n')
            reload_log = root / 'reloads.log'
            fn_patched = fn_caddy.replace('/etc/caddy/Caddyfile', cf.as_posix())
            script = '\n'.join([
                'set -uo pipefail',
                'log_step() { :; }; log_info() { :; }; log_warn() { :; }; log_err() { :; }',
                'caddy() { return 0; }',
                'find_cert_in_webserver() { return 1; }',
                'curl() { return 0; }',
                'sleep() { return 0; }',
                f'systemctl() {{ echo "$*" >> "{reload_log.as_posix()}"; return 0; }}',
                fn_decoy,
                fn_patched,
                'setup_cert_via_existing_caddy "new-node.example.com"; echo "RC=$?"',
            ])
            res = subprocess.run([BASH, '-c', script], capture_output=True, text=True,
                                 encoding='utf-8', errors='replace', timeout=20)
            self.assertIn('RC=1', res.stdout, res.stdout + res.stderr)
            self.assertEqual(cf.read_text(encoding='utf-8'), original,
                             '签发超时后自动追加到生产 Caddyfile 的占位块未被回滚')
            reloads = reload_log.read_text(encoding='utf-8').splitlines()
            self.assertGreaterEqual(reloads.count('reload caddy'), 2,
                                    f'回滚 Caddyfile 后应再次 reload caddy，实际调用: {reloads}')


if __name__ == '__main__':
    unittest.main()
