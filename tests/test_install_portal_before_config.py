"""安装时取不到门户整包，config.yaml 与 client_meta.json 必须保持原样（2026-11-03）。

旧顺序：generate_server_config 先重写 config.yaml（auth 指向新选的 PORTAL_LOCAL_PORT）
和 client_meta.json，最后才在 setup_portal 里取门户。三源都失败时安装中止，旧门户还在
旧端口，config.yaml 却已指向没人监听的端口 —— 下次 Hysteria 重启所有用户都连不上。

这里真跑 install.sh 里的 generate_server_config，外部依赖全部打桩、文件都在临时目录。
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'install.sh').read_text(encoding='utf-8')


def function(name):
    match = re.search(r'^' + name + r'\(\) \{\n.*?^\}', SOURCE, re.M | re.S)
    if not match:
        raise AssertionError(name)
    return match.group(0)


@unittest.skipUnless(shutil.which('bash') and shutil.which('jq'), 'needs bash + jq')
class InstallOrderTests(unittest.TestCase):
    def run_generate(self, fetch_ok):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            config = root / 'config.yaml'
            meta = root / 'client_meta.json'
            config.write_text('# old config: auth -> 127.0.0.1:11111\n', encoding='utf-8')
            meta.write_text('{"old": true}\n', encoding='utf-8')
            calls = root / 'calls'
            script = '\n'.join([
                'set -eo pipefail',
                'HY2_DIR=%s; HY2_CONFIG=%s; HY2_META_FILE=%s' % (root, config, meta),
                'LISTEN_PORT=443; PORTAL_LOCAL_PORT=22222; HY2_SUB_PORT=8443; CERT_TYPE=self',
                'CERT_FILE=%s/c.crt; KEY_FILE=%s/c.key; AUTH_PASSWORD=pw; OBFS_PASSWORD=""' % (root, root),
                'PUBLIC_IP=203.0.113.10; SERVER_NAME=node.example.com; IS_INSECURE=true',
                'HOP_PORT_RANGE=""; METER_SECRET=0123456789abcdef0123456789abcdef',
                'log_step(){ :; }; log_info(){ :; }; log_warn(){ :; }; log_err(){ echo "ERR: $*" >&2; }',
                'systemctl(){ echo "systemd 252"; }',
                'select_subscription_port(){ :; }',
                'portal_ensure_py(){ echo "ensure ONLY=${PORTAL_BUNDLE_ONLY:-0}" >> %s; return %d; }'
                % (calls, 0 if fetch_ok else 1),
                'setup_portal(){ echo "setup_portal PLACED=${PORTAL_BUNDLE_PLACED:-0}" >> %s; }' % calls,
                function('generate_server_config'),
                'generate_server_config',
            ])
            result = subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=60)
            return (result, config.read_text(encoding='utf-8'), meta.read_text(encoding='utf-8'),
                    calls.read_text(encoding='utf-8') if calls.exists() else '')

    def test_failed_portal_fetch_leaves_config_and_meta_untouched(self):
        result, config, meta, calls = self.run_generate(fetch_ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(config, '# old config: auth -> 127.0.0.1:11111\n', '取包失败却改了 config.yaml')
        self.assertEqual(meta, '{"old": true}\n', '取包失败却改了 client_meta.json')
        self.assertIn('ensure ONLY=1', calls)
        self.assertNotIn('setup_portal', calls)

    def test_successful_fetch_writes_config_then_finishes_portal_without_refetching(self):
        result, config, meta, calls = self.run_generate(fetch_ok=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('url: http://127.0.0.1:22222/auth', config)
        import json
        self.assertEqual(json.loads(meta)['listen_port'], 443)
        self.assertEqual(calls.splitlines(), ['ensure ONLY=1', 'setup_portal PLACED=1'])


if __name__ == '__main__':
    unittest.main()
