"""panel-join.py 的输出安全与参数校验（2026-11-04 修）。

真实运行脚本：临时目录里造 config.yaml / portal.json / client_meta.json。
"""
import json
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')


class PanelJoinSafetyTests(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        d = Path(self._td.name)
        self.cfg = d / 'config.yaml'
        self.cfg.write_text('listen: :443\nmasquerade:\n  listenHTTPS: 0.0.0.0:8443\n', encoding='utf-8')
        (d / 'portal.json').write_text(json.dumps({'api_key': 'k' * 32, 'port': 1}), encoding='utf-8')
        (d / 'meta.json').write_text(json.dumps({'server_name': 'node.example.com'}), encoding='utf-8')
        self.base = [sys.executable, str(ROOT / 'panel-join.py'), '--config', str(self.cfg),
                     '--portal', str(d / 'portal.json'), '--meta', str(d / 'meta.json')]

    def tearDown(self):
        self._td.cleanup()

    def run_pj(self, *args):
        import os
        env = dict(os.environ, PYTHONIOENCODING='utf-8')
        return subprocess.run(self.base + list(args), capture_output=True, text=True,
                              encoding='utf-8', timeout=30, env=env)

    def test_listen_https_with_host_gives_a_valid_url(self):
        r = self.run_pj('--format', 'json')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)['api_url'], 'https://node.example.com:8443')

    def test_panel_must_be_https(self):
        r = self.run_pj('--format', 'curl', '--panel', 'http://panel.example')
        self.assertEqual(r.returncode, 2)

    @unittest.skipUnless(BASH, 'requires bash')
    def test_curl_output_is_safe_to_paste(self):
        """--name 里的引号不能拼出额外命令；JWT 不原样打印。"""
        r = self.run_pj('--format', 'curl', '--panel', 'https://panel.example/',
                        '--name', "a'; touch PWNED; '", '--admin-token', 'SECRET-JWT')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn('SECRET-JWT', r.stdout)
        self.assertNotIn('//api/nodes', r.stdout)
        # 把生成的命令交给 bash 解析（curl 换成打印参数的桩），看注入的命令有没有被执行
        with tempfile.TemporaryDirectory() as td:
            # 参数用 NUL 分隔写出，免得 JSON 被按行切开
            script = ('curl() { printf "%s\\0" "$@" > args; }\nPANEL_ADMIN_TOKEN=t\n' + r.stdout)
            subprocess.run([BASH, '-c', script], cwd=td, timeout=10)
            self.assertFalse((Path(td) / 'PWNED').exists(), '粘贴 curl 命令执行了注入的命令')
            argv = (Path(td) / 'args').read_text(encoding='utf-8').split('\0')
            body = argv[argv.index('-d') + 1]
        self.assertEqual(json.loads(body)['name'], "a'; touch PWNED; '")


if __name__ == '__main__':
    unittest.main()
