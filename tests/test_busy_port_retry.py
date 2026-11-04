"""主监听端口被占时答 y 就地重选，而不是照样中止（2026-11-04 修）。

摘出 setup_ports_and_obfs 里真实的占用检测循环执行；port_owner 打桩成 44300 被占。
"""
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def fn(name):
    return re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M).group(0)


@unittest.skipUnless(BASH, 'requires bash')
class BusyPortRetryTests(unittest.TestCase):
    def run_loop(self, answers, env_port=''):
        body = fn('setup_ports_and_obfs')
        start = body.index('    while [[ -n "${LISTEN_PORT:-}" ]] && is_valid_port "$LISTEN_PORT"')
        end = body.index('\n    done\n', start) + len('\n    done\n')
        script = '\n'.join([
            'log_err() { :; }', 'log_info() { :; }', fn('is_valid_port'),
            'port_owner() { [[ "$2" == 44300 ]] && echo busyd; }',
            '_running_port=""', 'LISTEN_PORT=44300', 'HY2_PORT=%s' % env_port,
            'f() {', body[start:end], 'return 0; }',
            'f; echo "RC=$? PORT=$LISTEN_PORT"'])
        return subprocess.run([BASH, '-c', script], input=answers, capture_output=True,
                              text=True, timeout=20).stdout

    def test_yes_reprompts_and_accepts_a_free_port(self):
        self.assertIn('RC=0 PORT=45000', self.run_loop('y\n45000\n'))

    def test_no_aborts(self):
        self.assertIn('RC=1', self.run_loop('n\n'))

    def test_env_port_never_prompts(self):
        self.assertIn('RC=1', self.run_loop('y\n45000\n', env_port='44300'))


if __name__ == '__main__':
    unittest.main()
