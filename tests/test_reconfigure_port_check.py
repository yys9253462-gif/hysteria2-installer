"""重新配置时换成被占用的新端口要拦下（2026-11-03 修）。

旧条件是「hysteria-server 没在跑才检查」：重新配置 / 重装时服务总在跑，
换成被 TUIC / AWG 占着的 UDP 端口也不提示，Hysteria 绑不上、节点掉线。
沿用正在运行的那个端口时照旧跳过（它本来就被 Hysteria 自己占着）。
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def bash_path(path):
    cygpath = shutil.which('cygpath')
    if cygpath:
        return subprocess.run([cygpath, '-u', str(path)], capture_output=True, text=True).stdout.strip()
    return Path(path).as_posix()


def block():
    # 结尾是 `fi`（旧）或 `done`（2026-11-04 改成就地重选的循环）
    m = re.search(r'\n(    # ⚠️ 主监听端口占用检测.*?\n    (?:fi|done)\n)\n    # 端口跳跃', SRC, re.S)
    return m.group(1)


@unittest.skipUnless(BASH and shutil.which('jq'), 'requires bash and jq')
class ReconfigurePortCheckTests(unittest.TestCase):
    def run_check(self, listen_port, running=True):
        with tempfile.TemporaryDirectory() as td:
            meta = Path(td) / 'client_meta.json'
            meta.write_text('{"listen_port": 443}', encoding='utf-8')
            script = '\n'.join([
                'log_err() { echo "ERR $*"; }', 'log_info() { :; }',
                'is_valid_port() { return 0; }',
                'systemctl() { %s; }' % ('return 0' if running else 'return 3'),
                'port_owner() { [[ "$2" == 443 || "$2" == 45000 ]] && echo busy-proc; }',
                'HY2_META_FILE="%s"' % bash_path(meta), 'LISTEN_PORT=%s' % listen_port,
                'f() {', block(), 'echo PASSED', '}', 'f </dev/null'])
            return subprocess.run([BASH, '-c', script], capture_output=True, text=True,
                                  encoding='utf-8', timeout=20).stdout

    def test_new_port_taken_by_another_service_is_caught_while_running(self):
        out = self.run_check(45000, running=True)
        self.assertIn('ERR', out)
        self.assertNotIn('PASSED', out)

    def test_keeping_the_running_port_is_not_flagged(self):
        self.assertIn('PASSED', self.run_check(443, running=True))

    def test_free_new_port_passes(self):
        self.assertIn('PASSED', self.run_check(46000, running=True))


if __name__ == '__main__':
    unittest.main()
