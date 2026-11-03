"""菜单 3 / `install.sh info` 在 ACME 节点上要提示放行 TCP 80（2026-11-04 修）。

这两条入口在子 shell 里跑，CERT_TYPE 只在安装流程里赋值，旧实现永远读到空值，
ACME 节点从不提示 TCP 80，用户关掉安全组后证书续期失败。这里执行真实的
show_client_configs，CERT_TYPE 不设，cert_type 只写在 client_meta.json 里。
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


def fn(name):
    return re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M).group(0)


@unittest.skipUnless(BASH and shutil.which('jq'), 'requires bash and jq')
class InfoAcmePortHintTests(unittest.TestCase):
    def run_info(self, cert_type):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / 'portal-access.json').write_text(
                '{"url":"https://node.example.com:8443/tok/","username":"u","password":"p"}', encoding='utf-8')
            (td / 'client_meta.json').write_text(
                '{"cert_type":"%s","listen_port":443,"hop_port_range":""}' % cert_type, encoding='utf-8')
            script = '\n'.join([
                'RED= GREEN= YELLOW= BLUE= CYAN= PLAIN=', 'log_err() { echo "ERR $*"; }',
                'HY2_DIR="%s"' % bash_path(td), 'HY2_META_FILE="$HY2_DIR/client_meta.json"',
                'unset CERT_TYPE', fn('show_client_configs'), 'show_client_configs'])
            return subprocess.run([BASH, '-c', script], capture_output=True, text=True,
                                  encoding='utf-8', timeout=20).stdout

    def test_acme_node_gets_the_tcp_80_hint(self):
        self.assertIn('TCP 80', self.run_info('acme'))

    def test_custom_cert_node_does_not(self):
        self.assertNotIn('TCP 80', self.run_info('custom'))


if __name__ == '__main__':
    unittest.main()
