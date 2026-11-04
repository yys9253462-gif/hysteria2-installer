"""重新配置换了端口后收回旧端口的防火墙放行（2026-11-04 修）。

执行真实的 close_replaced_ports：ufw 处于 active，打桩记录调用。
"""
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def fn(name):
    return re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M).group(0)


@unittest.skipUnless(BASH and shutil.which('jq'), 'requires bash and jq')
class CloseReplacedPortsTests(unittest.TestCase):
    def run_close(self, old_udp, old_tcp, data=None):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / 'portal.json').write_text(json.dumps(data or {}))
            script = '\n'.join([
                'HY2_DIR=%s' % td, 'LISTEN_PORT=51000', 'HY2_SUB_PORT=52000', 'log_info() { :; }',
                'ufw() { if [[ "$1" == status ]]; then echo "Status: active"; else echo "UFW $*" >> %s/calls; fi; }' % td,
                'systemctl() { return 1; }',
                'command() { if [[ "$1" == -v ]]; then [[ "$2" == ufw ]]; return; fi; builtin command "$@"; }',
                fn('is_valid_port'), fn('close_replaced_ports'),
                'close_replaced_ports "%s" "%s"' % (old_udp, old_tcp)])
            subprocess.run([BASH, '-c', script], capture_output=True, text=True, timeout=20)
            calls = Path(td) / 'calls'
            return calls.read_text() if calls.exists() else ''

    def test_changed_ports_are_closed(self):
        out = self.run_close(44300, 8999)
        self.assertIn('UFW delete allow 44300/udp', out)
        self.assertIn('UFW delete allow 8999/tcp', out)

    def test_unchanged_ports_are_kept(self):
        self.assertNotIn('UFW', self.run_close(51000, 52000))

    def test_port_still_used_by_managed_protocol_is_kept(self):
        out = self.run_close(44300, 8999, {'tuic_config': {'port': 44300}})
        self.assertNotIn('44300', out)
        self.assertIn('8999/tcp', out)


if __name__ == '__main__':
    unittest.main()
