"""流量超额停用期间，重新配置 / WARP / gost 菜单不能拉起服务（2026-11-04 修）。

执行 install.sh 里真实的 flow_* 入口，traffic_suspended 读真实的 portal.json，
下游安装函数打桩记录是否被调用。
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
    m = re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M)
    if m:
        return m.group(0)
    return re.search(r'^%s\(\) \{.*\}$' % name, SRC, re.M).group(0)


@unittest.skipUnless(BASH and shutil.which('jq'), 'requires bash and jq')
class MenusRespectSuspensionTests(unittest.TestCase):
    def run_flow(self, flow, suspended):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / 'portal.json').write_text(json.dumps({'traffic_suspend': {'suspended': suspended}}))
            script = '\n'.join([
                'HY2_DIR=%s' % td, 'HY2_CONFIG=%s/portal.json' % td, 'log_warn() { :; }', 'check_root() { :; }', 'require_installed() { :; }',
                'install_warp_local_proxy() { echo RAN; }', 'install_gost() { echo RAN; }', 'check_arch() { :; }',
                'read() { echo RAN; return 1; }',
                fn('traffic_suspended'), fn('refuse_if_suspended'), fn(flow),
                '%s; echo "RC=$?"' % flow])
            return subprocess.run([BASH, '-c', script], capture_output=True, text=True, timeout=20).stdout

    def test_suspended_node_refuses(self):
        for flow in ('flow_warp', 'flow_gost', 'flow_reconfigure', 'flow_install'):
            with self.subTest(flow=flow):
                out = self.run_flow(flow, True)
                self.assertNotIn('RAN', out)
                self.assertIn('RC=1', out)

    def test_active_node_proceeds(self):
        for flow in ('flow_warp', 'flow_gost', 'flow_reconfigure', 'flow_install'):
            with self.subTest(flow=flow):
                self.assertIn('RAN', self.run_flow(flow, False))


if __name__ == '__main__':
    unittest.main()
