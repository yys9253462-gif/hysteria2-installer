"""回归测试：portal.py 代理服务上限/端口前导零/HTTP密码长度/深拷贝快照与 GOST 资产备份常规文件及大小守卫。"""

import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SOURCE = (REPO / 'portal.py').read_text(encoding='utf-8')


class PortalProxyBoundsSnapshotAndGostBackupGuardsTests(unittest.TestCase):
    def test_manage_proxy_enforces_cap_strict_port_http_pass_len_and_deep_snapshots(self):
        """_manage_proxy_operation 须限制代理总数(<=128)、禁前导零端口、限制HTTP/HTTPS密码长度并深拷贝端口快照。"""
        start = SOURCE.index('def _manage_proxy_operation(self, action, params):')
        end = SOURCE.index('def _h_post_manage_proxy(self, prefix):', start)
        block = SOURCE[start:end]

        self.assertIn('len(working) >= 128', block)
        self.assertIn("re.fullmatch(r'[1-9][0-9]{0,4}', raw_port)", block)
        self.assertIn("isinstance(raw_port_in, (int, str))", block)
        self.assertIn("len(password) > 256", block)
        self.assertIn("copy.deepcopy(data.get(k))", block)
        self.assertNotIn("_data_now = dict(data)", block)
        self.assertNotIn("data_snapshot = dict(data)", block)

    def test_install_gost_validates_regular_file_and_size_before_backing_up_assets(self):
        """_h_post_install_gost 备份现有 GOST 资产前须校验常规文件与大小上限，防 FIFO 阻塞或超大文件 OOM。"""
        start = SOURCE.index('def _h_post_install_gost(self, prefix):')
        end = SOURCE.index('with tempfile.TemporaryDirectory() as tmpdir:', start)
        block = SOURCE[start:end]

        self.assertIn('S_ISREG(', block)
        self.assertIn('asset_path.lstat()', block)
        self.assertIn('_max_asset_bytes', block)


if __name__ == '__main__':
    unittest.main()
