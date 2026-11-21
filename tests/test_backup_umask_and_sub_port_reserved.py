"""回归测试：install.sh 重配置快照私有权限且无磁盘清单残片，及 select_subscription_port 避让 TUIC 与代理端口。"""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8')


class BackupUmaskAndSubPortReservedTests(unittest.TestCase):
    def _fn_body(self, name: str) -> str:
        start = SRC.index(f'{name}() {{')
        end = SRC.index('\n}\n', start) + 3
        return SRC[start:end]

    def test_backup_state_uses_umask_077_chmod_600_and_no_disk_snapshot_list_file(self):
        body = self._fn_body('backup_state_before_reconfigure')
        self.assertIn('umask 077', body, '备份包含密码与私钥的文件时必须在 umask 077 下创建副本')
        self.assertIn('chmod 600', body, '备份副本应显式收紧为 600 权限')
        self.assertNotIn('.snapshot-list-', body, '不应在配置目录创建易残留的 .snapshot-list-$$ 磁盘临时文件')

    def test_select_subscription_port_reserves_tuic_and_proxy_services_ports(self):
        body = self._fn_body('select_subscription_port')
        self.assertIn("'tuic_config'", body, 'select_subscription_port 必须同时避让 tuic_config 端口')
        self.assertIn("'proxy_services'", body, 'select_subscription_port 必须同时避让 proxy_services 中已登记的代理端口')


if __name__ == '__main__':
    unittest.main()
