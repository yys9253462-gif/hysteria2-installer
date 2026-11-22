"""回归测试：核心配置与单元读取辅助函数防符号链接、体积上限与坏编码容错。"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import portal  # noqa: E402


class PortalCoreHelpersSymlinkSizeAndDecodeGuardsTests(unittest.TestCase):
    def test_existing_outbound_names_rejects_symlink_oversized_and_tolerates_bad_utf8(self):
        """_existing_outbound_names 须拒绝符号链接与超 4 MiB 配置，并对坏 UTF-8 宽容解码。"""
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'config.yaml'
            # 1) 超 4 MiB 直接返回空
            cfg.write_bytes(b'outbounds:\n  - name: ok_out\n' + b'#' * (4 * 1024 * 1024 + 32))
            with patch.object(portal, 'Path', return_value=cfg):
                self.assertEqual(portal._existing_outbound_names(), [])

            # 2) 符号链接直接返回空
            cfg.write_text('outbounds:\n  - name: ok_out\n', encoding='utf-8')
            with patch.object(portal, 'Path', return_value=cfg), \
                    patch.object(Path, 'is_symlink', autospec=True, side_effect=lambda p: p == cfg):
                self.assertEqual(portal._existing_outbound_names(), [])

            # 3) 含坏 UTF-8 注释行仍可提取出站名
            cfg.write_bytes(b'# bad \xff\xfe comment\noutbounds:\n  - name: warp_socks\n')
            with patch.object(portal, 'Path', return_value=cfg):
                self.assertIn('warp_socks', portal._existing_outbound_names())

    def test_config_acme_cert_path_and_gost_tls_paths_reject_symlink_and_oversized(self):
        """_config_acme_cert_path 与 gost_tls_paths 须拒绝符号链接与超 4 MiB config.yaml。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = root / 'config.yaml'
            cfg.write_bytes(b'acme:\n  domains:\n    - ex.com\n' + b'#' * (4 * 1024 * 1024 + 32))
            self.assertIsNone(portal._config_acme_cert_path(str(cfg)))

            cfg.write_text('acme:\n  domains:\n    - ex.com\n', encoding='utf-8')
            with patch.object(Path, 'is_symlink', autospec=True, side_effect=lambda p: p == cfg):
                self.assertIsNone(portal._config_acme_cert_path(str(cfg)))

            # gost_tls_paths：超 4 MiB 的 config.yaml 读 key 不得把整个文件读入内存
            cert = root / 'server.crt'
            key = root / 'server.key'
            cert.write_text('CERT', encoding='utf-8')
            key.write_text('KEY', encoding='utf-8')
            cfg.write_bytes(b'tls:\n  cert: server.crt\n  key: server.key\n' + b'#' * (4 * 1024 * 1024 + 32))
            with patch.object(Path, 'read_bytes', side_effect=AssertionError('超限文件不应调用 read_bytes')), \
                    patch.object(Path, 'read_text', side_effect=AssertionError('超限文件不应调用 read_text')):
                with self.assertRaises(RuntimeError):
                    portal.gost_tls_paths(root)

    def test_xray_unit_foreign_and_write_xray_unit_reject_symlink_and_oversized(self):
        """xray_unit_foreign 对符号链接或超 1 MiB 须返 True 拒覆盖；write_xray_unit 须拒符号链接。"""
        with tempfile.TemporaryDirectory() as td:
            unit = Path(td) / 'xray.service'
            unit.write_text(portal.XRAY_OWNED_EXECSTART + '\n', encoding='utf-8')
            with patch.object(Path, 'is_symlink', autospec=True, side_effect=lambda p: p == unit):
                self.assertTrue(portal.xray_unit_foreign(unit))

            unit.write_bytes((portal.XRAY_OWNED_EXECSTART + '\n').encode('utf-8') + b'#' * (1024 * 1024 + 32))
            self.assertTrue(portal.xray_unit_foreign(unit))

            unit.write_text('old\n', encoding='utf-8')
            with patch.object(portal, 'Path', return_value=unit), \
                    patch.object(Path, 'is_symlink', autospec=True, side_effect=lambda p: p == unit):
                with self.assertRaisesRegex(OSError, '符号链接'):
                    portal.write_xray_unit()

    def test_protocol_port_in_use_fails_closed_on_symlink_or_oversized_config(self):
        """protocol_port_in_use 遇到符号链接或超 4 MiB 的 anytls.json 时须 fail-closed 返回 True 且不读内容。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            anytls_cfg = root / portal.ANYTLS_CONFIG_NAME
            anytls_cfg.write_bytes(b'{' + b' ' * (4 * 1024 * 1024 + 32) + b'}')

            with patch.object(portal, 'Path', return_value=root), \
                    patch.object(portal, '_systemd_state', return_value='active'), \
                    patch.object(Path, 'read_bytes', side_effect=AssertionError('超限不应读取')), \
                    patch.object(Path, 'read_text', side_effect=AssertionError('超限不应读取')):
                self.assertTrue(portal.protocol_port_in_use(8443, 'tcp', {}, None))

            anytls_cfg.write_text(json.dumps({'inbounds': []}), encoding='utf-8')
            with patch.object(portal, 'Path', return_value=root), \
                    patch.object(portal, '_systemd_state', return_value='active'), \
                    patch.object(Path, 'is_symlink', autospec=True, side_effect=lambda p: p == anytls_cfg), \
                    patch.object(Path, 'read_bytes', side_effect=AssertionError('符号链接不应读取')), \
                    patch.object(Path, 'read_text', side_effect=AssertionError('符号链接不应读取')):
                self.assertTrue(portal.protocol_port_in_use(8443, 'tcp', {}, None))


if __name__ == '__main__':
    unittest.main()
