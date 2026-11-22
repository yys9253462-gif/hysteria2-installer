"""回归测试：_unlock_fetch 校验主机/超时与仅 http/https 重定向、_h_post_do_upgrade_impl 限计量配置体积与安全 O_NOFOLLOW 写盘/清理隔离、sysctl_conf_overrides 限体积及 _ob_list 清洗非字符串 apply_error。"""

import ast
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import portal

PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')


def _method_src(name: str) -> str:
    tree = ast.parse(PORTAL_SRC)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(PORTAL_SRC, node)
    raise AssertionError(f'未找到方法 {name}')


class TestPortalUnlockRedirectDoUpgradeAtomicSysctlAndOblistGuards(unittest.TestCase):
    def test_unlock_fetch_rejects_bad_host_control_chars_and_invalid_timeout_and_ftp_redirect(self):
        """_unlock_fetch 必须拒绝无主机/含控制字符 URL、布尔或非有限 timeout，且重定向处理器仅放行 http/https。"""
        for bad_url in ('https://', 'https://example.com/\r\nX: 1', 'ftp://example.com/a'):
            with self.subTest(url=bad_url):
                with self.assertRaises(ValueError):
                    portal._unlock_fetch(bad_url)

        for bad_to in (True, float('nan'), float('inf'), -1, 0):
            with self.subTest(timeout=bad_to):
                with self.assertRaises(ValueError):
                    portal._unlock_fetch('https://example.com/', timeout=bad_to)

        handler_cls = getattr(portal, '_UnlockHttpOnlyRedirectHandler', None)
        self.assertIsNotNone(handler_cls, 'portal 应提供仅允许 http/https 重定向的 _UnlockHttpOnlyRedirectHandler')
        handler = handler_cls()
        with self.assertRaises(portal.urllib.error.HTTPError):
            handler.redirect_request(
                portal.urllib.request.Request('https://example.com/'),
                None, 302, 'Found', {}, 'ftp://evil.example/file'
            )

    def test_sysctl_conf_overrides_guards_non_dict_and_oversized_file(self):
        """sysctl_conf_overrides 面对非 dict wanted 或超 2 MiB 文件必须安全返回空列表。"""
        self.assertEqual(portal.sysctl_conf_overrides(None), [])
        self.assertEqual(portal.sysctl_conf_overrides(['bad']), [])
        with tempfile.TemporaryDirectory() as td:
            big = Path(td) / 'sysctl.conf'
            big.write_bytes(b'# ' + b'x' * (2 * 1024 * 1024 + 32) + b'\nnet.ipv4.tcp_congestion_control = cubic\n')
            self.assertEqual(
                portal.sysctl_conf_overrides({'net.ipv4.tcp_congestion_control': 'bbr'}, path=str(big)),
                [],
                '超过 2 MiB 的异常 sysctl.conf 应安全跳过',
            )

    def test_do_upgrade_impl_uses_o_nofollow_and_guards_meter_cfg_size_and_cleanup(self):
        """_h_post_do_upgrade_impl 须限制 reality-online 计量配置体积、写临时文件用 O_NOFOLLOW 并隔离清理 OSError。"""
        src = _method_src('_h_post_do_upgrade_impl')
        self.assertIn('cfg_path.is_symlink()', src, 'reality-online 读 usage-meter-config.json 须拒符号链接')
        self.assertIn('1024 * 1024', src, 'reality-online 读 usage-meter-config.json 须限 1 MiB')
        self.assertIn("getattr(os, 'O_NOFOLLOW', 0)", src,
                      '门户自更新写备份/新文件/回滚临时文件必须叠加 O_NOFOLLOW 与 O_EXCL')
        self.assertIn('dest.is_symlink()', src, '门户自更新目标文件不允许为符号链接')

    def test_ob_list_sanitizes_non_string_apply_error(self):
        """_ob_list 必须清洗非字符串/含控制字符的 apply_error 防 NaN/对象破坏 JSON 响应。"""
        src = _method_src('_ob_list')
        self.assertIn('isinstance(_raw_err, str)', src)


if __name__ == '__main__':
    unittest.main()
