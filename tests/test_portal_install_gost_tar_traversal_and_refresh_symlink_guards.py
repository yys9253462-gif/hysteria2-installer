"""回归测试：门户 install-gost 防多层 ./ 穿越/特殊设备成员/符号链接与 O_NOFOLLOW 落盘，及 refresh/_refresh_portal_state 符号链接与体积上限守卫。"""

import ast
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import portal

ROOT = Path(__file__).resolve().parents[1]
PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
TREE = ast.parse(PORTAL_SRC)


def _get_func_source(name: str) -> str:
    for node in ast.walk(TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(PORTAL_SRC, node) or ''
    raise AssertionError(f'portal.py 中未找到函数 {name}')


class TestPortalInstallGostTarTraversalAndRefreshSymlinkGuards(unittest.TestCase):
    def test_install_gost_strips_nested_dot_slash_blocks_special_nodes_and_uses_o_nofollow(self):
        """_h_post_install_gost 必须循环剥离多层 ./、拒绝 FIFO/设备节点、拒绝符号链接资产并用 O_EXCL|O_NOFOLLOW 写 staged。"""
        src = _get_func_source('_h_post_install_gost')
        self.assertIn("while clean.startswith('./'):", src,
                      'tar 成员校验必须循环剥离多层 ./，不能只剥一次漏掉 ././/etc/passwd')
        self.assertIn('m.isfifo() or m.ischr() or m.isblk() or m.isdev()', src,
                      'tar 成员校验必须拦截 FIFO/字符/块设备等特殊节点')
        self.assertIn('gost_binary.is_symlink()', src, 'install-gost 必须拒绝符号链接形式的 gost 二进制或资产')
        self.assertIn("os.O_WRONLY | os.O_CREAT | os.O_EXCL", src,
                      'staged 写盘必须使用 O_EXCL 与 O_NOFOLLOW 防预置符号链接覆写')
        self.assertIn("errors='replace'", src, 'install-gost 子进程文本解码必须带 errors=replace')

    def test_refresh_and_refresh_portal_state_reject_symlinks_and_oversized_files(self):
        """refresh 与 _refresh_portal_state 必须拒绝符号链接与体积超限的 client_meta.json / portal.json。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            meta = root / 'client_meta.json'
            pjson = root / 'portal.json'
            meta.write_bytes(b'{"a":"' + b'x' * (1024 * 1024 + 32) + b'"}')
            pjson.write_text('{}', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, '过大'):
                portal._refresh_portal_state(meta)

            meta.write_text('{"server_name": "a.example.com", "public_ip": "1.2.3.4", "listen_port": 443}', encoding='utf-8')
            real_is_symlink = Path.is_symlink

            def fake_sym(self_p):
                if self_p == pjson:
                    return True
                return real_is_symlink(self_p)

            with mock.patch.object(Path, 'is_symlink', autospec=True, side_effect=fake_sym):
                with self.assertRaisesRegex(OSError, '符号链接'):
                    portal.refresh(meta)


if __name__ == '__main__':
    unittest.main()
