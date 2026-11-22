"""回归测试：portal.py 统一 _read_xray_json 安全读盘辅助并清零全部 16 处裸 xray.json read_text 调用。"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import portal

ROOT = Path(__file__).resolve().parents[1]
PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')


class TestPortalXrayJsonBoundedSymlinkReadCleanup(unittest.TestCase):
    def test_read_xray_json_helper_guards_symlink_size_and_dict_type(self):
        """_read_xray_json 必须拒绝符号链接与超 4 MiB 文件，非 strict 模式遇到非字典返回 None，strict 模式显式报错。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            p = root / 'xray.json'

            # 1) 不存在 -> 返回 None
            self.assertIsNone(portal._read_xray_json(p))
            self.assertIsNone(portal._read_xray_json(p, strict=True))

            # 2) 超 4 MiB -> 非 strict 返回 None，strict 抛 ValueError
            p.write_bytes(b'{"pad":"' + b'x' * (4 * 1024 * 1024 + 32) + b'"}')
            self.assertIsNone(portal._read_xray_json(p))
            with self.assertRaises(ValueError):
                portal._read_xray_json(p, strict=True)

            # 3) 符号链接 -> 非 strict 返回 None，strict 抛 OSError
            p.write_text('{"inbounds": []}', encoding='utf-8')
            real_is_symlink = Path.is_symlink

            def fake_sym(self_p):
                if self_p == p:
                    return True
                return real_is_symlink(self_p)

            with mock.patch.object(Path, 'is_symlink', autospec=True, side_effect=fake_sym):
                self.assertIsNone(portal._read_xray_json(p))
                with self.assertRaises(OSError):
                    portal._read_xray_json(p, strict=True)

            # 4) 非字典 JSON 数组 -> 非 strict 返回 None；strict 返回原数组交由调用方精准报错
            p.write_text('[]', encoding='utf-8')
            self.assertIsNone(portal._read_xray_json(p))
            self.assertEqual(portal._read_xray_json(p, strict=True), [])

            # 5) 合法 dict -> 正常返回
            p.write_text('{"inbounds": [{"tag": "reality"}]}', encoding='utf-8')
            self.assertEqual(portal._read_xray_json(p), {'inbounds': [{'tag': 'reality'}]})

    def test_no_raw_xray_json_read_text_remains_in_portal(self):
        """portal.py 中不得再残留裸调 xray_path.read_text(...) 或 Path('...xray.json').read_text(...)。"""
        bad = [
            f'L{i}: {ln.strip()}'
            for i, ln in enumerate(PORTAL_SRC.splitlines(), 1)
            if 'xray' in ln and 'read_text(' in ln
        ]
        self.assertEqual(bad, [], f'仍存在无界/无符号链接保护的裸读 xray.json：\n' + '\n'.join(bad))


if __name__ == '__main__':
    unittest.main()
