"""回归测试：门户备份清理守卫、重启脚本参数校验、受限流读取正整数守卫、校验清单双列严格解析、核心升级编码与锁 O_NOFOLLOW。"""

import ast
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
PORTAL_TREE = ast.parse(PORTAL_SRC)


def _fn_src(name: str) -> str:
    for node in ast.walk(PORTAL_TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(PORTAL_SRC, node)
    raise AssertionError(f'未找到函数 {name}')


class PortalBackupPruneStreamBoundsManifestAndLockGuardsTests(unittest.TestCase):
    def test_prune_portal_backups_guards_keep_and_skips_symlinks(self):
        """_prune_portal_backups 面对 keep<=0/bool/None 时必须保底保留至少 1 轮，且跳过符号链接。"""
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            for stamp in ('20261120-010000-1', '20261121-010000-2', '20261122-010000-3'):
                (d / f'portal.py.bak-{stamp}').write_text('x', encoding='utf-8')
            portal._prune_portal_backups(d, keep=0)
            left = sorted(p.name for p in d.iterdir())
            self.assertEqual(left, ['portal.py.bak-20261122-010000-3'], 'keep=0 时必须至少保留最新 1 轮')

            # bool / None 不得抛 TypeError 且回落默认 keep=3
            portal._prune_portal_backups(d, keep=False)
            portal._prune_portal_backups(d, keep=None)
            self.assertTrue((d / 'portal.py.bak-20261122-010000-3').exists())

        src = _fn_src('_prune_portal_backups')
        self.assertIn('is_symlink()', src)

    def test_portal_update_restart_script_rejects_float_nan_and_huge_digit_strings(self):
        """portal_update_restart_script 必须拒绝小数、NaN 与超长数字字符串 port / wait_seconds。"""
        for bad_port in (18080.9, float('nan'), '0' * 5000 + '8080', '9' * 5000, '08080'):
            with self.subTest(bad_port=bad_port):
                with self.assertRaises(ValueError):
                    portal.portal_update_restart_script(bad_port, [], [])
        for bad_wait in (20.5, float('inf'), '9' * 5000, '20.5', True):
            with self.subTest(bad_wait=bad_wait):
                with self.assertRaises(ValueError):
                    portal.portal_update_restart_script(18080, [], [], wait_seconds=bad_wait)

    def test_bounded_readers_reject_non_positive_or_bool_limits(self):
        """_read_bounded_bytes 与 _copy_stream_bounded 必须拒绝 <=0 或 bool 上限与块大小，防 -1 击穿内存上限。"""
        for bad in (0, -1, -2, True, False, 1.5, '10'):
            with self.subTest(read_limit=bad):
                with self.assertRaises(ValueError):
                    portal._read_bounded_bytes(io.BytesIO(b'abc'), limit=bad)
            with self.subTest(copy_limit=bad):
                with self.assertRaises(ValueError):
                    portal._copy_stream_bounded(io.BytesIO(b'abc'), io.BytesIO(), limit=bad)
            with self.subTest(chunk_size=bad):
                with self.assertRaises(ValueError):
                    portal._copy_stream_bounded(io.BytesIO(b'abc'), io.BytesIO(), limit=100, chunk_size=bad)

    def test_parse_checksum_manifest_rejects_non_str_asset_and_extra_columns(self):
        """parse_checksum_manifest 须拒绝非字符串 asset 及超过两列的含注释/多词行。"""
        h = 'a' * 64
        self.assertIsNone(portal.parse_checksum_manifest(f'{h}  foo.bin\n', 123))
        self.assertIsNone(
            portal.parse_checksum_manifest(f'{h}  other.bin  # not foo.bin\n', 'foo.bin'),
            '行尾注释里的资产名不得被 parts[-1] 误匹配',
        )
        self.assertEqual(portal.parse_checksum_manifest(f'{h}  ././build/foo.bin\n', 'foo.bin'), h)

    def test_core_upgrade_encoding_rollback_cleanup_and_lock_nofollow(self):
        """_upgrade_core_binary_locked 须对版本命令带 errors='replace' 并保护回滚清理；三处锁文件打开须带 O_NOFOLLOW。"""
        up_src = _fn_src('_upgrade_core_binary_locked')
        self.assertGreaterEqual(up_src.count("errors='replace'"), 2)
        rb_idx = up_src.index('if rb_tmp is not None:')
        self.assertIn('except OSError', up_src[rb_idx:rb_idx + 220])

        for fn_name in ('portal_update_process_lock', 'portal_state_file_lock', 'acquire_core_operation_lock'):
            with self.subTest(fn=fn_name):
                self.assertIn('O_NOFOLLOW', _fn_src(fn_name))


if __name__ == '__main__':
    unittest.main()
