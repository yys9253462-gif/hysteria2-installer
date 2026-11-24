"""回归测试：usage-meter-xray-config 零 TOCTOU 读取/O_DIRECTORY 刷盘/备份符号链接拦截与 usage-meter-core 控制字符及 retired_users 清洗守卫。"""

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, REPO / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class UsageMeterXrayNofollowDirsyncAndCoreUidRetiredGuardsTests(unittest.TestCase):
    def test_xray_config_read_uses_nofollow_fstat_dirsync_o_directory_and_backup_symlink_guard(self):
        """_read_regular_config_bytes 须用 O_NOFOLLOW+fstat，_fsync_parent_dir 须带 O_DIRECTORY，且备份前拒符号链接。"""
        src = (REPO / 'usage-meter-xray-config-20261007-v1.py').read_text(encoding='utf-8')
        self.assertIn("getattr(os, 'O_NOFOLLOW', 0)", src)
        self.assertIn('os.fstat(fd)', src)
        self.assertIn("os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0)", src)
        self.assertGreaterEqual(src.count('if backup.is_symlink():'), 2)

        mod = _load('um_xray_b65', 'usage-meter-xray-config-20261007-v1.py')
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'xray.json'
            p.write_text('{"inbounds":[]}', encoding='utf-8')
            raw, mode = mod._read_regular_config_bytes(p)
            self.assertEqual(raw, b'{"inbounds":[]}')
            self.assertGreater(mode, 0)

            # 模拟超大文件超过 4 MiB 应抛 ValueError
            fake_st = os.stat_result((0o100600, 0, 0, 1, 0, 0, mod._MAX_XRAY_CONFIG_BYTES + 1, 0, 0, 0))
            with mock.patch.object(Path, 'lstat', return_value=fake_st):
                with self.assertRaises(ValueError):
                    mod._read_regular_config_bytes(p)

    def test_usage_meter_core_rejects_ctrl_uid_and_sanitizes_corrupt_retired_users(self):
        """total_bytes/adjusted_bytes 须拒绝含控制字符 uid；apply_sample 须清洗非列表或含控制字符的 retired_users。"""
        core = _load('um_core_b65', 'usage-meter-core-20261007-v1.py')
        state = {'totals': {'alice': {'hysteria': 100}}, 'adjustments': {'alice': 0}}
        self.assertEqual(core.total_bytes(state, 'alice'), 100)
        self.assertEqual(core.adjusted_bytes(state, 'alice'), 100)
        for bad_uid in ('a\nb', 'a\x00b', 'a\x7fb'):
            with self.assertRaises(ValueError):
                core.total_bytes(state, bad_uid)
            with self.assertRaises(ValueError):
                core.adjusted_bytes(state, bad_uid)

        # retired_users 损坏成非列表时，即使 active_users=None 也应归一清洗并记缺口
        corrupt = {'retired_users': {'bad': 1}, 'totals': {}}
        core.apply_sample(corrupt, 'hysteria', 'ep1', {'alice': {'tx': 10, 'rx': 20}}, 1700000000)
        self.assertEqual(corrupt['retired_users'], [])
        self.assertTrue(any(g.get('reason') == 'corrupt_retired_reset' for g in corrupt.get('gaps', [])))

        # retired_users 含控制字符元素应被过滤
        dirty = {'retired_users': ['ok_user', 'bad\nuser'], 'totals': {}}
        core.apply_sample(dirty, 'hysteria', 'ep1', {'alice': {'tx': 10, 'rx': 20}}, 1700000001)
        self.assertEqual(dirty['retired_users'], ['ok_user'])


if __name__ == '__main__':
    unittest.main()
