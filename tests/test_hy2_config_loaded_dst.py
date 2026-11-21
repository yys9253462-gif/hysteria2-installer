"""回归测试：_hy2_config_loaded 解析 UTC/GMT 启动时间不得受本地夏令时（DST）偏移 1 小时影响。"""

import datetime
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class Hy2ConfigLoadedDstTests(unittest.TestCase):
    def test_utc_timestamp_immune_to_dst_offset_mismatch(self):
        """当本机处于夏令时（mktime 偏移与 time.timezone 差 3600 秒）时，UTC 启动时间解析仍必须精确到秒。"""
        # 构造一个真实的 UTC 时刻：2026-07-15 12:00:00 UTC
        real_utc = datetime.datetime(2026, 7, 15, 12, 0, 0, tzinfo=datetime.timezone.utc).timestamp()
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'config.yaml'
            cfg.write_text('listen: :443\n', encoding='utf-8')
            # 配置文件在服务启动后 60 秒才被修改 -> 尚未加载，必须返回 False！
            os.utime(cfg, (real_utc + 60, real_utc + 60))

            # 模拟处于 CEST (UTC+2) 夏令时的机器：
            # mktime 把无时区的 "2026-07-15 12:00:00" 当作本地 UTC+2 解析（得到 real_utc - 7200），
            # 而 time.timezone 是冬令时标准偏移 -3600，旧代码减 (-3600) 后会变成 real_utc - 3600；
            # 再模拟 EDT (UTC-4) 机器：mktime 得 real_utc + 14400，time.timezone = +18000 ->
            # 旧代码减 18000 得 real_utc - 3600；
            # 模拟反向（如夏令时比冬令时多 +3600 的 mktime，实际如南半球或本地正偏移）：
            # 更直接地：令模拟本地时区为 UTC-4 (EDT)，time.timezone=+18000，则 mktime 返回 real_utc + 14400。
            # 若 mtime = real_utc - 10（启动前 10 秒改的，已加载），旧代码算出的 timestamp = real_utc - 3600，
            # 于是 real_utc - 10 <= real_utc - 3600 + 1 为 False（把已加载的误判为未加载！）。
            os.utime(cfg, (real_utc - 10, real_utc - 10))
            with mock.patch.object(portal.time, 'mktime', side_effect=lambda st: real_utc + 14400), \
                 mock.patch.object(portal.time, 'timezone', 18000):
                loaded = portal._hy2_config_loaded(
                    str(cfg),
                    identity=('active', '1234', 'Wed 2026-07-15 12:00:00 UTC'),
                )
            self.assertTrue(loaded, '夏令时机器上启动前已写好的配置被误判为未加载（偏移 1 小时）')


if __name__ == '__main__':
    unittest.main()
