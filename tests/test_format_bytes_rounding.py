"""字节数显示先取整再定单位，不再出现「1024.0 KB」（2026-11-04 修）。后端与弹窗 JS 同一规则。"""
import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402

CASES = {1023: '1023 B', 1024 ** 2 - 1: '1.00 MB', 1024 ** 3 - 1: '1.00 GB', 1024 ** 4 - 1: '1.00 TB',
         1536: '1.5 KB'}


class FormatBytesRoundingTests(unittest.TestCase):
    def test_backend(self):
        for value, text in CASES.items():
            with self.subTest(value=value):
                self.assertEqual(portal.format_bytes(value), text)

    @unittest.skipUnless(shutil.which('node'), 'requires node')
    def test_modal_js(self):
        """用户弹窗的 fmtBytes 与后端逐字一致（2026-11-13 起 KB 也是一位小数，同用户表）。"""
        values = [1023, 1536, 1024 ** 2 - 1, 1024 ** 3 - 1, 1024 ** 4 - 1, 3 * 1024 ** 4]
        js = modal_formatter(portal.SCRIPT) + 'console.log(JSON.stringify(%s.map(fmtBytes)));' % values
        out = subprocess.run(['node', '-e', js], capture_output=True, text=True, timeout=20)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout), [portal.format_bytes(v) for v in values])



def modal_formatter(src):
    """用户弹窗里的 fmtBytes（连同公用的 fmtUnits，旧版本没有它；旧写法是多行箭头函数）。"""
    start = src.index('const fmtBytes = v =>')
    end = src.index('\n', start)
    if src[end - 1] == '{':
        end = src.index('\n      };', start) + len('\n      };')
    helper = ''
    if 'function fmtUnits(' in src:
        h = src.index('function fmtUnits(')
        helper = src[h:src.index('\n}\n', h) + 3]
    return helper + src[start:end] + '\n'


def live_formatters(src):
    """用户表轮询用的 fmtSpeed / fmtUsage（连同公用的 fmtUnits，旧版本没有它）。"""
    speed = src.index('function fmtSpeed(')
    start = src.find('function fmtUnits(')
    start = start if 0 <= start < speed else speed
    helpers = src[start:src.index('\n}\n', speed) + 3]
    usage = src.index('const fmtUsage =')
    end = src.index('\n', usage)
    if src[end - 1] == '{':          # 旧写法是多行箭头函数
        end = src.index('\n    };', usage) + len('\n    };')
    return helpers + src[usage:end] + '\n'


class LiveTrafficFormattingTests(unittest.TestCase):
    """用户表每 2 秒刷新的用量 / 网速与服务端渲染同一写法（2026-11-13 修）。

    旧的 fmtUsage 先换算再四舍五入：首屏服务端渲染的「1.00 MB」两秒后被改写成「1024.00 KB」，
    「1.5 KB」变成「1.50 KB」；fmtSpeed 同理把 1023.6 B/s 显示成「1024 B/s」。
    """
    VALUES = [0, 1023, 1024, 1536, 1048575, 1048576, 5 * 1024 ** 3, 1024 ** 4 - 1, 3 * 1024 ** 4]

    @unittest.skipUnless(shutil.which('node'), 'requires node')
    def test_live_usage_matches_the_server_rendering(self):
        js = live_formatters(portal.SCRIPT) + 'console.log(JSON.stringify(%s.map(fmtUsage)));' % self.VALUES
        out = subprocess.run(['node', '-e', js], capture_output=True, text=True, timeout=20)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout), [portal.format_bytes(v) for v in self.VALUES])

    @unittest.skipUnless(shutil.which('node'), 'requires node')
    def test_live_speed_carries_at_the_rounding_boundary(self):
        js = live_formatters(portal.SCRIPT) + (
            'console.log(JSON.stringify([500, 1023.6, 2048, 1048575, 5 * 1048576, undefined].map(fmtSpeed)));')
        out = subprocess.run(['node', '-e', js], capture_output=True, text=True, timeout=20)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout),
                         ['500 B/s', '1.0 KB/s', '2.0 KB/s', '1.00 MB/s', '5.00 MB/s', '0 B/s'])


class UsagePercentTests(unittest.TestCase):
    def test_only_a_full_quota_reads_100(self):
        self.assertEqual(portal.usage_percent(995, 1000), 99)
        self.assertEqual(portal.usage_percent(1000, 1000), 100)
        self.assertEqual(portal.usage_percent(1500, 1000), 100)
        self.assertEqual(portal.usage_percent(0, 1000), 0)


if __name__ == '__main__':
    unittest.main()
