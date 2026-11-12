"""门户命令行缺参数时报用法、未知子命令列全可用命令（2026-11-12 修）。

旧实现直接取 sys.argv[n]，缺参数抛 IndexError 堆栈；未知子命令的提示漏了 adopt。
真起 portal.py 进程，只走参数检查，不碰任何文件。
"""
import subprocess
import sys
import unittest
from pathlib import Path

PORTAL = Path(__file__).resolve().parents[1] / 'portal.py'


def run(*args):
    return subprocess.run([sys.executable, str(PORTAL), *args], capture_output=True, text=True,
                          encoding='utf-8', timeout=60)


class PortalCliUsageTests(unittest.TestCase):
    def test_missing_arguments_print_usage_instead_of_a_traceback(self):
        cases = {('prepare',): 'prepare', ('prepare', 'meta.json'): 'prepare', ('refresh',): 'refresh',
                 ('adopt', 'meta.json'): 'adopt', ('selfheal',): 'selfheal', ('serve',): 'serve'}
        for args, cmd in cases.items():
            with self.subTest(args=args):
                r = run(*args)
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertIn('用法: python3 portal.py ' + cmd, r.stderr)
                self.assertNotIn('Traceback', r.stderr)

    def test_unknown_subcommand_lists_every_valid_one(self):
        r = run('bogus')
        self.assertEqual(r.returncode, 2)
        for cmd in ('prepare', 'refresh', 'adopt', 'selfheal', 'serve'):
            self.assertIn(cmd, r.stderr)


if __name__ == '__main__':
    unittest.main()
