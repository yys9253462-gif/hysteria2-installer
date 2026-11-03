"""GOST 安装：跑不起来的新二进制不能覆盖正在用的旧 gost（2026-11-04 修）。

摘要与官方 checksums.txt 一致只说明下载完整，不说明能在本机执行（架构判错、
noexec、依赖缺失）。旧实现直接 os.replace 覆盖，所有代理随下次重启全部失效。
这里把真实的「暂存 → 校验 → 替换」那段代码摘出来，在临时目录里执行。
"""
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')


def staging_block():
    m = re.search(r"\n( +)if src_bin\.exists\(\):\n.*?\n\1    os\.replace\(str\(staged\), '/usr/local/bin/gost'\)\n",
                  SRC, re.S)
    return textwrap.dedent(m.group(0).lstrip('\n'))


@unittest.skipIf(os.name == 'nt', 'needs POSIX executables')
class GostInstallVerifyTests(unittest.TestCase):
    def run_block(self, new_script):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            target = root / 'gost'
            target.write_text('#!/bin/sh\necho gost old\n', encoding='utf-8')
            target.chmod(0o755)
            src_bin = root / 'downloaded-gost'
            src_bin.write_text(new_script, encoding='utf-8')
            code = staging_block().replace('/usr/local/bin/gost', str(target))
            body = 'for _ in [0]:\n' + textwrap.indent(code, '    ')
            env = {'Path': Path, 'shutil': __import__('shutil'), 'os': os, 'subprocess': subprocess,
                   'src_bin': src_bin, 'errors': [], 'host': 'mirror', 'assets_modified': False,
                   'installed': False}
            exec(compile(body, '<gost-stage>', 'exec'), env)
            return target.read_text(encoding='utf-8'), env['errors']

    def test_binary_that_cannot_run_is_not_installed(self):
        current, errors = self.run_block('#!/bin/sh\nexit 126\n')
        self.assertIn('gost old', current, '跑不起来的新 gost 覆盖了旧版本')
        self.assertTrue(errors)

    def test_working_binary_is_installed(self):
        current, errors = self.run_block('#!/bin/sh\necho "gost v3.2.6 (go1.25 linux/amd64)"\n')
        self.assertIn('v3.2.6', current)
        self.assertEqual(errors, [])


if __name__ == '__main__':
    unittest.main()
