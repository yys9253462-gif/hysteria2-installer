"""新建用户表单在浏览器里就按服务端的规则校验（2026-11-13 修）。

旧表单的用户标识只有 required，填了「a b」或 65 个字符要提交到服务端才被拒；备注没有长度上限，服务端
超过 200 个字符直接截断、不提示；流量步长 0.5，填 0.3 GB 被浏览器拦下，而服务端接受任意数值。
"""
import html
import json
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402
from test_hash_routing import render  # noqa: E402

NODE = shutil.which('node')


def attrs(page, ident):
    tag = re.search(r'<input\b[^>]*\bid="%s"[^>]*>' % ident, page).group(0)
    return {k: html.unescape(v) for k, v in re.findall(r'\b([a-z-]+)="([^"]*)"', tag)}


class UserFormConstraintsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        page = render()
        cls.uid, cls.pwd = attrs(page, 'f_uid'), attrs(page, 'f_pwd')
        cls.traffic, cls.note = attrs(page, 'f_traffic'), attrs(page, 'f_note')

    def test_user_id_rule_matches_the_server(self):
        pattern = self.uid.get('pattern', '')
        self.assertTrue(pattern, '用户标识没有格式约束')
        for sample in ('user_01', 'a.b-c', 'A_9', 'x' * 64, 'x' * 65, 'a b', '中文', 'a/b', 'a+b'):
            with self.subTest(sample=sample):
                self.assertEqual(bool(re.fullmatch(pattern, sample)), bool(portal.USER_ID_RE.match(sample)))
        self.assertEqual(self.uid.get('maxlength'), '64')

    def test_password_may_not_start_or_end_with_whitespace(self):
        pattern = self.pwd.get('pattern', '')
        self.assertTrue(pattern, '密码没有约束')
        for sample, ok in (('abc', True), ('a b', True), ('x', True), (' abc', False), ('abc ', False)):
            with self.subTest(sample=sample):
                self.assertEqual(bool(re.fullmatch(pattern, sample)), ok)

    def test_quota_and_note_limits_match_the_server(self):
        self.assertEqual(self.traffic.get('step'), 'any')
        self.assertEqual(self.traffic.get('max'), '1000000')
        self.assertEqual(self.note.get('maxlength'), '200')

    @unittest.skipUnless(NODE, 'requires node')
    def test_patterns_compile_the_way_browsers_compile_them(self):
        patterns = [self.uid.get('pattern', ''), self.pwd.get('pattern', '')]
        js = ('for (const p of %s) { new RegExp("^(?:" + p + ")$", "v"); new RegExp("^(?:" + p + ")$", "u"); }'
              % json.dumps(patterns))
        run = subprocess.run([NODE, '-e', js], capture_output=True, text=True, encoding='utf-8', timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == '__main__':
    unittest.main()
