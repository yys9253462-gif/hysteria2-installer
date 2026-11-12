"""reinstall-debian13.sh 拒收会被 InstallNET 改写的 root 密码；--help 只打印说明（2026-11-12 修）。

InstallNET 生成哈希时写的是 `openssl passwd -6 ''$tmpWORD''`，密码没加引号：空格被拆开，
* ? [ 按文件名展开，- 开头被当成选项。磁盘清空后用输入的密码登不上。
摘出「默认值 → 参数校验」与第 5 步的真实代码在 sh 里执行。
"""
import os
import shutil
import subprocess
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'reinstall-debian13.sh'
SRC = SCRIPT.read_text(encoding='utf-8').replace('\r\n', '\n')
SH = shutil.which('sh') or shutil.which('bash')
ENV_KNOBS = ('PASSWORD', 'PORT', 'MIRROR', 'DISK', 'RELEASE', 'SWAP_MB', 'NET_MODE', 'LOG')
BAD = ('ab cd', 'pa*ss', 'p?ss', 'p[1]x', '-pass', "it's", 'pa$s', 'tab\there')
GOOD = ('Abc123', 'a.b_c@d%e+f=g:h,i~j^k-l', '0123456789abcdef')


def run(script, env=None):
    full = {k: v for k, v in os.environ.items() if k not in ENV_KNOBS}
    full.update(env or {})
    return subprocess.run([SH, '-c', script, str(SCRIPT)], capture_output=True, text=True, timeout=20, env=full)


def quote(arg):
    return "'" + arg.replace("'", "'\\''") + "'"


def setup(*args, env=None):
    region = SRC[SRC.index('# ── 默认值'):SRC.index('# 初始化日志')]
    script = 'set -- %s\n' % ' '.join(quote(a) for a in args) + region + 'echo "SETUP_OK PASSWORD=[$PASSWORD]"\n'
    return run(script, env)


def rule_helpers():
    if 'PASSWORD_RULE=' not in SRC:
        return ''
    start = SRC.index('PASSWORD_RULE=')
    return SRC[start:SRC.index('\n}\n', start) + 3]


@unittest.skipUnless(SH, 'requires sh')
class ReinstallPasswordRuleTests(unittest.TestCase):
    def test_unsafe_password_from_option_is_refused_before_anything_runs(self):
        for pwd in BAD:
            with self.subTest(pwd=pwd):
                r = setup('--pwd', pwd)
                self.assertNotEqual(r.returncode, 0)
                self.assertNotIn('SETUP_OK', r.stdout)
                self.assertIn('root 密码只能用字母', r.stdout + r.stderr)

    def test_unsafe_password_from_environment_is_refused(self):
        r = setup(env={'PASSWORD': 'ab cd'})
        self.assertNotIn('SETUP_OK', r.stdout)
        self.assertIn('root 密码只能用字母', r.stdout + r.stderr)

    def test_safe_passwords_pass_through_unchanged(self):
        for pwd in GOOD:
            with self.subTest(pwd=pwd):
                r = setup('--pwd', pwd)
                self.assertIn('SETUP_OK PASSWORD=[%s]' % pwd, r.stdout, r.stderr)

    def test_password_typed_at_the_prompt_is_checked_too(self):
        start = SRC.index('if [ -z "$PASSWORD" ]; then')
        block = SRC[start:SRC.index("printf '   磁盘", start)]
        stubs = ('ask() { printf "%s" "$FAKE_ANSWER"; }\nwarn() { :; }\n'
                 'die() { echo "DIE $*"; exit 1; }\nASSUME_YES=0\nPASSWORD=""\n')
        for answer, refused in (('ab cd', True), ('pa*ss', True), ('Good.Pass-1', False)):
            with self.subTest(answer=answer):
                r = run(stubs + rule_helpers() + block + 'echo "PROMPT_OK [$PASSWORD]"\n', {'FAKE_ANSWER': answer})
                if refused:
                    self.assertIn('DIE root 密码只能用字母', r.stdout)
                    self.assertNotIn('PROMPT_OK', r.stdout)
                else:
                    self.assertIn('PROMPT_OK [Good.Pass-1]', r.stdout)

    def test_help_prints_only_the_header(self):
        r = setup('--help')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('第一次使用请务必先跑 --check', r.stdout)
        self.assertIn('只能用字母、数字和', r.stdout)
        for code in ('INSTALLNET_URL=', 'set -u', 'PORT="${PORT:-22}"'):
            self.assertNotIn(code, r.stdout)


if __name__ == '__main__':
    unittest.main()
