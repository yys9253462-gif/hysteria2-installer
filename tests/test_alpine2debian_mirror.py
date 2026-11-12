"""alpine2debian.sh 的安全更新源跟随 --mirror（2026-11-12 修）。

旧实现 --mirror 只换主源，debian-security 仍固定阿里云；它拉取失败时 chroot 里的
apt-get update 在 set -e 下中止，磁盘已清空、内核与引导却还没装上。
摘出「默认值 → 参数解析」整段真实代码在 sh 里执行。
"""
import os
import shutil
import subprocess
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'alpine2debian.sh'
SRC = SCRIPT.read_text(encoding='utf-8').replace('\r\n', '\n')
SH = shutil.which('sh') or shutil.which('bash')


def run(script, *args, env=None):
    full = {k: v for k, v in os.environ.items() if k not in ('MIRROR', 'SECURITY_MIRROR')}
    full.update(env or {})
    return subprocess.run([SH, '-c', script, *args], capture_output=True, text=True, timeout=20, env=full)


def setup_region():
    return SRC[SRC.index('# ── 默认值'):SRC.index('# ── 第 1 步')]


@unittest.skipUnless(SH, 'requires sh')
class SecurityMirrorTests(unittest.TestCase):
    def security_for(self, *cli, env=None):
        args = ' '.join("'%s'" % a for a in cli)
        r = run('set -- %s\n' % args + setup_region() + 'echo "SEC=$SECURITY_MIRROR"\n', env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip().rpartition('SEC=')[2]

    def test_default_stays_on_aliyun(self):
        self.assertEqual(self.security_for(), 'http://mirrors.aliyun.com/debian-security')

    def test_mirror_option_also_moves_security_source(self):
        cases = {
            'http://deb.debian.org/debian': 'http://deb.debian.org/debian-security',
            'https://mirrors.tuna.tsinghua.edu.cn/debian/': 'https://mirrors.tuna.tsinghua.edu.cn/debian-security',
            'http://ftp.example.net/pub/debian-mirror': 'http://security.debian.org/debian-security',
        }
        for mirror, want in cases.items():
            with self.subTest(mirror=mirror):
                self.assertEqual(self.security_for('--mirror', mirror), want)

    def test_mirror_from_environment_is_followed_too(self):
        self.assertEqual(self.security_for(env={'MIRROR': 'http://deb.debian.org/debian'}),
                         'http://deb.debian.org/debian-security')

    def test_explicit_security_mirror_wins(self):
        self.assertEqual(self.security_for('--mirror', 'http://deb.debian.org/debian',
                                           env={'SECURITY_MIRROR': 'http://sec.example.net/debian-security'}),
                         'http://sec.example.net/debian-security')

    def test_help_prints_the_whole_header_including_the_last_warning(self):
        start = SRC.index('usage() {')
        line = SRC[start:SRC.index('\n', start)]
        r = run(line + '\nusage\n', str(SCRIPT))
        self.assertIn('第一次使用请务必先跑 --dry-run', r.stdout)
        self.assertIn('SECURITY_MIRROR', r.stdout)
        self.assertNotIn('set -eu', r.stdout)


if __name__ == '__main__':
    unittest.main()
