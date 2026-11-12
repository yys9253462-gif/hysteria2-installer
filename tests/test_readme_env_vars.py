"""install.sh 读取的每个面向用户的 HY2_* 环境变量都要写进 README（2026-11-12 加）。

此前 DNS API 凭据、免交互自带证书、日志级别等十来个参数只在源码里，用户只能在签发失败的
报错里撞见它们；README 还把证书方式 2 写成「需交互」。新加参数忘了写文档时这里会失败。
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / 'install.sh').read_text(encoding='utf-8')
README = (ROOT / 'README.md').read_text(encoding='utf-8')

# 脚本内部状态，不是给用户设置的参数。
INTERNAL = {'HY2_ARCH', 'HY2_SUB_PORT', 'HY2_SYSTEMD_DIR', 'HY2_CERT_REUSE', 'HY2_LOG_LEVEL_EXPLICIT'}


class ReadmeEnvVarsTests(unittest.TestCase):
    def test_every_user_facing_variable_is_documented(self):
        read = set(re.findall(r'\$\{(HY2_[A-Z0-9_]+):?-', INSTALL)) - INTERNAL
        self.assertTrue(read, 'no HY2_* variables found; the pattern is broken')
        missing = sorted(v for v in read if '`%s`' % v not in README)
        self.assertEqual(missing, [], 'README 缺少这些环境变量的说明')

    def test_cert_type_two_is_not_described_as_interactive_only(self):
        self.assertNotIn('指定证书文件（需交互）', README)


if __name__ == '__main__':
    unittest.main()
