"""README「常用命令」表与 install.sh 实际支持的命令行子命令保持一致（2026-11-13 加）。

此前 `bash install.sh awg <子命令>` 透传一直没写进文档；以后脚本新增子命令而 README 漏写，
或文档里写了脚本并不支持的命令，这里直接失败。
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')
README = (ROOT / 'README.md').read_text(encoding='utf-8').replace('\r\n', '\n')
DISPATCH_RE = re.compile(r'^if \[\[ \$# -gt 0 \]\]; then\n.*?^    esac\n(    case "\$1" in\n.*?^    esac\n)',
                         re.S | re.M)


def cli_commands():
    block = DISPATCH_RE.search(INSTALL).group(1)
    return set(re.findall(r'^        ([a-z][a-z0-9-]*)\)', block, re.M))


def readme_command_table():
    start = README.index('常用命令：')
    end = README.index('\n\n', README.index('| :--- |', start))
    return README[start:end]


class ReadmeCliCommandsTest(unittest.TestCase):
    def test_every_subcommand_is_documented(self):
        commands = cli_commands()
        self.assertIn('awg', commands)
        table = readme_command_table()
        missing = sorted(c for c in commands
                         if not re.search(r'(bash install\.sh |`)%s[` ]' % re.escape(c), table))
        self.assertEqual(missing, [], 'README 常用命令表漏写了这些子命令')

    def test_documented_commands_exist(self):
        documented = set(re.findall(r'bash install\.sh ([a-z][a-z0-9-]*)', readme_command_table()))
        self.assertTrue(documented)
        self.assertEqual(sorted(documented - cli_commands()), [], 'README 写了 install.sh 不支持的命令')


if __name__ == '__main__':
    unittest.main()
