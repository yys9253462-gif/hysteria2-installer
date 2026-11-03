"""/etc/sysctl.conf 覆盖 BBR 设置时要指出来，而不是一直提示「重启后生效」（2026-11-04 修）。

systemd-sysctl 按文件名加载，99-sysctl.conf（指向 /etc/sysctl.conf）排在 99-bbr.conf
之后。镜像在 sysctl.conf 里写了 cubic 时，每次开机都覆盖回去，need_reboot 永远消不掉。
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


class SysctlOverrideTests(unittest.TestCase):
    def check(self, text, wanted):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'sysctl.conf'
            p.write_text(text, encoding='utf-8')
            return portal.sysctl_conf_overrides(wanted, str(p))

    def test_conflicting_line_is_reported(self):
        found = self.check('# comment\nnet.ipv4.tcp_congestion_control = cubic\nvm.swappiness=10\n',
                           {'net.ipv4.tcp_congestion_control': 'bbr'})
        self.assertEqual(found, ['net.ipv4.tcp_congestion_control = cubic'])

    def test_matching_commented_or_missing_lines_are_fine(self):
        wanted = {'net.ipv4.tcp_congestion_control': 'bbr'}
        self.assertEqual(self.check('net.ipv4.tcp_congestion_control=bbr\n', wanted), [])
        self.assertEqual(self.check('# net.ipv4.tcp_congestion_control = cubic\n', wanted), [])
        self.assertEqual(self.check('', wanted), [])
        self.assertEqual(portal.sysctl_conf_overrides(wanted, '/nonexistent/sysctl.conf'), [])


if __name__ == '__main__':
    unittest.main()
