"""回归测试：awgctl.sh 连接地址端口拒绝前导零，且卸载自删子进程关闭锁描述符 fd 9。"""
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AWG_SRC = (ROOT / 'awgctl.sh').read_text(encoding='utf-8').replace('\r\n', '\n')
BASH = shutil.which('bash')


@unittest.skipUnless(BASH, 'requires bash')
class AwgEndpointAndUninstallFdTests(unittest.TestCase):
    def _validate_endpoint(self, endpoint):
        start = AWG_SRC.index('validate_endpoint() {')
        end = AWG_SRC.index('\n}\n', start) + 3
        fn_src = AWG_SRC[start:end]
        script = 'log_err() { echo "ERR:$*" >&2; }\n' + fn_src + '\nvalidate_endpoint "$1"\n'
        return subprocess.run(
            [BASH, '-c', script, 'bash', endpoint],
            capture_output=True, text=True, encoding='utf-8', timeout=10,
        )

    def test_validate_endpoint_rejects_leading_zero_ports(self):
        for bad in ('vpn.example.com:051821', '1.2.3.4:08080', '[2001:db8::1]:055000', 'vpn.example.com:00001'):
            with self.subTest(endpoint=bad):
                res = self._validate_endpoint(bad)
                self.assertNotEqual(res.returncode, 0, f'带前导零端口的连接地址被错误放行: {bad}')
        for good in ('vpn.example.com:51821', '1.2.3.4:55000', '[2001:db8::1]:55000', 'vpn.example.com'):
            with self.subTest(endpoint=good):
                res = self._validate_endpoint(good)
                self.assertEqual(res.returncode, 0, f'合法连接地址被误拒: {good}\n{res.stderr}')

    def test_uninstall_self_delete_closes_lock_fd_9(self):
        start = AWG_SRC.index('cmd_uninstall() {')
        end = AWG_SRC.index('\ncmd_status() {', start)
        body = AWG_SRC[start:end]
        line = next(
            (ln for ln in body.splitlines() if 'nohup bash -c' in ln and 'AWG_CTL_INSTALLED' in ln),
            '',
        )
        self.assertTrue(line, '未找到延迟自删后台命令')
        self.assertIn('9>&-', line, '卸载延迟自删后台子进程未关闭继承的锁文件描述符 fd 9')


if __name__ == '__main__':
    unittest.main()
