"""awgctl 的下载不能无限期挂住、也不能让 curl 继承持锁的 fd 9（2026-11-03）。

门户调 awgctl 的超时是 420 秒，超时只杀 bash，不杀 curl。旧的两次下载都没有
--max-time，而 curl 继承了 acquire_lock 打开的 fd 9：下载卡住时孤儿 curl 一直
占着锁，之后每个改 AWG 的命令都等 300 秒再失败，EXIT 回滚也不执行。

这里用一个记录参数与 fd 9 状态的 curl 桩，真跑 download_binaries（不联网）。
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CURL_STUB = '''#!/usr/bin/env bash
{
  printf 'ARGS'; printf ' %s' "$@"; printf '\\n'
  if [ -e /proc/$$/fd/9 ]; then echo 'FD9 open'; else echo 'FD9 closed'; fi
} >> "$CURL_LOG"
exit 22
'''


@unittest.skipIf(shutil.which('bash') is None or sys.platform == 'win32', 'needs bash and /proc')
class AwgctlDownloadLockTests(unittest.TestCase):
    def test_downloads_are_time_bounded_and_do_not_inherit_the_lock(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bindir = root / 'bin'
            bindir.mkdir()
            stub = bindir / 'curl'
            stub.write_text(CURL_STUB, encoding='utf-8')
            stub.chmod(0o755)
            log = root / 'curl.log'
            script = ('source <(sed \'$d\' %s); AWG_LOCK_FILE=%s; acquire_lock; '
                      'download_binaries 3 amd64 || true' % (ROOT / 'awgctl.sh', root / 'awg.lock'))
            env = dict(os.environ, PATH='%s:%s' % (bindir, os.environ.get('PATH', '')),
                       CURL_LOG=str(log))
            subprocess.run(['bash', '-c', script], capture_output=True, text=True,
                           timeout=30, env=env)
            calls = log.read_text(encoding='utf-8').splitlines() if log.exists() else []
            arg_lines = [line for line in calls if line.startswith('ARGS')]
            self.assertTrue(arg_lines, '下载函数没有调用 curl：%r' % calls)
            for line in arg_lines:
                self.assertIn('--max-time', line, '下载没有总时长上限：' + line)
            self.assertNotIn('FD9 open', calls, 'curl 继承了持锁的 fd 9')


if __name__ == '__main__':
    unittest.main()
