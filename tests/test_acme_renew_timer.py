"""没有 cron 的机器上，acme.sh 以 --nocron 安装，并由 systemd timer 跑 --cron 续期（2026-11-04 修）。

上游 acme.sh 在缺 crontab 时 `--install` 直接返回 1（要求 --force），Nginx / DNS API 两条
签发路都失败；即便装上，也没人调用 --cron，证书 90 天后过期、reloadcmd 永不执行。
执行真实的 hy2_acme_ensure_renew_timer，PATH 里只放桩命令。
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def fn(name):
    return re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M).group(0)


@unittest.skipUnless(BASH and os.name != 'nt', 'requires bash on POSIX')
class AcmeRenewTimerTests(unittest.TestCase):
    def run_timer(self, with_cron):
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            (t / 'bin').mkdir()
            (t / 'units').mkdir()
            (t / 'bin' / 'systemctl').write_text('#!/bin/sh\necho "$@" >> %s/systemctl.log\n' % t)
            if with_cron:
                (t / 'bin' / 'crontab').write_text('#!/bin/sh\necho "0 0 * * * /root/.acme.sh/acme.sh --cron"\n')
            for f in (t / 'bin').iterdir():
                f.chmod(0o755)
            script = '\n'.join(['PATH=%s:/usr/bin:/bin' % (t / 'bin'), 'HY2_SYSTEMD_DIR=%s' % (t / 'units'),
                                fn('hy2_acme_ensure_renew_timer'),
                                'hy2_acme_ensure_renew_timer /root/.acme.sh; echo "RC=$?"'])
            # crontab 不在 PATH 里时 command -v 必须找不到：确认系统里没有真的 crontab 混进来
            env = dict(os.environ, PATH='%s:/usr/bin:/bin' % (t / 'bin'))
            out = subprocess.run([BASH, '-c', script], capture_output=True, text=True, timeout=20, env=env).stdout
            units = {p.name: p.read_text() for p in (t / 'units').iterdir()}
            log = (t / 'systemctl.log').read_text() if (t / 'systemctl.log').exists() else ''
        return out, units, log

    def test_without_cron_a_timer_runs_acme_cron(self):
        if shutil.which('crontab', path='/usr/bin:/bin'):
            self.skipTest('host has a real crontab on the base PATH')
        out, units, log = self.run_timer(with_cron=False)
        self.assertIn('RC=0', out)
        self.assertIn('ExecStart=/root/.acme.sh/acme.sh --cron --home /root/.acme.sh',
                      units.get('hy2-acme-renew.service', ''))
        self.assertIn('OnCalendar=daily', units.get('hy2-acme-renew.timer', ''))
        self.assertIn('enable --now hy2-acme-renew.timer', log)

    def test_existing_cron_entry_means_no_timer(self):
        out, units, _ = self.run_timer(with_cron=True)
        self.assertIn('RC=0', out)
        self.assertEqual(units, {})

    def test_installer_passes_nocron_without_crontab(self):
        """安装器调用处：缺 crontab 时带 --nocron（摘出那三行在 bash 里求值）。"""
        body = fn('hy2_acme_install_verified')
        start = body.index('    local _cron_flag=()')
        end = body.index('\n', body.index('_cron_flag=(--nocron)', start)) + 1
        script = ('PATH=/nonexistent\nf() {\n' + body[start:end] + 'echo "F=${_cron_flag[*]}"\n}\nf')
        out = subprocess.run([BASH, '-c', script], capture_output=True, text=True, timeout=10).stdout
        self.assertIn('F=--nocron', out)


if __name__ == '__main__':
    unittest.main()
