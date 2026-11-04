"""fix_cert_chain.sh 的修复路径（2026-11-04 修）。

真实运行脚本：临时目录里用 openssl 签一张叶证书和 CA，systemctl 通过 PATH 注入桩。
改配置与回滚那项需要 root（脚本会拒绝非 root 的实际修改），在 SE 上用 sudo 跑。
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
OPENSSL = shutil.which('openssl')


def sh(cmd, cwd):
    subprocess.run([BASH, '-c', cmd], cwd=cwd, check=True, capture_output=True, timeout=60)


@unittest.skipUnless(BASH and OPENSSL and os.name != 'nt', 'requires bash + openssl on POSIX')
class FixCertChainRepairTests(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        d = self.d = Path(self._td.name)
        sh('openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 30 -subj /CN=ca 2>/dev/null', d)
        for name in ('a', 'other'):
            sh('openssl req -newkey rsa:2048 -nodes -keyout %s.key -out %s.csr -subj /CN=%s.example 2>/dev/null && '
               'openssl x509 -req -in %s.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 -out %s.cer 2>/dev/null'
               % (name, name, name, name, name), d)
        (d / 'certs').mkdir()
        shutil.copy(d / 'a.cer', d / 'certs' / 'a.cer')
        shutil.copy(d / 'a.key', d / 'certs' / 'a.cer.key')
        (d / 'bin').mkdir()
        (d / 'bin' / 'systemctl').write_text('#!/bin/sh\necho "$@" >> %s/systemctl.log\n'
                                              '[ "$1" = is-active ] && exit ${ACTIVE_RC:-0}\nexit 0\n' % d)
        (d / 'bin' / 'systemctl').chmod(0o755)
        self.cfg = d / 'config.yaml'
        self.cfg.write_text('listen: :443\ntls:\n  cert: "%s/certs/a.cer"\n  key: "%s/certs/a.cer.key"\n'
                            'masquerade:\n  listenHTTPS: :1\n' % (d, d))

    def tearDown(self):
        self._td.cleanup()

    def run_script(self, *args, active_rc=0):
        env = dict(os.environ, PATH='%s:%s' % (self.d / 'bin', os.environ['PATH']), ACTIVE_RC=str(active_rc))
        return subprocess.run([BASH, str(ROOT / 'fix_cert_chain.sh'), '--config', str(self.cfg), *args],
                              env=env, capture_output=True, text=True, timeout=60)

    def test_config_without_value_does_not_hang(self):
        r = subprocess.run([BASH, str(ROOT / 'fix_cert_chain.sh'), '--config'],
                           capture_output=True, text=True, timeout=10)
        self.assertEqual(r.returncode, 2)

    def test_foreign_fullchain_is_rejected(self):
        (self.d / 'certs' / 'fullchain.cer').write_text(
            (self.d / 'other.cer').read_text() + (self.d / 'ca.crt').read_text())
        r = self.run_script('--dry-run')
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn('未找到可用的 fullchain', r.stdout)

    @unittest.skipUnless(os.name != 'nt' and os.geteuid() == 0, 'requires root to edit and restart')
    def test_only_tls_cert_line_changes_and_failed_restart_rolls_back(self):
        (self.d / 'certs' / 'fullchain.cer').write_text(
            (self.d / 'a.cer').read_text() + (self.d / 'ca.crt').read_text())
        before = self.cfg.read_text()
        r = self.run_script()
        after = self.cfg.read_text()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('cert: "%s/certs/fullchain.cer"' % self.d, after)
        self.assertIn('key: "%s/certs/a.cer.key"' % self.d, after, 'key 行被一起改坏了')
        self.cfg.write_text(before)
        r = self.run_script(active_rc=3)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.cfg.read_text(), before, '启动失败后没有恢复原配置')


if __name__ == '__main__':
    unittest.main()
