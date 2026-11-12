"""证书自愈单元启用失败时如实报告（2026-11-12 修）。

旧实现两条 `systemctl enable --now` 的失败都被 `|| true` 吞掉，函数最后照报「证书一致性自愈已启用」
并返回 0：菜单「刷新信息页」里专门写的「证书自愈单元未能补齐」提示永远不会出现。
改成失败返回非零后，全新安装（setup_portal 以它收尾）不能因此判整个安装失败 —— 门户已经起来了。
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / 'install.sh').read_text(encoding='utf-8')


def extract(name):
    start = INSTALL.index('\n' + name + '() {') + 1
    depth = 0
    for index in range(INSTALL.index('{', start), len(INSTALL)):
        if INSTALL[index] == '{':
            depth += 1
        elif INSTALL[index] == '}':
            depth -= 1
            if depth == 0:
                return INSTALL[start:index + 1]
    raise AssertionError(name + ' 未闭合')


def relocated(name):
    """把函数里写死的系统目录换到 $TEST_ROOT 下，测试不碰真实的 systemd。"""
    return (extract(name)
            .replace('/usr/local/bin/', '$TEST_ROOT/bin/')
            .replace('/etc/systemd/system/', '$TEST_ROOT/units/'))


STUBS = r'''
HY2_DIR="$TEST_ROOT/hy2"; HY2_CONFIG="$HY2_DIR/config.yaml"; HY2_CERT_DIR="$TEST_ROOT/cert"
HY2_META_FILE="$HY2_DIR/client_meta.json"; PORTAL_LOCAL_PORT=18555; NODE_API_KEY=k
log_info(){ printf 'INFO:%s\n' "$*"; }
log_warn(){ printf 'WARN:%s\n' "$*"; }
log_err(){ printf 'ERR:%s\n' "$*"; }
config_tls_cert(){ :; }
systemctl(){
    printf '%s\n' "$*" >> "$TEST_ROOT/calls"
    [[ "$1" == enable && "$2" == --now && -n "$FAIL_UNIT" && "$3" == "$FAIL_UNIT" ]] && return 1
    return 0
}
'''


@unittest.skipUnless(shutil.which('bash'), '需要 bash')
class CertSelfhealSetupTests(unittest.TestCase):
    def run_bash(self, body, fail_unit='', make_units=True):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for sub in ('bin', 'hy2', 'cert') + (('units',) if make_units else ()):
                (root / sub).mkdir()
            (root / 'hy2' / 'portal.json').write_text('{}', encoding='utf-8')
            run = subprocess.run(
                [shutil.which('bash'), '-c', STUBS + body],
                env=dict(os.environ, TEST_ROOT=str(root), FAIL_UNIT=fail_unit),
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
            calls = (root / 'calls').read_text(encoding='utf-8') if (root / 'calls').exists() else ''
            return run.stdout + run.stderr, calls

    def test_enable_failure_is_reported_instead_of_claimed(self):
        body = relocated('setup_cert_selfheal') + '\nsetup_cert_selfheal; echo "RC=$?"\n'
        out, calls = self.run_bash(body)
        self.assertIn('RC=0', out)
        self.assertIn('证书一致性自愈已启用', out)
        self.assertIn('enable --now hy2-cert-selfheal.timer', calls)
        self.assertIn('enable --now hy2-cert-selfheal.path', calls)
        for unit in ('hy2-cert-selfheal.timer', 'hy2-cert-selfheal.path'):
            with self.subTest(fail=unit):
                out, _ = self.run_bash(body, fail_unit=unit)
                self.assertIn('RC=1', out)
                self.assertNotIn('证书一致性自愈已启用', out)
        with self.subTest(fail='单元目录不可写'):
            out, calls = self.run_bash(body, make_units=False)
            self.assertIn('RC=1', out)
            self.assertNotIn('证书一致性自愈已启用', out)
            self.assertNotIn('enable --now', calls)

    def test_portal_refresh_warns_when_selfheal_cannot_be_enabled(self):
        body = (relocated('setup_cert_selfheal') + '\n' + extract('refresh_portal') + '\n'
                'portal_ensure_py(){ return 0; }; sync_cert_meta(){ return 0; }\n'
                'python3(){ return 0; }; chmod(){ :; }; sleep(){ :; }; journalctl(){ :; }\n'
                'refresh_portal; echo "RC=$?"\n')
        out, _ = self.run_bash(body, fail_unit='hy2-cert-selfheal.path')
        self.assertIn('证书自愈单元未能补齐', out)
        self.assertIn('网页已更新', out)
        self.assertIn('RC=0', out)

    def test_fresh_install_continues_when_selfheal_cannot_be_enabled(self):
        body = (relocated('setup_cert_selfheal') + '\n' + relocated('setup_portal') + '\n'
                'PORTAL_BUNDLE_PLACED=1; PRESERVE_PORTAL=0\n'
                'portal_write_meter_config(){ return 0; }\n'
                'python3(){ return 0; }; chmod(){ :; }; sleep(){ :; }\n'
                'setup_portal; echo "RC=$?"\n')
        out, _ = self.run_bash(body, fail_unit='hy2-cert-selfheal.timer')
        self.assertIn('RC=0', out)
        self.assertIn('证书一致性自愈单元未能启用', out)
        self.assertNotIn('证书一致性自愈已启用', out)
        out, _ = self.run_bash(body)
        self.assertIn('RC=0', out)
        self.assertIn('证书一致性自愈已启用', out)
        self.assertNotIn('未能启用', out)


if __name__ == '__main__':
    unittest.main()
