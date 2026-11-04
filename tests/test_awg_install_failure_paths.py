"""AWG 安装失败路径（2026-11-04 修）。

1. 首个客户端创建失败（cmd_peer_add 内 die=exit 1）不能让已提交的安装整体报错退出。
2. 首次安装回滚：单元文件被删后要 daemon-reload；not-found 状态下 disable 失败不算恢复不完整。
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
SRC = (ROOT / 'awgctl.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def fn(name):
    return re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M).group(0)


def run(script):
    return subprocess.run([BASH, '-c', script], capture_output=True, text=True,
                          encoding='utf-8', timeout=20).stdout


@unittest.skipUnless(BASH, 'requires bash')
class AwgInstallFailurePathTests(unittest.TestCase):
    def test_first_client_failure_does_not_abort_install(self):
        body = re.search(r'    if ! peer_exists "\$client"; then\n.*?\n        fi\n    fi\n', fn('cmd_install'), re.S)
        self.assertIsNotNone(body)
        script = '\n'.join([
            'die() { echo "DIE $*"; exit 1; }', 'log_step() { :; }', 'log_warn() { echo "WARN $*"; }',
            'peer_exists() { return 1; }', 'cmd_peer_add() { die pool full; }',
            'client=c1; ep=1.2.3.4',
            body.group(0), 'echo REACHED'])
        out = run(script)
        self.assertIn('WARN', out)
        self.assertIn('REACHED', out)

    def test_first_install_rollback_reloads_and_completes(self):
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            tx = t / 'tx'
            tx.mkdir()
            (tx / 'service-state').write_text('\nnot-found\n')
            unit = t / 'units' / 'awg.service'
            unit.parent.mkdir()
            unit.write_text('x')
            script = '\n'.join([
                'AWG_TRANSACTION_DIR=%s' % tx, 'AWG_DIR=%s/awg' % t,
                'AWG_META_FILE=%s/m; AWG_CONFIG=%s/c; AWG_PEERS_FILE=%s/p' % (t, t, t),
                'AWG_SERVICE=%s; AWG_SERVICE_NAME=awg' % unit,
                'AWG_VERSION_FILE=%s/v; AWG_GO_BIN=%s/g; AWG_BIN=%s/b; AWG_QUICK_BIN=%s/q' % (t, t, t, t),
                'systemctl() { echo "SYS $*" >> %s/calls; [[ "$1" == disable ]] && return 1; return 0; }' % t,
                fn('awg_transaction_restore'),
                'awg_transaction_restore; echo "RC=$?"'])
            out = run(script)
            calls = (t / 'calls').read_text()
            self.assertIn('RC=0', out)
            self.assertIn('daemon-reload', calls)
            self.assertFalse(unit.exists())
            self.assertFalse(tx.exists())



@unittest.skipUnless(BASH, 'requires bash')
class AwgInstallLineSwitchTests(unittest.TestCase):
    def _run(self, line, s4):
        block = re.search(r'    local _s4\n.*?\n    else\n        log_info "沿用已有混淆参数"\n    fi\n',
                          fn('cmd_install'), re.S).group(0)
        script = '\n'.join([
            'declare -A M=([S1]=20 [S4]=%s)' % s4,
            'meta_get() { echo "${M[$1]:-}"; }', 'meta_set() { M[$1]="$2"; }',
            'log_warn() { :; }', 'log_info() { :; }',
            'gen_obfs_params() { AWG_S1=30; AWG_S2=31; AWG_S3=32; AWG_S4=40; }',
            'line=%s' % line, block, 'echo "S4=${M[S4]}"'])
        return run(script)

    def test_switch_to_line3_regenerates_small_s4(self):
        self.assertIn('S4=40', self._run(3, 5))

    def test_same_params_kept_otherwise(self):
        self.assertIn('S4=5', self._run(2, 5))
        self.assertIn('S4=15', self._run(3, 15))



@unittest.skipUnless(BASH, 'requires bash')
class AwgReinstallPortChangeTests(unittest.TestCase):
    def _run(self, old, new):
        block = re.search(r'    allow_firewall "\$port"\n.*?\n    fi\n', fn('cmd_install'), re.S).group(0)
        with tempfile.TemporaryDirectory() as td:
            script = '\n'.join([
                'log_info() { :; }',
                'command() { if [[ "$1" == -v ]]; then [[ "$2" == ufw ]]; return; fi; builtin command "$@"; }',
                'ufw() { [[ "$1" == status ]] && { echo "Status: active"; return; }; echo "UFW $*" >> %s/calls; }' % td,
                'systemctl() { return 1; }',
                fn('allow_firewall'), fn('revoke_firewall'),
                'old_port=%s; port=%s' % (old, new), block])
            subprocess.run([BASH, '-c', script], timeout=20)
            calls = Path(td) / 'calls'
            return calls.read_text() if calls.exists() else ''

    def test_old_port_revoked_on_change(self):
        out = self._run(51234, 52345)
        self.assertIn('UFW allow 52345/udp', out)
        self.assertIn('UFW delete allow 51234/udp', out)

    def test_same_port_not_revoked(self):
        self.assertNotIn('delete', self._run(51234, 51234))
        self.assertNotIn('delete', self._run('', 51234))


if __name__ == '__main__':
    unittest.main()
