#!/usr/bin/env python3
"""核心升级事务的离线行为回归；只运行提取代码和临时目录内的桩。"""

import hashlib
import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_download_integrity import BASH, INSTALL, INSTALL_HELPERS, extract_install_fn


OLD = b'#!/bin/sh\nprintf "Version: old-current\\n"\n'
NEW = b'#!/bin/sh\nprintf "Version: new-tested\\n"\n'
USER_BACKUP = b'user-owned historical backup\n'


@unittest.skipUnless(BASH, 'requires bash')
class CoreTransactionTests(unittest.TestCase):
    def run_case(self, route, *, failure='', suspended=False, conditional=False):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # 下载内容、可执行测试脚本、设备数据各自放入独立目录。
            downloads = root / 'downloads'
            scripts = root / 'scripts'
            data = root / 'data'
            for directory in (downloads, scripts, data):
                directory.mkdir()
            binary = data / 'hysteria'
            binary.write_bytes(OLD)
            binary.chmod(0o755)
            backup = data / 'hysteria.bak'
            backup.write_bytes(USER_BACKUP)
            config = data / 'config.yaml'
            config.write_bytes(b'masquerade:\n  proxy:\n    rewriteHost: true\n    xForwarded: true\n')
            portal = data / 'portal.json'
            portal.write_text('{"traffic_suspend":{"suspended":%s}}\n' %
                              str(suspended).lower(), encoding='utf-8')
            users = data / 'users.json'
            users.write_bytes(b'{"keep":"user data"}\n')
            protected = {p.name: p.read_bytes() for p in (backup, config, portal, users)}
            (downloads / 'payload').write_bytes(NEW)
            (downloads / 'hashes.txt').write_text(
                hashlib.sha256(NEW).hexdigest() + '  hysteria-linux-amd64\n', encoding='utf-8')
            (downloads / 'release.json').write_text('{"tag_name":"app/v9.9.9"}', encoding='utf-8')
            quote = lambda p: shlex.quote(str(p).replace('\\', '/'))
            prelude = f'''
set -eo pipefail
HY2_DIR={quote(data)}
HY2_BIN={quote(binary)}
HY2_CONFIG="$HY2_DIR/config.yaml"
HY2_ARCH=amd64
DOWNLOADS={quote(downloads)}
FAILURE={shlex.quote(failure)}
export TMPDIR={quote(root)}
log_info() {{ echo "INFO: $*"; }}
log_warn() {{ echo "WARN: $*"; }}
log_err() {{ echo "ERR: $*"; }}
log_step() {{ :; }}
check_root() {{ :; }}
check_arch() {{ :; }}
uname() {{ printf 'x86_64\\n'; }}
# 所有外部服务、网络和 JSON 输入均封闭在桩中，不回退到宿主程序。
curl() {{
    local url='' dest=''
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o) dest="$2"; shift 2 ;;
            http*) url="$1"; shift ;;
            *) shift ;;
        esac
    done
    printf '%s\\n' "$url" >> "$HY2_DIR/curl.log"
    [[ "$FAILURE" != download ]] || return 22
    case "$url" in
        *releases/latest) cat "$DOWNLOADS/release.json" ;;
        *hashes.txt) command cp "$DOWNLOADS/hashes.txt" "$dest" ;;
        *hysteria-linux-amd64) command cp "$DOWNLOADS/payload" "$dest" ;;
        *) echo "unexpected curl: $url" >&2; return 99 ;;
    esac
}}
jq() {{
    case "$2" in
        '.tag_name // empty') cat >/dev/null; printf 'app/v9.9.9\\n' ;;
        '.traffic_suspend.suspended // false')
            if command grep -q '"suspended":true' "$3"; then echo true; else echo false; fi ;;
        *) echo "unexpected jq" >&2; return 99 ;;
    esac
}}
flock() {{
    [[ "$*" == '-n 9' || "$*" == '-n 10' ]] || return 99
}}
systemctl() {{
    [[ "$*" == 'restart hysteria-server' ]] || return 99
    # 记录重启时实际存在的二进制，证明回滚重启用的是本次旧版本。
    "$HY2_BIN" version >> "$HY2_DIR/restarts.log"
    case "$FAILURE" in
        restart_always|restore) return 1 ;;
        restart|backup_restart) [[ "$(wc -l < "$HY2_DIR/restarts.log")" -gt 1 ]] ;;
        suspend_on_restart)
            printf '%s\\n' '{{"traffic_suspend":{{"suspended":true}}}}' > "$HY2_DIR/portal.json"
            return 1 ;;
        *) return 0 ;;
    esac
}}
cp() {{
    if [[ "$*" == *"$HY2_BIN"* ]]; then
        [[ "$FAILURE" != backup_restart ]] || return 1
        if [[ "$FAILURE" == backup ]]; then
            # 模拟创建了部分备份后失败，不能把残片用作回滚来源。
            printf 'partial' > "${{@: -1}}"
            return 1
        fi
    fi
    command cp "$@"
}}
mv() {{
    if [[ "${{@: -1}}" == "$HY2_BIN" ]]; then
        case "$FAILURE" in
            replace) [[ "$1 $2" == *rollback* ]] || return 1 ;;
            restore) [[ "$1 $2" != *rollback* && "$1 $2" != *.bak* ]] || return 1 ;;
        esac
    fi
    command mv "$@"
}}
'''
            if route == 'generated':
                source = INSTALL.read_text(encoding='utf-8')
                body = source.split('cat > "$HY2_DIR/do_upgrade.sh" <<\'EOUG\'\n', 1)[1].split('\nEOUG\n', 1)[0]
                # 只重定向生成脚本的常量，执行完整 core 分支；portal 分支不会进入。
                body = body.replace('HY2_DIR="/etc/hysteria"', 'HY2_DIR=' + quote(data))
                body = body.replace('HY2_BIN="/usr/local/bin/hysteria"', 'HY2_BIN=' + quote(binary))
                script = prelude + '\nset -- core\n' + body
            else:
                names = INSTALL_HELPERS + ('install_binary', 'require_installed',
                                           'traffic_suspended', 'refuse_if_suspended',
                                           'restart_service', 'flow_update_core')
                script = prelude + '\n'.join(extract_install_fn(n) for n in names)
                script += ('\nif flow_update_core; then exit 0; else exit $?; fi\n'
                           if conditional else '\nflow_update_core\n')
            path = scripts / 'run.sh'
            path.write_text(script, encoding='utf-8', newline='\n')
            result = subprocess.run([BASH, str(path)], cwd=scripts, env=dict(os.environ),
                                    capture_output=True, text=True, encoding='utf-8',
                                    errors='replace', timeout=30)
            files = {p.name: p.read_bytes() for p in data.iterdir() if p.is_file()}
            return result, files, protected

    def assert_protected(self, files, protected):
        for name, content in protected.items():
            self.assertEqual(files.get(name), content, name + ' must be preserved')

    def assert_clean(self, files):
        self.assertFalse([name for name in files if name != 'hysteria.update.lock' and any(
            token in name for token in ('.rollback.', '.update.', '.new'))], files.keys())

    def test_backup_failure_aborts_before_replace_or_restart(self):
        for route in ('generated', 'cli'):
            with self.subTest(route=route):
                result, files, protected = self.run_case(route, failure='backup')
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(files['hysteria'], OLD)
                self.assertNotIn('restarts.log', files)
                self.assertIn('备份', result.stdout + result.stderr)
                self.assert_protected(files, protected)
                self.assert_clean(files)

    def test_backup_failure_never_consumes_historical_backup(self):
        for route in ('generated', 'cli'):
            with self.subTest(route=route):
                result, files, protected = self.run_case(route, failure='backup_restart')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(files['hysteria'], OLD)
                self.assertNotIn('restarts.log', files)
                self.assert_protected(files, protected)
                self.assert_clean(files)

    def test_suspension_during_failed_restart_blocks_recovery_restart(self):
        for route in ('generated', 'cli'):
            with self.subTest(route=route):
                result, files, protected = self.run_case(route, failure='suspend_on_restart')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(files['hysteria'], OLD)
                self.assertEqual(files['restarts.log'], b'Version: new-tested\n')
                self.assertIn('暂不重启', result.stdout + result.stderr)
                protected.pop('portal.json')  # 模拟控制台在重启期间写入停用状态。
                self.assert_protected(files, protected)
                self.assert_clean(files)

    def test_restart_failure_restores_current_binary_and_returns_failure(self):
        for route in ('generated', 'cli'):
            with self.subTest(route=route):
                result, files, protected = self.run_case(route, failure='restart')
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(files['hysteria'], OLD)
                self.assertEqual(files['restarts.log'], b'Version: new-tested\nVersion: old-current\n')
                self.assertIn('回滚', result.stdout + result.stderr)
                self.assert_protected(files, protected)
                self.assert_clean(files)

    def test_success_preserves_user_backup_and_data(self):
        for route in ('generated', 'cli'):
            with self.subTest(route=route):
                result, files, protected = self.run_case(route)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(files['hysteria'], NEW)
                self.assertEqual(files['restarts.log'], b'Version: new-tested\n')
                self.assert_protected(files, protected)
                self.assert_clean(files)

    def test_suspended_updates_without_restart(self):
        for route in ('generated', 'cli'):
            with self.subTest(route=route):
                result, files, protected = self.run_case(route, suspended=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(files['hysteria'], NEW)
                self.assertNotIn('restarts.log', files)
                self.assert_protected(files, protected)
                self.assert_clean(files)

    def test_recovery_restart_failure_is_reported(self):
        for route in ('generated', 'cli'):
            with self.subTest(route=route):
                result, files, protected = self.run_case(route, failure='restart_always')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(files['hysteria'], OLD)
                self.assertEqual(files['restarts.log'], b'Version: new-tested\nVersion: old-current\n')
                self.assertIn('旧版本重启仍失败', result.stdout + result.stderr)
                self.assert_protected(files, protected)
                self.assert_clean(files)

    def test_restore_failure_keeps_current_snapshot_for_recovery(self):
        for route in ('generated', 'cli'):
            with self.subTest(route=route):
                result, files, protected = self.run_case(route, failure='restore')
                self.assertNotEqual(result.returncode, 0)
                snapshots = [v for k, v in files.items() if '.rollback.' in k]
                self.assertEqual(snapshots, [OLD])
                self.assertEqual(files['restarts.log'], b'Version: new-tested\n')
                self.assertIn('回滚失败', result.stdout + result.stderr)
                self.assert_protected(files, protected)

    def test_replace_failure_is_not_reported_as_success(self):
        for route in ('generated', 'cli'):
            with self.subTest(route=route):
                # 条件调用会关闭函数内部的 errexit，必须显式传播 mv/restart 失败。
                result, files, protected = self.run_case(route, failure='replace', conditional=True)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(files['hysteria'], OLD)
                self.assertNotIn('restarts.log', files)
                self.assert_protected(files, protected)
                self.assert_clean(files)

    def test_cli_conditional_call_does_not_mask_restart_failure(self):
        result, files, protected = self.run_case('cli', failure='restart', conditional=True)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(files['hysteria'], OLD)
        self.assertEqual(files['restarts.log'], b'Version: new-tested\nVersion: old-current\n')
        self.assert_protected(files, protected)
        self.assert_clean(files)

    def test_download_failure_keeps_current_binary_and_data(self):
        for route in ('generated', 'cli'):
            with self.subTest(route=route):
                result, files, protected = self.run_case(route, failure='download')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(files['hysteria'], OLD)
                self.assertNotIn('restarts.log', files)
                self.assert_protected(files, protected)
                self.assert_clean(files)


if __name__ == '__main__':
    unittest.main()
