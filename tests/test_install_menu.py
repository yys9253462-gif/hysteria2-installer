"""install.sh 交互菜单的回归测试（2026-10-15）。

用真实的 menu() 跑：载入 install.sh 里「命令行直通参数」之前的全部定义，
把路径指到临时目录、systemctl / journalctl 换成记录调用的桩，再用管道喂输入。

覆盖的 BUG：
- 任何一步失败都会让 set -e 把整个脚本带走（没装时选 3、服务起不来……）
- 查看日志时按 Ctrl+C 会退出整个脚本
- 没装时「更新核心」会先装二进制再报错
- 节点被 Teyir 流量超额停用时，9 / 11 会把服务手动拉起来
- 输入带空格被判无效
以及「重新修改配置」沿用现有门户（portal.py adopt）。
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def extract_shell_function(name):
    source = (ROOT / 'install.sh').read_text(encoding='utf-8')
    start = source.index(name + '() {')
    brace = source.index('{', start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == '{':
            depth += 1
        elif source[index] == '}':
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise AssertionError('unbalanced shell function: ' + name)
import portal  # noqa: E402

INSTALL = (ROOT / 'install.sh').read_text(encoding='utf-8')
DEFINITIONS = INSTALL[:INSTALL.index('# 命令行直通参数')]


@unittest.skipIf(os.name != 'posix' or shutil.which('bash') is None, '需要 POSIX bash')
class MenuTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bindir = self.tmp / 'bin'
        self.bindir.mkdir()
        self.calls = self.tmp / 'calls.log'
        self.calls.touch()
        stub = '#!/bin/sh\necho "$(basename "$0") $*" >> %s\n' % self.calls
        for name in ('systemctl', 'clear'):
            (self.bindir / name).write_text(stub)
            (self.bindir / name).chmod(0o755)
        # journalctl 桩：模拟用户在看日志时按下 Ctrl+C（整个前台进程组都收到 SIGINT）。
        (self.bindir / 'journalctl').write_text(stub + 'kill -INT 0\nsleep 2\n')
        (self.bindir / 'journalctl').chmod(0o755)
        self.hy2_dir = self.tmp / 'hysteria'
        self.hy2_dir.mkdir()
        (self.tmp / 'defs.sh').write_text(DEFINITIONS, encoding='utf-8')

    def install_fake_node(self, suspended=False):
        binary = self.tmp / 'hysteria-bin'
        binary.write_text('#!/bin/sh\necho "Version: v2.13.0"\n')
        binary.chmod(0o755)
        (self.hy2_dir / 'config.yaml').write_text('auth:\n  type: http\n  http:\n    url: http://127.0.0.1:1/auth\n')
        (self.hy2_dir / 'portal.json').write_text(json.dumps(
            {'traffic_suspend': {'suspended': True, 'units': ['hysteria-server']}} if suspended else {}))

    def run_menu(self, keys):
        script = (
            'source %s\n'
            'HY2_DIR=%s; HY2_CONFIG=$HY2_DIR/config.yaml; HY2_META_FILE=$HY2_DIR/client_meta.json\n'
            'HY2_BIN=%s; AWG_CONFIG=%s\n'
            'check_root() { :; }; check_arch() { :; }\n'
            'menu\n' % (self.tmp / 'defs.sh', self.hy2_dir, self.tmp / 'hysteria-bin', self.tmp / 'no-awg.conf'))
        env = dict(os.environ, PATH='%s:%s' % (self.bindir, os.environ['PATH']), TERM='dumb')
        # 独立会话：journalctl 桩的 kill -INT 0 只打到菜单这一组进程，和终端里按 Ctrl+C 一样，
        # 不会波及跑测试的 Python 进程。
        result = subprocess.run(['bash', '-c', script], input=keys, capture_output=True,
                                text=True, timeout=30, env=env, start_new_session=True)
        return result, self.calls.read_text()

    def assert_back_in_menu(self, result):
        # read -p 只在 stdin 是终端时才打印提示，管道输入下看不到「按回车返回」；
        # 菜单标题被画了第二次，就说明确实回到了菜单。
        self.assertGreaterEqual(result.stdout.count('全功能生产级管理脚本'), 2, result.stdout + result.stderr)

    def test_failed_action_returns_to_menu_instead_of_exiting(self):
        result, _ = self.run_menu('3\n\n0\n')        # 没装时查看信息页 → 失败
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('尚未生成信息页', result.stdout + result.stderr)
        self.assert_back_in_menu(result)

    def test_service_actions_on_uninstalled_node_explain_and_return(self):
        result, calls = self.run_menu('9\n\n11\n\n0\n')
        self.assertEqual(result.returncode, 0)
        self.assertIn('尚未安装', result.stdout + result.stderr)
        self.assertNotIn('systemctl start', calls)

    def test_update_core_on_uninstalled_node_does_not_download(self):
        result, _ = self.run_menu('2\n\n0\n')
        self.assertEqual(result.returncode, 0)
        self.assertIn('尚未安装', result.stdout + result.stderr)

    def test_ctrl_c_in_logs_returns_to_menu(self):
        self.install_fake_node()
        result, calls = self.run_menu('12\n\n0\n')
        self.assertIn('journalctl', calls)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_back_in_menu(result)

    def test_suspended_node_is_not_restarted_from_menu(self):
        self.install_fake_node(suspended=True)
        result, calls = self.run_menu('9\n\n11\n\n0\n')
        self.assertEqual(result.returncode, 0)
        self.assertIn('流量超额', result.stdout + result.stderr)
        self.assertNotIn('systemctl start hysteria-server', calls)
        self.assertNotIn('systemctl restart hysteria-server', calls)

    def test_running_node_can_be_restarted(self):
        self.install_fake_node()
        result, calls = self.run_menu('11\n\n0\n')
        self.assertIn('systemctl restart hysteria-server', calls)

    def test_input_with_spaces_is_accepted(self):
        self.install_fake_node()
        result, calls = self.run_menu('  11  \n\n0\n')
        self.assertIn('systemctl restart hysteria-server', calls)
        self.assertNotIn('无效选项', result.stdout + result.stderr)

    def test_status_shows_portal_mode_and_suspension(self):
        self.install_fake_node(suspended=True)
        result, _ = self.run_menu('0\n')
        self.assertIn('门户状态', result.stdout)
        self.assertIn('Agent 模式', result.stdout)
        self.assertIn('已因流量超额被 Teyir 停用', result.stdout)

    def test_teyir_access_info(self):
        self.install_fake_node()
        (self.hy2_dir / 'portal-access.json').write_text(json.dumps(
            {'url': 'https://n.example.com:12345/tok/', 'username': 'u1', 'password': 'p1', 'api_key': 'k1'}))
        result, _ = self.run_menu('16\n\n0\n')
        for value in ('https://n.example.com:12345/tok/', 'u1', 'p1', 'k1'):
            self.assertIn(value, result.stdout)

    def test_eof_exits_cleanly(self):
        result, _ = self.run_menu('')
        self.assertEqual(result.returncode, 0)


class MenuSourceTest(unittest.TestCase):
    def test_reconfigure_defaults_to_current_mode_and_key(self):
        # 商城版固定启用 Agent；重装 / 改配置时必须沿用旧 Key，否则控制台凭据失效。
        # 注释里会提到「已移除」，要断言的是菜单选项本身不再出现
        self.assertNotIn('单机私密模式 (默认', INSTALL)
        self.assertNotIn('请输入选项 [1-2, 默认 ${_cur_mode}]', INSTALL)
        self.assertIn('NODE_MODE="agent"', INSTALL)
        self.assertIn('NODE_API_KEY=${NODE_API_KEY:-$_cur_api_key}', INSTALL)

    def test_setup_portal_adopts_when_preserving(self):
        self.assertIn('portal.py" adopt "$HY2_META_FILE" "$PORTAL_LOCAL_PORT" "$NODE_API_KEY"', INSTALL)

    def test_menu_numbers_match_readme(self):
        readme = (ROOT / 'README.md').read_text(encoding='utf-8')
        for n in range(17):
            self.assertIn('  %d. ' % n, readme)
        self.assertIn('请输入选项 [0-16]', INSTALL)


class UninstallSingboxOwnershipTests(unittest.TestCase):
    def test_uninstall_keeps_singbox_unless_managed_unit_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            units = root / 'etc/systemd/system'
            units.mkdir(parents=True)
            binary = root / 'usr/local/bin/sing-box'
            binary.parent.mkdir(parents=True)
            binary.write_text('unrelated-singbox', encoding='utf-8')
            script = root / 'uninstall.sh'
            script.write_text('''#!/usr/bin/env bash
set -e
UNIT_DIR="$TEST_ROOT/etc/systemd/system"
BINARY="$TEST_ROOT/usr/local/bin/sing-box"
managed_singbox=0
for sb_unit in hy2-anytls hy2-tuic; do
    if [[ -f "$UNIT_DIR/${sb_unit}.service" ]]; then
        managed_singbox=1
        rm -f "$UNIT_DIR/${sb_unit}.service"
    fi
done
if [[ "$managed_singbox" == 1 ]]; then rm -f "$BINARY"; fi
''', encoding='utf-8')
            env = dict(os.environ, TEST_ROOT=str(root))
            bash = shutil.which('bash')
            if not bash:
                self.skipTest('requires Bash')
            subprocess.run([bash, str(script)], check=True, env=env)
            self.assertTrue(binary.exists())
            (units / 'hy2-tuic.service').write_text('managed', encoding='utf-8')
            subprocess.run([bash, str(script)], check=True, env=env)
            self.assertFalse(binary.exists())


class DirectCommandArgumentTests(unittest.TestCase):
    def test_simple_commands_reject_extra_arguments(self):
        source = (ROOT / 'install.sh').read_text(encoding='utf-8')
        start = source.index('if [[ $# -gt 0 ]]; then', source.index('# 命令行直通参数'))
        end = source.index('        install)', start)
        guard = source[start:end]
        for command in ('install', 'update', 'info', 'refresh-page', 'status',
                        'restart', 'uninstall', 'awg-menu', 'awg-status',
                        'awg-update', 'awg-uninstall'):
            self.assertIn(command, guard)
        self.assertIn('if [[ $# -ne 1 ]]', guard)


class AwgBuildWorkflowInputTests(unittest.TestCase):
    def test_go_tags_are_read_from_env_and_validated_before_checkout(self):
        workflow = (ROOT / '.github/workflows/build-awg.yml').read_text(encoding='utf-8')
        start = workflow.index('      - name: 解析目标 tag 与 GOARCH')
        end = workflow.index('      - name: 检出 amneziawg-go', start)
        step = workflow[start:end]
        self.assertIn('AWG_GO_TAG_2: ${{ github.event.inputs.go_tag_2', step)
        self.assertIn('AWG_GO_TAG_3: ${{ github.event.inputs.go_tag_3', step)
        self.assertIn('TAG="$AWG_GO_TAG_2"', step)
        self.assertIn('TAG="$AWG_GO_TAG_3"', step)
        self.assertIn('[[ ! "$TAG" =~ ^v[0-9A-Za-z][0-9A-Za-z._+-]*$ ]]', step)
        self.assertNotIn('${{ env.AWG_GO_TAG_', step[step.index('        run: |'):])

    @unittest.skipUnless(shutil.which('bash'), 'requires Bash')
    def test_tag_validation_accepts_release_tag_and_rejects_shell_syntax(self):
        validator = '[[ "$TAG" =~ ^v[0-9A-Za-z][0-9A-Za-z._+-]*$ ]]'
        for tag, expected in (('v0.2.19', 0), ('v3.1.20260828', 0),
                              ('v1.2.3; touch /tmp/workflow-injected', 1),
                              ('$(touch /tmp/workflow-injected)', 1)):
            with self.subTest(tag=tag):
                result = subprocess.run([shutil.which('bash'), '-c', validator],
                    env=dict(os.environ, TAG=tag), capture_output=True, check=False)
                self.assertEqual(result.returncode, expected)


class ReconfigureSnapshotRetentionTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('bash'), 'requires Bash')
    def test_retains_five_old_snapshots_plus_current_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / 'client_meta.json'
            base.write_text('live')
            for i in range(8):
                path = Path(str(base) + '.bak-20250101-00000%d' % i)
                path.write_text('snapshot-%d' % i)
            script = (
                'set -eo pipefail\n'
                'HY2_DIR="."\n'
                'HY2_META_FILE="client_meta.json"\n'
                'HY2_CONFIG="missing.yaml"\n'
                'HY2_CERT_DIR="cert"\n'
                'log_info(){ :; }; log_warn(){ :; }; log_err(){ :; }\n'
                + extract_shell_function('backup_state_before_reconfigure') + '\n'
                'backup_state_before_reconfigure\n')
            result = subprocess.run([shutil.which('bash'), '-c', script], cwd=root,
                                    capture_output=True, text=True, encoding='utf-8', errors='replace')
            self.assertEqual(result.returncode, 0, result.stderr)
            retained = sorted(root.glob('client_meta.json.bak-*'))
            self.assertEqual(len(retained), 5)
            names = {path.name for path in retained}
            self.assertFalse(any('00000%d' % i in name for i in range(4) for name in names))
            self.assertTrue(all(any('00000%d' % i in name for name in names) for i in range(4, 8)))


class HoppingRuleOwnershipTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('bash'), 'requires Bash')
    def test_cleanup_deletes_only_marked_hysteria_rules_and_persists_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            calls = root / 'iptables.calls'
            script = (
                'set -eo pipefail\n'
                'CALLS="$PWD/iptables.calls"\n'
                'HY2_META_FILE="$PWD/missing-meta.json"\n'
                'iptables() {\n'
                '  if [[ "$*" == "-t nat -S PREROUTING" ]]; then\n'
                '    printf "%s\\n" "-A PREROUTING -p udp --dport 20000:40000 -m comment --comment hy2-installer -j REDIRECT --to-ports 14617" "-A PREROUTING -p udp --dport 30000:31000 -j REDIRECT --to-ports 9000"; return 0;\n'
                '  fi\n'
                '  printf "%s\\n" "$*" >> "$CALLS"\n'
                '}\n'
                'ip6tables() { :; }\n'
                'command() { if [[ "$1" == -v && "$2" == ip6tables ]]; then return 0; fi; builtin command "$@"; }\n'
                'systemctl() { :; }\n'
                'rm() { :; }\n'
                'netfilter-persistent() { printf "%s\\n" "$*" >> "$CALLS"; }\n'
                + extract_shell_function('_clear_hop_chain') + '\n'
                + extract_shell_function('persist_hopping_rules') + '\n'
                + extract_shell_function('clear_all_hopping_rules') + '\n'
                'clear_all_hopping_rules\n')
            result = subprocess.run([shutil.which('bash'), '-c', script], cwd=root,
                                    capture_output=True, text=True, encoding='utf-8', errors='replace')
            self.assertEqual(result.returncode, 0, result.stderr)
            calls_text = calls.read_text(encoding='utf-8')
            self.assertIn('--comment hy2-installer', calls_text)
            self.assertNotIn('--to-ports 9000', calls_text)
            self.assertIn('save', calls_text)


class UninstallOwnershipTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('bash'), 'requires Bash')
    def test_uninstall_preserves_unmanaged_xray_and_removes_its_sysctl(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hy2 = root / 'etc/hysteria'
            hy2.mkdir(parents=True)
            units = root / 'etc/systemd/system'
            units.mkdir(parents=True)
            sysctl_dir = root / 'etc/sysctl.d'
            sysctl_dir.mkdir(parents=True)
            xray_unit = units / 'xray.service'
            xray_unit.write_text('[Service]\nExecStart=/usr/local/bin/xray run -c /etc/xray/config.json\n')
            sysctl = sysctl_dir / '99-hysteria2.conf'
            sysctl.write_text('net.core.rmem_max = 1\n')
            binary = root / 'usr/local/bin/xray'
            binary.parent.mkdir(parents=True)
            binary.write_text('unmanaged-xray')
            marker = 'systemctl disable --now xray 2>/dev/null || true'
            start = INSTALL.index('        if [[ -f /etc/systemd/system/xray.service ]]',
                                  INSTALL.index('uninstall_all() {'))
            fragment = INSTALL[start:]
            self.assertIn(marker, fragment)
            fragment = fragment[:fragment.index('\n        # AnyTLS / TUIC')]
            fragment += '\nrm -f /etc/sysctl.d/99-hysteria2.conf\n'
            fragment = fragment.replace('/etc/systemd/system', str(units).replace('\\', '/'))
            fragment = fragment.replace('/usr/local/bin/xray', str(binary).replace('\\', '/'))
            fragment = fragment.replace('/etc/sysctl.d/99-hysteria2.conf',
                                        str(sysctl).replace('\\', '/'))
            script = root / 'uninstall.sh'
            script.write_text('''#!/usr/bin/env bash
HY2_DIR="$TEST_ROOT/etc/hysteria"
systemctl() { :; }
''' + fragment, encoding='utf-8')
            bash = shutil.which('bash')
            subprocess.run([bash, str(script)], check=True, env=dict(os.environ, TEST_ROOT=str(root)))
            self.assertTrue(xray_unit.exists())
            self.assertTrue(binary.exists())
            self.assertFalse(sysctl.exists())
            xray_unit.write_text(
                '[Service]\nExecStart=%s run -c /etc/hysteria/xray.json\n' % binary.as_posix())
            (hy2 / 'xray.json').write_text('{}')
            subprocess.run([bash, str(script)], check=True, env=dict(os.environ, TEST_ROOT=str(root)))
            self.assertFalse(xray_unit.exists())
            self.assertFalse(binary.exists())


class UninstallWireproxyOwnershipTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('bash'), 'requires Bash')
    def test_uninstall_preserves_unowned_wireproxy_service(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hy2 = root / 'etc/hysteria'
            hy2.mkdir(parents=True)
            units = root / 'etc/systemd/system'
            units.mkdir(parents=True)
            wireguard = root / 'etc/wireguard'
            wireguard.mkdir(parents=True)
            binary = root / 'usr/local/bin/wireproxy'
            binary.parent.mkdir(parents=True)
            binary.write_text('unmanaged wireproxy binary')
            unit = units / 'wireproxy.service'
            unit.write_text('[Service]\nExecStart=/usr/local/bin/wireproxy -c /etc/other/proxy.conf\n')
            fakebin = root / 'bin'
            fakebin.mkdir()
            (fakebin / 'systemctl').write_text('#!/bin/sh\nexit 0\n')
            (fakebin / 'systemctl').chmod(0o755)
            start = INSTALL.index('        # 只有 systemd unit 确认为本安装器生成')
            end = INSTALL.index('        # 证书自愈定时/事件单元', start)
            block = INSTALL[start:end]
            block = block.replace('/etc/hysteria', hy2.as_posix())
            block = block.replace('/etc/systemd/system', units.as_posix())
            block = block.replace('/etc/wireguard', wireguard.as_posix())
            block = block.replace('/usr/local/bin/wireproxy', binary.as_posix())
            block = block.replace('/usr/local/bin/wgcf', str(root / 'usr/local/bin/wgcf'))
            script = root / 'wireproxy-cleanup.sh'
            script.write_text('''#!/usr/bin/env bash
HY2_DIR="$TEST_ROOT/etc/hysteria"
systemctl() { :; }
''' + block, encoding='utf-8')
            subprocess.run([shutil.which('bash'), str(script)], check=True,
                           env=dict(os.environ, TEST_ROOT=str(root)))
            self.assertTrue(unit.exists())
            self.assertTrue(binary.exists())
            unit.write_text('[Service]\nExecStart=%s -c %s/wp.conf\n' %
                            (binary.as_posix(), wireguard.as_posix()))
            marker = hy2 / '.hy2-warp-owned'
            marker.write_text('owned')
            subprocess.run([shutil.which('bash'), str(script)], check=True,
                           env=dict(os.environ, TEST_ROOT=str(root)))
            self.assertFalse(unit.exists())
            self.assertFalse(binary.exists())


class UninstallSysctlCleanupTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('bash'), 'requires Bash')
    def _run_cleanup(self, root, sysctl):
        hy2 = root / 'etc/hysteria'
        hy2.mkdir(parents=True, exist_ok=True)
        (hy2 / '.hy2-installer-owned').write_text('owned')
        sysctl_dir = root / 'etc/sysctl.d'
        sysctl_dir.mkdir(parents=True, exist_ok=True)
        fragment_start = INSTALL.index('        # 仅删除首次安装时存在 marker 的安装器资产',
                                       INSTALL.index('uninstall_all() {'))
        fragment = INSTALL[fragment_start:INSTALL.index('\n        clear_all_hopping_rules', fragment_start)]
        fragment = fragment.replace('/etc/hysteria', 'etc/hysteria')
        fragment = fragment.replace('/etc/sysctl.d/99-hysteria2.conf', 'etc/sysctl.d/99-hysteria2.conf')
        fragment = fragment.replace('/usr/local/bin/gost', 'usr/local/bin/gost')
        fragment = fragment.replace('(由 hysteria2-installer 自动生成)', '(owned marker)')
        script = root / 'cleanup.sh'
        script.write_text('''#!/usr/bin/env bash
HY2_DIR="etc/hysteria"
clear_all_hopping_rules() { :; }
cleanup() {
''' + fragment + '\n}\ncleanup\n', encoding='utf-8')
        subprocess.run([shutil.which('bash'), str(script)], cwd=root, check=True,
                       env=dict(os.environ, TEST_ROOT=str(root)))

    def test_owned_sysctl_tuning_is_removed_on_uninstall(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sysctl = root / 'etc/sysctl.d/99-hysteria2.conf'
            sysctl.parent.mkdir(parents=True)
            sysctl.write_text('# Hysteria 2 tuning (owned marker)\n')
            self._run_cleanup(root, sysctl)
            self.assertFalse(sysctl.exists())

    def test_marker_alone_does_not_delete_replaced_sysctl_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sysctl = root / 'etc/sysctl.d/99-hysteria2.conf'
            sysctl.parent.mkdir(parents=True)
            content = '# administrator-owned settings\nnet.core.rmem_max = 1234\n'
            sysctl.write_text(content)
            self._run_cleanup(root, sysctl)
            self.assertEqual(sysctl.read_text(), content)


class AdoptTest(unittest.TestCase):
    """「重新修改配置」沿用现有门户：Teyir 保存的凭据与控制台开的用户都不能变。"""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.meta = self.root / 'client_meta.json'
        self.meta.write_text(json.dumps({
            'public_ip': '203.0.113.10', 'server_name': 'old.example.com', 'listen_port': 443,
            'auth_password': 'old-master', 'obfs_password': 'o', 'is_insecure': True,
            'hop_port_range': '20000-40000', 'subscription_port': 12345}), encoding='utf-8')
        portal.prepare(self.meta, 18080, 'teyir-key')
        data = json.loads((self.root / 'portal.json').read_text(encoding='utf-8'))
        data['users']['teyir_sub_1'] = {'password': 'sub-pw', 'status': 'active', 'expires_at': 9999999999}
        data['proxy_services'] = [{'id': 'proxy_1', 'type': 'socks5', 'port': 30001}]
        data['traffic_suspend'] = {'suspended': False}
        (self.root / 'portal.json').write_text(json.dumps(data), encoding='utf-8')
        self.before = data
        self.access_before = json.loads((self.root / 'portal-access.json').read_text(encoding='utf-8'))

    def reconfigure(self, **meta_changes):
        m = json.loads(self.meta.read_text(encoding='utf-8'))
        m.update(meta_changes)
        self.meta.write_text(json.dumps(m), encoding='utf-8')

    def test_credentials_users_and_services_survive(self):
        self.reconfigure(auth_password='new-master', listen_port=8443)
        portal.adopt(self.meta, 19090, '')
        after = json.loads((self.root / 'portal.json').read_text(encoding='utf-8'))
        access = json.loads((self.root / 'portal-access.json').read_text(encoding='utf-8'))
        for key in ('token', 'auth_hash', 'session_secret', 'api_key'):
            self.assertEqual(after[key], self.before[key], key)
        for key in ('username', 'password', 'api_key', 'url'):
            self.assertEqual(access[key], self.access_before[key], key)
        self.assertEqual(after['users']['teyir_sub_1']['password'], 'sub-pw')
        self.assertEqual(after['proxy_services'], self.before['proxy_services'])
        self.assertEqual(after['port'], 19090)
        self.assertEqual(after['users'][portal.MASTER_USER_ID]['password'], 'new-master')

    def test_new_api_key_is_applied_when_given(self):
        portal.adopt(self.meta, 18080, 'brand-new-key')
        after = json.loads((self.root / 'portal.json').read_text(encoding='utf-8'))
        access = json.loads((self.root / 'portal-access.json').read_text(encoding='utf-8'))
        self.assertEqual(after['api_key'], 'brand-new-key')
        self.assertEqual(access['api_key'], 'brand-new-key')

    def test_access_url_follows_domain_change_but_keeps_token(self):
        self.reconfigure(is_insecure=False, server_name='new.example.com')
        portal.adopt(self.meta, 18080, '')
        access = json.loads((self.root / 'portal-access.json').read_text(encoding='utf-8'))
        self.assertEqual(access['url'], 'https://new.example.com:12345/%s/' % self.before['token'])


if __name__ == '__main__':
    unittest.main()
