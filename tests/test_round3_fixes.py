"""第三轮排查修复的回归测试（2026-10-15）。

都围绕 Teyir 控制台的整机流量超额停用 / 用户管理联动：
- 恢复时启动失败的服务留在停用记录里，控制台下一轮重试能真的把它拉起来
- 停用期间 Hy2 已停，撤销用户不再因统计接口连不上而 503
- 停用期间改 Hy2 配置不会把 Hy2 重新拉起
- 同时在线 IP 限制把「仍连着但超过 180 秒没重新鉴权」的设备算进去
- awgctl 修改类命令互斥
"""
import ast
import copy
import io
import json
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))


def nested_function(name):
    return next(n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef) and n.name == name)


class SuspensionResumeTest(unittest.TestCase):
    def build(self, data, failing=()):
        calls = []

        def run(cmd, **kwargs):
            calls.append(cmd)
            ok = not (cmd[1] == 'start' and cmd[2] in failing)
            return SimpleNamespace(returncode=0 if ok else 1, stdout='active\n')
        env = {'data': data, 'data_lock': threading.RLock(), 'save_data': mock.Mock(),
               're': re, 'subprocess': SimpleNamespace(run=run), 'time': time,
               'TRAFFIC_SUSPEND_UNITS': ('hysteria-server', 'xray', 'gost', 'amneziawg-server'),
               '_unit_active': lambda unit: True}
        # 生产代码现在用模块级 suspend_state + 服务名正则清洗状态，
        # 提取闭包时要把这两个名字一并带进命名空间。
        for node in TREE.body:
            if isinstance(node, ast.FunctionDef) and node.name == 'suspend_state':
                exec(compile(ast.Module(body=[copy.deepcopy(node)], type_ignores=[]),
                             'suspend-state', 'exec'), env)
            if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == 'TRAFFIC_SUSPEND_UNIT_RE'
                    for t in node.targets):
                exec(compile(ast.Module(body=[copy.deepcopy(node)], type_ignores=[]),
                             'suspend-re', 'exec'), env)
        fn = nested_function('_set_traffic_suspension')
        exec(compile(ast.Module(body=[fn], type_ignores=[]), 'suspend', 'exec'), env)
        return env['_set_traffic_suspension'], calls

    def test_failed_unit_stays_suspended_and_is_retried(self):
        data = {'traffic_suspend': {'suspended': True, 'units': ['hysteria-server', 'xray'], 'since': 1}}
        resume, _ = self.build(data, failing={'xray'})
        state, results = resume(False)
        self.assertEqual(results, {'hysteria-server': True, 'xray': False})
        self.assertEqual(state, {'suspended': True, 'units': ['xray'], 'since': 1})
        # 控制台下一轮再恢复：这次只去启动上次失败的 xray。
        resume, calls = self.build(data)
        state, results = resume(False)
        self.assertEqual(results, {'xray': True})
        self.assertEqual(state, {'suspended': False})
        self.assertIn(['systemctl', 'start', 'xray'], calls)

    def test_clean_resume_clears_state(self):
        data = {'traffic_suspend': {'suspended': True, 'units': ['gost'], 'since': 1}}
        resume, _ = self.build(data)
        self.assertEqual(resume(False)[0], {'suspended': False})

    def test_suspend_records_running_units(self):
        data = {}
        suspend, calls = self.build(data)
        state, results = suspend(True)
        self.assertTrue(state['suspended'])
        self.assertIn('amneziawg-server', state['units'])
        self.assertIn(['systemctl', 'stop', 'amneziawg-server'], calls)


class RevocationWhileSuspendedTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        # 指向一个没人监听的回环端口：模拟 Hy2 被停后统计接口连不上。
        import socket
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
        (self.tmp / 'usage-meter-config.json').write_text(json.dumps(
            {'hysteria': {'url': 'http://127.0.0.1:%d' % port, 'secret': 'x'}}), encoding='utf-8')
        self.snapshot = {'users': {'gone': {'status': 'disabled'}}}

    def test_suspended_and_stopped_hy2_does_not_block_revocation(self):
        with mock.patch.object(portal, '_unit_suspended', lambda unit: unit == 'hysteria-server'), \
                mock.patch.object(portal, '_systemd_state', return_value='inactive'):
            self.assertTrue(portal.enforce_node_access(self.tmp, self.snapshot, ['gone']))

    def test_running_hy2_with_unreachable_stats_still_fails_closed(self):
        with mock.patch.object(portal, '_unit_suspended', lambda unit: unit == 'hysteria-server'), \
                mock.patch.object(portal, '_systemd_state', return_value='active'):
            with self.assertRaises(OSError):
                portal.enforce_node_access(self.tmp, self.snapshot, ['gone'])

    def test_inactive_but_not_suspended_still_fails_closed(self):
        """服务没装 / 单元不存在时 is-active 也是 inactive，不能据此放行（CI 上踩到）。"""
        with mock.patch.object(portal, '_unit_suspended', lambda unit: False), \
                mock.patch.object(portal, '_systemd_state', return_value='inactive'):
            with self.assertRaises(OSError):
                portal.enforce_node_access(self.tmp, self.snapshot, ['gone'])


class RestartWhileSuspendedTest(unittest.TestCase):
    def test_restart_hy2_is_skipped_while_suspended(self):
        with mock.patch.object(portal, '_unit_suspended', lambda unit: unit == 'hysteria-server'), \
                mock.patch.object(portal.subprocess, 'run') as run:
            portal._restart_hy2()
        run.assert_not_called()

    def test_restart_hy2_runs_normally(self):
        with mock.patch.object(portal, '_unit_suspended', lambda unit: False), \
                mock.patch.object(portal.subprocess, 'run') as run:
            portal._restart_hy2()
        self.assertIn(['systemctl', 'start', 'hysteria-server'], [c.args[0] for c in run.call_args_list])


class LiveIpLimitTest(unittest.TestCase):
    def auth(self, addr, live_ips, reality_ips=()):
        auth_if = next(n for n in ast.walk(TREE) if isinstance(n, ast.If)
                       and ast.unparse(n.test) == "self.path == '/auth'")
        fn = ast.parse('def handle(self):\n    pass').body[0]
        fn.body = [auth_if]
        data = {'users': {'u1': {'password': 'pw', 'status': 'active', 'expires_at': 9999999999,
                                 'ip_limit': 1}}}
        env = {'json': json, 'time': time, 'hmac': __import__('hmac'),
               'ipaddress': __import__('ipaddress'), 'data_lock': threading.RLock(),
               'data': data, 'ip_tracker': {}, 'IP_TIMEOUT_SECONDS': 180,
               'user_access_denial': portal.user_access_denial,
               'user_table': lambda data: (data.get('users')
                   if isinstance(data.get('users'), dict) else {}),
               'live_online_ips': lambda uid: set(live_ips),
               'reality_live_ips': lambda uid: set(reality_ips)}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])), 'auth', 'exec'), env)
        body = json.dumps({'auth': 'pw', 'addr': addr}).encode()

        class Handler:
            client_address = ('127.0.0.1', 12345)
            path = '/auth'
            headers = {'Content-Length': str(len(body))}
            rfile = io.BytesIO(body)

            def auth_rate_limited(self):
                return False

            def record_auth_failure(self):
                pass

            def reply_json(self, code, payload):
                return payload
        return env['handle'](Handler())

    def test_second_device_rejected_while_first_still_connected(self):
        """第一台设备早已过了 180 秒的鉴权记忆，但核心报告它仍在线 → 第二台要被拒。"""
        response = self.auth('198.51.100.2:5000', live_ips={'198.51.100.1'})
        self.assertFalse(response['ok'])
        self.assertIn('Concurrent IP limit', response['msg'])

    def test_reality_device_counts_against_hy2_quota(self):
        """两个协议共用一个上限：Reality 已占满时 Hy2 新 IP 也要被拒。"""
        response = self.auth('198.51.100.2:5000', live_ips=(), reality_ips={'198.51.100.1'})
        self.assertFalse(response['ok'])
        self.assertTrue(self.auth('198.51.100.1:5000', live_ips=(), reality_ips={'198.51.100.1'})['ok'])

    def test_same_device_reconnecting_is_allowed(self):
        self.assertTrue(self.auth('198.51.100.1:5001', live_ips={'198.51.100.1'})['ok'])

    def test_ipv6_spelling_differences_count_as_same_device(self):
        response = self.auth('[2001:DB8:0:0::1]:443', live_ips={'2001:db8::1'})
        self.assertTrue(response['ok'])

    def test_no_live_data_keeps_previous_behaviour(self):
        self.assertTrue(self.auth('198.51.100.2:5000', live_ips=())['ok'])


@unittest.skipIf(shutil.which('flock') is None or sys.platform == 'win32', '需要 util-linux flock')
class AwgctlLockTest(unittest.TestCase):
    def test_mutating_command_waits_for_lock(self):
        lock = Path(tempfile.mkdtemp()) / 'awgctl.lock'
        holder = subprocess.Popen(['flock', str(lock), 'sleep', '3'])
        self.addCleanup(holder.wait)
        self.addCleanup(holder.kill)
        time.sleep(0.3)
        script = ('source <(sed \'$d\' %s); AWG_LOCK_FILE=%s; '
                  'die(){ echo "$*"; exit 9; }; '
                  'flock(){ command flock -w 1 "${@:3}"; }; acquire_lock' % (ROOT / 'awgctl.sh', lock))
        result = subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 9, result.stdout + result.stderr)


class AwgctlLockWiringTest(unittest.TestCase):
    def test_all_mutating_commands_take_the_lock(self):
        src = (ROOT / 'awgctl.sh').read_text(encoding='utf-8')
        line = next(ln for ln in src.splitlines() if 'acquire_lock ;;' in ln)
        for cmd in ('install', 'update', 'uninstall', 'resync', 'peer-add', 'peer-del'):
            self.assertIn(cmd, line)


if __name__ == '__main__':
    unittest.main()
