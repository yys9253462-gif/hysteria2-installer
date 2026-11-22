"""回归测试：撤权入参过滤、整机流量数字上限、服务状态安全调用、计量落盘防回拨、GOST端口限长与去重、远端SHA缓存防回拨与校验、自检脚本落盘fsync与清理兜底。"""

import ast
import copy
import io
import json
import os
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
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import portal  # noqa: E402

SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
TREE = ast.parse(SRC)


def _load_nested(name: str, env: dict, nonlocal_to_global: bool = False):
    for node in ast.walk(TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            fn = copy.deepcopy(node)
            if nonlocal_to_global:
                fn.body = [
                    ast.Global(names=s.names) if isinstance(s, ast.Nonlocal) else s
                    for s in fn.body
                ]
            mod = ast.Module(body=[fn], type_ignores=[])
            ast.fix_missing_locations(mod)
            exec(compile(mod, f'<portal:{name}>', 'exec'), env)
            return env[name]
    raise AssertionError(f'portal.py 中未找到函数 {name}')


class TestPortalAccessGostTrafficCacheAndSelfcheckGuards(unittest.TestCase):
    def test_apply_access_filters_dirty_force_ids_and_scalar_string(self):
        """apply_access 遇到非字符串/控制字符/标量字符串 force_ids 时必须过滤，不得触发 TypeError 或拆字符。"""
        seen_pending = []
        data = {'_pending_revocations': ['u1']}

        def fake_enforce(_parent, _snap, pending, _lock, **_kw):
            seen_pending.append(set(pending))
            raise RuntimeError('simulate-fail')

        env = {
            'access_apply_lock': threading.Lock(),
            'data_lock': threading.RLock(),
            'data': data,
            'pending_revocations': portal.pending_revocations,
            'copy': copy,
            'blocked_user_ids': lambda: frozenset(),
            'acquire_core_operation_lock': lambda: 99,
            'enforce_node_access': fake_enforce,
            'portal_path': Path('/tmp/portal.json'),
            'reality_apply_lock': threading.Lock(),
            'save_data': lambda: None,
            '_log_ignored': lambda *a, **kw: None,
            'time': time,
            'sys': sys,
            'os': SimpleNamespace(close=lambda _fd: None),
            'AtomicWriteDurabilityError': portal.AtomicWriteDurabilityError,
            'USER_ID_RE': portal.USER_ID_RE,
            'last_enforced_blocked': None,
            'last_enforce_error': ('', 0.0),
        }
        fn = _load_nested('apply_access', env, nonlocal_to_global=True)

        # 含 None、整型、换行脏值与合法用户，不应在 sorted(...) 时抛 TypeError
        self.assertFalse(fn(force_ids=[None, 123, '', 'bad\nid', 'alice'], core_lock_fd=1))
        self.assertEqual(seen_pending[-1], {'u1', 'alice'})
        self.assertEqual(data['_pending_revocations'], ['alice', 'u1'])

        # 误传标量字符串不得拆成单字符 'b','o','b'
        self.assertFalse(fn(force_ids='bob', core_lock_fd=1))
        self.assertEqual(seen_pending[-1], {'u1', 'alice'})

    def test_node_traffic_counters_skips_overlong_or_non_ascii_digits(self):
        """node_traffic_counters 遇到超长数字列或全角数字时应跳过异常行而不崩溃或误累加。"""
        huge = '9' * 5000
        fullwidth = '１２３'
        fake_dev = (
            'Inter-|   Receive |  Transmit\n'
            f'  eth0: {huge} 0 0 0 0 0 0 0 100 0 0 0 0 0 0 0\n'
            f'  eth1: {fullwidth} 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0\n'
            '  eth2: 1024 0 0 0 0 0 0 0 2048 0 0 0 0 0 0 0\n'
        )

        def fake_open(path, *a, **kw):
            if str(path) == '/proc/net/dev':
                return io.StringIO(fake_dev)
            raise OSError('unexpected open')

        class _FakePath:
            def __init__(self, p):
                self._p = str(p)

            def read_text(self, *a, **kw):
                return 'boot-123\n'

        env = {
            'node_default_ifaces': lambda: ['eth0', 'eth1', 'eth2'],
            'open': fake_open,
            'Path': _FakePath,
        }
        fn = _load_nested('node_traffic_counters', env)
        res = fn()
        self.assertEqual(res['rx_bytes'], 1024)
        self.assertEqual(res['tx_bytes'], 2048)
        self.assertEqual(res['interfaces'], ['eth2'])

    def test_unit_active_rejects_invalid_unit_and_passes_utf8_replace(self):
        """_unit_active 拒绝非串/空白/控制字符/横杠开头参数，且 _unit_active 与 gost_status 传 encoding/errors。"""
        calls = []

        def fake_run(cmd, **kw):
            calls.append((cmd, kw))
            return SimpleNamespace(stdout='active\n', returncode=0)

        env = {'subprocess': SimpleNamespace(run=fake_run)}
        unit_active = _load_nested('_unit_active', env)
        gost_status = _load_nested('gost_status', env)

        for bad in (None, 123, '', '   ', '-H', '--system', 'xray\nfoo', 'xray foo'):
            self.assertFalse(unit_active(bad), f'应拒绝非法 unit: {bad!r}')
        self.assertEqual(calls, [])

        self.assertTrue(unit_active('xray'))
        self.assertTrue(gost_status())
        self.assertEqual(len(calls), 2)
        for _cmd, kw in calls:
            self.assertEqual(kw.get('encoding'), 'utf-8')
            self.assertEqual(kw.get('errors'), 'replace')

    def test_save_meter_data_handles_clock_rollback(self):
        """save_meter_data 在单调钟回拨时不得被负时间差永久阻断。"""
        saves = []
        clock = [200.0]
        env = {
            'time': SimpleNamespace(monotonic=lambda: clock[0]),
            '_meter_last_save': [500.0],
            'METER_SAVE_INTERVAL': 60,
            'save_data': lambda: saves.append(clock[0]),
        }
        fn = _load_nested('save_meter_data', env)
        fn()
        self.assertEqual(len(saves), 1)
        self.assertEqual(env['_meter_last_save'][0], 200.0)

    def test_write_gost_config_rejects_huge_port_string_and_dedups_ports(self):
        """write_gost_config 遇到 5000 位超长数字端口不崩，且对重复端口只写一条 service。"""
        written = {}
        gost_written_ports = []
        data = {
            'proxy_services': [
                {'type': 'socks5', 'port': '9' * 5000, 'username': 'u0', 'password': 'p0'},
                {'type': 'socks5', 'port': '1080', 'username': 'u1', 'password': 'p1'},
                {'type': 'http', 'port': 1080, 'username': 'u2', 'password': 'p2'},
                {'type': 'http', 'port': '2080', 'username': 'u3', 'password': 'p3'},
            ]
        }

        def fake_atomic_write(path, payload):
            written['path'] = path
            written['cfg'] = json.loads(payload.decode('utf-8'))

        with tempfile.TemporaryDirectory() as td:
            env = {
                'portal_path': Path(td) / 'portal.json',
                'data_lock': threading.RLock(),
                'data': data,
                'proxy_services': portal.proxy_services,
                'GOST_PRIVATE_BYPASS': portal.GOST_PRIVATE_BYPASS,
                'PRIVATE_REJECT_RULES': portal.PRIVATE_REJECT_RULES,
                'gost_written_ports': gost_written_ports,
                'gost_tls_paths': lambda _p: ('/c.pem', '/k.pem'),
                'atomic_write_private': fake_atomic_write,
                'json': json,
                'sys': sys,
            }
            fn = _load_nested('write_gost_config', env)
            fn()

        svcs = written['cfg']['services']
        self.assertEqual([s['addr'] for s in svcs], [':1080', ':2080'])
        self.assertEqual(gost_written_ports, [1080, 2080])

    def test_remote_root_shas_handles_clock_rollback_and_validates_sha_hex(self):
        """_remote_root_shas 免疫墙钟回拨，且仅保留合法 7~64 位十六进制 SHA 并转小写。"""
        valid_upper = 'A' * 40
        payload = json.dumps([
            {'name': 'portal.py', 'sha': valid_upper},
            {'name': 'bad_short.py', 'sha': 'abc12'},
            {'name': 'bad_long.py', 'sha': 'a' * 65},
            {'name': 'bad_char.py', 'sha': 'z' * 40},
        ]).encode('utf-8')

        class _Resp:
            def read(self, n=-1):
                return payload if n < 0 else payload[:n]

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        fetch_count = [0]

        def fake_urlopen(_req, timeout=8):
            fetch_count[0] += 1
            return _Resp()

        env = {
            'time': SimpleNamespace(time=lambda: 100.0),
            '_ver_cache_lock': threading.Lock(),
            '_ver_cache': {'t': 9999.0, 'data': {'portal.py': '0' * 40}},
            'AWG_REPO': 'example/repo',
            'urllib': SimpleNamespace(request=SimpleNamespace(
                Request=lambda url, headers=None: url,
                urlopen=fake_urlopen,
            )),
            'json': json,
            '_log_ignored': lambda *a, **kw: None,
        }
        fn = _load_nested('_remote_root_shas', env)
        res = fn()
        self.assertEqual(fetch_count[0], 1, '系统时钟回拨时必须失效陈旧缓存并重新拉取')
        self.assertEqual(res['portal.py'], 'a' * 40)
        self.assertEqual(res['bad_short.py'], '')
        self.assertEqual(res['bad_long.py'], '')
        self.assertEqual(res['bad_char.py'], '')

    def test_write_gost_selfcheck_fsyncs_and_isolates_cleanup_oserror(self):
        """write_gost_selfcheck 在 os.replace 前应调用 os.fsync，且 unlink 失败不得掩盖原始异常。"""
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / 'hy2-gost-selfcheck'
            events = []
            real_fsync = os.fsync
            real_replace = os.replace

            def tracked_fsync(fd):
                events.append('fsync')
                return real_fsync(fd)

            def tracked_replace(src, dst):
                events.append('replace')
                return real_replace(src, dst)

            fake_os = SimpleNamespace(
                urandom=os.urandom,
                O_WRONLY=os.O_WRONLY,
                O_CREAT=os.O_CREAT,
                O_EXCL=os.O_EXCL,
                open=os.open,
                fdopen=os.fdopen,
                fsync=tracked_fsync,
                chmod=os.chmod,
                replace=tracked_replace,
            )
            if hasattr(os, 'O_NOFOLLOW'):
                fake_os.O_NOFOLLOW = os.O_NOFOLLOW

            env = {
                'GOST_SELFCHECK_PATH': target,
                'GOST_SELFCHECK_SCRIPT': '#!/bin/sh\nexit 0\n',
                'os': fake_os,
                '_log_ignored': lambda *a, **kw: None,
            }
            fn = _load_nested('write_gost_selfcheck', env)
            self.assertTrue(fn())
            self.assertIn('fsync', events)
            self.assertLess(events.index('fsync'), events.index('replace'))

            # 替换失败且清理临时文件也抛出 OSError 时，仍应平滑返回 False 而不泄漏异常
            logged = []
            fake_os_fail = SimpleNamespace(
                urandom=os.urandom,
                O_WRONLY=os.O_WRONLY,
                O_CREAT=os.O_CREAT,
                O_EXCL=os.O_EXCL,
                open=os.open,
                fdopen=os.fdopen,
                fsync=real_fsync,
                chmod=os.chmod,
                replace=lambda _s, _d: (_ for _ in ()).throw(OSError('replace-failed')),
            )
            if hasattr(os, 'O_NOFOLLOW'):
                fake_os_fail.O_NOFOLLOW = os.O_NOFOLLOW
            env2 = {
                'GOST_SELFCHECK_PATH': target,
                'GOST_SELFCHECK_SCRIPT': '#!/bin/sh\nexit 0\n',
                'os': fake_os_fail,
                '_log_ignored': lambda tag, exc: logged.append((tag, str(exc))),
            }
            fn2 = _load_nested('write_gost_selfcheck', env2)
            with mock.patch.object(Path, 'unlink', side_effect=OSError('unlink-failed')):
                self.assertFalse(fn2())
            self.assertTrue(any('replace-failed' in msg for _, msg in logged))


if __name__ == '__main__':
    unittest.main()
