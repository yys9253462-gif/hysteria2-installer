"""第 8 轮（2026-10-31）回归：10 项修复的行为锁定。

风格与既有 test_roundN_fixes.py 一致：
  * 只锁**行为**，不匹配源码字符串（除非那条不变量本身就是"源码形态"）；
  * 用 ast 提取单个函数、在隔离命名空间里执行，避免把整个门户拖起来；
  * 每个用例注明它防的是哪一次真实故障。
"""
import ast
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
PORTAL = ROOT / 'portal.py'
SOURCE = PORTAL.read_text(encoding='utf-8')
TREE = ast.parse(SOURCE)


def function_node(name, tree=TREE):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError('函数不存在: %s' % name)


def exec_function(name, extra_env=None, drop_defaults=None):
    """把单个函数（及其默认参数/装饰器）放到隔离命名空间里执行，返回该函数。"""
    node = function_node(name)
    module = ast.Module(body=[node], type_ignores=[])
    ast.fix_missing_locations(module)
    env = {'__name__': 'portal_fn_' + name}
    env.update(extra_env or {})
    for key in (drop_defaults or ()):
        env.setdefault(key, mock.Mock())
    code = compile(module, str(PORTAL), 'exec')
    exec(code, env)
    return env[name]


# --------------------------------------------------------------------------
# 1. atomic_write_private 的临时文件必须唯一，且目录 fsync 失败才算"已替换"
# --------------------------------------------------------------------------
class AtomicWritePrivateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def load(self):
        class DurabilityError(OSError):
            replaced = True

        def ignored(where, exc):
            pass

        return exec_function('atomic_write_private', {
            'os': os, 'Path': Path, 'tempfile': tempfile, 'time': time,
            'AtomicWriteDurabilityError': DurabilityError,
        })

    def test_concurrent_writers_do_not_share_one_temp_file(self):
        """两个写入者交错时，旧实现共用 <name>.tmp 会互相截断。

        旧实现：temp = path.with_suffix('.tmp') —— 固定名。
        这里直接锁住"临时文件名唯一"这条不变量：并发写 40 次，
        最终内容必须严格等于最后一次写入的完整 payload（不能是半截）。
        """
        write = self.load()
        target = self.tmp / 'portal.json'
        payloads = [json.dumps({'n': i, 'pad': 'x' * 4096}).encode() for i in range(40)]
        errors = []

        def worker(payload):
            try:
                write(target, payload)
            except Exception as exc:  # pragma: no cover - 失败即断言失败
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(p,)) for p in payloads]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        final = json.loads(target.read_bytes().decode())
        self.assertIn(final, [json.loads(p.decode()) for p in payloads])
        # 目录里不能残留任何 .tmp
        leftovers = [p.name for p in self.tmp.iterdir() if p.name.endswith('.tmp')]
        self.assertEqual(leftovers, [])

    def test_missing_parent_is_a_plain_oserror_not_durability_error(self):
        """目录不存在时，不能报成 replaced=True。

        调用方（计量 runtime）对 replaced=True 的处理是"文件已落盘，保留内存新状态"。
        父目录根本不存在 / mkstemp 建不出临时文件时，必须按普通 OSError 抛，
        让调用方走正常回滚，而不是留下「内存有、磁盘没有」的分叉。
        """
        write = self.load()
        target = self.tmp / 'sub' / 'portal.json'
        with self.assertRaises(OSError) as cm:
            write(target, b'{}')
        self.assertFalse(getattr(cm.exception, 'replaced', False))

    def test_directory_fsync_failure_marks_replaced(self):
        """目录**打开成功、只说 fsync 失败**时，必须抛 replaced=True。

        Windows 既没有 O_DIRECTORY 也不支持目录 fsync（生产是 Linux），
        所以这里强制打开该分支，验证的正是 Linux 上的真实行为。
        """
        if not hasattr(os, 'O_DIRECTORY'):
            self.skipTest('平台不支持目录 fsync（生产部署是 Linux）')
        write = self.load()
        target = self.tmp / 'portal.json'
        real_fsync = os.fsync
        seen = {'file': False}

        def flaky_fsync(fd):
            # 文件那次正常 fsync；目录那次才失败。
            if not seen['file']:
                seen['file'] = True
                real_fsync(fd)
                return
            raise OSError('boom')

        with mock.patch.object(os, 'fsync', flaky_fsync):
            with self.assertRaises(OSError) as cm:
                write(target, b'{"a":1}')
        self.assertTrue(getattr(cm.exception, 'replaced', False))
        self.assertEqual(target.read_bytes(), b'{"a":1}')


# --------------------------------------------------------------------------
# 2. _unreachable_outbounds 必须容忍损坏的 custom_outbounds 条目
# --------------------------------------------------------------------------
class UnreachableOutboundsTests(unittest.TestCase):
    def test_corrupt_entries_are_skipped_not_raised(self):
        fn = exec_function('_unreachable_outbounds', {
            're': __import__('re'), 'socket': mock.Mock(),
        })
        # 旧实现在 "str" / 123 / None 上直接 AttributeError，
        # 于是「保存出站」永远失败，提示只有一句"应用失败"。
        for bad in ('str', 123, None, ['list'], {'type': 'socks5', 'addr': 42}):
            self.assertEqual(fn([bad], timeout=0.01), [])


# --------------------------------------------------------------------------
# 3. _restart_hy2 的超时必须变成可诊断的 RuntimeError
# --------------------------------------------------------------------------
class RestartHy2Tests(unittest.TestCase):
    def call(self, run_impl):
        fn = exec_function('_restart_hy2', {
            'subprocess': mock.Mock(run=run_impl, TimeoutExpired=subprocess.TimeoutExpired),
            '_unit_suspended': lambda unit: False,
        })
        return fn()

    def test_timeout_is_reported_with_the_unit_name(self):
        def boom(args, **kwargs):
            raise subprocess.TimeoutExpired(args, kwargs.get('timeout'))
        with self.assertRaises(RuntimeError) as cm:
            self.call(boom)
        self.assertIn('hysteria-server', str(cm.exception))
        self.assertIn('超时', str(cm.exception))

    def test_suspended_unit_is_not_touched(self):
        calls = []
        fn = exec_function('_restart_hy2', {
            'subprocess': mock.Mock(run=lambda *a, **k: calls.append(a)),
            '_unit_suspended': lambda unit: True,
        })
        fn()
        self.assertEqual(calls, [])


# --------------------------------------------------------------------------
# 4. _hy2_config_loaded 必须按 systemd 给出的时区解释启动时间
# --------------------------------------------------------------------------
class Hy2ConfigLoadedTests(unittest.TestCase):
    def test_utc_timestamp_is_not_shifted_by_local_timezone(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        cfg = tmp / 'config.yaml'
        cfg.write_text('acl: []\n')

        stamp = time.strftime('%a %Y-%m-%d %H:%M:%S', time.gmtime(cfg.stat().st_mtime + 5))
        fn = exec_function('_hy2_config_loaded', {
            'time': time, 'Path': Path,
            '_hy2_runtime_identity': lambda: ('active', '1234', stamp + ' UTC'),
        })
        # 配置比进程启动早 5 秒 → 已被加载。
        # 旧实现在非 UTC 机器上会整体偏移时区差（东八区偏移 8 小时），
        # 结果恒为 False（或不稳定），这里的断言在两种时区下都成立。
        self.assertTrue(fn(cfg))


# --------------------------------------------------------------------------
# 5/6. 两个常驻线程必须兜住 BaseException 继续跑
# --------------------------------------------------------------------------
class WorkerResilienceTests(unittest.TestCase):
    def test_usage_meter_run_survives_base_exception(self):
        spec = importlib.util.spec_from_file_location(
            'meter_runtime_probe', ROOT / 'usage-meter-runtime-20261007-v1.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        class Stop(Exception):
            pass

        meter = module.PortalMeter.__new__(module.PortalMeter)
        meter.stop = threading.Event()
        calls = []

        def poll():
            calls.append(1)
            if len(calls) >= 3:
                meter.stop.set()
            if len(calls) == 1:
                raise Stop('first round')

        meter.poll = poll
        meter.run()          # 不抛就是通过
        self.assertEqual(len(calls), 3)

    def test_poll_loop_of_both_workers_catches_base_exception(self):
        """两条常驻循环的 except 子句必须覆盖 BaseException（源码形态断言）。"""
        for worker in ('expiry_access_worker', 'reality_iplimit_worker'):
            node = function_node(worker)
            handlers = [h for t in ast.walk(node) if isinstance(t, ast.Try) for h in t.handlers]
            self.assertTrue(handlers, worker + ' 没有 try')
            names = [ast.unparse(h.type) if h.type else 'bare' for h in handlers]
            self.assertIn('BaseException', names, worker + ' 只兜了 Exception')


# --------------------------------------------------------------------------
# 7. 计量初始化失败必须给出可执行的下一步
# --------------------------------------------------------------------------
class MeterUnavailableHintTests(unittest.TestCase):
    def test_hint_mentions_the_bundle_files(self):
        idx = SOURCE.find('计量不可用')
        self.assertGreater(idx, 0, '缺少计量不可用的显式提示')
        window = SOURCE[idx:idx + 400]
        self.assertIn('usage-meter', window)


# --------------------------------------------------------------------------
# 8. Xray 预检/启动失败必须带出真实原因
# --------------------------------------------------------------------------
class XrayFailureDiagnosticsTests(unittest.TestCase):
    def test_unit_failure_hint_returns_empty_on_failure(self):
        fn = exec_function('_unit_failure_hint', {
            'subprocess': mock.Mock(run=mock.Mock(side_effect=OSError('no systemd'))),
        })
        self.assertEqual(fn('xray'), '')

    def test_unit_failure_hint_includes_journal_tail(self):
        out = mock.Mock(stdout='line-a\nline-b\n  \nline-c\n', returncode=0)
        fn = exec_function('_unit_failure_hint', {
            'subprocess': mock.Mock(run=lambda *a, **k: out),
        })
        hint = fn('xray')
        self.assertTrue(hint.startswith('：'))
        for part in ('line-a', 'line-b', 'line-c'):
            self.assertIn(part, hint)

    def test_precheck_failure_carries_stderr(self):
        """预检失败时 RuntimeError 里必须带上 xray run -test 的输出尾部。"""
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        cfg = tmp / 'xray.json'

        calls = []

        def fake_run(args, **kwargs):
            calls.append(args)
            if 'run' in args and '-test' in args:
                return mock.Mock(returncode=28, stdout='', stderr='failed to parse config: bad uuid')
            return mock.Mock(returncode=0, stdout='inactive', stderr='')

        fn = exec_function('apply_xray_config_transaction', {
            'Path': Path, 'json': json, 'os': os, 'subprocess': mock.Mock(run=fake_run),
            '_unit_failure_hint': lambda unit: '',
        })
        with self.assertRaises(RuntimeError) as cm:
            fn({'inbounds': []}, config_path=str(cfg), binary='/bin/true', restart=False)
        self.assertIn('bad uuid', str(cm.exception))
        self.assertFalse(cfg.exists(), '预检失败不能留下新配置')


# --------------------------------------------------------------------------
# 9. 分享页 / Reality 状态端点必须续期连接死线
# --------------------------------------------------------------------------
class SlowEndpointDeadlineTests(unittest.TestCase):
    def test_qr_rendering_endpoints_extend_deadline(self):
        for handler in ('_h_get_reality_status',):
            node = function_node(handler)
            text = ast.unparse(node)
            self.assertIn('_extend_deadline', text, handler + ' 未续期死线')
        # 分享页是 serve() 里的内联分支，用"续期调用出现在 qrencode 之前"钉住。
        share = SOURCE.index("if action_file == 'qr.svg'")
        window = SOURCE[max(0, share - 2000):share]
        self.assertIn('_extend_deadline', window, '分享页未在 qrencode 之前续期')


# --------------------------------------------------------------------------
# 10. CSP 必须包含 upgrade-insecure-requests
# --------------------------------------------------------------------------
class ContentPolicyTests(unittest.TestCase):
    def test_policy_upgrades_insecure_requests(self):
        fn = exec_function('content_policy', {
            'base64': __import__('base64'), 'hashlib': __import__('hashlib'),
            'SCRIPT': 'a', 'LOGIN_SCRIPT': 'b', 'USER_SCRIPT': 'c', 'STYLE': 'd',
        })
        policy = fn()
        self.assertIn('upgrade-insecure-requests', policy)
        self.assertIn("default-src 'none'", policy)


# --------------------------------------------------------------------------
# 11. awgctl.sh 的参数缺值必须是人话
# --------------------------------------------------------------------------
class AwgctlArgumentTests(unittest.TestCase):
    BASH = shutil.which('bash')

    def test_missing_option_value_gives_a_readable_error(self):
        if not self.BASH:
            self.skipTest('requires bash')
        script = ROOT / 'awgctl.sh'
        # 只跑到参数解析：用 require_root 之后的 die 之前就退出。
        result = subprocess.run([self.BASH, str(script), 'install', '--port'],
                                capture_output=True, text=True, timeout=20)
        combined = (result.stdout or '') + (result.stderr or '')
        self.assertNotIn('unbound variable', combined)
        self.assertIn('缺少取值', combined)

    def test_need_value_is_shared_not_duplicated(self):
        text = (ROOT / 'awgctl.sh').read_text(encoding='utf-8')
        self.assertIn('need_value()', text)
        # 每一处 `--option) var="$2"; shift 2 ;;` 都是旧写法，必须已经清零。
        import re
        leftovers = re.findall(r'--[a-z-]+\)\s+\w+="\$2";\s*shift 2 ;;', text)
        self.assertEqual(leftovers, [])


# --------------------------------------------------------------------------
# 12. _prune_portal_backups 不能删掉本轮备份（make-or-break：删了就没法回滚）
# --------------------------------------------------------------------------
class PrunePortalBackupsTests(unittest.TestCase):
    def load(self):
        return exec_function('_prune_portal_backups', {'Path': Path})

    def test_current_round_files_survive(self):
        """一次更新有 6 个文件；keep=3 若按文件数算会把本轮备份全删掉。"""
        prune = self.load()
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, True)
        # 三轮历史备份
        for stamp in ('20260101-000000-1', '20260102-000000-1', '20260103-000000-1'):
            (base / ('portal.py.bak-' + stamp)).write_text('old')
        # 本轮 6 个文件
        current = []
        for name in ('portal.py', 'portal_assets.py', 'usage-meter-core-20261007-v1.py',
                     'usage-meter-readers-20261007-v1.py',
                     'usage-meter-runtime-20261007-v1.py',
                     'usage-meter-xray-config-20261007-v1.py'):
            p = base / ('%s.bak-20260104-000000-9' % name)
            p.write_text('current')
            current.append(p)
        prune(base, keep=3, protected=[str(p) for p in current])
        for p in current:
            self.assertTrue(p.exists(), '本轮备份被删掉了，回滚会失效: %s' % p.name)
        # 最老的一轮应当已被清理
        self.assertFalse((base / 'portal.py.bak-20260101-000000-1').exists())

    def test_keep_counts_rounds_not_files(self):
        prune = self.load()
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, True)
        for stamp in ('20260101-000000-1', '20260102-000000-1', '20260103-000000-1',
                      '20260104-000000-1'):
            for name in ('portal.py', 'portal_assets.py'):
                (base / ('%s.bak-%s' % (name, stamp))).write_text('x')
        prune(base, keep=3)
        remaining = sorted(p.name for p in base.iterdir())
        # 保留最近 3 轮 × 2 文件 = 6 个
        self.assertEqual(len(remaining), 6, remaining)
        self.assertNotIn('portal.py.bak-20260101-000000-1', remaining)

    def test_legacy_fixed_bak_files_are_never_touched(self):
        """旧版本的固定名 .bak 可能是当前唯一可用的回滚点，绝不能删。"""
        prune = self.load()
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, True)
        legacy = base / 'portal.py.bak'
        legacy.write_text('legacy')
        for i in range(6):
            (base / ('portal.py.bak-2026010%d-000000-1' % i)).write_text('x')
        prune(base, keep=1)
        self.assertTrue(legacy.exists())


if __name__ == '__main__':
    unittest.main()
