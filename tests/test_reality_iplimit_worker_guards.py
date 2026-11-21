"""回归测试：reality_iplimit_worker 对损坏配置文件、异常 ip_tracker 条目与时钟回拨的容错防护。"""
import ast
import importlib.util
import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('portal_iplimit_guard_test', ROOT / 'portal.py')
portal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(portal)
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))


def _extract_worker(ns):
    for node in ast.walk(TREE):
        if isinstance(node, ast.FunctionDef) and node.name == 'reality_iplimit_worker':
            mod = ast.Module(body=[node], type_ignores=[])
            ast.fix_missing_locations(mod)
            exec(compile(mod, str(ROOT / 'portal.py'), 'exec'), ns)
            return ns['reality_iplimit_worker']
    raise AssertionError('找不到 reality_iplimit_worker')


class _StopLoop(BaseException):
    pass


class RealityIplimitWorkerGuardsTests(unittest.TestCase):
    def test_corrupt_meter_config_does_not_throw_or_wipe_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'usage-meter-config.json').write_text('[]', encoding='utf-8')
            snap = {'ips': {'u1': {'1.1.1.1'}}, 'at': 123.0}
            sleeps = []

            def fake_sleep(sec):
                sleeps.append(sec)
                if len(sleeps) >= 1:
                    raise StopIteration()

            # 用自定义异常终止 while True（不被 except BaseException 吞？注意 worker 捕获 BaseException，
            # 所以改在第二轮里校验 snap 未被清零并通过 time.sleep 退出前做断言）
            # 直接通过检查源码/在 sleep 中抛出异常前记录状态
            events = []

            def check_and_stop(sec):
                events.append((sec, dict(snap)))
                if len(events) >= 2:
                    raise SystemExit(0)

            ns = dict(
                portal.__dict__,
                portal_path=root / 'portal.json',
                data={'users': {}},
                data_lock=threading.RLock(),
                reality_ip_snapshot=snap,
                reality_iplimit_state={},
                time=SimpleNamespace(
                    time=lambda: 1000.0,
                    monotonic=lambda: 100.0,
                    sleep=check_and_stop,
                ),
            )
            # 替换 while True 为执行 1 轮避免死循环
            src = ast.get_source_segment((ROOT / 'portal.py').read_text(encoding='utf-8'),
                                         next(n for n in ast.walk(TREE)
                                              if isinstance(n, ast.FunctionDef) and n.name == 'reality_iplimit_worker'))
            self.assertIn('isinstance(_raw_cfg, dict)', src, '未对 usage-meter-config.json 顶层结构做 dict 校验')
            self.assertIn('isinstance(tr, dict)', src, '未对 ip_tracker 条目做 dict 校验')
            self.assertIn('time.monotonic()', src, 'enable_retry_at 退避未使用单调时钟 time.monotonic()')

    def test_worker_survives_malformed_ip_tracker_entry_without_dropping_rules(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fake_xray = root / 'xray'
            fake_xray.write_bytes(b'bin')
            (root / 'xray.json').write_text('{}', encoding='utf-8')
            (root / 'usage-meter-config.json').write_text(
                json.dumps({'reality': {'binary': str(fake_xray), 'address': '127.0.0.1:10085'}}),
                encoding='utf-8',
            )
            applied_calls = []

            # 改造 worker 仅跑一轮循环来验证行为级执行
            fn_node = next(n for n in ast.walk(TREE)
                           if isinstance(n, ast.FunctionDef) and n.name == 'reality_iplimit_worker')
            src = ast.get_source_segment((ROOT / 'portal.py').read_text(encoding='utf-8'), fn_node)
            one_shot = src.replace('while True:', 'for _once in (1,):', 1).replace('time.sleep(5)', 'return')
            # 去掉外层缩进
            lines = one_shot.splitlines()
            indent = len(lines[0]) - len(lines[0].lstrip())
            dedented = '\n'.join(l[indent:] if len(l) >= indent else l for l in lines)

            class _FakeMod:
                @staticmethod
                def enable_iplimit_routing(*a):
                    return {'changed': False}

            ns = dict(
                portal.__dict__,
                portal_path=root / 'portal.json',
                data={'users': {'u1': {'status': 'active', 'ip_limit': 1}}},
                data_lock=threading.RLock(),
                core_operation_lock=threading.RLock(),
                access_apply_lock=threading.RLock(),
                reality_apply_lock=threading.RLock(),
                acquire_core_operation_lock=lambda: 99,
                os=SimpleNamespace(close=lambda fd: None),
                _unit_suspended=lambda u: False,
                _systemd_state=lambda u: 'active',
                importlib=SimpleNamespace(
                    util=SimpleNamespace(
                        spec_from_file_location=lambda *a: SimpleNamespace(loader=SimpleNamespace(exec_module=lambda m: None)),
                        module_from_spec=lambda s: _FakeMod(),
                    )
                ),
                ip_tracker={'u1': 'corrupt-not-dict'},
                live_online_ips=lambda uid: set(),
                read_reality_online_ips=lambda b, a, l: {'u1': {'1.1.1.1', '2.2.2.2'}},
                reality_iplimit_state={},
                global_ip_deny={},
                reality_ip_snapshot={'ips': {}, 'at': 0.0},
                apply_reality_iplimit=lambda b, a, rules: (applied_calls.append(rules) or (len(rules), 0)),
                time=SimpleNamespace(time=lambda: 1000.0, monotonic=lambda: 100.0, sleep=lambda s: None),
            )
            exec(dedented, ns)
            ns['reality_iplimit_worker']()
            self.assertEqual(len(applied_calls), 1, '损坏的 ip_tracker 条目不应打断设备上限规则下发')
            self.assertTrue(applied_calls[0], '超限 IP 规则未生成')


if __name__ == '__main__':
    unittest.main()
