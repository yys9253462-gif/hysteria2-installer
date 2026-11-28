"""节点总流量限额与自动硬熔断（防云服务器超量计费）全链路离线回归测试。

覆盖范围：
  1. 三种统计口径（物理出口网卡仅出站 iface_tx / 所有用户累计 users_total / 物理出口网卡双向 iface_both）；
  2. 整机重启 boot_id 变化、网卡计数器回绕连续累计，首次启用建基线增量为 0 不误自锁；
  3. 删除用户或单用户数值下调绝不倒退累计流量，首次启用对齐总已用流量；
  4. 月周期（UTC+00:00，含非闰年/闰年 2 月对 31 日自动钳制与墙钟回拨免疫）自动归零恢复；
  5. 累计模式（cumulative）绝不自动重置；
  6. 硬熔断立即关停全部 6 个对外代理服务、绕过 60 秒节流立刻落盘、熔断期间持续防复活与永生兜底守护线程；
  7. 与主控制台 /api/v1/node/suspend 的 reasons 原因列表隔离和平共存（互不误解封、互不越权启动）；
  8. 网页会话路由 GET/POST <prefix>node-traffic-quota（含 401/413/边界校验/手动校准/清零恢复）、
     traffic-speed 摘要并入、低权限 /api/v1 不可达、CLI 状态合并保护（merge_cli_owned_state / refresh / adopt）；
  9. 前端渲染、登录页零泄漏、CSP 哈希、无裸花括号、无内联事件，以及 Node 执行真实 portal.SCRIPT 交互验收。
"""
import ast
import base64
import copy
import datetime
import email.message
import hashlib
import http.client
import io
import json
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))

import portal  # noqa: E402
from test_hash_routing import NODE, page_model, run_portal_page  # noqa: E402

PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
PORTAL_TREE = ast.parse(PORTAL_SRC)
GIB = 1024 ** 3


def _utc_ts(year, month, day, hour=0, minute=0, second=0):
    return int(datetime.datetime(year, month, day, hour, minute, second,
                                 tzinfo=datetime.timezone.utc).timestamp())


def _extract_serve_closure(names, extra_ns):
    """提取 serve() 内部的指定嵌套函数到受控命名空间中执行测试。"""
    wanted = set(names)
    serve_node = next(n for n in PORTAL_TREE.body if isinstance(n, ast.FunctionDef) and n.name == 'serve')
    nodes = [copy.deepcopy(n) for n in serve_node.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
    missing = wanted - {n.name for n in nodes}
    if missing:
        raise AssertionError(f'serve() 中未找到目标嵌套函数: {sorted(missing)}')
    mod = ast.Module(body=nodes, type_ignores=[])
    ast.fix_missing_locations(mod)
    ns = dict(portal.__dict__)
    ns.update(extra_ns)
    exec(compile(mod, '<serve-node-quota-test>', 'exec'), ns)
    return ns


def _extract_handler_method(name, extra_ns):
    """提取 Handler 类内单个方法，构造离线可测的处理函数。"""
    for node in ast.walk(PORTAL_TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            src = ast.get_source_segment(PORTAL_SRC, node)
            dedented = '\n'.join(line[8:] if line.startswith('        ') else line for line in src.splitlines())
            ns = dict(portal.__dict__)
            ns.update(extra_ns)
            exec(compile(dedented, f'<{name}>', 'exec'), ns)
            return ns[name]
    raise AssertionError(f'portal.py 未找到 Handler 方法 {name}')


class NodeQuotaPureEngineTests(unittest.TestCase):
    """纯函数计量引擎：三口径、重启、回绕、删用户、短月钳制、累计模式与损坏数据防御。"""

    def test_three_modes_and_first_baseline_never_self_locks(self):
        """首次启用网卡口径仅建基线（增量=0），绝不把机器开机历史大流量直接当成当前周期自锁。"""
        now = _utc_ts(2026, 11, 10, 12, 0, 0)
        q = portal.default_node_traffic_quota()
        q.update(enabled=True, mode='iface_tx', limit_bytes=50 * GIB, reset_mode='monthly', reset_day=1)

        # 机器已开机累计出站 500 GB（远超 50 GB 限额），首次采样只建基线，已用必须保持 0
        c0 = {'tx_bytes': 500 * GIB, 'rx_bytes': 300 * GIB, 'interfaces': ['ens4'], 'boot_id': 'boot-a'}
        q1, ev1 = portal.advance_node_traffic_quota(q, c0, {'u1': 5 * GIB}, now)
        self.assertTrue(ev1['baseline_initialized'])
        self.assertEqual(q1['used_bytes'], 0)
        self.assertFalse(ev1['over_limit'])
        self.assertEqual(q1['last_interfaces'], ['ens4'])

        # 后续产生 10 GB 出站 + 20 GB 入站：iface_tx 仅计 10 GB
        c1 = {'tx_bytes': 510 * GIB, 'rx_bytes': 320 * GIB, 'interfaces': ['ens4'], 'boot_id': 'boot-a'}
        q2, ev2 = portal.advance_node_traffic_quota(q1, c1, {'u1': 5 * GIB}, now + 5)
        self.assertEqual(q2['used_bytes'], 10 * GIB)
        self.assertFalse(ev2['over_limit'])

        # 切换为 iface_both（双向总计）：10 GB + 20 GB = 30 GB
        q2['mode'] = 'iface_both'
        q3, _ = portal.advance_node_traffic_quota(q2, c1, {'u1': 5 * GIB}, now + 10)
        self.assertEqual(q3['used_bytes'], 30 * GIB)

        # 切换为 users_total（所有用户累计）：首次初始化时对齐 5 GB，再加 12 GB 用户增量 -> 17 GB
        q3['mode'] = 'users_total'
        q4, _ = portal.advance_node_traffic_quota(q3, c1, {'u1': 17 * GIB}, now + 15)
        self.assertEqual(q4['used_bytes'], 17 * GIB)

    def test_reboot_boot_id_change_and_counter_wrap_preserve_accumulated_usage(self):
        """整机重启（boot_id 变化）与同开机网卡计数回绕均只累加新值，绝不丢旧累计。"""
        now = _utc_ts(2026, 11, 10, 12, 0, 0)
        q = portal.default_node_traffic_quota()
        q.update(enabled=True, mode='iface_tx', limit_bytes=100 * GIB)

        c0 = {'tx_bytes': 40 * GIB, 'rx_bytes': 10 * GIB, 'interfaces': ['eth0'], 'boot_id': 'boot-1'}
        q, _ = portal.advance_node_traffic_quota(q, c0, {}, now)
        # 正常增量 +25 GB -> 累计 25 GB
        c1 = {'tx_bytes': 65 * GIB, 'rx_bytes': 15 * GIB, 'interfaces': ['eth0'], 'boot_id': 'boot-1'}
        q, _ = portal.advance_node_traffic_quota(q, c1, {}, now + 5)
        self.assertEqual(q['used_bytes'], 25 * GIB)

        # 整机重启，boot_id 变为 boot-2，新开机计数器为 8 GB -> 累计 25 + 8 = 33 GB
        c2 = {'tx_bytes': 8 * GIB, 'rx_bytes': 2 * GIB, 'interfaces': ['eth0'], 'boot_id': 'boot-2'}
        q, _ = portal.advance_node_traffic_quota(q, c2, {}, now + 60)
        self.assertEqual(q['used_bytes'], 33 * GIB)
        self.assertEqual(q['last_boot_id'], 'boot-2')

        # 再次整机重启（boot-3），且重启后门户首次采样前已产生 12 GB（大于重启前的 8 GB）：
        # 必须依靠 boot_id 变化识别重启并全额累加 12 GB（33 + 12 = 45 GB），而非误算差值 12 - 8 = 4 GB！
        c2b = {'tx_bytes': 12 * GIB, 'rx_bytes': 4 * GIB, 'interfaces': ['eth0'], 'boot_id': 'boot-3'}
        q, _ = portal.advance_node_traffic_quota(q, c2b, {}, now + 120)
        self.assertEqual(q['used_bytes'], 45 * GIB)
        self.assertEqual(q['last_boot_id'], 'boot-3')

        # 同一次开机内驱动重载导致计数器从 12 GB 回绕到 3 GB -> 累加新值 3 GB -> 48 GB
        c3 = {'tx_bytes': 3 * GIB, 'rx_bytes': 1 * GIB, 'interfaces': ['eth0'], 'boot_id': 'boot-3'}
        q, _ = portal.advance_node_traffic_quota(q, c3, {}, now + 125)
        self.assertEqual(q['used_bytes'], 48 * GIB)

    def test_users_total_deleting_or_resetting_user_never_decreases_usage(self):
        """删除用户或用户计数回落绝不导致节点累计流量倒退，新用户与存量正增量正常累加。"""
        now = _utc_ts(2026, 11, 10, 12, 0, 0)
        q = portal.default_node_traffic_quota()
        q.update(enabled=True, mode='users_total', limit_bytes=20 * GIB)
        c = {'tx_bytes': 0, 'rx_bytes': 0, 'interfaces': ['eth0'], 'boot_id': 'b1'}

        # 首次初始化：对齐当前用户总已用流量 5 + 3 = 8 GB
        q, _ = portal.advance_node_traffic_quota(q, c, {'alice': 5 * GIB, 'bob': 3 * GIB}, now)
        self.assertEqual(q['used_bytes'], 8 * GIB)

        # 删除用户 bob：已用必须维持 8 GB 不倒退
        q, _ = portal.advance_node_traffic_quota(q, c, {'alice': 5 * GIB}, now + 5)
        self.assertEqual(q['used_bytes'], 8 * GIB)
        self.assertNotIn('bob', q['last_user_bytes'])

        # alice 增长 2 GB -> 10 GB；随后 alice 被误清成 1 GB（回退不减）-> 仍 10 GB
        q, _ = portal.advance_node_traffic_quota(q, c, {'alice': 7 * GIB}, now + 10)
        self.assertEqual(q['used_bytes'], 10 * GIB)
        q, _ = portal.advance_node_traffic_quota(q, c, {'alice': 1 * GIB}, now + 15)
        self.assertEqual(q['used_bytes'], 10 * GIB)

        # 同名新用户 bob 产生 11 GB -> 10 + 11 = 21 GB >= 20 GB 触发超限
        q, ev = portal.advance_node_traffic_quota(q, c, {'alice': 1 * GIB, 'bob': 11 * GIB}, now + 20)
        self.assertEqual(q['used_bytes'], 21 * GIB)
        self.assertTrue(ev['over_limit'])

    def test_monthly_reset_clamps_short_months_and_resists_clock_rollback(self):
        """月度重置按 UTC+00:00 将 31 日自动钳制到 2 月 28/29 日，且免疫墙钟回拨误清零。"""
        # 1) 非闰年 2026 年，账单日 31 日
        ck, start, nxt = portal.node_quota_cycle_window(_utc_ts(2026, 1, 31, 10), 31)
        self.assertEqual(ck, '2026-01-31')
        self.assertEqual(start, _utc_ts(2026, 1, 31, 0))
        self.assertEqual(nxt, _utc_ts(2026, 2, 28, 0))

        # 2 月 27 日 23:59:59 仍在 2026-01-31 周期，不触发重置
        q = portal.default_node_traffic_quota()
        q.update(enabled=True, mode='iface_tx', limit_bytes=10 * GIB, reset_mode='monthly', reset_day=31,
                 cycle_key='2026-01-31', cycle_start_ts=_utc_ts(2026, 1, 31, 0),
                 iface_tx_accum=12 * GIB, iface_baseline_ready=True, last_boot_id='b1', last_raw_tx=50 * GIB,
                 tripped=True, tripped_at=_utc_ts(2026, 2, 20, 0))
        c = {'tx_bytes': 50 * GIB, 'rx_bytes': 0, 'interfaces': ['eth0'], 'boot_id': 'b1'}
        q_before, ev_before = portal.advance_node_traffic_quota(q, c, {}, _utc_ts(2026, 2, 27, 23, 59, 59))
        self.assertFalse(ev_before['did_reset'])
        self.assertEqual(q_before['used_bytes'], 12 * GIB)
        self.assertTrue(ev_before['over_limit'])

        # 跨到 2026-02-28 00:00:00 UTC：自动归零并清除 tripped
        q_after, ev_after = portal.advance_node_traffic_quota(q_before, c, {}, _utc_ts(2026, 2, 28, 0, 0, 0))
        self.assertTrue(ev_after['did_reset'])
        self.assertEqual(q_after['cycle_key'], '2026-02-28')
        self.assertEqual(q_after['used_bytes'], 0)
        self.assertFalse(q_after['tripped'])
        self.assertFalse(ev_after['over_limit'])

        # 墙钟回拨到 2026-02-27 23:00：绝不能把新周期已用的 3 GB 误重置
        c_used = {'tx_bytes': 53 * GIB, 'rx_bytes': 0, 'interfaces': ['eth0'], 'boot_id': 'b1'}
        q_used, _ = portal.advance_node_traffic_quota(q_after, c_used, {}, _utc_ts(2026, 3, 1, 0, 0, 0))
        self.assertEqual(q_used['used_bytes'], 3 * GIB)
        q_back, ev_back = portal.advance_node_traffic_quota(q_used, c_used, {}, _utc_ts(2026, 2, 27, 23, 0, 0))
        self.assertFalse(ev_back['did_reset'])
        self.assertEqual(q_back['used_bytes'], 3 * GIB)

        # 2) 闰年 2024 年，账单日 31 日：2 月 28 日不重置，2 月 29 日才切换周期
        ck28, _, nxt28 = portal.node_quota_cycle_window(_utc_ts(2024, 2, 28, 12), 31)
        self.assertEqual(ck28, '2024-01-31')
        self.assertEqual(nxt28, _utc_ts(2024, 2, 29, 0))
        ck29, _, nxt29 = portal.node_quota_cycle_window(_utc_ts(2024, 2, 29, 0), 31)
        self.assertEqual(ck29, '2024-02-29')
        self.assertEqual(nxt29, _utc_ts(2024, 3, 31, 0))

    def test_cumulative_mode_never_auto_resets(self):
        """累计模式下跨过多个月绝不自动清零，始终保持超限状态。"""
        q = portal.default_node_traffic_quota()
        q.update(enabled=True, mode='iface_tx', limit_bytes=10 * GIB, reset_mode='cumulative', reset_day=1,
                 cycle_key='cumulative', cycle_start_ts=_utc_ts(2026, 1, 1),
                 iface_tx_accum=11 * GIB, iface_baseline_ready=True, last_boot_id='b1', last_raw_tx=11 * GIB,
                 tripped=True, tripped_at=_utc_ts(2026, 1, 5))
        c = {'tx_bytes': 11 * GIB, 'rx_bytes': 0, 'interfaces': ['eth0'], 'boot_id': 'b1'}
        q2, ev = portal.advance_node_traffic_quota(q, c, {}, _utc_ts(2026, 6, 15, 0, 0, 0))
        self.assertFalse(ev['did_reset'])
        self.assertEqual(q2['used_bytes'], 11 * GIB)
        self.assertTrue(ev['over_limit'])

    def test_corrupt_quota_data_is_sanitized_without_crashing(self):
        """磁盘上损坏的 node_traffic_quota 字段必须安全降级而不抛异常。"""
        for bad in (None, 123, 'broken', ['x'], {'enabled': 'yes', 'mode': 'bad', 'reset_day': True,
                                                 'limit_bytes': float('nan'), 'iface_tx_accum': -9,
                                                 'last_interfaces': [123, 'bad\nname', 'eth0']}):
            q = portal.normalize_node_traffic_quota(bad)
            self.assertIsInstance(q, dict)
            self.assertIn(q['mode'], portal.NODE_TRAFFIC_QUOTA_MODES)
            self.assertIn(q['reset_mode'], portal.NODE_TRAFFIC_QUOTA_RESETS)
            self.assertTrue(1 <= q['reset_day'] <= 31)
            self.assertGreaterEqual(q['used_bytes'], 0)


class HardTripAntiReviveAndReasonsCoexistenceTests(unittest.TestCase):
    """硬熔断关停全部 6 服务、绕过节流强落盘、5 秒防复活、与主控 reasons 和平共存。"""

    def _build_runtime(self, data, active_units, counters_ref):
        calls = []
        saves = []

        def fake_run(cmd, **kw):
            calls.append(list(cmd))
            if cmd[:2] == ['systemctl', 'stop']:
                active_units.discard(cmd[2])
            elif cmd[:2] == ['systemctl', 'start']:
                active_units.add(cmd[2])
            return subprocess.CompletedProcess(cmd, 0, '', '')

        def fake_save():
            saves.append(copy.deepcopy(data))

        ns = _extract_serve_closure(
            ('set_traffic_suspension', '_set_traffic_suspension', 'step_node_traffic_quota', 'node_traffic_quota_worker'),
            {
                'data': data,
                'data_lock': threading.RLock(),
                'traffic_suspend_lock': threading.Lock(),
                '_suspend_call_ctx': {'reason': 'controller'},
                'node_quota_lock': threading.Lock(),
                '_node_quota_last_save': [time.monotonic()],  # 故意设成刚刚落盘，验证超额瞬间能绕过 60 秒节流！
                'TRAFFIC_SUSPEND_UNITS': ('hysteria-server', 'xray', 'gost', 'amneziawg-server',
                                          portal.ANYTLS_SERVICE, portal.TUIC_SERVICE),
                '_unit_active': lambda u: u in active_units,
                'node_traffic_counters': lambda: dict(counters_ref['v']),
                'save_data': fake_save,
                'subprocess': SimpleNamespace(
                    run=fake_run,
                    TimeoutExpired=subprocess.TimeoutExpired,
                    SubprocessError=subprocess.SubprocessError,
                ),
            },
        )
        return ns, calls, saves

    def test_hard_trip_stops_all_six_units_forces_immediate_save_and_blocks_revival(self):
        """触达阈值立即关停全部 6 个对外代理服务、绕过 60 秒节流强落盘，并拦截手动复活。"""
        all_six = {'hysteria-server', 'xray', 'gost', 'amneziawg-server',
                   portal.ANYTLS_SERVICE, portal.TUIC_SERVICE}
        active = set(all_six)
        data = {
            'users': {},
            'anytls_config': {'enabled': True},
            'tuic_config': {'enabled': True},
            'node_traffic_quota': {
                'enabled': True,
                'mode': 'iface_tx',
                'limit_bytes': 10 * GIB,
                'reset_mode': 'monthly',
                'reset_day': 1,
                'cycle_key': '2026-11-01',
                'cycle_start_ts': _utc_ts(2026, 11, 1),
                'iface_tx_accum': 9 * GIB,
                'iface_baseline_ready': True,
                'last_boot_id': 'b1',
                'last_raw_tx': 100 * GIB,
                'last_raw_rx': 0,
            },
        }
        counters_ref = {'v': {'tx_bytes': 101 * GIB, 'rx_bytes': 0, 'interfaces': ['ens4'], 'boot_id': 'b1'}}
        ns, calls, saves = self._build_runtime(data, active, counters_ref)

        # 1) 达到 10 GB：立即触发硬熔断，6 个对外代理服务全部被停，且立即强制落盘（绕过 60 秒节流）
        ns['step_node_traffic_quota'](now_ts=_utc_ts(2026, 11, 15, 10))
        self.assertEqual(active, set(), '全部 6 个对外代理服务必须立即停用')
        stopped = {c[2] for c in calls if c[:2] == ['systemctl', 'stop']}
        self.assertEqual(stopped, all_six)
        self.assertNotIn('hysteria-portal', stopped, '绝不可停用门户自身')
        self.assertTrue(data['node_traffic_quota']['tripped'])
        self.assertEqual(data['traffic_suspend']['suspended'], True)
        self.assertEqual(data['traffic_suspend']['reasons'], ['local_quota'])
        self.assertGreaterEqual(len(saves), 1, '触发熔断瞬间必须绕过 60 秒节流立即落盘')

        # 2) 防复活：有人手工 systemctl start 拉起 hysteria-server 和 xray，下轮检测必须立刻强行掐停
        calls.clear()
        active.add('hysteria-server')
        active.add('xray')
        ns['step_node_traffic_quota'](now_ts=_utc_ts(2026, 11, 15, 10, 0, 5))
        self.assertEqual(active, set(), '防复活复核必须把手动拉起的服务再次掐停')
        restopped = {c[2] for c in calls if c[:2] == ['systemctl', 'stop']}
        self.assertTrue({'hysteria-server', 'xray'} <= restopped)

        # 3) 跨入下月账单日（2026-12-01 00:00 UTC）：自动归零并自动解除本机熔断、拉起 6 个服务
        calls.clear()
        ns['step_node_traffic_quota'](now_ts=_utc_ts(2026, 12, 1, 0, 0, 1))
        self.assertFalse(data['node_traffic_quota']['tripped'])
        self.assertEqual(data['node_traffic_quota']['used_bytes'], 0)
        self.assertEqual(data['traffic_suspend'], {'suspended': False})
        self.assertEqual(active, all_six, '月度自动重置后应恢复全部原本运行的代理服务')

    def test_controller_and_local_quota_reasons_coexist_without_stepping_on_each_other(self):
        """外部主控制台与本机限额通过 reasons 严格隔离：互不误解封、互不越权启动，并兼容旧无 reasons 状态。"""
        # 1) 旧版无 reasons 字段且 suspended=True 兼容视作 ['controller']
        self.assertEqual(portal.suspend_reasons({'suspended': True, 'units': ['hysteria-server']}), ['controller'])
        self.assertEqual(portal.suspend_reasons({'suspended': False}), [])

        # 2) 仅本机超量触发停用 -> 主控制台调 suspended=False 绝不误恢复
        active = {'hysteria-server', 'xray'}
        data = {'users': {}}
        counters_ref = {'v': {'tx_bytes': 0, 'rx_bytes': 0, 'interfaces': ['eth0'], 'boot_id': 'b1'}}
        ns, calls, _ = self._build_runtime(data, active, counters_ref)

        ns['set_traffic_suspension'](True, reason='local_quota')
        self.assertEqual(active, set())
        self.assertEqual(data['traffic_suspend']['reasons'], ['local_quota'])

        calls.clear()
        st, res = ns['set_traffic_suspension'](False, reason='controller')
        self.assertTrue(st['suspended'], '主控制台解封绝不得误解除本机超量熔断')
        self.assertEqual(st['reasons'], ['local_quota'])
        self.assertEqual(active, set(), '本机超量熔断仍在，不得启动任何代理服务')
        self.assertEqual(res, {})
        self.assertEqual([c for c in calls if c[:2] == ['systemctl', 'start']], [])

        # 3) 叠加上主控制台停用 -> 变成双原因 ['local_quota', 'controller']
        ns['set_traffic_suspension'](True, reason='controller')
        self.assertEqual(data['traffic_suspend']['reasons'], ['local_quota', 'controller'])

        # 本机解除 'local_quota' -> 主控原因仍在，绝不越权启动服务
        calls.clear()
        st2, res2 = ns['set_traffic_suspension'](False, reason='local_quota')
        self.assertTrue(st2['suspended'])
        self.assertEqual(st2['reasons'], ['controller'])
        self.assertEqual(active, set(), '主控制台仍停用中，本机不得越权拉起服务')
        self.assertEqual(res2, {})

        # 最后主控制台也解除 'controller' -> 全部原因清空，正式拉起原服务并恢复为 {'suspended': False}
        st3, res3 = ns['set_traffic_suspension'](False, reason='controller')
        self.assertEqual(st3, {'suspended': False})
        self.assertEqual(active, {'hysteria-server', 'xray'})
        self.assertTrue(all(res3.values()))

    def test_worker_has_5s_interval_and_immortal_guard_without_swallowing_exit_signals(self):
        """守护线程源码必须每 5 秒轮询、永生兜底 BaseException，且显式透传 SystemExit/KeyboardInterrupt。"""
        start = PORTAL_SRC.index('    def node_traffic_quota_worker():')
        end = PORTAL_SRC.index('        # 每个来源使用实际采样间隔计算速率', start)
        body = PORTAL_SRC[start:end]
        self.assertIn('time.sleep(5)', body)
        self.assertIn('except (SystemExit, KeyboardInterrupt):', body)
        self.assertIn('except BaseException as exc:', body)
        self.assertIn('target=node_traffic_quota_worker', PORTAL_SRC)


class RouteHandlerAndCliMergeTests(unittest.TestCase):
    """HTTP 路由 401/413/边界校验、校准/清零交互、traffic-speed 并入与 CLI 状态合并保护。"""

    def _call_post(self, data, body_bytes, *, headers=None, authenticated=True,
                   counters=None, active_units=None):
        active = set(active_units or ())
        replies = []
        saves = []

        def fake_run(cmd, **kw):
            if cmd[:2] == ['systemctl', 'stop']:
                active.discard(cmd[2])
            elif cmd[:2] == ['systemctl', 'start']:
                active.add(cmd[2])
            return subprocess.CompletedProcess(cmd, 0, '', '')

        def fake_save():
            saves.append(copy.deepcopy(data))

        susp_ns = _extract_serve_closure(
            ('set_traffic_suspension', '_set_traffic_suspension'),
            {
                'data': data,
                'data_lock': threading.RLock(),
                'traffic_suspend_lock': threading.Lock(),
                '_suspend_call_ctx': {'reason': 'controller'},
                'TRAFFIC_SUSPEND_UNITS': ('hysteria-server', 'xray', 'gost', 'amneziawg-server',
                                          portal.ANYTLS_SERVICE, portal.TUIC_SERVICE),
                '_unit_active': lambda u: u in active,
                'save_data': fake_save,
                'subprocess': SimpleNamespace(
                    run=fake_run,
                    TimeoutExpired=subprocess.TimeoutExpired,
                    SubprocessError=subprocess.SubprocessError,
                ),
            },
        )
        fn = _extract_handler_method('_h_post_node_traffic_quota', {
            'data': data,
            'data_lock': susp_ns['data_lock'],
            'node_quota_lock': threading.Lock(),
            '_node_quota_last_save': [None],
            'node_traffic_counters': lambda: dict(counters or {'tx_bytes': 0, 'rx_bytes': 0, 'interfaces': ['eth0'], 'boot_id': 'b1'}),
            'set_traffic_suspension': susp_ns['set_traffic_suspension'],
            'save_data': fake_save,
        })

        hdrs = headers if headers is not None else {'Content-Length': str(len(body_bytes)),
                                                    'Content-Type': 'application/x-www-form-urlencoded'}
        h = SimpleNamespace(
            headers=hdrs,
            rfile=io.BytesIO(body_bytes),
            is_authenticated=lambda: authenticated,
            _extend_deadline=lambda s: None,
            reply_json=lambda code, payload: (replies.append((code, payload)) or (code, payload)),
        )
        fn(h, '/tok/')
        return replies[0][0], replies[0][1], active, saves

    def test_post_security_401_413_duplicate_cl_and_input_bounds(self):
        """未鉴权返回 401；5000 位或超 64 KiB Content-Length 返回 413；重复/畸形头及越界参数返回 400。"""
        data = {'users': {}}
        # 401 未鉴权
        code, _, _, _ = self._call_post(data, b'action=reset', authenticated=False)
        self.assertEqual(code, 401)

        # 5000 位 Content-Length 返回 413（防整数 DoS）
        code, _, _, _ = self._call_post(data, b'', headers={'Content-Length': '9' * 5000})
        self.assertEqual(code, 413)

        # 超 64 KiB 返回 413
        code, _, _, _ = self._call_post(data, b'', headers={'Content-Length': '70000'})
        self.assertEqual(code, 413)

        # 重复 / 全角 / 负数 Content-Length 返回 400
        dup = email.message.Message()
        dup.add_header('Content-Length', '10')
        dup.add_header('Content-Length', '20')
        for bad_hdr in (dup, {'Content-Length': '１０'}, {'Content-Length': '-5'}, {'Content-Length': '+5'}):
            code, _, _, _ = self._call_post(data, b'', headers=bad_hdr)
            self.assertEqual(code, 400, f'畸形头应返回 400: {bad_hdr}')

        # 参数边界校验
        bad_payloads = [
            {'action': 'unknown'},
            {'action': 'save', 'enabled': 'maybe', 'limit_gb': '10'},
            {'action': 'save', 'enabled': 'true', 'mode': 'bad_mode', 'limit_gb': '10'},
            {'action': 'save', 'enabled': 'true', 'reset_mode': 'weekly', 'limit_gb': '10'},
            {'action': 'save', 'enabled': 'true', 'reset_day': '0', 'limit_gb': '10'},
            {'action': 'save', 'enabled': 'true', 'reset_day': '32', 'limit_gb': '10'},
            {'action': 'save', 'enabled': 'true', 'reset_day': '05', 'limit_gb': '10'},
            {'action': 'save', 'enabled': 'true', 'limit_gb': '0'},
            {'action': 'save', 'enabled': 'true', 'limit_gb': '0.0000000001'},
            {'action': 'save', 'enabled': 'true', 'limit_gb': '-1'},
            {'action': 'save', 'enabled': 'true', 'limit_gb': 'NaN'},
            {'action': 'save', 'enabled': 'true', 'limit_gb': '10', 'calibrate_used_gb': '-0.5'},
            {'action': 'save', 'enabled': 'true', 'limit_gb': '10', 'calibrate_used_gb': 'inf'},
            {'action': 'save', 'enabled': 'true', 'limit_gb': '1000001'},
            {'action': 'save', 'enabled': 'true', 'limit_gb': '10', 'reset_mode': 'cumulative', 'reset_day': '99'},
        ]
        for form in bad_payloads:
            with self.subTest(form=form):
                body = urllib.parse.urlencode(form).encode('utf-8')
                code, payload, _, _ = self._call_post(data, body)
                self.assertEqual(code, 400, f'非法入参应返回 400: {form} -> {payload}')
                self.assertFalse(payload['ok'])

        # 累计模式省略或传空 reset_day 必须合法并保留旧账单日
        data_cum = {'users': {}, 'node_traffic_quota': {'reset_day': 18}}
        for extra in ({}, {'reset_day': ''}):
            form_ok = {'action': 'save', 'enabled': 'true', 'mode': 'iface_tx',
                       'limit_gb': '50', 'reset_mode': 'cumulative'}
            form_ok.update(extra)
            code, payload, _, _ = self._call_post(data_cum, urllib.parse.urlencode(form_ok).encode('utf-8'))
            self.assertEqual(code, 200, payload)
            self.assertEqual(payload['quota']['reset_mode'], 'cumulative')
            self.assertEqual(payload['quota']['reset_day'], 18)

    def test_post_save_calibrate_immediate_trip_raise_limit_and_reset_recovery(self):
        """校准已用流量留空不变、填超限立即硬熔断、调高限额恢复、手动清零恢复。"""
        data = {'users': {'u1': {'used_bytes': 2 * GIB}}}
        counters = {'tx_bytes': 500 * GIB, 'rx_bytes': 100 * GIB, 'interfaces': ['ens4'], 'boot_id': 'b1'}
        active = {'hysteria-server', 'xray'}

        # 1) 启用 100 GB + 校准 80 GB：不熔断，已用精确校准为 80 GB
        body1 = urllib.parse.urlencode({
            'action': 'save', 'enabled': 'true', 'mode': 'iface_tx',
            'limit_gb': '100', 'reset_mode': 'monthly', 'reset_day': '15', 'calibrate_used_gb': '80',
        }).encode('utf-8')
        code, payload, active, _ = self._call_post(data, body1, counters=counters, active_units=active)
        self.assertEqual(code, 200, payload)
        self.assertEqual(payload['quota']['used_bytes'], 80 * GIB)
        self.assertFalse(payload['quota']['tripped'])
        self.assertEqual(active, {'hysteria-server', 'xray'})

        # 2) 留空 calibrate_used_gb 保存：已用保持 80 GB 不变
        body2 = urllib.parse.urlencode({
            'action': 'save', 'enabled': 'true', 'mode': 'iface_tx',
            'limit_gb': '90', 'reset_mode': 'monthly', 'reset_day': '15', 'calibrate_used_gb': '',
        }).encode('utf-8')
        code, payload, active, _ = self._call_post(data, body2, counters=counters, active_units=active)
        self.assertEqual(code, 200, payload)
        self.assertEqual(payload['quota']['used_bytes'], 80 * GIB)
        self.assertFalse(payload['quota']['tripped'])

        # 3) 校准为 95 GB（>= 90 GB）：立刻触发硬熔断关停全部对外代理服务
        body3 = urllib.parse.urlencode({
            'action': 'save', 'enabled': 'true', 'mode': 'iface_tx',
            'limit_gb': '90', 'reset_mode': 'cumulative', 'reset_day': '15', 'calibrate_used_gb': '95',
        }).encode('utf-8')
        code, payload, active, _ = self._call_post(data, body3, counters=counters, active_units=active)
        self.assertEqual(code, 200, payload)
        self.assertTrue(payload['quota']['tripped'])
        self.assertTrue(payload['suspended'])
        self.assertEqual(active, set())

        # 4) 手动清零 action=reset：累计归 0、自动解除本机熔断并拉起服务
        body4 = urllib.parse.urlencode({'action': 'reset'}).encode('utf-8')
        code, payload, active, _ = self._call_post(data, body4, counters=counters, active_units=active)
        self.assertEqual(code, 200, payload)
        self.assertEqual(payload['quota']['used_bytes'], 0)
        self.assertFalse(payload['quota']['tripped'])
        self.assertFalse(payload['suspended'])
        self.assertEqual(active, {'hysteria-server', 'xray'})

        # 5) JSON 格式也同样可用：再次校准超限熔断，然后调高限额恢复
        j1 = json.dumps({'action': 'save', 'enabled': True, 'mode': 'iface_tx', 'limit_gb': 10,
                         'reset_mode': 'cumulative', 'reset_day': 1, 'calibrate_used_gb': 12}).encode('utf-8')
        code, payload, active, _ = self._call_post(
            data, j1, headers={'Content-Length': str(len(j1)), 'Content-Type': 'application/json'},
            counters=counters, active_units=active)
        self.assertEqual(code, 200)
        self.assertTrue(payload['quota']['tripped'])
        self.assertEqual(active, set())

        j2 = json.dumps({'action': 'save', 'enabled': True, 'mode': 'iface_tx', 'limit_gb': 50,
                         'reset_mode': 'cumulative', 'reset_day': 1, 'calibrate_used_gb': ''}).encode('utf-8')
        code, payload, active, _ = self._call_post(
            data, j2, headers={'Content-Length': str(len(j2)), 'Content-Type': 'application/json'},
            counters=counters, active_units=active)
        self.assertEqual(code, 200)
        self.assertFalse(payload['quota']['tripped'])
        self.assertEqual(active, {'hysteria-server', 'xray'})

    def test_cli_merge_refresh_and_adopt_preserve_node_traffic_quota(self):
        """merge_cli_owned_state / refresh / adopt 绝不可清除已配置的 node_traffic_quota 与 traffic_suspend。"""
        quota_cfg = {
            'enabled': True, 'mode': 'iface_tx', 'limit_bytes': 120 * GIB,
            'reset_mode': 'monthly', 'reset_day': 10, 'iface_tx_accum': 45 * GIB,
            'tripped': False,
        }
        susp_cfg = {'suspended': True, 'units': ['hysteria-server'], 'since': 1700000000, 'reasons': ['local_quota']}

        # 1) merge_cli_owned_state
        mem = {'port': 10000, 'api_key': 'old', 'node_traffic_quota': copy.deepcopy(quota_cfg),
               'traffic_suspend': copy.deepcopy(susp_cfg), 'users': {portal.MASTER_USER_ID: {'password': 'p1'}}}
        disk = {'port': 10001, 'api_key': 'new-key', 'users': {portal.MASTER_USER_ID: {'password': 'p2'}}}
        portal.merge_cli_owned_state(mem, disk)
        self.assertEqual(mem['api_key'], 'new-key')
        self.assertEqual(mem['node_traffic_quota'], quota_cfg)
        self.assertEqual(mem['traffic_suspend'], susp_cfg)

        # 2) refresh & adopt 全流程保留
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            meta = {
                'public_ip': '192.0.2.1', 'server_name': 'hy2.example.com', 'listen_port': 27490,
                'auth_password': 'secret-pass', 'obfs_password': 'obfs-secret', 'is_insecure': False,
                'hop_port_range': '20000-40000', 'subscription_port': 11690,
            }
            (root / 'client_meta.json').write_text(json.dumps(meta), encoding='utf-8')
            portal.prepare(root / 'client_meta.json', 28888)
            pfile = root / 'portal.json'
            pdata = json.loads(pfile.read_text(encoding='utf-8'))
            pdata['node_traffic_quota'] = copy.deepcopy(quota_cfg)
            pdata['traffic_suspend'] = copy.deepcopy(susp_cfg)
            pfile.write_text(json.dumps(pdata, ensure_ascii=False), encoding='utf-8')

            with mock.patch.object(portal, 'qr_svg_for', return_value=None):
                portal.refresh(root / 'client_meta.json')
            after_refresh = json.loads(pfile.read_text(encoding='utf-8'))
            self.assertEqual(after_refresh.get('node_traffic_quota'), quota_cfg)
            self.assertEqual(after_refresh.get('traffic_suspend'), susp_cfg)

            with mock.patch.object(portal, 'qr_svg_for', return_value=None), \
                 mock.patch.object(portal, 'restore_egress_into_config', return_value=None):
                portal.adopt(root / 'client_meta.json', 28889)
            after_adopt = json.loads(pfile.read_text(encoding='utf-8'))
            self.assertEqual(after_adopt.get('node_traffic_quota'), quota_cfg)
            self.assertEqual(after_adopt.get('traffic_suspend'), susp_cfg)

    def test_live_http_server_routes_auth_and_traffic_speed_embedding(self):
        """起真实门户进程验证：GET/POST <prefix>node-traffic-quota、traffic-speed 摘要与 /api/v1 隔离。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with socket.socket() as s:
                s.bind(('127.0.0.1', 0))
                port = s.getsockname()[1]
            meta = {
                'public_ip': '192.0.2.9', 'server_name': 'quota.example.com', 'listen_port': 27490,
                'auth_password': 'pw-test-only', 'obfs_password': '', 'is_insecure': False,
                'hop_port_range': '20000-40000', 'subscription_port': 11690,
            }
            (root / 'client_meta.json').write_text(json.dumps(meta), encoding='utf-8')
            portal.prepare(root / 'client_meta.json', port)
            pdata = json.loads((root / 'portal.json').read_text(encoding='utf-8'))
            access = json.loads((root / 'portal-access.json').read_text(encoding='utf-8'))
            prefix = '/' + pdata['token'] + '/'
            basic = 'Basic ' + base64.b64encode(f"{access['username']}:{access['password']}".encode()).decode()
            bearer = 'Bearer ' + pdata['api_key']

            proc = subprocess.Popen(
                [sys.executable, str(ROOT / 'portal.py'), 'serve', str(root / 'portal.json')],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            try:
                for _ in range(80):
                    try:
                        with socket.create_connection(('127.0.0.1', port), 0.1):
                            break
                    except OSError:
                        time.sleep(0.05)
                else:
                    self.fail('真实门户服务未能按时启动')

                def req(method, path, body=None, headers=None):
                    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=8)
                    try:
                        conn.request(method, path, body=body, headers=headers or {})
                        r = conn.getresponse()
                        return r.status, r.read()
                    finally:
                        conn.close()

                # 1) 匿名访问 GET/POST 均返 401；低权限 /api/v1/node-traffic-quota 返 404
                self.assertEqual(req('GET', prefix + 'node-traffic-quota')[0], 401)
                self.assertEqual(req('POST', prefix + 'node-traffic-quota', b'action=reset')[0], 401)
                self.assertEqual(req('GET', '/api/v1/node-traffic-quota', headers={'Authorization': bearer})[0], 404)
                self.assertEqual(req('POST', '/api/v1/node-traffic-quota', b'{}',
                                     headers={'Authorization': bearer, 'Content-Type': 'application/json'})[0], 404)

                # 2) 已鉴权 GET（含查询串）返回 200 及完整摘要
                st, raw = req('GET', prefix + 'node-traffic-quota?t=1', headers={'Authorization': basic})
                self.assertEqual(st, 200, raw)
                j = json.loads(raw)
                self.assertTrue(j['ok'])
                self.assertEqual(j['quota']['mode'], 'iface_tx')
                self.assertEqual(j['quota']['reset_mode'], 'monthly')

                # 3) 已鉴权 POST 保存配置并校准已用流量，随后 traffic-speed 同步返回新摘要
                form = urllib.parse.urlencode({
                    'action': 'save', 'enabled': 'true', 'mode': 'users_total',
                    'limit_gb': '200', 'reset_mode': 'monthly', 'reset_day': '5', 'calibrate_used_gb': '50',
                }).encode('utf-8')
                st, raw = req('POST', prefix + 'node-traffic-quota', form, headers={
                    'Authorization': basic, 'Content-Type': 'application/x-www-form-urlencoded'})
                self.assertEqual(st, 200, raw)
                pj = json.loads(raw)
                self.assertTrue(pj['ok'])
                self.assertEqual(pj['quota']['used_bytes'], 50 * GIB)
                self.assertEqual(pj['quota']['percent'], 25.0)

                st, raw = req('GET', prefix + 'traffic-speed', headers={'Authorization': basic})
                self.assertEqual(st, 200, raw)
                sj = json.loads(raw)
                self.assertIn('node_traffic_quota', sj)
                self.assertEqual(sj['node_traffic_quota']['used_bytes'], 50 * GIB)
                self.assertEqual(sj['node_traffic_quota']['limit_bytes'], 200 * GIB)
                self.assertEqual(sj['node_traffic_quota']['mode'], 'users_total')
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()


class FrontendQuotaUiAndCspTests(unittest.TestCase):
    """前端 HTML、无裸花括号、CSP 哈希、登录页隔离以及 Node 真实脚本交互验证。"""

    def test_html_has_quota_card_banner_no_braces_no_inline_handlers_and_login_no_leak(self):
        meta = {
            'public_ip': '192.0.2.1', 'server_name': 'hy2.example.com', 'listen_port': 27490,
            'auth_password': 'pw', 'obfs_password': '', 'is_insecure': False,
            'hop_port_range': '20000-40000', 'subscription_port': 11690,
        }
        page = portal.page_html(meta, 'hysteria2://pw@hy2.example.com:27490/', '#s', 'c', '{}',
                                users={}, api_key='k', token='tok', session_secret='sec',
                                username='u', password='p')
        html_part = page.split('<script', 1)[0]
        # 无裸 Python f-string 花括号
        self.assertEqual(re.findall(r'\{[A-Za-z_][A-Za-z0-9_]*\}', html_part), [])
        # 无内联事件处理器（CSP 红线）
        self.assertIsNone(re.search(r'\son(?:click|change|submit|input)\s*=', html_part, re.I))
        # 必需 DOM 节点齐全
        for eid in ('node-quota-alert-banner', 'btn-quota-banner-goto', 'node-quota-header-badge',
                    'node-quota-card', 'nq-progress-bar', 'nq-enabled', 'nq-limit-gb',
                    'nq-mode', 'nq-reset-mode', 'nq-reset-day', 'nq-calibrate-gb',
                    'btn-nq-save', 'btn-nq-reset'):
            self.assertIn(f'id="{eid}"', html_part, f'首页缺少必要节点 id={eid}')

        # CSP 哈希必须覆盖 SCRIPT 且不允许 unsafe-inline
        policy = portal.content_policy()
        digest = base64.b64encode(hashlib.sha256(portal.SCRIPT.encode()).digest()).decode()
        self.assertIn('sha256-' + digest, policy)
        self.assertNotIn('unsafe-inline', policy.split('script-src', 1)[1].split(';', 1)[0])

        # 未登录页绝不泄露节点总流量限额卡片或配置标识
        login_page = portal.login_html('tok')
        for secret_id in ('node-quota-card', 'node-traffic-quota', 'node-quota-alert-banner'):
            self.assertNotIn(secret_id, login_page)

    @unittest.skipUnless(NODE, 'requires node')
    def test_real_portal_script_renders_polling_banner_save_and_reset(self):
        """在 Node 中执行整份真实 portal.SCRIPT，验证轮询更新、横幅跳转、表单保存与清零确认。"""
        after = r"""
async ctx => {
  const posted = [];
  let currentQuota = {
    enabled: true, mode: 'iface_tx', mode_label: '物理出口网卡（仅出站）',
    limit_bytes: 100 * 1073741824, limit_gb: 100, used_bytes: 100 * 1073741824,
    percent: 100.0, remaining_bytes: 0, reset_mode: 'monthly', reset_day: 15,
    next_reset_text: '2026-12-15 00:00 UTC', interfaces: ['ens4'],
    tripped: true, tripped_at: 1763200000, suspended: true,
    suspend_reasons: ['local_quota'], controller_suspended: false,
  };
  ctx.setRespond(async (url, init) => {
    const method = (init && init.method) || 'GET';
    if (url.endsWith('traffic-speed')) {
      return new Response(JSON.stringify({
        ok: true, node_tx: 0, node_rx: 0, users: {}, total_used_bytes: 0,
        node_traffic_quota: currentQuota,
      }), {status: 200});
    }
    if (url.endsWith('node-traffic-quota') && method === 'GET') {
      return new Response(JSON.stringify({ok: true, quota: currentQuota}), {status: 200});
    }
    if (url.endsWith('node-traffic-quota') && method === 'POST') {
      posted.push(String(init.body || ''));
      const params = new URLSearchParams(String(init.body || ''));
      if (params.get('action') === 'reset') {
        currentQuota = Object.assign({}, currentQuota, {used_bytes: 0, percent: 0, tripped: false, suspended: false, suspend_reasons: []});
      } else {
        currentQuota = Object.assign({}, currentQuota, {
          enabled: params.get('enabled') === 'true',
          limit_gb: Number(params.get('limit_gb') || 0),
          limit_bytes: Number(params.get('limit_gb') || 0) * 1073741824,
          reset_mode: params.get('reset_mode') || 'monthly',
          used_bytes: 20 * 1073741824, percent: 10.0, tripped: false, suspended: false,
        });
      }
      return new Response(JSON.stringify({ok: true, message: '操作成功', quota: currentQuota}), {status: 200});
    }
    return new Response(JSON.stringify({ok: true}), {status: 200});
  });

  // 触发一次限额加载与轮询刷新，确认红色横幅、徽章、进度条立即渲染
  await ctx.sandbox.loadNodeQuota(true);
  await ctx.sandbox.pollTrafficSpeed();
  const trippedView = {
    bannerDisplay: ctx.els['node-quota-alert-banner'].style.display,
    badgeText: ctx.els['node-quota-header-badge'].textContent,
    progressWidth: ctx.els['nq-progress-bar'].style.width,
    ifacesText: ctx.els['nq-meta-ifaces'].textContent,
  };

  // 点击顶部红色横幅跳转按钮应切到 users 页签
  ctx.els['btn-quota-banner-goto'].click();
  await ctx.tick();
  const tabAfterGoto = ctx.state().tab;

  // 切换为累计模式时隐藏账单日输入框；即使旧账单日框里残留非法值 99，保存也不得附带脏 reset_day
  ctx.els['nq-reset-day'].value = '99';
  ctx.els['nq-reset-mode'].value = 'cumulative';
  ctx.els['nq-reset-mode'].dispatch('change');
  const dayHiddenWhenCumulative = ctx.els['nq-reset-day-wrap'].style.display;

  // 修改表单并点击保存（含校准值），保存后校准框应自动清空且熔断横幅消失
  ctx.els['nq-enabled'].checked = true;
  ctx.els['nq-limit-gb'].value = '200';
  ctx.els['nq-calibrate-gb'].value = '20';
  ctx.els['btn-nq-save'].click();
  await ctx.tick();
  const afterSave = {
    calibrateAfter: ctx.els['nq-calibrate-gb'].value,
    bannerDisplay: ctx.els['node-quota-alert-banner'].style.display,
    badgeText: ctx.els['node-quota-header-badge'].textContent,
  };

  // 点击清零（模拟确认框确认）：发送 action=reset 并归零
  ctx.sandbox.showConfirm = async () => true;
  ctx.els['btn-nq-reset'].click();
  await ctx.tick();
  const afterReset = {
    progressWidth: ctx.els['nq-progress-bar'].style.width,
    posted,
  };

  // 验证「刷新状态」按钮在 500 服务端错误与 401 登录过期时如实报红，绝不谎报成功
  ctx.setRespond(async () => new Response(JSON.stringify({ok: false, error: '后端读取超时'}), {status: 500}));
  ctx.els['btn-nq-refresh'].click();
  await ctx.tick();
  const refresh500 = {text: ctx.els['nq-msg'].textContent, cls: ctx.els['nq-msg'].className};

  ctx.setRespond(async () => new Response('Authentication required', {status: 401}));
  ctx.els['btn-nq-refresh'].click();
  await ctx.tick();
  const refresh401 = {text: ctx.els['nq-msg'].textContent, cls: ctx.els['nq-msg'].className};

  return {trippedView, tabAfterGoto, dayHiddenWhenCumulative, afterSave, afterReset, refresh500, refresh401};
}
"""
        report = run_portal_page(page_model(), '', after=after)
        self.assertEqual(report['errors'], [], report['errors'])
        out = report['after']
        self.assertEqual(out['trippedView']['bannerDisplay'], 'flex')
        self.assertIn('已熔断停服', out['trippedView']['badgeText'])
        self.assertEqual(out['trippedView']['progressWidth'], '100%')
        self.assertEqual(out['trippedView']['ifacesText'], 'ens4')
        self.assertEqual(out['tabAfterGoto'], ['pane-users'])
        self.assertEqual(out['dayHiddenWhenCumulative'], 'none')
        self.assertEqual(out['afterSave']['calibrateAfter'], '')
        self.assertEqual(out['afterSave']['bannerDisplay'], 'none')
        self.assertIn('200', out['afterSave']['badgeText'])
        self.assertEqual(out['afterReset']['progressWidth'], '0%')
        self.assertEqual(len(out['afterReset']['posted']), 2)
        self.assertIn('action=save', out['afterReset']['posted'][0])
        self.assertNotIn('reset_day=', out['afterReset']['posted'][0])
        self.assertIn('action=reset', out['afterReset']['posted'][1])
        self.assertIn('err', out['refresh500']['cls'])
        self.assertIn('后端读取超时', out['refresh500']['text'])
        self.assertIn('err', out['refresh401']['cls'])
        self.assertIn('登录已过期', out['refresh401']['text'])


if __name__ == '__main__':
    unittest.main()
