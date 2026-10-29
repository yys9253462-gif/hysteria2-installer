"""计量方向与缺口窗口（2026-10-29 修复）。

两条都是「静默错」而不是「崩掉」的问题：
  * Xray 的 uplink/downlink 曾映射反了，界面上下行互换但总量不受影响；
  * gaps 从不按时间失效，重启一次之后 measurement_ok 永久为 false。
"""
import importlib.util
import json
import sys
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _load(name):
    spec = importlib.util.spec_from_file_location(name + '_t', ROOT / name)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class XrayDirectionTests(unittest.TestCase):
    def setUp(self):
        self.readers = _load('usage-meter-readers-20261007-v1.py')

    def test_uplink_is_tx_and_downlink_is_rx(self):
        """tx = 上行（客户端→服务端），rx = 下行 —— 与 Hysteria 的语义一致。

        Hysteria 的 core/server 在 ReceiveDatagram（上行）记 tx、
        SendMessage（下行）记 rx；界面把 rx 标为「下行 Download」。
        """
        raw = json.dumps({'stat': [
            {'name': 'user>>>u1>>>traffic>>>uplink', 'value': 111},
            {'name': 'user>>>u1>>>traffic>>>downlink', 'value': 999},
        ]})
        self.assertEqual(self.readers.parse_xray(raw),
                         {'u1': {'tx': 111, 'rx': 999}})


class XrayDuplicateStatTests(unittest.TestCase):
    def setUp(self):
        self.readers = _load('usage-meter-readers-20261007-v1.py')

    def test_duplicate_zero_entries_are_rejected(self):
        """两条同为 0 的重复统计也必须报错（旧实现只拦非零重复）。"""
        raw = json.dumps({'stat': [
            {'name': 'user>>>u1>>>traffic>>>uplink', 'value': 0},
            {'name': 'user>>>u1>>>traffic>>>uplink', 'value': 0},
        ]})
        with self.assertRaises(ValueError):
            self.readers.parse_xray(raw)

    def test_distinct_users_are_fine(self):
        raw = json.dumps({'stat': [
            {'name': 'user>>>u1>>>traffic>>>uplink', 'value': 0},
            {'name': 'user>>>u2>>>traffic>>>uplink', 'value': 0},
        ]})
        self.assertEqual(self.readers.parse_xray(raw),
                         {'u1': {'tx': 0, 'rx': 0}, 'u2': {'tx': 0, 'rx': 0}})


class GapWindowTests(unittest.TestCase):
    def setUp(self):
        self.runtime = _load('usage-meter-runtime-20261007-v1.py')

    def _gap(self, hours_ago):
        when = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
        return {'source': 'hysteria', 'at': when.isoformat(),
                'reason': 'service_restart_unsampled_tail_unknown'}

    def test_old_gap_does_not_count_as_recent(self):
        meter = {'gaps': [self._gap(48)]}
        self.assertEqual(self.runtime._recent_gaps(meter), [])

    def test_recent_gap_counts(self):
        meter = {'gaps': [self._gap(1)]}
        self.assertEqual(len(self.runtime._recent_gaps(meter)), 1)

    def test_undated_gap_is_treated_conservatively(self):
        """没有时间戳的条目按「最近」处理：宁可报异常，也不要谎报健康。"""
        meter = {'gaps': [{'from': 1, 'to': 2}]}
        self.assertEqual(len(self.runtime._recent_gaps(meter)), 1)

    def test_mixed_gaps_only_recent_survive(self):
        meter = {'gaps': [self._gap(72), self._gap(0)]}
        self.assertEqual(len(self.runtime._recent_gaps(meter)), 1)


class CorruptMeterStateTests(unittest.TestCase):
    """残缺的 usage_meter 状态不能让计量永久失效（2026-10-29 修复）。"""

    def setUp(self):
        self.core = _load('usage-meter-core-20261007-v1.py')

    def test_missing_counters_resets_to_baseline(self):
        state = {'sources': {'hysteria': {'epoch': 'E1'}}}  # 缺 counters
        out = self.core.apply_sample(state, 'hysteria', 'E2',
                                     {'u1': {'tx': 10, 'rx': 20}},
                                     '2026-10-29T00:00:00+00:00')
        self.assertEqual(out['deltas'], {})          # 首次基线，不谎报增量
        self.assertEqual(state['sources']['hysteria']['epoch'], 'E2')
        self.assertIn('corrupt_state_reset',
                      [g['reason'] for g in state['gaps']])

    def test_missing_epoch_also_resets(self):
        state = {'sources': {'hysteria': {'counters': {'u1': {'tx': 1, 'rx': 1}}}}}
        self.core.apply_sample(state, 'hysteria', 'E2', {}, '2026-10-29T00:00:00+00:00')
        self.assertEqual(state['sources']['hysteria']['epoch'], 'E2')

    def test_corrupt_previous_type_does_not_raise(self):
        state = {'sources': {'hysteria': 'garbage'}}
        self.core.apply_sample(state, 'hysteria', 'E2', {}, '2026-10-29T00:00:00+00:00')
        self.assertEqual(state['sources']['hysteria']['epoch'], 'E2')


class SourceFreshTests(unittest.TestCase):
    def setUp(self):
        self.runtime = _load('usage-meter-runtime-20261007-v1.py')

    def test_missing_or_bad_timestamp_is_not_fresh(self):
        for entry in ({}, {'ok': True}, {'ok': True, 'sampled_at': ''},
                      {'ok': True, 'sampled_at': 'not-a-date'}, 'garbage'):
            with self.subTest(entry=entry):
                self.assertFalse(self.runtime._source_fresh({'hysteria': entry}, 'hysteria'))

    def test_ok_and_recent_is_fresh(self):
        now = datetime.now(timezone.utc).isoformat()
        self.assertTrue(self.runtime._source_fresh(
            {'hysteria': {'ok': True, 'sampled_at': now}}, 'hysteria'))


class AwgEndpointRenderTests(unittest.TestCase):
    """Endpoint 已带端口时不能再拼一次（awgctl.sh）。"""

    def test_endpoint_rendering(self):
        import subprocess
        script = r'''
        source <(sed -n "/^endpoint_has_port()/,/^}/p" awgctl.sh)
        for e in "vpn.example.com" "vpn.example.com:51820" "[::1]:51820" "[::1]"; do
            if endpoint_has_port "$e"; then echo "$e|$e"; else echo "$e|$e:54321"; fi
        done
        '''
        # 用 stdin 传脚本：Windows 上 `bash -c <多行脚本>` 会把 $var 吃掉，
        # 导致测试本身假失败（实测）。
        out = subprocess.run(['bash'], input=script.encode('utf-8'), cwd=str(ROOT),
                             capture_output=True, timeout=30).stdout.decode('utf-8', 'replace')
        rows = dict(line.split('|') for line in out.strip().splitlines())
        self.assertEqual(rows['vpn.example.com'], 'vpn.example.com:54321')
        self.assertEqual(rows['vpn.example.com:51820'], 'vpn.example.com:51820')
        self.assertEqual(rows['[::1]:51820'], '[::1]:51820')
        self.assertEqual(rows['[::1]'], '[::1]:54321')


if __name__ == '__main__':
    unittest.main()
