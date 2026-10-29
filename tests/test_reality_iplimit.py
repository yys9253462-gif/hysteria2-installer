import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal

spec = importlib.util.spec_from_file_location('xcfg', ROOT / 'usage-meter-xray-config-20261007-v1.py')
xcfg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(xcfg)


def plan(limits, reality, hy2, state, now):
    return portal.plan_reality_iplimit(limits, reality, hy2, state, now)


class PlanTests(unittest.TestCase):
    def test_first_come_first_served_within_limit(self):
        state = {}
        self.assertEqual(plan({'u': 2}, {'u': {'1.1.1.1'}}, {}, state, 100), {})
        self.assertEqual(plan({'u': 2}, {'u': {'1.1.1.1', '2.2.2.2'}}, {}, state, 105), {})
        blocked = plan({'u': 2}, {'u': {'1.1.1.1', '2.2.2.2', '3.3.3.3'}}, {}, state, 110)
        self.assertEqual(blocked, {'u': {'3.3.3.3'}})

    def test_hy2_ips_share_the_same_quota(self):
        state = {}
        blocked = plan({'u': 2}, {'u': {'3.3.3.3'}}, {'u': {'1.1.1.1', '2.2.2.2'}}, state, 100)
        self.assertEqual(blocked, {'u': {'3.3.3.3'}})
        # 同一个 IP 同时走两个协议只算一台
        self.assertEqual(plan({'u': 2}, {'u': {'1.1.1.1'}}, {'u': {'1.1.1.1', '2.2.2.2'}}, {}, 100), {})

    def test_blocked_ip_does_not_flap_while_still_connected(self):
        state = {}
        plan({'u': 1}, {'u': {'1.1.1.1'}}, {}, state, 100)
        for t in range(105, 400, 5):
            self.assertEqual(plan({'u': 1}, {'u': {'1.1.1.1', '2.2.2.2'}}, {}, state, t), {'u': {'2.2.2.2'}})

    def test_admitted_ip_released_after_grace_then_waiter_admitted(self):
        state = {}
        plan({'u': 1}, {'u': {'1.1.1.1'}}, {}, state, 100)
        plan({'u': 1}, {'u': {'1.1.1.1', '2.2.2.2'}}, {}, state, 105)
        # 1.1.1.1 断开；宽限期内 2.2.2.2 仍被拦
        self.assertEqual(plan({'u': 1}, {'u': {'2.2.2.2'}}, {}, state, 200), {'u': {'2.2.2.2'}})
        # 超过 180 秒后放行
        self.assertEqual(plan({'u': 1}, {'u': {'2.2.2.2'}}, {}, state, 110 + 180), {})
        self.assertIn('2.2.2.2', state['u']['admitted'])

    def test_longest_waiting_blocked_ip_wins_free_slot(self):
        state = {}
        plan({'u': 1}, {'u': {'1.1.1.1'}}, {}, state, 100)
        plan({'u': 1}, {'u': {'1.1.1.1', '9.9.9.9'}}, {}, state, 105)
        plan({'u': 1}, {'u': {'1.1.1.1', '9.9.9.9', '2.2.2.2'}}, {}, state, 110)
        blocked = plan({'u': 1}, {'u': {'9.9.9.9', '2.2.2.2'}}, {}, state, 400)
        self.assertEqual(blocked, {'u': {'2.2.2.2'}})

    def test_users_without_limit_are_dropped(self):
        state = {'gone': {'admitted': {'1.1.1.1': 1}, 'blocked': {}}}
        plan({}, {'gone': {'1.1.1.1'}}, {}, state, 100)
        self.assertEqual(state, {})


class RuleTests(unittest.TestCase):
    def test_tag_changes_with_ip_set_and_is_stable(self):
        a = portal.reality_iplimit_rules({'u': {'2.2.2.2', '3.3.3.3'}})
        b = portal.reality_iplimit_rules({'u': {'3.3.3.3', '2.2.2.2'}})
        c = portal.reality_iplimit_rules({'u': {'2.2.2.2'}})
        self.assertEqual(a, b)
        self.assertNotEqual(set(a), set(c))
        rule = next(iter(a.values()))
        self.assertEqual(rule['user'], ['u'])
        self.assertEqual(rule['source'], ['2.2.2.2', '3.3.3.3'])
        self.assertEqual(rule['outboundTag'], 'iplimit-block')
        self.assertTrue(rule['ruleTag'].startswith('iplimit-'))


class FakeXray:
    def __init__(self, tags=(), fail=None):
        self.tags = list(tags)
        self.fail = fail
        self.calls = []
        self.added = []

    def __call__(self, args, **kwargs):
        verb = args[2]
        self.calls.append(verb)
        if verb == self.fail:
            return subprocess.CompletedProcess(args, 1, '', 'boom')
        if verb == 'lsrules':
            rules = [{'tag': 'usage-meter-api'}] + [{'ruleTag': t, 'tag': 'iplimit-block'} for t in self.tags]
            return subprocess.CompletedProcess(args, 0, json.dumps({'rules': rules}), '')
        if verb == 'adrules':
            self.assertAppend(args)
            doc = json.loads(Path(args[-1]).read_text(encoding='utf-8'))
            for r in doc['routing']['rules']:
                self.tags.append(r['ruleTag'])
                self.added.append(r)
            return subprocess.CompletedProcess(args, 0, '{}', '')
        if verb == 'rmrules':
            self.tags = [t for t in self.tags if t not in args[4:]]
            return subprocess.CompletedProcess(args, 0, '{}', '')
        raise AssertionError(verb)

    @staticmethod
    def assertAppend(args):
        # 不带 -append 会替换掉全部路由规则，包括计量 API 的那条
        if '-append' not in args:
            raise AssertionError('adrules must use -append')


class ApplyTests(unittest.TestCase):
    def test_adds_missing_then_removes_stale(self):
        fake = FakeXray(tags=['iplimit-old', 'other-rule'])
        desired = portal.reality_iplimit_rules({'u': {'2.2.2.2'}})
        added, removed = portal.apply_reality_iplimit('/x', '127.0.0.1:1', desired, run=fake)
        self.assertEqual((added, removed), (1, 1))
        self.assertEqual(fake.calls, ['lsrules', 'adrules', 'rmrules'])
        self.assertEqual(sorted(fake.tags), sorted(['other-rule'] + list(desired)))

    def test_noop_when_in_sync(self):
        desired = portal.reality_iplimit_rules({'u': {'2.2.2.2'}})
        fake = FakeXray(tags=list(desired))
        self.assertEqual(portal.apply_reality_iplimit('/x', '127.0.0.1:1', desired, run=fake), (0, 0))
        self.assertEqual(fake.calls, ['lsrules'])

    def test_failures_raise(self):
        for verb in ('lsrules', 'adrules'):
            with self.assertRaises(RuntimeError):
                portal.apply_reality_iplimit('/x', '127.0.0.1:1',
                                             portal.reality_iplimit_rules({'u': {'2.2.2.2'}}),
                                             run=FakeXray(fail=verb))

    def test_rejects_non_loopback(self):
        with self.assertRaises(ValueError):
            portal.apply_reality_iplimit('/x', '0.0.0.0:1', {}, run=FakeXray())


class ReadTests(unittest.TestCase):
    def test_reads_only_requested_online_users(self):
        calls = []

        def run(args, **kwargs):
            calls.append(args[2:])
            if args[2] == 'statsgetallonlineusers':
                return subprocess.CompletedProcess(args, 0, json.dumps(
                    {'users': ['user>>>a>>>online', 'user>>>b>>>online']}), '')
            return subprocess.CompletedProcess(args, 0, json.dumps({'ips': {'2001:db8::0001': 1, '1.1.1.1': 2}}), '')

        got = portal.read_reality_online_ips('/x', '127.0.0.1:1', {'a': 5, 'c': 5}, run=run)
        self.assertEqual(got, {'a': {'2001:db8::1', '1.1.1.1'}})
        self.assertEqual(len(calls), 2)

    def test_failure_raises(self):
        run = lambda args, **kw: subprocess.CompletedProcess(args, 1, '', 'x')
        with self.assertRaises(RuntimeError):
            portal.read_reality_online_ips('/x', '127.0.0.1:1', {'a': 1}, run=run)


class XrayConfigTests(unittest.TestCase):
    base = {
        'api': {'tag': 'usage-meter-api', 'services': ['StatsService']},
        'inbounds': [{'tag': 'vless-reality-in', 'protocol': 'vless',
                      'settings': {'clients': [{'id': 'x', 'email': 'u'}]}}],
        'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}],
        'routing': {'rules': []},
    }

    def test_add_iplimit_routing_idempotent_and_keeps_default_outbound(self):
        cfg = json.loads(json.dumps(self.base))
        xcfg.add_iplimit_routing(cfg)
        xcfg.add_iplimit_routing(cfg)
        self.assertEqual(cfg['api']['services'], ['StatsService', 'RoutingService'])
        self.assertEqual([o['tag'] for o in cfg['outbounds']], ['direct', 'iplimit-block'])
        self.assertFalse(xcfg.iplimit_routing_ready(cfg))
        self.assertTrue(xcfg.api_rule_first(cfg))
        self.assertTrue(xcfg.iplimit_routing_ready(cfg))
        self.assertFalse(xcfg.iplimit_routing_ready(self.base))

    def test_add_iplimit_routing_repairs_freedom_tag_and_preserves_other_config(self):
        for managed_is_default in (False, True):
            with self.subTest(managed_is_default=managed_is_default):
                cfg = json.loads(json.dumps(self.base))
                managed = {'protocol': 'freedom', 'tag': 'iplimit-block',
                           'settings': {'domainStrategy': 'UseIPv4'},
                           'sendThrough': '192.0.2.1'}
                proxy = {'protocol': 'socks', 'tag': 'proxy',
                         'settings': {'servers': [{'address': '127.0.0.1', 'port': 1080}]}}
                cfg['outbounds'] = ([managed, proxy] if managed_is_default else
                                    cfg['outbounds'] + [managed, proxy])
                cfg['api']['services'].append('HandlerService')
                cfg['routing']['rules'] = [json.loads(json.dumps(xcfg.API_RULE)),
                                          {'type': 'field', 'domain': ['example.com'],
                                           'outboundTag': 'proxy'}]
                original = json.loads(json.dumps(cfg))
                self.assertFalse(xcfg.iplimit_routing_ready(cfg))

                xcfg.add_iplimit_routing(cfg)

                self.assertTrue(xcfg.iplimit_routing_ready(cfg))
                self.assertEqual([o for o in cfg['outbounds'] if o.get('tag') == 'iplimit-block'],
                                 [{'protocol': 'blackhole', 'tag': 'iplimit-block'}])
                expected_default = dict(original['outbounds'][0])
                if managed_is_default:
                    expected_default.pop('tag')
                self.assertEqual(cfg['outbounds'][0], expected_default)
                self.assertEqual([o for o in cfg['outbounds'] if o.get('tag') == 'proxy'], [proxy])
                self.assertEqual(cfg['inbounds'], original['inbounds'])
                self.assertEqual(cfg['routing'], original['routing'])
                self.assertEqual(cfg['api']['services'],
                                 ['StatsService', 'HandlerService', 'RoutingService'])
                repaired = json.loads(json.dumps(cfg))
                xcfg.add_iplimit_routing(cfg)
                self.assertEqual(cfg, repaired)

    def test_enable_repairs_freedom_tag_once_without_repeated_restart(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'xray.json'
            cfg = json.loads(json.dumps(self.base))
            cfg['api']['services'].append('RoutingService')
            cfg['routing']['rules'] = [json.loads(json.dumps(xcfg.API_RULE))]
            cfg['outbounds'].append({'protocol': 'freedom', 'tag': 'iplimit-block'})
            path.write_text(json.dumps(cfg), encoding='utf-8')
            with patch.object(xcfg.subprocess, 'run',
                              return_value=subprocess.CompletedProcess([], 0)) as run:
                result = xcfg.enable_iplimit_routing(str(path), '/x', '127.0.0.1:1')
                self.assertTrue(result['changed'])
                self.assertEqual(sum(call.args[0] == ['systemctl', 'restart', 'xray']
                                     for call in run.call_args_list), 1)
                self.assertEqual(Path(result['backup']).read_text(encoding='utf-8'), json.dumps(cfg))
                saved = path.read_bytes()
                run.reset_mock()
                result = xcfg.enable_iplimit_routing(str(path), '/x', '127.0.0.1:1')
                self.assertFalse(result['changed'])
                run.assert_not_called()
                self.assertEqual(path.read_bytes(), saved)
            self.assertTrue(xcfg.iplimit_routing_ready(json.loads(saved)))

    def test_add_stats_preserves_existing_api_services(self):
        cfg = json.loads(json.dumps(self.base))
        cfg['api']['services'].append('HandlerService')
        out = xcfg.add_stats(cfg, 19997)
        self.assertEqual(out['api']['services'], ['StatsService', 'HandlerService', 'RoutingService'])
        self.assertEqual(cfg['api']['services'], ['StatsService', 'HandlerService'])

    def test_add_stats_includes_routing(self):
        cfg = {'inbounds': [{'tag': 'vless-reality-in', 'protocol': 'vless', 'port': 443,
                             'settings': {'clients': []}}],
               'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}]}
        out = xcfg.add_stats(cfg, 19997)
        self.assertTrue(xcfg.iplimit_routing_ready(out))

    def test_enable_skips_restart_when_ready(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'xray.json'
            cfg = xcfg.add_iplimit_routing(json.loads(json.dumps(self.base)))
            xcfg.api_rule_first(cfg)
            path.write_text(json.dumps(cfg), encoding='utf-8')
            with patch.object(xcfg.subprocess, 'run', side_effect=AssertionError('no restart')):
                self.assertFalse(xcfg.enable_iplimit_routing(str(path), '/x', '127.0.0.1:1')['changed'])

    def test_enable_installs_missing_api_route(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'xray.json'
            cfg = xcfg.add_iplimit_routing(json.loads(json.dumps(self.base)))
            path.write_text(json.dumps(cfg), encoding='utf-8')
            with patch.object(xcfg.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
                result = xcfg.enable_iplimit_routing(str(path), '/x', '127.0.0.1:1')
            self.assertTrue(result['changed'])
            self.assertTrue(xcfg.iplimit_routing_ready(json.loads(path.read_text(encoding='utf-8'))))

    def test_enable_restores_on_failed_restart(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'xray.json'
            original = json.dumps(self.base)
            path.write_text(original, encoding='utf-8')

            def run(args, **kwargs):
                if args[:2] == ['systemctl', 'restart'] and run.restarts == 0:
                    run.restarts += 1
                    raise subprocess.CalledProcessError(1, args)
                return subprocess.CompletedProcess(args, 0, '', '')
            run.restarts = 0
            with patch.object(xcfg.subprocess, 'run', side_effect=run):
                with self.assertRaises(subprocess.CalledProcessError):
                    xcfg.enable_iplimit_routing(str(path), '/x', '127.0.0.1:1')
            self.assertEqual(path.read_text(encoding='utf-8'), original)


if __name__ == '__main__':
    unittest.main()
