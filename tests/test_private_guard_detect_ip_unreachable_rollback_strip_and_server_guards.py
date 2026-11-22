"""回归测试：Xray 内网黑洞首位防护与规则去重、出口 IP 拒绝整型假地址、不可达探测参数守卫、回滚超时隔离、出站剥离段限定及服务器死线封顶。"""

import ast
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
PORTAL_TREE = ast.parse(PORTAL_SRC)


def _fn_src(name: str) -> str:
    for node in ast.walk(PORTAL_TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(PORTAL_SRC, node)
    raise AssertionError(f'未找到函数 {name}')


class PrivateGuardDetectIpUnreachableRollbackStripAndServerGuardsTests(unittest.TestCase):
    def test_add_private_network_guard_moves_blackhole_off_first_slot_and_dedups_stale_rules(self):
        """block-private 误放首位时必须补自由出站并将黑洞挪至末尾，且旧版不完整黑洞规则应去重替换。"""
        cfg = {
            'outbounds': [
                {'protocol': 'blackhole', 'tag': portal.XRAY_BLOCK_OUTBOUND_TAG},
                'corrupt_item',
                {'protocol': 'blackhole', 'tag': portal.XRAY_BLOCK_OUTBOUND_TAG},
            ],
            'routing': {
                'rules': [
                    {'type': 'field', 'ip': ['127.0.0.0/8'], 'outboundTag': portal.XRAY_BLOCK_OUTBOUND_TAG},
                    {'type': 'field', 'domain': ['example.com'], 'outboundTag': 'direct'},
                ],
            },
        }
        portal.add_private_network_guard(cfg)
        self.assertEqual(cfg['outbounds'][0]['protocol'], 'freedom', '首位绝不能是 blackhole 吞掉正常流量')
        block_outs = [o for o in cfg['outbounds'] if isinstance(o, dict) and o.get('tag') == portal.XRAY_BLOCK_OUTBOUND_TAG]
        self.assertEqual(len(block_outs), 1, 'block-private 出站必须唯一')
        self.assertEqual(cfg['outbounds'][-1]['tag'], portal.XRAY_BLOCK_OUTBOUND_TAG)
        block_rules = [r for r in cfg['routing']['rules'] if isinstance(r, dict) and r.get('outboundTag') == portal.XRAY_BLOCK_OUTBOUND_TAG]
        self.assertEqual(len(block_rules), 1, '旧版不完整内网黑洞规则应被替换去重')
        self.assertEqual(block_rules[0]['ip'], list(portal.XRAY_PRIVATE_REJECT_IPS))

    def test_detect_outbound_ip_rejects_int_json_ip_and_non_str_addr(self):
        """detect_outbound_ip 面对 {"ip": 123} 不得返回 0.0.0.123，面对非字符串 addr 须直接返回空串。"""
        self.assertEqual(portal.detect_outbound_ip('socks5', ['1.2.3.4:1080']), '')
        self.assertEqual(portal.detect_outbound_ip('http', 12345), '')

        fake_proc = subprocess.CompletedProcess(['curl'], 0, stdout='{"ip": 123}\n', stderr='')
        with mock.patch.object(portal.subprocess, 'run', return_value=fake_proc):
            self.assertEqual(portal.detect_outbound_ip('auto'), '', '整型 JSON ip 不得被 ipaddress 转成 0.0.0.123')

        src = _fn_src('detect_outbound_ip')
        self.assertIn("'errors': 'replace'", src)

    def test_unreachable_outbounds_guards_container_timeout_and_huge_port(self):
        """_unreachable_outbounds 面对非列表 outs、非有限/布尔 timeout 与超长/前导零端口不得误判或崩。"""
        self.assertEqual(portal._unreachable_outbounds('not-a-list'), [])
        self.assertEqual(portal._unreachable_outbounds({'a': 1}), [])

        called = []

        def fake_conn(addr, timeout=None):
            called.append((addr, timeout))
            return mock.MagicMock()

        outs = [
            {'name': 'bad_huge', 'type': 'socks5', 'addr': '1.2.3.4:' + '9' * 5000},
            {'name': 'bad_lead0', 'type': 'socks5', 'addr': '1.2.3.4:01080'},
            {'name': 'good_s5', 'type': 'socks5', 'addr': '1.2.3.4:1080'},
        ]
        with mock.patch.object(portal.socket, 'create_connection', side_effect=fake_conn):
            dead = portal._unreachable_outbounds(outs, timeout=float('nan'))
        self.assertEqual(dead, [])
        self.assertEqual(called, [(('1.2.3.4', 1080), 2.0)])

    def test_rollback_outbounds_guards_non_str_original_and_isolates_single_poll_timeout(self):
        """_rollback_outbounds 拒非字符串 original，且单次 is-active 超时不应放弃后续轮询。"""
        self.assertEqual(portal._rollback_outbounds('/tmp/unused', None), 'unknown')
        calls = {'n': 0}

        def fake_run(cmd, **kw):
            calls['n'] += 1
            if calls['n'] == 1:
                raise subprocess.TimeoutExpired(cmd, 8)
            return subprocess.CompletedProcess(cmd, 0, stdout='active\n', stderr='')

        with mock.patch.object(portal, 'atomic_write_private'), \
             mock.patch.object(portal, '_restart_hy2'), \
             mock.patch.object(portal.time, 'sleep'), \
             mock.patch.object(portal.subprocess, 'run', side_effect=fake_run):
            state = portal._rollback_outbounds('/tmp/unused', 'listen: :443\n')
        self.assertEqual(state, 'active')
        self.assertEqual(calls['n'], 2)

    def test_strip_managed_outbounds_only_strips_inside_outbounds_section(self):
        """strip_managed_outbounds 只能删顶层 outbounds: 段内的自定义出站，绝不误删其它段的 - name:。"""
        cfg = (
            "inbounds:\n"
            "  - name: keep_me\n"
            "    type: something\n"
            "outbounds:\n"
            "  - name: direct_ipv4\n"
            "    type: direct\n"
            "  - name: custom_s5\n"
            "    type: socks5\n"
            "    socks5:\n"
            "      addr: 1.2.3.4:1080\n"
            "acl:\n"
            "  inline:\n"
            "    - direct(all)\n"
        )
        stripped = portal.strip_managed_outbounds(cfg)
        self.assertIn('  - name: keep_me', stripped)
        self.assertIn('  - name: direct_ipv4', stripped)
        self.assertNotIn('custom_s5', stripped)

    def test_threading_server_caps_deadline_and_releases_slots_on_base_exception(self):
        """ThreadingHTTPServer.extend_deadline 须封顶秒数，process_request 须在 BaseException 时归还信号量。"""
        ext_src = _fn_src('extend_deadline')
        self.assertIn('3600', ext_src)
        pr_src = _fn_src('process_request')
        self.assertIn('except BaseException:', pr_src)


if __name__ == '__main__':
    unittest.main()
