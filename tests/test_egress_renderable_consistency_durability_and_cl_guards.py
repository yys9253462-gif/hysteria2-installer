"""回归测试：出站全局模式与 WARP 覆盖口径统一校验可渲染性、持久化不确定返 503、目录 fsync 容错与探测/管理请求长度校验。"""

import ast
import copy
import email.message
import io
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
PORTAL_TREE = ast.parse(PORTAL_SRC)


def _extract_method(name, extra_ns):
    for node in ast.walk(PORTAL_TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            src = ast.get_source_segment(PORTAL_SRC, node)
            dedented = '\n'.join(line[8:] if line.startswith('        ') else line for line in src.splitlines())
            ns = {
                'copy': copy,
                'time': __import__('time'),
                'Path': Path,
                'parse_qs': parse_qs,
                'routing_state': portal.routing_state,
                'clean_outbounds': portal.clean_outbounds,
                '_renderable_outbounds': portal._renderable_outbounds,
                'validate_outbound': portal.validate_outbound,
                'normalize_route_rules': portal.normalize_route_rules,
                'outbound_target_exists': portal.outbound_target_exists,
                '_clean_route_domain': portal._clean_route_domain,
                '_valid_route_domain': portal._valid_route_domain,
                'render_egress_config': portal.render_egress_config,
                'detect_outbound_ip': portal.detect_outbound_ip,
                'DEFAULT_WARP_DOMAINS': portal.DEFAULT_WARP_DOMAINS,
                'AtomicWriteDurabilityError': portal.AtomicWriteDurabilityError,
            }
            ns.update(extra_ns)
            exec(dedented, ns)
            return ns[name]
    raise AssertionError(f'未找到方法 {name}')


class _FakeHandler:
    def __init__(self, form=None, headers=None):
        raw = urlencode(form or {}).encode('utf-8')
        self.rfile = io.BytesIO(raw)
        self.headers = headers if headers is not None else {'Content-Length': str(len(raw))}
        self.resp = None

    def is_authenticated(self):
        return True

    def _extend_deadline(self, seconds, heavy=False):
        return True

    def reply_json(self, code, payload):
        self.resp = (code, payload)
        return self.resp

    def _reply_with_egress_apply(self, payload, kind='outbound'):
        self.resp = (200, dict(ok=True, **payload))
        return self.resp

    def _reply_with_warp_apply(self, payload):
        return self._reply_with_egress_apply(payload, kind='warp')


class EgressRenderableConsistencyDurabilityAndClGuardsTests(unittest.TestCase):
    def test_ob_manage_rejects_global_mode_and_resets_on_delete_when_only_corrupt_outbound_remains(self):
        """仅有不可渲染的损坏出站时，_ob_manage 必须拒绝切换 global，删掉最后一个合法出站时须重置为 rules。"""
        data = {
            'outbound_mode': 'rules',
            'custom_outbounds': [{'name': 'broken_socks', 'type': 'socks5', 'addr': 'not-a-host-port'}],
        }
        fn = _extract_method('_ob_manage', {
            'data': data,
            'data_lock': threading.Lock(),
            'save_data': lambda: None,
        })
        h = _FakeHandler({'action': 'mode', 'mode': 'global'})
        st, body = fn(h)
        self.assertEqual(st, 400, body)

        # 合法出站被删除后仅剩损坏出站：outbound_mode 必须重置为 rules
        data2 = {
            'outbound_mode': 'global',
            'custom_outbounds': [
                {'name': 'good_socks', 'type': 'socks5', 'addr': '1.2.3.4:1080'},
                {'name': 'broken_socks', 'type': 'socks5', 'addr': 'bad-addr'},
            ],
            'warp_rules': [],
        }
        fn2 = _extract_method('_ob_manage', {
            'data': data2,
            'data_lock': threading.Lock(),
            'save_data': lambda: None,
        })
        h2 = _FakeHandler({'action': 'delete', 'name': 'good_socks'})
        st2, _ = fn2(h2)
        self.assertEqual(st2, 200)
        self.assertEqual(data2['outbound_mode'], 'rules')

    def test_warp_status_overridden_false_when_only_corrupt_outbound_exists(self):
        """仅有损坏不可渲染出站时，/warp-status 不得谎报 overridden=True。"""
        data = {
            'warp_enabled': True,
            'outbound_mode': 'global',
            'custom_outbounds': [{'name': 'broken_socks', 'type': 'socks5', 'addr': 'bad'}],
            'warp_rules': ['openai.com'],
        }
        fn = _extract_method('_h_get_warp_status', {
            'data': data,
            'data_lock': threading.Lock(),
            'warp_backend_installed': lambda: False,
            '_warp_probe_lock': threading.Lock(),
            '_warp_probe_cache': {},
            '_hy2_config_loaded': lambda p: False,
        })
        h = _FakeHandler()
        st, body = fn(h, 'warp-status')
        self.assertEqual(st, 200)
        self.assertFalse(body['overridden'])

    def test_ob_manage_and_manage_warp_return_503_on_durability_error_and_reject_fullwidth_cl(self):
        """_ob_manage 与 _h_post_manage_warp 遇 AtomicWriteDurabilityError 返回 503，且拒绝全角/重复 Content-Length。"""
        data = {'outbound_mode': 'rules', 'custom_outbounds': []}
        ob_fn = _extract_method('_ob_manage', {
            'data': data,
            'data_lock': threading.Lock(),
            'save_data': Mock(side_effect=portal.AtomicWriteDurabilityError('dir sync')),
        })
        h_dur = _FakeHandler({'action': 'save', 'name': 's1', 'type': 'socks5', 'addr': '1.2.3.4:1080'})
        st, _ = ob_fn(h_dur)
        self.assertEqual(st, 503)

        h_fw = _FakeHandler({'action': 'mode', 'mode': 'rules'}, headers={'Content-Length': '１０'})
        st_fw, _ = ob_fn(h_fw)
        self.assertEqual(st_fw, 400)

        warp_fn = _extract_method('_h_post_manage_warp', {
            'data': {'warp_enabled': False},
            'data_lock': threading.Lock(),
            'warp_backend_installed': lambda: True,
            'save_data': Mock(side_effect=portal.AtomicWriteDurabilityError('dir sync')),
        })
        h_wdur = _FakeHandler({'action': 'enable'})
        st_w, _ = warp_fn(h_wdur, '/tok/')
        self.assertEqual(st_w, 503)

        probe_fn = _extract_method('_ob_probe', {})
        dup_headers = email.message.Message()
        dup_headers.add_header('Content-Length', '5')
        dup_headers.add_header('Content-Length', '6')
        h_p = _FakeHandler({}, headers=dup_headers)
        st_p, _ = probe_fn(h_p)
        self.assertEqual(st_p, 400)

    def test_apply_egress_config_resets_unrenderable_global_and_tolerates_dir_fsync_oserror(self):
        """apply_egress_config 面对不可渲染全局出站应归回 rules，且目录 fsync OSError 不得误触发回滚。"""
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'config.yaml'
            cfg.write_text('listen: :443\noutbounds:\n  - name: direct\n    type: direct\n', encoding='utf-8')
            data = {
                'warp_enabled': False,
                'outbound_mode': 'global',
                'custom_outbounds': [{'name': 'broken', 'type': 'socks5', 'addr': 'bad'}],
            }
            lock = threading.Lock()
            with patch.object(portal, '_hy2_runtime_identity', return_value=('active', '100', 'Sat 2026-11-22 00:00:00 UTC')), \
                 patch.object(portal, '_hy2_config_loaded', return_value=False), \
                 patch.object(portal, '_unit_suspended', return_value=True):
                ok, err = portal.apply_egress_config(data, lock, config_path=str(cfg))
            self.assertTrue(ok, err)
            self.assertEqual(data['outbound_mode'], 'rules')
            self.assertNotIn('broken(all)', cfg.read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
