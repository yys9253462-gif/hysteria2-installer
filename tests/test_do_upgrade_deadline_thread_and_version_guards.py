import ast
import copy
import io
import json
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs

REPO = Path(__file__).resolve().parent.parent
PORTAL_PATH = REPO / 'portal.py'
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import portal  # noqa: E402

TREE = ast.parse(PORTAL_PATH.read_text(encoding='utf-8'))


def _extract_method(name, extra_env):
    node = next(
        n for n in ast.walk(TREE)
        if isinstance(n, ast.FunctionDef) and n.name == name
    )
    env = dict(portal.__dict__)
    env['parse_qs'] = parse_qs
    env.update(extra_env)
    exec(
        compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(node)], type_ignores=[])), f'<{name}>', 'exec'),
        env,
    )
    return env[name]


class _FakeHandler:
    def __init__(self, body=b'', path='/tok/check-version', events=None, heavy_ok=True):
        self.headers = {'Content-Length': str(len(body))}
        self.rfile = io.BytesIO(body)
        self.path = path
        self.events = events if events is not None else []
        self.heavy_ok = heavy_ok

    def is_authenticated(self):
        return True

    def _extend_deadline(self, seconds, heavy=False):
        self.events.append(('deadline', seconds, heavy))
        return self.heavy_ok

    def reply_json(self, status, payload):
        return status, payload


class TestDoUpgradeDeadlineThreadAndVersionGuards(unittest.TestCase):
    def test_do_upgrade_awg_extends_deadline_before_ensure_awgctl(self):
        """target=awg 必须先申请重型死线槽再联网调用 ensure_awgctl(force=True)。"""
        events = []
        fn = _extract_method('_h_post_do_upgrade_impl', {
            'awg_installed': lambda: True,
            'unit_suspended': lambda u: False,
            'AWG_SVC_NAME': 'amneziawg-server',
            'ensure_awgctl': lambda force=False: (events.append(('ensure_awgctl', force)) or True),
            'awg_run': lambda args, timeout=0: (0, 'ok', ''),
            'awg_err_tail': lambda *a: '',
        })
        st, body = fn(_FakeHandler(b'target=awg', events=events, heavy_ok=False), '/tok/')
        self.assertEqual(st, 409)
        self.assertEqual(events, [('deadline', 480, True)])

    def test_do_upgrade_core_clears_running_state_if_worker_thread_fails_to_start(self):
        """target=core 若工作线程 start() 失败，不得让 core_upgrade 永久卡在 running。"""
        data = {}
        saved = []

        class _BoomThread:
            def __init__(self, *a, **k):
                pass
            def start(self):
                raise RuntimeError("can't start new thread")

        fn = _extract_method('_h_post_do_upgrade_impl', {
            'data_lock': threading.Lock(),
            'data': data,
            'save_data': lambda: saved.append(copy.deepcopy(data.get('core_upgrade'))),
            'upgrade_core_binary': lambda allow_custom=False: {'message': 'ok'},
            '_ver_cache_lock': threading.Lock(),
            '_core_ver_cache': {'t': 1.0, 'tag': '1.0'},
            'threading': SimpleNamespace(Thread=_BoomThread),
        })
        fn(_FakeHandler(b'target=core'), '/tok/')
        self.assertEqual(data['core_upgrade']['state'], 'failed')
        self.assertIn("can't start new thread", data['core_upgrade']['error'])

    def test_check_version_ignores_non_string_tag_name_and_reality_status_validates_svg_and_port(self):
        """_h_get_check_version 须忽略非字符串 tag_name；_h_get_reality_status 须校验 <svg 与合法端口。"""
        class _FakeResp:
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
            def read(self, n=-1):
                return json.dumps({'tag_name': ['v2.6.0']}).encode('utf-8')

        fake_urllib = SimpleNamespace(
            request=SimpleNamespace(
                Request=lambda *a, **k: object(),
                urlopen=lambda *a, **k: _FakeResp(),
            )
        )
        fn_ver = _extract_method('_h_get_check_version', {
            '_ver_cache_lock': threading.Lock(),
            '_ver_cache': {'t': 0.0, 'shas': {}},
            '_core_ver_cache': {'t': 0.0, 'tag': ''},
            'subprocess': SimpleNamespace(run=lambda *a, **k: SimpleNamespace(stdout='Version: v2.6.0\n')),
            'urllib': fake_urllib,
            'PORTAL_SELF': Path('/tmp/portal.py'),
            '_local_blob_sha': lambda p: 'a' * 40,
            '_remote_root_shas': lambda: {},
            '_version_triple': lambda *a: ('', '', False),
            'usage_meter': None,
            'usage_summary': lambda u: {},
            'MASTER_USER_ID': '__master__',
            'AWG_CTL': '/tmp/nonexistent-awgctl',
        })
        st, body = fn_ver(_FakeHandler(path='/tok/check-version'), 'check-version')
        self.assertEqual(st, 200)
        self.assertEqual(body['core_latest'], '')

        # _h_get_reality_status 非 SVG 输出应置空，损坏端口回退 443
        fn_real = _extract_method('_h_get_reality_status', {
            'Path': lambda p: SimpleNamespace(
                exists=lambda: True,
                read_text=lambda encoding='utf-8': json.dumps({
                    'inbounds': [{'tag': portal.REALITY_INBOUND_TAG, 'port': 443}]
                }),
            ),
            'managed_inbound_active': lambda cfg, tag: True,
            'data_lock': threading.Lock(),
            'data': {'reality_config': {'uri': 'vless://abc', 'port': 'not-a-port'}},
            'subprocess': SimpleNamespace(run=lambda *a, **k: SimpleNamespace(returncode=0, stdout=b'warning: broken')),
        })
        st2, body2 = fn_real(_FakeHandler(path='/tok/reality-status'), 'reality-status')
        self.assertEqual(st2, 200)
        self.assertEqual(body2['config']['qr_svg'], '')
        self.assertEqual(body2['config']['port'], 443)


if __name__ == '__main__':
    unittest.main()
