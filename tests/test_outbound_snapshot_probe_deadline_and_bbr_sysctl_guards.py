import ast
import copy
import io
import subprocess
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
    def __init__(self, body=b'', events=None):
        self.headers = {'Content-Length': str(len(body))}
        self.rfile = io.BytesIO(body)
        self.events = events if events is not None else []

    def is_authenticated(self):
        return True

    def _extend_deadline(self, seconds, heavy=False):
        self.events.append(('deadline', seconds, heavy))
        return True

    def reply(self, status, body, mime='text/plain', **kw):
        return status, body

    def reply_json(self, status, payload):
        return status, payload

    def _reply_with_egress_apply(self, payload, kind='outbound'):
        return 200, payload


class TestOutboundSnapshotProbeDeadlineAndBbrSysctlGuards(unittest.TestCase):
    def test_ob_manage_takes_rollback_snapshot_inside_write_lock_preserving_concurrent_changes(self):
        """_ob_manage 在 validate_outbound 期间若有并发修改，落盘失败回滚不得用旧快照覆盖并发修改。"""
        data = {
            'custom_outbounds': [],
            'warp_rules': [{'domain': 'initial.example.com', 'outbound': 'warp_socks'}],
            'outbound_mode': 'rules',
        }

        def concurrent_validate(entry):
            # 模拟锁外校验期间另一个请求成功添加了新规则并落盘
            data['warp_rules'].append({'domain': 'concurrent.example.com', 'outbound': 'warp_socks'})
            return True, {'name': 'hk', 'type': 'socks5', 'addr': '1.2.3.4:1080'}, ''

        def failing_save():
            raise OSError('disk full')

        fn = _extract_method('_ob_manage', {
            'data_lock': threading.Lock(),
            'data': data,
            'validate_outbound': concurrent_validate,
            'save_data': failing_save,
        })
        st, body = fn(_FakeHandler(b'action=save&name=hk&type=socks5&addr=1.2.3.4:1080'))
        self.assertEqual(st, 500)
        self.assertEqual(data['custom_outbounds'], [])
        domains = [r['domain'] for r in data['warp_rules']]
        self.assertIn('concurrent.example.com', domains, '锁外提前拍摄的旧快照在回滚时抹掉了并发新增规则')

    def test_ob_probe_extends_deadline_before_external_probe(self):
        """_ob_probe 在外连探测前必须续期连接死线。"""
        events = []
        fn = _extract_method('_ob_probe', {
            'detect_outbound_ip': lambda *a, **k: (events.append(('probe', a[0])) or '1.2.3.4'),
        })
        st, body = fn(_FakeHandler(b'kind=warp', events=events))
        self.assertEqual(st, 200)
        self.assertEqual(body['ip'], '1.2.3.4')
        self.assertEqual(events[0][0], 'deadline')
        self.assertEqual(events[1], ('probe', 'warp'))

    def test_bbr_status_survives_missing_sysctl_binary(self):
        """精简系统缺少 sysctl 命令时 _h_get_bbr_status 不得 500 崩溃，应降级返回 200。"""
        def missing_sysctl(cmd, **kwargs):
            if cmd and cmd[0] == 'sysctl':
                raise FileNotFoundError('sysctl not found')
            return SimpleNamespace(returncode=1, stdout='', stderr='')

        fn = _extract_method('_h_get_bbr_status', {
            'data_lock': threading.Lock(),
            'data': {},
            'sysctl_conf_overrides': lambda m: [],
            'subprocess': SimpleNamespace(
                run=missing_sysctl,
                SubprocessError=subprocess.SubprocessError,
            ),
            'Path': lambda p: SimpleNamespace(exists=lambda: False),
        })
        st, body = fn(_FakeHandler(), 'bbr-status')
        self.assertEqual(st, 200, f'缺少 sysctl 时不应 500: {body}')
        self.assertTrue(body['ok'])
        self.assertEqual(body['current'], '未知')
        self.assertEqual(body['available'], [])

    def test_post_login_rejects_empty_portal_token_with_503(self):
        """portal_token 为空时 _h_post_login 须返回 503 而非签发空路径 Cookie。"""
        fn = _extract_method('_h_post_login', {
            'data_lock': threading.Lock(),
            'data': {'token': '', 'auth_hash': 'a' * 64},
        })
        st, body = fn(_FakeHandler(b'username=u&password=p'), '/tok/')
        self.assertEqual(st, 503)


if __name__ == '__main__':
    unittest.main()
