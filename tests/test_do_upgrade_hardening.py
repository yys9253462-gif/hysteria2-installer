"""回归测试：_h_post_do_upgrade_impl 长度校验、reality-online 配置校验与续期、awg 刷新检查及锁内读端口。"""

import ast
import copy
import io
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORTAL = ROOT / 'portal.py'
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


def _extract_do_upgrade_impl(extra_env):
    tree = ast.parse(PORTAL.read_text(encoding='utf-8'))
    node = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == '_h_post_do_upgrade_impl'
    )
    fn = copy.deepcopy(node)
    env = dict(portal.__dict__)
    env.update(extra_env)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])), '<do_upgrade>', 'exec'), env)
    return env['_h_post_do_upgrade_impl']


class _FakeHandler:
    def __init__(self, body=b'', content_length=None):
        self.headers = {'Content-Length': str(len(body) if content_length is None else content_length)}
        self.rfile = io.BytesIO(body)
        self.replies = []
        self.deadlines = []

    def is_authenticated(self):
        return True

    def _extend_deadline(self, seconds, heavy=False):
        self.deadlines.append((seconds, heavy))
        return True

    def reply_json(self, status, payload):
        self.replies.append((status, payload))
        return status, payload


class DoUpgradeHardeningTests(unittest.TestCase):
    def test_negative_content_length_rejected_as_400(self):
        fn = _extract_do_upgrade_impl({'portal_path': Path('/tmp/portal.json')})
        h = _FakeHandler(b'target=awg', content_length=-5)
        status, payload = fn(h, '/tok/')
        self.assertEqual(status, 400)
        self.assertFalse(payload['ok'])

    def test_awg_target_aborts_when_ensure_awgctl_fails(self):
        called = []
        fn = _extract_do_upgrade_impl({
            'portal_path': Path('/tmp/portal.json'),
            'awg_installed': lambda: True,
            'unit_suspended': lambda u: False,
            'AWG_SVC_NAME': 'amneziawg',
            'ensure_awgctl': lambda force=False: False,
            'awg_run': lambda *a, **k: (called.append(a) or (0, '', '')),
        })
        h = _FakeHandler(b'target=awg')
        status, payload = fn(h, '/tok/')
        self.assertEqual(status, 500)
        self.assertFalse(payload['ok'])
        self.assertEqual(called, [], 'ensure_awgctl 失败后不应继续调用 awg_run')

    def test_reality_online_validates_meter_config_and_extends_deadline(self):
        src = PORTAL.read_text(encoding='utf-8')
        start = src.index('def _h_post_do_upgrade_impl(self, prefix):')
        end = src.index('def _manage_proxy_operation(self, action, params):', start)
        block = src[start:end]
        ro_start = block.index("if target == 'reality-online':")
        ro_end = block.index("if target == 'portal':", ro_start)
        ro_block = block[ro_start:ro_end]
        self.assertIn('_extend_deadline', ro_block, 'reality-online 变更配置并重启 xray 前未续期')

        # 缺失或损坏的 usage-meter-config.json 必须返回可读中文错误而不是裸异常名
        tmp = Path(self._testMethodName + '_tmp_dir')
        tmp.mkdir(exist_ok=True)
        try:
            cfg_file = tmp / 'usage-meter-config.json'
            cfg_file.write_text('[]', encoding='utf-8')
            fn = _extract_do_upgrade_impl({
                'portal_path': tmp / 'portal.json',
                'unit_suspended': lambda u: False,
            })
            h = _FakeHandler(b'target=reality-online')
            status, payload = fn(h, '/tok/')
            self.assertEqual(status, 500)
            self.assertIn('usage-meter-config.json', payload['error'])
        finally:
            for p in tmp.glob('*'):
                p.unlink(missing_ok=True)
            tmp.rmdir()

    def test_portal_restart_script_reads_port_under_data_lock(self):
        src = PORTAL.read_text(encoding='utf-8')
        start = src.index('def _h_post_do_upgrade_impl(self, prefix):')
        end = src.index('def _manage_proxy_operation(self, action, params):', start)
        block = src[start:end]
        p_start = block.index("if target == 'portal':")
        p_end = block.index("if target == 'awg':", p_start)
        p_block = block[p_start:p_end]
        self.assertIn('with data_lock:\n                                    restart_script = portal_update_restart_script(', p_block)


if __name__ == '__main__':
    unittest.main()
