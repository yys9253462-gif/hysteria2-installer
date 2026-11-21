"""回归测试：_h_post_install_warp 原子写单元与看门狗、wgcf 私钥私有权限、并发安装锁与 save_data 失败回滚。"""

import ast
import copy
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
PORTAL = ROOT / 'portal.py'
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class InstallWarpHardeningTests(unittest.TestCase):
    def _block(self):
        src = PORTAL.read_text(encoding='utf-8')
        start = src.index('def _h_post_install_warp(self, prefix):')
        end = src.index('def do_HEAD(self):', start)
        return src[start:end]

    def test_script_avoids_raw_cat_to_systemd_and_protects_wgcf_private_files(self):
        block = self._block()
        self.assertNotIn('cat > /etc/systemd/system/wireproxy.service', block)
        self.assertNotIn('cat > /usr/local/bin/hy2-warp-watchdog.sh', block)
        self.assertNotIn('cat > /etc/systemd/system/hy2-warp-watchdog.service', block)
        self.assertNotIn('cat > /etc/systemd/system/hy2-warp-watchdog.timer', block)
        self.assertNotIn('>/tmp/wgcf-register.log', block)
        self.assertNotIn('>/tmp/wgcf-generate.log', block)
        self.assertIn('chmod 600 "$WGCF_ACCT"', block)
        self.assertIn('chmod 600 "$WGCF_CONF"', block)

    def test_concurrent_install_lock_and_save_data_rollback(self):
        src = PORTAL.read_text(encoding='utf-8')
        self.assertIn('_warp_install_lock = threading.Lock()', src)
        tree = ast.parse(src)
        node = next(
            n for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef) and n.name == '_h_post_install_warp'
        )
        state = {'warp_enabled': False}
        lock = threading.Lock()
        env = dict(portal.__dict__)
        env.update({
            'data': state,
            'data_lock': threading.RLock(),
            'warp_apply_lock': threading.Lock(),
            '_warp_install_lock': lock,
            'subprocess': SimpleNamespace(
                run=lambda *a, **k: SimpleNamespace(returncode=0, stdout='ok', stderr='')
            ),
            'save_data': lambda: (_ for _ in ()).throw(OSError('disk full')),
        })
        exec(compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(node)], type_ignores=[])), '<iw>', 'exec'), env)
        fn = env['_h_post_install_warp']

        class FakeHandler:
            def is_authenticated(self):
                return True

            def _extend_deadline(self, seconds, heavy=False):
                return True

            def reply_json(self, status, payload):
                return status, payload

            def _reply_with_warp_apply(self, payload):
                return 200, dict(ok=True, **payload)

        # 模拟 save_data 磁盘满失败：内存里的 warp_enabled 与 warp_rules 必须回滚
        status, payload = fn(FakeHandler(), '/tok/')
        self.assertEqual(status, 500)
        self.assertFalse(payload['ok'])
        self.assertFalse(state.get('warp_enabled'), 'save_data 失败后 warp_enabled 未回滚')
        self.assertNotIn('warp_rules', state, 'save_data 失败后新增的 warp_rules 未回滚')

        # 模拟并发调用：锁被占用时必须直接返 409
        with lock:
            status2, payload2 = fn(FakeHandler(), '/tok/')
            self.assertEqual(status2, 409)
            self.assertFalse(payload2['ok'])


if __name__ == '__main__':
    unittest.main()
