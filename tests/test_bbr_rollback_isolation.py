"""回归测试：BBR 应用与保存失败回滚时，内存目标版本必须先还原且单项回滚异常不中断后续恢复。"""
import ast
import importlib.util
import io
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('portal_bbr_rb_test', ROOT / 'portal.py')
portal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(portal)
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))


def _extract_method(name, ns):
    for node in ast.walk(TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            mod = ast.Module(body=[node], type_ignores=[])
            ast.fix_missing_locations(mod)
            exec(compile(mod, str(ROOT / 'portal.py'), 'exec'), ns)
            return ns[name]
    raise AssertionError('找不到方法: ' + name)


class BbrRollbackIsolationTests(unittest.TestCase):
    def test_save_failure_restores_memory_target_and_all_sysctls_even_when_one_sysctl_times_out(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'etc/modules-load.d').mkdir(parents=True)
            (root / 'etc/sysctl.d').mkdir(parents=True)
            (root / 'etc/modules-load.d/bbr.conf').write_text('old-mod\n', encoding='utf-8')
            (root / 'etc/sysctl.d/99-bbr.conf').write_text('old-sysctl\n', encoding='utf-8')

            def fake_path(val):
                s = str(val)
                if s.startswith('/etc/'):
                    return root / s.lstrip('/')
                return Path(val)

            sysctl_w_calls = []

            def fake_run(args, **kwargs):
                if args[:2] == ['sysctl', '-n']:
                    key = args[2]
                    if key == 'net.ipv4.tcp_available_congestion_control':
                        return SimpleNamespace(returncode=0, stdout='cubic bbr bbr2\n')
                    if key == 'net.core.default_qdisc':
                        return SimpleNamespace(returncode=0, stdout='fq\n')
                    if key == 'net.ipv4.tcp_congestion_control':
                        # 首次探测读旧值 cubic，sysctl -p 后读回新值 bbr2
                        if (root / 'etc/sysctl.d/99-bbr.conf').read_text(encoding='utf-8').startswith(portal.BBR_FILE_MARKER):
                            return SimpleNamespace(returncode=0, stdout='bbr2\n')
                        return SimpleNamespace(returncode=0, stdout='cubic\n')
                    return SimpleNamespace(returncode=1, stdout='')
                if args[:2] == ['sysctl', '-w']:
                    sysctl_w_calls.append(args[2])
                    if len(sysctl_w_calls) == 1:
                        raise subprocess.TimeoutExpired(args, 3)
                    return SimpleNamespace(returncode=0, stdout='')
                return SimpleNamespace(returncode=0, stdout='')

            data = {'bbr_target_version': 'v1'}
            replies = []
            body = urlencode({'version': 'v2'}).encode()
            handler = SimpleNamespace(
                headers={'Content-Length': str(len(body))},
                rfile=io.BytesIO(body),
                reply_json=lambda code, payload: replies.append((code, payload)),
            )
            ns = dict(
                portal.__dict__,
                Path=fake_path,
                data=data,
                data_lock=threading.RLock(),
                save_data=lambda: (_ for _ in ()).throw(OSError('disk full')),
                subprocess=SimpleNamespace(run=fake_run, SubprocessError=subprocess.SubprocessError),
            )
            _extract_method('_set_bbr_locked', ns)(handler)
            self.assertEqual(replies[-1][0], 500)
            self.assertEqual(data.get('bbr_target_version'), 'v1',
                             'save_data 失败且某条 sysctl 回滚超时时，内存 bbr_target_version 未恢复')
            self.assertGreaterEqual(len(sysctl_w_calls), 2, '第一条 sysctl -w 超时中断了后续 sysctl 恢复')
            self.assertEqual((root / 'etc/modules-load.d/bbr.conf').read_text(encoding='utf-8'), 'old-mod\n')
            self.assertEqual((root / 'etc/sysctl.d/99-bbr.conf').read_text(encoding='utf-8'), 'old-sysctl\n')


if __name__ == '__main__':
    unittest.main()
