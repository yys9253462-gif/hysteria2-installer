"""收回时的 Hy2 兜底重启走 _restart_hy2，并等统计接口重新可用（2026-11-04 修）。

旧实现直接 `systemctl restart`（不清失败计数，一阵连续收回就撞上 StartLimitBurst 锁死），
随后立刻请求 /online：Type=simple 下进程刚 fork、统计端口还没绑好，ConnectionRefused
直接抛出，收回失败、下一轮再重启一次。
"""
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


class RevokeRestartTests(unittest.TestCase):
    def test_restart_uses_reset_failed_and_waits_for_stats(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'usage-meter-config.json').write_text(json.dumps(
                {'hysteria': {'url': 'http://127.0.0.1:9', 'secret': 's'}}), encoding='utf-8')
            state = {'phase': 'before', 'refused': 0}
            calls = []

            def urlopen(req, timeout=None):
                path = req.full_url.rsplit(':9', 1)[1]
                if state['phase'] == 'after':
                    if state['refused'] < 2:
                        state['refused'] += 1
                        raise ConnectionRefusedError(111, 'refused')
                    body = b'{}'
                else:
                    body = b'{}' if path == '/kick' else b'{"bob": 1}'
                resp = mock.MagicMock()
                resp.__enter__.return_value = io.BytesIO(body)
                return resp

            def run(args, **kw):
                calls.append(list(args))
                if args[:2] == ['systemctl', 'start']:
                    state['phase'] = 'after'
                return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
            with mock.patch.object(portal.urllib.request, 'urlopen', urlopen), \
                    mock.patch.object(portal.subprocess, 'run', run), \
                    mock.patch.object(portal, '_unit_suspended', lambda u: False), \
                    mock.patch.object(portal.time, 'sleep', lambda s: None), \
                    mock.patch.object(portal, '_systemd_state', lambda u: 'inactive'):
                ok = portal._enforce_node_access_xray_hy2(root, {'users': {}}, force_ids=['bob'])
        self.assertTrue(ok)
        self.assertIn(['systemctl', 'reset-failed', 'hysteria-server'], calls)
        self.assertNotIn(['systemctl', 'restart', 'hysteria-server'], calls)


if __name__ == '__main__':
    unittest.main()
