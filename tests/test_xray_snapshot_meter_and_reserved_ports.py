"""回归测试：Xray 准入快照损坏字段/回滚容错、计量配置校验与保留端口防崩溃。"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


class XraySnapshotMeterAndReservedPortsTests(unittest.TestCase):
    def test_snapshot_handles_null_settings_and_blank_binary_config(self):
        """入站 settings 为 null 且 meter_config.reality.binary 为空/None 时，不应抛 AttributeError/TypeError。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            xj = root / 'xray.json'
            xj.write_text(json.dumps({
                'inbounds': [{'tag': portal.REALITY_INBOUND_TAG, 'settings': None}],
            }), encoding='utf-8')
            seen_cmds = []

            def fake_run(args, **kwargs):
                seen_cmds.append(list(args))
                if args[:2] == ['systemctl', 'show']:
                    return SimpleNamespace(returncode=0, stdout='epoch-ok\n', stderr='')
                if args[:2] == ['systemctl', 'is-active']:
                    return SimpleNamespace(returncode=0, stdout='inactive\n', stderr='')
                return SimpleNamespace(returncode=0, stdout='', stderr='')

            wanted = {portal.REALITY_INBOUND_TAG: [{'id': 'u1', 'email': 'u1'}]}
            with patch.object(portal.subprocess, 'run', side_effect=fake_run):
                ok = portal._apply_xray_access_snapshot_locked(
                    root, xj, {}, {'u1'}, root / 'meter.json',
                    {'reality': {'binary': None}}, (), wanted,
                )
            self.assertTrue(ok)
            updated = json.loads(xj.read_text(encoding='utf-8'))
            self.assertEqual(updated['inbounds'][0]['settings']['clients'], wanted[portal.REALITY_INBOUND_TAG])
            test_cmds = [c for c in seen_cmds if '-test' in c]
            self.assertEqual(len(test_cmds), 1)
            self.assertEqual(test_cmds[0][0], '/usr/local/bin/xray')

    def test_snapshot_rollback_write_failure_preserves_original_exception(self):
        """回滚写盘发生 OSError 时，不得掩盖导致回滚的原始重启异常。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            xj = root / 'xray.json'
            xj.write_text(json.dumps({
                'inbounds': [{'tag': portal.REALITY_INBOUND_TAG, 'settings': {'clients': []}}],
            }), encoding='utf-8')

            real_write = portal._write_private_bytes
            write_calls = [0]

            def flaky_write(*args, **kwargs):
                write_calls[0] += 1
                # 第 1 次写 candidate，第 2 次写 last_good_tmp，第 3 次是回滚写回
                if write_calls[0] == 3:
                    raise OSError('disk full during rollback')
                return real_write(*args, **kwargs)

            def fake_run(args, **kwargs):
                if args[:2] == ['systemctl', 'show']:
                    return SimpleNamespace(returncode=0, stdout='epoch-1\n', stderr='')
                if args[:2] == ['systemctl', 'is-active']:
                    return SimpleNamespace(returncode=0, stdout='active\n', stderr='')
                if args[:2] == ['systemctl', 'restart']:
                    raise subprocess.CalledProcessError(1, args)
                return SimpleNamespace(returncode=0, stdout='', stderr='')

            wanted = {portal.REALITY_INBOUND_TAG: [{'id': 'u2', 'email': 'u2'}]}
            with patch.object(portal.subprocess, 'run', side_effect=fake_run), \
                    patch.object(portal, '_write_private_bytes', side_effect=flaky_write):
                with self.assertRaises(subprocess.CalledProcessError):
                    portal._apply_xray_access_snapshot_locked(
                        root, xj, {}, {'u2'}, root / 'meter.json',
                        {'reality': {'binary': '/usr/local/bin/xray'}}, (), wanted,
                    )

    def test_apply_xray_config_with_meter_rejects_corrupt_meter_and_invalid_ports(self):
        """损坏的计量配置结构与越界/全角端口应报 ValueError 而非 AttributeError 或静默放行。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg_path = root / 'xray.json'
            meter_path = root / 'usage-meter-config.json'
            base_cfg = {'inbounds': [], 'outbounds': []}

            # 非对象顶层 JSON 与非对象 reality 段落应优雅忽略并继续应用
            for raw in ('[]', '{"reality": "bad"}'):
                meter_path.write_text(raw, encoding='utf-8')
                with patch.object(portal, 'apply_xray_config_transaction') as mock_tx:
                    portal.apply_xray_config_with_meter(dict(base_cfg), cfg_path, meter_path, root)
                mock_tx.assert_called_once()

            # 越界端口、全角数字端口、非字符串地址都必须抛出 ValueError
            for payload in (
                {'reality': {'address': 12345}},
                {'reality': {'address': '127.0.0.1:0'}},
                {'reality': {'address': '127.0.0.1:70000'}},
                {'reality': {'address': '127.0.0.1:\uff11\uff10\uff10\uff18\uff15'}},
            ):
                meter_path.write_text(json.dumps(payload), encoding='utf-8')
                with patch.object(portal, 'apply_xray_config_transaction') as mock_tx:
                    with self.assertRaises(ValueError, msg=f'应拒绝异常计量地址: {payload}'):
                        portal.apply_xray_config_with_meter(dict(base_cfg), cfg_path, meter_path, root)
                mock_tx.assert_not_called()

    def test_managed_reserved_ports_ignores_booleans_and_corrupt_config(self):
        """布尔端口不应被 int(True)==1 收入集合，损坏的 config/inbounds 元素不应抛异常。"""
        meta = {'listen_port': True, 'subscription_port': False}
        data = {
            'reality_config': {'enabled': True, 'port': True},
            'vmess_config': {'enabled': True, 'port': 2087},
            'proxy_services': [{'port': True}, {'port': 10808}, 'bad-item'],
        }
        # config 为列表时不应抛 AttributeError
        ports = portal.managed_reserved_ports(meta, data, config=['not-a-dict'])
        self.assertEqual(ports, {2087, 10808})
        # inbounds 含非字典元素或布尔端口时不应崩溃，也不得收录端口 1
        ports2 = portal.managed_reserved_ports(
            meta,
            data,
            config={'inbounds': [None, 'bad', {'tag': 'x', 'port': True}, {'tag': 'y', 'port': 8443}]},
        )
        self.assertEqual(ports2, {2087, 10808, 8443})


if __name__ == '__main__':
    unittest.main()
