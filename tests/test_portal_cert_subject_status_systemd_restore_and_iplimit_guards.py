"""回归测试：证书主题/状态防选项注入与自愈读盘上限、systemd 状态查询/回滚守卫及 Reality IP 限制容错与清理隔离。"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import portal


class TestPortalCertSubjectStatusSystemdRestoreAndIplimitGuards(unittest.TestCase):
    def test_parse_cert_subject_and_cert_status_block_dash_path_and_oversized_heal_state(self):
        """_parse_cert_subject 须拒前导 - 路径并带 errors='replace'；cert_status 须拒符号链接/超 1 MiB 自愈状态并清洗 NaN/Inf。"""
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            return subprocess.CompletedProcess(cmd, 0, stdout='subject=CN=example.com\n', stderr='')

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            dash_cert = root / '-evil.pem'
            dash_cert.write_text('dummy', encoding='utf-8')
            with mock.patch.object(portal.subprocess, 'run', side_effect=fake_run):
                # 传入前导 - 的相对路径时不得调用 openssl
                old_cwd = os.getcwd()
                try:
                    os.chdir(td)
                    self.assertEqual(portal._parse_cert_subject('-evil.pem'), ('', [], False))
                    self.assertEqual(calls, [], '前导 - 的证书路径不得传入 openssl')
                finally:
                    os.chdir(old_cwd)

            # 正常证书路径：校验调用都带 errors='replace'
            good_cert = root / 'ok.pem'
            good_cert.write_text('dummy', encoding='utf-8')
            calls.clear()
            with mock.patch.object(portal.subprocess, 'run', side_effect=fake_run):
                portal._parse_cert_subject(good_cert)
            self.assertTrue(calls)
            self.assertTrue(all(kw.get('errors') == 'replace' for _, kw in calls))

            # cert_status 读取自愈状态：超 1 MiB 被拒绝；含 inf healed_at 时仍保留合法 heal_count 与 last_pin
            heal = root / 'cert-selfheal.json'
            heal.write_text('{"healed_at": Infinity, "heal_count": 7, "last_pin": "abcd1234"}', encoding='utf-8')
            with mock.patch.object(portal, '_resolve_live_cert', return_value=(good_cert, 'a.com', ['a.com'], False)), \
                 mock.patch.object(portal.subprocess, 'run', return_value=subprocess.CompletedProcess(
                     ['openssl'], 0,
                     stdout='issuer=CN=CA\nnotBefore=Jan  1 00:00:00 2026 GMT\nnotAfter=Jan  1 00:00:00 2028 GMT\n',
                     stderr='')):
                info = portal.cert_status(root, meta={}, selfheal_state_path=heal)
            self.assertEqual(info['healed_at'], 0)
            self.assertEqual(info['heal_count'], 7, 'healed_at 损坏不应连带丢弃同文件里的合法 heal_count！')
            self.assertEqual(info['pin_sha256'], 'abcd1234')

            heal.write_bytes(b'{"heal_count": 9, "pad": "' + b'x' * (1024 * 1024 + 32) + b'"}')
            with mock.patch.object(portal, '_resolve_live_cert', return_value=(good_cert, 'a.com', ['a.com'], False)), \
                 mock.patch.object(portal.subprocess, 'run', return_value=subprocess.CompletedProcess(
                     ['openssl'], 0,
                     stdout='issuer=CN=CA\nnotBefore=Jan  1 00:00:00 2026 GMT\nnotAfter=Jan  1 00:00:00 2028 GMT\n',
                     stderr='')):
                info2 = portal.cert_status(root, meta={}, selfheal_state_path=heal)
            self.assertEqual(info2['heal_count'], 0, '超过 1 MiB 的自愈状态文件必须拒绝读取')

    def test_systemd_state_snapshot_and_restore_unit_file_guards(self):
        """_systemd_state/_systemd_service_snapshot 须拒非法 unit 并带 errors='replace'；_restore_systemd_unit_file 须拒符号链接并兼容无 fchmod 与清理异常。"""
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            return subprocess.CompletedProcess(cmd, 0, stdout='active\n', stderr='')

        with mock.patch.object(portal.subprocess, 'run', side_effect=fake_run):
            self.assertEqual(portal._systemd_state('--all'), '')
            self.assertEqual(portal._systemd_service_snapshot('xray\nfoo'), {'active': '', 'enabled': ''})
            self.assertEqual(calls, [], '非法 unit 绝不得调用 systemctl')

            self.assertEqual(portal._systemd_state('xray'), 'active')
            self.assertTrue(all(kw.get('errors') == 'replace' for _, kw in calls))

        with tempfile.TemporaryDirectory() as td:
            unit = Path(td) / 'test.service'
            unit.write_bytes(b'old')
            real_is_symlink = Path.is_symlink

            def fake_is_symlink(self_path):
                if self_path == unit:
                    return True
                return real_is_symlink(self_path)

            with mock.patch.object(Path, 'is_symlink', autospec=True, side_effect=fake_is_symlink):
                with self.assertRaises(OSError):
                    portal._restore_systemd_unit_file(unit, b'new')

            # 正常写入：在 Windows（无 os.fchmod）下也应能原子恢复，且异常路径 unlink 报错不得掩盖原异常
            portal._restore_systemd_unit_file(unit, b'restored-unit')
            self.assertEqual(unit.read_bytes(), b'restored-unit')

    def test_read_reality_online_ips_survives_unhashable_uids_and_sync_isolates_unlink_error(self):
        """read_reality_online_ips 面对不可哈希 uids 元素不得崩溃；sync_reality_iplimit_rules 清理临时规则失败不得掩盖原异常。"""
        def fake_run(cmd, **kwargs):
            if 'statsgetallonlineusers' in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout='{"users": ["user>>>alice>>>online"]}', stderr='')
            if 'statsonlineiplist' in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout='{"ips": {"203.0.113.5": 1}}', stderr='')
            if 'lsrules' in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout='{"rules": []}', stderr='')
            if 'adrules' in cmd:
                raise RuntimeError('adrules boom')
            return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')

        # 包含不可哈希的 dict/list 脏 uid，不能抛 TypeError
        res = portal.read_reality_online_ips(
            '/usr/local/bin/xray', '127.0.0.1:10085', ['alice', {'bad': 1}, ['x'], 'bob\nctrl'], run=fake_run)
        self.assertEqual(res, {'alice': {'203.0.113.5'}})

        # adrules 抛 RuntimeError 且 finally os.unlink 也抛 OSError 时，必须保留原始 RuntimeError
        real_unlink = os.unlink
        created_tmp = []

        def failing_unlink(p):
            created_tmp.append(p)
            try:
                real_unlink(p)
            except OSError:
                pass
            raise OSError('unlink failed')

        desired = {portal.REALITY_IPLIMIT_TAG_PREFIX + 'u1': {'ruleTag': portal.REALITY_IPLIMIT_TAG_PREFIX + 'u1'}}
        with mock.patch.object(portal.os, 'unlink', side_effect=failing_unlink):
            with self.assertRaisesRegex(RuntimeError, 'adrules boom'):
                portal.apply_reality_iplimit('/usr/local/bin/xray', '127.0.0.1:10085', desired, run=fake_run)
        self.assertTrue(created_tmp)


if __name__ == '__main__':
    unittest.main()
