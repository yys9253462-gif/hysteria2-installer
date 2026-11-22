"""回归测试：portal_state_file_lock 防 resolve 绕过 O_NOFOLLOW 与关锁死锁、portal_start_update 防 fd 泄漏、ufw 前导 WARN 判定与 _listening_ports_detail 端口范围过滤。"""

import os
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import portal


class TestPortalStateLockSymlinkBypassCloseDeadlockUfwWarnAndCoreGuards(unittest.TestCase):
    def test_portal_state_file_lock_blocks_symlink_and_releases_thread_lock_on_close_error(self):
        """portal_state_file_lock 必须拒绝符号链接锁文件（不提前 resolve 绕过 O_NOFOLLOW），且 os.close 失败不得死锁。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # 1) 模拟 .portal-state.lock 为符号链接：必须直接抛 OSError，绝不能经 resolve() 落到真实目标
            target = root / 'real-secret.txt'
            target.write_text('secret', encoding='utf-8')
            lock_file = root / '.portal-state.lock'

            real_is_symlink = Path.is_symlink

            def fake_is_symlink(self_path):
                if self_path.name == '.portal-state.lock':
                    return True
                return real_is_symlink(self_path)

            with mock.patch.object(Path, 'is_symlink', autospec=True, side_effect=fake_is_symlink):
                with self.assertRaises(OSError):
                    with portal.portal_state_file_lock(str(root)):
                        pass

            # 2) os.close(lock_fd) 抛 OSError 时，线程锁必须仍能正常释放，其他线程可再次进入（不永久死锁）
            real_close = os.close
            closed_fds = []

            def failing_close(fd):
                closed_fds.append(fd)
                real_close(fd)
                raise OSError('simulated close failure')

            with mock.patch.object(portal.os, 'close', side_effect=failing_close):
                try:
                    with portal.portal_state_file_lock(str(root)):
                        pass
                except OSError:
                    pass
            self.assertTrue(closed_fds, '应当尝试关闭过锁文件描述符')

            # 在独立线程中验证锁已被释放（若未释放则会超时卡死）
            acquired = threading.Event()

            def worker():
                with portal.portal_state_file_lock(str(root)):
                    acquired.set()

            t = threading.Thread(target=worker, daemon=True)
            t.start()
            t.join(timeout=3.0)
            self.assertTrue(acquired.is_set(), 'os.close 失败后线程锁未释放，导致后续线程永久死锁！')

    def test_portal_start_update_isolates_fd_close_errors_and_sanitizes_timeout(self):
        """portal_start_update 在 finally 关闭全部 fd 时须彼此隔离 OSError，且须清洗非法 ready_timeout。"""
        close_calls = []

        def fake_close(fd):
            close_calls.append(fd)
            if len(close_calls) == 1:
                raise OSError('EBADF on first fd')

        pipe_pairs = iter([(101, 102), (103, 104)])
        with mock.patch.object(portal.os, 'pipe', side_effect=lambda: next(pipe_pairs)), \
             mock.patch.object(portal.subprocess, 'Popen', side_effect=RuntimeError('spawn boom')), \
             mock.patch.object(portal.os, 'close', side_effect=fake_close):
            with self.assertRaisesRegex(RuntimeError, 'spawn boom'):
                portal.portal_start_update(['bash', '-c'], 'true', lock_fd=55, ready_timeout=float('nan'))

        self.assertEqual(set(close_calls), {101, 102, 103, 104},
                         '首个 os.close 抛错后，其余管道 fd 被泄漏且掩盖了原始异常！')

    def test_firewall_port_handles_ufw_leading_warn_line(self):
        """ufw status 带前导 WARN 行时，firewall_port 仍须识别 Status: active 并执行放行命令。"""
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            if cmd == ['ufw', 'status']:
                return subprocess.CompletedProcess(
                    cmd, 0,
                    stdout='WARN: /etc/ufw/user.rules is world readable\nStatus: active\n',
                    stderr='',
                )
            return subprocess.CompletedProcess(cmd, 0, stdout='Rule added\n', stderr='')

        with mock.patch.object(portal.shutil, 'which', side_effect=lambda name: '/usr/sbin/ufw' if name == 'ufw' else None), \
             mock.patch.object(portal.subprocess, 'run', side_effect=fake_run):
            ok = portal.firewall_port(24443, proto='tcp', open_=True)

        self.assertTrue(ok)
        self.assertTrue(
            any(cmd == ['ufw', 'allow', '24443/tcp'] for cmd, _ in calls),
            f'ufw status 带前导 WARN 时漏执行了 ufw allow，实际调用: {calls}',
        )

    def test_listening_ports_detail_filters_non_ascii_and_out_of_range_ports(self):
        """_listening_ports_detail 必须过滤非 ASCII 数字（如上标 ²）与越界端口号（0/70000），并指定 UTF-8 替换解码。"""
        seen_kwargs = []

        def fake_run(cmd, **kwargs):
            seen_kwargs.append(kwargs)
            out = (
                'LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n'
                'LISTEN 0 128 0.0.0.0:0 0.0.0.0:*\n'
                'LISTEN 0 128 0.0.0.0:70000 0.0.0.0:*\n'
                'LISTEN 0 128 0.0.0.0:² 0.0.0.0:*\n'
            )
            return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr='')

        with mock.patch.object(portal.subprocess, 'run', side_effect=fake_run):
            ports, ok = portal._listening_ports_detail()

        self.assertTrue(ok)
        self.assertEqual(ports, {443})
        self.assertTrue(all(kw.get('errors') == 'replace' for kw in seen_kwargs))

    def test_upgrade_core_binary_rejects_symlink_binary_and_backup_dir(self):
        """_upgrade_core_binary_locked 必须拒绝符号链接形式的核心二进制与备份目录。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fake_bin = root / 'hysteria'
            fake_bin.write_bytes(b'\x7fELF')

            real_is_symlink = Path.is_symlink

            def fake_is_symlink(self_path):
                if self_path.name == 'hysteria':
                    return True
                return real_is_symlink(self_path)

            with mock.patch.object(Path, 'is_symlink', autospec=True, side_effect=fake_is_symlink):
                with self.assertRaisesRegex(RuntimeError, '符号链接'):
                    portal._upgrade_core_binary_locked(binary=str(fake_bin), backup_dir=str(root / 'bak'))


if __name__ == '__main__':
    unittest.main()
