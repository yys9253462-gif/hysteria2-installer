"""回归测试：_upgrade_core_binary_locked 回滚 mkstemp 异常不吞原错且仍尝试重启；acquire_core_operation_lock 异常必关 fd。"""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class UpgradeCoreRollbackAndLockFdTests(unittest.TestCase):
    def test_acquire_core_operation_lock_closes_fd_on_unexpected_flock_error(self):
        closed = []
        fake_fcntl = type('F', (), {
            'LOCK_EX': 2,
            'LOCK_NB': 4,
            'flock': staticmethod(lambda fd, op: (_ for _ in ()).throw(OSError('flock io error'))),
        })()
        with mock.patch.object(portal, 'fcntl', fake_fcntl), \
             mock.patch.object(portal.os, 'open', return_value=77), \
             mock.patch.object(portal.os, 'close', side_effect=lambda fd: closed.append(fd)):
            with self.assertRaises(OSError):
                portal.acquire_core_operation_lock('/tmp')
        self.assertEqual(closed, [77], 'flock 抛非 BlockingIOError 时泄漏了锁文件描述符')

    def test_upgrade_core_rollback_mkstemp_failure_does_not_mask_error_or_skip_restart(self):
        src = (ROOT / 'portal.py').read_text(encoding='utf-8')
        start = src.index('def _upgrade_core_binary_locked(')
        end = src.index('_portal_state_lock_guard =', start)
        block = src[start:end]
        rb_start = block.index('if replaced and backup is not None:')
        rb_block = block[rb_start:]
        # mkstemp 必须在 try 内部，不能放在 try 之前导致 OSError 跳过 _restart_hy2
        self.assertLess(rb_block.index('try:'), rb_block.index('tempfile.mkstemp('),
                        '回滚中的 tempfile.mkstemp 放在了 try 块之外，磁盘异常时会掩盖原错并跳过重启')


if __name__ == '__main__':
    unittest.main()
