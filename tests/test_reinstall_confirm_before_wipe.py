"""reinstall-debian13.sh 必须先确认再清盘（2026-11-04 修）。

整个脚本需要 root、真块设备与网络，无法在单测里端到端跑；这里检查顶层语句的执行顺序：
调用 wipe_disk / release_disk 的那段必须排在「确认开始？」之后，且同样受 CHECK_ONLY/DRY_RUN 保护。
"""
import unittest
from pathlib import Path

SRC = (Path(__file__).resolve().parents[1] / 'reinstall-debian13.sh').read_text(encoding='utf-8')


class ReinstallConfirmBeforeWipeTests(unittest.TestCase):
    def test_wipe_runs_after_confirmation(self):
        confirm = SRC.index("确认开始？输入 yes 回车")
        calls = [i for i in range(len(SRC)) if SRC.startswith('            wipe_disk "$DISK"', i)]
        self.assertTrue(calls, 'wipe_disk 调用不见了')
        for pos in calls:
            self.assertGreater(pos, confirm, '清盘发生在用户确认之前')

    def test_wipe_still_guarded_by_check_and_dry_run(self):
        pos = SRC.index('            wipe_disk "$DISK"')
        guard = SRC.rfind('if [ "$CHECK_ONLY" != "1" ] && [ "$DRY_RUN" != "1" ]; then', 0, pos)
        self.assertGreater(guard, SRC.index("确认开始？输入 yes 回车"))


if __name__ == '__main__':
    unittest.main()
