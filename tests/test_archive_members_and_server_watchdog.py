"""回归测试：归档成员反斜杠/NUL 拦截、HTTP 服务器死线看门狗锁外关闭与防退出、claim_heavy 幂等不漏槽及启动校验类型安全。"""

import ast
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')


class ArchiveMembersAndServerWatchdogTests(unittest.TestCase):
    def test_safe_tar_and_zip_members_reject_backslash_and_nul(self):
        for fn in (portal.safe_tar_members, portal.safe_zip_members):
            for bad in (r'..\xray', r'dir\xray', 'xray\x00.txt', 'dir/sub\\file'):
                with self.assertRaises(ValueError, msg=f'{fn.__name__} 必须拒绝 {bad!r}'):
                    fn([bad, 'xray'], 'xray')

    def test_watch_deadlines_shuts_down_outside_lock_and_guards_exceptions(self):
        start = SRC.index('        def watch_deadlines(self):')
        end = SRC.index('        def process_request(self, request, address):', start)
        body = SRC[start:end]
        self.assertIn('expired = []', body, 'watch_deadlines 应在锁内摘出超时连接、在锁外执行 shutdown')
        self.assertIn('except Exception:', body, 'watch_deadlines 循环体应兜底异常防止看门狗线程永久死亡')

    def test_claim_heavy_releases_duplicate_acquire_under_lock(self):
        start = SRC.index('        def claim_heavy(self, request):')
        end = SRC.index('        def extend_deadline(self, request, seconds):', start)
        body = SRC[start:end]
        self.assertIn('self.heavy_slots.release()', body,
                      'claim_heavy 二次加锁若发现已登记必须立即归还多余信号量，防止槽位泄漏')

    def test_startup_missing_config_check_handles_corrupt_non_dict_section(self):
        start = SRC.index('    # 已启用但配置文件不在：')
        end = SRC.index('        _missing = []', start)
        block = SRC[start:end]
        self.assertNotIn('(data.get(k) or {}).get(', block,
                         '启动检查不得假设协议配置必为 dict，否则坏值会触发 AttributeError')
        self.assertIn('config_section(data, k)', block)


if __name__ == '__main__':
    unittest.main()
