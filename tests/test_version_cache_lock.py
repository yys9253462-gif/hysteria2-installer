"""回归测试：_ver_cache 与 _core_ver_cache 必须受模块级 _ver_cache_lock 并发加锁保护。"""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORTAL = ROOT / 'portal.py'


class VersionCacheLockTests(unittest.TestCase):
    def test_module_level_ver_cache_lock_protects_remote_shas_check_version_and_upgrade_worker(self):
        src = PORTAL.read_text(encoding='utf-8')
        self.assertIn('_ver_cache_lock = threading.Lock()', src)

        shas_start = src.index('    def _remote_root_shas():')
        shas_end = src.index('    def _version_triple(', shas_start)
        self.assertIn('with _ver_cache_lock:', src[shas_start:shas_end])

        cv_start = src.index('        def _h_get_check_version(self, subpath):')
        cv_end = src.index('        def _h_get_reality_status(self, subpath):', cv_start)
        self.assertIn('with _ver_cache_lock:', src[cv_start:cv_end])

        uw_start = src.index('                def upgrade_worker():')
        uw_end = src.index('                try:\n                    self.reply_json(200,', uw_start)
        self.assertIn('with _ver_cache_lock:', src[uw_start:uw_end])


if __name__ == '__main__':
    unittest.main()
