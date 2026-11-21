"""回归测试：_h_post_install_xray 停用护栏与锁内读端口，以及 prepare() 非对象 meta 与非法端口校验。"""

import ast
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')


class InstallXraySuspendAndPrepareGuardsTests(unittest.TestCase):
    def test_install_xray_blocks_when_suspended_before_heavy_slot_and_locks_data_read(self):
        start = SRC.index('        def _h_post_install_xray(self, prefix):')
        end = SRC.index('        def _h_post_manage_reality(self, prefix):', start)
        body = SRC[start:end]
        self.assertIn("unit_suspended('xray')", body,
                      '_h_post_install_xray 必须拦截整机流量超额停用状态，避免绕过停用或误报失败')
        self.assertLess(body.index("unit_suspended('xray')"),
                        body.index('self._extend_deadline(300, heavy=True)'),
                        '停用护栏应在申领重型槽之前触发')
        tail = body[body.index("xr_state != 'active'"):]
        self.assertIn('with data_lock:', tail,
                      '读取 reality_config.port 必须在 data_lock 锁内执行')

    def test_prepare_rejects_non_dict_meta_and_invalid_or_bool_port(self):
        with tempfile.TemporaryDirectory() as td:
            meta_file = Path(td) / 'client_meta.json'
            meta_file.write_text('["not-an-object"]', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'JSON 对象'):
                portal.prepare(str(meta_file), 18080)

            meta_file.write_text(json.dumps({'auth_password': 'secret'}), encoding='utf-8')
            for bad_port in (True, False, 0, -1, 70000, 'abc'):
                with self.subTest(bad_port=bad_port):
                    with self.assertRaisesRegex(ValueError, '端口'):
                        portal.prepare(str(meta_file), bad_port)


if __name__ == '__main__':
    unittest.main()
