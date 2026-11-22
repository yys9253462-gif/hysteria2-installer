"""回归测试：门户 CLI 生命周期（prepare/adopt/ensure_portal_access/restore_egress/repair/serve）与 GOST 单元读盘防符号链接及体积上限。"""

import ast
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import portal  # noqa: E402

SOURCE = (REPO / 'portal.py').read_text(encoding='utf-8')
TREE = ast.parse(SOURCE)


def _func_src(name):
    node = next(
        n for n in ast.walk(TREE)
        if isinstance(n, ast.FunctionDef) and n.name == name
    )
    return ast.get_source_segment(SOURCE, node) or ''


class PortalCliLifecycleAndGostUnitSymlinkSizeGuardsTests(unittest.TestCase):
    def test_prepare_and_adopt_reject_symlink_and_oversized_inputs(self):
        """prepare 与 _adopt_locked 须拒绝符号链接及超限 client_meta.json / portal.json。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            meta = root / 'client_meta.json'
            meta.write_bytes(b'{"a":"' + b'x' * (1024 * 1024 + 32) + b'"}')
            with self.assertRaisesRegex(ValueError, '1 MiB'):
                portal.prepare(meta, 18080)

            meta.write_text('{}', encoding='utf-8')
            with patch.object(Path, 'is_symlink', autospec=True, side_effect=lambda p: p == meta):
                with self.assertRaisesRegex(OSError, '符号链接'):
                    portal.prepare(meta, 18080)

            pjson = root / 'portal.json'
            pjson.write_bytes(b'{' + b' ' * (8 * 1024 * 1024 + 32) + b'}')
            with self.assertRaisesRegex(ValueError, '8 MiB'):
                portal._adopt_locked(meta, 18080)

            pjson.write_text('{}', encoding='utf-8')
            with patch.object(Path, 'is_symlink', autospec=True, side_effect=lambda p: p == pjson):
                with self.assertRaisesRegex(OSError, '符号链接'):
                    portal._adopt_locked(meta, 18080)

    def test_ensure_portal_access_and_restore_egress_reject_symlinks_and_oversized(self):
        """ensure_portal_access 须拒符号链接 portal-access.json；restore_egress_into_config 须拒符号链接与超大配置。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            access_p = root / 'portal-access.json'
            access_p.write_text('{}', encoding='utf-8')
            with patch.object(Path, 'is_symlink', autospec=True, side_effect=lambda p: p == access_p):
                with self.assertRaisesRegex(OSError, '符号链接'):
                    portal.ensure_portal_access(root, {'listen_port': 443}, {'token': 't', 'api_key': 'k'})

            pjson = root / 'portal.json'
            cfg = root / 'config.yaml'
            pjson.write_text(json.dumps({'warp_enabled': True, 'warp_rules': ['openai.com']}), encoding='utf-8')
            cfg.write_bytes(b'listen: :443\n' + b'#' * (4 * 1024 * 1024 + 32))
            self.assertFalse(portal.restore_egress_into_config(root, cfg))

            cfg.write_text('listen: :443\n', encoding='utf-8')
            with patch.object(Path, 'is_symlink', autospec=True, side_effect=lambda p: p == cfg):
                self.assertFalse(portal.restore_egress_into_config(root, cfg))

    def test_repair_missing_api_key_and_serve_reject_symlink_and_oversized_portal_json(self):
        """repair_missing_api_key 与 serve 须拒绝符号链接及超 8 MiB portal.json。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pjson = root / 'portal.json'
            pjson.write_bytes(b'{' + b' ' * (8 * 1024 * 1024 + 32) + b'}')
            with self.assertRaisesRegex(ValueError, '8 MiB'):
                portal.repair_missing_api_key(pjson, {'api_key': 'k'})

            pjson.write_text('{}', encoding='utf-8')
            with patch.object(Path, 'is_symlink', autospec=True, side_effect=lambda p: p == pjson):
                with self.assertRaisesRegex(OSError, '符号链接'):
                    portal.repair_missing_api_key(pjson, {'api_key': 'k'})
                with self.assertRaisesRegex(OSError, '符号链接'):
                    portal.serve(pjson)

    def test_recover_xray_iplimit_worker_and_gost_unit_guards(self):
        """recover_xray_service_on_start / reality_iplimit_worker / reload_gost / ensure_gost_unit 须防符号链接与限体积。"""
        with tempfile.TemporaryDirectory() as td:
            xj = Path(td) / 'xray.json'
            xj.write_text(json.dumps({'inbounds': [{'tag': portal.REALITY_INBOUND_TAG, 'settings': {'clients': []}}]}), encoding='utf-8')
            with patch.object(Path, 'is_symlink', autospec=True, side_effect=lambda p: p == xj):
                self.assertEqual(
                    portal.recover_xray_service_on_start(
                        {'users': {}}, threading.Lock(), lambda *a, **k: True,
                        config_path=xj, suspended=lambda _: False, systemd_state=lambda _: 'inactive',
                    ),
                    '',
                )

        iplimit_src = _func_src('reality_iplimit_worker')
        self.assertIn('cfg_path.is_symlink()', iplimit_src)
        self.assertIn('1024 * 1024', iplimit_src)

        reload_src = _func_src('reload_gost')
        self.assertIn('is_symlink()', reload_src)
        self.assertIn('2 * 1024 * 1024', reload_src)

        gost_unit_src = _func_src('ensure_gost_unit')
        self.assertIn('unit_path.is_symlink()', gost_unit_src)
        self.assertIn("getattr(os, 'O_NOFOLLOW', 0)", gost_unit_src)


if __name__ == '__main__':
    unittest.main()
