"""回归测试：门户自更新原子备份/回滚与新建文件清理隔离，以及 Xray/GOST 单元文件原子写入。"""

import ast
import copy
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')


def _load_portal_fns(env, names):
    tree = ast.parse(PORTAL_SRC)
    nodes = [copy.deepcopy(n) for n in ast.walk(tree)
             if isinstance(n, ast.FunctionDef) and n.name in names]
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<portal-fns>', 'exec'), env)
    return env


class PortalUpgradeAndUnitAtomicWritesTests(unittest.TestCase):
    def test_portal_self_upgrade_backup_and_rollback_avoid_direct_copy2_and_isolate_unlink(self):
        """do-upgrade 的备份、回滚与新建文件清理必须原子化且隔离 unlink 异常。"""
        start = PORTAL_SRC.index('                    backups = []')
        end = PORTAL_SRC.index('                    if not changed:', start)
        block = PORTAL_SRC[start:end]
        self.assertNotIn('shutil.copy2(str(dest), str(bak))', block, '备份仍直接 shutil.copy2 写目标备份文件')
        self.assertNotIn('shutil.copy2(str(bak), str(dest))', block, '回滚仍直接 shutil.copy2 覆写门户源码')
        self.assertIn('portal_update.rollback_unlink', block, '清理 created 文件缺少 OSError 异常隔离')

    def test_write_xray_unit_writes_atomically_without_bare_write_text(self):
        """write_xray_unit 必须使用同目录临时文件 + os.replace 原子落盘。"""
        with tempfile.TemporaryDirectory() as td:
            unit = Path(td) / 'xray.service'
            unit.write_text('old-unit\n', encoding='utf-8')
            run_mock = mock.Mock()
            real_path = Path

            def fake_path(p):
                if str(p) == '/etc/systemd/system/xray.service':
                    return unit
                return real_path(p)

            with mock.patch.object(portal, 'Path', side_effect=fake_path), \
                 mock.patch.object(portal.subprocess, 'run', run_mock), \
                 mock.patch.object(Path, 'write_text', side_effect=AssertionError('不得直接 write_text 覆写 unit')):
                portal.write_xray_unit()

            self.assertEqual(unit.read_text(encoding='utf-8'), portal.XRAY_UNIT_CONTENT)
            self.assertEqual([p.name for p in Path(td).iterdir()], ['xray.service'])
            run_mock.assert_called_once()

    def test_ensure_gost_unit_writes_atomically_without_bare_write_text(self):
        """ensure_gost_unit 更新 gost.service 时必须原子写盘。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unit = root / 'gost.service'
            unit.write_text('[Service]\nExecStart=/usr/local/bin/gost -C /etc/hysteria/gost.yml -R 30s\n',
                            encoding='utf-8')
            marker = root / 'owned'
            marker.write_text('', encoding='utf-8')
            selfcheck = root / 'hy2-gost-selfcheck'
            selfcheck.write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
            real_path = Path

            def fake_path(p):
                s = str(p)
                if s == '/etc/systemd/system/gost.service':
                    return unit
                if s == '/etc/hysteria/.hy2-gost-owned':
                    return marker
                return real_path(p)

            run_mock = mock.Mock()
            env = _load_portal_fns(
                {
                    'Path': fake_path,
                    'os': os,
                    'subprocess': SimpleNamespace(run=run_mock),
                    'GOST_SELFCHECK_PATH': selfcheck,
                    'GOST_SELFCHECK_SCRIPT': '#!/bin/sh\nexit 0\n',
                    'GOST_UNIT_CONTENT': '[Service]\nExecStart=/usr/local/bin/gost -C /etc/hysteria/gost.yml -R 30s\nExecReload=/bin/kill -HUP $MAINPID\n',
                    '_log_ignored': lambda *a: None,
                },
                names=('gost_owned', 'ensure_gost_unit', 'write_gost_selfcheck'),
            )
            with mock.patch.object(Path, 'write_text', side_effect=AssertionError('不得直接 write_text 覆写 gost.service')):
                env['ensure_gost_unit']()

            self.assertEqual(unit.read_text(encoding='utf-8'), env['GOST_UNIT_CONTENT'])
            run_mock.assert_called_once()


if __name__ == '__main__':
    unittest.main()
