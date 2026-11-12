"""ensure_gost_unit 不改写不归本工具管理的 gost.service（2026-11-04 修）。"""
import ast
import copy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


def load(env, names=('gost_owned', 'ensure_gost_unit')):
    tree = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))
    nodes = [copy.deepcopy(n) for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
             and n.name in names]
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<gost>', 'exec'), env)
    return env


class GostUnitOwnershipTests(unittest.TestCase):
    def test_foreign_unit_is_left_alone(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            unit = root / 'gost.service'
            foreign = '[Service]\nExecStart=/usr/local/bin/gost -C /etc/gost/config.yml\n'
            unit.write_text(foreign)
            real_path = Path

            def fake_path(p):
                p = str(p)
                if p == '/etc/systemd/system/gost.service':
                    return real_path(unit)
                if p == '/etc/hysteria/.hy2-gost-owned':
                    return real_path(root / 'no-marker')
                return real_path(p)
            run = mock.Mock()
            env = load({'Path': fake_path, 'subprocess': mock.Mock(run=run),
                        'GOST_SELFCHECK_PATH': real_path('/usr/local/lib/hy2-gost-selfcheck'),
                        'GOST_UNIT_CONTENT': 'OURS', 'write_gost_selfcheck': mock.Mock(),
                        '_log_ignored': lambda *a: None})
            env['ensure_gost_unit']()
            self.assertEqual(unit.read_text(), foreign)
            run.assert_not_called()


class GostSelfcheckTests(unittest.TestCase):
    """单元的 ExecStartPost 依赖自检脚本：脚本不在时 systemd 每次启动都判失败并停掉 gost（2026-11-13 修）。"""

    def env_for(self, root, selfcheck, unit_text):
        unit = root / 'gost.service'
        unit.write_text(unit_text, encoding='utf-8')
        marker = root / 'owned'
        marker.write_text('', encoding='utf-8')
        real_path = Path

        def fake_path(p):
            p = str(p)
            if p == '/etc/systemd/system/gost.service':
                return real_path(unit)
            if p == '/etc/hysteria/.hy2-gost-owned':
                return real_path(marker)
            return real_path(p)
        run = mock.Mock()
        env = load({'Path': fake_path, 'subprocess': mock.Mock(run=run), 'os': portal.os,
                    'GOST_SELFCHECK_PATH': selfcheck, 'GOST_SELFCHECK_SCRIPT': '#!/bin/sh\nexit 0\n',
                    'GOST_UNIT_CONTENT': 'NEW UNIT', '_log_ignored': lambda *a: None},
                   names=('gost_owned', 'ensure_gost_unit', 'write_gost_selfcheck'))
        return env, unit, run

    def current_unit(self, selfcheck):
        return ('[Service]\nExecStart=/usr/local/bin/gost -C /etc/hysteria/gost.yml -R 30s\n'
                'ExecReload=/bin/kill -HUP $MAINPID\nExecStartPost=%s\n' % selfcheck.as_posix())

    def test_a_deleted_selfcheck_is_put_back_for_a_current_unit(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            selfcheck = root / 'lib' / 'hy2-gost-selfcheck'
            text = self.current_unit(selfcheck)
            env, unit, run = self.env_for(root, selfcheck, text)
            env['ensure_gost_unit']()
            self.assertTrue(selfcheck.is_file(), '自检脚本没被补回，gost 下次启动必然失败')
            self.assertEqual(unit.read_text(encoding='utf-8'), text)
            run.assert_not_called()

    def test_unit_is_not_switched_to_a_selfcheck_that_could_not_be_written(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'blocked').write_text('not a directory', encoding='utf-8')
            selfcheck = root / 'blocked' / 'hy2-gost-selfcheck'
            old = '[Service]\nExecStart=/usr/local/bin/gost -C /etc/hysteria/gost.yml -R 30s\n'
            env, unit, run = self.env_for(root, selfcheck, old)
            env['ensure_gost_unit']()
            self.assertEqual(unit.read_text(encoding='utf-8'), old, '换上了引用不存在脚本的新单元')
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
