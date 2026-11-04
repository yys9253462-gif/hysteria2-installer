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


def load(env):
    tree = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))
    nodes = [copy.deepcopy(n) for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
             and n.name in ('gost_owned', 'ensure_gost_unit')]
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


if __name__ == '__main__':
    unittest.main()
