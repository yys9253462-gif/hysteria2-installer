"""unit_suspended 的作用域回归测试（2026-10-26）。

真实故障（生产实测）：
  12 台节点批量升级到 ca3272ce 之后，在面板点「启用 VLESS Encryption」返回
    节点门户报错: name 'unit_suspended' is not defined

根因：
  `unit_suspended` 是 main() 内部的嵌套函数（约 4531 行），只有 main() 的
  作用域能看到它。模块级的 `serve()` 与 `apply_xray_config_with_meter()`
  里直接调用 `unit_suspended(...)`，运行时抛 NameError。

  为什么以前没炸：这两条路径只在「需要重新生成 Xray 配置 / 启动服务」时
  才走到。存量节点升级前配置已经生成好，不会重新进入；一旦启用新协议
  （VMess / VLESS Encryption）就必须写配置，于是必然触发。

  模块级本来就有 `_unit_suspended = lambda unit: False` 兜底，且 main()
  运行时会 `global _unit_suspended` 把它替换成真实现 —— 所以正确写法是
  模块级代码一律用 `_unit_suspended`。
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal


class TestUnitSuspendedScope(unittest.TestCase):
    def setUp(self):
        self.lines = (Path(portal.__file__).parent / 'portal.py').read_text(
            encoding='utf-8').splitlines()

    def _owner(self, lineno):
        """返回该行所属的顶层 def/class 名。"""
        for i in range(lineno - 1, -1, -1):
            line = self.lines[i]
            if line.startswith('def ') or line.startswith('class '):
                return line.split('(')[0][4:]
        return '<module>'

    def test_no_bare_unit_suspended_outside_main(self):
        """main() 之外的代码不得直接调用嵌套函数 unit_suspended。

        它们看不到 main() 的局部作用域，必然 NameError。
        """
        offenders = []
        for n, line in enumerate(self.lines, 1):
            if 'unit_suspended' not in line:
                continue
            if '_unit_suspended' in line or 'def unit_suspended' in line:
                continue
            # 注释里提到这个名字是正常的（说明性文字），不是调用。
            if line.lstrip().startswith('#'):
                continue
            owner = self._owner(n)
            if owner != 'main':
                offenders.append(f"{n}: [{owner}] {line.strip()}")
        self.assertEqual(
            offenders, [],
            "以下调用点看不到 main() 内的 unit_suspended，会抛 NameError：\n"
            + "\n".join(offenders))

    def test_module_level_fallback_exists(self):
        """模块级必须有 _unit_suspended 兜底，main() 才能安全地替换它。"""
        src = "\n".join(self.lines)
        self.assertIn('_unit_suspended = lambda unit: False', src,
                      '模块级兜底 _unit_suspended 缺失')
        self.assertIn('global _unit_suspended', src,
                      'main() 必须用 global 替换模块级实现')

    def test_apply_xray_config_with_meter_is_importable(self):
        """该函数在模块级必须可调用（不能因为引用未定义名而在调用时炸）。"""
        self.assertTrue(callable(getattr(portal, 'apply_xray_config_with_meter', None)),
                        'apply_xray_config_with_meter 未定义在模块级')


if __name__ == '__main__':
    unittest.main()
