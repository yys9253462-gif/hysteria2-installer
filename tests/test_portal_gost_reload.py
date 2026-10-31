"""gost 入站代理的「配置改了但没生效」回归测试。

来源事故（2026-10-01 在 us 节点实测定位）：
用户在门户里新建 HTTP 代理，页面提示"创建成功"、二维码也出来了，
但**代理就是连不上** —— 因为新端口从未被监听。

根因是 `reload_gost()` 里的一个经典陷阱：

    try:
        subprocess.run(['systemctl', 'reload', 'gost'], timeout=2)
    except Exception:                 # ← 以为失败会抛异常
        ...kill -HUP...
        except Exception:
            ...restart...

`subprocess.run` **不检查退出码**，只在超时或找不到命令时才抛异常。
而 unit 没有 `ExecReload` 时，`systemctl reload` 会打印
"Job type reload is not applicable for unit gost.service." 并且
**以退出码 3 正常返回** —— 不抛异常，于是两个 fallback 成了永不执行的死代码。
结果：`gost.yml` 写进了新服务，进程却从未重载，端口一直不监听。

实测证据（服务器上复现）：
    systemctl reload gost              -> 退出码 3
    subprocess.run(...)                -> 不抛异常, returncode=3
    写配置含 :42194 后等 3 秒          -> ss 里没有 42194   ← BUG

本文件锁死三条不变量：
  1. reload 的成败必须**看 returncode**，不能靠 except 捕获；
  2. 两处生成的 unit（install.sh 与 portal.py）必须**完全一致**，
     且都必须含 ExecReload / -R 自动重载 / 启动自检；
  3. 启动自检脚本必须在"端口未监听"时返回非零。
"""
import ast
import threading
from types import SimpleNamespace
from unittest.mock import Mock
import importlib.util
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
INSTALL_SRC = (ROOT / 'install.sh').read_text(encoding='utf-8')

GOST_BIN = '/usr/local/bin/gost'
GOST_CONFIG = '/etc/hysteria/gost.yml'
SELFCHECK_PATH = '/usr/local/lib/hy2-gost-selfcheck'


def _const(name):
    """取 portal.py 里某个常量赋值的求值结果。

    ⚠️ 必须取**整个 Assign 节点**的源码，不能只取 `n.value`。
    常量写作 `X = ('a' 'b')` 时，`get_source_segment(src, n.value)` 只返回
    括号**内部**的片段，丢掉外层圆括号 —— 拼回去就成了 `X = 'a'` 后跟一串
    独立表达式语句，相邻字符串字面量不再隐式拼接，**静默只剩第一行**。
    """
    for node in ast.walk(ast.parse(PORTAL_SRC)):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    stmt = ast.get_source_segment(PORTAL_SRC, node)
                    indent = ' ' * node.col_offset
                    body = ('if True:\n'
                            + indent + '    ' + stmt + '\n'
                            + indent + '    __out = ' + name)
                    ns = {'GOST_SELFCHECK_PATH': Path(SELFCHECK_PATH)}
                    exec(body, ns)                       # noqa: S102
                    return ns['__out']
    raise AssertionError('portal.py 里找不到常量 ' + name)


def _heredoc(marker, quote="<<'%s'"):
    """从 install.sh 取出某个 heredoc 的内容（去 CRLF、补回结尾换行）。

    ⚠️ 两个坑：
      - Windows 工作区的 install.sh 是 CRLF（core.autocrlf=true），
        而 portal.py 里的常量是 LF；不统一会得到
        "splitlines 一样、== 却是假" 的诡异结果。
      - heredoc 结尾的 "\\nEOF" 会吃掉最后一个换行符，而 Python 常量保留它；
        只差这 1 个字节就会假报不一致。
    """
    pattern = (re.escape('cat > ') + r'\S+ ' + re.escape(quote % marker)
               + r'\n(.*?)\n' + re.escape(marker))
    m = re.search(pattern, INSTALL_SRC, re.S)
    if not m:
        raise AssertionError('install.sh 里找不到 heredoc ' + marker)
    return m.group(1).replace('\r\n', '\n') + '\n'


def _shell_unit():
    m = re.search(r'cat > /etc/systemd/system/gost\.service <<EOF\n(.*?)\nEOF',
                  INSTALL_SRC, re.S)
    if not m:
        raise AssertionError('install.sh 里找不到 gost.service 的 heredoc')
    body = (m.group(1)
            .replace('${GOST_BIN}', GOST_BIN)
            .replace('${GOST_CONFIG}', GOST_CONFIG)
            .replace('\\$MAINPID', '$MAINPID'))
    return body.replace('\r\n', '\n') + '\n'


class ReloadGostChecksReturncode(unittest.TestCase):
    """reload_gost 必须依据 returncode 判断成败，而不是依赖异常。"""

    def setUp(self):
        tree = ast.parse(PORTAL_SRC)
        self.fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == 'reload_gost':
                self.fn = node
        self.assertIsNotNone(self.fn, 'portal.py 里找不到 reload_gost')
        self.src = ast.get_source_segment(PORTAL_SRC, self.fn)
        # ⚠️ 一堆断言都要"只看代码不看注释"：reload_gost 的 docstring 里
        # 为了讲清踩过的坑，自然会提到 returncode / kill 这些字样。
        # 谁要是把它们和代码混在一起查，就会得到"改坏了也照样通过"的假测试。
        body = list(self.fn.body)
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            body = body[1:]                      # 去掉 docstring
        self.code = '\n'.join(
            ast.get_source_segment(PORTAL_SRC, n) or '' for n in body)

    def test_checks_returncode(self):
        """必须真的读取 subprocess 的 returncode —— 这是修掉本 bug 的关键。

        用 AST 找「属性访问 .returncode」这个**语法结构**，而不是在源码文本里
        搜字符串：注释里为了讲清坑也会写 "returncode"，按文本搜会得到
        「把检查删了、测试照样通过」的假绿。
        """
        found = any(
            isinstance(n, ast.Attribute) and n.attr == 'returncode'
            for n in ast.walk(self.fn))
        self.assertTrue(
            found,
            'reload_gost 没有读取 .returncode：systemctl reload 在 unit 无 '
            'ExecReload 时会返回 3 且不抛异常，整个重载会静默失效')

    def test_has_restart_fallback(self):
        """必须有 restart 兜底 —— 它是一定能生效的那条路径。"""
        self.assertIn('restart', self.code,
                      'reload_gost 缺少 restart 兜底')

    def test_restart_reachable_when_reload_returns_nonzero(self):
        run = Mock(side_effect=[SimpleNamespace(returncode=3), SimpleNamespace(returncode=0)])
        env = {'Path': lambda path: SimpleNamespace(exists=lambda: True),
               'gost_operation_lock': threading.RLock(), 'ensure_gost_unit': Mock(),
               'write_gost_config': Mock(), 'gost_status': lambda: True,
               'gost_ports_ready': lambda: True, 'subprocess': SimpleNamespace(run=run),
               'time': SimpleNamespace(sleep=lambda seconds: None),
               # reload_gost 是模块级函数，只能看到模块级的 _unit_suspended；
               # 两个名字都给上，避免桩与实现命名漂移造成假红。
               'unit_suspended': lambda unit: False,
               '_unit_suspended': lambda unit: False}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[self.fn], type_ignores=[])),
                     'gost-reload-behavior', 'exec'), env)
        self.assertTrue(env['reload_gost']())
        self.assertIn(['systemctl', 'restart', 'gost'], [c.args[0] for c in run.call_args_list])

    def test_reload_success_without_listeners_is_not_a_false_success(self):
        run = Mock(return_value=SimpleNamespace(returncode=0))
        env = {'Path': lambda path: SimpleNamespace(exists=lambda: True),
               'gost_operation_lock': threading.RLock(), 'ensure_gost_unit': Mock(),
               'write_gost_config': Mock(), 'gost_status': lambda: True,
               'gost_ports_ready': lambda: False, 'subprocess': SimpleNamespace(run=run),
               'time': SimpleNamespace(sleep=lambda seconds: None),
               # reload_gost 是模块级函数，只能看到模块级的 _unit_suspended；
               # 两个名字都给上，避免桩与实现命名漂移造成假红。
               'unit_suspended': lambda unit: False,
               '_unit_suspended': lambda unit: False}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[self.fn], type_ignores=[])),
                     'gost-listener-readiness', 'exec'), env)
        self.assertFalse(env['reload_gost']())

    def test_no_manual_sighup_fallback(self):
        """不能再回到"只靠 kill -HUP 兜底"的老写法。

        老写法的特征是 except 块里嵌套 try 再手工发 SIGHUP —— 那套 fallback
        在 unit 没有 ExecReload 时压根不会执行，是死代码。
        """
        self.assertNotIn('kill', self.code,
                         'reload_gost 不该再手工 kill -HUP：'
                         '直接交给 systemctl（unit 里已有 ExecReload），'
                         '失败就 restart，更简单也更可靠')

    def test_unit_selfheal_before_write(self):
        """写配置前要先自愈 unit，否则老机器永远拿不到 ExecReload。"""
        self.assertIn('ensure_gost_unit', self.code,
                      'reload_gost 没有调用 ensure_gost_unit：'
                      '已装机的旧 unit 缺 ExecReload，reload 会一直静默失败')


class ReloadGostStartsWhenInactive(unittest.TestCase):
    """gost 已装但未运行时，写配置后必须把它拉起来（而不是静默跳过）。

    来源事故（2026-10-01 在 jp2 节点实测定位）：
    控制台「代理服务 → 新建代理」创建成功、条目也出现在页面上，
    但对应端口一直不监听 —— 因为机器上 gost 处于 inactive，
    而旧逻辑第一行就是：

        if not gost_status():
            return                     # ← 未运行就什么都不做

    于是配置没写、服务没起，但调用方拿到的是 ok=true。
    现象与「reload 不查 returncode」高度相似（页面说成功、代理连不上），
    区别在于这次连 gost.yml 都没被写。

    时间线证据（tokyo 57.181.25.17）：
        19:55:00  控制台创建代理成功，条目入库
        19:55~19:57  gost 无任何启动记录（静默 return）
        19:57:14  gost 才被后续手动操作拉起     ← 不是 add 拉起的
    """

    def setUp(self):
        tree = ast.parse(PORTAL_SRC)
        self.fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == 'reload_gost':
                self.fn = node
        self.assertIsNotNone(self.fn, 'portal.py 里找不到 reload_gost')
        body = list(self.fn.body)
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            body = body[1:]                      # 去掉 docstring
        self.code = '\n'.join(
            ast.get_source_segment(PORTAL_SRC, n) or '' for n in body)

    def test_skip_guard_is_binary_presence_not_running_state(self):
        """跳过条件必须只看「二进制是否存在」，不能看服务是否在跑。

        用 AST 找顶层 `if not gost_status(): return` 这个形状 ——
        它正是"未运行就静默跳过"的元凶。
        """
        offenders = []
        for node in ast.walk(self.fn):
            if not isinstance(node, ast.If):
                continue
            src = ast.get_source_segment(PORTAL_SRC, node) or ''
            # 只有「单个 return」的守卫才是致命的；带 else 分支的处理不算
            if ('gost_status' in src and 'not ' in src
                    and len(node.body) == 1 and isinstance(node.body[0], ast.Return)
                    and not node.orelse
                    and '/usr/local/bin/gost' not in src):
                offenders.append(src.splitlines()[0].strip())
        self.assertEqual(
            offenders, [],
            'reload_gost 仍在「gost 未运行就直接 return」：已装但没跑时应写配置并 '
            '拉起服务，否则控制台报成功、端口却不监听')

    def test_skips_only_when_binary_missing(self):
        """唯一合法的跳过理由是二进制不存在。"""
        self.assertIn('/usr/local/bin/gost', self.code,
                      'reload_gost 应以「gost 二进制是否存在」作为跳过判据')

    def test_writes_config_unconditionally(self):
        """写配置必须在状态判断**之前**、且不在任何 if 分支内无条件执行。

        旧代码把整个流程卡在 `if not gost_status(): return` 之后，
        导致"没跑 = 连配置都不写"。这里断言 write_gost_config 出现在
        gost_status 之前，确保它不再被运行状态门禁挡住。
        """
        idx_cfg = self.code.find('write_gost_config')
        self.assertNotEqual(idx_cfg, -1, 'reload_gost 没有调用 write_gost_config')
        idx_status = self.code.find('gost_status')
        self.assertTrue(
            idx_status == -1 or idx_cfg < idx_status,
            'write_gost_config 出现在 gost_status 之后：写配置不该被运行状态门禁挡住')


class GostUnitConsistency(unittest.TestCase):
    """install.sh 与 portal.py 生成的 unit 必须一致，且含三项关键配置。"""
    def setUp(self):
        self.portal_unit = _const('GOST_UNIT_CONTENT')
        self.shell_unit = _shell_unit()

    def test_web_install_establishes_marker_only_after_managed_unit_write(self):
        source = PORTAL_SRC
        start = source.index('        def _h_post_install_gost(self, prefix):')
        end = source.index('        def _h_post_install_amneziawg(self, prefix):', start)
        body = source[start:end]
        unit_write = body.index("Path('/etc/systemd/system/gost.service').write_text")
        marker_write = body.index("owner_marker.touch(mode=0o600, exist_ok=True)")
        self.assertLess(unit_write, marker_write)
        self.assertIn("Path('/etc/hysteria/.hy2-gost-owned')", body)
        self.assertIn("owner_marker.chmod(0o600)", body)

    def test_units_identical(self):
        """两处产物必须完全一致 —— 不一致正是本 bug 的起因。

        历史上 install.sh 有 ExecReload、portal.py 没有：
        于是"命令行装的 gost"能被 reload，"门户装的 gost"不能。
        """
        self.assertEqual(
            self.shell_unit, self.portal_unit,
            'install.sh 与 portal.py 生成的 gost.service 内容不一致。\n'
            '--- install.sh ---\n%s\n--- portal.py ---\n%s'
            % (self.shell_unit, self.portal_unit))

    def test_unit_has_execreload(self):
        self.assertIn('ExecReload=/bin/kill -HUP $MAINPID', self.portal_unit,
                      'unit 缺 ExecReload：systemctl reload 会返回 3 且什么都不做')

    def test_unit_has_autoreload(self):
        """-R 是官方周期自动重载，作为兜底保险。"""
        self.assertIn('-R 30s', self.portal_unit,
                      'unit 缺 gost 的 -R 自动重载参数（兜底保障）')

    def test_unit_has_selfcheck(self):
        self.assertIn('ExecStartPost=' + SELFCHECK_PATH, self.portal_unit,
                      'unit 缺 ExecStartPost 自检：'
                      '"active 但无监听"的静默故障不会被发现')

    def test_unit_waits_network_online(self):
        self.assertIn('After=network-online.target', self.portal_unit,
                      'unit 应等 network-online.target，'
                      '否则开机时可能抢在网络就绪前启动而绑定失败')


class GostSelfcheckScript(unittest.TestCase):
    """启动自检脚本：两处一致 + 语法合法 + 行为正确。"""

    def setUp(self):
        self.portal_script = _const('GOST_SELFCHECK_SCRIPT')
        self.shell_script = _heredoc('PYSELFCHECK')

    def test_scripts_identical(self):
        self.assertEqual(self.shell_script, self.portal_script,
                         'install.sh 与 portal.py 的自检脚本内容不一致')

    def test_script_is_valid_python(self):
        ast.parse(self.portal_script)            # 语法错会直接抛

    def test_script_returns_nonzero_when_port_missing(self):
        """核心行为：配置里写了端口却没人监听 -> 必须返回非 0。

        这是把"假健康"变成"启动失败"的那一步。
        直接对脚本里的 listening() 打桩，不真的启服务、也不真的等 5 秒
        （把 time.sleep 换掉，避免测试变慢）。
        """
        mod = self._load_script()
        with mock.patch.object(mod, 'listening', lambda p: p == 1), \
             mock.patch.object(mod, 'open',
                               mock.mock_open(read_data='{}'), create=True), \
             mock.patch.object(mod.json, 'load',
                               lambda fh: {'services': [{'addr': ':1'},
                                                        {'addr': ':42999'}]}), \
             mock.patch.object(mod.time, 'sleep', lambda s: None):
            self.assertNotEqual(mod.main(), 0,
                                '端口未监听时自检脚本必须返回非 0')

    def test_script_returns_zero_when_all_ports_listening(self):
        """所有端口都在监听 -> 必须返回 0（不能误报失败）。"""
        mod = self._load_script()
        with mock.patch.object(mod, 'listening', lambda p: True), \
             mock.patch.object(mod, 'open',
                               mock.mock_open(read_data='{}'), create=True), \
             mock.patch.object(mod.json, 'load',
                               lambda fh: {'services': [{'addr': ':1'},
                                                        {'addr': ':2'}]}):
            self.assertEqual(mod.main(), 0,
                             '端口都在监听时应返回 0')

    def test_script_returns_zero_when_no_services(self):
        """services 为空是合法状态（还没建代理），必须放行。"""
        mod = self._load_script()
        with mock.patch.object(mod, 'open',
                               mock.mock_open(read_data='{}'), create=True), \
             mock.patch.object(mod.json, 'load', lambda fh: {'services': []}):
            self.assertEqual(mod.main(), 0, 'services 为空时应返回 0')

    @staticmethod
    def _load_script():
        """把自检脚本当独立模块加载（它本身就是一个可执行的 .py）。"""
        spec = importlib.util.spec_from_loader(
            'gost_selfcheck_under_test',
            loader=None)
        mod = importlib.util.module_from_spec(spec)
        exec(compile(_const('GOST_SELFCHECK_SCRIPT'),
                     'gost_selfcheck_under_test', 'exec'), mod.__dict__)
        return mod


if __name__ == '__main__':
    unittest.main(verbosity=2)
