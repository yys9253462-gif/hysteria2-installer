"""真实计量（usage-meter）配置链路的回归测试。

来源事故（2026-10-08 在测试机 se / 13.63.71.232 上 5 轮排障定位）：

    测试机装完 hy2 后，门户启动日志只有一行异常：
        [portal] 真实计量未初始化: FileNotFoundError
    表现：界面用量永远「未开始计量」、/traffic-speed 恒 0、
          /api/v1/users/list 的 measurement_ok 恒 false、measured_bytes 恒 null。
    而**安装过程完全成功**,没有任何报错。

根因是一条被静默降级掩盖的断链：

    install.sh 生成 config.yaml 时**从不写 trafficStats 段**
      -> portal_ensure_py() 里 L1621 的 awk 读不到 secret
      -> 不生成 /etc/hysteria/usage-meter-config.json
      -> portal.py 启动时：
             spec_from_file_location(...) -> from_file(config=该路径)
             -> 读不存在的文件 -> FileNotFoundError
             -> except -> usage_meter = None（L1779 静默降级）
      -> serve() 里 L4951 `if usage_meter is not None: usage_meter.start()`
         被守卫跳过 -> poll() 永不运行
      -> on_speed 回调永不触发（f9f896c 才加上的速率写入侧成了死代码）
      -> speed_tracker 永远空 -> /traffic-speed 恒 0

全仓库此前 `grep trafficStats` 命中 4 处，**全在读取侧，零个写入点** ——
连 tests/portal-py-fetch-smoke.sh:33 也只是注释里提了一句。

本文件锁死五条不变量：
  1. install.sh 的 config.yaml 模板**必须**包含 trafficStats 段；
  2. trafficStats.listen 必须是回环（与 usage-meter-config.json 的
     "http://127.0.0.1:19996" 对齐 —— readers.read_hysteria 强制 loopback）；
  3. trafficStats.secret 与 usage-meter-config.json 的 hysteria.secret
     **逐字符一致**（不一致则 /traffic 恒 401，同样静默）；
  4. 缺 trafficStats 时必须**幂等补写**，而不是 log_warn 后继续；
  5. 补不上时**硬失败 return 1** —— 禁止静默降级继续安装。

第 4/5 条用一个「仿真老装机 config」的沙箱 harness 真正执行 install.sh 里
写出的自愈段来验证，而不是重写一遍逻辑（重写就等于没测到真代码）。
"""
import os
import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / 'install.sh'


def _read_install():
    return INSTALL.read_text(encoding='utf-8')


class StaticInvariantsTest(unittest.TestCase):
    """静态断言：源码层面必须有的结构。"""

    def test_install_writes_traffic_stats_block(self):
        """config.yaml 模板里必须有 trafficStats 写入点（不是只在注释里提）。"""
        src = _read_install()
        # 找 heredoc 内容的行（不是注释行）
        writes = [
            ln for ln in src.splitlines()
            if ln.strip() == 'trafficStats:' and not ln.strip().startswith('#')
        ]
        self.assertTrue(
            writes,
            'install.sh 没有任何地方写入 `trafficStats:` 段 —— '
            '计量配置链路会断在 portal_ensure_py() 的 awk 上',
        )
        # 必须出现在 config 生成函数体内（generate 到下一个函数定义之间）
        m = re.search(r'^generate_server_config\(\)\s*\{(.*?)^\}', src, re.M | re.S)
        self.assertIsNotNone(m, '未找到 generate_server_config()')
        self.assertIn(
            'trafficStats:', m.group(1),
            'trafficStats 必须写在 generate_server_config() 生成的 config 模板里',
        )

    def test_traffic_stats_listen_is_loopback_19996(self):
        """trafficStats.listen 必须回环，且与 portal 读的 19996 对齐。"""
        src = _read_install()
        self.assertIn(
            'listen: 127.0.0.1:19996', src,
            'trafficStats.listen 必须回环 127.0.0.1:19996 —— '
            'readers.read_hysteria() 强制 loopback（非回环直接 ValueError），'
            '且 usage-meter-config.json 写死的就是 19996',
        )

    def test_meter_secret_generated_with_openssl(self):
        """必须用 openssl rand -hex 16 生成 secret（与 AUTH/OBFS 同源惯例）。"""
        src = _read_install()
        self.assertIn('METER_SECRET="$(openssl rand -hex 16)"', src)

    def test_meter_config_written_unconditionally(self):
        """usage-meter-config.json 必须每次写（幂等覆盖），不能只在 !-f 时写。

        老机器上文件可能已存在但内容陈旧（secret 不匹配），
        只在 !-f 时写会让"配置漂移"永远治不好。
        """
        src = _read_install()
        # 定位写点：2026-11-03 起计量配置拆到 portal_write_meter_config（安装流程要先取包、
        # 写完 config.yaml 再写计量配置），portal_ensure_py 在非 BUNDLE_ONLY 时调用它。
        m = re.search(r'^portal_write_meter_config\(\)\s*\{(.*?)^\}', src, re.M | re.S)
        self.assertIsNotNone(m, '未找到 portal_write_meter_config()')
        body = m.group(1)
        self.assertIn('usage-meter-config.json', body)
        ensure = re.search(r'^portal_ensure_py\(\)\s*\{(.*?)^\}', src, re.M | re.S).group(1)
        self.assertIn('portal_write_meter_config', ensure)
        # 不允许"读不到 secret 就只 warn 然后继续"
        self.assertNotIn(
            'log_warn "未能从 ${HY2_CONFIG} 读到 trafficStats secret',
            body,
            '缺 secret 时不得只 warn 就继续 —— 那是静默降级，必须补写或硬失败',
        )

    def test_hard_fail_on_unrecoverable_meter_config(self):
        """补不上 trafficStats 时必须 return 1，禁止静默降级。"""
        src = _read_install()
        m = re.search(r'^portal_write_meter_config\(\)\s*\{(.*?)^\}', src, re.M | re.S)
        body = m.group(1)
        self.assertIn(
            'return 1', body,
            'portal_write_meter_config() 在无法建立 trafficStats 时必须 return 1',
        )
        self.assertRegex(
            body, r'拒绝以静默降级的方式继续',
            '硬失败路径必须显式声明拒绝静默降级（便于日后审查）',
        )


class SelfHealHarnessTest(unittest.TestCase):
    """动态断言：真跑 install.sh 里写出的自愈段（do_upgrade.sh 内嵌）。

    ⚠️ Windows 上的两个 harness 陷阱（都已踩过并绕过）：

    1. **不能依赖 `shutil.which('bash')`**：本机它解析到 WorkBuddy 自带的
       PortableGit，其 `/tmp` 与调用方看到的不是同一个地方，
       会表现成「config 写进去了但 shell 读不到 → 自愈段看起来没生效」。
       所以用 `_BASH` 显式探测可用的 bash 绝对路径。
    2. **不能把多行脚本当 `-c` 的参数**：MSYS 会对参数里的 POSIX 路径做
       转换，实测把 `$HY2_DIR/config.yaml` 里的前缀吃掉。
       所以脚本一律**写文件**再 `bash <file>`。

    产品代码本身没问题（真机是 Linux），以上都只是本机跑测试的环境约束。
    """

    @classmethod
    def setUpClass(cls):
        cls._bash = cls._find_bash()

    @classmethod
    def _find_bash(cls):
        """找一个能用的 bash 绝对路径。优先本机 PATH 上的，其次常见安装位置。"""
        import os
        cands = []
        for p in os.environ.get('PATH', '').split(os.pathsep):
            if p:
                cands.append(Path(p) / 'bash.exe')
                cands.append(Path(p) / 'bash')
        cands += [
            Path(r'C:\Program Files\Git\bin\bash.exe'),
            Path(r'C:\Program Files\Git\usr\bin\bash.exe'),
        ]
        for c in cands:
            try:
                if c.exists():
                    r = subprocess.run([str(c), '-c', 'echo ok'],
                                       capture_output=True, text=True,
                                       timeout=15)
                    if r.stdout.strip() == 'ok':
                        return str(c)
            except Exception:
                continue
        return None

    def _require_bash(self):
        if not self._bash:
            self.skipTest('未找到可用的 bash，跳过动态 harness 测试')

    def _posix_dir(self):
        """建一个本测试独占的临时目录，返回 bash 可见的 POSIX 路径。"""
        self._require_bash()
        td = tempfile.mkdtemp(prefix='metercfg_')
        self.addCleanup(lambda: __import__('shutil').rmtree(td, ignore_errors=True))
        # Windows：`pwd -W` 给的是 Windows 路径（pwsh/bash on Windows 的 cwd 语义不同，
        # 必须显式换算）。POSIX：tmpdir 本身就是路径，`pwd -W` 不存在会失败，
        # 必须在 cd 之前判平台 —— 否则会拿到一个 bash 根本用不了的路径，
        # 测试表现为「自愈段没生效」（config 里 trafficStats 计数为 0），
        # 很容易被误判成产品代码坏了。
        if os.name != 'nt':
            posix = td.replace('\\', '/')
            subprocess.run([self._bash, '-c', 'mkdir -p "$1/hysteria"', 'bash', posix],
                           check=True, capture_output=True)
            return posix
        r = subprocess.run(
            [self._bash, '-c', 'cd "$1" && pwd -W 2>/dev/null || pwd',
             'bash', td.replace('\\', '/')],
            capture_output=True, text=True, errors='replace', timeout=15)
        win = r.stdout.strip()
        self.assertTrue(win, '无法解析临时目录的 Windows 路径')
        subprocess.run([self._bash, '-c',
                        f'mkdir -p "{win}/hysteria"'], check=True,
                       capture_output=True)
        return win.replace('\\', '/')

    def _bash_run(self, script_body, cwd=None):
        """把脚本体写成文件再 `bash <file>` 执行（避开 -c 参数的 MSYS 转换）。"""
        self._require_bash()
        fd, path = tempfile.mkstemp(suffix='.sh', prefix='meterharness_')
        import os
        os.close(fd)
        Path(path).write_text(script_body, encoding='utf-8', newline='\n')

        def _cleanup():
            # Windows 上刚被 bash 读过的文件可能短暂被占，忽略即可。
            try:
                Path(path).unlink(missing_ok=True)
            except (PermissionError, OSError):
                pass
        self.addCleanup(_cleanup)
        return subprocess.run([self._bash, path], capture_output=True,
                              text=True, errors='replace', timeout=60)

    def _read_file(self, win_path):
        return Path(win_path).read_text(encoding='utf-8', errors='replace')

    def _write_file(self, win_path, content):
        Path(win_path).write_text(content, encoding='utf-8', newline='\n')

    def _extract_upgrade_selfheal(self):
        """从 install.sh 里抠出 do_upgrade.sh 的自愈段，返回可执行片段。

        注意：切片起点选在 `if [[ -f ...` 而不是它上方的注释 ——
        注释块第一行顶格（列 0），会让 textwrap.dedent 认为"公共缩进为 0"
        而整段不去缩进，拼进 bash 后立刻语法错。
        """
        src = _read_install()
        m = re.search(
            r"cat > \"\$HY2_DIR/do_upgrade\.sh\" <<'EOUG'\n(.*?)\nEOUG\n",
            src, re.S,
        )
        self.assertIsNotNone(m, '未找到 do_upgrade.sh 的 heredoc')
        body = m.group(1)
        i = body.index('# 计量配置自愈')
        # 从注释块之后的第一个 `if [[ -f` 开始切，跳过顶格注释
        start = body.index('if [[ -f "$HY2_DIR/config.yaml" ]]', i)
        # ⚠️ 终点必须锚在「计量自愈块的收尾 fi」上，不能按 systemctl restart 找。
        # 2026-10-09 之后 do_upgrade.sh 的同一个 heredoc 里又追加了「证书自愈」块，
        # 它同样以 systemctl restart hysteria-portal 收尾；按后者切会把证书块
        # （含嵌套 <<'PYEOF2' heredoc）整段带进来，dedent 遇到顶格终止符算错缩进，
        # 拼进 bash 立刻语法错 —— 表现为「trafficStats 被重复插入」这种假象。
        _gen = body.index('计量配置已生成（真实计量启用）', i)
        j = body.index('\n', body.index('\n        fi', _gen) + 1)
        seg = body[start:j]
        # 本地仿真没有 systemd，替换掉重启调用
        seg = seg.replace(
            'systemctl restart hysteria-server 2>/dev/null || true',
            'echo "[sim] restart hysteria-server"',
        )
        out = textwrap.dedent(seg)
        # 自检：不得残留 8 空格缩进的 shebang 级别语句
        self.assertFalse(
            out.startswith(' '),
            '自愈段提取后仍有前导空格 —— dedent 失败，bash 会语法错',
        )
        return out

    def test_selfheal_adds_traffic_stats_and_meter_config(self):
        base = self._posix_dir()
        cfg_path = f'{base}/hysteria/config.yaml'
        self._write_file(
            cfg_path,
            'listen: :19906\n'
            '\n'
            'masquerade:\n'
            '  type: proxy\n'
            '  proxy:\n'
            '    url: http://127.0.0.1:33947/\n'
            '  listenHTTPS: :10773\n'
            '\n'
            'bandwidth:\n'
            '  up: 1 gbps\n')

        script = (
            'set -e\n'
            f'HY2_DIR="{base}/hysteria"\n'
            + self._extract_upgrade_selfheal() + '\n'
        )
        r = self._bash_run(script)
        self.assertEqual(
            r.returncode, 0,
            f'self-heal 段执行失败:\n{r.stdout}\n{r.stderr}')

        cfg = self._read_file(cfg_path)
        self.assertIn('trafficStats:', cfg)
        self.assertIn('listen: 127.0.0.1:19996', cfg)

        meter = self._read_file(f'{base}/hysteria/usage-meter-config.json')
        self.assertIn('"secret"', meter, 'usage-meter-config.json 未生成')
        self.assertIn('19996', meter)

        yaml_secret = re.search(r'secret:\s*([0-9a-f]{32})', cfg).group(1)
        json_secret = re.search(r'"secret":\s*"([0-9a-f]{32})"', meter).group(1)
        self.assertEqual(
            yaml_secret, json_secret,
            'config.yaml 的 trafficStats.secret 必须与 '
            'usage-meter-config.json 的 hysteria.secret 逐字符一致，'
            '否则 /traffic 会恒 401（同样是静默降级）')

    def test_selfheal_is_idempotent(self):
        """连跑两次不得重复插入 trafficStats。"""
        base = self._posix_dir()
        cfg_path = f'{base}/hysteria/config.yaml'
        self._write_file(cfg_path,
                         'listen: :19906\nmasquerade:\n  type: proxy\n')
        seg = self._extract_upgrade_selfheal()
        script = ('set -e\n'
                  f'HY2_DIR="{base}/hysteria"\n'
                  + seg + '\n' + seg + '\n')
        r = self._bash_run(script)
        self.assertEqual(r.returncode, 0, r.stderr)
        cfg = self._read_file(cfg_path)
        self.assertEqual(
            cfg.count('trafficStats:'), 1,
            'trafficStats 被重复插入 —— 自愈段不幂等')

    def test_selfheal_keeps_existing_secret(self):
        """已有 trafficStats 的老机器：补 usage-meter-config.json 时必须
        沿用**已存在的 secret**，不许重新生成（否则线上 /traffic 立刻 401）。"""
        base = self._posix_dir()
        cfg_path = f'{base}/hysteria/config.yaml'
        existing = 'a' * 32
        self._write_file(
            cfg_path,
            'listen: :19906\n'
            'trafficStats:\n'
            '  listen: 127.0.0.1:19996\n'
            f'  secret: {existing}\n'
            'masquerade:\n  type: proxy\n')
        script = ('set -e\n'
                  f'HY2_DIR="{base}/hysteria"\n'
                  + self._extract_upgrade_selfheal() + '\n')
        r = self._bash_run(script)
        self.assertEqual(r.returncode, 0, r.stderr)
        meter = self._read_file(f'{base}/hysteria/usage-meter-config.json')
        self.assertIn(
            existing, meter,
            '已有 secret 被覆盖 —— 会让线上 /traffic 立即 401')


if __name__ == '__main__':
    unittest.main()
