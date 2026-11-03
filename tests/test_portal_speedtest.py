"""三网测速端点 `/api/v1/speedtest` 的行为测试。

这个端点的存在意义是：让**没绑 SSH 凭据**的节点也能测三网
（原先只有「面板 SSH 过去跑探针」一条路，这类节点页面上是四行「未测得」）。

所以要锁住的不变量都围绕「安全」与「诚实」两件事：

1. **靶点硬编码、不可注入** —— 这是本端点唯一能接受的安全姿态。
   portal 以 root 运行、subprocess 直接拼命令，一旦目标地址能由请求方
   指定就是本机 RCE。测试直接用注入尝试去证明它无效。
2. **没测到 ≠ 0ms** —— 骨干禁 ICMP 是常态（实测 51 个候选里 31 个 100% 丢包），
   「没测到」被写成 0 会在界面上显示成 `0 ms`，与同机房的真实 0 延迟无法区分。
3. **依赖缺失要明说** —— 没装 ping 报 NO_PING，与「靶点全不通」是两回事。
4. **解析兼容两种 ping 实现** —— iputils 与 BusyBox 输出格式不同，
   只认一种会让精简镜像的节点永远「未测得」而界面看不出原因。

跑法：python3 -m unittest discover -s tests -p 'test_*.py'
"""
import http.client
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal

META = dict(
    public_ip='192.0.2.1', server_name='hy2.example.com', listen_port=27490,
    auth_password='secret-pass', obfs_password='obfs-secret', is_insecure=False,
    hop_port_range='20000-40000', subscription_port=11690,
)

# ping 输出的两种形态。真实环境里两者都见过（iputils / BusyBox）。
# 共同点是 `= a/b/c` 且 avg 是第二项 —— 实现只锚定这个形状。
IPUTILS_PING = """
PING 202.96.128.86 (202.96.128.86) 56(84) bytes of data.
64 bytes from 202.96.128.86: icmp_seq=1 ttl=53 time=50.1 ms
64 bytes from 202.96.128.86: icmp_seq=2 ttl=53 time=50.3 ms
64 bytes from 202.96.128.86: icmp_seq=3 ttl=53 time=50.2 ms

--- 202.96.128.86 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2002ms
rtt min/avg/max/mdev = 50.100/50.200/50.300/0.082 ms
"""

BUSYBOX_PING = """
PING 202.96.128.86 (202.96.128.86): 56 data bytes
64 bytes from 202.96.128.86: seq=0 ttl=53 time=51.0 ms
64 bytes from 202.96.128.86: seq=1 ttl=53 time=49.0 ms
64 bytes from 202.96.128.86: seq=2 ttl=53 time=50.0 ms

--- 202.96.128.86 ping statistics ---
3 packets transmitted, 3 packets received, 0% packet loss
round-trip min/avg/max = 49.000/50.000/51.000 ms
"""

LOSS_PING = """
PING 202.96.128.86 (202.96.128.86) 56(84) bytes of data.

--- 202.96.128.86 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2040ms
"""


def parse_ping_output(text):
    """复刻 portal.Handler._ping_one 的解析逻辑（无副作用，便于单测）。"""
    loss = None
    m = re.search(r'([0-9]+(?:\.[0-9]+)?)%\s*packet loss', text)
    if m:
        try:
            loss = min(100.0, max(0.0, float(m.group(1))))
        except ValueError:
            loss = None
    avg = None
    m = re.search(r'=\s*([0-9.]+)/([0-9.]+)/[0-9.]+', text)
    if m:
        try:
            avg = min(60000.0, max(0.0, float(m.group(2))))
        except ValueError:
            avg = None
    return avg, loss


class SpeedtestTargetListTest(unittest.TestCase):
    """靶点清单本身的约束（不需要起服务）。"""

    def test_targets_are_hardcoded_not_read_from_request(self):
        """靶点必须是源码里的硬编码常量，且端点实现不读任何 query 参数。

        ⚠️ 为什么断言「源码里有没有这个常量」而不是「能不能从 portal 模块取到它」：
        SPEEDTEST_TARGETS 定义在 serve() 内部（它是闭包变量，
        Handler 类在其内部定义），模块级 import 拿不到 ——
        这个测试如果写成 `portal.SPEEDTEST_TARGETS` 会在 import 阶段就炸，
        看起来像"实现有问题"，其实是测试写错了（铁律⑨）。
        """
        src = (Path(portal.__file__).parent / 'portal.py').read_text(encoding='utf-8')
        self.assertIn('SPEEDTEST_TARGETS = (', src,
                      '靶点清单必须是源码内硬编码常量，不接受调用方传入')

        # 端点实现里不得出现读 query 的痕迹（parse_qs / self.query / query.get）。
        # 实现分在 _h_api_speedtest（单飞锁）与 _run_speedtest（真正测速）两段。
        m = re.search(r'def _h_api_speedtest\(self\):(.*?)\n        def _ping_one', src, re.S)
        self.assertIsNotNone(m, '未找到 _h_api_speedtest 实现')
        body = m.group(1)
        for danger in ('parse_qs', 'self.query', 'query.get(', 'urlparse'):
            self.assertNotIn(danger, body,
                             f'测速端点里出现了 {danger} —— 本端点不接受任何调用方输入')

    def test_every_target_is_a_plain_ipv4(self):
        """靶点只能是 IP 字面量 —— 域名会引入 DNS rebinding 面。"""
        m = re.search(r'SPEEDTEST_TARGETS = \((.*?)\n    \)', (Path(portal.__file__).parent / 'portal.py')
                      .read_text(encoding='utf-8'), re.S)
        self.assertIsNotNone(m, '未找到 SPEEDTEST_TARGETS 定义')
        rows = re.findall(r"\('([^']+)',\s*'([^']+)',\s*'([^']+)',\s*'([^']+)'\)", m.group(1))
        self.assertGreaterEqual(len(rows), 12, '靶点太少，三网无法交叉验证')
        seen_keys = set()
        for key, name, host, carrier in rows:
            with self.subTest(key=key):
                self.assertRegex(key, r'^[a-z0-9_-]{1,64}$', 'target_key 需为安全标识符')
                self.assertNotIn(key, seen_keys, 'target_key 重复')
                seen_keys.add(key)
                self.assertRegex(
                    host, r'^\d{1,3}(\.\d{1,3}){3}$',
                    f'靶点 {host} 不是 IPv4 字面量（域名会带来 DNS rebinding 面）')
                self.assertIn(carrier, ('telecom', 'unicom', 'mobile', 'other'))
                self.assertTrue(name.strip())

    def test_all_three_carriers_present(self):
        """电信/联通/移动三家必须都有 —— 少一家就退回「只有移动和公共」。"""
        src = (Path(portal.__file__).parent / 'portal.py').read_text(encoding='utf-8')
        m = re.search(r'SPEEDTEST_TARGETS = \((.*?)\n    \)', src, re.S)
        carriers = {c for _, _, _, c in re.findall(
            r"\('([^']+)',\s*'([^']+)',\s*'([^']+)',\s*'([^']+)'\)", m.group(1))}
        for want in ('telecom', 'unicom', 'mobile'):
            self.assertIn(want, carriers, f'缺 {want} 的靶点')

    def test_no_shell_metacharacters_in_targets(self):
        """靶点会被拼进 subprocess 的参数列表；虽然用的是列表形式（不经过 shell），
        这里仍守住「清单里不出现元字符」这条线，防止将来有人改成字符串拼接。"""
        src = (Path(portal.__file__).parent / 'portal.py').read_text(encoding='utf-8')
        m = re.search(r'SPEEDTEST_TARGETS = \((.*?)\n    \)', src, re.S)
        for key, _, host, _ in re.findall(
                r"\('([^']+)',\s*'([^']+)',\s*'([^']+)',\s*'([^']+)'\)", m.group(1)):
            with self.subTest(key=key):
                for ch in ";|&$`()<>'\"\\":
                    self.assertNotIn(ch, host, f'靶点 {host} 含 shell 元字符')


class PingParsingTest(unittest.TestCase):
    """ping 输出解析 —— 最容易被不同实现打脸的地方。"""

    def test_parses_iputils_format(self):
        avg, loss = parse_ping_output(IPUTILS_PING)
        self.assertAlmostEqual(avg, 50.2, places=2)
        self.assertEqual(loss, 0.0)

    def test_parses_busybox_format(self):
        """只认 iputils 的话，精简镜像的节点永远「未测得」而界面看不出原因。"""
        avg, loss = parse_ping_output(BUSYBOX_PING)
        self.assertAlmostEqual(avg, 50.0, places=2)
        self.assertEqual(loss, 0.0)

    def test_full_loss_yields_none_not_zero(self):
        """全丢包必须是 None —— 0 会被界面显示成「0 ms」，
        与真实测到的极低延迟无法区分（这条是整个端点最关键的语义）。"""
        avg, loss = parse_ping_output(LOSS_PING)
        self.assertIsNone(avg, '全丢包时 icmp_avg_ms 必须是 None，不能是 0')
        self.assertEqual(loss, 100.0)

    def test_empty_output_yields_none(self):
        avg, loss = parse_ping_output('')
        self.assertIsNone(avg)
        self.assertIsNone(loss)


class SpeedtestEndpointTest(unittest.TestCase):
    """起真实服务打真实 HTTP。"""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            cls.port = sock.getsockname()[1]
        (cls.root / 'meta.json').write_text(json.dumps(META), encoding='utf-8')
        portal.prepare(cls.root / 'meta.json', cls.port)
        cls.data = json.loads((cls.root / 'portal.json').read_text(encoding='utf-8'))
        # 假 ping：端点测试只验证结构与鉴权，不该真去 ping 公网靶点
        # （Linux 上每个靶点 3 次 × 2 秒超时，整组测试要跑近两分钟）。
        bindir = cls.root / 'bin'
        bindir.mkdir()
        fake_ping = bindir / 'ping'
        fake_ping.write_text('#!/bin/sh\necho "3 packets transmitted, 3 received, 0% packet loss"\n'
                             'echo "rtt min/avg/max/mdev = 10.0/12.0/14.0/1.0 ms"\n', encoding='utf-8')
        fake_ping.chmod(0o755)
        env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ.get('PATH', ''))
        cls.proc = subprocess.Popen(
            [sys.executable, str(Path(portal.__file__)), 'serve', str(cls.root / 'portal.json')],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        for _ in range(80):
            try:
                with socket.create_connection(('127.0.0.1', cls.port), .1):
                    break
            except OSError:
                time.sleep(.05)
        else:
            cls.proc.kill()
            raise RuntimeError('门户服务未能启动')

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=5)
        except Exception:
            cls.proc.kill()
        cls._tmp.cleanup()

    def get(self, path, auth=None, timeout=200):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=timeout)
        try:
            headers = {'Authorization': auth} if auth else {}
            conn.request('GET', path, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def bearer(self):
        return 'Bearer ' + self.data['api_key']

    def test_concurrent_runs_are_refused_not_stacked(self):
        """同一时刻只跑一轮测速，后来者 429（2026-11-04 修）。

        每轮最长约 60 秒；并发请求各占一个 quick 槽，32 个槽被占满后 /auth 也拿不到槽。
        这里把假 ping 换成慢的，同时发两个请求。
        """
        import threading
        slow = self.root / 'bin' / 'ping'
        original = slow.read_text(encoding='utf-8')
        slow.write_text('#!/bin/sh\nsleep 2\n' + original.split('\n', 1)[1], encoding='utf-8')
        try:
            results = []
            threads = [threading.Thread(target=lambda: results.append(
                self.get('/api/v1/speedtest', auth=self.bearer())[0])) for _ in range(2)]
            for t in threads:
                t.start()
                time.sleep(0.3)
            for t in threads:
                t.join()
            self.assertEqual(sorted(results), [200, 429])
        finally:
            slow.write_text(original, encoding='utf-8')

    def test_requires_api_key(self):
        """没鉴权必须 401 —— 这是新增端点最容易忘的一步。"""
        status, body = self.get('/api/v1/speedtest')
        self.assertEqual(status, 401)
        self.assertIn(b'Unauthorized', body)

    def test_rejects_wrong_api_key(self):
        status, _ = self.get('/api/v1/speedtest', auth='Bearer ' + 'x' * 40)
        self.assertEqual(status, 401)

    def test_returns_full_target_list(self):
        """鉴权通过后应返回全部靶点，结构与面板 node_speedtests 对齐。"""
        status, body = self.get('/api/v1/speedtest', auth=self.bearer())
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertTrue(payload['ok'], payload)
        self.assertGreaterEqual(payload['total_targets'], 12)
        self.assertEqual(len(payload['results']), payload['total_targets'])
        for row in payload['results']:
            for key in ('target_key', 'target_name', 'target_host', 'carrier',
                        'icmp_avg_ms', 'icmp_loss_pct'):
                self.assertIn(key, row)
            self.assertIn(row['carrier'], ('telecom', 'unicom', 'mobile', 'other'))
            # 测不到时必须是 JSON null，不是 0
            if row['icmp_avg_ms'] is not None:
                self.assertGreaterEqual(row['icmp_avg_ms'], 0)

    def test_query_parameters_cannot_inject_targets(self):
        """靶点不可注入：传任何参数都不得改变靶点集合。

        ⚠️ 顺带锁住一个真踩过的坑：self.path 含 query，
        `/api/v1/speedtest?x=1` 会让 `sub` 变成 'speedtest?x=1'，
        等值比较落空 → 404。路由因此先切 '?' 再比。
        这条测试同时验证「带 query 也能正常响应」与「参数被忽略」。
        """
        base = None
        status, body = self.get('/api/v1/speedtest', auth=self.bearer())
        self.assertEqual(status, 200)
        base = json.loads(body)

        status, body = self.get(
            '/api/v1/speedtest?target=169.254.169.254&hosts=evil.com&count=99999',
            auth=self.bearer())
        self.assertEqual(status, 200, '带 query 的请求不应 404')
        injected = json.loads(body)
        self.assertEqual(
            [r['target_host'] for r in injected['results']],
            [r['target_host'] for r in base['results']],
            '调用方传入的参数改变了靶点集合 —— 存在注入面')

    def test_unknown_api_subpath_still_404(self):
        """新端点不能影响既有 404 行为。"""
        status, body = self.get('/api/v1/definitely-not-a-real-endpoint', auth=self.bearer())
        self.assertEqual(status, 404)
        self.assertIn(b'not found', body.lower())

    def test_existing_endpoints_still_work(self):
        """回归：新增端点不能碰坏既有端点（它们承载开户与订阅）。"""
        for path, must in (('/api/v1/node/meta', b'meta'),
                           ('/api/v1/users/list', b'users')):
            with self.subTest(path=path):
                status, body = self.get(path, auth=self.bearer())
                self.assertEqual(status, 200)
                self.assertIn(must, body)


if __name__ == '__main__':
    unittest.main()
