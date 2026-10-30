import base64
import contextlib
import http.client
import io
import json
import re
import shutil
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal


class PortalTest(unittest.TestCase):
    def test_portal_is_fetched_not_embedded(self):
        """install.sh 不应再内嵌 portal.py —— 已改为运行时获取。

        内嵌副本曾占 install.sh 约七成行数（4948 行 / 244KB），
        每次改 portal.py 都要手动同步一次，漏一次就是「仓库里的门户」与
        「装到机器上的门户」不一致。这里锁住新不变量：

          1. 不许再出现 PYPORTAL heredoc（否则重复维护又回来了）
          2. 必须存在 portal_fetch_py / portal_ensure_py
          3. 三级回退源（GitHub API / jsDelivr / raw）都在
          4. 拿到之后必须做 Python 语法校验 —— 门户同时是 Hysteria 的 auth 后端，
             文件写坏 = 所有客户端都连不上
        """
        script = (Path(portal.__file__).parent/'install.sh').read_text(encoding="utf-8")
        self.assertNotIn("<<'PYPORTAL'", script,
                         'install.sh 又内嵌 portal.py 了；请改回运行时获取（portal_ensure_py）')
        self.assertIn('portal_fetch_py() {', script)
        self.assertIn('portal_ensure_py() {', script)
        self.assertIn('ast.parse', script, '获取到 portal.py 后必须做 Python 语法校验')
        for host in ('api.github.com', 'cdn.jsdelivr.net', 'raw.githubusercontent.com'):
            self.assertIn(host, script, f'缺少回退源 {host}')

    def test_subscription_port_selection(self):
        """订阅端口必须避开已被占用的端口。

        🔴 这条测试曾经是个「假测试」：它靠替换
           `port = 8443 if i == 0`
        把 busy 端口注入候选序列，但 install.sh 早就不再把 8443 当首选
        （8443 在本项目里是被主动避开的黑名单端口），那次 replace 因此退化成
        **空操作** —— 测试依然是绿的，却只在验证一条平凡成立的不等式
        （随机端口几乎不可能恰好等于 busy 端口），从未真正覆盖「bind 检测」。

        现在的做法：直接从 install.sh 里取出那段真实的端口探测 Python 代码，
        把**第一轮候选**强制改成指定的 busy 端口 ——
        命中 busy 时 bind 必须失败并跳过它，才说明检测真的在工作。

        实现上直接在进程内 exec 那段代码，不走 bash：
        Windows 上 subprocess 调 `bash` 会拿到 WSL 的 bash（system32\\bash.exe），
        它按 Linux 路径解析，看不到 `C:/...` 的临时脚本，测试会莫名其妙地 127 退出。
        """
        script = (Path(portal.__file__).parent/'install.sh').read_text(encoding="utf-8")
        found = re.search(r"HY2_SUB_PORT=\$\(python3 - <<'PYPORT'\n(.*?)\nPYPORT",
                          script, re.S)
        self.assertIsNotNone(found, 'install.sh 里找不到 HY2_SUB_PORT 的端口探测代码')
        code = found.group(1)

        # 这两句是刻意写死的：一旦 install.sh 的探测实现变了，测试必须显式失败
        # 来提醒同步，而不能像当年那样静默退化成假测试。
        probe = 'for _ in range(100):\n    port = 10000 + secrets.randbelow(50000)'
        self.assertIn(probe, code,
                      'install.sh 的端口探测实现已变化，本测试的注入方式必须同步更新')

        # busy 端口必须落在 20000-40000 之外，否则第一轮候选会因为「端口跳跃区间」
        # 那条规则被跳过，测到的就不是 bind 检测了。
        # 注意 socket 要一直保持打开到探测结束 —— 端口释放了就测不出占用。
        busy = None
        for _ in range(50):
            candidate_sock = socket.socket()
            candidate_sock.bind(('0.0.0.0', 0))
            candidate_sock.listen()
            if 20000 <= candidate_sock.getsockname()[1] <= 40000:
                candidate_sock.close()
                continue
            busy = candidate_sock
            break
        self.assertIsNotNone(busy, '未能取到区间外的空闲端口用于测试')
        busy_port = busy.getsockname()[1]
        try:
            patched = code.replace(
                probe,
                '_first = True\n'
                'for _ in range(100):\n'
                f'    port = {busy_port} if _first else 10000 + secrets.randbelow(50000)\n'
                '    _first = False',
            )
            self.assertNotEqual(patched, code,
                                '替换失败：busy 端口没有被注入候选序列')

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                exec(patched, {})
            selected = int(buf.getvalue().strip())
        finally:
            busy.close()

        self.assertNotEqual(selected, busy_port,
                            f'订阅端口竟然选中了已被占用的 {busy_port}，bind 检测没有生效')
        self.assertTrue(1024 < selected < 65536)
        self.assertFalse(20000 <= selected <= 40000,
                         '订阅端口不得落在 Hysteria 的端口跳跃区间 20000-40000')

    def test_authenticated_routes_and_throttling(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            meta = dict(public_ip='192.0.2.1', server_name='hy2.example.com', listen_port=27490,
                        auth_password='secret " & </textarea><script>', obfs_password='obfs-secret',
                        is_insecure=False, hop_port_range='20000-40000', subscription_port=8443)
            (root/'meta.json').write_text(json.dumps(meta))
            portal.prepare(root/'meta.json', port)
            access = json.loads((root/'portal-access.json').read_text(encoding="utf-8"))
            data = json.loads((root/'portal.json').read_text(encoding="utf-8"))
            portal.refresh(root/'meta.json')
            refreshed = json.loads((root/'portal.json').read_text(encoding="utf-8"))
            self.assertEqual(refreshed['token'], data['token'])
            self.assertEqual(refreshed['auth_hash'], data['auth_hash'])
            self.assertEqual(json.loads((root/'portal-access.json').read_text(encoding="utf-8")), access)
            # 🔴 2026-10-31：portal.json 不再存整页 HTML（只存 page_digest，
            # 见 portal.regenerate_page 的说明）。这里改成验证**同一件事**：
            # 页面能被重建出来，且重建结果与摘要一致、不含转义缺口。
            _meta_reload = json.loads((root/'meta.json').read_text(encoding='utf-8'))
            _uri, _clash, _sing = portal.artifacts(_meta_reload)
            _sub = ('https://%s:%s@%s:%d/%s/clash.yaml'
                    % (access['username'], access['password'],
                       meta['server_name'], meta['subscription_port'], refreshed['token']))
            page = portal.page_html(
                _meta_reload, _uri, _sub, _clash, _sing,
                users=refreshed['users'], api_key=refreshed['api_key'],
                token=refreshed['token'], session_secret=refreshed['session_secret'],
                username=access['username'], password=access['password'])
            self.assertIn('data-copy="hy2-link"', page)
            self.assertIn("script-src 'sha256-", portal.content_policy())
            policy = portal.content_policy()
            # 只允许 style-src-attr 的 inline（页面大量使用 style="..." 属性，
            # 哈希覆盖不到它们）；脚本仍然必须逐个哈希放行。
            script_src = policy.split('script-src', 1)[1].split(';', 1)[0]
            self.assertNotIn('unsafe-inline', script_src)
            self.assertEqual(len(data['token']), 64)
            self.assertEqual(json.loads(data['clash'])['proxies'][0]['password'], meta['auth_password'])
            # 整页 HTML 不该再落盘；摘要必须存在且是 64 位 hex。
            self.assertNotIn('page', refreshed)
            self.assertRegex(refreshed.get('page_digest', ''), r'^[0-9a-f]{64}$')
            self.assertNotIn('</textarea><script>', page)
            self.assertIn('MATCH,PROXY', data['clash'])
            self.assertIn('server_ports', data['sing'])
            proc = subprocess.Popen([sys.executable, str(Path(portal.__file__)), 'serve', str(root/'portal.json')])
            try:
                for _ in range(50):
                    try:
                        with socket.create_connection(('127.0.0.1', port), .1):
                            break
                    except OSError:
                        time.sleep(.05)
                def request(path, auth=None):
                    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
                    conn.request('GET', path, headers={'Authorization': auth} if auth else {})
                    response = conn.getresponse()
                    result = response.status, dict(response.getheaders()), response.read()
                    conn.close()
                    return result
                prefix = '/' + data['token'] + '/'
                auth = 'Basic ' + base64.b64encode((access['username']+':'+access['password']).encode()).decode()
                self.assertEqual(request('/')[0], 404)

                # 未鉴权时的响应分两类，这是 portal.py 里有意的设计
                # （见 do_GET 末尾：is_client_api 走 401 + WWW-Authenticate，
                #   其余浏览器请求返回登录页 200，方便用户直接在浏览器里登录）。
                # 本测试原先一律断言 401，是登录页 UX 引入之前写的，此处按实际行为修正；
                # 更要害的断言是：两条路径都不能吐出任何订阅内容或节点参数。
                # 注意保持每路由 2 次请求不变 —— 末尾的 429 限流断言依赖总请求次数。
                client_routes = ['clash.yaml', 'sing-box.json']
                browser_routes = ['', 'qr.svg']

                for route in client_routes:
                    self.assertEqual(request(prefix+route)[0], 401)
                    status, headers, body = request(prefix+route, auth)
                    self.assertEqual(status, 200)
                    self.assertEqual(headers['Cache-Control'], 'no-store')
                    self.assertTrue(body)

                for route in browser_routes:
                    status, _, body = request(prefix+route)
                    self.assertEqual(status, 200)
                    self.assertIn(b'login-form', body)          # 确实是登录页而非内容
                    self.assertNotIn(b'MATCH,PROXY', body)      # 不含 Clash 订阅内容
                    self.assertNotIn(b'hysteria2://', body)     # 不含节点直链
                    status, headers, body = request(prefix+route, auth)
                    self.assertEqual(status, 200)
                    self.assertEqual(headers['Cache-Control'], 'no-store')
                    # qr.svg 在**没有 qrencode 的机器**上是空的，这是**正确行为**
                    # （prepare() 已降级、不再因缺 qrencode 而崩掉整个安装）。
                    # 断言「必须有内容」等于要求测试机上一定装有 qrencode。
                    if route == 'qr.svg' and not shutil.which('qrencode'):
                        self.assertEqual(body, b'')    # 明确降级，而非报错
                    else:
                        self.assertTrue(body)
                self.assertEqual(request(prefix+'../portal.json', auth)[0], 404)
                self.assertEqual(request(prefix, 'Basic wrong')[0], 401)

                # 限流：web 桶在「1 秒内 >= 50 次请求」或「60 秒内 >= 60 次失败」时返回 429
                # （见 portal.py 的 check_rate_limit）。
                # 原断言只连发 25 次，低于任一阈值，在现行实现下永远不可能出现 429 ——
                # 同样属过时断言，此前被上面那条 401 断言挡住、从未执行到。
                # 这里按真实阈值构造：未鉴权请求 clash.yaml 会触发 record_failure()，
                # 连发 70 次即可保证在「快」（50 次/秒先到）与「慢」（60 次失败先到）
                # 两种计时情形下都必然出现 429。
                codes = [request(prefix+'clash.yaml')[0] for _ in range(70)]
                self.assertIn(429, codes)
            finally:
                proc.terminate()
                proc.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
