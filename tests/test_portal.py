import base64
import http.client
import json
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
    def test_embedded_program_and_port_selection(self):
        script = (Path(portal.__file__).parent/'install.sh').read_text()
        embedded = script.split("<<'PYPORTAL'\n", 1)[1].split('\nPYPORTAL', 1)[0]
        self.assertEqual(embedded.strip(), Path(portal.__file__).read_text().strip())
        function = script.split('select_subscription_port() {', 1)[1].split('\nclear_all_hopping_rules()', 1)[0]
        with socket.socket() as busy:
            busy.bind(('0.0.0.0', 0))
            busy.listen()
            port = busy.getsockname()[1]
            function = function.replace('port = 8443 if i == 0', f'port = {port} if i == 0')
            result = subprocess.run(['bash', '-c', 'set -eo pipefail\nselect_subscription_port() {' + function + '\nselect_subscription_port\necho "$HY2_SUB_PORT $PORTAL_LOCAL_PORT"'], capture_output=True, text=True, timeout=10, check=True)
            selected, local = map(int, result.stdout.split())
            self.assertNotEqual(selected, port)
            self.assertTrue(1024 < selected < 65536)
            self.assertTrue(local > 0)

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
            access = json.loads((root/'portal-access.json').read_text())
            data = json.loads((root/'portal.json').read_text())
            portal.refresh(root/'meta.json')
            refreshed = json.loads((root/'portal.json').read_text())
            self.assertEqual(refreshed['token'], data['token'])
            self.assertEqual(refreshed['auth_hash'], data['auth_hash'])
            self.assertEqual(json.loads((root/'portal-access.json').read_text()), access)
            self.assertIn('data-copy="hy2-link"', refreshed['page'])
            self.assertIn("script-src 'sha256-", portal.content_policy())
            self.assertNotIn('unsafe-inline', portal.content_policy())
            self.assertEqual(len(data['token']), 64)
            self.assertEqual(json.loads(data['clash'])['proxies'][0]['password'], meta['auth_password'])
            self.assertNotIn('</textarea><script>', data['page'])
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
