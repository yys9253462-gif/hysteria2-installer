"""Reality 多用户：真实 HTTP 五轮端到端（起 portal 进程，走 /api/v1/ 接口）。

与 test_portal_reality_e2e_5rounds 的区别：
  那个直接调模块函数（快、覆盖逻辑）；
  这个**真的把 portal.py 起成一个 HTTP 服务**，用 urllib 打真实的
  POST /api/v1/users/create|delete —— 覆盖 Handler 里的鉴权、限流、
  JSON 解析、回复封装这些**只有走 HTTP 才会经过**的路径。

五轮各自独立建用户，跑完清理。
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import fake_hy2_stats  # noqa: E402

PORT = None
BASE = None
TMP = None
PROC = None
API_KEY = None


def _free_port():
    import socket
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _api(path, payload, key):
    # ⚠️ 面板的 API 鉴权头是 `Authorization: Bearer <api_key>`
    # （见 portal.py 的 verify_api_key），不是 X-Api-Key —— 用错头会得到 401，
    # 看起来像「功能坏了」其实是测试写错了。
    headers = {'Content-Type': 'application/json'}
    if key:
        headers['Authorization'] = 'Bearer ' + key
    req = urllib.request.Request(
        BASE + path, data=json.dumps(payload).encode(),
        headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read().decode() or '{}')
    except urllib.error.HTTPError as e:
        raw = e.read().decode('utf-8', 'replace')
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {'raw': raw[:200]}
    except Exception as e:
        return 0, {'error': str(e)}


def _get(path, key=None):
    h = {'Authorization': 'Bearer ' + key} if key else {}
    req = urllib.request.Request(BASE + path, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')[:200]
    except Exception as e:
        return 0, str(e)[:200]


def setUpModule():
    global PORT, BASE, TMP, PROC, API_KEY
    TMP = Path(tempfile.mkdtemp(prefix='portal-reality-http-'))
    hdir = TMP / 'hysteria'
    hdir.mkdir(parents=True, exist_ok=True)

    # 假 xray / systemctl（只记录调用，不真启服务）
    bindir = TMP / 'bin'
    bindir.mkdir(parents=True, exist_ok=True)
    log = TMP / 'systemctl.log'
    x = bindir / 'xray'
    x.write_text('#!/bin/sh\nif [ "$1" = "x25519" ]; then\n'
                 '  echo "PrivateKey: FAKEDRV0000000000000000000"\n'
                 '  echo "Password (PublicKey): FAKEPUB000000000000000000"\n'
                 '  exit 0\nfi\nexit 0\n', encoding='utf-8')
    os.chmod(x, 0o755)
    sc = bindir / 'systemctl'
    sc.write_text('#!/bin/sh\necho "$@" >> "%s"\n'
                  'case "$*" in *is-active*) echo active;; esac\nexit 0\n' % log,
                  encoding='utf-8')
    os.chmod(sc, 0o755)
    os.environ['PATH'] = str(bindir) + os.pathsep + os.environ.get('PATH', '')

    (hdir / 'client_meta.json').write_text(json.dumps({
        'is_insecure': True, 'server_name': 'node.example.com',
        'public_ip': '203.0.113.10', 'auth_password': 'masterpw',
        'listen_port': 443, 'obfs_password': 'obfspw',
        'hop_port_range': '20000-40000',
    }), encoding='utf-8')
    (hdir / 'config.yaml').write_text(
        'auth:\n  type: http\n  http:\n    url: http://127.0.0.1:1/auth\n',
        encoding='utf-8')

    PORT = _free_port()
    BASE = 'http://127.0.0.1:%d' % PORT
    API_KEY = 'testapikey0123456789abcdef'

    (hdir / 'portal.json').write_text(json.dumps({
        'port': PORT, 'token': 'tok' + '0' * 30,
        'auth_hash': 'deadbeef', 'session_secret': 's' * 64,
        'api_key': API_KEY, 'page': '<html>ok</html>',
        'users': {}, 'proxy_services': [],
        # 预置 reality_config —— 模拟「这台机器已经装好并启用了 Reality」。
        # 没有它时 artifacts 拿不到 public_key/short_id，会**按设计**降级成
        # 单 Hy2 节点（那是对未安装 Reality 的节点的正确行为）。
        'reality_config': {
            'private_key': 'FAKEPRIV0000000000000000000',
            'public_key': 'FAKEPUB000000000000000000',
            'short_id': 'aabbccdd',
            'dest_sni': 'www.apple.com',
            'port': 443,
        },
    }, ensure_ascii=False), encoding='utf-8')

    global STATS
    STATS = fake_hy2_stats.start(hdir)

    env = dict(os.environ)
    env['HY2_PORTAL_AUTOSTART_PORT'] = str(PORT)
    # 隔离夹具模拟已运行的 Reality 入站；不依赖主机上的 Xray 或监听端口。
    (hdir / 'xray.json').write_text(json.dumps({'inbounds': [
        {'tag': 'vless-reality-in', 'protocol': 'vless', 'port': 443,
         'settings': {'clients': []}}
    ]}), encoding='utf-8')
    bootstrap = '''import runpy, sys
from pathlib import Path
namespace = runpy.run_path(sys.argv[1])
serve = namespace['serve']
env = serve.__globals__
root = Path(sys.argv[2]).parent
real_path = env['Path']
def fixture_path(value):
    if str(value) == '/etc/hysteria/xray.json':
        return root / 'xray.json'
    if str(value) == '/usr/local/bin/xray':
        return root.parent / 'bin' / 'xray'
    return real_path(value)
env['Path'] = fixture_path
env['_systemd_state'] = lambda unit: 'active'
env['_listening_ports'] = lambda: {443}
env['enforce_node_access'] = lambda *args, **kwargs: True
serve(sys.argv[2])
'''
    PROC = subprocess.Popen(
        [sys.executable, '-c', bootstrap, str(ROOT / 'portal.py'), str(hdir / 'portal.json')],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    # 等端口起来
    for _ in range(80):
        time.sleep(0.25)
        st, _b = _get('/api/health')
        if st in (200, 404, 401, 405):
            return
    out = ''
    try:
        PROC.kill()
        out = PROC.stdout.read()[:800] if PROC.stdout else ''
    except Exception:
        pass
    raise RuntimeError('portal 未能启动: ' + out)


STATS = None


def tearDownModule():
    global PROC
    if STATS:
        STATS.shutdown()
    if PROC:
        PROC.kill()
        try:
            PROC.wait(timeout=5)
        except Exception:
            pass
    if TMP:
        shutil.rmtree(TMP, ignore_errors=True)


class RealityHttpFiveRounds(unittest.TestCase):
    maxDiff = None

    # ---------- 第 1 轮 ----------
    def test_round1_create_returns_personal_reality_link(self):
        st, b = _api('/api/v1/users/create',
                     {'user_id': 'h1_alice', 'duration_days': 30}, API_KEY)
        self.assertEqual(st, 200, b)
        self.assertTrue(b.get('ok'), b)
        self.assertTrue(b.get('reality_uri'), '开户必须返回 Reality 链接: %s' % b)
        self.assertTrue(b.get('reality_uuid'), '开户必须返回 Reality UUID')
        self.assertIn(b['reality_uuid'], b['reality_uri'],
                      'Reality 链接里必须含该用户自己的 UUID')

    # ---------- 第 2 轮 ----------
    def test_round2_two_users_different_links(self):
        _, a = _api('/api/v1/users/create', {'user_id': 'h2_alice'}, API_KEY)
        _, b = _api('/api/v1/users/create', {'user_id': 'h2_bob'}, API_KEY)
        self.assertNotEqual(a['reality_uri'], b['reality_uri'],
                            '两个用户不能拿到同一条 Reality 链接')
        self.assertNotEqual(a['reality_uuid'], b['reality_uuid'])

    # ---------- 第 3 轮 ----------
    def test_round3_subscription_contains_both_protocols(self):
        _, r = _api('/api/v1/users/create', {'user_id': 'h3_carol'}, API_KEY)
        clash = json.loads(r['clash'])
        types = sorted(p['type'] for p in clash['proxies'])
        self.assertEqual(types, ['hysteria2', 'vless'],
                         '订阅里应同时有 Hy2 与 Reality: %s' % types)
        self.assertEqual(clash['proxy-groups'][0]['type'], 'url-test')
        sing = json.loads(r['sing_box'])
        self.assertIn('urltest', [o.get('type') for o in sing['outbounds']])

    # ---------- 第 4 轮 ----------
    def test_round4_delete_then_recreate(self):
        _, r = _api('/api/v1/users/create', {'user_id': 'h4_dave'}, API_KEY)
        uuid_first = r['reality_uuid']
        st, b = _api('/api/v1/users/delete', {'user_id': 'h4_dave'}, API_KEY)
        self.assertEqual(st, 200, b)
        self.assertTrue(b.get('ok'), b)
        # 重新开户：UUID 必须是同一个（幂等 —— 客户端配置不用重导入）
        _, r2 = _api('/api/v1/users/create', {'user_id': 'h4_dave'}, API_KEY)
        self.assertEqual(r2['reality_uuid'], uuid_first,
                         '同 user_id 重新开户应拿回同一 UUID（幂等）')

    # ---------- 第 5 轮 ----------
    def test_round5_full_lifecycle_over_http(self):
        ids = ['h5_f', 'h5_g', 'h5_h']
        created = {}
        for uid in ids:
            st, b = _api('/api/v1/users/create',
                         {'user_id': uid, 'duration_days': 30}, API_KEY)
            self.assertEqual(st, 200, b)
            created[uid] = b['reality_uuid']
        self.assertEqual(len(set(created.values())), 3, '三个用户三个 UUID')

        # 销掉 g，另两个不受影响
        st, b = _api('/api/v1/users/delete', {'user_id': 'h5_g'}, API_KEY)
        self.assertEqual(st, 200, b)
        st, b = _api('/api/v1/users/create', {'user_id': 'h5_g'}, API_KEY)
        self.assertEqual(b['reality_uuid'], created['h5_g'],
                         '销户再开户 UUID 不变')

        # f 与 h 仍然可以拉到含 Reality 的订阅
        for uid in ('h5_f', 'h5_h'):
            st, b = _api('/api/v1/users/create', {'user_id': uid + '_re'}, API_KEY)
            self.assertEqual(st, 200, b)
            clash = json.loads(b['clash'])
            self.assertEqual(len(clash['proxies']), 2)

        # 续期不动 UUID
        st, b = _api('/api/v1/users/renew',
                     {'user_id': 'h5_f', 'extend_days': 30}, API_KEY)
        self.assertEqual(st, 200, b)
        _, b2 = _api('/api/v1/users/create', {'user_id': 'h5_f'}, API_KEY)
        self.assertEqual(b2['reality_uuid'], created['h5_f'],
                         '续期不应改变 Reality UUID')

    # ---------- 鉴权面（顺带钉住，不能因本次改动放宽） ----------
    def test_api_key_still_required(self):
        req = urllib.request.Request(
            BASE + '/api/v1/users/create',
            data=json.dumps({'user_id': 'h6_nokey'}).encode(),
            headers={'Content-Type': 'application/json'}, method='POST')
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                self.fail('无 API key 也被放行了：HTTP %d' % r.status)
        except urllib.error.HTTPError as e:
            self.assertIn(e.code, (401, 429), '应当 401/429，实际 %d' % e.code)


if __name__ == '__main__':
    unittest.main(verbosity=2)
