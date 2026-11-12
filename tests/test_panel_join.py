"""panel-join.py 输出的 api_url 必须带主机名（2026-11-03）。

旧逻辑只从 config.yaml 的 acme.domains 找域名。证书来自 Caddy / 手工路径（tls 段）
或自签时没有这一段，于是在瑞典节点上打印出 `https://13427` 并返回 0。
现在与门户同一条规则：可信证书用 client_meta.json 的 server_name，自签用 public_ip。
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'panel-join.py'

TLS_CONFIG = """listen: :40515
tls:
  cert: /var/lib/caddy/certificates/node.example.com.crt
  key: /var/lib/caddy/certificates/node.example.com.key
auth:
  type: http
  http:
    url: http://127.0.0.1:45093/auth

masquerade:
  type: proxy
  proxy:
    url: http://127.0.0.1:45093/
  listenHTTPS: :13427
"""

ACME_CONFIG = """listen: :443
acme:
  domains:
    - acme.example.org
  email: ops@example.org

masquerade:
  type: proxy
  listenHTTPS: :8443
"""

# 与 install.sh 写出的格式一致：acme.domains 的列表项带引号。
INSTALLER_ACME_CONFIG = """listen: :443
acme:
  domains:
    - "%s"
  email: "ops@example.org"

masquerade:
  type: proxy
  listenHTTPS: :8443
"""

META = {'server_name': 'node.example.com', 'public_ip': '203.0.113.10', 'is_insecure': False}


class PanelJoinApiUrlTest(unittest.TestCase):
    def run_join(self, config, meta=None):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'config.yaml').write_text(config, encoding='utf-8')
            (root / 'portal.json').write_text(json.dumps({'api_key': 'k' * 48, 'port': 45093}),
                                              encoding='utf-8')
            meta_path = root / 'client_meta.json'
            if meta is not None:
                meta_path.write_text(json.dumps(meta), encoding='utf-8')
            result = subprocess.run(
                [sys.executable, str(SCRIPT), '--config', str(root / 'config.yaml'),
                 '--portal', str(root / 'portal.json'), '--meta', str(meta_path),
                 '--format', 'json'],
                capture_output=True, text=True, timeout=30)
        return result

    def api_url(self, config, meta=None):
        result = self.run_join(config, meta)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)['api_url']

    def test_trusted_certificate_without_acme_uses_server_name(self):
        self.assertEqual(self.api_url(TLS_CONFIG, {'server_name': 'node.example.com',
                                                   'public_ip': '203.0.113.10',
                                                   'is_insecure': False}),
                         'https://node.example.com:13427')

    def test_self_signed_node_uses_public_ip(self):
        self.assertEqual(self.api_url(TLS_CONFIG, {'server_name': 'www.bing.com',
                                                   'public_ip': '203.0.113.10',
                                                   'is_insecure': True}),
                         'https://203.0.113.10:13427')

    def test_ipv6_public_ip_is_bracketed(self):
        self.assertEqual(self.api_url(TLS_CONFIG, {'public_ip': '2001:db8::10',
                                                   'is_insecure': True}),
                         'https://[2001:db8::10]:13427')

    def test_acme_domain_still_used_without_meta(self):
        self.assertEqual(self.api_url(ACME_CONFIG), 'https://acme.example.org:8443')

    def test_no_host_anywhere_fails_instead_of_printing_port_only_url(self):
        result = self.run_join(TLS_CONFIG, {'is_insecure': False})
        self.assertEqual(result.returncode, 3, result.stdout)
        self.assertNotIn('https://13427', result.stdout)

    def test_installer_quoted_acme_domain_is_used_whole(self):
        """安装脚本写 `- "域名"`：旧正则从连字符起截成 node.example.org，无连字符则取不到（2026-11-12 修）。"""
        for name in ('my-node.example.org', 'example.org'):
            with self.subTest(name=name):
                self.assertEqual(self.api_url(INSTALLER_ACME_CONFIG % name), 'https://%s:8443' % name)


class PanelJoinConfigValuesTest(unittest.TestCase):
    """config.yaml 里合法但非默认的写法（2026-11-12 修）。"""

    run_join = PanelJoinApiUrlTest.run_join

    def result(self, config):
        r = self.run_join(config, META)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def test_trailing_comments_do_not_hide_ports(self):
        out = self.result('listen: :443  # 主端口\nmasquerade:\n  type: proxy\n'
                          '  listenHTTPS: ":8443"  # 订阅 / API\n')
        self.assertEqual(out['api_url'], 'https://node.example.com:8443')
        self.assertEqual(out['listen_port'], 443)

    def test_listen_with_bind_address_keeps_port_and_name(self):
        for listen in ('0.0.0.0:443', '"[::]:443"'):
            with self.subTest(listen=listen):
                out = self.result('listen: %s\nmasquerade:\n  listenHTTPS: :8443\n' % listen)
                self.assertEqual(out['listen_port'], 443)
                self.assertEqual(out['suggested_name'], 'node.example.com-443')

    def test_out_of_range_api_port_is_refused(self):
        for port in ('0', '70000'):
            with self.subTest(port=port):
                r = self.run_join('listen: :443\nmasquerade:\n  listenHTTPS: :%s\n' % port, META)
                self.assertEqual(r.returncode, 3, r.stdout)
                self.assertNotIn('api_url', r.stdout)

    def test_commented_out_listenhttps_is_not_used(self):
        r = self.run_join('listen: :443\nmasquerade:\n  type: proxy\n  # listenHTTPS: :1111\n', META)
        self.assertEqual(r.returncode, 3, r.stdout)
        self.assertNotIn(':1111', r.stdout)


if __name__ == '__main__':
    unittest.main()
