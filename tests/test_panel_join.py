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


if __name__ == '__main__':
    unittest.main()
