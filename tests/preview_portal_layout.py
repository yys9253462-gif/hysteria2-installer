"""Local preview of the portal information architecture (no privileged services).

Renders portal.page_html() with placeholder meta and stubs the portal's fetch
endpoints so the page can be inspected in a browser without a node install.
Run: python tests/preview_portal_layout.py  → http://127.0.0.1:8766/
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal

META = {
    'public_ip': '203.0.113.10', 'server_name': 'node.example.com',
    'subscription_port': 23456, 'listen_port': 443, 'hop_port_range': '20000-40000',
    'auth_password': 'preview-only', 'obfs_password': 'preview-obfs',
    'cert_type': 'acme', 'is_insecure': False, 'pin_sha256': '',
}

STUB = {
    'warp-status': {'ok': True, 'installed': True, 'active': True, 'enabled': True,
                    'rules': ['openai.com', 'claude.ai'], 'outbound_ip': '198.51.100.7'},
    'bbr-status': {'ok': True, 'current': 'bbr', 'qdisc': 'fq', 'kernel': '6.1.0',
                   'reboot_required': False},
    'cert-status': {'ok': True, 'days_left': 62, 'not_after': '2026-12-25 00:00',
                    'cn': 'node.example.com', 'sans': ['node.example.com'],
                    'issuer': "Let's Encrypt", 'cert_type': 'acme',
                    'server_name': 'node.example.com', 'pin': 'aa:bb:cc'},
    'check-version': {'ok': True, 'core_current': '2.6.4', 'core_latest': '2.6.4',
                      'core_has_update': False, 'portal_current': 'aaaaaaa',
                      'portal_latest': 'aaaaaaa', 'portal_has_update': False,
                      'portal_update_status': 'up_to_date', 'awg_installed': True,
                      'awg_current': 'ccccccc', 'awg_latest': 'ccccccc',
                      'awg_has_update': False},
    'proxy-services': {'ok': True, 'services': [
        {'id': 'p1', 'type': 'socks5', 'port': 31001, 'username': 'u_demo',
         'password': 'p_demo'}]},
    'awg-state': {'ok': True, 'installed': True, 'active': True, 'line': 3,
                  'port': 53821, 'peers': [{'name': 'phone', 'address': '10.66.0.2',
                                            'created': '2026-10-01'}]},
    'reality-status': {'ok': True, 'installed': True, 'active': True,
                       'port': 8443, 'sni': 'www.apple.com:443',
                       'uuid': '11111111-2222-3333-4444-555555555555',
                       'public_key': 'preview-pubkey', 'short_id': 'abcd', 'flow': 'xtls-rprx-vision'},
    'vmess-status': {'ok': True, 'installed': True, 'active': True,
                     'config': {'uri': 'vmess://preview-only', 'port': 2087,
                                'domain': 'node.example.com', 'sni': 'node.example.com',
                                'uuid': '11111111-2222-3333-4444-555555555555',
                                'ws_path': '/AbCdEf123456', 'qr_svg': ''}},
    'vlessenc-status': {'ok': True, 'installed': True, 'active': True,
                        'config': {'uri': 'vless://preview-only', 'port': 2088,
                                   'domain': 'node.example.com', 'sni': 'node.example.com',
                                   'uuid': '11111111-2222-3333-4444-555555555555',
                                   'qr_svg': ''}},
    'outbounds': {'ok': True, 'mode': 'rules', 'outbound_ip': '203.0.113.10',
                  'outbounds': [{'name': 'us_exit', 'type': 'socks5',
                                 'addr': '198.51.100.9:1080'}],
                  'rules': [{'domain': 'netflix.com', 'outbound': 'us_exit'}]},
    'traffic-speed': {'ok': True, 'rx_bps': 1200000, 'tx_bps': 240000},
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlsplit(self.path).path.strip('/')
        if path in STUB:
            body = json.dumps(STUB[path]).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(body)
            return
        if path == 'qr.svg':
            svg = ('<svg xmlns="http://www.w3.org/2000/svg" width="260" height="260">'
                   '<rect width="260" height="260" fill="#eaf5ef"/>'
                   '<text x="130" y="135" text-anchor="middle" font-size="14" fill="#4c6b70">'
                   'QR (preview)</text></svg>')
            self.send_response(200)
            self.send_header('Content-Type', 'image/svg+xml')
            self.end_headers()
            self.wfile.write(svg.encode())
            return
        page = portal.page_html(
            META, 'hysteria2://preview@node.example.com:443/?obfs=salamander&obfs-password=x',
            'https://node.example.com:23456/t/clash.yaml', 'proxy-groups: []', '{}',
            users={'buyer_01': {'password': 'x', 'status': 'active', 'used_bytes': 2 << 30,
                                'limit_bytes': 100 << 30, 'ip_limit': 1,
                                'expires_at': 1800000000, 'note': '预览用户'}},
            api_key='preview-api-key', token='t', session_secret='s')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(page.encode())

    def log_message(self, *_):
        pass


if __name__ == '__main__':
    print('Portal layout preview: http://127.0.0.1:8766/', flush=True)
    ThreadingHTTPServer(('127.0.0.1', 8766), Handler).serve_forever()
