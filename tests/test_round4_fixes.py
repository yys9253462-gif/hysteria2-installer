"""第四轮排查修复的回归测试（2026-10-15）。

- 经 masquerade 代理进来的 /auth（带 X-Forwarded-For）直接拒且不计入全局失败桶
- 安装模板与核心升级都给 masquerade.proxy 打开 xForwarded
- 卸载只删 wgcf 自己的文件、并停掉 xray
- 重装脚本校验 HTTPS、无可猜默认密码；alpine2debian 不把密码展开进脚本
- 分享链接按账号代际签发：删了重建同名用户，旧链接失效；老用户链接不变
"""
import ast
import hashlib
import hmac
import io
import json
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import portal  # noqa: E402
from test_round2_fixes import PortalServer  # noqa: E402

INSTALL = (ROOT / 'install.sh').read_text(encoding='utf-8')
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))


class ForwardedAuthTest(unittest.TestCase):
    def handle(self, headers):
        auth_if = next(n for n in ast.walk(TREE) if isinstance(n, ast.If)
                       and ast.unparse(n.test) == "self.path == '/auth'")
        fn = ast.parse('def handle(self):\n    pass').body[0]
        fn.body = [auth_if]
        data = {'users': {'u1': {'password': 'pw', 'status': 'active'}}}
        env = {'json': json, 'time': time, 'hmac': hmac, 'ipaddress': __import__('ipaddress'),
               'data_lock': threading.RLock(), 'data': data, 'ip_tracker': {},
               'IP_TIMEOUT_SECONDS': 180, 'live_online_ips': lambda uid: set(),
               'user_access_denial': portal.user_access_denial,
               'user_table': lambda data: (data.get('users')
                   if isinstance(data.get('users'), dict) else {})}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])), 'auth', 'exec'), env)
        body = json.dumps({'auth': 'wrong', 'addr': '203.0.113.9:1'}).encode()
        handler = mock.Mock()
        handler.path = '/auth'
        handler.client_address = ('127.0.0.1', 12345)
        handler.headers = dict(headers, **{'Content-Length': str(len(body))})
        handler.rfile = io.BytesIO(body)
        handler.auth_rate_limited.return_value = False
        handler.reply_json.side_effect = lambda code, payload: payload
        return env['handle'](handler), handler

    def test_proxied_auth_is_rejected_without_touching_the_failure_bucket(self):
        response, handler = self.handle({'X-Forwarded-For': '198.51.100.7'})
        self.assertFalse(response['ok'])
        handler.auth_rate_limited.assert_not_called()
        handler.record_auth_failure.assert_not_called()

    def test_direct_core_request_still_counts_failures(self):
        response, handler = self.handle({})
        self.assertFalse(response['ok'])
        handler.record_auth_failure.assert_called_once()


class XForwardedConfigTest(unittest.TestCase):
    def test_install_template_enables_xforwarded(self):
        block = re.search(r'masquerade:\n  type: proxy\n  proxy:\n(?:    .*\n|\s*#.*\n)+', INSTALL).group(0)
        self.assertIn('    xForwarded: true', block)

    @unittest.skipIf(shutil.which('sed') is None, '需要 sed')
    def test_core_upgrade_backfills_xforwarded_once(self):
        line = next(ln for ln in INSTALL.splitlines() if 'xForwarded: true/' in ln)
        cmd = re.search(r"sed -i -E '([^']+)'", line).group(1)
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'config.yaml'
            cfg.write_text('masquerade:\n  type: proxy\n  proxy:\n    url: http://127.0.0.1:1/\n'
                           '    rewriteHost: false\n  listenHTTPS: :8443\n', encoding='utf-8')
            subprocess.run(['sed', '-i', '-E', cmd, cfg.as_posix()], check=True)
            text = cfg.read_text(encoding='utf-8')
        self.assertIn('    rewriteHost: false\n    xForwarded: true\n  listenHTTPS', text)
        # 已有 xForwarded 时不能重复插入（核心每次升级都会走到这里）。
        self.assertIn("! grep -qE '^[[:space:]]+xForwarded:' \"$HY2_DIR/config.yaml\"", INSTALL)


class UninstallTest(unittest.TestCase):
    def uninstall_block(self):
        start = INSTALL.index('确定要彻底卸载 Hysteria 2 服务及所有配置文件吗')
        return INSTALL[start:INSTALL.index('Hysteria 2 已彻底卸载完成', start)]

    def test_does_not_wipe_shared_wireguard_dir(self):
        block = self.uninstall_block()
        self.assertNotIn('rm -rf /etc/wireguard', block)
        self.assertIn('/etc/wireguard/wgcf-account.toml', block)

    def test_stops_and_removes_xray(self):
        block = self.uninstall_block()
        self.assertIn('systemctl disable --now xray', block)
        self.assertIn('/usr/local/bin/xray', block)


class ReinstallScriptsTest(unittest.TestCase):
    def test_installnet_download_verifies_tls(self):
        src = (ROOT / 'reinstall-debian13.sh').read_text(encoding='utf-8')
        code = '\n'.join(ln for ln in src.splitlines() if not ln.lstrip().startswith('#'))
        self.assertNotIn('--no-check-certificate', code)

    def test_no_guessable_default_password(self):
        src = (ROOT / 'reinstall-debian13.sh').read_text(encoding='utf-8')
        self.assertNotRegex(src, r'"rd13\$\(date')

    def test_alpine2debian_does_not_expand_password_into_script(self):
        src = (ROOT / 'alpine2debian.sh').read_text(encoding='utf-8')
        body = src[src.index('BODY=$(cat <<CHROOT_EOF'):src.index('\nCHROOT_EOF\n')]
        self.assertNotIn('${ROOT_PWD}', body)
        self.assertIn("printf 'root:%s\\n' \"$ROOT_PWD\"", src)


class ViewKeyTest(unittest.TestCase):
    def test_legacy_users_keep_their_existing_links(self):
        legacy = hmac.new(b's', b'uv:alice', hashlib.sha256).hexdigest()[:16]
        self.assertEqual(portal.user_view_key('s', 'alice'), legacy)
        self.assertEqual(portal.user_view_key('s', 'alice', ''), legacy)

    def test_nonce_changes_the_key(self):
        self.assertNotEqual(portal.user_view_key('s', 'alice', 'n1'), portal.user_view_key('s', 'alice', 'n2'))


class ViewKeyHttpTest(PortalServer):
    def view_key_in_page(self, uid):
        cookie = self.session_cookie()
        _, body = self.request(self.prefix, headers={'Cookie': cookie})
        return re.search(r'data-uid="%s"[^>]*data-key="([0-9a-f]+)"' % re.escape(uid), body).group(1)

    def session_cookie(self):
        token, secret, iat = self.data['token'], self.data['session_secret'], str(int(time.time()))
        sig = hmac.new(secret.encode(), f'sess:{token}:{iat}'.encode(), hashlib.sha256).hexdigest()
        return f'hy2_session={token}.{iat}.{sig}'

    def share_page(self, uid, key):
        return self.request('%su/%s?k=%s' % (self.prefix, uid, key))[0]

    def test_recreated_user_invalidates_previous_share_link(self):
        self.assertEqual(self.api('users/create', {'user_id': 'reuse_me'})[0], 200)
        old_key = self.view_key_in_page('reuse_me')
        self.assertEqual(self.share_page('reuse_me', old_key), 200)
        self.assertEqual(self.api('users/delete', {'user_id': 'reuse_me'})[0], 200)
        self.assertEqual(self.api('users/create', {'user_id': 'reuse_me'})[0], 200)
        self.assertEqual(self.share_page('reuse_me', old_key), 403)
        self.assertEqual(self.share_page('reuse_me', self.view_key_in_page('reuse_me')), 200)

    def test_updating_user_keeps_share_link(self):
        self.assertEqual(self.api('users/create', {'user_id': 'keep_link'})[0], 200)
        key = self.view_key_in_page('keep_link')
        self.assertEqual(self.api('users/create', {'user_id': 'keep_link', 'duration_days': 60})[0], 200)
        self.assertEqual(self.api('users/update', {'user_id': 'keep_link', 'ip_limit': 2})[0], 200)
        self.assertEqual(self.share_page('keep_link', key), 200)

    def test_api_responses_do_not_expose_the_nonce(self):
        """Teyir 读到的 users/update、users/get 响应字段必须和原来一样。"""
        self.assertEqual(self.api('users/create', {'user_id': 'no_leak'})[0], 200)
        _, body = self.api('users/update', {'user_id': 'no_leak', 'ip_limit': 1})
        self.assertNotIn('view_nonce', body)
        _, body = self.request('/api/v1/users/get/no_leak', headers={'Authorization': 'Bearer ' + self.data['api_key']})
        self.assertNotIn('view_nonce', body)
        _, body = self.api('users/list', {})
        self.assertNotIn('view_nonce', body)


if __name__ == '__main__':
    unittest.main()
