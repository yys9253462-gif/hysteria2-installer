"""回归测试：regenerate_page 容忍损坏 ip_tracker 时间戳且锁内读 token；/u/<uid> 与 /user-config 容忍损坏 users 与非字符串节点身份。"""

import hashlib
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


def _extract_regenerate_page(ns):
    src = (ROOT / 'portal.py').read_text(encoding='utf-8')
    start = src.index('    def regenerate_page():')
    end = src.index('    # 会话在服务端过期', start)
    lines = src[start:end].splitlines()
    dedented = '\n'.join(ln[4:] if ln.startswith('    ') else ln for ln in lines)
    exec(compile(dedented, '<regenerate_page>', 'exec'), ns)
    return ns['regenerate_page']


class RegeneratePageAndShareCorruptDataTests(unittest.TestCase):
    def test_regenerate_page_survives_corrupt_ip_tracker_timestamps_and_filters_future_clock(self):
        """ip_tracker 含非数字或未来时间戳时，regenerate_page 不得抛 TypeError，且过滤非法/未来项。"""
        now_ts = int(time.time())
        data = {
            'token': 'tok_regen_1',
            'users': {'u1': {'password': 'p1', 'status': 'active'}},
        }
        ip_tracker = {
            'u1': {'1.1.1.1': 'bad-ts', '2.2.2.2': None, '3.3.3.3': now_ts + 3600, '4.4.4.4': now_ts - 5},
            'u_dead': {'5.5.5.5': 'bad-only'},
        }
        captured = {}

        def fake_page_html(m, uri, subscription, clash, sing, users=None, **kw):
            captured['subscription'] = subscription
            captured['users'] = users
            return '<html>ok</html>'

        ns = dict(
            portal.__dict__,
            data=data,
            data_lock=threading.RLock(),
            ip_tracker=ip_tracker,
            IP_TIMEOUT_SECONDS=120,
            meta_path=Path('/tmp/meta.json'),
            portal_path=Path('/tmp/portal.json'),
            session_secret='sec',
            read_meta_file=lambda _: {'public_ip': '198.51.100.1', 'listen_port': 443},
            artifacts=lambda m: ('hysteria2://u@h:443', 'clash', '{}'),
            read_access_file=lambda _: {'username': 'admin', 'password': 'pw'},
            resolve_subscription_port=lambda m: (8443, 'meta'),
            page_html=fake_page_html,
            qr_svg_for=lambda u: '<svg/>',
            save_data=mock.Mock(),
            hashlib=hashlib,
            time=time,
        )
        regen = _extract_regenerate_page(ns)
        regen()
        self.assertIn('/tok_regen_1/clash.yaml', captured['subscription'])
        self.assertEqual(list(captured['users']['u1']['online_ips'].keys()), ['4.4.4.4'])
        self.assertNotIn('u_dead', ip_tracker)

    def test_share_and_user_config_routes_use_user_table_and_clean_node_identity(self):
        """/u/<uid> 与 /user-config 必须经 user_table(data) 读取用户，且 /u/<uid> 校验清洗后的真实节点身份。"""
        src = (ROOT / 'portal.py').read_text(encoding='utf-8')
        u_start = src.index("if subpath.startswith('u/'):")
        u_end = src.index("# 2. 版本检查与更新 API", u_start)
        u_block = src[u_start:u_end]
        self.assertNotIn("data.get('users', {}).get(target_uid)", u_block,
                         '/u/<uid> 直接访问 data.get("users", {})，当 users 损坏为列表时会抛 AttributeError')
        self.assertIn('user_table(data).get(target_uid)', u_block)
        self.assertNotIn("if not (m.get('server_name') or m.get('public_ip')):", u_block,
                         '/u/<uid> 仅判断原始 m 字段，非字符串 server_name 会绕过校验退回 localhost')

        uc_start = src.index("if subpath == 'user-config' or subpath.startswith('user-config?'):")
        uc_end = src.index("m = read_meta_file(meta_path)", uc_start)
        uc_block = src[uc_start:uc_end]
        self.assertNotIn("data.get('users', {}).get(target_uid)", uc_block,
                         '/user-config 直接访问 data.get("users", {})，当 users 损坏为列表时会抛 AttributeError')
        self.assertIn('user_table(data).get(target_uid)', uc_block)


if __name__ == '__main__':
    unittest.main()
