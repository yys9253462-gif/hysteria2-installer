import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORTAL_PATH = ROOT / 'portal.py'


def _load_portal_module():
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    spec = importlib.util.spec_from_file_location('portal_batch56_item9', PORTAL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PageAndUserHtmlEscapingSvgAndDirtyArgsGuardTests(unittest.TestCase):
    def test_user_page_html_blocks_malicious_svg_and_escapes_attributes_and_dirty_args(self):
        mod = _load_portal_module()
        evil_svgs = [
            '<svg><script>alert(1)</script></svg>',
            '<svg onload="alert(1)"><rect/></svg>',
            '<svg><foreignObject><body onload=alert(1)/></foreignObject></svg>',
            '<img src=x onerror=alert(1)><svg></svg>',
        ]
        for bad_svg in evil_svgs:
            with self.subTest(bad_svg=bad_svg):
                out = mod.user_page_html(
                    'sni.example.com', '1.2.3.4', 443, '<b>bad</b>',
                    'u"1/x', {'used_bytes': 0}, 'hy2://u', 'clash', '{}',
                    bad_svg, 'tok" onclick="x', 'key" onmouseover="y', sub_port=18443,
                )
                self.assertNotIn('<script>alert(1)</script>', out)
                self.assertNotIn('onload="alert(1)"', out)
                self.assertNotIn('<foreignObject>', out)
                self.assertNotIn('<img src=x', out)
                self.assertNotIn('<b>bad</b>', out)
                self.assertNotIn('download="clash-u"1/x.yaml"', out)
                self.assertNotIn('action="/tok" onclick="x', out)
                self.assertNotIn('href="/tok" onclick="x', out)
                self.assertNotIn('?k=key" onmouseover="y"', out)

        # 非字符串 uri/clash/sing/host 不得导致 500
        out_dirty = mod.user_page_html(
            None, None, 443, None, 'alice', {'used_bytes': 0},
            None, 123, None, '<svg viewBox="0 0 10 10"><rect/></svg>', 'tok', 'key', sub_port=18443,
        )
        self.assertIn('<svg viewBox="0 0 10 10"><rect/></svg>', out_dirty)

    def test_page_html_escapes_token_and_tolerates_non_str_args_and_uid(self):
        mod = _load_portal_module()
        out = mod.page_html(
            {'server_name': 'node.example.com', 'listen_port': 443, 'subscription_port': 18443},
            None, 123, None, None,
            users={123: {'password': 'p'}, 'alice': {'password': 'p'}},
            api_key=456,
            token='tok" onclick="evil()',
            session_secret='sec',
            username=None,
            password=789,
        )
        self.assertNotIn('action="/tok" onclick="evil()/logout"', out)
        self.assertNotIn('action="/tok" onclick="evil()/manage-user"', out)
        self.assertNotIn('data-token="tok" onclick="evil()"', out)
        self.assertIn('alice', out)


if __name__ == '__main__':
    unittest.main()
