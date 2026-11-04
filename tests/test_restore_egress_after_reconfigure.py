"""「重新修改配置」重写 config.yaml 后，adopt 把保存的 WARP 分流写回去（2026-11-04 修）。"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402

FRESH = """listen: :443
auth:
  type: http
  http:
    url: http://127.0.0.1:1/auth

outbounds:
  - name: direct_ipv4
    type: direct
    direct:
      mode: "4"
  - name: warp_socks
    type: socks5
    socks5:
      addr: 127.0.0.1:19898

# 安全：禁止代理用户访问节点本机/内网/云元数据
acl:
  inline:
    - reject(127.0.0.0/8)
    - reject(10.0.0.0/8)
    - direct_ipv4(all)
"""


class RestoreEgressTests(unittest.TestCase):
    def test_saved_warp_rules_come_back(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'config.yaml').write_text(FRESH, encoding='utf-8')
            (root / 'portal.json').write_text(json.dumps({
                'warp_enabled': True, 'outbound_mode': 'rules',
                'warp_rules': [{'domain': 'openai.com', 'outbound': 'warp_socks'}],
                'custom_outbounds': []}), encoding='utf-8')
            with mock.patch.object(portal, '_existing_outbound_names', return_value=['direct_ipv4', 'warp_socks']):
                changed = portal.restore_egress_into_config(root)
            text = (root / 'config.yaml').read_text(encoding='utf-8')
        self.assertTrue(changed)
        self.assertIn('suffix:openai.com', text)

    def test_nothing_saved_leaves_config_alone(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'config.yaml').write_text(FRESH, encoding='utf-8')
            (root / 'portal.json').write_text(json.dumps({}), encoding='utf-8')
            before = (root / 'config.yaml').read_text(encoding='utf-8')
            with mock.patch.object(portal, '_existing_outbound_names', return_value=['direct_ipv4', 'warp_socks']):
                portal.restore_egress_into_config(root)
            self.assertEqual((root / 'config.yaml').read_text(encoding='utf-8'), before)


if __name__ == '__main__':
    unittest.main()
