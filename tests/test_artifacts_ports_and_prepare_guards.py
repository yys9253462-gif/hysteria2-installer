"""回归测试：_valid_port / clean_hop_range 纯 ASCII 校验、artifacts / page_html / sync_pin 非字典容错及 prepare 参数校验。"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


class ArtifactsPortsAndPrepareGuardsTests(unittest.TestCase):
    def test_valid_port_and_clean_hop_range_reject_non_ascii_digits(self):
        """_valid_port 与 clean_hop_range 必须拒绝全角数字及带正号的端口串。"""
        for bad in ('\uff14\uff14\uff13', '+443', '-443', float('inf'), float('nan')):
            with self.subTest(bad=bad):
                self.assertEqual(portal._valid_port(bad), 0)
        self.assertEqual(portal._valid_port('443'), 443)
        self.assertEqual(portal._valid_port(' 8443 '), 8443)
        self.assertEqual(portal._valid_port(443.0), 443)

        for bad_hop in ('\uff12\uff10\uff10\uff10\uff10-\uff14\uff10\uff10\uff10\uff10', '20000-\uff14\uff10\uff10\uff10\uff10'):
            with self.subTest(bad_hop=bad_hop):
                self.assertIsNone(portal.clean_hop_range(bad_hop))
        self.assertEqual(portal.clean_hop_range('20000-40000'), (20000, 40000))

    def test_artifacts_page_html_and_sync_pin_survive_non_dict_meta(self):
        """client_meta 为非 dict（如 None / []）时，artifacts、page_html、sync_pin 均不得抛 AttributeError。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for bad_meta in (None, [], 'corrupt'):
                with self.subTest(bad_meta=bad_meta):
                    uri, clash, sing = portal.artifacts(bad_meta)
                    self.assertTrue(uri.startswith('hysteria2://'))
                    self.assertIn('proxies', json.loads(clash))
                    self.assertIn('outbounds', json.loads(sing))
                    html_out = portal.page_html(bad_meta, uri, 'https://example.com', clash, sing)
                    self.assertIn('<html', html_out)
                    portal.sync_pin(bad_meta, root, root / 'client_meta.json')

    def test_prepare_rejects_fullwidth_port_and_invalid_node_api_key(self):
        """prepare 必须拒绝全角端口串以及含空白/控制字符/非 ASCII 的 node_api_key。"""
        with tempfile.TemporaryDirectory() as td:
            meta = Path(td) / 'client_meta.json'
            meta.write_text(json.dumps({'server_name': 'example.com', 'public_ip': '1.2.3.4'}), encoding='utf-8')
            with self.assertRaises(ValueError):
                portal.prepare(meta, '\uff18\uff10\uff18\uff10')
            for bad_key in (123, 'key with space', 'key\nline', '中文密钥'):
                with self.subTest(bad_key=bad_key):
                    with self.assertRaises(ValueError):
                        portal.prepare(meta, 8080, node_api_key=bad_key)


if __name__ == '__main__':
    unittest.main()
