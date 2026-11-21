"""回归测试：gost_tls_paths 容忍未闭合引号并拒绝空证书文件；reality_iplimit_worker 排除布尔时间戳。"""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORTAL = ROOT / 'portal.py'
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class IplimitBoolTsAndGostTlsPathsTests(unittest.TestCase):
    def test_gost_tls_paths_survives_unclosed_quote_and_rejects_empty_legacy_cert(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'config.yaml').write_text('tls:\n  cert: "unclosed\n  key: "unclosed\n', encoding='utf-8')
            legacy = root / 'gost-cert'
            legacy.mkdir()
            (legacy / 'cert.pem').write_bytes(b'')
            (legacy / 'key.pem').write_bytes(b'')
            with self.assertRaises(RuntimeError):
                portal.gost_tls_paths(root)

            # 写入有效非空 legacy 证书后，即便 config.yaml 含坏引号也能安全回落
            (legacy / 'cert.pem').write_bytes(b'CERT')
            (legacy / 'key.pem').write_bytes(b'KEY')
            cert, key = portal.gost_tls_paths(root)
            self.assertEqual(Path(cert), legacy / 'cert.pem')
            self.assertEqual(Path(key), legacy / 'key.pem')

    def test_reality_iplimit_worker_filters_bool_timestamps(self):
        src = PORTAL.read_text(encoding='utf-8')
        start = src.index('def reality_iplimit_worker():')
        end = src.index('def usage_summary(uid):', start)
        block = src[start:end]
        self.assertIn('not isinstance(t, bool)', block,
                      'reality_iplimit_worker 读取 ip_tracker 时间戳未排除 bool')


if __name__ == '__main__':
    unittest.main()
