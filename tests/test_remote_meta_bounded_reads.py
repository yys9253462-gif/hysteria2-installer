"""回归测试：门户所有外部元数据拉取均须有体积上限且防护非对象 JSON。"""
import io
import unittest
from pathlib import Path
from unittest import mock

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


class _CountingOversizedResp:
    """记录调用方是否传入读取字节上限；若无参 read() 则返回超限数据。"""

    def __init__(self, size=3 * 1024 * 1024, prefix=b''):
        self.size = size
        self.prefix = prefix
        self.read_args = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, n=-1):
        self.read_args.append(n)
        total = self.prefix + (b'a' * max(0, self.size - len(self.prefix)))
        if n is None or n < 0:
            return total
        return total[:n]


class RemoteMetaBoundedReadsTests(unittest.TestCase):
    def test_fetch_text_enforces_size_limit(self):
        resp = _CountingOversizedResp(size=3 * 1024 * 1024)
        with mock.patch.object(portal.urllib.request, 'urlopen', return_value=resp):
            with self.assertRaises(ValueError):
                portal.fetch_text('https://example.invalid/checksums.txt')
        self.assertTrue(resp.read_args and resp.read_args[0] > 0, 'fetch_text 未向 resp.read 传入上限')

    def test_resolve_update_ref_rejects_oversized_api_and_atom_responses(self):
        sha = 'a' * 40
        api_resp = _CountingOversizedResp(
            size=3 * 1024 * 1024,
            prefix=('{"sha":"%s","pad":"' % sha).encode(),
        )
        atom_resp = _CountingOversizedResp(
            size=3 * 1024 * 1024,
            prefix=('/commit/%s ' % sha).encode(),
        )
        with mock.patch.object(portal.urllib.request, 'urlopen', side_effect=[api_resp, atom_resp]):
            with self.assertRaises(RuntimeError):
                portal.resolve_update_ref('main')
        self.assertTrue(api_resp.read_args and api_resp.read_args[0] > 0, 'resolve_update_ref API 读取未限流')
        self.assertTrue(atom_resp.read_args and atom_resp.read_args[0] > 0, 'resolve_update_ref Atom 读取未限流')

    def test_portal_source_no_unbounded_meta_read_in_update_and_version_paths(self):
        src = (Path(__file__).resolve().parents[1] / 'portal.py').read_text(encoding='utf-8')
        # 检查 _remote_root_shas / _remote_blob_sha / _h_post_install_gost / _h_get_check_version / fetch_portal_file
        self.assertNotIn("items = json.loads(resp.read().decode('utf-8'))", src)
        self.assertNotIn("info = json.loads(resp.read().decode('utf-8'))", src)
        self.assertNotIn("rel_data = json.loads(r.read().decode())", src)
        self.assertNotIn("release = json.loads(response.read().decode('utf-8'))", src)
        self.assertNotIn("content = resp.read()\n                # 体积 + 关键字双重校验", src)


if __name__ == '__main__':
    unittest.main()
