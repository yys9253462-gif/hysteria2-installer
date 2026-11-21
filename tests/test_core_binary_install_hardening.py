"""回归测试：Xray 与 sing-box 二进制安装异常处理清理暂存文件，并防护异常 Release 元数据。"""
import io
import json
import os
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _zip_xray(content=b'NEW-XRAY'):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr('xray', content)
    return buf.getvalue()


def _tgz_singbox(content=b'NEW-SINGBOX'):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tf:
        info = tarfile.TarInfo('sing-box-1.12.0-linux-amd64/sing-box')
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


class CoreBinaryInstallHardeningTests(unittest.TestCase):
    def test_install_xray_cleans_staged_file_when_replace_fails(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            real_path = Path

            def fake_path(val):
                s = str(val)
                if s.startswith('/usr/local/bin/xray'):
                    return real_path(str(root) + s[len('/usr/local/bin'):])
                return real_path(val)

            payload = _zip_xray()
            with mock.patch.object(portal, 'Path', side_effect=fake_path), \
                 mock.patch.object(portal, '_xray_version', side_effect=lambda b='/usr/local/bin/xray': '' if b == '/usr/local/bin/xray' else '26.3.27'), \
                 mock.patch.object(portal, 'fetch_expected_sha256', return_value='a' * 64), \
                 mock.patch.object(portal, 'verify_sha256', return_value=True), \
                 mock.patch.object(portal.platform, 'machine', return_value='x86_64'), \
                 mock.patch.object(portal.urllib.request, 'urlopen', side_effect=lambda *a, **k: _Resp(payload)), \
                 mock.patch.object(portal.os, 'replace', side_effect=OSError('disk busy')):
                ok, _ = portal.install_xray_binary()
            self.assertFalse(ok)
            leftovers = [p.name for p in root.iterdir()]
            self.assertEqual(leftovers, [], f'install_xray_binary 失败后残留暂存文件: {leftovers}')

    def test_install_singbox_rejects_non_dict_and_oversized_release_json(self):
        with mock.patch.object(portal, '_singbox_version', return_value=None), \
             mock.patch.object(portal.platform, 'machine', return_value='x86_64'), \
             mock.patch.object(portal.urllib.request, 'urlopen', side_effect=lambda *a, **k: _Resp(b'[]')):
            ok, msg = portal.install_singbox()
            self.assertFalse(ok)
            self.assertTrue(msg)

        oversized = b'{"tag_name":"v1.12.0","pad":"' + (b'x' * (3 * 1024 * 1024)) + b'"}'
        with mock.patch.object(portal, '_singbox_version', return_value=None), \
             mock.patch.object(portal.platform, 'machine', return_value='x86_64'), \
             mock.patch.object(portal.urllib.request, 'urlopen', side_effect=lambda *a, **k: _Resp(oversized)):
            ok, msg = portal.install_singbox()
            self.assertFalse(ok)
            self.assertIn('过大', msg)

    def test_install_singbox_handles_malformed_assets_and_cleans_staged_on_failure(self):
        with tempfile.TemporaryDirectory() as td:
            target = str(Path(td) / 'sing-box')
            rel = {
                'tag_name': 'v1.12.0',
                'assets': [
                    'not-a-dict',
                    {'name': 'sing-box-1.12.0-linux-amd64.tar.gz', 'digest': 'sha256:' + 'b' * 64},
                ],
            }
            tgz = _tgz_singbox()

            def fake_urlopen(req, timeout=15):
                url = req.full_url if hasattr(req, 'full_url') else str(req)
                if 'api.github.com' in url:
                    return _Resp(json.dumps(rel).encode('utf-8'))
                return _Resp(tgz)

            with mock.patch.object(portal, 'ANYTLS_BINARY', target), \
                 mock.patch.object(portal, '_singbox_version', side_effect=lambda b=None: None if b in (None, target) else (1, 12, 0)), \
                 mock.patch.object(portal, 'verify_sha256', return_value=True), \
                 mock.patch.object(portal.platform, 'machine', return_value='x86_64'), \
                 mock.patch.object(portal.urllib.request, 'urlopen', side_effect=fake_urlopen), \
                 mock.patch.object(portal.os, 'replace', side_effect=OSError('replace failed')):
                ok, _ = portal.install_singbox()
            self.assertFalse(ok)
            leftovers = [p.name for p in Path(td).iterdir()]
            self.assertEqual(leftovers, [], f'install_singbox 失败后残留暂存文件: {leftovers}')


if __name__ == '__main__':
    unittest.main()
