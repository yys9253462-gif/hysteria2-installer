import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import portal  # noqa: E402


class TestCoreUpgradeGostTlsWritePrivAndUnlockSsrf(unittest.TestCase):
    def test_upgrade_core_binary_rejects_traversal_tag_and_bounds_download_stream(self):
        """_upgrade_core_binary_locked 必须拒绝非法/路径穿越 tag 且对下载流施加体积上限。"""
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            binary = td_path / 'hysteria'
            binary.write_bytes(b'\x7fELFdummy')
            backup_dir = td_path / 'backups'

            # 1) 路径穿越 tag 不得继续拼 URL 拉取 hashes.txt
            with mock.patch.object(portal.platform, 'machine', return_value='x86_64'), \
                 mock.patch.object(portal.subprocess, 'run', return_value=mock.Mock(returncode=0, stdout='Version: v2.6.0\n')), \
                 mock.patch.object(portal, 'fetch_text', return_value=json.dumps({'tag_name': '../evil/tag'})), \
                 mock.patch.object(portal.urllib.request, 'urlopen', side_effect=OSError('skip fallback')), \
                 mock.patch.object(portal, 'fetch_expected_sha256') as mock_sha:
                with self.assertRaisesRegex(RuntimeError, '无法确定 Hysteria 版本|版本'):
                    portal._upgrade_core_binary_locked(str(binary), str(backup_dir))
                mock_sha.assert_not_called()

            # 2) 超限下载流必须被 _copy_stream_bounded 拦截
            class _BigResp(io.BytesIO):
                def __enter__(self):
                    return self
                def __exit__(self, *a):
                    return False

            with mock.patch.object(portal.platform, 'machine', return_value='x86_64'), \
                 mock.patch.object(portal.subprocess, 'run', return_value=mock.Mock(returncode=0, stdout='Version: v2.6.0\n')), \
                 mock.patch.object(portal, 'fetch_text', return_value=json.dumps({'tag_name': 'app/v2.6.1'})), \
                 mock.patch.object(portal, 'fetch_expected_sha256', return_value='0' * 64), \
                 mock.patch.object(portal, '_MAX_BINARY_ARCHIVE_BYTES', 256), \
                 mock.patch.object(portal.urllib.request, 'urlopen', return_value=_BigResp(b'X' * 1024)):
                with self.assertRaisesRegex(ValueError, '超过上限'):
                    portal._upgrade_core_binary_locked(str(binary), str(backup_dir))

    def test_gost_tls_paths_survives_bad_utf8_and_finds_privkey_pem(self):
        """gost_tls_paths 遇到损坏 UTF-8 config.yaml 须回退到 gost-cert，且 fullchain.pem 应自动匹配 privkey.pem。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'config.yaml').write_bytes(b'\xff\xfe\xfd')
            legacy = root / 'gost-cert'
            legacy.mkdir()
            (legacy / 'cert.pem').write_text('CERT', encoding='utf-8')
            (legacy / 'key.pem').write_text('KEY', encoding='utf-8')
            cert, key = portal.gost_tls_paths(root)
            self.assertTrue(cert.endswith('cert.pem'))
            self.assertTrue(key.endswith('key.pem'))

            # fullchain.pem + privkey.pem 布局（未显式写 tls.key）
            root2 = Path(td) / 'c2'
            (root2 / 'certs').mkdir(parents=True)
            (root2 / 'certs' / 'fullchain.pem').write_text('CERT', encoding='utf-8')
            (root2 / 'certs' / 'privkey.pem').write_text('KEY', encoding='utf-8')
            (root2 / 'config.yaml').write_text('tls:\n  cert: certs/fullchain.pem\n', encoding='utf-8')
            cert2, key2 = portal.gost_tls_paths(root2)
            self.assertTrue(cert2.endswith('fullchain.pem'))
            self.assertTrue(key2.endswith('privkey.pem'))

    def test_write_private_bytes_uses_o_nofollow_and_unlock_fetch_blocks_file_scheme(self):
        """portal._write_private_bytes 源码须叠加 O_NOFOLLOW，且 _unlock_fetch 须拒绝 file:// 本地读取。"""
        src = (REPO / 'portal.py').read_text(encoding='utf-8')
        start = src.index('def _write_private_bytes(')
        end = src.index('def apply_xray_config_transaction(', start)
        self.assertIn('O_NOFOLLOW', src[start:end])

        with tempfile.TemporaryDirectory() as td:
            secret = Path(td) / 'secret.txt'
            secret.write_text('TOP_SECRET', encoding='utf-8')
            with self.assertRaises(Exception):
                portal._unlock_fetch(secret.as_uri())


if __name__ == '__main__':
    unittest.main()
