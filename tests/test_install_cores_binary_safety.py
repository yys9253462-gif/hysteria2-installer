"""回归测试：install_singbox 拦截空/非法 tag、全量检查 tar 成员安全并刷盘；install_xray_binary 落盘前刷盘。"""

import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class InstallCoresBinarySafetyTests(unittest.TestCase):
    def test_install_singbox_rejects_empty_or_traversal_tag_before_asset_lookup(self):
        for bad_tag in ('', '../evil', 'v1.12.0/../../x'):
            payload = json.dumps({'tag_name': bad_tag, 'assets': []}).encode('utf-8')
            fake_resp = mock.MagicMock()
            fake_resp.__enter__.return_value = io.BytesIO(payload)
            fake_resp.__exit__.return_value = False
            with mock.patch.object(portal, '_singbox_version', return_value=None), \
                 mock.patch.object(portal.platform, 'machine', return_value='x86_64'), \
                 mock.patch.object(portal.urllib.request, 'urlopen', return_value=fake_resp):
                ok, msg = portal.install_singbox()
            self.assertFalse(ok)
            self.assertIn('版本号', msg, f'bad_tag={bad_tag!r} 应被版本号校验前置拦截，实际={msg!r}')

    def test_install_singbox_checks_all_tar_members_and_both_installers_fsync(self):
        src = (ROOT / 'portal.py').read_text(encoding='utf-8')
        sb_start = src.index('def install_singbox():')
        sb_end = src.index('# ---- VLESS Encryption', sb_start)
        sb_block = src[sb_start:sb_end]
        self.assertNotIn('[m.name for m in tar.getmembers() if m.isfile()]', sb_block,
                         'install_singbox 不应跳过非普通文件 tar 成员的路径安全检查')
        self.assertIn('os.fsync(', sb_block, 'install_singbox 替换二进制前未 fsync 刷盘')

        xr_start = src.index('def install_xray_binary():')
        xr_end = src.index('def install_singbox():', xr_start)
        xr_block = src[xr_start:xr_end]
        self.assertIn('os.fsync(', xr_block, 'install_xray_binary 替换二进制前未 fsync 刷盘')

    def test_install_singbox_rejects_symlink_member_in_tar(self):
        import hashlib
        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode='w:gz') as tf:
            bin_info = tarfile.TarInfo('sing-box-1.12.0-linux-amd64/sing-box')
            bin_data = b'fake-bin'
            bin_info.size = len(bin_data)
            tf.addfile(bin_info, io.BytesIO(bin_data))
            sym_info = tarfile.TarInfo('sing-box-1.12.0-linux-amd64/link')
            sym_info.type = tarfile.SYMTYPE
            sym_info.linkname = '/etc/passwd'
            tf.addfile(sym_info)
        tar_bytes = tar_buf.getvalue()
        sha = hashlib.sha256(tar_bytes).hexdigest()
        meta_bytes = json.dumps({
            'tag_name': 'v1.12.0',
            'assets': [{
                'name': 'sing-box-1.12.0-linux-amd64.tar.gz',
                'digest': f'sha256:{sha}',
            }],
        }).encode('utf-8')

        def fake_urlopen(req, timeout=15):
            url = req.full_url if hasattr(req, 'full_url') else str(req)
            data = meta_bytes if 'api.github.com' in url else tar_bytes
            cm = mock.MagicMock()
            cm.__enter__.return_value = io.BytesIO(data)
            cm.__exit__.return_value = False
            return cm

        with mock.patch.object(portal, '_singbox_version', return_value=None), \
             mock.patch.object(portal.platform, 'machine', return_value='x86_64'), \
             mock.patch.object(portal.urllib.request, 'urlopen', side_effect=fake_urlopen), \
             mock.patch.object(portal.os, 'replace') as m_replace:
            ok, msg = portal.install_singbox()
        self.assertFalse(ok)
        self.assertIn('不允许的链接成员', msg)
        m_replace.assert_not_called()


if __name__ == '__main__':
    unittest.main()
