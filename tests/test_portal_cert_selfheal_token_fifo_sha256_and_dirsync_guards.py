"""回归测试：门户证书自愈防符号链接与坏UTF-8、令牌防FIFO阻塞、指纹零TOCTOU与目录fsync安全守卫。"""

import ast
import copy
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import portal  # noqa: E402

SOURCE = (REPO / 'portal.py').read_text(encoding='utf-8')
TREE = ast.parse(SOURCE)


def _fn_source(name):
    node = next(
        n for n in ast.walk(TREE)
        if isinstance(n, ast.FunctionDef) and n.name == name
    )
    lines = SOURCE.splitlines()
    return '\n'.join(lines[node.lineno - 1:node.end_lineno])


class PortalCertSelfhealTokenFifoSha256AndDirsyncGuardsTests(unittest.TestCase):
    def test_sync_cert_meta_from_cert_rejects_symlink_config_and_tolerates_bad_utf8_acme(self):
        """sync_cert_meta_from_cert 读 config.yaml 须拒绝符号链接且容错坏 UTF-8，避免把 ACME 节点误降级为 custom。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = root / 'config.yaml'
            cert = root / 'server.crt'
            cert.write_text('dummy-cert', encoding='utf-8')
            # 含非法 UTF-8 注释但带 acme: 块
            cfg.write_bytes(b'# bad \xff comment\nacme:\n  domains:\n    - a.example.com\n')
            meta = {
                'cert_type': 'self_signed',
                'is_insecure': True,
                'server_name': 'old.example.com',
                'cert_sha256': 'a' * 64,
            }
            meta_path = root / 'client_meta.json'
            with patch.object(portal, '_config_tls_cert_path', return_value=''), \
                    patch.object(portal, '_resolve_live_cert', return_value=(cert, 'a.example.com', ['a.example.com'], False)), \
                    patch.object(portal, 'atomic_write_private', return_value=None):
                changed = portal.sync_cert_trust(meta, root, meta_path, config_path=cfg)
            self.assertTrue(changed)
            self.assertEqual(meta['cert_type'], 'acme', '坏 UTF-8 注释不应导致 acme 配置被误判为 custom')
            self.assertFalse(meta['is_insecure'])

            # 符号链接 config.yaml 不得被跟随读取，config_has_acme 保持 False
            meta2 = {
                'cert_type': 'self_signed',
                'is_insecure': True,
                'server_name': 'old.example.com',
                'cert_sha256': 'a' * 64,
            }
            with patch.object(Path, 'is_symlink', autospec=True, side_effect=lambda p: p == cfg), \
                    patch.object(portal, '_config_tls_cert_path', return_value=''), \
                    patch.object(portal, '_resolve_live_cert', return_value=(cert, 'a.example.com', ['a.example.com'], False)), \
                    patch.object(portal, 'atomic_write_private', return_value=None):
                changed2 = portal.sync_cert_trust(meta2, root, meta_path, config_path=cfg)
            self.assertTrue(changed2)
            self.assertEqual(meta2['cert_type'], 'custom', '符号链接 config.yaml 不应被读取以识别 acme 段')

    def test_github_token_rejects_fifo_non_regular_file_and_uses_replace_decode(self):
        """github_token 遇到 FIFO 等非常规文件时必须立即拒绝且绝不调用读取方法。"""
        read_called = []

        class _FifoPath:
            def is_symlink(self):
                return False

            def stat(self):
                return SimpleNamespace(
                    st_mode=stat.S_IFIFO | 0o600,
                    st_size=0,
                    st_mtime=123.0,
                    st_mtime_ns=123,
                    st_ctime=123.0,
                    st_ctime_ns=123,
                    st_ino=99,
                )

            def read_bytes(self):
                read_called.append(True)
                return b'ghp_' + b'a' * 36

        with patch.object(portal, 'GITHUB_TOKEN_FILE', _FifoPath()):
            with portal._github_token_lock:
                portal._github_token_cache.update(mtime=None, token='')
            self.assertEqual(portal.github_token(), '')
        self.assertEqual(read_called, [], 'FIFO 非常规文件不得触发阻塞读盘')

        src_gt = _fn_source('github_token')
        self.assertIn("errors='replace'", src_gt)
        src_xr = _fn_source('_read_xray_json')
        self.assertIn("read_text(encoding='utf-8', errors='replace')", src_xr)

    def test_openssl_sha256_uses_fdopen_without_close_reopen_toctou(self):
        """_openssl_sha256_hex 须直接 os.fdopen(fd, 'wb') 接管临时文件句柄，不得先 close 再 open。"""
        src = _fn_source('_openssl_sha256_hex')
        self.assertIn("os.fdopen(fd, 'wb')", src)
        self.assertNotIn("open(tmp, 'wb')", src)

        # 运行时确认正常路径输出合法 SHA-256 且不泄漏临时文件
        digest = 'b' * 64

        def _fake_run(cmd, **kwargs):
            if cmd[:2] == ['openssl', 'x509']:
                kwargs['stdout'].write(b'DERBYTES')
                return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
            if cmd[:2] == ['openssl', 'dgst']:
                return SimpleNamespace(returncode=0, stdout=(digest + ' *file\n').encode(), stderr=b'')
            raise AssertionError(cmd)

        with patch.object(portal.subprocess, 'run', side_effect=_fake_run):
            self.assertEqual(portal._openssl_sha256_hex('/etc/hysteria/cert/server.crt'), digest)

    def test_atomic_write_private_fallback_and_dir_fsync_guards(self):
        """atomic_write_private Windows 回落须拒符号链接，升级与 BBR 目录 fsync 须带 O_DIRECTORY。"""
        src_aw = _fn_source('atomic_write_private')
        self.assertIn('if path.is_symlink():', src_aw)
        src_upg = _fn_source('_h_post_do_upgrade_impl')
        self.assertIn("os.open(str(base_dir), os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))", src_upg)
        src_bbr = _fn_source('_set_bbr_locked')
        self.assertIn("os.open(str(target_path.parent), os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))", src_bbr)


if __name__ == '__main__':
    unittest.main()
