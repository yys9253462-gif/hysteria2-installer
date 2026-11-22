"""回归测试：github_token 坏编码与体积/符号链接防护、_unit_failure_hint 选项注入防护、apply_xray_config_transaction 符号链接/体积/编码防护及 read_meta_file/read_access_file 符号链接与体积守卫。"""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import portal


class TestPortalGithubTokenXrayTxMetaAccessAndUnitHintGuards(unittest.TestCase):
    def test_github_token_survives_invalid_utf8_and_rejects_oversized_or_symlink_file(self):
        """github_token 遇到损坏 UTF-8 字节、超过 4 KiB 或符号链接令牌文件不得抛 UnicodeDecodeError 或无界读盘。"""
        with tempfile.TemporaryDirectory() as td:
            tok = Path(td) / 'github-token'
            # 1) 坏 UTF-8 字节：旧实现 read_text(encoding='utf-8') 抛未被捕获的 UnicodeDecodeError
            tok.write_bytes(b'\xff\xfe\xfd' + b'a' * 30)
            with mock.patch.object(portal, 'GITHUB_TOKEN_FILE', tok), \
                 mock.patch.dict(portal._github_token_cache, {'mtime': None, 'token': ''}):
                self.assertEqual(portal.github_token(), '')

            # 2) 超过 4096 字节：直接忽略返回空串
            tok.write_bytes(b'a' * 5000)
            with mock.patch.object(portal, 'GITHUB_TOKEN_FILE', tok), \
                 mock.patch.dict(portal._github_token_cache, {'mtime': None, 'token': ''}):
                self.assertEqual(portal.github_token(), '')

            # 3) 符号链接文件：即使内容是合法令牌也必须拒绝
            tok.write_text('ghp_' + 'A' * 36, encoding='utf-8')
            real_is_symlink = Path.is_symlink

            def fake_is_symlink(self_path):
                if self_path == tok:
                    return True
                return real_is_symlink(self_path)

            with mock.patch.object(portal, 'GITHUB_TOKEN_FILE', tok), \
                 mock.patch.dict(portal._github_token_cache, {'mtime': None, 'token': ''}), \
                 mock.patch.object(Path, 'is_symlink', autospec=True, side_effect=fake_is_symlink):
                self.assertEqual(portal.github_token(), '')

    def test_unit_failure_hint_rejects_option_injection_and_uses_utf8_replace(self):
        """_unit_failure_hint 必须拒绝前导 - 或含空白控制字符的 unit 名，且 journalctl 须带 errors='replace'。"""
        called = []

        def fake_run(cmd, **kwargs):
            called.append((cmd, kwargs))
            return subprocess.CompletedProcess(cmd, 0, stdout='line1\n', stderr='')

        with mock.patch.object(portal.subprocess, 'run', side_effect=fake_run):
            self.assertEqual(portal._unit_failure_hint('--system'), '')
            self.assertEqual(portal._unit_failure_hint('xray\nfoo'), '')
            self.assertEqual(called, [], '非法 unit 名称绝不得传入 journalctl')

            hint = portal._unit_failure_hint('xray', lines=999999)
            self.assertIn('line1', hint)
            self.assertEqual(len(called), 1)
            cmd, kw = called[0]
            self.assertEqual(kw.get('errors'), 'replace')
            n_idx = cmd.index('-n')
            self.assertLessEqual(int(cmd[n_idx + 1]), 50)

    def test_apply_xray_config_transaction_rejects_symlink_and_oversized_config(self):
        """apply_xray_config_transaction 必须拒绝符号链接配置与超过 4 MiB 的原配置。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = root / 'xray.json'
            cfg.write_bytes(b' ' * (4 * 1024 * 1024 + 16))
            with self.assertRaisesRegex(RuntimeError, '过大'):
                portal.apply_xray_config_transaction({'inbounds': []}, config_path=str(cfg), restart=False)

            cfg.write_text('{}', encoding='utf-8')
            real_is_symlink = Path.is_symlink

            def fake_is_symlink(self_path):
                if self_path == cfg:
                    return True
                return real_is_symlink(self_path)

            with mock.patch.object(Path, 'is_symlink', autospec=True, side_effect=fake_is_symlink):
                with self.assertRaisesRegex(RuntimeError, '符号链接'):
                    portal.apply_xray_config_transaction({'inbounds': []}, config_path=str(cfg), restart=False)

    def test_read_meta_and_access_file_reject_symlinks_and_oversized_files(self):
        """read_meta_file 与 read_access_file 必须拒绝符号链接与超过 1 MiB 文件并安全返回空字典。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            big = root / 'big.json'
            big.write_bytes(b'{"a":"' + b'x' * (1024 * 1024 + 32) + b'"}')
            self.assertEqual(portal.read_meta_file(big), {})
            self.assertEqual(portal.read_access_file(big), {})

            normal = root / 'ok.json'
            normal.write_text('{"server_name": "a.example.com", "username": "u"}', encoding='utf-8')
            real_is_symlink = Path.is_symlink

            def fake_is_symlink(self_path):
                if self_path == normal:
                    return True
                return real_is_symlink(self_path)

            with mock.patch.object(Path, 'is_symlink', autospec=True, side_effect=fake_is_symlink):
                self.assertEqual(portal.read_meta_file(normal), {})
                self.assertEqual(portal.read_access_file(normal), {})


if __name__ == '__main__':
    unittest.main()
