import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import portal  # noqa: E402


class _FakeCompleted:
    def __init__(self, returncode=0, stdout=''):
        self.returncode = returncode
        self.stdout = stdout


class TestCertSubjectSanAndTrustGuards(unittest.TestCase):
    def test_parse_cert_subject_strips_dns_prefix_on_all_sans_and_ignores_ip(self):
        """多域名 SAN 且含 IP Address 时，必须剥掉每一项的 DNS: 前缀并过滤非 DNS 项。"""
        with tempfile.TemporaryDirectory() as td:
            cert = Path(td) / 'fullchain.pem'
            cert.write_text('dummy', encoding='utf-8')

            def fake_run(cmd, **kwargs):
                if '-subject' in cmd:
                    return _FakeCompleted(0, 'subject=CN = a.example.com\n')
                if '-issuer' in cmd:
                    return _FakeCompleted(0, 'issuer=CN = Fake CA\n')
                if 'subjectAltName' in cmd:
                    return _FakeCompleted(
                        0,
                        'X509v3 Subject Alternative Name:\n'
                        '    IP Address:1.2.3.4, DNS:a.example.com, DNS:b.example.com, DNS:*.c.example.com\n',
                    )
                raise AssertionError(f'unexpected cmd: {cmd}')

            with mock.patch.object(portal.subprocess, 'run', side_effect=fake_run):
                cn, sans, self_signed = portal._parse_cert_subject(cert)

        self.assertEqual(cn, 'a.example.com')
        self.assertEqual(sans, ['a.example.com', 'b.example.com', '*.c.example.com'])
        self.assertFalse(self_signed)
        self.assertTrue(portal.certificate_covers_domain('b.example.com', sans, cn))

    def test_config_cert_and_key_parsers_handle_bad_utf8_comments_and_unclosed_quote(self):
        """配置文件含非法 UTF-8、未闭合引号或行尾注释时，解析函数不得抛异常且应剥离注释。"""
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            bad_cfg = td_path / 'bad.yaml'
            bad_cfg.write_bytes(b'\xff\xfe\xfd')

            self.assertEqual(portal._config_tls_cert_path(str(bad_cfg)), '')
            self.assertIsNone(portal._config_acme_cert_path(str(bad_cfg)))

            unclosed_acme = td_path / 'acme.yaml'
            unclosed_acme.write_text(
                'acme:\n'
                '  domains:\n'
                '    - "broken.example.com\n'
                '  ca: "letsencrypt\n',
                encoding='utf-8',
            )
            acme_path = portal._config_acme_cert_path(str(unclosed_acme))
            self.assertIsNotNone(acme_path)
            self.assertIn('broken.example.com', str(acme_path))

            cert = td_path / 'server.crt'
            key = td_path / 'custom.key'
            cert.write_text('cert', encoding='utf-8')
            key.write_text('key', encoding='utf-8')
            cfg_with_comment = td_path / 'config.yaml'
            cfg_with_comment.write_text(
                'tls:\n'
                '  cert: server.crt # 证书路径注释\n'
                '  key: custom.key  # 私钥路径注释\n',
                encoding='utf-8',
            )
            with mock.patch.object(portal, 'cert_key_matches', return_value=True):
                found = portal._find_cert_key(cert, td_path)
            self.assertEqual(found, key)

            # 空 key 值不得拼出目录 Path('.') 并误检
            cfg_empty_key = td_path / 'empty_key_dir'
            cfg_empty_key.mkdir()
            (cfg_empty_key / 'config.yaml').write_text('tls:\n  key:   # 仅注释\n', encoding='utf-8')
            (cfg_empty_key / 'server.crt').write_text('cert', encoding='utf-8')
            with mock.patch.object(portal, 'cert_key_matches', return_value=False):
                self.assertIsNone(portal._find_cert_key(cfg_empty_key / 'server.crt', cfg_empty_key))

    def test_is_dns_name_rejects_non_str_and_bing_prefix_injection(self):
        """_is_dns_name 必须拒绝非字符串与带非法后缀的 www.bing.com 前缀伪造。"""
        self.assertTrue(portal._is_dns_name('www.bing.com'))
        self.assertFalse(portal._is_dns_name(12345))
        self.assertFalse(portal._is_dns_name(['a.example.com']))
        self.assertFalse(portal._is_dns_name('www.bing.com;rm -rf /'))
        self.assertFalse(portal._is_dns_name('www.bing.com bad'))

    def test_sync_cert_trust_skips_unreadable_cert_and_sanitizes_non_string_meta(self):
        """证书损坏/截断时 sync_cert_trust 不得破坏原自签信任模型，且损坏 meta 字段不会写入非字符串。"""
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            (td_path / 'cert').mkdir()
            bad_cert = td_path / 'cert' / 'server.crt'
            bad_cert.write_text('-----BEGIN CERTIFICATE-----\ntruncated', encoding='utf-8')
            cfg = td_path / 'config.yaml'
            cfg.write_bytes(b'\xff\xfe')
            meta_path = td_path / 'client_meta.json'
            meta = {
                'cert_type': 'self_signed',
                'is_insecure': True,
                'server_name': 'www.bing.com',
                'pin_sha256': 'a' * 64,
            }
            meta_path.write_text(json.dumps(meta), encoding='utf-8')

            with mock.patch.object(portal, '_parse_cert_subject', return_value=('', [], False)):
                changed = portal.sync_cert_trust(meta, td_path, str(meta_path), str(cfg))

            self.assertFalse(changed)
            self.assertEqual(meta['cert_type'], 'self_signed')
            self.assertTrue(meta['is_insecure'])
            self.assertEqual(meta['pin_sha256'], 'a' * 64)

            # 合法自签证书但无 DNS 名、且 meta 中 server_name/public_ip 为非字符串时，应回退为 'localhost'
            meta_bad_types = {
                'cert_type': 'custom',
                'is_insecure': False,
                'server_name': ['bad'],
                'public_ip': 12345,
                'pin_sha256': '',
            }
            with mock.patch.object(portal, '_parse_cert_subject', return_value=('', [], True)), \
                 mock.patch.object(portal, 'pin_sha256_of_file', return_value='b' * 64):
                changed2 = portal.sync_cert_trust(meta_bad_types, td_path, str(meta_path), str(cfg))

            self.assertTrue(changed2)
            self.assertEqual(meta_bad_types['server_name'], 'localhost')
            self.assertEqual(meta_bad_types['cert_type'], 'self_signed')
            self.assertTrue(meta_bad_types['is_insecure'])


if __name__ == '__main__':
    unittest.main()
