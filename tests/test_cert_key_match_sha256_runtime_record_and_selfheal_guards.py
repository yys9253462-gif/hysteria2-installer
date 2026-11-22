"""回归测试：cert_key_matches 拒空公钥假匹配、_openssl_sha256_hex 防选项注入与空输出、record_cert_heal 超长数字与嵌套 NaN、sync_cert_runtime/selfheal 读盘体积上限。"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import portal  # noqa: E402


class TestCertKeyMatchSha256RuntimeRecordAndSelfhealGuards(unittest.TestCase):
    def test_cert_key_matches_rejects_empty_pubkey_false_positive_and_leading_dash(self):
        """当 openssl 返回空 stdout 时，空输入 SHA256 绝不能触发 cert_key_matches 假匹配；且拒绝前导横杠路径。"""
        empty_sha = b'SHA2-256(stdin)= e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n'

        def fake_run(cmd, **kw):
            if cmd[:2] == ['openssl', 'sha256']:
                return SimpleNamespace(returncode=0, stdout=empty_sha, stderr=b'')
            return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')

        with mock.patch.object(portal.subprocess, 'run', side_effect=fake_run):
            self.assertFalse(portal.cert_key_matches('/tmp/a.crt', '/tmp/a.key'),
                             '空公钥输出不得通过空哈希比对被误判为证书私钥匹配')

        with mock.patch.object(portal.subprocess, 'run') as m_run:
            self.assertFalse(portal.cert_key_matches('-evil.crt', '/tmp/a.key'))
            self.assertFalse(portal.cert_key_matches('/tmp/a.crt', '-evil.key'))
            m_run.assert_not_called()

    def test_openssl_sha256_hex_rejects_leading_dash_and_handles_empty_digest_stdout(self):
        """_openssl_sha256_hex 拒绝以横杠开头或含控制字符的路径，且空输出时静默返回空串不记忽略日志。"""
        with mock.patch.object(portal.subprocess, 'run') as m_run:
            self.assertEqual(portal._openssl_sha256_hex('-engine'), '')
            self.assertEqual(portal._openssl_sha256_hex('a\nb.crt'), '')
            m_run.assert_not_called()

        logged = []
        with mock.patch.object(portal.subprocess, 'run',
                               return_value=SimpleNamespace(returncode=0, stdout=b'   \n', stderr=b'')), \
             mock.patch.object(portal, '_log_ignored', side_effect=lambda *a: logged.append(a)):
            self.assertEqual(portal._openssl_sha256_hex('/tmp/ok.crt'), '')
        self.assertEqual(logged, [], 'openssl 空输出不应触发 IndexError 异常日志')

    def test_record_cert_heal_handles_huge_heal_count_and_nested_nan_state(self):
        """record_cert_heal 面对 5000 位超长数字 heal_count 与嵌套 NaN 状态时仍须成功写出合法 JSON。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            state_path = root / 'cert-selfheal.json'
            state_path.write_text(
                '{"heal_count": "' + ('9' * 5000) + '", "extra": [NaN, {"bad": Infinity}], "loaded_cert_sha256": "abc"}',
                encoding='utf-8',
            )
            portal.record_cert_heal(root, None, {'pin_sha256': 'a'}, {'pin_sha256': 'b'})
            saved = json.loads(state_path.read_text(encoding='utf-8'))
            self.assertEqual(saved['heal_count'], 1)
            self.assertEqual(saved['loaded_cert_sha256'], 'abc')
            self.assertEqual(saved['extra'], [None, {'bad': None}])

    def test_sync_cert_runtime_rejects_oversized_cert_and_scrubs_nested_nan(self):
        """sync_cert_runtime 必须拒绝超大证书文件，且状态文件含嵌套 NaN 时仍能原子落盘。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            big_cert = root / 'big.crt'
            big_cert.write_bytes(b'x' * (4 * 1024 * 1024 + 16))
            self.assertFalse(portal.sync_cert_runtime(root, big_cert))

            ok_cert = root / 'ok.crt'
            ok_cert.write_bytes(b'-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n')
            state_path = root / 'cert-selfheal.json'
            state_path.write_text('{"loaded_cert_sha256": "old", "nested": {"v": NaN}}', encoding='utf-8')
            with mock.patch.object(portal, '_systemd_state', return_value='inactive'):
                self.assertTrue(portal.sync_cert_runtime(root, ok_cert, state_path=state_path))
            saved = json.loads(state_path.read_text(encoding='utf-8'))
            self.assertEqual(saved['nested'], {'v': None})
            self.assertEqual(len(saved['loaded_cert_sha256']), 64)

    def test_config_tls_cert_path_and_selfheal_reject_oversized_files(self):
        """_config_tls_cert_path 与 selfheal 必须拒绝超过 4 MiB 的异常配置文件，防无界读入内存。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            big_cfg = root / 'config.yaml'
            big_cfg.write_bytes(b'tls:\n  cert: /a.crt\n' + b'#' * (4 * 1024 * 1024 + 16))
            self.assertEqual(portal._config_tls_cert_path(str(big_cfg)), '')

            big_meta = root / 'client_meta.json'
            big_meta.write_bytes(b'{"a":"' + b'x' * (4 * 1024 * 1024 + 16) + b'"}')
            self.assertFalse(portal.selfheal(str(big_meta), config_path=str(big_cfg)))


if __name__ == '__main__':
    unittest.main()
