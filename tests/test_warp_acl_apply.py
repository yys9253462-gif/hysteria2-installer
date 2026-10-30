import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

import sys  # noqa: E402
# 🔴 2026-10-31：CI 用的是 `python3 -m unittest discover -s tests -p 'test_*.py'`，
# 那条命令会把 CWD（仓库根）放进 sys.path；而「文档里教的、人最常敲的」
# `cd tests && python3 -m unittest test_xxx` 不会。用后一种方式时这六个文件
# 报 ModuleNotFoundError: No module named 'portal' —— 看着像代码坏了，其实是
# 加载方式差异。这里补上与其它 38 个测试一致的路径注入，两种跑法都能过。
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parents[1]))

import portal


BASE_CONFIG = """listen: :14617
outbounds:
  - name: direct_ipv4
    type: direct
    direct:
      mode: \"4\"
  - name: warp_socks
    type: socks5
    socks5:
      addr: 127.0.0.1:19898
obfs:
  type: salamander
  salamander:
    password: test-only
"""


class WarpAclApplyTests(unittest.TestCase):
    def test_enabled_builds_domain_routes_and_preserves_other_config(self):
        result = portal.build_warp_acl_config(BASE_CONFIG, True, ['openai.com', 'claude.ai'])
        self.assertIn('warp_socks(suffix:openai.com)', result)
        self.assertIn('warp_socks(suffix:claude.ai)', result)
        self.assertTrue(result.rstrip().endswith('direct_ipv4(all)'))
        self.assertIn('password: test-only', result)
        self.assertTrue(portal.warp_acl_matches(result, True, ['openai.com', 'claude.ai']))

    def test_disabled_removes_acl_but_preserves_outbound_and_obfs(self):
        enabled = portal.build_warp_acl_config(BASE_CONFIG, True, ['openai.com'])
        result = portal.build_warp_acl_config(enabled, False, ['openai.com'])
        self.assertIn('\nacl:\n', result)
        for cidr in portal.PRIVATE_REJECT_RULES:
            self.assertIn('reject(' + cidr + ')', result)
        self.assertNotIn('warp_socks(suffix:', result)
        self.assertIn('name: warp_socks', result)
        self.assertIn('password: test-only', result)
        self.assertTrue(portal.warp_acl_matches(result, False, ['openai.com']))

    def test_apply_requires_a_new_active_process_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / 'config.yaml'
            cfg.write_text(BASE_CONFIG, encoding='utf-8')
            data = {'warp_enabled': True, 'warp_rules': ['openai.com']}
            identities = iter([
                ('active', '10', 'old-start'),
                ('active', '11', 'new-start'),
                ('active', '11', 'new-start'),
            ])
            with patch.object(portal, '_hy2_runtime_identity', side_effect=lambda: next(identities)), \
                    patch.object(portal, '_restart_hy2'):
                ok, error = portal.apply_warp_acl_config(data, threading.RLock(), str(cfg))
            self.assertTrue(ok, error)
            self.assertIn('warp_socks(suffix:openai.com)', cfg.read_text(encoding='utf-8'))

    def test_warp_status_predicate_detects_missing_acl(self):
        self.assertFalse(portal.warp_acl_matches(BASE_CONFIG, True, ['openai.com']))
        # 即使关闭 WARP，缺少内网拒绝 ACL 的旧配置也应被判为未应用。
        self.assertFalse(portal.warp_acl_matches(BASE_CONFIG, False, ['openai.com']))
        secured = portal.build_warp_acl_config(BASE_CONFIG, False, ['openai.com'])
        self.assertTrue(portal.warp_acl_matches(secured, False, ['openai.com']))

    def test_reload_exception_rolls_back_original_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / 'config.yaml'
            cfg.write_text(BASE_CONFIG, encoding='utf-8')
            def rollback(path, original):
                path.write_text(original, encoding='utf-8')
                return 'active'
            with (patch.object(portal, '_hy2_runtime_identity', return_value=('active', '10', 'old')),
                  patch.object(portal, '_restart_hy2', side_effect=RuntimeError('restart rejected')),
                  patch.object(portal, '_rollback_outbounds', side_effect=rollback)):
                ok, error = portal.apply_warp_acl_config(
                    {'warp_enabled': True, 'warp_rules': ['openai.com']}, threading.RLock(), str(cfg))
            self.assertFalse(ok)
            self.assertIn('restart rejected', error)
            self.assertEqual(cfg.read_text(encoding='utf-8'), BASE_CONFIG)

    def test_sniffing_restores_domains_from_ip_only_client_requests(self):
        result = portal.build_warp_acl_config(BASE_CONFIG, True, ['openai.com'])
        self.assertIn('sniff:\n  enable: true', result)
        self.assertIn('tcpPorts: 80,443', result)
        self.assertIn('udpPorts: 443', result)

    def test_dict_rules_keep_direct_target_and_domain(self):
        rules = [{'domain': 'openai.com', 'outbound': 'warp_socks'},
                 {'domain': 'example.com', 'outbound': 'direct'}]
        result = portal.build_warp_acl_config(BASE_CONFIG, True, rules)
        self.assertIn('warp_socks(suffix:openai.com)', result)
        self.assertIn('direct(suffix:example.com)', result)

    def test_detection_uses_socks_protocol_without_no_proxy_bypass(self):
        with patch.object(portal.subprocess, 'run', return_value=SimpleNamespace(
                returncode=0, stdout='{"ip":"203.0.113.42"}')) as run:
            self.assertEqual(portal.detect_outbound_ip('warp'), '203.0.113.42')
        args = run.call_args.args[0]
        self.assertEqual(args[args.index('--proxy') + 1], 'socks5h://127.0.0.1:19898')
        self.assertEqual(args[args.index('--noproxy') + 1], '')

    def test_detection_never_falls_back_to_direct_after_proxy_failure(self):
        with patch.object(portal.subprocess, 'run', return_value=SimpleNamespace(
                returncode=7, stdout='')) as run:
            self.assertEqual(portal.detect_outbound_ip('warp'), '')
        self.assertEqual(run.call_count, 1)

    def test_installation_does_not_call_incompatible_legacy_script(self):
        source = Path(portal.__file__).read_text(encoding='utf-8')
        install = source.split('def _h_post_install_warp(', 1)[1].split('def do_GET(', 1)[0]
        self.assertNotIn("toggle_warp.sh', 'enable'", install)
        self.assertIn('_reply_with_warp_apply', install)


if __name__ == '__main__':
    unittest.main()
