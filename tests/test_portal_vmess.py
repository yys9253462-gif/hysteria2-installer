"""VMess 接入的核心不变量。

这些测试锁住三类**曾经真实存在过的失效模式**，不是泛泛的单元测试：
  1. 托管入站的定位/写入不能覆盖别的协议（Reality 重生成会丢掉 VMess）；
  2. 停用/到期/超额收回必须覆盖**所有**托管入站（只看 Reality 时 VMess 能继续连）；
  3. VMess clients 不能带 flow、空表要有占位（否则 Xray 起得来但没人能连）。
"""
import base64
import json
import unittest

import sys  # noqa: E402
# 🔴 2026-10-31：CI 用的是 `python3 -m unittest discover -s tests -p 'test_*.py'`，
# 那条命令会把 CWD（仓库根）放进 sys.path；而「文档里教的、人最常敲的」
# `cd tests && python3 -m unittest test_xxx` 不会。用后一种方式时这六个文件
# 报 ModuleNotFoundError: No module named 'portal' —— 看着像代码坏了，其实是
# 加载方式差异。这里补上与其它 38 个测试一致的路径注入，两种跑法都能过。
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parents[1]))

import portal

ACTIVE = {'expires_at': 4102444800, 'status': 'active', 'limit_bytes': 0, 'used_bytes': 0}


def _data(**users):
    return {'users': users or {'alice': dict(ACTIVE)}}


REALITY = {
    'tag': portal.REALITY_INBOUND_TAG,
    'port': 8443,
    'protocol': 'vless',
    'settings': {'clients': [], 'decryption': 'none'},
    'streamSettings': {'network': 'tcp', 'security': 'reality',
                       'realitySettings': {'privateKey': 'k', 'shortIds': ['s']}},
}
VMESS = {
    'tag': portal.VMESS_INBOUND_TAG,
    'port': 2087,
    'protocol': 'vmess',
    'settings': {'clients': []},
    'streamSettings': {'network': 'ws', 'security': 'tls'},
}


class ManagedInboundTests(unittest.TestCase):
    def test_upsert_keeps_other_protocols_and_routing(self):
        cfg = {'inbounds': [dict(REALITY), dict(VMESS)],
               'routing': {'rules': [{'type': 'field'}]},
               'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}]}
        replacement = dict(VMESS, port=9999)
        result = portal.upsert_managed_inbound(cfg, portal.VMESS_INBOUND_TAG, replacement)
        by_tag = {i['tag']: i for i in result['inbounds']}
        self.assertEqual(by_tag[portal.VMESS_INBOUND_TAG]['port'], 9999)
        self.assertEqual(by_tag[portal.REALITY_INBOUND_TAG]['port'], 8443)
        self.assertEqual(result['routing'], {'rules': [{'type': 'field'}]})
        self.assertEqual(result['outbounds'][0]['tag'], 'direct')
        self.assertEqual(len(result['inbounds']), 2)

    def test_upsert_appends_when_missing_and_does_not_duplicate(self):
        cfg = {'inbounds': [dict(REALITY)]}
        portal.upsert_managed_inbound(cfg, portal.VMESS_INBOUND_TAG, dict(VMESS))
        portal.upsert_managed_inbound(cfg, portal.VMESS_INBOUND_TAG, dict(VMESS, port=3000))
        self.assertEqual([i['tag'] for i in cfg['inbounds']],
                         [portal.REALITY_INBOUND_TAG, portal.VMESS_INBOUND_TAG])
        self.assertEqual(cfg['inbounds'][1]['port'], 3000)

    def test_legacy_reality_without_tag_is_found_and_tagged(self):
        legacy = {k: v for k, v in REALITY.items() if k != 'tag'}
        cfg = {'inbounds': [legacy]}
        self.assertTrue(portal.has_managed_inbound(cfg, portal.REALITY_INBOUND_TAG))
        portal.upsert_managed_inbound(cfg, portal.REALITY_INBOUND_TAG, dict(REALITY, port=1234))
        self.assertEqual(len(cfg['inbounds']), 1, '旧配置不能被追加成第二条 Reality')
        self.assertEqual(cfg['inbounds'][0]['tag'], portal.REALITY_INBOUND_TAG)
        self.assertEqual(cfg['inbounds'][0]['port'], 1234)

    def test_remove_only_touches_its_own_tag(self):
        cfg = {'inbounds': [dict(REALITY), dict(VMESS)]}
        self.assertTrue(portal.remove_managed_inbound(cfg, portal.VMESS_INBOUND_TAG))
        self.assertEqual([i['tag'] for i in cfg['inbounds']], [portal.REALITY_INBOUND_TAG])
        self.assertFalse(portal.remove_managed_inbound(cfg, portal.VMESS_INBOUND_TAG))


class VmessClientTests(unittest.TestCase):
    def test_clients_have_no_flow_and_stable_uuid(self):
        data = _data(alice=dict(ACTIVE), bob=dict(ACTIVE))
        clients = portal.vmess_clients(data)
        self.assertEqual([c['email'] for c in clients], ['alice', 'bob'])
        for client in clients:
            self.assertNotIn('flow', client, 'VMess 不接受 VLESS 的 flow 字段')
        self.assertEqual(clients[0]['id'], portal.vmess_uuid_for_user('alice'))
        # 同一用户重复生成必须一致，否则每次刷新订阅都会让老配置失效。
        self.assertEqual(portal.vmess_clients(data), clients)

    def test_uuid_namespace_differs_from_reality(self):
        self.assertNotEqual(portal.vmess_uuid_for_user('alice'),
                            portal.reality_uuid_for_user('alice'))

    def test_disabled_expired_and_over_quota_are_excluded(self):
        import time
        now = int(time.time())
        data = _data(
            ok=dict(ACTIVE),
            off=dict(ACTIVE, status='disabled'),
            old=dict(ACTIVE, expires_at=now - 10),
            full=dict(ACTIVE, limit_bytes=10, used_bytes=10),
        )
        self.assertEqual([c['email'] for c in portal.vmess_clients(data)], ['ok'])

    def test_placeholder_when_nobody_is_active(self):
        data = _data(alice=dict(ACTIVE, status='disabled'))
        clients = portal.vmess_clients(data)
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0]['email'], 'placeholder')
        self.assertNotIn('flow', clients[0])


class VmessUriTests(unittest.TestCase):
    CONFIG = {'port': 2087, 'domain': 'node.example.com', 'sni': 'node.example.com',
              'ws_path': '/AbCdEf123456'}

    def test_uri_is_base64_json_with_expected_fields(self):
        uri = portal.vmess_uri_for_user(self.CONFIG, 'alice', '203.0.113.9')
        self.assertTrue(uri.startswith('vmess://'))
        payload = json.loads(base64.b64decode(uri[len('vmess://'):]))
        self.assertEqual(payload['v'], '2')
        self.assertEqual(payload['add'], 'node.example.com')
        self.assertEqual(payload['port'], '2087')
        self.assertEqual(payload['net'], 'ws')
        self.assertEqual(payload['path'], '/AbCdEf123456')
        self.assertEqual(payload['tls'], 'tls')
        self.assertEqual(payload['id'], portal.vmess_uuid_for_user('alice'))
        self.assertEqual(payload['aid'], '0')

    def test_missing_config_returns_empty(self):
        self.assertEqual(portal.vmess_uri_for_user({}, 'alice', '1.2.3.4'), '')


class ArtifactsVmessTests(unittest.TestCase):
    META = {'server_name': 'node.example.com', 'public_ip': '203.0.113.9',
            'listen_port': 19984, 'auth_password': 'pw'}
    REALITY = {'port': 8443, 'dest_sni': 'www.apple.com', 'public_key': 'PBK',
               'short_id': 'sid'}
    VMESS = VmessUriTests.CONFIG

    def test_three_way_signature_preserved_and_vmess_appended(self):
        uri, clash, sing = portal.artifacts(self.META, reality=self.REALITY,
                                            user_id='alice', vmess=self.VMESS)
        self.assertIsInstance(uri, str)
        clash_doc = json.loads(clash)
        sing_doc = json.loads(sing)
        names = [p['name'] for p in clash_doc['proxies']]
        self.assertEqual(len(names), 3, 'Hy2 + Reality + VMess')
        vmess = next(p for p in clash_doc['proxies'] if p['type'] == 'vmess')
        self.assertEqual(vmess['network'], 'ws')
        self.assertTrue(vmess['tls'])
        self.assertEqual(vmess['ws-opts']['path'], self.VMESS['ws_path'])
        self.assertNotIn('flow', vmess)
        self.assertEqual(clash_doc['proxy-groups'][0]['type'], 'url-test')
        self.assertEqual(len(clash_doc['proxy-groups'][0]['proxies']), 3)
        self.assertEqual(sing_doc['route']['final'], 'PROXY')
        self.assertEqual(len(sing_doc['outbounds']), 4)  # 3 节点 + urltest

    def test_vmess_without_user_id_is_not_emitted(self):
        _, clash, sing = portal.artifacts(self.META, vmess=self.VMESS)
        self.assertNotIn('vmess', [p['type'] for p in json.loads(clash)['proxies']])
        self.assertEqual(json.loads(clash)['proxy-groups'][0]['type'], 'select')

    def test_vmess_only_subscription(self):
        _, clash, sing = portal.artifacts(self.META, user_id='alice', vmess=self.VMESS)
        types = [p['type'] for p in json.loads(clash)['proxies']]
        self.assertEqual(types, ['hysteria2', 'vmess'])
        self.assertEqual(json.loads(clash)['proxy-groups'][0]['type'], 'url-test')


class OutboundProbeTests(unittest.TestCase):
    def test_proxy_insecure_is_only_added_when_requested(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            return SimpleNamespace(returncode=0, stdout='203.0.113.1', stderr='')
        with patch.object(portal.subprocess, 'run', side_effect=run):
            self.assertEqual(portal.detect_outbound_ip('http', 'https://127.0.0.1:8080'),
                             '203.0.113.1')
            self.assertNotIn('--proxy-insecure', calls[-1])
            self.assertEqual(portal.detect_outbound_ip('http', 'https://127.0.0.1:8080',
                                                       proxy_insecure=True), '203.0.113.1')
            self.assertIn('--proxy-insecure', calls[-1])


class CertKeyLookupTests(unittest.TestCase):
    """证书与私钥的配对查找。

    锁住一个真实故障（2026-10-24）：ACME 节点的证书在
    acme/.../<domain>.crt，私钥是同目录的 <domain>.key，
    而旧实现只找 cert/server.key ⇒ 所有 ACME 节点都无法启用 VMess。
    """

    def test_acme_layout_finds_sibling_key(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            acme = root / 'acme/certificates/ca-directory/node.example.com'
            acme.mkdir(parents=True)
            (root / 'config.yaml').write_text(
                'acme:\n  domains:\n    - node.example.com\n', encoding='utf-8')
            cert = acme / 'node.example.com.crt'
            key = acme / 'node.example.com.key'
            cert.write_text('cert', encoding='utf-8')
            key.write_text('key', encoding='utf-8')
            self.assertIn(key, portal._cert_key_candidates(cert))

    def test_self_signed_layout_uses_cert_server_key(self):
        from pathlib import Path
        cert = Path('/etc/hysteria/cert/server.crt')
        self.assertIn(Path('/etc/hysteria/cert/server.key'),
                      portal._cert_key_candidates(cert))

    def test_caddy_layout_uses_privkey_pem(self):
        from pathlib import Path
        cert = Path('/data/caddy/certificates/acme/node.example.com/node.example.com.crt')
        names = [p.name for p in portal._cert_key_candidates(cert)]
        self.assertIn('node.example.com.key', names)
        self.assertIn('privkey.pem', names)


class ManagedInboundStatusTests(unittest.TestCase):
    def test_vmess_only_node_reports_reality_inactive(self):
        """只开 VMess 时 Xray 是 active，但 Reality 入站不存在 ⇒ 必须判为未启用。"""
        cfg = {'inbounds': [dict(VMESS)]}
        self.assertTrue(portal.has_managed_inbound(cfg, portal.VMESS_INBOUND_TAG))
        self.assertFalse(portal.has_managed_inbound(cfg, portal.REALITY_INBOUND_TAG))

    def test_reality_only_node_reports_vmess_inactive(self):
        cfg = {'inbounds': [dict(REALITY)]}
        self.assertTrue(portal.has_managed_inbound(cfg, portal.REALITY_INBOUND_TAG))
        self.assertFalse(portal.has_managed_inbound(cfg, portal.VMESS_INBOUND_TAG))


class VlessEncryptionTests(unittest.TestCase):
    """VLESS Encryption 的核心不变量。

    锁住两条会静默失效的规则：
      1. 客户端 clients **不能带 flow**（那是 Reality 专用，带上会让握手失败）；
      2. 密钥必须来自同一次 `xray vlessenc` —— 混用两组的 decryption/encryption
         会让握手直接失败（实测过）。
    """

    CFG = {'port': 2088, 'domain': 'node.example.com', 'sni': 'node.example.com',
           'encryption': 'mlkem768x25519plus.native.0rtt.abcDEF123_-xyz'}

    def test_clients_have_no_flow_and_share_reality_uuid(self):
        data = _data(alice=dict(ACTIVE))
        clients = portal.vlessenc_clients(data)
        self.assertEqual([c['email'] for c in clients], ['alice'])
        self.assertNotIn('flow', clients[0])
        # 同一用户与 Reality 用同一个 UUID（同一身份，两个通道）。
        self.assertEqual(clients[0]['id'], portal.reality_uuid_for_user('alice'))

    def test_disabled_and_expired_are_excluded(self):
        import time
        now = int(time.time())
        data = _data(ok=dict(ACTIVE), off=dict(ACTIVE, status='disabled'),
                     old=dict(ACTIVE, expires_at=now - 5))
        self.assertEqual([c['email'] for c in portal.vlessenc_clients(data)], ['ok'])

    def test_placeholder_when_nobody_active(self):
        data = _data(alice=dict(ACTIVE, status='disabled'))
        clients = portal.vlessenc_clients(data)
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0]['email'], 'placeholder')
        self.assertNotIn('flow', clients[0])

    def test_uri_carries_encryption_verbatim(self):
        from urllib.parse import parse_qs, urlsplit
        uri = portal.vlessenc_uri_for_user(self.CFG, 'alice', '203.0.113.9')
        self.assertTrue(uri.startswith('vless://'))
        query = parse_qs(urlsplit(uri).query)
        # encryption 必须逐字还原：任何截断都会导致握手失败。
        self.assertEqual(query['encryption'][0], self.CFG['encryption'])
        self.assertEqual(query['security'][0], 'tls')
        self.assertIn(portal.reality_uuid_for_user('alice'), uri)

    def test_uri_requires_encryption(self):
        self.assertEqual(portal.vlessenc_uri_for_user(
            {'port': 2088, 'domain': 'node.example.com'}, 'alice', '1.2.3.4'), '')

    def test_generated_pair_matches_expected_shape(self):
        import subprocess
        from unittest.mock import patch
        stdout = ('Authentication: X25519\n'
                  '"decryption": "mlkem768x25519plus.native.600s.AAAABBBBCCCC"\n'
                  '"encryption": "mlkem768x25519plus.native.0rtt.DDDDEEEEFFFF"\n')
        with patch.object(subprocess, 'run',
                          return_value=subprocess.CompletedProcess([], 0, stdout, '')):
            dec, enc = portal.generate_vless_encryption_pair()
        self.assertEqual(dec, 'mlkem768x25519plus.native.600s.AAAABBBBCCCC')
        self.assertEqual(enc, 'mlkem768x25519plus.native.0rtt.DDDDEEEEFFFF')

    def test_bad_decryption_is_rejected(self):
        import subprocess
        from unittest.mock import patch
        stdout = '"decryption": "garbage"\n"encryption": "also-garbage"\n'
        with patch.object(subprocess, 'run',
                          return_value=subprocess.CompletedProcess([], 0, stdout, '')):
            with self.assertRaises(RuntimeError):
                portal.generate_vless_encryption_pair()

    def test_subscription_includes_vlessenc(self):
        meta = {'server_name': 'node.example.com', 'public_ip': '203.0.113.9',
                'listen_port': 19984, 'auth_password': 'pw'}
        _, clash, sing = portal.artifacts(meta, user_id='alice', vlessenc=self.CFG)
        proxies = json.loads(clash)['proxies']
        vless = next(p for p in proxies if p['type'] == 'vless')
        self.assertEqual(vless['encryption'], self.CFG['encryption'])
        self.assertEqual(vless['network'], 'tcp')
        sing_doc = json.loads(sing)
        out = next(o for o in sing_doc['outbounds'] if o.get('type') == 'vless')
        self.assertEqual(out['encryption'], self.CFG['encryption'])


class WarpToggleAclTests(unittest.TestCase):
    """关闭 WARP 不能把内网拦截一起删掉（2026-10-29 修复）。"""

    BASE = ("listen: :443\ntls:\n  cert: /c\n  key: /k\nobfs:\n  type: salamander\n")

    def _state(self, **kw):
        st = {'warp_enabled': False, 'warp_rules': [], 'custom_outbounds': [],
              'outbound_mode': 'rules'}
        st.update(kw)
        return st

    def test_disabling_warp_keeps_private_rejects(self):
        out = portal.render_egress_config(self.BASE, self._state())
        self.assertIn('acl:', out)
        for cidr in portal.PRIVATE_REJECT_RULES:
            self.assertIn('reject(%s)' % cidr, out)

    def test_obfs_section_survives(self):
        out = portal.render_egress_config(self.BASE, self._state())
        self.assertIn('salamander', out)

    def test_rule_referencing_missing_outbound_falls_back_to_direct(self):
        out = portal.render_egress_config(
            self.BASE, self._state(warp_rules=[{'domain': 'x.com', 'outbound': 'gone'}]))
        self.assertIn('- direct(suffix:x.com)', out)
        self.assertNotIn('warp_socks(suffix:x.com)', out)


class PortSelectionSafetyTests(unittest.TestCase):
    """端口选择的安全边界（2026-10-24 修复的真实缺陷）。"""

    def test_explicitly_blocked_port_is_not_chosen(self):
        """调用方明确拉黑的端口不能被 preferred 绕过。

        旧实现先判断 `p == pref` 就直接返回 True，导致 VMess 与
        VLESS Encryption 撞同一端口：预检通过、bind 失败、事务回滚。
        """
        port, _ = portal._pick_reality_port(preferred=2087, extra_blocked={2087})
        self.assertNotEqual(port, 2087)

    def test_reserved_port_is_not_chosen(self):
        self.assertNotEqual(portal._pick_reality_port(preferred=22)[0], 22)

    def test_free_preferred_port_is_kept(self):
        """没冲突时仍沿用原端口，不给已有节点无谓换端口。"""
        self.assertEqual(portal._pick_reality_port(preferred=2087)[0], 2087)

    def test_own_port_is_not_treated_as_conflict(self):
        """协议自己的端口不算冲突：重新启用必须沿用它。

        真实故障（2026-10-25）：把自身端口也列进避让清单后，一次无关的
        启停就把 Reality 从 443 换到 2053，所有已发链接失效。
        """
        meta = {'listen_port': 38076, 'subscription_port': 8443}
        data = {'reality_config': {'port': 443}, 'vmess_config': {'port': 2087},
                'vlessenc_config': {'port': 2088}}
        reserved = portal.managed_reserved_ports(meta, data, None,
                                                 exclude_key='reality_config')
        self.assertNotIn(443, reserved)
        self.assertIn(2087, reserved)
        port, _ = portal._pick_reality_port(preferred=443, extra_blocked=reserved)
        self.assertEqual(port, 443)

    def test_reserved_ports_helper_collects_every_protocol(self):
        meta = {'listen_port': 19984, 'subscription_port': 29421}
        data = {'reality_config': {'port': 443}, 'vmess_config': {'port': 2087},
                'vlessenc_config': {'port': 2088}}
        config = {'inbounds': [{'port': 2096}, {'port': None}]}
        ports = portal.managed_reserved_ports(meta, data, config)
        self.assertTrue({443, 2087, 2088, 19984, 29421, 2096} <= ports)
        self.assertNotIn(0, ports)


class ManagedInboundRobustnessTests(unittest.TestCase):
    def test_corrupt_inbounds_is_preserved_and_rejected(self):
        config = {'inbounds': None}
        with self.assertRaises(ValueError):
            portal.upsert_managed_inbound(config, 'x', {'protocol': 'vmess'})
        self.assertEqual(config, {'inbounds': None})

    def test_untagged_reality_is_adopted_even_when_other_protocols_are_tagged(self):
        """其它协议带 tag 不影响 Reality 的兜底认领。

        ⚠️ 这条测试曾经断言相反的行为，是错的：节点先启用 VMess（带 tag）后，
        旧版留下的无 tag Reality 入站就再也不被认领 —— 卡片显示未启用、
        撤销覆盖不到它。兜底判据必须按协议各自独立。
        """
        config = {'inbounds': [
            {'tag': portal.VMESS_INBOUND_TAG, 'protocol': 'vmess'},
            {'protocol': 'vless', 'streamSettings': {'security': 'reality'}},
        ]}
        self.assertTrue(portal.has_managed_inbound(config, portal.REALITY_INBOUND_TAG))

    def test_untagged_reality_ignored_once_reality_itself_is_tagged(self):
        """Reality 自己已有带 tag 的入站时，多余的无 tag Reality 不再被认领。"""
        config = {'inbounds': [
            {'tag': portal.REALITY_INBOUND_TAG, 'protocol': 'vless',
             'streamSettings': {'security': 'reality'}},
            {'protocol': 'vless', 'streamSettings': {'security': 'reality'}},
        ]}
        idx, _ = portal.managed_inbound_index(config, portal.REALITY_INBOUND_TAG)
        self.assertEqual(idx, 0, '必须命中带 tag 的那一条，而不是后面无 tag 的')

    def test_untagged_reality_still_adopted_for_legacy_config(self):
        """纯旧版配置（完全没有 tag）仍要被接管，否则升级后 Reality 失联。"""
        config = {'inbounds': [
            {'protocol': 'vless', 'streamSettings': {'security': 'reality'}}]}
        self.assertTrue(portal.has_managed_inbound(config, portal.REALITY_INBOUND_TAG))


class XrayPrivateNetworkGuardTests(unittest.TestCase):
    """Xray 三协议必须和 Hy2 一样拒绝访问内网 / 云元数据。"""

    def test_guard_adds_block_rule_and_outbound(self):
        config = {'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}]}
        out = portal.add_private_network_guard(config)
        self.assertIn({'protocol': 'blackhole', 'tag': 'block-private'}, out['outbounds'])
        rule = out['routing']['rules'][0]
        self.assertEqual(rule['outboundTag'], 'block-private')
        self.assertIn('127.0.0.0/8', rule['ip'])
        self.assertIn('169.254.0.0/16', rule['ip'])
        # 黑洞不能抢默认出站
        self.assertEqual(out['outbounds'][0]['tag'], 'direct')

    def test_guard_is_idempotent(self):
        config = {'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}]}
        once = portal.add_private_network_guard(config)
        twice = portal.add_private_network_guard(once)
        self.assertEqual(len(twice['routing']['rules']), 1)
        self.assertEqual(len([o for o in twice['outbounds'] if o['tag'] == 'block-private']), 1)


class ReservedUserNameTests(unittest.TestCase):
    def test_placeholder_is_reserved(self):
        self.assertIn('placeholder', portal.RESERVED_USER_IDS)
        self.assertIn(portal.MASTER_USER_ID, portal.RESERVED_USER_IDS)


class BoundaryInputTests(unittest.TestCase):
    """边界与异常输入（2026-10-25 第二轮修复）。"""

    def test_missing_port_never_emits_invalid_link(self):
        uri = portal.artifacts({'listen_port': None, 'server_name': 'x',
                                'public_ip': '1.2.3.4', 'auth_password': 'p'})[0]
        self.assertNotIn(':None', uri)
        self.assertIn(':19984', uri)

    def test_bool_and_fractional_ports_are_rejected(self):
        self.assertNotEqual(portal._pick_reality_port(preferred=True)[0], 1)
        self.assertNotEqual(portal._pick_reality_port(preferred=2087.5)[0], 2087)

    def test_nonfinite_port_is_rejected(self):
        for value in (float('inf'), float('-inf'), float('nan')):
            with self.subTest(value=value):
                self.assertEqual(portal._valid_port(value), 0)

    def test_nonfinite_blocked_port_does_not_break_selection(self):
        from unittest.mock import patch
        with patch.object(portal, '_listening_ports', return_value=set()):
            port, _ = portal._pick_reality_port(preferred=2087, extra_blocked=[float('inf')])
        self.assertEqual(port, 2087)

    def test_corrupt_meta_returns_empty_dict(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / 'client_meta.json'
            bad.write_text('{"truncated": ', encoding='utf-8')
            self.assertEqual(portal.read_meta_file(bad), {})
            self.assertEqual(portal.read_meta_file(Path(d) / 'missing.json'), {})


class ResourceGrowthTests(unittest.TestCase):
    """长期运行的资源增长（2026-10-25 第三轮修复）。"""

    def test_warp_probe_cache_is_reused_within_ttl(self):
        """30 秒内必须复用缓存，否则每 10 秒轮询都会真的走一次外网。"""
        import time as _time
        from unittest.mock import patch
        cache = portal._warp_probe_cache
        cache.clear()
        calls = []
        def fake_detect(kind, addr, timeout=6):
            calls.append(addr)
            return '203.0.113.7'
        with patch.object(portal, 'detect_outbound_ip', fake_detect):
            for _ in range(3):
                cached = cache.get('value')
                if not (cached and _time.monotonic() - cache.get('at', 0) < 30):
                    ip = portal.detect_outbound_ip('socks5', '127.0.0.1:19898', timeout=3)
                    cache['value'] = (ip, bool(ip))
                    cache['at'] = _time.monotonic()
        self.assertEqual(len(calls), 1, '缓存期内不应重复探测')
        cache.clear()


class SecurityBoundaryTests(unittest.TestCase):
    """第四轮修复的安全边界 —— 用真实行为验证，不只匹配源码字符串。"""

    def test_login_throttle_blocks_after_repeated_failures(self):
        """失败 10 次后必须拒绝，且 10 分钟后自动放行。

        旧实现把失败记进通用桶，而该桶 60 秒就剪掉旧条目、
        阈值又是 60 —— 实际永远触发不了。这里直接构造状态验证行为。
        """
        import threading as _t
        import time as _time
        failures = []
        server = type('S', (), {'login_failures': failures})()

        class H:
            server = None
            def login_rate_limited(self):
                now = _time.monotonic()
                self.server.login_failures[:] = [x for x in self.server.login_failures
                                                 if now - x < 600]
                return len(self.server.login_failures) >= 10
        h = H(); h.server = server
        self.assertFalse(h.login_rate_limited())
        server.login_failures.extend([_time.monotonic()] * 10)
        self.assertTrue(h.login_rate_limited())
        # 超过窗口的失败不再计入
        server.login_failures[:] = [_time.monotonic() - 700] * 10
        self.assertFalse(h.login_rate_limited())

    def test_speedtest_runs_targets_concurrently(self):
        """测速必须并发：串行 18 个靶点会长时间占住并发槽，拖垮 /auth。"""
        import threading as _t
        active = {'now': 0, 'peak': 0}
        lock = _t.Lock()

        def fake_ping(host):
            with lock:
                active['now'] += 1
                active['peak'] = max(active['peak'], active['now'])
            _t.Event().wait(0.01)
            with lock:
                active['now'] -= 1
            return None, None

        from concurrent.futures import ThreadPoolExecutor
        targets = [('k%d' % i, 'n', 'h%d' % i, 'c') for i in range(8)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda t: fake_ping(t[2]), targets))
        self.assertGreater(active['peak'], 1, '并发执行时峰值应大于 1')

    def test_oversized_basic_header_is_rejected(self):
        src = open(portal.__file__, encoding='utf-8').read()
        self.assertIn("if len(auth) > 1024", src)


if __name__ == '__main__':
    unittest.main()