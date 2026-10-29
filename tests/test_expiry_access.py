import sys,unittest,json,tempfile,pathlib,ast,threading,re
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]));import portal
class Resp:
 def __init__(self,obj):self.obj=obj
 def __enter__(self):return self
 def __exit__(self,*a):pass
 def read(self):return json.dumps(self.obj).encode()
class ExpiryTests(unittest.TestCase):
 def test_deadline_status_quota(self):
  good={'status':'active','expires_at':200,'limit_bytes':100,'used_bytes':99}
  self.assertTrue(portal.user_access_allowed(good,100))
  for diff in [{'expires_at':100},{'expires_at':99},{'status':'disabled'},{'used_bytes':100}]:self.assertFalse(portal.user_access_allowed(dict(good,**diff),100))
 def test_reality_filters_expired_disabled_and_exhausted(self):
  d={'users':{'expired':{'status':'active','expires_at':1},'active':{'expires_at':2085974400},'disabled':{'status':'disabled','expires_at':2085974400},'quota':{'expires_at':2085974400,'limit_bytes':1,'used_bytes':1}}}
  self.assertEqual([x['email'] for x in portal.reality_clients(d)],['active'])
 def test_kick_and_confirm_all_sessions(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);(p/'usage-meter-config.json').write_text(json.dumps({'hysteria':{'url':'http://127.0.0.1:19996','secret':'fixture'}}))
   with patch.object(portal.urllib.request,'urlopen',side_effect=[Resp({'expired':2}),Resp({}),Resp({'expired':1}),Resp({})]),patch.object(portal.subprocess,'run') as run,patch.object(portal.time,'sleep'):
    self.assertTrue(portal.enforce_node_access(p,{'users':{'expired':{'expires_at':1}}}))
   self.assertTrue(any(x.args[0]==['systemctl','restart','hysteria-server'] for x in run.call_args_list))
 def test_failed_kick_never_acknowledges(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);(p/'usage-meter-config.json').write_text(json.dumps({'hysteria':{'url':'http://127.0.0.1:19996','secret':'fixture'}}))
   with patch.object(portal.urllib.request,'urlopen',side_effect=OSError('offline')):
    with self.assertRaises(OSError):portal.enforce_node_access(p,{'users':{}},['deleted'])
 def test_delete_failure_returns_retryable_503(self):
  source=pathlib.Path(portal.__file__).read_text(encoding='utf-8');tree=ast.parse(source)
  branch=next(n for n in ast.walk(tree) if isinstance(n,ast.If) and isinstance(n.test,ast.Compare) and any(isinstance(v,ast.Constant) and v.value=='users/delete' for v in n.test.comparators))
  f=ast.parse('def delete(self,params):\n pass').body[0];f.body=branch.body
  state={'users':{'probe':{'status':'active'}}};env={'data':state,'data_lock':threading.RLock(),'regenerate_page':lambda:None,'reality_registry':portal.reality_registry,'VALID_USER_ID_RE':re.compile('^[a-z]+$'),'MASTER_USER_ID':'admin_master','ip_tracker':{},'speed_tracker':{},'drop_meter_totals':portal.drop_meter_totals,'pending_revocations':portal.pending_revocations,'apply_access':lambda ids:False}
  exec(compile(ast.fix_missing_locations(ast.Module(body=[f],type_ignores=[])),'branch','exec'),env)
  class Fake:
   def reply_json(self,status,body):return status,body
  self.assertEqual(env['delete'](Fake(),{'user_id':'probe'})[0],503)
  self.assertEqual(state['_pending_revocations'],['probe'])
class ShareAvailabilityConsistencyTests(unittest.TestCase):
 """分享页可用性与节点准入必须同源（2026-10-25 修复）。"""

 def test_zero_expiry_blocks_both(self):
  u={'status':'active','expires_at':0,'limit_bytes':0,'used_bytes':0}
  self.assertEqual(portal.user_access_allowed(u), portal.user_share_available(u))
  self.assertFalse(portal.user_access_allowed(u))

 def test_missing_expiry_allows_both(self):
  u={'status':'active','limit_bytes':0,'used_bytes':0}
  self.assertTrue(portal.user_access_allowed(u))
  self.assertTrue(portal.user_share_available(u))

 def test_nonfinite_quota_fails_closed(self):
  for key in ('limit_bytes', 'used_bytes'):
   u={key: float('inf'), 'limit_bytes': 10} if key == 'used_bytes' else {key: float('inf')}
   self.assertFalse(portal.user_access_allowed(u, 100))
   self.assertFalse(portal.user_share_available(u, 100))

 def test_fractional_expiry_uses_same_clock(self):
  u={'expires_at':100.2}
  with patch.object(portal.time, 'time', return_value=100.5):
   self.assertFalse(portal.user_access_allowed(u))
   self.assertFalse(portal.user_share_available(u))

 def test_quota_exhausted_blocks_both(self):
  u={'status':'active','expires_at':2085974400,'limit_bytes':10,'used_bytes':10}
  self.assertFalse(portal.user_access_allowed(u))
  self.assertFalse(portal.user_share_available(u))


class FormatBytesEdgeTests(unittest.TestCase):
 def test_negative_is_clamped(self):
  self.assertEqual(portal.format_bytes(-1), '0 B')

if __name__=='__main__':unittest.main()


class MultiProtocolRevocationTests(unittest.TestCase):
    """撤销必须覆盖**所有**托管入站。

    真实缺口（2026-10-24 接入 VMess 时暴露）：enforce_node_access 曾经只找
    第一个 Reality 入站，于是 VMess-only 节点上「停用/到期/超额」的用户
    仍然能用 VMess 继续连。这里锁住三种协议同时被收回。
    """

    def _xray(self, root):
        cfg = {'inbounds': [
            {'tag': portal.REALITY_INBOUND_TAG, 'port': 443, 'protocol': 'vless',
             'settings': {'clients': [], 'decryption': 'none'},
             'streamSettings': {'network': 'tcp', 'security': 'reality',
                                'realitySettings': {'privateKey': 'k', 'shortIds': ['s']}}},
            {'tag': portal.VMESS_INBOUND_TAG, 'port': 2087, 'protocol': 'vmess',
             'settings': {'clients': []},
             'streamSettings': {'network': 'ws', 'security': 'tls'}},
            {'tag': portal.VLESSENC_INBOUND_TAG, 'port': 2088, 'protocol': 'vless',
             'settings': {'clients': [], 'decryption': 'mlkem768x25519plus.native.600s.x'},
             'streamSettings': {'network': 'tcp', 'security': 'tls'}},
        ]}
        (root / 'xray.json').write_text(json.dumps(cfg), encoding='utf-8')

    def test_all_three_protocols_drop_disabled_user(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            self._xray(root)
            # Hy2 撤销分支要求回环统计可用；这里给它一个真实回环地址，
            # 并把 /online 固定返回空表（没有在线会话要踢）。
            (root / 'usage-meter-config.json').write_text(json.dumps(
                {'hysteria': {'url': 'http://127.0.0.1:19996', 'secret': 'fixture'}}),
                encoding='utf-8')
            data = {'users': {'alive': {'expires_at': 2085974400, 'status': 'active'},
                              'dead': {'expires_at': 2085974400, 'status': 'disabled'}}}
            with patch.object(portal.urllib.request, 'urlopen', return_value=Resp({})),                     patch.object(portal.subprocess, 'run') as run:
                self.assertTrue(portal.enforce_node_access(root, data, ['dead']))
            written = json.loads((root / 'xray.json').read_text(encoding='utf-8'))
            by_tag = {i['tag']: i for i in written['inbounds']}
            for tag in (portal.REALITY_INBOUND_TAG, portal.VMESS_INBOUND_TAG,
                        portal.VLESSENC_INBOUND_TAG):
                emails = [c['email'] for c in by_tag[tag]['settings']['clients']]
                self.assertIn('alive', emails, tag)
                self.assertNotIn('dead', emails, tag)
            # 三种协议都在同一份配置里 → 只需重启一次 xray。
            restarts = [c for c in run.call_args_list
                        if c.args and c.args[0][:2] == ['systemctl', 'restart']]
            self.assertEqual(len(restarts), 1)
