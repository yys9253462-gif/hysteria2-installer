import json,subprocess,tempfile,unittest,importlib.util
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('cfg',Path(__file__).resolve().parents[1]/'usage-meter-xray-config-20261007-v1.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class EnableTests(unittest.TestCase):
 def test_preserves_clients_and_enables_all_levels(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'xray.json';original={'inbounds':[{'settings':{'clients':[{'id':'unchanged','email':'user','level':3}]}}],'outbounds':[{'protocol':'freedom'}]};p.write_text(json.dumps(original))
   with patch.object(m.subprocess,'run') as run:result=m.enable_reality_online(str(p),'xray','127.0.0.1:19997')
   changed=json.loads(p.read_text());self.assertEqual(changed['inbounds'],original['inbounds']);self.assertEqual(changed['outbounds'],original['outbounds'])
   self.assertTrue(changed['policy']['levels']['3']['statsUserOnline']);self.assertTrue(result['enabled']);self.assertTrue(Path(result['backup']).exists())
   self.assertTrue(run.call_args_list[0].args[0][-1].endswith('.json'))
 def test_restart_failure_rolls_back(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'xray.json';old=b'{"inbounds": [], "outbounds": []}';p.write_bytes(old);failed=False
   def run(args,**kwargs):
    nonlocal failed
    if args==['systemctl','restart','xray'] and not failed:failed=True;raise subprocess.CalledProcessError(1,args)
   with patch.object(m.subprocess,'run',side_effect=run):
    with self.assertRaises(subprocess.CalledProcessError):m.enable_reality_online(str(p),'xray','127.0.0.1:19997')
   self.assertEqual(p.read_bytes(),old)
 def test_concurrent_change_is_not_overwritten(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'xray.json';p.write_text('{"inbounds": []}')
   concurrent=b'{"inbounds": [], "concurrent": true}'
   def run(args,**kwargs):
    if args[1:3]==['run','-test']:p.write_bytes(concurrent)
   with patch.object(m.subprocess,'run',side_effect=run):
    with self.assertRaisesRegex(RuntimeError, 'changed concurrently'):m.enable_reality_online(str(p),'xray','127.0.0.1:19997')
   self.assertEqual(p.read_bytes(),concurrent)
 def test_invalid_config_never_replaces_original(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'xray.json';old=b'{"inbounds": []}';p.write_bytes(old)
   with patch.object(m.subprocess,'run',side_effect=subprocess.CalledProcessError(23,['xray'])):
    with self.assertRaises(subprocess.CalledProcessError):m.enable_reality_online(str(p),'xray','127.0.0.1:19997')
   self.assertEqual(p.read_bytes(),old)
class BackupAndErrorTests(unittest.TestCase):
 """备份不随改动累积；回滚重启失败不能盖住原始错误（2026-11-03 修）。"""
 def test_repeated_changes_keep_one_backup(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'xray.json'
   for level in (1,2,3):
    p.write_text(json.dumps({'inbounds':[{'settings':{'clients':[{'id':'x','level':level}]}}]}))
    with patch.object(m.subprocess,'run'):m.enable_reality_online(str(p),'xray','127.0.0.1:19997')
   backups=[f.name for f in Path(d).iterdir() if 'before-reality-online' in f.name]
   self.assertEqual(len(backups),1,backups)
 def test_rollback_restart_failure_keeps_original_error(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'xray.json';old=b'{"inbounds": []}';p.write_bytes(old)
   restarts=[]
   def run(args,**kwargs):
    if args[:2]==['xray','api']:raise RuntimeError('stats api unreachable')
    if args==['systemctl','restart','xray']:
     restarts.append(1)
     if len(restarts)==2:  # 回滚那次重启失败
      if kwargs.get('check'):raise subprocess.CalledProcessError(1,args)
      return subprocess.CompletedProcess(args,1)
   with patch.object(m.subprocess,'run',side_effect=run):
    with self.assertRaisesRegex(RuntimeError,'stats api unreachable'):m.enable_reality_online(str(p),'xray','127.0.0.1:19997')
   self.assertEqual(p.read_bytes(),old)

 def test_online_stats_probe_retries_transient_startup_failure(self):
  """Xray 刚重启时 gRPC 统计监听尚未就绪，单次探测易误触发回滚；应短暂重试。"""
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'xray.json';p.write_text('{"inbounds": [], "outbounds": []}')
   attempts=[]
   def run(args,**kwargs):
    if args[:2]==['xray','api']:
     attempts.append(1)
     if len(attempts)<3:
      raise subprocess.CalledProcessError(1,args)
    return subprocess.CompletedProcess(args,0)
   with patch.object(m.subprocess,'run',side_effect=run), patch.object(m.time,'sleep'):
    result=m.enable_reality_online(str(p),'xray','127.0.0.1:19997')
   self.assertTrue(result['enabled']);self.assertTrue(result['changed'])
   self.assertEqual(len(attempts),3)

 def test_rollback_restores_original_permissions_in_both_helpers(self):
  """回滚写回原配置前必须恢复原文件权限，避免 0600 的 xray.json 退化为默认 umask。"""
  for fn_name,cfg in (
   ('enable_reality_online',{'inbounds':[],'outbounds':[]}),
   ('enable_iplimit_routing',{'api':{'tag':'usage-meter-api','services':['StatsService']},'inbounds':[],'outbounds':[{'protocol':'freedom','tag':'direct'}]}),
  ):
   with self.subTest(fn=fn_name), tempfile.TemporaryDirectory() as d:
    p=Path(d)/'xray.json';raw=json.dumps(cfg).encode();p.write_bytes(raw)
    if hasattr(m.os,'chmod') and m.os.name!='nt':
     m.os.chmod(p,0o600)
    expected_mode=p.stat().st_mode & 0o777
    chmod_calls=[]
    real_chmod=m.os.chmod
    def spy_chmod(path,mode,*a,**kw):
     chmod_calls.append((Path(path).name,mode))
     return real_chmod(path,mode,*a,**kw)
    def run(args,**kwargs):
     if args[:2]==['xray','api']:raise RuntimeError('api fail')
     return subprocess.CompletedProcess(args,0)
    with patch.object(m.subprocess,'run',side_effect=run), patch.object(m.os,'chmod',side_effect=spy_chmod):
     with self.assertRaisesRegex(RuntimeError,'api fail'):
      getattr(m,fn_name)(str(p),'xray','127.0.0.1:19997')
    self.assertEqual(p.read_bytes(),raw)
    # 正常替换前 1 次 + 回滚替换前 1 次，共 2 次 chmod 且均恢复为原权限
    self.assertEqual(len(chmod_calls),2,chmod_calls)
    self.assertEqual(chmod_calls[-1][1],expected_mode)
    if m.os.name!='nt':
     self.assertEqual(p.stat().st_mode & 0o777,0o600)
if __name__=='__main__':unittest.main()
