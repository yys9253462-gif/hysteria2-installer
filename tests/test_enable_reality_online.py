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
if __name__=='__main__':unittest.main()
