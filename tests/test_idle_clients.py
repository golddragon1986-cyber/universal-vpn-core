import json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch,Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'vendor/panel/panel'))
import vpn_clients as v
import proxy_manager as m
import sing_box_update as updater

class IdleClients(unittest.TestCase):
 def test_saved_old_configs_do_not_count_as_usage(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'sb.json';path.write_text(json.dumps({'inbounds':[{'listen':'127.0.0.1','listen_port':18181}]}))
   node={'client':'mihomo','proxy':{'name':'A','type':'vless','server':'vpn.example','port':443},'client_proxies':{'sing-box':{'port':18181}}}
   with patch.object(v,'SB',path),patch.object(m,'read',return_value={'nodes':[node]}):self.assertEqual(v.users('sing-box'),[])
 def test_local_bridge_blocks_removal_even_if_label_is_wrong(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'sb.json';path.write_text(json.dumps({'inbounds':[{'listen':'127.0.0.1','listen_port':18181}]}))
   node={'client':'mihomo','proxy':{'name':'A','type':'socks5','server':'127.0.0.1','port':18181},'balance':False}
   with patch.object(v,'SB',path),patch.object(m,'read',return_value={'nodes':[node]}):self.assertEqual(v.users('sing-box'),['A'])
 def test_in_use_client_is_not_signalled(self):
  with patch.object(v,'users',return_value=['A']),patch.object(v.os,'kill') as kill:
   with self.assertRaises(ValueError):v.pause_unused('sing-box')
   kill.assert_not_called()
 def test_idle_supervisor_stays_alive(self):
  with tempfile.TemporaryDirectory() as d,patch.object(v,'users',return_value=[]),patch.object(updater,'supervisor',return_value={'pid':123,'idle':False}),patch.object(v.os,'kill') as kill,patch.object(v.subprocess,'run',return_value=Mock(returncode=1)):
   path=Path(d)/'idle'
   with patch.object(v,'IDLE',path):v.pause_unused('sing-box');self.assertTrue(path.exists())
   kill.assert_called_once_with(123,v.signal.SIGHUP)
 def test_background_does_not_start_unused_client(self):
  with patch.object(v,'users',return_value=[]),patch.object(v,'pause_unused') as pause,patch.object(v.subprocess,'Popen') as launch:
   v.ensure_runtime('sing-box');pause.assert_called_once_with('sing-box');launch.assert_not_called()

if __name__=='__main__':unittest.main()
