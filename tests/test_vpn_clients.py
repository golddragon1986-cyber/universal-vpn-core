import copy,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'vendor/panel/panel'))
import vpn_clients as v
import proxy_manager as m

P={'name':'Test','type':'vless','server':'vpn.example','port':443,'uuid':'secret','tls':True,'servername':'front.example','flow':'xtls-rprx-vision','client-fingerprint':'randomized','reality-opts':{'public-key':'key','short-id':'01','support-x25519mlkem768':True},'udp':True}

class Clients(unittest.TestCase):
 def test_cached_xray_is_rebuilt_without_automatic_healthcheck(self):
  with tempfile.TemporaryDirectory() as directory:
   path=Path(directory)/'panel-xray.json';path.write_text('{"old":true}')
   bridge={'name':'Test','type':'socks5','server':'127.0.0.1','port':18401,'udp':True}
   original={'nodes':[{'proxy':copy.deepcopy(P),'connection':copy.deepcopy(P),'client':'mihomo','client_ports':{'xray':18401},'client_proxies':{'xray':bridge}}]}
   events=[]
   with patch.object(v,'write'),patch.object(m,'read',return_value=copy.deepcopy(original)),patch.object(m,'save') as save,patch.object(m,'sync',side_effect=lambda:events.append('synced')),patch.object(m,'delay') as probe,patch.object(v,'binary',return_value='/xray'),patch.object(v,'build_external',return_value=(path,{'inbounds':[]},18401)) as build,patch.object(v,'validate') as validate,patch.object(v,'ensure_runtime',side_effect=lambda *args,**kwargs:events.append('started')) as start,patch.object(v,'users',return_value=['in-use']):
    v.select('Test','xray')
   probe.assert_not_called()
   self.assertEqual(events,['started','synced'])
   build.assert_called_once();validate.assert_called_once();start.assert_called_once_with('xray',force=True)
   self.assertEqual(save.call_args.args[0]['nodes'][0]['client'],'xray')
 def test_health_uses_provider_node_api(self):
  import io
  with patch.object(m.urllib.request,'urlopen',return_value=io.BytesIO(b'{"delay":42}')) as request:
   self.assertEqual(m.delay('Example VPN'),42)
   self.assertIn('/providers/proxies/USER-MANAGED/Example%20VPN/healthcheck?',request.call_args.args[0])
 def test_reality_mlkem_preserved(self):
  out=v.convert(P,'sing-box');self.assertTrue(out['tls']['reality']['enable_mlkem']);self.assertEqual(out['flow'],P['flow'])
 def test_explicit_vless_encryption_none_is_implicit_for_singbox(self):
  profile={**P,'encryption':'none'}
  self.assertEqual(v.convert(profile,'sing-box'),v.convert(P,'sing-box'))
  self.assertEqual(profile['encryption'],'none')
  self.assertEqual(v.convert(profile,'mihomo'),profile)
 def test_explicit_vless_encryption_none_maps_to_xray(self):
  profile=copy.deepcopy(P);profile['reality-opts'].pop('support-x25519mlkem768')
  profile['encryption']='none'
  self.assertEqual(v.convert(profile,'xray')['settings']['vnext'][0]['users'][0]['encryption'],'none')
 def test_encryption_not_discarded_for_other_protocols(self):
  with self.assertRaises(ValueError):v.convert({**P,'type':'vmess','encryption':'none'},'sing-box')
 def test_lossy_conversion_rejected(self):
  for extra in ({'encryption':'new-encryption'},{'packet-encoding':'xudp'},{'network':'xhttp'}):
   with self.assertRaises(ValueError):v.convert({**P,**extra},'sing-box')
  with patch.object(v,'xray_mlkem_supported',return_value=False):
   with self.assertRaises(ValueError):v.convert(P,'xray')
 def test_mihomo_preserves_all_options(self):
  self.assertEqual(v.convert(P,'mihomo'),P)
 def test_xray_vless(self):
  p=copy.deepcopy(P);p['reality-opts'].pop('support-x25519mlkem768')
  x=v.convert(p,'xray');self.assertEqual(x['streamSettings']['realitySettings']['password'],'key')
 def test_xray_mlkem_native_support_is_version_and_fingerprint_gated(self):
  from types import SimpleNamespace
  with patch.object(v,'binary',return_value='/xray'),patch.object(v.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='Xray 26.10.31 (Xray)')):
   x=v.convert(P,'xray')
   self.assertEqual(x['streamSettings']['realitySettings']['fingerprint'],'firefox')
   self.assertEqual(P['client-fingerprint'],'randomized')
   with self.assertRaises(ValueError):v.convert({**P,'client-fingerprint':'edge'},'xray')
  with patch.object(v,'binary',return_value='/xray'),patch.object(v.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='Xray 26.10.1 (Xray)')):
   with self.assertRaises(ValueError):v.convert(P,'xray')
 def test_xray_validation_uses_json_file_extension(self):
  from types import SimpleNamespace
  with tempfile.TemporaryDirectory() as directory:
   with patch.object(v,'ROOT',Path(directory)),patch.object(v,'binary',return_value='/xray'),patch.object(v.subprocess,'run',return_value=SimpleNamespace(returncode=0)) as run:
    v.validate('xray',{'outbounds':[]})
    self.assertTrue(run.call_args.args[0][-1].endswith('.json'))
 def test_unknown_uninstalled_rejected_without_save(self):
  with patch.object(m,'read',return_value={'nodes':[{'proxy':P}]}),patch.object(m,'save') as save,patch.object(v,'binary',return_value=None):
   for engine in ('exec','xray'):
    with self.assertRaises(ValueError):v.select('Test',engine)
   save.assert_not_called()
 def test_failed_apply_restores_original_database(self):
  original={'nodes':[{'proxy':{'name':'Test','type':'socks5','server':'127.0.0.1','port':18181},'client':'sing-box','connection':P,'balance':True}]}
  with patch.object(m,'read',return_value=copy.deepcopy(original)),patch.object(m,'save') as save,patch.object(m,'sync',side_effect=[RuntimeError('apply failed'),None]),patch.object(v,'validate'),patch.object(v,'binary',return_value='/mihomo'):
   with self.assertRaises(ValueError):v.select('Test','mihomo')
   self.assertEqual(save.call_args.args[0],original)
 def test_existing_bridge_adoption_preserves_real_endpoint(self):
  with tempfile.TemporaryDirectory() as d:
   file=Path(d)/'sb.json';out=v.convert(P,'sing-box');out['tag']='out'
   file.write_text(json.dumps({'inbounds':[{'tag':'in','listen_port':18181}],'outbounds':[out],'route':{'rules':[{'inbound':['in'],'outbound':'out'}]}}))
   with patch.object(v,'SB',file):
    node={'proxy':{'name':'Test','type':'socks5','server':'127.0.0.1','port':18181}}
    self.assertEqual(v.current(node),'sing-box');self.assertEqual(v.canonical(node),P)

if __name__=='__main__':unittest.main()
