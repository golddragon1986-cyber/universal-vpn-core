import sys,json,tempfile,struct,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'vendor/panel/panel'))
import local_dns_zones as zones,dns_forwarder as dns
class Tests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  for name,value in [('FILE',Path(self.temp.name)/'zones.json'),('write',lambda p,b:p.write_bytes(b))]:
   item=patch.object(zones,name,value);item.start();self.addCleanup(item.stop)
  class Router:
   def call(self,path):
    return ([{'name':'ad.internal','type':'FWD','forward-to':'ad','match-subdomain':'true'},{'name':'168.192.in-addr.arpa','type':'FWD','forward-to':'ad','match-subdomain':'true'},{'name':'crm','type':'A'}, {'name':'disabled.internal','type':'FWD','disabled':'true'}] if path=='ip/dns/static' else [{'name':'ad','dns-servers':'192.168.8.20,192.168.8.21'}])
  with patch.object(zones.rr,'Router',Router):zones.refresh()
 def test_routeros_authority_and_suffix_boundaries(self):
  row=zones.match('_ldap._tcp.dc._msdcs.ad.internal');self.assertEqual(row['servers'],['172.31.41.1']);self.assertEqual(row['upstreams'],['192.168.8.20','192.168.8.21'])
  self.assertTrue(zones.match('20.8.168.192.in-addr.arpa'));self.assertTrue(zones.match('crm'))
  for name in ['badad.internal','foo.crm','disabled.internal','example.com']:self.assertIsNone(zones.match(name))
 def test_local_domains_bypass_fakeip_before_general_rules(self):
  text=(Path(__file__).resolve().parents[1]/'vendor/panel/default-config.yaml').read_text()
  result=zones.configure(text);self.assertLess(result.index('DOMAIN-SUFFIX,ad.internal,real-ip'),result.index('RULE-SET,RU-BLOCKED,fake-ip'))
  self.assertIn('"+.ad.internal":',result);self.assertEqual(zones.configure(result),result)
 def packet(self,name,typ):return struct.pack('!6H',123,0x100,1,0,0,0)+b''.join(bytes([len(part)])+part.encode() for part in name.split('.'))+b'\0'+struct.pack('!HH',typ,1)
 def test_srv_ptr_direct_and_public_query_retains_selected_channel(self):
  for name,typ in [('_ldap._tcp.dc._msdcs.ad.internal',33),('20.8.168.192.in-addr.arpa',12),('example.com',1)]:
   packet=self.packet(name,typ);answer=bytearray(packet);answer[2]=0x81;answer[3]=0x80
   with patch.object(dns,'read_settings',return_value={'servers':[{'name':'Public','address':'8.8.8.8','route':'DIRECT','enabled':True}]}),patch.object(dns,'bootstrap_servers',return_value=[]),patch.object(dns,'exchange',return_value=bytes(answer)) as exchange:
    self.assertEqual(dns.resolve(packet,'CHANNEL-test'),answer)
    self.assertEqual(exchange.call_args.args[0],'8.8.8.8' if name=='example.com' else '172.31.41.1')
    self.assertEqual(exchange.call_args.kwargs['routed'],'CHANNEL-test' if name=='example.com' else False)
 def test_local_query_does_not_fall_back_to_public_dns(self):
  packet=self.packet('ad.internal',1)
  with patch.object(dns,'read_settings',return_value={'servers':[{'name':'Public','address':'8.8.8.8','route':'DIRECT','enabled':True}]}),patch.object(dns,'bootstrap_servers',return_value=[]),patch.object(dns,'exchange',side_effect=OSError('local DNS down')) as exchange:
   self.assertEqual(dns.resolve(packet,'CHANNEL-test')[3]&15,2)
   self.assertEqual([call.args[0] for call in exchange.call_args_list],['172.31.41.1'])
if __name__=='__main__':unittest.main()
