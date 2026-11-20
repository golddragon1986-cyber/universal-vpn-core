import copy,sys,unittest,tempfile
from unittest.mock import patch
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'vendor/panel/panel'))
import client_panel as panel,client_batch as batch,client_policy
client_policy.choices=lambda:["RULES","BYPASS","SELECTOR","LOADBALANCE","CHANNEL-test"]
class Router:
 def __init__(self,shared=True):
  self.data={'ip/firewall/address-list':[
   {'.id':'*1','list':'uvpn-main-lan','address':'10.0.0.0/8','comment':'Base LAN','disabled':False},
   {'.id':'*2','list':'uvpn-main-lan','address':'192.168.0.0/16','comment':'Base LAN','disabled':False},
   {'.id':'*3','list':'other-clients','address':'8.8.8.8','comment':'Foreign'}],
   'ip/firewall/nat':[
   {'.id':'*4','action':'dst-nat','chain':'dstnat','to-addresses':'172.31.41.2','to-ports':'53','dst-port':'53','src-address-list':'uvpn-main-lan','in-interface-list':'LAN'},
   {'.id':'*5','action':'dst-nat','chain':'dstnat','to-addresses':'172.31.41.2','to-ports':'53','dst-port':'53','src-address-list':'uvpn-main-lan','in-interface-list':'LAN','protocol':'tcp'}],
   'ip/firewall/filter':[{'.id':'*6','chain':'forward','action':'accept','out-interface':'uvpn-main-br','src-address-list':'uvpn-main-lan','comment':'uvpn-main: routing'}]}
  if shared:
   self.data['ip/firewall/nat'].append({'.id':'*7','action':'dst-nat','chain':'dstnat','to-addresses':'172.31.41.2','to-ports':'9091','src-address-list':'uvpn-main-lan'})
   self.data['ip/firewall/filter'].append({'.id':'*8','chain':'uvpn-main-in','action':'accept','src-address-list':'uvpn-main-lan','comment':'uvpn-main: base','dst-port':'9091,9090,1080'})
  self.data.update({'ip/firewall/mangle':[],'ip/route':[],'routing/table':[]});self.cfg={'bypass_table':'uvpn-main-direct'}
  self.calls=[];self.counter=16;self.fail_delete=False
 def call(self,path,method='GET',data=None):
  if method=='GET':return copy.deepcopy(self.data[path])
  self.calls.append((path,method,copy.deepcopy(data)))
  if method=='PUT':
   self.counter+=1;row={**data,'.id':'*'+format(self.counter,'X')};self.data[path].append(row);return copy.deepcopy(row)
  collection,ident=path.rsplit('/',1);row=next(row for row in self.data[collection] if row['.id']==ident)
  if method=='PATCH':row.update(data)
  if method=='DELETE':
   if self.fail_delete:self.fail_delete=False;raise RuntimeError('Injected ACL failure')
   self.data[collection].remove(row)
 def routes(self):return self.call('ip/route')
 def snapshot(self):return panel.read_state(self,cache=False)
 def clients(self,name='uvpn-main-lan'):return sorted((r['address'],r.get('comment',''),r.get('disabled',False)) for r in self.data['ip/firewall/address-list'] if r['list']==name)
class Tests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.writer=patch.object(client_policy,'write',lambda path,data:path.write_bytes(data));self.writer.start();self.addCleanup(self.writer.stop)
  self.patch=patch.object(client_policy,'FILE',Path(self.tmp.name)/'clients.json');self.patch.start();self.addCleanup(self.patch.stop)
 def test_internal_name_and_routeros_comment_are_independent(self):
  router=Router(False);state=router.snapshot();desired=copy.deepcopy(state['rows']);desired[0]['name']='Home'
  change=batch.plan(desired,panel.fingerprint(state),router);batch.apply(router,change);client_policy.save(change['desired'])
  self.assertEqual(router.clients()[0][1],'Base LAN');self.assertEqual(router.snapshot()['rows'][0]['name'],'Home')
  desired[0]['label']='Overwrite'
  with self.assertRaisesRegex(ValueError,'только для чтения'):batch.plan(desired,panel.fingerprint(router.snapshot()),router)
 def test_specific_network_overrides_broad_client_policy(self):
  rows=[{'id':'1','list':'LAN','address':'10.0.0.0/8','route':'CHANNEL-test','enabled':True},
        {'id':'2','list':'LAN','address':'10.0.0.35','route':'BYPASS','enabled':True},
        {'id':'3','list':'LAN','address':'10.1.0.0/16','route':'RULES','enabled':True}]
  client_policy.save(rows);text=client_policy.compose('rules:\n  - MATCH,SELECTOR\n')
  for value,target in [('10.0.0.35','BYPASS'),('10.1.0.5','RULES'),('10.2.0.5','CHANNEL-test')]:
   import ipaddress
   hits=[row['route'] for net,row in client_policy.effective(rows) if ipaddress.ip_address(value) in net]
   self.assertEqual(hits,[target])
  self.assertNotIn('SRC-IP-CIDR,10.0.0.0/8',text);self.assertIn('CHANNEL-test',text)
 def test_bypass_dns_and_routeros_routing_are_owned_and_reversible(self):
  router=Router(False);state=router.snapshot();desired=copy.deepcopy(state['rows']);desired[0]['route']='BYPASS'
  with patch.object(batch.rr,'ensure_wan_route'):
   change=batch.plan(desired,panel.fingerprint(state),router);batch.apply(router,change)
  self.assertTrue(any(row.get('new-routing-mark')=='uvpn-main-direct' for row in router.data['ip/firewall/mangle']))
  self.assertTrue(any(row.get('action')=='accept' and row.get('chain')==client_policy.DNS_CHAIN for row in router.data['ip/firewall/nat']))
  batch.restore(router,change);self.assertFalse(router.data['ip/firewall/mangle']);self.assertEqual(len(router.data['ip/firewall/nat']),2)

 def test_source_runtime_only_routes_forwarded_packets(self):
  import subprocess
  client_policy.save([{'id':'1','list':'LAN','address':'10.0.0.35','route':'CHANNEL-test','enabled':True}])
  tun=Path(self.tmp.name)/'Mihomo';tun.mkdir();(tun/'tun_flags').touch()
  eth=Path(self.tmp.name)/'eth0';eth.mkdir();(eth/'address').touch();(eth/'type').write_text('1')
  commands=[]
  def run(args,**kwargs):
   commands.append(args);return subprocess.CompletedProcess(args,0,'10900: from all lookup 100\n10901: from 10.1.1.1 lookup 206\n','')
  with patch.object(client_policy.Path,'iterdir',return_value=iter([tun,eth])),patch.object(client_policy.subprocess,'run',side_effect=run):client_policy.runtime()
  self.assertIn(['ip','-4','rule','del','pref','10901'],commands)
  self.assertNotIn(['ip','-4','rule','del','pref','10900'],commands)
  self.assertIn(['ip','-4','rule','add','pref','4000','iif','eth0','from','10.0.0.35/32','lookup','206'],commands)
 def test_pinned_client_dns_uses_its_channel(self):
  import dns_forwarder,struct
  packet=struct.pack('!6H',123,0x100,1,0,0,0)+b'\x07example\x03com\0'+struct.pack('!HH',1,1)
  answer=bytearray(packet);answer[2]=0x81;answer[3]=0x80
  with patch.object(dns_forwarder,'read_settings',return_value={'servers':[{'address':'8.8.8.8','enabled':True,'route':'DIRECT'}]}),patch.object(dns_forwarder,'bootstrap_servers',return_value=['8.8.8.8']),patch.object(dns_forwarder,'exchange',return_value=bytes(answer)) as exchange:
   self.assertEqual(dns_forwarder.resolve(packet,'CHANNEL-test'),answer)
   self.assertEqual(exchange.call_args.kwargs['routed'],'CHANNEL-test')
 def test_failed_replacement_can_restore_an_existing_policy(self):
  router=Router(False);state=router.snapshot();bypass=copy.deepcopy(state['rows']);bypass[0]['route']='BYPASS'
  with patch.object(batch.rr,'ensure_wan_route'):
   client_policy.apply(router,bypass,state);saved=client_policy.owned_snapshot(router)
   forced=copy.deepcopy(bypass);forced[0]['route']='CHANNEL-test';client_policy.apply(router,forced,state)
  self.assertTrue(any(row.get('new-routing-mark')==client_policy.TABLE for row in router.data['ip/firewall/mangle']))
  client_policy.restore(router,saved)
  self.assertTrue(any(row.get('new-routing-mark')=='uvpn-main-direct' for row in router.data['ip/firewall/mangle']))
  self.assertFalse(router.data['routing/table']);self.assertFalse(router.data['ip/route'])
 def test_source_discovery_and_ip_containment(self):
  state=Router().snapshot();self.assertEqual(len(state['rows']),2);self.assertEqual(list(state['lists']),['uvpn-main-lan']);self.assertEqual(len(state['bindings']),3);self.assertEqual(len(state['management_bindings']),2)
  self.assertTrue(panel.contains('10.0.0.0/8','10.0.0.35'));self.assertFalse(panel.contains('10.0.0.0/8','110.0.0.35'))
  self.assertTrue(panel.contains('10.0.0.2-10.0.0.20','10.0.0.10'));self.assertEqual(panel.address('10.0.0.35/32'),'10.0.0.35')
 def test_shared_acl_is_separated_before_removing_all_routing_clients(self):
  router=Router();state=router.snapshot();original=router.clients();change=batch.plan([],panel.fingerprint(state),router)
  batch.apply(router,change)
  self.assertEqual(router.clients(),[]);self.assertEqual(router.clients(panel.MANAGEMENT_LIST),original)
  self.assertEqual(router.data['ip/firewall/nat'][0]['src-address-list'],'uvpn-main-lan')
  self.assertEqual(router.data['ip/firewall/nat'][-1]['src-address-list'],panel.MANAGEMENT_LIST)
  self.assertEqual(router.data['ip/firewall/filter'][-1]['src-address-list'],panel.MANAGEMENT_LIST)
  batch.restore(router,change)
  self.assertEqual(router.clients(),original);self.assertEqual(router.clients(panel.MANAGEMENT_LIST),[])
  self.assertEqual(router.data['ip/firewall/nat'][-1]['src-address-list'],'uvpn-main-lan')
  self.assertEqual(router.clients('other-clients'),[('8.8.8.8','Foreign',False)])
 def test_edit_add_disable_and_restore(self):
  router=Router(False);state=router.snapshot();original=router.clients();desired=copy.deepcopy(state['rows']);desired[0]['enabled']=False;desired[0]['name']='Disabled'
  desired.append({'id':'new-client','list':'uvpn-main-lan','address':'172.30.255.254','label':'','name':'Temporary','enabled':False})
  change=batch.plan(desired,panel.fingerprint(state),router);self.assertFalse(change['migrations']);batch.apply(router,change)
  self.assertIn(('172.30.255.254','',True),router.clients());batch.restore(router,change);self.assertEqual(router.clients(),original)
 def test_partial_failure_restores_management_and_clients(self):
  router=Router();state=router.snapshot();original=router.clients();change=batch.plan([],panel.fingerprint(state),router);router.fail_delete=True
  with self.assertRaisesRegex(RuntimeError,'Injected'):batch.apply(router,change)
  batch.restore(router,change);self.assertEqual(router.clients(),original);self.assertEqual(router.clients(panel.MANAGEMENT_LIST),[])
  self.assertTrue(all(row['src-address-list']=='uvpn-main-lan' for row in router.data['ip/firewall/nat']))
 def test_stale_and_foreign_changes_are_rejected_without_writes(self):
  router=Router();state=router.snapshot();baseline=panel.fingerprint(state);desired=copy.deepcopy(state['rows'])
  router.data['ip/firewall/address-list'][0]['comment']='Changed outside panel'
  with self.assertRaises(ValueError):batch.plan(desired,baseline,router)
  self.assertFalse(router.calls)
  state=router.snapshot();desired=copy.deepcopy(state['rows']);desired[0]['id']='*3'
  with self.assertRaises(ValueError):batch.plan(desired,panel.fingerprint(state),router)
  self.assertFalse(router.calls)
 def test_dynamic_and_unsupported_networks_are_not_editable(self):
  self.assertFalse(panel.editable({'.id':'*A','list':'uvpn-main-lan','address':'10.0.0.35','dynamic':True}))
  for value in ['::1','0.0.0.0/0','224.0.0.1','10.0.0.1/24','10.0.0.20-10.0.0.2']:
   with self.subTest(value=value),self.assertRaises(ValueError):panel.address(value)
if __name__=='__main__':unittest.main()
