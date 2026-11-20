import sys,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'vendor/panel/panel'))
import router_routes as r
from contextlib import ExitStack

class GuardTests(unittest.TestCase):
 def test_local_access_cannot_be_captured(self):
  for value in ('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1','10.0.0.0/8','10.0.0.3/32','172.31.41.0/24','172.31.41.1/32','192.168.0.0/16','192.168.8.134/32','127.0.0.1/32','169.254.0.0/16','224.0.0.0/4','198.18.0.0/16','::/0'):
   with self.subTest(value=value),self.assertRaises(ValueError):r.validate_destination(value)
 def test_router_wan_servers_and_dns_cannot_be_captured(self):
  for value in ('176.118.221.86/32','176.118.221.80/28','89.22.227.150/32','89.0.0.0/8','8.8.8.8/32','1.1.1.1/32'):
   with self.subTest(value=value),self.assertRaises(ValueError):r.validate_destination(value,[{'address':'176.118.221.86/28'}],['89.22.227.150'])
 def test_telegram_and_public_routes_allowed(self):
  for value in ('91.108.4.0/22','149.154.160.0/20','9.9.9.9/32'):
   self.assertEqual(r.validate_destination(value),value)
 def test_invalid_or_ambiguous_input_rejected(self):
  for value in ('10.0.0.1/24','91.108.4.0/22; /ip route remove 0','91.108.4.0/33','example.com'):
   with self.subTest(value=value),self.assertRaises(ValueError):r.validate_destination(value)
 def test_fake_and_foreign_routes_not_deletable(self):
  base={'gateway':'172.31.41.2','routing-table':'main','dst-address':'198.18.0.0/16'}
  self.assertFalse(r.mutable(base))
  self.assertTrue(r.mutable({**base,'dst-address':'91.108.4.0/22'}))
  self.assertFalse(r.mutable({**base,'dst-address':'91.108.4.0/22','gateway':'10.0.0.1'}))
  self.assertFalse(r.mutable({**base,'dst-address':'91.108.4.0/22','dynamic':'true'}))
 def test_invalid_token_cannot_touch_router(self):
  with patch.object(r,'Router') as router:
   with self.assertRaises(ValueError):r.change('route_add',{'route_token':['bad']})
   router.assert_not_called()
 def test_tun_defaults_to_fake_ip_and_service_networks(self):
  template='tun:\n  enable: true\n'
  config=template+'rules:\n  # BEGIN SERVICE-ROUTES\n  - IP-CIDR,91.108.4.0/22,LOADBALANCE,no-resolve\n  # END SERVICE-ROUTES\n'
  updated=r.with_service_tun_routes(config,template)
  self.assertIn('  route-address:\n    - 198.18.0.0/16\n    - 91.108.4.0/22\n',updated)
  without_service=updated[:updated.index('rules:')]
  self.assertNotIn('91.108.4.0/22',r.with_service_tun_routes(without_service,template))

class TransactionTests(unittest.TestCase):
 def setUp(self):
  self.events=[];outer=self
  class Fake:
   cfg={'bypass_table':'direct'}
   routes_data=[{'.id':'*1','gateway':'172.31.41.2','routing-table':'main','dst-address':'198.18.0.0/16'}]
   rules_data=[]
   fail_add=False
   def routes(self):return list(self.routes_data)
   def rules(self):return list(self.rules_data)
   def addresses(self):return [{'address':'10.0.0.3/24'}]
   def call(self,path,method='GET',data=None):
    outer.events.append((method,path))
    if method=='PUT' and path=='ip/route':
     if self.fail_add:raise RuntimeError('Router write failed')
     value={**data,'.id':'*A'};self.routes_data.append(value);return value
    if method=='PUT' and path=='routing/rule':
     value={**data,'.id':'*B'};self.rules_data.append(value);return value
    if method=='DELETE':
     group=self.routes_data if path.startswith('ip/route/') else self.rules_data
     group[:]=[x for x in group if x['.id']!=path.rsplit('/',1)[1]]
  self.fake=Fake();self.stack=ExitStack();self.addCleanup(self.stack.close)
  for name,kwargs in [('Router',{'return_value':self.fake}),('server_ips',{'return_value':[]}),('saved_files',{'return_value':{}}),('intent',{}),('committed',{}),('clear_intent',{})]:self.stack.enter_context(patch.object(r,name,**kwargs))
  self.stack.enter_context(patch.object(r,'sync_container',side_effect=lambda routes:self.events.append(('sync',len(routes)))))
  self.rollback=self.stack.enter_context(patch.object(r,'rollback_files'))
 def test_add_prepares_container_and_bypass_before_router_route(self):
  r.change('route_add',{'route_token':[r.TOKEN],'destination':['9.9.9.0/24']})
  self.assertEqual(self.events,[('sync',2),('PUT','routing/rule'),('PUT','ip/route')])
 def test_failed_route_write_removes_bypass_and_restores_container(self):
  self.fake.fail_add=True
  with self.assertRaises(RuntimeError):r.change('route_add',{'route_token':[r.TOKEN],'destination':['9.9.9.0/24']})
  self.assertEqual(self.fake.rules_data,[]);self.rollback.assert_called_once()
 def test_delete_removes_router_route_before_tun_capture(self):
  self.fake.routes_data.append({'.id':'*C','gateway':'172.31.41.2','routing-table':'main','dst-address':'91.108.4.0/22'})
  r.change('route_delete',{'route_token':[r.TOKEN],'route_id':['*C']})
  self.assertEqual(self.events,[('DELETE','ip/route/*C'),('sync',1)])
 def test_service_routes_follow_service_lifecycle(self):
  self.fake.routes_data.append({'.id':'*D','routing-table':'direct','dst-address':'0.0.0.0/0','active':'true'})
  with patch.object(r,'CONFIG') as config,patch.object(r,'SERVICE_STATE'),patch.object(r,'write'):
   config.is_file.return_value=True
   r.sync_service_routes({'91.108.4.0/22'})
   self.assertEqual(self.events,[('PUT','routing/rule'),('PUT','ip/route')])
   self.assertFalse(r.mutable(self.fake.routes_data[-1]))
   r.sync_service_routes(set())
  self.assertEqual(self.events[-2:],[('DELETE','ip/route/*A'),('DELETE','routing/rule/*B')])

 def test_failed_service_route_write_rolls_back_bypass(self):
  self.fake.routes_data.append({'routing-table':'direct','dst-address':'0.0.0.0/0','active':'true'})
  self.fake.fail_add=True
  with patch.object(r,'CONFIG') as config,patch.object(r,'write'):
   config.is_file.return_value=True
   with self.assertRaises(RuntimeError):r.sync_service_routes({'91.108.4.0/22'})
  self.assertEqual(self.fake.rules_data,[])

 def test_automatic_routes_wait_for_activation_and_copy_wan(self):
  net='91.108.4.0/22'
  self.fake.cfg={'bypass_table':r.AUTO_TABLE}
  self.fake.routes_data[0]['active']='false'
  self.fake.routes_data.append({'.id':'*D','routing-table':'main','dst-address':'0.0.0.0/0','active':'true','immediate-gw':'10.0.0.1%wan'})
  original=self.fake.call
  def call(path,method='GET',data=None):
   row=original(path,method,data)
   if method=='PUT' and path=='ip/route' and row['comment']==r.WAN_ROUTE:
    row['active']='true'
   return row
  with patch.object(r,'auto_rest',return_value=True),patch.object(r,'SERVICE_STATE'),patch.object(self.fake,'call',side_effect=call):
   r.sync_service_routes({net})
   self.assertEqual(self.events,[])
   self.fake.routes_data[0]['active']='true'
   r.sync_service_routes({net})
   self.assertEqual(self.events,[('PUT','ip/route'),('PUT','routing/rule'),('PUT','ip/route')])
   self.assertEqual(self.fake.routes_data[-2]['gateway'],'10.0.0.1%wan')

if __name__=='__main__':unittest.main()
