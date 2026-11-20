import json,signal,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'vendor/panel/panel'))
import runtime_actions as actions
from action_queue import ActionQueue,LABELS

class RuntimeTests(unittest.TestCase):
 def test_dns_flushes_both_caches_without_fakeip(self):
  router=Mock();stages=[]
  with patch.object(actions,'api') as api,patch('router_routes.configured',return_value=True),patch('router_routes.Router',return_value=router):
   self.assertIn('RouterOS',actions.flush_dns(stages.append))
  api.assert_called_once_with('/cache/dns/flush','POST')
  router.call.assert_called_once_with('ip/dns/cache/flush','POST',{})
  self.assertEqual(len(stages),2)
 def test_cache_failure_still_attempts_routeros(self):
  router=Mock()
  with patch.object(actions,'api',side_effect=RuntimeError('DNS unavailable')),patch('router_routes.configured',return_value=True),patch('router_routes.Router',return_value=router):
   with self.assertRaisesRegex(RuntimeError,'Контейнер'):actions.flush_dns()
  router.call.assert_called_once()
 def test_core_restart_preserves_active_selector_and_never_rebuilds(self):
  old={'pid':10,'generation':1,'child':11};new={'pid':10,'generation':2,'child':12}
  with patch.object(signal,'SIGHUP',1,create=True),patch('component_binary.core_state',side_effect=[old,new]),patch.object(actions.os,'kill') as kill,patch.object(actions,'api') as api,patch('routing_panel.global_info',return_value={'now':'LOADBALANCE'}),patch('routing_panel.set_global_proxy') as select,patch('component_binary.core_ready') as full_reload,patch('boot_config.prepare') as prepare:
   actions.restart_mihomo(lambda _:None)
  kill.assert_called_once_with(10,1);select.assert_called_once_with('LOADBALANCE')
  api.assert_called_once_with('/version');full_reload.assert_not_called();prepare.assert_not_called()
 def test_restart_includes_active_external_clients(self):
  process=Mock();process.poll.return_value=None
  with patch.object(signal,'SIGHUP',1,create=True),patch('sing_box_update.supervisor',side_effect=[{'pid':20,'generation':1},{'pid':20,'generation':2,'ready':True}]),patch.object(actions.os,'kill') as kill,patch('vpn_clients.PROCESSES',{'xray':(process,'hash')}),patch('vpn_clients.ensure_runtime') as restart,patch.object(actions,'restart_mihomo') as core:
   text=actions.restart_clients()
  kill.assert_called_once_with(20,1);restart.assert_called_once_with('xray',force=True,restart=True);core.assert_called_once()
  self.assertIn('sing-box',text);self.assertIn('Xray',text);self.assertIn('Mihomo',text)
 def test_maintenance_queue_skips_all_configuration_recovery_even_on_failure(self):
  with tempfile.TemporaryDirectory() as tmp:
   recovery=Mock()
   def execute(payload):
    payload['_progress']('Maintenance')
    if 'core_restart' in payload['body']:raise RuntimeError('Injected restart failure')
    return 'ok'
   queue=ActionQueue(str(Path(tmp)/'queue.sqlite'),execute,recovery=recovery)
   try:
    queue.submit(LABELS['dns_flush'],{'path':'/action','body':'action=dns_flush'})
    queue.submit(LABELS['core_restart'],{'path':'/action','body':'action=core_restart'})
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
     jobs=queue.status()['jobs']
     if len(jobs)==2 and all(row['status'] in ('done','failed') for row in jobs):break
     time.sleep(.02)
    self.assertEqual({row['status'] for row in jobs},{'done','failed'})
    for name in ['begin','flush','abort','finish']:getattr(recovery,name).assert_not_called()
   finally:queue.close()
 def test_duplicate_maintenance_is_rejected(self):
  with tempfile.TemporaryDirectory() as tmp:
   queue=ActionQueue(str(Path(tmp)/'queue.sqlite'),lambda _:None,start=False)
   try:
    payload={'path':'/action','body':'action=core_restart'}
    queue.submit(LABELS['core_restart'],payload)
    with self.assertRaises(ValueError):queue.submit(LABELS['core_restart'],payload)
   finally:queue.close()
if __name__=='__main__':unittest.main()
