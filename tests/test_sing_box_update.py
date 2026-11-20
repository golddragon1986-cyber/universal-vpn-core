import hashlib,json,signal,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from contextlib import ExitStack
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'vendor/panel/panel'))
import sing_box_update as u

class UpdateTests(unittest.TestCase):
 def setUp(self):
  self.stack=ExitStack();self.addCleanup(self.stack.close)
  self.root=Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
  self.binary=self.root/'installed';self.binary.write_bytes(b'old-compatible-binary')
  self.updates=self.root/'updates';self.updates.mkdir();self.candidate=self.updates/'sing-box'
  for name,value in [('BINARY',self.binary),('UPDATES',self.updates),('CONFIG',self.root/'private-config.json')]:self.stack.enter_context(patch.object(u,name,value))
  self.commands=self.stack.enter_context(patch.object(u,'command',side_effect=lambda args:('sing-box version local-new' if args[0]==str(self.candidate) else 'sing-box version local-old') if args[1]=='version' else ''))
  self.supervisor=self.stack.enter_context(patch.object(u,'supervisor',return_value={'pid':77,'generation':1,'ready':True}))
  self.kill=self.stack.enter_context(patch.object(u.os,'kill'))
  self.wait=self.stack.enter_context(patch.object(u,'wait_ready'))
 def release(self,content=b'new-compatible-binary'):
  self.candidate.write_bytes(content)
  (self.updates/'release.json').write_text(json.dumps({'version':'local-new','sha256':hashlib.sha256(content).hexdigest()}))
 def test_no_prepared_update_is_truthful_noop(self):
  self.assertIn('Новых подготовленных',u.update());self.kill.assert_not_called()
 def test_same_binary_does_not_restart_client(self):
  self.release(self.binary.read_bytes());self.assertIn('уже установлена',u.update());self.kill.assert_not_called()
 def test_wrong_checksum_cannot_replace_binary(self):
  self.release();self.candidate.write_bytes(b'corrupted')
  with self.assertRaises(ValueError):u.update()
  self.assertEqual(self.binary.read_bytes(),b'old-compatible-binary');self.kill.assert_not_called()
 def test_failed_config_validation_does_not_replace_binary(self):
  self.release()
  def command(args):
   if args[1]=='check':raise ValueError('ML-KEM not supported')
   return 'sing-box version '+('local-new' if args[0]==str(self.candidate) else 'local-old')
  self.commands.side_effect=command
  with self.assertRaises(ValueError):u.update()
  self.assertEqual(self.binary.read_bytes(),b'old-compatible-binary');self.kill.assert_not_called()
 def test_successful_update_signals_only_validated_supervisor(self):
  self.release();self.assertIn('обновлён',u.update())
  self.assertEqual(self.binary.read_bytes(),b'new-compatible-binary');self.kill.assert_called_once_with(77,signal.SIGHUP)
  self.assertEqual(self.wait.call_args.args[1],'local-new')
 def test_failed_healthcheck_restores_old_binary(self):
  self.release();self.wait.side_effect=[RuntimeError('bad release'),None]
  with self.assertRaisesRegex(RuntimeError,'Предыдущая сборка восстановлена'):u.update()
  self.assertEqual(self.binary.read_bytes(),b'old-compatible-binary');self.assertEqual(self.kill.call_count,2)

if __name__=='__main__':unittest.main()
