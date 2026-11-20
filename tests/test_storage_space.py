import io,json,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'vendor/panel/panel'))
import storage_space as space,geodata_panel as geo,component_versions as versions,vpn_components as components,sing_box_update as sb
class Tests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
 def test_same_filesystem_peak_sizes_are_added_and_reserve_kept(self):
  with patch.object(space.shutil,'disk_usage',return_value=SimpleNamespace(free=space.RESERVE+150)):
   with self.assertRaisesRegex(ValueError,'Нужно.*доступно'):space.require_many([(self.root,100),(self.root/'new',100)])
   space.require_many([(self.root,100),(self.root/'new',50)])
 def test_different_filesystems_are_checked_independently(self):
  a=SimpleNamespace(stat=lambda:SimpleNamespace(st_dev=1));b=SimpleNamespace(stat=lambda:SimpleNamespace(st_dev=2))
  with patch.object(space,'existing',side_effect=[a,b]),patch.object(space.shutil,'disk_usage',return_value=SimpleNamespace(free=space.RESERVE+100)):
   space.require_many([('one',100),('two',100)])
 def test_upload_rejects_before_consuming_or_creating_files(self):
  stream=io.BytesIO(b'unread request')
  with patch.object(geo,'ROOT',self.root),patch.object(space.shutil,'disk_usage',return_value=SimpleNamespace(free=0)):
   with self.assertRaisesRegex(ValueError,'недостаточно свободного места'):
    with geo.read_request('multipart/form-data; boundary=test',stream,len(stream.getvalue())):pass
  self.assertEqual(stream.tell(),0);self.assertEqual(list(self.root.iterdir()),[])
 def test_space_loss_during_upload_cleans_temporary_file(self):
  boundary=b'--test\r\nContent-Disposition: form-data; name="file"; filename="test.dat"\r\n\r\npayload\r\n--test--\r\n'
  with patch.object(geo,'ROOT',self.root),patch.object(space.shutil,'disk_usage',side_effect=[SimpleNamespace(free=10**9),SimpleNamespace(free=0)]):
   with self.assertRaisesRegex(ValueError,'недостаточно свободного места'):
    with geo.read_request('multipart/form-data; boundary=test',io.BytesIO(boundary),len(boundary)):pass
  self.assertEqual(list(self.root.iterdir()),[])
 def test_failed_geodat_download_preserves_previous_file(self):
  import geodata_search as search
  target=self.root/'old.dat';target.write_bytes(b'previous valid database')
  def download(url,reader,**kwargs):return reader(io.BytesIO(b'a'*131072))
  with patch.object(search,'read_url',side_effect=download),patch.object(space.shutil,'disk_usage',side_effect=[SimpleNamespace(free=10**9),SimpleNamespace(free=10**9),SimpleNamespace(free=0)]):
   with self.assertRaisesRegex(ValueError,'недостаточно свободного места'):search.save_database('unused',target)
  self.assertEqual(target.read_bytes(),b'previous valid database');self.assertEqual(list(self.root.iterdir()),[target])
 def test_native_update_rejects_before_network_download(self):
  item={'id':'github:v1','version':'v1','installable':True,'size':100}
  with patch.object(versions,'catalog',return_value={'items':{'mihomo':[item]}}),patch.object(versions,'request') as request,patch.object(space.shutil,'disk_usage',return_value=SimpleNamespace(free=0)):
   with self.assertRaisesRegex(ValueError,'Обновление mihomo'):versions.install('mihomo','github:v1')
   request.assert_not_called()
 def test_apk_update_rejects_before_package_commands(self):
  item={'id':'apk:1','version':'1','installable':True}
  with patch.object(versions,'catalog',return_value={'items':{'openvpn':[item]}}),patch.object(components,'disk_limit',return_value=0),patch.object(components,'run') as run,patch.object(space.shutil,'disk_usage',return_value=SimpleNamespace(free=0)):
   with self.assertRaisesRegex(ValueError,'Установка openvpn'):versions.install('openvpn','apk:1')
   run.assert_not_called()
 def test_archive_space_is_checked_before_creating_archive(self):
  source=io.BytesIO(b'not read');source.headers={'Content-Length':'100'}
  item={'sha256':'a'*64,'url':'https://github.com/MetaCubeX/mihomo/releases/download/v1/file.gz'}
  with patch.object(versions,'request',return_value=source),patch.object(space.shutil,'disk_usage',return_value=SimpleNamespace(free=0)):
   with self.assertRaisesRegex(ValueError,'Обновление mihomo'):versions.download('mihomo',item,self.root)
  self.assertEqual(list(self.root.iterdir()),[])
if __name__=='__main__':unittest.main()
