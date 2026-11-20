import io,json,sys,tempfile,unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'vendor/panel/panel'))
import component_versions as v
import vpn_components as c

class VersionTests(unittest.TestCase):
 def test_architecture_asset_names(self):
  self.assertEqual(v.asset_name('mihomo','v1.19.33','armv7'),'mihomo-linux-armv7-v1.19.33.gz')
  self.assertEqual(v.asset_name('sing-box','v1.14.4','arm64'),'sing-box-1.14.4-linux-arm64.tar.gz')
  self.assertEqual(v.asset_name('xray','v26.10.31','armv7'),'Xray-linux-arm32-v7a.zip')
 def test_streaming_catalog_handles_unicode_chunk_boundaries(self):
  class Chunks(io.BytesIO):
   def read(self,size=-1):return super().read(3)
  data=[{'tag_name':'v1.0','body':'Проверка'}, {'tag_name':'v2.0'}]
  self.assertEqual(list(v.releases(Chunks(json.dumps(data,ensure_ascii=False).encode()))),data)
 def test_initial_page_does_not_query_or_install(self):
  with tempfile.TemporaryDirectory() as d,patch.object(v,'CACHE',Path(d)/'none'),patch.object(v,'arch',return_value='armv7'),patch.object(v.subprocess,'run') as run,patch.object(v,'request') as request:
   self.assertTrue(v.catalog()['unchecked']);run.assert_not_called();request.assert_not_called()
 def test_refresh_only_updates_metadata(self):
  with tempfile.TemporaryDirectory() as d,patch.object(v,'CACHE',Path(d)/'catalog'),patch.object(v,'arch',return_value='armv7'),patch.object(v,'local_versions',return_value=[]),patch.object(v,'github_versions',return_value=[]),patch.object(v.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='openvpn-2.7.7-r0 armv7\nwireguard-tools-wg-1.0-r0 armv7\n',stderr='')) as run:
   data=v.catalog(True)
   self.assertEqual(data['items']['openvpn'][0]['id'],'apk:2.7.7-r0')
   self.assertTrue(all(call.args[0][1] in ('update','list','info') for call in run.call_args_list))
 def test_unlisted_versions_cannot_be_installed(self):
  with patch.object(v,'catalog',return_value={'items':{'openvpn':[{'id':'apk:2.7.7-r0','installable':True}]}}),patch.object(c,'run') as run:
   with self.assertRaises(ValueError):v.install('openvpn','apk:2.7.7-r0;reboot')
   run.assert_not_called()
 def test_download_requires_vendor_url_and_digest(self):
  with tempfile.TemporaryDirectory() as d,patch.object(v,'request') as request:
   with self.assertRaises(ValueError):v.download('mihomo',{'sha256':'0'*64,'url':'https://example.com/untrusted.gz'},Path(d))
   request.assert_not_called()
 def test_catalog_exposes_only_metadata_to_browser(self):
  with patch.object(c,'status',return_value={'items':[]}),patch.object(v,'catalog',return_value={'items':{'mihomo':[{'id':'github:v1','url':'private-internal-url','sha256':'abc','asset':'file','version':'v1'}]}}):
   item=v.public_catalog()['items']['mihomo'][0]
   self.assertNotIn('url',item);self.assertNotIn('sha256',item);self.assertEqual(item['version'],'v1')

if __name__=='__main__':unittest.main()
