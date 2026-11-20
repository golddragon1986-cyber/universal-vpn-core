import io,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'vendor/panel/panel'))
import geodata_panel as panel,geodata_search as search

def varint(n):
 out=bytearray()
 while n>127:out.append((n&127)|128);n>>=7
 return bytes(out)+bytes([n])
def field(tag,data):return bytes([tag])+varint(len(data))+data
def database(ip=False):
 record=field(10,bytes([91,108,4,0]))+b'\x10\x16' if ip else b'\x08\x02'+field(18,b'example.com')
 return field(10,field(10,b'test-category')+field(18,record))
def multipart(data):
 boundary='boundary-test';body=b''
 for name,value in [('name',b'Local test'),('operation',b'upload'),('token',panel.TOKEN.encode()),('file',data)]:
  body+=b'--'+boundary.encode()+b'\r\nContent-Disposition: form-data; name="'+name.encode()+b'"'+(b'; filename="upload.dat"' if name=='file' else b'')+b'\r\n\r\n'+value+b'\r\n'
 body+=b'--'+boundary.encode()+b'--\r\n'
 return 'multipart/form-data; boundary='+boundary,body
class Chunked(io.BytesIO):
 def read(self,size=-1):return super().read(min(size,7))
class Tests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  for target,value in [('ROOT',Path(self.temp.name)),('write',lambda p,b:p.write_bytes(b)),('sync_dir',lambda p:None)]:
   item=patch.object(panel,target,value);item.start();self.addCleanup(item.stop)
 def test_dat_domain_and_ip_are_searchable_local_sources(self):
  for ip in [False,True]:
   content,body=multipart(database(ip))
   with panel.read_request(content,Chunked(body),len(body)) as form:
    uploaded=form['file'];self.assertNotIsInstance(uploaded,bytes);panel.handle(form)
   self.assertTrue(uploaded.closed)
  entries=panel.entries();self.assertEqual({v['behavior'] for v in entries.values()},{'domain','ipcidr'})
  self.assertTrue(all(v['kind']=='geodat' and v['file'].endswith('.dat') and not v['url'] for v in entries.values()))
  result=search.search('example.com');self.assertFalse(result['errors']);self.assertEqual(result['results'][0]['name'],'test-category')
  entry=next(k for k,v in entries.items() if v['behavior']=='domain');self.assertEqual(search.load_category(entry,'test-category'),[('domains','example.com')])
  self.assertNotIn('value="delete_file"',panel.render())
 def test_mrs_validation_is_preserved(self):
  raw=b'\x28\xb5\x2f\xfdvalid-mrs'
  with patch.object(panel,'detect_behavior',return_value='domain') as check:
   content,body=multipart(raw)
   with panel.read_request(content,io.BytesIO(body),len(body)) as form:panel.handle(form)
  check.assert_called_once_with(raw);self.assertTrue(next(iter(panel.entries().values()))['file'].endswith('.mrs'))
 def test_invalid_dat_does_not_register_or_leave_files(self):
  content,body=multipart(b'not a database')
  with self.assertRaises(ValueError):
   with panel.read_request(content,io.BytesIO(body),len(body)) as form:panel.handle(form)
  self.assertFalse(panel.entries());self.assertEqual(list(panel.ROOT.iterdir()),[])
 def test_truncated_multipart_is_rejected(self):
  content,body=multipart(database());body=body[:-6]
  with self.assertRaises(ValueError):
   with panel.read_request(content,Chunked(body),len(body)) as form:panel.handle(form)
  self.assertEqual(list(panel.ROOT.iterdir()),[])
 def test_dat_larger_than_mrs_limit(self):
  # Many small valid categories exercise the upload path beyond the old 2 MiB cap.
  data=database()*(panel.MAX_FILE//len(database())+1)
  content,body=multipart(data)
  with panel.read_request(content,io.BytesIO(body),len(body)) as form:panel.handle(form)
  self.assertGreater(next(iter(panel.entries().values()))['size'],panel.MAX_FILE)
if __name__=='__main__':unittest.main()
