import json,struct,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'vendor/panel/panel'))
from tls_profile_capture import parse_hello

class ProfileTests(unittest.TestCase):
 def packet(self):
  u16=lambda n:struct.pack('!H',n)
  ext=lambda n,b:u16(n)+u16(len(b))+b
  group=u16(29)+u16(32)+b'K'*32
  extensions=ext(43,b'\x04\x03\x04\x03\x03')+ext(10,u16(4)+u16(29)+u16(23))+ext(51,u16(len(group))+group)+ext(16,u16(12)+b'\x02h2\x08http/1.1')
  body=b'\x03\x03'+b'R'*32+b'\x20'+b'S'*32+u16(4)+u16(4865)+u16(4866)+b'\x01\x00'+u16(len(extensions))+extensions
  hs=b'\x01'+len(body).to_bytes(3,'big')+body
  return b'\x16\x03\x01'+u16(len(hs))+hs
 def test_extracts_wire_metadata_without_auth_or_key_bytes(self):
  p=parse_hello(self.packet())
  self.assertEqual(p['supported_versions'],[772,771])
  self.assertEqual(p['supported_groups'],[29,23])
  self.assertEqual(p['key_shares'],[{'group':29,'public_key_bytes':32}])
  self.assertEqual(p['alpn'],['h2','http/1.1'])
  self.assertEqual(p['ja3'],'771,4865-4866,43-10-51-16,29-23,')
  text=json.dumps(p)
  for secret in ('R'*32,'S'*32,'K'*32):self.assertNotIn(secret,text)
 def test_partial_record_does_not_produce_a_profile(self):
  self.assertIsNone(parse_hello(self.packet()[:-10]))

if __name__=='__main__':unittest.main()
