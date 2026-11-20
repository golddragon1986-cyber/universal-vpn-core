import fs from 'node:fs/promises';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
const root = path.dirname(fileURLToPath(import.meta.url));
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
import {execFileSync} from 'node:child_process';
const str = b => b.toString().split('\0')[0];
function pax(data) {
  const result = {}; let i = 0;
  while (i < data.length) {
    const space = data.indexOf(32, i), len = Number(data.subarray(i, space).toString());
    if (!len || space < 0) throw Error('Invalid PAX record');
    const line = data.subarray(space + 1, i + len - 1).toString(), eq = line.indexOf('=');
    result[line.slice(0, eq)] = line.slice(eq + 1); i += len;
  }
  return result;
}
function untar(buf) {
  const result = []; let extra = {}, global = {}, longName = null;
  for (let i = 0; i + 512 <= buf.length;) {
    const h = buf.subarray(i, i + 512); if (h.every(b => !b)) break;
    const sum = h.reduce((s, b, p) => s + (p >= 148 && p < 156 ? 32 : b), 0);
    if (sum !== parseInt(str(h.subarray(148, 156)).trim(), 8)) throw Error('Invalid TAR header');
    const size = parseInt(str(h.subarray(124, 136)).trim(), 8) || 0;
    const type = str(h.subarray(156, 157)) || '0';
    const data = buf.subarray(i + 512, i + 512 + size);
    let name = str(h.subarray(0, 100)), prefix = str(h.subarray(345, 500));
    if (prefix) name = prefix + '/' + name;
    if (type === 'x') extra = pax(data);
    else if (type === 'g') global = { ...global, ...pax(data) };
    else if (type === 'L') longName = str(data);
    else {
      const attrs = { ...global, ...extra };
      name = attrs.path || longName || name;
      name = name.replace(/^\.\//, '').replace(/\/$/, '');
      if (name.startsWith('/') || name.split('/').includes('..')) throw Error('Unsafe source path');
      result.push({ name, type, data, mode: parseInt(str(h.subarray(100, 108)).trim(), 8) || 0o644,
        link: attrs.linkpath || str(h.subarray(157, 257)) });
      extra = {}; longName = null;
    }
    i += 512 + Math.ceil(size / 512) * 512;
  }
  return result;
}
function header(e) {
  const b = Buffer.alloc(512), data = e.data || Buffer.alloc(0);
  let name = e.name, prefix = '';
  if (Buffer.byteLength(name) > 100) {
    const positions = [...name.matchAll(/\//g)].map(m => m.index).reverse();
    const split = positions.find(i => Buffer.byteLength(name.slice(0, i)) <= 155 && Buffer.byteLength(name.slice(i + 1)) <= 100);
    if (split === undefined) throw Error('Path too long for USTAR: ' + name);
    prefix = name.slice(0, split); name = name.slice(split + 1);
  }
  b.write(name, 0, 100); b.write(prefix, 345, 155);
  const oct = (v, o, n) => b.write(v.toString(8).padStart(n - 1, '0') + '\0', o, n);
  oct(e.mode || 0o644, 100, 8); oct(0, 108, 8); oct(0, 116, 8);
  oct(data.length, 124, 12); oct(1793577600, 136, 12);
  b.fill(32, 148, 156); b.write(e.type || '0', 156, 1);
  if (e.link) { if (Buffer.byteLength(e.link) > 100) throw Error('Link too long'); b.write(e.link, 157, 100); }
  b.write('ustar\0', 257, 6); b.write('00', 263, 2);
  b.write(b.reduce((a, v) => a + v, 0).toString(8).padStart(6, '0') + '\0 ', 148, 8);
  return b;
}
const tar = entries => Buffer.concat([...entries.flatMap(e => {
  const data = e.data || Buffer.alloc(0);
  return [header(e), data, Buffer.alloc((512 - data.length % 512) % 512)];
}), Buffer.alloc(1024)]);

const upx = process.argv[2];
if (!upx) throw Error('Usage: node build-lite.mjs PATH_TO_UPX');
const release = path.join(root, 'version', '0.31b.191126.1600', 'universal-vpn');
const output = path.join(root, 'build', 'lite-0.31b');
const buildInfo = JSON.parse(await fs.readFile(path.join(release, 'BUILD-INFO.json')));
await fs.mkdir(output, {recursive:true});
const results = process.argv[3] ? JSON.parse(await fs.readFile(path.join(output,'BUILD-INFO.json'))).architectures : {};
for (const arch of (process.argv[3] ? [process.argv[3]] : ['armv7', 'arm64'])) {
  const filename = 'universal-vpn-core-' + arch + '.tar';
  const source = await fs.readFile(path.join(release, filename));
  if (sha(source) !== buildInfo.architectures[arch].sha256) throw Error('Unexpected source SHA-256: ' + arch);
  const archive = new Map(untar(source).map(e => [e.name, e.data]));
  const blob = digest => archive.get('blobs/' + digest.replace(':', '/'));
  const index = JSON.parse(archive.get('index.json'));
  const manifest = JSON.parse(blob(index.manifests[0].digest));
  if (index.manifests.length !== 1 || manifest.layers.length !== 1) throw Error('Expected single-layer image');
  const config = JSON.parse(blob(manifest.config.digest));
  const originalLayer = zlib.gunzipSync(blob(manifest.layers[0].digest));
  const entries = untar(originalLayer);
  const core = entries.find(e => e.name === 'mihomo' && e.type === '0');
  if (!core) throw Error('Missing Mihomo ELF: ' + arch);
  const temporary = await fs.mkdtemp(path.join(output, '.pack-'));
  const additions = [];
  const entrypoint = 'usr/local/lib/mihomo-panel/entrypoint.sh';
  if (!entries.some(e => e.name === entrypoint)) {
    const script = (await fs.readFile(path.join(root,'vendor','panel','entrypoint.sh'),'utf8')).replace(/\r\n/g,'\n');
    additions.push({name:entrypoint,type:'0',mode:0o755,data:Buffer.from(script)});
  }
  const originalBytes = core.data.length;
  try {
    const input = path.join(temporary, 'original');
    const packed = path.join(temporary, 'packed');
    await fs.writeFile(input, core.data);
    execFileSync(upx, ['--best', '--lzma', '-o', packed, input], {stdio:'inherit'});
    core.data = await fs.readFile(packed);
  } finally {
    await fs.rm(temporary, {recursive:true, force:true});
  }
  // Preserve the original tar headers, entry ordering and extended metadata.
  let layer;
  for (let offset = 0; offset + 512 <= originalLayer.length;) {
    const originalHeader = originalLayer.subarray(offset, offset + 512);
    if (originalHeader.every(byte => !byte)) break;
    const bytes = parseInt(str(originalHeader.subarray(124, 136)).trim(), 8) || 0;
    const next = offset + 512 + Math.ceil(bytes / 512) * 512;
    if (str(originalHeader.subarray(0, 100)).replace(/^\.\//, '') === 'mihomo' &&
        bytes === originalBytes && str(originalHeader.subarray(345, 500)) === '') {
      layer = Buffer.concat([
        tar(additions).subarray(0, -1024), originalLayer.subarray(0, offset),
        header(core), core.data, Buffer.alloc((512 - core.data.length % 512) % 512),
        originalLayer.subarray(next)
      ]);
      break;
    }
    offset = next;
  }
  if (!layer) throw Error('Cannot locate the original Mihomo tar entry: ' + arch);
  const packed = zlib.gzipSync(layer, {level:9});
  const fileBytes = [...entries, ...additions].filter(e => e.type === '0').reduce((sum,e) => sum+e.data.length,0);
  if (fileBytes > 70 * 1024 ** 2) throw Error('Lite exceeds 70 MiB in regular files: ' + arch);
  const descriptor = (data, mediaType) => ({mediaType, digest:'sha256:'+sha(data), size:data.length});
  config.rootfs.diff_ids = ['sha256:'+sha(layer)];
  const configBytes = Buffer.from(JSON.stringify(config));
  manifest.config = descriptor(configBytes, manifest.config.mediaType);
  manifest.layers = [descriptor(packed, manifest.layers[0].mediaType)];
  const manifestBytes = Buffer.from(JSON.stringify(manifest));
  index.manifests[0] = {...index.manifests[0], ...descriptor(manifestBytes,index.manifests[0].mediaType)};
  const image = tar([
    {name:'oci-layout',data:archive.get('oci-layout')},
    {name:'index.json',data:Buffer.from(JSON.stringify(index))},
    ...[configBytes, manifestBytes, packed].map(data => ({name:'blobs/sha256/'+sha(data),data}))
  ]);
  const name = filename.replace('-core-', '-lite-');
  await fs.writeFile(path.join(output,name),image);
  results[arch] = {file:name, sha256:sha(image), archiveBytes:image.length, fileBytes, originalCoreBytes:originalBytes, packedCoreBytes:core.data.length};
}
await fs.writeFile(path.join(output,'BUILD-INFO.json'),JSON.stringify({source:buildInfo.version,architectures:results},null,2)+'\n');
console.log(results);


