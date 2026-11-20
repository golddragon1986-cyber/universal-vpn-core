import fs from 'node:fs/promises';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
const root = path.dirname(fileURLToPath(import.meta.url));
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const version = '0.1.0-core.20261104';
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
async function files(dir, prefix = '') {
  const entries = [];
  for (const name of (await fs.readdir(dir)).sort()) {
    const p = path.join(dir, name), st = await fs.lstat(p), n = prefix + name;
    if (st.isSymbolicLink()) throw Error('Source symlink not allowed: ' + p);
    if (st.isDirectory()) entries.push(...await files(p, n + '/'));
    else if (!/\.pyc$|__pycache__/.test(n)) entries.push({ name: n, type: '0', mode: /\.sh$/.test(n) ? 0o755 : 0o644, data: await fs.readFile(p) });
  }
  return entries;
}
const output = process.env.BUILD_OUTPUT ? path.resolve(process.env.BUILD_OUTPUT) : path.join(root, 'build');
const arm64Input = process.env.ARM64_INPUT;
const livePanel = Boolean(arm64Input) || process.env.USE_LIVE_PANEL === '1';
const platform = arm64Input ? {architecture:'arm64'} : {architecture:'arm',variant:'v7'};
const input = await fs.readFile(arm64Input
  ? path.join(root, 'usb-release', 'universal-vpn-core-armv7.tar')
  : path.join(output, 'base-armv7.tgz'));
const packageHashes = {};
const packageVersions = {};
const apkRepo = 'usr/local/share/universal-vpn-apk';
let sourceEntries;
if (arm64Input) {
  const sourceArchive = new Map(untar(input).map(e => [e.name, e.data]));
  const blob = digest => sourceArchive.get('blobs/' + digest.replace(':', '/'));
  const manifest = JSON.parse(blob(JSON.parse(sourceArchive.get('index.json')).manifests[0].digest));
  const sourceLayer = untar(zlib.gunzipSync(blob(manifest.layers[0].digest)));
  sourceEntries = sourceLayer.filter(e => /^usr\/local\/lib\/mihomo-panel(?:\/|$)/.test(e.name));
  const packageNames = (await fs.readFile(path.join(arm64Input, 'packages.txt'), 'utf8')).trim().split(/\s+/);
  for (const name of packageNames) {
    if (!/^[\w.+-]+\.apk$/.test(name)) throw Error('Invalid APK filename: ' + name);
    const apk = await fs.readFile(path.join(arm64Input, name));
    const contents = untar(zlib.gunzipSync(apk));
    const metadata = contents.find(e => e.name === '.PKGINFO')?.data.toString();
    if (!/^arch = (aarch64|noarch)$/m.test(metadata ?? '')) throw Error('Unexpected APK architecture: ' + name);
    packageHashes[name] = sha(apk);
    const packageName = /^pkgname = (.+)$/m.exec(metadata)[1];
    packageVersions[packageName] = /^pkgver = (.+)$/m.exec(metadata)[1];
    sourceEntries.push(...contents.filter(e => !e.name.startsWith('.')));
    sourceEntries.push({name:apkRepo+'/aarch64/'+name,type:'0',mode:0o644,data:apk});
  }
  const applets = sourceEntries.find(e => e.name === 'etc/busybox-paths.d/busybox').data.toString().trim().split('\n');
  const installed = new Set(sourceEntries.map(e => e.name));
  for (const name of applets) {
    if (!installed.has(name)) sourceEntries.push({name,type:'2',mode:0o777,link:'/bin/busybox',data:Buffer.alloc(0)});
  }
  for (const e of sourceLayer) {
    if (e.name === 'etc/apk/repositories' || (e.name.startsWith('etc/ssl/certs/') && e.type === '2')) {
      const target = path.posix.resolve('/', path.posix.dirname(e.name), e.link).slice(1);
      if (!installed.has(e.name) && (e.type !== '2' || installed.has(target))) sourceEntries.push(e);
    }
  }
} else {
  sourceEntries = untar(zlib.gunzipSync(input));
}
const entries = new Map();
for (const e of sourceEntries) {
  if (!['0','1','2','5'].includes(e.type)) continue;
  if (livePanel && /^(?:etc\/mihomo|root|tmp|run)(?:\/|$)/.test(e.name)) {
    if (arm64Input && e.type === '5') continue;
    throw Error('Runtime state in live base: '+e.name);
  }
  if (!livePanel && /^usr\/local\/lib\/mihomo-panel(?:\/|$)/.test(e.name)) continue;
  if (/__pycache__|\.pyc$/.test(e.name)) continue;
  if (e.type === '0' && e.data.includes(Buffer.from('PRIVATE KEY-----'))) throw Error('Private key in base');
  entries.set(e.name, e);
}
// RouterOS imports hardlinks in archive order. Materialize them for portability.
function resolveHardlink(e, seen=new Set()) {
  if(e.type!=='1') return e;
  if(seen.has(e.name)) throw Error('Hardlink cycle');
  seen.add(e.name);
  const target=entries.get(e.link.replace(/^\.\//,''));
  if(!target) throw Error('Missing hardlink target: '+e.link);
  return resolveHardlink(target,seen);
}
for(const [name,e] of entries) {
  if(e.type==='1') { const target=resolveHardlink(e); entries.set(name,{...target,name,type:'0',link:''}); }
}
const add = (name, data, mode=0o644) => entries.set(name,{name,type:'0',mode,data:Buffer.from(data)});
const releasePanel = arm64Input || process.env.USE_RELEASE_PANEL === '1';
if (releasePanel) {
  add('usr/local/lib/mihomo-panel/initialize.py', await fs.readFile(path.join(root,'vendor','panel','initialize.py')));
  add('usr/local/lib/mihomo-panel/default-services.json', await fs.readFile(path.join(root,'vendor','panel','default-services.json')));
  add('usr/local/lib/mihomo-panel/panel/dns_panel.py', await fs.readFile(path.join(root,'vendor','panel','panel','dns_panel.py')));
  const templateName='usr/local/lib/mihomo-panel/default-config.yaml';
  const template=entries.get(templateName)?.data.toString('utf8');
  const fakeIpFallback=/^    - MATCH,fake-ip(?=\r?$)/m;
  if (!template || (!fakeIpFallback.test(template) && !/^    - MATCH,real-ip(?=\r?$)/m.test(template))) {
    throw Error('Missing managed DNS fallback');
  }
  const unifiedDelay=/^unified-delay:[^\r\n]*/m;
  const dnsTemplate=template.replace(fakeIpFallback,'    - MATCH,real-ip');
  add(templateName,unifiedDelay.test(dnsTemplate)
    ? dnsTemplate.replace(unifiedDelay,'unified-delay: true')
    : 'unified-delay: true\n'+dnsTemplate);
  for (const name of ['manage_ru_blocked.py','panel_updater.py','action_queue_ui.html','control_shared.css','router_routes.py','proxy_manager.py','vpn_subscriptions.py','subscription_automation.py','vpn_clients.py','action_queue.py','action_log.py','vpn_components.py','components_ui.html','component_versions.py','component_binary.py','service_routes_panel.py','build-service-routes.py','apply-service-routes.py','boot_config.py','domain_provider.py','update-ru-blocked.sh','config_backup.py','action_recovery.py','geodata_panel.py','geodata_domains.py','geodata_search.py','geodata_service_files.py']) {
    add('usr/local/lib/mihomo-panel/panel/'+name, await fs.readFile(path.join(root,'vendor','panel','panel',name)), name.endsWith('.sh') ? 0o755 : 0o644);
  }
}
if (arm64Input) {
  add(apkRepo+'/aarch64/APKINDEX.tar.gz', await fs.readFile(path.join(arm64Input,'APKINDEX.tar.gz')));
  add(apkRepo+'/world', Object.keys(packageVersions).sort().join('\n')+'\n');
  add('usr/local/lib/mihomo-panel/arm64-apk-entrypoint.sh', await fs.readFile(path.join(root,'arm64-apk-entrypoint.sh')), 0o755);
  add('usr/local/lib/mihomo-panel/panel/bundled-apk-versions.json', JSON.stringify(packageVersions)+'\n');
  const mihomo = await fs.readFile(path.join(arm64Input, 'mihomo.gz'));
  if (sha(mihomo) !== 'ba408b317080ee265c46cb923a50018c1b82cbd708551cdd46a1e3e307396187') {
    throw Error('Mihomo v1.19.33 ARM64 release checksum mismatch');
  }
  const binary = zlib.gunzipSync(mihomo);
  add('mihomo', binary, 0o755);
  entries.set('usr/local/bin/mihomo',{name:'usr/local/bin/mihomo',type:'2',mode:0o777,link:'/mihomo'});
  for (const name of ['mihomo','bin/busybox','usr/bin/python3.14','lib/ld-musl-aarch64.so.1']) {
    if (!entries.has(name)) throw Error('Missing required ARM64 runtime file: ' + name);
  }
  for (const e of entries.values()) {
    if (e.data?.subarray(0,4).equals(Buffer.from([0x7f,0x45,0x4c,0x46])) &&
        (e.data[4] !== 2 || e.data[5] !== 1 || e.data.readUInt16LE(18) !== 183)) {
      throw Error('Unexpected ELF architecture: ' + e.name);
    }
  }
}
let localSingBox=null;
try {
  if (livePanel) throw Object.assign(new Error('Keep live binary'), {code:'ENOENT'});
  const binary=await fs.readFile(path.join(output,'sing-box-1.14.4-mlkem-armv7'));
  add('usr/local/bin/sing-box',binary,0o755);
  localSingBox={version:'1.14.4-local.mlkem1',sha256:sha(binary),bytes:binary.length,tags:['with_utls']};
} catch(error) { if(error.code!=='ENOENT')throw error; }
for (const e of livePanel ? [] : await files(path.join(root,'vendor','panel'))) {
  entries.set('usr/local/lib/mihomo-panel/'+e.name,{...e,name:'usr/local/lib/mihomo-panel/'+e.name});
}
add('usr/local/lib/mihomo-panel/VERSION',version+'\n');
add('usr/local/lib/mihomo-panel/official-container','\n');
add('usr/local/lib/mihomo-panel/management-acl-mode','routeros\n');
add('usr/local/lib/mihomo-panel/THIRD-PARTY-NOTICES.md',await fs.readFile(path.join(root,'vendor','THIRD-PARTY-NOTICES.md')));
add('etc/hostname','universal-vpn-core\n');
add('etc/hosts','127.0.0.1 localhost\n::1 localhost\n');
add('etc/resolv.conf','nameserver 1.1.1.1\n');
add('etc/shadow','root:!:0:0:99999:7:::\n',0o600);
for (const name of ['etc/mihomo','tmp','run','root','dev','proc','sys','var','var/log','var/cache']) {
  entries.set(name,{name,type:'5',mode:name==='tmp'?0o1777:0o755,data:Buffer.alloc(0)});
}
const layer=tar([...entries.values()].sort((a,b)=>a.name.localeCompare(b.name)));
const packed=zlib.gzipSync(layer,{level:9});
const entrypoint=arm64Input?'arm64-apk-entrypoint.sh':'entrypoint.sh';
const cfg=Buffer.from(JSON.stringify({...platform,os:'linux',config:{Entrypoint:['/bin/sh','/usr/local/lib/mihomo-panel/'+entrypoint],WorkingDir:'/etc/mihomo',Env:['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','TZ=Europe/Moscow','GOMEMLIMIT=100MiB','GOGC=50']},rootfs:{type:'layers',diff_ids:['sha256:'+sha(layer)]},history:[]}));
const man=Buffer.from(JSON.stringify({schemaVersion:2,mediaType:'application/vnd.oci.image.manifest.v1+json',config:{mediaType:'application/vnd.oci.image.config.v1+json',digest:'sha256:'+sha(cfg),size:cfg.length},layers:[{mediaType:'application/vnd.oci.image.layer.v1.tar+gzip',digest:'sha256:'+sha(packed),size:packed.length}]}));
const index=Buffer.from(JSON.stringify({schemaVersion:2,manifests:[{mediaType:'application/vnd.oci.image.manifest.v1+json',digest:'sha256:'+sha(man),size:man.length,platform:{os:'linux',...platform}}]}));
const archive=tar([{name:'oci-layout',data:Buffer.from('{"imageLayoutVersion":"1.0.0"}')},{name:'index.json',data:index},{name:'blobs/sha256/'+sha(cfg),data:cfg},{name:'blobs/sha256/'+sha(man),data:man},{name:'blobs/sha256/'+sha(packed),data:packed}]);
const name=arm64Input?'universal-vpn-core-arm64.tar':'universal-vpn-core-armv7.tar';
await fs.writeFile(path.join(output,name),archive);
const info={version,architecture:'arm/v7',core:'Mihomo 1.19.33',panelSource:'Mihomo-Controll-Panel 0.1.2-draft.20261103',baseSha256:sha(input),archiveSha256:sha(archive),archiveBytes:archive.length,regularFileBytes:[...entries.values()].filter(e=>e.type==='0').reduce((n,e)=>n+e.data.length,0),privateRuntimeStateIncluded:false,scope:'Core + panel + DNS/FakeIP + VPN import (native Mihomo protocols) + optional client package manager.',files:entries.size};
if(livePanel) {
  info.version='clean-rb4011-20261106';
  info.panelSource='Live RB4011 system software and running panel code; no runtime state';
  info.core='Live /mihomo binary from RB4011';
}
info.localSingBox=localSingBox;
if (releasePanel) {
  info.panelSource='Clean RB4011 export with live RB4011 Components files from 2026-11-10 and local dark theme';
}
if (arm64Input) {
  info.version='clean-rb4011-arm64-20261110';
  info.architecture='arm64';
  info.core='Official Mihomo 1.19.33 linux-arm64';
  info.alpinePackageSha256=packageHashes;
}
const maxImageBytes=Number(process.env.IMAGE_MAX_BYTES||0);
if(maxImageBytes>0 && info.regularFileBytes>maxImageBytes) throw Error('Image exceeds IMAGE_MAX_BYTES');
await fs.writeFile(path.join(output,'BUILD-INFO.json'),JSON.stringify(info,null,2)+'\n');
console.log(JSON.stringify(info,null,2));


