import json,os,subprocess,sys,tempfile
sys.path.insert(0,'/etc/mihomo/rules')
import vpn_clients as v,proxy_manager
for node in proxy_manager.read()['nodes']:
    p=v.canonical(node)
    if p.get('type')!='vless':continue
    _,cfg,_=v.build_external(node,'sing-box')
    fd,path=tempfile.mkstemp(dir='/etc/mihomo/clients',prefix='.diagnostic-')
    try:
        with os.fdopen(fd,'w') as f:json.dump(cfg,f)
        r=subprocess.run([v.binary('sing-box'),'check','-c',path],capture_output=True,text=True,timeout=45)
        text=(r.stderr+r.stdout)[-2500:]
        def redact(obj):
            nonlocal_dummy=None
            global text
            if isinstance(obj,dict):
                for key,value in obj.items():
                    if isinstance(value,str) and key in ('server','uuid','password','public_key','short_id','server_name') and value:text=text.replace(value,'[redacted]')
                    else:redact(value)
            elif isinstance(obj,list):
                for item in obj:redact(item)
        redact(cfg)
        print(json.dumps({'name':p['name'],'exit':r.returncode,'diagnostic':text}))
    finally:os.unlink(path)
