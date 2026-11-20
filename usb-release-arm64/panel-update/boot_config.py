import importlib.util
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.request import urlopen
from durable_io import write
from action_recovery import Recovery

ROOT=Path("/etc/mihomo")
BASE=ROOT/"rules"
TEMPLATE=BASE/"panel-managed-template.yaml"
CANDIDATE=ROOT/"default_config_candidate.yaml"
RUNTIME=ROOT/"default_config.yaml"

def apply_module():
    spec=importlib.util.spec_from_file_location("boot_apply",BASE/"apply-service-routes.py")
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def run(args,timeout=240):
    result=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    if result.returncode:raise RuntimeError((result.stderr or result.stdout)[-3000:])
    return result.stdout.strip()

def compose(text,settings):
    template=text
    module=apply_module()
    for begin,end in ((module.RULE_BEGIN,module.RULE_END),(module.GROUP_BEGIN,module.GROUP_END),(module.FAKE_BEGIN,module.FAKE_END),(module.SELECTOR_BEGIN,module.SELECTOR_END),(module.BALANCE_BEGIN,module.BALANCE_END)):
        module.get_block(text,begin,end)
    if not settings.get("services_enabled",True):
        text=module.replace_block(text,"  "+module.RULE_BEGIN+"\n  "+module.RULE_END,module.RULE_BEGIN,module.RULE_END)
        text=module.replace_block(text,"    "+module.FAKE_BEGIN+"\n    "+module.FAKE_END,module.FAKE_BEGIN,module.FAKE_END)
    mode="redir-host" if settings.get("main_proxy","LOADBALANCE")=="DIRECT" else settings.get("dns_enhanced_mode_before_direct",module.dns_mode(text))
    text=module.set_dns_mode(text,mode)
    from log_panel import saved_level
    level=saved_level()
    if level:
        import re
        text=re.sub(r'^log-level:.*$', 'log-level: '+level, text, flags=re.M)
    from router_routes import with_service_tun_routes
    text=with_service_tun_routes(text,template)
    return text,mode

def prepare():
    recovered=Recovery(str(ROOT)).recover()
    if recovered is not None:print("Rolled back interrupted action",recovered,flush=True)
    if (BASE/'router_routes.py').exists():
        import router_routes
        try:router_routes.recover_pending()
        except Exception:print('RouterOS route recovery pending: open Routes after restoring router access',flush=True)
    import proxy_manager
    from service_routes_panel import read_services,write_services
    write_services(read_services())
    proxy_manager.save(proxy_manager.read())
    print(run(["python3",str(BASE/"build-service-routes.py")]),flush=True)
    print(run(["env","MIHOMO_BUILD_OFFLINE=1",str(BASE/"update-ru-blocked.sh")]),flush=True)
    settings=json.loads((BASE/"routing-settings.json").read_text()) if (BASE/"routing-settings.json").exists() else {}
    text,mode=compose(TEMPLATE.read_text(),settings)
    from router_routes import SERVICE_STATE, service_networks, sync_service_routes
    networks=service_networks(text)
    previous_networks=service_networks(CANDIDATE.read_text()) if CANDIDATE.exists() else set()
    fd,tmp=tempfile.mkstemp(prefix=".managed-boot-",dir=ROOT);os.close(fd)
    try:
        write(tmp,text.encode())
        run(["mihomo","-t","-d",str(ROOT),"-f",tmp],timeout=60)
        write(ROOT/"template/default_config.yaml",TEMPLATE.read_bytes())
        write(CANDIDATE,text.encode())
        write(RUNTIME,text.encode())
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    if networks or previous_networks or SERVICE_STATE.exists():
        try:
            sync_service_routes(networks)
        except Exception as error:
            print('RouterOS service routes pending: '+str(error),flush=True)
    print("Managed configuration validated; DNS mode="+mode,flush=True)

def api(path):
    with urlopen("http://127.0.0.1:9090"+path,timeout=3) as response:return json.load(response)

def ready():
    # Container boot prepared the configuration before starting Mihomo.
    # A standalone panel restart also recovers any interrupted operation.
    if os.environ.get("MIHOMO_BOOT_PREPARED")!="1":
        prepare()
        needs_reload=True
    else:
        needs_reload=False
    deadline=time.monotonic()+90
    module=apply_module()
    while True:
        try:
            api("/version")
            if needs_reload:
                module.put_config()
                needs_reload=False
            from routing_panel import read_settings,set_global_proxy
            info=api("/proxies/SELECTOR");settings=read_settings(info.get("now","LOADBALANCE"))
            set_global_proxy(settings["main_proxy"])
            providers=api("/providers/proxies").get("providers",{})
            if not {"SRV","USER-MANAGED"}.issubset(providers):
                raise RuntimeError("Required proxy providers are missing")
            text=CANDIDATE.read_text()
            module.verify(module.domains_in(module.get_block(text,module.RULE_BEGIN,module.RULE_END)))
            from domain_provider import verify_provider
            with (BASE/"ru-blocked-domain.txt").open() as source:
                domain_count=sum(1 for line in source if line.strip())
            verify_provider(domain_count,"mrs" if domain_count else "text")
            module.save_last_good()
            print("STARTUP READY: full configuration, proxy providers and selected route verified",flush=True)
            return
        except Exception as error:
            if time.monotonic()>deadline:
                raise RuntimeError("Full configuration did not become ready within 90 seconds: "+str(error)) from error
            time.sleep(.5)

if __name__=="__main__":
    prepare()
