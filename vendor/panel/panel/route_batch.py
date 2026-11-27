"""Apply a complete manual-route draft as one recoverable reconfiguration."""
import hashlib
import json
from pathlib import Path
from durable_io import write
import router_routes as rr


def snapshot(routes=None):
    routes=rr.Router().routes() if routes is None else routes
    targets=rr.read_targets();rows={}
    for route in routes:
        if not rr.mutable(route):continue
        net=route['dst-address'];value=targets.get(net,{})
        rows[net]={'net':net,'label':route.get('comment','').removeprefix(rr.PREFIX),'target':value.get('target',rr.default_target()),
                   'metric':value.get('metric',100),'enabled':not rr.yes(route.get('disabled')),'override':False}
    for net,value in targets.items():
        if value.get('override'):rows[net]={'net':net,'label':value.get('label','Маршрут'),'target':value['target'],'metric':value.get('metric',100),'enabled':value.get('enabled',True),'override':True}
    return sorted(rows.values(),key=lambda row:row['net'])


def fingerprint(rows):
    clean=[{key:row[key] for key in ('net','label','target','metric','enabled')} for row in rows]
    return hashlib.sha256(json.dumps(sorted(clean,key=lambda row:row['net']),sort_keys=True,ensure_ascii=False).encode()).hexdigest()


def external_snapshot(router):
    return {'routes':[r for r in router.routes() if rr.via_container(r) and r.get('dst-address')!=str(rr.FAKE) and (rr.mutable(r) or r.get('comment')==rr.SERVICE_ROUTE)],
            'rules':[r for r in router.rules() if r.get('src-address')=='172.31.41.2/32' and r.get('comment') in {rr.PREFIX+'return path',rr.SERVICE_RETURN,'4011 Telegram DIRECT return path'}]}


def restore_external(router, saved):
    specs=[('ip/route','routes',('dst-address','gateway','routing-table','comment'),('dst-address','gateway','routing-table','distance','comment','disabled')),
           ('routing/rule','rules',('src-address','dst-address','table','comment'),('src-address','dst-address','table','action','comment','disabled'))]
    current=external_snapshot(router)
    for path,key,identity,fields in specs:
        ident=lambda row:tuple(row.get(k,'') for k in identity)
        previous={ident(row):row for row in saved[key]};now={ident(row):row for row in current[key]}
        for signature,row in now.items():
            if signature not in previous:router.call(path+'/'+rr.rid(row['.id']),'DELETE')
        for signature,row in previous.items():
            payload={field:row[field] for field in fields if field in row}
            payload.setdefault('disabled',False)
            if signature in now:router.call(path+'/'+rr.rid(now[signature]['.id']),'PATCH',payload)
            else:router.call(path,'PUT',payload)


def recover(journal):
    # A crash after the queue committed the job must not undo a successful batch.
    import sqlite3
    done=journal.get('committed',False)
    if journal.get('job_id'):
        database=rr.ROOT/'rules/configuration-jobs.sqlite3'
        with sqlite3.connect(database) as db:
            row=db.execute('SELECT status FROM jobs WHERE id=?',(journal['job_id'],)).fetchone()
        done=bool(row and row[0]=='done')
    router=rr.Router()
    if not done:
        if journal.get('clients'):
            import client_batch
            client_batch.restore(router,journal['clients'])
        elif journal.get('transit_policy'):
            import client_policy
            client_policy.restore(router,journal['transit_policy'])
        restore_external(router,journal['external'])
    rr.sync_container(router.routes(),reload=False)
    rr.clear_intent()


def apply(data, report=lambda _stage:None, after_commit=None, job_id=None, *, prepare=None, force=False, client_plan=None):
    rr.check_token(data.get('route_token',[''])[0])
    with rr.LOCK:
        router=rr.Router();routes=router.routes();original=snapshot(routes)
        if data.get('baseline',[''])[0]!=fingerprint(original):raise ValueError('Конфигурация маршрутов изменилась. Обновите список или отмените черновик.')
        rows=json.loads(data.get('draft',['[]'])[0])
        if not isinstance(rows,list) or len(rows)>512:raise ValueError('Допустимо до 512 ручных маршрутов')
        choices=rr.target_choices();addresses=router.addresses();servers=rr.server_ips();desired={}
        for row in rows:
            if not isinstance(row,dict) or type(row.get('enabled')) is not bool:raise ValueError('Некорректная строка маршрута')
            net=rr.validate_destination(str(row.get('net','')),addresses,servers)
            if net in desired:raise ValueError('Ручная запись для '+net+' повторяется')
            target=row.get('target')
            if target not in choices and (row['enabled'] or next((r['target'] for r in original if r['net']==net),None)!=target):raise ValueError('Маршрут недоступен: '+str(target))
            label=str(row.get('label','')).strip() or 'Маршрут'
            if len(label)>80 or any(ord(c)<32 for c in label):raise ValueError('Некорректное название маршрута')
            desired[net]={'target':target,'metric':rr.checked_metric(row.get('metric',100)),'label':label,'enabled':row['enabled'],'override':False}
        manual={r['dst-address']:r for r in routes if rr.mutable(r)}
        original_map={r['net']:r for r in original}
        needed=set(desired)-manual.keys()
        owned={r['dst-address'] for r in routes if r.get('comment')==rr.SERVICE_ROUTE and rr.via_container(r)}
        if needed-owned:
            from service_routes_panel import read_services
            from routes_table_ui import service_networks
            for item in read_services():
                for net in service_networks(item):
                    if net in needed:owned.add(net)
        for net,value in desired.items():
            value['override']=net in owned or original_map.get(net,{}).get('override',False)
            foreign=[r for r in routes if r.get('dst-address')==net and r.get('routing-table','main')=='main' and not rr.mutable(r) and r.get('comment')!=rr.SERVICE_ROUTE]
            if foreign:raise ValueError('Сеть '+net+' управляется вне панели')
        if not force and fingerprint(original)==fingerprint([{**value,'net':net} for net,value in desired.items()]):return 'Изменений маршрутов нет'
        before=rr.saved_files();external=external_snapshot(router)
        old_networks=rr.service_networks((rr.ROOT/'default_config_candidate.yaml').read_text())
        import client_policy
        transit_policy=client_policy.owned_snapshot(router) if not client_plan else None
        journal={'action':'route_apply','committed':False,'job_id':job_id,'external':external}
        if client_plan:journal['clients']=client_plan
        else:journal['transit_policy']=transit_policy
        write(rr.JOURNAL,json.dumps(journal).encode())
        try:
            report('Проверка и сборка нового набора маршрутов')
            predicted=[dict(r) for r in routes if not rr.mutable(r)]
            for net,value in desired.items():
                if value['override']:continue
                predicted.append({'dst-address':net,'gateway':'172.31.41.2','routing-table':'main','distance':str(value['metric']),
                                  'disabled':not value['enabled'],'comment':rr.PREFIX+value['label']})
            write(rr.TARGETS,json.dumps(desired,ensure_ascii=False).encode())
            if prepare:prepare()
            rr.sync_container(predicted,reload=False)
            if client_plan:
                import client_batch
                client_batch.apply(router,client_plan,report)
            report('Применение изменений в RouterOS')
            rr.ensure_wan_route(router,routes)
            for net,route in manual.items():
                if net not in desired or desired[net]['override']:
                    router.call('ip/route/'+rr.rid(route['.id']),'DELETE')
                    for rule in router.rules():
                        if rule.get('dst-address')==net and rule.get('src-address')=='172.31.41.2/32' and rule.get('comment') in {rr.PREFIX+'return path','4011 Telegram DIRECT return path'}:
                            router.call('routing/rule/'+rr.rid(rule['.id']),'DELETE')
            for net,value in desired.items():
                if value['override']:continue
                payload={'dst-address':net,'gateway':'172.31.41.2','routing-table':'main','distance':str(value['metric']),
                         'disabled':not value['enabled'],'comment':rr.PREFIX+value['label']}
                if net in manual:router.call('ip/route/'+rr.rid(manual[net]['.id']),'PATCH',payload)
                else:
                    router.call('routing/rule','PUT',{'src-address':'172.31.41.2/32','dst-address':net,'action':'lookup-only-in-table','table':router.cfg['bypass_table'],'comment':rr.PREFIX+'return path'})
                    router.call('ip/route','PUT',payload)
            new_networks=rr.service_networks((rr.ROOT/'default_config_candidate.yaml').read_text())
            report('Реконфигурация Mihomo')
            import boot_config
            module=boot_config.apply_module();module.put_config()
            from routing_panel import read_settings,set_global_proxy
            set_global_proxy(read_settings()['main_proxy'])
            from transit_mode import active as transit_active
            capture_desired=transit_active()
            if not client_plan and capture_desired:client_policy.sync_transit(router)
            rr.sync_service_routes(new_networks)
            if not client_plan and not capture_desired:client_policy.sync_transit(router)
            if fingerprint(snapshot(router.routes()))!=fingerprint([{**row,'net':net} for net,row in desired.items()]):raise RuntimeError('RouterOS не подтвердил итоговые маршруты')
            module.save_last_good()
        except Exception as error:
            try:
                if client_plan:
                    import client_batch
                    client_batch.restore(router,client_plan)
                else:client_policy.restore(router,transit_policy)
                restore_external(router,external)
                rr.rollback_files(before)
                rr.sync_service_routes(old_networks)
                rr.clear_intent()
            except Exception as rollback_error:
                raise RuntimeError(str(error)+'; откат маршрутов ожидает восстановления: '+str(rollback_error)) from error
            raise
        if after_commit:after_commit(rr.clear_intent)
        else:
            journal['committed']=True;write(rr.JOURNAL,json.dumps(journal).encode())
        return 'Набор ручных маршрутов применён. Записей: '+str(len(desired))
