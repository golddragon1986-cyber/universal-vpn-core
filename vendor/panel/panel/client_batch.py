"""Recoverable RouterOS client-list changes, including shared-ACL separation."""
import hashlib
import re
import client_panel as panel
import router_routes as rr


def payload(row, name=None):
    return {'list':name or row['list'],'address':row['address'],
            'comment':row.get('label',row.get('comment','')),
            'disabled':not row['enabled'] if 'enabled' in row else rr.yes(row.get('disabled'))}


def plan(rows, baseline, router=None, lease_requests=None, lease_actions=None):
    router=router or rr.Router()
    state=panel.read_state(router,cache=False)
    if baseline!=panel.fingerprint(state):raise ValueError('Список клиентов изменён в RouterOS. Обновите страницу или отмените черновик.')
    if not isinstance(rows,list) or len(rows)>512:raise ValueError('Допустимо до 512 записей клиентов')
    originals={row['id']:row for row in state['rows']};seen=set();ids=set();owners=set();desired=[]
    for row in rows:
        if not isinstance(row,dict) or type(row.get('enabled')) is not bool:raise ValueError('Некорректная запись клиента')
        ident=row.get('id','')
        if not isinstance(ident,str) or ident in ids or (ident not in originals and not re.fullmatch(r'new-[a-zA-Z0-9-]{1,80}',ident)):
            raise ValueError('Некорректный идентификатор клиента')
        ids.add(ident)
        name=row.get('list')
        if name not in state['lists']:raise ValueError('Этот список не используется для клиентов контейнера')
        if ident in originals and originals[ident]['list']!=name:raise ValueError('Нельзя переносить существующую запись в другой список')
        value=panel.address(row.get('address',''))
        if (name,value) in seen:raise ValueError('Адрес уже присутствует в списке клиентов: '+value)
        seen.add((name,value))
        label=originals[ident]['label'] if ident in originals else ''
        if ident in originals and row.get('label')!=label:raise ValueError('Комментарий RouterOS доступен только для чтения')
        alias=str(row.get('name','')).strip()
        route=row.get('route','RULES')
        import client_policy
        if route not in client_policy.choices():raise ValueError('Канал клиента недоступен: '+str(route))
        if len(alias)>100 or any(ord(ch)<32 for ch in alias):raise ValueError('Внутреннее имя: максимум 100 символов')
        if len(label)>100 or any(ord(ch)<32 for ch in label):raise ValueError('Название клиента: максимум 100 символов')
        owner=row.get('dhcp_owner','')
        if not isinstance(owner,str) or len(owner)>300 or (ident in originals and owner!=originals[ident].get('dhcp_owner','')):
            raise ValueError('Связь клиента с DHCP-арендой изменилась. Обновите страницу.')
        if owner and ident in originals and value!=originals[ident]['address']:
            raise ValueError('Адрес DHCP-клиента изменяется через аренду RouterOS')
        if owner:
            if owner in owners:raise ValueError('DHCP-аренда связана с несколькими клиентами')
            owners.add(owner)
        desired.append({'id':ident,'list':name,'address':value,'label':label,'name':alias,
                        'route':route,'enabled':row['enabled'],'dhcp_owner':owner})
    migrations={}
    existing_lists={row['list'] for row in router.call('ip/firewall/address-list')}
    for name in state['protected']:
        # Routing and management share an ACL. Copy its current membership and
        # move only management references, leaving routing scripts compatible.
        if any(rr.yes(row.get('dynamic')) for row in state['raw'] if row['list']==name):
            raise ValueError('Список '+name+' содержит динамические записи. Сначала выделите для маршрутизации отдельный статический список RouterOS.')
        target=panel.MANAGEMENT_LIST if name=='uvpn-main-lan' else 'uvpn-management-'+hashlib.sha256(name.encode()).hexdigest()[:12]
        if target in existing_lists:raise ValueError('Отдельный список '+target+' уже существует, но не подключён к управлению. Проверьте настройки RouterOS.')
        migrations[name]=target
    import client_policy
    import dhcp_leases
    dhcp_static = dhcp_leases.plan(lease_requests or [], desired, router)
    dhcp_actions = dhcp_leases.plan_actions(lease_actions or [], dhcp_static, router)
    leases = {dhcp_leases.owner_key(row): row for row in dhcp_leases.snapshot(router)['leases']} if owners else {}
    disabled_owners = {owner for owner, lease in leases.items() if owner and lease['disabled']}
    for item in dhcp_actions:
        owner=dhcp_leases.owner_key(item['identity'])
        linked = [row for row in desired if owner and row['dhcp_owner'] == owner]
        if item['action'] == 'unpin' and linked:
            raise ValueError('Сначала удалите маршрут DHCP-клиента')
        if item['action'] == 'disable' and owner:
            disabled_owners.add(owner)
        elif item['action'] == 'enable':
            disabled_owners.discard(owner)
    desired = [row for row in desired if row['dhcp_owner'] not in disabled_owners]
    new_owned=[row for row in desired if row['dhcp_owner'] and row['id'] not in originals]
    if new_owned:
        leases={dhcp_leases.owner_key(row):row for row in dhcp_leases.snapshot(router)['leases']}
        pinned={row['id'] for row in dhcp_static}
        for row in new_owned:
            lease=leases.get(row['dhcp_owner'])
            if (not lease or lease['ip']!=row['address']
                    or (lease['dynamic'] and lease['id'] not in pinned)):
                raise ValueError('Новый DHCP-клиент не связан с закреплённой арендой')
    client_policy.effective(desired)
    return {'baseline':baseline,'before':state['raw'],'bindings':state['management_bindings'],
            'policy_before':client_policy.owned_snapshot(router),'state':state,
            'desired':desired,'migrations':migrations,'lists':list(state['lists']),
            'dhcp_static':dhcp_static,'dhcp_actions':dhcp_actions}


def apply(router, change, report=lambda _:None):
    def external_fingerprint(state):
        state={**state,'rows':[{k:v for k,v in row.items() if k not in {'name','route','dhcp_owner'}} for row in state['rows']]}
        return panel.fingerprint(state)
    if external_fingerprint(panel.read_state(router,cache=False))!=external_fingerprint(change['state']):
        raise ValueError('Клиенты RouterOS изменились во время сборки конфигурации')
    report('Применение сетей и адресов клиентов в RouterOS')
    before={row['.id']:row for row in change['before'] if panel.editable(row)}
    migrations=change['migrations'];desired=change['desired']
    # Preserve the old management ACL in a separate list before editing the
    # routing-client list. Existing enable/disable-routing scripts keep working.
    for name,target in migrations.items():
        for row in change['before']:
            if row['list']==name:
                router.call('ip/firewall/address-list','PUT',payload(row,target))
        if not any(row['list']==name for row in change['before']):
            router.call('ip/firewall/address-list','PUT',{'list':target,'address':'0.0.0.0','comment':panel.MARKER,'disabled':True})
    for binding in change['bindings']:
        if binding['list'] in migrations:
            router.call(binding['path']+'/'+rr.rid(binding['id']),'PATCH',{'src-address-list':migrations[binding['list']]})
    for row in desired:
        if row['id'] not in before:
            router.call('ip/firewall/address-list','PUT',payload(row))
    for row in sorted(desired,key=lambda r:not r['enabled']):
        if row['id'] in before:
            router.call('ip/firewall/address-list/'+rr.rid(row['id']),'PATCH',payload(row))
    wanted={row['id'] for row in desired}
    for ident,row in before.items():
        if ident not in wanted:
            router.call('ip/firewall/address-list/'+rr.rid(ident),'DELETE')
    actual=router.call('ip/firewall/address-list')
    expected=sorted((r['list'],r['address'],r['label'],r['enabled']) for r in desired)
    observed=sorted((r['list'],r['address'],r.get('comment',''),not rr.yes(r.get('disabled'))) for r in actual
                    if r['list'] in change['lists'] and panel.editable(r))
    if observed!=expected:raise RuntimeError('RouterOS не подтвердил итоговый список клиентов')
    import client_policy
    client_policy.apply(router,desired,change['state'])
    import dhcp_leases
    dhcp_leases.apply(router,change.get('dhcp_static',[]),report)
    dhcp_leases.apply_actions(router,change.get('dhcp_actions',[]),report)


def restore(router, change):
    import dhcp_leases
    dhcp_leases.restore_actions(router,change.get('dhcp_actions',[]))
    dhcp_leases.restore(router,change.get('dhcp_static',[]))
    if 'policy_before' in change:
        import client_policy
        client_policy.restore(router,change['policy_before'])
    current=router.call('ip/firewall/address-list');by_id={row['.id']:row for row in current}
    original={row['.id']:row for row in change['before'] if panel.editable(row)}
    for ident,row in sorted(original.items(),key=lambda item:rr.yes(item[1].get('disabled'))):
        if ident in by_id:router.call('ip/firewall/address-list/'+rr.rid(ident),'PATCH',payload(row))
        else:router.call('ip/firewall/address-list','PUT',payload(row))
    for binding in change['bindings']:
        if binding['list'] in change['migrations']:
            router.call(binding['path']+'/'+rr.rid(binding['id']),'PATCH',{'src-address-list':binding['list']})
    new_rows={tuple(payload(row).get(key) for key in ('list','address','comment','disabled')) for row in change['desired'] if row['id'] not in original}
    for row in current:
        signature=tuple(payload(row).get(key) for key in ('list','address','comment','disabled'))
        if row['list'] in change['migrations'].values() or (row['.id'] not in original and signature in new_rows):
            router.call('ip/firewall/address-list/'+rr.rid(row['.id']),'DELETE')
