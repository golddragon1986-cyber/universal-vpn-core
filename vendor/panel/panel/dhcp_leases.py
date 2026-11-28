"""Read RouterOS DHCP leases and validate staged client pinning."""
import ipaddress
import json
import router_routes as rr

PATH = 'ip/dhcp-server/lease'


def _ipv4(value):
    try:
        return str(ipaddress.IPv4Address(str(value)))
    except ipaddress.AddressValueError:
        return ''


def model(row):
    status = row.get('status', '')
    active = _ipv4(row.get('active-address', '')) if status == 'bound' else ''
    return {
        'id': row.get('.id', ''),
        'ip': active or _ipv4(row.get('address', '')),
        'active_ip': active,
        'mac': row.get('active-mac-address') or row.get('mac-address', ''),
        'client_id': row.get('active-client-id') or row.get('client-id', ''),
        'host': row.get('host-name', ''),
        'comment': row.get('comment', ''),
        'server': row.get('active-server') or row.get('server', ''),
        'status': status,
        'dynamic': rr.yes(row.get('dynamic')),
        'disabled': rr.yes(row.get('disabled')),
        'last_seen': row.get('last-seen', ''),
        'expires_after': row.get('expires-after', ''),
    }


def snapshot(router=None):
    router = router or rr.Router()
    rows = [model(row) for row in router.call(PATH)]
    rows.sort(key=lambda row: (row['server'], row['host'].lower(), row['ip'], row['id']))
    return {'ok': True, 'leases': rows}


def _identity(row):
    return tuple(row.get(key, '') for key in ('ip', 'mac', 'server'))


def owner_key(row):
    """Stable lease identity across make-static, scoped to its assigned address."""
    address = row.get('active_ip') or row.get('ip', '')
    mac = str(row.get('mac', '')).upper()
    if not address or not mac:
        return ''
    return json.dumps([row.get('server', ''), mac, row.get('client_id', ''), address],
                      ensure_ascii=False, separators=(',', ':'))


def plan(requests, desired, router):
    if not isinstance(requests, list) or len(requests) > 64:
        raise ValueError('Допустимо закрепить до 64 DHCP-аренд за одно применение')
    if not requests:
        return []
    current = {row['id']: row for row in snapshot(router)['leases']}
    by_id = {row['id']: row for row in desired}
    seen = set()
    validated = []
    for request in requests:
        if not isinstance(request, dict) or not all(isinstance(request.get(key), str)
                for key in ('id', 'ip', 'mac', 'server', 'client_id', 'client_row_id')):
            raise ValueError('Некорректный запрос закрепления DHCP-аренды')
        rr.rid(request['id'])
        if request['id'] in seen:
            raise ValueError('DHCP-аренда указана дважды')
        seen.add(request['id'])
        observed = current.get(request['id'])
        if (not observed or not observed['dynamic'] or observed['disabled']
                or observed['status'] != 'bound' or not observed['active_ip']
                or _identity(observed) != _identity(request)):
            raise ValueError('DHCP-аренда изменилась. Обновите список клиентов и черновик.')
        client = by_id.get(request['client_row_id'])
        if request['client_row_id'] and (not client or not client['enabled'] or client['address'] != observed['active_ip']
                or client.get('dhcp_owner', '') not in ('', owner_key(observed))):
            raise ValueError('Закрепляемая DHCP-аренда не связана с активным правилом клиента')
        validated.append(observed)
    return validated


def apply(router, requests, report=lambda _: None):
    if not requests:
        return
    report('Закрепление DHCP-аренд клиентов RouterOS')
    for request in requests:
        observed = {row['id']: row for row in snapshot(router)['leases']}.get(request['id'])
        if not observed or not observed['dynamic'] or _identity(observed) != _identity(request):
            raise ValueError('DHCP-аренда изменилась во время применения конфигурации')
        router.call(PATH + '/make-static', 'POST', {'numbers': request['id']})
        updated = [row for row in snapshot(router)['leases'] if not row['dynamic']
                   and _identity(row) == _identity(request)]
        if len(updated) != 1:
            raise RuntimeError('RouterOS не подтвердил закрепление DHCP-аренды')
        lease = updated[0]
        comment = 'uvpn-main: dhcp-pin'
        if lease['comment']:
            comment += ' | ' + lease['comment']
        router.call(PATH + '/' + rr.rid(lease['id']), 'PATCH', {'comment': comment})
        if _match(router, request).get('comment') != comment:
            raise RuntimeError('RouterOS не подтвердил метку закрепления DHCP-аренды')


def restore(router, requests):
    if not requests:
        return
    current = snapshot(router)['leases']
    for request in requests:
        matches = [row for row in current if not row['dynamic'] and _identity(row) == _identity(request)]
        if len(matches) == 1:
            router.call(PATH + '/' + rr.rid(matches[0]['id']), 'DELETE')


WRITABLE = {'address', 'address-list', 'agent-circuit-id', 'agent-remote-id',
            'allow-dual-stack-queue', 'always-broadcast', 'block-access',
            'client-id', 'comment', 'dhcp-option', 'dhcp-option-set', 'disabled',
            'insert-queue-before', 'lease-time', 'mac-address', 'parent-queue',
            'queue-type', 'rate-limit', 'routes', 'server', 'use-src-mac'}


def plan_actions(requests, pins, router):
    if not isinstance(requests, list) or len(requests) > 64:
        raise ValueError('Некорректный список действий DHCP')
    if not requests:
        return []
    raw = {row['.id']: row for row in router.call(PATH)}
    pinned = {row['id'] for row in pins}
    seen = set()
    result = []
    for request in requests:
        if not isinstance(request, dict) or not all(isinstance(request.get(key), str)
                for key in ('id', 'ip', 'mac', 'server', 'client_id', 'action')):
            raise ValueError('Некорректное действие DHCP')
        ident = rr.rid(request['id'])
        action = request['action']
        if ident in seen or action not in {'enable', 'disable', 'unpin'}:
            raise ValueError('Некорректное действие DHCP')
        seen.add(ident)
        before = raw.get(ident)
        if not before or _identity(model(before)) != _identity(request):
            raise ValueError('DHCP-аренда изменилась. Обновите список клиентов и черновик.')
        if rr.yes(before.get('dynamic')) and (action == 'unpin' or ident not in pinned):
            raise ValueError('Сначала закрепите динамическую DHCP-аренду')
        result.append({'action': action, 'before': before, 'identity': model(before)})
    return result


def _match(router, identity):
    matches = [row for row in router.call(PATH) if _identity(model(row)) == _identity(identity)]
    if len(matches) != 1:
        raise RuntimeError('Не найден единственный DHCP-клиент для изменения')
    return matches[0]


def apply_actions(router, actions, report=lambda _: None):
    if not actions:
        return
    report('Управление DHCP-арендами RouterOS')
    for item in actions:
        row = _match(router, item['identity'])
        if rr.yes(row.get('dynamic')):
            raise RuntimeError('DHCP-аренда не закреплена')
        action = item['action']
        if action in {'enable', 'disable'}:
            router.call(PATH + '/' + rr.rid(row['.id']), 'PATCH', {'disabled': action == 'disable'})
            if rr.yes(_match(router, item['identity']).get('disabled')) != (action == 'disable'):
                raise RuntimeError('RouterOS не подтвердил состояние DHCP-аренды')
        else:
            router.call(PATH + '/' + rr.rid(row['.id']), 'DELETE')
            if any(_identity(model(row)) == _identity(item['identity']) and not rr.yes(row.get('dynamic'))
                   for row in router.call(PATH)):
                raise RuntimeError('RouterOS не подтвердил удаление DHCP-аренды')


def restore_actions(router, actions):
    for item in reversed(actions):
        before = item['before']
        matches = [row for row in router.call(PATH)
                   if _identity(model(row)) == _identity(item['identity'])]
        if len(matches) > 1:
            raise RuntimeError('Не найден единственный DHCP-клиент для восстановления')
        row = matches[0] if matches else None
        if item['action'] in {'enable', 'disable'}:
            if row and not rr.yes(row.get('dynamic')):
                router.call(PATH + '/' + rr.rid(row['.id']), 'PATCH',
                            {'disabled': rr.yes(before.get('disabled'))})
        elif row and rr.yes(row.get('dynamic')):
            router.call(PATH + '/make-static', 'POST', {'numbers': row['.id']})
            restored = _match(router, item['identity'])
            data = {key: value for key, value in before.items() if key in WRITABLE and value != ''}
            router.call(PATH + '/' + rr.rid(restored['.id']), 'PATCH', data)
        elif not row:
            data = {key: value for key, value in before.items() if key in WRITABLE and value != ''}
            router.call(PATH, 'PUT', data)
