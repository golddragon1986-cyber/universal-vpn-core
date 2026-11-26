"""Read RouterOS DHCP leases and validate staged client pinning."""
import ipaddress
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
    return tuple(row.get(key, '') for key in ('ip', 'mac', 'server', 'client_id'))


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
        if not client or not client['enabled'] or client['address'] != observed['active_ip']:
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


def restore(router, requests):
    if not requests:
        return
    current = snapshot(router)['leases']
    for request in requests:
        matches = [row for row in current if not row['dynamic'] and _identity(row) == _identity(request)]
        if len(matches) == 1:
            router.call(PATH + '/' + rr.rid(matches[0]['id']), 'DELETE')
