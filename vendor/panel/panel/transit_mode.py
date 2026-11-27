"""RouterOS NAT return path for traffic routed through the container TUN."""
import re


def with_group(text):
    """Upgrade old on-disk templates without replacing user configuration."""
    if '  - name: TRANSIT\n' not in text:
        group = ('  - name: TRANSIT\n    type: select\n    proxies:\n'
                 '      - DIRECT\n')
        marker = '  # BEGIN SERVICE-CHANNEL-GROUPS\n'
        if marker not in text:
            raise ValueError('В конфигурации отсутствует раздел групп маршрутов')
        text = text.replace(marker, group + marker, 1)
    selector = re.search(r'(?ms)^  - name: SELECTOR\n.*?(?=^  - name:|^rules:|\Z)', text)
    if selector is None:
        raise ValueError('В конфигурации отсутствует основной маршрут SELECTOR')
    block = selector.group()
    if '      - TRANSIT\n' not in block:
        block = block.replace('      - LOADBALANCE\n',
                              '      - LOADBALANCE\n      - TRANSIT\n', 1)
        if '      - TRANSIT\n' not in block:
            raise ValueError('SELECTOR не содержит LOADBALANCE')
        text = text[:selector.start()] + block + text[selector.end():]
    return text


def with_sniffer(text):
    begin = '# BEGIN TRANSIT SNIFFER\n'
    end = '# END TRANSIT SNIFFER\n'
    text = re.sub(r'(?ms)^# BEGIN TRANSIT SNIFFER\n.*?^# END TRANSIT SNIFFER\n', '', text)
    if not sniffer_active(): return text
    if re.search(r'(?m)^sniffer:', text): return text
    block = (begin + 'sniffer:\n  enable: true\n  force-dns-mapping: true\n'
             '  parse-pure-ip: true\n  override-destination: false\n'
             '  sniff:\n    HTTP:\n      ports: [80, 8080-8880]\n'
             '    TLS:\n      ports: [443, 8443]\n'
             '    QUIC:\n      ports: [443, 8443]\n' + end)
    return text.rstrip() + '\n' + block


def with_fallback(text):
    """Captured traffic not matched by a TRANSIT rule follows the main route."""
    text = text.replace('  - MATCH,SELECTOR # TRANSIT-FALLBACK\n',
                        '  - MATCH,DIRECT\n')
    if active():
        text = re.sub(r'(?m)^  - MATCH,DIRECT$',
                      '  - MATCH,SELECTOR # TRANSIT-FALLBACK', text, count=1)
    return text


def active():
    from routing_panel import read_settings
    settings = read_settings()
    if settings['main_proxy'] == 'TRANSIT': return True
    if not settings['services_enabled']: return False
    from service_routes_panel import read_services
    return any(row.get('enabled', True) and row.get('target') == 'TRANSIT'
               for row in read_services())


def sniffer_active():
    if active(): return True
    from client_policy import read
    return any(row.get('enabled', True) and row.get('route') == 'TRANSIT'
               for row in read())
