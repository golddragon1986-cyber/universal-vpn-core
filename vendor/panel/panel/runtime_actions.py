"""Immediate runtime maintenance; never compile or apply a configuration draft."""
import json
import os
import signal
import time
from urllib.request import Request, urlopen

ACTIONS = {'dns_flush', 'core_restart'}


def api(path, method='GET'):
    request = Request('http://127.0.0.1:9090' + path,
                      data=b'' if method == 'POST' else None, method=method)
    with urlopen(request, timeout=5) as response:
        raw = response.read()
    return json.loads(raw) if raw else None


def flush_dns(report=lambda _: None):
    errors = []
    report('Очистка DNS-кеша контейнера')
    try:
        api('/cache/dns/flush', 'POST')
    except Exception as error:
        errors.append('Контейнер: ' + str(error))
    report('Очистка DNS-кеша RouterOS')
    try:
        import router_routes
        if not router_routes.configured():
            raise RuntimeError('доступ к RouterOS не настроен')
        router_routes.Router().call('ip/dns/cache/flush', 'POST', {})
    except Exception as error:
        errors.append('RouterOS: ' + str(error))
    if errors:
        raise RuntimeError('Не удалось полностью очистить DNS-кеш. ' + '; '.join(errors))
    return 'Очищены DNS-кеши контейнера и RouterOS.'


def restart_mihomo(report):
    from component_binary import core_state
    from routing_panel import global_info, read_settings, set_global_proxy
    previous = core_state()
    try:
        selected = global_info()['now']
    except (OSError, ValueError, KeyError):
        selected = read_settings()['main_proxy']
    report('Перезапуск Mihomo с действующей конфигурацией')
    os.kill(previous['pid'], signal.SIGHUP)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            state = core_state()
            if (state['generation'] > previous['generation']
                    and state.get('child') != previous.get('child')):
                api('/version')
                set_global_proxy(selected)
                return
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(.2)
    raise RuntimeError('Mihomo не подтвердил запуск в течение 30 секунд')


def restart_clients(report=lambda _: None):
    import vpn_clients
    import sing_box_update
    restarted, errors = [], []
    with vpn_clients.LOCK:
        # The supervisor identity checks prevent signalling an unrelated process.
        try:
            state = sing_box_update.supervisor()
        except (OSError, ValueError):
            state = None
        if state and not state.get('idle'):
            report('Перезапуск sing-box с действующей конфигурацией')
            try:
                os.kill(state['pid'], signal.SIGHUP)
                deadline = time.monotonic() + 40
                while time.monotonic() < deadline:
                    try:
                        current = sing_box_update.supervisor()
                    except (OSError,ValueError,KeyError):
                        time.sleep(.2)
                        continue
                    if current['generation'] > state['generation']:
                        if current.get('failed'):
                            raise RuntimeError('sing-box не прошёл стартовую проверку')
                        if current.get('ready'):
                            restarted.append('sing-box')
                            break
                    time.sleep(.2)
                else:
                    raise RuntimeError('sing-box не подтвердил запуск в течение 40 секунд')
            except Exception as error:
                errors.append('sing-box: ' + str(error))
        process = vpn_clients.PROCESSES.get('xray')
        if process and process[0].poll() is None:
            report('Перезапуск Xray с действующей конфигурацией')
            try:
                vpn_clients.ensure_runtime('xray', force=True, restart=True)
                restarted.append('Xray')
            except Exception as error:
                errors.append('Xray: ' + str(error))
        try:
            restart_mihomo(report)
            restarted.append('Mihomo')
        except Exception as error:
            errors.append('Mihomo: ' + str(error))
    if errors:
        raise RuntimeError('Перезапущены: ' + (', '.join(restarted) or 'нет') + '. Ошибки: ' + '; '.join(errors))
    return 'Перезапущены: ' + ', '.join(restarted) + '. Конфигурация не пересобиралась.'


def execute(action, report=lambda _: None):
    if action == 'dns_flush':
        return flush_dns(report)
    if action == 'core_restart':
        return restart_clients(report)
    raise ValueError('Неизвестная служебная команда')
