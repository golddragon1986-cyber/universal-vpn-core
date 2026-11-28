from urllib.parse import parse_qs
from pathlib import Path

def describe(payload):
 if task:=payload.get("subscription_automation"):
  return "VPN-подписки", ("Автообновление подписки" if task["operation"]=="refresh" else "Обновление состава балансировки")
 if payload["path"]=="/api/backup/restore":return "Настройки и базы","восстановление из резервной копии"
 data=parse_qs(payload["body"])
 def value(k,default=""):return data.get(k,[default])[-1]
 action=value("action")
 if action=="dns_flush":return "DNS Cache","очистка кеша контейнера и RouterOS"
 if action=="core_restart":return "VPN-ядра","перезапуск с действующей конфигурацией"
 if action=="domain_dns":return "Домен «"+value("old")+"»","DNS "+value("dns_mode")
 if action=="client_apply":return "Клиенты контейнера","изменение сетей и адресов источников"
 if action=="route_apply":return "Ручные маршруты","применение набора изменений"
 if action=="dns_save":return "DNS-сервер","обновление адресов DNS"
 if action.startswith("subscription_"):
  if action=="subscription_edit":return "VPN-подписки", "Изменение настроек подписки"
  return "VPN-подписки", {"subscription_add":"Добавление подписки","subscription_refresh":"Обновление подписки","subscription_info_refresh":"Обновление данных подписки","subscription_delete":"Удаление подписки","subscription_automation":"Настройки автобалансировки"}[action]
 if action=="vpn_client":return "VPN «"+value('name')+"»","выбор клиента "+value('client')
 if action=="vpn_edit":return "VPN «"+value('name')+"»","параметры соединения обновлены (секреты скрыты)"
 if action=='route_toggle':return 'Маршруты RouterOS','включение/отключение маршрута'
 if action=='route_metric':return 'Маршруты RouterOS','метрика '+value('metric')
 if action.startswith('route_'):
  return 'Маршруты RouterOS',('добавление '+value('destination') if action=='route_add' else 'изменение маршрута на '+value('target') if action=='route_target' else 'удаление выбранного маршрута')
 if action=="component_change":
  operation=value('operation')
  description={'install':'установка','remove':'удаление','restart':'перезапуск','update':'обновление','set_version':'установка версии '+value('version_id').partition(':')[2]}.get(operation,operation)
  return "Компонент "+value('component'),description
 if action=="vpn_import":return "VPN-соединения","добавление конфигурации (секреты скрыты)"
 if action=="routing_save":
  import routing_panel
  current=routing_panel.read_settings(routing_panel.global_info().get("now","DIRECT"))
  old=current["main_proxy"];new=value("main_proxy",old)
  parts=[]
  if old!=new:parts.append("изменён с "+old+" на "+new)
  on=value("services_enabled","0")=="1"
  if on!=current["services_enabled"]:parts.append("правила "+("включены" if on else "отключены"))
  return "Основной маршрут","; ".join(parts) or "настройки применены повторно"
 if action.startswith("service_"):
  import service_routes_panel
  items=service_routes_panel.read_services();key=value("service_id")
  old=next((x for x in items if x.get("id")==key or "name:"+str(x.get("name",""))==key),{})
  name=old.get("name") or value("name") or value("catalog_service")
  subject="Правило «"+str(name)+"»" if name else "Правила"
  if action=="service_toggle":return subject,("отключено" if old.get("enabled",True) else "включено")
  if action=="service_set_target":return subject,"группа "+str(old.get("target", ""))+" → "+value("target")
  if action=="service_move":return subject,"перемещение "+("выше" if value("direction")=="up" else "ниже")
  if action=="service_reorder":return "Правила","применение нового порядка"
  if action=="service_delete":return subject,"удалено"
  if action=="service_update_source":return subject,"доменные правила обновлены из GitHub"
  if action=="service_refresh_geodata":return subject,"обновление из GeoDAT"
  if action=="service_catalog_import":return "Правила","загрузка из GitHub: "+", ".join(data.get("catalog_service",[]))+"; маршрут "+value("catalog_target","LOADBALANCE")
  if action=="service_save":
   parts=[]
   if not old:parts.append("добавлено")
   if old.get("name") and old["name"]!=value("name"):parts.append("переименовано в «"+value("name")+"»")
   if old.get("target")!=value("target"):parts.append("маршрут "+(str(old["target"])+" → " if old.get("target") else "")+value("target"))
   parts.append("доменные правила сохранены")
   return subject,"; ".join(parts)
 if action.startswith("proxy_"):
  name=value("name");names=", ".join(data.get("selected",[]))
  if action=="proxy_balance":return "Прокси «"+name+"»",("включён" if value("enabled")=="1" else "отключён")
  if action=="proxy_delete":return "Прокси «"+name+"»","удалён"
  if action=="proxy_delete_selected":return "Прокси","удалены: "+names
  if action=="proxy_enable_selected":return "Прокси","включены: "+names
  if action=="proxy_import":return "Прокси","добавлены из "+("подписки" if value("source").strip().startswith("https://") else "введённого списка")
 if action=="filter_save":
  old=Path("/etc/mihomo/rules/ru-blocked-filters.txt").read_text().strip()
  new=value("filter_expr").strip()
  return "Фильтры доменов",("изменены с «"+(old or "нет")+"» на «"+(new or "нет")+"»") if old!=new else "правила сохранены повторно"
 if action=="refresh":return "Список доменов","обновлён из GitHub"
 if action=="clear_auto_domains":return "Список доменов","автоматически загруженные домены удалены"
 if action=="add":return "Домены","добавлены: "+value("new").replace("\n","; ")
 if action in ("enable","disable","delete"):
  return "Домен «"+value("old")+"»",{"enable":"включён","disable":"отключён","delete":"удалён"}[action]
 return "Настройки","изменения применены"
