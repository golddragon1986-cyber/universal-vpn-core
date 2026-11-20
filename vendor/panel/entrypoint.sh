#!/bin/sh
set -eu
umask 077
PACKAGE=/usr/local/lib/mihomo-panel
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
export PYTHONDONTWRITEBYTECODE=1
if [ -f "$PACKAGE/official-container" ]; then
    export MIHOMO_REALITY_COMPAT=1
fi
python3 "$PACKAGE/initialize.py"
acl=nft
if [ -f "$PACKAGE/management-acl-mode" ]; then
    acl=$(cat "$PACKAGE/management-acl-mode")
fi
case "$acl" in
    nft) /bin/sh /etc/mihomo/rules/management-firewall.sh ;;
    routeros) echo 'Management ACL is enforced by RouterOS (explicit installer mode)' ;;
    *) echo 'Unknown management ACL mode' >&2; exit 1 ;;
esac
python3 /etc/mihomo/rules/boot_config.py
if [ -f /etc/mihomo/rules/transparent-tcp.json ]; then
    python3 /etc/mihomo/rules/transparent_tcp.py || echo 'Transparent TCP setup failed; retaining TUN fallback'
fi
export MIHOMO_BOOT_PREPARED=1
client_pid=
if [ -x /usr/local/bin/sing-box ] && [ -f /etc/mihomo/clients/sing-box.json ]; then
    /usr/local/bin/sing-box check -c /etc/mihomo/clients/sing-box.json
    GOMEMLIMIT=60MiB GOGC=50 python3 -u /etc/mihomo/rules/sing_box_supervisor.py /usr/local/bin/sing-box /etc/mihomo/clients/sing-box.json &
    client_pid=$!
fi
python3 -u /etc/mihomo/rules/manage_ru_blocked.py &
panel_pid=$!
GOMEMLIMIT=80MiB /bin/sh /etc/mihomo/rules/core-supervisor.sh mihomo -d /etc/mihomo -f /etc/mihomo/default_config.yaml &
core_pid=$!
stop() {
    trap '' TERM INT
    kill -TERM "$panel_pid" "$core_pid" 2>/dev/null || true
    [ -z "$client_pid" ] || kill -TERM "$client_pid" 2>/dev/null || true
    wait "$core_pid" 2>/dev/null || true
    wait "$panel_pid" 2>/dev/null || true
    [ -z "$client_pid" ] || wait "$client_pid" 2>/dev/null || true
}
trap 'stop; exit 143' TERM INT
# Exit the container if either component dies; RouterOS/Docker can then restart it.
while kill -0 "$panel_pid" 2>/dev/null && kill -0 "$core_pid" 2>/dev/null; do
    if [ -n "$client_pid" ] && ! kill -0 "$client_pid" 2>/dev/null; then
        echo 'Configured sing-box client exited' >&2
        break
    fi
    # A zombie panel must also trigger a restart rather than appearing healthy.
    case "$(awk '{print $3}' /proc/"$panel_pid"/stat 2>/dev/null || true)" in Z|'') break ;; esac
    case "$(awk '{print $3}' /proc/"$core_pid"/stat 2>/dev/null || true)" in Z|'') break ;; esac
    sleep 2
done
stop
exit 1
