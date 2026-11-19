#!/bin/sh
# Retry only the deterministic uTLS randomized-profile failure, not remote outages.
umask 077
run_dir=$(mktemp -d /tmp/mihomo-supervisor.XXXXXX) || exit 1
pipe="$run_dir/output"
mkfifo "$pipe" || exit 1
core_pid=
timer_pid=
route_pid=
reload_until=0
generation=0
reload_core() {
    retry=1
    reload_until=$(($(date +%s) + 90))
    [ -z "$core_pid" ] || kill -TERM "$core_pid" 2>/dev/null
}
stop_core() {
    trap '' TERM INT
    [ -z "$route_pid" ] || kill "$route_pid" 2>/dev/null
    [ -z "$timer_pid" ] || kill "$timer_pid" 2>/dev/null
    if [ -n "$core_pid" ]; then
        kill -TERM "$core_pid" 2>/dev/null
        (sleep 5; kill -KILL "$core_pid" 2>/dev/null) &
        timeout_pid=$!
        wait "$core_pid" 2>/dev/null
        kill "$timeout_pid" 2>/dev/null
        wait "$timeout_pid" 2>/dev/null
    fi
    rm -f "$pipe"
    rmdir "$run_dir"
    exit 143
}
trap stop_core TERM INT
trap reload_core HUP
attempts=0
restarts=0
while :; do
    retry=0
    "$@" > "$pipe" 2>&1 &
    core_pid=$!
    generation=$((generation + 1))
    printf '{"pid":%s,"generation":%s,"child":%s}\n' "$$" "$generation" "$core_pid" > /tmp/mihomo-supervisor.json
    if [ "$restarts" -gt 0 ] && [ "${MIHOMO_SUPERVISOR_RESTORE:-1}" = 1 ]; then
        python3 -u -c 'import sys;sys.path.insert(0,"/etc/mihomo/rules");import boot_config;boot_config.ready()' &
        route_pid=$!
    fi
    while IFS= read -r line; do
        printf '%s\n' "$line"
        case "$line" in
            *"tls: CurvePreferences includes unsupported curve"*)
                if [ "$retry" -eq 0 ]; then
                    retry=1
                    printf '%s\n' "STARTUP RECOVERY: incompatible randomized TLS profile; restarting $1"
                    kill -TERM "$core_pid" 2>/dev/null
                    (sleep 5; kill -KILL "$core_pid" 2>/dev/null) &
                    timer_pid=$!
                fi
                ;;
        esac
    done < "$pipe"
    wait "$core_pid"
    status=$?
    core_pid=
    if [ -n "$timer_pid" ]; then
        kill "$timer_pid" 2>/dev/null
        wait "$timer_pid" 2>/dev/null
        timer_pid=
    fi
    if [ -n "$route_pid" ]; then
        kill "$route_pid" 2>/dev/null
        wait "$route_pid" 2>/dev/null
        route_pid=
    fi
    if [ "$retry" -eq 0 ] && [ "$(date +%s)" -lt "$reload_until" ]; then retry=1; fi
    if [ "$retry" -eq 0 ]; then
        rm -f "$pipe"
        rmdir "$run_dir"
        exit "$status"
    fi
    attempts=$((attempts + 1))
    restarts=$((restarts + 1))
    if [ "$attempts" -ge 8 ]; then
        printf '%s\n' "STARTUP RECOVERY: repeated TLS profile failures; cooling down for 30 seconds"
        sleep 30
        attempts=0
    else
        sleep 1
    fi
done
