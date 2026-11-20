#!/bin/sh
set -eu

repo=/usr/local/share/universal-vpn-apk
ready=/lib/apk/db/.universal-vpn-initialized

if [ ! -f "$ready" ]; then
    echo 'Registering the bundled Alpine ARM64 packages'
    # The signed local repository keeps the package names in world unpinned.
    # Later apk commands use the normal Alpine repositories from /etc/apk.
    set -- $(cat "$repo/world")
    apk --no-network --no-cache --repositories-file /dev/null \
        --repository "$repo" add --initdb "$@"
    for package in "$@"; do
        apk info -e "$package" >/dev/null
    done
    touch "$ready"
    echo 'Alpine ARM64 package database ready'
fi

exec /bin/sh /usr/local/lib/mihomo-panel/entrypoint.sh
