#!/bin/sh
# Fresh distribution: restrict DNS and management; never replace Mihomo's own tables.
set -eu

command -v nft >/dev/null 2>&1 || {
    echo "ERROR: nft is required to protect the management listeners" >&2
    exit 1
}

# A single nft transaction replaces only our table, without an unprotected gap.
{
    if nft list table inet mihomo_management >/dev/null 2>&1; then
        printf '%s\n' 'delete table inet mihomo_management'
    fi
    cat <<'NFT'
table inet mihomo_management {
    chain input {
        type filter hook input priority -10; policy accept;
        tcp dport { 53, 1080, 9090, 9091 } jump management_access
        udp dport 53 jump management_access
    }
    chain management_access {
        iifname "lo" counter accept comment "Internal management clients"
        ip saddr { 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/16 } counter accept comment "Allowed IPv4 LANs"
        counter drop comment "Deny all other IPv4 and IPv6 management access"
    }
}
NFT
} | nft -f -

echo "Management and DNS ACL ready: IPv4 LANs only; loopback allowed"
