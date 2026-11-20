{
:local tag "uvpn-main: routing"
/ip firewall nat remove [find where comment=$tag]
/ip firewall filter remove [find where comment=$tag]
/ip route remove [find where comment=$tag]
:if ([:len [/routing table find where name="uvpn-main-direct"]] = 1) do={
    :foreach id in=[/ip route find where gateway="172.31.41.2" and comment="universal-vpn: service"] do={ /ip route remove $id }
    :foreach id in=[/routing rule find where table="uvpn-main-direct" and comment="universal-vpn: service return path"] do={ /routing rule remove $id }
}
:put "Routing rules removed. Refresh client DNS caches and connections."
}
