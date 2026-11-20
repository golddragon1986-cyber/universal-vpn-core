:local tag "uvpn-int: routing"
/ip firewall nat remove [find where comment=$tag]
/ip firewall filter remove [find where comment=$tag]
/ip route remove [find where comment=$tag]
:put "Routing rules removed. Refresh client DNS caches and connections."
