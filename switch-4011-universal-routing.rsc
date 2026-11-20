/ip firewall filter add chain=forward action=accept dst-address=172.31.41.2 src-address-list=mihomo-internal protocol=udp dst-port=53 place-before=0 comment="Universal VPN internal DNS UDP"
/ip firewall filter add chain=forward action=accept dst-address=172.31.41.2 src-address-list=mihomo-internal protocol=tcp dst-port=53 place-before=0 comment="Universal VPN internal DNS TCP"
/routing rule set [find where comment="4011 Telegram DIRECT return path"] src-address=172.31.41.2/32
/ip route set [find where comment="4011 Telegram static via Mihomo"] gateway=172.31.41.2
/ip route set [find where comment="4011 Mihomo FakeIP static route"] gateway=172.31.41.2
/tool netwatch set [find where comment="4011 Mihomo DNS primary"] dns-server=172.31.41.2 up-script={ :if ([:tostr [/ip dns get servers]] != "172.31.41.2") do={ /ip dns set servers=172.31.41.2; /ip dns cache flush; :log warning "4011 DNS upstream restored to Universal VPN" } }
/ip dns set servers=172.31.41.2
/ip dns cache flush
