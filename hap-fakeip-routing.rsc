# Fake IP route; direct internet and IPsec routes remain intact.
/ip route add dst-address=198.18.0.0/16 gateway=172.31.41.2 comment="Universal VPN Fake IP"
/ip firewall filter add chain=forward action=accept src-address=192.168.99.0/24 dst-address=198.18.0.0/16 out-interface=container-universal place-before=0 comment="Universal VPN Fake IP bypass FastTrack"
/ip firewall filter add chain=forward action=accept src-address=198.18.0.0/16 dst-address=192.168.99.0/24 in-interface=container-universal place-before=0 comment="Universal VPN Fake IP return bypass FastTrack"
# Limit DNS interception to trusted client networks; container upstream is excluded.
/ip firewall nat add chain=dstnat action=dst-nat src-address-list=universal-vpn-access protocol=udp dst-port=53,5353,1253 to-addresses=172.31.41.2 to-ports=53 place-before=0 comment="Universal VPN client DNS UDP"
/ip firewall nat add chain=dstnat action=dst-nat src-address-list=universal-vpn-access protocol=tcp dst-port=53,5353,1253 to-addresses=172.31.41.2 to-ports=53 place-before=0 comment="Universal VPN client DNS TCP"
/ip firewall nat disable [find where chain=dstnat action=redirect]
/ip firewall filter add chain=input action=drop in-interface-list=WAN ipsec-policy=in,none protocol=udp dst-port=53,5353,1253 place-before=0 comment="Universal VPN deny public DNS UDP"
/ip firewall filter add chain=input action=drop in-interface-list=WAN ipsec-policy=in,none protocol=tcp dst-port=53,5353,1253 place-before=0 comment="Universal VPN deny public DNS TCP"
/ip dhcp-client set [find where interface=ether1] use-peer-dns=no
/interface lte apn set [find where name=default] use-peer-dns=no
/ip dns set servers=172.31.41.2 allow-remote-requests=yes
/ip dhcp-server network set [find where address=192.168.99.0/24] dns-server=192.168.99.1
/ip dns cache flush
