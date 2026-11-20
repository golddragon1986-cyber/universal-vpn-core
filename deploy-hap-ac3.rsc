# hAP ac3 isolated VPN instance; client routing is unchanged.
:if ([:len [/container find where name="universal-vpn-core"]] > 0) do={ :error "Instance already exists" }
/interface bridge add name=container-universal comment="Universal VPN container"
/ip address add address=172.31.41.1/24 interface=container-universal comment="Universal VPN container"
/interface veth add name=veth-universal address=172.31.41.2/24 gateway=172.31.41.1
/interface bridge port add bridge=container-universal interface=veth-universal
/ip firewall address-list add list=universal-vpn-access address=192.168.99.0/24
/ip firewall address-list add list=universal-vpn-access address=192.168.8.0/23
/ip firewall filter add chain=forward action=drop dst-address=172.31.41.2 src-address-list=!universal-vpn-access connection-state=new place-before=0 comment="Universal VPN trusted clients only"
/ip firewall nat add chain=dstnat action=dst-nat dst-address=192.168.99.1 src-address-list=universal-vpn-access protocol=tcp dst-port=19091 to-addresses=172.31.41.2 to-ports=9091 comment="Universal VPN panel"
/ip firewall nat add chain=dstnat action=dst-nat dst-address=192.168.99.1 src-address-list=universal-vpn-access protocol=tcp dst-port=19090 to-addresses=172.31.41.2 to-ports=9090 comment="Universal VPN API"
/ip firewall nat add chain=dstnat action=dst-nat dst-address=192.168.99.1 src-address-list=universal-vpn-access protocol=tcp dst-port=11080 to-addresses=172.31.41.2 to-ports=1080 comment="Universal VPN test proxy"
/container mounts add list=universal-vpn-data src=/usb1-part1/universal-vpn-data dst=/etc/mihomo
/container add name=universal-vpn-core file=usb1-part1/universal-vpn-core-armv7.tar interface=veth-universal root-dir=usb1-part1/containers/universal-vpn-core mountlists=universal-vpn-data dns=1.1.1.1 memory-high=120M memory-max=160M swap-max=256M logging=yes start-on-boot=no restart-policy=no
