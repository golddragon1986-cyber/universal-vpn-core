# Dedicated development instance; existing mihomo-arm32 and client routes are untouched.
:if ([:len [/container find where name="universal-vpn-core"]] > 0) do={ :error "Instance already exists" }
:if ([:len [/interface find where name="container-universal"]] > 0) do={ :error "Network already exists" }
/interface bridge add name=container-universal comment="Universal VPN core development"
/ip address add address=172.31.41.1/24 interface=container-universal comment="Universal VPN core development"
/interface veth add name=veth-universal address=172.31.41.2/24 gateway=172.31.41.1 comment="Universal VPN core development"
/interface bridge port add bridge=container-universal interface=veth-universal
/ip firewall filter add chain=forward action=drop dst-address=172.31.41.2 src-address-list=!mihomo-local-access connection-state=new place-before=0 comment="Universal VPN core trusted clients only"
/ip firewall nat add chain=dstnat action=dst-nat dst-address=10.0.0.3 src-address-list=mihomo-local-access protocol=tcp dst-port=19091 to-addresses=172.31.41.2 to-ports=9091 comment="Universal VPN core panel"
/ip firewall nat add chain=dstnat action=dst-nat dst-address=10.0.0.3 src-address-list=mihomo-local-access protocol=tcp dst-port=19090 to-addresses=172.31.41.2 to-ports=9090 comment="Universal VPN core API"
/ip firewall nat add chain=dstnat action=dst-nat dst-address=10.0.0.3 src-address-list=mihomo-local-access protocol=tcp dst-port=11080 to-addresses=172.31.41.2 to-ports=1080 comment="Universal VPN core test proxy"
/container mounts add list=universal-vpn-data src=/universal-vpn-data dst=/etc/mihomo
/container add name=universal-vpn-core file=universal-vpn-core-armv7.tar interface=veth-universal root-dir=/containers/universal-vpn-core-v2 mountlists=universal-vpn-data dns=1.1.1.1 memory-high=180000000 memory-max=200000000 logging=yes start-on-boot=no restart-policy=no

