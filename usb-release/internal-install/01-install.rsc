# Edit LAN settings only if they differ on this router.
:local lan "LAN"
:local clients "uvpn-int-lan"
:local tag "uvpn-int: base"
:local base "universal-vpn"
:if ([:len [/file find where name="flash"]] > 0) do={ :set base "flash/universal-vpn" }
:local image ($base . "/universal-vpn-core-armv7.tar")
:local root ($base . "/rootfs")
:local data ($base . "/data")
:if ([/system resource get architecture-name] != "arm") do={ :error "ARM RouterOS required" }
:if ([/system device-mode get container] != true) do={ :error "Enable container device-mode first" }
:if ([:len [/file find where name=$image]] != 1) do={ :error "Image missing in internal storage" }
:if ([/system resource get free-hdd-space] < 157286400) do={ :error "Internal storage needs at least 150 MiB free after upload" }
:if ([:len [/interface list find where name=$lan]] != 1 || [:len [/interface list find where name="WAN"]] != 1) do={ :error "LAN and WAN interface lists required" }
:if ([:len [/container find where name="universal-vpn-core"]] > 0 || [:len [/interface find where name="uvpn-int-veth"]] > 0 || [:len [/interface find where name="uvpn-int-br"]] > 0 || [:len [/container mounts find where list="uvpn-int"]] > 0 || [:len [/container envs find where list="uvpn-int"]] > 0 || [:len [/file find where name=$root]] > 0 || [:len [/file find where name=$data]] > 0 || [:len [/ip route find where dst-address="172.31.41.0/24"]] > 0) do={ :error "Existing install, files or subnet conflict" }
:if ([:len [/ip firewall filter find where comment=$tag]] > 0 || [:len [/ip firewall nat find where comment=$tag]] > 0 || [:len [/ip address find where comment=$tag]] > 0) do={ :error "Existing internal installer rules or address" }
:if ([:len [/ip firewall address-list find where list=$clients]] > 0) do={ :error "Existing client address list" }
# Read independent upstream DNS before creating the container.
:local blockedDns ",0.0.0.0,172.31.41.1,172.31.41.2,"
:foreach id in=[/ip address find] do={
    :local address [:tostr [/ip address get $id address]]
    :set blockedDns ($blockedDns . [:pick $address 0 [:find $address "/"]] . ",")
}
:local safeDns do={
    :local ip [:toip $value]
    :if ([:typeof $ip] != "ip") do={ :return false }
    :if ([:pick [:tostr $ip] 0 4] = "127." || $ip in 198.18.0.0/16) do={ :return false }
    :if ([:typeof [:find $blocked ("," . [:tostr $ip] . ",")]] != "nil") do={ :return false }
    :return true
}
:local routerDnsPrimary ""
:foreach kind in={"servers";"dynamic-servers"} do={
    :foreach address in=[/ip dns get $kind] do={
        :local value [:tostr $address]
        :if ([$safeDns value=$value blocked=$blockedDns] = true) do={
            :if ([:typeof [:find ("," . $routerDnsPrimary . ",") ("," . $value . ",")]] = "nil") do={
                :if ([:len $routerDnsPrimary] > 0) do={ :set routerDnsPrimary ($routerDnsPrimary . ",") }
                :set routerDnsPrimary ($routerDnsPrimary . $value)
            }
        }
    }
}
:if ([:len $routerDnsPrimary] = 0) do={ :error "No independent upstream DNS in RouterOS; configure a DNS server outside this router and container" }
:local routerDnsMain [/ip dns get use-doh-server]
:if ([:len $routerDnsMain] > 0) do={
    :local end [:find $routerDnsMain "/" 8]
    :if ([:typeof $end] = "nil") do={ :set end [:len $routerDnsMain] }
    :local host [:pick $routerDnsMain 8 $end]
    :local port [:find $host ":"]
    :if ([:typeof $port] != "nil") do={ :set host [:pick $host 0 $port] }
    :if ([:typeof [:toip $host]] = "ip") do={
        :if ([$safeDns value=$host blocked=$blockedDns] != true) do={ :set routerDnsMain "" }
    } else={
        :if ($host = "localhost" || [:pick $host 0 1] = "[") do={ :set routerDnsMain "" } else={
            :foreach server in=[:toarray $routerDnsPrimary] do={
                :do {
                    :local resolved [:resolve domain-name=$host server=$server type=ipv4]
                    :if ([$safeDns value=$resolved blocked=$blockedDns] != true) do={ :set routerDnsMain "" }
                } on-error={}
            }
        }
    }
}
:if ([:len $routerDnsMain] = 0) do={ :set routerDnsMain $routerDnsPrimary }

:local firstFilter [:pick [/ip firewall filter find where dynamic=no] 0]
:local firstNat [:pick [/ip firewall nat find where dynamic=no] 0]
:onerror installError in={
    /ip firewall address-list add list=$clients address=10.0.0.0/8 comment=$tag
    /ip firewall address-list add list=$clients address=172.16.0.0/12 comment=$tag
    /ip firewall address-list add list=$clients address=192.168.0.0/16 comment=$tag
    /interface veth add name=uvpn-int-veth address=172.31.41.2/24 gateway=172.31.41.1
    /interface bridge add name=uvpn-int-br protocol-mode=none comment=$tag
    /interface bridge port add bridge=uvpn-int-br interface=uvpn-int-veth
    /ip address add address=172.31.41.1/24 interface=uvpn-int-br comment=$tag
    /ip firewall filter add chain=forward dst-address=172.31.41.2 action=jump jump-target=uvpn-int-in comment=$tag
    :if ([:typeof $firstFilter] = "id") do={ /ip firewall filter move [find where comment=$tag and chain=forward] destination=$firstFilter }
    /ip firewall filter add chain=uvpn-int-in connection-state=established,related action=accept comment=$tag
    /ip firewall filter add chain=uvpn-int-in in-interface-list=$lan src-address-list=$clients protocol=tcp dst-port=9091,9090,1080 action=accept comment=$tag
    /ip firewall filter add chain=uvpn-int-in in-interface-list=$lan src-address-list=$clients protocol=udp dst-port=53 action=accept comment=$tag
    /ip firewall filter add chain=uvpn-int-in in-interface-list=$lan src-address-list=$clients protocol=tcp dst-port=53 action=accept comment=$tag
    /ip firewall filter add chain=uvpn-int-in action=drop comment=$tag
    /ip firewall nat add chain=srcnat src-address=172.31.41.2 out-interface-list=WAN ipsec-policy=out,none action=masquerade comment=$tag
    :if ([:typeof $firstNat] = "id") do={ /ip firewall nat move [find where comment=$tag] destination=$firstNat }
    /container envs add list=uvpn-int key=UVPNC_PRIMARY_DNS value=$routerDnsPrimary
    /container envs add list=uvpn-int key=UVPNC_MAIN_DNS value=$routerDnsMain
    /container envs add list=uvpn-int key=MIHOMO_PANEL_TUN value=1
    /container envs add list=uvpn-int key=MIHOMO_PANEL_TUN_AUTO_REDIRECT value=0
    /container mounts add list=uvpn-int src=("/" . $data) dst=/etc/mihomo
    /container add name=universal-vpn-core file=$image interface=uvpn-int-veth root-dir=$root mountlists=uvpn-int envlist=uvpn-int dns=$routerDnsPrimary memory-high=160M memory-max=200M logging=yes start-on-boot=no
} do={
    :if ([:len [/container find where name="universal-vpn-core"]] = 0) do={
        /container mounts remove [find where list="uvpn-int"]
        /container envs remove [find where list="uvpn-int"]
        :foreach id in=[/ip firewall address-list find where list=$clients and comment=$tag] do={ /ip firewall address-list remove $id }
        /ip firewall nat remove [find where comment=$tag]
        /ip firewall filter remove [find where comment=$tag]
        /ip address remove [find where comment=$tag]
        /interface bridge port remove [find where bridge="uvpn-int-br" and interface="uvpn-int-veth"]
        /interface bridge remove [find where name="uvpn-int-br"]
        /interface veth remove [find where name="uvpn-int-veth"]
    }
    :error ("internal installation failed: " . $installError)
}
:put "Wait for extraction (status stopped), then start the container."
