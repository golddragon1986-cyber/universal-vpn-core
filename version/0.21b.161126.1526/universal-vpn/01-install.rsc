{
# Set lan only if your trusted interface list has another name.
:local lan "LAN"
:local clients "uvpn-main-lan"
:local tag "uvpn-main: base"
:local arch [/system resource get architecture-name]
:local tarName "universal-vpn-core-armv7.tar"
:local minimum 209715200
:if ($arch = "arm64") do={ :set tarName "universal-vpn-core-arm64.tar"; :set minimum 268435456 } else={
    :if ($arch != "arm") do={ :error "ARM or ARM64 RouterOS required" }
}
:if ([/system device-mode get container] != true) do={ :error "Enable container device-mode first" }
:local internal "universal-vpn"
:if ([:len [/file find where name="flash"]] > 0) do={ :set internal "flash/universal-vpn" }
:local disks [/disk find where mount-filesystem=yes]
:local image ""
:local sourceBase ""
:local sourceDisk ""
:local hits 0
:local found ""
:local fallback ""
:local fallbackCount 0
:if ([:len [/file find where name=($internal . "/" . $tarName)]] = 1) do={
    :set sourceBase $internal
    :set hits 1
    :set found ($internal . "/" . $tarName)
}
:foreach disk in=$disks do={
    :local mount [/disk get $disk mount-point]
    :if ([:len $mount] > 0 && $mount != "flash") do={
        :local candidate ($mount . "/universal-vpn")
        :if ([:len [/file find where name=($candidate . "/" . $tarName)]] = 1) do={
            :set sourceBase $candidate
            :set sourceDisk $disk
            :set hits ($hits + 1)
            :set found ($found . " " . $candidate . "/" . $tarName)
        }
        :if ([/disk get $disk fs] = "ext4" && [/disk get $disk mount-read-only] = false && [/disk get $disk free] >= $minimum) do={
            :set fallback $candidate
            :set fallbackCount ($fallbackCount + 1)
        }
    }
}
:if ($hits = 0) do={ :error ("Image not found for RouterOS architecture " . $arch . ": " . $tarName) }
:if ($hits > 1) do={ :error ("Keep exactly one copy of " . $tarName . ". Found:" . $found) }
:set image ($sourceBase . "/" . $tarName)
:local base $sourceBase
:if ([:typeof $sourceDisk] != "id") do={
    :if ([/system resource get free-hdd-space] < $minimum) do={
        :if ($fallbackCount != 1) do={ :error "Internal storage is low; connect exactly one writable ext4 disk with sufficient free space" }
        :set base $fallback
    }
} else={
    :if ([/disk get $sourceDisk fs] != "ext4" || [/disk get $sourceDisk mount-read-only] = true || [/disk get $sourceDisk free] < $minimum) do={
        :error "Image disk must be writable ext4 with sufficient free space"
    }
}
:local root ($base . "/rootfs")
:local data ($base . "/data")
:local marker ($base . "/universal-vpn.install-marker")
:if ([:len [/file find where name=$marker]] > 0) do={ :error "Installation marker already exists; use 04-uninstall first" }
:if ([:len [/interface list find where name=$lan]] != 1 || [:len [/interface list find where name="WAN"]] != 1) do={ :error "LAN and WAN interface lists required" }
:if ([:len [/container find where name="universal-vpn-core"]] > 0 || [:len [/interface find where name="uvpn-main-veth"]] > 0 || [:len [/interface find where name="uvpn-main-br"]] > 0 || [:len [/container mounts find where list="uvpn-main"]] > 0 || [:len [/container envs find where list="uvpn-main"]] > 0 || [:len [/file find where name=$root]] > 0 || [:len [/file find where name=$data]] > 0 || [:len [/ip route find where dst-address="172.31.41.0/24"]] > 0) do={ :error "Existing install, files or subnet conflict" }
:if ([:len [/ip firewall filter find where comment=$tag]] > 0 || [:len [/ip firewall nat find where comment=$tag]] > 0 || [:len [/ip address find where comment=$tag]] > 0) do={ :error "Existing installer rules or address" }
:if ([:len [/ip firewall address-list find where list=$clients]] > 0) do={ :error "Existing client address list" }
:local firstFilter [:pick [/ip firewall filter find where dynamic=no] 0]
:local firstNat [:pick [/ip firewall nat find where dynamic=no] 0]
:local restService [/ip service find where name="www-ssl"]
:if ([:len $restService] != 1) do={ :error "RouterOS HTTPS service unavailable" }
:if ([/ip service get $restService disabled] = false || [/ip service get $restService port] != 443 || [/ip service get $restService certificate] != "none") do={
    :error "www-ssl is already configured; cannot provision an isolated REST endpoint"
}
:local serviceAddresses ""
:onerror serviceFieldError in={
    :set serviceAddresses [/ip service get $restService "address"]
} do={
    :set serviceAddresses [/ip service get $restService "available-from"]
}
:if ([:len $serviceAddresses] > 0) do={ :error "www-ssl already has address restrictions; cannot provision REST" }
:if ([:len [/user find where name="uvpn-main-panel"]] > 0 || [:len [/user group find where name="uvpn-main-rest"]] > 0 || [:len [/certificate find where name="uvpn-main-ca" or name="uvpn-main-rest"]] > 0 || [:len [/routing table find where name="uvpn-main-direct"]] > 0 || [:len [/file find where name="uvpn-main-ca-export.crt"]] > 0) do={
    :error "REST resources already exist; run 04-uninstall first"
}
:if ([:len [/file find where name=$base]] = 0) do={ /file add name=$base type=directory }
/file add name=$marker type=file
:onerror installError in={
    /ip firewall address-list add list=$clients address=10.0.0.0/8 comment=$tag
    /ip firewall address-list add list=$clients address=172.16.0.0/12 comment=$tag
    /ip firewall address-list add list=$clients address=192.168.0.0/16 comment=$tag
    /interface veth add name=uvpn-main-veth address=172.31.41.2/24 gateway=172.31.41.1
    /interface bridge add name=uvpn-main-br protocol-mode=none comment=$tag
    /interface bridge port add bridge=uvpn-main-br interface=uvpn-main-veth
    /ip address add address=172.31.41.1/24 interface=uvpn-main-br comment=$tag
    /ip firewall filter add chain=forward dst-address=172.31.41.2 action=jump jump-target=uvpn-main-in comment=$tag
    :if ([:typeof $firstFilter] = "id") do={ /ip firewall filter move [find where comment=$tag and chain=forward] destination=$firstFilter }
    /ip firewall filter add chain=uvpn-main-in connection-state=established,related action=accept comment=$tag
    /ip firewall filter add chain=uvpn-main-in in-interface-list=$lan src-address-list=$clients protocol=tcp dst-port=9091,9090,1080 action=accept comment=$tag
    /ip firewall filter add chain=uvpn-main-in in-interface-list=$lan src-address-list=$clients protocol=udp dst-port=53 action=accept comment=$tag
    /ip firewall filter add chain=uvpn-main-in in-interface-list=$lan src-address-list=$clients protocol=tcp dst-port=53 action=accept comment=$tag
    /ip firewall filter add chain=uvpn-main-in action=drop comment=$tag
    /ip firewall nat add chain=srcnat src-address=172.31.41.2 out-interface-list=WAN ipsec-policy=out,none action=masquerade comment=$tag
    :if ([:typeof $firstNat] = "id") do={ /ip firewall nat move [find where comment=$tag] destination=$firstNat }
    /container envs add list=uvpn-main key=MIHOMO_PANEL_TUN value=1
    :if ([/system resource get board-name]~"^RB4011") do={ /container envs add list=uvpn-main key=MIHOMO_PANEL_TUN_AUTO_REDIRECT value=0 }
    /container mounts add list=uvpn-main src=("/" . $data) dst=/etc/mihomo
    :local restPassword [:rndstr length=48 from="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"]
    /certificate add name=uvpn-main-ca common-name=UvpnC-Local-CA key-size=2048 days-valid=3650 key-usage=key-cert-sign,crl-sign
    /certificate sign uvpn-main-ca name=uvpn-main-ca
    # RouterOS publishes signed certificates after the sign command returns.
    :delay 5s
    /certificate add name=uvpn-main-rest common-name=172.31.41.1 subject-alt-name=IP:172.31.41.1 key-size=2048 days-valid=825 key-usage=digital-signature,key-encipherment,tls-server
    /certificate sign uvpn-main-rest ca=uvpn-main-ca name=uvpn-main-rest
    :delay 5s
    /certificate export-certificate uvpn-main-ca type=pem file-name=uvpn-main-ca-export
    :local caFile [/file find where name="uvpn-main-ca-export.crt"]
    :if ([:len $caFile] != 1) do={ :error "REST CA export failed" }
    :local caPem [/file get $caFile contents]
    :if ([:len $caPem] < 100) do={ :error "REST CA export is empty" }
    /file remove $caFile
    /user group add name=uvpn-main-rest policy=read,write,api,rest-api
    /user add name=uvpn-main-panel group=uvpn-main-rest address=172.31.41.2/32 password=$restPassword
    /routing table add name=uvpn-main-direct fib
    /container envs add list=uvpn-main key=MIHOMO_ROUTEROS_REST_PASSWORD value=$restPassword
    /container envs add list=uvpn-main key=MIHOMO_ROUTEROS_REST_CA value=$caPem
    :local firstInput [:pick [/ip firewall filter find where dynamic=no and chain=input] 0]
    :if ([:typeof $firstInput] = "id") do={
        /ip firewall filter add chain=input protocol=tcp dst-port=8443 action=drop comment=$tag place-before=$firstInput
    } else={
        /ip firewall filter add chain=input protocol=tcp dst-port=8443 action=drop comment=$tag
    }
    :local restDrop [:pick [/ip firewall filter find where chain=input and comment=$tag and action=drop] 0]
    /ip firewall filter add chain=input in-interface=uvpn-main-br src-address=172.31.41.2 dst-address=172.31.41.1 protocol=tcp dst-port=8443 action=accept comment=$tag place-before=$restDrop
    /ip service set $restService disabled=no port=8443 certificate=uvpn-main-rest
    /container add name=universal-vpn-core file=$image interface=uvpn-main-veth root-dir=$root mountlists=uvpn-main envlist=uvpn-main dns=1.1.1.1 memory-high=160M memory-max=200M logging=yes start-on-boot=no
} do={
    :if ([:len [/container find where name="universal-vpn-core"]] = 0) do={
        :foreach id in=[/ip service find where name="www-ssl" and certificate="uvpn-main-rest"] do={
            /ip service set $id disabled=yes port=443 certificate=none
        }
        :foreach id in=[/user find where name="uvpn-main-panel" and group="uvpn-main-rest"] do={ /user remove $id }
        :if ([:len [/user find where group="uvpn-main-rest"]] = 0) do={
            :foreach id in=[/user group find where name="uvpn-main-rest"] do={ /user group remove $id }
        }
        :foreach id in=[/certificate find where name="uvpn-main-rest" and common-name="172.31.41.1"] do={ /certificate remove $id }
        :foreach id in=[/certificate find where name="uvpn-main-ca" and common-name="UvpnC-Local-CA"] do={ /certificate remove $id }
        :foreach id in=[/file find where name="uvpn-main-ca-export.crt"] do={ /file remove $id }
        :local bypassTable [/routing table find where name="uvpn-main-direct"]
        :if ([:len $bypassTable] = 1) do={
            :foreach id in=[/routing rule find where table="uvpn-main-direct" and src-address="172.31.41.2/32" and comment="universal-vpn: return path"] do={
                :local destination [/routing rule get $id dst-address]
                :foreach route in=[/ip route find where gateway="172.31.41.2" and dst-address=$destination and comment~"^universal-vpn: "] do={ /ip route remove $route }
                /routing rule remove $id
            }
            :foreach id in=[/ip route find where routing-table="uvpn-main-direct" and comment="uvpn-main: WAN bypass"] do={ /ip route remove $id }
            :if ([:len [/routing rule find where table="uvpn-main-direct"]] = 0 && [:len [/ip route find where routing-table="uvpn-main-direct"]] = 0) do={
                /routing table remove $bypassTable
            }
        }
        :foreach id in=[/container mounts find where list="uvpn-main"] do={ /container mounts remove $id }
        :foreach id in=[/container envs find where list="uvpn-main"] do={ /container envs remove $id }
        :foreach id in=[/ip firewall address-list find where list=$clients and comment=$tag] do={ /ip firewall address-list remove $id }
        :foreach id in=[/ip firewall nat find where comment=$tag] do={ /ip firewall nat remove $id }
        :foreach id in=[/ip firewall filter find where comment=$tag] do={ /ip firewall filter remove $id }
        :foreach id in=[/ip address find where comment=$tag] do={ /ip address remove $id }
        :foreach id in=[/interface bridge port find where bridge="uvpn-main-br" and interface="uvpn-main-veth"] do={ /interface bridge port remove $id }
        :foreach id in=[/interface bridge find where name="uvpn-main-br"] do={ /interface bridge remove $id }
        :foreach id in=[/interface veth find where name="uvpn-main-veth"] do={ /interface veth remove $id }
        :if ([:len [/file find where name=$root or name=$data]] = 0) do={
            :foreach id in=[/file find where name=$marker] do={ /file remove $id }
        }
    }
    :error ("installation failed: " . $installError)
}
:put ("Image: " . $image . ". Storage: " . $base . ". Waiting for container extraction...")
:local deadline ([/system resource get uptime] + 15m)
:local instance [/container find where name="universal-vpn-core" and interface="uvpn-main-veth"]
:if ([:len $instance] != 1) do={ :error "Installed container entry not found" }
:while ([:len [/container find where name="universal-vpn-core" and interface="uvpn-main-veth" and stopped=yes]] != 1) do={
    :if ([:len [/container find where name="universal-vpn-core" and interface="uvpn-main-veth"]] != 1) do={
        :error "Container entry disappeared during extraction"
    }
    :if ([/system resource get uptime] >= $deadline) do={
        :error "Container did not reach S (stopped) within 15 minutes; check /container print detail and the container log"
    }
    :delay 2s
}
:put "Container is ready to start (S - stopped)."
}
