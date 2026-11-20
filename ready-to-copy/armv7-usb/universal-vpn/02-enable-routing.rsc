# Use the same LAN interface list as in 01-install.rsc.
:local lan "LAN"
:local clients "uvpn-usb-lan"
:local tag "uvpn-usb: routing"
:local instance [/container find where name="universal-vpn-core" and interface="uvpn-usb-veth"]
:if ([:len $instance] != 1) do={ :error "USB container not installed" }
:if ([:len [/interface list find where name=$lan]] != 1) do={ :error "LAN interface list missing" }
:if ([:len [/ip route find where dst-address="198.18.0.0/16"]] > 0 || [:len [/ip firewall nat find where comment=$tag]] > 0 || [:len [/ip firewall filter find where comment=$tag]] > 0) do={ :error "Existing Fake-IP route or activation rules" }
:if ([:len [/ip firewall address-list find where list=$clients]] = 0) do={ :error "Client address list missing; install or migrate the LAN ACL first" }
:local firstFilter [:pick [/ip firewall filter find where dynamic=no] 0]
:local firstNat [:pick [/ip firewall nat find where dynamic=no] 0]
:do {
    /ip route add dst-address=198.18.0.0/16 gateway=172.31.41.2 comment=$tag
    /ip firewall filter add chain=forward in-interface-list=$lan src-address-list=$clients dst-address=198.18.0.0/16 out-interface=uvpn-usb-br action=accept comment=$tag
    /ip firewall filter add chain=forward in-interface=uvpn-usb-br src-address=198.18.0.0/16 dst-address-list=$clients out-interface-list=$lan connection-state=established,related action=accept comment=$tag
    /ip firewall filter add chain=forward dst-address=198.18.0.0/16 out-interface=uvpn-usb-br action=drop comment=$tag
    :if ([:typeof $firstFilter] = "id") do={
        :foreach id in=[/ip firewall filter find where comment=$tag] do={ /ip firewall filter move $id destination=$firstFilter }
    }
    /ip firewall nat add chain=dstnat in-interface-list=$lan src-address-list=$clients protocol=udp dst-port=53 action=dst-nat to-addresses=172.31.41.2 to-ports=53 comment=$tag
    /ip firewall nat add chain=dstnat in-interface-list=$lan src-address-list=$clients protocol=tcp dst-port=53 action=dst-nat to-addresses=172.31.41.2 to-ports=53 comment=$tag
    :if ([:typeof $firstNat] = "id") do={
        :foreach id in=[/ip firewall nat find where comment=$tag] do={ /ip firewall nat move $id destination=$firstNat }
    }
    /container set $instance start-on-boot=yes
} on-error={
    /ip firewall nat remove [find where comment=$tag]
    /ip firewall filter remove [find where comment=$tag]
    /ip route remove [find where comment=$tag]
    :error "Activation failed; activation rules removed"
}
:put "Client IPv4 DNS interception and Fake-IP route enabled."
