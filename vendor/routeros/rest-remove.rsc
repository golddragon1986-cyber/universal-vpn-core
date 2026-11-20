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
