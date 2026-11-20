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
