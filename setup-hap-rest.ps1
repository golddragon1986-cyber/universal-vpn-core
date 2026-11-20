$ErrorActionPreference='Stop'
$sshArgs=@('-i','C:/Users/gunikov/.ssh/mikrotik_ed25519','-o','IdentitiesOnly=yes','-o','HostKeyAlias=5.23.108.48')
$dest=Join-Path $PSScriptRoot 'backups/hap-ac3-2026-11-06/private-rest'
New-Item -ItemType Directory -Path $dest -Force | Out-Null
$routePassword=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()
$cfg=@{url='https://172.31.41.1:8443/rest';user='universal-vpn-panel';password=$routePassword;gateway='172.31.41.2';bypass_table='uvpn-direct';ca='/etc/mihomo/clients/routeros-ca.crt'}
$cfg|ConvertTo-Json|Set-Content -LiteralPath "$dest/routeros.json" -Encoding utf8
$script=@'
/certificate add name=uvpn-ca common-name=UniversalVPN-hAP-CA key-size=2048 days-valid=3650 key-usage=key-cert-sign,crl-sign
/certificate sign uvpn-ca name=uvpn-ca
/certificate set uvpn-ca trusted=yes
/certificate add name=uvpn-rest common-name=172.31.41.1 subject-alt-name=IP:172.31.41.1 key-size=2048 days-valid=825 key-usage=digital-signature,key-encipherment,tls-server
/certificate sign uvpn-rest ca=uvpn-ca name=uvpn-rest
/certificate export-certificate uvpn-ca type=pem file-name=uvpn-router-ca
/user group add name=universal-vpn-routes policy=read,write,api,rest-api
/user add name=universal-vpn-panel group=universal-vpn-routes address=172.31.41.2/32 password=ROUTE_PASSWORD
/ip firewall filter add chain=input action=drop protocol=tcp dst-port=8443 place-before=0 comment="Universal VPN REST deny other clients"
/ip firewall filter add chain=input action=accept protocol=tcp dst-address=172.31.41.1 dst-port=8443 src-address=172.31.41.2 in-interface=container-universal place-before=0 comment="Universal VPN REST from container"
/ip firewall filter move [find where comment="Universal VPN REST from container"] destination=[find where comment="Universal VPN REST deny other clients"]
/ip service set www-ssl disabled=no port=8443 certificate=uvpn-rest tls-version=only-1.2 available-from=172.31.41.2/32
'@
$script.Replace('ROUTE_PASSWORD',$routePassword)|Set-Content -LiteralPath "$dest/bootstrap.rsc" -Encoding utf8
& scp -O @sshArgs "$dest/bootstrap.rsc" dragon@192.168.99.1:usb1-part1/uvpn-rest-bootstrap.rsc
if($LASTEXITCODE){throw 'Bootstrap upload failed'}
$result=(& node "$PSScriptRoot/router-ssh.mjs" hap '/import usb1-part1/uvpn-rest-bootstrap.rsc') -join "`n"
$result|Set-Content -LiteralPath "$dest/bootstrap-result.txt"
if($LASTEXITCODE -or $result -match 'Script Error|failure:|syntax error'){throw 'REST bootstrap failed; inspect local log'}
& scp -O @sshArgs dragon@192.168.99.1:uvpn-router-ca.crt "$dest/routeros-ca.crt"
if($LASTEXITCODE){throw 'CA transfer failed'}
& node "$PSScriptRoot/router-ssh.mjs" hap '/container shell universal-vpn-core cmd="mkdir -p /etc/mihomo/clients"'
& scp -O @sshArgs "$dest/routeros-ca.crt" dragon@192.168.99.1:usb1-part1/universal-vpn-clean-data/clients/routeros-ca.crt
if($LASTEXITCODE){throw 'CA upload failed'}
& scp -O @sshArgs "$dest/routeros.json" dragon@192.168.99.1:usb1-part1/universal-vpn-clean-data/clients/routeros.json
if($LASTEXITCODE){throw 'REST configuration upload failed'}
Write-Output 'REST provisioned. Run verify-hap-rest.py inside the container to set credential ownership/mode and verify live access.'
