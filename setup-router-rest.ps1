$ErrorActionPreference='Stop'
$sshArgs=@('-o','BatchMode=yes','-o','UserKnownHostsFile=C:/Users/gunikov/Documents/ChatGPT/Ротеры/work/routeros-upgrade/known_hosts_v7','-i','C:/Users/gunikov/.ssh/mikrotik_border_rsa')
$scpArgs=@('-O')+$sshArgs
$dest='\\ds\web_backup\border_RB4011iGS+5HacQ2HnD\2026-11-05\routes-panel-bootstrap-'+(Get-Date -Format HHmmss)
New-Item -ItemType Directory -Path $dest|Out-Null
foreach($name in @('before-routes-panel-1105.backup','before-routes-panel-1105.rsc')){
 & scp @scpArgs "Edinstvo@10.0.0.3:$name" "$dest\$name"
 if($LASTEXITCODE){throw 'Backup transfer failed'}
}
Invoke-WebRequest 'http://10.0.0.3:19091/?download=backup' -OutFile "$dest\panel-settings.json" -TimeoutSec 60
$secretBytes=New-Object byte[] 32
$routeRng=[Security.Cryptography.RandomNumberGenerator]::Create()
$routeRng.GetBytes($secretBytes)
$routeRng.Dispose()
$routePassword=[Convert]::ToHexString($secretBytes).ToLowerInvariant()
$cfg=@{url='https://172.31.41.1:8443/rest';user='universal-vpn-panel';password=$routePassword;gateway='172.31.41.2';bypass_table='mihomo-telegram-direct';ca='/etc/mihomo/clients/routeros-ca.crt'}
$cfg|ConvertTo-Json|Set-Content "$dest\routeros.json" -Encoding utf8
$script=@'
/certificate add name=uvpn-ca common-name=UniversalVPN-Local-CA key-size=2048 days-valid=3650 key-usage=key-cert-sign,crl-sign
/certificate sign uvpn-ca name=uvpn-ca
/certificate set uvpn-ca trusted=yes
/certificate add name=uvpn-rest common-name=172.31.41.1 subject-alt-name=IP:172.31.41.1 key-size=2048 days-valid=825 key-usage=digital-signature,key-encipherment,tls-server
/certificate sign uvpn-rest ca=uvpn-ca name=uvpn-rest
/certificate set uvpn-rest trusted=yes
/certificate export-certificate uvpn-ca type=pem file-name=uvpn-router-ca
/user group add name=universal-vpn-routes policy=read,write,api,rest-api
/user add name=universal-vpn-panel group=universal-vpn-routes address=172.31.41.2/32 password=ROUTE_PASSWORD
/ip firewall filter add chain=input action=accept protocol=tcp dst-address=172.31.41.1 dst-port=8443 src-address=172.31.41.2 in-interface=container-universal place-before=0 comment="Universal VPN REST from container"
/ip firewall filter add chain=input action=drop protocol=tcp dst-port=8443 place-before=1 comment="Universal VPN REST deny other clients"
/ip service set www-ssl disabled=no port=8443 certificate=uvpn-rest tls-version=only-1.2 available-from=172.31.41.2/32
'@
$script.Replace('ROUTE_PASSWORD',$routePassword)|Set-Content "$dest\bootstrap.rsc" -Encoding utf8
& scp @scpArgs "$dest\bootstrap.rsc" Edinstvo@10.0.0.3:/uvpn-rest-bootstrap.rsc
if($LASTEXITCODE){throw 'Bootstrap upload failed'}
$bootstrapLog=(& ssh @sshArgs Edinstvo@10.0.0.3 '/import file-name=uvpn-rest-bootstrap.rsc') -join "`n"
$bootstrapLog|Set-Content "$dest\bootstrap-result.txt"
if($LASTEXITCODE -or $bootstrapLog -match 'Script Error|failure:|syntax error'){throw 'RouterOS rejected bootstrap; inspect the private NAS setup log'}
& scp @scpArgs Edinstvo@10.0.0.3:/uvpn-router-ca.crt "$dest\routeros-ca.crt"
if($LASTEXITCODE){throw 'CA download failed'}
& scp @scpArgs "$dest\routeros-ca.crt" Edinstvo@10.0.0.3:/universal-vpn-data/clients/routeros-ca.crt
if($LASTEXITCODE){throw 'CA upload failed'}
& scp @scpArgs "$dest\routeros.json" Edinstvo@10.0.0.3:/universal-vpn-data/clients/routeros.json
if($LASTEXITCODE){throw 'Credentials upload failed'}
& ssh @sshArgs Edinstvo@10.0.0.3 '/file remove [find where name="uvpn-rest-bootstrap.rsc"]'
Get-ChildItem -LiteralPath $dest -File|Get-FileHash -Algorithm SHA256|Select-Object Hash,Path|ConvertTo-Json|Set-Content "$dest\sha256.json"
$dest|Set-Content work-router-rest-backup-location.txt
Write-Output 'Restricted RouterOS HTTPS account provisioned; credentials stored only in private config and NAS backup.'
