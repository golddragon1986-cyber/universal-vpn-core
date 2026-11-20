$ErrorActionPreference='Stop'
$base='http://10.0.0.3:19091'
function RouteToken {
 $page=(Invoke-WebRequest "$base/?tab=routes" -TimeoutSec 12).Content
 [regex]::Match($page,'name="route_token" value="([^"]+)"').Groups[1].Value
}
function RouteAction($body,$expected='done') {
 $body.route_token=RouteToken
 $job=Invoke-RestMethod "$base/api/actions/queue" -Method Post -Body $body -TimeoutSec 12
 for($i=0;$i -lt 45;$i++){
  $state=(Invoke-RestMethod "$base/api/actions/status" -TimeoutSec 10).jobs|Where-Object id -eq $job.job_id
  if($state.status -in @('done','failed')){
   if($state.status -ne $expected){throw "Route action failed: $($state.message)"}
   Write-Output "$($body.action): $($state.status): $($state.message)"
   return
  }
  Start-Sleep -Milliseconds 700
 }
 throw 'Route action timeout'
}
RouteAction @{action='route_add';destination='0.0.0.0/0';label='Forbidden default'} 'failed'
$added=$false
try {
 RouteAction @{action='route_add';destination='9.9.9.10/32';label='Проверка управления'}
 $added=$true
 $page=(Invoke-WebRequest "$base/?tab=routes" -TimeoutSec 12).Content
 $row=[regex]::Match($page,'(?s)<tr><td>9\.9\.9\.10/32</td>.*?</tr>').Value
 $routeId=[regex]::Match($row,'name="route_id" value="([^"]+)"').Groups[1].Value
 if(-not $routeId){throw 'Added RouterOS route missing from UI'}
 RouteAction @{action='route_delete';route_id=$routeId}
 $added=$false
 $page=(Invoke-WebRequest "$base/?tab=routes" -TimeoutSec 12).Content
 if($page.Contains('<td>9.9.9.10/32</td>')){throw 'Deleted test route still displayed'}
 'Live panel CRUD and local-access guard verified'
} finally {
 if($added -and $routeId){RouteAction @{action='route_delete';route_id=$routeId}}
}
