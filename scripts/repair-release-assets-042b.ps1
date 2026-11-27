param([Parameter(Mandatory=$true)][string]$Version)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$folder = Join-Path $root (Join-Path 'version' (Join-Path $Version 'universal-vpn'))
$repository = 'golddragon1986-cyber/universal-vpn-core'
$credential = @("protocol=https`nhost=github.com`n`n" | git credential fill)
$passwordLine = @($credential | Where-Object { $_ -like 'password=*' })
if ($passwordLine.Count -ne 1) { throw 'GitHub credential unavailable' }
$headers = @{ Authorization = 'Bearer ' + $passwordLine[0].Substring('password='.Length); Accept = 'application/vnd.github+json'; 'X-GitHub-Api-Version' = '2022-11-28' }
$api = "https://api.github.com/repos/$repository"
$release = Invoke-RestMethod -Method Get -Uri "$api/releases/tags/v$Version" -Headers $headers
foreach ($name in @('panel.tar.gz','SHA256SUMS')) {
    $path = Join-Path $folder $name
    $digest = 'sha256:' + (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $old = @($release.assets | Where-Object { $_.name -eq $name })
    if ($old.Count -gt 1) { throw "Duplicate asset: $name" }
    if ($old.Count -eq 1 -and $old[0].digest -eq $digest) {
        Write-Output "Verified existing $name"
        continue
    }
    if ($old.Count -eq 1) {
        Invoke-RestMethod -Method Delete -Uri "$api/releases/assets/$($old[0].id)" -Headers $headers | Out-Null
    }
    $url = "https://uploads.github.com/repos/$repository/releases/$($release.id)/assets?name=$name"
    $uploaded = Invoke-RestMethod -Method Post -Uri $url -Headers $headers -ContentType 'application/octet-stream' -InFile $path -TimeoutSec 300
    if ($uploaded.digest -ne $digest -or [int64]$uploaded.size -ne (Get-Item $path).Length) { throw "Upload mismatch: $name" }
    Write-Output "Replaced ${name}: $digest"
}
