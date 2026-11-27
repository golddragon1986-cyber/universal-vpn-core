param([Parameter(Mandatory=$true)][string]$Version)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$releaseDir = Join-Path $root (Join-Path 'version' (Join-Path $Version 'universal-vpn'))
$repository = 'golddragon1986-cyber/universal-vpn-core'
$tag = 'v' + $Version
$head = (git -C $root rev-parse HEAD).Trim()
$credential = @("protocol=https`nhost=github.com`n`n" | git credential fill)
$passwordLine = @($credential | Where-Object { $_ -like 'password=*' })
if ($passwordLine.Count -ne 1) { throw 'GitHub credential unavailable' }
$token = $passwordLine[0].Substring('password='.Length)
$headers = @{ Authorization = 'Bearer ' + $token; Accept = 'application/vnd.github+json'; 'X-GitHub-Api-Version' = '2022-11-28' }
$api = "https://api.github.com/repos/$repository"
try {
    $release = Invoke-RestMethod -Method Get -Uri "$api/releases/tags/$tag" -Headers $headers
} catch {
    if ([int]$_.Exception.Response.StatusCode -ne 404) { throw }
    $release = $null
}
if ($null -eq $release) {
    $description = [IO.File]::ReadAllText((Join-Path $releaseDir 'CHANGELOG.md'))
    $body = @{ tag_name = $tag; target_commitish = $head; name = $Version; body = $description; draft = $true; prerelease = $false } | ConvertTo-Json -Depth 5
    $release = Invoke-RestMethod -Method Post -Uri "$api/releases" -Headers $headers -ContentType 'application/json' -Body $body
    Write-Output "Created draft $tag"
} elseif (-not $release.draft) {
    throw "Release $tag is already published"
}
$assets = @(Get-ChildItem -LiteralPath $releaseDir -File | Sort-Object Name)
foreach ($file in $assets) {
    $existing = @($release.assets | Where-Object { $_.name -eq $file.Name })
    if ($existing.Count -gt 0) {
        if ([int64]$existing[0].size -ne $file.Length) { throw "Asset size mismatch: $($file.Name)" }
        Write-Output "Present $($file.Name)"
        continue
    }
    $name = [uri]::EscapeDataString($file.Name)
    $url = "https://uploads.github.com/repos/$repository/releases/$($release.id)/assets?name=$name"
    $uploaded = Invoke-RestMethod -Method Post -Uri $url -Headers $headers -ContentType 'application/octet-stream' -InFile $file.FullName -TimeoutSec 300
    if ($uploaded.name -ne $file.Name -or [int64]$uploaded.size -ne $file.Length) { throw "Upload verification failed: $($file.Name)" }
    Write-Output "Uploaded $($file.Name) ($($file.Length) bytes)"
}
$checked = Invoke-RestMethod -Method Get -Uri "$api/releases/$($release.id)" -Headers $headers
if (@($checked.assets).Count -ne $assets.Count) { throw "Expected $($assets.Count) assets, found $(@($checked.assets).Count)" }
foreach ($file in $assets) {
    $remote = @($checked.assets | Where-Object { $_.name -eq $file.Name })
    if ($remote.Count -ne 1 -or [int64]$remote[0].size -ne $file.Length) { throw "Final asset check failed: $($file.Name)" }
}
$published = Invoke-RestMethod -Method Patch -Uri "$api/releases/$($release.id)" -Headers $headers -ContentType 'application/json' -Body '{"draft":false}'
if ($published.draft -or $published.tag_name -ne $tag) { throw 'Release publication was not confirmed' }
Write-Output "Published $($published.html_url) with $($assets.Count) assets"
