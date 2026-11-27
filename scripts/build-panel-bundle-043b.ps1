param([Parameter(Mandatory=$true)][string]$Version)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$source = Join-Path $root 'vendor\panel\panel'
$release = Join-Path $root (Join-Path 'version' (Join-Path $Version 'universal-vpn'))
$stage = Join-Path $root 'build\panel-bundle-0.43b'
$panelStage = Join-Path $stage 'panel'
$archive = Join-Path $release 'panel.tar.gz'
if (-not (Test-Path -LiteralPath $release)) { throw "Release directory missing: $release" }
if (Test-Path -LiteralPath $stage) { throw "Staging directory already exists: $stage" }
New-Item -ItemType Directory -Path $panelStage | Out-Null
$files = @(Get-ChildItem -LiteralPath $source -File | Where-Object { $_.Extension -in @('.py','.js','.html','.css','.sh') } | Sort-Object Name)
if ($files.Count -ne 71) { throw "Expected 71 panel files, got $($files.Count)" }
$manifestFiles = @()
foreach ($file in $files) {
    Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $panelStage $file.Name)
    $manifestFiles += @{ name = $file.Name; size = [int64]$file.Length; sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant(); mode = if ($file.Extension -eq '.sh') { 493 } else { 420 } }
}
$manifest = @{ version = '0.4.3'; files = $manifestFiles }
$utf8 = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText((Join-Path $panelStage 'panel-release.json'), (ConvertTo-Json -InputObject $manifest -Depth 8 -Compress), $utf8)
$entries = @('panel/panel-release.json') + @($files | ForEach-Object { 'panel/' + $_.Name })
& tar.exe -czf $archive -C $stage @entries
if ($LASTEXITCODE -ne 0) { throw "tar exited $LASTEXITCODE" }
$actual = @(tar.exe -tzf $archive)
if ($actual.Count -ne $entries.Count -or @($actual | Where-Object { $_ -notin $entries }).Count -ne 0) { throw 'Invalid archive entries' }
$size = (Get-Item -LiteralPath $archive).Length
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
$sums = Join-Path $release 'SHA256SUMS'
$line = "$hash  panel.tar.gz"
[IO.File]::AppendAllText($sums, $line + [Environment]::NewLine, [Text.Encoding]::ASCII)
$stable = @{ version = '0.4.3'; tag = 'v' + $Version; url = "https://github.com/golddragon1986-cyber/universal-vpn-core/releases/download/v$Version/panel.tar.gz"; sha256 = $hash; size = $size }
[IO.File]::WriteAllText((Join-Path $root 'build\panel-stable-0.43b.json'), (ConvertTo-Json -InputObject $stable -Depth 3) + [Environment]::NewLine, $utf8)
Write-Output (ConvertTo-Json -InputObject @{ version = $Version; panel_version = '0.4.3'; files = $files.Count; archive_size = $size; sha256 = $hash } -Compress)
