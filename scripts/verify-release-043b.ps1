param([Parameter(Mandatory=$true)][string]$Version)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$release = Join-Path $root (Join-Path 'version' (Join-Path $Version 'universal-vpn'))
$panelSource = Join-Path $root 'vendor\panel\panel'
$binarySource = Join-Path $root 'build\mihomo-043'
$buildInfo = Get-Content (Join-Path $release 'BUILD-INFO.json') -Raw | ConvertFrom-Json

function Get-Sha256([byte[]]$Bytes) {
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Read-Archive([byte[]]$Bytes, [bool]$Gzip = $false) {
    $memory = [IO.MemoryStream]::new($Bytes, $false)
    $stream = $memory
    if ($Gzip) { $stream = [IO.Compression.GZipStream]::new($memory, [IO.Compression.CompressionMode]::Decompress) }
    $reader = [System.Formats.Tar.TarReader]::new($stream)
    $files = @{}
    try {
        while ($null -ne ($entry = $reader.GetNextEntry())) {
            if ($entry.EntryType -ne [System.Formats.Tar.TarEntryType]::RegularFile) { continue }
            $buffer = [IO.MemoryStream]::new()
            try {
                if ($null -ne $entry.DataStream) { $entry.DataStream.CopyTo($buffer) }
                $files[$entry.Name] = $buffer.ToArray()
            } finally { $buffer.Dispose() }
        }
    } finally {
        $reader.Dispose()
        $stream.Dispose()
        if ($Gzip) { $memory.Dispose() }
    }
    return ,$files
}

$panelFiles = @{}
foreach ($file in (Get-ChildItem -LiteralPath $panelSource -File | Where-Object { $_.Extension -in @('.py','.sh','.html','.css','.js') })) { $panelFiles[$file.Name] = $file.FullName }
foreach ($arch in @('armv7','arm64')) {
    $outer = Read-Archive ([IO.File]::ReadAllBytes((Join-Path $release "universal-vpn-core-$arch.tar")))
    $index = [Text.Encoding]::UTF8.GetString($outer['index.json']) | ConvertFrom-Json
    $manifestDigest = $index.manifests[0].digest.Substring(7)
    $manifestBytes = [byte[]]$outer[('blobs/sha256/' + $manifestDigest)]
    if ((Get-Sha256 $manifestBytes) -ne $manifestDigest) { throw "$arch manifest hash mismatch" }
    $manifest = [Text.Encoding]::UTF8.GetString($manifestBytes) | ConvertFrom-Json
    $configDigest = $manifest.config.digest.Substring(7)
    $configBytes = [byte[]]$outer[('blobs/sha256/' + $configDigest)]
    if ((Get-Sha256 $configBytes) -ne $configDigest) { throw "$arch config hash mismatch" }
    $config = [Text.Encoding]::UTF8.GetString($configBytes) | ConvertFrom-Json
    $expectedArch = if ($arch -eq 'arm64') { 'arm64' } else { 'arm' }
    if ($config.architecture -ne $expectedArch) { throw "$arch architecture mismatch: $($config.architecture)" }
    $layerDigest = $manifest.layers[0].digest.Substring(7)
    $layerBytes = [byte[]]$outer[('blobs/sha256/' + $layerDigest)]
    if ((Get-Sha256 $layerBytes) -ne $layerDigest) { throw "$arch layer hash mismatch" }
    $layer = Read-Archive $layerBytes $true
    $prefix = 'usr/local/lib/mihomo-panel/'
    if (-not $layer.ContainsKey($prefix + 'entrypoint.sh')) { throw "$arch entrypoint missing" }
    if ([Text.Encoding]::UTF8.GetString($layer[$prefix + 'VERSION']).Trim() -ne $Version) { throw "$arch version mismatch" }
    $panelVersion = [Text.Encoding]::UTF8.GetString($layer[$prefix + 'default-state/panel-version.json']) | ConvertFrom-Json
    if ($panelVersion.version -ne '0.4.3' -or $panelVersion.tag -ne "v$Version") { throw "$arch panel version mismatch" }
    foreach ($fileName in $panelFiles.Keys) {
        $name = $prefix + 'panel/' + $fileName
        if (-not $layer.ContainsKey($name) -or (Get-Sha256 ([byte[]]$layer[$name])) -ne (Get-Sha256 ([IO.File]::ReadAllBytes($panelFiles[$fileName])))) {
            throw "$arch panel file mismatch: $fileName"
        }
    }
    $core = [byte[]]$layer['mihomo']
    $coreHash = Get-Sha256 $core
    $sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $binarySource "mihomo-$arch")).Hash.ToLowerInvariant()
    if ($coreHash -ne $sourceHash -or $coreHash -ne $buildInfo.architectures.$arch.core_sha256) { throw "$arch patched core hash mismatch" }
    $machine = [BitConverter]::ToUInt16($core,18)
    if (($arch -eq 'arm64' -and $machine -ne 183) -or ($arch -eq 'armv7' -and $machine -ne 40)) { throw "$arch Mihomo ELF architecture mismatch" }
    if (-not [Text.Encoding]::ASCII.GetString($core).Contains('uvpnc-reality-version')) { throw "$arch Mihomo patch marker missing" }
    $rules = [Text.Encoding]::UTF8.GetString($layer[$prefix + 'default-services.json']) | ConvertFrom-Json
    if (@($rules).Count -ne 3) { throw "$arch expected three rules" }
    if ($layer.ContainsKey($prefix + 'portable-settings.json')) { throw "$arch contains RouterOS settings" }
    if (@($layer.Keys | Where-Object { $_ -match '/clients/|private\.key|id_rsa' }).Count -gt 0) { throw "$arch private file in image" }
    Write-Output "$arch OCI verified: $($panelFiles.Count) panel files, $($layer.Count) layer files"
}

foreach ($line in [IO.File]::ReadAllLines((Join-Path $release 'SHA256SUMS'))) {
    $parts = $line -split '  ', 2
    if ($parts.Count -ne 2) { throw 'Invalid checksum line' }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $release $parts[1])).Hash.ToLowerInvariant() -ne $parts[0]) {
        throw "Checksum mismatch: $($parts[1])"
    }
}
Write-Output 'SHA256SUMS verified'
