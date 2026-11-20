param(
    [Parameter(Mandatory=$true)][string]$InputImage,
    [Parameter(Mandatory=$true)][string]$OutputImage
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$inputPath = (Resolve-Path -LiteralPath $InputImage).Path
$entrypointPath = Join-Path $root 'vendor\panel\entrypoint.sh'
$buildScript = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'build-release-031b.ps1'))
$helperStart = $buildScript.IndexOf('function Get-Sha256(')
$helperEnd = $buildScript.IndexOf('function Build-Image(')
if ($helperStart -lt 0 -or $helperEnd -le $helperStart) { throw 'Release build helpers not found' }

$utf8 = [Text.UTF8Encoding]::new($false)
$now = [DateTimeOffset]::Now
. ([scriptblock]::Create($buildScript.Substring($helperStart, $helperEnd - $helperStart)))

$source = Read-TarRecords ([IO.File]::ReadAllBytes($inputPath))
$sourceMap = @{}
foreach ($record in $source) { $sourceMap[$record.Name] = $record.Data }
$index = $utf8.GetString([byte[]]$sourceMap['index.json']) | ConvertFrom-Json -AsHashtable
$manifestKey = 'blobs/sha256/' + $index.manifests[0].digest.Substring(7)
$manifest = $utf8.GetString([byte[]]$sourceMap[$manifestKey]) | ConvertFrom-Json -AsHashtable
$configKey = 'blobs/sha256/' + $manifest.config.digest.Substring(7)
$config = $utf8.GetString([byte[]]$sourceMap[$configKey]) | ConvertFrom-Json -AsHashtable
$layerKey = 'blobs/sha256/' + $manifest.layers[0].digest.Substring(7)
$records = Read-TarRecords ([byte[]]$sourceMap[$layerKey]) $true

$entrypointName = 'usr/local/lib/mihomo-panel/entrypoint.sh'
if (@($records | Where-Object { $_.Name -eq $entrypointName }).Count -ne 0) {
    throw 'The ARM64 image already contains entrypoint.sh'
}
$expectedCommand = '/bin/sh /usr/local/lib/mihomo-panel/entrypoint.sh'
if (($config.config.Entrypoint -join ' ') -ne $expectedCommand) {
    throw "Unexpected ARM64 entrypoint: $($config.config.Entrypoint -join ' ')"
}
$records.Add([pscustomobject]@{
    Name = $entrypointName
    Type = [System.Formats.Tar.TarEntryType]::RegularFile
    Mode = [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::UserExecute -bor [IO.UnixFileMode]::GroupRead -bor [IO.UnixFileMode]::GroupExecute -bor [IO.UnixFileMode]::OtherRead -bor [IO.UnixFileMode]::OtherExecute
    Uid = 0; Gid = 0; UserName = 'root'; GroupName = 'root'; LinkName = ''; MTime = $now
    Data = [IO.File]::ReadAllBytes($entrypointPath)
})

$temporaryLayer = Join-Path ([IO.Path]::GetTempPath()) ("uvpnc-entrypoint-$([guid]::NewGuid().ToString('N')).tar.gz")
try {
    $layerInfo = Write-Layer $records $temporaryLayer
    $packedLayer = [byte[]]$layerInfo.Packed
    $config.rootfs.diff_ids[0] = 'sha256:' + $layerInfo.RawHash
    $newConfig = ConvertTo-JsonBytes $config
    $configDigest = Get-Sha256 $newConfig
    $manifest.config.digest = 'sha256:' + $configDigest
    $manifest.config.size = $newConfig.Length
    $manifest.layers[0].digest = 'sha256:' + (Get-Sha256 $packedLayer)
    $manifest.layers[0].size = $packedLayer.Length
    $newManifest = ConvertTo-JsonBytes $manifest
    $manifestDigest = Get-Sha256 $newManifest
    $index.manifests[0].digest = 'sha256:' + $manifestDigest
    $index.manifests[0].size = $newManifest.Length
    $newIndex = ConvertTo-JsonBytes $index

    $stream = [IO.MemoryStream]::new()
    try {
        $writer = [System.Formats.Tar.TarWriter]::new($stream, [System.Formats.Tar.TarEntryFormat]::Gnu, $true)
        try {
            Write-GnuEntry $writer 'oci-layout' ([byte[]]$sourceMap['oci-layout'])
            Write-GnuEntry $writer 'index.json' $newIndex
            Write-GnuEntry $writer ('blobs/sha256/' + $configDigest) $newConfig
            Write-GnuEntry $writer ('blobs/sha256/' + $manifestDigest) $newManifest
            Write-GnuEntry $writer ('blobs/sha256/' + $manifest.layers[0].digest.Substring(7)) $packedLayer
        } finally { $writer.Dispose() }
        [IO.File]::WriteAllBytes($OutputImage, $stream.ToArray())
    } finally { $stream.Dispose() }
} finally {
    Remove-Item -LiteralPath $temporaryLayer -Force -ErrorAction SilentlyContinue
}

$rebuilt = Read-TarRecords ([IO.File]::ReadAllBytes($OutputImage))
$rebuiltMap = @{}
foreach ($record in $rebuilt) { $rebuiltMap[$record.Name] = $record.Data }
$rebuiltIndex = $utf8.GetString([byte[]]$rebuiltMap['index.json']) | ConvertFrom-Json -AsHashtable
$rebuiltManifestDigest = $rebuiltIndex.manifests[0].digest.Substring(7)
$rebuiltManifestBytes = [byte[]]$rebuiltMap[('blobs/sha256/' + $rebuiltManifestDigest)]
if ((Get-Sha256 $rebuiltManifestBytes) -ne $rebuiltManifestDigest) { throw 'Manifest digest mismatch' }
$rebuiltManifest = $utf8.GetString($rebuiltManifestBytes) | ConvertFrom-Json -AsHashtable
$rebuiltConfigDigest = $rebuiltManifest.config.digest.Substring(7)
$rebuiltConfigBytes = [byte[]]$rebuiltMap[('blobs/sha256/' + $rebuiltConfigDigest)]
if ((Get-Sha256 $rebuiltConfigBytes) -ne $rebuiltConfigDigest) { throw 'Config digest mismatch' }
$rebuiltConfig = $utf8.GetString($rebuiltConfigBytes) | ConvertFrom-Json -AsHashtable
$rebuiltLayerDigest = $rebuiltManifest.layers[0].digest.Substring(7)
$rebuiltLayer = [byte[]]$rebuiltMap[('blobs/sha256/' + $rebuiltLayerDigest)]
if ((Get-Sha256 $rebuiltLayer) -ne $rebuiltLayerDigest) { throw 'Layer digest mismatch' }
$compressedStream = [IO.MemoryStream]::new($rebuiltLayer, $false)
$decompressor = [IO.Compression.GZipStream]::new($compressedStream, [IO.Compression.CompressionMode]::Decompress)
$rawStream = [IO.MemoryStream]::new()
try { $decompressor.CopyTo($rawStream) } finally { $decompressor.Dispose(); $compressedStream.Dispose() }
try {
    if ('sha256:' + (Get-Sha256 $rawStream.ToArray()) -ne $rebuiltConfig.rootfs.diff_ids[0]) { throw 'Rootfs diff ID mismatch' }
} finally { $rawStream.Dispose() }
$rebuiltRecords = Read-TarRecords $rebuiltLayer $true
$rebuiltEntrypoint = @($rebuiltRecords | Where-Object { $_.Name -eq $entrypointName })
if ($rebuiltEntrypoint.Count -ne 1 -or (Get-Sha256 ([byte[]]$rebuiltEntrypoint[0].Data)) -ne (Get-Sha256 ([IO.File]::ReadAllBytes($entrypointPath)))) {
    throw 'Entrypoint content mismatch'
}

$result = @{ image = $OutputImage; sha256 = Get-Sha256 ([IO.File]::ReadAllBytes($OutputImage)); entrypoint = $entrypointName; layer_entries = $records.Count }
$result | ConvertTo-Json -Compress
