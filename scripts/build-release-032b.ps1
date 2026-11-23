param(
    [Parameter(Mandatory=$true)][string]$Version
)

# Requires the local 0.31b base images and build/release-0.3b/defaults.tgz.
# Validate the generated ARMv7 and ARM64 OCI layers before publishing a release.
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location -LiteralPath $root

$previous = Join-Path $root 'version\0.31b.191126.1600\universal-vpn'
$defaultsArchive = Join-Path $root 'build\release-0.3b\defaults.tgz'
$release = Join-Path $root (Join-Path 'version' (Join-Path $Version 'universal-vpn'))
$panelSource = Join-Path $root 'vendor\panel\panel'
$packagePrefix = 'usr/local/lib/mihomo-panel/'
$utf8 = [System.Text.UTF8Encoding]::new($false)
$now = [DateTimeOffset]::Now
$newline = [Environment]::NewLine

if ($Version -notmatch '^0\.32b\.\d{6}\.\d{4}$') {
    throw 'Версия должна иметь формат 0.32b.ГГММДД.ЧЧММ.'
}
if (Test-Path -LiteralPath $release) {
    throw "Каталог релиза уже существует: $release"
}

function Get-Sha256([byte[]]$Bytes) {
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Get-BytesFromEntry($Entry) {
    if ($Entry.Length -eq 0 -or $null -eq $Entry.DataStream) { return ,([byte[]]::new(0)) }
    $buffer = [IO.MemoryStream]::new()
    try {
        $Entry.DataStream.CopyTo($buffer)
        return ,$buffer.ToArray()
    } finally {
        $buffer.Dispose()
    }
}

function Read-TarRecords([byte[]]$Bytes, [bool]$Gzip = $false) {
    $input = [IO.MemoryStream]::new($Bytes, $false)
    $decompressor = $null
    $reader = $null
    $records = [Collections.Generic.List[object]]::new()
    try {
        $stream = $input
        if ($Gzip) {
            $decompressor = [IO.Compression.GZipStream]::new($input, [IO.Compression.CompressionMode]::Decompress, $true)
            $stream = $decompressor
        }
        $reader = [System.Formats.Tar.TarReader]::new($stream, $true)
        while ($null -ne ($entry = $reader.GetNextEntry())) {
            $records.Add([pscustomobject]@{
                Name = $entry.Name
                Type = $entry.EntryType
                Mode = $entry.Mode
                Uid = $entry.Uid
                Gid = $entry.Gid
                UserName = $entry.UserName
                GroupName = $entry.GroupName
                LinkName = $entry.LinkName
                MTime = $entry.ModificationTime
                Data = (Get-BytesFromEntry $entry)
            })
        }
        return ,$records
    } finally {
        if ($null -ne $reader) { $reader.Dispose() }
        if ($null -ne $decompressor) { $decompressor.Dispose() }
        $input.Dispose()
    }
}

function Write-GnuEntry($Writer, [string]$Name, [byte[]]$Data, [long]$Mode = 420) {
    $entry = [System.Formats.Tar.GnuTarEntry]::new([System.Formats.Tar.TarEntryType]::RegularFile, $Name)
    $entry.Mode = [IO.UnixFileMode]$Mode
    $entry.Uid = 0
    $entry.Gid = 0
    $entry.UserName = 'root'
    $entry.GroupName = 'root'
    $entry.ModificationTime = $now
    $entry.DataStream = [IO.MemoryStream]::new($Data, $false)
    try { $Writer.WriteEntry($entry) } finally { $entry.DataStream.Dispose() }
}

function Write-Layer($Records, [string]$OutputPath) {
    $raw = [IO.MemoryStream]::new()
    $writer = [System.Formats.Tar.TarWriter]::new($raw, [System.Formats.Tar.TarEntryFormat]::Gnu, $true)
    try {
        foreach ($record in $Records) {
            $entry = [System.Formats.Tar.GnuTarEntry]::new($record.Type, $record.Name)
            $entry.Mode = $record.Mode
            $entry.Uid = $record.Uid
            $entry.Gid = $record.Gid
            $entry.UserName = $record.UserName
            $entry.GroupName = $record.GroupName
            $entry.ModificationTime = $record.MTime
            if ($record.Type -eq [System.Formats.Tar.TarEntryType]::RegularFile -or $record.Type -eq [System.Formats.Tar.TarEntryType]::ContiguousFile) {
                $entry.DataStream = [IO.MemoryStream]::new([byte[]]$record.Data, $false)
            } elseif ($record.Type -eq [System.Formats.Tar.TarEntryType]::SymbolicLink -or $record.Type -eq [System.Formats.Tar.TarEntryType]::HardLink) {
                $entry.LinkName = $record.LinkName
            }
            try { $writer.WriteEntry($entry) } finally {
                if ($null -ne $entry.DataStream) { $entry.DataStream.Dispose() }
            }
        }
    } finally {
        $writer.Dispose()
    }
    try {
        $rawBytes = $raw.ToArray()
        $rawHash = Get-Sha256 $rawBytes
        $compressed = [IO.MemoryStream]::new()
        $gzip = [IO.Compression.GZipStream]::new($compressed, [IO.Compression.CompressionLevel]::Optimal, $true)
        try { $gzip.Write($rawBytes, 0, $rawBytes.Length) } finally { $gzip.Dispose() }
        $packed = $compressed.ToArray()
        [IO.File]::WriteAllBytes($OutputPath, $packed)
        $regularBytes = 0L
        foreach ($record in $Records) {
            if ($record.Type -eq [System.Formats.Tar.TarEntryType]::RegularFile) { $regularBytes += $record.Data.Length }
        }
        return [pscustomobject]@{ RawHash = $rawHash; Packed = $packed; RegularBytes = $regularBytes; EntryCount = $Records.Count }
    } finally {
        $raw.Dispose()
    }
}

function ConvertTo-JsonBytes($Value) {
    return $utf8.GetBytes((ConvertTo-Json -InputObject $Value -Depth 100 -Compress))
}

function Build-Image([string]$Architecture, $DefaultFiles, $PanelFiles, $BuildInfo) {
    $sourcePath = Join-Path $previous "universal-vpn-core-$Architecture.tar"
    $sourceArchive = Read-TarRecords ([IO.File]::ReadAllBytes($sourcePath))
    $sourceMap = @{}
    foreach ($item in $sourceArchive) { $sourceMap[$item.Name] = $item.Data }
    $index = [Text.Encoding]::UTF8.GetString($sourceMap['index.json']) | ConvertFrom-Json -AsHashtable
    $manifestKey = 'blobs/sha256/' + $index.manifests[0].digest.Substring(7)
    $manifest = [Text.Encoding]::UTF8.GetString([byte[]]$sourceMap[$manifestKey]) | ConvertFrom-Json -AsHashtable
    $configKey = 'blobs/sha256/' + $manifest.config.digest.Substring(7)
    $oldConfig = [Text.Encoding]::UTF8.GetString([byte[]]$sourceMap[$configKey]) | ConvertFrom-Json -AsHashtable
    $layerKey = 'blobs/sha256/' + $manifest.layers[0].digest.Substring(7)
    $oldLayer = [byte[]]$sourceMap[$layerKey]
    $records = [Collections.Generic.List[object]]::new()
    $replaced = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in $DefaultFiles.Keys) { [void]$replaced.Add($packagePrefix + $name) }
    foreach ($name in $PanelFiles.Keys) { [void]$replaced.Add($packagePrefix + 'panel/' + $name) }
    foreach ($name in @('initialize.py','default-config.yaml','entrypoint.sh','VERSION')) {
        [void]$replaced.Add($packagePrefix + $name)
    }
    foreach ($record in (Read-TarRecords $oldLayer $true)) {
        $panelFile = $record.Name.StartsWith($packagePrefix + 'panel/', [StringComparison]::Ordinal) -and
            [IO.Path]::GetExtension($record.Name) -in @('.py','.sh','.html','.css','.js')
        $managedSeed = $record.Name.StartsWith($packagePrefix + 'default-domains/', [StringComparison]::Ordinal) -or
            $record.Name.StartsWith($packagePrefix + 'default-state/', [StringComparison]::Ordinal)
        if ($replaced.Contains($record.Name) -or $panelFile -or $managedSeed) { continue }
        $records.Add($record)
    }
    foreach ($name in $DefaultFiles.Keys) {
        $records.Add([pscustomobject]@{
            Name = $packagePrefix + $name
            Type = [System.Formats.Tar.TarEntryType]::RegularFile
            Mode = [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::GroupRead -bor [IO.UnixFileMode]::OtherRead
            Uid = 0; Gid = 0; UserName = 'root'; GroupName = 'root'; LinkName = ''; MTime = $now; Data = [byte[]]$DefaultFiles[$name]
        })
    }
    foreach ($name in $PanelFiles.Keys) {
        $records.Add([pscustomobject]@{
            Name = $packagePrefix + 'panel/' + $name
            Type = [System.Formats.Tar.TarEntryType]::RegularFile
            Mode = if ($name.EndsWith('.sh')) { [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::UserExecute -bor [IO.UnixFileMode]::GroupRead -bor [IO.UnixFileMode]::GroupExecute -bor [IO.UnixFileMode]::OtherRead -bor [IO.UnixFileMode]::OtherExecute } else { [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::GroupRead -bor [IO.UnixFileMode]::OtherRead }
            Uid = 0; Gid = 0; UserName = 'root'; GroupName = 'root'; LinkName = ''; MTime = $now; Data = [byte[]]$PanelFiles[$name]
        })
    }
    foreach ($name in @('initialize.py','default-config.yaml','entrypoint.sh')) {
        $file = Join-Path $root (Join-Path 'vendor\panel' $name)
        $scriptMode = $name -eq 'entrypoint.sh'
        $mode = if ($scriptMode) { [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::UserExecute -bor [IO.UnixFileMode]::GroupRead -bor [IO.UnixFileMode]::GroupExecute -bor [IO.UnixFileMode]::OtherRead -bor [IO.UnixFileMode]::OtherExecute } else { [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::GroupRead -bor [IO.UnixFileMode]::OtherRead }
        $records.Add([pscustomobject]@{
            Name = $packagePrefix + $name; Type = [System.Formats.Tar.TarEntryType]::RegularFile; Mode = $mode
            Uid = 0; Gid = 0; UserName = 'root'; GroupName = 'root'; LinkName = ''; MTime = $now; Data = [IO.File]::ReadAllBytes($file)
        })
    }
    $records.Add([pscustomobject]@{
        Name = $packagePrefix + 'VERSION'; Type = [System.Formats.Tar.TarEntryType]::RegularFile
        Mode = [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::GroupRead -bor [IO.UnixFileMode]::OtherRead
        Uid = 0; Gid = 0; UserName = 'root'; GroupName = 'root'; LinkName = ''; MTime = $now; Data = $utf8.GetBytes($Version + $newline)
    })
    if (@($records | Where-Object { $_.Name -eq ($packagePrefix + 'entrypoint.sh') }).Count -ne 1) {
        throw "Image $Architecture must contain exactly one entrypoint.sh"
    }
    $temporaryLayer = Join-Path ([IO.Path]::GetTempPath()) ("uvpnl-$Architecture-$([guid]::NewGuid().ToString('N')).tar.gz")
    try {
        $layerInfo = Write-Layer $records $temporaryLayer
        $packedLayer = [byte[]]$layerInfo.Packed
        $config = $oldConfig
        $config.rootfs.diff_ids = @('sha256:' + $layerInfo.RawHash)
        $config.created = $now.ToString('yyyy-MM-ddTHH:mm:ss.ffffffzzz')
        if ($null -eq $config.config.Labels) { $config.config.Labels = @{} }
        $config.config.Labels['org.opencontainers.image.version'] = $Version
        $config.config.Labels['org.opencontainers.image.title'] = 'Universal VPN Core'
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
        $out = [IO.MemoryStream]::new()
        $outer = [System.Formats.Tar.TarWriter]::new($out, [System.Formats.Tar.TarEntryFormat]::Gnu, $true)
        try {
            Write-GnuEntry $outer 'oci-layout' ([byte[]]$sourceMap['oci-layout'])
            Write-GnuEntry $outer 'index.json' $newIndex
            Write-GnuEntry $outer ('blobs/sha256/' + $configDigest) $newConfig
            Write-GnuEntry $outer ('blobs/sha256/' + $manifestDigest) $newManifest
            Write-GnuEntry $outer ('blobs/sha256/' + $manifest.layers[0].digest.Substring(7)) $packedLayer
        } finally { $outer.Dispose() }
        $archive = $out.ToArray()
        [IO.File]::WriteAllBytes((Join-Path $release "universal-vpn-core-$Architecture.tar"), $archive)
        $regularBytes = [long]$layerInfo.RegularBytes
        $BuildInfo.architectures[$Architecture] = @{
            sha256 = Get-Sha256 $archive
            archive_bytes = $archive.Length
            regular_file_bytes = $regularBytes
            files = $layerInfo.EntryCount
            base_sha256 = Get-Sha256 ([IO.File]::ReadAllBytes($sourcePath))
            layer_diff_id = 'sha256:' + $layerInfo.RawHash
            core_version = if ($Architecture -eq 'armv7') { 'Mihomo 1.19.34' } else { 'Mihomo 1.19.33 (from 0.31b ARM64 base)' }
        }
    } finally {
        Remove-Item -LiteralPath $temporaryLayer -Force -ErrorAction SilentlyContinue
    }
}

$defaultsRecords = Read-TarRecords ([IO.File]::ReadAllBytes($defaultsArchive)) $true
$defaults = @{}
foreach ($entry in $defaultsRecords) { $defaults[$entry.Name] = $entry.Data }
$services = [Text.Encoding]::UTF8.GetString([byte[]]$defaults['default-services.json']) | ConvertFrom-Json
if ($services.Count -ne 5) { throw 'Ожидались пять начальных правил GeoDAT.' }
$defaultFiles = @{}
foreach ($entry in $defaultsRecords) {
    if ($entry.Name -ne 'mihomo' -and $entry.Name -ne 'portable-settings.json') { $defaultFiles[$entry.Name] = $entry.Data }
}
$panelVersion = ([IO.File]::ReadAllText((Join-Path $root 'updates\panel\VERSION'), $utf8)).Trim()
if ($panelVersion -notmatch '^\d+\.\d+\.\d+$') { throw 'Invalid panel version' }
$defaultFiles['default-state/panel-version.json'] = $utf8.GetBytes((ConvertTo-Json -InputObject @{ version = $panelVersion; tag = "v$Version" } -Compress) + "`n")
$panelFiles = @{}
foreach ($file in Get-ChildItem -LiteralPath $panelSource -File | Where-Object { $_.Extension -in @('.py','.sh','.html','.css','.js') } | Sort-Object Name) {
    $panelFiles[$file.Name] = [IO.File]::ReadAllBytes($file.FullName)
}
foreach ($required in @('panel_updater.py','client_panel.py','local_dns_zones.py','vpn_traffic.py','manage_ru_blocked.py')) {
    if (-not $panelFiles.ContainsKey($required)) { throw "Нет обязательного модуля панели: $required" }
}

New-Item -ItemType Directory -Path $release -Force | Out-Null
$buildInfo = @{
    version = $Version; release = '0.32b'; created = $now.ToString('o')
    defaults_sha256 = Get-Sha256 ([IO.File]::ReadAllBytes($defaultsArchive))
    panel_sha256 = @{}
    vpn_profiles = 0; subscriptions = 0
    rules = @($services | ForEach-Object { @{ name = $_.name; target = $_.target } })
    private_runtime_state_included = $false
    architectures = @{}
}
foreach ($name in $panelFiles.Keys) { $buildInfo.panel_sha256[$name] = Get-Sha256 ([byte[]]$panelFiles[$name]) }
foreach ($architecture in @('armv7','arm64')) { Build-Image $architecture $defaultFiles $panelFiles $buildInfo }

[IO.File]::WriteAllBytes((Join-Path $release 'PORTABLE-SETTINGS.json'), [byte[]]$defaults['portable-settings.json'])
@('01-install.rsc','02-enable-routing.rsc','03-disable-routing.rsc','04-uninstall.rsc') | ForEach-Object {
    Copy-Item -LiteralPath (Join-Path $root (Join-Path 'ready-to-copy\universal\universal-vpn' $_)) -Destination (Join-Path $release $_)
}

$changes = @(
    'Обновлены панель, маршрутизация, DNS и работа с GeoDAT; добавлена английская локализация панели.',
    'Загрузка GeoDAT выполняется в фоне с отображением скачанного объёма и состояния в очереди.',
    'HTML-страницы панели отдаются с запретом кэширования, чтобы браузер получал актуальную разметку.'
)
$changelog = "# $Version" + $newline + $newline + "Дата: $($now.ToString('dd.MM.yyyy HH:mm')) MSK. Релиз **0.32b** для ARMv7 и ARM64." + $newline + $newline + '## Изменения после 0.31b' + $newline + $newline + (($changes | ForEach-Object { '- ' + $_ }) -join $newline) + $newline + $newline + 'Сборка использует системные компоненты образов 0.31b и текущие исходники панели. VPN-профили, подписки и ключи в образы не включены.' + $newline
[IO.File]::WriteAllText((Join-Path $release 'CHANGELOG.md'), $changelog, $utf8)
$oldReadme = [IO.File]::ReadAllText((Join-Path $previous 'README.md'), $utf8)
$readme = $oldReadme.Replace('0.31b.191126.1600', $Version)
$readme = [regex]::Replace($readme, '(?s)## Что изменилось в 0\.31b\r?\n.*?(?=## Возможности конфигурации)', ('## Что изменилось в 0.32b' + $newline + $newline + (($changes | ForEach-Object { '- ' + $_ }) -join $newline) + $newline + $newline))
$readme = $readme.Replace('Изменения после 0.3b описаны в [CHANGELOG.md](CHANGELOG.md).', 'Изменения после 0.31b описаны в [CHANGELOG.md](CHANGELOG.md).')
[IO.File]::WriteAllText((Join-Path $release 'README.md'), $readme, $utf8)
$oldHtml = [IO.File]::ReadAllText((Join-Path $previous 'README.html'), $utf8)
$html = $oldHtml.Replace('0.31b.191126.1600', $Version)
$htmlChanges = ($changes | ForEach-Object { '<li>' + [System.Net.WebUtility]::HtmlEncode($_) + '</li>' }) -join ''
$html = [regex]::Replace($html, '(?s)<h2>Что изменилось в 0\.31b</h2><ul>.*?</ul>(?=<h2>Возможности конфигурации</h2>)', ('<h2>Что изменилось в 0.32b</h2><ul>' + $htmlChanges + '</ul>'))
[IO.File]::WriteAllText((Join-Path $release 'README.html'), $html, $utf8)

$buildInfo.validation = @{
    oci_and_elf = @{
        armv7 = @{ oci = 'generated'; architecture = 'armv7'; panel_modules = $panelFiles.Count; seed_rules = $services.Count }
        arm64 = @{ oci = 'generated'; architecture = 'arm64'; panel_modules = $panelFiles.Count; seed_rules = $services.Count }
    }
    vpn_profiles = 0; subscriptions = 0; arm64_hardware_boot_tested = $false
}
[IO.File]::WriteAllText((Join-Path $release 'BUILD-INFO.json'), ((ConvertTo-Json -InputObject $buildInfo -Depth 100) + $newline), $utf8)
$sumLines = foreach ($file in Get-ChildItem -LiteralPath $release -File | Sort-Object Name) {
    (Get-Sha256 ([IO.File]::ReadAllBytes($file.FullName))) + '  ' + $file.Name
}
[IO.File]::WriteAllText((Join-Path $release 'SHA256SUMS'), (($sumLines -join $newline) + $newline), [Text.Encoding]::ASCII)
Write-Output (ConvertTo-Json -InputObject @{ release = $release; panel_modules = $panelFiles.Count; rules = $services.Count; vpn_profiles = 0; subscriptions = 0; artifacts = (Get-ChildItem -LiteralPath $release -File | Measure-Object).Count } -Compress)
