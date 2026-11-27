param(
    [string]$WorkDir = (Join-Path $PSScriptRoot '..\build\mihomo-reality-build')
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$work = [System.IO.Path]::GetFullPath($WorkDir)
if (Test-Path -LiteralPath $work) {
    throw "Build directory already exists: $work"
}
New-Item -ItemType Directory -Path $work | Out-Null

$archive = Join-Path $work 'go1.26.11.windows-amd64.zip'
Invoke-WebRequest -Uri 'https://go.dev/dl/go1.26.11.windows-amd64.zip' -OutFile $archive
$digest = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
if ($digest -ne '71ae086f0137e665f855a811cc119152b6a783e0bbc1b906e709f46d80141eb0') {
    throw "Go archive SHA256 mismatch: $digest"
}
Expand-Archive -LiteralPath $archive -DestinationPath $work

$source = Join-Path $work 'mihomo'
git clone --depth 1 --branch v1.19.34 https://github.com/MetaCubeX/mihomo.git $source
if ($LASTEXITCODE -ne 0) { throw 'Cannot clone Mihomo source' }
Push-Location -LiteralPath $source
try {
    $commit = (git rev-parse HEAD).Trim()
    if ($commit -ne '0455d0d28c4526937380505153e65a843d8612e8') {
        throw "Unexpected Mihomo source commit: $commit"
    }
    $patch = Join-Path $root 'patches\mihomo-reality-client-version.patch'
    git apply --check $patch
    if ($LASTEXITCODE -ne 0) { throw 'REALITY patch cannot be applied' }
    git apply $patch
    if ($LASTEXITCODE -ne 0) { throw 'REALITY patch failed' }

    $env:GOMODCACHE = Join-Path $work 'gomodcache'
    $env:GOPATH = Join-Path $work 'gopath'
    & (Join-Path $work 'go\bin\go.exe') test ./adapter/outbound -run TestRealityClientVersion -count=1
    if ($LASTEXITCODE -ne 0) { throw 'REALITY patch test failed' }
    $env:GOOS = 'linux'
    $env:GOARCH = 'arm64'
    $env:CGO_ENABLED = '0'
    $flags = '-X github.com/metacubex/mihomo/constant.Version=v1.19.34 -X github.com/metacubex/mihomo/constant.BuildTime=uvpnc-reality-version -w -s'
    $output = Join-Path $work 'mihomo-reality-arm64'
    & (Join-Path $work 'go\bin\go.exe') build -tags with_gvisor -trimpath -ldflags $flags -o $output .
    if ($LASTEXITCODE -ne 0) { throw 'Mihomo build failed' }
    Get-FileHash -Algorithm SHA256 -LiteralPath $output | Select-Object Path, Hash
}
finally {
    Pop-Location
}
