[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    if ($env:SKIP_VERIFY -ne '1') { & (Join-Path $PSScriptRoot 'verify.ps1') }
    cargo build --workspace --release --locked
    if ($LASTEXITCODE -ne 0) { throw 'Release workspace build failed' }
    $version = (Get-Content -Raw VERSION).Trim()
    Write-Output "TokenSaver Plugin SDK $version release workspace built"
} finally { Pop-Location }
