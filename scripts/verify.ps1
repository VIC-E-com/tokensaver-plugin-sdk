[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    python scripts/check-version.py
    if ($LASTEXITCODE -ne 0) { throw 'version check failed' }
    cargo test --workspace --locked
    if ($LASTEXITCODE -ne 0) { throw 'Rust tests failed' }
    cargo clippy --workspace --all-targets --locked -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'Rust Clippy failed' }
    cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw 'Rust formatting failed' }

    Push-Location sdk/go/tokensaverplugin
    try {
        go test -race ./...
        if ($LASTEXITCODE -ne 0) { throw 'Go tests failed' }
        go vet ./...
        if ($LASTEXITCODE -ne 0) { throw 'Go vet failed' }
        $unformatted = @(gofmt -l .)
        if ($unformatted.Count -ne 0) { throw "Unformatted Go files: $($unformatted -join ', ')" }
    } finally { Pop-Location }

    Push-Location sdk/python
    try {
        python -m unittest discover -s tests -v
        if ($LASTEXITCODE -ne 0) { throw 'Python tests failed' }
    } finally { Pop-Location }

    Push-Location sdk/typescript/tokensaver-plugin
    try {
        npm ci --ignore-scripts --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
        npm test
        if ($LASTEXITCODE -ne 0) { throw 'TypeScript runtime tests failed' }
        npm run check
        if ($LASTEXITCODE -ne 0) { throw 'TypeScript checks failed' }
    } finally { Pop-Location }

    python -m unittest discover -s scripts -p 'test_*.py' -v
    if ($LASTEXITCODE -ne 0) { throw 'Runtime-host verifier tests failed' }
} finally { Pop-Location }
