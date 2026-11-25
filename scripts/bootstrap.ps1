$ErrorActionPreference = 'Stop'
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    go mod tidy
    if ($LASTEXITCODE -ne 0) { throw 'Go dependency resolution failed' }
    Push-Location web
    try {
        npm.cmd install
        if ($LASTEXITCODE -ne 0) { throw 'npm dependency resolution failed' }
    } finally { Pop-Location }
    Write-Host 'Review go.sum and web/package-lock.json. Run scripts/verify.ps1 before publishing.'
} finally { Pop-Location }
