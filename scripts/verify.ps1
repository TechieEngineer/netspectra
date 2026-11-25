$ErrorActionPreference = 'Stop'
function Run-Checked($Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    if (!(Test-Path go.sum) -or !(Test-Path web/package-lock.json)) { throw 'Run scripts/bootstrap.ps1 first, then review and commit both lockfiles.' }
    Push-Location web
    try {
        Run-Checked npm.cmd @('ci')
        Run-Checked npm.cmd @('audit','--audit-level=moderate')
        Run-Checked npm.cmd @('run','build')
    } finally { Pop-Location }
    Run-Checked go @('mod','verify')
    Run-Checked go @('vet','./...')
    Run-Checked go @('test','-mod=readonly','-count=1','./...')
    Run-Checked go @('run','golang.org/x/vuln/cmd/govulncheck@latest','./...')
    New-Item -ItemType Directory -Force bin | Out-Null
    $previous = $env:CGO_ENABLED
    try {
        $env:CGO_ENABLED = '0'
        Run-Checked go @('build','-mod=readonly','-trimpath','-o','bin/netspectra.exe','./cmd/netspectra')
        Run-Checked './bin/netspectra.exe' @('--version')
    } finally { $env:CGO_ENABLED = $previous }
    Write-Host 'Local automated checks passed. Linux race, Docker, browser and independent review still required.'
} finally { Pop-Location }
