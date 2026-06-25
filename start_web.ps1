# ============================================================
#  AiSOC — Start the Web Console (Next.js on port 3000)
# ============================================================
#  Run this from anywhere:   .\start_web.ps1
#
#  If port 3000 is already in use (EADDRINUSE), this script
#  frees it first, then starts `pnpm dev`.
# ============================================================

$ErrorActionPreference = "Stop"
$webDir = Join-Path $PSScriptRoot "apps\web"

Write-Host "[AiSOC] Starting Web Console from $webDir" -ForegroundColor Cyan

# Free port 3000 if something is already listening on it.
$listener = Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue |
    Where-Object State -eq 'Listen'
if ($listener) {
    $procId = $listener.OwningProcess
    Write-Host "[AiSOC] Port 3000 busy — stopping PID $procId ..." -ForegroundColor Yellow
    Stop-Process -Id $procId -Force
}

Push-Location $webDir
try {
    Write-Host "[AiSOC] Launching Next.js on http://localhost:3000 ..." -ForegroundColor Green
    pnpm dev
}
finally {
    Pop-Location
}
