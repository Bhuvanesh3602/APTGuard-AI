# ============================================================
#  AiSOC — Start the Agents service (LangGraph, port 8001)
# ============================================================
#  Owns: playbooks, hunt search, copilot chat, contextual
#  actions, investigation runs. The web app proxies
#  /api/v1/playbooks, /api/v1/hunt, /api/v1/copilot, etc. here.
#
#  Run:   .\start_agents.ps1
# ============================================================

$ErrorActionPreference = "Stop"
$agentsDir = Join-Path $PSScriptRoot "services\agents"

Write-Host "[AiSOC] Starting Agents service from $agentsDir" -ForegroundColor Cyan

# Free port 8001 if already in use.
$c = Get-NetTCPConnection -LocalPort 8001 -ErrorAction SilentlyContinue |
    Where-Object State -eq 'Listen'
if ($c) {
    Write-Host "[AiSOC] Port 8001 busy — stopping PID $($c.OwningProcess) ..." -ForegroundColor Yellow
    Stop-Process -Id $c.OwningProcess -Force
}

Push-Location $agentsDir
try {
    Write-Host "[AiSOC] Syncing dependencies (poetry install) ..." -ForegroundColor DarkGray
    poetry install --without dev --no-interaction

    Write-Host "[AiSOC] Launching agents on http://localhost:8001 ..." -ForegroundColor Green
    poetry run uvicorn app.main:app --reload --port 8001 --host 0.0.0.0 --env-file .env
}
finally {
    Pop-Location
}
