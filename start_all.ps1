# ============================================================
#  AiSOC — Start the full local stack
# ============================================================
#  Opens 3 PowerShell windows:
#    1. Core API     → http://localhost:8000  (poetry)
#    2. Agents svc   → http://localhost:8001  (poetry)
#    3. Web console  → http://localhost:3000  (pnpm)
#
#  Run:   .\start_all.ps1
#  Then open http://localhost:3000  (admin@demo.local / admin)
# ============================================================

$root = $PSScriptRoot

Write-Host "[AiSOC] Launching full stack in separate windows ..." -ForegroundColor Cyan

Start-Process powershell -ArgumentList "-NoExit", "-File", (Join-Path $root "start_api.ps1")
Start-Process powershell -ArgumentList "-NoExit", "-File", (Join-Path $root "start_agents.ps1")
Start-Process powershell -ArgumentList "-NoExit", "-File", (Join-Path $root "start_web.ps1")

Write-Host "[AiSOC] All three services launching." -ForegroundColor Green
Write-Host "        API    : http://localhost:8000/api/docs" -ForegroundColor Gray
Write-Host "        Agents : http://localhost:8001/docs" -ForegroundColor Gray
Write-Host "        Web    : http://localhost:3000" -ForegroundColor Gray
Write-Host "        Login  : admin@demo.local / admin" -ForegroundColor Gray
