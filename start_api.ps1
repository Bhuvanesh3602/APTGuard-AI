# ============================================================
#  AiSOC — Start the Core API (FastAPI on port 8000)
# ============================================================
#  Run this from anywhere:   .\start_api.ps1
#
#  Do NOT use `pip install -e` or plain `uvicorn` for this
#  service: pyproject.toml sets `package-mode = false`, so it
#  is a Poetry-managed application, not a pip package. The
#  dependencies live in Poetry's virtualenv and are launched
#  with `poetry run`.
# ============================================================

$ErrorActionPreference = "Stop"
$apiDir = Join-Path $PSScriptRoot "services\api"

Write-Host "[AiSOC] Starting Core API from $apiDir" -ForegroundColor Cyan

# Ensure dependencies are present in Poetry's venv (fast no-op if already installed).
Push-Location $apiDir
try {
    Write-Host "[AiSOC] Syncing dependencies (poetry install) ..." -ForegroundColor DarkGray
    poetry install --without dev --no-interaction

    Write-Host "[AiSOC] Launching uvicorn on http://localhost:8000 ..." -ForegroundColor Green
    poetry run uvicorn app.main:app --reload --port 8000 --host 0.0.0.0 --env-file .env
}
finally {
    Pop-Location
}
