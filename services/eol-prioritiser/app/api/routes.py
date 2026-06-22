from __future__ import annotations

from fastapi import APIRouter

from app.models.asset import AssetRiskReport, AssetScanRequest
from app.services.prioritiser import prioritise_asset

router = APIRouter(prefix="/api/v1/eol")


@router.post("/scan", response_model=AssetRiskReport)
async def scan_asset(req: AssetScanRequest) -> AssetRiskReport:
    """Scan an asset for EoL software and return amplified CVE risk report."""
    return prioritise_asset(req)


@router.post("/scan/bulk", response_model=list[AssetRiskReport])
async def scan_bulk(assets: list[AssetScanRequest]) -> list[AssetRiskReport]:
    """Scan multiple assets and return risk-ranked remediation queue."""
    results = [prioritise_asset(a) for a in assets]
    results.sort(key=lambda r: r.max_amplified_cvss, reverse=True)
    return results


@router.get("/catalog")
async def get_eol_catalog() -> dict:
    """Return the EoL software catalog used for amplification."""
    from app.services.prioritiser import EOL_CATALOG
    return {
        "catalog": EOL_CATALOG,
        "total_entries": len(EOL_CATALOG),
        "india_context": "India govt networks: >70% EoL rate per National Cyber Security Policy 2023",
        "amplification_rationale": "EoL assets receive no security patches; any CVE is permanently unmitigatable",
    }
