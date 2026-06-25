from __future__ import annotations

from fastapi import APIRouter

from app.models.asset import AssetRiskReport, AssetScanRequest
from app.services.prioritiser import prioritise_asset, prioritise_asset_live

router = APIRouter(prefix="/api/v1/eol")


@router.post("/scan", response_model=AssetRiskReport)
async def scan_asset(req: AssetScanRequest) -> AssetRiskReport:
    """Scan an asset for EoL software and return amplified CVE risk report.

    When ``cve_ids`` are supplied (and ``use_live_feed`` is on) the base CVSS
    is pulled from NVD and the known-exploited flag from CISA KEV.
    """
    return await prioritise_asset_live(req)


@router.post("/scan/bulk", response_model=list[AssetRiskReport])
async def scan_bulk(assets: list[AssetScanRequest]) -> list[AssetRiskReport]:
    """Scan multiple assets and return a risk-ranked remediation queue."""
    results = [await prioritise_asset_live(a) for a in assets]
    results.sort(key=lambda r: (r.known_exploited, r.max_amplified_cvss), reverse=True)
    return results


@router.get("/cve/{cve_id}")
async def lookup_cve(cve_id: str) -> dict:
    """Live CVE lookup: NVD base score + CISA KEV known-exploited status."""
    from app.services.cve_feed import get_cve_feed

    return await get_cve_feed().lookup_cve(cve_id)


@router.get("/kev/status")
async def kev_status() -> dict:
    """Whether the CISA KEV catalog is loaded, its size, and its source."""
    from app.services.cve_feed import get_cve_feed

    return get_cve_feed().kev_status()


@router.post("/kev/refresh")
async def kev_refresh(force: bool = True) -> dict:
    """Force a refresh of the CISA KEV catalog from the live feed."""
    from app.services.cve_feed import get_cve_feed

    return await get_cve_feed().refresh_kev(force=force)


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
