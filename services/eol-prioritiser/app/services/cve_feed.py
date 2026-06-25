"""
Live CVE feed: NVD (CVSS base scores) + CISA KEV (known-exploited catalog).

The EoL prioritiser amplifies CVE severity for end-of-life assets. Previously
the base CVSS was whatever the caller passed in. This module pulls the score
from authoritative live feeds and adds a crucial signal government teams need
for triage: **is this CVE being actively exploited in the wild?** (CISA's
Known Exploited Vulnerabilities catalog). A KEV hit is the single strongest
"patch this first" indicator — and on an EoL asset that can never be patched,
it is the strongest "isolate this now" indicator.

Sources:
  * CISA KEV   — one JSON catalog, refreshed periodically and cached whole.
  * NVD CVE API — per-CVE CVSS lookup (v3.1 → v3.0 → v2 fallback), cached.

Both degrade gracefully to a small bundled offline snapshot covering the
CVEs used in the demo scenarios, so the service produces real scores even
with no internet access. Nothing here raises into the request path.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_KEV_TTL = 6 * 3600  # refresh KEV catalog every 6h
_NVD_TTL = 24 * 3600  # cache per-CVE NVD lookups for 24h

# ── Offline fallback snapshot (demo CVEs) ───────────────────────────────────
# Used when the live feeds are unreachable. Scores are the published NVD base
# scores; KEV membership reflects the real CISA catalog at time of writing.
_OFFLINE_CVE: dict[str, dict[str, Any]] = {
    "CVE-2017-0144": {"base_cvss": 8.1, "severity": "high", "kev": True, "name": "EternalBlue SMBv1 RCE"},
    "CVE-2019-0708": {"base_cvss": 9.8, "severity": "critical", "kev": True, "name": "BlueKeep RDP RCE"},
    "CVE-2020-0796": {"base_cvss": 10.0, "severity": "critical", "kev": True, "name": "SMBGhost"},
    "CVE-2021-44228": {"base_cvss": 10.0, "severity": "critical", "kev": True, "name": "Log4Shell"},
    "CVE-2021-34527": {"base_cvss": 8.8, "severity": "high", "kev": True, "name": "PrintNightmare"},
    "CVE-2021-41773": {"base_cvss": 7.5, "severity": "high", "kev": True, "name": "Apache 2.4.49 path traversal"},
    "CVE-2023-22809": {"base_cvss": 7.8, "severity": "high", "kev": False, "name": "sudo -e privilege escalation"},
    "CVE-2017-5638": {"base_cvss": 10.0, "severity": "critical", "kev": True, "name": "Apache Struts2 RCE"},
    "CVE-2014-0160": {"base_cvss": 7.5, "severity": "high", "kev": False, "name": "Heartbleed"},
}

_OFFLINE_KEV = {cve for cve, meta in _OFFLINE_CVE.items() if meta["kev"]}


def _severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "none"


class CVEFeed:
    def __init__(self, nvd_api_key: str | None = None, timeout: float = 10.0) -> None:
        self._nvd_api_key = nvd_api_key
        self._timeout = timeout
        self._kev: set[str] = set()
        self._kev_meta: dict[str, dict[str, Any]] = {}
        self._kev_loaded_at: float = 0.0
        self._kev_source: str = "none"
        self._nvd_cache: dict[str, tuple[float, dict[str, Any]]] = {}

    # ── CISA KEV ──────────────────────────────────────────────────────────

    async def refresh_kev(self, force: bool = False) -> dict[str, Any]:
        """Fetch the CISA KEV catalog. Falls back to the offline snapshot."""
        fresh = (time.time() - self._kev_loaded_at) < _KEV_TTL
        if self._kev and fresh and not force:
            return self.kev_status()

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(KEV_URL)
            resp.raise_for_status()
            data = resp.json()
            kev: set[str] = set()
            meta: dict[str, dict[str, Any]] = {}
            for v in data.get("vulnerabilities", []):
                cve = v.get("cveID")
                if not cve:
                    continue
                kev.add(cve)
                meta[cve] = {
                    "vendor": v.get("vendorProject"),
                    "product": v.get("product"),
                    "name": v.get("vulnerabilityName"),
                    "date_added": v.get("dateAdded"),
                    "ransomware": v.get("knownRansomwareCampaignUse"),
                }
            self._kev = kev
            self._kev_meta = meta
            self._kev_loaded_at = time.time()
            self._kev_source = "cisa_live"
            logger.info("cve_feed.kev_refreshed", count=len(kev), source="cisa_live")
        except Exception as exc:  # noqa: BLE001
            # Keep any previously loaded catalog; otherwise use offline snapshot.
            if not self._kev:
                self._kev = set(_OFFLINE_KEV)
                self._kev_meta = {
                    c: {"name": _OFFLINE_CVE[c]["name"], "vendor": None, "product": None,
                        "date_added": None, "ransomware": None}
                    for c in _OFFLINE_KEV
                }
                self._kev_loaded_at = time.time()
                self._kev_source = "offline_snapshot"
            logger.warning("cve_feed.kev_refresh_failed", error=str(exc), source=self._kev_source)
        return self.kev_status()

    def kev_status(self) -> dict[str, Any]:
        return {
            "loaded": bool(self._kev),
            "count": len(self._kev),
            "source": self._kev_source,
            "last_refreshed_epoch": round(self._kev_loaded_at, 0) if self._kev_loaded_at else None,
            "ttl_seconds": _KEV_TTL,
        }

    async def is_known_exploited(self, cve_id: str) -> bool:
        if not self._kev:
            await self.refresh_kev()
        return cve_id.upper() in self._kev

    # ── NVD lookup ────────────────────────────────────────────────────────

    async def lookup_cve(self, cve_id: str) -> dict[str, Any]:
        cve_id = cve_id.upper().strip()
        cached = self._nvd_cache.get(cve_id)
        if cached and (time.time() - cached[0]) < _NVD_TTL:
            return cached[1]

        known_exploited = await self.is_known_exploited(cve_id)
        result = await self._lookup_nvd(cve_id)
        if result is None:
            offline = _OFFLINE_CVE.get(cve_id)
            if offline:
                result = {
                    "cve_id": cve_id,
                    "base_cvss": offline["base_cvss"],
                    "severity": offline["severity"],
                    "source": "offline_snapshot",
                    "vector": None,
                    "name": offline["name"],
                }
            else:
                result = {
                    "cve_id": cve_id,
                    "base_cvss": None,
                    "severity": "unknown",
                    "source": "unknown",
                    "vector": None,
                    "name": None,
                }

        result["known_exploited"] = known_exploited
        if known_exploited and cve_id in self._kev_meta:
            result["kev_meta"] = self._kev_meta[cve_id]

        self._nvd_cache[cve_id] = (time.time(), result)
        return result

    async def _lookup_nvd(self, cve_id: str) -> dict[str, Any] | None:
        headers = {"apiKey": self._nvd_api_key} if self._nvd_api_key else {}
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(NVD_URL, params={"cveId": cve_id}, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None
            cve = vulns[0].get("cve", {})
            metrics = cve.get("metrics", {})
            score, severity, vector = self._extract_cvss(metrics)
            if score is None:
                return None
            return {
                "cve_id": cve_id,
                "base_cvss": score,
                "severity": severity or _severity(score),
                "source": "nvd_live",
                "vector": vector,
                "name": cve_id,
            }
        except Exception as exc:  # noqa: BLE001
            logger.debug("cve_feed.nvd_lookup_failed", cve=cve_id, error=str(exc))
            return None

    @staticmethod
    def _extract_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                data = entries[0].get("cvssData", {})
                score = data.get("baseScore")
                severity = entries[0].get("baseSeverity") or data.get("baseSeverity")
                vector = data.get("vectorString")
                if score is not None:
                    return float(score), (severity.lower() if severity else None), vector
        return None, None, None

    # ── batch enrichment ──────────────────────────────────────────────────

    async def enrich_cves(self, cve_ids: list[str]) -> dict[str, Any]:
        """Look up several CVEs and summarise the worst-case for scoring."""
        details = [await self.lookup_cve(c) for c in cve_ids]
        scored = [d for d in details if d.get("base_cvss") is not None]
        max_cvss = max((d["base_cvss"] for d in scored), default=None)
        any_kev = any(d.get("known_exploited") for d in details)
        return {
            "details": details,
            "max_base_cvss": max_cvss,
            "any_known_exploited": any_kev,
            "kev_count": sum(1 for d in details if d.get("known_exploited")),
            "kev_status": self.kev_status(),
        }


_singleton: CVEFeed | None = None


def get_cve_feed() -> CVEFeed:
    global _singleton
    if _singleton is None:
        import os

        _singleton = CVEFeed(nvd_api_key=os.getenv("NVD_API_KEY"))
    return _singleton
