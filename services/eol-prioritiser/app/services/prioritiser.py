"""
EoL Asset Vulnerability Prioritisation Engine.

Amplifies CVE severity scores for End-of-Life assets.
India CNI context: >70% of government entities run EoL IT (NCSP 2023).
"""

from __future__ import annotations

import structlog

from app.models.asset import AssetRiskReport, AssetScanRequest, EoLFinding, RemediationItem

logger = structlog.get_logger()

EOL_CATALOG = {
    "windows xp": {"eol_date": "2014-04-08", "amplifier": 2.5},
    "windows 7": {"eol_date": "2020-01-14", "amplifier": 2.2},
    "windows server 2003": {"eol_date": "2015-07-14", "amplifier": 2.5},
    "windows server 2008": {"eol_date": "2020-01-14", "amplifier": 2.2},
    "windows server 2012": {"eol_date": "2023-10-10", "amplifier": 1.8},
    "centos 6": {"eol_date": "2020-11-30", "amplifier": 2.0},
    "centos 7": {"eol_date": "2024-06-30", "amplifier": 1.6},
    "ubuntu 16.04": {"eol_date": "2021-04-30", "amplifier": 1.9},
    "ubuntu 18.04": {"eol_date": "2023-05-31", "amplifier": 1.7},
    "rhel 6": {"eol_date": "2020-11-30", "amplifier": 2.0},
    "oracle 11g": {"eol_date": "2020-12-31", "amplifier": 2.0},
    "mysql 5.6": {"eol_date": "2021-02-05", "amplifier": 1.8},
    "sql server 2008": {"eol_date": "2019-07-09", "amplifier": 2.2},
    "sql server 2012": {"eol_date": "2022-07-12", "amplifier": 1.9},
    "iis 6": {"eol_date": "2015-07-14", "amplifier": 2.5},
    "iis 7": {"eol_date": "2020-01-14", "amplifier": 2.2},
    "apache 2.2": {"eol_date": "2017-12-31", "amplifier": 2.3},
    "tomcat 6": {"eol_date": "2016-12-31", "amplifier": 2.3},
    "tomcat 7": {"eol_date": "2021-03-31", "amplifier": 1.8},
    "jdk 8": {"eol_date": "2022-03-31", "amplifier": 1.6},
    "cisco ios 12": {"eol_date": "2016-01-29", "amplifier": 2.4},
    "siemens s7-300": {"eol_date": "2023-10-01", "amplifier": 2.0},
    "scada wincc 7.0": {"eol_date": "2019-03-31", "amplifier": 2.3},
}

SEVERITY_RANGES = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
]


def _cvss_to_severity(score: float) -> str:
    for threshold, label in SEVERITY_RANGES:
        if score >= threshold:
            return label
    return "informational"


def _detect_eol(software_list: list[str], os_name: str) -> list[tuple[str, dict]]:
    all_software = [s.lower() for s in software_list] + [os_name.lower()]
    found = []
    for product, info in EOL_CATALOG.items():
        if any(product in s for s in all_software):
            found.append((product, info))
    return found


def _build_report(
    req: AssetScanRequest,
    base_cvss: float,
    known_exploited: bool,
    cve_intelligence: dict | None,
    cvss_source: str,
) -> AssetRiskReport:
    """Core EoL amplification scorer over a (possibly feed-derived) base CVSS."""
    eol_assets = _detect_eol(req.software, req.os_name)
    findings: list[EoLFinding] = []
    items: list[RemediationItem] = []

    if req.is_internet_facing:
        base_cvss = min(10.0, base_cvss * 1.3)
    if req.is_ot_asset:
        base_cvss = min(10.0, base_cvss * 1.5)
    # Actively exploited in the wild (CISA KEV) → amplify before EoL factor.
    if known_exploited:
        base_cvss = min(10.0, base_cvss * 1.25)

    for product, info in eol_assets:
        amplifier = info["amplifier"]
        amplified = min(10.0, base_cvss * amplifier)
        orig_sev = _cvss_to_severity(base_cvss)
        amp_sev = _cvss_to_severity(amplified)

        kev_clause = (
            " ACTIVELY EXPLOITED (CISA KEV) — treat as emergency." if known_exploited else ""
        )
        finding = EoLFinding(
            product=product,
            eol_date=info["eol_date"],
            base_cvss=round(base_cvss, 1),
            amplified_cvss=round(amplified, 1),
            amplifier=amplifier,
            original_severity=orig_sev,
            amplified_severity=amp_sev,
            patch_available=False,
            known_exploited=known_exploited,
            recommendation=(
                f"REPLACE or ISOLATE {product} (EoL {info['eol_date']}) — "
                "no security patches will be released. "
                f"Emergency network segmentation until replacement.{kev_clause}"
            ),
        )
        findings.append(finding)

        urgency = "IMMEDIATE" if (amplified >= 9.0 or known_exploited) else ("HIGH" if amplified >= 7.0 else "MEDIUM")
        items.append(RemediationItem(
            rank=0,
            hostname=req.hostname,
            ip_address=req.ip_address,
            finding=finding,
            risk_score=amplified,
            action=f"Replace {product} or apply emergency network segmentation",
            urgency=urgency,
        ))

    items.sort(key=lambda x: x.risk_score, reverse=True)
    for i, item in enumerate(items):
        item.rank = i + 1

    max_cvss = max((f.amplified_cvss for f in findings), default=0.0)

    logger.info(
        "EoL prioritisation complete",
        hostname=req.hostname,
        eol_count=len(findings),
        max_amplified_cvss=max_cvss,
        known_exploited=known_exploited,
        cvss_source=cvss_source,
    )

    return AssetRiskReport(
        hostname=req.hostname,
        ip_address=req.ip_address,
        sector=req.sector,
        eol_findings=findings,
        max_amplified_cvss=max_cvss,
        overall_risk=_cvss_to_severity(max_cvss),
        remediation_items=items,
        known_exploited=known_exploited,
        cve_intelligence=cve_intelligence,
        cvss_source=cvss_source,
    )


def prioritise_asset(req: AssetScanRequest) -> AssetRiskReport:
    """Synchronous scorer using the caller-supplied base CVSS (no live feed)."""
    return _build_report(req, req.base_cvss, False, None, "caller_supplied")


async def prioritise_asset_live(req: AssetScanRequest) -> AssetRiskReport:
    """
    Score an asset using live CVE intelligence when ``cve_ids`` are supplied:
    the base CVSS comes from NVD and the known-exploited flag from CISA KEV.
    Falls back to the caller-supplied base when no CVEs are given or the feed
    yields nothing.
    """
    if not (req.use_live_feed and req.cve_ids):
        return prioritise_asset(req)

    from app.services.cve_feed import get_cve_feed

    feed = get_cve_feed()
    intel = await feed.enrich_cves(req.cve_ids)

    effective_base = intel.get("max_base_cvss")
    if effective_base is None:
        effective_base = req.base_cvss
        cvss_source = "caller_supplied_feed_miss"
    else:
        # Mixed sources possible; label by the strongest available.
        sources = {d.get("source") for d in intel.get("details", [])}
        cvss_source = "nvd_live" if "nvd_live" in sources else (
            "offline_snapshot" if "offline_snapshot" in sources else "caller_supplied"
        )

    return _build_report(
        req,
        effective_base,
        intel.get("any_known_exploited", False),
        cve_intelligence=intel,
        cvss_source=cvss_source,
    )
