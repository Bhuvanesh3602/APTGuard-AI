from __future__ import annotations

from pydantic import BaseModel, Field


class AssetScanRequest(BaseModel):
    hostname: str
    ip_address: str
    os_name: str = ""
    os_version: str = ""
    software: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    base_cvss: float = 5.0
    sector: str = "general"
    is_internet_facing: bool = False
    is_ot_asset: bool = False
    # When cve_ids are supplied, pull the real CVSS base score from NVD and
    # the known-exploited flag from CISA KEV instead of using base_cvss.
    use_live_feed: bool = True


class EoLFinding(BaseModel):
    product: str
    eol_date: str
    base_cvss: float
    amplified_cvss: float
    amplifier: float
    original_severity: str
    amplified_severity: str
    patch_available: bool = False
    recommendation: str
    known_exploited: bool = False


class RemediationItem(BaseModel):
    rank: int
    hostname: str
    ip_address: str
    finding: EoLFinding
    risk_score: float
    action: str
    urgency: str


class AssetRiskReport(BaseModel):
    hostname: str
    ip_address: str
    sector: str
    eol_findings: list[EoLFinding]
    max_amplified_cvss: float
    overall_risk: str
    remediation_items: list[RemediationItem]
    india_context: str = "India govt networks: >70% EoL rate (NCSP 2023)"
    known_exploited: bool = False
    cve_intelligence: dict | None = None
    cvss_source: str = "caller_supplied"
