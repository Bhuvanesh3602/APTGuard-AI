from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class CertInCategory(str, Enum):
    CAT1 = "CAT-1"   # Targeted scanning/probing
    CAT2 = "CAT-2"   # Compromise of critical systems
    CAT3 = "CAT-3"   # Unauthorised access
    CAT4 = "CAT-4"   # Malicious code / ransomware
    CAT5 = "CAT-5"   # Identity theft / phishing
    CAT6 = "CAT-6"   # Fake mobile apps
    CAT7 = "CAT-7"   # Unauthorised social media
    CAT8 = "CAT-8"   # DDoS
    CAT9 = "CAT-9"   # Data breach
    CAT10 = "CAT-10"  # Critical infrastructure attack


class OrganisationType(str, Enum):
    HEALTHCARE_CNI = "healthcare_cni"
    EDUCATION_CNI = "education_cni"
    POWER_GRID_CNI = "power_grid_cni"
    GOVERNMENT_CNI = "government_cni"
    FINANCIAL = "financial"
    TELECOM = "telecom"
    GENERAL = "general"


class CertInReportRequest(BaseModel):
    category: CertInCategory
    incident_id: str
    organisation_type: OrganisationType = OrganisationType.GENERAL
    organisation_name: str = "CNI Organisation"
    organisation_sector: str = ""
    affected_systems: list[str] = Field(default_factory=list)
    incident_summary: str = ""
    severity: str = "high"
    mitre_techniques: list[str] = Field(default_factory=list)
    iocs: list[dict[str, Any]] = Field(default_factory=list)
    data_type: str = ""
    classification: str = "RESTRICTED"
    notify_nciipc: bool = False
    notify_cert_in: bool = True
    deadline_hours: int = 6


class CertInReport(BaseModel):
    report_id: str
    incident_id: str
    category: CertInCategory
    category_description: str
    organisation_type: str
    detection_timestamp: datetime
    reporting_deadline: datetime
    hours_remaining: float
    deadline_breached: bool
    report_status: str = "generated"
    submitted_at: datetime | None = None
    submission_reference: str | None = None
    report_data: dict[str, Any] = Field(default_factory=dict)
