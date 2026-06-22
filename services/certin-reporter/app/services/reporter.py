from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from app.models.report import CertInCategory, CertInReport, CertInReportRequest

logger = structlog.get_logger()

CERTIN_DEADLINE_HOURS = 6

CATEGORY_DESCRIPTIONS = {
    CertInCategory.CAT1: "Targeted Scanning/Probing of Critical Networks/Systems",
    CertInCategory.CAT2: "Compromise of Critical Systems/Information",
    CertInCategory.CAT3: "Unauthorised Access to IT Systems/Data",
    CertInCategory.CAT4: "Defacement of Website or Intrusion into a Website and Unauthorised Changes (incl. Malicious Code/Ransomware)",
    CertInCategory.CAT5: "Attacks on Servers such as Database, Mail and DNS and Network Devices such as Routers",
    CertInCategory.CAT6: "Identity Theft, Spoofing and Phishing Attacks",
    CertInCategory.CAT7: "Fake Mobile Apps",
    CertInCategory.CAT8: "Unauthorised Access to Social Media Accounts",
    CertInCategory.CAT9: "Attacks or Incident Affecting Digital Payment Systems",
    CertInCategory.CAT10: "Data Breach/Theft",
}

SECTOR_CONTACTS = {
    "healthcare_cni": {
        "ministry": "Ministry of Health & Family Welfare",
        "contact": "cybersecurity@mohfw.gov.in",
        "nciipc_sector": "Health",
    },
    "education_cni": {
        "ministry": "Ministry of Education",
        "contact": "cybersecurity@education.gov.in",
        "nciipc_sector": "Education",
    },
    "power_grid_cni": {
        "ministry": "Ministry of Power",
        "contact": "ciso@powergrid.in",
        "nciipc_sector": "Power",
    },
    "government_cni": {
        "ministry": "Ministry of Electronics and Information Technology",
        "contact": "incident@cert-in.org.in",
        "nciipc_sector": "Government",
    },
}


class CertInReporter:
    def __init__(self) -> None:
        self._reports: dict[str, CertInReport] = {}

    def generate_report(self, req: CertInReportRequest) -> CertInReport:
        now = datetime.now(UTC)
        deadline = now + timedelta(hours=CERTIN_DEADLINE_HOURS)
        hours_remaining = (deadline - now).total_seconds() / 3600
        report_id = f"CERTIN-{req.incident_id[:8].upper()}-{uuid.uuid4().hex[:6].upper()}"

        sector_info = SECTOR_CONTACTS.get(req.organisation_type.value, {})
        cat_desc = CATEGORY_DESCRIPTIONS.get(req.category, "Cybersecurity Incident")

        report_data: dict[str, Any] = {
            "form_type": "CERT-In Incident Report Form v3.0",
            "regulation": "CERT-In Directions 2022 under Section 70B of IT Act 2000",
            "report_id": report_id,
            "section_1_organisation": {
                "name": req.organisation_name,
                "type": req.organisation_type.value,
                "sector": req.organisation_sector or sector_info.get("nciipc_sector", ""),
                "ministry": sector_info.get("ministry", ""),
                "contact_email": "soc@organisation.gov.in",
                "classification": req.classification,
            },
            "section_2_incident": {
                "category_code": req.category.value,
                "category_description": cat_desc,
                "detection_datetime": now.isoformat(),
                "reporting_deadline": deadline.isoformat(),
                "severity": req.severity,
                "summary": req.incident_summary[:1000],
                "affected_systems": req.affected_systems,
            },
            "section_3_technical": {
                "mitre_techniques": req.mitre_techniques,
                "iocs_observed": req.iocs,
                "data_type_affected": req.data_type,
            },
            "section_4_impact": {
                "systems_affected_count": len(req.affected_systems),
                "data_compromised": bool(req.data_type),
                "services_disrupted": req.severity in ("high", "critical"),
                "estimated_impact": "Under investigation",
            },
            "section_5_actions": {
                "containment_actions": "Automated containment initiated via AiSOC",
                "evidence_preserved": True,
                "backup_status": "Emergency backup triggered",
            },
            "submission": {
                "certin_portal": "https://incident.cert-in.org.in",
                "email_fallback": "incident@cert-in.org.in",
                "nciipc_required": req.notify_nciipc,
                "nciipc_email": "incident@nciipc.gov.in" if req.notify_nciipc else None,
                "sector_ministry_email": sector_info.get("contact"),
            },
        }

        report = CertInReport(
            report_id=report_id,
            incident_id=req.incident_id,
            category=req.category,
            category_description=cat_desc,
            organisation_type=req.organisation_type.value,
            detection_timestamp=now,
            reporting_deadline=deadline,
            hours_remaining=round(hours_remaining, 2),
            deadline_breached=hours_remaining < 0,
            report_data=report_data,
        )

        self._reports[report_id] = report

        logger.info(
            "CERT-In report generated",
            report_id=report_id,
            category=req.category.value,
            hours_remaining=hours_remaining,
            deadline_breached=hours_remaining < 0,
        )
        return report

    def get_report(self, report_id: str) -> CertInReport | None:
        return self._reports.get(report_id)

    def list_reports(self) -> list[CertInReport]:
        return list(self._reports.values())

    def get_overdue_reports(self) -> list[CertInReport]:
        now = datetime.now(UTC)
        return [r for r in self._reports.values() if r.reporting_deadline < now and r.submitted_at is None]
