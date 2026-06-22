"""
CERT-In 6-Hour Compliance Agent.

Under the CERT-In Directions 2022 (amended 2023), Indian organisations must
report cybersecurity incidents to CERT-In within 6 hours of detection.
This agent automatically generates the mandatory incident report, calculates
the filing deadline, and flags if the deadline is at risk.

CERT-In reportable incident types (per Directions 2022):
- Targeted scanning/probing of critical networks
- Compromise of critical systems
- Unauthorised access to IT systems
- Defacement of websites
- Malicious code attacks
- Attacks on Internet infrastructure
- Identity theft / fraud
- Denial of Service / DDoS attacks
- Data breaches involving personal data
- Attacks on critical infrastructure (power, telecom, transport)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import structlog

from app.models.state import ActionRisk, AgentStatus, InvestigationState, ProposedAction

logger = structlog.get_logger()

CERTIN_DEADLINE_HOURS = 6

# CERT-In incident categories per Directions 2022
CERTIN_CATEGORIES = {
    "ransomware": {
        "code": "CAT-4",
        "description": "Malicious Code Attack (Ransomware)",
        "mandatory": True,
        "severity_threshold": "medium",
    },
    "data_breach": {
        "code": "CAT-9",
        "description": "Data Breach / Theft of Data",
        "mandatory": True,
        "severity_threshold": "low",
    },
    "apt": {
        "code": "CAT-2",
        "description": "Compromise of Critical Systems/Information",
        "mandatory": True,
        "severity_threshold": "medium",
    },
    "ddos": {
        "code": "CAT-8",
        "description": "Attacks on Internet Infrastructure / DDoS",
        "mandatory": True,
        "severity_threshold": "medium",
    },
    "unauthorized_access": {
        "code": "CAT-3",
        "description": "Unauthorised Access to IT Systems",
        "mandatory": True,
        "severity_threshold": "low",
    },
    "website_defacement": {
        "code": "CAT-4",
        "description": "Website Defacement",
        "mandatory": True,
        "severity_threshold": "low",
    },
    "critical_infra": {
        "code": "CAT-10",
        "description": "Attacks on Critical Infrastructure",
        "mandatory": True,
        "severity_threshold": "low",
    },
    "phishing": {
        "code": "CAT-5",
        "description": "Attacks on Identity / Phishing / Spoofing",
        "mandatory": True,
        "severity_threshold": "medium",
    },
    "scanning": {
        "code": "CAT-1",
        "description": "Targeted Scanning/Probing of Critical Networks",
        "mandatory": False,
        "severity_threshold": "high",
    },
}

# Keywords → CERT-In category mapping
_CATEGORY_KEYWORDS = {
    "ransomware": "ransomware",
    "encrypt": "ransomware",
    "lockbit": "ransomware",
    "data breach": "data_breach",
    "exfil": "data_breach",
    "pii": "data_breach",
    "personal data": "data_breach",
    "apt": "apt",
    "advanced persistent": "apt",
    "sidecopy": "apt",
    "apt36": "apt",
    "lazarus": "apt",
    "ddos": "ddos",
    "denial of service": "ddos",
    "defacement": "website_defacement",
    "defaced": "website_defacement",
    "phishing": "phishing",
    "spear": "phishing",
    "scada": "critical_infra",
    "modbus": "critical_infra",
    "ot attack": "critical_infra",
    "power grid": "critical_infra",
    "unauthorized": "unauthorized_access",
    "brute force": "unauthorized_access",
    "credential": "unauthorized_access",
    "scanning": "scanning",
    "probing": "scanning",
}


def _classify_certin_category(state: InvestigationState) -> str:
    text = (state.alert_summary + " " + str(state.raw_alert)).lower()
    for keyword, category in _CATEGORY_KEYWORDS.items():
        if keyword in text:
            return category
    return "unauthorized_access"  # default


def _is_reportable(category: str, severity: str) -> bool:
    cat_info = CERTIN_CATEGORIES.get(category, {})
    threshold = cat_info.get("severity_threshold", "high")
    severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return severity_rank.get(severity, 2) >= severity_rank.get(threshold, 3)


def _generate_certin_report(state: InvestigationState, category: str, detection_time: datetime) -> dict:
    cat_info = CERTIN_CATEGORIES.get(category, {})
    raw = state.raw_alert
    deadline = detection_time + timedelta(hours=CERTIN_DEADLINE_HOURS)
    now = datetime.now(UTC)
    hours_remaining = (deadline - now).total_seconds() / 3600

    return {
        "report_id": f"CERTIN-{str(state.incident_id)[:8].upper()}",
        "incident_category": cat_info.get("code", "CAT-3"),
        "category_description": cat_info.get("description", "Cybersecurity Incident"),
        "detection_timestamp": detection_time.isoformat(),
        "reporting_deadline": deadline.isoformat(),
        "hours_remaining": round(hours_remaining, 1),
        "deadline_breached": hours_remaining < 0,
        "organisation": raw.get("tenant_name", "CNI Organisation"),
        "affected_systems": raw.get("hostname", raw.get("src_ip", "Unknown")),
        "incident_summary": state.alert_summary[:500],
        "severity": raw.get("severity", "high"),
        "mitre_techniques": state.mitre_mappings,
        "iocs_observed": [
            raw.get("src_ip"),
            raw.get("dst_ip"),
            raw.get("domain"),
            raw.get("file_hash"),
        ],
        "impact_assessment": {
            "data_compromised": "under_investigation",
            "systems_affected": 1,
            "services_disrupted": raw.get("severity", "medium") in ("high", "critical"),
        },
        "reporter": {
            "name": "AiSOC Automated Reporting System",
            "email": "soc@organisation.gov.in",
            "phone": "+91-XXXXXXXXXX",
        },
        "certin_portal": "https://incident.cert-in.org.in",
        "regulation": "CERT-In Directions 2022 under Section 70B of IT Act 2000",
    }


async def run_certin_compliance(state: InvestigationState) -> InvestigationState:
    """Generate CERT-In mandatory incident report and track 6-hour deadline."""
    logger.info("CERT-In compliance agent starting", incident_id=str(state.incident_id))
    state.iteration_count += 1

    raw = state.raw_alert
    severity = raw.get("severity", "medium").lower()
    detection_time = datetime.now(UTC)

    category = _classify_certin_category(state)
    cat_info = CERTIN_CATEGORIES.get(category, {})

    state.add_finding(
        f"CERT-In compliance check: incident category {cat_info.get('code', 'CAT-?')} — "
        f"{cat_info.get('description', 'Unknown')}"
    )

    if not _is_reportable(category, severity):
        state.add_finding(
            f"CERT-In: incident below mandatory reporting threshold "
            f"(category={category}, severity={severity}) — voluntary reporting recommended."
        )
        state.threat_intel["certin_compliance"] = {
            "mandatory_reporting": False,
            "category": category,
            "severity": severity,
        }
        return state

    report = _generate_certin_report(state, category, detection_time)
    deadline = detection_time + timedelta(hours=CERTIN_DEADLINE_HOURS)
    hours_remaining = report["hours_remaining"]

    state.add_finding(
        f"CERT-In MANDATORY REPORTING REQUIRED: {cat_info.get('code')} — "
        f"{cat_info.get('description')} | "
        f"Deadline: {deadline.strftime('%Y-%m-%d %H:%M UTC')} "
        f"({hours_remaining:.1f}h remaining)"
    )

    if hours_remaining < 2:
        state.add_finding(
            f"CERT-In DEADLINE CRITICAL: only {hours_remaining:.1f} hours remaining! "
            "File report NOW at https://incident.cert-in.org.in"
        )

    state.proposed_actions.append(
        ProposedAction(
            action_type="notify",
            description=(
                f"File CERT-In incident report {report['report_id']} — "
                f"deadline {deadline.strftime('%H:%M UTC')} "
                f"({hours_remaining:.1f}h remaining)"
            ),
            risk_level=ActionRisk.HIGH,
            target="certin@gov.in",
            requires_approval=False,
            rationale=f"Mandatory under CERT-In Directions 2022, Section 70B IT Act 2000. Category: {cat_info.get('code')}",
            parameters={"certin_report": report},
        )
    )

    state.threat_intel["certin_compliance"] = {
        "mandatory_reporting": True,
        "report": report,
        "deadline_breached": report["deadline_breached"],
        "hours_remaining": hours_remaining,
        "regulation": "CERT-In Directions 2022",
    }

    if state.status == AgentStatus.RUNNING:
        state.status = AgentStatus.COMPLETED

    logger.info(
        "CERT-In agent complete",
        category=category,
        hours_remaining=hours_remaining,
        mandatory=True,
    )
    return state
