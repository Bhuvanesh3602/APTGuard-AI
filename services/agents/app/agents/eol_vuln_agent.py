"""
End-of-Life Asset Vulnerability Amplification Agent.

India's government institutions run >70% EoL IT (National Cyber Security Policy).
This agent amplifies CVE severity for EoL assets — a CVE that is MEDIUM on a
supported system becomes CRITICAL on EoL because no patch will ever be released.
Generates a dynamic, risk-ranked remediation queue.
"""

from __future__ import annotations

import structlog

from app.models.state import ActionRisk, AgentStatus, InvestigationState, ProposedAction

logger = structlog.get_logger()

# EoL software/OS database (common in Indian government systems)
EOL_CATALOG = {
    # Windows
    "windows xp": {"eol_date": "2014-04-08", "amplifier": 2.5, "cve_note": "No patches ever"},
    "windows 7": {"eol_date": "2020-01-14", "amplifier": 2.2, "cve_note": "ESU ended 2023"},
    "windows server 2003": {"eol_date": "2015-07-14", "amplifier": 2.5},
    "windows server 2008": {"eol_date": "2020-01-14", "amplifier": 2.2},
    "windows server 2012": {"eol_date": "2023-10-10", "amplifier": 1.8},
    # Linux
    "centos 6": {"eol_date": "2020-11-30", "amplifier": 2.0},
    "centos 7": {"eol_date": "2024-06-30", "amplifier": 1.6},
    "ubuntu 16.04": {"eol_date": "2021-04-30", "amplifier": 1.9},
    "ubuntu 18.04": {"eol_date": "2023-05-31", "amplifier": 1.7},
    "rhel 6": {"eol_date": "2020-11-30", "amplifier": 2.0},
    # Databases
    "oracle 11g": {"eol_date": "2020-12-31", "amplifier": 2.0},
    "mysql 5.6": {"eol_date": "2021-02-05", "amplifier": 1.8},
    "sql server 2008": {"eol_date": "2019-07-09", "amplifier": 2.2},
    "sql server 2012": {"eol_date": "2022-07-12", "amplifier": 1.9},
    # Web / App servers
    "iis 6": {"eol_date": "2015-07-14", "amplifier": 2.5},
    "iis 7": {"eol_date": "2020-01-14", "amplifier": 2.2},
    "apache 2.2": {"eol_date": "2017-12-31", "amplifier": 2.3},
    "tomcat 6": {"eol_date": "2016-12-31", "amplifier": 2.3},
    "tomcat 7": {"eol_date": "2021-03-31", "amplifier": 1.8},
    "jdk 8": {"eol_date": "2022-03-31", "amplifier": 1.6},
    "jdk 11": {"eol_date": "2024-09-30", "amplifier": 1.4},
    # Network / OT
    "cisco ios 12": {"eol_date": "2016-01-29", "amplifier": 2.4},
    "cisco ios 15": {"eol_date": "2020-12-31", "amplifier": 1.8},
    "siemens s7-300": {"eol_date": "2023-10-01", "amplifier": 2.0},
    "scada wincc 7.0": {"eol_date": "2019-03-31", "amplifier": 2.3},
}

# CVE severity base scores (CVSS v3)
CVSS_RANGES = {
    "critical": (9.0, 10.0),
    "high": (7.0, 8.9),
    "medium": (4.0, 6.9),
    "low": (0.1, 3.9),
}


def _detect_eol_assets(text: str) -> list[tuple[str, dict]]:
    """Find EoL software mentions in alert text."""
    text_lower = text.lower()
    found = []
    for product, info in EOL_CATALOG.items():
        if product in text_lower:
            found.append((product, info))
    return found


def _amplify_cvss(base_score: float, amplifier: float) -> float:
    """Amplify CVSS score for EoL assets, capped at 10.0."""
    return min(10.0, base_score * amplifier)


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


async def run_eol_vuln(state: InvestigationState) -> InvestigationState:
    """Amplify CVE risk for EoL assets and generate remediation queue."""
    logger.info("EoL vulnerability agent starting", incident_id=str(state.incident_id))
    state.iteration_count += 1

    raw = state.raw_alert
    full_text = state.alert_summary + " " + str(raw)
    eol_assets = _detect_eol_assets(full_text)

    if not eol_assets:
        state.add_finding("EoL agent: no End-of-Life software detected in alert context.")
        return state

    state.add_finding(
        f"EoL agent: detected {len(eol_assets)} End-of-Life asset(s) — "
        "applying CVE severity amplification (India CNI context: >70% EoL rate)."
    )

    base_cvss = float(raw.get("cvss_score", raw.get("risk_score", 5.0)) or 5.0)
    base_severity = raw.get("severity", "medium").lower()
    if base_severity == "critical":
        base_cvss = max(base_cvss, 9.0)
    elif base_severity == "high":
        base_cvss = max(base_cvss, 7.0)

    remediation_queue = []
    for product, info in eol_assets:
        amplifier = info.get("amplifier", 1.5)
        amplified_score = _amplify_cvss(base_cvss, amplifier)
        amplified_severity = _cvss_to_severity(amplified_score)

        state.add_finding(
            f"EoL Amplification — {product}: "
            f"CVSS {base_cvss:.1f} ({_cvss_to_severity(base_cvss).upper()}) → "
            f"{amplified_score:.1f} ({amplified_severity.upper()}) "
            f"[EoL since {info['eol_date']}, amplifier ×{amplifier}]"
        )

        remediation_queue.append({
            "product": product,
            "eol_date": info["eol_date"],
            "base_cvss": base_cvss,
            "amplified_cvss": amplified_score,
            "severity": amplified_severity,
            "amplifier": amplifier,
            "recommendation": (
                f"REPLACE or ISOLATE {product} (EoL {info['eol_date']}) — "
                "no patches available. Emergency network segmentation until replacement."
            ),
        })

    # Sort remediation queue by amplified CVSS descending
    remediation_queue.sort(key=lambda x: x["amplified_cvss"], reverse=True)

    # Propose isolation for the highest-risk EoL asset
    if remediation_queue:
        top = remediation_queue[0]
        if top["amplified_cvss"] >= 7.0:
            state.proposed_actions.append(
                ProposedAction(
                    action_type="block_network_segment",
                    description=(
                        f"Network-isolate EoL asset running {top['product']} "
                        f"(amplified CVSS {top['amplified_cvss']:.1f} — {top['severity'].upper()})"
                    ),
                    risk_level=ActionRisk.CRITICAL if top["amplified_cvss"] >= 9.0 else ActionRisk.HIGH,
                    target=raw.get("hostname", "eol_asset"),
                    requires_approval=True,
                    rationale=(
                        f"{top['product']} reached EoL on {top['eol_date']}. "
                        f"No patches available. Effective CVSS: {top['amplified_cvss']:.1f}."
                    ),
                    parameters={
                        "eol_product": top["product"],
                        "eol_date": top["eol_date"],
                        "amplified_cvss": top["amplified_cvss"],
                    },
                )
            )

    state.threat_intel["eol_assessment"] = {
        "eol_assets_detected": len(eol_assets),
        "base_cvss": base_cvss,
        "remediation_queue": remediation_queue,
        "india_eol_context": "India govt networks: >70% EoL rate per NCSP",
    }

    if state.status == AgentStatus.RUNNING:
        state.status = AgentStatus.COMPLETED

    logger.info("EoL agent complete", eol_count=len(eol_assets), top_cvss=remediation_queue[0]["amplified_cvss"] if remediation_queue else 0)
    return state
