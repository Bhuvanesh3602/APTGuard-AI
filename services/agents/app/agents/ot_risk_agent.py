"""
OT/ICS Risk Assessment Agent.

Evaluates alerts involving Operational Technology (OT) and Industrial Control Systems (ICS).
Detects Modbus/DNP3/SCADA anomalies, maps to ICS-specific MITRE ATT&CK techniques,
and proposes OT-safe containment (network segmentation over host isolation to avoid
physical process disruption in power grids, water treatment, etc.).
"""

from __future__ import annotations

import structlog

from app.models.state import ActionRisk, AgentStatus, InvestigationState, ProposedAction

logger = structlog.get_logger()

# ICS-MITRE ATT&CK technique catalog (MITRE ATT&CK for ICS)
ICS_TECHNIQUES = {
    "T0800": "Activate Firmware Update Mode",
    "T0801": "Monitor Process State",
    "T0802": "Automated Collection",
    "T0803": "Block Command Message",
    "T0804": "Block Reporting Message",
    "T0805": "Block Serial COM",
    "T0806": "Brute Force I/O",
    "T0807": "Command-Line Interface",
    "T0808": "Control Device Identification",
    "T0809": "Data Destruction",
    "T0810": "Data from Local System",
    "T0811": "Data from Information Repositories",
    "T0812": "Default Credentials",
    "T0813": "Denial of Control",
    "T0814": "Denial of Service",
    "T0815": "Denial of View",
    "T0816": "Device Restart/Shutdown",
    "T0817": "Drive-by Compromise",
    "T0818": "Engineering Workstation Compromise",
    "T0819": "Exploit Public-Facing Application",
    "T0820": "Exploitation for Evasion",
    "T0821": "Modify Controller Tasking",
    "T0822": "External Remote Services",
    "T0823": "Graphical User Interface",
    "T0824": "I/O Image",
    "T0825": "Location Identification",
    "T0826": "Loss of Availability",
    "T0827": "Loss of Control",
    "T0828": "Loss of Productivity and Revenue",
    "T0829": "Loss of Protection",
    "T0830": "Adversary-in-the-Middle",
    "T0831": "Manipulation of Control",
    "T0832": "Manipulation of View",
    "T0833": "Modify Alarm Settings",
    "T0834": "Native API",
    "T0835": "Manipulate I/O Image",
    "T0836": "Modify Parameter",
    "T0837": "Loss of Safety",
    "T0838": "Modify Alarm Settings",
    "T0839": "Module Firmware",
    "T0840": "Network Connection Enumeration",
    "T0841": "Network Identification",
    "T0842": "Network Sniffing",
    "T0843": "Program Download",
    "T0844": "Program Organization Units",
    "T0845": "Program Upload",
    "T0846": "Remote System Discovery",
    "T0847": "Replication Through Removable Media",
    "T0848": "Rogue Master",
    "T0849": "Masquerading",
    "T0850": "Role Identification",
    "T0851": "Rootkit",
    "T0852": "Screen Capture",
    "T0853": "Scripting",
    "T0854": "Serial Connection Enumeration",
    "T0855": "Unauthorized Command Message",
    "T0856": "Spoof Reporting Message",
    "T0857": "System Firmware",
    "T0858": "Change Credential",
    "T0859": "Valid Accounts",
    "T0860": "Wireless Compromise",
    "T0861": "Point & Tag Identification",
    "T0862": "Supply Chain Compromise",
    "T0863": "User Execution",
    "T0864": "Transient Cyber Asset",
    "T0865": "Spearphishing Attachment",
    "T0866": "Exploitation of Remote Services",
    "T0867": "Lateral Tool Transfer",
    "T0868": "Detect Operating Mode",
    "T0869": "Standard Application Layer Protocol",
    "T0870": "Exploitation for Privilege Escalation",
    "T0871": "Execution through API",
    "T0872": "Indicator Removal on Host",
    "T0873": "Project File Infection",
    "T0874": "Hooking",
    "T0875": "Change Program State",
    "T0876": "Loss of Life Safety",
    "T0877": "I/O Module Discovery",
    "T0878": "Alarm Suppression",
    "T0879": "Damage to Property",
    "T0880": "Loss of Safety",
    "T0881": "Service Stop",
    "T0882": "Theft of Operational Information",
    "T0883": "Internet Accessible Device",
    "T0884": "Connection Proxy",
    "T0885": "Commonly Used Port",
    "T0886": "Remote Services",
    "T0887": "Wireless Sniffing",
    "T0888": "Remote System Information Discovery",
    "T0889": "Modify Program",
    "T0890": "Exploitation for Defense Evasion",
    "T0891": "Hardcoded Credentials",
    "T0892": "Change Credential",
}

# Keywords that indicate OT/ICS context
OT_KEYWORDS = {
    "modbus", "dnp3", "scada", "ics", "plc", "hmi", "rtu", "historian",
    "pid controller", "setpoint", "ladder logic", "function block",
    "distributed control", "dcs", "fieldbuses", "profibus", "hart",
    "opc", "opc-ua", "opc-da", "iec 61850", "iec 104", "s7comm",
    "codesys", "step7", "wincc", "ignition", "inductive automation",
    "power grid", "substation", "relay", "breaker", "transformer",
    "water treatment", "purification", "pump", "valve", "flow meter",
    "gas pipeline", "compressor", "rtu", "telemetry",
}

# India-specific OT sectors at risk
INDIA_OT_SECTORS = {
    "power": ["NTPC", "PGCIL", "NHPC", "CPCL", "TATA Power", "Adani Power"],
    "oil_gas": ["ONGC", "IOCL", "BPCL", "Reliance", "GAIL"],
    "water": ["Municipal Corp", "DJB", "BWS", "water treatment"],
    "transport": ["AAI", "Railways", "NHAI", "Metro Rail"],
}


def _is_ot_alert(state: InvestigationState) -> bool:
    text = (state.alert_summary + " " + str(state.raw_alert)).lower()
    return any(kw in text for kw in OT_KEYWORDS)


def _map_ot_techniques(techniques: list[str]) -> list[tuple[str, str]]:
    return [(t, ICS_TECHNIQUES[t]) for t in techniques if t in ICS_TECHNIQUES]


def _classify_ot_impact(techniques: list[str]) -> str:
    """Classify potential physical impact level."""
    safety_critical = {"T0826", "T0827", "T0829", "T0831", "T0832", "T0876", "T0879", "T0880"}
    disruption = {"T0813", "T0814", "T0815", "T0816", "T0809", "T0881"}
    reconnaissance = {"T0801", "T0802", "T0810", "T0840", "T0841", "T0850", "T0861"}

    tech_set = set(techniques)
    if tech_set & safety_critical:
        return "SAFETY_CRITICAL"
    if tech_set & disruption:
        return "SERVICE_DISRUPTION"
    if tech_set & reconnaissance:
        return "RECONNAISSANCE"
    return "UNKNOWN"


async def run_ot_risk(state: InvestigationState) -> InvestigationState:
    """Assess OT/ICS risk and propose OT-safe containment."""
    logger.info("OT risk agent starting", incident_id=str(state.incident_id))
    state.iteration_count += 1

    if not _is_ot_alert(state):
        state.add_finding("OT risk agent: no OT/ICS indicators detected in alert — skipping.")
        return state

    state.add_finding("OT/ICS context detected — applying OT risk assessment protocol.")

    raw = state.raw_alert
    techniques = state.mitre_mappings or raw.get("mitre_techniques", [])
    ot_techniques = _map_ot_techniques(techniques)
    impact_level = _classify_ot_impact(techniques)

    state.add_finding(
        f"OT/ICS impact classification: {impact_level} | "
        f"ICS-MITRE techniques mapped: {len(ot_techniques)}"
    )

    for t_id, t_name in ot_techniques:
        state.add_finding(f"  ICS-ATT&CK {t_id}: {t_name}")

    # OT-SAFE containment: isolate at network level, NOT host-level
    # (host isolation can kill a physical process — catastrophic for power/water)
    if impact_level in ("SAFETY_CRITICAL", "SERVICE_DISRUPTION"):
        state.add_finding(
            "OT SAFETY NOTE: Host isolation is PROHIBITED for OT assets — "
            "physical process disruption risk. Applying network-layer DMZ segmentation."
        )
        state.proposed_actions.append(
            ProposedAction(
                action_type="block_network_segment",
                description=(
                    "Apply OT DMZ firewall rule — block IT→OT lateral movement path "
                    "without disrupting active physical processes"
                ),
                risk_level=ActionRisk.HIGH,
                target="ot_dmz_segment",
                requires_approval=True,
                rationale=(
                    f"OT impact level: {impact_level}. "
                    "Network segmentation preferred over host isolation to prevent process disruption."
                ),
                parameters={
                    "ot_techniques": [t[0] for t in ot_techniques],
                    "impact_level": impact_level,
                    "protocol": "firewall_acl",
                    "preserve_process_control": True,
                },
            )
        )

    if impact_level == "SAFETY_CRITICAL":
        state.add_finding(
            "CRITICAL: Safety-critical OT techniques detected — "
            "activate OT Incident Response Team and notify NCIIPC immediately."
        )
        state.proposed_actions.append(
            ProposedAction(
                action_type="notify",
                description="Notify NCIIPC (National Critical Information Infrastructure Protection Centre)",
                risk_level=ActionRisk.CRITICAL,
                target="nciipc@gov.in",
                requires_approval=False,
                rationale="NCIIPC mandatory notification for CNI OT incidents under IT Act 2000",
                parameters={
                    "agency": "NCIIPC",
                    "regulation": "IT Act 2000, Section 70",
                    "deadline_hours": 6,
                },
            )
        )

    state.threat_intel["ot_risk"] = {
        "is_ot_alert": True,
        "impact_level": impact_level,
        "ot_techniques": [{"id": t[0], "name": t[1]} for t in ot_techniques],
        "ot_safe_response": True,
        "nciipc_notification_required": impact_level == "SAFETY_CRITICAL",
    }

    if state.status == AgentStatus.RUNNING:
        state.status = AgentStatus.COMPLETED

    logger.info("OT risk agent complete", impact_level=impact_level, techniques=len(ot_techniques))
    return state
