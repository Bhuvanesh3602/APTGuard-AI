"""
APT Next-Stage Prediction Agent.

Given observed MITRE ATT&CK techniques and attributed threat actor,
predicts the most likely next-stage attack moves and generates
pre-emptive defensive recommendations.

Based on MITRE ATT&CK kill-chain transition probabilities derived from
public threat intelligence reports and CERT-In advisories.
"""

from __future__ import annotations

import structlog

from app.models.state import ActionRisk, AgentStatus, InvestigationState, ProposedAction

logger = structlog.get_logger()

# Kill-chain stage ordering
KILL_CHAIN_STAGES = [
    "reconnaissance",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]

# MITRE ATT&CK technique → kill-chain stage mapping
TECHNIQUE_TO_STAGE = {
    # Reconnaissance
    "T1595": "reconnaissance", "T1592": "reconnaissance", "T1589": "reconnaissance",
    "T1590": "reconnaissance", "T1591": "reconnaissance", "T1598": "reconnaissance",
    # Resource Development
    "T1583": "resource_development", "T1584": "resource_development",
    "T1585": "resource_development", "T1586": "resource_development",
    "T1587": "resource_development", "T1588": "resource_development",
    # Initial Access
    "T1566": "initial_access", "T1190": "initial_access", "T1133": "initial_access",
    "T1200": "initial_access", "T1091": "initial_access", "T1195": "initial_access",
    "T1199": "initial_access", "T1078": "initial_access",
    # Execution
    "T1059": "execution", "T1203": "execution", "T1204": "execution",
    "T1047": "execution", "T1053": "execution", "T1569": "execution",
    # Persistence
    "T1547": "persistence", "T1543": "persistence", "T1053": "persistence",
    "T1037": "persistence", "T1176": "persistence", "T1574": "persistence",
    "T1505": "persistence", "T1546": "persistence", "T1136": "persistence",
    # Privilege Escalation
    "T1548": "privilege_escalation", "T1134": "privilege_escalation",
    "T1068": "privilege_escalation", "T1055": "privilege_escalation",
    "T1611": "privilege_escalation",
    # Defense Evasion
    "T1562": "defense_evasion", "T1070": "defense_evasion", "T1036": "defense_evasion",
    "T1027": "defense_evasion", "T1553": "defense_evasion", "T1078": "defense_evasion",
    # Credential Access
    "T1003": "credential_access", "T1110": "credential_access", "T1555": "credential_access",
    "T1187": "credential_access", "T1606": "credential_access", "T1056": "credential_access",
    # Discovery
    "T1087": "discovery", "T1010": "discovery", "T1217": "discovery",
    "T1580": "discovery", "T1069": "discovery", "T1057": "discovery",
    "T1012": "discovery", "T1049": "discovery", "T1033": "discovery",
    "T1007": "discovery", "T1082": "discovery", "T1016": "discovery",
    "T1135": "discovery", "T1046": "discovery",
    # Lateral Movement
    "T1021": "lateral_movement", "T1550": "lateral_movement", "T1534": "lateral_movement",
    "T1080": "lateral_movement", "T1570": "lateral_movement",
    # Collection
    "T1560": "collection", "T1123": "collection", "T1119": "collection",
    "T1115": "collection", "T1530": "collection", "T1602": "collection",
    "T1213": "collection", "T1005": "collection", "T1039": "collection",
    "T1025": "collection",
    # C2
    "T1071": "command_and_control", "T1092": "command_and_control",
    "T1132": "command_and_control", "T1001": "command_and_control",
    "T1568": "command_and_control", "T1573": "command_and_control",
    # Exfiltration
    "T1041": "exfiltration", "T1011": "exfiltration", "T1052": "exfiltration",
    "T1567": "exfiltration", "T1048": "exfiltration",
    # Impact
    "T1485": "impact", "T1486": "impact", "T1490": "impact", "T1489": "impact",
    "T1498": "impact", "T1499": "impact", "T1529": "impact", "T1565": "impact",
    "T1491": "impact",
}

# Next-stage predictions: current stage → likely next techniques
NEXT_STAGE_PREDICTIONS = {
    "initial_access": {
        "next_stage": "execution",
        "predicted_techniques": ["T1059.001", "T1059.003", "T1204.002", "T1203"],
        "defensive_actions": [
            "Enable PowerShell Script Block Logging",
            "Deploy application whitelisting (WDAC/AppLocker)",
            "Block macro execution in Office documents",
        ],
    },
    "execution": {
        "next_stage": "persistence",
        "predicted_techniques": ["T1547.001", "T1543.003", "T1053.005", "T1136.001"],
        "defensive_actions": [
            "Monitor scheduled task creation",
            "Alert on new service installations",
            "Audit registry run keys",
        ],
    },
    "persistence": {
        "next_stage": "privilege_escalation",
        "predicted_techniques": ["T1068", "T1548.002", "T1055", "T1134"],
        "defensive_actions": [
            "Enforce least privilege (PAM solution)",
            "Monitor local admin group changes",
            "Alert on token impersonation",
        ],
    },
    "privilege_escalation": {
        "next_stage": "credential_access",
        "predicted_techniques": ["T1003.001", "T1003.002", "T1110.003", "T1555"],
        "defensive_actions": [
            "Deploy Credential Guard (Windows)",
            "Enable LSASS protection",
            "Alert on NTLM hash extraction patterns",
        ],
    },
    "credential_access": {
        "next_stage": "lateral_movement",
        "predicted_techniques": ["T1021.001", "T1021.002", "T1550.002", "T1570"],
        "defensive_actions": [
            "Enforce MFA on all remote access",
            "Monitor RDP/SMB lateral movement",
            "Implement network segmentation",
        ],
    },
    "lateral_movement": {
        "next_stage": "collection",
        "predicted_techniques": ["T1560.001", "T1119", "T1005", "T1213"],
        "defensive_actions": [
            "Deploy DLP on file servers",
            "Monitor bulk file access",
            "Alert on archive/compression tools",
        ],
    },
    "collection": {
        "next_stage": "exfiltration",
        "predicted_techniques": ["T1041", "T1048.003", "T1567.002", "T1011"],
        "defensive_actions": [
            "Monitor large outbound DNS queries",
            "Block cloud storage upload from server systems",
            "Alert on unusual outbound data volumes",
        ],
    },
    "command_and_control": {
        "next_stage": "impact",
        "predicted_techniques": ["T1486", "T1490", "T1489", "T1485"],
        "defensive_actions": [
            "CRITICAL: Initiate offline backup verification",
            "Pre-position incident response team",
            "Prepare network isolation runbooks",
        ],
    },
    "exfiltration": {
        "next_stage": "impact",
        "predicted_techniques": ["T1486", "T1485", "T1491", "T1529"],
        "defensive_actions": [
            "CRITICAL: Ransomware deployment imminent — isolate affected segments",
            "Take emergency offline backups",
            "Activate CNI Incident Response Team",
        ],
    },
    "discovery": {
        "next_stage": "lateral_movement",
        "predicted_techniques": ["T1021.001", "T1021.002", "T1021.006", "T1550"],
        "defensive_actions": [
            "Review AD delegation",
            "Alert on network scanning from internal hosts",
            "Enforce jump-server architecture",
        ],
    },
    "defense_evasion": {
        "next_stage": "credential_access",
        "predicted_techniques": ["T1003.001", "T1555.003", "T1110.003"],
        "defensive_actions": [
            "Check for disabled security tools",
            "Verify EDR agent health",
            "Review Windows Event log clearing",
        ],
    },
}


def _get_current_stage(techniques: list[str]) -> str | None:
    """Determine the furthest kill-chain stage from observed techniques."""
    stages_seen = set()
    for tech in techniques:
        # Handle subtechniques like T1059.001 → T1059
        base = tech.split(".")[0]
        stage = TECHNIQUE_TO_STAGE.get(tech) or TECHNIQUE_TO_STAGE.get(base)
        if stage:
            stages_seen.add(stage)

    if not stages_seen:
        return None

    # Return the furthest-progressed stage
    for stage in reversed(KILL_CHAIN_STAGES):
        if stage in stages_seen:
            return stage
    return None


async def run_apt_prediction(state: InvestigationState) -> InvestigationState:
    """Predict next-stage APT moves and generate pre-emptive defences."""
    logger.info("APT prediction agent starting", incident_id=str(state.incident_id))
    state.iteration_count += 1

    raw = state.raw_alert
    techniques = state.mitre_mappings or raw.get("mitre_techniques", [])

    if not techniques:
        state.add_finding("APT prediction agent: no MITRE techniques observed — cannot predict next stage.")
        return state

    current_stage = _get_current_stage(techniques)
    if not current_stage:
        state.add_finding(f"APT prediction agent: techniques {techniques} not mappable to kill-chain stage.")
        return state

    prediction = NEXT_STAGE_PREDICTIONS.get(current_stage)
    state.add_finding(
        f"APT Kill-Chain Position: '{current_stage}' → "
        f"Predicted next stage: '{prediction['next_stage'] if prediction else 'unknown'}'"
    )

    if prediction:
        state.add_finding(
            f"Predicted next-stage techniques: {', '.join(prediction['predicted_techniques'])}"
        )
        for defence in prediction["defensive_actions"]:
            state.add_finding(f"  Pre-emptive defence: {defence}")

        # Add pre-emptive containment action
        is_critical = current_stage in ("command_and_control", "exfiltration", "collection")
        state.proposed_actions.append(
            ProposedAction(
                action_type="create_hunt",
                description=(
                    f"Launch pre-emptive threat hunt for {prediction['next_stage']} TTPs: "
                    f"{', '.join(prediction['predicted_techniques'][:3])}"
                ),
                risk_level=ActionRisk.CRITICAL if is_critical else ActionRisk.HIGH,
                target="threat_hunting_team",
                requires_approval=not is_critical,
                rationale=(
                    f"Attack at '{current_stage}' stage. Next-stage prediction: "
                    f"'{prediction['next_stage']}'. Hunt before techniques execute."
                ),
                parameters={
                    "current_stage": current_stage,
                    "predicted_next_stage": prediction["next_stage"],
                    "hunt_techniques": prediction["predicted_techniques"],
                },
            )
        )

        # Check India APT context from previous agent
        india_apt = state.threat_intel.get("india_apt", {})
        attributed_actor = india_apt.get("actor")
        if attributed_actor and attributed_actor != "unknown":
            state.add_finding(
                f"APT prediction in {attributed_actor} context: "
                f"this actor historically completes {current_stage} → {prediction['next_stage']} "
                f"transition in 24–72 hours based on CERT-In incident reports."
            )

    state.threat_intel["apt_prediction"] = {
        "current_stage": current_stage,
        "observed_techniques": techniques,
        "next_stage": prediction["next_stage"] if prediction else None,
        "predicted_techniques": prediction["predicted_techniques"] if prediction else [],
        "defensive_actions": prediction["defensive_actions"] if prediction else [],
    }

    if state.status == AgentStatus.RUNNING:
        state.status = AgentStatus.COMPLETED

    logger.info("APT prediction complete", current_stage=current_stage)
    return state
