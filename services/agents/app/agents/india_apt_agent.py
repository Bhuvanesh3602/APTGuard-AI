"""
India APT Intelligence Agent.

Attributes observed TTPs, IOCs, and tools to India-relevant threat actor groups:
SideCopy, APT36 (Transparent Tribe), Lazarus (India ops), and Volt Typhoon.
Maps findings to CERT-In advisories and generates sector-specific defensive actions.
"""

from __future__ import annotations

import structlog

from app.models.state import ActionRisk, AgentStatus, InvestigationState, ProposedAction
from app.rag import get_certin_rag

logger = structlog.get_logger()

# ── India-relevant APT profiles ────────────────────────────────────────────────

INDIA_APT_CATALOG = {
    "SideCopy": {
        "aliases": ["APT-C-24"],
        "origin": "Pakistan-linked",
        "motivation": "espionage",
        "primary_targets": ["indian_defence", "government", "ministry_of_defence"],
        "ttps": ["T1566.001", "T1204.002", "T1059.001", "T1547.001", "T1071.001",
                 "T1105", "T1036.005", "T1027"],
        "tools": ["ReverseRat", "CetaRAT", "Allakore", "AsyncRAT", "njRAT"],
        "ioc_patterns": ["side-copy", "reverserat", "cetarat", "allakore"],
        "sectors": ["defence", "government", "aerospace"],
        "certin_refs": ["CERT-In Advisory CI-2023-0012", "CI-2024-0031"],
        "next_stage": ["T1003.001", "T1021.002", "T1041"],  # Predicted next moves
    },
    "APT36": {
        "aliases": ["Transparent Tribe", "ProjectM", "C-Major"],
        "origin": "Pakistan-linked",
        "motivation": "espionage",
        "primary_targets": ["indian_military", "education", "cbse", "government"],
        "ttps": ["T1566.001", "T1566.002", "T1059.001", "T1071.001", "T1105",
                 "T1547.001", "T1074.001", "T1041"],
        "tools": ["Crimson RAT", "ObliqueRAT", "ElectroRAT", "Capra", "AndroRAT"],
        "ioc_patterns": ["crimsonrat", "obliquerats", "capra", "transparent-tribe"],
        "sectors": ["education", "government", "military", "healthcare"],
        "certin_refs": ["CERT-In Advisory CI-2024-0018", "CI-2024-0062"],
        "next_stage": ["T1560.001", "T1048", "T1567"],  # Exfil stage
    },
    "Lazarus_India": {
        "aliases": ["Hidden Cobra", "ZINC", "Labyrinth Chollima"],
        "origin": "DPRK-linked",
        "motivation": "financial+espionage",
        "primary_targets": ["financial", "cryptocurrency", "healthcare", "critical_infra"],
        "ttps": ["T1059.001", "T1059.003", "T1071.001", "T1041", "T1486",
                 "T1490", "T1489", "T1070.004"],
        "tools": ["WannaCry", "VHD Ransomware", "MagicRAT", "BLINDINGCAN", "HOPLIGHT"],
        "ioc_patterns": ["wannacry", "vhd-ransomware", "magicrat", "blindingcan"],
        "sectors": ["healthcare", "financial", "cryptocurrency", "critical_infra"],
        "certin_refs": ["CERT-In Advisory CI-2022-0001", "CI-2023-0045"],
        "next_stage": ["T1486", "T1490", "T1489"],  # Ransomware deployment
    },
    "Volt_Typhoon": {
        "aliases": ["Bronze Silhouette", "Dev-0391", "Vanguard Panda"],
        "origin": "China-linked",
        "motivation": "pre-positioning+espionage",
        "primary_targets": ["power_grid", "telecom", "water", "critical_infra", "ot_systems"],
        "ttps": ["T1190", "T1133", "T1078", "T1021.001", "T1016", "T1049",
                 "T1082", "T1003.001", "T1048.003"],
        "tools": ["FRP", "Impacket", "WMI", "PsExec", "living-off-the-land"],
        "ioc_patterns": ["frp-proxy", "volt-typhoon", "bronze-silhouette"],
        "sectors": ["energy", "power_grid", "telecom", "water", "ot", "critical_infra"],
        "certin_refs": ["CERT-In Advisory CI-2023-0078", "NCIIPC-2023-009"],
        "next_stage": ["T1565.001", "T1561.002", "T1529"],  # OT disruption
    },
}

_SECTOR_MAP = {
    "aiims": "healthcare",
    "hospital": "healthcare",
    "medical": "healthcare",
    "cbse": "education",
    "school": "education",
    "university": "education",
    "power": "power_grid",
    "grid": "power_grid",
    "electricity": "power_grid",
    "scada": "ot",
    "modbus": "ot",
    "dnp3": "ot",
    "defence": "defence",
    "military": "military",
    "government": "government",
    "ministry": "government",
}


def _detect_sector(text: str) -> str:
    text_lower = text.lower()
    for keyword, sector in _SECTOR_MAP.items():
        if keyword in text_lower:
            return sector
    return "general"


def _score_apt_match(profile: dict, techniques: list[str], tools_text: str, sector: str) -> float:
    score = 0.0
    ttp_overlap = set(profile["ttps"]) & set(techniques)
    if profile["ttps"]:
        score += 0.5 * (len(ttp_overlap) / len(profile["ttps"]))
    for pattern in profile["ioc_patterns"]:
        if pattern in tools_text.lower():
            score += 0.3
            break
    if sector in profile["sectors"] or sector in profile["primary_targets"]:
        score += 0.2
    return min(score, 1.0)


async def _retrieve_certin_advisories(query: str, limit: int = 3) -> list[dict]:
    """Query the live CERT-In Qdrant collection. Never raises."""
    try:
        rag = get_certin_rag()
        return await rag.search(query, limit=limit)
    except Exception as exc:  # noqa: BLE001
        logger.debug("india_apt.rag_lookup_failed", error=str(exc))
        return []


async def run_india_apt(state: InvestigationState) -> InvestigationState:
    """Run India APT attribution and prediction."""
    logger.info("India APT agent starting", incident_id=str(state.incident_id))
    state.iteration_count += 1

    raw = state.raw_alert
    techniques = state.mitre_mappings or raw.get("mitre_techniques", [])
    tools_text = " ".join([
        raw.get("alert_summary", ""),
        state.alert_summary,
        str(raw.get("tags", [])),
        str(raw.get("tools", [])),
    ])
    sector = _detect_sector(state.alert_summary + " " + str(raw))

    state.add_finding(f"India APT agent: detected sector '{sector}', evaluating {len(INDIA_APT_CATALOG)} threat actors.")

    best_actor = None
    best_score = 0.0
    scores = {}

    for actor_id, profile in INDIA_APT_CATALOG.items():
        score = _score_apt_match(profile, techniques, tools_text, sector)
        scores[actor_id] = score
        if score > best_score:
            best_score = score
            best_actor = actor_id

    if best_actor and best_score >= 0.25:
        profile = INDIA_APT_CATALOG[best_actor]
        state.add_finding(
            f"APT Attribution: {best_actor} ({profile['aliases'][0]}) — "
            f"confidence {best_score:.2f} | motivation: {profile['motivation']} | "
            f"origin: {profile['origin']}"
        )
        state.add_finding(
            f"Relevant CERT-In advisories: {', '.join(profile['certin_refs'])}"
        )
        state.add_finding(
            f"Predicted next-stage TTPs: {', '.join(profile['next_stage'])}"
        )

        state.threat_intel["india_apt"] = {
            "actor": best_actor,
            "aliases": profile["aliases"],
            "confidence": best_score,
            "motivation": profile["motivation"],
            "origin": profile["origin"],
            "certin_refs": profile["certin_refs"],
            "matched_techniques": list(set(profile["ttps"]) & set(techniques)),
            "predicted_next_ttps": profile["next_stage"],
            "sector": sector,
            "all_scores": scores,
        }

        # Ground the attribution in live CERT-In advisory text (Qdrant RAG).
        # Best-effort: a missing/empty vector store leaves the static catalog
        # refs above untouched.
        rag_query = (
            f"{best_actor} {' '.join(profile['aliases'])} {profile['origin']} "
            f"{sector} {' '.join(profile['ioc_patterns'])} "
            f"advisory threat actor TTPs {' '.join(list(set(profile['ttps']) & set(techniques)))}"
        )
        advisories = await _retrieve_certin_advisories(rag_query)
        if advisories:
            state.threat_intel["india_apt"]["rag_advisories"] = advisories
            titles = ", ".join(a["title"] for a in advisories[:2])
            state.add_finding(
                f"CERT-In RAG: retrieved {len(advisories)} live advisor"
                f"{'y' if len(advisories) == 1 else 'ies'} grounding this attribution — {titles}"
            )

        # Propose sector-specific defensive action
        state.proposed_actions.append(
            ProposedAction(
                action_type="block_ip",
                description=(
                    f"Block {best_actor} ({profile['aliases'][0]}) C2 infrastructure — "
                    f"see CERT-In {profile['certin_refs'][0]}"
                ),
                risk_level=ActionRisk.HIGH,
                target="apt_c2_blocklist",
                requires_approval=True,
                rationale=f"Attribution confidence {best_score:.2f}; sector {sector} is a known {best_actor} target",
                parameters={
                    "actor": best_actor,
                    "certin_ref": profile["certin_refs"][0],
                    "predicted_next": profile["next_stage"],
                },
            )
        )

        # If ransomware-stage TTPs predicted, escalate immediately
        if any(t in profile["next_stage"] for t in ["T1486", "T1490", "T1489"]):
            state.add_finding(
                "CRITICAL: Ransomware deployment TTPs predicted as next stage — "
                "immediate offline backup verification recommended."
            )
            state.proposed_actions.append(
                ProposedAction(
                    action_type="create_case",
                    description="Escalate to CNI Incident Commander — ransomware deployment imminent",
                    risk_level=ActionRisk.CRITICAL,
                    target="incident_commander",
                    requires_approval=False,
                    rationale=f"{best_actor} kill chain at pre-ransomware stage",
                )
            )
    else:
        state.add_finding(
            f"India APT agent: no confident attribution (best={best_actor}, score={best_score:.2f}). "
            "Treating as unattributed threat actor."
        )
        state.threat_intel["india_apt"] = {
            "actor": "unknown",
            "confidence": best_score,
            "all_scores": scores,
        }

    if state.status == AgentStatus.RUNNING:
        state.status = AgentStatus.COMPLETED

    logger.info("India APT agent complete", actor=best_actor, score=best_score)
    return state
