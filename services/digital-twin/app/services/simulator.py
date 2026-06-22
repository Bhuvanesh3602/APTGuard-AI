"""
Digital Twin Attack Path Simulator.

Maintains an in-memory representation of the CNI network graph (mirroring
what would be stored in Neo4j in production). For each simulation request:
  1. Clone the graph into an isolated "twin"
  2. Run BFS/Dijkstra attack path analysis from the entry point
  3. Score blast radius and risk
  4. Return recommended pre-emptive controls
  5. Support what-if analysis (apply a control, re-measure risk delta)

In production this would call Neo4j directly via the neo4j-driver.
"""

from __future__ import annotations

import uuid
from typing import Any

from app.models.scenario import (
    AttackStep,
    CNIAsset,
    Criticality,
    SimulationRequest,
    SimulationResult,
    WhatIfRequest,
    WhatIfResult,
)

# ── Static CNI Asset Graph (mirrors Neo4j node catalog) ─────────────────────

CNI_ASSETS: dict[str, CNIAsset] = {
    "aiims-ehr": CNIAsset(
        asset_id="aiims-ehr",
        name="AIIMS-EHR-SRV01",
        asset_type="server",
        sector="Healthcare",
        criticality=Criticality.critical,
        os="Windows Server 2008",
        is_eol=True,
        eol_product="Windows Server 2008",
        eol_amplifier=2.2,
        services=["SMB", "RDP", "HTTP"],
        vulnerabilities=["CVE-2017-0144", "CVE-2019-0708"],
        network_zone="HOSPITAL_ADMIN",
    ),
    "aiims-pacs": CNIAsset(
        asset_id="aiims-pacs",
        name="AIIMS-PACS-SRV01",
        asset_type="server",
        sector="Healthcare",
        criticality=Criticality.critical,
        os="Windows Server 2012",
        is_eol=True,
        eol_product="Windows Server 2012",
        eol_amplifier=1.8,
        services=["DICOM", "SMB"],
        vulnerabilities=["CVE-2020-0796"],
        network_zone="HOSPITAL_CLINICAL",
    ),
    "aiims-ward": CNIAsset(
        asset_id="aiims-ward",
        name="Clinical Ward PCs (×34)",
        asset_type="workstation",
        sector="Healthcare",
        criticality=Criticality.safety_critical,
        os="Windows 10",
        is_eol=False,
        network_zone="HOSPITAL_CLINICAL",
    ),
    "cbse-db": CNIAsset(
        asset_id="cbse-db",
        name="CBSE-EXAM-DB01",
        asset_type="server",
        sector="Education",
        criticality=Criticality.critical,
        os="Ubuntu 18.04",
        is_eol=True,
        eol_product="Ubuntu 18.04",
        eol_amplifier=1.6,
        services=["MySQL", "SSH", "HTTP"],
        vulnerabilities=["CVE-2023-22809"],
        network_zone="CBSE_INTERNAL",
    ),
    "cbse-portal": CNIAsset(
        asset_id="cbse-portal",
        name="CBSE-RESULT-PORTAL",
        asset_type="server",
        sector="Education",
        criticality=Criticality.high,
        os="Ubuntu 20.04",
        is_eol=False,
        network_zone="CBSE_DMZ",
    ),
    "pgcil-hmi": CNIAsset(
        asset_id="pgcil-hmi",
        name="PGCIL-SUBSTATION-HMI01",
        asset_type="hmi",
        sector="Power Grid",
        criticality=Criticality.safety_critical,
        is_eol=False,
        services=["Modbus", "DNP3", "OPC-UA"],
        network_zone="OT_DMZ",
    ),
    "pgcil-plc": CNIAsset(
        asset_id="pgcil-plc",
        name="PGCIL-PLC-GRID01",
        asset_type="plc",
        sector="Power Grid",
        criticality=Criticality.safety_critical,
        is_eol=False,
        services=["Modbus"],
        network_zone="OT_FIELD",
    ),
    "ministry-ws": CNIAsset(
        asset_id="ministry-ws",
        name="MINISTRY-WS-047",
        asset_type="workstation",
        sector="Govt IT",
        criticality=Criticality.medium,
        os="Windows 7",
        is_eol=True,
        eol_product="Windows 7",
        eol_amplifier=2.2,
        services=["SMB", "RDP"],
        vulnerabilities=["CVE-2017-0144", "CVE-2019-0708"],
        network_zone="MINISTRY_INTERNAL",
    ),
    "dc-01": CNIAsset(
        asset_id="dc-01",
        name="DC01.ministry.gov.in",
        asset_type="server",
        sector="Govt IT",
        criticality=Criticality.critical,
        os="Windows Server 2019",
        is_eol=False,
        services=["LDAP", "Kerberos", "DNS"],
        network_zone="MINISTRY_INTERNAL",
    ),
}

# ── Predefined attack scenarios ──────────────────────────────────────────────

_SCENARIOS: dict[str, dict] = {
    "aiims_ransomware": {
        "name": "AIIMS Pattern — LockBit 3.0 Ransomware",
        "sector": "Healthcare",
        "entry_asset": "aiims-ehr",
        "attacker": "lockbit3",
        "steps": [
            AttackStep(
                step_number=1, technique_id="T1190",
                technique_name="Exploit Public-Facing App (EternalBlue CVE-2017-0144)",
                from_asset="Internet", to_asset="aiims-ehr",
                success_probability=0.92,
                impact_description="Initial access via EoL EternalBlue — CVSS 7.5 → 16.5 (×2.2 EoL amplifier)",
            ),
            AttackStep(
                step_number=2, technique_id="T1021.002",
                technique_name="SMB Lateral Movement to PACS server",
                from_asset="aiims-ehr", to_asset="aiims-pacs",
                success_probability=0.84,
                impact_description="Clinical imaging system compromised — patient scans at risk",
            ),
            AttackStep(
                step_number=3, technique_id="T1490",
                technique_name="Inhibit System Recovery (VSS shadow copy deletion)",
                from_asset="aiims-pacs", to_asset="ALL NODES",
                success_probability=0.97,
                impact_description="Recovery impossible — all VSS snapshots deleted across admin network",
            ),
            AttackStep(
                step_number=4, technique_id="T1486",
                technique_name="Data Encrypted for Impact (LockBit 3.0)",
                from_asset="ALL NODES", to_asset="EHR + PACS Databases",
                success_probability=0.99,
                impact_description="12,847 patient records encrypted — clinical operations down",
            ),
        ],
        "blast_radius": ["AIIMS-EHR-SRV01", "AIIMS-PACS-SRV01", "Clinical Ward PCs (×34)", "Patient DB"],
        "risk_score": 9.8,
        "impact": "Complete EHR outage · Paper-based clinical fallback · 5,000+ patients affected · possible patient safety risk",
        "certin_category": "CAT-4",
        "certin_mandatory": True,
        "nciipc": True,
        "controls": [
            "ISOLATE: Segment EHR admin network from clinical ward PCs at L3 firewall",
            "PATCH: Migrate off Windows Server 2008 (CVE-2017-0144 permanently unpatched)",
            "BACKUP: Deploy immutable air-gapped backup for patient records (3-2-1 rule)",
            "POLICY: Enable VSS protection via GPO — block deletion without dual-approval",
            "MONITOR: Deploy UEBA rule — alert on >500 file writes/min on EHR servers",
            "CERT-In CAT-4 mandatory report within 6 hours of detection",
        ],
        "control_risk_reduction": {
            "ISOLATE": 0.35,
            "PATCH": 0.40,
            "BACKUP": 0.10,
            "POLICY": 0.08,
            "MONITOR": 0.12,
        },
    },
    "cbse_apt36": {
        "name": "APT36 (Transparent Tribe) — CBSE Exam Data Exfiltration",
        "sector": "Education",
        "entry_asset": "cbse-db",
        "attacker": "apt36",
        "steps": [
            AttackStep(
                step_number=1, technique_id="T1566.001",
                technique_name="Spear-Phishing with Crimson RAT dropper",
                from_asset="APT36 Infrastructure", to_asset="Exam Coordinator Workstation",
                success_probability=0.73,
                impact_description="Initial compromise of exam coordinator account",
            ),
            AttackStep(
                step_number=2, technique_id="T1059.001",
                technique_name="PowerShell C2 beacon to APT36 infra",
                from_asset="Coordinator Workstation", to_asset="cbse-db",
                success_probability=0.88,
                impact_description="Lateral access to exam database via stolen coordinator credentials",
            ),
            AttackStep(
                step_number=3, technique_id="T1041",
                technique_name="Exfiltration via C2 (4.7 GB to 103.76.228.95)",
                from_asset="cbse-db", to_asset="Pakistan IP (103.76.228.95)",
                success_probability=0.91,
                impact_description="2.3M student Aadhaar-linked PII exfiltrated",
            ),
            AttackStep(
                step_number=4, technique_id="T1486",
                technique_name="Ransomware deployment (72h post-exfil)",
                from_asset="cbse-db", to_asset="CBSE Exam Infrastructure",
                success_probability=0.65,
                impact_description="Exam result system unavailable — national board impact",
            ),
        ],
        "blast_radius": ["CBSE-EXAM-DB01", "Result Management System", "2.3M Student Records (PII)", "UDISE Portal"],
        "risk_score": 9.5,
        "impact": "2.3M student Aadhaar-linked PII exfiltrated · National exam results at risk · PDPA violation",
        "certin_category": "CAT-9",
        "certin_mandatory": True,
        "nciipc": True,
        "controls": [
            "EMAIL: Deploy email security with attachment sandbox for all @cbse.gov.in accounts",
            "DLP: Alert on >500 records/hr query rate from exam coordinator accounts",
            "UEBA: Behavioral baseline for exam coordinators — anomaly on bulk data access",
            "NETWORK: Block Pakistan-origin ASNs (AS9260, AS45595) at perimeter",
            "CERT-In CAT-9 mandatory data breach report within 6 hours",
            "Notify PDPB authority under proposed DPDP Act 2023",
        ],
        "control_risk_reduction": {
            "EMAIL": 0.40,
            "DLP": 0.25,
            "UEBA": 0.20,
            "NETWORK": 0.15,
        },
    },
    "power_grid_ot": {
        "name": "Volt Typhoon — Power Grid OT Pre-Positioning",
        "sector": "Power Grid",
        "entry_asset": "pgcil-hmi",
        "attacker": "volt_typhoon",
        "steps": [
            AttackStep(
                step_number=1, technique_id="T1016",
                technique_name="LOTL Network Discovery (netsh/ipconfig/route print)",
                from_asset="IT DMZ (compromised)", to_asset="OT Workstation",
                success_probability=0.81,
                impact_description="OT network topology exposed — SCADA addressing mapped",
                ics_technique="T0840",
            ),
            AttackStep(
                step_number=2, technique_id="T1021.001",
                technique_name="RDP lateral move IT zone → OT DMZ",
                from_asset="IT Network", to_asset="pgcil-hmi",
                success_probability=0.76,
                impact_description="IT-OT boundary crossed — HMI access obtained",
                ics_technique="T0886",
            ),
            AttackStep(
                step_number=3, technique_id="T0855",
                technique_name="Unauthorized Modbus FC-16 Write to PLC register 4096",
                from_asset="pgcil-hmi", to_asset="pgcil-plc",
                success_probability=0.68,
                impact_description="PLC register modified — potential protective relay manipulation",
                ics_technique="T0855",
            ),
            AttackStep(
                step_number=4, technique_id="T0826",
                technique_name="Loss of Availability (grid segment blackout)",
                from_asset="pgcil-plc", to_asset="Substation Protection System",
                success_probability=0.55,
                impact_description="SAFETY_CRITICAL: substation trip — potential cascading outage",
                ics_technique="T0826",
            ),
        ],
        "blast_radius": ["PGCIL-SUBSTATION-HMI01", "PGCIL-PLC-GRID01", "Protection Relays (×12)", "Substation Automation"],
        "risk_score": 9.9,
        "impact": "SAFETY_CRITICAL: potential substation blackout · cascading grid failure · hospitals on grid at risk",
        "certin_category": "CAT-10",
        "certin_mandatory": True,
        "nciipc": True,
        "controls": [
            "OT-SAFE: IT-OT DMZ firewall rule — NO host isolation (preserves process control)",
            "PROTOCOL: Deploy industrial DPI (Modbus/DNP3) at IT-OT boundary — anomalous FC detection",
            "ZONE: Block all RDP/non-OT traffic from IT subnet to OT DMZ",
            "MONITOR: Deploy OT asset inventory (Dragos/Claroty) for passive protocol monitoring",
            "NCIIPC mandatory notification under IT Act §70 (power grid = designated CNI)",
            "CERT-In CAT-10 critical infrastructure report within 6 hours",
        ],
        "control_risk_reduction": {
            "OT-SAFE": 0.30,
            "PROTOCOL": 0.35,
            "ZONE": 0.20,
            "MONITOR": 0.15,
        },
    },
}


def get_all_scenarios() -> list[dict]:
    return [
        {"scenario_id": k, "name": v["name"], "sector": v["sector"], "risk_score": v["risk_score"]}
        for k, v in _SCENARIOS.items()
    ]


def get_all_assets() -> list[CNIAsset]:
    return list(CNI_ASSETS.values())


def run_simulation(req: SimulationRequest) -> SimulationResult:
    """
    Run attack path simulation on the digital twin.

    In production: clone Neo4j production graph → isolated sandbox DB
    → run Dijkstra/BFS attack path → return result → destroy sandbox.
    Here we use the static scenario catalog as the graph source.
    """
    scenario = _SCENARIOS.get(req.scenario_id)
    if not scenario:
        raise ValueError(f"Unknown scenario: {req.scenario_id}")

    baseline_risk = scenario["risk_score"]
    what_if_reduction = 0.0

    if req.what_if_controls:
        for ctrl_key in req.what_if_controls:
            for ctrl_prefix, reduction in scenario.get("control_risk_reduction", {}).items():
                if ctrl_prefix.lower() in ctrl_key.lower():
                    what_if_reduction += reduction
        what_if_reduction = min(what_if_reduction, 0.90)

    mitigated_risk = round(baseline_risk * (1 - what_if_reduction), 2) if what_if_reduction else None

    return SimulationResult(
        simulation_id=str(uuid.uuid4()),
        scenario_name=scenario["name"],
        sector=scenario["sector"],
        attacker_profile=req.attacker_profile or scenario["attacker"],
        entry_point=req.entry_asset_id,
        attack_path=scenario["steps"],
        blast_radius=scenario["blast_radius"],
        total_risk_score=baseline_risk,
        estimated_impact=scenario["impact"],
        certin_category=scenario.get("certin_category"),
        certin_mandatory=scenario.get("certin_mandatory", False),
        nciipc_notification=scenario.get("nciipc", False),
        recommended_controls=scenario["controls"],
        what_if_risk_reduction=round(what_if_reduction * baseline_risk, 2) if what_if_reduction else None,
    )


def run_what_if(req: WhatIfRequest) -> WhatIfResult:
    scenario = _SCENARIOS.get(req.scenario_id)
    if not scenario:
        raise ValueError(f"Unknown scenario: {req.scenario_id}")

    baseline_risk = scenario["risk_score"]
    total_reduction = 0.0
    controls_detail = []

    for ctrl in req.controls_applied:
        matched = False
        for prefix, reduction in scenario.get("control_risk_reduction", {}).items():
            if prefix.lower() in ctrl.lower():
                controls_detail.append({"control": ctrl, "risk_reduction": round(reduction * baseline_risk, 2), "matched_key": prefix})
                total_reduction += reduction
                matched = True
                break
        if not matched:
            controls_detail.append({"control": ctrl, "risk_reduction": 0.0, "matched_key": None, "note": "No matching reduction factor"})

    total_reduction = min(total_reduction, 0.90)
    mitigated = round(baseline_risk * (1 - total_reduction), 2)
    reduction_pct = round(total_reduction * 100, 1)

    recommendation = (
        f"Applying the selected controls reduces risk from {baseline_risk}/10 to {mitigated}/10 "
        f"({reduction_pct}% reduction). "
        + ("Prioritise the first two controls for maximum impact." if len(req.controls_applied) > 2 else "All controls recommended.")
    )

    return WhatIfResult(
        scenario_id=req.scenario_id,
        baseline_risk=baseline_risk,
        mitigated_risk=mitigated,
        risk_reduction_pct=reduction_pct,
        controls_evaluated=controls_detail,
        recommendation=recommendation,
    )
