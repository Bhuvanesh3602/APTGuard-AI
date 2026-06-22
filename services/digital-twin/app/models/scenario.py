"""Data models for digital twin attack simulation."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AssetType(str, Enum):
    server = "server"
    workstation = "workstation"
    plc = "plc"
    hmi = "hmi"
    rtu = "rtu"
    network = "network"
    cloud = "cloud"


class Criticality(str, Enum):
    safety_critical = "safety_critical"
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class CNIAsset(BaseModel):
    asset_id: str
    name: str
    asset_type: AssetType
    sector: str
    criticality: Criticality
    os: str | None = None
    is_eol: bool = False
    eol_product: str | None = None
    eol_amplifier: float = 1.0
    services: list[str] = Field(default_factory=list)
    vulnerabilities: list[str] = Field(default_factory=list)
    network_zone: str = "IT"
    properties: dict[str, Any] = Field(default_factory=dict)


class AttackStep(BaseModel):
    step_number: int
    technique_id: str
    technique_name: str
    from_asset: str
    to_asset: str
    success_probability: float
    impact_description: str
    ics_technique: str | None = None


class SimulationRequest(BaseModel):
    scenario_id: str = Field(..., description="Predefined scenario key or 'custom'")
    entry_asset_id: str = Field(..., description="Asset ID of the attack entry point")
    attacker_profile: str = Field(default="apt36", description="APT actor profile to simulate")
    what_if_controls: list[str] = Field(
        default_factory=list,
        description="Controls to simulate as applied — measure risk reduction"
    )


class SimulationResult(BaseModel):
    simulation_id: str
    scenario_name: str
    sector: str
    attacker_profile: str
    entry_point: str
    attack_path: list[AttackStep]
    blast_radius: list[str]
    total_risk_score: float
    estimated_impact: str
    certin_category: str | None
    certin_mandatory: bool
    nciipc_notification: bool
    recommended_controls: list[str]
    what_if_risk_reduction: float | None = None
    simulation_note: str = "Simulation ran on isolated Neo4j digital twin clone — production graph untouched"


class WhatIfRequest(BaseModel):
    scenario_id: str
    controls_applied: list[str] = Field(..., description="List of security controls to evaluate")


class WhatIfResult(BaseModel):
    scenario_id: str
    baseline_risk: float
    mitigated_risk: float
    risk_reduction_pct: float
    controls_evaluated: list[dict[str, Any]]
    recommendation: str
