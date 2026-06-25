"""
India CNI Agent REST endpoints.

Exposes attribution, prediction, OT risk, EoL amplification, and CERT-In
compliance results directly via the agents service API.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.models.state import InvestigationState

router = APIRouter(prefix="/api/v1/cni", tags=["India CNI"])


class CNIAlertRequest(BaseModel):
    alert_summary: str
    raw_alert: dict[str, Any] = {}
    mitre_techniques: list[str] = []
    incident_id: UUID | None = None
    tenant_id: UUID | None = None


def _make_state(req: CNIAlertRequest) -> InvestigationState:
    state = InvestigationState(
        incident_id=req.incident_id or uuid4(),
        tenant_id=req.tenant_id or uuid4(),
        alert_summary=req.alert_summary,
        raw_alert=req.raw_alert,
        mitre_mappings=req.mitre_techniques,
    )
    return state


@router.post("/apt/attribution")
async def apt_attribution(req: CNIAlertRequest) -> dict[str, Any]:
    """Run India APT attribution against CERT-In threat actor profiles."""
    from app.agents.india_apt_agent import run_india_apt
    state = _make_state(req)
    result = await run_india_apt(state)
    return {
        "incident_id": str(result.incident_id),
        "attribution": result.threat_intel.get("india_apt", {}),
        "findings": result.findings,
        "proposed_actions": [a.model_dump(mode="json") for a in result.proposed_actions],
    }


@router.post("/apt/prediction")
async def apt_prediction(req: CNIAlertRequest) -> dict[str, Any]:
    """Predict next-stage ATT&CK techniques from observed kill-chain position."""
    from app.agents.india_apt_agent import run_india_apt
    from app.agents.apt_prediction_agent import run_apt_prediction
    state = _make_state(req)
    state = await run_india_apt(state)
    result = await run_apt_prediction(state)
    return {
        "incident_id": str(result.incident_id),
        "apt_attribution": result.threat_intel.get("india_apt", {}),
        "prediction": result.threat_intel.get("apt_prediction", {}),
        "findings": result.findings,
        "proposed_actions": [a.model_dump(mode="json") for a in result.proposed_actions],
    }


@router.post("/ot/risk")
async def ot_risk_assessment(req: CNIAlertRequest) -> dict[str, Any]:
    """Assess OT/ICS risk with ICS-MITRE ATT&CK mapping and OT-safe response."""
    from app.agents.ot_risk_agent import run_ot_risk
    state = _make_state(req)
    result = await run_ot_risk(state)
    return {
        "incident_id": str(result.incident_id),
        "ot_risk": result.threat_intel.get("ot_risk", {}),
        "findings": result.findings,
        "proposed_actions": [a.model_dump(mode="json") for a in result.proposed_actions],
    }


@router.post("/eol/amplify")
async def eol_risk_amplification(req: CNIAlertRequest) -> dict[str, Any]:
    """Amplify CVE severity for EoL assets and return risk-ranked remediation queue."""
    from app.agents.eol_vuln_agent import run_eol_vuln
    state = _make_state(req)
    result = await run_eol_vuln(state)
    return {
        "incident_id": str(result.incident_id),
        "eol_assessment": result.threat_intel.get("eol_assessment", {}),
        "findings": result.findings,
        "proposed_actions": [a.model_dump(mode="json") for a in result.proposed_actions],
    }


@router.post("/certin/report")
async def certin_report(req: CNIAlertRequest) -> dict[str, Any]:
    """Generate mandatory CERT-In 6-hour incident report for the alert."""
    from app.agents.certin_agent import run_certin_compliance
    state = _make_state(req)
    result = await run_certin_compliance(state)
    compliance = result.threat_intel.get("certin_compliance", {})
    if not compliance.get("mandatory_reporting"):
        return {
            "incident_id": str(result.incident_id),
            "mandatory_reporting": False,
            "findings": result.findings,
        }
    return {
        "incident_id": str(result.incident_id),
        "mandatory_reporting": True,
        "report": compliance.get("report", {}),
        "deadline_breached": compliance.get("deadline_breached", False),
        "hours_remaining": compliance.get("hours_remaining"),
        "regulation": compliance.get("regulation"),
        "findings": result.findings,
        "proposed_actions": [a.model_dump(mode="json") for a in result.proposed_actions],
    }


@router.post("/full-assessment")
async def full_cni_assessment(req: CNIAlertRequest) -> dict[str, Any]:
    """
    Run all five CNI agents sequentially and return a unified assessment.

    Pipeline: india_apt → apt_prediction → ot_risk → eol_vuln → certin
    """
    from app.agents.india_apt_agent import run_india_apt
    from app.agents.apt_prediction_agent import run_apt_prediction
    from app.agents.ot_risk_agent import run_ot_risk
    from app.agents.eol_vuln_agent import run_eol_vuln
    from app.agents.certin_agent import run_certin_compliance

    state = _make_state(req)
    state = await run_india_apt(state)
    state = await run_apt_prediction(state)
    state = await run_ot_risk(state)
    state = await run_eol_vuln(state)
    state = await run_certin_compliance(state)

    return {
        "incident_id": str(state.incident_id),
        "findings": state.findings,
        "mitre_mappings": state.mitre_mappings,
        "proposed_actions": [a.model_dump(mode="json") for a in state.proposed_actions],
        "intelligence": {
            "india_apt": state.threat_intel.get("india_apt", {}),
            "apt_prediction": state.threat_intel.get("apt_prediction", {}),
            "ot_risk": state.threat_intel.get("ot_risk", {}),
            "eol_assessment": state.threat_intel.get("eol_assessment", {}),
            "certin_compliance": state.threat_intel.get("certin_compliance", {}),
        },
    }


@router.get("/apt/profiles")
async def get_apt_profiles() -> dict[str, Any]:
    """Return the India APT threat actor profile catalog."""
    from app.agents.india_apt_agent import INDIA_APT_CATALOG
    return {"profiles": INDIA_APT_CATALOG}


@router.get("/eol/catalog")
async def get_eol_catalog() -> dict[str, Any]:
    """Return the EoL software catalog with amplification factors."""
    from app.agents.eol_vuln_agent import EOL_CATALOG
    return {"catalog": EOL_CATALOG}
