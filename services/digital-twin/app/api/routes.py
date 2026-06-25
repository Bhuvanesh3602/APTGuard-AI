"""Digital Twin API routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.models.scenario import CNIAsset, SimulationRequest, SimulationResult, WhatIfRequest, WhatIfResult
from app.services import graph
from app.services.simulator import get_all_assets, get_all_scenarios, run_simulation, run_what_if

router = APIRouter(prefix="/api/v1/twin")


@router.get("/scenarios")
async def list_scenarios() -> list[dict]:
    """List all available CNI attack scenarios."""
    return get_all_scenarios()


@router.get("/assets", response_model=list[CNIAsset])
async def list_assets() -> list[CNIAsset]:
    """List all CNI assets in the digital twin graph."""
    return get_all_assets()


@router.post("/simulate", response_model=SimulationResult)
async def simulate(req: SimulationRequest) -> SimulationResult:
    """
    Run attack path simulation on the isolated digital twin.

    Clones the CNI network graph, executes BFS attack path analysis
    from the entry point, scores blast radius and risk, returns
    recommended pre-emptive controls.

    The production graph is never modified — simulation runs on an
    isolated Neo4j clone that is destroyed after the run.
    """
    try:
        return run_simulation(req)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@router.post("/what-if", response_model=WhatIfResult)
async def what_if(req: WhatIfRequest) -> WhatIfResult:
    """
    What-if analysis: apply a set of security controls and measure the
    risk reduction delta against the baseline simulation.

    Returns risk score before and after, per-control contribution,
    and a prioritised recommendation.
    """
    try:
        return run_what_if(req)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@router.get("/scenarios/{scenario_id}/impact")
async def scenario_impact(scenario_id: str) -> SimulationResult:
    """Quick impact summary for a scenario (no what-if controls)."""
    try:
        req = SimulationRequest(scenario_id=scenario_id, entry_asset_id="auto")
        return run_simulation(req)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


# ── Live asset-graph (Neo4j) endpoints ──────────────────────────────────────


@router.get("/graph/status")
async def graph_status() -> dict:
    """Whether the twin is backed by live Neo4j or the static fallback."""
    return await graph.graph_status()


@router.get("/graph/assets")
async def graph_assets() -> list[dict]:
    """All CNI assets, read live from the Neo4j asset graph when connected."""
    return await graph.list_assets()


@router.get("/graph/reachable/{asset_id}")
async def graph_reachable(asset_id: str, max_hops: int = 3) -> dict:
    """Assets reachable from a (hypothetically compromised) entry asset."""
    try:
        reachable = await graph.reachable_assets(asset_id, max_hops)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    return {
        "entry_asset": asset_id,
        "max_hops": max_hops,
        "backend": "neo4j" if graph.is_connected() else "static_fallback",
        "count": len(reachable),
        "reachable_assets": reachable,
    }


@router.get("/graph/attack-path")
async def graph_attack_path(from_asset: str, to_asset: str, max_hops: int = 6) -> dict:
    """Shortest lateral-movement path between two assets (Cypher shortestPath)."""
    try:
        return await graph.attack_path(from_asset, to_asset, max_hops)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@router.get("/graph/blast-radius/{asset_id}")
async def graph_blast_radius(asset_id: str, max_hops: int = 3) -> dict:
    """Criticality-weighted blast radius if ``asset_id`` is compromised."""
    try:
        return await graph.blast_radius(asset_id, max_hops)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
