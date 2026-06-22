"""
Tool: knowledge-graph queries via the API service.

Wraps the `/api/v1/graph/*` endpoints exposed by `services/api`. The agents
service uses these to walk attack paths, compute blast-radius severity, and
discover the immediate neighbourhood of an entity during an investigation.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

_API_URL = os.getenv("API_SERVICE_URL", "http://api:8000")
_TIMEOUT = float(os.getenv("AGENTS_API_TIMEOUT", "10.0"))


def _headers(api_token: str | None) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_token}"} if api_token else {}


async def get_attack_path(
    case_id: str,
    api_token: str | None = None,
    max_depth: int = 6,
) -> dict[str, Any]:
    """Return the Case → Alert → Host/User → IOC → Technique attack path."""
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{_API_URL}/api/v1/graph/attack-path/{case_id}",
                params={"max_depth": max_depth},
                headers=_headers(api_token),
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return {"case_id": case_id, "nodes": [], "edges": [], "node_count": 0, "edge_count": 0}
        logger.warning("attack_path query failed", case_id=case_id, error=str(exc))
        return {"error": str(exc), "case_id": case_id, "nodes": [], "edges": []}
    except Exception as exc:  # noqa: BLE001
        logger.warning("attack_path query failed", case_id=case_id, error=str(exc))
        return {"error": str(exc), "case_id": case_id, "nodes": [], "edges": []}


async def get_blast_radius(
    entity_type: str,
    entity_id: str,
    api_token: str | None = None,
    hops: int = 3,
) -> dict[str, Any]:
    """Compute the blast radius starting from a Host/User/IOC/Alert node."""
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{_API_URL}/api/v1/graph/blast-radius/{entity_type}/{entity_id}",
                params={"hops": hops},
                headers=_headers(api_token),
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "blast_radius query failed",
            entity_type=entity_type,
            entity_id=entity_id,
            error=str(exc),
        )
        return {
            "error": str(exc),
            "entity_id": entity_id,
            "entity_type": entity_type,
            "affected_nodes": [],
            "total_affected": 0,
            "type_breakdown": {},
            "blast_radius_score": 0.0,
        }


async def get_entity_neighbors(
    entity_type: str,
    entity_id: str,
    api_token: str | None = None,
) -> dict[str, Any]:
    """Return all nodes directly connected (depth 1) to the specified entity."""
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{_API_URL}/api/v1/graph/neighbors/{entity_type}/{entity_id}",
                headers=_headers(api_token),
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "entity_neighbors query failed",
            entity_type=entity_type,
            entity_id=entity_id,
            error=str(exc),
        )
        return {
            "error": str(exc),
            "entity_id": entity_id,
            "entity_type": entity_type,
            "neighbors": [],
            "neighbor_count": 0,
        }
