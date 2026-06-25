"""
Live asset-graph backend for the Digital Twin.

This connects the Digital Twin to a real Neo4j graph instead of only the
static in-memory catalog. On startup it:

  1. Opens an async Neo4j driver (best-effort — failure never blocks boot).
  2. Seeds the CNI asset inventory (:CNIAsset nodes) and the lateral-movement
     topology (:CONNECTS_TO edges) into Neo4j if the graph is empty. This is
     the "clone the live asset inventory into the twin" step — in a real
     deployment the nodes already exist (written by the ingest service) and
     this MERGE is a no-op.
  3. Answers reachability / shortest-attack-path / blast-radius queries with
     live Cypher (``shortestPath`` over ``CONNECTS_TO``).

Every query degrades gracefully: if Neo4j is unreachable the same answer is
computed by an in-process BFS over the static catalog, so the API stays up
for demos even with no database.
"""

from __future__ import annotations

import structlog

from app.core.config import get_settings
from app.services.simulator import CNI_ASSETS

logger = structlog.get_logger()

# ── Lateral-movement topology (directed CONNECTS_TO edges) ──────────────────
# Models realistic attacker reachability between CNI assets. dc-01 is a
# deliberate hub: an attacker on the government domain controller can pivot
# into the OT DMZ and the education DMZ, which makes its blast radius the
# largest in the graph — a compelling demo of IT→OT convergence risk.
_ASSET_EDGES: list[tuple[str, str]] = [
    # Healthcare (AIIMS) — admin → clinical lateral movement
    ("aiims-ehr", "aiims-pacs"),
    ("aiims-pacs", "aiims-ward"),
    ("aiims-ehr", "aiims-ward"),
    # Education (CBSE) — DMZ → internal exam DB
    ("cbse-portal", "cbse-db"),
    # Power grid — IT/OT DMZ → field PLC
    ("pgcil-hmi", "pgcil-plc"),
    # Government IT — workstation ↔ domain controller
    ("ministry-ws", "dc-01"),
    ("dc-01", "ministry-ws"),
    # Cross-domain pivots from the government backbone (the dangerous ones)
    ("dc-01", "pgcil-hmi"),   # govt IT → OT DMZ (IT/OT convergence)
    ("dc-01", "cbse-portal"),  # shared govt network → education DMZ
]

_CRITICALITY_WEIGHT = {
    "safety_critical": 1.0,
    "critical": 0.8,
    "high": 0.6,
    "medium": 0.4,
    "low": 0.2,
}

_driver = None  # type: ignore[var-annotated]
_connected = False


# ── driver lifecycle ────────────────────────────────────────────────────────

async def init_graph() -> None:
    """Connect to Neo4j and seed the asset graph. Best-effort."""
    global _driver, _connected
    settings = get_settings()

    if settings.disable_neo4j:
        logger.info("digital_twin.neo4j_disabled", reason="AISOC_DISABLE_NEO4J")
        return

    try:
        from neo4j import AsyncGraphDatabase

        _driver = AsyncGraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
            max_connection_pool_size=20,
            connection_acquisition_timeout=15,
        )
        await _driver.verify_connectivity()
        _connected = True
        logger.info("digital_twin.neo4j_connected", uri=settings.neo4j_uri)
        await _ensure_seeded()
    except Exception as exc:  # noqa: BLE001
        _connected = False
        logger.warning(
            "digital_twin.neo4j_unavailable_static_fallback",
            uri=settings.neo4j_uri,
            error=str(exc),
        )


async def close_graph() -> None:
    global _driver, _connected
    if _driver is not None:
        try:
            await _driver.close()
        except Exception:  # noqa: BLE001
            pass
    _driver = None
    _connected = False


def is_connected() -> bool:
    return _connected


# ── seeding ─────────────────────────────────────────────────────────────────

async def _ensure_seeded() -> None:
    """MERGE the CNI asset catalog + topology into Neo4j if not already present."""
    async with _driver.session(database="neo4j") as session:  # type: ignore[union-attr]
        await session.run(
            "CREATE CONSTRAINT cni_asset_id IF NOT EXISTS "
            "FOR (a:CNIAsset) REQUIRE a.asset_id IS UNIQUE"
        )

        existing = await (await session.run("MATCH (a:CNIAsset) RETURN count(a) AS n")).single()
        if existing and existing["n"] >= len(CNI_ASSETS):
            logger.info("digital_twin.graph_already_seeded", nodes=existing["n"])
            return

        for asset in CNI_ASSETS.values():
            await session.run(
                """
                MERGE (a:CNIAsset {asset_id: $asset_id})
                SET a.name = $name, a.asset_type = $asset_type, a.sector = $sector,
                    a.criticality = $criticality, a.os = $os, a.is_eol = $is_eol,
                    a.eol_product = $eol_product, a.eol_amplifier = $eol_amplifier,
                    a.services = $services, a.vulnerabilities = $vulnerabilities,
                    a.network_zone = $network_zone
                """,
                asset_id=asset.asset_id,
                name=asset.name,
                asset_type=asset.asset_type.value,
                sector=asset.sector,
                criticality=asset.criticality.value,
                os=asset.os,
                is_eol=asset.is_eol,
                eol_product=asset.eol_product,
                eol_amplifier=asset.eol_amplifier,
                services=asset.services,
                vulnerabilities=asset.vulnerabilities,
                network_zone=asset.network_zone,
            )

        for src, dst in _ASSET_EDGES:
            await session.run(
                """
                MATCH (a:CNIAsset {asset_id: $src}), (b:CNIAsset {asset_id: $dst})
                MERGE (a)-[:CONNECTS_TO]->(b)
                """,
                src=src,
                dst=dst,
            )

    logger.info(
        "digital_twin.graph_seeded",
        nodes=len(CNI_ASSETS),
        edges=len(_ASSET_EDGES),
    )


# ── queries (Neo4j-backed, static fallback) ─────────────────────────────────

async def graph_status() -> dict:
    settings = get_settings()
    status = {
        "backend": "neo4j" if _connected else "static_fallback",
        "connected": _connected,
        "uri": settings.neo4j_uri,
        "static_assets": len(CNI_ASSETS),
        "static_edges": len(_ASSET_EDGES),
    }
    if _connected:
        try:
            async with _driver.session(database="neo4j") as session:  # type: ignore[union-attr]
                rec = await (
                    await session.run(
                        "MATCH (a:CNIAsset) "
                        "OPTIONAL MATCH (:CNIAsset)-[r:CONNECTS_TO]->(:CNIAsset) "
                        "RETURN count(DISTINCT a) AS nodes, count(r) AS edges"
                    )
                ).single()
                status["graph_nodes"] = rec["nodes"] if rec else 0
                status["graph_edges"] = rec["edges"] if rec else 0
        except Exception as exc:  # noqa: BLE001
            status["error"] = str(exc)
    return status


async def list_assets() -> list[dict]:
    """All CNI assets, read live from Neo4j when connected."""
    if _connected:
        try:
            async with _driver.session(database="neo4j") as session:  # type: ignore[union-attr]
                result = await session.run(
                    "MATCH (a:CNIAsset) RETURN a ORDER BY a.criticality, a.asset_id"
                )
                rows = [dict(rec["a"]) async for rec in result]
                if rows:
                    return rows
        except Exception as exc:  # noqa: BLE001
            logger.warning("digital_twin.list_assets_failed", error=str(exc))
    return [_asset_to_dict(a) for a in CNI_ASSETS.values()]


async def reachable_assets(asset_id: str, max_hops: int = 3) -> list[dict]:
    """Assets reachable from ``asset_id`` within ``max_hops`` lateral moves."""
    max_hops = max(1, min(max_hops, get_settings().max_hops))
    if asset_id not in CNI_ASSETS:
        raise ValueError(f"Unknown asset: {asset_id}")

    if _connected:
        try:
            return await _reachable_neo4j(asset_id, max_hops)
        except Exception as exc:  # noqa: BLE001
            logger.warning("digital_twin.reachable_neo4j_failed_fallback", error=str(exc))
    return _reachable_static(asset_id, max_hops)


async def attack_path(from_id: str, to_id: str, max_hops: int = 6) -> dict:
    """Shortest lateral-movement path between two assets."""
    max_hops = max(1, min(max_hops, get_settings().max_hops))
    for aid in (from_id, to_id):
        if aid not in CNI_ASSETS:
            raise ValueError(f"Unknown asset: {aid}")

    if _connected:
        try:
            return await _attack_path_neo4j(from_id, to_id, max_hops)
        except Exception as exc:  # noqa: BLE001
            logger.warning("digital_twin.attack_path_neo4j_failed_fallback", error=str(exc))
    return _attack_path_static(from_id, to_id, max_hops)


async def blast_radius(asset_id: str, max_hops: int = 3) -> dict:
    """Reachable assets + a criticality-weighted blast-radius score."""
    reachable = await reachable_assets(asset_id, max_hops)
    entry = CNI_ASSETS[asset_id]

    score = _CRITICALITY_WEIGHT.get(entry.criticality.value, 0.4)
    for r in reachable:
        score += _CRITICALITY_WEIGHT.get(r.get("criticality", "medium"), 0.4)

    safety_critical = [r for r in reachable if r.get("criticality") == "safety_critical"]
    sectors = sorted({r.get("sector") for r in reachable if r.get("sector")})

    return {
        "entry_asset": asset_id,
        "entry_name": entry.name,
        "backend": "neo4j" if _connected else "static_fallback",
        "reachable_count": len(reachable),
        "blast_radius_score": round(score, 2),
        "max_hops": max_hops,
        "sectors_impacted": sectors,
        "safety_critical_reached": [r["name"] for r in safety_critical],
        "crosses_into_ot": any(r.get("network_zone", "").startswith("OT_") for r in reachable),
        "reachable_assets": reachable,
    }


# ── Neo4j query implementations ──────────────────────────────────────────────

async def _reachable_neo4j(asset_id: str, max_hops: int) -> list[dict]:
    # ``max_hops`` is an int we clamped above, safe to interpolate into the
    # variable-length pattern (Cypher cannot parameterise path bounds).
    cypher = (
        "MATCH (start:CNIAsset {asset_id: $id}) "
        f"MATCH p = shortestPath((start)-[:CONNECTS_TO*1..{max_hops}]->(t:CNIAsset)) "
        "WHERE t.asset_id <> $id "
        "RETURN t.asset_id AS asset_id, t.name AS name, t.criticality AS criticality, "
        "t.sector AS sector, t.network_zone AS network_zone, length(p) AS hops "
        "ORDER BY hops ASC, t.criticality ASC"
    )
    async with _driver.session(database="neo4j") as session:  # type: ignore[union-attr]
        result = await session.run(cypher, id=asset_id)
        return [dict(rec) async for rec in result]


async def _attack_path_neo4j(from_id: str, to_id: str, max_hops: int) -> dict:
    cypher = (
        "MATCH (a:CNIAsset {asset_id: $from}), (b:CNIAsset {asset_id: $to}) "
        f"MATCH p = shortestPath((a)-[:CONNECTS_TO*1..{max_hops}]->(b)) "
        "RETURN [n IN nodes(p) | {asset_id: n.asset_id, name: n.name, "
        "criticality: n.criticality, network_zone: n.network_zone}] AS hops, "
        "length(p) AS length"
    )
    async with _driver.session(database="neo4j") as session:  # type: ignore[union-attr]
        rec = await (await session.run(cypher, **{"from": from_id, "to": to_id})).single()
        if not rec:
            return {"reachable": False, "from": from_id, "to": to_id, "path": [], "hops": None}
        return {
            "reachable": True,
            "from": from_id,
            "to": to_id,
            "path": rec["hops"],
            "hops": rec["length"],
            "backend": "neo4j",
        }


# ── static BFS fallback ──────────────────────────────────────────────────────

def _adjacency() -> dict[str, list[str]]:
    adj: dict[str, list[str]] = {aid: [] for aid in CNI_ASSETS}
    for src, dst in _ASSET_EDGES:
        adj.setdefault(src, []).append(dst)
    return adj


def _reachable_static(asset_id: str, max_hops: int) -> list[dict]:
    adj = _adjacency()
    visited: dict[str, int] = {}
    frontier = [(asset_id, 0)]
    while frontier:
        node, dist = frontier.pop(0)
        if dist >= max_hops:
            continue
        for nxt in adj.get(node, []):
            if nxt not in visited or visited[nxt] > dist + 1:
                if nxt != asset_id:
                    visited[nxt] = dist + 1
                frontier.append((nxt, dist + 1))

    out = []
    for aid, hops in sorted(visited.items(), key=lambda x: x[1]):
        a = CNI_ASSETS[aid]
        out.append(
            {
                "asset_id": aid,
                "name": a.name,
                "criticality": a.criticality.value,
                "sector": a.sector,
                "network_zone": a.network_zone,
                "hops": hops,
            }
        )
    return out


def _attack_path_static(from_id: str, to_id: str, max_hops: int) -> dict:
    adj = _adjacency()
    # BFS keeping the predecessor for path reconstruction
    prev: dict[str, str] = {}
    frontier = [(from_id, 0)]
    seen = {from_id}
    found = False
    while frontier:
        node, dist = frontier.pop(0)
        if node == to_id:
            found = True
            break
        if dist >= max_hops:
            continue
        for nxt in adj.get(node, []):
            if nxt not in seen:
                seen.add(nxt)
                prev[nxt] = node
                frontier.append((nxt, dist + 1))

    if not found:
        return {"reachable": False, "from": from_id, "to": to_id, "path": [], "hops": None,
                "backend": "static_fallback"}

    chain = [to_id]
    while chain[-1] != from_id:
        chain.append(prev[chain[-1]])
    chain.reverse()
    path = [
        {
            "asset_id": aid,
            "name": CNI_ASSETS[aid].name,
            "criticality": CNI_ASSETS[aid].criticality.value,
            "network_zone": CNI_ASSETS[aid].network_zone,
        }
        for aid in chain
    ]
    return {"reachable": True, "from": from_id, "to": to_id, "path": path,
            "hops": len(chain) - 1, "backend": "static_fallback"}


def _asset_to_dict(asset) -> dict:
    return {
        "asset_id": asset.asset_id,
        "name": asset.name,
        "asset_type": asset.asset_type.value,
        "sector": asset.sector,
        "criticality": asset.criticality.value,
        "os": asset.os,
        "is_eol": asset.is_eol,
        "eol_product": asset.eol_product,
        "eol_amplifier": asset.eol_amplifier,
        "services": asset.services,
        "vulnerabilities": asset.vulnerabilities,
        "network_zone": asset.network_zone,
    }
