"""Digital Twin Attack Simulation Service."""

from __future__ import annotations

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router

logger = structlog.get_logger()

app = FastAPI(
    title="AiSOC Digital Twin Simulator",
    description=(
        "Clone-and-attack simulation for India CNI network graphs. "
        "Runs adversary attack paths on an isolated Neo4j twin without touching production. "
        "Supports what-if analysis for risk-ranked remediation planning."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/healthz")
async def health() -> dict:
    return {"status": "ok", "service": "digital-twin"}


@app.get("/")
async def root() -> dict:
    return {
        "service": "AiSOC Digital Twin Simulator",
        "purpose": "Attack path simulation on isolated Neo4j CNI graph clone",
        "capabilities": [
            "BFS attack path analysis from any CNI asset",
            "Blast radius scoring with EoL amplification",
            "CERT-In category mapping per simulated scenario",
            "OT-SAFE impact classification (SAFETY_CRITICAL → network segmentation only)",
            "What-if control evaluation with risk delta measurement",
        ],
        "graph": {
            "node_labels": 17,
            "edge_types": 14,
            "cni_assets": 9,
            "sectors": ["Healthcare", "Education", "Power Grid", "Govt IT", "Telecom"],
        },
        "docs": "/docs",
    }
