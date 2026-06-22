from __future__ import annotations

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router

logger = structlog.get_logger()

app = FastAPI(
    title="AiSOC EoL Vulnerability Prioritiser",
    description="CVE × End-of-Life amplification engine for India CNI asset risk ranking",
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
    return {"status": "ok", "service": "eol-prioritiser"}


@app.get("/")
async def root() -> dict:
    return {
        "service": "AiSOC EoL Vulnerability Prioritiser",
        "context": "India government networks: >70% EoL IT (National Cyber Security Policy 2023)",
        "methodology": "CVSS base score amplified by EoL multiplier (1.4–2.5×) — no patches ever available",
        "docs": "/docs",
    }
