from __future__ import annotations

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router

logger = structlog.get_logger()

app = FastAPI(
    title="AiSOC CERT-In Reporter",
    description="Automated CERT-In 6-hour mandatory incident reporting service — CERT-In Directions 2022",
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
    return {"status": "ok", "service": "certin-reporter"}


@app.get("/")
async def root() -> dict:
    return {
        "service": "AiSOC CERT-In Reporter",
        "regulation": "CERT-In Directions 2022 under Section 70B of IT Act 2000",
        "deadline": "6 hours from incident detection",
        "portal": "https://incident.cert-in.org.in",
        "docs": "/docs",
    }
