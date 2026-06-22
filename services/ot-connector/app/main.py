from __future__ import annotations

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router

logger = structlog.get_logger()

app = FastAPI(
    title="AiSOC OT/ICS Connector",
    description="Modbus/DNP3/SCADA telemetry normaliser to OCSF for India CNI environments",
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
    return {"status": "ok", "service": "ot-connector"}


@app.get("/")
async def root() -> dict:
    return {
        "service": "AiSOC OT/ICS Connector",
        "protocols": ["Modbus/TCP", "DNP3", "S7Comm", "OPC-UA", "IEC 60870-5-104"],
        "output_format": "OCSF Network Activity (class_uid 4001)",
        "india_cni_sectors": ["power_grid", "water_treatment", "oil_gas", "transport"],
        "docs": "/docs",
    }
