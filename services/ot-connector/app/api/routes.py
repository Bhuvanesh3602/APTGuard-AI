from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter

from app.models.ot_event import OCSFNetworkActivity, OTProtocol, OTRawEvent
from app.services.normaliser import normalise_to_ocsf

router = APIRouter(prefix="/api/v1/ot")


@router.post("/ingest", response_model=OCSFNetworkActivity)
async def ingest_ot_event(event: OTRawEvent) -> OCSFNetworkActivity:
    """Ingest a raw OT/ICS protocol event and normalise to OCSF."""
    return normalise_to_ocsf(event)


@router.post("/simulate/{protocol}")
async def simulate_ot_attack(protocol: OTProtocol) -> dict:
    """Simulate an OT attack event for demo/testing purposes."""
    from datetime import datetime
    demo_events = {
        OTProtocol.MODBUS: OTRawEvent(
            timestamp=datetime.now(UTC),
            protocol=OTProtocol.MODBUS,
            src_ip="192.168.1.50",  # IT network
            dst_ip="10.100.0.10",   # Power grid OT
            src_port=49152,
            dst_port=502,
            function_code=16,  # Write Multiple Registers
            unit_id=1,
            register_address=4096,
            register_value=9999,
            asset_id="plc-grid-001",
            asset_type="plc",
        ),
        OTProtocol.DNP3: OTRawEvent(
            timestamp=datetime.now(UTC),
            protocol=OTProtocol.DNP3,
            src_ip="10.100.0.99",  # Unknown master
            dst_ip="10.100.0.20",  # RTU
            src_port=20001,
            dst_port=20000,
            function_code=3,  # Direct Operate
            unit_id=5,
            register_address=0,
            register_value="TRIP",
            asset_id="rtu-substation-001",
            asset_type="rtu",
        ),
    }
    event = demo_events.get(protocol)
    if not event:
        return {"error": f"No demo available for {protocol}"}
    ocsf = normalise_to_ocsf(event)
    return ocsf.model_dump()


@router.get("/assets/classify")
async def classify_asset(asset_ip: str, check_process_state: bool = False) -> dict:
    """Classify an OT asset's criticality level."""
    from app.services.normaliser import _detect_cni_sector, _is_it_network
    sector = _detect_cni_sector(asset_ip)
    is_ot = not _is_it_network(asset_ip)
    return {
        "asset_ip": asset_ip,
        "is_ot": is_ot,
        "cni_sector": sector,
        "criticality": "critical" if sector in ("power_grid", "water_treatment") else "high",
        "ot_safe_response": is_ot,
        "isolation_prohibited": is_ot,
        "process_state": "running" if check_process_state else "unknown",
    }
