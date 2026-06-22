"""
OT/ICS Event Normaliser → OCSF.

Converts raw Modbus/DNP3/SCADA protocol events to OCSF Network Activity
format with OT-specific extensions and MITRE ATT&CK for ICS technique mapping.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

import structlog

from app.models.ot_event import OCSFNetworkActivity, OTEventType, OTProtocol, OTRawEvent

logger = structlog.get_logger()

# Modbus function code → MITRE ICS technique mapping
MODBUS_FC_TO_ICS = {
    1: [],          # Read Coils — normal
    2: [],          # Read Discrete Inputs — normal
    3: [],          # Read Holding Registers — normal
    4: [],          # Read Input Registers — normal
    5: ["T0855", "T0831"],   # Write Single Coil — Unauthorized Command, Manipulation of Control
    6: ["T0836", "T0831"],   # Write Single Register — Modify Parameter
    15: ["T0855", "T0831"],  # Write Multiple Coils
    16: ["T0836", "T0821"],  # Write Multiple Registers — also Modify Controller Tasking
    22: ["T0856"],           # Mask Write Register — Spoof Reporting
    23: ["T0801", "T0802"],  # Read/Write Multiple Registers
    43: ["T0808"],           # Encapsulated Interface Transport — Device Identification
    90: ["T0855"],           # Custom / non-standard — flag
    125: ["T0873"],          # Firmware write
    126: ["T0857"],          # Program download/upload
}

# OT event severity mapping
OT_SEVERITY = {
    OTEventType.UNAUTHORIZED_WRITE: (5, "Critical"),
    OTEventType.REPLAY_ATTACK: (5, "Critical"),
    OTEventType.COIL_MANIPULATION: (5, "Critical"),
    OTEventType.IT_OT_CROSSING: (4, "High"),
    OTEventType.ANOMALOUS_FUNCTION_CODE: (4, "High"),
    OTEventType.SETPOINT_CHANGE: (3, "Medium"),
    OTEventType.PROCESS_DEVIATION: (3, "Medium"),
    OTEventType.UNKNOWN_MASTER: (4, "High"),
}

# India CNI sector detection from destination IP ranges (simplified)
INDIA_CNI_SECTORS = {
    "10.100.": "power_grid",
    "10.101.": "water_treatment",
    "10.102.": "oil_gas",
    "10.103.": "transport",
    "192.168.100.": "healthcare",
    "192.168.101.": "government",
}


def _detect_ot_event_type(event: OTRawEvent) -> OTEventType:
    fc = event.function_code
    if fc in (5, 6, 15, 16) and not _is_authorized_master(event.src_ip):
        return OTEventType.UNAUTHORIZED_WRITE
    if fc in (5, 6, 15, 16):
        return OTEventType.COIL_MANIPULATION
    if fc not in range(1, 20) and fc is not None:
        return OTEventType.ANOMALOUS_FUNCTION_CODE
    if _is_it_network(event.src_ip):
        return OTEventType.IT_OT_CROSSING
    return OTEventType.SETPOINT_CHANGE


def _is_authorized_master(ip: str) -> bool:
    authorized_ranges = ["10.0.100.", "10.0.101.", "192.168.50."]
    return any(ip.startswith(r) for r in authorized_ranges)


def _is_it_network(ip: str) -> bool:
    it_ranges = ["192.168.1.", "192.168.2.", "10.10."]
    return any(ip.startswith(r) for r in it_ranges)


def _detect_cni_sector(dst_ip: str) -> str:
    for prefix, sector in INDIA_CNI_SECTORS.items():
        if dst_ip.startswith(prefix):
            return sector
    return "industrial"


def normalise_to_ocsf(event: OTRawEvent) -> OCSFNetworkActivity:
    """Convert raw OT event to OCSF Network Activity with ICS extensions."""
    event_type = _detect_ot_event_type(event)
    sev_id, sev_name = OT_SEVERITY.get(event_type, (3, "Medium"))
    mitre_techniques = MODBUS_FC_TO_ICS.get(event.function_code or 0, [])
    sector = _detect_cni_sector(event.dst_ip)

    ocsf = OCSFNetworkActivity(
        severity_id=sev_id,
        severity=sev_name,
        time=int(event.timestamp.timestamp()),
        metadata={
            "version": "1.1.0",
            "product": {
                "name": "AiSOC OT Connector",
                "vendor_name": "AiSOC CNI",
                "feature": {"name": "OT/ICS Monitor"},
            },
            "profiles": ["network", "ot_ics"],
        },
        src_endpoint={
            "ip": event.src_ip,
            "port": event.src_port,
            "type": "unknown",
        },
        dst_endpoint={
            "ip": event.dst_ip,
            "port": event.dst_port,
            "type": "ot_device",
            "asset_id": event.asset_id,
            "asset_type": event.asset_type,
        },
        network_traffic={
            "protocol": event.protocol.value.upper(),
            "direction": "Unknown",
            "bytes_in": 0,
            "bytes_out": 0,
        },
        unmapped={
            "ot_unit_id": event.unit_id,
            "ot_register_address": event.register_address,
            "ot_register_value": str(event.register_value) if event.register_value is not None else None,
        },
        ot_protocol=event.protocol.value,
        ot_function_code=event.function_code,
        ot_unit_id=event.unit_id,
        ot_event_type=event_type.value,
        ot_asset_type=event.asset_type,
        mitre_ics_techniques=mitre_techniques,
        certin_category="CAT-10" if sev_id >= 4 else "CAT-3",
        india_cni_sector=sector,
    )

    logger.info(
        "OT event normalised to OCSF",
        protocol=event.protocol.value,
        event_type=event_type.value,
        severity=sev_name,
        mitre_techniques=mitre_techniques,
        sector=sector,
    )

    return ocsf
