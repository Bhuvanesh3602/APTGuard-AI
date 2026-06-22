from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class OTProtocol(str, Enum):
    MODBUS = "modbus"
    DNP3 = "dnp3"
    S7COMM = "s7comm"
    OPC_UA = "opc_ua"
    IEC104 = "iec104"
    PROFIBUS = "profibus"
    ETHERNET_IP = "ethernet_ip"


class OTEventType(str, Enum):
    UNAUTHORIZED_WRITE = "unauthorized_write"
    REPLAY_ATTACK = "replay_attack"
    ANOMALOUS_FUNCTION_CODE = "anomalous_function_code"
    SETPOINT_CHANGE = "setpoint_change"
    PROCESS_DEVIATION = "process_deviation"
    IT_OT_CROSSING = "it_ot_crossing"
    UNKNOWN_MASTER = "unknown_master"
    COIL_MANIPULATION = "coil_manipulation"


class OTRawEvent(BaseModel):
    """Raw OT/ICS protocol event before normalisation."""
    timestamp: datetime
    protocol: OTProtocol
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    function_code: int | None = None
    unit_id: int | None = None
    register_address: int | None = None
    register_value: Any = None
    data_raw: bytes | None = None
    asset_id: str = ""
    asset_type: str = ""  # plc, rtu, hmi, historian


class OCSFNetworkActivity(BaseModel):
    """OCSF Network Activity (class_uid 4001) for OT events."""
    class_uid: int = 4001
    class_name: str = "Network Activity"
    category_uid: int = 4
    category_name: str = "Network Activity"
    severity_id: int = 4  # High
    severity: str = "High"
    status: str = "Other"
    activity_id: int = 6  # Traffic
    activity_name: str = "Traffic"
    time: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)
    src_endpoint: dict[str, Any] = Field(default_factory=dict)
    dst_endpoint: dict[str, Any] = Field(default_factory=dict)
    network_traffic: dict[str, Any] = Field(default_factory=dict)
    unmapped: dict[str, Any] = Field(default_factory=dict)

    # OT-specific extensions
    ot_protocol: str = ""
    ot_function_code: int | None = None
    ot_unit_id: int | None = None
    ot_event_type: str = ""
    ot_asset_type: str = ""
    mitre_ics_techniques: list[str] = Field(default_factory=list)
    certin_category: str = "CAT-10"
    india_cni_sector: str = ""
