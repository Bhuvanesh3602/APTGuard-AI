"""
Bridge: agent ``ProposedAction`` → Action Execution Service.

The CNI investigation agents emit ``ProposedAction`` objects with free-form
``action_type`` strings (``block_ip``, ``isolate_host``, ``notify``,
``block_network_segment`` …). The actions service speaks a fixed
``ActionType`` enum and applies a blast-radius gate that auto-executes
low-risk actions and escalates high-risk ones for human approval.

This module is the wiring between the two:

  * maps each agent action_type to a concrete actions-service ActionType
    (unknown types fall back to ``create_ticket`` so nothing is ever lost),
  * applies an **OT-safety** guard — host isolation is never sent for a
    safety-critical / OT asset; it is downgraded to network-level
    containment (the platform's "never isolate an OT host" invariant),
  * POSTs each action to ``{ACTIONS_SERVICE_URL}/api/v1/actions`` and returns
    a per-action result (executed vs awaiting-approval, blast radius, output).

Network failures degrade gracefully: a dispatch result carries
``dispatched: false`` + an ``error`` rather than raising, so a confirmed
investigation is never aborted because the SOAR layer is momentarily down.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
import structlog

from app.models.state import ProposedAction

logger = structlog.get_logger()

# Internal docker address is http://actions:8085; host port is 8002.
_DEFAULT_URL = "http://localhost:8002"

# agent action_type → actions-service ActionType value
_ACTION_TYPE_MAP: dict[str, str] = {
    "block_ip": "block_ip",
    "block_domain": "block_domain",
    "isolate_host": "isolate_host",
    "disable_user": "disable_user",
    "reset_password": "reset_password",
    "kill_process": "kill_process",
    "quarantine_file": "quarantine_file",
    "force_mfa": "force_mfa",
    "suspend_session": "suspend_session",
    "block_ioc": "block_ioc",
    "run_av_scan": "run_av_scan",
    # network segmentation is OT-safe network containment, not host isolation
    "block_network_segment": "block_ip",
    "notify": "notify_slack",
    "notify_slack": "notify_slack",
    "create_case": "create_ticket",
    "create_ticket": "create_ticket",
    # a threat hunt / forensics task has no direct executor — track it as a
    # ticket so the action is recorded and actionable rather than dropped.
    "create_hunt": "create_ticket",
    "capture_forensics": "create_ticket",
    "search_siem": "search_siem",
}

_FALLBACK_ACTION_TYPE = "create_ticket"

# Signals that an action is touching an OT / safety-critical asset.
_OT_MARKERS = (
    "plc", "scada", "modbus", "dnp3", "hmi", "rtu", "ot_", "ics",
    "safety_critical", "substation", "power_grid", "powergrid",
)


def _looks_like_ot(action: ProposedAction) -> bool:
    haystack = " ".join(
        [
            action.target or "",
            action.description or "",
            str(action.parameters or {}),
        ]
    ).lower()
    params = action.parameters or {}
    sector = str(params.get("sector", "")).lower()
    zone = str(params.get("network_zone", "")).lower()
    if sector in {"ot", "power_grid", "powergrid"} or zone.startswith("ot_"):
        return True
    return any(marker in haystack for marker in _OT_MARKERS)


def _map_action(action: ProposedAction) -> tuple[str, str | None]:
    """Return (actions_service_action_type, safety_note)."""
    raw = (action.action_type or "").lower()
    safety_note: str | None = None

    # OT-safety: never isolate a safety-critical / OT host.
    if raw == "isolate_host" and _looks_like_ot(action):
        safety_note = (
            "OT-SAFE: host isolation suppressed for safety-critical/OT asset "
            "(risk of physical process disruption); downgraded to network-level "
            "containment."
        )
        return "block_ip", safety_note

    return _ACTION_TYPE_MAP.get(raw, _FALLBACK_ACTION_TYPE), safety_note


class ActionsClient:
    def __init__(self, base_url: str | None = None, timeout: float = 8.0) -> None:
        self._base = (base_url or os.getenv("ACTIONS_SERVICE_URL") or _DEFAULT_URL).rstrip("/")
        self._timeout = timeout

    async def dispatch(
        self,
        action: ProposedAction,
        incident_id: str,
        tenant_id: str,
    ) -> dict[str, Any]:
        mapped_type, safety_note = _map_action(action)

        result: dict[str, Any] = {
            "action_id": str(action.id),
            "original_action_type": action.action_type,
            "mapped_action_type": mapped_type,
            "target": action.target,
            "agent_risk_level": action.risk_level.value if hasattr(action.risk_level, "value") else action.risk_level,
            "safety_adjusted": safety_note is not None,
            "safety_note": safety_note,
            "dispatched": False,
        }

        payload = {
            "id": str(action.id),
            "incident_id": incident_id,
            "tenant_id": tenant_id,
            "action_type": mapped_type,
            "target": action.target or "unspecified",
            "parameters": {
                **(action.parameters or {}),
                "origin": "cni_agent",
                "original_action_type": action.action_type,
                **({"ot_safety_note": safety_note} if safety_note else {}),
            },
            "requested_by": "cni_agent",
            "rationale": action.rationale or action.description,
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(f"{self._base}/api/v1/actions", json=payload)
            resp.raise_for_status()
            body = resp.json()
            result.update(
                {
                    "dispatched": True,
                    "status": body.get("status"),
                    "blast_radius": body.get("blast_radius"),
                    "gate_reason": body.get("gate_reason"),
                    "output": body.get("output"),
                    "requires_approval": body.get("status") == "awaiting_approval",
                }
            )
        except Exception as exc:  # noqa: BLE001
            result["error"] = str(exc)
            logger.warning(
                "actions_client.dispatch_failed",
                action_type=mapped_type,
                target=action.target,
                error=str(exc),
            )
        return result

    async def dispatch_many(
        self,
        actions: list[ProposedAction],
        incident_id: str,
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        results = []
        for action in actions:
            results.append(await self.dispatch(action, incident_id, tenant_id))
        return results


_singleton: ActionsClient | None = None


def get_actions_client() -> ActionsClient:
    global _singleton
    if _singleton is None:
        _singleton = ActionsClient()
    return _singleton


async def dispatch_proposed_actions(
    actions: list[ProposedAction],
    incident_id: str,
    tenant_id: str,
) -> dict[str, Any]:
    """Dispatch every proposed action and return a summary + per-action results."""
    client = get_actions_client()
    results = await client.dispatch_many(actions, incident_id, tenant_id)

    executed = [r for r in results if r.get("status") in ("completed", "approved")]
    awaiting = [r for r in results if r.get("requires_approval")]
    failed = [r for r in results if not r.get("dispatched")]
    return {
        "total": len(results),
        "executed": len(executed),
        "awaiting_approval": len(awaiting),
        "dispatch_failed": len(failed),
        "ot_safety_adjusted": sum(1 for r in results if r.get("safety_adjusted")),
        "results": results,
    }
