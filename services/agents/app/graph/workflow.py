"""
LangGraph workflow: wires Auto-Triage → Triage → Enrichment → Investigation
→ Attack-Path agents.

Auto-triage runs first.  If the LLM classifies the alert as FP/benign with
confidence above the auto-close threshold the graph terminates early.
Otherwise the alert flows through the full manual pipeline, ending with the
graph-aware Attack-Path agent that walks Neo4j to compute blast radius.
"""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from app.agents.apt_prediction_agent import run_apt_prediction
from app.agents.attack_path_agent import run_attack_path
from app.agents.auto_triage_agent import run_auto_triage
from app.agents.certin_agent import run_certin_compliance
from app.agents.enrichment_agent import run_enrichment
from app.agents.eol_vuln_agent import run_eol_vuln
from app.agents.india_apt_agent import run_india_apt
from app.agents.investigation_agent import run_investigation
from app.agents.ot_risk_agent import run_ot_risk
from app.agents.triage_agent import run_triage
from app.models.state import AgentStatus, InvestigationState

logger = structlog.get_logger()


def _state_dict(state: InvestigationState) -> dict:
    return state.to_dict()


def _from_dict(d: dict) -> InvestigationState:
    return InvestigationState.model_validate(d)


# ---- Node wrappers (LangGraph uses dict state, we wrap our Pydantic model) ----


async def auto_triage_node(state: dict) -> dict:
    s = _from_dict(state)
    s = await run_auto_triage(s)
    return s.to_dict()


async def triage_node(state: dict) -> dict:
    s = _from_dict(state)
    s = await run_triage(s)
    return s.to_dict()


async def enrichment_node(state: dict) -> dict:
    s = _from_dict(state)
    s = await run_enrichment(s)
    return s.to_dict()


async def investigation_node(state: dict) -> dict:
    s = _from_dict(state)
    s = await run_investigation(s)
    return s.to_dict()


async def attack_path_node(state: dict) -> dict:
    s = _from_dict(state)
    s = await run_attack_path(s)
    return s.to_dict()


async def india_apt_node(state: dict) -> dict:
    s = _from_dict(state)
    s = await run_india_apt(s)
    return s.to_dict()


async def apt_prediction_node(state: dict) -> dict:
    s = _from_dict(state)
    s = await run_apt_prediction(s)
    return s.to_dict()


async def ot_risk_node(state: dict) -> dict:
    s = _from_dict(state)
    s = await run_ot_risk(s)
    return s.to_dict()


async def eol_vuln_node(state: dict) -> dict:
    s = _from_dict(state)
    s = await run_eol_vuln(s)
    return s.to_dict()


async def certin_node(state: dict) -> dict:
    s = _from_dict(state)
    s = await run_certin_compliance(s)
    return s.to_dict()


def _should_continue(state: dict) -> str:
    """Conditional edge: stop if max iterations reached or status is terminal."""
    s = _from_dict(state)
    if s.iteration_count >= s.max_iterations:
        return "end"
    if s.status in (AgentStatus.COMPLETED, AgentStatus.FAILED, AgentStatus.CANCELLED):
        return "end"
    return "continue"


def _after_auto_triage(state: dict) -> str:
    """Route after auto-triage: auto-closed alerts go to END, others continue."""
    s = _from_dict(state)
    if s.status == AgentStatus.COMPLETED:
        return "end"
    return "continue"


def build_investigation_graph() -> StateGraph:
    """Build and compile the CNI investigation workflow graph.

    Flow:
        auto_triage ─┬─ (high-confidence FP/benign) ──► END
                      └─ (else) ──► triage ──► enrichment ──► investigation
                                          ──► attack_path ──► india_apt
                                          ──► apt_prediction ──► ot_risk
                                          ──► eol_vuln ──► certin ──► END
    """
    graph = StateGraph(dict)

    graph.add_node("auto_triage", auto_triage_node)
    graph.add_node("triage", triage_node)
    graph.add_node("enrichment", enrichment_node)
    graph.add_node("investigation", investigation_node)
    graph.add_node("attack_path", attack_path_node)
    graph.add_node("india_apt", india_apt_node)
    graph.add_node("apt_prediction", apt_prediction_node)
    graph.add_node("ot_risk", ot_risk_node)
    graph.add_node("eol_vuln", eol_vuln_node)
    graph.add_node("certin", certin_node)

    graph.set_entry_point("auto_triage")

    graph.add_conditional_edges(
        "auto_triage",
        _after_auto_triage,
        {"end": END, "continue": "triage"},
    )
    graph.add_edge("triage", "enrichment")
    graph.add_edge("enrichment", "investigation")
    graph.add_edge("investigation", "attack_path")
    graph.add_edge("attack_path", "india_apt")
    graph.add_edge("india_apt", "apt_prediction")
    graph.add_edge("apt_prediction", "ot_risk")
    graph.add_edge("ot_risk", "eol_vuln")
    graph.add_edge("eol_vuln", "certin")
    graph.add_edge("certin", END)

    return graph.compile()


# Module-level compiled graph (singleton)
investigation_graph = build_investigation_graph()
