"""
Digital Twin configuration.

Kept dependency-light (plain ``os.environ``) so the service has no
pydantic-settings requirement. Accepts both ``NEO4J_URL`` (used by this
service's docker-compose block) and ``NEO4J_URI`` (used by the rest of the
stack) so it works regardless of which the operator set.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    neo4j_uri: str
    neo4j_user: str
    neo4j_password: str
    disable_neo4j: bool
    max_hops: int

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            neo4j_uri=os.getenv("NEO4J_URL") or os.getenv("NEO4J_URI") or "bolt://localhost:7687",
            neo4j_user=os.getenv("NEO4J_USER", "neo4j"),
            neo4j_password=os.getenv("NEO4J_PASSWORD", "neo4j_dev_secret"),
            disable_neo4j=_truthy(os.getenv("AISOC_DISABLE_NEO4J")),
            max_hops=int(os.getenv("DIGITAL_TWIN_MAX_HOPS", "6")),
        )


def get_settings() -> Settings:
    return Settings.from_env()
