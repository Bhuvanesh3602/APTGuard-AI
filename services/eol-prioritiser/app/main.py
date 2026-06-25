from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router

logger = structlog.get_logger()

_scheduler = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Warm the CISA KEV catalog and schedule periodic refreshes (best-effort)."""
    global _scheduler
    from app.services.cve_feed import get_cve_feed

    feed = get_cve_feed()
    try:
        status = await feed.refresh_kev()
        logger.info("eol.kev_warmed", **{k: status[k] for k in ("count", "source")})
    except Exception as exc:  # noqa: BLE001
        logger.warning("eol.kev_warm_failed", error=str(exc))

    if os.getenv("EOL_KEV_SCHEDULER_DISABLE", "").strip().lower() not in ("1", "true", "yes"):
        try:
            from apscheduler.schedulers.asyncio import AsyncIOScheduler

            _scheduler = AsyncIOScheduler()
            # Pass the bound coroutine method (not a lambda) so APScheduler
            # detects a coroutine function and awaits it on its event loop.
            _scheduler.add_job(
                feed.refresh_kev,
                "interval",
                hours=6,
                kwargs={"force": True},
                id="kev_refresh",
                max_instances=1,
            )
            _scheduler.start()
            logger.info("eol.kev_scheduler_started", interval_hours=6)
        except Exception as exc:  # noqa: BLE001
            logger.warning("eol.kev_scheduler_failed", error=str(exc))

    yield

    if _scheduler is not None:
        try:
            _scheduler.shutdown(wait=False)
        except Exception:  # noqa: BLE001
            pass


app = FastAPI(
    title="AiSOC EoL Vulnerability Prioritiser",
    description="CVE × End-of-Life amplification engine for India CNI asset risk ranking",
    version="1.0.0",
    lifespan=lifespan,
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
    from app.services.cve_feed import get_cve_feed

    return {
        "service": "AiSOC EoL Vulnerability Prioritiser",
        "context": "India government networks: >70% EoL IT (National Cyber Security Policy 2023)",
        "methodology": "CVSS base score amplified by EoL multiplier (1.4–2.5×) — no patches ever available",
        "live_feeds": {
            "nvd": "https://services.nvd.nist.gov (CVSS base scores)",
            "cisa_kev": "https://www.cisa.gov (actively-exploited catalog)",
            "kev_status": get_cve_feed().kev_status(),
        },
        "docs": "/docs",
    }
