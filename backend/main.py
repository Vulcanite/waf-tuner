"""
WAF Tuner backend — FastAPI entrypoint.

Startup:
1. SQLite schema
2. Event archive files
3. CRS rule index
4. Background tasks: log_tailer, agent_worker(s)
"""
import asyncio
import logging
import os

from dotenv import load_dotenv

APP_VERSION = "0.1.0"

_root = os.path.join(os.path.dirname(__file__), "..")
load_dotenv(os.path.join(_root, "lab-data", ".env"))
load_dotenv(os.path.join(_root, ".env"))

from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware

from db.models import init_db, get_database_url
from services.application_context import ensure_default_application_profile
from services.crs_index import initialize_crs_index
from services.log_tailer import INGEST_STATE, log_tailer
from services.agent import (
    agent_worker, analysis_lease_reaper, initialize_analysis_queue, start_analysis_provider,
    stop_analysis_provider,
)
from routers import analytics, cases, events, exceptions, profiles, settings
from services.app_mode import product_info
from services.inference_retention import inference_retention_worker, retention_days

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="WAF Tuner Backend",
    version=APP_VERSION,
    description="Observe ModSecurity logs and recommend CRS exclusions",
)

# Opt-in only. Empty default keeps loopback Compose same-origin (frontend proxy).
# Example for Vite dev: CORS_ALLOW_ORIGINS=http://localhost:5173
_cors_origins = [
    origin.strip()
    for origin in os.environ.get("CORS_ALLOW_ORIGINS", "").split(",")
    if origin.strip()
]
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.include_router(events.router)
app.include_router(exceptions.router)
app.include_router(analytics.router)
app.include_router(profiles.router)
app.include_router(cases.router)
app.include_router(settings.router)


@app.on_event("startup")
async def startup():
    provider_days = retention_days("INFERENCE_ARTIFACT_RETENTION_DAYS")
    audit_days = retention_days("AUDIT_EVIDENCE_RETENTION_DAYS")
    db_url = get_database_url()
    logger.info(
        "Initialising database schema (%s)…",
        db_url.split("///")[-1] if "///" in db_url else db_url,
    )
    await init_db()
    logger.info("Database schema ready")
    if await ensure_default_application_profile():
        logger.info("Created default-lab application route profile")

    events_path = os.environ.get("EVENTS_JSONL_PATH", "/shared/events.jsonl")
    data_dir = os.path.dirname(events_path) or "/shared"
    os.makedirs(data_dir, exist_ok=True)
    if not os.path.exists(events_path):
        open(events_path, "w").close()
        logger.info("Created events.jsonl at %s", events_path)

    logger.info("Observe-only: no edge deploy or config writes")
    try:
        from services.runtime_config import get_audit_log_path, audit_log_status

        logger.info("Ingest audit log: %s", get_audit_log_path())
        logger.info("Ingest status: %s", audit_log_status())
    except Exception as exc:
        logger.warning("Could not resolve audit log path: %s", exc)

    crs_dir = os.environ.get("CRS_RULES_DIR", "/shared/crs-rules/")
    logger.info("CRS index status: %s", await asyncio.to_thread(initialize_crs_index, crs_dir))

    worker_count = max(1, min(16, int(os.environ.get("AGENT_WORKER_CONCURRENCY", "4"))))
    queue_changed = initialize_analysis_queue()
    app.state.tailer_task = asyncio.create_task(log_tailer(queue_changed))
    app.state.background_tasks = [app.state.tailer_task]
    if await start_analysis_provider(worker_count):
        app.state.background_tasks.extend([
            asyncio.create_task(analysis_lease_reaper()),
            *(asyncio.create_task(agent_worker(worker_id)) for worker_id in range(1, worker_count + 1)),
        ])
        logger.info("Background tasks started (%d agent workers)", worker_count)
    else:
        logger.warning("Audit ingest remains available while inference configuration is invalid")
    if provider_days or audit_days:
        app.state.background_tasks.append(asyncio.create_task(
            inference_retention_worker(provider_days, audit_days)
        ))


@app.on_event("shutdown")
async def shutdown():
    tasks = getattr(app.state, "background_tasks", [])
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    await stop_analysis_provider()


@app.get("/health")
async def health(response: Response):
    info = product_info()
    tailer = getattr(app.state, "tailer_task", None)
    # Healthy only while audit ingestion is actually running.
    ingest = "stopped" if tailer is None or tailer.done() else INGEST_STATE["state"]
    if ingest != "running":
        response.status_code = 503
    return {
        "status": "ok" if ingest == "running" else "degraded",
        "ingest": ingest,
        "ingest_error": INGEST_STATE["error"],
        "deploy_enabled": info["deploy_enabled"],
        "service": info["service"],
    }


@app.get("/")
async def root():
    from services.runtime_config import audit_log_status

    return {
        "service": "waf-tuner-backend",
        "version": APP_VERSION,
        **product_info(),
        "ingest": audit_log_status(),
    }
