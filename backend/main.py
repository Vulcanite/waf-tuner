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

_root = os.path.join(os.path.dirname(__file__), "..")
load_dotenv(os.path.join(_root, "lab-data", ".env"))
load_dotenv(os.path.join(_root, ".env"))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from db.models import init_db, get_database_url
from services.crs_index import build_crs_index
import services.crs_index as _crs_module
from services.log_tailer import log_tailer
from services.agent import agent_worker
from routers import analytics, cases, events, exceptions, profiles, settings
from services.app_mode import product_info

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="WAF Tuner Backend",
    version="1.0.0",
    description="Observe ModSecurity logs and recommend CRS exclusions",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
    db_url = get_database_url()
    logger.info(
        "Initialising database schema (%s)…",
        db_url.split("///")[-1] if "///" in db_url else db_url,
    )
    await init_db()
    logger.info("Database schema ready")

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
    _crs_module.CRS_INDEX = build_crs_index(crs_dir)
    logger.info("CRS index ready: %d rules from %s", len(_crs_module.CRS_INDEX), crs_dir)

    worker_count = max(1, min(16, int(os.environ.get("AGENT_WORKER_CONCURRENCY", "1"))))
    app.state.background_tasks = [
        asyncio.create_task(log_tailer()),
        *[
            asyncio.create_task(agent_worker(worker_id))
            for worker_id in range(1, worker_count + 1)
        ],
    ]
    logger.info("Background tasks started (%d agent workers)", worker_count)


@app.on_event("shutdown")
async def shutdown():
    tasks = getattr(app.state, "background_tasks", [])
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


@app.get("/health")
async def health():
    info = product_info()
    return {
        "status": "ok",
        "deploy_enabled": info["deploy_enabled"],
        "service": info["service"],
    }


@app.get("/")
async def root():
    from services.runtime_config import audit_log_status

    return {
        "service": "waf-tuner-backend",
        "version": "1.0.0",
        **product_info(),
        "ingest": audit_log_status(),
    }
