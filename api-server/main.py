"""
WAF Exception Agent — api-server entrypoint (FastAPI)

Startup sequence:
1. Run init.sql idempotently against Postgres.
2. Ensure events.jsonl and tracker.json exist.
3. Build CRS rule index.
4. Start background tasks: log_tailer, agent_worker, stale_checker.
"""
import asyncio
import json
import logging
import os

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "../.env"))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from db.models import init_db
from services.crs_index import build_crs_index, CRS_INDEX
import services.crs_index as _crs_module
from services.offset_tracker import ensure_tracker
from services.log_tailer import log_tailer
from services.agent import agent_worker
from services.stale_checker import stale_checker
from routers import events, exceptions, deploy, analytics

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(title="WAF Exception Agent API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(events.router)
app.include_router(exceptions.router)
app.include_router(deploy.router)
app.include_router(analytics.router)


@app.on_event("startup")
async def startup():
    # 1. Init Postgres schema
    logger.info("Initialising database schema…")
    await init_db()
    logger.info("Database schema ready")

    # 2. Ensure data files exist
    events_path = os.environ.get("EVENTS_JSONL_PATH", "/app/data/events.jsonl")
    data_dir = os.path.dirname(events_path)
    os.makedirs(data_dir, exist_ok=True)

    if not os.path.exists(events_path):
        open(events_path, "w").close()
        logger.info("Created events.jsonl at %s", events_path)

    ensure_tracker()

    # Ensure exceptions directory exists
    exceptions_dir = os.environ.get("MODSEC_EXCEPTIONS_DIR", "/app/data/exceptions/")
    os.makedirs(exceptions_dir, exist_ok=True)

    # 3. Build CRS rule index
    crs_dir = os.environ.get("CRS_RULES_DIR", "/etc/nginx/modsecurity/crs/rules/")
    _crs_module.CRS_INDEX = build_crs_index(crs_dir)
    logger.info("CRS index ready: %d rules", len(_crs_module.CRS_INDEX))

    # 4. Start background tasks
    asyncio.create_task(log_tailer())
    asyncio.create_task(agent_worker())
    asyncio.create_task(stale_checker())
    logger.info("Background tasks started")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/")
async def root():
    return {"service": "waf-exception-agent", "version": "1.0.0"}
