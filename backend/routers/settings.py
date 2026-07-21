"""Operator settings — ingest paths and product info."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from services.app_mode import product_info
from services import runtime_config

router = APIRouter(prefix="/api/settings", tags=["settings"])


class IngestBody(BaseModel):
    modsec_audit_log: str = Field(
        ...,
        description="Absolute path to ModSecurity JSON Serial audit log (as seen by the backend)",
        min_length=1,
        max_length=4096,
    )


@router.get("")
@router.get("/mode")
@router.get("/product")
async def get_product_settings():
    """Product info + audit-log contract."""
    return product_info()


@router.get("/ingest")
async def get_ingest_settings():
    """Audit log path status for frontend setup / Settings."""
    return runtime_config.audit_log_status()


@router.put("/ingest")
async def put_ingest_settings(body: IngestBody):
    """
    Set ModSecurity audit log path at runtime.

    Persists to runtime_config.json on the data volume. The log tailer picks
    up the new path on the next poll (no full rebuild required).
    """
    try:
        status = runtime_config.set_audit_log_path(body.modsec_audit_log)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Could not save config: {exc}") from exc
    return {
        "ok": True,
        "message": (
            "Audit log path saved. The tailer will follow this path on the next poll."
            if status.get("exists")
            else "Path saved. File not found yet — tailer will wait until it appears."
        ),
        **status,
    }
