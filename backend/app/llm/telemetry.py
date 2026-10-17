"""LLM observability: one ``llm_calls`` row per request with metadata only (source, model, status,
duration, sanitized error). Prompts, answers, conversations and credentials are never stored.

Callers label their requests with ``llm_context(source=..., user_id=..., run_id=...)``. The row is
written in its own short transaction so it survives a rollback of the caller, and a failure to
record never breaks the LLM call itself.
"""
from __future__ import annotations

import logging
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone

logger = logging.getLogger("fixit.llm")
_context: ContextVar[dict] = ContextVar("fixit_llm_context", default={})
ERROR_MAX = 300


@contextmanager
def llm_context(source: str, user_id: str | None = None, run_id: str | None = None):
    token = _context.set({"source": source[:40], "user_id": user_id, "run_id": run_id})
    try:
        yield
    finally:
        _context.reset(token)


def record(provider: str | None, model: str | None, status: str, duration_ms: int, error: str | None = None,
           fallback_used: bool = False) -> None:
    from app.core.database import SessionLocal
    from app.llm.provider import SECRET_PATTERN, _api_key
    from app.models import LLMCall

    ctx = _context.get()
    if error:
        key = _api_key()
        error = SECRET_PATTERN.sub("[redactado]", error.replace(key, "[redactado]") if key else error)
        error = " ".join(error.split())[:ERROR_MAX]
    db = SessionLocal()
    try:
        db.add(LLMCall(created_at=datetime.now(timezone.utc), source=ctx.get("source") or "asistente", provider=provider,
                       model=(model or "")[:100] or None, fallback_used=fallback_used, status=status, duration_ms=duration_ms,
                       error=error, user_id=ctx.get("user_id"), run_id=ctx.get("run_id")))
        db.commit()
    except Exception:
        db.rollback()
        logger.warning("No se pudo registrar la llamada LLM en llm_calls", exc_info=True)
    finally:
        db.close()
