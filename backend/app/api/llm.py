"""LLM assistant endpoints. Any authenticated user may chat; retrieval respects ticket permissions."""
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.api.router import can_access_ticket, get_ticket
from app.core.database import get_db
from app.llm import assistant, knowledge
from app.llm.provider import provider_status
from app.llm.telemetry import llm_context
from app.models import User
from app.schemas import ChatIn
from app.security.auth import current_user, require_roles
from app.services.audit import audit

llm_api = APIRouter(prefix="/api/llm", tags=["llm"])


@llm_api.get("/status")
def status(_: User = Depends(current_user)):
    return provider_status()


@llm_api.post("/chat")
def chat(payload: ChatIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    with llm_context("asistente", user.id):
        result = assistant.chat(db, user, payload.message, [h.model_dump() for h in payload.history])
    # Audit the use, never the content of the conversation.
    audit(db, user.id, "CONSULTA_ASISTENTE", "IA", "LLM", None, new={"llm_used": result["llm_used"], "sources": len(result["sources"])}, request=request)
    db.commit()
    return result


@llm_api.get("/search")
def search(q: str = Query(min_length=2, max_length=300), limit: int = Query(8, ge=1, le=25),
           user: User = Depends(current_user), db: Session = Depends(get_db)):
    return {"query": q, "results": knowledge.search(db, user, q, limit=limit), "engine": "TF-IDF local (no usa LLM)"}


@llm_api.post("/tickets/{ticket_id}/summary")
def summary(ticket_id: str, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    ticket = get_ticket(db, ticket_id)
    can_access_ticket(user, ticket)
    with llm_context("resumen_ticket", user.id):
        result = assistant.summarize_ticket(db, user, ticket)
    audit(db, user.id, "RESUMEN_IA", "IA", "TICKET", ticket.id, new={"llm_used": result["llm_used"]}, request=request)
    db.commit()
    return result


@llm_api.post("/tickets/{ticket_id}/suggestions")
def suggestions(ticket_id: str, request: Request, user: User = Depends(require_roles("ADMIN", "JEFE_TI", "TECNICO")),
                db: Session = Depends(get_db)):
    # Served by the diagnosis agent, so the request is logged, audited and monitored like any agent run.
    from app.api.agents import run_diagnosis
    return run_diagnosis(db, user, ticket_id, request)
