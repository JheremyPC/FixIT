"""AI agents and LLM monitoring. Administration and the global monitor are restricted to ADMIN and
JEFE_TI; other roles only reach the functions they are authorized for (ticket triage suggestions
while writing a ticket, diagnosis of tickets they can access)."""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.agents import catalog
from app.agents.runner import REGISTRY, AgentBusy, AgentDisabled, ensure_states, run_agent, run_data
from app.api.router import can_access_ticket, get_ticket
from app.core.database import get_db
from app.llm.provider import provider_status
from app.ml import store
from app.models import AgentAlert, AgentRun, AgentState, LLMCall, User
from app.schemas import AgentConfigIn, AgentRunIn, TriageSuggestIn
from app.security.auth import current_user, require_roles
from app.services.audit import audit

agents_api = APIRouter(prefix="/api/agents", tags=["agents"])
managers = require_roles("ADMIN", "JEFE_TI")
PARAMS = {"triage": ("limit",), "sla_risk": ("threshold",), "assignment": ("mode", "limit"),
          "automation": ("tasks", "inactive_hours"), "diagnosis": ()}


def _agent(name: str) -> str:
    if name not in REGISTRY:
        raise HTTPException(404, "Agente no encontrado")
    return name


def _run(name: str, actor: User | None, request: Request, db: Session, **kwargs) -> dict:
    try:
        return run_agent(name, actor, db=db, request=request, **kwargs)
    except (AgentBusy, AgentDisabled) as exc:
        raise HTTPException(409, str(exc))


def run_diagnosis(db: Session, user: User, ticket_id: str, request: Request) -> dict:
    """Diagnosis agent for one ticket; the caller must be allowed to see it. Returns the assistant answer."""
    ticket = get_ticket(db, ticket_id)
    can_access_ticket(user, ticket)
    run = _run("diagnosis", user, request, db, trigger="TICKET", ticket_id=ticket.id)
    if "response" not in run:
        raise HTTPException(502, run["error"] or "El agente de diagnóstico no devolvió resultado.")
    return {**run["response"], "agent_run": {k: run[k] for k in ("id", "status", "duration_ms", "summary")}}


def _state_data(state: AgentState | None, now: datetime) -> dict:
    expires = state.lock_expires_at if state else None
    if expires and not expires.tzinfo:
        expires = expires.replace(tzinfo=timezone.utc)
    return {"enabled": state.enabled if state else True, "schedule_minutes": state.schedule_minutes if state else None,
            "running": bool(state and state.lock_run_id and expires and expires > now)}


@agents_api.get("")
def overview(_: User = Depends(managers), db: Session = Depends(get_db)):
    """Agents, their academic justification and evaluation, and the regression model metrics."""
    ensure_states(db)
    meta = store.load_metadata() or {}
    resolution = (meta.get("models") or {}).get("resolution") or {}
    metrics = resolution.get("metrics") or {}
    regression = {"status": resolution.get("status"), "algorithm": resolution.get("algorithm"), "version": meta.get("version"),
                  "trained_at": meta.get("trained_at"), "n_train": resolution.get("n_train"), "n_test": resolution.get("n_test"),
                  "message": resolution.get("message"),
                  "metrics": {k: metrics.get(k) for k in ("mae_hours", "rmse_hours", "r2_hours", "r2_log", "median_ae_hours",
                                                          "baseline_mae_hours", "improvement_vs_baseline_pct", "within_50pct")}}
    return {"agents": [{"name": n, "schedulable": REGISTRY[n].schedulable, **catalog.CATALOG[n], "metrics": catalog.evaluation(db, n)}
                       for n in REGISTRY], "regression": regression}


@agents_api.get("/monitor")
def monitor(_: User = Depends(managers), db: Session = Depends(get_db), limit: int = Query(30, ge=5, le=100)):
    """Lightweight snapshot polled every few seconds by the dashboard."""
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=24)
    states = {s.agent: s for s in db.scalars(select(AgentState))}
    agents = []
    for name in REGISTRY:
        last = db.scalar(select(AgentRun).where(AgentRun.agent == name).order_by(AgentRun.started_at.desc()).limit(1))
        last_error = db.scalar(select(AgentRun).where(AgentRun.agent == name, AgentRun.status == "ERROR")
                               .order_by(AgentRun.started_at.desc()).limit(1))
        agents.append({"name": name, "title": catalog.CATALOG[name]["title"], **_state_data(states.get(name), now),
                       "last_run": run_data(last, detail=False) if last else None,
                       "last_error": {"at": last_error.started_at, "error": last_error.error} if last_error else None,
                       "runs_24h": db.scalar(select(func.count()).select_from(AgentRun).where(AgentRun.agent == name, AgentRun.started_at >= since)) or 0})
    runs = db.scalars(select(AgentRun).options(joinedload(AgentRun.actor)).order_by(AgentRun.started_at.desc()).limit(limit)).all()
    calls = db.scalars(select(LLMCall).order_by(LLMCall.created_at.desc()).limit(limit)).all()
    rows = db.execute(select(LLMCall.status, LLMCall.model, LLMCall.fallback_used, LLMCall.duration_ms).where(LLMCall.created_at >= since)).all()
    answered = [r for r in rows if r[0] == "OK"]
    by_model: dict[str, int] = {}
    for r in answered:
        by_model[r[1] or "—"] = by_model.get(r[1] or "—", 0) + 1
    llm_status = provider_status()
    return {
        "generated_at": now, "agents": agents,
        "runs": [{**run_data(r, detail=False), "actor": r.actor.full_name if r.actor else "Sistema"} for r in runs],
        "llm": {"configured": llm_status["configured"], "provider": llm_status["provider"], "model": llm_status["model"],
                "calls": [{"id": c.id, "created_at": c.created_at, "source": c.source, "provider": c.provider, "model": c.model,
                           "fallback_used": c.fallback_used, "status": c.status, "duration_ms": c.duration_ms, "error": c.error} for c in calls],
                "stats_24h": {"total": len(rows), "ok": len(answered), "errors": sum(1 for r in rows if r[0] == "ERROR"),
                              "not_configured": sum(1 for r in rows if r[0] == "NO_CONFIGURADO"),
                              "fallback": sum(1 for r in answered if r[2]),
                              "avg_ms": round(sum(r[3] for r in answered) / len(answered)) if answered else None, "by_model": by_model}},
        "alerts_24h": db.scalar(select(func.count()).select_from(AgentAlert).where(AgentAlert.created_at >= since)) or 0,
    }


@agents_api.get("/runs/{run_id}")
def run_detail(run_id: str, _: User = Depends(managers), db: Session = Depends(get_db)):
    run = db.get(AgentRun, run_id)
    if not run:
        raise HTTPException(404, "Ejecución no encontrada")
    return {**run_data(run), "actor": run.actor.full_name if run.actor else "Sistema"}


@agents_api.get("/alerts")
def alerts(limit: int = Query(50, ge=1, le=200), _: User = Depends(managers), db: Session = Depends(get_db)):
    rows = db.scalars(select(AgentAlert).order_by(AgentAlert.created_at.desc()).limit(limit)).all()
    return [{"id": a.id, "agent": a.agent, "kind": a.kind, "level": a.level, "ticket_id": a.ticket_id, "message": a.message,
             "value": a.value, "created_at": a.created_at} for a in rows]


@agents_api.post("/triage/suggest")
def triage_suggest(payload: TriageSuggestIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Priority and category suggestion for a ticket being written. The text is not stored; the
    category comes from aggregated votes of similar tickets, so no other ticket's content is exposed."""
    run = _run("triage", user, request, db, trigger="USUARIO", params={"chars": len(payload.title) + len(payload.description)},
               inputs=payload.model_dump())
    if "response" not in run:
        raise HTTPException(502, run["error"] or "No se pudo generar la sugerencia.")
    return run["response"]


@agents_api.post("/diagnosis/tickets/{ticket_id}")
def diagnose(ticket_id: str, request: Request, user: User = Depends(require_roles("ADMIN", "JEFE_TI", "TECNICO")),
             db: Session = Depends(get_db)):
    return run_diagnosis(db, user, ticket_id, request)


@agents_api.post("/{name}/run")
def run(name: str, payload: AgentRunIn, request: Request, actor: User = Depends(managers), db: Session = Depends(get_db)):
    name = _agent(name)
    if name == "diagnosis":
        if not payload.ticket_id:
            raise HTTPException(422, "El agente de diagnóstico requiere ticket_id")
        return run_diagnosis(db, actor, payload.ticket_id, request)
    if payload.ticket_id:
        get_ticket(db, payload.ticket_id)
    data = payload.model_dump()
    params = {k: data[k] for k in PARAMS[name] if data.get(k) is not None}
    return _run(name, actor, request, db, trigger="MANUAL", params=params, ticket_id=payload.ticket_id)


@agents_api.patch("/{name}")
def configure(name: str, payload: AgentConfigIn, request: Request, actor: User = Depends(managers), db: Session = Depends(get_db)):
    name = _agent(name)
    ensure_states(db)
    state = db.get(AgentState, name)
    old = {"enabled": state.enabled, "schedule_minutes": state.schedule_minutes}
    if payload.enabled is not None:
        state.enabled = payload.enabled
    if payload.clear_schedule:
        state.schedule_minutes = None
    elif payload.schedule_minutes is not None:
        if not REGISTRY[name].schedulable:
            raise HTTPException(422, "Este agente no admite ejecución programada")
        state.schedule_minutes = payload.schedule_minutes
    audit(db, actor.id, "CONFIGURAR_AGENTE", "AGENTES", "AGENT", name, old=old,
          new={"enabled": state.enabled, "schedule_minutes": state.schedule_minutes}, request=request)
    db.commit()
    return {"name": name, **_state_data(state, datetime.now(timezone.utc))}
