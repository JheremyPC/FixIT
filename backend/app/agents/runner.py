"""Execution engine shared by every FixIT agent.

Each run:
1. checks that the agent is enabled and takes its lock (``agent_states``: one atomic conditional
   UPDATE, so two processes or instances can never run the same exclusive agent at once; a lock
   left by a crashed process expires after ``lock_minutes``);
2. writes an ``agent_runs`` row (status EN_CURSO) in its own transaction, visible to the monitor;
3. executes the agent on the work session and commits its business changes atomically, or rolls
   them all back on error;
4. records status, duration, summary, result or a sanitized error, releases the lock and writes an
   audit log entry, even when the agent failed.

Agents return what they stored (``result``: counts and ticket references) separately from what is
only sent back to the caller (``response``: e.g. the LLM text), so generated text is never logged.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

from fastapi import HTTPException
from sqlalchemy import or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.llm.provider import SECRET_PATTERN, LLMError
from app.llm.telemetry import llm_context
from app.ml.predictor import ModelNotTrained
from app.models import AgentRun, AgentState, User, uid
from app.services.audit import audit

UTC = timezone.utc
log = logging.getLogger("fixit.agents")
RUNNING, OK, PARTIAL, ERROR, INTERRUPTED = "EN_CURSO", "OK", "PARCIAL", "ERROR", "INTERRUMPIDA"
TRIGGERS = {"MANUAL", "PROGRAMADA", "USUARIO", "TICKET"}


class AgentBusy(RuntimeError):
    pass


class AgentDisabled(RuntimeError):
    pass


@dataclass
class Output:
    summary: str
    result: dict = field(default_factory=dict)
    response: dict | None = None
    status: str = OK


@dataclass
class Context:
    db: Session
    actor: User | None
    run_id: str
    trigger: str
    params: dict
    inputs: dict
    ticket_id: str | None
    now: datetime


@dataclass
class Spec:
    name: str
    func: Callable[[Context], Output]
    exclusive: bool = True          # one run at a time across processes
    lock_minutes: int = 15
    schedulable: bool = False


REGISTRY: dict[str, Spec] = {}


def register(spec: Spec) -> None:
    REGISTRY[spec.name] = spec


def safe_error(exc: Exception) -> str:
    if isinstance(exc, HTTPException):
        text = str(exc.detail)
    elif isinstance(exc, (ModelNotTrained, LLMError, LookupError, ValueError, AgentBusy, AgentDisabled)):
        text = str(exc)
    else:
        text = f"Error interno ({type(exc).__name__}). Revise los registros del servidor."
    return " ".join(SECRET_PATTERN.sub("[redactado]", text).split())[:500]


def ensure_states(db: Session) -> None:
    """Create missing agent_states rows and close runs left EN_CURSO by a process that died."""
    now = datetime.now(UTC)
    existing = {s.agent: s for s in db.scalars(select(AgentState))}
    for name in REGISTRY:
        if name not in existing:
            db.add(AgentState(agent=name, enabled=True))
    try:
        db.commit()
    except IntegrityError:  # another instance created them first
        db.rollback()
    live = {s.lock_run_id for s in db.scalars(select(AgentState)) if s.lock_run_id and s.lock_expires_at and _aware(s.lock_expires_at) > now}
    for run in db.scalars(select(AgentRun).where(AgentRun.status == RUNNING)):
        minutes = REGISTRY[run.agent].lock_minutes if run.agent in REGISTRY else 15
        if run.id not in live and _aware(run.started_at) < now - timedelta(minutes=minutes):
            run.status, run.finished_at, run.error = INTERRUPTED, now, "La ejecución no terminó (reinicio o caída del proceso)."
    db.commit()


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _begin(spec: Spec, run_id: str, actor: User | None, trigger: str, params: dict, ticket_id: str | None, started: datetime,
           exclusive: bool) -> None:
    book = SessionLocal()
    try:
        if book.get(AgentState, spec.name) is None:
            ensure_states(book)
        state = book.get(AgentState, spec.name)
        if not state.enabled:
            raise AgentDisabled(f"El agente «{spec.name}» está deshabilitado.")
        if exclusive:
            taken = book.execute(update(AgentState).where(
                AgentState.agent == spec.name,
                or_(AgentState.lock_run_id.is_(None), AgentState.lock_expires_at < started))
                .values(lock_run_id=run_id, lock_expires_at=started + timedelta(minutes=spec.lock_minutes))
                .execution_options(synchronize_session=False)).rowcount
            if taken != 1:
                book.rollback()
                raise AgentBusy(f"El agente «{spec.name}» ya se está ejecutando. Espere a que termine.")
        elif ticket_id and book.scalar(select(AgentRun.id).where(
                AgentRun.agent == spec.name, AgentRun.ticket_id == ticket_id, AgentRun.status == RUNNING,
                AgentRun.started_at > started - timedelta(minutes=spec.lock_minutes))):
            raise AgentBusy(f"Ya hay una ejecución de «{spec.name}» en curso para este ticket.")
        book.add(AgentRun(id=run_id, agent=spec.name, trigger=trigger, status=RUNNING, actor_id=actor.id if actor else None,
                          ticket_id=ticket_id, params=params or None, started_at=started))
        book.commit()
    finally:
        book.close()


def _finish(spec: Spec, run_id: str, actor: User | None, status: str, out: Output | None, error: str | None,
            started: datetime, request) -> AgentRun:
    finished = datetime.now(UTC)
    book = SessionLocal()
    try:
        run = book.get(AgentRun, run_id)
        run.status, run.finished_at = status, finished
        run.duration_ms = int((finished - started).total_seconds() * 1000)
        run.summary = (out.summary if out else None) and out.summary[:500]
        run.result = out.result if out else None
        run.error = error
        state = book.get(AgentState, spec.name)
        state.last_run_at = finished
        if state.lock_run_id == run_id:
            state.lock_run_id = state.lock_expires_at = None
        audit(book, actor.id if actor else None, f"AGENTE_{spec.name.upper()}", "AGENTES", "AGENT_RUN", run_id,
              new={"status": status, "trigger": run.trigger, "ticket_id": run.ticket_id, "duration_ms": run.duration_ms}, request=request)
        book.commit()
        book.refresh(run)
        book.expunge(run)
        return run
    finally:
        book.close()


def run_agent(name: str, actor: User | None, trigger: str = "MANUAL", params: dict | None = None, inputs: dict | None = None,
              ticket_id: str | None = None, db: Session | None = None, request=None) -> dict:
    """Run an agent and return its run record (plus ``response`` when the agent sends something back).
    Raises AgentBusy / AgentDisabled / KeyError before anything is executed."""
    spec = REGISTRY[name]
    params = params or {}
    run_id, started = uid(), datetime.now(UTC)
    # Read-only suggestions for text being written (``inputs``) never wait for, nor block, a batch run.
    _begin(spec, run_id, actor, trigger, params, ticket_id, started, spec.exclusive and not inputs)
    work = db or SessionLocal()
    out, error, status = None, None, ERROR
    try:
        ctx = Context(db=work, actor=actor, run_id=run_id, trigger=trigger, params=params, inputs=inputs or {},
                      ticket_id=ticket_id, now=started)
        with llm_context(f"agente:{name}", actor.id if actor else None, run_id):
            out = spec.func(ctx)
        work.commit()
        status = out.status
    except Exception as exc:
        work.rollback()
        error = safe_error(exc)
        if not isinstance(exc, (HTTPException, ModelNotTrained, LookupError, ValueError)):
            log.exception("Agente %s falló (ejecución %s)", name, run_id)
    finally:
        if db is None:
            work.close()
        run = _finish(spec, run_id, actor, status, out if error is None else None, error, started, request)
    data = run_data(run)
    if out is not None and error is None and out.response is not None:
        data["response"] = out.response
    return data


def run_data(run: AgentRun, detail: bool = True) -> dict:
    data = {"id": run.id, "agent": run.agent, "trigger": run.trigger, "status": run.status, "ticket_id": run.ticket_id,
            "summary": run.summary, "error": run.error, "started_at": run.started_at, "finished_at": run.finished_at,
            "duration_ms": run.duration_ms, "params": run.params}
    if detail:
        data["result"] = run.result
    return data
