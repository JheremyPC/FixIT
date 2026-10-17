"""Runs schedulable agents (automation) at the interval an ADMIN/JEFE_TI configured. Disabled until
someone sets ``schedule_minutes``. The runner's lock prevents overlapping runs across processes."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.agents.runner import REGISTRY, AgentBusy, AgentDisabled, run_agent
from app.core.database import SessionLocal
from app.models import AgentState

log = logging.getLogger("fixit.agents")
CHECK_SECONDS = 30


def due_agents(now: datetime) -> list[str]:
    db = SessionLocal()
    try:
        out = []
        for state in db.scalars(select(AgentState).where(AgentState.enabled.is_(True), AgentState.schedule_minutes.is_not(None))):
            spec = REGISTRY.get(state.agent)
            last = state.last_run_at.replace(tzinfo=timezone.utc) if state.last_run_at and not state.last_run_at.tzinfo else state.last_run_at
            if spec and spec.schedulable and (last is None or last + timedelta(minutes=state.schedule_minutes) <= now):
                out.append(state.agent)
        return out
    finally:
        db.close()


def tick() -> list[dict]:
    runs = []
    for name in due_agents(datetime.now(timezone.utc)):
        try:
            runs.append(run_agent(name, None, trigger="PROGRAMADA"))
        except (AgentBusy, AgentDisabled):
            pass
    return runs


async def scheduler_loop(stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=CHECK_SECONDS)
            break
        except asyncio.TimeoutError:
            pass
        try:
            await asyncio.to_thread(tick)
        except Exception:
            log.exception("Error en la programación de agentes")
