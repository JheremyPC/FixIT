"""The five FixIT agents. They reuse the trained models (app.ml), the TF-IDF ticket index and the
LLM assistant (app.llm), and change tickets only through the existing business rules
(app.services.tickets.assign, AssignmentService). Every function receives a runner Context and
returns an Output; persistence of the run, locking and audit are handled by app.agents.runner."""
from __future__ import annotations

from collections import defaultdict
from contextlib import nullcontext
from datetime import timedelta

import numpy as np
from sklearn.metrics.pairwise import linear_kernel
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.agents.runner import OK, PARTIAL, Context, Output, Spec, register
from app.llm import assistant, knowledge
from app.ml import predictor as ml
from app.ml.dataset import OPEN_STATES
from app.models import AgentAlert, Area, Category, Role, Technician, Ticket, TicketState, User
from app.services.assignment import AssignmentService
from app.services.audit import audit, notify
from app.services.tickets import assign

NEEDS_ASSIGNMENT = {"NUEVO", "REABIERTO", "ESCALADO"}
ACTIVE_WORK = {"ASIGNADO", "EN_ATENCION", "EN_ESPERA"}
MAX_ITEMS = 50          # items kept in agent_runs.result
MAX_ALERTS = 200        # new alerts per run; the rest are raised on the next run


def _short(text: str | None, size: int = 90) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= size else text[: size - 1] + "…"


def _chiefs(db: Session) -> list[User]:
    return db.scalars(select(User).join(User.role).where(Role.code.in_(["ADMIN", "JEFE_TI"]), User.active.is_(True))).all()


def _savepoint(db: Session):
    """SAVEPOINT on PostgreSQL. pysqlite (tests, local SQLite) mishandles SAVEPOINT, so it is skipped there."""
    return db.begin_nested() if db.get_bind().dialect.name == "postgresql" else nullcontext()


def _raise_alert(db: Session, ctx: Context, agent: str, key: str, kind: str, level: str, message: str,
                 ticket_id: str | None = None, value: float | None = None) -> bool:
    """Insert the alert unless its dedup_key exists. The unique constraint is the final guard against
    concurrent duplicates (savepoint, so a collision does not undo the rest of the run)."""
    if db.scalar(select(AgentAlert.id).where(AgentAlert.dedup_key == key)):
        return False
    try:
        with _savepoint(db):
            db.add(AgentAlert(dedup_key=key[:120], agent=agent, kind=kind, level=level, ticket_id=ticket_id,
                              run_id=ctx.run_id, message=message[:300], value=value))
    except IntegrityError:
        return False
    return True


# --------------------------------------------------------------------------- 1. Triage

def similar_category(db: Session, text: str, exclude_id: str | None = None, k: int = 15) -> dict | None:
    """k-NN over the TF-IDF ticket index: categories of the most similar tickets, weighted by similarity.
    Only aggregated category names leave this function (no ticket content)."""
    index = knowledge.get_index(db)
    if index["vectorizer"] is None or not knowledge.analyze(text):
        return None
    scores = linear_kernel(index["vectorizer"].transform([text]), index["matrix"]).ravel()
    votes: dict[str, float] = defaultdict(float)
    used = 0
    for i in scores.argsort()[::-1]:
        if scores[i] <= 0.05 or used >= k:
            break
        if index["meta"][i]["id"] == exclude_id:
            continue
        votes[index["meta"][i]["category"]] += float(scores[i])
        used += 1
    if not votes:
        return None
    name, weight = max(votes.items(), key=lambda v: v[1])
    category = db.scalar(select(Category).where(Category.name == name))
    return {"id": category.id if category else None, "name": name, "confidence": round(weight / sum(votes.values()), 3), "neighbors": used}


def suggest_for_text(db: Session, title: str, description: str, area_id: str | None, category_id: str | None) -> dict:
    model = ml.Predictor()
    area = db.get(Area, area_id) if area_id else None
    category_suggestion = similar_category(db, f"{title} {title} {description}")
    category = db.get(Category, category_id) if category_id else None
    category_name = category.name if category else (category_suggestion or {}).get("name", "")
    priority = model.suggest_priority(title, description, area.name if area else "", category_name) if model.prio else None
    return {"priority": priority, "category": category_suggestion,
            "available": {"priority_model": model.prio is not None, "category_index": category_suggestion is not None}}


def triage(ctx: Context) -> Output:
    db = ctx.db
    if ctx.inputs.get("title"):  # suggestion for a ticket being written (no ticket yet; text is not stored)
        out = suggest_for_text(db, ctx.inputs["title"], ctx.inputs.get("description", ""), ctx.inputs.get("area_id"), ctx.inputs.get("category_id"))
        p, c = out["priority"], out["category"]
        summary = f"Sugerencia: prioridad {p['code'] if p else 'no disponible'}, categoría {c['name'] if c else 'no disponible'}"
        return Output(summary, {"priority": p and p["code"], "category": c and c["name"]}, response=out,
                      status=OK if p or c else PARTIAL)

    model = ml.Predictor()
    query = select(Ticket).join(TicketState, TicketState.id == Ticket.state_id)
    if ctx.ticket_id:
        query = query.where(Ticket.id == ctx.ticket_id)
    else:
        query = query.where(TicketState.code.in_(["NUEVO", "REABIERTO"])).order_by(Ticket.created_at.desc()).limit(int(ctx.params.get("limit", MAX_ITEMS)))
    tickets = db.scalars(query).all()
    if ctx.ticket_id and not tickets:
        raise LookupError("Ticket no encontrado")
    hours = {}
    try:
        hours = {r["id"]: r for r in ml.score_open(db)["rows"]}
    except ml.ModelNotTrained:
        pass
    items, priority_diff, category_diff = [], 0, 0
    for t in tickets:
        p = model.suggest_priority(t.title, t.description, t.area.name, t.category.name) if model.prio else None
        c = similar_category(db, f"{t.title} {t.title} {t.description}", exclude_id=t.id)
        priority_diff += bool(p and p["code"] != t.priority.code)
        category_diff += bool(c and c["name"] != t.category.name)
        row = hours.get(t.id, {})
        items.append({"ticket_id": t.id, "number": t.number, "title": _short(t.title), "state": t.state.code,
                      "priority": t.priority.code, "suggested_priority": p and p["code"],
                      "priority_confidence": p and p["probabilities"][p["code"]],
                      "category": t.category.name, "suggested_category": c and c["name"], "category_confidence": c and c["confidence"],
                      "predicted_hours": row.get("predicted_hours"), "sla_risk": row.get("sla_risk")})
    n = len(items)
    result = {"evaluated": n, "priority_model": model.prio is not None, "priority_differs": priority_diff, "category_differs": category_diff,
              "priority_agreement": round(1 - priority_diff / n, 3) if n and model.prio else None,
              "category_agreement": round(1 - category_diff / n, 3) if n else None, "items": items[:MAX_ITEMS]}
    summary = (f"{n} tickets clasificados: {priority_diff} con prioridad distinta a la registrada y "
               f"{category_diff} con categoría distinta" if n else "No hay tickets nuevos o reabiertos por clasificar")
    return Output(summary, result, status=OK if model.prio or not n else PARTIAL)


# --------------------------------------------------------------------------- 2. SLA risk

def sla_risk(ctx: Context) -> Output:
    db = ctx.db
    threshold = float(ctx.params.get("threshold", 0.6))
    scored = ml.score_open(db)
    rows = sorted(scored["rows"], key=lambda r: (not r["overdue"], -r["sla_risk"]))
    tickets = {t.id: t for t in db.scalars(select(Ticket).where(Ticket.id.in_([r["id"] for r in rows])))} if rows else {}
    new, duplicates, items = 0, 0, []
    per_chief = 0
    for r in rows:
        if not (r["overdue"] or r["sla_risk"] >= threshold):
            continue
        if new >= MAX_ALERTS:
            break
        kind = "SLA_VENCIDO" if r["overdue"] else "SLA_RIESGO"
        level = "vencido" if r["overdue"] else r["risk_level"]
        key = f"{kind}:{r['id']}:{r['due_at'][:16]}"
        message = (f"{r['number']}: SLA vencido, se estima {r['predicted_remaining_hours']} h más de trabajo" if r["overdue"] else
                   f"{r['number']}: riesgo de incumplir el SLA {r['sla_risk']:.0%} (tiempo estimado {r['predicted_hours']} h)")
        if not _raise_alert(db, ctx, "sla_risk", key, kind, level, message, r["id"], r["sla_risk"]):
            duplicates += 1
            continue
        new += 1
        ticket = tickets.get(r["id"])
        if ticket and ticket.technician:
            notify(db, ticket.technician.user_id, "ALERTA_SLA", f"Alerta SLA {r['number']}", message, r["id"])
        else:
            per_chief += 1
        if len(items) < MAX_ITEMS:
            items.append({"ticket_id": r["id"], "number": r["number"], "title": _short(r["title"]), "kind": kind,
                          "sla_risk": r["sla_risk"], "predicted_hours": r["predicted_hours"], "due_at": r["due_at"],
                          "technician": r["technician"]})
    if new:
        for chief in _chiefs(db):
            notify(db, chief.id, "ALERTA_SLA", f"{new} nuevas alertas de SLA",
                   f"El agente de riesgo SLA generó {new} alertas ({per_chief} sin técnico asignado). Revise Machine Learning → Agentes.")
    high = sum(1 for r in rows if r["sla_risk"] >= threshold)
    result = {"evaluated": len(rows), "threshold": threshold, "high_risk": high, "overdue": sum(r["overdue"] for r in rows),
              "new_alerts": new, "duplicates_skipped": duplicates, "model_version": scored["predictor"].model_info()["version"],
              "items": items}
    return Output(f"{len(rows)} tickets abiertos evaluados: {high} con riesgo ≥ {threshold:.0%}, "
                  f"{result['overdue']} vencidos; {new} alertas nuevas, {duplicates} ya emitidas", result)


# --------------------------------------------------------------------------- 3. Assignment

def assignment(ctx: Context) -> Output:
    db = ctx.db
    execute = ctx.params.get("mode") == "ejecutar"
    limit = min(int(ctx.params.get("limit", 10)), MAX_ITEMS)
    try:
        scored = ml.score_open(db)
        records = {r["id"]: r for r in scored["records"]}
    except ml.ModelNotTrained:
        scored, records = None, {}
    query = (select(Ticket).join(TicketState, TicketState.id == Ticket.state_id)
             .where(TicketState.code.in_(NEEDS_ASSIGNMENT) | (Ticket.technician_id.is_(None) & TicketState.code.in_(OPEN_STATES))))
    if ctx.ticket_id:
        query = select(Ticket).where(Ticket.id == ctx.ticket_id)
    tickets = db.scalars(query.order_by(Ticket.due_at).limit(limit)).all()
    if ctx.ticket_id and not tickets:
        raise LookupError("Ticket no encontrado")
    rules = AssignmentService(db)
    items, assigned, skipped = [], 0, 0
    for t in tickets:
        item = {"ticket_id": t.id, "number": t.number, "title": _short(t.title), "state": t.state.code, "category": t.category.name}
        if t.state.code not in OPEN_STATES or (t.state.code not in NEEDS_ASSIGNMENT and t.technician_id):
            item.update(action="omitido", reason="El ticket ya tiene técnico asignado" if t.state.code in OPEN_STATES else "El ticket no está abierto")
            skipped += 1
            items.append(item)
            continue
        choice = None
        if scored and t.id in records:
            options = ml.recommend(scored["predictor"], records[t.id], scored["tracker"], scored["techs"], top=5)
            required = t.category.specialty_id
            valid = [o for o in options if not o["at_capacity"] and (o["specialty_match"] or not required)]
            item["options"] = [{k: o[k] for k in ("name", "sla_risk", "predicted_hours", "open_tickets", "max_load")} for o in options[:3]]
            if valid:
                o = valid[0]
                choice = (db.get(Technician, o["technician_id"]), round((1 - o["sla_risk"]) * 100, 2), "AGENTE_ML",
                          f"Agente de asignación (ML): {o['reason']}")
        if choice is None:  # no trained model or no valid ML option: deterministic business rule
            candidate = rules.select(t)
            if candidate:
                choice = (candidate.technician, candidate.score, "AGENTE_REGLAS", f"Agente de asignación (reglas): {candidate.reason}")
        if choice is None:
            item.update(action="sin candidato", reason="No hay técnico disponible con la especialidad y capacidad requeridas")
            items.append(item)
            continue
        tech, score, kind, reason = choice
        item.update(technician=tech.user.full_name, score=score, method=kind, reason=reason)
        if execute:
            if not tech.available or not tech.user.active:
                item.update(action="omitido", reason="El técnico dejó de estar disponible")
                skipped += 1
            else:
                assign(db, t, tech, ctx.actor.id if ctx.actor else None, kind, score, reason)
                audit(db, ctx.actor.id if ctx.actor else None, "ASIGNAR_AGENTE", "TICKETS", "TICKET", t.id,
                      new={"technician_id": tech.id, "score": score, "method": kind, "run_id": ctx.run_id})
                if scored:
                    scored["tracker"].open_by_tech[tech.id] = scored["tracker"].open_by_tech.get(tech.id, 0) + 1
                db.flush()
                item["action"] = "asignado"
                assigned += 1
        else:
            item["action"] = "recomendado"
        items.append(item)
    recommended = sum(1 for i in items if i.get("technician"))
    result = {"mode": "ejecutar" if execute else "recomendar", "evaluated": len(tickets), "recommended": recommended,
              "assigned": assigned, "skipped": skipped, "ml_model": scored is not None, "items": items}
    summary = (f"{len(tickets)} tickets sin asignar evaluados: {assigned} asignados, {skipped} omitidos" if execute else
               f"{len(tickets)} tickets sin asignar evaluados: {recommended} con técnico recomendado")
    return Output(summary, result, status=OK if scored or not tickets else PARTIAL)


# --------------------------------------------------------------------------- 4. Diagnosis

def diagnosis(ctx: Context) -> Output:
    if not ctx.ticket_id or ctx.actor is None:
        raise ValueError("El agente de diagnóstico requiere un ticket y un usuario.")
    ticket = ctx.db.get(Ticket, ctx.ticket_id)
    if ticket is None:
        raise LookupError("Ticket no encontrado")
    answer = assistant.suggest_diagnosis(ctx.db, ctx.actor, ticket)
    sources = answer.get("sources") or []
    result = {"ticket": ticket.number, "similar_cases": len(sources), "similar": [{"number": s["number"], "score": s["score"]} for s in sources],
              "llm_used": answer.get("llm_used", False), "model": answer.get("model")}
    if answer.get("llm_used"):
        summary = f"{ticket.number}: sugerencia generada con {answer.get('model')} a partir de {len(sources)} casos similares"
    else:
        summary = f"{ticket.number}: {len(sources)} casos similares; sin respuesta del LLM"
    return Output(summary, result, response=answer, status=OK if answer.get("llm_used") else PARTIAL)


# --------------------------------------------------------------------------- 5. Automation

AUTOMATION_TASKS = ("alertas_sla", "seguimiento_atrasados", "seguimiento_inactivos", "resumen_operativo")


def _followups(ctx: Context, kind: str, tickets: list[Ticket], message) -> dict:
    day = ctx.now.strftime("%Y%m%d")
    sent = duplicates = unassigned = 0
    for t in tickets[:MAX_ALERTS]:
        text = message(t)
        if not _raise_alert(ctx.db, ctx, "automation", f"{kind}:{t.id}:{day}", kind, "seguimiento", text, t.id):
            duplicates += 1
            continue
        sent += 1
        if t.technician:
            notify(ctx.db, t.technician.user_id, kind, f"Seguimiento {t.number}", text, t.id)
        else:
            unassigned += 1
    if unassigned:
        for chief in _chiefs(ctx.db):
            notify(ctx.db, chief.id, kind, "Tickets sin técnico requieren seguimiento",
                   f"{unassigned} tickets sin técnico asignado necesitan seguimiento ({kind.lower()}).")
    return {"candidates": len(tickets), "reminders": sent, "already_sent_today": duplicates, "unassigned": unassigned}


def operational_summary(db: Session, now) -> dict:
    open_q = select(TicketState.code, func.count()).select_from(Ticket).join(TicketState, TicketState.id == Ticket.state_id) \
        .where(TicketState.code.in_(OPEN_STATES)).group_by(TicketState.code)
    by_state = dict(db.execute(open_q).all())
    since = now - timedelta(hours=24)
    count = lambda *where: db.scalar(select(func.count()).select_from(Ticket).join(TicketState, TicketState.id == Ticket.state_id).where(*where)) or 0
    return {"open": sum(by_state.values()), "open_by_state": by_state,
            "overdue": count(TicketState.code.in_(OPEN_STATES), Ticket.due_at < now),
            "unassigned": count(TicketState.code.in_(OPEN_STATES), Ticket.technician_id.is_(None)),
            "created_24h": count(Ticket.created_at >= since), "resolved_24h": count(Ticket.resolved_at >= since),
            "sla_alerts_24h": db.scalar(select(func.count()).select_from(AgentAlert)
                                        .where(AgentAlert.kind.in_(["SLA_RIESGO", "SLA_VENCIDO"]), AgentAlert.created_at >= since)) or 0}


def automation(ctx: Context) -> Output:
    db = ctx.db
    tasks = [t for t in (ctx.params.get("tasks") or AUTOMATION_TASKS) if t in AUTOMATION_TASKS]
    if not tasks:
        raise ValueError("No se indicó ninguna tarea autorizada.")
    inactive_hours = int(ctx.params.get("inactive_hours", 48))
    open_tickets = lambda *where: db.scalars(select(Ticket).join(TicketState, TicketState.id == Ticket.state_id)
                                             .where(*where).order_by(Ticket.due_at)).all()
    report, failures = {}, []
    for task in tasks:
        try:
            with _savepoint(db):
                if task == "alertas_sla":
                    out = sla_risk(ctx)
                    report[task] = {k: out.result[k] for k in ("evaluated", "high_risk", "overdue", "new_alerts", "duplicates_skipped")}
                elif task == "seguimiento_atrasados":
                    report[task] = _followups(ctx, "SEGUIMIENTO_ATRASO", open_tickets(TicketState.code.in_(OPEN_STATES), Ticket.due_at < ctx.now),
                                              lambda t: f"{t.number} superó su SLA ({t.priority.code}). Actualice el avance o escale el ticket.")
                elif task == "seguimiento_inactivos":
                    report[task] = _followups(ctx, "SEGUIMIENTO_INACTIVO", open_tickets(
                        TicketState.code.in_(ACTIVE_WORK), Ticket.updated_at < ctx.now - timedelta(hours=inactive_hours)),
                        lambda t: f"{t.number} no tiene actividad desde hace más de {inactive_hours} h. Registre el avance.")
                elif task == "resumen_operativo":
                    summary = operational_summary(db, ctx.now)
                    text = (f"Abiertos {summary['open']}, vencidos {summary['overdue']}, sin técnico {summary['unassigned']}, "
                            f"creados 24 h {summary['created_24h']}, resueltos 24 h {summary['resolved_24h']}, alertas SLA 24 h {summary['sla_alerts_24h']}.")
                    sent = _raise_alert(db, ctx, "automation", f"RESUMEN:{ctx.now:%Y%m%d}", "RESUMEN", "info", text)
                    if sent:
                        for chief in _chiefs(db):
                            notify(db, chief.id, "RESUMEN_OPERATIVO", f"Resumen operativo {ctx.now:%d/%m/%Y}", text)
                    report[task] = {**summary, "notified": sent}
        except ml.ModelNotTrained as exc:
            report[task] = {"error": str(exc)}
            failures.append(task)
    done = [t for t in tasks if t not in failures]
    labels = {"alertas_sla": lambda r: f"{r['new_alerts']} alertas SLA nuevas",
              "seguimiento_atrasados": lambda r: f"{r['reminders']} recordatorios por atraso",
              "seguimiento_inactivos": lambda r: f"{r['reminders']} recordatorios por inactividad",
              "resumen_operativo": lambda r: f"resumen operativo ({r['open']} abiertos, {r['overdue']} vencidos)"
                                             + ("" if r["notified"] else ", ya enviado hoy")}
    summary = "; ".join("alertas SLA: modelo no entrenado" if "error" in report[t] else labels[t](report[t]) for t in tasks)
    if not done:
        raise ml.ModelNotTrained(report[failures[0]]["error"])
    return Output(summary, {"tasks": report, "failed": failures}, status=PARTIAL if failures else OK)


register(Spec("triage", triage, exclusive=True, lock_minutes=10))
register(Spec("sla_risk", sla_risk, exclusive=True, lock_minutes=15))
register(Spec("assignment", assignment, exclusive=True, lock_minutes=10))
register(Spec("diagnosis", diagnosis, exclusive=False, lock_minutes=3))
register(Spec("automation", automation, exclusive=True, lock_minutes=20, schedulable=True))
