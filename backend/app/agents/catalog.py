"""Descriptions (academic justification) and live evaluation figures of the agents. Evaluation numbers
come only from stored model metadata and the agents' own execution records; nothing is estimated here."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.ml import store
from app.models import AgentAlert, AgentRun

CATALOG = {
    "triage": {
        "title": "Triage",
        "why": "La clasificación manual al registrar un ticket es la primera fuente de demoras y de prioridades mal asignadas.",
        "problem": "Tickets con prioridad o categoría incorrectas reciben un SLA y un técnico que no corresponden.",
        "technology": "Regresión logística sobre TF-IDF del texto (prioridad) y k vecinos más cercanos por similitud TF-IDF sobre el historial (categoría); regresión de horas de resolución.",
        "automates": "Clasifica los tickets nuevos o reabiertos y sugiere prioridad y categoría al usuario mientras redacta. Solo recomienda: no cambia el ticket.",
        "evaluation": "F1 macro del modelo de prioridad en evaluación temporal y porcentaje de coincidencia con la prioridad y categoría registradas.",
        "roles": "Ejecución por lotes: ADMIN y JEFE_TI. Sugerencia al crear un ticket: cualquier usuario autenticado.",
    },
    "sla_risk": {
        "title": "Riesgo SLA",
        "why": "Los incumplimientos de SLA se detectan tarde, cuando el plazo ya venció.",
        "problem": "Falta de aviso anticipado sobre tickets abiertos que probablemente se resolverán fuera de plazo.",
        "technology": "Clasificador HistGradientBoosting (probabilidad de incumplimiento) y regresor de horas de resolución entrenados con el historial.",
        "automates": "Evalúa todos los tickets abiertos y emite alertas únicas (clave de deduplicación) al técnico y a los jefes.",
        "evaluation": "Precisión, exhaustividad, F1 y AUC del clasificador en el periodo de evaluación; alertas emitidas y duplicados evitados por ejecución.",
        "roles": "ADMIN y JEFE_TI.",
    },
    "assignment": {
        "title": "Asignación",
        "why": "La asignación depende de la disponibilidad percibida y no del riesgo ni de la carga real.",
        "problem": "Tickets sin técnico o asignados a técnicos sin la especialidad o sobrecargados.",
        "technology": "Ranking con los modelos de tiempo y riesgo por candidato, filtro de especialidad y capacidad; reglas deterministas de FixIT como respaldo.",
        "automates": "Recomienda técnico para los tickets sin asignar y, si se ordena, asigna usando la regla de negocio existente con auditoría.",
        "evaluation": "Backtest del recomendador (coincidencia top-1/top-3 y tiempos/incumplimiento cuando se siguió la recomendación) y asignaciones realizadas.",
        "roles": "ADMIN y JEFE_TI.",
    },
    "diagnosis": {
        "title": "Diagnóstico",
        "why": "Muchos incidentes repiten problemas ya resueltos cuya solución está en el historial.",
        "problem": "El técnico invierte tiempo en investigar desde cero.",
        "technology": "Recuperación de casos similares por TF-IDF (solo tickets que el usuario puede ver) y generación con el LLM configurado (Gemini con reintentos y modelo alternativo).",
        "automates": "Propone causas probables, verificaciones y soluciones citando casos similares resueltos.",
        "evaluation": "Ejecuciones con respuesta del LLM, casos similares recuperados por consulta, errores y latencia del LLM.",
        "roles": "ADMIN, JEFE_TI y el técnico asignado al ticket.",
    },
    "automation": {
        "title": "Automatización",
        "why": "El seguimiento de atrasos y los reportes diarios se hacen a mano y se omiten.",
        "problem": "Tickets vencidos o sin actividad sin recordatorio, y ausencia de un resumen operativo periódico.",
        "technology": "Tareas programadas con bloqueo entre procesos; reutiliza el agente de riesgo SLA y consultas sobre la base de tickets.",
        "automates": "Alertas SLA, recordatorios diarios de tickets atrasados o inactivos y resumen operativo diario para los jefes. Solo tareas autorizadas y sin modificar tickets.",
        "evaluation": "Tasa de ejecuciones correctas, recordatorios enviados y duplicados evitados.",
        "roles": "ADMIN y JEFE_TI (configuran la programación).",
    },
}


def _runs(db: Session, agent: str, since: datetime) -> dict:
    rows = db.execute(select(AgentRun.status, func.count(), func.avg(AgentRun.duration_ms)).where(
        AgentRun.agent == agent, AgentRun.started_at >= since).group_by(AgentRun.status)).all()
    total = sum(r[1] for r in rows)
    ok = sum(r[1] for r in rows if r[0] in {"OK", "PARCIAL"})
    return {"runs_30d": total, "success_rate_30d": round(ok / total, 3) if total else None,
            "errors_30d": sum(r[1] for r in rows if r[0] == "ERROR")}


def _last_result(db: Session, agent: str) -> dict:
    run = db.scalar(select(AgentRun).where(AgentRun.agent == agent, AgentRun.status.in_(["OK", "PARCIAL"]), AgentRun.ticket_id.is_(None))
                    .order_by(AgentRun.started_at.desc()).limit(1))
    return (run.result or {}) if run else {}


def evaluation(db: Session, agent: str) -> dict:
    since = datetime.now(timezone.utc) - timedelta(days=30)
    models = (store.load_metadata() or {}).get("models", {})
    metric = lambda model, key: (models.get(model, {}).get("metrics") or {}).get(key)
    out = _runs(db, agent, since)
    if agent == "triage":
        last = _last_result(db, agent)
        out.update(priority_macro_f1=metric("priority", "macro_f1"), priority_agreement=last.get("priority_agreement"),
                   category_agreement=last.get("category_agreement"))
    elif agent == "sla_risk":
        out.update({k: metric("sla_risk", k) for k in ("precision", "recall", "f1", "roc_auc")})
        out["alerts_30d"] = db.scalar(select(func.count()).select_from(AgentAlert).where(
            AgentAlert.agent == "sla_risk", AgentAlert.created_at >= since)) or 0
    elif agent == "assignment":
        out.update(top1_match_rate=metric("recommendation", "top1_match_rate"), top3_match_rate=metric("recommendation", "top3_match_rate"))
        out["assigned_30d"] = sum((r.result or {}).get("assigned", 0) for r in db.scalars(
            select(AgentRun).where(AgentRun.agent == agent, AgentRun.started_at >= since)))
    elif agent == "diagnosis":
        runs = db.scalars(select(AgentRun).where(AgentRun.agent == agent, AgentRun.started_at >= since)).all()
        results = [r.result for r in runs if r.result]
        out["llm_answer_rate"] = round(sum(bool(r.get("llm_used")) for r in results) / len(results), 3) if results else None
        out["avg_similar_cases"] = round(sum(r.get("similar_cases", 0) for r in results) / len(results), 2) if results else None
    elif agent == "automation":
        out["reminders_30d"] = db.scalar(select(func.count()).select_from(AgentAlert).where(
            AgentAlert.agent == "automation", AgentAlert.kind.like("SEGUIMIENTO%"), AgentAlert.created_at >= since)) or 0
    return out
