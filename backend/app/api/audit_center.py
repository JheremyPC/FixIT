"""Centro Integral de Auditoría: API (prefix /api/audit-center).

Permissions are enforced here, never only in the web client:
* ADMIN: everything, including enabling/disabling controls and unredacted evidence packages.
* JEFE_TI: run audits with the enabled controls, read results, manage findings, action plans, evidence and reports.
* TECNICO: only the findings and action items assigned to them: read, update their status within the allowed transitions
  and attach correction evidence.
* USUARIO: no access. Every denied attempt is recorded in audit_logs with outcome DENEGADO.
Relevant actions (runs, status changes, assignments, evidence, imports, report downloads) are recorded in audit_logs
(module CENTRO_AUDITORIA). No endpoint executes SQL or system commands supplied by the client.
"""
from __future__ import annotations

import hashlib
from datetime import date, datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import FileResponse
from pydantic import ConfigDict, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, joinedload

from app.auditing import catalog, engine, evidence as ev, findings as fnd, importers, reports
from app.auditing.redaction import mask_email, secret_free
from app.core.config import settings
from app.core.database import get_db
from app.core.errors import forbidden, not_found
from app.models import (ACTION_STATUSES, FINDING_STATUSES, AuditActionItem, AuditControl, AuditEvidence, AuditExternalLog, AuditFinding,
                        AuditFindingEvent, AuditImport, AuditReport, AuditResult, AuditRun, Role, User, uid)
from app.schemas.schemas import Input
from app.security.auth import current_user
from app.services.audit import audit, iso, notify

audit_center_api = APIRouter(prefix="/api/audit-center", tags=["centro-auditoria"])
MODULE = "CENTRO_AUDITORIA"
UTC = timezone.utc
CODE = r"^[A-Z]{2,4}-[A-Z0-9]{2,5}(-[0-9]{2})?$"


def _guard(*roles: str):
    def dependency(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)) -> User:
        if user.role.code not in roles:
            audit(db, user.id, "ACCESO_DENEGADO", MODULE, "AUDIT_CENTER", None, new={"method": request.method, "path": request.url.path},
                  request=request, outcome="DENEGADO")
            db.commit()
            forbidden("Rol sin autorización")
        return user
    dependency.roles = roles  # read by the route inventory of SEG-AUT-02
    return dependency


managers = _guard("ADMIN", "JEFE_TI")
admin_only = _guard("ADMIN")
members = _guard("ADMIN", "JEFE_TI", "TECNICO")


def is_manager(user: User) -> bool:
    return user.role.code in ("ADMIN", "JEFE_TI")


# --- Schemas ------------------------------------------------------------------------------------------------------------
class RunOptions(Input):
    model_config = ConfigDict(extra="forbid")
    origen: Literal["todos", "reales", "sinteticos"] = "todos"
    sla_objetivo: float = Field(default=85, ge=50, le=100)
    dias_inactividad: int = Field(default=90, ge=7, le=730)
    max_admins: int = Field(default=3, ge=1, le=50)
    umbral_fallos: int = Field(default=5, ge=1, le=100)
    filas_minimas_indice: int = Field(default=1000, ge=0, le=10_000_000)
    segundos_max_hmac: int = Field(default=300, ge=10, le=600)


class RunIn(Input):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=3, max_length=150)
    categories: list[Literal[tuple(catalog.CATEGORIES)]] = Field(default_factory=list, max_length=8)  # type: ignore[valid-type]
    control_codes: list[str] | None = Field(default=None, max_length=200)
    period_from: datetime | None = None
    period_to: datetime | None = None
    description: str | None = Field(default=None, max_length=2000)
    options: RunOptions = Field(default_factory=RunOptions)


class ControlConfigIn(Input):
    model_config = ConfigDict(extra="forbid")
    enabled: bool


class FindingUpdateIn(Input):
    model_config = ConfigDict(extra="forbid")
    owner_id: str | None = Field(default=None, max_length=36)
    due_date: date | None = None
    clear_owner: bool = False
    clear_due_date: bool = False
    note: str | None = Field(default=None, max_length=2000)


class FindingStatusIn(Input):
    model_config = ConfigDict(extra="forbid")
    status: Literal[FINDING_STATUSES]  # type: ignore[valid-type]
    note: str = Field(min_length=5, max_length=2000)
    justification: str | None = Field(default=None, max_length=4000)
    review_date: date | None = None


class ActionIn(Input):
    model_config = ConfigDict(extra="forbid")
    description: str = Field(min_length=5, max_length=2000)
    owner_id: str | None = Field(default=None, max_length=36)
    due_date: date | None = None


class ActionUpdateIn(Input):
    model_config = ConfigDict(extra="forbid")
    status: Literal[ACTION_STATUSES] | None = None  # type: ignore[valid-type]
    note: str | None = Field(default=None, max_length=2000)
    owner_id: str | None = Field(default=None, max_length=36)
    due_date: date | None = None


# --- Serialization ------------------------------------------------------------------------------------------------------
def user_brief(user: User | None) -> dict | None:
    if user is None: return None
    return {"id": user.id, "name": user.full_name, "email": mask_email(user.email), "role": user.role.code}


def run_brief(run: AuditRun) -> dict:
    return {"id": run.id, "code": run.code, "name": run.name, "type": run.audit_type, "categories": run.categories, "status": run.status,
            "result": run.overall_result, "created_at": iso(run.created_at), "started_at": iso(run.started_at), "finished_at": iso(run.finished_at),
            "period_from": iso(run.period_from), "period_to": iso(run.period_to), "progress": {"done": run.progress_done, "total": run.progress_total,
            "current": run.current_control}, "summary": run.summary, "requested_by": user_brief(run.requested_by), "parent_run_id": run.parent_run_id,
            "cancel_requested": run.cancel_requested}


def result_data(r: AuditResult, titles: dict) -> dict:
    return {"control": r.control_code, "title": titles.get(r.control_code, r.control_code), "category": r.category, "status": r.status, "method": r.method,
            "severity": r.severity, "summary": r.summary, "details": r.details, "privileges": r.privileges, "started_at": iso(r.started_at),
            "duration_ms": r.duration_ms, "error": r.error, "run_id": r.run_id}


def finding_brief(f: AuditFinding) -> dict:
    return {"id": f.id, "code": f.code, "title": f.title, "category": f.category, "control": f.control_code, "resource": f.resource, "severity": f.severity,
            "status": f.status, "owner": user_brief(f.owner), "due_date": f.due_date.isoformat() if f.due_date else None, "detected_at": iso(f.detected_at),
            "last_seen_at": iso(f.last_seen_at), "occurrences": f.occurrences, "last_verification": f.last_verification,
            "last_verification_at": iso(f.last_verification_at)}


def evidence_data(e: AuditEvidence) -> dict:
    return {"id": e.id, "kind": e.kind, "title": e.title, "description": e.description, "control": e.control_code, "finding_id": e.finding_id,
            "run_id": e.run_id, "declared_result": e.declared_result, "evidence_date": e.evidence_date.isoformat() if e.evidence_date else None,
            "file": e.original_name, "content_type": e.content_type, "size": e.size, "sha256": e.sha256, "has_file": bool(e.stored_name),
            "created_at": iso(e.created_at), "uploaded_by": user_brief(e.uploaded_by)}


def action_data(a: AuditActionItem) -> dict:
    return {"id": a.id, "finding_id": a.finding_id, "description": a.description, "owner": user_brief(a.owner), "status": a.status, "note": a.note,
            "due_date": a.due_date.isoformat() if a.due_date else None, "created_at": iso(a.created_at), "updated_at": iso(a.updated_at),
            "completed_at": iso(a.completed_at)}


def import_data(i: AuditImport, detail: bool = False) -> dict:
    out = {"id": i.id, "kind": i.kind, "kind_label": importers.KINDS.get(i.kind, i.kind), "file": i.source_name, "sha256": i.sha256, "size": i.size,
           "status": i.status, "rows": {"total": i.rows_total, "imported": i.rows_imported, "duplicated": i.rows_duplicated, "rejected": i.rows_rejected},
           "tool": i.tool, "imported_at": iso(i.imported_at), "imported_by": user_brief(i.imported_by), "notes": i.notes}
    summary = i.summary or {}
    out["summary"] = summary if detail else {k: v for k, v in summary.items() if k != "items"}
    if detail: out["errors"] = i.errors
    return out


def _titles(db: Session) -> dict:
    return {c: t for c, t in db.execute(select(AuditControl.code, AuditControl.title))}


def _assignable(db: Session, user_id: str | None) -> User | None:
    if not user_id: return None
    user = db.get(User, user_id)
    if not user or not user.active or user.role.code not in ("ADMIN", "JEFE_TI", "TECNICO"):
        raise HTTPException(422, "El responsable debe ser una cuenta activa ADMIN, JEFE_TI o TECNICO")
    return user


def _finding_visible(db: Session, finding: AuditFinding, user: User) -> bool:
    if is_manager(user): return True
    return finding.owner_id == user.id or bool(db.scalar(select(func.count(AuditActionItem.id)).where(
        AuditActionItem.finding_id == finding.id, AuditActionItem.owner_id == user.id)))


def _get_finding(db: Session, finding_id: str, user: User) -> AuditFinding:
    finding = db.get(AuditFinding, finding_id)
    if not finding or not _finding_visible(db, finding, user): not_found("Hallazgo")
    return finding


def _get_run(db: Session, run_id: str) -> AuditRun:
    run = db.scalars(select(AuditRun).options(joinedload(AuditRun.requested_by).joinedload(User.role)).where(AuditRun.id == run_id)).first()
    if not run: not_found("Auditoría")
    return run


# --- Catalog and dashboard ----------------------------------------------------------------------------------------------
@audit_center_api.get("/meta")
def meta(user: User = Depends(members), db: Session = Depends(get_db)):
    rows = db.scalars(select(AuditControl).order_by(AuditControl.code)).all()
    registry = engine.controls()
    counts = {c: sum(1 for r in rows if r.category == c and r.enabled) for c in catalog.CATEGORIES}
    return {"categories": [{"code": c, **v, "controls": counts[c]} for c, v in catalog.CATEGORIES.items()],
            "statuses": catalog.STATUS_LABELS, "status_meaning": catalog.STATUS_MEANING, "severities": catalog.SEVERITY_LABELS,
            "finding_statuses": catalog.FINDING_LABELS, "transitions": {k: sorted(v) for k, v in catalog.TRANSITIONS.items()},
            "technician_transitions": sorted(f"{a}>{b}" for a, b in catalog.TECHNICIAN_TRANSITIONS), "run_statuses": catalog.RUN_LABELS,
            "results": catalog.RESULT_LABELS, "result_meaning": catalog.RESULT_MEANING, "methods": catalog.METHODS, "references": catalog.REFERENCES,
            "methodology": catalog.METHODOLOGY, "limitations": catalog.LIMITATIONS, "import_kinds": importers.KINDS,
            "evidence_types": sorted(ev.ALLOWED), "limits": {"evidence_bytes": settings.audit_evidence_max_bytes, "import_bytes": settings.audit_import_max_bytes,
            "import_rows": settings.audit_import_max_rows, "run_seconds": settings.audit_run_max_seconds},
            "options": RunOptions().model_dump(), "role": user.role.code, "can_manage": is_manager(user), "is_admin": user.role.code == "ADMIN",
            "controls": [{"code": r.code, "category": r.category, "title": r.title, "objective": r.objective, "method": r.method,
                          "severity": r.default_severity, "criteria": r.criteria or [], "enabled": r.enabled,
                          "guidance": registry[r.code].guidance if r.code in registry else None,
                          "evidence_days": registry[r.code].evidence_days if r.code in registry else None,
                          "requires": list(registry[r.code].requires) if r.code in registry else []} for r in rows] if is_manager(user) else []}


def latest_results(db: Session, codes: list[str] | None = None) -> dict[str, AuditResult]:
    query = (select(AuditResult).join(AuditRun, AuditRun.id == AuditResult.run_id).where(AuditRun.status.in_(engine.FINAL))
             .order_by(AuditResult.finished_at.desc()))
    if codes: query = query.where(AuditResult.control_code.in_(codes))
    out: dict[str, AuditResult] = {}
    for row in db.scalars(query.limit(5000)):
        out.setdefault(row.control_code, row)
    return out


@audit_center_api.get("/overview")
def overview(_: User = Depends(managers), db: Session = Depends(get_db)):
    engine.recover_stale(db)
    runs_by = dict(db.execute(select(AuditRun.status, func.count()).group_by(AuditRun.status)).all())
    open_q = AuditFinding.status.in_(catalog.OPEN_FINDING_STATUSES)
    by_severity = dict(db.execute(select(AuditFinding.severity, func.count()).where(open_q).group_by(AuditFinding.severity)).all())
    by_category = dict(db.execute(select(AuditFinding.category, func.count()).where(open_q).group_by(AuditFinding.category)).all())
    findings_by_status = dict(db.execute(select(AuditFinding.status, func.count()).group_by(AuditFinding.status)).all())
    enabled = {c.code: c for c in db.scalars(select(AuditControl).where(AuditControl.enabled.is_(True)))}
    latest = latest_results(db, list(enabled))
    status_counts = {s: 0 for s in catalog.STATUS_LABELS}
    per_category = {c: {"statuses": {s: 0 for s in catalog.STATUS_LABELS}, "never": 0, "last_run": None, "controls": 0} for c in catalog.CATEGORIES}
    for code, ctrl in enabled.items():
        bucket = per_category[ctrl.category]
        bucket["controls"] += 1
        res = latest.get(code)
        if res is None:
            bucket["never"] += 1
            continue
        status_counts[res.status] += 1
        bucket["statuses"][res.status] += 1
        moment = iso(res.finished_at)
        if not bucket["last_run"] or moment > bucket["last_run"]: bucket["last_run"] = moment
    recent = db.scalars(select(AuditRun).options(joinedload(AuditRun.requested_by).joinedload(User.role)).order_by(AuditRun.created_at.desc()).limit(8)).all()
    return {"kpis": {"runs_executed": runs_by.get("COMPLETADA", 0) + runs_by.get("COMPLETADA_CON_ERRORES", 0),
                     "runs_pending": runs_by.get("PENDIENTE", 0) + runs_by.get("EN_CURSO", 0),
                     "runs_interrupted": runs_by.get("INTERRUMPIDA", 0) + runs_by.get("CANCELADA", 0),
                     "findings_open": sum(by_severity.values()), "findings_critical_high": by_severity.get("CRITICO", 0) + by_severity.get("ALTO", 0),
                     "findings_closed": findings_by_status.get("CERRADO", 0), "findings_pending_verification": findings_by_status.get("CORREGIDO_PENDIENTE_VERIFICACION", 0),
                     "controls_approved": status_counts["APROBADO"], "controls_failed": status_counts["FALLIDO"], "controls_warning": status_counts["ADVERTENCIA"],
                     "controls_unverified": status_counts["NO_VERIFICADO"] + status_counts["ERROR_EJECUCION"],
                     "controls_never_run": sum(b["never"] for b in per_category.values()), "controls_enabled": len(enabled),
                     "reports_generated": db.scalar(select(func.count(AuditReport.id))) or 0},
            "controls_by_status": status_counts, "findings_by_severity": by_severity, "findings_by_category": by_category,
            "findings_by_status": findings_by_status, "categories": per_category, "recent_runs": [run_brief(r) for r in recent],
            "basis": "Estado de cada control según su última ejecución finalizada; los controles nunca ejecutados no cuentan como aprobados."}


@audit_center_api.get("/categories/{code}")
def category(code: str, _: User = Depends(managers), db: Session = Depends(get_db)):
    if code not in catalog.CATEGORIES: not_found("Categoría")
    registry = engine.controls()
    order = {c: i for i, c in enumerate(registry)}
    rows = sorted(db.scalars(select(AuditControl).where(AuditControl.category == code)).all(), key=lambda r: (order.get(r.code, 9999), r.code))
    latest = latest_results(db, [r.code for r in rows])
    run_codes = {r.id: r.code for r in db.scalars(select(AuditRun).where(AuditRun.id.in_({x.run_id for x in latest.values()} or {""})))}
    manual = {r.code for r in rows if r.method == "MANUAL"}
    last_evidence = {}
    for e in db.scalars(select(AuditEvidence).options(joinedload(AuditEvidence.uploaded_by).joinedload(User.role)).where(
            AuditEvidence.control_code.in_(manual or {""}), AuditEvidence.kind == "MANUAL").order_by(AuditEvidence.created_at.desc())):
        last_evidence.setdefault(e.control_code, evidence_data(e))
    findings = db.scalars(select(AuditFinding).options(joinedload(AuditFinding.owner).joinedload(User.role)).where(
        AuditFinding.category == code, AuditFinding.status.in_(catalog.OPEN_FINDING_STATUSES)).order_by(AuditFinding.detected_at.desc()).limit(100)).all()
    findings = sorted(findings, key=lambda f: (catalog.SEVERITY_ORDER.get(f.severity, 9), f.code))
    runs = db.scalars(select(AuditRun).options(joinedload(AuditRun.requested_by).joinedload(User.role)).order_by(AuditRun.created_at.desc()).limit(60)).all()
    out = {"category": {"code": code, **catalog.CATEGORIES[code]},
           "controls": [{"code": r.code, "title": r.title, "objective": r.objective, "method": r.method, "severity": r.default_severity, "criteria": r.criteria or [],
                         "enabled": r.enabled, "guidance": registry[r.code].guidance if r.code in registry else None,
                         "evidence_days": registry[r.code].evidence_days if r.code in registry else None,
                         "requires": list(registry[r.code].requires) if r.code in registry else [],
                         "latest": {**result_data(latest[r.code], {}), "run_code": run_codes.get(latest[r.code].run_id)} if r.code in latest else None,
                         "last_evidence": last_evidence.get(r.code)} for r in rows],
           "findings": [finding_brief(f) for f in findings], "runs": [run_brief(r) for r in runs if code in (r.categories or [])][:10]}
    if code == "BASE_DATOS":
        out["imports"] = [import_data(i) for i in db.scalars(select(AuditImport).options(joinedload(AuditImport.imported_by).joinedload(User.role))
                                                             .where(AuditImport.kind == "LOGS_BD").order_by(AuditImport.imported_at.desc()).limit(20))]
        out["external_logs"] = {"total": db.scalar(select(func.count(AuditExternalLog.id))) or 0,
                                "by_class": dict(db.execute(select(AuditExternalLog.statement_class, func.count()).group_by(AuditExternalLog.statement_class)).all()),
                                "first": iso(db.scalar(select(func.min(AuditExternalLog.log_time)))), "last": iso(db.scalar(select(func.max(AuditExternalLog.log_time))))}
    if code == "SEGURIDAD":
        out["imports"] = [import_data(i) for i in db.scalars(select(AuditImport).options(joinedload(AuditImport.imported_by).joinedload(User.role))
                                                             .where(AuditImport.kind != "LOGS_BD").order_by(AuditImport.imported_at.desc()).limit(20))]
    return out


@audit_center_api.patch("/controls/{code}")
def configure_control(code: str, payload: ControlConfigIn, request: Request, actor: User = Depends(admin_only), db: Session = Depends(get_db)):
    row = db.get(AuditControl, code)
    if not row: not_found("Control")
    old = {"enabled": row.enabled}
    row.enabled = payload.enabled
    audit(db, actor.id, "CONFIGURAR_CONTROL", MODULE, "AUDIT_CONTROL", None, old=old, new={"control": code, "enabled": payload.enabled}, request=request)
    db.commit()
    return {"code": code, "enabled": row.enabled}


@audit_center_api.get("/assignees")
def assignees(_: User = Depends(managers), db: Session = Depends(get_db)):
    rows = db.scalars(select(User).options(joinedload(User.role)).join(Role, Role.id == User.role_id)
                      .where(User.active.is_(True), Role.code.in_(("ADMIN", "JEFE_TI", "TECNICO"))).order_by(User.full_name)).all()
    return [user_brief(u) for u in rows]


# --- Runs ------------------------------------------------------------------------------------------------------------------
@audit_center_api.post("/runs", status_code=202)
def create_run(payload: RunIn, request: Request, actor: User = Depends(managers), db: Session = Depends(get_db)):
    try:
        run = engine.create_run(db, actor, payload.name, list(payload.categories), payload.control_codes, payload.period_from, payload.period_to,
                                {"descripcion": secret_free(payload.description) if payload.description else None, "options": payload.options.model_dump()})
    except engine.RunConflict as exc:
        raise HTTPException(409, str(exc)) from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    audit(db, actor.id, "CREAR_AUDITORIA", MODULE, "AUDIT_RUN", run.id, new={"codigo": run.code, "categorias": run.categories, "controles": len(run.control_codes)},
          request=request)
    db.commit()
    engine.submit(run.id)
    return run_brief(_get_run(db, run.id))


@audit_center_api.get("/runs")
def list_runs(response: Response, status: str | None = Query(None, pattern="^[A-Z_]{3,30}$"), category: str | None = Query(None, pattern="^[A-Z_]{3,30}$"),
              requested_by: str | None = Query(None, max_length=36), date_from: datetime | None = None, date_to: datetime | None = None,
              result: str | None = Query(None, pattern="^[A-Z_]{3,30}$"), q: str | None = Query(None, max_length=100),
              limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0), _: User = Depends(managers), db: Session = Depends(get_db)):
    query = select(AuditRun)
    if status: query = query.where(AuditRun.status == status)
    if result: query = query.where(AuditRun.overall_result == result)
    if requested_by: query = query.where(AuditRun.requested_by_id == requested_by)
    if date_from: query = query.where(AuditRun.created_at >= engine.aware(date_from))
    if date_to: query = query.where(AuditRun.created_at < engine.aware(date_to))
    if q:
        term = "%" + q.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        query = query.where(or_(func.lower(AuditRun.code).like(term, escape="\\"), func.lower(AuditRun.name).like(term, escape="\\")))
    rows = db.scalars(query.options(joinedload(AuditRun.requested_by).joinedload(User.role)).order_by(AuditRun.created_at.desc())).all()
    if category: rows = [r for r in rows if category in (r.categories or [])]
    response.headers["X-Total-Count"] = str(len(rows))
    return [run_brief(r) for r in rows[offset:offset + limit]]


@audit_center_api.get("/runs/{run_id}")
def read_run(run_id: str, _: User = Depends(managers), db: Session = Depends(get_db)):
    run = _get_run(db, run_id)
    titles = _titles(db)
    results = db.scalars(select(AuditResult).where(AuditResult.run_id == run.id)).all()
    order = {c: i for i, c in enumerate(run.control_codes)}
    related = db.scalars(select(AuditFinding).options(joinedload(AuditFinding.owner).joinedload(User.role)).where(
        or_(AuditFinding.first_run_id == run.id, AuditFinding.last_run_id == run.id, AuditFinding.last_verification_run_id == run.id))).all()
    generated = db.scalars(select(AuditReport).options(joinedload(AuditReport.generated_by).joinedload(User.role)).where(AuditReport.run_id == run.id)
                           .order_by(AuditReport.created_at.desc())).all()
    return {**run_brief(run), "control_codes": run.control_codes, "scope": run.scope, "app_version": run.app_version, "build": run.build,
            "tools": run.tools, "connection": run.connection_info, "observations": run.observations, "limitations": run.limitations, "error": run.error,
            "seal": run.results_seal, "seal_status": engine.verify_seal(run, results) if run.results_seal else None, "heartbeat_at": iso(run.heartbeat_at),
            "results": [result_data(r, titles) for r in sorted(results, key=lambda r: order.get(r.control_code, 9999))],
            "findings": [finding_brief(f) for f in sorted(related, key=lambda f: (catalog.SEVERITY_ORDER.get(f.severity, 9), f.code))],
            "reports": [{"id": r.id, "kind": r.kind, "filename": r.filename, "sha256": r.sha256, "size": r.size, "redacted": r.redacted,
                         "created_at": iso(r.created_at), "generated_by": user_brief(r.generated_by)} for r in generated]}


@audit_center_api.post("/runs/{run_id}/repeat", status_code=202)
def repeat_run(run_id: str, request: Request, actor: User = Depends(managers), db: Session = Depends(get_db)):
    previous = _get_run(db, run_id)
    try:
        run = engine.create_run(db, actor, f"{previous.name} (repetición)"[:150], previous.categories, previous.control_codes, previous.period_from,
                                previous.period_to, previous.scope, previous.audit_type, previous.id)
    except engine.RunConflict as exc:
        raise HTTPException(409, str(exc)) from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    audit(db, actor.id, "REPETIR_AUDITORIA", MODULE, "AUDIT_RUN", run.id, new={"codigo": run.code, "origen": previous.code}, request=request)
    db.commit()
    engine.submit(run.id)
    return run_brief(_get_run(db, run.id))


@audit_center_api.post("/runs/{run_id}/cancel")
def cancel_run(run_id: str, request: Request, actor: User = Depends(managers), db: Session = Depends(get_db)):
    run = _get_run(db, run_id)
    if run.status not in engine.ACTIVE: raise HTTPException(409, "La auditoría ya terminó")
    outcome = engine.request_cancel(db, run)
    audit(db, actor.id, "CANCELAR_AUDITORIA", MODULE, "AUDIT_RUN", run.id, new={"codigo": run.code, "resultado": outcome}, request=request)
    db.commit()
    return {"status": outcome}


@audit_center_api.get("/runs/{run_id}/compare")
def compare(run_id: str, other: str | None = Query(None, max_length=36), _: User = Depends(managers), db: Session = Depends(get_db)):
    run = _get_run(db, run_id)
    if other:
        base = _get_run(db, other)
    else:
        candidates = db.scalars(select(AuditRun).where(AuditRun.id != run.id, AuditRun.status.in_(engine.FINAL), AuditRun.created_at < run.created_at)
                                .order_by(AuditRun.created_at.desc()).limit(50)).all()
        base = next((r for r in candidates if set(r.control_codes) & set(run.control_codes)), None)
        if base is None: raise HTTPException(404, "No hay una ejecución anterior comparable (con controles en común)")
    rank = {"APROBADO": 0, "NO_APLICABLE": 0, "ADVERTENCIA": 1, "NO_VERIFICADO": 2, "ERROR_EJECUCION": 2, "FALLIDO": 3}
    titles = _titles(db)
    current = {r.control_code: r for r in db.scalars(select(AuditResult).where(AuditResult.run_id == run.id))}
    previous = {r.control_code: r for r in db.scalars(select(AuditResult).where(AuditResult.run_id == base.id))}
    rows = []
    for code in sorted(set(current) | set(previous)):
        a, b = previous.get(code), current.get(code)
        change = "NUEVO" if a is None else "AUSENTE" if b is None else "IGUAL" if a.status == b.status else (
            "MEJORA" if rank[b.status] < rank[a.status] else "EMPEORA" if rank[b.status] > rank[a.status] else "CAMBIO")
        rows.append({"control": code, "title": titles.get(code, code), "before": a.status if a else None, "after": b.status if b else None, "change": change})
    totals = {k: sum(1 for r in rows if r["change"] == k) for k in ("MEJORA", "EMPEORA", "IGUAL", "CAMBIO", "NUEVO", "AUSENTE")}
    return {"run": run_brief(run), "base": run_brief(base), "controls": rows, "totals": totals}


REPORT_KINDS = {"executive": ("EJECUTIVO", "informe-ejecutivo", "pdf", "application/pdf"), "technical": ("TECNICO", "informe-tecnico", "pdf", "application/pdf"),
                "package": ("PAQUETE", "paquete-evidencias", "zip", "application/zip")}


@audit_center_api.get("/runs/{run_id}/report/{kind}")
def download_report(run_id: str, kind: Literal["executive", "technical", "package"], request: Request, redact: bool = True,
                    actor: User = Depends(managers), db: Session = Depends(get_db)):
    run = _get_run(db, run_id)
    if run.status not in engine.FINAL: raise HTTPException(409, "La auditoría aún no terminó")
    if not redact and actor.role.code != "ADMIN": raise HTTPException(403, "Solo un administrador puede generar informes sin enmascarar")
    label, stem, ext, media = REPORT_KINDS[kind]
    data = reports.report_data(db, run, redacted=redact)
    body = reports.executive_pdf(data) if kind == "executive" else reports.technical_pdf(data) if kind == "technical" else reports.package(db, run, data, redact)
    digest = hashlib.sha256(body).hexdigest()
    filename = f"fixit-{stem}_{run.code}{'' if redact else '_sin-enmascarar'}.{ext}"
    event = audit(db, actor.id, "EXPORTAR_INFORME", MODULE, "AUDIT_RUN", run.id,
                  new={"tipo": label, "codigo": run.code, "sha256": digest, "bytes": len(body), "redactado": redact}, request=request)
    db.flush()
    db.add(AuditReport(run_id=run.id, kind=label, filename=filename, sha256=digest, size=len(body), redacted=redact, generated_by_id=actor.id,
                       audit_log_id=event.id, created_at=datetime.now(UTC)))
    db.commit()
    return Response(body, media_type=media, headers={"Content-Disposition": f'attachment; filename="{filename}"', "X-Content-SHA256": digest})


@audit_center_api.get("/reports")
def list_reports(response: Response, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0), _: User = Depends(managers),
                 db: Session = Depends(get_db)):
    total = db.scalar(select(func.count(AuditReport.id))) or 0
    rows = db.scalars(select(AuditReport).options(joinedload(AuditReport.generated_by).joinedload(User.role)).order_by(AuditReport.created_at.desc())
                      .offset(offset).limit(limit)).all()
    codes = {r.id: r.code for r in db.scalars(select(AuditRun).where(AuditRun.id.in_({x.run_id for x in rows} or {""})))}
    response.headers["X-Total-Count"] = str(total)
    return [{"id": r.id, "run_id": r.run_id, "run_code": codes.get(r.run_id), "kind": r.kind, "filename": r.filename, "sha256": r.sha256, "size": r.size,
             "redacted": r.redacted, "created_at": iso(r.created_at), "generated_by": user_brief(r.generated_by)} for r in rows]


# --- Findings ----------------------------------------------------------------------------------------------------------
@audit_center_api.get("/findings")
def list_findings(response: Response, category: str | None = Query(None, pattern="^[A-Z_]{3,30}$"), severity: str | None = Query(None, pattern="^[A-Z]{4,12}$"),
                  status: str | None = Query(None, pattern="^[A-Z_]{4,40}$"), owner: str | None = Query(None, max_length=36),
                  control: str | None = Query(None, pattern=CODE), q: str | None = Query(None, max_length=100), open_only: bool = False,
                  date_from: datetime | None = None, date_to: datetime | None = None, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
                  user: User = Depends(members), db: Session = Depends(get_db)):
    query = select(AuditFinding)
    if not is_manager(user):
        query = query.where(or_(AuditFinding.owner_id == user.id, AuditFinding.id.in_(select(AuditActionItem.finding_id).where(AuditActionItem.owner_id == user.id))))
    if category: query = query.where(AuditFinding.category == category)
    if severity: query = query.where(AuditFinding.severity == severity)
    if status: query = query.where(AuditFinding.status == status)
    if open_only: query = query.where(AuditFinding.status.in_(catalog.OPEN_FINDING_STATUSES))
    if control: query = query.where(AuditFinding.control_code == control)
    if owner == "none": query = query.where(AuditFinding.owner_id.is_(None))
    elif owner == "me": query = query.where(AuditFinding.owner_id == user.id)
    elif owner: query = query.where(AuditFinding.owner_id == owner)
    if date_from: query = query.where(AuditFinding.detected_at >= engine.aware(date_from))
    if date_to: query = query.where(AuditFinding.detected_at < engine.aware(date_to))
    if q:
        term = "%" + q.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        query = query.where(or_(*[func.lower(c).like(term, escape="\\") for c in (AuditFinding.code, AuditFinding.title, AuditFinding.resource, AuditFinding.control_code)]))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(query.options(joinedload(AuditFinding.owner).joinedload(User.role)).order_by(AuditFinding.last_seen_at.desc(), AuditFinding.code)).all()
    rows = sorted(rows, key=lambda f: (f.status not in catalog.OPEN_FINDING_STATUSES, catalog.SEVERITY_ORDER.get(f.severity, 9)))
    response.headers["X-Total-Count"] = str(total)
    return [finding_brief(f) for f in rows[offset:offset + limit]]


def _allowed_transitions(finding: AuditFinding, user: User) -> list[str]:
    options = sorted(catalog.TRANSITIONS.get(finding.status, set()))
    if is_manager(user): return options
    if finding.owner_id != user.id: return []
    return [t for t in options if (finding.status, t) in catalog.TECHNICIAN_TRANSITIONS]


@audit_center_api.get("/findings/{finding_id}")
def read_finding(finding_id: str, user: User = Depends(members), db: Session = Depends(get_db)):
    finding = _get_finding(db, finding_id, user)
    events = db.scalars(select(AuditFindingEvent).options(joinedload(AuditFindingEvent.actor).joinedload(User.role)).where(AuditFindingEvent.finding_id == finding.id)
                        .order_by(AuditFindingEvent.created_at)).all()
    actions = db.scalars(select(AuditActionItem).options(joinedload(AuditActionItem.owner).joinedload(User.role)).where(AuditActionItem.finding_id == finding.id)
                         .order_by(AuditActionItem.created_at)).all()
    evidences = db.scalars(select(AuditEvidence).options(joinedload(AuditEvidence.uploaded_by).joinedload(User.role)).where(AuditEvidence.finding_id == finding.id)
                           .order_by(AuditEvidence.created_at.desc())).all()
    runs = {r.id: r.code for r in db.scalars(select(AuditRun).where(AuditRun.id.in_({finding.first_run_id, finding.last_run_id, finding.last_verification_run_id} - {None} or {""})))}
    control = db.get(AuditControl, finding.control_code)
    accepted_by = db.get(User, finding.risk_accepted_by_id) if finding.risk_accepted_by_id else None
    return {**finding_brief(finding), "description": finding.description, "impact": finding.impact, "likelihood": finding.likelihood,
            "recommendation": finding.recommendation, "evidence": finding.evidence, "control_title": control.title if control else None,
            "control_method": control.method if control else None, "first_run": runs.get(finding.first_run_id), "last_run": runs.get(finding.last_run_id),
            "last_verification_run": runs.get(finding.last_verification_run_id),
            "risk": {"justification": finding.risk_justification, "review_date": finding.risk_review_date.isoformat() if finding.risk_review_date else None,
                     "accepted_by": user_brief(accepted_by)} if finding.risk_justification else None,
            "events": [{"id": e.id, "event": e.event, "from": e.from_status, "to": e.to_status, "note": e.note, "data": e.data, "created_at": iso(e.created_at),
                        "actor": user_brief(e.actor)} for e in events],
            "actions": [action_data(a) for a in actions], "evidences": [evidence_data(e) for e in evidences],
            "allowed_transitions": _allowed_transitions(finding, user), "can_manage": is_manager(user),
            "can_attach": is_manager(user) or finding.owner_id == user.id or any(a.owner_id == user.id for a in actions)}


@audit_center_api.patch("/findings/{finding_id}")
def update_finding(finding_id: str, payload: FindingUpdateIn, request: Request, actor: User = Depends(managers), db: Session = Depends(get_db)):
    finding = _get_finding(db, finding_id, actor)
    changes = {}
    if payload.clear_owner or payload.owner_id:
        owner = None if payload.clear_owner else _assignable(db, payload.owner_id)
        if (owner.id if owner else None) != finding.owner_id:
            changes["responsable"] = {"anterior": finding.owner_id, "nuevo": owner.id if owner else None}
            fnd.event(db, finding, actor, "ASIGNADO" if owner else "SIN_RESPONSABLE", payload.note or (f"Asignado a {owner.full_name}." if owner else "Responsable retirado."),
                      data=changes["responsable"])
            finding.owner_id = owner.id if owner else None
            if owner and owner.id != actor.id:
                notify(db, owner.id, "AUDITORIA", f"Hallazgo asignado: {finding.code}", finding.title[:180])
    if payload.clear_due_date or payload.due_date:
        due = None if payload.clear_due_date else payload.due_date
        if due and due < datetime.now(UTC).date(): raise HTTPException(422, "La fecha límite no puede estar en el pasado")
        if due != finding.due_date:
            changes["fecha_limite"] = {"anterior": finding.due_date.isoformat() if finding.due_date else None, "nueva": due.isoformat() if due else None}
            fnd.event(db, finding, actor, "FECHA_LIMITE", payload.note or "Fecha límite actualizada.", data=changes["fecha_limite"])
            finding.due_date = due
    if not changes: raise HTTPException(422, "No hay cambios")
    audit(db, actor.id, "ACTUALIZAR_HALLAZGO", MODULE, "AUDIT_FINDING", finding.id, new={"codigo": finding.code, **changes}, request=request)
    db.commit()
    return read_finding(finding.id, actor, db)


@audit_center_api.post("/findings/{finding_id}/status")
def change_finding_status(finding_id: str, payload: FindingStatusIn, request: Request, user: User = Depends(members), db: Session = Depends(get_db)):
    finding = _get_finding(db, finding_id, user)
    previous = finding.status
    fnd.change_status(db, finding, user, payload.status, payload.note, payload.justification, payload.review_date)
    audit(db, user.id, "CAMBIAR_ESTADO_HALLAZGO", MODULE, "AUDIT_FINDING", finding.id, old={"estado": previous},
          new={"codigo": finding.code, "estado": payload.status}, request=request)
    db.commit()
    return read_finding(finding.id, user, db)


@audit_center_api.post("/findings/{finding_id}/verify", status_code=202)
def verify_finding(finding_id: str, request: Request, actor: User = Depends(managers), db: Session = Depends(get_db)):
    finding = _get_finding(db, finding_id, actor)
    try:
        run = engine.create_run(db, actor, f"Verificación de {finding.code}", [], [finding.control_code], scope={"finding_id": finding.id, "options": {}},
                                audit_type="VERIFICACION")
    except engine.RunConflict as exc:
        raise HTTPException(409, str(exc)) from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    fnd.event(db, finding, actor, "VERIFICACION_SOLICITADA", f"Se ejecuta {finding.control_code} en {run.code}.", data={"run": run.code})
    audit(db, actor.id, "VERIFICAR_HALLAZGO", MODULE, "AUDIT_FINDING", finding.id, new={"codigo": finding.code, "ejecucion": run.code}, request=request)
    db.commit()
    engine.submit(run.id)
    return run_brief(_get_run(db, run.id))


@audit_center_api.post("/findings/{finding_id}/actions", status_code=201)
def create_action(finding_id: str, payload: ActionIn, request: Request, actor: User = Depends(managers), db: Session = Depends(get_db)):
    finding = _get_finding(db, finding_id, actor)
    owner = _assignable(db, payload.owner_id)
    if payload.due_date and payload.due_date < datetime.now(UTC).date(): raise HTTPException(422, "La fecha límite no puede estar en el pasado")
    item = AuditActionItem(finding_id=finding.id, description=secret_free(payload.description), owner_id=owner.id if owner else None,
                           due_date=payload.due_date, status="PENDIENTE", created_by_id=actor.id)
    db.add(item)
    db.flush()
    fnd.event(db, finding, actor, "PLAN_DE_ACCION", f"Tarea creada: {payload.description[:200]}", data={"tarea": item.id, "responsable": item.owner_id})
    if owner and owner.id != actor.id: notify(db, owner.id, "AUDITORIA", f"Nueva tarea de auditoría ({finding.code})", payload.description[:180])
    audit(db, actor.id, "CREAR_TAREA", MODULE, "AUDIT_ACTION", item.id, new={"hallazgo": finding.code, "responsable": item.owner_id}, request=request)
    db.commit()
    db.refresh(item)
    return action_data(item)


@audit_center_api.patch("/actions/{action_id}")
def update_action(action_id: str, payload: ActionUpdateIn, request: Request, user: User = Depends(members), db: Session = Depends(get_db)):
    item = db.get(AuditActionItem, action_id)
    if not item or not (is_manager(user) or item.owner_id == user.id): not_found("Tarea")
    finding = db.get(AuditFinding, item.finding_id)
    if not is_manager(user) and (payload.owner_id is not None or payload.due_date is not None):
        raise HTTPException(403, "Solo ADMIN o JEFE_TI pueden reasignar tareas o cambiar su fecha")
    changes = {}
    if payload.status and payload.status != item.status:
        changes["estado"] = {"anterior": item.status, "nuevo": payload.status}
        item.status = payload.status
        item.completed_at = datetime.now(UTC) if payload.status == "COMPLETADA" else None
    if payload.note is not None: item.note, changes["nota"] = secret_free(payload.note), True
    if payload.owner_id is not None:
        owner = _assignable(db, payload.owner_id)
        changes["responsable"] = {"anterior": item.owner_id, "nuevo": owner.id}
        item.owner_id = owner.id
    if payload.due_date is not None: item.due_date, changes["fecha_limite"] = payload.due_date, payload.due_date.isoformat()
    if not changes: raise HTTPException(422, "No hay cambios")
    fnd.event(db, finding, user, "TAREA_ACTUALIZADA", payload.note or f"Tarea {item.status.lower()}.", data={"tarea": item.id, **{k: v for k, v in changes.items() if k != "nota"}})
    audit(db, user.id, "ACTUALIZAR_TAREA", MODULE, "AUDIT_ACTION", item.id, new={"hallazgo": finding.code, **changes}, request=request)
    db.commit()
    db.refresh(item)
    return action_data(item)


@audit_center_api.get("/my")
def my_work(user: User = Depends(members), db: Session = Depends(get_db)):
    findings = db.scalars(select(AuditFinding).options(joinedload(AuditFinding.owner).joinedload(User.role)).where(
        AuditFinding.owner_id == user.id, AuditFinding.status.in_(catalog.OPEN_FINDING_STATUSES))).all()
    actions = db.scalars(select(AuditActionItem).options(joinedload(AuditActionItem.owner).joinedload(User.role)).where(
        AuditActionItem.owner_id == user.id, AuditActionItem.status.in_(("PENDIENTE", "EN_CURSO")))).all()
    codes = {f.id: f.code for f in db.scalars(select(AuditFinding).where(AuditFinding.id.in_({a.finding_id for a in actions} or {""})))}
    return {"findings": [finding_brief(f) for f in sorted(findings, key=lambda f: catalog.SEVERITY_ORDER.get(f.severity, 9))],
            "actions": [{**action_data(a), "finding_code": codes.get(a.finding_id)} for a in actions]}


# --- Evidence ----------------------------------------------------------------------------------------------------------
@audit_center_api.post("/evidences", status_code=201)
async def upload_evidence(request: Request, kind: Literal["MANUAL", "CORRECCION"] = Form(...), title: str = Form(..., min_length=5, max_length=200),
                          description: str | None = Form(None, max_length=4000), control_code: str | None = Form(None, pattern=CODE),
                          finding_id: str | None = Form(None, max_length=36), declared_result: str | None = Form(None, pattern="^(APROBADO|FALLIDO|ADVERTENCIA|NO_APLICABLE)$"),
                          evidence_date: date | None = Form(None), file: UploadFile | None = File(None), user: User = Depends(members),
                          db: Session = Depends(get_db)):
    if any("\x00" in (v or "") for v in (title, description)): raise HTTPException(422, "Contiene caracteres no permitidos")
    finding = None
    if kind == "MANUAL":
        if not is_manager(user): raise HTTPException(403, "Solo ADMIN o JEFE_TI registran evidencia manual de controles")
        control = db.get(AuditControl, control_code) if control_code else None
        if not control or control.method != "MANUAL": raise HTTPException(422, "Indique un control de verificación manual")
        if not declared_result: raise HTTPException(422, "Indique el resultado que acredita la evidencia")
        if not evidence_date: raise HTTPException(422, "Indique la fecha a la que corresponde la evidencia")
        if file is None: raise HTTPException(422, "La evidencia manual debe incluir un archivo")
    else:
        if not finding_id: raise HTTPException(422, "La evidencia de corrección debe asociarse a un hallazgo")
        finding = _get_finding(db, finding_id, user)
        if not is_manager(user) and finding.owner_id != user.id and not db.scalar(select(func.count(AuditActionItem.id)).where(
                AuditActionItem.finding_id == finding.id, AuditActionItem.owner_id == user.id)):
            raise HTTPException(403, "Solo el responsable del hallazgo o de una de sus tareas puede adjuntar evidencia")
        if file is None and len((description or "").strip()) < 20:
            raise HTTPException(422, "Adjunte un archivo o describa la corrección (mínimo 20 caracteres)")
        control_code, declared_result = finding.control_code, None
    if evidence_date and evidence_date > datetime.now(UTC).date(): raise HTTPException(422, "La fecha de la evidencia no puede ser futura")
    stored = digest = content_type = original = None
    size = None
    if file is not None:
        content_type = ev.detect_type(file.content_type, file.filename)
        raw = await file.read(settings.audit_evidence_max_bytes + 1)
        ev.validate(raw, content_type, settings.audit_evidence_max_bytes)
        stored, digest = ev.store(raw, content_type)
        original, size = ev.safe_name(file.filename), len(raw)
    row = AuditEvidence(kind=kind, title=secret_free(title, 200), description=secret_free(description) if description else None, control_code=control_code,
                        finding_id=finding.id if finding else None, declared_result=declared_result, evidence_date=evidence_date, original_name=original,
                        stored_name=stored, content_type=content_type, size=size, sha256=digest, uploaded_by_id=user.id, created_at=datetime.now(UTC))
    db.add(row)
    db.flush()
    if finding: fnd.event(db, finding, user, "EVIDENCIA", f"Evidencia de corrección: {row.title}", data={"evidencia": row.id, "sha256": digest})
    audit(db, user.id, "REGISTRAR_EVIDENCIA", MODULE, "AUDIT_EVIDENCE", row.id, new={"tipo": kind, "control": control_code, "hallazgo": finding.code if finding else None,
          "resultado_declarado": declared_result, "sha256": digest, "bytes": size}, request=request)
    db.commit()
    db.refresh(row)
    return evidence_data(row)


@audit_center_api.get("/evidences")
def list_evidences(response: Response, control: str | None = Query(None, pattern=CODE), kind: str | None = Query(None, pattern="^(MANUAL|CORRECCION|IMPORTADA)$"),
                   limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0), _: User = Depends(managers), db: Session = Depends(get_db)):
    query = select(AuditEvidence)
    if control: query = query.where(AuditEvidence.control_code == control)
    if kind: query = query.where(AuditEvidence.kind == kind)
    response.headers["X-Total-Count"] = str(db.scalar(select(func.count()).select_from(query.subquery())) or 0)
    rows = db.scalars(query.options(joinedload(AuditEvidence.uploaded_by).joinedload(User.role)).order_by(AuditEvidence.created_at.desc()).offset(offset).limit(limit)).all()
    return [evidence_data(e) for e in rows]


@audit_center_api.get("/evidences/{evidence_id}/download")
def download_evidence(evidence_id: str, request: Request, user: User = Depends(members), db: Session = Depends(get_db)):
    row = db.get(AuditEvidence, evidence_id)
    if not row: not_found("Evidencia")
    if not is_manager(user):
        finding = db.get(AuditFinding, row.finding_id) if row.finding_id else None
        if not finding or not _finding_visible(db, finding, user): not_found("Evidencia")
    if not row.stored_name: raise HTTPException(404, "La evidencia no tiene archivo")
    path = ev.path_of(row.stored_name)
    if not path.is_file(): raise HTTPException(404, "El archivo de la evidencia ya no existe en el servidor")
    audit(db, user.id, "DESCARGAR_EVIDENCIA", MODULE, "AUDIT_EVIDENCE", row.id, new={"sha256": row.sha256}, request=request)
    db.commit()
    return FileResponse(path, media_type=row.content_type or "application/octet-stream", filename=row.original_name or "evidencia",
                        headers={"X-Content-SHA256": row.sha256 or ""})


# --- Imports -----------------------------------------------------------------------------------------------------------
@audit_center_api.post("/imports", status_code=201)
async def import_file(request: Request, kind: Literal["LOGS_BD", "BANDIT", "PIP_AUDIT", "ZAP", "SARIF"] = Form(...),
                      notes: str | None = Form(None, max_length=2000), file: UploadFile = File(...), actor: User = Depends(managers),
                      db: Session = Depends(get_db)):
    raw = await file.read(settings.audit_import_max_bytes + 1)
    if not raw: raise HTTPException(422, "El archivo está vacío")
    if len(raw) > settings.audit_import_max_bytes: raise HTTPException(413, f"El archivo excede {settings.audit_import_max_bytes // 1_048_576} MB")
    digest = importers.sha256(raw)
    duplicate = db.scalars(select(AuditImport).where(AuditImport.kind == kind, AuditImport.sha256 == digest,
                                                     AuditImport.status.in_(("COMPLETADA", "PARCIAL")))).first()
    if duplicate: raise HTTPException(409, f"Este archivo ya se importó el {iso(duplicate.imported_at)} (importación {duplicate.id[:8]})")
    row = AuditImport(id=uid(), kind=kind, source_name=ev.safe_name(file.filename), sha256=digest, size=len(raw), status="RECHAZADA", imported_by_id=actor.id,
                      imported_at=datetime.now(UTC), notes=secret_free(notes) if notes else None)
    db.add(row)
    try:
        if kind == "LOGS_BD":
            parsed = importers.parse_db_logs(raw, settings.audit_import_max_rows)
            hashes = [r["record_hash"] for r in parsed["records"]]
            existing = set()
            for chunk in range(0, len(hashes), 900):
                existing |= set(db.scalars(select(AuditExternalLog.record_hash).where(AuditExternalLog.record_hash.in_(hashes[chunk:chunk + 900]))))
            db.flush()
            fresh, seen = [], set()
            for record in parsed["records"]:
                if record["record_hash"] in existing or record["record_hash"] in seen: continue
                seen.add(record["record_hash"])
                fresh.append(AuditExternalLog(import_id=row.id, **record))
            db.add_all(fresh)
            row.rows_total, row.rows_imported = parsed["total"], len(fresh)
            row.rows_duplicated = len(parsed["records"]) - len(fresh)
            row.rows_rejected = parsed["rejected"]
            row.tool = {"name": "PostgreSQL/pgAudit", "formato": parsed["format"]}
            row.summary = {"descartados_sin_interes": parsed["discarded"], "pgaudit": sum(1 for r in fresh if r.source == "PGAUDIT"),
                           "postgres": sum(1 for r in fresh if r.source == "POSTGRES"), "redactados": sum(1 for r in fresh if r.redacted),
                           "transformaciones": ["Caracteres de control escapados", "Secretos redactados", "Parámetros de pgAudit no almacenados",
                                                "Campos derivados (clase, comando, objeto) calculados desde el mensaje original"]}
            row.errors = parsed["errors"] or None
            row.status = "PARCIAL" if parsed["rejected"] else "COMPLETADA"
        else:
            parsed = importers.PARSERS[kind](raw)
            row.tool, row.summary, row.rows_total = parsed["tool"], parsed["summary"], parsed["total"]
            row.rows_imported, row.status = parsed["total"], "COMPLETADA"
    except importers.ImportRejected as exc:
        row.errors = [exc.detail]
        audit(db, actor.id, "IMPORTAR_EVIDENCIA", MODULE, "AUDIT_IMPORT", row.id, new={"tipo": kind, "sha256": digest, "estado": "RECHAZADA"}, request=request,
              outcome="FALLO")
        db.commit()
        raise
    audit(db, actor.id, "IMPORTAR_EVIDENCIA", MODULE, "AUDIT_IMPORT", row.id, new={"tipo": kind, "sha256": digest, "estado": row.status,
          "registros": row.rows_imported, "duplicados": row.rows_duplicated}, request=request)
    db.commit()
    db.refresh(row)
    return import_data(row, detail=True)


@audit_center_api.get("/imports")
def list_imports(response: Response, kind: str | None = Query(None, pattern="^[A-Z_]{3,20}$"), limit: int = Query(30, ge=1, le=100), offset: int = Query(0, ge=0),
                 _: User = Depends(managers), db: Session = Depends(get_db)):
    query = select(AuditImport)
    if kind: query = query.where(AuditImport.kind == kind)
    response.headers["X-Total-Count"] = str(db.scalar(select(func.count()).select_from(query.subquery())) or 0)
    rows = db.scalars(query.options(joinedload(AuditImport.imported_by).joinedload(User.role)).order_by(AuditImport.imported_at.desc()).offset(offset).limit(limit)).all()
    return [import_data(i) for i in rows]


@audit_center_api.get("/imports/{import_id}")
def read_import(import_id: str, _: User = Depends(managers), db: Session = Depends(get_db)):
    row = db.get(AuditImport, import_id)
    if not row: not_found("Importación")
    return import_data(row, detail=True)


@audit_center_api.get("/external-logs")
def external_logs(response: Response, source: str | None = Query(None, pattern="^(PGAUDIT|POSTGRES)$"), statement_class: str | None = Query(None, pattern="^[A-Z_]{2,30}$"),
                  db_user: str | None = Query(None, max_length=100), q: str | None = Query(None, max_length=100), date_from: datetime | None = None,
                  date_to: datetime | None = None, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0), _: User = Depends(managers),
                  db: Session = Depends(get_db)):
    query = select(AuditExternalLog)
    if source: query = query.where(AuditExternalLog.source == source)
    if statement_class: query = query.where(AuditExternalLog.statement_class == statement_class)
    if db_user: query = query.where(AuditExternalLog.db_user == db_user)
    if date_from: query = query.where(AuditExternalLog.log_time >= engine.aware(date_from))
    if date_to: query = query.where(AuditExternalLog.log_time < engine.aware(date_to))
    if q:
        term = "%" + q.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        query = query.where(or_(func.lower(AuditExternalLog.object_name).like(term, escape="\\"), func.lower(AuditExternalLog.command).like(term, escape="\\")))
    response.headers["X-Total-Count"] = str(db.scalar(select(func.count()).select_from(query.subquery())) or 0)
    rows = db.scalars(query.order_by(AuditExternalLog.log_time.desc()).offset(offset).limit(limit)).all()
    return [{"id": r.id, "import_id": r.import_id, "source": r.source, "log_time": iso(r.log_time), "db_user": r.db_user, "database": r.database,
             "audit_type": r.audit_type, "class": r.statement_class, "command": r.command, "object_type": r.object_type, "object": r.object_name,
             "statement": r.statement, "redacted": r.redacted, "original": r.original, "record_hash": r.record_hash} for r in rows]
