"""Audit trail: filtered queries and CSV/JSON export for external audits (format: docs/auditoria.md).

Only ADMIN and JEFE_TI. Authorization is enforced here, not by the web client; attempts by other roles are
recorded with outcome DENEGADO. Queries and exports are themselves audited. There is no endpoint that edits or
deletes audit records.
"""
import csv
import io
import json
import os
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import func, or_
from sqlalchemy.orm import Session, joinedload
from app import __version__
from app.core.config import settings
from app.core.database import get_db
from app.core.errors import forbidden
from app.models import AuditLog, Role, User
from app.security.auth import current_user
from app.services.audit import INTEGRITY, OUTCOMES, REDACTED, audit, iso, key_id, redact, utc, verify
from app.services.exports import safe_row

audit_api = APIRouter(prefix="/api/audit", tags=["auditoria"])
AUDITORS = {"ADMIN", "JEFE_TI"}
SYSTEM_USER = "SISTEMA"  # user_id filter value for records without a user (worker, scheduled agents, CLI)
CODE = r"^[A-Za-z0-9_.:\-]{1,80}$"
EXPORT_FORMAT = "1.0"
COLUMNS = [("id", "id"), ("fecha_utc", "created_at"), ("usuario_id", "user_id"), ("usuario_nombre", "user_name"),
           ("usuario_email", "user_email"), ("usuario_rol_actual", "user_role"), ("accion", "action"), ("modulo", "module"),
           ("entidad", "entity"), ("entidad_id", "entity_id"), ("resultado", "outcome"), ("ip", "ip"), ("navegador", "user_agent"),
           ("valor_anterior", "old_value"), ("valor_nuevo", "new_value"), ("integridad", "integrity")]


def auditor(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)) -> User:
    if user.role.code not in AUDITORS:
        audit(db, user.id, "ACCESO_DENEGADO", "AUDITORIA", "AUDIT_LOG", None,
              new={"method": request.method, "path": request.url.path}, request=request, outcome="DENEGADO")
        db.commit()
        forbidden("Rol sin autorización")
    return user


class AuditFilters:
    """Query filters shared by the list and the export. ``date_from`` is inclusive and ``date_to`` exclusive;
    datetimes without offset are taken as UTC."""

    def __init__(self, date_from: datetime | None = Query(None), date_to: datetime | None = Query(None),
                 user_id: str | None = Query(None, max_length=36), action: str | None = Query(None, pattern=CODE),
                 module: str | None = Query(None, pattern=CODE), entity: str | None = Query(None, pattern=CODE),
                 entity_id: str | None = Query(None, max_length=36), outcome: str | None = Query(None, pattern=f"^({'|'.join(OUTCOMES)})$"),
                 ip: str | None = Query(None, max_length=64), q: str | None = Query(None, max_length=100)):
        self.date_from, self.date_to = utc(date_from), utc(date_to)
        if self.date_from and self.date_to and self.date_from >= self.date_to:
            raise HTTPException(422, "La fecha inicial debe ser anterior a la final")
        self.user_id, self.action, self.module, self.entity = user_id or None, action, module, entity
        self.entity_id, self.outcome, self.ip, self.q = entity_id or None, outcome, ip or None, (q or "").strip() or None

    def applied(self) -> dict:
        values = {"desde": iso(self.date_from), "hasta": iso(self.date_to), "usuario_id": self.user_id, "accion": self.action,
                  "modulo": self.module, "entidad": self.entity, "entidad_id": self.entity_id, "resultado": self.outcome,
                  "ip": self.ip, "texto": self.q}
        return {k: v for k, v in values.items() if v is not None}

    def apply(self, query):
        if self.date_from: query = query.filter(AuditLog.created_at >= self.date_from)
        if self.date_to: query = query.filter(AuditLog.created_at < self.date_to)
        if self.user_id == SYSTEM_USER: query = query.filter(AuditLog.user_id.is_(None))
        elif self.user_id: query = query.filter(AuditLog.user_id == self.user_id)
        for column, value in ((AuditLog.action, self.action), (AuditLog.module, self.module), (AuditLog.entity, self.entity),
                              (AuditLog.entity_id, self.entity_id), (AuditLog.outcome, self.outcome), (AuditLog.ip, self.ip)):
            if value: query = query.filter(column == value)
        if self.q:
            term = "%" + self.q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            query = query.filter(or_(*[func.lower(c).like(term, escape="\\") for c in
                                       (AuditLog.action, AuditLog.module, AuditLog.entity, AuditLog.entity_id)]))
        return query


def record(row: AuditLog) -> dict:
    user = row.user
    return {"id": row.id, "created_at": iso(row.created_at), "user_id": row.user_id, "user_name": user.full_name if user else "Sistema",
            "user_email": user.email if user else None, "user_role": user.role.code if user else None, "action": row.action,
            "module": row.module, "entity": row.entity, "entity_id": row.entity_id, "outcome": row.outcome, "ip": row.ip,
            "user_agent": row.user_agent, "old_value": redact(row.old_value), "new_value": redact(row.new_value), "integrity": verify(row)}


def _query(db: Session, filters: AuditFilters):
    return filters.apply(db.query(AuditLog))


@audit_api.get("")
def list_audit(response: Response, request: Request, filters: AuditFilters = Depends(), limit: int = Query(100, ge=1, le=500),
               offset: int = Query(0, ge=0), actor: User = Depends(auditor), db: Session = Depends(get_db)):
    query = _query(db, filters)
    total = query.order_by(None).count()
    rows = query.options(joinedload(AuditLog.user).joinedload(User.role)).order_by(AuditLog.created_at.desc(), AuditLog.id).offset(offset).limit(limit).all()
    data = [record(x) for x in rows]
    if offset == 0:  # one record per query; paging through its results is not logged again
        audit(db, actor.id, "CONSULTAR", "AUDITORIA", "AUDIT_LOG", None, new={"filtros": filters.applied(), "total": total}, request=request)
        db.commit()
    response.headers["X-Total-Count"] = str(total)
    return data


@audit_api.get("/facets")
def facets(_: User = Depends(auditor), db: Session = Depends(get_db)):
    """Values present in the trail, for the filter controls."""
    def distinct(column):
        return [x for (x,) in db.query(column).distinct().order_by(column).limit(500) if x]
    users = (db.query(User.id, User.full_name, User.email, Role.code).join(Role, User.role_id == Role.id)
             .filter(User.id.in_(db.query(AuditLog.user_id).filter(AuditLog.user_id.isnot(None)).distinct()))
             .order_by(User.full_name).limit(500).all())
    return {"actions": distinct(AuditLog.action), "modules": distinct(AuditLog.module), "entities": distinct(AuditLog.entity),
            "outcomes": list(OUTCOMES), "integrity": INTEGRITY, "system_user": SYSTEM_USER,
            "users": [{"id": u[0], "name": u[1], "email": u[2], "role": u[3]} for u in users],
            "export_max_rows": settings.audit_export_max_rows}


def _metadata(actor: User, filters: AuditFilters, records: list[dict], event_id: str, now: datetime) -> dict:
    status = {}
    for r in records: status[r["integrity"]] = status.get(r["integrity"], 0) + 1
    return {
        "formato": "fixit-auditoria", "version_formato": EXPORT_FORMAT,
        "aplicacion": {"nombre": "FixIT", "version": __version__, "compilacion": (os.getenv("RENDER_GIT_COMMIT") or "")[:12] or None},
        "exportado_en": iso(now), "zona_horaria": "UTC",
        "exportado_por": {"id": actor.id, "nombre": actor.full_name, "email": actor.email, "rol": actor.role.code},
        "evento_exportacion_id": event_id,
        "filtros": filters.applied(),
        "intervalo_solicitado": {"desde": iso(filters.date_from), "hasta_exclusivo": iso(filters.date_to)},
        "intervalo_registros": {"primero": records[0]["created_at"] if records else None, "ultimo": records[-1]["created_at"] if records else None},
        "total_registros": len(records), "orden": "fecha_utc ascendente",
        "integridad": {"metodo": "HMAC-SHA256 por registro, calculado al crearlo (sello v1)", "clave_id": key_id(), "resumen": status,
                       "estados": INTEGRITY,
                       "alcance": "El sello permite detectar cambios en un registro hechos fuera de la aplicación. No detecta registros "
                                  "eliminados por quien pueda desactivar las protecciones de la base de datos ni acredita por sí solo el "
                                  "origen del archivo; para eso conserve el archivo junto con una constancia de su recepción."},
        "redaccion": f"Los campos cuyo nombre indica contraseñas, tokens, claves, cookies o credenciales se muestran como {REDACTED}.",
        "notas": ["El evento de esta exportación se registra en la auditoría y no está incluido en el archivo.",
                  "usuario_rol_actual es el rol del usuario al momento de exportar, no necesariamente el que tenía en la fecha del evento.",
                  "En CSV, los textos que empiezan con = + - @ llevan un apóstrofo inicial para que las hojas de cálculo no los ejecuten."],
    }


def _csv(meta: dict, records: list[dict]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    lines = [("formato", f"{meta['formato']} {meta['version_formato']}"), ("aplicacion", json.dumps(meta["aplicacion"], ensure_ascii=False)),
             ("exportado_en", meta["exportado_en"]), ("zona_horaria", meta["zona_horaria"]),
             ("exportado_por", f"{meta['exportado_por']['email']} ({meta['exportado_por']['rol']}, id {meta['exportado_por']['id']})"),
             ("evento_exportacion_id", meta["evento_exportacion_id"]), ("filtros", json.dumps(meta["filtros"], ensure_ascii=False)),
             ("intervalo_solicitado", json.dumps(meta["intervalo_solicitado"])), ("intervalo_registros", json.dumps(meta["intervalo_registros"])),
             ("total_registros", meta["total_registros"]), ("integridad", f"{meta['integridad']['metodo']}; clave {meta['integridad']['clave_id']}; "
                                                                           f"{json.dumps(meta['integridad']['resumen'])}")]
    writer.writerow(safe_row(["# filas_metadatos", len(lines) + 1]))
    for key, value in lines: writer.writerow(safe_row([f"# {key}", value]))
    writer.writerow([])
    writer.writerow([name for name, _ in COLUMNS])
    for r in records:
        writer.writerow(safe_row([json.dumps(r[k], ensure_ascii=False, sort_keys=True) if k in ("old_value", "new_value") and r[k] is not None
                                  else r[k] for _, k in COLUMNS]))
    return "﻿" + out.getvalue()  # BOM: spreadsheet programs then read the file as UTF-8


@audit_api.get("/export")
def export(request: Request, format: str = Query("csv", pattern="^(csv|json)$"), filters: AuditFilters = Depends(),
           actor: User = Depends(auditor), db: Session = Depends(get_db)):
    query = _query(db, filters)
    total = query.order_by(None).count()
    if total > settings.audit_export_max_rows:
        raise HTTPException(422, f"La exportación tendría {total} registros y el máximo es {settings.audit_export_max_rows}. "
                                 "Acote el rango de fechas u otros filtros.")
    rows = query.options(joinedload(AuditLog.user).joinedload(User.role)).order_by(AuditLog.created_at, AuditLog.id).all()
    records = [record(x) for x in rows]
    now = datetime.now(timezone.utc)
    event = audit(db, actor.id, "EXPORTAR", "AUDITORIA", "AUDIT_LOG", None,
                  new={"formato": format, "filtros": filters.applied(), "registros": len(records)}, request=request)
    db.commit()
    meta = _metadata(actor, filters, records, event.id, now)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    span = "_".join(x.strftime("%Y%m%d") for x in (filters.date_from, filters.date_to) if x)
    filename = f"fixit-auditoria_{stamp}{'_' + span if span else ''}.{format}"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"', "X-Total-Count": str(len(records))}
    if format == "json":
        body = json.dumps({"metadatos": meta, "registros": [{name: r[k] for name, k in COLUMNS} for r in records]},
                          ensure_ascii=False, indent=2)
        return Response(body, media_type="application/json; charset=utf-8", headers=headers)
    return Response(_csv(meta, records), media_type="text/csv; charset=utf-8", headers=headers)
