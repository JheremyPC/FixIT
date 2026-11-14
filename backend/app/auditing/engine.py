"""Audit engine: creates runs, executes their controls in the background and stores results.

Execution model
* A run is created PENDIENTE and submitted to a small thread pool (``AUDIT_MAX_CONCURRENT_RUNS``, default 1), so HTTP
  requests never wait for it. The run is claimed with one conditional UPDATE (PENDIENTE -> EN_CURSO), so the same run can
  never execute twice, even with several processes.
* Each control runs on its own read-only transaction (app.auditing.readonly) and its result is committed immediately,
  with a heartbeat; progress survives a crash. A run that exceeds ``AUDIT_RUN_MAX_SECONDS`` or is cancelled records the
  remaining controls as NO_VERIFICADO.
* On startup, PENDIENTE runs are queued again and EN_CURSO runs without a recent heartbeat are closed as INTERRUMPIDA
  (their missing controls are stored as NO_VERIFICADO, never as approved).
* At the end, findings are synchronized (app.auditing.findings), the overall result is computed and the results are sealed
  with HMAC-SHA256 (same server key as the activity trail) so later edits in the database are detectable.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import platform
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from importlib import metadata

from sqlalchemy import func, select, update
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from app import __version__
from app.auditing import readonly
from app.auditing.catalog import CATEGORIES, ENGINE_VERSION, SEVERITY_ORDER
from app.auditing.redaction import redact_details, safe_error, secret_free
from app.auditing.registry import Control, Ctx, NotVerifiable, Outcome, RunInfo, load_controls
from app.core.config import settings
from app.core.database import SessionLocal
from app.models import AuditControl, AuditResult, AuditRun, User
from app.services.audit import _key, audit, iso, key_id

UTC = timezone.utc
log = logging.getLogger("fixit.auditing")
ACTIVE = ("PENDIENTE", "EN_CURSO")
FINAL = ("COMPLETADA", "COMPLETADA_CON_ERRORES", "CANCELADA", "INTERRUMPIDA")
MAX_QUEUED = 5
SEAL_VERSION = "r1"
PRIVILEGES = {
    "ESTATICO": "Lectura de los archivos y la configuración de la aplicación desplegada (sin acceso de escritura).",
    "DINAMICO": "Solicitud interna al propio proceso (ASGI), sin tráfico de red ni escritura de datos.",
    "MANUAL": "Evidencias registradas por personas (lectura de audit_evidences).",
    "IMPORTADO": "Informes importados por personas (lectura de audit_imports y audit_external_logs).",
}


class RunConflict(RuntimeError):
    pass


def now() -> datetime:
    return datetime.now(UTC)


def aware(moment: datetime | None) -> datetime | None:
    if moment is None: return None
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)


# --- Catalog --------------------------------------------------------------------------------------------------------
def controls() -> dict[str, Control]:
    return load_controls()


def sync_catalog(db: Session) -> None:
    """Insert new controls and refresh the description of existing ones; ``enabled`` (set by ADMIN) is preserved."""
    registry = controls()
    rows = {c.code: c for c in db.scalars(select(AuditControl))}
    for code, ctrl in registry.items():
        row = rows.get(code)
        if row is None:
            db.add(AuditControl(code=code, category=ctrl.category, title=ctrl.title, objective=ctrl.objective, method=ctrl.method,
                                default_severity=ctrl.severity, criteria=ctrl.criteria, enabled=True))
        else:
            for attr, value in (("category", ctrl.category), ("title", ctrl.title), ("objective", ctrl.objective), ("method", ctrl.method),
                                ("default_severity", ctrl.severity), ("criteria", ctrl.criteria)):
                if getattr(row, attr) != value: setattr(row, attr, value)
    try:
        db.commit()
    except IntegrityError:  # another instance synchronized first
        db.rollback()


def enabled_codes(db: Session) -> set[str]:
    return {c for (c,) in db.execute(select(AuditControl.code).where(AuditControl.enabled.is_(True)))}


# --- Runs -----------------------------------------------------------------------------------------------------------
def next_code(db: Session, model, prefix: str) -> str:
    year = now().year
    head = f"{prefix}-{year}-"
    last = db.scalar(select(func.max(model.code)).where(model.code.like(f"{head}%")))
    number = int(last.rsplit("-", 1)[1]) + 1 if last else 1
    return f"{head}{number:04d}"


def create_run(db: Session, actor: User | None, name: str, categories: list[str], control_codes: list[str] | None = None,
               period_from: datetime | None = None, period_to: datetime | None = None, scope: dict | None = None,
               audit_type: str | None = None, parent_run_id: str | None = None) -> AuditRun:
    registry = controls()
    allowed = enabled_codes(db)
    categories = [c for c in dict.fromkeys(categories) if c in CATEGORIES]
    if control_codes:
        codes = [c for c in dict.fromkeys(control_codes) if c in registry]
        unknown = set(control_codes) - set(registry)
        if unknown: raise ValueError(f"Controles desconocidos: {', '.join(sorted(unknown))}")
        disabled = [c for c in codes if c not in allowed]
        if disabled: raise ValueError(f"Controles deshabilitados por un administrador: {', '.join(disabled)}")
        categories = list(dict.fromkeys([registry[c].category for c in codes]))
    else:
        if not categories: raise ValueError("Seleccione al menos una categoría")
        codes = [c for c, ctrl in registry.items() if ctrl.category in categories and c in allowed]
    if not codes: raise ValueError("No hay controles habilitados para el alcance seleccionado")
    period_from, period_to = aware(period_from), aware(period_to)
    if period_from and period_to and period_from >= period_to: raise ValueError("El inicio del periodo debe ser anterior al fin")
    if period_to and period_to > now() + timedelta(days=1): raise ValueError("El periodo no puede terminar en el futuro")
    recover_stale(db)
    active = db.scalars(select(AuditRun).where(AuditRun.status.in_(ACTIVE))).all()
    if any(sorted(r.control_codes) == sorted(codes) for r in active):
        raise RunConflict("Ya hay una ejecución pendiente o en curso con los mismos controles. Espere a que termine.")
    if len(active) >= MAX_QUEUED:
        raise RunConflict(f"Hay {len(active)} auditorías pendientes o en curso; el máximo en cola es {MAX_QUEUED}.")
    if audit_type is None:
        audit_type = "COMPLETA" if set(categories) == set(CATEGORIES) and not control_codes else (
            "PERSONALIZADA" if control_codes else "CATEGORIA")
    for _ in range(3):
        run = AuditRun(code=next_code(db, AuditRun, "AUD"), name=name.strip()[:150], audit_type=audit_type, categories=categories,
                       control_codes=codes, scope=scope or {}, period_from=period_from, period_to=period_to, status="PENDIENTE",
                       requested_by_id=actor.id if actor else None, parent_run_id=parent_run_id, app_version=__version__,
                       build=(os.getenv("RENDER_GIT_COMMIT") or "")[:12] or None, progress_total=len(codes), created_at=now())
        db.add(run)
        try:
            db.flush()
            return run
        except IntegrityError:  # code taken concurrently
            db.rollback()
    raise RunConflict("No se pudo asignar un código a la auditoría; vuelva a intentarlo.")


# --- Background execution -------------------------------------------------------------------------------------------
_executor: ThreadPoolExecutor | None = None
_queued: set[str] = set()
_lock = threading.Lock()
_stopping = threading.Event()


def _pool() -> ThreadPoolExecutor:
    global _executor
    with _lock:
        if _executor is None:
            _executor = ThreadPoolExecutor(max_workers=max(1, settings.audit_max_concurrent_runs), thread_name_prefix="fixit-audit")
        return _executor


def submit(run_id: str) -> None:
    with _lock:
        if run_id in _queued: return
        _queued.add(run_id)
    _stopping.clear()
    _pool().submit(_execute_safely, run_id)


def _execute_safely(run_id: str) -> None:
    try:
        execute(run_id)
    except Exception:  # noqa: BLE001 - logged; the run is closed as INTERRUMPIDA inside execute when possible
        log.exception("Fallo inesperado del motor de auditoría (ejecución %s)", run_id)
    finally:
        with _lock: _queued.discard(run_id)


def request_cancel(db: Session, run: AuditRun) -> str:
    """A PENDIENTE run is closed at once (CANCELADA); a running one stops after its current control. The conditional
    UPDATE decides the race with a worker that is claiming the run at the same moment."""
    closed = db.execute(update(AuditRun).where(AuditRun.id == run.id, AuditRun.status == "PENDIENTE")
                        .values(cancel_requested=True, status="EN_CURSO", started_at=now(), heartbeat_at=now())
                        .execution_options(synchronize_session=False)).rowcount
    db.refresh(run)
    if closed == 1:
        _close_unexecuted(db, run, "No se ejecutó: la auditoría se canceló antes de iniciar.")
        _finish(db, run, "CANCELADA", {})
        return "CANCELADA"
    if run.status == "EN_CURSO":
        db.execute(update(AuditRun).where(AuditRun.id == run.id).values(cancel_requested=True).execution_options(synchronize_session=False))
        db.commit()
        return "CANCELACION_SOLICITADA"
    return run.status


def effective_severity(out: Outcome, default_severity: str | None) -> str | None:
    """Severity of a FALLIDO/ADVERTENCIA result: the one the control returned, otherwise its default. A warning is capped at
    MEDIO unless the control explicitly says otherwise (it is not a confirmed failure)."""
    if out.status not in ("FALLIDO", "ADVERTENCIA"): return out.severity
    severity = out.severity or default_severity
    if out.status == "ADVERTENCIA" and not out.severity and severity and SEVERITY_ORDER.get(severity, 9) < SEVERITY_ORDER["MEDIO"]:
        severity = "MEDIO"
    return severity


def _privileges(ctrl: Control, conn_summary: str) -> str:
    return PRIVILEGES.get(ctrl.method) or conn_summary


def run_control(ctrl: Control, info: RunInfo, conn_summary: str) -> tuple[Outcome, datetime, datetime]:
    """Execute one control on a fresh read-only transaction. Never raises."""
    started = now()
    try:
        with readonly.read_only() as conn:
            dialect = conn.dialect.name
            if "postgresql" in ctrl.requires and dialect != "postgresql":
                out = Outcome("NO_APLICABLE", "Requiere PostgreSQL; la base de datos de este entorno es SQLite.")
            else:
                ctx = Ctx(conn=conn, dialect=dialect, run=info, now=started, privileges=conn_summary, control=ctrl)
                try:
                    out = ctrl.fn(ctx)
                finally:
                    if ctx._session is not None: ctx._session.close()
    except NotVerifiable as exc:
        out = Outcome("NO_VERIFICADO", secret_free(str(exc), 480))
    except DBAPIError as exc:
        code = getattr(getattr(exc, "orig", None), "sqlstate", None) or getattr(getattr(exc, "orig", None), "pgcode", None)
        if code == "42501":
            out = Outcome("NO_VERIFICADO", "Permisos insuficientes de la conexión de auditoría para esta comprobación.",
                          {"error": safe_error(exc)})
        elif code == "57014":
            out = Outcome("NO_VERIFICADO", f"La consulta superó el tiempo límite ({settings.audit_statement_timeout_ms} ms).")
        else:
            out = Outcome("ERROR_EJECUCION", "La consulta del control falló.", {"error": safe_error(exc)})
    except Exception as exc:  # noqa: BLE001 - a broken control must not stop the run
        log.warning("Control %s: error de ejecución", ctrl.code, exc_info=True)
        out = Outcome("ERROR_EJECUCION", "El control produjo un error técnico; su resultado es desconocido.", {"error": safe_error(exc)})
    return out, started, now()


def _store_result(db: Session, run: AuditRun, code: str, category: str, method: str, out: Outcome, started: datetime,
                  finished: datetime, privileges: str | None, default_severity: str | None) -> AuditResult:
    severity = effective_severity(out, default_severity)
    row = AuditResult(run_id=run.id, control_code=code, category=category, status=out.status, method=out.method or method,
                      severity=severity, summary=secret_free(out.summary, 490) or "", details=redact_details(out.details) or None,
                      privileges=(privileges or "")[:300] or None, started_at=started, finished_at=finished,
                      duration_ms=int((finished - started).total_seconds() * 1000),
                      error=(out.details or {}).get("error") if out.status == "ERROR_EJECUCION" else None)
    db.add(row)
    return row


def execute(run_id: str) -> None:
    from app.auditing import findings as finding_sync

    db = SessionLocal()
    try:
        started = now()
        claimed = db.execute(update(AuditRun).where(AuditRun.id == run_id, AuditRun.status == "PENDIENTE", AuditRun.cancel_requested.is_(False))
                             .values(status="EN_CURSO", started_at=started, heartbeat_at=started)
                             .execution_options(synchronize_session=False)).rowcount
        db.commit()
        run = db.get(AuditRun, run_id)
        if run is None: return
        if claimed != 1:  # executed by another worker, or cancelled (request_cancel closes it)
            return
        conn = readonly.describe_connection()
        run.connection_info = conn
        run.tools = _tools(conn)
        db.commit()
        registry = controls()
        info = RunInfo(id=run.id, code=run.code, period_from=aware(run.period_from), period_to=aware(run.period_to),
                       options=dict((run.scope or {}).get("options") or {}))
        deadline = time.monotonic() + settings.audit_run_max_seconds
        outcomes: dict[str, Outcome] = {}
        stop = None
        for code in run.control_codes:
            db.refresh(run)
            if stop is None and run.cancel_requested: stop = ("CANCELADA", "No se ejecutó: la auditoría fue cancelada por un usuario.")
            if stop is None and _stopping.is_set(): stop = ("INTERRUMPIDA", "No se ejecutó: el servidor se detuvo durante la auditoría.")
            if stop is None and time.monotonic() > deadline:
                stop = ("COMPLETADA_CON_ERRORES", f"No se ejecutó: la auditoría alcanzó su duración máxima ({settings.audit_run_max_seconds} s).")
            ctrl = registry.get(code)
            if stop or ctrl is None:
                out = Outcome("NO_VERIFICADO", stop[1] if stop else "Control no disponible en esta versión de FixIT.")
                moment = now()
                _store_result(db, run, code, ctrl.category if ctrl else "DESCONOCIDA", ctrl.method if ctrl else "ESTATICO", out, moment, moment, None, None)
            else:
                run.current_control = code
                db.commit()
                out, t0, t1 = run_control(ctrl, info, conn.get("resumen") or "")
                _store_result(db, run, code, ctrl.category, ctrl.method, out, t0, t1, _privileges(ctrl, conn.get("resumen") or ""), ctrl.severity)
            outcomes[code] = out
            run.progress_done += 1
            run.heartbeat_at = now()
            db.commit()
        run.current_control = None
        finding_sync.sync(db, run, outcomes, registry)
        status = stop[0] if stop else "COMPLETADA"
        if status == "COMPLETADA" and any(o.status == "ERROR_EJECUCION" for o in outcomes.values()): status = "COMPLETADA_CON_ERRORES"
        _finish(db, run, status, outcomes)
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        log.exception("La auditoría %s no pudo completarse", run_id)
        run = db.get(AuditRun, run_id)
        if run is not None and run.status == "EN_CURSO":
            run.error = safe_error(exc)
            _close_unexecuted(db, run, "No se ejecutó: el motor de auditoría se detuvo por un error interno.")
            _finish(db, run, "INTERRUMPIDA", {})
    finally:
        db.close()


def _close_unexecuted(db: Session, run: AuditRun, reason: str) -> None:
    registry = controls()
    done = {c for (c,) in db.execute(select(AuditResult.control_code).where(AuditResult.run_id == run.id))}
    moment = now()
    for code in run.control_codes:
        if code in done: continue
        ctrl = registry.get(code)
        _store_result(db, run, code, ctrl.category if ctrl else "DESCONOCIDA", ctrl.method if ctrl else "ESTATICO",
                      Outcome("NO_VERIFICADO", reason), moment, moment, None, None)
    db.flush()


def summarize(results: list[AuditResult]) -> tuple[dict, str]:
    by_status: dict[str, int] = {}
    by_category: dict[str, dict[str, int]] = {}
    failed_by_severity: dict[str, int] = {}
    for r in results:
        by_status[r.status] = by_status.get(r.status, 0) + 1
        by_category.setdefault(r.category, {}).setdefault(r.status, 0)
        by_category[r.category][r.status] += 1
        if r.status in ("FALLIDO", "ADVERTENCIA") and r.severity:
            failed_by_severity[r.severity] = failed_by_severity.get(r.severity, 0) + 1
    executed = sum(by_status.get(s, 0) for s in ("APROBADO", "FALLIDO", "ADVERTENCIA"))
    unverified = by_status.get("NO_VERIFICADO", 0) + by_status.get("ERROR_EJECUCION", 0)
    applicable = executed + unverified
    serious_fail = any(r.status == "FALLIDO" and r.severity in ("CRITICO", "ALTO") for r in results)
    if executed == 0: result = "NO_CONCLUYENTE"
    elif serious_fail: result = "DESFAVORABLE"
    elif applicable and unverified / applicable > 0.5: result = "NO_CONCLUYENTE"
    elif by_status.get("FALLIDO") or by_status.get("ADVERTENCIA"): result = "CON_OBSERVACIONES"
    else: result = "FAVORABLE"
    return {"total": len(results), "por_estado": by_status, "por_categoria": by_category, "por_severidad": failed_by_severity,
            "ejecutados": executed, "sin_verificar": unverified}, result


def _canonical(run: AuditRun, results: list[AuditResult]) -> bytes:
    data = {"run": [run.id, run.code, run.status, run.overall_result, iso(run.started_at), iso(run.finished_at)],
            "results": sorted([r.control_code, r.status, r.severity, r.summary, r.method] for r in results)}
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def seal(run: AuditRun, results: list[AuditResult]) -> str:
    return f"{SEAL_VERSION}:{key_id()}:{hmac.new(_key(), _canonical(run, results), hashlib.sha256).hexdigest()}"


def verify_seal(run: AuditRun, results: list[AuditResult]) -> str:
    """VALIDO, ALTERADO, SIN_SELLO or CLAVE_DISTINTA (same meaning as the activity trail)."""
    if not run.results_seal: return "SIN_SELLO"
    parts = run.results_seal.split(":")
    if len(parts) != 3 or parts[0] != SEAL_VERSION: return "ALTERADO"
    if parts[1] != key_id(): return "CLAVE_DISTINTA"
    return "VALIDO" if hmac.compare_digest(run.results_seal, seal(run, results)) else "ALTERADO"


def _finish(db: Session, run: AuditRun, status: str, outcomes: dict[str, Outcome]) -> None:
    db.flush()
    results = db.scalars(select(AuditResult).where(AuditResult.run_id == run.id)).all()
    summary, result = summarize(results)
    imports = [o.details["_informe"] for o in outcomes.values() if isinstance(o.details, dict) and o.details.get("_informe")]
    if imports:
        run.tools = {**(run.tools or {}), "informes_importados": imports}
    limitations = [f"{r.control_code}: {r.summary}" for r in results if r.status in ("NO_VERIFICADO", "ERROR_EJECUCION")]
    run.summary, run.overall_result, run.status = summary, result, status
    run.limitations = limitations[:200]
    run.finished_at = now()
    run.heartbeat_at = run.finished_at
    run.current_control = None
    run.results_seal = seal(run, results)
    audit(db, run.requested_by_id, "AUDITORIA_EJECUTADA", "CENTRO_AUDITORIA", "AUDIT_RUN", run.id,
          new={"codigo": run.code, "estado": status, "resultado": result, "por_estado": summary["por_estado"]})
    db.commit()


def _tools(conn: dict) -> dict:
    def version(name: str) -> str | None:
        try: return metadata.version(name)
        except metadata.PackageNotFoundError: return None
    return {"motor": f"FixIT Audit Engine {ENGINE_VERSION}", "aplicacion": __version__, "python": platform.python_version(),
            "fastapi": version("fastapi"), "sqlalchemy": version("sqlalchemy"), "reportlab": version("reportlab"),
            "base_de_datos": conn.get("version_servidor"), "conexion": conn.get("modo")}


# --- Startup / shutdown ---------------------------------------------------------------------------------------------
def recover_stale(db: Session) -> int:
    """Close EN_CURSO runs whose heartbeat is older than the maximum duration (their process died)."""
    limit = now() - timedelta(seconds=settings.audit_run_max_seconds + 120)
    stale = db.scalars(select(AuditRun).where(AuditRun.status == "EN_CURSO")).all()
    count = 0
    for run in stale:
        beat = aware(run.heartbeat_at or run.started_at or run.created_at)
        if run.id in _queued or (beat and beat > limit): continue
        run.error = "La ejecución no terminó (reinicio o caída del proceso)."
        _close_unexecuted(db, run, "No se ejecutó: la auditoría se interrumpió por un reinicio o caída del servidor.")
        _finish(db, run, "INTERRUMPIDA", {})
        count += 1
    return count


def startup() -> None:
    db = SessionLocal()
    try:
        sync_catalog(db)
        recover_stale(db)
        pending = db.scalars(select(AuditRun.id).where(AuditRun.status == "PENDIENTE").order_by(AuditRun.created_at)).all()
    except Exception:  # noqa: BLE001 - the audit center must never block the application startup
        db.rollback()
        log.exception("No se pudo preparar el Centro de Auditoría")
        return
    finally:
        db.close()
    for run_id in pending:
        submit(run_id)


def shutdown() -> None:
    """Stop after the current control; queued runs stay PENDIENTE in the database and are resumed at the next start."""
    global _executor
    _stopping.set()
    with _lock:
        pool, _executor = _executor, None
        _queued.clear()
    if pool is not None:
        pool.shutdown(wait=False, cancel_futures=True)
