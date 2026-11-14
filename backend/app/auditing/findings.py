"""Findings: deduplicated creation from run results, re-verification and the manual life cycle.

* Deduplication: a finding is identified by ``fingerprint = sha256(control code | affected resource)``. A detection that
  already exists updates ``last_seen_at``, ``occurrences`` and the evidence instead of creating a new finding.
* Re-verification: every run that executes a control checks the findings of that control. Not detected again with a
  conclusive result -> ``last_verification = NO_REPRODUCIDO``; detected again -> REPRODUCIDO (a finding marked as corrected
  goes back to EN_CORRECCION, a closed one is reopened); control not verifiable -> NO_CONCLUYENTE.
* Nothing is ever closed automatically. Closing requires correction evidence and a verification NO_REPRODUCIDO obtained
  after the finding was marked as corrected. Accepting a risk requires ADMIN/JEFE_TI, a justification and a review date.
* History (``audit_finding_events``) is append-only from the application; corrected findings are kept.
"""
from __future__ import annotations

import hashlib
from datetime import date, datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auditing.catalog import FINDING_LABELS, SEVERITY_ORDER, TECHNICIAN_TRANSITIONS, TRANSITIONS
from app.auditing.redaction import redact_details, secret_free
from app.auditing.registry import Control, Outcome
from app.models import AuditEvidence, AuditFinding, AuditFindingEvent, AuditRun, User

UTC = timezone.utc
CONCLUSIVE = ("APROBADO", "FALLIDO", "ADVERTENCIA")
MANAGERS = ("ADMIN", "JEFE_TI")


def now() -> datetime:
    return datetime.now(UTC)


def fingerprint(control_code: str, resource: str) -> str:
    return hashlib.sha256(f"{control_code}|{resource.strip().lower()}".encode()).hexdigest()


def event(db: Session, finding: AuditFinding, actor: User | None, kind: str, note: str | None = None, from_status: str | None = None,
          to_status: str | None = None, data: dict | None = None) -> AuditFindingEvent:
    row = AuditFindingEvent(finding_id=finding.id, actor_id=actor.id if actor else None, event=kind, from_status=from_status,
                            to_status=to_status, note=secret_free(note, 4000) if note else None, data=redact_details(data) if data else None,
                            created_at=now())
    db.add(row)
    return row


def _next_code(db: Session) -> str:
    last = db.scalar(select(func.max(AuditFinding.code)).where(AuditFinding.code.like("HAL-%")))
    return f"HAL-{(int(last.split('-')[1]) + 1) if last else 1:05d}"


def sync(db: Session, run: AuditRun, outcomes: dict[str, Outcome], registry: dict[str, Control]) -> dict:
    from app.auditing.engine import effective_severity

    moment = now()
    produced: dict[str, tuple] = {}
    for code, out in outcomes.items():
        ctrl = registry.get(code)
        if ctrl is None or out.status not in ("FALLIDO", "ADVERTENCIA"): continue
        for spec in out.findings:
            severity = spec.severity or effective_severity(out, ctrl.severity) or ctrl.severity
            produced[fingerprint(code, spec.resource)] = (code, ctrl, spec, severity)
    existing = {f.fingerprint: f for f in db.scalars(select(AuditFinding).where(AuditFinding.control_code.in_(list(outcomes))))}
    stats = {"nuevos": 0, "reproducidos": 0, "no_reproducidos": 0, "reabiertos": 0}
    for fp, (code, ctrl, spec, severity) in produced.items():
        finding = existing.get(fp)
        evidence = redact_details(spec.evidence) if spec.evidence else None
        if finding is None:
            for _ in range(3):
                finding = AuditFinding(code=_next_code(db), fingerprint=fp, title=secret_free(spec.title, 200), description=secret_free(spec.description),
                                       category=ctrl.category, control_code=code, resource=secret_free(spec.resource, 300), severity=severity,
                                       impact=spec.impact, likelihood=spec.likelihood, recommendation=spec.recommendation, evidence=evidence,
                                       status="ABIERTO", detected_at=moment, last_seen_at=moment, occurrences=1, first_run_id=run.id,
                                       last_run_id=run.id)
                if db.get_bind().dialect.name != "postgresql":  # single local process: no concurrent writer of codes
                    db.add(finding)
                    db.flush()
                    break
                try:  # another instance may take the same code at the same moment: retry inside a savepoint
                    with db.begin_nested():
                        db.add(finding)
                        db.flush()
                    break
                except IntegrityError:
                    pass
            event(db, finding, None, "DETECTADO", f"Detectado en {run.code}.", None, "ABIERTO", {"run": run.code, "control": code})
            stats["nuevos"] += 1
            continue
        stats["reproducidos"] += 1
        finding.last_seen_at, finding.last_run_id = moment, run.id
        finding.occurrences += 1
        finding.evidence = evidence or finding.evidence
        finding.last_verification, finding.last_verification_at, finding.last_verification_run_id = "REPRODUCIDO", moment, run.id
        if SEVERITY_ORDER[severity] < SEVERITY_ORDER[finding.severity]:
            event(db, finding, None, "SEVERIDAD_ACTUALIZADA", f"La nueva detección en {run.code} tiene mayor severidad.",
                  data={"anterior": finding.severity, "nueva": severity})
            finding.severity = severity
        if finding.status == "CORREGIDO_PENDIENTE_VERIFICACION":
            event(db, finding, None, "VERIFICACION_FALLIDA", f"El hallazgo se reprodujo en {run.code}; vuelve a corrección.",
                  finding.status, "EN_CORRECCION", {"run": run.code})
            finding.status = "EN_CORRECCION"
        elif finding.status == "CERRADO":
            event(db, finding, None, "REAPARECIDO", f"El hallazgo cerrado volvió a detectarse en {run.code}.", "CERRADO", "ABIERTO",
                  {"run": run.code})
            finding.status = "ABIERTO"
            stats["reabiertos"] += 1
    for fp, finding in existing.items():
        if fp in produced: continue
        out = outcomes.get(finding.control_code)
        if out is None: continue
        verdict = "NO_REPRODUCIDO" if out.status in CONCLUSIVE else "NO_CONCLUYENTE"
        previous = finding.last_verification
        finding.last_verification, finding.last_verification_at, finding.last_verification_run_id = verdict, moment, run.id
        if verdict == "NO_REPRODUCIDO": stats["no_reproducidos"] += 1
        if finding.status == "CORREGIDO_PENDIENTE_VERIFICACION" or (verdict != previous and finding.status not in ("CERRADO", "FALSO_POSITIVO")):
            text = (f"No se reprodujo en {run.code} (resultado del control: {out.status})." if verdict == "NO_REPRODUCIDO"
                    else f"Verificación no concluyente en {run.code}: el control quedó {out.status}.")
            event(db, finding, None, "VERIFICACION", text, data={"run": run.code, "resultado": verdict})
    db.flush()
    return stats


# --- Manual life cycle ------------------------------------------------------------------------------------------------
def _has_correction_evidence(db: Session, finding: AuditFinding) -> bool:
    return bool(db.scalar(select(func.count(AuditEvidence.id)).where(AuditEvidence.finding_id == finding.id,
                                                                     AuditEvidence.kind == "CORRECCION")))


def _marked_corrected_at(db: Session, finding: AuditFinding) -> datetime | None:
    moment = db.scalar(select(func.max(AuditFindingEvent.created_at)).where(
        AuditFindingEvent.finding_id == finding.id, AuditFindingEvent.to_status == "CORREGIDO_PENDIENTE_VERIFICACION"))
    return moment.replace(tzinfo=UTC) if moment is not None and moment.tzinfo is None else moment


def change_status(db: Session, finding: AuditFinding, actor: User, target: str, note: str, justification: str | None = None,
                  review_date: date | None = None) -> None:
    role = actor.role.code
    current = finding.status
    if target == current: raise HTTPException(422, "El hallazgo ya tiene ese estado")
    if target not in TRANSITIONS.get(current, set()):
        raise HTTPException(422, f"Transición no permitida: {FINDING_LABELS[current]} → {FINDING_LABELS.get(target, target)}")
    if role == "TECNICO":
        if finding.owner_id != actor.id or (current, target) not in TECHNICIAN_TRANSITIONS:
            raise HTTPException(403, "Solo puede pasar a corrección o marcar como corregidos los hallazgos asignados a usted")
    elif role not in MANAGERS:
        raise HTTPException(403, "Rol sin autorización")
    note = (note or "").strip()
    if len(note) < 5: raise HTTPException(422, "Describa el motivo del cambio (mínimo 5 caracteres)")
    data = {}
    if target in ("RIESGO_ACEPTADO", "FALSO_POSITIVO"):
        justification = (justification or "").strip()
        if len(justification) < 20: raise HTTPException(422, "La justificación debe tener al menos 20 caracteres")
        data["justificacion"] = justification
    if target == "RIESGO_ACEPTADO":
        today = now().date()
        if review_date is None or review_date <= today or review_date > today + timedelta(days=366):
            raise HTTPException(422, "Indique una fecha de revisión futura, como máximo dentro de un año")
        finding.risk_justification, finding.risk_accepted_by_id, finding.risk_review_date = justification, actor.id, review_date
        data["revision"] = review_date.isoformat()
    if target == "CORREGIDO_PENDIENTE_VERIFICACION" and not _has_correction_evidence(db, finding):
        raise HTTPException(422, "Adjunte primero una evidencia de corrección")
    if target == "CERRADO":
        if not _has_correction_evidence(db, finding): raise HTTPException(422, "No hay evidencia de corrección adjunta")
        marked = _marked_corrected_at(db, finding)
        verified = finding.last_verification_at.replace(tzinfo=UTC) if finding.last_verification_at and finding.last_verification_at.tzinfo is None \
            else finding.last_verification_at
        if finding.last_verification != "NO_REPRODUCIDO" or not verified or not marked or verified <= marked:
            raise HTTPException(422, "Para cerrar el hallazgo, ejecute la verificación: una nueva ejecución del control debe "
                                     "confirmar que ya no se reproduce después de marcarlo como corregido")
        data["verificacion"] = {"resultado": finding.last_verification, "ejecucion_id": finding.last_verification_run_id}
    if current == "RIESGO_ACEPTADO":
        data["riesgo_aceptado_anterior"] = {"justificacion": finding.risk_justification,
                                           "revision": finding.risk_review_date.isoformat() if finding.risk_review_date else None}
    event(db, finding, actor, "CAMBIO_ESTADO", note, current, target, data or None)
    finding.status = target
