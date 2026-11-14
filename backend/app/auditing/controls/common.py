"""Helpers shared by the controls."""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from sqlalchemy import select

from app.auditing.redaction import mask_email
from app.auditing.registry import Ctx, FindingSpec, NotVerifiable, Outcome
from app.core.database import Base
from app.models import AuditEvidence, AuditImport, AuditControl

UTC = timezone.utc
LIMA = timezone(timedelta(hours=-5), "America/Lima")  # Peru has no daylight saving time


def finding(resource: str, title: str, description: str, impact: str, likelihood: str, recommendation: str, severity: str | None = None,
            evidence: dict | None = None) -> FindingSpec:
    return FindingSpec(resource=resource, title=title, description=description, impact=impact, likelihood=likelihood,
                       recommendation=recommendation, severity=severity, evidence=evidence)


def app_tables() -> set[str]:
    """Tables declared by the FixIT models (the application's own schema)."""
    import app.models  # noqa: F401 - registers every model
    return set(Base.metadata.tables)


def aware(moment: datetime | None) -> datetime | None:
    if moment is None: return None
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)


def iso(moment: datetime | None) -> str | None:
    moment = aware(moment)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ") if moment else None


def pct(part: int | float, whole: int | float, digits: int = 1) -> float | None:
    return round(100 * part / whole, digits) if whole else None


def user_ref(user_id: str | None, email: str | None, role: str | None = None) -> str:
    """How a user appears in evidence: masked e-mail, role and the first characters of the id."""
    if not user_id: return "Sistema"
    return f"{mask_email(email) or 'sin correo'} ({role or 'rol desconocido'}, id {user_id[:8]})"


def period_text(ctx: Ctx) -> str:
    start, end = ctx.period()
    return f"{start.date().isoformat()} a {end.date().isoformat()} (UTC)"


def sample(values, limit: int = 15) -> list:
    return list(values)[:limit]


def latest_import(ctx: Ctx, kind: str) -> AuditImport | None:
    return ctx.session.scalars(select(AuditImport).where(AuditImport.kind == kind, AuditImport.status.in_(("COMPLETADA", "PARCIAL")))
                               .order_by(AuditImport.imported_at.desc()).limit(1)).first()


def import_ref(row: AuditImport) -> dict:
    return {"id": row.id, "tipo": row.kind, "archivo": row.source_name, "sha256": row.sha256, "importado_en": iso(row.imported_at),
            "herramienta": (row.tool or {}).get("name"), "version": (row.tool or {}).get("version")}


def from_import(ctx: Ctx, kind: str, label: str, how: str, max_age_days: int = 30) -> tuple[AuditImport, dict, list[str]]:
    """The latest imported report of ``kind`` or NotVerifiable; returns (row, reference, notes)."""
    row = latest_import(ctx, kind)
    if row is None:
        raise NotVerifiable(f"No hay ningún informe de {label} importado. {how}")
    notes = []
    age = (ctx.now - aware(row.imported_at)).days
    if age > max_age_days:
        notes.append(f"El último informe se importó hace {age} días (más de {max_age_days}); puede no reflejar el estado actual.")
    return row, import_ref(row), notes


def manual(ctx: Ctx, code: str | None = None) -> Outcome:
    """Result of a control that depends on evidence provided by people (provider panels, institutional documents).
    The latest MANUAL evidence for the control decides; without it, or if it is older than the control allows, the control
    is NO_VERIFICADO. The outcome is always marked as method MANUAL and names the evidence it relies on."""
    ctrl = ctx.control
    code = code or ctrl.code
    row = ctx.session.scalars(select(AuditEvidence).where(AuditEvidence.control_code == code, AuditEvidence.kind == "MANUAL",
                                                          AuditEvidence.declared_result.is_not(None))
                              .order_by(AuditEvidence.created_at.desc()).limit(1)).first()
    guidance = ctrl.guidance or "Adjunte la evidencia correspondiente desde el Centro de Auditoría."
    if row is None:
        raise NotVerifiable(f"Sin evidencia registrada. {guidance}")
    reference = row.evidence_date or aware(row.created_at).date()
    age = (ctx.now.date() - reference).days
    details = {"evidencia": {"id": row.id, "titulo": row.title, "fecha_evidencia": reference.isoformat(), "resultado_declarado": row.declared_result,
                             "archivo": row.original_name, "sha256": row.sha256, "registrada_en": iso(row.created_at),
                             "registrada_por": user_ref(row.uploaded_by_id, row.uploaded_by.email if row.uploaded_by else None,
                                                        row.uploaded_by.role.code if row.uploaded_by else None)},
               "naturaleza": "Declaración manual respaldada por evidencia; FixIT no puede comprobarla técnicamente."}
    if ctrl.evidence_days and age > ctrl.evidence_days:
        raise NotVerifiable(f"La última evidencia es del {reference.isoformat()} ({age} días); este control exige una de los últimos "
                            f"{ctrl.evidence_days} días. {guidance}")
    status = row.declared_result
    summary = f"Según evidencia manual del {reference.isoformat()}: {row.title}"
    out_findings = []
    if status in ("FALLIDO", "ADVERTENCIA"):
        out_findings.append(finding(f"evidencia:{code}", ctrl.title, f"La evidencia manual «{row.title}» declara el resultado {status}.",
                                    "Depende del control; ver su objetivo.", "Declarado por el responsable que registró la evidencia.",
                                    guidance, evidence=details["evidencia"]))
    return Outcome(status, summary, details, out_findings, method="MANUAL")


def control_enabled(ctx: Ctx, code: str) -> bool:
    row = ctx.session.get(AuditControl, code)
    return bool(row and row.enabled)


def day_range(start: datetime, end: datetime) -> list[date]:
    days, current = [], start.date()
    while current <= end.date() and len(days) < 400:
        days.append(current)
        current += timedelta(days=1)
    return days
