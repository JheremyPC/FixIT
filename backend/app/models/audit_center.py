"""Centro Integral de Auditoría (app.auditing, migration 0006).

These tables hold the results of the audit engine. They are related to, but distinct from, the activity trail
(``audit_logs``): ``audit_logs`` records what users and processes did; these tables record what an audit examined,
what it concluded, the evidence it relied on and what was done about each finding.
"""
from datetime import date, datetime
from sqlalchemy import Boolean, CheckConstraint, Date, DateTime, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base
from app.models.models import User, uid

CONTROL_STATUSES = ("APROBADO", "FALLIDO", "ADVERTENCIA", "NO_APLICABLE", "NO_VERIFICADO", "ERROR_EJECUCION")
SEVERITIES = ("CRITICO", "ALTO", "MEDIO", "BAJO", "INFORMATIVO")
FINDING_STATUSES = ("ABIERTO", "EN_REVISION", "EN_CORRECCION", "CORREGIDO_PENDIENTE_VERIFICACION", "CERRADO", "RIESGO_ACEPTADO",
                    "FALSO_POSITIVO")
RUN_STATUSES = ("PENDIENTE", "EN_CURSO", "COMPLETADA", "COMPLETADA_CON_ERRORES", "CANCELADA", "INTERRUMPIDA")
ACTION_STATUSES = ("PENDIENTE", "EN_CURSO", "COMPLETADA", "DESCARTADA")
EVIDENCE_KINDS = ("MANUAL", "CORRECCION", "IMPORTADA")
REPORT_KINDS = ("EJECUTIVO", "TECNICO", "PAQUETE")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(chr(39) + v + chr(39) for v in values)})"


class AuditControl(Base):
    """Catalog of controls, synchronized from the code registry at startup. ADMIN may disable a control."""
    __tablename__ = "audit_controls"
    code: Mapped[str] = mapped_column(String(40), primary_key=True)
    category: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    objective: Mapped[str] = mapped_column(Text, nullable=False)
    method: Mapped[str] = mapped_column(String(20), nullable=False)
    default_severity: Mapped[str] = mapped_column(String(15), nullable=False)
    criteria: Mapped[list | None] = mapped_column(JSON)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class AuditRun(Base):
    """One execution of the audit engine: scope, period, progress, overall result and a seal over its results."""
    __tablename__ = "audit_runs"
    __table_args__ = (CheckConstraint(_in("status", RUN_STATUSES), name="ck_audit_runs_status"),
                      Index("ix_audit_runs_status_created", "status", "created_at"))
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    code: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    audit_type: Mapped[str] = mapped_column(String(20), nullable=False)
    categories: Mapped[list] = mapped_column(JSON, nullable=False)
    control_codes: Mapped[list] = mapped_column(JSON, nullable=False)
    scope: Mapped[dict | None] = mapped_column(JSON)
    period_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    period_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(25), nullable=False, default="PENDIENTE")
    overall_result: Mapped[str | None] = mapped_column(String(30))
    requested_by_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), index=True)
    parent_run_id: Mapped[str | None] = mapped_column(ForeignKey("audit_runs.id"))
    app_version: Mapped[str] = mapped_column(String(20), nullable=False)
    build: Mapped[str | None] = mapped_column(String(40))
    tools: Mapped[dict | None] = mapped_column(JSON)
    connection_info: Mapped[dict | None] = mapped_column(JSON)
    summary: Mapped[dict | None] = mapped_column(JSON)
    observations: Mapped[str | None] = mapped_column(Text)
    limitations: Mapped[list | None] = mapped_column(JSON)
    progress_done: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    progress_total: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    current_control: Mapped[str | None] = mapped_column(String(40))
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    error: Mapped[str | None] = mapped_column(String(500))
    results_seal: Mapped[str | None] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    requested_by: Mapped[User | None] = relationship()


class AuditResult(Base):
    """Outcome of one control in one run. ``details`` holds the (redacted) evidence the control gathered."""
    __tablename__ = "audit_results"
    __table_args__ = (UniqueConstraint("run_id", "control_code", name="uq_audit_results_run_control"),
                      CheckConstraint(_in("status", CONTROL_STATUSES), name="ck_audit_results_status"))
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    run_id: Mapped[str] = mapped_column(ForeignKey("audit_runs.id"), nullable=False, index=True)
    control_code: Mapped[str] = mapped_column(ForeignKey("audit_controls.code"), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(30), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    method: Mapped[str] = mapped_column(String(20), nullable=False)
    severity: Mapped[str | None] = mapped_column(String(15))
    summary: Mapped[str] = mapped_column(String(500), nullable=False)
    details: Mapped[dict | None] = mapped_column(JSON)
    privileges: Mapped[str | None] = mapped_column(String(300))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    error: Mapped[str | None] = mapped_column(String(500))


class AuditFinding(Base):
    """Central register of findings. ``fingerprint`` (control + resource) deduplicates detections across runs."""
    __tablename__ = "audit_findings"
    __table_args__ = (CheckConstraint(_in("severity", SEVERITIES), name="ck_audit_findings_severity"),
                      CheckConstraint(_in("status", FINDING_STATUSES), name="ck_audit_findings_status"))
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    code: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    control_code: Mapped[str] = mapped_column(ForeignKey("audit_controls.code"), nullable=False, index=True)
    resource: Mapped[str] = mapped_column(String(300), nullable=False)
    severity: Mapped[str] = mapped_column(String(15), nullable=False, index=True)
    impact: Mapped[str] = mapped_column(Text, nullable=False)
    likelihood: Mapped[str] = mapped_column(Text, nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict | None] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="ABIERTO", index=True)
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), index=True)
    due_date: Mapped[date | None] = mapped_column(Date)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    occurrences: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    first_run_id: Mapped[str | None] = mapped_column(ForeignKey("audit_runs.id"))
    last_run_id: Mapped[str | None] = mapped_column(ForeignKey("audit_runs.id"))
    last_verification: Mapped[str | None] = mapped_column(String(20))
    last_verification_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_verification_run_id: Mapped[str | None] = mapped_column(ForeignKey("audit_runs.id"))
    risk_justification: Mapped[str | None] = mapped_column(Text)
    risk_accepted_by_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    risk_review_date: Mapped[date | None] = mapped_column(Date)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    owner: Mapped[User | None] = relationship(foreign_keys=[owner_id])


class AuditFindingEvent(Base):
    """History of a finding (detections, verifications, status changes, assignments, evidence). No endpoint edits it."""
    __tablename__ = "audit_finding_events"
    __table_args__ = (Index("ix_audit_finding_events_finding_created", "finding_id", "created_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    finding_id: Mapped[str] = mapped_column(ForeignKey("audit_findings.id"), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    event: Mapped[str] = mapped_column(String(40), nullable=False)
    from_status: Mapped[str | None] = mapped_column(String(40))
    to_status: Mapped[str | None] = mapped_column(String(40))
    note: Mapped[str | None] = mapped_column(Text)
    data: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor: Mapped[User | None] = relationship()


class AuditActionItem(Base):
    """Action plan task of a finding, assignable to ADMIN, JEFE_TI or TECNICO accounts."""
    __tablename__ = "audit_action_items"
    __table_args__ = (CheckConstraint(_in("status", ACTION_STATUSES), name="ck_audit_action_items_status"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    finding_id: Mapped[str] = mapped_column(ForeignKey("audit_findings.id"), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), index=True)
    due_date: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDIENTE")
    note: Mapped[str | None] = mapped_column(Text)
    created_by_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    owner: Mapped[User | None] = relationship(foreign_keys=[owner_id])


class AuditImport(Base):
    """An imported external file (pgAudit/PostgreSQL logs, Bandit, pip-audit, OWASP ZAP, SARIF). The raw file is not kept:
    only its SHA-256 and either the sanitized records (audit_external_logs) or a summary of the report."""
    __tablename__ = "audit_imports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    kind: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    source_name: Mapped[str] = mapped_column(String(255), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    rows_total: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    rows_imported: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    rows_duplicated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    rows_rejected: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tool: Mapped[dict | None] = mapped_column(JSON)
    summary: Mapped[dict | None] = mapped_column(JSON)
    errors: Mapped[list | None] = mapped_column(JSON)
    notes: Mapped[str | None] = mapped_column(Text)
    imported_by_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    imported_by: Mapped[User | None] = relationship()


class AuditExternalLog(Base):
    """A database activity record imported from an exported log file. ``original`` keeps the received fields (control
    characters escaped, secrets redacted, bind parameters never stored); the other columns are parsed from it."""
    __tablename__ = "audit_external_logs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    import_id: Mapped[str] = mapped_column(ForeignKey("audit_imports.id"), nullable=False, index=True)
    record_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    source: Mapped[str] = mapped_column(String(20), nullable=False)
    log_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    db_user: Mapped[str | None] = mapped_column(String(100))
    database: Mapped[str | None] = mapped_column(String(100))
    session_id: Mapped[str | None] = mapped_column(String(100))
    audit_type: Mapped[str | None] = mapped_column(String(20))
    statement_class: Mapped[str | None] = mapped_column(String(30), index=True)
    command: Mapped[str | None] = mapped_column(String(60))
    object_type: Mapped[str | None] = mapped_column(String(40))
    object_name: Mapped[str | None] = mapped_column(String(200))
    statement: Mapped[str | None] = mapped_column(Text)
    redacted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    original: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AuditEvidence(Base):
    """Evidence added by a person: a manual declaration for a control (optionally with a file) or a correction proof for a
    finding. Files are stored outside the web root and served only through the API, after authorization."""
    __tablename__ = "audit_evidences"
    __table_args__ = (CheckConstraint(_in("kind", EVIDENCE_KINDS), name="ck_audit_evidences_kind"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    control_code: Mapped[str | None] = mapped_column(ForeignKey("audit_controls.code"), index=True)
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("audit_findings.id"), index=True)
    run_id: Mapped[str | None] = mapped_column(ForeignKey("audit_runs.id"))
    import_id: Mapped[str | None] = mapped_column(ForeignKey("audit_imports.id"))
    declared_result: Mapped[str | None] = mapped_column(String(20))
    evidence_date: Mapped[date | None] = mapped_column(Date)
    original_name: Mapped[str | None] = mapped_column(String(255))
    stored_name: Mapped[str | None] = mapped_column(String(255), unique=True)
    content_type: Mapped[str | None] = mapped_column(String(100))
    size: Mapped[int | None] = mapped_column(Integer)
    sha256: Mapped[str | None] = mapped_column(String(64))
    uploaded_by_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    uploaded_by: Mapped[User | None] = relationship()


class AuditReport(Base):
    """Record of every generated report or evidence package (the file itself is regenerated on demand)."""
    __tablename__ = "audit_reports"
    __table_args__ = (CheckConstraint(_in("kind", REPORT_KINDS), name="ck_audit_reports_kind"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    run_id: Mapped[str] = mapped_column(ForeignKey("audit_runs.id"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    filename: Mapped[str] = mapped_column(String(200), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    redacted: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    generated_by_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    audit_log_id: Mapped[str | None] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    generated_by: Mapped[User | None] = relationship()


__all__ = ["AuditControl", "AuditRun", "AuditResult", "AuditFinding", "AuditFindingEvent", "AuditActionItem", "AuditImport",
           "AuditExternalLog", "AuditEvidence", "AuditReport", "CONTROL_STATUSES", "SEVERITIES", "FINDING_STATUSES", "RUN_STATUSES",
           "ACTION_STATUSES", "EVIDENCE_KINDS", "REPORT_KINDS", "AUDIT_CENTER_TABLES"]

AUDIT_CENTER_TABLES = ("audit_controls", "audit_runs", "audit_results", "audit_findings", "audit_finding_events", "audit_action_items",
                       "audit_imports", "audit_external_logs", "audit_evidences", "audit_reports")
