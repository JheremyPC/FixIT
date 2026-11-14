"""Centro Integral de Auditoría.

Revision ID: 0006_audit_center
Revises: 0005_audit_security

Additive and idempotent: creates the ten tables of the audit center (controls catalog, runs, results, findings and their
history, action plans, evidence, imports, imported database logs and generated reports). Tables that already exist (created
by the app's create_all) are skipped. Existing tables and data, including ``audit_logs`` and its HMAC seals, are not touched.

PostgreSQL: row level security is enabled, without policies, on the new tables owned by the role running the migration, so
Supabase's REST roles (anon/authenticated) cannot read or write them; the owner role used by the application is not affected.

Downgrade drops only these ten tables (intended for test databases; never run it in production: it deletes audit results).
"""
from alembic import op
import sqlalchemy as sa

revision = "0006_audit_center"
down_revision = "0005_audit_security"
branch_labels = None
depends_on = None

TABLES = ("audit_controls", "audit_runs", "audit_results", "audit_findings", "audit_finding_events", "audit_action_items", "audit_imports",
          "audit_external_logs", "audit_evidences", "audit_reports")
CONTROL_STATUSES = ("APROBADO", "FALLIDO", "ADVERTENCIA", "NO_APLICABLE", "NO_VERIFICADO", "ERROR_EJECUCION")
SEVERITIES = ("CRITICO", "ALTO", "MEDIO", "BAJO", "INFORMATIVO")
FINDING_STATUSES = ("ABIERTO", "EN_REVISION", "EN_CORRECCION", "CORREGIDO_PENDIENTE_VERIFICACION", "CERRADO", "RIESGO_ACEPTADO", "FALSO_POSITIVO")
RUN_STATUSES = ("PENDIENTE", "EN_CURSO", "COMPLETADA", "COMPLETADA_CON_ERRORES", "CANCELADA", "INTERRUMPIDA")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(chr(39) + v + chr(39) for v in values)})"


def _tables():
    tz = sa.DateTime(timezone=True)
    users = lambda name: sa.Column(name, sa.String(36), sa.ForeignKey("users.id"))  # noqa: E731
    return {
        "audit_controls": [
            sa.Column("code", sa.String(40), primary_key=True),
            sa.Column("category", sa.String(30), nullable=False, index=True),
            sa.Column("title", sa.String(200), nullable=False),
            sa.Column("objective", sa.Text(), nullable=False),
            sa.Column("method", sa.String(20), nullable=False),
            sa.Column("default_severity", sa.String(15), nullable=False),
            sa.Column("criteria", sa.JSON()),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("updated_at", tz, nullable=False, server_default=sa.func.now()),
        ],
        "audit_runs": [
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("code", sa.String(30), nullable=False, unique=True),
            sa.Column("name", sa.String(150), nullable=False),
            sa.Column("audit_type", sa.String(20), nullable=False),
            sa.Column("categories", sa.JSON(), nullable=False),
            sa.Column("control_codes", sa.JSON(), nullable=False),
            sa.Column("scope", sa.JSON()),
            sa.Column("period_from", tz),
            sa.Column("period_to", tz),
            sa.Column("status", sa.String(25), nullable=False),
            sa.Column("overall_result", sa.String(30)),
            sa.Column("requested_by_id", sa.String(36), sa.ForeignKey("users.id"), index=True),
            sa.Column("parent_run_id", sa.String(36), sa.ForeignKey("audit_runs.id")),
            sa.Column("app_version", sa.String(20), nullable=False),
            sa.Column("build", sa.String(40)),
            sa.Column("tools", sa.JSON()),
            sa.Column("connection_info", sa.JSON()),
            sa.Column("summary", sa.JSON()),
            sa.Column("observations", sa.Text()),
            sa.Column("limitations", sa.JSON()),
            sa.Column("progress_done", sa.Integer(), nullable=False),
            sa.Column("progress_total", sa.Integer(), nullable=False),
            sa.Column("current_control", sa.String(40)),
            sa.Column("cancel_requested", sa.Boolean(), nullable=False),
            sa.Column("error", sa.String(500)),
            sa.Column("results_seal", sa.String(120)),
            sa.Column("created_at", tz, nullable=False),
            sa.Column("started_at", tz),
            sa.Column("finished_at", tz),
            sa.Column("heartbeat_at", tz),
            sa.CheckConstraint(_in("status", RUN_STATUSES), name="ck_audit_runs_status"),
            sa.Index("ix_audit_runs_status_created", "status", "created_at"),
        ],
        "audit_results": [
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("run_id", sa.String(36), sa.ForeignKey("audit_runs.id"), nullable=False, index=True),
            sa.Column("control_code", sa.String(40), sa.ForeignKey("audit_controls.code"), nullable=False, index=True),
            sa.Column("category", sa.String(30), nullable=False),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("method", sa.String(20), nullable=False),
            sa.Column("severity", sa.String(15)),
            sa.Column("summary", sa.String(500), nullable=False),
            sa.Column("details", sa.JSON()),
            sa.Column("privileges", sa.String(300)),
            sa.Column("started_at", tz, nullable=False),
            sa.Column("finished_at", tz, nullable=False),
            sa.Column("duration_ms", sa.Integer(), nullable=False),
            sa.Column("error", sa.String(500)),
            sa.UniqueConstraint("run_id", "control_code", name="uq_audit_results_run_control"),
            sa.CheckConstraint(_in("status", CONTROL_STATUSES), name="ck_audit_results_status"),
        ],
        "audit_findings": [
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("code", sa.String(20), nullable=False, unique=True),
            sa.Column("fingerprint", sa.String(64), nullable=False, unique=True),
            sa.Column("title", sa.String(200), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("category", sa.String(30), nullable=False, index=True),
            sa.Column("control_code", sa.String(40), sa.ForeignKey("audit_controls.code"), nullable=False, index=True),
            sa.Column("resource", sa.String(300), nullable=False),
            sa.Column("severity", sa.String(15), nullable=False, index=True),
            sa.Column("impact", sa.Text(), nullable=False),
            sa.Column("likelihood", sa.Text(), nullable=False),
            sa.Column("recommendation", sa.Text(), nullable=False),
            sa.Column("evidence", sa.JSON()),
            sa.Column("status", sa.String(40), nullable=False, index=True),
            sa.Column("owner_id", sa.String(36), sa.ForeignKey("users.id"), index=True),
            sa.Column("due_date", sa.Date()),
            sa.Column("detected_at", tz, nullable=False),
            sa.Column("last_seen_at", tz, nullable=False),
            sa.Column("occurrences", sa.Integer(), nullable=False),
            sa.Column("first_run_id", sa.String(36), sa.ForeignKey("audit_runs.id")),
            sa.Column("last_run_id", sa.String(36), sa.ForeignKey("audit_runs.id")),
            sa.Column("last_verification", sa.String(20)),
            sa.Column("last_verification_at", tz),
            sa.Column("last_verification_run_id", sa.String(36), sa.ForeignKey("audit_runs.id")),
            sa.Column("risk_justification", sa.Text()),
            users("risk_accepted_by_id"),
            sa.Column("risk_review_date", sa.Date()),
            sa.Column("created_at", tz, nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", tz, nullable=False, server_default=sa.func.now()),
            sa.CheckConstraint(_in("severity", SEVERITIES), name="ck_audit_findings_severity"),
            sa.CheckConstraint(_in("status", FINDING_STATUSES), name="ck_audit_findings_status"),
        ],
        "audit_finding_events": [
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("finding_id", sa.String(36), sa.ForeignKey("audit_findings.id"), nullable=False),
            users("actor_id"),
            sa.Column("event", sa.String(40), nullable=False),
            sa.Column("from_status", sa.String(40)),
            sa.Column("to_status", sa.String(40)),
            sa.Column("note", sa.Text()),
            sa.Column("data", sa.JSON()),
            sa.Column("created_at", tz, nullable=False),
            sa.Index("ix_audit_finding_events_finding_created", "finding_id", "created_at"),
        ],
        "audit_action_items": [
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("finding_id", sa.String(36), sa.ForeignKey("audit_findings.id"), nullable=False, index=True),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("owner_id", sa.String(36), sa.ForeignKey("users.id"), index=True),
            sa.Column("due_date", sa.Date()),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("note", sa.Text()),
            users("created_by_id"),
            sa.Column("created_at", tz, nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", tz, nullable=False, server_default=sa.func.now()),
            sa.Column("completed_at", tz),
            sa.CheckConstraint(_in("status", ("PENDIENTE", "EN_CURSO", "COMPLETADA", "DESCARTADA")), name="ck_audit_action_items_status"),
        ],
        "audit_imports": [
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("kind", sa.String(30), nullable=False, index=True),
            sa.Column("source_name", sa.String(255), nullable=False),
            sa.Column("sha256", sa.String(64), nullable=False, index=True),
            sa.Column("size", sa.Integer(), nullable=False),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("rows_total", sa.Integer(), nullable=False),
            sa.Column("rows_imported", sa.Integer(), nullable=False),
            sa.Column("rows_duplicated", sa.Integer(), nullable=False),
            sa.Column("rows_rejected", sa.Integer(), nullable=False),
            sa.Column("tool", sa.JSON()),
            sa.Column("summary", sa.JSON()),
            sa.Column("errors", sa.JSON()),
            sa.Column("notes", sa.Text()),
            users("imported_by_id"),
            sa.Column("imported_at", tz, nullable=False),
        ],
        "audit_external_logs": [
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("import_id", sa.String(36), sa.ForeignKey("audit_imports.id"), nullable=False, index=True),
            sa.Column("record_hash", sa.String(64), nullable=False, unique=True),
            sa.Column("source", sa.String(20), nullable=False),
            sa.Column("log_time", tz, index=True),
            sa.Column("db_user", sa.String(100)),
            sa.Column("database", sa.String(100)),
            sa.Column("session_id", sa.String(100)),
            sa.Column("audit_type", sa.String(20)),
            sa.Column("statement_class", sa.String(30), index=True),
            sa.Column("command", sa.String(60)),
            sa.Column("object_type", sa.String(40)),
            sa.Column("object_name", sa.String(200)),
            sa.Column("statement", sa.Text()),
            sa.Column("redacted", sa.Boolean(), nullable=False),
            sa.Column("original", sa.JSON()),
            sa.Column("created_at", tz, nullable=False, server_default=sa.func.now()),
        ],
        "audit_evidences": [
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("kind", sa.String(20), nullable=False),
            sa.Column("title", sa.String(200), nullable=False),
            sa.Column("description", sa.Text()),
            sa.Column("control_code", sa.String(40), sa.ForeignKey("audit_controls.code"), index=True),
            sa.Column("finding_id", sa.String(36), sa.ForeignKey("audit_findings.id"), index=True),
            sa.Column("run_id", sa.String(36), sa.ForeignKey("audit_runs.id")),
            sa.Column("import_id", sa.String(36), sa.ForeignKey("audit_imports.id")),
            sa.Column("declared_result", sa.String(20)),
            sa.Column("evidence_date", sa.Date()),
            sa.Column("original_name", sa.String(255)),
            sa.Column("stored_name", sa.String(255), unique=True),
            sa.Column("content_type", sa.String(100)),
            sa.Column("size", sa.Integer()),
            sa.Column("sha256", sa.String(64)),
            users("uploaded_by_id"),
            sa.Column("created_at", tz, nullable=False),
            sa.CheckConstraint(_in("kind", ("MANUAL", "CORRECCION", "IMPORTADA")), name="ck_audit_evidences_kind"),
        ],
        "audit_reports": [
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("run_id", sa.String(36), sa.ForeignKey("audit_runs.id"), nullable=False, index=True),
            sa.Column("kind", sa.String(20), nullable=False),
            sa.Column("filename", sa.String(200), nullable=False),
            sa.Column("sha256", sa.String(64), nullable=False),
            sa.Column("size", sa.Integer(), nullable=False),
            sa.Column("redacted", sa.Boolean(), nullable=False),
            users("generated_by_id"),
            sa.Column("audit_log_id", sa.String(36)),
            sa.Column("created_at", tz, nullable=False),
            sa.CheckConstraint(_in("kind", ("EJECUTIVO", "TECNICO", "PAQUETE")), name="ck_audit_reports_kind"),
        ],
    }


def upgrade():
    bind = op.get_bind()
    existing = sa.inspect(bind)
    for name, columns in _tables().items():
        if not existing.has_table(name):
            op.create_table(name, *columns)
    if bind.dialect.name == "postgresql":
        owned = bind.execute(sa.text("""
            SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = current_schema() AND c.relkind = 'r' AND c.relname = ANY(:names)
              AND NOT c.relrowsecurity AND pg_has_role(current_user, c.relowner, 'MEMBER')"""), {"names": list(TABLES)}).scalars().all()
        for name in owned:
            op.execute(sa.text(f'ALTER TABLE "{name}" ENABLE ROW LEVEL SECURITY'))


def downgrade():
    for name in reversed(TABLES):
        op.drop_table(name)
