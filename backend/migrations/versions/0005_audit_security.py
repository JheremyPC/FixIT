"""Audit trail hardening, terms acceptance and removal of the temporary demo accounts.

Revision ID: 0005_audit_security
Revises: 0004_agents_observability

Additive and idempotent (objects already created by the app's create_all are skipped):

* ``audit_logs``: new columns ``outcome`` (EXITO/FALLO/DENEGADO, existing rows get EXITO) and ``integrity_hash``
  (per-record HMAC seal written by the application; existing rows stay without seal and are reported as
  SIN_SELLO), plus an index on ``created_at`` for date-range queries and exports.
* ``terms_acceptances``: express acceptances of the terms of use (user, document, version, date).
* Accounts ``*@demo.fixit.example`` left by the removed "Accesos de demostración" feature are deactivated, not
  deleted (their history and audit records are kept). Their sessions stop working because every request checks
  that the user is active. Each deactivation is audited.
* PostgreSQL only: a trigger makes ``audit_logs`` append-only (UPDATE, DELETE and TRUNCATE raise an error), and
  row level security is enabled, without policies, on the FixIT tables owned by the role running the migration,
  so Supabase's REST roles (anon/authenticated) cannot read them. The owner role used by the application is not
  affected by RLS, and tables owned by other roles are left untouched. No ticket, user or audit data is deleted.

Downgrade removes the trigger, the new table, index and columns. It keeps RLS enabled and the demo accounts
deactivated, since reverting either would weaken security.
"""
from alembic import op
import sqlalchemy as sa

revision = "0005_audit_security"
down_revision = "0004_agents_observability"
branch_labels = None
depends_on = None

DEMO_DOMAIN = "demo.fixit.example"
FUNCTION = "fixit_audit_logs_append_only"
RLS_TABLES = ("roles", "users", "areas", "specialties", "technicians", "technician_specialties", "categories", "priorities",
              "ticket_states", "tickets", "ticket_assignments", "ticket_comments", "ticket_attachments", "ticket_history",
              "ratings", "notifications", "audit_logs", "settings", "terms_acceptances", "alembic_version")


def _audit_columns(bind) -> None:
    columns = {c["name"] for c in sa.inspect(bind).get_columns("audit_logs")}
    if "outcome" not in columns:
        op.add_column("audit_logs", sa.Column("outcome", sa.String(20), nullable=False, server_default="EXITO"))
    if "integrity_hash" not in columns:
        op.add_column("audit_logs", sa.Column("integrity_hash", sa.String(100)))
    if "ix_audit_logs_created_at" not in {i["name"] for i in sa.inspect(bind).get_indexes("audit_logs")}:
        op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])


def _terms_table(bind) -> None:
    if sa.inspect(bind).has_table("terms_acceptances"):
        return
    op.create_table(
        "terms_acceptances",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False, index=True),
        sa.Column("document", sa.String(30), nullable=False),
        sa.Column("version", sa.String(30), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ip", sa.String(64)),
        sa.Column("user_agent", sa.String(500)),
        sa.UniqueConstraint("user_id", "document", "version", name="uq_terms_acceptance"),
    )


def _deactivate_demo_accounts(bind) -> None:
    from app.services.audit import sealed_fields  # same seal as the application

    users = sa.table("users", sa.column("id", sa.String), sa.column("email", sa.String), sa.column("active", sa.Boolean))
    audit_logs = sa.table("audit_logs", *[sa.column(c, sa.String) for c in ("id", "user_id", "action", "module", "entity", "entity_id",
                                                                            "ip", "user_agent", "outcome", "integrity_hash")],
                          sa.column("old_value", sa.JSON), sa.column("new_value", sa.JSON), sa.column("created_at", sa.DateTime(timezone=True)))
    rows = bind.execute(sa.select(users.c.id, users.c.email)
                        .where(sa.func.lower(users.c.email).like(f"%@{DEMO_DOMAIN}"), users.c.active.is_(True))).all()
    for user_id, email in rows:
        bind.execute(users.update().where(users.c.id == user_id).values(active=False))
        bind.execute(audit_logs.insert().values(**sealed_fields(
            None, "DESACTIVAR_CUENTA_DEMO", "AUTH", "USER", user_id, old={"active": True}, new={"active": False, "email": email,
            "motivo": "Retiro del módulo temporal de accesos de demostración"}, ip="MIGRACION", user_agent="alembic 0005_audit_security")))


def _postgres_protections(bind) -> None:
    op.execute(sa.text(f"""
        CREATE OR REPLACE FUNCTION {FUNCTION}() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'audit_logs es de solo inserción: % no permitido', TG_OP USING ERRCODE = 'insufficient_privilege';
        END
        $$"""))
    op.execute(sa.text("DROP TRIGGER IF EXISTS audit_logs_append_only ON audit_logs"))
    op.execute(sa.text("DROP TRIGGER IF EXISTS audit_logs_no_truncate ON audit_logs"))
    op.execute(sa.text(f"CREATE TRIGGER audit_logs_append_only BEFORE UPDATE OR DELETE ON audit_logs "
                       f"FOR EACH ROW EXECUTE FUNCTION {FUNCTION}()"))
    op.execute(sa.text(f"CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs "
                       f"FOR EACH STATEMENT EXECUTE FUNCTION {FUNCTION}()"))
    # Only tables this role owns (directly or through role membership): RLS never applies to their owner, so the
    # application keeps full access. Tables owned by someone else are skipped rather than risking lock-out.
    owned = bind.execute(sa.text("""
        SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema() AND c.relkind = 'r' AND c.relname = ANY(:names)
          AND NOT c.relrowsecurity AND pg_has_role(current_user, c.relowner, 'MEMBER')"""), {"names": list(RLS_TABLES)}).scalars().all()
    for name in owned:
        op.execute(sa.text(f'ALTER TABLE "{name}" ENABLE ROW LEVEL SECURITY'))


def upgrade():
    bind = op.get_bind()
    _audit_columns(bind)
    _terms_table(bind)
    _deactivate_demo_accounts(bind)
    if bind.dialect.name == "postgresql":
        _postgres_protections(bind)


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("DROP TRIGGER IF EXISTS audit_logs_append_only ON audit_logs"))
        op.execute(sa.text("DROP TRIGGER IF EXISTS audit_logs_no_truncate ON audit_logs"))
        op.execute(sa.text(f"DROP FUNCTION IF EXISTS {FUNCTION}()"))
    op.drop_table("terms_acceptances")
    op.drop_index("ix_audit_logs_created_at", table_name="audit_logs")
    with op.batch_alter_table("audit_logs") as batch:
        batch.drop_column("integrity_hash")
        batch.drop_column("outcome")
