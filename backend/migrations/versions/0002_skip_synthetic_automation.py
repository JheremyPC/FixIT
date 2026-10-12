"""Synthetic demo imports do not enqueue automation events.

Revision ID: 0002_skip_synthetic_automation
Revises: 0001_initial

Supabase has ``fixit_enqueue_automation_event()`` (created outside Alembic) fired AFTER INSERT on
tickets, ticket_assignments, ticket_comments and ratings. This revision adds a guard at the top of
that function: rows are skipped only when BOTH hold

* the transaction-local setting ``fixit.synthetic_import`` is ``on`` (the synthetic importer sets it
  with ``set_config(..., true)``, so it ends with the import transaction and never reaches other
  sessions or pooled connections), and
* the row belongs to a ``SYN-`` ticket.

Every other row (real tickets created by users, the API, the worker) behaves exactly as before.
Databases without the function (SQLite, local PostgreSQL created by Alembic) are left untouched.
The upgrade refuses to overwrite a function whose body is not the known original, so manual
changes made in Supabase are never lost silently; the downgrade restores the original body.
"""
from alembic import op
import sqlalchemy as sa

revision = "0002_skip_synthetic_automation"
down_revision = "0001_initial"
branch_labels = None
depends_on = None

FUNCTION = "fixit_enqueue_automation_event"
SKIP_SETTING = "fixit.synthetic_import"

# Body as deployed in Supabase on 2026-10-12 (pg_get_functiondef), unchanged.
ORIGINAL_BODY = """
DECLARE
    payload_new JSONB := to_jsonb(NEW);
    payload_old JSONB := CASE WHEN TG_OP = 'UPDATE' THEN to_jsonb(OLD) ELSE NULL END;
    event_name VARCHAR(80);
BEGIN
    IF TG_TABLE_NAME = 'tickets' AND TG_OP = 'INSERT' THEN
        event_name := 'TICKET_CREADO';
    ELSIF TG_TABLE_NAME = 'tickets' AND TG_OP = 'UPDATE' THEN
        event_name := 'TICKET_ACTUALIZADO';
    ELSIF TG_TABLE_NAME = 'ticket_assignments' AND TG_OP = 'INSERT' THEN
        event_name := 'TICKET_ASIGNADO';
    ELSIF TG_TABLE_NAME = 'ratings' AND TG_OP = 'INSERT' THEN
        event_name := 'TICKET_CALIFICADO';
    ELSIF TG_TABLE_NAME = 'ticket_comments' AND TG_OP = 'INSERT' THEN
        event_name := 'TICKET_COMENTADO';
    ELSE
        RETURN NEW;
    END IF;

    INSERT INTO automation_events(
        event_type,
        source_table,
        aggregate_id,
        payload
    )
    VALUES (
        event_name,
        TG_TABLE_NAME,
        CASE
            WHEN payload_new ? 'ticket_id'
                THEN NULLIF(payload_new->>'ticket_id', '')::UUID
            WHEN payload_new ? 'id' AND TG_TABLE_NAME = 'tickets'
                THEN NULLIF(payload_new->>'id', '')::UUID
            ELSE NULL
        END,
        jsonb_build_object(
            'operation', TG_OP,
            'new', payload_new,
            'old', payload_old,
            'table', TG_TABLE_NAME,
            'event_type', event_name,
            'created_at', NOW()
        )
    );

    PERFORM pg_notify(
        'fixit_automation',
        json_build_object(
            'event_type', event_name,
            'source_table', TG_TABLE_NAME
        )::text
    );

    RETURN NEW;
END;
"""

GUARD = f"""    -- Synthetic demo import (python -m app.synthetic): transaction-local flag AND a SYN- ticket.
    IF current_setting('{SKIP_SETTING}', true) = 'on' AND (
        (TG_TABLE_NAME = 'tickets' AND payload_new->>'number' LIKE 'SYN-%')
        OR (TG_TABLE_NAME <> 'tickets' AND EXISTS (
            SELECT 1 FROM tickets t WHERE t.id = payload_new->>'ticket_id' AND t.number LIKE 'SYN-%'))
    ) THEN
        RETURN NEW;
    END IF;

"""
GUARDED_BODY = ORIGINAL_BODY.replace("BEGIN\n", "BEGIN\n" + GUARD, 1)


def _normalized(body: str) -> str:
    return " ".join(body.split())


def _current(bind) -> tuple[str, str] | None:
    """(schema, body) of the function visible on the search_path, or None if it does not exist."""
    row = bind.execute(sa.text(
        "SELECT n.nspname, p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
        "WHERE p.oid = to_regprocedure(:sig)"), {"sig": f"{FUNCTION}()"}).first()
    return (row[0], row[1]) if row else None


def _replace(bind, expected: str, new_body: str) -> None:
    if bind.dialect.name != "postgresql":
        return
    current = _current(bind)
    if current is None:
        return  # no automation triggers in this database
    schema, body = current
    if _normalized(body) == _normalized(new_body):
        return  # already applied
    if _normalized(body) != _normalized(expected):
        raise RuntimeError(f"{schema}.{FUNCTION}() no coincide con la definición conocida; revísela antes de migrar. "
                           "No se modificó nada.")
    op.execute(sa.text(
        f'CREATE OR REPLACE FUNCTION "{schema}".{FUNCTION}() RETURNS trigger LANGUAGE plpgsql AS $function${new_body}$function$'))


def upgrade():
    _replace(op.get_bind(), ORIGINAL_BODY, GUARDED_BODY)


def downgrade():
    _replace(op.get_bind(), GUARDED_BODY, ORIGINAL_BODY)
