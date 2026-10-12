"""Synthetic imports vs. Supabase automation triggers (migration 0002), on a real PostgreSQL.

Runs only when FIXIT_TEST_POSTGRES_URL points to a LOCAL PostgreSQL, e.g.
    docker run -d --rm -p 127.0.0.1:15432:5432 -e POSTGRES_PASSWORD=test postgres:16-alpine
    FIXIT_TEST_POSTGRES_URL=postgresql+psycopg://postgres:test@127.0.0.1:15432/postgres pytest
Each test works in its own temporary schema that reproduces the Supabase automation objects
(automation_events, fixit_enqueue_automation_event() and its four triggers), dropped afterwards.
"""
import importlib.util
import os
import uuid
from datetime import date
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.core.database import Base
from app.models import Area, Category, Priority, Role, Ticket, TicketComment, TicketState, User
from app.synthetic import importer
from app.synthetic.generator import generate

PG_URL = os.getenv("FIXIT_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not PG_URL, reason="FIXIT_TEST_POSTGRES_URL no definida (PostgreSQL local)")

_path = Path(__file__).resolve().parents[1] / "migrations" / "versions" / "0002_skip_synthetic_automation.py"
_spec = importlib.util.spec_from_file_location("migration_0002", _path)
M0002 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(M0002)

END = date(2026, 6, 30)
SUPABASE_OBJECTS = [
    """CREATE TABLE automation_events (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(), event_type VARCHAR(80) NOT NULL, source_table VARCHAR(80),
        aggregate_id UUID, payload JSONB NOT NULL DEFAULT '{}'::jsonb, status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
        attempts INTEGER NOT NULL DEFAULT 0, available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        processed_at TIMESTAMPTZ, last_error TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""",
    f"CREATE FUNCTION fixit_enqueue_automation_event() RETURNS trigger LANGUAGE plpgsql AS $function${M0002.ORIGINAL_BODY}$function$",
    "CREATE TRIGGER trg_tickets_automation_events AFTER INSERT OR UPDATE ON tickets FOR EACH ROW EXECUTE FUNCTION fixit_enqueue_automation_event()",
    "CREATE TRIGGER trg_ticket_assignments_automation_events AFTER INSERT ON ticket_assignments FOR EACH ROW EXECUTE FUNCTION fixit_enqueue_automation_event()",
    "CREATE TRIGGER trg_ticket_comments_automation_events AFTER INSERT ON ticket_comments FOR EACH ROW EXECUTE FUNCTION fixit_enqueue_automation_event()",
    "CREATE TRIGGER trg_ratings_automation_events AFTER INSERT ON ratings FOR EACH ROW EXECUTE FUNCTION fixit_enqueue_automation_event()",
]


@pytest.fixture
def engine():
    assert importer.assert_local(PG_URL)["local"]  # never a remote database
    schema = f"fixit_test_{uuid.uuid4().hex[:10]}"
    admin = create_engine(PG_URL, poolclass=NullPool)
    with admin.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    # A single pooled connection: every transaction below reuses the connection of the import.
    eng = create_engine(PG_URL, pool_size=1, max_overflow=0, connect_args={"options": f"-c search_path={schema}"})
    try:
        Base.metadata.create_all(eng)
        with eng.begin() as conn:
            for sql in SUPABASE_OBJECTS:
                conn.execute(text(sql))
        yield eng
    finally:
        eng.dispose()
        with admin.begin() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


def migrate(eng, direction: str):
    with eng.begin() as conn, Operations.context(MigrationContext.configure(conn)):
        getattr(M0002, direction)()


def function_body(eng) -> str:
    with eng.connect() as conn:
        return conn.scalar(text("SELECT prosrc FROM pg_proc WHERE oid = to_regprocedure('fixit_enqueue_automation_event()')"))


def events(eng, synthetic: bool | None = None) -> int:
    sql = "SELECT count(*) FROM automation_events e LEFT JOIN tickets t ON t.id = e.aggregate_id::text"
    if synthetic is not None:
        sql += f" WHERE t.number {'' if synthetic else 'NOT '}LIKE 'SYN-%'"
    with eng.connect() as conn:
        return conn.scalar(text(sql))


def real_ticket(db: Session, number: str) -> Ticket:
    user = db.scalar(select(User).where(User.email == "real@empresa.org"))
    if not user:
        user = User(full_name="Persona Real", email="real@empresa.org", password_hash="x",
                    role_id=db.scalar(select(Role.id).where(Role.code == "USUARIO")))
        db.add(user)
        db.flush()
    ticket = Ticket(number=number, title="Ticket real", description="Descripción real del problema", requester_id=user.id,
                    area_id=db.scalar(select(Area.id)), category_id=db.scalar(select(Category.id)),
                    priority_id=db.scalar(select(Priority.id)), state_id=db.scalar(select(TicketState.id).where(TicketState.code == "NUEVO")))
    db.add(ticket)
    db.flush()
    return ticket


def test_import_is_refused_before_writing_when_guard_is_missing(engine):
    with pytest.raises(importer.AutomationGuardMissing):
        importer.import_dataset(engine, generate(50, seed=5, end_date=END, days=60))
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(Ticket)) == 0
        assert db.scalar(select(func.count()).select_from(Role)) == 0  # not even the base catalogs were seeded
    assert events(engine) == 0


def test_synthetic_import_skips_events_while_real_tickets_keep_generating_them(engine):
    migrate(engine, "upgrade")
    importer._ensure_base(engine)
    with Session(engine) as db, db.begin():
        ticket = real_ticket(db, "FIX-REAL-0001")
        db.add(TicketComment(ticket_id=ticket.id, author_id=ticket.requester_id, body="Comentario real", internal=False))
    assert events(engine, synthetic=False) == 2  # TICKET_CREADO + TICKET_COMENTADO
    with engine.connect() as conn:
        before = conn.execute(text("SELECT * FROM tickets WHERE number = 'FIX-REAL-0001'")).mappings().one()

    ds = generate(120, seed=5, end_date=END, days=60)
    assert ds.assignments and ds.comments and ds.ratings
    result = importer.import_dataset(engine, ds)
    assert result["imported"]["tickets"] == 120
    assert events(engine, synthetic=True) == 0 and events(engine) == 2
    with engine.connect() as conn:
        assert conn.execute(text("SELECT * FROM tickets WHERE number = 'FIX-REAL-0001'")).mappings().one() == before
        # Same pooled connection as the import: the flag did not survive its transaction.
        assert conn.scalar(text("SELECT coalesce(current_setting('fixit.synthetic_import', true), '')")) != "on"

    with Session(engine) as db, db.begin():  # a user creates a real ticket after the import
        real_ticket(db, "FIX-REAL-0002")
    assert events(engine, synthetic=False) == 3

    with Session(engine) as db, db.begin():  # the flag alone never hides real tickets
        db.execute(text("SELECT set_config('fixit.synthetic_import', 'on', true)"))
        real_ticket(db, "FIX-REAL-0003")
    assert events(engine, synthetic=False) == 4

    with Session(engine) as db, db.begin():  # normal activity on a demo ticket is automated as usual
        db.execute(text("UPDATE tickets SET title = 'Editado' WHERE number = 'SYN-000001'"))
    assert events(engine, synthetic=True) == 1


def test_migration_is_idempotent_reversible_and_refuses_unknown_definitions(engine):
    original = function_body(engine)
    migrate(engine, "upgrade")
    migrate(engine, "upgrade")  # already applied: no-op
    assert importer.AUTOMATION_SKIP_SETTING in function_body(engine)

    migrate(engine, "downgrade")
    assert function_body(engine) == original
    with pytest.raises(importer.AutomationGuardMissing):
        importer.import_dataset(engine, generate(50, seed=5, end_date=END, days=60))

    with engine.begin() as conn:  # someone edited the function by hand
        conn.execute(text("CREATE OR REPLACE FUNCTION fixit_enqueue_automation_event() RETURNS trigger LANGUAGE plpgsql "
                          "AS $f$ BEGIN RETURN NEW; END; $f$"))
    edited = function_body(engine)
    with pytest.raises(RuntimeError):
        migrate(engine, "upgrade")
    assert function_body(engine) == edited
