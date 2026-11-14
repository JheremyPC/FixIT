"""Audit center on a real PostgreSQL: migration 0006 (empty database, database with the 0005 schema and data, downgrade in a
test database) and the database controls (RLS, privileges, policies, SECURITY DEFINER, indexes, append-only trigger).

Runs only when FIXIT_TEST_POSTGRES_URL points to a LOCAL PostgreSQL, e.g.
    docker run -d --rm -p 127.0.0.1:15432:5432 -e POSTGRES_PASSWORD=test postgres:16-alpine
    FIXIT_TEST_POSTGRES_URL=postgresql+psycopg://postgres:test@127.0.0.1:15432/postgres pytest tests/test_audit_center_pg.py
Each test creates its own temporary database and drops it afterwards. Roles anon/authenticated are created in the local
cluster if missing (they reproduce Supabase's API roles).
"""
import os
import subprocess  # noqa: S404 - runs Alembic with fixed arguments against a local test database
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import bcrypt
import pytest
from pydantic import SecretStr
from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

from app.auditing import engine as audit_engine, readonly
from app.auditing.registry import RunInfo, load_controls
from app.core.config import settings
from app.models import AUDIT_CENTER_TABLES
from app.services.audit import sealed_fields
from app.synthetic import importer

PG_URL = os.getenv("FIXIT_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not PG_URL, reason="FIXIT_TEST_POSTGRES_URL no definida (PostgreSQL local)")
BACKEND = Path(__file__).resolve().parents[1]
BUSINESS = ("roles", "users", "areas", "categories", "priorities", "ticket_states", "tickets", "ticket_history", "audit_logs")


def _url(database: str) -> str:
    parts = urlsplit(PG_URL)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


@pytest.fixture
def database():
    assert importer.assert_local(PG_URL)["local"]  # never a remote database
    name = f"fixit_ac_{uuid.uuid4().hex[:10]}"
    admin = create_engine(PG_URL, isolation_level="AUTOCOMMIT", poolclass=NullPool)
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
        for role in ("anon", "authenticated"):
            conn.execute(text(f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN CREATE ROLE {role} NOLOGIN; END IF; END $$"))
    try:
        yield _url(name)
    finally:
        readonly.reset_engine()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def alembic(url: str, *args: str) -> str:
    env = {**os.environ, "DATABASE_URL": url, "JWT_SECRET_KEY": settings.jwt_secret_key, "PYTHONPATH": str(BACKEND), "FIXIT_ADMIN_PASSWORD": ""}
    result = subprocess.run([sys.executable, "-m", "alembic", "-c", str(BACKEND / "alembic.ini"), *args], cwd=BACKEND, env=env,  # noqa: S603
                            capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stderr[-4000:]
    return result.stdout + result.stderr


def _tables(conn) -> set[str]:
    return set(conn.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")).scalars())


def _digests(conn) -> dict:
    return {t: conn.execute(text(f'SELECT count(*)::text || \':\' || COALESCE(md5(string_agg(x::text, \',\' ORDER BY x::text)), \'\') FROM "{t}" x')).scalar()  # noqa: S608
            for t in BUSINESS}


def _seed(conn) -> None:
    ids = {k: str(uuid.uuid4()) for k in ("role", "user", "area", "cat", "prio", "state", "ticket")}
    conn.execute(text("INSERT INTO roles(id, code, name) VALUES (:id, 'USUARIO', 'Usuario')"), {"id": ids["role"]})
    conn.execute(text("INSERT INTO users(id, full_name, email, password_hash, role_id, active, created_at, updated_at) VALUES "
                      "(:id, 'Persona de prueba', 'persona@fixit.org', :h, :r, true, now(), now())"),
                 {"id": ids["user"], "h": bcrypt.hashpw(b"Secure!123", bcrypt.gensalt(4)).decode(), "r": ids["role"]})
    conn.execute(text("INSERT INTO areas(id, name, active, created_at, updated_at) VALUES (:id, 'TI', true, now(), now())"), {"id": ids["area"]})
    conn.execute(text("INSERT INTO categories(id, name, active, created_at, updated_at) VALUES (:id, 'General', true, now(), now())"), {"id": ids["cat"]})
    conn.execute(text("INSERT INTO priorities(id, code, name, level, sla_hours, color) VALUES (:id, 'MEDIA', 'Media', 2, 48, '#3b82f6')"), {"id": ids["prio"]})
    conn.execute(text("INSERT INTO ticket_states(id, code, name, terminal) VALUES (:id, 'NUEVO', 'Nuevo', false)"), {"id": ids["state"]})
    conn.execute(text("INSERT INTO tickets(id, number, title, description, requester_id, area_id, category_id, priority_id, state_id, created_at, updated_at, due_at) "
                      "VALUES (:t, 'FIX-20261114-AAAAAAA', 'Impresora', 'No imprime desde ayer', :u, :a, :c, :p, :s, now(), now(), now() + interval '48 hours')"),
                 {"t": ids["ticket"], "u": ids["user"], "a": ids["area"], "c": ids["cat"], "p": ids["prio"], "s": ids["state"]})
    conn.execute(text("INSERT INTO ticket_history(id, ticket_id, actor_id, event, detail, created_at) VALUES (:id, :t, :u, 'CREADO', 'Ticket creado', now())"),
                 {"id": str(uuid.uuid4()), "t": ids["ticket"], "u": ids["user"]})
    fields = sealed_fields(ids["user"], "CREAR", "TICKETS", "TICKET", ids["ticket"], new={"number": "FIX-20261114-AAAAAAA"})
    conn.execute(text("INSERT INTO audit_logs(id, user_id, action, module, entity, entity_id, new_value, outcome, integrity_hash, created_at) "
                      "VALUES (:id, :user_id, :action, :module, :entity, :entity_id, CAST(:new_value AS json), :outcome, :integrity_hash, :created_at)"),
                 {**{k: fields[k] for k in ("id", "user_id", "action", "module", "entity", "entity_id", "outcome", "integrity_hash", "created_at")},
                  "new_value": __import__("json").dumps(fields["new_value"])})


def test_migration_on_an_empty_database_and_downgrade(database):
    alembic(database, "upgrade", "head")
    eng = create_engine(database, poolclass=NullPool)
    with eng.connect() as conn:
        assert set(AUDIT_CENTER_TABLES) <= _tables(conn)
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0006_audit_center"
        rls = dict(conn.execute(text("SELECT relname, relrowsecurity FROM pg_class WHERE relname = ANY(:t)"), {"t": list(AUDIT_CENTER_TABLES)}).all())
        assert all(rls[t] for t in AUDIT_CENTER_TABLES)
        checks = set(conn.execute(text("SELECT conname FROM pg_constraint WHERE contype = 'c'")).scalars())
        assert {"ck_audit_results_status", "ck_audit_findings_status", "ck_audit_findings_severity", "ck_audit_runs_status"} <= checks
    alembic(database, "downgrade", "0005_audit_security")
    with eng.connect() as conn:
        tables = _tables(conn)
        assert not set(AUDIT_CENTER_TABLES) & tables and {"users", "tickets", "audit_logs"} <= tables
    alembic(database, "upgrade", "head")
    with eng.connect() as conn:
        assert set(AUDIT_CENTER_TABLES) <= _tables(conn)
    eng.dispose()


def test_migration_preserves_an_existing_0005_database(database):
    alembic(database, "upgrade", "0005_audit_security")
    eng = create_engine(database, poolclass=NullPool)
    with eng.begin() as conn:
        # The 0005 release did not have the audit center tables (0001 creates the current models): remove them first.
        for table in reversed(AUDIT_CENTER_TABLES):
            conn.execute(text(f'DROP TABLE IF EXISTS "{table}"'))
        _seed(conn)
    with eng.connect() as conn:
        before = _digests(conn)
    alembic(database, "upgrade", "head")
    with eng.connect() as conn:
        assert _digests(conn) == before and set(AUDIT_CENTER_TABLES) <= _tables(conn)
    alembic(database, "downgrade", "0005_audit_security")  # test database only: never in production
    with eng.connect() as conn:
        assert _digests(conn) == before
    eng.dispose()


def _run(codes: list[str]) -> dict:
    registry = load_controls()
    info = RunInfo("pg-test", "AUD-PG", None, None, {"filas_minimas_indice": 0})
    return {code: audit_engine.run_control(registry[code], info, "prueba")[0] for code in codes}


def test_database_controls_detect_exposure_without_modifying_data(database, monkeypatch):
    alembic(database, "upgrade", "head")
    owner = create_engine(database, poolclass=NullPool)
    with owner.begin() as conn:
        _seed(conn)
        conn.execute(text("CREATE TABLE expuesta_prueba (id int PRIMARY KEY)"))
        conn.execute(text("GRANT SELECT ON expuesta_prueba TO anon"))
        conn.execute(text("GRANT SELECT ON users TO anon"))  # blocked: RLS without policies
        conn.execute(text("GRANT SELECT ON terms_acceptances TO anon"))
        conn.execute(text("CREATE POLICY abierta ON terms_acceptances FOR SELECT TO anon USING (true)"))
        conn.execute(text("CREATE FUNCTION fn_definer_prueba() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'select 1'"))
        conn.execute(text("CREATE INDEX ix_duplicado_prueba ON tickets (state_id)"))
    with owner.connect() as conn:
        before = _digests(conn)
    monkeypatch.setattr(settings, "audit_database_url", SecretStr(database))
    readonly.reset_engine()

    with readonly.read_only() as conn:  # the audit connection is read-only even for a superuser
        with pytest.raises(Exception, match="read-only transaction"):
            conn.execute(text("INSERT INTO settings(key, value) VALUES ('x', 'y')"))

    out = _run(list(load_controls()))  # every control, so PostgreSQL dialect problems surface as test failures
    errors = {c: o.details for c, o in out.items() if o.status == "ERROR_EJECUCION"}
    assert not errors, errors
    resources = lambda code: {f.resource for f in out[code].findings}  # noqa: E731
    assert out["BD-SEG-01"].status == "FALLIDO" and "rls:expuesta_prueba" in resources("BD-SEG-01")
    assert out["BD-SEG-03"].status == "FALLIDO" and "exposicion:expuesta_prueba:anon" in resources("BD-SEG-03")
    assert out["BD-SEG-08"].status == "FALLIDO" and "sensible:terms_acceptances:anon" in resources("BD-SEG-08")
    assert "sensible:users:anon" not in resources("BD-SEG-08")  # granted, but RLS without policies blocks it
    assert out["BD-SEG-02"].status == "FALLIDO" and "politica:terms_acceptances.abierta" in resources("BD-SEG-02")
    assert out["BD-SEG-04"].status == "FALLIDO" and any("fn_definer_prueba" in r for r in resources("BD-SEG-04"))
    assert out["BD-EST-05"].status == "ADVERTENCIA" and any("ix_duplicado_prueba" in r for r in resources("BD-EST-05"))
    assert out["BD-EST-01"].status == "ADVERTENCIA" and "expuesta_prueba" in out["BD-EST-01"].details["objetos_inesperados"]
    assert out["BD-EST-02"].status == "APROBADO" and out["BD-EST-03"].status == "APROBADO" and out["BD-EST-07"].status == "APROBADO"
    assert out["BD-EST-06"].status == "APROBADO", out["BD-EST-06"].details
    assert out["BD-SEG-07"].status == "ADVERTENCIA" and out["BD-SEG-07"].details["superusuario"] is True
    assert out["BD-SEG-07"].details["transaccion_solo_lectura"] == "on"
    assert out["BD-SEG-10"].status == "NO_APLICABLE"  # local connection without TLS
    assert out["BD-ACT-01"].status in ("ADVERTENCIA", "APROBADO") and out["BD-ACT-04"].status in ("NO_VERIFICADO", "APROBADO", "ADVERTENCIA")
    assert out["REG-02"].status == "APROBADO" and out["INF-03"].status == "APROBADO"

    with owner.begin() as conn:
        conn.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_append_only"))
    assert _run(["REG-02"])["REG-02"].status == "FALLIDO"
    with owner.connect() as conn:
        assert _digests(conn) == before  # no control modified business data
    owner.dispose()
