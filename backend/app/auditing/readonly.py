"""Read-only database access for the audit controls.

* A dedicated engine (``AUDIT_DATABASE_URL`` when configured, otherwise ``DATABASE_URL``), separate from the application's
  pool, so a read-only setting can never leak into a connection the application later uses for writes.
* PostgreSQL: every control runs in its own transaction opened with ``SET TRANSACTION READ ONLY`` plus ``statement_timeout``
  and ``lock_timeout``; the transaction is always rolled back. A write attempt fails with "cannot execute ... in a
  read-only transaction" even if the role could write.
* SQLite (tests and local use): ``PRAGMA query_only = ON`` on a non-pooled connection that is discarded afterwards.

The URL is never logged, stored or shown; only the role name and its attributes are reported.
"""
from __future__ import annotations

from contextlib import contextmanager
from urllib.parse import urlsplit

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.pool import NullPool

from app.core.config import settings

_engine: Engine | None = None


def audit_url() -> tuple[str, bool]:
    """(URL, whether it is the dedicated AUDIT_DATABASE_URL)."""
    if settings.audit_database_url and settings.audit_database_url.get_secret_value().strip():
        return settings.audit_database_url.get_secret_value().strip(), True
    return settings.database_url, False


def host_kind(url: str) -> str:
    """Coarse description of where the database lives (no host name, user or password)."""
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return "desconocido"
    if url.startswith("sqlite"): return "SQLite local"
    if host in {"localhost", "127.0.0.1", "::1", "db"}: return "PostgreSQL local"
    if "supabase" in host: return "PostgreSQL administrado (Supabase)"
    if "render.com" in host: return "PostgreSQL administrado (Render)"
    return "PostgreSQL remoto"


def engine() -> Engine:
    global _engine
    if _engine is None:
        url, _ = audit_url()
        if url.startswith("sqlite"):
            eng = create_engine(url, poolclass=NullPool, connect_args={"check_same_thread": False})

            @event.listens_for(eng, "connect")
            def _query_only(dbapi_conn, _):  # every SQLite connection of this engine is read-only from the start
                dbapi_conn.execute("PRAGMA query_only = ON")
            _engine = eng
        else:
            _engine = create_engine(url, pool_pre_ping=True, pool_size=2, max_overflow=1, pool_recycle=600)
    return _engine


def reset_engine() -> None:
    global _engine
    if _engine is not None: _engine.dispose()
    _engine = None


@contextmanager
def read_only() -> Connection:
    """A connection inside a read-only transaction that is always rolled back."""
    with engine().connect() as conn:
        tx = conn.begin()
        try:
            if conn.dialect.name == "postgresql":
                conn.execute(text("SET TRANSACTION READ ONLY"))
                conn.execute(text("SELECT set_config('statement_timeout', :t, true), set_config('lock_timeout', '3000', true)"),
                             {"t": str(int(settings.audit_statement_timeout_ms))})
            yield conn
        finally:
            tx.rollback()


def describe_connection() -> dict:
    """Privileges of the connection the controls use, for the report ("con qué permisos se comprobó")."""
    url, dedicated = audit_url()
    info = {"origen": "AUDIT_DATABASE_URL (conexión dedicada a auditoría)" if dedicated else
            "DATABASE_URL (conexión de la aplicación, usada solo en transacciones de solo lectura)",
            "ubicacion": host_kind(url), "modo": None}
    try:
        with read_only() as conn:
            if conn.dialect.name == "postgresql":
                row = conn.execute(text("""
                    SELECT current_user AS rol, r.rolsuper AS superusuario, r.rolcreaterole AS crea_roles, r.rolcreatedb AS crea_bases,
                           r.rolbypassrls AS omite_rls, r.rolreplication AS replicacion, current_setting('transaction_read_only') AS solo_lectura,
                           current_setting('server_version') AS version_servidor,
                           (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                             WHERE n.nspname = current_schema() AND c.relkind IN ('r','p') AND pg_has_role(current_user, c.relowner, 'USAGE')) AS tablas_propias
                    FROM pg_roles r WHERE r.rolname = current_user""")).first()
                data = dict(row._mapping) if row else {}
                info.update(data)
                info["modo"] = "Transacción READ ONLY con statement_timeout por control"
                privileged = [k for k in ("superusuario", "omite_rls", "crea_roles") if data.get(k)]
                info["resumen"] = (f"Rol «{data.get('rol')}»" + (f" con atributos privilegiados: {', '.join(privileged)}" if privileged else
                                   " sin atributos de superusuario") + f"; propietario de {data.get('tablas_propias', 0)} tablas del esquema. "
                                   "Las comprobaciones se ejecutan en transacciones de solo lectura.")
            else:
                info.update({"rol": None, "solo_lectura": str(conn.exec_driver_sql("PRAGMA query_only").scalar() == 1).lower(),
                             "version_servidor": conn.exec_driver_sql("select sqlite_version()").scalar()})
                info["modo"] = "SQLite con PRAGMA query_only = ON"
                info["resumen"] = "Base SQLite local abierta en modo de solo consulta (query_only)."
    except Exception as exc:  # noqa: BLE001 - reported, never raised: the run continues and controls report their own errors
        from app.auditing.redaction import safe_error
        info["error"] = safe_error(exc)
        info["resumen"] = "No se pudo abrir la conexión de auditoría."
    return info
