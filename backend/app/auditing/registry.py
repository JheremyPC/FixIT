"""Control registry. A control is a function ``fn(ctx) -> Outcome`` registered with ``@control(...)``. It receives a
read-only connection (``ctx.conn`` / ``ctx.session``) and returns its status, a summary, structured evidence and the
findings it detected. A control that cannot verify something raises :class:`NotVerifiable` (status NO_VERIFICADO);
any other exception becomes ERROR_EJECUCION. A control never reports APROBADO for something it did not check."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session

from app.auditing.catalog import CATEGORIES, METHODS
from app.models.audit_center import CONTROL_STATUSES, SEVERITIES


class NotVerifiable(Exception):
    """The control could not be executed (missing privilege, evidence, data or provider access)."""


@dataclass
class FindingSpec:
    resource: str
    title: str
    description: str
    impact: str
    likelihood: str
    recommendation: str
    severity: str | None = None      # default: the control's severity
    evidence: dict | None = None


@dataclass
class Outcome:
    status: str
    summary: str
    details: dict = field(default_factory=dict)
    findings: list[FindingSpec] = field(default_factory=list)
    severity: str | None = None
    method: str | None = None        # overrides the control's method (e.g. MANUAL when evidence decides)

    def __post_init__(self):
        if self.status not in CONTROL_STATUSES: raise ValueError(f"Estado inválido: {self.status}")
        if self.severity and self.severity not in SEVERITIES: raise ValueError(f"Severidad inválida: {self.severity}")


@dataclass
class Control:
    code: str
    category: str
    title: str
    objective: str
    method: str
    severity: str
    fn: Callable[["Ctx"], Outcome]
    criteria: list[str] = field(default_factory=list)
    requires: tuple[str, ...] = ()   # "postgresql"
    evidence_days: int | None = None  # manual controls: how old a declaration may be
    guidance: str | None = None       # what evidence a person must provide (manual controls)


@dataclass
class RunInfo:
    id: str
    code: str
    period_from: datetime | None
    period_to: datetime | None
    options: dict


@dataclass
class Ctx:
    conn: Connection
    dialect: str
    run: RunInfo
    now: datetime
    privileges: str
    control: Control | None = None
    _session: Session | None = None

    @property
    def session(self) -> Session:
        """ORM session bound to the same read-only connection (writes fail at the database)."""
        if self._session is None: self._session = Session(bind=self.conn, autoflush=False)
        return self._session

    @property
    def pg(self) -> bool:
        return self.dialect == "postgresql"

    def rows(self, sql: str, **params) -> list[dict]:
        return [dict(r._mapping) for r in self.conn.execute(text(sql), params)]

    def one(self, sql: str, **params) -> dict | None:
        row = self.conn.execute(text(sql), params).first()
        return dict(row._mapping) if row else None

    def scalar(self, sql: str, **params):
        return self.conn.execute(text(sql), params).scalar()

    def option(self, key: str, default):
        value = self.run.options.get(key)
        return default if value is None else value

    def period(self) -> tuple[datetime, datetime]:
        """Evaluation period of the run (default: the last 30 days up to now)."""
        from datetime import timedelta
        end = self.run.period_to or self.now
        start = self.run.period_from or end - timedelta(days=30)
        return start, end


REGISTRY: dict[str, Control] = {}


def control(code: str, category: str, title: str, objective: str, method: str, severity: str, criteria: list[str] | None = None,
            requires: tuple[str, ...] = (), evidence_days: int | None = None, guidance: str | None = None):
    if category not in CATEGORIES: raise ValueError(f"Categoría desconocida: {category}")
    if method not in METHODS: raise ValueError(f"Método desconocido: {method}")
    if severity not in SEVERITIES: raise ValueError(f"Severidad desconocida: {severity}")

    def wrap(fn):
        if code in REGISTRY: raise ValueError(f"Control duplicado: {code}")
        REGISTRY[code] = Control(code, category, title, objective, method, severity, fn, criteria or [], requires, evidence_days, guidance)
        return fn
    return wrap


def ok(summary: str, **details) -> Outcome:
    return Outcome("APROBADO", summary, details)


def warn(summary: str, findings: list[FindingSpec] | None = None, severity: str | None = None, **details) -> Outcome:
    return Outcome("ADVERTENCIA", summary, details, findings or [], severity)


def fail(summary: str, findings: list[FindingSpec] | None = None, severity: str | None = None, **details) -> Outcome:
    return Outcome("FALLIDO", summary, details, findings or [], severity)


def not_applicable(summary: str, **details) -> Outcome:
    return Outcome("NO_APLICABLE", summary, details)


def load_controls() -> dict[str, Control]:
    """Import every control module (registration happens at import time)."""
    from app.auditing.controls import access, continuity, database, infrastructure, logs, operations, privacy, security  # noqa: F401
    return REGISTRY
